# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Utilities for Google Compute Engine

Utilities for making it easier to use OAuth 2.0 on Google Compute Engine.
"""

import json
import logging
import warnings

import httplib2
from six.moves import http_client

from oauth2client._helpers import _from_bytes
from oauth2client import util
from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.client import AssertionCredentials


__author__ = 'jcgregorio@google.com (Joe Gregorio)'

logger = logging.getLogger(__name__)

# URI Template for the endpoint that returns access_tokens.
_METADATA_ROOT = 'http://metadata.google.internal/0.1/meta-data'
_SCOPES_WARNING = """\
You have requested explicit scopes to be used with a GCE service account.
Using this argument will have no effect on the actual scopes for tokens
requested. These scopes are set at VM instance creation time and
can't be overridden in the request.
"""


def _get_metadata(http_request=None, *path):
    if not http_request:
        http_request = httplib2.Http().request
    full_path = "/".join(path.insert(0, _METADATA_ROOT))
    response, content = http_request(
        full_path,
        headers={'Metadata-Flavor': 'Google'}
    )
    if response.status == http_client.OK:
        return None, json.loads(_from_bytes(content))
    else:
        raise AttributeError(
            (
                'Failed to retrieve the {} from the Google Compute Engine'
                'metadata service. Response:\n{}'
            ).format(full_path, response)
        )


def _get_access_token(http_request, email='default'):
    token_json = _get_metadata(
        'service-accounts',
        email,
        'acquire',
        http_request=http_request
    )
    return token_json.get('accessToken'), token_json.get('expiresAt')


class AppAssertionCredentials(AssertionCredentials):
    """Credentials object for Compute Engine Assertion Grants

    This object will allow a Compute Engine instance to identify itself to
    Google and other OAuth 2.0 servers that can verify assertions. It can be
    used for the purpose of accessing data stored under an account assigned to
    the Compute Engine instance itself.

    This credential does not require a flow to instantiate because it
    represents a two legged flow, and therefore has all of the required
    information to generate and refresh its own access tokens.
    """

    @util.positional(2)
    def __init__(self, scope='', service_account_email='default', **kwargs):
        """Constructor for AppAssertionCredentials

        Args:
            scope: string or iterable of strings, scope(s) of the credentials
                   being requested. Using this argument will have no effect on
                   the actual scopes for tokens requested. These scopes are
                   set at VM instance creation time and won't change.
        """
        if scope:
            warnings.warn(_SCOPES_WARNING)

        service_account_json = _get_metadata(
            'service-accounts',
            service_account_email
        )

        self.scope = util.scopes_to_string(
            service_account_json.get('scopes', [])
        )
        self.service_account_email = service_account_json.get(
            'serviceAccount',
            None
        )

        self._project_id = None

        self.kwargs = kwargs

        # Assertion type is no longer used, but still in the
        # parent class signature.
        super(AppAssertionCredentials, self).__init__(None)

    @classmethod
    def from_json(cls, json_data):
        data = json.loads(_from_bytes(json_data))
        return AppAssertionCredentials(data['scope'])

    def _refresh(self, http_request):
        """Refreshes the access_token.

        Skip all the storage hoops and just refresh using the API.

        Args:
            http_request: callable, a callable that matches the method
                          signature of httplib2.Http.request, used to make
                          the refresh request.

        Raises:
            HttpAccessTokenRefreshError: When the refresh fails.
        """
        try:
            self.access_token, self.token_expiry = _get_access_token(
                http_request,
                email=self.service_account_email
            )
        except AttributeError as e:
            raise HttpAccessTokenRefreshError(str(e))

    @property
    def serialization_data(self):
        raise NotImplementedError(
            'Cannot serialize credentials for GCE service accounts.')

    def create_scoped_required(self):
        return False

    def create_scoped(self, scopes):
        return AppAssertionCredentials(scopes, **self.kwargs)

    @property
    def project_id(self):
        if not self._project_id:
            self._project_id = _get_metadata('project-id')
        return self._project_id

    def sign_blob(self, blob):
        """Cryptographically sign a blob (of bytes).

        This method is provided to support a common interface, but
        the actual key used for a Google Compute Engine service account
        is not available, so it can't be used to sign content.

        Args:
            blob: bytes, Message to be signed.

        Raises:
            NotImplementedError, always.
        """
        raise NotImplementedError(
            'Compute Engine service accounts cannot sign blobs'
        )
