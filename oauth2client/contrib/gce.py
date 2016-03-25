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
import time
from six.moves import http_client

from oauth2client._helpers import _from_bytes
from oauth2client import util
from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.client import AssertionCredentials


__author__ = 'jcgregorio@google.com (Joe Gregorio)'

logger = logging.getLogger(__name__)

# URI Template for the endpoint that returns access_tokens.
_METADATA_ROOT = 'http://metadata.google.internal/v1/computeMetadata'
_SCOPES_WARNING = """\
You have requested explicit scopes to be used with a GCE service account.
Using this argument will have no effect on the actual scopes for tokens
requested. These scopes are set at VM instance creation time and
can't be overridden in the request.
"""


def _get_metadata(http_request=None, *path):
    """
    Args:
        http_request: an httplib2.Http().request object or equivalent
            with which to make the call to the metadata server
        *path: a list of strings denoting the metadata server request
            path.
    Returns:
        A deserialized JSON object representing the data returned
        from the metadata server
    """

    if not http_request:
        http_request = httplib2.Http().request

    full_path = '/'.join(path.insert(0, _METADATA_ROOT)) + '/?recursive=true'
    response, content = http_request(
        full_path,
        headers={'Metadata-Flavor': 'Google'}
    )
    if response.status == http_client.OK:
        return json.loads(_from_bytes(content))
    else:
        msg = (
            'Failed to retrieve {} from the Google Compute Engine'
            'metadata service. Response:\n{}'
        ).format(full_path, response)
        raise AttributeError(msg)


def _get_access_token(http_request, email):
    """
    Args:
        http_request: an httplib2.Http().request object or equivalent
            with which to make the call to the metadata server
        email: The service account email to request an access token with
    Returns:
        A tuple (accessToken, token expiry)
    """
    token_json = _get_metadata(
        'instance',
        'service-accounts',
        email,
        'acquire',
        http_request=http_request
    )
    token_expiry = int(token_json.get('expires_in')) + time.time()
    return token_json.get('access_token'), token_expiry


def _get_service_account_info(email, http_request=None):
    """
    Args:
        http_request: an httplib2.Http().request object or equivalent
            with which to make the call to the metadata server
        email: The service account email to request an access token with
    Returns:
        A deserialized JSON service account object of the form:
            {
               'aliases': [],
               'scopes': [],
               'email': "a@example.com"
            }
    """

    return _get_metadata(
        'instance',
        'service-accounts',
        email,
        http_request=http_request
    )


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
            scope:
                string or iterable of strings, scope(s) of the credentials
                being requested. Using this argument will have no effect on
                the actual scopes for tokens requested. These scopes are
                set at VM instance creation time and won't change.
            service_account_email:
                the email for these credentials. This can be used with custom
                service accounts, or left blank to use the default service
                account for the instance. Usually the compute engine service
                account.
        """
        if scope:
            warnings.warn(_SCOPES_WARNING)

        self._service_account_info = {'email': service_account_email}
        self._project_id = None

        self.kwargs = kwargs

        # Assertion type is no longer used, but still in the
        # parent class signature.
        super(AppAssertionCredentials, self).__init__(None)

    @property
    def service_account_info(self):
        if self._service_account_info.get('email', 'default') == 'default':
            self._service_account_info = _get_service_account_info(
                self._service_account_info.get('email', 'default')
            )
        return self._service_account_info

    @property
    def scopes(self):
        return self._retrieve_scopes(httplib2.Http().request)

    @property
    def service_account_email(self):
        return self.service_account_info['email']

    @property
    def project_id(self):
        if not self._project_id:
            self._project_id = _get_metadata('project', 'project-id')
        return self._project_id

    @property
    def serialization_data(self):
        return {
            'email': self.service_account_email
        }

    def _retrieve_scopes(self, http_request):
        return self.service_account_info['scopes']

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
        except (AttributeError, ValueError) as e:
            raise HttpAccessTokenRefreshError(str(e))

    def create_scoped_required(self):
        return False

    def create_scoped(self, scopes):
        return AppAssertionCredentials(scopes, **self.kwargs)

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

    @classmethod
    def from_json(cls, json_data):
        return AppAssertionCredentials(
            service_account_email=json_data['email']
        )
