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
import datetime
from six.moves import http_client

from oauth2client._helpers import _from_bytes
from oauth2client import util
from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.client import AssertionCredentials
from oauth2client.contrib.iam_signer import IAMSigner

__author__ = 'jcgregorio@google.com (Joe Gregorio)'

logger = logging.getLogger(__name__)

# URI Template for the endpoint that returns access_tokens.
_METADATA_ROOT = 'http://metadata.google.internal/computeMetadata/v1/'
_SCOPES_WARNING = """\
You have requested explicit scopes to be used with a GCE service account.
Using this argument will have no effect on the actual scopes for tokens
requested. These scopes are set at VM instance creation time and
can't be overridden in the request.
"""


def _get_metadata(http_request=None, path=None, recursive=True):
    """Gets a JSON object from the specified path on the Metadata Server
    Args:
        http_request: an httplib2.Http().request object or equivalent
            with which to make the call to the metadata server
        *path: a list of strings denoting the metadata server request
            path.
    Returns:
        A deserialized JSON object representing the data returned
        from the metadata server
    """

    if not path:
        path = []

    if not http_request:
        http_request = httplib2.Http().request

    r_string = '/?recursive=true' if recursive else ''
    full_path = _METADATA_ROOT + '/'.join(path) + r_string
    response, content = http_request(
        full_path,
        headers={'Metadata-Flavor': 'Google'}
    )
    if response.status == http_client.OK:
        decoded = _from_bytes(content)
        if recursive:
            return json.loads(decoded)
        else:
            return decoded
    else:
        msg = (
            'Failed to retrieve {path} from the Google Compute Engine'
            'metadata service. Response:\n{error}'
        ).format(path=full_path, error=response)
        raise ValueError(msg)


def _get_access_token(http_request, email):
    """Get an access token for the specified email from the Metadata Server.
    Args:
        http_request: an httplib2.Http().request object or equivalent
            with which to make the call to the metadata server
        email: The service account email to request an access token with
    Returns:
        A tuple (accessToken, token expiry)
    """
    token_json = _get_metadata(
        http_request=http_request,
        path=[
            'instance',
            'service-accounts',
            email,
            'token'
        ]
    )
    token_expiry = datetime.datetime.now() + datetime.timedelta(
        seconds=token_json.get('expires_in')
    )
    return token_json.get('access_token'), token_expiry


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

    @util.positional(3)
    def __init__(self,
                 scope=None,
                 service_account_email='default',
                 service_account_info=None,
                 **kwargs):
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
            service_account_info:
                Deserialized JSON object, returned by self.service_account_info
        """

        self._service_account_info = service_account_info or {
            'email': service_account_email
        }
        self._project_id = None
        self._partial = service_account_info is None
        self._iam_signer = None

        if scope:
            if self.has_scopes(scope):
                warnings.warn(_SCOPES_WARNING)
            else:
                raise ValueError(_SCOPES_WARNING)

        self.kwargs = kwargs

        # Assertion type is no longer used, but still in the
        # parent class signature.
        super(AppAssertionCredentials, self).__init__(None)

    @property
    def service_account_info(self):
        """Info about this service account
        By using _get_service_account_info this property is
        always guaranteed to have the members ['email', 'scopes'].
        It may also have the member: 'aliases'
        """
        return self._get_service_account_info()

    @property
    def scopes(self):
        return self.service_account_info['scopes']

    @scopes.setter
    def scopes(self, value):
        pass

    @property
    def service_account_email(self):
        return self.service_account_info['email']

    @property
    def project_id(self):
        if not self._project_id:
            self._project_id = _get_metadata(
                path=['project', 'project-id'],
                recursive=False
            )
        return self._project_id

    @property
    def serialization_data(self):
        return {'service_account_info': self.service_account_info}

    def _get_service_account_info(self, http_request=None):
        """Retrieves the full info for a service account and caches it.
        Args:
            http_request: an httplib2.Http().request object or equivalent
                with which to make the call to the metadata server
        Returns:
            A deserialized JSON service account object of the form:
                {
                   'aliases': [],
                   'scopes': [],
                   'email': 'a@example.com'
                }
        """
        if self._partial:
            self._service_account_info = _get_metadata(
                path=[
                    'instance',
                    'service-accounts',
                    self._service_account_info['email'],
                ],
                http_request=http_request
            )
            self._partial = False
        return self._service_account_info

    def _retrieve_scopes(self, http_request):
        return self._get_service_account_info(
            http_request=http_request
        )['scopes']

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
                self._service_account_info['email']
            )
        except ValueError as e:
            raise HttpAccessTokenRefreshError(str(e))

    def create_scoped(self, scopes):
        return AppAssertionCredentials(
            scope=scopes,
            service_account_info=self.service_account_info
        )

    def to_json(self):
        return self._to_json(
            self.NON_SERIALIZED_MEMBERS,
            to_serialize=self.serialization_data
        )

    @classmethod
    def from_json(cls, json_data):
        data = json.loads(json_data)
        return AppAssertionCredentials(
            service_account_info=data['service_account_info']
        )

    def sign_blob(self, blob):
        if not self._iam_signer:
            self._iam_signer = IAMSigner.from_credentials(self)
        return self._iam_signer.sign_blob(blob)
