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


from oauth2client._helpers import _from_bytes
from oauth2client import util
from oauth2client.client import AssertionCredentials
from oauth2client.contrib import metadata


__author__ = 'jcgregorio@google.com (Joe Gregorio)'

logger = logging.getLogger(__name__)

_SCOPES_WARNING = """\
You have specified explicit scopes to be used with a GCE service account
credentials, and these scopes *are* present on the credentials.
However, setting scopes on the GCE service account credentials has no effect
on the actual scopes for tokens requested. The credentials scopes
are set at VM instance creation time and can't be overridden in the request.
To learn more go to https://cloud.google.com/compute/docs/authentication .
"""
_SCOPES_ERROR = """\
You have specified explicit scopes to be used with a GCE service account
which are not available on the credentials. The scopes are set at VM instance
creation time and can't be overridden in the request.
To learn more go to https://cloud.google.com/compute/docs/authentication .
"""


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

    def __init__(self, *args, **kwargs):
        """Constructor for AppAssertionCredentials"""
        # Cache until Metadata Server supports Cache-Control Header
        self._service_account_info = None

        if 'scopes' in kwargs:
            self._check_scopes_and_notify(kwargs['scopes'])

        # Assertion type is no longer used, but still in the
        # parent class signature.
        super(AppAssertionCredentials, self).__init__(None, *args, **kwargs)

    def _get_service_account_info(self, http_request=None):
        if self._service_account_info is None:
            self._service_account_info = metadata.get_service_account_info(
                http_request=http_request)
        return self._service_account_info

    def _check_scopes_and_notify(self, scopes):
        if scopes:
            if self.has_scopes(scopes):
                warnings.warn(_SCOPES_WARNING)
            else:
                raise AttributeError(_SCOPES_ERROR)

    def _retrieve_scopes(self, http_request):
        return self._get_service_account_info(
            http_request=http_request)['scopes']

    @property
    def scopes(self):
        return self._get_service_account_info()['scopes']

    @scopes.setter
    def scopes(self, value):
        self._check_scopes_and_notify(value)

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
        self.access_token, self.token_expiry = metadata.get_token(
            http_request=http_request)

    @property
    def serialization_data(self):
        raise NotImplementedError(
            'Cannot serialize credentials for GCE service accounts.')

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
            'Compute Engine service accounts cannot sign blobs')

    @property
    def service_account_email(self):
        """Get the email for the current service account.

        Uses the Google Compute Engine metadata service to retrieve the email
        of the default service account.

        Returns:
            string, The email associated with the Google Compute Engine
            service account.
        """
        return self._get_service_account_info()['email']

