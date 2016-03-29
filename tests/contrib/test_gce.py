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

"""Unit tests for oauth2client.contrib.gce."""

from six.moves import http_client
import unittest2
import time
import mock
import json

import httplib2
from oauth2client.client import HttpAccessTokenRefreshError,\
    Credentials,\
    save_to_well_known_file
from oauth2client.contrib.gce import _SCOPES_WARNING,\
    _METADATA_ROOT,\
    _get_metadata,\
    AppAssertionCredentials
import tempfile

__author__ = 'jcgregorio@google.com (Joe Gregorio)'

METADATA_SERVER = 'oauth2client.contrib.gce._get_metadata'
DEFAULT_SERVICE_ACCOUNT = {'email': 'default'}
A_SERVICE_ACCOUNT = {
    'scopes': [
        'https://www.googleapis.com/auth/cloud-platform',
        'https://www.googleapis.com/auth/iam'
    ],
    'email': '12345678-compute@developer.gserviceaccount.com'
}

GET_ACCESS_TOKEN = 'oauth2client.contrib.gce._get_access_token'
ONE_SECOND_TOKEN = {'access_token': '12345abcde', 'expires_in': 1}
FOREVER_TOKEN = {'access_token': '12345abcde', 'expires_in': 999999999}


class AppAssertionCredentialsTests(unittest2.TestCase):

    # BASIC TESTS

    def test_constructor(self):
        credentials = AppAssertionCredentials(foo='bar')
        self.assertEqual(credentials.kwargs, {'foo': 'bar'})
        self.assertEqual(credentials.assertion_type, None)

    @mock.patch('warnings.warn')
    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_constructor_with_matching_scopes(self, get_metadata, warn_mock):
        scope = 'http://www.googleapis.com/auth/cloud-platform'
        AppAssertionCredentials(scope=scope)
        warn_mock.assert_called_once_with(_SCOPES_WARNING)

    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_construtor_with_missing_scopes(self, get_metadata):
        scope = 'http://wwww.nobodyhasthisscope.com'
        error = None
        try:
            AppAssertionCredentials(scope=scope)
        except ValueError as e:
            error = e
        self.assertIsNotNone(error)

    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_default_service_account_info(self, get_metadata):
        credentials = AppAssertionCredentials()
        self.assertEquals(
            credentials._service_account_info,
            DEFAULT_SERVICE_ACCOUNT
        )
        self.assertEquals(credentials.scopes, A_SERVICE_ACCOUNT['scopes'])
        self.assertEquals(
            credentials.service_account_email,
            A_SERVICE_ACCOUNT['email']
        )
        self.assertEquals(credentials.service_account_info, A_SERVICE_ACCOUNT)
        get_metadata.assert_called_once_with(
            path=[
                'instance',
                'service-accounts',
                'default'
            ],
            http_request=None
        )

    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_custom_service_account_info(self, get_metadata):
        credentials = AppAssertionCredentials(
            service_account_email=A_SERVICE_ACCOUNT['email']
        )
        self.assertEquals(
            credentials._service_account_info,
            {'email': A_SERVICE_ACCOUNT['email']}
        )
        self.assertEquals(credentials.scopes, A_SERVICE_ACCOUNT['scopes'])
        self.assertEquals(
            credentials.service_account_email,
            A_SERVICE_ACCOUNT['email']
        )
        self.assertEquals(credentials.service_account_info, A_SERVICE_ACCOUNT)
        get_metadata.assert_called_once_with(
            path=[
                'instance',
                'service-accounts',
                A_SERVICE_ACCOUNT['email']
            ],
            http_request=None
        )

    @mock.patch(METADATA_SERVER, return_value='a-project-id')
    def test_project_id(self, get_metadata):
        credentials = AppAssertionCredentials()
        self.assertIsNone(credentials._project_id)
        self.assertEquals(credentials.project_id, 'a-project-id')
        self.assertEquals(credentials.project_id, 'a-project-id')
        get_metadata.assert_called_once_with(
            path=[
                'project',
                'project-id'
            ],
        )

    def test_refresh_token(self):
        credentials = AppAssertionCredentials()
        self.assertEquals(None, credentials.access_token)

        with mock.patch(METADATA_SERVER, return_value=ONE_SECOND_TOKEN):
            credentials.get_access_token()
            time.sleep(2)
            self.assertTrue(credentials.access_token_expired)

        with mock.patch(METADATA_SERVER, return_value=FOREVER_TOKEN):
            credentials.get_access_token()
            self.assertFalse(credentials.access_token_expired)

    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_serialize_deserialize(self, get_metadata):
        credentials = AppAssertionCredentials()
        credentials_from_json = Credentials.new_from_json(
            credentials.to_json()
        )
        self.assertTrue(
            credentials.service_account_info,
            credentials_from_json.service_account_info
        )

    @mock.patch('warnings.warn')
    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_create_scoped_valid(self, get_metadata, warn_mock):
        scope = 'http://www.googleapis.com/auth/cloud-platform'
        credentials = AppAssertionCredentials()
        credentials.create_scoped(scope=scope)
        warn_mock.assert_called_once_with(_SCOPES_WARNING)

    # ERROR TESTS

    def test_sign_blob_not_implemented(self):
        credentials = AppAssertionCredentials([])
        with self.assertRaises(NotImplementedError):
            credentials.sign_blob(b'blob')

    def test_refresh_failure_bad_json(self):
        http = mock.MagicMock()
        content = '{BADJSON'
        http.request = mock.MagicMock(
            return_value=(mock.Mock(status=http_client.OK), content))

        credentials = AppAssertionCredentials()
        self.assertRaises(
            HttpAccessTokenRefreshError,
            credentials.refresh,
            http
        )

    def test_refresh_failure_400(self):
        http = mock.MagicMock()
        content = '{}'
        http.request = mock.MagicMock(
            return_value=(mock.Mock(status=http_client.BAD_REQUEST), content)
        )

        credentials = AppAssertionCredentials()
        exception_caught = None
        try:
            credentials.refresh(http)
        except HttpAccessTokenRefreshError as exc:
            exception_caught = exc

        self.assertNotEqual(exception_caught, None)

    def test_refresh_failure_404(self):
        http = mock.MagicMock()
        content = '{}'
        http.request = mock.MagicMock(
            return_value=(mock.Mock(status=http_client.NOT_FOUND), content))

        credentials = AppAssertionCredentials()
        exception_caught = None
        try:
            credentials.refresh(http)
        except HttpAccessTokenRefreshError as exc:
            exception_caught = exc

        self.assertNotEqual(exception_caught, None)

    def test_scopes_failure(self):
        # Set-up the mock.
        http = mock.MagicMock()
        content = '{}'
        http.request = mock.MagicMock(
            return_value=(mock.Mock(status=http_client.NOT_FOUND), content))
        # Test the failure.
        credentials = AppAssertionCredentials()

        error = None
        try:
            credentials._retrieve_scopes(http.request)
        except AttributeError as e:
            error = e

        self.assertIsNotNone(error)

        self.assertEquals(
            credentials._service_account_info['email'],
            'default'
        )
        self.assertFalse(
            'scopes' in credentials._service_account_info
        )

    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_save_to_well_known_file(self, get_metadata):
        with tempfile.NamedTemporaryFile() as f:
            credentials = AppAssertionCredentials()
            save_to_well_known_file(credentials, well_known_file=f.name)


class Test__get_metadata(unittest2.TestCase):

    def test_success(self):
        http_request = mock.MagicMock()
        data = json.dumps(A_SERVICE_ACCOUNT).encode('utf-8')
        http_request.return_value = (
            httplib2.Response({'status': http_client.OK}), data)
        result = _get_metadata(http_request)
        self.assertEqual(result, json.loads(data.decode('utf-8')))
        http_request.assert_called_once_with(
            _METADATA_ROOT + '/?recursive=true',
            headers={'Metadata-Flavor': 'Google'})

    def test_failure(self):
        http_request = mock.MagicMock()
        response = httplib2.Response({'status': http_client.NOT_FOUND})
        content = b'Not found'
        http_request.return_value = (response, content)
        error = None
        try:
            _get_metadata(http_request)
        except AttributeError as e:
            error = e

        self.assertIsNotNone(error)
        http_request.assert_called_once_with(
            _METADATA_ROOT + '/?recursive=true',
            headers={'Metadata-Flavor': 'Google'})


if __name__ == '__main__':  # pragma: NO COVER
    unittest2.main()
