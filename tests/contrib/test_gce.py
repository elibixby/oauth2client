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
import json
import tempfile
import unittest2
import mock
from datetime import datetime
from datetime import timedelta

import httplib2
from six.moves import http_client
from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.client import Credentials
from oauth2client.client import save_to_well_known_file
from oauth2client.contrib.gce import _SCOPES_WARNING
from oauth2client.contrib.gce import _METADATA_ROOT
from oauth2client.contrib.gce import _get_metadata
from oauth2client.contrib.gce import AppAssertionCredentials
from oauth2client.contrib.gce import MetadataServerHttpError


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
FOREVER_TOKEN = {'access_token': '12345abcde', 'expires_in': 999999999}


class AppAssertionCredentialsTests(unittest2.TestCase):

    def test_constructor(self):
        credentials = AppAssertionCredentials(foo='bar')
        self.assertEqual(credentials.kwargs, {'foo': 'bar'})
        self.assertEqual(credentials.assertion_type, None)

    @mock.patch('warnings.warn')
    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_constructor_with_matching_scopes(self, get_metadata, warn_mock):
        scope = 'https://www.googleapis.com/auth/cloud-platform'
        credentials = AppAssertionCredentials(scope=scope)
        self.assertEqual(
            credentials.scopes,
            get_metadata.return_value['scopes']
        )
        warn_mock.assert_called_once_with(_SCOPES_WARNING)

    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_construtor_with_missing_scopes(self, get_metadata):
        scope = 'http://wwww.nobodyhasthisscope.com'
        with self.assertRaises(AttributeError):
            AppAssertionCredentials(scope=scope)

    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_default_service_account_info(self, get_metadata):
        credentials = AppAssertionCredentials()
        self.assertEqual(
            credentials._service_account_info,
            DEFAULT_SERVICE_ACCOUNT
        )
        self.assertEqual(
            credentials.scopes,
            get_metadata.return_value['scopes']
        )
        self.assertEqual(
            credentials.service_account_email,
            get_metadata.return_value['email']
        )
        self.assertEqual(credentials.service_account_info, A_SERVICE_ACCOUNT)
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
            service_account_email=get_metadata.return_value['email']
        )
        self.assertEqual(
            credentials._service_account_info,
            {'email': get_metadata.return_value['email']}
        )
        self.assertEqual(
            credentials.scopes,
            get_metadata.return_value['scopes']
        )
        self.assertEqual(
            credentials.service_account_email,
            get_metadata.return_value['email']
        )
        self.assertEqual(credentials.service_account_info, A_SERVICE_ACCOUNT)
        get_metadata.assert_called_once_with(
            path=[
                'instance',
                'service-accounts',
                get_metadata.return_value['email']
            ],
            http_request=None
        )

    @mock.patch(METADATA_SERVER, return_value='a-project-id')
    def test_project_id(self, get_metadata):
        credentials = AppAssertionCredentials()
        self.assertIsNone(credentials._project_id)
        self.assertEqual(credentials.project_id, 'a-project-id')
        self.assertEqual(credentials.project_id, 'a-project-id')
        get_metadata.assert_called_once_with(
            path=[
                'project',
                'project-id'
            ],
            recursive=False
        )

    @mock.patch(METADATA_SERVER, return_value=FOREVER_TOKEN)
    def test_refresh_token(self, get_metadata):
        credentials = AppAssertionCredentials()
        self.assertIsNone(credentials.access_token)

        with mock.patch('oauth2client.contrib.gce._NOW',
                        side_effect=[
                            datetime.min,
                            datetime.max
                        ]):
            credentials.get_access_token()
            self.assertTrue(credentials.access_token_expired)

        with mock.patch('oauth2client.contrib.gce._NOW',
                        side_effect=[
                            datetime.max - timedelta(
                                seconds=get_metadata.return_value['expires_in']
                            ),  # Force refresh
                            datetime.min,
                            datetime.min
                        ]):
            credentials.get_access_token()
            self.assertFalse(credentials.access_token_expired)

    @mock.patch('warnings.warn')
    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_create_scoped_valid(self, get_metadata, warn_mock):
        scope = 'https://www.googleapis.com/auth/cloud-platform'
        credentials = AppAssertionCredentials()
        credentials.create_scoped(scope)
        warn_mock.assert_called_once_with(_SCOPES_WARNING)


class TestAppAssertionCredentialsSerializeDeserialize(unittest2.TestCase):

    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_serialize_deserialize(self, get_metadata):
        credentials = AppAssertionCredentials()
        credentials_from_json = Credentials.new_from_json(
            credentials.to_json()
        )
        self.assertEqual(
            credentials.service_account_info,
            credentials_from_json.service_account_info
        )

    @mock.patch('warnings.warn')
    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_create_scoped_valid(self, get_metadata, warn_mock):
        scope = 'https://www.googleapis.com/auth/cloud-platform'
        credentials = AppAssertionCredentials()
        credentials.create_scoped(scope)
        warn_mock.assert_called_once_with(_SCOPES_WARNING)

    def test_sign_blob(self):
        with mock.patch(METADATA_SERVER,
                        side_effect=[A_SERVICE_ACCOUNT,
                                     'a-project-id',
                                     FOREVER_TOKEN]) as m:
            http = _http_mock(
                http_client.OK,
                {'keyId': '1234', 'signature': 'FoOB4R'}
            )
            request_orig = http.request
            with mock.patch('httplib2.Http', return_value=http):
                credentials = AppAssertionCredentials()
                self.assertIsNone(credentials._iam_signer)
                key_id, signature = credentials.sign_blob(b'1234')
                m.assert_has_calls([
                    mock.call(
                        path=[
                            'instance',
                            'service-accounts',
                            'default'
                        ],
                        http_request=None
                    ),
                    mock.call(
                        path=[
                            'project',
                            'project-id'
                        ],
                        recursive=False
                    ),
                    mock.call(
                        path=[
                            'instance',
                            'service-accounts',
                            A_SERVICE_ACCOUNT['email'],
                            'token'
                        ],
                        http_request=request_orig
                    )
                ])
                self.assertIsNotNone(credentials._iam_signer)
                self.assertEquals((key_id, signature), ('1234', 'FoOB4R'))

            request_orig.assert_called_once_with(
                IAM_SIGN_BLOB_ENDPOINT.format(
                    project_id='a-project-id',
                    service_account_email=A_SERVICE_ACCOUNT['email']
                ),
                'POST',
                json.dumps({'bytesToSign': b'1234'}),
                {'Authorization': 'Bearer ' + FOREVER_TOKEN['access_token']},
                5,
                None
            )

    @mock.patch(METADATA_SERVER, return_value=A_SERVICE_ACCOUNT)
    def test_save_to_well_known_file(self, get_metadata):
        with tempfile.NamedTemporaryFile() as f:
            credentials = AppAssertionCredentials()
            save_to_well_known_file(credentials, well_known_file=temp.name)
            self.assertIsNotNone(temp.read())

    # ERROR TESTS

    def test_refresh_failure_bad_json(self):
        http = mock.MagicMock()
        content = '{BADJSON'
        http.request = mock.MagicMock(
            return_value=(httplib2.Response({
                'status': http_client.OK,
                'content-type': 'application/json'
            }), content))

        credentials = AppAssertionCredentials()
        self.assertRaises(
            ValueError,
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
        with self.assertRaises(HttpAccessTokenRefreshError):
            credentials.refresh(http)

    def test_scopes_failure(self):
        # Set-up the mock.
        http = mock.MagicMock()
        content = '{}'
        http.request = mock.MagicMock(
            return_value=(mock.Mock(status=http_client.NOT_FOUND), content))
        # Test the failure.
        credentials = AppAssertionCredentials()

        with self.assertRaises(MetadataServerHttpError):
            credentials._retrieve_scopes(http.request)

        self.assertEqual(
            credentials._service_account_info['email'],
            'default'
        )
        self.assertFalse(
            'scopes' in credentials._service_account_info
        )


class Test__get_metadata(unittest2.TestCase):

    def test_success(self):
        http_request = mock.MagicMock()
        data = json.dumps(A_SERVICE_ACCOUNT).encode('utf-8')
        http_request.return_value = (
            httplib2.Response({'status': http_client.OK,
                               'content-type': 'application/json'}), data)
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
        with self.assertRaises(MetadataServerHttpError):
            _get_metadata(http_request)

        http_request.assert_called_once_with(
            _METADATA_ROOT + '/?recursive=true',
            headers={'Metadata-Flavor': 'Google'})

    def test_success_not_json(self):
        http_request = mock.MagicMock()
        data = '12345'.encode('utf-8')
        http_request.return_value = (
            httplib2.Response({'status': http_client.OK,
                               'content-type': 'text/plain'}), data)
        result = _get_metadata(http_request, recursive=False)
        self.assertEqual(result, data.decode('utf-8'))
        http_request.assert_called_once_with(
            _METADATA_ROOT,
            headers={'Metadata-Flavor': 'Google'})


if __name__ == '__main__':  # pragma: NO COVER
    unittest2.main()
