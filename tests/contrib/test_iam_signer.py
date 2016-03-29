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
from oauth2client.contrib.iam_signer import IAMSigner
import tempfile

__author__ = 'elibixby@google.com (Eli Bixby)'

METADATA_SERVER = 'oauth2client.contrib.gce._get_metadata'
VALID_SERVICE_ACCOUNT = {
    'scopes': [
        'https://www.googleapis.com/auth/cloud-platform',
    ],
    'email': 'good@developer.gserviceaccount.com'
}
INVALID_SERVICE_ACCOUNT = {
    'scopes': [
        'https://www.googleapis.com/auth/bigquery',
    ],
    'email': 'bad@developer.gserviceaccount.com'
}

SIGNED_BLOB = {'keyId': 'abcd', 'signature': 'efg'}

class IAMSignerTests(unittest2.TestCase):

    def _make_valid_signer(self):
        with mock.patch.multiple(METADATA_SERVER,
                                 FIRST_PATCH=VALID_SERVICE_ACCOUNT,
                                 SECOND_PATCH='a-project-id') as m:
            http_mock = mock.MagicMock()
            http_mock.request = mock.MagicMock(
                return_value=(
                    mock.Mock(status=http_client.OK), json.dumps(
                    )
                )
            )
            credentials = AppAssertionCredentials()
            valid_signer = IAMSigner(
                credentials,
                http=self.http_mock
            )
            m.assert_called_with(
                ({
                    'path': [
                        'instance',
                        'service-accounts',
                        'default'
                    ],
                    'http_request': None
                }),
                ({
                    'path': [
                        'project',
                        'project-id'
                    ]
                })
            )
            return http_mock, credentials, valid_signer

    # BASIC TESTS

    def test_constructor_with_matching_scopes(self):
        http_mock, credentials, valid_signer = self._make_valid_signer()
        self.assertEqual(valid_signer._iam_endpoint,)

    def test_constructor_with_missing_scopes(self):
        error = None
        with mock.patch(METADATA_SERVER, return_value=INVALID_SERVICE_ACCOUNT):
            try:
                IAMSigner(AppAssertionCredentials())
            except ValueError as e:
                error = e
        self.assertIsNotNone(error)

    def test_sign_blob(self):



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
