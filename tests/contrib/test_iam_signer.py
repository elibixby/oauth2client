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

"""Unit tests for oauth2client.contrib.iam_signer."""

from six.moves import http_client
import unittest2
import mock
import json

import httplib2
from oauth2client.contrib.gce import AppAssertionCredentials
from oauth2client.contrib.iam_signer import IAMSigner,\
    IAM_SIGN_BLOB_ENDPOINT

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


def _http_mock(status, content):
    http = mock.MagicMock()
    http.request = mock.MagicMock(
        return_value=(
            mock.MagicMock(status=status),
            json.dumps(content).encode('utf-8')
        )
    )
    return http


class IAMSignerTests(unittest2.TestCase):

    def test_constructor(self):
        signer = IAMSigner('a-project', 'a@example.com', httplib2.Http())
        self.assertEqual(
            signer._iam_endpoint,
            IAM_SIGN_BLOB_ENDPOINT.format(
                project_id='a-project',
                service_account_email='a@example.com'
            )
        )

    def test_from_credentials(self):
        with mock.patch(METADATA_SERVER,
                        side_effect=[VALID_SERVICE_ACCOUNT,
                                     'a-project-id']) as m:
            IAMSigner.from_credentials(AppAssertionCredentials())
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
                )
            ])

    @mock.patch(METADATA_SERVER, return_value=INVALID_SERVICE_ACCOUNT)
    def test_from_credentials_bad_scopes(self, m):
        error = None
        try:
            IAMSigner.from_credentials(AppAssertionCredentials())
            m.assert_called_once_with(
                path=[
                    'instance',
                    'service-accounts',
                    'default'
                ],
                http_request=None
            )
        except ValueError as e:
            error = e
        self.assertIsNotNone(error)

    def test_sign_blob_success(self):
        http = _http_mock(
            http_client.OK,
            {'keyId': 'abc123', 'signature': 'FoOB4R'}
        )
        signer = IAMSigner('a-project-id', 'a@example.com', http)
        keyId, signature = signer.sign_blob(b'1234')
        http.request.assert_called_once_with(
            IAM_SIGN_BLOB_ENDPOINT.format(
                project_id='a-project-id',
                service_account_email='a@example.com'
            ),
            method='POST',
            body=json.dumps({'bytesToSign': b'1234'})
        )
        self.assertEqual((keyId, signature), ('abc123', 'FoOB4R'))

    def test_sign_blob_failure(self):
        http = _http_mock(http_client.NOT_FOUND, {})
        signer = IAMSigner('a-project-id', 'a@example.com', http)
        error = None
        try:
            signer.sign_blob(b'1234')
        except ValueError as e:
            error = e
        http.request.assert_called_once_with(
            IAM_SIGN_BLOB_ENDPOINT.format(
                project_id='a-project-id',
                service_account_email='a@example.com'
            ),
            method='POST',
            body=json.dumps({'bytesToSign': b'1234'})
        )
        self.assertIsNotNone(error)


if __name__ == '__main__':  # pragma: NO COVER
    unittest2.main()
