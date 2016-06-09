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

import datetime
import unittest2

import mock

from oauth2client.client import save_to_well_known_file
from oauth2client.contrib.gce import _SCOPES_WARNING
from oauth2client.contrib.gce import AppAssertionCredentials


__author__ = 'jcgregorio@google.com (Joe Gregorio)'


class AppAssertionCredentialsTests(unittest2.TestCase):

    def test_constructor(self):
        credentials = AppAssertionCredentials()
        self.assertEqual(credentials.assertion_type, None)

    @mock.patch('warnings.warn')
    @mock.patch('oauth2client.contrib.metadata.get_service_account_info',
                return_value={'scopes': 'a', 'email': 'a@google.com'})
    def test_constructor_with_valid_scopes(self, metadata, warn_mock):
        AppAssertionCredentials(scopes=['a'])
        warn_mock.assert_called_once_with(_SCOPES_WARNING)
        metadata.assert_called_once_with(http_request=None)

    @mock.patch('oauth2client.contrib.metadata.get_service_account_info',
                return_value={'scopes': 'b', 'email': 'a@google.com'})
    def test_constructor_with_invalid_scopes(self, metadata):
        with self.assertRaises(AttributeError):
            AppAssertionCredentials(scopes=['a'])
        metadata.assert_called_once_with(http_request=None)

    @mock.patch('oauth2client.contrib.metadata.get_token',
                side_effect=[('A', datetime.datetime.min),
                             ('B', datetime.datetime.max)])
    def test_refresh_token(self, metadata):
        credentials = AppAssertionCredentials()
        self.assertIsNone(credentials.access_token)
        credentials.get_access_token()
        self.assertEqual(credentials.access_token, 'A')
        self.assertTrue(credentials.access_token_expired)
        credentials.get_access_token()
        self.assertEqual(credentials.access_token, 'B')
        self.assertFalse(credentials.access_token_expired)

    @mock.patch('oauth2client.contrib.metadata.get_service_account_info',
                return_value={'scopes': 'b', 'email': 'a@google.com'})
    def test_get_scopes(self, metadata):
        credentials = AppAssertionCredentials()
        self.assertEqual(credentials.scopes, 'b')
        # Test Caching
        self.assertEqual(credentials.scopes, 'b')
        metadata.assert_called_once_with(http_request=None)

    @mock.patch('warnings.warn')
    @mock.patch('oauth2client.contrib.metadata.get_service_account_info',
                return_value={'scopes': 'a', 'email': 'a@google.com'})
    def test_set_scopes_with_valid_scopes(self, metadata, warn_mock):
        credentials = AppAssertionCredentials()
        credentials.scopes = ['a']
        warn_mock.assert_called_once_with(_SCOPES_WARNING)
        metadata.assert_called_once_with(http_request=None)

    @mock.patch('oauth2client.contrib.metadata.get_service_account_info',
                return_value={'scopes': 'b', 'email': 'a@google.com'})
    def test_set_scopes_with_invalid_scopes(self, metadata):
        with self.assertRaises(AttributeError):
            credentials = AppAssertionCredentials()
            credentials.scopes = ['a']
        metadata.assert_called_once_with(http_request=None)

    def test_serialization_data(self):
        credentials = AppAssertionCredentials()
        self.assertRaises(NotImplementedError, getattr,
                          credentials, 'serialization_data')

    def test_create_scoped_required(self):
        credentials = AppAssertionCredentials()
        self.assertFalse(credentials.create_scoped_required())

    def test_sign_blob_not_implemented(self):
        credentials = AppAssertionCredentials()
        with self.assertRaises(NotImplementedError):
            credentials.sign_blob(b'blob')

    @mock.patch('oauth2client.contrib.metadata.get_service_account_info',
                return_value={'email': 'a@example.com'})
    def test_service_account_email(self, metadata):
        credentials = AppAssertionCredentials()
        # Assert that service account isn't pre-fetched
        metadata.assert_not_called()
        self.assertEqual(credentials.service_account_email, 'a@example.com')

    def test_save_to_well_known_file(self):
        import os
        ORIGINAL_ISDIR = os.path.isdir
        try:
            os.path.isdir = lambda path: True
            credentials = AppAssertionCredentials()
            self.assertRaises(NotImplementedError, save_to_well_known_file,
                              credentials)
        finally:
            os.path.isdir = ORIGINAL_ISDIR


if __name__ == '__main__':  # pragma: NO COVER
    unittest2.main()
