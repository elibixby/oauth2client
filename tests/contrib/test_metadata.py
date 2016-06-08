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

"""Unit tests for oauth2client.contrib.metadata"""
import datetime
import json
import mock
import unittest2

from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.contrib.metadata import MetadataServer
from oauth2client.contrib.metadata import MetadataServerHttpError
from oauth2client.contrib.metadata import NestedDict

PATH = ['a', 'b']
DATA = {'foo': 'bar'}
EXPECTED_ARGS = ['http://metadata.google.internal/computeMetadata/v1/a/b/?recursive=true']
EXPECTED_KWARGS = dict(headers={'Metadata-Flavor': 'Google'})


def get_json_request_mock():
    return mock.MagicMock(return_value=(
        {'status': http_client.OK, 'content-type': 'application/json'},
        json.dumps(DATA).encode('utf-8')
    ))

def get_string_request_mock():
    return mock.MagicMock(return_value=(
        {'status': http_client.OK, 'content-type': 'text/html'},
        '<p>Hello World!</p>'.encode('utf-8')
    ))


def get_error_request_mock():
    return mock.MagicMock(return_value=(
        {'status': http_client.NOT_FOUND, 'content-type': 'text/html'},
        '<p>Error</p>'.encode('utf-8')
    ))


class TestNestedDict(unittest2.TestCase):

    def test_get_path(self):
        self.assertEqual(NestedDict(a={'b': {'c': 'd'}}).get_path(['a','b','c']), 'd')

    def test_set_path(self):
        test_dict = NestedDict(a={'b': {'c': 'd'}})
        test_dict.set_path(['a','b', 'e'], 'f')
        self.assertEqual(test_dict, {'a': {'b': {'c': 'd', 'e': 'f'}}})


class TestMetadata(unittest2.TestCase):

    def test_constructor(self):
        cache = NestedDict(a='b', c={'d': 'e'})
        self.assertEqual(MetadataServer(cache=cache).cache, cache)

    def test_make_request_success_json(self):
        http_request = get_json_request_mock()
        metadata = MetadataServer()
        self.assertEqual(
            metadata._make_request(PATH, http_request=http_request),
            DATA
        )
        http_request.assert_called_once_with(
            )

    def test_make_request_success_string(self):
        http_request = get_string_request_mock()
        metadata = MetadataServer()
        self.assertEqual(
            metadata._make_request(PATH, http_request=http_request),
            '<p>Hello World!</p>'
        )
        http_request.assert_called_once_with(*EXPECTED_ARGS, **EXPECTED_KWARGS)

    def test_make_request_failure(self):
        http_request = get_error_request_mock()
        metadata = MetadataServer()
        with self.assertRaises(MetadataServerHttpError):
            metadata._make_request(PATH, http_request=http_request)

        http_request.assert_called_once_with(*EXPECTED_ARGS, **EXPECTED_KWARGS)

    def test_get_cached_present(self):
        cache = NestedDict(a={'b': DATA})
        http_request = get_json_request_mock()
        metadata = MetadataServer(cache=cache)

        result = metadata.get(PATH, http_request=http_request)
        self.assertEqual(result, DATA)
        http_request.assert_not_called()

    def test_get_cached_absent(self):
        http_request = get_json_request_mock()
        metadata = MetadataServer()
        self.assertEqual(
            metadata.get(PATH, http_request=http_request),
            DATA
        )
        http_request.assert_called_once_with(*EXPECTED_ARGS, **EXPECTED_KWARGS)
        self.assertTrue(PATH[0] in metadata.cache)
        self.assertTrue(PATH[1] in metadata.cache[PATH[0]])
        self.assertEqual(metadata.cache['a']['b'], DATA)

    def test_uncached(self):
        http_request = get_json_request_mock()
        cache = NestedDict()
        metadata = MetadataServer(cache=cache)
        self.assertEqual(
            metadata.get(PATH, use_cache=False, http_request=http_request),
            DATA
        )
        http_request.assert_called_once_with(*EXPECTED_ARGS, **EXPECTED_KWARGS)
        self.assertTrue('a' not in metadata.cache)

    @mock.patch('oauth2client.client._UTCNOW', return_value=datetime.datetime.min)
    def test_get_token_success(self):
        http_request = mock.MagicMock(
            return_value=(
                {'status': http_client.OK, 'content-type': 'application/json'},
                json.dumps({'access_token': 'a', 'expires_in': 100}).encode('utf-8')
            )
        )
        metadata = MetadataServer()
        token, expiry = metadata.get_token(http_request=http_request)
        self.assertEqual(token, 'a')
        self.assertEqual(expiry, datetime.datetime.min + datetime.timedelta(seconds=100))
        http_request.assert_called_once_with(
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            **EXPECTED_KWARGS
        )

    def test_get_token_failed_fetch(self):
        http_request = mock.MagicMock(
            return_value=(
                {'status': http_client.NOT_FOUND, 'content-type': 'application/json'},
                json.dumps({'access_token': 'a', 'expires_in': 100}).encode('utf-8')
            )
        )
        metadata = MetadataServer()
        with self.assertRaises(HttpAccessTokenRefreshError):
            metadata.get_token(http_request=http_request)

        http_request.assert_called_once_with(
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            **EXPECTED_KWARGS
        )

    def test_service_account_info(self):
        http_request = get_json_request_mock()
        metadata = MetadataServer()
        info = metadata.get_service_account_info(http_request=http_request)
        self.assertEqual(info, DATA)

        http_request.assert_called_once_with(
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/?recursive=true',
            **EXPECTED_KWARGS
        )
