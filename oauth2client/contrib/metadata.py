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

"""Thin wrapper class for talking to the GCE Metadata Server."""
import datetime
import httplib2
import json

from six.moves import http_client

from oauth2client._helpers import _from_bytes
from oauth2client.client import _UTCNOW
from oauth2client.client import HttpAccessTokenRefreshError

class NestedDict(dict):
    """Stores a dict and allows setting and retrieving
     values by path (list of keys)."""

    def get_path(self, path):
        leaf = self
        for key in path:
            leaf = leaf.get(key)
            if leaf is None:
                return None
        return leaf

    def set_path(self, path, value):
        leaf = self
        for key in path[:-1]:
            leaf = leaf.setdefault(key, {})
        leaf[path[-1]] = value


class MetadataServerHttpError(Exception):
    """Error for Http failures originating from the Metadata Server"""


class MetadataServer:
    """handles requests to and from the metadata server,
     and caches requests by default"""

    def __init__(self,
                 client=None,
                 cache=None,
                 root='http://metadata.google.internal/computeMetadata/v1/'):
        self._client = client or httplib2.Http()
        self._root = root
        self.cache = cache or NestedDict()

    def _make_request(self, path, recursive=True, http_request=None):
        if path is None:
            path = []

        if not http_request:
            http_request = self._client.request

        r_string = '/?recursive=true' if recursive else ''
        full_path = self._root + '/'.join(path) + r_string
        response, content = http_request(
            full_path,
            headers={'Metadata-Flavor': 'Google'}
        )
        if response.status == http_client.OK:
            decoded = _from_bytes(content)
            if response['content-type'] == 'application/json':
                return json.loads(decoded)
            else:
                return decoded
        else:
            msg = (
                'Failed to retrieve {path} from the Google Compute Engine'
                'metadata service. Response:\n{error}'
            ).format(path=full_path, error=response)
            raise MetadataServerHttpError(msg)

    def get(self, path, use_cache=True, recursive=True, http_request=None):
        """ Retrieve a value from the metadata server.
        :param path: Path on the metadata server to fetch from
        :param use_cache: Use a cached value (if available) and update the cache (if not)
        :param recursive: True if this is not a leaf
        :param http_request: callable, a callable that matches the method
            signature of httplib2.Http.request, used to make
            the refresh request.
        :return: The value from the metadata server (String if recursive=False, dict otherwise)
        """

        if use_cache:
            cached_value = self.cache.get_path(path)
            if cached_value is not None:
                return cached_value
        value = self._make_request(path, recursive=recursive, http_request=http_request)
        if use_cache:
            self.cache.set_path(path, value)
        return value

    def get_service_account_info(self, service_account='default', http_request=None):
        """ Get information about a service account from the metadata server.
        :param service_account: a service account email. Left blank information for
            the default service account of current compute engine instance will be looked up.
        :param http_request: callable, a callable that matches the method
            signature of httplib2.Http.request, used to make
            the refresh request.
        :return: A dictionary with information about the specified service account.
        """
        return self.get(
            ['instance', 'service-accounts', service_account],
            use_cache=True,
            recursive=True,
            http_request=http_request
        )

    def get_token(self, service_account='default', http_request=None):
        """Fetch an OAuth access token from the metadata server
        :param service_account: a service account email. Left blank information for
            the default service account of current compute engine instance will be looked up.
        :param http_request: callable, a callable that matches the method
            signature of httplib2.Http.request, used to make
            the refresh request.
        :return:
        """
        try:
            token_json = self.get(
                ['instance', 'service-accounts', service_account, 'token'],
                use_cache=False,
                recursive=False,
                http_request=http_request
            )
        except MetadataServerHttpError as failed_fetch:
            raise HttpAccessTokenRefreshError(str(failed_fetch))

        token_expiry = _UTCNOW() + datetime.timedelta(
            seconds=token_json['expires_in'])
        return token_json['access_token'], token_expiry


