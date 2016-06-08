# Copyright 2016 Google Inc. All rights reserved.
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

METADATA_ROOT = 'http://metadata.google.internal/computeMetadata/v1/'
METADATA_HEADERS = {'Metadata-Flavor': 'Google'}


def get(path, recursive=True, http_request=None, root=METADATA_ROOT):
    if path is None:
        path = []

    if not http_request:
        http_request = httplib2.Http().request

    r_string = '/?recursive=true' if recursive else ''
    full_path = root + '/'.join(path) + r_string
    response, content = http_request(
        full_path,
        headers=METADATA_HEADERS
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
        raise httplib2.HttpLib2Error(msg)


def get_service_account_info(service_account='default', http_request=None):
    """ Get information about a service account from the metadata server.
    :param service_account: a service account email. Left blank information for
        the default service account of current compute engine instance will be looked up.
    :param http_request: callable, a callable that matches the method
        signature of httplib2.Http.request, used to make
        the refresh request.
    :return: A dictionary with information about the specified service account.
    """
    return get(
        ['instance', 'service-accounts', service_account],
        recursive=True,
        http_request=http_request
    )


def get_token(service_account='default', http_request=None):
    """Fetch an OAuth access token from the metadata server
    :param service_account: a service account email. Left blank information for
        the default service account of current compute engine instance will be looked up.
    :param http_request: callable, a callable that matches the method
        signature of httplib2.Http.request, used to make
        the refresh request.
    :return:
    """
    try:
        token_json = get(
            ['instance', 'service-accounts', service_account, 'token'],
            recursive=False,
            http_request=http_request
        )
    except httplib2.HttpLib2Error as failed_fetch:
        raise HttpAccessTokenRefreshError(str(failed_fetch))

    token_expiry = _UTCNOW() + datetime.timedelta(
        seconds=token_json['expires_in'])
    return token_json['access_token'], token_expiry
