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

"""Provides helper methods for talking to the Compute Engine metadata server.

See https://cloud.google.com/compute/docs/metadata
"""

import datetime
import httplib2
import json

from six.moves import http_client
from six.moves.urllib.parse import urlencode

from oauth2client._helpers import _from_bytes
from oauth2client.client import _UTCNOW

METADATA_ROOT = 'http://metadata.google.internal/computeMetadata/v1/'
METADATA_HEADERS = {'Metadata-Flavor': 'Google'}


def get(path, http_request=None, root=METADATA_ROOT, **kwargs):
    if path is None:
        path = []

    if not http_request:
        http_request = httplib2.Http().request

    if kwargs:
        path.append('?' + urlencode(kwargs))

    full_path = root + '/'.join(path)
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
        raise httplib2.HttpLib2Error(
            (
                'Failed to retrieve {path} from the Google Compute Engine'
                'metadata service. Response:\n{error}'
            ).format(path=full_path, error=response)
        )


def get_service_account_info(service_account='default', http_request=None):
    """ Get information about a service account from the metadata server.

    Args:
        service_account: An email specifying the service account for which to
            look up information. Default will be information for the "default"
            service account of the current compute engine instance.
        http_request: callable, a callable that matches the method
            signature of httplib2.Http.request. Used to make the request to the metadata
            server.
    Returns:
         A dictionary with information about the specified service account.
    """
    return get(
        ['instance', 'service-accounts', service_account],
        recursive=True,
        http_request=http_request
    )


def get_token(service_account='default', http_request=None):
    """ Fetch an oauth token for the

    Args:
        service_account: An email specifying the service account this token should
            represent. Default will be a token for the "default" service account
            of the current compute engine instance.
        http_request: callable, a callable that matches the method
            signature of httplib2.Http.request. Used to make the request to the metadata
            server.

    Returns:
         A dictionary with information about the specified service account.
    """
    token_json = get(
        ['instance', 'service-accounts', service_account, 'token'],
        http_request=http_request
    )
    token_expiry = _UTCNOW() + datetime.timedelta(
        seconds=token_json['expires_in'])
    return token_json['access_token'], token_expiry
