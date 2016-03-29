from six.moves import http_client
from oauth2client._helpers import _from_bytes,\
    _json_encode
from oauth2client import util
import httplib2
import json

__author__ = 'elibixby@google.com (Eli Bixby)'

IAM_SERVICE_ACCOUNT_ENDPOINT = (
    'https://iam.googleapis.com/v1/projects/{project_id}/'
    'serviceAccounts/{service_account_email}:signBlob'
)

IAM_SCOPES = [
    'https://www.googleapis.com/auth/iam',
    'https://www.googleapis.com/auth/cloud-platform'
]


class IAMSigner:

    @util.positional(2)
    def __init__(self,
                 credentials,
                 project_id=None,
                 service_account_email=None,
                 http=None):
        if not (credentials.has_scopes(
            IAM_SCOPES[0]
        ) or credentials.has_scopes(
            IAM_SCOPES[1]
        )):
            raise ValueError(
                ('Insufficient scopes to sign a blob with iam,'
                 'requires one of {iam_scopes}').format(iam_scopes=IAM_SCOPES)
            )

        self._iam_endpoint = IAM_SERVICE_ACCOUNT_ENDPOINT.format(
            project_id=project_id or credentials.project_id,
            service_account_email=service_account_email or
            credentials.service_account_email
        )
        self._http = http or credentials.authorize(httplib2.Http())

    def sign_blob(self, blob):
        response, content = self._http.request(
            self._iam_endpoint,
            method='POST',
            body=_json_encode({'bytesToSign': blob})
        )

        if response.status == http_client.OK:
            d = json.loads(_from_bytes(content))
            return d['keyId'], d['signature']
        else:
            raise ValueError(str(response))
