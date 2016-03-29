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

    @util.positional(1)
    def __init__(self,
                 project_id=None,
                 service_account_email=None,
                 http=None):
        """Constructor for IAMSigner.
        Args:
            project_id:
                the project id for the project that owns the specified service
                account
            service_account_email:
                the email for the service account to sign with
            http:
                an httplib2.Http like client that is authenticated with
                the proper scopes to call the iam API, and able to access
                the service account given in 'service_account_email'.
                Scopes can be checked with IAMSigner.has_scopes(credentials)
        """
        self._iam_endpoint = IAM_SERVICE_ACCOUNT_ENDPOINT.format(
            project_id=project_id,
            service_account_email=service_account_email
        )
        self._http = http

    @classmethod
    def from_credentials(cls, credentials):
        if not cls.check_scopes(credentials):
            raise ValueError(
                ('Insufficient scopes to sign a blob with iam,'
                 'requires one of {iam_scopes}').format(iam_scopes=IAM_SCOPES)
            )
        return cls(
            credentials.project_id,
            credentials.service_account_email,
            credentials.authorize(httplib2.Http())
        )

    @classmethod
    def has_scopes(cls, credentials):
        return credentials.has_scopes(
            IAM_SCOPES[0]
        ) or credentials.has_scopes(
            IAM_SCOPES[1]
        )

    def sign_blob(self, blob):
        """Signs a blob with the Google Cloud IAM API.
        See: https://cloud.google.com/iam/reference/rest/v1/
        """
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
