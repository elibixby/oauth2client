from six.moves import http_client
import httplib2
from oauth2client._helpers import _from_bytes
import json

__author__ = 'elibixby@google.com (Eli Bixby)'

_IAM_ROOT = 'https://iam.googleapis.com/v1/'

_SIGN_BLOB = _IAM_ROOT + (
    'projects/{project_id}/'
    'serviceAccounts/{service_account_email}:signBlob'
)

IAM_SCOPES = set([
    'https://www.googleapis.com/auth/iam',
    'https://www.googleapis.com/auth/cloud-platform'
])

_SCOPES_ERROR = ('Provided credentials must have one of {iam_scopes}'
                 'to call the iam API').format(IAM_SCOPES)


class Iam:
    # TODO(elibixby) add test_permissions method once roll recommendations
    # can be made with iam.roles()

    def __init__(self, credentials, http=None):
        """Constructor for IAMSigner.

        Args:
            http:
                an httplib2.Http like client
                see: https://cloud.google.com/iam/reference/rest/v1/
        """
        if credentials.create_scope_required:
            credentials = credentials.create_scoped(IAM_SCOPES)
        elif not set(credentials.scopes) & IAM_SCOPES:
            raise AttributeError(_SCOPES_ERROR)

        self._http = credentials.authorize(http or httplib2.Http())

    def sign_blob(self, project_id, service_account_email, blob):
        """Signs a blob with the Google Cloud IAM API.

        Args:
            project_id:
                The project_id for the project that owns the specified
                service account
            service_account_email:
                The email for the service account who's private key will
                be used to sign the blob.
            blob:
                bytes to sign

        Returns:
            A tuple of strings (key, signature) where key is the private
            key used to sign the blob, and signature is the signed blob

        See: https://cloud.google.com/iam/reference/rest/v1/
        """
        response, content = self._http.request(
            _SIGN_BLOB.format(
                project_id=project_id,
                service_account_email=service_account_email
            ),
            method='POST',
            body=json.dumps({'bytesToSign': blob})
        )

        if response.status == http_client.OK:
            d = json.loads(_from_bytes(content))
            return d['keyId'], d['signature']
        else:
            raise ValueError(str(response))
