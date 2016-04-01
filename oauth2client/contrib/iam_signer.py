from six.moves import http_client
from oauth2client._helpers import _from_bytes
import httplib2
import json

__author__ = 'elibixby@google.com (Eli Bixby)'

IAM_SIGN_BLOB_ENDPOINT = (
    'https://iam.googleapis.com/v1/projects/{project_id}/'
    'serviceAccounts/{service_account_email}:signBlob'
)

IAM_SCOPES = set([
    'https://www.googleapis.com/auth/iam',
    'https://www.googleapis.com/auth/cloud-platform'
])

FORBIDDEN_ERROR = (
    'The credentials do not have permission to sign blobs on behalf '
    'of service account {service_account_email}. Go to '
    'https://console.cloud.google.com/permissions/serviceaccounts'
    '?project={project_id} and add your credentials as a '
    '\"Service Account Actor\" to {service_account_email} to enable IAM blob '
    'signing. The server response is: {response}'
)


class IAMSigner:

    def __init__(self, project_id, service_account_email, http):
        """Constructor for IAMSigner.

        Args:
            project_id:
                the project id for the project that owns the specified service
                account
            service_account_email:
                the email for the service account to sign blobs with
            http:
                an httplib2.Http like client that is authenticated with
                the proper scopes to call the iam API, and have
                "roles/iam.serviceAccountActor" on the service account
                specified with project_id and service_account_email.
                Scopes can be checked with
                `(set(scopes) & iam_signer.IAM_SCOPES)`.
                Role permissions may be checked by attempting to sign a blob,
                or making a testIamPermissions call
                see: https://cloud.google.com/iam/reference/rest/v1/
        """
        self._iam_endpoint = IAM_SIGN_BLOB_ENDPOINT.format(
            project_id=project_id,
            service_account_email=service_account_email
        )
        self._project_id = project_id
        self._service_account_email = service_account_email
        self._http = http

    @classmethod
    def from_credentials(cls, credentials, http=None):
        """Convenience method, constructs an IAMSigner from credentials.

        This method assumes `project_id` and `service_account_email` as
        properties on your credentials. It also checks that your credentials
        have sufficient scopes to access the IAM API.
        """
        if not set(credentials.scopes) & IAM_SCOPES:
            raise ValueError(
                ('Insufficient scopes to sign a blob with iam,'
                 'requires one of {iam_scopes}').format(iam_scopes=IAM_SCOPES)
            )
        return cls(
            credentials.project_id,
            credentials.service_account_email,
            credentials.authorize(http or httplib2.Http())
        )

    def sign_blob(self, blob):
        """Signs a blob with the Google Cloud IAM API.

        See: https://cloud.google.com/iam/reference/rest/v1/
        """
        response, content = self._http.request(
            self._iam_endpoint,
            method='POST',
            body=json.dumps({'bytesToSign': blob})
        )

        if response.status == http_client.OK:
            d = json.loads(_from_bytes(content))
            return d['keyId'], d['signature']
        if response.status == http_client.FORBIDDEN:
            raise ValueError(FORBIDDEN_ERROR.format(
                project_id=self._project_id,
                service_account_email=self._service_account_email,
                response=str(response)
            ))
        else:
            raise ValueError(str(response))
