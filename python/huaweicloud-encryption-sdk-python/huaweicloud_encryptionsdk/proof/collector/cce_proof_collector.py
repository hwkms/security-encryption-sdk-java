from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException
from huaweicloud_encryptionsdk.proof.attestation_document import AttestationDocument
from huaweicloud_encryptionsdk.proof.proof_collector import ProofCollector
from huaweicloud_encryptionsdk.proof.proof_info import ProofInfo


SERVICE_ACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


class CceProofCollector(ProofCollector):

    def collect(self, proof_info: ProofInfo) -> AttestationDocument:
        service_token = self._read_service_account_token()
        return AttestationDocument(service_token=service_token)

    @staticmethod
    def _read_service_account_token() -> str:
        try:
            with open(SERVICE_ACCOUNT_TOKEN_PATH, "r") as f:
                return f.read().strip()
        except Exception as e:
            raise HuaweicloudException(
                f"Failed to read CCE service account token from {SERVICE_ACCOUNT_TOKEN_PATH}", e
            )
