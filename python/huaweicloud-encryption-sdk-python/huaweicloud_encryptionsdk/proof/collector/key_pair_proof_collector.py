import base64
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from cryptography.hazmat.primitives import hashes, serialization

from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.proof.attestation_document import AttestationDocument
from huaweicloud_encryptionsdk.proof.proof_collector import ProofCollector
from huaweicloud_encryptionsdk.proof.proof_info import ProofInfo
from huaweicloud_encryptionsdk.common.ec_private_key_loader import ECPrivateKeyLoader


class KeyPairProofCollector(ProofCollector):

    def collect(self, proof_info: ProofInfo) -> AttestationDocument:
        private_key_str = proof_info.private_key_decrypt_callback(proof_info.encrypted_private_key)
        private_key = ECPrivateKeyLoader.load(private_key_str)
        expire_time = self._get_expire_time()
        origin_text = (proof_info.key_capsule or "") + expire_time
        signature = self._get_signature(private_key, origin_text)
        return AttestationDocument(
            custom_public_key=self._get_public_key_from_private_key(private_key),
            custom_signature=signature,
            expire_time=expire_time,
        )

    @staticmethod
    def _get_public_key_from_private_key(private_key) -> str:
        try:
            public_key = private_key.public_key()
            public_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return base64.b64encode(public_der).decode("utf-8")
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.GET_PUB_KEY_EXCEPTION.message, e)

    @staticmethod
    def _get_signature(private_key, origin_text: str) -> str:
        try:
            signature_bytes = private_key.sign(
                origin_text.encode("utf-8"),
                ec.ECDSA(hashes.SHA256()),
            )
            return base64.b64encode(signature_bytes).decode("utf-8")
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.COLLECT_PROOF_EXCEPTION.message, e)

    @staticmethod
    def _get_expire_time() -> str:
        expire = datetime.now(timezone.utc) + timedelta(minutes=30)
        expire = expire.replace(microsecond=0)
        return expire.isoformat().replace("+00:00", "Z")
