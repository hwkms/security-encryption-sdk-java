from huaweicloud_encryptionsdk.common.ecs_metadata_service import EcsMetadataService
from huaweicloud_encryptionsdk.proof.attestation_document import AttestationDocument
from huaweicloud_encryptionsdk.proof.proof_collector import ProofCollector
from huaweicloud_encryptionsdk.proof.proof_info import ProofInfo


class EcsProofCollector(ProofCollector):

    def collect(self, proof_info: ProofInfo) -> AttestationDocument:
        signature = EcsMetadataService.fetch_identity_signature()
        return AttestationDocument(ecs_signature=signature)
