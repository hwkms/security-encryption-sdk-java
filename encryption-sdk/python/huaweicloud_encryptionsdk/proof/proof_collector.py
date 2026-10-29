from abc import ABC, abstractmethod

from huaweicloud_encryptionsdk.proof.proof_info import ProofInfo
from huaweicloud_encryptionsdk.proof.attestation_document import AttestationDocument


class ProofCollector(ABC):

    @abstractmethod
    def collect(self, proof_info: ProofInfo) -> AttestationDocument:
        pass
