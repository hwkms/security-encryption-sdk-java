import threading
from typing import Dict, Optional

from huaweicloud_encryptionsdk.proof.proof_collector import ProofCollector
from huaweicloud_encryptionsdk.proof.proof_info import ProofInfo
from huaweicloud_encryptionsdk.proof.attestation_document import AttestationDocument
from huaweicloud_encryptionsdk.proof.collector.ecs_proof_collector import EcsProofCollector
from huaweicloud_encryptionsdk.proof.collector.key_pair_proof_collector import KeyPairProofCollector
from huaweicloud_encryptionsdk.proof.collector.cce_proof_collector import CceProofCollector
from huaweicloud_encryptionsdk.proof.collector.ma_proof_collector import MaProofCollector


class ProofCollectorFactory:

    _COLLECTORS: Dict[int, ProofCollector] = {}
    _lock = threading.Lock()

    @classmethod
    def _init_collectors(cls):
        if not cls._COLLECTORS:
            with cls._lock:
                if not cls._COLLECTORS:
                    cls._COLLECTORS[1] = EcsProofCollector()
                    cls._COLLECTORS[2] = KeyPairProofCollector()
                    cls._COLLECTORS[3] = CceProofCollector()
                    cls._COLLECTORS[4] = MaProofCollector()

    @classmethod
    def register_collector(cls, type_val: int, collector: ProofCollector) -> None:
        if collector is None:
            raise ValueError("Type and collector cannot be null")
        with cls._lock:
            cls._COLLECTORS[type_val] = collector

    @classmethod
    def get_collector(cls, type_val: int) -> ProofCollector:
        cls._init_collectors()
        if type_val is None:
            raise ValueError("Access point type cannot be null")
        collector = cls._COLLECTORS.get(type_val)
        if collector is None:
            raise ValueError(
                f"Unsupported access point type: {type_val}. Supported types: {list(cls._COLLECTORS.keys())}"
            )
        return collector

    @classmethod
    def collect(cls, proof_info: ProofInfo) -> AttestationDocument:
        if proof_info is None:
            raise ValueError("AccessPointConfig cannot be null")
        type_val = proof_info.type
        collector = cls.get_collector(type_val)
        return collector.collect(proof_info)
