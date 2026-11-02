from dataclasses import dataclass, field
from typing import Dict, List, Optional

from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.key_capsule import KeyCapsule
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey


@dataclass
class DataKeyMaterials:
    plaintext_data_key: bytes = b""
    ciphertext_data_keys: List[CiphertextDataKey] = field(default_factory=list)
    encryption_contexts: Dict[str, str] = field(default_factory=dict)
    crypto_algorithm: Optional[CryptoAlgorithm] = None
    key_capsule: Optional[KeyCapsule] = None
    policy_id: Optional[str] = None
    key_policy: Optional[str] = None
