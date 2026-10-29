from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class ProofInfo:
    type: int = 0
    encrypted_private_key: Optional[str] = None
    private_key_decrypt_callback: Optional[Callable[[str], str]] = None
    key_capsule: Optional[str] = None
