from dataclasses import dataclass
from typing import Optional

from huaweicloud_encryptionsdk.model.cipher_header import CipherHeader
from huaweicloud_encryptionsdk.model.cipher_body import CipherBody


@dataclass
class DataMaterials:
    cipher_body: Optional[CipherBody] = None
    headers: Optional[CipherHeader] = None
