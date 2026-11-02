from dataclasses import dataclass, field
from typing import Generic, TypeVar, Optional

T = TypeVar("T")


@dataclass
class CryptoResult(Generic[T]):
    result: Optional[T] = None
    headers: Optional["CipherHeader"] = None
    data_length: int = 0
