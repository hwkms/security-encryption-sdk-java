from abc import ABC, abstractmethod
from typing import Optional

from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.common.utils import add_prevent_overflow


class UsageStatus:

    def __init__(self, bytes_encrypt_count: int, message_encrypt_count: int):
        self._bytes_encrypt_count = bytes_encrypt_count
        self._message_encrypt_count = message_encrypt_count

    @property
    def bytes_encrypt_count(self) -> int:
        return self._bytes_encrypt_count

    @property
    def message_encrypt_count(self) -> int:
        return self._message_encrypt_count

    def add(self, other: "UsageStatus") -> "UsageStatus":
        return UsageStatus(
            add_prevent_overflow(self._bytes_encrypt_count, other._bytes_encrypt_count),
            add_prevent_overflow(self._message_encrypt_count, other._message_encrypt_count),
        )


class EncryptCacheEntry(ABC):

    @abstractmethod
    def get_usage_status(self) -> UsageStatus:
        pass

    @abstractmethod
    def get_data_key_materials(self) -> DataKeyMaterials:
        pass

    def invalidate(self) -> None:
        pass


class DecryptCacheEntry(ABC):

    @abstractmethod
    def get_data_key_materials(self) -> DataKeyMaterials:
        pass

    def invalidate(self) -> None:
        pass


class DataKeyCache(ABC):

    @abstractmethod
    def get_entry_for_encrypt(self, cache_id: str, usage_status: UsageStatus) -> Optional[EncryptCacheEntry]:
        pass

    @abstractmethod
    def put_entry_for_encrypt(self, cache_id: str, data_key_materials: DataKeyMaterials, initial_usage: UsageStatus) -> None:
        pass

    def put_entry_for_encrypt_with_ttl(self, cache_id: str, survive_time: int, data_key_materials: DataKeyMaterials, initial_usage: UsageStatus) -> None:
        self.put_entry_for_encrypt(cache_id, data_key_materials, initial_usage)

    @abstractmethod
    def get_entry_for_decrypt(self, cache_id: str) -> Optional[DecryptCacheEntry]:
        pass

    @abstractmethod
    def put_entry_for_decrypt(self, cache_id: str, data_key_materials: DataKeyMaterials) -> None:
        pass

    def put_entry_for_decrypt_with_ttl(self, cache_id: str, survive_time: int, data_key_materials: DataKeyMaterials) -> None:
        self.put_entry_for_decrypt(cache_id, data_key_materials)

    @abstractmethod
    def set_survival_time(self, survival_time: int) -> None:
        pass
