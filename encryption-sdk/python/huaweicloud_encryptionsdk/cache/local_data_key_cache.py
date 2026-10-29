import time
import threading
from collections import OrderedDict
from typing import Optional, List

from huaweicloud_encryptionsdk.cache.data_key_cache import DataKeyCache, UsageStatus, EncryptCacheEntry, DecryptCacheEntry
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials


class _BaseEntry:

    def __init__(self, key: str, expire_timestamp: int, material: Optional[DataKeyMaterials] = None, usage_status: Optional[UsageStatus] = None):
        self.key = key
        self.expire_timestamp = expire_timestamp
        self.create_timestamp = int(time.time() * 1000)
        self.material = material
        self.usage_status = usage_status
        self._lock = threading.Lock()

    def is_expired(self) -> bool:
        return int(time.time() * 1000) > self.expire_timestamp

    def add_usage_info(self, usage_status: UsageStatus) -> UsageStatus:
        with self._lock:
            self.usage_status = self.usage_status.add(usage_status)
            return self.usage_status

    def __lt__(self, other):
        if self.expire_timestamp != other.expire_timestamp:
            return self.expire_timestamp < other.expire_timestamp
        return self.create_timestamp < other.create_timestamp

    def __eq__(self, other):
        if not isinstance(other, _BaseEntry):
            return False
        return (self.expire_timestamp == other.expire_timestamp
                and self.create_timestamp == other.create_timestamp
                and self.key == other.key)

    def __hash__(self):
        return hash((self.key, self.expire_timestamp, self.create_timestamp))


class _EncryptionEntryExposed(EncryptCacheEntry):

    def __init__(self, entry: _BaseEntry, usage_status: UsageStatus):
        self._entry = entry
        self._usage_status = usage_status

    def get_usage_status(self) -> UsageStatus:
        return self._usage_status

    def get_data_key_materials(self) -> DataKeyMaterials:
        return self._entry.material

    def invalidate(self) -> None:
        pass


class _DecryptionEntry(_BaseEntry, DecryptCacheEntry):

    def get_data_key_materials(self) -> DataKeyMaterials:
        return self.material

    def invalidate(self) -> None:
        pass


class LocalDataKeyCache(DataKeyCache):

    DEFAULT_CAPACITY = 1 << 4
    DEFAULT_TTL = 1000000

    def __init__(self):
        self._capacity = self.DEFAULT_CAPACITY
        self._key_expire_time = self.DEFAULT_TTL
        self._cache: OrderedDict[str, _BaseEntry] = OrderedDict()
        self._tree_set: List[_BaseEntry] = []
        self._lock = threading.Lock()

    def set_capacity(self, capacity: int) -> None:
        self._capacity = capacity

    def get_entry_for_encrypt(self, cache_id: str, usage_status: UsageStatus) -> Optional[EncryptCacheEntry]:
        entry = self._get_entry(cache_id)
        if entry is None:
            return None
        if entry.is_expired():
            self._remove_entry(entry)
            return None
        status = entry.add_usage_info(usage_status)
        return _EncryptionEntryExposed(entry, status)

    def put_entry_for_encrypt(self, cache_id: str, data_key_materials: DataKeyMaterials, initial_usage: UsageStatus) -> None:
        base_entry = _BaseEntry(cache_id, self._key_expire_time + int(time.time() * 1000), data_key_materials, initial_usage)
        self._put_entry(base_entry)

    def put_entry_for_encrypt_with_ttl(self, cache_id: str, survive_time: int, data_key_materials: DataKeyMaterials, initial_usage: UsageStatus) -> None:
        base_entry = _BaseEntry(cache_id, survive_time + int(time.time() * 1000), data_key_materials, initial_usage)
        self._put_entry(base_entry)

    def get_entry_for_decrypt(self, cache_id: str) -> Optional[DecryptCacheEntry]:
        entry = self._get_entry(cache_id)
        if entry is None:
            return None
        if entry.is_expired():
            self._remove_entry(entry)
            return None
        return _DecryptionEntry(entry.key, entry.expire_timestamp, entry.material, entry.usage_status)

    def put_entry_for_decrypt(self, cache_id: str, data_key_materials: DataKeyMaterials) -> None:
        entry = _DecryptionEntry(cache_id, self._key_expire_time + int(time.time() * 1000), data_key_materials, None)
        self._put_entry(entry)

    def put_entry_for_decrypt_with_ttl(self, cache_id: str, survive_time: int, data_key_materials: DataKeyMaterials) -> None:
        entry = _DecryptionEntry(cache_id, survive_time + int(time.time() * 1000), data_key_materials, None)
        self._put_entry(entry)

    def set_survival_time(self, survival_time: int) -> None:
        self._key_expire_time = survival_time

    def _get_entry(self, key: str) -> Optional[_BaseEntry]:
        with self._lock:
            entry = self._cache.get(key)
            if entry is not None:
                self._cache.move_to_end(key)
            return entry

    def _remove_entry(self, entry: _BaseEntry) -> None:
        with self._lock:
            self._cache.pop(entry.key, None)
            try:
                self._tree_set.remove(entry)
            except ValueError:
                pass

    def _put_entry(self, entry: _BaseEntry) -> None:
        with self._lock:
            old_entry = self._cache.pop(entry.key, None)
            if old_entry is not None:
                try:
                    self._tree_set.remove(old_entry)
                except ValueError:
                    pass
            self._cache[entry.key] = entry
            self._tree_set.append(entry)
            self._tree_set.sort()
            now = int(time.time() * 1000)
            while self._tree_set and self._tree_set[0].expire_timestamp < now:
                expired = self._tree_set.pop(0)
                self._cache.pop(expired.key, None)
            self._check_capacity()

    def _check_capacity(self) -> None:
        while len(self._cache) > self._capacity:
            oldest_key = next(iter(self._cache))
            old_entry = self._cache.pop(oldest_key)
            try:
                self._tree_set.remove(old_entry)
            except ValueError:
                pass
