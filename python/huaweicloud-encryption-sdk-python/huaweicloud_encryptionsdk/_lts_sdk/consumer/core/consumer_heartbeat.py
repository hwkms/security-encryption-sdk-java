import threading
from concurrent.futures import ThreadPoolExecutor

from loguru import logger

from consumer.client.consumer_client_adapter import LogConsumerClientAdapter
from consumer.model.consumer_config import ConsumerConfig
from huaweicloud_encryptionsdk._lts_sdk.utils import common, lts_threading


class LogConsumerHeartBeat(threading.Thread):
    def __init__(self, client_adapter: LogConsumerClientAdapter, config: ConsumerConfig):
        super().__init__()
        self._client_adapter = client_adapter
        self._heartbeat_interval_mill = config.heartbeat_interval_mill
        self._timeout_sec = config.timeout_sec
        self._current_held_shards = {}
        self._all_heart_shards = {}
        self._last_success_time = 0
        self._is_stop = False
        self._lock = lts_threading.ReadWriteLock()
        self._thread_pool = ThreadPoolExecutor(max_workers=10240, thread_name_prefix="io_thread_pool_sender")

    @property
    def lock(self):
        return self._lock

    @property
    def current_held_shards(self):
        return self._current_held_shards

    @current_held_shards.setter
    def current_held_shards(self, value: int):
        self._current_held_shards = value

    def run(self):
        while True:
            if self._is_stop:
                return
            err, shards = self._client_adapter.hear_beat(_convert_all_heart_shards(self._all_heart_shards))
            if err is not None:
                now = common.current_time_ms()
                if now - self._last_success_time > self._timeout_sec * 1000 + self._heartbeat_interval_mill:
                    self._current_held_shards = {}
            else:
                self._current_held_shards = {}
                self._lock.acquire_write()
                for shard in shards:
                    self._current_held_shards[shard] = ""
                    self._all_heart_shards[shard] = ""
                self._lock.release_write()
                self._last_success_time = common.current_time_ms()
                logger.debug(
                    "after heart beat, current_held_shards is {}, all_heart_shards is {}, last_success_time is {}",
                    self._current_held_shards, self._all_heart_shards, self._last_success_time)
                common.sleep_ms(self._heartbeat_interval_mill)

    def unsubscribe(self, shards):
        for shard, consume in shards:
            try:
                self._all_heart_shards.pop(shard)
            except KeyError as e:
                logger.error("shard {} is not in all heart shard", shard)

    def stop(self):
        self._is_stop = True


def _convert_all_heart_shards(all_heart_shards):
    shards = []
    for key, value in all_heart_shards.items():
        shards.append(key)
    return shards
