import threading
import time

from huaweicloud_encryptionsdk._lts_sdk.producer.model.retry_queue import RetryQueue
from huaweicloud_encryptionsdk._lts_sdk.utils import common


class Mover(threading.Thread):
    def __init__(self, io_worker, accumulator, io_thread_pool, config):
        super().__init__()
        self._io_worker = io_worker
        self._accumulator = accumulator
        self._io_thread_pool = io_thread_pool
        self._retry_queue = RetryQueue()
        self._config = config

    def run(self):
        while True:
            sleep_ms = self._config.linger_ms
            now_time_ms = common.current_time_ms()
            self._accumulator.accumulator_lock.acquire_write()
            try:
                if self._accumulator.log_batch_map is None:
                    map_count = 0
                else:
                    map_count = len(self._accumulator.log_batch_map)
                for key, batch in self._accumulator.log_batch_map.items():
                    time_interval = batch.create_time_ms + self._config.linger_ms - now_time_ms
                    if time_interval <= 0:
                        self._mover_send_to_server(key, batch, self._config)
                    else:
                        if sleep_ms > time_interval:
                            sleep_ms = time_interval
            finally:
                self._accumulator.accumulator_lock.release_write()

            if map_count == 0:
                sleep_ms = self._config.linger_ms

            retry_batch_list = self._retry_queue.get_retry_batch()
            if retry_batch_list is None or len(retry_batch_list) == 0:
                time.sleep(sleep_ms / 1000)
            else:
                for retry_batch in retry_batch_list:
                    self._io_thread_pool.add_task(retry_batch)

            self._accumulator.accumulator_lock.acquire_write()
            try:
                if self._accumulator.log_batch_map is not None:
                    for key, batch in self._accumulator.log_batch_map.items():
                        self._io_thread_pool.add_task(batch)

                self._accumulator.log_batch_map = {}

            finally:
                self._accumulator.accumulator_lock.release_write()

            batch_list = self._retry_queue.get_retry_batch()
            if batch_list is not None:
                for batch in batch_list:
                    self._io_thread_pool.add_task(batch)

    def _mover_send_to_server(self, key, batch, config):
        if key not in self._accumulator.log_batch_map:
            return
        if common.current_time_ms() - self._accumulator.log_batch_map.get(key).create_time_ms < config.linger_ms:
            return
        self._io_thread_pool.add_task(batch)
        self._accumulator.log_batch_map.pop(key)
