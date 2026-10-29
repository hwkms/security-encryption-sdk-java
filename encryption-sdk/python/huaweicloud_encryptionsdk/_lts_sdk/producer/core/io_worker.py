import math
import queue
import threading

from huaweicloud_encryptionsdk._lts_sdk.producer.lts_http import http_client
from huaweicloud_encryptionsdk._lts_sdk.producer.model import log_batch
from huaweicloud_encryptionsdk._lts_sdk.producer.model import result
from huaweicloud_encryptionsdk._lts_sdk.producer.model.error import Error
from huaweicloud_encryptionsdk._lts_sdk.utils import lts_threading, common


class IOWorker(threading.Thread):
    def __init__(self, max_io_worker_count, no_retry_code, producer):
        super().__init__()
        self._task_count_lock = lts_threading.ReadWriteLock()
        self._task_count = 0
        # 控制io_worker数量，超过限制时，后面的都进行等待，等待前面io_worker处理完
        self._max_io_worker = queue.Queue(max_io_worker_count)
        self._no_retry_status_code = no_retry_code
        self._producer = producer
        self._retry_queue_lock = lts_threading.ReadWriteLock()
        self._retry_queue = queue.Queue()
        self._lock = threading.Lock()
        self._client = http_client.HttpClient()

    @property
    def producer(self):
        return self._producer

    @producer.setter
    def producer(self, value):
        self._producer = value

    @property
    def task_count(self):
        self._task_count_lock.acquire_read()
        try:
            return self._task_count
        finally:
            self._task_count_lock.release_read()

    @task_count.setter
    def task_count(self, value):
        self._task_count_lock.acquire_write()
        try:
            self._task_count = value
        finally:
            self._task_count_lock.release_write()

    def io_worker_send_to_server(self, batch: log_batch.LogBatch):
        begin_time = common.current_time_ms()
        # TODO 此处进行日志发送
        err = self._client.put_logs(batch.group_id, batch.stream_id, batch.log_group, self._producer.producer_config)
        if err is None:
            if batch.attempt_count < self._producer.producer_config.max_reserved_attempts:
                now_time = common.current_time_ms()
                attempt = result.Attempt(True, 200, "", "", "", now_time, now_time - begin_time)
                batch.add_attempt(attempt)
            batch.result.success = True
            if len(batch.call_back_list) > 0:
                for call_back in batch.call_back_list:
                    call_back.invoke_on_success(batch.result)

        else:
            if err.http_code in self._no_retry_status_code:
                self.add_error_msg_to_batch_attempt(batch, err, False, begin_time)
                self.exec_failed_call_back(batch)
                return

            if batch.attempt_count < self._producer.producer_config.retries:
                self.add_error_msg_to_batch_attempt(batch, err, True, begin_time)
                retry_wait_time = self._producer.producer_config.base_retry_backoff_ms * math.pow(2,
                                                                                                  batch.attempt_count - 1)
                if retry_wait_time < self.producer.producer_config.max_retry_backoff_ms:
                    batch.next_retry_ms = common.current_time_ms() + retry_wait_time
                else:
                    batch.next_retry_ms = common.current_time_ms() + self.producer.producer_config.max_retry_backoff_ms
                self.send_to_retry_queue(batch)
            else:
                self.exec_failed_call_back(batch)

    def end_this_send_task(self):
        self._max_io_worker.get()
        self.dec_task_count()

    def start_this_send_task(self):
        self.inc_task_count()
        self._max_io_worker.put(1)

    def inc_task_count(self):
        self._task_count_lock.acquire_write()
        try:
            self._task_count += 1
        finally:
            self._task_count_lock.release_write()

    def dec_task_count(self):
        self._task_count_lock.acquire_write()
        try:
            self._task_count -= 1
        finally:
            self._task_count_lock.release_write()

    def send_to_retry_queue(self, batch: log_batch.LogBatch):
        self._retry_queue_lock.acquire_write()
        try:
            self._retry_queue.put_nowait(batch)
        finally:
            self._retry_queue_lock.release_write()

    def add_error_msg_to_batch_attempt(self, batch: log_batch.LogBatch, err: Error, retry: bool, begin_ms: int):
        if batch.attempt_count < self.producer.producer_config.max_reserved_attempts:
            now_ms = common.current_time_ms()
            attempt = result.Attempt(False, err.http_code, err.request_id, err.error_code, err.error_msg, now_ms,
                                     now_ms - begin_ms)
            batch.add_attempt(attempt)
        batch.result.success = False
        batch.attempt_count += 1

    @classmethod
    def exec_failed_call_back(cls, batch: log_batch.LogBatch):
        if len(batch.call_back_list) > 0:
            for call_back in batch.call_back_list:
                call_back.invoke_on_failed(batch.result)
