import queue
import threading

from huaweicloud_encryptionsdk._lts_sdk.producer.model import log_batch
from huaweicloud_encryptionsdk._lts_sdk.utils import common


class RetryQueue(object):

    def __init__(self):
        self._batch_queue = queue.Queue()
        self._lock = threading.Lock()

    def send_to_retry_queue(self, batch: log_batch.LogBatch):
        self._lock.acquire()
        try:
            if batch is not None:
                self._batch_queue.put_nowait(batch)
        finally:
            self._lock.release()

    def get_retry_batch(self):
        retry_batch_list = []
        self._lock.acquire()
        try:
            while not self._batch_queue.empty():
                retry_batch = self._batch_queue.get_nowait()
                if retry_batch.next_retry_ms() < common.current_time_ms():
                    retry_batch_list.append(retry_batch)
                else:
                    self._batch_queue.put_nowait(retry_batch)
            return retry_batch_list
        finally:
            self._lock.release()

    def length(self):
        if self._batch_queue is None:
            return 0
        return self._batch_queue.qsize()
