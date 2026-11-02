import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from loguru import logger
from huaweicloud_encryptionsdk._lts_sdk.producer.model.log_batch import LogBatch
from huaweicloud_encryptionsdk._lts_sdk.utils import lts_threading


class IOThreadPool(threading.Thread):
    def __init__(self, io_worker):
        super().__init__()
        self._thread_pool_lock = lts_threading.ReadWriteLock()
        self._deal_batch_queue = queue.Queue()
        self._submit_thread_pool = ThreadPoolExecutor(max_workers=10240, thread_name_prefix="io_thread_pool_sender")
        self._io_worker = io_worker

    @property
    def io_worker(self):
        return self._io_worker

    @io_worker.setter
    def io_worker(self, value: int):
        self._io_worker = value

    @property
    def thread_pool_lock(self):
        return self._thread_pool_lock

    @thread_pool_lock.setter
    def thread_pool_lock(self, value: int):
        self._thread_pool_lock = value

    @property
    def deal_batch_queue(self):
        self._thread_pool_lock.acquire_read()
        try:
            return self._deal_batch_queue
        finally:
            self._thread_pool_lock.release_read()

    @deal_batch_queue.setter
    def deal_batch_queue(self, value: int):
        self._thread_pool_lock.acquire_write()
        try:
            self._deal_batch_queue = value
        finally:
            self._thread_pool_lock.release_write()

    def add_task(self, batch: LogBatch):

        self._thread_pool_lock.acquire_write()
        try:
            self._deal_batch_queue.put_nowait(batch)
        except queue.Full as e:
            logger.error("log batch queue is full, log generate is too fast")
        finally:
            self._thread_pool_lock.release_write()

    def take_task(self):
        self._thread_pool_lock.acquire_read()
        try:
            if self._deal_batch_queue is None or self._deal_batch_queue.empty():
                return None
            batch = self._deal_batch_queue.get_nowait()
            return batch
        finally:
            self._thread_pool_lock.release_read()

    def has_task(self):
        self._thread_pool_lock.acquire_read()
        try:
            if self._deal_batch_queue is None:
                return False
            return not self._deal_batch_queue.empty()
        finally:
            self._thread_pool_lock.release_read()

    def task_queue_size(self):
        self._thread_pool_lock.acquire_read()
        try:
            if self._deal_batch_queue is None:
                return 0
            return self._deal_batch_queue.qsize()
        finally:
            self._thread_pool_lock.release_read()

    def run(self):
        try:
            while True:
                batch = self.take_task()
                if batch is None:
                    time.sleep(0.1)
                else:
                    self.io_worker.start_this_send_task()

                    def send_to_server_handler(io_worker, log_batch):
                        try:
                            io_worker.io_worker_send_to_server(log_batch)
                        finally:
                            io_worker.end_this_send_task()

                    self._submit_thread_pool.submit(send_to_server_handler, self.io_worker, batch)

        finally:
            self.io_worker.dec_task_count()
