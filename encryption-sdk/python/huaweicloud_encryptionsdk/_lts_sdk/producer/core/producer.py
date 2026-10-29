from huaweicloud_encryptionsdk._lts_sdk.producer.callback.call_back import CallBack
from huaweicloud_encryptionsdk._lts_sdk.producer.core.accumulator import Accumulator
from huaweicloud_encryptionsdk._lts_sdk.producer.core.io_thread_pool import IOThreadPool
from huaweicloud_encryptionsdk._lts_sdk.producer.core.io_worker import IOWorker
from huaweicloud_encryptionsdk._lts_sdk.producer.core.mover import Mover
from huaweicloud_encryptionsdk._lts_sdk.producer.model import error
from huaweicloud_encryptionsdk._lts_sdk.producer.model.config import Config
from huaweicloud_encryptionsdk._lts_sdk.producer.model.log import Log


class Producer(object):

    def __init__(self, config):
        if config is None:
            config = Config()
        self._producer_config = config.validate_config()
        self._io_worker = None
        self._accumulator = None
        self._io_thread_pool = None
        self._mover = None
        self._buckets = config.bucket

    @staticmethod
    def init_producer(producer_config):
        producer = Producer(producer_config)

        io_worker = IOWorker(producer_config.max_io_workers, producer_config.no_retry_code_list, producer)
        io_thread_pool = IOThreadPool(io_worker)
        accumulator = Accumulator.init_accumulator(producer_config, io_worker, producer, io_thread_pool)
        mover = Mover(io_worker, accumulator, io_thread_pool, producer_config)
        producer.io_thread_pool = io_thread_pool
        producer.accumulator = accumulator
        producer.io_worker = io_worker
        producer.mover = mover
        return producer

    @property
    def producer_config(self):
        return self._producer_config

    @producer_config.setter
    def producer_config(self, value):
        self._producer_config = value

    @property
    def io_worker(self):
        return self._io_worker

    @io_worker.setter
    def io_worker(self, value):
        self._io_worker = value

    @property
    def buckets(self):
        return self._buckets

    @buckets.setter
    def buckets(self, value):
        self._buckets = value

    @property
    def accumulator(self):
        return self._accumulator

    @accumulator.setter
    def accumulator(self, value):
        self._accumulator = value

    @property
    def io_thread_pool(self):
        return self._io_thread_pool

    @io_thread_pool.setter
    def io_thread_pool(self, value):
        self._io_thread_pool = value

    @property
    def mover(self):
        return self._mover

    @mover.setter
    def mover(self, value):
        self._mover = value

    def start_producer(self):
        self._mover.name = "lts-mover-thread"
        self._mover.start()
        self._io_thread_pool.name = "lts-io-thread-pool-thread"
        self._io_thread_pool.start()

    def send_log(self, group_id: str, stream_id: str, log: Log):
        return self._accumulator.add_log_to_log_batch_map(log, group_id, stream_id, None)

    def send_log_with_callback(self, group_id: str, stream_id: str, log: Log, call_back: CallBack):
        if call_back is None:
            return error.Error(error_code=error.PARAMETER_ERROR_CODE,
                               error_msg="call back fn is None, please check")
        return self._accumulator.add_log_to_log_batch_map(log, group_id, stream_id, call_back)
