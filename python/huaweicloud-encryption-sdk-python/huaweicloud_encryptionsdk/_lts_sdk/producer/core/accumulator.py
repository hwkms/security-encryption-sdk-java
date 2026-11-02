from loguru import logger

from huaweicloud_encryptionsdk._lts_sdk.producer.model import log_batch
from huaweicloud_encryptionsdk._lts_sdk.producer.model.log import Log
from huaweicloud_encryptionsdk._lts_sdk.utils import lts_threading

DELIMITER = "|"

log_num = 0


class Accumulator(object):

    def __init__(self):
        self._log_batch_map = {}
        self._accumulator_lock = lts_threading.ReadWriteLock()
        self._config = None
        self._io_worker = None
        self._producer = None
        self._io_thread_pool = None
        self._already_send_num = 0

    @staticmethod
    def init_accumulator(config, io_worker, producer, thread_pool):
        accumulator = Accumulator()
        accumulator.config = config
        accumulator.io_thread_pool = thread_pool
        accumulator.io_worker = io_worker
        accumulator.producer = producer
        return accumulator

    @property
    def log_batch_map(self):
        return self._log_batch_map

    @property
    def accumulator_lock(self):
        return self._accumulator_lock

    @log_batch_map.setter
    def log_batch_map(self, value):
        self._log_batch_map = value

    @property
    def config(self):
        return self._config

    @config.setter
    def config(self, value):
        self._config = value

    @property
    def io_worker(self):
        return self._io_worker

    @io_worker.setter
    def io_worker(self, value):
        self._io_worker = value

    @property
    def io_thread_pool(self):
        return self._io_thread_pool

    @io_thread_pool.setter
    def io_thread_pool(self, value):
        self._io_thread_pool = value

    @property
    def producer(self):
        return self._producer

    @producer.setter
    def producer(self, value):
        self._producer = value

    def add_log_to_log_batch_map(self, log_data: Log, group_id: str, stream_id: str, call_back):
        global log_num
        try:
            key = self.get_log_batch_key(group_id, stream_id)
            self._accumulator_lock.acquire_write()
            try:
                if key in self.log_batch_map:
                    batch_value = self.log_batch_map.get(key)
                    # TODO 需要计算producer的总大小
                    log_size = log_data.getSize()
                    batch_value.add_total_data_size(log_size)
                    self._add_or_send_producer_batch(key, group_id, stream_id, batch_value, log_data, call_back)

                else:
                    self._create_new_producer_log_batch(log_data, key, group_id, stream_id, call_back)

            finally:
                self._accumulator_lock.release_write()

            return None
        finally:
            log_num += len(log_data.contents)
            if log_num % 10000 == 0:
                logger.warning("add log num {}", log_num)

    def _create_new_producer_log_batch(self, log_data: Log, key: str, group_id: str, stream_id: str, call_back):
        _new_batch = log_batch.init_product_batch_var_single_log(log_data, call_back, group_id, stream_id, self.config)
        self.log_batch_map[key] = _new_batch

    def _add_or_send_producer_batch(self, key: str, group_id: str, stream_id: str, batch_value: log_batch.LogBatch,
                                    log: Log,
                                    call_back):
        total_data_count = batch_value.log_group_count + 1
        # batch中日志大小超过MaxBatchSize && batch中日志大小< 5242880 && batch中日志条数 <= MaxBatchCount
        # 直接发送
        if (self.config.batch_size_threshold_in_bytes < batch_value.total_data_size < 5242880
                and total_data_count <= self.config.batch_count_threshold):
            batch_value.add_log_to_log_group(log)
            if call_back is not None:
                batch_value.add_call_back(call_back)
            self._inner_send_to_server(key, batch_value)
        # batch中日志大小和条数都没有满足 配置，则log加入batch中先缓存
        elif (batch_value.total_data_size <= self.config.batch_size_threshold_in_bytes
              and total_data_count <= self.config.batch_count_threshold):

            batch_value.add_log_to_log_group(log)
            if call_back is not None:
                batch_value.add_call_back(call_back)

        else:
            self._inner_send_to_server(key, batch_value)
            self._create_new_producer_log_batch(log, key, group_id, stream_id, call_back)

    def _inner_send_to_server(self, key: str, batch: log_batch.LogBatch):
        self.io_thread_pool.add_task(batch)
        self.log_batch_map.pop(key)

    @staticmethod
    def get_log_batch_key(group_id: str, stream_id: str) -> str:
        return group_id + DELIMITER + stream_id + DELIMITER
