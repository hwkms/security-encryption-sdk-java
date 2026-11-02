import threading
from typing import List

from huaweicloud_encryptionsdk._lts_sdk.producer.model.config import Config
from huaweicloud_encryptionsdk._lts_sdk.producer.model.log import LogGroup, Log
from huaweicloud_encryptionsdk._lts_sdk.producer.model.result import Result
from huaweicloud_encryptionsdk._lts_sdk.utils import common


class LogBatch(object):
    def __init__(self):
        self._log_group = None
        self._total_data_size = 0
        self._log_group_count = 0
        self._attempt_count = 0
        self.lock = threading.Lock()
        self._call_back_list = []
        self._group_id = None
        self._stream_id = None
        self._config = None
        self._create_time_ms = common.current_time_ms()
        self._result = Result()
        self._next_retry_ms = 0

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, value):
        self._result = value

    @property
    def next_retry_ms(self):
        return self._next_retry_ms

    @next_retry_ms.setter
    def next_retry_ms(self, value):
        self._next_retry_ms = value

    @property
    def create_time_ms(self) -> int:
        return self._create_time_ms

    @create_time_ms.setter
    def create_time_ms(self, value: int):
        self._create_time_ms = value

    @property
    def total_data_size(self) -> int:
        return self._total_data_size

    @total_data_size.setter
    def total_data_size(self, value: int):
        self._total_data_size = value

    @property
    def log_group_count(self) -> int:
        return self._log_group_count

    @log_group_count.setter
    def log_group_count(self, value: int):
        self._log_group_count = value

    @property
    def attempt_count(self) -> int:
        return self._attempt_count

    @attempt_count.setter
    def attempt_count(self, value: int):
        self._attempt_count = value

    @property
    def log_group(self) -> LogGroup:
        return self._log_group

    @log_group.setter
    def log_group(self, value: LogGroup):
        self._log_group = value

    @property
    def group_id(self) -> str:
        return self._group_id

    @group_id.setter
    def group_id(self, value: str):
        self._group_id = value

    @property
    def stream_id(self) -> str:
        return self._stream_id

    @stream_id.setter
    def stream_id(self, value: str):
        self._stream_id = value

    @property
    def config(self) -> Config:
        return self._config

    @config.setter
    def config(self, value: Config):
        self._config = value

    @property
    def call_back_list(self):
        return self._call_back_list

    @call_back_list.setter
    def call_back_list(self, value):
        self._call_back_list = value

    def add_attempt(self, attempt):
        if attempt is None:
            return
        if self._result is None:
            self._result = Result()
        if self._result.attempt_list is None:
            self._result.attempt_list = []
        self._result.attempt_list.append(attempt)

    def add_call_back(self, call_back):
        if call_back is None:
            return
        else:
            self._call_back_list.append(call_back)

    def add_log_to_log_group(self, log: Log):
        self.log_group.log_items.append(log)

    def add_total_data_size(self, delta):
        self._total_data_size += delta


def init_product_batch_var_single_log(log_data: Log, call_back, group_id: str, stream_id: str, config: Config):
    logs = [log_data]
    log_group = LogGroup(log_items=logs)
    return _producer_batch(call_back, group_id, stream_id, config, log_group)


def init_product_batch_var_multi_log(log_data: List[Log], call_back, group_id: str, stream_id: str, config: Config):
    log_group = LogGroup(log_items=log_data)
    return _producer_batch(call_back, group_id, stream_id, config, log_group)


def _producer_batch(call_back, group_id: str, stream_id: str, config: Config, log_group: LogGroup):
    log_batch = LogBatch()
    log_batch.log_group = log_group
    log_batch.add_call_back(call_back)
    log_batch._group_id = group_id
    log_batch.stream_id = stream_id
    log_batch.config = config
    log_batch.total_data_size = log_group.getSize()
    return log_batch
