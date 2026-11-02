from consumer.client.http_client import HttpClient
from consumer.model.consumer_config import ConsumerConfig
from huaweicloud_encryptionsdk._lts_sdk.utils import lts_threading


class LogConsumerClientAdapter(object):
    def __init__(self, config: ConsumerConfig):
        self._project_id = config.project_id
        self._log_group_id = config.log_group_id
        self._log_stream_id = config.log_stream_id
        self._region_name = config.region_name
        self._consumer_group_name = config.consumer_group_name
        self._consumer = config.consumer
        self._is_shutdown = False
        self._client = HttpClient(config)
        self._lock = lts_threading.ReadWriteLock()

    def shutdown(self):
        self._is_shutdown = True

    def hear_beat(self, all_shards):
        self._lock.acquire_read()
        try:
            return self._client.heart_beat(self._project_id, self._log_group_id, self._log_stream_id,
                                           self._consumer_group_name, self._consumer, all_shards)
        finally:
            self._lock.release_read()

    def fetch_consumer_group(self, shard_id):
        self._lock.acquire_read()
        try:
            return self._client.fetch_consumer_group(self._project_id, self._log_group_id, self._log_stream_id,
                                                     self._consumer_group_name, shard_id)
        finally:
            self._lock.release_read()

    def update_check_point(self, shard_id, consumer, check_point):
        self._lock.acquire_read()
        try:
            return self._client.update_check_point(self._project_id, self._log_group_id, self._log_stream_id,
                                                   self._consumer_group_name, shard_id, consumer, check_point)
        finally:
            self._lock.release_read()

    def batch_get_logs(self, shard_id, batch_size, start_time, end_time):
        self._lock.acquire_read()
        try:
            return self._client.batch_get_log(self._project_id, self._log_group_id, self._log_stream_id, shard_id,
                                              batch_size, start_time, end_time)
        finally:
            self._lock.release_read()

    def get_cursor_by_time(self, shard_id, time):
        self._lock.acquire_read()
        try:
            return self._client.get_cursor_by_time(self._project_id, self._log_group_id, self._log_stream_id, shard_id,
                                                   time)
        finally:
            self._lock.release_read()
