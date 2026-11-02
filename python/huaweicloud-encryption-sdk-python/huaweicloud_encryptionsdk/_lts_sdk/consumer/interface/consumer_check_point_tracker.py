from consumer.client.consumer_client_adapter import LogConsumerClientAdapter
from consumer.model.consumer_config import ConsumerConfig


class ILogConsumerCheckPointTracker(object):
    def save_check_point(self, persistent: bool):
        raise NotImplemented("please implement me")

    def get_check_point(self) -> str:
        raise NotImplemented("please implement me")

    def get_current_cursor(self) -> str:
        raise NotImplemented("please implement me")


class DefaultLogConsumerCheckPointTracker(ILogConsumerCheckPointTracker):

    def __init__(self, client_adapter, config: ConsumerConfig, shard_id, heart_beat):
        self._client_adapter = client_adapter
        self._consumer = config.consumer
        self._shard_id = shard_id
        self._heart_beat = heart_beat

        self._pending_check_point = ""
        self._last_save_check_point = ""
        self._next_cursor = ""
        self._current_cursor = ""
        self._initial_cursor = ""

    @property
    def client_adapter(self) -> LogConsumerClientAdapter:
        return self._client_adapter

    @property
    def consumer(self):
        return self._consumer

    @consumer.setter
    def consumer(self, value: str):
        self._consumer = value

    @property
    def shard_id(self):
        return self._shard_id

    @shard_id.setter
    def shard_id(self, value: str):
        self._shard_id = value

    @property
    def pending_check_point(self):
        return self._pending_check_point

    @pending_check_point.setter
    def pending_check_point(self, value: str):
        self._pending_check_point = value

    @property
    def last_save_check_point(self):
        return self._last_save_check_point

    @last_save_check_point.setter
    def last_save_check_point(self, value: str):
        self._last_save_check_point = value

    @property
    def next_cursor(self):
        return self._next_cursor

    @next_cursor.setter
    def next_cursor(self, value: str):
        self._next_cursor = value

    @property
    def initial_cursor(self):
        return self._initial_cursor

    @initial_cursor.setter
    def initial_cursor(self, value: str):
        self._initial_cursor = value

    @property
    def current_cursor(self):
        return self._current_cursor

    @current_cursor.setter
    def current_cursor(self, value: str):
        self._current_cursor = value

    def save_check_point(self, persistent: bool):
        self._pending_check_point = self._next_cursor
        if persistent:
            return self.flush_check_point()
        return None

    def flush_check_point(self):
        self._pending_check_point = self._next_cursor
        checkpoint = self._pending_check_point
        if isinstance(checkpoint, str):
            if len(checkpoint) == 0 or checkpoint == self._last_save_check_point:
                return None
        elif isinstance(checkpoint, int):
            if int == 0 or checkpoint == self._last_save_check_point:
                return None
        err = self._client_adapter.update_check_point(self._shard_id, self._consumer, checkpoint)
        if err is None:
            self._last_save_check_point = checkpoint
        return err

    def get_check_point(self) -> str:
        if len(self._pending_check_point) != 0:
            return self._pending_check_point
        else:
            return self._initial_cursor

    def get_current_cursor(self) -> str:
        return self._current_cursor

    def consume_data_end_flush_checkpoint(self):
        return self.flush_check_point()
