from typing import List

from consumer.interface.consumer_check_point_tracker import ILogConsumerCheckPointTracker
from consumer.model.log_data import LogData


class ILogConsumerProcessor(object):
    def initialize(self, shard_id):
        raise NotImplemented("please implement me")

    def process(self, log_group: List[LogData], tracker: ILogConsumerCheckPointTracker) -> str:
        raise NotImplemented("please implement me")

    def shutdown(self, tracker: ILogConsumerCheckPointTracker):
        raise NotImplemented("please implement me")

    def shard_consumer_thread_success(self, shard_id, is_success):
        pass
