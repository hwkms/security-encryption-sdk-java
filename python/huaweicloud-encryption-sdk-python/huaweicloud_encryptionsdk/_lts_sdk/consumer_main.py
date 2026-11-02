import argparse
import sys
import time
from typing import List

from loguru import logger

from consumer.core.client_consumer_worker import get_client_consumer_worker
from consumer.interface.consumer_check_point_tracker import ILogConsumerCheckPointTracker
from consumer.interface.consumer_processor import ILogConsumerProcessor
from consumer.interface.consumer_processor_factory import ILogConsumerProcessorFactory
from consumer.model.consumer_config import ConsumerConfig
from consumer.model.log_data import LogData


class DemoLogConsumerProcessor(ILogConsumerProcessor):

    def __init__(self):
        self.log_count = 0

    def initialize(self, shard_id):
        pass

    def process(self, log_group: List[LogData], tracker: ILogConsumerCheckPointTracker) -> str:
        self.log_count += len(log_group)
        logger.info("this time consume log {} total log num {}", len(log_group), self.log_count)

    def shutdown(self, tracker: ILogConsumerCheckPointTracker):
        return tracker.save_check_point(True)


class DemoLogConsumerProcessorFactory(ILogConsumerProcessorFactory):
    def generate_processor(self):
        return DemoLogConsumerProcessor()


def start_consume(endpoint, region_name, project_id, log_group_id, log_stream_id, access_key, access_secret,
                  consumer_group_name, start_time, end_time, log_level, is_test, consumer_count, consume_batch_size):
    logger.remove()
    logger.add(sys.stderr, level=log_level)
    if is_test:
        logger.add("/opt/cloud/log.log", level="DEBUG")
    logger.info("start time {}, end time {}", start_time, end_time)
    workers = []

    for i in range(consumer_count):
        config = ConsumerConfig(endpoint, region_name, project_id, log_group_id, log_stream_id, access_key,
                                access_secret, consumer_group_name, start_time, end_time, consume_batch_size)
        work = get_client_consumer_worker(DemoLogConsumerProcessorFactory(), config)
        if work is None:
            logger.error("get work error, work is none")
        else:
            workers.append(work)

    for work in workers:
        work.start()

    time.sleep(30000 * 60)
    for work in workers:
        work.shutdown()

    time.sleep(60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='lts python sdk consume log help tester information')
    parser.add_argument('--endpoint', dest='endpoint', type=str, help='lts endpoint', default="https://endpoint")
    parser.add_argument('--project_id', dest='project_id', type=str, help='huaweicloud project_id', default="projectId")
    parser.add_argument('--region', dest='region', type=str, help='huaweicloud region', default="region")
    parser.add_argument('--group_id', dest='group_id', type=str, help='send log group_id', default="group_id")
    parser.add_argument('--stream_id', dest='stream_id', type=str, help='send log stream_id', default="stream_id")
    parser.add_argument('--ak', dest='ak', type=str, help='huaweicloud ak', default="ak")
    parser.add_argument('--sk', dest='sk', type=str, help='huaweicloud sk', default="sk")
    parser.add_argument('--consumer_count', dest='consumer_count', type=int, help='consumer count', default=1)
    parser.add_argument('--consume_batch_size', dest='consume_batch_size', type=int, help='each fetch max log nums',
                        default=1000)
    parser.add_argument('--consumer_group_name', dest='consumer_group_name', type=str, help='consumer group name',
                        default="consumer_group_name")
    parser.add_argument('--start_time', dest='start_time', type=int, help='consume log start time ms',
                        default=213123123123)
    parser.add_argument('--end_time', dest='end_time', type=int, help='consume log end time ms', default=0)
    parser.add_argument('--log_level', dest='log_level', type=str, help='consume log end time ms', default="INFO")
    parser.add_argument('--is_test', dest='is_test', type=bool, help='test consumer will write log to node',
                        default=True)
    args = parser.parse_args()
    start_consume(args.endpoint, args.region, args.project_id, args.group_id, args.stream_id, args.ak,
                  args.sk, args.consumer_group_name, args.start_time, args.end_time, args.log_level, args.is_test,
                  args.consumer_count, args.consume_batch_size)
