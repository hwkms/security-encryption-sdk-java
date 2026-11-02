import threading
import time
from concurrent.futures import ThreadPoolExecutor

from loguru import logger

from consumer.client.consumer_client_adapter import LogConsumerClientAdapter
from consumer.core.consumer_heartbeat import LogConsumerHeartBeat
from consumer.core.log_shard_consumer import LogShardConsumer
from consumer.interface.consumer_processor_factory import ILogConsumerProcessorFactory
from consumer.model.consumer_config import ConsumerConfig


class ClientConsumerWorker(threading.Thread):
    def __init__(self, processor_factory: ILogConsumerProcessorFactory, config: ConsumerConfig):
        super().__init__()
        self.processor_factory = processor_factory
        self.config = config
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="huawei-log-pool-")
        self.shard_consumer = {}
        self.client_adapter = LogConsumerClientAdapter(config)
        self.heart_beat = LogConsumerHeartBeat(self.client_adapter, config)
        self.shut_down = False
        self.main_loop_exit = False

    def check_consumer_group_exist(self):
        err, check_point = self.client_adapter.fetch_consumer_group("")
        return err

    def run(self):
        self.heart_beat.start()
        while True:
            if not self.shut_down:
                self.heart_beat.lock.acquire_write()
                for shard in self.heart_beat.current_held_shards:
                    consumer = self.consumer_for_shard(shard)
                    consumer.consume()

                self.clean_consumer(self.heart_beat.current_held_shards)
                self.heart_beat.lock.release_write()
                time.sleep(self.config.fetch_interval_mill / 1000)
            else:
                break
        self.main_loop_exit = True

    def consumer_for_shard(self, shard_id):
        if shard_id in self.shard_consumer:
            return self.shard_consumer[shard_id]
        return self.get_log_shard_consumer(shard_id)

    def get_log_shard_consumer(self, shard_id):
        consumer = LogShardConsumer(self.client_adapter, shard_id, self.processor_factory.generate_processor(),
                                    self.config, self.heart_beat)
        self.shard_consumer[shard_id] = consumer
        logger.info("create a consumer for shard: {}", shard_id)
        return consumer

    def clean_consumer(self, owned_shard):
        shard_to_unload = {}
        for shard, consumer in self.shard_consumer.items():
            if shard in owned_shard:
                if consumer.is_shutdown():
                    consumer = LogShardConsumer(self.client_adapter, shard,
                                                self.processor_factory.generate_processor(),
                                                self.config, self.heart_beat)
                    logger.info("create a consumer for shard: {}", shard)
                    self.shard_consumer[shard] = consumer
                continue
            # logger.info("shutting down consumer of shard: {}", shard)
            # consumer.shutdown()
            if consumer.is_shutdown():
                shard_to_unload[shard] = consumer
                logger.info("shard shutdown done, removing from heartbeat list: {}", shard)

        for shard, consumer in shard_to_unload.items():
            self.shard_consumer.pop(shard)

        for shard, consumer in owned_shard.items():
            if shard not in self.shard_consumer:
                shard_to_unload[shard] = consumer

        if len(shard_to_unload) > 0:
            self.heart_beat.unsubscribe(shard_to_unload)
            logger.warning("cancel heart beating for {}", shard_to_unload)

    def shutdown(self):
        self.shut_down = True
        times = 0
        while not self.main_loop_exit and times < 20:
            times += 1
            time.sleep(1)

        for key, consumer in self.shard_consumer:
            consumer.shutdown()

        self.heart_beat.stop()
        self.client_adapter.shutdown()


def get_client_consumer_worker(processor_factory: ILogConsumerProcessorFactory, config: ConsumerConfig):
    worker = ClientConsumerWorker(processor_factory, config)
    err = worker.check_consumer_group_exist()
    if err is not None:
        logger.error("get client consumer work error {}", err.error_msg)
        return None
    return worker
