from concurrent.futures import ThreadPoolExecutor

from loguru import logger

from consumer.client.consumer_client_adapter import LogConsumerClientAdapter
from consumer.core.consumer_heartbeat import LogConsumerHeartBeat
from consumer.interface.consumer_check_point_tracker import DefaultLogConsumerCheckPointTracker
from consumer.interface.consumer_processor import ILogConsumerProcessor
from consumer.model.consumer_config import ConsumerConfig
from consumer.model.log_data import FetchedLogData
from consumer.model.task_result import TaskResult, ProcessTaskResult
from consumer.task.consumer_fetch_task import LogConsumerFetchTask, consumer_fetch_log
from consumer.task.initial_task import InitializeTask, initialize_task
from consumer.task.process_task import ProcessTask, process_task
from consumer.task.shutdown_task import ShutDownTask, shutdown_task
from huaweicloud_encryptionsdk._lts_sdk.utils import common

INITIALIZING = "INITIALIZING"
PROCESSING = "PROCESSING"
SHUTTING_DOWN = "SHUTTING_DOWN"
SHUTDOWN_COMPLETE = "SHUTDOWN_COMPLETE"


class LogShardConsumer(object):
    def __init__(self, client_adapter: LogConsumerClientAdapter, shard_id, processor: ILogConsumerProcessor,
                 config: ConsumerConfig, heart_beat: LogConsumerHeartBeat):
        self.client_adapter = client_adapter
        self.shard_id = shard_id
        self.start_time = config.start_time_ns
        self.end_time = config.end_time_ns
        self.processor = processor
        self.checkpoint_tracker = DefaultLogConsumerCheckPointTracker(client_adapter=client_adapter, config=config,
                                                                      shard_id=shard_id, heart_beat=heart_beat)
        self.config = config
        self.executor = ThreadPoolExecutor(max_workers=100, thread_name_prefix="log_shard_consumer-")
        self.next_fetch_cursor = ""
        self.final_fetch_cursor = ""
        self.fetch_data_future = None
        self.task_future = None
        self.last_fetched_data = None
        self.last_log_error_time = 0
        self.current_status = INITIALIZING
        self.current_task = None
        self._shutdown = False
        self.fetch_data_task_exist = False

    def consume(self):
        self.check_and_generate_next_task()
        if self.current_status == PROCESSING and self.last_fetched_data is None:
            self.fetch_data()

    def do_process_task_result(self, process_task_result):
        checkpoint = process_task_result.rollback_checkpoint
        if checkpoint is not None and len(checkpoint) > 0:
            self.cancel_current_fetch()
            self.next_fetch_cursor = checkpoint

    def do_process_init_result(self, init_task_result):
        self.next_fetch_cursor = init_task_result.start_time
        self.final_fetch_cursor = init_task_result.end_time
        self.checkpoint_tracker.initial_cursor = self.next_fetch_cursor
        if init_task_result.cursor_persistent:
            self.checkpoint_tracker.last_save_check_point = self.next_fetch_cursor

    def fetch_data(self):
        has_error = False
        if self.fetch_data_future is not None:
            if self.fetch_data_future.cancelled():
                self.fetch_data_future = None
                self.last_fetched_data = None
                return
            elif not self.fetch_data_future.done():
                return
            result = self.get_task_result(self.fetch_data_future)
            if result is not None and result.error is None:
                fetch = result.fetch_data
                self.last_fetched_data = FetchedLogData(self.shard_id, fetch, result.next_cursor,
                                                        result.cursor)
                self.next_fetch_cursor = result.next_cursor
                self.sample_log_error(result)
                has_error = result.error is not None
        if not has_error:
            task = LogConsumerFetchTask(self.client_adapter, self.shard_id, self.next_fetch_cursor,
                                        self.final_fetch_cursor,
                                        self.config)
            self.fetch_data_future = self.executor.submit(consumer_fetch_log, task)
        else:
            self.fetch_data_future = None

    def cancel_current_fetch(self):
        if self.fetch_data_future is not None:
            self.fetch_data_future.cancel()
            self.get_task_result(self.fetch_data_future)
            self.fetch_data_future = None
            logger.info("cancel a fetch task, shard id: {}", self.shard_id)
        self.last_fetched_data = None

    def sample_log_error(self, result: TaskResult):
        if result is not None and result.error is not None:
            current_time = common.current_time_ms()
            if current_time - self.last_log_error_time > 5 * 1000:
                logger.warning("error is {}", result.error)
                self.last_log_error_time = current_time

    def update_status(self, task_success):
        if self.current_status == SHUTTING_DOWN:
            if self.current_task is None or task_success:
                self.current_status = SHUTDOWN_COMPLETE
        elif self.is_shutdown():
            self.current_status = SHUTTING_DOWN
        elif task_success:
            if self.current_status == INITIALIZING:
                self.current_status = PROCESSING

    def generate_next_task(self):
        next_task = None
        logger.debug("when generate next task, status is {}", self.current_status)
        if self.current_status == INITIALIZING:
            next_task = InitializeTask(self.processor, self.client_adapter, self.shard_id, self.start_time,
                                       self.end_time)
        elif self.current_status == PROCESSING:
            if self.last_fetched_data is not None:
                self.checkpoint_tracker.current_cursor = self.last_fetched_data.cursor
                self.checkpoint_tracker.next_cursor = self.last_fetched_data.next_cursor
                next_task = ProcessTask(self.processor, self.last_fetched_data.fetchedData, self.checkpoint_tracker,
                                        self.final_fetch_cursor)
                self.last_fetched_data = None
            else:
                logger.debug("last fetched data is none")
        elif self.current_status == SHUTTING_DOWN:
            next_task = ShutDownTask(self.processor, self.checkpoint_tracker)
            self.cancel_current_fetch()
        if next_task is not None:
            self.current_task = next_task
            if isinstance(self.current_task, InitializeTask):
                logger.debug("current task is initialize task")
                self.task_future = self.executor.submit(initialize_task, self.current_task)
            elif isinstance(self.current_task, ProcessTask):
                logger.debug("current task is process task")
                self.task_future = self.executor.submit(process_task, self.current_task)
            elif isinstance(self.current_task, ShutDownTask):
                logger.debug("current task is shutdown task")
                self.task_future = self.executor.submit(shutdown_task, self.current_task)
        else:
            logger.debug("next task is none")

    def check_and_generate_next_task(self):
        if self.task_future is None or self.task_future.cancelled() or self.task_future.done():
            task_success = False
            result = self.get_task_result(self.task_future)
            logger.debug("after get task result, result is {}", result)
            self.task_future = None
            if result is not None and result.error is None:
                task_success = True
                if self.current_status == INITIALIZING:
                    self.do_process_init_result(result)
                elif isinstance(result, ProcessTaskResult):
                    self.do_process_task_result(result)
            self.sample_log_error(result)
            self.update_status(task_success)
            self.generate_next_task()

    def shutdown(self):
        self._shutdown = True
        if not self.is_shutdown():
            self.check_and_generate_next_task()

    def is_shutdown(self):
        return self.current_status == SHUTDOWN_COMPLETE

    @staticmethod
    def get_task_result(future):
        if future is not None and (future.done() or future.cancelled()):
            try:
                logger.debug("result type is {}", future)
                return future.result()
            except Exception as e:
                logger.error("error retrieving task result, error: {}", e)
        return None
