from loguru import logger

from consumer.client.consumer_client_adapter import LogConsumerClientAdapter
from consumer.interface.consumer_processor import ILogConsumerProcessor
from consumer.model.task_result import TaskResult, InitTaskResult
from huaweicloud_encryptionsdk._lts_sdk.utils import common


class InitializeTask(object):
    def __init__(self, processor: ILogConsumerProcessor, client_adapter: LogConsumerClientAdapter, shard_id, start_time,
                 end_time):
        self.processor = processor
        self.client_adapter = client_adapter
        self.shard_id = shard_id
        self.start_time = start_time
        self.end_time = end_time


def initialize_task(task: InitializeTask) -> TaskResult:
    task.processor.initialize(task.shard_id)
    err, shard_checkpoint_list = task.client_adapter.fetch_consumer_group(task.shard_id)
    if err is not None:
        logger.error("error fetching initial position: {}", err)
        return TaskResult(err)
    is_cursor_persistent = False
    start_time_by_cursor = ""
    end_time_by_cursor = ""
    if task.end_time is not None and task.end_time != 0:
        err, end_time_2_cursor = task.client_adapter.get_cursor_by_time(task.shard_id, str(task.end_time))
        if err is not None:
            logger.error("error fetching initial position, get cursor by time error: {}", err)
            return TaskResult(err)
        end_time_by_cursor = end_time_2_cursor.cursor
        logger.debug("initialize task shardId {}, endTime {}, endTimeByCursor {}", task.shard_id, task.end_time,
                     end_time_by_cursor)

    logger.debug("shard checkpoint list is {}", shard_checkpoint_list)
    if shard_checkpoint_list is not None and len(shard_checkpoint_list) > 0:
        shard_checkpoint = shard_checkpoint_list[0]
        logger.debug("shard checkpoint is {}", shard_checkpoint)
        is_cursor_persistent = True
        start_time_by_cursor = shard_checkpoint.checkpoint
    else:
        if task.start_time is not None and task.start_time != 0:
            err, start_time_2_cursor = task.client_adapter.get_cursor_by_time(task.shard_id, str(task.start_time))
            if err is not None:
                logger.error("error fetching initial position, get cursor by time error: {}", err)
                return TaskResult(err)
            start_time_by_cursor = start_time_2_cursor.cursor
            logger.debug("initialize task shardId {}, endTime {}, endTimeByCursor {}", task.shard_id, task.start_time,
                         start_time_by_cursor)

    logger.debug("initialize result, shardId {}, startTimeByCursor {}, endTimeByCursor {}, isCursorPersistent {}",
                 task.shard_id, start_time_by_cursor, end_time_by_cursor, is_cursor_persistent)
    return InitTaskResult(start_time_by_cursor, end_time_by_cursor, is_cursor_persistent)
