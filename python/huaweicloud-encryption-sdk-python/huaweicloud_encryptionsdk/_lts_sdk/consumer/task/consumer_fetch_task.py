import time

from loguru import logger

from consumer.client.consumer_client_adapter import LogConsumerClientAdapter
from consumer.model.consumer_config import ConsumerConfig
from consumer.model.task_result import TaskResult, FetchTaskResult


class LogConsumerFetchTask(object):
    def __init__(self, client_adapter: LogConsumerClientAdapter, shard_id, cursor, final_fetch_cursor,
                 config: ConsumerConfig):
        self.client_adapter = client_adapter
        self.shard_id = shard_id
        self.cursor = cursor
        self.final_fetch_cursor = final_fetch_cursor
        self.config = config


def consumer_fetch_log(task: LogConsumerFetchTask) -> TaskResult:
    err = None
    for i in range(2):
        if task.final_fetch_cursor is not None and len(task.final_fetch_cursor) > 0:
            err, batch_log = task.client_adapter.batch_get_logs(task.shard_id, task.config.batch_size, task.cursor,
                                                                task.final_fetch_cursor)
        else:
            err, batch_log = task.client_adapter.batch_get_logs(task.shard_id, task.config.batch_size, task.cursor,
                                                                "")
        if err is not None:
            logger.error("failed pull data from shard {}, cursor {}, error {}", task.shard_id, task.cursor, err)
            time.sleep(0.2)
            continue
        else:
            fetched_data = batch_log.logs
            logger.debug("shard {}, cursor {}, next cursor {}, response size: {}", task.shard_id, task.cursor,
                         batch_log.next, batch_log.count)
            next_cursor = batch_log.next
            if isinstance(next_cursor, int):
                logger.debug("int cursor is {}", next_cursor)
                if next_cursor == 0:
                    logger.info("shard {} next cursor is empty, set to current int cursor {}", task.shard_id,
                                task.cursor)
                    next_cursor = task.cursor
            if isinstance(next_cursor, str):
                logger.debug("str cursor is {}", next_cursor)
                if len(next_cursor) == 0:
                    logger.info("shard {} next cursor is empty, set to current str cursor {}", task.shard_id,
                                task.cursor)
                    next_cursor = task.cursor
            return FetchTaskResult(fetched_data, task.cursor, next_cursor)

    if err is not None:
        return TaskResult(err)
