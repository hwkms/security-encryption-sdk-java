from loguru import logger

from consumer.interface.consumer_check_point_tracker import DefaultLogConsumerCheckPointTracker
from consumer.interface.consumer_processor import ILogConsumerProcessor
from consumer.model.task_result import TaskResult


class ShutDownTask(object):
    def __init__(self, processor: ILogConsumerProcessor, checkpoint_tracker: DefaultLogConsumerCheckPointTracker):
        self.processor = processor
        self.checkpoint_tracker = checkpoint_tracker


def shutdown_task(task: ShutDownTask):
    try:
        task.processor.shutdown(task.checkpoint_tracker)
    except Exception as e:
        logger.error("could not shut down processor {}", e)

    err = task.checkpoint_tracker.flush_check_point()
    if err is not None:
        return TaskResult(None)
    else:
        return TaskResult(err)
