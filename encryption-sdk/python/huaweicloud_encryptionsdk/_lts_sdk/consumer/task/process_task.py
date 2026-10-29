from consumer.interface.consumer_check_point_tracker import DefaultLogConsumerCheckPointTracker
from consumer.interface.consumer_processor import ILogConsumerProcessor
from consumer.model.task_result import TaskResult, ProcessTaskResult


class ProcessTask(object):
    def __init__(self, processor: ILogConsumerProcessor, log_groups,
                 checkpoint_tracker: DefaultLogConsumerCheckPointTracker,
                 final_fetch_cursor):
        self.processor = processor
        self.chunk = log_groups
        self.checkpoint_tracker = checkpoint_tracker
        self.final_fetch_cursor = final_fetch_cursor


def process_task(task: ProcessTask) -> TaskResult:
    task.checkpoint_tracker.pending_check_point = task.checkpoint_tracker.next_cursor
    checkpoint = task.processor.process(task.chunk, task.checkpoint_tracker)
    task.processor.shard_consumer_thread_success(task.checkpoint_tracker.shard_id,
                                                 task.final_fetch_cursor == task.checkpoint_tracker.next_cursor)
    err = task.checkpoint_tracker.consume_data_end_flush_checkpoint()
    if err is None:
        return ProcessTaskResult(checkpoint)
    else:
        return TaskResult(err)
