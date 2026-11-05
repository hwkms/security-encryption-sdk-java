from huaweicloud_encryptionsdk._lts_sdk.utils import common


class TaskResult(object):
    def __init__(self, error):
        self.error = error

    def __str__(self):
        return common.convert_obj2_json_str(self.error)


class FetchTaskResult(TaskResult):
    def __init__(self, fetch_data, cursor, next_cursor):
        super().__init__(None)
        self.fetch_data = fetch_data
        self.cursor = cursor
        self.next_cursor = next_cursor

    def __str__(self):
        return common.convert_obj2_json_str(self)


class InitTaskResult(TaskResult):
    def __init__(self, start_time, end_time, cursor_persistent):
        super().__init__(None)
        self.start_time = start_time
        self.end_time = end_time
        self.cursor_persistent = cursor_persistent

    def __str__(self):
        return common.convert_obj2_json_str(self)


class ProcessTaskResult(TaskResult):
    def __init__(self, rollback_checkpoint):
        super().__init__(None)
        self.rollback_checkpoint = rollback_checkpoint

    def __str__(self):
        return common.convert_obj2_json_str(self)
