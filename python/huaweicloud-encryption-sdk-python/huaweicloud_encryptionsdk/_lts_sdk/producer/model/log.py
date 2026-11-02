from typing import List

from huaweicloud_encryptionsdk._lts_sdk.utils.common import solv_log


class LogContent(object):
    def __init__(self, log_time_ns: int, log: str):
        self.log_time_ns = log_time_ns
        self.log = log

    def getSize(self) -> int:
        log_length = 0
        if self.log:
            log_length += len(self.log)

        return log_length + solv_log(self.log_time_ns)

    def __len__(self) -> int:
        log_length = 0
        if self.log:
            log_length += len(self.log)

        return log_length + solv_log(self.log_time_ns)


class Log(object):
    def __init__(self, contents: List[LogContent], labels: str):
        self.contents = contents
        self.labels = labels

    def getSize(self) -> int:
        log_length = 0
        l = 0
        if self.contents is None or len(self.contents) == 0:
            return log_length

        for content in self.contents:
            if content is None:
                l = 0
            else:
                l = content.getSize()

            log_length += 1 + l + solv_log(l)
        return log_length

    def __len__(self) -> int:
        log_length = 0
        l = 0
        if self.contents is None or len(self.contents) == 0:
            return log_length

        for content in self.contents:
            if content is None:
                l = 0
            else:
                l = len(content)

            log_length += 1 + l + solv_log(l)
        return log_length


class LogGroup(object):
    def __init__(self, log_items: List[Log]):
        self.log_items = log_items

    def is_empty_logs(self):
        return self.log_items is None or len(self.log_items) == 0

    def getSize(self) -> int:
        log_length = 0
        l = 0

        if not self.is_empty_logs():
            for log_item in self.log_items:
                l = log_item.getSize()
                log_length += 1 + l + solv_log(l)
        return log_length

    def __len__(self) -> int:
        log_length = 0
        l = 0

        if not self.is_empty_logs():
            for log_item in self.log_items:
                l = len(log_item)
                log_length += 1 + l + solv_log(l)
        return log_length
