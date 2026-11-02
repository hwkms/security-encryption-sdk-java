class LogData(object):
    def __init__(self):
        self.labels = {}


class BatchGetLog(object):
    def __init__(self):
        self.count = 0
        self.next = ""
        self.logs = LogData()


class FetchedLogData(object):
    def __init__(self, shard_id, fetched_data, next_cursor, cursor):
        self.shard_id = shard_id
        self.cursor = cursor
        self.next_cursor = next_cursor
        self.fetchedData = fetched_data
