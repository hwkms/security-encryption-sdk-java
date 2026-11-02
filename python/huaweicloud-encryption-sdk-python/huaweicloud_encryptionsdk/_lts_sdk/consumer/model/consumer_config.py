import uuid


class ConsumerConfig(object):
    def __init__(self, endpoint, region_name, project_id, log_group_id, log_stream_id, access_key, access_secret,
                 consumer_group_name, start_time_ns, end_time_ns, batch_size, heartbeat_interval_mill=1000,
                 fetch_interval_mill=200, auto_commit_enable=True, auto_commit_interval_ms=60 * 1000, timeout_sec=60,
                 unload_after_commit_enable=False):
        self.endpoint = endpoint
        self.region_name = region_name
        self.project_id = project_id
        self.log_group_id = log_group_id
        self.log_stream_id = log_stream_id
        self.access_key = access_key
        self.access_secret = access_secret
        self.consumer_group_name = consumer_group_name
        self.start_time_ns = start_time_ns
        self.end_time_ns = end_time_ns
        self.consumer = str(uuid.uuid4())
        self.is_compress = True
        self.heartbeat_interval_mill = heartbeat_interval_mill
        self.fetch_interval_mill = fetch_interval_mill
        self.auto_commit_enable = auto_commit_enable
        self.auto_commit_interval_ms = auto_commit_interval_ms
        self.timeout_sec = timeout_sec
        self.unload_after_commit_enable = unload_after_commit_enable
        self.batch_size = batch_size
