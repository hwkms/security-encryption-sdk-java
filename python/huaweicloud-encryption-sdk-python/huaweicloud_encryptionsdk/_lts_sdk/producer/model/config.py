class Config(object):

    def __init__(self, max_block_sec=0, max_io_workers=200, batch_size_threshold_in_bytes=512 * 1024,
                 batch_count_threshold=4096, linger_ms=2000, retries=3, base_retry_backoff_ms=100,
                 max_retry_backoff_ms=5000, http_max_timeout_sec=60, bucket=64,
                 no_retry_code_list=None, total_size_in_bytes=100 * 1024 * 1024,
                 max_reserved_attempts=11):
        if no_retry_code_list is None:
            no_retry_code_list = {413, 429}
        self.max_block_sec = max_block_sec
        self.max_io_workers = max_io_workers
        self.batch_size_threshold_in_bytes = batch_size_threshold_in_bytes
        self.batch_count_threshold = batch_count_threshold
        self.linger_ms = linger_ms
        self.retries = retries
        self.base_retry_backoff_ms = base_retry_backoff_ms
        self.max_retry_backoff_ms = max_retry_backoff_ms
        self.http_max_timeout_sec = http_max_timeout_sec
        self.bucket = bucket
        self.no_retry_code_list = no_retry_code_list
        self.total_size_in_bytes = total_size_in_bytes
        self.max_reserved_attempts = max_reserved_attempts

        self.endpoint = ""
        self.access_key = ""
        self.access_secret = ""
        self.security_token = ""
        self.project_id = ""
        self.region_id = ""

    def validate_config(self):
        if self.max_reserved_attempts <= 0:
            self.max_reserved_attempts = 11
        if self.batch_count_threshold > 40960 or self.batch_count_threshold <= 0:
            self.batch_count_threshold = 40960
        if self.batch_size_threshold_in_bytes > 512 * 1024 or self.batch_size_threshold_in_bytes <= 0:
            self.batch_size_threshold_in_bytes = 512 * 1024

        if self.max_io_workers <= 0:
            self.max_io_workers = 10

        if self.base_retry_backoff_ms <= 0:
            self.base_retry_backoff_ms = 100

        if self.total_size_in_bytes <= 0:
            self.total_size_in_bytes = 100 * 1024 * 1024

        if self.linger_ms < 100:
            self.linger_ms = 2000
        return self
