import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LogConfig:
    log_group_id: str = ""
    log_stream_id: str = ""
    log_group_name: str = "DSC"
    log_stream_name: str = "crypto_operation_log"
    region: Optional[str] = None
    project_id: Optional[str] = None
    lts_endpoint: Optional[str] = None
    batch_count_threshold: int = 1000
    batch_size_threshold_in_bytes: int = 524288
    linger_ms: int = 30000
    total_size_in_bytes: int = 104857600
    max_block_ms: int = 0
    io_thread_count: int = field(default_factory=lambda: os.cpu_count() or 1)
    retries: int = 5
    base_retry_backoff_ms: int = 100
    max_retry_backoff_ms: int = 500
    enable_local_test: bool = False
    backup_dir: str = field(default_factory=lambda: os.path.join(os.path.expanduser("~"), "lts_log_backup"))
    max_backup_file_size: int = 10 * 1024 * 1024
    enable_recovery_on_startup: bool = True
    recovery_batch_size: int = 1000
    recovery_batch_interval: int = 1000
    fail_on_backup_dir_missing: bool = False
