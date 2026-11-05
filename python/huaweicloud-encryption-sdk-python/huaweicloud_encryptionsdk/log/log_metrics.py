import threading
from typing import Optional


class LogMetrics:

    def __init__(self):
        self._lock = threading.Lock()
        self._last_report_time: int = 0
        self._success_count: int = 0
        self._failure_count: int = 0
        self._success_log_count: int = 0
        self._failure_log_count: int = 0
        self._buffer_log_count: int = 0
        self._last_error_message: Optional[str] = None
        self._last_error_time: int = 0

    @property
    def last_report_time(self) -> int:
        with self._lock:
            return self._last_report_time

    @last_report_time.setter
    def last_report_time(self, value: int) -> None:
        with self._lock:
            self._last_report_time = value

    @property
    def success_count(self) -> int:
        with self._lock:
            return self._success_count

    @success_count.setter
    def success_count(self, value: int) -> None:
        with self._lock:
            self._success_count = value

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    @failure_count.setter
    def failure_count(self, value: int) -> None:
        with self._lock:
            self._failure_count = value

    @property
    def success_log_count(self) -> int:
        with self._lock:
            return self._success_log_count

    @success_log_count.setter
    def success_log_count(self, value: int) -> None:
        with self._lock:
            self._success_log_count = value

    @property
    def failure_log_count(self) -> int:
        with self._lock:
            return self._failure_log_count

    @failure_log_count.setter
    def failure_log_count(self, value: int) -> None:
        with self._lock:
            self._failure_log_count = value

    @property
    def buffer_log_count(self) -> int:
        with self._lock:
            return self._buffer_log_count

    @buffer_log_count.setter
    def buffer_log_count(self, value: int) -> None:
        with self._lock:
            self._buffer_log_count = value

    @property
    def last_error_message(self) -> Optional[str]:
        with self._lock:
            return self._last_error_message

    @last_error_message.setter
    def last_error_message(self, value: Optional[str]) -> None:
        with self._lock:
            self._last_error_message = value

    @property
    def last_error_time(self) -> int:
        with self._lock:
            return self._last_error_time

    @last_error_time.setter
    def last_error_time(self, value: int) -> None:
        with self._lock:
            self._last_error_time = value

    def increment_success_count(self) -> int:
        with self._lock:
            self._success_count += 1
            return self._success_count

    def increment_failure_count(self) -> int:
        with self._lock:
            self._failure_count += 1
            return self._failure_count

    def add_success_log_count(self, delta: int) -> int:
        with self._lock:
            self._success_log_count += delta
            return self._success_log_count

    def add_failure_log_count(self, delta: int) -> int:
        with self._lock:
            self._failure_log_count += delta
            return self._failure_log_count

    def add_buffer_log_count(self, delta: int) -> int:
        with self._lock:
            self._buffer_log_count += delta
            return self._buffer_log_count

    def reset(self) -> None:
        with self._lock:
            self._last_report_time = 0
            self._success_count = 0
            self._failure_count = 0
            self._success_log_count = 0
            self._failure_log_count = 0
            self._buffer_log_count = 0
            self._last_error_message = None
            self._last_error_time = 0
