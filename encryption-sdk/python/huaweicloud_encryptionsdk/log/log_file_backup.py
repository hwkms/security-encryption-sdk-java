import json
import os
import time
import threading
from typing import List, Optional

from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException


class LogFileBackup:

    DEFAULT_BACKUP_DIR = "lts_log_backup"
    BACKUP_FILE_PREFIX = "lts_backup_"
    BACKUP_FILE_SUFFIX = ".json"
    MAX_BACKUP_FILE_SIZE = 10 * 1024 * 1024
    _save_lock = threading.Lock()

    def __init__(self, backup_dir_path: Optional[str] = None, fail_on_missing: bool = False):
        if backup_dir_path is None or backup_dir_path.strip() == "":
            backup_dir_path = os.path.join(os.path.expanduser("~"), self.DEFAULT_BACKUP_DIR)
        self._backup_dir_path = backup_dir_path.strip()
        self._fail_on_missing = fail_on_missing
        self._init_backup_dir()

    def _init_backup_dir(self) -> None:
        backup_dir = self._backup_dir_path
        if os.path.exists(backup_dir):
            if not os.path.isdir(backup_dir):
                if self._fail_on_missing:
                    raise HuaweicloudException(f"Backup path exists but is not a directory: {backup_dir}")
                return
            if not os.access(backup_dir, os.W_OK):
                if self._fail_on_missing:
                    raise HuaweicloudException(f"No write permission for backup directory: {backup_dir}")
                return
            test_file = os.path.join(backup_dir, f".write_test_{int(time.time() * 1000)}")
            try:
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
            except Exception as e:
                if self._fail_on_missing:
                    raise HuaweicloudException(f"Cannot write to backup directory: {backup_dir}", e)
                return
        else:
            try:
                os.makedirs(backup_dir, exist_ok=True)
            except Exception:
                if self._fail_on_missing:
                    raise HuaweicloudException(f"Failed to create backup directory: {backup_dir}")
                return

    def save_failed_logs(self, logs: List[dict], timestamp: int) -> Optional[str]:
        if logs is None or len(logs) == 0:
            return None
        try:
            date_str = time.strftime("%Y%m%d", time.localtime(timestamp / 1000))
            file_name = f"{self.BACKUP_FILE_PREFIX}{date_str}{self.BACKUP_FILE_SUFFIX}"
            backup_file = os.path.join(self._backup_dir_path, file_name)

            with self._save_lock:
                existing_logs = []
                if os.path.exists(backup_file):
                    try:
                        if os.path.getsize(backup_file) < self.MAX_BACKUP_FILE_SIZE:
                            with open(backup_file, "r", encoding="utf-8") as f:
                                existing_logs = json.loads(f.read())
                        else:
                            seq = 1
                            while True:
                                file_name = f"{self.BACKUP_FILE_PREFIX}{date_str}_{seq}{self.BACKUP_FILE_SUFFIX}"
                                backup_file = os.path.join(self._backup_dir_path, file_name)
                                if not os.path.exists(backup_file) or os.path.getsize(backup_file) < self.MAX_BACKUP_FILE_SIZE:
                                    if os.path.exists(backup_file):
                                        with open(backup_file, "r", encoding="utf-8") as f:
                                            existing_logs = json.loads(f.read())
                                    break
                                seq += 1
                    except Exception:
                        existing_logs = []

                existing_logs.extend(logs)
                json_content = json.dumps(existing_logs, ensure_ascii=False, default=str)
                with open(backup_file, "w", encoding="utf-8") as f:
                    f.write(json_content)

            return os.path.abspath(backup_file)
        except Exception:
            return None

    def recover_failed_logs(self) -> List[dict]:
        recovered_logs = []
        try:
            if not os.path.exists(self._backup_dir_path) or not os.path.isdir(self._backup_dir_path):
                return recovered_logs
            backup_files = []
            for name in os.listdir(self._backup_dir_path):
                if name.startswith(self.BACKUP_FILE_PREFIX) and name.endswith(self.BACKUP_FILE_SUFFIX):
                    backup_files.append(name)
            if not backup_files:
                return recovered_logs
            backup_files.sort(key=lambda f: self._extract_timestamp_from_file(f))
            for file_name in backup_files:
                backup_file = os.path.join(self._backup_dir_path, file_name)
                try:
                    file_size = os.path.getsize(backup_file)
                    if file_size > self.MAX_BACKUP_FILE_SIZE:
                        continue
                    with open(backup_file, "r", encoding="utf-8") as f:
                        content = f.read()
                    logs = json.loads(content)
                    if logs and len(logs) > 0:
                        recovered_logs.extend(logs)
                        try:
                            os.remove(backup_file)
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass
        return recovered_logs

    def _extract_timestamp_from_file(self, file_name: str) -> int:
        try:
            ts_str = file_name[len(self.BACKUP_FILE_PREFIX):-len(self.BACKUP_FILE_SUFFIX)]
            ts_str = ts_str.split("_")[0]
            return int(ts_str)
        except Exception:
            return 0

    def clear_all_backup_files(self) -> None:
        if not os.path.exists(self._backup_dir_path):
            return
        for name in os.listdir(self._backup_dir_path):
            if name.startswith(self.BACKUP_FILE_PREFIX) and name.endswith(self.BACKUP_FILE_SUFFIX):
                try:
                    os.remove(os.path.join(self._backup_dir_path, name))
                except Exception:
                    pass

    @property
    def backup_dir_path(self) -> str:
        return self._backup_dir_path
