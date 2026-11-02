import os
import json
import time
import pytest
from huaweicloud_encryptionsdk.log.log_file_backup import LogFileBackup


class TestLogFileBackup:
    def test_save_and_recover(self, tmp_path):
        backup = LogFileBackup(backup_dir_path=str(tmp_path))
        logs = [{"operation": "encrypt", "keyId": "kid-123"}]
        filepath = backup.save_failed_logs(logs, int(time.time() * 1000))
        assert filepath is not None
        assert os.path.exists(filepath)

        recovered = backup.recover_failed_logs()
        assert len(recovered) == 1
        assert recovered[0]["operation"] == "encrypt"
        assert recovered[0]["keyId"] == "kid-123"

    def test_save_multiple_batches(self, tmp_path):
        backup = LogFileBackup(backup_dir_path=str(tmp_path))
        backup.save_failed_logs([{"op": "a"}], int(time.time() * 1000))
        time.sleep(0.01)
        backup.save_failed_logs([{"op": "b"}], int(time.time() * 1000))

        recovered = backup.recover_failed_logs()
        assert len(recovered) == 2

    def test_clear_all(self, tmp_path):
        backup = LogFileBackup(backup_dir_path=str(tmp_path))
        backup.save_failed_logs([{"op": "a"}], int(time.time() * 1000))
        backup.clear_all_backup_files()

        recovered = backup.recover_failed_logs()
        assert len(recovered) == 0

    def test_recover_from_empty_dir(self, tmp_path):
        backup = LogFileBackup(backup_dir_path=str(tmp_path))
        recovered = backup.recover_failed_logs()
        assert recovered == []

    def test_backup_dir_property(self, tmp_path):
        backup = LogFileBackup(backup_dir_path=str(tmp_path))
        assert backup.backup_dir_path == str(tmp_path)
