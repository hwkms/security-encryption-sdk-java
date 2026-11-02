import logging
import threading
from typing import Optional

from huaweicloud_encryptionsdk.log.log_config import LogConfig
from huaweicloud_encryptionsdk.log.lts_sdk_producer import LTSSDKProducer
from huaweicloud_encryptionsdk.log.lts_struct_log_builder import LtsStructLogBuilder

logger = logging.getLogger(__name__)

MAX_INIT_RETRY_COUNT = 3


def desensitize(value: Optional[str]) -> str:
    if value is None or len(value) <= 4:
        return "****"
    return value[:2] + "****" + value[-2:]


class LogReporterManager:

    def __init__(self):
        self._lts_producer: Optional[LTSSDKProducer] = None
        self._log_config: Optional[LogConfig] = None
        self._local_log_only: bool = False
        self._initialized: bool = False
        self._init_retry_count: int = 0
        self._lock = threading.Lock()

    def init(self, config) -> None:
        with self._lock:
            if self._initialized:
                logger.debug("LogReporterManager is already initialized")
                return

            if self._init_retry_count >= MAX_INIT_RETRY_COUNT:
                logger.warn("LogReporterManager init has exceeded max retry count (%d), giving up", MAX_INIT_RETRY_COUNT)
                return

            if config.log_config is None and not config.local_log_only:
                logger.info("Log config is not provided and localLogOnly is false, logging is disabled")
                return

            self._log_config = config.log_config if config.log_config is not None else LogConfig()

            if config.local_log_only:
                self._local_log_only = True
                self._initialized = True
                logger.info("LogReporterManager initialized with local log only mode")
                return

            try:
                if self._log_config.project_id is None:
                    if config.kms_config_list and len(config.kms_config_list) > 0:
                        self._log_config.project_id = config.kms_config_list[0].project_id
                    else:
                        self._log_config.project_id = "default"
                self._lts_producer = LTSSDKProducer(
                    config.get_ak(),
                    config.get_sk(),
                    self._log_config.project_id,
                    self._log_config.region,
                    self._log_config,
                    security_token=config.security_token or "",
                )
                self._initialized = True
                logger.info("LogReporterManager initialized successfully with LTS mode")
                logger.info("Log config: batchCountThreshold=%s, lingerMs=%s, ioThreadCount=%s",
                            self._log_config.batch_count_threshold,
                            self._log_config.linger_ms,
                            self._log_config.io_thread_count)
            except Exception as e:
                self._init_retry_count += 1
                logger.error("Failed to initialize LogReporterManager (attempt %d/%d): %s",
                             self._init_retry_count, MAX_INIT_RETRY_COUNT, str(e), exc_info=e)
                if self._log_config.fail_on_backup_dir_missing:
                    raise

    def record_encrypt_log(
        self,
        encrypt_file_name: Optional[str],
        encrypt_data_bytes: Optional[int],
        encrypt_output_file_name: Optional[str],
        encrypt_output_bytes: Optional[int],
        key_id: Optional[str],
        access_point_type: Optional[str],
        instance_id: Optional[str],
    ) -> None:
        self._record_log(
            "encrypt", encrypt_file_name, encrypt_data_bytes,
            encrypt_output_file_name, encrypt_output_bytes,
            key_id, access_point_type, instance_id,
        )

    def record_decrypt_log(
        self,
        decrypt_file_name: Optional[str],
        decrypt_data_bytes: Optional[int],
        decrypt_output_file_name: Optional[str],
        decrypt_output_bytes: Optional[int],
        key_id: Optional[str],
        access_point_type: Optional[str],
        instance_id: Optional[str],
    ) -> None:
        self._record_log(
            "decrypt", decrypt_file_name, decrypt_data_bytes,
            decrypt_output_file_name, decrypt_output_bytes,
            key_id, access_point_type, instance_id,
        )

    def _record_log(
        self,
        operation: str,
        file_name: Optional[str],
        data_bytes: Optional[int],
        output_file_name: Optional[str],
        output_bytes: Optional[int],
        key_id: Optional[str],
        access_point_type: Optional[str],
        instance_id: Optional[str],
    ) -> None:
        if not self._initialized:
            return
        try:
            struct_log = LtsStructLogBuilder.build_struct_log(
                operation, file_name, data_bytes,
                output_file_name, output_bytes,
                key_id, access_point_type, instance_id,
            )

            if self._local_log_only:
                logger.info("[LOCAL_LOG] %s", struct_log)
                return

            if self._lts_producer is not None:
                self._lts_producer.send_struct_log(struct_log)
            logger.info("Recorded %s log for keyId: %s, dataBytes: %s, accessPointType: %s",
                        operation, desensitize(key_id), data_bytes, access_point_type)
        except Exception as e:
            logger.error("Failed to record %s operation log: %s", operation, str(e))

    def shutdown(self) -> None:
        with self._lock:
            if not self._initialized:
                return
            if self._lts_producer is not None:
                try:
                    self._lts_producer.close()
                except Exception as e:
                    logger.error("Failed to close LTS producer during shutdown, will retry on next shutdown call: %s", str(e))
                    return
                self._lts_producer = None
            self._initialized = False
            self._init_retry_count = 0
            logger.info("LogReporterManager shutdown successfully")

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def lts_producer(self) -> Optional[LTSSDKProducer]:
        return self._lts_producer
