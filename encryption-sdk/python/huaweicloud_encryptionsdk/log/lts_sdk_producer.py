import json
import re
import time
import logging
from typing import List, Optional
from urllib.parse import urlencode

from huaweicloud_encryptionsdk.log.log_config import LogConfig
from huaweicloud_encryptionsdk.log.log_metrics import LogMetrics
from huaweicloud_encryptionsdk.log.log_file_backup import LogFileBackup

logger = logging.getLogger(__name__)

_CONTROL_CHARS_PATTERN = re.compile(r'[\r\n\t\x00-\x1F\x7F-\x9F]')


def sanitize(input_str: Optional[str]) -> str:
    if input_str is None:
        return ""
    return _CONTROL_CHARS_PATTERN.sub("", input_str)


class _LtsLogCallBack:

    def __init__(self, producer, logs):
        self._producer = producer
        self._logs = logs

    def invoke_on_success(self, result):
        try:
            self._producer._handle_success(self._logs)
        except Exception as e:
            logger.error("Error in invoke_on_success callback: %s", str(e))

    def invoke_on_failed(self, result):
        last_attempt = result.attempt_list[-1] if result.attempt_list else None
        if last_attempt:
            error_message = "ErrorCode: {}, ErrorMessage: {}".format(
                last_attempt.error_code, last_attempt.error_msg)
            logger.error("LTS log report failed, httpCode=%s, %s",
                         last_attempt.http_code, error_message)
        else:
            error_message = "LTS log report failed, no attempt info available"
            logger.error(error_message)
        try:
            self._producer._handle_failure(self._logs, error_message)
        except Exception as e:
            logger.error("Error in invoke_on_failed callback: %s", str(e))


class LTSSDKProducer:

    def __init__(self, ak: str, sk: str, project_id: str, region: str, log_config: LogConfig, security_token: str = ""):
        self._ak = ak
        self._sk = sk
        self._project_id = project_id
        self._region = region
        self._log_config = log_config
        self._security_token = security_token
        self._log_file_backup = LogFileBackup(log_config.backup_dir, log_config.fail_on_backup_dir_missing)
        self._resolve_log_group_stream_ids()
        self._producer = self._create_producer(ak, sk, project_id, region, log_config)
        self._initialized = True
        self._metrics = LogMetrics()
        self._recover_failed_logs_on_startup()

    def _resolve_log_group_stream_ids(self) -> None:
        if self._log_config.log_group_id and self._log_config.log_stream_id:
            logger.info("Using logGroupId and logStreamId from config: groupId=%s, streamId=%s",
                        self._log_config.log_group_id, self._log_config.log_stream_id)
            return

        log_group_name = self._log_config.log_group_name
        log_stream_name = self._log_config.log_stream_name
        if not log_group_name or not log_stream_name:
            logger.warning("Both logGroupId/logStreamId and logGroupName/logStreamName are not configured")
            return

        logger.info("logGroupId or logStreamId is empty, resolving from names: groupName=%s, streamName=%s",
                    log_group_name, log_stream_name)
        try:
            group_id, stream_id = self._query_log_group_stream_info_by_name(
                self._project_id, log_group_name, log_stream_name
            )
            if group_id and stream_id:
                self._log_config.log_group_id = group_id
                self._log_config.log_stream_id = stream_id
                logger.info("Resolved logGroupId=%s, logStreamId=%s from names", group_id, stream_id)
            else:
                logger.error("Failed to resolve logGroupId/logStreamId from names, response is empty")
        except Exception as e:
            logger.error("Failed to resolve logGroupId/logStreamId from names: %s", str(e))

    def _query_log_group_stream_info_by_name(
        self, project_id: str, log_group_name: str, log_stream_name: str
    ) -> tuple:
        import requests as req_lib
        from urllib.parse import urlparse
        from huaweicloud_encryptionsdk._lts_sdk.auth.signer import Signer as LtsSigner
        from huaweicloud_encryptionsdk._lts_sdk.producer.lts_http.simple_request import LtsRequest

        endpoint = self._log_config.lts_endpoint or ""
        if not endpoint:
            raise ValueError("lts_endpoint is required to resolve log group/stream IDs by name")

        url = "{}/v2/{}/log-group-stream-info".format(endpoint.rstrip("/"), project_id)
        params = {
            "log_group_name": log_group_name,
            "log_stream_name": log_stream_name,
        }
        full_url = "{}?{}".format(url, urlencode(params))

        parsed = urlparse(full_url)
        host = parsed.netloc
        interface = parsed.path
        query_params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

        lts_request = LtsRequest(
            method="GET",
            host="{}://{}".format(parsed.scheme, host),
            headers={
                "host": host,
                "Content-Type": "application/json",
            },
            body="",
            region=self._region,
            interface=interface,
            ak=self._ak,
            sk=self._sk,
            security_token=self._security_token,
            **query_params,
        )

        signer = LtsSigner()
        signed_req = signer.sign(lts_request)

        prepared = signed_req.prepare()
        resp = req_lib.request(
            method=prepared.method,
            url=prepared.url,
            headers=prepared.headers,
            data=prepared.body,
            timeout=(10, 10),
            verify=False,
        )
        logger.info("Query log group stream info response: status=%s, body=%s",
                    resp.status_code, resp.text[:500])

        if resp.status_code == 200:
            data = resp.json()
            info_list = data if isinstance(data, list) else data.get("logGroupStreamInfoList", data.get("results", []))
            if info_list and len(info_list) > 0:
                info = info_list[0]
                return info.get("log_group_id", ""), info.get("log_stream_id", "")
        return "", ""

    def _create_producer(self, ak: str, sk: str, project_id: str, region: str, config: LogConfig):
        try:
            from huaweicloud_encryptionsdk._lts_sdk.producer.core.producer import Producer
            from huaweicloud_encryptionsdk._lts_sdk.producer.model.config import Config

            lts_config = Config()
            lts_config.access_key = ak
            lts_config.access_secret = sk
            lts_config.region_id = region
            lts_config.project_id = project_id
            lts_config.endpoint = config.lts_endpoint if hasattr(config, 'lts_endpoint') and config.lts_endpoint else ""
            lts_config.security_token = self._security_token
            lts_config.logGroup = config.log_group_id
            lts_config.logStream = config.log_stream_id

            producer = Producer.init_producer(lts_config)
            producer.start_producer()
            logger.info("LTS Producer created with config:")
            logger.info("  logGroupId: %s", config.log_group_id)
            logger.info("  logStreamId: %s", config.log_stream_id)
            logger.info("  logGroupName: %s", config.log_group_name)
            logger.info("  logStreamName: %s", config.log_stream_name)
            logger.info("  endpoint: %s", config.lts_endpoint)
            logger.info("  region: %s", region)
            logger.info("  backupDir: %s", config.backup_dir)
            return producer
        except Exception as e:
            logger.warning("Failed to create LTS Producer, LTS logging will be disabled: %s", str(e))
            return None

    def send_struct_log(self, struct_log: dict) -> None:
        if not self._initialized:
            return
        sanitized = self._sanitize_log(struct_log)
        try:
            if self._producer is not None:
                self._do_send(sanitized)
            self._metrics.add_buffer_log_count(1)
            logger.debug("Sent log to buffer, buffer count: %s", self._metrics.buffer_log_count)
        except Exception as e:
            self._handle_exception(e, [sanitized])

    def send_batch_struct_log(self, struct_logs: List[dict]) -> None:
        if not self._initialized or struct_logs is None or len(struct_logs) == 0:
            return
        sanitized_logs = [self._sanitize_log(log) for log in struct_logs]
        try:
            if self._producer is not None:
                for log_item in sanitized_logs:
                    self._do_send(log_item)
            self._metrics.add_buffer_log_count(len(sanitized_logs))
            logger.debug("Sent batch %d logs to buffer, total buffer count: %s",
                         len(sanitized_logs), self._metrics.buffer_log_count)
        except Exception as e:
            self._handle_exception(e, sanitized_logs)

    def _sanitize_log(self, struct_log: dict) -> dict:
        sanitized = {}
        for key, value in struct_log.items():
            if isinstance(value, str):
                sanitized[key] = sanitize(value)
            else:
                sanitized[key] = value
        return sanitized

    def _do_send(self, struct_log: dict) -> None:
        try:
            from huaweicloud_encryptionsdk._lts_sdk.producer.model import lts_store

            log_group_id = self._log_config.log_group_id
            log_stream_id = self._log_config.log_stream_id

            if not log_group_id or not log_stream_id:
                logger.warning("logGroupId or logStreamId is not configured, skipping log send")
                return

            content = json.dumps(struct_log, ensure_ascii=False)
            labels = {"source": "EncryptionSDK_PYTHON"}
            log_p = lts_store.generate_log([content], labels)

            self._producer.send_log_with_callback(log_group_id, log_stream_id, log_p, _LtsLogCallBack(self, [struct_log]))
        except Exception as e:
            self._handle_failure([struct_log], sanitize(str(e)))

    def _handle_success(self, logs: list) -> None:
        self._metrics.last_report_time = int(time.time() * 1000)
        self._metrics.increment_success_count()
        self._metrics.add_success_log_count(len(logs))
        self._metrics.add_buffer_log_count(-len(logs))

    def _handle_failure(self, logs: list, error_message: str) -> None:
        self._metrics.increment_failure_count()
        self._metrics.add_failure_log_count(len(logs))
        self._metrics.last_error_message = error_message
        self._metrics.last_error_time = int(time.time() * 1000)
        logger.warn("Log report failed: %d logs, error: %s, saving to backup dir", len(logs), error_message)
        try:
            backup_path = self._log_file_backup.save_failed_logs(logs, int(time.time() * 1000))
            if backup_path:
                logger.info("Failed logs backed up to: %s", backup_path)
            else:
                logger.warn("Failed to save failed logs to backup directory")
        except Exception as e:
            logger.error("Error saving failed logs to backup: %s", str(e))

    def _handle_exception(self, e: Exception, logs: list) -> None:
        error_message = sanitize(str(e))
        self._metrics.increment_failure_count()
        self._metrics.add_failure_log_count(len(logs))
        self._metrics.last_error_message = error_message
        self._metrics.last_error_time = int(time.time() * 1000)
        logger.warn("Log report exception: %d logs, error: %s", len(logs), error_message, exc_info=e)
        try:
            backup_path = self._log_file_backup.save_failed_logs(logs, int(time.time() * 1000))
            if backup_path:
                logger.info("Failed logs backed up to: %s", backup_path)
            else:
                logger.warn("Failed to save failed logs to backup directory")
        except Exception as ex:
            logger.error("Error saving failed logs to backup: %s", str(ex))

    def _recover_failed_logs_on_startup(self) -> None:
        if not self._log_config.enable_recovery_on_startup:
            return
        recovered_logs = self._log_file_backup.recover_failed_logs()
        if recovered_logs:
            batch_size = max(1, self._log_config.recovery_batch_size)
            batch_interval = self._log_config.recovery_batch_interval / 1000.0
            for i in range(0, len(recovered_logs), batch_size):
                batch = recovered_logs[i:i + batch_size]
                self.send_batch_struct_log(batch)
                if i + batch_size < len(recovered_logs):
                    time.sleep(batch_interval)

    @property
    def metrics(self) -> LogMetrics:
        return self._metrics

    def reset_metrics(self) -> None:
        self._metrics.reset()

    def close(self) -> None:
        if not self._initialized:
            return
        try:
            if self._producer is not None:
                logger.info("LTS Producer closing, flushing remaining logs...")
                self._flush_remaining_logs()
                self._wait_send_complete()
                self._wait_submit_pool_and_save_failed()
                self._producer = None
                logger.info("LTS Producer closed")
        except Exception as e:
            logger.error("Failed to close LTS Producer: %s", str(e))
        finally:
            self._initialized = False

    def _flush_remaining_logs(self) -> None:
        try:
            accumulator = self._producer.accumulator
            io_thread_pool = self._producer.io_thread_pool
            if accumulator is None or io_thread_pool is None:
                return
            accumulator.accumulator_lock.acquire_write()
            try:
                if accumulator.log_batch_map:
                    for key, batch in accumulator.log_batch_map.items():
                        io_thread_pool.add_task(batch)
                    logger.info("Flushed %d remaining log batches to LTS", len(accumulator.log_batch_map))
                    accumulator.log_batch_map = {}
            finally:
                accumulator.accumulator_lock.release_write()
        except Exception as e:
            logger.error("Failed to flush remaining logs: %s", str(e))

    def _wait_send_complete(self, timeout: int = 30) -> None:
        try:
            io_thread_pool = self._producer.io_thread_pool
            if io_thread_pool is None:
                return
            start = time.time()
            while time.time() - start < timeout:
                queue_size = io_thread_pool.task_queue_size()
                if queue_size <= 0:
                    time.sleep(1)
                    logger.info("All LTS log tasks completed")
                    return
                time.sleep(0.5)
            logger.warning("LTS log tasks not completed within %s seconds, force closing", timeout)
        except Exception as e:
            logger.error("Failed to wait for send complete: %s", str(e))

    def _wait_submit_pool_and_save_failed(self) -> None:
        try:
            io_thread_pool = self._producer.io_thread_pool
            if io_thread_pool is not None and hasattr(io_thread_pool, '_submit_thread_pool'):
                submit_pool = io_thread_pool._submit_thread_pool
                if submit_pool is not None:
                    logger.info("Waiting for in-flight LTS requests to complete...")
                    submit_pool.shutdown(wait=True)
                    logger.info("All in-flight LTS requests completed")
        except Exception as e:
            logger.error("Failed to wait for submit thread pool: %s", str(e))

        try:
            retry_queue = None
            io_thread_pool = self._producer.io_thread_pool
            if io_thread_pool is not None and io_thread_pool.io_worker is not None:
                retry_queue = io_thread_pool.io_worker._retry_queue

            if retry_queue is not None:
                saved_count = 0
                while not retry_queue.empty():
                    try:
                        batch = retry_queue.get_nowait()
                        for call_back in batch.call_back_list:
                            if isinstance(call_back, _LtsLogCallBack):
                                self._log_file_backup.save_failed_logs(
                                    call_back._logs, int(time.time() * 1000))
                                saved_count += len(call_back._logs)
                    except Exception:
                        break
                if saved_count > 0:
                    logger.info("Saved %d failed logs from retry queue to backup", saved_count)
        except Exception as e:
            logger.error("Failed to save inflight failed logs: %s", str(e))

    @property
    def producer(self):
        return self._producer
