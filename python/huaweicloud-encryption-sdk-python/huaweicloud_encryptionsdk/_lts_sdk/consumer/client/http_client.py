import json
from json import JSONDecodeError

import requests
import urllib3
from loguru import logger
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

from huaweicloud_encryptionsdk._lts_sdk.auth.signer import Signer
from consumer.model.check_point import ShardCheckPoint, Cursor
from consumer.model.consumer_config import ConsumerConfig
from consumer.model.log_data import BatchGetLog
from huaweicloud_encryptionsdk._lts_sdk.producer.lts_http.simple_request import LtsRequest
from huaweicloud_encryptionsdk._lts_sdk.producer.model import error
from huaweicloud_encryptionsdk._lts_sdk.utils import common


class HttpClient(object):
    def __init__(self, config: ConsumerConfig):
        self._session = requests.Session()
        self._signer = Signer()
        self._config = config

        retry_strategy = Retry(
            total=2,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
        urllib3.disable_warnings(InsecureRequestWarning)

    @staticmethod
    def connect_query_string(query_map, url):
        if query_map is None or len(query_map) == 0:
            return url
        query_list = []
        for key, value in query_map.items():
            query_list.append(key + "=" + value)

        query_url = "&".join(query_list)
        return url + "?" + query_url

    def heart_beat(self, project_id, log_group_id, log_stream_id, consumer_group_name, consumer, all_shards):
        interface = f"/v2/{project_id}/groups/{log_group_id}/streams/{log_stream_id}/consumer-groups/{consumer_group_name}/heartbeat"
        query_map = {"consumer_name": consumer}
        body = common.convert_obj2_json_str(all_shards)
        r = self.generate_request("POST", interface, query_map, body, self._config)
        try:
            begin_time = common.current_time_ms()
            response = self._session.send(r, verify=False)
            response.encoding = "utf-8"
            end_time = common.current_time_ms()
            logger.debug("httpclient url is {}, code is {}, body is {}, result is {}, cost [{}]ms", r.url,
                         response.status_code,
                         body,
                         response.content.decode("utf-8"),
                         end_time - begin_time)
            if response.status_code == 200:
                result_str = response.content.decode("utf-8")
                try:
                    result = json.loads(result_str)
                except JSONDecodeError as e:
                    logger.info("heart beat result is not json: {}", result_str)
                    return error.Error(error_code=error.RESULT_JSON_FORMAT_ERROR_CODE,
                                       error_msg=result_str,
                                       http_code=response.status_code), None
                return None, result
            else:
                return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=response.content.decode("utf-8"),
                                   http_code=response.status_code), None
        except Exception as e:
            logger.error("httpclient url is {}, exception is {}", r.url, str(e))
            return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=str(e), http_code=0), None

    def fetch_consumer_group(self, project_id, log_group_id, log_stream_id, consumer_group_name, shard_id):
        interface = f"/v2/{project_id}/groups/{log_group_id}/streams/{log_stream_id}/consumer-groups/{consumer_group_name}"
        query_map = None
        if len(shard_id) > 0:
            query_map = {"shard_id": shard_id}
        r = self.generate_request("GET", interface, query_map, "", self._config)
        try:
            begin_time = common.current_time_ms()
            response = self._session.send(r, verify=False)
            end_time = common.current_time_ms()
            response.encoding = "utf-8"
            logger.debug("httpclient url is {}, code is {}, result is {}, cost [{}]ms", r.url, response.status_code,
                         response.content.decode("utf-8"), end_time - begin_time)
            if response.status_code == 200:
                result_str = response.content.decode("utf-8")
                try:
                    result = common.convert_json_str2_list_obj(result_str, ShardCheckPoint)
                except JSONDecodeError as e:
                    logger.error("fetch_consumer_group result is not json: {}", result_str)
                    return error.Error(error_code=error.RESULT_JSON_FORMAT_ERROR_CODE,
                                       error_msg=result_str,
                                       http_code=response.status_code), None
                return None, result
            else:
                return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=response.content.decode("utf-8"),
                                   http_code=response.status_code), None
        except Exception as e:
            logger.error("httpclient url is {}, exception is {}", r.url, str(e))
            return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=str(e), http_code=0), None

    def get_cursor_by_time(self, project_id, log_group_id, log_stream_id, shard_id, time):
        interface = f"/v2/{project_id}/groups/{log_group_id}/streams/{log_stream_id}/shards/{shard_id}/cursor"
        query_map = {"from": time}
        r = self.generate_request("GET", interface, query_map, "", self._config)
        try:
            begin_time = common.current_time_ms()
            response = self._session.send(r, verify=False)
            end_time = common.current_time_ms()
            response.encoding = "utf-8"
            logger.info("httpclient url is {}, code is {}, result is {}, cost [{}]ms", r.url, response.status_code,
                        response.content.decode("utf-8"), end_time - begin_time)
            if response.status_code == 200:
                result_str = response.content.decode("utf-8")
                try:
                    result = common.convert_json_str2_obj(result_str, Cursor)
                except JSONDecodeError as e:
                    logger.error("get_cursor_by_time result is not json: {}", result_str)
                    return error.Error(error_code=error.RESULT_JSON_FORMAT_ERROR_CODE,
                                       error_msg=result_str,
                                       http_code=response.status_code), None
                return None, result
            else:
                return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=response.content.decode("utf-8"),
                                   http_code=response.status_code), None
        except Exception as e:
            logger.error("httpclient url is {}, exception is {}", r.url, str(e))
            return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=str(e), http_code=0), None

    def update_check_point(self, project_id, log_group_id, log_stream_id, consumer_group_name, shard_id, consumer,
                           check_point):
        interface = f"/v2/{project_id}/groups/{log_group_id}/streams/{log_stream_id}/consumer-groups/{consumer_group_name}"
        query_map = {"consumer_name": consumer}
        request_body = []
        param = {"shard_id": shard_id, "checkpoint": check_point}
        request_body.append(param)
        logger.debug("update check point, shard_id {}, checkpoint {} request_body is {}", shard_id, check_point,
                     request_body)
        body = common.convert_obj2_json_str(request_body)
        r = self.generate_request("POST", interface, query_map, body, self._config)
        try:
            begin_time = common.current_time_ms()
            response = self._session.send(r, verify=False)
            end_time = common.current_time_ms()
            response.encoding = "utf-8"
            logger.debug("httpclient url is {}, code is {}, body is {}, result is {}, cost [{}]ms", r.url,
                         response.status_code,
                         body,
                         response.content.decode("utf-8"), end_time - begin_time)
            if response.status_code == 200:
                return None
            else:
                return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=response.content.decode("utf-8"),
                                   http_code=response.status_code)
        except Exception as e:
            logger.error("httpclient url is {}, exception is {}", r.url, str(e))
            return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=str(e), http_code=0)

    def batch_get_log(self, project_id, log_group_id, log_stream_id, shard_id, batch_size, start_time, end_time):
        interface = f"/v2/{project_id}/groups/{log_group_id}/streams/{log_stream_id}/shards/{shard_id}"
        query_map = {"limit": batch_size, "start": start_time}
        if len(end_time) > 0:
            query_map["end"] = end_time
        r = self.generate_request("GET", interface, query_map, "", self._config)
        try:
            begin_time = common.current_time_ms()
            response = self._session.send(r, verify=False)
            end_time = common.current_time_ms()
            response.encoding = "utf-8"
            logger.debug("httpclient url is {} query map is {}, code is {}, result is {}, cost [{}]ms", r.url,
                         query_map,
                         response.status_code,
                         response.content.decode("utf-8"), end_time - begin_time)
            if response.status_code == 200:
                result_str = response.content.decode("utf-8")
                try:
                    result = common.convert_json_str2_obj(result_str, BatchGetLog)
                except JSONDecodeError as e:
                    logger.error("batch_get_log result is not json: {}", result_str)
                    return error.Error(error_code=error.RESULT_JSON_FORMAT_ERROR_CODE,
                                       error_msg=result_str,
                                       http_code=response.status_code), None
                return None, result
            else:
                return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=response.content.decode("utf-8"),
                                   http_code=response.status_code), None
        except Exception as e:
            logger.error("httpclient url is {}, exception is {}", r.url, str(e))
            return error.Error(error_code=error.HTTP_QUEST_ERROR_CODE, error_msg=str(e), http_code=0), None

    def generate_request(self, method, interface, query_map, body, config):
        header = {"content-type": "application/json"}
        if query_map is None:
            req = LtsRequest(method=method, host=config.endpoint, headers=header, body=body, region=config.region_name,
                             interface=interface, ak=config.access_key, sk=config.access_secret)
            request = self._signer.sign(req)
            r = request.prepare()
            return r
        else:
            req = LtsRequest(method=method, host=config.endpoint, headers=header, body=body, region=config.region_name,
                             interface=interface, ak=config.access_key, sk=config.access_secret, **query_map)
            request = self._signer.sign(req)
            r = request.prepare()
            return r
