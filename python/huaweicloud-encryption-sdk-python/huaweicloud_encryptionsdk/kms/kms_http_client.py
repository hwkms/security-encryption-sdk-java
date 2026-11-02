import json
import logging

import requests

from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig

logger = logging.getLogger(__name__)

SIGNATURE_ALGORITHM = "SDK-HMAC-SHA256"
CONTENT_TYPE_JSON = "application/json"
CONNECT_TIMEOUT_SECONDS = 10
SOCKET_TIMEOUT_SECONDS = 10


class KmsHttpClient:

    def __init__(self, ak: str, sk: str, kms_config: KMSConfig, security_token: str = ""):
        self._ak = ak
        self._sk = sk
        self._kms_config = kms_config
        self._security_token = security_token
        self._signer = self._create_signer()

    def _create_signer(self):
        from huaweicloud_encryptionsdk._apig_sdk import signer
        sig = signer.Signer()
        sig.Key = self._ak
        sig.Secret = self._sk
        return sig

    def post(self, uri, body, response_type=None):
        return self._execute("POST", uri, body, response_type)

    def get(self, uri, response_type=None):
        return self._execute("GET", uri, None, response_type)

    def put(self, uri, body, response_type=None):
        return self._execute("PUT", uri, body, response_type)

    def delete(self, uri, body, response_type=None):
        return self._execute("DELETE", uri, body, response_type)

    def _execute(self, method, uri, body, response_type):
        from huaweicloud_encryptionsdk._apig_sdk.signer import HttpRequest
        url = self._build_url(uri)
        json_body = json.dumps(body, default=self._json_default) if body is not None else None
        try:
            r = HttpRequest(method, url)
            r.headers["Content-Type"] = CONTENT_TYPE_JSON
            if self._security_token:
                r.headers["X-Security-Token"] = self._security_token
            if json_body is not None:
                r.body = json_body

            self._signer.Sign(r)

            logger.info("[EncryptionSDK] KMS Request: %s %s", method, url)
            if json_body is not None:
                logger.debug("[EncryptionSDK] KMS Request Body: %s", json_body)

            resp = requests.request(
                method=r.method,
                url=r.scheme + "://" + r.host + r.uri,
                headers=r.headers,
                data=r.body,
                timeout=(CONNECT_TIMEOUT_SECONDS, SOCKET_TIMEOUT_SECONDS)
            )
            request_id = resp.headers.get("X-Request-Id", "")
            logger.info("[EncryptionSDK] X-Request-Id is %s", request_id)
            logger.info("[EncryptionSDK] KMS Response Status: %s", resp.status_code)
            logger.debug("[EncryptionSDK] KMS Response Body: %s", resp.text[:1024] if resp.text else "")
            if resp.status_code != 200:
                raise HuaweicloudException(
                    "KMS API call failed, status=" + str(resp.status_code)
                    + ", body=" + resp.text
                )
            response_data = resp.json()
            if response_type is not None:
                return self._deserialize_response(response_data, response_type)
            return response_data
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.KMS_CREATE_KEY_EXCEPTION.message, e)

    def _build_url(self, uri):
        endpoint = self._kms_config.end_point
        if not endpoint:
            raise HuaweicloudException(ErrorMessage.END_POINT_NOT_NULL.message)
        if not endpoint.startswith("http://") and not endpoint.startswith("https://"):
            endpoint = "https://" + endpoint
        return endpoint + "/v1.0/" + self._kms_config.project_id + uri

    @staticmethod
    def _deserialize_response(data, response_type):
        if hasattr(response_type, 'from_dict'):
            return response_type.from_dict(data)
        obj = response_type()
        for key, value in data.items():
            attr_name = key.replace("-", "_").replace(" ", "_")
            if hasattr(obj, attr_name):
                setattr(obj, attr_name, value)
        return obj

    @staticmethod
    def _json_default(obj):
        if hasattr(obj, '__dict__'):
            result = {}
            for key, value in obj.__dict__.items():
                if value is not None:
                    json_key = key.lstrip('_')
                    result[json_key] = value
            return result
        return str(obj)
