#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DSC HTTP client using huaweicloudsdkcore for signing"""

import json
import requests
from urllib.parse import urlparse
from typing import Dict, Any

from huaweicloudsdkcore.auth.credentials import Credentials
from huaweicloudsdkcore.signer.signer import Signer
from huaweicloudsdkcore.sdk_request import SdkRequest

from .dsc_config import DscConfig


class DscHttpClient:
    """HTTP client for DSC API with Huawei Cloud signature"""

    CONNECT_TIMEOUT = 10  # seconds
    READ_TIMEOUT = 10  # seconds

    def __init__(self, config: DscConfig):
        """Initialize DSC HTTP client.

        Args:
            config: DSC configuration
        """
        self._config = config
        self._credentials = Credentials(ak=config.ak, sk=config.sk)
        self._signer = Signer(self._credentials)

    def _mask(self, text: str) -> str:
        """脱敏处理，避免日志中输出 project_id、AK/SK 等敏感信息。"""
        if not text:
            return text
        for secret in (self._config.project_id, self._config.ak, self._config.sk, self._config.security_token):
            if secret:
                text = text.replace(secret, "***")
        return text

    def report_and_check(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Report to DSC and check activation status.

        POST /v1/{project_id}/data-security-zones/obfuscation

        Args:
            body: Request body (model_info or client_info)

        Returns:
            Dict with 'activated' field

        Raises:
            Exception: If HTTP request fails
        """
        # Parse endpoint URL
        parsed = urlparse(self._config.endpoint)
        scheme = parsed.scheme
        host = parsed.netloc

        # Build resource path
        resource_path = f"/v1/{self._config.project_id}/data-security-zones/obfuscation"

        # Build full URL
        url = f"{scheme}://{host}{resource_path}"

        # Convert body to JSON string
        json_body = json.dumps(body, ensure_ascii=False)

        # Create SDK request
        sdk_request = SdkRequest(
            method="POST",
            schema=scheme,
            host=host,
            resource_path=resource_path,
            header_params={"Content-Type": "application/json"},
            query_params=[],
            body=json_body
        )

        # Add security token if present
        if self._config.security_token:
            sdk_request.header_params["X-Security-Token"] = self._config.security_token

        # Sign the request
        signed_request = self._signer.sign(sdk_request)

        # Send HTTP request
        try:
            # 仅打印请求方法与脱敏后的 URL，不打印请求头（含签名信息）和请求体
            print(f"[DSC Request] POST {self._mask(url)}")

            response = requests.post(
                url,
                headers=signed_request.header_params,
                data=json_body,
                timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT)
            )

            # 仅打印状态码，不打印响应体
            print(f"[DSC Response] Status: {response.status_code}")

            if response.status_code != 200:
                raise Exception(f"DSC API request failed: status={response.status_code}")

            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"[DSC Response] Error: {self._mask(str(e))}")
            raise Exception(f"DSC API request error: {self._mask(str(e))}")
