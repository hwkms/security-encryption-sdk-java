#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DSC reporter for obfuscation tracking"""

import hashlib
from typing import Optional

from .dsc_config import DscConfig
from .dsc_http_client import DscHttpClient
from .client_ip_util import ClientIpUtil
from ..utils.c_utils.log_util import log


class DscReporter:
    """Reporter for DSC obfuscation tracking with mandatory validation"""

    _instance: Optional['DscReporter'] = None
    _initialized: bool = False

    def __init__(self):
        """Initialize DSC reporter."""
        self._enabled = False
        self._http_client: Optional[DscHttpClient] = None

        # Load config from environment
        config = DscConfig.from_env()
        if config:
            self._enabled = True
            self._http_client = DscHttpClient(config)
        else:
            log.warning("DSC configuration not found in environment variables, DSC reporting disabled. "
                        f"Missing environment variables: {', '.join(DscConfig.get_missing_env_vars())}")

    def _log_disabled(self):
        """DSC 未启用时输出缺失的环境变量，便于用户排查配置问题。"""
        message = ("DSC configuration not found in environment variables, obfuscation aborted. "
                   f"Missing environment variables: {', '.join(DscConfig.get_missing_env_vars())}")
        print(f"[DSC Reporter] {message}")
        log.error(message)

    @classmethod
    def get_instance(cls) -> 'DscReporter':
        """Get singleton instance of DscReporter.

        Returns:
            DscReporter: Singleton instance
        """
        if cls._instance is None:
            cls._instance = cls()
            cls._initialized = True
        return cls._instance

    def report_model(self, model_name: str, model_type: str, seed_content_bytes: bytes) -> bool:
        """Report model obfuscation info to DSC.

        Args:
            model_name: Model file name
            model_type: Model type
            seed_content_bytes: Seed content bytes for computing digest

        Returns:
            bool: True if DSC is activated, False otherwise (must exit)
        """
        print(f"[DSC Reporter] report_model called, enabled={self._enabled}")
        if not self._enabled:
            self._log_disabled()
            return False

        try:
            seed_digest = hashlib.sha256(seed_content_bytes).hexdigest()
            body = {
                "report_type": "model",
                "model_info": {
                    "model_name": model_name,
                    "model_type": model_type,
                    "seed_digest": seed_digest
                }
            }
            response = self._http_client.report_and_check(body)
            activated = response.get("activated", False)
            if not activated:
                log.error("DSC security zone not activated, obfuscation aborted")
                return False

            return True

        except Exception as e:
            log.error(f"DSC report failed: {str(e)}, obfuscation aborted")
            return False

    def report_client(self, seed_content_bytes: bytes) -> bool:
        """Report client obfuscation info to DSC.

        Args:
            seed_content_bytes: Seed content bytes for computing digest

        Returns:
            bool: True if DSC is activated, False otherwise (must exit)
        """
        if not self._enabled:
            self._log_disabled()
            return False

        try:
            seed_digest = hashlib.sha256(seed_content_bytes).hexdigest()
            client_ip = ClientIpUtil.get_client_ip()
            body = {
                "report_type": "client",
                "client_info": {
                    "client_ip": client_ip,
                    "seed_digest": seed_digest
                }
            }
            response = self._http_client.report_and_check(body)
            activated = response.get("activated", False)
            if not activated:
                log.error("DSC security zone not activated, obfuscation aborted")
                return False

            return True

        except Exception as e:
            log.error(f"DSC report failed: {str(e)}, obfuscation aborted")
            return False
