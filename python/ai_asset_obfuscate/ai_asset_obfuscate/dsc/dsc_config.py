#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DSC configuration from environment variables"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class DscConfig:
    """DSC configuration loaded from environment variables"""

    # 必填环境变量清单（用于缺失时提示用户）
    REQUIRED_ENV_VARS = ('DSC_AK', 'DSC_SK', 'PROJECT_ID', 'DSC_ENDPOINT')

    ak: str
    sk: str
    project_id: str
    endpoint: str
    security_token: Optional[str] = None

    @classmethod
    def get_missing_env_vars(cls) -> list:
        """返回缺失的必填环境变量名称列表，便于用户排查配置问题。"""
        return [name for name in cls.REQUIRED_ENV_VARS if not os.getenv(name)]

    @classmethod
    def from_env(cls) -> Optional['DscConfig']:
        """Load configuration from environment variables.

        Required environment variables:
        - DSC_AK: Access Key
        - DSC_SK: Secret Key
        - PROJECT_ID: Project ID (note: not DSC_PROJECT_ID)
        - DSC_ENDPOINT: DSC service endpoint

        Optional environment variables:
        - DSC_SECURITY_TOKEN: Security token for temporary credentials
        """
        ak = os.getenv('DSC_AK')
        sk = os.getenv('DSC_SK')
        project_id = os.getenv('PROJECT_ID')  # Note: PROJECT_ID, not DSC_PROJECT_ID
        endpoint = os.getenv('DSC_ENDPOINT')
        security_token = os.getenv('DSC_SECURITY_TOKEN')

        if not all([ak, sk, project_id, endpoint]):
            return None

        return cls(
            ak=ak,
            sk=sk,
            project_id=project_id,
            endpoint=endpoint,
            security_token=security_token
        )
