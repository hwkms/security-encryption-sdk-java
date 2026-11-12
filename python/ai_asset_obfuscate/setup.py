#!/usr/bin/python3.11
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
"""配置文件，用于打包AI混淆项目"""

from setuptools import setup, find_packages

setup(
    name="ai_asset_obfuscate",  # 打包后包的文件名
    version='26.0.0.8',  # 版本号
    description="混淆算子SDK,用于模型混淆和用户参数混淆",
    packages=find_packages(),
    package_data={"ai_asset_obfuscate": ["libs/*so", "conf/**"]},  # 数据文件全部打包
    install_requires=[
        "huaweicloudsdkcore>=3.1.208",
        "requests",
    ],
)