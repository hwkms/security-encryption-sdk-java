#!/usr/bin/python3.11
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
"""配置文件，用于打包AI混淆项目

支持双架构打包：
    python setup.py bdist_wheel --plat-name manylinux2014_x86_64
    python setup.py bdist_wheel --plat-name manylinux2014_aarch64

打包时根据 --plat-name 自动从 libs/ai_asset_obfuscate_libs_x86_64 或
libs/ai_asset_obfuscate_libs_aarch64 目录选择对应架构的 .so，
拷贝到构建产物 ai_asset_obfuscate/libs/ 根目录（运行时按该路径加载）。
"""

import os
import shutil
import sys

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py

# ---------- 双架构 .so 目录配置 ----------
LIBS_DIR = os.path.join("ai_asset_obfuscate", "libs")
ARCH_LIB_DIRS = {
    "x86_64": os.path.join(LIBS_DIR, "ai_asset_obfuscate_libs_x86_64"),
    "aarch64": os.path.join(LIBS_DIR, "ai_asset_obfuscate_libs_aarch64"),
}
REQUIRED_SO = ("libkmc.so", "libobfuscate.so", "libsdp.so", "libsecurec.so")


def detect_arch(plat_name):
    """从 bdist_wheel 的 plat_name 推断目标架构。"""
    plat = (plat_name or "").lower()
    if "aarch64" in plat or "arm64" in plat or plat.startswith("arm"):
        return "aarch64"
    return "x86_64"


def elf_arch(path):
    """读取 ELF 头的 e_machine 字段判断架构（纯Python，无外部依赖）。

    ELF 头第 18-19 字节（小端）为 e_machine：0x3E=x86-64，0xB7=aarch64。
    返回 'x86_64' / 'aarch64'，无法识别时返回 None。
    """
    try:
        with open(path, "rb") as f:
            head = f.read(20)
        if head[:4] != b"\x7fELF":
            return None
        machine = int.from_bytes(head[18:20], "little")
        return {0x3E: "x86_64", 0xB7: "aarch64"}.get(machine)
    except OSError:
        return None


class BuildPyWithArchLibs(build_py):
    """按 --plat-name 选择对应架构 .so 拷入构建产物，并校验架构一致性。"""

    def _target_arch(self):
        # 从命令行解析出的 plat_name 获取目标架构（bdist_wheel 在 build 之前已 finalize）
        for cmd_name in ("bdist_wheel", "bdist"):
            try:
                cmd = self.get_finalized_command(cmd_name)
                plat_name = getattr(cmd, "plat_name", None)
                if plat_name:
                    return detect_arch(plat_name)
            except Exception:
                continue
        return None

    def run(self):
        arch = self._target_arch()
        if arch is None:
            sys.exit("[build] 无法从 bdist_wheel/bdist 获取 plat_name，"
                     "请使用: python setup.py bdist_wheel --plat-name manylinux2014_x86_64 "
                     "或 --plat-name manylinux2014_aarch64")
        src_dir = ARCH_LIB_DIRS[arch]

        # 源目录完整性检查
        missing = [n for n in REQUIRED_SO if not os.path.isfile(os.path.join(src_dir, n))]
        if missing:
            sys.exit(f"[build] {src_dir} 缺少 {arch} 架构的 .so 文件: {missing}")

        # 架构一致性校验（防止目录里的 .so 放错）
        for name in REQUIRED_SO:
            real = elf_arch(os.path.join(src_dir, name))
            if real != arch:
                sys.exit(f"[build] 架构校验失败: {src_dir}/{name} 实际为 {real}，"
                         f"与目标架构 {arch} 不一致")

        super().run()

        # 拷贝到构建产物 libs/ 根层（运行时 c_lib.py 按该路径加载）
        dst_dir = os.path.join(self.build_lib, LIBS_DIR)
        os.makedirs(dst_dir, exist_ok=True)
        # 先清理产物目录下已有的 .so，防止陈旧 build 残留其他架构的库
        for old in os.listdir(dst_dir):
            if old.endswith(".so"):
                os.remove(os.path.join(dst_dir, old))
        for name in REQUIRED_SO:
            shutil.copy2(os.path.join(src_dir, name), os.path.join(dst_dir, name))
        print(f"[build] 已选择 {arch} 架构 .so（来源: {src_dir}），"
              f"拷贝 {len(REQUIRED_SO)} 个文件到构建产物")


setup(
    name="huaweicloud-ai-asset-obfuscate",  # 打包后包的文件名
    version='26.0.0.8',  # 版本号
    description="混淆算子SDK,用于模型混淆和用户参数混淆",
    packages=find_packages(),
    package_data={"ai_asset_obfuscate": ["libs/*so", "conf/**"]},  # 数据文件全部打包
    cmdclass={"build_py": BuildPyWithArchLibs},
    install_requires=[
        "huaweicloudsdkcore>=3.1.208",
        "requests",
    ],
)
