#!/usr/bin/python3.11
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
import os
import unittest
from pathlib import Path
from unittest.mock import patch


class TestSeedManage(unittest.TestCase):
    def setUp(self):
        self.patcher = patch("ctypes.CDLL")
        self.mock_cdll = self.patcher.start()
        self.mock_lib = self.mock_cdll.return_value
        self.mock_lib.InitLog.return_value = 0
        self.mock_lib.GenerateRandomBytes.return_value = 0
        self.mock_lib.DecryptData.return_value = 0
        self.mock_lib.EncryptData.return_value = 0
        self.mock_lib.CreateWeightObfuscator.return_value = 0x12345678
        self.mock_lib.DestroyWeightObfuscator.return_value = None
        self.mock_lib.ApplyWeightObfuscation.return_value = 0

    def tearDown(self):
        self.patcher.stop()

    def test_passwd_enc_success(self):
        from ai_asset_obfuscate import passwd_enc
        resources_dir = os.path.join(Path(__file__).resolve().parent, 'resources')
        error_code, error_msg = passwd_enc(resources_dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", "test")
        self.assertEqual(error_code, 0)

    def test_passwd_security(self):
        from ai_asset_obfuscate import passwd_enc
        from ai_asset_obfuscate import ErrorCode
        resources_dir = os.path.join(Path(__file__).resolve().parent, 'resources')
        passwd_right = ["Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"]
        passwd_wrong = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "11111111111111111111111111111111111111111", "AAA"]
        for pwd in passwd_right:
            error_code, error_msg = passwd_enc(resources_dir, pwd, "test")
            self.assertEqual(error_code, 0)
        for pwd in passwd_wrong:
            error_code, error_msg = passwd_enc(resources_dir, pwd, "test")
            self.assertEqual(error_code, ErrorCode.INVALID_PARAM.value[0])