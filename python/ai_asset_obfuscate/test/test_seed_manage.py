#!/usr/bin/python3.11
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

import unittest
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

    def test_distribute_obf_seed(self):
        from ai_asset_obfuscate import distribute_obf_seed
        from ai_asset_obfuscate import TLSConfig
        from ai_asset_obfuscate import PskConfig
        patcher1 = patch.object(TLSConfig, "decrypt_validate")
        patcher2 = patch.object(PskConfig, "decrypt_validate")
        patcher3 = patch("ai_asset_obfuscate.api.seed_manage.call_obf_reg_seed")
        mock1 = patcher1.start()
        mock2 = patcher2.start()
        mock3 = patcher3.start()
        mock1.return_value = True
        mock2.return_value = True
        mock3.return_value = 0
        tls = TLSConfig("test", "test", "test", "test", "test")
        psk = PskConfig("test", "test", "test")
        result = distribute_obf_seed(2, tls, psk, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", [0, 1])
        self.assertEqual(result, (0, 'Success.'))

    def test_local_save_obf_seed(self):
        from ai_asset_obfuscate import local_save_obf_seed
        from ai_asset_obfuscate import ErrorCode
        patcher = patch("ai_asset_obfuscate.api.seed_manage.data_enc_mul")
        mock = patcher.start()
        mock.return_value = 0
        result = local_save_obf_seed(1, "/tmp", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        self.assertEqual(result, ErrorCode.SUCCESS.value)
        result = local_save_obf_seed(1, "/tmp", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        self.assertEqual(result, ErrorCode.INVALID_PARAM.value)
        result = local_save_obf_seed(3, "/tmp", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        self.assertEqual(result, ErrorCode.INVALID_PARAM.value)
        result = local_save_obf_seed(2, None, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        self.assertEqual(result, ErrorCode.INVALID_PARAM.value)
        mock.return_value = 1
        result = local_save_obf_seed(2, "/tmp", None)
        self.assertEqual(result, ErrorCode.ENCRYPT_FAILED.value)
