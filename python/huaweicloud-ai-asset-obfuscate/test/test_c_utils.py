#!/usr/bin/python3.11
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

import unittest
from unittest.mock import patch


class TestCUtils(unittest.TestCase):
    def setUp(self):
        self.patcher = patch("ctypes.CDLL")
        self.mock_cdll = self.patcher.start()
        self.mock_lib = self.mock_cdll.return_value
        self.mock_lib.DecryptData.return_value = 0
        self.mock_lib.EncryptData.return_value = 0
        self.mock_lib.DecryptDataMul.return_value = 0
        self.mock_lib.GenerateRandomBytes.return_value = 0
        self.mock_lib.GenerateObfAndDeObfDict.return_value = 0
        self.mock_lib.InitLog.return_value = 0
        self.mock_lib.CreateWeightObfuscator.return_value = 0x12345678
        self.mock_lib.DestroyWeightObfuscator.return_value = None
        self.mock_lib.ApplyWeightObfuscation.return_value = 0
        self.mock_lib.GeneratePatchAndChannelPermute.return_value = 0

    def tearDown(self):
        self.patcher.stop()

    def test_log(self):
        from ai_asset_obfuscate.utils.c_utils.log_util import ObfLog
        with patch.object(ObfLog, 'record_log') as mock_record_log:
            from ai_asset_obfuscate.utils import log
            log.debug("test")
            log.info("test")
            log.warning("test")
            log.error("test")
            log.critical("test")
            self.assertEqual(mock_record_log.call_count, 5)

    def test_call_obf_del_seed(self):
        from ai_asset_obfuscate.utils.c_utils import obf_tool_util
        from ai_asset_obfuscate import TLSConfig
        tls = TLSConfig("mnt/cert/ca.pem", "mnt/cert/cfs.pem", "mnt/cert/cfs.key", "test",
                        "test")
        tls.set_port(1024)
        tls.passwd = bytearray('test', "utf-8")
        del_result = obf_tool_util.call_obf_del_seed(tls, (1, 2, 3, 4, 5), 1)
        self.assertNotEqual(del_result, None)

    def test_call_obf_reg_seed(self):
        from ai_asset_obfuscate.utils.c_utils import obf_tool_util
        from ai_asset_obfuscate import PskConfig
        from ai_asset_obfuscate import TLSConfig
        tls = TLSConfig("mnt/cert/ca.pem", "mnt/cert/cfs.pem", "mnt/cert/cfs.key", "test",
                        "test")
        tls.set_port(1024)
        psk = PskConfig("test", "test", "test")
        tls.decrypt_validate()
        psk.decrypt_validate()
        with patch.object(TLSConfig, "check_passwd") as mock_tls:
            mock_tls.return_value = True
            tls.decrypt_validate()
        with patch.object(PskConfig, "check_passwd") as mock_psk:
            mock_psk.return_value = True
            psk.decrypt_validate()
        tls.passwd = bytearray('test', 'utf-8')
        psk.passwd = bytearray('test', 'utf-8')
        reg_result = obf_tool_util.call_obf_reg_seed(0, bytearray('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.', "utf-8"),
                                                     (1, 2, 3, 4, 5), psk, tls)
        self.assertNotEqual(reg_result, None)

    def test_call_obf_query_seed(self):
        from ai_asset_obfuscate.utils.c_utils import obf_tool_util
        from ai_asset_obfuscate import PskConfig
        from ai_asset_obfuscate import TLSConfig
        tls = TLSConfig("mnt/cert/ca.pem", "mnt/cert/cfs.pem", "mnt/cert/cfs.key", "test",
                        "test")
        tls.set_port(1024)
        tls.passwd = bytearray('test', "utf-8")
        psk = PskConfig("test", "test", "test")
        psk.passwd = bytearray('test', "utf-8")
        device_id = {0}
        query_result = obf_tool_util.call_obf_query_seed(tls, psk, device_id)
        self.assertEqual(query_result, None)

    def test_data_enc(self):
        from ai_asset_obfuscate.utils.c_utils import obf_tool_util
        result = obf_tool_util.data_enc("mnt/cert/ca.pem",
                                        bytearray('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.', "utf-8"), "test")
        self.assertEqual(result, 0)

    def test_date_dec(self):
        from ai_asset_obfuscate.utils.c_utils import obf_tool_util
        result = obf_tool_util.date_dec("mnt/cert/ca.pem", 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.')
        self.assertEqual(len(result), 128)

    def test_data_enc_mul(self):
        from ai_asset_obfuscate.utils.c_utils import obf_tool_util
        result = obf_tool_util.data_enc_mul("mnt/cert/ca.pem",
                                        bytearray('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.', "utf-8"), "test")
        self.assertNotEqual(result, 0)

    def test_date_dec_mul(self):
        from ai_asset_obfuscate.utils.c_utils import obf_tool_util
        result = obf_tool_util.data_dec_mul("mnt/cert/ca.pem", 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.')
        self.assertEqual(len(result), 128)
