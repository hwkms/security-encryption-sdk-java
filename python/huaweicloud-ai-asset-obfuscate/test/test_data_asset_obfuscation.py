#!/usr/bin/python3.11
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

import unittest
from unittest.mock import patch
import os
import json
import base64
from io import BytesIO

from PIL import Image
import torchvision


class TestDataAssetObfuscation(unittest.TestCase):

    def setUp(self):
        self.patcher = patch("ctypes.CDLL")
        self.mock_cdll = self.patcher.start()
        self.mock_lib = self.mock_cdll.return_value
        self.mock_lib.DecryptData.return_value = 0
        self.mock_lib.GenerateRandomBytes.return_value = 0
        self.mock_lib.GenerateObfAndDeObfDict.return_value = 0
        self.mock_lib.InitLog.return_value = 0
        self.mock_lib.EncryptData.return_value = 0
        self.mock_lib.CreateWeightObfuscator.return_value = 0x12345678
        self.mock_lib.DestroyWeightObfuscator.return_value = None
        self.mock_lib.ApplyWeightObfuscation.return_value = 0
        self.mock_lib.GeneratePatchAndChannelPermute.return_value = 0
        from ai_asset_obfuscate import DataAssetObfuscation
        from ai_asset_obfuscate.vision_api import ImageDataAssetObfuscation, VideoDataAssetObfuscation
        self.asset_obj = DataAssetObfuscation(10)
        self.asset_obj.set_seed_content('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.', False, None)

        self.asset_obj_white_list = DataAssetObfuscation(10, [1, 2, 3])
        self.asset_obj_white_list.set_seed_content('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.', False, None)

        self.image_obj = ImageDataAssetObfuscation()
        self.image_obj.set_seed_content('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.', False, None)

        self.video_obj = VideoDataAssetObfuscation()
        self.video_obj.set_seed_content('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.', False, None)

    def tearDown(self):
        self.patcher.stop()

    def test_set_seed_safer(self):
        from ai_asset_obfuscate import ErrorCode
        result = self.asset_obj.set_seed_safer(("mnt/cert/ca.pem", "mnt/cert/cfs.pem", "mnt/cert/cfs.key", 1024,
                                                "test", "test"), ("test", "test", "test"))
        self.assertEqual(result, ErrorCode.INVALID_PARAM.value)

    def test_export_set_obf_seed(self):
        from ai_asset_obfuscate import ErrorCode
        from ai_asset_obfuscate import TLSConfig
        from ai_asset_obfuscate import PskConfig
        tls = TLSConfig("mnt/cert/ca.pem", "mnt/cert/cfs.pem", "mnt/cert/cfs.key", "test", "test")
        psk = PskConfig("test", "test", "test")
        result = self.asset_obj.export_set_obf_seed(tls, psk, [0, 0])
        self.assertEqual(result, ErrorCode.INVALID_PARAM.value)

    def test_data_2d_obf(self):
        tokens = [[1, 2, 3], [4, 5, 6]]
        obf_tokens = self.asset_obj.data_2d_obf(tokens)
        self.assertEqual(len(obf_tokens), 2)
        self.assertEqual(len(obf_tokens[0]), 3)
        self.assertNotEqual(obf_tokens[0][0], 1)

    def test_data_1d_obf(self):
        tokens = [1, 2, 3]
        obf_tokens = self.asset_obj.data_1d_obf(tokens)
        self.assertEqual(len(obf_tokens), 3)
        self.assertNotEqual(obf_tokens[0], 1)

    def test_data_2d_deobf(self):
        tokens = [[1, 2, 3], [4, 5, 6]]
        obf_tokens = self.asset_obj.data_2d_deobf(tokens)
        self.assertEqual(len(obf_tokens), 2)
        self.assertEqual(len(obf_tokens[0]), 3)
        self.assertNotEqual(obf_tokens[0][0], 1)

    def test_data_1d_deobf(self):
        marks = [1, 2, 3]
        obf_tokens = self.asset_obj.data_1d_deobf(marks)
        self.assertEqual(len(obf_tokens), 3)
        self.assertNotEqual(obf_tokens[0], 1)

    def test_data_token_obf(self):
        obf_tokens = self.asset_obj.token_obf(1)
        self.assertNotEqual(obf_tokens, 1)

    def test_data_token_deobf(self):
        obf_tokens = self.asset_obj.token_deobf(1)
        self.assertNotEqual(obf_tokens, 1)

    def test_set_seed_when_exception(self):
        from ai_asset_obfuscate import ErrorCode
        error_code = self.asset_obj.set_seed_content('')
        self.assertEqual(error_code, ErrorCode.INVALID_SEED_CONTENT.value)

    def test_data_2d_obf_when_exception(self):
        from ai_asset_obfuscate import ObfException
        from ai_asset_obfuscate import ErrorCode
        tokens = [[1, 2, 3], [4, 5, 10]]
        with self.assertRaises(ObfException) as context:
            self.asset_obj.data_2d_obf(tokens)
            self.assertEqual(context.exception.message, ErrorCode.ITEM_VALIDATE_FAILED.value)
        tokens = [[1, 2, 3], [4, 5, '10']]
        with self.assertRaises(ObfException) as context:
            self.asset_obj.data_2d_obf(tokens)
            self.assertEqual(context.exception.message, ErrorCode.ITEM_VALIDATE_FAILED.value)

    def test_set_seed_white_list(self):
        from ai_asset_obfuscate import ErrorCode
        error_code = self.asset_obj_white_list.set_seed_content('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.')
        self.assertEqual(error_code, ErrorCode.SUCCESS.value)

    def test_image_init_with_valid_params(self):
        from ai_asset_obfuscate.vision_api import ImageDataAssetObfuscation
        image_obj = ImageDataAssetObfuscation()
        self.assertEqual(image_obj.patch_size, 16)
        self.assertEqual(image_obj.merge_size, 2)
        self.assertEqual(image_obj.longest_edge, 16777216)
        self.assertEqual(image_obj.shortest_edge, 65536)
        self.assertEqual(image_obj.temporal_patch_size, 2)

    def test_image_init_with_invalid_params(self):
        from ai_asset_obfuscate.vision_api import ImageDataAssetObfuscation
        from ai_asset_obfuscate import ObfException
        from ai_asset_obfuscate import ErrorCode
        with self.assertRaises(ObfException) as context:
            ImageDataAssetObfuscation(patch_size='invalid')
        self.assertEqual(context.exception.message, ErrorCode.INVALID_PARAM.message)

    def test_image_create_by_config_with_valid_config(self):
        from ai_asset_obfuscate.vision_api import ImageDataAssetObfuscation
        image_config_path = 'image_test_config.json'
        image_valid_config = {
            "patch_size": 16,
            "merge_size": 2,
            "size": {"longest_edge": 16777216, "shortest_edge": 65536},
            "temporal_patch_size": 2
        }
        with open(image_config_path, 'w') as f:
            json.dump(image_valid_config, f)
        image_obj = ImageDataAssetObfuscation.create_by_config(image_config_path)
        self.assertEqual(image_obj.patch_size, 16)
        self.assertEqual(image_obj.merge_size, 2)
        self.assertEqual(image_obj.longest_edge, 16777216)
        self.assertEqual(image_obj.shortest_edge, 65536)
        self.assertEqual(image_obj.temporal_patch_size, 2)
        if os.path.exists(image_config_path):
            os.remove(image_config_path)

    def test_image_create_by_config_with_invalid_config_path(self):
        from ai_asset_obfuscate.vision_api import ImageDataAssetObfuscation
        from ai_asset_obfuscate import ObfException
        from ai_asset_obfuscate import ErrorCode
        with self.assertRaises(ObfException) as context:
            ImageDataAssetObfuscation.create_by_config('invalid_path.json')
        self.assertEqual(context.exception.message, ErrorCode.INVALID_PATH.message)

    def test_image_create_by_config_with_invalid_json(self):
        from ai_asset_obfuscate.vision_api import ImageDataAssetObfuscation
        from ai_asset_obfuscate import ObfException
        from ai_asset_obfuscate import ErrorCode
        image_config_path = 'image_test_config.json'
        with open(image_config_path, 'w') as f:
            f.write('invalid json')
        with self.assertRaises(ObfException) as context:
            ImageDataAssetObfuscation.create_by_config(image_config_path)
        self.assertEqual(context.exception.message, ErrorCode.INVALID_JSON_FILE.message)
        if os.path.exists(image_config_path):
            os.remove(image_config_path)

    def test_image_base64_obf_with_invalid_base64_string(self):
        from ai_asset_obfuscate import ObfException
        from ai_asset_obfuscate import ErrorCode
        with self.assertRaises(ObfException) as context:
            self.image_obj.image_base64_obf('invalid_base64_string')
        self.assertEqual(context.exception.message, ErrorCode.INVALID_BASE64_STRING.message)

    def test_image_base64_obf_with_valid_image(self):
        test_image = Image.new('RGBA', (100, 100), color='red')
        test_image_bytes = BytesIO()
        test_image.save(test_image_bytes, format='PNG')
        # 创建一个base64编码的图片
        test_image_base64 = 'data:image/png;base64,' + base64.b64encode(test_image_bytes.getvalue()).decode('utf-8')
        obf_base64 = self.image_obj.image_base64_obf(test_image_base64)
        self.assertIsInstance(obf_base64, str)

    def test_image_bytearray_obf_with_valid_image(self):
        test_image = Image.new('RGB', (5000, 5000), color='red')
        test_image_bytes = BytesIO()
        test_image.save(test_image_bytes, format='JPEG')
        test_image_bytearray = bytearray(test_image_bytes.getvalue())
        obf_bytearray = self.image_obj.image_bytearray_obf(test_image_bytearray)
        self.assertIsInstance(obf_bytearray, bytearray)

    def test_image_bytearray_obf_with_long_bytes(self):
        from ai_asset_obfuscate import ObfException
        from ai_asset_obfuscate import ErrorCode
        byte_array = bytearray(30 * 1024 * 1024)
        with self.assertRaises(ObfException) as context:
            self.image_obj.image_bytearray_obf(byte_array)
        self.assertEqual(context.exception.message, ErrorCode.INVALID_PARAM.message)

    def test_image_base64_obf_with_long_string(self):
        from ai_asset_obfuscate import ObfException
        from ai_asset_obfuscate import ErrorCode
        image = 'a' * 30 * 1024 * 1024
        with self.assertRaises(ObfException) as context:
            self.image_obj.image_base64_obf(image)
        self.assertEqual(context.exception.message, ErrorCode.INVALID_PARAM.message)

    def test_video_init(self):
        from ai_asset_obfuscate.vision_api import VideoDataAssetObfuscation
        from ai_asset_obfuscate import ObfException
        obfuscation = VideoDataAssetObfuscation()
        self.assertEqual(obfuscation.patch_size, 16)
        self.assertEqual(obfuscation.merge_size, 2)
        self.assertEqual(obfuscation.longest_edge, 25165824)
        self.assertEqual(obfuscation.shortest_edge, 4096)
        self.assertEqual(obfuscation.temporal_patch_size, 2)

        with self.assertRaises(ObfException):
            VideoDataAssetObfuscation(patch_size='invalid')

    def test_video_create_by_config(self):
        video_config_path = 'video_test_config.json'
        video_valid_config = {
            "patch_size": 16,
            "merge_size": 2,
            "size": {"longest_edge": 25165824, "shortest_edge": 4096},
            "temporal_patch_size": 2
        }
        from ai_asset_obfuscate.vision_api import VideoDataAssetObfuscation
        from ai_asset_obfuscate import ObfException
        with open(video_config_path, 'w') as f:
            json.dump(video_valid_config, f)

        obfuscation = VideoDataAssetObfuscation.create_by_config(video_config_path)
        self.assertEqual(obfuscation.patch_size, 16)
        self.assertEqual(obfuscation.merge_size, 2)
        self.assertEqual(obfuscation.longest_edge, 25165824)
        self.assertEqual(obfuscation.shortest_edge, 4096)
        self.assertEqual(obfuscation.temporal_patch_size, 2)

        with self.assertRaises(ObfException):
            VideoDataAssetObfuscation.create_by_config('nonexistent.json')

        with open(video_config_path, 'w') as f:
            json.dump({"patch_size": 16}, f)

        with self.assertRaises(ObfException):
            VideoDataAssetObfuscation.create_by_config(video_config_path)
        if os.path.exists(video_config_path):
            os.remove(video_config_path)

    def test_image_bytearray_obf(self):
        video = 'R0lGODlhIAAgAPAAAP///wAAACH5BAEAAAAALAAAAAAgACAAAAIcEAAn+6nHgBy02otrsTDzDndrSY5SBaKmdqsXWwAAOw=='
        obf_base64 = self.video_obj.video_base64_obf(video)
        self.assertIsInstance(obf_base64, str)