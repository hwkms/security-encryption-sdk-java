#!/usr/bin/python3.11
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from safetensors import safe_open
import safetensors.torch
import torch


class BaseTestCase(unittest.TestCase):
    obf_cfg = "obf_conf_json"
    model_dir = "model/qwen2"

    def setUp(self):
        self.patcher = patch("ctypes.CDLL")
        self.mock_cdll = self.patcher.start()
        self.mock_lib = self.mock_cdll.return_value
        self.mock_lib.DecryptData.return_value = 0
        self.mock_lib.EncryptData.return_value = 0
        self.mock_lib.InitLog.return_value = 0
        self.mock_lib.GenerateRandomBytes.return_value = 0
        self.mock_lib.GenerateObfAndDeObfDict.return_value = 0
        # Mock for new C++ interfaces
        self.mock_lib.CreateWeightObfuscator.return_value = 0x12345678
        self.mock_lib.DestroyWeightObfuscator.return_value = None
        self.mock_lib.ApplyWeightObfuscation.return_value = 0
        self.mock_lib.GeneratePatchAndChannelPermute.return_value = 0

    def tearDown(self):
        self.patcher.stop()
        if os.path.exists(self.model_path_safetensor):
            os.remove(self.model_path_safetensor)
        if os.path.exists(self.model_path_pth):
            os.remove(self.model_path_pth)
        if os.path.exists(self.flag_config_path):
            os.remove(self.flag_config_path)

    def initial_model_resources(self, test_model):
        self.model_dir = os.path.join(Path(__file__).resolve().parent, 'resources', self.model_dir)
        self.conf_dir = os.path.join(Path(__file__).resolve().parent, 'resources', self.obf_cfg)
        self.model_path_safetensor = os.path.join(self.model_dir, 'model.safetensors')
        self.model_path_pth = os.path.join(self.model_dir, 'model.pth')
        self.flag_config_path = os.path.join(self.model_dir, 'obf_config.json')
        self.test_model = test_model
        safetensors.torch.save_file(self.test_model, self.model_path_safetensor, metadata={"format": "pt"})
        torch.save(self.test_model, self.model_path_pth)
        self.output_dir_path = os.path.join(Path(__file__).resolve().parent, 'resources', 'obf_model')
        Path(self.output_dir_path).mkdir(exist_ok=True)


class TestModelObfuscation(BaseTestCase):
    def setUp(self):
        super().setUp()
        test_model = {"model.embed_tokens.weight": torch.tensor(
            [[-1.0071e-02 for _ in range(6)] for _ in range(6)], dtype=torch.bfloat16),
            "model.embed_tokens.weight.test_mtp": torch.tensor(
                [[-1.0071e-02 for _ in range(12)] for _ in range(6)], dtype=torch.bfloat16),
            "model.embed_tokens1.weight": torch.tensor(
                [[-1.0071e-02 for _ in range(6)] for _ in range(6)], dtype=torch.bfloat16),
            "model.embed_tokens1.weight.test_mtp": torch.tensor(
                [[-1.0071e-02 for _ in range(12)] for _ in range(6)], dtype=torch.bfloat16)
        }

        self.initial_model_resources(test_model)
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        self.model = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir, 1,
                                                                           token_white_list=[0, 1])

        set_seed_result = self.model.set_seed_content(1, "a" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        set_seed_result = self.model.set_seed_content(2, "b" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.output_dir_path, ignore_errors=True)

    def test_model_weight_obf_0_0_no_output_dir_path(self):
        obf_result = self.model.model_weight_obf(0, 0)
        from ai_asset_obfuscate import ErrorCode
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_model_weight_obf_0_0(self):
        obf_result = self.model.model_weight_obf(0, 0, self.output_dir_path)
        from ai_asset_obfuscate import ErrorCode
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_model_weight_obf_0_1(self):
        obf_result = self.model.model_weight_obf(0, 1, self.output_dir_path)
        from ai_asset_obfuscate import ErrorCode
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_model_weight_obf_1_0(self):
        obf_result = self.model.model_weight_obf(1, 0, self.output_dir_path)
        from ai_asset_obfuscate import ErrorCode
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_model_weight_obf_1_1(self):
        obf_result = self.model.model_weight_obf(1, 1, self.output_dir_path)
        from ai_asset_obfuscate import ErrorCode
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_model_weight_obf_2_0(self):
        obf_result = self.model.model_weight_obf(2, 0, self.output_dir_path)
        from ai_asset_obfuscate import ErrorCode
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_model_weight_obf_2_1(self):
        obf_result = self.model.model_weight_obf(2, 1, self.output_dir_path)
        from ai_asset_obfuscate import ErrorCode
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_model_weight_obf_cpu(self):
        obf_result = self.model.model_weight_obf(2, 1, self.output_dir_path, 'cpu')
        from ai_asset_obfuscate import ErrorCode
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_model_qwen_7b(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ModelType
        self.model = ModelAssetObfuscation.create_model_obfuscation(self.model_dir, ModelType.DEEPSEEK_QWEN_7B, 1)

    def test_model_weight_obf_error_param(self):
        from ai_asset_obfuscate import ErrorCode
        obf_result = self.model.model_weight_obf(3, 1, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.INVALID_OBF_TYPE.value)

        set_seed_result = self.model.set_seed_content(2, "a" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(2, 2, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.INVALID_PARAM.value)

        set_seed_result = self.model.set_seed_content(2, "b" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(2, 1, b'test')
        self.assertEqual(obf_result, ErrorCode.INVALID_PATH.value)

        set_seed_result = self.model.set_seed_content(2, "c" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(2, 1, os.path.join(self.output_dir_path, "a", "b"))
        self.assertEqual(obf_result, ErrorCode.INVALID_PATH.value)

        obf_result = self.model.model_weight_obf(2, 1, self.model_dir)
        self.assertEqual(obf_result, ErrorCode.UNMATCHED_OBF_TYPE.value)
        set_seed_result = self.model.set_seed_content(2, "d" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(2, 1, self.output_dir_path, 'npu', [1, 2, '1'])
        self.assertEqual(obf_result, ErrorCode.INVALID_DEVICE_ID.value)

        target = os.path.join(self.conf_dir, 'config.json')
        link_name = 'example_config.json'
        os.symlink(target, link_name)
        set_seed_result = self.model.set_seed_content(2, "e" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(2, 1, link_name)
        os.remove(link_name)
        self.assertEqual(obf_result, ErrorCode.INVALID_PATH.value)

    def test_model_obfuscation_when_input_error(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ObfException
        from ai_asset_obfuscate import ErrorCode
        with self.assertRaises(ObfException) as context:
            ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir, 4)
        self.assertEqual(context.exception.message, ErrorCode.MODEL_CONFIG_INVALID_HIDDEN_SIZE.message)
        with self.assertRaises(ObfException) as context:
            ModelAssetObfuscation()
        self.assertEqual(context.exception.message, ErrorCode.MODEL_PATH_FAILED.message)

    def test_model_obf_when_dim_error(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        conf_dir_error_dim = os.path.join(Path(__file__).resolve().parent, 'resources', 'obf_conf_error_dim')
        model_obf = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, conf_dir_error_dim)
        result = model_obf.set_seed_content(1, "a" * 32, False, None)
        self.assertEqual(result, ErrorCode.CONFIGURATION_FILE_FORMAT_ERROR.value)

    def test_model_weight_obf_flag_none(self):
        from ai_asset_obfuscate import ErrorCode
        self.model.flag = None
        set_seed_result = self.model.set_seed_content(1, "b" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        set_seed_result = self.model.set_seed_content(2, "c" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(0, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.INVALID_FLAG.value)

        set_seed_result = self.model.set_seed_content(1, "d" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(1, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.INVALID_FLAG.value)

        set_seed_result = self.model.set_seed_content(2, "e" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(2, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.INVALID_FLAG.value)

    def test_model_weight_obf_flag_invalid(self):
        from ai_asset_obfuscate import ErrorCode
        self.model.flag = "invalid_flag"
        set_seed_result = self.model.set_seed_content(1, "b" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        set_seed_result = self.model.set_seed_content(2, "a" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(0, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.INVALID_FLAG.value)

        set_seed_result = self.model.set_seed_content(1, "a" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(1, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.INVALID_FLAG.value)

        set_seed_result = self.model.set_seed_content(2, "a" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(2, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.INVALID_FLAG.value)

    def test_obf_model_after_obf_model(self):
        from ai_asset_obfuscate import ErrorCode
        from ai_asset_obfuscate.constants import Constant
        self.model.flag = Constant.MODEL_CONFUSED
        obf_result = self.model.model_weight_obf(0, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.MODEL_ALREADY_OBFUSCATED.value)

    def test_obf_data_after_obf_model(self):
        from ai_asset_obfuscate import ErrorCode
        from ai_asset_obfuscate.constants import Constant
        self.model.flag = Constant.MODEL_CONFUSED
        obf_result = self.model.model_weight_obf(1, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.MODEL_ALREADY_OBFUSCATED.value)

    def test_obf_all_after_obf_model(self):
        from ai_asset_obfuscate import ErrorCode
        from ai_asset_obfuscate.constants import Constant
        self.model.flag = Constant.MODEL_CONFUSED
        obf_result = self.model.model_weight_obf(2, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_obf_data_after_obf_data(self):
        from ai_asset_obfuscate import ErrorCode
        from ai_asset_obfuscate.constants import Constant
        self.model.flag = Constant.DATA_CONFUSED
        obf_result = self.model.model_weight_obf(0, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.DATA_ALREADY_OBFUSCATED.value)

    def test_obf_model_after_obf_data(self):
        from ai_asset_obfuscate import ErrorCode
        from ai_asset_obfuscate.constants import Constant
        self.model.flag = Constant.DATA_CONFUSED
        obf_result = self.model.model_weight_obf(1, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_obf_all_after_obf_data(self):
        from ai_asset_obfuscate import ErrorCode
        from ai_asset_obfuscate.constants import Constant
        self.model.flag = Constant.DATA_CONFUSED
        obf_result = self.model.model_weight_obf(2, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.DATA_ALREADY_OBFUSCATED.value)

    def test_model_weight_obf_flag_model_and_data(self):
        from ai_asset_obfuscate import ErrorCode
        from ai_asset_obfuscate.constants import Constant
        self.model.flag = Constant.BOTH_CONFUSED
        obf_result = self.model.model_weight_obf(0, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.OBFUSCATION_ALREADY_COMPLETED.value)

        set_seed_result = self.model.set_seed_content(1, "x" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(1, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.OBFUSCATION_ALREADY_COMPLETED.value)

        set_seed_result = self.model.set_seed_content(2, "y" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        obf_result = self.model.model_weight_obf(2, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.OBFUSCATION_ALREADY_COMPLETED.value)

    def test_model_weight_obf_flag_seed_content(self):
        from ai_asset_obfuscate import ErrorCode
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate.constants import Constant
        import json
        flag_config = {"flag": Constant.MODEL_CONFUSED}
        with open(self.flag_config_path, 'w', encoding='utf-8') as f:
            json.dump(flag_config, f, indent=4, ensure_ascii=False)
        self.model = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir, 1,
                                                                           token_white_list=[0, 1])
        self.model.set_seed_content(1, "m" * 32, False, None)
        self.model.set_seed_content(2, "n" * 32, False, None)
        obf_result = self.model.model_weight_obf(2, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

    def test_model_metadata(self):
        from ai_asset_obfuscate import ErrorCode
        obf_result = self.model.model_weight_obf(0, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)
        safetensors_files = []
        for root, _, files in os.walk(self.output_dir_path):
            for file in files:
                if file.endswith(".safetensors"):
                    safetensors_files.append((root, file))
        for root, file in safetensors_files:
            original_file_path = os.path.join(self.model_dir, file)
            target_file_path = os.path.join(root, file)
            with safe_open(original_file_path, framework="pt") as f:
                original_metadata = f.metadata()
            with safe_open(target_file_path, framework="pt") as f:
                new_metadata = f.metadata()
            self.assertEqual(original_metadata, new_metadata)

    def test_model_weight_obf_op_type(self):
        self.temp_dir = tempfile.mkdtemp(dir=os.path.join(Path(__file__).resolve().parent, 'resources'))
        self.copied_conf_dir = os.path.join(self.temp_dir, 'obf_conf_json')
        shutil.copytree(self.conf_dir, self.copied_conf_dir)
        self.model_file_path = os.path.join(self.copied_conf_dir, 'model_protection_config.json')
        self.data_file_path = os.path.join(self.copied_conf_dir, 'data_protection_config_model_confused.json')
        import json

        with open(self.model_file_path, "r") as file:
            if self.obf_cfg == "obf_conf_json":
                value_model = json.load(file)
            else:
                value_model = json.load(file).get("weight_map", {})

        value_model["model.embed_tokens.weight"].append([15, 0])
        with open(self.model_file_path, "w") as file:
            json.dump(value_model, file, indent=4)
        with open(self.data_file_path, "r") as file:
            if self.obf_cfg == "obf_conf_json":
                value_data = json.load(file)
            else:
                value_data = json.load(file).get("weight_map", {})
        value_data["model.embed_tokens.weight"].append([2, 1, 0, 2, 4])
        with open(self.data_file_path, 'w') as file:
            json.dump(value_data, file, indent=4)
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        self.model = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.copied_conf_dir)
        result = self.model.set_seed_content(1, "q" * 32)
        self.assertEqual(result, ErrorCode.CONFIGURATION_FILE_FORMAT_ERROR.value)
        result = self.model.set_seed_content(2, "k" * 32)
        self.assertEqual(result, ErrorCode.CONFIGURATION_FILE_FORMAT_ERROR.value)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_model_obf_when_seed_error(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        model_obf = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir)
        result = model_obf.set_seed_content(3, "a" * 32)
        self.assertEqual(result, ErrorCode.INVALID_SEED_TYPE.value)
        result = model_obf.set_seed_content(2, 111)
        self.assertEqual(result, ErrorCode.INVALID_SEED_CONTENT.value)
        result = model_obf.set_seed_content(1)
        self.assertEqual(result, ErrorCode.INVALID_SEED_CONTENT.value)


class TestModelDeObfuscation(BaseTestCase):
    def setUp(self):
        super().setUp()
        test_model = {"model.embed_tokens.weight": torch.tensor(
            [[i + row for i in range(6)] for row in range(6)], dtype=torch.bfloat16),
            "model.embed_tokens.weight.test_mtp": torch.tensor(
                [[i + row for i in range(12)] for row in range(6)], dtype=torch.bfloat16),
            "model.embed_tokens1.weight": torch.tensor(
                [[i + row for i in range(6)] for row in range(6)], dtype=torch.bfloat16),
            "model.embed_tokens1.weight.test_mtp": torch.tensor(
                [[i + row for i in range(12)] for row in range(6)], dtype=torch.bfloat16)
        }
        self.initial_model_resources(test_model)
        self.de_output_dir_path = os.path.join(Path(__file__).resolve().parent, 'resources', 'de_obf_model')
        Path(self.de_output_dir_path).mkdir(exist_ok=True)

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.output_dir_path, ignore_errors=True)
        shutil.rmtree(self.de_output_dir_path, ignore_errors=True)

    def compare_tensor_content(self, van_model_path, de_model_path):
        obf_size = 0
        with safe_open(van_model_path, framework="pt", device='cpu') as f_van:
            van_keys = list(f_van.keys())
            for key in van_keys:
                van = f_van.get_tensor(key)
                with safe_open(de_model_path, framework="pt", device='cpu') as f_obf:
                    de_obf = f_obf.get_tensor(key)
                layer_obf = torch.sum(van != de_obf).item()
                obf_size += layer_obf
        return obf_size

    def test_model_weight_obf_2_deobf_2(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        self.model_van = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir, 1,
                                                                               token_white_list=[0, 1])
        self.model_van.set_seed_content(2, "c" * 32, False, None)
        obf_result = self.model_van.model_weight_obf(2, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)
        self.model_obf = ModelAssetObfuscation.create_custom_model_obfuscation(self.output_dir_path, self.conf_dir,
                                                                               1, token_white_list=[0, 1],
                                                                               is_obfuscation=False)
        self.model_obf.set_seed_content(2, "a" * 32, False, None)
        de_obf_result = self.model_obf.model_weight_obf(2, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.SUCCESS.value)
        van_model_path = self.model_path_safetensor
        de_model_path = os.path.join(self.de_output_dir_path, "model.safetensors")
        obf_size = self.compare_tensor_content(van_model_path, de_model_path)
        
        self.assertEqual(106, obf_size)

    def test_model_weight_obf_1_deobf_1(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        self.model_van = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir)
        self.model_van.set_seed_content(1, "a" * 32, False, None)
        obf_result = self.model_van.model_weight_obf(1, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)
        obf_flag_config_path = os.path.join(self.output_dir_path, 'obf_config.json')
        if os.path.exists(obf_flag_config_path):
            os.remove(obf_flag_config_path)
        self.model_obf = ModelAssetObfuscation.create_custom_model_obfuscation(self.output_dir_path, self.conf_dir,
                                                                               is_obfuscation=False)
        self.model_obf.set_seed_content(1, "b" * 32, False, None)
        de_obf_result = self.model_obf.model_weight_obf(1, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.SUCCESS.value)
        van_model_path = self.model_path_safetensor
        de_model_path = os.path.join(self.de_output_dir_path, "model.safetensors")
        obf_size = self.compare_tensor_content(van_model_path, de_model_path)
        
        self.assertEqual(106, obf_size)

    def test_model_weight_obf_0_deobf_0(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        self.model_van = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir)
        self.model_van.set_seed_content(1, "a" * 32, False, None)
        self.model_van.set_seed_content(2, "b" * 32, False, None)
        obf_result = self.model_van.model_weight_obf(0, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)
        obf_flag_config_path = os.path.join(self.output_dir_path, 'obf_config.json')
        if os.path.exists(obf_flag_config_path):
            os.remove(obf_flag_config_path)
        self.model_obf = ModelAssetObfuscation.create_custom_model_obfuscation(self.output_dir_path, self.conf_dir,
                                                                               is_obfuscation=False)
        self.model_obf.set_seed_content(1, "c" * 32, False, None)
        self.model_obf.set_seed_content(2, "d" * 32, False, None)
        de_obf_result = self.model_obf.model_weight_obf(0, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.SUCCESS.value)
        van_model_path = self.model_path_safetensor
        de_model_path = os.path.join(self.de_output_dir_path, "model.safetensors")
        obf_size = self.compare_tensor_content(van_model_path, de_model_path)
       
        self.assertEqual(106, obf_size)

    def test_model_weight_obf_0_deobf_error(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        self.model_van = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir)
        self.model_van.set_seed_content(1, "a" * 32, False, None)
        self.model_van.set_seed_content(2, "b" * 32, False, None)
        obf_result = self.model_van.model_weight_obf(0, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

        self.model_obf = ModelAssetObfuscation.create_custom_model_obfuscation(self.output_dir_path, self.conf_dir,
                                                                               is_obfuscation=False)
        self.model_obf.set_seed_content(1, "c" * 32, False, None)
        self.model_obf.set_seed_content(2, "d" * 32, False, None)
        de_obf_result = self.model_obf.model_weight_obf(0, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.INVALID_DE_OBFUSCATION.value)

        set_seed_result = self.model_obf.set_seed_content(1, "e" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        de_obf_result = self.model_obf.model_weight_obf(1, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.INVALID_DE_OBFUSCATION.value)

        set_seed_result = self.model_obf.set_seed_content(2, "f" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        de_obf_result = self.model_obf.model_weight_obf(2, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.INVALID_DE_OBFUSCATION.value)

    def test_model_weight_obf_1_deobf_error(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        self.model_van = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir)
        self.model_van.set_seed_content(1, "1" * 32, False, None)
        obf_result = self.model_van.model_weight_obf(1, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

        self.model_obf = ModelAssetObfuscation.create_custom_model_obfuscation(self.output_dir_path, self.conf_dir,
                                                                               is_obfuscation=False)
        self.model_obf.set_seed_content(1, "1" * 32, False, None)
        self.model_obf.set_seed_content(2, "b" * 32, False, None)
        de_obf_result = self.model_obf.model_weight_obf(0, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.INVALID_DE_OBFUSCATION.value)

        set_seed_result = self.model_obf.set_seed_content(1, "c" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        de_obf_result = self.model_obf.model_weight_obf(1, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.INVALID_DE_OBFUSCATION.value)

        set_seed_result = self.model_obf.set_seed_content(2, "d" * 32, False, None)
        self.assertEqual(ErrorCode.SUCCESS.value, set_seed_result)
        de_obf_result = self.model_obf.model_weight_obf(2, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.INVALID_DE_OBFUSCATION.value)

    def test_model_weight_obf_2_deobf_error(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ErrorCode
        self.model_van = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir)
        self.model_van.set_seed_content(2, "a" * 32, False, None)
        obf_result = self.model_van.model_weight_obf(2, 0, self.output_dir_path)
        self.assertEqual(obf_result, ErrorCode.SUCCESS.value)

        self.model_obf = ModelAssetObfuscation.create_custom_model_obfuscation(self.output_dir_path, self.conf_dir,
                                                                               is_obfuscation=False)
        self.model_obf.set_seed_content(1, "1" * 32, False, None)
        self.model_obf.set_seed_content(2, "2" * 32, False, None)
        de_obf_result = self.model_obf.model_weight_obf(0, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.INVALID_DE_OBFUSCATION.value)
        self.model_obf.set_seed_content(1, "d" * 32, False, None)
        de_obf_result = self.model_obf.model_weight_obf(1, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.INVALID_DE_OBFUSCATION.value)
        self.model_obf.set_seed_content(2, "e" * 32, False, None)
        de_obf_result = self.model_obf.model_weight_obf(2, 0, self.de_output_dir_path)
        self.assertEqual(de_obf_result, ErrorCode.SUCCESS.value)

    def test_model_weight_obf_is_obfuscation(self):
        from ai_asset_obfuscate import ModelAssetObfuscation
        from ai_asset_obfuscate import ObfException
        from ai_asset_obfuscate import ErrorCode
        self.model = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir)
        self.assertTrue(self.model.is_obfuscation)
        self.model = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir,
                                                                           is_obfuscation=True)
        self.assertTrue(self.model.is_obfuscation)
        self.model = ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir,
                                                                           is_obfuscation=False)
        self.assertFalse(self.model.is_obfuscation)
        with self.assertRaises(ObfException) as context:
            ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir, is_obfuscation="test")
        self.assertEqual(context.exception.message, ErrorCode.INVALID_PARAM.message)
        with self.assertRaises(ObfException) as context:
            ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir, is_obfuscation=1)
        self.assertEqual(context.exception.message, ErrorCode.INVALID_PARAM.message)
        with self.assertRaises(ObfException) as context:
            ModelAssetObfuscation.create_custom_model_obfuscation(self.model_dir, self.conf_dir, is_obfuscation=None)
        self.assertEqual(context.exception.message, ErrorCode.INVALID_PARAM.message)


class TestAssemblyCfgModelObfuscation(TestModelObfuscation):
    obf_cfg = "assemble_obf_conf_json"
    model_dir = "model/qwen3_vl_moe"


if __name__ == '__main__':
    unittest.main()
