import os
import sys

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest
from huaweicloud_encryptionsdk.keyrings.kms_keyring_factory import KmsKeyringFactory


def parse_properties(config_path):
    """解析 .properties 配置文件，返回字典"""
    props = {}
    with open(config_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                props[key.strip()] = value.strip()
    return props


def parse_encryption_context(props):
    """从配置中解析 encryption_context，支持两种格式：
    1. encryption_context.xxx=value（前缀格式）
    2. encryption_context=k1:v1,k2:v2（紧凑格式）
    """
    prefix = "encryption_context."
    context = {}
    for key, value in props.items():
        if key.startswith(prefix):
            context[key[len(prefix):]] = value
    if context:
        return context
    compact = props.get("encryption_context")
    if compact:
        for pair in compact.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                context[k.strip()] = v.strip()
    return context


def main():
    # if len(sys.argv) < 2:
    #     print("Usage: python kms_discovery_encryption_example.py <config.properties>")
    #     sys.exit(1)
    #
    # config_path = sys.argv[1]
    # if not os.path.exists(config_path):
    #     print(f"Config file not found: {config_path}")
    #     sys.exit(1)
    #
    # props = parse_properties(config_path)
    #
    # required_keys = ["ak", "sk", "kms.projectId", "kms.region", "kms.keyId", "test.plainText"]
    # missing = [k for k in required_keys if k not in props]
    # if missing:
    #     print(f"Missing required config: {', '.join(missing)}")
    #     sys.exit(1)

    ak = "HPUAYRH5AFOCQPSRDCSH"
    sk = "QrI1qWMRTQva5tOu5LvTUZu3vEoCt7FOTWsqf6Rz"
    project_id = "b23d3033a81d4739901790c63a74f7ef"
    region = "cn-north-4"
    key_id = "19416758-5131-424a-9a81-afcfee7969d4"
    plain_text = "测试数据0802"

    # ak = "HPUAUV4D8QNT9CVENDM6"
    # sk = "UAr5KV317Vq1sxASOfzrHhmnV3eFj1gseba5JAxa"
    # project_id = "d4e559b49b3b403da5279723299ed4a6"
    # region = "cn-north-7"
    # key_id = "cc05882f-6e26-4b57-a450-dc5020acf4f4"
    # plain_text = "测试数据0802"

    algo_name = "AES_256_GCM_NOPADDING"
    crypto_algorithm = CryptoAlgorithm[algo_name]

    kms_config_list = [KMSConfig(region=region, key_id=key_id, project_id=project_id, verify=False)]

    huawei_config = HuaweiConfig(
        ak=ak,
        sk=sk,
        kms_config_list=kms_config_list,
        crypto_algorithm=crypto_algorithm,
        is_discovery=True,
    )

    keyring = KmsKeyringFactory().get_keyring(KeyringTypeEnum.KMS_MULTI_REGION.type)

    huawei_crypto = HuaweiCrypto(huawei_config).with_keyring(keyring)

    encryption_context = {"encryption": "context", "simple": "test", "caching": "encrypt"}

    result = huawei_crypto.encrypt(
        EncryptRequest(encryption_context=encryption_context, plain_text=plain_text.encode("utf-8"))
    )

    huawei_config_discovery = HuaweiConfig(ak=ak, sk=sk)
    keyring_discovery = KmsKeyringFactory().get_keyring(KeyringTypeEnum.KMS_DISCOVERY.type)
    huawei_crypto_decrypt = HuaweiCrypto(huawei_config_discovery).with_keyring(keyring_discovery)

    decrypt_result = huawei_crypto_decrypt.decrypt(result.result)

    assert plain_text.encode("utf-8") == decrypt_result.result, "Decrypted data does not match original"
    print("KMS discovery encryption example completed successfully!")


if __name__ == "__main__":
    main()
