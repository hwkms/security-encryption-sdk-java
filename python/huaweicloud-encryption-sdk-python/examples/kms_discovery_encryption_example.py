import os
import sys

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest
from huaweicloud_encryptionsdk.keyrings.kms_keyring_factory import KmsKeyringFactory


def main():
    if len(sys.argv) < 5:
        print("Usage: python kms_discovery_encryption_example.py <project_id> <region> <key_id> <plain_text>")
        sys.exit(1)

    ak = os.environ.get("CLOUD_SDK_AK")
    sk = os.environ.get("CLOUD_SDK_SK")

    project_id = sys.argv[1]
    region = sys.argv[2]
    key_id = sys.argv[3]
    plain_text = sys.argv[4]

    kms_config_list = [KMSConfig(region=region, key_id=key_id, project_id=project_id)]

    huawei_config = HuaweiConfig(
        ak=ak,
        sk=sk,
        kms_config_list=kms_config_list,
        crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING,
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
