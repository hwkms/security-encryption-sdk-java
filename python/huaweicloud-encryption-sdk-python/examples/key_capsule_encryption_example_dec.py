import logging
import os
import sys

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.keyrings.kms_keyring_factory import KmsKeyringFactory
from huaweicloud_encryptionsdk.model.access_point_config import AccessPointConfig
from huaweicloud_encryptionsdk.model.key_capsule_config import KeyCapsuleConfig
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum

logger = logging.getLogger(__name__)

# ── 配置（写死） ──────────────────────────────────────
AK = "HPUAUTEDGPJLONNQYMWF"
SK = "BGCzZMIMMLiDkhYERFeRPOHb6SFrosgJyBZAwdvR"

KMS_PROJECT_ID = "d4e559b49b3b403da5279723299ed4a6"
KMS_REGION = "cn-north-7"
KMS_KEY_ID = "a5abaf44-136b-4230-8a16-1274d75fa3ee"
KMS_ENDPOINT = "kms.cn-north-7.myhuaweicloud.com"

KEY_CAPSULE_REGION = "cn-north-7"
KEY_CAPSULE_DEFAULT_POLICY_ID = "01a07f03-352c-7000-8ad0-2bdd9f1ffc5c"
ACCESS_POINT_TYPE = 4  # 1-ECS, 2-通用场景, 3-CCE, 4-MA(ModelArts)
ENCRYPTED_PRIVATE_KEY = "AAAAAgAAAAAAAAAAAAAAAQAAAAlzoCbw6ij35aVxHi3NMIKOnsHQk/Psa9jqwh4KAAAAAAEAAAEAAAAAAAAA2PyangvovK9oAHERWaJ7EZ0/GdYY08j6DFuNWXXmoKN9/EGgdG7AZwo1KN16swNVv7zMe7o/mT1yOG2RIAK6ggwHA56AjN4DmuofPVZbLYlD3CRnaCwmUuMSQ1uhpDTz1E/3tjcbNrZUHBBRLqg5km11HVu7OBOU8gOwz8grSITMGgWkXhiN4mSksms3HZfs66hXE0Szhi/QI/8iSSyTlMWA6IP7K2HIwa5bUBzsW28J8I/2dhMvoUSphK31DeSLv3tDYPOVrbo7XM8Pg0wp8/isoTIgUtJkJg=="
PLAIN_PRIVATE_KEY = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg+iPybwNyYht8ZlrtSfKR4w790gr7d/8PcQ4oKOND7wqgCgYIKoZIzj0DAQehRANCAATl7X4/N8N5i6CcJELYMS5cfc9ihIIepzvuJ1NDf5Gd5i1Jq4pxvmozX4luzIyAFDeIDPcaS8rJ750YfcrvgECd"


def main():
    if len(sys.argv) < 2:
        print("Usage: python key_capsule_encryption_example_dec.py <encrypted_file_path>")
        sys.exit(1)

    encrypted_file_path = sys.argv[1]
    if not os.path.exists(encrypted_file_path):
        print(f"Error: file not found: {encrypted_file_path}")
        sys.exit(1)

    decrypt_file_path = encrypted_file_path + ".dec"

    access_point_config = AccessPointConfig(
        type=ACCESS_POINT_TYPE,
        encrypted_private_key=ENCRYPTED_PRIVATE_KEY,
        private_key_decrypt_callback=lambda encrypted_key: PLAIN_PRIVATE_KEY,
    )

    key_capsule_config = KeyCapsuleConfig(
        region=KEY_CAPSULE_REGION,
        default_policy_id=KEY_CAPSULE_DEFAULT_POLICY_ID,
        access_point_config=access_point_config,
    )

    decrypt_config = HuaweiConfig(
        ak=AK,
        sk=SK,
        key_capsule_config=key_capsule_config,
    )
    decrypt_keyring = KmsKeyringFactory().get_keyring(KeyringTypeEnum.KMS_KEY_CAPSULE.type)
    decrypt_crypto = HuaweiCrypto(decrypt_config).with_keyring(decrypt_keyring)

    logger.info("开始解密文件: %s", encrypted_file_path)
    decrypt_crypto.decrypt_file(encrypted_file_path, decrypt_file_path)
    logger.info("解密成功: %s -> %s", encrypted_file_path, decrypt_file_path)
    print(f"Decrypt completed: {encrypted_file_path} -> {decrypt_file_path}")

    decrypt_crypto.close()
    os._exit(0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    main()
