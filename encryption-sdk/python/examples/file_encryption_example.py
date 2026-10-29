import base64
import sys

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.keyrings.raw_keyring_factory import RawKeyringFactory


def compare_file(source_file_path: str, target_file_path: str) -> bool:
    import os
    if os.path.getsize(source_file_path) != os.path.getsize(target_file_path):
        return False
    with open(source_file_path, "rb") as sf, open(target_file_path, "rb") as tf:
        while True:
            source_chunk = sf.read(1024)
            target_chunk = tf.read(1024)
            if not source_chunk:
                break
            if source_chunk != target_chunk:
                return False
    return True


def main():
    if len(sys.argv) < 5:
        print("Usage: python file_encryption_example.py <symmetric_key> <source_file> <encrypted_file> <decrypted_file>")
        sys.exit(1)

    symmetry_key = sys.argv[1]
    source_file_path = sys.argv[2]
    target_file_path = sys.argv[3]
    backup_file_path = sys.argv[4]

    huawei_config = HuaweiConfig(
        crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING,
    )

    keyring = RawKeyringFactory().get_keyring(KeyringTypeEnum.RAW_AES.type)

    key_bytes = base64.b64decode(symmetry_key.encode("utf-8"))
    keyring.set_symmetric_key([key_bytes])

    huawei_crypto = HuaweiCrypto(huawei_config).with_keyring(keyring)

    encryption_context = {"key": "value", "context": "encrypt"}

    huawei_crypto.encrypt_file(source_file_path, target_file_path, encryption_context)

    huawei_crypto.decrypt_file(target_file_path, backup_file_path)

    assert compare_file(source_file_path, backup_file_path), "Decrypted file does not match original"
    print("File encryption example completed successfully!")


if __name__ == "__main__":
    main()
