import base64
import logging
import sys

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.keyrings.raw_keyring_factory import RawKeyringFactory
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest

logger = logging.getLogger(__name__)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def main():
    if len(sys.argv) < 2:
        print("Usage: python local_aes_encryption_example.py <symmetric_key_base64> [plain_text]")
        print("  symmetric_key_base64: Base64 encoded 16-byte (AES-128) or 32-byte (AES-256) key")
        print("  plain_text: optional, default 'Hello, AES!'")
        sys.exit(1)

    symmetric_key = sys.argv[1]
    plain_text = sys.argv[2] if len(sys.argv) > 2 else "Hello, AES!"

    key_bytes = base64.b64decode(symmetric_key.encode("utf-8"))
    key_len = len(key_bytes)
    if key_len == 16:
        algorithm = CryptoAlgorithm.AES_128_GCM_NOPADDING
    elif key_len == 32:
        algorithm = CryptoAlgorithm.AES_256_GCM_NOPADDING
    else:
        print(f"Error: key length must be 16 or 32 bytes, got {key_len}")
        sys.exit(1)

    config = HuaweiConfig(crypto_algorithm=algorithm)
    keyring = RawKeyringFactory().get_keyring(KeyringTypeEnum.RAW_AES.type)
    keyring.set_symmetric_key([key_bytes])

    crypto = HuaweiCrypto(config).with_keyring(keyring)

    encrypt_request = EncryptRequest(plain_text=plain_text.encode("utf-8"))
    logger.info("原文: %s, HEX: %s", plain_text, bytes_to_hex(plain_text.encode("utf-8")))

    result = crypto.encrypt(encrypt_request)
    logger.info("加密成功，密文HEX: %s", bytes_to_hex(result.result))

    decrypt_result = crypto.decrypt(result.result)
    logger.info("解密成功: %s, HEX: %s", decrypt_result.result.decode("utf-8"), bytes_to_hex(decrypt_result.result))

    assert plain_text.encode("utf-8") == decrypt_result.result, "Decrypted data does not match original"
    print("Local AES encryption example completed successfully!")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    main()
