import base64
import logging
import sys

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.keyrings.raw_keyring_factory import RawKeyringFactory
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest

logger = logging.getLogger(__name__)


def main():
    key_bytes = base64.b64decode("I+BmZXZEftgtsDfs5YNnUg==")

    config = HuaweiConfig(crypto_algorithm=CryptoAlgorithm.SM4_128_CBC_PADDING)
    keyring = RawKeyringFactory().get_keyring(KeyringTypeEnum.RAW_SM4_CBC.type)
    keyring.set_symmetric_key([key_bytes])

    crypto = HuaweiCrypto(config).with_keyring(keyring)

    plain_text = b"Hello, SM4-CBC!"
    req = EncryptRequest(plain_text=plain_text)
    result = crypto.encrypt(req)
    logger.info("加密成功, 密文HEX: %s", result.result.hex())

    decrypt_result = crypto.decrypt(result.result)
    logger.info("解密成功: %s", decrypt_result.result.decode("utf-8"))

    assert plain_text == decrypt_result.result
    print("SM4-CBC test passed!")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    main()
