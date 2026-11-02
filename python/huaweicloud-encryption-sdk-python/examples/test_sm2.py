import logging
import sys

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.keyrings.raw_keyring_factory import RawKeyringFactory
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest

logger = logging.getLogger(__name__)

SM2_PRIVATE_KEY = "d7dd778833db7bca5f67a5df84497cc709f0bf1955146c8a82ab22a3d9566631"
SM2_PUBLIC_KEY = "da8582c7d9e6c621f9d4a56ff0b95e7544c14c37aa763ed160473ffa2c7acee333d02543c1e06eaf100fd479f98175f94021a35143aab17fff3d36e23295a45d"


def main():
    keyring = RawKeyringFactory().get_keyring(KeyringTypeEnum.RAW_SM2.type)
    keyring.set_public_key([bytes.fromhex(SM2_PUBLIC_KEY)])
    keyring.set_private_key([bytes.fromhex(SM2_PRIVATE_KEY)])

    config = HuaweiConfig(crypto_algorithm=CryptoAlgorithm.SM4_128_GCM_NOPADDING)
    crypto = HuaweiCrypto(config).with_keyring(keyring)

    plain_text = b"Hello, SM2!"
    req = EncryptRequest(plain_text=plain_text)
    result = crypto.encrypt(req)
    logger.info("加密成功, 密文HEX: %s", result.result.hex())

    decrypt_result = crypto.decrypt(result.result)
    logger.info("解密成功: %s", decrypt_result.result.decode("utf-8"))

    assert plain_text == decrypt_result.result
    print("SM2 test passed!")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    main()
