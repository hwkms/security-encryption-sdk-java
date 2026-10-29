import base64
import logging
import sys

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.keyrings.raw_keyring_factory import RawKeyringFactory
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest

logger = logging.getLogger(__name__)

RSA_PUB = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgxDL8ovgpDITH2v5QlRAsTJ9/toepH9dwyh+Nw+6LMS6Xlyp2QLrSLzPLpW0XsNFPYb6l910e7SpDOSuaualCNb3UqlIphiZmZ3DTzIqsSqY+rTY6S65oFM/wMstZjgy5DYwuNNMrB1JOuLb5JwX9inotcHel4UFH0OnjRzPj+PTfFqv+/PIA2yFBdKVMLqn0fjKRnTxKEhM1hRz/YRTVFwUqvSRbU/bqBmd/2chtRKi5gVpyx37/HYHdZywYSIf8ckM9hGsdxigAThmrLUKud7jOFSAHAtUSIlXTOhQRNWDSiPY9FDE4tCujoUOOGJ0WVaNHGQop8NjCPIlZUmj0QIDAQAB"
RSA_PRI = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCDEMvyi+CkMhMfa/lCVECxMn3+2h6kf13DKH43D7osxLpeXKnZAutIvM8ulbRew0U9hvqX3XR7tKkM5K5q5qUI1vdSqUimGJmZncNPMiqxKpj6tNjpLrmgUz/Ayy1mODLkNjC400ysHUk64tvknBf2Kei1wd6XhQUfQ6eNHM+P49N8Wq/788gDbIUF0pUwuqfR+MpGdPEoSEzWFHP9hFNUXBSq9JFtT9uoGZ3/ZyG1EqLmBWnLHfv8dgd1nLBhIh/xyQz2Eax3GKABOGastQq53uM4VIAcC1RIiVdM6FBE1YNKI9j0UMTi0K6OhQ44YnRZVo0cZCinw2MI8iVlSaPRAgMBAAECggEAXg5Uvdehu1NwI7GBrBb4YfFhN93h9Zytddr+UJdJvMzlDcij3udYX9eXOtAWI5cwfkn6VbeH2yq30lfdzzt7nc9ep4RybTfkKrhrq87NklyGcgwMSbLNZX+4lat5Bg04gEtfRZPlRvKxVb/tm65lB7Plm2HoUoYUOe58NClDzvbeDHN/czJbk8EpJBi0re2czQ7NK0icS9zorhclhazssYKxBCS37cQDIgwr5+5HFIGpkZLirnB+yR+iGUelSsYLt+X+wQy+wp6ymhm0+poNOm3NbJbzmnY5b8OZJHai2k9OXVLvgA7F3IiTmZ20vG8wYkCWxX6B48jr40j/xfpMfQKBgQDam3UECjPdO4Z6asELsz93EeAVjxKUh48FQjJMOU0EYSyIGdcWDnVaiCiXq/26t0zBb7lYwNDVziD6c006UHxF7R26BGJm4pypQjTU9P4OrDd82sOn8UMi/QH/OAQNAF8KKah/o9la/EdLKS1SFtZppI1AN9/CMfm2pXXqLJ6tlwKBgQCZe/+p30P7URXggw3JtK9LXTNqIKFLDJGxjTuVhkURHNRnrHJvD46azjiG7qPzEt3pgB0+G7rGOuHLfrNBCPA8aQAMsZPAfciU1aq8Rsdab6XjL+7pvbNqlcCRsp75bM6bJ4pA3Qk86SF1zcTpvS91iEsqHvQ9bXMmV8F5ZNg21wKBgQCIIj8goOnjX2pDWa+WBa4EDFGrm0lKzZA3Ch4gcZ6Ql6MPrmfPCHn0Qs5khWqgl/1oiJa3untSaecHkD4LjouVUDAu4wQUZhKBJQWZiGed44k6a1FkiE3yv/Q6Zzu+jPiib4bK1dJJYslS+PWMJUSozRxZXXIukMidATUI+3hlSQKBgCUDt3ODKYTpWCpN0LxtO70kG+sjNWLBBD3afp0fxXZMCpl6CBrqmIyS4SUBVj6ftS7Du8mnrFJ0DtIhmx87BZy8AcwN40EP1Ji4MrW3KAqSVGJGxApQun0g4lEAz7/9UpIuZfQgmkK7QluDpVJtUo24sc/VqTdLNvLvRPR+snn/AoGAfrHketzlE6W9btyKcw7G6mf2utTdAkKaD/TFmVFCNtLc+Aw5cMlmWWhiMGP3ec0oFw9qHg1xUTdz38ThhRvThNlB/tbJbqscIfqC9+rY722GThZIl1jGCW8jR4O24lWS3jfF+B0iOdxFdTEn6bhTGtY5i4eZrqq7d44n70f3jRg="


def main():
    rsa_pub = base64.b64decode(RSA_PUB)
    rsa_pri = base64.b64decode(RSA_PRI)

    config = HuaweiConfig(crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING)
    keyring = RawKeyringFactory().get_keyring(KeyringTypeEnum.RAW_RSA.type)
    keyring.set_public_key([rsa_pub])
    keyring.set_private_key([rsa_pri])

    crypto = HuaweiCrypto(config).with_keyring(keyring)

    plain_text = b"Hello, RSA!"
    req = EncryptRequest(plain_text=plain_text)
    result = crypto.encrypt(req)
    logger.info("加密成功, 密文HEX: %s", result.result.hex())

    decrypt_result = crypto.decrypt(result.result)
    logger.info("解密成功: %s", decrypt_result.result.decode("utf-8"))

    assert plain_text == decrypt_result.result
    print("RSA test passed!")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    main()
