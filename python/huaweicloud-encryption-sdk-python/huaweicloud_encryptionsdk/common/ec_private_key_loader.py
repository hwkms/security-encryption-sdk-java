import base64

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
)
from cryptography.hazmat.backends import default_backend


class ECPrivateKeyLoader:

    @staticmethod
    def load(key_content):
        if key_content.strip().startswith('-----BEGIN'):
            try:
                return ECPrivateKeyLoader.load_pem(key_content)
            except Exception as e:
                raise Exception("access point key exception") from e
        try:
            der = base64.b64decode(key_content)
            return ECPrivateKeyLoader.load_der(der)
        except Exception as e:
            raise Exception("access point key exception") from e

    @staticmethod
    def load_pem(pem):
        try:
            private_key = load_pem_private_key(
                pem.encode("utf-8"), password=None, backend=default_backend()
            )
            return private_key
        except Exception as e:
            raise Exception("access point key exception") from e

    @staticmethod
    def load_der(der):
        try:
            private_key = load_der_private_key(
                der, password=None, backend=default_backend()
            )
            return private_key
        except Exception as e:
            raise Exception("access point key exception") from e
