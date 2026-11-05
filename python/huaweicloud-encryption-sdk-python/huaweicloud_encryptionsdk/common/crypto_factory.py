import hashlib


class CryptoFactory:

    @staticmethod
    def get_cipher(algorithm):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        parts = algorithm.split("/")
        alg_name = parts[0]
        mode_name = parts[1] if len(parts) > 1 else ""
        return alg_name, mode_name

    @staticmethod
    def get_message_digest(algorithm):
        if algorithm is None:
            raise ValueError('algorithm must not be None')
        if CryptoFactory.is_sm_algorithm(algorithm):
            try:
                from gmssl import sm3
                return SM3Digest()
            except ImportError:
                raise ValueError('SM3 algorithm requires gmssl library. Install with: pip install gmssl')
        return hashlib.new(algorithm)

    @staticmethod
    def is_sm_algorithm(algorithm):
        return algorithm is not None and "SM" in algorithm.upper()


class SM3Digest:

    def __init__(self):
        from gmssl import sm3 as _sm3
        self._sm3 = _sm3
        self._data = bytearray()

    def update(self, data):
        self._data.extend(data)

    def digest(self):
        from gmssl import sm3 as _sm3, func
        result = _sm3.sm3_hash(list(self._data))
        return bytes.fromhex(result)

    def hexdigest(self):
        from gmssl import sm3 as _sm3
        return _sm3.sm3_hash(list(self._data))
