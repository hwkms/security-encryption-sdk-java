from enum import Enum


class CryptoAlgorithm(Enum):

    AES_128_GCM_NOPADDING = ("AES_128", "AES/GCM/NoPadding", 16, 12, 16, 16, 1, 1, "AES", 128)
    AES_256_GCM_NOPADDING = ("AES_256", "AES/GCM/NoPadding", 32, 12, 16, 16, 2, 1, "AES", 256)
    SM4_128_GCM_NOPADDING = ("SM4_128", "SM4/GCM/NoPadding", 16, 12, 16, 16, 3, 1, "SM4", 128)
    SM4_128_CBC_PADDING = ("SM4_128", "SM4/CBC/PKCS5Padding", 16, 16, 16, 16, 4, 1, "SM4", 128)

    def __init__(self, key_spec, crypto_alg, key_len, iv_len, tag_len, block_size, value, version, sec_key_algorithm, datakey_length):
        self._key_spec = key_spec
        self._crypto_alg = crypto_alg
        self._key_len = key_len
        self._iv_len = iv_len
        self._tag_len = tag_len
        self._block_size = block_size
        self._value = value
        self._version = version
        self._sec_key_algorithm = sec_key_algorithm
        self._datakey_length = datakey_length

    @property
    def key_spec(self):
        return self._key_spec

    @property
    def crypto_alg(self):
        return self._crypto_alg

    @property
    def key_len(self):
        return self._key_len

    @property
    def iv_len(self):
        return self._iv_len

    @property
    def tag_len(self):
        return self._tag_len

    @property
    def block_size(self):
        return self._block_size

    @property
    def value(self):
        return self._value

    @property
    def version(self):
        return self._version

    @property
    def sec_key_algorithm(self):
        return self._sec_key_algorithm

    @property
    def datakey_length(self):
        return self._datakey_length

    @classmethod
    def get_algorithm(cls, algorithm_value):
        for algorithm in cls:
            if algorithm.value == algorithm_value:
                return algorithm
        return None

    def get_algorithm_name(self):
        return self._key_spec.split("_")[0]

    def get_crypto_mode(self):
        parts = self._crypto_alg.split("/")
        return parts[1]
