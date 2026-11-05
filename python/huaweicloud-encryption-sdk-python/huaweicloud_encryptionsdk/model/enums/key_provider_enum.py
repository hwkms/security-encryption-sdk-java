from enum import Enum


class KeyProviderEnum(Enum):

    LOCAL_PROVIDER = (1, "huawei-local")
    KMS_PROVIDER = (2, "huawei-kms")

    def __init__(self, code, name):
        self._code = code
        self._name = name

    @property
    def code(self):
        return self._code

    @property
    def name(self):
        return self._name
