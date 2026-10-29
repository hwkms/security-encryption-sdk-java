from enum import Enum


class DataKeyGenerateType(Enum):

    LOCAL_GENERATE = ("create data key from local", 1)
    KMS_GENERATE = ("create data key from KMS", 2)
    KEY_CAPSULE_GENERATE = ("create data key from key capsule", 3)

    def __init__(self, desc, code):
        self._desc = desc
        self._code = code

    @property
    def desc(self):
        return self._desc

    @property
    def code(self):
        return self._code
