from abc import ABC, abstractmethod

from huaweicloud_encryptionsdk.keyrings.keyring import Keyring


class KeyringFactory(ABC):

    @abstractmethod
    def get_keyring(self, type: str) -> Keyring:
        pass
