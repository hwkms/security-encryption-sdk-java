from typing import Protocol


class PrivateKeyDecryptCallback(Protocol):

    def decrypt(self, encrypted_private_key: str) -> str:
        ...
