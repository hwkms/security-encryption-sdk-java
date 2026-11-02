from typing import Dict


class CommonUtils:

    @staticmethod
    def get_encrypt_map() -> Dict[str, str]:
        return {"key": "value", "context": "encrypt"}

    @staticmethod
    def get_encryption_context() -> Dict[str, str]:
        return {"encryption": "context", "simple": "test", "caching": "encrypt"}
