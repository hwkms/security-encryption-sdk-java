import logging

from huaweicloud_encryptionsdk.common.utils import byte_to_secret_key
from huaweicloud_encryptionsdk.exception.errors import EncryptException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_keyring import RawKeyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials

logger = logging.getLogger(__name__)


def _extract_ec_point_from_der(der_bytes: bytes) -> tuple:
    idx = der_bytes.find(b'\x03')
    if idx < 0:
        raise ValueError("Invalid EC public key DER: BIT STRING not found")
    pos = idx + 1
    if der_bytes[pos] == 0x81:
        content_start = pos + 2
    elif der_bytes[pos] == 0x82:
        content_start = pos + 3
    else:
        content_start = pos + 1
    content_start += 1
    if der_bytes[content_start] != 0x04:
        raise ValueError("Invalid EC public key DER: uncompressed point not found")
    coord_len = (len(der_bytes) - content_start - 1) // 2
    x = int.from_bytes(der_bytes[content_start + 1:content_start + 1 + coord_len], 'big')
    y = int.from_bytes(der_bytes[content_start + 1 + coord_len:content_start + 1 + 2 * coord_len], 'big')
    return x, y


def _extract_ec_private_from_der(der_bytes: bytes) -> int:
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    pri_key = load_der_private_key(der_bytes, password=None)
    return pri_key.private_numbers().private_value


class RawSM2Keyring(RawKeyring):

    def real_encrypt(self, key_bytes: bytes, ciphertext_data_keys: list, data_key_materials: DataKeyMaterials):
        try:
            from gmssl import sm2
            try:
                x, y = _extract_ec_point_from_der(key_bytes)
                public_key_hex = "04" + format(x, '064x') + format(y, '064x')
            except Exception:
                public_key_hex = key_bytes.hex()
            sm2_crypt = sm2.CryptSM2(public_key=public_key_hex, private_key="")
            encrypted = sm2_crypt.encrypt(data_key_materials.plaintext_data_key)
            ciphertext_data_keys.append(CiphertextDataKey(data_key=encrypted))
        except Exception as e:
            raise EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.message, e)

    def real_decrypt(self, key_bytes: bytes, ciphertext_data_key: CiphertextDataKey, data_key_materials: DataKeyMaterials) -> bool:
        try:
            from gmssl import sm2
            try:
                d = _extract_ec_private_from_der(key_bytes)
                private_key_hex = format(d, '064x')
            except Exception:
                private_key_hex = key_bytes.hex()
            sm2_crypt = sm2.CryptSM2(public_key="", private_key=private_key_hex)
            decrypted = sm2_crypt.decrypt(ciphertext_data_key.data_key)
            algo_name = data_key_materials.crypto_algorithm.get_algorithm_name() if data_key_materials.crypto_algorithm else "SM4"
            data_key_materials.plaintext_data_key = byte_to_secret_key(decrypted, algo_name)
            return True
        except Exception:
            logger.warning("one master key may be not match when decrypt data key in RawSM2Keyring")
        return False

    def get_encrypt_secret_key(self) -> list[bytes]:
        return self.public_key

    def get_decrypt_secret_key(self) -> list[bytes]:
        return self.private_key
