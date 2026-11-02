import os
import struct
from io import BytesIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from huaweicloud_encryptionsdk.common.utils import serialize_context
from huaweicloud_encryptionsdk.model.cipher_header import CipherHeader
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm


ENCRYPT_MODE = 1
DECRYPT_MODE = 2


class CipherHandler:

    def __init__(self, algorithm, secret_key, mode):
        self._mode = mode
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._iv = self._generate_iv(algorithm)

    @staticmethod
    def _generate_iv(algorithm):
        return os.urandom(algorithm.iv_len)

    def get_iv(self):
        return self._iv

    def set_iv(self, iv):
        self._iv = iv

    def reset_iv(self):
        self._iv = self._generate_iv(self._algorithm)

    def _get_parameter_spec(self, plain_text=None):
        crypto_mode = self._algorithm.get_crypto_mode()
        if crypto_mode.upper() == "CBC":
            return modes.CBC(self._iv)
        if self._mode == DECRYPT_MODE and crypto_mode.upper() == "GCM":
            tag = plain_text[-self._algorithm.tag_len:]
            return modes.GCM(self._iv, tag, min_tag_length=self._algorithm.tag_len)
        return modes.GCM(self._iv)

    def _create_cipher(self, mode_spec):
        alg_name = self._algorithm.crypto_alg.split("/")[0]
        if alg_name.upper() == "SM4":
            from cryptography.hazmat.primitives.ciphers import algorithms as _algs
            return Cipher(_algs.SM4(self._secret_key), mode_spec, backend=default_backend())
        if alg_name.upper() == "AES":
            return Cipher(
                algorithms.AES(self._secret_key), mode_spec, backend=default_backend()
            )
        raise Exception("unsupported algorithm: " + alg_name)

    def _do_sm4_cbc(self, data, mode_int):
        from gmssl.sm4 import CryptSM4, SM4_DECRYPT, SM4_ENCRYPT
        crypt_sm4 = CryptSM4()
        if mode_int == ENCRYPT_MODE:
            crypt_sm4.set_key(self._secret_key, SM4_ENCRYPT)
        else:
            crypt_sm4.set_key(self._secret_key, SM4_DECRYPT)
        return crypt_sm4.crypt_cbc(self._iv, data)

    def _do_sm4_gcm(self, data, aad, mode_int):
        from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
        from cryptography.hazmat.primitives.ciphers import algorithms as _algs, modes as _modes

        sm4_alg = _algs.SM4(self._secret_key)

        if mode_int == ENCRYPT_MODE:
            gcm = _modes.GCM(self._iv)
            cipher = _Cipher(sm4_alg, gcm, backend=default_backend())
            encryptor = cipher.encryptor()
            if aad:
                encryptor.authenticate_additional_data(aad)
            ct = encryptor.update(data) + encryptor.finalize()
            return ct + encryptor.tag
        else:
            if len(data) < self._algorithm.tag_len:
                raise ValueError("data too short for GCM tag")
            tag = data[-self._algorithm.tag_len:]
            ct = data[:-self._algorithm.tag_len]
            gcm = _modes.GCM(self._iv, tag, min_tag_length=self._algorithm.tag_len)
            cipher = _Cipher(sm4_alg, gcm, backend=default_backend())
            decryptor = cipher.decryptor()
            if aad:
                decryptor.authenticate_additional_data(aad)
            return decryptor.update(ct) + decryptor.finalize()

    def cipher_data(self, plain_text, encryption_context, offset, length):
        try:
            aad = serialize_context(encryption_context)
            crypto_mode = self._algorithm.get_crypto_mode()
            alg_name = self._algorithm.crypto_alg.split("/")[0]
            data = plain_text[offset: offset + length]

            if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
                from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
                padded = self._pkcs7_pad(data, 16)
                crypt_sm4 = CryptSM4()
                if self._mode == ENCRYPT_MODE:
                    crypt_sm4.set_key(self._secret_key, SM4_ENCRYPT)
                    return crypt_sm4.crypt_cbc(self._iv, padded)
                else:
                    crypt_sm4.set_key(self._secret_key, SM4_DECRYPT)
                    decrypted = crypt_sm4.crypt_cbc(self._iv, data)
                    return self._pkcs7_unpad(decrypted)

            if self._algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
                return self._do_sm4_gcm(data, aad, self._mode)

            mode_spec = self._get_parameter_spec(plain_text if self._mode == DECRYPT_MODE else None)
            cipher_obj = self._create_cipher(mode_spec)

            if self._mode == ENCRYPT_MODE:
                encryptor = cipher_obj.encryptor()
                if crypto_mode.upper() == "GCM":
                    if aad:
                        encryptor.authenticate_additional_data(aad)
                ct = encryptor.update(data) + encryptor.finalize()
                if crypto_mode.upper() == "GCM":
                    ct = ct + encryptor.tag
                return ct
            else:
                if crypto_mode.upper() == "GCM":
                    gcm_data = data[:-self._algorithm.tag_len]
                else:
                    gcm_data = data
                decryptor = cipher_obj.decryptor()
                if crypto_mode.upper() == "GCM":
                    if aad:
                        decryptor.authenticate_additional_data(aad)
                return decryptor.update(gcm_data) + decryptor.finalize()
        except Exception as e:
            raise Exception("cipher exception: " + str(e)) from e

    def cipher_header_data(self, content, encryption_context, offset, length):
        try:
            crypto_mode = self._algorithm.get_crypto_mode()
            alg_name = self._algorithm.crypto_alg.split("/")[0]

            if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
                from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
                crypt_sm4 = CryptSM4()
                if self._mode == ENCRYPT_MODE:
                    crypt_sm4.set_key(self._secret_key, SM4_ENCRYPT)
                    if length == 0:
                        digest_data = b"\x00"
                        padded = self._pkcs7_pad(digest_data, 16)
                        return crypt_sm4.crypt_cbc(self._iv, padded)
                    padded = self._pkcs7_pad(content[offset:offset + length], 16)
                    return crypt_sm4.crypt_cbc(self._iv, padded)
                else:
                    crypt_sm4.set_key(self._secret_key, SM4_DECRYPT)
                    decrypted = crypt_sm4.crypt_cbc(self._iv, content[offset:offset + length])
                    return self._pkcs7_unpad(decrypted)

            if self._algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
                return self._do_sm4_gcm(
                    content[offset: offset + length] if length > 0 else b"",
                    encryption_context,
                    self._mode,
                )

            if crypto_mode.upper() == "CBC":
                mode_spec = modes.CBC(self._iv)
            elif crypto_mode.upper() == "GCM":
                if self._mode == DECRYPT_MODE:
                    data = content[offset: offset + length]
                    tag = data[-self._algorithm.tag_len:]
                    ct = data[:-self._algorithm.tag_len]
                    mode_spec = modes.GCM(self._iv, tag, min_tag_length=self._algorithm.tag_len)
                else:
                    mode_spec = modes.GCM(self._iv)
                    ct = None
            else:
                raise Exception("unsupported mode: " + crypto_mode)

            cipher_obj = self._create_cipher(mode_spec)

            if self._mode == ENCRYPT_MODE:
                encryptor = cipher_obj.encryptor()
                if crypto_mode.upper() == "GCM":
                    if encryption_context:
                        encryptor.authenticate_additional_data(encryption_context)
                ct = encryptor.update(content[offset: offset + length]) + encryptor.finalize()
                if crypto_mode.upper() == "GCM":
                    ct = ct + encryptor.tag
                return ct
            else:
                decryptor = cipher_obj.decryptor()
                if crypto_mode.upper() == "GCM":
                    if encryption_context:
                        decryptor.authenticate_additional_data(encryption_context)
                    return decryptor.update(ct) + decryptor.finalize()
                return decryptor.update(content[offset: offset + length]) + decryptor.finalize()
        except Exception as e:
            raise Exception("cipher exception: " + str(e)) from e

    def process_encrypt_byte(self, read_bytes, read_len, output_stream, aad):
        try:
            self._init_cipher()
            crypto_mode = self._algorithm.get_crypto_mode()
            data = read_bytes[:read_len]

            if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
                from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
                padded = self._pkcs7_pad(data, 16)
                crypt_sm4 = CryptSM4()
                crypt_sm4.set_key(self._secret_key, SM4_ENCRYPT)
                encrypted = crypt_sm4.crypt_cbc(self._iv, padded)
            elif self._algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
                encrypted = self._do_sm4_gcm(data, aad, ENCRYPT_MODE)
            else:
                if crypto_mode.upper() == "GCM":
                    mode_spec = modes.GCM(self._iv)
                else:
                    mode_spec = modes.CBC(self._iv)
                cipher_obj = self._create_cipher(mode_spec)
                encryptor = cipher_obj.encryptor()
                if crypto_mode.upper() == "GCM" and aad:
                    encryptor.authenticate_additional_data(aad)
                ct = encryptor.update(data) + encryptor.finalize()
                if crypto_mode.upper() == "GCM":
                    encrypted = ct + encryptor.tag
                else:
                    encrypted = ct

            cipher_header = CipherHeader()
            cipher_header.iv = self._iv
            cipher_header.content_length = len(encrypted)
            header_byte = cipher_header.serialize_file_fields()
            output_stream.write(header_byte)
            output_stream.write(encrypted)
            return encrypted
        except Exception as e:
            raise Exception("process file error: " + str(e)) from e

    def process_decrypt_byte(self, read_bytes, read_len, output_stream, aad):
        try:
            self._init_cipher()
            crypto_mode = self._algorithm.get_crypto_mode()
            data = read_bytes[:read_len]

            if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
                from gmssl.sm4 import CryptSM4, SM4_DECRYPT
                crypt_sm4 = CryptSM4()
                crypt_sm4.set_key(self._secret_key, SM4_DECRYPT)
                result = crypt_sm4.crypt_cbc(self._iv, data)
                decrypted = self._pkcs7_unpad(result)
            elif self._algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
                decrypted = self._do_sm4_gcm(data, aad, DECRYPT_MODE)
            else:
                if crypto_mode.upper() == "GCM":
                    tag = data[-self._algorithm.tag_len:]
                    gcm_data = data[:-self._algorithm.tag_len]
                    mode_spec = modes.GCM(self._iv, tag, min_tag_length=self._algorithm.tag_len)
                else:
                    mode_spec = modes.CBC(self._iv)
                    gcm_data = data
                cipher_obj = self._create_cipher(mode_spec)
                decryptor = cipher_obj.decryptor()
                if crypto_mode.upper() == "GCM" and aad:
                    decryptor.authenticate_additional_data(aad)
                decrypted = decryptor.update(gcm_data) + decryptor.finalize()
                if crypto_mode.upper() != "GCM":
                    decrypted = self._pkcs7_unpad(decrypted)

            output_stream.write(decrypted)
            return decrypted
        except Exception as e:
            raise Exception("process file error: " + str(e)) from e

    def _init_cipher(self):
        pass

    @staticmethod
    def _pkcs7_pad(data, block_size):
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data, block_size=16):
        if not data or len(data) % block_size != 0:
            raise ValueError("invalid data length")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("invalid padding length")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("invalid padding bytes")
        return data[:-pad_len]
