import os

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
        # 检查华为 OpenSSL 是否可用，不可用则降级到 cryptography
        try:
            from huaweicloud_encryptionsdk._openssl import is_available
            self._use_openssl = is_available()
        except Exception:
            self._use_openssl = False

    @staticmethod
    def _generate_iv(algorithm):
        return os.urandom(algorithm.iv_len)

    def get_iv(self):
        return self._iv

    def set_iv(self, iv):
        self._iv = iv

    def reset_iv(self):
        self._iv = self._generate_iv(self._algorithm)

    # ── cryptography 降级实现（仅 AES-GCM）──────────────

    def _crypto_aes_gcm_encrypt(self, data, aad):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(self._secret_key), modes.GCM(self._iv), backend=None)
        encryptor = cipher.encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        return ct + tag

    def _crypto_aes_gcm_decrypt(self, data, aad):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        tag_len = self._algorithm.tag_len
        tag = data[-tag_len:]
        ct = data[:-tag_len]
        cipher = Cipher(algorithms.AES(self._secret_key), modes.GCM(self._iv, tag), backend=None)
        decryptor = cipher.decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        return decryptor.update(ct) + decryptor.finalize()

    # ── _openssl 实现 ──────────────────────────────────

    def _do_sm4_cbc(self, data, mode_int):
        from huaweicloud_encryptionsdk._openssl import sm4_cbc_encrypt, sm4_cbc_decrypt
        if mode_int == ENCRYPT_MODE:
            return sm4_cbc_encrypt(self._secret_key, self._iv, data)
        else:
            return sm4_cbc_decrypt(self._secret_key, self._iv, data)

    def _do_sm4_gcm(self, data, aad, mode_int):
        from huaweicloud_encryptionsdk._openssl import sm4_gcm_encrypt, sm4_gcm_decrypt
        if mode_int == ENCRYPT_MODE:
            ct, tag = sm4_gcm_encrypt(self._secret_key, self._iv, data, aad)
            return ct + tag
        else:
            tag = data[-self._algorithm.tag_len:]
            ct = data[:-self._algorithm.tag_len:]
            return sm4_gcm_decrypt(self._secret_key, self._iv, ct, tag, aad)

    def _openssl_aes_gcm_encrypt(self, data, aad):
        from huaweicloud_encryptionsdk._openssl import aes_gcm_encrypt
        ct, tag = aes_gcm_encrypt(self._secret_key, self._iv, data, aad)
        return ct + tag

    def _openssl_aes_gcm_decrypt(self, data, aad):
        from huaweicloud_encryptionsdk._openssl import aes_gcm_decrypt
        tag = data[-self._algorithm.tag_len:]
        ct = data[:-self._algorithm.tag_len:]
        return aes_gcm_decrypt(self._secret_key, self._iv, ct, tag, aad)

    # ── AES-GCM 路由（按 backend 选择）─────────────────

    def _aes_gcm_encrypt(self, data, aad):
        if self._use_openssl:
            return self._openssl_aes_gcm_encrypt(data, aad)
        return self._crypto_aes_gcm_encrypt(data, aad)

    def _aes_gcm_decrypt(self, data, aad):
        if self._use_openssl:
            return self._openssl_aes_gcm_decrypt(data, aad)
        return self._crypto_aes_gcm_decrypt(data, aad)

    # ── 业务方法 ───────────────────────────────────────

    def cipher_data(self, plain_text, encryption_context, offset, length):
        try:
            aad = serialize_context(encryption_context)
            data = plain_text[offset: offset + length]

            if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
                if self._mode == ENCRYPT_MODE:
                    return self._do_sm4_cbc(data, ENCRYPT_MODE)
                else:
                    return self._do_sm4_cbc(data, DECRYPT_MODE)

            if self._algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
                return self._do_sm4_gcm(data, aad, self._mode)

            # AES-GCM
            if self._mode == ENCRYPT_MODE:
                return self._aes_gcm_encrypt(data, aad)
            else:
                return self._aes_gcm_decrypt(data, aad)
        except Exception as e:
            raise Exception("cipher exception: " + str(e))

    def cipher_header_data(self, content, encryption_context, offset, length):
        try:
            aad = encryption_context if isinstance(encryption_context, (bytes, bytearray)) else serialize_context(encryption_context)

            if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
                if self._mode == ENCRYPT_MODE:
                    if length == 0:
                        digest_data = b"\x00"
                        return self._do_sm4_cbc(digest_data, ENCRYPT_MODE)
                    return self._do_sm4_cbc(content[offset:offset + length], ENCRYPT_MODE)
                else:
                    return self._do_sm4_cbc(content[offset:offset + length], DECRYPT_MODE)

            if self._algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
                return self._do_sm4_gcm(
                    content[offset: offset + length] if length > 0 else b"",
                    aad,
                    self._mode,
                )

            # AES-GCM
            data = content[offset: offset + length]
            if self._mode == ENCRYPT_MODE:
                return self._aes_gcm_encrypt(data, aad)
            else:
                return self._aes_gcm_decrypt(data, aad)
        except Exception as e:
            raise Exception("cipher exception: " + str(e))

    def process_encrypt_byte(self, read_bytes, read_len, output_stream, aad):
        try:
            self._init_cipher()
            data = read_bytes[:read_len]

            if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
                encrypted = self._do_sm4_cbc(data, ENCRYPT_MODE)
            elif self._algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
                encrypted = self._do_sm4_gcm(data, aad, ENCRYPT_MODE)
            else:
                encrypted = self._aes_gcm_encrypt(data, aad)

            cipher_header = CipherHeader()
            cipher_header.iv = self._iv
            cipher_header.content_length = len(encrypted)
            header_byte = cipher_header.serialize_file_fields()
            output_stream.write(header_byte)
            output_stream.write(encrypted)
            return encrypted
        except Exception as e:
            raise Exception("process file error: " + str(e))

    def process_decrypt_byte(self, read_bytes, read_len, output_stream, aad):
        try:
            self._init_cipher()
            data = read_bytes[:read_len]

            if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
                decrypted = self._do_sm4_cbc(data, DECRYPT_MODE)
            elif self._algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
                decrypted = self._do_sm4_gcm(data, aad, DECRYPT_MODE)
            else:
                decrypted = self._aes_gcm_decrypt(data, aad)

            output_stream.write(decrypted)
            return decrypted
        except Exception as e:
            raise Exception("process file error: " + str(e))

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
