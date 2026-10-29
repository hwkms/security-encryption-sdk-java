from huaweicloud_encryptionsdk.handler.cipher_handler import CipherHandler
from huaweicloud_encryptionsdk.common.utils import serialize_context


class FileEncryptHandler:

    def __init__(self, algorithm, secret_key, mode):
        self._mode = mode
        self._algorithm = algorithm
        self._secret_key = secret_key

    def process_byte(self, input_stream, output_stream, encryption_context, block_size):
        read_bytes = bytearray(block_size)
        cipher_handler = CipherHandler(self._algorithm, self._secret_key, self._mode)
        aad = serialize_context(encryption_context)
        while True:
            read_len = input_stream.readinto(read_bytes) if hasattr(input_stream, 'readinto') else self._read_stream(input_stream, read_bytes)
            if read_len is None or read_len == -1 or read_len == 0:
                break
            cipher_handler.reset_iv()
            cipher_handler.process_encrypt_byte(read_bytes[:read_len], read_len, output_stream, aad)

    @staticmethod
    def _read_stream(input_stream, buf):
        data = input_stream.read(len(buf))
        if data is None or len(data) == 0:
            return -1
        n = len(data)
        buf[:n] = data
        return n
