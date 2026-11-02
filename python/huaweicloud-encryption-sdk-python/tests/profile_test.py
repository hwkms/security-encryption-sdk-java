import time
import os
import struct
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

TEST_DIR = "/home/py"
FILE_2GB = os.path.join(TEST_DIR, "profile_2gb.bin")
BLOCK_SIZE = 1024 * 256
NUM_BLOCKS = 8192

key = os.urandom(16)
data = os.urandom(BLOCK_SIZE)

# 准备2GB测试文件
print("准备2GB测试文件...")
with open(FILE_2GB, "wb") as f:
    for i in range(NUM_BLOCKS):
        f.write(data)
print("文件准备完成\n")

# 测试1: 纯文件读
start = time.perf_counter()
with open(FILE_2GB, "rb") as f:
    for i in range(NUM_BLOCKS):
        f.read(BLOCK_SIZE)
print("纯文件读耗时: %.2fs" % (time.perf_counter() - start))

# 测试2: 纯文件写
out_file = os.path.join(TEST_DIR, "profile_2gb_out.bin")
start = time.perf_counter()
with open(out_file, "wb") as f:
    for i in range(NUM_BLOCKS):
        f.write(data)
print("纯文件写耗时: %.2fs" % (time.perf_counter() - start))
os.remove(out_file)

# 测试3: 文件读 + 加密 + 文件写（模拟完整流程）
class CountingOutputStream:
    def __init__(self, output_stream):
        self._output_stream = output_stream
        self._bytes_written = 0

    def write(self, data):
        if isinstance(data, (bytes, bytearray)):
            self._output_stream.write(data)
            self._bytes_written += len(data)
        else:
            self._output_stream.write(data)
            self._bytes_written += 1

    def get_bytes_written(self):
        return self._bytes_written

start = time.perf_counter()
with open(FILE_2GB, "rb") as fin, open(out_file, "wb") as fout:
    counting_stream = CountingOutputStream(fout)
    read_bytes = bytearray(BLOCK_SIZE)
    aad = b""
    for i in range(NUM_BLOCKS):
        read_len = fin.readinto(read_bytes)
        if read_len == 0:
            break
        iv = os.urandom(12)
        mode_spec = modes.GCM(iv)
        cipher_obj = Cipher(algorithms.AES(key), mode_spec, backend=default_backend())
        encryptor = cipher_obj.encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(bytes(read_bytes[:read_len])) + encryptor.finalize()
        encrypted = ct + encryptor.tag
        header_byte = iv + struct.pack(">q", len(encrypted))
        counting_stream.write(header_byte)
        counting_stream.write(encrypted)
full_time = time.perf_counter() - start
print("完整流程（读+加密+写）耗时: %.2fs" % full_time)
os.remove(out_file)

# 测试4: 完整流程但用/dev/null输出（排除写I/O）
start = time.perf_counter()
with open(FILE_2GB, "rb") as fin:
    devnull = open(os.devnull, "wb")
    counting_stream = CountingOutputStream(devnull)
    read_bytes = bytearray(BLOCK_SIZE)
    aad = b""
    for i in range(NUM_BLOCKS):
        read_len = fin.readinto(read_bytes)
        if read_len == 0:
            break
        iv = os.urandom(12)
        mode_spec = modes.GCM(iv)
        cipher_obj = Cipher(algorithms.AES(key), mode_spec, backend=default_backend())
        encryptor = cipher_obj.encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(bytes(read_bytes[:read_len])) + encryptor.finalize()
        encrypted = ct + encryptor.tag
        header_byte = iv + struct.pack(">q", len(encrypted))
        counting_stream.write(header_byte)
        counting_stream.write(encrypted)
    devnull.close()
read_crypto_time = time.perf_counter() - start
print("读+加密+写/dev/null耗时: %.2fs" % read_crypto_time)

# 测试5: 纯加密（无I/O，无文件操作）
start = time.perf_counter()
read_bytes = bytearray(BLOCK_SIZE)
aad = b""
for i in range(NUM_BLOCKS):
    iv = os.urandom(12)
    mode_spec = modes.GCM(iv)
    cipher_obj = Cipher(algorithms.AES(key), mode_spec, backend=default_backend())
    encryptor = cipher_obj.encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)
    ct = encryptor.update(data) + encryptor.finalize()
    encrypted = ct + encryptor.tag
    header_byte = iv + struct.pack(">q", len(encrypted))
pure_crypto_time = time.perf_counter() - start
print("纯加密（无I/O）耗时: %.2fs" % pure_crypto_time)

# 分析
print("\n=== 开销分析 ===")
print("完整流程: %.2fs" % full_time)
print("  - 纯加密: %.2fs" % pure_crypto_time)
print("  - 读I/O: %.2fs" % (read_crypto_time - pure_crypto_time))
print("  - 写I/O: %.2fs" % (full_time - read_crypto_time))

os.remove(FILE_2GB)
