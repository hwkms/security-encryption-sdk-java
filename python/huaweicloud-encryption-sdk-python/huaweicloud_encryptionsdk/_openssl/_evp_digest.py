"""
EVP 摘要算法: SM3, SHA256
接口匹配 hashlib (update/digest/hexdigest)
"""
import ctypes

from huaweicloud_encryptionsdk._openssl._library import get_libcrypto, EVP_SUCCESS, OpenSSLError


class Digest:
    """EVP 摘要, 接口兼容 hashlib"""

    def __init__(self, algorithm: str):
        """
        :param algorithm: "SM3", "SHA256", "SHA384", "SHA512" 等
        """
        self._lc = get_libcrypto()
        lib = self._lc.lib

        if lib is None:
            raise OpenSSLError("华为 OpenSSL 不可用，无法执行 %s 摘要计算" % algorithm)

        self._md = self._lc.fetch_digest(algorithm.encode())
        if not self._md:
            raise OpenSSLError("fetch_digest(%s) 失败" % algorithm)

        self._md_size = self._lc.digest_size(self._md)
        if self._md_size <= 0:
            self._lc.free_digest(self._md)
            raise OpenSSLError("digest_size(%s) 返回 %d" % (algorithm, self._md_size))

        self._ctx = lib.EVP_MD_CTX_new()
        if not self._ctx:
            self._lc.free_digest(self._md)
            raise OpenSSLError("EVP_MD_CTX_new 失败")

        if lib.EVP_DigestInit_ex(self._ctx, self._md, None) != EVP_SUCCESS:
            lib.EVP_MD_CTX_free(self._ctx)
            self._lc.free_digest(self._md)
            raise OpenSSLError("EVP_DigestInit_ex(%s) 失败" % algorithm)

        self._finalized = False

    def update(self, data: bytes):
        if self._finalized:
            raise OpenSSLError("digest 已 finalize, 不能再 update")
        if not data:
            return
        if self._lc.lib.EVP_DigestUpdate(self._ctx, data, len(data)) != EVP_SUCCESS:
            raise OpenSSLError("EVP_DigestUpdate 失败")

    def digest(self) -> bytes:
        if self._finalized:
            raise OpenSSLError("digest 已 finalize")
        self._finalized = True

        out = ctypes.create_string_buffer(self._md_size)
        out_len = ctypes.c_uint(0)
        if self._lc.lib.EVP_DigestFinal_ex(self._ctx, out, ctypes.byref(out_len)) != EVP_SUCCESS:
            raise OpenSSLError("EVP_DigestFinal_ex 失败")
        return out.raw[:out_len.value]

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "Digest":
        """复制当前状态 (用于多次 finalize 场景)"""
        # 重新创建, 因为 OpenSSL 3.x 的 EVP_MD_CTX_copy_ex 需要额外签名
        new = Digest.__new__(Digest)
        new._lc = self._lc
        new._md_size = self._md_size
        # 重新 fetch md
        lib = self._lc.lib
        # 无法直接 copy ctx, 这里用重新 init + 重新 update 的方式
        # 注意: 调用者应在 finalize 前 copy
        raise NotImplementedError("Digest.copy 暂未实现, 请在 finalize 前手动缓存数据")

    def __del__(self):
        try:
            if hasattr(self, "_ctx") and self._ctx:
                self._lc.lib.EVP_MD_CTX_free(self._ctx)
            if hasattr(self, "_md") and self._md:
                self._lc.free_digest(self._md)
        except Exception:
            pass


# ── 便捷函数 ───────────────────────────────────────────

def sm3(data: bytes) -> bytes:
    """计算 SM3 摘要"""
    d = Digest("SM3")
    d.update(data)
    return d.digest()


def sha256(data: bytes) -> bytes:
    """计算 SHA256 摘要"""
    d = Digest("SHA256")
    d.update(data)
    return d.digest()


def new(algorithm: str) -> Digest:
    """
    创建摘要对象, 类似 hashlib.new(algorithm)
    :param algorithm: "SM3", "SHA256", "SHA384", "SHA512"
    """
    return Digest(algorithm)
