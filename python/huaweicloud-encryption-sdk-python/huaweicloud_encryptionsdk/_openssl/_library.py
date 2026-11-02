"""
加载华为 OpenSSL libcrypto.so，设置 ctypes 函数签名。

加载策略:
  1. 包内 libcrypto（按平台选择: x86_64 / aarch64）
  2. 加载失败（兼容性问题等）直接降级到 cryptography

不读取环境变量，不依赖系统安装路径，客户无需任何配置。
"""
import ctypes
import os
import platform
import logging

_logger = logging.getLogger(__name__)

# ── EVP ctrl 常量 ──────────────────────────────────────
EVP_CTRL_GCM_SET_IVLEN = 0x09
EVP_CTRL_GCM_GET_TAG   = 0x10
EVP_CTRL_GCM_SET_TAG   = 0x11

# ── 通用常量 ───────────────────────────────────────────
EVP_SUCCESS = 1

# ── RSA padding 常量 ───────────────────────────────────
RSA_PKCS1_OAEP_PADDING = 4
EVP_PKEY_CTRL_RSA_PADDING = 0x1001
EVP_PKEY_CTRL_RSA_OAEP_MD = 0x1002
EVP_PKEY_CTRL_RSA_MGF1_MD = 0x1003

# ── NID (密钥类型) ────────────────────────────────────
EVP_PKEY_RSA = 6
EVP_PKEY_EC = 408


class OpenSSLError(Exception):
    """libcrypto 调用异常"""
    pass


def _find_library():
    """加载包内自带的 libcrypto.so（按平台选择）。

    Returns:
        (ctypes.CDLL 或 None, source 或 None, path 或 None)
        加载失败（兼容性问题等）返回 (None, None, None)，上层降级到 cryptography。
    """
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    machine = platform.machine().lower()
    arch_map = {
        "x86_64": "libcrypto_x86_64.so",
        "amd64": "libcrypto_x86_64.so",
        "aarch64": "libcrypto_aarch64.so",
        "arm64": "libcrypto_aarch64.so",
    }
    bundled_name = arch_map.get(machine)
    if not bundled_name:
        _logger.warning("不支持的平台 %s，降级到 cryptography", machine)
        return None, None, None

    path = os.path.join(pkg_dir, bundled_name)
    if not os.path.exists(path):
        _logger.warning("包内未找到 %s，降级到 cryptography", bundled_name)
        return None, None, None

    try:
        lib = ctypes.CDLL(path)
        _logger.info("加载 libcrypto [%s]: %s", "package-" + machine, path)
        return lib, "package-" + machine, path
    except OSError as e:
        _logger.warning("加载 %s 失败（兼容性问题），降级到 cryptography: %s", path, e)
        return None, None, None


def _setup_common_signatures(lib):
    """设置 1.1.x/3.x 通用的 ctypes 签名"""

    # ── 版本 ──
    lib.OpenSSL_version.restype = ctypes.c_char_p
    lib.OpenSSL_version.argtypes = [ctypes.c_int]

    # ── 错误 ──
    lib.ERR_get_error.restype = ctypes.c_ulong
    lib.ERR_get_error.argtypes = []
    lib.ERR_clear_error.restype = None
    lib.ERR_clear_error.argtypes = []

    # ── EVP_MD_CTX (摘要上下文) ──
    lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
    lib.EVP_MD_CTX_new.argtypes = []

    lib.EVP_MD_CTX_free.restype = None
    lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]

    lib.EVP_DigestInit_ex.restype = ctypes.c_int
    lib.EVP_DigestInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

    lib.EVP_DigestUpdate.restype = ctypes.c_int
    lib.EVP_DigestUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    lib.EVP_DigestFinal_ex.restype = ctypes.c_int
    lib.EVP_DigestFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]

    # ── EVP_CIPHER_CTX (对称加密上下文) ──
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_new.argtypes = []

    lib.EVP_CIPHER_CTX_free.restype = None
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

    lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]

    lib.EVP_EncryptInit_ex.restype = ctypes.c_int
    lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_EncryptUpdate.restype = ctypes.c_int
    lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]

    lib.EVP_EncryptFinal_ex.restype = ctypes.c_int
    lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]

    lib.EVP_DecryptInit_ex.restype = ctypes.c_int
    lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_DecryptUpdate.restype = ctypes.c_int
    lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]

    lib.EVP_DecryptFinal_ex.restype = ctypes.c_int
    lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]

    # ── EVP_PKEY (非对称密钥) ──
    lib.EVP_PKEY_new.restype = ctypes.c_void_p
    lib.EVP_PKEY_new.argtypes = []

    lib.EVP_PKEY_free.restype = None
    lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]

    lib.EVP_PKEY_CTX_new.restype = ctypes.c_void_p
    lib.EVP_PKEY_CTX_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    lib.EVP_PKEY_CTX_free.restype = None
    lib.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]

    lib.EVP_PKEY_encrypt_init.restype = ctypes.c_int
    lib.EVP_PKEY_encrypt_init.argtypes = [ctypes.c_void_p]

    lib.EVP_PKEY_encrypt.restype = ctypes.c_int
    lib.EVP_PKEY_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t]

    lib.EVP_PKEY_decrypt_init.restype = ctypes.c_int
    lib.EVP_PKEY_decrypt_init.argtypes = [ctypes.c_void_p]

    lib.EVP_PKEY_decrypt.restype = ctypes.c_int
    lib.EVP_PKEY_decrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t]

    # ── 密钥序列化 ──
    lib.d2i_PrivateKey.restype = ctypes.c_void_p
    lib.d2i_PrivateKey.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
                                    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_long]

    # d2i_AutoPrivateKey: 自动检测格式 (PKCS#8/PKCS#1/SEC1), 同 d2i_PUBKEY 调用模式
    lib.d2i_AutoPrivateKey.restype = ctypes.c_void_p
    lib.d2i_AutoPrivateKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_long]

    lib.d2i_PUBKEY.restype = ctypes.c_void_p
    lib.d2i_PUBKEY.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_long]

    # ── 随机数 ──
    lib.RAND_bytes.restype = ctypes.c_int
    lib.RAND_bytes.argtypes = [ctypes.c_void_p, ctypes.c_int]

    # ── RSA padding 控制 ──
    lib.EVP_PKEY_CTX_ctrl.restype = ctypes.c_int
    lib.EVP_PKEY_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_int, ctypes.c_void_p]

    # ── RSA 字符串控制 (OpenSSL 3.x 推荐, 绕开 keytype/optype/p2 类型问题) ──
    lib.EVP_PKEY_CTX_ctrl_str.restype = ctypes.c_int
    lib.EVP_PKEY_CTX_ctrl_str.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    # ── ECDSA 签名 ──
    lib.EVP_DigestSignInit.restype = ctypes.c_int
    lib.EVP_DigestSignInit.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.EVP_DigestSignUpdate.restype = ctypes.c_int
    lib.EVP_DigestSignUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.EVP_DigestSignFinal.restype = ctypes.c_int
    lib.EVP_DigestSignFinal.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.POINTER(ctypes.c_size_t)]

    # ── 公钥序列化 ──
    lib.i2d_PUBKEY.restype = ctypes.c_int
    lib.i2d_PUBKEY.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]

    # ── BIO (PEM 加载) ──
    lib.BIO_new_mem_buf.restype = ctypes.c_void_p
    lib.BIO_new_mem_buf.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.BIO_free.restype = ctypes.c_int
    lib.BIO_free.argtypes = [ctypes.c_void_p]
    lib.PEM_read_bio_PrivateKey.restype = ctypes.c_void_p
    lib.PEM_read_bio_PrivateKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                            ctypes.c_void_p, ctypes.c_void_p]

    # ── PKCS#8 DER 私钥加载 ──
    lib.d2i_PKCS8PrivateKey_bio.restype = ctypes.c_void_p
    lib.d2i_PKCS8PrivateKey_bio.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                            ctypes.c_void_p, ctypes.c_void_p]

    # ── 内存释放 (i2d 输出) ──
    lib.CRYPTO_free.restype = None
    lib.CRYPTO_free.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]

    # ── EC 密钥访问 (SM2 DER 解析) ──
    lib.EVP_PKEY_get0_EC_KEY.restype = ctypes.c_void_p
    lib.EVP_PKEY_get0_EC_KEY.argtypes = [ctypes.c_void_p]
    lib.EC_KEY_get0_private_key.restype = ctypes.c_void_p
    lib.EC_KEY_get0_private_key.argtypes = [ctypes.c_void_p]
    lib.BN_num_bits.restype = ctypes.c_int
    lib.BN_num_bits.argtypes = [ctypes.c_void_p]
    lib.BN_bn2bin.restype = ctypes.c_int
    lib.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_char_p]


def _setup_v3_signatures(lib):
    """设置 OpenSSL 3.x 独有的 ctypes 签名 (provider fetch API)"""

    # ── MD fetch ──
    lib.EVP_MD_fetch.restype = ctypes.c_void_p
    lib.EVP_MD_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_MD_free.restype = None
    lib.EVP_MD_free.argtypes = [ctypes.c_void_p]

    lib.EVP_MD_get_size.restype = ctypes.c_int
    lib.EVP_MD_get_size.argtypes = [ctypes.c_void_p]

    # ── Cipher fetch ──
    lib.EVP_CIPHER_fetch.restype = ctypes.c_void_p
    lib.EVP_CIPHER_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_CIPHER_free.restype = None
    lib.EVP_CIPHER_free.argtypes = [ctypes.c_void_p]

    lib.EVP_CIPHER_get_block_size.restype = ctypes.c_int
    lib.EVP_CIPHER_get_block_size.argtypes = [ctypes.c_void_p]

    # ── HMAC (EVP_MAC, 仅 3.x) ──
    lib.EVP_MAC_fetch.restype = ctypes.c_void_p
    lib.EVP_MAC_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_MAC_free.restype = None
    lib.EVP_MAC_free.argtypes = [ctypes.c_void_p]

    lib.EVP_MAC_CTX_new.restype = ctypes.c_void_p
    lib.EVP_MAC_CTX_new.argtypes = [ctypes.c_void_p]

    lib.EVP_MAC_CTX_free.restype = None
    lib.EVP_MAC_CTX_free.argtypes = [ctypes.c_void_p]

    lib.EVP_MAC_init.restype = ctypes.c_int
    lib.EVP_MAC_init.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                  ctypes.c_void_p, ctypes.c_void_p]

    lib.EVP_MAC_update.restype = ctypes.c_int
    lib.EVP_MAC_update.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    lib.EVP_MAC_final.restype = ctypes.c_int
    lib.EVP_MAC_final.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.POINTER(ctypes.c_size_t), ctypes.c_size_t]

    # ── EVP_PKEY_CTX_new_from_name (仅 3.x) ──
    lib.EVP_PKEY_CTX_new_from_name.restype = ctypes.c_void_p
    lib.EVP_PKEY_CTX_new_from_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    # ── EVP_PKEY_get_id (仅 3.x, 1.1.x 用 EVP_PKEY_id) ──
    lib.EVP_PKEY_get_id.restype = ctypes.c_int
    lib.EVP_PKEY_get_id.argtypes = [ctypes.c_void_p]

    # ── EVP_PKEY_get_id (3.x 替代 EVP_PKEY_id) ──
    lib.EVP_PKEY_get_id.restype = ctypes.c_int
    lib.EVP_PKEY_get_id.argtypes = [ctypes.c_void_p]


def _setup_legacy_signatures(lib):
    """设置 OpenSSL 1.1.x 独有的 ctypes 签名 (byname API)"""

    lib.EVP_get_digestbyname.restype = ctypes.c_void_p
    lib.EVP_get_digestbyname.argtypes = [ctypes.c_char_p]

    lib.EVP_get_cipherbyname.restype = ctypes.c_void_p
    lib.EVP_get_cipherbyname.argtypes = [ctypes.c_char_p]

    lib.EVP_CIPHER_block_size.restype = ctypes.c_int
    lib.EVP_CIPHER_block_size.argtypes = [ctypes.c_void_p]

    lib.EVP_MD_size.restype = ctypes.c_int
    lib.EVP_MD_size.argtypes = [ctypes.c_void_p]

    # ── EVP_PKEY_id (仅 1.1.x, 3.x 用 EVP_PKEY_get_id) ──
    lib.EVP_PKEY_id.restype = ctypes.c_int
    lib.EVP_PKEY_id.argtypes = [ctypes.c_void_p]

    # ── EVP_PKEY_id (1.1.x) ──
    lib.EVP_PKEY_id.restype = ctypes.c_int
    lib.EVP_PKEY_id.argtypes = [ctypes.c_void_p]


class _LibCrypto:
    """libcrypto 单例, 兼容 OpenSSL 1.1.x / 3.x。

    加载失败时 _lib 为 None，所有方法调用会返回默认值或抛出异常，
    上层应通过 is_available() 检查后再使用。
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._lib, self._source, self._path = _find_library()

        # 如果加载失败，设置默认值并标记为不可用
        if self._lib is None:
            self._major = 0
            self._minor = 0
            self._is_v3 = False
            self._sm4_gcm_supported = False
            self._initialized = True
            return

        # 1. 先注册通用签名 (含 OpenSSL_version, 1.1.x/3.x 都有)
        _setup_common_signatures(self._lib)
        # 2. 解析版本
        self._major, self._minor = self._parse_version()
        self._is_v3 = self._major >= 3
        # 3. 按版本注册专属签名
        if self._is_v3:
            _setup_v3_signatures(self._lib)
        else:
            _setup_legacy_signatures(self._lib)
        self._sm4_gcm_supported = None  # 懒加载缓存
        self._initialized = True

    def is_available(self):
        """检查 libcrypto 是否成功加载"""
        return self._lib is not None

    @property
    def library_path(self):
        """已加载的 libcrypto 文件路径, 未加载时返回 None"""
        return self._path

    @property
    def library_source(self):
        """已加载的 libcrypto 来源标识。

        可能的值:
          - 'package-x86_64' / 'package-aarch64': 包内自带的 .so
          - None: 未加载（降级到 cryptography）
        """
        return self._source

    @property
    def lib(self):
        return self._lib

    def version(self):
        if self._lib is None:
            return None
        return self._lib.OpenSSL_version(0).decode()

    def _parse_version(self):
        """解析 OpenSSL 版本号, 返回 (major, minor)
        e.g. "OpenSSL 3.5.4 ..." -> (3, 5)
             "OpenSSL 1.1.1m ..." -> (1, 1)
        """
        ver = self.version()
        if ver is None:
            return 0, 0
        parts = ver.split()
        ver_str = parts[1] if len(parts) >= 2 else "0.0"
        nums = ver_str.split(".")
        try:
            return int(nums[0]), int(nums[1])
        except (ValueError, IndexError):
            return 0, 0

    def is_v3(self):
        """是否为 OpenSSL 3.x"""
        return self._is_v3

    # ── cipher 辅助方法 (抽象 1.1.x / 3.x 差异) ──

    def fetch_cipher(self, name):
        """获取 cipher 指针. v3: EVP_CIPHER_fetch; 1.1.x: EVP_get_cipherbyname"""
        if self._lib is None:
            return None
        if self._is_v3:
            return self._lib.EVP_CIPHER_fetch(None, name, None)
        else:
            return self._lib.EVP_get_cipherbyname(name)

    def free_cipher(self, cipher):
        """释放 cipher. v3: EVP_CIPHER_free; 1.1.x: no-op (静态指针)"""
        if self._lib is None:
            return
        if self._is_v3 and cipher:
            self._lib.EVP_CIPHER_free(cipher)

    def cipher_block_size(self, cipher):
        """获取 cipher 块大小. v3: EVP_CIPHER_get_block_size; 1.1.x: EVP_CIPHER_block_size"""
        if self._lib is None:
            return 0
        if self._is_v3:
            return self._lib.EVP_CIPHER_get_block_size(cipher)
        else:
            return self._lib.EVP_CIPHER_block_size(cipher)

    # ── digest 辅助方法 ──

    def fetch_digest(self, name):
        """获取 digest 指针. v3: EVP_MD_fetch; 1.1.x: EVP_get_digestbyname"""
        if self._lib is None:
            return None
        if self._is_v3:
            return self._lib.EVP_MD_fetch(None, name, None)
        else:
            return self._lib.EVP_get_digestbyname(name)

    def free_digest(self, md):
        """释放 digest. v3: EVP_MD_free; 1.1.x: no-op"""
        if self._lib is None:
            return
        if self._is_v3 and md:
            self._lib.EVP_MD_free(md)

    def digest_size(self, md):
        """获取 digest 大小. v3: EVP_MD_get_size; 1.1.x: EVP_MD_size"""
        if self._lib is None:
            return 0
        if self._is_v3:
            return self._lib.EVP_MD_get_size(md)
        else:
            return self._lib.EVP_MD_size(md)

    # ── pkey 辅助方法 ──

    def pkey_id(self, pkey):
        """获取 EVP_PKEY 的密钥类型 NID. v3: EVP_PKEY_get_id; 1.1.x: EVP_PKEY_id"""
        if self._lib is None:
            return -1
        if self._is_v3:
            return self._lib.EVP_PKEY_get_id(pkey)
        else:
            return self._lib.EVP_PKEY_id(pkey)

    # ── 能力检测 ──

    def supports_sm4_gcm(self):
        """检测当前 OpenSSL 是否支持 SM4-GCM (仅 3.x 支持).
        首次调用时尝试 fetch, 结果缓存.
        """
        if self._sm4_gcm_supported is not None:
            return self._sm4_gcm_supported
        if self._lib is None or not self._is_v3:
            self._sm4_gcm_supported = False
            return False
        # 3.x: 尝试 fetch SM4-GCM
        cipher = self.fetch_cipher(b"SM4-GCM")
        self._sm4_gcm_supported = bool(cipher)
        if cipher:
            self.free_cipher(cipher)
        return self._sm4_gcm_supported

    def clear_error(self):
        if self._lib is None:
            return
        self._lib.ERR_clear_error()


# 全局单例
_libcrypto = None


def get_libcrypto():
    """获取 libcrypto 单例。

    Returns:
        _LibCrypto 实例（通过 is_available() 检查是否可用）
    """
    global _libcrypto
    if _libcrypto is None:
        _libcrypto = _LibCrypto()
    return _libcrypto


def is_available():
    """检查华为 OpenSSL 是否可用。

    上层调用处用此函数决定走 _openssl 还是 cryptography。
    """
    return get_libcrypto().is_available()


def supports_sm4_gcm():
    """检测当前 OpenSSL 是否支持 SM4-GCM (模块级便捷函数)"""
    return get_libcrypto().supports_sm4_gcm()
