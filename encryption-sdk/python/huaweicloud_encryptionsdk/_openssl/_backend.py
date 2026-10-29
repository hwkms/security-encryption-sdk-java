"""后端自动选择：native（1 FFI/操作）→ ctypes（10-12 FFI/操作）。

用户无需配置任何环境变量，SDK 自动选择最优后端：
1. native C 扩展可用 → 使用 native（静默，无 warning）
2. native 不可用 → 降级到 ctypes（打 warning 提示性能较低）
3. ctypes 也不可用 → 各调用方已有的 cryptography/gmssl 兜底机制接管

ctypes 后端有内置 libcrypto_*.so 支持，基本不会失败。
"""
import importlib
import platform
import sys
import warnings

NATIVE = "native"
CTYPES = "ctypes"
_backend = None
_native_core = None

# 按平台映射 native core .so 文件名
_ARCH_FILE = {
    "x86_64": "_native_core_x86_64.abi3.so",
    "amd64": "_native_core_x86_64.abi3.so",
    "aarch64": "_native_core_aarch64.abi3.so",
    "arm64": "_native_core_aarch64.abi3.so",
}

# C 扩展的 init 函数名（固定，不随平台变化）
_INIT_FUNC = "PyInit__native_core"
_MODULE_NAME = "huaweicloud_encryptionsdk._openssl._native_core"


def _try_native() -> bool:
    """检测 native C 扩展是否可用，按平台加载对应的 .abi3.so。"""
    global _native_core
    try:
        machine = platform.machine().lower()
        so_file = _ARCH_FILE.get(machine)
        if not so_file:
            return False

        import os
        import ctypes
        so_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), so_file)
        if not os.path.exists(so_path):
            return False

        # 用 importlib 直接加载 .so（不需要文件名匹配 init 函数名）
        import importlib.util
        spec = importlib.util.spec_from_file_location(_MODULE_NAME, so_path)
        if spec is None:
            return False
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        _native_core = mod
        return all(hasattr(mod, fn) for fn in (
            "sm3_digest", "sm4_gcm_encrypt", "sm4_gcm_decrypt",
            "aes_gcm_encrypt", "aes_gcm_decrypt",
            "sm4_cbc_encrypt", "sm4_cbc_decrypt",
            "rsa_encrypt", "rsa_decrypt", "ecdsa_sign",
            "load_der_private_key", "load_der_public_key",
            "load_pem_private_key", "free_pkey",
            "pkey_get_public_der", "extract_ec_private_value",
        ))
    except Exception:
        return False


def _get_native_core():
    """返回已加载的 native core 模块。"""
    if _native_core is None:
        _try_native()
    return _native_core


def _try_ctypes() -> bool:
    """检测 ctypes 后端是否可用（内置 libcrypto_*.so，基本必定成功）。"""
    try:
        from huaweicloud_encryptionsdk._openssl import _library
        _library.get_libcrypto()
        return _library.is_available()
    except Exception:
        return False


def get_backend() -> str:
    """返回当前后端名称，首次调用时解析并缓存。

    返回值: 'native' | 'ctypes'
    native 不可用时自动降级到 ctypes 并打 warning。
    ctypes 也不可用时返回 'ctypes'（实际 is_available()=False 时各调用方自行降级到 cryptography/gmssl）。
    """
    global _backend
    if _backend is None:
        if _try_native():
            _backend = NATIVE
        elif _try_ctypes():
            warnings.warn(
                "[EncryptionSDK] Native C 扩展不可用，降级到 ctypes 后端"
                "（小块消息性能较低）。安装对应平台的预编译 .so 可获得最佳性能。",
                RuntimeWarning,
                stacklevel=3,
            )
            _backend = CTYPES
        else:
            # ctypes 也失败，标记为 ctypes
            # 此时 is_available() 返回 False，各调用方走 cryptography/gmssl 兜底
            _backend = CTYPES
    return _backend


def is_native() -> bool:
    return get_backend() == NATIVE
