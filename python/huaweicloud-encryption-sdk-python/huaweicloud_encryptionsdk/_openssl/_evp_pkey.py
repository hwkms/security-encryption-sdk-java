"""
EVP_PKEY 非对称加密: RSA, ECDSA, 密钥加载

接口设计:
  load_der_private_key(der_bytes) -> pkey_ptr
  load_der_public_key(der_bytes) -> pkey_ptr
  load_pem_private_key(pem_bytes) -> pkey_ptr
  rsa_encrypt(pub_der, plaintext) -> ciphertext    # OAEP + SHA256
  rsa_decrypt(priv_der, ciphertext) -> plaintext    # OAEP + SHA256
  ecdsa_sign(priv_pkey, message) -> signature_bytes # ECDSA-SHA256
  pkey_get_public_der(priv_pkey) -> der_bytes       # SPKI DER
  free_pkey(pkey_ptr)                               # 释放
"""
import ctypes

from huaweicloud_encryptionsdk._openssl._library import (
    get_libcrypto, EVP_SUCCESS, OpenSSLError,
    RSA_PKCS1_OAEP_PADDING, EVP_PKEY_CTRL_RSA_PADDING,
    EVP_PKEY_CTRL_RSA_OAEP_MD, EVP_PKEY_CTRL_RSA_MGF1_MD,
    EVP_PKEY_RSA, EVP_PKEY_EC,
)


def free_pkey(pkey):
    """释放 EVP_PKEY"""
    if pkey:
        get_libcrypto().lib.EVP_PKEY_free(pkey)


def load_der_private_key(der_bytes: bytes) -> int:
    """加载 DER 格式私钥 (自动检测 PKCS#8/PKCS#1/SEC1)

    Args:
        der_bytes: DER 编码的私钥 (PKCS#8 或传统格式)

    Returns:
        EVP_PKEY 指针（需要调用者负责释放，使用 free_pkey）

    Raises:
        OpenSSLError: 加载失败
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法加载 DER 私钥")

    # d2i_AutoPrivateKey: 自动检测格式, 与 d2i_PUBKEY 相同的调用模式
    data_ptr = ctypes.cast(ctypes.c_char_p(der_bytes), ctypes.c_void_p)
    pkey = lib.d2i_AutoPrivateKey(None, ctypes.byref(data_ptr), len(der_bytes))
    if not pkey:
        raise OpenSSLError("d2i_AutoPrivateKey 失败：无效的 DER 私钥")
    return pkey


def load_der_public_key(der_bytes: bytes) -> int:
    """加载 SubjectPublicKeyInfo DER 格式公钥

    Args:
        der_bytes: SubjectPublicKeyInfo DER 编码的公钥

    Returns:
        EVP_PKEY 指针（需要调用者负责释放，使用 free_pkey）

    Raises:
        OpenSSLError: 加载失败
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法加载 DER 公钥")

    # d2i_PUBKEY: const unsigned char **pp (in/out, d2i advances it past parsed bytes)
    data_ptr = ctypes.cast(ctypes.c_char_p(der_bytes), ctypes.c_void_p)
    pkey = lib.d2i_PUBKEY(None, ctypes.byref(data_ptr), len(der_bytes))
    if not pkey:
        raise OpenSSLError("d2i_PUBKEY 失败：无效的 SubjectPublicKeyInfo DER 公钥")
    return pkey


def load_pem_private_key(pem_bytes: bytes) -> int:
    """加载 PEM 格式私钥

    Args:
        pem_bytes: PEM 编码的私钥（包含 BEGIN/END 行）

    Returns:
        EVP_PKEY 指针（需要调用者负责释放，使用 free_pkey）

    Raises:
        OpenSSLError: 加载失败
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法加载 PEM 私钥")

    # 创建 BIO
    bio = lib.BIO_new_mem_buf(pem_bytes, len(pem_bytes))
    if not bio:
        raise OpenSSLError("BIO_new_mem_buf 失败")

    try:
        # 加载 PEM 私钥
        pkey = lib.PEM_read_bio_PrivateKey(bio, None, None, None)
        if not pkey:
            raise OpenSSLError("PEM_read_bio_PrivateKey 失败：无效的 PEM 私钥")
        return pkey
    finally:
        lib.BIO_free(bio)


def rsa_encrypt(pub_der: bytes, plaintext: bytes) -> bytes:
    """RSA-OAEP 加密（SHA256）

    Args:
        pub_der: SubjectPublicKeyInfo DER 编码的公钥
        plaintext: 明文数据

    Returns:
        密文数据

    Raises:
        OpenSSLError: 加密失败
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法执行 RSA 加密")

    pkey = load_der_public_key(pub_der)
    if not pkey:
        raise OpenSSLError("加载 RSA 公钥失败")

    try:
        # 创建加密上下文
        ctx = lib.EVP_PKEY_CTX_new(pkey, None)
        if not ctx:
            raise OpenSSLError("EVP_PKEY_CTX_new 失败")

        try:
            # 初始化加密
            if lib.EVP_PKEY_encrypt_init(ctx) <= 0:
                raise OpenSSLError("EVP_PKEY_encrypt_init 失败")

            # 使用 ctrl_str 设置 OAEP (OpenSSL 3.x 推荐方式, 绕开 keytype/optype/p2 类型问题)
            if lib.EVP_PKEY_CTX_ctrl_str(ctx, b"rsa_padding_mode", b"oaep") <= 0:
                raise OpenSSLError("设置 RSA OAEP padding 失败")
            if lib.EVP_PKEY_CTX_ctrl_str(ctx, b"rsa_oaep_md", b"sha256") <= 0:
                raise OpenSSLError("设置 RSA OAEP MD 失败")
            if lib.EVP_PKEY_CTX_ctrl_str(ctx, b"rsa_mgf1_md", b"sha256") <= 0:
                raise OpenSSLError("设置 RSA MGF1 MD 失败")

            # 第一次调用获取密文长度
            outlen = ctypes.c_size_t(0)
            if lib.EVP_PKEY_encrypt(ctx, None, ctypes.byref(outlen),
                                   plaintext, len(plaintext)) <= 0:
                raise OpenSSLError("EVP_PKEY_encrypt (获取长度) 失败")

            # 分配输出缓冲区
            outbuf = ctypes.create_string_buffer(outlen.value)

            # 第二次调用执行加密
            if lib.EVP_PKEY_encrypt(ctx, outbuf, ctypes.byref(outlen),
                                   plaintext, len(plaintext)) <= 0:
                raise OpenSSLError("EVP_PKEY_encrypt 失败")

            return outbuf.raw[:outlen.value]
        finally:
            lib.EVP_PKEY_CTX_free(ctx)
    finally:
        free_pkey(pkey)


def rsa_decrypt(priv_der: bytes, ciphertext: bytes) -> bytes:
    """RSA-OAEP 解密（SHA256）

    Args:
        priv_der: PKCS#8 DER 编码的私钥
        ciphertext: 密文数据

    Returns:
        明文数据

    Raises:
        OpenSSLError: 解密失败
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法执行 RSA 解密")

    pkey = load_der_private_key(priv_der)
    if not pkey:
        raise OpenSSLError("加载 RSA 私钥失败")

    try:
        # 创建解密上下文
        ctx = lib.EVP_PKEY_CTX_new(pkey, None)
        if not ctx:
            raise OpenSSLError("EVP_PKEY_CTX_new 失败")

        try:
            # 初始化解密
            if lib.EVP_PKEY_decrypt_init(ctx) <= 0:
                raise OpenSSLError("EVP_PKEY_decrypt_init 失败")

            # 使用 ctrl_str 设置 OAEP (OpenSSL 3.x 推荐方式, 绕开 keytype/optype/p2 类型问题)
            if lib.EVP_PKEY_CTX_ctrl_str(ctx, b"rsa_padding_mode", b"oaep") <= 0:
                raise OpenSSLError("设置 RSA OAEP padding 失败")
            if lib.EVP_PKEY_CTX_ctrl_str(ctx, b"rsa_oaep_md", b"sha256") <= 0:
                raise OpenSSLError("设置 RSA OAEP MD 失败")
            if lib.EVP_PKEY_CTX_ctrl_str(ctx, b"rsa_mgf1_md", b"sha256") <= 0:
                raise OpenSSLError("设置 RSA MGF1 MD 失败")

            # 第一次调用获取明文长度
            outlen = ctypes.c_size_t(0)
            if lib.EVP_PKEY_decrypt(ctx, None, ctypes.byref(outlen),
                                   ciphertext, len(ciphertext)) <= 0:
                raise OpenSSLError("EVP_PKEY_decrypt (获取长度) 失败")

            # 分配输出缓冲区
            outbuf = ctypes.create_string_buffer(outlen.value)

            # 第二次调用执行解密
            if lib.EVP_PKEY_decrypt(ctx, outbuf, ctypes.byref(outlen),
                                   ciphertext, len(ciphertext)) <= 0:
                raise OpenSSLError("EVP_PKEY_decrypt 失败")

            return outbuf.raw[:outlen.value]
        finally:
            lib.EVP_PKEY_CTX_free(ctx)
    finally:
        free_pkey(pkey)


def ecdsa_sign(priv_pkey: int, message: bytes) -> bytes:
    """ECDSA-SHA256 签名

    Args:
        priv_pkey: EVP_PKEY 指针（EC 私钥）
        message: 待签名消息

    Returns:
        DER 编码的签名

    Raises:
        OpenSSLError: 签名失败
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法执行 ECDSA 签名")

    # 获取 SHA256 digest
    md = lc.fetch_digest(b"SHA256")
    if not md:
        raise OpenSSLError("获取 SHA256 digest 失败")

    try:
        # 创建签名上下文
        mctx = lib.EVP_MD_CTX_new()
        if not mctx:
            raise OpenSSLError("EVP_MD_CTX_new 失败")

        try:
            # 初始化签名
            if lib.EVP_DigestSignInit(mctx, None, md, None, priv_pkey) <= 0:
                raise OpenSSLError("EVP_DigestSignInit 失败")

            # 更新数据
            if lib.EVP_DigestSignUpdate(mctx, message, len(message)) <= 0:
                raise OpenSSLError("EVP_DigestSignUpdate 失败")

            # 第一次调用获取签名长度
            siglen = ctypes.c_size_t(0)
            if lib.EVP_DigestSignFinal(mctx, None, ctypes.byref(siglen)) <= 0:
                raise OpenSSLError("EVP_DigestSignFinal (获取长度) 失败")

            # 分配签名缓冲区
            sigbuf = ctypes.create_string_buffer(siglen.value)

            # 第二次调用执行签名
            if lib.EVP_DigestSignFinal(mctx, sigbuf, ctypes.byref(siglen)) <= 0:
                raise OpenSSLError("EVP_DigestSignFinal 失败")

            return sigbuf.raw[:siglen.value]
        finally:
            lib.EVP_MD_CTX_free(mctx)
    finally:
        lc.free_digest(md)


def pkey_get_public_der(priv_pkey: int) -> bytes:
    """从私钥提取公钥的 SubjectPublicKeyInfo DER 编码

    Args:
        priv_pkey: EVP_PKEY 指针（私钥）

    Returns:
        SubjectPublicKeyInfo DER 编码的公钥

    Raises:
        OpenSSLError: 提取失败
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法提取公钥")

    # 第一次调用获取 DER 长度
    derlen = lib.i2d_PUBKEY(priv_pkey, None)
    if derlen <= 0:
        raise OpenSSLError("i2d_PUBKEY (获取长度) 失败")

    # 分配缓冲区
    derbuf = ctypes.create_string_buffer(derlen)
    pp = ctypes.cast(derbuf, ctypes.POINTER(ctypes.c_ubyte))

    # 第二次调用执行序列化
    if lib.i2d_PUBKEY(priv_pkey, ctypes.byref(pp)) <= 0:
        raise OpenSSLError("i2d_PUBKEY 失败")

    return derbuf.raw[:derlen]


def extract_ec_private_value(der_bytes: bytes) -> int:
    """从 PKCS#8 DER EC 私钥提取私钥标量值

    用于 SM2 keyring 替代 cryptography 的 load_der_private_key + private_numbers().private_value

    Args:
        der_bytes: PKCS#8 DER 编码的 EC 私钥

    Returns:
        私钥标量值（整数）

    Raises:
        OpenSSLError: 提取失败
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法提取 EC 私钥")

    pkey = load_der_private_key(der_bytes)
    if not pkey:
        raise OpenSSLError("加载 EC 私钥失败")

    try:
        # 检查是否为 EC 密钥
        key_id = lc.pkey_id(pkey)
        if key_id != EVP_PKEY_EC:
            raise OpenSSLError("密钥不是 EC 类型 (key_id=%d)" % key_id)

        # 获取 EC_KEY
        ec_key = lib.EVP_PKEY_get0_EC_KEY(pkey)
        if not ec_key:
            raise OpenSSLError("EVP_PKEY_get0_EC_KEY 失败")

        # 获取私钥 BIGNUM
        bn = lib.EC_KEY_get0_private_key(ec_key)
        if not bn:
            raise OpenSSLError("EC_KEY_get0_private_key 失败")

        # 获取 BIGNUM 的字节长度
        num_bytes = (lib.BN_num_bits(bn) + 7) // 8
        if num_bytes <= 0:
            raise OpenSSLError("BN_num_bits 返回 0")

        # 将 BIGNUM 转换为大端字节
        buf = ctypes.create_string_buffer(num_bytes)
        written = lib.BN_bn2bin(bn, buf)
        if written <= 0:
            raise OpenSSLError("BN_bn2bin 失败")

        return int.from_bytes(buf.raw[:written], 'big')
    finally:
        free_pkey(pkey)
