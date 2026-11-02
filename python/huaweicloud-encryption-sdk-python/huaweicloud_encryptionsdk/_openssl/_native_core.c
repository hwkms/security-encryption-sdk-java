/*
 * _native_core.c — huaweicloud-encryption-sdk native C extension (abi3)
 *
 * 兼容 Python 3.9+，编译一个 .abi3.so 通用所有版本。
 * 每个高层操作只穿越一次 Python↔C 边界，EVP 状态机全部在 C 内完成。
 * 运行时 dlopen SDK 内置 libcrypto（libcrypto_x86_64.so / libcrypto_aarch64.so）。
 * 不依赖 OpenSSL 头文件：原型自声明，符号经 dlsym 解析。
 *
 * 构建 (abi3, 兼容 Python 3.9+):
 *   gcc -O2 -std=c99 -shared -fPIC \
 *       -I"$(python3 -c 'import sysconfig;print(sysconfig.get_paths()["include"])')" \
 *       _native_core.c -o "_native_core.abi3.so"
 */
#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x030900f0
#include <Python.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---- OpenSSL 最小原型（自声明，避免依赖头文件） ---- */
typedef struct engine_st ENGINE;
typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct bio_st BIO;

#define EVP_CTRL_AEAD_SET_IVLEN  0x9
#define EVP_CTRL_AEAD_GET_TAG    0x10
#define EVP_CTRL_AEAD_SET_TAG    0x11
#define GCM_TAG_LEN  16
#define SM3_MD_LEN   32
#define SM4_BLOCK    16
#define EVP_LEN_MAX  0x7FFFFFF0
#define EVP_PKEY_EC  408

/* ---- 函数指针 ---- */
static EVP_CIPHER_CTX *(*p_ctx_new)(void);
static void (*p_ctx_free)(EVP_CIPHER_CTX *);
static int (*p_enc_init)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                         const unsigned char *, const unsigned char *);
static int (*p_enc_update)(EVP_CIPHER_CTX *, unsigned char *, int *,
                           const unsigned char *, int);
static int (*p_enc_final)(EVP_CIPHER_CTX *, unsigned char *, int *);
static int (*p_dec_init)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                         const unsigned char *, const unsigned char *);
static int (*p_dec_update)(EVP_CIPHER_CTX *, unsigned char *, int *,
                           const unsigned char *, int);
static int (*p_dec_final)(EVP_CIPHER_CTX *, unsigned char *, int *);
static int (*p_ctx_ctrl)(EVP_CIPHER_CTX *, int, int, void *);

static EVP_CIPHER *(*p_cipher_fetch)(void *, const char *, const char *);
static void (*p_cipher_free)(EVP_CIPHER *);

static int (*p_digest)(const void *, size_t, unsigned char *, unsigned int *,
                       const EVP_MD *, ENGINE *);
static const EVP_MD *(*p_sm3)(void);

static const EVP_CIPHER *(*p_aes128_gcm)(void);
static const EVP_CIPHER *(*p_aes256_gcm)(void);

static unsigned long (*p_version_num)(void);
static const char *(*p_version_str)(int);

static void (*p_pkey_free)(EVP_PKEY *);
static EVP_PKEY *(*p_d2i_AutoPrivateKey)(EVP_PKEY *, const unsigned char **, long);
static EVP_PKEY *(*p_d2i_PUBKEY)(EVP_PKEY *, const unsigned char **, long);
static BIO *(*p_bio_new_mem_buf)(const void *, int);
static int (*p_bio_free)(BIO *);
static EVP_PKEY *(*p_pem_read_bio_privatekey)(BIO *, EVP_PKEY *, void *, void *);
static EVP_PKEY_CTX *(*p_pkey_ctx_new)(EVP_PKEY *, ENGINE *);
static void (*p_pkey_ctx_free)(EVP_PKEY_CTX *);
static int (*p_pkey_encrypt_init)(EVP_PKEY_CTX *);
static int (*p_pkey_decrypt_init)(EVP_PKEY_CTX *);
static int (*p_pkey_encrypt)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                             const unsigned char *, size_t);
static int (*p_pkey_decrypt)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                             const unsigned char *, size_t);
static int (*p_pkey_ctx_ctrl_str)(EVP_PKEY_CTX *, const char *, const char *);

static EVP_MD_CTX *(*p_md_ctx_new)(void);
static void (*p_md_ctx_free)(EVP_MD_CTX *);
static int (*p_digest_sign_init)(EVP_MD_CTX *, EVP_PKEY_CTX **, const EVP_MD *,
                                  ENGINE *, EVP_PKEY *);
static int (*p_digest_sign_update)(EVP_MD_CTX *, const void *, size_t);
static int (*p_digest_sign_final)(EVP_MD_CTX *, unsigned char *, size_t *);
static const EVP_MD *(*p_sha256)(void);

static int (*p_i2d_PUBKEY)(EVP_PKEY *, unsigned char **);

static int (*p_pkey_id)(const EVP_PKEY *);
static void *(*p_pkey_get0_ec_key)(const EVP_PKEY *);
static const void *(*p_ec_key_get0_private_key)(const void *);
static int (*p_bn_num_bits)(const void *);
static int (*p_bn_bn2bin)(const void *, unsigned char *);

static void (*p_err_clear_error)(void);

/* ---- 全局状态 ---- */
static void *g_handle = NULL;
static const char *g_last_err = NULL;
static char g_lib_path[512] = {0};

static EVP_CIPHER *g_sm4_gcm = NULL;
static EVP_CIPHER *g_sm4_cbc = NULL;
static const EVP_MD *g_sm3_md = NULL;
static PyObject *InvalidTagError = NULL;

#define SYM(var, name) do {                                   \
    *(void **)(&(var)) = dlsym(g_handle, name);               \
    if (!(var)) { g_last_err = name; goto fail; }             \
} while (0)

/* ---- libcrypto 加载 ---- */
static int load_libcrypto(void) {
    const char *env = getenv("SDK_OPENSSL_LIB");
    if (env && *env) {
        g_handle = dlopen(env, RTLD_NOW | RTLD_LOCAL);
        if (!g_handle) { g_last_err = dlerror(); return -1; }
        strncpy(g_lib_path, env, sizeof(g_lib_path) - 1);
        goto loaded;
    }

    /* 用 dladdr 获取本 .so 自身路径，推导 _openssl 目录 */
    {
        Dl_info info;
        if (dladdr((void *)load_libcrypto, &info) && info.dli_fname) {
            char dir[512];
            strncpy(dir, info.dli_fname, sizeof(dir) - 1);
            dir[sizeof(dir) - 1] = '\0';
            char *slash = strrchr(dir, '/');
            if (slash) *slash = '\0';

            const char *arch_file;
#if defined(__x86_64__) || defined(__amd64__)
            arch_file = "libcrypto_x86_64.so";
#elif defined(__aarch64__) || defined(__arm64__)
            arch_file = "libcrypto_aarch64.so";
#else
            g_last_err = "unsupported platform";
            return -1;
#endif
            snprintf(g_lib_path, sizeof(g_lib_path), "%s/%s", dir, arch_file);
            g_handle = dlopen(g_lib_path, RTLD_NOW | RTLD_LOCAL);
            if (g_handle) goto loaded;
        }
    }

    g_last_err = "could not find bundled libcrypto.so (check _openssl/ directory)";
    return -1;

loaded:
    SYM(p_ctx_new, "EVP_CIPHER_CTX_new");
    SYM(p_ctx_free, "EVP_CIPHER_CTX_free");
    SYM(p_enc_init, "EVP_EncryptInit_ex");
    SYM(p_enc_update, "EVP_EncryptUpdate");
    SYM(p_enc_final, "EVP_EncryptFinal_ex");
    SYM(p_dec_init, "EVP_DecryptInit_ex");
    SYM(p_dec_update, "EVP_DecryptUpdate");
    SYM(p_dec_final, "EVP_DecryptFinal_ex");
    SYM(p_ctx_ctrl, "EVP_CIPHER_CTX_ctrl");
    SYM(p_cipher_fetch, "EVP_CIPHER_fetch");
    SYM(p_cipher_free, "EVP_CIPHER_free");
    SYM(p_digest, "EVP_Digest");
    SYM(p_sm3, "EVP_sm3");
    SYM(p_aes128_gcm, "EVP_aes_128_gcm");
    SYM(p_aes256_gcm, "EVP_aes_256_gcm");
    SYM(p_version_num, "OpenSSL_version_num");
    SYM(p_version_str, "OpenSSL_version");
    SYM(p_pkey_free, "EVP_PKEY_free");
    SYM(p_d2i_AutoPrivateKey, "d2i_AutoPrivateKey");
    SYM(p_d2i_PUBKEY, "d2i_PUBKEY");
    SYM(p_bio_new_mem_buf, "BIO_new_mem_buf");
    SYM(p_bio_free, "BIO_free");
    SYM(p_pem_read_bio_privatekey, "PEM_read_bio_PrivateKey");
    SYM(p_pkey_ctx_new, "EVP_PKEY_CTX_new");
    SYM(p_pkey_ctx_free, "EVP_PKEY_CTX_free");
    SYM(p_pkey_encrypt_init, "EVP_PKEY_encrypt_init");
    SYM(p_pkey_decrypt_init, "EVP_PKEY_decrypt_init");
    SYM(p_pkey_encrypt, "EVP_PKEY_encrypt");
    SYM(p_pkey_decrypt, "EVP_PKEY_decrypt");
    SYM(p_pkey_ctx_ctrl_str, "EVP_PKEY_CTX_ctrl_str");
    SYM(p_md_ctx_new, "EVP_MD_CTX_new");
    SYM(p_md_ctx_free, "EVP_MD_CTX_free");
    SYM(p_digest_sign_init, "EVP_DigestSignInit");
    SYM(p_digest_sign_update, "EVP_DigestSignUpdate");
    SYM(p_digest_sign_final, "EVP_DigestSignFinal");
    SYM(p_sha256, "EVP_sha256");
    SYM(p_i2d_PUBKEY, "i2d_PUBKEY");
    SYM(p_pkey_id, "EVP_PKEY_get_id");
    SYM(p_pkey_get0_ec_key, "EVP_PKEY_get0_EC_KEY");
    SYM(p_ec_key_get0_private_key, "EC_KEY_get0_private_key");
    SYM(p_bn_num_bits, "BN_num_bits");
    SYM(p_bn_bn2bin, "BN_bn2bin");
    SYM(p_err_clear_error, "ERR_clear_error");

    if ((p_version_num() >> 28) != 3) {
        g_last_err = "OpenSSL 3.x required";
        goto fail;
    }

    g_sm3_md = p_sm3();
    if (!g_sm3_md) { g_last_err = "EVP_sm3 missing"; goto fail; }

    g_sm4_gcm = p_cipher_fetch(NULL, "SM4-GCM", NULL);
    g_sm4_cbc = p_cipher_fetch(NULL, "SM4-CBC", NULL);
    return 0;

fail:
    if (g_handle) { dlclose(g_handle); g_handle = NULL; }
    return -1;
}

/* ---- 辅助：新建精确大小 bytes ---- */
static PyObject *shrink_bytes(PyObject *obj, Py_ssize_t new_len) {
    if (!obj) return NULL;
    char *buf = PyBytes_AsString(obj);
    if (!buf) { Py_DECREF(obj); return NULL; }
    PyObject *result = PyBytes_FromStringAndSize(buf, new_len);
    Py_DECREF(obj);
    return result;
}

/* ---- SM3 一次性摘要 ---- */
static PyObject *py_sm3_digest(PyObject *self, PyObject *arg) {
    const char *data;
    Py_ssize_t data_len;
    if (PyBytes_AsStringAndSize(arg, &data, &data_len) < 0) return NULL;
    unsigned char out[SM3_MD_LEN];
    unsigned int out_len = 0;
    int ok;
    Py_BEGIN_ALLOW_THREADS
    ok = p_digest(data, (size_t)data_len, out, &out_len, g_sm3_md, NULL) == 1;
    Py_END_ALLOW_THREADS
    if (!ok) {
        PyErr_SetString(PyExc_RuntimeError, "EVP_Digest(SM3) failed");
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)out_len);
}

/* ---- GCM 公共核心 ---- */
static int gcm_run(const EVP_CIPHER *cipher,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *iv, size_t iv_len,
                   const unsigned char *aad, size_t aad_len,
                   const unsigned char *in, size_t in_len,
                   unsigned char *out, int encrypting) {
    EVP_CIPHER_CTX *ctx = p_ctx_new();
    if (!ctx) return 1;
    int rc = 1;
    do {
        int n = 0;
        int (*init1)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                     const unsigned char *, const unsigned char *) =
            encrypting ? p_enc_init : p_dec_init;
        int (*update)(EVP_CIPHER_CTX *, unsigned char *, int *,
                      const unsigned char *, int) =
            encrypting ? p_enc_update : p_dec_update;
        int (*fin)(EVP_CIPHER_CTX *, unsigned char *, int *) =
            encrypting ? p_enc_final : p_dec_final;

        if (init1(ctx, cipher, NULL, NULL, NULL) != 1) break;
        if (p_ctx_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_len, NULL) != 1) break;
        if (init1(ctx, NULL, NULL, key, iv) != 1) break;
        if (aad_len > 0 && update(ctx, NULL, &n, aad, (int)aad_len) != 1) break;

        if (encrypting) {
            int body = 0;
            if (in_len > 0 && update(ctx, out, &n, in, (int)in_len) != 1) break;
            body = n;
            int fl = 0;
            if (fin(ctx, out + body, &fl) != 1) break;
            if (p_ctx_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_LEN,
                           out + in_len) != 1) break;
        } else {
            size_t body_len = in_len - GCM_TAG_LEN;
            int body = 0;
            if (body_len > 0 && update(ctx, out, &n, in, (int)body_len) != 1) break;
            body = n;
            if (p_ctx_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_LEN,
                           (void *)(in + body_len)) != 1) break;
            int fl = 0;
            if (fin(ctx, out + body, &fl) != 1) { rc = 2; break; }
        }
        rc = 0;
    } while (0);
    p_ctx_free(ctx);
    return rc;
}

/* ---- CBC 公共核心 ---- */
static int cbc_run(const EVP_CIPHER *cipher,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *iv,
                   const unsigned char *in, size_t in_len,
                   unsigned char *out, size_t *out_len,
                   int encrypting) {
    EVP_CIPHER_CTX *ctx = p_ctx_new();
    if (!ctx) return 1;
    int rc = 1;
    do {
        if (encrypting) {
            if (p_enc_init(ctx, cipher, NULL, key, iv) != 1) break;
            int n = 0;
            if (in_len > 0 && p_enc_update(ctx, out, &n, in, (int)in_len) != 1) break;
            int fl = 0;
            if (p_enc_final(ctx, out + n, &fl) != 1) break;
            *out_len = (size_t)(n + fl);
        } else {
            if (p_dec_init(ctx, cipher, NULL, key, iv) != 1) break;
            int n = 0;
            if (in_len > 0 && p_dec_update(ctx, out, &n, in, (int)in_len) != 1) break;
            int fl = 0;
            if (p_dec_final(ctx, out + n, &fl) != 1) break;
            *out_len = (size_t)(n + fl);
        }
        rc = 0;
    } while (0);
    p_ctx_free(ctx);
    return rc;
}

/* ---- cipher resolver ---- */
typedef const EVP_CIPHER *(*cipher_resolver)(Py_ssize_t key_len, int *err);

static const EVP_CIPHER *resolve_sm4_gcm(Py_ssize_t key_len, int *err) {
    if (key_len != 16) { *err = 1; return NULL; }
    if (!g_sm4_gcm) { *err = 2; return NULL; }
    return g_sm4_gcm;
}

static const EVP_CIPHER *resolve_aes_gcm(Py_ssize_t key_len, int *err) {
    if (key_len == 16) return p_aes128_gcm();
    if (key_len == 32) return p_aes256_gcm();
    *err = 1;
    return NULL;
}

/* ---- GCM 加密/解密 ---- */
static PyObject *gcm_encrypt_py(PyObject *args, cipher_resolver resolve) {
    const char *key, *iv, *aad, *pt;
    Py_ssize_t key_len, iv_len, aad_len, pt_len;
    if (!PyArg_ParseTuple(args, "y#y#y#y#",
            &key, &key_len, &iv, &iv_len, &aad, &aad_len, &pt, &pt_len))
        return NULL;

    int err = 0;
    const EVP_CIPHER *cipher = resolve(key_len, &err);
    if (!cipher || iv_len == 0 || pt_len > EVP_LEN_MAX || aad_len > EVP_LEN_MAX) {
        if (!cipher && err == 2)
            PyErr_SetString(PyExc_RuntimeError, "libcrypto does not provide SM4-GCM");
        else
            PyErr_SetString(PyExc_ValueError,
                            "key must be 16 (SM4/AES-128) or 32 (AES-256) bytes; IV non-empty");
        return NULL;
    }

    PyObject *result = PyBytes_FromStringAndSize(NULL, pt_len + GCM_TAG_LEN);
    if (!result) return NULL;
    unsigned char *out = (unsigned char *)PyBytes_AsString(result);

    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = gcm_run(cipher, (const unsigned char *)key, (size_t)key_len,
                 (const unsigned char *)iv, (size_t)iv_len,
                 (const unsigned char *)aad, (size_t)aad_len,
                 (const unsigned char *)pt, (size_t)pt_len, out, 1);
    Py_END_ALLOW_THREADS

    if (rc != 0) {
        Py_DECREF(result);
        PyErr_SetString(PyExc_RuntimeError, "GCM encryption failed");
        return NULL;
    }
    return result;
}

static PyObject *gcm_decrypt_py(PyObject *args, cipher_resolver resolve) {
    const char *key, *iv, *aad, *ct;
    Py_ssize_t key_len, iv_len, aad_len, ct_len;
    if (!PyArg_ParseTuple(args, "y#y#y#y#",
            &key, &key_len, &iv, &iv_len, &aad, &aad_len, &ct, &ct_len))
        return NULL;

    int err = 0;
    const EVP_CIPHER *cipher = resolve(key_len, &err);
    if (!cipher || iv_len == 0 || ct_len < GCM_TAG_LEN ||
            ct_len > EVP_LEN_MAX || aad_len > EVP_LEN_MAX) {
        if (!cipher && err == 2)
            PyErr_SetString(PyExc_RuntimeError, "libcrypto does not provide SM4-GCM");
        else
            PyErr_SetString(PyExc_ValueError,
                            "key must be 16/32 bytes; IV non-empty; ciphertext must include 16-byte tag");
        return NULL;
    }

    PyObject *result = PyBytes_FromStringAndSize(NULL, ct_len - GCM_TAG_LEN);
    if (!result) return NULL;
    unsigned char *out = (unsigned char *)PyBytes_AsString(result);

    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = gcm_run(cipher, (const unsigned char *)key, (size_t)key_len,
                 (const unsigned char *)iv, (size_t)iv_len,
                 (const unsigned char *)aad, (size_t)aad_len,
                 (const unsigned char *)ct, (size_t)ct_len, out, 0);
    Py_END_ALLOW_THREADS

    if (rc != 0) {
        Py_DECREF(result);
        if (rc == 2)
            PyErr_SetString(InvalidTagError, "GCM tag verification failed");
        else
            PyErr_SetString(PyExc_RuntimeError, "GCM decryption failed");
        return NULL;
    }
    return result;
}

static PyObject *py_sm4_gcm_encrypt(PyObject *self, PyObject *args) {
    return gcm_encrypt_py(args, resolve_sm4_gcm);
}
static PyObject *py_sm4_gcm_decrypt(PyObject *self, PyObject *args) {
    return gcm_decrypt_py(args, resolve_sm4_gcm);
}
static PyObject *py_aes_gcm_encrypt(PyObject *self, PyObject *args) {
    return gcm_encrypt_py(args, resolve_aes_gcm);
}
static PyObject *py_aes_gcm_decrypt(PyObject *self, PyObject *args) {
    return gcm_decrypt_py(args, resolve_aes_gcm);
}

/* ---- SM4-CBC 加密/解密 ---- */
static PyObject *py_sm4_cbc_encrypt(PyObject *self, PyObject *args) {
    const char *key, *iv, *pt;
    Py_ssize_t key_len, iv_len, pt_len;
    if (!PyArg_ParseTuple(args, "y#y#y#", &key, &key_len, &iv, &iv_len, &pt, &pt_len))
        return NULL;

    if (key_len != 16 || iv_len != 16 || !g_sm4_cbc) {
        if (!g_sm4_cbc)
            PyErr_SetString(PyExc_RuntimeError, "libcrypto does not provide SM4-CBC");
        else
            PyErr_SetString(PyExc_ValueError, "SM4 key must be 16 bytes, IV must be 16 bytes");
        return NULL;
    }

    size_t out_max = (size_t)pt_len + SM4_BLOCK;
    PyObject *result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)out_max);
    if (!result) return NULL;
    unsigned char *out = (unsigned char *)PyBytes_AsString(result);

    size_t out_len = 0;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = cbc_run(g_sm4_cbc, (const unsigned char *)key, (size_t)key_len,
                 (const unsigned char *)iv, (const unsigned char *)pt, (size_t)pt_len,
                 out, &out_len, 1);
    Py_END_ALLOW_THREADS

    if (rc != 0) {
        Py_DECREF(result);
        PyErr_SetString(PyExc_RuntimeError, "SM4-CBC encryption failed");
        return NULL;
    }
    return shrink_bytes(result, (Py_ssize_t)out_len);
}

static PyObject *py_sm4_cbc_decrypt(PyObject *self, PyObject *args) {
    const char *key, *iv, *ct;
    Py_ssize_t key_len, iv_len, ct_len;
    if (!PyArg_ParseTuple(args, "y#y#y#", &key, &key_len, &iv, &iv_len, &ct, &ct_len))
        return NULL;

    if (key_len != 16 || iv_len != 16 || !g_sm4_cbc) {
        if (!g_sm4_cbc)
            PyErr_SetString(PyExc_RuntimeError, "libcrypto does not provide SM4-CBC");
        else
            PyErr_SetString(PyExc_ValueError, "SM4 key must be 16 bytes, IV must be 16 bytes");
        return NULL;
    }

    size_t out_max = (size_t)ct_len;
    PyObject *result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)out_max);
    if (!result) return NULL;
    unsigned char *out = (unsigned char *)PyBytes_AsString(result);

    size_t out_len = 0;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = cbc_run(g_sm4_cbc, (const unsigned char *)key, (size_t)key_len,
                 (const unsigned char *)iv, (const unsigned char *)ct, (size_t)ct_len,
                 out, &out_len, 0);
    Py_END_ALLOW_THREADS

    if (rc != 0) {
        Py_DECREF(result);
        PyErr_SetString(PyExc_RuntimeError, "CBC padding error");
        return NULL;
    }
    return shrink_bytes(result, (Py_ssize_t)out_len);
}

/* ---- RSA-OAEP-SHA256 加密 ---- */
static PyObject *py_rsa_encrypt(PyObject *self, PyObject *args) {
    const char *pub_der, *pt;
    Py_ssize_t pub_der_len, pt_len;
    if (!PyArg_ParseTuple(args, "y#y#", &pub_der, &pub_der_len, &pt, &pt_len))
        return NULL;

    const unsigned char *p = (const unsigned char *)pub_der;
    EVP_PKEY *pkey = p_d2i_PUBKEY(NULL, &p, (long)pub_der_len);
    if (!pkey) {
        PyErr_SetString(PyExc_RuntimeError, "d2i_PUBKEY failed: invalid DER public key");
        return NULL;
    }

    EVP_PKEY_CTX *ctx = p_pkey_ctx_new(pkey, NULL);
    if (!ctx) {
        p_pkey_free(pkey);
        PyErr_SetString(PyExc_RuntimeError, "EVP_PKEY_CTX_new failed");
        return NULL;
    }

    PyObject *result = NULL;
    do {
        if (p_pkey_encrypt_init(ctx) <= 0) break;
        if (p_pkey_ctx_ctrl_str(ctx, "rsa_padding_mode", "oaep") <= 0) break;
        if (p_pkey_ctx_ctrl_str(ctx, "rsa_oaep_md", "sha256") <= 0) break;
        if (p_pkey_ctx_ctrl_str(ctx, "rsa_mgf1_md", "sha256") <= 0) break;

        size_t outlen = 0;
        if (p_pkey_encrypt(ctx, NULL, &outlen,
                           (const unsigned char *)pt, (size_t)pt_len) <= 0) break;

        result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)outlen);
        if (!result) break;
        unsigned char *out = (unsigned char *)PyBytes_AsString(result);

        size_t outlen2 = outlen;
        if (p_pkey_encrypt(ctx, out, &outlen2,
                           (const unsigned char *)pt, (size_t)pt_len) <= 0) {
            Py_DECREF(result);
            result = NULL;
            break;
        }
        if (outlen2 != outlen)
            result = shrink_bytes(result, (Py_ssize_t)outlen2);
    } while (0);

    p_pkey_ctx_free(ctx);
    p_pkey_free(pkey);

    if (!result && !PyErr_Occurred())
        PyErr_SetString(PyExc_RuntimeError, "RSA encryption failed");
    return result;
}

/* ---- RSA-OAEP-SHA256 解密 ---- */
static PyObject *py_rsa_decrypt(PyObject *self, PyObject *args) {
    const char *priv_der, *ct;
    Py_ssize_t priv_der_len, ct_len;
    if (!PyArg_ParseTuple(args, "y#y#", &priv_der, &priv_der_len, &ct, &ct_len))
        return NULL;

    const unsigned char *p = (const unsigned char *)priv_der;
    EVP_PKEY *pkey = p_d2i_AutoPrivateKey(NULL, &p, (long)priv_der_len);
    if (!pkey) {
        PyErr_SetString(PyExc_RuntimeError, "d2i_AutoPrivateKey failed: invalid DER private key");
        return NULL;
    }

    EVP_PKEY_CTX *ctx = p_pkey_ctx_new(pkey, NULL);
    if (!ctx) {
        p_pkey_free(pkey);
        PyErr_SetString(PyExc_RuntimeError, "EVP_PKEY_CTX_new failed");
        return NULL;
    }

    PyObject *result = NULL;
    do {
        if (p_pkey_decrypt_init(ctx) <= 0) break;
        if (p_pkey_ctx_ctrl_str(ctx, "rsa_padding_mode", "oaep") <= 0) break;
        if (p_pkey_ctx_ctrl_str(ctx, "rsa_oaep_md", "sha256") <= 0) break;
        if (p_pkey_ctx_ctrl_str(ctx, "rsa_mgf1_md", "sha256") <= 0) break;

        size_t outlen = 0;
        if (p_pkey_decrypt(ctx, NULL, &outlen,
                           (const unsigned char *)ct, (size_t)ct_len) <= 0) break;

        result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)outlen);
        if (!result) break;
        unsigned char *out = (unsigned char *)PyBytes_AsString(result);

        size_t outlen2 = outlen;
        if (p_pkey_decrypt(ctx, out, &outlen2,
                           (const unsigned char *)ct, (size_t)ct_len) <= 0) {
            Py_DECREF(result);
            result = NULL;
            break;
        }
        if (outlen2 != outlen)
            result = shrink_bytes(result, (Py_ssize_t)outlen2);
    } while (0);

    p_pkey_ctx_free(ctx);
    p_pkey_free(pkey);

    if (!result && !PyErr_Occurred())
        PyErr_SetString(PyExc_RuntimeError, "RSA decryption failed");
    return result;
}

/* ---- 密钥加载 ---- */
static PyObject *py_load_der_private_key(PyObject *self, PyObject *args) {
    const char *der;
    Py_ssize_t der_len;
    if (!PyArg_ParseTuple(args, "y#", &der, &der_len)) return NULL;
    const unsigned char *p = (const unsigned char *)der;
    EVP_PKEY *pkey = p_d2i_AutoPrivateKey(NULL, &p, (long)der_len);
    if (!pkey) {
        PyErr_SetString(PyExc_RuntimeError, "d2i_AutoPrivateKey failed: invalid DER private key");
        return NULL;
    }
    return PyLong_FromVoidPtr(pkey);
}

static PyObject *py_load_der_public_key(PyObject *self, PyObject *args) {
    const char *der;
    Py_ssize_t der_len;
    if (!PyArg_ParseTuple(args, "y#", &der, &der_len)) return NULL;
    const unsigned char *p = (const unsigned char *)der;
    EVP_PKEY *pkey = p_d2i_PUBKEY(NULL, &p, (long)der_len);
    if (!pkey) {
        PyErr_SetString(PyExc_RuntimeError, "d2i_PUBKEY failed: invalid DER public key");
        return NULL;
    }
    return PyLong_FromVoidPtr(pkey);
}

static PyObject *py_load_pem_private_key(PyObject *self, PyObject *args) {
    const char *pem;
    Py_ssize_t pem_len;
    if (!PyArg_ParseTuple(args, "y#", &pem, &pem_len)) return NULL;
    BIO *bio = p_bio_new_mem_buf(pem, (int)pem_len);
    if (!bio) {
        PyErr_SetString(PyExc_RuntimeError, "BIO_new_mem_buf failed");
        return NULL;
    }
    EVP_PKEY *pkey = p_pem_read_bio_privatekey(bio, NULL, NULL, NULL);
    p_bio_free(bio);
    if (!pkey) {
        PyErr_SetString(PyExc_RuntimeError, "PEM_read_bio_PrivateKey failed: invalid PEM private key");
        return NULL;
    }
    return PyLong_FromVoidPtr(pkey);
}

static PyObject *py_free_pkey(PyObject *self, PyObject *args) {
    long long ptr;
    if (!PyArg_ParseTuple(args, "L", &ptr)) return NULL;
    if (ptr) p_pkey_free((EVP_PKEY *)(intptr_t)ptr);
    Py_RETURN_NONE;
}

/* ---- ECDSA-SHA256 签名 ---- */
static PyObject *py_ecdsa_sign(PyObject *self, PyObject *args) {
    long long ptr;
    const char *msg;
    Py_ssize_t msg_len;
    if (!PyArg_ParseTuple(args, "Ly#", &ptr, &msg, &msg_len)) return NULL;

    EVP_PKEY *pkey = (EVP_PKEY *)(intptr_t)ptr;
    if (!pkey) {
        PyErr_SetString(PyExc_ValueError, "private key pointer is null");
        return NULL;
    }

    const EVP_MD *md = p_sha256();
    EVP_MD_CTX *mctx = p_md_ctx_new();
    if (!mctx) {
        PyErr_SetString(PyExc_RuntimeError, "EVP_MD_CTX_new failed");
        return NULL;
    }

    PyObject *result = NULL;
    do {
        if (p_digest_sign_init(mctx, NULL, md, NULL, pkey) <= 0) break;
        if (p_digest_sign_update(mctx, msg, (size_t)msg_len) <= 0) break;

        size_t siglen = 0;
        if (p_digest_sign_final(mctx, NULL, &siglen) <= 0) break;

        result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)siglen);
        if (!result) break;
        unsigned char *sig = (unsigned char *)PyBytes_AsString(result);

        size_t siglen2 = siglen;
        if (p_digest_sign_final(mctx, sig, &siglen2) <= 0) {
            Py_DECREF(result);
            result = NULL;
            break;
        }
        if (siglen2 != siglen)
            result = shrink_bytes(result, (Py_ssize_t)siglen2);
    } while (0);

    p_md_ctx_free(mctx);

    if (!result && !PyErr_Occurred())
        PyErr_SetString(PyExc_RuntimeError, "ECDSA signing failed");
    return result;
}

/* ---- 从私钥提取公钥 DER ---- */
static PyObject *py_pkey_get_public_der(PyObject *self, PyObject *args) {
    long long ptr;
    if (!PyArg_ParseTuple(args, "L", &ptr)) return NULL;

    EVP_PKEY *pkey = (EVP_PKEY *)(intptr_t)ptr;
    if (!pkey) {
        PyErr_SetString(PyExc_ValueError, "private key pointer is null");
        return NULL;
    }

    int derlen = p_i2d_PUBKEY(pkey, NULL);
    if (derlen <= 0) {
        PyErr_SetString(PyExc_RuntimeError, "i2d_PUBKEY failed");
        return NULL;
    }

    PyObject *result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)derlen);
    if (!result) return NULL;

    unsigned char *out = (unsigned char *)PyBytes_AsString(result);
    unsigned char *p = out;
    int derlen2 = p_i2d_PUBKEY(pkey, &p);
    if (derlen2 <= 0) {
        Py_DECREF(result);
        PyErr_SetString(PyExc_RuntimeError, "i2d_PUBKEY serialization failed");
        return NULL;
    }
    if (derlen2 != derlen)
        result = shrink_bytes(result, (Py_ssize_t)derlen2);
    return result;
}

/* ---- 从 DER EC 私钥提取私钥标量 ---- */
static PyObject *py_extract_ec_private_value(PyObject *self, PyObject *args) {
    const char *der;
    Py_ssize_t der_len;
    if (!PyArg_ParseTuple(args, "y#", &der, &der_len)) return NULL;

    const unsigned char *p = (const unsigned char *)der;
    EVP_PKEY *pkey = p_d2i_AutoPrivateKey(NULL, &p, (long)der_len);
    if (!pkey) {
        PyErr_SetString(PyExc_RuntimeError, "d2i_AutoPrivateKey failed: invalid DER private key");
        return NULL;
    }

    PyObject *result = NULL;
    do {
        int key_id = p_pkey_id(pkey);
        if (key_id != EVP_PKEY_EC) {
            PyErr_SetString(PyExc_RuntimeError, "key is not EC type");
            break;
        }

        const void *ec_key = p_pkey_get0_ec_key(pkey);
        if (!ec_key) {
            PyErr_SetString(PyExc_RuntimeError, "EVP_PKEY_get0_EC_KEY failed");
            break;
        }

        const void *bn = p_ec_key_get0_private_key(ec_key);
        if (!bn) {
            PyErr_SetString(PyExc_RuntimeError, "EC_KEY_get0_private_key failed");
            break;
        }

        int num_bits = p_bn_num_bits(bn);
        if (num_bits <= 0) {
            PyErr_SetString(PyExc_RuntimeError, "BN_num_bits returned 0");
            break;
        }

        int num_bytes = (num_bits + 7) / 8;
        unsigned char *buf = (unsigned char *)PyMem_Malloc(num_bytes);
        if (!buf) { PyErr_NoMemory(); break; }

        int written = p_bn_bn2bin(bn, buf);
        if (written <= 0) {
            PyMem_Free(buf);
            PyErr_SetString(PyExc_RuntimeError, "BN_bn2bin failed");
            break;
        }

        /* 转为 Python int（大端无符号） */
        result = PyLong_FromUnsignedLong(0);
        if (result) {
            int i;
            for (i = 0; i < written; i++) {
                PyObject *mul256 = PyLong_FromLong(256);
                if (!mul256) { Py_DECREF(result); result = NULL; break; }
                PyObject *tmp = PyNumber_Multiply(result, mul256);
                Py_DECREF(mul256);
                Py_DECREF(result);
                PyObject *byte_val = PyLong_FromUnsignedLong(buf[i]);
                if (!byte_val) { Py_XDECREF(tmp); result = NULL; break; }
                result = PyNumber_Add(tmp, byte_val);
                Py_DECREF(tmp);
                Py_DECREF(byte_val);
                if (!result) break;
            }
        }
        PyMem_Free(buf);
    } while (0);

    p_pkey_free(pkey);
    return result;
}

/* ---- 版本信息 ---- */
static PyObject *py_get_version(PyObject *self, PyObject *args) {
    const char *ver = p_version_str(0);
    if (ver) return PyUnicode_FromString(ver);
    Py_RETURN_NONE;
}

static PyObject *py_get_libcrypto_path(PyObject *self, PyObject *args) {
    if (g_lib_path[0]) return PyUnicode_FromString(g_lib_path);
    Py_RETURN_NONE;
}

/* ---- 方法表 ---- */
static PyMethodDef METHODS[] = {
    {"sm3_digest", py_sm3_digest, METH_O, "SM3 一次性摘要"},
    {"sm4_gcm_encrypt", py_sm4_gcm_encrypt, METH_VARARGS,
     "sm4_gcm_encrypt(key, iv, aad, plaintext) -> ct||tag"},
    {"sm4_gcm_decrypt", py_sm4_gcm_decrypt, METH_VARARGS,
     "sm4_gcm_decrypt(key, iv, aad, ct_and_tag) -> plaintext"},
    {"aes_gcm_encrypt", py_aes_gcm_encrypt, METH_VARARGS,
     "aes_gcm_encrypt(key128|256, iv, aad, plaintext) -> ct||tag"},
    {"aes_gcm_decrypt", py_aes_gcm_decrypt, METH_VARARGS,
     "aes_gcm_decrypt(key128|256, iv, aad, ct_and_tag) -> plaintext"},
    {"sm4_cbc_encrypt", py_sm4_cbc_encrypt, METH_VARARGS,
     "sm4_cbc_encrypt(key, iv, plaintext) -> ciphertext (PKCS7)"},
    {"sm4_cbc_decrypt", py_sm4_cbc_decrypt, METH_VARARGS,
     "sm4_cbc_decrypt(key, iv, ciphertext) -> plaintext (PKCS7)"},
    {"rsa_encrypt", py_rsa_encrypt, METH_VARARGS,
     "rsa_encrypt(pub_der, plaintext) -> ciphertext (OAEP+SHA256)"},
    {"rsa_decrypt", py_rsa_decrypt, METH_VARARGS,
     "rsa_decrypt(priv_der, ciphertext) -> plaintext (OAEP+SHA256)"},
    {"load_der_private_key", py_load_der_private_key, METH_VARARGS,
     "load_der_private_key(der) -> pkey_ptr"},
    {"load_der_public_key", py_load_der_public_key, METH_VARARGS,
     "load_der_public_key(der) -> pkey_ptr"},
    {"load_pem_private_key", py_load_pem_private_key, METH_VARARGS,
     "load_pem_private_key(pem) -> pkey_ptr"},
    {"free_pkey", py_free_pkey, METH_VARARGS, "释放 EVP_PKEY"},
    {"ecdsa_sign", py_ecdsa_sign, METH_VARARGS,
     "ecdsa_sign(priv_pkey, message) -> DER signature"},
    {"pkey_get_public_der", py_pkey_get_public_der, METH_VARARGS,
     "pkey_get_public_der(priv_pkey) -> SPKI DER"},
    {"extract_ec_private_value", py_extract_ec_private_value, METH_VARARGS,
     "extract_ec_private_value(der) -> int (private scalar)"},
    {"get_version", py_get_version, METH_NOARGS, "libcrypto 版本字符串"},
    {"get_libcrypto_path", py_get_libcrypto_path, METH_NOARGS, "libcrypto 路径"},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef MODULE_DEF = {
    PyModuleDef_HEAD_INIT, "_native_core",
    "huaweicloud-encryption-sdk native C extension (1 FFI/operation, abi3)",
    -1, METHODS, NULL, NULL, NULL, NULL,
};

PyMODINIT_FUNC PyInit__native_core(void) {
    if (load_libcrypto() < 0) {
        PyErr_Format(PyExc_ImportError,
                     "_native_core: failed to load libcrypto: %s", g_last_err);
        return NULL;
    }
    PyObject *m = PyModule_Create(&MODULE_DEF);
    if (!m) return NULL;
    InvalidTagError = PyErr_NewException(
        "huaweicloud_encryptionsdk._openssl._native_core.InvalidTagError",
        NULL, NULL);
    if (!InvalidTagError || PyModule_AddObject(m, "InvalidTagError",
                                               InvalidTagError) < 0) {
        Py_XDECREF(InvalidTagError);
        Py_DECREF(m);
        return NULL;
    }
    return m;
}
