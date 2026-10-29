# _openssl 迁移测试方案

本文档描述将 `gmssl + cryptography` 替换为华为 OpenSSL ctypes 封装 (`_openssl` 模块) 后,
对所有改动代码的测试方案.

## 一、改动文件清单

| # | 文件 | 改动点 |
|---|------|--------|
| 1 | `huaweicloud_encryptionsdk/_openssl/` (新建) | ctypes 封装 libcrypto, 提供 SM3/SHA256/AES-GCM/SM4-GCM/SM4-CBC |
| 2 | `common/crypto_factory.py` | `get_message_digest("SM3")` 改用 `_openssl.Digest`; 删除 `SM3Digest` 类 |
| 3 | `handler/cipher_handler.py` | 三种算法分支改用 `_openssl` 函数; 删除 `cryptography` 导入和 `_create_cipher` |
| 4 | `keyrings/rawkeyring/raw_aes_keyring.py` | `real_encrypt/real_decrypt` 改用 `aes_gcm_encrypt/decrypt` |
| 5 | `keyrings/rawkeyring/raw_sm4_keyring.py` | `real_encrypt/real_decrypt` 改用 `sm4_gcm_encrypt/decrypt` |
| 6 | `keyrings/rawkeyring/raw_sm4_cbc_keyring.py` | `real_encrypt/real_decrypt` 改用 `sm4_cbc_encrypt/decrypt`; 移除手动 PKCS7 |

## 二、测试文件清单

| 文件 | 覆盖范围 |
|------|----------|
| `test_openssl_module.py` (已存在) | `_openssl` 模块底层 API (库加载, SM3, SHA256, AES-GCM, SM4-GCM, SM4-CBC) |
| `tests/test_openssl_crypto_factory.py` | `crypto_factory.py` 改动: SM3 摘要, 非 SM 走 hashlib, `is_sm_algorithm` |
| `tests/test_openssl_cipher_handler.py` | `cipher_handler.py` 改动: 三种算法的 `cipher_data`/`cipher_header_data`/`process_encrypt_byte`/`process_decrypt_byte` |
| `tests/test_openssl_keyrings.py` | 三个 keyring 的 `real_encrypt`/`real_decrypt`, 含错误 key/AAD 不匹配/多 key |
| `tests/test_openssl_integration.py` | 端到端: `HuaweiCrypto` 的 bytes/stream/file 加解密, 三种算法, 多 master key |

## 三、测试矩阵

### 3.1 crypto_factory.py
| 测试 | 说明 |
|------|------|
| `test_sm3_known_vector` | SM3("abc") 标准向量 |
| `test_sm3_empty` | 空串 |
| `test_sm3_multiple_update` | 分次 update 一致性 |
| `test_sm3_digest_bytes` | digest() 返回 32 字节 |
| `test_sm3_large_data` | 1MB 数据稳定性 |
| `test_sha256_uses_hashlib` | SHA-256 仍走 hashlib |
| `test_sha1_uses_hashlib` | SHA-1 仍走 hashlib |
| `test_md5_uses_hashlib` | MD5 仍走 hashlib |
| `test_sm3_detected` / `test_aes_not_sm` | `is_sm_algorithm` 判断 |

### 3.2 cipher_handler.py
| 测试 | 说明 |
|------|------|
| `TestSm4CbcCipherData` | SM4-CBC `cipher_data` 往返, block 对齐, 空明文, 不同 IV |
| `TestSm4CbcCipherHeaderData` | SM4-CBC `cipher_header_data` 往返, length=0 分支 |
| `TestSm4GcmCipherData` | SM4-GCM `cipher_data` 往返, AAD 完整性, tag 篡改 |
| `TestSm4GcmCipherHeaderData` | SM4-GCM `cipher_header_data` 往返, length=0 |
| `TestAesGcmCipherData` | AES-128/256-GCM `cipher_data` 往返, AAD 不匹配 |
| `TestAesGcmCipherHeaderData` | AES-GCM `cipher_header_data` 往返 |
| `TestProcessByte` | 四种算法 `process_encrypt_byte` 不报错 |
| `TestIvManagement` | IV 生成/reset/set/长度 |

### 3.3 keyrings
| 测试 | 说明 |
|------|------|
| `TestRawAesKeyring.test_roundtrip` | AES-128/256-GCM 数据密钥往返 |
| `TestRawAesKeyring.test_wrong_master_key_returns_false` | 错误 key 返回 False |
| `TestRawAesKeyring.test_aad_mismatch_returns_false` | AAD 不匹配返回 False |
| `TestRawAesKeyring.test_multiple_master_keys` | 多 master key |
| `TestRawSm4Keyring.*` | SM4-GCM 同上 |
| `TestRawSm4CbcKeyring.test_roundtrip` | SM4-CBC 数据密钥往返 |
| `TestRawSm4CbcKeyring.test_roundtrip_non_block_aligned` | 非 block 对齐 (PKCS7) |
| `TestRawSm4CbcKeyring.test_wrong_key_returns_false` | 错误 key 不抛未捕获异常 |
| `TestRawSm4CbcKeyring.test_ciphertext_includes_iv_prefix` | 密文格式 IV(16)+ct |
| `TestKeyringConsistency` | 走 `encrypt_data_key`/`decrypt_data_key` 完整流程 |

### 3.4 集成测试 (HuaweiCrypto 端到端)
| 测试 | 说明 |
|------|------|
| `TestBytesRoundtrip.test_encrypt_decrypt_bytes` | 四种算法 bytes 往返 |
| `TestBytesRoundtrip.test_bytes_with_context` | encryption_context 透传 |
| `TestBytesRoundtrip.test_bytes_empty` | 空明文 |
| `TestBytesRoundtrip.test_bytes_large_1mb` | 1MB 大数据 |
| `TestStreamRoundtrip.test_encrypt_decrypt_stream` | 三种算法 stream 往返 |
| `TestStreamRoundtrip.test_stream_with_context` | stream + context |
| `TestFileRoundtrip.test_encrypt_decrypt_file` | 三种算法 file 往返 (tmp_path) |
| `TestFileRoundtrip.test_file_large` | 512KB 文件 |
| `TestMultiMasterKey` | 多 master key 解密 |
| `TestAlgorithmSwitching` | 不同算法产生不同密文 |
| `TestHeaderIntegrity` | 篡改密文应失败 |

## 四、运行方式

### 4.1 部署到服务器

```bash
# 在本地仓库 python/ 目录
bash scripts/deploy_openssl_changes.sh --dry-run   # 预览
bash scripts/deploy_openssl_changes.sh              # 实际部署
```

### 4.2 运行测试

```bash
# 进入 site-packages 上级目录 (测试文件已部署到此)
cd $(python3 -c "import huaweicloud_encryptionsdk, os; print(os.path.dirname(os.path.dirname(huaweicloud_encryptionsdk.__file__)))")

# 1. 底层 _openssl 模块验证
python -m pytest test_openssl_module.py -v

# 2. crypto_factory 测试
python -m pytest test_openssl_crypto_factory.py -v

# 3. cipher_handler 测试
python -m pytest test_openssl_cipher_handler.py -v

# 4. keyrings 测试
python -m pytest test_openssl_keyrings.py -v

# 5. 集成测试
python -m pytest test_openssl_integration.py -v

# 全部运行
python -m pytest test_openssl_module.py test_openssl_crypto_factory.py test_openssl_cipher_handler.py test_openssl_keyrings.py test_openssl_integration.py -v
```

### 4.3 环境变量

```bash
# 如果华为 OpenSSL 不在默认路径 /opt/huawei-openssl/lib/
export HUAWEI_OPENSSL_LIB=/path/to/libcrypto.so
```

## 五、预期结果

所有测试应全部 PASS. 关键验证点:

1. **OpenSSL 版本**: `3.5.4` (华为版本)
2. **SM3 标准向量**: `SM3("abc") == 66c7f0f4...`
3. **AES-GCM/SM4-GCM**: AAD 不匹配或 tag 篡改应解密失败
4. **SM4-CBC**: PKCS7 padding 由 OpenSSL 自动处理, 非 block 对齐明文可正确往返
5. **错误 master key**: `real_decrypt` 返回 `False`, 不抛未捕获异常
6. **端到端**: bytes/stream/file 三种 I/O 模式, 四种算法均可往返还原原文

## 六、回归对照

迁移前 (gmssl + cryptography) 与迁移后 (_openssl) 应满足:
- 相同明文 + 相同 key + 相同 IV → 相同密文 (确定性)
- 迁移前加密的密文, 迁移后能解密 (向后兼容) — 注意: 因 IV 随机, 实际通过往返测试保证
- SM3 摘要值与标准向量一致 (实现正确性)
