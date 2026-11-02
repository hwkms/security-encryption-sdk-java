# HuaweiCloud Encryption SDK Python 开发指南（密钥胶囊）

## 1. 环境要求

- Python >= 3.11（离线 whl 包为 cp311 构建）
- 操作系统：Linux（x86_64 / ARM64）

> **注意**：`cryptography` 和 `cffi` 的 whl 文件与 Python 版本绑定（cp311），因此要求 Python 3.11。如使用其他 Python 版本，需自行编译或下载对应版本的 whl。

## 2. 安装

### 2.1 安装依赖

**在线环境**（推荐）：

```bash
pip install cryptography gmssl huaweicloudsdkkms huaweicloudsdkcore requests cachetools
```

如需 LTS 日志上报功能，额外安装：

```bash
pip install loguru six
```

**离线环境**：

SDK 提供 `wheels_x86/` 目录，包含所有依赖的 whl 文件，用于无法访问 PyPI 的内网环境。将目录上传到服务器后执行：

```bash
pip install --no-index --find-links=file:///absolute/path/to/wheels_x86/ \
    cryptography gmssl huaweicloudsdkkms huaweicloudsdkcore requests cachetools \
    cffi pycparser certifi charset_normalizer idna urllib3 \
    typing_extensions pyasn1 pycryptodomex defusedxml dnspython pymongo pyyaml requests_toolbelt simplejson
```

LTS 日志上报额外安装：

```bash
pip install --no-index --find-links=file:///absolute/path/to/wheels_x86/ loguru six
```

> **注意**：`--find-links` 使用绝对路径时，需要加 `file://` 前缀（如 `file:///home/py/wheels_x86/`），否则 pip 可能忽略该路径。

### 2.2 安装 SDK

方式一：通过 PYTHONPATH 引用（推荐，开发调试阶段）

```bash
export PYTHONPATH=/path/to/EncryptionSDK_python
```

方式二：构建 wheel 包安装（推荐，正式部署）

```bash
# 构建
pip install build
python -m build

# 安装（离线环境将 whl 文件拷贝到目标机器）
pip install dist/huaweicloud_encryption_sdk_python-1.1.0-py3-none-any.whl
```

### 2.3 验证安装

```bash
python3 -c "from huaweicloud_encryptionsdk import HuaweiCrypto; print('OK')"
```

### 2.4 依赖清单

| 包名 | 版本要求 | 用途 |
|------|---------|------|
| cryptography | >=42.0.0 | AES/SM4-GCM 加解密 |
| gmssl | >=3.2.2 | SM4-CBC/SM2/SM3 国密算法 |
| huaweicloudsdkkms | >=3.1.190 | 华为云 KMS 服务 SDK |
| huaweicloudsdkcore | >=3.1.190 | 华为云 SDK 核心库 |
| requests | >=2.31.0 | HTTP 请求 |
| cachetools | >=5.3.0 | 缓存管理 |

LTS 日志上报依赖（可选）：

| 包名 | 版本 | 用途 |
|------|------|------|
| loguru | 0.7.3 | LTS SDK 日志 |
| six | 1.17.0 | Python 2/3 兼容 |

## 3. 快速开始

### 3.1 密钥胶囊加密

```python
import os
from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.keyrings.kms_keyring_factory import KmsKeyringFactory
from huaweicloud_encryptionsdk.model.access_point_config import AccessPointConfig
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig
from huaweicloud_encryptionsdk.model.key_capsule_config import KeyCapsuleConfig
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest

# 1. 鉴权信息（建议从环境变量获取）
ak = os.environ.get("CLOUD_SDK_AK")
sk = os.environ.get("CLOUD_SDK_SK")

# 2. KMS 配置
kms_config_list = [KMSConfig(
    region="cn-north-7",
    key_id="your_key_id",
    project_id="your_project_id",
    end_point="https://kms.cn-north-7.myhuaweicloud.com",
)]

# 3. 接入点配置
access_point_config = AccessPointConfig(
    type=2,  # 1:ECS, 2:Custom, 3:CCE
    encrypted_private_key="your_encrypted_private_key",
    private_key_decrypt_callback=lambda encrypted_key: "your_plain_private_key",
)

# 4. 密钥胶囊配置
key_capsule_config = KeyCapsuleConfig(
    region="cn-north-7",
    default_policy_id="your_policy_id",
    default_key_policy=None,
    access_point_config=access_point_config,
)

# 5. 构建加密配置
config = HuaweiConfig(
    ak=ak,
    sk=sk,
    crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING,
    kms_config_list=kms_config_list,
    key_capsule_config=key_capsule_config,
)

# 6. 创建密钥胶囊密钥环并初始化 SDK
keyring = KmsKeyringFactory().get_keyring(KeyringTypeEnum.KMS_KEY_CAPSULE.type)
crypto = HuaweiCrypto(config).with_keyring(keyring)

# 7. 加密
encrypt_request = EncryptRequest(plain_text=b"Hello, Key Capsule!")
result = crypto.encrypt(encrypt_request)

# 8. 构建解密配置（解密无需 kms_config_list）
decrypt_config = HuaweiConfig(
    ak=ak,
    sk=sk,
    key_capsule_config=key_capsule_config,
)
decrypt_keyring = KmsKeyringFactory().get_keyring(KeyringTypeEnum.KMS_KEY_CAPSULE.type)
decrypt_crypto = HuaweiCrypto(decrypt_config).with_keyring(decrypt_keyring)

# 9. 解密
decrypt_result = decrypt_crypto.decrypt(result.result)
print(decrypt_result.result.decode("utf-8"))
```

### 3.2 通过配置文件运行（测试 Demo）

SDK 提供了基于配置文件的测试示例，可用于快速验证加解密功能：

```bash
python3 examples/key_capsule_encryption_example.py examples/config.properties
```

配置文件参考 `examples/config.properties`。

> **说明**：此方式仅为测试验证用途，实际开发请参考 3.1 的代码示例集成到业务代码中。

## 4. 配置说明

### 4.1 KMSConfig（KMS 配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| region | str | 是 | KMS 区域，如 `cn-north-7` |
| key_id | str | 是 | KMS 对称主密钥 ID |
| project_id | str | 是 | 项目 ID |
| end_point | str | 是 | KMS 端点，如 `https://kms.cn-north-7.myhuaweicloud.com` |

支持多个 region，加密时按顺序选择：

```python
kms_config_list = [
    KMSConfig(region="cn-north-7", key_id="key_id_1", project_id="project_id_1", end_point="https://kms.cn-north-7.myhuaweicloud.com"),
    KMSConfig(region="cn-south-1", key_id="key_id_2", project_id="project_id_2", end_point="https://kms.cn-south-1.myhuaweicloud.com"),
]
```

> **重要**：`KeyCapsuleConfig.region` 必须是 `kms_config_list` 中已配置的 region。`KMSConfig` 支持配置多个 region，但 `KeyCapsuleConfig` 只能配置一个 region，且该 region 必须在 `kms_config_list` 中存在。

### 4.2 AccessPointConfig（接入点配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| type | int | 是 | 接入点类型：1=ECS，2=Custom（通用），3=CCE |
| encrypted_private_key | str | 是 | 加密的私钥（Base64 编码） |
| private_key_decrypt_callback | Callable[[str], str] | 是 | 私钥解密回调，接收加密私钥，返回 Base64 格式的明文私钥 |
| service_account | str | 否 | CCE 场景的 ServiceAccount 名称（已废弃，SDK 自动从 `/var/run/secrets/kubernetes.io/serviceaccount/token` 读取 service token） |

### 4.3 KeyCapsuleConfig（密钥胶囊配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| region | str | 是 | 创建/解密密钥胶囊的 region |
| default_policy_id | str | 否 | 默认策略 ID（EncryptRequest 未指定策略时使用） |
| default_key_policy | str | 否 | 默认内联策略 JSON（优先级低于 defaultPolicyId） |
| access_point_config | AccessPointConfig | 是 | 接入点配置 |

### 4.4 HuaweiConfig（全局配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| ak | str | 是 | 华为云 Access Key |
| sk | str | 是 | 华为云 Secret Key |
| crypto_algorithm | CryptoAlgorithm | 加密必填 | 加密算法（解密时自动从密文头解析） |
| kms_config_list | list[KMSConfig] | 加密必填 | KMS 配置列表（解密时无需传入） |
| key_capsule_config | KeyCapsuleConfig | 是 | 密钥胶囊配置 |
| log_config | LogConfig | 否 | LTS 日志上报配置 |
| local_log_only | bool | 否 | 是否仅本地打印日志（不上报 LTS），默认 False |

### 4.5 EncryptRequest（加密请求）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| plain_text | bytes | 是 | 待加密的明文 |
| policy_id | str | 否 | 本次加密使用的策略 ID（覆盖 default_policy_id） |
| key_policy | str | 否 | 本次加密使用的内联策略 JSON（覆盖 default_key_policy） |

## 5. 支持的加密算法

| 枚举值 | 说明 |
|-------|------|
| `CryptoAlgorithm.AES_128_GCM_NOPADDING` | AES-128-GCM |
| `CryptoAlgorithm.AES_256_GCM_NOPADDING` | AES-256-GCM |
| `CryptoAlgorithm.SM4_128_GCM_NOPADDING` | SM4-128-GCM |
| `CryptoAlgorithm.SM4_128_CBC_PADDING` | SM4-128-CBC-PKCS7 |

## 6. LTS 日志上报（可选）

### 6.1 启用日志上报

```python
from huaweicloud_encryptionsdk.log.log_config import LogConfig

log_config = LogConfig(
    log_group_name="DSC",
    log_stream_name="crypto_operation_log",
    region="cn-north-7",
    project_id="your_project_id",
    lts_endpoint="https://lts-access.cn-north-7.myhuaweicloud.com",
    batch_count_threshold=1000,
    linger_ms=30000,
    batch_size_threshold_in_bytes=524288,
    io_thread_count=4,
    total_size_in_bytes=104857600,
    max_block_ms=0,
    retries=5,
    base_retry_backoff_ms=100,
    max_retry_backoff_ms=500,
    backup_dir="/home/logbackup",
    enable_recovery_on_startup=True,
    recovery_batch_size=1000,
    recovery_batch_interval=1000,
)

config = HuaweiConfig(
    ak=ak, sk=sk,
    crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING,
    kms_config_list=kms_config_list,
    key_capsule_config=key_capsule_config,
    log_config=log_config,
)
```

### 6.2 仅本地打印日志（不上报 LTS）

```python
config = HuaweiConfig(
    ak=ak, sk=sk,
    crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING,
    kms_config_list=kms_config_list,
    key_capsule_config=key_capsule_config,
    local_log_only=True,
)
```

### 6.3 LogConfig 配置说明

| 字段 | 默认值 | 说明 |
|------|-------|------|
| log_group_id | `""` | 日志组 UUID（为空则根据 log_group_name 自动解析） |
| log_stream_id | `""` | 日志流 UUID（为空则根据 log_stream_name 自动解析） |
| log_group_name | `DSC` | 日志组名称 |
| log_stream_name | `crypto_operation_log` | 日志流名称 |
| region | - | LTS 服务区域（必填） |
| project_id | - | 项目 ID（必填） |
| lts_endpoint | - | LTS 服务端点，如 `https://lts-access.{region}.myhuaweicloud.com` |
| batch_count_threshold | 1000 | 缓冲区记录条数阈值 |
| linger_ms | 30000 | 异步上报间隔（毫秒） |
| batch_size_threshold_in_bytes | 524288 | 批量大小阈值（字节） |
| io_thread_count | CPU 核数 | IO 线程数 |
| total_size_in_bytes | 104857600 | 缓冲区大小上限（100MB） |
| max_block_ms | 0 | 发送阻塞时间（毫秒），0=不阻塞 |
| retries | 5 | 重试次数 |
| base_retry_backoff_ms | 100 | 首次重试退避时间（毫秒） |
| max_retry_backoff_ms | 500 | 最大重试退避时间（毫秒） |
| backup_dir | `~/lts_log_backup` | 失败日志备份目录 |
| enable_recovery_on_startup | True | 启动时恢复失败日志 |
| recovery_batch_size | 1000 | 恢复批量大小 |
| recovery_batch_interval | 1000 | 恢复批次间隔（毫秒） |

### 6.4 注意事项

- 不使用 LTS 日志上报时，无需安装 `loguru` 和 `six`
- LTS SDK 内部线程为非守护线程，程序退出时需调用 `LogReporterManager.get_instance().shutdown()` 后使用 `os._exit(0)` 退出

## 7. 缓存（可选）

```python
from huaweicloud_encryptionsdk.cache.local_data_key_cache import LocalDataKeyCache
from huaweicloud_encryptionsdk.meterialmanager.cache_crypto_meterial_manager import CacheCryptoMaterialsManager

local_data_key_cache = LocalDataKeyCache()
local_data_key_cache.set_capacity(10)

cache_manager = CacheCryptoMaterialsManager(local_data_key_cache, config)
cache_manager.set_max_byte_limit(3000)
cache_manager.set_max_message_limit(1000)
cache_manager.set_survival_time(5000)

crypto.with_crypto_material_manager(cache_manager)
```

| 配置项 | 默认值 | 说明 |
|-------|-------|------|
| capacity | - | 最大缓存容量，超出按 LRU 淘汰 |
| max_byte_limit | - | 单个数据密钥加密 byte 最大数量 |
| max_message_limit | - | 单个数据密钥加密数据条数最大限制 |
| survival_time | - | 缓存存活时间（毫秒） |

## 8. 跨语言兼容性

Python SDK 的二进制序列化格式与 Java SDK 完全兼容，支持：
- Java 加密 → Python 解密
- Python 加密 → Java 解密

密文为二进制格式，跨语言传递时可使用 HEX 编码。

## 9. 安全建议

- AK/SK 不应硬编码在代码中，建议从环境变量或密钥管理服务获取
- `private_key_decrypt_callback` 中应实现安全的私钥解密逻辑，避免明文存储私钥

## 10. 项目结构

```
EncryptionSDK_python/
├── src/huaweicloud_encryptionsdk/
│   ├── huawei_crypto.py              # 主入口
│   ├── huawei_config.py              # 全局配置
│   ├── keyrings/                     # 密钥环实现
│   │   ├── kms_keyring_factory.py    # KMS 密钥环工厂
│   │   └── rawkeyring/               # 本地密钥环
│   ├── model/                        # 数据模型
│   │   ├── key_capsule_config.py     # 密钥胶囊配置
│   │   ├── access_point_config.py    # 接入点配置
│   │   ├── kms_config.py             # KMS 配置
│   │   └── enums/                    # 枚举（算法/密钥环类型）
│   ├── handler/                      # 加解密处理器
│   ├── cache/                        # 缓存实现
│   ├── log/                          # LTS 日志上报
│   ├── proof/                        # 证明机制（ECS/CCE/KeyPair）
│   ├── meterialmanager/              # 材料管理器（含缓存）
│   ├── kms/                          # KMS HTTP 客户端
│   ├── common/                       # 通用工具
│   ├── _apig_sdk/                    # API Gateway 签名
│   └── _lts_sdk/                     # LTS SDK（官方源码，勿修改）
├── examples/                         # 示例程序
├── wheels_x86/                       # x86 离线依赖包
└── pyproject.toml                    # 项目配置
```
