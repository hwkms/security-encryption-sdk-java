import base64
import logging
import os
import sys

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.cache.local_data_key_cache import LocalDataKeyCache
from huaweicloud_encryptionsdk.keyrings.kms_keyring_factory import KmsKeyringFactory
from huaweicloud_encryptionsdk.log.log_config import LogConfig
from huaweicloud_encryptionsdk.meterialmanager.cache_crypto_meterial_manager import CacheCryptoMaterialsManager
from huaweicloud_encryptionsdk.model.access_point_config import AccessPointConfig
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig
from huaweicloud_encryptionsdk.model.key_capsule_config import KeyCapsuleConfig
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest
from huaweicloud_encryptionsdk.common import utils as _utils

logger = logging.getLogger(__name__)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def load_properties(filepath: str) -> dict:
    props = {}
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sep = line.find("=")
            if sep > 0:
                key = line[:sep].strip()
                value = line[sep + 1:].strip()
                props[key] = value
    return props


def main():
    if len(sys.argv) < 2:
        print("Usage: python key_capsule_encryption_example.py <config.properties>")
        sys.exit(1)

    props = load_properties(sys.argv[1])

    ak = props.get("ak")
    sk = props.get("sk")

    kms_config_list = [KMSConfig(
        region=props.get("kms.region"),
        key_id=props.get("kms.keyId"),
        project_id=props.get("kms.projectId"),
        end_point=props.get("kms.endpoint"),
    )]

    access_point_config = AccessPointConfig(
        type=int(props.get("keyCapsule.accessPointType", "2")),
        encrypted_private_key=props.get("keyCapsule.encryptedPrivateKey"),
        private_key_decrypt_callback=lambda encrypted_key: props.get("keyCapsule.plainPrivateKey"),
    )

    key_capsule_config = KeyCapsuleConfig(
        region=props.get("keyCapsule.region"),
        default_policy_id=props.get("keyCapsule.defaultPolicyId"),
        default_key_policy=props.get("keyCapsule.defaultKeyPolicy"),
        access_point_config=access_point_config,
    )

    log_enabled = props.get("log.enabled", "false").lower() == "true"
    log_config = None
    if log_enabled:
        log_config = LogConfig(
            log_group_id=props.get("log.groupId"),
            log_stream_id=props.get("log.streamId"),
            log_group_name=props.get("log.groupName", "DSC"),
            log_stream_name=props.get("log.streamName", "crypto_operation_log"),
            region=props.get("log.region"),
            lts_endpoint=props.get("log.ltsEndpoint"),
            project_id=props.get("log.projectId"),
            batch_count_threshold=int(props.get("log.batchCountThreshold", "1000")),
            linger_ms=int(props.get("log.lingerMs", "30000")),
            batch_size_threshold_in_bytes=int(props.get("log.batchSizeThresholdInBytes", "524288")),
            io_thread_count=int(props.get("log.ioThreadCount", "4")),
            total_size_in_bytes=int(props.get("log.totalSizeInBytes", "104857600")),
            max_block_ms=int(props.get("log.maxBlockMs", "0")),
            retries=int(props.get("log.retries", "5")),
            base_retry_backoff_ms=int(props.get("log.baseRetryBackoffMs", "100")),
            max_retry_backoff_ms=int(props.get("log.maxRetryBackoffMs", "500")),
            backup_dir=props.get("log.backupDir", "/home/logbackup"),
            enable_recovery_on_startup=props.get("log.enableRecoveryOnStartup", "true").lower() == "true",
            recovery_batch_size=int(props.get("log.recoveryBatchSize", "1000")),
            recovery_batch_interval=int(props.get("log.recoveryBatchInterval", "1000")),
        )

    config = HuaweiConfig(
        ak=ak,
        sk=sk,
        crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING,
        kms_config_list=kms_config_list,
        key_capsule_config=key_capsule_config,
        log_config=log_config,
    )

    keyring = KmsKeyringFactory().get_keyring(KeyringTypeEnum.KMS_KEY_CAPSULE.type)
    crypto = HuaweiCrypto(config).with_keyring(keyring)

    decrypt_config = HuaweiConfig(
        ak=ak,
        sk=sk,
        key_capsule_config=key_capsule_config,
        log_config=log_config,
    )
    decrypt_keyring = KmsKeyringFactory().get_keyring(KeyringTypeEnum.KMS_KEY_CAPSULE.type)
    decrypt_crypto = HuaweiCrypto(decrypt_config).with_keyring(decrypt_keyring)

    cache_enabled = props.get("cache.enabled", "false").lower() == "true"
    if cache_enabled:
        local_data_key_cache = LocalDataKeyCache()
        local_data_key_cache.set_capacity(int(props.get("cache.capacity", "10")))
        cache_manager = CacheCryptoMaterialsManager(local_data_key_cache, config)
        cache_manager.set_max_byte_limit(int(props.get("cache.maxByteLimit", "3000")))
        cache_manager.set_max_message_limit(int(props.get("cache.maxMessageLimit", "1000")))
        cache_manager.set_survival_time(int(props.get("cache.survivalTime", "5000")))
        crypto.with_crypto_material_manager(cache_manager)
        decrypt_cache_manager = CacheCryptoMaterialsManager(local_data_key_cache, decrypt_config)
        decrypt_cache_manager.set_max_byte_limit(int(props.get("cache.maxByteLimit", "3000")))
        decrypt_cache_manager.set_max_message_limit(int(props.get("cache.maxMessageLimit", "1000")))
        decrypt_cache_manager.set_survival_time(int(props.get("cache.survivalTime", "5000")))
        decrypt_crypto.with_crypto_material_manager(decrypt_cache_manager)

    test_file_enabled = props.get("test.file.enabled", "false").lower() == "true"
    cross_lang_enabled = props.get("test.crossLang.enabled", "false").lower() == "true"

    if cross_lang_enabled:
        cross_lang_mode = props.get("test.crossLang.mode", "decrypt").lower()
        if cross_lang_mode == "decrypt":
            cipher_hex = props.get("test.crossLang.cipherHex", "")
            if not cipher_hex:
                logger.error("test.crossLang.cipherHex 未配置")
                crypto.close()
                decrypt_crypto.close()
                os._exit(1)
            cipher_data = bytes.fromhex(cipher_hex)
            decrypt_result = decrypt_crypto.decrypt(cipher_data)
            logger.info("跨语言解密成功: %s", decrypt_result.result.decode("utf-8"))
            print("Cross-language decrypt passed! Plain text:", decrypt_result.result.decode("utf-8"))
        elif cross_lang_mode == "encrypt":
            plain_text = props.get("test.plainText", "Hello, Key Capsule!")
            encrypt_request = EncryptRequest(plain_text=plain_text.encode("utf-8"))
            custom_policy_id = props.get("test.encrypt.policyId")
            custom_key_policy = props.get("test.encrypt.keyPolicy")
            if custom_policy_id:
                encrypt_request.policy_id = custom_policy_id
            if custom_key_policy:
                encrypt_request.key_policy = custom_key_policy
            result = crypto.encrypt(encrypt_request)
            cipher_hex = bytes_to_hex(result.result)
            logger.info("跨语言加密成功, 密文HEX: %s", cipher_hex)

            cipher_file_path = props.get("test.crossLang.cipherFile", "")
            if cipher_file_path:
                with open(cipher_file_path, "wb") as f:
                    f.write(result.result)
                logger.info("密文已写入文件: %s", cipher_file_path)
            else:
                print("cipherHex=" + cipher_hex)
            print("Cross-language encrypt passed!")
        elif cross_lang_mode == "decryptFile":
            cipher_file_path = props.get("test.crossLang.cipherFile", "")
            if not cipher_file_path:
                logger.error("test.crossLang.cipherFile 未配置")
                crypto.close()
                decrypt_crypto.close()
                os._exit(1)
            with open(cipher_file_path, "rb") as f:
                cipher_data = f.read()
            decrypt_result = decrypt_crypto.decrypt(cipher_data)
            logger.info("跨语言文件解密成功: %s", decrypt_result.result.decode("utf-8"))
            print("Cross-language decrypt file passed! Plain text:", decrypt_result.result.decode("utf-8"))
        else:
            logger.error("不支持的 test.crossLang.mode: %s (支持: decrypt/encrypt/decryptFile)", cross_lang_mode)
            crypto.close()
            decrypt_crypto.close()
            os._exit(1)
    elif test_file_enabled:
        origin_file_path = props.get("test.file.path.origin")
        encrypt_file_path = props.get("test.file.path.encrypt")
        decrypt_file_path = props.get("test.file.path.decrypt")
        crypto.encrypt_file(origin_file_path, encrypt_file_path, None)
        logger.info("加密成功，源文件：%s，加密后文件：%s", origin_file_path, encrypt_file_path)
        crypto.decrypt_file(encrypt_file_path, decrypt_file_path)
        logger.info("解密成功：源文件：%s，解密后文件：%s", encrypt_file_path, decrypt_file_path)
    else:
        encrypt_request = EncryptRequest()
        custom_policy_id = props.get("test.encrypt.policyId")
        custom_key_policy = props.get("test.encrypt.keyPolicy")
        if custom_policy_id:
            encrypt_request.policy_id = custom_policy_id
        if custom_key_policy:
            encrypt_request.key_policy = custom_key_policy

        plain_text = props.get("test.plainText", "Hello, Key Capsule!")
        encrypt_request.plain_text = plain_text.encode("utf-8")
        logger.info("原文: %s, HEX: %s", plain_text, bytes_to_hex(plain_text.encode("utf-8")))

        # 第一次加密：创建密钥胶囊，生成数据密钥
        result = crypto.encrypt(encrypt_request)
        logger.info("第1次加密成功，密文HEX: %s", bytes_to_hex(result.result))

        # 第二次加密：相同策略，命中加密缓存，复用数据密钥
        plain_text2 = "xxxxxxxxxxxxxxxxxxxxxxxxxxssssssssssssss"
        encrypt_request.plain_text = plain_text2.encode("utf-8")
        result2 = crypto.encrypt(encrypt_request)
        logger.info("第2次加密成功（命中加密缓存），密文HEX: %s", bytes_to_hex(result2.result))

        # encHex1 = "0200020000010a6875617765692d6b6d737b012463633035383832662d366532362d346235372d613435302d6463353032306163663466340a636e2d6e6f7274682d372064346535353962343962336234303364613532373937323332393965643461362868747470733a2f2f6b6d732e636e2d6e6f7274682d372e6d79687561776569636c6f75642e636f6d01520101240030313965663362382d623235302d373030302d626334612d303761636162646136346232023d0082a8706f6c6963794964d92430313965663362662d343238332d373030302d623832342d356461666361326362306337a776657273696f6ea476312e30039c00050064006b98fe4b2aced0f515d0d49ce68a2cdd35d4da2f07072d05108dc5ad99570a6c635231abfef85cc9e82f082ed4a0b4e1bece2c25fedf2ec95430dc0763633035383832662d366532362d346235372d613435302d6463353032306163663466340000000014131211100f0e0d0c0b0a0908070605040302013c6dfd5c78023edf345ab0c6e5f60e0806e44ba6cb943733aa0f1e4d73718413044800304602210094322b0eeddc0c04f5744b7668f83e2492b3c5e8f611a5059ba5521aeb942dd90221009b9cf773b896a6dbee3fe52e523437f3f45ccef7cb1b407d4511b0d31352231d010c000002d40000002463633035383832662d366532362d346235372d613435302d646335303230616366346634000002a43031303132343030333033313339363536363333363233383264363233323335333032643337333033303330326436323633333436313264333033373631363336313632363436313336333436323332303233643030383261383730366636633639363337393439363464393234333033313339363536363333363236363264333433323338333332643337333033303330326436323338333233343264333536343631363636333631333236333632333036333337613737363635373237333639366636656134373633313265333030333963303030353030363430303662393866653462326163656430663531356430643439636536386132636464333564346461326630373037326430353130386463356164393935373061366336333532333161626665663835636339653832663038326564346130623465316265636532633235666564663265633935343330646330373633363333303335333833383332363632643336363533323336326433343632333533373264363133343335333032643634363333353330333233303631363336363334363633343030303030303030313431333132313131303066306530643063306230613039303830373036303530343033303230313363366466643563373830323365646633343561623063366535663630653038303665343462613663623934333733336161306631653464373337313834313330343438303033303436303232313030393433323262306565646463306330346635373434623736363866383365323439326233633565386636313161353035396261353532316165623934326464393032323130303962396366373733623839366136646265653366653532653532333433376633663435636365663763623162343037643435313162306433313335323233316400000001001ca65bef18a898010f701c7df2ab96ef7863d4c58c56086c19aaf48cd2240ed6b618f19470f42bccc90000000000000013a9bb136da90ef53d47207bb28a79619036b6e53483934fe0a3145687a048fba23db06a"
        # encHex2 = "0200020000010a6875617765692d6b6d737b012463633035383832662d366532362d346235372d613435302d6463353032306163663466340a636e2d6e6f7274682d372064346535353962343962336234303364613532373937323332393965643461362868747470733a2f2f6b6d732e636e2d6e6f7274682d372e6d79687561776569636c6f75642e636f6d01510101240030313965663362382d623235302d373030302d626334612d303761636162646136346232023d0082a8706f6c6963794964d92430313965663362662d343238332d373030302d623832342d356461666361326362306337a776657273696f6ea476312e30039c0005006400ab449c495f299a35b8e01dff7444364d038afbd721eeba85faaf103f3bce848bc430e9d45dc9e9ab2fd1ee5287216e5f1552a2168c1894f94ddabeaf63633035383832662d366532362d346235372d613435302d6463353032306163663466340000000014131211100f0e0d0c0b0a0908070605040302017364ec6d796b69f52a79674f21d71ba9a5613594e0a8434205581372e55885f504470030450220765e71084e3768faabf363698a92b0be4c7f58c6d706ab86267870139f313ee0022100d5d93f83fdfe701b9286875c043d8820c319da8b085820dec42f511e09a0669d010c000002d20000002463633035383832662d366532362d346235372d613435302d646335303230616366346634000002a2303130313234303033303331333936353636333336323338326436323332333533303264333733303330333032643632363333343631326433303337363136333631363236343631333633343632333230323364303038326138373036663663363936333739343936346439323433303331333936353636333336323636326433343332333833333264333733303330333032643632333833323334326433353634363136363633363133323633363233303633333761373736363537323733363936663665613437363331326533303033396330303035303036343030616234343963343935663239396133356238653031646666373434343336346430333861666264373231656562613835666161663130336633626365383438626334333065396434356463396539616232666431656535323837323136653566313535326132313638633138393466393464646162656166363336333330333533383338333236363264333636353332333632643334363233353337326436313334333533303264363436333335333033323330363136333636333436363334303030303030303031343133313231313130306630653064306330623061303930383037303630353034303330323031373336346563366437393662363966353261373936373466323164373162613961353631333539346530613834333432303535383133373265353538383566353034343730303330343530323230373635653731303834653337363866616162663336333639386139326230626534633766353863366437303661623836323637383730313339663331336565303032323130306435643933663833666466653730316239323836383735633034336438383230633331396461386230383538323064656334326635313165303961303636396400000001001ca9b08b8751b75fdbb3b3ca65138a9c5de8ab50f451896d8a40041301ae1092d6ea48c33de6c961a7000000000000000f8a5e5b4a4befaea03920a18cbb6dfdf8ae1463cc3048f00da4b4b46f1591c8"

        # 第一次解密：解密密钥胶囊
        decrypt_result = decrypt_crypto.decrypt(result.result)
        logger.info("第1次解密成功: %s", decrypt_result.result.decode("utf-8"))

        # 第二次解密：同一密文，命中解密缓存
        decrypt_result2 = decrypt_crypto.decrypt(result2.result)
        logger.info("第2次解密成功: %s", decrypt_result2.result.decode("utf-8"))

        assert plain_text.encode("utf-8") == decrypt_result.result, "Decrypted data does not match original"
        assert plain_text2.encode("utf-8") == decrypt_result2.result, "Decrypted data from cache does not match original"
        print("Key Capsule encryption example completed successfully!")

    crypto.close()
    decrypt_crypto.close()
    os._exit(0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    main()
