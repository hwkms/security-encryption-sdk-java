import logging
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed

from huaweicloud_encryptionsdk.common.utils import is_empty, bytes_to_hex, hex_to_bytes, common_hash
from huaweicloud_encryptionsdk.exception.errors import EncryptException, HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.keyring import Keyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig

logger = logging.getLogger(__name__)

SHA256 = "SHA256"
SM3 = "SM3"


class KMSKeyring(Keyring):

    kms_client_cache: dict = {}

    def __init__(self):
        self._huawei_config = None

    @property
    def huawei_config(self):
        return self._huawei_config

    @huawei_config.setter
    def huawei_config(self, value):
        self._huawei_config = value

    @abstractmethod
    def do_decrypt(self, data_key_materials: DataKeyMaterials):
        pass

    def encrypt_data_key(self, data_key_materials: DataKeyMaterials) -> DataKeyMaterials:
        self._do_encrypt(data_key_materials)
        return data_key_materials

    def decrypt_data_key(self, data_key_materials: DataKeyMaterials) -> DataKeyMaterials:
        self.do_decrypt(data_key_materials)
        return data_key_materials

    def _do_encrypt(self, data_key_materials: DataKeyMaterials):
        kms_config_list = self.huawei_config.kms_config_list
        ciphertext_data_keys = []

        def encrypt_for_config(kms_config):
            try:
                from huaweicloudsdkcore.auth.credentials import BasicCredentials
                from huaweicloudsdkkms.v2.region.kms_region import KmsRegion
                from huaweicloudsdkkms.v2 import KmsClient
                from huaweicloudsdkkms.v2.model.encrypt_datakey_request import EncryptDatakeyRequest
                from huaweicloudsdkkms.v2.model.encrypt_datakey_request_body import EncryptDatakeyRequestBody

                auth = BasicCredentials(self.huawei_config.ak, self.huawei_config.sk, kms_config.project_id)
                if self.huawei_config.security_token:
                    auth = auth.with_security_token(self.huawei_config.security_token)
                kms_client = self._get_kms_client(kms_config.region, kms_config.end_point, auth)
                plaintext_data_key = data_key_materials.plaintext_data_key
                data_key_hex = bytes_to_hex(plaintext_data_key)
                length = len(data_key_hex)
                key_spec = self._get_key_spec(kms_client, kms_config.key_id)
                if key_spec == "AES_256":
                    digest_alg = SHA256
                else:
                    digest_alg = SM3
                tmp_digest = common_hash(plaintext_data_key, digest_alg)
                data_key_with_hash = data_key_hex + bytes_to_hex(tmp_digest)
                body = EncryptDatakeyRequestBody(
                    key_id=kms_config.key_id,
                    plain_text=data_key_with_hash,
                    datakey_plain_length=str(length // 2)
                )
                request = EncryptDatakeyRequest(body=body)
                response = kms_client.encrypt_datakey(request)
                cipher_data_key_bytes = hex_to_bytes(response.cipher_text)
                if self.huawei_config.is_discovery:
                    ciphertext_data_key = CiphertextDataKey(data_key=cipher_data_key_bytes, kms_config=kms_config)
                else:
                    ciphertext_data_key = CiphertextDataKey(data_key=cipher_data_key_bytes, kms_config=None)
                ciphertext_data_keys.append(ciphertext_data_key)
            except Exception:
                logger.warning(
                    "encrypt data key error by kms server,please check the server information is right,region is :%s,keyId is:%s",
                    kms_config.region, kms_config.key_id
                )

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(encrypt_for_config, kms_config) for kms_config in kms_config_list]
            for future in as_completed(futures):
                future.result()

        if len(ciphertext_data_keys) <= 0:
            raise EncryptException(ErrorMessage.ENCRYPT_DATA_KEY_EXCEPTION.message)
        data_key_materials.ciphertext_data_keys = ciphertext_data_keys

    def _get_key_spec(self, kms_client, key_id):
        try:
            from huaweicloudsdkkms.v2.model.list_key_detail_request import ListKeyDetailRequest
            from huaweicloudsdkkms.v2.model.operate_key_request_body import OperateKeyRequestBody
            body = OperateKeyRequestBody(key_id=key_id)
            request = ListKeyDetailRequest(body=body)
            response = kms_client.list_key_detail(request)
            return response.key_info.key_spec
        except Exception:
            return "AES_256"

    def _get_kms_client(self, region_str, end_point, auth):
        from huaweicloudsdkkms.v2.region.kms_region import KmsRegion
        from huaweicloudsdkkms.v2 import KmsClient

        cache_key = self.huawei_config.ak + self.huawei_config.sk + region_str
        if cache_key in KMSKeyring.kms_client_cache:
            return KMSKeyring.kms_client_cache[cache_key]
        if is_empty(end_point):
            region = KmsRegion.value_of(region_str)
        else:
            from huaweicloudsdkcore.region.region import Region
            region = Region(region_str, end_point)
        kms_client = KmsClient.new_builder().with_credentials(auth).with_region(region).build()
        KMSKeyring.kms_client_cache[cache_key] = kms_client
        return kms_client

    def real_decrypt(self, data_key_materials: DataKeyMaterials):
        kms_config_list = self.huawei_config.kms_config_list
        ciphertext_data_keys = data_key_materials.ciphertext_data_keys
        for kms_config in kms_config_list:
            from huaweicloudsdkcore.auth.credentials import BasicCredentials
            auth = BasicCredentials(self.huawei_config.ak, self.huawei_config.sk, kms_config.project_id)
            if self.huawei_config.security_token:
                auth = auth.with_security_token(self.huawei_config.security_token)
            for ciphertext_data_key in ciphertext_data_keys:
                try:
                    region_str = kms_config.region
                    end_point = kms_config.end_point
                    key_id = kms_config.key_id
                    kms_client = self._get_kms_client(region_str, end_point, auth)
                    encode_data_key = bytes_to_hex(ciphertext_data_key.data_key)
                    from huaweicloudsdkkms.v2.model.decrypt_datakey_request import DecryptDatakeyRequest
                    from huaweicloudsdkkms.v2.model.decrypt_datakey_request_body import DecryptDatakeyRequestBody
                    body = DecryptDatakeyRequestBody(
                        key_id=key_id,
                        cipher_text=encode_data_key,
                        datakey_cipher_length="32"
                    )
                    request = DecryptDatakeyRequest(body=body)
                    response = kms_client.decrypt_datakey(request)
                    plaint_bytes = hex_to_bytes(response.data_key)
                    algorithm_name = data_key_materials.crypto_algorithm.sec_key_algorithm
                    data_key_materials.plaintext_data_key = plaint_bytes
                    return
                except Exception as e:
                    logger.error("one master key may be not match when decrypt data key in KMSKeyring: %s", e)
