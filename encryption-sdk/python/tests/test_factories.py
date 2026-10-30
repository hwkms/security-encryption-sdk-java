import pytest
from huaweicloud_encryptionsdk.keyrings.kms_keyring_factory import KmsKeyringFactory
from huaweicloud_encryptionsdk.keyrings.raw_keyring_factory import RawKeyringFactory
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_aes_keyring import RawAesKeyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm4_keyring import RawSM4Keyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm4_cbc_keyring import RawSM4CBCKeyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_rsa_keyring import RawRSAKeyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm2_keyring import RawSM2Keyring
from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_multi_region_keyring import KMSMultiRegionKeyring
from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_discovery_keyring import KMSDiscoveryKeyring
from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_key_capsule_keyring import KMSKeyCapsuleKeyring
from huaweicloud_encryptionsdk.meterialmanager.data_key_generate_factory import DataKeyGenerateFactory
from huaweicloud_encryptionsdk.meterialmanager.local_data_key_generate import LocalDataKeyGenerate
from huaweicloud_encryptionsdk.meterialmanager.kms_data_key_generate import KmsDataKeyGenerate
from huaweicloud_encryptionsdk.meterialmanager.key_capsule_data_key_generate import KeyCapsuleDataKeyGenerate
from huaweicloud_encryptionsdk.proof.proof_collector_factory import ProofCollectorFactory
from huaweicloud_encryptionsdk.proof.proof_collector import ProofCollector
from huaweicloud_encryptionsdk.proof.proof_info import ProofInfo
from huaweicloud_encryptionsdk.proof.attestation_document import AttestationDocument
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.model.enums.data_key_generate_type import DataKeyGenerateType


class TestRawKeyringFactory:
    def test_aes(self):
        kr = RawKeyringFactory().get_keyring("AES")
        assert isinstance(kr, RawAesKeyring)

    def test_sm4(self):
        kr = RawKeyringFactory().get_keyring("SM4_GCM")
        assert isinstance(kr, RawSM4Keyring)

    def test_sm4_cbc(self):
        kr = RawKeyringFactory().get_keyring("SM4_CBC")
        assert isinstance(kr, RawSM4CBCKeyring)

    def test_rsa(self):
        kr = RawKeyringFactory().get_keyring("RSA")
        assert isinstance(kr, RawRSAKeyring)

    def test_sm2(self):
        kr = RawKeyringFactory().get_keyring("SM2")
        assert isinstance(kr, RawSM2Keyring)


class TestKmsKeyringFactory:
    def test_multi_region(self):
        kr = KmsKeyringFactory().get_keyring("multi")
        assert isinstance(kr, KMSMultiRegionKeyring)

    def test_discovery(self):
        kr = KmsKeyringFactory().get_keyring("discovery")
        assert isinstance(kr, KMSDiscoveryKeyring)

    def test_key_capsule(self):
        kr = KmsKeyringFactory().get_keyring("key_capsule")
        assert isinstance(kr, KMSKeyCapsuleKeyring)


class TestDataKeyGenerateFactory:
    def test_local(self):
        gen = DataKeyGenerateFactory.get_data_key_generate(DataKeyGenerateType.LOCAL_GENERATE)
        assert isinstance(gen, LocalDataKeyGenerate)

    def test_kms(self):
        gen = DataKeyGenerateFactory.get_data_key_generate(DataKeyGenerateType.KMS_GENERATE)
        assert isinstance(gen, KmsDataKeyGenerate)

    def test_key_capsule(self):
        gen = DataKeyGenerateFactory.get_data_key_generate(DataKeyGenerateType.KEY_CAPSULE_GENERATE)
        assert isinstance(gen, KeyCapsuleDataKeyGenerate)


class TestProofCollectorFactory:
    def test_register_and_get(self):
        class MockCollector(ProofCollector):
            def collect(self, proof_info):
                return AttestationDocument(service_token="Msheowudhswer")

        ProofCollectorFactory.register_collector(99, MockCollector())
        collector = ProofCollectorFactory.get_collector(99)
        result = collector.collect(ProofInfo())
        assert result.service_token == "Msheowudhswer"

    def test_get_collector_for_known_types(self):
        ProofCollectorFactory._COLLECTORS.clear()
        ProofCollectorFactory._init_collectors()
        for type_val in [1, 2, 3]:
            collector = ProofCollectorFactory.get_collector(type_val)
            assert collector is not None
