from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_keyring import KMSKeyring
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials


class KMSMultiRegionKeyring(KMSKeyring):

    def do_decrypt(self, data_key_materials: DataKeyMaterials):
        self.real_decrypt(data_key_materials)
