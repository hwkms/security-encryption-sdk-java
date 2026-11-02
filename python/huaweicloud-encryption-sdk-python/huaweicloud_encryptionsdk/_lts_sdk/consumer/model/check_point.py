from huaweicloud_encryptionsdk._lts_sdk.utils import common


class ShardCheckPoint:
    def __init__(self):
        self.shard_id = ""
        self.checkpoint = 0
        self.update_time = 0
        self.consumer_name = ""

    def __str__(self):
        return common.convert_obj2_json_str(self)


class Cursor(object):
    def __init__(self):
        self.cursor = ""

    def __str__(self):
        return common.convert_obj2_json_str(self)
