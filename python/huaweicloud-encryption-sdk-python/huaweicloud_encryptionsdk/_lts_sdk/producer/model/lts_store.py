import json
import time
from typing import List

from huaweicloud_encryptionsdk._lts_sdk.producer.model.log import Log, LogContent


def generate_log(log_list: List[str], labels: dict) -> Log:
    """

    :rtype: object
    """
    log_contents = []
    for log_str in log_list:
        log_content = LogContent(time.time_ns(), log_str)
        log_contents.append(log_content)

    label_str = ""
    if labels is not None:
        label_str = json.dumps(labels)
    return Log(contents=log_contents, labels=label_str)
