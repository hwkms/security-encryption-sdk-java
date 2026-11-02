import random
import time
from concurrent.futures import ThreadPoolExecutor

from loguru import logger

from huaweicloud_encryptionsdk._lts_sdk.producer.core.producer import Producer
from huaweicloud_encryptionsdk._lts_sdk.producer.model import lts_store
from huaweicloud_encryptionsdk._lts_sdk.producer.model.config import Config
from huaweicloud_encryptionsdk._lts_sdk.producer.utils import common


def generate_random_str(str_len=16):
    """
    生成一个指定长度的随机字符串
    """
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(str_len):
        random_str += base_str[random.randint(0, length)]
    return random_str

def send_log_single_producer():
    thread_num = 100
    threads = []
    begin_ms = common.current_time_ms()
    submit_send_log_thread_pool = ThreadPoolExecutor(max_workers=thread_num, thread_name_prefix="send_log_thread")

    config = Config()
    config.endpoint = ""
    config.access_key = ""
    config.access_secret = ""
    config.region_id = ""
    config.project_id = ""
    producer = Producer.init_producer(config)
    producer.start_producer()

    group_id = ""
    stream_id = ""

    log_content = generate_random_str(1024)
    log = [log_content]
    labels = {"keyA": "valueA"}
    log_p = lts_store.generate_log(log, labels)

    for i in range(thread_num):
        new_thread = submit_send_log_thread_pool.submit(send_log_function, producer, group_id, stream_id, log_p)
        threads.append(new_thread)

    for t in threads:
        t.result()
    end_ms = common.current_time_ms()
    logger.info("end send log, cost [{}]ms", end_ms - begin_ms)


def send_log_function(one_producer, group_id, stream_id, log_p):
    for i in range(2000):
        one_producer.send_log(group_id, stream_id, log_p)


if __name__ == '__main__':
    send_log_single_producer()
    time.sleep(1000)
