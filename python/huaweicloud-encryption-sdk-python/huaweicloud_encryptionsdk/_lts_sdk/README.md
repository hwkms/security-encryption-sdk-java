## 1. 使用前提

- 要使用LTS Python SDK ，您需要拥有云账号以及该账号对应的 Access Key（AK）和 Secret Access Key（SK）。
  请在华为云控制台“我的凭证-访问密钥”页面上创建和查看您的 AK&SK
  。更多信息请查看 [访问密钥](https://support.huaweicloud.com/usermanual-ca/zh-cn_topic_0046606340.html)  。
- 要使用LTS Python SDK 上报日志 
  - 您需要确认已在 [华为云控制台](https://console.huaweicloud.com/console/?locale=zh-cn&region=cn-north-4#/home) 开通LTS服务
  - 您需要确认已经在LTS控制台创建日志组和日志流
- 要使用LTS Python SDK 消费日志
  - 您需要确认已经在LTS控制台创建日志组合日志流
  - 您需要确认已经在消费的日志流中创建消费组
- LTS Python SDK 适用于
    - python 3.10.1 及以上版本

## 2. Python-SDK使用的三方库

LTS Python SDK使用了以下第三方库

| 三方库      | 版本     |
|----------|--------|
| requests | 2.32.3 |
| loguru   | 0.7.2  |
| six      | 1.16.0 |

## 3. 代码配置以及示例

### 1. 日志发送场景

#### 1. 参数配置

使用LTS python SDK时，有以下配置参数：

| 参数名称      | 描述                      | 类型     | 是否必填 | 默认值 |
|-----------|-------------------------|--------|------|-----|
| projectId | 华为云帐号的项目ID（project id）。 | String | 必填   |     |
| ak        | 华为云帐号的AK。               | String | 必填   |     |
| sk        | 华为云帐号的SK。               | String | 必填   |     |
| region    | 云日志服务的区域。               | String | 必填   |     |
| endpoint  | 日志上报的目的地址。              | String | 必填   |     |
| logGroup  | 上报日志的日志组。               | String | 必填   |     |
| logStream | 上报日志的日志流。               | String | 必填   |     |

#### 2. 代码示例

```python
import random
import time
from concurrent.futures import ThreadPoolExecutor

from loguru import logger

from producer.core.producer import Producer
from producer.model import lts_store
from producer.model.config import Config
from utils import common


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


def send_log_function(one_producer, group_id, stream_id, log_p):
    for i in range(2000):
        one_producer.send_log(group_id, stream_id, log_p)


if __name__ == '__main__':
    send_log_single_producer()
    time.sleep(1000)
```

### 2. 日志消费场景

#### 1. 参数配置

使用LTS python SDK时，有以下配置参数：

| 参数名称            | 描述                               | 类型   | 是否必填 | 默认值 |
|---------------------|------------------------------------|--------|----------|--------|
| projectId           | 华为云帐号的项目ID（project id）。 | String | 必填     |        |
| ak                  | 华为云帐号的AK。                   | String | 必填     |        |
| sk                  | 华为云帐号的SK。                   | String | 必填     |        |
| region              | 云日志服务的区域。                 | String | 必填     |        |
| endpoint            | 日志上报的目的地址。               | String | 必填     |        |
| logGroup            | 上报日志的日志组。                 | String | 必填     |        |
| logStream           | 上报日志的日志流。                 | String | 必填     |        |
| consumer_group_name | 消费的groupName                    | string | 必填     |        |
| start_time          | 消费开始时间                       | int    | 必填     |        |
| consume_batch_size  | 一次能拉取最大日志数量             | int    | 选填     | 1000   |
| consumer_count      | 消费者的数量                       | int    | 选填     | 1      |
#### 2. 代码示例
```python
import argparse
import sys
import time
from typing import List

from loguru import logger

from consumer.core.client_consumer_worker import get_client_consumer_worker
from consumer.interface.consumer_check_point_tracker import ILogConsumerCheckPointTracker
from consumer.interface.consumer_processor import ILogConsumerProcessor
from consumer.interface.consumer_processor_factory import ILogConsumerProcessorFactory
from consumer.model.consumer_config import ConsumerConfig
from consumer.model.log_data import LogData


class DemoLogConsumerProcessor(ILogConsumerProcessor):

    def __init__(self):
        self.log_count = 0

    def initialize(self, shard_id):
        pass

    def process(self, log_group: List[LogData], tracker: ILogConsumerCheckPointTracker) -> str:
        self.log_count += len(log_group)
        logger.info("this time consume log {} total log num {}", len(log_group), self.log_count)

    def shutdown(self, tracker: ILogConsumerCheckPointTracker):
        return tracker.save_check_point(True)


class DemoLogConsumerProcessorFactory(ILogConsumerProcessorFactory):
    def generate_processor(self):
        return DemoLogConsumerProcessor()


def start_consume(endpoint, region_name, project_id, log_group_id, log_stream_id, access_key, access_secret,
                  consumer_group_name, start_time, end_time, log_level, is_test, consumer_count, consume_batch_size):
    logger.remove()
    logger.add(sys.stderr, level=log_level)
    if is_test:
        logger.add("/fanxin/log.log", level="DEBUG")
    logger.info("start time {}, end time {}", start_time, end_time)
    workers = []

    for i in range(consumer_count):
        config = ConsumerConfig(endpoint, region_name, project_id, log_group_id, log_stream_id, access_key,
                                access_secret, consumer_group_name, start_time, end_time, consume_batch_size)
        work = get_client_consumer_worker(DemoLogConsumerProcessorFactory(), config)
        if work is None:
            logger.error("get work error, work is none")
        else:
            workers.append(work)

    for work in workers:
        work.start()

    time.sleep(30000 * 60)
    for work in workers:
        work.shutdown()

    time.sleep(60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='lts python sdk consume log help tester information')
    parser.add_argument('--endpoint', dest='endpoint', type=str, help='lts endpoint', default="https://endpoint")
    parser.add_argument('--project_id', dest='project_id', type=str, help='huaweicloud project_id', default="projectId")
    parser.add_argument('--region', dest='region', type=str, help='huaweicloud region', default="region")
    parser.add_argument('--group_id', dest='group_id', type=str, help='send log group_id', default="group_id")
    parser.add_argument('--stream_id', dest='stream_id', type=str, help='send log stream_id', default="stream_id")
    parser.add_argument('--ak', dest='ak', type=str, help='huaweicloud ak', default="ak")
    parser.add_argument('--sk', dest='sk', type=str, help='huaweicloud sk', default="sk")
    parser.add_argument('--consumer_count', dest='consumer_count', type=int, help='consumer count', default=1)
    parser.add_argument('--consume_batch_size', dest='consume_batch_size', type=int, help='each fetch max log nums',
                        default=1000)
    parser.add_argument('--consumer_group_name', dest='consumer_group_name', type=str, help='consumer group name',
                        default="consumer_group_name")
    parser.add_argument('--start_time', dest='start_time', type=int, help='consume log start time ms',
                        default=213123123123)
    parser.add_argument('--end_time', dest='end_time', type=int, help='consume log end time ms', default=0)
    parser.add_argument('--log_level', dest='log_level', type=str, help='consume log end time ms', default="INFO")
    parser.add_argument('--is_test', dest='is_test', type=bool, help='test consumer will write log to node',
                        default=True)
    args = parser.parse_args()
    start_consume(args.endpoint, args.region, args.project_id, args.group_id, args.stream_id, args.ak,
                  args.sk, args.consumer_group_name, args.start_time, args.end_time, args.log_level, args.is_test,
                  args.consumer_count, args.consume_batch_size)

```

#### 3. 使用约束
1. 使用sdk消费日志前，日志组、日志流以及消费组必须存在；
2. 使用AKSK认证时，当前不支持临时AKSK认证
3. 消费历史日志时，只支持开通公测白名单时间点后的日志
4. 当前只支持消费startTime为某一具体时间点的日志