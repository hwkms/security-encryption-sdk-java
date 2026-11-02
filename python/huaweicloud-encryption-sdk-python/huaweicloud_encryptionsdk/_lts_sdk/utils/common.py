import json
import time


def solv_log(x):
    n = 0
    while True:
        n += 1
        x >>= 7
        if x == 0:
            break
    return n


def _encode_obj(obj) -> dict:
    obj_dict = {}
    obj_dict.update(obj.__dict__)
    return obj_dict


def convert_obj2_json_str(obj):
    if obj is None:
        return ""
    return json.dumps(obj, default=_encode_obj, indent=None, sort_keys=True)


def convert_json_str2_obj(json_str, objClass):
    parse_data = json.loads(json_str.strip('\t\r\n'))
    result = objClass()
    result.__dict__ = parse_data
    return result


def convert_dict2_obj(parse_data, objClass):
    result = objClass()
    result.__dict__ = parse_data
    return result


def convert_json_str2_list_obj(json_str, objClass):
    lists = json.loads(json_str.strip('\t\r\n'))
    result = []
    for each_item in lists:
        result.append(convert_dict2_obj(each_item, objClass))
    return result


def current_time_ms() -> int:
    return int((time.time() * 1000))


def current_time_ns() -> int:
    return time.time_ns()


def sleep_ms(mill):
    time.sleep(mill / 1000)
