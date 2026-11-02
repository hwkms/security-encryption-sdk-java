
class Attempt(object):
    def __init__(self, success, http_code, request_id, error_code, error_msg, time_stamp_ms, last_attempt_cost_ms):
        self.success = success
        self.http_code = http_code
        self.request_id = request_id
        self.error_code = error_code
        self.error_msg = error_msg
        self.time_stamp_ms = time_stamp_ms
        self.last_attempt_cost_ms = last_attempt_cost_ms


class Result(object):
    def __init__(self):
        self.attempt_list = []
        self.success = False

