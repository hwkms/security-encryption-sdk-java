import threading


class ReadWriteLock:

    def __init__(self):
        self._cond = threading.Condition(threading.Lock())
        self._active_readers = 0

    def acquire_read(self):
        self._cond.acquire()
        try:
            self._active_readers += 1
        finally:
            self._cond.release()

    def release_read(self):
        self._cond.acquire()
        try:
            self._active_readers -= 1
            if not self._active_readers:
                self._cond.notify_all()
        finally:
            self._cond.release()

    def acquire_write(self):
        self._cond.acquire()
        while self._active_readers > 0:
            self._cond.wait()

    def release_write(self):
        self._cond.release()
