class CountingOutputStream:

    def __init__(self, output_stream):
        self._output_stream = output_stream
        self._bytes_written = 0

    def write(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._output_stream.write(data)
        self._bytes_written += len(data)

    def get_bytes_written(self):
        return self._bytes_written

    @property
    def output_stream(self):
        return self._output_stream
