#  Copyright (c) 2020 SBA- MIT License

import io
import threading
from typing import Optional


class NonBlockWrapper(io.RawIOBase):
    def __init__(self, base):
        self.base = base
        self.q = []
        self.lock = threading.Lock()
        self.ended = False
        self.stop = False
        self.t = threading.Thread(target=self.reader, daemon=True)
        self.t.start()

    def readable(self) -> bool:
        return True

    def readinto(self, __buffer: bytearray) -> Optional[int]:
        with self.lock:
            if len(self.q) == 0:
                return 0 if self.ended else None
            else:
                data = b''.join(self.q)
                mn = min(len(data), len(__buffer))
                __buffer[:mn] = data[:mn]
                self.q = [data[mn:]] if len(data) > mn else []
                return mn

    def reader(self):
        while True:
            temp = self.base.read()
            if isinstance(temp, str):
                temp = temp.encode()
            if len(temp) == 0:
                self.ended = True
                return
            with self.lock:
                self.q.append(temp)

    def close(self):
        super().close()
        with self.lock:
            self.base.close()
            self.stop = True
