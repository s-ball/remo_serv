#  Copyright (c) 2020 SBA- MIT License

"""Various utilities used both by servers and clients."""

import http.client
import io
from cryptography import fernet


def build_status(code):
    """Transform a numeric code (200) in a HTTP status ('200 OK')."""
    status = http.HTTPStatus(code)
    return '{:3d} {}'.format(code, status.phrase)


class Codec(io.RawIOBase):
    """io wrapper to automatically encrypt/decrypt a stream"""
    block_size = 8192

    def __init__(self, base: io.RawIOBase, codec: fernet.Fernet, decode=True,
                 allow_plain=True):
        self.codec = codec
        self.raw = base
        self.data = ''
        self.start = 0
        self.first = True
        self.allow_plain = allow_plain
        if decode:
            self.transform = codec.decrypt
            self.input = base.readline
        else:
            self.input = lambda: base.read(self.block_size)

    def transform(self, data):
        if self.first:
            self.first = False
            prolog = b''
        else:
            prolog = b'\r\n'
        return prolog + self.codec.encrypt(data)

    def readable(self):
        return True

    def readinto(self, buf):
        got = 0
        beg = 0
        while True:
            req = len(buf) - beg
            if req == 0:
                return got
            available = len(self.data) - self.start
            if available == 0:
                tmp = self.input()
                if tmp == b'':
                    break
                try:
                    self.data = self.transform(tmp)
                except fernet.InvalidToken:
                    if not self.allow_plain:
                        raise
                    self.data = tmp
                self.start = 0
                available = len(self.data)
            nb = min(available, req)
            buf[beg: beg + nb] = self.data[self.start: self.start + nb]
            self.start += nb
            beg += nb
            got += nb
            available -= nb
        return got