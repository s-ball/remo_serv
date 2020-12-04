#  Copyright (c) 2020 SBA- MIT License

"""Various utilities used both by servers and clients."""

import http.client
import io
import struct
import time

from cryptography import fernet
from cryptography.hazmat.primitives import hashes

TTL = 10


def build_status(code):
    """Transform a numeric code (200) in a HTTP status ('200 OK')."""
    status = http.HTTPStatus(code)
    return '{:3d} {}'.format(code, status.phrase)


def do_hash(data: bytes) -> bytes:
    """remo_serv hash function.
    Currently based on SHA384
    """
    # noinspection PyArgumentList
    h = hashes.Hash(hashes.SHA384())
    h.update(data)
    return h.finalize()


class Codec(io.RawIOBase):
    """io wrapper to automatically encrypt/decrypt a stream"""
    block_size = 8192

    def __init__(self, base: io.RawIOBase, codec: fernet.Fernet, req_no,
                 last_req = 0, cmd_hash=b'', decode=True, allow_plain=False):
        self.codec = codec
        self.raw = base
        self.data = ''
        self.start = 0
        self.first = True
        self.req_no = req_no
        self.last_req = time.time() if last_req is None else last_req
        self.tok = 0
        self.ended = False
        self.cmd_hash = cmd_hash
        self.hash_len = len(cmd_hash)
        self.allow_plain = allow_plain
        if decode:
            self.transform = self.decrypt
            self.input = base.readline
        else:
            self.input = lambda: base.read(self.block_size)

    def decrypt(self, data):
        if data == b'' and self.ended:
            return b''
        if self.ended:
            raise fernet.InvalidToken()
        data = self.codec.decrypt(data, TTL)
        req, tok = struct.unpack('>hh', data[2:6])
        if self.first:
            self.first = False
            if (time.time() < self.last_req + TTL and self.req_no != req) \
                    or data[0:1] != b'B' or tok != 0 \
                    or self.cmd_hash != data[6:6+self.hash_len]:
                raise fernet.InvalidToken()
            self.req_no = req
            ret = data[6 + self.hash_len:]
        else:
            if data[0:1] == b'B' or tok != self.tok + 1 or req != self.req_no:
                raise fernet.InvalidToken()
            ret = data[6:]
        if data[1:2] == b'E':
            self.ended = True
        self.tok = tok
        return ret

    def transform(self, data):
        if self.first:
            self.first = False
            prolog = b''
            begin = b'B'
            cmd_hash = self.cmd_hash
        else:
            prolog = b'\r\n'
            begin = b'.'
            cmd_hash = b''
        if self.ended:
            return b''
        if data == b'':
            end = b'E'
            self.ended = True
        else:
            end = b'.'
        out = prolog + self.codec.encrypt(begin + end + struct.pack(
            '>hh', self.req_no, self.tok) + cmd_hash + data)
        self.tok += 1
        return out

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
                try:
                    self.data = self.transform(tmp)
                except fernet.InvalidToken:
                    if not self.allow_plain:
                        raise
                    self.data = tmp
                self.start = 0
                available = len(self.data)
            if available == 0:
                break
            nb = min(available, req)
            buf[beg: beg + nb] = self.data[self.start: self.start + nb]
            self.start += nb
            beg += nb
            got += nb
            available -= nb
        if got == 0 and not self.ended and not self.allow_plain:
            raise fernet.InvalidToken()
        return got
