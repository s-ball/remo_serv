#  Copyright (c) 2020 SBA- MIT License

from unittest import TestCase

import io
import time
import struct
from cryptography import fernet

from remo_tools import http_tools as tools


class TestTools(TestCase):
    def test_build_ok(self):
        self.assertEqual('200 OK', tools.build_status(200))

    def test_build_forbidden(self):
        self.assertEqual('403 Forbidden', tools.build_status(403))


class TestCodec(TestCase):
    def setUp(self) -> None:
        key = fernet.Fernet.generate_key()
        self.fernet = fernet.Fernet(key)

    def encode(self, data: bytes, prefix:bytes,
               hash_val: bytes, req_no: int, tok: int) -> bytes:
        return self.fernet.encrypt(prefix + struct.pack('>hh', req_no, tok)
                                   + hash_val + data)

    def test_deco_lines(self):
        req = 5
        data = b''.join(self.encode(d[1], d[0], b'', req, i)+b'\r\n'
                        for i, d in enumerate((
            (b'B.', b'abc'),(b'..', b'd\ne'), (b'.E', b'fgh'))))
        fd = io.BytesIO(data)
        codec = tools.Codec(fd, self.fernet, 5, time.time(), b'')
        self.assertEqual([b'abcd\n', b'efgh'], codec.readlines())

    def test_deco_all(self):
        req = 5
        data = b''.join(self.encode(d[1], d[0], b'', req, i)+b'\r\n'
                        for i, d in enumerate((
            (b'B.', b'abc'),(b'..', b'd\ne'), (b'.E', b'fgh'))))
        fd = io.BytesIO(data)
        codec = tools.Codec(fd, self.fernet, 5, time.time(), b'')
        self.assertEqual(b'abcd\nefgh', codec.read())

    def test_deco_missing_end(self):
        req = 5
        data = b''.join(self.encode(d[1], d[0], b'', req, i)+b'\r\n'
                        for i, d in enumerate((
            (b'B.', b'abc'),(b'..', b'd\ne'), (b'..', b'fgh'))))
        fd = io.BytesIO(data)
        codec = tools.Codec(fd, self.fernet, 5, time.time(), b'')
        with self.assertRaises(fernet.InvalidToken):
            codec.read()

    def test_deco_missing_tok(self):
        req = 5
        data = b''.join(self.encode(d[1], d[0], b'', req, i * 2)+b'\r\n'
                        for i, d in enumerate((
            (b'B.', b'abc'),(b'..', b'd\ne'), (b'.E', b'fgh'))))
        fd = io.BytesIO(data)
        codec = tools.Codec(fd, self.fernet, 5, time.time(), b'')
        self.assertEqual(b'abc', codec.read(3))
        with self.assertRaises(fernet.InvalidToken):
            codec.read(1)

    def test_deco_rnd_req(self):
        req = 5
        data = b''.join(self.encode(d[1], d[0], b'', req, i)+b'\r\n'
                        for i, d in enumerate((
            (b'B.', b'abc'),(b'..', b'd\ne'), (b'.E', b'fgh'))))
        fd = io.BytesIO(data)
        # a different request number is allowed if last_req is small enough
        codec = tools.Codec(fd, self.fernet, 3, 0, b'')
        self.assertEqual(b'abcd\nefgh', codec.read())

    def test_enco_simple(self):
        data = (b'abcd\nefgh\n' + bytes(i for i in range(256))) * 3
        codec = tools.Codec(io.BytesIO(data), self.fernet, 10, time.time(),
                            decode=False)
        lines = [self.fernet.decrypt(line) for line in codec.readlines()]
        self.assertEqual(data, lines[0][6:])
        self.assertEqual(b'.E\x00\x0a\x00\x01', lines[1])

    def test_enco_blocs_nb(self):
        data = (b'abcd\nefgh\n' + bytes(i for i in range(256))) * 3
        codec = tools.Codec(io.BytesIO(data), self.fernet, 10, time.time(),
                            decode=False)
        codec.block_size = 256
        self.assertEqual(5, len(codec.readlines()))

    def test_enco_blocs(self):
        data = (b'abcd\nefgh\n' + bytes(i for i in range(256))) * 3
        codec = tools.Codec(io.BytesIO(data), self.fernet, 10, time.time(),
                            decode=False)
        codec.block_size = 256
        self.assertEqual(data, b''.join(self.fernet.decrypt(line)[6:]
                                        for line in codec))

    def test_enco_with_hash(self):
        h = tools.do_hash(b'foobar')
        data = (b'abcd\nefgh\n' + bytes(i for i in range(256))) * 3
        codec = tools.Codec(io.BytesIO(data), self.fernet, 10, time.time(),
                            cmd_hash=h, decode=False)
        lines = [self.fernet.decrypt(line) for line in codec.readlines()]
        self.assertEqual(h, lines[0][6:6+len(h)])
        self.assertEqual(data, lines[0][6+len(h):])
        self.assertEqual(b'.E\x00\x0a\x00\x01', lines[1])
