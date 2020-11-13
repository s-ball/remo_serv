#  Copyright (c) 2020 SBA- MIT License

from unittest import TestCase

import io
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

    def test_deco_lines(self):
        data = b''.join(self.fernet.encrypt(d)+b'\r\n'
                        for d in (b'abc', b'd\ne', b'fgh'))
        fd = io.BytesIO(data)
        codec = tools.Codec(fd, self.fernet)
        self.assertEqual([b'abcd\n', b'efgh'], codec.readlines())

    def test_deco_all(self):
        data = b''.join(self.fernet.encrypt(d)+b'\r\n'
                        for d in (b'abc', b'd\ne', b'fgh'))
        fd = io.BytesIO(data)
        codec = tools.Codec(fd, self.fernet)
        self.assertEqual(b'abcd\nefgh', codec.read())

    def test_enco_simple(self):
        data = (b'abcd\nefgh\n' + bytes(i for i in range(256))) * 3
        codec = tools.Codec(io.BytesIO(data), self.fernet, False)
        self.assertEqual(data, self.fernet.decrypt(codec.read()))

    def test_enco_blocs_nb(self):
        data = (b'abcd\nefgh\n' + bytes(i for i in range(256))) * 3
        codec = tools.Codec(io.BytesIO(data), self.fernet, False)
        codec.block_size = 256
        self.assertEqual(4, len(codec.readlines()))

    def test_enco_blocs(self):
        data = (b'abcd\nefgh\n' + bytes(i for i in range(256))) * 3
        codec = tools.Codec(io.BytesIO(data), self.fernet, False)
        codec.block_size = 256
        self.assertEqual(data, b''.join(self.fernet.decrypt(line)
                                        for line in codec))
