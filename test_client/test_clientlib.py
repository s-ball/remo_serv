#  Copyright (c) 2020 SBA- MIT License

import unittest
from unittest.mock import Mock, patch

import struct
import io
import time
import urllib.request
import http.client

from cryptography import fernet

from client import clientlib
from remo_tools import http_tools


class ResponseStub(io.BytesIO):
    def __init__(self, data: bytes, code):
        super().__init__(data)
        self.code = code


class TestResponse(unittest.TestCase):
    def setUp(self) -> None:
        key = fernet.Fernet.generate_key()
        self.fernet = fernet.Fernet(key)

    def test_simple(self):
        req_no = 5
        data = b'BE' + struct.pack('>hh', req_no, 0) + b'200foo'
        data = self.fernet.encrypt(data)
        r = clientlib.Response(ResponseStub(data, 200), self.fernet, req_no)
        self.assertEqual(b'foo', r.read())
        self.assertTrue(r.is_deco_ok())

    def test_no_encrypt(self):
        r = clientlib.Response(ResponseStub(b'foo', 200), self.fernet, 1)
        self.assertEqual(b'foo', r.read())

    def test_wrong_req(self):
        req_no = 5
        data = b'BE' + struct.pack('>hh', req_no + 1, 0) + b'foo'
        data = self.fernet.encrypt(data)
        r = clientlib.Response(ResponseStub(data, 200), self.fernet, req_no)
        self.assertTrue(r.is_deco_ok())
        r.read()
        self.assertFalse(r.is_deco_ok())


# BEWARE: tests in this TestCase depend on an opener to call _open after
# pre-processing the request in its handlers
class TestOpener(unittest.TestCase):
    def setUp(self) -> None:
        key = fernet.Fernet.generate_key()
        self.fernet = fernet.Fernet(key)
        self.servHandler = clientlib.RemoServHandler(self.fernet,
                                                     'http://foo.com/')
        self.opener = urllib.request.build_opener(self.servHandler)

    def test_url_ok(self):
        with patch.object(self.opener, '_open') as r:
            resp = Mock(http.client.HTTPResponse)
            resp.headers = {}
            resp.code = 200
            resp.msg = '200 OK'
            r.return_value = resp
            self.opener.open('http://x/bar')
            req = r.call_args[0][0]
            self.assertEqual('http://foo.com/bar', req.full_url)

    def test_url_with_path(self):
        self.servHandler.base_path = 'http://foo.com/path/to'
        with patch.object(self.opener, '_open') as r:
            resp = Mock(http.client.HTTPResponse)
            resp.headers = {}
            resp.code = 200
            resp.msg = '200 OK'
            r.return_value = resp
            self.opener.open('http://x/bar')
            req = r.call_args[0][0]
            self.assertEqual('http://foo.com/path/to/bar', req.full_url)


class TestHandler(unittest.TestCase):
    def setUp(self) -> None:
        key = fernet.Fernet.generate_key()
        self.fernet = fernet.Fernet(key)
        self.servHandler = clientlib.RemoServHandler(self.fernet,
                                                     'http://foo.com')

    def test_simple(self):
        req = urllib.request.Request('http:/get/foo')
        r = self.servHandler.http_request(req)
        self.assertEqual('http://foo.com/get/foo', r.full_url)
        self.assertIsNotNone(r.data)
        c = http_tools.Codec(io.BytesIO(r.data), self.fernet, 1, time.time(),
                             http_tools.do_hash(b'/get/foo'))
        self.assertEqual(b'', c.read())
        self.assertTrue(c.deco_ok)

    def test_iterable(self):
        req = urllib.request.Request('http:/get/foo', (b'ab\nc', b'd\nef'))
        r = self.servHandler.http_request(req)
        self.assertEqual('http://foo.com/get/foo', r.full_url)
        self.assertIsNotNone(r.data)
        self.assertEqual(3, len(r.data.splitlines()))
        c = http_tools.Codec(io.BytesIO(r.data), self.fernet, 1, time.time(),
                             http_tools.do_hash(b'/get/foo'))
        self.assertEqual([b'ab\n', b'cd\n', b'ef'], c.readlines())


if __name__ == '__main__':
    unittest.main()
