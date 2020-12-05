#  Copyright (c) 2020 SBA- MIT License

from unittest import TestCase
from unittest.mock import Mock, patch
import io
import json

from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives import serialization
from cryptography import fernet
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives import hashes

import secrets
import base64
import struct

from remo_serv import session_manager, crypter
from remo_tools import http_tools
from remo_serv.user_service import UserService, MemoryUserService


# noinspection PyUnresolvedReferences
def app(_environ, start_response):
    start_response(http_tools.build_status(200),
                   [('Content-type', 'text/plain')])
    return [b'foo', b'bar']


class Connection:
    # noinspection PyTypeChecker
    def __init__(self, user, user_service: UserService):
        self.user = user
        self.user_key = user_service.private(user)
        self.private = x448.X448PrivateKey.generate()
        self.pub = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# noinspection PyUnresolvedReferences,PyTypeChecker
class TestCryptor(TestCase):
    def setUp(self) -> None:
        self.session = session_manager.Session('sess')
        self.input = Mock(io.BytesIO)
        self.environ = {
            'SESSION': self.session,
            'wsgi.input': self.input,
            'PATH_INFO': '/',
        }
        self.app = Mock(app)
        self.user_service = MemoryUserService('foo', 'bar')
        with patch.object(serialization, 'load_pem_private_key') \
                as loader, patch('builtins.open'):
            loader.return_value = ed448.Ed448PrivateKey.generate()
            self.crypt = crypter.Cryptor(
                self.app, 'keyfile', self.user_service)
        # noinspection PyArgumentList
        self.kdf = ConcatKDFHash(hashes.SHA256(), 32, b'remo_serv')

    def test_no_auth_public(self):
        self.environ['PATH_INFO'] = '/info'
        start_response = Mock()
        self.crypt(self.environ, start_response)
        self.app.assert_called_once_with(self.environ, start_response)

    def test_no_auth(self):
        start_response = Mock()
        self.crypt(self.environ, start_response)
        self.app.assert_not_called()
        start_response.assert_called_once()
        self.assertEqual(http_tools.build_status(403),
                         start_response.call_args[0][0])

    def test_authenticated(self):
        start_response = Mock()
        session_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        msg = b'A B\nC'
        hash_val = http_tools.do_hash(self.environ['PATH_INFO'].encode())
        coder = fernet.Fernet(session_key)
        coded = coder.encrypt(b'BE' + struct.pack('>hh', 5, 0)
                              + hash_val + msg)
        self.environ['SESSION'].key = session_key
        self.environ['wsgi.input'] = io.BytesIO(coded)
        self.environ['CONTENT_LENGTH'] = len(coded)
        resp = b'x yzt'
        resp = [resp, resp+resp]
        self.app.return_value = resp
        out = self.crypt(self.environ, start_response)
        self.app.assert_called_once()
        env = self.app.call_args[0][0]
        input_data = env['wsgi.input'].read()
        self.assertEqual(msg, input_data)
        i = -1
        resp.append(b'')
        for i, data in enumerate(out):
            data = coder.decrypt(data)
            if i == 0:
                self.assertEqual(b'200' + resp[i], data[6:])
            else:
                self.assertEqual(resp[i], data[6:])
            req, tok = struct.unpack('>hh', data[2:6])
            self.assertEqual(5, req)
            self.assertEqual(i, tok)
        self.assertEqual(2, i)

    def test_authenticated_no_len(self):
        start_response = Mock()
        session_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        msg = b'A B\nC'
        hash_val = http_tools.do_hash(self.environ['PATH_INFO'].encode())
        coder = fernet.Fernet(session_key)
        coded = coder.encrypt(b'BE' + struct.pack('>hh', 5, 0)
                              + hash_val + msg)
        self.environ['SESSION'].key = session_key
        self.environ['wsgi.input'] = io.BytesIO(coded)
        resp = b'x yzt'
        resp = [resp, resp+resp]
        input_data = b''

        def data_input(_x, _y):
            nonlocal input_data

            input_data = self.environ['wsgi.input'].read()
            return resp

        self.app.side_effect = data_input
        out = self.crypt(self.environ, start_response)
        self.app.assert_called_once()
        env = self.app.call_args[0][0]
        self.assertEqual(msg, input_data)
        i = -1
        resp.append(b'')
        for i, data in enumerate(out):
            data = coder.decrypt(data)
            if i == 0:
                self.assertEqual(b'200' + resp[i], data[6:])
            else:
                self.assertEqual(resp[i], data[6:])
            req, tok = struct.unpack('>hh', data[2:6])
            self.assertEqual(5, req)
            self.assertEqual(i, tok)
        self.assertEqual(2, i)

    def test_deco(self):
        self.environ['SESSION'].key = base64.urlsafe_b64encode(
            secrets.token_bytes(32))
        self.environ['CONTENT_LENGTH'] = 0
        self.environ['PATH_INFO'] = '/auth'
        start_response = Mock()
        self.environ['wsgi.input'].read = Mock(return_value=b'')
        self.crypt(self.environ, start_response)
        self.app.assert_not_called()
        start_response.assert_called_once()
        self.assertIsNone(self.environ['SESSION'].key)
        self.assertTrue(start_response.call_args[0][0].startswith('200 '))

    def test_connect(self):
        con = Connection('foo', self.user_service)
        self.environ['PATH_INFO'] = '/auth'
        sign = self.user_service.private('foo').sign(b'foo' + con.pub)
        data = json.dumps({'user': 'foo',
                           'key': base64.urlsafe_b64encode(con.pub).decode(),
                           'sign': base64.urlsafe_b64encode(sign).decode(),
                           })
        self.environ['wsgi.input'] = io.BytesIO(data.encode())
        start_response = Mock()
        out = self.crypt(self.environ, start_response)
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('200 '))
        data = next(iter(out))
        remo_pub_bytes = base64.urlsafe_b64decode(data)
        remo_pub = x448.X448PublicKey.from_public_bytes(remo_pub_bytes)
        tempo = con.private.exchange(remo_pub)
        key = base64.urlsafe_b64encode(self.kdf.derive(tempo))
        self.assertEqual(self.environ['SESSION'].key, key)

    def test_content_length_0(self):
        session_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        self.environ['SESSION'].key = session_key
        codec = fernet.Fernet(session_key)
        hash_val = http_tools.do_hash(self.environ['PATH_INFO'].encode())
        plain = b''
        data = codec.encrypt(b'BE' + struct.pack('>hh', 5, 0) + hash_val
                             + plain)
        self.environ['CONTENT_LENGTH'] = len(data)
        self.environ['wsgi.input'] = io.BytesIO(data)
        start_response = Mock()
        self.app.return_value = [b'']
        self.crypt(self.environ, start_response)
        self.assertEqual(b'', self.environ['wsgi.input'].read())

    def test_content_length(self):
        session_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        self.environ['SESSION'].key = session_key
        codec = fernet.Fernet(session_key)
        hash_val = http_tools.do_hash(self.environ['PATH_INFO'].encode())
        plain = b'abcdef'
        data = codec.encrypt(b'BE' + struct.pack('>hh', 5, 0) + hash_val
                             + plain)
        self.environ['CONTENT_LENGTH'] = len(data)
        self.environ['wsgi.input'] = io.BytesIO(data)
        start_response = Mock()
        self.app.return_value = [b'']
        self.crypt(self.environ, start_response)
        self.assertEqual(plain, self.environ['wsgi.input'].read())
        self.assertEqual(len(plain), self.environ['CONTENT_LENGTH'])

    def test_content_length_unknown(self):
        session_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        self.environ['SESSION'].key = session_key
        coder = fernet.Fernet(session_key)
        hash_val = http_tools.do_hash(self.environ['PATH_INFO'].encode())
        codec = http_tools.Codec(io.BytesIO(), coder, 5, 0, hash_val, False)
        plains = [b'abc', b'def', b'']
        data = b''.join(codec.transform(x) for x in plains)
        self.environ['wsgi.input'] = io.BytesIO(data)
        start_response = Mock()
        self.app.return_value = [b'']
        self.crypt(self.environ, start_response)
        self.assertEqual(b''.join(plains), self.environ['wsgi.input'].read())
        self.assertFalse('CONTENT_LENGTH' in self.environ)

    def test_wrong_cmd_hash(self):
        session_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        self.environ['SESSION'].key = session_key
        coder = fernet.Fernet(session_key)
        hash_val = http_tools.do_hash(self.environ['PATH_INFO'].encode() + b'x')
        codec = http_tools.Codec(io.BytesIO(), coder, 5, 0, hash_val, False)
        plains = [b'abc', b'def', b'']
        data = b''.join(codec.transform(x) for x in plains)
        self.environ['wsgi.input'] = io.BytesIO(data)
        start_response = Mock()
        self.app.return_value = [b'']
        with self.assertRaises(fernet.InvalidToken):
            self.crypt(self.environ, start_response)
            self.environ['wsgi.input'].read()

    def test_data_error(self):
        session_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        self.environ['SESSION'].key = session_key
        # noinspection SpellCheckingInspection
        plains = b'abcdef'
        data = plains
        self.environ['wsgi.input'] = io.BytesIO(data)
        start_response = Mock()
        self.app.side_effect = lambda environ, _x: [environ['wsgi.input'].read()]
        self.crypt(self.environ, start_response)
        self.assertEqual(http_tools.build_status(400),
                         start_response.call_args[0][0])

    def test_RSA_connect(self):
        from cryptography.hazmat.primitives.asymmetric import rsa, padding

        # noinspection PyArgumentList
        private = rsa.generate_private_key(65537, 2048)
        public = private.public_key()
        user_service = Mock(UserService)
        user_service.private.return_value = private
        user_service.public_data.return_value = public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        con = Connection('foo', user_service)
        self.environ['PATH_INFO'] = '/auth'
        # noinspection PyArgumentList
        sign = user_service.private('foo').sign(
            b'foo' + con.pub, padding.PKCS1v15(), hashes.SHA512())
        data = json.dumps({'user': 'foo',
                           'key': base64.urlsafe_b64encode(con.pub).decode(),
                           'sign': base64.urlsafe_b64encode(sign).decode(),
                           })
        self.environ['wsgi.input'] = io.BytesIO(data.encode())
        start_response = Mock()
        with patch.object(self.crypt, 'user_service', user_service):
            out = self.crypt(self.environ, start_response)
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('200 '))
        data = next(iter(out))
        remo_pub_bytes = base64.urlsafe_b64decode(data)
        remo_pub = x448.X448PublicKey.from_public_bytes(remo_pub_bytes)
        tempo = con.private.exchange(remo_pub)
        key = base64.urlsafe_b64encode(self.kdf.derive(tempo))
        self.assertEqual(self.environ['SESSION'].key, key)
