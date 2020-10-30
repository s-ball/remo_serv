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

from remo_serv import session_manager, crypter, http_tools
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
        self.environ['PATH_INFO'] = '/public'
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
        coder = fernet.Fernet(session_key)
        coded = coder.encrypt(msg)
        self.environ['SESSION'].key = session_key
        self.environ['wsgi.input'] = io.BytesIO(coded)
        resp = b'x yzt'
        resp = [resp, resp+resp]
        self.app.return_value = resp
        out = self.crypt(self.environ, start_response)
        self.app.assert_called_once()
        env = self.app.call_args[0][0]
        input_data = env['wsgi.input'].read()
        self.assertEqual(msg, input_data)
        i = -1
        for i, data in enumerate(out):
            self.assertEqual(resp[i], coder.decrypt(data, 10))
        self.assertEqual(1, i)

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
