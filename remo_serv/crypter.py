#  Copyright (c) 2020 SBA- MIT License

import sys
import base64
import io
import json
import logging

from cryptography import fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from .http_tools import build_status

logger = logging.getLogger(__name__)


class Cryptor:
    # noinspection PyArgumentList
    def __init__(self, app, key, user_service, path='/auth',
                 public='/pub'):
        if isinstance(key, ed448.Ed448PrivateKey):
            self.key = key
        else:
            with open(key, 'rb') as fd:
                self.key = serialization.load_pem_private_key(fd.read(), None)
        self.app = app
        self.user_service = user_service
        self.path = path
        self.public = public

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '/')
        try:
            session = environ['SESSION']
        except LookupError:
            start_response(build_status(500), [('Content-Length', 0)])
            return [b'']
        if path == self.path:
            try:
                data = environ['wsgi.input'].read()
                if len(data) == 0 or environ['CONTENT_LENGTH'] == '0':
                    session.key = None
                    start_response(build_status(200),
                                   [('Content-Type', 'text/plain')])
                    return [b'Disconnected']
            except LookupError:
                pass
            try:
                data = json.loads(data)
                user = data['user']
                pub = base64.urlsafe_b64decode(data['key'].encode())
                sign = base64.urlsafe_b64decode(data['sign'].encode())
            except (json.JSONDecodeError, LookupError):
                start_response(build_status(400), [('Content-Length', '0')])
                return [b'']
            try:
                user_bytes = self.user_service.public_data(user)
                user_key = ed448.Ed448PublicKey.from_public_bytes(user_bytes)
                user_key.verify(sign, user.encode() + pub)
            except (LookupError, TypeError, ValueError):
                logger.warning('Error login %s', user, exc_info=sys.exc_info())
                start_response(build_status(403), [('Content-Length', '0')])
                return [b'']
            tmp_key = x448.X448PrivateKey.generate()
            tmp_pub = tmp_key.public_key()
            # noinspection PyTypeChecker
            tmp_bytes = tmp_pub.public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
            tmp_text = base64.urlsafe_b64encode(tmp_bytes)
            tmp_text += b'\r\n' + base64.urlsafe_b64encode(
                self.key.sign(tmp_bytes))
            remo_pub = x448.X448PublicKey.from_public_bytes(pub)
            session_key = tmp_key.exchange(remo_pub)
            kdf = ConcatKDFHash(hashes.SHA256(), 32, b'remo_serv')
            session.key = base64.urlsafe_b64encode(kdf.derive(session_key))
            session.user = user
            logger.debug('Login %s (%s - %s)', user, session.id, session.key)
            start_response(build_status(200),
                           [('Content-type', 'text_plain'),
                            ('Content-Length', str(len(tmp_text)))])
            return [tmp_text]
        elif session.key is None:
            if path.startswith(self.public):
                return self.app(environ, start_response)
            else:
                start_response(build_status(403), [('Content-Length', '0')])
            return [b'']
        else:
            deco = fernet.Fernet(session.key)
            length = environ.get('CONTENT_LENGTH')
            if length != '0':
                data = environ['wsgi.input'].read()
                if len(data) != 0:
                    data = deco.decrypt(data)
                environ['CONTENT_LENGTH'] = len(data)
                environ['wsgi.input'] = io.BytesIO(data)
            elif length is None:
                environ['wsgi.input'] = io.BytesIO()
            out = self.app(environ, Starter(deco, start_response)
                           .start_response)
            return (deco.encrypt(data) + b'\r\n' for data in out)


class Writer:
    def __init__(self, stream, encoder: fernet.Fernet):
        self.stream = stream
        self.encoder = encoder

    def write(self, data):
        self.stream.write(self.encoder.encrypt(data))


class Starter:
    def __init__(self, encoder: fernet.Fernet, start_response):
        self.encoder = encoder
        self.start_parent = start_response

    def start_response(self, status, headers, exc_info=None):
        stream = self.start_parent(status,
                                   [header for header in headers
                                    if header[0].lower() != 'content-length'],
                                   exc_info)
        return Writer(stream, self.encoder)
