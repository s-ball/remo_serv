#  Copyright (c) 2020 SBA- MIT License

"""Encryption/decryption and signature management using cryptography."""
import sys
import base64
import io
import json
import logging

from cryptography import fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, x448, padding
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from remo_tools.http_tools import build_status, Codec

logger = logging.getLogger(__name__)


class Cryptor:
    """WSGI middleware handling en/de-cryption of request and response bodies.

    The middleware internally handles the /auth PATH_INFO to perform login.
    """
    # noinspection PyArgumentList
    def __init__(self, app, key, user_service, path='/auth',
                 public='/info'):
        """Constructor parameters:
        - app: the WSGI application wrapped in the middleware
        - key: the private (ed448) key used to sign
        - user_service: a UserService implementation to get the public
        keys of registered users
        - path: the authentication path (default /auth)
        - public: the root of a public subtree accessible without
        authentication (default /info)
        """
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
        """The call to the WSGI middleware."""
        path = environ.get('PATH_INFO', '/')
        try:
            session = environ['SESSION']
        except LookupError:
            logger.error('No valid session')
            start_response(build_status(500), [('Content-Length', 0)])
            return [b'']
        if path == self.path:
            data = environ['wsgi.input'].read()
            try:
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
                logger.warning('Invalid authentication json %s', str(data))
                start_response(build_status(400), [('Content-Length', '0')])
                return [b'']
            try:
                user_bytes = self.user_service.public_data(user)
                user_key = serialization.load_pem_public_key(user_bytes)
                if isinstance(user_key, ed448.Ed448PublicKey):
                    user_key.verify(sign, user.encode() + pub)
                else:
                    user_key.verify(sign, user.encode() + pub,
                                    padding.PKCS1v15(), hashes.SHA512())
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
            # noinspection PyArgumentList
            kdf = ConcatKDFHash(hashes.SHA256(), 32, b'remo_serv')
            session.key = base64.urlsafe_b64encode(kdf.derive(session_key))
            session.user = user
            logger.info('Login %s (%s - %s)', user, session.id, session.key)
            start_response(build_status(200),
                           [('Content-type', 'text_plain'),
                            ('Content-Length', str(len(tmp_text)))])
            return [tmp_text]
        elif session.key is None:
            if path.startswith(self.public):
                return self.app(environ, start_response)
            else:
                logger.debug('Unauthenticated request for %s', path)
                start_response(build_status(403), [('Content-Length', '0')])
            return [b'']
        else:
            deco = fernet.Fernet(session.key)
            length = environ.get('CONTENT_LENGTH')
            if length == 0:
                environ['wsgi.input'] = io.BytesIO()
            elif length is not None:
                data = environ['wsgi.input'].read()
                if len(data) != 0:
                    data = deco.decrypt(data)
                environ['CONTENT_LENGTH'] = len(data)
                environ['wsgi.input'] = io.BytesIO(data)
            else:
                environ['wsgi.input'] = Codec(environ['wsgi.input'], deco,
                                              allow_plain=False)
            try:
                out = self.app(environ, Starter(deco, start_response)
                               .start_response)
            except fernet.InvalidToken:
                logger.warning('Invalid encrypted token')
                start_response(build_status(400), [])
                return [b'Invalid encoding']
            return (deco.encrypt(data) + b'\r\n' for data in out)


class Writer:
    """Wraps a stream and encode the output with the given Fernet."""
    def __init__(self, stream, encoder: fernet.Fernet):
        self.stream = stream
        self.encoder = encoder

    def write(self, data):
        self.stream.write(self.encoder.encrypt(data) + b'\r\n')


class Starter:
    """Auxiliary class to provide start_response callables.

    It wraps an original start_response by removing any Content-Length
    header and returning an encoding writer
    """
    def __init__(self, encoder: fernet.Fernet, start_response):
        self.encoder = encoder
        self.start_parent = start_response

    def start_response(self, status, headers, exc_info=None):
        stream = self.start_parent(status,
                                   [header for header in headers
                                    if header[0].lower() != 'content-length'],
                                   exc_info)
        return Writer(stream, self.encoder)
