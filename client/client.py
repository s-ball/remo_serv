#  Copyright (c) 2020 SBA- MIT License
import collections
import urllib.request
import base64
import json
import io
from remo_serv.http_tools import Codec

from cryptography import fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf import concatkdf
from cryptography.hazmat.primitives.asymmetric import ed448, x448

SERVER = 'http://localhost:8080'


class Response(io.BufferedReader):
    def __init__(self, response, codec: fernet.Fernet):
        decoder = Codec(response, codec)
        super().__init__(decoder)
        for k in vars(response).keys():
            setattr(self, k, getattr(response, k))
        self.response = response

    def __getitem__(self, item):
        return self.response[item]

    def __getattr__(self, item):
        return getattr(self.response, item)


class RemoServHandler(urllib.request.BaseHandler):
    def __init__(self, codec: fernet.Fernet):
        self.codec = codec

    # noinspection PyTypeChecker
    def http_request(self, req: urllib.request.Request
                     ) -> urllib.request.Request:
        data = req.data
        if data is None:
            return req
        elif hasattr(data, 'read'):
            req.data = Codec(data, self.codec, False)
        else:
            try:
                memoryview(data)
                req.data = self.codec.encrypt(data)
            except TypeError:
                if isinstance(data, collections.abc.Iterable):
                    req.data = (self.codec.encrypt(d) + '\r\n'
                                for d in data)
                else:
                    raise TypeError('RemoServHandler can only process '
                                    'bytes or iterables, got %r', type(data))
        return req

    def http_response(self, _req, response):
        if 'Content-Length' not in response.headers:
            return Response(response, self.codec)
        else:
            return response


def login(url: str, user: str, key: ed448.Ed448PrivateKey,
          remo_pub: ed448.Ed448PublicKey):
    cookie_processor = urllib.request.HTTPCookieProcessor()
    opener = urllib.request.build_opener(cookie_processor)
    tmp_key = x448.X448PrivateKey.generate()
    # noinspection PyTypeChecker
    pub = tmp_key.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
    sign = key.sign(user.encode() + pub)
    data = json.dumps({'user': user,
                       'key': base64.urlsafe_b64encode(pub).decode(),
                       'sign': base64.urlsafe_b64encode(sign).decode()
                       })
    r = opener.open(url, data.encode())
    data = r.read()
    remo = base64.urlsafe_b64decode(data[:76])
    remo_pub.verify(base64.urlsafe_b64decode(data[78:]), remo)
    remo = x448.X448PublicKey.from_public_bytes(remo)
    session_key = tmp_key.exchange(remo)
    # noinspection PyArgumentList
    df = concatkdf.ConcatKDFHash(hashes.SHA256(), 32, b'remo_serv')
    session_key = df.derive(session_key)
    session_key = base64.urlsafe_b64encode(session_key)
    session_codec = fernet.Fernet(session_key)
    return urllib.request.build_opener(RemoServHandler(session_codec),
                                       cookie_processor)


def run():
    global opener

    with open('remo_serv.pem', 'rb') as fd:
        # noinspection PyArgumentList
        remo_pub = serialization.load_pem_public_key(fd.read())
    # noinspection PyArgumentList
    with open('foo_key.PEM', 'rb') as fd:
        own_key = serialization.load_pem_private_key(fd.read(), b'foo')
    opener = login(SERVER + '/auth', 'foo', own_key, remo_pub)
    r = opener.open(SERVER + '/info')
    print(r.code)
    print(r.headers, end='')
    data = r.read()
    print(data)


opener = None

if __name__ == '__main__':
    run()

h = [x for x in opener.handlers if isinstance(x, RemoServHandler)]
codec = h[0].codec
cmd = codec.encrypt(b'cmd /c echo foo')

r = opener.open(SERVER + '/cmd/' + cmd.decode())
