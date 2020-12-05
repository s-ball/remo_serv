#  Copyright (c) 2020 SBA- MIT License
import base64
import collections
import io
import json
import urllib.request
import urllib.parse
import http.client
import time
import struct

from typing import Optional

from cryptography import fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives.kdf import concatkdf

from . import smartcard
from remo_tools.http_tools import Codec, do_hash


class Response(io.BufferedReader):
    def __init__(self, response, codec: fernet.Fernet, req_no: int):
        self.decoder = Codec(response, codec, req_no, time.time(),
                             '{:03d}'.format(response.code).encode(),
                             allow_plain=True)
        super().__init__(self.decoder)
        for k in vars(response).keys():
            setattr(self, k, getattr(response, k))
        self.response = response

    def is_deco_ok(self):
        return self.decoder.deco_ok

    def __getitem__(self, item):
        return self.response[item]

    def __getattr__(self, item):
        return getattr(self.response, item)


class RemoServHandler(urllib.request.BaseHandler):
    def __init__(self, codec: fernet.Fernet, base_path: str):
        self.codec = codec
        self.req_no = 0
        self.last_req = 0
        self.base_path = base_path.rstrip('/')

    # noinspection PyTypeChecker
    def http_request(self, req: urllib.request.Request
                     ) -> urllib.request.Request:
        self.req_no += 1
        data = req.data
        path = req.selector
        req.full_url = self.base_path + path
        hash_val = do_hash(path.encode())
        if data is None:
            req.data = self.codec.encrypt(b'BE' + struct.pack(
                '>hh', self.req_no, 0) + hash_val)
        elif hasattr(data, 'read'):
            req.data = Codec(data, self.codec, self.req_no, 0, hash_val,
                             False)
        else:
            try:
                memoryview(data)
                req.data = self.codec.encrypt(b'BE' + struct.pack(
                    '>hh', self.req_no, 0) + hash_val + data)
            except TypeError:
                if isinstance(data, collections.abc.Iterable):
                    codec = Codec(io.BytesIO(), self.codec, self.req_no,
                                  0, hash_val, False)
                    req.data = b''.join(codec.transform(d) for d in data)\
                               + codec.transform(b'')
                else:
                    raise TypeError('RemoServHandler can only process '
                                    'bytes or iterables, got %r', type(data))
        return req

    def http_response(self, _req, response):
        if 'Content-Length' not in response.headers:
            r = Response(response, self.codec, self.req_no)
            if r.code == 200 and not r.is_deco_ok():
                raise fernet.InvalidToken()
            return r
        else:
            return response


# noinspection PyTypeChecker
class Connection:
    def __init__(self, user: str, opener: urllib.request.OpenerDirector,
                 codec: fernet.Fernet):
        self.user = user
        self.opener = opener
        self.codec = codec
        self.app_url = 'http://x'

    def get(self, remote_file: str, local_file: str = None):
        cmd = b'/get/' + self.codec.encrypt(remote_file.encode())
        if local_file is None:
            local_file = remote_file
        inp = self.opener.open(self.app_url + cmd.decode())
        with open(local_file, 'wb') as out:
            while True:
                data = inp.read(8192)
                if len(data) == 0:
                    break
                out.write(data)

    def put(self, remote_file: str, local_file: str = None):
        cmd = b'/put/' + self.codec.encrypt(remote_file.encode())
        if local_file is None:
            local_file = remote_file
        with open(local_file, 'rb') as fd:
            self.opener.open(self.app_url + cmd.decode(), fd)

    def exec(self, command: str) -> http.client.HTTPResponse:
        cmd = b'/cmd/' + self.codec.encrypt(command.encode())
        r = self.opener.open(self.app_url + cmd.decode())
        return r

    def iexec(self, command: str) -> http.client.HTTPResponse:
        cmd = b'/icm/' + self.codec.encrypt(command.encode())
        r = self.opener.open(self.app_url + cmd.decode())
        return r

    def idata(self, data: str) -> http.client.HTTPResponse:
        cmd = b'/idt'
        r = self.opener.open(self.app_url + cmd.decode(),
                             data.encode() + b'\n')
        return r

    def end_cmd(self) -> http.client.HTTPResponse:
        cmd = b'/edt'
        r = self.opener.open(self.app_url + cmd.decode())
        return r


def login(url: str, path: str, user: str,
          key: Optional[ed448.Ed448PrivateKey],
          signer: Optional[smartcard.Signer],
          remo_pub: ed448.Ed448PublicKey):
    cookie_processor = urllib.request.HTTPCookieProcessor()
    opener = urllib.request.build_opener(cookie_processor)
    tmp_key = x448.X448PrivateKey.generate()
    # noinspection PyTypeChecker
    pub = tmp_key.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
    data = user.encode() + pub
    sign = key.sign(data) if signer is None else signer.sign(data)
    data = json.dumps({'user': user,
                       'key': base64.urlsafe_b64encode(pub).decode(),
                       'sign': base64.urlsafe_b64encode(sign).decode()
                       })
    r = opener.open(url + path, data.encode())
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
    return Connection(user,
                      urllib.request.build_opener(
                          RemoServHandler(session_codec, url),
                          cookie_processor),
                      session_codec)
