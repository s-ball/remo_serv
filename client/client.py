#  Copyright (c) 2020 SBA- MIT License

import urllib.request
import base64
import sqlite3
import json

from cryptography import fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf import concatkdf
from cryptography.hazmat.primitives.asymmetric import ed448, x448

SERVER = 'http://localhost:8080'


def login(url: str, user: str, key: ed448.Ed448PrivateKey,
          remo_pub: ed448.Ed448PublicKey):
    cookie_processor = urllib.request.HTTPCookieProcessor
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
    jar = cookie_processor.cookiejar
    return session_codec, jar


def run():
    with open('remo_serv.pub', 'rb') as fd:
        # noinspection PyArgumentList
        remo_pub = serialization.load_pem_public_key(fd.read())
    con = sqlite3.connect('user_db.sqlite')
    data = con.execute("SELECT key FROM users WHERE user = ?",
                       ('foo',)).fetchone()[0]
    own_key = ed448.Ed448PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(data))
    codec, jar = login(SERVER + '/auth', 'foo', own_key, remo_pub)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar))
    r = opener.open(SERVER + '/')
    print(r.code)
    print(r.headers, end='')
    data = r.read()
    print(data)
    print(codec.decrypt(data))


if __name__ == '__main__':
    run()
