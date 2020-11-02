#  Copyright (c) 2020 SBA- MIT License
from cryptography.hazmat.primitives import serialization

from client.clientlib import login

SERVER = 'http://localhost:8080'


# noinspection PyArgumentList
def run():
    with open('remo_serv.pem', 'rb') as fd:
        remo_pub = serialization.load_pem_public_key(fd.read())
    with open('foo_key.PEM', 'rb') as fd:
        own_key = serialization.load_pem_private_key(fd.read(), b'foo')
    con = login(SERVER, '/auth', 'foo', own_key, remo_pub)
    r = con.opener.open(SERVER + '/')
    print(r.code)
    print(r.headers, end='')
    data = r.read()
    print(data)
    con.get('foo_key.pem', 'x.pem')
    con.put('y.pem', 'x.pem')
    r = con.exec('cmd /c echo foo')
    print(r.read())
    r = con.iexec('cmd /c echo foo')
    print(r.read())
    r = con.idata(None)
    print(r.read())


if __name__ == '__main__':
    run()
