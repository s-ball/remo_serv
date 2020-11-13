#  Copyright (c) 2020 SBA - MIT License

import sys
import os.path
import getpass

from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives import serialization


# noinspection PyTypeChecker
def build_key(prefix: str, folder: str = None):
    key = ed448.Ed448PrivateKey.generate()
    pub = key.public_key()
    if folder is not None:
        prefix = os.path.join(folder, prefix)

    file = prefix + '_key.pem'
    passwd = getpass.getpass('Password for the private key '
                             '(if empty, key will not be encrypted): ')
    passwd = passwd.strip()
    encryption = serialization.NoEncryption() if passwd == '' \
        else serialization.BestAvailableEncryption(passwd.encode())
    with open(file, 'wb') as fd:
        fd.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   encryption))

    file = prefix + '.pem'
    with open(file, 'wb') as fd:
        fd.write(pub.public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat
                                  .SubjectPublicKeyInfo))


if __name__ == '__main__':
    build_key(*sys.argv[1:])
