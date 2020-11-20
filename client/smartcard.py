#  Copyright (c) 2020 SBA- MIT License

import os
from typing import Union

try:
    # noinspection PyPackageRequirements,PyUnresolvedReferences
    import pkcs11
    # noinspection PyPackageRequirements,PyUnresolvedReferences
    from pkcs11.constants import Attribute, ObjectClass
    # noinspection PyPackageRequirements,PyUnresolvedReferences
    from pkcs11.exceptions import PKCS11Error

    pkcs_ok = True
except ImportError:
    pkcs_ok = False


class Signer:
    def __init__(self, token: pkcs11.Token, label: str):
        self.token = token
        self.label = label

    def sign(self, data: bytes):
        with self.token.open(user_pin=pkcs11.PROTECTED_AUTH) as session:
            key = session.get_key(ObjectClass.PRIVATE_KEY, label=self.label)
            # noinspection PyUnresolvedReferences
            return key.sign(data)


def get_token(label: str = None, serial: Union[bytes, bytearray, str] = None
              ) -> Signer:
    if not pkcs_ok:
        raise ValueError('pkcs11 module is not available')

    try:
        pkcs11lib = os.environ['PKCS11_LIB']
    except LookupError:
        raise ValueError('PKCS11_LIB not available in environment')
    lib = pkcs11.lib(pkcs11lib)

    token: pkcs11.Token

    tokens = list(lib.get_tokens())
    if serial is not None:
        if isinstance(serial, str):
            serial = serial.encode()
        tokens = [tok for tok in tokens if tok.serial.startswith(serial)]
    if len(tokens) == 1:
        token = tokens[0]
    else:
        raise ValueError('No valid card found' if len(tokens) == 0
                         else 'More than one card found')

    with token.open() as session:
        try:
            session.get_key(ObjectClass.PRIVATE_KEY, label=label)
        except PKCS11Error as e:
            raise ValueError(f'No key found for {label}') from e
    return Signer(token, label)
