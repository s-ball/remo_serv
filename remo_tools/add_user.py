#  Copyright (c) 2020 SBA - MIT License

import sys
import argparse
from cryptography.hazmat.primitives import serialization
from remo_serv.user_service import SqliteUserService


def parse(args):
    parser = argparse.ArgumentParser(args[0])
    parser.add_argument('--base', '-b', default='users_db',
                        help='User database(default users_db)')
    parser.add_argument('user')
    parser.add_argument('pem', nargs='?',
                        help='PEM file for public key '
                        '(default user.PEM)')
    return parser.parse_args(args[1:])


def add(base: str, user: str, pem: str):
    if not base.endswith('.sqlite') and base != ':memory:':
        base += '.sqlite'
    users = SqliteUserService(base)
    if pem is None:
        pem = user + '.pem'
    with open(pem, 'rb') as fd:
        key = fd.read()
    users.add(user, pub=key)


if __name__ == '__main__':
    opt = parse(sys.argv)
    add(opt.base, opt.user, opt.pem)
