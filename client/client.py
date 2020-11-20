#  Copyright (c) 2020 SBA- MIT License

import getpass
import argparse
import sys
import cmd
import shlex

from urllib.error import HTTPError

from cryptography.hazmat.primitives import serialization

from client.clientlib import login, Connection
from client import smartcard


def parse2(arg):
    args = list(shlex.split(arg))
    if len(args) == 1:
        args.append(args[0])
    elif len(args) != 2:
        return None, None
    return args


class CmdLoop(cmd.Cmd):
    def __init__(self, con: Connection, server, encoding):
        self.con = con
        self.prompt = server + '> '
        super().__init__()
        self.encoding = encoding

    def do_get(self, arg):
        """Get a file from remote: get remote_file [local_file]"""
        params = parse2(arg)
        if params[0] is None:
            print('ERROR: 1 or 2 parameters required', file=sys.stderr)
        else:
            try:
                self.con.get(*params)
            except HTTPError as e:
                print(e)

    def do_put(self, arg):
        """Send a file to remote: put remote_file [local_file]"""
        params = parse2(arg)
        if params[0] is None:
            print('ERROR: 1 or 2 parameters required', file=sys.stderr)
        else:
            try:
                self.con.put(*params)
            except HTTPError as e:
                print(e)

    def do_exec(self, arg):
        """Execute a command on the remote and print the result: exec cmd param"""
        try:
            r = self.con.exec(arg)
            print(r.read().decode(self.encoding))
        except HTTPError as e:
            print(e)

    def do_iexec(self, arg):
        """Execute an interactive command"""
        try:
            r = self.con.iexec(arg)
            print(r.read().decode(self.encoding))
        except HTTPError as e:
            print(e)

    def do_idata(self, arg):
        """Send input to the interactive command: idata data..."""
        try:
            r = self.con.idata(arg)
            print(r.read().decode(self.encoding))
        except HTTPError as e:
            print(e)

    def do_iend(self, _arg):
        """Close the input channel of the interactive command"""
        try:
            r = self.con.end_cmd()
            print(r.read().decode(self.encoding))
        except HTTPError as e:
            print(e)

    # noinspection PyPep8Naming
    @staticmethod
    def do_EOF(_arg):
        """Quit the program"""
        return True

    @staticmethod
    def do_quit(_arg):
        """Quit the program"""
        return True

    def do_set_encoding(self, arg):
        """Set the server encoding"""
        self.encoding = arg


def parse(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('host', help='Name or address of remote')
    parser.add_argument('port', nargs='?', default=80, type=int,
                        help='Server port (default: 80)')
    parser.add_argument('--server', '-s', default='remo_serv.pem',
                        help='Public key of the server (PEM format)')
    parser.add_argument('--user', '-u', default=getpass.getuser(),
                        help='user name')
    parser.add_argument('--key', '-k', help='File name of user key'
                                            ' (PEM format). Default: user_key.pem')
    parser.add_argument('--label', '-l', help='Label of a certificate '
                                              'private key on a smart card')
    parser.add_argument('--encoding', '-e', default='utf_8',
                        help='encoding of the server')
    params = parser.parse_args(args)
    if params.key is None:
        params.key = params.user + '_key.pem'
    return params


# noinspection PyArgumentList
def run(args):
    params = parse(args)
    with open(params.server, 'rb') as fd:
        remo_pub = serialization.load_pem_public_key(fd.read())
    if params.label is None:
        with open(params.key, 'rb') as fd:
            own_key = serialization.load_pem_private_key(fd.read(), b'foo')
        signer = None
    else:
        own_key = None
        signer = smartcard.get_token(params.label)
    server = 'http://' + params.host
    if params.port != 80:
        server += ':' + str(params.port)

    con = login(server, '/auth', params.user, own_key, signer, remo_pub)
    cmd_loop = CmdLoop(con, server, params.encoding)
    cmd_loop.cmdloop()


if __name__ == '__main__':
    run(sys.argv[1:])
