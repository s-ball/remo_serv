#  Copyright (c) 2020 SBA- MIT License

import argparse
import os.path
import sys

import toml
from cheroot.wsgi import Server  # , PathInfoDispatcher

from .app import application


def parse(args):
    parser = argparse.ArgumentParser(os.path.basename(args[0]))
    parser.add_argument('--conf', '-c', help='Configuration file')
    parser.add_argument('--port', '-p', help='Port', type=int)
    parser.add_argument('--interface', '-i', help='Interface')
    parser.add_argument('--user-service', '-u', help='User service')
    parser.add_argument('--key-file', '-k', help='PEM main key file')
    parser.add_argument('--log', '-l', help='logging configuration file')
    parser.add_argument('--session', '-s', type=int,
                        help='Session timeout (seconds)')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Add debugging traces in log')
    ns = parser.parse_args(args[1:])
    conf = toml.load(ns.conf) if ns.conf is not None else {}
    if ns.port is not None:
        conf['port'] = ns.port
    elif 'port' not in conf:
        conf['port'] = 8080
    if ns.interface is not None:
        conf['host'] = ns.interface
    elif 'host' not in conf:
        conf['host'] = '0.0.0.0'
    if ns.session is not None:
        conf['timeout'] = ns.session
    elif 'timeout' not in conf:
        conf['timeout'] = 600
    if ns.log is not None:
        conf['log'] = ns.log
    conf['debug'] = bool(ns.debug)
    if ns.user_service is not None:
        conf['user-service'] = ns.user_service
    elif 'user-service' not in conf:
        conf['user-service'] = 'SqliteUserService:users_db.sqlite'
    if ns.key_file is not None:
        conf['key-file'] = ns.key_file
    elif 'key-file' not in conf:
        conf['key-file'] = 'remo_serv_key.pem'
    return conf


class App:
    def __init__(self, conf):
        self.environ = {
            'KEYFILE': conf['key-file'],
            'USER_SERVICE': conf['user-service'],
            'DEBUG': conf['debug'],
        }
        if 'log' in conf:
            self.environ['LOGGING'] = conf('log')

    def __call__(self, environ, start_response):
        environ.update(self.environ)
        return application(environ, start_response)


def run(args):
    conf = parse(args)
    server = Server((conf['host'], conf['port']), App(conf))
    server.start()


if __name__ == '__main__':
    run(sys.argv)
