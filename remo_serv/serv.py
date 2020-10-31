#  Copyright (c) 2020 SBA- MIT License

import argparse
import logging.config
import os.path
import sys
import io

import toml
from cheroot.wsgi import Server  # , PathInfoDispatcher

from .crypter import Cryptor
from .http_tools import build_status
from .session_manager import SessionContainer
from . import user_service, __version__

from cryptography import fernet

import subprocess, shlex


def hello_app(environ, start_response):
    out = [b'']
    headers = [('Content_type', 'text/plain')]
    status = 404
    path = environ.get('PATH_INFO', '/')
    if path == '/stop' and 'SERVER' in environ:
        environ['SERVER'].stop()
        status = 200
    elif path == '/get':
        filename = environ['wsgi.input'].read().decode()

        def chunk(file):
            with open(file, 'rb') as cfd:
                while True:
                    d = cfd.read(16384)
                    if len(d) == 0:
                        break
                    yield d
        out = chunk(filename)
        status = 200
    elif path == '/put':
        data = environ['wsgi.input'].read(16384)
        try:
            ix = data.index(b'\r\n')
            filename = data[ix:]
            with open(filename, 'wb') as fd:
                fd.write(data[ix+2])
                while True:
                    data = environ['wsgi.input'].read(16384)
                    if len(data) == 0:
                        break
                    fd.write(data)
            status = 200
        except ValueError:
            status = 400
        except OSError:
            status = 500
    elif path == '/info':
        out = [f'remo_serv {__version__} here'.encode()]
        status = 200
    elif path.startswith('/cmd/'):
        try:
            cmd = fernet.Fernet(environ['SESSION'].key).decrypt(
                path[5:].encode()).decode()
        except (LookupError, AttributeError, ValueError, fernet.InvalidToken):
            status = 403
        if status != 403:
            try:
                data = environ['wsgi.input'].read()
                p = subprocess.run(shlex.split(cmd),
                                   input=data,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)

                data = p.stdout
                out = [data]
                status = 200

            except RuntimeError as e:
                print(e)
                status = 500

    if out == [b'']:
        headers.append(('Content-Length', '0'))
    start_response(build_status(status), headers)
    return out


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
    elif 'user-service' not in  conf:
        conf['user-service'] = 'SqliteUserService:users_db.sqlite'
    if ns.key_file is not None:
        conf['key-file'] = ns.key_file
    elif 'key-file' not in conf:
        conf['key-file'] = 'remo_serv_key.PEM'
    return conf


def config_logging(conf):
    if 'log' in conf:
        logging.config.fileConfig(conf.log, disable_existing_loggers=False)
    else:
        stream = sys.stdout
        logging.config.dictConfig({
            'version': 1,
            'root': {
                'handlers': ['console'],
                'level': 'WARNING'
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'stream': stream,
                    'formatter': 'deft',
                    'level': 'NOTSET',
                }
            },
            'formatters': {
                'deft': {
                    'format': '%(asctime)s: %(levelname)s %(name)s - %(message)s'
                }
            },
            'disable_existing_loggers': False,
        })
    if conf['debug']:
        logging.getLogger().setLevel(logging.DEBUG)


def build_service(spec: str) -> user_service.UserService:
    try:
        spec_mod, *spec_data = spec.split(':')
        cls = getattr(user_service, spec_mod)
        serv = cls(*spec_data)
    except (ValueError, AttributeError, TypeError, RuntimeError) as e:
        raise ValueError(f'wrong user-service {spec}') from e
    return serv


def run(args):
    conf = parse(args)
    config_logging(conf)
    logger = logging.getLogger()
    if 'user-service' not in conf:
        logger.critical('No user service set: fatal')
        sys.exit(1)

    serv = build_service(conf['user-service'])
    crypt = Cryptor(hello_app, conf['key-file'], serv)
    session_container = SessionContainer(crypt, conf['timeout'])
    logger.info('start')
    server = Server((conf['host'], conf['port']), session_container)
    session_container.server = server
    server.start()


if __name__ == '__main__':
    run(sys.argv)
