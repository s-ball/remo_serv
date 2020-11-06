#  Copyright (c) 2020 SBA- MIT License

import argparse
import logging.config
import os.path
import select
import shlex
import socket
import subprocess
import sys

import toml
from cheroot.wsgi import Server  # , PathInfoDispatcher
from cryptography import fernet

from . import user_service, __version__
from .crypter import Cryptor
from .http_tools import build_status
from .session_manager import SessionContainer


# noinspection PyUnboundLocalVariable
def application(environ, start_response):
    out = [b'']
    headers = [('Content_type', 'text/plain')]
    status = 404
    path = environ.get('PATH_INFO', '/')
    try:
        p, m = environ['SESSION']['__PROCESS__']
        if path not in ('/idt', '/edt'):
            m.close()
            if not p.poll():
                p.terminate()
            del environ['SESSION']['__PROCESS__']
    except (LookupError, TypeError, AttributeError):
        pass
    if path == '/stop' and 'SERVER' in environ:
        environ['SERVER'].stop()
        status = 200
    elif path.startswith('/get/'):
        try:
            filename = fernet.Fernet(environ['SESSION'].key).decrypt(
                path[5:].encode()).decode()

            def chunk(file):
                with open(file, 'rb') as cfd:
                    while True:
                        d = cfd.read(16384)
                        if len(d) == 0:
                            break
                        yield d

            out = chunk(filename)
            status = 200
        except (fernet.InvalidToken, OSError):
            status = 400
    elif path.startswith('/put/'):
        filename = None
        try:
            filename = fernet.Fernet(environ['SESSION'].key).decrypt(
                path[5:].encode()).decode()
            with open(filename, 'wb') as fd:
                while True:
                    data = environ['wsgi.input'].read(16384)
                    if len(data) == 0:
                        break
                    fd.write(data)
            status = 200
        except (LookupError, AttributeError, ValueError, fernet.InvalidToken):
            status = 400
            try:
                if filename is not None:
                    os.remove(filename)
            except OSError:
                pass
        except OSError:
            status = 500
            try:
                os.remove(filename)
            except OSError:
                pass
    elif path == '/':
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

                # noinspection PyTypeChecker
                out = [p.stdout]
                status = 200

            except RuntimeError:
                status = 500
    elif path.startswith('/icm/'):
        try:
            cmd = fernet.Fernet(environ['SESSION'].key).decrypt(
                path[5:].encode()).decode()
        except (LookupError, AttributeError, ValueError, fernet.InvalidToken):
            status = 403
        if status != 403:
            try:
                m, s = socket.socketpair(socket.AF_UNIX)
                data = environ['wsgi.input'].read()
                # noinspection PyTypeChecker
                p = subprocess.Popen(shlex.split(cmd),
                                     bufsize=0,
                                     stdin=s,
                                     stdout=s,
                                     stderr=s)
                m.send(data)
                if [m] == select.select([m], [], [], .1)[0]:
                    data = m.recv(8192)
                    if data == b'':
                        p = None
                else:
                    data = b''
                out = [data]
                status = 200
                if p is not None:
                    environ['SESSION']['__PROCESS__'] = (p, m)
            except AttributeError:
                status = 404
            except RuntimeError as e:
                print(e)
                status = 500
    elif path == '/idt':
        try:
            p, m = environ['SESSION']['__PROCESS__']
        except (LookupError, TypeError):
            status = 400
        if status != 400:
            try:
                data = environ['wsgi.input'].read()
                if len(data) > 0:
                    m.send(data)
                sel = select.select([m], [], [], .1)
                if [m] == sel[0]:
                    data = m.recv(8192)
                    if data == b'':
                        p = None
                else:
                    data = b''
                out = [data]
                status = 200
                if p is None:
                    del environ['SESSION']['__PROCESS__']
            except RuntimeError:
                status = 500
            pass
    elif path == '/edt':
        try:
            p, m = environ['SESSION']['__PROCESS__']
        except (LookupError, TypeError):
            status = 400
        if status != 400:
            try:
                m.shutdown(socket.SHUT_WR)

                if [m] == select.select([m], [], [], .1)[0]:
                    data = m.recv(8192)
                    if data == b'':
                        p = None
                else:
                    data = b''
                out = [data]
                status = 200
                if p is None:
                    del environ['SESSION']['__PROCESS__']
            except RuntimeError:
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
    elif 'user-service' not in conf:
        conf['user-service'] = 'SqliteUserService:users_db.sqlite'
    if ns.key_file is not None:
        conf['key-file'] = ns.key_file
    elif 'key-file' not in conf:
        conf['key-file'] = 'remo_serv_key.pem'
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
    crypt = Cryptor(application, conf['key-file'], serv)
    session_container = SessionContainer(crypt, conf['timeout'])
    logger.info('start')
    server = Server((conf['host'], conf['port']), session_container)
    session_container.server = server
    server.start()


if __name__ == '__main__':
    run(sys.argv)
