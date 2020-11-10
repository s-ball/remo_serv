#  Copyright (c) 2020 SBA- MIT License

"""WSGI application aimed at providing a remote access.

It can only be used in a single process WSGI server
"""

import logging.config
import os.path
import select
import shlex
import socket
import subprocess
import sys

from cryptography import fernet

from . import user_service, __version__
from .crypter import Cryptor
from .http_tools import build_status
from .session_manager import SessionContainer

init_ok = False


# noinspection PyUnboundLocalVariable
def remo_application(environ, start_response):
    """This is the main WSGI application.

    It expects to be called through 2 middlewares:
    - session_manager.SessionContainer for the session management
    - crypter.Cryptor for handling the coding-decoding part

    This one handles the "remo" protocol:
    - /info displays the version of the application (accessible even with
    no valid connection)
    - /auth (handled in Cryptor) for authentication and setting of an
    encrypted channel using a Fernet
    - /get/encrypted_file_name retrieve a local file
    - /put/encrypted_file_name store locally the body of the request
    - /cmd/encrypted_command_line executes the command and returns the
    output (both stdout and stderr) using subprocess.run
    - /icm/encrypted_command_line executes the command in an interactive
    way: the command is executed using subprocess.Popen and left running
    to be later feed with idt and/or edt commands. The optional body
    if send to stdin and immediately available output is returned in the
    response. It currently uses an AF_UNIX socketpair and can only run in
    Posix systems (returns 404 on Windows)
    - /idt feeds the request body to the running interactive command and
    returns the available output
    - /edt same as idt but shutdowns the input of the interactive command

    edt and idt return 400 if no interactive command is running

    Any other command will close a running interactive command
    """
    logger = logging.getLogger(__name__)
    out = [b'']
    headers = [('Content_type', 'text/plain')]
    status = 404
    path = environ.get('PATH_INFO', '/')
    try:
        p, m = environ['SESSION']['__PROCESS__']
        if path not in ('/idt', '/edt'):
            logger.debug('Interactive command closed by %s', path[:4])
            m.close()
            if not p.poll():
                p.terminate()
            del environ['SESSION']['__PROCESS__']
    except (LookupError, TypeError, AttributeError):
        pass
    if path.startswith('/get/'):
        try:
            filename = fernet.Fernet(environ['SESSION'].key).decrypt(
                path[5:].encode()).decode()
            logger.debug(f"get {filename}")
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
            logger.warning('Error get', exc_info=sys.exc_info())
    elif path.startswith('/put/'):
        filename = None
        try:
            filename = fernet.Fernet(environ['SESSION'].key).decrypt(
                path[5:].encode()).decode()
            logger.debug('put %s', filename)
            with open(filename, 'wb') as fd:
                while True:
                    data = environ['wsgi.input'].read(16384)
                    if len(data) == 0:
                        break
                    fd.write(data)
            status = 200
        except (LookupError, AttributeError, ValueError, fernet.InvalidToken):
            status = 400
            logger.warning('Error put', exc_info=sys.exc_info())
            try:
                if filename is not None:
                    os.remove(filename)
            except OSError:
                pass
        except OSError:
            status = 500
            logger.warning('Internal error put', exc_info=sys.exc_info())
            try:
                os.remove(filename)
            except OSError:
                pass
    elif path == '/info':
        out = [f'remo_serv {__version__} here'.encode()]
        status = 200
    elif path.startswith('/cmd/'):
        try:
            cmd = fernet.Fernet(environ['SESSION'].key).decrypt(
                path[5:].encode()).decode()
        except (LookupError, AttributeError, ValueError, fernet.InvalidToken):
            status = 403
            logger.warning('Error cmd', exc_info=sys.exc_info())
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
                logger.warning('Internal error cmd %s', cmd, exc_info=sys.exc_info())
    elif path.startswith('/icm/'):
        try:
            cmd = fernet.Fernet(environ['SESSION'].key).decrypt(
                path[5:].encode()).decode()
        except (LookupError, AttributeError, ValueError, fernet.InvalidToken):
            status = 403
            logger.warning('Error icmd', exc_info=sys.exc_info())
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
                status = 500
                logger.warning('Internal error icmd %s', cmd, exc_info=sys.exc_info())
    elif path == '/idt':
        try:
            p, m = environ['SESSION']['__PROCESS__']
        except (LookupError, TypeError):
            status = 400
            logger.warning('No running icmd')
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
                logger.warning('Internal error idt', exc_info=sys.exc_info())
            pass
    elif path == '/edt':
        try:
            p, m = environ['SESSION']['__PROCESS__']
        except (LookupError, TypeError):
            status = 400
            logger.warning('No running icmd')
        if status != 400:
            try:
                m.shutdown(socket.SHUT_WR)

                def chunk_sock(s):
                    while True:
                        d = s.recv(8192)
                        if len(d) == 0:
                            break
                        yield d

                out = chunk_sock(m)

                status = 200
                del environ['SESSION']['__PROCESS__']
            except RuntimeError:
                status = 500
                logger.warning('Internal error edt', exc_info=sys.exc_info())

    if out == [b'']:
        headers.append(('Content-Length', '0'))
    start_response(build_status(status), headers)
    return out


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


sessionContainer: SessionContainer


def application(environ, start_response):
    """Main application exposed to the WSGI server."""
    global init_ok
    global sessionContainer
    if not init_ok:
        conf = {'debug': environ.get('remo_serv.debug', False)}
        if 'remo_serv.log' in environ:
            conf['log'] = environ['remo_serv.log']
        config_logging(conf)
        crypt = Cryptor(remo_application, environ['KEYFILE'],
                        build_service(environ['USER_SERVICE']))
        timeout = float(environ['remo_serv.timeout'])

        sessionContainer = SessionContainer(crypt, timeout=timeout)
        init_ok = True

    if environ['wsgi.multiprocess']:
        start_response(build_status(500), {'Content-type': 'text/plain',
                                           'Content-length': '0'})
        logging.getLogger(__name__).critical(
            'Cannot run in a multiprocess server')

    return sessionContainer(environ, start_response)
