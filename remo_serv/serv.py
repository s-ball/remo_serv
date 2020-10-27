#  Copyright (c) 2020 SBA- MIT License

from cheroot.wsgi import Server  # , PathInfoDispatcher
import toml
import logging.config
import argparse
import os.path
import sys

from .session_manager import SessionContainer


def hello_app(environ, start_response):
    if environ['PATH_INFO'] == '/stop' and 'SERVER' in environ:
        environ['SERVER'].stop()
    headers = [('Content_type', 'text/plain')]
    start_response('200 OK', headers)
    return [b'Hello']


def parse(args):
    parser = argparse.ArgumentParser(os.path.basename(args[0]))
    parser.add_argument('--conf', '-c', help='Configuration file')
    parser.add_argument('--port', '-p', help='Port', type=int)
    parser.add_argument('--interface', '-i', help='Interface')
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


def run(args):
    conf = parse(args)
    config_logging(conf)
    logger = logging.getLogger()
    session_container = SessionContainer(hello_app, conf['timeout'])
    logger.info('start')
    server = Server((conf['host'], conf['port']), session_container)
    session_container.server = server
    server.start()


if __name__ == '__main__':
    run(sys.argv)
