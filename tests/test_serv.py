#  Copyright (c) 2020 SBA- MIT License

import unittest
import sys
import os.path
from unittest.mock import Mock
import http
import logging


def get_serv():
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from remo_serv import serv
    return serv


serv = get_serv()


class TestServ(unittest.TestCase):
    def test_hello_resp(self):
        start_response = Mock()
        environ = {'PATH_INFO': '/'}
        serv.application(environ, start_response)
        ok = http.HTTPStatus.OK
        # noinspection PyUnresolvedReferences
        ok = '{} {}'.format(ok.value, ok.phrase)
        self.assertEqual(1, len(environ))
        start_response.assert_called_once()
        self.assertEqual(ok, start_response.call_args[0][0])

    def test_parse_no_conf(self):
        conf = serv.parse('foo -i localhost -s 120'.split())
        self.assertEqual('localhost', conf['host'])
        self.assertEqual(8080, conf['port'])
        self.assertEqual(120, conf['timeout'])

    def test_with_conf(self):
        file = os.path.join(os.path.dirname(__file__), 'conf_test.toml')
        conf = serv.parse(('foo --conf=' + file).split())
        self.assertEqual('my_host', conf['host'])
        self.assertEqual(8080, conf['port'])
        self.assertEqual(500, conf['timeout'])
        self.assertEqual(False, conf['debug'])

    def test_override_conf(self):
        file = os.path.join(os.path.dirname(__file__), 'conf_test.toml')
        conf = serv.parse(f'foo --session=1200 --conf={file} -d'.split())
        self.assertEqual('my_host', conf['host'])
        self.assertEqual(8080, conf['port'])
        self.assertEqual(1200, conf['timeout'])
        self.assertEqual(True, conf['debug'])

    def test_logging_deft(self):
        serv.config_logging({'debug': False})
        root = logging.getLogger()
        self.assertEqual(1, len(root.handlers))
        self.assertEqual(logging.WARNING, root.getEffectiveLevel())

    def test_logging_debug(self):
        serv.config_logging({'debug': True})
        root = logging.getLogger()
        self.assertEqual(logging.DEBUG, root.getEffectiveLevel())


if __name__ == '__main__':
    unittest.main()
