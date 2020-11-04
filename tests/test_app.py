#  Copyright (c) 2020 SBA- MIT License

from pyfakefs.fake_filesystem_unittest import TestCase
from unittest.mock import Mock, patch

import os.path
import itertools
import time
from cryptography import fernet

from remo_serv.serv import application
from remo_serv.session_manager import Session


# noinspection PyUnresolvedReferences,PyTypeChecker
class MyTestCase(TestCase):
    def setUp(self) -> None:
        self.setUpPyfakefs()
        self.environ = {'SESSION': Session('sess')}
        self.session_key = fernet.Fernet.generate_key()
        self.environ['SESSION'].key = self.session_key
        self.fs.create_file('/data')
        with open('/data', 'wb') as fd:
            for _ in range(128):
                fd.write(bytes(range(256)))

    def test_data(self):
        self.assertTrue(os.path.exists('/data'))
        st = os.stat('/data')
        self.assertEqual(32768, st.st_size)

    def test_stop(self):
        self.environ['SERVER'] = Mock()
        self.environ['PATH_INFO'] = '/stop'
        start_response = Mock()
        application(self.environ, start_response)
        start_response.assert_called_once()
        self.assertEqual('200 OK', start_response.call_args[0][0])
        # noinspection PyUnresolvedReferences
        self.environ['SERVER'].stop.assert_called_once()

    def test_get(self):
        codec = fernet.Fernet(self.session_key)
        self.environ['PATH_INFO'] = '/get/' + codec.encrypt('/data'.encode()).decode()
        start_response = Mock()
        out = application(self.environ, start_response)
        start_response.assert_called_once()
        self.assertEqual('200 OK', start_response.call_args[0][0])
        with open('/data', 'rb') as fd:
            for chunk in out:
                self.assertEqual(fd.read(len(chunk)), chunk)

    def test_put(self):
        codec = fernet.Fernet(self.session_key)
        self.environ['PATH_INFO'] = '/put/' + codec.encrypt('/upload'.encode()).decode()
        self.environ['wsgi.input'] = Mock()
        self.environ['wsgi.input'].read = Mock(side_effect=itertools.chain(
            (bytes(256) * 8 for _ in range(12)), (b'',)))
        start_response = Mock()
        application(self.environ, start_response)
        start_response.assert_called_once()
        self.assertEqual('200 OK', start_response.call_args[0][0])
        st = os.stat('/upload')
        self.assertEqual(24 * 1024, st.st_size)

    def test_put_wrong(self):
        codec = fernet.Fernet(self.session_key)
        self.environ['PATH_INFO'] = '/put/' + codec.encrypt('/upload'.encode()).decode()
        self.environ['wsgi.input'] = Mock()
        self.environ['wsgi.input'].read = Mock(side_effect=fernet.InvalidToken)
        start_response = Mock()
        application(self.environ, start_response)
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('400'))
        self.assertFalse(os.path.exists('/upload'))

    def test_exec(self):
        codec = fernet.Fernet(self.session_key)
        self.environ['PATH_INFO'] = '/cmd/' + codec.encrypt('do something'.encode()).decode()
        self.environ['wsgi.input'] = Mock()
        start_response = Mock()
        with patch('subprocess.run') as run:
            proc = Mock()
            proc.stdout = b'foo'
            run.return_value = proc
            out = list(application(self.environ, start_response))
            self.assertEqual(['do', 'something'], list(run.call_args[0][0]))
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('200'))
        self.assertEqual([b'foo'], out)

    def test_exec_err(self):
        codec = fernet.Fernet(self.session_key)
        self.environ['PATH_INFO'] = '/cmd/' + codec.encrypt('do something'.encode()).decode()
        self.environ['wsgi.input'] = Mock()
        start_response = Mock()
        with patch('subprocess.run') as run:
            run.side_effect = RuntimeError
            list(application(self.environ, start_response))
            self.assertEqual(['do', 'something'], list(run.call_args[0][0]))
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('500'))

    def test_exec_wrong(self):
        self.environ['PATH_INFO'] = '/cmd/do+something'
        self.environ['wsgi.input'] = Mock()
        start_response = Mock()
        with patch('subprocess.run') as run:
            run.side_effect = RuntimeError
            list(application(self.environ, start_response))
            run.assert_not_called()
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('403'))

    def test_icmd(self):
        codec = fernet.Fernet(self.session_key)
        self.environ['PATH_INFO'] = '/icm/' + codec.encrypt('do something'.encode()).decode()
        self.environ['wsgi.input'] = Mock()
        start_response = Mock()
        with patch('subprocess.Popen') as run:
            def tempo_data():
                data = [(0, b'ab'), (.2, b'cd'), (0, b'')]
                it = iter(data)

                def f(*_args):
                    timeout, val = next(it)
                    time.sleep(timeout)
                    return val

                return f
            proc = Mock()
            proc.stdout = Mock()
            proc.stdout.read = Mock(side_effect=tempo_data())
            run.return_value = proc
            out = list(application(self.environ, start_response))
            self.assertEqual(['do', 'something'], list(run.call_args[0][0]))
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('200'))
        self.assertTrue(out in ([b'ab'], [b'']))
        self.assertEqual(proc, self.environ['SESSION']['__PROCESS__'])

    def test_idt(self):
        self.test_icmd()
        time.sleep(.3)
        self.environ['PATH_INFO'] = '/idt'
        self.environ['wsgi.input'] = Mock()
        self.environ['wsgi.input'].read = Mock(return_value=b'')
        start_response = Mock()
        out = list(application(self.environ, start_response))
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('200'))
        self.assertTrue(out[0].endswith(b'cd'))
        self.assertTrue('__PROCESS__' in self.environ['SESSION'])

    def test_idt_exhaust(self):
        self.test_icmd()
        time.sleep(.3)
        self.test_idt()
        self.environ['PATH_INFO'] = '/idt'
        self.environ['wsgi.input'] = Mock()
        self.environ['wsgi.input'].read = Mock(return_value=b'')
        start_response = Mock()
        out = list(application(self.environ, start_response))
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('200'))
        self.assertEqual([b''], out)
        self.assertFalse('__PROCESS__' in self.environ['SESSION'])

    def test_edt(self):
        self.test_icmd()
        time.sleep(.3)
        self.environ['PATH_INFO'] = '/edt'
        self.environ['wsgi.input'] = Mock()
        self.environ['wsgi.input'].read = Mock(return_value=b'')
        start_response = Mock()
        out = list(application(self.environ, start_response))
        start_response.assert_called_once()
        self.assertTrue(start_response.call_args[0][0].startswith('200'))
        self.assertTrue(out[0].endswith(b'cd'))
        self.assertTrue('__PROCESS__' in self.environ['SESSION'])
        self.assertTrue(self.environ['SESSION']['__PROCESS__'].stdin.closed)
