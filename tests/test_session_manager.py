#  Copyright (c) 2020 SBA- MIT License

from unittest import TestCase

import os.path
import sys
import time

from unittest.mock import Mock


def get_session_manager():
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from remo_serv import session_manager
    return session_manager


session_manager = get_session_manager()


class TestSession(TestCase):
    """Controls that a session is a valid MutableMapping"""
    def setUp(self) -> None:
        self.session = session_manager.Session('foo')

    def test_initial(self):
        self.assertIsNone(self.session.key)
        self.assertEqual(0, len(self.session))
        cur = time.time()
        self.assertAlmostEqual(cur, self.session.timestamp, delta=0.5)
        self.assertEqual('foo', self.session.id)

    def test_add(self):
        self.session['foo'] = 'bar'
        self.session['fee'] = 'baz'
        self.assertEqual(2, len(self.session))
        self.assertEqual('bar', self.session['foo'])

    def test_wrong_key(self):
        self.session['foo'] = 'bar'
        self.assertIsNone(self.session.get('fee'))
        with self.assertRaises(KeyError):
            # noinspection PyStatementEffect
            self.session['fee']

    def test_del(self):
        self.session['foo'] = 'bar'
        self.session['fee'] = 'baz'
        del self.session['fee']
        self.assertEqual(1, len(self.session))

    def test_iter(self):
        self.session['foo'] = 'bar'
        self.session['fee'] = 'baz'
        self.assertEqual({'foo', 'fee'}, set(i for i in self.session))


def app_test(_environ, start_response):
    start_response('200 OK', [])
    return [b'foo', b'bar']


class TestSessionContainer(TestCase):
    def setUp(self) -> None:
        self.data = [b'foo', b'bar']
        self.app = Mock(app_test, side_effect=app_test)
        self.container = session_manager.SessionContainer(self.app)

    def test_auto_expire(self):
        container = session_manager.SessionContainer(self.app, 1, 1)
        container.get_session(None, True)
        self.assertEqual(1, len(container.sessions))
        time.sleep(1.5)
        self.assertEqual(0, len(container.sessions))

    def test_simple_expire(self):
        container = session_manager.SessionContainer(self.app, 1)
        session = container.get_session(None, True)
        time.sleep(1.5)
        s2 = container.get_session(session.id)
        self.assertIsNone(s2)
        self.assertEqual(0, len(container.sessions))

    def test_expire_and_new(self):
        container = session_manager.SessionContainer(self.app, 1)
        session = container.get_session(None, True)
        time.sleep(1.5)
        s2 = container.get_session(session.id, True)
        self.assertNotEqual(session.id, s2.id)
        self.assertEqual(1, len(container.sessions))

    def test_no_cookie(self):
        self.assertIsNone(session_manager.get_session_id({}))

    def test_simple_cookie(self):
        env = {'HTTP_COOKIE': 'SESSION_ID=foo'}
        self.assertEqual('foo', session_manager.get_session_id(env))

    def test_multi_cookies(self):
        env = {'HTTP_COOKIE': 'SESSION_ID=foo; Expire=200; bar=abra'}
        self.assertEqual('foo', session_manager.get_session_id(env))

    def test_app_new_session(self):
        start_response = Mock()
        environ = {}
        ret = self.container(environ, start_response)
        self.app.assert_called_once()
        self.assertEqual(environ, self.app.call_args[0][0])
        self.assertTrue(isinstance(environ['SESSION'], session_manager.Session))
        self.assertEqual(self.data, list(ret))

    def test_app_expired_session(self):
        start_response = Mock()
        environ = {'HTTP_COOKIE': 'SESSION_ID=foo'}
        self.container(environ, start_response)
        session = environ['SESSION']
        # noinspection PyUnresolvedReferences
        self.assertNotEqual('foo', session.id)

    def test_app_old_session(self):
        start_response = Mock()
        session = self.container.get_session('foo', True)
        environ = {'HTTP_COOKIE': 'SESSION_ID=foo'}
        self.container(environ, start_response)
        self.assertEqual(session, environ['SESSION'])

    def test_start_response(self):
        start_response = Mock()
        environ = {}
        self.container(environ, start_response)
        start_response.assert_called_once()
        self.assertEqual('200 OK',  start_response.call_args[0][0])
        session_id = environ['SESSION'].id
        self.assertEqual([('Set-Cookie', f'SESSION_ID={session_id}')],
                         start_response.call_args[0][1])

    def test_build_session(self):
        s1 = self.container.get_session(None, True)
        env = {'SESSION': s1}
        s2 = self.container.session_build(env)
        self.assertNotEqual(s1.id, s2.id)
        self.assertEqual(1, len(self.container.sessions))
        self.assertEqual(s2, env['SESSION'])

    def test_build_session_missing(self):
        env = {}
        s2 = self.container.session_build(env)
        self.assertIsInstance(s2, session_manager.Session)
        self.assertEqual(1, len(self.container.sessions))
        self.assertEqual(s2, env['SESSION'])

    def test_pass_server(self):
        self.container.server = Mock()
        env = {}
        self.container(env, Mock())
        self.assertEqual(self.container.server, env['SERVER'])

    def test_refresh_session(self):
        session = self.container.get_session(None, True)
        session.timestamp -= 120
        env = {'HTTP_COOKIE': 'SESSION_ID=' + session.id}
        now = time.time()
        self.container(env, Mock())
        self.assertGreaterEqual(session.timestamp, now)

    def test_app_raise(self):
        start_response = Mock()
        e = RuntimeError()
        self.app.side_effect = e
        env = {}
        with self.assertRaises(type(e)):
            self.container(env, start_response)
