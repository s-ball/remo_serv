#  Copyright (c) 2020 SBA- MIT License

import time
from unittest import TestCase
from unittest.mock import Mock

from remo_serv.non_block_wrapper import NonBlockWrapper


class TestNonBlockWrapper(TestCase):
    def setUp(self) -> None:
        self.base = Mock()
        self.base.read = Mock()

    def tearDown(self) -> None:
        try:
            self.w.stop = True
        except AttributeError:
            pass

    def test_readable(self):
        self.base.read.return_value = b''
        self.w = NonBlockWrapper(self.base)
        self.assertTrue(self.w.readable())

    def test_all_ok(self):
        self.base.read.side_effect = [b'abcd', b'']
        self.w = NonBlockWrapper(self.base)
        time.sleep(.1)
        self.assertEqual(b'ab', self.w.read(2))
        self.assertEqual(b'cd', self.w.read())
        self.assertEqual(b'', self.w.read())
        self.assertEqual(2, self.base.read.call_count)

    def test_tempo(self):
        def tempo_data():
            data = [(.2, b'ab'), (.2, b'cd'), (0, b'')]
            it = iter(data)

            def f():
                timeout, val = next(it)
                time.sleep(timeout)
                return val
            return f
        self.base.read.side_effect = tempo_data()
        self.w = NonBlockWrapper(self.base)
        a = self.w.read()
        self.assertEqual(None, a)
        time.sleep(.3)
        a = self.w.read()
        self.assertEqual(b'ab', a)
        a = self.w.read()
        self.assertEqual(None, a)
        time.sleep(.2)
        a = self.w.read()
        self.assertEqual(b'cd', a)
        self.assertTrue(self.w.ended)
        self.assertEqual(b'', self.w.read())

    def test_agg(self):
        def tempo_data():
            data = [(.2, b'ab'), (.2, b'cd'), (0, b'')]
            it = iter(data)

            def f():
                timeout, val = next(it)
                time.sleep(timeout)
                return val
            return f
        self.base.read.side_effect = tempo_data()
        self.w = NonBlockWrapper(self.base)
        time.sleep(.5)
        self.assertTrue(self.w.ended)
        a = self.w.read()
        self.assertEqual(b'abcd', a)
