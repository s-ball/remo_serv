#  Copyright (c) 2020 SBA- MIT License

from unittest import TestCase
import sys
import os.path


def get_tools():
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from remo_serv import http_tools
    return http_tools


tools = get_tools()


class TestTools(TestCase):
    def test_build_ok(self):
        self.assertEqual('200 OK', tools.build_status(200))

    def test_build_forbidden(self):
        self.assertEqual('403 Forbidden', tools.build_status(403))
