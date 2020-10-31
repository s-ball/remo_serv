#  Copyright (c) 2020 SBA- MIT License

from unittest import TestCase
from remo_serv.user_service import SqliteUserService

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448

import base64


class TestSqliteUserService(TestCase):
    def setUp(self) -> None:
        self.user_service = SqliteUserService(':memory:')

    def test_none(self):
        self.user_service.add('foo')
        self.assertEqual(self.user_service.public_data('foo'),
                         self.user_service.private('foo').public_key()
                         .public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw))

    def test_private(self):
        key = ed448.Ed448PrivateKey.generate()
        self.user_service.add('foo', key=key)
        self.assertEqual(self.user_service.public_data('foo'),
                         self.user_service.private('foo').public_key()
                         .public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw))

        self.assertEqual(self.user_service.public_data('foo'),
                         key.public_key().public_bytes(
                             serialization.Encoding.Raw,
                             serialization.PublicFormat.Raw))

    def test_public(self):
        key = ed448.Ed448PrivateKey.generate()
        self.user_service.add('foo', pub=key.public_key())
        self.assertEqual(self.user_service.public_data('foo'),
                         key.public_key().public_bytes(
                             serialization.Encoding.Raw,
                             serialization.PublicFormat.Raw))

    def test_both_ok(self):
        key = ed448.Ed448PrivateKey.generate()
        self.user_service.add('foo', key=key, pub=key.public_key())
        self.assertEqual(self.user_service.public_data('foo'),
                         self.user_service.private('foo').public_key()
                         .public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw))
        self.assertEqual(self.user_service.public_data('foo'),
                         key.public_key()
                         .public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw))

    def test_both_ko(self):
        key = ed448.Ed448PrivateKey.generate()
        key2 = ed448.Ed448PrivateKey.generate()
        with self.assertRaises(ValueError):
            self.user_service.add('foo', key=key, pub=key2.public_key())

    def test_not_found(self):
        self.user_service.add('foo')
        with self.assertRaises(LookupError):
            self.user_service.private('bar')
        with self.assertRaises(LookupError):
            self.user_service.public_data('bar')
