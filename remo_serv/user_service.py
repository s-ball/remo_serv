#  Copyright (c) 2020 SBA- MIT License


import abc
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448


class UserService(abc.ABC):
    """Abstract class representing a user service."""
    @abc.abstractmethod
    def private(self, user: str) -> ed448.Ed448PrivateKey:
        """Returns the private key for a user (if available)"""
        pass

    @abc.abstractmethod
    def public_data(self, user: str) -> bytes:
        """Returns the bytes for the public key of a user"""
        pass


# noinspection PyArgumentList,PyTypeChecker
class MemoryUserService(UserService):
    """Simple in memory implementation which generates ed448 keys for a
    number of users.
    """
    def __init__(self, *users):
        """Constructor parameters:
        - *users list of users to consider.
        """
        self.users = {}
        for user in users:
            self.users[user] = ed448.Ed448PrivateKey.generate()

    def private(self, user):
        return self.users[user]

    def public_data(self, user):
        pub = self.users[user].public_key()
        return pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat
                                .SubjectPublicKeyInfo)


# noinspection PyTypeChecker
class SqliteUserService(UserService):
    """SQLite3 implementation of a UserService.
    """
    def __init__(self, db):
        """Constructor parameters:
        - db database path
        """
        import sqlite3

        self.con = sqlite3.connect(db, check_same_thread=False)
        self.con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT UNIQUE, key TEXT, pub TEXT) """)

    def add(self, user, *, key: ed448.Ed448PrivateKey = None,
            pub: bytes = None):
        """ Add a new user and its public and/or private keys.
        """
        if key is None and pub is None:
            key = ed448.Ed448PrivateKey.generate()
        if pub is None:
            pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat
                                                .SubjectPublicKeyInfo)

        if key is not None and (pub != key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo)):
            raise ValueError('Inconsistent private and public keys')
        # noinspection PyUnresolvedReferences
        private_data = None if key is None else base64.urlsafe_b64encode(
            key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))
        self.con.execute("INSERT INTO users(user, key, pub) VALUES (?,?,?)",
                         (user, private_data, pub))
        self.con.commit()

    def private(self, user: str) -> ed448.Ed448PrivateKey:
        try:
            data = self.con.execute("SELECT key FROM users WHERE user=?",
                                    (user,)).fetchone()[0]
        except TypeError as e:
            raise LookupError() from e
        return ed448.Ed448PrivateKey.from_private_bytes(
            base64.urlsafe_b64decode(data))

    def public_data(self, user: str) -> bytes:
        try:
            data = self.con.execute("SELECT pub FROM users WHERE user=?",
                                    (user,)).fetchone()[0]
        except TypeError as e:
            raise LookupError() from e
        return data
