#  Copyright (c) 2020 SBA- MIT License


import abc
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448


class UserService(abc.ABC):
    @abc.abstractmethod
    def private(self, user: str) -> ed448.Ed448PrivateKey:
        pass

    @abc.abstractmethod
    def public_data(self, user: str) -> bytes:
        pass


# noinspection PyArgumentList,PyTypeChecker
class MemoryUserService(UserService):
    def __init__(self, *users):
        self.users = {}
        for user in users:
            self.users[user] = ed448.Ed448PrivateKey.generate()

    def private(self, user):
        return self.users[user]

    def public_data(self, user):
        pub = self.users[user].public_key()
        return pub.public_bytes(serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw)


# noinspection PyTypeChecker
class SqliteUserService(UserService):
    def __init__(self, db):
        import sqlite3

        self.con = sqlite3.connect(db, check_same_thread=False)
        self.con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT UNIQUE, key TEXT, pub TEXT) """)

    def add(self, user, *, key: ed448.Ed448PrivateKey = None,
            pub: ed448.Ed448PublicKey = None):
        if key is None and pub is None:
            key = ed448.Ed448PrivateKey.generate()
        if pub is None:
            pub = key.public_key()

        if key is not None and (pub.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                                != key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw)):
            raise ValueError('Inconsistent private and public keys')
        pub_data = base64.urlsafe_b64encode(pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        # noinspection PyUnresolvedReferences
        private_data = None if key is None else base64.urlsafe_b64encode(
            key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))
        self.con.execute("INSERT INTO users(user, key, pub) VALUES (?,?,?)",
                         (user, private_data, pub_data))

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
