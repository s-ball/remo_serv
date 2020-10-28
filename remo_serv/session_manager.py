#  Copyright (c) 2020 SBA- MIT License

import threading

import secrets
import time
import collections.abc
from typing import Optional
import logging

logger = logging.getLogger(__name__)

cookie_name = 'SESSION_ID='
SESSIONS = {}


class Session(collections.abc.MutableMapping):
    def __init__(self, s_id):
        self.id = s_id
        self.timestamp = time.time()
        self.content = {}
        self.key = None
        self.user = None

    def refresh(self):
        self.timestamp = time.time()

    def __getitem__(self, item):
        return self.content[item]

    def __setitem__(self, key, value):
        self.content[key] = value

    def __delitem__(self, key):
        del self.content[key]

    def __len__(self):
        return len(self.content)

    def __iter__(self):
        return iter(self.content)


class SessionContainer:
    def __init__(self, app, timeout=600, delay=60):
        self.app = app
        self.sessions = {}
        self.timeout = timeout
        self.lock = threading.Lock()
        self.server = None
        if delay is not None:
            self.expire_thread = threading.Thread(
                target=self._do_expire, args=(delay,), daemon=True)
            self.expire_thread.start()

    def get_session(self, session_id, create=False) -> Optional[Session]:
        with self.lock:
            now = time.time()
            try:
                session = self.sessions[session_id]
                if now - session.timestamp > self.timeout:
                    logger.debug('%s expired', session_id)
                    session = None
                    del self.sessions[session_id]
                else:
                    logger.debug('%s refreshed', session_id)
                    session.refresh()
            except LookupError:
                session = None
            if create and session is None:
                logger.debug('ask new id for %s', session_id)
                session_id = secrets.token_urlsafe(8)
                logger.debug('got %s', session_id)
                session = Session(session_id)
                self.sessions[session_id] = session
            return session

    def _do_expire(self, delta):
        while True:
            with self.lock:
                now = time.time()
                expired = [session for session in self.sessions.values()
                           if now - session.timestamp > self.timeout]
                for s in expired:
                    del self.sessions[s.id]
            time.sleep(delta)

    def session_build(self, environ):
        s = self.get_session(None, True)
        try:
            del self.sessions[environ['SESSION'].id]
        except (LookupError, AttributeError):
            pass
        environ['SESSION'] = s
        return s

    def __call__(self, environ, start_response):
        def my_start_response(status, headers, exc_info=None):
            try:
                sess_id = environ['SESSION'].id
            except (LookupError, AttributeError):
                sess_id = session.id
            headers.append(('Set-Cookie', cookie_name + sess_id))
            return start_response(status, headers, exc_info)

        session_id = get_session_id(environ)
        session = self.get_session(session_id, True)
        environ['SESSION'] = session
        environ['SESSION_BUILD'] = self.session_build
        if self.server is not None:
            environ['SERVER'] = self.server
        out = self.app(environ, my_start_response)
        return out


def get_session_id(environ):
    session_id = environ.get('HTTP_COOKIE')
    if session_id is not None:
        try:
            ix = session_id.index(cookie_name)
            session_id = session_id[ix + len(cookie_name):].split(';', 1)[0]
        except ValueError:
            session_id = None
    return session_id
