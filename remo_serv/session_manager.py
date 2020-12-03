#  Copyright (c) 2020 SBA- MIT License

"""WSGI middleware for session management.
"""
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
    """MutableMapping representing a session.

    A session contains:
    - a session id
    - a timestamp used to expire the session
    - a user name
    - a dictionary for its content
    """
    def __init__(self, s_id):
        self.id = s_id
        self.timestamp = time.time()
        self.content = {}
        self.key = None
        self.user = None

    def refresh(self):
        """Resets the session timestamp to the current time."""
        self.timestamp = time.time()

    def invalidate(self):
        """Invalidates a session.
        Current version sets the timestamp to 0 and the key to None to
        prevent further usage.
        """
        self.timestamp = 0
        self.key = None

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
    """A WSGI middleware that creates session, puts them into the WSGI
    environment and eventually expires them.
    """
    def __init__(self, app, timeout=600, delay=60):
        """Constructor parameters:
        - app: the wrapped WSGI application
        - timeout: maximum session duration (in seconds) default 600
        - delay: step in seconds between calls to the expire thread
        """
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
        """Gets a session from the container.

        If session_id exists and is not expired, returns it; else returns
        None if create is False, or create a new session.
        """
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
        """The expire thread method."""
        while True:
            with self.lock:
                now = time.time()
                expired = [session for session in self.sessions.values()
                           if now - session.timestamp > self.timeout]
                for s in expired:
                    del self.sessions[s.id]
            time.sleep(delta)

    def session_build(self, environ):
        """Builds a new session and registers it in the WSGI environment."""
        s = self.get_session(None, True)
        try:
            del self.sessions[environ['SESSION'].id]
        except (LookupError, AttributeError):
            pass
        environ['SESSION'] = s
        return s

    def __call__(self, environ, start_response):
        """The WSGI application call.

        Puts the session in the environment (eventually a new one) and
        calls the wrapped WSGI application
        """
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
    """Extract the session id from a SESSION_ID cookie or returns None."""
    session_id = environ.get('HTTP_COOKIE')
    if session_id is not None:
        try:
            ix = session_id.index(cookie_name)
            session_id = session_id[ix + len(cookie_name):].split(';', 1)[0]
        except ValueError:
            session_id = None
    return session_id
