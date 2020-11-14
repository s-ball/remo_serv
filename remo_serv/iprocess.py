#  Copyright (c) 2020 SBA- MIT License

import subprocess
import socket
import select
import non_blocking_io_wrapper

from typing import Sequence, Optional
from abc import ABC, abstractmethod


class IProcess(ABC):
    process: subprocess.Popen

    @abstractmethod
    def select(self, timeout: Optional[float]) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def read(self, hint: int = -1) -> bytes:
        raise NotImplementedError()

    def write(self, data: bytes):
        raise NotImplementedError

    @abstractmethod
    def shutdown(self):
        raise NotImplementedError()

    def terminate(self, timeout=None):
        self.process.terminate()
        self.process.wait(timeout)
        if self.poll() is not None:
            self.process.kill()

    def poll(self) -> Optional[int]:
        return self.process.poll()


def build_process(*cmd) -> IProcess:
    try:
        p = SocketPairIProcess(cmd)
    except AttributeError:
        p = NonBlockingIProcess(cmd)
    return p


class SocketPairIProcess(IProcess):
    # noinspection PyTypeChecker
    def __init__(self, cmd: Sequence[str]):
        self.m, s = socket.socketpair(socket.AF_UNIX)
        self.process = subprocess.Popen(cmd, bufsize=0, stdin=s, stdout=s,
                                        stderr=s)
        self.closed = False

    def select(self, timeout: float = None) -> bool:
        x = select.select([self.m], [], [], timeout)
        return ([self.m], [], []) == x

    def read(self, hint: int = -1) -> bytes:
        if hint <= 0:
            hint = 8292
        return self.m.recv(hint)

    def write(self, data: bytes):
        self.m.send(data)

    def shutdown(self):
        self.m.shutdown(socket.SHUT_WR)
        self.closed = True


class NonBlockingIProcess(IProcess):
    def __init__(self, cmd: Sequence[str]):
        self.process = subprocess.Popen(cmd, bufsize=0,
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT)
        self.fd = non_blocking_io_wrapper.NonBlockingReader(
            self.process.stdout)

    def select(self, timeout: float = None) -> bool:
        return self.fd.select(timeout)

    def read(self, hint: int = -1) -> bytes:
        return self.fd.read(hint)

    def write(self, data: bytes):
        self.process.stdin.write(data)

    def shutdown(self):
        self.fd.close()

    @property
    def closed(self):
        return self.fd.closed
