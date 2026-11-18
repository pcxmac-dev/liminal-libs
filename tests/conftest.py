"""Fixtures the library's test files share.

`no_outside`: a test that asks for it fails if the code under test starts a process, opens a connection, listens for
one, or resolves a name for real. The stand-ins raise `Reached`, a BaseException and not an Exception, so no `except
Exception` in the code under test can swallow it; and every reach is also noted and failed at the test's end, in case
something caught even that (1.62.0, after a review found two tests that reached the real thing and still passed).

A file whose code starts processes or opens sockets asks for it for every test of its own:

    pytestmark = pytest.mark.usefixtures("no_outside")

What it stands in for (REFUSED names each one this system has):
- a process: subprocess's Popen, run, call, check_call, check_output, getoutput and getstatusoutput; os.system,
  startfile, posix_spawn(p), spawnv(e/p/pe), fork, forkpty, execv and execve (the other exec* go through these two);
  and what Popen itself starts a process with, _winapi.CreateProcess on Windows and _posixsubprocess.fork_exec (with
  subprocess's own name for it) elsewhere, so that a Popen made before the guard (asyncio.windows_utils.Popen),
  multiprocessing and pty start nothing either;
- a socket: socket.create_connection, create_server and socketpair, and a socket's connect, connect_ex, bind, listen,
  sendto and sendmsg (a socket may be made, and closed: it reaches nothing until one of these is asked);
- a name: socket.getaddrinfo, gethostbyname, gethostbyname_ex, gethostbyaddr and getnameinfo.

It bites only where the code looks the names up when it runs (`subprocess.Popen`, `socket.create_connection`): a
name bound when a module was imported (`from subprocess import Popen`, a default argument `popen=subprocess.Popen`)
is out of its reach, so the code resolves such names at call time; what ctypes asks of the system itself is out of
its reach too. `requests` is imported here, before any test: urllib3 binds a socket of its own (::1, port 0) when it
is first imported, to learn whether IPv6 is there, which the guard would otherwise take for the test's doing."""
from __future__ import annotations

import os
import socket
import subprocess

import pytest

try:
    import requests  # noqa: F401 - imported before any guard: urllib3's own check binds a socket when first imported
except ImportError:  # (not every test run has it)
    pass

# (what holds the names, the words a reach is said by, the names)
STOOD_IN = [
    (subprocess, "subprocess", ("Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput",
                                "_fork_exec")),
    (os, "os", ("system", "startfile", "posix_spawn", "posix_spawnp", "spawnv", "spawnve", "spawnvp", "spawnvpe",
                "fork", "forkpty", "execv", "execve")),
    (socket, "socket", ("create_connection", "create_server", "socketpair", "getaddrinfo", "gethostbyname",
                        "gethostbyname_ex", "gethostbyaddr", "getnameinfo")),
    (socket.socket, "socket.socket", ("connect", "connect_ex", "bind", "listen", "sendto", "sendmsg")),
]
if os.name == "nt":
    import _winapi

    STOOD_IN.append((_winapi, "_winapi", ("CreateProcess",)))
else:
    import _posixsubprocess

    STOOD_IN.append((_posixsubprocess, "_posixsubprocess", ("fork_exec",)))
REFUSED = tuple(f"{said}.{name}" for owner, said, names in STOOD_IN for name in names if hasattr(owner, name))


class Reached(BaseException):
    """A test reached for real what it must stand in for."""


@pytest.fixture
def no_outside(monkeypatch):
    reached: list[str] = []

    def refuse(what):
        def stand_in(*args, **kwargs):
            reached.append(f"{what} {args[:2]!r}"[:300])
            raise Reached(f"the test reached {what} for real: give the code a stand-in")
        return stand_in

    for owner, said, names in STOOD_IN:
        for name in names:
            if hasattr(owner, name):
                monkeypatch.setattr(owner, name, refuse(f"{said}.{name}"))
    yield reached
    assert not reached, f"the test reached the outside for real: {reached}"
