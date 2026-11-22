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
is first imported, to learn whether IPv6 is there, which the guard would otherwise take for the test's doing.

`no_real_hosts` (1.65.0; B-critique B1), for every test, asked for by none: a firewall a test attaches reads its
recording setting through its login, and a login with no variables of its own reads this user's (the platform's
EnvironmentLogin, the saved ones under the process's), so once the user chose "always" such a test would start a
thread reading this machine's socket table into this machine's own hosts database. So each test runs with
LIMINAL_HOSTS_RECORDING set to "shown" in its process (which wins over a saved one), the socket reader refused (a
`Reached` again, noted and failed at its end: sockets.read, looked up when the code reads), and the hosts database
and the infrastructure layers' folder moved into the test's own folder (its tmp_path where it has one, else one made
the first time either is asked); each book made there is let go after it. A test that reads a socket table gives
the code a reader of its own, or calls the real one taken before any test (`READ = sockets.read`)."""
from __future__ import annotations

import os
import socket
import subprocess
import threading

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


@pytest.fixture(autouse=True)
def no_real_hosts(monkeypatch, request, tmp_path_factory):
    """Every test: no recording all the time by the user's own setting, no socket table read for real, and the hosts
    database and the infrastructure layers kept in the test's own folder (the module's docstring). Yields the reads
    refused, so the guard's own test can clear the one it made on purpose."""
    from liminal_libs import hostbook, netpath, sockets
    from liminal_libs.machines import infrastructure, lookups, routes

    folder = request.getfixturevalue("tmp_path") if "tmp_path" in request.fixturenames else None
    lock = threading.Lock()

    def own():  # the test's own folder: made when first asked, from whichever thread asks
        nonlocal folder
        with lock:
            if folder is None:
                folder = tmp_path_factory.mktemp("no-real-hosts")
            return folder

    refused: list[str] = []

    def read(*args, **kwargs):
        refused.append(f"sockets.read {args[:1]!r}"[:300])
        raise Reached("the test read this machine's socket table for real: give the code a reader of its own")

    def probe(*args, **kwargs):  # 1.67.0: a route is never traced for real (Windows' ICMP API, the tracers)
        refused.append(f"netpath probe {args[:2]!r}"[:300])
        raise Reached("the test traced a route for real: give netpath.trace a probe and a run of its own")

    def tracer(args, timeout=None):
        refused.append(f"netpath tracer {list(args)[:1]!r}"[:300])
        return None  # as a tracer that is not there: nothing runs

    def thread(work):  # nor is the routes' thread started: a test steps its Routes itself
        refused.append("routes thread")

    monkeypatch.setenv(hostbook.VARIABLE, "shown")
    monkeypatch.setattr(sockets, "read", read)
    monkeypatch.setattr(netpath, "_icmp_probe", probe)
    monkeypatch.setattr(netpath, "_run", tracer)
    monkeypatch.setattr(netpath, "_trace_run", lambda args, timeout=None, stop=None: (tracer(args), ""))
    monkeypatch.setattr(routes.Routes, "_thread", staticmethod(thread))

    def reach(what):  # 1.72.0: a router is never looked up for real: neither its name nor its network
        def refuse(*args, **kwargs):
            refused.append(f"lookups {what} {args[:1]!r}"[:300])
            raise Reached(f"the test looked a router up for real ({what}): give the lookups stand-ins")
        return refuse
    monkeypatch.setattr(lookups, "_ptr", reach("reverse DNS"))
    monkeypatch.setattr(lookups, "_get", reach("RDAP"))
    monkeypatch.setattr(lookups.Lookups, "_thread", staticmethod(lambda work: None))  # not run: a test steps it
    monkeypatch.setattr(hostbook, "path", lambda: own() / "liminal-data" / hostbook.FOLDER / hostbook.FILE)
    monkeypatch.setattr(hostbook, "_BOOKS", {})
    monkeypatch.setattr(infrastructure, "folder", lambda: own() / "liminal-data" / infrastructure.FOLDER)
    yield refused
    for book in list(hostbook._BOOKS.values()):  # the books handed out in the test: written and let go
        try:
            book.close()
        except Exception:  # noqa: BLE001 - a test's own book that it broke on purpose
            pass
    assert not refused, f"the test read this machine's socket table for real: {refused}"
