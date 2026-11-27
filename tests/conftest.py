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
the code a reader of its own, or calls the real one taken before any test (`READ = sockets.read`).

`stand_in_facts` (1.103.0), for every test, asked for by none: the needs judgement's facts of this machine are a
recorded machine's (needs_machines' this-pc), put in place as the one reader of the process and put back after.

`stand_in_environment` (1.100.0): a test that asks for it runs in a stand-in for this process's environment, which
holds this user's own variables, API keys among them. pytest writes the arguments of the frame an error is raised in
and the values an assertion looked at, and a load test found a failing test's output holding this user's whole
environment (children.stream, given none, holds this process's whole in its `env`): in a public repository's CI log
it would be public. os.environ is then a small mapping of the test's own (`Environment`: names told apart as this
system tells them, and nothing set in it reaches the system's own), so what the code reads through os.environ as
this process's environment, what it hands a stand-in of it and what a test asserts of it are the test's own, whether
it fails or passes, with -l or -vv. It holds STAND_IN, a home of the test's own (HOMES: `~` is a folder in its
tmp_path, never this user's), the variable `no_real_hosts` sets, and pytest's name for the test and its phase
(CURRENT, PYTEST_CURRENT_TEST) from its start: pytest sets that in this process's own environment before a test's
fixtures, and again for its call and for its teardown in whatever os.environ is then, so the stand-in is given it
when it is made and pytest keeps it there. While it is set an app's stop event is named for the test
(lifecycle.stop_event_name, 1.88.2: a suite run once stopped the four running apps); a stand-in made without it let
a fixture set up after it name, and set, a running app's own (1.100.0's review). A file whose code reads this
process's environment asks for it for every test of its own, as for `no_outside`; a test elsewhere asks for it by
name; and a fixture that reads or changes the environment for every test of its file asks for it too, so that the
stand-in is there first.

On Windows the library also reads this user's saved variables from the registry, not through os.environ
(config.UserEnvironment.saved, apps.authorization.saved_variables). In the stand-in that key is not there
(`no_saved_variables`: winreg.OpenKey and OpenKeyEx asked for HKEY_CURRENT_USER's Environment by that name), so none
saved is read and none can be saved. That was not checked with a canary or a spy: it has its own test, no more.

It covers the tests that ask for it, and no other: a test that does not, and whose code reads this process's
environment, still writes of it what its failure holds. And it reaches what is read through os.environ when the
code runs: what a module reads when it is imported is read once, of whatever os.environ is then (capture.py reads
SystemRoot so), and what C code reads of the system's own environment is not Python's to stand in for. Which files
ask for it, and how that was checked, is in CHANGELOG.md (1.100.0)."""
from __future__ import annotations

import os
import socket
import subprocess
import threading
from collections.abc import MutableMapping

import pytest

try:
    import requests  # noqa: F401 - imported before any guard: urllib3's own check binds a socket when first imported
except ImportError:  # (not every test run has it)
    pass
# 1.109.0: imported before any guard too. asyncio's first import makes `class Popen(subprocess.Popen)`
# (asyncio.windows_utils): under a stand-in that is a function it fails half way (TypeError) and leaves the
# interpreter's asyncio broken for every later test ("name 'base_events' is not defined"); Python 3.12's
# unittest.mock imports asyncio, so a test's own `import unittest.mock` did that on CI (item 14)
import asyncio  # noqa: F401,E402
import unittest.mock  # noqa: F401,E402

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


def as_class(refusing, name: str = "Popen") -> type:
    """A stand-in for a class (subprocess.Popen), itself a class (1.109.0): a module imported under the guard may
    subclass it (asyncio.windows_utils' `class Popen(subprocess.Popen)`), which a function refuses half way through
    the import; what makes one, or one of its subclasses, is refused as the function refuses it."""
    def __new__(cls, *args, **kwargs):
        return refusing(*args, **kwargs)
    return type(name, (), {"__new__": __new__, "__doc__": "The guard's stand-in: what makes one is refused."})


@pytest.fixture
def no_outside(monkeypatch):
    reached: list[str] = []

    def refuse(what):
        def stand_in(*args, **kwargs):
            reached.append(f"{what} {args[:2]!r}"[:300])
            raise Reached(f"the test reached {what} for real: give the code a stand-in")
        return as_class(stand_in) if what == "subprocess.Popen" else stand_in

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


class Environment(MutableMapping):
    """os.environ as a test's stand-in (`stand_in_environment`): pairs of its own, none of this process's. On Windows
    a name is told apart without regard to case and kept upper-cased, as os.environ keeps it there; what is set in it
    never reaches the system's own environment."""

    def __init__(self, pairs=()):
        self._pairs: dict[str, str] = {}
        self.update(pairs)

    @staticmethod
    def _name(name) -> str:
        if not isinstance(name, str):
            raise TypeError(f"str expected, not {type(name).__name__}")
        return name.upper() if os.name == "nt" else name

    def __getitem__(self, name):
        return self._pairs[self._name(name)]

    def __setitem__(self, name, value):
        if not isinstance(value, str):
            raise TypeError(f"str expected, not {type(value).__name__}")
        self._pairs[self._name(name)] = value

    def __delitem__(self, name):
        del self._pairs[self._name(name)]

    def __iter__(self):
        return iter(list(self._pairs))

    def __len__(self):
        return len(self._pairs)

    def copy(self) -> dict[str, str]:
        return dict(self._pairs)

    def __repr__(self):
        return f"Environment({self._pairs!r})"


# What a test's stand-in environment holds at its start (USERNAME: getpass.getuser reads it, a login's user)
STAND_IN = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "USERNAME": "someone"}
HOMES = ("HOME", "USERPROFILE")  # where `~` is read from (elsewhere, on Windows): in a stand-in, the test's own folder
CURRENT = "PYTEST_CURRENT_TEST"  # pytest's name for the test and its phase: by it an app's stop event is the test's
SAVED = "Environment"  # under HKEY_CURRENT_USER: where Windows keeps this user's saved variables


def no_saved_variables(monkeypatch) -> None:
    """On Windows the library reads this user's saved variables too, from the registry and not through os.environ
    (config.UserEnvironment, apps.authorization.saved_variables: winreg.OpenKey, looked up when they read). For a
    test in the stand-in that key is not there, as winreg says it (FileNotFoundError): none saved is read, and none
    can be saved. Elsewhere there is no registry (the saved ones are asked over the link, by the stand-in's
    LIMINAL_DB)."""
    try:
        import winreg
    except ImportError:
        return

    def without(opener):
        def opened(key, sub_key, *args, **kwargs):
            if key == winreg.HKEY_CURRENT_USER and str(sub_key).strip("\\").lower() == SAVED.lower():
                raise FileNotFoundError(2, "a test's stand-in environment has no saved variables of this user's")
            return opener(key, sub_key, *args, **kwargs)
        return opened

    for name in ("OpenKey", "OpenKeyEx"):
        monkeypatch.setattr(winreg, name, without(getattr(winreg, name)))


@pytest.fixture(autouse=True)
def stand_in_facts(no_real_hosts):
    """Every test (1.103.0): this machine's facts for the needs judgement are a recorded machine's, this PC's as the
    needs plan's map read it (liminal_libs.needs_machines "this-pc"), so nothing of the machine the suite runs on is
    read for any test, even one that missed its seam (the real reads refuse under a test as well: facts.refused). A
    test names another machine with facts.use(needs_machines.reader(NAME)); the one before is put back after."""
    from liminal_libs import facts, needs_machines

    before = facts.use(needs_machines.reader("this-pc"))
    try:
        yield
    finally:
        facts.use(before)


@pytest.fixture
def stand_in_environment(monkeypatch, no_real_hosts, tmp_path):
    """This process's environment for one test: a stand-in holding STAND_IN, a home of the test's own (HOMES: the
    folder `home` in its tmp_path, which nothing makes), what the guards set and pytest's name for the test (the
    module's docstring); what the test sets in it is its own."""
    from liminal_libs import hostbook

    stand_in = Environment(STAND_IN)
    stand_in.update(dict.fromkeys(HOMES, str(tmp_path / "home")))
    stand_in[hostbook.VARIABLE] = os.environ[hostbook.VARIABLE]  # (no_real_hosts set it in the real one before)
    stand_in[CURRENT] = os.environ[CURRENT]  # (pytest set it there before any fixture: without it, no stand-in)
    monkeypatch.setattr(os, "environ", stand_in)
    no_saved_variables(monkeypatch)
    return stand_in
