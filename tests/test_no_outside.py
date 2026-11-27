"""The shared guard (tests/conftest.py, `no_outside`) bites, the code under test cannot silence it, and a stand-in
handed to the code is used as it is. Nothing here is started, connected, bound or looked up for real: a name is
called only once it is known to be the guard's stand-in, the one socket made is closed, and every program named is
one that is nowhere. The hosts' guard beside it (`no_real_hosts`, every test's) keeps a firewall a test attaches
from recording this machine's sockets by the user's own setting, and a test's stand-in environment
(`stand_in_environment`) is all the code reads of this process's through os.environ: none of this user's variables,
so no failure of a test in it writes them."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading

import pytest

from conftest import HOMES, REFUSED, STAND_IN, STOOD_IN, Environment, Reached
from liminal_libs import hostbook, sockets
from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.machines import children, gpu, infrastructure, terminal

pytestmark = pytest.mark.usefixtures("no_outside", "stand_in_environment")

NOWHERE = "liminal-no-such-program"  # were it started for real, there is no such program to start


def names() -> dict:
    """Every name the guard names, as it is now."""
    return {f"{said}.{name}": getattr(owner, name) for owner, said, listed in STOOD_IN for name in listed
            if hasattr(owner, name)}


BEFORE = names()  # as they are without the guard: read when this file is imported, before any test
REAL = os.environ  # this process's own environment, taken before any test: a test asks it only for one name at a time


class Early(subprocess.Popen):
    """A Popen made before the guard, as asyncio.windows_utils.Popen is made when asyncio is imported: the real Popen
    is under it, not the guard's stand-in."""


def stood_in(*dotted: str) -> None:
    """That each of `dotted` is the guard's stand-in now, so that a test may call it."""
    now = names()
    real = [name for name in dotted if now[name] is BEFORE[name]]
    assert real == [], f"not stood in for: {real}"


def test_every_name_it_names_is_stood_in_for():
    assert sorted(names()) == sorted(REFUSED)
    stood_in(*REFUSED)
    mine = {"subprocess.Popen", "subprocess.run", "os.system", "os.execv", "os.execve", "socket.create_connection",
            "socket.create_server", "socket.socketpair", "socket.getaddrinfo", "socket.gethostbyaddr",
            "socket.getnameinfo", "socket.socket.connect", "socket.socket.bind", "socket.socket.listen",
            "socket.socket.sendto"}
    mine |= ({"_winapi.CreateProcess", "os.startfile"} if os.name == "nt" else
             {"_posixsubprocess.fork_exec", "subprocess._fork_exec", "os.fork", "os.forkpty", "os.posix_spawn",
              "socket.socket.sendmsg"})
    assert mine <= set(REFUSED), sorted(mine - set(REFUSED))


def test_a_process_started_for_real_is_refused_and_cannot_be_swallowed(no_outside):
    def code_under_test():
        try:
            subprocess.Popen([NOWHERE])
        except Exception:  # noqa: BLE001 - the code's own handling, as in the library
            return "swallowed"
        return "started"

    stood_in("subprocess.Popen")
    with pytest.raises(Reached):
        code_under_test()
    assert no_outside and no_outside[0].startswith("subprocess.Popen")
    no_outside.clear()  # (this test reached it on purpose: the guard's own check at the end stays quiet)


def test_a_process_started_under_popen_by_fork_or_by_exec_is_refused_too(no_outside):
    if os.name == "nt":
        import _winapi

        stood_in("_winapi.CreateProcess", "os.execv")
        reaches = [lambda: _winapi.CreateProcess(None, NOWHERE, None, None, False, 0, None, None, None)]
    else:
        import _posixsubprocess

        stood_in("_posixsubprocess.fork_exec", "subprocess._fork_exec", "os.posix_spawn", "os.fork", "os.forkpty",
                 "os.execv")
        reaches = [lambda: _posixsubprocess.fork_exec(), os.fork, os.forkpty]
    reaches += [lambda: Early([NOWHERE]),  # a Popen the guard did not replace, as asyncio's: what it starts with is
                lambda: os.execv(os.path.join(os.sep, "nowhere", NOWHERE), [NOWHERE])]  # ... and exec, under execl*
    for reach in reaches:
        with pytest.raises(Reached):
            reach()
    assert len(no_outside) == len(reaches)
    no_outside.clear()


def test_a_class_made_of_popen_under_the_guard_is_made_and_refused_only_when_it_starts(no_outside):
    """1.109.0 (item 14; CI, windows-latest 3.12): asyncio's first import makes `class Popen(subprocess.Popen)`; under
    a stand-in that was a function that import failed half way and asyncio stayed broken for every later test. The
    stand-in is a class now, and asyncio and unittest.mock are imported before any guard."""
    stood_in("subprocess.Popen")

    class Late(subprocess.Popen):  # as asyncio.windows_utils makes one, under the guard
        pass
    with pytest.raises(Reached):
        Late([NOWHERE])
    with pytest.raises(Reached):
        subprocess.Popen([NOWHERE])
    assert len(no_outside) == 2 and all(r.startswith("subprocess.Popen") for r in no_outside)
    no_outside.clear()
    assert {"asyncio", "asyncio.base_events", "unittest.mock"} <= set(sys.modules)


def test_a_connection_a_listener_or_a_lookup_for_real_is_refused(no_outside):
    stood_in(*(name for name in REFUSED if name.startswith("socket.")))
    here, nobody = ("127.0.0.1", 9), "example.test"
    with socket.socket() as made:  # made, and closed: by itself it reaches nothing
        reaches = [lambda: made.connect(here), lambda: made.connect_ex(here), lambda: made.bind(("127.0.0.1", 0)),
                   lambda: made.listen(1), lambda: made.sendto(b"x", here)]
        if hasattr(made, "sendmsg"):
            reaches.append(lambda: made.sendmsg([b"x"], [], 0, here))
        reaches += [lambda: socket.create_connection(here), lambda: socket.create_server(("127.0.0.1", 0)),
                    socket.socketpair, lambda: socket.getaddrinfo(nobody, 443), lambda: socket.gethostbyname(nobody),
                    lambda: socket.gethostbyname_ex(nobody), lambda: socket.gethostbyaddr("127.0.0.1"),
                    lambda: socket.getnameinfo(here, 0)]
        for reach in reaches:
            with pytest.raises(Reached):
                reach()
    assert len(no_outside) == len(reaches) and made.fileno() == -1  # every one refused, and the socket closed
    no_outside.clear()


def test_a_stand_in_handed_to_the_code_is_used_and_the_guard_stays_quiet(no_outside):
    asked = []

    def runner(args, timeout):  # nvidia-smi, as a model server's page asks it
        asked.append(args[0])
        return 0, "0, NVIDIA GeForce RTX 5090, 32607, 1000, 31607, 595.71\n", ""
    reading = gpu.read(runner)
    assert [card.name for card in reading.cards] == ["NVIDIA GeForce RTX 5090"] and asked == ["nvidia-smi"]
    assert no_outside == []  # the code ran its stand-in, and nothing for real: the guard did not fire
    stood_in("subprocess.run")
    with pytest.raises(Reached, match="subprocess.run"):  # the same code without one meets the guard
        gpu.read(which=lambda name: NOWHERE)
    no_outside.clear()


def test_a_stand_in_environment_is_all_the_code_reads_of_this_processs(request, monkeypatch, tmp_path):
    # (1.100.0: a failing test's output held this user's whole environment, an API key among it. Whatever is asked
    # here of an environment is asked outside its assertion, and the stand-in is no argument of this test: were it
    # this process's own, or made of it, an assertion that looked at it would write it whole, and so would the
    # arguments pytest writes of a test that failed)
    stood_in = (os.environ is request.getfixturevalue("stand_in_environment") and isinstance(os.environ, Environment)
                and os.environ is not REAL)
    assert stood_in
    monkeypatch.delenv("PYTEST_CURRENT_TEST")  # (pytest names the test there, in whatever os.environ is then)
    home = dict.fromkeys(HOMES, str(tmp_path / "home"))  # where `~` is read from: the test's own folder
    its_own = dict(os.environ) == {**STAND_IN, **home, hostbook.VARIABLE: "shown"}
    assert its_own  # its own pairs, its home and the hosts' guard's, and nothing else
    a_childs = children.environment(children.Launch(("tool",))) == dict(os.environ)
    assert a_childs  # what a child's is made of
    inherited = terminal.inherited() == {**STAND_IN, **home}
    assert inherited  # (this process's without LIMINAL_*)
    handed_on: list = []  # what is handed to the system's own environment, which os.environ's own pairs are
    monkeypatch.setattr(os, "putenv", lambda name, value: handed_on.append(name))
    monkeypatch.setenv("Liminal_Stand_In", "1")  # set in it, its name told apart as by os.environ
    assert os.environ["Liminal_Stand_In"] == "1" and ("LIMINAL_STAND_IN" in os.environ) == (os.name == "nt")
    leaked = "Liminal_Stand_In" in REAL
    assert not leaked and handed_on == []  # nothing set in it reaches this process's own, nor the system's
    with pytest.raises(TypeError):
        os.environ["NUMBER"] = 1  # a value is text, as in os.environ


def test_in_the_stand_in_none_of_this_users_saved_variables_is_read():
    # (1.100.0's review: on Windows the library reads this user's saved variables from the registry, not through
    # os.environ. Asked outside the assertions: were one read, an assertion that looked at it would write it. TEMP is
    # among every Windows user's saved variables, so without the stand-in both readers hold something there)
    from liminal_libs import config
    from liminal_libs.apps import authorization

    none_by_name = config.UserEnvironment(names=("TEMP", "TMP", "Path")).saved() == {}
    none_at_all = authorization.saved_variables() == {}
    assert none_by_name and none_at_all
    if os.name == "nt":
        import winreg

        for opener in (winreg.OpenKey, winreg.OpenKeyEx):  # (read access only: nothing is asked to be written)
            with pytest.raises(FileNotFoundError):
                opener(winreg.HKEY_CURRENT_USER, "Environment")


def test_a_firewall_attached_under_a_login_that_says_always_starts_nothing_real(no_real_hosts, tmp_path):
    """B-critique B1: the platform's suite builds its app with no login given, so with this user's own variables, and
    attaches its stand-in firewall. Here the user's saved variables say LIMINAL_HOSTS_RECORDING=always (what the
    Recording form keeps on Windows): the guard's "shown" in the test's process wins (the process's own variable over
    a saved one), so nothing records; and the socket table the view would read is the guard's refusal, the database
    and the layers in the test's own folder."""
    from test_firewall import FakeFirewall

    saved = {"LIMINAL_HOSTS_RECORDING": "always"}
    fw = FakeFirewall()
    fw.attach(object(), EnvironmentLogin(saved=lambda: dict(saved)))  # the platform's own login, as it reads it
    try:
        view = fw.netstat_view(make=False)
        assert view is not None and view.mode() == "shown" and not view.recording()
        assert not [t for t in threading.enumerate() if t.name.endswith("-hosts")]
        assert os.environ[hostbook.VARIABLE] == "shown"
        assert hostbook.path().is_relative_to(tmp_path) and infrastructure.folder().is_relative_to(tmp_path)
        with pytest.raises(Reached, match="socket table for real"):
            view.touch()  # the reader the firewall's view is made with by default: the guard's
        assert no_real_hosts == ["sockets.read ()"]
        no_real_hosts.clear()  # (read on purpose: the guard's own check at the end stays quiet)
        assert not hostbook.path().exists()  # nothing was kept
    finally:
        fw.detach()
    with pytest.raises(Reached):
        sockets.read("windows")  # whichever system it is asked for
    no_real_hosts.clear()
