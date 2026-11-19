"""The shared guard (tests/conftest.py, `no_outside`) bites, the code under test cannot silence it, and a stand-in
handed to the code is used as it is. Nothing here is started, connected, bound or looked up for real: a name is
called only once it is known to be the guard's stand-in, the one socket made is closed, and every program named is
one that is nowhere. The hosts' guard beside it (`no_real_hosts`, every test's) keeps a firewall a test attaches
from recording this machine's sockets by the user's own setting."""
from __future__ import annotations

import os
import socket
import subprocess
import threading

import pytest

from conftest import REFUSED, STOOD_IN, Reached
from liminal_libs import hostbook, sockets
from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.machines import gpu, infrastructure

pytestmark = pytest.mark.usefixtures("no_outside")

NOWHERE = "liminal-no-such-program"  # were it started for real, there is no such program to start


def names() -> dict:
    """Every name the guard names, as it is now."""
    return {f"{said}.{name}": getattr(owner, name) for owner, said, listed in STOOD_IN for name in listed
            if hasattr(owner, name)}


BEFORE = names()  # as they are without the guard: read when this file is imported, before any test


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
