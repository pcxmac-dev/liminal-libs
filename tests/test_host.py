"""The hosts' names and sockets (host.py, 1.53.1), found running the suite on Linux (the user, 2026-11-15: "check for
bugs in the linux environment"): a socket file left by a host that ended without closing it no longer stops the next
host; a database is named as its system compares paths; a host started off Windows gets a session of its own. No
process is started: `Popen` is stood in."""
from __future__ import annotations

import os
import socket
import sys
import threading
from pathlib import Path

import pytest

from liminal_libs import host as hosting

POSIX = pytest.mark.skipif(sys.platform == "win32", reason="a pipe on Windows goes with its process: no file is left")


@pytest.fixture
def ipc(monkeypatch, tmp_path):
    monkeypatch.setenv("LIMINAL_IPC_DIR", str(tmp_path / "ipc"))
    return tmp_path


def test_a_database_is_named_as_its_system_compares_paths(tmp_path):
    lower, upper = tmp_path / "data" / "liminal.db", tmp_path / "DATA" / "liminal.db"
    folds = os.path.normcase("A") == "a"  # Windows: one file; elsewhere two paths are two databases
    assert (hosting._digest(lower) == hosting._digest(upper)) is folds
    assert hosting._digest(lower) == hosting._digest(Path(str(lower))) and len(hosting._digest(lower)) == 10


@POSIX
def test_a_socket_left_by_a_host_that_was_killed_does_not_stop_the_next(ipc):
    db = ipc / "liminal.db"
    where = hosting.address("t", db)
    Path(where).parent.mkdir(parents=True, exist_ok=True)
    left = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    left.bind(where)
    left.close()  # bound and never removed: what a killed host leaves
    assert os.path.exists(where)
    lines: list[str] = []
    why = hosting.Host("t", db, log=lines.append).serve(lambda stop: None)
    assert "another host answers" not in why and why == "its work ended"
    assert any("a socket file left by a host" in m for m in lines) and any("up for liminal.db" in m for m in lines)


@POSIX
def test_a_live_hosts_socket_is_left_alone_and_a_second_host_gives_way(ipc):
    db = ipc / "liminal.db"
    up, done = threading.Event(), threading.Event()

    def work(stop):
        up.set()
        done.wait(15)

    first = threading.Thread(target=lambda: hosting.Host("t", db, log=lambda m: None).serve(work), daemon=True)
    first.start()
    try:
        assert up.wait(15)
        where = hosting.address("t", db)
        assert hosting._clear_stale(where) is False and os.path.exists(where)  # something answers: left
        assert hosting.Host("t", db, log=lambda m: None).serve(lambda stop: None).startswith("another host answers for t")
    finally:
        done.set()
        first.join(15)


def test_nothing_is_cleared_where_no_socket_file_is(ipc):
    assert hosting._clear_stale(str(ipc / "ipc" / "none.sock")) is False


def test_a_host_is_started_in_a_session_of_its_own_off_windows(monkeypatch, tmp_path):
    seen: dict = {}
    monkeypatch.setattr(hosting.subprocess, "Popen", lambda argv, **kw: seen.update(argv=list(argv), **kw))
    hosting.Host.start("fetcher", tmp_path / "liminal.db")
    assert seen["argv"][-2:] == ["host", "fetcher"] and seen["env"]["LIMINAL_DB"] == str(tmp_path / "liminal.db")
    assert seen["start_new_session"] is (os.name != "nt")  # a terminal closing there no longer ends the host
