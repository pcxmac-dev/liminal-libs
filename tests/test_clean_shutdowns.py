"""Every shutdown is clean (1.88.4; the user, 2026-11-24: "all shutdowns need to be clean").

liminal-stop and liminal-signal ask (TERM) and report what did not end, killing nothing unless --kill is given; with
--kill only what holds no data is forced, a data holder (mongod, the MongoDB host, a ledger row holding data) only when
named (--pid N --kill); an app's late plugin has its trees asked again and left; an explicit KILL never kills a data
holder; mongo.stop waits for the server's process and never kills it; a data holder is never in a job that ends it
with its owner; and the library's other forcing places ask and report.

Stand-ins only: a process table of stand-ins that is its own killer (lifecycle.FakeTable), a ledger in memory, a clock
that moves only when slept on, stand-in Popen objects and a stand-in kernel32. Nothing is started, signalled or
reached: no real stop event, no real MongoDB, no network.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from liminal_libs import lifecycle, mongo, nodes, proctree, stop
from liminal_libs.apps.app import App
from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.lifecycle import FakeClock, FakeTable, MemoryLedger, Proc, Row, Signal

pytestmark = pytest.mark.usefixtures("stand_in_environment")  # its code reads this process's environment

ME = os.getpid()
VENV = "C:/liminal/.venv/Scripts"
SRC = Path(__file__).resolve().parents[1] / "src" / "liminal_libs"


@pytest.fixture(autouse=True)
def _nothing_left():
    with lifecycle._MINE_LOCK:
        saved = dict(lifecycle._MINE)
        lifecycle._MINE.clear()
    yield
    with lifecycle._MINE_LOCK:
        lifecycle._MINE.clear()
        lifecycle._MINE.update(saved)


class _NoNode:
    def reach(self, *a):
        raise ConnectionError("no node answers")


def command(table, ledger=None, running=None):
    """The stop command on stand-ins: no app answers by its route unless `running` names it."""
    clock = FakeClock()
    out: list[str] = []
    running = running or {}

    def http(method, url, headers, body):
        port = int(url.split(":")[2].split("/")[0])
        name = next((n for n in stop.APPS if stop.app_port(n, {}) == port), None)
        path = "/" + url.split("/", 3)[3]
        if name not in running:
            return 0, {}
        if path == "/api/app":
            return 200, {"app": name}
        if path == "/api/app/signal":
            return 202, {"app": name, "pid": running[name]}
        return 404, {}

    cmd = stop.SignalCommand(node=_NoNode(), http=http, table=table, killer=table,
                             ledger=ledger or MemoryLedger(table), key=b"k" * 32, env={}, venvs=[VENV],
                             clock=clock, sleep=clock.sleep, out=out.append, set_event=lambda name: False)
    return cmd, out, clock


def liminal(pid, cmd="python -m liminal_charts serve", ppid=1, started=2):
    return Proc(pid, ppid, f"{VENV}/python.exe", cmd, started)


def mongod(pid=9003, ppid=1, started=4):
    return Proc(pid, ppid, "C:/mongo/bin/mongod.exe", "mongod --port 27017", started)


def mongod_row(pid=9003, started=4):
    return Row(pid=pid, started=started, owner="host:mongo", owner_pid=1, owner_started=None, kind="mongod",
               command=["mongod"])


def kills(table) -> list[int]:
    return [pid for pid, how in table.sent if how == "KILL"]


# -- 1. liminal-stop: TERM alone by default, what is left reported ------------------------------------------------------
def test_liminal_stop_asks_term_alone_and_reports_what_is_left_with_exit_1():
    charts, sync = liminal(9001), liminal(9002, "python -m liminal_charts sync --extras-only", ppid=9001, started=3)
    table = FakeTable([charts, sync, mongod()], ignores={9001, 9002})
    ledger = MemoryLedger(table)
    ledger.add(mongod_row())
    cmd, out, clock = command(table, ledger, running={"charts": 9001})
    assert cmd.signal(Signal.TERM, timeout=5) == stop.EXIT_LEFT
    assert kills(table) == []  # nothing killed
    assert (9001, "TERM") in table.sent and (9002, "TERM") in table.sent and (9003, "SHUTDOWN") in table.sent
    left = [line for line in out if ": left" in line]
    assert any("(pid 9001): left" in line and "owner Liminal's by what it runs" in line and "asked " in line
               and " s ago" in line for line in left), out
    assert any("--kill" in line for line in out)
    # stop_main is TERM, never KILL, without --kill
    seen = {}

    class Spy:
        def signal(self, sig, **kw):
            seen.update(sig=sig, **kw)
            return 0

    assert stop.stop_main([], Spy()) == 0 and seen["sig"] is Signal.TERM and not seen["kill"]
    assert stop.stop_main(["--kill"], Spy()) == 0 and seen["sig"] is Signal.TERM and seen["kill"] is True
    assert stop.stop_main(["--pid", "77", "--kill"], Spy()) == 0 and seen["pid"] == 77
    assert stop.signal_main(["KILL", "--all"], Spy()) == stop.EXIT_USAGE  # KILL forces: only with --kill


def test_with_kill_what_holds_no_data_is_forced_and_a_data_holder_never_is():
    host = liminal(9010, "pythonw -m liminal_charts host live", started=5)
    plain = liminal(9011, "python -m liminal_charts sync --extras-only", started=6)
    table = FakeTable([host, plain, mongod()], ignores={9010, 9011, 9003})  # nothing heeds being asked
    ledger = MemoryLedger(table)
    ledger.add(mongod_row())
    ledger.add(Row(pid=9010, started=5, owner="host:live", owner_pid=1, owner_started=None, kind="host",
                   command=["pythonw"], holds_data=True))
    cmd, out, clock = command(table, ledger)
    assert cmd.signal(Signal.TERM, timeout=5, kill=True) == stop.EXIT_LEFT
    assert kills(table) == [9011]  # what holds no data, forced once its time was up
    assert (9003, "SHUTDOWN") in table.sent and 9003 in table.rows and 9010 in table.rows
    assert any("(pid 9003): left: it holds data" in line for line in out)
    assert any("never forced: name it (--pid N --kill)" in line for line in out)
    # liminal-signal KILL --kill: the same holders spared
    cmd, out, clock = command(table, ledger)
    cmd.signal(Signal.KILL, kill=True)
    assert 9003 not in kills(table) and 9010 not in kills(table)


def test_a_data_holder_named_by_pid_is_forced_only_with_kill():
    table = FakeTable([mongod()], ignores={9003})
    ledger = MemoryLedger(table)
    ledger.add(mongod_row())
    cmd, out, clock = command(table, ledger)
    assert cmd.signal(Signal.TERM, pid=9003, timeout=5) == stop.EXIT_LEFT  # asked (its shutdown), not forced
    assert table.sent == [(9003, "SHUTDOWN")]
    assert cmd.signal(Signal.TERM, pid=9003, timeout=5, kill=True) == stop.EXIT_OK
    assert table.sent[-2:] == [(9003, "SHUTDOWN"), (9003, "KILL")] and 9003 not in table.rows
    # a process that is not Liminal's is never touched by its id
    other = FakeTable([Proc(9020, 1, "C:/Other/x.exe", "x", 2)])
    cmd, out, clock = command(other)
    assert cmd.signal(Signal.TERM, pid=9020, kill=True) == stop.EXIT_REFUSED and other.sent == []


def test_end_trees_spares_a_data_holder_by_what_it_runs_even_with_no_ledger_row():
    table = FakeTable([mongod(7001, ppid=ME, started=1), Proc(7002, ME, "x", "plain", 1)], ignores={7001})
    out = lifecycle.end_trees([table.rows[7001], table.rows[7002]], Signal.KILL, 0, table=table, killer=table, rows=[])
    assert {r["pid"]: r["how"] for r in out} == {7001: "left", 7002: "killed"}
    assert table.sent == [(7002, "KILL"), (7001, "SHUTDOWN")]
    assert lifecycle.end_trees([table.rows[7001]], Signal.KILL, 0, table=table, killer=table, rows=[],
                               force={7001})[0]["how"] == "killed"


# -- 2. an app: a late plugin's trees asked again and left; an explicit KILL never kills a data holder ----------------
class Plain(App):
    NAME, TITLE, ICON = "plain", "Plain", "plug"
    STOP_GRACE_S = 0.0


def test_a_late_plugin_told_with_the_others_has_its_trees_asked_again_never_killed():
    table = FakeTable([Proc(4201, ME, "x", "child", 7)], ignores={4201})
    ledger = MemoryLedger(table)
    gate = threading.Event()

    class Stuck:
        name = "stuck"

        def signal(self, sig, deadline, sender=None):
            gate.wait(5)

    try:
        with lifecycle.standins(table=table, killer=table, ledger=ledger, sleep=lambda s: None):
            lifecycle.note(Row(pid=4201, started=7, owner="stuck", owner_pid=ME, owner_started=None, kind="test",
                               command=["child"]), ledger)
            out = lifecycle.deliver_all([("stuck", Stuck())], Signal.TERM, lifecycle.deadline_in(0.05), grace=0.0)
    finally:
        gate.set()
    assert out[0]["how"] == "late" and "not killed" in out[0]["why"]
    assert table.sent == [(4201, "TERM")] and 4201 in table.rows and [r.pid for r in ledger.kept] == [4201]
    assert lifecycle.mine("stuck") == []  # let go from memory: asked once, not waited for again


def test_an_explicit_kill_kills_what_holds_no_data_and_asks_mongod_to_shut_down():
    table = FakeTable([mongod(4301, ppid=ME, started=5), Proc(4302, ME, "x", "child", 6)], ignores={4301})
    ledger = MemoryLedger(table)
    with lifecycle.standins(table=table, killer=table, ledger=ledger, clock=FakeClock(), sleep=lambda s: None):
        app = Plain(log=lambda m: None, login=EnvironmentLogin(env={}))
        lifecycle.note(Row(pid=4301, started=5, owner="plain", owner_pid=ME, owner_started=None, kind="mongod",
                           command=["mongod"], holds_data=True), ledger)
        lifecycle.note(Row(pid=4302, started=6, owner="plain", owner_pid=ME, owner_started=None, kind="test",
                           command=["child"]), ledger)
        report = app.terminate(Signal.KILL, 0)
    assert kills(table) == [4302] and (4301, "SHUTDOWN") in table.sent and 4301 in table.rows
    assert {p["pid"]: p["how"] for p in report["processes"]} == {4301: "left", 4302: "killed"}


def test_a_start_past_its_deadline_is_asked_never_killed():
    table = FakeTable([Proc(4060, ME, "py", "python -m liminal_libs.nodes serve acme", 3)], ignores={4060})
    ledger = MemoryLedger(table)
    ledger.add(Row(pid=4060, started=3, owner="node:acme", owner_pid=ME, owner_started=None, kind="plugin-node",
                   command=["python"], at=time.time()))
    gate = threading.Event()

    class Never:
        def reach(self, *a):
            gate.wait(5)
            raise ConnectionError("nobody answers")

    try:
        out = nodes.reach_or_start(Never(), "acme", "scope", deadline_s=0.05, launch=lambda: None, ledger=ledger,
                                   table=table, killer=table)
    finally:
        gate.set()
    assert kills(table) == [] and out["ended"][0]["how"] == "left"


# -- 3. mongo.stop: its shutdown, a wait for its process, never a kill --------------------------------------------------
def test_mongo_stop_reports_a_server_still_running_after_60_s_and_never_kills_it(monkeypatch):
    def no(*a, **k):
        raise AssertionError("nothing is ended by force")

    monkeypatch.setattr(lifecycle, "end_trees", no)
    clock, said, looks = FakeClock(0.0), [], []

    def sleep(s):
        looks.append(s)
        clock.sleep(s)

    assert mongo.stop(clock=clock, sleep=sleep, log=said.append, answers=lambda: True, shutdown=lambda: 4242,
                      alive=lambda pid: True, started_of=lambda pid: 7) is False
    assert clock() == 60.0 and set(looks) == {0.5} and len(looks) == 120
    assert any("pid 4242" in s and "still running" in s and "not killed" in s for s in said)
    assert mongo.stop(answers=lambda: False, shutdown=no) is False  # none running: nothing asked


def test_the_keepers_end_shuts_the_server_down_through_stop_and_says_when_it_is_left(monkeypatch):
    asked = []
    monkeypatch.setattr(mongo, "stop", lambda **kw: asked.append(kw) or False)

    class Gone:
        def wait(self, timeout=None):
            return True  # its clients are gone at the first look

    said = []
    mongo.keep(Path("data"), Gone(), said.append, starter=lambda d: None, answers=lambda: True,
               alive=lambda pid: False, started_of=lambda p: 7)
    assert asked and asked[0].get("log") == said.append
    assert any("left running, not killed" in s for s in said)


# -- 4. a data holder is never in a job that ends it with its owner ------------------------------------------------------
class _K32:
    def __init__(self, calls, tag):
        self.calls, self.tag = calls, tag

    def CreateJobObjectW(self, a, name):
        self.calls.append((self.tag, "create", name))
        return 6

    def SetInformationJobObject(self, job, cls, info, size):
        self.calls.append((self.tag, "limits", info._obj.BasicLimitInformation.LimitFlags))
        return 1

    def AssignProcessToJobObject(self, job, handle):
        self.calls.append((self.tag, "assign", handle))
        return 1


class _Nt:
    def NtResumeProcess(self, handle):
        return 0


class _Child:
    pid, _handle = 8301, 57


def test_a_data_holder_is_never_in_a_kill_on_close_job_and_other_children_stay_tied(monkeypatch):
    calls, made = [], []
    popen = (lambda a, **k: made.append(k) or _Child())
    monkeypatch.setattr(lifecycle.os, "name", "nt")
    monkeypatch.setattr(lifecycle, "_REAL_POPEN", popen)
    monkeypatch.setattr(lifecycle, "_kernel32", lambda: _K32(calls, "named"))
    monkeypatch.setattr(lifecycle, "_ntdll", lambda: _Nt())
    monkeypatch.setattr(lifecycle, "_JOB", lifecycle.JobTie(_K32(calls, "owner's"), _Nt()))
    monkeypatch.setattr(lifecycle._proc, "started", lambda pid: 3)
    ledger = MemoryLedger(FakeTable([Proc(8301, 1, "x", "c", 3)]))
    lifecycle.spawn(["mongod.exe"], owner="host:mongo", kind="mongod", tied=True, holds_data=True, popen=popen,
                    ledger=ledger)
    assert made[0]["creationflags"] & lifecycle.CREATE_BREAKAWAY_FROM_JOB  # out of its starter's jobs
    assert ("named", "limits", lifecycle.JOB_BREAKAWAY_OK) in calls  # its own job: no kill on close
    assert not [c for c in calls if c[0] == "owner's"]  # never the owner's kill-on-close job
    assert ledger.kept[0].holds_data and "untied" in ledger.kept[0].tie
    # a child holding no data stays tied: in the owner's job, which ends it with its owner
    calls.clear()
    lifecycle.spawn(["x.exe"], owner="o", kind="k", popen=popen, ledger=ledger)
    assert ("owner's", "limits", lifecycle.JOB_KILL_ON_CLOSE | lifecycle.JOB_BREAKAWAY_OK) in calls
    assert not made[-1]["creationflags"] & lifecycle.CREATE_BREAKAWAY_FROM_JOB


def test_a_data_holder_whose_starters_job_allows_no_breakaway_is_started_and_said(monkeypatch):
    made = []

    def popen(a, **k):
        made.append(k)
        if k["creationflags"] & lifecycle.CREATE_BREAKAWAY_FROM_JOB:
            raise PermissionError(13, "Access is denied")
        return _Child()

    monkeypatch.setattr(lifecycle.os, "name", "nt")
    monkeypatch.setattr(lifecycle._proc, "started", lambda pid: 3)
    ledger = MemoryLedger(FakeTable([Proc(8301, 1, "x", "c", 3)]))
    lifecycle.spawn(["mongod.exe"], owner="host:mongo", kind="mongod", tied=False, holds_data=True, popen=popen,
                    ledger=ledger, job=lifecycle.JobTie(_K32([], "named"), _Nt(), name="Local\\liminal-job-t",
                                                        kill_on_close=False))
    assert len(made) == 2 and "allows no breakaway" in ledger.kept[0].tie


def test_mongod_and_every_host_are_started_as_holding_data(monkeypatch):
    seen = []
    monkeypatch.setattr(lifecycle, "spawn", lambda args, **kw: seen.append(kw) or type("P", (), {"pid": 1})())
    mongo._spawn(["mongod"])
    from liminal_libs import host

    host.Host.start("live", Path("x.db"))
    assert [kw.get("holds_data") for kw in seen] == [True, True] and seen[0]["kind"] == "mongod"


# -- 5. the library's other forcing places ask and report ---------------------------------------------------------------
class _Hangs:
    """A stand-in Popen past every timeout, deaf to every ask: what is done to it is noted."""

    def __init__(self, args, **kw):
        self.args, self.kw, self.pid, self.returncode, self.done = list(args), kw, 4321, None, []

    def communicate(self, input=None, timeout=None):
        raise subprocess.TimeoutExpired(self.args, timeout)

    def wait(self, timeout=None):
        raise subprocess.TimeoutExpired(self.args, timeout)

    def poll(self):
        return None

    def terminate(self):
        self.done.append("terminate")

    def kill(self):
        self.done.append("kill")


def test_a_commands_timeout_asks_its_tree_and_never_forces_it(monkeypatch):
    made, ran = [], []
    monkeypatch.setattr(proctree, "_nt", lambda: True)
    monkeypatch.setattr(proctree, "TERM_GRACE_S", 0.0)
    monkeypatch.setattr(proctree.subprocess, "run", lambda args, **kw: ran.append(list(args)))
    with pytest.raises(subprocess.TimeoutExpired) as err:
        proctree.run(["git", "status"], 5, popen=lambda a, **k: made.append(_Hangs(a, **k)) or made[-1])
    assert ran == [["taskkill", "/T", "/PID", "4321"]] and made[0].done == []  # no /F, no kill
    assert isinstance(err.value, proctree.StillRunning) and "still running (pid 4321)" in str(err.value)
    signals = []
    monkeypatch.setattr(proctree, "_nt", lambda: False)
    monkeypatch.setattr(proctree.os, "killpg", lambda pid, sig: signals.append((pid, sig)), raising=False)
    with pytest.raises(proctree.StillRunning):
        proctree.run(["git", "status"], 5, popen=lambda a, **k: made.append(_Hangs(a, **k)) or made[-1])
    assert signals == [(4321, proctree.signal.SIGTERM)] and made[1].done == []


def test_a_bpftrace_deaf_to_sigterm_is_left_and_said_never_killed():
    from liminal_libs.ebpf import watch

    proc = _Hangs(["sudo", "bpftrace"])
    assert watch._halt(proc, grace=0.0) is False and proc.done == ["terminate"]


def test_the_recorders_strays_are_asked_never_terminated(monkeypatch):
    from liminal_libs import live
    from liminal_libs import proc as procmod

    sent = []
    monkeypatch.setattr(procmod, "terminate", lambda pid: sent.append((pid, "forced")) or True)  # the old way
    monkeypatch.setattr(lifecycle.OsKiller, "send", lambda self, pid, sig, group=False: sent.append((pid, sig.value)) or True)
    assert live.reap_strays(log=lambda m: None, others=[11, 12]) == 2
    assert sent == [(11, "TERM"), (12, "TERM")]


def test_the_keepers_command_is_asked_when_the_keeper_ends_never_terminated(monkeypatch, tmp_path):
    from liminal_libs.machines import keep

    stand = _Hangs(["python", "-m", "liminal_charts", "serve"])
    stand.wait = lambda timeout=None: (_ for _ in ()).throw(KeyboardInterrupt())
    asked = []
    monkeypatch.setattr(keep.subprocess, "Popen", lambda *a, **k: stand)
    monkeypatch.setattr(proctree, "ask_end", lambda p, grace=proctree.TERM_GRACE_S: asked.append(p) or False)
    with pytest.raises(KeyboardInterrupt):
        keep.run_once(["python"], tmp_path / "keep.log")
    assert asked == [stand] and stand.done == []
    assert "left, not killed" in (tmp_path / "keep.log").read_text(encoding="utf-8")
    assert "KILL_ON_JOB_CLOSE | BREAKAWAY_OK" in (SRC / "machines" / "keep.py").read_text(encoding="utf-8")


def test_a_terminal_closed_is_asked_and_left_never_killed(monkeypatch):
    from liminal_libs.machines import terminal

    stand = _Hangs(["bash"])

    class Stdin:
        def close(self):
            stand.done.append("stdin closed")

    stand.stdin = Stdin()
    monkeypatch.setattr(proctree, "_nt", lambda: False)
    t = object.__new__(terminal.Terminal)
    t.proc = stand
    assert t.close() is False and stand.done == ["stdin closed", "terminate"]


def test_no_other_forcing_place_is_left_in_the_modules_that_had_one():
    for rel in ("machines/ai.py", "machines/download.py", "machines/terminal.py", "netpath.py", "storage/link.py"):
        text = (SRC / rel).read_text(encoding="utf-8")
        for word in ("process.kill()", "child.kill()", "proc.kill()"):
            assert word not in text, f"{rel} still forces: {word}"
