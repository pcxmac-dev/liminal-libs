"""How every part of Liminal is told to end, and what it started ends with it (1.86.0, Monday list item 38).

Stand-ins only: a process table of stand-ins (lifecycle.FakeTable, its own killer), a ledger in memory or in tmp_path,
a clock that moves only when slept on, a stand-in kernel32 and libc, a stand-in liminal-net node, and the apps' routes
called in-process. Nothing is started, signalled or reached.
"""
from __future__ import annotations

import os
import threading
import time

import pytest

from liminal_libs import lifecycle, nodes, stop
from liminal_libs.apps.app import App, Refused
from liminal_libs.apps.authorization import EnvironmentLogin, lent_login
from liminal_libs.lifecycle import FakeClock, FakeTable, MemoryLedger, Proc, Row, Signal
from liminal_libs.sources.conformance import node_problems, problems
from liminal_libs.sources.plugin import FeedPlugin

ME = os.getpid()


@pytest.fixture(autouse=True)
def _nothing_left():
    """Each test's own rows of what "this process started" are its own: none before, none after."""
    with lifecycle._MINE_LOCK:
        saved = dict(lifecycle._MINE)
        lifecycle._MINE.clear()
    yield
    with lifecycle._MINE_LOCK:
        lifecycle._MINE.clear()
        lifecycle._MINE.update(saved)


def machine(*procs, ignores=()):
    table, clock = FakeTable(procs, ignores), FakeClock()
    ledger = MemoryLedger(table)
    return table, clock, ledger, lifecycle.standins(table=table, killer=table, ledger=ledger, clock=clock,
                                                    sleep=clock.sleep)


def child_of(owner: str, pid: int, started: int = 7, ppid: int = ME, cmd: str = "child") -> tuple[Proc, Row]:
    return (Proc(pid, ppid, "C:/elsewhere/child.exe", cmd, started),
            Row(pid=pid, started=started, owner=owner, owner_pid=ME, owner_started=None, kind="test",
                command=cmd.split(), at=time.time()))


class Acme(FeedPlugin):
    name, title, api = "acme", "Acme", "2.0"
    assets = frozenset({"stock"})

    def __init__(self, record=None, **kw):
        super().__init__(**kw)
        object.__setattr__(self, "_record", record if record is not None else [])

    def build(self, settings, request_budget):
        return None

    def app_stopping(self):
        self._record.append(f"plugin {self.name}")


class Beta(Acme):
    name, title = "beta", "Beta"


class Login:
    """A login an app includes (its LOGIN_CLASS): its end is noted."""

    def __init__(self, log=print, superclass=None):
        self.superclass = superclass

    def close(self):
        self.superclass.record.append("login")


class Part:
    def __init__(self, record):
        self.record = record

    def signal(self, sig, deadline, sender=None):
        self.record.append(f"part {Signal.of(sig).value}")


class Demo(App):
    NAME, TITLE, ICON = "demo", "Demo", "plug"
    LOGIN, LOGIN_CLASS = True, Login

    def __init__(self, record, parts=(), **kw):
        super().__init__(log=lambda m: None, login=EnvironmentLogin(env={}), **kw)
        self.record, self._parts = record, tuple(parts)

    def parts(self):
        return self._parts

    def signal_key(self):
        return b"k" * 32


class Headers(dict):
    pass


class Handler:
    def __init__(self, **headers):
        self.headers = Headers(headers)


# -- the signal ------------------------------------------------------------------------------------------------------
def test_a_signal_is_read_from_its_names_and_numbers():
    assert [Signal.of(x) for x in ("TERM", "sigterm", 15, "KILL", "SIGKILL", "9")] == [Signal.TERM] * 3 + [Signal.KILL] * 3
    with pytest.raises(ValueError, match="TERM or KILL"):
        Signal.of("HUP")


# -- an app's end ----------------------------------------------------------------------------------------------------
def test_term_reaches_the_login_a_platform_part_and_every_plugin_in_that_order_then_the_processes():
    record: list[str] = []
    proc, row = child_of("acme", 4001)
    table, clock, ledger, held = machine(proc)
    with held:
        app = Demo(record, parts=[Part(record)])
        assert app.login_object() is not None
        a, b = Acme(record), Beta(record)
        app.attach(a)
        app.attach(b)
        lifecycle.note(row, ledger)
        real = table.send

        def send(pid, sig, group=False):
            record.append(f"process {pid} {Signal.of(sig).value}")
            return real(pid, sig, group)

        table.send = send
        report = app.terminate(Signal.TERM, 5)
    # the plugin's own child ends with its plugin (its last client let go), before any process of the app's own
    assert record == ["login", "part TERM", "plugin acme", "process 4001 TERM", "plugin beta"]
    assert [o["name"] for o in report["objects"]] == ["login", "Part", "acme", "beta"]
    assert a.app is None and a.login is None and app.plugins() == {} and 4001 not in table.rows
    assert app.terminate(Signal.TERM) is report  # twice: the first's report, nothing done again
    assert app.stopping and record.count("login") == 1


def test_kill_ends_the_trees_at_once_without_waiting_and_never_asks_a_plugin_to_stop():
    record: list[str] = []
    proc, row = child_of("demo", 4002)
    grandchild = Proc(4003, 4002, "C:/x/g.exe", "grandchild", 9)
    table, clock, ledger, held = machine(proc, grandchild, ignores={4002, 4003})
    with held:
        app = Demo(record)
        app.attach(Acme(record))
        lifecycle.note(row, ledger)
        at = clock()
        report = app.terminate(Signal.KILL, 30)
    assert clock() == at  # nothing waited for
    assert table.sent == [(4003, "KILL"), (4002, "KILL")]  # deepest first, KILL alone
    assert {p["how"] for p in report["processes"]} == {"killed"} and "plugin acme" not in record
    assert app.plugins() == {}


def test_a_kill_while_a_term_is_under_way_kills_what_was_started_at_once():
    record: list[str] = []
    proc, row = child_of("demo", 4010)
    table, clock, ledger, held = machine(proc, ignores={4010})
    release = threading.Event()

    class Slow(Acme):
        name, title = "slow", "Slow"

        def app_stopping(self):
            app.terminate(Signal.KILL)  # the KILL comes now, from another caller, while this TERM is under way
            release.set()

    with held:
        app = Demo(record)
        app.attach(Slow(record))
        lifecycle.note(row, ledger)
        app.terminate(Signal.TERM, 30)
    assert release.is_set() and (4010, "KILL") in table.sent and (4010, "TERM") not in table.sent


def test_a_plugin_that_does_not_end_within_its_deadline_is_late_and_its_trees_are_killed():
    record: list[str] = []
    proc, row = child_of("stuck", 4020)
    table, clock, ledger, held = machine(proc, ignores={4020})
    gate = threading.Event()

    class Stuck(Acme):
        name, title = "stuck", "Stuck"
        STOP_DEADLINE_S = 0.2

        def app_stopping(self):
            gate.wait(5)  # ignores TERM until let go below

    try:
        with held:
            app = Demo(record)
            app.attach(Stuck(record))
            lifecycle.note(row, ledger)
            # the plugin's deadline is read on the real clock here: the worker is joined for it
            with lifecycle.standins(table=table, killer=table, ledger=ledger, clock=time.monotonic, sleep=clock.sleep):
                out = app.signal_plugin("stuck", Signal.TERM)
    finally:
        gate.set()
    assert out["how"] == "late" and (4020, "KILL") in table.sent and 4020 not in table.rows


def test_stop_is_terminate_and_a_request_while_ending_is_refused(tmp_path):
    record: list[str] = []
    app = Demo(record)
    app.stop()
    assert app.stopping and app._terminated is not None
    with pytest.raises(RuntimeError, match="is ending"):
        app.attach(Acme(record))


# -- the plugins' login ----------------------------------------------------------------------------------------------
def test_a_plugin_asked_before_it_is_attached_is_lent_the_environments_login_and_its_app_replaces_it(caplog,
                                                                                                    monkeypatch):
    from liminal_libs.sources import plugin as contract

    monkeypatch.setattr(contract, "_LENT_SAID", set())
    class Holder(Acme):
        def build(self, settings, request_budget):
            return self.login  # what it holds while it is asked

    app = Demo([])
    p = Holder()
    assert p.login is None
    with caplog.at_level("INFO", logger="liminal_libs.sources.plugin"):
        held = [p.ask("build", None, 1), p.ask("build", None, 2)]
    assert held == [lent_login()] * 2 and isinstance(held[0], EnvironmentLogin) and held[0].env is None
    assert p.login is None  # between asks none again, as before 1.86.0
    assert [r.getMessage() for r in caplog.records].count(
        "acme was asked before an app attached it: lent the environment's login") == 1  # said once
    app.attach(p)
    assert p.login is app.login and p.app is app and p.ask("build", None, 1) is app.login
    app.detach("acme")
    assert p.login is None and p.app is None


def test_an_app_given_no_login_lends_the_environments():
    class Bare(App):
        NAME, TITLE, ICON = "bare", "Bare", "plug"

    app = Bare(log=lambda m: None)
    p = Acme()
    app.attach(p)
    assert p.login is lent_login() and p.login is app.lent_login() and app.login is None


def test_a_signal_from_anyone_but_its_app_or_its_login_is_refused():
    app = Demo([])
    p = Acme()
    with pytest.raises(lifecycle.SignalRefused, match="attached to no app"):
        p.signal(Signal.TERM, lifecycle.deadline_in(1), sender=app)
    app.attach(p)
    for stranger in (None, object(), Demo([])):
        with pytest.raises(lifecycle.SignalRefused, match="only from its own app"):
            p.signal(Signal.TERM, lifecycle.deadline_in(1), sender=stranger)
    assert p.signal(Signal.TERM, lifecycle.deadline_in(1), sender=app)["stopped"] is True
    assert p.signal(Signal.KILL, lifecycle.deadline_in(1), sender=p.login)["signal"] == "KILL"


def test_a_plugin_that_replaces_its_login_is_refused_by_its_app_and_by_the_conformance():
    class Swapper(Acme):
        name, title = "swapper", "Swapper"

        def attach(self, app, login):
            out = super().attach(app, login)
            object.__setattr__(self, "login", EnvironmentLogin(env={}))  # another in its place
            return out

    app = Demo([])
    with pytest.raises(RuntimeError, match="did not keep the login"):
        app.attach(Swapper())
    assert app.plugins() == {}
    assert any("does not hold the login" in w or "cannot be attached" in w for w in node_problems(Swapper()))

    class Owned(Acme):
        name, title = "owned", "Owned"

        @property
        def login(self):
            return None

    assert any("makes `login` its own" in w for w in problems(Owned()))


# -- the modes and the deadlines ---------------------------------------------------------------------------------------
def test_service_mode_is_refused_by_the_conformance_and_deadlines_must_be_seconds():
    class Daemon(Acme):
        name, title = "daemon", "Daemon"
        MODE = "service"

    class Odd(Acme):
        name, title = "odd", "Odd"
        MODE, START_DEADLINE_S, STOP_DEADLINE_S = "sometimes", 0, float("inf")

    assert "daemon: MODE 'service': service mode is not yet allowed: on demand only" in problems(Daemon())
    found = problems(Odd())
    assert any("MODE 'sometimes'" in w for w in found)
    assert any("START_DEADLINE_S 0" in w for w in found) and any("STOP_DEADLINE_S inf" in w for w in found)
    assert not [w for w in problems(Acme()) if "MODE" in w or "DEADLINE" in w]
    assert lifecycle.mode_of(Acme()) == {"mode": "on_demand", "startDeadline": 10.0, "stopDeadline": 15.0}


def test_an_on_demand_plugins_children_end_when_its_last_client_detaches():
    proc, row = child_of("acme", 4030)
    other, other_row = child_of("beta", 4031)
    table, clock, ledger, held = machine(proc, other)
    with held:
        app = Demo([])
        app.attach(Acme())
        app.attach(Beta())
        lifecycle.note(row, ledger)
        lifecycle.note(other_row, ledger)
        app.detach("acme")
        assert table.sent == [(4030, "TERM")] and 4030 not in table.rows and 4031 in table.rows  # its own alone
        assert [r.pid for r in ledger.kept] == [4031]


# -- the trees and the ledger ----------------------------------------------------------------------------------------
def test_a_reused_pid_is_never_signalled():
    table = FakeTable([Proc(5001, 1, "x", "someone else's", started=99)])
    out = lifecycle.end_trees([Proc(5001, 1, "x", "ours", started=7)], Signal.KILL, 0, table=table, killer=table)
    assert out == [{"pid": 5001, "how": "gone", "why": "it had ended (or its id is another's now)"}] and table.sent == []
    # a "child" that started before its parent is another process under a parent id given again: left alone
    table = FakeTable([Proc(5002, 1, "x", "ours", 50), Proc(5003, 5002, "x", "older than its parent", 10)])
    lifecycle.end_trees([Proc(5002, 1, "x", "ours", 50)], Signal.KILL, 0, table=table, killer=table)
    assert table.sent == [(5002, "KILL")]


def test_term_waits_its_timeout_then_kills_what_is_left():
    table = FakeTable([Proc(6001, ME, "x", "heeds", 1), Proc(6002, ME, "x", "ignores", 1)], ignores={6002})
    clock = FakeClock()
    out = lifecycle.end_trees([table.rows[6001], table.rows[6002]], Signal.TERM, 3.0, table=table, killer=table,
                              clock=clock, sleep=clock.sleep)
    assert {r["pid"]: r["how"] for r in out} == {6001: "terminated", 6002: "killed"}
    assert clock.now - 1000.0 >= 3.0 and table.sent == [(6001, "TERM"), (6002, "TERM"), (6002, "KILL")]


def test_the_ledger_file_is_written_whole_and_drops_the_rows_of_processes_gone(tmp_path):
    table = FakeTable([Proc(7001, ME, "x", "alive", 5), Proc(7002, ME, "x", "reused", 6)])
    ledger = lifecycle.Ledger(tmp_path / "processes" / "here.json", table)
    for pid, started in ((7001, 5), (7002, 5), (7003, 5)):  # 7002 is another process now, 7003 is gone
        ledger.add(Row(pid=pid, started=started, owner="demo", owner_pid=ME, owner_started=1, kind="t", command=["x"]))
    assert [r.pid for r in ledger.rows()] == [7001]
    assert sorted(p.name for p in (tmp_path / "processes").iterdir()) == ["here.json"]  # no temporary or lock left
    ledger.forget(7001)
    assert ledger.rows() == []


def test_spawn_writes_its_row_and_ties_the_child_to_its_owner(monkeypatch):
    class Child:
        pid, _handle = 8001, 77

    made = []

    def popen(args, **kw):
        made.append((args, kw))
        return Child()

    class K32:
        def __init__(self):
            self.calls = []

        def CreateJobObjectW(self, a, b):
            self.calls.append("create")
            return 5

        def SetInformationJobObject(self, job, cls, info, size):
            limits = ctypes_cast(info)
            self.calls.append(("limits", cls, limits))
            return 1

        def AssignProcessToJobObject(self, job, handle):
            self.calls.append(("assign", job, handle))
            return 1

        def CloseHandle(self, h):
            self.calls.append(("close", h))
            return 1

    def ctypes_cast(info):
        return info._obj.BasicLimitInformation.LimitFlags

    k32 = K32()
    ledger = MemoryLedger(FakeTable([Proc(8001, ME, "x", "c", 3)]))
    monkeypatch.setattr(lifecycle._proc, "started", lambda pid: 3)
    monkeypatch.setattr(lifecycle.os, "name", "nt")
    child = lifecycle.spawn(["mongod", "--port", "1"], owner="host:mongo", kind="mongod", popen=popen, ledger=ledger,
                            job=lifecycle.JobTie(k32), creationflags=0x8)
    assert child.pid == 8001 and made[0][1]["creationflags"] == 0x8 | lifecycle.NO_WINDOW
    assert k32.calls[0] == "create" and k32.calls[1][1] == lifecycle.EXTENDED_LIMITS
    assert k32.calls[1][2] & lifecycle.JOB_KILL_ON_CLOSE and k32.calls[2] == ("assign", 5, 77)
    row = ledger.kept[0]
    assert (row.pid, row.started, row.owner, row.owner_pid, row.kind, row.tie) == (8001, 3, "host:mongo", ME, "mongod", "job")
    assert lifecycle.mine("host:mongo")[0].command == ["mongod", "--port", "1"]


def test_a_job_that_cannot_be_had_is_noted_never_fatal():
    class NoJob:
        def CreateJobObjectW(self, a, b):
            return 0

    class Child:
        pid, _handle = 8002, 1

    tie = lifecycle.JobTie(NoJob())
    assert tie.tie(Child()).startswith("no job: CreateJobObjectW failed")

    class Refuses(NoJob):
        def CreateJobObjectW(self, a, b):
            return 9

        def SetInformationJobObject(self, *a):
            return 1

        def AssignProcessToJobObject(self, job, handle):
            return 0

    assert lifecycle.JobTie(Refuses()).tie(Child()).startswith("no job: AssignProcessToJobObject failed")


def test_a_linux_child_is_sent_sigterm_when_its_owner_ends_only_when_started_on_the_main_thread():
    class Libc:
        def __init__(self):
            self.called = []

        def prctl(self, *args):
            self.called.append(args)

    libc = Libc()
    pre = lifecycle.pdeathsig_preexec(libc, sig=15, main_thread=True)
    pre()
    assert libc.called == [(lifecycle.PR_SET_PDEATHSIG, 15, 0, 0, 0)]
    assert lifecycle.pdeathsig_preexec(libc, main_thread=False) is None  # a thread that ends would end the child


def test_a_commands_secrets_are_hidden_when_it_is_shown():
    assert lifecycle.scrub_command(["srv", "--api-key", "s3cret", "--token=abc", "--port", "1"]) == [
        "srv", "--api-key", "<hidden>", "--token=<hidden>", "--port", "1"]


# -- an app's routes: with the proof of this user's key ----------------------------------------------------------------
def test_the_signal_route_needs_the_proof_of_this_users_key():
    app = Demo([])
    later = []
    app.later = later.append
    with pytest.raises(Refused) as e:
        app.api(Handler(), "POST", "/api/app/signal", {}, {"signal": "TERM"})
    assert e.value.status == 401
    with pytest.raises(Refused) as e:
        app.api(Handler(**{lifecycle.PROOF_HEADER: lifecycle.proof(b"x" * 32)}), "POST", "/api/app/signal", {}, {})
    assert e.value.status == 403 and later == []
    proved = Handler(**{lifecycle.PROOF_HEADER: lifecycle.proof(app.signal_key())})
    status, data = app.api(proved, "POST", "/api/app/signal", {}, {"signal": "KILL", "timeout": 2})
    assert status == 202 and data["signal"] == "KILL" and data["pid"] == ME and len(later) == 1
    later[0]()
    assert app.stopping and app._terminated["signal"] == "KILL"


def test_a_plugin_is_asked_what_it_is_through_its_app_reading_only():
    app = Demo([])
    app.attach(Acme())
    proved = Handler(**{lifecycle.PROOF_HEADER: lifecycle.proof(app.signal_key())})
    proc, row = child_of("acme", 4040, cmd="srv --api-key hush")
    table, clock, ledger, held = machine(proc)
    with held:
        lifecycle.note(row, ledger)
        status, mode = app.api(proved, "GET", "/api/plugins/acme/mode", {}, None)
        _, procs = app.api(proved, "GET", "/api/plugins/acme/processes", {}, None)
        _, face = app.api(proved, "GET", "/api/plugins/acme/interface", {}, None)
        _, status_of = app.api(proved, "GET", "/api/plugins/acme/status", {}, None)
    assert status == 200 and mode == {"name": "acme", "mode": "on_demand", "startDeadline": 10.0, "stopDeadline": 15.0}
    assert [p["command"] for p in procs["processes"]] == [["srv", "--api-key", "<hidden>"]]
    assert face["name"] == "acme" and status_of == {"name": "acme", "status": None, "why": "it answers no status"}
    with pytest.raises(Refused) as e:
        app.api(Handler(), "GET", "/api/plugins/acme/mode", {}, None)
    assert e.value.status == 401


# -- a plugin as its node ----------------------------------------------------------------------------------------------
class StandInNode:
    def __init__(self, name, kind, scope, hillock, interface, ipc_dir=None, timing=None):
        self.name, self.hillock, self.interface = name, hillock, interface
        self.stopped, self.fired = [], []

    def stop(self, why):
        self.stopped.append(why)

    def fire(self, signal, data):
        self.fired.append((signal, data))

    def stage(self):
        return "ended" if self.stopped else "running"


def test_a_plugin_node_offers_its_hooks_and_the_lifecycles_requests_and_ends_on_term(tmp_path):
    app = Demo([])
    node, hillock = nodes.plugin_node(Acme(), app, scope=tmp_path, node_factory=StandInNode)
    hillock._later = lambda fn: fn()
    face = node.interface
    assert node.name == "plugin-acme" and face["base"][0] == nodes.TRAIT
    assert {"build", "term", "kill", "ask"} <= set(face["methods"]) and face["signals"]["lifecycle"]["kind"] == "stream"
    assert face["methods"]["build"]["signature"] == "(settings, request_budget)"
    assert hillock.request({"pid": 1}, "build", [None, 3], {}) is None  # a hook, through its app
    assert hillock.request({}, "ask", ["mode"], {})["mode"] == "on_demand"
    out = hillock.request({}, "term", [], {})
    assert out["stage"] == "ended" and node.stopped == ["TERM"] and [f[1]["stage"] for f in node.fired] == ["ending", "ended"]
    with pytest.raises(nodes.Refused, match="is ending"):
        hillock.request({}, "build", [None, 3], {})


def test_kill_ends_a_plugin_nodes_own_process_after_its_trees():
    exits = []
    app = Demo([])
    proc, row = child_of("acme", 4050)
    table, clock, ledger, held = machine(proc, ignores={4050})
    with held:
        node, hillock = nodes.plugin_node(Acme(), app, node_factory=StandInNode, own_process=True)
        hillock._exit, hillock._later = exits.append, (lambda fn: fn())
        lifecycle.note(row, ledger)
        hillock.kill()
    assert table.sent == [(4050, "KILL")] and node.stopped == ["KILL"] and exits == [nodes.KILL_EXIT]


def test_a_start_that_misses_its_deadline_is_reported_and_its_tree_ended():
    table = FakeTable([Proc(4060, ME, "py", "python -m liminal_libs.nodes serve acme", 3)])
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
    assert out["remote"] is None and "start deadline" in out["why"] and table.sent == [(4060, "KILL")]


# -- the command -------------------------------------------------------------------------------------------------------
VENV = "C:/liminal/.venv/Scripts"


class Apps:
    """The apps' routes as the command reaches them: which answer, what they were asked."""

    def __init__(self, running: dict[str, int], key: bytes):
        self.running, self.key, self.asked = running, key, []

    def __call__(self, method, url, headers, body):
        port = int(url.split(":")[2].split("/")[0])
        name = next((n for n in stop.APPS if stop.app_port(n, {}) == port), None)
        path = "/" + url.split("/", 3)[3]
        self.asked.append((method, name, path))
        if name not in self.running:
            return 0, {}
        if path == "/api/app":
            return 200, {"app": name}
        if path == "/api/plugins":
            return 200, {"plugins": {"acme": {}} if name == "platform" else {}}
        if not lifecycle.proof_ok(self.key, headers.get(lifecycle.PROOF_HEADER, "")):
            return 401, {"error": "no proof"}
        if path == "/api/app/signal":
            return 202, {"app": name, "pid": self.running[name]}
        if path.startswith("/api/plugins/acme/"):
            return 200, {"name": "acme", "asked": path.rsplit("/", 1)[1]}
        return 404, {}


def command(table, apps, ledger=None, clock=None, node=None):
    clock = clock or FakeClock()
    out: list[str] = []
    cmd = stop.SignalCommand(node=node or _NoNode(), http=apps, table=table, killer=table,
                             ledger=ledger or MemoryLedger(table), key=apps.key, env={}, venvs=[VENV],
                             clock=clock, sleep=clock.sleep, out=out.append)
    return cmd, out


class _NoNode:
    def reach(self, *a):
        raise ConnectionError("no node answers")


def test_the_stop_command_asks_the_apps_waits_then_ends_what_is_left_by_its_tree():
    me = Proc(ME, 1, f"{VENV}/python.exe", "python -m liminal_libs.stop", 1)
    charts = Proc(9001, 1, f"{VENV}/python.exe", "python -m liminal_charts serve", 2)
    sync = Proc(9002, 9001, f"{VENV}/python.exe", "python -m liminal_charts sync --extras-only", 3)
    mongod = Proc(9003, 1, "C:/mongo/bin/mongod.exe", "mongod --port 27017", 4)
    table = FakeTable([me, charts, sync, mongod], ignores={9001, 9002})
    ledger = MemoryLedger(table)
    ledger.add(Row(pid=9003, started=4, owner="host:mongo", owner_pid=1, owner_started=None, kind="mongod",
                   command=["mongod"]))
    apps = Apps({"charts": 9001}, b"k" * 32)
    cmd, out = command(table, apps, ledger)
    assert cmd.signal(Signal.TERM, timeout=5) == stop.EXIT_OK
    assert ("POST", "charts", "/api/app/signal") in apps.asked
    assert "app charts (pid 9001): asked: TERM through its route" in out
    # what was left after the timeout ended by its tree: the sync under the charts, the charts, mongod by the ledger
    assert (9002, "KILL") in table.sent and (9001, "KILL") in table.sent and (9003, "TERM") in table.sent
    assert ME in table.rows and not any(pid == ME for pid, _ in table.sent)  # never the command itself


def test_the_stop_commands_list_changes_nothing():
    charts = Proc(9101, 1, f"{VENV}/python.exe", "python -m liminal_charts serve", 2)
    table = FakeTable([charts])
    apps = Apps({"charts": 9101}, b"k" * 32)
    cmd, out = command(table, apps)
    assert cmd.signal(Signal.TERM, listing=True) == stop.EXIT_OK
    assert table.sent == [] and not [a for a in apps.asked if a[0] == "POST"]
    assert any("would be asked" in line for line in out) and any("would end" in line for line in out)


def test_a_process_that_is_not_liminals_is_never_touched():
    others = [Proc(9201, 1, f"{VENV}/python.exe", "python -m pip install x", 2),  # Liminal's python, not its module
              Proc(9202, 1, "C:/Other/python.exe", "python -m liminal_charts serve", 2),  # its module, not its python
              Proc(9203, 1, "C:/mongo/bin/mongod.exe", "mongod", 2)]  # no ledger row: not Liminal's
    table = FakeTable(others)
    cmd, out = command(table, Apps({}, b"k" * 32))
    assert cmd.signal(Signal.KILL) == stop.EXIT_OK and table.sent == []


def test_the_command_reaches_an_app_by_its_node_first():
    class Remote:
        def __init__(self):
            self.asked = []

        def request(self, method, *args):
            self.asked.append((method, args))
            return {"pid": 9301}

        def pid(self):
            return 9301

    remote = Remote()

    class Node:
        def reach(self, name, scope, launcher):
            if name == "app-platform":
                return remote
            raise ConnectionError("no node")

    table = FakeTable([])
    apps = Apps({}, b"k" * 32)
    cmd, out = command(table, apps, node=Node())
    assert cmd.signal(Signal.KILL, apps=["platform"]) == stop.EXIT_OK
    assert remote.asked == [("kill", ())] and "app platform (pid 9301): asked: KILL through its node" in out


def test_ask_finds_the_app_holding_a_plugin_and_ask_all_lists_modes_and_deadlines():
    table = FakeTable([])
    apps = Apps({"platform": 9401}, b"k" * 32)
    cmd, out = command(table, apps)
    assert cmd.ask("acme", "mode") == stop.EXIT_OK
    assert ("GET", "platform", "/api/plugins/acme/mode") in apps.asked and '"asked": "mode"' in "".join(out)
    out.clear()
    assert cmd.ask(None, every=True) == stop.EXIT_OK
    assert any(line.startswith("  plugin acme: answered") for line in out)


def test_the_executables_say_what_they_were_not_told():
    cmd, out = command(FakeTable([]), Apps({}, b"k" * 32))
    assert stop.signal_main(["TERM"], cmd) == stop.EXIT_USAGE  # neither --all, --app nor --plugin
    assert stop.signal_main(["HUP", "--all"], cmd) == stop.EXIT_USAGE
    assert stop.stop_main(["--list"], cmd) == stop.EXIT_OK


def test_the_console_scripts_are_installed_as_executables():
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'liminal-signal = "liminal_libs.stop:signal_main"' in text and 'liminal-stop = "liminal_libs.stop:stop_main"' in text


# -- every plugin found here, served as its node on stand-ins ------------------------------------------------------------
def _found():
    from liminal_libs.sources import registry

    out = {}
    for group in (registry.providers, registry.publishers, registry.assistants, registry.machines, registry.databases,
                  registry.auditors):
        out.update(group())
    return sorted(out.items())


FOUND = _found()


@pytest.mark.parametrize("plugin", [p for _, p in FOUND], ids=[n for n, _ in FOUND])
def test_every_plugin_found_is_served_as_its_node_answers_ask_and_ends_on_term_within_its_deadline(plugin):
    """node_problems: attached with its app's login, ASK answered in shape, TERM ended within its deadline with nothing
    left (ledger, children, claims), a child ignoring TERM killed at the deadline. One that cannot be served yet is a
    named xfail with its reason."""
    found = node_problems(plugin)
    cannot = [w for w in found if "cannot be attached and served" in w or "no copy of it can be made" in w]
    if cannot:
        pytest.xfail(cannot[0])
    assert found == []


def test_the_plugins_found_are_counted():
    assert len(FOUND) >= 1
