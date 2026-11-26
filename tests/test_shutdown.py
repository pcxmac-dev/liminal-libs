"""What ends promptly when asked (1.87.0; the shutdown audit of 2026-11-24): hosts at their last client's detach, the
rate limiter's wait, the derive pass, composites, publications, datasets, the auditors' sweep, MongoDB's keeper and
server, a child and its redirector's child in one job, an app's stop event, and an app's plugins told together.

Stand-ins only, every order forced: no process is started, no pipe or port opened, nothing waited for past a
fraction of a second.
"""
from __future__ import annotations

import threading
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from liminal_libs import auditing, composite, datasets, derive, host, lifecycle, mongo, publications, stop
from liminal_libs.apps.app import App
from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.errors import Paused
from liminal_libs.lifecycle import FakeClock, FakeTable, MemoryLedger, Proc, Row, Signal
from liminal_libs.ratelimit import RateLimiter
from liminal_libs.sources.http import HttpClient
from liminal_libs.sources.plugin import FeedPlugin

pytestmark = pytest.mark.usefixtures("stand_in_environment")  # its code reads this process's environment


# -- 1. hosts -----------------------------------------------------------------------------------------------------------
class Conn:
    """A client's end of a host's pipe: its hello, then what it says (a word, or EOFError: its process ended)."""

    def __init__(self, *said):
        self.said = list(said)
        self.sent = []

    def poll(self, timeout=None):
        return bool(self.said)

    def recv(self):
        item = self.said.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def send(self, what):
        self.sent.append(what)

    def close(self):
        pass


def a_host(tmp_path, idle=60.0):
    return host.Host("feed-x", tmp_path / "liminal.db", idle=idle, start=30, log=lambda m: None)


def test_a_hosts_last_client_that_lets_it_go_ends_it_at_once(tmp_path):
    h = a_host(tmp_path)
    h._client(Conn({"attach": "feed-x", "pid": 1}, "detach"), 1)
    assert h.idle_for() == 0.0 and h.check_idle(now=100.0) is True and h.reason == "its last client let it go"


def test_a_host_whose_last_clients_process_is_gone_waits_a_short_idle(tmp_path):
    h = a_host(tmp_path)
    h._client(Conn({"attach": "feed-x", "pid": 1}, EOFError("its process ended")), 1)
    assert h.idle_for() == host.GONE_SECONDS
    assert h.check_idle(now=100.0) is False and h.check_idle(now=100.0 + host.GONE_SECONDS - 0.1) is False
    assert h.check_idle(now=100.0 + host.GONE_SECONDS) is True and "5 s" in h.reason


def test_a_page_in_touch_keeps_a_host_for_its_idle_time(tmp_path):
    h = a_host(tmp_path, idle=60.0)
    h._client(Conn({"attach": "feed-x", "pid": 1}, "detach"), 1)
    h.touch()
    assert h.check_idle() is False and not h.stop.is_set()


def test_a_hosts_work_that_fails_is_logged_with_its_traceback(tmp_path, monkeypatch):
    lines = []

    class Listener:
        def __init__(self, *a, **k):
            pass

        def accept(self):
            h.stop.wait(2)
            raise OSError("closed")

        def close(self):
            h.stop.set()

    monkeypatch.setattr(host, "Listener", Listener)
    monkeypatch.setattr(host, "key", lambda: b"k" * 32)
    h = host.Host("history", tmp_path / "liminal.db", idle=60, log=lines.append)

    def work(stop):
        raise ValueError("a month that cannot be copied")

    with pytest.raises(ValueError):
        h.serve(work)
    said = "\n".join(lines)
    assert "host history: its work failed:" in said and "Traceback" in said and "a month that cannot be copied" in said


# -- 2. the rate limiter and the HTTP client ----------------------------------------------------------------------------
def test_a_rate_wait_ends_at_a_stop_within_a_second():
    clock = FakeClock(0.0)
    limiter = RateLimiter(1, 25.0, clock=clock, sleep=clock.sleep)
    limiter.acquire()
    asked = []

    def stopping():
        asked.append(clock())
        return "the app stops" if clock() >= 1.5 else None

    with pytest.raises(Paused, match="the app stops"):
        limiter.acquire(stop=stopping)
    assert clock() <= 2.0  # not 25 s: in slices of a second at the most


def test_a_streamed_download_ends_at_a_stop_between_its_pieces():
    class Writer:
        def __init__(self):
            self.pieces, self.abandoned = [], False

        def write(self, piece):
            self.pieces.append(piece)

        def abandon(self):
            self.abandoned = True

    writer = Writer()

    class Pull:
        def payload(self, path, status):
            return writer

    class Resp:
        status_code = 200

        def iter_content(self, n):
            yield from (b"a", b"b", b"c")

        def close(self):
            pass

    told = iter([None, "the app stops"])
    with pytest.raises(Paused, match="the app stops"):
        HttpClient._to_cache(Pull(), "https://x.example/p", Resp(), True, lambda: next(told))
    assert writer.pieces == [b"a"] and writer.abandoned


# -- 3. derive and composites --------------------------------------------------------------------------------------------
class Watching:
    def __init__(self, tickers):
        self.tickers = tickers
        self.kv = {}

    def watchlist(self):
        return [{"source": "massive", "ticker": t, "asset": "stock", "source_ticker": t} for t in self.tickers]

    def contracts(self, *a):
        return []

    def stored_series(self):
        return [("massive", t, "minute") for t in self.tickers]

    def kv_set(self, k, v):
        self.kv[k] = v

    def prune_changes(self):
        pass


def test_the_derive_pass_ends_before_the_next_symbol_when_asked():
    built = []

    class Builder(derive.Builder):
        def symbol(self, source, ticker, asset, progress=(1, 1), exchange=None):
            built.append(ticker)
            return 1

    store = Watching(["AAA", "BBB", "CCC", "DDD"])
    n = Builder(store, log=lambda m: None).run(stop=lambda: len(built) >= 2)
    assert built == ["AAA", "BBB"] and n == 2


def test_the_composite_refresh_ends_before_the_next_asset_when_asked():
    class Store(Watching):
        def bar_edges(self, *a):
            raise AssertionError("nothing is read once it is asked to stop")

    out = composite.refresh(Store(["AAA", "BBB"]), {}, datetime(2026, 11, 24, tzinfo=timezone.utc), log=lambda m: None,
                            stop=lambda: True)
    assert out == {}


# -- 4. publications and datasets ---------------------------------------------------------------------------------------
def test_publications_end_before_the_next_feed_when_asked(monkeypatch):
    now = datetime(2026, 11, 24, 12, tzinfo=timezone.utc)

    class Gdb:
        def recheck_get(self, name):
            return {"at": now.isoformat()}

        def fetched(self):
            return {}

    class Feed:
        def __init__(self, key):
            self.key, self.url, self.agency = key, f"https://x.example/{key}", "X"

    class Pub:
        name, title, kind, feeds = "x", "X", "vendor", [Feed("a"), Feed("b"), Feed("c")]

        class policy:
            contact = False

    reader = publications.Reader(Gdb(), session=object(), log=lambda m: None, contact="me")
    read = []
    monkeypatch.setattr(reader, "set_up", lambda pub: True)
    monkeypatch.setattr(reader, "kill", lambda pub, now: False)
    monkeypatch.setattr(reader, "held", lambda pub, now: None)
    monkeypatch.setattr(reader, "next_read", lambda pub, feed, now, row=None: now)
    monkeypatch.setattr(reader, "read", lambda pub, feed, now: read.append(feed.key))
    reader.stopping = lambda: len(read) >= 1
    reader._step_one(Pub(), now, False)
    assert read == ["a"]
    assert "stopping" in publications.Context.__dataclass_fields__  # lent to each read


def test_a_datasets_fetch_ends_before_the_next_file_when_asked(monkeypatch):
    got = []

    class Session:
        def get(self, url, **kw):
            got.append(url)
            raise datasets.requests.ConnectionError("a stand-in")

    class Queue:
        def __init__(self, *a):
            pass

        plan = start = end = lambda self, *a, **k: None

    class Ds:
        name, title = "ds", "DS"

        def files(self, today):
            return ["u1", "u2", "u3"]

    monkeypatch.setattr(datasets, "due_files", lambda store, ds, today, force: [("https://x/u1", False),
                                                                                ("https://x/u2", False)])
    monkeypatch.setattr(datasets, "FileQueue", Queue)
    monkeypatch.setattr(datasets, "refusal", lambda ds, url: None)
    f = datasets.DatasetFetcher(object(), date(2026, 11, 24), Session(), log=lambda m: None, stop=lambda: len(got) >= 1)
    assert f.files(Ds()) == 0 and got == ["https://x/u1"]


def test_git_is_run_through_proctree_so_its_tree_ends_at_its_timeout(monkeypatch):
    import subprocess

    from liminal_libs import proctree

    asked = []

    def run(args, timeout, **kw):
        asked.append((args, timeout))
        return subprocess.CompletedProcess(args, 0, b"out", b"")

    monkeypatch.setattr(proctree, "run", run)
    assert datasets._git(Path("repo"), "status") == "out" and asked == [(["git", "-C", "repo", "status"], 600)]

    def late(args, timeout, **kw):
        raise subprocess.TimeoutExpired(args, timeout)

    monkeypatch.setattr(proctree, "run", late)
    with pytest.raises(datasets.GitError, match="did not end within 600 s"):
        datasets._git(Path("repo"), "fetch")


# -- 5. the auditors' sweep ---------------------------------------------------------------------------------------------
def test_the_auditors_sweep_ends_before_the_next_series_when_asked(monkeypatch):
    class Store(Watching):
        def kv_get(self, k):
            return self.kv.get(k)

    monkeypatch.setattr(auditing, "read_only", lambda: False)
    monkeypatch.setattr(auditing, "recover", lambda *a, **k: 0)
    monkeypatch.setattr(auditing, "audit_pulls", lambda *a, **k: [])
    monkeypatch.setattr(auditing, "tidy", lambda *a, **k: {"removed": 0, "forgotten": 0})
    seen = []

    class Visit:
        pulls = days = holes = absent = closed = rules = 0
        skipped = False

    class Sweep(auditing.Sweep):
        def _ledger_only(self):
            return 0

        def series(self, row):
            seen.append(row["ticker"])
            return Visit()

    out = Sweep(Store(["AAA", "BBB", "CCC"]), policy_=auditing.Policy()).run(budget_s=60, stop=lambda: len(seen) >= 1)
    assert seen == ["AAA"] and out["stopped"] is True and out["complete"] is False


# -- 6. MongoDB's keeper and server -------------------------------------------------------------------------------------
class Waits:
    """The keeper's stop event: a look each time, `n` looks before its clients are gone."""

    def __init__(self, n):
        self.n = n

    def wait(self, timeout=None):
        self.n -= 1
        return self.n < 0


def keep(answers, *, pid=4242, alive=lambda pid: False, looks=10, clock=None):
    clock = clock or FakeClock(0.0)
    said, ended = [], []
    pings = iter(answers)

    def answer():
        clock.now += 5.0  # a look every KEEP_SECONDS
        return next(pings, False)

    mongo.keep(Path("data"), Waits(looks), said.append, starter=lambda d: pid, answers=answer,
               ender=lambda: ended.append(True), alive=alive, started_of=lambda p: 7, clock=clock)
    return said, ended


def test_one_failed_ping_does_not_end_the_keeper():
    said, ended = keep([True, False, True, True, True], looks=5)
    assert not any("the keeper ends" in s for s in said) and ended == [True]  # its clients gone: ended then, cleanly


def test_a_server_gone_for_its_grace_ends_the_keeper_and_a_busy_one_of_its_own_does_not():
    said, ended = keep([False] * 10)
    assert any("has not answered 3 pings" in s for s in said) and ended == [True]
    said, _ = keep([False] * 6, alive=lambda pid: True, looks=6)  # the process it started is still there: busy
    assert not any("the keeper ends" in s for s in said)


def test_an_orphan_server_is_adopted_not_started_twice():
    said, ended = keep([True], pid=None, looks=1)
    assert said[0].startswith("host mongo: server running already: adopted") and ended == [True]


def test_the_keepers_look_is_keep_seconds_as_set_when_it_runs(monkeypatch):
    # 1.88.1: the default was fixed at import (1.87.0), and a KEEP_SECONDS set later was not heard
    asked = []

    class Stop:
        def wait(self, timeout=None):
            asked.append(timeout)
            return True  # its clients are gone at the first look
    monkeypatch.setattr(mongo, "KEEP_SECONDS", 0.05)
    mongo.keep(Path("data"), Stop(), lambda m: None, starter=lambda d: None, answers=lambda: True,
               ender=lambda: None, alive=lambda pid: False, started_of=lambda p: 7)
    assert asked == [0.05]


def test_mongo_stop_waits_for_the_servers_process_to_exit():
    # 1.88.4: its own shutdown, then a wait for its process (never a kill: test_clean_shutdowns has the one left)
    clock = FakeClock(0.0)
    alive = [True] * 4
    import liminal_libs.mongo as m

    assert m.stop(clock=clock, sleep=clock.sleep, log=lambda s: None, answers=lambda: True, shutdown=lambda: 4242,
                  alive=lambda pid: alive.pop(0) if alive else False, started_of=lambda pid: 7) is True
    assert clock() == 2.0  # four looks of 0.5 s


# -- 7. a child and what its redirector starts, in one job ---------------------------------------------------------------
def test_an_untied_child_is_started_suspended_in_a_named_job_of_its_own(monkeypatch):
    calls = []

    class K32:
        def CreateJobObjectW(self, a, name):
            calls.append(("create", name))
            return 6

        def SetInformationJobObject(self, job, cls, info, size):
            calls.append(("limits", info._obj.BasicLimitInformation.LimitFlags))
            return 1

        def AssignProcessToJobObject(self, job, handle):
            calls.append(("assign", handle))
            return 1

    class Nt:
        def NtResumeProcess(self, handle):
            calls.append(("resume", handle))
            return 0

    class Child:
        pid, _handle = 8101, 55

    made = []
    monkeypatch.setattr(lifecycle.os, "name", "nt")
    monkeypatch.setattr(lifecycle._proc, "started", lambda pid: 3)
    ledger = MemoryLedger(FakeTable([Proc(8101, 1, "x", "c", 3)]))
    job = lifecycle.JobTie(K32(), Nt(), name="Local\\liminal-job-test", kill_on_close=False)
    lifecycle.spawn(["pythonw.exe", "-m", "liminal_charts", "host", "fetcher"], owner="host:fetcher", kind="host",
                    tied=False, popen=lambda a, **k: made.append(k) or Child(), ledger=ledger, job=job)
    assert made[0]["creationflags"] & lifecycle.CREATE_SUSPENDED
    assert calls == [("create", "Local\\liminal-job-test"), ("limits", lifecycle.JOB_BREAKAWAY_OK), ("assign", 55),
                     ("resume", 55)]  # no kill on close: it outlives its starter; resumed only once in the job
    row = ledger.kept[0]
    assert lifecycle.job_of(row.tie) == "Local\\liminal-job-test" and "untied" in row.tie


def test_a_child_that_cannot_be_resumed_is_ended_never_left_suspended(monkeypatch):
    class K32:
        def CreateJobObjectW(self, a, name):
            return 6

        def SetInformationJobObject(self, *a):
            return 1

        def AssignProcessToJobObject(self, job, handle):
            return 1

    class Nt:
        def NtResumeProcess(self, handle):
            return 1  # refused

    class Child:
        pid, _handle, killed = 8102, 56, False

        def kill(self):
            Child.killed = True

    monkeypatch.setattr(lifecycle.os, "name", "nt")
    with pytest.raises(OSError, match="could not be resumed"):
        lifecycle.spawn(["x"], owner="o", kind="k", popen=lambda a, **k: Child(), ledger=MemoryLedger(),
                        job=lifecycle.JobTie(K32(), Nt()))
    assert Child.killed


def test_the_stop_command_ends_a_rows_job_by_its_name():
    table = FakeTable([Proc(8201, 1, "C:/py/pythonw.exe", "pythonw -m liminal_charts host fetcher", 3)])
    ledger = MemoryLedger(table)
    ledger.add(Row(pid=8201, started=3, owner="host:fetcher", owner_pid=1, owner_started=None, kind="host",
                   command=["pythonw"], tie="job:Local\\liminal-job-a; untied: it outlives its starter by design"))
    ended = []

    class Killer:
        def send(self, pid, sig, group=False):
            return table.send(pid, sig, group)

        def end_job(self, name):
            ended.append(name)
            return True

    out = []
    cmd = stop.SignalCommand(node=_NoNode(), http=lambda *a: (0, {}), table=table, killer=Killer(), ledger=ledger,
                             key=b"k" * 32, env={}, venvs=["C:/py"], clock=FakeClock(), sleep=lambda s: None,
                             out=out.append, set_event=lambda name: False)
    cmd.signal(Signal.KILL)
    assert ended == ["Local\\liminal-job-a"] and any(line.startswith("job Local\\liminal-job-a") for line in out)


class _NoNode:
    def reach(self, *a):
        raise ConnectionError("no node")


# -- 8. an app's stop event -----------------------------------------------------------------------------------------------
def test_an_apps_stop_event_is_set_by_the_command_before_anything_is_ended_and_ends_its_serve():
    order = []
    charts = Proc(8301, 1, "C:/py/python.exe", "python -m liminal_charts serve", 2)
    table = FakeTable([charts], ignores={8301})
    real = table.send

    def send(pid, sig, group=False):
        order.append(("send", pid, Signal.of(sig).value))
        return real(pid, sig, group)

    table.send = send

    def set_event(name):
        order.append(("event", name))
        return name.endswith("charts")

    clock = FakeClock()
    cmd = stop.SignalCommand(node=_NoNode(), http=lambda *a: (0, {}), table=table, killer=table,
                             ledger=MemoryLedger(table), key=b"k" * 32, env={}, venvs=["C:/py"], clock=clock,
                             sleep=clock.sleep, out=lambda line: None, set_event=set_event)
    cmd.signal(Signal.TERM, timeout=1)
    events = [o for o in order if o[0] == "event"]
    assert ("event", lifecycle.stop_event_name("charts")) in events
    assert order.index(("event", lifecycle.stop_event_name("charts"))) < order.index(("send", 8301, "TERM"))


def test_serve_ends_when_its_stop_event_is_set():
    class Event:
        looks, closed = 0, False

        def is_set(self):
            Event.looks += 1
            return Event.looks >= 2

        def close(self):
            Event.closed = True

    class Quiet(App):
        NAME, TITLE, ICON = "quiet", "Quiet", "plug"

        def start(self, port=None, open_browser=False):
            return "http://127.0.0.1:0/"  # no server: the wait alone is looked at

        def stop_event(self):
            return Event()

    app = Quiet(log=lambda m: None)
    app.serve()
    assert Event.looks == 2 and Event.closed and app.stopping


def test_a_stop_event_is_made_named_and_set_through_kernel32():
    class K32:
        def __init__(self):
            self.calls, self.set = [], False

        def CreateEventW(self, a, manual, initial, name):
            self.calls.append(("create", manual, initial, name))
            return 9

        def WaitForSingleObject(self, h, ms):
            return 0 if self.set else 258  # WAIT_TIMEOUT

        def OpenEventW(self, access, inherit, name):
            self.calls.append(("open", access, name))
            return 10

        def SetEvent(self, h):
            self.set = True
            return 1

        def CloseHandle(self, h):
            self.calls.append(("close", h))
            return 1

    k32 = K32()
    event = lifecycle.StopEvent(lifecycle.stop_event_name("platform"), k32)
    assert not event.is_set()
    assert lifecycle.set_stop_event(lifecycle.stop_event_name("platform"), k32) and event.is_set()
    event.close()
    assert ("create", 1, 0, lifecycle.stop_event_name("platform")) in k32.calls and ("close", 9) in k32.calls


# -- 9. an app's plugins told together ------------------------------------------------------------------------------------
def test_an_apps_plugins_are_told_together_under_one_deadline():
    met = threading.Barrier(2, timeout=0.5)  # each waits for the other: told one after another, neither would end
    ended = []

    class Meets(FeedPlugin):
        api, assets = "2.0", frozenset({"stock"})

        def build(self, settings, request_budget):
            return None

        def app_stopping(self):
            met.wait()
            ended.append(self.name)

    class One(Meets):
        name, title = "one", "One"

    class Two(Meets):
        name, title = "two", "Two"

    class Plain(App):
        NAME, TITLE, ICON = "plain", "Plain", "plug"
        STOP_GRACE_S = 0.0

    app = Plain(log=lambda m: None, login=EnvironmentLogin(env={}))
    app.attach(One())
    app.attach(Two())
    report = app.terminate(Signal.TERM, 5)
    assert sorted(ended) == ["one", "two"] and [o["how"] for o in report["objects"]] == ["signalled", "signalled"]
    assert app.plugins() == {}
