"""What a process that is gone left running is taken back; what another is still working on is left to it (1.56.0).

Until then a fetcher starting reset every request being collected, and a plugin's pass starting reset every job of that
plugin being fetched, whoever was at them: with a second integrator on the database (the user, 2026-11-15: "If i run
integrator on both sides, there cannot be any conflicts") each would have taken the other's work. Rows now name the
installation that took them, and claims.gone() judges: a process of this installation is looked up, one of another
installation is at work while it holds a claim heard from lately. Every database is the test's own; no process is
started."""
from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timezone

import pytest

from liminal_libs import claims as c
from liminal_libs import runner
from liminal_libs.claims import STALE_S, Claims
from liminal_libs.storage import Store
from liminal_libs.storage import common

pytestmark = pytest.mark.usefixtures("stand_in_environment")  # its code reads this process's environment

DEAD = 999_999_999  # no such process
NOW = datetime(2026, 11, 15, 20, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def nothing_left_held():
    yield
    c._give_back()
    common.set_read_only(False)


def _other(path, pid: int = 77) -> Claims:
    return Claims.open(path, me="other::elsewhere", pid=pid, alive=lambda p, s: True)


def test_who_is_gone(tmp_path):
    at = [1_000_000.0]
    other = Claims.open(tmp_path / "liminal.db", me="linux::Ubuntu", pid=20, started=1, clock=lambda: at[0])
    try:
        other.take("feed:massive")
        alive = {10: True, 11: False}.get
        owners = [("windows::A", 10), ("windows::A", 11), ("windows::A", os.getpid()), (None, 10), (None, 11), (None, None),
                  ("linux::Ubuntu", 20), ("linux::Ubuntu", 21), ("linux::Ubuntu", None)]
        ask = lambda **kw: c.gone(other.conn, owners, me="windows::A", alive=lambda p: bool(alive(p)), now=at[0], **kw)  # noqa: E731
        assert ask() == {("windows::A", 11),  # a process of this installation that is no more
                         ("windows::A", os.getpid()),  # this process: what an earlier pass of its own left
                         (None, 11), (None, None), ("linux::Ubuntu", None),  # nobody named, or a dead one from before rows named theirs
                         ("linux::Ubuntu", 21)}  # the other installation's, holding no claim
        there = ask(own_files=False)  # on another system's drive an unnamed process is that system's to judge
        assert (None, 10) not in there and (None, 11) not in there and (None, None) in there and ("windows::A", 11) in there
        at[0] += STALE_S  # the other installation silent that long: what it left is left behind
        assert ("linux::Ubuntu", 20) in ask()
        raw = sqlite3.connect(":memory:")  # a file from before claims: nobody holds any
        assert c.gone(raw, [("linux::Ubuntu", 20), ("windows::A", 10)], me="windows::A", alive=lambda p: True) == {("linux::Ubuntu", 20)}
        raw.close()
    finally:
        other.close()


def test_a_process_at_work_says_so_and_is_seen_by_its_own_clock(tmp_path):
    path = tmp_path / "liminal.db"
    here = c.present(path, what="the fetcher")
    assert here is not None and here.key == f"process:{c.instance()}:{os.getpid()}"
    reader = sqlite3.connect(str(path))
    try:
        assert c.gone(reader, [(c.instance(), os.getpid())], me="other::elsewhere") == set()  # another installation sees it at work
        c.release(path, here)
        assert c.gone(reader, [(c.instance(), os.getpid())], me="other::elsewhere") == {(c.instance(), os.getpid())}
    finally:
        reader.close()


def test_a_fetcher_starting_takes_back_only_what_a_fetcher_that_is_gone_left(tmp_path):
    path = tmp_path / "liminal.db"
    other = None
    with Store(path) as store:
        ids = [store.request_put(s)["id"] for s in ("AAPL", "MSFT", "NVDA", "TSLA", "AMZN", "META")]
        taken = [store.request_next(NOW) for _ in ids]
        assert all(r is not None and r["pid"] == os.getpid() for r in taken) and store.request_next(NOW) is None
        me = store.conn.execute("SELECT DISTINCT instance FROM fetch_requests").fetchall()
        assert me == [(c.instance(),)]  # a request taken names its installation
        who = {ids[0]: (c.instance(), os.getpid()),  # this process, in an earlier pass
               ids[1]: (c.instance(), DEAD),  # a fetcher here that is no more
               ids[2]: (c.instance(), os.getppid()),  # another fetcher here, alive
               ids[3]: ("other::elsewhere", 77),  # the other installation's fetcher, at work
               ids[4]: ("other::elsewhere", 78),  # one of its that is gone
               ids[5]: (None, DEAD)}  # taken before requests named their installation, by a process that is no more
        with store.conn:
            for i, (inst, pid) in who.items():
                store.conn.execute("UPDATE fetch_requests SET instance=?, pid=?, state='collecting' WHERE id=?", (inst, pid, i))
        other = _other(path)
        other.take("process:other::elsewhere:77", what="the fetcher")
        assert store.request_reset() == 4
        states = {r["id"]: (r["state"], r["pid"]) for r in store.request_rows()}
        assert states == {ids[0]: ("waiting", None), ids[1]: ("waiting", None), ids[2]: ("collecting", os.getppid()),
                          ids[3]: ("collecting", 77), ids[4]: ("waiting", None), ids[5]: ("waiting", None)}
        assert store.request_get(ids[1])["detail"] == "the fetcher ended before it"
        other.release("process:other::elsewhere:77")  # its fetcher ends: what it was collecting is taken back
        assert store.request_reset() == 1 and store.request_get(ids[3])["state"] == "waiting"
    if other is not None:
        other.close()


def test_a_pass_starting_takes_back_only_the_jobs_a_run_that_is_gone_left(tmp_path):
    path = tmp_path / "liminal.db"
    with Store(path) as store, pytest.MonkeyPatch.context() as mp:
        other = _other(path)
        try:
            other.take("feed:massive", what="the massive feed's run")
            for key in ("AAPL", "MSFT", "NVDA", "TSLA"):
                store.queue_start("massive", "massive", "bars", key, now=NOW)
            store.queue_start("massive", "headlines", "news", "feed", now=NOW)
            row = store.conn.execute("SELECT pid, instance FROM fetch_queue WHERE key='AAPL'").fetchone()
            assert tuple(row) == (os.getpid(), c.instance())  # a job being fetched names its process and its installation
            with store.conn:
                store.conn.execute("UPDATE fetch_queue SET pid=?, instance=? WHERE key='MSFT'", (77, "other::elsewhere"))
                store.conn.execute("UPDATE fetch_queue SET pid=?, instance=? WHERE key='NVDA'", (os.getppid(), c.instance()))
                store.conn.execute("UPDATE fetch_queue SET pid=? WHERE key='TSLA'", (DEAD,))
            # a pass of the plugin's own fetching starts: the feed's run on the other installation, and another
            # process's here, go on fetching what they were fetching
            assert store.queue_reset("massive") == 3
            states = {r["key"]: r["state"] for r in store.queue_rows("massive")}
            assert states == {"AAPL": "waiting", "MSFT": "running", "NVDA": "running", "TSLA": "waiting", "feed": "waiting"}
            assert store.queue_reset("massive", "massive", "bars") == 0
            # a feed's own run starts (it holds the feed's claim): every row of its bars was left behind
            assert store.queue_reset("massive", "massive", "bars", mine_alone=True) == 2
            assert {r["state"] for r in store.queue_rows("massive")} == {"waiting"}
            row = store.queue_claim("massive", now=NOW)
            assert row is not None and store.conn.execute(
                "SELECT instance FROM fetch_queue WHERE state='running'").fetchone()[0] == c.instance()
            # a job taken before rows named their installation, on another system's drive: only that system can tell
            mp.setattr("liminal_libs.storage.queue.own_files", lambda path: False)
            with store.conn:
                store.conn.execute("UPDATE fetch_queue SET state='waiting', pid=NULL, instance=NULL")
                store.conn.execute("UPDATE fetch_queue SET state='running', pid=? WHERE key='TSLA'", (DEAD,))
            assert store.queue_reset("massive") == 0
            mp.undo()
            assert store.queue_reset("massive") == 1  # on this system's own disk it is looked up, and is gone
        finally:
            other.close()


def test_two_asks_at_once_make_one_open_request(tmp_path):
    path = tmp_path / "liminal.db"
    Store(path).close()
    for round_ in range(12):
        symbol = f"SYM{round_}"
        together = threading.Barrier(2)
        errors: list[BaseException] = []

        def ask() -> None:
            try:
                with Store(path) as store:
                    together.wait(timeout=10)
                    store.request_put(symbol, by="chart")
            except BaseException as e:  # noqa: BLE001 - said by the test
                errors.append(e)

        threads = [threading.Thread(target=ask) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert errors == []
        with Store(path) as store:
            assert len([r for r in store.requests_open() if r["symbol"] == symbol]) == 1


def test_a_process_that_reads_only_takes_no_claim(tmp_path):
    path = tmp_path / "liminal.db"
    Store(path).close()
    common.set_read_only(True)
    assert c.take(path, "feed:massive") is None and c.present(path) is None and c._process == {}
    with pytest.raises(c.Taken) as e:
        with c.exclusive(path, "feed:massive", tmp_path / "liminal-fetch-massive.lock"):
            pytest.fail("a process that reads only fetches nothing")
    assert "reads only" in e.value.holder and not (tmp_path / "liminal-fetch-massive.lock").exists()
    assert c.held(path) == []  # it may look: nothing was written
    common.set_read_only(False)
    assert c.take(path, "feed:massive") is not None


class _Quiet:
    """A plugin's own fetcher with nothing to do."""

    def plan(self, ctx):
        return []

    def fetch(self, ctx, job):  # pragma: no cover - it plans nothing
        raise AssertionError("nothing was planned")


def test_a_plugins_own_fetching_is_one_pass_at_a_time_on_every_system(tmp_path):
    path = tmp_path / "liminal.db"
    with Store(path) as store:
        r = runner.Runner(lambda: store, None, lambda m: None)
        parts = [("docs", _Quiet())]
        assert r.plugin("acme", parts, store, clock=lambda: NOW) == {"done": 0, "failed": 0, "held": 0, "stopped": None}
        assert c.held(path) == [] and c._process == {}  # its claim given back with the pass
        other = _other(path)
        try:
            other.take("plugin:acme", what="acme's own fetching")
            out = r.plugin("acme", parts, store, clock=lambda: NOW)
            assert out["stopped"] == "its fetching is going on already: other::elsewhere (process 77): acme's own fetching"
            assert r.plugin("zenith", parts, store, clock=lambda: NOW)["stopped"] is None  # another plugin goes on
        finally:
            other.close()
    with Store(":memory:") as memory:  # a store in memory is nobody else's: no claim asked for
        assert runner.Runner(lambda: memory, None, lambda m: None).plugin("acme", [("docs", _Quiet())], memory,
                                                                         clock=lambda: NOW)["stopped"] is None
