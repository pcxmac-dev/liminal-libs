"""Claims (claims.py, 1.56.0; the user, 2026-11-15: "If i run integrator on both sides, there cannot be any conflicts,
so if one symbol is being operated on, the other integrator would have to operate on another symbol"): two
installations on one database never hold one key at once; inside one installation a symbol is shared and a feed's run
is one process's; a crashed process of this installation gives way at once; another installation's is challenged
first and taken over only when still silent; a token tells a holder it was taken over. Two instances are two Claims
objects on one file with a clock of the test's own: no process is started and nothing sleeps."""
from __future__ import annotations

import sqlite3
import threading
import time

import pytest

from liminal_libs import claims as c
from liminal_libs.claims import BEAT_S, GRACE_S, STALE_S, Claims, Keeper


class Clock:
    def __init__(self, at: float = 1_000_000.0):
        self.at = at

    def __call__(self) -> float:
        return self.at

    def pass_(self, seconds: float) -> None:
        self.at += seconds


@pytest.fixture
def two(tmp_path):
    """Windows' side and Linux's on one database, and the clock both read."""
    clock = Clock()
    alive = {(10, 1): True, (11, 1): True, (20, 1): True}
    path = tmp_path / "liminal.db"
    make = lambda me, pid: Claims(sqlite3.connect(str(path), timeout=5), me=me, pid=pid, started=1,  # noqa: E731
                                  alive=lambda p, s: alive.get((p, s), False), clock=clock)
    w, w2, x = make("windows::NEPTUNE", 10), make("windows::NEPTUNE", 11), make("linux::Ubuntu", 20)
    yield w, w2, x, clock, alive
    for each in (w, w2, x):
        each.close()


def test_a_key_is_one_instances_at_a_time(two):
    w, _, x, clock, _ = two
    mine = w.take("feed:massive", what="its hourly run")
    assert mine is not None and mine.key == "feed:massive" and mine.instance == "windows::NEPTUNE" and mine.pid == 10
    assert x.take("feed:massive") is None and x.take("feed:tiingo") is not None  # another feed is free
    held = x.holder("feed:massive")
    assert held is not None and held.instance == "windows::NEPTUNE" and not held.mine
    assert held.words() == "windows::NEPTUNE (process 10): its hourly run"
    w.release(mine)
    theirs = x.take("feed:massive")
    assert theirs is not None and theirs.token == mine.token + 1 and w.take("feed:massive") is None


def test_a_symbol_is_shared_inside_an_instance_and_a_feeds_run_is_not(two):
    w, w2, x, _, _ = two
    a, b = w.take(c.symbol_key("stock", "aapl"), shared=True), w2.take(c.symbol_key("stock", "AAPL"), shared=True)
    assert a is not None and b is not None and a.key == b.key == "symbol:stock:AAPL"
    assert x.take("symbol:stock:AAPL", shared=True) is None  # the other integrator takes another symbol
    assert x.take("symbol:stock:MSFT", shared=True) is not None and w.take("symbol:stock:MSFT", shared=True) is None
    w.release(a)
    assert x.take("symbol:stock:AAPL", shared=True) is None  # the instance's other process still works on it
    w2.release(b)
    assert x.take("symbol:stock:AAPL", shared=True) is not None
    assert w.take("feed:massive") is not None and w2.take("feed:massive") is None  # a run: one process, here too
    assert [h.pid for h in w2.holders("feed:")] == [10]


def test_a_claim_taken_again_by_its_holder_is_the_same_claim(two):
    w, _, _, clock, _ = two
    first = w.take("history")
    clock.pass_(30)
    again = w.take("history")
    assert again == first and w.holds(first)
    w.release("history")
    assert not w.holds(first) and w.take("history").token == first.token + 1


def test_a_process_of_this_instance_that_is_gone_gives_way_at_once(two):
    w, w2, _, _, alive = two
    old = w2.take("feed:massive")
    assert old is not None and w.take("feed:massive") is None
    alive[(11, 1)] = False  # it crashed: its own system sees that, as a lock file's holder was seen
    new = w.take("feed:massive")
    assert new is not None and new.pid == 10 and new.token == old.token + 1 and not w2.holds(old)
    assert [h.pid for h in w.holders("feed:massive")] == [10]


def test_another_instance_is_challenged_first_and_taken_over_only_if_still_silent(two):
    w, _, x, clock, _ = two
    held = w.take("feed:massive")
    clock.pass_(STALE_S - 1)
    assert x.take("feed:massive") is None and x.holder("feed:massive") is not None  # heard from lately
    clock.pass_(2)  # silent for STALE_S now: challenged, not taken
    assert x.take("feed:massive") is None and w.holds(held)
    clock.pass_(GRACE_S - 1)
    assert x.take("feed:massive") is None  # its time to answer is not over
    assert w.beat() == 1  # it wakes (a computer asleep) and answers
    clock.pass_(5)
    assert x.take("feed:massive") is None and w.holds(held)  # the challenge is answered: nothing is taken
    clock.pass_(STALE_S)  # silent again, for good this time
    assert x.take("feed:massive") is None  # challenged again
    clock.pass_(GRACE_S)
    taken = x.take("feed:massive")
    assert taken is not None and taken.instance == "linux::Ubuntu" and taken.token == held.token + 1
    assert not w.holds(held) and w.take("feed:massive") is None  # the old holder finds out before it writes on


def test_both_sides_waking_from_sleep_take_nothing_from_each_other(two):
    """The computer asleep for an hour: every heartbeat is an hour old on both sides. Whichever looks first only
    challenges; both beat within a heartbeat's time; nobody is taken over."""
    w, _, x, clock, _ = two
    a, b = w.take("feed:massive"), x.take("feed:tiingo")
    clock.pass_(3600)
    assert x.take("feed:massive") is None and w.take("feed:tiingo") is None
    clock.pass_(BEAT_S)
    assert w.beat() == 1 and x.beat() == 1
    clock.pass_(GRACE_S)
    assert x.take("feed:massive") is None and w.take("feed:tiingo") is None and w.holds(a) and x.holds(b)


def test_holders_lists_what_is_held_and_release_all_gives_everything_back(two):
    w, w2, x, clock, alive = two
    w.take("feed:massive")
    w.take("symbol:stock:AAPL", shared=True)
    w2.take("symbol:stock:AAPL", shared=True)
    x.take("feed:tiingo")
    assert [(h.key, h.pid, h.mine) for h in w.holders()] == [("feed:massive", 10, True), ("feed:tiingo", 20, False),
                                                              ("symbol:stock:AAPL", 10, True), ("symbol:stock:AAPL", 11, True)]
    assert [h.key for h in w.holders("feed:")] == ["feed:massive", "feed:tiingo"]
    assert [h.key for h in w.holders("feed:", elsewhere=True)] == ["feed:tiingo"]
    alive[(11, 1)] = False
    assert [h.pid for h in x.holders("symbol:")] == [10, 11]  # another instance cannot look a process up: by heartbeat
    assert [h.pid for h in w.holders("symbol:")] == [10]  # its own system sees it gone
    clock.pass_(40)
    assert x.holder("feed:massive").quiet == 40
    assert w.release_all() == 2 and [h.key for h in x.holders()] == ["feed:tiingo", "symbol:stock:AAPL"]


def test_the_instance_is_named_by_its_system_or_as_it_is_told():
    assert c.os_name("win32") == "windows" and c.os_name("linux") == "linux" and c.os_name("darwin") == "macos"
    assert c.instance({"LIMINAL_INSTANCE": " linux::Ubuntu "}) == "linux::Ubuntu"
    assert c.instance({"WSL_DISTRO_NAME": "Ubuntu"}) == f"{c.os_name()}::Ubuntu"
    assert c.instance({}).startswith(f"{c.os_name()}::") and len(c.instance({})) > len(c.os_name()) + 2
    assert c.feed_key("massive") == "feed:massive" and c.symbol_key("crypto", "x:btcusd") == "symbol:crypto:X:BTCUSD"


def test_the_clock_is_the_databases_and_an_older_file_gets_the_tables(tmp_path):
    path = tmp_path / "older.db"
    with sqlite3.connect(str(path)) as raw:
        raw.execute("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT)")  # a main file from before claims
    mine = Claims.open(path, me="windows::A")
    try:
        assert abs(mine.now() - time.time()) < 5  # read in SQL: every instance on the file reads the same clock
        got = mine.take("post")
        assert got is not None and mine.holds(got) and mine.holder("post").quiet < 5
        tables = {r[0] for r in mine.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"claims", "claim_tokens", "kv"} <= tables
    finally:
        mine.close()


def test_a_keeper_beats_until_stopped_and_gives_back_what_was_held(tmp_path):
    path = tmp_path / "liminal.db"
    mine, other = Claims.open(path, me="windows::A"), Claims.open(path, me="linux::B", pid=99, alive=lambda p, s: True)
    try:
        got = mine.take("feed:massive")
        first = mine.conn.execute("SELECT beat_at FROM claims").fetchone()[0]
        beats = threading.Event()
        beat = mine.beat
        mine.beat = lambda: (beat(), beats.set())[0]
        keeper = Keeper(mine, every=0.05).start()
        assert beats.wait(10)
        assert mine.conn.execute("SELECT beat_at FROM claims").fetchone()[0] >= first and other.take("feed:massive") is None
        keeper.stop()
        assert not mine.holds(got) and other.take("feed:massive") is not None  # stopped: given back
    finally:
        mine.close()
        other.close()
