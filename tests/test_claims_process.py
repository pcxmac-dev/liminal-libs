"""This process's claims on a database by its path (claims.take, release, held, exclusive, feed_runs; 1.56.0), and the
switch-over from lock files: one connection and one heartbeat thread while the process holds something, closed when it
holds nothing; the lock file that kept a key until claims taken beside the claim, for the processes that still look at
lock files alone; on another system's drive no lock file written, and one there without a claim held. Every database
is the test's own; no process is started."""
from __future__ import annotations

import os
import sqlite3

import pytest

from liminal_libs import claims as c
from liminal_libs import proc
from liminal_libs.claims import GRACE_S, STALE_S, Claims


@pytest.fixture(autouse=True)
def nothing_left_held():
    yield
    c._give_back()  # whatever a test left: its connections closed before its folder goes


def _other(path, pid: int = 77) -> Claims:
    """Another installation on the same file (its processes cannot be looked up from here: always alive)."""
    return Claims.open(path, me="other::elsewhere", pid=pid, alive=lambda p, s: True)


def test_a_connection_and_a_heartbeat_only_while_this_process_holds_something(tmp_path):
    path = tmp_path / "liminal.db"
    assert c.held(path) == [] and c.mine(path) == {} and not path.exists()  # asking makes no file
    c.release(path, "feed:massive")  # nothing held: nothing done, nothing opened
    assert not path.exists() and c._process == {}
    feed = c.take(path, "feed:massive", what="a run")
    assert feed is not None and c.holds(path, feed) and set(c.mine(path)) == {"feed:massive"}
    kept = c._process[c._path_key(path)]
    assert kept.keeper._thread is not None and kept.keeper._thread.is_alive()
    symbol = c.take(path, c.symbol_key("stock", "aapl"), shared=True)
    now = c.held(path)
    assert [(h.key, h.shared) for h in now] == [("feed:massive", False), ("symbol:stock:AAPL", True)]
    assert all(h.own and h.mine and h.pid == os.getpid() for h in now) and now[0].what == "a run"
    c.release(path, symbol)
    assert c._process[c._path_key(path)] is kept  # still holding the feed: the same connection and heartbeat
    assert c.take(path, "feed:massive") == feed  # taken again by its holder: the same claim
    c.release(path, feed)
    assert c._process == {} and kept.keeper._thread is None and not c.holds(path, feed)
    with pytest.raises(sqlite3.ProgrammingError):
        kept.claims.conn.execute("SELECT 1")  # closed: nothing stays open on a database nobody works on
    assert c.held(path) == []  # read over a connection of the moment


def test_another_installations_claim_is_seen_and_nothing_stays_open_when_a_take_fails(tmp_path):
    path = tmp_path / "liminal.db"
    other = _other(path)
    try:
        theirs = other.take("feed:tiingo", what="its hourly run")
        assert [(h.key, h.instance, h.mine, h.own) for h in c.held(path)] == [("feed:tiingo", "other::elsewhere", False, False)]
        assert c.held(path, "feed:", elsewhere=True)[0].words() == "other::elsewhere (process 77): its hourly run"
        assert c.take(path, "feed:tiingo") is None and c._process == {}  # not taken: nothing kept open
        mine = c.take(path, "feed:massive")
        assert [h.key for h in c.held(path, elsewhere=True)] == ["feed:tiingo"] and other.take("feed:massive") is None
        other.release(theirs)
        assert c.take(path, "feed:tiingo") is not None and set(c.mine(path)) == {"feed:massive", "feed:tiingo"}
        assert mine is not None
    finally:
        other.close()


def test_when_the_process_ends_everything_it_holds_is_given_back(tmp_path):
    one, two = tmp_path / "one.db", tmp_path / "two.db"
    c.take(one, "feed:massive")
    c.take(one, "history")
    c.take(two, "post")
    assert len(c._process) == 2
    c._give_back()  # what atexit runs
    assert c._process == {} and c.held(one) == [] and c.held(two) == []
    other = _other(one)
    try:
        assert other.take("feed:massive") is not None  # free at once, no heartbeat waited for
    finally:
        other.close()


def test_a_shared_claim_and_one_held_alone_do_not_mix_inside_an_instance(tmp_path):
    path = tmp_path / "liminal.db"
    alive = lambda p, s: True  # noqa: E731
    a, b = (Claims.open(path, me="windows::A", pid=p, started=1, alive=alive) for p in (10, 11))
    try:
        assert a.take("symbol:stock:AAPL", shared=True) is not None and b.take("symbol:stock:AAPL", shared=True) is not None
        assert Claims.holders(a, "symbol:")[0].shared is True
        assert b.take("symbol:stock:MSFT") is not None and a.take("symbol:stock:MSFT", shared=True) is None  # held alone
        a.release("symbol:stock:AAPL")
        assert a.take("symbol:stock:AAPL") is None  # asked alone while another shares it
        b.release("symbol:stock:AAPL")
        assert a.take("symbol:stock:AAPL") is not None and b.take("symbol:stock:AAPL", shared=True) is None
    finally:
        a.close()
        b.close()


def test_a_beat_writes_nothing_when_nothing_is_held_and_forgets_what_was_taken_over(tmp_path):
    path = tmp_path / "liminal.db"
    at = [1_000_000.0]
    mine = Claims.open(path, me="windows::A", pid=10, started=1, clock=lambda: at[0])
    other = Claims.open(path, me="linux::B", pid=20, started=1, clock=lambda: at[0])
    try:
        before = mine.conn.total_changes
        assert mine.beat() == 0 and mine.conn.total_changes == before and not mine.conn.in_transaction
        lost, kept = mine.take("feed:massive"), mine.take("feed:tiingo")
        assert set(mine.held) == {"feed:massive", "feed:tiingo"}
        at[0] += STALE_S
        assert other.take("feed:massive") is None  # challenged
        at[0] += GRACE_S
        assert other.take("feed:massive") is not None  # still silent: taken over
        assert mine.beat() == 1 and set(mine.held) == {"feed:tiingo"}  # it wakes: one is still its own
        assert not mine.holds(lost) and mine.holds(kept)
        mine.release(kept)
        assert mine.held == {} and mine.beat() == 0
    finally:
        mine.close()
        other.close()


def test_a_file_from_before_claims_holds_none_and_gets_its_tables_at_the_first_take(tmp_path):
    path = tmp_path / "older.db"
    with sqlite3.connect(str(path)) as raw:
        raw.execute("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT)")
    raw.close()
    reader = Claims.open(path, create=False)
    try:
        assert reader.tables is False and reader.holders() == [] and reader.release_all() == 0
        assert reader.conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='claims'").fetchone()[0] == 0  # a read made none
    finally:
        reader.close()
    assert c.held(path) == []
    assert c.take(path, "post") is not None and [h.key for h in c.held(path)] == ["post"]


def test_exclusive_takes_the_claim_and_the_lock_file_that_kept_the_key_before(tmp_path):
    path, lock = tmp_path / "liminal.db", tmp_path / "liminal-fetch-massive.lock"
    with c.exclusive(path, "feed:massive", lock, what="its run") as hold:
        assert hold.still() and hold.lock == lock and proc.owns(lock)  # a process from before claims sees the file
        with c.exclusive(path, "feed:massive", lock) as again:  # entered again by the process that holds it
            assert again.claim == hold.claim and again.lock is None
        assert hold.still() and proc.owns(lock)  # the inner one gave nothing back
        runs = c.feed_runs(path)
        assert list(runs) == ["massive"] and runs["massive"].own and runs["massive"].what == "its run"
    assert not lock.exists() and c.held(path) == [] and c.feed_runs(path) == {} and c._process == {}
    # a process from before claims: the lock file and no claim. Not taken, and the claim taken for it is given back
    lock.write_text(f"{os.getppid()} 0")
    with pytest.raises(c.Taken) as e:
        with c.exclusive(path, "feed:massive", lock):
            pytest.fail("held by a process from before claims")
    assert f"process {os.getppid()}" in e.value.holder and str(lock) in e.value.holder and e.value.key == "feed:massive"
    assert c.held(path) == [] and lock.exists() and c._process == {}
    runs = c.feed_runs(path)
    assert runs["massive"].pid == os.getppid() and runs["massive"].mine and not runs["massive"].own
    assert runs["massive"].what == "lock file"
    lock.unlink()
    # another installation holds the claim: said in its words, and no lock file is left behind
    other = _other(path)
    try:
        other.take("feed:massive", what="its hourly run")
        with pytest.raises(c.Taken) as e:
            with c.exclusive(path, "feed:massive", lock):
                pytest.fail("held by another installation")
        assert e.value.holder == "other::elsewhere (process 77): its hourly run" and "feed:massive is held by" in str(e.value)
        assert not lock.exists() and c.feed_runs(path)["massive"].instance == "other::elsewhere"
    finally:
        other.close()
    # the whole database's lock stays a file: seen beside the claims
    (tmp_path / "liminal.lock").write_text(f"{os.getppid()} 0")
    assert None in c.feed_runs(path) and c.feed_runs(path)[None].pid == os.getppid()
    with c.exclusive(path, "history") as alone:  # a key that never had a lock file: the claim alone
        assert alone.still() and alone.lock is None
    with c.exclusive(path, "post") as h:  # a body that fails gives everything back
        with pytest.raises(RuntimeError):
            with c.exclusive(path, "publications", tmp_path / "publications.lock"):
                raise RuntimeError("the pass failed")
        assert h.still() and not (tmp_path / "publications.lock").exists() and set(c.mine(path)) == {"post"}


def test_on_another_systems_drive_no_lock_file_is_written_and_one_without_a_claim_is_held(tmp_path, monkeypatch):
    path, lock = tmp_path / "liminal.db", tmp_path / "liminal-fetch-massive.lock"
    Claims.open(path).close()  # the database as its own system made it (none is made from another: test_owners_layout)
    monkeypatch.setenv("LIMINAL_LINK", "loopback")  # its databases through a link, as from there
    monkeypatch.setattr(c.mounts, "foreign", lambda p, mounts=None: True)  # Windows' drive, seen from Linux
    with c.exclusive(path, "feed:massive", lock) as hold:
        # the claim alone: a lock file written here would name a process the files' own system cannot look up
        assert hold.still() and hold.lock is None and not lock.exists()
    lock.write_text("4321 99")  # one its own system wrote, and no claim: a process from before claims may be behind it
    with pytest.raises(c.Taken) as e:
        with c.exclusive(path, "feed:massive", lock):
            pytest.fail("a lock file that cannot be judged")
    assert "only that system can judge" in e.value.holder and lock.exists() and c.held(path) == [] and c._process == {}
    runs = c.feed_runs(path)
    assert runs["massive"].instance == "another system" and not runs["massive"].mine and not runs["massive"].own
    (tmp_path / "liminal.lock").write_text("1 1")
    assert None in c.feed_runs(path)  # the whole database's lock likewise: its data may be moving
    other = _other(path)
    try:  # with a claim, the claim says who: the lock file beside it is its holder's own
        other.take("feed:massive", what="its hourly run")
        assert c.feed_runs(path)["massive"].words() == "other::elsewhere (process 77): its hourly run"
    finally:
        other.close()
