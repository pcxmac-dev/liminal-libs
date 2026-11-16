"""The places that were lock files, held against every installation on the database (1.56.0): the publications'
reader, the live recorder, a series' build of derived frames; and the work that is the files' own system's (the closed
months' copy, MongoDB's start, the documents' move), refused from another. The other installation is a second Claims
object on the same file; "another system's drive" is mounts.foreign standing in; no process is started."""
from __future__ import annotations

import os
import time
from types import SimpleNamespace

import pytest

from liminal_libs import claims, derive, live, mongo, mounts, publications, stores
from liminal_libs.claims import GRACE_S, STALE_S, Claims
from liminal_libs.storage import Store

DEAD = 999_999_999


@pytest.fixture(autouse=True)
def nothing_left_held():
    yield
    claims._give_back()


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("LIMINAL_LIVE_LOCK", str(tmp_path / "machine" / "live.lock"))
    path = tmp_path / "data" / "liminal.db"
    Store(path).close()
    return path


def _other(path, pid: int = 77, **kw) -> Claims:
    return Claims.open(path, me="other::elsewhere", pid=pid, alive=lambda p, s: True, **kw)


def _foreign(monkeypatch) -> None:
    monkeypatch.setenv("LIMINAL_LINK", "loopback")  # its databases through a link, as from there
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: True)


def test_a_hold_is_taken_and_given_back_in_two_places(db):
    lock = db.with_name("post.lock")
    held = claims.hold(db, claims.POST, lock, what="composites and derived frames")
    assert held.still() and held.lock == lock and lock.exists() and not held.again
    again = claims.try_hold(db, claims.POST, lock)
    assert again is not None and again.again and again.claim == held.claim and again.lock is None
    claims.let_go(again)  # taken again by its holder: giving that back gives nothing back
    assert held.still() and lock.exists()
    claims.let_go(held)
    claims.let_go(None)
    assert not lock.exists() and claims.held(db) == []
    other = _other(db)
    try:
        other.take(claims.POST)
        assert claims.try_hold(db, claims.POST, lock) is None and not lock.exists()
        with pytest.raises(claims.Taken):
            claims.hold(db, claims.POST, lock)
    finally:
        other.close()


def test_the_publications_reader_is_one_on_a_database_on_every_system(db):
    held = publications.take_reader(db)
    assert held is not None and held.claim.key == "publications" and publications.lock_path(db).exists()
    claims.let_go(held)
    assert not publications.lock_path(db).exists()
    other = _other(db)
    try:
        theirs = other.take("publications", what="the publications' reader")
        assert publications.take_reader(db) is None and not publications.lock_path(db).exists()
        other.release(theirs)
        again = publications.take_reader(db)
        assert again is not None
        claims.let_go(again)
    finally:
        other.close()
    publications.lock_path(db).write_text(f"{os.getppid()} 0")  # a reader from before claims
    assert publications.take_reader(db) is None and claims.held(db) == []


def test_the_live_recorder_is_one_on_a_database_on_every_system(db, tmp_path):
    locks = live.take_locks(db)
    assert locks == [live.lock_path(db), live.machine_lock()] and all(p.exists() for p in locks)
    assert locks.hold.claim.key == "live" and live.running(db)
    recorder = SimpleNamespace(locks=locks)
    assert live.Recorder.holds_locks(recorder)
    assert live.take_locks(db) is None  # one recorder: a second gets nothing, and takes nothing from the first
    assert live.Recorder.holds_locks(recorder) and all(p.exists() for p in locks)
    ahead = [0.0]
    other = _other(db, clock=lambda: time.time() + ahead[0])
    try:
        assert other.take("live") is None  # the other installation's recorder stays out
        ahead[0] = STALE_S + 1  # this computer slept: found silent, asked, then taken over
        assert other.take("live") is None
        ahead[0] += GRACE_S + 1
        assert other.take("live") is not None
        assert not live.Recorder.holds_locks(recorder)  # it finds out at its next check, and stops
    finally:
        other.close()
    live.release_locks(locks)
    assert not live.lock_path(db).exists() and not live.machine_lock().exists()
    # held by the other installation: nothing is taken, the machine's lock no more than the database's
    other = _other(db)
    try:
        other.take("live", what="the live recorder")
        assert live.take_locks(db) is None and not live.machine_lock().exists() and not live.lock_path(db).exists()
        assert live.running(db)  # for this database, though no lock file here says so
    finally:
        other.close()
    assert live.Recorder.holds_locks(SimpleNamespace(locks=[]))  # a recorder given no locks (a test's) checks none


def test_on_another_systems_drive_the_recorder_writes_no_lock_file_beside_the_database(db, monkeypatch):
    real = mounts.foreign
    monkeypatch.setenv("LIMINAL_LINK", "loopback")  # its databases through a link, as from there
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: "machine" not in str(p) or real(p))
    locks = live.take_locks(db)  # the database is Windows', the machine's lock this system's own
    assert locks == [live.machine_lock()] and not live.lock_path(db).exists() and locks.hold.still()
    live.release_locks(locks)
    assert not live.machine_lock().exists() and claims.held(db) == []
    live.lock_path(db).write_text("4321 99")  # a recorder from before claims on the files' own system, perhaps
    assert live.take_locks(db) is None and not live.machine_lock().exists()


def test_a_series_build_is_leased_against_every_installation(db):
    with Store(db) as store:
        now_ms = 1_800_000_000_000
        assert derive.take_lease(store, "massive", "AAPL", now_ms)  # this process's
        lease = store.kv_update(derive.LEASE_KEY.format("massive", "AAPL"), lambda held: held, {})
        assert lease["pid"] == os.getpid() and lease["instance"] == claims.instance()
        assert derive.take_lease(store, "massive", "AAPL", now_ms)  # its own again
        # the other installation is building it: its process cannot be looked up, its claim says it is at work
        theirs = {"pid": 77, "instance": "other::elsewhere", "start": 1, "until": now_ms + derive.LEASE_MS}
        store.kv_update(derive.LEASE_KEY.format("massive", "AAPL"), lambda held: dict(theirs), {})
        other = _other(db)
        try:
            other.take("symbol:stock:AAPL", shared=True)
            assert not derive.take_lease(store, "massive", "AAPL", now_ms)
            derive.drop_lease(store, "massive", "AAPL")  # not this process's to drop
            assert store.kv_update(derive.LEASE_KEY.format("massive", "AAPL"), lambda held: held, {})["pid"] == 77
            other.release("symbol:stock:AAPL")  # it holds nothing any more: its build is gone
            assert derive.take_lease(store, "massive", "AAPL", now_ms)
        finally:
            other.close()
        # a lease with this process's id from another installation is not this process's
        same = {"pid": os.getpid(), "instance": "other::elsewhere", "start": 1, "until": now_ms + derive.LEASE_MS}
        store.kv_update(derive.LEASE_KEY.format("massive", "MSFT"), lambda held: dict(same), {})
        derive.drop_lease(store, "massive", "MSFT")
        assert store.kv_update(derive.LEASE_KEY.format("massive", "MSFT"), lambda held: held, {}) == same
        # a lease from before leases named their installation: a process here that is gone gives way
        old = {"pid": DEAD, "start": 0, "until": now_ms + derive.LEASE_MS}
        store.kv_update(derive.LEASE_KEY.format("massive", "NVDA"), lambda held: dict(old), {})
        assert derive.take_lease(store, "massive", "NVDA", now_ms)
        with derive.Lease(store, "massive", "TSLA", now_ms) as taken:
            assert taken


def test_the_files_own_systems_work_is_refused_from_another(db, tmp_path, monkeypatch):
    settings = SimpleNamespace(db_path=db)
    monkeypatch.setattr(stores, "bars_feeds", lambda store: ["massive"])
    assert stores.history_due(settings) is True
    other = _other(db)
    try:
        theirs = other.take("history", what="the closed months' copy")
        assert stores.history_due(settings) is False  # a copy is going, on whichever system
        other.release(theirs)
    finally:
        other.close()
    mounts.owner_only(db, "a backup")  # this system's own files: nothing said
    monkeypatch.setattr(mongo, "running", lambda: False)
    monkeypatch.setattr(mongo, "startable", lambda: None)
    _foreign(monkeypatch)
    assert stores.history_due(settings) is False  # the copy is the files' own system's
    with Store(db) as store:
        assert stores.settle(store, None, db.parent) == []  # so is moving the documents between engines
    with pytest.raises(mounts.NotHere, match="another system's drive"):
        mongo.start(db.parent)  # and starting their server
    assert not (db.parent / "mongo-start.lock").exists()
    with pytest.raises(mounts.NotHere, match="a backup"):
        mounts.owner_only(db, "a backup")
    assert isinstance(mounts.NotHere("x"), RuntimeError)


def test_a_page_does_not_show_a_job_the_other_installation_is_fetching_as_stopped(db):
    with Store(db) as store:
        for key in ("AAPL", "MSFT", "NVDA", "TSLA"):
            store.queue_start("massive", "massive", "bars", key)
        with store.conn:
            store.conn.execute("UPDATE fetch_queue SET pid=77, instance='other::elsewhere' WHERE key='MSFT'")
            store.conn.execute("UPDATE fetch_queue SET pid=78, instance='other::elsewhere' WHERE key='NVDA'")
            store.conn.execute("UPDATE fetch_queue SET pid=? WHERE key='TSLA'", (DEAD,))
        other = _other(db)
        try:
            other.take("feed:massive")
            rows = store.queue_rows("massive")
            assert all("instance" in r for r in rows)
            # this process's own job is running; so is the other installation's whose process holds a claim
            assert store.queue_gone(rows) == {("other::elsewhere", 78), (claims.instance(), DEAD)}
        finally:
            other.close()
