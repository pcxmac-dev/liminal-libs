"""A file on another system's drive keeps the layout its own system gave it (1.57.0).

The suite runs a second time inside WSL on Windows' databases. A store brings a file's tables up to its own
software when it opens it, a process that reads only (LIMINAL_READONLY) included: it made the tables first and was
sealed after. From the other system that would add a column under the software running on the system that holds the
file (an older one there writes its rows by position: one more column and its writes fail), and before the user said
the file may change at all. So from another system nothing of a file's layout is changed: an up-to-date file opens
untouched, one that is behind is said to be, and no file is made there.

"Another system's drive" is mounts.foreign standing in and the link a helper in the test's own process
(LIMINAL_LINK=loopback); no process is started."""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing

import pytest

from liminal_libs import claims, gov, mounts
from liminal_libs.storage import Store, common
from liminal_libs.storage import link as lk
from liminal_libs.storage.common import Behind

pytestmark = pytest.mark.usefixtures("stand_in_environment")  # its code reads this process's environment

BAR = {"t": 60_000, "o": 1.0, "h": 2.0, "l": 0.5, "c": 1.5, "v": 10}


@pytest.fixture(autouse=True)
def nothing_left_held():
    yield
    claims._give_back()


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A database as its own system left it: the main file, one feed with a bar, a dataset file, the agencies' file."""
    monkeypatch.setenv("LIMINAL_LIVE_LOCK", str(tmp_path / "machine" / "live.lock"))
    monkeypatch.delenv(lk.FORCE_VAR, raising=False)
    path = tmp_path / "data" / "liminal.db"
    with Store(path) as s:
        s.watch("massive", ["AAPL"], "minute")
        s.upsert_bars("massive", "AAPL", "minute", 1, [BAR])
        s._dataset_db("french", create=True)
    gov.open_db(path).conn.close()
    return path


@pytest.fixture
def elsewhere(monkeypatch):
    """From here on the test's files are another system's, reached through a helper in this process."""
    monkeypatch.setenv(lk.FORCE_VAR, "loopback")
    monkeypatch.setattr(lk, "_links", {})
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: True)
    yield
    for link in list(lk._links.values()):
        link.close()


def _reads_only(monkeypatch) -> None:
    monkeypatch.setattr(common, "_READ_ONLY", [True])


def _own(monkeypatch) -> None:
    """For a while the files are this system's own again: what their own system does to them."""
    monkeypatch.delenv(lk.FORCE_VAR, raising=False)
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: False)


def _away(monkeypatch) -> None:
    monkeypatch.setenv(lk.FORCE_VAR, "loopback")
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: True)


def _files(path) -> dict[str, str]:
    """Every database file under the data folder, by what it holds. Nothing waits in a log beside one: all of it is
    in the file (a connection that could only read leaves SQLite's empty log file behind; it holds nothing)."""
    out = {}
    for f in sorted(path.parent.rglob("*.db")):
        out[f.relative_to(path.parent).as_posix()] = hashlib.sha256(f.read_bytes()).hexdigest()
    assert [f.name for f in path.parent.rglob("*.db-wal") if f.stat().st_size] == [], "writes wait in a log"
    return out


def _older(path) -> None:
    """The main file as software from before claims left it: no claims tables, no `instance` columns."""
    with closing(sqlite3.connect(path)) as raw:
        raw.executescript("DROP TABLE claims; DROP TABLE claim_tokens; ALTER TABLE fetch_requests DROP COLUMN instance; "
                          "ALTER TABLE fetch_queue DROP COLUMN instance;")


def test_an_up_to_date_file_opens_from_another_system_and_is_not_touched(db, elsewhere, monkeypatch):
    before = _files(db)
    assert set(before) == {"liminal.db", "feeds/massive.db", "datasets/french.db", "gov/gov.db"}
    with Store(db) as s:  # a process that writes: its layout part ran query-only, then it may write rows
        assert isinstance(s.conn, lk.Connection) and s.conn.execute("PRAGMA query_only").fetchone() == (0,)
        assert s.count_bars("massive", "AAPL", "minute") == 1 and s._dataset_db("french") is not None
        assert s._bars("massive").execute("PRAGMA query_only").fetchone() == (0,)
    g = gov.open_db(db)
    assert g.conn.execute("PRAGMA query_only").fetchone() == (0,)
    g.conn.close()
    assert _files(db) == before  # opened, read, closed: every file is what its own system left
    with Store(db) as s:
        s.upsert_bars("massive", "AAPL", "minute", 1, [{**BAR, "t": 120_000}])  # rows are another matter: written
        assert s.count_bars("massive", "AAPL", "minute") == 2
    after = _files(db)
    assert after["liminal.db"] == before["liminal.db"] and after != before
    _reads_only(monkeypatch)  # LIMINAL_READONLY: opened for reading alone, and sealed
    with Store(db) as s:
        assert s.conn.execute("PRAGMA query_only").fetchone() == (1,) and s.count_bars("massive", "AAPL", "minute") == 2
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            s.upsert_bars("massive", "AAPL", "minute", 1, [{**BAR, "t": 180_000}])
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            s.conn.execute("CREATE TABLE anything (n)")
        s.conn.execute("PRAGMA query_only=OFF")  # even unsealed by mistake, the file itself was opened read-only
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            s.conn.execute("CREATE TABLE anything (n)")
    assert _files(db) == after


def test_a_file_that_is_behind_is_said_to_be_and_left_as_it_is(db, elsewhere, monkeypatch):
    _own(monkeypatch)  # (as its own system's older software left it)
    _older(db)
    before = _files(db)
    _away(monkeypatch)
    for reads_only in (False, True):
        monkeypatch.setattr(common, "_READ_ONLY", [reads_only])
        with pytest.raises(Behind) as said:
            Store(db)
        words = str(said.value)
        assert "no table claims, claim_tokens; no column fetch_requests.instance, fetch_queue.instance" in words
        assert "brought up to date by the system that holds it" in words and "nothing of it is changed from here" in words
        assert isinstance(said.value, mounts.NotHere)  # its own system's work, as a backup is
        assert lk._links["loopback"].server._workers == {}  # and nothing of it is left open
    monkeypatch.setattr(common, "_READ_ONLY", [False])
    assert _files(db) == before
    # a process that would take a claim there is told the same; one that only looks finds none held
    with pytest.raises(Behind, match="no table claims"):
        claims.take(db, "feed:massive")
    assert claims.held(db) == [] and _files(db) == before
    # its own system brings it up to date, as always; then it opens from the other
    _own(monkeypatch)
    Store(db).close()
    _away(monkeypatch)
    with Store(db) as s:
        assert s.count_bars("massive", "AAPL", "minute") == 1
    held = claims.take(db, "feed:massive")
    assert held is not None and [h.key for h in claims.held(db)] == ["feed:massive"]
    claims.release(db, held)


def test_a_feeds_file_that_is_behind_is_not_upgraded_from_another_system(db, elsewhere, monkeypatch):
    feed = db.parent / "feeds" / "massive.db"
    _own(monkeypatch)
    with closing(sqlite3.connect(feed)) as raw:  # a file from before its changes were logged
        raw.executescript("DROP TABLE changes_since;")
    before = _files(db)
    _away(monkeypatch)
    with pytest.raises(Behind, match="massive.db is on another system's drive and behind this software"):
        Store(db)
    for link in list(lk._links.values()):  # (the main file's connection of the store that did not open)
        link.close()
    lk._links.clear()
    assert _files(db) == before
    if lk.guard():  # where a mount can show another system's drive, nothing opens a file there directly either
        with pytest.raises(lk.LinkError, match="opened by that system alone"):
            sqlite3.connect(feed)
    _own(monkeypatch)
    with Store(db) as s:  # its own system: upgraded, the bar there as before
        assert s.count_bars("massive", "AAPL", "minute") == 1
    assert _files(db) != before


def test_no_database_is_made_on_another_systems_drive(db, elsewhere, monkeypatch):
    new = db.parent / "feeds" / "tiingo.db"
    with pytest.raises(mounts.NotHere, match="no such database, and one is made by the system that holds the files"):
        lk.connect(new)
    with Store(db) as s:
        with pytest.raises(mounts.NotHere, match="tiingo.db: there is no such database"):
            s.upsert_bars("tiingo", "AAPL", "day", 1, [BAR])  # a feed never fetched there: its file is not made here
        assert s._dataset_db("datahub") is None  # (a dataset it does not have: none, as always)
        with pytest.raises(mounts.NotHere, match="no such database"):
            s._dataset_db("datahub", create=True)
    _reads_only(monkeypatch)
    with pytest.raises(sqlite3.OperationalError, match="unable to open"):
        lk.connect(new)  # a process that reads only: sqlite3's own word for a file that is not there
    assert not new.exists() and not (db.parent / "datasets" / "datahub.db").exists()
    assert not (db.parent / "elsewhere").exists()
    with pytest.raises((mounts.NotHere, sqlite3.OperationalError)):
        Store(db.parent / "elsewhere" / "liminal.db")  # nor a folder for one
    assert not (db.parent / "elsewhere").exists()


def test_on_its_own_system_a_file_is_made_and_upgraded_as_always(tmp_path, monkeypatch):
    monkeypatch.delenv(lk.FORCE_VAR, raising=False)
    path = tmp_path / "own" / "liminal.db"
    with Store(path) as s:  # made
        s.upsert_bars("massive", "AAPL", "minute", 1, [BAR])
        assert s.conn.execute("PRAGMA query_only").fetchone() == (0,)
    _older(path)
    with Store(path) as s:  # upgraded
        assert s._lacks() == "" and s.count_bars("massive", "AAPL", "minute") == 1
    monkeypatch.setattr(common, "_READ_ONLY", [True])
    _older(path)
    with Store(path) as s:  # a process that reads only, on its own system's file: upgraded, then sealed (as before)
        assert s._lacks() == "" and s.conn.execute("PRAGMA query_only").fetchone() == (1,)
    with common.owners_layout(None, ":memory:"):  # (a store in memory is this process's own)
        pass
