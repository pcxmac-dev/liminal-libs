"""The link (storage/link.py, 1.57.0; the user, 2026-11-15: "keep the databases (sql/duck/etc) in the same place find a
way to link linux to windows ... that is safe and secure"): a SQLite file on another system's drive is opened by that
system, reached over a private pipe to a helper there. Here the helper is a thread of the test's own process
(Link.loopback: the whole protocol, two pipes), every file the test's own; no process is started."""
from __future__ import annotations

import pickle
import sqlite3
import threading
import time
from datetime import date, datetime

import pytest

from liminal_libs import mounts
from liminal_libs.storage import link as lk
from liminal_libs.storage.link import Connection, Link, LinkError


@pytest.fixture
def linked(tmp_path):
    """A link to a helper that opens files in the test's folder alone."""
    link = Link.loopback([tmp_path / "data"], saved=lambda names: {n: f"value of {n}" for n in names if n != "UNSET"})
    (tmp_path / "data").mkdir()
    yield link, tmp_path / "data"
    link.close()


def test_a_file_is_read_and_written_through_the_link_as_through_sqlite3(linked):
    link, data = linked
    assert link.info["version"] == lk.VERSION and link.info["sqlite"] == sqlite3.sqlite_version
    conn = link.open(data / "liminal.db", timeout=5.0)
    assert isinstance(conn, Connection) and conn.in_transaction is False and conn.row_factory is None
    conn.execute("CREATE TABLE bars (ticker TEXT, ts INTEGER, c REAL, note BLOB, PRIMARY KEY (ticker, ts))")
    cur = conn.execute("INSERT INTO bars VALUES (?, ?, ?, ?)", ("AAPL", 1, 10.5, b"\x00\x01raw"))
    assert cur.rowcount == 1 and cur.lastrowid == 1 and cur.description is None and conn.in_transaction is True
    conn.commit()
    assert conn.in_transaction is False and conn.total_changes == 1
    many = conn.executemany("INSERT INTO bars (ticker, ts, c) VALUES (?, ?, ?)", [("AAPL", t, float(t)) for t in range(2, 12)])
    assert many.rowcount == 10
    conn.commit()
    cur = conn.execute("SELECT ticker, ts, c, note FROM bars WHERE ts <= ? ORDER BY ts", (3,))
    assert [d[0] for d in cur.description] == ["ticker", "ts", "c", "note"] and len(cur.description[0]) == 7 and cur.rowcount == -1
    assert cur.fetchone() == ("AAPL", 1, 10.5, b"\x00\x01raw") and cur.fetchall() == [("AAPL", 2, 2.0, None), ("AAPL", 3, 3.0, None)]
    assert cur.fetchone() is None and cur.fetchall() == []
    named = conn.execute("SELECT COUNT(*) FROM bars WHERE ticker = :t AND ts > :after", {"t": "AAPL", "after": 5}).fetchone()
    assert named == (6,)
    conn.executescript("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT); INSERT INTO kv VALUES ('a', '1');")
    assert conn.execute("SELECT value FROM kv").fetchone() == ("1",)
    assert conn.execute("PRAGMA table_info(kv)").fetchall()[0][1] == "key"
    # what the file holds is what a connection of sqlite3's own sees (the helper wrote it)
    conn.close()
    with sqlite3.connect(str(data / "liminal.db")) as raw:
        assert raw.execute("SELECT COUNT(*), SUM(c) FROM bars").fetchone() == (11, 10.5 + sum(range(2, 12)))
    raw.close()
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        conn.execute("SELECT 1")
    conn.close()  # closed twice: nothing


def test_transactions_commit_and_roll_back_as_sqlite3s_do(linked):
    link, data = linked
    conn, other = link.open(data / "t.db"), link.open(data / "t.db")
    conn.execute("CREATE TABLE t (n INTEGER PRIMARY KEY)")
    conn.commit()
    with conn:  # committed at the end of the block
        conn.execute("INSERT INTO t VALUES (1)")
        assert conn.in_transaction and other.execute("SELECT COUNT(*) FROM t").fetchone() == (0,)  # not seen before
    assert not conn.in_transaction and other.execute("SELECT COUNT(*) FROM t").fetchone() == (1,)
    with pytest.raises(RuntimeError):
        with conn:  # rolled back when the block fails
            conn.execute("INSERT INTO t VALUES (2)")
            raise RuntimeError("the write failed")
    assert not conn.in_transaction and conn.execute("SELECT COUNT(*) FROM t").fetchone() == (1,)
    conn.execute("BEGIN IMMEDIATE")  # the storage's write transactions
    assert conn.in_transaction
    conn.execute("INSERT INTO t VALUES (3)")
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM t").fetchone() == (1,)
    assert conn.executemany("INSERT INTO t VALUES (?)", []).rowcount == 0 and conn.in_transaction  # begun all the same
    conn.rollback()
    auto = link.open(data / "t.db", isolation_level=None)  # each statement its own (the ledgers open so)
    auto.execute("INSERT INTO t VALUES (9)")
    assert auto.in_transaction is False and other.execute("SELECT COUNT(*) FROM t").fetchone() == (2,)
    ro = link.open(data / "t.db", read_only=True)
    assert ro.execute("SELECT COUNT(*) FROM t").fetchone() == (2,)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        ro.execute("INSERT INTO t VALUES (10)")
    for c in (conn, other, auto, ro):
        c.close()


def test_a_querys_rows_come_in_batches_and_the_cursor_reads_them_as_one(linked, monkeypatch):
    link, data = linked
    monkeypatch.setattr(lk, "BATCH_ROWS", 4)
    monkeypatch.setattr(lk, "MANY_ROWS", 7)
    conn = link.open(data / "rows.db")
    conn.execute("CREATE TABLE t (n INTEGER PRIMARY KEY, name TEXT)")
    assert conn.executemany("INSERT INTO t VALUES (?, ?)", ((n, f"row {n}") for n in range(25))).rowcount == 25  # in fours of 7
    conn.commit()
    cur = conn.execute("SELECT n FROM t ORDER BY n")
    assert cur.fetchone() == (0,) and cur.fetchmany(6) == [(n,) for n in range(1, 7)]  # across two batches
    assert [r[0] for r in cur] == list(range(7, 25)) and cur.fetchone() is None
    assert len(conn.execute("SELECT * FROM t").fetchall()) == 25
    assert conn.execute("SELECT n FROM t WHERE n < 4 ORDER BY n").fetchall() == [(0,), (1,), (2,), (3,)]  # exactly a batch
    half = conn.execute("SELECT n FROM t ORDER BY n")
    assert half.fetchone() == (0,)
    half.close()  # left unread: the helper lets it go
    again = conn.execute("SELECT n FROM t ORDER BY n DESC")
    assert again.fetchmany(2) == [(24,), (23,)]
    again.execute("SELECT COUNT(*) FROM t")  # executed anew: the first statement's rows are dropped
    assert again.fetchall() == [(25,)]
    # rows by name, as the login reads its own
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT n, name AS Name FROM t WHERE n = 3").fetchone()
    assert row["n"] == 3 and row["Name"] == "row 3" and row["name"] == "row 3" and row[1] == "row 3" and row.keys() == ["n", "Name"]
    assert dict(row) == {"n": 3, "Name": "row 3"} and tuple(row) == (3, "row 3")
    with pytest.raises(IndexError):
        row["nothing"]
    conn.row_factory = lambda cursor, values: {d[0]: v for d, v in zip(cursor.description, values)}
    assert conn.execute("SELECT n FROM t WHERE n = 5").fetchall() == [{"n": 5}]
    conn.close()


def test_errors_come_back_as_sqlite3s_own(linked):
    link, data = linked
    conn = link.open(data / "e.db")
    conn.execute("CREATE TABLE t (n INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO t VALUES (1)")
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        conn.execute("INSERT INTO t VALUES (1)")
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        conn.execute("SELECT * FROM missing_table")
    with pytest.raises(sqlite3.OperationalError, match="syntax"):
        conn.executescript("CREATE TABLE ok (n); THIS IS NOT SQL;")
    with pytest.raises(sqlite3.ProgrammingError, match="not supported"):
        conn.execute("INSERT INTO t VALUES (?)", (object(),))
    conn.rollback()
    # what crosses is what sqlite3 binds: a bool as a number, a date and a time as text, bytes as they are
    conn.execute("CREATE TABLE v (a, b, c, d, e)")
    conn.execute("INSERT INTO v VALUES (?, ?, ?, ?, ?)", (True, date(2026, 11, 15), datetime(2026, 11, 15, 20, 30), bytearray(b"ab"), 2.5))
    assert conn.execute("SELECT * FROM v").fetchone() == (1, "2026-11-15", "2026-11-15 20:30:00", b"ab", 2.5)
    conn.close()


def test_a_value_of_a_class_built_on_a_number_or_text_crosses_as_what_it_holds(linked):
    """Found running the charts suite over the link: a price read out of a table (a numpy.float64, which is a float
    to sqlite3) went onto the pipe as numpy's own class, the helper read nothing but plain data, and the link ended
    for the whole process."""
    np = pytest.importorskip("numpy")
    import enum

    class Side(enum.IntEnum):
        BUY = 1

    class Ticker(str):
        def __str__(self):  # what a class says of itself is not what sqlite3 binds: the text it holds is
            return "not this"

    class Raw(bytes):
        pass

    link, data = linked
    conn = link.open(data / "kinds.db")
    conn.execute("CREATE TABLE v (a, b, c, d, e, f)")
    given = (np.float64(10.25), Side.BUY, Ticker("AAPL"), Raw(b"\x00raw"), np.str_("text"), memoryview(b"view"))
    conn.execute("INSERT INTO v VALUES (?, ?, ?, ?, ?, ?)", given)
    conn.executemany("INSERT INTO v (a, b) VALUES (:a, :b)", [{"a": np.float64(1.5), "b": True}])
    stored = conn.execute("SELECT * FROM v ORDER BY rowid").fetchall()
    assert stored == [(10.25, 1, "AAPL", b"\x00raw", "text", b"view"), (1.5, 1, None, None, None, None)]
    assert [type(x) for x in stored[0]] == [float, int, str, bytes, str, bytes]
    own = sqlite3.connect(":memory:")  # ... which is what sqlite3 itself stores of the same values
    own.execute("CREATE TABLE v (a, b, c, d, e, f)")
    own.execute("INSERT INTO v VALUES (?, ?, ?, ?, ?, ?)", given)
    assert own.execute("SELECT * FROM v").fetchall() == stored[:1]
    own.close()
    # a numpy integer is no int: sqlite3 would store its eight raw bytes; here it is refused, in sqlite3's words
    with pytest.raises(sqlite3.ProgrammingError, match="type 'int64' is not supported"):
        conn.execute("INSERT INTO v (a) VALUES (?)", (np.int64(7),))
    with pytest.raises(sqlite3.ProgrammingError, match="not supported"):
        conn.executemany("INSERT INTO v (a) VALUES (?)", [(1,), (np.arange(3),)])
    assert conn.execute("SELECT COUNT(*) FROM v").fetchone() == (2,)  # and the link is there as before
    conn.close()


def test_what_is_not_plain_is_refused_before_it_is_sent_and_the_link_stays(linked):
    link, data = linked
    conn = link.open(data / "stays.db")
    for bad in (object(), time.time, sqlite3.OperationalError("x"), datetime(2026, 11, 15), [(1, {"k": Link})]):
        with pytest.raises(LinkError, match="plain data only, not a "):
            link.call("clock", bad)  # by the one who gave it: nothing of it reached the helper
    assert conn.execute("SELECT 1").fetchone() == (1,) and link.dead is None and not link._waiting
    assert abs(link.call("clock")[0] - time.time()) < 5
    for fine in (bytearray(b"ab"), {1, 2}, frozenset(("a",))):  # what is written without naming a class is read
        assert lk._loads(lk._dumps(fine)) == fine
    conn.close()


def test_a_closed_connection_has_left_its_file_closed(linked, monkeypatch):
    """Found running the charts suite over the link: close() came back before the helper had closed the file, so
    what the caller did next (the file's size read, a copy made of it) found a file still open, its last writes
    still in its log."""
    link, data = linked
    shut = lk._Worker._shut

    def slowly(self) -> None:
        time.sleep(0.3)  # the helper busy closing: writing the log back into the file
        shut(self)

    monkeypatch.setattr(lk._Worker, "_shut", slowly)
    conn = link.open(data / "closing.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (n, pad)")
    conn.executemany("INSERT INTO t VALUES (?, ?)", [(n, "x" * 500) for n in range(2000)])
    conn.commit()
    wal = data / "closing.db-wal"
    assert wal.exists() and wal.stat().st_size > 500_000 and (data / "closing.db").stat().st_size < 100_000
    conn.close()
    assert not wal.exists() and (data / "closing.db").stat().st_size > 1_000_000  # written back, the log gone
    assert link.server._workers == {}  # and the helper holds nothing of it


def test_the_statements_sqlite_runs_are_told_as_sqlite3_tells_them(linked):
    link, data = linked
    over, own = link.open(data / "traced.db"), sqlite3.connect(str(data / "traced-own.db"))
    told: dict[str, list] = {"over": [], "own": []}
    for name, conn in (("over", over), ("own", own)):
        conn.execute("CREATE TABLE t (n INTEGER PRIMARY KEY, name TEXT)")
        conn.commit()
        conn.set_trace_callback(told[name].append)
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO t VALUES (?, ?)", (1, "one"))
        conn.executemany("INSERT INTO t VALUES (?, ?)", [(2, "two"), (3, "three")])
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM t WHERE n > ?", (1,)).fetchone() == (2,)
        conn.set_trace_callback(None)
        conn.execute("SELECT 1").fetchone()  # no longer told
    assert told["over"] == told["own"] and told["own"][0] == "BEGIN IMMEDIATE" and "COMMIT" in told["own"]
    assert len(told["over"]) == 6 and not any("SELECT 1" in q for q in told["over"])
    over.close()
    own.close()


def test_the_helper_is_started_without_a_window(monkeypatch):
    """On Windows a console child of a process without a console gets a terminal window of its own (the user,
    2026-11-01: "i have 30 cmd prompts open"): the helper is started as every other process of this software is."""
    import os

    started: list[dict] = []

    def popen(args, **kw):
        started.append({"args": args, **kw})
        raise OSError("no such program")

    monkeypatch.setattr(lk.subprocess, "Popen", popen)
    monkeypatch.delenv(lk.LOG_VAR, raising=False)
    with pytest.raises(LinkError, match="could not be started"):
        Link.start("pythonw.exe -m liminal_libs.storage.link", cwd=None)
    assert started[0]["args"] == ["pythonw.exe", "-m", "liminal_libs.storage.link"]
    assert started[0].get("creationflags", 0) == (0x08000000 if os.name == "nt" else 0)
    assert started[0]["stdin"] == lk.subprocess.PIPE and started[0]["stdout"] == lk.subprocess.PIPE


def test_the_helper_opens_nothing_outside_its_folders(linked, tmp_path):
    link, data = linked
    outside = tmp_path / "elsewhere.db"
    sqlite3.connect(str(outside)).close()
    with pytest.raises(mounts.NotHere, match="not in the folders this helper opens"):
        link.open(outside)
    conn = link.open(data / "main.db")
    conn.execute("CREATE TABLE t (n)")
    conn.commit()
    with pytest.raises(mounts.NotHere, match="not attached"):
        conn.execute("ATTACH DATABASE ? AS other", (str(outside),))  # given as a parameter: checked before it runs
    literal = str(outside).replace("'", "''")
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        conn.execute(f"ATTACH DATABASE '{literal}' AS other")  # named in the statement: SQLite asks, and is told no
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        conn.executescript(f"ATTACH DATABASE '{literal}' AS other;")
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        conn.execute("ATTACH DATABASE ('a' || 'b') AS other")  # computed: it cannot be checked, so it is refused
    conn.execute("ATTACH DATABASE ? AS ticks", (str(data / "ticks.db"),))  # one of its own: attached
    conn.execute("CREATE TABLE ticks.trades (n)")
    conn.execute("ATTACH DATABASE ? AS scratch", (":memory:",))
    assert {r[1] for r in conn.execute("PRAGMA database_list")} == {"main", "ticks", "scratch"}
    with pytest.raises(mounts.NotHere, match="VACUUM INTO"):
        conn.execute("VACUUM INTO ?", (str(data / "copy.db"),))
    with pytest.raises(mounts.NotHere, match="backup"):
        conn.backup(None)
    assert not (data / "copy.db").exists()
    conn.close()


def test_nothing_but_plain_data_is_rebuilt_from_the_pipe():
    for bad in (datetime(2026, 11, 15), time.time, {"k": sqlite3.OperationalError("x")}, [LinkError]):
        with pytest.raises(pickle.UnpicklingError, match="plain data only"):
            lk._loads(pickle.dumps(bad, protocol=5))
    plain = (1, 2.5, "text", b"bytes", None, True, [1, (2, 3)], {"k": [b"v"]})
    assert lk._loads(lk._dumps(plain)) == plain
    for bad in (datetime(2026, 11, 15), time.time, [LinkError], (1, {"k": object()})):  # nor is it put there
        with pytest.raises(LinkError, match="plain data only"):
            lk._dumps(bad)


def test_one_connections_long_query_does_not_hold_up_another(linked):
    link, data = linked
    slow, quick = link.open(data / "a.db"), link.open(data / "b.db")
    quick.execute("CREATE TABLE t (n)")
    started, out = threading.Event(), {}

    def long_query() -> None:
        started.set()
        try:
            with lk.time_limit(slow, 30.0):
                slow.execute("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 200000000) SELECT MAX(x) FROM c").fetchone()
        except sqlite3.OperationalError as e:
            out["error"] = str(e)

    t = threading.Thread(target=long_query)
    t.start()
    started.wait(5)
    time.sleep(0.2)
    began = time.monotonic()
    quick.execute("INSERT INTO t VALUES (1)")
    quick.commit()
    assert quick.execute("SELECT COUNT(*) FROM t").fetchone() == (1,) and time.monotonic() - began < 5  # answered meanwhile
    slow.interrupt()  # from this thread, while it runs in the other
    t.join(30)
    assert not t.is_alive() and "interrupted" in out["error"]
    for c in (slow, quick):
        c.close()


def test_a_time_limit_ends_a_read_that_runs_too_long_on_either_kind_of_connection(linked):
    link, data = linked
    endless = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 2000000000) SELECT MAX(x) FROM c"
    for conn in (link.open(data / "limit.db"), sqlite3.connect(str(data / "limit-own.db"))):
        began = time.monotonic()
        with pytest.raises(sqlite3.OperationalError, match="interrupted"):
            with lk.time_limit(conn, 0.3):
                conn.execute(endless).fetchone()
        assert time.monotonic() - began < 20
        assert conn.execute("SELECT 1").fetchone() == (1,)  # the limit ended with the block
        conn.close()
    conn = link.open(data / "limit.db")
    conn.set_progress_handler(None, 0)  # ending one crosses; a handler of this process's cannot
    with pytest.raises(LinkError, match="time_limit"):
        conn.set_progress_handler(lambda: 0, 100)
    with pytest.raises(LinkError):
        conn.create_function("f", 1, lambda x: x)
    conn.close()


def test_a_link_that_is_gone_is_said_and_never_made_again(linked):
    link, data = linked
    conn = link.open(data / "gone.db")
    conn.execute("CREATE TABLE t (n)")
    conn.execute("INSERT INTO t VALUES (1)")  # not committed: it ends with the link, as with a process
    link.close()
    for ask in (lambda: conn.execute("SELECT 1"), lambda: link.open(data / "gone.db"), lambda: link.saved(["A"])):
        with pytest.raises(sqlite3.OperationalError, match="is gone .* must be started again"):
            ask()
    conn.close()  # nothing to say to a helper that is no more
    with sqlite3.connect(str(data / "gone.db")) as raw:
        assert raw.execute("SELECT COUNT(*) FROM t").fetchone() == (0,)
    raw.close()


def test_the_owners_clock_and_the_users_saved_settings_come_over_the_link(linked):
    link, _ = linked
    assert abs(link.owner_now() - time.time()) < 2 and abs(link.skew) < 2  # the same machine here: the same clock
    link.skew = 12.0  # WSL's clock twelve seconds off Windows': what is stamped follows the files' own system
    assert 11 < link.owner_now() - time.time() < 13
    assert link.saved(["MASSIVE_API_KEY", "UNSET"]) == {"MASSIVE_API_KEY": "value of MASSIVE_API_KEY"}
    quiet = Link.loopback([], saved=None)
    try:
        with pytest.raises(LinkError, match="tells no settings"):
            quiet.saved(["A"])
    finally:
        quiet.close()


def test_connect_opens_this_systems_files_itself_and_another_systems_through_the_link(tmp_path, monkeypatch):
    monkeypatch.delenv(lk.FORCE_VAR, raising=False)
    monkeypatch.setattr(lk, "_links", {})
    own = lk.connect(tmp_path / "own.db", timeout=3.0)
    assert isinstance(own, sqlite3.Connection)
    own.execute("CREATE TABLE t (n)")
    own.commit()
    own.close()
    assert isinstance(lk.connect(":memory:"), sqlite3.Connection)
    ro = lk.connect(tmp_path / "own.db", read_only=True)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        ro.execute("INSERT INTO t VALUES (1)")
    ro.close()
    auto = lk.connect(tmp_path / "own.db", isolation_level=None)
    assert auto.isolation_level is None
    auto.close()
    # a suite run over the link: every file through a helper inside this process
    monkeypatch.setenv(lk.FORCE_VAR, "loopback")
    over = lk.connect(tmp_path / "own.db")
    try:
        assert isinstance(over, Connection) and over.execute("SELECT COUNT(*) FROM t").fetchone() == (0,)
        assert isinstance(lk.connect(":memory:"), sqlite3.Connection)  # memory is this process's own
        assert lk.owner_link() is lk._links["loopback"]
    finally:
        over.close()
        lk._links.pop("loopback").close()
    monkeypatch.delenv(lk.FORCE_VAR)
    # another system's drive with no helper to start: said, and never opened directly
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: True)
    monkeypatch.setattr(mounts, "owner_path", lambda p, text=None: None)
    monkeypatch.setattr(mounts, "fstype", lambda p, mounts=None: "cifs")
    with pytest.raises(LinkError, match="no helper can be started"):
        lk.connect(tmp_path / "own.db")
    monkeypatch.setattr(mounts, "owner_path", lambda p, text=None: "C:\\x\\own.db")
    monkeypatch.delenv(lk.COMMAND_VAR, raising=False)
    with pytest.raises(LinkError, match="no helper is named"):
        lk.connect(tmp_path / "own.db")


def test_no_code_opens_another_systems_file_directly(tmp_path, monkeypatch):
    own = str(tmp_path / "own.db")
    lk._refuse_direct("sqlite3.connect", (own,))  # this system's own: nothing said
    lk._refuse_direct("sqlite3.connect", (":memory:",))
    lk._refuse_direct("open", (own,))  # another event: not its business
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: str(p).replace("\\", "/").startswith("/mnt/c/"))
    for target in ("/mnt/c/data/liminal.db", b"/mnt/c/data/liminal.db", "file:///mnt/c/data/liminal.db?mode=ro"):
        with pytest.raises(LinkError, match="opened by that system alone"):
            lk._refuse_direct("sqlite3.connect", (target,))
    lk._refuse_direct("sqlite3.connect", ("file:/home/x/own.db?mode=ro",))
    import sys

    assert lk.guard() is sys.platform.startswith("linux")  # on where a mount can show another system's drive


def test_a_frame_is_the_same_from_either_kind_of_connection(linked):
    pd = pytest.importorskip("pandas")
    link, data = linked
    over = link.open(data / "frames.db")
    over.execute("CREATE TABLE bars (ticker TEXT, ts INTEGER, c REAL, v INTEGER, note TEXT)")
    over.executemany("INSERT INTO bars VALUES (?, ?, ?, ?, ?)",
                     [("AAPL", 1, 10.5, 100, None), ("AAPL", 2, 11.0, None, "x"), ("MSFT", 1, 20.25, 300, "y")])
    over.commit()
    own = sqlite3.connect(str(data / "frames.db"))
    for sql, params in (("SELECT * FROM bars ORDER BY ticker, ts", None),
                        ("SELECT ts, c FROM bars WHERE ticker = ? ORDER BY ts", ("AAPL",)),
                        ("SELECT ticker, v FROM bars WHERE ts > ?", (99,))):  # no rows: the columns alone
        a, b = lk.frame(sql, own, params), lk.frame(sql, over, params)
        pd.testing.assert_frame_equal(a, b)
    own.close()
    over.close()
