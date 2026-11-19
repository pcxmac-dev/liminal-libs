"""The fetch cache and the copy audit (1.64.0): spool.py (the files), storage/pulls.py (the ledger), the HTTP client's
and the stores' hooks, and auditing.py's copy audit.

The user, 2026-11-15: "when the integrator goes to a source and pulls the data, make sure that the data is stored in a
temporary cache (not on ram), until it can be read in to the symbol database. leave the data in cache until an auditor
goes over the symbol and checks the data bit by bit to ensure it was copied successfully".

No process, no network: the HTTP client is given a real requests session whose wire is a stand-in (an adapter that
answers from memory), and the stores are files under tmp_path."""
from __future__ import annotations

import ast
import io
import json
import math
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

from liminal_libs import auditing, claims, collector, spool
from liminal_libs.collector import ET, StopRun
from liminal_libs.coverage import ms
from liminal_libs.errors import BudgetExhausted, SourceError
from liminal_libs.sources.base import DataSource
from liminal_libs.sources.http import HttpClient, SameHostSession
from liminal_libs.storage import Store, feeds, pulls, set_read_only

pytestmark = pytest.mark.usefixtures("no_outside")

OPEN = ms(datetime(2026, 10, 20, 9, 30, tzinfo=ET))  # a Tuesday's session
CLOSE = ms(datetime(2026, 10, 20, 16, 0, tzinfo=ET))
QUIET = lambda *_: None  # noqa: E731


def _bar(t: int, price: float = 10.0, **more) -> dict:
    return {"t": t, "o": price, "h": price + 1, "l": price - 1, "c": price + 0.1, "v": 100, "vw": price + 0.05, "n": 7,
            **more}


def _minutes(n: int, start: int = OPEN, price: float = 10.0) -> list[dict]:
    return [_bar(start + i * 60_000, price + i * 0.01) for i in range(n)]


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data" / "liminal.db") as s:
        yield s


@pytest.fixture(autouse=True)
def the_defaults(monkeypatch):
    """Every test starts on the default policy, with the cache on, writing."""
    monkeypatch.delenv(pulls.SWITCH, raising=False)
    auditing.set_policy(None)
    yield
    auditing.set_policy(None)
    set_read_only(False)


def _stored(store, feed="fake", ticker="AAA", timespan="minute") -> list[tuple]:
    conn = store._bars(feed)
    if conn is None:
        return []
    return conn.execute("SELECT ts, open, high, low, close, volume, vwap, transactions FROM bars WHERE ticker=? AND "
                        "timespan=? ORDER BY ts", (ticker, timespan)).fetchall()


def _cache_files(store) -> list[str]:
    folder = pulls.cache_dir(store)
    return sorted(p.name for p in folder.rglob("*") if p.is_file()) if folder.is_dir() else []


# -- the files ---------------------------------------------------------------------------------------------------------
def test_a_rows_file_gives_back_exactly_the_values_written(tmp_path):
    awkward = [0.1 + 0.2, 1e-320, -0.0, 1.7976931348623157e308, 123456789.12345679, 2**53 + 1, -7, None, True, "AAA",
               math.pi, 100.0, 5e-324]
    rows = [["AAA", "minute", 1, 1000 + i, v, v, v, v, v, v, 3] for i, v in enumerate(awkward)]
    written = spool.write_rows(tmp_path, "00001" + spool.ROWS_SUFFIX, {"feed": "fake", "stored_at": 5}, rows)
    assert written.rows == len(rows) and written.bytes == (tmp_path / written.name).stat().st_size > 0
    header, back, digest = spool.read_rows(tmp_path / written.name)
    assert header == {"v": spool.VERSION, "feed": "fake", "stored_at": 5} and digest == written.sha256
    assert len(back) == len(rows)
    for was, now in zip(awkward, (r[4] for r in back)):
        assert type(now) is type(was)  # an int stays an int, a float a float
        if isinstance(was, float):
            assert was.hex() == now.hex(), was  # the same float, bit for bit (a negative zero too)
        else:
            assert now == was
    assert [p.name for p in tmp_path.iterdir()] == [written.name]  # nothing half written is left beside it


def test_a_rows_file_takes_numpy_numbers_as_the_numbers_they_are_and_refuses_what_is_no_value(tmp_path):
    np = pytest.importorskip("numpy")
    rows = [["AAA", "minute", 1, np.int64(1000), np.float64(0.1), 1.0, 1.0, 1.0, np.int64(5), None, 2]]
    spool.write_rows(tmp_path, "a" + spool.ROWS_SUFFIX, {}, rows)
    _, back, _ = spool.read_rows(tmp_path / ("a" + spool.ROWS_SUFFIX))
    assert back == [["AAA", "minute", 1, 1000, 0.1, 1.0, 1.0, 1.0, 5, None, 2]]
    assert type(back[0][3]) is int and type(back[0][4]) is float
    with pytest.raises(spool.Unspoolable, match="not a bytes"):
        spool.write_rows(tmp_path, "b" + spool.ROWS_SUFFIX, {}, [["AAA", "minute", 1, 1, b"\x00", 1, 1, 1, 1, 1, 1]])
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a" + spool.ROWS_SUFFIX]  # the refused one wrote nothing


def test_what_is_no_rows_file_is_said_to_be_none(tmp_path):
    import gzip

    path = tmp_path / ("x" + spool.ROWS_SUFFIX)
    for text in (b"not json", b'{"v": 99, "rows": []}', b'{"v": 1, "rows": 5}', b"[1, 2]"):
        path.write_bytes(gzip.compress(text))
        with pytest.raises(ValueError, match="not a rows file"):
            spool.read_rows(path)


def test_a_payload_goes_to_disk_piece_by_piece_and_comes_back_whole(tmp_path):
    import hashlib

    body = b'{"results": [' + b",".join(b'{"t": %d}' % i for i in range(5000)) + b"]}"
    writer = spool.PayloadWriter(tmp_path, "00001" + spool.PAYLOAD_SUFFIX)
    for i in range(0, len(body), 1000):
        writer.write(body[i:i + 1000])
    assert (tmp_path / ("00001" + spool.PAYLOAD_SUFFIX)).exists() is False  # not under its name before it is whole
    written = writer.close()
    assert written.sha256 == hashlib.sha256(body).hexdigest() and writer.received == len(body)
    assert spool.read_payload(tmp_path / written.name) == body and spool.payload_sha256(tmp_path / written.name) == written.sha256
    assert written.bytes < len(body)  # (packed)
    cut = spool.PayloadWriter(tmp_path, "00002" + spool.PAYLOAD_SUFFIX)
    cut.write(b"half an ans")
    cut.abandon()
    assert [p.name for p in tmp_path.iterdir()] == [written.name]  # an answer cut off leaves nothing


def test_a_disk_that_refuses_is_the_caches_own_failure(tmp_path):
    with pytest.raises(spool.CacheFailed, match="could not be written"):
        spool.write_rows(tmp_path / "no" / "such" / "folder", "a" + spool.ROWS_SUFFIX, {}, [[1]])
    with pytest.raises(spool.CacheFailed, match="could not be written"):
        spool.PayloadWriter(tmp_path / "no" / "such" / "folder", "a" + spool.PAYLOAD_SUFFIX)
    assert issubclass(spool.CacheFailed, OSError) and not issubclass(spool.CacheFailed, requests.RequestException)


def test_the_pull_that_is_open_is_this_threads_alone():
    assert spool.current() is None
    with spool.opened("outer") as outer:
        assert spool.current() == "outer" == outer
        with spool.opened("inner"):
            assert spool.current() == "inner"
        assert spool.current() == "outer"
        import threading

        seen = []
        t = threading.Thread(target=lambda: seen.append(spool.current()))
        t.start()
        t.join()
        assert seen == [None]  # a thread started inside has none
    assert spool.current() is None


def test_the_spool_is_plain_the_standard_library_alone():
    # the HTTP client is every plugin's, the assistants' and the platform's too: asking which pull is open loads nothing
    tree = ast.parse(Path(spool.__file__).read_text(encoding="utf-8"))
    named = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    named |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and not n.level}
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level]  # nothing of the library
    assert named <= set(sys.stdlib_module_names), named


# -- the ledger --------------------------------------------------------------------------------------------------------
def test_a_pull_that_writes_nothing_leaves_nothing(store):
    with pulls.pulling(store, "fake", "bars", ticker="aaa", asset="stock", timespan="minute", start_ms=1, end_ms=2) as p:
        assert spool.current() is p and p.spools and not p.made
    assert p.closed and store.pulls() == [] and not pulls.cache_dir(store).exists()


def test_a_write_of_bars_goes_through_the_pull_that_is_open(store):
    bars = _minutes(3)
    with pulls.pulling(store, "fake", "bars", ticker="aaa", asset="stock", timespan="minute", start_ms=OPEN, end_ms=CLOSE) as p:
        assert store.upsert_bars("fake", "AAA", "minute", 1, bars) == 3
        (row,) = store.pulls()
        assert (row["id"], row["state"], row["audit"], row["ticker"], row["kind"]) == (p.id, "open", None, "AAA", "bars")
        assert row["instance"] == claims.instance() and (row["start_ms"], row["end_ms"]) == (OPEN, CLOSE)
        (f,) = store.pull_files(p.id)
        assert (f["kind"], f["rows"], f["feed"], f["lo_ms"], f["hi_ms"]) == ("rows", 3, "fake", OPEN, OPEN + 120_000)
        assert f["loaded_at"] is not None and f["audited_at"] is None and f["removed_at"] is None
    (row,) = store.pulls()
    assert row["state"] == "complete" and row["closed_at"] and row["audit"] is None  # (pulling audits nothing itself)
    folder = store.pull_folder(p.id)
    assert folder == pulls.cache_dir(store) / "fake" / p.id and [x.name for x in folder.iterdir()] == [f["name"]]
    header, rows, digest = spool.read_rows(folder / f["name"])
    assert digest == f["sha256"] and header["feed"] == "fake" and header["pull"] == p.id and header["seq"] == 1
    assert header["columns"] == list(pulls.ROW_COLUMNS) and header["stored_at"] == f["stored_at"]
    assert [tuple(r[3:]) for r in rows] == _stored(store)  # what the file holds is what is stored
    assert store.cache_bytes() == f["bytes"] and store.cache_bytes(unverified_only=False) == f["bytes"]


def test_the_database_is_written_from_the_file_read_back_not_from_the_rows_in_memory(store, monkeypatch):
    real = spool.read_rows

    def other_rows(path):
        header, rows, digest = real(path)
        return header, [[*r[:7], 99.5, *r[8:]] for r in rows], digest  # (the close, as if the file said so)

    monkeypatch.setattr(spool, "read_rows", other_rows)
    with pulls.pulling(store, "fake", "bars", ticker="AAA", timespan="minute"):
        store.upsert_bars("fake", "AAA", "minute", 1, _minutes(2))
    assert [r[4] for r in _stored(store)] == [99.5, 99.5]


def test_a_rows_file_read_back_otherwise_than_written_stops_the_write(store, monkeypatch):
    real = spool.read_rows
    monkeypatch.setattr(spool, "read_rows", lambda path: (*real(path)[:2], "0" * 64))
    with pytest.raises(spool.CacheFailed, match="not what was written"):
        with pulls.pulling(store, "fake", "bars", ticker="AAA", timespan="minute"):
            store.upsert_bars("fake", "AAA", "minute", 1, _minutes(2))
    assert _stored(store) == []  # nothing reached the database
    (row,) = store.pulls()
    assert row["state"] == "cut" and "CacheFailed" in row["note"]


def test_a_pull_left_by_an_error_is_cut_and_says_why(store):
    with pytest.raises(RuntimeError):
        with pulls.pulling(store, "fake", "bars", ticker="AAA", timespan="minute"):
            store.upsert_bars("fake", "AAA", "minute", 1, _minutes(2))
            raise RuntimeError("the feed went away")
    (row,) = store.pulls()
    assert row["state"] == "cut" and row["note"] == "RuntimeError: the feed went away"
    assert len(_stored(store)) == 2  # what was loaded before it stays


def test_with_no_pull_open_a_write_is_as_it_always_was(store):
    assert store.upsert_bars("fake", "AAA", "minute", 1, _minutes(2)) == 2
    assert store.pulls() == [] and not pulls.cache_dir(store).exists() and len(_stored(store)) == 2


@pytest.mark.parametrize("how", ["switched off", "reading only", "in memory"])
def test_where_nothing_is_cached_a_pull_is_open_in_name_only(tmp_path, monkeypatch, how):
    if how == "switched off":
        monkeypatch.setenv(pulls.SWITCH, "off")
    with Store(":memory:" if how == "in memory" else tmp_path / "liminal.db") as s:
        if how == "reading only":
            s.upsert_bars("fake", "AAA", "minute", 1, _minutes(1))  # (its feed's file made while it still writes)
            set_read_only(True)
        with pulls.pulling(s, "fake", "bars", ticker="AAA", timespan="minute") as p:
            assert not p.spools and p.payload("/v2/aggs", 200) is None
            assert p.rows("fake", [("AAA", "minute", 1, 1, 1, 1, 1, 1, 1, 1, 1, 5)], 5) == (
                [("AAA", "minute", 1, 1, 1, 1, 1, 1, 1, 1, 1, 5)], None)
            if how != "reading only":
                s.upsert_bars("fake", "AAA", "minute", 1, _minutes(2))
        assert s.conn.execute("SELECT COUNT(*) FROM pulls").fetchone()[0] == 0
        assert pulls.cache_dir(s) is None or not pulls.cache_dir(s).exists()


def test_a_whole_markets_day_is_a_pull_of_many_symbols(store):
    from datetime import date

    day = date(2026, 10, 20)
    bars = [{"T": "aaa", **_bar(OPEN)}, {"T": "BBB", **_bar(OPEN, 20.0)}]
    with pulls.pulling(store, "fake", "market_day", asset="stock", timespan="day") as p:
        assert store.save_market_day("fake", day, bars, OPEN, OPEN + 86_400_000) == 2
    with pulls.pulling(store, "fake", "grouped_day", asset="stock", timespan="day") as q:
        assert store.save_grouped_day("fake", day, bars) == 2
    for pull in (p, q):
        (f,) = store.pull_files(pull.id)
        _, rows, _ = spool.read_rows(store.pull_folder(pull.id) / f["name"])
        assert [r[0] for r in rows] == ["AAA", "BBB"] and f["rows"] == 2 and f["loaded_at"]
    assert [a.result for a in auditing.audit_pulls(store)] == ["ok", "ok"]


def test_a_kind_that_is_none_is_refused(store):
    with pytest.raises(ValueError, match="not a kind of pull"):
        store.pull_open("fake", "anything")


# -- the HTTP client -----------------------------------------------------------------------------------------------------
class Wire(requests.adapters.BaseAdapter):
    """The wire, standing in: answers from memory, and notes each request with whether it was asked in pieces."""

    def __init__(self, answers):
        super().__init__()
        self.answers = list(answers)
        self.sent: list[tuple[str, bool]] = []

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        self.sent.append((request.url, bool(stream)))
        status, body = self.answers.pop(0)
        r = requests.Response()
        r.status_code, r.url, r.request = status, request.url, request
        r.headers["Content-Type"] = "application/json"
        r.raw = body if hasattr(body, "read") else io.BytesIO(body)
        return r

    def close(self):
        pass


class CutOff:
    """A body that ends before its end."""

    def __init__(self, first: bytes):
        self.first = first

    def read(self, n=-1):
        if self.first:
            out, self.first = self.first, b""
            return out
        raise requests.exceptions.ChunkedEncodingError("the connection was cut")


def _client(answers, **kw) -> tuple[HttpClient, Wire]:
    wire = Wire(answers)
    session = SameHostSession()
    session.trust_env = False  # (no proxy looked up: nothing of this machine's settings is read)
    session.mount("https://", wire)
    return HttpClient("https://api.feed.test", headers={"Authorization": "Bearer KEY"}, session=session,
                      sleep=lambda s: None, **kw), wire


def test_an_answer_goes_to_the_open_pulls_folder_and_is_parsed_from_there(store):
    import hashlib

    body = json.dumps({"results": [_bar(OPEN + i * 60_000) for i in range(400)], "note": "ünïcode"}).encode()
    client, wire = _client([(200, body), (200, body)])
    with pulls.pulling(store, "fake", "bars", ticker="AAA", timespan="minute") as p:
        got = client.get("/v2/aggs/AAA", {"apiKey": "SECRET", "limit": 400})
        (f,) = store.pull_files(p.id)
        folder = store.pull_folder(p.id)
        assert spool.read_payload(folder / f["name"]) == body
        ledger = json.dumps([store.pull_files(p.id), store.pulls()])
        assert "SECRET" not in ledger and "apiKey" not in ledger  # the request is kept by its path, never its query
        assert all("SECRET" not in x.name for x in folder.iterdir())
    assert got == json.loads(body) and wire.sent == [("https://api.feed.test/v2/aggs/AAA?apiKey=SECRET&limit=400", True)]
    assert (f["kind"], f["path"], f["status"], f["sha256"]) == ("payload", "/v2/aggs/AAA", 200, hashlib.sha256(body).hexdigest())
    # it loaded no rows, so there was nothing to check: complete, its answer goes with it
    assert store.pull(p.id) is None and not folder.exists()
    assert client.get("/v2/aggs/AAA") == json.loads(body) and wire.sent[-1][1] is False  # no pull open: as it always was
    assert store.pulls() == [] and client.requests_made == 2


def test_what_is_parsed_is_the_files_bytes(store, monkeypatch):
    client, _ = _client([(200, b'{"from": "the wire"}')])
    monkeypatch.setattr(spool, "read_payload", lambda path: b'{"from": "the file"}')
    with pulls.pulling(store, "fake", "bars", ticker="AAA", timespan="minute"):
        assert client.get("/x") == {"from": "the file"}


def test_an_answer_that_is_refused_is_not_kept(store):
    client, wire = _client([(404, b'{"message": "no such ticker"}'), (500, b"oops"), (200, b'{"ok": true}')], max_retries=1)
    with pulls.pulling(store, "fake", "bars", ticker="AAA", timespan="minute") as p:
        with pytest.raises(SourceError, match="no such ticker"):
            client.get("/a")
        assert client.get("/b") == {"ok": True}  # (a 500, then tried again: only the good answer is kept)
        assert [(f["path"], f["status"]) for f in store.pull_files(p.id)] == [("/b", 200)]
    assert [s for _, s in wire.sent] == [True, True, True]


def test_an_answer_cut_off_on_its_way_is_asked_for_again_and_leaves_nothing_half_written(store):
    client, wire = _client([(200, CutOff(b'{"results": [1, 2')), (200, b'{"results": [1, 2, 3]}')])
    retried: list = []
    client.on_retry = lambda seconds, status: retried.append(status)
    with pulls.pulling(store, "fake", "bars", ticker="AAA", timespan="minute") as p:
        assert client.get("/a") == {"results": [1, 2, 3]}
        files = store.pull_files(p.id)
        on_disk = sorted(x.name for x in store.pull_folder(p.id).iterdir())
    assert retried == [0] and len(wire.sent) == 2 and client.requests_made == 2
    assert len(files) == 1 and on_disk == [files[0]["name"]]  # one answer kept; the cut one left no part of itself
    client, _ = _client([(200, CutOff(b"{"))], max_retries=0)
    with pulls.pulling(store, "fake", "bars", ticker="BBB", timespan="minute"):
        with pytest.raises(SourceError, match="no answer: ChunkedEncodingError"):
            client.get("/a")


def test_a_cache_that_cannot_take_the_answer_fails_as_the_cache_not_as_the_feed(store, monkeypatch):
    client, wire = _client([(200, b'{"ok": true}'), (200, b'{"ok": true}')])

    def full(self, piece):
        raise spool.CacheFailed("the fetch cache could not be written (the disk is full)")

    monkeypatch.setattr(spool.PayloadWriter, "write", full)
    with pytest.raises(spool.CacheFailed, match="disk is full"):
        with pulls.pulling(store, "fake", "bars", ticker="AAA", timespan="minute"):
            client.get("/a")
    assert len(wire.sent) == 1  # not asked again: the feed answered


def test_a_stand_in_session_is_asked_as_before_and_its_body_kept(store):
    class Answer:
        status_code, headers = 200, {}
        content = b'{"results": [5]}'

        def json(self):
            return json.loads(self.content)

    class Session:
        def __init__(self):
            self.asked: list[dict] = []

        def get(self, url, params=None, headers=None, timeout=None):  # (no `stream`: a test's session never had it)
            self.asked.append({"url": url, "params": params})
            return Answer()

    session = Session()
    client = HttpClient("https://api.feed.test", session=session)
    with pulls.pulling(store, "fake", "bars", ticker="AAA", timespan="minute") as p:
        assert client.get("/a", {"k": "v"}) == {"results": [5]}
        (f,) = store.pull_files(p.id)
        assert spool.read_payload(store.pull_folder(p.id) / f["name"]) == b'{"results": [5]}'
    assert session.asked == [{"url": "https://api.feed.test/a", "params": {"k": "v"}}]

    class Bare:
        status_code, headers = 200, {}

        def json(self):
            return {"bare": True}

    session.get = lambda url, params=None, headers=None, timeout=None: Bare()
    with pulls.pulling(store, "fake", "bars", ticker="BBB", timespan="minute") as q:
        assert client.get("/b") == {"bare": True}  # an answer with no body to keep is left as it is
    assert store.pull(q.id) is None and _cache_files(store) == []


# -- the copy audit ------------------------------------------------------------------------------------------------------
def _pull_of(store, bars, ticker="AAA", feed="fake", timespan="minute") -> str:
    """A pull loaded and closed, not audited."""
    with pulls.pulling(store, feed, "bars", ticker=ticker, asset="stock", timespan=timespan, start_ms=OPEN, end_ms=CLOSE) as p:
        for i in range(0, len(bars), 50):
            store.upsert_bars(feed, ticker, timespan, 1, bars[i:i + 50])
    return p.id


def test_a_pull_that_was_copied_exactly_passes_and_its_files_go(store):
    pull = _pull_of(store, _minutes(120))
    assert len(store.pull_files(pull)) == 3 and len(_cache_files(store)) == 3
    said: list[str] = []
    got = auditing.audit_pull(store, pull, log=said.append)
    assert (got.result, got.rows, got.missing, got.differing, got.removed) == ("ok", 120, 0, 0, 3)
    assert [f.result for f in got.files] == ["ok"] * 3 and said == []  # a pass says nothing in the log
    row = store.pull(pull)
    assert row["audit"] == "ok" and row["audited_at"] and row["note"] is None
    assert all(f["result"] == "ok" and f["audited_at"] and f["removed_at"] for f in store.pull_files(pull))
    assert _cache_files(store) == [] and not store.pull_folder(pull).exists()
    assert store.findings() == [] and store.cache_bytes() == 0 == store.cache_bytes(unverified_only=False)
    assert auditing.audit_pull(store, pull) is None  # audited already
    assert got.words() == "audit fake:AAA: 120 bars of 3 cache files match what is stored"


def test_one_changed_bit_is_caught_and_nothing_stored_is_overwritten(store):
    pull = _pull_of(store, _minutes(60))
    conn = store._bars("fake")
    was = conn.execute("SELECT close FROM bars WHERE ts=?", (OPEN + 7 * 60_000,)).fetchone()[0]
    other = math.nextafter(was, math.inf)  # the next float up: one bit of it differs
    with conn:
        conn.execute("UPDATE bars SET close=? WHERE ts=?", (other, OPEN + 7 * 60_000))
    said: list[str] = []
    got = auditing.audit_pull(store, pull, log=said.append)
    assert (got.result, got.differing, got.missing, got.removed) == ("mismatch", 1, 0, 0)
    assert conn.execute("SELECT close FROM bars WHERE ts=?", (OPEN + 7 * 60_000,)).fetchone()[0] == other  # as stored
    assert len(_cache_files(store)) == 2  # its files stay: the evidence
    row = store.pull(pull)
    assert row["audit"] == "mismatch" and "1 are stored with other values" in row["note"]
    (finding,) = store.findings()
    assert (finding["kind"], finding["state"], finding["count"], finding["pull"]) == ("copy-differs", "open", 1, pull)
    (first,) = finding["detail"]["first"]
    assert first["ts"] == OPEN + 7 * 60_000 and first["cached"][3] == was and first["stored"][3] == other
    assert said == ["audit fake:AAA: 60 bars of 2 cache files, 1 are stored with other values (kept as stored; asked of "
                    "the feed again)"]
    assert store.cache_bytes() == 0 and store.cache_bytes(unverified_only=False) > 0  # kept, and not counted by the cap


def test_a_bar_the_cache_has_and_the_database_has_not_is_put_in_from_the_cache(store):
    pull = _pull_of(store, _minutes(60))
    before = _stored(store)
    conn = store._bars("fake")
    with conn:
        conn.execute("DELETE FROM bars WHERE ts IN (?, ?)", (OPEN, OPEN + 59 * 60_000))
    got = auditing.audit_pull(store, pull)
    assert (got.result, got.missing, got.differing) == ("repaired", 2, 0) and sum(f.repaired for f in got.files) == 2
    assert _stored(store) == before and _cache_files(store) == []  # as the feed sent it again, and the files gone
    (finding,) = store.findings()
    assert (finding["kind"], finding["state"], finding["count"]) == ("copy-missing", "repaired", 2)
    assert finding["detail"]["repaired"] == 2 and [f["ts"] for f in finding["detail"]["first"]] == [OPEN, OPEN + 59 * 60_000]


def test_told_to_flag_only_the_auditor_puts_nothing_in(store):
    pull = _pull_of(store, _minutes(10))
    conn = store._bars("fake")
    with conn:
        conn.execute("DELETE FROM bars WHERE ts=?", (OPEN,))
    got = auditing.audit_pull(store, pull, auditing.Policy(repair=False))
    assert (got.result, got.missing) == ("mismatch", 1) and len(_stored(store)) == 9 and len(_cache_files(store)) == 1
    assert [(f["kind"], f["state"]) for f in store.findings()] == [("copy-missing", "open")]


def test_a_bar_a_later_pull_rewrote_passes_with_the_older_value_kept_as_replaced(store, monkeypatch):
    clock = iter(range(1_000_000, 2_000_000, 1000))
    monkeypatch.setattr(feeds, "_stored_ms", lambda: next(clock))
    first = _pull_of(store, _minutes(5, price=10.0))
    second = _pull_of(store, _minutes(5, price=11.0))  # a correction: every bar another value
    assert [r[1] for r in _stored(store)][0] == 11.0
    a, b = auditing.audit_pull(store, first), auditing.audit_pull(store, second)
    assert (a.result, a.differing, sum(f.replaced for f in a.files)) == ("ok", 0, 5)
    assert (b.result, b.differing, b.rows) == ("ok", 0, 5) and store.findings() == []


def test_a_value_changed_without_a_later_write_is_not_taken_for_a_correction(store, monkeypatch):
    # the bar is stored under the moment the pull stored it, and yet holds another value: nobody's later write
    clock = iter(range(1_000_000, 2_000_000, 1000))
    monkeypatch.setattr(feeds, "_stored_ms", lambda: next(clock))
    pull = _pull_of(store, _minutes(5))
    conn = store._bars("fake")
    with conn:  # (the update's trigger keeps the old version as replaced at that same moment)
        conn.execute("UPDATE bars SET volume=volume+1 WHERE ts=?", (OPEN,))
    assert conn.execute("SELECT COUNT(*) FROM bar_revisions").fetchone()[0] == 1
    got = auditing.audit_pull(store, pull)
    assert (got.result, got.differing) == ("mismatch", 1)


def test_a_bar_moved_out_as_another_instruments_is_left_where_it_is(store):
    pull = _pull_of(store, _minutes(10))
    assert store.archive_before("fake", "AAA", reason="another company's") == 10 and _stored(store) == []
    got = auditing.audit_pull(store, pull)
    assert (got.result, got.missing, sum(f.moved for f in got.files)) == ("ok", 0, 10) and _stored(store) == []
    assert store.findings() == []


def test_a_cache_file_that_is_not_what_was_written_is_said_and_kept(store):
    pull = _pull_of(store, _minutes(10))
    (f,) = store.pull_files(pull)
    path = store.pull_folder(pull) / f["name"]
    header, rows, _ = spool.read_rows(path)
    spool.write_rows(path.parent, path.name, header, [[*r[:4], 0.0, *r[5:]] for r in rows])  # another text under its name
    got = auditing.audit_pull(store, pull)
    assert got.result == "mismatch" and [x.result for x in got.files] == ["damaged"] and got.differing == 0
    assert "sha256" in got.files[0].why and path.exists()
    (finding,) = store.findings()
    assert (finding["kind"], finding["count"]) == ("cache-file", 1) and len(_stored(store)) == 10  # the bars untouched


def test_a_verified_pulls_files_are_kept_the_days_the_policy_says(store):
    keep = auditing.Policy(keep_days=1)
    pull = _pull_of(store, _minutes(10))
    got = auditing.audit_pull(store, pull, keep)
    assert got.result == "ok" and got.removed == 0 and len(_cache_files(store)) == 1
    assert store.cache_bytes() == 0 and store.cache_bytes(unverified_only=False) > 0  # verified: not the cap's to count
    now = datetime.now(timezone.utc)
    assert auditing.tidy(store, keep, now + timedelta(hours=12)) == {"removed": 0, "forgotten": 0}
    assert auditing.tidy(store, keep, now + timedelta(days=2)) == {"removed": 1, "forgotten": 0} and _cache_files(store) == []
    assert store.pull(pull)["audit"] == "ok" and not store.pull_folder(pull).exists()  # in the ledger still, for its page
    assert auditing.tidy(store, keep, now + timedelta(days=1 + auditing.FORGET_DAYS)) == {"removed": 0, "forgotten": 1}
    assert store.pull(pull) is None and store.pull_files(pull) == []


def test_an_open_pull_is_not_audited_and_a_process_that_reads_only_audits_nothing(store):
    p = store.pull_open("fake", "bars", ticker="AAA", timespan="minute")
    with spool.opened(p):
        store.upsert_bars("fake", "AAA", "minute", 1, _minutes(3))
        assert auditing.audit_pull(store, p.id) is None and auditing.audit_pulls(store) == []
    p.close()
    set_read_only(True)
    assert auditing.audit_pull(store, p.id) is None and auditing.audit_pulls(store) == []
    set_read_only(False)
    assert auditing.audit_pull(store, p.id).result == "ok"


def test_the_summary_says_the_cache_by_state(store):
    done = _pull_of(store, _minutes(10))
    auditing.audit_pull(store, done, auditing.Policy(keep_days=1))
    _pull_of(store, _minutes(20), ticker="BBB")
    rows = {(r["state"], r["audit"]): r for r in store.cache_summary()}
    assert set(rows) == {("complete", "ok"), ("complete", None)}
    assert (rows["complete", None]["pulls"], rows["complete", None]["files"], rows["complete", None]["rows"]) == (1, 1, 20)
    assert rows["complete", "ok"]["rows"] == 10 and rows["complete", "ok"]["bytes"] > 0


# -- what a run that is gone left --------------------------------------------------------------------------------------
def _left_open(store, bars, loaded: bool) -> pulls.Pull:
    """A pull as a run that died left it: open, a rows file written, its rows in the database or not."""
    p = store.pull_open("fake", "bars", ticker="AAA", asset="stock", timespan="minute", start_ms=OPEN, end_ms=CLOSE)
    stored = feeds._stored_ms()
    rows = feeds._ascending([feeds._bar_row("AAA", "minute", 1, b, stored) for b in bars])
    back, seq = p.rows("fake", rows, stored)
    if loaded:
        conn = store._feed("fake", create=True).conn
        with conn:
            conn.executemany(feeds._UPSERT_BAR, back)
        p.loaded(seq)
    return p


def test_a_pull_written_and_not_loaded_is_loaded_later_without_asking_the_feed_again(store):
    p = _left_open(store, _minutes(30), loaded=False)
    assert _stored(store) == [] and store.pull(p.id)["state"] == "open"
    said: list[str] = []
    assert auditing.recover(store, "fake", said.append) == 1
    assert len(_stored(store)) == 30  # from the cache: no feed was there to ask
    row = store.pull(p.id)
    assert row["state"] == "cut" and row["note"] == "its run ended without closing it; 1 cache files loaded since"
    assert store.coverage("AAA", "minute")["fake"] == [(OPEN, OPEN + 30 * 60_000)]  # held: not asked for again
    assert said == ["cache fake:AAA: a pull left open by a run that is gone was closed, 1 of its cache files loaded "
                    "without asking the feed again"]
    assert auditing.audit_pull(store, p.id).result == "ok" and _cache_files(store) == []
    assert auditing.recover(store, "fake") == 0


def test_a_rows_file_the_ledger_never_heard_of_is_entered_and_loaded(store):
    p = _left_open(store, _minutes(5), loaded=False)
    with store.conn:  # the run ended between the file and its row
        store.conn.execute("DELETE FROM pull_files WHERE pull=?", (p.id,))
    assert auditing.recover(store) == 1 and len(_stored(store)) == 5
    (f,) = store.pull_files(p.id)
    assert (f["seq"], f["rows"], f["feed"], f["lo_ms"]) == (1, 5, "fake", OPEN) and f["loaded_at"]


def test_a_pull_whose_process_is_at_work_is_left_to_it(store, monkeypatch):
    p = _left_open(store, _minutes(5), loaded=False)
    monkeypatch.setattr(claims, "gone", lambda conn, owners, **kw: set())  # its owner answers
    assert auditing.recover(store, "fake") == 0 and store.pull(p.id)["state"] == "open" and _stored(store) == []


def test_a_cut_pulls_unloaded_file_is_loaded_by_its_audit(store):
    p = _left_open(store, _minutes(5), loaded=False)
    p.close("cut", "the database was busy")
    got = auditing.audit_pull(store, p.id)
    assert (got.result, got.loaded_late, got.rows) == ("ok", 1, 5) and len(_stored(store)) == 5


# -- the collector -----------------------------------------------------------------------------------------------------
class Feed(DataSource):
    """A feed that answers a series' bars in pages, and can stop after some."""

    name = "fake"

    def __init__(self, pages: list[list[dict]], stop_after: int | None = None):
        self.pages, self.stop_after, self.asked = pages, stop_after, 0

    @property
    def requests_made(self) -> int:
        return self.asked

    def bar_pages(self, ticker, start, end, timespan, multiplier=1, descending=False, asset="stock"):
        for i, page in enumerate(self.pages):
            if self.stop_after is not None and i >= self.stop_after:
                raise BudgetExhausted("request cap of 1 reached")
            self.asked += 1
            yield list(page)

    def is_entitled(self, resolution, ticker, asset="stock"):
        return True

    def trade_pages(self, *a, **k):
        raise AssertionError("no ticks are fetched for history")

    def exchanges(self):
        return []

    def instrument(self, ticker, resolve_exchange=True):
        raise AssertionError("no listing is looked up here")


def _fill(store, source, **kw):
    return collector._fill(source, store, "AAA", "minute", OPEN, CLOSE, "AAA", "stock", False, False, **kw)


def test_a_gap_filled_is_one_pull_audited_as_it_closes(store):
    pages = [_minutes(40, OPEN + 80 * 60_000), _minutes(40, OPEN + 40 * 60_000), _minutes(40)]  # newest first
    saved, newest = _fill(store, Feed(pages))
    assert (saved, newest) == (120, OPEN + 119 * 60_000) and len(_stored(store)) == 120
    (row,) = store.pulls()
    assert (row["kind"], row["state"], row["audit"], row["ticker"], row["timespan"]) == ("bars", "complete", "ok", "AAA", "minute")
    assert (row["start_ms"], row["end_ms"]) == (OPEN, CLOSE)
    assert [f["result"] for f in store.pull_files(row["id"])] == ["ok"] * 3 and _cache_files(store) == []
    assert store.coverage("AAA", "minute")["fake"] == [(OPEN, CLOSE)] and store.findings() == []


def test_a_gap_cut_off_by_the_cap_is_known_to_be_a_fragment_and_what_it_loaded_is_audited(store):
    with pytest.raises(StopRun, match="request cap reached"):
        _fill(store, Feed([_minutes(40, OPEN + 80 * 60_000), _minutes(40, OPEN + 40 * 60_000)], stop_after=1))
    (row,) = store.pulls()
    assert (row["state"], row["audit"]) == ("cut", "ok") and row["note"].startswith("StopRun: request cap reached")
    assert len(_stored(store)) == 40 and _cache_files(store) == []


def test_with_auditing_on_update_off_a_pull_waits_for_its_auditor(store):
    auditing.set_policy(auditing.Policy(on_update=False))
    _fill(store, Feed([_minutes(10)]))
    (row,) = store.pulls()
    assert (row["state"], row["audit"]) == ("complete", None) and len(_cache_files(store)) == 1
    assert [a.result for a in auditing.audit_pulls(store, feed="fake", ticker="AAA")] == ["ok"] and _cache_files(store) == []


def test_a_cache_that_cannot_be_written_stops_the_run_without_a_strike(store, monkeypatch):
    def full(folder, name, header, rows):
        raise spool.CacheFailed("the fetch cache could not be written (the disk is full)")

    monkeypatch.setattr(spool, "write_rows", full)
    with pytest.raises(StopRun, match="disk is full") as stopped:
        _fill(store, Feed([_minutes(10)]))
    assert stopped.value.strike is False and _stored(store) == []  # nothing reached the database unseen by the cache


def test_at_its_cap_the_cache_is_audited_at_once_and_fetching_waits_if_that_frees_too_little(store, monkeypatch):
    auditing.set_policy(auditing.Policy(on_update=False, cap_gb=5))
    waiting = _pull_of(store, _minutes(10), ticker="BBB")
    sizes = iter([6 * 2**30, 0])  # over the cap; then, what waited audited, under it
    monkeypatch.setattr(store, "cache_bytes", lambda unverified_only=True: next(sizes))
    _fill(store, Feed([_minutes(5)]))
    assert store.pull(waiting)["audit"] == "ok"  # audited at once, to make room
    monkeypatch.setattr(store, "cache_bytes", lambda unverified_only=True: 6 * 2**30)
    with pytest.raises(StopRun, match=r"6\.0 GB not audited yet \(its cap: 5 GB\): fetching waits for the auditors") as full:
        _fill(store, Feed([_minutes(5)]))
    assert full.value.strike is False


def test_a_run_settles_what_earlier_runs_left_before_it_asks_anything(store):
    from liminal_libs.collector import Collector
    from liminal_libs.config import Tier

    p = _left_open(store, _minutes(8), loaded=False)
    said: list[str] = []
    c = Collector(Feed([]), store, Tier("free", requests_per_minute=5, history_years=2), log=said.append)
    c.only = {"ZZZ"}  # (a run for chosen symbols settles the cache too)
    c._before_symbols()
    assert len(_stored(store)) == 8 and store.pull(p.id)["audit"] == "ok" and _cache_files(store) == []
    assert any("left open by a run that is gone" in line for line in said)


# -- the policy --------------------------------------------------------------------------------------------------------
def test_the_policy_is_the_options_each_one_of_its_choices():
    assert auditing.Policy.of({}) == auditing.Policy() == auditing.Policy.of(None)
    assert auditing.Policy() == auditing.Policy(on_update=True, sweep_hours=24.0, sweep_minutes=10, repair=True,
                                                keep_days=0, cap_gb=20, repulls=5)
    assert {name: choices[0] for name, choices in auditing.CHOICES.items()} == {
        "AUDITOR_ON_UPDATE": "on", "AUDITOR_SWEEP_EVERY": "24h", "AUDITOR_SWEEP_MINUTES": "10",
        "AUDITOR_ON_MISMATCH": "repair", "AUDITOR_KEEP_DAYS": "0", "AUDITOR_CACHE_GB": "20", "AUDITOR_REPULLS": "5"}
    assert set(auditing.ABOUT) == set(auditing.CHOICES)
    got = auditing.Policy.of({"AUDITOR_ON_UPDATE": " OFF ", "AUDITOR_SWEEP_EVERY": "7d", "AUDITOR_SWEEP_MINUTES": "60",
                              "AUDITOR_ON_MISMATCH": "flag", "AUDITOR_KEEP_DAYS": "30", "AUDITOR_CACHE_GB": "100",
                              "AUDITOR_REPULLS": "0", "SOMETHING_ELSE": "x"})
    assert got == auditing.Policy(False, 168.0, 60, False, 30, 100, 0)
    assert auditing.Policy.of({"AUDITOR_SWEEP_EVERY": "off"}).sweep_hours is None
    for name, choices in auditing.CHOICES.items():
        for value in choices:
            auditing.Policy.of({name: value})
        with pytest.raises(ValueError, match=f"{name}='nonsense': one of {', '.join(choices)}"):
            auditing.Policy.of({name: "nonsense"})
    assert json.dumps(got.as_dict())  # (a page's)


def test_the_processs_policy_is_set_once_and_the_defaults_stand_without_a_plugin():
    class Settings:
        def __init__(self, own):
            self.own = own

        def plugin(self, name):
            return self.own if name == "auditor" else None

    mine = auditing.Policy(keep_days=7)
    assert auditing.policy_of(Settings(mine)) is mine
    assert auditing.policy_of(Settings(None)) == auditing.Policy() == auditing.policy_of(None)  # no plugin: the defaults
    assert auditing.policy_of(Settings("not a policy")) == auditing.Policy()
    auditing.set_policy(mine)
    assert auditing.policy() is mine
    auditing.set_policy(None)
    assert auditing.policy() == auditing.Policy()
