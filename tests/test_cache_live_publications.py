"""The live recorder and the publishers through the fetch cache (1.82.0; Monday list item 5).

The recorder's trades go to a trades file of its stream's minute pull before the tick file, and the copy audit holds
them against the tick file when the minute is over; a publisher's answer goes to a pull's folder, is parsed from
there, and stays until its items are read back as they were parsed. Stand-ins only: no stream, no socket, no feed."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from liminal_libs import auditing, gov, live, provenance, publications, spool
from liminal_libs.sources.publisher import Feed, Policy, Publisher
from liminal_libs.storage import Store, pulls

pytestmark = pytest.mark.usefixtures("no_outside")

MINUTE = 29_000_000  # a minute's number (ms // 60,000): 2025-02-20 ...
T0 = MINUTE * 60_000  # its first ms
QUIET = lambda *_: None  # noqa: E731


@pytest.fixture(autouse=True)
def the_defaults(monkeypatch):
    monkeypatch.delenv(pulls.SWITCH, raising=False)
    monkeypatch.setattr(pulls, "_pause", lambda *_: None)
    monkeypatch.setattr(provenance, "code_version", lambda: "test")  # (git is not asked)
    auditing.set_policy(None)
    yield
    auditing.set_policy(None)


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data" / "liminal.db", ticks=True) as s:
        yield s


def _cache_files(store) -> list[str]:
    folder = pulls.cache_dir(store)
    return sorted(p.name for p in folder.rglob("*") if p.is_file()) if folder.is_dir() else []


def _trade(i: int, price: float = 100.0, at_ms: int = T0 + 1_000) -> dict:
    return {"sip_timestamp": (at_ms + i) * 1_000_000 + 7, "sequence_number": 0, "price": price + i * 0.25,
            "size": 0.5 + i, "exchange": None, "conditions": [], "id": f"t{i}", "tape": None}


def _recorder(tmp_path, said: list) -> live.Recorder:
    rec = live.Recorder(tmp_path / "data" / "liminal.db", coins=(), sources=(), log=said.append)
    rec.streams = [SimpleNamespace(source="coinbase", asset="crypto", url="wss://stand-in", dynamic=False,
                                   tape_rules=False)]
    rec._status = {"coinbase": {"connected": True, "pairs": {}}}
    return rec


def _stored_trades(store) -> list[tuple]:
    return store._ticks("coinbase").execute(
        "SELECT ticker, ts_ns, seq, price, size, exchange, conditions, trade_id, tape FROM ticks.trades ORDER BY ts_ns"
    ).fetchall()


# -- the recorder ------------------------------------------------------------------------------------------------------
def test_a_flush_writes_its_trades_through_a_trades_file_and_the_minutes_audit_passes_and_removes_it(store, tmp_path):
    said: list[str] = []
    rec = _recorder(tmp_path, said)
    rec._buffer[("coinbase", "BTCUSD")] = [_trade(i) for i in range(5)]
    assert rec.flush(store, now_ms=T0 + 2_000) == 5
    (row,) = store.pulls()
    assert (row["kind"], row["feed"], row["state"], row["timespan"]) == ("live", "coinbase", "open", "trades")
    (f,) = store.pull_files(row["id"])
    assert (f["kind"], f["rows"], f["loaded_at"] is not None) == ("trades", 5, True)
    header, rows, digest = spool.read_rows(store.pull_folder(row) / f["name"])
    assert header["table"] == "trades" and header["columns"] == list(pulls.TRADE_COLUMNS) and digest == f["sha256"]
    assert [tuple(r) for r in rows] == _stored_trades(store)  # what the tick file holds is what the file holds

    rec._buffer[("coinbase", "BTCUSD")] = [_trade(9, at_ms=T0 + 3_000)]
    rec.flush(store, now_ms=T0 + 4_000)  # the same minute: the same pull, a second file
    assert [p["id"] for p in store.pulls()] == [row["id"]] and len(store.pull_files(row["id"])) == 2

    rec.flush(store, now_ms=T0 + 60_000)  # the next minute: the last one's pull closed and audited
    assert store.pulls() == [] and _cache_files(store) == []  # verified, its files gone, forgotten at once
    assert store.cache_verified()["pulls"] == 1 and store.cache_verified()["rows"] == 6
    assert len(_stored_trades(store)) == 6 and store.findings() == []


def test_a_trade_stored_otherwise_than_its_file_is_a_finding_and_one_lost_is_put_back(store, tmp_path):
    rec = _recorder(tmp_path, [])
    rec._buffer[("coinbase", "BTCUSD")] = [_trade(i) for i in range(4)]
    rec.flush(store, now_ms=T0 + 2_000)
    (row,) = store.pulls()
    conn = store._ticks("coinbase")
    first, second = _stored_trades(store)[:2]
    with conn:
        conn.execute("UPDATE ticks.trades SET price=price+0.01 WHERE ts_ns=?", (first[1],))  # one bit of it
        conn.execute("DELETE FROM ticks.trades WHERE ts_ns=?", (second[1],))
    rec.end_pulls(store)
    kept = store.pull(row["id"])
    assert kept["audit"] == "mismatch" and _cache_files(store)  # its files kept as the evidence
    kinds = {f["kind"]: f for f in store.findings()}
    assert kinds["copy-differs"]["count"] == 1 and kinds["copy-differs"]["timespan"] == "trades"
    assert kinds["copy-missing"]["state"] == "repaired"
    assert second in _stored_trades(store)  # put back from the file
    assert [t for t in _stored_trades(store) if t[1] == first[1]][0][3] == pytest.approx(first[3] + 0.01)  # untouched


def test_a_flush_cut_off_leaves_a_pull_the_next_start_recovers_without_asking_anything_again(store, tmp_path,
                                                                                              monkeypatch):
    real = pulls.Pull.rows

    def then_the_machine_goes_off(self, *args, **kw):
        real(self, *args, **kw)  # the trades file is written ...
        raise RuntimeError("the machine went off")  # ... and nothing reaches the tick file

    monkeypatch.setattr(pulls.Pull, "rows", then_the_machine_goes_off)
    rec = _recorder(tmp_path, [])
    rec._buffer[("coinbase", "BTCUSD")] = [_trade(i) for i in range(3)]
    with pytest.raises(RuntimeError):
        rec.flush(store, now_ms=T0 + 2_000)
    monkeypatch.setattr(pulls.Pull, "rows", real)
    (row,) = store.pulls()
    assert row["state"] == "open" and _stored_trades(store) == []
    with pulls._live_lock:
        pulls._live.discard(row["id"])  # (its process is gone: no thread of this one is in it)

    said: list[str] = []
    again = _recorder(tmp_path, said)  # the next start: no stream is asked for anything
    again.settle_cache(store)
    assert len(_stored_trades(store)) == 3  # from the cache
    row = store.pull(row["id"])
    assert row["state"] == "cut" and row["audit"] == "ok" and _cache_files(store) == []
    assert any("loaded without asking the feed again" in s for s in said)


def test_a_cache_at_its_cap_never_stops_the_recorder(store, tmp_path, monkeypatch):
    monkeypatch.setattr(auditing, "_over", lambda *_: "the fetch cache is at its cap")
    said: list[str] = []
    rec = _recorder(tmp_path, said)
    rec._buffer[("coinbase", "BTCUSD")] = [_trade(i) for i in range(2)]
    assert rec.flush(store, now_ms=T0 + 2_000) == 2 and len(_stored_trades(store)) == 2
    assert store.pulls() == [] and any("without the fetch cache this minute" in s for s in said)


# -- the publishers ----------------------------------------------------------------------------------------------------
RSS = (b'<?xml version="1.0"?><rss><channel>'
       b'<item><title>Rates held</title><link>https://example.gov/a</link><guid>a1</guid></item>'
       b'<item><title>Minutes out</title><link>https://example.gov/b</link><guid>b2</guid></item>'
       b'</channel></rss>')
NOW = datetime(2026, 11, 24, 15, 0, tzinfo=timezone.utc)


class Answer:
    status_code = 200
    headers = {"Content-Type": "application/rss+xml"}

    def __init__(self, body: bytes):
        self.content = body


class Session:
    def __init__(self):
        self.asked: list[str] = []

    def get(self, url, **kw):
        self.asked.append(url)
        return Answer(RSS)


def _reader(store, seen: list | None = None):
    def parse(r, feed):
        if seen is not None:  # where the answer is while it is parsed
            pull = spool.current()
            seen.append((pull, sorted(p.name for p in pull.folder.iterdir()) if pull and pull.made else [],
                         spool.read_payload(next(pull.folder.glob("*" + spool.PAYLOAD_SUFFIX))) if pull and pull.made
                         else None, r.content))
        return publications.parse_rss(r.content, feed)

    feed = Feed(key="test-press", agency="Test", title="Press", url="https://example.gov/feed.xml", parse=parse)
    pub = Publisher(name="testpub", title="Test agency", about="", feeds=(feed,), policy=Policy(hosts=("example.gov",)))
    gdb = gov.open_db(store.path)
    gdb.robots_set("example.gov", NOW, 404, "")  # (read already: no robots.txt is asked)
    return publications.Reader(gdb, store=store, session=Session(), log=QUIET), pub, feed, gdb


def test_a_publishers_answer_lands_in_the_pull_folder_is_parsed_from_there_and_goes_once_verified(store):
    seen: list = []
    reader, pub, feed, gdb = _reader(store, seen)
    reader._read(pub, feed, NOW)
    ((pull, names, cached, parsed),) = seen
    assert pull is not None and pull.kind == "publication" and pull.feed == "testpub"
    assert names == ["00001" + spool.PAYLOAD_SUFFIX] and cached == RSS and parsed == RSS
    assert {d["id"] for d in gdb.items_held("test-press", ["a1", "b2"]).values()} == {"a1", "b2"}
    assert store.pulls() == [] and _cache_files(store) == []  # read back as parsed: its file gone, forgotten
    gdb.close()


def test_a_publication_stored_otherwise_than_parsed_keeps_its_answer_with_a_finding(store, monkeypatch):
    reader, pub, feed, gdb = _reader(store)
    real = gov.GovDB.save_items

    def misstored(self, source, items, now):
        return real(self, source, [{**it, "title": it["title"] + "?"} if it["id"] == "b2" else it for it in items], now)

    monkeypatch.setattr(gov.GovDB, "save_items", misstored)
    reader._read(pub, feed, NOW)
    (row,) = store.pulls()
    assert (row["kind"], row["state"], row["audit"]) == ("publication", "complete", "mismatch")
    assert _cache_files(store) == ["00001" + spool.PAYLOAD_SUFFIX]  # the answer, kept as the evidence
    (f,) = store.findings()
    assert (f["kind"], f["feed"], f["count"], f["pull"]) == ("document-differs", "testpub", 1, row["id"])
    assert f["detail"] == {"feed": "test-press", "ids": ["b2"]}
    assert auditing.tidy(store)["forgotten"] == 0 and store.pull(row["id"]) is not None  # kept, as a mismatch is
    gdb.close()


def test_an_item_held_already_keeps_its_own_and_is_no_finding(store):
    reader, pub, feed, gdb = _reader(store)
    gdb.save_items("test-press", [{"id": "a1", "agency": "Test", "title": "Rates held (first)", "url": None}], NOW)
    reader._read(pub, feed, NOW)
    assert store.findings() == [] and store.pulls() == []
    gdb.close()


# -- the switch --------------------------------------------------------------------------------------------------------
def test_with_the_switch_off_nothing_is_cached_and_everything_is_written_as_before(store, tmp_path, monkeypatch):
    monkeypatch.setenv(pulls.SWITCH, "off")
    rec = _recorder(tmp_path, [])
    rec._buffer[("coinbase", "BTCUSD")] = [_trade(i) for i in range(3)]
    assert rec.flush(store, now_ms=T0 + 2_000) == 3 and len(_stored_trades(store)) == 3
    rec.end_pulls(store)
    seen: list = []
    reader, pub, feed, gdb = _reader(store, seen)
    reader._read(pub, feed, NOW)
    assert seen[0][0] is not None and not seen[0][0].spools and seen[0][3] == RSS
    assert len(gdb.items_held("test-press", ["a1", "b2"])) == 2
    assert store.pulls() == [] and not pulls.cache_dir(store).exists()
    gdb.close()
