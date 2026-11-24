"""The review of 2026-11-21, Monday list item 4 (1.81.0): five faults in the library, each pinned by a test that
fails on 1.80.0. The audit queue widens a waiting span, never replaces it (1); an audit that could not run stays
queued, one with nothing to compare is recorded (2); a feed's quality is built from every ticker judged (3); the
daily cap is asked before the rate window (4); a dataset file is never found cut off under its name (5). Nothing
here starts a process or reaches the network: every feed and session is a stand-in."""
from __future__ import annotations

import builtins
import io
import random
from datetime import datetime
from types import SimpleNamespace

import pytest

from liminal_libs import audit, composite, datasets
from liminal_libs.config import Tier
from liminal_libs.coverage import FeedProfile, ms
from liminal_libs.errors import BudgetExhausted, Paused
from liminal_libs.ratelimit import RateLimiter
from liminal_libs.sessions import ET
from liminal_libs.sources.http import HttpClient
from liminal_libs.storage import Store

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=ET)  # a Wednesday, midday
PLAN = Tier("free", requests_per_minute=5, history_years=2)
QUIET = lambda *_: None  # noqa: E731


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "liminal.db") as s:
        yield s


# -- 1: the queue widens -----------------------------------------------------------------------------------------------

def test_a_span_queued_while_another_waits_widens_it_and_never_narrows_it(store):
    day = 86_400_000
    store.queue_audit("AAA", "minute", 10 * day, 12 * day, "massive")
    store.queue_audit("AAA", "minute", 11 * day, 11 * day + 3_600_000, "massive")  # narrower, inside: it stays as wide
    store.queue_audit("AAA", "minute", 20 * day, 21 * day, "massive")  # later: both covered
    (q,) = store.audit_queue()
    assert (q["start_ms"], q["end_ms"]) == (10 * day, 21 * day)
    store.queue_audit("AAA", "minute", 5 * day, 6 * day, "massive")  # earlier, a backfill
    (q,) = store.audit_queue()
    assert (q["start_ms"], q["end_ms"]) == (5 * day, 21 * day)
    store.queue_audit("AAA", "minute", 1 * day, 2 * day, "alpaca")  # still one entry per series and owner
    store.queue_audit("AAA", "day", 1 * day, 2 * day, "massive")
    assert store.audit_queue_count() == 3
    # taken off only while it is the span audited: one widened meanwhile waits on
    store.dequeue_audit("AAA", "minute", 5 * day, "massive", 20 * day)
    assert store.audit_queue_count() == 3
    store.dequeue_audit("AAA", "minute", 5 * day, "massive", 21 * day)
    assert store.audit_queue_count() == 2


def _auditor(store, monkeypatch, answer):
    audited: list[tuple] = []
    monkeypatch.setattr(audit, "audit_span", lambda *a, **k: audited.append(a) or answer)
    feeds = {"massive": FeedProfile("massive", PLAN, frozenset({"stock"}), 0, venues={"stock": "sip"}),
             "fake": FeedProfile("fake", PLAN, frozenset({"stock"}), 1, venues={"stock": "sip"})}
    store.watch("massive", ["AAA", "BBB"], "minute")
    store.watch("fake", ["AAA", "BBB"], "minute")
    source = SimpleNamespace(name="fake", requests_made=0, serves=lambda asset: True)
    return audit.Auditor(source, store, feeds["fake"], feeds, NOW, log=QUIET, rng=random.Random(1)), audited


def test_a_widened_span_reaching_below_the_floor_is_audited_from_the_floor_up(store, monkeypatch):
    auditor, audited = _auditor(store, monkeypatch, {"verdict": "pass"})
    lo, _ = auditor.window("stock", "minute")
    a, b = ms(datetime(2026, 10, 13, tzinfo=ET)), ms(datetime(2026, 10, 14, tzinfo=ET))
    store.queue_audit("AAA", "minute", lo - 30 * 86_400_000, lo - 29 * 86_400_000, "massive")  # an old backfill
    store.queue_audit("AAA", "minute", a, b, "massive")  # this week's download: the entry now reaches below the floor
    assert auditor.run(queued=2, random_count=0) == 1
    (args,) = audited
    assert lo <= args[4] < args[5] <= b and store.audit_queue() == []


# -- 2: an audit that could not run stays queued -------------------------------------------------------------------------

def test_an_audit_that_could_not_run_stays_queued_and_counts_as_a_try(store, monkeypatch):
    auditor, audited = _auditor(store, monkeypatch, None)  # audit_span's None: the feed refused or did not answer
    a, b = ms(datetime(2026, 10, 13, tzinfo=ET)), ms(datetime(2026, 10, 14, tzinfo=ET))
    store.queue_audit("AAA", "minute", a, b, "massive")
    store.queue_audit("BBB", "minute", a, b, "massive")
    assert auditor.run(queued=1, random_count=0) == 0  # nothing audited
    assert len(audited) == 1  # one try, as `queued` allows
    assert store.audit_queue_count() == 2  # both wait for the next pass
    # one the second feed had nothing for is a result (saved as no-data by audit_span) and leaves the queue
    auditor2, audited2 = _auditor(store, monkeypatch, {"verdict": "no-data"})
    assert auditor2.run(queued=2, random_count=0) == 2 and store.audit_queue_count() == 0


def test_audit_span_returns_none_only_when_it_could_not_run_and_a_no_data_verdict_is_saved(store):
    from liminal_libs.errors import SourceError

    store.watch("fake", ["AAA"], "minute")

    class Feed:
        name = "fake"

        def __init__(self, pages):
            self.pages = pages

        def bar_pages(self, *a, **k):
            if isinstance(self.pages, Exception):
                raise self.pages
            yield from self.pages

    a, b = ms(datetime(2026, 10, 13, 10, tzinfo=ET)), ms(datetime(2026, 10, 13, 11, tzinfo=ET))
    assert audit.audit_span(Feed(SourceError(0, "no answer")), store, "AAA", "minute", a, b, "massive", "x", QUIET) is None
    got = audit.audit_span(Feed([[]]), store, "AAA", "minute", a, b, "massive", "x", QUIET)
    assert got is not None and got["verdict"] == "no-data" and store.audits()[0]["verdict"] == "no-data"


# -- 3: a feed's quality from every ticker judged ------------------------------------------------------------------------

def _stats(close_bps, bars):
    return {"closeBps": close_bps, "highBps": close_bps, "lowBps": close_bps, "outlierShare": 0.0,
            "completeness": 1.0, "bars": bars}


def test_a_feeds_quality_is_the_bar_weighted_mean_of_its_tickers_never_one_tickers_alone(store):
    good, bad = _stats(0.0, 3000), _stats(20.0, 1000)
    composite.feed_quality(store, "coinbase", "crypto", "BTC-USD", good)
    composite.feed_quality(store, "coinbase", "crypto", "ETH-USD", bad)  # the last one judged
    q = store.quality("coinbase", "crypto")
    want = round((composite.score(good) * 3000 + composite.score(bad) * 1000) / 4000, 4)
    assert q["score"] == pytest.approx(want) and q["score"] > composite.score(bad) + 0.3
    assert set(q["details"]["tickers"]) == {"BTC-USD", "ETH-USD"}  # each ticker's stats and score kept
    assert q["details"]["tickers"]["ETH-USD"]["score"] == composite.score(bad)
    composite.feed_quality(store, "coinbase", "crypto", "ETH-USD", good)  # a ticker judged again replaces its own
    assert store.quality("coinbase", "crypto")["score"] == composite.score(good)


def test_refresh_writes_the_feeds_quality_through_feed_quality():
    import inspect

    text = inspect.getsource(composite.refresh)
    assert "feed_quality(store, f, asset, ticker, stats[v], derivation)" in text and "set_quality" not in text


# -- 4: the daily cap before the window ----------------------------------------------------------------------------------

class _Answer:
    status_code, headers, content, text = 200, {}, b"{}", "{}"

    def json(self):
        return {}


class _Session:
    def __init__(self):
        self.calls = 0

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls += 1
        return _Answer()


def test_a_request_the_daily_cap_refuses_takes_no_place_in_the_window():
    clock = [1000.0]
    limiter = RateLimiter(2, 60.0, clock=lambda: clock[0], sleep=lambda s: None)
    session = _Session()
    client = HttpClient("https://x.example", rate_limiter=limiter, session=session, sleep=lambda s: None)
    client.take_day = lambda: False
    with pytest.raises(BudgetExhausted):
        client.get("/v1/bars")
    assert len(limiter._calls) == 0 and session.calls == 0  # no place taken, nothing sent
    client.take_day = lambda: True
    client.get("/v1/bars")
    assert len(limiter._calls) == 1 and session.calls == 1


def test_a_request_counted_for_the_day_and_paused_in_the_windows_wait_is_given_back():
    day, given = [], []
    limiter = RateLimiter(5, 60.0, clock=lambda: 1000.0, sleep=lambda s: None)
    client = HttpClient("https://x.example", rate_limiter=limiter, session=_Session(), sleep=lambda s: None)
    client.take_day = lambda: day.append(1) or True
    client.give_day = lambda: given.append(1)
    asked = iter([None, "paused by the user"])  # before the window, then after its wait
    client.should_stop = lambda: next(asked)
    with pytest.raises(Paused):
        client.get("/v1/bars")
    assert day == [1] and given == [1] and client.requests_made == 0


# -- 5: a dataset file kept whole or not at all -------------------------------------------------------------------------

def _keep_args(tmp_path):
    data = tmp_path / "data"
    (data / "datasets").mkdir(parents=True)
    return SimpleNamespace(datasets_dir=data / "datasets"), SimpleNamespace(provider="cftc")


def test_a_dataset_file_cut_off_by_a_crash_is_never_left_under_its_name(tmp_path, monkeypatch):
    store, ds = _keep_args(tmp_path)
    blob = b"x" * 10_000
    real_open, real_io_open = builtins.open, io.open

    class Cut(io.BufferedWriter):
        def write(self, b):
            super().write(bytes(b)[:100])
            self.flush()
            raise OSError("the machine went down")

    def cutting(opener):
        def stand_in(file, mode="r", *a, **k):
            if "w" in mode and "cftc" in str(file):
                return Cut(io.FileIO(file, "wb"))
            return opener(file, mode, *a, **k)
        return stand_in

    monkeypatch.setattr(builtins, "open", cutting(real_open))
    monkeypatch.setattr(io, "open", cutting(real_io_open))
    with pytest.raises(OSError):
        datasets._keep(store, ds, "f.csv", blob, "ab" * 32)
    monkeypatch.undo()
    dest = store.datasets_dir.parent / datasets.downloads("cftc") / f"f.{'ab' * 6}.csv"
    assert not dest.exists()  # no file under its finished name: never one cut off
    assert datasets._keep(store, ds, "f.csv", blob, "ab" * 32) == dest and dest.read_bytes() == blob


def test_a_dataset_file_cut_off_before_is_written_again_whole(tmp_path):
    store, ds = _keep_args(tmp_path)
    blob = b"y" * 5000
    dest = store.datasets_dir.parent / datasets.downloads("cftc") / f"g.{'cd' * 6}.csv"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(blob[:100])  # what write_bytes left when the process died
    assert datasets._keep(store, ds, "g.csv", blob, "cd" * 32) == dest and dest.read_bytes() == blob
    assert [p.name for p in dest.parent.iterdir()] == [dest.name]  # no part file left beside it
