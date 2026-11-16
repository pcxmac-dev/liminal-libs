"""A symbol being fetched is claimed (1.56.0; the user, 2026-11-15: "if one symbol is being operated on, the other
integrator would have to operate on another symbol"): a run takes `symbol:<asset>:<ticker>` round each symbol it
fetches, shared with its installation's other runs and held against every other installation on the database. A symbol
another installation is working on goes back in the run's line and is taken again later; still held ten minutes on, it
is left for the next run. A run taken over while it was silent stores nothing more. The other installation is a
second Claims object on the same file; the clock and the waits are the test's; no process is started."""
from __future__ import annotations

import time
from datetime import date, datetime
from types import SimpleNamespace

import pytest

from liminal_libs import claims, collector
from liminal_libs.claims import GRACE_S, STALE_S, Claims
from liminal_libs.collector import ELSEWHERE, ET, Collector, StopRun
from liminal_libs.coverage import ms
from liminal_libs.storage import Store, common

from test_run_classes import NOW, PLAN, FakeSource, _bar

DAY = ms(datetime(2026, 10, 20, tzinfo=ET))  # Tuesday's session, over by NOW
MINUTE = ms(datetime(2026, 10, 20, 10, 0, tzinfo=ET))
BARS = {"day": [_bar(DAY)], "minute": [_bar(MINUTE)]}


@pytest.fixture(autouse=True)
def nothing_left_held():
    yield
    claims._give_back()
    common.set_read_only(False)


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "liminal.db") as s:
        yield s


@pytest.fixture
def quiet_start(monkeypatch):
    for name in ("sync_exchanges", "refresh_calendars", "market_days", "fetch_market_moves"):
        monkeypatch.setattr(collector, name, lambda *a, **k: 0)


@pytest.fixture
def clock(monkeypatch):
    """The run's clock and its waits: a wait passes at once, and says how long it was."""
    c = SimpleNamespace(now=1000.0, waits=[], on_wait=None)

    def wait(seconds: float) -> None:
        c.waits.append(round(seconds, 3))
        c.now += seconds
        if c.on_wait:
            c.on_wait()

    monkeypatch.setattr(collector, "monotonic", lambda: c.now)
    monkeypatch.setattr(collector, "sleep", wait)
    return c


def _other(store, pid: int = 77, **kw) -> Claims:
    """Another installation on the same database (its processes cannot be looked up from here)."""
    return Claims.open(store.path, me="other::elsewhere", pid=pid, alive=lambda p, s: True, **kw)


class Watching(FakeSource):
    """A feed that notes what this process holds on the database while each request is made."""

    def __init__(self, store, **kw):
        super().__init__(**kw)
        self.store, self.held = store, []

    def bar_pages(self, ticker, *a, **k):
        self.held.append((ticker, sorted(h.key for h in claims.held(self.store.path, claims.SYMBOL) if h.own)))
        yield from super().bar_pages(ticker, *a, **k)


def test_a_symbol_is_claimed_while_it_is_fetched_and_given_back_after(store, quiet_start):
    store.watch("fake", ["AAA", "BBB"], "minute")
    src = Watching(store, bars=BARS)
    log: list[str] = []
    result = Collector(src, store, PLAN, now=NOW, log=log.append).run()
    assert result.rows == 2 and result.stopped is None
    assert src.held and all(held == [f"symbol:stock:{ticker}"] for ticker, held in src.held)  # its own symbol, no other
    assert claims.held(store.path) == [] and claims._process == {}  # given back: nothing stays open
    again = Collector(Watching(store, bars=BARS), store, PLAN, now=NOW, log=log.append)
    assert again.run().skipped == 2 and again.source.held == []  # left alone: nothing claimed, nothing written for it


def test_a_symbol_the_other_installation_is_working_on_is_put_back_and_taken_again_later(store, quiet_start, clock):
    store.watch("fake", ["AAA", "BBB"], "minute")
    other = _other(store)
    try:
        theirs = other.take("symbol:stock:AAA", shared=True, what="massive's run")
        clock.on_wait = lambda: other.release(theirs)  # it finishes with the symbol while this run waits
        src = FakeSource(bars=BARS)
        log: list[str] = []
        c = Collector(src, store, PLAN, now=NOW, log=log.append)
        result = c.run()
        minutes = [t for t, span in src.calls if span == "minute"]
        assert minutes == ["BBB", "AAA"]  # the other symbol first; this one once it was free
        assert clock.waits == [collector.DEFER_MIN_S]  # only it was left: the run waited for its time
        # (the sweep of daily bars left it too: its daily bar comes with its own pass, and is counted there)
        assert result.rows == 3 and result.skipped == 0 and result.stopped is None
        assert store.bar_range("fake", "AAA", "minute") == (MINUTE, MINUTE) and store.bar_range("fake", "AAA", "day") == (DAY, DAY)
        assert store.bar_range("fake", "BBB", "day") == (DAY, DAY)
        said = [m for m in log if "is working on it" in m]
        assert said == ["AAA: other::elsewhere (process 77): massive's run is working on it; taken again later in this run"]
        assert c.deferred == {} and c.waited == {} and c.pending == []
    finally:
        other.close()


def test_a_symbol_still_held_ten_minutes_on_is_left_for_the_next_run(store, quiet_start, clock):
    store.watch("fake", ["AAA"], "minute")
    other = _other(store)
    try:
        other.take("symbol:stock:AAA", shared=True)
        src = FakeSource(bars=BARS)
        log: list[str] = []
        result = Collector(src, store, PLAN, now=NOW, log=log.append).run()
        assert src.calls == [] and result.rows == 0 and result.skipped == 1 and result.stopped is None
        assert clock.waits == [15.0, 30.0, 60.0, 120.0, 120.0, 120.0, 120.0]  # doubling, to two minutes, ten in all
        assert sum(clock.waits) <= collector.DEFER_FOR_S
        assert [m for m in log if "left for the next run" in m] == \
            ["AAA: other::elsewhere (process 77) is still working on it; left for the next run"]
        assert len([m for m in log if "taken again later" in m]) == 1  # said once, not at every try
        assert store.bar_range("fake", "AAA", "minute") is None
    finally:
        other.close()


def test_the_next_symbol_passes_over_those_being_worked_on_elsewhere(store, clock):
    rows = [{"ticker": t, "asset": "stock"} for t in ("AAA", "BBB", "CCC")]
    deferred = {"AAA": clock.now + 30, "BBB": clock.now + 15}
    pending = list(rows)
    assert collector._next_item(pending, store, NOW, "fake", {}, deferred) == (rows[2], False)  # the first that is free
    assert [w["ticker"] for w in pending] == ["AAA", "BBB"] and clock.waits == []
    assert collector._next_item(pending, store, NOW, "fake", {}, deferred) == (rows[1], False)  # only those are left:
    assert clock.waits == [15.0]  # the one whose time comes first, waited for
    clock.now += 20
    assert collector._next_item(pending, store, NOW, "fake", {}, deferred) == (rows[0], False) and clock.waits == [15.0]
    # a symbol opened in the chart waits its time too, and the sweep is not held up for it meanwhile
    store.watch("fake", ["DDD"], "minute")
    collector.request_priority(store, "DDD", NOW)
    row = store.watchlist("fake", "DDD")[0]
    assert collector._unserved_request(store, "fake", NOW, {}) == "DDD"
    assert collector._unserved_request(store, "fake", NOW, {}, {"DDD": clock.now + 60}) is None
    pending = [row, rows[2]]
    assert collector._next_item(pending, store, NOW, "fake", {}, {"DDD": clock.now + 60}) == (rows[2], False)
    clock.now += 61
    item, urgent = collector._next_item(pending, store, NOW, "fake", {}, {"DDD": clock.now - 1})
    assert item["ticker"] == "DDD" and urgent is True  # its time has come: asked for still


def test_a_run_taken_over_while_it_was_silent_stores_nothing_more(store):
    src = FakeSource()
    assert collector._store_bars(store, src, "AAA", "minute", [_bar(MINUTE)], False) == 1  # no claim held: as before
    mine = claims.take(store.path, claims.feed_key("fake"), what="fake's run")
    assert mine is not None and not claims.lost(store.path, "feed:fake")
    assert collector._store_bars(store, src, "AAA", "minute", [_bar(MINUTE + 60_000)], False) == 1
    ahead = [0.0]
    other = _other(store, clock=lambda: time.time() + ahead[0])
    try:  # this computer slept: the other installation found the run silent, asked, waited, and took the feed
        ahead[0] = STALE_S + 1
        assert other.take("feed:fake") is None
        ahead[0] += GRACE_S + 1
        assert other.take("feed:fake") is not None
        with pytest.raises(StopRun, match="taken over by another installation"):
            collector._store_bars(store, src, "AAA", "minute", [_bar(MINUTE + 120_000)], False)
        assert store.bar_range("fake", "AAA", "minute") == (MINUTE, MINUTE + 60_000)  # the page was not stored
        assert claims.lost(store.path, "feed:fake") and "feed:fake" not in claims.mine(store.path)
        claims.release(store.path, "feed:fake")  # the run ends: nothing of it is left
        assert not claims.lost(store.path, "feed:fake") and claims._process == {}
    finally:
        other.close()


def test_a_download_by_hand_leaves_a_symbol_the_other_installation_is_working_on(store):
    store.watch("fake", ["AAA"], "day")
    src = FakeSource(bars=BARS)
    log: list[str] = []
    other = _other(store)
    try:
        theirs = other.take("symbol:stock:AAA", shared=True, what="massive's run")
        assert collector.download_bars(src, store, PLAN, "AAA", date(2026, 10, 19), date(2026, 10, 21), log=log.append) == 0
        assert src.calls == [] and "is working on it; try again in a moment" in log[-1]
        other.release(theirs)
        assert collector.download_bars(src, store, PLAN, "AAA", date(2026, 10, 19), date(2026, 10, 21), log=log.append) == 1
        assert claims.held(store.path) == []
    finally:
        other.close()


def test_nothing_is_claimed_where_there_is_nothing_to_claim_on(store):
    with Store(":memory:") as memory:
        assert collector.take_symbol(memory, "stock", "AAA") is None  # a store in memory is this process's alone
    assert collector.take_symbol(SimpleNamespace(), "stock", "AAA") is None  # a stand-in without a file
    common.set_read_only(True)
    assert collector.take_symbol(store, "stock", "AAA") is None and claims._process == {}  # reads only: fetches nothing
    common.set_read_only(False)
    claim = collector.take_symbol(store, "stock", "aaa", "a test")
    assert claim is not None and claim is not ELSEWHERE and claim.key == "symbol:stock:AAA"
    collector.give_symbol(store, claim)
    collector.give_symbol(store, None)
    collector.give_symbol(store, ELSEWHERE)
    assert claims.held(store.path) == [] and collector.symbol_holder(store, "stock", "AAA") == "another installation"
