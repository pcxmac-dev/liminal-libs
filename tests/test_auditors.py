"""The sweep, the re-pulls, the auditors' plugin kind (plugin API 2.4) and an audit asked for (1.64.0; auditing.py).

The user, 2026-11-15: "make sure that auditing goes over all symbols to look for consistency issues or broken
connections that fragmented data"; "For the integrator, there needs to be a plugin called auditor and it will manage
the configuration of auditing data"; and 2026-11-18: "an auditor plugin, for auditing sources and maintaining the
integrity of the feeds".

No process, no network: stores are files under tmp_path, a feed is a stand-in, the calendar is the library's own."""
from __future__ import annotations

import json
from datetime import date, datetime
from types import SimpleNamespace

import pytest

from liminal_libs import auditing, collector, config, layout
from liminal_libs.apps import App, attach_registry
from liminal_libs.collector import ET, Collector
from liminal_libs.config import ConfigError, Tier
from liminal_libs.coverage import FeedProfile, day_start_ms, ms
from liminal_libs.errors import NotEntitled, SourceError
from liminal_libs.sources import conformance, registry
from liminal_libs.sources.apis import Api, Link
from liminal_libs.sources.base import DataSource
from liminal_libs.storage import Store, pulls, set_read_only
from liminal_libs.storage.requests import AUDIT, EVERYTHING, KINDS

pytestmark = pytest.mark.usefixtures("no_outside")

DAY = 86_400_000
WEEK = [date(2026, 10, d) for d in (12, 13, 14, 15, 16)]  # Monday to Friday, every one a session
MON, TUE, WED, THU, FRI = (day_start_ms(d) for d in WEEK)
SAT = day_start_ms(date(2026, 10, 17))
NOW = ms(datetime(2026, 10, 30, 12, 0, tzinfo=ET))  # two weeks on: every day of the week has settled
PLAN = Tier("free", requests_per_minute=5, history_years=2)
QUIET = lambda *_: None  # noqa: E731


def _minute(day_ms: int, price: float = 10.0, hour: int = 10) -> dict:
    return {"t": day_ms + hour * 3_600_000, "o": price, "h": price + 1, "l": price - 1, "c": price, "v": 100, "vw": price,
            "n": 5}


def _daily(day_ms: int, price: float = 10.0, volume: float = 5000) -> dict:
    return {"t": day_ms, "o": price, "h": price + 1, "l": price - 1, "c": price, "v": volume, "vw": price, "n": 50}


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data" / "liminal.db") as s:
        yield s


@pytest.fixture(autouse=True)
def the_defaults(monkeypatch):
    monkeypatch.delenv(pulls.SWITCH, raising=False)
    auditing.set_policy(None)
    yield
    auditing.set_policy(None)
    set_read_only(False)


def _series(store, days=(MON, TUE, WED, THU, FRI), dailies=(MON, TUE, WED, THU, FRI), feed="fake", ticker="AAA") -> dict:
    """A watched series: a minute bar on each of `days`, a daily bar on each of `dailies`, the whole week said held."""
    store.watch(feed, [ticker], "minute")
    if days:
        store.upsert_bars(feed, ticker, "minute", 1, [_minute(d) for d in days])
    if dailies:
        store.upsert_bars(feed, ticker, "day", 1, [_daily(d) for d in dailies])
    store.add_coverage(feed, ticker, "minute", MON, SAT)
    store.add_coverage(feed, ticker, "day", MON, SAT)
    return store.watchlist(feed, ticker)[0]


def _sweep(store, **kw) -> auditing.Sweep:
    return auditing.Sweep(store, now_ms=NOW, **kw)


def _findings(store, **kw) -> list[tuple]:
    return sorted((f["kind"], f["timespan"], f["start_ms"], f["end_ms"], f["count"], f["state"]) for f in store.findings(**kw))


# -- the days ------------------------------------------------------------------------------------------------------------
def test_a_series_whole_in_every_session_day_has_no_finding(store):
    visit = _sweep(store).series(_series(store))
    assert (visit.days, visit.holes, visit.closed, visit.skipped) == (10, 0, 0, "") and store.findings() == []


def test_a_day_without_bars_is_a_hole_when_the_feeds_own_daily_bar_shows_it_traded(store):
    visit = _sweep(store).series(_series(store, days=(MON, TUE, THU, FRI)))
    assert visit.holes == 1 and _findings(store) == [("hole", "minute", WED, THU, 1, "open")]
    (found,) = store.findings()
    assert found["detail"] == {"days": 1, "evidence": "its own daily bar shows it traded"} and found["feed"] == "fake"
    again = _sweep(store).series(store.watchlist("fake", "AAA")[0])  # known already: not found a second time
    assert again.holes == 0 and len(store.findings()) == 1


def test_a_quiet_day_is_no_hole(store):
    # no bar that day, and nothing says there should be one: its own daily bar is missing too (a thin stock)
    visit = _sweep(store).series(_series(store, days=(MON, TUE, THU, FRI), dailies=(MON, TUE, THU, FRI)))
    assert visit.holes == 0 and store.findings() == []
    # a daily bar that shows no volume is no evidence either
    store.upsert_bars("fake", "AAA", "day", 1, [_daily(WED, volume=0)])
    assert _sweep(store).series(store.watchlist("fake", "AAA")[0]).holes == 0


def test_days_next_to_each_other_are_one_hole(store):
    _sweep(store).series(_series(store, days=(MON, THU, FRI)))
    assert _findings(store) == [("hole", "minute", TUE, THU, 2, "open")]


def test_a_missing_daily_bar_is_a_hole_when_the_finer_bars_of_that_day_are_there(store):
    _sweep(store).series(_series(store, dailies=(MON, TUE, THU, FRI)))
    assert _findings(store) == [("hole", "day", WED, THU, 1, "open")]
    assert store.findings()[0]["detail"]["evidence"] == "its own finer bars are there"


def test_another_feed_of_the_same_market_holding_bars_that_day_is_evidence(store):
    row = _series(store, days=(MON, TUE, THU, FRI), dailies=(MON, TUE, THU, FRI))
    store.upsert_bars("other", "AAA", "minute", 1, [_minute(WED)])
    feeds = {n: FeedProfile(n, PLAN, frozenset({"stock"}), venues={"stock": "sip"}) for n in ("fake", "other")}
    assert _sweep(store, feeds=feeds).series(row).holes == 2  # its minutes of that day, and its daily bar
    assert [(f[0], f[1], f[2]) for f in _findings(store)] == [("hole", "day", WED), ("hole", "minute", WED)]
    assert {f["detail"]["evidence"] for f in store.findings()} == {"other holds bars there"}


def test_a_feed_of_another_market_is_no_evidence(store):
    row = _series(store, days=(MON, TUE, THU, FRI), dailies=(MON, TUE, THU, FRI))
    store.upsert_bars("other", "AAA", "minute", 1, [_minute(WED)])
    feeds = {"fake": FeedProfile("fake", PLAN, frozenset({"stock"}), venues={"stock": "sip"}),
             "other": FeedProfile("other", PLAN, frozenset({"stock"}), venues={"stock": "iex"})}
    assert _sweep(store, feeds=feeds).series(row).holes == 0 and store.findings() == []


def test_a_span_said_to_be_held_that_holds_nothing_is_an_empty_span(store):
    store.watch("fake", ["AAA"], "minute")
    store.upsert_bars("fake", "AAA", "day", 1, [_daily(d) for d in (MON, TUE, WED, THU, FRI)])
    store.add_coverage("fake", "AAA", "minute", MON, SAT)  # held, says the ledger: not a bar of it is there
    store.add_coverage("fake", "AAA", "day", MON, SAT)
    visit = _sweep(store).series(store.watchlist("fake", "AAA")[0])
    assert visit.holes == 1 and _findings(store) == [("empty-span", "minute", MON, SAT, 5, "open")]
    assert store.findings()[0]["detail"]["evidence"] == "the ledger says it is held"


def test_a_span_with_no_session_in_it_and_a_day_too_recent_are_not_judged(store):
    store.watch("fake", ["AAA"], "minute")
    store.add_coverage("fake", "AAA", "minute", SAT, SAT + 2 * DAY)  # a weekend, held as every closed span is
    recent = day_start_ms(date(2026, 10, 29))  # yesterday: its bars may still be on their way
    store.add_coverage("fake", "AAA", "minute", recent, recent + DAY)
    visit = _sweep(store).series(store.watchlist("fake", "AAA")[0])
    assert (visit.days, visit.holes) == (0, 0) and store.findings() == []


def _cut(store, start_ms: int, end_ms: int) -> None:
    with pytest.raises(RuntimeError):
        with pulls.pulling(store, "fake", "bars", ticker="AAA", asset="stock", timespan="minute", start_ms=start_ms,
                           end_ms=end_ms):
            store.upsert_bars("fake", "AAA", "minute", 1, [_minute(MON)])
            raise RuntimeError("the connection broke")


def test_a_pull_that_was_cut_off_is_a_finding_until_the_span_it_asked_is_held(store):
    store.watch("fake", ["AAA"], "minute")
    store.upsert_bars("fake", "AAA", "minute", 1, [_minute(d) for d in (MON, TUE, THU, FRI)])
    store.add_coverage("fake", "AAA", "minute", MON, WED)  # the run stopped before Wednesday
    store.add_coverage("fake", "AAA", "minute", WED + DAY, SAT)
    _cut(store, MON, SAT)
    visit = _sweep(store).series(store.watchlist("fake", "AAA")[0])
    assert visit.pulls == 1 and [f[0] for f in _findings(store)] == ["cut-pull"]  # (Wednesday is not said to be held)
    (cut,) = store.findings(kind="cut-pull")
    assert cut["detail"] == {"why": "RuntimeError: the connection broke", "kind": "bars"} and cut["state"] == "open"
    assert _sweep(store).series(store.watchlist("fake", "AAA")[0]).closed == 0 and len(store.findings()) == 1
    (kept,) = store.pulls()  # its audit passed and its files are gone, and it stays: the sweep still judges its span
    assert (kept["state"], kept["audit"]) == ("cut", "ok") and store.cache_verified()["pulls"] == 1
    # a later run asked for the rest, and the feed has nothing there: the span the pull asked is whole
    store.add_coverage("fake", "AAA", "minute", WED, WED + DAY, origin="none")
    visit = _sweep(store).series(store.watchlist("fake", "AAA")[0])
    assert (visit.closed, visit.holes) == (1, 0) and _findings(store)[0][-1] == "closed"
    assert store.pulls() == []  # what it asked is held: nothing more to judge it by, and it is forgotten


def test_a_cut_pulls_finding_is_closed_by_its_own_span_once_its_pull_is_forgotten(store):
    from datetime import timedelta, timezone

    store.watch("fake", ["AAA"], "minute")
    store.upsert_bars("fake", "AAA", "minute", 1, [_minute(d) for d in (MON, TUE, THU, FRI)])
    store.add_coverage("fake", "AAA", "minute", MON, WED)
    store.add_coverage("fake", "AAA", "minute", WED + DAY, SAT)
    _cut(store, MON, SAT)
    row = store.watchlist("fake", "AAA")[0]
    assert _sweep(store).series(row).pulls == 1 and [f["state"] for f in store.findings(kind="cut-pull")] == ["open"]
    later = datetime.now(timezone.utc) + timedelta(days=auditing.FORGET_DAYS + 1)
    assert auditing.tidy(store, now=later)["forgotten"] == 1 and store.pulls() == []  # the ledger forgot the pull
    visit = _sweep(store).series(row)  # its finding still stands, and is still evidence: Wednesday is not held
    assert visit.closed == 0 and [f["state"] for f in store.findings(kind="cut-pull")] == ["open"]
    store.add_coverage("fake", "AAA", "minute", WED, WED + DAY, origin="none")
    visit = _sweep(store).series(row)
    assert visit.closed == 1 and [f["state"] for f in store.findings(kind="cut-pull")] == ["closed"]


def test_a_pull_that_was_cut_off_is_evidence_for_a_day_missing_inside_what_is_held(store):
    store.watch("fake", ["AAA"], "minute")
    store.upsert_bars("fake", "AAA", "minute", 1, [_minute(d) for d in (MON, TUE, THU, FRI)])
    store.add_coverage("fake", "AAA", "minute", MON, SAT)  # the week is said to be held; the pull asked two
    _cut(store, MON, SAT + 7 * DAY)
    visit = _sweep(store).series(store.watchlist("fake", "AAA")[0])
    assert visit.holes == 1 and {f["kind"]: f["state"] for f in store.findings()} == {"cut-pull": "open", "hole": "open"}
    assert store.findings(kind="hole")[0]["detail"]["evidence"] == "a pull that was cut off"


# -- asked again -----------------------------------------------------------------------------------------------------------
class Feed(DataSource):
    """A feed that answers what it is asked with the bars it has, and notes what it was asked."""

    name = "fake"

    def __init__(self, bars=(), fails: Exception | None = None):
        self.bars, self.fails, self.asked = list(bars), fails, []

    @property
    def requests_made(self) -> int:
        return len(self.asked)

    def bar_pages(self, ticker, start, end, timespan, multiplier=1, descending=False, asset="stock"):
        self.asked.append((ticker, timespan, ms(start), ms(end)))
        if self.fails is not None:
            raise self.fails
        yield [b for b in self.bars if ms(start) <= b["t"] < ms(end)]

    def is_entitled(self, resolution, ticker, asset="stock"):
        return True

    def trade_pages(self, *a, **k):
        raise AssertionError("no ticks are fetched for history")

    def exchanges(self):
        return []

    def instrument(self, ticker, resolve_exchange=True):
        raise AssertionError("no listing is looked up here")


def _run(store, feed, repulls=5) -> tuple[Collector, list[str]]:
    said: list[str] = []
    c = Collector(feed, store, PLAN, log=said.append)
    c.repulls_left = repulls
    return c, said


def test_a_hole_is_asked_of_the_feed_again_and_filled(store):
    _sweep(store).series(_series(store, days=(MON, TUE, THU, FRI)))
    assert auditing.repulls(store, "fake", "AAA", 5) == [
        {"finding": store.findings()[0]["id"], "timespan": "minute", "start_ms": WED, "end_ms": THU}]
    feed = Feed([_minute(WED)])
    c, said = _run(store, feed)
    assert c._repull("AAA", "AAA", False, "stock") == 1 and feed.asked == [("AAA", "minute", WED, THU)]
    assert c.repulls_left == 4 and _findings(store) == [("hole", "minute", WED, THU, 1, "asked")]
    assert said == ["AAA: fake asked again for 1 spans the auditors found missing or differing: 1 bars stored"]
    assert store.pulls() == [] and store.cache_verified()["pulls"] == 1  # the second answer went through the cache too
    visit = _sweep(store).series(store.watchlist("fake", "AAA")[0])
    assert visit.closed == 1 and _findings(store) == [("hole", "minute", WED, THU, 1, "closed")]
    assert auditing.repulls(store, "fake", "AAA", 5) == []


def test_a_hole_the_feed_has_nothing_for_is_remembered_as_absent_and_not_asked_a_third_time(store):
    _sweep(store).series(_series(store, days=(MON, TUE, THU, FRI)))
    feed = Feed([])
    c, _ = _run(store, feed)
    assert c._repull("AAA", "AAA", False, "stock") == 0 and _findings(store)[0][-1] == "asked"
    visit = _sweep(store).series(store.watchlist("fake", "AAA")[0])
    assert visit.absent == 1 and _findings(store) == [("hole", "minute", WED, THU, 1, "absent")]
    assert auditing.repulls(store, "fake", "AAA", 5) == []
    assert c._repull("AAA", "AAA", False, "stock") == 0 and len(feed.asked) == 1  # not asked again
    visit = _sweep(store).series(store.watchlist("fake", "AAA")[0])
    assert (visit.holes, visit.absent) == (0, 0) and len(store.findings()) == 1  # known: neither found anew nor counted


def test_a_run_asks_again_for_no_more_than_the_policy_says(store):
    row = _series(store, days=(MON, WED, FRI))  # two holes: Tuesday and Thursday
    _sweep(store).series(row)
    assert [f[2] for f in _findings(store)] == [TUE, THU]
    feed = Feed([_minute(TUE), _minute(THU)])
    c, _ = _run(store, feed, repulls=1)
    assert c._repull("AAA", "AAA", False, "stock") == 1 and len(feed.asked) == 1 and c.repulls_left == 0
    assert sorted(f[-1] for f in _findings(store)) == ["asked", "open"]
    assert c._repull("AAA", "AAA", False, "stock") == 0 and len(feed.asked) == 1  # the run's share is spent
    assert auditing.repulls(store, "fake", "AAA", 0) == []


def test_a_span_the_plan_refuses_counts_as_asked_and_one_the_feed_fails_on_is_left_for_the_next_run(store):
    _sweep(store).series(_series(store, days=(MON, TUE, THU, FRI)))
    c, said = _run(store, Feed(fails=SourceError(503, "busy")))
    assert c._repull("AAA", "AAA", False, "stock") == 0 and _findings(store)[0][-1] == "open"
    assert said == ["AAA minute: fake could not be asked again for 2026-10-14 (HTTP 503: busy); next run"] or "next run" in said[0]
    c, _ = _run(store, Feed(fails=NotEntitled(403, "outside your plan")))
    assert c._repull("AAA", "AAA", False, "stock") == 0 and _findings(store)[0][-1] == "asked"


def test_a_bar_stored_with_other_values_is_asked_again_by_its_own_minute(store):
    store.watch("fake", ["AAA"], "minute")
    with pulls.pulling(store, "fake", "bars", ticker="AAA", asset="stock", timespan="minute", start_ms=MON, end_ms=SAT) as p:
        store.upsert_bars("fake", "AAA", "minute", 1, [_minute(MON), _minute(TUE)])
    conn = store._bars("fake")
    with conn:
        conn.execute("UPDATE bars SET close=close+1 WHERE ts=?", (_minute(TUE)["t"],))
    assert auditing.audit_pull(store, p.id).result == "mismatch"
    (want,) = auditing.repulls(store, "fake", "AAA", 5)
    assert (want["timespan"], want["start_ms"], want["end_ms"]) == ("minute", _minute(TUE)["t"], _minute(TUE)["t"] + 60_000)
    c, _ = _run(store, Feed([_minute(TUE)]))
    assert c._repull("AAA", "AAA", False, "stock") == 1
    assert conn.execute("SELECT close FROM bars WHERE ts=?", (_minute(TUE)["t"],)).fetchone()[0] == 10.0  # as the feed says
    assert store.findings(kind="copy-differs")[0]["state"] == "asked"
    assert conn.execute("SELECT close FROM bar_revisions WHERE ts=?", (_minute(TUE)["t"],)).fetchall() == [(10.0,), (11.0,)]


# -- the month's rules -----------------------------------------------------------------------------------------------------
def test_what_a_storage_rule_catches_in_the_month_is_kept_and_closed_when_it_is_put_right(store):
    row = _series(store)
    bad = {**_minute(WED, hour=11), "h": 5.0, "l": 9.0}  # its high below its low
    store.upsert_bars("fake", "AAA", "minute", 1, [bad])
    visit = _sweep(store).series(row)
    assert visit.rules == 1
    (found,) = store.findings(kind="integrity")
    assert (found["timespan"], found["count"], found["state"]) == ("minute", 1, "open")
    assert found["detail"]["rules"] == {"malformed": 1} and found["detail"]["first"][0]["at"] == bad["t"]
    assert found["detail"]["rows"] == 6 and 0 < found["detail"]["completeness"] <= 1
    store.upsert_bars("fake", "AAA", "minute", 1, [_minute(WED, hour=11)])  # the feed's correction
    visit = _sweep(store).series(row)
    assert (visit.rules, visit.closed) == (0, 1) and store.findings(kind="integrity")[0]["state"] == "closed"


# -- a run -----------------------------------------------------------------------------------------------------------------
def _ticking(step: float = 10.0):
    at = iter(range(0, 10**9))
    return lambda: next(at) * step


def test_the_series_take_their_turns_run_after_run_and_a_round_is_whole_when_the_last_has_had_its(store):
    for ticker in ("AAA", "BBB", "CCC"):
        _series(store, ticker=ticker)
    policy = auditing.Policy()
    seen = []
    for _ in range(4):
        sweep = _sweep(store, policy_=policy, clock=_ticking())
        visited = sweep.series
        sweep.series = lambda row, visited=visited: seen.append(row["ticker"]) or visited(row)
        out = sweep.run(budget_s=15)  # time for one series a run
        assert (out["series"], out["complete"], out["watched"]) == (1, False, 3)
    assert seen == ["AAA", "BBB", "CCC", "AAA"]  # from where the last run stopped, round the end
    assert store.kv_get(auditing.CURSOR_KEY) == "fake\tAAA" and _sweep(store).round() == 1  # CCC had its turn: one round
    out = _sweep(store, policy_=policy).run()  # with time for all of them
    assert (out["series"], out["complete"], out["round"]) == (3, True, 2) and out["days"] == 30
    assert json.loads(store.kv_get(auditing.LAST_KEY))["series"] == 3


def test_an_audit_asked_for_a_symbol_goes_out_of_turn_and_leaves_the_round_where_it_was(store):
    for ticker in ("AAA", "BBB"):
        _series(store, ticker=ticker)
    out = _sweep(store).run(only={("fake", "BBB")})
    assert (out["series"], out["only"], out["complete"]) == (1, ["fake:BBB"], True)
    assert store.kv_get(auditing.CURSOR_KEY) is None and store.kv_get(auditing.LAST_KEY) is None


def test_a_run_audits_what_waits_in_the_cache_first(store):
    _series(store)
    with pulls.pulling(store, "fake", "bars", ticker="AAA", asset="stock", timespan="minute", start_ms=MON, end_ms=SAT) as p:
        store.upsert_bars("fake", "AAA", "minute", 1, [_minute(MON, hour=12)])
    out = _sweep(store).run()
    assert out["pulls"] == 1 and store.pull(p.id) is None and store.cache_verified()["rows"] == 1


def test_a_symbol_another_installation_is_working_on_is_left_for_the_next_round(store, monkeypatch):
    row = _series(store, days=(MON, TUE, THU, FRI))
    monkeypatch.setattr(collector, "take_symbol", lambda store, asset, ticker, what="": collector.ELSEWHERE)
    visit = _sweep(store).series(row)
    assert visit.skipped == "another installation is working on it" and visit.days == 0 and store.findings() == []


def test_a_copy_that_reads_only_audits_nothing_and_a_future_is_not_judged_by_days(store):
    row = _series(store, days=(MON, TUE, THU, FRI))
    set_read_only(True)
    out = _sweep(store).run()
    assert out["series"] == 0 and "reads only" in out["note"]
    set_read_only(False)
    visit = _sweep(store).series({**row, "asset": "future"})
    assert (visit.days, visit.holes) == (0, 0)


def test_the_page_is_told_the_policy_the_cache_the_last_sweep_and_the_findings(store):
    _sweep(store).series(_series(store, days=(MON, TUE, THU, FRI)))
    _sweep(store).run()
    got = auditing.overview(store, auditing.Policy(keep_days=7))
    assert got["policy"]["keepDays"] == 7 and got["cache"]["on"] is True and got["cache"]["capBytes"] == 20 * 2**30
    assert got["cache"]["folder"].endswith("cache") and got["cache"]["unverifiedBytes"] == 0
    assert got["sweep"]["last"]["series"] == 1 and got["sweep"]["cursor"] == "fake:AAA" and got["sweep"]["round"] == 1
    assert got["findings"]["open"] == 1 and got["findings"]["counts"] == {"open": 1}
    assert [f["kind"] for f in got["findings"]["latest"]] == ["hole"]
    json.dumps(got)  # a page's


# -- an audit asked for ----------------------------------------------------------------------------------------------------
def test_an_audit_asked_for_is_a_request_of_its_own_beside_the_symbols_fetch(store):
    assert KINDS == ("bars", "live", "audit") and (AUDIT, EVERYTHING) == ("audit", "*")
    fetch = store.request_put("aaa", ("bars",), by="chart")
    audit = store.request_put("AAA", (AUDIT,), by="page")
    assert audit["id"] != fetch["id"] and audit["kinds"] == ("audit",) and fetch["kinds"] == ("bars",)
    assert store.request_put("AAA", (AUDIT,), by="cli")["id"] == audit["id"]  # asked again: the same request
    assert store.request_put("AAA", ("live",))["id"] == fetch["id"] and store.request_get(fetch["id"])["kinds"] == ("bars", "live")
    assert store.request_get(audit["id"])["kinds"] == ("audit",)  # the fetch's kinds joined the fetch, not the audit
    sweep = store.request_put(EVERYTHING, (AUDIT,), by="page")
    assert sweep["symbol"] == "*" and len(store.requests_open()) == 3


# -- the auditors' plugin --------------------------------------------------------------------------------------------------
CARD = (Api(name="SQLite", maker="The SQLite project", about="The comparison of a cache file with what is stored.",
            kind="sdk", links=(Link("SQL Language Expressions", "https://www.sqlite.org/lang_expr.html", "docs"),),
            verified="2026-11-18"),)


class Auditor(auditing.AuditorPlugin):
    name, title, about, api, version = "auditor", "Auditor", "holds the auditors' options", "2.4", "0.1.0"
    apis = CARD

    def settings(self, variables):
        return self.policy(variables)


@pytest.fixture
def installed(monkeypatch):
    """Plugins loaded as installed packages' entry points; the plugin directory out of the way."""
    monkeypatch.setattr(layout, "plugins_dir", lambda: None)

    def install(*plugins):
        eps = [SimpleNamespace(name=f"p{i}", value=f"fake_{i}:AUDITOR", load=(lambda p=p: SimpleNamespace(AUDITOR=p)))
               for i, p in enumerate(plugins)]
        monkeypatch.setattr(registry, "_entry_points", lambda: eps)
        return registry.reload()

    yield install
    registry._providers = None


def test_the_auditors_plugin_is_a_kind_of_its_own_found_with_the_others(installed):
    assert registry.PLUGIN_API == "2.4" and registry.api_refusal("2.3") is None and registry.api_refusal("2.4") is None
    installed(Auditor)
    assert list(registry.auditors()) == ["auditor"] and registry.auditor().origin.startswith("package:")
    assert registry.errors() == [] and registry._kind(registry.auditor()) == "auditor"
    for others in (registry.providers(), registry.publishers(), registry.assistants(), registry.machines(), registry.databases()):
        assert "auditor" not in others
    assert len(registry.discover_everything()) == 5 and len(registry.discover_all()) == 3  # the older finders as they were
    assert set(auditing.CHOICES) <= set(registry.variables())  # its options are read with the user's saved variables
    assert registry.plugins_loaded()[-1] == "auditor" and registry.plugin_keys("auditor") == []
    p = registry.auditor()
    assert (p.KIND, p.SYSTEM, p.ICON) == ("auditor", "integrator", "scales") and p.has_settings and not p.has_scan
    assert p.options == tuple(auditing.CHOICES) and dict(p.plan_choices) == auditing.CHOICES
    assert registry.select("none").everything is False and registry.auditors() == {}
    registry.select(None)
    assert list(registry.auditors()) == ["auditor"]
    registry.leave_out("auditor", "its settings failed")
    assert registry.auditors() == {} and registry.auditor() is None and registry.errors()[-1][1] == "auditor: its settings failed"


def test_one_plugin_holds_the_auditors_options_a_second_is_left_out(installed):
    class Second(Auditor):
        name = "auditor-two"

    installed(Auditor, Second)
    assert list(registry.auditors()) == ["auditor"]
    assert any("'auditor' holds the auditors' options already" in why for _, why in registry.errors())


def test_its_settings_are_the_policy_and_the_defaults_stand_without_it(installed, monkeypatch):
    installed(Auditor)
    made = config.Settings.load(env={"AUDITOR_KEEP_DAYS": "7", "AUDITOR_ON_MISMATCH": "flag"}, env_file=None)
    assert made.plugin("auditor") == auditing.Policy(keep_days=7, repair=False) == auditing.policy_of(made)
    assert made.env["AUDITOR_KEEP_DAYS"] == "7"
    with pytest.raises(ConfigError, match="AUDITOR_CACHE_GB='3': one of 20, 5, 50, 100"):
        config.Settings.load(env={"AUDITOR_CACHE_GB": "3"}, env_file=None)
    installed()  # no such plugin installed
    bare = config.Settings.load(env={"AUDITOR_KEEP_DAYS": "7"}, env_file=None)
    assert bare.plugin("auditor") is None and auditing.policy_of(bare) == auditing.Policy()  # the defaults, never off


def test_the_integrators_app_attaches_it(installed):
    class Integrator(App):
        NAME, SYSTEM = "integrator", "integrator"

    installed(Auditor)
    app = Integrator()
    assert "auditor" in attach_registry(app, only="integrator") and registry.auditor().app is app
    assert "auditor" not in attach_registry(Integrator(), only="platform")
    registry.auditor().detach()


def test_what_the_contract_holds_the_auditors_plugin_to():
    assert conformance.problems(Auditor()) == []

    class Old(Auditor):
        api = "2.3"

    class Short(Auditor):
        options = ("AUDITOR_ON_UPDATE",)
        plan_choices = {"AUDITOR_ON_UPDATE": ("off", "on")}

    class Silent(auditing.AuditorPlugin):
        name, title, about, api, version, apis = "auditor", "Auditor", "says nothing", "2.4", "0.1.0", CARD

    class Wrong(Auditor):
        def settings(self, variables):
            return {"keep": 7}

    assert conformance.problems(Old()) == ["auditor: the auditors' plugin is written for plugin API 2.4, not 2.3"]
    short = conformance.problems(Short())
    lacking = ("auditor: its options lack AUDITOR_SWEEP_EVERY, AUDITOR_SWEEP_MINUTES, AUDITOR_ON_MISMATCH, "
               "AUDITOR_KEEP_DAYS, AUDITOR_CACHE_GB, AUDITOR_REPULLS")
    assert lacking in short
    assert "auditor: AUDITOR_ON_UPDATE's choices are on, off (auditing.CHOICES), the default first" in short
    assert conformance.problems(Silent()) == [
        "auditor: the auditors' plugin must give settings(): the Policy its options make"]
    assert conformance.problems(Wrong()) == [
        "auditor: settings({}) must give an auditing.Policy (the defaults), not {'keep': 7}"]
    assert conformance._kind_of(Auditor()) == "auditor" and "AUDITOR" in registry.NAMES
