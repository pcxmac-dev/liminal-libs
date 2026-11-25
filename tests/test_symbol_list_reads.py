"""Monday list item 16 (1.84.0): the reads the charts' symbol list makes for every symbol, set-based. bar_edges_many,
newest_many, probes and rolls_of give what bar_edges, newest_any, probe and rolls give one at a time, in one
statement each however many symbols are asked; the loose index scan behind stored_series (`_distinct`) is one
statement however many series there are, with the same rows."""
from __future__ import annotations

import random
from datetime import date, datetime, timezone

from liminal_libs.storage import Store
from liminal_libs.storage.common import _distinct

NOW = datetime(2026, 10, 21, 16, 0, tzinfo=timezone.utc)


def _insert(store: Store, feed: str, rows: list[tuple], built: bool = False) -> None:
    conn = store._feed(feed, create=True).conn
    with conn:
        if built:
            conn.executemany("INSERT INTO built_bars (ticker, timespan, multiplier, ts, close, derivation) "
                             "VALUES (?, ?, ?, ?, 1.0, 1)", rows)
        else:
            conn.executemany("INSERT INTO bars (ticker, timespan, multiplier, ts, close) VALUES (?, ?, ?, ?, 1.0)", rows)
    store._wrote()


def _store(tmp_path) -> Store:
    s = Store(tmp_path / "s.db", check_same_thread=False)
    _insert(s, "massive", [("AAA", "minute", 1, 100), ("AAA", "minute", 1, 900),  # the feed's own only
                           ("BOTH", "minute", 1, 300), ("BOTH", "minute", 1, 700),  # built reaches further back
                           ("AAA", "day", 1, 5), ("AAA", "minute", 5, 10_000),  # other series: not these
                           ("TIE", "minute", 1, 50), ("TIE", "minute", 1, 500),
                           ("NQZ6", "minute", 1, 1_000), ("NQZ6", "minute", 1, 2_000)])
    _insert(s, "massive", [("BUILT", "minute", 1, 200), ("BUILT", "minute", 1, 400),
                           ("BOTH", "minute", 1, 100), ("BOTH", "minute", 1, 600)], built=True)
    _insert(s, "alpaca", [("AAA", "minute", 1, 950), ("TIE", "minute", 1, 500), ("OTHER", "minute", 1, 1)])
    _insert(s, "alpaca", [("BOTH", "minute", 1, 800)], built=True)
    return s


TICKERS = ["AAA", "BOTH", "BUILT", "NONE", "TIE", "OTHER", "aaa", "NQZ6"]


def _count(store: Store) -> list[str]:
    seen: list[str] = []
    for conn in [store.conn] + [f.conn for f in store._open_feeds()]:
        conn.set_trace_callback(seen.append)
    return seen


def test_bar_edges_many_is_bar_edges_for_each(tmp_path):
    s = _store(tmp_path)
    for feed in ("massive", "alpaca", "nofeed"):
        for timespan, mult in (("minute", 1), ("minute", 5), ("day", 1)):
            want = {t: e for t in TICKERS if (e := s.bar_edges(feed, t, timespan, mult)) is not None}
            assert s.bar_edges_many(feed, TICKERS, timespan, mult) == want
    assert s.bar_edges_many("massive", TICKERS)["BOTH"] == (100, 700)  # min over both tables, max over both
    assert s.bar_edges_many("massive", []) == {}


def test_newest_many_is_newest_any_for_each(tmp_path):
    s = _store(tmp_path)
    holders = s.series_holders()
    want = {t: n for t in TICKERS if (n := s.newest_any(t, "minute", holders)) is not None}
    assert s.newest_many(TICKERS, "minute", holders) == want
    assert s.newest_many(TICKERS, "minute") == want  # holders looked up itself
    assert want["AAA"] == ("alpaca", 950) and want["BOTH"] == ("alpaca", 800)
    assert want["TIE"] == ("alpaca", 500)  # a tie: the first holder in order, as newest_any
    assert s.newest_many(TICKERS, "day", holders) == {t: n for t in TICKERS if (n := s.newest_any(t, "day", holders))}


def test_probes_and_rolls_of_are_probe_and_rolls_for_each(tmp_path):
    s = _store(tmp_path)
    s.watch("massive", ["AAA", "BOTH", "NONE"], "minute")
    s.watch("alpaca", ["AAA"], "minute")
    s.set_probe("massive", "AAA", NOW, 900)
    s.set_probe("massive", "BOTH", NOW, None)
    s.set_probe("alpaca", "AAA", NOW, 1)
    for feed in ("massive", "alpaca"):
        assert s.probes(feed) == {t: p for t in ("AAA", "BOTH", "NONE") if (p := s.probe(feed, t)) is not None}
    s.set_rolls("massive", "NQ", 1, [(date(2026, 9, 18), "NQZ6"), (date(2026, 9, 17), "NQU6")])
    s.set_rolls("massive", "ES", 1, [(date(2026, 9, 17), "ESU6")])
    s.set_rolls("massive", "ES", 2, [(date(2026, 9, 17), "ESZ6")])
    assert s.rolls_of("massive") == {"NQ": s.rolls("massive", "NQ"), "ES": s.rolls("massive", "ES")}
    assert s.rolls_of("massive", 2) == {"ES": s.rolls("massive", "ES", 2)}
    assert s.rolls_of("alpaca") == {}


def test_each_read_is_one_statement_however_many_symbols(tmp_path):
    s = _store(tmp_path)
    many = [f"S{i:04d}" for i in range(300)]
    _insert(s, "massive", [(t, "minute", 1, i) for i, t in enumerate(many)])
    holders = s.series_holders()
    for asked in (many[:3], many):
        seen = _count(s)
        edges = s.bar_edges_many("massive", asked)
        assert len(seen) == 1 and len(edges) == len(asked)
        seen = _count(s)
        newest = s.newest_many(asked, "minute", holders)
        assert len(seen) == 1 and len(newest) == len(asked)  # one feed holds them: one statement
        seen = _count(s)
        s.probes("massive")
        assert len(seen) == 1


def _distinct_a_step_at_a_time(conn, table, cols, rest):
    """The loose index scan as it was before 1.84.0: a statement a step."""
    names, key = ", ".join(cols), ", ".join(cols + rest)
    out, row = [], conn.execute(f"SELECT {names} FROM {table} ORDER BY {names} LIMIT 1").fetchone()
    while row is not None:
        out.append(tuple(row))
        row = conn.execute(f"SELECT {names} FROM {table} WHERE ({key}) > ({', '.join('?' * (len(cols) + len(rest)))}) "
                           f"ORDER BY {key} LIMIT 1", tuple(row) + (2**63 - 1,) * len(rest)).fetchone()
    return out


def test_the_loose_index_scan_is_one_statement_with_the_same_rows(tmp_path):
    s = Store(tmp_path / "s.db", check_same_thread=False)
    r = random.Random(16)
    tickers = [f"T{i}" for i in range(120)] + ["123", "BRK.B", "Ünï", "NQ1!", 'q"uote\\d']
    rows = {(t, span, m, r.randrange(-2**40, 2**62)) for t in tickers for span in r.sample(["minute", "day", "second"], 2)
            for m in (1, 5) for _ in range(r.randrange(1, 30))}
    _insert(s, "massive", sorted(rows))
    conn = s._feed("massive").conn
    want = _distinct_a_step_at_a_time(conn, "bars", ("ticker", "timespan", "multiplier"), ("ts",))
    seen: list[str] = []
    conn.set_trace_callback(seen.append)
    got = _distinct(conn, "bars", ("ticker", "timespan", "multiplier"), ("ts",))
    conn.set_trace_callback(None)
    assert got == want and len(got) == len(tickers) * 4
    assert len(seen) == 1, f"{len(seen)} statements for {len(got)} series"
    assert _distinct(conn, "built_bars", ("ticker", "timespan", "multiplier"), ("ts",)) == []
    assert {(t, k) for _, t, k in s.stored_series()} == {(t, k) for t, k, m in want if m == 1}
