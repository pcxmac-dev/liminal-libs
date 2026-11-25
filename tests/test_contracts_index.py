"""A product's futures contracts are read by an index, never a scan of the feed's (1.85.0; Monday list item 16)."""
from __future__ import annotations

from datetime import date

from liminal_libs.storage import Store


def test_a_products_contracts_are_read_by_the_index_in_first_trade_order(tmp_path):
    with Store(tmp_path / "liminal.db") as store:
        rows = [("massive", p, f"{p}{m}{y}", f"20{y}-{m:02d}-01", f"20{y}-{m:02d}-20")
                for p in ("NQ", "ES", "YM") for y in (25, 26) for m in (3, 6, 9, 12)]
        with store.conn:
            store.conn.executemany("INSERT INTO futures_contracts (source, product, ticker, first_trade, last_trade) "
                                   "VALUES (?, ?, ?, ?, ?)", rows)
        plan = " ".join(r[-1] for r in store.conn.execute(
            "EXPLAIN QUERY PLAN SELECT ticker, first_trade, last_trade, state, checked FROM futures_contracts "
            "WHERE source=? AND product=? ORDER BY first_trade", ("massive", "NQ")))
        assert "futures_contracts_product" in plan and "TEMP B-TREE" not in plan, plan
        got = store.contracts("massive", "NQ")
        assert [c["month"] for c in got] == sorted(c["month"] for c in got) and len(got) == 8
        assert got[0]["month"] == date(2025, 3, 1) and all(c["ticker"].startswith("NQ") for c in got)
