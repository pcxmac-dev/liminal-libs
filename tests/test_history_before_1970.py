"""A closed month before 1970 is copied to DuckDB and its check agrees (1.88.3)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

duckdb = pytest.importorskip("duckdb")

from liminal_libs.storage import Store, history  # noqa: E402


def _ms(y, m, d):
    return int(datetime(y, m, d, tzinfo=timezone.utc).timestamp() * 1000)


def test_a_month_of_bars_before_1970_is_archived_and_its_check_agrees(tmp_path):
    with Store(tmp_path / "data" / "liminal.db") as store:
        bars = [{"t": _ms(1969, 12, d), "o": 10.0, "h": 11.0, "l": 9.0, "c": 10.5, "v": 100.0 + d} for d in range(1, 29)]
        store.upsert_bars("fake", "AAA", "day", 1, bars)
        conn = store._bars("fake")
        folder = tmp_path / "history"
        folder.mkdir()
        got = history.archive_month(conn, folder, "fake", "1969-12")
        assert got  # archived, not refused with a checksum that disagrees
