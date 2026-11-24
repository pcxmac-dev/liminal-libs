"""Small helpers shared by the storage modules: clocks, dates and key scans."""

from __future__ import annotations

import re
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timezone
from typing import Iterator
from zoneinfo import ZoneInfo

from ..mounts import NotHere


_ET = ZoneInfo("America/New_York")

# How long a connection waits for another process's write before failing with "database is
# locked": the hourly sync, the live recorder and the chart app write the same files.
BUSY_TIMEOUT_S = 30.0


# Read-only (LIMINAL_READONLY): a process sets it once it knows its settings (cli.py); every
# connection a store opens is then made query-only once its tables are looked for, so no write of
# this process reaches a file (SQLite refuses it: "attempt to write a readonly database").
_READ_ONLY = [False]


def set_read_only(on: bool) -> None:
    _READ_ONLY[0] = bool(on)


def read_only() -> bool:
    return _READ_ONLY[0]


def seal(conn: sqlite3.Connection) -> sqlite3.Connection:
    """The connection query-only when this process reads only."""
    if _READ_ONLY[0]:
        conn.execute("PRAGMA query_only=ON")
    return conn


@contextmanager
def write_transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """One write transaction taken from its start (BEGIN IMMEDIATE), committed at the end: what
    is read inside it cannot change before it is written back. A deferred one reads first and only
    then takes the write lock, so two processes reading the same row both write from what they
    read, and the later loses the earlier's change."""
    with conn:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        yield conn


def own_files(path) -> bool:
    """Whether a store's files are this system's own: not another system's seen through a mount
    (mounts.foreign), where a process id in a row names a process this system cannot look up. A
    store in memory is this process's."""
    from .. import mounts

    return str(path) == ":memory:" or not mounts.foreign(path)


class Behind(NotHere):
    """A file on another system's drive whose tables are older than this software's: it is brought up to date by
    the system that holds it, never from here."""


@contextmanager
def owners_layout(conn, path, behind: str = "") -> Iterator[None]:
    """Round the part of an open that brings a file's tables up to this software's (the schema's scripts, the
    upgrades of an older file). On a file of this system's own: as always, it is made and upgraded here. On a file
    on another system's drive nothing of its layout is changed from here: that part runs query-only, which does
    nothing to a file that is up to date, and a file that is behind is said to be (Behind) rather than altered
    under the software running on the system that holds it (a column added by a newer suite in WSL would break the
    older one's writes on Windows). A process that reads only (LIMINAL_READONLY) stays query-only after it.
    `behind()`: what the file lacks, in words, when the caller can say."""
    if path is None or own_files(path):
        yield
        return
    conn.execute("PRAGMA query_only=ON")
    try:
        yield
    except sqlite3.OperationalError as e:
        if "readonly" not in str(e).lower():
            raise
        lacks = behind() if callable(behind) else behind
        raise Behind(f"{path} is on another system's drive and behind this software{f' ({lacks})' if lacks else ''}: "
                     "its tables are brought up to date by the system that holds it (the suite started there on "
                     "this version), and nothing of it is changed from here") from None
    if not _READ_ONLY[0]:
        conn.execute("PRAGMA query_only=OFF")


def busy(e: BaseException) -> bool:
    """Whether an error is the database being busy (another connection holding its write lock past this one's
    wait), not a fault of what was asked."""
    return isinstance(e, sqlite3.OperationalError) and any(w in str(e).lower() for w in ("locked", "busy"))


def add_column(conn: sqlite3.Connection, table: str, column: str, kind: str) -> None:
    """ALTER TABLE ADD COLUMN unless the column is there (inside the caller's write transaction:
    two processes opening an old file at once both found it missing, and the second failed)."""
    if column in {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}:
        return
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
    except sqlite3.OperationalError as e:
        if "duplicate column" not in str(e):
            raise


def utc_now() -> datetime:
    """The time, as what is stored is stamped with it: this system's clock; in a process that reaches its files
    through the link, the clock of the system that owns them (link.Link.owner_now: the two systems' clocks
    differ, WSL's by seconds at times, and a copy that asks what was written since it began would miss a row
    stamped by a clock that runs behind)."""
    from . import link

    owner = link.owner_link()
    if owner is not None and not owner.dead:
        try:
            return datetime.fromtimestamp(owner.owner_now(), timezone.utc)
        except sqlite3.Error:
            pass  # the link ended meanwhile: its files cannot be written any more either
    return datetime.now(timezone.utc)


def _now() -> str:
    return utc_now().isoformat(timespec="seconds")


def _now_precise() -> str:
    return utc_now().isoformat(timespec="microseconds")


def _date_ms(d: date) -> int:
    return int(datetime(d.year, d.month, d.day, tzinfo=timezone.utc).timestamp() * 1000)


FEED_NAME = re.compile(r"[A-Za-z0-9_]+(-[A-Za-z0-9_]+)*")


def _feed_name(name: str) -> bool:
    return bool(FEED_NAME.fullmatch(name)) and not name.endswith("-ticks")


def _distinct(conn: sqlite3.Connection, table: str, cols: tuple[str, ...], rest: tuple[str, ...]) -> list[tuple]:
    """Distinct values of a primary-key prefix `cols`. Each step seeks past the whole key
    (`rest` = the remaining integer key columns, set to their maximum), so rows sharing a
    prefix are skipped in the index rather than read."""
    names = ", ".join(cols)
    key = ", ".join(cols + rest)
    top = (2**63 - 1,) * len(rest)
    out: list[tuple] = []
    row = conn.execute(f"SELECT {names} FROM {table} ORDER BY {names} LIMIT 1").fetchone()
    while row is not None:
        out.append(tuple(row))
        row = conn.execute(
            f"SELECT {names} FROM {table} WHERE ({key}) > ({', '.join('?' * (len(cols) + len(rest)))}) "
            f"ORDER BY {key} LIMIT 1", tuple(row) + top).fetchone()
    return out
