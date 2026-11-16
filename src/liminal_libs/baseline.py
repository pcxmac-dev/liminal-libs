"""What is usual for this machine's traffic, learned while Liminal watches, for the firewalls' Filter tab (the user,
2026-11-14: "monitor send and receive traffic, especially traffic that is out of the ordinary", "the filter allows
(uses ebpf) tracking one off connections").

What it learns: the peers this machine talks with (by group: an IPv4 /24, an IPv6 /48), the ports it serves (and the
ports it reaches, when a flow says so), its programs on the network, and its peers' countries and networks (ASNs).
They are kept in one small SQLite table, seen(key, kind, first, last, count, again: when the second flow that saw it
began), capped in rows (the ones longest unseen are pruned first). Nothing else goes to disk: no packets, no
payloads, no flows.

Learning comes first. Nothing is flagged until 30 minutes of watching are learned, and only the time Liminal watches
counts (the plugin's tab being asked, `watch`, and the flows it remembers), never the hours it is closed;
`learning()` says how far it is, and `describe()` says it in words. After that, `flags` names what a flow brings:
- something the learned history has never seen (new-peer, new-port, new-program, new-country, new-asn);
- a one-off: a short connection with a new peer, not repeated within 10 watched minutes;
- a spike: its port carrying, in the last minute, 8 times its usual minute.
Every flag's words say it is "unusual for this machine while Liminal was watching": what was seen here, never a
judgment of intent.

A flow is a dict: dir ("in": a peer reached this machine, "out": this machine reached it, "local": never kept), remote
(the peer's address), remote_group, local_port, program, country, asn, start, end (epoch seconds, datetimes or ISO
times) and bytes; remote_port, proto and org when known. An outgoing flow's local port is a passing (ephemeral) one, so
its port is the remote_port it reached, when given. Tell a flow to `flags` before `remember` (or both at once:
`observe`). A flow told again (the same start, its bytes grown) is counted once, and asked again it says the same; a
one-off is known only once its 10 watched minutes have passed, so ask again for the flows still shown. A time more
than a minute later than the clock (FUTURE_S) is taken as the clock's. The file stays open from the first call that
watches, remembers or flags to `close()`: close it when the watching stops, and the next such call opens it again (a
call that only reads what is learned, `learning` or `describe`, opens it for that read alone, and makes no file). All
in memory is capped, a flow's words too; no thread is started."""
from __future__ import annotations

import ipaddress
import math
import os
import re
import sqlite3
import statistics
import threading
import time
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import layout

FOLDER = "baseline"  # in layout.data_dir(): one file per plugin
CAP = 50_000  # learned rows kept
LEARN_S = 30 * 60.0  # watching learned before anything is flagged
GAP_S = 30.0  # a longer pause between two moments seen is not watching (the watcher had stopped)
# A flow's time further ahead of the clock than this is taken as the clock's (a wrong unit, a skew). A time within it
# may carry the latest moment watched ahead of the clock, so the clock is taken as gone back only when it reads more
# than GAP_S + FUTURE_S before that moment: a flow source's clock running ahead is never the clock going back.
FUTURE_S = 60.0
ONE_OFF_S = 10 * 60.0  # a short connection with a new peer not seen again in this much watching is a one-off
SHORT_S = 30.0  # a connection this long or shorter is short-lived
SPIKE_X = 8.0  # a port's bytes in the last minute this many times its usual minute's
SPIKE_MINUTES = 30  # the busy minutes (a port's minutes with traffic) its usual is the median of
SPIKE_MIN_MINUTES = 5  # fewer busy minutes known say nothing about what is usual
SPIKE_FLOOR = 64 * 1024  # less than this in a minute is never a spike
STEP_S = 5  # a port's last minute is counted in steps of this many seconds
MAX_FLOWS = 4096  # flows remembered by who they are, so one told twice is counted once
MAX_PORTS = 256  # ports whose minutes are kept in memory, the one used longest ago dropped first
MAX_SPANS = 256  # spells of watching kept in memory (a one-off's 10 watched minutes are counted over them)
MAX_KEPT = 2048  # flows whose one-off or spike, once judged, is kept for when they are asked again
# A flow's words kept at the most, in its keys and its flags' words (a longer one is cut there): a program's path, a
# peer that is no address, a country, a network's name, a protocol or a direction. A group given longer than
# MAX_REMOTE is no group (the address's is taken).
MAX_PROGRAM, MAX_REMOTE, MAX_COUNTRY, MAX_ORG, MAX_WORD = 1024, 255, 8, 256, 16
UNUSUAL = "unusual for this machine while Liminal was watching"
FLAGS = {  # a flag's id, and its name in plain words (the page's chips and filters)
    "new-peer": "new peer", "new-port": "new port", "new-program": "new program", "new-country": "new country",
    "new-asn": "new network", "one-off": "one-off", "spike": "spike"}
KINDS = ("peer", "port", "program", "country", "asn")  # what the seen table learns
WATCH = "watch"  # the kind of the two rows that hold the watching itself (never pruned, never counted in the cap)
_TIME, _LEARNED = "watch:time", "watch:learned"


@dataclass(frozen=True)
class Flag:
    """What is unusual about a flow: its id (one of FLAGS) and the words that say it."""
    id: str
    words: str

    def as_dict(self) -> dict:
        return {"id": self.id, "words": self.words}


def path_for(plugin: str) -> Path:
    """A plugin's baseline file: layout.data_dir()/baseline/<plugin>.db."""
    name = re.sub(r"[^a-z0-9_.-]+", "-", str(plugin).strip().lower()).strip(".-") or "plugin"
    return layout.data_dir() / FOLDER / f"{name}.db"


def group_of(address) -> str:
    """An address's group, the peer a baseline learns: its IPv4 /24 or its IPv6 /48 ("203.0.113.0/24"; an IPv4
    address written as IPv6 is taken as IPv4), as traffic.group_of has it; what is no address is a group of its own."""
    ip = _address(address)
    if ip is None:
        return str(address)
    return str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 48}", strict=False))


# -- a flow read ----------------------------------------------------------------------------------------------------

def _address(remote):
    if isinstance(remote, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = remote
    else:
        s = remote if isinstance(remote, str) else str(remote or "")
        if len(s) > 128:  # longer than an address, a zone and a port, blanks and all: no address
            return None
        s = s.strip()
        if s.startswith("["):  # [v6]:port
            s = s[1:].split("]", 1)[0]
        elif s.count(":") == 1:  # v4:port
            s = s.split(":", 1)[0]
        try:
            ip = ipaddress.ip_address(s.split("%", 1)[0])
        except ValueError:
            return None
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip


def _time(value) -> float | None:
    """Epoch seconds from a number, a datetime or an ISO time (one with no zone is UTC); None when it is none (or no
    time a float can hold)."""
    if value is None or isinstance(value, bool) or value == "":
        return None
    try:
        if isinstance(value, (int, float)):
            t = float(value)
        elif isinstance(value, datetime):
            t = (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).timestamp()
        else:
            s = str(value).strip()
            if len(s) > 64:  # no time is written longer
                return None
            try:
                t = float(s)
            except ValueError:
                d = datetime.fromisoformat(s.replace("Z", "+00:00"))
                t = (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()
    except (OverflowError, ValueError, OSError):
        return None
    return t if math.isfinite(t) else None


def _port(value) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return port if 0 < port < 65536 else None


def _count(value) -> int:
    try:
        n = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return int(n) if math.isfinite(n) and n > 0 else 0


def _asn(value) -> int | None:
    s = str(value or "").strip().upper()
    s = s[2:].strip() if s.startswith("AS") else s
    if len(s) > 10 or not (s.isascii() and s.isdigit()):  # ASCII digits only ("²" is a digit int() refuses)
        return None
    n = int(s)
    return n if 0 < n < 2**32 else None


def _clip(value, most: int) -> str:
    """A flow's words, stripped, `most` characters of them at the most (a longer one cut there)."""
    s = value if isinstance(value, str) else str(value or "")
    if len(s) > most:
        s = s.lstrip()[:most]
    return s.strip()


def _group(value) -> str | None:
    s = value if isinstance(value, str) else str(value or "")
    s = s.strip().lower() if len(s) <= MAX_REMOTE else ""  # a longer one is no group: the address's is taken
    if not s:
        return None
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError:
        return s


@dataclass
class _Flow:
    """A flow as the baseline reads it."""
    dir: str
    remote: str  # the peer's address ("" when the flow gave none)
    peer: str | None  # its group
    port: str | None  # the port served ("in tcp/3389") or reached ("out tcp/8443")
    port_words: str
    program: str | None  # casefolded: a key
    program_words: str
    country: str | None
    asn: int | None
    org: str
    start: float | None
    end: float | None
    first: float  # its start, else when it was seen
    at: float  # when it was seen: its end, else its start, else now
    bytes: int
    identity: tuple | None  # who it is, to know it when told again (None: no start, never known again)

    def keys(self) -> list[tuple[str, str]]:
        out = []
        if self.peer:
            out.append(("peer", f"peer:{self.peer}"))
        if self.port:
            out.append(("port", f"port:{self.port}"))
        if self.program:
            out.append(("program", f"program:{self.program}"))
        if self.country:
            out.append(("country", f"country:{self.country}"))
        if self.asn:
            out.append(("asn", f"asn:{self.asn}"))
        return out


def _read(flow, now: float) -> _Flow | None:
    """A flow dict read, None when it is no flow or the machine talking to itself (dir "local", a loopback peer). A
    time more than FUTURE_S ahead of `now` is taken as `now`."""
    if not isinstance(flow, dict):
        return None
    direction = _clip(flow.get("dir"), MAX_WORD).lower()
    ip = _address(flow.get("remote"))
    if direction == "local" or (ip is not None and (ip.is_loopback or ip.is_unspecified)):
        return None
    remote = str(ip) if ip is not None else _clip(flow.get("remote"), MAX_REMOTE).lower()
    peer = _group(flow.get("remote_group")) or (group_of(ip) if ip is not None else remote or None)
    proto = _clip(flow.get("proto"), MAX_WORD).lower()
    local_port, remote_port = _port(flow.get("local_port")), _port(flow.get("remote_port"))
    port = local_port if direction == "in" else remote_port if direction == "out" else None
    port_name = f"{port}/{proto}" if proto and port else str(port or "")
    program_words = _clip(flow.get("program"), MAX_PROGRAM)
    country = _clip(flow.get("country"), MAX_COUNTRY).upper() or None
    start, end = (_ahead(_time(flow.get(k)), now) for k in ("start", "end"))
    if start is not None and end is not None and end < start:
        end = start
    at = end if end is not None else start if start is not None else now
    return _Flow(
        dir=direction, remote=remote, peer=peer,
        port=f"{direction} {proto + '/' if proto else ''}{port}" if port else None,
        port_words=("in on port " if direction == "in" else "out to port ") + port_name if port else "",
        program=program_words.casefold() or None, program_words=program_words, country=country,
        asn=_asn(flow.get("asn")), org=_clip(flow.get("org"), MAX_ORG),
        start=start, end=end, first=start if start is not None else at, at=at, bytes=_count(flow.get("bytes")),
        identity=(direction, remote, local_port, remote_port, proto, program_words.casefold(), start)
        if start is not None else None)


def _ahead(t: float | None, now: float) -> float | None:
    return now if t is not None and t > now + FUTURE_S else t


# -- words -----------------------------------------------------------------------------------------------------------

def _size(n: float) -> str:
    for unit, scale in (("GB", 2**30), ("MB", 2**20), ("KB", 2**10)):
        if n >= scale:
            return f"{n / scale:.1f} {unit}"
    return f"{n:.0f} bytes"


def _span(seconds: float) -> str:
    s = max(0.0, float(seconds))
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 60:
        return f"{s:.1f} s" if s < 10 else f"{s:.0f} s"
    if s < 3600:
        return f"{s // 60:.0f} min"
    return f"{s // 3600:.0f} h {s % 3600 // 60:.0f} min"


def _iso(t: float | None) -> str | None:
    return None if t is None else datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds")


# -- a port's minutes -------------------------------------------------------------------------------------------------

def _bump(buckets: deque, key: int, n: int) -> None:
    """`n` added to the bucket `key`, the buckets kept in order (the newest last): a late one goes in its place (the
    oldest dropped when they are full), and one older than every bucket kept is counted only while there is room."""
    if buckets and buckets[-1][0] == key:
        buckets[-1][1] += n
        return
    if not buckets or buckets[-1][0] < key:
        buckets.append([key, n])
        return
    for i in range(len(buckets) - 2, -1, -1):
        k = buckets[i][0]
        if k == key:
            buckets[i][1] += n
            return
        if k < key:
            if len(buckets) == buckets.maxlen:
                buckets.popleft()
                i -= 1
            buckets.insert(i + 1, [key, n])
            return
    if len(buckets) < buckets.maxlen:
        buckets.appendleft([key, n])


class _Port:
    """A port's bytes: in steps of STEP_S seconds for the last minute, by minute for what is usual (busy minutes only:
    a minute without traffic says nothing of how much the port carries when it is used)."""
    __slots__ = ("steps", "minutes")

    def __init__(self):
        self.steps: deque = deque(maxlen=60 // STEP_S + 2)  # [step, bytes]
        self.minutes: deque = deque(maxlen=SPIKE_MINUTES + 2)  # [minute, bytes]

    def add(self, t: float, n: int) -> None:
        _bump(self.steps, int(t // STEP_S), n)
        _bump(self.minutes, int(t // 60), n)

    def last_minute(self, t: float) -> int:
        """The bytes of the minute up to `t`, in whole steps (the step that holds t - 60 left out)."""
        first, last = int((t - 60) // STEP_S) + 1, int(t // STEP_S)
        return sum(n for k, n in self.steps if first <= k <= last)

    def usual(self, t: float) -> list[int]:
        """The busy minutes wholly before the last minute, the latest SPIKE_MINUTES of them."""
        before = math.floor((t - 60) / 60)
        return [n for m, n in self.minutes if m < before][-SPIKE_MINUTES:]


# -- the baseline -------------------------------------------------------------------------------------------------

class Baseline:
    """What is usual here, in one SQLite file at `path`: the seen table, at most `cap` learned rows (the ones longest
    unseen pruned first) and two rows of the watching itself (kind "watch": since when, until when, how long, and when
    the learning was done). In memory, all bounded: the spells of watching (MAX_SPANS), the flows told lately
    (MAX_FLOWS), the ports' minutes (MAX_PORTS) and the one-offs and spikes judged (MAX_KEPT). One connection, opened
    at the first call that watches, remembers or flags and kept to `close()` (a call that only reads what is learned
    opens it for that read alone); every call holds one lock, so the watcher's thread and the page's may share it.
    `clock` gives the time now (epoch seconds), `learn_s` the watching learned before anything is flagged."""

    def __init__(self, path, cap: int = CAP, learn_s: float = LEARN_S, clock=time.time):
        self.path = Path(path)
        self.cap = max(1, int(cap))
        self.learn_s = float(learn_s)
        self.clock = clock
        self.note = ""  # what happened to a file that could not be read
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._loaded = False
        self._rows = 0
        self._forget()

    def _forget(self) -> None:
        """Nothing learned yet, in memory (a new file)."""
        self._since: float | None = None  # the first moment watched
        self._last: float | None = None  # the latest moment watched
        self._watched = 0.0  # seconds watched, all told
        self._learned_at: float | None = None  # when the watching reached learn_s: flows from then on are judged
        self._spans: deque = deque(maxlen=MAX_SPANS)  # [from, to]: the spells of watching seen by this object
        self._flows: OrderedDict = OrderedDict()  # identity -> bytes counted
        self._ports: OrderedDict = OrderedDict()  # port key -> _Port
        self._kept: OrderedDict = OrderedDict()  # identity -> {flag id: Flag}: a one-off or a spike, once judged

    # -- the file ------------------------------------------------------------------------------------------------
    def __enter__(self) -> Baseline:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        """The file closed (what is learned is kept); the next call opens it again."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10, isolation_level=None, check_same_thread=False)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, kind TEXT NOT NULL, "
                         "first REAL NOT NULL, last REAL NOT NULL, count INTEGER NOT NULL, again REAL)")
            if not self._has_again(conn):  # a file from before `again` was kept: the column added, empty
                try:
                    conn.execute("ALTER TABLE seen ADD COLUMN again REAL")
                except sqlite3.OperationalError:
                    if not self._has_again(conn):  # not another connection adding it at the same moment
                        raise
            conn.execute("CREATE INDEX IF NOT EXISTS seen_last ON seen (last)")
            conn.execute("SELECT COUNT(*) FROM seen").fetchone()
        except BaseException:
            conn.close()
            raise
        return conn

    @staticmethod
    def _has_again(conn: sqlite3.Connection) -> bool:
        return any(row[1] == "again" for row in conn.execute("PRAGMA table_info(seen)"))

    def _set_aside(self, error: Exception) -> None:
        """A file that is no database moved aside (one copy, <name>.bad), so the learning starts anew."""
        bad = self.path.with_name(self.path.name + ".bad")
        os.replace(self.path, bad)
        for extra in ("-wal", "-shm"):
            try:
                os.remove(f"{self.path}{extra}")
            except OSError:
                pass
        self.note = (f"The baseline kept could not be read ({error}): it was set aside as {bad.name}, and learning "
                     f"starts anew.")

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fresh = not self.path.exists()
            try:
                conn = self._connect()
            except sqlite3.DatabaseError as e:
                if isinstance(e, sqlite3.OperationalError) or fresh:
                    raise
                self._set_aside(e)
                conn = self._connect()
                fresh = True
            try:
                if fresh or not self._loaded:  # a new file holds nothing learned, whatever this object had seen
                    self._forget()
                    self._load(conn)
                self._rows = self._count(conn)
            except BaseException:
                conn.close()
                raise
            self._conn = conn
        return self._conn

    @staticmethod
    def _count(conn: sqlite3.Connection) -> int:
        return conn.execute("SELECT COUNT(*) FROM seen WHERE kind != ?", (WATCH,)).fetchone()[0]

    def _load(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT first, last, count FROM seen WHERE key = ?", (_TIME,)).fetchone()
        if row:
            self._since, self._last, self._watched = float(row[0]), float(row[1]), float(row[2])
        row = conn.execute("SELECT first FROM seen WHERE key = ?", (_LEARNED,)).fetchone()
        if self._watched >= self.learn_s:
            self._learned_at = float(row[0]) if row else self._last
        self._loaded = True

    def _transaction(self, conn: sqlite3.Connection, write) -> None:
        conn.execute("BEGIN IMMEDIATE")
        try:
            write(conn)
            conn.execute("COMMIT")
        except BaseException:
            try:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                self._rows = self._count(conn)
            except sqlite3.Error:  # the first error is the one to tell
                pass
            raise

    # -- the watching ------------------------------------------------------------------------------------------------
    def _account(self, t: float) -> None:
        """The moment `t` watched: the time since the latest moment counts when it is GAP_S or less."""
        last = self._last
        if last is None or t - last > GAP_S:  # a new spell of watching: the pause before it is not counted
            self._spans.append([t, t])
            self._last = t
            if self._since is None:
                self._since = t
        elif t > last:
            self._watched += t - last
            if self._spans and self._spans[-1][1] == last:
                self._spans[-1][1] = t
            else:
                self._spans.append([last, t])
            self._last = t
        if self._learned_at is None and self._watched >= self.learn_s:
            self._learned_at = self._last

    def _save_watch(self, conn: sqlite3.Connection) -> None:
        if self._since is None:
            return
        conn.execute("INSERT OR REPLACE INTO seen (key, kind, first, last, count) VALUES (?, ?, ?, ?, ?)",
                     (_TIME, WATCH, self._since, self._last, self._watched))
        if self._learned_at is not None:
            conn.execute("INSERT OR REPLACE INTO seen (key, kind, first, last, count) VALUES (?, ?, ?, ?, ?)",
                         (_LEARNED, WATCH, self._learned_at, self._learned_at, self.learn_s))

    def _watched_between(self, a: float, b: float) -> float:
        """The seconds watched between `a` and `b`, over the spells this object has seen."""
        return sum(max(0.0, min(end, b) - max(start, a)) for start, end in self._spans)

    def _learned(self) -> bool:
        return self._watched >= self.learn_s and self._learned_at is not None

    def watch(self, now: float | None = None) -> None:
        """Liminal is watching at `now` (the tab was asked; the clock's time when None): the time since the latest
        moment counts toward the learning, flows or none; a moment given before the latest counts nothing. The clock
        read going back (set right after running ahead: more than GAP_S before the latest moment, past the FUTURE_S a
        flow's time may run ahead of it) goes on from its new time, as a new spell of watching, and what was learned
        "later" is taken as learned then (`_went_back`)."""
        with self._lock:
            conn = self._db()
            t = self.clock() if now is None else float(now)
            if not math.isfinite(t):
                return
            # the latest moment may be a flow's, up to FUTURE_S ahead of the clock that read it: the clock only reading
            # behind such a moment is the flow source's lead, not the clock going back
            back = now is None and self._last is not None and t < self._last - GAP_S - FUTURE_S
            if back:
                self._went_back(t)
            self._account(t)

            def write(c: sqlite3.Connection) -> None:
                if back:
                    c.execute("UPDATE seen SET first = min(first, ?), last = ?, "
                              "again = CASE WHEN again > ? THEN ? ELSE again END WHERE kind != ? AND last > ?",
                              (t, t, t, t, WATCH, t))
                self._save_watch(c)

            self._transaction(conn, write)

    def _went_back(self, t: float) -> None:
        """The clock went back to `t`: the watching goes on from there, a learning done after it is done at it, and
        what memory holds of the time after it (spells, ports' minutes, judgments) is let go. The rows seen after it
        are taken as seen at it (in `watch`'s write), so the peers they hold are not new to the flows that follow."""
        self._last = None
        self._since = t if self._since is None else min(self._since, t)
        if self._learned_at is not None:
            self._learned_at = min(self._learned_at, t)
        self._spans.clear()
        self._ports.clear()
        self._kept.clear()

    @contextmanager
    def _reading(self):
        """What is learned, for a call that only reads it: from the file open, or from the file opened for this read
        alone and closed again after it (a read keeps no file open while nothing watches), or nothing learned when
        there is no file (none is made for a read)."""
        if self._conn is not None:
            yield
            return
        if not self.path.exists():
            self._forget()
            self._rows = 0
            yield
            return
        self._db()
        try:
            yield
        finally:
            self.close()

    def learning(self) -> tuple[float, float | None]:
        """(seconds watched, since when: epoch seconds, None before any watching). Nothing is flagged until the
        seconds reach learn_s (30 minutes): `describe` says so in words."""
        with self._lock, self._reading():
            return self._watched, self._since

    @property
    def learned(self) -> bool:
        """Whether learn_s of watching are learned: flows from then on are judged."""
        with self._lock, self._reading():
            return self._learned()

    @property
    def rows(self) -> int:
        """Learned rows kept (at most cap)."""
        with self._lock, self._reading():
            return self._rows

    def describe(self) -> dict:
        """The learning in words, for the page: learned, watched, needed, since, learned_at, rows, cap and words."""
        with self._lock, self._reading():
            watched, since, learned = self._watched, self._since, self._learned()
            if learned:
                words = (f"Learned from {_span(watched)} of watching since {_iso(since)}: a flag says what is "
                         f"{UNUSUAL}.")
            else:
                words = (f"Learning what is usual for this machine: {watched // 60:.0f} of {self.learn_s / 60:.0f} "
                         f"minutes watched. Nothing is flagged until then.")
            return {"learned": learned, "watched": round(watched, 1), "needed": self.learn_s, "since": _iso(since),
                    "learned_at": _iso(self._learned_at) if learned else None, "rows": self._rows, "cap": self.cap,
                    "words": words + (f" {self.note}" if self.note else "")}

    # -- remembering -----------------------------------------------------------------------------------------------
    def remember(self, flow: dict) -> None:
        """A flow learned: each of its keys seen (first, last, count), the watching counted to its time, its bytes
        added to its port's minutes; the rows over the cap pruned, the ones longest unseen first."""
        with self._lock:
            f = _read(flow, self.clock())
            if f is not None:
                self._remember(f)

    def _remember(self, f: _Flow) -> None:
        conn = self._db()
        known = f.identity is not None and f.identity in self._flows
        counted = self._flows.get(f.identity, 0) if known else 0
        self._account(f.at)

        def write(c: sqlite3.Connection) -> None:
            for kind, key in f.keys():
                if c.execute("INSERT OR IGNORE INTO seen (key, kind, first, last, count) VALUES (?, ?, ?, ?, 1)",
                             (key, kind, f.first, f.at)).rowcount:
                    self._rows += 1
                elif known:  # the same flow told again: seen until later, by no other flow
                    c.execute("UPDATE seen SET first = min(first, ?), last = max(last, ?) WHERE key = ?",
                              (f.first, f.at, key))
                else:  # another flow: `again` is when the second of its flows began (the second-earliest first),
                    # so a long or a told-again flow after the first never moves it (a row from before `again` was
                    # kept, seen twice already, keeps none: when it was seen again is not known)
                    c.execute("UPDATE seen SET again = CASE WHEN count = 1 THEN max(first, ?) "
                              "WHEN again IS NULL THEN NULL ELSE min(again, max(first, ?)) END, "
                              "first = min(first, ?), last = max(last, ?), count = count + 1 WHERE key = ?",
                              (f.first, f.first, f.first, f.at, key))
            self._save_watch(c)
            if self._rows > self.cap:
                self._prune(c)

        self._transaction(conn, write)
        added = f.bytes - counted
        if f.port and added > 0:
            port = self._ports.get(f.port)
            if port is None:
                port = self._ports[f.port] = _Port()
                while len(self._ports) > MAX_PORTS:
                    self._ports.popitem(last=False)
            self._ports.move_to_end(f.port)
            port.add(f.at, added)
        if f.identity is not None:
            self._flows[f.identity] = max(counted, f.bytes)
            self._flows.move_to_end(f.identity)
            while len(self._flows) > MAX_FLOWS:
                self._flows.popitem(last=False)

    def _prune(self, conn: sqlite3.Connection) -> None:
        """Back under the cap (a hundredth under it, so a prune is not every row's), the rows longest unseen first."""
        rows = self._count(conn)
        excess = rows - (self.cap - self.cap // 100)
        if excess > 0:
            conn.execute("DELETE FROM seen WHERE key IN "
                         "(SELECT key FROM seen WHERE kind != ? ORDER BY last, key LIMIT ?)", (WATCH, excess))
        self._rows = self._count(conn)

    # -- flags -----------------------------------------------------------------------------------------------------
    def flags(self, flow: dict) -> list[Flag]:
        """What is unusual about a flow, judged against what was learned before it: none until learn_s of watching
        are learned, none for a flow that started while learning. Asked again later for a flow still shown, it says
        the same, and a one-off once its 10 watched minutes have passed."""
        with self._lock:
            f = _read(flow, self.clock())
            if f is None:
                return []
            self._db()
            return self._flags(f) if self._learned() and f.first >= self._learned_at else []

    def observe(self, flow: dict) -> list[Flag]:
        """`flags(flow)`, then `remember(flow)`, under one lock: the flags a new flow brings."""
        with self._lock:
            f = _read(flow, self.clock())
            if f is None:
                return []
            self._db()
            out = self._flags(f) if self._learned() and f.first >= self._learned_at else []
            self._remember(f)
            return out

    def _flags(self, f: _Flow) -> list[Flag]:
        conn = self._db()
        keys = [key for _, key in f.keys()]
        rows: dict[str, tuple] = {}
        if keys:
            marks = ",".join("?" * len(keys))
            rows = {r[0]: r[1:] for r in conn.execute(
                f"SELECT key, first, last, count, again FROM seen WHERE key IN ({marks})", keys)}

        def new(key: str) -> bool:  # never seen before this flow (only by it or by later flows)
            row = rows.get(key)
            return row is None or row[0] >= f.first

        out = []
        peer_new = bool(f.peer) and new(f"peer:{f.peer}")
        if peer_new:
            shown = f" ({f.remote})" if f.remote and f.remote != f.peer else ""
            out.append(Flag("new-peer", f"First contact with {f.peer}{shown}: {UNUSUAL}."))
        if f.port and new(f"port:{f.port}"):
            out.append(Flag("new-port", f"Traffic {f.port_words} for the first time: {UNUSUAL}."))
        if f.program and new(f"program:{f.program}"):
            out.append(Flag("new-program", f"{f.program_words} on the network for the first time: {UNUSUAL}."))
        if f.country and new(f"country:{f.country}"):
            out.append(Flag("new-country", f"First traffic with a peer in {f.country}: {UNUSUAL}."))
        if f.asn and new(f"asn:{f.asn}"):
            org = f" ({f.org})" if f.org else ""
            out.append(Flag("new-asn", f"First traffic with the network AS{f.asn}{org}: {UNUSUAL}."))
        kept = self._kept.get(f.identity, {}) if f.identity is not None else {}
        one_off = kept.get("one-off")
        if one_off is None and peer_new and self._one_off(f, rows.get(f"peer:{f.peer}")):
            one_off = self._keep(f, Flag(
                "one-off", f"One short connection ({_span(f.end - f.start)}) with {f.remote or f.peer}, a peer not "
                           f"seen before and not again in the {_span(ONE_OFF_S)} watched after it: {UNUSUAL}."))
        if one_off is not None:
            out.append(one_off)
        spike = kept.get("spike")
        if spike is None:
            spike = self._spike(f)
            if spike is not None:
                self._keep(f, spike)
        if spike is not None:
            out.append(spike)
        return out

    def _keep(self, f: _Flow, flag: Flag) -> Flag:
        """A one-off or a spike judged, kept for when the flow is asked again (MAX_KEPT flows, the latest)."""
        if f.identity is not None:
            kept = self._kept.get(f.identity)
            if kept is None:
                kept = self._kept[f.identity] = {}
                while len(self._kept) > MAX_KEPT:
                    self._kept.popitem(last=False)
            kept[flag.id] = flag
            self._kept.move_to_end(f.identity)
        return flag

    def _one_off(self, f: _Flow, row: tuple | None) -> bool:
        """Short (SHORT_S or less), its peer seen by no flow before it, and ONE_OFF_S watched after it ended before
        the peer was seen again: never, or by a flow that began only after those minutes (the row's `again`, when
        the second of its flows began: however long that flow lasts, and however many come after it)."""
        if f.start is None or f.end is None or f.end - f.start > SHORT_S:
            return False
        again = None
        if row is not None:
            first, _last, count, again = row
            if first < f.start:
                return False
            if first > f.start:  # every flow of the row began after this one (it was not remembered): seen again then
                again = first
            elif count == 1:  # this flow alone
                again = None
            elif again is None:  # seen again, when not known (a row from before `again` was kept): no one-off
                return False
        return self._watched_between(f.end, math.inf if again is None else again) >= ONE_OFF_S

    def _spike(self, f: _Flow) -> Flag | None:
        """Its port's bytes in the last minute (this flow's with them) at least SPIKE_X times the port's usual
        minute, the median of its latest busy minutes (at least SPIKE_MIN_MINUTES of them), and SPIKE_FLOOR or more."""
        if not f.port:
            return None
        port = self._ports.get(f.port)
        if port is None:
            return None
        counted = self._flows.get(f.identity, 0) if f.identity is not None else 0
        now = port.last_minute(f.at) + max(0, f.bytes - counted)
        usual = port.usual(f.at)
        if len(usual) < SPIKE_MIN_MINUTES or now < SPIKE_FLOOR:
            return None
        median = statistics.median(usual)
        if median <= 0 or now < SPIKE_X * median:
            return None
        return Flag("spike", f"{_size(now)} {f.port_words} in the last minute, {now / median:.0f} times its usual "
                             f"{_size(median)} a minute: {UNUSUAL}.")
