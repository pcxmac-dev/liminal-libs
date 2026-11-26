"""The hosts database: which program talked with which remote host, for the firewalls' Netstat tab and the globe's
filters (the user, 2026-11-16: "the firewall app should also have a globe that can be zoomed and rotated and geoip'd
hosts are databased for the apps they talk to, the time they are connected to *this *computer"; "the globe-firewall
should allow filtering, so i can view apps connected to hosts all across the globe, or ports talking to all hosts").

One small SQLite file for each system, on its own disk (`path`: hosts/hosts.db in the data folder). A row of its hosts
table is a program, a remote host, a protocol, the service's port and a direction. It keeps the program's path and
service, whether the host is on the internet or the local network, the host's name where the system knows one, the
first and the last time seen, the seconds connected, how many connections, and the host's place once a GeoIP file on
this machine gave one (`place`). At most CAP rows, the ones longest unseen pruned first: about 13 MB with ordinary
values. A text is cut to 128 characters, a path to 260. This machine's own connections are never kept, and a local
host has no place, ever.

It is fed from readings of the socket table a few seconds apart (sockets.read, judged by sockets.judge; a judged row
is a plain dict here): no capture, no elevation, no lookup of any name, and nothing sent anywhere. Each reading is fed
once, in the order the readings were taken: whoever reads, judges and feeds holds one lock over the three, and a
reading taken before the last one fed, or that one again, is set aside (STALE_S). What a reading does
(`HostBook.feed`), `t` being its time and `prev` the time of the reading before it (none in a new file):
1. A row counts when it has a remote host on the local network or the internet and is up: TCP in one of UP's states,
   UDP "connected". A connection is known again by its key: the protocol and both ends, then, where the system says
   when a socket began (Windows), its pid and that start, and elsewhere (Linux) the socket's inode. One listed with no
   owner yet (Linux: no inode before it is accepted) is the same connection once it has one.
2. A key not open is a new connection: its row's connections go up by one. Where the system says starts its time
   counts from the later of its start and `prev`, and none of the sleep since `prev` is counted: for a socket begun
   since, the sleep is taken as after its start unless it fits only before it (a socket begins while the system is
   awake). With no two awake readings (a new file, a restart, a forget) its time is never longer than the awake clock
   says the system has been awake. Elsewhere it counts from `t`.
3. A key already open adds the time since it was last seen, and no connection. That time is the lesser of the wall
   clock's and the awake clock's (the reading's `awake`: a clock that does not count sleep), so a night asleep is not
   time connected, and nothing when the awake clock went back (the system restarted). Where the system says no
   starts, or a reading has no awake clock, a gap longer than GAP_S adds nothing. Time is added only while a row is
   "established" (UDP: "connected"): a connection the far end has hung up stays open and adds nothing.
4. A key open and not in the reading has ended: nothing is added past its last reading. Only the keys of a table the
   reading read whole end (`read`), and none in a reading whose rows were cut (`cut`), so a table that failed once
   does not count its connections again.
5. The open connections are in the file too, so across a restart rule 3 goes on where it stopped. Nothing is counted
   twice: a new key never counts time before `prev`.
A TCP row its owner has let go of while it closes (time-wait; or fin-wait-1, fin-wait-2, closing and last-ack with no
owner: no inode on Linux, no pid on Windows) still names its two ends. If they are no open key's, it is a connection
that began and ended between two readings, named by its host and not its program: it is counted once under
NOT_NAMED, with no time, and held until it leaves the table. One whose key ended in this reading or the last was
counted under its program already; the last is the first reading NEAR_S or more after the one where its key ended, so
another view's reading just after that one is not taken for it. A clock set back adds nothing negative: the reading's
time becomes every open key's and every pending row's. Past MAX_OPEN connections open at once, one more is neither
held nor counted, and `describe` says how many, and whether the last reading was cut.

Readings are added up in memory and written by `flush`, in one transaction: at each ask while a tab is shown, every
FLUSH_S when recording runs all the time (the Netstat view decides which: `VARIABLE`, a setting kept through the
login), and by a reading itself past MAX_PENDING rows waiting. The queries read what was last written: `hosts`,
`programs`, `ports`, and `places` for the globe, grouped by point in the query. A call that only reads makes no file
and leaves none open.

The file is this system's own: on a folder of another system's drive (`foreign`: WSL's /mnt/c, a share, a network
drive) nothing is made, read or written, and `describe` says why. It is opened directly, never through the link
(storage/link.py reaches another system's file through that system, and a hosts database is never another
system's). A file SQLite finds damaged, or no database at all, is set aside as hosts.db.bad when that is found, and
recording starts anew. `forget` leaves nothing it removed in the file (it is built anew from what is left, and its log
emptied), and a copy set aside goes with it. `book` hands out one HostBook for a path in a process, so two views feed
one book under one lock. Off Windows the folder is made for this account alone (0700) and the file too (0600): it
lists every program's hosts.

1.68.0, every connection (the user, 2026-11-20: "all connections need to be databased, basically who, what, when,
why,where"): beside the hosts' rows, which fold a program's connections to a host and a port into one, the table
`connections` keeps each connection as its own row, from the reading that first counts it (rule 2) to the first
reading without it (rule 4): who (the program, its path, its process, its user, its service and the service's
title), what (the protocol and family, both ends, the direction, the service's port, the host's name where the
system knows one), when (its start where the system says one, first and last seen, when it was gone, the seconds
connected, counted as the hosts' are), why (`why_of`: in words, from what this machine knows: which way it goes,
the port and what this system's services file says it is for, the service behind it) and where (the local network
or the internet; the place, network and owner the GeoIP file gives, looked up as the hosts' are by `place`). A row
waiting to close that no open connection had is a connection that began and ended between two readings: kept under
NOT_NAMED, gone as soon as it is seen. Its id (`_cid`) is its key and when it was first counted, so a connection
open across a restart goes on in the same row. The table `routes` keeps the route traced to each host
(machines/routes.py, by `keep_route`): when, whether it reached the host, how, its hops and the places on its way;
`connections` hands each connection out with its host's route. At most CONNECTIONS connections, the ones that
ended longest ago pruned first, none kept past KEEP_DAYS after it ended; at most ROUTES routes, none past ROUTE_DAYS.
`forget` forgets them with the hosts."""
from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import threading
import time
from collections.abc import Mapping
from pathlib import Path

from . import geo, layout
from .sources.keys import KeyVar

FOLDER = "hosts"  # in layout.data_dir(): one file for each system, on its own disk
FILE = "hosts.db"
VERSION = 1  # the file's layout, kept in its meta table
CAP = 50_000  # rows kept (about 13 MB with ordinary values): the ones longest unseen are pruned first
CONNECTIONS = 500_000  # connections kept, a row each (about 150 MB with ordinary values): the oldest ended pruned first
KEEP_DAYS = 90  # a connection that ended longer ago than this is let go
ROUTES = 20_000  # routes kept, one a host: the ones traced longest ago pruned first
ROUTE_DAYS = 30  # a route traced longer ago than this is let go
ROUTES_OF = 256  # 1.74.1: the hosts whose kept routes one read hands back, at most
# 1.74.0 (the user, 2026-11-22: "all routes need to be saved in a database for now"): every trace kept, each its
# own row of `traces`, however often a host is traced again and however long ago; TRACES of them at most, the
# ones traced longest ago let go first (about 2 kB a trace: some 1 GB at the most)
TRACES = 500_000
CONNECTION_ROWS = 2_000  # connections `connections` hands out at the most
WHY = 300  # characters kept of a connection's why
MAX_OPEN = 8192  # connections held open at once, the ones waiting to close among them: one more is not counted
GAP_S = 30.0  # without the system's word on starts, or an awake clock, a longer gap between two readings adds no time
FLUSH_S = 30.0  # recording all the time: what is pending is written this often (the Netstat view's thread)
ALWAYS_S = 5.0  # recording all the time: the socket table is read this often
STALE_S = 10.0  # a reading taken before the last one fed, by this much at most (the awake clock's word, where there
# is one): two feeders' readings handed over out of turn, set aside. Further back, the clock went back.
NEAR_S = 2.5  # readings closer than this are one look at the table (the socket reader's READ_S: a view shares a
# reading this young), so another view's reading this soon after the one where a connection ended is not "the last"
MAX_PENDING = 2000  # rows waiting to be written: past this a reading writes them itself
# the rows are counted by each write itself; the hosts and the programs are counted again by a write that added or
# removed rows while the file holds COUNT_ROWS rows or fewer (a few ms), and past that at most every COUNT_S of the
# readings' time (at the cap the count takes about 25 ms, and a shown tab writes every few seconds)
COUNT_ROWS = 10_000
COUNT_S = 60.0
QUERY_ROWS = 20_000  # rows `hosts` hands out at the most
PLACE_ROWS = 512  # rows `place` looks up in one call
PLACES = 300  # places `places` hands out when not told (the globe draws as many: world.MAX_DRAWN)
MAX_PLACES = 512  # ... and at the very most (as many as the globe reads)
PLACE_PROGRAMS = 8  # programs named for a place, the ones with the most connections
PLACE_PORTS = 16  # ports named for a place, the ones with the most connections
POINTS = MAX_PLACES  # places asked for their programs and ports in one statement (two values each, as many as the
# connection's own limit of values lets one statement take)
TEXT = 128  # characters kept of a program, a host, a service, a name or a place's words (as geo.TEXT)
PATH = 260  # characters kept of a program's path
CODE = 8  # characters kept of a country's code (as geo.CODE)
STAMP = 32  # characters kept of a GeoIP file's date
# 1.102.0 (Monday list item 20): characters kept of a place's stamp, the GeoIP files it came from (machines/geosources:
# the default source's date, as before, or #<places>:<date>+<networks>:<date>); a row is placed again whenever its stamp
# is not the one of the files in use
PLACE_STAMP = 64
FOLDER_MODE, FILE_MODE = 0o700, 0o600  # off Windows: this account's alone
NOT_NAMED = "?"  # the program of a connection whose program could not be read
VARIABLE = "LIMINAL_HOSTS_RECORDING"  # the setting, kept through the login: one of MODES
# only while this plugin's Netstat or World Wide Web tab is shown (the default), or all the time the platform runs
MODES = ("shown", "always")
HOSTS_KEY = KeyVar(VARIABLE, label="Recording hosts", secret=False,
                   hint="optional: always records every program's remote hosts all the time the platform runs (a "
                        "reading of the socket table every 5 s); shown, or nothing, only while this plugin's Netstat "
                        "or World Wide Web tab is shown")
TABLES = ("tcp4", "tcp6", "udp4", "udp6")  # a reading's tables: a row's is its protocol and its family
# a TCP connection that is up: the same six words as sockets.UP (kept here, so a book needs no socket reader)
UP = frozenset({"established", "close-wait", "fin-wait-1", "fin-wait-2", "closing", "last-ack"})
# ... and of those, the ones a connection closes in: with no owner, its program has let go of it (Linux lists no inode
# for it, Windows no pid), and it waits to close as a time-wait row does
CLOSING = frozenset({"fin-wait-1", "fin-wait-2", "closing", "last-ack"})
CONNECTED = {"tcp": "established", "udp": "connected"}  # the one state of each protocol whose time is counted
WAITING = "time-wait"  # a TCP row waiting to close: its owner has ended, its two ends are still listed
INTERNET, LOCAL = "internet", "local"  # a row's network
NETWORKS = {"internet": INTERNET, "local network": LOCAL}  # by a judged row's `where` ("this machine" is never kept)
COLUMNS = ("program", "host", "proto", "port", "direction", "path", "service", "network", "name", "first", "last",
           "seconds", "connections", "country", "code", "city", "lat", "lon", "asn", "org", "placed")
CORRUPT, NOT_A_DATABASE = 11, 26  # SQLite's codes for a damaged file and for a file that is no database
CUT_WORDS = ("The socket table's last reading was cut, more sockets being listed than one reading takes: no "
             "connection ends while readings are cut, so the ones that ended stay open here until a reading is whole.")
_WORDS = ("country", "code", "city", "org", "placed")  # a row's texts that may be empty in the file: "" when handed out
_POSIX = os.name == "posix"
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS hosts (program TEXT NOT NULL, host TEXT NOT NULL, proto TEXT NOT NULL, "
    "port INTEGER NOT NULL, direction TEXT NOT NULL, path TEXT NOT NULL DEFAULT '', service TEXT NOT NULL DEFAULT '', "
    "network TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', first REAL NOT NULL, last REAL NOT NULL, "
    "seconds REAL NOT NULL DEFAULT 0, connections INTEGER NOT NULL DEFAULT 0, country TEXT, code TEXT, city TEXT, "
    "lat REAL, lon REAL, asn INTEGER, org TEXT, placed TEXT, "
    "PRIMARY KEY (program, host, proto, port, direction)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS hosts_last ON hosts (last)",
    "CREATE INDEX IF NOT EXISTS hosts_host ON hosts (host)",  # 1.68.0: a connection finds its host's place
    "CREATE TABLE IF NOT EXISTS open (key TEXT PRIMARY KEY, program TEXT NOT NULL, host TEXT NOT NULL, "
    "proto TEXT NOT NULL, port INTEGER NOT NULL, direction TEXT NOT NULL, started REAL, first REAL NOT NULL, "
    "last REAL NOT NULL, tbl TEXT NOT NULL, awake REAL, waiting INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value) WITHOUT ROWID",
    # 1.68.0: every connection, a row each, and the route traced to each host
    "CREATE TABLE IF NOT EXISTS connections (cid TEXT PRIMARY KEY, program TEXT NOT NULL, path TEXT NOT NULL DEFAULT "
    "'', pid INTEGER, user TEXT NOT NULL DEFAULT '', service TEXT NOT NULL DEFAULT '', service_title TEXT NOT NULL "
    "DEFAULT '', proto TEXT NOT NULL, family INTEGER, local TEXT NOT NULL DEFAULT '', local_port INTEGER, "
    "remote TEXT NOT NULL, remote_port INTEGER, direction TEXT NOT NULL, port INTEGER NOT NULL, network TEXT NOT "
    "NULL, name TEXT NOT NULL DEFAULT '', started REAL, first REAL NOT NULL, last REAL NOT NULL, ended REAL, "
    "seconds REAL NOT NULL DEFAULT 0, why TEXT NOT NULL DEFAULT '', country TEXT, code TEXT, city TEXT, lat REAL, "
    "lon REAL, asn INTEGER, org TEXT, placed TEXT) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS connections_first ON connections (first)",
    "CREATE INDEX IF NOT EXISTS connections_last ON connections (last)",
    "CREATE INDEX IF NOT EXISTS connections_remote ON connections (remote)",
    "CREATE TABLE IF NOT EXISTS routes (remote TEXT PRIMARY KEY, traced REAL NOT NULL, reached INTEGER NOT NULL, "
    "how TEXT NOT NULL DEFAULT '', hops TEXT NOT NULL, way TEXT NOT NULL DEFAULT '') WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS routes_traced ON routes (traced)",
    "CREATE TABLE IF NOT EXISTS traces (id INTEGER PRIMARY KEY, remote TEXT NOT NULL, traced REAL NOT NULL, "
    "reached INTEGER NOT NULL, how TEXT NOT NULL DEFAULT '', hops TEXT NOT NULL, way TEXT NOT NULL DEFAULT '')",
    "CREATE INDEX IF NOT EXISTS traces_remote ON traces (remote, traced)",
    "CREATE INDEX IF NOT EXISTS traces_traced ON traces (traced)")
# a connection's columns, as `_born` keeps them and `_CONN_INSERT` writes them, in this order
CONNECTION_COLUMNS = ("cid", "program", "path", "pid", "user", "service", "service_title", "proto", "family",
                      "local", "local_port", "remote", "remote_port", "direction", "port", "network", "name",
                      "started", "first", "last", "ended", "seconds", "why")
_LAST, _ENDED, _SECONDS = (CONNECTION_COLUMNS.index(c) for c in ("last", "ended", "seconds"))
_CONN_INSERT = (f"INSERT OR IGNORE INTO connections ({', '.join(CONNECTION_COLUMNS)}) "
                f"VALUES ({', '.join('?' * len(CONNECTION_COLUMNS))})")
_CONN_TOUCH = ("UPDATE connections SET last = CASE WHEN ? IS NULL THEN last ELSE max(last, ?) END, "
               "seconds = seconds + ?, ended = coalesce(?, ended) WHERE cid = ?")
_CONN_PLACE = ("UPDATE connections SET country = ?, code = ?, city = ?, lat = ?, lon = ?, asn = ?, org = ?, placed = ? "
               "WHERE remote = ? AND network = 'internet' AND (placed IS NULL OR placed <> ?)")
_ROUTE_KEEP = "INSERT OR REPLACE INTO routes (remote, traced, reached, how, hops, way) VALUES (?, ?, ?, ?, ?, ?)"
_TRACE_KEEP = "INSERT INTO traces (remote, traced, reached, how, hops, way) VALUES (?, ?, ?, ?, ?, ?)"  # 1.74.0
_CONN_PRUNE = ("DELETE FROM connections WHERE cid IN (SELECT cid FROM connections WHERE ended IS NOT NULL ORDER BY "
               "last LIMIT ?)")
# a new connection's place: its host's, where a hosts row of it has one (looked up by the index on host)
_CONN_HOSTS_PLACE = ("UPDATE connections SET (country, code, city, lat, lon, asn, org, placed) = (SELECT country, "
                     "code, city, lat, lon, asn, org, placed FROM hosts WHERE hosts.host = connections.remote AND "
                     "hosts.placed IS NOT NULL ORDER BY hosts.placed DESC LIMIT 1) WHERE cid = ? AND placed IS NULL "
                     "AND EXISTS (SELECT 1 FROM hosts WHERE hosts.host = connections.remote AND hosts.placed IS NOT "
                     "NULL)")
# 1.102.0: once the book knows the stamp of the files in use (place, unplaced), a new connection takes only a host's row
# placed by them: "#..." and "2026-..." sort by their letters, not by their age
_CONN_HOSTS_STAMPED = ("UPDATE connections SET (country, code, city, lat, lon, asn, org, placed) = (SELECT country, "
                       "code, city, lat, lon, asn, org, placed FROM hosts WHERE hosts.host = connections.remote AND "
                       "hosts.placed = ? LIMIT 1) WHERE cid = ? AND placed IS NULL AND EXISTS (SELECT 1 FROM hosts "
                       "WHERE hosts.host = connections.remote AND hosts.placed = ?)")
_KEY = "program = ? AND host = ? AND proto = ? AND port = ? AND direction = ?"  # a hosts row, by its key
_INSERT = ("INSERT OR IGNORE INTO hosts (program, host, proto, port, direction, path, service, network, name, first, "
           "last, seconds, connections) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
_UPDATE = ("UPDATE hosts SET path = CASE WHEN ? != '' THEN ? ELSE path END, "
           "service = CASE WHEN ? != '' THEN ? ELSE service END, network = ?, "
           "name = CASE WHEN ? != '' THEN ? ELSE name END, first = min(first, ?), last = max(last, ?), "
           f"seconds = seconds + ?, connections = connections + ? WHERE {_KEY}")
_PRUNE = ("DELETE FROM hosts WHERE (program, host, proto, port, direction) IN (SELECT program, host, proto, port, "
          "direction FROM hosts ORDER BY last, program, host, proto, port, direction LIMIT ?)")
_HOLD = ("INSERT INTO open (key, program, host, proto, port, direction, started, first, last, tbl, awake, waiting) "
         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
_PLACE = ("UPDATE hosts SET country = ?, code = ?, city = ?, lat = ?, lon = ?, asn = ?, org = ?, placed = ? "
          f"WHERE {_KEY}")
_FACTS = "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)"
# a hosts row the globe draws (an internet host with a point), one that has no point yet, the local network's
_DRAWN = f"(network = '{INTERNET}' AND lat IS NOT NULL AND lon IS NOT NULL)"
_UNPLACED = f"(network = '{INTERNET}' AND (lat IS NULL OR lon IS NULL))"
_LOCALS = f"(network != '{INTERNET}')"
_SECURE = {0: "OFF", 1: "ON", 2: "FAST"}  # PRAGMA secure_delete's answers, as it is told them


class ForgetRefused(ValueError):
    """The hosts recorded are not removed until the user says so a second time: `accept` names the argument that,
    exactly true, removes them; the platform's page asks it as a second, explicit confirmation."""

    accept = "accept_forget"


def path() -> Path:
    """The hosts database's file: hosts/hosts.db in the data folder (layout.data_dir()). One for each system, on its
    own disk."""
    return layout.data_dir() / FOLDER / FILE


def foreign(p=None) -> str:
    """Why the hosts database at `p` (the data folder's own when None) is not kept from here, in words; "" when it
    is. A folder on another system's drive (WSL's /mnt/c, a share, a network drive: geo.foreign) holds that system's
    files, and each system keeps its own hosts."""
    return geo.foreign(p if p is not None else path(), "Keeping the hosts database")


def _own() -> Path:
    return path()  # the module's `path`, where an argument of the same name hides it


_BOOKS: dict[str, "HostBook"] = {}  # the books handed out, by their resolved path
_BOOKS_LOCK = threading.Lock()


def book(path=None) -> HostBook:
    """The one HostBook of this process for `path` (the data folder's own when None), whichever way the path is
    spelled: every view feeds and reads it under its one lock, so two of them never count a connection or its time
    twice. A view never makes a HostBook of its own."""
    p = Path(path) if path is not None else _own()
    try:
        key = os.path.normcase(os.path.realpath(p))
    except (OSError, ValueError):  # a name that cannot be followed: by its spelling
        key = os.path.normcase(os.path.abspath(p))
    with _BOOKS_LOCK:
        found = _BOOKS.get(key)
        if found is None:
            found = _BOOKS[key] = HostBook(p)
        return found


def _broken(error) -> bool:
    """Whether SQLite's error says the file is damaged or no database at all (as opposed to one it could not reach
    or write now: locked, a full disk, an input or output error), so it is set aside."""
    if not isinstance(error, sqlite3.DatabaseError) or isinstance(error, sqlite3.OperationalError):
        return False
    code = getattr(error, "sqlite_errorcode", None)
    if isinstance(code, int):
        return (code & 0xFF) in (CORRUPT, NOT_A_DATABASE)
    return type(error) is sqlite3.DatabaseError  # what SQLite's two codes are raised as, where no code is told


# -- a judged row read ----------------------------------------------------------------------------------------------

def _clip(value, most: int = TEXT) -> str:
    """A row's words, stripped, `most` characters of them at the most (a longer one cut there)."""
    s = value if isinstance(value, str) else "" if value is None else str(value)
    return s.strip()[:most].strip()


def _number(value) -> float | None:
    """A time or a clock's reading as a float; None for what is none (a bool, a text, a number no float holds)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        value = float(value)
    except OverflowError:
        return None
    return value if math.isfinite(value) else None


def _whole(value, most: int | None = None) -> int:
    """A pid, an inode or a port: a whole number above 0 (and no more than `most`), else 0."""
    try:
        n = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return n if n > 0 and (most is None or n <= most) else 0


class _Row:
    """A judged row as the book reads it: its key (the protocol and both ends first), the table it was read from, the
    hosts row its connection and time go to, what that row keeps of the program, whether its time counts now
    (`counts`) or it only waits to close (`waiting`), and the key it would have with no owner (`bare`; None for a row
    that has none)."""
    __slots__ = ("key", "table", "row", "path", "service", "network", "name", "started", "counts", "waiting", "bare",
                 "who")

    def __init__(self, key, table, row, path, service, network, name, started, counts, waiting, bare=None, who=None):
        self.key, self.table, self.row, self.path, self.service = key, table, row, path, service
        self.network, self.name, self.started, self.counts, self.waiting = network, name, started, counts, waiting
        self.bare = bare
        # 1.68.0: the rest a connection's own row keeps: (pid, user, service title, local address, local port,
        # remote port, family, what the service's port is for)
        self.who = who or (0, "", "", "", 0, 0, 0, "")


def _row_of(row, starts: bool) -> _Row | None:
    """A judged row read (rule 1); None for one that is not kept: no remote, this machine's own, not up and not
    waiting to close. A row's owner is its pid where the system says starts (Windows), else its inode (Linux)."""
    if not isinstance(row, Mapping):
        return None
    proto, state = _clip(row.get("proto"), CODE).lower(), _clip(row.get("state"), STAMP).lower()
    owner = _whole(row.get("pid") if starts else row.get("inode"))
    waiting = proto == "tcp" and (state == WAITING or (state in CLOSING and not owner))
    if not waiting and not (state in UP if proto == "tcp" else proto == "udp" and state == CONNECTED["udp"]):
        return None
    where = row.get("where")
    network = NETWORKS.get(where) if isinstance(where, str) else None
    remote = _clip(row.get("remote"))
    if network is None or not remote:
        return None
    local = _clip(row.get("local"))
    local_port, remote_port = _whole(row.get("local_port"), 65535), _whole(row.get("remote_port"), 65535)
    direction = "in" if row.get("direction") == "in" else "out"
    port = _whole(row.get("port"), 65535) or (local_port if direction == "in" else remote_port)
    family = row.get("family")
    table = f"{proto}{family if family in (4, 6) else 6 if ':' in local else 4}"
    ends = (proto, local, local_port, remote, remote_port)
    fam = 6 if table.endswith("6") else 4
    if waiting:  # its owner has let go of it: the table names its host, not its program
        return _Row((*ends, "w"), table, (NOT_NAMED, remote, proto, port, direction), "", "", network,
                    _clip(row.get("name")), None, False, True,
                    who=(0, "", "", local, local_port, remote_port, fam, _clip(row.get("port_name"))))
    started = _number(row.get("started")) if starts and owner else None
    bare = (*ends, 0, None) if starts else (*ends, 0)
    key = (*ends, owner, started) if starts else (*ends, owner)
    program = _clip(row.get("program")) or NOT_NAMED
    return _Row(key, table, (program, remote, proto, port, direction), _clip(row.get("path"), PATH),
                _clip(row.get("service")), network, _clip(row.get("name")), started, state == CONNECTED[proto], False,
                bare if owner else None,
                who=(_whole(row.get("pid")), _clip(row.get("user")), _clip(row.get("service_title")), local,
                     local_port, remote_port, fam, _clip(row.get("port_name"))))


def why_of(r: _Row) -> str:
    """Why a connection is there, in words this machine can say without asking anyone: which way it goes, its
    service's port and what this system's services file says the port is for, whether the host is on the local network
    or the internet, and the service behind its program."""
    _program, _host, proto, port, direction = r.row
    named = r.who[7]  # sockets.judge's port_name
    words = f"{port}/{proto}" + (f" ({named})" if named else "")
    where = "the local network" if r.network == LOCAL else "the internet"
    if r.waiting:
        return _clip(f"a connection with {where} on {words} that began and ended between two readings: its "
                     "program had let go of it", WHY)
    said = (f"this machine answered a host on {where} on {words}" if direction == "in"
            else f"its program reached out to a host on {where} on {words}")
    title = r.who[2]
    if title or r.service:
        said += f", for the service {title or r.service}" + (f" ({r.service})" if title and r.service and
                                                              r.service != title else "")
    return _clip(said, WHY)


def _cid(key: tuple, first: float) -> str:
    """A connection's own id in the connections table: its key and when it was first counted, the same after a
    restart (the open connections' keys and first times are kept in the file)."""
    return hashlib.sha1(f"{json.dumps(list(key))}|{float(first)!r}".encode()).hexdigest()[:20]


def _between(wall: float, awake: float | None, before: float | None, starts: bool) -> float:
    """The seconds a connection seen at two readings `wall` seconds apart was up between them (rule 3): the lesser of
    the wall clock's and the awake clock's (`awake` now, `before` then), nothing when the awake clock went back or
    the wall clock did not go on; without the system's word on starts, or without both awake readings, nothing for a
    gap longer than GAP_S."""
    if not wall > 0:
        return 0.0
    if awake is None or before is None:
        return wall if wall <= GAP_S else 0.0
    if awake < before or (not starts and wall > GAP_S):
        return 0.0
    return min(wall, awake - before)


def _stale(t: float, awake: float | None, prev: float | None, before: float | None) -> bool:
    """Whether a reading was taken before the last one fed, or is that one again (two feeders' readings handed over
    out of turn): by the awake clock where both readings have one (it went back by STALE_S at most, or stood still
    with the wall clock not gone on; further back the system restarted), else by the wall clock (before the last
    one, by STALE_S at most)."""
    if prev is None:
        return False
    if awake is not None and before is not None:
        return 0 <= before - awake <= STALE_S and (awake < before or t <= prev)
    return 0 < prev - t <= STALE_S


class _Open:
    """A connection the book holds open: the hosts row its time goes to, the table it was read from, its start where
    the system says one, when it was first and last seen, the awake clock at that last reading, and whether it only
    waits to close (held so that it is counted once, never given time)."""
    __slots__ = ("row", "table", "started", "first", "last", "awake", "waiting", "cid")

    def __init__(self, row, table, started, first, last, awake, waiting=False, cid=None):
        self.row, self.table, self.started, self.first = row, table, started, first
        self.last, self.awake, self.waiting = last, awake, waiting
        self.cid = cid  # 1.68.0: its row of the connections table


def _windows(text) -> dict[tuple, tuple]:
    """The ends of the connections that ended lately, as the file keeps them (meta's "ended": [[proto, local,
    local_port, remote, remote_port, ended, next], ...]); what does not read as one is passed over."""
    try:
        items = json.loads(text) if isinstance(text, str) else []
    except ValueError:
        return {}
    found: dict[tuple, tuple] = {}
    for item in items if isinstance(items, list) else ():
        if isinstance(item, list) and len(item) == 7 and _number(item[5]) is not None:
            found[tuple(item[:5])] = (_number(item[5]), _number(item[6]))
    return dict(list(found.items())[-MAX_OPEN:])


def _filters(program=None, proto="", port=0, direction="", since=None) -> tuple[list[str], list]:
    """The queries' filters as SQL: a program (None or "": every program), a protocol ("": both), the service's port
    (0: every port), a direction ("": both) and `since` (epoch seconds: the rows last seen then or later).

    A program is found by the hosts' own key, whose first column it is. The other four are written as expressions
    (`+port`: the same values, of no index), so SQLite reads the table through: given the columns, it would read
    them from the index on `last` (which holds the key's columns too) and look up each row it lets through, which at
    the cap took ten times as long for a filter by port, direction or a month's time as reading the table itself
    (SQLite 3.45 and 3.53 alike). `hosts` sorts by `+last` for the same reason."""
    clauses, args = [], []
    program = _clip(program)
    if program:
        clauses.append("program = ?")
        args.append(program)
    for column, value in (("proto", _clip(proto, CODE).lower()), ("direction", _clip(direction, CODE).lower())):
        if value:
            clauses.append(f"+{column} = ?")
            args.append(value)
    if port:
        clauses.append("+port = ?")
        args.append(int(port))
    if since is not None:
        clauses.append("+last >= ?")
        args.append(float(since))
    return clauses, args


def _most(limit) -> int:
    return max(0, int(limit))


def _where(clauses: list[str]) -> str:
    return f" WHERE {' AND '.join(clauses)}" if clauses else ""


def _sums() -> dict:
    return {"hosts": 0, "connections": 0, "seconds": 0.0}


def _over(which: str) -> str:
    """The hosts, the connections and the seconds of the groups that are `which`, summed over every group of the
    query by a window: each row handed out carries them, however few are."""
    return ", ".join(f"SUM(CASE WHEN {which} THEN {value} END) OVER ()"
                     for value in ("COUNT(DISTINCT host)", "SUM(connections)", "SUM(seconds)"))


def _summed(hosts, connections, seconds) -> dict:
    return {"hosts": hosts or 0, "connections": connections or 0, "seconds": float(seconds or 0.0)}


def _degrees(value, limit: float) -> float | None:
    value = _number(value)
    return value if value is not None and -limit <= value <= limit else None


def _placed(place) -> tuple:
    """What a lookup's answer gives a row: (country, code, city, lat, lon, asn, org), each None where it says nothing.
    The answer is a geo.Place, or a mapping of its keys (country: the code, country_name, city, lat, lon, asn, org);
    None, or anything else, is no place. A point is both of latitude and longitude, or neither."""
    if place is None:
        return (None,) * 7
    get = place.get if isinstance(place, Mapping) else lambda name: getattr(place, name, None)
    code, lat, lon, asn = _clip(get("country"), CODE), _degrees(get("lat"), 90), _degrees(get("lon"), 180), get("asn")
    if lat is None or lon is None:
        lat = lon = None
    asn = asn if isinstance(asn, int) and not isinstance(asn, bool) and 0 < asn < 1 << 32 else None
    return (_clip(get("country_name")) or code or None, code or None, _clip(get("city")) or None, lat, lon, asn,
            _clip(get("org")) or None)


def _route_row(traced, reached, how, hops) -> dict | None:
    """1.74.1: a kept route as routes_of hands it back; None where its hops cannot be read."""
    try:
        listed = json.loads(hops)
    except (TypeError, ValueError):
        return None
    if not isinstance(listed, list):
        return None
    return {"traced": traced, "reached": bool(reached), "how": how,
            "hops": [h for h in listed if isinstance(h, dict)]}


def _discard(name) -> None:
    """A file removed where it is; nothing where there is none."""
    try:
        os.remove(name)
    except FileNotFoundError:
        pass


# -- the book -------------------------------------------------------------------------------------------------------

class HostBook:
    """The hosts database in one SQLite file at `path` (the data folder's own when None): at most `cap` rows of
    hosts, the connections open now and a few facts of the file itself. Readings are fed in memory (`feed`), written
    in one transaction (`flush`), and read back by the queries; `close` writes what is pending and lets the file go,
    and the next call opens it again. One connection under one lock, so a recording thread and a page's ask may
    share a book; a file that is damaged or no database is set aside as hosts.db.bad. All in memory is bounded:
    MAX_OPEN open connections (and as many ends of connections that ended lately), and the rows pending (written by a
    reading itself past MAX_PENDING). `clock` gives the time now (epoch seconds) where no reading does: for `forget`.

    `changes` counts the writes that changed the hosts' rows (a flush, the places kept, a forget): a page made for
    the same count is still good."""

    def __init__(self, path=None, *, cap: int = CAP, clock=time.time):
        self.path = Path(path) if path is not None else _own()
        self.cap = max(1, int(cap))
        self.clock = clock
        self.changes = 0
        self.stamp: str | None = None  # 1.102.0: the stamp of the GeoIP files in use, once place or unplaced was asked
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._loaded = False  # whether what the file holds of the open connections and of itself is in memory
        self._open: dict[tuple, _Open] = {}  # the connections open now, by key: MAX_OPEN at most
        # hosts rows to write, by their key: [first, last, seconds, connections, path, service, network, name]
        self._pending: dict[tuple, list] = {}
        # 1.68.0: connections to write: new ones whole (CONNECTION_COLUMNS), by id; known ones' changes by id:
        # [last (or None), seconds to add, ended (or None)]; routes to keep, by host
        self._born: dict[str, list] = {}
        self._touched: dict[str, list] = {}
        self._routes: dict[str, tuple] = {}
        self._traces: list[tuple] = []  # 1.74.0: every trace, its own row of `traces`
        self._n_connections = 0  # as the last count left it
        # the two ends of the keys that ended lately: (the time of the reading they ended in, the time of the next
        # reading NEAR_S or more after it, None until there is one); dropped at the reading after that next one
        self._ended: dict[tuple, tuple] = {}
        self._since: float | None = None  # the first reading kept (or the last forget)
        self._last: float | None = None  # the last reading's time ...
        self._awake: float | None = None  # ... and its awake clock
        self._back: float | None = None  # the clock went back to this: rows seen "later" are set to it at a flush
        self._dirty = False  # the open connections or the file's facts changed since they were written
        self._n_rows = self._n_hosts = self._n_programs = 0  # the rows by each write; the others as COUNT_S says
        self._counted: float | None = None  # the readings' time when the hosts and the programs were last counted
        self._recount = False  # the last count failed: the next write counts again
        self._not_kept = 0  # connections of the last reading neither held nor counted (past MAX_OPEN)
        self._cut = False  # whether the last reading's rows were cut
        self._elsewhere = ""  # why not from here: the folder is on another system's drive
        self._refused = ""  # a file of a newer layout: left as it is
        self._note = ""  # what happened to a file that was damaged or no database
        self._error = ""  # the last read or write that failed, until one works ...
        self._cause = ""  # ... and SQLite's or the system's own words for it

    def __enter__(self) -> HostBook:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- the file ----------------------------------------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10, isolation_level=None, check_same_thread=False)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            for statement in _SCHEMA:
                conn.execute(statement)
            conn.execute("SELECT COUNT(*) FROM meta").fetchone()
        except BaseException:
            conn.close()
            raise
        return conn

    def _make_room(self) -> None:
        """The folder made for a new file, and off Windows the empty file too, both this account's alone: the folder
        0700 when it is made here (one that was there is left as it is), the file 0600, and with it the files SQLite
        keeps beside it (they take its mode). The hosts a user's programs talk with are no other account's to read."""
        folder = self.path.parent
        if not folder.is_dir():
            folder.mkdir(parents=True, exist_ok=True)
            if _POSIX:
                os.chmod(folder, FOLDER_MODE)
        if _POSIX:
            try:
                os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE))
            except FileExistsError:
                pass
            os.chmod(self.path, FILE_MODE)

    def _bad(self) -> Path:
        return self.path.with_name(self.path.name + ".bad")

    def _set_aside(self, error: Exception) -> None:
        """A file that is damaged or no database moved aside (one copy, hosts.db.bad), so recording starts anew."""
        bad = self._bad()
        os.replace(self.path, bad)
        for extra in ("-wal", "-shm"):
            try:
                os.remove(f"{self.path}{extra}")
            except OSError:
                pass
        self._n_rows = self._n_hosts = self._n_programs = 0
        self._note = (f"The hosts database kept could not be read ({error}): it was set aside as {bad.name}, and "
                      "recording starts anew.")

    def _file(self, make: bool) -> sqlite3.Connection | None:
        """The file open: the one connection, kept until `_close`. None where there is no file and none is to be
        made (`make` false: a read makes none), also after a file that was no database was set aside."""
        if self._conn is None:
            there = self.path.exists()
            if not there:
                if not make:
                    return None
                self._n_rows = self._n_hosts = self._n_programs = 0  # a new file holds no row, whatever one before did
                self._make_room()
            try:
                self._conn = self._connect()
            except sqlite3.DatabaseError as e:
                if not there or not _broken(e):
                    raise
                self._set_aside(e)
                if not make:
                    return None
                self._make_room()
                self._conn = self._connect()
        return self._conn

    def _close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def _failed(self, done: str, error: Exception) -> bool:
        """A read or a write that failed (a file another program holds, a full disk): the file let go and the words
        kept for `describe`, until one works. A file SQLite finds damaged or no database is set aside instead, so
        recording starts anew: True then."""
        try:
            self._close()
        except sqlite3.Error:
            pass
        self._cause = str(error)
        if _broken(error) and self.path.exists():
            try:
                self._set_aside(error)
            except OSError as e:
                self._error = f"The hosts database could not be {done} ({error}), nor set aside ({e})."
                return False
            self._error = ""
            return True
        self._error = f"The hosts database could not be {done} ({error})."
        return False

    def _fresh(self) -> None:
        """What was read of a file just set aside let go: the book as for a new file."""
        self._open, self._pending, self._ended = {}, {}, {}
        self._since = self._last = self._awake = self._back = None
        self._n_rows = self._n_hosts = self._n_programs = 0

    @staticmethod
    def _transaction(conn: sqlite3.Connection, write) -> None:
        conn.execute("BEGIN IMMEDIATE")
        try:
            write(conn)
            conn.execute("COMMIT")
        except BaseException:
            try:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
            except sqlite3.Error:  # the first error is the one to tell
                pass
            raise

    @classmethod
    def _erase(cls, conn: sqlite3.Connection, write) -> str:
        """`write` in one transaction, SQLite told to overwrite what it deletes (secure_delete); then the file built
        anew from what is left (VACUUM, its work kept in memory) and its log folded into it and emptied (a
        checkpoint), so neither the pages freed before nor the log keep anything that went. Raises as the
        transaction does; what could not be cleared after it is answered in words ("" when all was)."""
        was = conn.execute("PRAGMA secure_delete").fetchone()[0]
        conn.execute("PRAGMA secure_delete=ON")
        try:
            cls._transaction(conn, write)
        finally:
            try:
                conn.execute(f"PRAGMA secure_delete={_SECURE.get(was, 'OFF')}")
            except sqlite3.Error:  # the first error is the one to tell
                pass
        store = None
        try:
            store = conn.execute("PRAGMA temp_store").fetchone()[0]
            conn.execute("PRAGMA temp_store=MEMORY")  # VACUUM's copy of the hosts kept: in memory, not a temp file
            conn.execute("VACUUM")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            return ""
        except sqlite3.Error as e:
            return f"The hosts were forgotten, but what the file kept of them could not be cleared ({e})."
        finally:
            if store is not None:
                try:
                    conn.execute(f"PRAGMA temp_store={int(store)}")
                except (sqlite3.Error, TypeError, ValueError):
                    pass

    def _count(self, conn: sqlite3.Connection) -> None:
        """The file's rows, hosts and programs counted (at first use; after a write, as COUNT_ROWS and COUNT_S say)."""
        self._n_rows, self._n_hosts, self._n_programs = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT host), COUNT(DISTINCT program) FROM hosts").fetchone()
        self._n_connections = conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
        self._counted = self._last

    def _due(self) -> bool:
        """Whether a write that added or removed rows counts the hosts and the programs again: always while the file
        holds COUNT_ROWS rows or fewer, else once COUNT_S of the readings' time went by since they were last counted
        (or that time went back)."""
        last, counted = self._last, self._counted
        return (self._n_rows <= COUNT_ROWS or last is None or counted is None
                or not 0 <= last - counted < COUNT_S)

    def _ready(self) -> bool:
        """Whether the book is kept here, asked before anything is read or written: not on a folder of another
        system's drive, nor a file of a newer layout. At first use, what the file holds of the open connections and
        of itself is read into memory (no file is made for it, and none stays open); a file found damaged then is
        set aside, and the book starts as for a new file."""
        self._elsewhere = foreign(self.path)
        if self._elsewhere:
            return False
        if not self._loaded:
            try:
                self._load()
            except (sqlite3.Error, OSError) as e:
                if not self._failed("read", e):
                    return False
                self._fresh()
                self._loaded = True
        return not self._refused

    def _load(self) -> None:
        conn = self._file(make=False)
        try:
            if conn is not None:
                facts = dict(conn.execute("SELECT key, value FROM meta"))
                version = _whole(facts.get("version")) or VERSION
                if version > VERSION:
                    self._refused = (f"The hosts database at {self.path} was written by a newer Liminal (its layout is "
                                     f"version {version}, and this one reads version {VERSION}): it is left as it is, "
                                     "and nothing is recorded or shown from it here.")
                else:
                    self._since, self._last, self._awake = (_number(facts.get(k)) for k in ("since", "last", "awake"))
                    self._ended = _windows(facts.get("ended"))
                    self._held(conn)
                    self._count(conn)
            self._loaded = True
        finally:
            self._close()

    def _held(self, conn: sqlite3.Connection) -> None:
        """The open connections as the file holds them (rule 5); one that does not read as one is passed over."""
        for key, program, host, proto, port, direction, started, first, last, table, awake, waiting in conn.execute(
                "SELECT key, program, host, proto, port, direction, started, first, last, tbl, awake, waiting "
                "FROM open ORDER BY last DESC LIMIT ?", (MAX_OPEN,)):
            try:
                key = tuple(json.loads(key))
            except (TypeError, ValueError):
                continue
            first, last = _number(first), _number(last)
            if len(key) >= 6 and first is not None and last is not None:
                self._open[key] = _Open((program, host, proto, port, direction), table, _number(started), first, last,
                                        _number(awake), bool(waiting), cid=_cid(key, first))

    def _read(self, work, nothing):
        """`work(conn)` for a call that only reads: over the file open, or opened for this read alone and let go
        after it; `nothing` where the book is not kept here, where there is no file (none is made for a read) and
        when the read fails (`describe` says why; a file found damaged is set aside)."""
        with self._lock:
            if not self._ready():
                return nothing
            was_open = self._conn is not None
            try:
                conn = self._file(make=False)
                return nothing if conn is None else work(conn)
            except (sqlite3.Error, OSError) as e:
                self._failed("read", e)
                return nothing
            finally:
                if not was_open:
                    self._close()

    # -- a reading ---------------------------------------------------------------------------------------------------
    def feed(self, rows, at, *, starts, read=TABLES, cut=False, awake=None) -> dict:
        """One reading's judged rows added up, in memory (the rules: this module's words): {"new": connections
        counted, "ended": connections that ended, "open": connections open now}. `at`: the reading's time; `starts`:
        whether its system says when a socket began; `read`: its tables read whole; `cut`: whether its rows were
        cut; `awake`: its clock that does not count sleep, None when it has none. Each reading is fed once and in the
        order the readings were taken (the caller holds one lock over reading, judging and feeding): a reading taken
        before the last one fed, or that one again, is set aside and counts nothing. Nothing at all on a folder of
        another system's drive. Past MAX_PENDING rows waiting, they are written here (the file left open or closed,
        as it was)."""
        with self._lock:
            if not self._ready():
                return {"new": 0, "ended": 0, "open": 0}
            t, awake, starts = _number(at), _number(awake), bool(starts)
            prev, before = self._last, self._awake
            if t is None or _stale(t, awake, prev, before):
                return {"new": 0, "ended": 0, "open": self._up()}
            was_open = self._conn is not None
            if prev is not None and t < prev:  # the clock went back: every open key goes on from this reading's time
                self._went_back(t)
                prev = t
            up: dict[tuple, _Row] = {}
            waiting: dict[tuple, _Row] = {}
            for row in rows or ():
                r = _row_of(row, starts)
                if r is not None:
                    (waiting if r.waiting else up).setdefault(r.key, r)
            new = ended = lost = 0
            for key, r in up.items():
                held = self._open.get(key)
                if held is None and r.bare is not None and r.bare not in up:
                    held = self._carried(key, r.bare)
                if held is None:  # rule 2
                    if len(self._open) >= MAX_OPEN:
                        lost += 1
                        continue
                    first, seconds = self._begins(r, t, prev, awake, before)
                    self._open[key] = _Open(r.row, r.table, r.started, first, t, awake, cid=_cid(key, first))
                    self._add(r.row, r, first, t, seconds, 1)
                    self._born_now(self._open[key].cid, r, first, t, seconds)
                    new += 1
                else:  # rule 3
                    seconds = _between(t - held.last, awake, held.awake, starts) if r.counts else 0.0
                    held.last, held.awake = t, awake
                    self._add(held.row, r, t, t, seconds, 0)
                    self._touch(held.cid, t, seconds)
            gone: set[tuple] = set()
            if not cut:  # rule 4
                whole = {_clip(name, CODE).lower() for name in read or ()}
                for key in [k for k, held in self._open.items()
                            if held.table in whole and k not in up and k not in waiting]:
                    went = self._open.pop(key)
                    if not went.waiting:
                        ended += 1
                        gone.add(key[:5])
                        self._touch(went.cid, None, 0.0, ended=t)  # gone by this reading
                self._window(t, gone)
            ends = None
            for key, r in waiting.items():
                held = self._open.get(key)
                if held is not None:  # held already: counted once, never given time
                    held.last = t
                    continue
                if ends is None:
                    ends = {k[:5] for k, o in self._open.items() if not o.waiting}
                if key[:5] in ends:  # its connection is still open here (its table was not read whole): not yet
                    continue
                counted = key[:5] in self._ended  # under its program, while it was up
                if len(self._open) >= MAX_OPEN:
                    lost += 0 if counted else 1
                    continue
                self._open[key] = _Open(r.row, r.table, None, t, t, awake, waiting=True, cid=_cid(key, t))
                if not counted:
                    self._add(r.row, r, t, t, 0.0, 1)
                    new += 1
                    self._born_now(self._open[key].cid, r, t, t, 0.0, ended=t)  # began and ended between two readings
            self._last, self._awake, self._not_kept, self._cut, self._dirty = t, awake, lost, bool(cut), True
            if self._since is None:
                self._since = t
            if len(self._pending) > MAX_PENDING or len(self._born) > MAX_PENDING:
                self._flush(keep_open=was_open)
            return {"new": new, "ended": ended, "open": self._up()}

    def _went_back(self, t: float) -> None:
        """The wall clock went back to `t`: no open key, pending row or window is seen after it, and at the next
        flush no row of the file either."""
        for held in self._open.values():
            held.first, held.last = min(held.first, t), min(held.last, t)
        for pending in self._pending.values():
            pending[0], pending[1] = min(pending[0], t), min(pending[1], t)
        for ends, (began, following) in list(self._ended.items()):
            self._ended[ends] = (min(began, t), None if following is None else min(following, t))
        self._back = t if self._back is None else min(self._back, t)
        if self._since is not None:
            self._since = min(self._since, t)

    def _carried(self, key: tuple, bare: tuple) -> _Open | None:
        """A connection held with no owner (Linux: listed before it was accepted, with no inode) found again with
        one: the same connection, held on under its new key; None where there is none such."""
        held = self._open.get(bare)
        if held is None or held.waiting:
            return None
        del self._open[bare]
        self._open[key] = held
        return held

    def _window(self, t: float, gone: set[tuple]) -> None:
        """S7's window, for a reading at `t` whose tables were read whole: the ends that ended in it kept (`gone`),
        each kept through the next reading NEAR_S or more after the one it ended in and dropped at the one after,
        MAX_OPEN of them at most (the ones that ended last)."""
        for ends, (began, following) in list(self._ended.items()):
            if following is None:
                if t >= began + NEAR_S:
                    self._ended[ends] = (began, t)  # this reading is the next one: kept through it
            elif t > following:
                del self._ended[ends]
        for ends in gone:
            self._ended[ends] = (t, None)
        if len(self._ended) > MAX_OPEN:
            self._ended = dict(sorted(self._ended.items(), key=lambda item: item[1][0])[-MAX_OPEN:])

    @staticmethod
    def _begins(r: _Row, t: float, prev: float | None, awake: float | None,
                before: float | None) -> tuple[float, float]:
        """A new connection's (first time seen, seconds to count now), by rule 2: where its row says when its socket
        began, from the later of that start and the reading before; else from this reading. A row that is not
        "established" counts none. No sleep is counted: for a socket begun since the reading before, the system's
        sleep between the two (the wall clock's gap less the awake clock's) is taken as after its start, unless it
        cannot have been (it is longer than the socket has been open) and fits before it, the system being awake as
        the socket began: so neither the sleep nor the time awake before the start is the socket's. With no two awake
        readings to tell the sleep by (a new file, the system restarted, the hosts forgotten), no socket is older than
        the system's time awake (the awake clock now)."""
        started = r.started
        if started is None or not started <= t:
            return t, 0.0
        if prev is not None and started < prev:  # open at the reading before: the time since it, as rule 3 says
            return prev, _between(t - prev, awake, before, True) if r.counts else 0.0
        first, seconds = started, t - started
        if prev is not None and awake is not None and before is not None and awake >= before:
            slept = (t - prev) - (awake - before)
            if slept > 0 and not seconds < slept <= started - prev:
                seconds = max(0.0, seconds - slept)
        elif awake is not None and awake >= 0:  # no socket is older than the system's time awake
            seconds = min(seconds, awake)
        return first, seconds if r.counts else 0.0

    def _add(self, row: tuple, r: _Row, first: float, last: float, seconds: float, connections: int) -> None:
        """A reading's part of a hosts row, pending. The program's path and service are taken from the reading's row
        only when it names the program the hosts row is kept under: one read after its connection was counted under
        NOT_NAMED writes nothing of its own onto a row many programs share."""
        path, service = (r.path, r.service) if r.row[0] == row[0] else ("", "")
        pending = self._pending.get(row)
        if pending is None:
            self._pending[row] = [first, last, max(0.0, seconds), connections, path, service, r.network, r.name]
            return
        pending[0], pending[1] = min(pending[0], first), max(pending[1], last)
        pending[2] += max(0.0, seconds)
        pending[3] += connections
        pending[4], pending[5], pending[6], pending[7] = (path or pending[4], service or pending[5], r.network,
                                                          r.name or pending[7])

    def _born_now(self, cid: str, r: _Row, first: float, last: float, seconds: float, ended=None) -> None:
        """A new connection's own row, pending: who, what, when, why (`why_of`); its place comes with `place`."""
        program, host, proto, port, direction = r.row
        pid, user, title, local, local_port, remote_port, family, _named = r.who
        self._born[cid] = [cid, program, r.path, pid or None, user, r.service, title, proto, family or None, local,
                           local_port, host, remote_port, direction, port, r.network, r.name, r.started, first,
                           last, ended, max(0.0, seconds), why_of(r)]

    def _touch(self, cid, last, seconds: float, ended=None) -> None:
        """A known connection seen again (`last`, the `seconds` it adds) or gone (`ended`): onto its pending row when it
        has one, else kept to be written onto the row in the file."""
        if cid is None:
            return
        born = self._born.get(cid)
        if born is not None:
            if last is not None:
                born[_LAST] = max(born[_LAST], last)
            born[_SECONDS] += max(0.0, seconds)
            if ended is not None:
                born[_ENDED] = ended
            return
        touched = self._touched.get(cid)
        if touched is None:
            self._touched[cid] = [last, max(0.0, seconds), ended]
            return
        if last is not None:
            touched[0] = last if touched[0] is None else max(touched[0], last)
        touched[1] += max(0.0, seconds)
        if ended is not None:
            touched[2] = ended

    def keep_route(self, remote, traced, reached, how, hops, way) -> None:
        """The route traced to a host (machines/routes.py), kept with the next write: `traced` (epoch seconds),
        whether it reached the host, how it was traced, its hops (a list of mappings: n, address, ms, and the place's
        label, lat and lon where the GeoIP file gave one) and the places on its way in words. Nothing on a folder of
        another system's drive."""
        with self._lock:
            if not self._ready():
                return
            host, at = _clip(remote), _number(traced)
            if not host or at is None:
                return
            if len(self._routes) >= MAX_PENDING and host not in self._routes:
                return  # bounded: kept again at its next trace
            self._routes[host] = (host, at, int(bool(reached)), _clip(how, CODE * 4),
                                  json.dumps(list(hops or ())[:64], separators=(",", ":"))[:16_000],
                                  _clip(way, WHY))
            if len(self._traces) < MAX_PENDING:
                self._traces.append(self._routes[host])
            self._dirty = True

    def _up(self) -> int:
        return sum(1 for held in self._open.values() if not held.waiting)

    # -- writing -----------------------------------------------------------------------------------------------------
    def flush(self, keep_open: bool = False) -> None:
        """What is pending written in one transaction: the hosts' rows (the ones over the cap pruned, the longest
        unseen first), the open connections and the file's facts. Then the file is closed, unless `keep_open`.
        Nothing fed since the last flush: nothing is written, and no file is made. A write that fails is told by
        `describe` and tried again at the next flush; a file found damaged is set aside and written anew."""
        with self._lock:
            if self._ready():
                self._flush(keep_open)

    def close(self) -> None:
        """What is pending written and the file let go; the next call opens it again."""
        self.flush()

    def _ended_facts(self) -> str:
        return json.dumps([[*ends, began, following] for ends, (began, following) in self._ended.items()])

    def _flush(self, keep_open: bool) -> None:
        if not (self._pending or self._dirty):
            if not keep_open:
                self._close()
            return
        pending, back = self._pending, self._back
        born, touched, routes, traces = self._born, self._touched, self._routes, self._traces
        changed = grew = False
        counted = self._n_rows
        tallied = self._n_connections  # the connections' rows (not `connections`: a hosts row's count is named so)
        now = self._last if self._last is not None else _number(self.clock()) or 0.0

        def write(c: sqlite3.Connection) -> None:
            nonlocal changed, grew, counted, tallied
            changed = grew = False
            rows = self._n_rows
            if back is not None:  # the clock went back: no row was seen after the time it went back to
                changed = c.execute("UPDATE hosts SET first = min(first, ?), last = ? WHERE last > ?",
                                    (back, back, back)).rowcount > 0
            for row, (first, last, seconds, connections, path, service, network, name) in pending.items():
                if c.execute(_INSERT, (*row, path, service, network, name, first, last, seconds, connections)).rowcount:
                    rows += 1
                    grew = True
                else:
                    c.execute(_UPDATE, (path, path, service, service, network, name, name, first, last, seconds,
                                        connections, *row))
                changed = True
            if rows > self.cap:  # back under the cap, a hundredth under it, so a prune is not every flush's
                rows -= c.execute(_PRUNE, (rows - (self.cap - self.cap // 100),)).rowcount
                grew = True
            counted = rows  # the rows as this write leaves them, counted by it
            # 1.68.0: every connection's own row, its changes, the routes; then the old ones let go, and past the cap
            # the ones that ended longest ago
            many = tallied
            for rec in born.values():
                many += c.execute(_CONN_INSERT, rec).rowcount
            new = [rec[0] for rec in born.values() if rec[15] == INTERNET]
            if self.stamp is None:
                c.executemany(_CONN_HOSTS_PLACE, [(cid,) for cid in new])
            else:  # 1.102.0: a host's row placed by the files in use alone
                c.executemany(_CONN_HOSTS_STAMPED, [(self.stamp, cid, self.stamp) for cid in new])
            for cid, (last, seconds, ended) in touched.items():
                c.execute(_CONN_TOUCH, (last, last, seconds, ended, cid))
            c.executemany(_ROUTE_KEEP, list(routes.values()))
            c.executemany(_TRACE_KEEP, traces)  # 1.74.0: and every trace, its own row
            if born or touched or routes:
                changed = True
            many -= c.execute("DELETE FROM connections WHERE last < ? AND ended IS NOT NULL",
                              (now - KEEP_DAYS * 86400.0,)).rowcount
            if many > CONNECTIONS:
                many -= c.execute(_CONN_PRUNE, (many - (CONNECTIONS - CONNECTIONS // 100),)).rowcount
            c.execute("DELETE FROM routes WHERE traced < ?", (now - ROUTE_DAYS * 86400.0,))
            if traces and c.execute("SELECT COUNT(*) FROM traces").fetchone()[0] > TRACES:
                c.execute("DELETE FROM traces WHERE id IN (SELECT id FROM traces ORDER BY traced LIMIT "
                          "(SELECT COUNT(*) FROM traces) - ?)", (TRACES,))
            if routes and c.execute("SELECT COUNT(*) FROM routes").fetchone()[0] > ROUTES:
                c.execute("DELETE FROM routes WHERE remote IN (SELECT remote FROM routes ORDER BY traced LIMIT "
                          "(SELECT COUNT(*) FROM routes) - ?)", (ROUTES,))
            tallied = max(0, many)
            c.execute("DELETE FROM open")
            c.executemany(_HOLD, [(json.dumps(key), *held.row, held.started, held.first, held.last, held.table,
                                   held.awake, int(held.waiting)) for key, held in self._open.items()])
            c.executemany(_FACTS, [("version", VERSION), ("since", self._since), ("last", self._last),
                                   ("awake", self._awake)])
            if self._ended:
                c.execute(_FACTS, ("ended", self._ended_facts()))
            else:
                c.execute("DELETE FROM meta WHERE key = 'ended'")

        failure = None
        for _ in range(2):  # a second time only into a new file, the one there set aside as damaged
            try:
                self._transaction(self._file(make=True), write)
                failure = None
                break
            except (sqlite3.Error, OSError) as e:
                failure = e
                if not self._failed("written", e):
                    break
        if failure is not None:
            if not self._error:
                self._error = f"The hosts database could not be written ({failure})."
            self._error += " What was seen since is kept in memory and written at the next try."
            if len(born) > 2 * MAX_PENDING:  # memory stays bounded: what cannot be written is let go (connections)
                self._error += f" {len(born):,} connections waiting were more than is kept so, and were let go."
                self._born, self._touched, self._routes, self._traces = {}, {}, {}, []
            if len(pending) > 2 * MAX_PENDING:  # ... and the hosts' rows
                self._error += f" {len(pending):,} rows waiting were more than is kept so, and were let go."
                self._pending = {}
            return
        # written: nothing of it is pending any more, whatever the count below does
        self._pending, self._back, self._dirty, self._error = {}, None, False, ""
        self._born, self._touched, self._routes, self._n_connections = {}, {}, {}, tallied
        self._traces = []
        if changed:
            self.changes += 1
        if grew or self._recount:
            self._n_rows = counted
            if self._recount or self._due():
                try:
                    self._count(self._conn)
                    self._recount = False
                except (sqlite3.Error, OSError) as e:  # the counts are the last ones read, until a count works
                    self._recount = True
                    self._failed("read", e)
        if not keep_open:
            self._close()

    def place(self, lookup, stamp, most: int = PLACE_ROWS) -> int:
        """The internet's rows with no place looked up yet, or one from an older GeoIP file, looked up and kept: the
        `most` last seen of them; how many were looked up. `lookup(host)` answers a geo.Place (or a mapping of its
        keys), None where the file has no place: GeoIP.lookup. `stamp` is the GeoIP file's own date, as text
        ("2026-11-01"): it is kept on each row looked up, so a host the file has no point for is not asked again
        until a newer file is here. A local host is never looked up. Ask `unplaced(stamp)` first, and open the GeoIP
        file only when it is not 0."""
        with self._lock:
            if not self._ready():
                return 0
            stamp, most = _clip(stamp, PLACE_STAMP), _most(most)
            self.stamp = stamp
            was_open = self._conn is not None
            try:
                conn = self._file(make=False)
                if conn is None or not most:
                    return 0
                rows = conn.execute(
                    "SELECT program, host, proto, port, direction FROM hosts WHERE network = ? AND (placed IS NULL OR "
                    "placed <> ?) ORDER BY last DESC, program, host, proto, port, direction LIMIT ?",
                    (INTERNET, stamp, most)).fetchall()
                if not rows:
                    return 0
                found: dict[str, tuple] = {}
                for row in rows:
                    if row[1] not in found:
                        found[row[1]] = _placed(lookup(row[1]))
                placed = [(*found[row[1]], stamp, *row) for row in rows]
                # 1.68.0: each connection's own row placed as its host's
                linked = [(*found[host], stamp, host, stamp) for host in found]

                def write(c: sqlite3.Connection) -> None:
                    c.executemany(_PLACE, placed)
                    c.executemany(_CONN_PLACE, linked)
                self._transaction(conn, write)
            except (sqlite3.Error, OSError) as e:
                self._failed("written", e)
                return 0
            finally:
                if not was_open:
                    self._close()
            self.changes += 1
            return len(rows)

    def forget(self) -> int:
        """Every row removed; how many there were. What was pending goes too, and so does the copy of a file set
        aside (hosts.db.bad). Nothing removed is left in the file: it is built anew from what is left (`_erase`).
        Recording goes on from now: `since` and the last reading's time are now, and every connection open now is
        counted anew by the next reading, its time from now on (never from its start, which would bring back the
        days just forgotten). The rows waiting to close stay held, so none of them comes back as a connection.
        OSError, in words, when the file cannot be read or written: nothing is forgotten then. A file found damaged
        is set aside and removed, which forgets it all the same."""
        with self._lock:
            if not self._ready():
                if self._elsewhere or self._refused:
                    return 0
                raise OSError(f"the hosts database at {self.path} could not be read ({self._cause}): nothing was "
                              "forgotten")
            now = _number(self.clock()) or 0.0
            kept = {key: held for key, held in self._open.items() if held.waiting}
            removed, known, left = 0, self._n_rows, ""
            was_open = self._conn is not None

            def write(c: sqlite3.Connection) -> None:
                nonlocal removed
                removed = c.execute("DELETE FROM hosts").rowcount
                c.execute("DELETE FROM open")
                c.execute("DELETE FROM connections")
                c.execute("DELETE FROM routes")
                c.execute("DELETE FROM traces")
                c.executemany(_HOLD, [(json.dumps(key), *held.row, None, held.first, held.last, held.table,
                                       held.awake, 1) for key, held in kept.items()])
                c.executemany(_FACTS, [("version", VERSION), ("since", now), ("last", now), ("awake", None)])
                c.execute("DELETE FROM meta WHERE key = 'ended'")

            try:
                conn = self._file(make=False)
                if conn is not None:
                    left = self._erase(conn, write)
            except (sqlite3.Error, OSError) as e:
                if not self._failed("written", e):  # set aside, it is removed below with the copy of any before it
                    raise OSError(f"the hosts database at {self.path} could not be emptied ({e}): nothing was "
                                  "forgotten") from e
                removed = known  # its rows cannot be counted now: as many as were counted last
            finally:
                if not was_open:
                    self._close()
            self._open, self._pending, self._ended = kept, {}, {}
            self._born, self._touched, self._routes, self._n_connections = {}, {}, {}, 0
            self._traces = []
            self._since = self._last = now
            self._awake = self._back = None
            self._n_rows = self._n_hosts = self._n_programs = self._not_kept = 0
            self._dirty = self._recount = False
            self._error, self._note = left, ""
            self.changes += 1
            try:
                _discard(self._bad())
            except OSError as e:
                self._error = " ".join(filter(None, (
                    left, f"The copy set aside as {self._bad().name} could not be removed ({e}).")))
            return removed

    # -- reading -----------------------------------------------------------------------------------------------------
    def hosts(self, *, program=None, proto="", port=0, direction="", since=None, limit: int = QUERY_ROWS) -> list[dict]:
        """The rows that pass the filters, the last seen first, `limit` at most: each a dict of COLUMNS (first and last
        in epoch seconds; lat, lon and asn None where there is none; a place's words "" where there are none). The
        filters: a program (None: every program), a protocol ("tcp", "udp"; "": both), the service's port (0: every
        port), a direction ("in", "out"; "": both) and `since` (epoch seconds: the rows last seen then or later)."""
        clauses, args = _filters(program, proto, port, direction, since)
        # +last: sorted, never walked through the index on `last` with a lookup a row (as _filters says)
        sql = (f"SELECT {', '.join(COLUMNS)} FROM hosts{_where(clauses)} ORDER BY +last DESC, program, host, proto, "
               "port, direction LIMIT ?")

        def work(conn: sqlite3.Connection) -> list[dict]:
            out = []
            for values in conn.execute(sql, (*args, _most(limit))):
                row = dict(zip(COLUMNS, values))
                for name in _WORDS:
                    row[name] = row[name] or ""
                out.append(row)
            return out
        return self._read(work, [])

    def programs(self, limit: int = 100, **filters) -> list[dict]:
        """The programs summed over the rows that pass the filters (`hosts`' own, by name), the ones with the most
        hosts first: {"program", "path", "hosts", "connections", "seconds", "last"}."""
        clauses, args = _filters(**filters)
        sql = ("SELECT program, MAX(path), COUNT(DISTINCT host), SUM(connections), SUM(seconds), MAX(last) FROM hosts"
               f"{_where(clauses)} GROUP BY program ORDER BY 3 DESC, 4 DESC, program LIMIT ?")
        names = ("program", "path", "hosts", "connections", "seconds", "last")
        return self._read(lambda conn: [dict(zip(names, row)) for row in conn.execute(sql, (*args, _most(limit)))], [])

    def routed(self) -> set[str]:
        """1.74.0: the hosts with a route traced and kept (their routes' rows): each is not traced again."""
        return self._read(lambda conn: {row[0] for row in conn.execute("SELECT remote FROM routes")}, set())

    def routes_of(self, remotes) -> dict[str, list[dict]]:
        """1.74.1: the routes kept of these hosts (ROUTES_OF at most), as their last check found them, for the hosts
        not traced again (routed): {remote: [{"traced", "reached", "how", "hops"}, ...]}, the check's other routes
        (the traces' rows of its time) first and the one drawn (the routes' row) last; a host with none, or whose
        hops cannot be read, left out."""
        hosts = list(dict.fromkeys(_clip(r) for r in remotes if r))[:ROUTES_OF]
        if not hosts:
            return {}

        def work(conn: sqlite3.Connection) -> dict[str, list[dict]]:
            marks = ", ".join("?" * len(hosts))
            drawn = {row[0]: row[1:] for row in conn.execute(
                f"SELECT remote, traced, reached, how, hops FROM routes WHERE remote IN ({marks})", hosts)}
            others: dict[str, list] = {}
            if drawn:
                pairs = ", ".join(["(?, ?)"] * len(drawn))
                for remote, traced, reached, how, hops in conn.execute(
                        "SELECT remote, traced, reached, how, hops FROM traces WHERE (remote, traced) IN "
                        f"(VALUES {pairs}) ORDER BY id", [v for r, row in drawn.items() for v in (r, row[0])]):
                    if hops != drawn[remote][3]:  # the drawn one is a trace too: kept once
                        others.setdefault(remote, []).append((traced, reached, how, hops))
            out: dict[str, list[dict]] = {}
            for remote, row in drawn.items():
                last = _route_row(*row)
                if last is not None:  # its drawn route unreadable: the host left out
                    out[remote] = [r for r in map(lambda o: _route_row(*o), others.get(remote, ())) if r] + [last]
            return out
        return self._read(work, {})

    def ports(self, limit: int = 100, **filters) -> list[dict]:
        """The services' ports summed over the rows that pass the filters (`hosts`' own, by name), the ones with the
        most hosts first: {"proto", "port", "hosts", "connections", "seconds", "last"}."""
        clauses, args = _filters(**filters)
        sql = ("SELECT proto, port, COUNT(DISTINCT host), SUM(connections), SUM(seconds), MAX(last) FROM hosts"
               f"{_where(clauses)} GROUP BY proto, port ORDER BY 3 DESC, 4 DESC, proto, port LIMIT ?")
        names = ("proto", "port", "hosts", "connections", "seconds", "last")
        return self._read(lambda conn: [dict(zip(names, row)) for row in conn.execute(sql, (*args, _most(limit)))], [])

    def places(self, *, program=None, proto="", port=0, direction="", since=None,
               most: int = PLACES) -> tuple[list[dict], dict]:
        """The globe's places: the rows that pass the filters (`hosts`' own) grouped by point in the query, the
        places with the most connections first, `most` of them (MAX_PLACES at the very most), and what is left
        summed in the same query (only the places drawn are handed out of it). A place: {"lat", "lon", "country",
        "code", "city", "asn", "org" (the network's, when every host of the place has one and the same), "hosts",
        "connections", "in" (the connections that came in), "direction" ("in" when most came in, else "out"),
        "seconds", "first", "last", "programs" (PLACE_PROGRAMS at most, the most connections first), "ports"
        (PLACE_PORTS at most, the same)}. The second answer: {"places", "hosts", "connections", "seconds"} of the
        places over `most`; "unplaced": the internet's hosts with no point (not looked up yet, or the GeoIP file has
        none for them), {"hosts", "connections", "seconds"}; "local": the local network's, never placed, the same
        three."""
        most = min(_most(most), MAX_PLACES)
        clauses, args = _filters(program, proto, port, direction, since)
        grouped = ("SELECT lat, lon, COUNT(DISTINCT host), SUM(connections), SUM(seconds), MIN(first), MAX(last), "
                   f"SUM(CASE WHEN direction = 'in' THEN connections ELSE 0 END), {_DRAWN}, SUM({_DRAWN}) OVER (), "
                   f"{_over(_DRAWN)}, {_over(_UNPLACED)}, {_over(_LOCALS)} FROM hosts{_where(clauses)} "
                   "GROUP BY network, lat, lon ORDER BY 9 DESC, 4 DESC, 5 DESC, 1, 2 LIMIT ?")

        def work(conn: sqlite3.Connection) -> tuple[list[dict], dict]:
            drawn: list[dict] = []
            rest = {"places": 0, **_sums(), "unplaced": _sums(), "local": _sums()}
            sums: list = []  # every row carries them: the drawn groups', the unplaced hosts' and the local network's
            for lat, lon, hosts, connections, seconds, first, last, came, shown, *sums in conn.execute(
                    grouped, (*args, max(most, 1))):  # one row at least, for its sums
                if shown and len(drawn) < most:
                    drawn.append({"lat": lat, "lon": lon, "country": "", "code": "", "city": "", "asn": None,
                                  "org": "", "hosts": hosts, "connections": connections, "in": came,
                                  "direction": "in" if came * 2 > connections else "out", "seconds": seconds,
                                  "first": first, "last": last, "programs": [], "ports": []})
            if sums:
                groups, every = sums[0] or 0, _summed(*sums[1:4])
                rest["places"] = groups - len(drawn)
                if rest["places"] > 0:  # what the places drawn leave of every place's
                    rest["hosts"] = every["hosts"] - sum(p["hosts"] for p in drawn)
                    rest["connections"] = every["connections"] - sum(p["connections"] for p in drawn)
                    rest["seconds"] = max(0.0, every["seconds"] - math.fsum(p["seconds"] for p in drawn))
                rest["unplaced"], rest["local"] = _summed(*sums[4:7]), _summed(*sums[7:10])
            room = conn.getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER) - len(args) - 1
            step = max(1, min(POINTS, room // 2))
            for i in range(0, len(drawn), step):
                self._details(conn, drawn[i:i + step], clauses, args)
            return drawn, rest
        return self._read(work, ([], {"places": 0, **_sums(), "unplaced": _sums(), "local": _sums()}))

    @staticmethod
    def _details(conn: sqlite3.Connection, places: list[dict], clauses: list[str], args: list) -> None:
        """The places' words, and the programs and the ports with the most connections at each: one statement for
        these places alone. A place names a network (asn, org) only when every row there names one, and the same."""
        at = {(p["lat"], p["lon"]): (p, {}, {}, []) for p in places}
        points = ", ".join(["(?, ?)"] * len(places))
        sql = ("SELECT lat, lon, program, port, SUM(connections), MAX(country), MAX(code), MAX(city), MIN(asn), "
               "MAX(asn), SUM(asn IS NULL), MIN(org), MAX(org), SUM(org IS NULL OR org = '') FROM hosts"
               f"{_where([*clauses, 'network = ?'])} AND (lat, lon) IN (VALUES {points}) GROUP BY lat, lon, program, "
               "port")
        for lat, lon, program, port, connections, *words in conn.execute(
                sql, (*args, INTERNET, *(value for point in at for value in point))):
            place, programs, ports, said = at[(lat, lon)]
            programs[program] = programs.get(program, 0) + connections
            ports[port] = ports.get(port, 0) + connections
            said.append(words)
        for place, programs, ports, said in at.values():
            for i, name in enumerate(("country", "code", "city")):
                place[name] = max((words[i] for words in said if words[i]), default="")
            asns = {a for words in said for a in words[3:5] if a is not None}
            orgs = {o for words in said for o in words[6:8] if o}
            place["asn"] = asns.pop() if len(asns) == 1 and not any(words[5] for words in said) else None
            place["org"] = orgs.pop() if len(orgs) == 1 and not any(words[8] for words in said) else ""
            place["programs"] = sorted(programs, key=lambda name: (-programs[name], name))[:PLACE_PROGRAMS]
            place["ports"] = sorted(ports, key=lambda number: (-ports[number], number))[:PLACE_PORTS]

    def sums(self, **filters) -> dict:
        """{"hosts", "connections", "seconds"} of the rows that pass the filters (`hosts`' own, by name), as `places`
        sums them over its places drawn, those over its most, the hosts not placed and the local network's (a host
        counted once at each point it is placed at), in one plain query, no place handed out: an Every row's numbers."""
        clauses, args = _filters(**filters)
        sql = ("SELECT SUM(h), SUM(c), SUM(s) FROM (SELECT COUNT(DISTINCT host) AS h, SUM(connections) AS c, "
               f"SUM(seconds) AS s FROM hosts{_where(clauses)} GROUP BY network, lat, lon)")
        return self._read(lambda conn: _summed(*conn.execute(sql, args).fetchone()), _sums())

    def unplaced(self, stamp) -> int:
        """How many of the internet's rows have no place looked up yet, or one from a GeoIP file older than `stamp`
        (the file's own date, as text): what `place` would take. The GeoIP file needs opening only when it is not 0."""
        sql = "SELECT COUNT(*) FROM hosts WHERE network = ? AND (placed IS NULL OR placed <> ?)"
        stamp = _clip(stamp, PLACE_STAMP)
        self.stamp = stamp  # 1.102.0: what a new connection's place is taken from
        return self._read(lambda conn: conn.execute(sql, (INTERNET, stamp)).fetchone()[0], 0)

    def clear_places(self, role: str, pattern: str) -> int:
        """1.102.0: the places a source gave in `role` taken out, where no file in use can place them: rows whose
        stamp is LIKE `pattern` (geosources.cleared) lose country, code, city, lat and lon (places) or asn and org
        (networks), in hosts and connections both, and are placed again at the next ask. How many hosts rows."""
        columns = ("country = NULL, code = NULL, city = NULL, lat = NULL, lon = NULL" if role == "places" else
                   "asn = NULL, org = NULL")
        with self._lock:
            if not self._ready():
                return 0
            was_open = self._conn is not None
            try:
                conn = self._file(make=False)
                if conn is None:
                    return 0
                counted = []

                def write(c: sqlite3.Connection) -> None:
                    counted.append(c.execute(f"UPDATE hosts SET {columns}, placed = NULL WHERE placed LIKE ?",
                                             (pattern,)).rowcount)
                    c.execute(f"UPDATE connections SET {columns}, placed = NULL WHERE placed LIKE ?", (pattern,))
                self._transaction(conn, write)
            except (sqlite3.Error, OSError) as e:
                self._failed("written", e)
                return 0
            finally:
                if not was_open:
                    self._close()
            self.changes += 1
            return counted[0] if counted else 0

    def connections(self, *, program=None, proto="", port=0, direction="", since=None,
                    limit: int = 200) -> list[dict]:
        """Every connection's own row as last written, the newest first (by when it was first seen), filtered as
        `hosts` is (`since`: seen since), at most `limit` (CONNECTION_ROWS at the very most): each its who, what, when,
        why and where (CONNECTION_COLUMNS and the place's), and its host's route as kept (`route`: traced, reached,
        how, way; None where none was traced)."""
        clauses, args = _filters(program=program, proto=proto, port=port, direction=direction, since=since)
        most = max(1, min(int(limit or 1), CONNECTION_ROWS))
        columns = [f"c.{name}" for name in (*CONNECTION_COLUMNS, "country", "code", "city", "lat", "lon", "asn",
                                                  "org")]
        # the hosts' filters, on this table: "+port = ?" (of no index) as "+c.port = ?"
        where = _where([f"+c.{clause[1:]}" if clause.startswith("+") else f"c.{clause}" for clause in clauses])
        sql = (f"SELECT {', '.join(columns)}, r.traced, r.reached, r.how, r.way FROM connections c LEFT JOIN routes r "
               f"ON r.remote = c.remote{where} ORDER BY c.first DESC LIMIT ?")
        names = (*CONNECTION_COLUMNS, "country", "code", "city", "lat", "lon", "asn", "org")

        def work(conn):
            out = []
            for values in conn.execute(sql, (*args, most)):
                d = dict(zip(names, values[:len(names)]))
                traced, reached, how, way = values[len(names):]
                d["route"] = None if traced is None else {"traced": traced, "reached": bool(reached), "how": how,
                                                          "way": way}
                out.append(d)
            return out
        return self._read(work, [])

    def describe(self) -> dict:
        """The book, asking nothing of the hosts' rows: {"path", "rows" (as the last write left them), "hosts",
        "programs" (as counted at the last write that added or removed rows, not anew; past COUNT_ROWS rows at most
        every COUNT_S of the readings' time), "since", "last" (epoch seconds; None before any reading),
        "bytes" (the file's, its log's with it), "cap", "open" (connections open now), "not_kept" (connections of the
        last reading past MAX_OPEN, neither held nor counted), "cut" (whether the last reading's rows were cut: no
        connection ends then), "elsewhere" (why it is not kept from here, or ""), "problem" (a file set aside, a
        newer one left alone, a read or a write that failed, a reading cut; or "")}."""
        with self._lock:
            self._ready()
            size = 0
            if not self._elsewhere:
                for name in (str(self.path), f"{self.path}-wal"):
                    try:
                        size += os.stat(name).st_size
                    except OSError:
                        pass
            said = (self._refused, self._note, self._error, CUT_WORDS if self._cut else "")
            return {"path": str(self.path), "rows": self._n_rows, "hosts": self._n_hosts,
                    "programs": self._n_programs, "since": self._since, "last": self._last, "bytes": size,
                    "cap": self.cap, "open": self._up(), "not_kept": self._not_kept, "cut": self._cut,
                    "connections": self._n_connections,
                    "elsewhere": self._elsewhere, "problem": " ".join(words for words in said if words)}
