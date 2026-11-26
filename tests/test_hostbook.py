"""The hosts database (liminal_libs.hostbook; the user, 2026-11-16: "geoip'd hosts are databased for the apps they talk
to, the time they are connected to *this *computer", "so i can view apps connected to hosts all across the globe, or
ports talking to all hosts"), fed with readings whose times the tests set and whose judged rows are plain dicts: a
connection counted once and from the right moment on each system, time added only while it is established and never
for sleep (nor, for a socket begun between two readings, the time before it began), a table not read whole ending
nothing, a reading out of turn set aside, a row waiting to close kept once without time (one whose program let go of it
while it closes too), a connection carried over to the owner it is read with later, the open connections kept across a
restart, the cap and the counts kept by the writes, the filters (read through the table, never the index on last),
the places grouped and summed by point in the query and their sums alone, places looked up once a file, forgetting
(nothing of it left in the file), a clock set back, a file that is damaged or no database set aside wherever that is
found, a folder on another system's drive left alone, and one book for a path.

Nothing real: every file is under tmp_path, the socket reader is never imported (its rows are stood in), no process is
started, no socket opened and no network reached (this file's own guard, and the library's shared `no_outside`); each
of those fails the test that reaches it."""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from liminal_libs import geo, hostbook, layout, mounts
from liminal_libs.hostbook import (ALWAYS_S, CAP, COLUMNS, FILE, FLUSH_S, FOLDER, GAP_S, HOSTS_KEY, MAX_OPEN, MODES,
                                   NOT_NAMED, PLACE_ROWS, QUERY_ROWS, UP, VARIABLE, VERSION, ForgetRefused, HostBook)

pytestmark = pytest.mark.usefixtures("no_outside")  # the library's shared guard (tests/conftest.py), besides our own

OWN_PATH = hostbook.path  # the module's own, as imported: a suite's guard may move hostbook.path into its tmp_path
T0 = 1_800_000_000.0  # 2027-01-15 08:00:00 UTC
LAN, LAN6 = "192.168.1.20", "2001:db8:1::20"
WEB, WEB2, MAIL, SHELL, V6 = "203.0.113.5", "203.0.113.9", "198.51.100.20", "192.0.2.40", "2001:db8:ffff::5"
PRINTER = "192.168.1.50"
BROWSER, MAILER = "browser.exe", "mail.exe"
BROWSER_PATH = "C:\\Program Files\\Browser\\browser.exe"
OCTOBER, NOVEMBER, DECEMBER = "2026-10-01", "2026-11-01", "2026-12-01"  # GeoIP files' own dates
LONDON = geo.Place("GB", "United Kingdom", "London", 51.5142, -0.0931)
NUREMBERG = geo.Place("DE", "Germany", "Nuremberg", 49.4478, 11.0683, 64500, "Example Net")
AUSTRALIA = geo.Place("AU", "Australia", None, None, None)  # the country known, not the point
NOWHERE = {"new": 0, "ended": 0, "open": 0}


class Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def row(remote=WEB, remote_port=443, *, local=LAN, local_port=51000, proto="tcp", state="established", pid=4321,
        program=BROWSER, path=BROWSER_PATH, service="", started=None, inode=0, where="internet", direction="out",
        port=None, name="", **more) -> dict:
    """A judged row as the socket reader's judgement hands one (the plan's keys), stood in as a plain dict: by default
    a browser's connection out to a web server's 443 on the internet."""
    judged = {"proto": proto, "family": 6 if ":" in local else 4, "state": state, "local": local,
              "local_port": local_port, "remote": remote, "remote_port": remote_port, "pid": pid,
              "pids": [pid] if pid else [], "program": program,
              "path": path, "service": service, "service_title": "", "user": "", "started": started,
              "process_started": None, "count": 1, "unread": {}, "inode": inode, "where": where, "direction": direction,
              "port": port if port is not None else local_port if direction == "in" else remote_port, "place": None,
              "name": name}
    judged.update(more)
    return judged


def closing(remote=WEB, remote_port=443, **given) -> dict:
    """A row waiting to close: its owner has ended (no pid, no program, no start, no inode), its two ends are still
    listed."""
    return row(remote, remote_port, state="time-wait", pid=0, program="", path="", started=None, inode=0, **given)


def win(book: HostBook, at: float, *rows: dict, **reading) -> dict:
    """A Windows reading fed: its system says when each socket began."""
    return book.feed(list(rows), at, starts=True, **reading)


def lin(book: HostBook, at: float, *rows: dict, **reading) -> dict:
    """A Linux reading fed: no socket's start is known, each is known by its inode."""
    return book.feed(list(rows), at, starts=False, **reading)


def kept(book: HostBook, **filters) -> list[dict]:
    """The rows as they are in the file once what is pending is written."""
    book.flush()
    return book.hosts(**filters)


def one(book: HostBook, **filters) -> dict:
    [found] = kept(book, **filters)
    return found


def table(path: Path, name: str = "hosts") -> list[tuple]:
    """A table of the file, read apart from the book."""
    con = sqlite3.connect(path)
    try:
        return con.execute(f"SELECT * FROM {name}").fetchall()
    finally:
        con.close()


def atlas(places: dict, asked: list | None = None):
    """A GeoIP file's lookup as a stand-in: each host's place (None for one it has none for), the hosts asked noted."""
    def lookup(host):
        if asked is not None:
            asked.append(host)
        return places.get(host)
    return lookup


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch, tmp_path):
    """Nothing real is reached: no process started, no socket opened, nothing asked of the network, the socket table
    not read, and no database opened outside the test's own folder (this machine's data folder least of all). Each
    reach is noted, so one inside a thread is seen too. Every folder is this system's own unless a test says
    otherwise, each test has its own books, and every book it makes is closed after it. Yields the files opened."""
    reached: list[str] = []

    def refusing(name):
        def refuse(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"a test reached the real {name}")
        return refuse
    for module, name in ((subprocess, "Popen"), (subprocess, "run"), (urllib.request, "urlopen"), (socket, "socket"),
                         (socket, "create_connection")):
        monkeypatch.setattr(module, name, refusing(f"{module.__name__}.{name}"))
    reader = sys.modules.get("liminal_libs.sockets")  # another builder's, never imported here
    if reader is not None and hasattr(reader, "read"):
        monkeypatch.setattr(reader, "read", refusing("sockets.read"))
    monkeypatch.setattr(layout, "data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(mounts, "foreign", lambda path, mounts=None: False)
    monkeypatch.setattr(hostbook, "_BOOKS", {})
    opened: list[str] = []
    connect = sqlite3.connect

    def inside(database, *args, **kwargs):
        if not Path(database).resolve().is_relative_to(tmp_path.resolve()):
            reached.append(f"sqlite3.connect({database})")
            raise AssertionError(f"a test opened a database outside its own folder: {database}")
        opened.append(str(database))
        return connect(database, *args, **kwargs)
    monkeypatch.setattr(hostbook.sqlite3, "connect", inside)
    made: list[HostBook] = []
    init = HostBook.__init__

    def tracked(self, *args, **kwargs):
        init(self, *args, **kwargs)
        made.append(self)
    monkeypatch.setattr(HostBook, "__init__", tracked)
    yield opened
    for book in made:
        book.close()
    assert reached == []


@pytest.fixture
def db(tmp_path) -> Path:
    return tmp_path / "hosts" / FILE


# -- what the module says of itself ------------------------------------------------------------------------------------

def test_the_constants_the_setting_and_the_refusal_are_as_planned():
    assert (FOLDER, FILE, VERSION, CAP, MAX_OPEN, GAP_S, FLUSH_S, ALWAYS_S) == ("hosts", "hosts.db", 1, 50_000, 8192,
                                                                                30.0, 30.0, 5.0)
    assert (QUERY_ROWS, PLACE_ROWS, NOT_NAMED, hostbook.MAX_PENDING, hostbook.PLACES) == (20_000, 512, "?", 2000, 300)
    assert (VARIABLE, MODES) == ("LIMINAL_HOSTS_RECORDING", ("shown", "always"))
    assert (HOSTS_KEY.name, HOSTS_KEY.label, HOSTS_KEY.secret) == (VARIABLE, "Recording hosts", False)
    # one wording for the two modes everywhere
    assert "all the time the platform runs" in HOSTS_KEY.hint
    assert "only while this plugin's Netstat or World Wide Web tab is shown" in HOSTS_KEY.hint
    # the same six words as the socket reader's (kept here: a book needs no socket reader), and those a connection
    # closes in, the one where the far end has hung up and the program holds on to it left out
    assert UP == {"established", "close-wait", "fin-wait-1", "fin-wait-2", "closing", "last-ack"}
    assert hostbook.CLOSING == UP - {"established", "close-wait"}
    assert issubclass(ForgetRefused, ValueError) and ForgetRefused.accept == "accept_forget"
    assert (hostbook.TEXT, hostbook.PATH) == (128, 260)
    # a reading out of turn by at most four of the socket reader's READ_S; readings closer than one are one look
    assert (hostbook.STALE_S, hostbook.NEAR_S) == (10.0, 2.5)
    assert hostbook.POINTS == hostbook.MAX_PLACES == 512


def test_the_module_names_no_address_starts_nothing_and_keeps_its_lines_short():
    source = Path(hostbook.__file__).read_text(encoding="utf-8")
    assert "://" not in source  # no outside address in the library, docstrings included
    for word in ("subprocess", "socket.", "import socket", "urllib", "WinDLL", "import pwd", "winreg", "from .storage",
                 "storage.link import", "import sockets", "gethostby", "getnameinfo", "Thread("):
        assert word not in source, word
    assert max(len(line) for line in source.splitlines()) <= 120
    assert "about 13 MB with ordinary values" in source


def test_the_file_is_in_the_data_folder_one_for_each_system(tmp_path):
    assert OWN_PATH() == tmp_path / "data" / "hosts" / "hosts.db"  # layout.data_dir() is stood in by tmp_path
    assert HostBook().path == hostbook.path() and HostBook(cap=7).cap == 7
    assert hostbook.path().resolve().is_relative_to(tmp_path.resolve())
    assert hostbook.foreign() == "" and hostbook.foreign(tmp_path / "x.db") == ""


# -- rules 1 and 2: what counts, and from when -----------------------------------------------------------------------

def test_a_first_reading_counts_a_connection_from_its_sockets_own_start(db):
    b = HostBook(db)
    assert win(b, T0, row(started=T0 - 3600)) == {"new": 1, "ended": 0, "open": 1}
    assert b.hosts() == []  # in memory until it is written
    h = one(b)
    assert set(h) == set(COLUMNS)
    assert (h["program"], h["host"], h["proto"], h["port"], h["direction"]) == (BROWSER, WEB, "tcp", 443, "out")
    assert (h["path"], h["service"], h["network"], h["name"]) == (BROWSER_PATH, "", "internet", "")
    assert (h["connections"], h["seconds"], h["first"], h["last"]) == (1, 3600.0, T0 - 3600, T0)
    assert (h["lat"], h["lon"], h["asn"], h["country"], h["code"], h["city"], h["org"], h["placed"]) == (
        None, None, None, "", "", "", "", "")  # a new row has no place
    d = b.describe()
    assert (d["rows"], d["hosts"], d["programs"], d["open"], d["since"], d["last"]) == (1, 1, 1, 1, T0, T0)
    assert d["path"] == str(db) and d["cap"] == CAP and d["bytes"] > 0 and d["not_kept"] == 0
    assert (d["elsewhere"], d["problem"]) == ("", "")
    json.dumps([d, b.hosts(), b.programs(), b.ports(), b.places()], allow_nan=False)


def test_where_the_system_says_no_starts_a_connection_counts_from_the_reading_that_first_saw_it(db):
    b = HostBook(db)
    first = row(inode=7001, program="firefox", path="/usr/lib/firefox/firefox")
    assert lin(b, T0, first) == {"new": 1, "ended": 0, "open": 1}
    h = one(b)
    assert (h["program"], h["path"], h["connections"], h["seconds"], h["first"], h["last"]) == (
        "firefox", "/usr/lib/firefox/firefox", 1, 0.0, T0, T0)
    # a start a Linux row might carry is not the socket's own: it is not read
    lin(b, T0 + 5, row(inode=7001, program="firefox"), row(WEB2, inode=7002, program="firefox", started=T0 - 999))
    assert [(h["host"], h["seconds"], h["first"]) for h in kept(b)] == [(WEB, 5.0, T0), (WEB2, 0.0, T0 + 5)]


def test_a_new_connection_never_counts_time_before_the_reading_before_it(db):
    b = HostBook(db)
    win(b, T0, row(started=T0 - 100))
    out = win(b, T0 + 5, row(started=T0 - 100),
              row(WEB2, started=T0 - 50, local_port=51001),  # there before the last reading, yet not counted then
              row(MAIL, 993, started=T0 + 2, local_port=51002, program=MAILER))  # began after it
    assert out == {"new": 2, "ended": 0, "open": 3}
    rows = {h["host"]: h for h in kept(b)}
    assert (rows[WEB]["seconds"], rows[WEB]["first"], rows[WEB]["connections"]) == (105.0, T0 - 100, 1)
    assert (rows[WEB2]["seconds"], rows[WEB2]["first"]) == (5.0, T0)  # from the reading before, not from its start
    assert (rows[MAIL]["seconds"], rows[MAIL]["first"]) == (3.0, T0 + 2)  # from its own start
    assert all(h["last"] == T0 + 5 for h in rows.values())


def test_only_a_row_that_is_up_with_a_remote_host_elsewhere_counts(db):
    b = HostBook(db)
    out = win(b, T0,
              row("127.0.0.1", 8765, where="this machine", direction="local", started=T0),  # this machine's own
              row(LAN, 8775, where="this machine", direction="local", started=T0),  # by its own address, too
              row("", 0, state="listening", where="", direction="", local="0.0.0.0", local_port=8765, started=T0),
              row("", 0, proto="udp", state="bound", where="", direction="", local_port=5353, started=T0),
              row(WEB, state="syn-sent", started=T0), row(WEB, state="closed", started=T0, local_port=51009),
              row(WEB, proto="udp", state="bound", started=T0), row(WEB, where="", started=T0),
              row(WEB, proto="icmp", started=T0), "no row at all", None)
    assert out == NOWHERE and kept(b) == [] and b.describe()["rows"] == 0
    for n, state in enumerate(sorted(UP)):  # every state that is up counts as a connection
        assert win(b, T0 + 1, row(local_port=52000 + n, state=state, started=T0))["new"] == 1
    asked = row(proto="udp", state="connected", remote_port=53, inode=5)  # Linux says a connected UDP socket's peer
    assert lin(HostBook(db.with_name("linux.db")), T0, asked) == {"new": 1, "ended": 0, "open": 1}


def test_a_program_not_read_is_kept_as_not_named_and_the_port_is_the_services(db):
    b = HostBook(db)
    win(b, T0, row(program="", path="", started=T0),
        row(SHELL, 50123, local_port=22, direction="in", program="sshd.exe", path="", started=T0, service="sshd",
            name="laptop.lan"))
    unnamed, shell = sorted(kept(b), key=lambda h: h["direction"], reverse=True)
    assert (unnamed["program"], unnamed["port"], unnamed["direction"]) == (NOT_NAMED, 443, "out")
    assert (shell["program"], shell["port"], shell["direction"], shell["service"], shell["name"]) == (
        "sshd.exe", 22, "in", "sshd", "laptop.lan")
    # a row that says no port of the service's: the local one for a connection in, else the remote one
    b2 = HostBook(db.with_name("other.db"))
    shell, web = row(SHELL, 50123, local_port=22, direction="in", started=T0), row(WEB, started=T0)
    shell["port"], web["port"] = 0, None
    win(b2, T0, shell, web)
    assert sorted((h["host"], h["port"]) for h in kept(b2)) == [(SHELL, 22), (WEB, 443)]


def test_texts_are_cut_to_128_characters_and_a_path_to_260(db):
    b = HostBook(db)
    win(b, T0, row(program="p" * 500, path="C:\\" + "d" * 1000, service="s" * 500, name="n" * 500, started=T0))
    h = one(b)
    assert (len(h["program"]), len(h["path"]), len(h["service"]), len(h["name"])) == (128, 260, 128, 128)
    assert b.place(atlas({WEB: geo.Place("G" * 50, "C" * 500, "T" * 500, 1.0, 2.0, 7, "O" * 500)}), "9" * 100) == 1
    h = one(b)
    # 1.101.0: a place's stamp keeps PLACE_STAMP (64) characters: #<places>:<date>+<networks>:<date>
    assert [len(h[k]) for k in ("country", "code", "city", "org", "placed")] == [128, 8, 128, 128, 64]


def test_a_connection_is_known_again_by_its_key_on_each_system(db):
    b = HostBook(db)
    win(b, T0, row(started=T0 - 10))
    # the same two ends, pid and start: the same connection; the same ends with another start: a port used again
    assert win(b, T0 + 5, row(started=T0 - 10))["new"] == 0
    assert win(b, T0 + 10, row(started=T0 + 7)) == {"new": 1, "ended": 1, "open": 1}
    assert win(b, T0 + 15, row(started=T0 + 7, pid=999)) == {"new": 1, "ended": 1, "open": 1}  # another process's
    assert one(b)["connections"] == 3
    # Linux: by the socket's inode, whatever is known of its process (another user's has none)
    x = HostBook(db.with_name("linux.db"))
    lin(x, T0, row(inode=31, pid=0, program=""))
    assert lin(x, T0 + 5, row(inode=31, pid=0, program=""))["new"] == 0
    assert lin(x, T0 + 10, row(inode=31, pid=812, program="curl"))["new"] == 0  # its program read since: no new one
    assert lin(x, T0 + 15, row(inode=32, pid=812, program="curl")) == {"new": 1, "ended": 1, "open": 1}
    assert sorted((h["program"], h["connections"], h["seconds"]) for h in kept(x)) == [("?", 1, 10.0), ("curl", 1, 0.0)]


# -- rule 3: the time added ------------------------------------------------------------------------------------------

def test_the_gap_between_two_readings_is_time_connected_on_windows_and_not_on_linux(db):
    w = HostBook(db)
    win(w, T0, row(started=T0 - 60), awake=1000.0)
    assert win(w, T0 + 300, row(started=T0 - 60), awake=1300.0) == {"new": 0, "ended": 0, "open": 1}
    h = one(w)
    assert (h["seconds"], h["connections"], h["last"]) == (360.0, 1, T0 + 300)  # the same socket by its own start

    x = HostBook(db.with_name("linux.db"))
    lin(x, T0, row(inode=7001), awake=1000.0)
    assert lin(x, T0 + 300, row(inode=7001), awake=1300.0) == {"new": 0, "ended": 0, "open": 1}
    assert (one(x)["seconds"], one(x)["connections"]) == (0.0, 1)  # a gap longer than GAP_S: nothing, and no new one
    lin(x, T0 + 300 + GAP_S, row(inode=7001), awake=1300.0 + GAP_S)
    assert one(x)["seconds"] == GAP_S  # a gap of GAP_S or less is time it was up
    lin(x, T0 + 305 + GAP_S, row(inode=7001), awake=1305.0 + GAP_S)
    assert one(x)["seconds"] == GAP_S + 5


def test_sleep_is_not_time_connected(db):
    b = HostBook(db)
    win(b, T0, row(started=T0 - 10), awake=1000.0)
    win(b, T0 + 28800, row(started=T0 - 10), awake=1060.0)  # a night later by the wall clock, a minute awake
    assert one(b)["seconds"] == 70.0
    win(b, T0 + 28805, row(started=T0 - 10), awake=5.0)  # the awake clock went back: the system restarted
    assert one(b)["seconds"] == 70.0
    win(b, T0 + 28810, row(started=T0 - 10), awake=10.0)
    assert one(b)["seconds"] == 75.0
    win(b, T0 + 29110, row(started=T0 - 10))  # a reading with no awake clock: a gap longer than GAP_S adds nothing
    assert one(b)["seconds"] == 75.0
    win(b, T0 + 29130, row(started=T0 - 10))  # ... and a short one is added
    assert one(b)["seconds"] == 95.0
    win(b, T0 + 29135, row(started=T0 - 10), awake=40.0)  # one awake clock is no pair: by the wall clock, bounded
    assert one(b)["seconds"] == 100.0
    win(b, T0 + 29140, row(started=T0 - 10), awake=42.0)  # the lesser of the two clocks
    assert (one(b)["seconds"], one(b)["connections"]) == (102.0, 1)


def test_a_new_connection_is_not_given_the_sleep_before_it_was_seen_either(db):
    b = HostBook(db)
    win(b, T0, awake=1000.0)  # a reading with nothing connected
    win(b, T0 + 28800, row(started=T0 - 500), row(WEB2, started=T0 + 10, local_port=51001), awake=1060.0)
    rows = {h["host"]: h for h in kept(b)}
    assert (rows[WEB]["seconds"], rows[WEB]["first"]) == (60.0, T0)  # began before the last reading: the awake minute
    # began 10 s after it and slept through: the night is after its start (it is far longer than those 10 s), so the
    # minute awake less the 10 s before the socket began
    assert (rows[WEB2]["seconds"], rows[WEB2]["first"]) == (50.0, T0 + 10)


def test_a_socket_begun_in_a_gap_is_given_neither_the_sleep_nor_the_time_awake_before_it_began(db):
    """A socket that began between two readings far apart (the tab not shown meanwhile) was up from its start, less
    the sleep in the gap: the wall clock's gap less the awake clock's, taken as after its start, unless it is longer
    than the socket has been open and fits before it (a socket begins while the system is awake). With no two awake
    readings, its time is the system's time awake at the most."""
    H = 3600.0
    evening = HostBook(db)
    win(evening, T0, awake=5 * H)  # 10:10, the tab closed
    # 17:00 a connection opens; 23:00 to 07:00 the system sleeps (the row stays listed); 08:00 the tab is shown again
    win(evening, T0 + 21 * H + 50 * 60, row(started=T0 + 6 * H + 50 * 60), awake=5 * H + 13 * H + 50 * 60)
    assert one(evening)["seconds"] == 7 * H  # up while awake: 17:00 to 23:00 and 07:00 to 08:00, not 13 h 50 min
    morning = HostBook(db.with_name("morning.db"))
    win(morning, T0, awake=5 * H)  # 22:00, the tab closed; the system sleeps 23:00 to 07:00
    win(morning, T0 + 11 * H, row(started=T0 + 10 * H), awake=8 * H)  # opened at 08:00, the tab shown at 09:00
    assert one(morning)["seconds"] == H  # the night does not fit after its start: all of its hour
    awake = HostBook(db.with_name("awake.db"))
    win(awake, T0, awake=5 * H)
    win(awake, T0 + 2 * H, row(started=T0 + H), awake=7 * H)  # no sleep between the readings: all its time
    assert one(awake)["seconds"] == H
    restarted = HostBook(db.with_name("restarted.db"))
    win(restarted, T0, awake=50 * H)  # then the system starts again, and later sleeps ten hours
    # opened ten minutes after the start, read twelve hours after it: two hours awake since the system started
    win(restarted, T0 + 13 * H, row(started=T0 + H + 600), awake=2 * H)
    assert one(restarted)["seconds"] == 2 * H  # its time awake at the most, not 11 h 50 min


def test_a_new_file_does_not_give_a_socket_the_sleep_before_it_either(db):
    b = HostBook(db)
    # opened three days ago; this system has been awake one day of that since it started
    win(b, T0, row(started=T0 - 3 * 86400), row(WEB2, started=T0 - 600, local_port=51001), awake=86400.0)
    rows = {h["host"]: h for h in kept(b)}
    assert (rows[WEB]["first"], rows[WEB]["seconds"]) == (T0 - 3 * 86400, 86400.0)  # its awake life at the most
    assert (rows[WEB2]["first"], rows[WEB2]["seconds"]) == (T0 - 600, 600.0)


def test_time_is_added_only_while_a_connection_is_established(db):
    b = HostBook(db)
    win(b, T0, row(started=T0))
    win(b, T0 + 5, row(started=T0))
    # the far end has hung up and the program has not closed it: open still, connected no more
    assert win(b, T0 + 10, row(started=T0, state="close-wait")) == {"new": 0, "ended": 0, "open": 1}
    assert win(b, T0 + 15, row(started=T0, state="close-wait")) == {"new": 0, "ended": 0, "open": 1}
    assert win(b, T0 + 20) == {"new": 0, "ended": 1, "open": 0}
    h = one(b)
    assert (h["seconds"], h["connections"], h["last"]) == (5.0, 1, T0 + 15)
    # one first seen when it was no longer established is a connection, with no time
    win(b, T0 + 25, row(MAIL, 993, state="fin-wait-2", started=T0 - 1000, local_port=51005))
    late = one(b, port=993)
    assert (late["connections"], late["seconds"]) == (1, 0.0)
    # UDP has one state that is up
    x = HostBook(db.with_name("linux.db"))
    lin(x, T0, row(proto="udp", state="connected", remote_port=53, inode=5))
    lin(x, T0 + 5, row(proto="udp", state="connected", remote_port=53, inode=5))
    assert (one(x)["proto"], one(x)["port"], one(x)["seconds"]) == ("udp", 53, 5.0)


# -- rule 4: what has ended ------------------------------------------------------------------------------------------

def test_a_connection_gone_from_a_reading_has_ended_and_adds_nothing_past_its_last_reading(db):
    b = HostBook(db)
    win(b, T0, row(started=T0 - 10))
    win(b, T0 + 5, row(started=T0 - 10))
    assert win(b, T0 + 10) == {"new": 0, "ended": 1, "open": 0}
    assert win(b, T0 + 20) == NOWHERE
    h = one(b)
    assert (h["seconds"], h["last"], h["connections"]) == (15.0, T0 + 5, 1)
    assert win(b, T0 + 25, row(started=T0 + 22)) == {"new": 1, "ended": 0, "open": 1}  # the same ends, a new socket
    h = one(b)
    assert (h["seconds"], h["last"], h["connections"], h["first"]) == (18.0, T0 + 25, 2, T0 - 10)


def test_a_table_not_read_whole_ends_nothing_and_neither_does_a_reading_that_was_cut(db):
    b = HostBook(db)
    web = row(started=T0)
    six = row(V6, local=LAN6, local_port=52000, started=T0, pid=77, program=MAILER)  # in the tcp6 table
    assert win(b, T0, web, six) == {"new": 2, "ended": 0, "open": 2}
    # Windows' tcp4 table could not be read this once: its connections are not ended, the other table's are
    assert b.feed([], T0 + 5, starts=True, read=("tcp6", "udp4", "udp6")) == {"new": 0, "ended": 1, "open": 1}
    assert win(b, T0 + 10, web) == {"new": 0, "ended": 0, "open": 1}  # not counted again
    # a reading whose rows were cut ends none
    assert b.feed([], T0 + 15, starts=True, cut=True) == {"new": 0, "ended": 0, "open": 1}
    assert b.feed([], T0 + 16, starts=True, read=()) == {"new": 0, "ended": 0, "open": 1}  # no table read whole
    assert win(b, T0 + 20, web) == {"new": 0, "ended": 0, "open": 1}
    rows = {h["host"]: h for h in kept(b)}
    assert (rows[WEB]["connections"], rows[WEB]["seconds"]) == (1, 20.0)  # the time between the readings that saw it
    assert (rows[V6]["connections"], rows[V6]["seconds"], rows[V6]["last"]) == (1, 0.0, T0)
    assert win(b, T0 + 25) == {"new": 0, "ended": 1, "open": 0}  # read whole again, and gone: ended


def test_a_reading_that_was_cut_is_said_while_it_keeps_connections_open(db):
    b = HostBook(db)
    win(b, T0, row(started=T0))
    assert b.feed([], T0 + 5, starts=True, read=("tcp6", "udp4", "udp6"), cut=True) == {
        "new": 0, "ended": 0, "open": 1}
    d = b.describe()
    assert d["cut"] is True and d["problem"] == (
        "The socket table's last reading was cut, more sockets being listed than one reading takes: no connection "
        "ends while readings are cut, so the ones that ended stay open here until a reading is whole.")
    assert win(b, T0 + 10) == {"new": 0, "ended": 1, "open": 0}
    assert (b.describe()["cut"], b.describe()["problem"]) == (False, "")


# -- rule 5: across a restart ----------------------------------------------------------------------------------------

def test_a_restart_goes_on_where_it_stopped(db):
    with HostBook(db) as first:
        win(first, T0, row(started=T0 - 60), awake=100.0)
    assert table(db, "open") != []
    assert dict(table(db, "meta")) == {"version": 1, "since": T0, "last": T0, "awake": 100.0}
    b = HostBook(db)
    d = b.describe()
    assert (d["open"], d["since"], d["last"], d["rows"], d["hosts"], d["programs"]) == (1, T0, T0, 1, 1, 1)
    # Windows: the socket is still there by its own start, so the two minutes the platform was down are time it was up
    out = win(b, T0 + 120, row(started=T0 - 60), row(WEB2, started=T0 + 100, local_port=51001), awake=220.0)
    assert out == {"new": 1, "ended": 0, "open": 2}
    rows = {h["host"]: h for h in kept(b)}
    assert (rows[WEB]["seconds"], rows[WEB]["connections"]) == (180.0, 1)  # nothing counted twice
    assert (rows[WEB2]["seconds"], rows[WEB2]["first"]) == (20.0, T0 + 100)  # began while it was down: from its start
    b.close()
    assert win(HostBook(db), T0 + 130, awake=230.0) == {"new": 0, "ended": 2, "open": 0}  # ended across a restart, too


def test_a_restart_on_linux_counts_only_a_gap_within_the_gap(db):
    with HostBook(db) as first:
        lin(first, T0, row(inode=9), awake=100.0)
    b = HostBook(db)
    assert lin(b, T0 + 120, row(inode=9), awake=220.0) == {"new": 0, "ended": 0, "open": 1}
    assert (one(b)["seconds"], one(b)["connections"]) == (0.0, 1)
    b.close()
    again = HostBook(db)
    lin(again, T0 + 125, row(inode=9), awake=225.0)
    assert (one(again)["seconds"], one(again)["connections"]) == (5.0, 1)


def test_nothing_is_counted_twice_when_a_reading_is_fed_twice(db):
    b = HostBook(db)
    reading = [row(started=T0 - 30), row(MAIL, 993, started=T0 - 5, local_port=51001, program=MAILER)]
    assert b.feed(iter(reading), T0, starts=True, awake=50.0) == {"new": 2, "ended": 0, "open": 2}
    assert b.feed(iter(reading), T0, starts=True, awake=50.0) == {"new": 0, "ended": 0, "open": 2}
    assert sorted((h["host"], h["connections"], h["seconds"]) for h in kept(b)) == [(MAIL, 1, 5.0), (WEB, 1, 30.0)]


def test_a_reading_taken_before_the_last_one_fed_is_set_aside(db):
    """Two feeders of one book (two views, or a recording thread and a page's ask) may hand it a reading taken before
    the last one it was fed: that reading is set aside, so no connection is counted again or ended early."""
    b = HostBook(db)
    x, y = row(started=T0 - 10), row(WEB2, local_port=51001, started=T0 + 4.5)  # y began between the two readings
    win(b, T0, x, awake=100.0)
    assert win(b, T0 + 5, y, awake=105.0) == {"new": 1, "ended": 1, "open": 1}  # the second view's: x gone, y new
    assert win(b, T0 + 4, x, awake=104.0) == {"new": 0, "ended": 0, "open": 1}  # the first view's, taken first
    assert win(b, T0 + 10, y, awake=110.0) == {"new": 0, "ended": 0, "open": 1}
    rows = {h["host"]: h for h in kept(b)}
    assert (rows[WEB]["connections"], rows[WEB]["seconds"], rows[WEB]["last"]) == (1, 10.0, T0)
    assert (rows[WEB2]["connections"], rows[WEB2]["seconds"], rows[WEB2]["first"]) == (1, 5.5, T0 + 4.5)
    # by the awake clock where there is one: taken before the last one fed, though the wall clock was set back since
    assert win(b, T0 + 12, x, awake=109.0) == {"new": 0, "ended": 0, "open": 1}
    # the wall clock set back while the awake clock went on is no older reading: it is read, and adds nothing
    assert win(b, T0 + 8, y, awake=113.0) == {"new": 0, "ended": 0, "open": 1}
    assert win(b, T0 + 13, y, awake=118.0) == {"new": 0, "ended": 0, "open": 1}
    rows = {h["host"]: h for h in kept(b)}
    assert (rows[WEB]["connections"], rows[WEB2]["connections"], rows[WEB2]["seconds"]) == (1, 1, 10.5)
    # without an awake clock, by the wall clock alone
    z = HostBook(db.with_name("wall.db"))
    win(z, T0, x)
    win(z, T0 + 5, y)
    assert win(z, T0 + 4, x) == {"new": 0, "ended": 0, "open": 1}
    assert [(h["host"], h["connections"]) for h in kept(z)] == [(WEB2, 1), (WEB, 1)]


def test_a_row_waiting_to_close_is_known_by_the_reading_its_connection_ended_in_whoever_fed_it(db):
    """'This reading or the last': a reading another view took just after the one where a connection ended is not
    taken for the last, a reading fed twice is one reading, and the window goes on across a restart."""
    b = HostBook(db)
    win(b, T0, row(started=T0 - 20), awake=100.0)
    assert win(b, T0 + 5, awake=105.0) == {"new": 0, "ended": 1, "open": 0}
    assert win(b, T0 + 6, awake=106.0) == NOWHERE  # the other view's reading, a second later
    assert win(b, T0 + 10, closing(), awake=110.0) == NOWHERE  # the next one of the first view's
    assert [(h["program"], h["connections"]) for h in kept(b)] == [(BROWSER, 1)]

    twice = HostBook(db.with_name("twice.db"))
    win(twice, T0, row(started=T0 - 20), awake=100.0)
    win(twice, T0 + 5, awake=105.0)
    assert win(twice, T0 + 5, awake=105.0) == NOWHERE
    assert win(twice, T0 + 10, closing(), awake=110.0) == NOWHERE
    assert [(h["program"], h["connections"]) for h in kept(twice)] == [(BROWSER, 1)]

    with HostBook(db.with_name("restart.db")) as first:
        win(first, T0, row(started=T0 - 20), awake=100.0)
        win(first, T0 + 5, awake=105.0)
    again = HostBook(db.with_name("restart.db"))
    assert win(again, T0 + 10, closing(), awake=110.0) == NOWHERE
    assert [(h["program"], h["connections"]) for h in kept(again)] == [(BROWSER, 1)]
    assert win(again, T0 + 15, awake=115.0) == NOWHERE and win(again, T0 + 20, closing(), awake=120.0)["new"] == 1


def test_a_reading_with_no_time_changes_nothing(db):
    b = HostBook(db)
    win(b, T0, row(started=T0))
    for at in (None, "now", float("nan"), float("inf"), True):
        assert b.feed([row(WEB2, started=T0)], at, starts=True) == {"new": 0, "ended": 0, "open": 1}
    assert [h["host"] for h in kept(b)] == [WEB] and b.describe()["last"] == T0


# -- a row waiting to close --------------------------------------------------------------------------------------------

def test_a_row_waiting_to_close_whose_connection_was_never_seen_is_kept_once_without_time(db):
    b = HostBook(db)
    assert win(b, T0, closing()) == {"new": 1, "ended": 0, "open": 0}  # a connection, not one open
    h = one(b)
    assert (h["program"], h["host"], h["port"], h["direction"], h["connections"], h["seconds"]) == (
        NOT_NAMED, WEB, 443, "out", 1, 0.0)
    for later in (5, 10, 60):  # it stands in the table for minutes: held, never counted again, never given time
        assert win(b, T0 + later, closing()) == NOWHERE
    assert (one(b)["connections"], one(b)["seconds"], one(b)["last"]) == (1, 0.0, T0)
    assert win(b, T0 + 65) == NOWHERE  # it left the table: no connection ended, the mark let go
    assert win(b, T0 + 70, closing()) == {"new": 1, "ended": 0, "open": 0}  # the same ends, waiting again: another
    assert one(b)["connections"] == 2
    # this machine's own are never kept, waiting or not; nor one without a remote
    assert win(b, T0 + 75, closing(), closing("127.0.0.1", 8765, where="this machine", direction="local"),
               closing("", 0, where="")) == NOWHERE
    assert len(kept(b)) == 1


def test_a_row_waiting_to_close_whose_connection_was_counted_adds_nothing(db):
    b = HostBook(db)
    win(b, T0, row(started=T0 - 20))
    # its own row turned into the one waiting to close: it ended in this reading
    assert win(b, T0 + 5, closing()) == {"new": 0, "ended": 1, "open": 0}
    assert win(b, T0 + 10, closing()) == NOWHERE
    assert [(h["program"], h["connections"]) for h in kept(b)] == [(BROWSER, 1)]

    # gone from one reading, waiting to close in the next: it ended in the last reading
    x = HostBook(db.with_name("last.db"))
    win(x, T0, row(started=T0 - 20))
    assert win(x, T0 + 5) == {"new": 0, "ended": 1, "open": 0}
    assert win(x, T0 + 10, closing()) == NOWHERE
    assert win(x, T0 + 15, closing()) == NOWHERE  # held from then on
    assert [(h["program"], h["connections"]) for h in kept(x)] == [(BROWSER, 1)]

    # two readings after its connection ended it is another's: one that began and ended unseen on the same ends
    y = HostBook(db.with_name("later.db"))
    win(y, T0, row(started=T0 - 20))
    win(y, T0 + 5)
    win(y, T0 + 10)
    assert win(y, T0 + 15, closing()) == {"new": 1, "ended": 0, "open": 0}
    assert sorted((h["program"], h["connections"]) for h in kept(y)) == [(NOT_NAMED, 1), (BROWSER, 1)]


def test_a_row_waiting_to_close_beside_its_connection_still_open_here_waits_for_it_to_end(db):
    b = HostBook(db)
    lin(b, T0, row(inode=41, program="curl"))
    # a reading that was cut ends no key: the row waiting to close has the two ends of a connection still open here
    assert lin(b, T0 + 5, closing(), cut=True) == {"new": 0, "ended": 0, "open": 1}
    assert lin(b, T0 + 10, closing()) == {"new": 0, "ended": 1, "open": 0}  # read whole: it ended, and adds nothing
    assert lin(b, T0 + 15, closing()) == NOWHERE
    assert [(h["program"], h["connections"]) for h in kept(b)] == [("curl", 1)]


def test_a_row_waiting_to_close_is_held_across_a_restart(db):
    with HostBook(db) as first:
        assert lin(first, T0, closing(direction="in", local_port=22, remote_port=50001))["new"] == 1
    [(key, program, *_rest, waiting)] = table(db, "open")
    assert (json.loads(key), program, waiting) == (["tcp", LAN, 22, WEB, 50001, "w"], NOT_NAMED, 1)
    b = HostBook(db)
    assert b.describe()["open"] == 0
    assert lin(b, T0 + 30, closing(direction="in", local_port=22, remote_port=50001)) == NOWHERE
    h = one(b)
    assert (h["program"], h["port"], h["direction"], h["connections"]) == (NOT_NAMED, 22, "in", 1)


def test_a_connection_its_program_closed_waits_to_close_as_the_same_connection(db):
    """A socket its program has closed is listed with no owner while it closes (Linux: no inode, in fin-wait-1,
    fin-wait-2, closing or last-ack, then time-wait; Windows: no pid): it is the connection counted already, not
    another under NOT_NAMED. One its program still holds while it closes is its program's, as before."""
    gone = {"inode": 0, "pid": 0, "program": "", "path": ""}
    b = HostBook(db)
    lin(b, T0, row(inode=7001, program="firefox"))
    assert lin(b, T0 + 5, row(state="fin-wait-2", **gone)) == {"new": 0, "ended": 1, "open": 0}
    assert lin(b, T0 + 10, row(state="time-wait", **gone)) == NOWHERE  # held from then on, as one waiting
    # the far end closed first: close-wait while the program holds it, then last-ack once it closed it
    lin(b, T0 + 15, row(WEB2, inode=7002, program="firefox", local_port=51001))
    assert lin(b, T0 + 20, row(WEB2, state="close-wait", inode=7002, program="firefox", local_port=51001)) == {
        "new": 0, "ended": 0, "open": 1}
    assert lin(b, T0 + 25, row(WEB2, state="last-ack", local_port=51001, **gone)) == {"new": 0, "ended": 1, "open": 0}
    assert lin(b, T0 + 30) == NOWHERE
    assert sorted((h["host"], h["program"], h["connections"]) for h in kept(b)) == [
        (WEB, "firefox", 1), (WEB2, "firefox", 1)]
    # one first seen already closed by its program began and ended unseen: counted once, under NOT_NAMED, no time
    closed = [row(MAIL, 993, state=state, local_port=52000 + n, **gone)
              for n, state in enumerate(("fin-wait-1", "fin-wait-2", "closing", "last-ack"))]
    assert lin(b, T0 + 35, *closed) == {"new": 4, "ended": 0, "open": 0}
    assert lin(b, T0 + 40, *closed) == NOWHERE
    assert (one(b, port=993)["program"], one(b, port=993)["connections"], one(b, port=993)["seconds"]) == (
        NOT_NAMED, 4, 0.0)
    # one its program still holds while it closes (Linux: its inode) is its program's open connection
    assert lin(b, T0 + 45, row(SHELL, state="fin-wait-1", inode=7003, program="curl", local_port=51002)) == {
        "new": 1, "ended": 0, "open": 1}
    assert one(b, program="curl")["connections"] == 1

    w = HostBook(db.with_name("windows.db"))
    win(w, T0, row(started=T0 - 30))
    assert win(w, T0 + 5, row(state="fin-wait-2", pid=0, program="", path="")) == {"new": 0, "ended": 1, "open": 0}
    assert win(w, T0 + 10, closing()) == NOWHERE
    assert [(h["program"], h["connections"], h["seconds"]) for h in kept(w)] == [(BROWSER, 1, 30.0)]
    assert win(w, T0 + 15, row(WEB2, state="fin-wait-1", started=T0 + 12, local_port=51001)) == {
        "new": 1, "ended": 0, "open": 1}  # its program's still: by its pid and its start


def test_a_connection_seen_before_its_owner_was_known_is_carried_over(db):
    """Linux lists a connection still waiting to be accepted with no inode; once accepted it has one: the same
    connection, counted once, its time going on (under NOT_NAMED, where it was counted)."""
    b = HostBook(db)
    waiting = row(SHELL, 50123, local_port=22, direction="in", inode=0, pid=0, program="", path="")
    assert lin(b, T0, waiting) == {"new": 1, "ended": 0, "open": 1}
    accepted = row(SHELL, 50123, local_port=22, direction="in", inode=812, pid=900, program="sshd",
                   path="/usr/sbin/sshd")
    assert lin(b, T0 + 5, accepted) == {"new": 0, "ended": 0, "open": 1}
    assert lin(b, T0 + 10, accepted) == {"new": 0, "ended": 0, "open": 1}
    h = one(b)
    assert (h["program"], h["connections"], h["seconds"], h["path"]) == (NOT_NAMED, 1, 10.0, "")
    assert lin(b, T0 + 15) == {"new": 0, "ended": 1, "open": 0}
    # the same on Windows, where a row with no owner has no pid
    w = HostBook(db.with_name("windows.db"))
    assert win(w, T0, row(pid=0, program="", path="", started=None)) == {"new": 1, "ended": 0, "open": 1}
    assert win(w, T0 + 5, row(started=T0 - 30)) == {"new": 0, "ended": 0, "open": 1}
    assert (one(w)["connections"], one(w)["seconds"]) == (1, 5.0)


def test_a_program_read_later_leaves_the_not_named_rows_words_as_they_were(db):
    """A connection first read with no program stays counted under NOT_NAMED; its program, read later, adds time
    there but writes no path or service of its own onto a row many programs share. The host's own name is kept."""
    b = HostBook(db)
    lin(b, T0, row(inode=31, pid=0, program="", path=""))
    lin(b, T0 + 5, row(inode=31, pid=812, program="curl", path="/usr/bin/curl", service="backup.service",
                       name="mirror.example"))
    h = one(b)
    assert (h["program"], h["path"], h["service"], h["name"], h["seconds"]) == (NOT_NAMED, "", "", "mirror.example",
                                                                                5.0)
    assert b.programs()[0]["path"] == ""


# -- the bounds --------------------------------------------------------------------------------------------------------

def test_the_rows_longest_unseen_are_pruned_first_past_the_cap(db):
    b = HostBook(db, cap=5)
    stays = row(MAIL, 993, started=T0, local_port=50999, program=MAILER)  # seen in every reading
    for i in range(8):
        win(b, T0 + i, stays, row(f"203.0.113.{i + 1}", started=T0 + i, local_port=51000 + i))
    rows = kept(b)
    assert len(rows) == 5 and b.describe()["rows"] == 5 and b.describe()["hosts"] == 5
    assert [h["host"] for h in rows] == ["203.0.113.8", MAIL, "203.0.113.7", "203.0.113.6", "203.0.113.5"]
    win(b, T0 + 8, stays, row("203.0.113.9", started=T0 + 8, local_port=51008))
    assert [h["host"] for h in kept(b)] == ["203.0.113.9", MAIL, "203.0.113.8", "203.0.113.7", "203.0.113.6"]

    big = HostBook(db.with_name("big.db"), cap=200)  # a hundredth under the cap, so a prune is not every flush's
    win(big, T0, *(row(f"198.51.{i // 250}.{i % 250 + 1}", started=T0, local_port=40000 + i) for i in range(201)))
    assert len(kept(big)) == 198 and big.describe()["rows"] == 198
    win(big, T0 + 1, row(SHELL, started=T0 + 1))
    assert len(kept(big)) == 199  # under the cap: nothing pruned


def test_past_max_open_a_connection_is_neither_held_nor_counted_and_describe_says_how_many(db, monkeypatch):
    monkeypatch.setattr(hostbook, "MAX_OPEN", 3)
    b = HostBook(db)
    five = [row(f"203.0.113.{i}", started=T0, local_port=51000 + i) for i in range(1, 6)]
    assert win(b, T0, *five) == {"new": 3, "ended": 0, "open": 3} and b.describe()["not_kept"] == 2
    assert win(b, T0 + 5, *five) == {"new": 0, "ended": 0, "open": 3}  # not a new connection at every reading
    assert b.describe()["not_kept"] == 2
    assert sorted((h["host"], h["connections"]) for h in kept(b)) == [(f"203.0.113.{i}", 1) for i in (1, 2, 3)]
    assert win(b, T0 + 10, *five[2:]) == {"new": 0, "ended": 2, "open": 1}  # room only once the reading is done
    assert win(b, T0 + 15, *five[2:]) == {"new": 2, "ended": 0, "open": 3} and b.describe()["not_kept"] == 0
    rows = {h["host"]: h for h in kept(b)}
    assert len(rows) == 5 and all(h["connections"] == 1 for h in rows.values())
    assert (rows["203.0.113.4"]["seconds"], rows["203.0.113.4"]["first"]) == (5.0, T0 + 10)  # from when it was held
    # a row waiting to close is not counted past it either
    assert win(b, T0 + 20, *five[2:], closing(MAIL, 993)) == {"new": 0, "ended": 0, "open": 3}
    assert b.describe()["not_kept"] == 1 and len(kept(b)) == 5


def test_rows_waiting_to_be_written_are_written_by_a_reading_past_max_pending(db, monkeypatch):
    monkeypatch.setattr(hostbook, "MAX_PENDING", 3)
    b = HostBook(db)
    win(b, T0, *(row(f"203.0.113.{i}", started=T0, local_port=51000 + i) for i in range(1, 4)))
    assert not db.exists()  # three waiting: not yet
    win(b, T0 + 5, *(row(f"203.0.113.{i}", started=T0, local_port=51000 + i) for i in range(1, 6)))
    assert len(table(db)) == 5 and b._conn is None and b.changes == 1  # written, and the file closed as it was
    win(b, T0 + 6, row("203.0.113.1", started=T0, local_port=51001))
    b.flush(keep_open=True)
    win(b, T0 + 10, *(row(f"203.0.113.{i}", started=T0, local_port=51000 + i) for i in range(1, 10)))
    assert len(table(db)) == 9 and b._conn is not None and b.changes == 3  # ... or left open as it was


# -- the queries -------------------------------------------------------------------------------------------------------

def recorded(db: Path) -> HostBook:
    """A Linux book with a few hosts: a browser to two web servers, a mailer, a name server over UDP, a shell that came
    in from the internet and a printer on the local network."""
    b = HostBook(db)
    lin(b, T0, row(inode=1, program="firefox", path="/usr/lib/firefox/firefox"),
        row(inode=2, program="firefox", path="/usr/lib/firefox/firefox", local_port=51001),
        row(WEB2, inode=3, program="firefox", path="/usr/lib/firefox/firefox", local_port=51002),
        row(MAIL, 993, inode=4, program="thunderbird", path="/usr/lib/thunderbird/thunderbird", local_port=51003),
        row(SHELL, 50123, inode=5, program="sshd", path="", local_port=22, direction="in", service="ssh.service"),
        row(PRINTER, 631, inode=6, program="cupsd", path="", local_port=51004, where="local network",
            name="printer.lan"))
    lin(b, T0 + 10, row(inode=1, program="firefox", path="/usr/lib/firefox/firefox"),
        row(MAIL, 993, inode=4, program="thunderbird", path="/usr/lib/thunderbird/thunderbird", local_port=51003),
        row(SHELL, 53, inode=7, proto="udp", state="connected", program="systemd-resolve", path="", local_port=40000))
    lin(b, T0 + 20, row(inode=1, program="firefox", path="/usr/lib/firefox/firefox"))
    b.flush()
    return b


def test_the_hosts_pass_the_filters_the_last_seen_first(db):
    b = recorded(db)
    assert [(h["program"], h["host"], h["proto"], h["port"], h["direction"]) for h in b.hosts()] == [
        ("firefox", WEB, "tcp", 443, "out"), ("systemd-resolve", SHELL, "udp", 53, "out"),
        ("thunderbird", MAIL, "tcp", 993, "out"), ("cupsd", PRINTER, "tcp", 631, "out"),
        ("firefox", WEB2, "tcp", 443, "out"), ("sshd", SHELL, "tcp", 22, "in")]
    web = b.hosts(program="firefox", port=443)[0]
    assert (web["connections"], web["seconds"], web["first"], web["last"]) == (2, 20.0, T0, T0 + 20)
    assert [h["host"] for h in b.hosts(program="firefox")] == [WEB, WEB2]
    assert [h["program"] for h in b.hosts(proto="udp")] == ["systemd-resolve"]
    assert [h["program"] for h in b.hosts(proto="TCP", port=993)] == ["thunderbird"]
    assert [h["program"] for h in b.hosts(direction="in")] == ["sshd"]
    assert [h["program"] for h in b.hosts(since=T0 + 10)] == ["firefox", "systemd-resolve", "thunderbird"]
    assert [h["program"] for h in b.hosts(since=T0 + 10, direction="out", proto="tcp", port=993)] == ["thunderbird"]
    assert [h["host"] for h in b.hosts(limit=2)] == [WEB, SHELL] and b.hosts(limit=0) == []
    assert b.hosts(program="") == b.hosts() == b.hosts(program=None, proto="", port=0, direction="", since=None)
    assert b.hosts(program="nobody") == [] and b.hosts(direction="sideways") == [] and b.hosts(since=T0 + 99) == []
    printer = b.hosts(port=631)[0]
    assert [printer[k] for k in ("network", "name", "lat", "placed")] == ["local", "printer.lan", None, ""]


def test_programs_and_ports_are_summed_under_the_other_filters_the_most_hosts_first(db):
    b = recorded(db)
    assert b.programs() == [
        {"program": "firefox", "path": "/usr/lib/firefox/firefox", "hosts": 2, "connections": 3, "seconds": 20.0,
         "last": T0 + 20},
        {"program": "cupsd", "path": "", "hosts": 1, "connections": 1, "seconds": 0.0, "last": T0},
        {"program": "sshd", "path": "", "hosts": 1, "connections": 1, "seconds": 0.0, "last": T0},
        {"program": "systemd-resolve", "path": "", "hosts": 1, "connections": 1, "seconds": 0.0, "last": T0 + 10},
        {"program": "thunderbird", "path": "/usr/lib/thunderbird/thunderbird", "hosts": 1, "connections": 1,
         "seconds": 10.0, "last": T0 + 10}]
    assert [p["program"] for p in b.programs(port=443)] == ["firefox"]
    assert [p["program"] for p in b.programs(direction="in")] == ["sshd"]
    assert [p["program"] for p in b.programs(since=T0 + 10, proto="tcp")] == ["firefox", "thunderbird"]
    assert [p["program"] for p in b.programs(2)] == ["firefox", "cupsd"] and b.programs(limit=0) == []
    assert b.ports() == [
        {"proto": "tcp", "port": 443, "hosts": 2, "connections": 3, "seconds": 20.0, "last": T0 + 20},
        {"proto": "tcp", "port": 22, "hosts": 1, "connections": 1, "seconds": 0.0, "last": T0},
        {"proto": "tcp", "port": 631, "hosts": 1, "connections": 1, "seconds": 0.0, "last": T0},
        {"proto": "tcp", "port": 993, "hosts": 1, "connections": 1, "seconds": 10.0, "last": T0 + 10},
        {"proto": "udp", "port": 53, "hosts": 1, "connections": 1, "seconds": 0.0, "last": T0 + 10}]
    assert [(p["proto"], p["port"]) for p in b.ports(program="firefox")] == [("tcp", 443)]
    assert [(p["proto"], p["port"]) for p in b.ports(direction="out", since=T0 + 10)] == [
        ("tcp", 443), ("tcp", 993), ("udp", 53)]
    assert [(p["proto"], p["port"]) for p in b.ports(1)] == [("tcp", 443)]
    with pytest.raises(TypeError):
        b.programs(host=WEB)  # no such filter
    with pytest.raises(TypeError):
        b.ports(network="local")


def test_a_query_reads_what_was_last_written(db):
    b = HostBook(db)
    win(b, T0, row(started=T0))
    b.flush()
    win(b, T0 + 5, row(started=T0), row(MAIL, 993, started=T0 + 1, local_port=51001))
    assert [h["host"] for h in b.hosts()] == [WEB] and b.describe()["rows"] == 1 and b.changes == 1
    b.flush()
    assert [h["host"] for h in b.hosts()] == [MAIL, WEB] and b.describe()["rows"] == 2 and b.changes == 2
    b.flush()  # nothing fed since: nothing written
    assert b.changes == 2


# -- places ------------------------------------------------------------------------------------------------------------

def test_a_local_host_is_kept_without_a_place_ever(db):
    b = HostBook(db)
    win(b, T0, row(PRINTER, 631, where="local network", started=T0 - 9, name="printer.lan"))
    asked: list = []
    assert b.unplaced(NOVEMBER) == 0 and b.place(atlas({PRINTER: LONDON}, asked), NOVEMBER) == 0 and asked == []
    b.flush()
    assert b.unplaced(NOVEMBER) == 0 and b.place(atlas({PRINTER: LONDON}, asked), NOVEMBER) == 0 and asked == []
    h = one(b)
    assert [h[k] for k in ("network", "lat", "lon", "country", "placed", "name")] == [
        "local", None, None, "", "", "printer.lan"]
    assert b.places() == ([], {"places": 0, "hosts": 0, "connections": 0, "seconds": 0.0,
                               "unplaced": {"hosts": 0, "connections": 0, "seconds": 0.0},
                               "local": {"hosts": 1, "connections": 1, "seconds": 9.0}})


def test_place_looks_up_only_the_rows_not_looked_up_yet_or_looked_up_in_an_older_file(db):
    b = HostBook(db)
    win(b, T0, row(started=T0), row(WEB2, started=T0, local_port=51001), row(SHELL, started=T0, local_port=51002),
        row(PRINTER, 631, where="local network", started=T0, local_port=51003))
    win(b, T0 + 5, row(WEB2, started=T0, local_port=51001))  # the last seen
    b.flush()
    before = b.changes
    asked: list = []
    lookup = atlas({WEB: LONDON, SHELL: AUSTRALIA}, asked)  # the file has no place for WEB2, and no point for SHELL
    assert b.unplaced(NOVEMBER) == 3
    assert b.place(lookup, NOVEMBER) == 3 and asked == [WEB2, SHELL, WEB] and b.changes == before + 1
    rows = {h["host"]: h for h in b.hosts()}
    assert [rows[WEB][k] for k in ("country", "code", "city", "lat", "lon", "asn", "org", "placed")] == [
        "United Kingdom", "GB", "London", 51.5142, -0.0931, None, "", NOVEMBER]
    assert [rows[SHELL][k] for k in ("country", "code", "city", "lat", "lon", "placed")] == [
        "Australia", "AU", "", None, None, NOVEMBER]
    assert [rows[WEB2][k] for k in ("country", "code", "lat", "lon", "placed")] == ["", "", None, None, NOVEMBER]
    assert rows[PRINTER]["placed"] == ""  # never looked up
    # looked up in this file: none is asked again, though two of them have no point (the file is not even opened)
    # (1.101.0: any other file's stamp, an older one too, places them again: a switch back is a switch)
    assert b.unplaced(NOVEMBER) == 0 and b.place(lookup, NOVEMBER) == 0 and b.unplaced(OCTOBER) == 3
    assert asked == [WEB2, SHELL, WEB] and b.changes == before + 1
    # a newer file: asked again, the last seen first, `most` at a time; a mapping answers as a Place does
    assert b.unplaced(DECEMBER) == 3
    newer = atlas({WEB2: NUREMBERG.as_dict()}, asked)
    assert b.place(newer, DECEMBER, most=1) == 1 and asked[3:] == [WEB2] and b.unplaced(DECEMBER) == 2
    assert b.place(newer, DECEMBER, most=0) == 0
    assert b.place(newer, DECEMBER) == 2 and asked[4:] == [SHELL, WEB] and b.unplaced(DECEMBER) == 0
    rows = {h["host"]: h for h in b.hosts()}
    assert [rows[WEB2][k] for k in ("country", "code", "city", "lat", "lon", "asn", "org", "placed")] == [
        "Germany", "DE", "Nuremberg", 49.4478, 11.0683, 64500, "Example Net", DECEMBER]
    assert [rows[WEB][k] for k in ("country", "lat", "placed")] == ["", None, DECEMBER]  # the newer file's word
    # a host of several rows is asked once, and a new row is the only one looked up
    win(b, T0 + 10, row(MAIL, 993, started=T0 + 10, local_port=51004),
        row(MAIL, 465, started=T0 + 10, local_port=51005))
    b.flush()
    assert b.unplaced(DECEMBER) == 2 and b.place(atlas({MAIL: LONDON}, asked), DECEMBER) == 2 and asked[6:] == [MAIL]


def test_a_place_that_is_no_place_gives_a_row_none(db):
    b = HostBook(db)
    win(b, T0, *(row(f"203.0.113.{i}", started=T0, local_port=51000 + i) for i in range(1, 6)))
    b.flush()
    odd = {"203.0.113.1": geo.Place("GB", None, None, 91.0, 0.0), "203.0.113.2": {"lat": 10.0},
           "203.0.113.3": {"country": "FR", "lat": float("nan"), "lon": 2.0, "asn": True}, "203.0.113.4": "London",
           "203.0.113.5": {"country": "US", "lat": 37, "lon": -122, "asn": 15169}}
    assert b.place(atlas(odd), NOVEMBER) == 5
    rows = {h["host"][-1]: [h[k] for k in ("country", "code", "lat", "lon", "asn")] for h in b.hosts()}
    assert rows == {"1": ["GB", "GB", None, None, None], "2": ["", "", None, None, None],
                    "3": ["FR", "FR", None, None, None], "4": ["", "", None, None, None],
                    "5": ["US", "US", 37.0, -122.0, 15169]}
    json.dumps(b.hosts(), allow_nan=False)


def placed(db: Path) -> HostBook:
    """A Windows book whose hosts are placed: two in London (a browser's, with three connections, and a mailer's), one
    in Nuremberg that mostly came in, one the file has no point for, one not looked up yet, one on the local network."""
    b = HostBook(db)
    win(b, T0, row(started=T0 - 100), row(started=T0 - 50, local_port=51001), row(started=T0 - 20, local_port=51002),
        row(WEB2, 993, started=T0 - 10, local_port=51003, program=MAILER),
        row(MAIL, 50001, started=T0 - 7, local_port=8443, direction="in", program="server.exe"),
        row(MAIL, 50002, started=T0 - 6, local_port=8443, direction="in", program="server.exe"),
        row(MAIL, 22, started=T0 - 5, local_port=51004, program="ssh.exe"),
        row(SHELL, started=T0 - 3, local_port=51005),
        row(PRINTER, 631, started=T0 - 2, local_port=51006, where="local network", program="spoolsv.exe"))
    b.flush()
    assert b.place(atlas({WEB: LONDON, WEB2: LONDON, MAIL: NUREMBERG, SHELL: AUSTRALIA}), NOVEMBER) == 5
    win(b, T0 + 5, row(V6, local=LAN6, local_port=52000, started=T0 + 5))  # not looked up yet
    b.flush()
    return b


def test_places_are_grouped_by_point_in_the_query_the_most_connections_first(db):
    b = placed(db)
    places, rest = b.places()
    assert places == [
        {"lat": 51.5142, "lon": -0.0931, "country": "United Kingdom", "code": "GB", "city": "London", "asn": None,
         "org": "", "hosts": 2, "connections": 4, "in": 0, "direction": "out", "seconds": 180.0, "first": T0 - 100,
         "last": T0, "programs": [BROWSER, MAILER], "ports": [443, 993]},
        {"lat": 49.4478, "lon": 11.0683, "country": "Germany", "code": "DE", "city": "Nuremberg", "asn": 64500,
         "org": "Example Net", "hosts": 1, "connections": 3, "in": 2, "direction": "in", "seconds": 18.0,
         "first": T0 - 7, "last": T0, "programs": ["server.exe", "ssh.exe"], "ports": [8443, 22]}]
    assert rest == {"places": 0, "hosts": 0, "connections": 0, "seconds": 0.0,
                    "unplaced": {"hosts": 2, "connections": 2, "seconds": 3.0},  # no point, and not looked up yet
                    "local": {"hosts": 1, "connections": 1, "seconds": 2.0}}  # never placed
    json.dumps([places, rest], allow_nan=False)
    # what is over `most` is summed, not handed out
    [london], rest = b.places(most=1)
    assert london["city"] == "London"
    assert (rest["places"], rest["hosts"], rest["connections"], rest["seconds"]) == (1, 1, 3, 18.0)
    none, rest = b.places(most=0)
    assert none == [] and (rest["places"], rest["hosts"], rest["connections"], rest["seconds"]) == (2, 3, 7, 198.0)


def test_places_pass_the_same_filters_as_the_hosts(db):
    b = placed(db)
    [london], rest = b.places(program=MAILER)
    assert (london["hosts"], london["connections"], london["programs"], london["ports"]) == (1, 1, [MAILER], [993])
    assert rest["unplaced"]["hosts"] == 0 and rest["local"]["hosts"] == 0
    [nuremberg], _ = b.places(direction="in")
    assert [nuremberg[k] for k in ("city", "connections", "in", "programs", "ports")] == [
        "Nuremberg", 2, 2, ["server.exe"], [8443]]
    assert [p["city"] for p in b.places(port=443)[0]] == ["London"] and b.places(port=443)[1]["unplaced"]["hosts"] == 2
    assert b.places(proto="udp") == ([], {"places": 0, "hosts": 0, "connections": 0, "seconds": 0.0,
                                         "unplaced": {"hosts": 0, "connections": 0, "seconds": 0.0},
                                         "local": {"hosts": 0, "connections": 0, "seconds": 0.0}})
    places, rest = b.places(since=T0 + 1)
    assert places == [] and rest["unplaced"] == {"hosts": 1, "connections": 1, "seconds": 0.0}
    assert b.places(program="spoolsv.exe")[1]["local"] == {"hosts": 1, "connections": 1, "seconds": 2.0}


def test_sums_are_what_places_sums_in_one_plain_query(db):
    b = placed(db)
    for filters in ({}, {"program": MAILER}, {"direction": "in"}, {"proto": "tcp", "port": 443}, {"proto": "udp"},
                    {"since": T0 + 1}, {"program": "spoolsv.exe"}, {"program": "nobody"}):
        drawn, rest = b.places(**filters, most=0)
        every = {key: rest[key] + rest["unplaced"][key] + rest["local"][key] for key in ("hosts", "connections",
                                                                                          "seconds")}
        assert drawn == [] and b.sums(**filters) == every, filters
    # London's two, Nuremberg's one, the two with no point and the local network's one
    assert b.sums() == {"hosts": 6, "connections": 10, "seconds": 203.0}
    assert HostBook(db.with_name("none.db")).sums() == {"hosts": 0, "connections": 0, "seconds": 0.0}  # no file made
    assert not db.with_name("none.db").exists()
    with pytest.raises(TypeError):
        b.sums(host=WEB)  # no such filter


def test_a_filter_by_port_direction_or_time_reads_the_table_through_never_the_index_on_last(db, monkeypatch):
    """Given those columns, SQLite would read them from the index on `last` (which holds the key's columns too) and
    look each row it lets through up again: at the cap ten times as long as reading the table itself. A program is
    found by the key, its first column; no query of the hosts goes through the index on `last`."""
    b = placed(db)
    asked: list[tuple] = []
    connect = HostBook._connect

    class Recorded:  # the book's connection, every statement it is given noted with its values
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, args=()):
            asked.append((sql, tuple(args)))
            return self.conn.execute(sql, args)

        def __getattr__(self, name):
            return getattr(self.conn, name)
    monkeypatch.setattr(HostBook, "_connect", lambda self: Recorded(connect(self)))
    for filters in ({"proto": "tcp", "port": 443}, {"direction": "in"}, {"since": T0 + 1},
                    {"proto": "tcp", "port": 443, "direction": "out", "since": T0 - 1}, {"program": BROWSER}):
        b.places(**filters)
        b.sums(**filters)
        b.programs(**filters)
        b.ports(**filters)
        b.hosts(**filters)
    reads = [(sql, args) for sql, args in asked if sql.startswith("SELECT") and "FROM hosts" in sql]
    assert len(reads) >= 25
    con = sqlite3.connect(db)
    try:
        plans = [" ".join(str(r[3]) for r in con.execute(f"EXPLAIN QUERY PLAN {sql}", args)) for sql, args in reads]
    finally:
        con.close()
    assert [p for p in plans if "hosts_last" in p] == []
    assert sum("PRIMARY KEY (program=?)" in p for p in plans) >= 5  # a program's rows found by the key


def test_a_place_names_its_network_only_when_every_host_there_has_the_same(db):
    b = HostBook(db)
    win(b, T0, row(started=T0), row(WEB2, started=T0, local_port=51001), row(MAIL, started=T0, local_port=51002),
        row(SHELL, started=T0, local_port=51003))
    b.flush()
    here = geo.Place("DE", "Germany", "Nuremberg", 49.4478, 11.0683, 64500, "Example Net")
    there = geo.Place("DE", "Germany", "Nuremberg", 49.4478, 11.0683, 64501, "Other Net")
    b.place(atlas({WEB: here, WEB2: there, MAIL: LONDON, SHELL: LONDON}), NOVEMBER)
    places = {p["city"]: p for p in b.places()[0]}
    assert (places["Nuremberg"]["asn"], places["Nuremberg"]["org"], places["Nuremberg"]["hosts"]) == (None, "", 2)
    assert (places["London"]["asn"], places["London"]["org"]) == (None, "")
    assert [p["city"] for p in b.places()[0]] == ["Nuremberg", "London"]  # as many connections: by the point, steadily


def test_a_place_names_no_network_when_one_of_its_hosts_has_none(db):
    b = HostBook(db)
    win(b, T0, row(started=T0), row(WEB2, started=T0, local_port=51001))
    b.flush()
    named = geo.Place("DE", "Germany", "Nuremberg", 49.4478, 11.0683, 64500, "Example Net")
    unnamed = geo.Place("DE", "Germany", "Nuremberg", 49.4478, 11.0683)  # looked up with no network's file
    b.place(atlas({WEB: named, WEB2: unnamed}), NOVEMBER)
    [nuremberg], _ = b.places()
    assert (nuremberg["hosts"], nuremberg["asn"], nuremberg["org"]) == (2, None, "")
    [both], _ = b.places(port=443, program=BROWSER, since=T0)
    assert (both["hosts"], both["asn"]) == (2, None)
    assert b.places(direction="in") == ([], {"places": 0, "hosts": 0, "connections": 0, "seconds": 0.0,
                                            "unplaced": {"hosts": 0, "connections": 0, "seconds": 0.0},
                                            "local": {"hosts": 0, "connections": 0, "seconds": 0.0}})


class Counted:
    """A connection whose statements' rows are counted as they are handed to Python."""

    def __init__(self, conn):
        self.conn, self.rows = conn, 0

    def execute(self, *args):
        cursor, counted = self.conn.execute(*args), self

        class Rows:
            def __iter__(self):
                for found in cursor:
                    counted.rows += 1
                    yield found

            def fetchall(self):
                return list(self)

            def fetchone(self):
                found = cursor.fetchone()
                counted.rows += found is not None
                return found
        return Rows()

    def __getattr__(self, name):
        return getattr(self.conn, name)


def test_places_hands_python_only_the_places_it_draws(db, monkeypatch):
    """The places past `most` are summed in the query itself: only the ones drawn (and their programs and ports)
    come out of it, however many points there are."""
    b = HostBook(db)
    hosts = [f"198.51.100.{i}" for i in range(1, 41)]
    win(b, T0, *(row(host, started=T0 - i, local_port=40000 + i) for i, host in enumerate(hosts)),
        row(PRINTER, 631, where="local network", started=T0, local_port=51000),
        row(SHELL, started=T0 - 50, local_port=51001))
    b.flush()
    cities = {host: geo.Place("XX", "Somewhere", f"City {i}", float(i), float(i)) for i, host in enumerate(hosts)}
    b.place(atlas(cities), NOVEMBER)
    counted: list[Counted] = []
    opened = HostBook._file

    def counting(self, make):
        conn = opened(self, make)
        if conn is None:
            return None
        counted.append(Counted(conn))
        return counted[-1]
    monkeypatch.setattr(HostBook, "_file", counting)
    places, rest = b.places(most=5)
    assert [p["city"] for p in places] == ["City 39", "City 38", "City 37", "City 36", "City 35"]
    assert rest == {"places": 35, "hosts": 35, "connections": 35, "seconds": float(sum(range(35))),
                    "unplaced": {"hosts": 1, "connections": 1, "seconds": 50.0},
                    "local": {"hosts": 1, "connections": 1, "seconds": 0.0}}
    assert sum(c.rows for c in counted) <= 10  # five places, and one program and one port at each
    none, rest = b.places(most=0)
    assert none == [] and (rest["places"], rest["hosts"], rest["seconds"]) == (40, 40, float(sum(range(40))))


def test_more_places_than_one_statement_asks_for_are_all_given_their_programs_and_ports(db, monkeypatch):
    monkeypatch.setattr(hostbook, "POINTS", 4)
    monkeypatch.setattr(hostbook, "PLACE_PROGRAMS", 2)
    monkeypatch.setattr(hostbook, "PLACE_PORTS", 2)
    b = HostBook(db)
    hosts = [f"203.0.113.{i}" for i in range(1, 12)]
    rows = [row(host, 443 + n, started=T0, local_port=51000 + 10 * i + n, program=f"p{n}.exe")
            for i, host in enumerate(hosts) for n in range(i % 4 + 1)]
    win(b, T0, *rows)
    win(b, T0 + 1, *rows, row(hosts[0], 443, started=T0 + 1, local_port=60000, program="p3.exe"))
    b.flush()
    cities = {host: geo.Place("XX", "Somewhere", f"City {i}", float(i), float(-i)) for i, host in enumerate(hosts)}
    b.place(atlas(cities), NOVEMBER)
    places, rest = b.places()
    assert len(places) == 11 and rest["places"] == 0 and all(p["programs"] and p["ports"] for p in places)
    by_city = {p["city"]: p for p in places}
    assert (by_city["City 3"]["programs"], by_city["City 3"]["ports"], by_city["City 3"]["connections"]) == (
        ["p0.exe", "p1.exe"], [443, 444], 4)  # the two with the most connections, then by name
    assert (by_city["City 0"]["programs"], by_city["City 0"]["ports"]) == (["p0.exe", "p3.exe"], [443])
    assert len(b.places(most=10_000)[0]) == 11 and hostbook.MAX_PLACES == 512


def test_past_count_rows_a_write_counts_its_rows_itself_and_the_hosts_again_only_every_count_s(db, monkeypatch):
    """At the cap the count of the hosts and the programs takes about 25 ms, and a shown tab writes every few seconds:
    past COUNT_ROWS rows a write that adds or prunes rows counts the rows itself, and the hosts and the programs are
    counted again once COUNT_S of the readings' time went by (or it went back); up to COUNT_ROWS, at each such write."""
    assert (hostbook.COUNT_ROWS, hostbook.COUNT_S) == (10_000, 60.0)
    monkeypatch.setattr(hostbook, "COUNT_ROWS", 2)
    counts: list[str] = []
    connect = HostBook._connect

    class Counting:  # the book's connection, its counts of the whole file noted
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, args=()):
            if "COUNT(DISTINCT program)" in sql and "GROUP BY" not in sql:
                counts.append(sql)
            return self.conn.execute(sql, args)

        def __getattr__(self, name):
            return getattr(self.conn, name)
    monkeypatch.setattr(HostBook, "_connect", lambda self: Counting(connect(self)))
    b = HostBook(db, cap=4)
    win(b, T0, row(started=T0), row(WEB2, started=T0, local_port=51001))
    b.flush()
    assert len(counts) == 1 and (b.describe()["rows"], b.describe()["hosts"]) == (2, 2)  # up to COUNT_ROWS: counted
    win(b, T0 + 5, row(MAIL, 993, started=T0 + 5, local_port=51002, program=MAILER))
    b.flush()
    d = b.describe()
    assert len(counts) == 1 and (d["rows"], d["hosts"], d["programs"]) == (3, 2, 1)  # the rows by the write alone
    win(b, T0 + 10, *(row(f"198.51.100.{i}", started=T0 + 10, local_port=52000 + i) for i in range(1, 4)))
    b.flush()  # six rows over a cap of four: the two longest unseen pruned, the rows counted by the write still
    d = b.describe()
    assert len(counts) == 1 and d["rows"] == 4 == len(b.hosts()) and d["hosts"] == 2
    win(b, T0 + 5 + hostbook.COUNT_S, row(SHELL, started=T0 + 60, local_port=51003))
    b.flush()  # COUNT_S after the last count: counted again (the mailer's row pruned: the browser's four are left)
    d = b.describe()
    assert len(counts) == 2 and (d["rows"], d["hosts"], d["programs"]) == (4, 4, 1) and len(b.hosts()) == 4
    win(b, T0 + 6, row(V6, local=LAN6, started=T0 + 6, local_port=52010))  # the clock set back: counted again
    b.flush()
    assert len(counts) == 3 and b.describe()["rows"] == 4 == len(b.hosts())


def test_describe_keeps_its_counts_from_the_last_flush_and_asks_the_file_nothing(db, _nothing_real):
    b = recorded(db)
    opened = len(_nothing_real)
    for _ in range(3):
        d = b.describe()
        assert (d["rows"], d["hosts"], d["programs"], d["open"], d["since"], d["last"]) == (6, 5, 5, 1, T0, T0 + 20)
    assert len(_nothing_real) == opened and b._conn is None  # the file was not opened for it
    lin(b, T0 + 25, row(inode=1, program="firefox"), row(V6, local=LAN6, inode=8, program="firefox"))
    assert (b.describe()["rows"], b.describe()["hosts"], b.describe()["open"]) == (6, 5, 2)  # not written yet
    b.flush()
    d = b.describe()
    assert (d["rows"], d["hosts"], d["programs"], d["last"]) == (7, 6, 5, T0 + 25)
    assert d["bytes"] == db.stat().st_size > 0


# -- forgetting, and a clock set back ----------------------------------------------------------------------------------

def test_forget_removes_every_row_and_recording_goes_on_from_now(db):
    clock = Clock()
    b = HostBook(db, clock=clock)
    old = row(started=T0 - 86400)
    win(b, T0, old, row(MAIL, 993, started=T0 - 5, local_port=51001, program=MAILER), closing(WEB2))
    b.flush()
    assert one(b, program=BROWSER)["seconds"] == 86400.0 and b.describe()["rows"] == 3
    win(b, T0 + 5, old, row(MAIL, 993, started=T0 - 5, local_port=51001, program=MAILER), closing(WEB2),
        row(SHELL, started=T0 + 1, local_port=51002))  # pending: forgotten too
    clock.t, before = T0 + 10, b.changes
    assert b.forget() == 3 and b.changes == before + 1
    d = b.describe()
    assert (d["rows"], d["hosts"], d["programs"], d["open"], d["since"], d["last"], d["problem"]) == (
        0, 0, 0, 0, T0 + 10, T0 + 10, "")
    assert b.hosts() == [] and table(db) == [] and dict(table(db, "meta"))["since"] == T0 + 10
    # every connection open now is counted anew, its time from now on: never the day before it was forgotten
    assert win(b, T0 + 15, old, closing(WEB2)) == {"new": 1, "ended": 0, "open": 1}
    h = one(b)
    assert (h["program"], h["connections"], h["seconds"], h["first"], h["last"]) == (BROWSER, 1, 5.0, T0 + 10, T0 + 15)
    # ... and a row that was waiting to close does not come back as a connection, after a restart either
    b.close()
    again = HostBook(db, clock=clock)
    assert win(again, T0 + 20, old, closing(WEB2)) == {"new": 0, "ended": 0, "open": 1}
    assert [(h["program"], h["seconds"]) for h in kept(again)] == [(BROWSER, 10.0)]
    assert again.forget() == 1 and again.forget() == 0


def test_forget_leaves_no_host_in_the_file(db):
    """Forgotten is gone from the file itself, not only from its tables: SQLite's free pages and its log keep none of
    it, and a copy set aside once goes too."""
    b = HostBook(db, clock=Clock(T0 + 60))
    win(b, T0, *(row(f"198.51.100.{i}", started=T0, local_port=40000 + i, program="secret-diary.exe",
                     path="C:\\Diary\\secret-diary.exe") for i in range(1, 201)))
    b.flush(keep_open=True)
    win(b, T0 + 5, *(row(f"198.51.100.{i}", started=T0, local_port=40000 + i, program="secret-diary.exe")
                     for i in range(1, 101)))
    b.flush(keep_open=True)  # recording all the time: the log holds the pages as they were
    db.with_name("hosts.db.bad").write_bytes(b"a file set aside before, which held secret-diary.exe's hosts")
    assert b.forget() == 200
    beside = {p.name: p.read_bytes() for p in db.parent.iterdir()}
    assert "hosts.db.bad" not in beside
    assert not any(b"secret-diary" in data or b"198.51.100." in data for data in beside.values()), sorted(beside)
    b.close()
    assert not any(b"secret-diary" in p.read_bytes() for p in db.parent.iterdir())
    assert b.describe()["problem"] == "" and b.hosts() == []


def test_forget_with_no_file_makes_none(db):
    clock = Clock(T0 + 3)
    b = HostBook(db, clock=clock)
    assert b.forget() == 0 and not db.parent.exists()
    win(b, T0 + 1, row(started=T0 - 50))  # fed, never written
    assert b.forget() == 0 and not db.parent.exists() and b.describe()["since"] == T0 + 3
    assert win(b, T0 + 8, row(started=T0 - 50)) == {"new": 1, "ended": 0, "open": 1}
    assert (one(b)["seconds"], one(b)["first"]) == (5.0, T0 + 3)


def test_a_clock_set_back_adds_nothing_negative_and_goes_on_from_the_readings_time(db):
    b = HostBook(db)
    win(b, T0 + 3600, row(started=T0 + 3500), awake=1000.0)  # the clock ran an hour ahead
    assert (one(b)["seconds"], one(b)["last"]) == (100.0, T0 + 3600)
    out = win(b, T0, row(started=T0 + 3500), row(MAIL, 993, started=T0 + 3550, local_port=51001), awake=1005.0)
    assert out == {"new": 1, "ended": 0, "open": 2}
    d = b.describe()
    assert (d["last"], d["since"]) == (T0, T0)
    rows = {h["host"]: h for h in kept(b)}
    assert (rows[WEB]["seconds"], rows[WEB]["first"], rows[WEB]["last"]) == (100.0, T0, T0)  # no row seen "later"
    assert (rows[MAIL]["seconds"], rows[MAIL]["first"], rows[MAIL]["last"]) == (0.0, T0, T0)  # a start still to come
    win(b, T0 + 5, row(started=T0 + 3500), row(MAIL, 993, started=T0 + 3550, local_port=51001), awake=1010.0)
    rows = {h["host"]: h for h in kept(b)}
    assert (rows[WEB]["seconds"], rows[MAIL]["seconds"], rows[WEB]["last"]) == (105.0, 5.0, T0 + 5)
    assert all(h["seconds"] >= 0 and h["first"] <= h["last"] for h in rows.values())
    assert dict(table(db, "meta"))["last"] == T0 + 5


def test_rows_waiting_to_be_written_when_the_clock_is_set_back_are_not_seen_later(db):
    b = HostBook(db)
    win(b, T0 + 3600, row(started=T0 + 3500), awake=1000.0)  # the clock an hour ahead; nothing written yet
    win(b, T0, row(started=T0 + 3500), awake=1005.0)  # set right
    h = one(b)
    assert (h["first"], h["last"], h["seconds"], h["connections"]) == (T0, T0, 100.0, 1)
    assert dict(table(db, "meta"))["last"] == T0 and b.hosts(since=T0 + 1) == []


# -- the file ----------------------------------------------------------------------------------------------------------

def test_no_file_is_made_by_a_read(db):
    b = HostBook(db)
    assert b.hosts() == [] and b.programs() == [] and b.ports() == [] and b.unplaced(NOVEMBER) == 0
    assert b.places()[0] == [] and b.place(atlas({}), NOVEMBER) == 0
    d = b.describe()
    assert (d["rows"], d["hosts"], d["programs"], d["since"], d["last"], d["bytes"], d["open"], d["problem"]) == (
        0, 0, 0, None, None, 0, 0, "")
    b.flush()
    b.flush(keep_open=True)
    b.close()
    assert not db.exists() and not db.parent.exists() and b.changes == 0


def test_the_file_is_closed_after_a_flush_and_a_read_leaves_none_open(db):
    b = HostBook(db)
    win(b, T0, row(started=T0))
    assert not db.exists()  # a reading is added up in memory
    b.flush()
    assert db.exists() and b._conn is None and sorted(p.name for p in db.parent.iterdir()) == [FILE]
    assert len(b.hosts()) == 1 and b.programs() and b.ports() and b.unplaced(NOVEMBER) == 1 and b._conn is None
    assert sorted(p.name for p in db.parent.iterdir()) == [FILE]  # opened for the read alone
    db.replace(db.with_name("moved.db"))  # nothing holds it (Windows would refuse)
    db.with_name("moved.db").replace(db)
    win(b, T0 + 5, row(started=T0))
    b.flush(keep_open=True)  # recording all the time: kept open between flushes
    assert b._conn is not None and len(b.hosts()) == 1 and b._conn is not None  # a read leaves it as it was
    b.flush(keep_open=True)
    assert b._conn is not None
    b.close()
    assert b._conn is None and sorted(p.name for p in db.parent.iterdir()) == [FILE]
    assert one(b)["seconds"] == 5.0  # and the next call opens it again


def test_a_file_that_is_no_database_is_set_aside(db):
    db.parent.mkdir()
    db.write_bytes(b"this is no database, " * 64)
    b = HostBook(db)
    assert b.hosts() == [] and not db.exists()  # a read sets it aside and makes no new one
    assert db.with_name("hosts.db.bad").read_bytes() == b"this is no database, " * 64
    problem = b.describe()["problem"]
    assert problem.startswith("The hosts database kept could not be read (")
    assert problem.endswith("): it was set aside as hosts.db.bad, and recording starts anew.")
    assert win(b, T0, row(started=T0 - 4)) == {"new": 1, "ended": 0, "open": 1}
    assert (one(b)["seconds"], b.describe()["rows"]) == (4.0, 1) and b.describe()["problem"] == problem

    # one that breaks under a book that has read it: set aside at the next write, what is open kept
    c = HostBook(db.with_name("later.db"))
    win(c, T0, row(started=T0))
    c.flush()
    c.path.write_bytes(b"\0" * 4096 + b"not SQLite")
    win(c, T0 + 5, row(started=T0))
    c.flush()
    assert c.path.with_name("later.db.bad").exists() and "set aside as later.db.bad" in c.describe()["problem"]
    assert [(h["connections"], h["seconds"]) for h in c.hosts()] == [(0, 5.0)] and c.describe()["rows"] == 1


def damage(path: Path, *names: str) -> None:
    """The first page of each table or index named overwritten, the file's header and its schema left sound: a file
    damaged in the middle, as a crash with the disk's cache on or a bad sector leaves one."""
    con = sqlite3.connect(path)
    try:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        size = con.execute("PRAGMA page_size").fetchone()[0]
        roots = [con.execute("SELECT rootpage FROM sqlite_master WHERE name = ?", (name,)).fetchone()[0]
                 for name in names]
    finally:
        con.close()
    data = bytearray(path.read_bytes())
    for root in roots:
        data[(root - 1) * size:root * size] = b"\x55" * size
    path.write_bytes(bytes(data))


def test_a_file_with_a_damaged_page_is_set_aside_and_recording_starts_anew(db):
    many = [row(f"198.51.{i // 250}.{i % 250 + 1}", started=T0, local_port=20000 + i) for i in range(600)]
    with HostBook(db) as first:
        win(first, T0, *many)
    damage(db, "hosts", "hosts_last", "hosts_host")
    b = HostBook(db)  # its header and its schema are sound: the damage is found when the hosts are counted
    assert win(b, T0 + 5, row(SHELL, started=T0 + 1, local_port=51000)) == {"new": 1, "ended": 0, "open": 1}
    problem = b.describe()["problem"]
    assert problem.startswith("The hosts database kept could not be read (database disk image is malformed)")
    assert problem.endswith("set aside as hosts.db.bad, and recording starts anew.")
    assert [(h["host"], h["connections"], h["seconds"]) for h in kept(b)] == [(SHELL, 1, 4.0)]
    assert db.with_name("hosts.db.bad").exists() and b.describe()["rows"] == 1

    # damaged under a book that has read it: found by a query, set aside, and the next write makes a new file
    c = HostBook(db.with_name("later.db"))
    win(c, T0, *many)
    c.flush()
    damage(c.path, "hosts", "hosts_last", "hosts_host")
    assert c.hosts() == [] and not c.path.exists() and c.path.with_name("later.db.bad").exists()
    assert "set aside as later.db.bad" in c.describe()["problem"]
    win(c, T0 + 5, *many[:2])
    assert len(kept(c)) == 2 and c.describe()["rows"] == 2  # what is open now, from now on

    # ... or by a write
    d = HostBook(db.with_name("written.db"))
    win(d, T0, *many)
    d.flush()
    damage(d.path, "hosts", "hosts_last", "hosts_host")
    win(d, T0 + 5, *many[:3])
    d.flush()
    assert d.path.with_name("written.db.bad").exists() and len(d.hosts()) == 3 and d.describe()["rows"] == 3


def test_forget_says_so_when_the_file_cannot_be_read(db, monkeypatch):
    with HostBook(db) as first:
        win(first, T0, row(started=T0))
    b = HostBook(db, clock=Clock(T0 + 10))
    connect = hostbook.sqlite3.connect
    monkeypatch.setattr(hostbook.sqlite3, "connect",
                        lambda *args, **kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("database is locked")))
    with pytest.raises(OSError, match="could not be read \\(database is locked\\): nothing was forgotten"):
        b.forget()  # another program holds it at the book's first use: nothing to tell from 0 rows forgotten
    monkeypatch.setattr(hostbook.sqlite3, "connect", connect)
    assert len(table(db)) == 1 and b.forget() == 1 and table(db) == []


def test_a_file_of_a_newer_layout_is_left_as_it_is(db):
    with HostBook(db) as first:
        win(first, T0, row(started=T0))
    con = sqlite3.connect(db)
    con.execute("UPDATE meta SET value = 2 WHERE key = 'version'")
    con.commit()
    con.close()
    size = db.read_bytes()
    b = HostBook(db)
    assert win(b, T0 + 5, row(started=T0), row(MAIL, started=T0)) == NOWHERE
    b.flush()
    assert b.hosts() == [] and b.places()[0] == [] and b.forget() == 0 and b.place(atlas({}), NOVEMBER) == 0
    d = b.describe()
    assert d["problem"] == (f"The hosts database at {db} was written by a newer Liminal (its layout is version 2, and "
                            "this one reads version 1): it is left as it is, and nothing is recorded or shown from it "
                            "here.")
    assert (d["rows"], d["open"]) == (0, 0) and db.read_bytes() == size and len(table(db)) == 1


def test_a_write_that_fails_is_said_and_tried_again(db, monkeypatch):
    b = HostBook(db)
    win(b, T0, row(started=T0 - 3))
    connect = hostbook.sqlite3.connect

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(hostbook.sqlite3, "connect", locked)
    b.flush()
    assert b.describe()["problem"] == ("The hosts database could not be written (database is locked). What was seen "
                                      "since is kept in memory and written at the next try.")
    assert b.changes == 0 and b._conn is None
    win(b, T0 + 5, row(started=T0 - 3))
    monkeypatch.setattr(hostbook.sqlite3, "connect", connect)
    b.flush()
    assert b.describe()["problem"] == "" and b.changes == 1
    assert (one(b)["connections"], one(b)["seconds"]) == (1, 8.0)  # nothing lost meanwhile

    # a read that fails says so and answers nothing; forgetting says in words that nothing was forgotten
    monkeypatch.setattr(hostbook.sqlite3, "connect", locked)
    assert b.hosts() == [] and b.places()[0] == [] and b.unplaced(NOVEMBER) == 0
    assert b.describe()["problem"] == "The hosts database could not be read (database is locked)."
    with pytest.raises(OSError, match="could not be emptied \\(database is locked\\): nothing was forgotten"):
        b.forget()
    monkeypatch.setattr(hostbook.sqlite3, "connect", connect)
    assert len(b.hosts()) == 1 and b.describe()["rows"] == 1


def test_rows_written_are_not_written_again_when_counting_them_fails(db, monkeypatch):
    b = HostBook(db)
    win(b, T0, row(started=T0 - 60))
    count, failed = HostBook._count, []

    def once(self, conn):
        if not failed:
            failed.append(True)
            raise sqlite3.OperationalError("disk I/O error")
        return count(self, conn)
    monkeypatch.setattr(HostBook, "_count", once)
    b.flush()  # written, then the count fails: what was written is not kept to be written again
    assert failed and b._pending == {} and b.changes == 1
    assert b.describe()["problem"] == "The hosts database could not be read (disk I/O error)."
    b.flush()
    win(b, T0 + 5, row(started=T0 - 60))
    b.flush()
    assert (one(b)["connections"], one(b)["seconds"]) == (1, 65.0)
    assert (b.describe()["problem"], b.describe()["rows"]) == ("", 1)  # counted again at the next write


def test_rows_that_cannot_be_written_are_let_go_past_twice_max_pending(db, monkeypatch):
    monkeypatch.setattr(hostbook, "MAX_PENDING", 2)
    b = HostBook(db)
    monkeypatch.setattr(hostbook.sqlite3, "connect",
                        lambda *args, **kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("disk I/O error")))
    win(b, T0, *(row(f"203.0.113.{i}", started=T0, local_port=51000 + i) for i in range(1, 4)))
    assert len(b._pending) == 3 and "written at the next try" in b.describe()["problem"]
    win(b, T0 + 5, *(row(f"203.0.113.{i}", started=T0, local_port=51000 + i) for i in range(1, 7)))
    assert b._pending == {}
    assert b.describe()["problem"].endswith("6 rows waiting were more than is kept so, and were let go.")


def test_a_folder_on_another_systems_drive_is_left_alone(tmp_path, monkeypatch):
    monkeypatch.setattr(mounts, "foreign", lambda path, mounts=None: "mnt" in Path(path).parts)  # a stand-in
    there = tmp_path / "mnt" / "c" / "store" / "data" / "hosts" / "hosts.db"
    words = hostbook.foreign(there)
    assert words.startswith("Keeping the hosts database: ") and "hosts.db" in words
    assert words.endswith(" is on another system's drive, and that is done from that system, not from here")
    assert hostbook.foreign(tmp_path / "hosts.db") == ""
    b = HostBook(there, clock=Clock())
    assert win(b, T0, row(started=T0 - 60)) == NOWHERE
    b.flush()
    b.flush(keep_open=True)
    assert b.hosts() == [] and b.programs() == [] and b.ports() == [] and b.unplaced(NOVEMBER) == 0
    assert b.places() == ([], {"places": 0, "hosts": 0, "connections": 0, "seconds": 0.0,
                               "unplaced": {"hosts": 0, "connections": 0, "seconds": 0.0},
                               "local": {"hosts": 0, "connections": 0, "seconds": 0.0}})
    assert b.place(atlas({WEB: LONDON}), NOVEMBER) == 0 and b.forget() == 0 and b.changes == 0
    d = b.describe()
    assert d["elsewhere"] == words
    assert (d["rows"], d["open"], d["bytes"], d["since"], d["last"]) == (0, 0, 0, None, None)
    b.close()
    assert not (tmp_path / "mnt").exists()  # nothing made, nothing written


def test_the_folder_and_the_file_are_asked_to_be_this_accounts_alone(db, monkeypatch):
    """The modes asked for, on any system (the file's own are looked at on Linux, below)."""
    monkeypatch.setattr(hostbook, "_POSIX", True)
    asked: list[tuple[str, int]] = []
    chmod = os.chmod

    def noted(path, mode, *args, **kwargs):
        asked.append((Path(path).name, mode))
        return chmod(path, mode, *args, **kwargs)
    monkeypatch.setattr(os, "chmod", noted)
    b = HostBook(db)
    win(b, T0, row(started=T0))
    b.flush()
    assert asked == [("hosts", 0o700), (FILE, 0o600)] and one(b)["connections"] == 1
    b.close()
    # a folder that was there is left as it is: it is not this module's
    asked.clear()
    there = db.parent.parent / "shared" / "hosts.db"
    there.parent.mkdir()
    c = HostBook(there)
    win(c, T0, row(started=T0))
    c.flush()
    assert asked == [("hosts.db", 0o600)]


@pytest.mark.skipif(os.name == "nt", reason="Windows keeps no such modes: a file there is as its folder lets it be")
def test_on_linux_the_folder_is_0700_and_the_file_0600(db):
    old = os.umask(0o022)
    try:
        b = HostBook(db)
        win(b, T0, row(started=T0))
        b.flush(keep_open=True)
        assert stat.S_IMODE(db.parent.stat().st_mode) == 0o700
        beside = sorted(p.name for p in db.parent.iterdir())
        assert FILE in beside and all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in db.parent.iterdir()), beside
        b.close()
        assert stat.S_IMODE(db.stat().st_mode) == 0o600
        shared = db.parent.parent / "shared"
        shared.mkdir(mode=0o755)
        c = HostBook(shared / FILE)
        win(c, T0, row(started=T0))
        c.flush()
        assert stat.S_IMODE(shared.stat().st_mode) == 0o755 and stat.S_IMODE((shared / FILE).stat().st_mode) == 0o600
    finally:
        os.umask(old)


# -- one book for a path -----------------------------------------------------------------------------------------------

def test_there_is_one_book_for_a_path_in_a_process(db, tmp_path):
    b = hostbook.book(db)
    assert isinstance(b, HostBook) and b.path == db
    assert hostbook.book(db) is b and hostbook.book(str(db)) is b
    assert hostbook.book(db.parent / "x" / ".." / FILE) is b and hostbook.book(db.parent / "." / FILE) is b
    other = hostbook.book(db.with_name("other.db"))
    assert other is not b and hostbook.book(db.with_name("other.db")) is other
    mine = hostbook.book()  # the data folder's own
    assert mine.path == hostbook.path() and hostbook.book() is mine and mine is not b
    assert mine.path.resolve().is_relative_to(tmp_path.resolve())
    found: list[HostBook] = []
    threads = [threading.Thread(target=lambda: found.append(hostbook.book(db.with_name("raced.db")))) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(found) == 8 and all(book is found[0] for book in found)


def test_two_views_of_one_path_feed_one_book_and_count_nothing_twice(db):
    netstat, world = hostbook.book(db), hostbook.book(db)  # a view each: never a HostBook of its own
    reading = [row(started=T0 - 30), closing(WEB2)]
    assert netstat.feed(reading, T0, starts=True, awake=100.0) == {"new": 2, "ended": 0, "open": 1}
    assert world.feed(reading, T0, starts=True, awake=100.0) == {"new": 0, "ended": 0, "open": 1}
    assert world.feed(reading, T0 + 3, starts=True, awake=103.0) == {"new": 0, "ended": 0, "open": 1}
    assert netstat.feed(reading, T0 + 5, starts=True, awake=105.0) == {"new": 0, "ended": 0, "open": 1}
    world.flush()
    assert sorted((h["program"], h["connections"], h["seconds"]) for h in netstat.hosts()) == [
        (NOT_NAMED, 1, 0.0), (BROWSER, 1, 35.0)]


def test_a_recording_thread_and_a_pages_ask_share_a_book(db):
    b = HostBook(db)
    failed: list[BaseException] = []

    def record():
        try:
            for i in range(120):
                win(b, T0 + i, row(started=T0), row(f"203.0.113.{i % 50 + 10}", started=T0 + i, local_port=52000 + i))
                if i % 7 == 0:
                    b.flush(keep_open=True)
        except BaseException as e:  # noqa: BLE001 - told below
            failed.append(e)

    def ask():
        try:
            for _ in range(120):
                b.describe()
                b.hosts(limit=5)
                b.places()
                b.programs()
        except BaseException as e:  # noqa: BLE001
            failed.append(e)
    threads = [threading.Thread(target=record), threading.Thread(target=ask)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert failed == [] and not any(t.is_alive() for t in threads)
    b.close()
    rows = {h["host"]: h for h in b.hosts()}
    assert (rows[WEB]["connections"], rows[WEB]["seconds"]) == (1, 119.0) and b.describe()["problem"] == ""
    assert sum(h["connections"] for h in rows.values()) == 121



# -- 1.68.0: every connection its own row: who, what, when, why, where --------------------------------------------
def test_each_connection_is_its_own_row_with_who_what_when_why_and_where(db):
    """The user, 2026-11-20: "all connections need to be databased, basically who, what, when, why,where". A
    connection is its own row from the reading that first counts it to the first one without it, its seconds counted
    as its host's are; two connections of one program to one host and port are two rows (the hosts' row folds them)."""
    b = HostBook(db)
    first = row(started=T0 - 1, user="NEPTUNE\\ciara", service="BITS", service_title="Background Intelligent Transfer",
                port_name="https")
    second = row(started=T0 + 2, local_port=51001, port_name="https")
    win(b, T0, first)
    win(b, T0 + 5, first, second)
    win(b, T0 + 10, second)
    b.flush()
    rows = b.connections()
    assert [(r["local_port"], r["ended"]) for r in rows] == [(51001, None), (51000, T0 + 10)]  # the newest first
    one = rows[1]
    assert (one["program"], one["path"], one["pid"], one["user"], one["service"], one["service_title"]) == (
        BROWSER, BROWSER_PATH, 4321, "NEPTUNE\\ciara", "BITS", "Background Intelligent Transfer")  # who
    assert (one["proto"], one["family"], one["local"], one["local_port"], one["remote"], one["remote_port"],
            one["direction"], one["port"], one["network"]) == ("tcp", 4, LAN, 51000, WEB, 443, "out", 443,
                                                               "internet")  # what
    assert (one["started"], one["first"], one["last"], one["ended"]) == (T0 - 1, T0 - 1, T0 + 5, T0 + 10)  # when
    assert one["seconds"] == kept(b)[0]["seconds"] - 0 - rows[0]["seconds"]  # the host's time is the two's together
    assert one["why"] == ("its program reached out to a host on the internet on 443/tcp (https), for the service "
                          "Background Intelligent Transfer (BITS)")  # why
    assert (one["country"], one["city"], one["route"]) == (None, None, None)  # where: placed by `place`, no route
    assert len(kept(b)) == 1 and kept(b)[0]["connections"] == 2 and b.describe()["connections"] == 2


def test_a_connection_open_across_a_restart_goes_on_in_its_own_row(db):
    with HostBook(db) as first:
        win(first, T0, row(started=T0))
    b = HostBook(db)
    win(b, T0 + 5, row(started=T0))
    win(b, T0 + 9)
    b.flush()
    rows = b.connections()
    assert len(rows) == 1 and (rows[0]["first"], rows[0]["last"], rows[0]["ended"]) == (T0, T0 + 5, T0 + 9)
    assert rows[0]["seconds"] == 5.0


def test_a_connection_that_began_and_ended_between_two_readings_is_its_own_row_too(db):
    b = HostBook(db)
    win(b, T0, closing(WEB2, port_name="https"))
    b.flush()
    (one,) = b.connections()
    assert (one["program"], one["remote"], one["first"], one["ended"], one["seconds"]) == (NOT_NAMED, WEB2, T0, T0, 0.0)
    assert one["why"] == ("a connection with the internet on 443/tcp (https) that began and ended between two readings: "
                          "its program had let go of it")


def test_a_connection_takes_its_hosts_place_and_placing_a_host_places_its_connections(db):
    b = HostBook(db)
    win(b, T0, row(started=T0))
    b.flush()
    assert b.place(lambda host: NUREMBERG if host == WEB else None, NOVEMBER) == 1
    (one,) = b.connections()
    assert (one["city"], one["country"], one["asn"], one["org"]) == ("Nuremberg", "Germany", 64500, "Example Net")
    win(b, T0 + 5, row(started=T0), row(started=T0 + 4, local_port=51009))
    b.flush()  # a new connection to a host placed already takes its place when it is written
    assert [r["city"] for r in b.connections()] == ["Nuremberg", "Nuremberg"]


def test_a_route_traced_is_kept_and_handed_out_with_its_hosts_connections(db):
    b = HostBook(db)
    win(b, T0, row(started=T0), row(WEB2, started=T0, local_port=51001))
    hops = [{"n": 1, "address": "192.168.1.1", "ms": 0.5}, {"n": 2, "address": WEB, "ms": 9.0}]
    b.keep_route(WEB, T0 + 1, True, "icmp", hops, "Amsterdam → Frankfurt")
    b.flush()
    by = {r["remote"]: r for r in b.connections()}
    assert by[WEB]["route"] == {"traced": T0 + 1, "reached": True, "how": "icmp", "way": "Amsterdam → Frankfurt"}
    assert by[WEB2]["route"] is None
    con = sqlite3.connect(db)
    try:
        assert json.loads(con.execute("SELECT hops FROM routes").fetchone()[0]) == hops
    finally:
        con.close()


def test_the_connections_are_filtered_as_the_hosts_are(db):
    b = HostBook(db)
    win(b, T0, row(started=T0), row(MAIL, 993, started=T0, local_port=51001, program=MAILER, path=""),
        row(PRINTER, 9100, started=T0, local_port=51002, where="local network"))
    b.flush()
    assert {r["remote"] for r in b.connections(program=MAILER)} == {MAIL}
    assert {r["remote"] for r in b.connections(port=9100)} == {PRINTER}
    assert {r["remote"] for r in b.connections(proto="tcp", direction="out", since=T0)} == {WEB, MAIL, PRINTER}
    assert b.connections(direction="in") == [] and len(b.connections(limit=2)) == 2


def test_old_connections_and_routes_are_let_go_and_past_the_cap_the_ones_that_ended_longest_ago(db, monkeypatch):
    monkeypatch.setattr(hostbook, "CONNECTIONS", 3)
    b = HostBook(db)
    for i in range(5):  # five connections, one after the other, each gone by the next reading
        win(b, T0 + 10 * i, row(started=T0 + 10 * i, local_port=52000 + i))
    win(b, T0 + 50)
    b.keep_route(WEB, T0, True, "icmp", [], "")
    b.flush()
    assert [r["local_port"] for r in b.connections()] == [52004, 52003, 52002]  # three kept: the last three
    later = T0 + hostbook.KEEP_DAYS * 86400.0 + 100
    win(b, later, row(started=later, local_port=53000))
    b.flush()  # every one that ended KEEP_DAYS ago goes; so does the route traced ROUTE_DAYS ago
    assert [r["local_port"] for r in b.connections()] == [53000] and b.describe()["connections"] == 1
    con = sqlite3.connect(db)
    try:
        assert con.execute("SELECT COUNT(*) FROM routes").fetchone()[0] == 0
    finally:
        con.close()


def test_forget_forgets_the_connections_and_the_routes_too(db):
    b = HostBook(db, clock=Clock(T0 + 60))
    win(b, T0, row(started=T0))
    b.keep_route(WEB, T0, True, "icmp", [], "")
    b.flush()
    assert b.forget() == 1 and b.connections() == [] and b.describe()["connections"] == 0
    con = sqlite3.connect(db)
    try:
        assert con.execute("SELECT COUNT(*) FROM routes").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM connections").fetchone()[0] == 0
    finally:
        con.close()


def test_every_trace_is_kept_its_own_row_and_forgetting_lets_them_go(db):
    """1.74.0 (the user: "all routes need to be saved in a database for now"): a host traced again keeps its newest
    route in `routes` and every trace in `traces`."""
    b = HostBook(db)
    win(b, T0, row(started=T0))
    b.keep_route(WEB, T0 + 1, True, "icmp", [{"n": 1, "address": WEB, "ms": 9.0}], "Amsterdam")
    b.flush()
    b.keep_route(WEB, T0 + 3601, False, "icmp", [], "")
    b.flush()
    con = sqlite3.connect(db)
    try:
        assert con.execute("SELECT COUNT(*) FROM routes").fetchone()[0] == 1
        assert con.execute("SELECT traced, reached, way FROM traces ORDER BY traced").fetchall() == [
            (T0 + 1, 1, "Amsterdam"), (T0 + 3601, 0, "")]
    finally:
        con.close()
    b.forget()
    con = sqlite3.connect(db)
    try:
        assert con.execute("SELECT COUNT(*) FROM traces").fetchone()[0] == 0
    finally:
        con.close()


def test_a_hosts_kept_routes_are_handed_back_the_checks_others_first_the_drawn_one_last(db):
    """1.74.1: routes_of, for the hosts not traced again after a restart."""
    b = HostBook(db)
    win(b, T0, row(started=T0))
    other = [{"n": 1, "address": "62.0.0.2", "ms": 2.0}, {"n": 2, "address": WEB, "ms": 9.0}]
    drawn = [{"n": 1, "address": "62.0.0.1", "ms": 1.0}, {"n": 2, "address": None, "ms": None},
             {"n": 3, "address": WEB, "ms": 8.0}]
    b.keep_route(WEB, T0 + 1, True, "icmp", other, "")
    b.keep_route(WEB, T0 + 1, True, "icmp", drawn, "Amsterdam")
    b.keep_route("81.2.69.160", T0 + 2, False, "icmp", [], "")
    b.flush()
    got = b.routes_of([WEB, "81.2.69.160", "81.2.69.142", ""])
    assert set(got) == {WEB, "81.2.69.160"}  # the one with none left out
    assert [r["hops"] for r in got[WEB]] == [other, drawn] and got[WEB][-1]["traced"] == T0 + 1
    assert got[WEB][-1]["reached"] is True and got[WEB][-1]["how"] == "icmp"
    assert got["81.2.69.160"] == [{"traced": T0 + 2, "reached": False, "how": "icmp", "hops": []}]
    assert b.routes_of([]) == {} and HostBook(db.parent / "none.db").routes_of([WEB]) == {}  # no file: none made
    assert not (db.parent / "none.db").exists()


# -- 1.101.0 (Monday list item 20): the stamps of the GeoIP sources' files ------------------------------------------------
def test_a_switch_of_source_either_way_places_the_hosts_again_and_the_defaults_stamps_stay(db):
    from liminal_libs.machines import geosources
    b = HostBook(db)
    win(b, T0, row(started=T0))
    b.flush()
    default = geosources.stamp(("dbip", NOVEMBER), ("dbip", NOVEMBER), "dbip")
    assert default == NOVEMBER  # the stamp rows already carry: none placed again
    asked: list = []
    assert b.place(atlas({WEB: LONDON}, asked), default) == 1 and b.unplaced(default) == 0
    other = geosources.stamp(("dbip", NOVEMBER), ("ipinfo", "2026-11-24"), "dbip")
    assert b.unplaced(other) == 1 and b.place(atlas({WEB: NUREMBERG}, asked), other) == 1
    (h,) = b.hosts()
    assert (h["placed"], h["asn"]) == (other, 64500) and b.unplaced(other) == 0
    assert b.unplaced(default) == 1  # and back: placed again
    assert b.place(atlas({WEB: LONDON}, asked), default) == 1 and b.hosts()[0]["placed"] == NOVEMBER


def test_a_new_connection_takes_its_hosts_place_from_the_files_in_use_alone(db, monkeypatch):
    b = HostBook(db)
    win(b, T0, row(started=T0))
    b.flush()
    stamp = "#dbip:2026-11-01+ipinfo:2026-11-24"
    b.place(atlas({WEB: NUREMBERG}), stamp)
    # a second row of the same host, placed by an older file, whose stamp sorts after "#..."
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO hosts (program, host, proto, port, direction, network, first, last, seconds, "
                 "connections, country, placed) VALUES ('other.exe', ?, 'tcp', 443, 'out', 'internet', ?, ?, 0, 1, "
                 "'Elsewhere', '2026-12-01')", (WEB, T0, T0))
    conn.commit()
    conn.close()
    win(b, T0 + 60, row(started=T0 + 50, local_port=51500))  # a new connection of WEB
    b.flush()
    newest = max(b.connections(), key=lambda c: c["first"])
    assert newest["country"] == "Germany"  # not "Elsewhere", the greatest string


def test_clearing_by_role_takes_one_sources_places_out_of_both_tables(db):
    from liminal_libs.machines import geosources
    b = HostBook(db)
    win(b, T0, row(started=T0), row(WEB2, started=T0, local_port=51001))
    b.flush()
    b.place(atlas({WEB: NUREMBERG, WEB2: NUREMBERG}), "#dbip:2026-11-01+ipinfo:2026-11-24")
    assert b.clear_places("networks", geosources.cleared("networks", "ipinfo")) == 2
    rows = b.hosts()
    assert {(h["asn"], h["org"], h["country"], h["placed"]) for h in rows} == {(None, "", "Germany", "")}
    assert all(c["asn"] is None for c in b.connections())
    assert b.unplaced("#dbip:2026-11-01+none") == 2
    b.place(atlas({WEB: NUREMBERG}), "#maker:2026-11-24+none")
    assert b.clear_places("places", geosources.cleared("places", "maker")) == 2  # both looked up in it
    cleared = {h["host"]: h for h in b.hosts()}[WEB]
    assert (cleared["country"], cleared["lat"], cleared["placed"]) == ("", None, "")
    assert b.clear_places("places", geosources.cleared("places", "nobody")) == 0


def test_an_older_librarys_statement_takes_the_sources_rows_as_older(db):
    b = HostBook(db)
    win(b, T0, row(started=T0))
    b.flush()
    b.place(atlas({WEB: NUREMBERG}), "#maker:2026-11-24+none")
    conn = sqlite3.connect(db)
    try:  # what 1.100.0 and before ask: placed < the DB-IP file's date
        (n,) = conn.execute("SELECT COUNT(*) FROM hosts WHERE network = 'internet' AND (placed IS NULL OR placed < ?)",
                            (NOVEMBER,)).fetchone()
    finally:
        conn.close()
    assert n == 1  # placed again by an older library, from DB-IP
