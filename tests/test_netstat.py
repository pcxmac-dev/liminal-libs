"""The firewalls' Netstat tab, the hosts' recording and what the World Wide Web tab's globe gains (machines/netstat.py,
and the Firewall base's netstat, hosts_recording, hosts_forget, world_show, world_direction, world_within, world_pick,
world_layer, world_layer_get, world_layer_remove, attach, app_stopping, settings_changed and detach; the user,
2026-11-16: "the firewall app should have a 'netstat' like interface for looking at active ports and what apps they are
attached to, and the hosts that they connect to across the lan or wan", "geoip'd hosts are databased for the apps they
talk to, the time they are connected to *this *computer", "the globe-firewall should allow filtering, so i can view
apps connected to hosts all across the globe, or ports talking to all hosts").

The tab's page over a Windows and a Linux reading (each connection with its program, pid and service, where its host
is, its name or place, since when and for how long; the listening ports, Liminal's own named; the hosts database and its
forms), one reading shared and fed once and each of its rows kept once, judged, no thread while recording only while a
tab is shown, the recording thread of "always" ended by a stop, a detach, the platform's stop (twice) and the setting
set back, never started in a one-shot app or on another system's drive, a setting that does not last said; the globe's
choice, its filters and their refusals, the traffic view given its first table, its layers and their table, the hosts
view's places grouped by point, its tables and its programs and ports right under the globe, its Every rows by one
plain query, made again at most every ten seconds unless a choice changed, the GeoIP file opened for places only when
a host needs one, its note reaching the globe whole; a layer's geometry, a data set's download as the plugin's job,
and its removal; and on a machine the plugin is not for, every one of those hooks refused before anything is made.

Nothing real: the socket table is a stand-in reading (the suite's guard refuses the real one), the hosts database and
the layers' folder are in tmp_path (the same guard), the GeoIP file is a stand-in, the download's fetch is a stand-in
that answers nothing, no process is started and nothing reaches the network (the shared `no_outside`)."""
from __future__ import annotations

import copy
import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from liminal_libs import geo, hostbook, internal, sockets
from liminal_libs.apps.authorization import EnvironmentLogin, Login, Unauthorized, pair_name
from liminal_libs.machines import infrastructure, netstat, world
from liminal_libs.machines.firewall import Firewall
from liminal_libs.machines.infrastructure import DataSet, Index, pack, parse
from liminal_libs.machines.netstat import EVERY, HOOK, HOSTS_S, TAB, TITLE, Choice, NetstatView
from liminal_libs.machines.world import LicenceRefused, WorldView
from liminal_libs.machines.worldweb import WorldWideWeb
from liminal_libs.ui import STATIC

from test_firewall import FakeFirewall

pytestmark = pytest.mark.usefixtures("no_outside")  # the library's shared guard (tests/conftest.py)

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc).timestamp()
LAN, LAN6, PRINTER, ROUTER = "192.168.1.20", "2001:db8:1::20", "192.168.1.50", "192.168.1.1"
# public addresses (the documentation ranges are the local network's to the globe: never placed)
WEB, WEB2, V6WEB, NOWHERE = "81.2.69.142", "81.2.69.160", "2606:4700::1111", "5.6.7.8"
WSL, WSL_GATEWAY = "172.29.152.10", "172.29.144.1"
EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
PY = "C:\\Python315\\python.exe"
NAMES = {"127.0.0.1": "localhost", WEB2: "cdn.example"}  # the system's own hosts file, stood in
LONDON = geo.Place("GB", "United Kingdom", "London", 51.5142, -0.0931)
NUREMBERG = geo.Place("DE", "Germany", "Nuremberg", 49.4478, 11.0683, 64500, "Example Net")
PLACES = {WEB: LONDON, V6WEB: NUREMBERG, WEB2: LONDON}  # NOWHERE: the file has no place for it


def sock(proto="tcp", local=LAN, local_port=51000, remote="", remote_port=0, *, state="established", pid=4321,
         program="msedge.exe", path=EDGE, service="", title="", started=None, seen=None, inode=0, user="",
         unread=None) -> dict:
    """One socket as a reader's row (sockets' shape)."""
    return {"proto": proto, "family": 6 if ":" in local else 4, "state": state, "local": local,
            "local_port": local_port, "remote": remote, "remote_port": remote_port, "pid": pid,
            "pids": [pid] if pid else [], "program": program, "path": path, "service": service,
            "service_title": title, "user": user, "started": started, "process_started": None, "count": 1,
            "inode": inode, "seen": seen if seen is not None else started, "unread": dict(unread or {})}


def windows_rows(at: float = NOW) -> list[dict]:
    return [
        sock(remote=WEB, remote_port=443, started=at - 120),  # out to the internet
        sock(local=LAN6, local_port=52000, remote=V6WEB, remote_port=443, started=at - 60),  # out, over IPv6
        sock("udp", "0.0.0.0", 5353, state="bound", pid=1200, program="svchost.exe", path="", service="Dnscache",
             title="DNS Client", started=at - 3 * 86400, unread={"path": sockets.REFUSED}),
        sock(local="0.0.0.0", local_port=8765, state="listening", pid=900, program="python.exe", path=PY,
             started=at - 3600),  # the charts' page, on every address
        sock(local="127.0.0.1", local_port=8775, state="listening", pid=901, program="python.exe", path=PY,
             started=at - 3600),  # the platform's, this machine only
        sock(local=LAN, local_port=8765, remote=PRINTER, remote_port=50500, pid=900, program="python.exe", path=PY,
             started=at - 30),  # in, from the local network
        sock(local="127.0.0.1", local_port=51010, remote="127.0.0.1", remote_port=8775, pid=902, program="python.exe",
             path=PY, started=at - 10),  # a connection inside this machine, both its ends
        sock(local="127.0.0.1", local_port=8775, remote="127.0.0.1", remote_port=51010, pid=901, program="python.exe",
             path=PY, started=at - 10),
        sock(local="0.0.0.0", local_port=445, state="listening", pid=4, program="System", path="",
             started=at - 3 * 86400, unread={"service": sockets.SYSTEM, "path": sockets.SYSTEM_PATH}),
        sock(local=LAN, local_port=51003, remote=WEB2, remote_port=443, state="time-wait", pid=0, program="", path="",
             seen=at - 5, unread={"program": sockets.GONE}),  # its owner gone: only waiting to close
    ]


def reading(rows=None, *, system="windows", at: float = NOW, notes=None, starts=None, awake: float = 1000.0) -> dict:
    """A reading as sockets.read answers it, taken at `at` (its rows' times are NOW's: the same sockets read later)."""
    return {"system": system, "at": at, "awake": awake, "took": 0.004, "root": False,
            "starts": system == "windows" if starts is None else starts, "read": sockets.TABLES, "cut": False,
            "rows": windows_rows() if rows is None else rows,
            "notes": [sockets.UDP_NOTE] if notes is None and system == "windows" else list(notes or ())}


ANOTHER = "another user's (root): only root reads which program holds it"


def linux_reading(at: float = NOW) -> dict:
    rows = [
        sock(local=WSL, local_port=41000, remote=WEB2, remote_port=443, pid=2000, program="curl", path="/usr/bin/curl",
             user="sysop", inode=7001, seen=at - 30),
        sock("udp", WSL, 41001, WSL_GATEWAY, 53, state="connected", pid=2001, program="dig", path="/usr/bin/dig",
             user="sysop", inode=7002, seen=at - 2),
        sock(local="0.0.0.0", local_port=22, state="listening", pid=0, program="", path="", user="root", inode=4001,
             seen=at - 86400, unread={"program": ANOTHER}),  # root's sshd: named by the firewall's own root read
        sock(local="0.0.0.0", local_port=631, state="listening", pid=0, program="", path="", user="root", inode=4002,
             seen=at - 86400, unread={"program": ANOTHER}),  # root's, and not named by it either
    ]
    return reading(rows, system="linux", at=at, notes=["Read as sysop: the kernel lists every socket here and names "
                                                       "the program of your own alone.", sockets.NO_START_NOTE])


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class Keeping(Login):
    """A login that keeps what it is given, as the login app does (so a setting lasts a restart); it counts its
    reads."""

    def __init__(self, **values):
        self.values = {pair_name(k): v for k, v in values.items()}
        self.reads, self.saved = 0, []

    def user(self) -> dict:
        return {"name": "tester"}

    def vector(self, name: str) -> str:
        self.reads += 1
        if name not in self.values:
            raise Unauthorized(f"no {name} here", 404)
        return self.values[name]

    def save(self, variable: str, value) -> str:
        self.saved.append((variable, value))
        if value is None:
            self.values.pop(pair_name(variable), None)
        else:
            self.values[pair_name(variable)] = value
        return "the test's login"


class Placing:
    """A GeoIP file as a stand-in: its own date, and the place of each address it knows."""

    def __init__(self, places=None, date: str = "2026-11-01"):
        self.places, self.date, self.asked = dict(PLACES if places is None else places), date, []

    def lookup(self, ip):
        self.asked.append(ip)
        return self.places.get(ip)

    def describe(self) -> dict:
        return {"date": self.date, "open": True}


class Feed:
    """A capture that is opened and never hands a packet (the traffic view's, never asked here for packets)."""

    address = LAN

    def open(self):
        pass

    def next(self):
        return None

    def close(self):
        pass


class Globe(WorldView):
    """The plugin's WorldView, its GeoIP file a stand-in (`placing`; none when None), counting the opens and the lets
    go."""

    def __init__(self, tmp_path: Path, placing=None, **more):
        more.setdefault("resolve", lambda version, servers: (None, "no name server answers in a test"))
        super().__init__("wall", capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(),
                         wall=lambda: NOW, **more)
        self.placing, self.opened, self.rested = placing, 0, 0

    def geoip(self):
        self.opened += 1
        return self.placing

    def rest(self) -> None:
        self.rested += 1
        super().rest()


def threads() -> list[str]:
    return [t.name for t in threading.enumerate() if t.name.endswith("-hosts") or t.name.endswith("-layer-download")]


def wait_for(condition, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


@pytest.fixture(autouse=True)
def _views(monkeypatch):
    """Every NetstatView a test makes is closed after it, and no recording or download thread is left."""
    made: list[NetstatView] = []
    init = NetstatView.__init__

    def tracked(self, *args, **kwargs):
        init(self, *args, **kwargs)
        made.append(self)
    monkeypatch.setattr(NetstatView, "__init__", tracked)
    monkeypatch.setattr(sockets, "under_wsl", lambda *args, **kwargs: None)  # not this machine's WSL, if it is one
    monkeypatch.setattr(world, "under_wsl", lambda *args, **kwargs: None)
    # a GeoIP reader as if maxminddb were here (the files themselves are stand-ins), so each system reads alike
    monkeypatch.setattr(geo, "available", lambda: (True, "a stand-in reader"))
    yield made
    for view in made:
        view.close()
    assert wait_for(lambda: threads() == []), f"a thread was left: {threads()}"


def view_of(source=None, *, login=None, clock=None, wall: float = NOW, **more) -> NetstatView:
    """A view over a stand-in reader handing `source` (a reading, or () -> one; by default the Windows reading, taken
    three seconds after the one before, as readings are), counting its readings."""
    asked: list[float] = []

    def reader() -> dict:
        given = source() if callable(source) else source
        if given is None:
            given = reading(at=NOW + 3 * len(asked), awake=1000.0 + 3 * len(asked))
        asked.append(1)
        return copy.deepcopy(given)
    more.setdefault("names", NAMES)
    view = NetstatView("wall", reader=reader, login_of=lambda: login, clock=clock or Clock(), wall=lambda: wall,
                       **more)
    view.asked = asked
    return view


def at_time(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


def by_remote(page: dict) -> dict:
    return {r["remote"]: r for r in page["flows"]["rows"]}


def plain(page: dict) -> dict:
    assert json.loads(json.dumps(page, allow_nan=False)) == page  # plain data, as the platform sends it
    return page


# -- what the module says of itself -----------------------------------------------------------------------------------
def test_the_tab_its_hooks_and_the_module_name_no_address_and_start_nothing():
    assert (TAB, TITLE, HOOK, EVERY, HOSTS_S) == ("netstat", "Netstat", "netstat", 3.0, 10.0)
    assert netstat.HOOKS == ("netstat", "hosts_recording", "hosts_forget", "world_show", "world_direction",
                             "world_within", "world_pick", "world_layer", "world_layer_get", "world_layer_remove",
                             "world_sky", "world_sky_get", "world_sky_remove")  # 1.104.0: the satellites
    assert (netstat.FLOW_ROWS, netstat.LISTEN_ROWS, netstat.TABLE_ROWS, netstat.PICKS) == (2000, 200, 100, 8)
    assert netstat.WITHIN == {"hour": 3600, "day": 86400, "week": 604800, "month": 2592000}
    source = Path(netstat.__file__).read_text(encoding="utf-8")
    assert "://" not in source  # no outside address in the library, docstrings included
    for word in ("subprocess", "import ctypes", "from .. import capture", "urllib", "WinDLL", "winreg", "Popen",
                 "storage.link", "gethostby", "getnameinfo"):
        assert word not in source, word
    assert max(len(line) for line in source.splitlines()) <= 120
    # one wording for the two modes everywhere (B-revisions M10), the hosts database's own words with them
    hint = hostbook.HOSTS_KEY.hint
    assert netstat.MODE_WORDS["shown"] in hint and netstat.MODE_WORDS["always"] in hint


# -- the Netstat tab --------------------------------------------------------------------------------------------------
def test_a_windows_reading_tables_each_connection_with_its_program_its_hosts_place_and_how_long_it_is_up(tmp_path):
    globe = Globe(tmp_path, Placing())
    view = view_of(app_ports=lambda: {"charts": 8765, "platform": 8775, "integrator": 8785, "login": 8795})
    page = plain(view.page(globe))
    assert page["title"] == "Netstat"
    assert page["note"].startswith(f"This machine's socket table, read {at_time(NOW)} in 4 ms with no capture and no "
                                   "administrator asked: 4 listening ports, 6 connections to 5 hosts (3 on the "
                                   "internet, 1 on the local network, 1 on this machine).")
    assert sockets.UDP_NOTE in page["note"] and netstat.INTERPRETER in page["note"]
    assert "Hosts are recorded only while this plugin's Netstat or World Wide Web tab is shown." in page["note"]
    flows = page["flows"]
    assert [(c["key"], c["title"]) for c in flows["columns"]] == [
        ("program", "Program"), ("dir", "Direction"), ("remote", "Remote host"), ("labels", "Where"),
        ("name", "Name or place"), ("proto", "Protocol"), ("local", "Here"), ("state", "State"), ("since", "Since"),
        ("duration", "Up for"), ("unread", "Not read")]
    # the page's own filters: its directions and the three places a host can be; no "flagged" (nothing is flagged)
    assert flows["filters"] == {"dir": ["in", "out", "local"], "labels": ["internet", "local network", "this machine"]}
    rows = by_remote(page)
    edge = rows[f"{WEB}:443"]
    assert (edge["program"], edge["dir"], edge["proto"], edge["local"], edge["state"]) == (
        "msedge.exe (pid 4321)", "out", "tcp", f"{LAN}:51000", "established")
    assert edge["labels"] == [{"kind": "internet"}] and edge["name"] == "London, United Kingdom"  # its GeoIP place
    assert (edge["time"], edge["since"], edge["duration"], edge["unread"]) == (NOW - 120, at_time(NOW - 120), 120.0, "")
    six = rows[f"[{V6WEB}]:443"]  # an IPv6 address in brackets, as the page shows an address with its port
    assert six["local"] == f"[{LAN6}]:52000" and six["name"] == "Nuremberg, Germany"
    lan = rows[f"{PRINTER}:50500"]  # to a port this machine listens on, from the local network: never placed
    assert (lan["dir"], lan["labels"], lan["name"]) == ("in", [{"kind": "local network"}], "")
    inside = [r for r in flows["rows"] if r["labels"] == [{"kind": "this machine"}]]
    assert len(inside) == 2 and {r["dir"] for r in inside} == {"local"} and {r["name"] for r in inside} == {"localhost"}
    closing = rows[f"{WEB2}:443"]  # its owner gone: the row's own words for its program, and when it was first seen
    assert (closing["program"], closing["state"], closing["duration"]) == (sockets.GONE, "time-wait", None)
    assert closing["since"] == at_time(NOW - 5) and closing["name"] == "cdn.example"  # the hosts file's name wins
    assert flows["rows"][-1] == closing  # the ones up first
    assert globe.opened == 1 and globe.rested == 1  # the GeoIP file asked once for the page, and let go again
    # the listening ports: each protocol, port and program; Liminal's own pages named; where each is reached from
    listening = page["tables"][0]
    assert listening["title"] == "Listening ports" and [c["title"] for c in listening["columns"]] == [
        "Port", "Protocol", "Reached from", "Program", "Service", "Since"]
    three = datetime.fromtimestamp(NOW - 3 * 86400)  # not today: said with its date
    days_ago = f"{three.day} {netstat.MONTHS[three.month - 1]} {three:%H:%M}"
    # what a listener could not read is said under its name, as the connections' Not read says it
    assert listening["rows"] == [
        ["445", "tcp", "every address",
         {"text": "System (pid 4)", "sub": f"{sockets.SYSTEM}; {sockets.SYSTEM_PATH}"}, "", days_ago],
        ["5353", "udp", "every address", {"text": "svchost.exe (pid 1200) · Dnscache (DNS Client)",
                                          "sub": sockets.REFUSED}, "Dnscache (DNS Client)", days_ago],
        [{"text": "8765", "sub": "Liminal's charts page"}, "tcp", "every address", "python.exe (pid 900)", "",
         at_time(NOW - 3600)],
        [{"text": "8775", "sub": "Liminal's platform page"}, "tcp", "this machine only", "python.exe (pid 901)", "",
         at_time(NOW - 3600)]]
    database = page["tables"][1]
    assert database["title"] == "The hosts database" and dict(database["rows"])["Kept in"] == str(hostbook.path())
    # its bound is the rows; its size is no bound (long names and paths make it larger), so said as about, not at most
    assert "50,000 rows at most (about 13 MB with ordinary values), the hosts longest unseen pruned first" in (
        database["note"])
    assert [a["form"] for a in database["actions"]] == ["hosts-recording", "hosts-forget"]
    assert [f["id"] for f in page["forms"]] == ["hosts-recording", "hosts-forget"]


def test_a_linux_reading_names_another_users_listener_by_the_firewalls_own_read_and_says_no_time_up(tmp_path):
    view = view_of(linux_reading(), listeners=lambda: {("tcp", 22): "sshd"})
    page = plain(view.page(Globe(tmp_path, Placing())))
    assert sockets.NO_START_NOTE in page["note"] and "Read as sysop" in page["note"]
    rows = by_remote(page)
    curl = rows[f"{WEB2}:443"]
    assert (curl["program"], curl["dir"], curl["name"]) == ("curl (pid 2000)", "out", "cdn.example")
    assert (curl["duration"], curl["since"]) == (None, at_time(NOW - 30))  # Linux says no start: first seen, not up for
    dig = rows[f"{WSL_GATEWAY}:53"]  # a connected UDP socket names its peer on Linux
    assert (dig["proto"], dig["labels"], dig["state"]) == ("udp", [{"kind": "local network"}], "connected")
    listening = {r[0]: r for r in page["tables"][0]["rows"]}
    assert listening["22"][3] == {"text": "sshd", "sub": "named by the firewall's own root read; its pid is not read"}
    assert listening["631"][3] == ANOTHER  # not named by it either: the row's own words
    # the connections' note says what holds on every system; what Windows lists or not is its reading's own note, and
    # it names no tab this version has not got
    assert page["flows"]["note"] == ("A connection shorter than the gap between two readings (3 s while this tab is "
                                     "shown) can be missed. Up for is said where the system says when a connection "
                                     "began.")


def test_one_reading_is_shared_by_every_ask_and_fed_to_the_hosts_database_once(tmp_path):
    clock = Clock()
    view = view_of(clock=clock)
    globe = Globe(tmp_path, Placing())
    view.page(globe)
    view.touch()
    view.page(globe)
    assert len(view.asked) == 1  # three asks within sockets.READ_S: one reading
    assert view.book.describe()["rows"] == 4  # the internet's three and the local network's one; never this machine's
    clock.t += sockets.READ_S
    view.touch()
    assert len(view.asked) == 2
    hosts = {(h["program"], h["host"]): h for h in view.book.hosts()}
    assert hosts[("msedge.exe", WEB)]["connections"] == 1  # the same connection read again: counted once
    assert hosts[(hostbook.NOT_NAMED, WEB2)]["connections"] == 1  # one that closed between two readings: once
    assert ("python.exe", "127.0.0.1") not in hosts and ("python.exe", PRINTER) in hosts


def test_between_readings_the_view_keeps_each_row_once_judged():
    """Up to sockets.MAX_ROWS rows a reading: the view keeps them judged alone, and of the reading its own facts and
    how many rows it had, not a second copy of each row."""
    view = view_of()
    got = view.touch()
    assert "rows" not in got["reading"] and (got["reading"]["system"], got["reading"]["at"]) == ("windows", NOW)
    assert len(got["rows"]) == 10 and all("where" in r for r in got["rows"])  # each row once, judged
    assert view.describe()["reading"]["rows"] == 10
    assert "4 listening ports, 6 connections to 5 hosts" in view.page()["note"] and len(view.asked) == 1


def test_recording_while_a_tab_is_shown_starts_no_thread_and_lets_the_file_go_after_each_ask(tmp_path):
    view = view_of(login=Keeping())
    view.follow(once=False)
    view.page(Globe(tmp_path))
    assert view.mode() == "shown" and not view.recording() and threads() == []
    assert view.book._conn is None and hostbook.path().exists()  # written, and the file let go
    assert hostbook.path().is_relative_to(tmp_path)  # the suite's guard keeps it in the test's own folder


def test_recording_all_the_time_runs_on_its_own_thread_until_it_is_stopped_set_back_or_detached(tmp_path):
    login = Keeping(LIMINAL_HOSTS_RECORDING="always")
    view = view_of(login=login)
    view.follow(once=False)
    assert view.recording() and threads() == ["wall-hosts"]
    assert wait_for(lambda: len(view.asked) == 1) and wait_for(lambda: view.book.describe()["last"] == NOW)
    assert view.book.describe()["rows"] == 0  # read, and written every FLUSH_S while it records all the time
    began = time.monotonic()
    view.stop()  # the platform's stop: joined at once (its wait ends with the stop), what it read written
    assert time.monotonic() - began < 2.0 and not view.recording() and threads() == []
    assert view.book._conn is None and view.book.describe()["rows"] == 4
    view.stop()  # a second time: nothing to stop
    view.follow()
    assert view.recording()
    answer = view.set_mode("shown")  # set back: it stops
    assert answer == {"said": "recording only while this plugin's Netstat or World Wide Web tab is shown", "ok": True,
                      "lines": ["kept in the test's login"]}
    assert not view.recording() and login.saved == [("LIMINAL_HOSTS_RECORDING", "shown")]
    assert view.set_mode("always")["said"] == "recording all the time the platform runs" and view.recording()
    view.close()  # the plugin detached: for good
    assert not view.recording() and wait_for(lambda: threads() == [])
    view.follow()
    assert not view.recording()  # a closed view starts nothing again


def test_recording_all_the_time_writes_every_flush_s_itself_and_keeps_the_file_open_meanwhile(monkeypatch):
    monkeypatch.setattr(hostbook, "FLUSH_S", 0.0)  # every round writes
    monkeypatch.setattr(hostbook, "ALWAYS_S", 0.01)
    view = view_of(login=Keeping(LIMINAL_HOSTS_RECORDING="always"))
    view.follow(once=False)
    assert wait_for(lambda: view.book.describe()["rows"] == 4)  # written by the thread, no page asked
    assert view.book._conn is not None  # the file kept open while it records all the time
    view.page()  # a page's ask meanwhile shares the reading and leaves the file open for the thread
    assert view.book._conn is not None and len(view.asked) == 1
    view.stop()
    assert view.book._conn is None and threads() == []  # written and let go


def test_recording_never_starts_in_a_one_shot_app_nor_for_a_database_on_another_systems_drive(tmp_path, monkeypatch):
    view = view_of(login=Keeping(LIMINAL_HOSTS_RECORDING="always"))
    view.follow(once=True)  # a command that answers and ends
    assert not view.recording() and view.mode() == "always"
    view.follow()  # the app is still a one-shot one
    assert not view.recording()
    there = view_of(login=Keeping(LIMINAL_HOSTS_RECORDING="always"))
    words = "Keeping the hosts database here is another system's: its drive"
    monkeypatch.setattr(hostbook, "foreign", lambda p=None: words)
    there.follow(once=False)
    assert not there.recording() and threads() == []
    with pytest.raises(ValueError, match="another system's"):
        there.set_mode("always")


def test_the_setting_is_read_through_the_login_now_and_then_a_bad_value_said_and_one_that_does_not_last_said():
    clock, login = Clock(), Keeping(LIMINAL_HOSTS_RECORDING="sometimes")
    view = view_of(login=login, clock=clock)
    assert view.mode() == "shown" and view.mode() == "shown" and login.reads == 1  # read every SETTING_S at most
    note = view.page()["note"]
    assert "LIMINAL_HOSTS_RECORDING is 'sometimes', neither shown nor always: shown is taken." in note
    clock.t += netstat.SETTING_S
    login.values["liminal-hosts-recording"] = "always"
    view.forget_setting()
    assert view.mode() == "always" and login.reads == 2
    view.stop()
    # a login that keeps a value in this process alone (an EnvironmentLogin of its own variables; off Windows, the
    # platform's): said in the answer and on the page
    kept_here = EnvironmentLogin(env={})
    passing = view_of(login=kept_here)
    answer = passing.set_mode("always")
    assert answer["lines"] == ["kept in the login's variables", netstat.NOT_LASTING]
    assert netstat.NOT_LASTING in passing.page()["note"]
    passing.close()
    assert netstat.NOT_LASTING not in view_of(login=Keeping()).set_mode("always")["lines"]


def test_recording_is_set_to_one_of_its_two_words_through_a_login(tmp_path):
    view = view_of(login=Keeping())
    for bad in ("sometimes", "", None, 3, "always now"):
        with pytest.raises(ValueError, match="recording is shown or always, not"):
            view.set_mode(bad)
    assert view.set_mode(" Always ")["said"] == "recording all the time the platform runs"
    view.stop()
    with pytest.raises(ValueError, match="kept through the platform's login, and this plugin has none"):
        view_of().set_mode("always")

    class Refusing(Keeping):
        def save(self, variable, value):
            raise Unauthorized("Refusing keeps no settings", 405)
    with pytest.raises(ValueError, match="the setting could not be kept: Refusing keeps no settings"):
        view_of(login=Refusing()).set_mode("always")


def test_the_hosts_are_forgotten_only_once_asked_twice_and_none_is_left(tmp_path):
    view = view_of()
    view.page(Globe(tmp_path, Placing()))
    assert view.book.describe()["rows"] == 4
    with pytest.raises(hostbook.ForgetRefused) as refused:
        view.forget()
    assert refused.value.accept == "accept_forget" and "a second time" in str(refused.value)
    with pytest.raises(hostbook.ForgetRefused):
        view.forget("yes")  # only exactly True
    assert view.book.describe()["rows"] == 4
    answer = view.forget(accept_forget=True)
    assert answer["said"] == "forgot 4 rows of the hosts database" and answer["ok"] is True
    assert answer["lines"] == [f"removed from {view.book.path}",
                               "recording goes on only while this plugin's Netstat or World Wide Web tab is shown"]
    assert view.book.hosts() == [] and view.book.describe()["rows"] == 0


def test_the_forms_say_what_is_kept_and_where_and_forgetting_asks_a_second_time():
    view = view_of(login=Keeping())
    recording, forget = view.page()["forms"]
    assert (recording["id"], recording["hook"], recording["title"]) == ("hosts-recording", "hosts_recording",
                                                                        "Recording the hosts")
    [mode] = recording["fields"]
    assert (mode["name"], mode["type"], mode["value"]) == ("mode", "choice", "shown")
    assert [c["value"] for c in mode["choices"]] == ["shown", "always"] and mode["choices"][1]["note"] == (
        "a reading every 5 s")
    words = recording["confirm"]["words"]
    assert words.startswith("Recording is set to {mode}. Always reads this machine's socket table every 5 seconds")
    assert str(hostbook.path()) in words and "50,000 rows at most" in words and "nothing is sent anywhere" in words
    assert (forget["hook"], forget["danger"], forget["confirm"]["danger"]) == ("hosts_forget", True, True)
    [accept] = forget["fields"]
    assert (accept["name"], accept["type"], accept["yes"]) == ("accept_forget", "accept", "Forget them")
    assert "They cannot be brought back" in forget["confirm"]["words"] and "rows since" in forget["confirm"]["words"]


def test_a_hosts_database_on_another_systems_drive_is_left_alone_and_said(tmp_path, monkeypatch):
    words = "Keeping the hosts database here is another system's: its drive is seen through a mount"
    monkeypatch.setattr(hostbook, "foreign", lambda p=None: words)
    monkeypatch.setattr(hostbook.HostBook, "_ready", lambda self: setattr(self, "_elsewhere", words) or False)
    view = view_of()
    page = plain(view.page(Globe(tmp_path, Placing())))
    assert len(page["flows"]["rows"]) == 6  # the socket table is read all the same: it is this system's own
    database = page["tables"][1]
    assert database["rows"] == [["Recording", "not from here"], ["Why", words]] and "actions" not in database
    assert page["forms"] == []
    view.show("hosts")
    globe = Globe(tmp_path, Placing())
    hosts = plain(view.onto(None, globe))
    assert hosts["note"] == f"No host is shown here. {words}. Each system's platform keeps its own."
    assert hosts["globe"]["origins"] == [] and globe.placing.asked == []  # nothing of it looked up
    assert not tmp_path.joinpath("liminal-data").exists() or not hostbook.path().exists()


def test_a_reader_that_fails_is_said_and_the_last_reading_kept(tmp_path):
    clock, readings = Clock(), [reading()]

    def source():
        if not readings:
            raise OSError("the table could not be read")
        return readings.pop()
    view = view_of(source, clock=clock)
    first = view.page()
    clock.t += sockets.READ_S
    again = view.page()
    assert "It could not be read again just now (OSError: the table could not be read)" in again["note"]
    assert again["flows"]["rows"] == first["flows"]["rows"]
    assert view.describe()["reading"]["rows"] == 10  # the last reading's count kept with it
    lone = view_of(lambda: 1 / 0)
    assert lone.page()["note"].startswith("This machine's socket table could not be read: ZeroDivisionError")


# -- the World Wide Web tab: what the globe shows -------------------------------------------------------------------
def test_the_choices_set_what_the_globe_shows_and_refuse_anything_else():
    view = view_of()
    assert view.shows() == "traffic" and view.choice() == Choice()
    assert view.show("hosts") == {"said": "Hosts recorded · all of them", "ok": True}
    assert view.show("Traffic") == {"said": "Traffic watched now", "ok": True}
    assert view.direction("out")["said"] == "Hosts recorded · out"  # a filter sets the globe to the hosts
    assert view.within("day")["said"] == "Hosts recorded · out · seen in the last 24 hours"
    assert view.pick("program=msedge.exe")["said"] == "Hosts recorded · msedge.exe · out · seen in the last 24 hours"
    assert view.pick("port=TCP/443")["said"] == ("Hosts recorded · msedge.exe · port 443/tcp · out · seen in the last "
                                                 "24 hours")
    assert view.choice() == Choice("hosts", "msedge.exe", "tcp", 443, "out", "day")
    assert view.pick("program=")["said"] == "Hosts recorded · port 443/tcp · out · seen in the last 24 hours"
    assert view.pick("port=")["said"] == "Hosts recorded · out · seen in the last 24 hours"
    assert view.direction("")["said"] == "Hosts recorded · seen in the last 24 hours"  # both ways
    assert view.within(None)["said"] == "Hosts recorded · all of them"  # any time
    view.pick("program=a")
    assert view.pick("clear") == {"said": "Hosts recorded · all of them", "ok": True}
    assert view.choice() == Choice("hosts")
    for hook, bad, words in ((view.show, "both", "the globe shows traffic or hosts, not 'both'"),
                             (view.direction, "sideways", "a direction is in, out or neither, not 'sideways'"),
                             (view.within, "year", "seen within hour, day, week or month, or any time, not 'year'"),
                             (view.pick, "host=1.2.3.4", "a pick is program=<name>, port=<tcp|udp>/<number> or clear"),
                             (view.pick, "port=icmp/1", "a pick is"), (view.pick, "port=tcp/70000", "a pick is"),
                             (view.pick, "program=a\nb", "a pick is"), (view.pick, None, "a pick is")):
        with pytest.raises(ValueError, match=words.replace("|", "\\|").replace("(", "\\(")):
            hook(bad)
    assert view.choice() == Choice("hosts")  # a refusal changes nothing


CENTRES = {"id": "osm-datacentres", "title": "Data centres", "format": "overpass",
           "url": "https://overpass.example/api/interpreter", "source": "OpenStreetMap, through the Overpass API",
           "licence_name": "ODbL 1.0", "licence": "OpenStreetMap's data is free under the Open Database License 1.0.",
           "credit": {"text": "© OpenStreetMap contributors", "url": "https://www.openstreetmap.example/copyright"},
           "size": 2_000_000, "wait": 190, "about": "about 5,000 sites",
           "query": '[out:json][timeout:180];(nwr["telecom"="data_center"];);out tags center qt;'}
ANSWER = json.dumps({"version": 0.6, "elements": [
    {"type": "node", "id": 1, "lat": 52.3033, "lon": 4.9394, "tags": {"telecom": "data_center", "name": "AMS1"}},
    {"type": "node", "id": 2, "lat": 50.1109, "lon": 8.6821,
     "tags": {"telecom": "internet_exchange", "name": "Example-IX"}}]})


def installed(dataset=CENTRES) -> Path:
    """A data set as its download keeps it, in the layers' folder (the suite's guard keeps that in tmp_path)."""
    folder = infrastructure.folder()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{dataset['id']}.json"
    path.write_text(json.dumps(pack(dataset, parse(dataset, ANSWER), NOW), separators=(",", ":")), encoding="ascii")
    return path


def test_the_traffic_view_gains_its_choice_right_under_the_globe_and_the_infrastructures_layers_and_table(tmp_path):
    installed()
    view = view_of(index=Index(datasets=[CENTRES]))
    globe = Globe(tmp_path)
    page = globe.page(can_install=False)
    page["watching"]["error"] = "Npcap is not installed"  # as where its capture cannot run
    page = plain(view.onto(page, globe))
    first = page["tables"][0]
    assert first["title"] == "What the globe shows" and first["rows"] == [["Show", "Traffic watched now"]]
    [show] = first["options"]
    assert (show["hook"], show["value"], [c["value"] for c in show["choices"]]) == (
        "world_show", "traffic", ["traffic", "hosts"])
    assert [t["title"] for t in page["tables"]] == ["What the globe shows", "Busiest ports here", "Places",
                                                    "Ports elsewhere", "Internet infrastructure"]
    g = page["globe"]
    assert g["layer_hook"] == "world_layer" and g["showing"] == "Traffic watched now" and "kinds" not in g
    assert g["layer_area"] is True  # 1.104.0: the hook reads a layer by area
    assert [(layer["id"], layer["count"]) for layer in g["layers"]] == [("exchanges", 1), ("datacentres", 1)]
    assert "sun" not in g  # no day and night in this version (B-revisions S9)
    infra = page["tables"][-1]
    assert infra["rows"][0][0] == {"text": "Data centres", "sub": "about 5,000 sites"}
    assert [f["id"] for f in page["forms"]] == ["world-layer-osm-datacentres", "world-layer-remove-osm-datacentres"]
    assert page["note"].endswith("Hosts recorded needs no capture: choose it under What the globe shows.")
    assert globe.rested == 0  # the traffic page let the file go itself


def test_the_hosts_view_draws_each_programs_hosts_by_place_filtered_as_chosen_with_no_traffic_page(tmp_path):
    clock = Clock()
    view = view_of(clock=clock)
    view.touch()
    clock.t += sockets.READ_S
    later = reading([*windows_rows(), sock(local=LAN, local_port=51020, remote=NOWHERE, remote_port=8443, pid=5000,
                                            program="updater.exe", path="", started=NOW - 1)], at=NOW + 3, awake=1003.0)
    view._reader = lambda: copy.deepcopy(later)
    view.touch()
    placing = Placing()
    globe = Globe(tmp_path, placing)
    view.show("hosts")
    page = plain(view.onto(None, globe))
    assert page["title"] == "World Wide Web" and "charts" not in page and "watching" not in page
    assert page["note"].startswith("The globe shows the hosts recorded (5 rows since ")
    assert "packets are not watched meanwhile" in page["note"] and "no address is sent anywhere" in page["note"]
    g = page["globe"]
    assert g["kinds"] == ["allowed", "outbound"] and g["showing"] == "Hosts recorded · all of them"
    places = {o["id"]: o for o in g["origins"]}
    london = places[f"{LONDON.lat},{LONDON.lon}"]
    assert (london["label"], london["kind"], london["hosts"], london["count"], london["bytes"]) == (
        "London, United Kingdom", "outbound", 2, 2, 0)
    assert sorted(london["programs"]) == ["?", "msedge.exe"] and london["ports"] == [443]
    assert places[f"{NUREMBERG.lat},{NUREMBERG.lon}"]["asn"] == 64500
    unplaced = places["not placed"]  # the file has no place for it: sent without a point, and counted
    assert (unplaced["lat"], unplaced["lon"], unplaced["hosts"]) == (None, None, 1)
    assert g["local"] == {"count": 1, "bytes": 0, "hosts": 1}  # the local network's, summed, never placed
    assert sorted(placing.asked) == sorted([WEB, WEB2, V6WEB, NOWHERE])  # looked up once each, the local one never
    assert globe.rested >= 1  # the GeoIP file let go again
    titles = [t["title"] for t in page["tables"]]
    assert titles == ["What the globe shows", "Programs", "Ports", "Hosts", "Internet infrastructure"]
    hosts_table = page["tables"][3]  # 1.105.0: each host picked is told in full, its facts matching its row
    assert len(hosts_table["details"]) == len(hosts_table["rows"]) > 0
    for row, said in zip(hosts_table["rows"], hosts_table["details"]):
        host = row[0]["text"] if isinstance(row[0], dict) else row[0]
        assert said["title"] == host and ["Program", row[1]] in said["facts"] and ["Place", row[2]] in said["facts"]
    first = page["tables"][0]
    assert [o["hook"] for o in first["options"]] == ["world_show", "world_direction", "world_within", "world_pick",
                                                     "world_pick"]
    programs = first["options"][3]
    assert programs["value"] == "program=" and programs["choices"][0] == {"value": "program=", "title": "Every program"}
    assert {c["value"] for c in programs["choices"]} >= {"program=msedge.exe", "program=?", "program=updater.exe"}
    ports = first["options"][4]
    assert ports["choices"][:2] == [{"value": "port=", "title": "Every port"},
                                    {"value": "port=tcp/443", "title": "443/tcp", "note": "3 hosts"}]
    assert first["actions"] == [{"hook": "world_pick", "args": ["clear"], "title": "Clear the filters"}]
    table = page["tables"][1]
    assert table["select"] == {"hook": "world_pick", "value": "program=", "title": "Show its hosts on the globe"}
    assert table["rows"][0]["key"] == "program=" and table["rows"][0]["cells"][1:3] == ["5", "5"]
    # a program picked: its hosts alone on the globe; the programs' table still counts every program
    view.pick("program=msedge.exe")
    picked = plain(view.onto(None, globe))
    assert {o["id"] for o in picked["globe"]["origins"]} == {f"{LONDON.lat},{LONDON.lon}",
                                                            f"{NUREMBERG.lat},{NUREMBERG.lon}"}
    assert picked["globe"]["showing"] == "Hosts recorded · msedge.exe" and picked["globe"]["local"]["hosts"] == 0
    every = picked["tables"][1]["rows"][0]
    assert every["key"] == "program=" and every["cells"][1:3] == ["5", "5"]  # under the other filters, not this one
    assert picked["tables"][1]["select"]["value"] == "program=msedge.exe"
    assert [r[1] for r in picked["tables"][3]["rows"]] == ["msedge.exe", "msedge.exe"]
    view.pick("clear")
    view.direction("in")
    inward = view.onto(None, globe)
    assert inward["globe"]["origins"] == [] and inward["globe"]["local"]["hosts"] == 1  # in: the printer's alone


def test_the_hosts_view_is_made_again_at_most_every_ten_seconds_unless_a_choice_changed(tmp_path, monkeypatch):
    clock = Clock()
    view = view_of(clock=clock)
    view.touch()
    view.show("hosts")
    globe = Globe(tmp_path, Placing())
    made = []
    places, sums = hostbook.HostBook.places, hostbook.HostBook.sums

    def counted(self, *args, **kwargs):
        made.append(kwargs.get("most"))
        return places(self, *args, **kwargs)

    def summed(self, **filters):
        made.append("sums")
        return sums(self, **filters)
    monkeypatch.setattr(hostbook.HostBook, "places", counted)
    monkeypatch.setattr(hostbook.HostBook, "sums", summed)
    view.onto(None, globe)
    view.onto(None, globe)
    assert made == [world.MAX_DRAWN]  # asked again at once: the same parts
    view.direction("out")  # a choice changed: made again now
    view.onto(None, globe)
    assert len(made) == 2
    clock.t += HOSTS_S - 1
    view.onto(None, globe)
    assert len(made) == 2
    clock.t += 1  # ten seconds, and nothing written since: still good
    view.onto(None, globe)
    assert len(made) == 2
    clock.t += sockets.READ_S
    view.touch()  # a reading written: the book changed
    view.onto(None, globe)
    assert len(made) == 2  # within ten seconds of the last look: the same parts, though the book changed
    clock.t += HOSTS_S
    view.onto(None, globe)
    assert len(made) == 3
    view.pick("program=msedge.exe")  # a program picked: its table's Every row is counted under the other filters too,
    view.onto(None, globe)  # by one plain query of the book's (its places are not asked for that)
    assert made[-2:] == [world.MAX_DRAWN, "sums"]
    every = view.onto(None, globe)["tables"][1]["rows"][0]
    assert every["key"] == "program=" and every["cells"][1:3] == ["3", "3"]  # every program's out, as places sums them


def test_the_geoip_file_is_opened_for_places_only_when_a_host_needs_one(tmp_path):
    clock = Clock()
    view = view_of(clock=clock)
    view.touch()
    view.show("hosts")
    placing = Placing()
    globe = Globe(tmp_path, placing)
    view.onto(None, globe)
    asked, opened = len(placing.asked), globe.opened
    assert asked == 3  # the internet's three hosts, once each
    clock.t += HOSTS_S
    view.pick("program=msedge.exe")
    view.onto(None, globe)
    assert len(placing.asked) == asked and globe.opened == opened + 1  # every host placed: opened for the frame alone
    clock.t += netstat.STAMP_S  # now and then a newer file is looked for, its hosts not asked again
    view.pick("program=")
    view.onto(None, globe)
    assert len(placing.asked) == asked
    newer = Placing(date="2026-12-01")  # a newer file: each host looked up again
    globe.placing = newer
    clock.t += netstat.STAMP_S
    view.direction("out")
    view.onto(None, globe)
    assert sorted(newer.asked) == sorted([WEB, WEB2, V6WEB])


def test_the_hosts_views_globe_note_reaches_the_globe_whole(tmp_path):
    """The globe cuts a spec's note past its own bound (liminal-globe.js reads it with text(s.note, ...)), and the hosts
    view's words come after the GeoIP file's and the home's: on a first start (no GeoIP file yet, its install offered,
    home not placed), with hosts on the internet not placed and one of the local network, the note fits in it whole."""
    js = (STATIC / "liminal-globe.js").read_text(encoding="utf-8")
    [bound] = re.findall(r"\bnote: text\(s\.note, (\w+)\)", js)
    most = int(bound) if bound.isdecimal() else int(re.search(rf"\bconst {bound} = (\d+);", js).group(1))
    fw = Webbed(tmp_path, placing=None)  # no GeoIP file installed yet
    fw.GEOIP_URL = "https://geoip.example/{year}-{month}.mmdb"  # the plugin names one, as both firewalls do
    fw.world()  # a first reading of the socket table, recorded
    fw.world_show("hosts")
    fw.world_view().stop()
    note = plain(fw.world())["globe"]["note"]
    assert note.startswith("This machine is placed once a GeoIP file is installed") and "Install the GeoIP file" in note
    assert note.endswith("3 hosts on the internet have no known point yet: the GeoIP file on this machine places them, "
                         "once it has one for them. 1 host of the local network, never placed.")
    assert len(note) > 400 and len(note) <= most
    fw.detach()


# -- the layers and their data sets ----------------------------------------------------------------------------------
class Panel:
    """A job's panel as the platform hands it: its lines, and whether the page asked to cancel it."""

    def __init__(self, cancelled: bool = False):
        self.lines, self.cancelled = [], cancelled

    def __call__(self, line: str) -> None:
        self.lines.append(line)


def test_a_layer_is_read_from_the_files_here_and_a_download_is_the_plugins_job_on_the_users_word(tmp_path):
    installed()
    asked = []

    def fetch(url, timeout, *, agent="", what=""):
        asked.append((url, agent, what))
        raise OSError("no network in a test")
    view = view_of(index=Index(datasets=[CENTRES]), fetch=fetch, agent="wall/0.7.0")
    layer = view.layer("datacentres")
    assert layer["id"] == "datacentres" and layer["parts"][0]["points"]["names"] == ["AMS1"]
    with pytest.raises(LookupError, match="no layer 'cables' is installed here"):
        view.layer("cables")
    with pytest.raises(ValueError, match="'osm-cables' is not one of this plugin's data sets: osm-datacentres"):
        view.get("osm-cables", True)
    with pytest.raises(LicenceRefused):
        view.get("osm-datacentres")  # its licence first, before anything is asked of anyone
    assert asked == []
    assert view.get("osm-datacentres", True, Panel(cancelled=True)) == {"said": "cancelled: nothing was installed",
                                                                        "ok": False}
    panel = Panel()
    with pytest.raises(infrastructure.InfrastructureError, match="could not be downloaded from overpass.example"):
        view.get("osm-datacentres", True, panel)
    assert asked == [(DataSet.of(CENTRES).address(), "wall/0.7.0", "a data set")]  # the plugin's name and version
    assert panel.lines and wait_for(lambda: threads() == [])
    assert view.drop("osm-datacentres")["said"] == "removed Data centres"
    assert view.drop("osm-datacentres")["said"] == "Data centres is not installed here"
    view.close()
    assert view.get("osm-datacentres", True, Panel()) == {"said": "cancelled: nothing was installed", "ok": False}


# -- the Firewall base's hooks ---------------------------------------------------------------------------------------
class Wall(FakeFirewall):
    """A stand-in firewall whose tabs read stand-ins: a socket table, a GeoIP file, no capture."""

    name = "wall"
    version = "0.7.0"

    def __init__(self, tmp_path: Path, source=None, placing=None, **more):
        super().__init__()
        self.tmp, self.source, self.placing, self.more = tmp_path, source, placing, more

    def make_netstat_view(self) -> NetstatView:
        made = super().make_netstat_view()  # the base's own: its index, its listeners, its agent
        view = view_of(self.source, login=None, index=made.index, listeners=self.netstat_listeners, agent=made.agent,
                       refused=made.refused, **self.more)
        view._login_of = lambda: getattr(self, "login", None)
        return view


class Webbed(WorldWideWeb):
    """1.105.0: the World Wide Web plugin over a Wall (its firewall, asked in this process as the platform would ask
    it): its globe a Globe, its routes traced by a stand-in, stepped by the test (no thread)."""

    name = "web"
    version = "0.7.0"
    title = "A stand-in World Wide Web plugin"
    about = "the globe over a stand-in firewall"
    api = "2.1"
    order = 960

    def __init__(self, tmp_path: Path, source=None, placing=None, **more):
        self.tmp, self.placing = tmp_path, placing
        self.wall = Wall(tmp_path, source, placing, **more)

    def present(self) -> bool:
        return True

    def firewall(self) -> str:
        return self.wall.name

    def firewalls(self) -> list[str]:
        return [self.wall.name]

    def _seen(self) -> dict:
        return self.wall.netstat_seen()

    def _ask(self, hook, *args):
        return getattr(self.wall, hook)(*args)

    def make_world_view(self) -> WorldView:
        return Globe(self.tmp, self.placing)

    def make_world_routes(self):  # 1.67.0: routes traced by a stand-in, stepped by the test (no thread)
        from liminal_libs import netpath
        from liminal_libs.machines.routes import Routes

        def tracer(address):
            return netpath.Trace(address, (netpath.Hop(1, ROUTER, 0.5), netpath.Hop(2, address, 9.0)), True, "stand-in")
        self.started = []
        return Routes(tracer=tracer, start=self.started.append, keep=self._keep_route, known=self._routed,
                      stored=self._stored_routes)

    def detach(self) -> None:
        super().detach()
        self.wall.detach()


class App:
    def __init__(self, once: bool = False):
        self.once = once


def test_the_firewall_tab_reads_the_socket_table_says_not_for_here_and_what_wsl_changes(tmp_path, monkeypatch):
    fw = Wall(tmp_path, placing=Placing())
    page = fw.ask("netstat")  # the platform asks it so, every three seconds while the tab is shown
    assert page["title"] == "Netstat" and len(page["flows"]["rows"]) == 6
    assert [t["title"] for t in page["tables"]] == ["Listening ports", "The hosts database", "Connections recorded"]
    under = {"title": "Under WSL", "columns": [{"title": "What"}], "rows": [["This Linux", "WSL 2: Ubuntu"]]}
    monkeypatch.setattr(sockets, "under_wsl", lambda: under)
    assert fw.netstat()["tables"][-1] == under
    fw.detach()
    away = Wall(tmp_path)
    away.not_for_here = lambda: "for a Windows machine"
    assert away.netstat() == {"title": "Netstat",
                              "note": "Not for this machine: for a Windows machine. Nothing is read here."}
    with pytest.raises(ValueError, match="not for this machine"):
        away.hosts_found("describe")
    assert away.netstat_view(make=False) is None


def test_on_a_machine_it_is_not_for_no_hook_records_keeps_forgets_or_removes_anything(tmp_path):
    """A plugin enabled but not for this machine is still asked by the platform (it refuses only a disabled one): each
    hook of the Netstat tab, the hosts database and the globe refuses in words before any view is made, so recording
    all the time never starts there, and this system's own hosts and layers, which the plugin for it keeps, stay."""
    installed()

    class Named(Webbed):
        INFRASTRUCTURE = (CENTRES,)
    here = Wall(tmp_path, placing=Placing())
    here.netstat()  # the plugin this machine is for records its hosts
    book = here.netstat_view().book
    assert book.describe()["rows"] == 4
    login = Keeping()
    away = Wall(tmp_path)
    away.not_for_here = lambda: "for a Windows machine"
    away.attach(App(), login)
    web = Named(tmp_path)  # 1.105.0: the globe's hooks are the World Wide Web plugin's
    web.not_for_here = lambda: "for a Windows machine"
    web.attach(App(), login)
    given = {"hosts_recording": ("always",), "hosts_forget": (True,)}
    globe = {"world_show": ("hosts",), "world_direction": ("out",), "world_within": ("day",),
             "world_pick": ("port=tcp/443",), "world_layer": ("datacentres",),
             "world_layer_get": ("osm-datacentres", True), "world_layer_remove": ("osm-datacentres",),
             "world_sky": (), "world_sky_get": (True,), "world_sky_remove": ()}  # 1.104.0
    assert set(given) == set(netstat.FIREWALL_HOOKS) - {netstat.HOOK}  # every hook of the module but the tab's page
    assert set(globe) == set(netstat.GLOBE_HOOKS)
    for plugin, hooks in ((away, given), (web, globe)):
        for hook, args in hooks.items():
            with pytest.raises(ValueError, match="^not for this machine: for a Windows machine$"):
                plugin.ask(hook, *args)
    assert away.netstat_view(make=False) is None and web.netstat_view(make=False) is None
    assert threads() == []  # nothing made, nothing runs
    assert login.saved == [] and login.reads == 0  # nothing kept through its login, nothing read
    assert book.describe()["rows"] == 4 and len(book.hosts()) == 4  # this system's hosts are not forgotten
    assert infrastructure.folder().joinpath("osm-datacentres.json").is_file()  # nor its layer removed
    assert away.netstat()["note"] == "Not for this machine: for a Windows machine. Nothing is read here."
    away.detach()
    web.detach()
    here.detach()


def test_the_world_tab_reads_for_the_hosts_and_shows_them_when_chosen_with_no_capture(tmp_path):
    fw = Webbed(tmp_path, placing=Placing())
    page = fw.world()  # the traffic view (the default): its capture is a stand-in
    titles = [t["title"] for t in page["tables"]]
    assert titles[0] == "What the globe shows" and titles[-4:] == ["Internet infrastructure", "Routes",
                                                                    "Routes, hop by hop", "Legs waiting for a line"]
    assert fw.wall.netstat_view().book.describe()["rows"] == 4  # recorded by the firewall while the tab is shown
    assert fw.world_show("hosts")["said"] == "Hosts recorded · all of them"
    fw.world_view().stop()
    hosts = plain(fw.world())
    assert hosts["globe"]["showing"] == "Hosts recorded · all of them" and not fw.world_view().running
    assert [t["title"] for t in hosts["tables"]] == ["What the globe shows", "Programs", "Ports", "Hosts",
                                                     "Internet infrastructure", "Routes",
                                                     "Routes, hop by hop", "Legs waiting for a line"]
    assert fw.world_pick("port=tcp/443")["said"] == "Hosts recorded · port 443/tcp"
    assert fw.world_direction("out")["ok"] and fw.world_within("week")["ok"]
    assert fw.world()["globe"]["showing"] == "Hosts recorded · port 443/tcp · out · seen in the last 7 days"
    fw.detach()


def test_attaching_follows_the_recording_setting_and_the_platforms_stop_and_a_detach_end_it(tmp_path):
    fw = Wall(tmp_path)
    fw.attach(App(), Keeping(LIMINAL_HOSTS_RECORDING="always"))
    view = fw.netstat_view(make=False)
    assert view is not None and view.recording() and threads() == ["wall-hosts"]
    fw.app_stopping()
    assert not view.recording()
    fw.app_stopping()  # twice: nothing to stop
    fw.settings_changed()  # the setting read anew: recording all the time again
    assert view.recording()
    fw.detach()
    assert view.closed and not view.recording() and fw.netstat_view(make=False) is None and threads() == []
    once = Wall(tmp_path)
    once.attach(App(once=True), Keeping(LIMINAL_HOSTS_RECORDING="always"))  # a one-shot app: never
    assert not once.netstat_view().recording()
    once.detach()
    quiet = Wall(tmp_path)
    quiet.attach(App(), Keeping())  # nothing set: shown, nothing runs
    assert not quiet.netstat_view().recording() and threads() == []
    assert quiet.hosts_recording("always")["ok"] and quiet.netstat_view().recording()
    quiet.detach()
    away = Wall(tmp_path)
    away.not_for_here = lambda: "for a Windows machine"
    away.attach(App(), Keeping(LIMINAL_HOSTS_RECORDING="always"))
    assert away.netstat_view(make=False) is None  # not for this machine: nothing made, nothing runs
    away.detach()


def test_a_firewalls_data_sets_make_its_index_and_those_that_do_not_read_are_said(tmp_path):
    installed()

    class Named(Webbed):
        INFRASTRUCTURE = (CENTRES, {"id": "broken", "title": "A data set"}, CENTRES)
    fw = Named(tmp_path)
    view = fw.netstat_view()
    assert [d.id for d in view.index.datasets] == ["osm-datacentres"] and view.agent == "web/0.7.0"
    # the User-Agent a download is made with: a product's name and version and nothing else
    assert netstat.agent_of("firewall-windows", "0.7.0") == "firewall-windows/0.7.0"
    assert (netstat.agent_of("firewall linux\n", ""), netstat.agent_of("", "1.0"), netstat.agent_of("-x", "1")) == (
        "firewalllinux", "", "")
    formats = infrastructure.FORMATS  # 1.104.0: the globe's formats after the first six
    assert formats[:6] == ("overpass", "sparql", "geojson", "gml", "ourairports", "geonames")
    assert view.refused == (f"the data set broken's format is {', '.join(formats[:-1])} or {formats[-1]}, not None",
                            "the data set osm-datacentres is named twice: its first is kept")
    infra = {t["title"]: t for t in fw.world()["tables"]}["Internet infrastructure"]  # the routes' table after it
    assert "Left out, not read as data sets: the data set broken's format" in infra["note"]
    assert fw.world_layer("datacentres")["parts"][0]["set"] == "osm-datacentres"
    assert fw.world_layer_remove("osm-datacentres")["ok"]
    with pytest.raises(LookupError):
        fw.world_layer("datacentres")
    assert internal.problems(fw) == []
    fw.detach()


def test_the_views_facts_ask_nothing():
    login = Keeping()
    view = view_of(login=login)
    facts = view.describe()
    assert (facts["reading"], facts["mode"], facts["recording"], facts["book"], facts["show"]) == (
        None, "shown", False, None, "traffic")
    assert login.reads == 0 and view.asked == []
    view.page()
    facts = view.describe()
    assert facts["reading"] == {"at": NOW, "rows": 10, "took": 0.004, "system": "windows"}
    assert facts["book"]["rows"] == 4 and facts["filters"] == {"program": None, "proto": "", "port": 0,
                                                              "direction": "", "within": ""}
    reads = login.reads
    view.describe()
    assert login.reads == reads and len(view.asked) == 1
    assert FakeFirewall().netstat_view(make=False) is None and isinstance(FakeFirewall(), Firewall)



def test_every_connection_to_the_internet_has_its_route_traced_while_the_tab_is_shown(tmp_path):
    """1.67.0 (the user, 2026-11-19: "trace all connections"): each ask of the World Wide Web tab hands the routes the
    remote addresses of the connections open to the internet, and only those; the routes' thread is started once, and
    nothing is traced but by it (here a stand-in, stepped by the test). Detached: the routes are closed."""
    fw = Webbed(tmp_path, placing=Placing())
    page = fw.world()
    routes = fw.world_routes()
    assert fw.started and len(fw.started) == 1  # the thread asked for once, not run here
    assert routes.describe()["waiting"] == 3 and routes.describe()["kept"] == 0  # WEB, WEB2, V6WEB; not the LAN
    # last but the legs waiting for a line (1.70.0): every table before them keeps its place
    assert [t["title"] for t in page["tables"]][-3:] == ["Routes", "Routes, hop by hop", "Legs waiting for a line"]
    while routes.step():
        pass
    assert routes.describe() == {"kept": 3, "waiting": 0, "tracing": "", "running": False, "traced": 3}
    again = fw.world()
    table = next(t for t in again["tables"] if t["title"] == "Routes")
    assert len(table["rows"]) == 3 and "3 of 3 traced, 0 waiting." in table["note"]
    assert len(fw.started) == 1  # nothing new to trace within the hour: no second thread asked for
    fw.app_stopping()  # stopped: these routes closed and let go; a platform started again traces anew
    assert routes.closed and fw.world_routes() is not routes and not fw.world_routes().closed
    fw.detach()



    assert routes.closed and routes.describe()["kept"] == 0



def test_the_netstat_tab_tables_every_connection_recorded_its_who_what_when_where_and_why(tmp_path):
    """1.68.0: each connection the hosts database recorded, its own row, the newest first, under the database's own
    table: when it began, how long it lasted, when it was gone, who, what, where and why."""
    fw = Wall(tmp_path, placing=Placing())
    page = fw.ask("netstat")
    recorded = page["tables"][-1]
    assert recorded["title"] == "Connections recorded"
    assert [c["title"] for c in recorded["columns"]] == ["Began", "Lasted", "Gone", "Who", "What", "Where", "Why"]
    rows = recorded["rows"]
    assert rows and all(len(r) == 7 for r in rows)
    out = next(r for r in rows if r[4]["text"].endswith(f"→ {WEB}:443"))
    assert out[2] == "open" and out[3]["text"] and "reached out to a host on the internet on 443/tcp" in out[6]
    assert "kept, the newest" in recorded["note"] and "Nothing in it is sent anywhere." in recorded["note"]
    database = page["tables"][1]
    assert any(r[0] == "Connections" and "at most, each its own row" in r[1] for r in database["rows"])
    fw.detach()


def test_the_routes_the_hosts_database_keeps_are_handed_to_the_tabs_routes(tmp_path):
    """1.74.1: the base's routes read the hosts database's routes back (HostBook.routes_of), here only; 1.105.0: the
    firewall's database, asked by the World Wide Web plugin."""
    fw = Webbed(tmp_path, placing=Placing())
    book = fw.wall.netstat_view().book
    book.keep_route("81.2.69.142", NOW, True, "icmp", [{"n": 1, "address": "81.2.69.142", "ms": 9.0}], "")
    book.flush()
    got = fw._stored_routes(["81.2.69.142"])
    assert got["81.2.69.142"][-1]["hops"] == [{"n": 1, "address": "81.2.69.142", "ms": 9.0}]
    routes = WorldWideWeb.make_world_routes(fw)
    try:
        assert routes._stored == fw._stored_routes and routes._known == fw._routed
    finally:
        routes.close()
    away = Webbed(tmp_path)
    away.not_for_here = lambda: "for a Windows machine"
    assert away._stored_routes(["81.2.69.142"]) == {}
    fw.detach()


def test_the_hosts_are_stamped_with_the_files_in_use_and_placed_again_once_they_change(tmp_path):
    """1.101.0 (Monday list item 20): the stamp is the WorldView's (geosources.stamp), and replaced() forgets the one
    kept, so a switch of source places the hosts again at the next ask rather than STAMP_S later."""
    class Sourced(Globe):
        mark = "#dbip:2026-11-01+ipinfo:2026-11-24"

        def stamp(self, geoip=None):
            return self.mark
    globe = Sourced(tmp_path, Placing())
    view = view_of()
    view.page(globe)
    assert view.book.stamp == Sourced.mark and view.book.unplaced(Sourced.mark) == 0
    globe.mark = "#dbip:2026-11-01+none"
    view.page(globe)
    assert view.book.unplaced("#dbip:2026-11-01+none") > 0  # the stamp kept: not looked at again so soon
    view.replaced()
    view.page(globe)
    assert view.book.stamp == "#dbip:2026-11-01+none" and view.book.unplaced("#dbip:2026-11-01+none") == 0
