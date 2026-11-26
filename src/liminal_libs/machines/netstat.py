"""The firewalls' Netstat tab, the hosts database's recording and what the World Wide Web tab's globe gains from both
(the user, 2026-11-16: "the firewall app should have a 'netstat' like interface for looking at active ports and what
apps they are attached to, and the hosts that they connect to across the lan or wan. the firewall app should also have a
globe that can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they are
connected to *this *computer"; "the globe-firewall should allow filtering, so i can view apps connected to hosts all
across the globe, or ports talking to all hosts. The globe should have the same kind of geography associated with the
exchanges globe, but the firewall globe should instead of exchanges, have all the backbones,ibones, major internet
infrastructure, (as many as possible) datacenter locations").

A NetstatView is one firewall plugin's (machines/firewall.py makes it, `Firewall.netstat_view`):

- A reading (`touch`) is this machine's socket table (sockets.read: no capture, no administrator, no child process, no
  window, no name looked up, nothing sent anywhere), judged (sockets.judge: where each remote host is, which way, the
  service's port, its name in the system's own hosts file) and fed to the hosts database (hostbook.book: one HostBook
  for the file in this process) exactly once. A reading younger than sockets.READ_S is shared by every ask, and one
  reading at a time is taken in this process, read, judged and fed in one hold, so the book has them in their order.
- Recording, a setting kept through the login (hostbook.VARIABLE): "shown" (the default) reads only while this plugin's
  Netstat or World Wide Web tab is shown, at each of their asks, the file written and let go again after each: nothing
  runs and nothing is open once no tab asks. "always" reads all the time the platform runs, on a thread of its own
  (<name>-hosts) every hostbook.ALWAYS_S, writing every hostbook.FLUSH_S with the file kept open. That thread never
  starts in a one-shot app, on a machine the plugin is not for (the Firewall base asks) or on a folder of another
  system's drive; it stops, joined for JOIN_S at most and written, when the plugin is detached (`close`), when the
  platform stops (the base's app_stopping, `stop`), when the setting leaves always, and as the process exits.
- `page` is the Netstat tab's: the connections (each with its program, pid and service, the remote host and port,
  whether it is this machine's, the local network's or the internet's, its name or its GeoIP place, its state, since
  when and for how long where the system says), the listening ports, the hosts database and its two forms (Recording,
  Forget). What a row could not read is said in it.
- `onto` is what the World Wide Web tab's page gains: the globe's choice (the traffic watched now, or the hosts
  recorded, filtered by program, by port, by direction and by when they were last seen), the internet infrastructure's
  layers (machines/infrastructure.py) and their table. The hosts recorded are grouped by point in the database's own
  query (HostBook.places), made again at most every HOSTS_S unless a choice changed, and placed by the GeoIP file on
  this machine, which is asked for hosts only when one needs a place (the page's frame asks it at each ask, as the
  traffic view does, for the globe's home and whether one is installed, and lets it go after). No traffic page is
  made in that view.
- The filters are this view's, one for every page that shows the tab, kept until the plugin is detached; a pick also
  sets the globe to the hosts recorded. The data sets are downloaded only on the user's word, as a job (`get`).

Nothing here starts a process or opens a window; nothing runs while no tab asks unless the user chose always. Every
outside thing is a test's stand-in when given (the reader, the book, the index, the login, the hosts file's names)."""
from __future__ import annotations

import atexit
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime

from .. import geo, hostbook, ports, sockets, traffic
from . import infrastructure, world as world_module
from .infrastructure import Index

TAB = "netstat"  # the tab's id, in the page's address (#name/netstat)
TITLE = "Netstat"
HOOK = "netstat"  # the tab's read hook, asked with no arguments
EVERY = 3.0  # seconds between the tab's asks while it is shown
SETTING_S = 30.0  # the recording setting is read again through the login after this long
NAMES_S = 60.0  # the system's hosts file is read again after this long
FLOW_ROWS = 2000  # connections the tab is sent, the ones up first
LISTEN_ROWS = 200  # rows of the listening ports
TABLE_ROWS = 100  # rows of the hosts view's tables (programs, ports, hosts)
RECORDED_ROWS = 200  # connections the Netstat tab's "Connections recorded" shows, the newest first (1.68.0)
PICKS = 8  # programs and ports offered right under the globe, the ones with the most hosts
MOST = 1000  # programs and ports summed for the hosts view's tables, at most
HOSTS_S = 10.0  # the hosts view's places and tables are made again this often at most, unless a choice changed
STAMP_S = 3600.0  # while every host has its place, a newer GeoIP file is looked for this often at most
JOIN_S = 3.0  # the recording thread is waited for this long at most when it stops
RECORDING_FORM, FORGET_FORM = "hosts-recording", "hosts-forget"  # the forms' ids
RECORDING_HOOK, FORGET_HOOK = "hosts_recording", "hosts_forget"
SHOW_HOOK, DIRECTION_HOOK, WITHIN_HOOK, PICK_HOOK = "world_show", "world_direction", "world_within", "world_pick"
LAYER_HOOK, GET_HOOK, REMOVE_HOOK = infrastructure.LAYER_HOOK, infrastructure.GET_HOOK, infrastructure.REMOVE_HOOK
# the Firewall base's hooks of this module, in the order its HOOKS name them
HOOKS = (HOOK, RECORDING_HOOK, FORGET_HOOK, SHOW_HOOK, DIRECTION_HOOK, WITHIN_HOOK, PICK_HOOK, LAYER_HOOK, GET_HOOK,
         REMOVE_HOOK)
SHOWS = ("traffic", "hosts")  # what the globe shows
DIRECTIONS = ("", "out", "in")  # "": both
WITHIN = {"hour": 3600, "day": 86400, "week": 604800, "month": 2592000}  # a host last seen within it
WITHIN_WORDS = {"hour": "the last hour", "day": "the last 24 hours", "week": "the last 7 days",
                "month": "the last 30 days"}
MODE_WORDS = {"shown": "only while this plugin's Netstat or World Wide Web tab is shown",
              "always": "all the time the platform runs"}
NOT_LASTING = ("On this system the login keeps a setting only until the platform restarts: always is asked for again "
               "after a restart.")
INTERPRETER = ("A program run by an interpreter shows as the interpreter: Liminal's own four apps show as python.exe "
               "(python on Linux).")
NO_LOGIN = "the setting is kept through the platform's login, and this plugin has none: open it on the platform"
NOT_NAMED_WORDS = ("its program was not read: a connection that began and ended between two readings, or one another "
                   "user's program holds")
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
KINDS = ("allowed", "outbound")  # the globe's kinds the hosts recorded are drawn as: came in, went out
FLOW_COLUMNS = (("program", "Program"), ("dir", "Direction"), ("remote", "Remote host"), ("labels", "Where"),
                ("name", "Name or place"), ("proto", "Protocol"), ("local", "Here"), ("state", "State"),
                ("since", "Since"), ("duration", "Up for"), ("unread", "Not read"))

_READING = threading.Lock()  # one reading at a time in this process: read, judged and fed in one hold, so every view's
# readings reach a book in the order they were taken (a reading fed out of turn is set aside there)


def _word(value) -> str | None:
    """A choice as the page sends it, trimmed and lower case: None (and nothing) as "", anything not text as None."""
    if value is None:
        return ""
    return value.strip().lower() if isinstance(value, str) else None


def _when(epoch, now: float) -> str:
    """A moment in words, as this machine's clock says it: the time of day when it is today ("14:03:22"), else with its
    date ("14 Nov 14:03"; and its year when that is not this one). "" for none."""
    if epoch is None:
        return ""
    try:
        t, today = datetime.fromtimestamp(float(epoch)), datetime.fromtimestamp(float(now))
    except (OverflowError, OSError, TypeError, ValueError):
        return ""
    if t.date() == today.date():
        return f"{t:%H:%M:%S}"
    year = f" {t.year}" if t.year != today.year else ""
    return f"{t.day} {MONTHS[t.month - 1]}{year} {t:%H:%M}"


def _lasted(seconds) -> str:
    """A time connected in words: 45 s, 12 min, 3 h 12 min, 2 d 4 h."""
    try:
        s = max(0, int(float(seconds or 0)))
    except (OverflowError, TypeError, ValueError):
        return "–"
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        return f"{s // 3600} h {s % 3600 // 60} min"
    return f"{s // 86400:,} d {s % 86400 // 3600} h"


def _end(address: str, port: int) -> str:
    """An address and its port as one: 192.168.1.20:51000, [2606:4700::1111]:443."""
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def _program(row: Mapping) -> tuple[str, bool]:
    """A row's program in words (its name, its pid, its service), and whether it was read: where it was not, the row's
    own words for why."""
    name = str(row.get("program") or "")
    if not name:
        return str((row.get("unread") or {}).get("program") or "not named"), False
    pids = [p for p in row.get("pids") or () if p] or ([row["pid"]] if row.get("pid") else [])
    words = name + (f" (pid {pids[0]})" if len(pids) == 1 else f" (pid {pids[0]} and {len(pids) - 1} more)"
                    if pids else "")
    service, title = str(row.get("service") or ""), str(row.get("service_title") or "")
    if service:
        words += f" · {service}" + (f" ({title})" if title and title != service else "")
    return words, True


def _unread(row: Mapping, named: bool) -> str:
    """What a row could not read, in words, but the program's words already said in its Program cell."""
    said = row.get("unread") or {}
    return "; ".join(str(v) for k, v in said.items() if v and (named or k != "program"))


def agent_of(name: str, version: str) -> str:
    """A data set download's User-Agent for a plugin: its name and version and nothing else, as infrastructure.install
    takes one ("firewall-windows/0.7.0"; "" for the library's own when the name is none to say)."""
    def plain(text: str) -> str:
        return "".join(c for c in str(text or "") if c.isascii() and (c.isalnum() or c in "._+-"))[:40]
    name, version = plain(name), plain(version)
    if not name or not name[0].isalnum():
        return ""
    return f"{name}/{version}" if version else name


def _lasts(login) -> bool:
    """Whether a setting kept through `login` is there after the platform restarts: machines.ai.lasts where the library
    has it; else not through an EnvironmentLogin off Windows (it keeps a value in this process alone)."""
    system = "windows" if os.name == "nt" else "linux"
    try:
        from . import ai

        lasts = getattr(ai, "lasts", None)
    except ImportError:  # a library without the AI plugins' base
        lasts = None
    if callable(lasts):
        try:
            return bool(lasts(login, system))
        except Exception:  # noqa: BLE001 - a login that cannot say: kept, as any other login keeps what it is given
            return True
    try:
        kind = str((login.describe() or {}).get("kind") or "")
    except Exception:  # noqa: BLE001
        return True
    return kind != "EnvironmentLogin" or system == "windows"


@dataclass(frozen=True)
class Choice:
    """What the World Wide Web tab's globe shows: the traffic watched now, or the hosts recorded; and the hosts'
    filters, a program (None: every one), a port (0: every one) with its protocol, a direction ("": both) and how
    recently they were last seen ("": any time; one of WITHIN)."""

    show: str = "traffic"
    program: str | None = None
    proto: str = ""
    port: int = 0
    direction: str = ""
    within: str = ""


@dataclass(frozen=True)
class _Seen:
    """A reading as the view keeps it between readings: when it was taken (the view's clock), the reading's own facts
    without its rows (_without_rows: they are kept once, judged), its judged rows, why the last try failed, if it did,
    and how many rows the reading had."""

    at: float
    reading: dict | None
    rows: list
    error: str = ""
    count: int = 0


def _without_rows(reading) -> dict:
    """A reading's own facts, its rows left out (the view keeps them judged alone: a second copy of every row, up to
    sockets.MAX_ROWS of them, is not held between readings)."""
    return {k: v for k, v in reading.items() if k != "rows"} if isinstance(reading, Mapping) else {}


@dataclass
class _Made:
    """The hosts view's parts as last made: for which choice, when (the view's clock) and at which of the book's
    changes."""

    choice: Choice
    at: float
    changes: int
    origins: list
    local: dict
    more: dict
    notes: list
    note: str
    tables: list
    programs: list
    ports: list


_NOTHING = _Seen(0.0, None, [])


class NetstatView:
    """One firewall plugin's Netstat tab, its hosts database's recording and its World Wide Web tab's choice and layers.

    `name` is the plugin's. Each of these is a test's stand-in when given: `reader` (() -> a reading, as sockets.read
    answers; sockets.read when None, looked up when asked), `book` (a hostbook.HostBook; hostbook.book() when None, the
    one for the data folder's file), `index` (an infrastructure.Index of the plugin's data sets; one of none when None),
    `login_of` (() -> the plugin's login now, or None), `listeners` (() -> {(proto, port): program}: listeners another
    user holds, named by the plugin's own read), `app_ports` (() -> {app: port}: Liminal's own pages), `fetch` (a data
    set's download; world.fetch_url when None), `names` (() -> {address: name}; sockets.known_names when None). `agent`:
    the User-Agent of a download (the plugin's name and version). `refused`: the words of the plugin's data sets that
    could not be read. `clock` is monotonic (a test's own), `wall` the time of day. Thread-safe: the platform asks from
    a thread per request."""

    def __init__(self, name: str, *, reader=None, book=None, index=None, login_of=None, listeners=None, app_ports=None,
                 fetch=None, agent: str = "", names=None, refused=(), clock=time.monotonic, wall=time.time):
        self.name = str(name or "")
        self._reader, self._book, self._login_of = reader, book, login_of
        self.index = index if index is not None else Index()
        self._listeners, self._app_ports, self._fetch, self._names_of = listeners, app_ports, fetch, names
        self.agent = str(agent or "")
        self.refused = tuple(str(r) for r in refused or ())
        self.clock, self.wall = clock, wall
        self._lock = threading.RLock()
        self._seen: _Seen | None = None
        self._setting: tuple[float, str, str] | None = None  # (when read, the mode, words about the value read)
        self._names: tuple[float, dict] | None = None
        self._choice = Choice()
        self._made: _Made | None = None
        self._stamp: tuple[float, str] | None = None  # (when, the date of the GeoIP file last opened for places)
        self._thread: threading.Thread | None = None
        self._halt = threading.Event()
        self._exiting = False  # the atexit hook is registered
        self._once = False  # a one-shot app: the recording thread never starts
        self.closed = False  # close(): for good, the plugin detached
        self.error = ""  # the recording thread's last problem, until a reading works again

    # -- the book, the login, the names ----------------------------------------------------------------------------
    @property
    def book(self) -> hostbook.HostBook:
        """The hosts database: the one given, else this process's one for the data folder's file (looked up at first
        use, never made by the view itself)."""
        if self._book is None:
            with self._lock:
                if self._book is None:
                    self._book = hostbook.book()
        return self._book

    def elsewhere(self) -> str:
        """Why the hosts database is not kept from here ("" when it is): its folder is on another system's drive."""
        return hostbook.foreign(self.book.path)

    def _login(self):
        if not callable(self._login_of):
            return None
        try:
            return self._login_of()
        except Exception:  # noqa: BLE001 - a plugin that cannot say: no login
            return None

    def names(self) -> dict:
        """The names this system already knows for addresses (its hosts file: sockets.known_names), read again every
        NAMES_S at most; a test's own when given. Nothing is looked up."""
        given = self._names_of
        if given is not None:
            found = given() if callable(given) else given
            return dict(found) if isinstance(found, Mapping) else {}
        now = self.clock()
        with self._lock:
            kept = self._names
            if kept is not None and 0 <= now - kept[0] < NAMES_S:
                return kept[1]
        try:
            found = sockets.known_names()
        except Exception:  # noqa: BLE001 - a hosts file that cannot be read names nothing
            found = {}
        with self._lock:
            self._names = (now, found)
        return found

    # -- the recording setting --------------------------------------------------------------------------------------
    def mode(self) -> str:
        """When hosts are recorded, as the login says now (hostbook.VARIABLE, read every SETTING_S at most): "shown"
        (also with no login, nothing set, or a value that is neither word: said on the page) or "always"."""
        return self._mode()[0]

    def _mode(self) -> tuple[str, str]:
        now = self.clock()
        with self._lock:
            kept = self._setting
            if kept is not None and 0 <= now - kept[0] < SETTING_S:
                return kept[1], kept[2]
        mode, said, login = "shown", "", self._login()
        if login is not None:
            try:
                raw = (login.variables([hostbook.VARIABLE]) or {}).get(hostbook.VARIABLE)
            except Exception as e:  # noqa: BLE001 - a login that cannot say: shown, and said
                raw, said = None, f"The recording setting could not be read ({e}): shown is taken."
            word = str(raw).strip().lower() if raw is not None else ""
            if word in hostbook.MODES:
                mode = word
            elif word:
                said = (f"{hostbook.VARIABLE} is {world_module._shown(str(raw))}, neither shown nor always: shown is "
                        "taken.")
        with self._lock:
            self._setting = (now, mode, said)
        return mode, said

    def forget_setting(self) -> None:
        """The recording setting read anew at the next ask (the platform kept one of the plugin's settings)."""
        with self._lock:
            self._setting = None

    def set_mode(self, mode) -> dict:
        """Recording set to "shown" or "always" and kept through the plugin's login; the recording thread started or
        stopped as it says. ValueError, in words: neither word, a folder on another system's drive, no login, a login
        that keeps nothing."""
        word = _word(mode)
        if word not in hostbook.MODES:
            raise ValueError(f"recording is shown or always, not {world_module._shown(mode)}")
        elsewhere = self.elsewhere()
        if elsewhere:
            raise ValueError(elsewhere)
        login = self._login()
        if login is None:
            raise ValueError(NO_LOGIN)
        try:
            where = login.save(hostbook.VARIABLE, word)
        except Exception as e:  # noqa: BLE001 - a login that keeps nothing: its own words
            raise ValueError(f"the setting could not be kept: {e}") from None
        with self._lock:
            self._setting = (self.clock(), word, "")
        self.follow()
        lines = [f"kept in {where}"]
        if not _lasts(login):
            lines.append(NOT_LASTING)
        return {"said": f"recording {MODE_WORDS[word]}", "ok": True, "lines": lines}

    # -- recording all the time -------------------------------------------------------------------------------------
    def recording(self) -> bool:
        """Whether the recording thread runs (recording all the time)."""
        thread = self._thread
        return thread is not None and thread.is_alive()

    def follow(self, *, once: bool | None = None) -> None:
        """The recording thread started or stopped as the setting says now (`once`: whether the app is a one-shot one,
        kept from the attach: no thread then). Not after close(), nor on a folder of another system's drive."""
        if once is not None:
            self._once = bool(once)
        if self.closed:
            return
        if not self._once and self.mode() == "always" and not self.elsewhere():
            self._start()
        else:
            self.stop()

    def _start(self) -> None:
        with self._lock:
            if self.closed or self.recording():
                return
            halt = self._halt = threading.Event()
            thread = threading.Thread(target=self._run, args=(halt,), name=f"{self.name or 'firewall'}-hosts",
                                      daemon=True)
            self._thread = thread
            try:
                thread.start()
            except RuntimeError as e:  # no thread to read on: said, and tried again at the next follow
                self._thread = None
                self.error = f"Recording all the time could not start: {e}."
                return
            if not self._exiting:
                atexit.register(self._at_exit)
                self._exiting = True

    def _run(self, halt: threading.Event) -> None:
        """The recording thread: a reading every hostbook.ALWAYS_S, written every hostbook.FLUSH_S, the file kept
        open; it ends by itself once the setting leaves always, writing what is pending and letting the file go."""
        written = self.clock()
        try:
            while not halt.is_set():
                try:
                    if self.mode() != "always":
                        break
                    seen = self._take()
                    if self.clock() - written >= hostbook.FLUSH_S:
                        self.book.flush(keep_open=True)
                        written = self.clock()
                    self.error = f"The socket table could not be read: {seen.error}." if seen.error else ""
                except Exception as e:  # noqa: BLE001 - said on the page; tried again at the next round
                    self.error = f"Recording failed: {type(e).__name__}: {e}."
                halt.wait(hostbook.ALWAYS_S)
        finally:
            try:
                self.book.flush()
            except Exception:  # noqa: BLE001 - what could not be written is said by the book
                pass
            with self._lock:
                if self._thread is threading.current_thread():
                    self._thread = None

    def stop(self) -> None:
        """The recording thread ended (joined JOIN_S at most) and the book written and let go. It bears a second call,
        and starts nothing: the next follow() does, as the setting says (the platform's stop, the setting changed)."""
        with self._lock:
            thread, self._thread = self._thread, None
            self._halt.set()
            exiting, self._exiting = self._exiting, False
        if thread is not None and thread is not threading.current_thread():
            thread.join(JOIN_S)
        if exiting:
            atexit.unregister(self._at_exit)
        book = self._book
        if book is not None:
            try:
                book.flush()
            except Exception:  # noqa: BLE001 - said by the book's describe
                pass

    def _at_exit(self) -> None:
        """As the process exits: the thread told to stop, what is pending written."""
        self._halt.set()
        book = self._book
        if book is not None:
            try:
                book.flush()
            except Exception:  # noqa: BLE001
                pass

    def close(self) -> None:
        """Stopped for good (the plugin detached): the thread ended, the book written and let go, and no ask still under
        way reads again or starts the thread."""
        with self._lock:
            self.closed = True
        self.stop()

    # -- a reading ----------------------------------------------------------------------------------------------------
    def touch(self) -> dict:
        """A reading of the socket table no older than sockets.READ_S, judged and fed to the hosts database exactly
        once, and written: {"reading" (its own facts, its rows left out), "rows" (judged), "error" (why the last
        try failed, "")}. Every ask of the Netstat or the World Wide Web tab makes one, and the recording thread's
        rounds; they share it. The file is let go after it unless recording runs all the time."""
        seen = self._take()
        self._flush()
        return {"reading": seen.reading, "rows": seen.rows, "error": seen.error}

    def _take(self) -> _Seen:
        with _READING:
            now = self.clock()
            with self._lock:
                seen = self._seen
                if self.closed or (seen is not None and 0 <= now - seen.at < sockets.READ_S):
                    return seen or _NOTHING
            reader = self._reader if self._reader is not None else sockets.read
            try:
                reading = reader()
                rows = sockets.judge(reading, names=self.names())
            except Exception as e:  # noqa: BLE001 - a reading that failed: said, the last one kept, tried again later
                seen = _Seen(now, seen.reading if seen else None, seen.rows if seen else [],
                             f"{type(e).__name__}: {e}", seen.count if seen else 0)
            else:
                self._feed(reading, rows)
                seen = _Seen(now, _without_rows(reading), rows, count=len(reading.get("rows") or ()))
            with self._lock:
                self._seen = seen
            return seen

    def _feed(self, reading: dict, rows: list) -> None:
        if not reading.get("system"):  # no socket table is read on this system: nothing to keep
            return
        try:
            self.book.feed(rows, reading.get("at"), starts=bool(reading.get("starts")),
                           read=tuple(reading.get("read", sockets.TABLES) or ()), cut=bool(reading.get("cut")),
                           awake=reading.get("awake"))
        except Exception as e:  # noqa: BLE001 - the book says its own failures; this one is said on the page
            self.error = f"The reading could not be kept: {type(e).__name__}: {e}."

    def _flush(self) -> None:
        """What is pending written (a tab's ask): the file kept open while the recording thread runs, else let go."""
        try:
            self.book.flush(keep_open=self.recording())
        except Exception:  # noqa: BLE001 - said by the book's describe
            pass

    # -- the Netstat tab ----------------------------------------------------------------------------------------------
    def page(self, world=None) -> dict:
        """The Netstat tab's page (apps/tabs.py's shape): its note (the reading in numbers, the system's own words, how
        hosts are recorded), the connections as `flows` (filtered on the page), the listening ports, the hosts
        database and its forms. `world` is the plugin's WorldView: the internet's hosts are placed by its GeoIP file,
        which is let go again unless that tab watches (WorldView.rest)."""
        seen = self._take()
        self._flush()
        now = self.wall()
        rows = list(seen.rows)
        geoip = None
        try:
            if world is not None and not self.closed and any(r.get("where") == sockets.WHERE[2] for r in rows):
                geoip = world.geoip()
            flows = self._flows(rows, geoip, now)
            if geoip is not None:  # 1.68.0: the connections recorded with no place yet placed while it is open
                self._place(world, geoip)
        finally:
            if geoip is not None:
                world.rest()
        listening = self._listening(rows, now)
        facts = self._facts()
        return {"title": TITLE, "note": self._note(seen, rows, now), "flows": flows,
                "tables": [listening, self._database(facts, now), self._recorded(facts, now)],
                "forms": self._forms(facts, now)}

    def _recorded(self, facts: dict, now: float) -> dict:
        """1.68.0 (the user, 2026-11-20: "all connections need to be databased, basically who, what, when, why,where"):
        each connection the hosts database recorded, its own row, the newest RECORDED_ROWS: when it began, how long
        it lasted and when it was gone; who (the program, its service, its user, its process); what (the protocol,
        both ends, the host's name); where (the place and network the GeoIP file gives, and the route traced to the
        host); why (hostbook.why_of's words)."""
        title = "Connections recorded"
        columns = [{"title": "Began"}, {"title": "Lasted"}, {"title": "Gone"}, {"title": "Who"},
                   {"title": "What"}, {"title": "Where"}, {"title": "Why"}]
        if facts.get("elsewhere"):
            return {"title": title, "columns": columns, "rows": [], "empty": facts["elsewhere"]}
        out = []
        for c in self.book.connections(limit=RECORDED_ROWS):
            began = c.get("started") if c.get("started") is not None else c.get("first")
            who = [c.get("service_title") or c.get("service") or "", c.get("user") or "",
                   f"process {c['pid']}" if c.get("pid") else ""]
            place = ", ".join(x for x in (c.get("city"), c.get("country")) if x)
            if c.get("network") != hostbook.INTERNET:
                place = "the local network"
            owner = " ".join(x for x in (f"AS{c['asn']}" if c.get("asn") else "", c.get("org") or "") if x)
            route = c.get("route") or {}
            way = route.get("way") or ""
            out.append([_when(began, now), _lasted(c.get("seconds")),
                        "open" if c.get("ended") is None else _when(c["ended"], now),
                        {"text": c.get("program") or "", "sub": " · ".join(x for x in who if x)},
                        {"text": f"{c.get('proto', '')} {_end(c.get('local') or '', c.get('local_port') or 0)} "
                                 f"{'←' if c.get('direction') == 'in' else '→'} "
                                 f"{_end(c.get('remote') or '', c.get('remote_port') or 0)}",
                         "sub": c.get("name") or ""},
                        {"text": place or "not placed yet",
                         "sub": " · ".join(x for x in (owner, f"by way of {way}" if way else "") if x)},
                        c.get("why") or ""])
        held = facts.get("connections", 0)
        note = (f"Every connection the hosts database recorded is its own row, from the reading that first listed it "
                f"to the first one without it: {world_module._plural(held, 'connection')} kept, the newest "
                f"{len(out):,} here. Kept {hostbook.KEEP_DAYS} days after they end, {hostbook.CONNECTIONS:,} at "
                "most, the ones that ended longest ago let go first. A place is the GeoIP file's, looked up on this "
                "machine; a route is the one traced to the host while the World Wide Web tab was shown. Nothing in "
                "it is sent anywhere.")
        return {"title": title, "note": note, "empty": "No connection recorded yet.", "columns": columns,
                "rows": out}

    def _note(self, seen: _Seen, rows: list, now: float) -> str:
        reading = seen.reading or {}
        if not reading:
            head = f"This machine's socket table could not be read: {seen.error}." if seen.error else (
                "This machine's socket table is read while this tab is shown.")
        else:
            listening = {(r["proto"], r["local_port"]) for r in rows
                         if not r.get("remote") and r.get("state") in sockets.LISTENS}
            remote = [r for r in rows if r.get("remote")]
            hosts = {r["remote"]: r.get("where") for r in remote}
            where = [sum(1 for w in hosts.values() if w == kind) for kind in reversed(sockets.WHERE)]
            took = max(0.0, float(reading.get("took") or 0.0)) * 1000
            head = (f"This machine's socket table, read {_when(reading.get('at'), now)} in {took:,.0f} ms with no "
                    f"capture and no administrator asked: {world_module._plural(len(listening), 'listening port')}, "
                    f"{world_module._plural(len(remote), 'connection')} to {world_module._plural(len(hosts), 'host')} "
                    f"({where[0]:,} on the internet, {where[1]:,} on the local network, {where[2]:,} on this machine).")
            if seen.error:
                head += f" It could not be read again just now ({seen.error}): this is the last reading."
        said = [head, *[str(n) for n in reading.get("notes") or ()], INTERPRETER]
        mode, words = self._mode()
        said.append(f"Hosts are recorded {MODE_WORDS[mode]}" + (f" (a reading every {hostbook.ALWAYS_S:g} s)."
                                                                 if mode == "always" else "."))
        if words:
            said.append(words)
        login = self._login()
        if mode == "always" and login is not None and not _lasts(login):
            said.append(NOT_LASTING)
        if self.error:
            said.append(self.error)
        return " ".join(said)

    def _flows(self, rows: list, geoip, now: float) -> dict:
        placed: dict[str, object] = {}

        def place(address: str):
            if address not in placed:
                try:
                    placed[address] = geoip.lookup(address) if geoip is not None else None
                except Exception:  # noqa: BLE001 - a lookup that fails places nothing
                    placed[address] = None
            return placed[address]
        connections = [r for r in rows if r.get("remote")]
        connections.sort(key=lambda r: (r.get("state") not in sockets.UP, str(r.get("program") or "~").lower(),
                                        r["remote"], r.get("remote_port", 0), r.get("local_port", 0)))
        out = []
        for i, r in enumerate(connections[:FLOW_ROWS]):
            program, named = _program(r)
            where = r.get("where") or ""
            found = place(r["remote"]) if where == sockets.WHERE[2] else None
            label = getattr(found, "label", "") if found is not None else ""
            began = r.get("started")
            moment = began if began is not None else r.get("seen")
            out.append({"id": f"{i}:{r['proto']}{r.get('family', '')}:{_end(r['local'], r['local_port'])}:"
                              f"{_end(r['remote'], r['remote_port'])}:{r.get('pid') or r.get('inode') or 0}",
                        "time": moment, "since": _when(moment, now), "dir": r.get("direction") or "",
                        "proto": r["proto"], "local": _end(r["local"], r["local_port"]),
                        "remote": _end(r["remote"], r["remote_port"]), "name": r.get("name") or label,
                        "program": program, "labels": [{"kind": where}] if where else [], "state": r.get("state", ""),
                        "duration": max(0.0, now - began) if began is not None else None,
                        "unread": _unread(r, named)})
        # what a system lists or not (Windows no UDP remote host, Linux no start) is the reading's own notes, said once
        note = (f"A connection shorter than the gap between two readings ({EVERY:g} s while this tab is shown) can be "
                "missed. Up for is said where the system says when a connection began.")
        if len(connections) > len(out):
            note += f" The first {len(out):,} of {len(connections):,} are listed, the ones up first."
        return {"title": "Connections", "note": note,
                "empty": "No connection is open.", "columns": [{"key": k, "title": t} for k, t in FLOW_COLUMNS],
                "rows": out, "filters": {"dir": ["in", "out", "local"], "labels": list(reversed(sockets.WHERE))}}

    def _listening(self, rows: list, now: float) -> dict:
        try:
            pages = {int(p): str(app) for app, p in ((self._app_ports() if callable(self._app_ports) else {}) or
                                                     {}).items()}
        except Exception:  # noqa: BLE001 - no app's port known: none said
            pages = {}
        try:
            named = dict((self._listeners() if callable(self._listeners) else {}) or {})
        except Exception:  # noqa: BLE001 - the plugin's own read cannot say: nothing named by it
            named = {}
        groups: dict[tuple, dict] = {}
        for r in rows:
            if r.get("remote") or r.get("state") not in sockets.LISTENS:
                continue
            program, read = _program(r)
            sub = _unread(r, read) if read else ""  # what of it could not be read, under its name (as Not read says)
            if not read and named.get((r["proto"], r["local_port"])):
                program, sub = str(named[(r["proto"], r["local_port"])]), ("named by the firewall's own root read; its "
                                                                          "pid is not read")
            key = (r["local_port"], r["proto"], program)
            group = groups.setdefault(key, {"addresses": set(), "service": "", "since": None, "sub": sub})
            group["sub"] = group["sub"] or sub
            group["addresses"].add(r["local"])
            title = str(r.get("service_title") or "")
            if r.get("service"):
                group["service"] = str(r["service"]) + (f" ({title})" if title and title != r["service"] else "")
            moment = r.get("started") if r.get("started") is not None else r.get("seen")
            if moment is not None and (group["since"] is None or moment < group["since"]):
                group["since"] = moment
        out = []
        for (port, proto, program), g in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2]))[
                :LISTEN_ROWS]:
            app = pages.get(port) if proto == "tcp" else None
            out.append([{"text": str(port), "sub": f"Liminal's {app} page"} if app else str(port), proto,
                        ports.reach(g["addresses"]), {"text": program, "sub": g["sub"]} if g["sub"] else program,
                        g["service"], _when(g["since"], now)])
        note = ("Each protocol, port and program listening here: TCP listening, UDP bound (Windows lists every UDP "
                "socket so). Reached from: every address, or this machine only.")
        if len(groups) > LISTEN_ROWS:
            note += f" The first {LISTEN_ROWS:,} of {len(groups):,} are listed, by port."
        return {"title": "Listening ports", "note": note,
                "columns": [{"title": "Port", "num": True}, {"title": "Protocol"}, {"title": "Reached from"},
                            {"title": "Program"}, {"title": "Service"}, {"title": "Since"}],
                "rows": out, "empty": "Nothing listens here."}

    def _facts(self) -> dict:
        try:
            return self.book.describe()
        except Exception as e:  # noqa: BLE001 - a book that cannot say: said
            return {"path": "", "rows": 0, "hosts": 0, "programs": 0, "since": None, "last": None, "bytes": 0,
                    "cap": hostbook.CAP, "open": 0, "not_kept": 0, "cut": False, "elsewhere": "",
                    "problem": f"the hosts database could not be read: {e}"}

    def _database(self, facts: dict, now: float) -> dict:
        title = "The hosts database"
        columns = [{"title": "What"}, {"title": "Here"}]
        if facts.get("elsewhere"):
            return {"title": title, "columns": columns,
                    "rows": [["Recording", "not from here"], ["Why", facts["elsewhere"]]]}
        mode = self.mode()
        rows = [["Recording", MODE_WORDS[mode] + (f" (a reading every {hostbook.ALWAYS_S:g} s)" if mode == "always"
                                                  else "")],
                ["Kept in", facts.get("path", "")],
                ["Rows", f"{facts.get('rows', 0):,} of {facts.get('cap', hostbook.CAP):,} at most "
                         f"({world_module._plural(facts.get('hosts', 0), 'host')}, "
                         f"{world_module._plural(facts.get('programs', 0), 'program')})"],
                ["Since", _when(facts.get("since"), now) or "nothing recorded yet"],
                ["Last reading", _when(facts.get("last"), now) or "none yet"],
                ["Size", world_module.size_words(facts.get("bytes", 0))],
                ["Open now", world_module._plural(facts.get("open", 0), "connection")],
                ["Connections", f"{facts.get('connections', 0):,} of {hostbook.CONNECTIONS:,} at most, each its own "
                                f"row (kept {hostbook.KEEP_DAYS} days after it ends)"]]
        if facts.get("not_kept"):
            rows.append(["Not kept", f"{world_module._plural(facts['not_kept'], 'connection')} of the last reading, "
                                     f"past the {hostbook.MAX_OPEN:,} held open at once"])
        if facts.get("problem"):
            rows.append(["Problem", facts["problem"]])
        return {"title": title, "columns": columns, "rows": rows,
                "note": ("Each program's remote hosts, their ports, when they were first and last seen and how long "
                         "they were connected to this machine, in one file on this machine's own disk: "
                         f"{hostbook.CAP:,} rows at most (about 13 MB with ordinary values), the hosts longest unseen "
                         f"pruned first. A connection whose program was not read is kept under {hostbook.NOT_NAMED}. "
                         "Nothing in it is sent anywhere."),
                "actions": [{"form": RECORDING_FORM, "title": "Recording…"}, {"form": FORGET_FORM, "title": "Forget…"}]}

    def _forms(self, facts: dict, now: float) -> list[dict]:
        if facts.get("elsewhere"):
            return []
        path, mode = facts.get("path", ""), self.mode()
        recording = {
            "id": RECORDING_FORM, "hook": RECORDING_HOOK, "title": "Recording the hosts",
            "fields": [{"name": "mode", "label": "Recording", "type": "choice", "value": mode, "choices": [
                {"value": "shown", "title": "Only while this plugin's Netstat or World Wide Web tab is shown"},
                {"value": "always", "title": "All the time the platform runs",
                 "note": f"a reading every {hostbook.ALWAYS_S:g} s"}]}],
            "confirm": {"title": "Change when hosts are recorded?", "yes": "Change it", "words": (
                "Recording is set to {mode}. Always reads this machine's socket table every "
                f"{hostbook.ALWAYS_S:g} seconds for as long as the platform runs, with no page open too, and keeps "
                "each program's remote hosts, their ports, when they were seen and how long they were connected in "
                f"{path}, {hostbook.CAP:,} rows at most. Shown reads only while this plugin's Netstat or World Wide "
                "Web tab is shown. Either way nothing is captured, nothing is sent anywhere and no administrator is "
                "asked. The choice is kept through your login.")}}
        since = _when(facts.get("since"), now) or "the start"
        forget = {
            "id": FORGET_FORM, "hook": FORGET_HOOK, "title": "Forget the hosts recorded", "danger": True,
            "fields": [{"name": hostbook.ForgetRefused.accept, "type": "accept", "title": "Forget them all?",
                        "words": ("Nothing of them is left in the file, and they cannot be brought back. Recording "
                                  "goes on as it is set."),
                        "yes": "Forget them"}],
            "confirm": {"title": "Forget the hosts recorded?", "yes": "Forget…", "danger": True, "words": (
                f"Every row of the hosts database at {path} is removed: each program's hosts, their ports, when they "
                f"were seen and how long they were connected ({facts.get('rows', 0):,} rows since {since}). They "
                "cannot be brought back. Recording goes on as it is set. You are asked a second time.")}}
        return [recording, forget]

    def forget(self, accept_forget=False) -> dict:
        """Every row of the hosts database removed, on the user's word asked twice: hostbook.ForgetRefused (naming
        accept_forget, which the page asks as a second confirmation) unless `accept_forget` is exactly True. ValueError
        for a folder on another system's drive; OSError, in words, when the file cannot be emptied."""
        elsewhere = self.elsewhere()
        if elsewhere:
            raise ValueError(elsewhere)
        if accept_forget is not True:
            raise hostbook.ForgetRefused("the hosts recorded are forgotten only once you say so a second time")
        book = self.book
        removed = book.forget()
        with self._lock:
            self._made = None
        return {"said": f"forgot {world_module._plural(removed, 'row')} of the hosts database", "ok": True,
                "lines": [f"removed from {book.path}", f"recording goes on {MODE_WORDS[self.mode()]}"]}

    # -- the World Wide Web tab: what the globe shows -----------------------------------------------------------------
    def shows(self) -> str:
        """What the globe shows now: "traffic" (the default) or "hosts"."""
        with self._lock:
            return self._choice.show

    def choice(self) -> Choice:
        with self._lock:
            return self._choice

    def _choose(self, **changes) -> dict:
        with self._lock:
            self._choice = replace(self._choice, **changes)
            choice = self._choice
        return {"said": self._showing(choice), "ok": True}

    def show(self, what) -> dict:
        """The globe set to the traffic watched now ("traffic") or the hosts recorded ("hosts")."""
        word = _word(what)
        if word not in SHOWS:
            raise ValueError(f"the globe shows traffic or hosts, not {world_module._shown(what)}")
        return self._choose(show=word)

    def direction(self, value) -> dict:
        """The hosts recorded of one direction: "out", "in", or "" for both; the globe set to the hosts."""
        word = _word(value)
        if word not in DIRECTIONS:
            raise ValueError(f"a direction is in, out or neither, not {world_module._shown(value)}")
        return self._choose(show="hosts", direction=word)

    def within(self, value) -> dict:
        """The hosts last seen within the last hour, day, week or month, or "" for any time; the globe set to the
        hosts."""
        word = _word(value)
        if word is None or (word and word not in WITHIN):
            raise ValueError(f"seen within hour, day, week or month, or any time, not {world_module._shown(value)}")
        return self._choose(show="hosts", within=word)

    def pick(self, choice) -> dict:
        """A program's hosts (program=<name>; program= for every program), a port's (port=<tcp|udp>/<number>; port= for
        every port), or the filters cleared (clear); the globe set to the hosts."""
        text = choice.strip() if isinstance(choice, str) else None
        refused = ValueError("a pick is program=<name>, port=<tcp|udp>/<number> or clear, not "
                             f"{world_module._shown(choice)}")
        if text == "clear":
            return self._choose(show="hosts", program=None, proto="", port=0, direction="", within="")
        if text is not None and text.startswith("program="):
            name = text[len("program="):].strip()[:hostbook.TEXT]
            if any(ord(c) < 32 for c in name):
                raise refused
            return self._choose(show="hosts", program=name or None)
        if text is not None and text.startswith("port="):
            rest = text[len("port="):].strip().lower()
            if not rest:
                return self._choose(show="hosts", proto="", port=0)
            proto, _, number = rest.partition("/")
            if proto in ("tcp", "udp") and number.isdecimal() and 0 < int(number) < 65536:
                return self._choose(show="hosts", proto=proto, port=int(number))
        raise refused

    def _showing(self, c: Choice) -> str:
        """The globe's filter in words, over its map: "Hosts recorded · msedge.exe · port 443/tcp · out · seen in the
        last 24 hours"."""
        if c.show != "hosts":
            return "Traffic watched now"
        parts = ["Hosts recorded"]
        if c.program:
            parts.append(c.program)
        if c.port:
            parts.append(f"port {c.port}/{c.proto}")
        if c.direction:
            parts.append(c.direction)
        if c.within:
            parts.append(f"seen in {WITHIN_WORDS[c.within]}")
        return " · ".join(parts) if len(parts) > 1 else "Hosts recorded · all of them"

    def _filters(self, c: Choice, *, program: bool = True, port: bool = True) -> dict:
        """The book's query filters for a choice; without the program's or the port's (the tables' Every row)."""
        return {"program": c.program if program else None, "proto": c.proto if port else "",
                "port": c.port if port else 0, "direction": c.direction,
                "since": self.wall() - WITHIN[c.within] if c.within else None}

    # -- the World Wide Web tab's page --------------------------------------------------------------------------------
    def onto(self, page, world, **frame) -> dict:
        """The World Wide Web tab's page given what the globe shows, its layers and their table. `page`: the traffic
        page (WorldView.page) while the globe shows the traffic; None while it shows the hosts recorded, whose frame
        (its home, its places' attribution, the GeoIP file's install) is made here from `frame` (WorldView.page's own
        arguments) and `world` (the plugin's WorldView), with no traffic counted read for it."""
        c = self.choice()
        hosts = c.show == "hosts"
        try:
            if page is None:
                page = self._frame(world, **frame)
            globe = page.get("globe")
            if not isinstance(globe, dict):
                globe = page["globe"] = {}
            try:
                globe["layers"] = self.index.layers()
            except Exception:  # noqa: BLE001 - a folder that cannot be read: no layer drawn, its table says why
                globe["layers"] = []
            globe["layer_hook"] = LAYER_HOOK
            globe["showing"] = self._showing(c)
            forms = [f for f in page.get("forms") or () if isinstance(f, dict)]
            if hosts:
                made = self._hosts(c, world)
                globe.update(origins=made.origins, local=made.local, more=made.more, kinds=list(KINDS))
                globe["note"] = " ".join(x for x in (globe.get("note") or "", *made.notes) if x)
                page["note"] = made.note
                page.pop("charts", None)
                page.pop("watching", None)
                # 1.101.0: the GeoIP sources' table the frame kept, its buttons with it
                kept = [t for t in page.get("tables") or ()
                        if isinstance(t, dict) and t.get("title") == world_module.SOURCES_TITLE]
                tables = [self._first(c, made), *made.tables, *kept]
            else:
                tables = [self._first(c, None), *[t for t in page.get("tables") or () if isinstance(t, dict)]]
                if (page.get("watching") or {}).get("error"):
                    page["note"] = (str(page.get("note") or "") + " Hosts recorded needs no capture: choose it under "
                                    "What the globe shows.").strip()
            tables.append(self._infrastructure())
            if not hosts:  # 1.68.0: the connections recorded with no place yet placed (the hosts view places its own)
                self._place(world)
            try:
                forms += self.index.forms(can=True)
            except Exception:  # noqa: BLE001 - its table says why
                pass
            page["tables"] = tables
            if forms:
                page["forms"] = forms
            else:  # none to offer: no forms at all, as a page with nothing to install has none
                page.pop("forms", None)
            return page
        finally:
            if hosts and world is not None:
                world.rest()

    def _frame(self, world, *, home=None, public=None, attribution=None, can_install: bool = True, licence: str = "",
               source: str = "", asn_source: str = "", asn_licence: str = "", keys=None) -> dict:
        """The tab's page with no traffic in it, from the WorldView's own words: the globe's home (the user's place, or
        this network's public address placed), its places' attribution, the notes on the GeoIP file and its install
        offered where none is (an empty count of traffic stands in, so nothing counted is read or thrown away). With
        GeoIP sources (1.101.0), their table is the one table kept, its buttons shown from `keys` (the key names set in
        the asking person's login store, as WorldView.page)."""
        if world is None or getattr(world, "closed", False):
            return {"title": world_module.TITLE, "note": "Nothing is shown now: the plugin was detached.", "globe": {}}
        readable, unreadable = geo.available()
        geoip = world.geoip() if readable else None
        page = world._page(world.watcher.status(), traffic.TrafficBook().snapshot(), world.wall(), None, readable,
                           unreadable, geoip, home, public, attribution, can_install, licence, source,
                           asn_source=asn_source, asn_licence=asn_licence, keys=keys)  # 1.75.0: the ASN file's offer
        page["tables"] = [t for t in page.get("tables") or ()
                          if isinstance(t, dict) and t.get("title") == world_module.SOURCES_TITLE]
        return page

    def _first(self, c: Choice, made: _Made | None) -> dict:
        """The first table, right under the globe: what it shows, and the choices that set it (the hosts' filters and
        the programs and the ports with the most hosts, in the hosts view)."""
        show = {"title": "Show", "hook": SHOW_HOOK, "value": c.show, "choices": [
            {"value": "traffic", "title": "Traffic watched now",
             "note": "packets at this machine's adapter, while this tab is shown"},
            {"value": "hosts", "title": "Hosts recorded",
             "note": "each program's remote hosts, from the hosts database"}]}
        shown = "Hosts recorded" if c.show == "hosts" else "Traffic watched now"
        table = {"title": "What the globe shows", "columns": [{"title": "Filter"}, {"title": "Chosen"}],
                 "options": [show], "rows": [["Show", shown]]}
        if made is None:
            table["note"] = ("The traffic watched while this tab is shown, or each program's remote hosts as the hosts "
                             "database recorded them: choose Hosts recorded to filter them by program, port, direction "
                             "and when they were last seen.")
            return table
        table["rows"] += [["Program", c.program or "every program"],
                          ["Port", f"{c.port}/{c.proto}" if c.port else "every port"],
                          ["Direction", c.direction or "in and out"],
                          ["Seen", WITHIN_WORDS[c.within] if c.within else "any time"]]
        table["note"] = ("A program shows its hosts across the globe; a port, every host on it. The programs and the "
                         "ports with the most hosts are here; every one of them is in the tables below.")
        programs = [{"value": "program=", "title": "Every program"}]
        for p in made.programs[:PICKS]:
            programs.append({"value": f"program={p['program']}", "title": p["program"],
                             "note": world_module._plural(p["hosts"] or 0, "host")})
        if c.program and not any(x["value"] == f"program={c.program}" for x in programs):
            programs.append({"value": f"program={c.program}", "title": c.program, "note": "chosen"})
        portlist = [{"value": "port=", "title": "Every port"}]
        for p in made.ports[:PICKS]:
            portlist.append({"value": f"port={p['proto']}/{p['port']}", "title": f"{p['port']}/{p['proto']}",
                             "note": world_module._plural(p["hosts"] or 0, "host")})
        if c.port and not any(x["value"] == f"port={c.proto}/{c.port}" for x in portlist):
            portlist.append({"value": f"port={c.proto}/{c.port}", "title": f"{c.port}/{c.proto}", "note": "chosen"})
        table["options"] += [
            {"title": "Direction", "hook": DIRECTION_HOOK, "value": c.direction, "choices": [
                {"value": "", "title": "In and out"},
                {"value": "out", "title": "Out", "note": "connections this machine began"},
                {"value": "in", "title": "In", "note": "connections to a port this machine listens on"}]},
            {"title": "Seen", "hook": WITHIN_HOOK, "value": c.within, "choices": [
                {"value": "", "title": "Any time"},
                *({"value": k, "title": WITHIN_WORDS[k].capitalize()} for k in WITHIN)]},
            {"title": f"Programs (the {PICKS} with the most hosts)", "hook": PICK_HOOK,
             "value": f"program={c.program or ''}", "choices": programs},
            {"title": f"Ports (the {PICKS} with the most hosts)", "hook": PICK_HOOK,
             "value": f"port={c.proto}/{c.port}" if c.port else "port=", "choices": portlist}]
        table["actions"] = [{"hook": PICK_HOOK, "args": ["clear"], "title": "Clear the filters"}]
        return table

    def _infrastructure(self) -> dict:
        try:
            table = self.index.table(can=True)
        except Exception as e:  # noqa: BLE001 - a folder that cannot be read: said
            table = {"title": infrastructure.TITLE, "note": f"The data sets could not be read here: {e}.",
                     "columns": [{"title": "Data set"}], "rows": []}
        if self.refused:
            table["note"] = (str(table.get("note") or "") + " Left out, not read as data sets: "
                             + "; ".join(self.refused) + ".").strip()
        return table

    # -- the hosts recorded, on the globe and in its tables ---------------------------------------------------------
    def _hosts(self, c: Choice, world) -> _Made:
        now, book = self.clock(), self.book
        with self._lock:
            made = self._made
        if made is not None and made.choice == c and 0 <= now - made.at < HOSTS_S:
            return made
        if made is not None and made.choice == c and made.changes == book.changes and not c.within:
            with self._lock:
                made.at = now
            return made
        keep = self.recording()
        try:
            book.flush(keep_open=True)  # what is pending written, and the file held open for the queries that follow
            self._place(world)
            made = self._make(c, now, book)
        finally:
            if not keep:
                book.flush()  # and let go again
        with self._lock:
            self._made = made
        return made

    def replaced(self) -> None:
        """1.101.0: the GeoIP files in use changed (a use, an install, a removal, an expiry): the stamp kept is
        forgotten, so the hosts are placed again at the next ask, not up to STAMP_S later."""
        with self._lock:
            self._stamp = None

    def _place(self, world, geoip=None) -> None:
        """The internet's hosts with no place yet (or one from an older GeoIP file) looked up in the GeoIP file on this
        machine and kept: the file is opened only when a host needs a place, or STAMP_S after it was last looked at,
        for a newer one (the caller lets it go again)."""
        if world is None or self.closed or self.elsewhere():  # another system's database: nothing of it is placed
            return
        book, now = self.book, self.clock()
        with self._lock:
            stamp = self._stamp
        if stamp is not None and 0 <= now - stamp[0] < STAMP_S and not book.unplaced(stamp[1]):
            return
        geoip = geoip if geoip is not None else world.geoip()  # one the caller has open already
        if geoip is None:
            return
        stamped = getattr(world, "stamp", None)  # 1.101.0: the stamp of the files in use (geosources.stamp)
        try:
            date = str(stamped(geoip) if callable(stamped) else (geoip.describe() or {}).get("date") or "")
        except Exception:  # noqa: BLE001 - a file that cannot say its date: placed as of none
            date = ""
        with self._lock:
            self._stamp = (now, date)
        if book.unplaced(date):
            book.place(geoip.lookup, date)

    @staticmethod
    def _sums(drawn: list, rest: dict) -> dict:
        """Every host, connection and second of a places() answer: the places drawn, those over its most, the hosts
        not placed and the local network's."""
        out = {"hosts": 0, "connections": 0, "seconds": 0.0}
        for part in (*drawn, rest, rest.get("unplaced") or {}, rest.get("local") or {}):
            for key in out:
                out[key] += part.get(key) or 0
        return out

    def _make(self, c: Choice, now: float, book: hostbook.HostBook) -> _Made:
        drawn, rest = book.places(**self._filters(c), most=world_module.MAX_DRAWN)
        programs = book.programs(limit=MOST, **self._filters(c, program=False))
        portlist = book.ports(limit=MOST, **self._filters(c, port=False))
        hosts = book.hosts(**self._filters(c), limit=TABLE_ROWS * 4)
        facts = book.describe()
        every = self._sums(drawn, rest)  # the Every rows under the other filters: one plain query each, no places
        every_program = every if not c.program else book.sums(**self._filters(c, program=False))
        every_port = every if not c.port else book.sums(**self._filters(c, port=False))
        origins = []
        for p in drawn:
            origins.append({"id": f"{p['lat']},{p['lon']}", "lat": p["lat"], "lon": p["lon"],
                            "label": ", ".join(x for x in (p["city"], p["country"]) if x), "country": p["country"],
                            "code": p["code"], "city": p["city"], "asn": p["asn"], "org": p["org"],
                            "count": p["connections"], "bytes": 0,
                            "kind": KINDS[0] if p["direction"] == "in" else KINDS[1], "ports": list(p["ports"]),
                            "hosts": p["hosts"], "programs": list(p["programs"]), "seconds": p["seconds"]})
        unplaced = rest.get("unplaced") or {}
        notes = []
        if unplaced.get("hosts"):
            origins.append({"id": "not placed", "lat": None, "lon": None, "label": "", "country": "", "code": "",
                            "city": "", "asn": None, "org": "", "count": unplaced.get("connections") or 0, "bytes": 0,
                            "kind": KINDS[1], "ports": [], "hosts": unplaced["hosts"], "programs": [],
                            "seconds": unplaced.get("seconds") or 0.0})
            have = "has" if unplaced["hosts"] == 1 else "have"
            notes.append(f"{world_module._plural(unplaced['hosts'], 'host')} on the internet {have} no known point "
                         "yet: the GeoIP file on this machine places them, once it has one for them.")
        local = rest.get("local") or {}
        more = {"places": rest.get("places") or 0, "count": rest.get("connections") or 0,
                "hosts": rest.get("hosts") or 0, "seconds": rest.get("seconds") or 0.0, "bytes": 0}
        if more["places"]:
            notes.append(f"{world_module._plural(more['places'], 'more place')} not drawn "
                         f"({world_module._plural(more['count'], 'connection')}): the {world_module.MAX_DRAWN} with "
                         "the most connections are.")
        if local.get("hosts"):
            notes.append(f"{world_module._plural(local['hosts'], 'host')} of the local network, never placed.")
        mode = self.mode()
        note = (f"The globe shows the hosts recorded ({facts.get('rows', 0):,} rows since "
                f"{_when(facts.get('since'), self.wall()) or 'now'}; recorded {MODE_WORDS[mode]}): packets are not "
                "watched meanwhile. Places come from the GeoIP file on this machine, and no address is sent anywhere.")
        if facts.get("elsewhere"):
            note = f"No host is shown here. {facts['elsewhere']}. Each system's platform keeps its own."
        elif facts.get("problem"):
            note += f" {facts['problem']}"
        wall = self.wall()
        tables = [self._programs_table(c, programs, every_program, wall),
                  self._ports_table(c, portlist, every_port, wall), self._hosts_table(c, hosts, wall)]
        return _Made(choice=c, at=now, changes=book.changes, origins=origins,
                     local={"count": local.get("connections") or 0, "bytes": 0, "hosts": local.get("hosts") or 0},
                     more=more, notes=notes, note=note, tables=tables, programs=programs, ports=portlist)

    @staticmethod
    def _row(key: str, first, hosts, connections, seconds, last, wall: float) -> dict:
        return {"key": key, "cells": [first, f"{hosts or 0:,}", f"{connections or 0:,}", _lasted(seconds),
                                      _when(last, wall) or "–"]}

    def _programs_table(self, c: Choice, programs: list, every: dict, wall: float) -> dict:
        rows = [self._row("program=", {"text": "Every program", "sub": "under the other filters"}, every["hosts"],
                          every["connections"], every["seconds"], max((p["last"] or 0 for p in programs), default=None),
                          wall)]
        for p in programs[:TABLE_ROWS]:
            name = p["program"]
            sub = NOT_NAMED_WORDS if name == hostbook.NOT_NAMED else str(p.get("path") or "")
            rows.append(self._row(f"program={name}", {"text": name, "sub": sub} if sub else name, p["hosts"],
                                  p["connections"], p["seconds"], p["last"], wall))
        return {"title": "Programs", "note": ("Each program's remote hosts under the other filters, the most hosts "
                                              "first: choose one to show its hosts on the globe."
                                              + (f" The first {TABLE_ROWS} of {len(programs):,} are listed."
                                                 if len(programs) > TABLE_ROWS else "")),
                "columns": [{"title": "Program"}, {"title": "Hosts", "num": True},
                            {"title": "Connections", "num": True}, {"title": "Connected"}, {"title": "Last seen"}],
                "select": {"hook": PICK_HOOK, "value": f"program={c.program or ''}",
                           "title": "Show its hosts on the globe"},
                "rows": rows, "empty": "No program is recorded yet."}

    def _ports_table(self, c: Choice, portlist: list, every: dict, wall: float) -> dict:
        rows = [self._row("port=", {"text": "Every port", "sub": "under the other filters"}, every["hosts"],
                          every["connections"], every["seconds"], max((p["last"] or 0 for p in portlist), default=None),
                          wall)]
        for p in portlist[:TABLE_ROWS]:
            rows.append(self._row(f"port={p['proto']}/{p['port']}", f"{p['port']}/{p['proto']}", p["hosts"],
                                  p["connections"], p["seconds"], p["last"], wall))
        return {"title": "Ports", "note": ("The services' ports and the hosts on each under the other filters, the "
                                           "most hosts first: choose one to show every host on it on the globe."
                                           + (f" The first {TABLE_ROWS} of {len(portlist):,} are listed."
                                              if len(portlist) > TABLE_ROWS else "")),
                "columns": [{"title": "Port"}, {"title": "Hosts", "num": True}, {"title": "Connections", "num": True},
                            {"title": "Connected"}, {"title": "Last seen"}],
                "select": {"hook": PICK_HOOK, "value": f"port={c.proto}/{c.port}" if c.port else "port=",
                           "title": "Show its hosts on the globe"},
                "rows": rows, "empty": "No port is recorded yet."}

    @staticmethod
    def _hosts_table(c: Choice, hosts: list, wall: float) -> dict:
        merged: dict[tuple, dict] = {}
        for h in hosts:
            key = (h["host"], h["program"])
            m = merged.get(key)
            if m is None:
                if len(merged) >= TABLE_ROWS:
                    continue
                m = merged[key] = {**h, "ports": set(), "connections": 0, "seconds": 0.0}
            m["ports"].add((h["port"], h["proto"], h["direction"]))
            m["connections"] += h["connections"] or 0
            m["seconds"] += h["seconds"] or 0.0
            m["first"], m["last"] = min(m["first"], h["first"]), max(m["last"], h["last"])
        rows = []
        for m in merged.values():
            if m["network"] != hostbook.INTERNET:
                place = "local network"
            else:
                place = ", ".join(x for x in (m["city"], m["country"]) if x) or "not placed yet"
            ports_ = ", ".join(f"{port}/{proto}{' in' if d == 'in' else ''}" for port, proto, d in sorted(m["ports"]))
            rows.append([{"text": m["host"], "sub": m["name"]} if m["name"] else m["host"], m["program"], place, ports_,
                         f"{m['connections']:,}", _lasted(m["seconds"]), _when(m["first"], wall) or "–",
                         _when(m["last"], wall) or "–"])
        filtered = any((c.program, c.port, c.direction, c.within))
        empty = "No host recorded passes the filters." if filtered else "No host is recorded yet."
        return {"title": "Hosts", "note": ("The hosts recorded that pass the filters, the last seen first: each with "
                                           "the program that talked to it, its place, the ports and how long it was "
                                           f"connected. {TABLE_ROWS} at most."),
                "columns": [{"title": "Host"}, {"title": "Program"}, {"title": "Place"}, {"title": "Ports"},
                            {"title": "Connections", "num": True}, {"title": "Connected"}, {"title": "First seen"},
                            {"title": "Last seen"}],
                "rows": rows, "empty": empty}

    # -- the layers and their data sets -------------------------------------------------------------------------------
    def layer(self, layer_id) -> dict:
        """One infrastructure layer's geometry as the files on this machine hold it (Index.layer), for the globe;
        LookupError when no such layer is installed here."""
        return self.index.layer(layer_id)

    def get(self, dataset, accept_licence=False, log=None, accepted=None) -> dict:
        """A data set downloaded on the user's word (infrastructure.install, run by the platform as a job: `log` is its
        panel, and its `cancelled` stops it, as the plugin's detach does). ValueError for a data set that is none of
        the plugin's; world.LicenceRefused until its licence is accepted. `accepted` (1.101.0): asked once the
        download's refusals passed, before anything is fetched (infrastructure.install's)."""
        found = self.index.dataset(dataset)

        def cancelled() -> bool:
            try:
                return self.closed or bool(getattr(log, "cancelled", False))
            except Exception:  # noqa: BLE001 - a log that cannot say: not cancelled
                return self.closed
        return infrastructure.install(found, self.index.folder, accept_licence=accept_licence, fetch=self._fetch,
                                      log=log, cancel=cancelled, agent=self.agent, accepted=accepted)

    def drop(self, dataset) -> dict:
        """A data set's file removed (infrastructure.remove): the globe no longer draws it."""
        return infrastructure.remove(self.index.dataset(dataset), self.index.folder)

    # -- what asks nothing --------------------------------------------------------------------------------------------
    def describe(self) -> dict:
        """The view as it is now, asking nothing of the socket table, the login or the network (for the plugin's API
        card): the last reading ({at, rows, took, system}, or None), the recording ({mode} as last read, whether its
        thread runs), the hosts database (HostBook.describe, once the view used it), the data sets (Index.sets), what
        the globe shows and its filters."""
        with self._lock:
            seen, setting, c, book = self._seen, self._setting, self._choice, self._book
        reading = seen.reading if seen is not None else None
        try:
            sets = self.index.sets()
        except Exception:  # noqa: BLE001 - a folder that cannot be read: none
            sets = []
        return {"reading": None if not reading else {"at": reading.get("at"), "rows": seen.count,
                                                       "took": reading.get("took"), "system": reading.get("system")},
                "mode": setting[1] if setting else "shown", "recording": self.recording(),
                "book": book.describe() if book is not None else None, "sets": sets, "show": c.show,
                "filters": {"program": c.program, "proto": c.proto, "port": c.port, "direction": c.direction,
                            "within": c.within},
                "error": self.error or (seen.error if seen is not None else "")}
