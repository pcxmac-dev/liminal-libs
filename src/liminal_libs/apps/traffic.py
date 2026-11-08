"""What an app, its page, its plugins and its login say to each other, as it happens (the user, 2026-11-08: "the root
plugin (platform) will need to visually illustrate how plugins are connected to each other or to the main
app/plugin/icon via IPC, all requests and interactions should be classified and give the user a way to understand how
the app and it's plugins communicate, visually").

Every request of a page (or a program) to its app, every call of the app to a plugin (attached, detached, its status,
a hook by name, its setup), every setting read or kept through the login, and, once an app watches (`watch`), every
program started and every host reached by the app or one of its plugins: each one classified (CLASSES), timed, kept
(the latest few hundred, one row for the same thing said again and again) and counted per link (from, to, class). Never
a value: a setting is named, a hook's arguments are not kept, a program is named without its arguments, a host by its
name or address and port.

Who reached a program or a host is read off the calling code (an audit hook, `sys.addaudithook`): the innermost frame
whose `self` is a plugin the app owns, or whose module is a plugin's package, names it; the app's own code names the app;
anything else (the library alone, a test) is not recorded."""
from __future__ import annotations

import os
import re
import sys
import threading
import time
import weakref
from collections import OrderedDict
from collections.abc import Iterable
from contextlib import contextmanager

from .authorization import Login

KEEP = 400  # rows kept, the latest
LINKS = 300  # links counted (from, to, class); the one silent longest drops out first
SAME_S = 30.0  # the same interaction again within this long of its last time is the same row, counted
DEPTH = 80  # frames looked through for who called
CLASSES = {  # an interaction's class, in the order the page's legend lists them
    "read": "reads what the other side holds and changes nothing (a page's GET, a plugin's status)",
    "change": "asks for a change (a plugin on or off, its settings, a setup)",
    "ask": "a hook asked by name (a plugin's action, a form's)",
    "stream": "a stream read or written (a job's output, a terminal's keys and output)",
    "attach": "a plugin attached to its app, or detached",
    "login": "a setting read or kept through the login (by its name, never its value)",
    "process": "a program started (by its name, never its arguments)",
    "network": "a host reached (its name or address and port, never what was sent)",
}
APP_ICONS = {"charts": "disk", "integrator": "scroll", "login": "user", "platform": "chip"}
_NOT_OWNERS = ("liminal_libs", "builtins", "__main__", "threading", "concurrent", "asyncio")


def program_name(executable, argv) -> str:
    """A program's name alone (powershell, wsl, nslookup): never its folder, never its arguments."""
    prog = executable
    if not prog:
        if isinstance(argv, (str, bytes)):
            text = os.fsdecode(argv).strip()
            prog = text[1:].split('"', 1)[0] if text.startswith('"') else (text.split(None, 1) or [""])[0]
        elif isinstance(argv, (list, tuple)) and argv:
            prog = argv[0]
    try:
        prog = os.fsdecode(os.fspath(prog)) if prog else ""
    except TypeError:
        return ""
    name = re.split(r"[\\/]", prog.strip().strip('"'))[-1].lower()
    return (name[:-4] if name.endswith(".exe") else name)[:40]


def _port(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _loopback(host: str) -> bool:
    return host in ("::1", "localhost") or host.startswith("127.")


def node_of(end: str) -> dict:
    """What the page draws for one end of a link it has no better word for: the page, a program calling the app, a
    program started, a host reached, another app of the framework, else a plugin by its name."""
    kind, _, rest = end.partition(":")
    if end == "page":
        return {"id": end, "role": "caller", "title": "This page", "sub": "the app's own page in a browser", "icon": "eye"}
    if end == "client":
        return {"id": end, "role": "caller", "title": "Programs", "sub": "a client of the app's API (no browser)", "icon": "terminal"}
    if kind == "process" and rest:
        return {"id": end, "role": "outside", "kind": "process", "title": rest, "sub": "a program", "icon": "terminal"}
    if kind == "host" and rest:
        return {"id": end, "role": "outside", "kind": "host", "title": rest, "sub": "a host", "icon": "globe"}
    if kind == "app" and rest:
        return {"id": end, "role": "outside", "kind": "app", "title": rest, "sub": "a Liminal app on this machine",
                "icon": APP_ICONS.get(rest, "chip")}
    return {"id": end, "role": "plugin", "title": end, "icon": "plug"}


class Traffic:
    """The interactions of one app: the latest rows (the same thing said again within SAME_S one row, counted), a count
    per link (from, to, class), and who owns what code (`own`), for `watch`."""

    def __init__(self, keep: int = KEEP, links: int = LINKS, clock=time.time):
        self.clock = clock
        self.started = clock()
        self.me = ""  # whose traffic: the app's name (a call of its own to itself is not drawn)
        self.apps: dict[int, str] = {}  # this machine's ports of the framework's apps (watch): a link to one names it
        self.owners_by_id: dict[int, str] = {}
        self.owners_by_package: dict[str, str | None] = {}  # None: a package two plugins share (named by `self` only)
        self._kept: list = []  # the owners themselves, so an id stays theirs
        self._keep, self._max_links = keep, links
        self._rows: OrderedDict[int, dict] = OrderedDict()
        self._open: dict[tuple, int] = {}  # (from, to, class, what) -> the row it extends
        self._links: dict[tuple, dict] = {}
        self._seq = self._ids = 0
        self._lock = threading.Lock()

    # -- recording ---------------------------------------------------------------------------------------------------
    def record(self, source: str, target: str, kind: str, what: str = "", ms: float = 0.0, ok: bool = True) -> dict:
        """One interaction noted: a row of its own, or the same row counted once more when said again within SAME_S."""
        kind = kind if kind in CLASSES else "read"
        source, target, what = str(source), str(target), str(what)[:160]
        key, now, ms, ok = (source, target, kind, what), self.clock(), round(float(ms), 1), bool(ok)
        with self._lock:
            self._seq += 1
            rid = self._open.get(key)
            row = self._rows.get(rid) if rid is not None else None
            if row is not None and now - row["at"] <= SAME_S:
                row.update(at=now, seq=self._seq, times=row["times"] + 1, ms=ms, ok=ok, failed=row["failed"] + (not ok))
                self._rows.move_to_end(rid)
            else:
                self._ids += 1
                rid = self._ids
                row = {"id": rid, "seq": self._seq, "first": now, "at": now, "from": source, "to": target, "kind": kind,
                       "what": what, "times": 1, "ms": ms, "ok": ok, "failed": int(not ok)}
                self._rows[rid] = row
                self._open[key] = rid
                while len(self._rows) > self._keep:
                    old_id, old = self._rows.popitem(last=False)
                    old_key = (old["from"], old["to"], old["kind"], old["what"])
                    if self._open.get(old_key) == old_id:
                        del self._open[old_key]
            link = self._links.get(key[:3])
            if link is None:
                if len(self._links) >= self._max_links:
                    del self._links[min(self._links, key=lambda k: self._links[k]["last"])]
                link = self._links[key[:3]] = {"count": 0, "failed": 0, "ms": 0.0, "first": now, "last": now, "what": what}
            link["count"] += 1
            link["failed"] += not ok
            link["ms"] += ms
            link["last"], link["what"] = now, what
            return dict(row)

    @contextmanager
    def timed(self, source: str, target: str, kind: str, what: str = ""):
        """The block's call noted when it ends: how long it took, and whether it raised (it raises on)."""
        began, ok = time.perf_counter(), True
        try:
            yield
        except BaseException:
            ok = False
            raise
        finally:
            self.record(source, target, kind, what, (time.perf_counter() - began) * 1000, ok)

    # -- what the page reads -------------------------------------------------------------------------------------------
    def links(self) -> list[dict]:
        """Every link counted, the latest first: from, to, class, how many, how many failed, the mean time, the last."""
        with self._lock:
            items = [(k, dict(v)) for k, v in self._links.items()]
        items.sort(key=lambda kv: -kv[1]["last"])
        return [{"from": s, "to": t, "kind": k, "count": v["count"], "failed": v["failed"], "first": v["first"],
                 "last": v["last"], "what": v["what"], "ms": round(v["ms"] / v["count"], 1) if v["count"] else 0.0}
                for (s, t, k), v in items]

    def recent(self, last: int = 200) -> list[dict]:
        """The latest rows, the newest first."""
        with self._lock:
            rows = list(self._rows.values())[-max(0, last):] if last else []
            return [dict(r) for r in reversed(rows)]

    def snapshot(self, last: int = 200) -> dict:
        """What a page draws: the classes, the links counted, the latest rows, the time now and since when."""
        with self._lock:
            seq = self._seq
        return {"now": self.clock(), "since": self.started, "seq": seq, "classes": CLASSES, "links": self.links(),
                "recent": self.recent(last)}

    # -- who owns what code (for watch) -----------------------------------------------------------------------------
    def own(self, obj, name: str) -> None:
        """`obj` (a plugin, the app) is `name`'s: a program it starts or a host it reaches is noted as name's, and so is
        one started by its package's code (unless two plugins share that package)."""
        with self._lock:
            if id(obj) not in self.owners_by_id:
                self._kept.append(obj)
            self.owners_by_id[id(obj)] = name
            package = (type(obj).__module__ or "").partition(".")[0]
            if not package or package in _NOT_OWNERS or package.startswith(("test", "conftest", "_pytest")):
                return
            had = self.owners_by_package.get(package, name)
            self.owners_by_package[package] = name if had == name else None

    def actor(self, frame) -> str | None:
        """Who is calling, from `frame` outwards: the innermost frame whose `self` is owned, or whose module's package
        is; None when no owned code is calling."""
        return _claim(frame, (self,))[1]

    def watch(self, apps: dict[int, str] | None = None) -> None:
        """Programs started and hosts reached by owned code noted from now on (the audit hook, installed once in a
        process); `apps`: this machine's ports of the framework's apps, so a link to one is drawn as that app."""
        self.apps = dict(apps or {})
        _install(self)

    def unwatch(self) -> None:
        """Nothing more noted from outside (the app stopped serving)."""
        with _hook_lock:
            _watched.discard(self)

    def place(self, address, verb: str) -> tuple[str | None, str]:
        """Where a socket was pointed, as a link's end and what: another app of the framework on this machine, this
        machine, a host by the name looked up just before (else its address), with the port."""
        if isinstance(address, (str, bytes)):
            return "host:a local socket", verb
        if not isinstance(address, tuple) or len(address) < 2:
            return None, ""
        host, port = str(address[0]), _port(address[1])
        named = getattr(_names, "last", None)
        name = named[0] if named and named[0] and named[1] == port else host
        if _loopback(host) or _loopback(name):
            if port in self.apps:
                return f"app:{self.apps[port]}", f"{verb} :{port}"
            name = "this machine"
        return f"host:{name}", f"{verb} :{port}" if port is not None else verb


# -- the audit hook: one per process, for every Traffic watching ---------------------------------------------------------
_WANTED = frozenset({"subprocess.Popen", "os.system", "os.posix_spawn", "os.spawn", "os.exec", "socket.connect",
                     "socket.sendto", "socket.getaddrinfo"})
_watched: weakref.WeakSet = weakref.WeakSet()
_hooked = False
_hook_lock = threading.Lock()
_names = threading.local()  # the name this thread looked up last, with its port: the connect after it is named so
_inside = threading.local()  # the hook at work in this thread: nothing it does is noted again


def _install(traffic: Traffic) -> None:
    global _hooked
    with _hook_lock:
        if not _hooked:
            sys.addaudithook(_hook)
            _hooked = True
        _watched.add(traffic)


def _watching() -> tuple:
    with _hook_lock:
        return tuple(_watched)


def _claim(frame, traffics) -> tuple:
    """The Traffic and the owner the calling code names, from `frame` outwards: the innermost frame whose `self` one of
    them owns (else whose module's package one owns) wins, so of two apps in one process each names its own."""
    f, depth = frame, 0
    while f is not None and depth < DEPTH:
        code = f.f_code
        if code.co_argcount and code.co_varnames[:1] == ("self",):
            try:
                me = id(f.f_locals.get("self"))
            except Exception:  # noqa: BLE001 - a frame that cannot say
                me = None
            for t in traffics:
                who = t.owners_by_id.get(me)
                if who is not None:
                    return t, who
        package = (f.f_globals.get("__name__") or "").partition(".")[0]
        for t in traffics:
            who = t.owners_by_package.get(package)
            if who is not None:
                return t, who
        f, depth = f.f_back, depth + 1
    return None, None


def _hook(event: str, args: tuple) -> None:
    try:
        if event not in _WANTED:
            return
        if event == "socket.getaddrinfo":
            host = args[0].decode("ascii", "replace") if isinstance(args[0], bytes) else args[0]
            _names.last = (host, _port(args[1])) if isinstance(host, str) else None
            return
        if getattr(_inside, "on", False):
            return
        _inside.on = True
        try:
            _seen(event, args, sys._getframe(1))
        finally:
            _inside.on = False
    except Exception:  # noqa: BLE001 - never in the way of what was audited
        pass


def _program_of(event: str, args: tuple) -> str:
    """The program an audited start names (each event's own arguments: os.system has the command line alone)."""
    if event == "os.system":
        return program_name(None, args[0])
    if event == "os.spawn":  # (mode, path, args, env)
        return program_name(args[1], args[2])
    return program_name(args[0], args[1])  # subprocess.Popen, os.posix_spawn, os.exec: (executable or path, args, ...)


def _seen(event: str, args: tuple, frame) -> None:
    watching = _watching()
    if not watching:
        return
    traffic, who = _claim(frame, watching)
    if traffic is None:
        return
    if event in ("socket.connect", "socket.sendto"):
        target, what = traffic.place(args[1], "connect" if event == "socket.connect" else "send")
        kind = "network"
    else:
        name = _program_of(event, args)
        target, what, kind = (f"process:{name}" if name else None), "started", "process"
    if target is None or target == f"app:{who}":  # nothing said, or a call to itself
        return
    traffic.record(who, target, kind, what)


class RecordingLogin(Login):
    """The login as one plugin (or the app itself) is lent it: every call passed through, the reads and the saves
    noted as `name`'s (a setting by its name, never its value)."""

    def __init__(self, login: Login, name: str, traffic: Traffic, target: str = "login"):
        self.inner, self.name, self.traffic, self.target = login, name, traffic, target
        self.NAMESPACE = getattr(login, "NAMESPACE", "")

    def __getattr__(self, attr):  # anything else the login offers (its realization's own)
        if attr in ("inner", "name", "traffic", "target"):
            raise AttributeError(attr)
        return getattr(self.inner, attr)

    def user(self) -> dict:
        return self.inner.user()

    def vector(self, name: str) -> str:
        with self.traffic.timed(self.name, self.target, "login", f"read {name}"):
            return self.inner.vector(name)

    def names(self) -> set[str] | None:
        with self.traffic.timed(self.name, self.target, "login", "list the pairs"):
            return self.inner.names()

    def variables(self, wanted: Iterable[str]) -> dict[str, str]:
        wanted = [str(w) for w in wanted]
        if not wanted:
            return {}
        shown = ", ".join(wanted[:3]) + (f" and {len(wanted) - 3} more" if len(wanted) > 3 else "")
        with self.traffic.timed(self.name, self.target, "login", f"read {shown}"):
            return self.inner.variables(wanted)

    def may(self, plugin: str, action: str) -> bool:
        with self.traffic.timed(self.name, self.target, "login", f"may {plugin} {action}?"):
            return self.inner.may(plugin, action)

    def save(self, variable: str, value: str | None) -> str:
        with self.traffic.timed(self.name, self.target, "login", f"{'forget' if value is None else 'keep'} {variable}"):
            return self.inner.save(variable, value)

    @property
    def signed_in(self) -> bool:
        return self.inner.signed_in

    def describe(self) -> dict:
        return self.inner.describe()
