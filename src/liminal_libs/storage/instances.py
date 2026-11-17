"""What a database instance is, what is kept of the ones the user adds, and the shares a helper keeps to (1.61.0).

The plain half of the database plugins (storage/databases.py says the whole of it): `Instance` and its parts (`Method`,
`Share`), the value a plugin's instances are kept in through its login (`Kept`, `Instances`), what a form's fields
must be (`clean_name`, `clean_holds`, `clean_who`; a `Refusal` otherwise), and `SharePolicy`, what the link's helper
lets another system's suite open. It imports nothing of the plugin contract: the helper (storage/link.py) loads this
module alone, and stays small.

What every kind of instance shares (a name, its variables, `Refusal`, `is_local`, `listening`, the value kept through
a login) is liminal_libs/instances.py's since 1.62.0, as plain as this module, and is imported back here under the
same names, the same objects: the model servers' instances (machines/modelserver.py) use it too."""
from __future__ import annotations

import json
import ntpath
import os
import re
import socket  # noqa: F401 - a test of the databases reaches the socket module through here
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping

from .. import instances as shared
from ..instances import (  # noqa: F401 - the same objects, importable from here as before 1.62.0
    HEARD_S, MAX_KEPT, MAX_TITLE, NAME, VERSION, Refusal, Store, _heard, clean_name, clean_title, credential_variables,
    is_local, now_iso, secret_variable, variable_of)

ENGINES = {"sqlite": "SQLite", "duckdb": "DuckDB", "mongodb": "MongoDB", "postgres": "PostgreSQL", "mariadb": "MariaDB"}
SUFFIXES = {"sqlite": (".db", ".sqlite", ".sqlite3"), "duckdb": (".duckdb",)}  # a file engine's files
PORTS = {"mongodb": 27017, "postgres": 5432, "mariadb": 3306}  # a server engine's usual port
HOLDS = {  # what an instance can hold -> its words on a page
    "main": "the main file (the watchlist, the ledgers, the requests)",
    "bars": "bars",
    "ticks": "trades",
    "history": "closed months of bars",
    "series": "series (the datasets')",
    "documents": "documents (releases, headlines, filings)",
}
ACCESS = ("read", "write")
NONE = "none"  # share(..., "none"): the share taken away
INSTANCES = "instances"  # the data folder's folder for the databases made here
OWN_FOLDERS = ("feeds", "history", "datasets", "gov", "login", "mongo", "logs", "sources", "cache")  # the app's own
WHO = re.compile(r"^[A-Za-z0-9_.-]{1,32}::[A-Za-z0-9_. -]{1,64}$")  # a suite as it is named on a database
DATABASE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")  # a server's database, a role
HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^\[?[0-9A-Fa-f:]{2,39}\]?$")
MAX_INSTANCES = 24  # kept by one plugin
MAX_SHARES = 12  # of one instance
POLICY_S = 5.0  # a helper reads the shares again after this long


@dataclass(frozen=True)
class Method:
    """A way an instance is reached: its name, its words on a page, and whether it is an address (a server's)."""

    name: str
    title: str
    about: str
    address: bool = False

    def as_dict(self) -> dict:
        return {"name": self.name, "title": self.title, "about": self.about, "address": self.address}


METHODS = {m.name: m for m in (
    Method("file", "File", "the file opened directly, on this machine's own disk"),
    Method("helper", "Helper", "a private pipe to a helper process on the system that holds the file: no port, nothing "
                               "listening"),
    Method("socket", "Socket", "a Unix socket, or a Windows named pipe, on this machine", address=True),
    Method("tcp", "TCP", "an address and a port; off this machine only with TLS and credentials", address=True),
)}


@dataclass(frozen=True)
class Made:
    """What a plugin's `make` made: a line for each thing, and, on a server, the role it made for Liminal there with
    what that role may do (its password is the plugin's to keep through the login: keep_credentials; never here)."""

    lines: tuple[str, ...] = ()
    role: str = ""
    grants: tuple[str, ...] = ()


@dataclass(frozen=True)
class Share:
    """Who else may attach to an instance: a suite by the name it has on a database (claims.instance()), reading only or
    writing too."""

    who: str
    access: str = "read"

    def as_dict(self) -> dict:
        return {"who": self.who, "access": self.access}


@dataclass(frozen=True)
class Instance:
    """One database of a plugin's engine with its own configuration (the module's docstring says each part)."""

    name: str
    title: str = ""
    engine: str = ""
    where: str = ""  # a path in the data folder (relative; a folder ends in /), a path elsewhere, or host / socket
    method: str = "file"
    holds: tuple[str, ...] = ()
    port: int | None = None  # tcp: the port, the instance's own
    database: str = ""  # a server's database
    tls: bool = False
    auth: bool = False  # signs in: its name and password kept through the login (credential_variables)
    remote: bool = False  # reached off this machine: set only when asked twice
    shared: tuple[Share, ...] = ()
    role: str = ""  # on a server: the role Liminal uses there
    grants: tuple[str, ...] = ()  # ... and what it may do
    builtin: bool = False  # the plugin's own: today's database, not removed
    made: bool = False  # made by the plugin (New database), not connected to
    at: str = ""  # when it was kept (ISO, UTC)
    note: str = ""

    @property
    def folder(self) -> bool:
        return self.where.endswith(("/", "\\")) or self.where in ("", ".")

    def kept(self) -> dict:
        """What is kept of it: what differs from an instance's defaults (a built-in is not kept: its shares are)."""
        out: dict = {"name": self.name, "where": self.where, "method": self.method}
        for key, value, default in (("title", self.title, ""), ("holds", list(self.holds), []), ("port", self.port, None),
                                    ("database", self.database, ""), ("tls", self.tls, False), ("auth", self.auth, False),
                                    ("remote", self.remote, False), ("role", self.role, ""), ("grants", list(self.grants), []),
                                    ("made", self.made, False), ("at", self.at, ""), ("note", self.note, "")):
            if value != default:
                out[key] = value
        if self.shared:
            out["shared"] = [s.as_dict() for s in self.shared]
        return out

    def as_dict(self) -> dict:
        """As a page reads it (its state is the plugin's to add: DatabasePlugin.status)."""
        method = METHODS.get(self.method)
        return {"name": self.name, "title": self.title or self.name, "engine": self.engine, "where": self.where,
                "method": self.method, "methodTitle": method.title if method else self.method,
                "holds": [{"name": h, "title": HOLDS.get(h, h)} for h in self.holds], "port": self.port,
                "database": self.database, "tls": self.tls, "auth": self.auth, "remote": self.remote,
                "shared": [s.as_dict() for s in self.shared], "role": self.role, "grants": list(self.grants),
                "builtin": self.builtin, "made": self.made, "at": self.at, "note": self.note}


def clean_holds(holds, allowed: Iterable[str]) -> tuple[str, ...]:
    """What an instance is to hold, as given (names, or their text comma separated), each one of `allowed`."""
    allowed = tuple(allowed)
    names = holds.replace(",", " ").split() if isinstance(holds, str) else [str(h) for h in (holds or ())]
    out = tuple(dict.fromkeys(n.strip().lower() for n in names if n.strip()))
    wrong = [n for n in out if n not in allowed]
    if wrong:
        raise Refusal(f"it cannot hold {', '.join(wrong)}: this engine's instances hold {', '.join(allowed) or 'nothing'}")
    return out


def clean_who(who) -> str:
    text = str(who or "").strip()
    if not WHO.match(text):
        raise Refusal("a suite is named as it is on a database, its system and its name there (linux::Ubuntu, "
                      f"windows::NEPTUNE): not {str(who or '')[:60]!r}")
    return text


def is_absolute(where: str) -> bool:
    """Whether a path is a whole one, as Windows or as Linux writes it (what is kept on one system is read on the
    other): C:\\data\\x.db, \\\\server\\share\\x.db, /srv/x.db."""
    return bool(ntpath.splitdrive(where)[0]) or where.startswith(("/", "\\"))


def listening(host: str, port: int, timeout: float = 0.3, fresh: bool = False) -> bool:
    """Whether something listens at host:port (liminal_libs.instances.listening says the whole of it), remembered in
    this module's own `_heard`: the shared one unless something put another in its place (a test of the databases)."""
    return shared.listening(host, port, timeout, fresh, heard=_heard)


# -- what is kept ------------------------------------------------------------------------------------------------------
def _shares(raw) -> tuple[Share, ...]:
    out: dict[str, Share] = {}
    for item in raw if isinstance(raw, list) else ():
        if not isinstance(item, dict):
            continue
        who, access = str(item.get("who") or "").strip(), str(item.get("access") or "read").strip().lower()
        if WHO.match(who) and access in ACCESS:
            out[who] = Share(who, access)
    return tuple(out.values())[:MAX_SHARES]


def _instance(raw, engine: str) -> Instance | None:
    """One kept instance read back; None for what is not one (a value changed by hand: left out, never an error)."""
    if not isinstance(raw, dict):
        return None
    name, where = str(raw.get("name") or ""), raw.get("where")
    method = str(raw.get("method") or "file")
    if not NAME.match(name) or not isinstance(where, str) or not where.strip() or method not in METHODS:
        return None
    port = raw.get("port")
    if isinstance(port, bool) or not (port is None or (isinstance(port, int) and 0 < port < 65536)):
        return None
    holds = tuple(h for h in raw.get("holds") or () if isinstance(h, str) and h in HOLDS) if isinstance(raw.get("holds"), list) else ()
    grants = tuple(str(g) for g in raw.get("grants") or ())[:16] if isinstance(raw.get("grants"), list) else ()
    text = lambda key, most: str(raw.get(key) or "")[:most]  # noqa: E731
    return Instance(name=name, title=text("title", MAX_TITLE), engine=engine, where=where.strip(), method=method, holds=holds,
                    port=port, database=text("database", 63), tls=raw.get("tls") is True, auth=raw.get("auth") is True,
                    remote=raw.get("remote") is True, shared=_shares(raw.get("shared")), role=text("role", 63),
                    grants=grants, made=raw.get("made") is True, at=text("at", 32), note=text("note", 200))


@dataclass
class Kept:
    """What the user added to a plugin's own instances: the instances made or connected to (by name), and what was set
    on a built-in one (its shares). `problem`: why the value kept could not be read, in words (then nothing is)."""

    instances: dict[str, Instance] = field(default_factory=dict)
    builtin: dict[str, tuple[Share, ...]] = field(default_factory=dict)
    problem: str = ""

    @classmethod
    def of(cls, text: str | None, engine: str = "") -> "Kept":
        if not text or not str(text).strip():
            return cls()
        try:
            raw = json.loads(text)
        except (TypeError, ValueError) as e:
            return cls(problem=f"what is kept of the instances is not readable ({e}): none is shown until it is set again")
        if not isinstance(raw, dict):
            return cls(problem="what is kept of the instances is not a list of them: none is shown until it is set again")
        out = cls()
        for item in raw.get("instances") or () if isinstance(raw.get("instances"), list) else ():
            inst = _instance(item, engine)
            if inst is not None and inst.name not in out.instances and len(out.instances) < MAX_INSTANCES:
                out.instances[inst.name] = inst
        own = raw.get("builtin")
        for name, value in (own.items() if isinstance(own, dict) else ()):
            shares = _shares(value.get("shared") if isinstance(value, dict) else None)
            if isinstance(name, str) and NAME.match(name) and shares:
                out.builtin[name] = shares
        return out

    def text(self) -> str | None:
        """The value to keep; None when there is nothing to keep (the variable is then forgotten)."""
        if not self.instances and not self.builtin:
            return None
        out: dict = {"v": VERSION}
        if self.instances:
            out["instances"] = [i.kept() for i in self.instances.values()]
        if self.builtin:
            out["builtin"] = {n: {"shared": [s.as_dict() for s in shares]} for n, shares in self.builtin.items()}
        return json.dumps(out, separators=(",", ":"), ensure_ascii=True)


class Instances(Store):
    """A plugin's kept instances, read and kept through its login under `variable` (`login_of`: the plugin's login now,
    None when it has none: then nothing is kept). `saved`: given only where the data folder is another system's (the
    suite inside WSL on Windows' data): what is kept is then that system's, asked of it (its user's saved variables,
    through the link) and never of this one's login, which keeps none of it. The value's text is read as every
    Store's is (liminal_libs.instances.Store.text)."""

    def __init__(self, variable: str, login_of: Callable[[], object], engine: str = "",
                 saved: Callable[[], Mapping[str, str]] | None = None):
        super().__init__(variable, login_of, saved)
        self.engine = engine

    def read(self) -> Kept:
        try:
            return Kept.of(self.text(), self.engine)
        except Exception as e:  # noqa: BLE001 - a login that cannot say: the plugin's own instances alone, said
            return Kept(problem=f"what is kept of the instances could not be read: {e}")

    def current(self) -> Kept:
        """What is kept, to change: a value that cannot be read is started again by the change."""
        kept = self.read()
        return Kept() if kept.problem else kept

    def keep(self, kept: Kept) -> str:
        """`kept` kept through the login; where, in words."""
        login = self._login_of()
        if login is None:
            raise Refusal("instances are kept through the integrator's login, and this plugin has none: open it on the "
                          "integrator's page")
        text = kept.text()
        if text is not None and len(text) > MAX_KEPT:
            raise Refusal(f"too much to keep ({len(kept.instances)} instances and their shares): forget one first")
        return login.save(self.variable, text)


# -- the shares a helper keeps to (storage/link.py) ---------------------------------------------------------------------
SQLITE = "sqlite"  # the engine the link's helper opens: its plugin's name, and so its variable (SQLITE_INSTANCES)
DATA = "data"  # the SQLite plugin's own instance: the data folder, with every file of the app's in it


class SharePolicy:
    """What a helper lets another system's suite open: the SQLite plugin's instances as they are kept on this system
    (the user's own settings here), read again every POLICY_S.

    A file belongs to the instance whose place holds it, the nearest one: an instance the user added (a file), else the
    data folder's own (DATA). With no share set on that instance the suite is let in as before (reading and writing):
    nothing changes until the user sets one. With shares set, the suite named reads, or reads and writes, as its share
    says, and any other is refused; one that does not say who it is (a library from before 1.61.0) is refused too."""

    def __init__(self, read: Callable[[], str], data_dir: Path, clock: Callable[[], float] = time.monotonic):
        self._read, self.data_dir, self._clock = read, Path(data_dir), clock
        self._kept: Kept | None = None
        self._at = 0.0

    def kept(self) -> Kept:
        now = self._clock()
        if self._kept is None or now - self._at >= POLICY_S:
            try:
                self._kept = Kept.of(self._read(), SQLITE)
            except Exception:  # noqa: BLE001 - settings that cannot be read: as with none set
                self._kept = Kept()
            self._at = now
        return self._kept

    def _places(self) -> list[tuple[Path, str, tuple[Share, ...]]]:
        kept = self.kept()
        out = []
        for inst in kept.instances.values():
            if inst.method != "file" or inst.folder:
                continue
            path = Path(inst.where) if is_absolute(inst.where) else self.data_dir / inst.where
            try:
                out.append((path.resolve(), inst.name, inst.shared))
            except (OSError, ValueError):
                continue
        return out

    def roots(self) -> list[Path]:
        """The folders of the instances shared with another suite that lie outside the data folder: what the helper may
        open besides its own folders (an instance not shared is never opened for another system)."""
        base = self.data_dir.resolve()
        return list(dict.fromkeys(p.parent for p, _, shares in self._places()
                                  if shares and base != p.parent and base not in p.parents))

    def access(self, path: str, who: str) -> tuple[str, str]:
        """What `who` may do with the file at `path`: ("write" | "read" | "", why in words when it is less than write)."""
        try:
            p = Path(path).resolve()
        except (OSError, ValueError):
            return "", f"{path} is no path here"
        name, shares = DATA, self.kept().builtin.get(DATA, ())
        for place, instance, its in self._places():
            if p == place or p.name.startswith(place.name + "-") and p.parent == place.parent:  # (its -wal, -shm)
                name, shares = instance, its
                break
        else:
            base = self.data_dir.resolve()
            if not (p == base or base in p.parents):
                return "write", ""  # the helper's other folders (the ledger's): as they were
        if not shares:
            return "write", ""
        if not who:
            return "", (f"{name} is shared by name, and the process asking does not say who it is (a library from before "
                        "1.61.0): bring it up to date")
        for share in shares:
            if share.who == who:
                return share.access, ("" if share.access == "write" else f"{name} is shared with {who} for reading only")
        return "", f"{name} is not shared with {who} ({', '.join(s.who for s in shares)} may attach)"


def saved_policy(data_dir: Path) -> SharePolicy:
    """The policy of this system's own helper: the SQLite plugin's instances as the user's saved variables keep them."""
    variable = variable_of(SQLITE)

    def read() -> str:
        from ..config import UserEnvironment

        return UserEnvironment(names=(variable,)).saved().get(variable, "") or os.environ.get(variable, "")

    return SharePolicy(read, data_dir)
