"""A database plugin for each engine, each holding its instances (plugin API 2.3, liminal-libs 1.61.0).

The user, 2026-11-15: "for the integrator i need plugins for each type of database and in each plugin can setup either
new databases or connections to existing databases using many different types of IP or IPC methods. each instance in
the plugin has it's own configuration how it's shared, ports, permissions etc"; "make sure to include integrator plugins
for postgres and mariadb" "alongside existing used databases".

A database plugin (`DatabasePlugin`, the integrator's fifth kind of plugin: `DATABASE` in its module) is one engine's:
SQLite's, DuckDB's, MongoDB's, PostgreSQL's, MariaDB's. It holds **instances** (`Instance`). An instance is a database
the plugin made, or a connection to one that exists, and each has its own configuration:

  - what it holds (`holds`, HOLDS): the main file, bars, trades, the closed months, series, documents;
  - where it is (`where`): a path in the data folder, a path elsewhere, or a server's address;
  - how it is reached (`method`, METHODS): `file`, the file opened directly on this machine's own disk; `helper`, a
    private pipe to a helper process on the system that holds the file, no port (storage/link.py); `socket`, a Unix
    socket or a Windows named pipe; `tcp`, an address and a port, its own (`port`), off this machine only with TLS
    and credentials and only when asked twice (`Refusal.accept`);
  - who else may attach (`shared`: a Share for each suite, by the name it has on a database, claims.instance():
    windows::NEPTUNE, linux::Ubuntu), reading only or writing too;
  - on a server, the role Liminal uses there and its grants (`role`, `grants`), and whether it signs in (`auth`): its
    name and password are pairs kept through the login (`credential_variables`), never in a file, never shown.

With nothing set, nothing changes: a plugin's own instances (`builtin`) are today's databases, opened as today (the
data folder's SQLite files, a feed's closed months in DuckDB, the MongoDB server here at its port), and what the user
adds is kept through the plugin's login as one value under the plugin's variable (`variable_of`: SQLITE_INSTANCES),
never in a file of this software's. A change is made by the system that holds the data folder alone (mounts.owner_only):
another system's suite (the one inside WSL) reads what is kept there and changes nothing of it.

What a plugin answers (its hooks): `builtin` (its own instances), `open` (a connection to one: the one way the storage
code is to open a database of its engine), `probe` (one opened for reading and asked what it is), `make` (a new
database made) and `own_port` (the port of one of its own instances changed). What an app asks of it goes through the
templates here, the same for every engine: `instances`, `instance`, `state`, `test`, `new_database`, `connect_to`,
`share`, `set_port`, `forget`, `set_credentials`, `status`.

A share is kept only where something keeps to it. For SQLite that is the helper (storage/link.py): a suite on
another system reaches the files through it, says who it is, and is let in as its share says (`SharePolicy`); with no
share set on an instance, whoever can start a helper on this system may read and write it, as before 1.61.0.
"""
from __future__ import annotations

import os
import posixpath
import secrets
import time
from dataclasses import replace
from pathlib import Path
from typing import Mapping

from .. import layout, mounts
from ..sources.plugin import IntegratorPlugin
from .instances import (ACCESS, DATA, DATABASE, ENGINES, HOLDS, HOST, INSTANCES, MAX_INSTANCES, MAX_KEPT,  # noqa: F401 - plugins import them from here
                        MAX_SHARES, MAX_TITLE, METHODS, NAME, NONE, OWN_FOLDERS, POLICY_S, PORTS, SQLITE, SUFFIXES, VERSION,
                        WHO, Instance, Instances, Kept, Made, Method, Refusal, Share, SharePolicy, clean_holds, clean_name,
                        clean_title, clean_who, credential_variables, is_absolute, is_local, listening, now_iso,
                        saved_policy, variable_of)


def data_folder(app=None) -> Path:
    """The data folder an app's database plugins speak of: beside the app's own database when it names one
    (IntegratorApp.db_path), else LIMINAL_DB's folder, else the workspace's (layout.data_dir)."""
    db = getattr(app, "db_path", None)
    if db is not None:
        return Path(db).parent
    from ..config import setting

    named = setting("LIMINAL_DB")
    return Path(named).expanduser().parent if named else layout.data_dir()


# -- the contract ------------------------------------------------------------------------------------------------------
class DatabasePlugin(IntegratorPlugin):
    """A database engine's plugin. A subclass sets `name`, `title`, `about`, its ENGINE, METHODS and HOLDS, lists its
    variable among its `options` (`variable_of(name)`), and answers the hooks: `builtin`, `open`, `probe`, `make`."""

    CONTRACT = True
    KIND = "database"
    HOOKS = ("builtin", "open", "probe", "make", "own_port", "scan", "settings")
    READ_HOOKS = ("builtin", "probe")  # its reads (Plugin.READ_HOOKS), agreed 2026-11-16 with the session of this file
    ICON = "database"  # its icon on a page (icons.js)
    ENGINE = ""  # one of ENGINES
    METHODS: tuple[str, ...] = ()  # the ways its instances are reached, the usual one first
    HOLDS: tuple[str, ...] = ()  # what its instances can hold
    SERVER = False  # a server's engine: an address, a database, a role; else a file's
    DRIVER = ""  # the Python module its connections need ("": the standard library's own)
    DRIVER_HINT = ""  # how it is had, in words, when it is not installed
    SHARES = False  # whether a share on its instances is kept to (SQLite's: by the helper); else said in SHARED
    SHARED = ""  # who can reach its instances, in words, when shares are not its to keep
    MAKES = True  # whether New database is offered
    CONNECTS = True  # whether Connect is offered

    # -- the hooks: what an engine's plugin answers ---------------------------------------------------------------
    def builtin(self, data_dir: Path) -> tuple[Instance, ...]:
        """Its own instances: today's databases of its engine for the data folder `data_dir`, as they are with nothing
        set. The contract has none."""
        return ()

    def open(self, instance: Instance, part: str = "", read_only: bool = True, data_dir: Path | None = None):
        """A connection to `instance` through its method (`part`: a file of a folder instance, by its path in it):
        the one way a database of this engine is opened. Closed by whoever asked."""
        raise NotImplementedError(f"{self.name}: opens no database")

    def probe(self, instance: Instance, data_dir: Path) -> list[str]:
        """`instance` opened for reading and asked what it is: a line for each thing found (the engine's version, its
        tables or collections). Raises, in words, when it cannot be: Test says so. Never starts a server."""
        raise NotImplementedError(f"{self.name}: tests no database")

    def make(self, instance: Instance, data_dir: Path, **given) -> "Made | list[str]":
        """A new database made for `instance` (a file's engine: the file; a server's: the database, and the role it is
        used with): what was made, a line each, or a Made naming the role too. `given`: what the form asked once and
        is not kept (a server's administrator: admin_user, admin_password). Never over one that is there."""
        raise NotImplementedError(f"{self.name}: makes no database")

    def own_port(self, instance: Instance, port: int, data_dir: Path) -> dict:
        """The port of one of the plugin's own instances changed (`set_port` asks this for one): kept where the
        engine itself reads it, and said as a template's answer ({"ok", "said", "lines"}). The contract changes none."""
        raise Refusal(f"{instance.name} is {self.title or self.name}'s own: its port is not changed here")

    # -- what it is ------------------------------------------------------------------------------------------------
    @property
    def instances_variable(self) -> str:
        return variable_of(self.name)

    @property
    def engine_title(self) -> str:
        return ENGINES.get(self.ENGINE, self.ENGINE)

    def default_port(self) -> int | None:
        """The port a server instance has when none is given: the engine's usual one (PORTS); a plugin whose own server
        is kept on another says that one."""
        return PORTS.get(self.ENGINE)

    def driver(self) -> tuple[bool, str]:
        """Whether its connections can be made in this Python, and if not why (its driver is its own dependency,
        looked for when asked, loaded when used)."""
        if not self.DRIVER:
            return True, ""
        import importlib.util

        try:
            found = importlib.util.find_spec(self.DRIVER) is not None
        except (ImportError, ValueError):
            found = False
        return (True, "") if found else (False, self.DRIVER_HINT or f"{self.DRIVER} is not installed in the app's Python")

    def data_dir(self) -> Path:
        return data_folder(self.app)

    def _store(self, folder: Path | None = None) -> Instances:
        variable, saved = self.instances_variable, None
        if mounts.foreign(folder if folder is not None else self.data_dir()):  # another system's data: what is kept
            # of it is that system's to say
            def saved() -> Mapping[str, str]:
                from ..config import UserEnvironment

                return UserEnvironment(names=(variable,)).saved()
        return Instances(variable, lambda: self.login, self.ENGINE, saved)

    def kept(self, data_dir: Path | None = None) -> Kept:
        """What the user added to its own instances, as it is kept for the data folder asked about."""
        return self._store(data_dir).read()

    # -- the instances ---------------------------------------------------------------------------------------------
    def instances(self, data_dir: Path | None = None) -> tuple[Instance, ...]:
        """Every instance: its own (each with the shares set on it), then the ones the user added, in the order added."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        kept = self.kept(folder)
        own = [replace(i, engine=self.ENGINE, builtin=True, shared=kept.builtin.get(i.name, i.shared))
               for i in self.builtin(folder)]
        names = {i.name for i in own}
        return (*own, *(i for n, i in kept.instances.items() if n not in names))

    def instance(self, name: str, data_dir: Path | None = None) -> Instance:
        wanted = str(name or "").strip().lower()
        for inst in self.instances(data_dir):
            if inst.name == wanted:
                return inst
        raise LookupError(f"{self.title or self.name} has no instance {str(name or '')[:40]!r}")

    def path_of(self, instance: Instance, data_dir: Path | None = None) -> Path | None:
        """A file instance's place here: in the data folder, or the whole path it was given. None for a server's, and
        for a path of another system that this one has no name for (a Windows path with no mount of its drive)."""
        if self.SERVER:
            return None
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        where = instance.where
        if not is_absolute(where):
            return folder if where in ("", ".", "./") else folder / where
        linux = where.startswith("/") and not where.startswith("//")  # as Linux writes a whole path
        if os.name == "nt":
            return None if linux else Path(where)  # (a Linux path read on Windows: no name for it here)
        if linux:
            return Path(where)
        here = mounts.here_path(where)  # a Windows path read on Linux: where its drive is mounted, if it is
        return Path(here) if here else None

    def effective_method(self, instance: Instance, data_dir: Path | None = None) -> str:
        """How it is reached from this system: its own method; a file on another system's drive through the helper
        when the engine has one (SQLite), chosen by itself."""
        if self.SERVER or instance.method != "file":
            return instance.method
        path = self.path_of(instance, data_dir)
        return "helper" if path is not None and "helper" in self.METHODS and mounts.foreign(path) else "file"

    def state(self, instance: Instance, data_dir: Path | None = None) -> dict:
        """How it is now, without opening it: a file's presence and size (a folder's: whether it is there; its files
        are the Databases view's to count), a server's address and, on this machine only, whether anything listens
        there. Never starts anything."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        method = self.effective_method(instance, folder)
        out: dict = {"method": method, "methodTitle": METHODS[method].title if method in METHODS else method}
        ok, why = self.driver()
        if self.SERVER:
            port = instance.port or self.default_port()
            out.update(address=_address(instance, port), local=instance.method == "socket" or is_local(instance.where))
            if not ok:
                return {**out, "state": "no driver", "why": why}
            if instance.method == "tcp" and out["local"]:
                up = listening(instance.where, port)
                return {**out, "state": "listening" if up else "not running",
                        "why": "" if up else f"nothing listens at {out['address']}; it is never started to be asked"}
            return {**out, "state": "not asked", "why": "asked only when you test it"}
        path = self.path_of(instance, folder)
        out.update(path=str(path) if path is not None else instance.where)
        if path is None:
            return {**out, "state": "elsewhere", "foreign": True,
                    "why": "on the system that holds the data: this one has no name for that path"}
        foreign = mounts.foreign(path)
        out["foreign"] = foreign
        try:
            exists = path.is_dir() if instance.folder else path.is_file()
        except OSError:
            exists = False
        if not exists:
            return {**out, "state": "absent", "why": f"no such {'folder' if instance.folder else 'file'}"}
        if not instance.folder:
            out["bytes"] = _file_bytes(path)
        if not ok:
            return {**out, "state": "no driver", "why": why}
        return {**out, "state": "ready", "why": ""}

    # -- asked by a page -------------------------------------------------------------------------------------------
    def test(self, name: str, data_dir: Path | None = None) -> dict:
        """One instance opened for reading and asked what it is; said in words, with what it found."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        inst = self.instance(name, folder)
        ok, why = self.driver()
        if not ok:
            return {"ok": False, "said": f"{inst.name} was not tested: {why}", "lines": []}
        began = time.monotonic()
        try:
            lines = list(self.probe(inst, folder))
        except Exception as e:  # noqa: BLE001 - what it said is the test's answer
            return {"ok": False, "said": f"{inst.name} did not answer: {_words(e)}", "lines": []}
        took = time.monotonic() - began
        return {"ok": True, "said": f"{inst.name} answers ({self.effective_method(inst, folder)}, {took * 1000:.0f} ms)",
                "lines": lines}

    def _changing(self, folder: Path, what: str) -> Kept:
        """What is kept, to change it: from the system that holds the data folder alone, through a login."""
        mounts.owner_only(folder, what)
        if self.login is None:
            raise Refusal("instances are kept through the integrator's login, and this plugin has none: open it on the "
                          "integrator's page")
        return self._store(folder).current()

    def _free_name(self, name, kept: Kept, folder: Path) -> str:
        clean = clean_name(name)
        if clean in kept.instances or clean in {i.name for i in self.builtin(folder)}:
            raise Refusal(f"there is an instance {clean} already")
        if len(kept.instances) >= MAX_INSTANCES:
            raise Refusal(f"{MAX_INSTANCES} instances at most: forget one first")
        return clean

    @staticmethod
    def _fits(kept: Kept) -> None:
        """Refusal when what is to be kept would not fit, said before anything is made or connected."""
        if len(kept.text() or "") > MAX_KEPT - 400:  # (a role's name and grants are added once it is made)
            raise Refusal(f"too much to keep ({len(kept.instances)} instances and their shares): forget one first")

    def new_database(self, name, where="", holds=(), title="", data_dir: Path | None = None, port=None, database="",
                     tls=False, accept_remote=False, **given) -> dict:
        """A new database made, and kept as an instance: a file's engine makes the file (in the data folder's
        instances/ unless a whole path is given; never over a file that is there), a server's the database on the
        server named, with a role of its own (`given`: the server's administrator, admin_user and admin_password,
        asked once and not kept)."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        if not self.MAKES:
            raise Refusal(f"{self.title or self.name} makes no new databases")
        kept = self._changing(folder, f"making a {self.engine_title} database")
        name = self._free_name(name, kept, folder)
        ok, why = self.driver()
        if not ok:
            raise Refusal(why)
        inst = Instance(name=name, title=clean_title(title), engine=self.ENGINE, holds=clean_holds(holds, self.HOLDS),
                        made=True, at=now_iso())
        if self.SERVER:  # (a role is made with it when the server's administrator is given: it then signs in)
            inst = self._server(replace(inst, auth=bool(given.get("admin_user"))), where, port, database or name, tls,
                                accept_remote, method="")
        else:
            inst = replace(inst, where=self._new_file(name, where, folder), method="file")
        kept.instances[name] = inst
        self._fits(kept)
        made = self.make(inst, folder, **given)
        lines = list(made.lines) if isinstance(made, Made) else list(made or ())
        if isinstance(made, Made):
            inst = replace(inst, auth=bool(made.role), role=made.role, grants=tuple(made.grants))
        elif self.SERVER:
            inst = replace(inst, auth=False)
        kept.instances[name] = inst
        try:
            where_kept = self._store(folder).keep(kept)
        except Exception as e:  # noqa: BLE001 - made, and said so: nothing is lost, Connect keeps it
            raise Refusal(f"{_place(self, inst, folder)} was made but could not be kept as an instance ({_words(e)}): "
                          "Connect keeps it") from None
        return {"ok": True, "said": f"{name} made: {_place(self, inst, folder)}", "lines": [*lines, f"kept in {where_kept}"],
                "instance": name}

    def _forget_credentials(self, instance: str) -> None:
        for variable in credential_variables(self.name, instance):
            try:
                self.login.save(variable, None)
            except Exception:  # noqa: BLE001 - a login that cannot forget one keeps the other from being forgotten no more
                pass

    def keep_credentials(self, instance: str, user: str, password: str) -> str:
        """An instance's name and password kept through the login as two pairs (a plugin's `make`, for the role it
        made); where, in words."""
        if self.login is None:
            raise Refusal("a sign-in is kept through the integrator's login, and this plugin has none")
        user_var, password_var = credential_variables(self.name, instance)
        try:
            where_kept = self.login.save(user_var, user)
            self.login.save(password_var, password)
        except Exception:
            self._forget_credentials(instance)  # never half a sign-in
            raise
        return where_kept

    def connect_to(self, name, where="", method="", holds=(), title="", data_dir: Path | None = None, port=None,
                   database="", tls=False, auth=False, accept_remote=False, user="", password="") -> dict:
        """A database that exists kept as an instance: it is asked what it is first (probe), and kept only when it
        answers. A server off this machine is refused until accepted (`accept_remote`: asked twice), and then only
        with TLS and a sign-in. `user`, `password`: the sign-in, kept through the login as two pairs before the
        server is asked (it signs in to answer) and forgotten again when it does not; `auth` alone: the pairs are
        there already."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        if not self.CONNECTS:
            raise Refusal(f"{self.title or self.name} connects to no other databases")
        kept = self._changing(folder, f"connecting a {self.engine_title} database")
        name = self._free_name(name, kept, folder)
        ok, why = self.driver()
        if not ok:
            raise Refusal(why)
        inst = Instance(name=name, title=clean_title(title), engine=self.ENGINE, holds=clean_holds(holds, self.HOLDS),
                        at=now_iso())
        signs_in = False
        if self.SERVER:
            user, password = str(user or "").strip(), str(password or "")
            if bool(user) != bool(password):
                raise Refusal("a sign-in is a name and a password: both, or neither")
            if user and not DATABASE.match(user):
                raise Refusal("a role's name is letters, digits, underscores and dashes")
            inst = self._server(replace(inst, auth=bool(user) or bool(auth), role=user), where, port, database, tls,
                                accept_remote, method=method)
            signs_in = bool(user)
        else:
            inst = replace(inst, where=self._existing_file(where, folder), method="file")
        kept.instances[name] = inst
        self._fits(kept)
        if signs_in:
            self.keep_credentials(name, user, password)
        try:
            found = list(self.probe(inst, folder))
        except Exception as e:  # noqa: BLE001 - why it is not connected, in its words
            if signs_in:
                self._forget_credentials(name)
            raise Refusal(f"{_place(self, inst, folder)} did not answer, so it is not kept: {_words(e)}") from None
        where_kept = self._store(folder).keep(kept)
        return {"ok": True, "said": f"{name} connected: {_place(self, inst, folder)}",
                "lines": [*found, f"kept in {where_kept}"], "instance": name}

    def share(self, name, who, access, data_dir: Path | None = None) -> dict:
        """Who else may attach to an instance: `who` (a suite, as it is named on a database) reading only (`read`),
        writing too (`write`), or not at all (`none`: its share taken away)."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        if not self.SHARES:
            raise Refusal(self.SHARED or f"{self.title or self.name} keeps no shares: its engine decides who reaches it")
        kept = self._changing(folder, "changing who may attach")
        inst = self.instance(name, folder)
        who = clean_who(who)
        access = str(access or "").strip().lower()
        if access not in (*ACCESS, NONE):
            raise Refusal(f"a share is {', '.join(ACCESS)} or {NONE}: not {access[:20]!r}")
        shares = {s.who: s for s in inst.shared}
        if access == NONE:
            if who not in shares:
                return {"ok": True, "said": f"{who} had no share of {inst.name}", "lines": []}
            del shares[who]
        else:
            if who not in shares and len(shares) >= MAX_SHARES:
                raise Refusal(f"{MAX_SHARES} shares at most on one instance: take one away first")
            shares[who] = Share(who, access)
        new = tuple(shares.values())
        if inst.builtin:
            if new:
                kept.builtin[inst.name] = new
            else:
                kept.builtin.pop(inst.name, None)
        else:
            kept.instances[inst.name] = replace(kept.instances[inst.name], shared=new)
        where_kept = self._store(folder).keep(kept)
        said = (f"{who} no longer attaches to {inst.name}" if access == NONE
                else f"{who} {'reads' if access == 'read' else 'reads and writes'} {inst.name}")
        return {"ok": True, "said": said, "lines": [shared_words(self, replace(inst, shared=new), folder),
                                                    f"kept in {where_kept}"]}

    def forget(self, name, data_dir: Path | None = None) -> dict:
        """An instance the user added, forgotten: what it holds stays where it is (only the user removes data), its
        sign-in is forgotten with it. One of the plugin's own is not forgotten."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        kept = self._changing(folder, "forgetting an instance")
        inst = self.instance(name, folder)
        if inst.builtin:
            raise Refusal(f"{inst.name} is {self.title or self.name}'s own: it is not forgotten")
        del kept.instances[inst.name]
        where_kept = self._store(folder).keep(kept)
        lines = [f"{_place(self, inst, folder)} stays as it is: nothing of it was removed", f"kept in {where_kept}"]
        if inst.auth:
            self._forget_credentials(inst.name)
            lines.insert(1, "its sign-in is forgotten")
        return {"ok": True, "said": f"{inst.name} forgotten", "lines": lines}

    def set_credentials(self, name, user, password, data_dir: Path | None = None) -> dict:
        """The name and password an instance signs in with, kept through the login as two pairs (never in the value the
        instances are kept in, never shown again); both empty: forgotten."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        kept = self._changing(folder, "keeping a sign-in")
        inst = self.instance(name, folder)
        if not self.SERVER:
            raise Refusal(f"{inst.name} is a file: nothing signs in to it")
        if inst.builtin:
            raise Refusal(f"{inst.name} is {self.title or self.name}'s own, on this machine alone: it takes no sign-in")
        user, password = str(user or "").strip(), str(password or "")
        if bool(user) != bool(password):
            raise Refusal("a sign-in is a name and a password: both, or neither to forget it")
        if user and not DATABASE.match(user):
            raise Refusal("a role's name is letters, digits, underscores and dashes")
        user_var, password_var = credential_variables(self.name, inst.name)
        if inst.remote and not user:
            raise Refusal(f"{inst.name} is not on this machine: it is reached with a sign-in alone (forget the instance to "
                          "leave it)")
        if user:
            where_kept = self.keep_credentials(inst.name, user, password)  # (whole, or not at all)
        else:
            where_kept = self.login.save(user_var, None)
            self.login.save(password_var, None)
        kept.instances[inst.name] = replace(kept.instances[inst.name], auth=bool(user), role=user)
        self._store(folder).keep(kept)
        lines = [f"kept in {where_kept}"] + (["Test says whether the server takes it"] if user else [])
        return {"ok": True, "said": f"{inst.name}'s sign-in {'kept' if user else 'forgotten'}", "lines": lines}

    def set_port(self, name, port, data_dir: Path | None = None) -> dict:
        """A server instance's port, its own, changed. One the user added is asked at the new port first and the change
        kept only when it answers; one of the plugin's own is the plugin's to change (`own_port`)."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        kept = self._changing(folder, "changing a port")
        inst = self.instance(name, folder)
        if not self.SERVER or inst.method != "tcp":
            raise Refusal(f"{inst.name} is reached by {'its ' + inst.method if self.SERVER else 'its file'}: it has no port")
        port = _port(port)
        if inst.builtin:
            return self.own_port(inst, port, folder)
        if port == inst.port:
            return {"ok": True, "said": f"{inst.name}'s port is {port} already", "lines": []}
        new = replace(inst, port=port)
        try:
            found = list(self.probe(new, folder))
        except Exception as e:  # noqa: BLE001 - why the port stays, in its words
            raise Refusal(f"nothing answered at {_place(self, new, folder)}, so {inst.name}'s port stays {inst.port}: "
                          f"{_words(e)}") from None
        kept.instances[inst.name] = new
        where_kept = self._store(folder).keep(kept)
        return {"ok": True, "said": f"{inst.name}'s port is {port} now", "lines": [*found, f"kept in {where_kept}"]}

    def credentials(self, instance: Instance) -> tuple[str, str] | None:
        """The name and password an instance signs in with, from the login (None: it does not sign in, or they are not
        there): for the plugin's own `open` alone, never for a page."""
        if not instance.auth or self.login is None:
            return None
        user_var, password_var = credential_variables(self.name, instance.name)
        got = self.login.variables([user_var, password_var])
        return (got[user_var], got[password_var]) if got.get(user_var) and got.get(password_var) else None

    # -- a file's place, a server's address --------------------------------------------------------------------------
    def _suffix(self, where: str) -> None:
        suffixes = SUFFIXES.get(self.ENGINE, ())
        if suffixes and not where.lower().endswith(suffixes):
            raise Refusal(f"a {self.engine_title} file ends in {' or '.join(suffixes)}: not {where[-60:]!r}")

    def _new_file(self, name: str, where, folder: Path) -> str:
        """Where a new file goes: the data folder's instances/<name> unless a whole path is given; never a file that is
        there, never one of the app's own folders, never another system's drive."""
        where = str(where or "").strip()
        suffixes = SUFFIXES.get(self.ENGINE, ("",))
        if not where:
            where = f"{INSTANCES}/{name}{suffixes[0]}"
        self._suffix(where)
        if is_absolute(where):
            path = Path(where)
            if not path.parent.is_dir():
                raise Refusal(f"{path.parent} is no folder here: a new database goes in a folder that is there")
        else:
            where = _relative(where)
            if posixpath.dirname(where) != INSTANCES:
                raise Refusal(f"a new database in the data folder goes in its {INSTANCES}/ folder ({INSTANCES}/{name}"
                              f"{suffixes[0]}); give a whole path for one elsewhere")
            path = folder / where
        mounts.owner_only(path.parent if path.parent.exists() else folder, "making a database")
        if path.exists():
            raise Refusal(f"{path} is there already: a new database is never made over a file (Connect keeps one that exists)")
        return where

    def _existing_file(self, where, folder: Path) -> str:
        """A file that exists, to connect to: in the data folder (not one the plugin's own instances hold already) or a
        whole path; on another system's drive only where the engine has a helper for it."""
        where = str(where or "").strip()
        if not where:
            raise Refusal("which file: its path in the data folder, or its whole path")
        self._suffix(where)
        if is_absolute(where):
            path = Path(where)
        else:
            where = _relative(where)
            top = where.split("/", 1)[0]
            if "/" not in where or top in OWN_FOLDERS:
                raise Refusal(f"{where} is one of the data folder's own files: {self.title or self.name}'s own instance "
                              "holds it already")
            path = folder / where
        if not path.is_file():
            raise Refusal(f"{path} is no file here")
        if mounts.foreign(path) and not mounts.foreign(folder):
            if "helper" not in self.METHODS or mounts.owner_path(path) is None:
                raise Refusal(f"{path} is on another system's drive, and a {self.engine_title} file there cannot be opened "
                              "safely from here: connect it on the system that holds it")
        return where

    def _server(self, inst: Instance, where, port, database, tls, accept_remote, method: str) -> Instance:
        """A server's instance from what a form gave: its host (or its socket), its port, its database; off this
        machine only when accepted, and then only with TLS and a sign-in."""
        where = str(where or "").strip()
        method = str(method or "").strip().lower() or ("socket" if where.startswith(("/", "\\\\.\\pipe\\")) else "tcp")
        if method not in self.METHODS or not METHODS[method].address:
            raise Refusal(f"{self.title or self.name} is reached by {', '.join(m for m in self.METHODS)}: not {method!r}")
        database = str(database or "").strip()
        if not DATABASE.match(database):
            raise Refusal("which database on the server: its name (letters, digits, underscores and dashes)")
        if method == "socket":
            if not where.startswith(("/", "\\\\.\\pipe\\")) or len(where) > 200 or any(ord(c) < 32 for c in where):
                raise Refusal("a socket is its whole path (/run/postgresql), a Windows pipe \\\\.\\pipe\\<name>")
            return replace(inst, where=where, method="socket", port=None, database=database, tls=False, remote=False)
        host = where or "127.0.0.1"
        if ":" in host and not host.startswith("[") and host.count(":") == 1:  # host:port as typed
            host, _, typed = host.partition(":")
            port = port if port not in (None, "") else typed
        if not HOST.match(host):
            raise Refusal(f"a server's address is its host's name or number, with its port apart: not {host[:60]!r}")
        port = _port(port if port not in (None, "") else self.default_port() or 0)
        remote = not is_local(host)
        if remote:
            if not accept_remote:
                raise Refusal(f"{host} is not this machine: the data would be kept on, and read from, another one. Say so "
                              "again to keep it there (it is then reached with TLS and a sign-in alone)", accept="accept_remote")
            if not tls or not inst.auth:
                raise Refusal(f"{host} is not this machine: it is reached only with TLS and a sign-in (both set)")
        return replace(inst, where=host, method="tcp", port=port, database=database, tls=bool(tls), remote=remote)

    # -- for a page -------------------------------------------------------------------------------------------------
    def status(self, data_dir: Path | None = None) -> dict:
        """The plugin and its instances as a page draws them: what it is, whether its driver is here, its methods and
        what it holds, what may be changed from here (and why not), and every instance with its state."""
        folder = Path(data_dir) if data_dir is not None else self.data_dir()
        ok, why = self.driver()
        kept = self.kept(folder)
        foreign = mounts.foreign(folder)
        cannot = ("" if not foreign else "the data is on another system's drive: its instances are changed from that "
                  "system, and read here") or ("" if self.login is not None else "open it on the integrator's page to change it")
        rows = []
        for inst in self.instances(folder):
            row = {**inst.as_dict(), **self.state(inst, folder), "sharedWords": shared_words(self, inst, folder),
                   "place": _place(self, inst, folder)}
            if self.SERVER and inst.auth:
                row["signsIn"] = self.credentials(inst) is not None
            rows.append(row)
        return {"name": self.name, "title": self.title, "about": self.about, "version": self.version, "api": self.api,
                "origin": self.origin, "engine": self.ENGINE, "engineTitle": self.engine_title, "server": self.SERVER,
                "icon": self.ICON, "driver": {"name": self.DRIVER, "ok": ok, "why": why},
                "methods": [METHODS[m].as_dict() for m in self.METHODS if m in METHODS],
                "holds": [{"name": h, "title": HOLDS.get(h, h)} for h in self.HOLDS],
                "variable": self.instances_variable, "problem": kept.problem, "dataFolder": str(folder), "foreign": foreign,
                "can": {"new": self.MAKES and not cannot and ok, "connect": self.CONNECTS and not cannot and ok,
                        "share": self.SHARES and not cannot, "forget": not cannot,
                        "why": cannot or ("" if ok else why)},
                "shares": self.SHARES, "sharedNote": self.SHARED, "defaultPort": self.default_port(),
                "instances": rows}


def _port(value) -> int:
    """A port as a form gave it; Refusal for what is none."""
    try:
        port = int(value) if not isinstance(value, bool) else 0
    except (TypeError, ValueError):
        port = 0
    if not 0 < port < 65536:
        raise Refusal("a port is a number from 1 to 65535")
    return port


def _relative(where: str) -> str:
    """A path in the data folder as given, with / between its parts; Refusal for one that leaves the folder."""
    parts = [p for p in where.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise Refusal(f"{where[:80]!r} is not a path in the data folder (give its whole path for one elsewhere)")
    return "/".join(parts)


def _file_bytes(path: Path) -> int | None:
    """A database file's bytes on disk, its write-ahead log with it; None when it cannot be read."""
    try:
        total = path.stat().st_size
    except OSError:
        return None
    for suffix in ("-wal", ".wal"):
        side = path.with_name(path.name + suffix)
        try:
            total += side.stat().st_size
        except OSError:
            pass
    return total


def _address(instance: Instance, port: int | None) -> str:
    if instance.method == "socket":
        return f"{instance.where} ({instance.database})" if instance.database else instance.where
    return f"{instance.where}:{port}" + (f"/{instance.database}" if instance.database else "")


def _place(plugin: DatabasePlugin, instance: Instance, folder: Path) -> str:
    """Where an instance is, in a few words: a file's path here, a server's address."""
    if plugin.SERVER:
        return _address(instance, instance.port or plugin.default_port())
    path = plugin.path_of(instance, folder)
    return str(path) if path is not None else instance.where


def _words(e: BaseException) -> str:
    text = " ".join(str(e).split()) or type(e).__name__
    return text if len(text) <= 300 else text[:297] + "..."


def shared_words(plugin: DatabasePlugin, instance: Instance, folder: Path | None = None) -> str:
    """Who can reach an instance, in words: its shares; with none set, what holds without one (in the data folder
    `folder`, whoever can start a helper here; outside it, this system alone: a helper opens the data folder and the
    instances shared with someone, no other place)."""
    if not plugin.SHARES:
        return plugin.SHARED or "its engine decides who reaches it"
    if not instance.shared:
        if folder is not None and not instance.builtin and _outside(plugin, instance, folder):
            return "no share set: this system alone opens it (it is outside the data folder; shared, a helper opens it too)"
        return "no share set: any suite that can start a helper on this system reads and writes it"
    reads = [s.who for s in instance.shared if s.access == "read"]
    writes = [s.who for s in instance.shared if s.access == "write"]
    parts = ([f"{', '.join(writes)} read{'s' if len(writes) == 1 else ''} and write{'s' if len(writes) == 1 else ''}"]
             if writes else []) + ([f"{', '.join(reads)} read{'s' if len(reads) == 1 else ''} only"] if reads else [])
    return "; ".join(parts) + "; no other suite attaches"


def _outside(plugin: DatabasePlugin, instance: Instance, folder: Path) -> bool:
    """Whether a file instance lies outside the data folder (one this system has no name for is outside it)."""
    path = plugin.path_of(instance, folder)
    if path is None:
        return True
    try:
        base, here = Path(folder).resolve(), path.resolve()
    except (OSError, ValueError):
        return True
    return not (here == base or base in here.parents)


def new_password() -> str:
    """A password for a role a plugin makes: made here, kept through the login, never shown."""
    return secrets.token_urlsafe(24)
