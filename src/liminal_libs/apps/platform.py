"""The platform's core, the base the apps inherit (1.90.0, Monday list item 30, step 1).

The user, 2026-11-24: "through the rust interface", then "inheritance bro": the charts and the integrator inherit a
platform base class (`ChartsApp(Platform)`, `IntegratorApp(Platform)`), and liminal-platform's PlatformApp inherits the
same base and adds the machine and AI sections. 2026-11-25: the instance forms move to the platform's Databases
section, the platform the only writer of instance settings. The design is item-30-design.md in the sessions folder.

`Platform(App)` is the core alone, not the whole liminal-platform app:
- it holds its plugins by section (`sections`: a plugin's SECTION, else its kind's: KIND_SECTIONS);
- it attaches the kinds a subclass declares it takes (`PLATFORM_KINDS`, e.g. ("database",): `attach_kinds`; 1.103.0's
  names: "needs" is what a plugin needs of the machine, liminal_libs.needs), with its own login as every App does (the login object it includes, LOGIN, is the App frame's own: nothing changes there);
- it answers the Databases section's routes when it needs "database" (apps/databases.py, moved from the integrator):
  `GET /api/databases/plugins` and `POST /api/databases/instances`, the same shapes as the integrator's;
- the one-writer rule: instance settings are read, changed and written back with no lock across processes, so only the
  running platform changes them (`PLATFORM_WRITER`, the flag liminal-platform's app sets; or `writer=` given). A
  Platform that is not it (a part included in another app's process) reads them and opens its databases itself, and
  its change routes answer 409, "change this on the platform's Databases section";
- across processes, through liminal-net, never HTTP (NETWORK.md; decision of 2026-11-24): the running platform serves
  its Databases section as a node (`serve_databases`: DatabasesHillock, its interface DATABASES_INTERFACE), and a part
  in another process reaches it as a Remote for a change (`change_on_platform`). Opening a database stays in each
  app's own process: the data path pays no hop.

Nothing here starts a process: a node is served only when the platform asks (`serve_databases`), and a part reaches
the platform's node without a launcher (a platform not running is said, never started)."""
from __future__ import annotations

import threading
from http import HTTPStatus
from pathlib import Path
from typing import Callable

from .app import App, Refused
from . import databases as section

# a plugin's place on the platform's list when its class names none (MachinePlugin.SECTION names its own)
KIND_SECTIONS = {"database": "databases", "machine": "machine", "assistant": "ai"}
KINDS = tuple(KIND_SECTIONS)  # the kinds a Platform can be declared to attach (1.103.0: PLATFORM_KINDS)
NEEDS = KINDS  # the old name (1.90.0-1.102.0), kept for one release: "needs" is what a plugin needs of the machine
ELSEWHERE = "change this on the platform's Databases section"  # a part that is not the platform, asked to change
NOT_RUNNING = "the platform is not running: start it to change an instance"
DATABASES_NODE = "platform-databases"  # the running platform's Databases section, as a node
DATABASES_TRAIT = "liminal.platform.Databases"
SECTION_TRAIT = "liminal.PlatformSection"
_FORM = [{"name": "form", "type": "map"}]
DATABASES_READS = ("overview", "elsewhere", "test")  # what any peer may ask: changes nothing anywhere
DATABASES_CHANGES = ("change",)  # what changes an instance's settings: the running platform's alone
DATABASES_INTERFACE = {  # (NETWORK.md §6's shape: what crosses is args, returns and the signature the pages show)
    "trait": DATABASES_TRAIT, "base": [SECTION_TRAIT],
    "methods": {
        "overview": {"args": [], "returns": "map", "signature": "()"},  # GET /api/databases/plugins' answer
        "elsewhere": {"args": [], "returns": "list<map>", "signature": "()"},  # the file instances outside the folder
        "test": {"args": _FORM, "returns": "map", "signature": "(form)"},  # the Test form: opened for reading
        "change": {"args": _FORM, "returns": "map", "signature": "(form)"},  # new, connect, share, port, credentials,
    },                                                                        # forget: confirmed on a page
    "signals": {},
}


def section_of(plugin) -> str:
    """The section a plugin is drawn under: its class's SECTION, else its kind's (KIND_SECTIONS), else none ("")."""
    return str(getattr(plugin, "SECTION", "") or KIND_SECTIONS.get(getattr(plugin, "KIND", ""), ""))


def _declared_kinds(cls) -> tuple[str, ...]:
    """The kinds a Platform class takes: PLATFORM_KINDS or the old PLATFORM_NEEDS, whichever the nearest class of its
    line sets (so a subclass of one that set the old name, setting the new, is read by the new)."""
    for k in cls.__mro__:
        for name in ("PLATFORM_KINDS", "PLATFORM_NEEDS"):
            if name in vars(k) and not isinstance(vars(k)[name], _OldKinds):
                return tuple(vars(k)[name])
    return ()


class _OldKinds:
    """PLATFORM_NEEDS read on a class that does not set it itself: the kinds it declares (1.103.0, for one release), so
    the old name read on a class that sets only PLATFORM_KINDS gives those kinds and never (); a subclass setting
    PLATFORM_NEEDS (the charts, the integrator) still sets it as before."""

    def __get__(self, obj, owner=None) -> tuple[str, ...]:
        return _declared_kinds(owner if owner is not None else type(obj))


def _finders() -> dict[str, Callable[[], dict]]:
    from ..sources import registry

    return {"database": registry.databases, "machine": registry.machines, "assistant": registry.assistants}


class Platform(App):
    """The platform core. A subclass declares PLATFORM_KINDS (the kinds it attaches); liminal-platform's app sets
    PLATFORM_WRITER. ChartsApp and IntegratorApp inherit it from their next releases (steps 4 and 5)."""

    PLATFORM_KINDS: tuple[str, ...] = ()  # the plugin kinds it attaches (KINDS): ("database",) for the charts, the integrator
    PLATFORM_NEEDS = _OldKinds()  # the old name of PLATFORM_KINDS (1.90.0-1.102.0), for one release: set by a subclass
    # that still sets it, and read as the declared kinds (_OldKinds) on one that sets only PLATFORM_KINDS
    PLATFORM_WRITER = False  # the running platform: the one writer of instance settings (liminal-platform's app sets it)
    PLATFORM_SCOPE: Path | None = None  # where its nodes are reached (None: nodes.default_scope, the data folder)

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if "PLATFORM_KINDS" in vars(cls) and "PLATFORM_NEEDS" not in vars(cls):
            cls.PLATFORM_NEEDS = _OldKinds()  # read as the new name here, past a base that set the old one

    def __init__(self, log=print, login=None, *, writer: bool | None = None, node_factory=None):
        super().__init__(log=log, login=login)
        self._kinds = _declared_kinds(type(self))
        unknown = [k for k in self._kinds if k not in KINDS]
        if unknown:
            raise ValueError(f"{type(self).__name__}: PLATFORM_KINDS names {unknown}, none of {list(KINDS)}")
        self._writer = self.PLATFORM_WRITER if writer is None else bool(writer)
        self._node_factory = node_factory  # liminal_net.Node, or a test's stand-in (nodes.make_node)
        self._platform_lock = threading.Lock()
        self._node = None  # this part's own node, to reach the platform's (made when first needed)
        self.databases_node = None  # the platform's Databases section served as a node (serve_databases)

    # -- what it is -----------------------------------------------------------------------------------------------
    @property
    def is_platform(self) -> bool:
        """Whether this is the running platform, the one writer of instance settings."""
        return self._writer

    @property
    def kinds(self) -> tuple[str, ...]:
        """The plugin kinds it attaches (PLATFORM_KINDS, or the old PLATFORM_NEEDS a subclass still sets)."""
        return self._kinds

    def takes(self, kind: str) -> bool:
        """Whether it attaches plugins of `kind`."""
        return kind in self._kinds

    needs = takes  # the old name (1.90.0-1.102.0), kept for one release

    # -- its plugins, by section ----------------------------------------------------------------------------------
    def attach_kinds(self) -> list[str]:
        """Every plugin of the kinds it takes that the registry loaded, attached here with this app's login unless
        another app holds it; the names attached (one attached here already is not attached again). One whose
        required needs this machine does not meet is not attached (liminal_libs.needs, 1.103.0; item 38: a plugin
        whose needs are unmet is never started). 1.110.0 (item 14): one whose needs are unmet only for the moment (a
        Windows feature off, no internet now) is attached, held and asked nothing until they are met, as the needs
        plan shows it (red, not gone): attached once, it is there when the condition changes."""
        finders, out = _finders(), []
        for kind in self._kinds:
            for p in finders[kind]().values():
                if getattr(p, "KIND", "") != kind or p.app is self:
                    continue
                if p.app is not None:
                    continue  # another app's
                if self._unmet_here(p):
                    continue
                self.attach(p)
                out.append(p.name)
        return out

    attach_needs = attach_kinds  # the old name (1.90.0-1.102.0), kept for one release

    def _unmet_here(self, plugin) -> bool:
        """Whether a required need of the plugin is unmet by this machine (App.needs_of's judgement): not one unmet only
        for the moment (its sort "moment", 1.110.0); False where it cannot tell."""
        judge = getattr(self, "needs_of", None)
        if not callable(judge):
            return False
        try:
            answer = judge(plugin)
            return answer.get("met") is False and answer.get("sort") != "moment"
        except Exception:  # noqa: BLE001 - a judgement that fails hides nothing (the user's answer 10)
            return False

    def sections(self) -> dict[str, dict]:
        """The plugins attached here by section ({section: {name: plugin}}), the sections in KINDS' order first; a
        plugin of no section is left out."""
        out: dict[str, dict] = {}
        for name, p in self._plugins.items():
            where = section_of(p)
            if where:
                out.setdefault(where, {})[name] = p
        order = [KIND_SECTIONS[k] for k in KINDS]
        return dict(sorted(out.items(), key=lambda kv: (order.index(kv[0]) if kv[0] in order else len(order), kv[0])))

    def section(self, name: str) -> dict:
        return dict(self.sections().get(name, {}))

    # -- the Databases section ------------------------------------------------------------------------------------
    def database_plugins(self) -> dict:
        """The database plugins held here (attached at the first ask: apps/databases.plugins)."""
        if not self.takes("database"):
            return {}
        return section.plugins(self)

    def databases_overview(self) -> dict:
        """What `GET /api/databases/plugins` answers: the integrator's shape, and `writer` (whether a change is made
        here). On a part that is not the platform, no change is offered and each plugin says where it is made."""
        out = section.overview(self)
        out["writer"] = self.is_platform
        if not self.is_platform:
            for row in out["plugins"]:
                can = row.get("can")
                if isinstance(can, dict):
                    row["can"] = {**{k: False for k in can if k != "why"}, "why": ELSEWHERE}
        return out

    def instances_asked(self, body: dict) -> dict:
        """What `POST /api/databases/instances` answers: a test anywhere; a change on the running platform alone (409,
        ELSEWHERE, on any other part, before anything is read or asked)."""
        body = body if isinstance(body, dict) else {}
        if section.text_of(body, "action") in section.CHANGES and not self.is_platform:
            raise Refused(HTTPStatus.CONFLICT, ELSEWHERE)
        return section.ask(self, body)

    def api(self, handler, method: str, path: str, query: dict, body: dict | None):
        if self.takes("database"):
            if method == "GET" and path == "/api/databases/plugins":
                return 200, self.databases_overview()
            if method == "POST" and path == "/api/databases/instances":
                return 200, self.instances_asked(body if isinstance(body, dict) else {})
        return super().api(handler, method, path, query, body)

    # -- through liminal-net --------------------------------------------------------------------------------------
    def serve_databases(self, scope: Path | None = None, node_factory=None, start: bool = True):
        """The running platform's Databases section served as its node (DATABASES_NODE), in the background when
        `start`; the node. Only the platform serves it: a part that is not is refused (RuntimeError)."""
        if not self.is_platform:
            raise RuntimeError(f"{self.NAME or 'this app'} is not the running platform: it serves no Databases section")
        from .. import nodes

        hillock = DatabasesHillock(self)
        node = nodes.make_node(DATABASES_NODE, "platform", hillock, DATABASES_INTERFACE, scope or self.PLATFORM_SCOPE,
                               node_factory or self._node_factory)
        self.databases_node = node
        if start:
            node.start()
        return node

    def _end_server(self) -> None:
        """Its page's server ended (App.terminate's last step), and the Databases section's node with it: a node served
        here ends with the platform that serves it."""
        node, self.databases_node = self.databases_node, None
        if node is not None:
            try:
                node.stop("the platform is ending")
            except Exception:  # noqa: BLE001 - a node already ended
                pass
        super()._end_server()

    def own_node(self):
        """This part's own node (app-<NAME>-platform), made when first needed, not served: what reaches the platform's
        node (a node reaches another through its axon; its own dendrites need not listen)."""
        with self._platform_lock:
            if self._node is None:
                from .. import nodes

                self._node = nodes.make_node(f"app-{self.NAME or 'part'}-platform", "app", _PartHillock(self),
                                             _PART_INTERFACE, self.PLATFORM_SCOPE, self._node_factory)
            return self._node

    def platform_remote(self):
        """The running platform's Databases section, as a Remote (liminal_net), reached without a launcher: a
        platform not running is said (Refused 503, NOT_RUNNING), never started from here."""
        from .. import nodes

        node = self.own_node()
        try:
            return node.reach(DATABASES_NODE, str(self.PLATFORM_SCOPE or nodes.default_scope()), None)
        except ConnectionError as e:  # liminal_net.NetworkError: nobody answers, refused
            raise Refused(HTTPStatus.SERVICE_UNAVAILABLE, f"{NOT_RUNNING} ({e})") from None

    def change_on_platform(self, body: dict) -> dict:
        """A form's change made where it may be: here on the running platform, else asked of the platform's node (its
        refusal back as it was said there: Asked, its status, its words and what accepts it)."""
        if self.is_platform:
            return self.instances_asked(body)
        remote = self.platform_remote()
        try:
            return remote.request("change", body if isinstance(body, dict) else {})
        except ConnectionError as e:
            raise Refused(HTTPStatus.SERVICE_UNAVAILABLE, f"{NOT_RUNNING} ({e})") from None
        except Exception as e:  # noqa: BLE001 - liminal_net.RemoteError: the platform's refusal, as it crossed
            raise from_remote(e) from None

    def ask_platform(self, method: str, *args):
        """One of the platform's reads (DATABASES_READS) asked of its node."""
        if method not in DATABASES_READS:
            raise LookupError(f"the platform's Databases section offers no read {method!r}: {', '.join(DATABASES_READS)}")
        remote = self.platform_remote()
        try:
            return remote.request(method, *args)
        except ConnectionError as e:
            raise Refused(HTTPStatus.SERVICE_UNAVAILABLE, f"{NOT_RUNNING} ({e})") from None
        except Exception as e:  # noqa: BLE001
            raise from_remote(e) from None


def from_remote(e: BaseException) -> Refused:
    """A refusal that crossed liminal-net (a RemoteError: its kind, message, status, accept) as the Refused it was."""
    status = getattr(e, "status", None)
    words = getattr(e, "message", None) or str(e)
    return section.Asked(int(status) if isinstance(status, int) and 400 <= status < 600 else HTTPStatus.BAD_GATEWAY,
                         str(words), getattr(e, "accept", None) or None)


class DatabasesHillock:
    """The running platform's Databases section as a node's code (liminal_net.Node's hillock): its reads for any peer,
    its change only while the app is the platform (a part that stopped being it refuses: 409)."""

    def __init__(self, app: Platform):
        self.app = app
        self.node = None
        self.interface = DATABASES_INTERFACE
        self.peers: dict[int, dict] = {}
        self._lock = threading.Lock()

    def request(self, peer, method: str, args, kwargs):
        args, kwargs = list(args or ()), dict(kwargs or {})
        form = (args[0] if args else kwargs.get("form")) or {}
        if method == "overview":
            return self.app.databases_overview()
        if method == "elsewhere":
            return section.elsewhere(self.app)
        if method == "test":
            return self.app.instances_asked({**form, "action": "test"})
        if method == "change":
            if not self.app.is_platform:
                raise Refused(HTTPStatus.CONFLICT, ELSEWHERE)
            who = (peer or {}).get("name") or "a peer"
            out = self.app.instances_asked(form if isinstance(form, dict) else {})
            self.app.log(f"{self.app.NAME or 'platform'}: asked by {who} through its node: "
                         f"{section.text_of(form, 'plugin')} {section.text_of(form, 'action')}")
            return out
        raise Refused(HTTPStatus.NOT_FOUND, f"the Databases section offers no {method!r}")

    def attach(self, peer) -> None:
        with self._lock:
            self.peers[int((peer or {}).get("pid") or 0)] = dict(peer or {})

    def detach(self, peer) -> None:
        with self._lock:
            self.peers.pop(int((peer or {}).get("pid") or 0), None)

    def shutdown(self) -> None:
        pass  # the section ends with the platform; nothing of its own to secure


_PART_INTERFACE = {"trait": "liminal.PlatformPart", "base": [SECTION_TRAIT], "methods": {}, "signals": {}}


class _PartHillock:
    """A part's own node's code: it offers nothing (it only reaches the platform)."""

    def __init__(self, app: Platform):
        self.app = app
        self.node = None

    def request(self, peer, method, args, kwargs):  # noqa: ARG002
        raise Refused(HTTPStatus.NOT_FOUND, f"{self.app.NAME or 'this part'} offers nothing: it reaches the platform")

    def shutdown(self) -> None:
        pass
