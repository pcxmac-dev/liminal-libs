"""`ContainedService`: the base of a service plugin (1.94.0; service-containers-design §3.8, with the user's answers of
2026-11-23 and 2026-11-25). Jenkins, GoCD and Buildbot (Monday list item 34), then the source-control servers (item 35)
and the databases' servers, are built on it: each says its recipe (`spec_for`) and how its own software answers
(`ready`, `lan_ready`, `address`, `after`); this base asks the container plugins through its app and holds the rules:

- **Containers only** (the user, 2026-11-25: "Containers only"). Its service is installed, started, stopped, updated
  and removed only as a container, through the container plugin you pick, in that plugin's plans, approved on the page.
  A server you installed yourself is still found and read by the plugin itself; nothing here installs one natively.
- **Who asks.** Its five changes (service_install, service_change, service_carry, service_log, service_forget) are
  the page's alone: declared PAGE_ONLY_HOOKS (refused by the frame and the platform to any other asker) and checked
  again inside each hook (a Refusal). `hosts` is a read any asker may ask.
- **Where it can run** (`hosts`): every attached container plugin (one whose hooks list hosting, segments and
  service_plan) asked `hosting(owner, specs)` with one spec per system its recipe has, holding no lock, kept READ_S;
  every container plugin the platform knows that is not attached listed with the platform's word on why
  (`plugin_state`), asked nothing. A target is offered only while it is on this machine, ready, takes the recipe,
  has let this plugin in (the grant, on the container plugin's page), and, while NEEDS_LOOPBACK holds, publishes its
  ports at a loopback address: its own client sends a token over plain http to this machine alone (N24).
- **Plans.** Install… and every other change build the spec (`spec_for`) and ask `service_plan` of the picked
  container plugin; the answer is `containers.approval_answer`: the plans to approve, in order, and `service_carry`
  as the job that carries them out once you approved them. Nothing changes before your approval.
- **Carrying it out** (`service_carry`, a job you can cancel): refused before its first line unless the plan is
  approved and not expired (plan_words); then apply_plan, its work followed every FOLLOW_S, your Cancel forwarded
  once; once it ends well, its own software waited for (`ready`, READY_S at most), the placement kept through its
  login (<NAME>_SERVICES) and its own steps run (`after`).
- **Your network.** A plugin whose LAN_FIRST is False (GoCD, Buildbot: seeded sign-ins, the user's "Seeded, PC-only
  first") installs on this PC alone, and Expose… opens it only once `lan_ready` says its sign-in answers.
- **Service mode** (start at boot, left running after sign-off) is provided for in the words (the form's At boot,
  the action "boot") and refused until it is offered (containers.SERVICE_MODE_OFFERED).
- **Images.** A recipe pins every image by digest; a pin whose digest is UNREAD (not read from its registry yet) is
  refused before any plan.
- **Lifecycle.** Turned off (its detach while the platform says it is disabled), it asks release_owned of each container
  plugin hosting one of its services; a detach for invalidity asks nothing. Nothing restarts a service after a crash.

Plain: the standard library and the library's own modules."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets as _secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping

from ..apps import asking
from ..instances import Refusal, Store
from . import containers as C
from .containers import ServiceSpec
from .plugin import MachinePlugin

HOSTS, INSTALL, CHANGE, CARRY, LOG, FORGET = ("hosts", "service_install", "service_change", "service_carry",
                                              "service_log", "service_forget")
CHANGES = ("start", "stop", "restart", "update", "rollback", "expose", "boot", "remove", "delete_data")
CHOICES = {"rollback": ("as-is", "backup"), "expose": ("on", "off"), "boot": ("on", "off"),
           "delete_data": ("keep", "delete")}
WAITS_READY = ("install", "start", "restart", "update", "rollback", "expose")  # its software asked after these
FOLLOW_S = 0.5  # how often a carry follows its work
READY_S = 300.0  # how long a carry waits for its own software to answer
READY_EVERY_S = 2.0
UNREAD = "sha256:" + "0" * 64  # a pin's digest not read from its registry yet: refused before any plan
INSTALLED, REMOVED = "installed", "removed, data kept"
BUTTONS = (("start", "Start…"), ("stop", "Stop…"), ("restart", "Restart…"), ("update", "Update…"),
           ("rollback", "Roll back…"), ("expose", "Expose…"), ("remove", "Remove…"), ("delete_data", "Delete its data…"))
PBKDF2_ROUNDS = 600_000


def loopback(reach: str) -> bool:
    """Whether an address (127.0.0.1, ::1, localhost, with a port or not) is this machine's loopback."""
    host = str(reach or "").strip().lower()
    host = re.sub(r"^[a-z]+://", "", host).split("/", 1)[0]
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host == "localhost" or host == "::1" or host.startswith("127.")


def unread_pins(spec: ServiceSpec) -> list[str]:
    """The images of a spec whose digest is not read from its registry yet (UNREAD)."""
    return [p.image.ref for p in spec.parts if p.image.digest == UNREAD]


# -- hashes a seed may hold (never the password: the base refuses a seed holding a secret's value) --------------------
def pbkdf2_hash(password: str, salt: str | None = None, rounds: int = PBKDF2_ROUNDS) -> str:
    """`pbkdf2_sha256$<rounds>$<salt>$<hash>` (Django's shape): a salted hash a seeded sign-in checks with the standard
    library alone (hashlib.pbkdf2_hmac, hmac.compare_digest)."""
    salt = salt or _secrets.token_hex(16)
    if not re.fullmatch(r"[A-Za-z0-9]{8,64}", salt):
        raise ValueError("a salt is 8 to 64 letters and digits")
    raw = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), int(rounds))
    return f"pbkdf2_sha256${int(rounds)}${salt}${base64.b64encode(raw).decode('ascii')}"


def pbkdf2_check(password: str, hashed: str) -> bool:
    """Whether `password` is the one `hashed` (pbkdf2_hash's) was made of."""
    try:
        kind, rounds, salt, _ = hashed.split("$", 3)
        if kind != "pbkdf2_sha256":
            return False
        return hmac.compare_digest(pbkdf2_hash(password, salt, int(rounds)), hashed)
    except (ValueError, TypeError):
        return False


def sha1_b64(password: str) -> str:
    """base64 of the password's SHA-1, unsalted: the one hash GoCD's password-file sign-in reads that the standard
    library makes (its others are bcrypt's and PBKDF2's in its own shape); weak against a guess, so its file is kept in
    its own volume alone."""
    return base64.b64encode(hashlib.sha1(password.encode("utf-8")).digest()).decode("ascii")


@dataclass
class Pace:
    """The clocks a carry waits with, a test's where given."""

    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    wall: Callable[[], float] = time.time


@dataclass
class _Held:
    """What the plugin keeps in memory while it lives, shared by the registry's copies: the last hosts() answer and the
    plans it asked for, by plan id (who, what, where), until carried or expired."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    hosts: tuple | None = None  # (when, answer)
    pending: dict = field(default_factory=dict)


def _noop(_line: str) -> None:
    return None


class ContainedService(MachinePlugin):
    """The base of a service plugin. A subclass spreads these words into its own (`HOOKS = (*ContainedService.HOOKS,
    ...)`; READ_HOOKS and PAGE_ONLY_HOOKS add up along the class line), calls `ContainedService.__init__(self, pace)`,
    and gives `spec_for`; `ready`, `lan_ready`, `after` and `address` when its software says more. Its own status merges
    `service_status()`."""

    NEEDS_LOOPBACK = True  # its own client sends a token over plain http to this machine alone (the CI plugins')
    LAN_FIRST = True  # Install… may open it to your network at once; False: this PC alone until lan_ready says yes
    SERVICE = "ci"  # the name a service of its gets unless you give another
    SYSTEMS: tuple = ("linux",)  # the systems its recipe has images for
    DEFAULT_MEMORY_MB = 2048
    HOOKS = (*MachinePlugin.HOOKS, HOSTS, INSTALL, CHANGE, CARRY, LOG, FORGET)
    READ_HOOKS = (HOSTS, LOG)
    PAGE_ONLY_HOOKS = (INSTALL, CHANGE, CARRY, LOG, FORGET)
    JOB_HOOKS = (CARRY,)
    CANCEL_HOOKS = (CARRY,)
    ASKS = (("", C.HOSTING, "where its service can run, and how exactly each target takes it"),
            ("", C.HOSTED, "its service's state"), ("", C.HOSTED_LOGS, "its service's log, on your click"),
            ("", C.PLAN, "a plan of a change you asked for, held for your approval"),
            ("", C.PLAN_WORDS, "whether you approved it"), ("", C.APPLY, "the approved plan carried out"),
            ("", C.WORK, "its lines"), ("", C.CANCEL, "your Cancel"), ("", C.DECLINE, "a plan you left"),
            ("", C.HOSTED_FILE, "a file its recipe names"),
            ("", C.RELEASE, "its services stopped when you turn it off"))

    def __init__(self, pace: Pace | None = None):
        self._pace = pace or Pace()
        self._held = _Held()

    # -- what a subclass says -------------------------------------------------------------------------------------------
    def spec_for(self, system: str, name: str, options: Mapping) -> ServiceSpec:
        """Its recipe for that system: options are `lan` (bool), `memory_mb` (0: its own default), `ports` (host ports in
        its recipe's order; none: its own), `fit` (True: only for reading the fit, so a seed may be left out) and, at
        Install… (1.95.0), `target`: the target's row as its container plugin answered it (its os_build and mechanism),
        so that a recipe with several pins for a part picks one with containers.choose_pin."""
        raise Refusal(f"{self.title or self.name} has no recipe for {system}")

    def ready(self, hosted: Mapping) -> tuple[bool, str]:
        """Whether its software answers (its own client, at the port's here), and why not."""
        return True, ""

    def lan_ready(self, hosted: Mapping) -> tuple[bool, str]:
        """Whether it may be opened to your network now (its sign-in is on), and why not."""
        return True, ""

    def after(self, action: str, hosted: Mapping, line: Callable[[str], None]) -> list[str]:
        """Its own steps after an action carried out well (its lines)."""
        return []

    def address(self, hosted: Mapping | None = None) -> str:
        """Where its own API is asked: its placement's first port at its here ("" when nothing is placed). A subclass's
        URL setting wins over this."""
        if hosted:
            ports = [p for p in hosted.get("ports") or [] if isinstance(p, Mapping) and p.get("here")]
            if ports:
                return str(ports[0]["here"])
        placed = self.placement()
        here = (placed or {}).get("here") or {}
        return str(next(iter(here.values()), "")) if isinstance(here, Mapping) else ""

    # -- small parts ----------------------------------------------------------------------------------------------------
    @property
    def KEEPS(self):  # noqa: N802 - read as a declared word
        return ((self._services_var(), "where its services were placed: which container plugin, target and image"),)

    def _services_var(self) -> str:
        return f"{self.name.upper().replace('-', '_')}_SERVICES"

    def _title(self) -> str:
        return self.title or self.name

    def _need_page(self, hook: str) -> None:
        who = asking.asker()
        if who != asking.PAGE:
            raise Refusal(f"{self.name}'s {hook} is yours, from its page alone: {who or 'no one'} asked it")

    def _sid(self, name: str) -> str:
        name = str(name or "").strip()
        if not C.NAME.match(name):
            raise Refusal(f"a service's name is lowercase letters, digits and dashes, 16 at most: not {name[:40]!r}")
        return f"{self.name}/{name}"

    def ask_plugin(self, name: str, hook: str, *args):
        """Another plugin's hook asked through the app: the platform's ask(name, hook, args) or the frame's
        ask(name, hook, *args). Holds no lock while it asks."""
        app = self.app
        if app is None:
            raise Refusal(f"{self.name} is not attached: it asks no other plugin")
        import inspect

        try:
            spread = inspect.signature(app.ask).parameters.get("args")
        except (TypeError, ValueError):
            spread = None
        if spread is not None and spread.kind is inspect.Parameter.VAR_POSITIONAL:
            return app.ask(name, hook, *args)
        return app.ask(name, hook, list(args))

    @staticmethod
    def _hosts_in(hooks) -> bool:
        """Whether a plugin's hooks are a container plugin's (hosting, segments and service_plan)."""
        return bool(hooks) and all(h in hooks for h in (C.HOSTING, C.SEGMENTS, C.PLAN))

    def _container_plugins(self) -> dict[str, Mapping]:
        app = self.app
        try:
            faces = dict(app.plugins() or {}) if app is not None else {}
        except Exception:  # noqa: BLE001 - an app that cannot list its plugins: none
            return {}
        return {n: f for n, f in faces.items() if n != self.name and isinstance(f, Mapping)
                and self._hosts_in(f.get("hooks"))}

    def _turned_off(self) -> bool:
        app = self.app
        try:
            return self.name in (app.disabled() if app is not None and callable(getattr(app, "disabled", None))
                                 else ())
        except Exception:  # noqa: BLE001 - a platform that cannot say: not turned off
            return False

    # -- placements, kept through its login ----------------------------------------------------------------------------
    def placements(self) -> dict[str, dict]:
        """Its services' placements as kept through its login, by name: {} when none is (or the login cannot say)."""
        try:
            data = json.loads(Store(self._services_var(), lambda: self.login).text() or "{}")
        except Exception:  # noqa: BLE001 - nothing kept, or not readable: none
            return {}
        out = {}
        for name, row in dict(data.get("services") or {}).items() if isinstance(data, Mapping) else ():
            if isinstance(name, str) and C.NAME.match(name) and isinstance(row, Mapping):
                out[name] = dict(row)
        return out

    def placement(self, name: str | None = None) -> dict | None:
        return self.placements().get(name or self.SERVICE)

    def _keep(self, name: str, row: dict | None) -> str:
        kept = self.placements()
        if row is None:
            kept.pop(name, None)
        else:
            kept[name] = row
        return Store(self._services_var(), lambda: self.login).put(
            json.dumps({"v": 1, "services": kept}, sort_keys=True) if kept else None)

    # -- where it can run -----------------------------------------------------------------------------------------------
    def _specs(self, name: str) -> dict:
        out = {}
        for system in self.SYSTEMS:
            try:
                out[system] = self.spec_for(system, name, {"lan": self.LAN_FIRST, "fit": True}).as_dict()
            except Refusal:
                continue
        return out

    def _offer(self, t: Mapping, plugin: str, title: str) -> str:
        """Why a target is not offered for Install… ("" when it is)."""
        if not t.get("here", True):
            return f"{t.get('id')} is not on this machine: only this machine's engines host its service"
        if t.get("state") != "ready":
            return f"{t.get('title') or t.get('id')} is {t.get('state')}: {t.get('why') or 'not ready'} (nothing here starts it)"
        fit = t.get("fit")
        if not isinstance(fit, Mapping):
            return f"its recipe has no {t.get('system')} image"
        if fit.get("takes"):
            return f"it cannot take {self._title()}: {fit['takes']}"
        if t.get("unset"):  # 1.95.0: places and sizes of yours its container plugin needs, set on its page first
            return (f"set {', '.join(str(x) for x in t['unset'])} for {t.get('id')} on {title}'s page first: Liminal "
                    "picks none of them for you")
        if self.NEEDS_LOOPBACK and not loopback(str(t.get("reach") or "")):
            return (f"its API would be asked at {t.get('reach')} over plain http, and {self._title()}'s token goes "
                    "over plain http to this machine alone")
        if self.name not in (t.get("granted") or []):
            return f"{title} has not let {self._title()} run its services on {t.get('id')} yet: Let it… on its page"
        return ""

    def hosts(self, fresh=False) -> dict:
        """Where its service can run: each container plugin and its targets, each with its fit for this plugin's recipe
        and whether Install… is offered there (and why not); the container plugins the platform knows that are not
        active, with why; its services as they host them; its placements. Kept READ_S; starts nothing."""
        now = self._pace.clock()
        with self._held.lock:
            kept = self._held.hosts
        if kept is not None and not fresh and now - kept[0] < C.READ_S:
            return kept[1]
        specs = self._specs(self.SERVICE)
        rows, services = [], []
        attached = self._container_plugins()
        for name in attached:
            try:
                answer = self.ask_plugin(name, C.HOSTING, self.name, specs)
            except Exception as e:  # noqa: BLE001 - one that refuses is said, in its words
                rows.append({"plugin": name, "title": name, "state": "refused", "why": str(e)[:300], "page": f"#{name}",
                             "targets": [], "runtime": ""})
                continue
            if not isinstance(answer, Mapping):
                continue
            title = str(answer.get("title") or name)
            targets = []
            for t in answer.get("targets") or []:
                if isinstance(t, Mapping):
                    targets.append({**t, "offer": self._offer(t, name, title)})
            rows.append({"plugin": name, "title": title, "state": "active", "why": "", "page": f"#{name}",
                         "runtime": str(answer.get("runtime") or ""), "targets": targets})
            for s in answer.get("services") or []:
                if isinstance(s, Mapping) and str(s.get("sid", "")).startswith(self.name + "/"):
                    services.append(dict(s))
        app = self.app
        known = getattr(app, "known_plugins", None) if app is not None else None
        try:
            others = list(known()) if callable(known) else []
        except Exception:  # noqa: BLE001 - a platform that cannot say: none
            others = []
        state_of = getattr(app, "plugin_state", None) if app is not None else None
        for p in others:
            pname = str(getattr(p, "name", ""))
            if not pname or pname == self.name or pname in attached:
                continue
            if not self._hosts_in(tuple(getattr(p, "HOOKS", ()) or ())):
                continue
            said = {}
            if callable(state_of):
                try:
                    said = dict(state_of(pname) or {})
                except Exception:  # noqa: BLE001 - not said
                    said = {}
            why = str(said.get("why") or "") or "its page says why"
            rows.append({"plugin": pname, "title": str(getattr(p, "title", "") or pname),
                         "state": str(said.get("state") or "not active"), "why": f"not active: {why}",
                         "page": str(said.get("page") or f"#{pname}"), "runtime": str(getattr(p, "RUNTIME", "")),
                         "targets": []})
        rows.sort(key=lambda r: (r["state"] != "active", r["runtime"] != "docker", r["plugin"]))
        out = {"plugin": self.name, "plugins": rows, "services": services, "placed": self.placements(),
               "service_mode": C.SERVICE_MODE_WORDS}
        with self._held.lock:
            self._held.hosts = (now, out)
        return out

    def _forget_hosts(self) -> None:
        with self._held.lock:
            self._held.hosts = None

    # -- the plans you ask for --------------------------------------------------------------------------------------------
    def _approval(self, plugin: str, plan: Mapping, action: str, name: str, extra: Mapping) -> dict:
        pid = str(plan.get("plan") or "")
        if not pid:
            raise Refusal(f"{plugin} answered no plan: {plan.get('refused') or plan}"[:300])
        with self._held.lock:
            self._held.pending[pid] = {"plugin": plugin, "action": action, "name": name, **dict(extra)}
            del_keys = list(self._held.pending)[:-32]
            for k in del_keys:
                del self._held.pending[k]
        title = str(plan.get("title") or f"{action} {self._title()}")
        said = (f"{title}: approve it on {plugin}'s page (Waiting for your answer), then Carry it out… here")
        answer = C.approval_answer(plugin, list(plan.get("approve") or [{"plugin": plugin, "plan": pid}]),
                                   {"hook": CARRY, "args": [plugin, pid], "job": True}, said)
        answer.update({"plan": pid, "title": title})
        return answer

    def service_install(self, plugin, target, name="ci", lan="yes", boot="no", memory_mb=0, *ports) -> dict:
        """Install… on a container plugin's target, from its page alone: its recipe for that target's system, asked as
        that plugin's plan; answered with the plans you approve and the job that carries them out."""
        self._need_page(INSTALL)
        sid = self._sid(name)
        name = sid.split("/", 1)[1]
        if str(boot) not in ("no", ""):
            raise Refusal(C.SERVICE_MODE_WORDS)
        if str(lan) not in ("yes", "no"):
            raise Refusal("your network is yes (published on every address) or no (this PC alone)")
        if str(lan) == "yes" and not self.LAN_FIRST:
            raise Refusal(f"{self._title()} is installed on this PC alone first: once its sign-in answers, Expose… "
                          "opens it to your network")
        try:
            memory = int(memory_mb or 0)
            host_ports = [int(p) for p in ports if str(p).strip() != ""]
        except (TypeError, ValueError):
            raise Refusal("memory and ports are whole numbers") from None
        if memory < 0:
            raise Refusal("memory is 0 (its own) or more megabytes")
        placed = self.placement(name)
        if placed and placed.get("state") == INSTALLED:
            raise Refusal(f"{sid} is placed already on {placed.get('plugin')}'s {placed.get('target')}: change it there, "
                          "or Remove… it first")
        info = self.hosts(fresh=True)
        row = next((r for r in info["plugins"] if r["plugin"] == str(plugin)), None)
        if row is None:
            raise Refusal(f"{str(plugin)[:40]!r} is no container plugin here")
        if row["state"] != "active":
            raise Refusal(f"{row['title']}: {row['why']}")
        t = next((x for x in row["targets"] if x.get("id") == str(target)), None)
        if t is None:
            raise Refusal(f"{row['title']} has no target {str(target)[:40]!r}")
        if t["offer"]:
            raise Refusal(t["offer"])
        spec = self.spec_for(str(t.get("system")), name, {"lan": str(lan) == "yes", "memory_mb": memory,
                                                          "ports": host_ports, "target": dict(t)})
        spec = ServiceSpec.of(spec.as_dict()) if isinstance(spec, ServiceSpec) else ServiceSpec.of(spec)
        unread = unread_pins(spec)
        if unread:
            raise Refusal(f"{', '.join(unread)}: its image is not pinned by digest yet (read from its registry for the "
                          "plugin's release): nothing is installed from a pin not read")
        plan = self.ask_plugin(str(plugin), C.PLAN, "install", sid, spec.as_dict(), str(target), {})
        return self._approval(str(plugin), plan, "install", name,
                              {"target": str(target), "system": spec.system, "lan": str(lan) == "yes",
                               "memory_mb": memory, "ports": host_ports})

    def service_change(self, action, name="ci", choice="") -> dict:
        """Start…, Stop…, Restart…, Update…, Roll back…, Expose…, Remove… or Delete its data… of a placed service, from
        its page alone, asked as its container plugin's plan (choice: rollback's as-is or backup, expose's on or off,
        delete_data's keep or delete)."""
        self._need_page(CHANGE)
        sid = self._sid(name)
        name = sid.split("/", 1)[1]
        act = str(action or "")
        if act not in CHANGES:
            raise Refusal(f"a change is one of {', '.join(CHANGES)}, not {act[:20]!r}")
        if act == "boot":
            raise Refusal(C.SERVICE_MODE_WORDS)
        choice = str(choice or "")
        if act in CHOICES and choice and choice not in CHOICES[act]:
            raise Refusal(f"{act} takes {' or '.join(CHOICES[act])}, not {choice[:20]!r}")
        placed = self.placement(name)
        if not placed:
            raise Refusal(f"{sid} is placed nowhere: Install… it first")
        plugin = str(placed.get("plugin") or "")
        if placed.get("state") == REMOVED and act != "delete_data":
            raise Refusal(f"{sid} was removed and its data kept: Install… again uses its data, or Delete its data…")
        spec, options, target = None, {}, ""
        if act == "update":
            spec = self.spec_for(str(placed.get("system") or "linux"), name,
                                 {"lan": bool(placed.get("lan")), "memory_mb": int(placed.get("memory_mb") or 0),
                                  "ports": list(placed.get("ports") or [])})
            spec = ServiceSpec.of(spec.as_dict())
            unread = unread_pins(spec)
            if unread:
                raise Refusal(f"{', '.join(unread)}: its image is not pinned by digest yet: no update to it")
            pins = {p.name: p.image.digest for p in spec.parts}
            if pins == dict(placed.get("image") or {}):
                raise Refusal(f"{sid} runs this plugin's pins already: an update comes with a release that pins newer "
                              "images")
            spec = self._update_first(plugin, sid, spec).as_dict()
        elif act == "expose":
            on = (choice or "on") == "on"
            options = {"lan": on}
            if on:
                hosted = self.ask_plugin(plugin, C.HOSTED, sid)
                ok, why = self.lan_ready(hosted if isinstance(hosted, Mapping) else {})
                if not ok:
                    raise Refusal(f"{self._title()} is not opened to your network yet: {why or 'its sign-in does not answer'}")
        elif act == "rollback":
            options = {"choice": choice or "as-is"}
        elif act == "delete_data":
            options = {"backups": choice or "keep"}
            target = str(placed.get("target") or "")
        plan = self.ask_plugin(plugin, C.PLAN, act, sid, spec, target, options)
        return self._approval(plugin, plan, act, name, {"target": str(placed.get("target") or ""),
                                                        "options": options})

    def _update_first(self, plugin: str, sid: str, spec: ServiceSpec) -> ServiceSpec:
        """1.95.0: an update whose recipe both adds a part (Jenkins' agent, once its secret is set) and changes a part
        it runs is two plans in turn (the container plugin refuses them as one): this one updates the parts it runs,
        and the next Update… adds the new part. A recipe that only adds, or only changes, goes as it is."""
        try:
            hosted = self.ask_plugin(plugin, C.HOSTED, sid)
        except Exception:  # noqa: BLE001 - not read: asked as it is, and the container plugin says
            return spec
        running = {str(p.get("name")) for p in (hosted or {}).get("parts") or [] if isinstance(p, Mapping)}
        if not running or all(p.name in running for p in spec.parts):
            return spec
        kept = tuple(p for p in spec.parts if p.name in running)
        placed = (self.placement(sid.split("/", 1)[1]) or {}).get("image") or {}
        if not kept or all(placed.get(p.name) == p.image.digest for p in kept):
            return spec  # only adds: one plan
        return ServiceSpec.of({**spec.as_dict(), "parts": [p.as_dict() for p in kept]})

    # -- carrying it out -------------------------------------------------------------------------------------------------
    def service_carry(self, plugin, plan, log=None) -> dict:
        """Carries out a plan you approved, as a job you can cancel: refused before its first line unless approved and
        not expired; its container plugin's lines followed, your Cancel forwarded; then its software waited for, the
        placement kept through its login, and its own steps after."""
        self._need_page(CARRY)
        plugin, plan = str(plugin or ""), str(plan or "")
        if plugin not in self._container_plugins():
            raise Refusal(f"{plugin[:40]!r} is no active container plugin here")
        words = self.ask_plugin(plugin, C.PLAN_WORDS, plan)
        if not isinstance(words, Mapping) or words.get("approved") is not True:
            raise Refusal(f"{(words or {}).get('title') or plan}: not approved yet: approve it first (each plan the "
                          "dialog names, or on the container plugin's page)")
        sid = str(words.get("sid") or "")
        if not sid.startswith(self.name + "/"):
            raise Refusal(f"{plan} is a plan of {sid or 'another service'}, not of {self.name}'s")
        say = log if callable(log) else _noop
        cancelled = (lambda: bool(getattr(log, "cancelled", False))) if log is not None else (lambda: False)
        act = str(words.get("action") or "")
        name = sid.split("/", 1)[1]
        with self._held.lock:
            pending = dict(self._held.pending.get(plan) or {})
        started = self.ask_plugin(plugin, C.APPLY, plan)
        work = str((started or {}).get("work") or "")
        after, asked_cancel, page = 0, False, {}
        while True:
            page = self.ask_plugin(plugin, C.WORK, work, after)
            for line in page.get("lines") or []:
                say(str(line))
            after = int(page.get("next") or after)
            if page.get("done"):
                break
            if cancelled() and not asked_cancel:
                self.ask_plugin(plugin, C.CANCEL, work)
                say("your Cancel was passed on: it stops between its steps, undoing what it made")
                asked_cancel = True
            self._pace.sleep(FOLLOW_S)
        with self._held.lock:
            self._held.pending.pop(plan, None)
        self._forget_hosts()
        answer = page.get("answer") if isinstance(page.get("answer"), Mapping) else {}
        if page.get("ok") is not True:
            return {"said": f"{words.get('title') or act}: {answer.get('said') or 'it did not end well'}",
                    "ok": False, "lines": [f"work {work}"]}
        hosted = {}
        if act != "delete_data":
            try:
                hosted = dict(self.ask_plugin(plugin, C.HOSTED, sid) or {})
            except Exception:  # noqa: BLE001 - not read now: kept as asked
                hosted = {}
        lines = [f"work {work}"]
        lines.append(self._placed_after(act, name, plugin, words, pending, hosted))
        said = str(answer.get("said") or words.get("title") or act)
        if act in WAITS_READY:
            ok, why = self._wait_ready(hosted, cancelled)
            if ok:
                say(f"{self._title()} answers at {self.address(hosted) or 'its port'}")
            else:
                said += f"; {self._title()} does not answer yet: {why}"
                lines.append(f"{self._title()} does not answer yet: {why}")
        if act != "delete_data":
            try:
                lines += [str(x) for x in self.after(act, hosted, say) or []]
            except Refusal as e:
                lines.append(f"its own step after {act}: {e}")
        return {"said": said, "ok": True, "lines": lines}

    def _wait_ready(self, hosted: Mapping, cancelled) -> tuple[bool, str]:
        deadline = self._pace.clock() + READY_S
        why = ""
        while True:
            try:
                ok, why = self.ready(hosted)
            except Exception as e:  # noqa: BLE001 - its client's trouble, in words
                ok, why = False, str(e)[:200]
            if ok:
                return True, ""
            if cancelled() or self._pace.clock() >= deadline:
                return False, why or "it did not answer in time"
            self._pace.sleep(READY_EVERY_S)

    def _placed_after(self, act: str, name: str, plugin: str, words: Mapping, pending: Mapping,
                      hosted: Mapping) -> str:
        kept = self.placement(name) or {}
        spec = words.get("spec") if isinstance(words.get("spec"), Mapping) else None
        here = {str(p.get("name")): str(p.get("here")) for p in hosted.get("ports") or []
                if isinstance(p, Mapping) and p.get("here")}
        if act == "install":
            parts = (spec or {}).get("parts") or []
            row = {"plugin": plugin, "target": str(words.get("target") or pending.get("target") or ""),
                   "sid": f"{self.name}/{name}", "system": str((spec or {}).get("system") or pending.get("system") or ""),
                   "image": {str(p.get("name")): str((p.get("image") or {}).get("digest", "")) for p in parts},
                   "ports": [int(x.get("host")) for p in parts for x in p.get("ports") or []],
                   "lan": any(bool(x.get("lan")) for p in parts for x in p.get("ports") or []),
                   "memory_mb": int(pending.get("memory_mb") or 0), "boot": False, "state": INSTALLED,
                   "here": here, "made": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._pace.wall())),
                   "platform": str(hosted.get("platform") or "")}
            self._keep(name, row)
            return f"kept: {row['sid']} on {plugin}'s {row['target']}"
        if not kept:
            return "no placement was kept for it"
        if act == "update" and spec:
            kept["image"] = {str(p.get("name")): str((p.get("image") or {}).get("digest", "")) for p in spec.get("parts") or []}
        elif act == "rollback":
            kept["image"] = {}  # its previous container's, as the runtime reads it
        elif act == "expose":
            kept["lan"] = bool(((pending.get("options") or {}) or (words.get("options") or {})).get("lan"))
        elif act == "remove":
            kept["state"] = REMOVED
        elif act == "delete_data":
            self._keep(name, None)
            return f"forgotten: {self.name}/{name}'s placement (its data deleted)"
        if here:
            kept["here"] = here
        self._keep(name, kept)
        return f"kept: {self.name}/{name} {kept['state']}"

    # -- reads and forgetting --------------------------------------------------------------------------------------------
    def service_log(self, name="ci", part="", lines=100) -> dict:
        """Its service's last lines, from its container plugin, for its page alone (a log may hold a secret)."""
        self._need_page(LOG)
        sid = self._sid(name)
        placed = self.placement(sid.split("/", 1)[1])
        if not placed:
            raise Refusal(f"{sid} is placed nowhere")
        return self.ask_plugin(str(placed.get("plugin")), C.HOSTED_LOGS, sid, str(part or ""), lines)

    def service_forget(self, name="ci") -> dict:
        """Forgets a placement whose target or service is gone, from its page alone: deletes nothing, and says so."""
        self._need_page(FORGET)
        sid = self._sid(name)
        name = sid.split("/", 1)[1]
        placed = self.placement(name)
        if not placed:
            raise Refusal(f"{sid} is placed nowhere: nothing to forget")
        plugin = str(placed.get("plugin") or "")
        if plugin in self._container_plugins() and placed.get("state") == INSTALLED:
            try:
                state = str((self.ask_plugin(plugin, C.HOSTED, sid) or {}).get("state", ""))
            except Exception:  # noqa: BLE001 - not answered: taken as gone
                state = "missing"
            if state != "missing":
                raise Refusal(f"{sid} is still there on {plugin} ({state}): Remove… it instead")
        self._keep(name, None)
        self._forget_hosts()
        return {"said": f"{sid}'s placement forgotten: nothing was deleted (a volume left on its engine stays, its "
                        "container plugin's Kept data lists it)", "ok": True}

    # -- its end ----------------------------------------------------------------------------------------------------------
    def release_services(self) -> list[str]:
        """Asks release_owned of each container plugin hosting one of its services: its "page" services stopped."""
        lines = []
        plugins = sorted({str(r.get("plugin")) for r in self.placements().values()
                          if r.get("state") == INSTALLED and r.get("plugin")})
        attached = self._container_plugins()
        for p in plugins:
            if p not in attached:
                continue
            try:
                said = self.ask_plugin(p, C.RELEASE)
                lines.append(f"{p}: {(said or {}).get('said', 'released')}")
            except Exception as e:  # noqa: BLE001 - said, and let go
                lines.append(f"{p}: {e}")
        return lines

    def detach(self) -> None:
        """Turned off (the platform says it is disabled at its detach): its services released first; a detach for
        invalidity asks nothing. What it kept in memory goes."""
        if self.app is not None and self._turned_off():
            self.release_services()
        with self._held.lock:
            self._held.hosts = None
            self._held.pending.clear()
        super().detach()

    # -- the page ---------------------------------------------------------------------------------------------------------
    def service_present(self) -> bool:
        """Whether a placement is kept (its tray presence, beside a server of your own found)."""
        return any(r.get("state") == INSTALLED for r in self.placements().values())

    def service_valid(self) -> bool:
        """Valid while it can be placed (its recipe has an image for a system) or is placed."""
        return bool(self.SYSTEMS) or bool(self.placements())

    def service_status(self) -> dict:
        """What the base adds to its page: Run it in a container (each container plugin's targets, Install… where
        offered), Its services (state, ports, image; each change's button), Waiting to be carried out; and their
        forms. Never raises."""
        try:
            return self._service_status()
        except Exception as e:  # noqa: BLE001 - a status never raises
            return {"tables": [], "forms": [], "notes": [f"where it can run could not be read: {e}"[:300]]}

    def _service_status(self) -> dict:
        info = self.hosts()
        title = self._title()
        placed = info["placed"]
        rows = []
        for r in info["plugins"]:
            if not r["targets"]:
                rows.append([{"text": r["title"], "sub": r["plugin"]}, "–", {"text": r["state"], "sub": r["why"] or None},
                             "–", {"link": r["page"], "text": "its page"}])
                continue
            for t in r["targets"]:
                fit = t.get("fit") if isinstance(t.get("fit"), Mapping) else {}
                differs = [f"{k}: {a.get('words')}" for k, a in dict(fit.get("parts") or {}).items()
                           if isinstance(a, Mapping) and a.get("fit") == "differs"]
                where = f"{t.get('mechanism', '')} · {t.get('system', '')} · {t.get('reach', '')}"
                button = ({"form": "install", "title": "Install…", "values": {"plugin": r["plugin"], "target": t["id"]},
                           "label": f"Install {title} on {t['id']}"} if not t["offer"] and not placed.get(self.SERVICE)
                          else {"text": "–", "sub": t["offer"] or "placed already"})
                rows.append([{"text": r["title"], "sub": r["plugin"]}, {"text": t.get("id"), "sub": where},
                             {"text": t.get("state"), "sub": t.get("why") or None},
                             {"text": "differs" if differs else "exact" if fit else "–",
                              "sub": "; ".join(differs)[:300] or (t.get("lan_words") or None)}, button])
        tables = [{"title": f"Run {title} in a container", "rows": rows, "columns": [
            {"title": "Container plugin"}, {"title": "Target"}, {"title": "State"}, {"title": "Fit"},
            {"title": "Install"}],
            "empty": "No container plugin is active: turn on Docker (or another container plugin) on the platform.",
            "note": (f"{title} runs only as a container, through the plugin you pick, in its plans you approve; a "
                     f"{title} you installed yourself is found and read as it is. {C.SERVICE_MODE_WORDS}.")}]
        hosted = {str(s.get("name")): s for s in info["services"]}
        srows = []
        for name, p in sorted(placed.items()):
            h = hosted.get(name) or {}
            state = h.get("state") or ("removed, data kept" if p.get("state") == REMOVED else "not read")
            ports = ", ".join(f"{x.get('host')}/{x.get('protocol', 'tcp')} at {x.get('here')}"
                              + (" (your network)" if x.get("lan") else " (this PC)") for x in h.get("ports") or [])
            actions = []
            for act, label in BUTTONS:
                if p.get("state") == REMOVED and act != "delete_data":
                    actions.append("–")
                    continue
                actions.append({"form": act, "title": label, "values": {"name": name}})
            actions.append({"form": "log", "title": "Log…", "values": {"name": name}})
            actions.append({"form": "forget", "title": "Forget…", "values": {"name": name}})
            srows.append([{"text": f"{self.name}/{name}", "sub": f"{p.get('plugin')} · {p.get('target')}"},
                          {"text": state, "sub": h.get("why") or h.get("drift") or None}, ports or "–",
                          ", ".join(f"{k}: {v[:19]}…" for k, v in dict(p.get("image") or {}).items()) or "as it runs",
                          *actions])
        if placed:
            tables.append({"title": "Its services", "rows": srows, "empty": "",
                           "columns": [{"title": "Service"}, {"title": "State"}, {"title": "Ports"},
                                       {"title": "Image"}, *({"title": label.rstrip("…")} for _, label in BUTTONS),
                                       {"title": "Log"}, {"title": "Forget"}],
                           "note": "Each change is a plan of its container plugin's, which you approve; nothing "
                                   "restarts it after a crash; it stops when the platform stops."})
        with self._held.lock:
            pending = dict(self._held.pending)
        if pending:
            tables.append({"title": "Waiting to be carried out", "empty": "", "rows": [
                [p["action"], p["plugin"], pid, {"form": "carry", "title": "Carry it out…",
                                                  "values": {"plugin": p["plugin"], "plan": pid}}]
                for pid, p in pending.items()],
                "columns": [{"title": "Change"}, {"title": "Container plugin"}, {"title": "Plan"},
                            {"title": "Carry"}],
                "note": "Approve each plan on its container plugin's page first (an older platform draws no dialog)."})
        return {"tables": tables, "forms": self._service_forms()}

    def _port_fields(self) -> list[dict]:
        try:
            spec = self.spec_for(self.SYSTEMS[0], self.SERVICE, {"lan": self.LAN_FIRST, "fit": True})
        except Refusal:
            return []
        return [{"name": f"port_{p.name}", "label": f"Port ({p.about or p.name})", "type": "number", "min": 1024,
                 "max": 65535, "value": p.host} for p in spec.ports()]

    def _service_forms(self) -> list[dict]:
        title = self._title()
        lan_choices = ([{"value": "yes", "title": "yes", "note": "published on every address (asked again)"}]
                       if self.LAN_FIRST else []) + [{"value": "no", "title": "no", "note": "this PC alone"}]
        forms = [{"id": "install", "hook": INSTALL, "title": f"Install {title} in a container", "submit": "Review",
                  "fields": [{"name": "plugin", "label": "Container plugin", "type": "fixed"},
                             {"name": "target", "label": "Target", "type": "fixed"},
                             {"name": "name", "label": "Name", "type": "text", "value": self.SERVICE},
                             {"name": "lan", "label": "Your network", "type": "choice", "choices": lan_choices,
                              "value": lan_choices[0]["value"]},
                             {"name": "boot", "label": "At boot", "type": "choice",
                              "choices": [{"value": "no", "title": "no", "note": C.SERVICE_MODE_WORDS}], "value": "no"},
                             {"name": "memory_mb", "label": "Memory (MB)", "type": "number", "min": 0,
                              "value": self.DEFAULT_MEMORY_MB},
                             *self._port_fields()],
                  "confirm": {"title": "Plan {name} on {target}?",
                              "words": "Its container plugin makes a plan and holds it: nothing changes until you "
                                       "approve it, in that plugin's words.", "yes": "Plan it"}}]
        for act, label in (("start", "Start"), ("stop", "Stop"), ("restart", "Restart"), ("update", "Update"),
                           ("rollback", "Roll back"), ("expose", "Expose"), ("remove", "Remove"),
                           ("delete_data", "Delete the data of")):
            fields = [{"name": "action", "label": "Change", "type": "fixed", "value": act},
                      {"name": "name", "label": "Service", "type": "fixed"}]
            if act in CHOICES:
                fields.append({"name": "choice", "label": "How", "type": "choice",
                               "choices": [{"value": c, "title": c} for c in CHOICES[act]], "value": CHOICES[act][0]})
            forms.append({"id": act, "hook": CHANGE, "title": f"{label} {title}", "submit": "Review", "fields": fields,
                          "confirm": {"title": f"{label} {{name}}?", "words": "Planned by its container plugin, and "
                                      "done only once you approve that plan.", "yes": "Plan it",
                                      "danger": act in ("remove", "delete_data")}})
        forms.append({"id": "carry", "hook": CARRY, "title": "Carry out an approved plan", "job": True,
                      "fields": [{"name": "plugin", "label": "Container plugin", "type": "fixed"},
                                 {"name": "plan", "label": "Plan", "type": "fixed"}],
                      "confirm": {"title": "Carry out {plan}?", "words": "Refused unless you approved it.",
                                  "yes": "Carry it out"}})
        forms.append({"id": "log", "hook": LOG, "title": f"{title}'s log",
                      "fields": [{"name": "name", "label": "Service", "type": "fixed"}]})
        forms.append({"id": "forget", "hook": FORGET, "title": "Forget a placement",
                      "fields": [{"name": "name", "label": "Service", "type": "fixed"}],
                      "confirm": {"title": "Forget {name}?", "words": "Only the placement kept through your login is "
                                  "forgotten: nothing is deleted.", "yes": "Forget it"}})
        return forms


__all__ = ["ContainedService", "Pace", "UNREAD", "loopback", "pbkdf2_hash", "pbkdf2_check", "sha1_b64",
           "unread_pins"]
