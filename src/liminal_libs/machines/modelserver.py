"""What a model server's plugin is (1.62.0; the user, 2026-11-16: "i need 3 plugins for inference serving local models
on the platform, :: lama.cpp, ollama and vLLM"; "also remote connection to instances if possible"; "the plugins manage
the services, the app can be started @ boot like a service, ports can be configured via the plugin, the plugin should
report conflicts.").

`ModelServer` is the base, under AiPlugin (machines/ai.py), of llama.cpp's, Ollama's and vLLM's plugins: drawn under
the platform's AI heading in the Inference group. It holds instances (`Instance`), each one server:

- local: a server this plugin runs here, started and stopped by a click as a windowless child it owns
  (children.Child: its log home/logs/<name>.log, its pidfile home/run/<name>.pid), stopped when the platform stops or
  the plugin is turned off, unless it starts at boot: then its start and its stop are its scheduled task's or its
  systemd user unit's (autostart, running `python -m liminal_libs.machines.launch serve`, whose own log is
  home/logs/<name>.boot.log), and the plugin attaches to what the system started;
- found: a server found on this machine, started elsewhere (the Ollama inside WSL answering at this PC's own loopback
  address through WSL's relay): asked, never started or stopped from here;
- remote: another machine's, by its address and an optional key; plain http to another machine is asked twice.

Instances are kept through the Login as one JSON pair (`Instances`, LIMINAL_AI_<NAME>_INSTANCES); a key is its own
secret pair (LIMINAL_AI_<NAME>_<INSTANCE>_KEY), never in the JSON, an answer, a log, an error or a command line. A
port is each instance's own setting, the maker's by default (DEFAULT_PORT), and conflicts are reported before a start
and in the status (`conflict`): a port outside 1024 to 65535, one of the four Liminal apps' pages, another instance's
(this plugin's, or another inference plugin's, asked through the platform: `serving`), one held by another program
(its name and pid, from this system's socket table), WSL's relay.

What is read and when (A.9, revisions S3 and S10):
- `status()` (Main) and `state()` read kept readings only: the socket table (at most every TABLE_S, one for every
  model server plugin of this process), the pidfiles, the plugin's own children, the boot registrations (one command
  in a thread, at most every BOOT_S, only when an instance starts at boot). Nothing is asked of an instance over the
  network and nothing is run for them.
- `conflict(instance, port, ask=True)`, asked by a user's click (a start, an add, a change), also connects to this
  machine's port, for "nothing listed, yet it answers".
- The Models tab (`models()`, asked every 15 s while it is shown, never otherwise) asks the shown instance once per
  SEEN_S through the subclass's `look()`; `models_of()` asks it now.
- `serving()`, what another plugin asks through the platform (a harness for its page, another model server for a
  port), asks nothing over the network, runs nothing (the boot registrations as they were last read, never read
  again for it) and never calls `conflict()`; no lock is held while this plugin asks another.

A subclass says how its server is started (`launch`: its command and environment, its bind address and port, its
privacy switches, its key by environment, never on its command line), how it is recognised and its models listed
(`look`), the words of its start and its sharing (`start_words`, `share_words`), its own model cells
(`model_cells`, under MODEL_COLUMNS) and what it adds to its Main and Models pages (`main_more`, `more`), besides
what every AI plugin says (package, installed, install_into, remove_from, runs_here)."""
from __future__ import annotations

import dataclasses
import json
import math
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Iterable, Mapping

from .. import instances, layout, ports, resources
from ..apps.authorization import Unauthorized
from ..apps.tabs import Tab
from ..sources import keys as keys_mod
from . import autostart, children, gpu, linux
from .ai import (_UNREAD, LASTING, LINES_MOST, SERVING, SETTING_NAME, STEM, TEXT_MOST, AiPlugin, Installed, Refusal,
                 Run, Setting, _and, exactly, platform_folder)
from .ai import _which as _DEFAULT_WHICH  # an Outside's own `which`: the real lookup
from .ai import _words as _fault_words
from .endpoint import ACCEPT_PLAIN, ANSWER_CHARS, CHAT_S, LOOK_S, Endpoint, EndpointError, base_url, parse_address
from .firewall import app_ports
from .plugin import CommandError
from .world import size_words

__all__ = ["ACCEPT_PLAIN", "ACCEPT_SHARE", "BOOT_S", "Holder", "Instance", "Instances", "Kept", "MAX_INSTANCES",
           "ModelServer", "PORTS", "RELAYS", "SEEN_S", "SERVING", "Seen", "ServerRun", "Setting", "TABLE_S", "WHERE",
           "held_words", "holders", "reserved"]

WHERE = ("local", "found", "remote")  # run here; found on this machine; another machine's
MAX_INSTANCES = 16  # instances a plugin holds at most
PORTS = (1024, 65535)  # the ports a server of this machine may be given
ACCEPT_SHARE = "accept_share"  # a share beyond this machine, its second confirmation
RELAYS = ("wslrelay.exe",)  # WSL's relay: a server inside a WSL distribution, reached at this PC's loopback address
TABLE_S = 5.0  # seconds the socket table is kept
BOOT_S = 60.0  # seconds the boot registrations' states are kept (read in a thread)
SEEN_S = 15.0  # seconds what an instance answered is kept (the Models tab is asked every 15 s while it is shown)
LOOPBACK = "127.0.0.1"
VERSION = 1  # of the value the instances are kept in
PROMPT_CHARS = 4000  # characters of a prompt Try it sends (M10)
TRY_TOKENS = 512  # tokens Try it asks for at the most (its answer is cut at endpoint.ANSWER_CHARS besides)
V1 = "/v1"  # what every OpenAI-compatible ask adds to an instance's address (/v1/models, /v1/chat/completions)
UP = ("running", "starting")  # the states of a local instance that runs, or whose task or unit runs it
MODEL_CHARS = 200  # characters of a model's name
LOG_LINES = 40  # lines of a log shown
BOOT_LINES = 10  # lines of a boot registration's own log shown after them
WHERE_WORDS = {"local": "run here", "found": "found on this machine", "remote": "another machine's"}
STATES = ("running", "starting", "stopped", "exited", "answering", "silent", "unasked")
YES = ("yes", "on", "true")
NO = ("no", "off", "false")
MIRRORED = ("WSL under mirrored networking, or another user's program")
UNENCRYPTED = "Its key and everything sent to it travel unencrypted between the two machines."  # plain http's words


def _words(e: BaseException) -> str:
    """A fault in words on one line (ai._words), a lookup's and an endpoint's as they are too."""
    return _fault_words(e, (ValueError, LookupError, CommandError, EndpointError))


def _every(command) -> bool:
    """Every process is reported (the socket table's owners on Linux are the processes a probe reports)."""
    return True


def _scalar(value):
    """A setting's value as it is kept: a whole number, a finite number, a bool, or a text of TEXT_MOST characters at
    most without a control character; None for anything else."""
    if isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        text = value.strip()
        if text and len(text) <= TEXT_MOST and not instances.has_control(text):
            return text
    return None


def _settings(given) -> dict:
    """An instance's settings as they are kept: by a setting's name, a value each (an empty one left out)."""
    out: dict = {}
    if not isinstance(given, Mapping):
        return out
    for name, value in given.items():
        if isinstance(name, str) and SETTING_NAME.fullmatch(name):
            kept = _scalar(value)
            if kept is not None:
                out[name] = kept
    return out


def _when(at: float, now: float) -> str:
    """A moment in words: its time today, else its day and time."""
    if not at:
        return ""
    stamp = time.localtime(at)
    if time.localtime(now)[:3] == stamp[:3]:
        return time.strftime("%H:%M", stamp)
    return time.strftime("%Y-%m-%d %H:%M", stamp)


def _iso(at: float) -> str:
    return instances.now_iso(lambda: at) if at else ""


# -- an instance and how instances are kept ----------------------------------------------------------------------------
@dataclass(frozen=True)
class Instance:
    """One server of a plugin: its `name`, `where` it is (local, found, remote), its `host` (this machine's loopback
    address for a local and a found one; another machine's for a remote one), its `port` (0: the maker's, the plugin's
    DEFAULT_PORT), a `title`, when it was added (`at`); a remote one's `tls` (https), `prefix` (the path its asks go
    under) and `plain` (plain http to it was accepted); a local one's `shared` (it listens beyond this machine) and
    `boot` (it starts at boot); `keyed` (a key is kept for it, as its own pair) and the tool's main `settings`, by a
    setting's name. ValueError when it cannot be one. Two are equal when every field is, its settings too; its hash
    leaves its settings out (they are a mapping), so an instance can be a key or in a set."""

    name: str
    where: str = "local"
    host: str = LOOPBACK
    port: int = 0
    title: str = ""
    at: str = ""
    tls: bool = False
    prefix: str = ""
    plain: bool = False
    shared: bool = False
    boot: bool = False
    keyed: bool = False
    settings: Mapping = field(default_factory=dict, hash=False)

    def __post_init__(self):
        name = str(self.name or "")
        if not instances.NAME.fullmatch(name):
            raise ValueError("an instance's name is lowercase letters, digits and dashes, 32 at most: not "
                             f"{name[:40]!r}")
        if self.where not in WHERE:
            raise ValueError(f"an instance is local, found or remote, not {str(self.where)[:20]!r}")
        port = self.port
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError(f"an instance's port is a whole number from 0 (the maker's) to 65535, not {port!r}")
        for flag in ("tls", "plain", "shared", "boot", "keyed"):
            if not isinstance(getattr(self, flag), bool):
                raise ValueError(f"an instance's {flag} is true or false")
        title = instances.clean_title(self.title)
        at = str(self.at or "")
        if len(at) > 40 or any(ord(c) < 32 for c in at):
            raise ValueError("an instance's time of adding is a moment in ISO form")
        host, tls, prefix, plain = LOOPBACK, False, "", False
        shared, boot = (self.shared, self.boot) if self.where == "local" else (False, False)
        if self.where == "remote":
            if not port:
                raise ValueError("a remote instance names its port")
            host, port, tls, prefix = parse_address(base_url(self.host, port, self.tls, self.prefix), port)
            if instances.is_local(host):
                raise ValueError(f"{host} is this machine: an instance there is found here, not another machine's")
            plain = self.plain and not tls
        for key, value in (("host", host), ("port", port), ("title", title), ("at", at), ("tls", tls),
                           ("prefix", prefix), ("plain", plain), ("shared", shared), ("boot", boot),
                           ("settings", MappingProxyType(_settings(self.settings)))):
            object.__setattr__(self, key, value)

    def kept(self) -> dict:
        """What is kept of it: its name, and every field that differs from the defaults."""
        out: dict = {"name": self.name}
        for f in dataclasses.fields(self):
            if f.name in ("name", "settings"):
                continue
            value = getattr(self, f.name)
            if value != f.default:
                out[f.name] = value
        if self.settings:
            out["settings"] = dict(self.settings)
        return out

    @classmethod
    def of(cls, item) -> "Instance":
        """An instance as it was kept (`kept()`); ValueError (or TypeError) when it is not one."""
        if not isinstance(item, Mapping):
            raise ValueError("an instance is kept as an object")
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in item.items() if k in known})


@dataclass
class Kept:
    """A plugin's instances as they are kept, by name; `problem`: what of the value could not be read, in words."""

    instances: dict = field(default_factory=dict)
    problem: str = ""

    @classmethod
    def of(cls, text) -> "Kept":
        """The instances of a kept value: none for none; a value that cannot be read is said (`problem`) and holds
        none, an instance that cannot be read is left out and said, and MAX_INSTANCES are read at most."""
        if text is None or not str(text).strip():
            return cls()
        try:
            raw = json.loads(text)
        except (TypeError, ValueError) as e:
            return cls(problem=f"what is kept of the instances is not readable ({e}): none is shown until one is "
                               "added again")
        if not isinstance(raw, dict) or not isinstance(raw.get("instances"), list):
            return cls(problem="what is kept of the instances is not a list of them: none is shown until one is added "
                               "again")
        out, left = cls(), 0
        for item in raw["instances"]:
            try:
                inst = Instance.of(item)
            except (TypeError, ValueError):
                left += 1
                continue
            if inst.name in out.instances or len(out.instances) >= MAX_INSTANCES:
                left += 1
                continue
            out.instances[inst.name] = inst
        if left:
            out.problem = f"{left} of the kept instances could not be read and {'is' if left == 1 else 'are'} left out"
        return out

    def text(self) -> str | None:
        """The value kept: {"v": 1, "instances": [...]}; None when there is none (the pair is then forgotten)."""
        if not self.instances:
            return None
        return json.dumps({"v": VERSION, "instances": [i.kept() for i in self.instances.values()]},
                          separators=(",", ":"), ensure_ascii=True)


class Instances(instances.Store):
    """A model server plugin's instances, kept through its login under `variable` (LIMINAL_AI_<NAME>_INSTANCES) as
    one JSON value (Kept.text)."""

    NO_LOGIN = ("a model server's instances are kept through the platform's login, and this plugin has none: open it "
                "on the platform's page")

    def read(self) -> Kept:
        """What is kept now: none when nothing is, or when it cannot be asked (then said as its problem)."""
        try:
            return Kept.of(self.text())
        except Exception as e:  # noqa: BLE001 - a login that cannot say: no instance, said
            return Kept(problem=f"what is kept of the instances could not be read: {_words(e)}")

    def keep(self, kept: Kept) -> str:
        """`kept` kept through the login: where, in the login's words. A Refusal when it is not kept."""
        try:
            return self.put(kept.text())
        except Unauthorized as e:
            raise Refusal(f"the instances are not kept: {e.reason}") from None


# -- who holds a port --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Holder:
    """A program listening on a port of this machine, as this system's socket table says it: its `pid` (0: not
    readable, another user's), its program's `name`, where it can be reached from (`reach`: ports.reach) and whether
    it is WSL's relay."""

    pid: int
    name: str
    reach: str
    relay: bool = False


@dataclass(frozen=True)
class _Table:
    """The socket table as it was read (`at`): its listening sockets and their programs' names, or why it could not
    be read. It answers as a probe does (connections, program_names), so `holders` reads it as it reads one."""

    at: float
    conns: tuple = ()
    names: Mapping = field(default_factory=dict)
    problem: str = ""

    def connections(self) -> list:
        return list(self.conns)

    def program_names(self, pids=None) -> dict:
        wanted = None if pids is None else set(pids)
        return {p: n for p, n in self.names.items() if wanted is None or p in wanted}


# This process's socket tables, shared by its model server plugins (a status, and each other plugin's `serving` that a
# conflict asks, read one table, not one each): [(the probe a table was read through, the table)], the newest first,
# TABLES_KEPT at most. A table is kept by the probe object itself, held here, so a test's stand-in answers for itself.
TABLES_KEPT = 4
_tables: list[tuple[object, _Table]] = []
_probes: list = []  # this system's one probe (resources.default_probe), made when first asked
_tables_lock = threading.Lock()


def holders(port: int, probe) -> list[Holder]:
    """Who listens on `port` of this machine, from a probe's socket table (resources.WindowsProbe, LinuxProbe, or the
    plugin's kept reading of one): nothing is sent anywhere. Each program once, the readable ones first."""
    by: dict[int, set[str]] = {}
    for c in probe.connections():
        if getattr(c, "state", "") != "listening":
            continue
        end = ports.endpoint(getattr(c, "local", ""))
        if end is None or end[1] != port:
            continue
        by.setdefault(int(getattr(c, "pid", 0) or 0), set()).add(end[0])
    named = [p for p in by if p]
    try:
        names = dict(probe.program_names(named)) if named else {}
    except Exception:  # noqa: BLE001 - a program that cannot be named is said by its number
        names = {}
    out = []
    for pid in sorted(by, key=lambda p: (p == 0, p)):
        name = str(names.get(pid) or (f"pid {pid}" if pid else ""))
        out.append(Holder(pid, name, ports.reach(by[pid]), name.lower() in RELAYS))
    return out


def reserved(port: int, env: Mapping[str, str] | None = None) -> str:
    """"" or the Liminal app whose page `port` is (the four: firewall.app_ports, moved by their variables in `env`)."""
    for app, own in app_ports(env).items():
        if own == port:
            return app
    return ""


def _holder_words(h: Holder) -> str:
    if h.relay:
        return f"WSL's relay ({h.name}, pid {h.pid}): a server inside a WSL distribution listens there"
    if not h.pid:
        return f"a program not named (another user's), reachable from {h.reach}"
    return f"{h.name} (pid {h.pid}), reachable from {h.reach}"


def held_words(port: int, held: Iterable[Holder]) -> str:
    """Who holds `port`, in words: each program, its pid and where it can be reached from; WSL's relay said as such;
    "nothing listens on it here" for none."""
    shown = [_holder_words(h) for h in held]
    return "; ".join(shown) if shown else f"nothing listens on port {port} here"


def _conflict_of(port: int, held: list[Holder]) -> str:
    """The conflict a port held by programs not of this instance makes, in words: a named program first, then WSL's
    relay, then a program not named."""
    named = [h for h in held if h.pid and not h.relay]
    if named:
        h = named[0]
        return f"port {port} is held by {h.name} (pid {h.pid}), reachable from {h.reach}"
    relay = [h for h in held if h.relay]
    if relay:
        h = relay[0]
        return (f"port {port} is held by WSL's relay ({h.name}, pid {h.pid}): a server inside a WSL distribution "
                f"listens there, and Windows reaches it at {LOOPBACK}:{port}. Add it as a found instance, or choose "
                "another port")
    return f"port {port} is held by a program not named (another user's)"


# -- what an instance answered -----------------------------------------------------------------------------------------
def _model(item) -> dict | None:
    """A model as a look lists it: {"id", "size", "context", "loaded", "tools", "detail"} and whatever more its plugin
    keeps; None for one with no id."""
    if not isinstance(item, Mapping) or not isinstance(item.get("id"), str) or not item["id"].strip():
        return None
    out = dict(item)
    out["id"] = item["id"].strip()[:MODEL_CHARS]
    for key in ("size", "context"):
        value = item.get(key)
        out[key] = value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None
    for key in ("loaded", "tools"):
        value = item.get(key)
        out[key] = value if isinstance(value, bool) else None
    out["detail"] = str(item.get("detail") or "")[:200]
    return out


@dataclass(frozen=True)
class Seen:
    """What an instance answered when it was asked (`look`): whether it is the software expected and answers (`ok`),
    what it said in words (`said`), its `version`, when it was asked (`at`, the clock's seconds) and how long that took
    (`seconds`), its `models` (each {"id", "size" (bytes or None), "context" (tokens or None), "loaded" (True, False,
    None), "tools" (True, False, None), "detail"}), and a plugin's own `facts`."""

    ok: bool
    said: str = ""
    version: str = ""
    at: float = 0.0
    seconds: float = 0.0
    models: tuple = ()
    facts: Mapping = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "ok", self.ok is True)
        object.__setattr__(self, "said", " ".join(str(self.said or "").split())[:400])
        object.__setattr__(self, "version", str(self.version or "")[:80])
        listed = [m for m in (_model(x) for x in (self.models or ())) if m is not None]
        object.__setattr__(self, "models", tuple(listed))
        object.__setattr__(self, "facts", MappingProxyType(dict(self.facts or {})))


def _served(models) -> list[dict]:
    """The models as another plugin is told them: {"id", "context", "tools"}."""
    return [{"id": m["id"], "context": m.get("context"), "tools": m.get("tools")} for m in models]


# -- the base ----------------------------------------------------------------------------------------------------------
class ServerRun(Run):
    """A model server plugin's run state (ai.Run and more): its children by instance, those found by their pidfiles,
    the instance shown, what each instance answered, the other plugins' instances, the boot registrations' states
    (the socket table is the module's: `_tables`). A plugin that keeps more subclasses it and names its class in
    RUN_STATE."""

    def __init__(self):
        super().__init__()
        self.children: dict = {}  # instance -> the Child a click of this process started
        self.adopted: dict = {}  # instance -> a Child found by its pidfile (an earlier run's, a boot task's)
        self.shown = ""  # the instance shown (choose): kept until the platform restarts
        self.seen: dict[str, Seen] = {}  # instance -> what it answered last
        self.others: tuple[float, list] | None = None  # (when, [(plugin's title, row)]): other plugins' instances
        self.boot: tuple[float, dict, str] | None = None  # (when, {instance: Startup}, problem)
        self.boot_thread: threading.Thread | None = None
        self.keeping = threading.Lock()  # one change of the kept instances at a time


class ModelServer(AiPlugin):
    """A model server's plugin: its instances, their starts and stops, their ports and conflicts, their keys, their
    start at boot, their models and a prompt to try (the module's words). A subclass sets DEFAULT_PORT (the maker's
    port), NATIVE (its own API's name for the harnesses: "ollama", "llamacpp", "vllm"), KEYED (whether its server
    checks a key), SETTINGS (the tool's main settings, each a form's field named by its Setting.name), READY_S (how
    long a start may take before it listens) and MODEL_COLUMNS (its own model cells' titles), and says `launch` and
    `look` besides what every AI plugin says."""

    GROUP = "inference"
    TABS = (Tab("models", "Models", "models", 15.0),)
    HOOKS = (*AiPlugin.HOOKS, "choose", "add_instance", "change_instance", "remove_instance", "set_key", "forget_key",
             "share", "start", "stop", "boot", "log_of", "models", "try_it", SERVING, "models_of")
    RUN_STATE = ServerRun
    DEFAULT_PORT = 0  # the maker's port (Ollama 11434, llama.cpp 9931, vLLM 8000)
    NATIVE = ""  # its own API, as the harnesses read it ("ollama": Ollama's own beside /v1)
    KEYED = True  # whether its server checks a key of its own
    SETTINGS: tuple = ()  # Setting, each a field of ai-add and ai-change named by its name
    READY_S = 120.0  # seconds a start is "starting" before it listens
    MODEL_COLUMNS: tuple = ()  # the titles of model_cells' cells
    CHILD = None  # the class its servers are started and found again with; None: children.Child (a test's stand-in)
    # What it says of the interface it shares (the contract's words of liminal-libs 1.63.0, read by name by the Internal
    # API tab; nothing reads them before it): its reads beside its bases' (`choose` changes only which instance its
    # page shows, until the platform restarts), the services other plugins ask of it through the platform, what it
    # asks of the others, and what it keeps through the login (KEEPS, below; its keys' names in INTERNAL_NOTES)
    READ_HOOKS = ("choose", "log_of", "models", SERVING, "models_of")
    SERVICE_HOOKS = (SERVING, "models_of")
    ASKS = (("", SERVING, "whether another inference plugin's instance holds a port of this machine"),)
    INTERNAL_NOTES = ("Each instance's key is a secret pair of its own, LIMINAL_AI_<NAME>_<INSTANCE>_KEY "
                      "(key_variable), kept apart from its instances' pair and never in an answer, a log, an "
                      "error or a command line.",)

    @property
    def KEEPS(self) -> tuple:  # noqa: N802 - a declared word of the contract, as READ_HOOKS
        """What it keeps through its login beside its keys (Plugin.KEEPS): its instances, one JSON pair under
        LIMINAL_AI_<NAME>_INSTANCES (`kept_instances`). Said by name: no login is asked."""
        return ((self.variable("instances"), "its instances: where each is, its address and port, whether it is "
                 "shared, keyed or started at boot, and its settings"),)

    # -- what a subclass says ---------------------------------------------------------------------------------------
    def launch(self, instance: Instance, key: str = "") -> children.Launch:
        """A local instance's server as it is started: its command and environment (children.Launch), its bind address
        (this machine's loopback address unless the instance is `shared`) and port (port_of), its privacy switches,
        its `key` by environment (a name of `secret`), never on its command line. A Refusal (a ValueError) in words
        when it cannot be started so: it is the start's own refusal."""
        raise NotImplementedError(f"{self.title or self.name} says nothing of how its server is started")

    def look(self, at: Endpoint, instance: Instance) -> Seen:
        """What an instance answers now, a few asks of LOOK_S each: whether it is this software, its version, its
        models. Asked by the Models tab and a user's click, never by a status. The base's: the OpenAI-compatible list
        of models (Endpoint.models); a subclass recognises its own software."""
        found = at.models()
        models = tuple({"id": m["id"], "context": m.get("context"), "detail": m.get("owner") or ""} for m in found)
        many = f"{len(models)} model{'' if len(models) == 1 else 's'}"
        return Seen(True, f"it answers at {self.address(instance)}: {many} listed", models=models)

    def start_words(self, instance: Instance) -> str:
        """What a start of `instance` does besides the base's words (ai-start's confirmation): "" by default."""
        return ""

    def share_words(self, instance: Instance) -> str:
        """What sharing `instance` beyond this machine means, its second confirmation's words; a subclass adds its own
        after these."""
        p = self.port_of(instance)
        words = (f"Every machine that reaches this one's port {p} can then use it; only its key stands in front, sent "
                 "in the clear.")
        if self.system == "windows":
            return words + (" Windows may ask once whether it may accept connections: your answer is its firewall "
                            "rule.")
        return words + " No firewall rule is made from here: a firewall of this machine's may still stop it."

    def model_cells(self, instance: Instance, model: dict) -> list:
        """A model's own cells, after the base's, under MODEL_COLUMNS (a form button each, as a status's cell is)."""
        return []

    def more(self, shown: Instance | None, seen: Seen | None) -> dict:
        """{"tables", "forms", "actions"} added to the Models tab, asked at every draw: `seen` None for an instance
        not asked (a local one that is stopped, or none shown)."""
        return {}

    def main_more(self) -> dict:
        """{"tables", "forms", "actions"} added to Main, asked at every draw (files and kept readings only)."""
        return {}

    # -- its files ----------------------------------------------------------------------------------------------------
    def log_path(self, name: str) -> Path:
        """A local instance's log: home/logs/<name>.log."""
        return self.home / "logs" / f"{name}.log"

    def boot_log(self, name: str) -> Path:
        """Its start at boot's own log (`launch serve`'s starts and ends): home/logs/<name>.boot.log."""
        return self.home / "logs" / f"{name}.boot.log"

    def pidfile(self, name: str) -> Path:
        return self.home / "run" / f"{name}.pid"

    def stop_marker(self, name: str) -> Path:
        """Left by a stop from the page of an instance its start at boot runs: `launch serve` then ends when its
        server does, rather than starting it again."""
        return self.home / "run" / f"{name}.stop"

    # -- its instances ------------------------------------------------------------------------------------------------
    def _store(self) -> Instances:
        return Instances(self.variable("instances"), self._login)

    def kept_instances(self) -> Kept:
        """Its instances as they are kept through its login now."""
        return self._store().read()

    def _changing(self) -> Kept:
        """What is kept, to change: a value that cannot be read is started again by the change."""
        kept = self.kept_instances()
        return Kept() if kept.problem and not kept.instances else Kept(dict(kept.instances))

    def _keep(self, kept: Kept) -> str:
        return self._store().keep(kept)

    def _change(self, name: str, *, check: Callable[[Kept, Instance], str] | None = None,
                **changes) -> tuple[Instance, str]:
        """One instance changed and kept: its fields `changes` laid over it as it is kept when it is kept (under the
        keeping lock, so what another change kept meanwhile, a key or At boot, stays). `check(kept, changed)`: "" or
        why the change is refused (a Refusal), asked under that lock. It as kept, and where."""
        with self._rt.keeping:
            kept = self._changing()
            if name not in kept.instances:
                raise LookupError(f"{self.title or self.name} has no instance {name!r}")
            changed = dataclasses.replace(kept.instances[name], **changes)
            why = check(kept, changed) if check is not None else ""
            if why:
                raise Refusal(why)
            kept.instances[name] = changed
            return changed, self._keep(kept)

    def _taken(self, kept: Kept, instance: Instance, port: int | None = None) -> str:
        """"" or which other instance of this plugin's (among `kept`) is on `instance`'s port of this machine already
        (`port`: its own unless given), in words. A remote one's port is its machine's: none."""
        if instance.where == "remote":
            return ""
        p = self.port_of(instance) if port is None else port
        for other in kept.instances.values():
            if other.name != instance.name and other.where != "remote" and self.port_of(other) == p:
                return f"port {p} is {self.title or self.name}'s instance {other.name} already"
        return ""

    def instance(self, name) -> Instance:
        """The instance kept by that name; LookupError for none."""
        key = str(name or "").strip().lower()
        found = self.kept_instances().instances.get(key)
        if found is None:
            raise LookupError(f"{self.title or self.name} has no instance {str(name or '')[:40]!r}")
        return found

    def shown(self) -> Instance | None:
        """The instance shown (choose), else the first; None when there is none."""
        kept = self.kept_instances().instances
        with self._rt.lock:
            chosen = self._rt.shown
        return kept.get(chosen) or next(iter(kept.values()), None)

    def port_of(self, instance: Instance) -> int:
        """Its port: its own, else the maker's (DEFAULT_PORT)."""
        return int(instance.port or self.DEFAULT_PORT or 0)

    def base(self, instance: Instance) -> str:
        """Its address as it is asked (endpoint.base_url): a remote one's own; a local or a found one at this machine's
        loopback address. ValueError when it has no port."""
        if instance.where == "remote":
            return base_url(instance.host, instance.port, instance.tls, instance.prefix)
        return base_url(LOOPBACK, self.port_of(instance))

    def address(self, instance: Instance) -> str:
        """Where it is, in words."""
        p = self.port_of(instance)
        if instance.where == "remote":
            try:
                return self.base(instance)
            except ValueError:
                return f"{instance.host}:{p}"
        if instance.where == "local" and instance.shared:
            return f"every address of this machine, port {p}"
        return f"{LOOPBACK}:{p}"

    def key_variable(self, name: str) -> str:
        """The pair an instance's key is kept under: LIMINAL_AI_<NAME>_<INSTANCE>_KEY."""
        return instances.secret_variable(STEM + self.name, name, "key")

    def key_of(self, instance: Instance) -> str:
        """Its key, read through the login when one is kept for it; "" otherwise."""
        return self.pair(self.key_variable(instance.name)) if instance.keyed else ""

    def endpoint(self, instance: Instance, timeout: float = LOOK_S) -> Endpoint:
        """It, to be asked over http (its key with every ask; plain http to another machine only as accepted)."""
        return Endpoint(self.base(instance), key=self.key_of(instance), plain=instance.plain, timeout=timeout,
                        transport=self.out.transport)

    def _task(self) -> str:
        return "task" if self.system == "windows" else "unit"

    # -- this system's socket table, the pidfiles and the children ---------------------------------------------------
    def _probe(self):
        """The socket table's probe: the Outside's, else this system's one, shared by every model server plugin."""
        if self.out.probe is not None:
            return self.out.probe
        with _tables_lock:
            if not _probes:
                _probes.append(resources.default_probe(_every))
            return _probes[0]

    def _table(self) -> _Table:
        """The listening sockets of this system and their programs, read at most every TABLE_S by all the model server
        plugins of this process that read them through the same probe (nothing sent): two asking at once make one
        read."""
        now = self.out.clock()
        try:
            probe = self._probe()
        except Exception as e:  # noqa: BLE001 - no probe: nothing is known to hold a port
            return _Table(now, (), {}, f"this system's socket table could not be read: {_words(e)}")
        with _tables_lock:
            for was, kept in _tables:
                if was is probe and 0 <= now - kept.at < TABLE_S:
                    return kept
            try:
                if self.system == "linux" and callable(getattr(probe, "processes", None)):
                    probe.processes()  # its sockets' owners are the processes it reports
                conns = tuple(c for c in probe.connections() if getattr(c, "state", "") == "listening")
                pids = sorted({int(c.pid) for c in conns if getattr(c, "pid", 0)})
                ask = getattr(probe, "program_names", None)
                table = _Table(now, conns, dict(ask(pids)) if pids and callable(ask) else {})
            except Exception as e:  # noqa: BLE001 - a table that cannot be read: nothing is known to hold a port
                table = _Table(now, (), {}, f"this system's socket table could not be read: {_words(e)}")
            _tables[:] = [(probe, table), *((w, t) for w, t in _tables if w is not probe)][:TABLES_KEPT]
        return table

    def _child_class(self):
        return self.CHILD if self.CHILD is not None else children.Child

    def child(self, instance: Instance, launch: children.Launch):
        """The child a local instance's server is started as (its log and its pidfile, this plugin's stand-ins)."""
        name = instance.name
        return self._child_class()(name, launch, self.log_path(name), self.pidfile(name), popen=self.out.popen,
                                   system=self.system)

    @staticmethod
    def _owns(child, pid: int) -> bool:
        try:
            return bool(pid) and (pid == child.pid or bool(child.owns(pid)))
        except Exception:  # noqa: BLE001 - a process that cannot be told is not its own
            return False

    @staticmethod
    def _by(instance: Instance, child) -> str:
        """Who started a server found by its pidfile: "earlier" when the program that started it has ended (an earlier
        platform's run, ended without stopping it); "system" while its starter still runs and it starts at boot (its
        task's or its unit's `launch serve`); "earlier" otherwise (another run of the platform)."""
        if getattr(child, "note", ""):
            return "earlier"
        return "system" if instance.boot else "earlier"

    def _live(self, instance: Instance):
        """The child that runs a local instance's server now and who started it: (it, "plugin" | "system" |
        "earlier"), or (None, "") when none runs. Read from this process's children and the pidfile alone."""
        if instance.where != "local":
            return None, ""
        name = instance.name
        with self._rt.lock:
            ours, adopted = self._rt.children.get(name), self._rt.adopted.get(name)
        try:
            if ours is not None and ours.alive:
                return ours, "plugin"
            if adopted is not None and adopted.alive:
                return adopted, self._by(instance, adopted)
            found = self._child_class().adopt(name, self.log_path(name), self.pidfile(name), system=self.system)
        except Exception:  # noqa: BLE001 - a pidfile that cannot be read: none is known to run
            found = None
        if found is None or found is ours or not found.alive:
            with self._rt.lock:
                if self._rt.adopted.get(name) is adopted:
                    self._rt.adopted.pop(name, None)
            return None, ""
        with self._rt.lock:
            self._rt.adopted[name] = found
        return found, self._by(instance, found)

    def running(self) -> list[str]:
        """The local instances whose servers run now, by this plugin or by the system (their pidfiles), or whose task
        or unit runs them (its `launch serve` between two starts of the server, as last read): Install and Uninstall
        wait for each, as the page's state says ("starting")."""
        return [i.name for i in self.kept_instances().instances.values() if self._runs(i)]

    def boot_names(self) -> list[str]:
        """The instances that start at boot."""
        return [i.name for i in self.kept_instances().instances.values() if i.boot]

    def _boot_states(self, read: bool = True) -> dict:
        """The boot registrations' states by instance, as last read; read again in a thread once they are BOOT_S old
        (one command: autostart.read), so a page may show them a moment late and never waits for them. `read` False
        (serving, a hook): what was last read alone, nothing started."""
        now = self.out.clock()
        start = None
        with self._rt.lock:
            was, thread = self._rt.boot, self._rt.boot_thread
            stale = was is None or not 0 <= now - was[0] < BOOT_S
            if read and stale and (thread is None or not thread.is_alive()):
                start = threading.Thread(target=self._boot_read, daemon=True, name=f"boot-{self.name}")
                self._rt.boot_thread = start
        if start is not None:
            start.start()
        return dict(was[1]) if was is not None else {}

    def _boot_problem(self) -> str:
        """What could not be read of the boot registrations when they were last read, in words ("" for nothing)."""
        with self._rt.lock:
            was = self._rt.boot
        return was[2] if was is not None else ""

    def _task_runs(self, instance: Instance) -> bool:
        """Whether its start at boot's task or unit runs now, as last read (nothing is read here): its `launch serve`
        starting its server, or waiting to start it again."""
        if instance.where != "local" or not instance.boot:
            return False
        startup = self._boot_states(read=False).get(instance.name)
        return startup is not None and startup.state in UP

    def _runs(self, instance: Instance) -> bool:
        """Whether a local instance's server runs (this process's child, or one its pidfile names), or its task or its
        unit runs it: what is read when it starts cannot be changed then."""
        return self._live(instance)[0] is not None or self._task_runs(instance)

    def _idle_words(self, instance: Instance, then: str) -> str:
        """Why a local instance whose server is not running is not asked, in words: its task or unit waits to start
        it again, or `then` (what to do)."""
        if self._task_runs(instance):
            return (f"{instance.name} is not running now: its {self._task()} starts it, or waits to start it again "
                    "(its Log says why)")
        return f"{instance.name} is not running: {then}"

    def _boot_read(self) -> None:
        try:
            found = autostart.read(self.name, **self._boot_kw())
            problem = ""
        except Exception as e:  # noqa: BLE001 - its registrations could not be read: said
            found, problem = {}, f"its starts at boot could not be read: {_words(e)}"
        with self._rt.lock:
            self._rt.boot = (self.out.clock(), dict(found), problem)

    def _reading(self, instance: Instance, *, boot: bool = True) -> dict:
        """Its state from kept readings alone (the socket table, the pidfile, this process's children, what it answered
        last, the boot registrations as last read), knowing nothing of other plugins: {"state", "by", "pid", "since",
        "holder", "said"}. `boot` False (serving): the boot registrations are not read again even when they are old.
        A local one whose server is not running while its task or unit runs is "starting" by "system", its pid None:
        its `launch serve` starts it, or waits to start it again."""
        out = {"state": "", "by": "", "pid": None, "since": None, "holder": "", "said": ""}
        now = self.out.clock()
        name, p = instance.name, self.port_of(instance)
        seen = self.seen(name)
        if instance.where == "remote":
            said = (f"as last asked, at {_when(seen.at, now)}: {seen.said}" if seen is not None
                    else "not asked yet: its Models tab asks it while it is shown")
            out.update(state="unasked", said=said)
            return out
        table = self._table()
        held = holders(p, table) if p else []
        if instance.where == "found":
            if held:
                words = held_words(p, held)
                out.update(state="answering", pid=held[0].pid or None, holder=words, said=f"listening: {words}")
            elif seen is not None and seen.ok:
                out.update(state="answering", said=f"answered when asked at {_when(seen.at, now)}")
            else:
                out.update(state="silent", said=f"nothing listens on port {p} here" + (
                    f" ({table.problem})" if table.problem else ""))
            return out
        child, by = self._live(instance)
        if child is not None:
            pid, since = child.pid, child.since
            mine = [h for h in held if self._owns(child, h.pid)]
            others = [h for h in held if h not in mine]
            started = f" since {_when(since, now)}" if since else ""
            if mine or table.problem:
                state, said = "running", f"running (pid {pid}){started}"
            elif since and 0 <= now - since < self.READY_S:
                state, said = "starting", f"starting (pid {pid}): not listening on port {p} yet"
            else:
                state, said = "running", (f"running (pid {pid}){started}, but it does not listen on port {p}: its log "
                                          "may say why")
            if by == "system":
                said += f" · started by its {self._task()} at boot"
            elif by == "earlier":
                said += " · started by an earlier run of the platform"
                note = str(getattr(child, "note", "") or "")
                if note:
                    said += f": {note}"
            out.update(state=state, by=by, pid=pid, since=since, said=said,
                       holder=held_words(p, others) if others else "")
            return out
        with self._rt.lock:
            ours = self._rt.children.get(name)
        code = ours.code if ours is not None else None
        if code is not None:
            last = ""
            try:
                last = (ours.tail(1) or [""])[-1]
            except Exception:  # noqa: BLE001 - a log that cannot be read: its code alone
                pass
            out.update(state="exited", said=f"exited (code {code})" + (f": {last}" if last else ""))
        else:
            out.update(state="stopped", said="stopped")
        if instance.boot:
            task = self._task()
            startup = self._boot_states(read=boot).get(name)
            if startup is not None and startup.state in UP:
                out.update(state="starting", by="system",
                           said=f"not running now: its {task} {startup.name} runs, and starts it or waits to start it "
                                "again (Log says why)")
            elif startup is not None:
                out["said"] += f" · its {task} {startup.name}: {startup.state}"
            elif self._boot_problem():
                out["said"] += f" · {self._boot_problem()}"
        if held:
            out["holder"] = held_words(p, held)
        return out

    def state(self, instance: Instance) -> dict:
        """Its state: {"state" (running | starting | stopped | exited | answering | silent | unasked), "by" (plugin |
        system | earlier | ""), "pid", "since", "holder" (who else listens on its port), "said" (the state in words),
        "conflict" (conflict's words, "" for none)}. From kept readings and the socket table only: nothing is asked
        over the network, and nothing is run but the boot registrations' read for one that starts at boot (one command
        in a thread, at most every BOOT_S, never waited for)."""
        out = self._reading(instance)
        out["conflict"] = self.conflict(instance)
        return out

    # -- conflicts ----------------------------------------------------------------------------------------------------
    def _listening(self, host: str, port: int) -> bool:
        listen = self.out.listening if self.out.listening is not None else instances.listening
        try:
            return bool(listen(host, port))
        except Exception:  # noqa: BLE001 - an answer that cannot be had says nothing
            return False

    def _others(self) -> list:
        """The instances of this machine that the other inference plugins hold, asked through the app (`serving`,
        kept TABLE_S): [(the plugin's title, its row)]. No lock is held while they are asked; one that refuses is left
        out."""
        if self.app is None:
            return []
        now = self.out.clock()
        with self._rt.lock:
            kept = self._rt.others
        if kept is not None and 0 <= now - kept[0] < TABLE_S:
            return list(kept[1])
        try:
            answers = self._ask_others(SERVING)
        except Exception:  # noqa: BLE001 - an app that cannot list its plugins: none is asked
            answers = []
        rows: list = []
        for name, answer, _ in answers:
            if not isinstance(answer, Mapping):  # (one that refused answered None)
                continue
            title = str(answer.get("title") or answer.get("plugin") or name)
            for row in answer.get("instances") or ():
                if isinstance(row, Mapping) and row.get("local"):
                    rows.append((title, row))
        with self._rt.lock:
            self._rt.others = (now, rows)
        return rows

    @staticmethod
    def _row_port(row: Mapping) -> int:
        port = row.get("port")
        if isinstance(port, int) and not isinstance(port, bool):
            return port
        try:
            return parse_address(str(row.get("base") or ""), 0)[1]
        except ValueError:
            return 0

    def conflict(self, instance: Instance, port: int | None = None, *, ask: bool = False,
                 kept: Kept | None = None) -> str:
        """"" or why `instance` (on `port`, its own unless given) cannot be served on this machine, in words, in this
        order: a port outside 1024 to 65535; one of the four Liminal apps' pages; another instance's (this plugin's, or
        another inference plugin's through `serving`); for a local one, a program not its own holding it (by name and
        pid, WSL's relay, or one not named), and only with `ask` (a user's click) something that answers there though
        no program is listed as holding it. A remote one's port is its machine's: none. `kept`: its instances as read
        for the same draw already (a status reads them once); read now otherwise."""
        if instance.where == "remote":
            return ""
        p = self.port_of(instance) if port is None else port
        if isinstance(p, bool) or not isinstance(p, int) or not PORTS[0] <= p <= PORTS[1]:
            return f"a port is a whole number from {PORTS[0]} to {PORTS[1]}, not {p}"
        app = reserved(p, self.out.env)
        if app:
            return f"port {p} is Liminal's {app} page's own: choose another"
        taken = self._taken(self.kept_instances() if kept is None else kept, instance, p)
        if taken:
            return taken
        for title, row in self._others():
            if self._row_port(row) == p:
                return f"port {p} is {title}'s instance {row.get('name') or 'one'} already"
        if instance.where != "local":
            return ""
        child, _ = self._live(instance)
        strangers = [h for h in holders(p, self._table()) if child is None or not self._owns(child, h.pid)]
        if strangers:
            return _conflict_of(p, strangers)
        if ask and child is None and self._listening(LOOPBACK, p):
            return (f"something answers at {LOOPBACK}:{p} that no program here is listed as holding "
                    f"({MIRRORED})")
        return ""

    # -- what an instance answers -------------------------------------------------------------------------------------
    def seen(self, name: str) -> Seen | None:
        """What an instance answered when it was last asked; None when it was not."""
        with self._rt.lock:
            return self._rt.seen.get(name)

    def forget_seen(self, name: str) -> None:
        """What an instance answered forgotten: the next look asks it again (after a download, a delete)."""
        with self._rt.lock:
            self._rt.seen.pop(name, None)

    def asked(self, instance: Instance, fresh: bool = False) -> Seen:
        """What it answers (`look`), asked now unless it was asked less than SEEN_S ago (`fresh`: asked now all the
        same); what failed said as a Seen that is not ok. Kept for its page and for `serving`."""
        now = self.out.clock()
        kept = self.seen(instance.name)
        if kept is not None and not fresh and 0 <= now - kept.at < SEEN_S:
            return kept
        try:
            got = self.look(self.endpoint(instance), instance)
            if not isinstance(got, Seen):
                raise TypeError(f"its look answered {type(got).__name__}, not a Seen")
        except Exception as e:  # noqa: BLE001 - what failed is what it answered
            got = Seen(False, self._scrubbed(_words(e)))
        took = max(0.0, self.out.clock() - now)
        got = dataclasses.replace(got, at=now, seconds=got.seconds or round(took, 3),
                                  said=self._scrubbed(got.said))
        with self._rt.lock:
            self._rt.seen[instance.name] = got
        return got

    def seen_facts(self) -> dict:
        """What the instances answered when last asked, in words by instance, for a plugin's api_facts (asking
        nothing)."""
        now = self.out.clock()
        with self._rt.lock:
            seen = dict(self._rt.seen)
        return {name: f"{'answered' if s.ok else 'failed'} at {_when(s.at, now)} in {s.seconds:g} s"
                      + (f" ({s.version})" if s.version else "") + (f": {s.said}" if s.said else "")
                for name, s in seen.items()}

    # -- the hooks ----------------------------------------------------------------------------------------------------
    def _boot_kw(self) -> dict:
        """What every call into autostart is given: this system and its commands."""
        return {"system": self.system, "powershell": self.out.powershell, "shell": self.out.shell}

    def choose(self, name) -> dict:
        """The instance shown on the page, its models on the Models tab (kept until the platform restarts)."""
        instance = self.instance(name)
        with self._rt.lock:
            self._rt.shown = instance.name
        return self._reply(f"{instance.name} is shown: its models are on the Models tab")

    @staticmethod
    def _port_value(port) -> int:
        """A port as typed: 0 (the maker's) for none; a Refusal for what is no whole number."""
        if port is None or (isinstance(port, str) and not port.strip()):
            return 0
        if isinstance(port, float) and port.is_integer():
            port = int(port)
        if isinstance(port, str) and re.fullmatch(r"\d{1,5}", port.strip()):
            port = int(port.strip())
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise Refusal(f"a port is a whole number from {PORTS[0]} to {PORTS[1]}, not {str(port)[:20]!r}")
        return port

    def _values(self, values) -> dict:
        """The settings typed (the form's fields after the instance's own, in SETTINGS' order): kept by name, an empty
        one left out (the tool's own default)."""
        out: dict = {}
        for setting, value in zip(self.SETTINGS, values):
            kept = setting.clean(value)
            if kept is not None:
                out[setting.name] = kept
        return out

    def _remote(self, address, accept_plain) -> tuple[str, int, bool, str, bool, str]:
        """A remote instance's address as typed: (host, port, tls, prefix, plain, a line of words). An address ending
        in /v1, as the makers write their OpenAI-compatible base, is kept without it (every ask adds it), and the line
        says so; "" otherwise. Refused: no address, one that is no address, this machine's, and plain http until it
        is accepted (a Refusal naming accept_plain)."""
        try:
            host, port, tls, prefix = parse_address(address, int(self.DEFAULT_PORT or 0))
        except ValueError as e:
            raise Refusal(str(e)) from None
        if instances.is_local(host):
            raise Refusal(f"{host} is this machine: add an instance there as found on this machine, not as another "
                          "machine's")
        if not tls and not exactly(accept_plain):
            raise Refusal(f"{host} would be asked over plain http: its key and everything sent to it can be read on "
                          "the way. Give an https address, or accept it for a network you trust.", accept=ACCEPT_PLAIN)
        said = ""
        if prefix.endswith(V1):
            prefix = prefix[:-len(V1)]
            said = f"its address is kept without its last {V1}: every ask adds it ({V1}/models, {V1}/chat/completions)"
        return host, port, tls, prefix, not tls, said

    def add_instance(self, name, where="local", address=None, port=None, accept_plain=False, *values) -> dict:
        """An instance added and kept through the login: run here (local: its port, then SETTINGS' values), found on
        this machine (found: its port) or another machine's (remote: its address; plain http to it asked twice,
        accept_plain). Nothing is started, installed or asked of it. Refused: a name that is none or is taken, more
        than MAX_INSTANCES, a kind this system cannot run (runs_here), a conflict (this plugin's own ports looked at
        again as it is kept: two adds at once on one port keep one), this machine's address as remote."""
        clean = instances.clean_name(name)
        kind = str(where or "local").strip().lower()
        if kind not in WHERE:
            raise Refusal("an instance is run here (local), found on this machine (found) or another machine's "
                          f"(remote), not {kind[:20]!r}")
        if kind == "local":
            here = self.runs_here()
            if here:
                raise Refusal(here)
        stamp = instances.now_iso(self.out.clock)
        lines = ["nothing was started, installed or asked of it"]
        if kind == "remote":
            host, p, tls, prefix, plain, said = self._remote(address, accept_plain)
            candidate = Instance(clean, "remote", host=host, port=p, tls=tls, prefix=prefix, plain=plain, at=stamp)
            lines += [said] if said else []
        else:
            settings = self._values(values) if kind == "local" else {}
            candidate = Instance(clean, kind, port=self._port_value(port), settings=settings, at=stamp)
            problem = self.conflict(candidate, ask=True)
            if problem:
                raise Refusal(problem)
        title = self.title or self.name
        with self._rt.keeping:
            kept = self._changing()
            if clean in kept.instances:
                raise Refusal(f"{clean} is an instance of {title} already: choose another name")
            if len(kept.instances) >= MAX_INSTANCES:
                raise Refusal(f"{title} holds {MAX_INSTANCES} instances at most: forget one first")
            taken = self._taken(kept, candidate)
            if taken:
                raise Refusal(taken)
            kept.instances[clean] = candidate
            where_kept = self._keep(kept)
        with self._rt.lock:
            self._rt.shown = clean
        return self._reply(f"{clean} added ({WHERE_WORDS[kind]}, {self.address(candidate)}): kept in {where_kept}",
                           True, lines)

    def change_instance(self, name, address=None, port=None, accept_plain=False, *values) -> dict:
        """An instance's address (a remote one's), port (a local or a found one's) and settings (a local one's)
        changed and kept: those fields alone, laid over it as it is kept then (a key or At boot kept meanwhile stays),
        its port looked at again among this plugin's instances as it is kept. An address left empty stays as it is; a
        port left empty is the maker's; a setting left empty is the tool's own. Refused while it runs, or while its
        task or unit runs it: its settings are read when it starts."""
        instance = self.instance(name)
        if self._runs(instance):
            raise Refusal(f"stop {instance.name} first: its settings are read when it starts")
        lines: list[str] = []
        if instance.where == "remote":
            changes: dict = {}
            if address is not None and str(address).strip():
                host, p, tls, prefix, plain, said = self._remote(address, accept_plain)
                changes = {"host": host, "port": p, "tls": tls, "prefix": prefix, "plain": plain}
                lines += [said] if said else []
            candidate = dataclasses.replace(instance, **changes)
        else:
            changes = {"port": self._port_value(port)}
            if instance.where == "local":
                changes["settings"] = self._values(values)
            candidate = dataclasses.replace(instance, **changes)
            problem = self.conflict(candidate, ask=True)
            if problem:
                raise Refusal(problem)
        if candidate == instance:
            return self._reply(f"{instance.name} is as it was: nothing changed", True, lines)
        now, where_kept = self._change(instance.name, check=self._taken, **changes)
        self.forget_seen(instance.name)
        return self._reply(f"{now.name} changed ({self.address(now)}): kept in {where_kept}", True, lines)

    def _end_boot_run(self, instance: Instance, child) -> list[str]:
        """A server its start at boot runs, stopped (`child`: it, None when its `launch serve` runs without it,
        waiting to start it again): the stop marker left for `launch serve` (it then ends with its server), the
        server asked to end first on Windows (Task Scheduler's stop would end it at once), then its task or its unit
        stopped (on Linux systemd tells the launcher, which ends its server in order). The boot registrations are
        read again by the next status."""
        lines: list[str] = []
        name, task = instance.name, self._task()
        marker = self.stop_marker(name)
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("stopped from the platform's page\n", encoding="utf-8")
        except OSError as e:
            lines.append(f"its stop could not be noted for its {task} ({e}): it may be started again")
        if child is not None and self.system == "windows":
            try:
                lines.append(f"{name} {child.stop()}")
            except children.ChildError as e:
                lines.append(str(e))
        try:
            autostart.act(self.name, name, "stop", **self._boot_kw())
            lines.append(f"its {task} is stopped: it starts again at your next sign-in")
        except (CommandError, ValueError) as e:
            lines.append(f"its {task} could not be stopped: {_words(e)}")
        with self._rt.lock:
            self._rt.adopted.pop(name, None)
            self._rt.boot = None
        return lines

    def remove_instance(self, name) -> dict:
        """An instance forgotten: its definition and its key, and its start at boot removed (stopped first). The
        software and its models stay; a remote server is told nothing. Refused while this plugin runs it."""
        instance = self.instance(name)
        child, by = self._live(instance)
        if child is not None and by != "system":
            raise Refusal(f"stop {instance.name} first: it runs (pid {child.pid})")
        lines: list[str] = []
        if instance.boot or by == "system":
            if child is not None:
                lines += self._end_boot_run(instance, child)
            try:
                autostart.remove(self.name, instance.name, **self._boot_kw())
            except (CommandError, ValueError) as e:
                raise Refusal(f"{instance.name}'s start at boot could not be removed ({_words(e)}): the instance is "
                              "kept until it can be") from None
            lines.append("its start at boot is removed")
        with self._rt.keeping:
            kept = self._changing()
            kept.instances.pop(instance.name, None)
            where_kept = self._keep(kept)
        if instance.keyed:
            try:
                self.keep_pair(self.key_variable(instance.name), None)
                lines.append("its key is forgotten")
            except Refusal as e:
                lines.append(f"its key could not be forgotten: {e}")
        with self._rt.lock:
            self._rt.children.pop(instance.name, None)
            self._rt.adopted.pop(instance.name, None)
            self._rt.seen.pop(instance.name, None)
            if self._rt.shown == instance.name:
                self._rt.shown = ""
        if instance.where == "local" and self.log_path(instance.name).exists():
            lines.append(f"its log stays in {self.log_path(instance.name)}")
        return self._reply(f"{instance.name} is forgotten: kept in {where_kept}", True, lines)

    def set_key(self, name, key) -> dict:
        """A key kept for an instance, as its own pair through the login (never in the JSON, a file or a log): a local
        server starts with it, a found or a remote one is sent it with each ask. Refused: no key typed, one that
        cannot be one; a local instance of a server that checks no key (KEYED false); a local one running, or run by
        its task or unit."""
        instance = self.instance(name)
        if key is None:
            raise Refusal("type the key first")
        try:
            value = keys_mod.clean(key)
        except ValueError as e:
            raise Refusal(f"the key is not kept: {e}") from None
        title = self.title or self.name
        if instance.where == "local" and not self.KEYED:
            raise Refusal(f"{title}'s server checks no key: none is kept for one run here")
        if self._runs(instance):
            raise Refusal(f"stop {instance.name} first: its key is read when it starts")
        variable = self.key_variable(instance.name)
        where_kept = self.keep_pair(variable, value)
        if not instance.keyed:
            self._change(instance.name, keyed=True)
        self.forget_seen(instance.name)
        return self._reply(f"a key is kept for {instance.name} as its own pair, {variable}: kept in {where_kept}")

    def forget_key(self, name) -> dict:
        """An instance's key forgotten. Refused while it is shared (only its key stands in front of it), and while a
        local one runs or its task or unit runs it (its server checks the key it was started with: the harnesses
        would be told there is none)."""
        instance = self.instance(name)
        if instance.shared:
            raise Refusal(f"{instance.name} is shared beyond this machine: turn Share off first, since only its key "
                          "stands in front of it")
        if self._runs(instance):
            raise Refusal(f"stop {instance.name} first: its key is read when it starts")
        variable = self.key_variable(instance.name)
        where_kept = self.keep_pair(variable, None)
        if instance.keyed:
            self._change(instance.name, keyed=False)
        self.forget_seen(instance.name)
        return self._reply(f"{instance.name}'s key ({variable}) is forgotten: {where_kept}")

    @staticmethod
    def _yes(on) -> bool:
        if on is True or on is False:
            return on
        word = str(on or "").strip().lower()
        if word in YES:
            return True
        if word in NO:
            return False
        raise Refusal(f"choose yes or no, not {word[:20]!r}")

    def share(self, name, on, accept_share=False) -> dict:
        """A local instance set to listen beyond this machine (`on`: yes) or on it alone (no), read at its next start.
        Sharing is asked twice (accept_share, with share_words) and needs its key. Refused: not a local one; a server
        that checks no key (KEYED false); no key kept; running, or run by its task or unit."""
        instance = self.instance(name)
        turn = self._yes(on)
        title = self.title or self.name
        if instance.where != "local":
            raise Refusal(f"{instance.name} is {WHERE_WORDS[instance.where]}: only a server run here is shared from "
                          "this plugin")
        if not self.KEYED:
            raise Refusal(f"{title}'s server has no key of its own: it is not shared from here")
        if self._runs(instance):
            raise Refusal(f"stop {instance.name} first: where it listens is read when it starts")
        if turn == instance.shared:
            return self._reply(f"{instance.name} listens {'beyond this machine' if turn else 'on this machine alone'} "
                               "already: nothing changed")
        if turn:
            if not instance.keyed:
                raise Refusal(f"keep a key for {instance.name} first (Key…): only its key stands in front of it on the "
                              "network")
            if not exactly(accept_share):
                raise Refusal(self.share_words(instance), accept=ACCEPT_SHARE)
        now, where_kept = self._change(instance.name, shared=turn)
        said = "beyond this machine" if turn else "on this machine alone"
        return self._reply(f"{now.name} listens {said} from its next start: kept in {where_kept}")

    def startable(self, instance: Instance, have: Installed | None | object = _UNREAD) -> str:
        """"" or why a server of `instance` can never be started here as things are, in words: not a local one; the
        software cannot run on this system (runs_here); the plugin's folder is on another system's drive; it is not
        installed (`have`: what installed() answered for the same draw already; asked now otherwise)."""
        if instance.where != "local":
            return f"{instance.name} is {WHERE_WORDS[instance.where]}: it is started where it runs"
        here = self.runs_here()
        if here:
            return here
        trouble = self.home_problem()
        if trouble:
            return trouble
        if (self.installed() if have is _UNREAD else have) is None:
            return f"{self.title or self.name} is not installed here: Install… first"
        return ""

    def prepared(self, instance: Instance) -> children.Launch:
        """A local instance's launch as it is started: the subclass's `launch` with its key, every variable holding the
        key named secret, and every pair of Liminal's dropped from its environment (`dropping`). Refused when its key
        would be on its command line."""
        key = self.key_of(instance)
        launch = self.launch(instance, key)
        if not isinstance(launch, children.Launch):
            raise TypeError(f"{self.title or self.name}'s launch is {type(launch).__name__}, not a children.Launch")
        if key:
            if any(children.carries(word, key) for word in (*launch.argv, launch.cwd)):
                raise Refusal(f"{self.title or self.name} would be given {instance.name}'s key on its command line, "
                              "where every program of this machine can read it: not started")
            secret = (*launch.secret, *(n for n, v in launch.env.items() if children.carries(v, key)))
            launch = dataclasses.replace(launch, secret=tuple(dict.fromkeys(secret)))
        return self.dropping(launch)

    def start(self, name) -> dict:
        """A local instance's server started as a windowless program of this user's, owned by this plugin (its log and
        its pidfile in the plugin's folder); one that starts at boot is started by its task or its unit, as at boot
        (from a platform that answers and ends too: the system's task is no child of it). Refused: not a local one,
        not startable here, running already or run by its task or unit, a conflict (this machine's port asked now), a
        platform that answers and ends (or none) for a server of its own, and whatever its launch refuses."""
        instance = self.instance(name)
        why = self.startable(instance)
        if why:
            raise Refusal(why)
        child, _ = self._live(instance)
        if child is not None:
            raise Refusal(f"{instance.name} runs already (pid {child.pid})")
        task = self._task()
        if self._task_runs(instance):
            raise Refusal(f"{instance.name}: its {task} runs already, and starts it or waits to start it again (its "
                          f"Log says why); Stop stops its {task}")
        app = self.app
        if not instance.boot and (app is None or getattr(app, "once", False)):
            raise Refusal(f"{instance.name} is started from the platform's page: a command that answers and ends "
                          "would end it with itself")
        problem = self.conflict(instance, ask=True)
        if problem:
            raise Refusal(problem)
        name = instance.name
        if instance.boot:
            try:
                self.stop_marker(name).unlink()
            except OSError:
                pass
            autostart.act(self.name, name, "start", **self._boot_kw())
            with self._rt.lock:
                self._rt.boot = None  # read again by the next status
            return self._reply(f"{name} is started by its {task}, as at boot", True,
                               [f"its log: {self.log_path(name)}", f"its {task}'s log: {self.boot_log(name)}"])
        launch = self.prepared(instance)
        started = self.child(instance, launch)
        pid = started.start()
        with self._rt.lock:
            self._rt.children[name] = started
            self._rt.adopted.pop(name, None)
            self._rt.seen.pop(name, None)
        return self._reply(f"{name} started (pid {pid}) at {self.address(instance)}", True,
                           [f"its log: {self.log_path(name)}",
                            "it stops when the platform stops or this plugin is disabled"])

    def stop(self, name) -> dict:
        """A local instance's server stopped: asked to end (Ctrl+C on Windows, SIGTERM on Linux) and given 8 s, then
        ended with what it started. One its start at boot runs is stopped by its task or its unit, and so is that task
        or unit while it runs without its server (its `launch serve` waiting to start it again). Refused: a found or
        a remote one (it is stopped where it was started), one not running."""
        instance = self.instance(name)
        if instance.where != "local":
            raise Refusal(f"{instance.name} is {WHERE_WORDS[instance.where]}: it is stopped where it was started")
        child, by = self._live(instance)
        if child is None and self._task_runs(instance):
            lines = self._end_boot_run(instance, None)
            return self._reply(f"{instance.name}'s {self._task()} is stopped: its server was not running", True, lines)
        if child is None:
            raise Refusal(f"{instance.name} is not running")
        if by == "system":
            lines = self._end_boot_run(instance, child)
            return self._reply(f"{instance.name} is stopped by its {self._task()}", True, lines)
        words = child.stop()
        with self._rt.lock:
            if self._rt.children.get(instance.name) is child:
                del self._rt.children[instance.name]
            self._rt.adopted.pop(instance.name, None)
            self._rt.seen.pop(instance.name, None)
        return self._reply(f"{instance.name} {words}")

    def systemd_runs(self) -> bool:
        """Whether this Linux's init is systemd (linux.systemd_runs, asked when it is wanted)."""
        return linux.systemd_runs()

    def _boot_refusal(self, instance: Instance, why: str | None = None) -> str:
        """"" or why `instance` cannot start at boot here, in words (`why`: what startable() answered already)."""
        why = self.startable(instance) if why is None else why
        if why:
            return why
        if self.system == "linux":
            why = autostart.why_not("linux", systemd=self.systemd_runs(), wsl=self.wsl)
            if why:
                return why
        if self.lasting():
            return f"start at boot needs {instance.name} kept across a restart, and {LASTING[0].lower()}{LASTING[1:]}"
        return ""

    def _plugins_folder(self) -> Path | None:
        env = self.out.env if self.out.env is not None else os.environ
        named = str(env.get(layout.PLUGINS_VAR) or "").strip()
        return Path(named).expanduser() if named else layout.plugins_dir()

    def boot(self, name, on) -> dict:
        """A local instance started by the system when its user signs in (`on`: yes) or no longer (no): its task (a
        scheduled task at logon, no elevation) or its unit (a systemd user unit) registered, running `launch serve`;
        nothing is started now. Off: its task or unit stopped (its server asked to end first) and removed; the
        instance stays. Refused: not a local one, not startable here, no start at boot on this system, a login that
        keeps nothing across a restart."""
        instance = self.instance(name)
        turn = self._yes(on)
        task = self._task()
        if instance.where != "local":
            raise Refusal(f"{instance.name} is {WHERE_WORDS[instance.where]}: only a server run here starts at boot "
                          "from this plugin")
        if turn:
            why = self._boot_refusal(instance)
            if why:
                raise Refusal(why)
            from . import launch as launcher

            command = launcher.command(self.name, instance.name, platform_folder(self.out.env), self._plugins_folder())
            about = f"{self.title or self.name}'s model server {instance.name}"
            startup = autostart.register(self.name, instance.name, command, about, **self._boot_kw())
            try:
                _, where_kept = self._change(instance.name, boot=True)
            except Exception:
                try:
                    autostart.remove(self.name, instance.name, **self._boot_kw())
                except Exception:  # noqa: BLE001 - what was kept is said by the refusal
                    pass
                raise
            with self._rt.lock:
                self._rt.boot = None
            said = f"{instance.name} starts at boot from now on: its {task} {startup.name} ({startup.state})"
            lines = [autostart.how(self.system, self.wsl), "nothing was started now", f"kept in {where_kept}"]
            child, by = self._live(instance)
            if child is not None and by == "plugin":
                lines.insert(1, f"the server running now (pid {child.pid}) was started from this page: it still stops "
                                f"when the platform stops, and its {task} starts it from your next sign-in")
            return self._reply(said, True, lines)
        lines: list[str] = []
        child, by = self._live(instance)
        if child is not None and by == "system":
            lines += self._end_boot_run(instance, child)
        existed = autostart.remove(self.name, instance.name, **self._boot_kw())
        lines.append(f"its {task} is removed" if existed else f"no {task} of it was found")
        if instance.boot:
            _, where_kept = self._change(instance.name, boot=False)
            lines.append(f"kept in {where_kept}")
        with self._rt.lock:
            self._rt.boot = None
        return self._reply(f"{instance.name} no longer starts at boot", True, lines)

    def log_of(self, name) -> dict:
        """A local instance's log: its path and its last lines (its start at boot's own log's after them)."""
        instance = self.instance(name)
        log = self.log_path(instance.name)
        lines = children.last_lines(log, LOG_LINES)
        if instance.boot:
            boot = children.last_lines(self.boot_log(instance.name), BOOT_LINES)
            if boot:
                lines += [f"… its {self._task()}'s own log, {self.boot_log(instance.name)}:", *boot]
        return self._reply(str(log), True, lines or ["nothing is in it yet"])

    def try_it(self, name, model, prompt) -> dict:
        """A prompt answered by an instance through its OpenAI-compatible endpoint: cut at TRY_TOKENS tokens and
        ANSWER_CHARS characters, waited for CHAT_S. Refused: no prompt, one past PROMPT_CHARS characters, no model, a
        local instance not running."""
        instance = self.instance(name)
        text = "" if prompt is None else str(prompt)
        if not text.strip():
            raise Refusal("type a prompt first")
        if len(text) > PROMPT_CHARS:
            raise Refusal(f"the prompt is {len(text):,} characters long: {PROMPT_CHARS:,} at most")
        named = " ".join(str(model or "").split())
        if not named or len(named) > MODEL_CHARS or instances.has_control(named):
            raise Refusal(f"name a model of {instance.name}'s, {MODEL_CHARS} characters at most")
        if instance.where == "local" and self._live(instance)[0] is None:
            raise Refusal(self._idle_words(instance, "start it first"))
        try:
            got = self.endpoint(instance, timeout=CHAT_S).chat(named, text, max_tokens=TRY_TOKENS, timeout=CHAT_S)
        except EndpointError as e:
            return self._reply(f"{named} on {instance.name} did not answer: {_words(e)}", False)
        lines = [line for line in str(got.get("text") or "").splitlines() if line.strip()] or ["(an empty answer)"]
        notes = [*([f"… its answer is cut here, at {ANSWER_CHARS:,} characters"] if got.get("cut") else []),
                 *([f"… it stopped at {TRY_TOKENS} tokens"] if got.get("finish") == "length" else [])]
        room = LINES_MOST - len(notes)  # an answer holds LINES_MOST lines: what is said of the cut is kept after them
        if len(lines) > room:
            lines = [*lines[:room - 1], f"… and {len(lines) - room + 1:,} more lines"]
        lines += notes
        tokens = (got.get("tokens") or {}).get("completion")
        said = f"{got.get('model') or named} answered in {got.get('seconds', 0):g} s" + (
            f" ({tokens:,} tokens)" if isinstance(tokens, int) else "")
        return self._reply(said, True, lines)

    def _row(self, instance: Instance) -> dict:
        """An instance as another plugin is told it (serving): from what is kept alone, the boot registrations as last
        read (no command is run for another plugin's ask)."""
        reading = self._reading(instance, boot=False)
        seen = self.seen(instance.name)
        try:
            base = self.base(instance)
        except ValueError:
            base = ""
        context = instance.settings.get("context")
        model = instance.settings.get("model")
        return {"name": instance.name, "title": instance.title, "where": instance.where,
                "local": instance.where != "remote", "base": base, "openai": f"{base}/v1" if base else "",
                "plain": instance.plain, "state": reading["state"],
                "key": self.key_variable(instance.name) if instance.keyed else "",
                "model": model if isinstance(model, str) else "",
                "context": context if isinstance(context, int) and not isinstance(context, bool) else None,
                "models": _served(seen.models) if seen is not None and seen.ok else [],
                "asked": _iso(seen.at) if seen is not None else "", "port": self.port_of(instance)}

    def serving(self, name: str = "") -> dict:
        """What this plugin offers the other AI plugins, asked through the platform: {"plugin", "title", "native",
        "instances": [{"name", "title", "where", "local", "base", "openai" (base + "/v1"), "plain", "state" (the word
        alone), "key" (its pair's variable, "" when none: never the key), "model", "context", "models": [{"id",
        "context", "tools"}] as last listed, "asked", "port"}]}; with `name`, that one alone (LookupError for none). No
        network, no process; `conflict` is never asked."""
        kept = self.kept_instances().instances
        if name:
            key = str(name).strip().lower()
            if key not in kept:
                raise LookupError(f"{self.title or self.name} has no instance {str(name)[:40]!r}")
            chosen = [kept[key]]
        else:
            chosen = list(kept.values())
        return {"plugin": self.name, "title": self.title or self.name, "native": self.NATIVE,
                "instances": [self._row(i) for i in chosen]}

    def models_of(self, name) -> dict:
        """An instance asked now for its models (another plugin's ask, through the platform): {"said", "ok",
        "models": [{"id", "context", "tools"}], "asked"}. A local one that is not running is not asked."""
        instance = self.instance(name)
        if instance.where == "local" and self._live(instance)[0] is None:
            return {"said": self._idle_words(instance, f"start it on {self.title or self.name}'s page first"),
                    "ok": False, "models": [], "asked": ""}
        seen = self.asked(instance, fresh=True)
        return {"said": seen.said, "ok": seen.ok, "models": _served(seen.models) if seen.ok else [],
                "asked": _iso(seen.at)}

    def app_stopping(self) -> None:
        """The platform stops, or the plugin is turned off: every server a click started stopped side by side (this
        run's, and one an earlier run of the platform started and left behind), what the system started left
        running. It bears a second call. ChildError naming what could not be ended."""
        with self._rt.lock:
            ours = list(self._rt.children.values())
        kids = [c for c in ours if c.alive]
        try:
            kept = list(self.kept_instances().instances.values())
        except Exception:  # noqa: BLE001 - its instances cannot be read: its own children alone
            kept = []
        named = {getattr(c, "name", "") for c in kids}
        for instance in kept:
            if instance.where != "local" or instance.boot or instance.name in named:
                continue
            child, by = self._live(instance)
            if child is not None and by == "earlier" and getattr(child, "note", ""):
                kids.append(child)
        if not kids:
            return
        children.stop_these(kids)
        left = []
        for c in kids:
            try:
                alive = c.alive
            except Exception:  # noqa: BLE001 - one that cannot say is taken for ended
                alive = False
            if alive:
                left.append(str(getattr(c, "name", "")))
        with self._rt.lock:
            for key in [k for k, c in self._rt.children.items() if c in kids and k not in left]:
                del self._rt.children[key]
            for key in [k for k, c in self._rt.adopted.items() if c in kids and k not in left]:
                del self._rt.adopted[key]
        if left:
            raise children.ChildError(f"{_and(left)} could not be ended: {'it runs' if len(left) == 1 else 'they run'}"
                                      " on")

    # -- what the page draws ------------------------------------------------------------------------------------------
    def _extra(self, call: Callable[[], dict]) -> tuple[dict, str]:
        """What a subclass adds to a page ({"tables", "forms", "actions"}), and what failed of it, in words."""
        try:
            got = call()
        except Exception as e:  # noqa: BLE001 - its own part fails: the base's is drawn and the fault said
            return {}, self._scrubbed(_words(e))
        return (dict(got) if isinstance(got, Mapping) else {}), ""

    @staticmethod
    def _merge(page: dict, extra: Mapping) -> dict:
        for key in ("tables", "forms", "actions"):
            page[key] = [*page.get(key, []), *(x for x in (extra.get(key) or ()) if isinstance(x, Mapping))]
        for key, value in extra.items():
            if key not in ("tables", "forms", "actions") and key not in page:
                page[key] = value
        return page

    def _change_values(self, instance: Instance) -> dict:
        values: dict = {"name": instance.name}
        if instance.where == "remote":
            values["address"] = self.address(instance)
        else:
            values["port"] = self.port_of(instance)
        if instance.where == "local":
            values.update({s.name: instance.settings[s.name] for s in self.SETTINGS if s.name in instance.settings})
        return values

    def _tasks(self, instance: Instance, reading: Mapping, have: Installed | None | object = _UNREAD) -> list[dict]:
        """The shown instance's buttons, one that does not apply now disabled with why (`have`: startable()'s)."""
        name, local = instance.name, instance.where == "local"
        runs = reading.get("state") in UP and local
        by = reading.get("by")
        values = {"name": name}
        elsewhere = f"{WHERE_WORDS[instance.where]}: it runs where it was started"
        startable = self.startable(instance, have)
        running = (f"its {self._task()} runs it" if by == "system" else "it runs") if runs else ""
        start_why = elsewhere if not local else startable or running
        stop_why = elsewhere if not local else "" if runs else "it is not running"
        change_why = "stop it first" if runs else ""
        key_why = (f"{self.title or self.name}'s server checks no key" if local and not self.KEYED
                   else "stop it first" if runs else "")
        share_why = (elsewhere if not local else f"{self.title or self.name}'s server has no key" if not self.KEYED
                     else "stop it first" if runs else "")
        boot_why = elsewhere if not local else (self._boot_refusal(instance, startable) if not instance.boot else "")
        log_why = "" if local else f"{WHERE_WORDS[instance.where]}: it keeps its log where it runs"
        forget_why = "stop it first" if runs and by != "system" else ""
        out = [self._button("ai-start", "Start", values, start_why),
               self._button("ai-stop", "Stop", values, stop_why),
               self._button("ai-change", "Change…", self._change_values(instance), change_why),
               self._button("ai-key", "Key…", values, key_why)]
        if instance.keyed:
            out.append(self._button("ai-key-forget", "Forget the key…", values,
                                    "turn Share off first" if instance.shared else "stop it first" if runs else ""))
        out += [self._button("ai-share", "Share…", {**values, "on": "no" if instance.shared else "yes"}, share_why),
                self._button("ai-boot", "At boot…", {**values, "on": "no" if instance.boot else "yes"}, boot_why),
                self._button("ai-log", "Log", values, log_why),
                self._button("ai-remove", "Forget…", values, forget_why)]
        return out

    def _name_field(self, name: str) -> dict:
        return {"name": "name", "label": "Instance", "type": "fixed", "value": name}

    def _forms(self, listed: list[Instance], shown: Instance | None, reading: Mapping | None = None) -> list[dict]:
        """The instances' forms: ai-add always; the others for the instance shown (their words are its own, and its
        `reading`'s: a server of a click's running now)."""
        title = self.title or self.name
        p = int(self.DEFAULT_PORT or 0)
        where = [{"value": "local", "title": "Run here", "note": f"{title} is started and stopped from this page"},
                 {"value": "found", "title": "Found on this machine",
                  "note": "a server started elsewhere that answers at this machine's own address"},
                 {"value": "remote", "title": "Another machine", "note": "asked by its address, never started here"}]
        if self.runs_here():
            where = where[1:]
        local_only = {"where": ["local"]}
        free = "default" if "default" not in {i.name for i in listed} else ""
        add_fields = [
            {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "default",
             "note": "lowercase letters, digits and dashes", **({"value": free} if free and not listed else {})},
            {"name": "where", "label": "Where", "type": "choice", "choices": where},
            {"name": "address", "label": "Address", "type": "text", "when": {"where": ["remote"]},
             "placeholder": f"gpu-box:{p or 'port'}, or an https address", "keyboard": "url",
             "note": f"a host and its port, without {V1} (every ask adds it); http to another machine is asked again"},
            {"name": "port", "label": "Port", "type": "number", "min": PORTS[0], "max": PORTS[1],
             "when": {"where": ["local", "found"]},
             "placeholder": f"empty: {p}, the maker's" if p else "its port", "note": "this machine's port for it"},
            {"name": ACCEPT_PLAIN, "type": "accept", "title": "Ask it over plain http?", "yes": "Add it anyway",
             "words": UNENCRYPTED},
            *({**s.field(), "when": local_only} for s in self.SETTINGS)]
        forms = [{"id": "ai-add", "hook": "add_instance", "title": "Add an instance", "submit": "Review",
                  "note": "An instance is a server: one run here, one found on this machine, or another machine's.",
                  "fields": add_fields,
                  "confirm": {"title": "Add the instance {name}?",
                              "words": "It is kept through your login. Nothing is started, installed or asked of it "
                                       "now.", "yes": "Add"}}]
        if shown is None:
            return forms
        name, task = shown.name, self._task()
        fixed = self._name_field(name)
        remotes = [i.name for i in listed if i.where == "remote"]
        here = [i.name for i in listed if i.where != "remote"]
        locals_ = [i.name for i in listed if i.where == "local"]
        change_fields = [
            fixed,
            {"name": "address", "label": "Address", "type": "text", "when": {"name": remotes}, "keyboard": "url",
             "note": f"left as it is, its address stays; without {V1} (every ask adds it)"},
            {"name": "port", "label": "Port", "type": "number", "min": PORTS[0], "max": PORTS[1],
             "when": {"name": here}, "placeholder": f"empty: {p}, the maker's" if p else "its port"},
            {"name": ACCEPT_PLAIN, "type": "accept", "title": "Ask it over plain http?", "yes": "Change it anyway",
             "words": UNENCRYPTED},
            *({**s.field(shown.settings.get(s.name)), "when": {"name": locals_}} for s in self.SETTINGS)]
        log = self.log_path(name)
        boot_line = (f" It is started by its {task}, as at boot." if shown.boot else
                     " It stops when the platform stops or this plugin is disabled, unless it starts at boot.")
        extra = self._one_line(lambda: self.start_words(shown))
        start_words = (f"{title} is started at {self.address(shown)} as a program of yours, without a window; its log "
                       f"is {log}.{boot_line}" + (f" {extra}" if extra else ""))
        stop_words = (f"It is asked to end and given {children.GRACE_S:g} s, then ended with what it started. Programs "
                      "using it lose it."
                      + (f" Its {task} is stopped too; it starts again at your next sign-in." if shown.boot else ""))
        boot_words = (f"{autostart.how(self.system, self.wsl)}. Turned on, it is started by the system when you sign "
                      "in and again after a failure, this plugin attaching to it; it no longer stops with the "
                      f"platform. Its {task} runs one program of the platform's beside the server for as long as it "
                      "runs (launch serve, which loads the platform's plugins). Nothing is started now. Turned off, "
                      f"its {task} is stopped and removed; the instance stays.")
        if not shown.boot and reading is not None and reading.get("by") == "plugin":
            boot_words += (" The server running now was started from this page: it still stops with the platform, "
                           f"and its {task} starts it from your next sign-in.")
        pair = self.key_variable(name)
        forms += [
            {"id": "ai-change", "hook": "change_instance", "title": f"Change {name}", "submit": "Review",
             "fields": change_fields,
             "confirm": {"title": "Change {name}?",
                         "words": "Its definition is kept through your login and read at its next start or ask.",
                         "yes": "Change"}},
            {"id": "ai-remove", "hook": "remove_instance", "title": f"Forget {name}", "fields": [fixed],
             "confirm": {"title": "Forget the instance {name}?",
                         "words": "Its definition and its key are forgotten and its start at boot is removed. The "
                                  "software and its models stay; a remote server is told nothing.",
                         "yes": "Forget", "danger": True}},
            {"id": "ai-key", "hook": "set_key", "title": f"A key for {name}", "submit": "Review",
             "fields": [fixed, {"name": "key", "label": "Key", "type": "password", "required": True,
                                "note": "never shown back"}],
             "confirm": {"title": "Keep a key for {name}?",
                         "words": f"It is kept through your login as its own pair ({pair}), never in a file or a "
                                  "log; a local server starts with it, a remote one is sent it with each ask.",
                         "yes": "Keep"}},
            {"id": "ai-key-forget", "hook": "forget_key", "title": f"Forget {name}'s key", "fields": [fixed],
             "confirm": {"title": "Forget {name}'s key?", "words": f"Its pair {pair} is forgotten.", "yes": "Forget"}},
            {"id": "ai-share", "hook": "share", "title": f"Where {name} listens", "submit": "Review",
             "fields": [fixed, {"name": "on", "label": "Listen", "type": "choice",
                                "choices": [{"value": "yes", "title": "Beyond this machine"},
                                            {"value": "no", "title": "On this machine alone"}]},
                        {"name": ACCEPT_SHARE, "type": "accept", "title": "Listen beyond this machine?",
                         "yes": "Share it", "words": "Read at its next start."}],
             "confirm": {"title": "Where {name} listens: {on}?", "words": "Read at its next start.", "yes": "Go on"}},
            {"id": "ai-start", "hook": "start", "title": f"Start {name}", "fields": [fixed],
             "confirm": {"title": "Start {name}?", "words": start_words, "yes": "Start"}},
            {"id": "ai-stop", "hook": "stop", "title": f"Stop {name}", "fields": [fixed],
             "confirm": {"title": "Stop {name}?", "words": stop_words, "yes": "Stop"}},
            {"id": "ai-boot", "hook": "boot", "title": f"{name} at boot", "submit": "Review",
             "fields": [fixed, {"name": "on", "label": "At boot", "type": "choice",
                                "choices": [{"value": "yes", "title": "Start it at boot"},
                                            {"value": "no", "title": "Not at boot"}]}],
             "confirm": {"title": "{name}: {on}?", "words": boot_words, "yes": "Go on"}},
            {"id": "ai-log", "hook": "log_of", "title": f"{name}'s log", "fields": [fixed], "confirm": False}]
        return forms

    def _one_line(self, call: Callable[[], str]) -> str:
        """What `call` says, on one line; "" when it cannot be had (never AiPlugin._said, which a status needs)."""
        try:
            return " ".join(str(call() or "").split())
        except Exception:  # noqa: BLE001 - its own words cannot be had: the base's stand
            return ""

    def _instances_table(self, listed, readings, conflicts, shown, have=_UNREAD) -> dict:
        rows = []
        for i in listed:
            r, c = readings[i.name], conflicts[i.name]
            cells = [{"text": i.name, "sub": i.title} if i.title else i.name, WHERE_WORDS[i.where], self.address(i),
                     {"text": r["state"], "sub": c or r["said"]},
                     ("yes" if i.boot else "no") if i.where == "local" else "–", "kept" if i.keyed else "none"]
            rows.append({"key": i.name, "cells": cells})
        table = {"title": "Instances",
                 "note": "Each a server: run here, found on this machine, or another machine's. Its models are on the "
                         "Models tab; choose one to show it.",
                 "columns": [{"title": "Instance"}, {"title": "Where"}, {"title": "Address"}, {"title": "State"},
                             {"title": "At boot"}, {"title": "Key"}],
                 "rows": rows, "select": {"hook": "choose", "value": shown.name if shown else "",
                                          "title": "Show its models"},
                 "actions": [{"form": "ai-add", "title": "Add an instance…"}],
                 "empty": "No instance yet: Add an instance… (a server run here, one found on this machine, or "
                          "another machine's)."}
        if shown is not None:
            table["tasks"] = {"title": "Instance", "subject": shown.name,
                              "actions": self._tasks(shown, readings[shown.name], have)}
        return table

    def _answering(self, listed) -> dict | None:
        """A listener on the maker's port that no instance covers, offered as a found instance."""
        p = int(self.DEFAULT_PORT or 0)
        if not p or any(self.port_of(i) == p for i in listed if i.where != "remote"):
            return None
        held = holders(p, self._table())
        if not held:
            return None
        names = {i.name for i in listed}
        stem = "wsl" if any(h.relay for h in held) else "found"
        name = next((n for n in (stem, *(f"{stem}-{k}" for k in range(2, 99))) if n not in names), stem)
        return {"title": "Answering on this machine",
                "note": f"Something listens on {self.title or self.name}'s own port {p} and no instance covers it.",
                "columns": [{"title": "Address"}, {"title": "Held by"}, {"title": ""}],
                "rows": [[f"{LOOPBACK}:{p}", held_words(p, held),
                          {"form": "ai-add", "title": "Add it…", "values": {"name": name, "where": "found", "port": p},
                           "label": f"Add what answers at port {p} as a found instance"}]]}

    def status(self) -> dict:
        """Its Main: the base's (the install), then its instances (each one's state, its conflict, its buttons), what
        answers on the maker's port that no instance covers, and main_more(). Asks nothing over the network and runs
        nothing (the socket table, the pidfiles, kept readings) but the boot registrations' read when an instance
        starts at boot (state's). Its instances and the install are read once for the whole draw. Never raises."""
        if self.not_for_here() or self.too_old():
            return self.base_status()  # (nothing of its instances is read)
        kept = self.kept_instances()
        listed = list(kept.instances.values())
        have = self.installed()
        readings = {i.name: self._reading(i) for i in listed}
        local = [i for i in listed if i.where == "local"]
        up = [i.name for i in local if readings[i.name]["state"] in UP]  # what running() answers: read once here
        out = self.base_status(have=have, running=up, boot=[i.name for i in listed if i.boot])
        with self._rt.lock:
            chosen = self._rt.shown
        shown = kept.instances.get(chosen) or (listed[0] if listed else None)
        conflicts = {i.name: self.conflict(i, kept=kept) for i in listed}
        if local:
            out["running"] = f"{len(up)} of {len(local)}"
            out["summary"] = f"{out.get('summary') or self.title}; {len(up)} of {len(local)} running here"
        problems = [str(out.get("problem") or ""), kept.problem]
        problems += [f"{n}: {c}" for n, c in conflicts.items() if c][:1]
        if any(i.boot for i in local):
            problems.append(self._boot_problem())
        tables = [self._instances_table(listed, readings, conflicts, shown, have)]
        answering = self._answering(listed)
        if answering is not None:
            tables.append(answering)
        out["tables"] = [*out.get("tables", []), *tables]
        out["forms"] = [*out.get("forms", []),
                        *self._forms(listed, shown, readings[shown.name] if shown is not None else None)]
        extra, fault = self._extra(self.main_more)
        self._merge(out, extra)
        if fault:
            problems.append(f"its own part of this page could not be drawn: {fault}")
        problem = "; ".join(p for p in problems if p)
        if problem:
            out["problem"] = problem
        else:
            out.pop("problem", None)
        return out

    def _gpus(self):
        which = None if self.out.which is _DEFAULT_WHICH else self.out.which
        return gpu.kept(runner=self.out.runner, which=which, clock=self.out.clock, env=self.child_env())

    def _model_row(self, instance: Instance, model: dict, gpus) -> list:
        size, context, loaded = model.get("size"), model.get("context"), model.get("loaded")
        if instance.where == "remote":
            fits = "the other machine's GPU is not read from here"
        elif gpus is None:
            fits = "–"
        else:
            fits = gpu.fit(size, gpus) or "its size is not said"
        cells = [{"text": model["id"], "sub": model["detail"]} if model.get("detail") else model["id"],
                 size_words(size) if size else "–", f"{context:,}" if context else "–",
                 "yes" if loaded is True else "no" if loaded is False else "–", fits]
        own: list = []
        try:
            own = list(self.model_cells(instance, model) or [])
        except Exception:  # noqa: BLE001 - its own cells cannot be had: left empty
            own = []
        own = own[:len(self.MODEL_COLUMNS)]
        return cells + own + [""] * (len(self.MODEL_COLUMNS) - len(own))

    def _try_form(self, instance: Instance, seen: Seen | None) -> dict:
        listed = [m["id"] for m in seen.models] if seen is not None and seen.ok else []
        model = ({"name": "model", "label": "Model", "type": "choice", "choices": [{"value": m} for m in listed]}
                 if listed else {"name": "model", "label": "Model", "type": "text", "required": True,
                                 "note": "its name as the server lists it"})
        return {"id": "ai-try", "hook": "try_it", "title": f"Try {instance.name}", "submit": "Review",
                "fields": [self._name_field(instance.name), model,
                           {"name": "prompt", "label": "Prompt", "type": "text", "required": True,
                            "note": f"{PROMPT_CHARS:,} characters at most"}],
                "confirm": {"title": "Ask {model}?",
                            "words": f"The prompt is sent to {instance.name} at {self.address(instance)}; a model not "
                                     f"loaded is loaded first and takes memory. The answer is cut at {TRY_TOKENS} "
                                     f"tokens and {ANSWER_CHARS:,} characters, and waited for {CHAT_S:g} s.",
                            "yes": "Ask"}}

    def _models_page(self) -> dict:
        shown = self.shown()
        if shown is None:
            page = {"title": "Models", "note": "No instance yet: add one on the Main tab (Add an instance…); then its "
                                               "models are listed here.", "tables": [], "forms": [], "actions": []}
            extra, fault = self._extra(lambda: self.more(None, None))
            if fault:
                page["note"] += f" Its own part of this page could not be drawn: {fault}"
            return self._merge(page, extra)
        name = shown.name
        reading = self._reading(shown)
        # a local one with no server running: stopped, exited, or its task or unit waiting to start it again
        stopped = shown.where == "local" and (reading["state"] in ("stopped", "exited") or reading["pid"] is None)
        seen = None if stopped else self.asked(shown)
        gpus = self._gpus() if shown.where != "remote" else None
        rows = [self._model_row(shown, m, gpus) for m in seen.models] if seen is not None and seen.ok else []
        now = self.out.clock()
        if stopped:
            note = self._idle_words(shown, "start it on the Main tab") + ", and then its models are listed here."
        elif seen.ok:
            note = (f"{seen.said} (asked at {_when(seen.at, now)}, {seen.seconds:g} s"
                    + (f"; {seen.version}" if seen.version else "") + ").")
        else:
            note = f"{name} did not answer as expected: {seen.said}"
        try_why = f"{name} is not running" if stopped else ""  # (a list that failed may not stop a chat)
        columns = [{"title": "Model"}, {"title": "Size", "num": True}, {"title": "Context", "num": True},
                   {"title": "Loaded"}, {"title": "Fits this GPU"}, *({"title": c} for c in self.MODEL_COLUMNS)]
        table = {"title": f"Models on {name}", "note": f"{WHERE_WORDS[shown.where]}, {self.address(shown)}",
                 "columns": columns, "rows": rows,
                 "empty": (f"{name} is not running." if stopped else "It lists no model." if seen.ok
                           else "Nothing is listed: it did not answer."),
                 "actions": [self._button("ai-try", "Try it…", {"name": name}, try_why),
                             {"hook": "models_of", "args": [name], "title": "Ask it again",
                              "note": f"asks {name} now", **({"disabled": True, "note": try_why} if stopped else {})}]}
        tables = [table]
        if gpus is not None:
            tables.append(gpu.table(gpus))
        page = {"title": f"{name}: its models", "note": note, "tables": tables, "forms": [self._try_form(shown, seen)],
                "actions": []}
        extra, fault = self._extra(lambda: self.more(shown, seen))
        if fault:
            page["note"] += f" Its own part of this page could not be drawn: {fault}"
        return self._merge(page, extra)

    def models(self) -> dict:
        """Its Models tab (asked every 15 s while it is shown, never otherwise): the shown instance's models as it
        lists them (asked once per SEEN_S; a local one that is stopped is not asked), this machine's GPU and what fits
        it, Try it, and more(). Never raises: what failed is said on the page."""
        try:
            return self._models_page()
        except Exception as e:  # noqa: BLE001 - the page says what failed
            return {"title": "Models", "note": f"this page could not be drawn whole: {self._scrubbed(_words(e))}",
                    "tables": [], "forms": [], "actions": []}
