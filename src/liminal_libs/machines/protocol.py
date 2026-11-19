"""What every protocol plugin of the platform shares (1.66.0; the user, 2026-11-18: "now i need an MCP plugin for
platform, basically a protocol plugin that mediates MCP connections to resources by local AI agents").

`ProtocolPlugin` is the base, under AiPlugin (machines/ai.py), of a plugin that speaks a protocol to the local AI agents
on the platform's own port: MCP's first (plugin-platform-mcp). It is drawn under the platform's AI heading, among the
protocols (GROUP "protocol"). Its software is its own code: there is nothing to install (Installed.how "part"). A
subclass says three things: its protocol (`serve`), how an agent is wired to it (`offer`) and what its grants can name
(`grantable`). The base gives the rest:

- The route's hook (RPC_HOOK, "rpc"). The platform's route hands it a request whole (liminal-platform 0.34.0: POST, GET
  and DELETE on /api/machines/<name>/rpc); it is never asked by name. The base finds the agent by its bearer token and
  holds it to its rate, then the request is the subclass's. A request without a token it knows is answered 401, with
  WWW-Authenticate: Bearer.
- Its agents (`clients`). Each is named by 1 to 24 lowercase letters and digits (RESERVED names refused), MAX_CLIENTS
  at most, kept as one JSON pair through the login: LIMINAL_AI_<NAME>_CLIENTS. Each agent's grants are a pair of its
  own: LIMINAL_AI_<NAME>_AGENT_<A>_GRANTS. A new agent is granted nothing. The pairs are read once, at attach, and used
  from memory: a pair changed outside the plugin is not used, and its page says so.
- Tokens, never kept as text. A hand-wired token is shown once (`token_once`): its sha256 and its expiry are kept in
  its agent's entry. A launch token is made for the asking plugin's agent (`launch_token`): its sha256 is held in
  memory alone, MAX_LAUNCH at most, and ended by `end_launch`, by a stop, or by newer ones past the cap. Each token is
  made with secrets.token_urlsafe and compared with hmac.compare_digest.
- Calls held for the user's answer on the page (`hold`, `decide`). MAX_HELD_EACH wait for one agent and MAX_HELD in
  all. Each waits on an event and looks at its request's gone() every POLL_S. A call ends by an answer, by its hold
  running out, by its request gone, by the agent's cancel (`cancel_held`) or by a stop. A call that ends unanswered
  never runs.
- The audit (`record`). The last RING calls are kept in memory, their arguments masked and cut. Each call is a line of
  home/logs/calls.log on disk, without its arguments (moved aside past 1 MB, as a child's log is), and a row of the
  platform's traffic: agent:<name> to this plugin. Every secret value the plugin knows is masked.

Who asks is the platform's to say (apps/asking.py: `asker`). Its decisions are asked only from its page
(PAGE_ONLY_HOOKS). What hands out a token is asked only by another plugin through the platform, for that plugin's own
agent (PLUGIN_ONLY_HOOKS). The base holds each to that too, and an ask that does not say who asks is refused, in
words. Nothing it holds lets it contain an agent whose own commands can reach the platform's API: what it does not stop
is the subclass's to say on its page."""
from __future__ import annotations

import functools
import hashlib
import hmac
import inspect
import json
import math
import re
import secrets
import threading
import time
import unicodedata
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from .. import instances
from ..apps import asking
from ..instances import _stem
from . import children
from .ai import STEM, AiPlugin, Installed, Refusal, Run, _and, _words, exactly
from .plugin import MachinePlugin

PROTOCOL = "protocol"  # its group under the platform's AI heading (liminal-platform 0.34.0 draws it as Protocols)
RPC_HOOK = "rpc"  # the hook the platform's route hands a request to whole: never asked by name
NAME = re.compile(r"^[a-z0-9]{1,24}$")  # an agent's name: no hyphen (a pair's name turns "-" into "_")
RESERVED = ("platform", "mcp", "liminal", "page")  # names no agent takes
MAX_CLIENTS = 16  # agents at most
MAX_GRANTS = 160  # grants of one agent at most
WHAT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+=-]{0,159}$")  # what a grant names
HOW_CHARS = 16  # characters of how a grant takes what it names
MAX_LAUNCH = 32  # launch tokens held at most, in all: a newer one pushes out the oldest
MAX_HELD = 16  # calls waiting for the user's answer at most, in all
MAX_HELD_EACH = 4  # and for one agent
RING = 500  # calls kept in memory
SHOWN_CHARS = 200  # characters of a call's arguments in a row, masked
WHOLE_MOST = 16 << 10  # bytes of a held call's arguments as shown: one longer cannot be shown whole, so not allowed
WORDS_CHARS = 400  # characters of the words said of a held call
WHAT_CHARS = 200  # characters of what a call reaches, as it is noted
TOKEN_BYTES = 32  # of a token, as secrets.token_urlsafe makes it (43 characters)
TOKEN_CHARS = 512  # of a bearer token read: a longer one is none of this plugin's
DAYS, DAYS_MOST = 30, 365  # a hand-wired token's days, by default and at most
DAY_S = 86400
HOLD_S, HOLD_LEAST, HOLD_MOST = 50, 10, 600  # an agent's hold: how long a call waits for an answer, in seconds
RATE, RATE_MOST = 60, 600  # an agent's requests a minute, by default and at most
WINDOW_S = 60.0  # the rate's window
POLL_S = 0.5  # how often a held call looks at whether its request is gone
SESSION_S = 600.0  # "Allow for this session" lasts this long at most
ALLOWANCES = 256  # such allowances held at most
CALLS_LOG = "calls.log"  # in its folder's logs/: one line a call, no argument in it
LOG_MAX = children.LOG_MAX  # bytes: the calls log is moved to calls.log.1 past this
VERSION = 1  # of the values kept
ACCEPT_SHOWN = "accept_shown"  # token_once's second confirmation: a token shown once, the one before ended
ACCEPT_TWICE = "accept"  # decide's second confirmation, for a call whose rule asks twice
RULES = ("allow", "ask", "ask twice", "deny")  # how a grant of calls takes them (a subclass's grantable says so)
ANSWERS = ("once", "session", "deny")  # the user's answers to a held call
ENDS = (*ANSWERS, "timeout", "gone", "cancelled", "stopped", "refused")  # how a held call ends
OWN = ("hold", "rate")  # what a grant names that is the base's own: kept in the agent's entry
KINDS = ("read", "change", "ask", "stream")  # a call's class in the platform's traffic (apps/traffic.py)
# the ways a harness reaches it, as an offer names them (machines/harness.py reads these words): "stdio", its bridge, a
# program the harness's tool starts and speaks to over its standard input and output; "http", the platform's route
WIRES = ("stdio", "http")
WIRE_WORDS = {"stdio": "stdio (its bridge)", "http": "http (the platform's route)"}
DIGEST = re.compile(r"^[0-9a-f]{64}$")
# characters that draw nothing yet are characters all the same: shown as their code points (visible)
UNSEEN = frozenset({0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180E, 0x180F, 0x3164, 0xFFA0,
                    *range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)})
TOKEN_WORDS = ("a bearer token for each agent: a hand-wired one kept as its sha256 and expiry alone, a launch token "
               "as its sha256, in memory alone")
_request = threading.local()  # how many rows a request handed to `serve` noted (`record`), in its own thread


def asker() -> str | None:
    """Who asks this plugin now, as the platform hands it over (apps/asking.py's asker): another plugin's name, "page"
    for its page (and a job started there: asking.PAGE), or None when nothing was handed over. Looked up when it is
    asked, so a stand-in for it is seen."""
    try:
        who = asking.asker()
    except Exception:  # noqa: BLE001 - an asker that cannot be told is no asker: every hook it gates is refused
        return None
    return who if isinstance(who, str) and who else None


def digest_of(token) -> str:
    """A token's sha256, in hex: all that is ever kept of it."""
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def agent_of(plugin) -> str:
    """The agent a plugin's ensure_client makes: its name without its hyphens (codex-cli's is codexcli)."""
    return str(plugin or "").strip().lower().replace("-", "")


def visible(text) -> str:
    """`text` with each character that draws nothing, or turns the text's direction, written as its code point
    (<U+202E>): a control (but a line feed), a format character, a separator other than the space, one of private use
    or unassigned, and the fillers and selectors that draw nothing (UNSEEN)."""
    out = []
    for c in str(text):
        kind = unicodedata.category(c)
        if c != "\n" and (kind in ("Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp") or (kind == "Zs" and c != " ")
                          or ord(c) in UNSEEN):
            out.append(f"<U+{ord(c):04X}>")
        else:
            out.append(c)
    return "".join(out)


def _cut(text: str, chars: int) -> str:
    return text if len(text) <= chars else text[:chars - 1].rstrip() + "…"


def _what(what) -> str:
    """What a call asks, as it is held, allowed and noted: on one line, every character shown, WHAT_CHARS at most."""
    return _cut(visible(" ".join(str(what or "").split())), WHAT_CHARS) or "a call"


def _key(key) -> str:
    """An agent's own id for a call, or its session, as it is held: 200 characters at most."""
    return str(key or "")[:200]


def _said(value, chars: int) -> str:
    """A kept word as text, on one line, `chars` at most."""
    return _cut(" ".join(str(value).split()), chars) if isinstance(value, (str, int)) else ""


def _number(value, low: int, high: int, default: int) -> int:
    """A kept whole number within its bounds; `default` for anything else."""
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        return default
    return value


def _whole(value, low: int, high: int, label: str) -> int:
    """A whole number as typed, within its bounds: a Refusal in words for anything else."""
    number = value
    if isinstance(number, float) and number.is_integer():
        number = int(number)
    elif isinstance(number, str) and re.fullmatch(r"\s*\d{1,9}\s*", number):
        number = int(number)
    if isinstance(number, bool) or not isinstance(number, int) or not low <= number <= high:
        raise Refusal(f"{label} is a whole number from {low:,} to {high:,}, not {str(value)[:40]!r}")
    return number


def _text_of(arguments, *, compact: bool = False) -> str:
    """A call's arguments as text: JSON, every character as it is, in their order (`compact`: on one line); text as
    it is."""
    if arguments is None:
        return ""
    if isinstance(arguments, str):
        return arguments
    try:
        if compact:
            return json.dumps(arguments, ensure_ascii=False, separators=(",", ":"), default=str)
        return json.dumps(arguments, ensure_ascii=False, indent=1, default=str)
    except (TypeError, ValueError):
        return str(arguments)


def _waits(event: threading.Event, seconds: float) -> bool:
    return event.wait(max(0.0, seconds))


def _gone(probe) -> bool:
    """Whether a request's agent has closed its connection, as its probe says: one that fails is gone too."""
    try:
        return bool(probe())
    except Exception:  # noqa: BLE001 - a connection that cannot say cannot be answered either
        return True


def _folder_of(cls) -> str:
    """The folder of a class's own code (files looked at only)."""
    try:
        return str(Path(inspect.getfile(cls)).parent)
    except (TypeError, OSError):
        return ""


def _iso(seconds) -> str:
    return instances.now_iso(lambda: float(seconds)) if seconds else ""


def _or(words) -> str:
    """Words as choices: "a", "a or b", "a, b or c"."""
    shown = [str(w) for w in words if str(w)]
    return "".join(shown) if len(shown) < 2 else ", ".join(shown[:-1]) + " or " + shown[-1]


def _listed(value) -> list:
    return list(value) if isinstance(value, (list, tuple)) else []


def _many(n: int, one: str, more: str = "") -> str:
    return f"{n} {one if n == 1 else (more or one + 's')}"


def _entry_of(name, item, reserved) -> dict | None:
    """One kept agent's entry, checked: None when it cannot be read."""
    if not isinstance(name, str) or not NAME.fullmatch(name) or name in reserved or not isinstance(item, dict):
        return None
    digest = item.get("digest") or ""
    if not isinstance(digest, str) or (digest and not DIGEST.fullmatch(digest)):
        return None
    return {"title": _said(item.get("title"), instances.MAX_TITLE) or name, "made": _said(item.get("made"), 40),
            "by": _said(item.get("by"), 64), "digest": digest, "expires": _number(item.get("expires"), 0, 2 ** 53, 0),
            "hold_s": _number(item.get("hold_s"), HOLD_LEAST, HOLD_MOST, HOLD_S),
            "rate": _number(item.get("rate"), 1, RATE_MOST, RATE)}


def clients_of(text, reserved=RESERVED) -> tuple[dict, str]:
    """The agents of a kept value, by name, and what of it could not be read, in words: none for none; a value that
    cannot be read holds none; an agent that cannot be read is left out; MAX_CLIENTS are read at most."""
    if text is None or not str(text).strip():
        return {}, ""
    try:
        raw = json.loads(text)
    except (TypeError, ValueError) as e:
        return {}, f"what is kept of its agents is not readable ({e}): none is used until one is added again"
    kept = raw.get("clients") if isinstance(raw, dict) else None
    if not isinstance(kept, dict):
        return {}, "what is kept of its agents is not a list of them: none is used until one is added again"
    out, left = {}, 0
    for name, item in kept.items():
        entry = _entry_of(name, item, reserved)
        if entry is None or len(out) >= MAX_CLIENTS:
            left += 1
            continue
        out[name] = entry
    if left:
        return out, f"{left} of its kept agents could not be read and {'is' if left == 1 else 'are'} left out"
    return out, ""


def grants_of(text) -> tuple[dict, str]:
    """An agent's grants of a kept value, {what: how}, and what of it could not be read, in words: none for none, and
    none of a value that cannot be read (the agent is granted nothing until it is granted again)."""
    if text is None or not str(text).strip():
        return {}, ""
    try:
        raw = json.loads(text)
    except (TypeError, ValueError) as e:
        return {}, f"what is kept of its grants is not readable ({e}): it is granted nothing until it is granted again"
    kept = raw.get("grants") if isinstance(raw, dict) else None
    if not isinstance(kept, dict):
        return {}, "what is kept of its grants is not a list of them: it is granted nothing until it is granted again"
    out, left = {}, 0
    for what, how in kept.items():
        sound = isinstance(what, str) and WHAT.fullmatch(what) and isinstance(how, str) and 0 < len(how) <= HOW_CHARS
        if not sound or len(out) >= MAX_GRANTS:
            left += 1
            continue
        out[what] = how
    if left:
        return out, f"{left} of its kept grants could not be read and {'is' if left == 1 else 'are'} left out"
    return out, ""


def clients_text(clients: Mapping) -> str | None:
    """The value its agents are kept as: {"v": 1, "clients": {name: entry}}; None for none (the pair is forgotten)."""
    if not clients:
        return None
    return json.dumps({"v": VERSION, "clients": dict(clients)}, separators=(",", ":"), ensure_ascii=True)


def grants_text(grants: Mapping) -> str | None:
    """The value an agent's grants are kept as: {"v": 1, "grants": {what: how}}; None for none."""
    if not grants:
        return None
    return json.dumps({"v": VERSION, "grants": dict(grants)}, separators=(",", ":"), ensure_ascii=True)


def _offered(grantable) -> dict[str, dict]:
    """What a subclass's grantable() answers, as {what: {"title", "hows", "note"}}: each `what` of WHAT's letters (and
    neither of OWN), its hows HOW_CHARS each at most; anything else left out."""
    out: dict[str, dict] = {}
    items = grantable.items() if isinstance(grantable, Mapping) else ()
    for what, said in list(items)[:MAX_GRANTS * 4]:
        if not isinstance(what, str) or not WHAT.fullmatch(what) or what in OWN:
            continue
        if isinstance(said, Mapping):
            hows, title, note = said.get("hows") or (), said.get("title") or what, said.get("note") or ""
        else:
            hows, title, note = said, what, ""
        hows = tuple(h for h in (hows if isinstance(hows, (tuple, list)) else ()) if isinstance(h, str)
                     and 0 < len(h) <= HOW_CHARS)
        if hows:
            out[what] = {"title": _said(title, 120) or what, "hows": hows, "note": _said(note, 300)}
    return out


def _headers(headers) -> dict[str, str]:
    """A request's headers as the base reads them: named in lowercase, their values text (the route's allow-list and
    bounds are the platform's)."""
    out: dict[str, str] = {}
    for k, v in (headers.items() if isinstance(headers, Mapping) else ()):
        if isinstance(k, str) and isinstance(v, (str, int)) and not isinstance(v, bool):
            out[k.strip().lower()] = str(v)
    return out


def _answer_of(out) -> tuple[int, dict | None, dict[str, str]]:
    """What `serve` answered, checked: (a status from 200 to 599, a dict or None, headers); a TypeError otherwise."""
    if isinstance(out, tuple) and len(out) in (2, 3):
        status, data = out[0], out[1]
        extra = out[2] if len(out) == 3 else {}
        if (isinstance(status, int) and not isinstance(status, bool) and 200 <= status <= 599
                and (data is None or isinstance(data, dict)) and isinstance(extra, Mapping)):
            return status, data, {str(k): str(v) for k, v in extra.items()}
    raise TypeError(f"serve answered {type(out).__name__}, not (status, body or None, headers)")


@dataclass(frozen=True)
class Held:
    """How a held call ended (`hold`): `answer` is one of ENDS ("once" and "session" let it run, the rest do nothing),
    `words` the words for the agent when it does not run, and `ticket` its ticket ("" when it was never held)."""

    answer: str
    words: str = ""
    ticket: str = ""

    @property
    def allowed(self) -> bool:
        """Whether the call runs now."""
        return self.answer in ("once", "session")


class _Call:
    """A call held for the user's answer. Its `answer` is set once, under the run state's lock: by `decide`, a cancel,
    a stop, its agent forgotten, its hold running out or its request gone (`ending`: the words that one has for the
    agent). Once `ended`, nothing more is set."""

    def __init__(self, ticket: str, client: str, what: str, text: str, asked: float, hold_s: int, words: str,
                 twice: str, gone, key: str, session: str):
        self.ticket, self.client, self.what, self.text, self.asked = ticket, client, what, text, asked
        self.hold_s, self.deadline, self.words, self.twice = hold_s, asked + hold_s, words, twice
        self.gone, self.key, self.session = gone, key, session
        self.event = threading.Event()
        self.answer = ""
        self.ending = ""
        self.ended = False


@dataclass
class Policy:
    """Its agents and their grants as read at attach and changed by this plugin since (used from memory), with the text
    of each pair as it read or kept it last (`texts`; None: it could not be read), to tell a change made outside it."""

    clients: dict = field(default_factory=dict)
    grants: dict = field(default_factory=dict)
    texts: dict = field(default_factory=dict)
    problem: str = ""


class ProtocolRun(Run):
    """A protocol plugin's run state (ai.Run and more): its policy, the launch tokens' digests, the calls held, the
    audit ring, the allowances, each agent's requests of the last minute, and whether it is stopping."""

    def __init__(self):
        super().__init__()
        self.keeping = threading.RLock()  # one change of its kept pairs at a time (taken before `state`, never after)
        self.state = threading.Lock()  # what follows
        self.policy: Policy | None = None  # read at attach, used from memory
        self.launch: OrderedDict[str, str] = OrderedDict()  # a launch token's sha256 -> its agent, the oldest first
        self.held: OrderedDict[str, _Call] = OrderedDict()  # ticket -> a call waiting for the user's answer
        self.ring: deque = deque(maxlen=RING)  # the calls noted last
        self.allowances: OrderedDict[tuple, float] = OrderedDict()  # (agent, session, what) -> until when
        self.rates: dict[str, deque] = {}  # agent -> the times of its requests in the last minute
        self.seen: dict[str, tuple[str, int]] = {}  # agent -> (its last call, its calls since the plugin started)
        self.stopping = False  # set by a stop: no call is held until it is attached again
        self.writing = threading.Lock()  # one line at a time into its calls log
        self.log_problem = ""  # why its calls log could not be written last


def _stops_too(stopping: Callable) -> Callable:
    """A subclass's app_stopping made one that ends the base's part first: every held call and every launch token."""
    @functools.wraps(stopping)
    def app_stopping(self) -> None:
        try:
            ProtocolPlugin._end_all(self)
        finally:
            stopping(self)

    app_stopping.ends_held = True
    return app_stopping


class ProtocolPlugin(AiPlugin):
    """A protocol plugin: one endpoint on the platform's own port for every local agent, its agents and their grants,
    their tokens, the calls held for the user's answer and the audit. A subclass sets what every AI plugin sets (name,
    title, about, order, ICON, apis, LIBS_FLOOR) and says `serve`, `offer` and `grantable`; `main_more` has the base's
    answer. Its app_stopping, when it has one, runs after the base's own end of the held calls and launch tokens."""

    GROUP = PROTOCOL
    RPC_HOOK = RPC_HOOK  # the platform's route hands a request to it (liminal-platform 0.34.0); never asked by name
    # its software is its own code: no install and no uninstall among its hooks (AiPlugin's standard interface less
    # those two), then its own
    HOOKS = (*MachinePlugin.HOOKS, "refresh", RPC_HOOK, "clients", "pending", "calls", "client_offer", "add_client",
             "forget_client", "grant", "token_once", "revoke", "waiting_call", "decide", "ensure_client",
             "launch_token", "end_launch")
    RUN_STATE = ProtocolRun
    RESERVED = RESERVED  # names no agent takes here (a subclass may name more)
    # What it says of the interface it shares (the contract's words, read by name by the Internal API tab): its reads
    # beside its bases', the services other plugins ask through the platform, the hooks asked only by another plugin
    # (the agent being the asking plugin's) and those asked only from its page (its decisions)
    READ_HOOKS = ("clients", "pending", "calls", "client_offer", "waiting_call")
    SERVICE_HOOKS = ("client_offer", "ensure_client", "launch_token", "end_launch")
    PLUGIN_ONLY_HOOKS = ("ensure_client", "launch_token", "end_launch")
    PAGE_ONLY_HOOKS = ("add_client", "forget_client", "grant", "token_once", "revoke", "waiting_call", "decide")
    INTERNAL_NOTES = (
        "No token's text is kept anywhere: a hand-wired token's sha256 and expiry in its agent's entry, a launch "
        "token's sha256 in memory alone (32 at most), each compared with hmac.compare_digest.",
        "rpc belongs to the platform's route alone (RPC_HOOK): it is handed a request whole, finds the agent by its "
        "bearer token and is never asked by name.",
        "Its decisions are asked only from its page (PAGE_ONLY_HOOKS). What hands out a token is asked only by "
        "another plugin through the platform, for that plugin's own agent as the platform names it "
        "(PLUGIN_ONLY_HOOKS): never an argument.",
        "Its agents and their grants are read once, at attach, and used from memory: a pair changed outside the "
        "plugin is not used, and its page says so.",
    )

    def __init__(self, outside=None):
        super().__init__(outside)
        # how a held call waits between two looks at its request (a test's stand-in moves its clock instead)
        self.waits: Callable[[threading.Event, float], bool] = _waits

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        own = cls.__dict__.get("app_stopping")
        if inspect.isfunction(own) and not getattr(own, "ends_held", False):
            cls.app_stopping = _stops_too(own)

    # -- what a subclass says -----------------------------------------------------------------------------------------
    def serve(self, method: str, headers: Mapping[str, str], body, client: str, gone) -> tuple:
        """One request of the agent `client`, in its protocol: `method`, its `headers` (the route's allow-list, named
        in lowercase, its token taken out), its JSON `body` and `gone()`. (status, body or None, headers), as the
        route sends them. It notes what it does (`record`) and holds what waits for the user (`hold`). The base's:
        nothing is served."""
        raise NotImplementedError(f"{self.title or self.name} speaks no protocol yet")

    def offer(self, client: str) -> dict:
        """How an agent is wired to it, in the words a harness reads (machines/harness.py): "wires", the ways this
        platform serves (of WIRES: "stdio" for its bridge, "http" for the platform's route); "bridge", the bridge's
        command as a list of words; "endpoint", the route's address, and "headers", what goes with each request;
        "revisions", the revisions it speaks. "problem": words for what keeps it from saying more. `client`: the
        asking plugin's agent, "" for none. Never a token. The base's: nothing."""
        return {}

    def grantable(self) -> Mapping:
        """What a grant can name now, and how each is taken: {what: its hows} (RULES for calls, ("on", "off") for a
        status), or {what: {"title", "hows", "note"}}. Each `what` is WHAT's letters. The base's: nothing."""
        return {}

    def main_more(self) -> dict:
        """What more its Main shows: {"facts", "tables", "forms", "actions"} ("facts" a dict of words), its tables
        after the base's. Asked at every draw: it asks nothing over the network and starts nothing. The base's:
        nothing."""
        return {}

    # -- its software: its own code -----------------------------------------------------------------------------------
    def package(self):
        """Nothing is installed from here: its software is its own code."""
        return None

    def installed(self) -> Installed:
        """Its software: its own code, part of this plugin (nothing to install or remove), its version the plugin's.
        Files looked at only."""
        return Installed(str(self.version or ""), _folder_of(type(self)), "part")

    @property
    def token_variable(self) -> str:
        """The variable a harness hands its agent's token in: LIMINAL_<NAME>_TOKEN (LIMINAL_MCP_TOKEN), a secret of
        its launch, never on a command line or in a file."""
        return f"LIMINAL_{_stem(self.name)}_TOKEN"

    def grants_variable(self, name: str) -> str:
        """The variable one agent's grants are kept under: LIMINAL_AI_<NAME>_AGENT_<A>_GRANTS."""
        return self.variable(f"agent_{name}_grants")

    @property
    def KEEPS(self) -> tuple:  # noqa: N802 - a declared word of the contract, as READ_HOOKS
        """What it keeps through its login beside its keys: its agents, one pair, and each agent's grants, a pair of
        its own. Said by name: no login is asked."""
        return ((self.variable("clients"), "its agents: each one's title, when it was made and for whom, its "
                                           "hand-wired token's sha256 and expiry, its hold and its rate"),
                (f"{_stem(STEM + self.name)}_AGENT_<A>_GRANTS", "each agent's grants, a pair of its own: what it may "
                                                                "reach, and how"))

    # -- attached: what is kept, read once ----------------------------------------------------------------------------
    def attach(self, app, login) -> dict:
        """Attached by the platform: its app and its login are this plugin's from here on, and its agents and their
        grants are read through the login now, once. That is what it uses, from memory, until it is attached again."""
        out = super().attach(app, login)
        with self._rt.state:
            self._rt.stopping = False
        self._load()
        return out

    def _load(self, *, again: bool = True) -> Policy:
        """Its agents and their grants read through the login now (`again` False: only when they were not read yet),
        then used from memory. Never raises: what cannot be read is said (Policy.problem)."""
        with self._rt.keeping:
            if not again:
                with self._rt.state:
                    if self._rt.policy is not None:
                        return self._rt.policy
            problems: list[str] = []
            variable = self.variable("clients")
            text = self._read(variable, problems)
            clients, trouble = clients_of(text, self.RESERVED)
            texts: dict[str, str | None] = {variable: text}
            grants: dict[str, dict] = {}
            for name in clients:
                kept = self.grants_variable(name)
                texts[kept] = got = self._read(kept, problems)
                grants[name], said = grants_of(got)
                if said:
                    problems.append(f"{name}: {said}")
            policy = Policy(clients, {n: g for n, g in grants.items() if g}, texts,
                            "; ".join(p for p in (trouble, *problems) if p))
            with self._rt.state:
                self._rt.policy = policy
            return policy

    def _read(self, variable: str, problems: list[str]) -> str | None:
        try:
            return self.pair(variable)
        except Exception as e:  # noqa: BLE001 - a login that cannot be read: said, and nothing of it used
            problems.append(self._scrubbed(f"{variable} could not be read ({_words(e)}): nothing of it is used"))
            return None

    def _policy(self) -> Policy:
        with self._rt.state:
            policy = self._rt.policy
        return policy if policy is not None else self._load(again=False)

    def _entry(self, name) -> dict | None:
        """One agent's entry as used now (a copy, its digest in it); None for none."""
        policy = self._policy()
        with self._rt.state:
            entry = policy.clients.get(name)
            return dict(entry) if entry is not None else None

    def changed_outside(self) -> list[str]:
        """The variables of its pairs found changed outside this plugin since it read or kept them last: what they
        hold now is not used. Read through the login now; none when the login cannot be read."""
        policy = self._policy()
        with self._rt.state:
            texts = {v: t for v, t in policy.texts.items() if t is not None}
        if not texts:
            return []
        try:
            login = self._login()
            if not login.signed_in:
                return []
            now = login.variables(list(texts)) or {}
        except Exception:  # noqa: BLE001 - not read now: nothing is said of it
            return []
        return [v for v, t in texts.items() if (now.get(v) or "") != (t or "")]

    def _keep_clients(self, policy: Policy, clients: dict) -> str:
        """Its agents kept through the login and used from now on (under `keeping`): where, in the login's words."""
        variable = self.variable("clients")
        text = clients_text(clients)
        where = self.keep_pair(variable, text)
        with self._rt.state:
            policy.clients = dict(clients)
            policy.texts[variable] = text or ""
            for name in clients:  # a new agent's grants: none kept, so a pair written outside for it is said
                policy.texts.setdefault(self.grants_variable(name), "")
        return where

    def _keep_grants(self, policy: Policy, name: str, grants: dict | None) -> str:
        """One agent's grants kept through the login (None: forgotten, its agent with it) and used from now on (under
        `keeping`): where, in the login's words."""
        variable = self.grants_variable(name)
        text = grants_text(grants or {})
        where = self.keep_pair(variable, text)
        with self._rt.state:
            others = {n: g for n, g in policy.grants.items() if n != name}
            policy.grants = {**others, name: dict(grants)} if grants else others
            if grants is None:
                policy.texts.pop(variable, None)
            else:
                policy.texts[variable] = text or ""
        return where

    # -- who asks -----------------------------------------------------------------------------------------------------
    def _from_page(self, hook: str) -> None:
        """Refused in words unless the platform says its page asks (asker() is asking.PAGE)."""
        who, name = asker(), self.title or self.name
        if who == asking.PAGE:
            return
        if who is None:
            raise Refusal(f"{name}'s {hook} is asked only from its page, and this ask does not say that it comes from "
                          "there: nothing was done")
        raise Refusal(f"{name}'s {hook} is asked only from its page, never by another plugin ({who[:64]}): nothing "
                      "was done")

    def _from_plugin(self, hook: str) -> str:
        """The plugin that asks, as the platform names it; refused in words when no other plugin asks."""
        who, name = asker(), self.title or self.name
        if who is None:
            raise Refusal(f"{name}'s {hook} is asked only by another plugin through the platform, and this ask names "
                          "none: nothing was done")
        if who == asking.PAGE:
            raise Refusal(f"{name}'s {hook} is asked only by another plugin through the platform, never from a page: "
                          "nothing was done")
        if who == self.name:
            raise Refusal(f"{name}'s {hook} is asked only by another plugin through the platform, not by {name} "
                          "itself: nothing was done")
        return who

    def _agent_for(self, plugin: str) -> str:
        """The name of the agent a plugin asks for: its own name without its hyphens."""
        name = agent_of(plugin)
        if not NAME.fullmatch(name) or name in self.RESERVED:
            raise Refusal(f"{plugin[:64]} cannot have an agent here: its name without its hyphens ({name[:40]!r}) is "
                          f"not 1 to 24 lowercase letters and digits, or is one no agent takes ({_and(self.RESERVED)})")
        return name

    def _new_name(self, name) -> str:
        text = str(name if name is not None else "").strip().lower()
        if not NAME.fullmatch(text):
            raise Refusal("an agent's name is 1 to 24 lowercase letters and digits, with no hyphen: not "
                          f"{str(name if name is not None else '')[:40]!r}")
        if text in self.RESERVED:
            raise Refusal(f"{text} is a name no agent takes here ({_and(self.RESERVED)})")
        return text

    def _known(self, name) -> tuple[str, dict]:
        """An agent it has, by name, and its entry: a LookupError in words for any other."""
        text = str(name if name is not None else "").strip().lower()
        entry = self._entry(text) if NAME.fullmatch(text) else None
        if entry is None:
            raise LookupError(f"{self.title or self.name} has no agent {str(name if name is not None else '')[:40]!r}")
        return text, entry

    # -- the reads ----------------------------------------------------------------------------------------------------
    def agents(self) -> list[str]:
        """Its agents' names, in the order they were made."""
        policy = self._policy()
        with self._rt.state:
            return list(policy.clients)

    def client_of(self, name) -> dict | None:
        """One agent as it is used now (a copy): its title, when it was made and for whom, its token's expiry, its hold
        and its rate; None for none. No digest is in it."""
        entry = self._entry(name)
        if entry is None:
            return None
        entry.pop("digest", None)
        return entry

    def grants_of(self, name) -> dict:
        """One agent's grants as they are used now (a copy): {what: how}; none for an agent it does not have."""
        policy = self._policy()
        with self._rt.state:
            return dict(policy.grants.get(name) or {})

    def clients(self) -> list[dict]:
        """Its agents as it uses them now, in the order they were made: each one's name, title, when it was made and
        for whom, whether its hand-wired token is live and until when, its launch tokens, its hold, its rate, its
        grants and its last call. A read: no token and no digest is in it."""
        policy = self._policy()
        now = self.out.clock()
        with self._rt.state:
            clients = dict(policy.clients)
            granted = {n: len(g) for n, g in policy.grants.items()}
            launch = Counter(self._rt.launch.values())
            seen = dict(self._rt.seen)
        out = []
        for name, entry in clients.items():
            live = bool(entry["digest"]) and entry["expires"] > now
            last, calls = seen.get(name, ("", 0))
            out.append({"name": name, "title": entry["title"], "made": entry["made"], "by": entry["by"],
                        "token": "live" if live else "expired" if entry["digest"] else "none",
                        "expires": _iso(entry["expires"]) if entry["digest"] else "", "launch": launch.get(name, 0),
                        "hold_s": entry["hold_s"], "rate": entry["rate"], "grants": granted.get(name, 0),
                        "last": last, "calls": calls})
        return out

    def pending(self) -> list[dict]:
        """The calls waiting for the user's answer now, the oldest first, without their arguments: each one's ticket,
        agent, what it asks, the words said of it, when it was asked, the seconds left and whether its rule asks
        twice. A read."""
        now = self.out.clock()
        with self._rt.state:
            calls = [c for c in self._rt.held.values() if not c.answer]
        return [self._pending_row(c, now) for c in calls]

    def _pending_row(self, call: _Call, now: float) -> dict:
        entry = self._entry(call.client) or {}
        return {"ticket": call.ticket, "agent": call.client, "title": entry.get("title") or call.client,
                "what": call.what, "words": call.words, "asked": _iso(call.asked),
                "left_s": max(0, int(math.ceil(call.deadline - now))), "twice": bool(call.twice)}

    def calls(self, last: int = 200) -> list[dict]:
        """The calls noted last, the newest first (`last` of them at most; RING are kept): when, the agent, the era,
        the method, what it reached, the decision, the time it took, its size, the definition's digest, and its
        arguments masked and cut at SHOWN_CHARS. A read."""
        try:
            want = max(0, min(int(last), RING))
        except (TypeError, ValueError):
            want = 200
        with self._rt.state:
            rows = list(self._rt.ring)[-want:] if want else []
        return [dict(r) for r in reversed(rows)]

    def client_offer(self) -> dict:
        """How an agent is wired to it: a service other plugins ask through the platform, and what its page's How to
        connect… shows. What the subclass says (`offer`: the ways this platform serves, of WIRES, the bridge's
        command, the endpoint and its headers, the revisions), with the variable a token is handed in, the hold (the
        asking plugin's agent's, when it has one) and that agent. A way of the offer's that is not one of WIRES is
        left out, and said ("problem"). A read: no token is in it."""
        who = asker()
        name = agent_of(who) if who not in (None, asking.PAGE) else ""
        entry = self._entry(name) if name and NAME.fullmatch(name) else None
        mine = name if entry is not None and entry["by"] == who else ""
        try:
            said = self.offer(mine)
        except Exception as e:  # noqa: BLE001 - what the subclass could not say is said in words
            said = {"problem": self._scrubbed(_words(e))}
        out = dict(said) if isinstance(said, Mapping) else {}
        if "wires" in out:  # (one way said alone is that way, as a list)
            named = _listed(out["wires"]) if isinstance(out["wires"], (list, tuple)) else [out["wires"]]
            out["wires"] = [w for i, w in enumerate(named) if isinstance(w, str) and w in WIRES and w not in named[:i]]
            unknown = [_said(w, 40) or repr(w)[:40] for w in named if not (isinstance(w, str) and w in WIRES)]
            if unknown:
                words = (f"{self.title or self.name}'s offer names a way no harness reaches it by ({', '.join(unknown)}"
                         f"): a harness reaches it by {_or(WIRE_WORDS.values())}")
                out["problem"] = "; ".join(p for p in (_said(out.get("problem") or "", 400), words) if p)
        out.update({"variable": self.token_variable, "hold_s": entry["hold_s"] if mine else HOLD_S, "agent": mine})
        return out

    # -- its page's changes -------------------------------------------------------------------------------------------
    def add_client(self, name, title="") -> dict:
        """An agent added from its page, named and titled as typed: granted nothing, with no token until one is shown
        once (Show its token once…). Refused in words for a name taken, a name no agent takes, past MAX_CLIENTS, or
        when it is not kept."""
        self._from_page("add_client")
        agent = self._new_name(name)
        said = instances.clean_title(title) or agent
        with self._rt.keeping:
            policy = self._policy()
            if agent in policy.clients:
                raise Refusal(f"{agent} is an agent here already")
            if len(policy.clients) >= MAX_CLIENTS:
                raise Refusal(f"{self.title or self.name} holds {MAX_CLIENTS} agents at most: forget one first")
            entry = {"title": said, "made": instances.now_iso(self.out.clock), "by": "", "digest": "", "expires": 0,
                     "hold_s": HOLD_S, "rate": RATE}
            where = self._keep_clients(policy, {**policy.clients, agent: entry})
        return self._reply(f"{said} ({agent}) added: it is granted nothing yet", True,
                           [f"kept in {where}", "its token is shown once by Show its token once…"])

    def forget_client(self, name) -> dict:
        """An agent forgotten from its page: its entry and its grants, its tokens (hand-wired and launch), its
        allowances; calls of it waiting for the user are denied. A harness that made it makes it again, granted
        nothing, when its Use… turns this protocol on again (ensure_client); until then its windows get no token."""
        self._from_page("forget_client")
        agent, entry = self._known(name)
        lines = []
        with self._rt.keeping:
            policy = self._policy()
            where = self._keep_clients(policy, {n: e for n, e in policy.clients.items() if n != agent})
            lines.append(f"forgotten in {where}")
            try:
                self._keep_grants(policy, agent, None)
            except Exception as e:  # noqa: BLE001 - its entry is gone already: what is left is said
                lines.append(self._scrubbed(f"its grants' pair could not be forgotten ({_words(e)}): it is not used"))
        ended = self._end_agent(agent, f"{entry['title']} was forgotten on Liminal's page: nothing was done")
        if ended:
            lines.append(f"{_many(ended, 'call')} of it waiting for you denied")
        return self._reply(f"{entry['title']} ({agent}) forgotten: its grants and tokens end now", True, lines)

    def _end_agent(self, agent: str, words: str) -> int:
        """What is held in memory for an agent let go: its launch tokens, allowances, rate and last call; its calls
        waiting are denied with `words`. How many were waiting."""
        with self._rt.state:
            for digest in [d for d, a in self._rt.launch.items() if a == agent]:
                del self._rt.launch[digest]
            for key in [k for k in self._rt.allowances if k[0] == agent]:
                del self._rt.allowances[key]
            self._rt.rates.pop(agent, None)
            self._rt.seen.pop(agent, None)
            calls = [c for c in self._rt.held.values() if c.client == agent and not c.answer]
            for call in calls:
                call.answer, call.ending = "deny", words
        for call in calls:
            call.event.set()
        return len(calls)

    def grant(self, name, what, how=None) -> dict:
        """One grant of an agent's set from its page: `what` one of grantable()'s names and `how` one of its hows
        (empty: forgotten, so not granted); or its "hold" (HOLD_LEAST to HOLD_MOST seconds) or its "rate" (1 to
        RATE_MOST requests a minute), kept in its entry. Refused in words for anything else, past MAX_GRANTS, or when
        it is not kept."""
        self._from_page("grant")
        agent, entry = self._known(name)
        said = str(what if what is not None else "").strip()
        if said in OWN:
            return self._grant_own(agent, said, how)
        try:
            offered = _offered(self.grantable())
        except Exception as e:  # noqa: BLE001 - what cannot be said cannot be granted
            raise Refusal(self._scrubbed(f"what can be granted could not be read: {_words(e)}")) from None
        forget = how is None or (isinstance(how, str) and not how.strip())
        took = "" if forget else str(how).strip()
        if not forget:
            if said not in offered:
                raise Refusal(f"{said[:80]!r} is not something {self.title or self.name} grants now")
            if took not in offered[said]["hows"]:
                raise Refusal(f"{offered[said]['title']} is granted as {_or(offered[said]['hows'])}, not "
                              f"{took[:40]!r}")
        with self._rt.keeping:
            policy = self._policy()
            grants = dict(policy.grants.get(agent) or {})
            if forget:
                if said not in grants:
                    raise Refusal(f"{entry['title']} is granted nothing as {said[:80]!r}: there is nothing to forget")
                grants.pop(said)
            else:
                if said not in grants and len(grants) >= MAX_GRANTS:
                    raise Refusal(f"{entry['title']} holds {MAX_GRANTS} grants at most: forget one first")
                grants[said] = took
            where = self._keep_grants(policy, agent, grants)
        words = f"{said} forgotten" if forget else f"{said}: {took}"
        return self._reply(f"{entry['title']} ({agent}): {words}", True, [f"kept in {where}"])

    def _grant_own(self, agent: str, what: str, how) -> dict:
        """An agent's hold or rate set: kept in its entry."""
        if what == "hold":
            value, label = _whole(how, HOLD_LEAST, HOLD_MOST, "its hold, in seconds,"), "hold_s"
        else:
            value, label = _whole(how, 1, RATE_MOST, "its rate, in requests a minute,"), "rate"
        with self._rt.keeping:
            policy = self._policy()
            if agent not in policy.clients:
                raise LookupError(f"{self.title or self.name} has no agent {agent!r}")
            entry = {**policy.clients[agent], label: value}
            where = self._keep_clients(policy, {**policy.clients, agent: entry})
        said = f"a call of it waits {value} s for your answer" if what == "hold" else f"{value} requests a minute"
        return self._reply(f"{entry['title']} ({agent}): {said}", True, [f"kept in {where}"])

    def token_once(self, name, days=DAYS, accept_shown=False) -> dict:
        """A new hand-wired token for an agent, asked from its page twice (`accept_shown`): shown in this one answer
        alone, for `days` days (1 to DAYS_MOST). Only its sha256 and its expiry are kept, in the agent's entry, and the
        token shown before stops working."""
        self._from_page("token_once")
        agent, entry = self._known(name)
        lasting = _whole(DAYS if days is None else days, 1, DAYS_MOST, "a token's days")
        if not exactly(accept_shown):
            raise Refusal(f"A new token for {entry['title']} is shown once, in the next answer alone: copy it then. "
                          "The one shown before stops working now.", accept=ACCEPT_SHOWN)
        token = secrets.token_urlsafe(TOKEN_BYTES)
        expires = int(self.out.clock() + lasting * DAY_S)
        with self._rt.keeping:
            policy = self._policy()
            if agent not in policy.clients:
                raise LookupError(f"{self.title or self.name} has no agent {agent!r}")
            kept = {**policy.clients[agent], "digest": digest_of(token), "expires": expires}
            where = self._keep_clients(policy, {**policy.clients, agent: kept})
        until = _iso(expires)
        return {"said": self._scrubbed(f"a new token for {entry['title']} ({agent}), until {until}: copy it now, it "
                                       "is not shown again"), "ok": True,
                "lines": [f"its token: {token}",
                          f"its agent sends it as Authorization: Bearer <its token>, or a bridge reads it from "
                          f"{self.token_variable}",
                          self._scrubbed(f"kept as its sha256 alone, in {where}"), "the token shown before is ended"],
                "token": token, "agent": agent, "expires": until, "variable": self.token_variable}

    def revoke(self, name) -> dict:
        """Every token of an agent ended from its page: its hand-wired one (its digest forgotten) and its launch
        tokens. It keeps its grants; a harness gets a new launch token at its next Open…."""
        self._from_page("revoke")
        agent, entry = self._known(name)
        lines = []
        with self._rt.keeping:
            policy = self._policy()
            if agent in policy.clients and policy.clients[agent]["digest"]:
                kept = {**policy.clients[agent], "digest": "", "expires": 0}
                where = self._keep_clients(policy, {**policy.clients, agent: kept})
                lines.append(f"its hand-wired token ended, in {where}")
        with self._rt.state:
            ended = [d for d, a in self._rt.launch.items() if a == agent]
            for digest in ended:
                del self._rt.launch[digest]
        lines.append(f"{_many(len(ended), 'launch token')} ended")
        return self._reply(f"every token of {entry['title']} ({agent}) is ended", True, lines)

    def waiting_call(self, ticket) -> dict:
        """One call waiting for the user's answer, whole, for its page alone: the agent, what it asks, the words said
        of it, when it was asked, the seconds left, whether its rule asks twice, and its arguments as text, every
        character shown (visible), WHOLE_MOST bytes at most. A read: nothing is answered."""
        self._from_page("waiting_call")
        call = self._call(ticket)
        row = self._pending_row(call, self.out.clock())
        lines = [f"asked {row['asked']}, {row['left_s']} s left", *(call.words.splitlines() if call.words else []),
                 "its rule asks twice: allowing it is confirmed a second time" if call.twice else "",
                 "its arguments, exactly:", *(call.text.splitlines() or ["none"])]
        return {"said": f"{row['title']} ({call.client}) asks {call.what}", "ok": True,
                "lines": [line for line in lines if line], **row, "arguments": call.text}

    def _call(self, ticket) -> _Call:
        said = str(ticket if ticket is not None else "").strip()
        with self._rt.state:
            call = self._rt.held.get(said)
            if call is not None and not call.answer and not call.ended:
                return call
        raise LookupError(f"no call waits as {said[:40]!r} now: it was answered, timed out or dropped, and nothing "
                          "more is done")

    def decide(self, ticket, answer, accept=False) -> dict:
        """A waiting call answered from its page: "once" (allowed this once), "session" (allowed, and the same call of
        that agent again without asking, in its session or for SESSION_S, whichever ends first) or "deny". A call
        whose rule asks twice is allowed only once it is confirmed a second time (`accept`), with its exact
        arguments, and never for a session. An answer to a call that ended does nothing, and says so."""
        self._from_page("decide")
        said = str(answer if answer is not None else "").strip().lower()
        if said not in ANSWERS:
            raise Refusal(f"a call is answered {_or(ANSWERS)}, not {str(answer)[:40]!r}")
        call = self._call(ticket)
        title = (self._entry(call.client) or {}).get("title") or call.client
        if call.twice and said == "session":
            raise Refusal(f"{title}'s {call.what} asks twice: it is allowed once at a time, never for a session")
        if call.twice and said == "once" and not exactly(accept):
            raise Refusal(f"{title} ({call.client}) asks {call.what}, and its rule asks twice. Exactly, with these "
                          f"arguments: {call.text or 'none'}", accept=ACCEPT_TWICE)
        with self._rt.state:
            if call.answer or call.ended:
                raise LookupError(f"the call {call.ticket} ended before this answer: nothing more is done")
            call.answer = said
        call.event.set()
        words = {"once": f"allowed once: {title}'s {call.what} runs now",
                 "session": (f"allowed for this session: {title}'s {call.what} runs now, and again without asking "
                             f"while its session lasts, {SESSION_S / 60:g} minutes at most"),
                 "deny": f"denied: nothing of {title}'s {call.what} is done"}[said]
        return self._reply(words, True)

    # -- what other plugins ask through the platform ------------------------------------------------------------------
    def ensure_client(self, title="") -> dict:
        """The asking plugin's own agent, made when it has none: named after that plugin without its hyphens and
        titled `title` (its own title), granted nothing. Asked only by another plugin through the platform (a harness
        whose user turns this protocol on): the agent is the one the platform names, never an argument."""
        plugin = self._from_plugin("ensure_client")
        agent = self._agent_for(plugin)
        said = instances.clean_title(title) or plugin
        with self._rt.keeping:
            policy = self._policy()
            entry = policy.clients.get(agent)
            if entry is not None:
                if entry["by"] != plugin:
                    made = f"for {entry['by']}" if entry["by"] else "on its page"
                    raise Refusal(f"{agent} is an agent made {made}, not {plugin}'s: forget it on "
                                  f"{self.title or self.name}'s page first")
                return {"said": f"{entry['title']} ({agent}) is {plugin}'s agent", "ok": True, "agent": agent,
                        "made": False, "hold_s": entry["hold_s"], "variable": self.token_variable}
            if len(policy.clients) >= MAX_CLIENTS:
                raise Refusal(f"{self.title or self.name} holds {MAX_CLIENTS} agents at most: forget one on its page "
                              "first")
            entry = {"title": said, "made": instances.now_iso(self.out.clock), "by": plugin, "digest": "",
                     "expires": 0, "hold_s": HOLD_S, "rate": RATE}
            self._keep_clients(policy, {**policy.clients, agent: entry})
        return {"said": f"{said} ({agent}) made for {plugin}: it is granted nothing yet", "ok": True, "agent": agent,
                "made": True, "hold_s": HOLD_S, "variable": self.token_variable}

    def launch_token(self) -> dict:
        """A launch token for the asking plugin's agent: made now, answered to that plugin alone and held here as its
        sha256, in memory, until end_launch, a stop, or MAX_LAUNCH newer ones. Asked only by another plugin through
        the platform (a harness, at each Open…), whose agent it must have made (ensure_client)."""
        plugin = self._from_plugin("launch_token")
        agent = self._agent_for(plugin)
        entry = self._entry(agent)
        if entry is None or entry["by"] != plugin:
            raise Refusal(f"{plugin} has no agent of its own here: turn {self.title or self.name} on in its Use… "
                          "first (ensure_client)")
        token = secrets.token_urlsafe(TOKEN_BYTES)
        with self._rt.state:
            if self._rt.stopping:
                raise Refusal(f"{self.title or self.name} is stopping: no token is made now")
            self._rt.launch[digest_of(token)] = agent
            while len(self._rt.launch) > MAX_LAUNCH:
                self._rt.launch.popitem(last=False)
        return {"token": token, "agent": agent, "variable": self.token_variable, "hold_s": entry["hold_s"]}

    def end_launch(self, token) -> dict:
        """A launch token of the asking plugin's agent ended (its window is gone). Asked only by another plugin through
        the platform; a token of another agent is not ended, and not said to be."""
        plugin = self._from_plugin("end_launch")
        agent = self._agent_for(plugin)
        digest = digest_of(token) if isinstance(token, str) and token else ""
        with self._rt.state:
            mine = next((d for d, a in self._rt.launch.items() if a == agent and hmac.compare_digest(d, digest)), None)
            if mine is not None:
                del self._rt.launch[mine]
        return {"ended": mine is not None, "agent": agent}

    # -- the route's hook ---------------------------------------------------------------------------------------------
    def rpc(self, method, headers=None, body=None, gone=None) -> tuple:
        """One request of an agent, as the platform's route hands it over whole (RPC_HOOK, never asked by name):
        `method`, its allow-listed `headers`, its JSON `body` and `gone()`, whether the agent has closed its
        connection. The agent is found by its bearer token and held to its rate, then the request is the subclass's
        (`serve`, handed the headers without the token). (status, body or None, headers). It never raises."""
        began = time.perf_counter()
        said = str(method or "").strip().upper()[:8]
        heard = _headers(headers)
        try:
            client, why = self._bearer(heard)
        except Exception as e:  # noqa: BLE001 - nothing is let through
            client, why = None, self._scrubbed(f"its token could not be checked: {_words(e)}")
        if client is None:
            self.record("", said, "", "unauthorized", kind="read", ms=_since(began))
            return 401, {"error": why}, {"WWW-Authenticate": "Bearer"}
        wait = self._over_rate(client)
        if wait:
            self.record(client, said, "", "too many", kind="read", ms=_since(began))
            return (429, {"error": f"{client} asks more than its rate allows: ask again in {wait} s"},
                    {"Retry-After": str(wait)})
        heard.pop("authorization", None)
        _request.recorded = 0
        try:
            status, data, extra = _answer_of(self.serve(said, heard, body, client, gone))
        except NotImplementedError as e:
            status, data, extra = 501, {"error": self._scrubbed(_words(e))}, {}
        except Exception as e:  # noqa: BLE001 - the agent is told in words, never more
            status, data, extra = 500, {"error": self._scrubbed(f"{self.title or self.name} failed: {_words(e)}")}, {}
        if not getattr(_request, "recorded", 0):
            self.record(client, said, "", "answered" if status < 400 else "failed", ms=_since(began))
        _request.recorded = 0
        return status, data, extra

    def _bearer(self, heard: Mapping[str, str]) -> tuple[str | None, str]:
        """The agent a request's bearer token is, and ""; or None and why not, in words."""
        name = self.title or self.name
        scheme, _, token = str(heard.get("authorization") or "").strip().partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            return None, (f"no bearer token: each agent sends its own (Authorization: Bearer …), shown once on "
                          f"{name}'s page or handed to it by the harness that started it")
        if len(token) > TOKEN_CHARS:
            return None, f"this token is none of {name}'s"
        digest, now = digest_of(token), self.out.clock()
        policy = self._policy()
        with self._rt.state:
            kept = [(n, e["digest"], e["expires"]) for n, e in policy.clients.items() if e["digest"]]
            launch = list(self._rt.launch.items())
        found, expired = None, False
        for agent, known, expires in kept:  # every digest compared, whatever matched before
            if hmac.compare_digest(digest, known):
                if expires > now:
                    found = found or agent
                else:
                    expired = True
        for known, agent in launch:
            if hmac.compare_digest(digest, known):
                found = found or agent
        if found is not None:
            return found, ""
        if expired:
            return None, f"this token has expired: show a new one on {name}'s page"
        return None, f"this token is none of {name}'s: it was never shown, or it was ended"

    def _over_rate(self, client: str) -> int:
        """0, or the seconds until the next request of `client` is taken (its rate: requests a minute)."""
        entry = self._entry(client) or {}
        rate, now = int(entry.get("rate") or RATE), self.out.clock()
        with self._rt.state:
            times = self._rt.rates.setdefault(client, deque())
            while times and now - times[0] >= WINDOW_S:
                times.popleft()
            if len(times) >= rate:
                return max(1, int(math.ceil(WINDOW_S - (now - times[0]))))
            times.append(now)
        return 0

    # -- calls held for the user's answer -----------------------------------------------------------------------------
    def hold(self, client, what, arguments=None, *, words="", twice=False, gone=None, key="", session="") -> Held:
        """A call held for the user's answer on its page, as its agent's rule asks (`twice`: allowing it is confirmed a
        second time). `what` is what it asks, in words; `arguments` its arguments (JSON, or text); `words` the words
        the plugin says of it (never words the server wrote); `gone` its request's probe; `key` the agent's own id
        for it (cancel_held); `session` its session ("": none). Refused at once past MAX_HELD_EACH for that agent or
        MAX_HELD in all, for arguments past WHOLE_MOST as shown, and while it stops. Otherwise it waits: for the
        user's answer, its agent's hold, its request gone, a cancel or a stop. A call allowed for this session runs
        without asking. How it ended (Held)."""
        agent = str(client or "")
        entry = self._entry(agent)
        said = _what(what)
        if entry is None:
            return Held("refused", f"{agent[:40]} is not an agent of {self.title or self.name}: nothing was done")
        if not twice and self.allowed(agent, said, session):
            return Held("session")
        text = visible(_text_of(arguments))
        if len(text.encode("utf-8")) > WHOLE_MOST:
            return Held("refused", f"its arguments are more than {WHOLE_MOST // 1024} KiB: they cannot be shown whole "
                                   "on Liminal's page, so it cannot be allowed: nothing was done")
        call = _Call(secrets.token_urlsafe(9), agent, said, text, self.out.clock(), entry["hold_s"],
                     _cut(visible(str(words or "").strip()), WORDS_CHARS), ACCEPT_TWICE if twice else "", gone,
                     _key(key), _key(session))
        with self._rt.state:
            if self._rt.stopping:
                return Held("stopped", f"{self.title or self.name} is stopping: nothing was done")
            waiting = [c for c in self._rt.held.values() if not c.answer]
            if sum(1 for c in waiting if c.client == agent) >= MAX_HELD_EACH:
                return Held("refused", f"{MAX_HELD_EACH} calls of {agent} wait for an answer already: nothing was done")
            if len(waiting) >= MAX_HELD:
                return Held("refused", f"{MAX_HELD} calls wait for an answer already: nothing was done")
            self._rt.held[call.ticket] = call
        try:
            self._wait_for(call)
        finally:
            with self._rt.state:
                self._rt.held.pop(call.ticket, None)
                if not call.answer:
                    call.answer = "stopped"
                call.ended = True
                answer, ending = call.answer, call.ending
        if answer == "session":
            self._allow(agent, said, call.session)
        return Held(answer, ending or self._end_words(answer, call), call.ticket)

    def _wait_for(self, call: _Call) -> None:
        """Until `call` has its answer: the user's, a cancel's or a stop's; its hold running out ("timeout"); its
        request gone ("gone"), looked at every POLL_S."""
        while True:
            with self._rt.state:
                if call.answer:
                    return
            left = call.deadline - self.out.clock()
            if left <= 0:
                self._end(call, "timeout")
                return
            if call.gone is not None and _gone(call.gone):
                self._end(call, "gone")
                return
            self.waits(call.event, min(POLL_S, left))

    def _end(self, call: _Call, answer: str) -> bool:
        """`call` ended with `answer` unless it has one already: whether this one is its answer."""
        with self._rt.state:
            if call.answer or call.ended:
                return False
            call.answer = answer
        call.event.set()
        return True

    def _end_words(self, answer: str, call: _Call) -> str:
        """What the agent is told of a call that does not run ("" for one that runs)."""
        words = {"deny": "denied on Liminal's page: nothing was done",
                 "timeout": f"not answered on Liminal's page within {call.hold_s} s: nothing was done",
                 "gone": "dropped: its request was closed before it was answered, and nothing was done",
                 "cancelled": "cancelled by its agent before it was answered: nothing was done",
                 "stopped": f"{self.title or self.name} stopped before it was answered: nothing was done"}
        return words.get(answer, "")

    def cancel_held(self, client, key) -> bool:
        """A call of `client` waiting for the user ended by its agent's own cancel, by the agent's `key` for it: whether
        one was waiting."""
        said = _key(key)
        if not said:
            return False
        with self._rt.state:
            call = next((c for c in self._rt.held.values() if c.client == client and c.key == said and not c.answer),
                        None)
        return call is not None and self._end(call, "cancelled")

    def allowed(self, client, what, session="") -> bool:
        """Whether the user allowed `what` of `client` for this session (decide's "session"), still: in that session,
        SESSION_S at most."""
        key, now = (str(client or ""), _key(session), _what(what)), self.out.clock()
        with self._rt.state:
            until = self._rt.allowances.get(key)
            if until is None:
                return False
            if now >= until:
                del self._rt.allowances[key]
                return False
            return True

    def _allow(self, client: str, what: str, session: str) -> None:
        key = (client, _key(session), what)
        with self._rt.state:
            self._rt.allowances[key] = self.out.clock() + SESSION_S
            self._rt.allowances.move_to_end(key)
            while len(self._rt.allowances) > ALLOWANCES:
                self._rt.allowances.popitem(last=False)

    def end_session(self, client, session) -> None:
        """A session of `client` ended: what was allowed in it for the session is asked again."""
        said = _key(session)
        with self._rt.state:
            for key in [k for k in self._rt.allowances if k[0] == client and k[1] == said]:
                del self._rt.allowances[key]

    # -- the audit ----------------------------------------------------------------------------------------------------
    def remember_secret(self, value) -> None:
        """A secret value it knows (a server's key), masked from then on in every row, line and answer of its own."""
        self._keep_secret(value)

    def masked(self, text, chars: int = SHOWN_CHARS) -> str:
        """`text` on one line, every secret value it knows masked, every character shown (visible), `chars` at most."""
        return _cut(visible(" ".join(self._scrubbed(str(text)).split())), chars)

    def record(self, client, method, what="", decision="answered", *, era="", kind="ask", ms=0.0, size=0,
               digest="", arguments=None) -> dict:
        """One request of an agent noted: in the ring (its arguments masked, cut at SHOWN_CHARS), as a line of its
        calls log (no argument), and in the platform's traffic as agent:<client> to this plugin (`kind`, one of KINDS:
        "read" for a list, "ask" for a call). `decision` in words: "answered", "allowed", "asked and allowed", "asked
        and denied", "denied by rule", "timed out", "dropped", "failed". The row as noted."""
        agent = str(client or "")[:64]
        took = float(ms) if isinstance(ms, (int, float)) and not isinstance(ms, bool) and math.isfinite(ms) else 0.0
        many = size if isinstance(size, int) and not isinstance(size, bool) else 0
        row = {"at": instances.now_iso(self.out.clock), "agent": agent, "era": self.masked(era, 40),
               "method": self.masked(method, 80), "what": self.masked(what, WHAT_CHARS),
               "decision": self.masked(decision, 40), "ms": round(max(0.0, took), 1), "size": max(0, many),
               "digest": self.masked(digest, 64)}
        shown = self.masked(_text_of(arguments, compact=True)) if arguments is not None else ""
        with self._rt.state:
            self._rt.ring.append({**row, "arguments": shown})
            if agent:
                self._rt.seen[agent] = (row["at"], self._rt.seen.get(agent, ("", 0))[1] + 1)
        self._log(row)
        if agent:
            self._traffic(agent, kind, row["what"] or row["method"], row["ms"], decision != "failed")
        _request.recorded = getattr(_request, "recorded", 0) + 1
        return dict(row)

    def _log(self, row: dict) -> None:
        """A line of its calls log (home/logs/calls.log, moved aside past LOG_MAX as a child's log is): one call, no
        argument. Not on another system's drive; a log that cannot be written is said by the next status."""
        if self.home_problem():
            return
        line = (self._scrubbed(json.dumps(row, separators=(",", ":"), ensure_ascii=True)) + "\n").encode("utf-8")
        with self._rt.writing:
            log = children._Log(self.home / "logs" / CALLS_LOG, LOG_MAX)
            try:
                log.open()
                log.write(line)
                self._rt.log_problem = "" if log.file is not None else "its calls log could not be written"
            except OSError as e:
                self._rt.log_problem = self._scrubbed(f"its calls log could not be written: {e}")
            finally:
                log.close()

    def _traffic(self, agent: str, kind: str, what: str, ms: float, ok: bool) -> None:
        traffic = getattr(self.app, "traffic", None) if self.app is not None else None
        note = getattr(traffic, "record", None)
        if not callable(note):
            return
        try:
            note(f"agent:{agent}", self.name, kind if kind in KINDS else "ask", what, ms, ok)
        except Exception:  # noqa: BLE001 - the call is answered all the same
            pass

    # -- stopping -----------------------------------------------------------------------------------------------------
    def app_stopping(self) -> None:
        """The platform stops, or the plugin is turned off: every call waiting for the user ends unanswered (nothing of
        it is done), every launch token and every allowance ends, and no call is held until it is attached again. It
        bears a second call."""
        self._end_all()

    def _end_all(self) -> None:
        with self._rt.state:
            self._rt.stopping = True
            calls = [c for c in self._rt.held.values() if not c.answer]
            for call in calls:
                call.answer = "stopped"
            self._rt.launch.clear()
            self._rt.allowances.clear()
        for call in calls:
            call.event.set()

    # -- what the page draws ------------------------------------------------------------------------------------------
    def status(self) -> dict:
        """Its Main: AiPlugin's (its software, part of this plugin), its agents and the calls waiting for you, with
        their forms; then what the subclass adds (main_more). A pair changed outside the plugin, what could not be
        read and a calls log that could not be written are its problems. Nothing is asked over the network and
        nothing is started. Never raises."""
        out = self.base_status()
        if out.get("applies") is False or not out.get("valid", True):
            return out
        problems = [str(out["problem"])] if out.get("problem") else []
        policy = self._policy()
        if policy.problem:
            problems.append(policy.problem)
        changed = self.changed_outside()
        if changed:
            name, one = self.title or self.name, len(changed) == 1
            problems.append(f"{_and(changed)} {'was' if one else 'were'} changed outside {name} since it read "
                            f"{'it' if one else 'them'}: that is not used. Turn {name} off and on again, or start the "
                            "platform again, to read it anew")
        if self._rt.log_problem:
            problems.append(self._rt.log_problem)
        agents, waiting = self.clients(), self.pending()
        out["summary"] = _many(len(agents), "agent") + (f", {_many(len(waiting), 'call')} waiting for you"
                                                        if waiting else "")
        out["agents"] = f"{len(agents)} of {MAX_CLIENTS} at most"
        out["waiting"] = _many(len(waiting), "call") if waiting else "nothing"
        out["tokens"] = TOKEN_WORDS
        more = self._more(problems)
        facts = more.get("facts")
        for key, value in (facts.items() if isinstance(facts, Mapping) else ()):
            if isinstance(key, str) and isinstance(value, (str, int, float, bool)) and key not in out:
                out[key] = value
        offered = self._grantable_now(problems)
        out["tables"] = [*_listed(out.get("tables")), self._agents_table(agents), self._waiting_table(waiting),
                         *_listed(more.get("tables"))]
        out["forms"] = [*_listed(out.get("forms")), *self._forms(offered, agents), *_listed(more.get("forms"))]
        full = f"{MAX_CLIENTS} agents at most: forget one first" if len(agents) >= MAX_CLIENTS else ""
        out["actions"] = [*_listed(out.get("actions")), self._button("ai-add-agent", "Add an agent…", why=full),
                          self._button("ai-pace", "An agent's hold or rate…", why="" if agents else "no agent yet"),
                          self._button("ai-connect", "How to connect…"), *_listed(more.get("actions"))]
        if problems:
            out["problem"] = "; ".join(problems)
        return out

    def _more(self, problems: list[str]) -> Mapping:
        try:
            more = self.main_more() or {}
        except Exception as e:  # noqa: BLE001 - the rest of its page is drawn all the same
            problems.append(self._scrubbed(f"part of its page could not be drawn: {_words(e)}"))
            return {}
        if not isinstance(more, Mapping):
            problems.append(f"part of its page could not be drawn: main_more answered {type(more).__name__}")
            return {}
        return more

    def _grantable_now(self, problems: list[str]) -> dict[str, dict]:
        try:
            return _offered(self.grantable())
        except Exception as e:  # noqa: BLE001 - nothing can be granted until it can be said
            problems.append(self._scrubbed(f"what can be granted could not be read: {_words(e)}"))
            return {}

    def _agents_table(self, agents: list[dict]) -> dict:
        rows = []
        for a in agents:
            name, values = a["name"], {"name": a["name"]}
            token = {"live": f"until {a['expires']}", "expired": f"expired {a['expires']}", "none": "none shown"}
            rows.append([
                {"text": a["title"], "sub": name},
                {"text": a["made"] or "not said", "sub": f"for {a['by']}" if a["by"] else "added here"},
                {"text": a["last"] or "none yet", "sub": _many(a["calls"], "call")},
                {"text": _many(a["grants"], "grant") if a["grants"] else "nothing",
                 "sub": f"waits {a['hold_s']} s · {a['rate']} a minute"},
                {"text": token[a["token"]], "sub": _many(a["launch"], "launch token") if a["launch"] else ""},
                {"form": "ai-grant", "title": "Grant…", "label": f"Grant {name} something", "values": values},
                {"form": "ai-token", "title": "Show its token once…", "label": f"A new token for {name}",
                 "values": values},
                {"form": "ai-revoke", "title": "Revoke its tokens", "label": f"End every token of {name}",
                 "values": values},
                {"form": "ai-forget-agent", "title": "Forget…", "label": f"Forget {name}", "values": values},
            ])
        return {"title": "Agents",
                "columns": [{"title": "Agent"}, {"title": "Made"}, {"title": "Last call"}, {"title": "Granted"},
                            {"title": "Token"}, {"title": ""}, {"title": ""}, {"title": ""}, {"title": ""}],
                "rows": rows, "note": ("Each agent sends its own token. A new agent is granted nothing. Its calls are "
                                       "noted here; their arguments are never written to disk."),
                "empty": "No agent yet: Add an agent…, or let a harness make its own (its Use…)."}

    def _waiting_table(self, waiting: list[dict]) -> dict:
        with self._rt.state:
            texts = {c.ticket: c.text for c in self._rt.held.values()}
        rows = []
        for w in waiting:
            values = {"ticket": w["ticket"]}
            session = {"form": "ai-allow-session", "title": "Allow for this session…", "values": values,
                       "label": f"Allow {w['what']} for this session"}
            if w["twice"]:
                session.update(disabled=True, note="its rule asks twice: it is allowed once at a time")
            rows.append([
                {"text": w["title"], "sub": w["agent"]},
                {"text": w["what"], "sub": w["words"]},
                self.masked(texts.get(w["ticket"], "")) or "none",
                {"text": w["asked"], "sub": f"{w['left_s']} s left"},
                "ask twice" if w["twice"] else "ask",
                {"form": "ai-open-call", "title": "Open…", "label": f"Its call whole: {w['what']}", "values": values},
                {"form": "ai-allow-once", "title": "Allow once…", "label": f"Allow {w['what']} once",
                 "values": values},
                session,
                {"form": "ai-deny", "title": "Deny…", "label": f"Deny {w['what']}", "values": values},
            ])
        return {"title": "Waiting for you",
                "columns": [{"title": "Agent"}, {"title": "Call"}, {"title": "Arguments"}, {"title": "Asked"},
                            {"title": "Rule"}, {"title": ""}, {"title": ""}, {"title": ""}, {"title": ""}],
                "rows": rows, "note": (f"A call whose rule asks waits here, {HOLD_S} s by default; unanswered, "
                                       "nothing of it is done. Open… shows its arguments whole, every character."),
                "empty": "Nothing waits for you."}

    def _forms(self, offered: dict[str, dict], agents: list[dict]) -> list[dict]:
        name = self.title or self.name
        agent = {"name": "name", "label": "Agent", "type": "fixed"}
        ticket = {"name": "ticket", "label": "Call", "type": "fixed"}
        hows = list(dict.fromkeys(h for o in offered.values() for h in o["hows"]))
        what = {"name": "what", "label": "What", "type": "choice",
                "choices": [{"value": w, "title": o["title"], "note": o["note"] or _or(o["hows"])}
                            for w, o in offered.items()] or [{"value": "", "title": "nothing can be granted now"}]}
        how = {"name": "how", "label": "How", "type": "choice",
               "choices": [*({"value": h, "title": h} for h in hows), {"value": "", "title": "forgotten: not granted"}]}
        chosen = {"name": "name", "label": "Agent", "type": "choice",
                  "choices": [{"value": a["name"], "title": a["title"], "note": a["name"]} for a in agents]
                  or [{"value": "", "title": "no agent yet"}]}

        def deciding(id_: str, answer: str, title: str, asked: str, words: str, yes: str, danger: bool = False):
            return {"id": id_, "hook": "decide", "title": title,
                    "fields": [ticket, {"name": "answer", "label": "Answer", "type": "fixed", "value": answer},
                               {"name": ACCEPT_TWICE, "type": "accept", "title": "Allow it, exactly so?",
                                "yes": "Allow it", "words": "Its rule asks twice. Allowed, it runs now, with exactly "
                                                            "the arguments shown."}],
                    "confirm": {"title": asked, "words": words, "yes": yes, **({"danger": True} if danger else {})}}

        return [
            {"id": "ai-add-agent", "hook": "add_client", "title": "Add an agent", "submit": "Review",
             "note": "An agent you wire by hand: its token is shown once by Show its token once….",
             "fields": [{"name": "name", "label": "Name", "type": "text", "required": True,
                         "placeholder": "1 to 24 lowercase letters and digits",
                         "note": f"no hyphen; not {_or(self.RESERVED)}"},
                        {"name": "title", "label": "Title", "type": "text", "placeholder": "left empty: its name"}],
             "confirm": {"title": "Add the agent {name}?",
                         "words": f"It is granted nothing until you grant it something here (Grant…). {name} keeps "
                                  "it through your login.", "yes": "Add it"}},
            {"id": "ai-forget-agent", "hook": "forget_client", "title": "Forget an agent", "fields": [agent],
             "confirm": {"title": "Forget {name}?",
                         "words": ("Its grants and every token of it end now, and its calls waiting for you are "
                                   "denied. A harness that made it makes it again, granted nothing, when its Use… "
                                   "turns Liminal's MCP on again."),
                         "yes": "Forget it", "danger": True}},
            {"id": "ai-token", "hook": "token_once", "title": "Show its token once", "submit": "Review",
             "fields": [agent, {"name": "days", "label": "Days", "type": "number", "value": DAYS, "min": 1,
                                "max": DAYS_MOST, "note": "how long it works"},
                        {"name": ACCEPT_SHOWN, "type": "accept", "title": "Show a new token for {name}?",
                         "yes": "Show it", "words": ("It is shown in the next answer alone: copy it then. Only its "
                                                     "sha256 is kept. The token shown before stops working.")}],
             "confirm": {"title": "A new token for {name}?",
                         "words": "The token shown before, if any, stops working now.", "yes": "Go on"}},
            {"id": "ai-revoke", "hook": "revoke", "title": "Revoke its tokens", "fields": [agent],
             "confirm": {"title": "End every token of {name}?",
                         "words": ("Its hand-wired token and its launch tokens stop working now. It keeps its "
                                   "grants; a harness gets a new launch token at its next Open…."),
                         "yes": "End them", "danger": True}},
            {"id": "ai-grant", "hook": "grant", "title": "Grant", "submit": "Review", "fields": [agent, what, how],
             "confirm": {"title": "Grant {name} {what}: {how}?",
                         "words": f"Kept through your login and used by {name} at once.", "yes": "Grant it"}},
            {"id": "ai-pace", "hook": "grant", "title": "An agent's hold or rate", "submit": "Review",
             "fields": [chosen, {"name": "what", "label": "What", "type": "choice",
                                 "choices": [{"value": "hold", "title": "Its hold",
                                              "note": f"seconds a call of it waits for your answer: {HOLD_LEAST} to "
                                                      f"{HOLD_MOST}, {HOLD_S} by default"},
                                             {"value": "rate", "title": "Its rate",
                                              "note": f"requests a minute: 1 to {RATE_MOST}, {RATE} by default"}]},
                        {"name": "how", "label": "Seconds, or requests a minute", "type": "number", "min": 1,
                         "max": max(HOLD_MOST, RATE_MOST), "required": True}],
             "confirm": {"title": "{name}'s {what}: {how}?", "words": "Kept through your login and used at once.",
                         "yes": "Keep it"}},
            {"id": "ai-open-call", "hook": "waiting_call", "title": "A call waiting", "fields": [ticket],
             "confirm": False},
            deciding("ai-allow-once", "once", "Allow once", "Allow this call once?",
                     "It runs now, as its agent asked it.", "Allow once"),
            deciding("ai-allow-session", "session", "Allow for this session", "Allow it for this session?",
                     f"It runs now, and the same call of this agent runs again without asking while its session "
                     f"lasts, {SESSION_S / 60:g} minutes at most.", "Allow"),
            deciding("ai-deny", "deny", "Deny", "Deny this call?", "Nothing of it is done; its agent is told so.",
                     "Deny it", danger=True),
            {"id": "ai-connect", "hook": "client_offer", "title": "How to connect an agent", "fields": [],
             "confirm": False},
        ]


def _since(began: float) -> float:
    """Milliseconds since `began` (time.perf_counter's)."""
    return (time.perf_counter() - began) * 1000.0
