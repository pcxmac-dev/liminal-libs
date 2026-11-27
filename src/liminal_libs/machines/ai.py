"""What every AI plugin of the platform shares (1.62.0; the user, 2026-11-16: "i need 3 plugins for inference serving
local models on the platform, :: lama.cpp, ollama and vLLM, i also need 3 harness plugins for the platform ::
OpenCode, Aider, and Continue"; "they will be classified as AI plugins"; "all three plugins need to allow installation
and configuration of their respective code").

`AiPlugin` is the base, under MachinePlugin, of the model servers' plugins (machines/modelserver.py: ModelServer) and
the harnesses' (machines/harness.py: Harness). It is drawn under the platform's AI heading (SECTION "ai", in the group
its GROUP names) and is valid wherever it can serve anything (A.2): what a system lacks is a fact and a refusal in
words, never a reason to be invalid. A subclass says what Install brings here (`package`), what is there now
(`installed`: files looked at only, nothing run), how its software is installed and removed (`install_into`,
`remove_from`) and why it cannot run on this system (`runs_here`). Software that is the plugin's own code (a protocol
plugin's: machines/protocol.py) is there as a part of it (1.66.0: Installed.how "part"): nothing to install, nothing
to remove. The base gives the rest:

- Install, a job the page asks as a confirmed form: its size, its hosts, what of it is checked against a sum pinned in
  the plugin (Package.checked) and its licence said first, the licence accepted in a second confirmation
  (`accept_licence`), Cancel answered as nothing installed (what was downloaded said kept only where it is), a detach
  cancelling it as the page's Cancel does. Uninstall asked twice (`accept_removal`); with nothing installed, the same
  hook forgets what a cancel kept in downloads/ (Forget the download…, confirmed once). Refresh, a read. Every refusal
  comes before the first line of the job and in words; no administrator is ever asked.
- Its folder, `home`: <the platform's folder>/ai/<name> (app/, models/, logs/, run/, downloads/, config/), on this
  system's own disk: one on another system's drive (mounts.foreign) is that system's, so the status says so and
  Install refuses. One layout for every install: the software in app/<pin>/ and app/CURRENT, one line naming the
  folder in use (`current`, `building`, `adopt`, `forget_install`). Whether the install in use is the one Install
  brings is told by its pin (Package.pin), never by how a version is said; the install in use is never built again
  over itself, so a cancel or a failure leaves it whole.
- A start and an install exclude each other: each hook that runs the software from its folder (START_HOOKS: a model
  server's start, a harness's open) is refused while an install or an uninstall is under way (`changing_words`), and
  neither begins while a start runs (`starting`).
- Its settings: pairs kept through the platform's login (`pair`, `keep_pair`), named LIMINAL_AI_<NAME>_<WHAT>
  (`variable`): on Windows a pair is a user variable every program started afterwards inherits, and OLLAMA_*, VLLM_*
  and the like are read by the tools themselves. Where the login keeps a pair only until the platform restarts (an
  EnvironmentLogin off Windows), `lasting()` says so.
- No pair of Liminal's reaches a child (`dropped`): every variable an installed plugin declares and every LIMINAL_*
  name is taken out of the environment of what the base starts or hands on (`dropping`, `child_env`, `stream`,
  `unpack`, `short`). A streamed command's lines reach the job's panel without a secret the plugin knows, and a short
  command's output is kept to SHORT_KEPT bytes.
- Outside things are an `Outside`'s: a test's stand-ins, the real ones where it leaves them None (looked up when they
  are asked for, so a stand-in put in their place is seen).
- `status()` never raises, a subclass's own included: whatever fails inside it is answered valid with a `problem` in
  words, so the platform never takes the plugin off its page (and so never stops the servers it runs) for one read
  that failed. A version is read only by Refresh and inside a job (`read_version`), never by a status.
"""
from __future__ import annotations

import contextlib
import dataclasses
import functools
import inspect
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Mapping

from .. import instances, layout, mounts
from ..apps import authorization
from ..instances import _stem
from . import children, download, linux
from .plugin import CommandError, MachinePlugin
from .terminal import Cancelled
from .world import size_words

STEM = "liminal-ai-"  # what the AI plugins' pairs are named under: LIMINAL_AI_<NAME>_<WHAT>
ACCEPT_LICENCE = "accept_licence"  # the install's second confirmation: its licence accepted
ACCEPT_REMOVAL = "accept_removal"  # the uninstall's second confirmation
PLATFORM_DIR_VAR = "LIMINAL_PLATFORM_DIR"  # the platform's own folder (liminal-platform's rule), else the data folder's
FOLDERS = ("app", "models", "logs", "run", "downloads", "config")  # what a plugin's folder holds, each made when needed
APP = "app"  # the software: app/<pin>/, and app/CURRENT naming the one in use
CURRENT = "CURRENT"
DOWNLOADS = "downloads"  # what fetch keeps: the archives and their parts (and a tool's cache, its plugin's choice)
FORGET_FORM = "ai-forget-download"  # the form that forgets what a cancel kept while nothing is installed
LIMINAL = "LIMINAL_*"  # Liminal's own variables, never a child's
SECRET_ENDS = ("_KEY", "_TOKEN", "_PASSWORD", "_SECRET")  # a pair whose name ends so is a secret
HIDDEN = "<hidden>"  # what a secret is said as, where words that hold one are shown
SECRETS_KEPT = 32  # secret values remembered to be taken out of words
# a pinned install's folder name (0.40.16, b12359): never ending in ".", which Windows leaves out of a folder's name
PIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,78}[A-Za-z0-9_+-])?$")
NUMBERED = re.compile(r"^v?\d+(?:\.\d+){0,5}$")  # a version said in numbers alone ("0.40.16", "v2.3"): one compared
SHORT_S = 10.0  # what a plugin's own short command is given (a version read)
SHORT_KEPT = 64 << 10  # bytes kept of what a short command writes, and of its errors: the rest is read and dropped
LINES_MOST = 60  # lines of one answer
PROBLEM_CHARS = 400  # characters of a fault's words in a status
TEXT_MOST = 400  # characters of a setting typed as text
UNWRITTEN = ("Cc", "Cf", "Zl", "Zp")  # what a setting's text never holds: Unicode's controls (C0 and C1), its format
# characters (a direction's override shows a switch otherwise than it is) and its line and paragraph separators
SETTING_NAME = re.compile(r"^[a-z][a-z0-9_]{0,39}$")  # a setting's name: its form field's, a cell's value fills it
KINDS = ("text", "number", "choice")
# how what is installed came (Installed.how): this plugin's install, the user's own found here, or (1.66.0) the plugin's
# own code, a part of it with nothing to install or remove
HOWS = ("plugin", "found", "part")
PART = "part of this plugin, nothing to install"  # what a part is said as
SIZE_LOOKS = 4096  # entries looked at, at the most, to say how much its downloads/ holds
CANCELLED = "cancelled: nothing was installed (what was downloaded is kept for the next try)"
CANCELLED_AFRESH = "cancelled: nothing was installed (nothing was kept: the next try downloads it again)"
UNCHECKED = "It is not checked against a pinned sum."  # A-revisions 3's words, where a plugin pins no sum for it
LASTING = ("On this system the Login keeps a pair only until the platform restarts: what is added here is gone after "
           "a restart.")
# what a model server tells the other AI plugins it serves, asked through the platform (liminal-platform 0.31.0 keeps
# it out of its log)
SERVING = "serving"
Refusal = instances.Refusal  # a change not made, in words; `accept`: the argument a second confirmation sets
_UNREAD = object()  # an argument not given: what it stands for is read where it is wanted


def exactly(value) -> bool:
    """Whether an accepting argument is True itself: a page's true. Nothing else accepts ("true", 1, "yes")."""
    return value is True


def _innermost(login):
    """The login a lent one wraps (RecordingLogin's `inner`, however deep), else the login itself."""
    for _ in range(8):
        inner = vars(login).get("inner") if hasattr(login, "__dict__") else None
        if inner is None:
            break
        login = inner
    return login


def lasts(login, system: str) -> bool:
    """Whether a pair saved through `login` is still there after the platform restarts: not without a login; not
    through an EnvironmentLogin off Windows (it keeps a pair in this process alone: apps/authorization.py), nor through
    one holding variables of its own (a test's, a scratch preview's: LIMINAL_PLATFORM_LOGIN=memory); any other login
    keeps what it is given. Told by the login a lent one wraps (RecordingLogin passes everything through), and by what
    a login of another kind says it is (describe()["kind"]) only where it is no Login at all, so a status asks the
    login app nothing (LoginClient's describe() asks it); never by a pair."""
    if login is None:
        return False
    inner = _innermost(login)
    if isinstance(inner, authorization.EnvironmentLogin):
        own = vars(inner).get("env") is not None  # its own variables: kept in that mapping alone
        return not own and system == "windows"
    if isinstance(inner, authorization.Login):
        return True
    try:
        kind = str((login.describe() or {}).get("kind") or "")
    except Exception:  # noqa: BLE001 - a login that cannot say what it is keeps what it is given
        return True
    return kind != authorization.EnvironmentLogin.__name__ or system == "windows"


def _which(name, mode=os.F_OK | os.X_OK, path=None):
    """shutil.which, looked up when it is asked: a test's stand-in for it is seen."""
    return shutil.which(name, mode=mode, path=path)


def _now() -> float:
    return time.time()


def _registry_variables() -> tuple[str, ...]:
    from ..sources import registry  # when asked: the registry loads every plugin

    return tuple(registry.variables())


def _good_pin(name) -> bool:
    """Whether `name` can name an install's folder (PIN's letters), and is neither CURRENT itself nor a part."""
    text = str(name or "")
    return bool(PIN.fullmatch(text)) and text.upper() != CURRENT and not text.lower().endswith(download.PART)


@dataclass
class Outside:
    """Every outside thing an AI plugin reaches, a test's stand-ins; None: the real one, looked up when it is asked for.

    `env`: the environment as the plugin reads it (this process's); `system`: "windows" or "linux" (this one's); `wsl`:
    the WSL distribution this Linux is, "" for none (linux.wsl()); `home`: the plugin's own folder (<the platform's
    folder>/ai/<name>); `clock`: the wall's seconds; `which`: a program found on PATH; `interactive`: whether a window
    can be shown (windows.interactive); `powershell`, `shell`: Windows' and Linux's commands (autostart); `probe`: the
    socket table and the programs' names (resources.default_probe); `transport`, `opener`: http for an instance
    (endpoint) and for a download (download); `streamer(argv, line, *, env, cwd, timeout, cancel) -> exit code`:
    children.stream; `popen`: subprocess.Popen; `runner(args, timeout) -> (code, out, err)`: a short command
    (gpu.read, a version read); `listening(host, port)`: instances.listening; `variables() -> names`: every variable
    an installed plugin declares (registry.variables)."""

    env: Mapping[str, str] | None = None
    system: str | None = None
    wsl: str | None = None
    home: Path | None = None
    clock: Callable[[], float] = _now
    which: Callable = _which
    interactive: Callable | None = None
    powershell: object = None
    shell: object = None
    probe: object = None
    transport: Callable | None = None
    opener: Callable | None = None
    streamer: Callable | None = None
    popen: Callable | None = None
    runner: Callable | None = None
    listening: Callable | None = None
    variables: Callable | None = None


@dataclass(frozen=True)
class Package:
    """What Install brings here at the plugin's pinned version: its `title`, its `version` as its maker says it (words:
    "0.40.16", "1.0.0 (b12359)"), its `size` in bytes (0: not known until it is downloaded), its licence in words, the
    `hosts` it is downloaded from, what is downloaded (`parts`: "Ollama's standalone archive ..."), what an uninstall
    leaves (`keeps`: "Its models stay ..."), its `pin` and what of it is `checked`.

    `pin` names the folder it is installed in (app/<pin>) and alone tells whether the install in use is this one: the
    version itself when it is not given, which must then be one (letters, digits, . _ + -, not ending in .), so a
    version said as "1.0.0 (b12359)" gives its pin ("b12359"); another build of the same version is another pin
    ("b12359-cuda13", "b12359-vulkan"). It is set from the version as the package is made: `dataclasses.replace` with
    another version keeps the old pin, so give it anew. A bad one is refused when it is made (ValueError).

    `checked`: what of it is checked against a sum pinned in this plugin, a sentence in the plugin's own words ("It is
    checked against the sha256 pinned in this plugin."; "uv's archive is checked against its pinned sha256; the 108
    packages uv resolves from PyPI are not checked against a pinned sum."), said on one line and ended; "" when
    nothing of it is, and the install's words then say so (UNCHECKED)."""

    title: str
    version: str
    size: int
    licence: str
    hosts: tuple[str, ...]
    parts: str = ""
    keeps: str = ""
    pin: str = ""
    checked: str = ""

    def __post_init__(self):
        hosts = (self.hosts,) if isinstance(self.hosts, str) else tuple(self.hosts or ())
        object.__setattr__(self, "hosts", tuple(str(h) for h in hosts if str(h).strip()))
        size = self.size if isinstance(self.size, int) and not isinstance(self.size, bool) else -1
        if size < 0:
            raise ValueError(f"a package's size is a number of bytes (0: not known), not {self.size!r}")
        pin = str(self.pin or self.version or "").strip()
        if not _good_pin(pin):
            raise ValueError(f"a package's pin names the folder it is installed in (letters, digits, . _ + -, not "
                             f"ending in .): give one (pin=...) for {self.title} {str(self.version)[:80]!r}, not "
                             f"{pin[:80]!r}")
        object.__setattr__(self, "pin", pin)
        said = " ".join(str(self.checked or "").split())
        object.__setattr__(self, "checked", said if not said or said.endswith((".", "!", "?")) else said + ".")


@dataclass(frozen=True)
class Installed:
    """What is installed here: its `version` ("": not read yet, as with one found and not run), its program's or its
    folder's `path`, `how` it came ("plugin": this plugin's install; "found": the user's own, used as it is and never
    replaced or removed from here; "part", 1.66.0: software that is the plugin's own code, with no install and no
    uninstall, its version the plugin's), and a `note` shown beside it on the page."""

    version: str
    path: str
    how: str = "plugin"
    note: str = ""

    def __post_init__(self):
        if self.how not in HOWS:
            raise ValueError(f"an install is the plugin's, one found or a part of the plugin, not {self.how!r}")
        object.__setattr__(self, "version", str(self.version or ""))
        object.__setattr__(self, "path", str(self.path))


@dataclass(frozen=True)
class Setting:
    """One of a tool's main settings, as a form asks it and as it is kept (a model server's instance, a harness's use):
    `name`, its field's name (a cell's `values` fill it by that name: "context" in all three inference plugins),
    `label`, `kind` ("text", "number" or "choice"), its `default` (None: the tool's own), its `choices` (a value each,
    or (value, title) or (value, title, note)), a `note`, and a number's `min` and `max`. A bad declaration is refused
    when it is made (ValueError), so a plugin that declares one fails as it loads, not on the page."""

    name: str
    label: str
    kind: str = "text"
    default: object = None
    choices: tuple = ()
    note: str = ""
    min: int | None = None
    max: int | None = None

    def __post_init__(self):
        if not isinstance(self.name, str) or not SETTING_NAME.fullmatch(self.name):
            raise ValueError(f"a setting's name is lowercase letters, digits and _, not {self.name!r}")
        if self.kind not in KINDS:
            raise ValueError(f"setting {self.name}: its kind is one of {', '.join(KINDS)}, not {self.kind!r}")
        object.__setattr__(self, "choices", tuple(self.choices or ()))
        if self.kind == "choice" and not self.choices:
            raise ValueError(f"setting {self.name}: a choice offers at least one value")
        for bound in (self.min, self.max):
            if bound is not None and (isinstance(bound, bool) or not isinstance(bound, int)):
                raise ValueError(f"setting {self.name}: its bounds are whole numbers, not {bound!r}")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError(f"setting {self.name}: its min is above its max")

    def _offered(self) -> list[dict]:
        out = []
        for c in self.choices:
            value, title, note = (tuple(c) + (None, None))[:3] if isinstance(c, (tuple, list)) else (c, None, None)
            out.append({"value": value, "title": str(value if title is None else title), "note": str(note or "")})
        return out

    def field(self, value=None) -> dict:
        """The setting as a form's field (liminal-platform's status.forms), showing `value` (None: its default)."""
        shown = self.default if value is None else value
        out: dict = {"name": self.name, "label": self.label, "type": self.kind}
        if shown is not None:
            out["value"] = shown
        if self.note:
            out["note"] = self.note
        if self.kind == "number":
            if self.min is not None:
                out["min"] = self.min
            if self.max is not None:
                out["max"] = self.max
        if self.kind == "choice":
            out["choices"] = self._offered()
        elif shown is None:
            out["placeholder"] = "left empty: the tool's own default"
        return out

    def clean(self, value):
        """The value kept for what was typed: None when it was left empty (the tool's own default then); a number as a
        whole number within its bounds, a choice as one of its values, a text trimmed, TEXT_MOST characters at most and
        without a line break of any kind, a control character or a format character (UNWRITTEN: such a setting goes
        into a generated file or onto a command line). A Refusal in words for anything else."""
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        if self.kind == "number":
            number = value
            if isinstance(number, float) and number.is_integer():
                number = int(number)
            elif isinstance(number, str) and re.fullmatch(r"-?\d{1,18}", number.strip()):
                number = int(number.strip())
            if isinstance(number, bool) or not isinstance(number, int):
                raise Refusal(f"{self.label} is a whole number, not {str(value)[:40]!r}")
            low, high = self.min, self.max
            if (low is not None and number < low) or (high is not None and number > high):
                span = (f"from {low:,} to {high:,}" if low is not None and high is not None
                        else f"{low:,} or more" if low is not None else f"{high:,} or less")
                raise Refusal(f"{self.label} is a whole number {span}, not {number:,}")
            return number
        if self.kind == "choice":
            said = str(value).strip()
            for c in self._offered():
                if str(c["value"]) == said:
                    return c["value"]
            raise Refusal(f"{self.label} is one of {', '.join(c['title'] for c in self._offered())}, not {said[:40]!r}")
        text = str(value).strip()
        if len(text) > TEXT_MOST or any(unicodedata.category(c) in UNWRITTEN for c in text):
            raise Refusal(f"{self.label} is {TEXT_MOST} characters at most, with no line break or control character")
        return text


def _and(names: Iterable[str]) -> str:
    """Names in words: "a", "a and b", "a, b and c"."""
    shown = [str(n) for n in names if str(n)]
    if len(shown) < 2:
        return "".join(shown)
    return ", ".join(shown[:-1]) + " and " + shown[-1]


def _words(e: BaseException, plain: tuple = (ValueError, CommandError, download.DownloadError, mounts.NotHere)) -> str:
    """A fault in words, on one line: one of the kinds `plain` names (a refusal's, a failure the library words itself)
    as it is, any other with the name of its kind first."""
    said = " ".join(str(e).split())
    if said and isinstance(e, plain):
        return said
    return f"{type(e).__name__}: {said}" if said else type(e).__name__


def _sayer(log) -> Callable[[str], None]:
    """Each line said to `log` (a job's panel, or anything callable): to no one without one; a log that fails is let
    be, the work goes on."""
    if not callable(log):
        return lambda line: None

    def say(line: str) -> None:
        try:
            log(line)
        except Exception:  # noqa: BLE001 - the work goes on without its panel
            pass
    return say


def _a_job(log) -> bool:
    """Whether `log` is a job's panel as the platform hands one (liminal-libs 1.62.0's Output: callable with a line,
    taking a cancel)."""
    return callable(log) and callable(getattr(log, "cancel", None))


def _was_cancelled(log) -> bool:
    """Whether the job writing to `log` was cancelled, as its Output says (`cancelled`); a log that cannot say was
    not."""
    try:
        return bool(getattr(log, "cancelled", False))
    except Exception:  # noqa: BLE001 - a log that cannot say was not cancelled
        return False


class _Panel:
    """The panel install_into is given when the install was asked without a job's (the platform's plain ask, another
    plugin, a test): its lines said to `log` when that is callable, else to no one; its cancel a flag of its own (a
    detach sets it), `log`'s own `cancelled` looked at too; as a job's Output has them (`cancel`, `cancelled`,
    `wait_cancelled`)."""

    def __init__(self, log=None):
        self._log, self._say, self._stop = log, _sayer(log), threading.Event()

    def __call__(self, line: str) -> None:
        self._say(line)

    def cancel(self) -> None:
        self._stop.set()

    @property
    def cancelled(self) -> bool:
        return self._stop.is_set() or _was_cancelled(self._log)

    def wait_cancelled(self, timeout: float) -> bool:
        self._stop.wait(max(0.0, float(timeout)))
        return self.cancelled


def _number(part: str) -> int:
    digits = re.match(r"\d+", part.strip())
    return int(digits.group(0)) if digits else 0


def version_tuple(text) -> tuple[int, ...]:
    """A version's numbers, for comparing two, its trailing zeros left out ("1.62.0" and "1.62" are both (1, 62)); a
    part that is no number counts as 0 ("1.62.0rc1" is 1.62.0's)."""
    parts = [_number(p) for p in str(text or "").strip().split(".")] or [0]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _older(new, old) -> bool:
    """Whether version `new` is older than `old`, where both are said in numbers alone ("0.40.16", "v2.3"); never
    otherwise (words such as "b12359" or "1.0.0 (b12359)" are not compared)."""
    a, b = str(new or "").strip(), str(old or "").strip()
    if not (NUMBERED.fullmatch(a) and NUMBERED.fullmatch(b)):
        return False
    return version_tuple(a.lstrip("v")) < version_tuple(b.lstrip("v"))


def _named_folder(env: Mapping[str, str] | None) -> str:
    return str((env or {}).get(PLATFORM_DIR_VAR) or os.environ.get(PLATFORM_DIR_VAR) or "").strip()


def platform_folder(env: Mapping[str, str] | None = None) -> Path:
    """The platform's own folder, by its rule: LIMINAL_PLATFORM_DIR (of `env`, else of this process), else the data
    folder's platform/."""
    named = _named_folder(env)
    return Path(named).expanduser() if named else layout.data_dir() / "platform"


def is_secret(variable: str) -> bool:
    """Whether a pair's name says it is a secret (a key, a token, a password)."""
    return str(variable or "").strip().upper().endswith(SECRET_ENDS)


def _steady(read: Callable) -> Callable:
    """A status made one that never raises: what it raised, or an answer that is no dict, is answered by the plugin's
    `_fallen`, valid with a problem in words; what it said is noted once it is whole (AiPlugin._said)."""
    @functools.wraps(read)
    def status(self, *args, **kwargs):
        try:
            out = read(self, *args, **kwargs)
        except Exception as e:  # noqa: BLE001 - one read that failed is a problem said, never the plugin taken off
            out = self._fallen(e)
        else:
            if not isinstance(out, dict):
                out = self._fallen(TypeError(f"its status is {type(out).__name__}, not a dict"))
        self._said(out)
        return out

    status.steady = True
    return status


def _held(start: Callable) -> Callable:
    """A hook that runs the software from its folder (START_HOOKS) made one an install waits for: refused while an
    install or an uninstall is under way, and holding both off while it runs (AiPlugin.starting). Its name, its words
    and its signature stay its own."""
    @functools.wraps(start)
    def held(self, *args, **kwargs):
        with self.starting():
            return start(self, *args, **kwargs)

    held.held = True
    return held


def _drained(pipe, kept: bytearray, most: int) -> None:
    """A pipe read to its end: its first `most` bytes kept in `kept` as they come, the rest read and dropped."""
    read = getattr(pipe, "read1", None) or pipe.read
    try:
        while True:
            piece = read(children.CHUNK)
            if not piece:
                return
            room = most - len(kept)
            if room > 0:
                kept += piece[:room]
    except (OSError, ValueError):
        return
    finally:
        try:
            pipe.close()
        except (OSError, ValueError):
            pass


def _bytes_under(paths: Iterable[Path], most: int = SIZE_LOOKS) -> tuple[int, bool]:
    """What the files under `paths` hold, in bytes, no link or junction followed, and whether all of them were counted
    (`most` entries are looked at, at the most)."""
    total, looked, todo = 0, 0, [str(p) for p in paths]
    while todo:
        looked += 1
        if looked > most:
            return total, False
        path = todo.pop()
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode) and not download._junction(path):
            try:
                todo.extend(os.path.join(path, name) for name in os.listdir(path))
            except OSError:
                pass
        elif stat.S_ISREG(st.st_mode):
            total += st.st_size
    return total, True


class Run:
    """What an AI plugin keeps while it lives (its `_rt`), shared by its copies (the registry hands out a shallow one:
    with_). A base or a plugin that keeps more subclasses it and names its class in RUN_STATE: one run state, not
    two."""

    def __init__(self):
        self.lock = threading.Lock()
        self.versions: dict[str, str] = {}  # an install's version as read (read_version), by its path, until refresh
        self.changing = threading.Lock()  # one install or uninstall at a time
        self.starts = 0  # starts of its software under way (`starting`, under `lock`): no install begins meanwhile
        self.job = None  # the panel of the install under way (its job's Output, or the base's): a detach cancels it
        self.building: Path | None = None  # the folder an install builds now (building): removed when it fails
        self.secrets: list[str] = []  # secret values read or kept through the login: taken out of a fault's words
        self.trouble = ""  # what its last stop could not end (app_stopping on a detach): said, then while it runs on
        self.trouble_said = False  # whether a whole status has said it: once one has, it goes as soon as nothing runs
        self.home: tuple | None = None  # (the variables it was worked out from, its folder): `home`, worked out once


class AiPlugin(MachinePlugin):
    """An AI plugin of the platform: a model server's or a harness's (their bases: ModelServer, Harness). A subclass
    sets `name`, `title`, `about`, `order`, `ICON`, `apis`, `GROUP` and `LIBS_FLOOR`, says what Install brings and what
    is installed (`package`, `installed`), does the work (`install_into`, `remove_from`) and says why its software
    cannot run here (`runs_here`). Its `status()`, like the base's, never raises (each status a class defines is held to
    it when the class is made), and each hook of START_HOOKS it defines waits for no install (`starting`)."""

    SECTION = "ai"  # drawn under the platform's AI heading (liminal-platform 0.31.0)
    GROUP = ""  # its group there: "inference" (ModelServer), "harness" (Harness)
    api = "2.2"
    LIBS_FLOOR = ""  # the oldest liminal-libs it works with (too_old): the six plugins say "1.62.0"
    JOB_HOOKS = ("install",)  # run by the platform as a job, its lines in the page's panel
    CANCEL_HOOKS = ("install",)  # a job the page may ask to stop (liminal-platform 0.31.0's Cancel)
    # never "instances": that hook is Docker's (a model server listed there would be taken for a Docker engine)
    HOOKS = (*MachinePlugin.HOOKS, "refresh", "install", "uninstall")
    # What it says of the interface it shares (the contract's words of liminal-libs 1.63.0, read by name by the Internal
    # API tab; nothing reads them before it): its reads beside its bases'
    READ_HOOKS = ("refresh",)
    # (its install and its removal are named page-only by ModelServer and Harness, not here: a ProtocolPlugin's HOOKS
    # leave both out, and a word may name only a hook among its HOOKS. Left undeclared they are the page's alone all
    # the same: closed by default, 1.107.0)
    # The hooks that run its software from its folder (a model server's start, a harness's open). Each one a class
    # defines and lists in its HOOKS is held to `starting` when the class is made: refused while an install or an
    # uninstall is under way, and holding both off while it runs. A plugin adds its own: (*Base.START_HOOKS, "serve").
    START_HOOKS = ("start", "open")
    RUN_STATE = Run  # the class of its run state (`_rt`): a subclass of Run where a base or a plugin keeps more

    def __init__(self, outside: Outside | None = None):
        super().__init__()
        self.out = outside if outside is not None else Outside()
        self._rt = self.RUN_STATE()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        own = cls.__dict__.get("status")
        if inspect.isfunction(own) and not getattr(own, "steady", False):
            cls.status = _steady(own)
        hooks = set(cls.HOOKS)
        for name in cls.START_HOOKS:
            given = cls.__dict__.get(name)
            if name in hooks and inspect.isfunction(given) and not getattr(given, "held", False):
                setattr(cls, name, _held(given))

    # -- what a subclass says -----------------------------------------------------------------------------------------
    def package(self) -> Package | None:
        """What Install brings here at the plugin's pinned version; None: nothing is installed from here on this
        system (vLLM on Windows: its instances are held by their address alone)."""
        return None

    def installed(self) -> Installed | None:
        """What is installed here now, files looked at only (nothing is run: its version, when it is not known from
        the files, is read by `read_version`, on Refresh and inside a job). The base's: the folder app/CURRENT names,
        its pin as its version; a subclass looks for its program's file, and for an install of the user's own."""
        folder = self.current()
        return None if folder is None else Installed(folder.name, str(folder), "plugin")

    def read_version(self, installed: Installed) -> str:
        """An install's version, read by running its program (windowless, with a short timeout: `short`) where the
        files do not say it; "" when it cannot be read. Asked only by Refresh and inside a job, never by a status;
        what it answers is kept until the next Refresh. The base's: ""."""
        return ""

    def install_into(self, log, cancel: Callable[[], bool]) -> list[str]:
        """The install's work, its lines for the answer: downloaded, checked and unpacked into `building(pin)` (the
        package's pin), then put in use with `adopt(pin)` (`fetch`, `unpack`, `stream`). `log(line)`: the job's panel,
        always callable (a panel of the base's when the install was asked without a job, its lines then said to no
        one), with `cancelled` and `wait_cancelled(timeout)` as a job's Output has them; `cancel()`: true once the
        user cancelled or the plugin was turned off (Cancelled from the pieces; the base removes the folder it was
        building)."""
        raise NotImplementedError(f"{self.title or self.name} says nothing of how it is installed")

    def remove_from(self) -> list[str]:
        """The uninstall's work, its lines for the answer. The base's: the install's folder removed (`forget_install`),
        then what was downloaded for it (`forget_downloads`); a subclass removes what else it put in its folder, and
        leaves what Package.keeps says stays."""
        return [*self.forget_install(), *self.forget_downloads()]

    def runs_here(self) -> str:
        """"" or why the software cannot run on this system, in words (it is said, and Install refuses with it)."""
        return ""

    def running(self) -> list[str]:
        """What of the software runs now, by name (a model server's local instances: ModelServer.running): Install and
        Uninstall are refused while there is any. The base's: nothing."""
        return []

    def boot_names(self) -> list[str]:
        """What of it starts at boot, by name (a model server's instances with At boot on): Uninstall is refused while
        there is any, or its task or unit would start a program that is gone, again and again. The base's: none."""
        return []

    def app_stopping(self) -> None:
        """The platform stops (liminal-platform 0.31.0), or the plugin is turned off (detach): what a click started is
        stopped here, what the system started is left. The base's: nothing runs. It bears a second call."""

    # -- what the base gives ------------------------------------------------------------------------------------------
    @property
    def system(self) -> str:
        """This system as the plugin works on it: "windows" or "linux"."""
        given = str(self.out.system or "").strip().lower()
        return given if given in ("windows", "linux") else children.this_system()

    @property
    def wsl(self) -> str:
        """The WSL distribution this Linux is ("Ubuntu"), "" on Windows and on a Linux machine of its own."""
        if self.out.wsl is not None:
            return str(self.out.wsl)
        return linux.wsl() if self.system == "linux" else ""

    @property
    def home(self) -> Path:
        """The plugin's own folder: <the platform's folder>/ai/<name> (its app/, models/, logs/, run/, downloads/,
        config/ in it, each made when needed). Worked out once while the variables it is worked out from stay as they
        are (the data folder's rule looks at the workspace's folders)."""
        if self.out.home is not None:
            return Path(self.out.home)
        named = (_named_folder(self.out.env), os.environ.get(layout.HOME_VAR))
        kept = self._rt.home
        if kept is None or kept[0] != named:
            kept = self._rt.home = (named, platform_folder(self.out.env) / "ai" / self.name)
        return kept[1]

    def home_problem(self) -> str:
        """"" or why its folder cannot hold its work here: one on another system's drive (mounts.foreign) is that
        system's. Install refuses with it, and so does a model server's start."""
        try:
            foreign = mounts.foreign(self.home)
        except Exception:  # noqa: BLE001 - a path that cannot be judged is this system's
            foreign = False
        if not foreign:
            return ""
        return (f"its folder {self.home} is on another system's drive: set {PLATFORM_DIR_VAR} to a folder on this "
                "system's own disk")

    def too_old(self) -> str:
        """"" or, when LIBS_FLOOR names a liminal-libs newer than this one, why that does not do, in words."""
        floor = str(self.LIBS_FLOOR or "").strip()
        if not floor:
            return ""
        import liminal_libs  # its version as it is when asked

        have = str(getattr(liminal_libs, "__version__", "") or "")
        if have and version_tuple(have) >= version_tuple(floor):
            return ""
        return (f"{self.title or self.name} needs liminal-libs {floor} or newer, and this is "
                f"{have or 'a version that does not say'}: update the library")

    def present(self) -> bool:
        """Whether it can serve anything here: always (A.2), unless its library is too old."""
        return not self.too_old()

    def variable(self, what: str) -> str:
        """The variable one of its pairs is kept under: LIMINAL_AI_<NAME>_<WHAT> ("instances" names the same one as
        instances.variable_of(STEM + name))."""
        word = str(what or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", word):
            raise ValueError(f"a pair of {self.name} is named by letters, digits, - and _, not {word[:40]!r}")
        return f"{_stem(STEM + self.name)}_{_stem(word)}"

    def _login(self):
        """The login it keeps its pairs through: the platform's, lent attached or not; without one, the environment's
        (the given environment's alone when an Outside gives one: a test's; else this process's over the user's
        saved variables)."""
        login = self.login
        if login is not None:
            return login
        env = self.out.env
        if env is not None:
            return authorization.EnvironmentLogin(env=env if isinstance(env, dict) else dict(env))
        return authorization.EnvironmentLogin(saved=authorization.saved_variables)

    def _remember(self, variable: str, value) -> None:
        if is_secret(variable):
            self._keep_secret(value)

    def _keep_secret(self, value) -> None:
        """A secret's value remembered (SECRETS_KEPT at most), to be taken out of every word said (`_scrubbed`)."""
        if not isinstance(value, str) or len(value) < 4:
            return
        with self._rt.lock:
            if value not in self._rt.secrets:
                self._rt.secrets.append(value)
                del self._rt.secrets[:-SECRETS_KEPT]

    def _scrubbed(self, text: str) -> str:
        """`text` with every secret this plugin read or kept through its login, or gave a streamed command, taken
        out."""
        with self._rt.lock:
            values = sorted(self._rt.secrets, key=len, reverse=True)
        for value in values:
            text = text.replace(value, HIDDEN)
        return text

    def pair(self, variable: str) -> str:
        """The value of one of its pairs, kept through its login; "" when there is none or no one is signed in."""
        try:
            text = instances.Store(variable, self._login).text()
        except authorization.Unauthorized:
            return ""
        self._remember(variable, text)
        return text

    def keep_pair(self, variable: str, text: str | None) -> str:
        """One of its pairs kept through its login (`text` None: forgotten): where, in the login's own words. A
        Refusal in words when it is not kept (no login, too long, a login that keeps nothing)."""
        self._remember(variable, text)
        try:
            return instances.Store(variable, self._login).put(text)
        except authorization.Unauthorized as e:
            raise Refusal(self._scrubbed(f"{variable} is not kept: {e.reason}")) from None

    def lasting(self) -> str:
        """"" or, where its login keeps a pair only until the platform restarts, that, in words."""
        return "" if lasts(self._login(), self.system) else LASTING

    @staticmethod
    def cancel_of(log) -> Callable[[], bool]:
        """Whether the job writing to `log` was cancelled, as a callable for the pieces that look between their steps
        (fetch, unpack, stream): the job's Output says it (`cancelled`); anything else never is."""
        return functools.partial(_was_cancelled, log)

    # -- a start and an install exclude each other --------------------------------------------------------------------
    def changing_words(self) -> str:
        """"" or, while an install or an uninstall of its software is under way, that in words: what a start of it is
        refused with meanwhile (`starting`), and what its button's note says."""
        if not self._rt.changing.locked():
            return ""
        return f"{self.title or self.name} is being installed or removed: wait for that to end"

    @contextlib.contextmanager
    def starting(self) -> Iterator[None]:
        """While its software is started from its folder (each hook of START_HOOKS is held to it; a subclass's own way
        of starting it may be too): refused before anything is done while an install or an uninstall is under way
        (`changing_words`), and no install or uninstall begins until it has ended. Starts may run beside each other."""
        with self._rt.lock:
            words = self.changing_words()
            if words:
                raise Refusal(words)
            self._rt.starts += 1
        try:
            yield
        finally:
            with self._rt.lock:
                self._rt.starts -= 1

    def _starts(self) -> int:
        with self._rt.lock:
            return self._rt.starts

    # -- the other plugins, asked through the app ---------------------------------------------------------------------
    @staticmethod
    def _ask_app(app, name: str, hook: str, args: list):
        """Another plugin's hook asked through the app: the platform's ask(name, hook, args) or the frame's
        ask(name, hook, *args)."""
        ask = app.ask
        try:
            spread = inspect.signature(ask).parameters.get("args")
        except (TypeError, ValueError):
            spread = None
        if spread is not None and spread.kind is inspect.Parameter.VAR_POSITIONAL:
            return ask(name, hook, *args)
        return ask(name, hook, list(args))

    def _ask_others(self, hook: str, *args) -> list[tuple[str, object, BaseException | None]]:
        """Each other plugin attached beside it whose hooks list `hook`, asked it through the app with `args` while no
        lock is held (two plugins asking each other never wait on each other), in the app's order: [(its name, its
        answer, None), or (its name, None, what it raised)]. None without an app; what the app's list of its plugins
        raises is raised."""
        app = self.app
        if app is None:
            return []
        out: list[tuple[str, object, BaseException | None]] = []
        for name, face in dict(app.plugins() or {}).items():
            hooks = face.get("hooks") if isinstance(face, Mapping) else None
            if name == self.name or not hooks or hook not in hooks:
                continue
            try:
                out.append((name, self._ask_app(app, name, hook, list(args)), None))
            except Exception as e:  # noqa: BLE001 - one that refuses is its asker's to say or to leave out
                out.append((name, None, e))
        return out

    # -- what reaches a child -----------------------------------------------------------------------------------------
    def dropped(self) -> tuple[str, ...]:
        """What is taken out of every child's environment: every variable an installed plugin declares (its keys,
        plans and options: registry.variables(), on Windows kept as user variables every process inherits) and every
        LIMINAL_* name. Where the registry cannot say, LIMINAL_* alone."""
        try:
            names = tuple((self.out.variables or _registry_variables)() or ())
        except Exception:  # noqa: BLE001 - a registry that cannot say: Liminal's own names still go
            names = ()
        return tuple(dict.fromkeys([*(str(n) for n in names if str(n).strip()), LIMINAL]))

    def dropping(self, launch: children.Launch) -> children.Launch:
        """`launch` with every pair of Liminal's (`dropped`) taken out of its environment too."""
        return dataclasses.replace(launch, drop=tuple(dict.fromkeys([*launch.drop, *self.dropped()])))

    def child_env(self, env: Mapping[str, str] | None = None) -> dict[str, str]:
        """A child's whole environment: this process's (the Outside's when it gives one) without `dropped`, then `env`
        laid over it."""
        launch = children.Launch((), env=dict(env or {}), drop=self.dropped())
        return children.environment(launch, base=self.out.env, system=self.system)

    def stream(self, argv, log=None, *, env: Mapping[str, str] | None = None, cwd=None, timeout: float = 1800.0,
               cancel: Callable[[], bool] | None = None, secret: Iterable[str] = ()) -> int:
        """An installer's command run to its end, windowless (children.stream): each line to `log` as it comes, every
        secret the plugin knows taken out of it (those it read or kept through its login, and the values of `env`
        that a secret's name holds or `secret` names: a tool may print what it was given); its environment
        `child_env(env)`, cancelled once `cancel()` (the job's, by default) is true; its exit code."""
        given = dict(env or {})
        named = {str(n) for n in ((secret,) if isinstance(secret, str) else (secret or ()))}
        for variable, value in given.items():
            if str(variable) in named or is_secret(str(variable)):
                self._keep_secret(str(value))
        say, stop = _sayer(log), cancel if cancel is not None else self.cancel_of(log)

        def line(text: str) -> None:
            say(self._scrubbed(text))

        whole = self.child_env(given)
        if self.out.streamer is not None:
            return self.out.streamer([str(a) for a in argv], line, env=whole, cwd=cwd, timeout=timeout, cancel=stop)
        return children.stream(argv, line, env=whole, cwd=cwd, timeout=timeout, cancel=stop, popen=self.out.popen,
                               system=self.system)

    def fetch(self, source: download.Source, folder=None, *, log=None, cancel: Callable[[], bool] | None = None,
              resume: bool = True, limit: int = 8 << 30, timeout: float = 7200.0) -> Path:
        """A pinned file downloaded into `folder` (its downloads/ by default), whole and checked (download.fetch)."""
        stop = cancel if cancel is not None else self.cancel_of(log)
        return download.fetch(source, folder if folder is not None else self.home / DOWNLOADS, log=log, cancel=stop,
                              resume=resume, limit=limit, timeout=timeout, opener=self.out.opener)

    def unpack(self, archive, into, *, log=None, cancel: Callable[[], bool] | None = None, strip: int = 0,
               limit: int = 16 << 30) -> int:
        """An archive unpacked into `into` (download.unpack), zstd where one is needed started without a pair of
        Liminal's in its environment (`child_env`): the files written."""
        stop = cancel if cancel is not None else self.cancel_of(log)
        return download.unpack(archive, into, log=log, cancel=stop, limit=limit, strip=strip, which=self.out.which,
                               popen=self.out.popen, env=self.child_env())

    def short(self, args, timeout: float = SHORT_S) -> tuple[int, str, str]:
        """A short command of the plugin's own (a version's read): windowless, nothing typed into it, its environment
        `child_env()`, `timeout` seconds at most (then it is ended): (its exit code, what it wrote, its errors), each
        of the two cut at SHORT_KEPT bytes (the rest is read and dropped). children.ChildError in words when it cannot
        be run or takes too long. The Outside's `runner` stands in for it."""
        argv = [str(a) for a in args]
        if self.out.runner is not None:
            return self.out.runner(argv, timeout)
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=self.child_env(),
                                       **({"creationflags": children.NO_WINDOW} if os.name == "nt" else {}))
        except (OSError, ValueError) as e:
            raise children.ChildError(f"{children.said(argv)} could not run: {e}") from None
        out, err = bytearray(), bytearray()
        readers = [threading.Thread(target=_drained, args=(pipe, kept, SHORT_KEPT), daemon=True, name="short-read")
                   for pipe, kept in ((process.stdout, out), (process.stderr, err))]
        for reader in readers:
            reader.start()
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # asked to end, never forced (1.88.4, "all shutdowns need to be clean"): one still running is left, and said
            from .. import proctree

            left = "" if proctree.ask_end(process, children.END_S) else \
                f" (asked to end, still running as pid {getattr(process, 'pid', '?')}: left, not killed)"
            raise children.ChildError(f"{children.said(argv)} took more than {timeout:g} s{left}") from None
        finally:
            for reader in readers:
                reader.join(children.LEFT_S)  # what it started may hold its output open: not waited for past this
        return code, bytes(out).decode("utf-8", "replace"), bytes(err).decode("utf-8", "replace")

    # -- the one layout of an install ---------------------------------------------------------------------------------
    @staticmethod
    def _pin(pin) -> str:
        name = str(pin or "").strip()
        if not _good_pin(name):
            raise ValueError(f"an install's folder is named by its pin (letters, digits, . _ + -, not ending in .), "
                             f"not {name[:80]!r}")
        return name

    def current(self) -> Path | None:
        """The install's folder in use: the one app/CURRENT names, when it is there; None otherwise."""
        app = self.home / APP
        try:
            name = (app / CURRENT).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            return None
        if not _good_pin(name):
            return None
        folder = app / name
        return folder if folder.is_dir() and not folder.is_symlink() else None

    def building(self, pin) -> Path:
        """An empty folder for the install of `pin`, app/<pin>: one left there before (half built by a try that failed
        or was cancelled, or a copy that does not run: `installed` says none) is removed first, and CURRENT with it
        when it named that one. The install in use, while `installed` says it is there, is never built again over
        itself (ValueError): a new one is built beside it, under its own pin, and put in use once it is whole, so a
        cancel or a failure leaves the one in use as it was. The install's own: should the install fail or be
        cancelled, the base removes it; CURRENT names it only once `adopt` puts it in use."""
        name = self._pin(pin)
        app = self.home / APP
        mounts.owner_only(app, f"Installing {self.title or self.name}")
        folder = app / name
        if os.path.lexists(folder):
            if self.current() == folder:
                have = self.installed()
                if have is not None and have.how == "plugin":
                    raise ValueError(f"{folder} is the install in use: it is not built again over itself (a new one "
                                     "is built beside it, under its own pin)")
                (app / CURRENT).unlink()  # rebuilt where it was in use: nothing is in use until `adopt`
            download.remove_tree(folder, app)
        folder.mkdir(parents=True)
        with self._rt.lock:
            self._rt.building = folder
        return folder

    def _clear(self, app: Path, keep: Iterable[str]) -> list[str]:
        """Everything of app/ removed but what `keep` names (by its name as this system compares names: Windows takes
        two that differ in case for one): its lines (one that cannot be removed is said and left)."""
        kept = {os.path.normcase(k) for k in keep}
        part = os.path.normcase(CURRENT + download.PART)
        lines = []
        try:
            entries = sorted(app.iterdir(), key=lambda p: p.name)
        except OSError:
            return lines
        for entry in entries:
            if os.path.normcase(entry.name) in kept:
                continue
            try:
                freed = download.remove_tree(entry, app)
            except (OSError, ValueError, mounts.NotHere) as e:
                lines.append(f"{entry} could not be removed ({e}): the next install or uninstall removes it")
                continue
            if os.path.normcase(entry.name) != part:
                lines.append(f"removed {entry.name} ({size_words(freed)})")
        return lines

    def adopt(self, pin) -> list[str]:
        """The install of `pin` put in use: app/CURRENT names it (written whole, a part file renamed), then every other
        folder of app/ is removed: its lines (one that cannot be removed, a program still running from it on Windows,
        is said and left for the next install or uninstall)."""
        name = self._pin(pin)
        app = self.home / APP
        folder = app / name
        if not folder.is_dir():
            raise ValueError(f"{folder} is not there: nothing is put in use")
        part = app / (CURRENT + download.PART)
        part.write_text(name + "\n", encoding="utf-8")
        os.replace(part, app / CURRENT)
        with self._rt.lock:
            if self._rt.building == folder:
                self._rt.building = None
        return [f"in use now: {folder}", *self._clear(app, (CURRENT, name))]

    def forget_install(self) -> list[str]:
        """The install removed whole: app/CURRENT first (nothing is in use from then on, whatever else cannot be
        removed), then every folder of app/: its lines (one that cannot be removed is said and left)."""
        app = self.home / APP
        if not os.path.lexists(app):
            return [f"nothing was installed in {app}"]
        lines = []
        try:
            (app / CURRENT).unlink()
            lines.append(f"{app / CURRENT} removed: nothing of {self.title or self.name} is in use")
        except FileNotFoundError:
            pass
        except OSError as e:
            lines.append(f"{app / CURRENT} could not be removed: {e}")
        lines += self._clear(app, ())
        try:
            app.rmdir()
        except OSError:
            pass
        with self._rt.lock:
            self._rt.versions.clear()
            self._rt.building = None
        return lines

    def forget_downloads(self) -> list[str]:
        """What was downloaded for it removed: its downloads/ (the archives, the parts a cancel kept, a tool's cache)
        with all it holds. Its lines (what cannot be removed is said and left)."""
        folder = self.home / DOWNLOADS
        if not os.path.lexists(folder):
            return []
        try:
            freed = download.remove_tree(folder, self.home)
        except (OSError, ValueError, mounts.NotHere) as e:
            return [f"{folder} could not be removed whole ({e}): what is left is removed by the next uninstall"]
        return [f"removed {DOWNLOADS} ({size_words(freed)})"]

    def _downloaded(self) -> list[Path]:
        """What its downloads/ holds now (archives, the parts a cancel kept, a tool's cache), by name; none when it is
        not there. Looked at only."""
        try:
            return sorted((self.home / DOWNLOADS).iterdir(), key=lambda p: p.name)
        except OSError:
            return []

    def _abandon(self) -> list[str]:
        """The folder an install was building removed, when it is not the one in use: after a failure or a cancel."""
        with self._rt.lock:
            folder, self._rt.building = self._rt.building, None
        if folder is None or not os.path.lexists(folder) or folder == self.current():
            return []
        try:
            download.remove_tree(folder, self.home / APP)
        except (OSError, ValueError, mounts.NotHere) as e:
            return [f"the half-built {folder} could not be removed ({e}): the next install removes it"]
        return [f"the half-built {folder} was removed"]

    def _pinned(self, have: Installed | None, pkg: Package) -> bool:
        """Whether this plugin's own install is the one Install brings: told by its pin (the name of the folder
        app/CURRENT names), never by how a version is said; an install laid out otherwise, by its version."""
        if have is None or have.how != "plugin":
            return False
        folder = self.current()
        return (folder.name if folder is not None else have.version) == pkg.pin

    def _landed(self, pkg: Package) -> Installed | None:
        """This plugin's install of `pkg`'s pin when it is in use now (`adopt` put it in use before a later step failed
        or was cancelled); None otherwise, and when that cannot be told."""
        try:
            folder, now = self.current(), self.installed()
        except Exception:  # noqa: BLE001 - what cannot be told is said as not installed
            return None
        if folder is None or folder.name != pkg.pin or now is None or now.how != "plugin":
            return None
        return now

    # -- the words of an install --------------------------------------------------------------------------------------
    def _known_version(self, have: Installed | None) -> str:
        """An install's version where it is known (its own, or the one read: `read_version`); "" otherwise."""
        if have is None:
            return ""
        with self._rt.lock:
            read = self._rt.versions.get(have.path, "")
        return have.version or read

    def _version_of(self, have: Installed) -> str:
        return self._known_version(have) or "version not read yet"

    def _installed_words(self, have: Installed | None, pkg: Package | None, here: str) -> str:
        if have is None:
            if here:
                return f"not installed: {here}"
            if pkg is not None:
                return f"not installed: Install… brings {pkg.title} {pkg.version} ({self._size(pkg)})"
            return "not installed, and nothing is installed from here on this system"
        if have.how == "part":
            said = self._part_words(have)
        elif have.how == "plugin":
            said = f"{self._version_of(have)}, installed by this plugin in {have.path}"
        else:
            said = (f"{self._version_of(have)} at {have.path}: your own install, used as it is and never replaced "
                    "from here")
        return f"{said} · {have.note}" if have.note else said

    def _part_words(self, have: Installed) -> str:
        """What software that is part of the plugin is said as: "{title} {version}: part of this plugin, nothing to
        install" (its version its own, else the plugin's)."""
        version = self._known_version(have) or str(self.version or "")
        return " ".join(x for x in (self.title or self.name, version) if x) + f": {PART}"

    def _not_part(self, what: str) -> None:
        """Refused in words when its software is part of the plugin (Installed.how "part"): there is nothing to
        `what` ("install", "remove")."""
        have = self.installed()
        if have is not None and have.how == "part":
            raise Refusal(f"{self.title or self.name} is part of this plugin: there is nothing to {what}")

    @staticmethod
    def _size(pkg: Package) -> str:
        return f"about {size_words(pkg.size)}" if pkg.size else "its size is not known until it is downloaded"

    def _system_words(self) -> str:
        if self.system == "windows":
            return "Windows"
        return f"Linux, inside WSL ({self.wsl})" if self.wsl else "Linux"

    def _keep_version(self, have: Installed | None, say=None) -> str:
        """The version of `have` read now (read_version) and kept until the next Refresh: "" when it cannot be."""
        if have is None:
            return ""
        try:
            read = str(self.read_version(have) or "").strip()
        except Exception as e:  # noqa: BLE001 - a version that cannot be read is not known
            if say is not None:
                say(f"its version could not be read: {self._scrubbed(_words(e))}")
            return ""
        if read:
            with self._rt.lock:
                self._rt.versions[have.path] = read[:80]
        return read[:80]

    def _usable(self) -> None:
        old = self.too_old()
        if old:
            raise Refusal(old)

    def _reply(self, said: str, ok: bool = True, lines: Iterable[str] = ()) -> dict:
        shown = [self._scrubbed(str(x)) for x in lines if str(x).strip()]
        if len(shown) > LINES_MOST:
            shown = [*shown[:LINES_MOST - 1], f"… and {len(shown) - LINES_MOST + 1:,} more"]
        return {"said": self._scrubbed(said), "ok": ok, "lines": shown}

    def _cancelled(self) -> str:
        """The cancelled answer as things are: what was downloaded said kept only where its downloads/ holds something
        (download.fetch keeps a part only where a sha256 is pinned for it; a tool's cache stays where it is)."""
        return CANCELLED if self._downloaded() else CANCELLED_AFRESH

    # -- the hooks ----------------------------------------------------------------------------------------------------
    def refresh(self) -> dict:
        """What is installed looked at again now, its version read (a found install's by running it once, windowless,
        with a short timeout) and kept until the next Refresh. A read: nothing is changed."""
        self._usable()
        with self._rt.lock:
            self._rt.versions.clear()
        lines: list[str] = []
        have = self.installed()
        if have is not None:
            self._keep_version(have, lines.append)
        pkg = self.package()
        words = self._installed_words(have, pkg, self.runs_here())
        named = have is not None and have.how != "part"  # (a part's words name it already)
        return self._reply(f"read again: {self.title or self.name} {words}" if named else f"read again: {words}", True,
                            lines)

    def install(self, accept_licence=False, log=None) -> dict:
        """Its software installed (or updated to the pinned version, or put back to it) into its own folder, for this
        user alone, as a job (`log`: the platform's panel, which also says whether the user cancelled it). Refused in
        words before the job's first line: its library too old; its software part of the plugin (Installed.how
        "part": nothing to install); nothing installed from here on this system (`runs_here`, `package`); its folder
        on another system's drive; an install or an uninstall under way; the user's own install found (used as it is,
        never replaced); the pinned install in use already (told by its pin); a start of it under way, or something
        of it running; and its licence not accepted yet (a Refusal naming accept_licence, asked as a second
        confirmation with the licence's words).

        Then `install_into` does the work, given the job's panel (or one of the base's when it was asked without a
        job: always callable, its cancel set by a detach, as a job's is by the page's Cancel). A cancel answers
        CANCELLED, or CANCELLED_AFRESH where nothing downloaded was kept (ok False); a failure its words (ok False);
        each with the half-built folder removed and the one in use kept. Once the new pin is in use (`adopt`), a later
        failure or cancel is answered as installed, with what went wrong said (ok True)."""
        self._usable()
        self._not_part("install")
        pkg = self.package()
        here = self.runs_here()
        if pkg is None or here:
            raise Refusal(here or f"{self.title or self.name} is not installed from here on this system")
        with self._software_change():
            return self._install(pkg, accept_licence, log)

    @contextlib.contextmanager
    def _software_change(self) -> Iterator[None]:
        """An install or an uninstall, one at a time: refused before anything is done while its folder is on another
        system's drive or another one is under way; no start begins meanwhile (`starting`)."""
        trouble = self.home_problem()
        if trouble:
            raise Refusal(trouble)
        if not self._rt.changing.acquire(blocking=False):
            raise Refusal(f"{self.title} is being installed or removed already: wait for that to end")
        try:
            yield
        finally:
            with self._rt.lock:
                self._rt.job = None
            self._rt.changing.release()

    def _install(self, pkg: Package, accept_licence, log) -> dict:
        """The install, its lock held (no start begins meanwhile): its last refusals, then the work."""
        have = self.installed()
        if have is not None and have.how != "plugin":
            raise Refusal(f"{self.title} at {have.path} is your own install: it is used as it is, never replaced from "
                          "here")
        if self._pinned(have, pkg):
            raise Refusal(f"{pkg.title} {pkg.version} is installed already")
        if self._starts():
            raise Refusal(f"{pkg.title} is being started: it is not changed while it runs")
        busy = self.running()
        if busy:
            raise Refusal(f"stop {_and(busy)} first: {pkg.title} is not changed while it runs")
        if not exactly(accept_licence):
            raise Refusal(f"the licence of {pkg.title} {pkg.version} is not accepted yet", accept=ACCEPT_LICENCE)
        panel = log if _a_job(log) else _Panel(log)
        say, cancel = _sayer(panel), self.cancel_of(panel)
        with self._rt.lock:
            self._rt.building, self._rt.job = None, panel
        old = self._known_version(have)
        verb = "installing" if have is None else "going back to" if _older(pkg.version, old) else "updating"
        say(f"{verb} {pkg.title} {pkg.version}{f' (from {old})' if old else ''} into {self.home}")
        try:
            lines = [str(x) for x in (self.install_into(panel, cancel) or [])]
            now = self.installed()
        except Exception as e:  # noqa: BLE001 - a cancel, and every failure, answered in its words, the panel told
            cancelled = isinstance(e, Cancelled)
            words = "" if cancelled else self._scrubbed(_words(e))
            gone = self._abandon()
            landed = self._landed(pkg)
            if landed is not None:
                trouble = "it was in use before Cancel was seen" if cancelled else f"a last step failed: {words}"
                return self._installed_answer(pkg, landed, say, gone, trouble)
            said = self._cancelled() if cancelled else f"not installed: {words}"
            say(said)
            return self._reply(said if cancelled else f"{pkg.title} {pkg.version} was not installed: {words}", False,
                               gone)
        if now is None or now.how != "plugin":
            said = f"{pkg.title} {pkg.version} was not put in use: no install of it is found in {self.home}"
            gone = self._abandon()
            say(said)
            return self._reply(said, False, [*lines, *gone])
        with self._rt.lock:
            self._rt.building = None
        return self._installed_answer(pkg, now, say, lines)

    def _installed_answer(self, pkg: Package, now: Installed, say, lines: list[str], trouble: str = "") -> dict:
        """The answer of an install whose pin is in use now: installed; with `trouble`, what went wrong after it was
        put in use (a later step failed or was cancelled) said with it."""
        read = self._keep_version(now, say) or now.version or pkg.version
        said = (f"{pkg.title} {read} is installed in {now.path}, but {trouble}" if trouble
                else f"{pkg.title} {read} installed in {now.path}")
        say(said)
        return self._reply(said, True, [*lines, "nothing was started"])

    def uninstall(self, accept_removal=False) -> dict:
        """Its software removed from its folder (`remove_from`), asked twice: refused in words while its library is
        too old, for software that is part of the plugin (nothing to remove), while its folder is on another system's
        drive, while an install or an uninstall is under way, while nothing of this plugin's is installed (the user's
        own install is never removed from here), while a start of it is under way or something of it runs or starts
        at boot, and until it is accepted (a Refusal naming accept_removal). Its instances and what Package.keeps names
        stay.

        With nothing installed, what was downloaded for it (what a cancel kept in downloads/) is what it removes, at
        once: its form (Forget the download…) is confirmed once and carries no accept_removal, so should an install
        have come meanwhile, that form's ask is refused (accepting the removal is the uninstall form's alone)."""
        self._usable()
        self._not_part("remove")
        with self._software_change():
            return self._uninstall(accept_removal)

    def _uninstall(self, accept_removal) -> dict:
        """The uninstall, its lock held: its last refusals, then the work."""
        have = self.installed()
        if have is None:
            if not self._downloaded():
                raise Refusal(f"{self.title} is not installed here: there is nothing to remove")
            return self._forget_kept()
        if have.how != "plugin":
            raise Refusal(f"{self.title} at {have.path} is your own install: it is never removed from here")
        if self._starts():
            raise Refusal(f"{self.title} is being started: it is not removed while it runs")
        busy = self.running()
        if busy:
            raise Refusal(f"stop {_and(busy)} first: {self.title} is not removed while it runs")
        boot = self.boot_names()
        if boot:
            raise Refusal(f"turn At boot off for {_and(boot)} first: its task or unit would start a program that is "
                          "gone")
        version = self._version_of(have)
        if not exactly(accept_removal):
            raise Refusal(f"{self.title} {version} is removed from {self.home} only once that is accepted",
                          accept=ACCEPT_REMOVAL)
        try:
            lines = [str(x) for x in (self.remove_from() or [])]
        except Exception as e:  # noqa: BLE001 - what was removed so far is said with what was not
            return self._reply(f"{self.title} {version} was not removed whole: {_words(e)}", False)
        with self._rt.lock:
            self._rt.versions.clear()
        left = self.installed()
        if left is not None and left.how == "plugin":
            return self._reply(f"{self.title} {version} is not removed whole: {left.path} is still there", False,
                                lines)
        return self._reply(f"{self.title} {version} removed from {self.home}", True, lines)

    def _forget_kept(self) -> dict:
        """With nothing installed, what was downloaded for it removed (what a cancel kept): its form confirmed it."""
        folder = self.home / DOWNLOADS
        lines = self.forget_downloads()
        if self._downloaded():
            return self._reply(f"what was downloaded for {self.title} is not removed whole from {folder}", False,
                                lines)
        return self._reply(f"what was downloaded for {self.title} is removed from {folder}", True, lines)

    # -- what the page draws -----------------------------------------------------------------------------------------
    def install_form(self, pkg: Package, have: Installed | None) -> dict:
        """The install's form (ai-install): a job, its words first (what of it is checked against a pinned sum among
        them), its licence accepted in a second confirmation. Over an older pin of this plugin's it is an update; over
        a newer one (the plugin put back to an older release), going back."""
        update = have is not None and have.how == "plugin"
        old = self._known_version(have) if update else ""
        if update and _older(pkg.version, old):
            title, asked, yes = (f"Go back to {pkg.title} {pkg.version}",
                                 f"Replace {pkg.title} {old} with the older {pkg.version}?", "Replace")
        elif update:
            title, asked, yes = (f"Update {pkg.title} to {pkg.version}",
                                 f"Update {pkg.title} {self._version_of(have)} to {pkg.version}?", "Update")
        else:
            title, asked, yes = f"Install {pkg.title} {pkg.version}", f"Install {pkg.title} {pkg.version}?", "Install"
        hosts = _and(pkg.hosts) or "its maker's servers"
        words = (f"{pkg.parts or f'{pkg.title} {pkg.version}'} is downloaded from {hosts} ({self._size(pkg)}) and "
                 f"unpacked into {self.home}, for you alone: no administrator is asked. Its progress shows in the "
                 f"panel below; Cancel stops it. {pkg.checked or UNCHECKED} Its licence, first: {pkg.licence} You are "
                 "asked to accept it next.")
        return {"id": "ai-install", "hook": "install", "title": title, "job": True, "submit": "Review",
                "note": f"For you alone, into {self.home}: no administrator is asked.",
                "fields": [{"name": ACCEPT_LICENCE, "type": "accept", "title": f"Accept {pkg.title}'s licence?",
                            "yes": "Accept and install",
                            "words": f"{pkg.licence} Accepted, {pkg.title} {pkg.version} is installed now."}],
                "confirm": {"title": asked, "words": words, "yes": yes}}

    def uninstall_form(self, have: Installed, pkg: Package | None) -> dict:
        """The uninstall's form (ai-uninstall): a danger, asked twice."""
        version = self._version_of(have)
        keeps = f" {pkg.keeps}" if pkg is not None and pkg.keeps else ""
        return {"id": "ai-uninstall", "hook": "uninstall", "title": f"Uninstall {self.title}",
                "fields": [{"name": ACCEPT_REMOVAL, "type": "accept", "title": f"Remove {self.title} {version}?",
                            "yes": "Uninstall",
                            "words": (f"Its files are deleted from {self.home / APP}, and what was downloaded for it "
                                      f"from {self.home / DOWNLOADS}: this cannot be undone, and only an install "
                                      "brings it back.")}],
                "confirm": {"title": f"Uninstall {self.title}?",
                            "words": f"{self.title} {version} is removed from {self.home}.{keeps} You are asked a "
                                     "second time.",
                            "yes": "Uninstall", "danger": True}}

    def forget_download_form(self, kept: list[Path]) -> dict:
        """The form that forgets what was downloaded for it while nothing is installed (ai-forget-download, asked of
        the uninstall's hook): a danger confirmed once, what it holds and its size said. It has no field: the
        uninstall's second confirmation (accept_removal) is never its to give, so it can never remove an install that
        came meanwhile."""
        size, whole = _bytes_under(kept)
        held = size_words(size) if whole else f"more than {size_words(size)}"
        names = [p.name for p in kept]
        shown = _and(names) if len(names) <= 3 else f"{', '.join(names[:3])} and {len(names) - 3:,} more"
        folder, name = self.home / DOWNLOADS, self.title or self.name
        return {"id": FORGET_FORM, "hook": "uninstall", "title": f"Forget what was downloaded for {name}", "fields": [],
                "confirm": {"title": f"Forget what was downloaded for {name}?",
                            "words": f"{shown} ({held}), kept in {folder} for the next try, is deleted. Nothing of "
                                     f"{name} is installed, and nothing else is changed: an install downloads it "
                                     "again from the start.",
                            "yes": "Forget", "danger": True}}

    def _stop_trouble(self, busy) -> str:
        """What its last stop could not end: said by the next status whatever runs, then by every status while
        something of it still runs; forgotten once a status has said it (`_said`) and nothing of it runs."""
        with self._rt.lock:
            if self._rt.trouble and self._rt.trouble_said and not busy:
                self._rt.trouble, self._rt.trouble_said = "", False
            return self._rt.trouble

    def _said(self, out) -> None:
        """A whole status said (every status of the plugin's is held to it: _steady): what its last stop could not end
        is noted said once a status carried it, so a later one drops it while nothing of it runs. Never raises."""
        try:
            problem = str(out.get("problem") or "")
            with self._rt.lock:
                if self._rt.trouble and self._rt.trouble in problem:
                    self._rt.trouble_said = True
        except Exception:  # noqa: BLE001 - a status is said all the same
            pass

    @staticmethod
    def _button(form: str, title: str, values: Mapping | None = None, why: str = "") -> dict:
        """A button that opens `form` (its fields filled from `values`), disabled with `why` when that is said."""
        out: dict = {"form": form, "title": title}
        if values is not None:
            out["values"] = dict(values)
        if why:
            out.update(disabled=True, note=why)
        return out

    def base_status(self, *, have: Installed | None | object = _UNREAD, running: list[str] | None = None,
                    boot: list[str] | None = None) -> dict:
        """What every AI plugin's Main shows (F 4): present and valid (unless its library is too old), the install in
        words (`installed`, its note beside it), this system, its folder, what does not last ("kept"), a problem with
        its folder or with its last stop (`_stop_trouble`), and the install's forms and actions:
        Install… (or Update…, or Go back…) while the pinned install is not the one in use, Uninstall… for this
        plugin's own install, Forget the download… while nothing is installed and a cancel kept something, Read
        again. Files are looked at; nothing is run or asked over the network. `have`, `running`, `boot`: what
        installed(), running() and boot_names() answer, where the caller read them for the same draw already (a
        model server's status reads its instances once); asked here otherwise."""
        note = self.not_for_here()
        if note:
            return self.not_here_status(note, tables=[], forms=[], actions=[])
        old = self.too_old()
        refresh = {"hook": "refresh", "args": [], "title": "Read again",
                   "note": "looks at what is installed here again now, and reads its version (a found install's by "
                           "running it once, windowless)"}
        out: dict = {"present": not old, "valid": not old, "why": old}
        if old:
            out.update({"summary": old, "system": self._system_words(), "folder": str(self.home), "tables": [],
                        "forms": [], "actions": []})
            return out
        pkg, have, here = self.package(), self.installed() if have is _UNREAD else have, self.runs_here()
        trouble = self.home_problem()
        busy, changing = self.running() if running is None else running, self._rt.changing.locked()
        name = self.title or self.name
        if have is not None and have.how == "part":
            out["summary"] = self._part_words(have)
        elif have is not None:
            mine = "" if have.how == "plugin" else ": your own install"
            out["summary"] = f"{name} {self._version_of(have)}{mine}"
        else:
            out["summary"] = f"not installed: {here}" if here else "not installed"
        out["installed"] = self._installed_words(have, pkg, here)
        out["system"] = self._system_words()
        out["folder"] = str(self.home)
        kept = self.lasting()
        if kept:
            out["kept"] = kept
        problems = [p for p in (trouble, self._stop_trouble(busy)) if p]
        if problems:
            out["problem"] = "; ".join(problems)
        forms: list[dict] = []
        actions: list[dict] = [refresh]
        under_way = "an install or an uninstall is under way" if changing else ""
        blocked = trouble or (f"stop {_and(busy)} first" if busy else "") or under_way
        if pkg is not None and (have is None or have.how == "plugin"):
            update = have is not None
            if not self._pinned(have, pkg):
                forms.append(self.install_form(pkg, have))
                why = here or blocked
                back = update and _older(pkg.version, self._known_version(have))
                title = f"Go back to {pkg.version}…" if back else f"Update to {pkg.version}…" if update else "Install…"
                actions.append(self._button("ai-install", title, why=why))
        elif pkg is not None and have is not None and have.how == "found":
            actions.append(self._button("ai-install", "Install…", why=f"your own install at {have.path} is used as it "
                                                                      "is, never replaced from here"))
        if have is not None and have.how == "plugin":
            forms.append(self.uninstall_form(have, pkg))
            boot = self.boot_names() if boot is None else boot
            why = blocked or (f"turn At boot off for {_and(boot)} first" if boot else "")
            actions.append(self._button("ai-uninstall", "Uninstall…", why=why))
        if have is None:
            downloaded = self._downloaded()
            if downloaded:
                forms.append(self.forget_download_form(downloaded))
                actions.append(self._button(FORGET_FORM, "Forget the download…", why=trouble or under_way))
        out.update({"tables": [], "forms": forms, "actions": actions})
        return out

    @_steady
    def status(self) -> dict:
        """Its Main (base_status): a subclass's own adds its tables, forms and facts. Never raises."""
        return self.base_status()

    def ask(self, hook: str, *args, **kwargs):
        """A hook asked by name (the platform's way: Plugin.ask), refused in words while its library is older than
        LIBS_FLOOR: every hook but `present` and `status`, a subclass's own too."""
        if hook not in ("present", "status"):
            self._usable()
        return super().ask(hook, *args, **kwargs)

    def _fallen(self, error: BaseException) -> dict:
        """The status when reading it failed: valid (A.2) with the fault as its problem, in words without a secret,
        what the base can still say around it (its install's forms, Read again); never raises."""
        try:
            name = self.title or self.name or type(self).__name__
            words = self._scrubbed(_words(error))
            if len(words) > PROBLEM_CHARS:
                words = words[:PROBLEM_CHARS - 1] + "…"
            problem = f"part of {name}'s state could not be read: {words}"
            try:
                out = dict(self.base_status())
            except Exception:  # noqa: BLE001 - the base's part failed too: what is left to say
                old = self.too_old()
                out = {"present": not old, "valid": not old, "why": old, "folder": str(self.home), "tables": [],
                       "forms": [],
                       "actions": [{"hook": "refresh", "args": [], "title": "Read again",
                                    "note": "looks at what is installed here again now"}]}
            out["summary"] = f"{name}: its state could not be read whole"
            out["problem"] = "; ".join(p for p in (problem, str(out.get("problem") or "")) if p)
            return out
        except Exception:  # noqa: BLE001 - nothing more can be said, and still nothing is raised
            return {"present": True, "valid": True, "why": "", "summary": "its state could not be read",
                    "problem": "its state could not be read"}

    def detach(self) -> None:
        """Detached (turned off, or the platform ending): an install under way asked to stop, as the page's Cancel
        asks it (its job ends as cancelled: nothing of a plugin turned off goes on running); then told it stops
        (`app_stopping`: what a click started is stopped); then detached as every plugin is. What the stop could not
        end is said by the next status, and by every one after it while something of it still runs."""
        with self._rt.lock:
            self._rt.trouble, self._rt.trouble_said = "", False
            job = self._rt.job
            if job is not None:  # (under the lock: the install cannot end and let its panel go meanwhile)
                try:
                    job.cancel()
                except Exception:  # noqa: BLE001 - a panel that takes no cancel: the install ends by itself
                    pass
        try:
            self.app_stopping()
        except Exception as e:  # noqa: BLE001 - it is detached all the same
            words = f"its last stop could not end everything: {self._scrubbed(_words(e))}"  # (it takes the lock)
            with self._rt.lock:
                self._rt.trouble, self._rt.trouble_said = words, False
        super().detach()
