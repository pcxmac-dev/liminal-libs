"""A program a plugin starts and owns, and a command whose lines are followed (1.62.0; the user, 2026-11-16, of the
model servers: "the plugins manage the services", and of the six tools: "all three plugins need to allow installation
and configuration of their respective code").

`Child` is a server its plugin started by a click: windowless, with no standard input, what it prints appended to its
log (moved to <log>.1 past LOG_MAX, closed before it is moved), its number and its start written to a pidfile so that
a later run of the platform finds it again (`adopt`), ended with what it started when it is stopped or when this
process ends (`stop_all`). Two threads follow it: one copies what it prints into its log, the other waits for its end
and cleans up after it at once, even while a program it started still holds its output open. On Windows it is held in
a job object (keep.py's) that ends it with this process, and it is asked to end with Ctrl+C (`interrupt`: the
console's helper, liminal_libs/console.py), since a console program there ends cleanly only that way; it is never
given a process group of its own, which would turn Ctrl+C off in it, and this process clears its own "ignore Ctrl+C"
before its first child is started, since a child inherits that too. On Linux it leads a session of its own and is
asked with SIGTERM; its group is then ended with SIGKILL.

`Piped` (1.66.0; the user, 2026-11-18: "an MCP plugin for platform, basically a protocol plugin that mediates MCP
connections to resources by local AI agents") is a child its plugin talks to: an MCP server over stdio. Its standard
input and output are pipes, and each message is one line. It is started as a Child is (windowless, in a job object on
Windows, in a session of its own on Linux, its pidfile written), and what it prints as errors goes into its log.
`send` writes a line to it; a thread hands each line it prints to its plugin; a line longer than LINE_MAX ends it. It
is stopped in the order MCP's stdio transport gives (2026-07-28): its input is closed, it gets its grace, and then it
is ended with what it started (its job on Windows; SIGTERM, then SIGKILL, to its group on Linux). One an earlier run
left running is ended at its next start.

`Launch` is what is started: the command, the variables laid over this process's environment, the names taken out of
that environment first (`drop`: no pair of Liminal's, and no variable a tool reads by itself, reaches a child unless
its plugin sets it), the folder, and which of the variables are secret. `environment` makes the child's environment
of it; `shown` writes the same launch as lines to paste into a terminal, a secret's value never among them, nor in a
child's log.

`stream` runs a command to its end (an installer's: uv, npm, hf), each line it prints handed on as it comes, and ends
it with what it started when it takes too long or its user cancels the job; output that something out of its reach
holds open after it (a daemon that left its group) is given up, and that is said, rather than waited for.

A process is told by its number (a signal, the console's helper, an end) only while that number is surely its own: one
this module started through the real subprocess.Popen and has not collected yet, or one adopted by a pidfile whose
start still matches (proc.holder). A stand-in for a process (a test's) is told through its own methods alone: its
number may be some real program's."""
from __future__ import annotations

import atexit
import codecs
import ctypes
import functools
import os
import queue
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Iterator, Mapping

from .. import console, proc
from . import keep
from .plugin import CommandError
from .terminal import Cancelled
from .windows import quote

GRACE_S = 8.0  # what a child is given to end by itself once it is asked
LOG_MAX = 1_000_000  # bytes: a child's log is moved to <log>.1 past this
LINE_CHARS = 2000  # a line longer than this is cut
INTERRUPT_S = 5.0  # the console's helper at most
END_S = 5.0  # what a child that was ended is given to be gone
STEP_S = 0.1  # between two looks at a child that is ending
WAIT_S = 1.0  # a wait for a child's end is taken in pieces of this (Windows hears Ctrl+C only between two waits)
WATCH_S = 0.2  # how often a streamed command's cancel is looked at
LEFT_S = 2.0  # what a program's output is given to end once the program has (one it started may hold it open)
CHUNK = 65536  # bytes read at once
QUEUED = 8  # pieces of a streamed command's output read ahead of its lines at most (CHUNK bytes each)
TAIL_BYTES = 262144  # of a log's end are read for its last lines
SAID_CHARS = 40  # a word of a command said in words (`said`) is cut past this
HIDE_MIN = 4  # a secret this long is looked for inside other text; a shorter one only as a whole word
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW
PLACEHOLDER = "<the key kept for it>"  # what `shown` writes where a secret's value would be: its user types it
MARK = PLACEHOLDER.encode("utf-8")  # the same in a child's log
PLAIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")  # a variable's name both shells write as it is
LIMINAL = ("LIMINAL_*",)  # what a streamed command given no environment is run without: Liminal's own variables
TERM = signal.SIGTERM
KILL = getattr(signal, "SIGKILL", 9)  # (Windows has no such name)
# The real Popen class, for isinstance alone (what it made is a process of this system, told by its number). It is
# never called here: a start looks subprocess.Popen up when it runs, so a test's guard stands in for it there.
_Popen = subprocess.Popen
_PEEKS = hasattr(os, "waitid")  # a child's end can be seen without collecting it (Linux)

program = console.program  # a program by its name: C:/tools/uv.exe as uv


class ChildError(CommandError):
    """A child could not be started or ended, or a streamed command ran too long: why, in words."""


def this_system() -> str:
    """This system as a launch names it: "windows" or "linux" (another POSIX system starts and ends a child as Linux
    does)."""
    return "windows" if os.name == "nt" else "linux"


def said(args) -> str:
    """A command in a few words, its program by name, each word on one line and cut past SAID_CHARS characters: uv
    pip install --python."""
    args = [str(a) for a in args]
    return " ".join(_word(word) for word in [program(args[0]), *args[1:4]]) if args else "the command"


def _word(text: str) -> str:
    text = " ".join(text.split())  # on one line
    return text if len(text) <= SAID_CHARS else text[:SAID_CHARS - 1] + "…"


# -- what is started ---------------------------------------------------------------------------------------------------
def _names(given) -> tuple[str, ...]:
    return (given,) if isinstance(given, str) else tuple(str(n) for n in given or ())


@dataclass(frozen=True)
class Launch:
    """What is started: `argv`, the command; `env`, the variables laid over this process's environment; `cwd`, the
    folder ("": this process's); `drop`, the names taken out of the environment first, each a name or a prefix ending
    "*" (OLLAMA_*); `secret`, the names of `env` whose values are secret. No line `shown` writes holds a secret's
    value; a child's log holds none in its first line (the command) and none of HIDE_MIN characters or more in what
    the program prints."""

    argv: tuple[str, ...]
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str = ""
    drop: tuple[str, ...] = ()
    secret: tuple[str, ...] = ()

    def __post_init__(self):
        argv = (self.argv,) if isinstance(self.argv, (str, os.PathLike)) else tuple(self.argv)
        object.__setattr__(self, "argv", tuple(str(a) for a in argv))
        object.__setattr__(self, "env", {str(k): str(v) for k, v in dict(self.env or {}).items()})
        object.__setattr__(self, "cwd", str(self.cwd or ""))
        object.__setattr__(self, "drop", _names(self.drop))
        object.__setattr__(self, "secret", _names(self.secret))


def _named(patterns: Iterable[str], name: str, fold: bool) -> bool:
    """Whether one of `patterns` names a variable: a name as it is, or a prefix ending "*"; `fold`: without regard to
    case, as Windows reads a variable's name."""
    name = name.upper() if fold else name
    for pattern in patterns:
        pattern = pattern.upper() if fold else pattern
        if pattern.endswith("*"):
            if name.startswith(pattern[:-1]):
                return True
        elif name == pattern:
            return True
    return False


def environment(launch: Launch, base: Mapping[str, str] | None = None, *, system: str | None = None) -> dict[str, str]:
    """A child's environment: `base` (this process's own unless given) without every name `launch.drop` names (a
    name, or a prefix ending "*"), then `launch.env` laid over it. Nothing else is taken out: what must not reach a
    child is named in `drop` (the plugin bases name every pair of Liminal's there). On Windows (`system`: this one
    unless given) names are told apart without regard to case, as Windows does."""
    base = os.environ if base is None else base
    fold = (system or this_system()) == "windows"
    mine = {name.upper() for name in launch.env} if fold else set()
    out = {str(name): str(value) for name, value in base.items()
           if not _named(launch.drop, str(name), fold) and not (fold and str(name).upper() in mine)}
    out.update(launch.env)
    return out


def _secrets(launch: Launch) -> list[str]:
    """The launch's secret values (of the names `secret` holds, told apart without regard to case), the longest
    first."""
    secret = {name.upper() for name in launch.secret}
    found = {value for name, value in launch.env.items() if name.upper() in secret and value}
    return sorted(found, key=len, reverse=True)


def masked(text: str, values: Iterable[str], inside: int = HIDE_MIN) -> str:
    """`text` with each of `values` (secrets, the longest first) replaced by the placeholder: one that is the whole
    of it, or all after its last "=" (--api-key=abc), whatever its length; inside other text, one of `inside`
    characters or more (a shorter one may be any word's letters by chance). `carries` asks the same of one key."""
    values = list(values)
    if text in values:
        return PLACEHOLDER
    head, equals, tail = text.rpartition("=")
    text, end = (head, "=" + PLACEHOLDER) if equals and tail in values else (text, "")
    for value in values:
        if len(value) >= inside:
            text = text.replace(value, PLACEHOLDER)
    return text + end


def carries(text, key: str, inside: int = HIDE_MIN) -> bool:
    """Whether `text` (a word of a command, a variable's value, a folder) holds the secret `key` where `masked` would
    hide it: as the whole of it, as all after its last "=", or inside it when the key is `inside` characters or
    more."""
    text = str(text or "")
    if not key:
        return False
    return text == key or text.rpartition("=")[2] == key or (len(key) >= inside and key in text)


def _unset(name: str, windows: bool) -> str:
    """The line that takes a variable out of a terminal's environment ("": sh cannot write that name)."""
    if not windows:
        return f"unset {name}" if PLAIN.match(name) else ""
    path = f"Env:{name}" if PLAIN.match(name) else f"-LiteralPath {quote('Env:' + name)}"
    return f"Remove-Item {path} -ErrorAction SilentlyContinue"


def _set(name: str, value: str, windows: bool) -> str:
    """The line that sets a variable in a terminal's environment ("": sh cannot write that name). PowerShell writes
    a name of other characters as a quoted path, as `_unset` does: ${env:...} would end at a brace in it."""
    if not windows:
        return f"export {name}={shlex.quote(value)}" if PLAIN.match(name) else ""
    if PLAIN.match(name):
        return f"$env:{name} = {quote(value)}"
    return f"Set-Item -LiteralPath {quote('Env:' + name)} -Value {quote(value)}"


def not_passed(word: str) -> str:
    """Why Windows PowerShell 5.1 would not hand `word` to a program as it is, in words ("": it would). It passes a
    program its words by its old rules (7.3 and later quote each word for the program themselves, and so hand over
    as it is every word these rules do): an empty word is left out; a double quote is passed unescaped, so the
    program reads it as one of the command line's own; a word that holds whitespace is put in double quotes as it
    is, so a backslash at its end escapes the closing one; and a word that is its stop-parsing token, --%, is taken
    for that, the words after it passed unquoted.
    (Measured on Windows PowerShell 5.1.26100, 2026-11-18, single-quoted words as `shown` writes them.)"""
    if not word:
        return "it is empty, and PowerShell 5.1 leaves an empty word out"
    if '"' in word:
        return "it holds a double quote, which PowerShell 5.1 passes on unescaped"
    if word == "--%":
        return "it is PowerShell's stop-parsing token, which PowerShell 5.1 takes for itself"
    if word.endswith("\\") and any(c.isspace() and c not in _SEPARATORS for c in word):
        return "it holds a space and ends in a backslash, which escapes the quote PowerShell 5.1 closes it with"
    return ""


_SEPARATORS = "\x1c\x1d\x1e\x1f"  # whitespace to Python and not to .NET's char.IsWhiteSpace, which PowerShell asks


def shown(launch: Launch, system: str, base: Mapping[str, str] | None = None) -> list[str]:
    """The launch as lines to paste into a terminal (PowerShell's on "windows", sh's on "linux"): a line unsetting
    each variable of `base` (this process's environment unless given) that `launch.drop` names and that is set there
    now, a line setting each name of `launch.env`, the folder when `launch.cwd` names one, then the command, each
    quoted for that shell (PowerShell's single quotes, the typographic ones among them, doubled: windows.quote). A
    secret name's value is the placeholder `<the key kept for it>`, which its user replaces: a secret's value is in
    no line. (A name sh cannot write, one that is not letters, digits and underscores, is left out of sh's lines.)
    PowerShell hands a program its words by rules of its own: a ValueError, in words, for a word of the command that
    Windows PowerShell 5.1 would not hand it as it is (`not_passed`), since no line would then run the launch."""
    base = os.environ if base is None else base
    windows = system == "windows"
    secret = {name.upper() if windows else name for name in launch.secret}
    named, seen = [], set()
    for name in sorted(str(n) for n in base):  # (on Windows one name once, whatever its case)
        if _named(launch.drop, name, windows) and (name.upper() if windows else name) not in seen:
            seen.add(name.upper() if windows else name)
            named.append(name)
    lines = [_unset(name, windows) for name in named]
    values = _secrets(launch)
    for name, value in launch.env.items():
        kept = (name.upper() if windows else name) in secret
        lines.append(_set(name, PLACEHOLDER if kept else masked(value, values), windows))
    words = [masked(word, values) for word in launch.argv]
    folder = masked(launch.cwd, values)
    if windows:
        for word in words[1:]:
            why = not_passed(word)
            if why:
                raise ValueError(f"{program(words[0])}'s command cannot be pasted into PowerShell as it is: its word "
                                 f"{_word(word)!r} would not reach it as it is ({why})")
        lines.append(f"Set-Location -LiteralPath {quote(folder)}" if folder else "")
        lines.append("& " + " ".join(quote(word) for word in words) if words else "")
    else:
        lines.append(f"cd {shlex.quote(folder)}" if folder else "")
        lines.append(shlex.join(words))
    return [line for line in lines if line]


# -- this system's processes, by handle and by number ------------------------------------------------------------------
def _flags(system: str) -> dict:
    """How a child is started on a system. Windows: without a window (CREATE_NO_WINDOW alone: a process group of its
    own would turn Ctrl+C off in it). Linux: in a session of its own, so its group is the child and what it started."""
    return {"creationflags": NO_WINDOW} if system == "windows" else {"start_new_session": True}


def _real(starter) -> bool:
    """Whether `starter` is the real subprocess.Popen (or a class of its own): what it starts is a process of this
    system."""
    return starter is _Popen or (isinstance(starter, type) and issubclass(starter, _Popen))


_ctrl_c_lock = threading.Lock()
_ctrl_c_cleared = False  # this process's "ignore Ctrl+C" was cleared before its first child (Windows)


def _hear_ctrl_c() -> None:
    """This process's "ignore Ctrl+C" cleared, once, before the first child is started on Windows
    (console.hear_ctrl_c). A child inherits it, and one started with it set never hears the Ctrl+C that asks it to
    end, so its every Stop would wait out the grace and end it by force. A platform started by a program that had it
    set (one that gave it a process group of its own, a detached start) has it; one started at sign-in, as the logon
    task starts it, has not, and nothing changes. Cleared before the start is made, under a lock: a child started
    at the same moment from another thread inherits it cleared too."""
    global _ctrl_c_cleared
    with _ctrl_c_lock:
        if not _ctrl_c_cleared:
            console.hear_ctrl_c()
            _ctrl_c_cleared = True


def _held(process):
    """A job object holding `process` and whatever it starts, which ends them with this process (Windows, keep.py's):
    None where none can be made or `process` cannot be put in it."""
    job = keep._job()
    if job is None:
        return None
    if keep._hold(job, process):
        return job
    _close_job(job)
    return None


@functools.cache
def _kernel32():
    """Windows' kernel32 with the four calls of the helpers below declared, loaded once: `_in_job` is asked for every
    listener on an instance's port at every draw of its page. None where there is none (not Windows)."""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.TerminateJobObject.restype = ctypes.c_int
        k32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        k32.CloseHandle.restype = ctypes.c_int
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k32.IsProcessInJob.restype = ctypes.c_int
        k32.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        return k32
    except (AttributeError, OSError):
        return None


def _end_job(job) -> bool:
    """Everything a job holds ended now (TerminateJobObject): a child and what it started. Whether Windows did."""
    try:
        k32 = _kernel32()
        return k32 is not None and bool(k32.TerminateJobObject(job, 1))
    except (AttributeError, OSError):
        return False


def _close_job(job) -> None:
    """A job's handle given back (what it still holds ends with it)."""
    try:
        k32 = _kernel32()
        if k32 is not None:
            k32.CloseHandle(job)
    except (AttributeError, OSError):
        pass


def _in_job(job, pid: int) -> bool:
    """Whether the process `pid` is held in a job (IsProcessInJob): one the job's child started."""
    try:
        k32 = _kernel32()
        if k32 is None:
            return False
        handle = k32.OpenProcess(0x1000, 0, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            inside = ctypes.c_int(0)
            return bool(k32.IsProcessInJob(handle, job, ctypes.byref(inside))) and bool(inside.value)
        finally:
            k32.CloseHandle(handle)
    except (AttributeError, OSError):
        return False


def _signal_group(pid: int, sig: int) -> bool:
    """`sig` to the process group `pid` leads (POSIX): whether it was sent."""
    try:
        os.killpg(pid, sig)
        return True
    except (AttributeError, OSError):
        return False


def _signal_one(pid: int, sig: int) -> bool:
    """`sig` to the one process `pid`: whether it was sent."""
    try:
        os.kill(pid, sig)
        return True
    except OSError:
        return False


def _leads(pid: int) -> bool:
    """Whether the process `pid` leads a process group of its own (POSIX)."""
    try:
        return os.getpgid(pid) == pid
    except (AttributeError, OSError):
        return False


def _session_of(pid: int) -> int | None:
    """The session the process `pid` is in, by its leader's number (POSIX); None when it cannot be told."""
    try:
        return os.getsid(pid)
    except (AttributeError, OSError):
        return None


def _peek(pid: int, block: bool) -> str:
    """Whether a child of this process has ended, asked without collecting it (waitid's WNOWAIT; `block`: its end is
    waited for): "" while it runs, "ended" once it has (until it is collected its number stays its own, so its group
    can still be told by it), "gone" when it was collected already."""
    try:
        seen = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | (0 if block else os.WNOHANG))
    except ChildProcessError:
        return "gone"
    except (AttributeError, OSError):
        return ""
    return "ended" if seen is not None else ""


def _uncollected(process, system: str) -> bool:
    """Whether `process` is one whose end this module sees before it collects it: a real one, on a system that can."""
    return isinstance(process, _Popen) and system != "windows" and _PEEKS


def _run(args, timeout: float) -> tuple[int, str, str]:
    """A short command of this module's own run without a window, with no input, its output dropped: (its exit code,
    "", ""). No output is read, so no thread is needed: it also runs while this process is ending."""
    done = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=timeout, **proc.no_window())
    return done.returncode, "", ""


def interrupt(pid: int, runner=None) -> bool:
    """Ctrl+C delivered to a child that runs without a window (Windows): whether it was. A process cannot send it to
    another's console while it has one of its own, so a helper does: `python -P -m liminal_libs.console interrupt
    PID`, run without a window and given INTERRUPT_S seconds. False when it could not (the child has no console, it
    has ended, the helper did not run) and on a system that is not Windows. True means it was sent, not that it was
    heard: a program may ignore it. `runner(args, timeout) -> (code, out, err)` stands in for the helper in tests."""
    if runner is None and this_system() != "windows":
        return False
    try:
        code, _, _ = (runner or _run)(console.interrupt_command(pid), INTERRUPT_S)
    except (OSError, TypeError, ValueError, subprocess.SubprocessError, CommandError):
        return False
    return code == 0


# -- a child's log -----------------------------------------------------------------------------------------------------
class _Log:
    """A child's log: appended to as the child prints, and moved to <log>.1 once it is past `most` bytes, at the end
    of a line where the output has one. It is closed before it is moved (Windows moves no open file). When the move
    fails (another program holds the log, or <log>.1, open: a page reading its last lines, an editor), it is copied
    over <log>.1 and cut, or cut alone when <log>.1 cannot be written, so that the two together stay within about
    two of its sizes and neither is lost for the other; one that can be neither moved nor cut is given up.
    `hide`: secret values (those of HIDE_MIN characters or more), replaced
    by the placeholder as they come; the end of a line not ended yet is held back as far as a secret could begin
    there, and written with what follows. A log that cannot be written is given up: the child's output is still
    read, so the child never waits on a full pipe."""

    def __init__(self, path: Path, most: int = LOG_MAX, hide: Iterable[str] = ()):
        self.path, self.most = Path(path), int(most)
        self.file = None
        self._size = 0
        values = {str(value).encode("utf-8") for value in hide if len(str(value)) >= HIDE_MIN}
        self._hide = sorted(values, key=len, reverse=True)
        self._back = max((len(value) for value in self._hide), default=1) - 1  # bytes a secret may begin in
        self._held = b""  # the end of a line not ended yet, where a secret may begin

    def open(self) -> None:
        """Opened to be appended to (OSError when it cannot be); one left past its size by an earlier run is moved
        aside first, or cut when it cannot be moved."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._aside(self.most)
        except OSError:
            pass  # neither moved nor cut: its next turn tries again, and gives it up if it still cannot
        self._reopen()

    def _reopen(self) -> None:
        self.file = self.path.open("ab")
        self._size = self.file.seek(0, os.SEEK_END)

    def _length(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def _aside(self, most: int) -> None:
        """Moved to <log>.1 once it is `most` bytes or more (it is closed now). When it cannot be moved (Windows moves
        no file another program holds open: the log, which a page or an editor reads, or <log>.1), it is copied over
        <log>.1 and then cut, which a program that only reads either file lets be done; when <log>.1 cannot be
        written either, the log alone is cut and <log>.1 is kept as it is. Nothing is removed before it is known to be
        replaced. OSError when the log can be neither moved nor cut."""
        keep.rotate(self.path, most)
        if self._length() < max(most, 1):
            return
        try:
            with self.path.open("rb") as source, self.path.with_name(self.path.name + ".1").open("wb") as target:
                shutil.copyfileobj(source, target, CHUNK)
        except OSError:
            pass  # <log>.1 cannot be written: kept as it is, and the log is cut alone
        self._cut()

    def _cut(self) -> None:
        """Emptied where it lies: what it held is lost, its size kept within bounds."""
        self.path.open("wb").close()

    def _kept(self, data: bytes) -> bytes:
        """`data` as it is written: each secret replaced; of a line not ended yet, the end held back as far as a
        secret could begin there (no secret holds a line feed), to be looked at again with what follows."""
        if not self._hide:
            return data
        data = self._held + data
        for value in self._hide:
            data = data.replace(value, MARK)
        cut = max(data.rfind(b"\n") + 1, len(data) - self._back)
        self._held = data[cut:]
        return data[:cut]

    def write(self, data: bytes) -> None:
        if self.file is None or not data:
            return
        data = self._kept(data)
        try:
            if data and self._size + len(data) >= self.most:
                cut = data.rfind(b"\n") + 1 or len(data)
                self.file.write(data[:cut])
                self.file.close()  # closed, then moved
                self._aside(0)  # (OSError: neither moved nor cut: the log is given up below)
                self._reopen()
                data = data[cut:]
            if data:
                self.file.write(data)
                self.file.flush()
                self._size += len(data)
        except (OSError, ValueError):
            self.close()

    def close(self) -> None:
        """Closed, what was held back written first."""
        file, self.file = self.file, None
        held, self._held = self._held, b""
        try:
            if file is not None:
                if held and not file.closed:
                    file.write(held)
                file.close()
        except (OSError, ValueError):
            pass


def last_lines(log: Path, lines: int = 40) -> list[str]:
    """A log's last lines, the oldest first, each cut at LINE_CHARS, blank ones left out: from <log>.1 before it when
    the log was moved aside a moment ago; none when there is no log."""
    log, want = Path(log), max(0, int(lines))
    out: list[str] = []
    for path in (log, log.with_name(log.name + ".1")):
        if len(out) < want:
            out = _end_of(path, want - len(out)) + out
    return out


def _end_of(path: Path, want: int) -> list[str]:
    try:
        with path.open("rb") as f:
            start = max(0, f.seek(0, os.SEEK_END) - TAIL_BYTES)
            f.seek(start)
            data = f.read()
    except OSError:
        return []
    if start:  # the read began inside a line: that one is left out
        data = data.partition(b"\n")[2]
    found = [line.rstrip()[:LINE_CHARS] for line in data.decode("utf-8", "replace").splitlines() if line.strip()]
    return found[-want:] if want else []


def _chunks(pipe) -> Iterator[bytes]:
    """What a program's output gives, CHUNK bytes at most at a time, until it ends or can be read no more."""
    while True:
        try:
            chunk = pipe.read(CHUNK)
        except (OSError, ValueError):
            return
        if not chunk:
            return
        yield chunk


class _Lines:
    """A command's output cut into lines as it comes: at a line feed or a carriage return (a progress line drawn over
    itself is a line each time it is drawn), read as UTF-8 (what is not: replaced), each cut at LINE_CHARS, blank
    ones left out."""

    def __init__(self, line: Callable[[str], None]):
        self._line = line
        self._decode = codecs.getincrementaldecoder("utf-8")("replace")
        self._held = ""  # a line not ended yet: LINE_CHARS of it at most, the rest of it is dropped as it comes

    def feed(self, data: bytes) -> None:
        parts = re.split("[\r\n]", self._held + self._decode.decode(data))
        self._held = parts.pop()[:LINE_CHARS]
        for part in parts:
            self._give(part)

    def end(self) -> None:
        self._give(self._held + self._decode.decode(b"", final=True))
        self._held = ""

    def _give(self, text: str) -> None:
        if text.strip():
            self._line(text.rstrip()[:LINE_CHARS])


# -- a child -----------------------------------------------------------------------------------------------------------
_all: list["Child"] = []  # the children this process started that have not ended
_all_lock = threading.Lock()
_hooked = False  # stop_all is registered with atexit (at the first start)


def adopted_words(system: str | None = None) -> str:
    """What is said of an adopted child whose starter has ended without stopping it (its `note`): an earlier
    platform's run, or a boot task's `launch serve`, ended by force. What the child prints went to that program, so
    it reaches no log now; on Linux a program that does not ignore a lost output, as one in C or Go does not, ends
    at its next line."""
    words = "the program that started it has ended without stopping it: what it prints now reaches no log"
    if (system or this_system()) != "windows":
        words += ", and a program that does not ignore a lost output (one in C or Go) ends at its next line"
    return words


def _owner_gone(pidfile: Path) -> bool:
    """Whether the run that started the child a pidfile names, and read what it printed, has ended: its number is not
    alive, or is another process's by now. False while it runs, or where the pidfile does not say who it was."""
    try:
        parts = Path(pidfile).read_text().split()
        owner, began = int(parts[2]), int(parts[3])
    except (OSError, ValueError, IndexError):
        return False
    if owner <= 0:
        return False
    if not proc.pid_alive(owner):
        return True
    now = proc.started(owner)
    return bool(began) and now is not None and now != began


class Child:
    """A program started for a plugin and owned by it: `start()`, `stop()`, whether it is `alive`, its `pid`, its
    exit `code`, `since` when it runs, the last lines of its log (`tail`), whether a process is its own (`owns`).
    `name` is what its words call it; `log` and `pidfile` are files in the plugin's own folder. `adopt` gives the
    child an earlier run of this program left running, by its pidfile; its `note` says what is to be said of it ("":
    nothing). `popen`, `interrupt`, `clock`, `sleep` and `system` stand in for subprocess.Popen, for the console's
    Ctrl+C (`interrupt(pid) -> bool`), for the clock and the wait a stop's grace is measured with, and for this system
    ("windows" | "linux"). A `popen` that is neither subprocess.Popen nor a class of it leaves this process's own
    Ctrl+C as it is (a test's stand-in starts nothing that could inherit it)."""

    def __init__(self, name: str, launch: Launch, log: Path, pidfile: Path, *, popen=None, interrupt=None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 system: str | None = None):
        self.name = str(name)
        self.launch = launch
        self.log = Path(log)
        self.pidfile = Path(pidfile)
        self.system = system or this_system()
        self.adopted = False  # found by its pidfile, started by an earlier run: not this process's to collect
        self.note = ""  # what is to be said of it: of an adopted one, that its output is lost (`adopted_words`)
        self._popen = popen
        self._interrupt = interrupt
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.RLock()  # its state; a real child is collected, and its job closed, only under it
        self._stopping = threading.Lock()  # one stop at a time: a second waits and finds it ended
        self._process = None  # what Popen gave, when this process started it
        self._pid: int | None = None
        self._job = None  # the job object holding it (Windows)
        self._since: float | None = None
        self._over = True  # nothing runs: never started, or its end was seen and cleaned up after
        self._reader: threading.Thread | None = None  # copies what it prints into its log
        self._watcher: threading.Thread | None = None  # waits for its end and cleans up after it
        self._gone: threading.Event | None = None  # set by the watcher once its wait is over: what `wait` waits on

    # -- starting --------------------------------------------------------------------------------------------------
    def start(self) -> int:
        """It is started: its number. ChildError, in words, when it runs already or cannot be started."""
        global _hooked
        with self._lock:
            if self._look():
                raise ChildError(f"{self.name} runs already (pid {self._pid})")
            held = proc.holder(self.pidfile)
            if held is not None:
                raise ChildError(f"{self.name} runs already (pid {held}): an earlier run of this program started it "
                                 "and it is still there")
            if not self.launch.argv:
                raise ChildError(f"{self.name} has no command to start")
            hide = _secrets(self.launch)
            out = _Log(self.log, LOG_MAX, hide=hide)
            try:
                self.pidfile.parent.mkdir(parents=True, exist_ok=True)
                out.open()
            except OSError as e:
                raise ChildError(f"{self.name} could not start: its log {self.log} cannot be written ({e})") from None
            starter = self._popen or subprocess.Popen
            if self.system == "windows" and _real(starter):
                _hear_ctrl_c()  # before it is started: it inherits whether Ctrl+C is ignored
            try:
                process = starter(
                    list(self.launch.argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    bufsize=0, env=environment(self.launch, system=self.system), cwd=self.launch.cwd or None,
                    **_flags(self.system))
            except (OSError, ValueError, TypeError) as e:  # (ValueError: a NUL in a word or a variable)
                out.close()
                why = f"{self.name} could not start ({program(self.launch.argv[0])}): {e}"
                raise ChildError(masked(why, hide)) from None
            self._process, self._pid, self._over, self.adopted, self.note = process, process.pid, False, False, ""
            self._since = time.time()
            self._job = _held(process) if self.system == "windows" else None
            stamp = datetime.now().isoformat(timespec="seconds")
            words = keep.words([masked(word, hide) for word in self.launch.argv])  # hidden, then quoted
            out.write(f"{stamp} liminal: {self.name} started (pid {process.pid}): {words}\n".encode("utf-8", "replace"))
            if self.system == "windows" and self._job is None:
                out.write(f"{stamp} liminal: it could not be held in a job: what it starts is not ended with it\n"
                          .encode("utf-8"))
            self._note(process.pid)
            self._reader = threading.Thread(target=self._pump, args=(process, out), daemon=True,
                                            name=f"child-{self.name}")
            self._gone = threading.Event()
            self._watcher = threading.Thread(target=self._watch, args=(process, self._reader, self._gone), daemon=True,
                                             name=f"child-end-{self.name}")
            self._reader.start()
            self._watcher.start()
        with _all_lock:
            if self not in _all:
                _all.append(self)
            if not _hooked:
                atexit.register(stop_all)
                _hooked = True
        return process.pid

    @classmethod
    def adopt(cls, name: str, log: Path, pidfile: Path, *, interrupt=None, clock: Callable[[], float] = time.monotonic,
              sleep: Callable[[float], None] = time.sleep, system: str | None = None) -> "Child | None":
        """The child a pidfile names, when it is alive and is still the process that was written there (proc.holder):
        one an earlier run of this program started and left running. It can be asked whether it is alive, what it
        owns and for its log, and it can be stopped; its exit code is not this process's to read. None when the
        pidfile names nothing alive. A child this process started itself is given back as it is, never a second.
        Its `note`: `adopted_words` when the program that started it, and read what it prints, has ended (a
        platform ended by force); "" while that program still reads it (a boot instance's `launch serve`), or where
        the pidfile does not say which program that was."""
        pidfile = Path(pidfile)
        pid = proc.holder(pidfile)
        if pid is None or pid == os.getpid():
            return None
        with _all_lock:
            for mine in _all:
                if mine._pid == pid and not mine._over:
                    return mine
        child = cls(name, Launch(()), log, pidfile, interrupt=interrupt, clock=clock, sleep=sleep, system=system)
        child.adopted, child._pid, child._over = True, pid, False
        child.note = adopted_words(child.system) if _owner_gone(pidfile) else ""
        try:
            child._since = pidfile.stat().st_mtime  # the pidfile was written when it started
        except OSError:
            pass
        return child

    def _note(self, pid: int) -> None:
        """The pidfile: "<pid> <when it started> <this process's pid> <when this one started>", written whole.
        proc.holder reads the child back by the first two; `adopt` reads by the last two whether the run that reads
        what it prints is still there."""
        try:
            part = self.pidfile.with_name(self.pidfile.name + ".part")
            part.write_text(f"{pid} {proc.started(pid) or 0} {proc.stamp()}", encoding="ascii")  # (stamp: this one's)
            os.replace(part, self.pidfile)
        except OSError:
            pass  # not written: it runs all the same, and a later run will not find it again

    def _pump(self, process, out: _Log) -> None:
        """The reader's thread: what the child prints appended to its log until its output ends (with the child, or
        with the last program it started that held it open), then the log closed."""
        try:
            for chunk in _chunks(process.stdout):
                out.write(chunk)
        finally:
            out.close()

    def _watch(self, process, reader: threading.Thread | None, gone: threading.Event) -> None:
        """The watcher's thread: the child's end waited for apart from its output, which a program it started may
        hold open after it (a model server a router started), and said to `wait` (`gone`). Once it has ended and its
        output has been read to the end (LEFT_S at most), it is cleaned up after (`_look`): on Windows its job is
        closed, which ends what it left running; on Linux its group is ended while its number is still its own."""
        try:
            if _uncollected(process, self.system):
                _peek(process.pid, True)  # its end waited for and left for `_poll` to collect
            else:
                process.wait()
        except Exception:  # noqa: BLE001 - a wait that fails is a look that comes later
            return
        finally:
            gone.set()  # (`wait` woken at its end; or, where this wait failed, to look for it itself)
        if reader is not None:
            reader.join(LEFT_S)
        with self._lock:
            if self._process is process:
                self._look()

    # -- what it is ------------------------------------------------------------------------------------------------
    def _poll(self) -> int | None:
        """Its exit code, None while it runs (asked with the lock held). A real child on Linux is seen ended before
        it is collected: while its number is still its own, what it left behind in its group is ended with it."""
        process = self._process
        if process is None:
            return None
        if not _uncollected(process, self.system):
            return process.poll()
        if process.returncode is None:
            state = _peek(process.pid, False)
            if not state:
                return None
            if state == "ended":
                _signal_group(process.pid, KILL)
            process.wait()
        return process.returncode

    def _look(self) -> bool:
        """Whether it runs now; its end, seen here for the first time, is cleaned up after."""
        with self._lock:
            if self._over:
                return False
            if self._process is not None:
                running = self._poll() is None
            else:
                running = proc.holder(self.pidfile) == self._pid
            if not running:
                self._ended()
            return running

    def _ended(self) -> None:
        """Its end: its job is closed, which ends what it still holds (Windows: what the child started and left
        running), its pidfile is removed when it still names it, and it is no longer one of this process's running
        children."""
        with self._lock:
            if self._over:
                return
            self._over = True
            job, self._job = self._job, None
            if job is not None:
                _close_job(job)
            try:
                if self.pidfile.read_text().split()[:1] == [str(self._pid)]:
                    self.pidfile.unlink()
            except (OSError, ValueError):
                pass
        with _all_lock:
            if self in _all:
                _all.remove(self)

    @property
    def pid(self) -> int | None:
        """The running child's number; None when none runs."""
        return self._pid if self._look() else None

    @property
    def alive(self) -> bool:
        return self._look()

    @property
    def code(self) -> int | None:
        """Its exit code once it has ended; None while it runs, before it was started, and for an adopted child."""
        with self._lock:
            if self._process is None:
                return None
            self._look()
            return self._poll()

    @property
    def since(self) -> float | None:
        """When it was last started, in seconds since the epoch; None when it never was."""
        return self._since

    def owns(self, pid: int) -> bool:
        """Whether a process is this child or one it started: the child's own number; on Windows a process held in
        its job (an adopted child has no job here: its own number alone); on Linux a process of the session it
        leads."""
        with self._lock:
            mine, process = self._pid, self._process
            if mine is None or not self._look():
                return False
            if pid == mine:
                return True
            if self.system == "windows":
                return self._job is not None and _in_job(self._job, pid)
        if process is not None and not isinstance(process, _Popen):
            return False  # a stand-in: no number is asked of the system for it
        return _session_of(pid) == mine

    def tail(self, lines: int = 40) -> list[str]:
        """Its log's last lines (`last_lines`)."""
        return last_lines(self.log, lines)

    # -- ending ----------------------------------------------------------------------------------------------------
    def wait(self, timeout: float | None = None) -> int | None:
        """Until it has ended, `timeout` seconds at most on its own clock (None: however long it runs): its exit code;
        None when it still runs, or when its code is not this process's to read (an adopted child). A real child this
        process started is waited for through its watcher, which wakes at its end alone (a boot server's `launch
        serve` waits so for days), until its clock says the time is over: where a coarse clock says so only after the
        watcher's wait (time.monotonic on Windows before Python 3.13 moves by 15.6 ms), the rest is the watcher's too,
        and nothing else is looked at meanwhile; any other is looked at every STEP_S, on its own clock."""
        if timeout is None:
            while self._look():
                self._rest(None)
            return self.code
        with self._lock:
            process, gone = self._process, self._gone
        if isinstance(process, _Popen) and gone is not None:
            until = self._clock() + max(0.0, timeout)
            left = max(0.0, timeout)
            while not gone.wait(min(left, threading.TIMEOUT_MAX)):
                left = until - self._clock()
                if left <= 0:
                    return self.code  # its watcher has not woken: it runs (an end just now is seen by this look)
            timeout = until - self._clock()  # (what is left once it was woken: its end is looked for in that)
        self._gone_within(timeout)
        return self.code

    def stop(self, grace: float = GRACE_S) -> str:
        """It is asked to end (Ctrl+C on Windows, SIGTERM to its group on Linux) and given `grace` seconds; then it
        is ended, with what it started where that is held with it (its job on Windows, its group on Linux). How it
        went, in words: whether the asking was sent is known, not whether it was heard. A child that does not run is
        left alone: a second call does nothing. ChildError when it cannot be ended."""
        with self._stopping:
            if not self._look():
                return self._was_over()
            how = "Ctrl+C" if self.system == "windows" else "SIGTERM"
            pid, began = self._pid, self._clock()
            asked = self._ask()
            if asked and self._gone_within(grace):
                return f"ended when asked ({how}), after {max(0.0, self._clock() - began):.1f} s"
            whole = self._end()
            if not self._gone_within(END_S):
                raise ChildError(f"{self.name} could not be ended: it still runs (pid {pid})")
            first = f"did not end within {grace:g} s after {how} was sent" if asked else f"{how} could not reach it"
            return f"{first}: " + ("ended with what it started" if whole else
                                   "ended; what it started is not held with it and may still run")

    def _was_over(self) -> str:
        if self._pid is None:
            return "was not started"
        code = getattr(self._process, "returncode", None)
        return "had ended already" + (f" (exit code {code})" if code is not None else "")

    def _ask(self) -> bool:
        """Asked to end by itself: whether the asking reached it."""
        if self.system != "windows":
            return self._signal(TERM)
        process, pid = self._process, self._pid
        if self._interrupt is not None:
            return bool(self._interrupt(pid))
        if process is None:  # adopted: by its number, while its pidfile still names it
            return proc.holder(self.pidfile) == pid and interrupt(pid)
        return isinstance(process, _Popen) and interrupt(pid)  # (a stand-in's number is asked of nothing)

    def _signal(self, sig: int) -> bool:
        """A signal to it and what it started (Linux): to the group it leads; whether it was sent."""
        with self._lock:
            if self._over:
                return False
            process, pid = self._process, self._pid
            if process is None:  # adopted: by its number, while its pidfile still names it
                if proc.holder(self.pidfile) != pid:
                    return False
                return _signal_group(pid, sig) if _leads(pid) else _signal_one(pid, sig)
            if not isinstance(process, _Popen):  # a stand-in: told through its own methods alone
                (process.kill if sig == KILL else process.terminate)()
                return True
            return process.returncode is None and _signal_group(process.pid, sig)  # not collected: still its own

    def _end(self) -> bool:
        """Ended now: whether what it started is ended with it."""
        if self.system != "windows":
            whole = self._process is not None or _leads(self._pid)
            self._signal(KILL)
            return whole
        with self._lock:
            process, pid = self._process, self._pid
            if self._job is not None and _end_job(self._job):
                return True
        if process is None:  # adopted: the one process, by its number, while its pidfile still names it
            if proc.holder(self.pidfile) == pid:
                proc.terminate(pid)
            return False
        try:
            process.kill()
        except OSError:
            pass
        return False

    def _gone_within(self, seconds: float) -> bool:
        """Whether it has ended, waited for `seconds` at most on the child's clock."""
        until = self._clock() + max(0.0, seconds)
        while self._look():
            left = until - self._clock()
            if left <= 0:
                return False
            self._rest(min(left, STEP_S))
        return True

    def _rest(self, seconds: float | None) -> None:
        """A wait for its end, `seconds` at most (None: as long as one wait may take), that does not collect it."""
        process = self._process
        if process is not None and isinstance(process, _Popen):
            if self.system == "windows":
                try:
                    process.wait(timeout=WAIT_S if seconds is None else seconds)
                except subprocess.TimeoutExpired:
                    pass
                return
            if seconds is None and _PEEKS:
                _peek(process.pid, True)
                return
        self._sleep(STEP_S if seconds is None else seconds)


def stop_these(children: Iterable[Child], grace: float = GRACE_S) -> list[str]:
    """Several children stopped side by side, so that together they take one grace and not one each: what each
    `stop` said (or why it could not be ended), in their order. While this process is ending a thread may not be
    startable: a child it cannot be started for is stopped in this thread, one after another."""
    kids = list(children)
    words: list[str] = [""] * len(kids)

    def one(i: int) -> None:
        try:
            words[i] = kids[i].stop(grace)
        except Exception as e:  # noqa: BLE001 - one that cannot be ended does not keep the others running
            words[i] = str(e)

    threads: list[threading.Thread] = []
    for i in range(1, len(kids)):
        thread = threading.Thread(target=one, args=(i,), daemon=True, name=f"child-stop-{kids[i].name}")
        try:
            thread.start()
        except RuntimeError:  # the interpreter is ending
            one(i)
        else:
            threads.append(thread)
    if kids:
        one(0)
    for thread in threads:
        thread.join()
    return words


def stop_all(grace: float = GRACE_S) -> None:
    """Every child this process started that still runs, stopped side by side; it bears being called again.

    It is registered with atexit at the first start, so it runs when this process ends by itself: its main returns,
    sys.exit, an error nobody caught, Ctrl+C in its console (KeyboardInterrupt). It does not run when the process is
    ended from outside, by a signal Python does not handle (SIGTERM and SIGHUP, by default: a `kill`, a closed
    terminal tab) or by force (SIGKILL, TerminateProcess). On Windows the children's job objects end them with this
    process all the same; on Linux nothing does, unless the program that runs this module turns SIGTERM and SIGHUP
    into an ordinary end in its main thread (the platform's `serve` does, from 0.31.0), and a child left so runs on
    until a later run adopts it by its pidfile (`Child.adopt`) and stops it, or it ends at its next line of output
    (`adopted_words`)."""
    with _all_lock:
        kids = list(_all)
    stop_these(kids, grace)


# -- a child spoken to through pipes -----------------------------------------------------------------------------------
LINE_MAX = 4 * 1024 * 1024  # bytes: a line a piped child prints is this long at most (4 MiB); a longer one ends it
TERM_S = 2.0  # what a piped child is given after SIGTERM, before SIGKILL (Linux), once its grace is over
SEND_WAIT_S = 1.0  # what a stop waits for a line being sent: a child that does not read its input is not waited for


def _close(pipe) -> None:
    """A pipe of ours closed; one that is closed already, or cannot be, is left as it is."""
    try:
        if pipe is not None:
            pipe.close()
    except (AttributeError, OSError, ValueError):
        pass


def _written(pipe, data: bytes) -> None:
    """All of `data` written to a pipe, however many writes that takes (OSError when it takes none)."""
    view = memoryview(data)
    while view:
        done = pipe.write(view)
        if not done:
            raise OSError("the pipe took nothing")
        view = view[done:]
    flush = getattr(pipe, "flush", None)
    if callable(flush):
        flush()


def _copied(pipe, out: _Log, lock) -> None:
    """A piped child's error output appended to its log until it ends; then the log is closed, and the pipe."""
    try:
        for chunk in _chunks(pipe):
            with lock:
                out.write(chunk)
    finally:
        with lock:
            out.close()
        _close(pipe)


class _Both:
    """Threads waited for as one, within one timeout: what a piped child's watcher waits for before it cleans up (its
    errors copied, its lines read)."""

    def __init__(self, *threads: threading.Thread):
        self.threads = threads

    def join(self, timeout: float | None = None) -> None:
        until = None if timeout is None else time.monotonic() + max(0.0, timeout)
        for thread in self.threads:
            thread.join(None if until is None else max(0.0, until - time.monotonic()))


class Piped(Child):
    """A child its plugin talks to through pipes: an MCP server over stdio. Each message is one line.

    It is started as a Child is: windowless, in a job object on Windows and in a session of its own on Linux, with
    its pidfile written. Its standard input, output and errors are pipes. What it prints as errors goes into its log
    (LOG_MAX, moved aside past it, its secrets masked). `send(line)` writes one line to it. A thread reads what it
    prints and hands each line to `line(text)`, without its line end; a blank line is left out. A line longer than
    LINE_MAX bytes ends it, and so does a `line` that fails: what it prints after that is read and dropped. Once its
    output has ended, `ended(why)` is told once: "" when it just ended, else why it was ended (`why` says it too).

    `stop(grace)` follows MCP's stdio transport (2026-07-28): its input is closed, and it gets `grace` seconds to end
    by itself. Then it is ended with what it started: its job on Windows; SIGTERM, then SIGKILL after TERM_S, to its
    group on Linux. `stop_all` stops it at exit with every other child.

    Its pidfile works as a Child's. One an earlier run left running (a platform ended by force on Linux) is ended at
    the next `start`, before the new one starts; `adopt` gives it too, to be stopped. An adopted one has no pipes:
    it is ended as the second half of a stop."""

    def __init__(self, name: str, launch: Launch, log: Path, pidfile: Path, *,
                 line: Callable[[str], None] | None = None, ended: Callable[[str], None] | None = None, popen=None,
                 interrupt=None, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep, system: str | None = None):
        super().__init__(name, launch, log, pidfile, popen=popen, interrupt=interrupt, clock=clock, sleep=sleep,
                         system=system)
        self._on_line = line
        self._on_end = ended
        self._sending = threading.Lock()  # one line written at a time; a stop closes the input only between two
        self._log_lock = threading.Lock()  # its log is written by its errors' thread and by its notes
        self._input = None  # its standard input, while it is open
        self._out: _Log | None = None  # its log, while it runs
        self._hearer: threading.Thread | None = None  # reads what it prints, line by line
        self.why = ""  # why this module ended it ("": it was not; it ended by itself, or was stopped)

    # -- starting --------------------------------------------------------------------------------------------------
    def start(self) -> int:
        """It is started, its three pipes open: its number. One an earlier run left running is ended first.
        ChildError, in words, when it runs already, or it cannot be started, or that earlier one cannot be ended."""
        global _hooked
        earlier = self._earlier()  # (outside the lock: ending it may take its grace)
        with self._lock:
            if self._look():
                raise ChildError(f"{self.name} runs already (pid {self._pid})")
            held = proc.holder(self.pidfile)
            if held is not None:
                raise ChildError(f"{self.name} runs already (pid {held})")
            if not self.launch.argv:
                raise ChildError(f"{self.name} has no command to start")
            hide = _secrets(self.launch)
            out = _Log(self.log, LOG_MAX, hide=hide)
            try:
                self.pidfile.parent.mkdir(parents=True, exist_ok=True)
                out.open()
            except OSError as e:
                raise ChildError(f"{self.name} could not start: its log {self.log} cannot be written ({e})") from None
            starter = self._popen or subprocess.Popen
            try:
                process = starter(
                    list(self.launch.argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    bufsize=0, env=environment(self.launch, system=self.system), cwd=self.launch.cwd or None,
                    **_flags(self.system))
            except (OSError, ValueError, TypeError) as e:  # (ValueError: a NUL in a word or a variable)
                out.close()
                why = f"{self.name} could not start ({program(self.launch.argv[0])}): {e}"
                raise ChildError(masked(why, hide)) from None
            self._process, self._pid, self._over, self.adopted, self.note = process, process.pid, False, False, ""
            self._input, self._out, self.why = process.stdin, out, ""
            self._since = time.time()
            self._job = _held(process) if self.system == "windows" else None
            stamp = datetime.now().isoformat(timespec="seconds")
            if earlier:
                out.write(f"{stamp} liminal: {earlier}\n".encode("utf-8", "replace"))
            words = keep.words([masked(word, hide) for word in self.launch.argv])  # hidden, then quoted
            out.write(f"{stamp} liminal: {self.name} started (pid {process.pid}), its input and output piped: "
                      f"{words}\n".encode("utf-8", "replace"))
            if self.system == "windows" and self._job is None:
                out.write(f"{stamp} liminal: it could not be held in a job: what it starts is not ended with it\n"
                          .encode("utf-8"))
            self._note(process.pid)
            self._reader = threading.Thread(target=_copied, args=(process.stderr, out, self._log_lock), daemon=True,
                                            name=f"child-{self.name}")
            self._hearer = threading.Thread(target=self._hear, args=(process.stdout,), daemon=True,
                                            name=f"child-out-{self.name}")
            self._gone = threading.Event()
            self._watcher = threading.Thread(target=self._watch, args=(process, _Both(self._reader, self._hearer),
                                                                       self._gone),
                                             daemon=True, name=f"child-end-{self.name}")
            self._reader.start()
            self._hearer.start()
            self._watcher.start()
        with _all_lock:
            if self not in _all:
                _all.append(self)
            if not _hooked:
                atexit.register(stop_all)
                _hooked = True
        return process.pid

    def _earlier(self) -> str:
        """The child an earlier run left running, by its pidfile, ended: what is said of it ("": there is none).
        ChildError when it is one this process runs, or when it cannot be ended."""
        pid = proc.holder(self.pidfile)
        if pid is None:
            return ""
        with _all_lock:
            if any(mine._pid == pid and not mine._over for mine in _all):
                raise ChildError(f"{self.name} runs already (pid {pid})")
        earlier = type(self).adopt(self.name, self.log, self.pidfile, clock=self._clock, sleep=self._sleep,
                                   system=self.system)
        if earlier is None:  # gone meanwhile (or it names this very process: refused as running, below)
            return ""
        try:
            said = earlier.stop()
        except ChildError:
            raise ChildError(f"{self.name} could not start: an earlier run's (pid {pid}) still runs and could not be "
                             "ended") from None
        return f"{self.name} of an earlier run (pid {pid}) was ended first: {said}"

    # -- talking ---------------------------------------------------------------------------------------------------
    def send(self, line) -> None:
        """One message written to its standard input as one line, a line feed added: `line` is text (sent as UTF-8)
        or bytes, without a line break. ValueError for a line break. ChildError in words when it does not run, or
        its input is closed or broken. A child that does not read its input holds the send up until it does, or
        until it is ended."""
        data = line.encode("utf-8") if isinstance(line, str) else bytes(line)
        if b"\n" in data or b"\r" in data:
            raise ValueError(f"a line sent to {self.name} holds no line break: each message is one line")
        with self._sending:
            pipe, running = self._input, self._look()
            if pipe is None or not running:
                if pipe is not None:  # it has ended: its input goes too
                    self._input = None
                    _close(pipe)
                if not running:
                    raise ChildError(f"{self.name} does not run: nothing was sent to it")
                raise ChildError(f"{self.name}'s input is closed: nothing was sent to it"
                                 + (" (an earlier run started it)" if self.adopted else ""))
            try:
                _written(pipe, data + b"\n")
            except (OSError, ValueError) as e:
                raise ChildError(f"{self.name} did not take the line: its input is closed ({e})") from None

    def _close_input(self, wait: float) -> bool:
        """Its standard input closed, so that it reads its end: whether it is closed now (or was already). A send under
        way is waited for `wait` seconds at most. Past that it is left open: closing a pipe that a write still waits
        on would wait as long as the write (Windows), and a child that does not read its input will not end at its
        end anyway."""
        if not self._sending.acquire(timeout=max(0.0, wait)):
            return False
        try:
            pipe, self._input = self._input, None
        finally:
            self._sending.release()
        _close(pipe)
        return True

    def _hear(self, pipe) -> None:
        """The reader's thread: what it prints cut into lines and handed to `line`, until its output ends. A line
        longer than LINE_MAX, or one `line` cannot take, ends the child; what it prints after that is read and
        dropped. At the end: the pipe closed, its input closed (unless a send is under way), and `ended` told."""
        held = bytearray()
        why = ""
        try:
            for chunk in _chunks(pipe):
                if why:
                    continue  # it is being ended: what it still prints is dropped
                *whole, rest = chunk.split(b"\n")
                for part in whole:
                    held += part
                    why = self._give(bytes(held))
                    held.clear()
                    if why:
                        break
                if not why:
                    held += rest
                    if len(held) > LINE_MAX:
                        why = _too_long()
                if why:
                    held.clear()
                    self._cut(why)
            if held and not why:  # its last line, not ended by a line feed
                why = self._give(bytes(held))
                if why:
                    self._cut(why)
        finally:
            _close(pipe)
            self._close_input(0.0)
            told = self._on_end
            if told is not None:
                try:
                    told(why)
                except Exception:  # noqa: BLE001 - its plugin's own fault: the child has ended all the same
                    pass

    def _give(self, data: bytes) -> str:
        """One line handed to `line`, its line end taken off and read as UTF-8 (what is not, replaced): "" when it was,
        or left out (a blank line; no `line` given), else why it cannot be."""
        if data.endswith(b"\r"):
            data = data[:-1]
        if len(data) > LINE_MAX:
            return _too_long()
        text = data.decode("utf-8", "replace")
        if not text.strip() or self._on_line is None:
            return ""
        try:
            self._on_line(text)
        except Exception as e:  # noqa: BLE001 - a line its plugin cannot take ends the talk
            return f"its line could not be taken ({_word(f'{type(e).__name__}: {e}')})"
        return ""

    def _cut(self, why: str) -> None:
        """Ended now, for `why`: said in its log, its input closed (unless a send is under way), and it is ended with
        what it started at once (its job, or SIGKILL to its group). Its watcher cleans up after it."""
        self.why = why
        self._say(f"{self.name} was ended: {why}")
        self._close_input(0.0)
        try:
            self._end()
        except Exception:  # noqa: BLE001 - one that cannot be ended now is ended by its stop
            pass

    def _say(self, words: str) -> None:
        """A line of this module's own in its log, while it is open."""
        out = self._out
        if out is None:
            return
        stamp = datetime.now().isoformat(timespec="seconds")
        with self._log_lock:
            out.write(f"{stamp} liminal: {words}\n".encode("utf-8", "replace"))

    # -- ending ----------------------------------------------------------------------------------------------------
    def stop(self, grace: float = GRACE_S) -> str:
        """It is stopped as MCP's stdio transport says: its input is closed, and it gets `grace` seconds to end by
        itself. Then it is ended with what it started: its job on Windows; on Linux SIGTERM to its group, and SIGKILL
        after TERM_S. How it went, in words. When a line it does not read is still being sent, its input cannot be
        closed, and it is ended without the grace. One that does not run is left alone: a second call does nothing.
        ChildError when it cannot be ended."""
        with self._stopping:
            if not self._look():
                return self._was_over()
            pid, began = self._pid, self._clock()
            if self._process is None:  # adopted: its input is not this process's to close
                return self._finish(pid, "")
            if not self._close_input(SEND_WAIT_S):
                return self._finish(pid, "its input could not be closed (a line it does not read was being sent)")
            if self._gone_within(grace):
                return f"ended when its input was closed, after {max(0.0, self._clock() - began):.1f} s"
            return self._finish(pid, f"did not end within {grace:g} s after its input was closed")

    def _finish(self, pid: int | None, first: str) -> str:
        """The second half of a stop: on Linux SIGTERM, TERM_S, then SIGKILL; on Windows ended at once. `first`: what
        came before, in words ("": nothing, as for an adopted child)."""
        if self.system != "windows":
            if self._signal(TERM) and self._gone_within(TERM_S):
                ended = "ended by SIGTERM, with what it started" if self._process is not None else "ended by SIGTERM"
                return f"{first}: {ended}" if first else ended
            first = f"{first}, nor within {TERM_S:g} s after SIGTERM" if first else (
                f"did not end within {TERM_S:g} s after SIGTERM")
        whole = self._end()
        if not self._gone_within(END_S):
            raise ChildError(f"{self.name} could not be ended: it still runs (pid {pid})")
        ended = ("ended with what it started" if whole else
                 "ended; what it started is not held with it and may still run")
        return f"{first}: {ended}" if first else ended


def _too_long() -> str:
    return f"it printed a line longer than {LINE_MAX:,} bytes"


# -- a command's lines -------------------------------------------------------------------------------------------------
def _asked(cancel) -> bool:
    try:
        return bool(cancel())
    except Exception:  # noqa: BLE001 - a cancel that cannot be asked is not a cancel
        return False


def stream(argv, line: Callable[[str], None], *, env: Mapping[str, str] | None = None, cwd=None,
           timeout: float = 1800.0, cancel: Callable[[], bool] | None = None, popen=None,
           system: str | None = None) -> int:
    """`argv` run to its end without a window and with no standard input (an installer's command: uv, npm, hf), each
    line it prints, its errors among them, cut at LINE_CHARS and given to `line` as it comes: its exit code. `env` is
    its whole environment; None: this process's without Liminal's own variables (LIMINAL_*), a net only, since a
    plugin gives `environment(...)` of a launch whose `drop` names every pair of every plugin (its base's
    `dropped()`). Running past `timeout` seconds it is ended with what it started (ChildError); once `cancel()` is
    true, likewise (Cancelled); the words say when what it started could not be ended with it (Windows without a job
    object). What it left running ends with it. Its timeout and its cancel hold until its output has ended, which
    a program it started may keep open after it: once it was ended, its output is given LEFT_S more, then given up
    and that is said (ChildError, or Cancelled when it was cancelled), since what holds it is out of reach (a daemon
    that left its group) and may still run. Its output is read by a thread of its own, its lines handed on here.
    `popen` and `system` stand in for subprocess.Popen and for this system."""
    args = [str(a) for a in argv]
    if not args:
        raise ChildError("there is no command to run")
    system = system or this_system()
    if env is None:
        env = environment(Launch(tuple(args), drop=LIMINAL), system=system)
    try:
        process = (popen or subprocess.Popen)(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
            env={str(k): str(v) for k, v in env.items()}, cwd=str(cwd) if cwd else None, **_flags(system))
    except (OSError, ValueError, TypeError) as e:  # (ValueError: a NUL in a word or a variable)
        raise ChildError(f"{program(args[0])} could not run: {e}") from None
    job = _held(process) if system == "windows" else None
    grouped = isinstance(process, _Popen) and system != "windows"  # a real one on Linux: told by its group's number
    pieces: queue.Queue = queue.Queue(QUEUED)  # what it prints, read ahead of its lines; None: its output has ended
    given_up = threading.Event()  # its output is read no more: what still comes is dropped as it comes

    def read() -> None:  # the reader's thread: its output into `pieces`, and nothing else of it is told anything
        try:
            for chunk in _chunks(process.stdout):
                if not given_up.is_set():
                    pieces.put(chunk)
        finally:
            pieces.put(None)

    def has_ended() -> bool:  # asked without collecting it
        if grouped:
            return _PEEKS and bool(_peek(process.pid, False))
        return process.poll() is not None

    def end() -> bool:  # ended now, in this thread alone (so never once it is collected): whether with what it started
        if grouped:
            if process.returncode is None:
                _signal_group(process.pid, KILL)
            return True
        if job is not None and _end_job(job):
            return True
        try:
            process.kill()
        except OSError:
            pass
        return False

    threading.Thread(target=read, daemon=True, name="child-stream").start()
    lines = _Lines(line)
    until = time.monotonic() + max(0.0, timeout)
    ended_at = None  # when its end was first seen while its output was still open
    cut_at = None  # when it was ended: its output and its end are given LEFT_S more from then
    reason = ""  # why it was ended: "cancelled" or "timeout" ("": it was not, or for its output held open)
    whole = True  # once it was ended: whether what it started was ended with it
    reading = True  # its output has not ended
    left = False  # its output was given up: something it started that was not ended with it holds it open
    try:
        while True:
            if reading:
                try:
                    chunk = pieces.get(timeout=WATCH_S)
                except queue.Empty:
                    chunk = b""
                if chunk is None:
                    reading = False
                    lines.end()
                elif chunk:
                    lines.feed(chunk)
            if not reading and has_ended():
                break
            now = time.monotonic()
            if cut_at is None:
                reason = ("cancelled" if cancel is not None and _asked(cancel) else
                          "timeout" if now >= until else "")
                if not reason and reading and has_ended():  # it has ended, and something it started holds its output
                    ended_at = now if ended_at is None else ended_at
                    if now - ended_at < LEFT_S:
                        continue
                elif not reason:
                    if not reading:
                        time.sleep(WATCH_S)  # its output has ended, it has not: its end waited for
                    continue
                whole = end()
                cut_at = now
                continue
            if reason != "cancelled" and cancel is not None and _asked(cancel):
                reason = "cancelled"  # (ended already: a cancel meanwhile is what its words say)
            if now - cut_at >= LEFT_S:
                left = reading
                if left:
                    lines.end()
                break
            if not reading:
                time.sleep(WATCH_S)
    finally:
        given_up.set()
        while True:  # (what was read ahead is let go: a reader waiting to hand on more goes on and drops it)
            try:
                pieces.get_nowait()
            except queue.Empty:
                break
        if grouped:
            if process.returncode is None:  # not collected: its group is still told by its number
                _signal_group(process.pid, KILL)  # it (when its reading failed) and what it left running
        elif job is not None:
            _end_job(job)
        elif process.poll() is None:
            process.kill()
        code = process.wait()
        if job is not None:
            _close_job(job)
    if left:
        ended = "ended; something it started still holds its output and may still run"
    else:
        ended = ("ended with what it started" if whole else
                 "ended; what it started is not held with it and may still run")
    if reason == "cancelled":
        raise Cancelled(f"{said(args)} was cancelled: {ended}")
    if reason == "timeout":
        raise ChildError(f"{said(args)} took more than {timeout:g} s: {ended}")
    if left:
        raise ChildError(f"{said(args)} ended (exit code {code}), but something it started still holds its output and "
                         "may still run")
    return code
