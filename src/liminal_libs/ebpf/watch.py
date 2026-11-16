"""Watching events with eBPF while a tab is being asked (the user, 2026-11-14: "the filter allows (uses ebpf)
tracking one off connections"; "trapdoor will monitor all processes ... networking done"). A `Watch` holds a
bounded ring of recent `Event`s; a caller reads what is new since a sequence number, and the watch stops itself a
short while after the last read, and on `stop()`, so nothing runs while unused (the design: "every watcher stops
itself after its viewing timeout and on the plugin's detach; no threads are left behind").

Two backends sit behind the one base. On Linux, `BpftraceWatch` runs bpftrace with the scripts in `scripts/` and
streams its JSON lines into events. On Windows, `make_watch` imports `NpcapEtwWatch` lazily (another module writes
it): on this PC the eBPF for Windows runtime is test-signed and cannot load, so Windows captures with Npcap and ETW
behind the same `Watch` interface. The kinds a watch covers are a subset of {"net", "process", "file", "registry"};
Linux has no registry.

The Linux scripts are low-rate by construction, so a burst of one kind cannot push the others out of the ring:
  - net: TCP prints one line per connection change, never per packet; UDP one line per socket and peer a minute,
    at most 50 a second;
  - file: only the target's process tree when `spec["pid"]` names one (bpftrace's $1), else every process; either
    way a program's path once a minute for each way it is opened, at most 50 lines a second;
  - process: exec, and exit for a process (not for each of its threads).
What a budget held back comes as one "skipped" event a second, with `extra["count"]`. What bpftrace itself dropped
is counted in `Watch.lost`. A TCP event whose pid and program are only the task that happened to be on the CPU
carries `extra["approx"] = True`. Each script line is one JSON object of known keys (`_SHAPES`); a line with any
other key, or with a key twice, is dropped, since a path or a program name is text another user chooses."""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
KINDS = ("net", "process", "file", "registry")
SCRIPTS = {"net": "net.bt", "process": "process.bt", "file": "file.bt"}  # registry is Windows-only (ETW)
DEFAULT_TIMEOUT = 20.0
DEFAULT_RING = 2000
STOP_GRACE = 2.0           # seconds bpftrace has to end on SIGTERM, and again after a SIGKILL, before moving on
PID_MAX = 4194304          # the kernel's largest pid (PID_MAX_LIMIT on 64-bit)
NOTES = 5                  # the last lines of bpftrace's or sudo's own words kept, to say why it ended
NOTE_CHARS = 300           # each cut to this many characters
CREATE_NO_WINDOW = 0x08000000


@dataclass
class Event:
    """One thing seen: a sequence number, when, its kind and action, and whatever of pid, parent, program, path,
    local and remote addresses, protocol and bytes the source gave. `extra` holds anything backend-specific (on
    Linux: the open "flags"; "count" on a "skipped" event; "approx" when the pid and program are not known to be
    the socket's owner)."""
    seq: int
    time: float
    kind: str
    action: str
    pid: int | None = None
    ppid: int | None = None
    program: str = ""
    path: str = ""
    local: str = ""
    remote: str = ""
    proto: str = ""
    bytes: int = 0
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"seq": self.seq, "time": self.time, "kind": self.kind, "action": self.action,
                "pid": self.pid, "ppid": self.ppid, "program": self.program, "path": self.path,
                "local": self.local, "remote": self.remote, "proto": self.proto, "bytes": self.bytes,
                "extra": self.extra}


class Watch:
    """The base: `start`, `read(since_seq) -> (seq, events)`, `stop`, a bounded ring and a self-stop after the
    viewing timeout. A subclass fills `_begin` (open the source) and `_end` (close it) and calls `_emit`. `lost`
    counts the events the source said it dropped (0 where a source never says)."""

    def __init__(self, kinds, spec: dict | None = None, *, timeout: float = DEFAULT_TIMEOUT,
                 ring: int = DEFAULT_RING, clock=time.monotonic):
        self.kinds = frozenset(k for k in kinds if k in KINDS)
        self.spec = dict(spec or {})
        self.timeout = float(timeout)
        self._ring: deque[Event] = deque(maxlen=max(1, int(ring)))
        self._seq = 0
        self._lock = threading.Lock()
        # start's _begin and stop's _end never overlap: a stop while a start is opening its source waits for it, so a
        # source opened (a bpftrace process, an ETW session) is always closed. Re-entrant, so a _begin may stop itself.
        self._life = threading.RLock()
        self._clock = clock
        self._last = clock()
        self._stop = threading.Event()
        self._started = False
        self._watchdog: threading.Thread | None = None
        self.error = ""
        self.lost = 0

    # -- lifecycle -------------------------------------------------------------------------------------------

    def start(self) -> None:
        """Open the source and begin watching; idempotent. The self-stop timer runs from here."""
        with self._life:
            with self._lock:
                if self._started or self._stop.is_set():
                    return
                self._started = True
                self._last = self._clock()
            self._begin()
            watchdog = threading.Thread(target=self._idle, name="ebpf-watch", daemon=True)
            watchdog.start()
            self._watchdog = watchdog  # set once running: a stop never joins a thread not yet started

    def read(self, since_seq: int = 0) -> tuple[int, list[Event]]:
        """The latest sequence number and the events newer than `since_seq`. A read also keeps the watch alive."""
        with self._lock:
            self._last = self._clock()
            events = [e for e in self._ring if e.seq > since_seq]
            return self._seq, events

    def touch(self) -> None:
        """Keep the watch alive without reading (the tab is still shown)."""
        with self._lock:
            self._last = self._clock()

    def stop(self) -> None:
        """Close the source and end the watch; idempotent, and safe to call from the self-stop thread itself. The
        flag is set under the lock so a stop and a self-stop at once still end the source only once."""
        with self._lock:
            if self._stop.is_set():
                return
            self._stop.set()
        with self._life:  # a start still opening its source finishes first, then its source is closed here
            try:
                self._end()
            finally:
                wd = self._watchdog
                if wd is not None and wd is not threading.current_thread() and wd.is_alive():
                    wd.join(timeout=2.0)

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    # -- for subclasses --------------------------------------------------------------------------------------

    def _begin(self) -> None:
        """Open the source (spawn the reader). Overridden by a backend."""

    def _end(self) -> None:
        """Close the source (kill the process). Overridden by a backend."""

    def _emit(self, kind: str, action: str, **fields) -> None:
        """Add one event to the ring, numbered in order."""
        with self._lock:
            self._seq += 1
            self._ring.append(Event(self._seq, self._clock(), kind, action, **fields))

    # -- self-stop -------------------------------------------------------------------------------------------

    def _idle(self) -> None:
        """Stop the watch once it has gone `timeout` seconds without a read or touch. One daemon thread, which
        exits the moment the watch is stopped from anywhere."""
        while not self._stop.is_set():
            with self._lock:
                idle = self._clock() - self._last
            remaining = self.timeout - idle
            if remaining <= 0:
                self.stop()
                return
            self._stop.wait(min(remaining, 1.0))


# -- the Linux backend: bpftrace ----------------------------------------------------------------------------

class BpftraceWatch(Watch):
    """`sudo -n bpftrace -f json -e <script> [target]`, its JSON lines streamed into events, the process ended and
    reaped on stop. `spec["pid"]` names the process whose file opens are followed (with the children it forks
    while watched); it reaches the script as $1, and without it every process's opens are seen, budgeted.
    `runner(argv) -> process` stands in for spawning bpftrace in tests; the process has an iterable `.stdout` of
    lines (str or bytes) and a `.kill()`, and a real one also `.terminate()` and `.wait(timeout)`. `scripts_dir`
    overrides where the `.bt` scripts are read from."""

    system = "linux"

    def __init__(self, kinds, spec: dict | None = None, *, runner=None, scripts_dir=None,
                 timeout: float = DEFAULT_TIMEOUT, ring: int = DEFAULT_RING, clock=time.monotonic):
        super().__init__(kinds, spec, timeout=timeout, ring=ring, clock=clock)
        self._runner = runner
        self._scripts_dir = Path(scripts_dir) if scripts_dir else SCRIPTS_DIR
        self._proc = None
        self._reader: threading.Thread | None = None
        self.target = _target_pid(self.spec)
        self._notes: deque[str] = deque(maxlen=NOTES)

    def script(self) -> str:
        """The scripts for the kinds asked, joined into one program, then one END that clears every map they use,
        so bpftrace prints none of them as it exits (bpftrace takes a single END, so the scripts keep none of
        their own). Kinds with no Linux script (registry) are left out; with nothing left, a valid no-op."""
        wanted = [k for k in KINDS if k in self.kinds and k in SCRIPTS]
        parts = []
        for k in wanted:
            path = self._scripts_dir / SCRIPTS[k]
            parts.append(path.read_text(encoding="utf-8"))
        text = "\n".join(parts).strip()
        if not text:
            return "BEGIN { }"
        code = _bare(text)
        maps = sorted(set(_MAP.findall(code)))
        if not maps or _END_PROBE.search(code):
            return text
        clears = "".join(f"    clear({name});\n" for name in maps)
        return f"{text}\n\nEND\n{{\n{clears}}}"

    def argv(self) -> list[str]:
        """The command: bpftrace in JSON, the program, and the target pid as $1 when the program reads $1. Only
        digits ever follow the program (see `_target_pid`)."""
        script = self.script()
        argv = ["sudo", "-n", "bpftrace", "-f", "json", "-e", script]
        if _POSITIONAL.search(_bare(script)):
            argv.append(str(self.target))
        return argv

    def _begin(self) -> None:
        argv = self.argv()
        try:
            self._proc = self._runner(argv) if self._runner is not None else _spawn(argv)
        except OSError as e:
            self.error = f"bpftrace could not start: {e}"
            self._stop.set()
            return
        self._reader = threading.Thread(target=self._pump, name="ebpf-bpftrace", daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        """Read bpftrace's lines until the stream ends (the process ended), turning each event line into an Event.
        bpftrace's own lines (its attached-probes line, a map) and malformed or unexpected lines are skipped; its
        lost-events lines are counted in `lost`; plain text (bpftrace's or sudo's own words) is kept, the last few,
        so that if bpftrace ends while the watch is still wanted, the watch says why and stops."""
        stdout = getattr(self._proc, "stdout", None)
        if stdout is None:
            return
        try:
            for raw in stdout:
                if self._stop.is_set():
                    break
                line = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
                what, value = _classify(line)
                if what == "event":
                    self._ingest(value)
                elif what == "lost":
                    with self._lock:
                        self.lost += value
                elif what == "text":
                    self._notes.append(value)
        except (OSError, ValueError):
            pass
        if not self._stop.is_set():
            self._ended()

    def _ended(self) -> None:
        """bpftrace's stream ended while the watch was still wanted: it could not start (sudo wanted a password,
        bpftrace is missing, the script was refused) or something else ended it. Say so in `error`, with its exit
        code and its last words, and stop, so nothing waits on a source that is gone."""
        code = None
        wait = getattr(self._proc, "wait", None)
        if callable(wait):
            try:
                code = wait(timeout=1.0)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                code = None
        if not self.error:
            words = " | ".join(self._notes)
            self.error = ("bpftrace ended" + (f" (exit code {code})" if isinstance(code, int) else "")
                          + (f": {words}" if words else ""))
        self.stop()

    def _ingest(self, obj: dict) -> None:
        """One event object from a script into an Event. The scripts print compact keys (evt, act, pid, ppid,
        comm, proto, saddr/sport, daddr/dport, path, flags, count, approx; old/new for a TCP state change, named
        here as connect, accept or close)."""
        kind = str(obj.get("evt") or "")
        action = str(obj.get("act") or "")
        if not kind:
            return
        if action == "tcp":
            action = _tcp_action(_int(obj.get("old")), _int(obj.get("new")))
        extra = {k: obj[k] for k in ("flags", "code") if k in obj}
        if "count" in obj:
            extra["count"] = _int(obj.get("count")) or 0
        if _int(obj.get("approx")):
            extra["approx"] = True
        self._emit(
            kind, action,
            pid=_int(obj.get("pid")), ppid=_int(obj.get("ppid")),
            program=str(obj.get("comm") or ""), path=str(obj.get("path") or ""),
            local=_endpoint(obj.get("saddr"), obj.get("sport")),
            remote=_endpoint(obj.get("daddr"), obj.get("dport")),
            proto=str(obj.get("proto") or ""), bytes=_int(obj.get("bytes")) or 0,
            extra=extra)

    def _end(self) -> None:
        """End bpftrace and reap it (`_halt`), then wait for the reader."""
        proc = self._proc
        if proc is not None:
            _halt(proc)
        reader = self._reader
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=2.0)


def _spawn(argv, *, popen=None, windows: bool | None = None):
    """Start bpftrace: its stdout a pipe of lines, with its stderr on the same pipe (so the watch can say why it
    ended), and stdin closed. On Linux it gets a session of its own: sudo passes a signal on to its command only
    when it comes from outside sudo's process group, so this is what lets the watch's SIGTERM reach bpftrace. No
    console window on Windows (bpftrace never runs there, but every child gets the flag)."""
    popen = popen or subprocess.Popen
    windows = (os.name == "nt") if windows is None else windows
    extra = {"creationflags": CREATE_NO_WINDOW} if windows else {"start_new_session": True}
    return popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                 close_fds=True, **extra)


def _halt(proc, grace: float = STOP_GRACE) -> None:
    """End a bpftrace process and reap it, so neither it nor a zombie is left. SIGTERM first: sudo passes it on to
    bpftrace (its process group is its own, see `_spawn`), which detaches its probes, runs END and exits; a SIGKILL
    would end sudo alone and could leave bpftrace running as root. If it has not gone within `grace` seconds,
    SIGKILL, then wait again. A stand-in with only `kill()` is simply killed."""
    terminate = getattr(proc, "terminate", None)
    wait = getattr(proc, "wait", None)
    if callable(terminate) and callable(wait):
        try:
            terminate()
        except (OSError, ValueError):
            pass
        if _reaped(wait, grace):
            return
    try:
        proc.kill()
    except (OSError, ValueError):
        pass
    if callable(wait):
        _reaped(wait, grace)


def _reaped(wait, timeout: float) -> bool:
    """Whether the process ended (and was reaped) within `timeout` seconds."""
    try:
        wait(timeout=timeout)
        return True
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return False


# -- reading bpftrace's lines -------------------------------------------------------------------------------

# The keys each script line may carry, by (evt, act). The scripts print evt and act first, so text another user
# chooses (a path, a program name) cannot change them without repeating a key; and a line cannot carry a key its
# kind and action do not have. Either way it is dropped.
_BASE_KEYS = frozenset({"evt", "act", "pid", "comm"})
_ADDR_KEYS = frozenset({"proto", "saddr", "sport", "daddr", "dport"})
_SHAPES = {
    ("process", "exec"): _BASE_KEYS | {"ppid", "path"},
    ("process", "exit"): _BASE_KEYS | {"ppid"},
    ("file", "open"): _BASE_KEYS | {"path", "flags"},
    ("file", "skipped"): frozenset({"evt", "act", "count"}),
    ("net", "tcp"): _BASE_KEYS | _ADDR_KEYS | {"old", "new", "approx"},
    ("net", "udp_send"): _BASE_KEYS | _ADDR_KEYS,
    ("net", "skipped"): frozenset({"evt", "act", "proto", "count"}),
    # TCP lines named in the script, as the scripts printed them before; still read
    ("net", "connect"): _BASE_KEYS | _ADDR_KEYS,
    ("net", "accept"): _BASE_KEYS | _ADDR_KEYS,
    ("net", "close"): _BASE_KEYS | _ADDR_KEYS,
}
_ANY_KEYS = frozenset().union(*_SHAPES.values()) | {"bytes", "code"}

_LITERAL_OR_COMMENT = re.compile(r'"(?:\\.|[^"\\\n])*"|//[^\n]*')
_MAP = re.compile(r"@[A-Za-z_][A-Za-z0-9_]*")
_END_PROBE = re.compile(r"(?m)^\s*END\b")
_POSITIONAL = re.compile(r"\$1(?!\d)")


def _bare(text: str) -> str:
    """A script's code without its comments and string literals, for finding the maps and $1 it uses."""
    return _LITERAL_OR_COMMENT.sub(" ", text)


def _classify(line: str):
    """What one line of bpftrace's output is: ("event", our event object), ("lost", how many events bpftrace
    dropped), ("text", words that are not JSON, cut to NOTE_CHARS) or ("skip", None) for the rest: bpftrace's
    attached-probes and map lines, a blank line, a malformed or unexpected event line. bpftrace wraps a printf as
    {"type":"printf","data":"..."}, the data being the string a script printed; a bare object (a test's) is read
    as is."""
    line = (line or "").strip()
    if not line:
        return "skip", None
    try:
        outer = json.loads(line, object_pairs_hook=_unique)
    except ValueError:
        return "text", line[:NOTE_CHARS]
    if not isinstance(outer, dict):
        return "skip", None
    kind = outer.get("type")
    if kind == "printf":
        inner = _inner(outer.get("data"))
        return ("event", inner) if inner is not None else ("skip", None)
    if kind == "lost_events":
        data = outer.get("data")
        n = _int(data.get("events")) if isinstance(data, dict) else None
        return ("lost", n) if n is not None and n > 0 else ("skip", None)
    if kind is None and "evt" in outer and _fits(outer):
        return "event", outer
    return "skip", None


def _event_object(line: str) -> dict | None:
    """Our event object out of one bpftrace JSON line, or None for anything else."""
    what, value = _classify(line)
    return value if what == "event" else None


def _inner(data) -> dict | None:
    """The event object a printf line's data holds, or None when it is not one of ours."""
    if isinstance(data, dict):
        obj = data
    elif isinstance(data, str):
        try:
            obj = json.loads(data, object_pairs_hook=_unique)
        except ValueError:
            return None
    else:
        return None
    return obj if isinstance(obj, dict) and _fits(obj) else None


def _unique(pairs) -> dict:
    """A JSON object's pairs as a dict, refusing a key given twice. json's own rule is that the last one wins,
    which is how a crafted path would overwrite the keys after it."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"key {key!r} given twice")
        obj[key] = value
    return obj


def _fits(obj: dict) -> bool:
    """Whether an event object carries only the keys its kind and action may have."""
    evt, act = obj.get("evt"), obj.get("act")
    if not isinstance(evt, str) or not (act is None or isinstance(act, str)):
        return False
    return set(obj) <= _SHAPES.get((evt, act), _ANY_KEYS)


def _tcp_action(old, new) -> str:
    """A TCP state change named: connect (SYN_SENT 2 -> ESTABLISHED 1), accept (SYN_RECV 3 -> ESTABLISHED 1) or
    close (any -> CLOSE 7). Any other change, which net.bt does not print, is "state"."""
    if new == 7:
        return "close"
    if new == 1 and old == 2:
        return "connect"
    if new == 1 and old == 3:
        return "accept"
    return "state"


def _target_pid(spec: dict) -> int:
    """The process whose file opens a watch follows, from spec["pid"]: a whole number from 1 to the kernel's
    largest pid, as an int or a string of ASCII digits. Anything else is 0 (every process), so nothing but digits
    ever follows the program on bpftrace's command line."""
    value = spec.get("pid")
    if isinstance(value, bool):
        return 0
    if isinstance(value, str):
        text = value.strip()
        if not (0 < len(text) <= 7 and text.isascii() and text.isdigit()):
            return 0
        value = int(text)
    if not isinstance(value, int):
        return 0
    return value if 0 < value <= PID_MAX else 0


def _endpoint(addr, port) -> str:
    addr = "" if addr is None else str(addr)
    p = _int(port)
    if addr and p is not None:
        return f"[{addr}]:{p}" if ":" in addr else f"{addr}:{p}"
    return addr


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):  # OverflowError: JSON's Infinity
        return None


# -- the factory --------------------------------------------------------------------------------------------

def watch_system(runtime=None, system=None) -> str:
    """Which backend a watch should use: an explicit `system`, else the runtime's, else this machine's."""
    if system in ("linux", "windows"):
        return system
    s = getattr(runtime, "system", "")
    if s in ("linux", "windows"):
        return s
    return "windows" if os.name == "nt" else "linux"


def make_watch(kinds, spec: dict | None = None, runtime=None, *, system=None, **options) -> Watch:
    """A watch for `kinds`, for the right machine: `BpftraceWatch` on Linux, or `NpcapEtwWatch` on Windows
    (imported lazily from the module another builder writes; it is not needed, nor imported, on Linux)."""
    if watch_system(runtime, system) == "windows":
        from .windows_watch import NpcapEtwWatch

        return NpcapEtwWatch(kinds, spec, **options)
    return BpftraceWatch(kinds, spec, **options)
