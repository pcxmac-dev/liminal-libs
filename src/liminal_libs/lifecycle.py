"""How every part of Liminal is told to end, and how what it started ends with it (1.86.0, Monday list item 38).

The user, 2026-11-24: "there needs to be a way to pass the object, that inherits the login-app/platform/... a way to
send a KILL signal, like in linux"; "a reliable way to disconnect from all plugins"; "all plugins either have daemon
mode (on going service), or on demand ... for now lets just do on demand only"; "a reliable way to terminate all
apps/plugins and related processes safely". Seen the same day: `schtasks /End` on the four apps' tasks left what they
had started (the integrator's `liminal_charts sync --extras-only`, `liminal_charts host mongo` and its mongod) running
10-20 minutes, since ending a process on Windows ends that process alone.

So:
- `Signal`: TERM (finish what is under way, secure data, release claims, detach, end the children) and KILL (no
  waiting: every child tree ended now). Every object that can be stopped answers `signal(sig, deadline, sender)`
  (`Stoppable`); `deliver` passes one to an object and says what came of it.
- The plugin modes: ON_DEMAND, the only one allowed for now; SERVICE is named and refused (SERVICE_REFUSED).
- The process ledger: every process the library starts for an app or a plugin (`spawn`) is written down with its
  owner, its id and its start time (a reused id is never taken for it), its kind and its command, in a small file per
  machine under the data folder. On Windows a child is put in a job object of its owner's that ends it when the owner
  ends, however the owner ends (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE); on Linux it starts in a session of its own and is
  sent SIGTERM when its owner ends (PR_SET_PDEATHSIG). What fails there is noted, never fatal.
- `end_trees`: processes ended with everything they started, found by parent in a process table and checked by start
  time before each signal: TERM first and KILL once the time is up, or KILL at once.
The machine-wide command is liminal_libs.stop (`liminal-signal`, `liminal-stop`).
"""
from __future__ import annotations

import ctypes
import enum
import json
import os
import re
import signal as _signals
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Protocol, runtime_checkable

from . import proc as _proc

ON_DEMAND = "on_demand"  # a plugin that runs while a client holds it, and ends what it started when let go
SERVICE = "service"  # a plugin that goes on by itself (a daemon): named, not yet allowed
MODES = (ON_DEMAND, SERVICE)
SERVICE_REFUSED = "service mode is not yet allowed: on demand only"
TERM_TIMEOUT_S = 10.0  # what TERM is given before what is left is killed
START_DEADLINE_S = 10.0  # a plugin's start is given this long (its START_DEADLINE_S), then its tree is ended
STOP_DEADLINE_S = 15.0  # a plugin's TERM is given this long (its STOP_DEADLINE_S), then KILL
PROOF_HEADER = "X-Liminal-Proof"  # a signal's or an ask's proof of this user's key, to an app that is no node yet
PROOF_WORDS = b"liminal-signal 1"
STEP_S = 0.1  # between two looks at processes that are ending
LEDGER_VAR = "LIMINAL_PROCESS_LEDGER"  # the ledger's file, named outright (a test's)
LOCK_WAIT_S = 2.0  # the ledger's lock file is waited for this long, then taken as left by a process that ended
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW
JOB_KILL_ON_CLOSE = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
JOB_BREAKAWAY_OK = 0x0800  # JOB_OBJECT_LIMIT_BREAKAWAY_OK: a child started detached (a host) may leave the job
EXTENDED_LIMITS = 9  # JobObjectExtendedLimitInformation
PR_SET_PDEATHSIG = 1


class Signal(str, enum.Enum):
    """What an object is told: TERM, end in good order; KILL, end now."""

    TERM = "TERM"
    KILL = "KILL"

    @classmethod
    def of(cls, value) -> "Signal":
        """A signal from its name, Linux's (SIGTERM, SIGKILL), its number (15, 9) or itself; ValueError otherwise."""
        if isinstance(value, Signal):
            return value
        text = str(value).strip().upper()
        text = text[3:] if text.startswith("SIG") else text
        named = {"TERM": cls.TERM, "15": cls.TERM, "KILL": cls.KILL, "9": cls.KILL}.get(text)
        if named is None:
            raise ValueError(f"no such signal {value!r}: TERM or KILL")
        return named


class SignalRefused(PermissionError):
    """A signal from someone it may not come from (a plugin hears one only from its own app or that app's login)."""


@runtime_checkable
class Stoppable(Protocol):
    """Every object that can be told to end: an app, the login it includes, a platform part, a plugin, a host."""

    def signal(self, sig: Signal, deadline: float, sender=None) -> dict | None: ...


# What this module uses of the machine when it is not given one: the real table, killer, ledger and clock, or a
# test's (and the conformance's) stand-ins while `standins` holds them
_STANDINS: dict = {}
_STANDINS_LOCK = threading.Lock()


class standins:
    """Stand-ins for the machine (table, killer, ledger, clock, sleep) used by everything here that is given none, for
    the time of a `with`: what the conformance's node check and the tests serve a plugin with, so nothing real is
    looked up, signalled or written."""

    def __init__(self, **given):
        unknown = set(given) - {"table", "killer", "ledger", "clock", "sleep"}
        if unknown:
            raise TypeError(f"no stand-in for {sorted(unknown)}")
        self.given = given

    def __enter__(self):
        with _STANDINS_LOCK:
            self.old = dict(_STANDINS)
            _STANDINS.update(self.given)
        return self

    def __exit__(self, *exc):
        with _STANDINS_LOCK:
            _STANDINS.clear()
            _STANDINS.update(self.old)
        return False


def _table(table=None):
    return table or _STANDINS.get("table") or OsTable()


def _killer(killer=None):
    return killer or _STANDINS.get("killer") or OsKiller()


def _ledger(ledger=None):
    return ledger or _STANDINS.get("ledger") or Ledger()


def _clock(clock=None) -> Callable[[], float]:
    return clock or _STANDINS.get("clock") or time.monotonic


def _sleep(sleep=None) -> Callable[[float], None]:
    return sleep or _STANDINS.get("sleep") or time.sleep


def deadline_in(timeout: float, clock: Callable[[], float] | None = None) -> float:
    return _clock(clock)() + max(float(timeout), 0.0)


def left(deadline: float, clock: Callable[[], float] | None = None) -> float:
    return max(deadline - _clock(clock)(), 0.0)


def stop_deadline(obj) -> float:
    """What TERM gives an object before KILL: its STOP_DEADLINE_S (a plugin's, the contract's 15 s by default)."""
    try:
        value = float(getattr(obj, "STOP_DEADLINE_S", STOP_DEADLINE_S))
    except (TypeError, ValueError):
        value = STOP_DEADLINE_S
    return value if value > 0 else STOP_DEADLINE_S


def start_deadline(obj) -> float:
    """What a start is given before it is taken as failed and its tree ended: its START_DEADLINE_S (10 s)."""
    try:
        value = float(getattr(obj, "START_DEADLINE_S", START_DEADLINE_S))
    except (TypeError, ValueError):
        value = START_DEADLINE_S
    return value if value > 0 else START_DEADLINE_S


def _told(obj, sig: Signal, deadline: float, sender) -> str:
    told = getattr(obj, "signal", None)
    if callable(told):
        told(sig, deadline, sender=sender)
        return "signalled"
    if sig is Signal.TERM:
        for how, attr in (("stopped", "app_stopping"), ("closed", "close")):
            fn = getattr(obj, attr, None)
            if callable(fn):
                fn()
                return how
    return "nothing"


def deliver(obj, sig: Signal, deadline: float, sender=None, name: str = "", within: bool = False,
            clock: Callable[[], float] | None = None) -> dict:
    """`sig` passed to `obj`: its own `signal` when it has one; else, for TERM, its `app_stopping` or its `close`. What
    came of it: {"name", "how": signalled | stopped | closed | nothing | refused | failed | late, "why"}. Nothing
    raised. `within`: the object is given until `deadline` and no longer (its answer waited for on a thread of its
    own): one that has not answered by then is "late", and what it started (spawn, owned by `name`) is killed with
    its trees, as KILL ends them."""
    sig = Signal.of(sig)
    name = name or str(getattr(obj, "name", "") or getattr(obj, "NAME", "") or type(obj).__name__)
    box: dict = {}

    def run() -> None:
        try:
            box["how"] = _told(obj, sig, deadline, sender)
        except SignalRefused as e:
            box["refused"] = str(e)
        except Exception as e:  # noqa: BLE001 - one object failing never keeps the signal from the others
            box["failed"] = f"{type(e).__name__}: {e}"

    if within:
        worker = threading.Thread(target=run, name=f"liminal-signal-{name}", daemon=True)
        worker.start()
        worker.join(left(deadline, clock))
        if worker.is_alive():
            killed = end_owned(name, Signal.KILL, deadline_in(0))
            return {"name": name, "how": "late", "why": f"it did not end within its deadline: killed what it "
                                                       f"started ({len(killed)} processes)", "processes": killed}
    else:
        run()
    if "refused" in box:
        return {"name": name, "how": "refused", "why": box["refused"]}
    if "failed" in box:
        return {"name": name, "how": "failed", "why": box["failed"]}
    how = box.get("how", "nothing")
    return {"name": name, "how": how, "why": "it has nothing to end" if how == "nothing" else ""}


PLUGINS_DEADLINE_S = 10.0  # an app's plugins told TERM together are given this long in all (1.87.0)
GRACE_S = 2.5  # ... and this much more before one still at it is taken for late


def deliver_all(items, sig: Signal, deadline: float, sender=None, grace: float = GRACE_S,
                clock: Callable[[], float] | None = None) -> list[dict]:
    """`sig` passed to each of `items` ((name, object)) at once, each on a thread of its own, under one `deadline`
    and `grace` seconds more (1.87.0; the shutdown audit of 2026-11-24: the platform told its plugins one after
    another, about 54 s and more): what each came to, in their order (deliver's); one still at it then is "late", and
    what was started for it is killed with its trees."""
    sig = Signal.of(sig)
    box: dict[str, dict] = {}
    threads = []
    for name, obj in items:
        def run(name=name, obj=obj) -> None:
            box[name] = deliver(obj, sig, deadline, sender=sender, name=name)

        t = threading.Thread(target=run, name=f"liminal-signal-{name}", daemon=True)
        t.start()
        threads.append((name, t))
    for _, t in threads:
        t.join(left(deadline, clock))
    end = time.monotonic() + max(grace, 0.0)
    for _, t in threads:
        t.join(max(end - time.monotonic(), 0.0))
    out = []
    for name, t in threads:
        if t.is_alive():
            killed = end_owned(name, Signal.KILL, deadline_in(0))
            out.append({"name": name, "how": "late", "processes": killed,
                        "why": f"it did not end within the deadline and its grace: killed what it started "
                               f"({len(killed)} processes)"})
        else:
            out.append(box.get(name) or {"name": name, "how": "failed", "why": "it said nothing"})
    return out


def check_sender(plugin, sender) -> None:
    """A plugin hears a signal only from its own app, or the login that app attached it with; SignalRefused else."""
    app, login = getattr(plugin, "app", None), getattr(plugin, "login", None)
    who = getattr(plugin, "name", "") or type(plugin).__name__
    if app is None:
        raise SignalRefused(f"{who} is attached to no app: a signal reaches a plugin only through its app")
    if sender is None or not (sender is app or (login is not None and sender is login)):
        raise SignalRefused(f"{who} takes a signal only from its own app ({getattr(app, 'NAME', '') or 'its app'}) "
                            "or its login")


# -- the process table: what runs on this machine --------------------------------------------------------------------
@dataclass(frozen=True)
class Proc:
    """One process as a table lists it: its id, its parent's, its executable, its command line, when it started (a
    number that stays the same for its life: proc.started's)."""

    pid: int
    ppid: int
    exe: str
    cmdline: str
    started: int | None


class OsTable:
    """This machine's processes: Windows' own table (CIM, every process), else /proc. Asked only by the stop command
    and by an owner ending its children; a test gives a table of its own."""

    def list(self) -> list[Proc]:
        if os.name == "nt":
            return self._windows()
        return self._linux()

    def alive(self, pid: int) -> bool:
        return _proc.pid_alive(pid)

    def started(self, pid: int) -> int | None:
        return _proc.started(pid)

    def _windows(self) -> list[Proc]:
        script = ("Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId)`t$($_.ParentProcessId)`t"
                  "$($_.ExecutablePath)`t$($_.CommandLine)\" }")
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                 capture_output=True, text=True, timeout=60, creationflags=NO_WINDOW).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        rows = []
        for line in out.splitlines():
            parts = line.split("\t", 3)
            if len(parts) == 4 and parts[0].isdigit() and parts[1].isdigit():
                pid = int(parts[0])
                rows.append(Proc(pid, int(parts[1]), parts[2], parts[3], _proc.started(pid)))
        return rows

    def _linux(self) -> list[Proc]:
        rows = []
        for d in Path("/proc").glob("[0-9]*"):
            try:
                cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
                stat = (d / "stat").read_text().rsplit(")", 1)[1].split()
                ppid, started = int(stat[1]), int(stat[19])
                try:
                    exe = os.readlink(d / "exe")
                except OSError:
                    exe = ""
            except (OSError, ValueError, IndexError):
                continue
            rows.append(Proc(int(d.name), ppid, exe, cmd, started))
        return rows


def job_of(tie: str) -> str | None:
    """The name of a ledger row's job (its tie "job:<name>..."), or None."""
    head = str(tie or "").split(";", 1)[0].strip()
    return head[4:] if head.startswith("job:") and len(head) > 4 else None


class OsKiller:
    """How a signal reaches one process: Linux's os.kill (or its group's, os.killpg, when it leads one); on Windows
    TERM is taskkill without /F (a polite close: what has a window or a console may hear it) and KILL is
    TerminateProcess (os.kill)."""

    def end_job(self, name: str) -> bool:
        """Everything in the named job ended at once (Windows: OpenJobObjectW, TerminateJobObject). Whether it was."""
        if os.name != "nt" or not name:
            return False
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.OpenJobObjectW.restype = ctypes.c_void_p
            k32.OpenJobObjectW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
            k32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
            job = k32.OpenJobObjectW(0x0008, 0, name)  # JOB_OBJECT_TERMINATE
            if not job:
                return False
            try:
                return bool(k32.TerminateJobObject(job, 1))
            finally:
                k32.CloseHandle(job)
        except (AttributeError, OSError):
            return False

    def send(self, pid: int, sig: Signal, group: bool = False) -> bool:
        if os.name == "nt":
            if sig is Signal.TERM:
                try:
                    done = subprocess.run(["taskkill", "/PID", str(pid)], capture_output=True, timeout=30,
                                          creationflags=NO_WINDOW)
                    return done.returncode == 0
                except (OSError, subprocess.SubprocessError):
                    return False
            try:
                os.kill(pid, _signals.SIGTERM)  # TerminateProcess on Windows: the end at once
                return True
            except OSError:
                return False
        number = _signals.SIGTERM if sig is Signal.TERM else getattr(_signals, "SIGKILL", _signals.SIGTERM)
        try:
            if group and getattr(os, "getpgid", None) is not None and os.getpgid(pid) == pid:
                os.killpg(pid, number)
            else:
                os.kill(pid, number)
            return True
        except OSError:
            return False


def descendants(root: Proc, rows: Iterable[Proc]) -> list[Proc]:
    """What `root` started and what they started, deepest first, from a table's parents. A row is taken for a child
    only when it started after its parent did (a parent id the system gave again later names another process)."""
    children: dict[int, list[Proc]] = {}
    for r in rows:
        children.setdefault(r.ppid, []).append(r)
    out: list[Proc] = []
    seen = {root.pid}

    def walk(p: Proc) -> None:
        for c in children.get(p.pid, ()):
            if c.pid in seen:
                continue
            if p.started is not None and c.started is not None and c.started < p.started:
                continue  # started before its "parent": that parent id is a later process's
            seen.add(c.pid)
            walk(c)
            out.append(c)

    walk(root)
    return out


def _same(table, p: Proc) -> bool:
    """Whether `p` is still the process it was when listed: alive, and started when it started (never a reused id)."""
    if p.started is None:
        return False  # its start cannot be told: never signalled
    return table.alive(p.pid) and table.started(p.pid) == p.started


def end_trees(roots: Iterable[Proc], sig: Signal, timeout: float = TERM_TIMEOUT_S, *, table=None, killer=None,
              clock: Callable[[], float] | None = None, sleep: Callable[[float], None] | None = None,
              protect: Iterable[int] = ()) -> list[dict]:
    """Each of `roots` ended with everything it started (its descendants in `table`): TERM to each, deepest first,
    then KILL to whatever is left once `timeout` is up; KILL: at once. Before each signal the process is looked at
    again: one gone, or whose start time is another's (its id given again), is left. `protect`: ids never signalled
    (the caller and its parents). Returns, for each process: {"pid", "how": terminated | killed | gone | left,
    "why"}."""
    table, killer, clock, sleep = _table(table), _killer(killer), _clock(clock), _sleep(sleep)
    sig = Signal.of(sig)
    protect = set(protect)
    rows = table.list()
    targets: dict[int, Proc] = {}
    for root in roots:
        for p in [*descendants(root, rows), root]:
            if p.pid not in protect and p.pid not in targets:
                targets[p.pid] = p
    out: dict[int, dict] = {}
    if sig is Signal.TERM:
        for p in targets.values():
            if not _same(table, p):
                out[p.pid] = {"pid": p.pid, "how": "gone", "why": "it had ended (or its id is another's now)"}
                continue
            killer.send(p.pid, Signal.TERM, group=True)
        end = clock() + max(timeout, 0.0)
        while clock() < end and any(p.pid not in out and _same(table, p) for p in targets.values()):
            sleep(STEP_S)
        for p in targets.values():
            if p.pid not in out and not _same(table, p):
                out[p.pid] = {"pid": p.pid, "how": "terminated", "why": ""}
    for p in targets.values():
        if p.pid in out:
            continue
        if not _same(table, p):
            out[p.pid] = {"pid": p.pid, "how": "gone", "why": "it had ended (or its id is another's now)"}
            continue
        sent = killer.send(p.pid, Signal.KILL, group=True)
        out[p.pid] = {"pid": p.pid, "how": "killed" if sent else "left",
                      "why": "" if sent else "the system refused to end it (another user's, or elevated)"}
    return list(out.values())


# -- the ledger: every process the library started for an app or a plugin ------------------------------------------
@dataclass
class Row:
    """One process the library started: its id and start time, its owner (an app or a plugin, by name) and the owner's
    process (its id and start time), its kind (host, mongod, model server, sync ...), its command, when it was started
    (the wall clock), and what became of its tie to its owner (a job object on Windows, PR_SET_PDEATHSIG on Linux)."""

    pid: int
    started: int | None
    owner: str
    owner_pid: int
    owner_started: int | None
    kind: str
    command: list = field(default_factory=list)
    at: float = 0.0
    tie: str = ""

    def as_proc(self) -> Proc:
        return Proc(self.pid, self.owner_pid, "", " ".join(str(c) for c in self.command), self.started)


def ledger_path() -> Path:
    """The ledger's file: LIMINAL_PROCESS_LEDGER, else processes/<this installation>.json in the data folder (one a
    machine: Windows' and each WSL distribution's apart, as claims name them)."""
    named = (os.environ.get(LEDGER_VAR) or "").strip()
    if named:
        return Path(named)
    from . import layout
    from .claims import instance

    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", instance()).strip("-") or "here"
    return layout.data_dir() / "processes" / f"{safe}.json"


class Ledger:
    """The ledger's file: read, written whole (a temporary file put in place), one process at a time (a lock file
    beside it). A row whose process is gone, or whose id is another process's now, is dropped when read."""

    def __init__(self, path: Path | None = None, table=None):
        self._path = Path(path) if path is not None else None
        self.table = table or OsTable()
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path if self._path is not None else ledger_path()

    def _read(self) -> list[Row]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        rows = []
        for d in data.get("rows", []) if isinstance(data, dict) else []:
            try:
                rows.append(Row(**{k: d[k] for k in Row.__dataclass_fields__ if k in d}))
            except TypeError:
                continue
        return rows

    def _write(self, rows: list[Row]) -> None:
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.new")
        tmp.write_text(json.dumps({"rows": [asdict(r) for r in rows]}, indent=1), encoding="utf-8")
        os.replace(tmp, path)

    def _held(self):
        ledger = self

        class Held:
            def __enter__(self):
                ledger._lock.acquire()
                self.lock = ledger.path.with_name(ledger.path.name + ".lock")
                self.lock.parent.mkdir(parents=True, exist_ok=True)
                end = time.monotonic() + LOCK_WAIT_S
                while True:
                    try:
                        os.close(os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
                        return self
                    except FileExistsError:
                        if time.monotonic() > end:  # left by a process that ended while it held it
                            self.lock.unlink(missing_ok=True)
                            end = time.monotonic() + LOCK_WAIT_S
                        time.sleep(0.02)
                    except OSError:
                        return self  # a folder that takes no lock file: one process's writes at a time all the same

            def __exit__(self, *exc):
                try:
                    self.lock.unlink(missing_ok=True)
                finally:
                    ledger._lock.release()
                return False

        return Held()

    def _live(self, rows: list[Row]) -> list[Row]:
        return [r for r in rows if r.started is not None and self.table.alive(r.pid) and self.table.started(r.pid) == r.started]

    def rows(self) -> list[Row]:
        """The rows of processes still running (the others dropped from the file)."""
        with self._held():
            rows = self._read()
            live = self._live(rows)
            if len(live) != len(rows):
                self._write(live)
            return live

    def add(self, row: Row) -> None:
        with self._held():
            rows = [r for r in self._live(self._read()) if r.pid != row.pid]
            self._write([*rows, row])

    def forget(self, pid: int) -> None:
        with self._held():
            rows = self._read()
            kept = [r for r in rows if r.pid != pid]
            if len(kept) != len(rows):
                self._write(kept)


# -- the ties: a child ends with its owner ---------------------------------------------------------------------------
class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", ctypes.c_uint32), ("SchedulingClass", ctypes.c_uint32)]


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                               "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _kernel32():
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = ctypes.c_void_p
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        k32.SetInformationJobObject.restype = ctypes.c_int
        k32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        k32.AssignProcessToJobObject.restype = ctypes.c_int
        k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k32.CloseHandle.restype = ctypes.c_int
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        return k32
    except (AttributeError, OSError):
        return None


def _ntdll():
    try:
        nt = ctypes.WinDLL("ntdll")
        nt.NtResumeProcess.restype = ctypes.c_long
        nt.NtResumeProcess.argtypes = [ctypes.c_void_p]
        return nt
    except (AttributeError, OSError):
        return None


CREATE_SUSPENDED = 0x00000004


class JobTie:
    """A job object on Windows. The process's own (one, made when first needed, its handle held for this process's
    life, `kill_on_close`): every child put in it is ended by Windows when this process ends, however it ends (its last
    handle closed). Or one for a child meant to outlive its starter (`name`: Local\\liminal-job-..., written in its
    ledger row): nothing ends it with its starter, and liminal-stop ends everything in it at once by its name
    (OsKiller.end_job). 1.87.0 (the shutdown audit of 2026-11-24): a child is started suspended and resumed once it is in
    the job (`can_resume`, NtResumeProcess), so what it starts at once is in it too: the venv's pythonw.exe is a
    redirector that starts the base interpreter as its child, and that child was left out. `k32`, `ntdll`: a test's."""

    def __init__(self, k32=None, ntdll=None, name: str | None = None, kill_on_close: bool = True):
        self._k32 = k32
        self._nt = ntdll
        self._job = None
        self._lock = threading.Lock()
        self.problem = ""
        self.name = name
        self.kill_on_close = kill_on_close

    def can_resume(self) -> bool:
        """Whether a child can be started suspended and resumed here (ntdll's NtResumeProcess)."""
        if self._nt is None:
            self._nt = _ntdll() or False
        return bool(self._nt) and self._job_handle() is not None

    def resume(self, popen) -> bool:
        """A child started suspended let run (NtResumeProcess on its handle). Whether it was."""
        nt = self._nt
        handle = getattr(popen, "_handle", None)
        if not nt or not handle:
            return False
        try:
            return nt.NtResumeProcess(int(handle)) == 0
        except (OSError, ValueError, TypeError):
            return False

    def _job_handle(self):
        with self._lock:
            if self._job is not None or self.problem:
                return self._job
            k32 = self._k32 if self._k32 is not None else _kernel32()
            self._k32 = k32
            if k32 is None:
                self.problem = "no kernel32 here"
                return None
            job = k32.CreateJobObjectW(None, self.name)
            if not job:
                self.problem = f"CreateJobObjectW failed ({ctypes.get_last_error() if os.name == 'nt' else 0})"
                return None
            info = _ExtendedLimits()
            info.BasicLimitInformation.LimitFlags = (JOB_KILL_ON_CLOSE if self.kill_on_close else 0) | JOB_BREAKAWAY_OK
            if not k32.SetInformationJobObject(job, EXTENDED_LIMITS, ctypes.byref(info), ctypes.sizeof(info)):
                self.problem = "SetInformationJobObject failed"
                k32.CloseHandle(job)
                return None
            self._job = job
            return job

    def tie(self, popen) -> str:
        """`popen`'s process put in the job: "job" when it is, else why not (noted, never raised)."""
        job = self._job_handle()
        if job is None:
            return f"no job: {self.problem}"
        k32 = self._k32
        handle = getattr(popen, "_handle", None)
        opened = None
        if not handle:
            opened = handle = k32.OpenProcess(0x0100 | 0x0001, 0, int(popen.pid))  # SET_QUOTA | TERMINATE
        try:
            if handle and k32.AssignProcessToJobObject(job, int(handle)):
                return f"job:{self.name}" if self.name else "job"
            return "no job: AssignProcessToJobObject failed (a job that allows no nesting, or the child had ended)"
        finally:
            if opened:
                k32.CloseHandle(opened)


_JOB = JobTie()
_REAL_POPEN = subprocess.Popen


def pdeathsig_preexec(libc=None, sig: int | None = None, main_thread: bool | None = None):
    """The preexec function a Linux child is started with: PR_SET_PDEATHSIG, so it is sent SIGTERM when its owner ends.
    None where it cannot be had (no libc's prctl), or when the start is not on the main thread: the signal comes when
    the thread that started the child ends, not its process, and a request's thread ends at once."""
    if main_thread is None:
        main_thread = threading.current_thread() is threading.main_thread()
    if not main_thread:
        return None
    if libc is None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl  # noqa: B018 - looked up here, before the fork
        except (OSError, AttributeError):
            return None
    number = int(sig if sig is not None else _signals.SIGTERM)

    def preexec() -> None:
        libc.prctl(PR_SET_PDEATHSIG, number, 0, 0, 0)

    return preexec


_MINE: dict[int, Row] = {}  # what this process started (spawn), by id: ended by end_owned without reading the file
_MINE_LOCK = threading.Lock()


def spawn(args, owner: str, kind: str, *, tied: bool = True, ledger: Ledger | None = None, popen: Callable | None = None,
          job: JobTie | None = None, libc=None, **kwargs) -> subprocess.Popen:
    """A process started for `owner` (an app's or a plugin's name), of `kind`, written in the ledger. `tied` (the
    default): it ends with this process (Windows: this process's job object; Linux: PR_SET_PDEATHSIG, and a session of
    its own so its tree can be signalled as one). Not tied: a process meant to outlive its starter (a host started by
    a client, mongod), written down all the same so the stop command finds it. Popen's own arguments are passed as
    given (creationflags, start_new_session ...); windowless on Windows unless said otherwise."""
    popen = popen or subprocess.Popen
    nt = os.name == "nt"
    tie = ""
    if nt:
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | NO_WINDOW
    else:
        kwargs.setdefault("start_new_session", True)
        if tied and "preexec_fn" not in kwargs:
            pre = pdeathsig_preexec(libc)
            if pre is not None:
                kwargs["preexec_fn"] = pre
                tie = "pdeathsig"
            else:
                tie = "no pdeathsig (no prctl here, or started from a thread that ends)"
    holder = None
    # a job is made only for a real start, or one given (a test's stand-in Popen gets no kernel object of this machine)
    if nt and (popen is _REAL_POPEN or job is not None):
        if tied:
            holder = job or _JOB
        else:
            import uuid

            holder = job or JobTie(name=f"Local\\liminal-job-{uuid.uuid4().hex[:16]}", kill_on_close=False)
    suspended = bool(holder is not None and holder.can_resume())
    if suspended:
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_SUSPENDED
    child = popen(args, **kwargs)
    if holder is not None:
        try:
            tie = holder.tie(child)
        finally:
            if suspended and not holder.resume(child):
                try:
                    child.kill()  # never left suspended for good
                finally:
                    raise OSError(f"{owner}'s {kind} could not be resumed after it was put in its job: ended")
        if not tied:
            tie = f"{tie}; untied: it outlives its starter by design"
    elif not tied:
        tie = "untied: it outlives its starter by design"
    pid = getattr(child, "pid", None)
    started = _proc.started(pid) if isinstance(pid, int) and not isinstance(pid, bool) else None
    if started is None:  # no process to tell apart from a later one with its id (ended already, or a stand-in's)
        return child
    row = Row(pid=pid, started=started, owner=owner, owner_pid=os.getpid(),
              owner_started=_proc.started(os.getpid()), kind=kind, command=[str(a) for a in args], at=time.time(),
              tie=tie)
    with _MINE_LOCK:
        _MINE[row.pid] = row
    try:
        _ledger(ledger).add(row)
    except OSError:
        pass  # a ledger that cannot be written: the child runs all the same, ended by its owner from memory
    return child


def mine(owner: str | None = None) -> list[Row]:
    """What this process started (spawn) for `owner` (None: for anyone)."""
    with _MINE_LOCK:
        return [r for r in _MINE.values() if owner is None or r.owner == owner]


def end_owned(owner: str | None, sig: Signal, deadline: float, *, table=None, killer=None, ledger: Ledger | None = None,
              clock: Callable[[], float] | None = None, sleep: Callable[[float], None] | None = None) -> list[dict]:
    """What this process started for `owner` (None: for anyone) ended, each with its tree (end_trees): TERM, then KILL
    at `deadline`; KILL at once. Taken from memory: nothing is read when nothing was started. Returns end_trees'."""
    rows = mine(owner)
    if not rows:
        return []
    out = end_trees([r.as_proc() for r in rows], sig, left(deadline, clock), table=table, killer=killer,
                    clock=clock, sleep=sleep, protect={os.getpid()})
    with _MINE_LOCK:
        for r in rows:
            _MINE.pop(r.pid, None)
    for r in rows:
        try:
            _ledger(ledger).forget(r.pid)
        except OSError:
            pass
    return out


def scrub_command(command) -> list[str]:
    """A command as it may be shown: the value after a word naming a key, a token, a password or a secret (`--api-key
    X`, `--token=X`) replaced."""
    out: list[str] = []
    hide = False
    for word in [str(w) for w in command or ()]:
        if hide:
            out.append("<hidden>")
            hide = False
            continue
        name, eq, _ = word.partition("=")
        if re.search(r"(key|token|password|secret|passwd)", name, re.I) and name.startswith("-"):
            if eq:
                out.append(f"{name}=<hidden>")
            else:
                out.append(word)
                hide = True
            continue
        out.append(word)
    return out


def stop_event_name(app: str) -> str:
    """The named event an app waits on for a graceful stop on Windows (1.87.0): Local\\liminal-stop-<app>.

    While a test runs (pytest sets PYTEST_CURRENT_TEST for each test) the name carries the test process's own suffix
    (1.88.2): a test that made, opened or set an app's event by its real name reached the real app on this machine,
    and a library suite run at 21:36 on 2026-11-24 stopped all four running apps that way. Outside a test the name is
    as before."""
    name = f"Local\\liminal-stop-{app}"
    if os.environ.get("PYTEST_CURRENT_TEST"):
        name += f"-test{os.getpid()}"
    return name


class StopEvent:
    """An app's stop event on Windows (1.87.0; the shutdown audit of 2026-11-24): a console-less pythonw hears no
    Ctrl+C and no SIGTERM, and `schtasks /End` kills outright, so liminal-signal sets this event before it ends
    anything and App.serve, which looks at it, stops in good order. Elsewhere it is never set (SIGTERM is). `k32`: a
    test's stand-in."""

    def __init__(self, name: str, k32=None):
        self.name = name
        self._k32 = k32
        self._handle = None
        if os.name == "nt" or k32 is not None:
            try:
                k = self._kernel32()
                self._handle = k.CreateEventW(None, 1, 0, name) or None  # manual reset, not set
            except (AttributeError, OSError):
                self._handle = None

    def _kernel32(self):
        if self._k32 is None:
            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.CreateEventW.restype = ctypes.c_void_p
            k.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
            k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            k.WaitForSingleObject.restype = ctypes.c_uint32
            k.CloseHandle.argtypes = [ctypes.c_void_p]
            self._k32 = k
        return self._k32

    def is_set(self) -> bool:
        if self._handle is None:
            return False
        try:
            return self._kernel32().WaitForSingleObject(self._handle, 0) == 0  # WAIT_OBJECT_0
        except (AttributeError, OSError):
            return False

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            try:
                self._kernel32().CloseHandle(handle)
            except (AttributeError, OSError):
                pass


def set_stop_event(name: str, k32=None) -> bool:
    """The stop event `name` set, when an app holds it (OpenEventW, SetEvent). Whether one was."""
    if os.name != "nt" and k32 is None:
        return False
    try:
        if k32 is None:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.OpenEventW.restype = ctypes.c_void_p
            k32.OpenEventW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
            k32.SetEvent.argtypes = [ctypes.c_void_p]
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = k32.OpenEventW(0x0002, 0, name)  # EVENT_MODIFY_STATE
        if not handle:
            return False
        try:
            return bool(k32.SetEvent(handle))
        finally:
            k32.CloseHandle(handle)
    except (AttributeError, OSError):
        return False


def install_handlers(target, signals_=None) -> Callable[[], None]:
    """This process's SIGTERM (and SIGBREAK on Windows, SIGHUP elsewhere) passed to `target.signal(TERM)`, on the main
    thread only. Returns what puts the old handlers back."""
    if threading.current_thread() is not threading.main_thread():
        return lambda: None
    names = signals_ or ("SIGTERM", "SIGBREAK" if os.name == "nt" else "SIGHUP")
    old: dict = {}

    def handler(signum, frame):  # noqa: ARG001 - the signal module's signature
        threading.Thread(target=target.signal, args=(Signal.TERM, deadline_in(TERM_TIMEOUT_S)),
                         name="liminal-signal", daemon=True).start()

    for name in names:
        number = getattr(_signals, name, None)
        if number is None:
            continue
        try:
            old[number] = _signals.signal(number, handler)
        except (OSError, ValueError):
            continue

    def restore() -> None:
        for number, was in old.items():
            try:
                _signals.signal(number, was)
            except (OSError, ValueError, TypeError):
                pass

    return restore


def _python_exe(path: str) -> bool:
    return Path(path or "").name.lower() in ("python", "python.exe", "pythonw.exe", "python3") or \
        re.fullmatch(r"python3(\.\d+)?", Path(path or "").name.lower()) is not None


LIMINAL_MODULE = re.compile(r"(?:^|\s)-m\s+liminal[_a-z0-9.]*\b", re.I)
LIMINAL_SCRIPT = re.compile(r"liminal-[a-z0-9-]+(?:\.exe)?$", re.I)


def is_liminal(p: Proc, venvs: Iterable[str | Path]) -> bool:
    """Whether a process is Liminal's by what it runs: a python of one of `venvs` (or a liminal-* script there) running
    a `-m liminal_...` module. Nothing else (a model server, mongod) is taken by its name: those only by the ledger."""
    folders = {os.path.normcase(str(Path(v))) for v in venvs if v}
    exe = os.path.normcase(str(Path(p.exe).parent)) if p.exe else ""
    if not exe or exe not in folders:
        return False
    if _python_exe(p.exe):
        return bool(LIMINAL_MODULE.search(p.cmdline or ""))
    return bool(LIMINAL_SCRIPT.search(Path(p.exe).name))


def venv_folders() -> list[str]:
    """Where Liminal's interpreters are: this one's folder and its base's (a venv's launcher runs the base's python as
    its child on Windows), and LIMINAL_VENVS (folders, os.pathsep apart)."""
    out = [str(Path(sys.executable).parent)]
    base = getattr(sys, "_base_executable", "") or ""
    if base:
        out.append(str(Path(base).parent))
    out += [v for v in (os.environ.get("LIMINAL_VENVS") or "").split(os.pathsep) if v.strip()]
    return out


# -- the proof of this user's key, for an app that is no liminal-net node yet ----------------------------------------
def proof(key: bytes) -> str:
    """What a signal or an ask carries to an app's route (PROOF_HEADER): an HMAC of PROOF_WORDS under this user's key
    (host.key(), the file liminal-net's handshake and host.py's pipes use), never the key."""
    import hashlib
    import hmac

    return hmac.new(bytes(key), PROOF_WORDS, hashlib.sha256).hexdigest()


def proof_ok(key: bytes, given: str) -> bool:
    import hmac

    return hmac.compare_digest(proof(key), str(given or ""))


# -- what an object is, asked: a read alone --------------------------------------------------------------------------
def shown_rows(rows: Iterable[Row]) -> list[dict]:
    """Ledger rows as they may be shown: each command's secrets hidden (scrub_command)."""
    return [{**asdict(r), "command": scrub_command(r.command)} for r in rows]


def mode_of(obj) -> dict:
    """An object's mode and deadlines, as `ask` answers them."""
    return {"mode": getattr(obj, "MODE", ON_DEMAND), "startDeadline": start_deadline(obj),
            "stopDeadline": stop_deadline(obj)}


def processes_of(name: str, ledger: Ledger | None = None) -> list[dict]:
    """What was started for `name`: this process's own rows, and the ledger's (other processes' spawns for it)."""
    rows = {r.pid: r for r in mine(name)}
    try:
        for r in _ledger(ledger).rows():
            if r.owner == name or r.owner == f"node:{name}":
                rows.setdefault(r.pid, r)
    except OSError:
        pass
    return shown_rows(rows.values())


def ask_of(plugin, what: str, ask: Callable[[str], object] | None = None, apis: Callable[[], dict] | None = None,
           ledger: Ledger | None = None):
    """A plugin asked what it is (`what`: status, interface, apis, needs, mode, processes), reading only. Its status only
    when it answers one that only reads (its READ_HOOKS: liminal_libs.internal.reads_of), asked through `ask` (its
    app's). Its own answer is passed as it is, as its page shows it."""
    name = getattr(plugin, "name", "") or type(plugin).__name__
    if what == "interface":
        return plugin.interface()
    if what == "mode":
        return {"name": name, **mode_of(plugin)}
    if what == "processes":
        return {"name": name, "processes": processes_of(name, ledger)}
    if what == "apis":
        if apis is not None:
            return apis()
        from .apis import as_dicts

        return {"apis": as_dicts(getattr(plugin, "apis", ()))}
    if what == "needs":
        needs = getattr(plugin, "needs", None)
        if callable(needs):
            return {"name": name, "needs": needs()}
        declared = getattr(plugin, "NEEDS", None)
        if declared is not None:
            return {"name": name, "needs": declared}
        return {"name": name, "needs": None, "why": "it declares no needs"}
    if what == "status":
        from .internal import reads_of

        gives = getattr(plugin, "gives", None)
        if not (callable(gives) and gives("status")):
            return {"name": name, "status": None, "why": "it answers no status"}
        if "status" not in reads_of(plugin):
            return {"name": name, "status": None, "why": "its status is not one that only reads: not asked"}
        try:
            return {"name": name, "status": (ask or plugin.ask)("status")}
        except Exception as e:  # noqa: BLE001 - what it could not say is said
            return {"name": name, "status": None, "why": f"{type(e).__name__}: {e}"}
    raise LookupError(f"nothing {what!r} to ask: status, interface, apis, needs, mode or processes")


def claims_held() -> list[str]:
    """The databases this process holds a claim on now (liminal_libs.claims; none when it was never imported)."""
    claims = sys.modules.get("liminal_libs.claims")
    if claims is None:
        return []
    with claims._process_lock:
        return [k for k, m in claims._process.items() if m.claims.held]


def give_back_claims() -> None:
    """Every claim this process holds given back (its end: what claims' atexit does, at once)."""
    claims = sys.modules.get("liminal_libs.claims")
    if claims is not None:
        claims._give_back()


def note(row: Row, ledger: Ledger | None = None) -> Row:
    """A process this process started, written down as spawn writes it (a launcher of its own, a test's stand-in)."""
    with _MINE_LOCK:
        _MINE[row.pid] = row
    try:
        _ledger(ledger).add(row)
    except OSError:
        pass
    return row


class FakeTable:
    """A process table of stand-ins (the conformance's node check, the tests): rows by id, each alive until a signal it
    heeds ends it. `ignores`: ids that do not heed TERM (only KILL ends them). Nothing real is looked up."""

    def __init__(self, rows: Iterable[Proc] = (), ignores: Iterable[int] = ()):
        self.rows = {p.pid: p for p in rows}
        self.ignores = set(ignores)
        self.sent: list[tuple[int, str]] = []

    def list(self) -> list[Proc]:
        return list(self.rows.values())

    def alive(self, pid: int) -> bool:
        return pid in self.rows

    def started(self, pid: int) -> int | None:
        p = self.rows.get(pid)
        return p.started if p is not None else None

    def send(self, pid: int, sig: Signal, group: bool = False) -> bool:  # the table is its own killer
        self.sent.append((pid, Signal.of(sig).value))
        if pid in self.rows and (Signal.of(sig) is Signal.KILL or pid not in self.ignores):
            del self.rows[pid]
        return True


class FakeClock:
    """A clock that moves only when slept on: a deadline is reached by its order, never by waiting."""

    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(seconds, 0.0)


class MemoryLedger(Ledger):
    """A ledger kept in memory (nothing written): the conformance's and the tests'."""

    def __init__(self, table=None):
        super().__init__(Path("<memory>"), table)
        self.kept: list[Row] = []

    def _read(self) -> list[Row]:
        return list(self.kept)

    def _write(self, rows: list[Row]) -> None:
        self.kept = list(rows)

    def _held(self):
        lock = self._lock

        class Held:
            def __enter__(self):
                lock.acquire()

            def __exit__(self, *exc):
                lock.release()
                return False

        return Held()
