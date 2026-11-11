"""A command kept running (1.47.0, the boot services on Windows): Task Scheduler starts a task again only when it could
not start it, never when its program ends with an error, so a boot task runs its app through this keeper:

    python -m liminal_libs.machines.keep --log PATH [--delay S] -- COMMAND ...

It starts the command windowless, notes each start and end in the log with the command's own error output (its
ordinary output is the app's own log's business), starts it again after a failure (`delay` s, doubling up to
MAX_DELAY_S while it keeps failing soon after it starts, back to `delay` once it has run STEADY_S), and ends when the
command ends well (exit 0: stopped as asked). On Windows the command, and whatever it starts, is held in a job object
that ends them with the keeper, so ending the task (Stop-ScheduledTask) ends the app too. Linux's boot services need
none of it: systemd (Restart=on-failure) and OpenRC (supervise-daemon) start them again themselves."""
from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

DELAY_S = 10.0  # the first wait after a failure
MAX_DELAY_S = 600.0  # the longest wait while it keeps failing
STEADY_S = 600.0  # a run this long brings the wait back to the first
LOG_MAX_BYTES = 1_000_000  # the log is moved to <log>.1 past this, between runs
KILL_ON_JOB_CLOSE = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
EXTENDED_LIMITS = 9  # JobObjectExtendedLimitInformation


class _Basic(ctypes.Structure):  # JOBOBJECT_BASIC_LIMIT_INFORMATION
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", ctypes.c_uint32), ("SchedulingClass", ctypes.c_uint32)]


class _Io(ctypes.Structure):  # IO_COUNTERS
    _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                               "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _Extended(ctypes.Structure):  # JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    _fields_ = [("BasicLimitInformation", _Basic), ("IoInfo", _Io), ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def note(log: Path, line: str) -> None:
    """A line of the keeper's own in its log (never raises: a log that cannot be written is skipped)."""
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat(timespec='seconds')} keep: {line}\n")
    except OSError:
        pass


def rotate(log: Path, most: int = LOG_MAX_BYTES) -> None:
    """The log moved to <log>.1 once it has grown past `most` bytes (between runs: the command holds it while it runs)."""
    try:
        if log.stat().st_size >= most:
            log.replace(log.with_name(log.name + ".1"))
    except OSError:
        pass


def words(command: list[str]) -> str:
    return subprocess.list2cmdline(command) if os.name == "nt" else " ".join(command)


def _job():
    """A job object ending what it holds when the keeper ends (Windows); None elsewhere, or when none can be made."""
    if os.name != "nt":
        return None
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = ctypes.c_void_p
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        k32.SetInformationJobObject.restype = ctypes.c_int
        k32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _Extended()
        info.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE
        if not k32.SetInformationJobObject(job, EXTENDED_LIMITS, ctypes.byref(info), ctypes.sizeof(info)):
            return None
        return job
    except (AttributeError, OSError):
        return None


def _hold(job, proc) -> bool:
    """`proc` put in the job (it ends with the keeper); False when it cannot be."""
    if job is None:
        return False
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.AssignProcessToJobObject.restype = ctypes.c_int
        k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        return bool(k32.AssignProcessToJobObject(job, int(proc._handle)))
    except (AttributeError, OSError):
        return False


def run_once(command: list[str], log: Path, job=None) -> int:
    """The command run to its end, windowless, its error output appended to the log; its exit code. It starts a process:
    tests stand in for it (`keep`'s `run`)."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as err:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err, close_fds=True,
                                creationflags=0x08000000 if os.name == "nt" else 0)  # CREATE_NO_WINDOW
        if job is not None and not _hold(job, proc):
            note(log, "it could not be held in a job: stopping the task may leave it running")
        try:
            return proc.wait()
        except BaseException:  # the keeper told to end (Ctrl+C, SystemExit): the command too
            proc.terminate()
            raise


def keep(command: list[str], log: Path, delay: float = DELAY_S, longest: float = MAX_DELAY_S, steady: float = STEADY_S,
         run=None, sleep=time.sleep, clock=time.monotonic, rounds: int | None = None) -> int:
    """Run `command` until it ends well (exit 0), starting it again after each failure, waiting `delay` s at first and
    twice as long after each failure that came soon after its start (up to `longest`), back to `delay` once a run has
    lasted `steady` s; each start and end noted in the log. `run() -> exit code` stands in for the command in tests;
    `rounds`: a test's number of runs at most."""
    log = Path(log)
    job = _job() if run is None else None
    run = run or (lambda: run_once(command, log, job))
    wait, runs = float(delay), 0
    while True:
        rotate(log)
        note(log, f"starting {words(command)}")
        began = clock()
        try:
            code = run()
        except OSError as e:
            code = None
            note(log, f"it could not start: {e}")
        runs += 1
        if code == 0:
            note(log, "it ended well (exit 0): not started again")
            return 0
        lasted = clock() - began
        if lasted >= steady:
            wait = float(delay)
        if rounds is not None and runs >= rounds:
            note(log, f"it ended with {code} after {lasted:.0f} s: not started again ({runs} runs)")
            return code if isinstance(code, int) and code else 1
        note(log, f"it ended with {code} after {lasted:.0f} s: started again in {wait:g} s")
        sleep(wait)
        wait = min(wait * 2, float(longest))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv or argv.index("--") == len(argv) - 1:
        print("python -m liminal_libs.machines.keep --log PATH [--delay S] -- COMMAND ...", file=sys.stderr)
        return 2
    i = argv.index("--")
    p = argparse.ArgumentParser(prog="python -m liminal_libs.machines.keep", description="Keep a command running: started again after a failure.")
    p.add_argument("--log", required=True, help="where its starts, its ends and its error output go")
    p.add_argument("--delay", type=float, default=DELAY_S, help=f"the first wait after a failure, in seconds ({DELAY_S:g})")
    args = p.parse_args(argv[:i])
    return keep(argv[i + 1:], Path(args.log), delay=max(args.delay, 1.0))


if __name__ == "__main__":
    sys.exit(main())
