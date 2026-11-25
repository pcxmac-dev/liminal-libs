"""A command run to its end or, past its timeout, ended together with what it started (1.80.0).

The review of 2026-11-21, item 26 (its 8th and 9th): subprocess.run's timeout kills only the direct child. A Hyper-V
job or a package update powershell.exe had started went on after the change was reported failed, so a retry did it
twice; behind sudo the real command went on too. Here a child starts in its own session on Linux (its process group
is its pid), and on a timeout the whole tree is ended: on Windows with taskkill /T /F by pid (windowless), on Linux
its process group asked to stop (SIGTERM, which sudo passes on to the command it runs as root, where this process
may not signal it) and killed a few seconds later. What cannot be reached from here is not: a process behind UAC
(elevated, refused to an unelevated taskkill), and the Linux side of wsl.exe (its own kernel's processes). The
machines/children.py supervisor is the long-running children's; this is for a command waited for.

1.88.4 (the user, 2026-11-24: "all shutdowns need to be clean"): a timeout asks, it never forces. The tree is asked to
end (Windows: taskkill /T without /F, a polite close; Linux: SIGTERM to its group, which sudo passes on) and given
TERM_GRACE_S; one still running then is left as it is and said (StillRunning, a TimeoutExpired), never killed: a git
killed mid-write leaves its index.lock and a half-written object, a Hyper-V job or an installer a half-made change.
"""
from __future__ import annotations

import os
import signal
import subprocess
from typing import Callable

CREATE_NO_WINDOW = 0x08000000
_POPEN = subprocess.Popen  # the real class, as imported: ask_end's taskkill is for a real child alone
TERM_GRACE_S = 5.0  # a Linux group asked to stop is killed after this long
DRAIN_S = 5.0  # what is left of the output is read this long once the tree was ended (a survivor may hold the pipe)


def _nt() -> bool:
    return os.name == "nt"


def spawn_args(nt: bool | None = None) -> dict:
    """Popen's arguments for a child ended with its tree: windowless on Windows, its own session on Linux."""
    nt = _nt() if nt is None else nt
    return {"creationflags": CREATE_NO_WINDOW} if nt else {"start_new_session": True}


class StillRunning(subprocess.TimeoutExpired):
    """A command past its timeout that was asked to end and is still running: left as it is, never killed (1.88.4)."""

    def __init__(self, cmd, timeout, pid=None):
        super().__init__(cmd, timeout)
        self.pid = pid

    def __str__(self) -> str:
        return f"{super().__str__()} It was asked to end and is still running (pid {self.pid}): left, not killed."


def kill_tree(proc, nt: bool | None = None, run: Callable | None = None, killpg: Callable | None = None,
              grace: float = TERM_GRACE_S) -> bool:
    """`proc` and what it started asked to end, never forced (1.88.4; its name kept for its callers). Windows:
    taskkill /T /PID without /F (the tree by parent, a polite close). Linux: its group (its own session's:
    `spawn_args`) sent SIGTERM. Then `grace` s for `proc` to end. Whether it ended: one still running is left."""
    nt = _nt() if nt is None else nt
    if nt:
        try:
            (run or subprocess.run)(["taskkill", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=30,
                creationflags=CREATE_NO_WINDOW)
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        killpg = killpg or getattr(os, "killpg", None)
        try:
            if killpg is not None:
                killpg(proc.pid, signal.SIGTERM)
            else:
                proc.terminate()
        except OSError:
            pass  # the group is gone (or not this process's to signal)
    try:
        proc.wait(timeout=grace)
        return True
    except subprocess.TimeoutExpired:
        return False
    except OSError:
        return True


def ask_end(proc, grace: float = TERM_GRACE_S, nt: bool | None = None, run: Callable | None = None) -> bool:
    """One child (a Popen) and what it started asked to end, never forced (1.88.4, the user's "all shutdowns need to
    be clean"; the library's other forcing places): Windows, taskkill /T /PID without /F (a polite close); elsewhere
    its own terminate() (SIGTERM). Then `grace` s for it to end. Whether it ended: one still running is left, and its
    caller says so. A stand-in (no real Popen, and no `run` given) is asked by its own terminate(), never taskkill."""
    poll, wait = getattr(proc, "poll", None), getattr(proc, "wait", None)
    try:
        if callable(poll) and poll() is not None:
            return True
    except (OSError, ValueError):
        return True
    nt = _nt() if nt is None else nt
    try:
        if nt and (run is not None or isinstance(proc, _POPEN)):
            (run or subprocess.run)(["taskkill", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=30,
                creationflags=CREATE_NO_WINDOW)
        elif callable(getattr(proc, "terminate", None)):
            proc.terminate()
    except (OSError, subprocess.SubprocessError):
        pass
    if not callable(wait):
        return not callable(poll) or poll() is not None
    try:
        wait(timeout=grace)
    except subprocess.TimeoutExpired:
        return False
    except OSError:
        return True
    return not callable(poll) or poll() is not None


def run(args, timeout: float, input=None, text: bool = False, env=None,
        popen: Callable | None = None, kill: Callable | None = None) -> subprocess.CompletedProcess:
    """What subprocess's run does with capture_output=True, timeout, input and text, but a timeout asks the child's
    whole tree to end before subprocess.TimeoutExpired is raised (as that run raises it): StillRunning, its pid named,
    when it is still running then, left and not waited for (1.88.4). Not written as a call here: the charts' test of
    every start (test_no_console_windows) reads every such call written in a module's text."""
    popen, kill = popen or subprocess.Popen, kill or kill_tree
    nt = _nt()
    # spawn_args() said outright (the charts' test of every start reads creationflags in each call's text): windowless
    # on Windows, its own session elsewhere (creationflags must be 0 off Windows; start_new_session is POSIX's)
    # not a `with`: its end waits for the child, and one left running past its timeout is not waited for (1.88.4)
    proc = popen(args, stdin=subprocess.PIPE if input is not None else None, stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE, text=text, env=env, creationflags=CREATE_NO_WINDOW if nt else 0,
                 start_new_session=not nt)
    try:
        out, err = proc.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        if kill(proc) is False:
            raise StillRunning(args, timeout, getattr(proc, "pid", None)) from None
        try:
            proc.communicate(timeout=DRAIN_S)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass
        raise subprocess.TimeoutExpired(args, timeout) from None
    except BaseException:
        kill(proc)
        raise
    return subprocess.CompletedProcess(args, proc.returncode, out, err)
