"""A command run to its end or, past its timeout, ended together with what it started (1.80.0).

The review of 2026-11-21, item 26 (its 8th and 9th): subprocess.run's timeout kills only the direct child. A Hyper-V
job or a package update powershell.exe had started went on after the change was reported failed, so a retry did it
twice; behind sudo the real command went on too. Here a child starts in its own session on Linux (its process group
is its pid), and on a timeout the whole tree is ended: on Windows with taskkill /T /F by pid (windowless), on Linux
its process group asked to stop (SIGTERM, which sudo passes on to the command it runs as root, where this process
may not signal it) and killed a few seconds later. What cannot be reached from here is not: a process behind UAC
(elevated, refused to an unelevated taskkill), and the Linux side of wsl.exe (its own kernel's processes). The
machines/children.py supervisor is the long-running children's; this is for a command waited for.
"""
from __future__ import annotations

import os
import signal
import subprocess
from typing import Callable

CREATE_NO_WINDOW = 0x08000000
TERM_GRACE_S = 5.0  # a Linux group asked to stop is killed after this long
DRAIN_S = 5.0  # what is left of the output is read this long once the tree was ended (a survivor may hold the pipe)


def _nt() -> bool:
    return os.name == "nt"


def spawn_args(nt: bool | None = None) -> dict:
    """Popen's arguments for a child ended with its tree: windowless on Windows, its own session on Linux."""
    nt = _nt() if nt is None else nt
    return {"creationflags": CREATE_NO_WINDOW} if nt else {"start_new_session": True}


def kill_tree(proc, nt: bool | None = None, run: Callable | None = None, killpg: Callable | None = None,
              grace: float = TERM_GRACE_S) -> None:
    """`proc` and what it started ended. Windows: taskkill /T /F /PID (the tree by parent, found while `proc` lives),
    then `proc` itself. Linux: its group (its own session's: `spawn_args`) sent SIGTERM, then SIGKILL after `grace`
    s unless `proc` ended sooner (what it started may still be stopping: killed all the same)."""
    nt = _nt() if nt is None else nt
    if nt:
        try:
            (run or subprocess.run)(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, timeout=30,
                creationflags=CREATE_NO_WINDOW)
        except (OSError, subprocess.SubprocessError):
            pass  # proc.kill below still ends the direct child
    else:
        killpg = killpg or getattr(os, "killpg", None)
        if killpg is not None:
            try:
                killpg(proc.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass
            try:
                killpg(proc.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
            except OSError:
                pass  # the group is gone (or not this process's to signal)
    try:
        proc.kill()
    except OSError:
        pass


def run(args, timeout: float, input=None, text: bool = False, env=None,
        popen: Callable | None = None, kill: Callable | None = None) -> subprocess.CompletedProcess:
    """subprocess.run(args, capture_output=True, timeout=timeout, input=input, text=text), but a timeout ends the
    child's whole tree before subprocess.TimeoutExpired is raised (as subprocess.run raises it)."""
    popen, kill = popen or subprocess.Popen, kill or kill_tree
    with popen(args, stdin=subprocess.PIPE if input is not None else None, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, text=text, env=env, **spawn_args()) as proc:
        try:
            out, err = proc.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired:
            kill(proc)
            try:
                proc.communicate(timeout=DRAIN_S)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                pass
            raise subprocess.TimeoutExpired(args, timeout) from None
        except BaseException:
            kill(proc)
            raise
        return subprocess.CompletedProcess(args, proc.returncode, out, err)
