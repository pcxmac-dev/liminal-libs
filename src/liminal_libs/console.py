"""A console's two helpers (1.62.0), each a short program of its own:

    python -m liminal_libs.console interrupt PID
    python -m liminal_libs.console hold -- COMMAND ...

`interrupt` delivers Ctrl+C to a program that runs without a window (Windows). A model server its plugin started (the
user, 2026-11-16: "the plugins manage the services") is a console program started windowless, and on Windows such a
program ends cleanly only at Ctrl+C. A process can send Ctrl+C only to the console it is attached to, and it is
attached to one at most, so the platform does not do it itself: this helper, started for the moment
(machines/children.py, `interrupt`), leaves its own console, attaches to the server's (a console all the same, without
a window), turns Ctrl+C off for itself and sends it to everything on that console: the server and what it started.

`hold` runs a command in this console and waits for Enter once it has ended. A harness opened from the platform's page
gets a console window of its own (machines/harness.py), and Windows closes such a window the moment its program ends,
with whatever it said last unread: this keeps it open and says how the program ended.

Both rest on a program hearing Ctrl+C at all. Windows passes a process's "ignore Ctrl+C" attribute on to every program
it starts, and a platform started by a program that had it set (one that gave it a process group of its own, a
detached start) would pass it to its servers and windows, which then never hear Ctrl+C: a Stop would wait out its
grace and end the server by force, and Ctrl+C typed in a harness's window would reach nothing. `hear_ctrl_c` clears
it: children.py does so once before the first server is started, and `hold` before it starts its command.

This module imports the standard library only, and tests/test_console.py reads its imports to prove it. A program of
the machines package loads the plugin contract first, and with it pandas (0.35 s and 80 MB, measured 2026-11-16): a
window that stays open for hours and a helper run at every Stop load none of that here."""
from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import sys

MODULE = "liminal_libs.console"  # what `python -m` runs (its own __name__ is __main__ then, so it is written here)
USAGE = f"python -m {MODULE} interrupt PID\npython -m {MODULE} hold -- COMMAND ..."
CTRL_C_EVENT = 0
CLOSE = "Press Enter to close this window."
_UNCHANGED = object()  # Ctrl+C's handler was left as it was


def program(path) -> str:
    """A program by its name: C:/tools/opencode.exe as opencode."""
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1]
    return name[:-4] if name.lower().endswith(".exe") else name


def with_console(python: str | None = None) -> str:
    """The Python that has a console: `python` (this one unless given), or python.exe beside it where that is
    pythonw.exe, which has none (a platform started at sign-in runs under it)."""
    exe = str(python or sys.executable or "python")
    folder, name = os.path.split(exe)
    if name.lower() == "pythonw.exe" and os.path.exists(os.path.join(folder, "python.exe")):
        return os.path.join(folder, "python.exe")
    return exe


def interrupt_command(pid: int, python: str | None = None) -> list[str]:
    """What delivers Ctrl+C to the process `pid`: this module's `interrupt`, under this Python unless another is
    given. It is started windowless and waited for a few seconds (machines/children.py), in the platform's own
    folder, so with -P: nothing lying there (a signal.py, a ctypes.py) is imported in place of Python's own."""
    return [str(python or sys.executable or "python"), "-P", "-m", MODULE, "interrupt", str(int(pid))]


def hold_command(command, python: str | None = None) -> list[str]:
    """What a harness's window runs: this module's `hold` before `command`, under the Python that has a console. It
    is started in a folder its user picked, so with -P: nothing lying in that folder is imported in place of a module
    of Python's own or of this library."""
    return [with_console(python), "-P", "-m", MODULE, "hold", "--", *(str(c) for c in command)]


def _kernel32():
    """Windows' kernel32 with the five console calls declared; None where there is none (not Windows)."""
    if os.name != "nt":
        return None
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.FreeConsole.restype = ctypes.c_int
        k32.FreeConsole.argtypes = []
        k32.AttachConsole.restype = ctypes.c_int
        k32.AttachConsole.argtypes = [ctypes.c_uint32]
        k32.SetConsoleCtrlHandler.restype = ctypes.c_int
        k32.SetConsoleCtrlHandler.argtypes = [ctypes.c_void_p, ctypes.c_int]
        k32.GenerateConsoleCtrlEvent.restype = ctypes.c_int
        k32.GenerateConsoleCtrlEvent.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        k32.SetConsoleTitleW.restype = ctypes.c_int
        k32.SetConsoleTitleW.argtypes = [ctypes.c_wchar_p]
        return k32
    except (AttributeError, OSError):
        return None


def _last_error() -> int:
    """Windows' number for why its last call failed (0 where it is not known)."""
    try:
        return int(ctypes.get_last_error())
    except AttributeError:  # not Windows
        return 0


def hear_ctrl_c(k32=None) -> bool:
    """This process, and every program it starts from now on, hears Ctrl+C (Windows): the "ignore Ctrl+C" attribute
    it may have been started with is cleared (SetConsoleCtrlHandler(NULL, FALSE)), and so is not passed on. The
    handlers it has are kept: Python's own still turns Ctrl+C into KeyboardInterrupt, or into what `hold` set. It
    changes nothing where this process has no console (pythonw) but what its programs inherit. Whether it was
    cleared: False off Windows, or when Windows refused. `k32`: a test's stand-in for Windows' kernel32."""
    k32 = _kernel32() if k32 is None else k32
    if k32 is None:
        return False
    try:
        return bool(k32.SetConsoleCtrlHandler(None, 0))
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def interrupt(pid: int, k32=None, last_error=None) -> str:
    """Ctrl+C sent to the console the process `pid` runs on, and so to it and to what it started there: "" when it was
    sent, else why not, in words. This process leaves its own console first and ignores the Ctrl+C it sends. `k32`,
    `last_error`: a test's stand-ins for Windows' kernel32 and its error number."""
    pid = int(pid)
    if not 0 < pid < 0xFFFFFFFF or pid == os.getpid():
        return f"{pid} is not the number of a process to interrupt"
    k32 = _kernel32() if k32 is None else k32
    if k32 is None:
        return "Ctrl+C is sent through a console on Windows only: on another system a process is sent a signal"
    why = last_error or _last_error
    k32.FreeConsole()  # a process is attached to one console at most: its own is left (it may have none)
    if not k32.AttachConsole(pid):
        return (f"process {pid} has no console to reach (Windows' error {why()}): it has ended, or it runs "
                "without one")
    if not k32.SetConsoleCtrlHandler(None, 1):  # NULL, TRUE: this process ignores Ctrl+C from here on
        return f"Ctrl+C was not sent to process {pid}: this helper could not turn it off for itself ({why()})"
    if not k32.GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0):  # group 0: every process on the console
        return f"Ctrl+C could not be sent to process {pid}'s console (Windows' error {why()})"
    return ""


def _say(text: str, to=None) -> None:
    """A line printed (on standard output unless told otherwise); never an error: a program without a console has
    nowhere to print."""
    try:
        print(text, file=sys.stdout if to is None else to, flush=True)
    except (AttributeError, OSError, ValueError):
        pass


def _title(text: str) -> None:
    """This console window's title (Windows; nothing elsewhere, or where there is no console)."""
    k32 = _kernel32()
    try:
        if k32 is not None:
            k32.SetConsoleTitleW(str(text))
    except (AttributeError, OSError):
        pass


def _nothing(*_) -> None:
    """Ctrl+C's handler while a held command runs: nothing. (A handler, not "ignore": a program started from here
    inherits an ignored Ctrl+C on Linux, never a handler.)"""


def _until_ended(child) -> int:
    """A started command's exit code, waited for however often Ctrl+C is typed meanwhile: the command hears it too,
    in the same console, and goes on or ends as it sees fit."""
    while True:
        try:
            return child.wait()
        except KeyboardInterrupt:
            continue


def hold(command, *, popen=None, say=None, read=None, title=None) -> int:
    """`command` run in this console, then a last line saying how it ended and a wait for Enter, so the window stays
    until its user has read it: the command's exit code (1 when it could not start). Ctrl+C typed while it runs is
    the command's alone; typed at the last line it closes the window as Enter does. An "ignore Ctrl+C" this window
    was started with (passed on from the platform's own start) is cleared first, so the command hears it.
    `popen`, `say`, `read`, `title`: a test's stand-ins for starting the command, printing a line, the wait for
    Enter and the window's title (a test stands in for Windows' kernel32 through `_kernel32`)."""
    command = [str(c) for c in command]
    name = program(command[0])
    (title or _title)(name)
    say = say or _say
    try:
        old = signal.signal(signal.SIGINT, _nothing)
    except (ValueError, OSError):  # not the main thread: Ctrl+C is caught where the command is waited for instead
        old = _UNCHANGED
    try:
        hear_ctrl_c()  # once `_nothing` holds Ctrl+C here, and before the command starts: it inherits it
        try:
            child = (popen or subprocess.Popen)(command)
        except (OSError, ValueError) as e:  # (ValueError: a NUL in a word)
            code, last = 1, f"{name} could not start: {e}. {CLOSE}"
        else:
            code = _until_ended(child)
            last = f"{name} ended ({code}). {CLOSE}"
        say("")
        say(last)
    finally:
        if old is not _UNCHANGED and old is not None:
            signal.signal(signal.SIGINT, old)
    try:
        (read or input)()
    except (EOFError, KeyboardInterrupt, OSError):
        pass
    return code


def main(argv: list[str] | None = None) -> int:
    """`interrupt PID`: 0 when Ctrl+C was sent, 1 with why not; `hold -- COMMAND ...`: the command's exit code; 2 with
    how it is called for anything else."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 2 and argv[0] == "interrupt" and argv[1].isascii() and argv[1].isdigit():
        why = interrupt(int(argv[1]))
        if why:
            _say(why, sys.stderr)
        return 1 if why else 0
    if len(argv) > 2 and argv[:2] == ["hold", "--"]:
        return hold(argv[2:])
    _say(USAGE, sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
