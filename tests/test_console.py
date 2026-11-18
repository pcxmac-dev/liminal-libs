"""The console's two helpers (liminal_libs.console, 1.62.0): Ctrl+C sent to a windowless program's console through
Windows' four calls in their order, and what is said when one of them fails; an "ignore Ctrl+C" a starter passed on,
cleared; a command held in its window until its user has read how it ended, the command hearing Ctrl+C; how the
module is called; and that it imports the standard library alone. Windows' calls, the command and the Enter are
stand-ins: no process is started (the shared guard, `no_outside`, fails a test that does) and no console is
touched."""
from __future__ import annotations

import os
import signal
import sys
import threading

import pytest

from conftest import Reached
from liminal_libs import console

from test_instances_shared import _outside, loaded_by

pytestmark = pytest.mark.usefixtures("no_outside")

LAST = "Press Enter to close this window."
HEAR = ("SetConsoleCtrlHandler", None, 0)  # NULL, FALSE: Ctrl+C heard again


def refusing(what):
    def refused(*a, **k):
        raise Reached(f"a test reached for the real {what}")
    return refused


class Kernel32:
    """Windows' kernel32 as a stand-in: each call noted, answering 1 (done) unless the test says 0 (failed)."""

    def __init__(self, **answers):
        self.calls: list[tuple] = []
        self.answers = answers

    def _call(self, name, *args):
        self.calls.append((name, *args))
        return self.answers.get(name, 1)

    def FreeConsole(self):
        return self._call("FreeConsole")

    def AttachConsole(self, pid):
        return self._call("AttachConsole", pid)

    def SetConsoleCtrlHandler(self, handler, add):
        return self._call("SetConsoleCtrlHandler", handler, add)

    def GenerateConsoleCtrlEvent(self, event, group):
        return self._call("GenerateConsoleCtrlEvent", event, group)


@pytest.fixture(autouse=True)
def k32(monkeypatch):
    """This machine's console is never reached for real: Windows' kernel32 is a stand-in that notes each call, and
    the window's title is refused."""
    stand_in = Kernel32()
    monkeypatch.setattr(console, "_kernel32", lambda: stand_in)
    monkeypatch.setattr(console, "_title", refusing("console window's title"))
    return stand_in


# -- interrupt ---------------------------------------------------------------------------------------------------------
def test_ctrl_c_is_sent_through_windows_four_calls_in_their_order():
    k32 = Kernel32(FreeConsole=0)  # the helper had no console of its own to leave: it goes on all the same
    assert console.interrupt(4321, k32=k32) == ""
    assert k32.calls == [("FreeConsole",), ("AttachConsole", 4321), ("SetConsoleCtrlHandler", None, 1),
                         ("GenerateConsoleCtrlEvent", console.CTRL_C_EVENT, 0)]
    assert console.CTRL_C_EVENT == 0  # Ctrl+C, to group 0: every process on that console


def test_a_program_without_a_console_is_said_and_nothing_is_sent():
    k32 = Kernel32(AttachConsole=0)
    said = console.interrupt(4321, k32=k32, last_error=lambda: 6)
    assert said.startswith("process 4321 has no console to reach (Windows' error 6)") and "it has ended" in said
    assert k32.calls == [("FreeConsole",), ("AttachConsole", 4321)]
    deaf = Kernel32(SetConsoleCtrlHandler=0)  # it could not turn Ctrl+C off for itself: it sends none
    assert "Ctrl+C was not sent to process 4321" in console.interrupt(4321, k32=deaf, last_error=lambda: 5)
    assert [c[0] for c in deaf.calls] == ["FreeConsole", "AttachConsole", "SetConsoleCtrlHandler"]
    unsent = Kernel32(GenerateConsoleCtrlEvent=0)
    assert console.interrupt(4321, k32=unsent, last_error=lambda: 87) == (
        "Ctrl+C could not be sent to process 4321's console (Windows' error 87)")


def test_what_is_no_other_process_number_is_attached_to_nothing():
    k32 = Kernel32()
    for pid in (0, -1, 0xFFFFFFFF, os.getpid()):  # (0xFFFFFFFF is Windows' word for "my parent's console")
        assert console.interrupt(pid, k32=k32) == f"{pid} is not the number of a process to interrupt"
    assert k32.calls == []


def test_off_windows_it_says_that_ctrl_c_is_windows(monkeypatch):
    monkeypatch.setattr(console, "_kernel32", lambda: None)
    assert console.interrupt(4321).startswith("Ctrl+C is sent through a console on Windows only")
    assert console._last_error() >= 0  # a number on every system
    assert console.hear_ctrl_c() is False  # nothing to clear


# -- Ctrl+C heard ------------------------------------------------------------------------------------------------------
def test_an_ignore_ctrl_c_passed_on_by_a_starter_is_cleared(k32):
    # NULL, FALSE: the attribute alone; the handlers this process has (Python's own) are kept
    assert console.hear_ctrl_c() is True and k32.calls == [HEAR]
    refused = Kernel32(SetConsoleCtrlHandler=0)
    assert console.hear_ctrl_c(k32=refused) is False and refused.calls == [HEAR]

    class Broken:
        def SetConsoleCtrlHandler(self, handler, add):
            raise OSError("no console here")
    assert console.hear_ctrl_c(k32=Broken()) is False  # never an error


# -- hold --------------------------------------------------------------------------------------------------------------
class Command:
    """A started command as a stand-in: its exit code once waited for, a Ctrl+C heard first when the test says so."""

    def __init__(self, code=0, ctrl_c=0):
        self.code, self.ctrl_c = code, ctrl_c
        self.handlers: list = []

    def wait(self):
        self.handlers.append(signal.getsignal(signal.SIGINT))
        if self.ctrl_c:
            self.ctrl_c -= 1
            raise KeyboardInterrupt
        return self.code


def held(command, code=0, ctrl_c=0, read=None):
    """`hold` over stand-ins: (its answer, the lines it said, what was started, how, and what had been asked of
    Windows by then, the titles, the command)."""
    said, started, titles, reads = [], [], [], []
    made = Command(code, ctrl_c)
    k32 = console._kernel32()

    def popen(argv, **kw):
        started.append((list(argv), kw, list(k32.calls)))
        return made

    def enter():
        reads.append("read")
        if read is not None:
            raise read
    answer = console.hold(command, popen=popen, say=said.append, read=enter, title=titles.append)
    assert reads == ["read"]  # the window waits for its user once, whatever happened
    return answer, said, started, titles, made


def test_a_held_command_runs_in_this_console_and_the_last_line_says_how_it_ended():
    before = signal.getsignal(signal.SIGINT)
    answer, said, started, titles, made = held(["C:\\tools\\opencode.exe", "--model", "qwen3:8b"])
    assert answer == 0 and said == ["", f"opencode ended (0). {LAST}"]
    # nothing redirected, no flag: this console is the command's; and Ctrl+C is heard in it, cleared before it starts
    assert started == [(["C:\\tools\\opencode.exe", "--model", "qwen3:8b"], {}, [HEAR])]
    assert titles == ["opencode"]
    assert made.handlers == [console._nothing]  # Ctrl+C typed while it runs does not end the holder
    assert signal.getsignal(signal.SIGINT) is before  # and is as it was afterwards
    answer, said, *_ = held(["aider"], code=3)
    assert answer == 3 and said[-1] == f"aider ended (3). {LAST}"


def test_ctrl_c_and_a_closed_input_never_take_the_last_line_away():
    answer, said, _, _, made = held(["aider"], code=1, ctrl_c=2)  # heard twice where it is waited for: waited again
    assert answer == 1 and len(made.handlers) == 3 and said[-1] == f"aider ended (1). {LAST}"
    for closed in (EOFError(), KeyboardInterrupt(), OSError("no console")):  # no Enter can come: it ends there
        assert held(["aider"], read=closed)[0] == 0


def test_a_command_that_cannot_start_is_said_and_the_window_still_waits():
    said, reads = [], []

    def missing(argv, **kw):
        raise FileNotFoundError("no such program")
    assert console.hold(["cn", "--config", "x.yaml"], popen=missing, say=said.append,
                        read=lambda: reads.append("read"), title=lambda t: None) == 1
    assert said == ["", f"cn could not start: no such program. {LAST}"] and reads == ["read"]

    def refused(argv, **kw):
        raise ValueError("embedded null byte")
    assert console.hold(["cn", "x\0"], popen=refused, say=said.append, read=lambda: None, title=lambda t: None) == 1
    assert said[-1] == f"cn could not start: embedded null byte. {LAST}"  # said, not a traceback that closes it


def test_off_the_main_thread_ctrl_c_is_left_as_it_is():
    before = signal.getsignal(signal.SIGINT)
    answers: list = []
    thread = threading.Thread(target=lambda: answers.append(held(["aider"], code=2)), daemon=True)
    thread.start()
    thread.join(10)
    answer, said, _, _, made = answers[0]
    assert answer == 2 and said[-1] == f"aider ended (2). {LAST}"
    assert made.handlers == [before] and signal.getsignal(signal.SIGINT) is before


# -- how it is called --------------------------------------------------------------------------------------------------
def test_how_the_module_is_called(monkeypatch, capsys):
    asked: list = []
    whys = {4321: "", 99: "process 99 has no console to reach"}
    monkeypatch.setattr(console, "interrupt", lambda pid: asked.append(pid) or whys[pid])
    monkeypatch.setattr(console, "hold", lambda command: asked.append(command) or 7)
    assert console.main(["interrupt", "4321"]) == 0 and capsys.readouterr().err == ""
    assert console.main(["interrupt", "99"]) == 1 and capsys.readouterr().err == "process 99 has no console to reach\n"
    assert console.main(["hold", "--", "opencode", "--model", "x"]) == 7  # the command's own exit code
    assert asked == [4321, 99, ["opencode", "--model", "x"]]
    for wrong in ([], ["interrupt"], ["interrupt", "abc"], ["interrupt", "-5"], ["interrupt", "\u00b2"],
                  ["interrupt", "1", "2"], ["hold"], ["hold", "--"], ["hold", "opencode"], ["serve", "x"]):
        assert console.main(wrong) == 2 and capsys.readouterr().err == console.USAGE + "\n"
    assert len(asked) == 3  # nothing wrong was passed on
    assert "interrupt PID" in console.USAGE and "hold -- COMMAND ..." in console.USAGE


def test_the_commands_that_run_it(tmp_path):
    assert console.MODULE == console.__name__ == "liminal_libs.console"
    # both with -P: the helper runs in the platform's folder, a window in one its user picked, and nothing lying there
    # is imported in place of a module of Python's own or of this library
    assert console.interrupt_command(4321, python="py") == ["py", "-P", "-m", "liminal_libs.console", "interrupt",
                                                            "4321"]
    assert console.interrupt_command(4321)[0] == sys.executable
    with pytest.raises(ValueError):
        console.interrupt_command("4321; calc")  # a number and nothing else
    assert console.hold_command(["opencode", "--model", "x"], python="py") == [
        "py", "-P", "-m", "liminal_libs.console", "hold", "--", "opencode", "--model", "x"]
    quiet = tmp_path / "pythonw.exe"
    quiet.write_bytes(b"")
    assert console.with_console(str(quiet)) == str(quiet)  # no python.exe beside it: as it is
    (tmp_path / "python.exe").write_bytes(b"")
    assert console.with_console(str(quiet)) == os.path.join(str(tmp_path), "python.exe")
    assert console.hold_command(["aider"], python=str(quiet))[0].endswith("python.exe")
    assert console.with_console() == console.with_console(sys.executable) and console.with_console("py") == "py"


def test_a_program_is_called_by_its_name_and_a_line_is_never_an_error(monkeypatch):
    assert console.program("C:\\tools\\opencode.exe") == "opencode" and console.program("/usr/bin/aider") == "aider"
    assert console.program("OLLAMA.EXE") == "OLLAMA" and console.program("cn") == "cn"
    monkeypatch.setattr(sys, "stdout", None)  # a program without a console (pythonw) has nowhere to print
    console._say("nobody reads this")

    class Shut:
        def write(self, text):
            raise OSError("closed")
    console._say("nor this", Shut())


# -- plain: what importing it loads ------------------------------------------------------------------------------------
def test_the_module_imports_the_standard_library_alone():
    assert loaded_by("liminal_libs.console") == {"liminal_libs", "liminal_libs.console"}
    for module in ("liminal_libs.console", "liminal_libs"):
        assert _outside(module) <= set(sys.stdlib_module_names), (module, _outside(module))
    # what it is kept clear of: a program of the machines package loads the plugin contract before its first line
    assert "liminal_libs.sources.plugin" in loaded_by("liminal_libs.machines.keep")
