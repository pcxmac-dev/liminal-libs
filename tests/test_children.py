"""A child a plugin owns and a command's lines (liminal_libs.machines.children, 1.62.0): how a child is started on
each system, its log written by a thread and moved aside past its size (closed first, and kept within bounds when it
cannot be moved), the launch's secrets kept out of it, its pidfile's numbers, what its environment drops, how it is
stopped (asked, given its grace on a stand-in clock, ended; twice safe), its end seen by a thread of its own even
while what it started holds its output, a child of an earlier run adopted, what a child owns, this process's Ctrl+C
heard again before its first child, a streamed command's lines with its timeout and its cancel (kept while something
out of its reach holds its output), every child stopped side by side, and a launch shown as lines for both shells,
quoted so that no word can end its string early, with no secret among them, and refused where Windows PowerShell 5.1
would not hand a word over as it is (a model of how it passes words, measured on it).

A piped child (1.66.0, an MCP server over stdio): its three pipes and how it is started on each system, its job
object, its lines handed on as they come, its errors in its log, a line sent, a line too long or one its plugin cannot
take ending it, a stop that closes its input first (and one a send that is not read cannot hold up), the SIGTERM and
SIGKILL that follow on Linux, an earlier run's child ended before the next one starts, and every one stopped at exit.

Everything outside is a stand-in: subprocess.Popen, the console's Ctrl+C, Windows' kernel32, the job object, the
signals, this machine's process table and the clock. The shared guard (`no_outside`) fails a test that starts a
process or opens a connection; this file's own fails one that tells a process of this machine anything by its
number, or reaches its job objects or its console."""
from __future__ import annotations

import dataclasses
import io
import os
import random
import re
import shlex
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from conftest import Reached
from liminal_libs import console
from liminal_libs import proc as proc_mod
from liminal_libs.machines import children, windows
from liminal_libs.machines import keep as keep_mod
from liminal_libs.machines.children import (GRACE_S, LINE_CHARS, LOG_MAX, PLACEHOLDER, Child, ChildError, Launch,
                                            environment, shown, stream)
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.terminal import Cancelled, Output

pytestmark = pytest.mark.usefixtures("no_outside")

NAME = "ollama default"
ROTATE = keep_mod.rotate  # the real one: a test's stand-in looks, then lets it move the file
REAL_RUN = children._run  # the real one: a test puts it back over its refusal to see how it runs the helper
MADE: list = []  # every stand-in process of the test that runs: ended after it, so no reader's thread is left
REACHED: list = []  # what a test reached through one of this file's refusals: it fails at its end, even if caught
QUOTES = "'\u2018\u2019\u201a\u201b"  # what PowerShell ends a single-quoted string at: ' ‘ ’ ‚ ‛


def refusing(what):
    def refused(*a, **k):
        REACHED.append(what)
        raise Reached(f"a test reached for the real {what}")
    return refused


class Kernel32:
    """Windows' kernel32 as this module asks it (through console.hear_ctrl_c), a stand-in: each call noted."""

    def __init__(self):
        self.calls: list[tuple] = []

    def SetConsoleCtrlHandler(self, handler, add):
        self.calls.append(("SetConsoleCtrlHandler", handler, add))
        return 1


@pytest.fixture(autouse=True)
def k32(monkeypatch):
    """This process's console is never asked anything for real: kernel32 is a stand-in."""
    stand_in = Kernel32()
    monkeypatch.setattr(console, "_kernel32", lambda: stand_in)
    return stand_in


@pytest.fixture(autouse=True)
def nothing_real(monkeypatch):
    """Nothing real is reached that the shared guard does not cover: no signal or end sent to a number, no job object,
    no helper run; this machine's process table knows no number; atexit is a list (what a test registered there);
    this process's Ctrl+C is as at its start."""
    REACHED.clear()
    for name in ("kill", "killpg", "waitid", "getsid", "getpgid"):
        monkeypatch.setattr(os, name, refusing(f"os.{name}"), raising=False)
    monkeypatch.setattr(proc_mod, "terminate", refusing("proc.terminate"))
    monkeypatch.setattr(proc_mod, "pid_alive", lambda pid: False)
    monkeypatch.setattr(proc_mod, "started", lambda pid: None)
    monkeypatch.setattr(keep_mod, "_job", lambda: None)
    for name in ("_end_job", "_close_job", "_in_job", "_run"):
        monkeypatch.setattr(children, name, refusing(f"children.{name}"))
    hooked: list = []
    monkeypatch.setattr(children, "atexit", types.SimpleNamespace(register=hooked.append))
    monkeypatch.setattr(children, "_hooked", False)
    monkeypatch.setattr(children, "_all", [])
    monkeypatch.setattr(children, "_ctrl_c_cleared", False)
    yield hooked
    for process in MADE:  # (before the stand-ins above are taken away again)
        process.end(0)
    MADE.clear()
    for thread in threading.enumerate():
        if thread.name.startswith("child-"):
            thread.join(10)
    assert not REACHED, f"a test reached for the real thing: {REACHED}"


# -- stand-ins ---------------------------------------------------------------------------------------------------------
class Pipe(io.RawIOBase):
    """A process's output: pieces as they come, then the end (as tests/test_terminal.py's)."""

    def __init__(self):
        self.chunks: list[bytes] = []
        self.done = threading.Event()

    def readable(self):
        return True

    def read(self, n=-1):
        while not self.chunks and not self.done.is_set():
            time.sleep(0.005)
        return self.chunks.pop(0) if self.chunks else b""


class Process:
    """A started process as a stand-in: what it was started with, what it was told, its end when the test says. A
    wait without a timeout lasts until its end, as a real one's does (10 s at most: the test then ends it)."""

    def __init__(self, argv, pid=4321, **kw):
        self.argv, self.kw, self.pid = list(argv), kw, pid
        self.stdout = Pipe()
        self.returncode = None
        self.told: list[str] = []
        self.deaf = False  # asked to end (terminate), it goes on
        self.ended = threading.Event()
        MADE.append(self)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            if timeout is not None:
                raise subprocess.TimeoutExpired(self.argv, timeout)
            self.ended.wait(10)
        return self.returncode

    def leave(self, code=0):
        """It ends; a program it started still holds its output open."""
        if self.returncode is None:
            self.returncode = code
        self.ended.set()

    def end(self, code=0):
        self.leave(code)
        self.stdout.done.set()

    def terminate(self):
        self.told.append("terminate")
        if not self.deaf:
            self.end(-15)

    def kill(self):
        self.told.append("kill")
        self.end(-9)


class Real(children._Popen):
    """A process as the real subprocess.Popen makes one, as far as isinstance can tell; nothing is started. It has
    ended (`code`) before it is collected (`returncode`), as a real one, and notes when it is collected."""

    def __init__(self, argv, pid=4321, **kw):  # (the real __init__ starts a process: never called)
        self.argv, self.kw, self.pid = list(argv), kw, pid
        self.stdout = Pipe()
        self.returncode = None
        self.code = None
        self.deaf = False
        self.events: list = []
        self.waits: list[float] = []
        self.ended = threading.Event()
        MADE.append(self)

    def leave(self, code=0):
        """It ends; a program it started still holds its output open."""
        if self.code is None:
            self.code = code
        self.ended.set()

    def end(self, code=0):
        self.leave(code)
        self.stdout.done.set()

    def poll(self):
        if self.code is not None and self.returncode is None:
            self.events.append("collected")
            self.returncode = self.code
        return self.returncode

    def wait(self, timeout=None):
        if timeout is not None:
            self.waits.append(timeout)
            if self.code is None:
                raise subprocess.TimeoutExpired(self.argv, timeout)
        elif self.code is None:
            self.ended.wait(10)
        return self.poll()

    def kill(self):
        self.events.append("kill")
        self.end(-9)


class Starter:
    """subprocess.Popen as a stand-in: every process it made, numbered from `first` (or as the test names it)."""

    def __init__(self, first=4321, kind=Process):
        self.made: list = []
        self.first, self.kind = first, kind

    def __call__(self, argv, pid=None, **kw):
        self.made.append(self.kind(argv, pid=self.first + len(self.made) if pid is None else pid, **kw))
        return self.made[-1]


class Clock:
    """A clock that is a second later at every look: a grace passes without a wait."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 1.0
        return self.now


def make(folder, system, launch=None, starter=None, **outside):
    """A child over stand-ins, in a folder of its own: (the child, what stands in for Popen)."""
    starter = starter or Starter()
    outside.setdefault("clock", Clock())
    outside.setdefault("sleep", lambda seconds: None)
    child = Child(NAME, launch or Launch(("ollama", "serve")), Path(folder) / "logs" / "default.log",
                  Path(folder) / "run" / "default.pid", popen=starter, system=system, **outside)
    return child, starter


def settle(child):
    """The reader's thread has read the child's output to its end, and the watcher's has seen its end and cleaned up
    after it."""
    for thread in (child._reader, child._watcher):
        thread.join(10)
        assert not thread.is_alive()


def a_job(monkeypatch, starter, ends=True):
    """A job object as stand-ins: handle 77, holding what is put in it; ended, it ends what it holds (unless the test
    says it cannot). What was done with it, in order."""
    done: list = []

    def end(job):
        done.append(("end", job))
        for process in starter.made if ends else ():
            process.end(1)
        return True
    monkeypatch.setattr(keep_mod, "_job", lambda: 77)
    monkeypatch.setattr(keep_mod, "_hold", lambda job, process: done.append(("hold", job, process.pid)) or True)
    monkeypatch.setattr(children, "_end_job", end)
    monkeypatch.setattr(children, "_close_job", lambda job: done.append(("close", job)))
    return done


def real_linux(monkeypatch, kind=None):
    """Real processes on Linux as stand-ins: one's end seen without collecting it, its group told by its number.
    (Popen's stand-in, the processes made, what happened to them in order.) A group told by a number that was
    collected already fails the test. `kind`: the stand-in's class (Real unless given: a piped one has three pipes)."""
    starter, events = Starter(kind=kind or Real), []

    def popen(argv, **kw):
        process = starter(argv, **kw)
        process.events = events
        return process

    def of(pid):
        return next(p for p in starter.made if p.pid == pid)

    def peek(pid, block):
        process = of(pid)
        if block:
            process.ended.wait(10)
        return "gone" if process.returncode is not None else "ended" if process.code is not None else ""

    def group(pid, sig):
        process = of(pid)
        assert process.returncode is None, "a group was told by a number that was collected already"
        events.append(("group", pid, sig))
        if sig == children.KILL or not process.deaf:
            process.end(-sig)  # (the group's end: what held its output ends with it)
        return True
    monkeypatch.setattr(children, "_PEEKS", True)
    monkeypatch.setattr(children, "_peek", peek)
    monkeypatch.setattr(children, "_signal_group", group)
    return popen, starter.made, events


def an_earlier_run(folder, monkeypatch, pid=5555, started=111):
    """A pidfile an earlier run left behind, and this machine's process table as a stand-in: (the pidfile, the
    numbers alive, which the test changes)."""
    alive = {pid}
    pidfile = Path(folder) / "run" / "default.pid"
    pidfile.parent.mkdir(parents=True, exist_ok=True)
    pidfile.write_text(f"{pid} {started}")
    monkeypatch.setattr(proc_mod, "pid_alive", lambda p: p in alive)
    monkeypatch.setattr(proc_mod, "started", lambda p: started if p in alive else None)
    return pidfile, alive


def read_ps(line: str) -> tuple[str, list[str]]:
    """A PowerShell line read as its tokenizer reads single-quoted strings: (the line with each string's text taken
    out, the strings' texts). A string begins at any of the five quotes and ends at one that no other follows; a
    quote followed by another stands for that other. A string that is not ended fails the test."""
    outside, strings, i = [], [], 0
    while i < len(line):
        if line[i] not in QUOTES:
            outside.append(line[i])
            i += 1
            continue
        text, i = [], i + 1
        while True:
            assert i < len(line), f"a string is not ended: {line!r}"
            if line[i] in QUOTES:
                if i + 1 < len(line) and line[i + 1] in QUOTES:
                    text.append(line[i + 1])
                    i += 2
                    continue
                i += 1
                break
            text.append(line[i])
            i += 1
        outside.append("''")
        strings.append("".join(text))
    return "".join(outside), strings


# -- a launch, its environment, its lines ------------------------------------------------------------------------------
def test_a_launch_holds_what_is_started_as_text():
    given = {"OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_NUM_PARALLEL": 2}
    launch = Launch((Path("ollama"), "serve"), given, cwd=Path("work"), drop="OLLAMA_*", secret=["OLLAMA_KEY"])
    given["LATER"] = "not the launch's"
    assert launch.argv == ("ollama", "serve") and launch.cwd == "work"
    assert launch.env == {"OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_NUM_PARALLEL": "2"}
    assert launch.drop == ("OLLAMA_*",) and launch.secret == ("OLLAMA_KEY",)  # one name is one name, not its letters
    plain = Launch("ollama")
    assert (plain.argv, plain.env, plain.cwd, plain.drop, plain.secret) == (("ollama",), {}, "", (), ())
    assert Launch(("ollama", "serve"), {}, "", ("OLLAMA_*",)).drop == ("OLLAMA_*",)  # as the plugins write it
    with pytest.raises(dataclasses.FrozenInstanceError):
        launch.cwd = "elsewhere"
    assert (GRACE_S, LOG_MAX, LINE_CHARS) == (8.0, 1_000_000, 2000) and issubclass(ChildError, CommandError)


def test_the_environment_drops_what_is_named_and_lays_the_launchs_own_over_it(monkeypatch):
    base = {"PATH": "/bin", "OLLAMA_HOST": "0.0.0.0", "OLLAMA_DEBUG": "1", "OLLAMAS": "not a prefix's",
            "HF_TOKEN": "hf", "LIMINAL_AI_OLLAMA_INSTANCES": "{}", "MASSIVE_API_KEY": "key",
            "ollama_models": "elsewhere"}
    launch = Launch(("ollama", "serve"), {"OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_NO_CLOUD": "1"},
                    drop=("OLLAMA_*", "HF_TOKEN", "LIMINAL_*", "MASSIVE_API_KEY", "NOT_SET"))
    assert environment(launch, base, system="linux") == {
        "PATH": "/bin", "OLLAMAS": "not a prefix's", "ollama_models": "elsewhere",
        "OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_NO_CLOUD": "1"}
    assert base["OLLAMA_HOST"] == "0.0.0.0" and len(base) == 8  # the base is read, never changed
    # nothing is taken out that is not named: the plugin bases name Liminal's pairs themselves
    assert environment(Launch(("ollama",)), base, system="linux") == base
    # Windows tells names apart without regard to case, in what is dropped and in what is laid over
    assert environment(launch, base, system="windows") == {
        "PATH": "/bin", "OLLAMAS": "not a prefix's", "OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_NO_CLOUD": "1"}
    npm = Launch(("npm", "install"), {"npm_config_cache": "mine"})
    assert environment(npm, {"NPM_CONFIG_CACHE": "theirs", "Path": "p"}, system="windows") == {
        "Path": "p", "npm_config_cache": "mine"}
    assert len(environment(npm, {"NPM_CONFIG_CACHE": "theirs"}, system="linux")) == 2
    # without a base: this process's own environment
    monkeypatch.setenv("OLLAMA_ORIGINS", "*")
    monkeypatch.setenv("LIMINAL_TEST_STAYS", "yes")
    mine = environment(Launch(("ollama", "serve"), {"OLLAMA_HOST": "127.0.0.1:11434"}, drop=("OLLAMA_*",)))
    assert "OLLAMA_ORIGINS" not in mine and mine["LIMINAL_TEST_STAYS"] == "yes"
    assert mine["OLLAMA_HOST"] == "127.0.0.1:11434" and "OLLAMA_ORIGINS" in os.environ


SECRET = "sk-secret-0001"


def test_a_launch_is_shown_as_powershells_lines_without_its_secret():
    launch = Launch(("C:\\Program Files\\Ollama\\ollama.exe", "serve", "--it's"),
                    {"OLLAMA_HOST": "127.0.0.1:11434", "VLLM_API_KEY": SECRET}, cwd="C:\\work\\my project",
                    drop=("OLLAMA_*", "LIMINAL_*", "HF_TOKEN"), secret=("vllm_api_key",))
    base = {"PATH": "p", "OLLAMA_DEBUG": "1", "LIMINAL_AI_OLLAMA_INSTANCES": "{}", "ollama_models": "m"}
    lines = shown(launch, "windows", base)
    assert lines == [
        "Remove-Item Env:LIMINAL_AI_OLLAMA_INSTANCES -ErrorAction SilentlyContinue",
        "Remove-Item Env:OLLAMA_DEBUG -ErrorAction SilentlyContinue",
        "Remove-Item Env:ollama_models -ErrorAction SilentlyContinue",  # (HF_TOKEN is not set now: no line for it)
        "$env:OLLAMA_HOST = '127.0.0.1:11434'",
        f"$env:VLLM_API_KEY = '{PLACEHOLDER}'",
        "Set-Location -LiteralPath 'C:\\work\\my project'",
        "& 'C:\\Program Files\\Ollama\\ollama.exe' 'serve' '--it''s'",
    ]
    assert PLACEHOLDER == "<the key kept for it>" and not any(SECRET in line for line in lines)
    # a name ${env:...} could not hold is written as a quoted path, as it is unset
    odd = Launch(("ollama",), {"odd-name": "x", "a}b": "y"}, drop=("ProgramFiles(x86)",))
    assert shown(odd, "windows", {"ProgramFiles(x86)": "C:\\x86"}) == [
        "Remove-Item -LiteralPath 'Env:ProgramFiles(x86)' -ErrorAction SilentlyContinue",
        "Set-Item -LiteralPath 'Env:odd-name' -Value 'x'", "Set-Item -LiteralPath 'Env:a}b' -Value 'y'", "& 'ollama'"]


def test_a_launch_is_shown_as_shs_lines_without_its_secret(monkeypatch):
    launch = Launch(("/opt/ollama/bin/ollama", "serve", "--it's"),
                    {"OLLAMA_HOST": "127.0.0.1:11434", "VLLM_API_KEY": SECRET}, cwd="/home/u/my project",
                    drop=("OLLAMA_*", "LIMINAL_*", "HF_TOKEN"), secret=("VLLM_API_KEY",))
    base = {"PATH": "p", "OLLAMA_DEBUG": "1", "LIMINAL_AI_OLLAMA_INSTANCES": "{}", "ollama_models": "m"}
    lines = shown(launch, "linux", base)
    assert lines == [
        "unset LIMINAL_AI_OLLAMA_INSTANCES",
        "unset OLLAMA_DEBUG",  # (ollama_models is another name on Linux; HF_TOKEN is not set now)
        "export OLLAMA_HOST=127.0.0.1:11434",
        f"export VLLM_API_KEY='{PLACEHOLDER}'",
        "cd '/home/u/my project'",
        "/opt/ollama/bin/ollama serve '--it'\"'\"'s'",
    ]
    assert not any(SECRET in line for line in lines)
    # a variable the launch sets again is unset first all the same: the lines do what `environment` does, in its order
    again = shown(Launch(("ollama", "serve"), {"OLLAMA_HOST": "127.0.0.1:11434"}, drop=("OLLAMA_*",)), "linux",
                  {"OLLAMA_HOST": "0.0.0.0"})
    assert again == ["unset OLLAMA_HOST", "export OLLAMA_HOST=127.0.0.1:11434", "ollama serve"]
    # no folder, no variables: the command alone; a name sh cannot write is left out
    assert shown(Launch(("aider",)), "linux", {}) == ["aider"]
    assert shown(Launch(("aider",), {"odd-name": "x"}, drop=("a(b)",)), "linux", {"a(b)": "1"}) == ["aider"]
    # a secret a plugin put on the command line by mistake is not shown there either
    slip = Launch(("vllm", "serve", "--api-key", SECRET), {"KEY": SECRET, "NOTE": f"uses {SECRET}"},
                  cwd=f"/x/{SECRET}", secret=("KEY",))
    for system in ("windows", "linux"):
        lines = shown(slip, system, {})
        assert len(lines) == 4 and not any(SECRET in line for line in lines) and PLACEHOLDER in lines[-1]
    # without a base: what is set in this process's environment now
    monkeypatch.setenv("OLLAMA_DEBUG", "1")
    monkeypatch.delenv("HF_TOKEN", raising=False)
    assert shown(Launch(("ollama",), drop=("OLLAMA_DEBUG", "HF_TOKEN")), "linux") == ["unset OLLAMA_DEBUG", "ollama"]


def test_each_of_powershells_five_single_quotes_is_doubled_so_no_string_ends_early():
    for q in QUOTES:
        assert windows.quote(f"Bob{q}s") == f"'Bob{q}{q}s'"
        assert read_ps(windows.quote(f"Bob{q}s")) == ("''", [f"Bob{q}s"])
    every ="a'b\u2018c\u2019d\u201ae\u201bf''g"
    assert read_ps(windows.quote(every)) == ("''", [every]) and windows.quote("") == "''" and windows.quote(5) == "'5'"
    assert windows.SINGLE_QUOTES == QUOTES
    # each of them in a folder, a variable's value and a word of the command (a model id a remote server listed, say):
    # every line holds its words exactly, and nothing after a quote is read as a command of its own
    for q in QUOTES:
        launch = Launch(("C:\\tools\\aider.exe", "--model", f"openai/x{q}; Get-Date; {q}", f"a{q}b"),
                        {"AIDER_NOTE": f"Bob{q}s box", "odd-name": f"{q}; calc"}, cwd=f"C:\\work\\Ciara{q}s project")
        lines = shown(launch, "windows", {})
        assert [read_ps(line) for line in lines] == [
            ("$env:AIDER_NOTE = ''", [f"Bob{q}s box"]),
            ("Set-Item -LiteralPath '' -Value ''", ["Env:odd-name", f"{q}; calc"]),
            ("Set-Location -LiteralPath ''", [f"C:\\work\\Ciara{q}s project"]),
            ("& '' '' '' ''", list(launch.argv))], q
        # sh's lines are shlex's: the same words come back
        sh = shown(launch, "linux", {})
        assert len(sh) == 3 and shlex.split(sh[0]) == ["export", f"AIDER_NOTE=Bob{q}s box"]
        assert shlex.split(sh[1]) == ["cd", launch.cwd] and shlex.split(sh[2]) == list(launch.argv)


NET_SPACE = {c for c in map(chr, range(0x3001)) if c.isspace()} - set("\x1c\x1d\x1e\x1f")  # .NET's IsWhiteSpace


def crt_split(line: str) -> list[str]:
    """A command line's arguments as the MSVC runtime reads them: whitespace between words, double quotes around a
    part with spaces, 2n backslashes before a quote n and the quote a delimiter, 2n+1 n and a quote; "" inside
    quotes one quote."""
    out, i, n = [], 0, len(line)
    while True:
        while i < n and line[i] in " \t":
            i += 1
        if i >= n:
            return out
        word, inside = [], False
        while i < n and (inside or line[i] not in " \t"):
            if line[i] == "\\":
                j = i
                while j < n and line[j] == "\\":
                    j += 1
                if j < n and line[j] == '"':
                    word.append("\\" * ((j - i) // 2) + ('"' if (j - i) % 2 else ""))
                    i = j + 1 if (j - i) % 2 else j
                else:
                    word.append(line[i:j])
                    i = j
            elif line[i] == '"':
                if inside and line[i + 1:i + 2] == '"':
                    word.append('"')
                    i += 2
                else:
                    inside, i = not inside, i + 1
            else:
                word.append(line[i])
                i += 1
        out.append("".join(word))


def ps51_receives(line: str) -> list[str]:
    """What a program is handed by a line `& 'program' 'word' ...` in Windows PowerShell 5.1, as measured on it
    (2026-11-18, 5.1.26100: this model foretold all 45 measured cases): the line's strings as its tokenizer reads them
    (read_ps), each passed by its old rules (an empty one left out; its stop-parsing token, --%, taken for itself and
    every word after it passed as it is; one that holds whitespace outside a double quote put in double quotes as it
    is, a quote after a backslash not counted), then that command line read as the MSVC runtime reads one."""
    rest, strings = read_ps(line)
    assert rest == "& " + " ".join(["''"] * len(strings)), line
    parts, verbatim = [], False
    for word in strings[1:]:
        if verbatim or word == "--%":
            parts += [word] if verbatim else []
            verbatim = True
            continue
        quotes, after, spaced = 0, False, False
        for c in word:
            if c == '"' and not after:
                quotes += 1
            elif c in NET_SPACE and quotes % 2 == 0:
                spaced = True
            after = c == "\\"
        if word:
            parts.append(f'"{word}"' if spaced else word)
    return crt_split(" ".join(parts))


def test_powershells_lines_hand_the_program_its_words_as_they_are_or_are_refused():
    # Windows PowerShell 5.1, the only PowerShell of the user's PC, hands a program its words by rules of its own: the
    # words it passes as they are, in every way they come
    good = ["--model", "openai/qwen3", "C:\\dir\\", "a b", "a\\\\b c", "a\tb", "a\u00a0b", " leading", "trailing ",
            "a \u201cb c", "Ciara\u2019s project", "%PATH%", "--%x", "a --% b", "-x:y", "--a=b c", "a|b", "$env:PATH",
            "\u4e2d\u6587 \u6587", "a\u180eb\\", "a\u001cb\\"]
    launch = Launch(("C:\\tools\\aider.exe", *good))
    assert ps51_receives(shown(launch, "windows", {})[-1]) == good
    # a word it would not pass as it is: refused in words, and the model shows what the program would have been handed
    # (Aider's planned line: the model's id before the switches that keep it from committing and sending)
    for word, why in (("", "it is empty"), ('openai/x"y', "a double quote"), ('{"a": 1}', "a double quote"),
                      ("--%", "stop-parsing token"), ("C:\\my dir\\", "ends in a backslash"),
                      ("a\u3000b\\", "ends in a backslash")):
        argv = ("C:\\tools\\aider.exe", "--model", word, "--no-auto-commits", "--no-analytics")
        with pytest.raises(ValueError) as caught:
            shown(Launch(argv), "windows", {})
        assert str(caught.value).startswith(f"aider's command cannot be pasted into PowerShell as it is: its word "
                                            f"{children._word(word)!r} would not reach it as it is ("), word
        assert why in str(caught.value) and children.not_passed(word)
        assert ps51_receives("& " + " ".join(windows.quote(w) for w in argv)) != list(argv[1:]), word
        assert shlex.split(shown(Launch(argv), "linux", {})[-1]) == list(argv)  # sh's lines take every word as it is
    # every word, in a thousand made of what matters to it: refused exactly when it would not be passed as it is
    pick = random.Random(118)
    letters = ["a", " ", "\t", "\\", '"', "\u00a0", "-", "%", "\u201c", "'", "\u2019", "=", "\u3000"]
    for word in ["--%", *("".join(pick.choice(letters) for _ in range(pick.randint(0, 6))) for _ in range(1000))]:
        argv = ("C:\\tools\\tool.exe", "--before", word, "--after")
        passed = ps51_receives("& " + " ".join(windows.quote(w) for w in argv)) == list(argv[1:])
        assert passed == (children.not_passed(word) == ""), repr(word)
        try:
            lines = shown(Launch(argv), "windows", {})
        except ValueError:
            assert not passed, repr(word)
        else:
            assert passed and ps51_receives(lines[-1]) == list(argv[1:]), repr(word)


def test_a_short_secret_and_one_quoting_would_change_are_hidden_as_whole_words(tmp_path):
    quoted = 'sk-ab"cd-1234'  # a key may hold a double quote: Windows' quoting writes it as \"
    launch = Launch(("tool", "--key", "q7Z", "--token=q7Z", quoted, "--other=q7Zx"), {"TOOL_KEY": "q7Z", "T2": quoted},
                    cwd="q7Z", secret=("TOOL_KEY", "t2"))
    key = PLACEHOLDER
    assert shown(launch, "windows", {}) == [
        f"$env:TOOL_KEY = '{key}'", f"$env:T2 = '{key}'", f"Set-Location -LiteralPath '{key}'",
        f"& 'tool' '--key' '{key}' '--token={key}' '{key}' '--other=q7Zx'"]  # (a part of a word is no secret)
    assert shown(launch, "linux", {}) == [
        f"export TOOL_KEY='{key}'", f"export T2='{key}'", f"cd '{key}'",
        f"tool --key '{key}' '--token={key}' '{key}' --other=q7Zx"]
    child, starter = make(tmp_path, "windows", launch, interrupt=lambda pid: False)
    child.start()  # each word hidden before it is quoted (Windows writes the " of a word as \"): no secret is left
    first = child.log.read_text("utf-8").splitlines()[0]
    assert "sk-ab" not in first and "\\" not in first and first.count(key) == 3 and first.endswith(" --other=q7Zx")


# -- starting ----------------------------------------------------------------------------------------------------------
def test_on_windows_a_child_is_started_without_a_window_and_held_in_a_job(tmp_path, monkeypatch, nothing_real):
    launch = Launch(("ollama", "serve"), {"OLLAMA_HOST": "127.0.0.1:11434"}, cwd=str(tmp_path), drop=("OLLAMA_*",))
    monkeypatch.setenv("OLLAMA_ORIGINS", "*")
    child, starter = make(tmp_path, "windows", launch)
    done = a_job(monkeypatch, starter)
    assert (child.pid, child.alive, child.code, child.since, child.tail()) == (None, False, None, None, [])
    before = time.time()
    assert child.start() == 4321 and child.pid == 4321 and child.alive and child.code is None
    assert before <= child.since <= time.time()
    process = starter.made[0]
    kw = process.kw
    assert process.argv == ["ollama", "serve"] and kw["cwd"] == str(tmp_path) and kw["bufsize"] == 0
    assert (kw["stdin"], kw["stdout"], kw["stderr"]) == (subprocess.DEVNULL, subprocess.PIPE, subprocess.STDOUT)
    # CREATE_NO_WINDOW and nothing else: a process group of its own (0x200) would turn Ctrl+C off in it
    assert kw["creationflags"] == 0x08000000 and "start_new_session" not in kw
    assert kw["env"] == environment(launch, system="windows") and "OLLAMA_ORIGINS" not in kw["env"]
    assert kw["env"]["OLLAMA_HOST"] == "127.0.0.1:11434"
    assert done == [("hold", 77, 4321)] and nothing_real == [children.stop_all] and children._all == [child]
    assert child._watcher.daemon and child._watcher.name == "child-end-ollama default"
    process.end(0)
    settle(child)
    assert done == [("hold", 77, 4321), ("close", 77)]  # its job closed at its end: what it left running ends with it
    assert not child.alive and child.pid is None and child.code == 0 and children._all == []


def test_on_linux_a_child_leads_a_session_of_its_own(tmp_path, monkeypatch):
    monkeypatch.setattr(keep_mod, "_job", refusing("job object"))  # Windows' way: not asked for here
    child, starter = make(tmp_path, "linux")
    assert child.start() == 4321
    kw = starter.made[0].kw
    assert kw["start_new_session"] is True and "creationflags" not in kw and kw["cwd"] is None
    assert (kw["stdin"], kw["stdout"], kw["stderr"]) == (subprocess.DEVNULL, subprocess.PIPE, subprocess.STDOUT)
    assert children.this_system() == ("windows" if os.name == "nt" else "linux")
    assert Child(NAME, Launch(("ollama",)), tmp_path / "a.log", tmp_path / "a.pid").system == children.this_system()


def test_ctrl_c_is_heard_again_once_before_the_first_real_child_on_windows(tmp_path, k32):
    seen: list = []

    class Started(Real):  # what the real Popen class makes, as far as isinstance and issubclass can tell
        def __init__(self, argv, **kw):
            seen.append(list(k32.calls))  # what this process had asked of Windows when the child was made
            super().__init__(argv, pid=4321 + len(seen), **kw)

    for n in (1, 2):
        Child(NAME, Launch(("ollama", "serve")), tmp_path / f"{n}.log", tmp_path / f"{n}.pid", popen=Started,
              system="windows").start()
    # NULL, FALSE: the "ignore Ctrl+C" a starter may have passed on is cleared before the first child is made, which
    # inherits it; once for the process
    assert seen == [[("SetConsoleCtrlHandler", None, 0)]] * 2 and k32.calls == [("SetConsoleCtrlHandler", None, 0)]


def test_a_stand_in_or_a_child_on_linux_leaves_this_processes_ctrl_c_as_it_is(tmp_path, monkeypatch, k32):
    monkeypatch.setattr(children, "_PEEKS", False)  # (the Linux child's end is waited for by its handle, as a test's)
    make(tmp_path / "windows", "windows")[0].start()  # a stand-in's start makes no process of this system
    Child(NAME, Launch(("vllm", "serve")), tmp_path / "l.log", tmp_path / "l.pid", popen=Real, system="linux").start()
    assert k32.calls == [] and children._ctrl_c_cleared is False


def test_what_a_child_prints_is_appended_to_its_log_by_a_thread(tmp_path):
    child, starter = make(tmp_path, "linux")
    child.start()
    assert child._reader.daemon and child._reader.name == "child-ollama default"
    word = "café\n".encode()
    starter.made[0].stdout.chunks += [b"listening on 127.0.0.1:11434\n", b"\n", word[:4], word[4:]]
    starter.made[0].end(0)
    settle(child)
    lines = child.log.read_text(encoding="utf-8").splitlines()
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d liminal: ollama default started \(pid 4321\): ollama serve",
                        lines[0])
    assert lines[1:] == ["listening on 127.0.0.1:11434", "", "café"]
    assert child.tail(2) == ["listening on 127.0.0.1:11434", "café"] and child.tail(0) == []
    child.start()  # a second run goes on in the same log
    starter.made[1].stdout.chunks.append(b"listening again\n")
    starter.made[1].end(0)
    settle(child)
    assert [line.split("liminal: ")[-1] for line in child.tail(5)] == [
        "ollama default started (pid 4321): ollama serve", "listening on 127.0.0.1:11434", "café",
        "ollama default started (pid 4322): ollama serve", "listening again"]


def test_a_secret_on_the_command_line_is_not_written_into_the_log(tmp_path):
    launch = Launch(("vllm", "serve", "--api-key", SECRET), {"VLLM_API_KEY": SECRET}, secret=("VLLM_API_KEY",))
    child, starter = make(tmp_path, "linux", launch)
    child.start()
    assert starter.made[0].kw["env"]["VLLM_API_KEY"] == SECRET  # the child has it
    first = child.log.read_text(encoding="utf-8").splitlines()[0]
    assert SECRET not in first and first.endswith(("vllm serve --api-key " + PLACEHOLDER,  # (quoted on Windows)
                                                   f'vllm serve --api-key "{PLACEHOLDER}"'))


def test_a_secret_the_program_prints_is_not_written_into_its_log(tmp_path):
    launch = Launch(("vllm", "serve"), {"VLLM_API_KEY": SECRET, "PIN": "q7Z"}, secret=("VLLM_API_KEY", "PIN"))
    child, starter = make(tmp_path, "linux", launch)  # (the same on Windows: the pipe is read by the same thread)
    child.start()
    key = SECRET.encode()
    starter.made[0].stdout.chunks += [b"args: api_key=" + key[:5], key[5:] + b" port 8000\nready\n", b"key " + key]
    starter.made[0].end(0)
    settle(child)
    text = child.log.read_text(encoding="utf-8")
    assert SECRET not in text and "sk-se" not in text  # (cut across two pieces of output, too)
    assert text.splitlines()[1:] == [f"args: api_key={PLACEHOLDER} port 8000", "ready", f"key {PLACEHOLDER}"]


def test_only_a_lines_end_where_a_secret_may_begin_waits_to_be_written(tmp_path):
    path = tmp_path / "x.log"
    log = children._Log(path, hide=[SECRET, "q7Z", ""])  # (a value under HIDE_MIN is not looked for in what is printed)
    log.open()
    log.write(b"ready\nkey=" + SECRET[:6].encode())  # a whole line is written at once; a secret may begin after it
    assert path.read_bytes() == b"ready\n"
    log.write(SECRET[6:].encode() + b" ok\n")
    assert path.read_bytes() == f"ready\nkey={PLACEHOLDER} ok\n".encode()
    log.write(b"pin q7Z, and a line not ended " + b"x" * 40)
    assert path.read_bytes().endswith(b"pin q7Z, and a line not ended " + b"x" * 27)  # all but what may begin a secret
    log.close()  # what was held back is written at the end
    assert path.read_bytes().endswith(b"x" * 40) and children._Log(path)._hide == []


def test_the_log_is_closed_before_it_is_moved_aside_past_its_size(tmp_path, monkeypatch):
    monkeypatch.setattr(children, "LOG_MAX", 200)
    logs, moves = [], []

    class Seen(children._Log):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            logs.append(self)

    def rotate(log, most=keep_mod.LOG_MAX_BYTES):
        moves.append((log.name, most, all(seen.file is None or seen.file.closed for seen in logs)))
        ROTATE(log, most)
    monkeypatch.setattr(children, "_Log", Seen)
    monkeypatch.setattr(keep_mod, "rotate", rotate)
    child, starter = make(tmp_path, "linux")
    child.start()
    first, second, third = (bytes([65 + i]) * 89 + b"\n" for i in range(3))
    starter.made[0].stdout.chunks += [first, second, third]
    starter.made[0].end(0)
    settle(child)
    aside = child.log.with_name("default.log.1").read_bytes()
    assert aside.endswith(first + second) and aside.count(b"\n") == 3 and b"started (pid 4321)" in aside
    assert child.log.read_bytes() == third
    # looked at when it was opened (nothing open yet), then moved once: closed at that moment (Windows moves no open
    # file)
    assert moves == [("default.log", 200, True), ("default.log", 0, True)]
    assert child.tail(3) == ["A" * 89, "B" * 89, "C" * 89]  # its last lines reach into the one moved aside


def test_a_log_is_cut_at_a_lines_end_and_one_that_cannot_be_written_is_given_up(tmp_path):
    path = tmp_path / "x.log"
    log = children._Log(path, most=10)
    log.open()
    log.write(b"12345\n")
    log.write(b"6789\nabc")  # past its size inside this piece: what ends a line stays, the rest begins the new log
    log.write(b"defghijklmnop")  # no line ends in this one: cut where the piece ends
    log.close()
    assert path.with_name("x.log.1").read_bytes() == b"abcdefghijklmnop" and path.read_bytes() == b""
    path.write_bytes(b"x" * 12)  # an earlier run left it past its size: moved aside when it is opened
    log = children._Log(path, most=10)
    log.open()
    log.close()
    assert path.with_name("x.log.1").read_bytes() == b"x" * 12 and path.read_bytes() == b""
    log = children._Log(path, most=1000)
    log.open()
    log.file.close()  # it cannot be written any more
    log.write(b"lost")
    assert log.file is None  # given up quietly: the child's output is read on
    log.write(b"and this")
    log.close()


def test_a_log_that_cannot_be_moved_stays_within_two_of_its_sizes(tmp_path, monkeypatch):
    path, aside = tmp_path / "x.log", tmp_path / "x.log.1"
    aside.write_bytes(b"an older log another program holds open")
    tries: list = []
    monkeypatch.setattr(keep_mod, "rotate", lambda log, most=0: tries.append(most))  # it never moves
    log = children._Log(path, most=100)
    log.open()
    for n in range(200):
        log.write(b"line %03d of a server that goes on printing\n" % n)
        assert path.stat().st_size + (aside.stat().st_size if aside.exists() else 0) < 2 * (100 + 45)
    log.close()
    # not moved: copied over <log>.1 and cut where it lies, at each turn
    assert tries[:3] == [100, 0, 0] and aside.read_bytes().startswith(b"line ")
    assert path.read_bytes().startswith(b"line ")
    # <log>.1 alone kept it from moving (another program reads it): written over where it lies, the log cut
    aside.write_bytes(b"held")
    monkeypatch.setattr(keep_mod, "rotate", lambda log, most=0: tries.append(most) or (
        None if aside.exists() else ROTATE(log, most)))
    log = children._Log(path, most=10)
    log.open()
    log.write(b"0123456789\n")
    log.close()
    assert aside.read_bytes() == b"0123456789\n" and path.read_bytes() == b""
    # neither moved nor cut: given up, so that it grows no further
    def cannot_cut(self):
        raise OSError("another program holds it")
    monkeypatch.setattr(keep_mod, "rotate", lambda log, most=0: None)
    monkeypatch.setattr(children._Log, "_cut", cannot_cut)
    path.write_bytes(b"")
    log = children._Log(path, most=10)
    log.open()
    log.write(b"0123456789\n")
    assert log.file is None and path.read_bytes() == b"0123456789\n"
    log.write(b"more")
    log.close()
    assert path.read_bytes() == b"0123456789\n"


def test_a_log_another_program_reads_as_it_turns_is_copied_aside_and_cut_and_neither_is_lost(tmp_path, monkeypatch):
    path, aside = tmp_path / "default.log", tmp_path / "default.log.1"

    def turn(held_by_reader: bool):
        aside.write_bytes(b"the log before this one\n")
        log = children._Log(path, most=100)
        log.open()
        log.write(b"line 1 of the server's output\n" * 3)  # 90 bytes: under its size
        reader = path.open("rb") if held_by_reader else None  # a page reading its last lines this moment
        try:
            log.write(b"line 2, the one that passes the size\n")
        finally:
            if reader is not None:
                reader.close()
        log.write(b"line 3, after\n")
        log.close()
        assert aside.read_bytes() == b"line 1 of the server's output\n" * 3 + b"line 2, the one that passes the size\n"
        assert path.read_bytes() == b"line 3, after\n"
        path.unlink()

    # the log itself held as it is moved (Windows moves no file another program holds open): it is copied over
    # <log>.1 and cut, <log>.1 is never removed for it
    monkeypatch.setattr(keep_mod, "rotate", lambda log, most=0: None)
    turn(held_by_reader=False)
    if os.name == "nt":  # and for real: Windows' own refusal to move a file a reader holds
        monkeypatch.setattr(keep_mod, "rotate", ROTATE)
        turn(held_by_reader=True)
    # <log>.1 that cannot be written either (a folder in its place, as a file another program holds without letting it
    # be written): the log alone is cut, <log>.1 kept as it is
    monkeypatch.setattr(keep_mod, "rotate", lambda log, most=0: None)
    aside.unlink()
    aside.mkdir()
    log = children._Log(path, most=10)
    log.open()
    log.write(b"0123456789\n")
    log.close()
    assert aside.is_dir() and path.read_bytes() == b""


def test_the_last_lines_of_a_log(tmp_path, monkeypatch):
    log = tmp_path / "x.log"
    assert children.last_lines(log) == []  # no log yet
    log.with_name("x.log.1").write_bytes(b"one\ntwo\n")
    long = "four " + "x" * 3000
    log.write_bytes(b"three\r\n\n   \n" + long.encode() + b"\nfive")
    assert children.last_lines(log, 3) == ["three", long[:LINE_CHARS], "five"]
    assert children.last_lines(log, 4)[0] == "two" and children.last_lines(log)[:2] == ["one", "two"]
    monkeypatch.setattr(children, "TAIL_BYTES", 8)  # only a log's end is read: the line the read began in is left out
    assert children.last_lines(log, 2) == ["two", "five"]


def test_the_pidfile_holds_the_childs_number_and_its_start_and_goes_at_its_end(tmp_path, monkeypatch):
    monkeypatch.setattr(proc_mod, "started", lambda pid: 133_000_000_000 + pid)
    child, starter = make(tmp_path, "linux")
    child.start()
    me = os.getpid()  # and who reads what it prints: this process
    assert child.pidfile.read_text() == f"4321 133000004321 {me} {133_000_000_000 + me}"
    assert os.listdir(child.pidfile.parent) == ["default.pid"]
    monkeypatch.setattr(proc_mod, "pid_alive", lambda pid: pid == 4321)
    assert proc_mod.holder(child.pidfile) == 4321  # as a later run reads it back
    monkeypatch.setattr(proc_mod, "started", lambda pid: 7)  # that number is another process's by now
    assert proc_mod.holder(child.pidfile) is None
    starter.made[0].end(0)
    settle(child)
    assert not child.pidfile.exists()
    child.start()
    child.pidfile.write_text("9999 1")  # it names another process by the time this one ends: that one's, left
    starter.made[1].end(0)
    settle(child)
    assert child.pidfile.read_text() == "9999 1"


def test_a_child_that_cannot_start_or_runs_already_says_so(tmp_path, monkeypatch):
    def missing(argv, **kw):
        raise FileNotFoundError("no such file")
    child = Child(NAME, Launch(("C:/tools/ollama.exe", "serve")), tmp_path / "a.log", tmp_path / "a.pid",
                  popen=missing, system="windows")
    with pytest.raises(ChildError, match=r"^ollama default could not start \(ollama\): no such file$") as e:
        child.start()
    assert isinstance(e.value, CommandError) and not child.alive and child.pid is None and not child.pidfile.exists()
    (tmp_path / "taken").write_text("a file where its folder would be")
    child = Child(NAME, Launch(("ollama",)), tmp_path / "taken" / "a.log", tmp_path / "a.pid", popen=refusing("Popen"))
    with pytest.raises(ChildError, match="ollama default could not start: its log .* cannot be written"):
        child.start()
    with pytest.raises(ChildError, match="ollama default has no command to start"):
        Child(NAME, Launch(()), tmp_path / "a.log", tmp_path / "a.pid", popen=refusing("Popen")).start()
    child, starter = make(tmp_path, "linux")
    child.start()
    with pytest.raises(ChildError, match=r"^ollama default runs already \(pid 4321\)$"):
        child.start()
    assert len(starter.made) == 1
    starter.made[0].end(3)
    settle(child)
    assert child.code == 3 and child.start() == 4322 and child.alive  # ended: it can be started again
    other, unused = make(tmp_path / "other", "linux")  # an earlier run's child is still there, by its pidfile
    pidfile, alive = an_earlier_run(tmp_path / "other", monkeypatch, pid=555)
    with pytest.raises(ChildError, match=r"runs already \(pid 555\): an earlier run of this program started it"):
        other.start()
    assert unused.made == [] and pidfile.read_text() == "555 111"


def test_a_word_or_a_variable_that_popen_refuses_is_said_in_words(tmp_path):
    def refuses(argv, **kw):
        raise ValueError("embedded null byte")
    launch = Launch(("ollama", "serve\0"), {"KEY": SECRET}, secret=("KEY",))
    child = Child(NAME, launch, tmp_path / "a.log", tmp_path / "a.pid", popen=refuses, system="windows")
    with pytest.raises(ChildError, match=r"^ollama default could not start \(ollama\): embedded null byte$"):
        child.start()
    child.log.unlink()  # its log was closed (Windows removes no file that is open)
    assert not child.alive and not child.pidfile.exists()

    def wrong(argv, **kw):
        raise TypeError("expected str, bytes or os.PathLike object, not NoneType")
    with pytest.raises(ChildError, match="^uv could not run: expected str"):
        stream(["uv", "sync"], print, popen=wrong)
    with pytest.raises(ChildError, match="^uv could not run: embedded null byte$"):
        stream(["uv", "sync\0"], print, popen=refuses)


# -- stopping ----------------------------------------------------------------------------------------------------------
def test_stop_asks_with_ctrl_c_and_ends_the_job_once_the_grace_is_over(tmp_path, monkeypatch):
    clock, naps, asked = Clock(), [], []
    child, starter = make(tmp_path, "windows", clock=clock, sleep=naps.append,
                          interrupt=lambda pid: asked.append(pid) or True)  # it hears Ctrl+C and goes on
    done = a_job(monkeypatch, starter)
    child.start()
    # sent, which is all that is known: not whether it was heard
    assert child.stop() == "did not end within 8 s after Ctrl+C was sent: ended with what it started"
    assert asked == [4321] and done == [("hold", 77, 4321), ("end", 77), ("close", 77)]
    assert clock.now >= GRACE_S and naps and set(naps) == {children.STEP_S}  # the grace, on the child's own clock
    assert not child.alive and child.code == 1 and not child.pidfile.exists() and children._all == []
    # a second call does nothing
    assert child.stop() == "had ended already (exit code 1)" and child.stop(0) == "had ended already (exit code 1)"
    assert asked == [4321] and len(done) == 3 and starter.made[0].told == []


def test_a_child_that_ends_when_asked_is_not_ended_by_force(tmp_path, monkeypatch):
    child, starter = make(tmp_path, "windows", interrupt=lambda pid: starter.made[0].end(0) or True)
    done = a_job(monkeypatch, starter)
    child.start()
    assert child.stop() == "ended when asked (Ctrl+C), after 2.0 s"
    assert done == [("hold", 77, 4321), ("close", 77)] and child.code == 0 and starter.made[0].told == []


def test_a_child_ctrl_c_cannot_reach_is_ended_at_once(tmp_path, monkeypatch):
    clock = Clock()
    child, starter = make(tmp_path, "windows", clock=clock, interrupt=lambda pid: False)
    done = a_job(monkeypatch, starter)
    child.start()
    assert child.stop() == "Ctrl+C could not reach it: ended with what it started"
    assert clock.now < GRACE_S and done[1:] == [("end", 77), ("close", 77)]  # no grace for what was never asked


def test_without_a_job_the_child_alone_is_ended_and_that_is_said(tmp_path):
    child, starter = make(tmp_path, "windows", interrupt=lambda pid: False)
    child.start()
    assert "it could not be held in a job: what it starts is not ended with it" in child.log.read_text("utf-8")
    assert child.stop() == "Ctrl+C could not reach it: ended; what it started is not held with it and may still run"
    assert starter.made[0].told == ["kill"] and not child.owns(4321)


def test_a_stand_ins_number_is_never_given_to_this_machine(tmp_path, monkeypatch):
    monkeypatch.setattr(children, "interrupt", refusing("console's helper"))
    monkeypatch.setattr(children, "_session_of", refusing("session of a number"))
    child, starter = make(tmp_path / "windows", "windows")  # no Ctrl+C given: the real one is for real processes
    child.start()
    assert child.owns(4321) and not child.owns(5000)
    assert child.stop().startswith("Ctrl+C could not reach it: ended") and starter.made[0].told == ["kill"]
    child, starter = make(tmp_path / "linux", "linux")
    child.start()
    assert child.owns(4321) and not child.owns(5000)  # (its session is not asked of this machine)
    assert child.stop() == "ended when asked (SIGTERM), after 2.0 s" and starter.made[0].told == ["terminate"]


def test_on_linux_a_child_is_asked_with_sigterm_and_killed_once_the_grace_is_over(tmp_path):
    clock = Clock()
    child, starter = make(tmp_path, "linux", clock=clock)
    assert child.stop() == "was not started"
    child.start()
    starter.made[0].deaf = True
    assert child.stop() == "did not end within 8 s after SIGTERM was sent: ended with what it started"
    assert starter.made[0].told == ["terminate", "kill"] and clock.now >= GRACE_S and child.code == -9
    assert child.stop() == "had ended already (exit code -9)" and len(starter.made[0].told) == 2
    child.start()
    starter.made[1].deaf = True
    clock.now = 0.0
    assert child.stop(2) == "did not end within 2 s after SIGTERM was sent: ended with what it started"
    assert clock.now < GRACE_S


def test_a_child_that_cannot_be_ended_is_an_error_in_words(tmp_path, monkeypatch):
    child, starter = make(tmp_path, "windows", interrupt=lambda pid: False)
    a_job(monkeypatch, starter, ends=False)
    child.start()
    with pytest.raises(ChildError, match=r"^ollama default could not be ended: it still runs \(pid 4321\)$"):
        child.stop()
    assert child.alive and child.pidfile.exists()


def test_waiting_for_a_child_gives_its_exit_code_or_none_while_it_runs(tmp_path):
    naps: list = []

    def nap(seconds):
        naps.append(seconds)
        if len(naps) == 3:
            starter.made[0].end(5)
    child, starter = make(tmp_path, "linux", sleep=nap)
    assert child.wait(1.0) is None and child.wait() is None  # never started: nothing to wait for
    child.start()
    assert child.wait(0.5) is None and child.alive and naps == []  # half a second on its own clock: still running
    assert child.wait() == 5 and naps == [children.STEP_S] * 3 and child.wait() == 5 and child.wait(1.0) == 5


def test_a_real_childs_wait_is_its_watchers_and_looks_at_nothing_meanwhile(tmp_path, monkeypatch):
    # (a boot server's `launch serve` waits so for days, half a second at a time: no timer wakes it every STEP_S)
    starter = Starter(kind=Real)
    child, _ = make(tmp_path / "windows", "windows", starter=starter, clock=time.monotonic,
                    sleep=refusing("sleep: a real child's end is its watcher's to see"))
    child.start()
    began = time.monotonic()
    assert child.wait(0.3) is None and time.monotonic() - began >= 0.3 and child.alive
    threading.Timer(0.1, starter.made[0].end, args=(3,)).start()
    assert child.wait(10) == 3 and time.monotonic() - began < 5  # its end seen as it comes
    assert starter.made[0].waits == []  # its handle never asked with a timeout: its watcher's wait alone
    popen, made, events = real_linux(monkeypatch)  # Linux: its watcher waits by waitid, without collecting it
    child, _ = make(tmp_path / "linux", "linux", starter=popen, clock=time.monotonic,
                    sleep=refusing("sleep: a real child's end is its watcher's to see"))
    child.start()
    assert child.wait(0.3) is None and child.alive
    threading.Timer(0.1, made[0].end, args=(1,)).start()
    assert child.wait(10) == 1 and events == [("group", 4321, children.KILL), "collected"]

    class Unwaited(Real):  # its watcher's wait fails: its end is looked for every STEP_S, as any other child's
        def wait(self, timeout=None):
            if timeout is None:
                raise OSError("its handle cannot be waited on")
            return super().wait(timeout)
    starter = Starter(kind=Unwaited)
    child, _ = make(tmp_path / "unwaited", "windows", starter=starter, clock=time.monotonic)
    child.start()
    child._watcher.join(10)
    began = time.monotonic()
    threading.Timer(0.1, starter.made[0].end, args=(2,)).start()
    assert child.wait(10) == 2 and time.monotonic() - began < 5 and starter.made[0].waits


# -- its end, seen apart from its output -------------------------------------------------------------------------------
def test_a_child_that_ends_while_what_it_started_holds_its_output_is_cleaned_up_at_once(tmp_path, monkeypatch):
    monkeypatch.setattr(children, "LEFT_S", 0.05)
    child, starter = make(tmp_path, "windows", interrupt=lambda pid: False)
    done = a_job(monkeypatch, starter, ends=False)
    child.start()
    process = starter.made[0]
    process.stdout.chunks.append(b"router: a model server started\n")
    process.leave(3)  # the router ends; the model server it started still holds its output open
    child._watcher.join(10)
    # seen ended with nobody asking: its job closed (which ends the model server), its pidfile gone, not counted
    assert done == [("hold", 77, 4321), ("close", 77)] and not child.pidfile.exists() and children._all == []
    assert child._reader.is_alive()  # (what still holds its output ends with the job: here, by the test's hand)
    process.stdout.done.set()
    settle(child)
    assert child.code == 3 and child.tail(1) == ["router: a model server started"]


def test_on_linux_a_child_that_ends_while_its_group_holds_its_output_is_cleaned_up_at_once(tmp_path, monkeypatch):
    monkeypatch.setattr(children, "LEFT_S", 0.05)
    popen, made, events = real_linux(monkeypatch)
    child, _ = make(tmp_path, "linux", starter=popen)
    child.start()
    made[0].leave(1)  # it ends; what it started in its group still holds its output
    settle(child)  # its group ended while its number was still its own, which ends what held its output, then collected
    assert events == [("group", 4321, children.KILL), "collected"] and not child.pidfile.exists()
    assert child.code == 1 and children._all == []


# -- a real process, as far as this module can tell --------------------------------------------------------------------
def test_a_real_child_on_linux_is_seen_ended_before_it_is_collected(tmp_path, monkeypatch):
    popen, made, events = real_linux(monkeypatch)
    child, _ = make(tmp_path, "linux", Launch(("vllm", "serve")), starter=popen)
    child.start()
    assert child.alive and child.code is None and events == []  # looked at: not collected, told nothing
    monkeypatch.setattr(children, "_session_of", {5000: 4321, 6000: 1}.get)
    assert child.owns(4321) and child.owns(5000) and not child.owns(6000) and not child.owns(7000)
    assert child.stop() == "ended when asked (SIGTERM), after 2.0 s"
    # its group is asked; once it has ended, what it left behind is killed while its number is still its own; only
    # then is it collected
    assert events == [("group", 4321, children.TERM), ("group", 4321, children.KILL), "collected"]
    assert child.code == -children.TERM and not child.owns(4321) and not child.owns(5000)
    assert child._signal(children.KILL) is False and len(events) == 3  # collected: its number is told nothing more


def test_a_real_child_on_linux_that_does_not_end_is_killed_by_its_group(tmp_path, monkeypatch):
    popen, made, events = real_linux(monkeypatch)
    child, _ = make(tmp_path, "linux", starter=popen)
    child.start()
    made[0].deaf = True
    assert child.stop() == "did not end within 8 s after SIGTERM was sent: ended with what it started"
    assert events == [("group", 4321, children.TERM), ("group", 4321, children.KILL), ("group", 4321, children.KILL),
                      "collected"]
    assert child.code == -children.KILL and child.wait() == -children.KILL


def test_a_real_child_on_linux_that_ends_by_itself_takes_what_it_started_with_it(tmp_path, monkeypatch):
    popen, made, events = real_linux(monkeypatch)
    child, _ = make(tmp_path, "linux", starter=popen)
    child.start()
    made[0].end(1)  # it failed; what it started still runs in its group
    settle(child)
    assert events == [("group", 4321, children.KILL), "collected"] and not child.alive and child.code == 1
    assert child.stop() == "had ended already (exit code 1)" and len(events) == 2


def test_a_real_child_on_windows_is_asked_through_the_helper_and_waited_on_by_its_handle(tmp_path, monkeypatch):
    starter, asked = Starter(kind=Real), []
    monkeypatch.setattr(children, "interrupt", lambda pid: asked.append(pid) or True)  # the module's own, by number
    child, _ = make(tmp_path, "windows", starter=starter, sleep=refusing("sleep: Windows waits on the process itself"))
    done = a_job(monkeypatch, starter)
    child.start()
    assert child.stop() == "did not end within 8 s after Ctrl+C was sent: ended with what it started"
    assert asked == [4321] and done == [("hold", 77, 4321), ("end", 77), ("close", 77)]
    waits = starter.made[0].waits
    assert waits and all(0 < seconds <= children.STEP_S for seconds in waits) and child.code == 1


def test_what_a_child_owns_on_windows_is_what_its_job_holds(tmp_path, monkeypatch):
    child, starter = make(tmp_path, "windows", interrupt=lambda pid: False)
    a_job(monkeypatch, starter)
    monkeypatch.setattr(children, "_in_job", lambda job, pid: (job, pid) == (77, 5000))
    assert not child.owns(4321)  # not started: nothing is its own
    child.start()
    assert child.owns(4321) and child.owns(5000) and not child.owns(6000)  # itself, a program it started, another's
    child.stop()
    assert not child.owns(4321) and not child.owns(5000)


# -- a child an earlier run left ---------------------------------------------------------------------------------------
def test_a_child_an_earlier_run_left_is_adopted_by_its_pidfile(tmp_path, monkeypatch):
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)
    log = tmp_path / "default.log"
    log.write_text("still serving\n")
    child = Child.adopt(NAME, log, pidfile, clock=Clock(), sleep=lambda seconds: None, system="linux")
    assert child.adopted and child.pid == 5555 and child.alive and child.launch.argv == ()
    assert child.since == pidfile.stat().st_mtime and child.tail() == ["still serving"]
    assert child.note == ""  # (the pidfile does not say who read what it printed)
    assert child.code is None and child.wait(1.0) is None  # its exit code is not this process's to read
    with pytest.raises(ChildError, match=r"runs already \(pid 5555\)"):
        child.start()
    assert Child.adopt(NAME, log, tmp_path / "none.pid") is None  # no pidfile
    pidfile.write_text(f"{os.getpid()} 111")  # (it names this very process)
    alive.add(os.getpid())
    assert Child.adopt(NAME, log, pidfile) is None
    pidfile.write_text("5555 112")  # the number is another process's by now: started at another moment
    assert Child.adopt(NAME, log, pidfile) is None and child.alive is False
    pidfile.write_text("5555 111")
    alive.clear()  # nothing has that number any more
    assert Child.adopt(NAME, log, pidfile) is None


def test_an_adopted_childs_note_says_when_its_output_reaches_no_log(tmp_path, monkeypatch):
    starts = {5555: 111, 7000: 222}  # the child, and the run that started it and reads what it prints
    monkeypatch.setattr(proc_mod, "pid_alive", lambda pid: pid in starts)
    monkeypatch.setattr(proc_mod, "started", starts.get)
    pidfile = tmp_path / "default.pid"
    pidfile.write_text("5555 111 7000 222")
    for system in ("linux", "windows"):  # that run is still there (a boot instance's `launch serve`): nothing to say
        assert Child.adopt(NAME, tmp_path / "x.log", pidfile, system=system).note == ""
    starts[7000] = 223  # its number is another process's by now
    linux = Child.adopt(NAME, tmp_path / "x.log", pidfile, system="linux")
    assert linux.note == children.adopted_words("linux") and "reaches no log" in linux.note
    assert "ends at its next line" in linux.note  # a program in C or Go ends at its next line on Linux (SIGPIPE)
    del starts[7000]  # it has ended
    windows_child = Child.adopt(NAME, tmp_path / "x.log", pidfile, system="windows")
    assert windows_child.note == children.adopted_words("windows") and "next line" not in windows_child.note
    assert windows_child.note.startswith("the program that started it has ended without stopping it")
    started, _ = make(tmp_path / "mine", "linux")
    started.start()
    assert started.note == "" and not started.adopted


def test_adopting_what_this_process_started_gives_the_same_child(tmp_path, monkeypatch):
    child, starter = make(tmp_path, "linux")
    child.start()
    monkeypatch.setattr(proc_mod, "pid_alive", lambda pid: pid == 4321)
    assert Child.adopt("another name", child.log, child.pidfile) is child  # never a second for one process
    starter.made[0].end(0)
    settle(child)
    assert Child.adopt(NAME, child.log, child.pidfile) is None


def test_an_adopted_child_on_linux_is_told_by_its_number_while_its_pidfile_names_it(tmp_path, monkeypatch):
    told: list = []
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)
    monkeypatch.setattr(children, "_leads", lambda pid: True)
    monkeypatch.setattr(children, "_session_of", {5600: 5555}.get)
    monkeypatch.setattr(children, "_signal_group",
                        lambda pid, sig: told.append(("group", pid, sig)) or alive.discard(pid) or True)
    child = Child.adopt(NAME, tmp_path / "x.log", pidfile, clock=Clock(), sleep=lambda seconds: None, system="linux")
    assert child.owns(5555) and child.owns(5600) and not child.owns(5700)  # the session it leads
    assert child.stop() == "ended when asked (SIGTERM), after 2.0 s"
    assert told == [("group", 5555, children.TERM)] and not pidfile.exists() and child.pid is None
    assert child.stop() == "had ended already" and len(told) == 1
    # one that leads no group of its own is told alone, and that is said
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)
    monkeypatch.setattr(children, "_leads", lambda pid: False)
    monkeypatch.setattr(children, "_signal_one", lambda pid, sig: told.append(("one", pid, sig))
                        or (alive.discard(pid) if sig == children.KILL else None) or True)
    child = Child.adopt(NAME, tmp_path / "x.log", pidfile, clock=Clock(), sleep=lambda seconds: None, system="linux")
    assert child.stop() == ("did not end within 8 s after SIGTERM was sent: ended; what it started is not held with "
                            "it and may still run")
    assert told[1:] == [("one", 5555, children.TERM), ("one", 5555, children.KILL)]
    # its number has become another process's: that one is told nothing
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)
    child = Child.adopt(NAME, tmp_path / "x.log", pidfile, clock=Clock(), sleep=lambda seconds: None, system="linux")
    monkeypatch.setattr(proc_mod, "started", lambda pid: 999)
    assert child._signal(children.KILL) is False and child.stop() == "had ended already" and len(told) == 3


def test_an_adopted_child_on_windows_is_asked_through_the_helper_and_ended_alone(tmp_path, monkeypatch):
    asked, ended = [], []
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)
    monkeypatch.setattr(children, "interrupt", lambda pid: asked.append(pid) or False)
    monkeypatch.setattr(proc_mod, "terminate", lambda pid: ended.append(pid) or alive.discard(pid) or True)
    child = Child.adopt(NAME, tmp_path / "x.log", pidfile, clock=Clock(), sleep=lambda seconds: None, system="windows")
    assert child.owns(5555) and not child.owns(5600)  # no job of this process's holds it: its own number alone
    assert child.stop() == "Ctrl+C could not reach it: ended; what it started is not held with it and may still run"
    assert asked == [5555] and ended == [5555] and not pidfile.exists()
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)  # a Ctrl+C of the caller's own is used as it is given
    child = Child.adopt(NAME, tmp_path / "x.log", pidfile, interrupt=lambda pid: alive.discard(pid) or True,
                        clock=Clock(), sleep=lambda seconds: None, system="windows")
    assert child.stop() == "ended when asked (Ctrl+C), after 2.0 s" and asked == [5555] and ended == [5555]


# -- Ctrl+C ------------------------------------------------------------------------------------------------------------
def test_ctrl_c_goes_through_the_consoles_helper(monkeypatch):
    ran: list = []

    def runner(args, timeout):
        ran.append((args, timeout))
        return (0 if args[-1] == "4321" else 1), "", ""
    assert children.interrupt(4321, runner=runner) is True and children.interrupt(99, runner=runner) is False
    # -P: the helper runs in the platform's own folder, and nothing lying there is imported in place of Python's own
    assert ran[0] == ([sys.executable, "-P", "-m", "liminal_libs.console", "interrupt", "4321"], 5.0)
    for error in (OSError("no python"), subprocess.TimeoutExpired("python", 5), CommandError("refused")):
        def failing(args, timeout, error=error):
            raise error
        assert children.interrupt(4321, runner=failing) is False  # it could not: never an error
    assert children.interrupt("not a number", runner=runner) is False and len(ran) == 2
    # without a stand-in: the helper is run on Windows, and nothing is run anywhere else
    monkeypatch.setattr(children, "this_system", lambda: "linux")
    assert children.interrupt(4321) is False
    monkeypatch.setattr(children, "this_system", lambda: "windows")
    monkeypatch.setattr(children, "_run", runner)
    assert children.interrupt(4321) is True and len(ran) == 3


def test_the_helper_is_run_without_a_window_and_without_a_thread(monkeypatch):
    seen: dict = {}

    def run(args, **kw):
        seen.update(kw, args=args)
        return subprocess.CompletedProcess(args, 3)
    monkeypatch.setattr(children, "_run", REAL_RUN)  # the real one, over a stand-in for subprocess.run
    monkeypatch.setattr(subprocess, "run", run)
    assert children._run(["python", "-P", "-m", "liminal_libs.console", "interrupt", "4321"], 5.0) == (3, "", "")
    assert seen["args"][-2:] == ["interrupt", "4321"] and seen["timeout"] == 5.0
    # nothing of its output is read (reading it takes threads, which cannot be started while this process is ending)
    assert (seen["stdin"], seen["stdout"], seen["stderr"]) == (subprocess.DEVNULL,) * 3
    assert seen.get("creationflags", 0) == (0x08000000 if os.name == "nt" else 0)


# -- every child at once -----------------------------------------------------------------------------------------------
def test_every_child_is_stopped_side_by_side(tmp_path, nothing_real):
    together = threading.Barrier(2, timeout=10)
    starters: list = []

    def ctrl_c(pid):
        together.wait()  # each is asked while the other is being asked too: side by side, not one after another
        next(p for s in starters for p in s.made if p.pid == pid).end(0)
        return True
    kids = []
    for n in (1, 2):
        child, starter = make(tmp_path / str(n), "windows", starter=Starter(first=4320 + n), interrupt=ctrl_c)
        starters.append(starter)
        kids.append(child)
        child.start()
    assert nothing_real == [children.stop_all] and children._all == kids  # registered once, at the first start
    children.stop_all()
    assert not kids[0].alive and not kids[1].alive and children._all == []
    children.stop_all()  # again: none is left, nothing is done
    assert [s.made[0].told for s in starters] == [[], []]


def test_stopping_several_says_how_each_went_and_one_failure_keeps_none_running(tmp_path):
    first, _ = make(tmp_path / "1", "linux")
    second, starter = make(tmp_path / "2", "linux", starter=Starter(first=5000))
    third, _ = make(tmp_path / "3", "linux")
    first.start()
    second.start()

    def broken():
        raise OSError("its handle is gone")
    starter.made[0].terminate = broken
    assert children.stop_these([first, second, third]) == [
        "ended when asked (SIGTERM), after 2.0 s", "its handle is gone", "was not started"]
    assert children.stop_these([]) == []


def test_while_this_process_is_ending_children_are_stopped_one_after_another(tmp_path, monkeypatch):
    kids = [make(tmp_path / str(n), "linux", starter=Starter(first=4320 + n))[0] for n in (1, 2, 3)]
    for child in kids:
        child.start()
    start = threading.Thread.start

    def no_new_thread(self):
        if self.name.startswith("child-stop-"):
            raise RuntimeError("can't create new thread at interpreter shutdown")
        start(self)
    monkeypatch.setattr(threading.Thread, "start", no_new_thread)
    assert children.stop_these(kids) == ["ended when asked (SIGTERM), after 2.0 s"] * 3
    assert not any(child.alive for child in kids)


# -- a command's lines -------------------------------------------------------------------------------------------------
def command(chunks=(), code=0, ends=True, kind=Process):
    """subprocess.Popen as a stand-in for a streamed command: what it prints, then its end (`ends` False: it runs on
    until it is ended). (The stand-in, the processes it made.)"""
    starter = Starter(kind=kind)

    def popen(argv, **kw):
        process = starter(argv, **kw)
        process.stdout.chunks += list(chunks)
        if ends:
            process.end(code)
        return process
    return popen, starter.made


def test_a_streamed_commands_lines_are_handed_on_as_they_come(tmp_path):
    e = "é".encode()
    popen, made = command([b"Resolved 3 packages\r\nDown", b"loading torch\rDownloading torch 50%\r",
                           b"Downloading torch 100%\n\n   \n", b"x" * 5000 + b"\n", e[:1], e[1:] + b" done"])
    lines: list = []
    assert stream(["C:/tools/uv.exe", "pip", "install", "torch"], lines.append, env={"UV_CACHE_DIR": tmp_path},
                  cwd=tmp_path, popen=popen, system="windows") == 0
    assert lines == ["Resolved 3 packages", "Downloading torch", "Downloading torch 50%", "Downloading torch 100%",
                     "x" * LINE_CHARS, "é done"]
    kw = made[0].kw
    assert made[0].argv == ["C:/tools/uv.exe", "pip", "install", "torch"] and made[0].told == []
    # no standard input, its errors among its lines, no window
    assert (kw["stdin"], kw["stdout"], kw["stderr"]) == (subprocess.DEVNULL, subprocess.PIPE, subprocess.STDOUT)
    assert kw["creationflags"] == 0x08000000 and "start_new_session" not in kw
    assert kw["env"] == {"UV_CACHE_DIR": str(tmp_path)} and kw["cwd"] == str(tmp_path)
    popen, made = command([b"error: no such package\n"], code=2)
    assert stream(["uv", "pip", "install", "nothing"], lines.append, popen=popen, system="linux") == 2  # the caller's
    assert made[0].kw["start_new_session"] is True and made[0].kw["cwd"] is None
    assert lines[-1] == "error: no such package" and "creationflags" not in made[0].kw


def test_a_streamed_command_given_no_environment_gets_none_of_liminals_variables(monkeypatch):
    monkeypatch.setenv("LIMINAL_AI_OLLAMA_INSTANCES", "{}")
    monkeypatch.setenv("LIMINAL_PLATFORM_DIR", "elsewhere")
    monkeypatch.setenv("HF_HOME", "kept")
    for system in ("linux", "windows"):
        popen, made = command([b"done\n"])
        assert stream(["hf", "download", "org/model"], lambda line: None, popen=popen, system=system) == 0
        env = made[0].kw["env"]
        assert env["HF_HOME"] == "kept" and "LIMINAL_PLATFORM_DIR" not in env, system
        assert "LIMINAL_AI_OLLAMA_INSTANCES" not in env
        assert env == environment(Launch(("hf",), drop=("LIMINAL_*",)), system=system)  # this process's, but those


def test_a_streamed_command_that_runs_too_long_is_ended(monkeypatch):
    monkeypatch.setattr(children, "WATCH_S", 0.01)
    popen, made = command([b"Downloading torch\n"], ends=False)
    lines: list = []
    # on Windows without a job object, the command alone is ended, and that is said
    with pytest.raises(ChildError, match=r"^uv pip install torch took more than 0\.05 s: ended; what it started is "
                                         r"not held with it and may still run$") as e:
        stream(["C:/uv.exe", "pip", "install", "torch", "--quiet"], lines.append, timeout=0.05, popen=popen,
               system="windows")
    assert isinstance(e.value, CommandError) and made[0].told == ["kill"] and lines == ["Downloading torch"]


def test_a_cancelled_job_ends_its_command(monkeypatch):
    monkeypatch.setattr(children, "WATCH_S", 0.01)
    popen, made = command([b"Downloading model\n"], ends=False)
    out = Output()
    threading.Timer(0.05, out.cancel).start()
    with pytest.raises(Cancelled, match=r"^hf download org/model was cancelled: ended; what it started is not held"):
        stream(["hf", "download", "org/model"], out, cancel=lambda: out.cancelled, popen=popen, system="windows")
    assert made[0].told == ["kill"] and out.text == "Downloading model\n"
    assert not issubclass(Cancelled, CommandError)  # a stop its user asked for, not a failure

    def broken():
        raise RuntimeError("the job is gone")
    popen, made = command([b"done\n"])
    assert stream(["hf", "download", "org/model"], out, cancel=broken, popen=popen, system="linux") == 0


def test_on_windows_a_streamed_command_is_ended_through_its_job(monkeypatch):
    monkeypatch.setattr(children, "WATCH_S", 0.01)
    popen, made = command(ends=False)
    done = a_job(monkeypatch, types.SimpleNamespace(made=made))
    with pytest.raises(ChildError, match="^npm install took more than 0.03 s: ended with what it started$"):
        stream(["npm", "install"], lambda line: None, timeout=0.03, popen=popen, system="windows")
    # ended with what it started when its time was up; at its end the job is ended again (what it left running) and
    # closed
    assert done == [("hold", 77, 4321), ("end", 77), ("end", 77), ("close", 77)] and made[0].told == []


def test_a_command_that_ended_while_something_it_started_holds_its_output_is_not_waited_for(monkeypatch):
    monkeypatch.setattr(children, "WATCH_S", 0.01)
    monkeypatch.setattr(children, "LEFT_S", 0.03)
    popen, made = command([b"added 12 packages\n"], ends=False)
    lines: list = []

    def line(text):
        lines.append(text)
        made[0].returncode = 0  # the command ends here; a program it started keeps its output open
    assert stream(["npm", "install"], line, popen=popen, system="linux") == 0
    assert made[0].told == ["kill"] and lines == ["added 12 packages"]


class Escaped(Process):
    """A command one of whose programs is out of what ends with it (a daemon that left its group, one outside its
    job): ending the command ends it alone, and its output stays open until that program ends by itself, 3 s after
    the start (or at the test's end)."""

    def __init__(self, argv, pid=4321, **kw):
        super().__init__(argv, pid=pid, **kw)
        self.stdout.chunks.append(b"started\n")
        later = threading.Timer(3.0, self.stdout.done.set)
        later.daemon = True
        later.start()

    def kill(self):
        self.told.append("kill")
        self.leave(-9)


def test_its_timeout_and_its_cancel_hold_while_something_out_of_reach_holds_its_output(monkeypatch):
    monkeypatch.setattr(children, "WATCH_S", 0.01)
    monkeypatch.setattr(children, "LEFT_S", 0.05)
    starter = Starter(kind=Escaped)
    lines: list = []
    gone = "ended; something it started still holds its output and may still run"
    # its time is up: it is ended, its output given LEFT_S more, then given up, and that is said
    began = time.monotonic()
    with pytest.raises(ChildError, match=rf"^npm install took more than 0\.1 s: {gone}$"):
        stream(["npm", "install"], lines.append, timeout=0.1, popen=starter, system="linux")
    assert time.monotonic() - began < 1.5 and starter.made[-1].told == ["kill"] and lines == ["started"]
    # cancelled: the same, as a cancel (Windows without a job: the command alone is ended, as there)
    cancelled = threading.Event()
    threading.Timer(0.1, cancelled.set).start()
    began = time.monotonic()
    with pytest.raises(Cancelled, match=rf"^npm install was cancelled: {gone}$"):
        stream(["npm", "install"], lines.append, cancel=cancelled.is_set, popen=starter, system="windows")
    assert time.monotonic() - began < 1.5 and starter.made[-1].told == ["kill"]

    # it ends by itself, and what holds its output is not ended with it: given up, and said, not waited for
    def ended(text):
        starter.made[-1].leave(0)
    began = time.monotonic()
    with pytest.raises(ChildError, match=r"^npm install ended \(exit code 0\), but something it started still holds "
                                         r"its output and may still run$"):
        stream(["npm", "install"], ended, popen=starter, system="linux")
    assert time.monotonic() - began < 1.5 and starter.made[-1].told == ["kill"]


def test_a_reader_that_fails_ends_the_command_and_its_error_passes_on():
    popen, made = command([b"one\n", b"two\n"], ends=False)

    def line(text):
        raise RuntimeError("the page is gone")
    with pytest.raises(RuntimeError, match="the page is gone"):
        stream(["uv", "sync"], line, popen=popen, system="linux")
    assert made[0].told == ["kill"]


def test_a_command_that_cannot_run_says_so():
    def missing(argv, **kw):
        raise FileNotFoundError("no such file")
    with pytest.raises(ChildError, match="^uv could not run: no such file$"):
        stream(["/opt/uv", "sync"], print, popen=missing)
    with pytest.raises(ChildError, match="there is no command to run"):
        stream([], print, popen=missing)
    assert children.said(["C:\\tools\\uv.exe", "pip", "install", "--python", "x", "y"]) == "uv pip install --python"
    assert children.said([]) == "the command" and children.program("/usr/bin/npm") == "npm"
    # each word on one line, cut: a script or a long value never fills the words
    script = "import sys\nprint(sys.version)\n" + "x" * 100
    assert children.said(["python", "-c", script]) == "python -c " + ("import sys print(sys.version) " + "x" * 9) + "…"
    assert len(children.said(["uv", "y" * 500])) == len("uv ") + children.SAID_CHARS


def test_a_real_streamed_command_on_linux_is_ended_by_its_group_before_it_is_collected(monkeypatch):
    monkeypatch.setattr(children, "WATCH_S", 0.01)
    popen, made, events = real_linux(monkeypatch)
    with pytest.raises(ChildError, match="^uv sync took more than 0.03 s: ended with what it started$"):
        stream(["uv", "sync"], lambda line: None, timeout=0.03, popen=popen, system="linux")
    assert events == [("group", 4321, children.KILL), ("group", 4321, children.KILL), "collected"]
    del events[:]

    def ended(argv, **kw):
        process = popen(argv, pid=4400, **kw)
        process.stdout.chunks.append(b"Installed 3 packages\n")
        process.end(0)
        return process
    lines: list = []
    assert stream(["uv", "sync"], lines.append, popen=ended, system="linux") == 0 and lines == ["Installed 3 packages"]
    assert events == [("group", 4400, children.KILL), "collected"]  # what it left running, then it is collected


# -- a child spoken to through pipes -----------------------------------------------------------------------------------
class Input:
    """A piped child's standard input as a stand-in: what was written to it, and when it was closed (noted in its
    process's `told`). A write can be held, as a child that does not read its input holds it; its end breaks it."""

    def __init__(self, told: list):
        self.told = told
        self.written = bytearray()
        self.closed = False
        self.held: threading.Event | None = None  # set by the test: a write waits for it
        self.writing = threading.Event()  # a write has begun
        self.broken = False  # its child has ended: a write fails
        self.at_end = None  # what its child does when it reads the end of its input

    def write(self, data):
        if self.closed:
            raise ValueError("write to closed file")
        self.writing.set()
        if self.held is not None:
            self.held.wait(10)
        if self.broken:
            raise BrokenPipeError(32, "Broken pipe")
        self.written += bytes(data)
        return len(data)

    def flush(self):
        pass

    def close(self):
        if not self.closed:
            self.closed = True
            self.told.append("input closed")
            if self.at_end is not None:
                self.at_end()


class Talker(Process):
    """A piped child as a stand-in: its three pipes. It ends when its input is closed, unless the test makes it
    `stubborn`; its end ends its output, its errors and any write that waits on its input."""

    def __init__(self, argv, pid=4321, **kw):
        super().__init__(argv, pid=pid, **kw)
        self.stdin = Input(self.told)
        self.stderr = Pipe()
        self.stubborn = False
        self.stdin.at_end = lambda: None if self.stubborn else self.end(0)

    def end(self, code=0):
        super().end(code)
        self.stderr.done.set()
        self.stdin.broken = True
        if self.stdin.held is not None:
            self.stdin.held.set()


class RealTalker(Real):
    """A piped child as the real subprocess.Popen makes one, as far as isinstance can tell (Real's, with three
    pipes). Its end comes before it is collected, as a real one's."""

    def __init__(self, argv, pid=4321, **kw):
        super().__init__(argv, pid=pid, **kw)
        self.told: list = []
        self.stdin = Input(self.told)
        self.stderr = Pipe()
        self.stubborn = False
        self.stdin.at_end = lambda: None if self.stubborn else self.end(0)

    def end(self, code=0):
        super().end(code)
        self.stderr.done.set()
        self.stdin.broken = True


def piped(folder, system, launch=None, starter=None, line=None, **outside):
    """A piped child over stand-ins, in a folder of its own: (the child, what stands in for Popen, the lines handed
    on, what it was told at its end)."""
    starter = starter or Starter(kind=Talker)
    lines, ends = [], []
    outside.setdefault("clock", Clock())
    outside.setdefault("sleep", lambda seconds: None)
    child = children.Piped("git", launch or Launch(("uvx", "mcp-server-git")), Path(folder) / "logs" / "default.log",
                           Path(folder) / "run" / "default.pid", line=line or lines.append, ended=ends.append,
                           popen=starter, system=system, **outside)
    return child, starter, lines, ends


def heard(child):
    """Its errors copied, its lines read, its end seen and cleaned up after."""
    for thread in (child._reader, child._hearer, child._watcher):
        thread.join(10)
        assert not thread.is_alive()


def until(test, seconds=5.0):
    """Waited for: what a thread of the child does comes as it comes."""
    end = time.monotonic() + seconds
    while not test():
        assert time.monotonic() < end, "it did not come in time"
        time.sleep(0.005)


PIPES = (subprocess.PIPE,) * 3


def test_a_piped_child_is_started_windowless_with_three_pipes_and_held_in_a_job(tmp_path, monkeypatch, nothing_real,
                                                                                 k32):
    launch = Launch(("C:/tools/uv/uvx.exe", "mcp-server-git", "--repository", str(tmp_path)),
                    {"PATH": "C:\\Windows", "GIT_TOKEN": SECRET}, drop=("*",), secret=("GIT_TOKEN",))
    monkeypatch.setenv("OLLAMA_ORIGINS", "*")
    child, starter, lines, ends = piped(tmp_path, "windows", launch)
    done = a_job(monkeypatch, starter)
    assert isinstance(child, Child) and (child.pid, child.alive, child.code, child.why) == (None, False, None, "")
    assert child.start() == 4321 and child.alive and child.pid == 4321
    kw = starter.made[0].kw
    assert (kw["stdin"], kw["stdout"], kw["stderr"]) == PIPES and kw["bufsize"] == 0 and kw["cwd"] is None
    assert kw["creationflags"] == 0x08000000 and "start_new_session" not in kw  # windowless, no group of its own
    assert kw["env"] == {"PATH": "C:\\Windows", "GIT_TOKEN": SECRET}  # drop "*": what its launch gives, alone
    assert done == [("hold", 77, 4321)] and children._all == [child] and nothing_real == [children.stop_all]
    assert k32.calls == []  # its console's Ctrl+C is never asked for: it is told by its input
    names = [(t.name, t.daemon) for t in (child._reader, child._hearer, child._watcher)]
    assert names == [("child-git", True), ("child-out-git", True), ("child-end-git", True)]
    first = child.log.read_text("utf-8").splitlines()[0]
    assert re.fullmatch(r"\S+ liminal: git started \(pid 4321\), its input and output piped: .*mcp-server-git.*", first)
    assert SECRET not in first and child.pidfile.read_text().split()[0] == "4321"
    starter.made[0].end(0)
    heard(child)
    assert done == [("hold", 77, 4321), ("close", 77)] and not child.alive and child.code == 0
    assert ends == [""] and children._all == [] and not child.pidfile.exists()


def test_on_linux_a_piped_child_leads_a_session_of_its_own(tmp_path, monkeypatch):
    monkeypatch.setattr(keep_mod, "_job", refusing("job object"))  # Windows' way: not asked for here
    child, starter, lines, ends = piped(tmp_path, "linux", Launch(("uvx", "mcp-server-time"), cwd=str(tmp_path)))
    child.start()
    kw = starter.made[0].kw
    assert kw["start_new_session"] is True and "creationflags" not in kw and kw["cwd"] == str(tmp_path)
    assert (kw["stdin"], kw["stdout"], kw["stderr"]) == PIPES and kw["bufsize"] == 0


def test_each_line_it_prints_is_handed_on_as_it_comes(tmp_path):
    child, starter, lines, ends = piped(tmp_path, "linux")
    child.start()
    out = starter.made[0].stdout
    out.chunks += [b'{"jsonrpc":"2.0","id":1,', b'"result":{}}\r\n']  # one line in two pieces, ended as on Windows
    until(lambda: lines == ['{"jsonrpc":"2.0","id":1,"result":{}}'])  # handed on before it ends
    word = "é".encode()
    out.chunks += [b"\n  \n" + b'{"id":2}\n{"id"', b":3}\n" + word[:1], word[1:] + b" its last line, not ended"]
    starter.made[0].end(0)
    heard(child)
    assert lines == ['{"jsonrpc":"2.0","id":1,"result":{}}', '{"id":2}', '{"id":3}', "é its last line, not ended"]
    assert ends == [""] and child.why == "" and starter.made[0].stdout.closed  # its pipe closed once read to its end
    assert starter.made[0].stdin.closed  # its input too, once its output has ended
    assert '"id"' not in child.log.read_text("utf-8")  # what it says is no part of its log


def test_what_it_prints_as_errors_goes_into_its_log_without_its_secret(tmp_path, monkeypatch):
    launch = Launch(("uvx", "mcp-server-git"), {"GIT_TOKEN": SECRET}, secret=("GIT_TOKEN",))
    child, starter, lines, ends = piped(tmp_path, "linux", launch)
    child.start()
    key = SECRET.encode()
    starter.made[0].stderr.chunks += [b"warning: token " + key[:4], key[4:] + b" refused\n", b"listening on stdio\n"]
    starter.made[0].end(0)
    heard(child)
    text = child.log.read_text("utf-8")
    assert SECRET not in text and text.splitlines()[1:] == [f"warning: token {PLACEHOLDER} refused",
                                                            "listening on stdio"]
    assert child.tail(1) == ["listening on stdio"] and lines == []
    monkeypatch.setattr(children, "LOG_MAX", 200)  # past its size it is moved aside, as a Child's
    child.start()
    starter.made[1].stderr.chunks += [bytes([65 + i]) * 89 + b"\n" for i in range(3)]
    starter.made[1].end(0)
    heard(child)
    both = child.log.with_name("default.log.1").read_bytes() + child.log.read_bytes()
    assert all(bytes([65 + i]) * 89 + b"\n" in both for i in range(3)) and child.log.stat().st_size < 200


def test_a_line_is_sent_whole_and_what_is_not_one_line_is_refused(tmp_path):
    child, starter, lines, ends = piped(tmp_path, "windows")
    with pytest.raises(ChildError, match="^git does not run: nothing was sent to it$"):
        child.send("{}")  # not started
    child.start()
    child.send('{"jsonrpc":"2.0","id":1,"method":"ping"}')
    child.send(b'{"id":2}')
    child.send("é")
    stdin = starter.made[0].stdin
    assert bytes(stdin.written) == b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"id":2}\n' + "é\n".encode()
    for bad in ("a\nb", "a\rb", b"x\n", "{}\r\n"):
        with pytest.raises(ValueError, match="^a line sent to git holds no line break: each message is one line$"):
            child.send(bad)
    stdin.broken = True  # its input broke (it is ending)
    with pytest.raises(ChildError, match=r"^git did not take the line: its input is closed \(.*Broken pipe"):
        child.send("{}")
    starter.made[0].end(0)
    heard(child)
    with pytest.raises(ChildError, match="^git does not run: nothing was sent to it$"):
        child.send("{}")
    assert child._input is None and stdin.closed


def test_a_line_longer_than_its_most_ends_the_child(tmp_path, monkeypatch):
    monkeypatch.setattr(children, "LINE_MAX", 64)
    child, starter, lines, ends = piped(tmp_path, "windows")
    done = a_job(monkeypatch, starter)
    child.start()
    starter.made[0].stubborn = True  # (the end of its input would not end it)
    starter.made[0].stdout.chunks += [b'{"id":1}\n', b"x" * 40, b"y" * 40]  # no line end within 64 bytes
    heard(child)
    words = "it printed a line longer than 64 bytes"
    assert lines == ['{"id":1}'] and child.why == words and ends == [words]
    assert done == [("hold", 77, 4321), ("end", 77), ("close", 77)] and not child.alive  # ended with its job, at once
    assert child.code == 1 and f"liminal: git was ended: {words}" in child.log.read_text("utf-8")
    assert starter.made[0].told == ["input closed"]
    # one whole line longer than that, on Linux: killed; what it printed after it is read and dropped
    child, starter, lines, ends = piped(tmp_path / "linux", "linux")
    child.start()
    starter.made[0].stubborn = True
    starter.made[0].stdout.chunks += [b"z" * 70 + b"\n" + b'{"id":2}\n', b'{"id":3}\n']
    heard(child)
    assert lines == [] and ends == [words] and starter.made[0].told == ["input closed", "kill"]
    child.start()  # its next start is a start like any other
    assert child.why == "" and child.alive


def test_its_most_is_four_mib():
    assert children.LINE_MAX == 4 * 1024 * 1024 and children.TERM_S == 2.0 and children.SEND_WAIT_S == 1.0


def test_a_line_its_plugin_cannot_take_ends_the_child(tmp_path):
    def take(text):
        raise ValueError(f"not JSON: {text[:5]}")
    child, starter, lines, ends = piped(tmp_path, "linux", line=take)
    child.start()
    starter.made[0].stubborn = True
    starter.made[0].stdout.chunks.append(b"hello there\n")
    heard(child)
    assert child.why == "its line could not be taken (ValueError: not JSON: hello)" and ends == [child.why]
    assert starter.made[0].told == ["input closed", "kill"] and not child.alive
    said: list = []

    def told(why):
        said.append(why)
        raise RuntimeError("its plugin's own fault")
    talker = Starter(kind=Talker)
    child = children.Piped("git", Launch(("uvx",)), tmp_path / "b.log", tmp_path / "b.pid", ended=told, popen=talker,
                           system="linux")  # no `line`: its lines are dropped
    child.start()
    talker.made[0].stdout.chunks.append(b'{"id":1}\n')
    talker.made[0].end(0)
    heard(child)
    assert said == [""] and not child.alive and child.why == ""


def test_stop_closes_its_input_first_and_one_that_ends_then_is_not_ended_by_force(tmp_path, monkeypatch):
    child, starter, lines, ends = piped(tmp_path, "windows", interrupt=refusing("Ctrl+C: it is told by its input"))
    done = a_job(monkeypatch, starter)
    assert child.stop() == "was not started"
    child.start()
    assert child.stop() == "ended when its input was closed, after 2.0 s"  # (the stand-in clock: a second a look)
    assert starter.made[0].told == ["input closed"] and done == [("hold", 77, 4321), ("close", 77)]
    assert child.stop() == "had ended already (exit code 0)" and starter.made[0].told == ["input closed"]
    heard(child)
    assert ends == [""]


def test_one_that_does_not_end_at_the_end_of_its_input_is_ended_after_its_grace_on_windows(tmp_path, monkeypatch):
    clock = Clock()
    child, starter, lines, ends = piped(tmp_path, "windows", clock=clock)
    done = a_job(monkeypatch, starter)
    child.start()
    starter.made[0].stubborn = True
    assert child.stop() == "did not end within 8 s after its input was closed: ended with what it started"
    assert clock.now >= GRACE_S and done == [("hold", 77, 4321), ("end", 77), ("close", 77)]
    assert starter.made[0].told == ["input closed"] and child.code == 1  # (its job's end: TerminateJobObject)
    # without a job: the child alone, and that is said
    monkeypatch.setattr(keep_mod, "_job", lambda: None)
    child, starter, lines, ends = piped(tmp_path / "alone", "windows")
    child.start()
    starter.made[0].stubborn = True
    assert child.stop(2) == ("did not end within 2 s after its input was closed: ended; what it started is not held "
                             "with it and may still run")
    assert starter.made[0].told == ["input closed", "kill"]


def test_on_linux_sigterm_then_sigkill_follow_its_grace(tmp_path):
    clock = Clock()
    child, starter, lines, ends = piped(tmp_path, "linux", clock=clock)
    child.start()
    starter.made[0].stubborn = True  # it goes on past the end of its input, and ends at SIGTERM
    assert child.stop() == ("did not end within 8 s after its input was closed: ended by SIGTERM, with what it "
                            "started")
    assert starter.made[0].told == ["input closed", "terminate"] and child.code == -15
    child.start()
    starter.made[1].stubborn = starter.made[1].deaf = True  # and SIGTERM too: SIGKILL, TERM_S later
    began = clock.now
    assert child.stop(2) == ("did not end within 2 s after its input was closed, nor within 2 s after SIGTERM: "
                             "ended with what it started")
    assert starter.made[1].told == ["input closed", "terminate", "kill"] and clock.now - began >= 4


def test_a_real_piped_child_on_linux_is_ended_by_its_group_before_it_is_collected(tmp_path, monkeypatch):
    popen, made, events = real_linux(monkeypatch, kind=RealTalker)
    child, _, lines, ends = piped(tmp_path, "linux", starter=popen)
    child.start()
    assert child.stop() == "ended when its input was closed, after 2.0 s"
    # its input closed; it ended; what it left in its group killed while its number was its own; then collected
    assert made[0].told == ["input closed"] and events == [("group", 4321, children.KILL), "collected"]
    child, _, lines, ends = piped(tmp_path / "2", "linux", starter=popen)
    child.start()
    made[1].stubborn = True
    assert child.stop() == ("did not end within 8 s after its input was closed: ended by SIGTERM, with what it "
                            "started")
    assert events[2:] == [("group", 4322, children.TERM), ("group", 4322, children.KILL), "collected"]


def test_a_send_its_child_does_not_read_does_not_hold_up_its_stop(tmp_path, monkeypatch):
    monkeypatch.setattr(children, "SEND_WAIT_S", 0.05)
    child, starter, lines, ends = piped(tmp_path, "linux")
    child.start()
    stdin = starter.made[0].stdin
    stdin.held = threading.Event()  # it reads nothing: the write waits
    failed: list = []

    def send():
        try:
            child.send('{"id":1,"method":"tools/call"}')
        except ChildError as e:
            failed.append(str(e))
    sender = threading.Thread(target=send, name="sender")
    sender.start()
    assert stdin.writing.wait(5)
    # its input cannot be closed under the write (Windows would wait as long as the write): no grace, it is ended,
    # SEND_WAIT_S after the stop was asked (the write would hold it 10 s)
    began = time.monotonic()
    assert child.stop() == ("its input could not be closed (a line it does not read was being sent): ended by "
                            "SIGTERM, with what it started")
    assert time.monotonic() - began < 2.0
    assert starter.made[0].told[:1] == ["terminate"]  # its input was not closed first (its reader may, at its end)
    sender.join(10)
    assert failed and failed[0].startswith("git did not take the line: its input is closed")


def test_a_piped_child_an_earlier_run_left_is_ended_before_the_next_one_starts(tmp_path, monkeypatch):
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)
    told: list = []
    monkeypatch.setattr(children, "_leads", lambda pid: True)
    monkeypatch.setattr(children, "_signal_group",
                        lambda pid, sig: told.append(("group", pid, sig)) or alive.discard(pid) or True)
    child, starter, lines, ends = piped(tmp_path, "linux")
    assert child.start() == 4321 and told == [("group", 5555, children.TERM)]
    first, second = child.log.read_text("utf-8").splitlines()[:2]
    assert first.endswith("liminal: git of an earlier run (pid 5555) was ended first: ended by SIGTERM")
    assert "git started (pid 4321)" in second and child.pidfile.read_text().split()[0] == "4321"
    starter.made[0].end(0)
    heard(child)
    # deaf to SIGTERM: SIGKILL to its group, TERM_S later
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)
    monkeypatch.setattr(children, "_signal_group", lambda pid, sig: told.append(("group", pid, sig)) or (
        alive.discard(pid) if sig == children.KILL else None) or True)
    child.start()
    assert told[1:] == [("group", 5555, children.TERM), ("group", 5555, children.KILL)]
    assert "was ended first: did not end within 2 s after SIGTERM: ended with what it started" in child.log.read_text(
        "utf-8")
    starter.made[1].end(0)
    heard(child)
    # one that cannot be ended: nothing is started
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)
    monkeypatch.setattr(children, "_signal_group", lambda pid, sig: True)
    with pytest.raises(ChildError, match=r"^git could not start: an earlier run's \(pid 5555\) still runs and could "
                                         r"not be ended$"):
        child.start()
    assert len(starter.made) == 2


def test_an_earlier_run_s_piped_child_on_windows_is_ended_alone_and_not_asked_with_ctrl_c(tmp_path, monkeypatch):
    pidfile, alive = an_earlier_run(tmp_path, monkeypatch)
    ended: list = []
    monkeypatch.setattr(children, "interrupt", refusing("Ctrl+C: a piped child is not asked so"))
    monkeypatch.setattr(proc_mod, "terminate", lambda pid: ended.append(pid) or alive.discard(pid) or True)
    adopted = children.Piped.adopt("git", tmp_path / "x.log", pidfile, clock=Clock(), sleep=lambda s: None,
                                   system="windows")
    assert isinstance(adopted, children.Piped) and adopted.adopted and adopted.pid == 5555
    with pytest.raises(ChildError, match=r"^git's input is closed: nothing was sent to it \(an earlier run started "
                                         r"it\)$"):
        adopted.send("{}")  # its pipes were an earlier run's
    assert adopted.stop() == "ended; what it started is not held with it and may still run" and ended == [5555]
    assert not pidfile.exists() and adopted.stop() == "had ended already"


def test_one_this_process_runs_is_never_ended_for_another_start(tmp_path, monkeypatch):
    first, starter, lines, ends = piped(tmp_path, "linux")
    first.start()
    monkeypatch.setattr(proc_mod, "pid_alive", lambda pid: pid == 4321)
    second, unused, _, _ = piped(tmp_path, "linux")  # the same pidfile: the first one's
    with pytest.raises(ChildError, match=r"^git runs already \(pid 4321\)$"):
        second.start()
    assert first.alive and starter.made[0].told == [] and unused.made == []


def test_piped_children_are_stopped_at_exit_with_every_other(tmp_path, nothing_real):
    plain, plain_starter = make(tmp_path / "plain", "linux")
    talker, starter, lines, ends = piped(tmp_path / "piped", "linux")
    plain.start()
    talker.start()
    assert nothing_real == [children.stop_all] and children._all == [plain, talker]  # registered once
    children.stop_all()
    assert not plain.alive and not talker.alive and children._all == []
    assert starter.made[0].told == ["input closed"] and plain_starter.made[0].told == ["terminate"]
