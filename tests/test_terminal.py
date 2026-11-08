"""The platform's terminal (liminal_libs.machines.terminal): output read from an offset, the oldest dropped past the cap; a
process's output kept as it comes, the keys written to it, closed; all through a stand-in process (none started here)."""
from __future__ import annotations

import io
import threading
import time

from liminal_libs.machines.terminal import Output, Terminal


def test_output_is_read_from_an_offset_and_keeps_the_latest():
    out = Output(max_kept=10)
    out("one")
    out.write("two")
    assert out.read(0) == ("one\ntwo", 0, 7) and out.read(4) == ("two", 4, 7)
    out.write("-three-four")
    text, start, end = out.read(0)
    assert (text, start, end) == ("three-four", 8, 18)  # the oldest dropped past the cap; a page that fell behind reads from there
    assert out.read(17) == ("r", 17, 18) and out.end == 18


class Pipe(io.RawIOBase):
    """A process's standard output: chunks as they come, then the end."""

    def __init__(self):
        self.chunks: list[bytes] = []
        self.done = threading.Event()

    def readable(self):
        return True

    def read(self, n=-1):
        while not self.chunks and not self.done.is_set():
            time.sleep(0.01)
        return self.chunks.pop(0) if self.chunks else b""


class Proc:
    def __init__(self, argv, **kw):
        self.argv, self.kw = argv, kw
        self.stdout, self.stdin, self.code = Pipe(), io.BytesIO(), None

    def poll(self):
        return self.code

    def terminate(self):
        self.code = -15
        self.stdout.done.set()

    def wait(self, timeout=None):
        return self.code

    def kill(self):
        self.terminate()


def test_a_terminal_keeps_what_the_process_prints_and_writes_the_keys():
    made: list = []

    def popen(argv, **kw):
        made.append(Proc(argv, **kw))
        return made[-1]
    term = Terminal(["wsl", "-d", "Liminal-Ubuntu"], popen=popen, title="Liminal-Ubuntu")
    proc = made[0]
    assert proc.kw["bufsize"] == 0 and proc.kw["env"]["WSL_UTF8"] == "1" and term.alive
    word = "café".encode()
    proc.stdout.chunks += ["liminal@pc:~$ ".encode(), word[:4], word[4:]]  # a character split between two reads
    for _ in range(200):
        if term.output.end >= 18:
            break
        time.sleep(0.01)
    got = term.read(0)
    assert got["text"] == "liminal@pc:~$ café" and got["alive"] and got["title"] == "Liminal-Ubuntu"
    assert term.read(got["offset"])["text"] == ""
    term.write("ls\r")
    assert proc.stdin.getvalue() == b"ls\r"
    term.close()
    assert not term.alive and proc.code == -15


def test_a_read_is_held_until_there_is_output():
    """A page's read waits for the next output (its echo shows at once) or the end, never longer than asked."""
    out = Output()
    started = time.monotonic()
    assert out.wait(0, 0.05) is False and time.monotonic() - started < 1.0  # nothing came: back after the timeout
    threading.Timer(0.05, lambda: out.write("x")).start()
    started = time.monotonic()
    assert out.wait(0, 5.0) is True and time.monotonic() - started < 2.0 and out.read(0)[0] == "x"  # back when it came
    threading.Timer(0.05, out.finish).start()
    started = time.monotonic()
    assert out.wait(1, 5.0) is False and time.monotonic() - started < 2.0 and out.finished  # the end said at once
