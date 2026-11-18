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


def test_a_jobs_output_can_be_asked_to_cancel_and_a_waiter_is_told():
    import threading

    from liminal_libs.machines.terminal import Cancelled, Output

    out = Output()
    assert out.cancelled is False and out.wait_cancelled(0) is False
    answers: list = []
    waiter = threading.Thread(target=lambda: answers.append(out.wait_cancelled(30)), daemon=True)
    waiter.start()
    out.cancel()
    waiter.join(10)
    assert answers == [True] and out.cancelled is True  # told at once, not after its 30 s
    out.cancel()  # twice changes nothing
    out.finish()
    out.cancel()  # and after the end
    assert out.cancelled is True and out.finished is True and out.text == ""
    assert out.wait(0, 0) is False  # a page's read still waits for text: a cancel alone gives it nothing to show
    assert issubclass(Cancelled, Exception) and not issubclass(Cancelled, ValueError)  # no refusal: a stop


def test_a_cancel_leaves_what_was_written_readable():
    from liminal_libs.machines.terminal import Output

    out = Output()
    out("downloading")
    out.cancel()
    out("cancelled: nothing was installed")
    assert out.read(0)[0] == "downloading\ncancelled: nothing was installed\n" and out.wait(0, 0) is True


def test_a_wait_may_have_no_end_or_one_longer_than_threading_takes():
    """wait_cancelled(None) waits until a cancel; a wait of inf, or longer than threading.TIMEOUT_MAX, is held to
    that bound instead of raising in the job (OverflowError); and wait() holds its seconds the same way. Each waiter
    is in its wait before it is told: the cancel (or the text) takes the lock the wait lets go of."""
    from liminal_libs.machines.terminal import Output

    for timeout in (None, float("inf"), 1e12, threading.TIMEOUT_MAX * 2):
        for tell, ask in ((Output.cancel, lambda out: out.wait_cancelled(timeout)),
                          (lambda out: out.write("x"), lambda out: out.wait(0, timeout))):
            out = Output()
            entered, real = threading.Event(), out._grew.wait

            def waiting(seconds=None, real=real, entered=entered):  # in its wait, the lock about to be let go
                entered.set()
                return real(seconds)
            out._grew.wait = waiting
            answers: list = []

            def wait(out=out, ask=ask, answers=answers, entered=entered):
                try:
                    answers.append(ask(out))
                except BaseException as e:  # noqa: BLE001 - what the waiter met is the answer
                    answers.append(e)
                    entered.set()
            waiter = threading.Thread(target=wait, daemon=True)
            waiter.start()
            assert entered.wait(10), timeout
            tell(out)
            waiter.join(10)
            assert answers == [True], (timeout, answers)
    out = Output()
    assert [out.wait_cancelled(t) for t in (float("nan"), -5, 0)] == [False] * 3  # no wait at all
    out.cancel()
    assert out.wait_cancelled(None) is True  # asked already: no wait
    out.write("x")
    assert out.wait(0, None) is True and out.wait(0, float("inf")) is True


def test_a_child_inherits_the_environment_given_else_this_ones_without_liminals_own(monkeypatch):
    from liminal_libs.machines import terminal

    monkeypatch.setenv("LIMINAL_AI_OLLAMA_DEFAULT_KEY", "s3cret")
    monkeypatch.setenv("Liminal_Platform_Dir", "/somewhere")  # any case: told apart without regard to it
    monkeypatch.setenv("SOMETHING_OF_THE_USERS", "kept")
    own = terminal.inherited()
    assert not any(name.upper().startswith("LIMINAL_") for name in own) and own["SOMETHING_OF_THE_USERS"] == "kept"
    given = {"PATH": "/usr/bin", "LIMINAL_GIVEN": "1"}  # one given is the whole of it, as it is: its maker's to make
    assert terminal.inherited(given) == given and terminal.inherited(given) is not given

