"""An interactive terminal into a machine for the platform's page (the user, 2026-11-07: "the plugin also allows for a user
to login through a terminal in to the environment"): a process (a login shell in a WSL distribution of Liminal's own,
given a terminal inside Linux by `script`) whose output is kept for the page to read from an offset, and the keys the page
sends written to it. `Job` output (an install, a package update) uses the same reading. Windowless; the last MAX_KEPT
characters are kept."""
from __future__ import annotations

import codecs
import os
import subprocess
import threading
import time
from collections.abc import Mapping

MAX_KEPT = 256 * 1024
OWN = "LIMINAL_"  # the names of Liminal's own pairs: never in the environment a child inherits (`inherited`)


def _seconds(timeout: float | None) -> float | None:
    """A wait's seconds as threading takes them: None stays None (no end); a number is held between 0 and
    threading.TIMEOUT_MAX (a longer one would raise there, OverflowError), and one that is no number (NaN) is 0."""
    if timeout is None:
        return None
    seconds = float(timeout)
    if seconds != seconds:
        return 0.0
    return min(max(0.0, seconds), threading.TIMEOUT_MAX)


class Cancelled(Exception):
    """Work stopped because its user cancelled it (a job's Cancel): nothing went wrong, and what was asked for was
    not finished."""


def inherited(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """A child's whole environment (gpu's command, autostart's, download's zstd): `env` as it is given (an AI
    plugin's child_env(): every variable an installed plugin declares and every LIMINAL_* name taken out), else this
    process's own without any LIMINAL_* name, told apart without regard to case. That default is a net only: it takes
    out Liminal's own pairs and no other plugin's (a key named by its plugin's variable, NAMECHEAP_API_KEY), which
    cannot be known here, so a plugin hands its own (the AI base does)."""
    if env is not None:
        return {str(name): str(value) for name, value in env.items()}
    return {name: value for name, value in os.environ.items() if not name.upper().startswith(OWN)}


class Output:
    """Text that grows (a terminal's, a job's), read from an offset: what a page has not seen yet. A job's work may
    be cancelled through it (1.62.0): `cancel()` sets a flag the work looks at (`cancelled`) between its steps."""

    def __init__(self, max_kept: int = MAX_KEPT):
        self.max_kept = max_kept
        self._text = ""
        self._base = 0  # the offset of the first character kept
        self._lock = threading.Lock()
        self._grew = threading.Condition(self._lock)  # told of every write, of the end, and of a cancel
        self.finished = False
        self._cancelled = False

    def write(self, text: str) -> None:
        if not text:
            return
        with self._lock:
            self._text += text
            over = len(self._text) - self.max_kept
            if over > 0:
                self._text = self._text[over:]
                self._base += over
            self._grew.notify_all()

    def finish(self) -> None:
        """No more text will come (the process ended): whoever waits is told now."""
        with self._lock:
            self.finished = True
            self._grew.notify_all()

    def cancel(self) -> None:
        """The work writing here is asked to stop: the flag is set for it to see, and whoever waits is told now.
        Asking twice, or after the end, changes nothing."""
        with self._lock:
            self._cancelled = True
            self._grew.notify_all()

    @property
    def cancelled(self) -> bool:
        """Whether a cancel was asked: the work looks at it between its steps and stops by itself (Cancelled)."""
        with self._lock:
            return self._cancelled

    def wait_cancelled(self, timeout: float | None) -> bool:
        """Until a cancel is asked or `timeout` seconds pass (None: until a cancel, however long that is): whether
        one was. A wait the work may take between two tries, ended at once by a cancel; a wait longer than threading
        can take (threading.TIMEOUT_MAX: 49 days on Windows) is held to that."""
        with self._grew:
            self._grew.wait_for(lambda: self._cancelled, timeout=_seconds(timeout))
            return self._cancelled

    def wait(self, since: int, timeout: float | None) -> bool:
        """Until there is text after `since`, the end, or `timeout` seconds (held as wait_cancelled holds them):
        whether there is text (a page's read held until there is something to show: its echo at once, one read at a
        time)."""
        with self._grew:
            self._grew.wait_for(lambda: self._base + len(self._text) > since or self.finished,
                                timeout=_seconds(timeout))
            return self._base + len(self._text) > since

    def __call__(self, line: str) -> None:  # a log line (a setup's step)
        self.write(f"{line}\n")

    @property
    def end(self) -> int:
        with self._lock:
            return self._base + len(self._text)

    def read(self, since: int = 0) -> tuple[str, int, int]:
        """(the text after `since`, where it starts, where it ends); from the oldest kept when `since` is older."""
        with self._lock:
            start = max(int(since), self._base)
            return self._text[start - self._base:], start, self._base + len(self._text)

    @property
    def text(self) -> str:
        with self._lock:
            return self._text


class Terminal:
    """A process with its standard input and output (and errors) for a page: `read(since)`, `write(keys)`, `close()`."""

    def __init__(self, argv: list[str], popen=None, title: str = ""):
        self.argv = list(argv)
        self.title = title
        self.started = time.time()
        self.seen = time.monotonic()  # the last time the page read it: an unread terminal is closed (Platform)
        self.output = Output()
        env = dict(os.environ, WSL_UTF8="1")  # wsl's own words in UTF-8 rather than UTF-16
        self.proc = (popen or subprocess.Popen)(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                bufsize=0, env=env, **_no_window())
        self._reader = threading.Thread(target=self._read, daemon=True, name="terminal")
        self._reader.start()

    def _read(self) -> None:
        decode = codecs.getincrementaldecoder("utf-8")("replace")
        while True:
            try:
                chunk = self.proc.stdout.read(4096)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            self.output.write(decode.decode(chunk))
        self.output.write(decode.decode(b"", final=True))
        self.output.finish()

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    def read(self, since: int = 0, wait: float = 0.0) -> dict:
        """What it printed after `since`; with `wait`, held until there is some (or the end, or so many seconds)."""
        self.seen = time.monotonic()
        if wait > 0 and self.alive:
            self.output.wait(since, wait)
            self.seen = time.monotonic()
        text, start, end = self.output.read(since)
        return {"text": text, "from": start, "offset": end, "alive": self.alive, "title": self.title}

    def write(self, data: str) -> None:
        """Keys typed on the page, as the terminal sends them (Enter as \\r, the arrows as escape sequences)."""
        if not self.alive:
            raise OSError("the terminal has ended")
        self.proc.stdin.write(data.encode("utf-8"))
        self.proc.stdin.flush()

    def close(self) -> None:
        if self.alive:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:  # noqa: BLE001 - it goes, one way or the other
                self.proc.kill()


def _no_window() -> dict:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}
