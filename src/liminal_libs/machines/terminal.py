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

MAX_KEPT = 256 * 1024


class Output:
    """Text that grows (a terminal's, a job's), read from an offset: what a page has not seen yet."""

    def __init__(self, max_kept: int = MAX_KEPT):
        self.max_kept = max_kept
        self._text = ""
        self._base = 0  # the offset of the first character kept
        self._lock = threading.Lock()

    def write(self, text: str) -> None:
        if not text:
            return
        with self._lock:
            self._text += text
            over = len(self._text) - self.max_kept
            if over > 0:
                self._text = self._text[over:]
                self._base += over

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

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    def read(self, since: int = 0) -> dict:
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
