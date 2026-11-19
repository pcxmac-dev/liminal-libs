"""The fetch cache's files (1.64.0): what a pull writes to disk before anything of it reaches a database.

The user, 2026-11-15: "when the integrator goes to a source and pulls the data, make sure that the data is stored in a
temporary cache (not on ram), until it can be read in to the symbol database. leave the data in cache until an auditor
goes over the symbol and checks the data bit by bit to ensure it was copied successfully".

A pull (storage/pulls.py: one gap of one series asked of a feed, a market's day, a download by hand) has a folder of
its own under the data folder's cache/<feed>/. Two kinds of file go into it, in the order they are made:

  - a **payload**: an answer as the server sent it (its body, gzip, with the sha256 of the body as received), written
    piece by piece as it arrives (`PayloadWriter`) and parsed from the file read back, not from the pieces;
  - a **rows file**: what one write hands to the database, the exact values, one JSON document (`write_rows`). The
    write is then made from the file read back (`read_rows`), never from the rows in memory: what the database holds
    is what the file holds, and the copy audit (auditing.py) can say so value by value before the files are removed.

A number is written as Python writes it and reads it back: an int as its digits, a float as the shortest text that
gives the same float again, so nothing is rounded on the way (a value that is no number, text, true, false or null
cannot be written: `Unspoolable`, and its write is then made as before 1.64.0, and said).

Which pull is open is this module's to say (`current`, `opened`): the HTTP client (sources/http.py) and the stores'
write functions (storage/feeds.py) ask it. It is plain on purpose, the standard library only: the HTTP client is every
plugin's, the AI assistants' and the platform's too, and loads nothing of the storage to ask."""
from __future__ import annotations

import contextvars
import gzip
import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

VERSION = 1  # of a rows file
ROWS_SUFFIX = ".rows.json.gz"
PAYLOAD_SUFFIX = ".body.gz"
LEVEL = 1  # gzip's: these files live for seconds or hours, so fast before small
CHUNK = 1 << 16  # an answer's body is taken from the wire in pieces this long


class CacheFailed(OSError):
    """The cache could not be written (a full disk, a folder that cannot be made): nothing of the answer or of the
    rows was handed on. A run stops on it without a strike against the feed: the fault is this machine's."""


class Unspoolable(TypeError):
    """Rows that cannot be written to a rows file exactly: a value that is no number, text, true, false or null."""


@dataclass(frozen=True)
class Written:
    """A file of the cache as it was written: its name in its pull's folder, its size on disk, the sha256 of what it
    holds (before gzip: the body as received, the rows' text as written) and, for a rows file, its rows."""

    name: str
    bytes: int
    sha256: str
    rows: int = 0


# -- the pull that is open ---------------------------------------------------------------------------------------------
_open: contextvars.ContextVar = contextvars.ContextVar("liminal_libs_pull", default=None)


def current():
    """The pull open where this is asked (storage/pulls.py: Pull), or None: nothing is written to the cache."""
    return _open.get()


@contextmanager
def opened(pull) -> Iterator:
    """`pull` is the one open inside the block (a thread started inside it has none: a pull is one line of work's)."""
    token = _open.set(pull)
    try:
        yield pull
    finally:
        _open.reset(token)


# -- the files ---------------------------------------------------------------------------------------------------------
def _part(path: Path) -> Path:
    return path.with_name("." + path.name + ".part")  # a file not finished yet: never taken for a file of the cache


def _finish(handle, part: Path, path: Path) -> int:
    """A written file made durable and put under its name: flushed to the disk first, then renamed into place, so a
    file under its name is always whole."""
    handle.flush()
    os.fsync(handle.fileno())
    handle.close()
    os.replace(part, path)
    return path.stat().st_size


def _native(value):
    item = getattr(value, "item", None)  # a numpy number: its Python value, the same number
    if callable(item):
        out = item()
        if out is None or isinstance(out, (bool, int, float, str)):
            return out
    raise TypeError(f"a rows file holds numbers, text, true, false and null, not a {type(value).__name__}")


def rows_text(header: dict, rows: Iterable) -> bytes:
    """A rows file's text: one JSON document, the header's words and `rows`, each row a list of values."""
    rows = rows if isinstance(rows, list) else list(rows)
    try:
        return json.dumps({"v": VERSION, **header, "rows": rows}, separators=(",", ":"), default=_native).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as e:
        raise Unspoolable(str(e)) from e


def write_rows(folder: Path, name: str, header: dict, rows: Iterable) -> Written:
    """`rows` written as the rows file `name` in `folder`, whole or not at all. Unspoolable before anything is
    written; CacheFailed when the disk refuses."""
    rows = rows if isinstance(rows, list) else list(rows)
    text = rows_text(header, rows)
    path = Path(folder) / name
    part = _part(path)
    try:
        handle = open(part, "wb")
        try:
            with gzip.GzipFile(filename="", mode="wb", fileobj=handle, compresslevel=LEVEL, mtime=0) as packed:
                packed.write(text)
            size = _finish(handle, part, path)
        finally:
            handle.close()
    except OSError as e:
        _forget(part)
        raise CacheFailed(f"the fetch cache could not be written ({path}: {e})") from e
    return Written(name, size, hashlib.sha256(text).hexdigest(), len(rows))


def read_rows(path: Path) -> tuple[dict, list, str]:
    """A rows file read back: its header, its rows, and the sha256 of its text as read (the auditor holds it against
    the one kept when it was written). ValueError for a file that is not one; OSError when it cannot be read."""
    with gzip.open(path, "rb") as packed:
        text = packed.read()
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise ValueError(f"{Path(path).name} is not a rows file: {e}") from e
    if not isinstance(doc, dict) or doc.get("v") != VERSION or not isinstance(doc.get("rows"), list):
        raise ValueError(f"{Path(path).name} is not a rows file of version {VERSION}")
    rows = doc.pop("rows")
    return doc, rows, hashlib.sha256(text).hexdigest()


class PayloadWriter:
    """An answer's body on its way to disk, piece by piece: gzip, with the sha256 of the body as it was received.
    `close` puts it under its name; `abandon` leaves nothing (the answer was cut off on its way)."""

    def __init__(self, folder: Path, name: str):
        self.name = name
        self.path = Path(folder) / name
        self._part = _part(self.path)
        self._hash = hashlib.sha256()
        self.received = 0
        try:
            self._handle = open(self._part, "wb")
        except OSError as e:
            raise CacheFailed(f"the fetch cache could not be written ({self.path}: {e})") from e
        self._packed = gzip.GzipFile(filename="", mode="wb", fileobj=self._handle, compresslevel=LEVEL, mtime=0)

    def write(self, piece: bytes) -> None:
        if not piece:
            return
        try:
            self._packed.write(piece)
        except OSError as e:
            self.abandon()
            raise CacheFailed(f"the fetch cache could not be written ({self.path}: {e})") from e
        self._hash.update(piece)
        self.received += len(piece)

    def close(self) -> Written:
        try:
            self._packed.close()
            size = _finish(self._handle, self._part, self.path)
        except OSError as e:
            self.abandon()
            raise CacheFailed(f"the fetch cache could not be written ({self.path}: {e})") from e
        return Written(self.name, size, self._hash.hexdigest())

    def abandon(self) -> None:
        for closing in (self._packed, self._handle):
            try:
                closing.close()
            except (OSError, ValueError):
                pass
        _forget(self._part)


def read_payload(path: Path) -> bytes:
    """A payload's body as it was received, read back from its file."""
    with gzip.open(path, "rb") as packed:
        return packed.read()


def payload_sha256(path: Path) -> str:
    """The sha256 of a payload's body, read from its file a piece at a time (the auditor's check of the file)."""
    digest = hashlib.sha256()
    with gzip.open(path, "rb") as packed:
        for piece in iter(lambda: packed.read(CHUNK), b""):
            digest.update(piece)
    return digest.hexdigest()


def _forget(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
