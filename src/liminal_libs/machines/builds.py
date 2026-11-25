"""An image built here (1.97.0; SERVICE-INTERFACE.md §10, the user's "Build one here" of 2026-11-25): the build's
context folder and the pinned files fetched into it, by an approved work alone (ContainerHost._built), never at plan
time.

- **Where.** `<platform folder>/containers/build/<owner>-<part>/<the context's digest>/`, 0700 off Windows; the last
  two contexts of a part kept (`prune`), for the next build.
- **A file** (`fetched`): one found there already is checked again (its size and sha256) and used, or deleted and
  fetched anew; one fetched comes over https alone, never redirected to another host (`https_fetch`), `size` bytes at
  most, written beside its place and kept only once its sha256 is its pin's: a file that differs is deleted and the
  work fails in words. A Cancel ends a fetch between its chunks, its part deleted.
- Nothing in a context is ever run on this machine: its engine reads it as a build's context.

The standard library alone."""
from __future__ import annotations

import hashlib
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit

from ..instances import Refusal
from .plans import Cancelled

CHUNK = 1 << 20
FETCH_S = 600.0
CONTEXTS_KEPT = 2


def make_private(folder: Path) -> None:
    """The folder made (its parents too), 0700 off Windows."""
    folder.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        for d in (folder, folder.parent):
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


class _SameHost(urllib.request.HTTPRedirectHandler):
    """A redirect followed only to https on the same host: any other is refused."""

    def __init__(self, host: str):
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urlsplit(newurl)
        if u.scheme != "https" or (u.hostname or "") != self.host:
            raise Refusal(f"{self.host} redirected to {u.scheme}://{u.hostname}: a pinned file comes from its own "
                          "host alone")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def https_fetch(url: str, most: int, timeout: float = FETCH_S) -> Iterable[bytes]:
    """A pinned file's bytes, in chunks: https alone, no redirect to another host, `most` bytes at most (one more is
    read, so that a longer answer is seen)."""
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise Refusal(f"a pinned file comes over https alone, not {url[:80]}")
    opener = urllib.request.build_opener(_SameHost(u.hostname))
    req = urllib.request.Request(url, headers={"User-Agent": "liminal-build/1"})
    try:
        with opener.open(req, timeout=timeout) as r:
            left = most + 1
            while left > 0:
                chunk = r.read(min(CHUNK, left))
                if not chunk:
                    return
                left -= len(chunk)
                yield chunk
    except urllib.error.URLError as e:
        raise Refusal(f"{u.hostname} could not be reached for {Path(u.path).name}: {e.reason}") from None


def fetched(context: Path, f, fetch: Callable[[str, int], Iterable[bytes]], line, cancelled) -> Path:
    """The pinned file `f` (containers.PinnedFile) in the context folder, checked by its sha256: found and checked,
    or fetched and checked; a Refusal (the file deleted) when it differs."""
    path = context / f.name
    if path.exists():
        if path.is_file() and path.stat().st_size == f.size and sha256_of(path) == f.sha256:
            line(f"{f.name}: found in its build's folder, its sha256 checked again")
            return path
        _gone(path)
        line(f"{f.name}: the copy in its build's folder differs from its pin: deleted, fetched again")
    part = context / (f.name + ".part")
    _gone(part)
    h, n = hashlib.sha256(), 0
    line(f"{f.name}: fetched from {f.host} ({f.size:,} bytes pinned)")
    try:
        with open(part, "wb") as out:
            for chunk in fetch(f.url, f.size):
                if cancelled():
                    raise Cancelled(f"the fetch of {f.name} was cancelled")
                n += len(chunk)
                if n > f.size:
                    raise Refusal(f"{f.name} from {f.host} is longer than its pinned {f.size:,} bytes: deleted")
                h.update(chunk)
                out.write(chunk)
    except BaseException:
        _gone(part)
        raise
    got = h.hexdigest()
    if n != f.size or got != f.sha256:
        _gone(part)
        raise Refusal(f"{f.name} from {f.host} came as sha256 {got} ({n:,} bytes), not its pinned {f.sha256} "
                      f"({f.size:,} bytes): deleted, and nothing is built")
    os.replace(part, path)
    line(f"{f.name}: its sha256 checked ({got[:16]}…)")
    return path


def prune(root: Path, keep: str, kept: int = CONTEXTS_KEPT) -> None:
    """A part's contexts beyond the newest `kept` (the one in use among them) deleted."""
    try:
        others = sorted((d for d in root.iterdir() if d.is_dir() and d.name != keep), key=lambda d: d.stat().st_mtime)
    except OSError:
        return
    for d in others[:max(0, len(others) - (kept - 1))]:
        shutil.rmtree(d, ignore_errors=True)


def _gone(path: Path) -> None:
    try:
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink()
    except FileNotFoundError:
        pass


__all__ = ["CONTEXTS_KEPT", "fetched", "https_fetch", "make_private", "prune", "sha256_of"]
