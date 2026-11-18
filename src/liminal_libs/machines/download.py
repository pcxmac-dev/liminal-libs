"""A file fetched as a job (1.62.0): what an AI plugin's Install brings to this machine (the user, 2026-11-16: "all
three plugins need to allow installation and configuration of their respective code"). The plugin pins each file it
installs from: its address, the name it is kept under, its size, its sha256 and the hosts it may come from. This
module downloads it when the user asks, checks it, unpacks it, and removes it again, each inside the plugin's own
folder.

    source = Source(address, "ollama-linux-amd64.tar.zst", size, sha256, hosts)    # the plugin's pin
    archive = fetch(source, home / "downloads", log=log, cancel=cancelled)         # whole and checked, or not there
    unpack(archive, home / "app" / pin, log=log, cancel=cancelled)                 # nothing lands outside that folder
    remove_tree(home / "app" / old, home)                                          # only what lies inside `home`

- A download happens only when a caller asks for one (the plugin's Install, a job the user started on the page, its
  size and licence said first there). Nothing here looks for a newer file or asks anything by itself.
- https on every hop. A redirect is followed MAX_REDIRECTS times at most, each over https and only to the address's
  own host or one of the pin's `hosts` (a release file's storage); any other is refused before anything is asked of
  it, and no redirect's body is read. No host is named here: every address is its plugin's.
- Checked. The size and the sha256 the plugin pins are both checked before the file gets its name: until then it is
  `<name>.part`. A wrong one is a ChecksumError, the part removed, nothing used.
- Resumed, where a sha256 is pinned (a size alone cannot tell the rest of the same file from the rest of another of
  that size). A part left by a download that was cancelled or broke off is gone on from with a Range request, when
  the server answers 206 for the same whole size; else it starts again. A part gone on from that turns out not to
  be this file's (the pin moved on since) is downloaded again from the start, once. Without a sum, no part is kept.
- Bounded: `limit` bytes and `timeout` seconds a download, `limit` bytes and MOST_FILES entries an unpacking,
  HEADER_MOST bytes a tar member's extended header and HEADERS_MOST all of an archive's together (tarfile keeps what
  each says), NAME_MOST characters a member's name (NAME_MOST_WINDOWS on Windows) and LINK_MOST a link's target; a
  sparse file (GNU tar's) is not unpacked. `cancel()` and the deadline are looked at after every receive (a read
  that gets nothing ends at the socket's own wait, READ_S at most): Cancelled, the part kept for the next try where
  a sum is pinned.
- This system's own disk. A folder on another system's drive (mounts.owner_only: WSL's view of a Windows drive, a
  share) is that system's: mounts.NotHere before anything is asked, read or written.
- Unpacking writes inside its folder only: a member or a link that leads out of it, a device or a pipe is refused,
  and nothing more is unpacked. Where a link leads is judged as this system follows one (on Windows its `..` folded
  against the link's own folder first, as Windows folds it), and a link is written with this system's separator;
  every link made is looked at again when the unpacking ends (a later member may have changed the way it goes), and
  one that leads out then is removed and the archive refused. The system's zstd, where one is needed, is started
  without a window, with the environment its caller gives (an AI plugin's, every pair of every plugin taken out:
  AiPlugin.unpack), else this process's own without LIMINAL_* (terminal.inherited: a net only). Removing follows no
  link.

`opener(url, headers, timeout) -> Reply` is a test's stand-in; else the `requests` package as machines/endpoint.py
uses it (nothing taken from the environment, no redirect followed by it).
"""
from __future__ import annotations

import hashlib
import ntpath
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .. import mounts
from ..instances import has_control
from ..proc import no_window
from .endpoint import Progress, Reply, _lower, requests_transport, trouble
from .terminal import Cancelled, inherited
from .world import _close, _sayer, _where, size_words

MAX_REDIRECTS = 5  # redirects one download follows: each over https, to the address's own host or one the pin lists
REDIRECTS = (301, 302, 303, 307, 308)
CHUNK = 1 << 20  # bytes read, written and summed at a time at most (a read hands on what one receive gave)
READ_S = 60.0  # seconds each socket operation of a download waits at most (less once less is left of its time)
PART = ".part"  # what a download is written to until it is whole and checked: <name>.part
USER_AGENT = "liminal-libs (download)"  # a fixed name: nothing of the user's, nothing of the machine's
MOST_FILES = 200_000  # entries one archive may hold
LINK_MOST = 4096  # characters of a link's target (in a .zip, its bytes): POSIX's longest path
NAME_MOST = 4096  # characters of a member's name: POSIX's longest path (PATH_MAX), looked at before it is split
NAME_MOST_WINDOWS = 32_767  # ... and Windows' longest
HEADER_MOST = 1 << 20  # bytes of a tar member's extended header (PAX records, a GNU long name): tarfile reads one whole
HEADERS_MOST = 16 << 20  # bytes of all of an archive's extended headers together: tarfile keeps what each says
TRAIL_MOST = 1 << 20  # bytes that may follow a .tar.zst's last entry (its padding): read off, so zstd ends by itself
ZSTD_END_S = 30.0  # seconds zstd is given to end once all it wrote was read
KINDS = ((".zip", "zip"), (".tar.gz", "gz"), (".tgz", "gz"), (".tar.xz", "xz"), (".tar.zst", "zst"))
# the command that installs zstd, by what a distribution's os-release says it is (ID) or is like (ID_LIKE): words for
# the user to run, never run from here
ZSTD_PACKAGES = (
    (("debian", "ubuntu"), "sudo apt install zstd"),
    (("fedora", "rhel", "centos"), "sudo dnf install zstd"),
    (("gentoo",), "sudo emerge app-arch/zstd"),
    (("alpine",), "sudo apk add zstd"),
    (("arch",), "sudo pacman -S zstd"),
    (("suse", "opensuse"), "sudo zypper install zstd"),
)
# the headers tarfile reads whole into memory before the member they describe
_LONG = (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK)
_SUM = re.compile(r"^[0-9a-f]{64}$")
_RANGE = re.compile(r"^bytes\s+(?:(\d+)-(\d+)|\*)/(\d+|\*)$")
_STEPS = re.compile(r"[/\\]")  # what parts a member's name into its folders: a backslash too, as Windows reads it
# names Windows keeps for its devices, by the part of a name before its first dot (a superscript 1, 2 or 3 after COM
# or LPT is that digit to Windows; COM0 and LPT0 are named by its own pages): never a file's name there
_RESERVED = frozenset({"con", "prn", "aux", "nul", "conin$", "conout$",
                       *(f"{device}{n}" for device in ("com", "lpt") for n in "0123456789" "\N{SUPERSCRIPT ONE}"
                         "\N{SUPERSCRIPT TWO}" "\N{SUPERSCRIPT THREE}")})
_UNKEPT = frozenset(':"*<>?|')  # what no name of Windows' holds (a colon names a drive or a file's stream)
_ISRESERVED = getattr(ntpath, "isreserved", None)  # Python's own word on it, where it has one (3.13 on)
_COUNTED = "_liminal_header_bytes"  # kept on a TarFile as it is read: the bytes of its extended headers so far
SPARSE = "a sparse file (GNU tar's), which no install here unpacks"


class DownloadError(Exception):
    """A download or an unpacking that failed, or a pin that is none, in words: nothing was installed."""


class ChecksumError(DownloadError):
    """What came is not the file its plugin pins (another size, another sha256): removed, never used."""


@dataclass(frozen=True)
class Source:
    """One file as its plugin pins it: `url` (https), the `name` it is kept under, its `size` in bytes and its
    `sha256` (0 and "": not pinned, so not checked), and `hosts`: the other hosts it may be sent on to (where a
    release's files are stored). They are the plugin's constants: the library names no host."""

    url: str
    name: str
    size: int = 0
    sha256: str = ""
    hosts: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Pin:
    """A Source looked over: an https address and its host, a plain name, the size, the sum in lower case, and the
    hosts it may come from (its own first)."""

    url: str
    host: str
    name: str
    size: int
    sha256: str
    hosts: tuple[str, ...]


# -- the pin and its words ---------------------------------------------------------------------------------------------
def _named(host) -> str:
    return str(host or "").strip().strip("[]").rstrip(".").lower()


def _pin(source: Source) -> _Pin:
    """A Source as fetch and size_of use it; DownloadError in words for one that is no pin (a name with a folder in
    it, an address that is not https, a sum that is no sha256)."""
    name = str(source.name or "")
    if (not name or name in (".", "..") or name != name.strip() or len(name) > 200
            or any(c in '/\\:*?"<>|' or ord(c) < 32 for c in name)):
        raise DownloadError(f"{name[:80]!r} is no plain file name: a download is kept under its own name, in the "
                            "folder it is given")
    try:
        parts = urlsplit(str(source.url or ""))
        host = _named(parts.hostname)
    except ValueError:
        parts, host = None, ""
    if parts is None or parts.scheme.lower() != "https" or not host or "@" in parts.netloc:
        raise DownloadError(f"{name} is downloaded over https only, not from {_where(source.url)}")
    size = source.size if isinstance(source.size, int) and not isinstance(source.size, bool) else -1
    if size < 0:
        raise DownloadError(f"{name}'s pinned size is no number of bytes: {source.size!r}")
    digest = str(source.sha256 or "").strip().lower()
    if digest and not _SUM.match(digest):
        raise DownloadError(f"{name}'s pinned sha256 is none (64 hexadecimal digits): {digest[:80]!r}")
    more = (source.hosts,) if isinstance(source.hosts, str) else tuple(source.hosts or ())
    hosts = tuple(dict.fromkeys(h for h in (host, *(_named(h) for h in more)) if h))
    return _Pin(str(source.url), host, name, size, digest, hosts)


def _span(seconds: float) -> str:
    return f"{seconds / 60:,.0f} minutes" if seconds >= 120 else f"{seconds:g} s"


def _of(done: int, whole: int | None) -> str:
    return f"{size_words(done)} of {size_words(whole)}" if whole else size_words(done)


def _length(headers: dict[str, str]) -> int | None:
    """The bytes an answer says it holds (Content-Length); None when it says none."""
    value = headers.get("content-length", "").strip()
    return int(value) if value.isdigit() else None


def _range(headers: dict[str, str]) -> tuple[int | None, int | None]:
    """An answer's Content-Range as (the first byte it holds, the whole's size): `bytes 100-199/200` is (100, 200),
    `bytes */200` (a range that cannot be given) is (None, 200); None for what it does not say."""
    found = _RANGE.match(headers.get("content-range", "").strip())
    if not found:
        return None, None
    return (int(found.group(1)) if found.group(1) else None), (int(found.group(3)) if found.group(3) != "*" else None)


def _size(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:
        return 0


def _drop(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass  # not there, or held open elsewhere: the next download writes it anew


# -- asking for it -----------------------------------------------------------------------------------------------------
def _requests_opener(url: str, headers, timeout: float) -> Reply:
    """The `requests` transport, its pieces handed on as they come (CHUNK bytes at most): a download's cancel and its
    deadline are looked at after every receive, not only once a whole CHUNK has come."""
    return requests_transport("GET", url, headers, None, timeout, True, CHUNK)


def _onward(url: str, where: str, pin: _Pin) -> str:
    """The address a redirect sends on to (a relative one read against `url`): https and one of the pin's hosts, or
    DownloadError before anything is asked of it."""
    new = urljoin(url, where)
    try:
        parts = urlsplit(new)
        host = _named(parts.hostname)
    except ValueError:
        parts, host = None, ""
    if parts is None or parts.scheme.lower() != "https" or host not in pin.hosts:
        raise DownloadError(f"{pin.name} was sent on to {_where(new)}, and it comes over https from "
                            f"{' or '.join(pin.hosts)} alone: nothing was asked of it")
    if "@" in parts.netloc:
        raise DownloadError(f"{pin.name} was sent on to an address with a user name in it: nothing was asked of it")
    return new


def _open(pin: _Pin, headers: dict[str, str], opener, deadline: float, clock, span: str,
          each: float = READ_S) -> tuple[Reply, str, float]:
    """The answer for the pin's file, redirects followed as the module docstring says: a Reply whose body is not
    read yet (the caller closes it), the host it came from (the last a redirect sent on to) and the seconds each
    socket operation of it waits. DownloadError in words when it cannot be had."""
    url = pin.url
    for _ in range(MAX_REDIRECTS + 1):
        left = deadline - clock()
        if left <= 0:
            raise DownloadError(f"{pin.name} was not whole after {span}: stopped")
        host = _named(urlsplit(url).hostname)
        wait = min(each, left)
        try:
            reply = (opener or _requests_opener)(url, dict(headers), wait)
        except Exception as e:  # noqa: BLE001 - the connection's trouble, in words
            raise DownloadError(f"{pin.name} could not be downloaded: {trouble(e, host, round(wait, 1))}") from None
        if int(reply.status) not in REDIRECTS:
            return reply, host, wait
        where = _lower(reply.headers).get("location", "").strip()
        _close(reply)  # a redirect's body is never read
        if not where:
            raise DownloadError(f"{pin.name} could not be downloaded: {host} sent it on (HTTP {int(reply.status)}) "
                                "without saying where")
        url = _onward(url, where, pin)
    raise DownloadError(f"{pin.name} was sent on more than {MAX_REDIRECTS} times: not followed further")


def _plain(headers: dict[str, str], pin: _Pin, host: str) -> None:
    coding = headers.get("content-encoding", "").strip().lower()
    if coding and coding != "identity":
        raise DownloadError(f"{pin.name} comes {coding[:20]}-encoded from {host}, which was not asked for: not "
                            "downloaded")


def size_of(source: Source, *, opener: Callable | None = None, timeout: float = 20.0) -> int:
    """What the server says the pin's file holds, in bytes (0: it does not say): asked for with a GET whose body is
    not read, redirects followed as a download's. For a size said before a download where none is pinned."""
    pin = _pin(source)
    wait = max(0.1, float(timeout))
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity"}
    reply, host, _ = _open(pin, headers, opener, time.monotonic() + wait, time.monotonic, _span(wait), wait)
    try:
        if int(reply.status) != 200:
            raise DownloadError(f"{pin.name}'s size could not be asked of {host}: HTTP {int(reply.status)}")
        said = _lower(reply.headers)
        _plain(said, pin, host)
        return _length(said) or 0
    finally:
        _close(reply)


# -- fetching it -------------------------------------------------------------------------------------------------------
def sha256(path, cancel: Callable[[], bool] | None = None) -> str:
    """A file's sha256, in lower-case hexadecimal, read CHUNK bytes at a time; `cancel()` is looked at in between
    (Cancelled)."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            if cancel is not None and cancel():
                raise Cancelled("cancelled")
            piece = f.read(CHUNK)
            if not piece:
                return digest.hexdigest()
            digest.update(piece)


def _as_pinned(path: Path, pin: _Pin, cancel) -> bool:
    """Whether a whole file is the one pinned: by its size, and by its sha256 where one is pinned."""
    if pin.size and _size(path) != pin.size:
        return False
    return not pin.sha256 or sha256(path, cancel) == pin.sha256


def _check(part: Path, pin: _Pin, cancel, say) -> None:
    """A part that is all there, checked against what is pinned: ChecksumError for another size or another sum
    (the caller removes it)."""
    size = _size(part)
    if pin.size and size != pin.size:
        raise ChecksumError(f"{pin.name} is {size:,} bytes, not the {pin.size:,} pinned for it: removed, nothing was "
                            "installed")
    if pin.sha256:
        say(f"{pin.name}: {size_words(size)} here, checked against the sha256 pinned for it")
        got = sha256(part, cancel)
        if got != pin.sha256:
            raise ChecksumError(f"{pin.name} is not the file pinned: its sha256 is {got}, not {pin.sha256}: removed, "
                                "nothing was installed")
        say(f"{pin.name} is the file pinned: its sha256 is {got}")
    elif pin.size:
        say(f"{pin.name} is {size:,} bytes, as pinned; no sha256 is pinned for it")
    else:
        say(f"{pin.name}: {size_words(size)}, not checked against a pinned sum: none is pinned for it")


def _take(pin: _Pin, part: Path, have: int, *, opener, cancel, limit: int, deadline: float, clock, span: str,
          resume: bool, log, say) -> bool:
    """The pin's file downloaded into `part`, going on from the `have` bytes it holds when the server gives the
    rest of the same whole (206), else from the start. It ends with the part all there, or raises. True when what
    is there went on from the bytes the part held (they were its first, by the server's word, and only its check
    can say whether they are this file's); False when all of it came now."""
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity"}
    kept = ("what came is kept, and the next download goes on from there" if resume
            else "what came of it was removed")
    host = pin.host
    for _ in range(2):  # the second: from the start, after a range the server would not go on from
        reply, host, wait = _open(pin, {**headers, "Range": f"bytes={have}-"} if have else headers, opener, deadline,
                                  clock, span)
        try:
            status, said = int(reply.status), _lower(reply.headers)
            first, whole = _range(said)
            if have and status == 206 and first == have and whole is not None and (not pin.size or whole == pin.size):
                mode = "ab"
            elif have and status == 416 and whole == have:
                return True  # the part is as long as the file: all of it is here, and only its check is left
            elif have and status in (206, 416):  # not the range asked for, or of another whole: from the start
                _drop(part)
                have = 0
                continue
            elif status == 200:
                have, whole, mode = 0, _length(said), "wb"
            else:
                raise DownloadError(f"{pin.name} could not be downloaded from {host}: HTTP {status}"
                                    + (" (it is not there)" if status == 404 else ""))
            _plain(said, pin, host)
            if whole is not None and pin.size and whole != pin.size:
                _drop(part)
                raise ChecksumError(f"{pin.name} is {whole:,} bytes at its maker's, not the {pin.size:,} pinned for "
                                    "it: not downloaded")
            if whole is not None and whole > limit:
                _drop(part)
                raise DownloadError(f"{pin.name} is {size_words(whole)}, more than the {size_words(limit)} a "
                                    "download may be: not downloaded")
            expect = whole if whole is not None else (pin.size or None)
            most = pin.size or limit
            say(f"going on with {pin.name} from {_of(have, expect)}" if have else
                f"downloading {pin.name} from {host}" + (f" ({size_words(expect)})" if expect else
                                                         ": its size is not known until it is downloaded"))
            done, over = have, False
            progress = Progress(log, clock=clock)

            def stopped() -> None:  # a cancel, or the deadline: looked at after every receive
                if cancel is not None and cancel():
                    raise Cancelled(f"cancelled at {_of(done, expect)} of {pin.name}: {kept}")
                if clock() >= deadline:
                    raise DownloadError(f"{pin.name} was not whole after {span}: stopped at {_of(done, expect)}; "
                                        f"{kept}")
            with open(part, mode) as out:
                chunks = iter(reply.chunks)
                while True:
                    stopped()
                    try:
                        piece, broke = next(chunks, None), ""
                    except Exception as e:  # noqa: BLE001 - the connection's trouble, in words
                        piece, broke = None, trouble(e, host, round(wait, 1))
                    if broke:
                        stopped()  # cancelled, or out of time, while the read waited: that is how it ended
                        raise DownloadError(f"the download of {pin.name} broke off at {_of(done, expect)} ({broke}); "
                                            f"{kept}")
                    if piece is None:
                        break
                    done += len(piece)
                    if done > most:
                        over = True
                        break
                    out.write(piece)
                    progress.say(done, expect, pin.name)
                out.flush()
                os.fsync(out.fileno())
            if over:
                _drop(part)
                if pin.size:
                    raise ChecksumError(f"more came of {pin.name} than the {pin.size:,} bytes pinned for it: "
                                        "removed, nothing was installed")
                raise DownloadError(f"{pin.name} is more than the {size_words(limit)} a download may be: stopped, "
                                    "and what came was removed")
            if expect is not None and done < expect:
                raise DownloadError(f"the download of {pin.name} broke off at {_of(done, expect)}; {kept}")
            if not done:
                raise DownloadError(f"nothing came of {pin.name} from {host}")
            say(f"{pin.name}: {size_words(done)} downloaded")
            return mode == "ab"
        finally:
            _close(reply)
    raise DownloadError(f"{pin.name} could not be downloaded from {host}: it gives a part of it, never the whole")


def fetch(source: Source, folder, *, log=None, cancel: Callable[[], bool] | None = None, resume: bool = True,
          limit: int = 8 << 30, timeout: float = 7200.0, opener: Callable | None = None,
          clock: Callable[[], float] = time.monotonic) -> Path:
    """The pin's file downloaded into `folder`, whole and checked: its path there (`folder/name`).

    It is written to `<name>.part` and gets its name only once its size and its sha256 are the pinned ones (a wrong
    one: ChecksumError, the part removed). With `resume`, a whole file already there that is the pinned one (by its
    size and its sum, where pinned) is used as it is, nothing asked; and where a sha256 is pinned, a part left by an
    earlier try is gone on from (without one, nothing could tell the rest of the same file from the rest of another
    of that size: no part is gone on from, so none is kept). `log(line)`: the job's panel (its steps, and how far it
    is every two seconds at most). `cancel()`: looked at after every receive; once true, Cancelled, the part kept
    where it can be gone on from, else removed. Past `limit` bytes or `timeout` seconds (a number above 0, else
    ValueError) it stops, and says so (DownloadError: every failure's words; a part kept as with a cancel).
    mounts.NotHere for a folder on another system's drive, before anything is asked or made."""
    pin = _pin(source)
    seconds = float(timeout)
    if not seconds > 0:
        raise ValueError(f"a download waits a number of seconds above 0, not {timeout!r}")
    folder = Path(folder)
    mounts.owner_only(folder, f"Downloading {pin.name}")
    if pin.size > limit:
        raise DownloadError(f"{pin.name} is pinned at {size_words(pin.size)}, more than the {size_words(limit)} a "
                            "download may be: not downloaded")
    say = _sayer(log)
    target, part = folder / pin.name, folder / (pin.name + PART)
    deadline, span = clock() + seconds, _span(seconds)
    keep = resume and bool(pin.sha256)  # a part is gone on from, and so kept, only where a sum can tell its whole
    try:
        folder.mkdir(parents=True, exist_ok=True)
        if resume and (pin.size or pin.sha256) and target.is_file():
            if _as_pinned(target, pin, cancel):
                _drop(part)
                say(f"{pin.name} is here already ({size_words(_size(target))}) and is the file pinned: not "
                    "downloaded again")
                return target
            say(f"the {pin.name} here is not the file pinned: it is downloaded again")
        if not keep:
            _drop(part)  # no part is gone on from: none is kept, or no sum would say the whole is this file
        for again in (False, True):
            have = _size(part)
            if pin.size and have > pin.size:
                _drop(part)
                have = 0
            if pin.size and have == pin.size:
                older = True  # all of it came in an earlier try: only its check is left
            else:
                older = _take(pin, part, have, opener=opener, cancel=cancel, limit=int(limit), deadline=deadline,
                              clock=clock, span=span, resume=keep, log=log, say=say)
            try:
                _check(part, pin, cancel, say)
                break
            except ChecksumError:
                _drop(part)
                if not older or again:  # all of it came now: another try would bring the same file
                    raise
                say(f"what was here of {pin.name} was not this file's: it is downloaded again from the start")
        os.replace(part, target)
        return target
    except (DownloadError, Cancelled):
        if not keep:
            _drop(part)
        raise
    except OSError as e:
        if not keep:
            _drop(part)
        raise DownloadError(f"{pin.name} could not be kept in {folder}: {e}") from None


# -- unpacking it ------------------------------------------------------------------------------------------------------
def _within(root: str, path: str) -> bool:
    """Whether `path` is `root` or lies under it, both as they are written (the callers hand real paths)."""
    a, b = os.path.normcase(root), os.path.normcase(path)
    return b == a or b.startswith(a.rstrip(os.sep) + os.sep)


def _junction(path) -> bool:
    """Whether a path is a Windows junction (a folder that shows another): a link, though no symbolic one."""
    judge = getattr(os.path, "isjunction", None)
    try:
        return bool(judge(path)) if judge else False
    except OSError:
        return False


def _reads_zst() -> bool:
    """Whether this Python reads a .tar.zst by itself (3.14 on)."""
    try:
        import compression.zstd  # noqa: F401
    except ImportError:
        return False
    return True


def _device(step: str) -> bool:
    """Whether Windows takes a name for one of its devices (CON, nul.txt, `NUL .txt`, CONOUT$, COM and a superscript
    1): its part before the first dot, without the spaces at its end, is a device's; or Python says it is reserved."""
    if step.split(".")[0].rstrip(" ").lower() in _RESERVED:
        return True
    return _ISRESERVED is not None and bool(_ISRESERVED(step))


def link_target(aim: str, windows: bool | None = None) -> str:
    """A link's target as this system writes it (`windows`: None, this system's way): on Windows with Windows' own
    separator, which is how Windows follows a link's target (one written with `/` leads nowhere there); elsewhere as
    the archive names it."""
    windows = os.name == "nt" if windows is None else windows
    return str(aim).replace("/", "\\") if windows else str(aim)


def member_steps(member: str, archive: str = "the archive", windows: bool | None = None) -> list[str]:
    """A member's name as the folders and the file it names, in order, `.` and empty steps left out. DownloadError
    for a name that leads out of the folder it is unpacked into (a whole path, a drive, a `..` step), that is longer
    than any path the system keeps (NAME_MOST characters, NAME_MOST_WINDOWS on Windows: said before it is split), or
    that the system cannot hold (a control character; on Windows a colon or another character no name of Windows'
    holds, a device's name, a dot or a space at its end, which Windows drops and so turns into another name)."""
    text = str(member or "")
    shown = repr(text[:120])
    windows = os.name == "nt" if windows is None else windows
    most = NAME_MOST_WINDOWS if windows else NAME_MOST
    if len(text) > most:
        raise DownloadError(f"{archive} holds a name of {len(text):,} characters ({shown}...), longer than any path "
                            f"this system keeps ({most:,}): not unpacked further")
    if not text or "\x00" in text:
        raise DownloadError(f"{archive} holds a member without a name: not unpacked further")
    if text.startswith(("/", "\\")):
        raise DownloadError(f"{archive} holds a whole path ({shown}), which leads out of the folder it is unpacked "
                            "into: not unpacked further")
    steps = [s for s in _STEPS.split(text) if s not in ("", ".")]
    for step in steps:
        if step == "..":
            raise DownloadError(f"{archive} holds {shown}, which leads out of the folder it is unpacked into: not "
                                "unpacked further")
        if has_control(step):
            raise DownloadError(f"{archive} holds a name with a control character ({shown}): not unpacked further")
        if windows and (_UNKEPT.intersection(step) or step != step.rstrip(". ") or _device(step)):
            raise DownloadError(f"{archive} holds {shown}, a name Windows does not keep as it is (a drive or a "
                                "stream's colon or another character no name there holds, a device's name, a dot or a "
                                "space at its end): not unpacked further")
    return steps


class _Unpacking:
    """One unpacking under way: the folder it writes in as it really is (`root`), its bounds, and what it wrote."""

    def __init__(self, name: str, into: Path, limit: int, strip: int, cancel, progress: Progress):
        self.name, self.into, self.root = name, into, os.path.realpath(into)
        self.limit, self.strip, self.cancel, self.progress = int(limit), int(strip), cancel, progress
        self.files = self.bytes = self.written = self.entries = 0
        self.total: int | None = None  # the bytes it will write, where the archive says them first (a .zip)
        self._inside: set[str] = set()  # folders known to lie inside `root`, until a link is made
        self.links: dict[str, str] = {}  # every link it made: where it is, and its member as the archive names it

    def leading_out(self) -> list[str]:
        """Every link it made that leads out of `root` now: a later member may have changed the way one goes (a link
        it went through pointed elsewhere, or made where there was nothing). Each such link is removed, as the link
        it is (what it shows is never touched); their members, in the order they were made."""
        out = []
        for dest, named in self.links.items():
            try:
                if not os.path.islink(dest):
                    continue  # a later member put a file or a folder in its place
                if _within(self.root, os.path.realpath(dest)):
                    continue
            except (OSError, ValueError, RuntimeError):  # (RuntimeError: a chain of links too long to follow, 3.12)
                pass  # where it leads cannot be read: it goes, as one that leads out
            try:
                os.unlink(dest)
            except OSError:
                pass  # (the caller removes the folder this unpacking made, as a refusal's words ask)
            out.append(named)
        return out

    def asked(self) -> None:
        if self.cancel is not None and self.cancel():
            raise Cancelled(f"cancelled: {self.name} was not unpacked whole, and what was unpacked is left in "
                            f"{self.into}")

    def entry(self) -> None:
        self.asked()
        self.entries += 1
        if self.entries > MOST_FILES:
            raise DownloadError(f"{self.name} holds more than {MOST_FILES:,} entries: not unpacked further")

    def out(self, member: str) -> DownloadError:
        return DownloadError(f"{self.name} holds {str(member)[:120]!r}, which leads out of {self.into}: not unpacked "
                             "further")

    def place(self, member: str) -> str | None:
        """Where a member goes: under `root`, its first `strip` steps left out. None for one that names nothing
        then (the top folder itself). DownloadError for one that leads out, by its name or through a link there."""
        steps = member_steps(member, self.name)[self.strip:]
        if not steps:
            return None
        dest = os.path.join(self.root, *steps)
        self.inside(os.path.dirname(dest), member)
        return dest

    def inside(self, folder: str, member: str) -> None:
        if folder not in self._inside:
            if not _within(self.root, os.path.realpath(folder)):
                raise self.out(member)
            self._inside.add(folder)

    def room(self, size: int) -> None:
        self.bytes += max(0, int(size))
        if self.bytes > self.limit:
            raise DownloadError(f"{self.name} unpacks to more than {size_words(self.limit)}: stopped, not unpacked "
                                "whole")

    def clear(self, dest: str) -> None:
        """What is there under a member's name goes first: a file, or a link, which is never written through."""
        if os.path.islink(dest) or _junction(dest) or os.path.isfile(dest):
            os.unlink(dest)

    def folder(self, dest: str, member: str) -> None:
        self.inside(dest, member)
        os.makedirs(dest, exist_ok=True)

    def file(self, dest: str, read, size: int, mode: int | None, member: str) -> None:
        """A file written from `read(n)`: the `size` bytes its entry says, counted against the limit before the
        first is written; its mode the entry's without what lets others write it or run it as its owner."""
        self.room(size)
        self.clear(dest)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        left = max(0, int(size))
        with open(dest, "wb") as out:
            while left > 0:
                self.asked()
                piece = read(min(CHUNK, left))
                if not piece:
                    raise DownloadError(f"{self.name} ends inside {str(member)[:120]!r}: it is not whole")
                out.write(piece)
                left -= len(piece)
                self.written += len(piece)
                self.progress.say(self.written, self.total, f"unpacking {self.name}")
        if mode and os.name != "nt":
            os.chmod(dest, (mode & 0o755) | 0o600)
        self.files += 1

    def too_long(self, member: str) -> DownloadError:
        return DownloadError(f"{self.name} holds a link ({str(member)[:120]!r}) to a target of more than "
                             f"{LINK_MOST:,} characters: not unpacked further")

    def link(self, dest: str, target: str, member: str) -> None:
        """A symbolic link made as its entry says, when what it points at lies inside `root`: a whole path, one that
        leads out through `..` or through another link, or one of more than LINK_MOST characters, is refused. Where
        it leads is judged as this system follows a link: on Linux step by step (a `..` after a link climbs from
        where that link went), on Windows with its `..` folded against the link's own folder first, as Windows
        itself folds it (and ntpath.realpath with it), so `hop/../..` leads where it is written to, whatever `hop`
        is. It is written with this system's separator (link_target) and looked at again when the unpacking ends
        (leading_out)."""
        aim, shown = str(target or ""), repr(str(member)[:120])
        if len(aim) > LINK_MOST:
            raise self.too_long(member)
        if not aim or "\x00" in aim or aim.startswith(("/", "\\")) or aim[1:2] == ":":
            raise DownloadError(f"{self.name} holds a link ({shown}) to a whole path ({aim[:80]!r}): not unpacked "
                                "further")
        real = os.path.realpath(os.path.join(os.path.realpath(os.path.dirname(dest)), *_STEPS.split(aim)))
        if not _within(self.root, real):
            raise self.out(f"{member} -> {aim}")
        self.clear(dest)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            os.symlink(link_target(aim), dest, target_is_directory=os.path.isdir(real))
        except (OSError, NotImplementedError) as e:
            raise DownloadError(f"{self.name} holds a link ({shown}), and this system did not let it be made: "
                                f"{e}") from None
        self._inside.clear()
        self.links.pop(dest, None)  # (made again: in the order of its last making)
        self.links[dest] = f"{member} -> {aim}"
        self.files += 1

    def copy(self, dest: str, source: str, member: str) -> None:
        """A hard link's entry: the file it names, unpacked earlier, copied (two names of one file are not kept)."""
        steps = member_steps(source, self.name)[self.strip:]
        real = os.path.realpath(os.path.join(self.root, *steps)) if steps else ""
        if not real or not _within(self.root, real) or not os.path.isfile(real):
            raise DownloadError(f"{self.name} holds a link ({str(member)[:120]!r}) to {str(source)[:120]!r}, which "
                                "is no file it unpacked: not unpacked further")
        if os.path.exists(dest) and os.path.samefile(real, dest):
            return
        self.room(os.path.getsize(real))
        self.clear(dest)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(real, dest)
        shutil.copymode(real, dest)
        self.files += 1


def _unzip(archive: Path, out: _Unpacking) -> None:
    with zipfile.ZipFile(archive) as packed:
        infos = packed.infolist()
        if len(infos) > MOST_FILES:
            raise DownloadError(f"{out.name} holds more than {MOST_FILES:,} entries: not unpacked")
        out.total = sum(info.file_size for info in infos if not info.is_dir())
        if out.total > out.limit:  # as it says itself, before anything is written
            raise DownloadError(f"{out.name} unpacks to {size_words(out.total)}, more than {size_words(out.limit)}: "
                                "not unpacked")
        for info in infos:
            out.entry()
            mode = info.external_attr >> 16
            dest = out.place(info.filename)
            if dest is None:
                continue
            if info.is_dir():
                out.folder(dest, info.filename)
            elif info.flag_bits & 0x1:
                raise DownloadError(f"{out.name} holds an encrypted member ({info.filename[:120]!r}): not unpacked "
                                    "further")
            elif stat.S_ISLNK(mode):
                if info.file_size > LINK_MOST:  # said before its bytes are read
                    raise out.too_long(info.filename)
                out.link(dest, packed.read(info).decode("utf-8", "replace"), info.filename)
            elif stat.S_IFMT(mode) and not stat.S_ISREG(mode):
                raise DownloadError(f"{out.name} holds what is neither a file, a folder nor a link "
                                    f"({info.filename[:120]!r}): not unpacked further")
            else:
                with packed.open(info) as member:
                    out.file(dest, member.read, info.file_size, mode & 0o777, info.filename)


class _Stopped(DownloadError):
    """What tarfile is stopped at before it reads it: an extended header past its bound, a sparse file (unpack says
    it with the archive's name)."""


class _Bounded(tarfile.TarInfo):
    """A tar member as tarfile reads it, stopped before tarfile reads what no bound of an unpacking counts (its limit
    counts the members' bytes, not their headers'): an extended header (PAX records, a global one among them, a GNU
    long name or link) past HEADER_MOST bytes, or past HEADERS_MOST with every one before it, since tarfile reads each
    whole into memory and keeps what it says (a global one for the rest of the archive, a chain of long names all at
    once, every member's name with the member); and a sparse file, of either kind, whose map tarfile reads whole
    before it hands the member on. A small archive could hold gigabytes of any of them."""

    def _proc_member(self, archive):  # tarfile's own way for a subclass to take a member's header first
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise _Stopped(SPARSE)
        if self.type in _LONG:
            size = max(0, int(self.size))
            if size > HEADER_MOST:
                raise _Stopped(f"an extended header of {size_words(size)}, more than the {size_words(HEADER_MOST)} "
                               "read of one")
            total = int(getattr(archive, _COUNTED, 0)) + size
            setattr(archive, _COUNTED, total)
            if total > HEADERS_MOST:
                raise _Stopped(f"more than {size_words(HEADERS_MOST)} of extended headers (PAX records, long names) "
                               "in all")
        return super()._proc_member(archive)

    def _proc_gnusparse_00(self, *args):  # a sparse file as PAX records say it (GNU's 0.0, 0.1 and 1.0): its map unread
        raise _Stopped(SPARSE)

    _proc_gnusparse_01 = _proc_gnusparse_10 = _proc_gnusparse_00


def _members(packed: tarfile.TarFile, out: _Unpacking) -> None:
    for member in packed:
        out.entry()
        dest = out.place(member.name)
        if dest is None:
            continue
        if member.isdir():
            out.folder(dest, member.name)
        elif member.isreg():
            out.file(dest, packed.extractfile(member).read, member.size, member.mode, member.name)
        elif member.issym():
            out.link(dest, member.linkname, member.name)
        elif member.islnk():
            out.copy(dest, member.linkname, member.name)
        else:
            raise DownloadError(f"{out.name} holds what is neither a file, a folder nor a link "
                                f"({member.name[:120]!r}: a device or a pipe): not unpacked further")


def _os_release() -> dict:
    """What this Linux's os-release says of it (its ID, ID_LIKE ...); {} where there is none to read."""
    try:
        import platform

        return dict(platform.freedesktop_os_release())
    except (OSError, AttributeError):
        return {}


def _no_zstd(name: str, linux: bool | None = None, release: Mapping[str, str] | None = None) -> str:
    """Why a .tar.zst cannot be unpacked here, and what puts it right: on Linux the command that installs zstd on
    this distribution (by its os-release: `release`, a test's stand-in), the user's to run (nothing here asks for
    root), or, for a distribution not known here, its own package manager."""
    version = f"{sys.version_info[0]}.{sys.version_info[1]}"
    if sys.platform.startswith("linux") if linux is None else linux:
        said = _os_release() if release is None else release
        kinds = {str(said.get("ID", "")).strip().lower(), *str(said.get("ID_LIKE", "")).lower().split()}
        command = next((line for ids, line in ZSTD_PACKAGES if kinds & set(ids)), "")
        how = (f"`{command}`, yours to run" if command
               else "your distribution's package manager installs it, yours to run")
        return (f"{name} is a .tar.zst, which this Python ({version}) does not read by itself, and zstd is not "
                f"installed here: {how}")
    return (f"{name} is a .tar.zst, which this Python ({version}) does not read by itself, and no zstd program is "
            "on this system's PATH")


def _through_zstd(archive: Path, out: _Unpacking, which, popen, env: Mapping[str, str] | None = None) -> None:
    """A .tar.zst unpacked through the system's zstd where this Python reads none: `zstd -d -c`, windowless, its
    environment `env` (terminal.inherited), its output read as the archive; ended with the unpacking, however that
    ends."""
    program = (which or shutil.which)("zstd")
    if not program:
        raise DownloadError(_no_zstd(out.name))
    child = (popen or subprocess.Popen)([str(program), "-d", "-c", "-q", "--", str(archive)], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=inherited(env),
                                        **no_window())
    try:
        with tarfile.open(fileobj=child.stdout, mode="r|", tarinfo=_Bounded) as packed:
            _members(packed, out)
        after = 0
        while True:  # what follows the last entry (its padding) is read off, so that zstd ends by itself
            out.asked()
            more = child.stdout.read(CHUNK)
            if not more:
                break
            after += len(more)
            if after > TRAIL_MOST:
                raise DownloadError(f"{out.name} goes on after its last entry: no plain .tar.zst, not unpacked whole")
        code = child.wait(timeout=ZSTD_END_S)
        if code != 0:
            raise DownloadError(f"zstd could not unpack {out.name} (it ended with {code}): the file is not whole, "
                                "or no .tar.zst")
    finally:
        try:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=ZSTD_END_S)
        except Exception:  # noqa: BLE001 - gone already
            pass
        try:
            child.stdout.close()
        except Exception:  # noqa: BLE001 - closed already
            pass


def unpack(archive, into, *, log=None, cancel: Callable[[], bool] | None = None, limit: int = 16 << 30,
           strip: int = 0, which: Callable | None = None, popen: Callable | None = None,
           env: Mapping[str, str] | None = None) -> int:
    """An archive unpacked into the folder `into` (made when it is not there): the files written.

    A .zip, .tar.gz, .tgz or .tar.xz; a .tar.zst where this Python reads one (3.14 on), else through the system's
    `zstd` when it is on PATH (`which`, `popen`: a test's stand-ins; the child is windowless, its environment `env`
    as given, else this process's own without every LIMINAL_* name: a net only, so a plugin hands its own, as
    AiPlugin.unpack does), else DownloadError naming the command that installs it, the user's to run. `strip`:
    leading folders left out of every member's name (1: the archive's one top folder); a member that names nothing
    then is skipped.

    Nothing is written outside `into`: a member whose name leads out (a whole path, `..`), a link that points
    out (judged as this system follows a link: link), a device or a pipe is refused in words (DownloadError) and
    nothing more is unpacked. A link that stays inside is made, with this system's separator; a hard link's file is
    copied. Every link made is looked at again when the unpacking ends, however it ends: one that leads out then (a
    later member changed the way it goes) is removed, and an unpacking that would have ended well is refused for
    it. More than `limit` bytes or MOST_FILES entries; a tar member's extended header past HEADER_MOST bytes, or all
    of them past HEADERS_MOST; a name past NAME_MOST characters (NAME_MOST_WINDOWS on Windows), a link's target past
    LINK_MOST; a sparse file: refused. `cancel()` is looked at between members and between reads (Cancelled).
    After a refusal or a cancel, what was unpacked so far is left in `into`: the caller's to remove (it unpacks into
    a folder of its own making). mounts.NotHere for a folder on another system's drive."""
    archive, into = Path(archive), Path(into)
    low = archive.name.lower()
    kind = next((k for end, k in KINDS if low.endswith(end)), "")
    if not kind:
        raise DownloadError(f"{archive.name} is no archive unpacked here: a .zip, .tar.gz, .tgz, .tar.xz or .tar.zst")
    if isinstance(strip, bool) or not isinstance(strip, int) or strip < 0:
        raise ValueError(f"strip is a number of leading folders, 0 or more: not {strip!r}")
    mounts.owner_only(into, f"Unpacking {archive.name}")
    say = _sayer(log)
    out: _Unpacking | None = None
    led: list[str] = []
    try:
        try:
            into.mkdir(parents=True, exist_ok=True)
            out = _Unpacking(archive.name, into, limit, strip, cancel, Progress(log))
            say(f"unpacking {archive.name} into {into}")
            if kind == "zip":
                _unzip(archive, out)
            elif kind == "zst" and not _reads_zst():
                _through_zstd(archive, out, which, popen, env)
            else:
                with tarfile.open(archive, f"r:{kind}", tarinfo=_Bounded) as packed:
                    _members(packed, out)
        finally:
            led = out.leading_out() if out is not None else []  # however it ended: none is left leading out
    except _Stopped as e:
        raise DownloadError(f"{archive.name} holds {e}: not unpacked further") from None
    except (DownloadError, Cancelled):
        raise
    except Exception as e:  # noqa: BLE001 - the archive's own trouble (not whole, no archive), the disk's
        raise DownloadError(f"{archive.name} could not be unpacked into {into}: {type(e).__name__}: {e}") from None
    if led:
        more = f" (and {len(led) - 1:,} more)" if len(led) > 1 else ""
        raise DownloadError(f"{archive.name} holds a link ({led[0][:160]!r}){more} that leads out of {into} once the "
                            "members after it were unpacked: removed, and the archive refused")
    say(f"{out.files:,} files unpacked into {into} ({size_words(out.bytes)})")
    return out.files


# -- removing it -------------------------------------------------------------------------------------------------------
def _unlink(path: str, link: bool) -> None:
    """One file or link removed; a file that Windows marks read-only, or whose folder lets nothing be removed
    (POSIX), is tried once more with that taken off."""
    try:
        os.unlink(path)
    except PermissionError:
        if os.name == "nt" and not link:
            os.chmod(path, stat.S_IWRITE)
        elif os.name != "nt":
            os.chmod(os.path.dirname(path), 0o700)
        os.unlink(path)


def remove_tree(folder, inside) -> int:
    """A folder of the plugin's own removed with all it holds: the bytes its files held.

    Only a folder that lies inside `inside` (the plugin's own folder), by its path as written and by what its
    parent really is: ValueError otherwise, and for `inside` itself. No link is followed: a link or a Windows
    junction, in it or `folder` itself, is removed as the link it is, and what it shows stays. A folder that is
    not there is 0. What cannot be removed (a program still running from it, on Windows) is left, the rest still
    removed, and said in an OSError at the end. mounts.NotHere for a folder on another system's drive."""
    top, home = os.path.abspath(str(folder)), os.path.abspath(str(inside))
    if not _within(home, top) or os.path.normcase(top) == os.path.normcase(home):
        raise ValueError(f"{folder} does not lie inside {inside}: only a folder of the plugin's own is removed")
    mounts.owner_only(top, f"Removing {os.path.basename(top)}")
    if not os.path.lexists(top):
        return 0
    really = os.path.join(os.path.realpath(os.path.dirname(top)), os.path.basename(top))
    if not _within(os.path.realpath(home), really):
        raise ValueError(f"{folder} is reached through a link that leads out of {inside}: not removed")
    link = os.path.islink(top) or _junction(top)
    if link or not os.path.isdir(top):
        size = 0 if link else os.path.getsize(top)
        _unlink(top, link)
        return size
    freed = 0
    left: list[tuple[str, OSError]] = []  # what could not be removed, and why
    todo: list[tuple[str, bool]] = [(top, False)]  # folders to empty, and (emptied) to remove once their own are gone
    while todo:
        path, emptied = todo.pop()
        try:
            if emptied:
                if not any(kept.startswith(path + os.sep) for kept, _ in left):  # else it still holds what was left
                    os.rmdir(path)
                continue
            todo.append((path, True))
            with os.scandir(path) as found:
                entries = list(found)
        except OSError as e:
            left.append((path, e))
            continue
        for entry in entries:
            try:
                link = entry.is_symlink() or _junction(entry.path)
                if not link and entry.is_dir(follow_symlinks=False):
                    todo.append((entry.path, False))
                    continue
                size = 0 if link else entry.stat(follow_symlinks=False).st_size
                _unlink(entry.path, link)
                freed += size
            except OSError as e:
                left.append((entry.path, e))
    if left:
        path, why = left[0]
        raise OSError(f"{path} could not be removed" + (f" (nor {len(left) - 1:,} more)" if len(left) > 1 else "")
                      + f": {why}; {size_words(freed)} of {folder} was removed")
    return freed
