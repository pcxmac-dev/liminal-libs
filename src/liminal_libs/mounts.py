"""Whose files a path's are: this system's own disk, or another system's seen through a mount (1.56.0).

The user's data stays where it is, on the Windows drive, and the suite runs a second time inside WSL (2026-11-15: "keep
the databases (sql/duck/etc) in the same place"). Seen from Linux those files are `/mnt/c/...`, a 9p mount of Windows'
drive, and three things that hold on a system's own disk do not hold there: SQLite's locks and its WAL's shared memory
do not cross, a process id in a lock file names a process of the other system, and the two systems' clocks differ. So
the code asks here before it trusts any of the three. `foreign()` is the one question; storage/link.py (the helper that
opens such a file on its own system) and claims.py (a lock file there cannot be judged) are its askers.
"""
from __future__ import annotations

import os
import re
import sys
from functools import lru_cache
from pathlib import Path

# Filesystems that show another system's files: WSL's view of a Windows drive (9p in WSL 2, drvfs in WSL 1), shares
# over the network, a virtual machine's shared folders
FOREIGN = frozenset({"9p", "drvfs", "cifs", "smb3", "smbfs", "nfs", "nfs4", "fuse.sshfs", "virtiofs", "vboxsf",
                     "fuse.vmhgfs-fuse", "prl_fs"})
MOUNTS = "/proc/self/mounts"
_ESCAPED = re.compile(r"\\([0-7]{3})")  # a space in a mount point is written \040 there
DRIVE_REMOTE = 4  # GetDriveTypeW: a network drive


class NotHere(RuntimeError):
    """Work that only the system whose drive the files are on does, asked for from another."""


def owner_only(path, what: str) -> None:
    """NotHere when `path` is another system's file seen through a mount: `what` (starting MongoDB, a backup, the
    closed months' copy ...) is done by the system the files belong to. Two systems doing it would undo each
    other's work, and the files it moves or swaps are open on the other side."""
    if foreign(path):
        raise NotHere(f"{what}: {path} is on another system's drive, and that is done from that system, not from here")


def _rows(text: str | None = None) -> list[tuple[str, str, str]]:
    """The mounts as this process sees them: (what is mounted, mount point, filesystem type), in the system's order."""
    if text is None:
        try:
            text = Path(MOUNTS).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
    plain = lambda s: _ESCAPED.sub(lambda m: chr(int(m.group(1), 8)), s)  # noqa: E731
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            rows.append((plain(parts[0]), plain(parts[1]), parts[2]))
    return rows


def table(text: str | None = None) -> list[tuple[str, str]]:
    """The mounts as this process sees them: (mount point, filesystem type), in the order the system lists them (a
    later one at the same point is the one in force). `text`: /proc/self/mounts' content (a test's); without it the
    file is read, and where there is none (Windows, macOS) the table is empty."""
    return [(point, kind) for _, point, kind in _rows(text)]


_DRIVE = re.compile(r"^[A-Za-z]:\\?$")  # what a WSL mount of a Windows drive says it shows: C:\


def owner_path(path, text: str | None = None) -> str | None:
    r"""A file on a Windows drive seen from WSL, as Windows names it: /mnt/c/Users/x/liminal.db is
    C:\Users\x\liminal.db (the mount says which drive it shows). None for a path that is on no such mount: this
    system's own disk, a share, WSL's own folders. `text`: /proc/self/mounts' content (a test's: the path is then
    taken as written)."""
    p = os.path.realpath(str(path)) if text is None else str(path)
    best: tuple[str, str] | None = None
    for source, point, kind in _rows(text):
        if kind in ("9p", "drvfs") and (p == point or p.startswith(point.rstrip("/") + "/")):
            if best is None or len(point) >= len(best[1]):
                best = (source, point)
    if best is None or not _DRIVE.match(best[0]):
        return None
    rest = p[len(best[1]):].lstrip("/")
    return best[0].rstrip("\\") + "\\" + rest.replace("/", "\\")


def fstype(path, mounts: list[tuple[str, str]] | None = None) -> str | None:
    """The filesystem type of the mount that holds `path`: the longest mount point it lies under. None where the
    system has no such table. `mounts`: a table to read instead of this system's (a test's: the path is then taken as
    written, with forward slashes)."""
    rows = table() if mounts is None else mounts
    if not rows:
        return None
    p = os.path.realpath(str(path)) if mounts is None else str(path)  # a link into the other system's drive counts
    best: tuple[str, str] | None = None
    for point, kind in rows:
        under = p == point or p.startswith(point.rstrip("/") + "/")
        if under and (best is None or len(point) >= len(best[0])):
            best = (point, kind)
    return best[1] if best else None


def foreign(path, mounts: list[tuple[str, str]] | None = None) -> bool:
    """Whether `path` is another system's file seen through a mount: its locks, its lock files' process ids and its
    clock are that system's, not this one's. On Windows: a share's path (\\\\server\\share, WSL's own \\\\wsl.localhost)
    or a network drive."""
    if mounts is not None:
        return fstype(path, mounts) in FOREIGN
    return _foreign(str(path))


@lru_cache(maxsize=256)
def _foreign(path: str) -> bool:
    """foreign() for this system, remembered by path: a data folder does not change disks under a running process."""
    if sys.platform == "win32":
        if path.startswith("\\\\") or path.startswith("//"):
            return True
        drive = os.path.splitdrive(os.path.abspath(path))[0]
        if not drive:
            return False
        try:
            import ctypes

            return ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") == DRIVE_REMOTE
        except (OSError, AttributeError):
            return False
    return fstype(path) in FOREIGN
