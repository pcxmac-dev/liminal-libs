"""Whose files a path's are (mounts.py, 1.56.0): Windows' drive seen from WSL is another system's (its locks, its lock
files' process ids and its clock are not this one's), a Linux disk of its own is not. The table read here is the one
the user's Ubuntu showed on 2026-11-15, shortened."""
from __future__ import annotations

import os
import platform
import sys

import pytest

from liminal_libs import mounts

WSL2 = r"""none /usr/lib/modules/6.18.58.1-microsoft-standard-WSL2 overlay rw,nosuid,nodev,noatime 0 0
none /mnt/wsl tmpfs rw,relatime 0 0
drivers /usr/lib/wsl/drivers 9p ro,nosuid,nodev,noatime,aname=drivers;fmask=222;dmask=222,cache=0x5,access=client,msize=65536,trans=fd,rfd=8,wfd=8 0 0
/dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered 0 0
none /mnt/wslg tmpfs rw,relatime 0 0
none /run tmpfs rw,nosuid,nodev,mode=755 0 0
none /run/user tmpfs rw,nosuid,nodev,noexec,noatime,mode=755 0 0
C:\134 /mnt/c 9p rw,noatime,aname=drvfs;path=C:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6 0 0
tmpfs /run/user/1000 tmpfs rw,nosuid,nodev,relatime,size=3258464k,nr_inodes=814616,mode=700,uid=1000,gid=1000 0 0
"""


def test_windows_drive_seen_from_wsl_is_another_systems_and_linuxs_own_disk_is_not():
    rows = mounts.table(WSL2)
    assert ("/mnt/c", "9p") in rows and ("/", "ext4") in rows and len(rows) == 9
    data = "/mnt/c/Users/ciara/source/liminal/store/data"
    assert mounts.fstype(f"{data}/liminal.db", rows) == "9p" and mounts.foreign(f"{data}/liminal.db", rows)
    assert mounts.foreign("/mnt/c", rows) and mounts.foreign(f"{data}/liminal-fetch-massive.lock", rows)
    assert not mounts.foreign("/home/sysop/liminal/store/data/liminal.db", rows)  # the clone's own data, on Linux's disk
    assert not mounts.foreign("/mnt/cache/liminal.db", rows)  # /mnt/c is a folder there, not the start of a name
    assert not mounts.foreign("/mnt/wsl/liminal.db", rows) and not mounts.foreign("/tmp/x.db", rows)
    assert mounts.fstype("/run/user/1000/x", rows) == "tmpfs"  # the longest mount point it lies under


def test_a_mount_point_with_a_space_and_a_later_mount_at_the_same_point():
    rows = mounts.table("//server/share /mnt/my\\040share cifs rw 0 0\n"
                        "/dev/sda1 /data ext4 rw 0 0\n"
                        "server:/export /data nfs4 rw 0 0\n"
                        "a line that is not one\n")
    assert rows[:3] == [("/mnt/my share", "cifs"), ("/data", "ext4"), ("/data", "nfs4")]
    assert mounts.foreign("/mnt/my share/liminal.db", rows)
    assert mounts.fstype("/data/x", rows) == "nfs4" and mounts.foreign("/data/x", rows)  # the later one is in force
    for kind in ("sshfs", "virtiofs", "vboxsf"):
        named = "fuse.sshfs" if kind == "sshfs" else kind
        assert mounts.foreign("/shared/x", [("/", "ext4"), ("/shared", named)])


def test_where_there_is_no_table_nothing_is_foreign():
    assert mounts.table("") == [] and mounts.fstype("/x", []) is None and not mounts.foreign("/x", [])


def test_this_systems_own_disk_is_its_own(tmp_path):
    assert mounts.foreign(tmp_path / "liminal.db") is False
    if sys.platform == "win32":
        assert mounts.table() == [] and mounts.fstype(tmp_path) is None
        assert mounts.foreign(r"\\wsl.localhost\Ubuntu\home\sysop\liminal\liminal.db") is True  # Linux's files from Windows
        assert mounts.foreign("C:\\") is False
    else:
        assert mounts.table() and mounts.fstype("/") is not None


@pytest.mark.skipif(not (sys.platform.startswith("linux") and "microsoft" in platform.release().lower()
                         and os.path.isdir("/mnt/c/Windows")), reason="only inside WSL with Windows' drive mounted")
def test_inside_wsl_the_real_windows_drive_is_foreign():
    assert mounts.foreign("/mnt/c/Windows") and mounts.fstype("/mnt/c/Windows") in mounts.FOREIGN
    assert not mounts.foreign(os.path.expanduser("~"))


def test_on_windows_a_path_is_judged_as_it_really_is():
    """1.58.1, found by a review of the GeoIP guard: Windows judged a path by its spelling. A junction from this
    machine's disk into a share passed for this machine's own (Linux's judgement follows links), and a local folder in
    its extended-length or device spelling counted as a share, so work on this machine's own files was refused."""
    here = lambda text: text  # noqa: E731 - nothing is a link
    local = lambda root: False  # noqa: E731 - no network drive
    judge = lambda path, real=here, remote=local: mounts.foreign_on_windows(path, real=real, remote=remote)  # noqa: E731
    assert not judge(r"C:\Users\x\source\liminal\store\data\liminal.db") and not judge("C:/data/liminal.db")
    assert judge(r"\\server\share\liminal\liminal.db") and judge("//server/share/liminal.db")
    assert judge(r"\\wsl.localhost\Ubuntu\home\sysop\liminal\store\data\liminal.db")
    # a local path spelled the long way, or as a device's, is the local path it is
    assert not judge(r"\\?\C:\Users\x\data\liminal.db") and not judge(r"\\.\C:\Users\x\data\liminal.db")
    assert judge(r"\\?\UNC\server\share\liminal.db")  # ... and a share so spelled is still a share
    assert mounts.plain_windows(r"\\?\C:\x") == r"C:\x" and mounts.plain_windows(r"\\?\UNC\s\sh\x") == r"\\s\sh\x"
    assert mounts.plain_windows(r"C:\x") == r"C:\x" and mounts.plain_windows(r"\\server\share") == r"\\server\share"
    # a link from this machine's disk into a share is the share's
    junction = lambda text: text.replace(r"C:\data", r"\\nas\share\liminal")  # noqa: E731
    assert judge(r"C:\data\liminal.db", real=junction) and not judge(r"C:\other\liminal.db", real=junction)
    into_wsl = lambda text: r"\\?\UNC\wsl.localhost\Ubuntu\home\sysop\x" if text.startswith("D:") else text  # noqa: E731
    assert judge(r"D:\link\x", real=into_wsl)
    # a network drive by Windows' word, and by where its letter really leads
    assert judge(r"Z:\liminal\liminal.db", remote=lambda root: root == "Z:\\") and not judge(r"C:\x", remote=lambda root: root == "Z:\\")
    assert judge(r"Z:\liminal.db", real=lambda text: text.replace("Z:", r"\\server\share"))
    # a volume by its own name is a disk here unless Windows says it is not
    volume = r"\\?\Volume{4c1b02c1-d990-11dc-99ae-806e6f6e6963}\data\liminal.db"
    assert not judge(volume) and judge(volume, remote=lambda root: root.startswith("\\\\?\\Volume{"))

    def unreadable(text):
        raise OSError("no such name")

    assert not judge(r"C:\data\liminal.db", real=unreadable) and judge(r"\\server\share\x", real=unreadable)  # by its spelling


@pytest.mark.skipif(sys.platform != "win32", reason="Windows' own answer")
def test_on_this_windows_machine_its_own_disk_is_its_own_however_it_is_spelled(tmp_path):
    mounts._foreign.cache_clear()
    plain = str(tmp_path / "liminal.db")
    assert not mounts.foreign(plain) and not mounts.foreign("\\\\?\\" + plain) and not mounts.foreign(plain.replace("\\", "/"))
    mounts.owner_only("\\\\?\\" + plain, "a backup")  # this machine's own files so spelled: not refused
    assert mounts.foreign(r"\\wsl.localhost\Ubuntu\home") and mounts.foreign(r"\\?\UNC\wsl.localhost\Ubuntu\home")


def test_a_windows_path_is_named_here_where_its_drive_is_mounted():
    """What is kept on Windows names a file as Windows does; the suite inside WSL finds it where that drive is mounted
    (1.61.0: a database instance's path, storage/databases.py), or says it has no name for it."""
    assert mounts.here_path(r"C:\Users\ciara\source\liminal\store\data\liminal.db", WSL2) == (
        "/mnt/c/Users/ciara/source/liminal/store/data/liminal.db")
    assert mounts.here_path("c:\\", WSL2) == "/mnt/c/" and mounts.here_path(r"C:\x", WSL2) == "/mnt/c/x"
    assert mounts.owner_path(mounts.here_path(r"C:\data\x.db", WSL2), WSL2) == r"C:\data\x.db"  # there and back
    for nowhere in (r"D:\data\x.db", r"\\server\share\x.db", "/srv/x.db", "x.db", ""):
        assert mounts.here_path(nowhere, WSL2) is None  # a drive not mounted here, a share, no Windows path at all
    two = WSL2 + "D:\\134 /mnt/d 9p rw 0 0\nC:\\134 /mnt/c/again 9p rw 0 0\n"
    assert mounts.here_path(r"D:\x.db", two) == "/mnt/d/x.db" and mounts.here_path(r"C:\x.db", two) == "/mnt/c/x.db"
    assert mounts.here_path(r"C:\x.db", "") is None  # no table at all (Windows itself, macOS)
