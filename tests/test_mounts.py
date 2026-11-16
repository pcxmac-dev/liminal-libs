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
