"""Linux's socket table with the program behind each socket (liminal_libs.sockets: read_linux, ProcFiles, Owners; the
user, 2026-11-16: "the firewall app should have a 'netstat' like interface for looking at active ports and what apps
they are attached to, and the hosts that they connect to across the lan or wan"). /proc is a stand-in (FakeFiles:
files and links in dicts, as test_resources_linux's), so every test runs on Windows as on Linux: the four files of
/proc/net as the kernel writes them, each process's descriptors, its comm, exe, cgroup and stat; an ordinary user is
kept out of the other users' descriptors as the kernel keeps it out.

Nothing real is reached: not this machine's /proc, its users or its clock ticks, no process, no socket, nothing of
the network (this file's own fixture and the library's shared guard, `no_outside`, fail a test that does)."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import urllib.request

import pytest

from liminal_libs import sockets
from liminal_libs.sockets import Owners

pytestmark = pytest.mark.usefixtures("no_outside")

READ = sockets.read  # the real one, over stand-ins only (the suite's own guard may refuse the module's name for it)
REAL = {name: getattr(sockets.ProcFiles, name) for name in ("read", "listdir", "readlink")}  # on a test's folder
NOW, BOOT = 1_800_050_000.0, 1_800_000_000
LAN, LAN6, PEER, WEB, WEB6 = "192.168.1.20", "2001:db8:1::20", "192.168.1.7", "93.184.216.34", "2606:4700::1111"
USERS = {0: "root", 1000: "ada", 107: "avahi"}
OTHERS = (1, 600, 700, 900, 950, 951)  # the processes of other users: an ordinary user may not look into them
KEYS = ["proto", "family", "state", "local", "local_port", "remote", "remote_port", "pid", "pids", "program", "path",
        "service", "service_title", "user", "started", "process_started", "count", "inode", "seen", "unread"]
TCP_HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
UDP_HEAD = ("   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref "
            "pointer drops\n")
NO_SOCKET = "the kernel lists no socket for it (closing, or not open yet)"
NO_USER = "the kernel keeps no user for it (closing, or not open yet)"
NOT_HELD = ("no process this account may look into holds it: another WSL distribution's or a container's, or a "
            "program of yours that does not let itself be looked into")
NOT_HELD_ROOT = "no process here holds it: another WSL distribution's or a container's, or the kernel's own"


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch):
    """Nothing real is reached: no child process, no download, no socket, none of Windows' libraries, not this
    machine's /proc, its hosts file, its user or its users' names (each reach is noted, so one that was caught is seen
    too). No owner is kept from one test to the next."""
    reached: list[str] = []

    def refusing(name):
        def refuse(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"a test reached the real {name}")
        return refuse
    for owner, name in ((subprocess, "Popen"), (subprocess, "run"), (urllib.request, "urlopen"), (socket, "socket"),
                        (sockets.WindowsApi, "_library"), (sockets.WindowsApi, "names"),
                        (sockets.WindowsApi, "elevated"), (sockets.ProcFiles, "read"), (sockets.ProcFiles, "listdir"),
                        (sockets.ProcFiles, "readlink"), (sockets, "_hosts_text"), (sockets, "_uid"),
                        (sockets, "_user_of")):
        monkeypatch.setattr(owner, name, refusing(f"{owner.__name__}.{name}"))
    monkeypatch.setattr(sockets, "_SHARED", {})
    yield
    assert reached == []


# -- /proc as the kernel writes it -------------------------------------------------------------------------------------
def end(address: str, port: int) -> str:
    """An address and port as /proc/net writes them: each 32-bit word of the address in the machine's own order
    (0100007F is 127.0.0.1), the port in plain hex."""
    packed = ipaddress.ip_address(address).packed
    words = b"".join(packed[i:i + 4][::-1] for i in range(0, len(packed), 4))
    return f"{words.hex().upper()}:{port:04X}"


def line(n, local, local_port, remote, remote_port, state, uid, inode, udp=False, timer=0) -> str:
    """One line of a table as the kernel prints it; `timer` is its tr column (3: a TIME_WAIT minisock's)."""
    zero = "::" if ":" in local else "0.0.0.0"
    ends = f"{end(local, local_port)} {end(remote or zero, remote_port)}"
    tail = "2 0000000000000000 0" if udp else "1 0000000000000000 100 0 0 10 0"
    return (f"{n:4d}: {ends} {state:02X} 00000000:00000000 {timer:02X}:00000000 00000000 {uid:5d}        0 {inode} "
            f"{tail}\n")


def stat_line(pid, comm, start) -> str:
    return f"{pid} ({comm}) S 1 0 0 0 -1 0 0 0 0 0 250 50 0 0 20 0 12 0 {start} 0 0\n"


def proc() -> tuple[dict, dict]:
    files = {
        "/proc/stat": f"cpu  1000 0 500 8000 500 0 0 0 0 0\ncpu0 1000 0 500 8000 500 0 0 0 0 0\nbtime {BOOT}\n",
        "/proc/net/tcp": TCP_HEAD
        + line(0, "0.0.0.0", 22, "", 0, 0x0A, 0, 1001)  # root's sshd, held by the init too
        + line(1, "127.0.0.1", 8765, "", 0, 0x0A, 1000, 11111)
        + line(2, LAN, 51000, WEB, 443, 0x01, 1000, 22222)
        + line(3, LAN, 51001, WEB, 443, 0x06, 0, 0, timer=3)  # TIME_WAIT: the kernel keeps no socket and no user
        + line(4, LAN, 40001, "192.168.1.9", 445, 0x01, 1000, 33333)  # this user's, and no process here holds it
        + line(5, LAN, 22, "203.0.113.9", 60122, 0x01, 0, 1002),
        "/proc/net/tcp6": TCP_HEAD
        + line(0, "::", 8080, "", 0, 0x0A, 1000, 44444)
        + line(1, f"::ffff:{LAN}", 8080, f"::ffff:{PEER}", 50123, 0x01, 1000, 44445)  # an IPv4 peer of that listener
        + line(2, LAN6, 51002, WEB6, 443, 0x01, 1000, 22223),
        "/proc/net/udp": UDP_HEAD
        + line(0, "0.0.0.0", 5353, "", 0, 0x07, 107, 555, udp=True)
        + line(1, LAN, 40000, "142.250.1.1", 443, 0x01, 1000, 666, udp=True)  # connected: Linux says its peer
        + line(2, "127.0.0.53", 53, "", 0, 0x07, 999, 777, udp=True),
        "/proc/net/udp6": UDP_HEAD + line(0, "::", 5353, "", 0, 0x07, 107, 556, udp=True),
        "/proc/1/comm": "systemd\n", "/proc/1/stat": stat_line(1, "systemd", 5), "/proc/1/cgroup": "0::/init.scope\n",
        "/proc/2/comm": "kthreadd\n", "/proc/2/stat": stat_line(2, "kthreadd", 6),
        "/proc/600/comm": "systemd-resolve\n", "/proc/600/stat": stat_line(600, "systemd-resolve", 900),
        "/proc/600/cgroup": "0::/system.slice/systemd-resolved.service\n",
        "/proc/700/comm": "avahi-daemon\n", "/proc/700/stat": stat_line(700, "avahi-daemon", 1000),
        "/proc/700/cgroup": "0::/system.slice/avahi-daemon.service\n",
        "/proc/900/comm": "sshd\n", "/proc/900/stat": stat_line(900, "sshd", 1200),
        "/proc/900/cgroup": "0::/system.slice/ssh.service\n",
        "/proc/950/comm": "sshd\n", "/proc/950/stat": stat_line(950, "sshd", 300000),
        "/proc/950/cgroup": "0::/user.slice/user-1000.slice/session-3.scope\n",
        "/proc/951/comm": "sshd\n", "/proc/951/stat": stat_line(951, "sshd", 300100),
        "/proc/951/cgroup": "0::/user.slice/user-1000.slice/session-3.scope\n",
        "/proc/4242/comm": "python3\n", "/proc/4242/stat": stat_line(4242, "python3", 360000),
        "/proc/4242/cgroup": "0::/user.slice/user-1000.slice/user@1000.service/app.slice/liminal-platform.service\n",
        "/proc/5000/comm": "firefox\n", "/proc/5000/stat": stat_line(5000, "a (strange) name", 370000),
        "/proc/5000/cgroup": "0::/user.slice/user-1000.slice/session-3.scope\n",
    }
    links = {
        "/proc/1/exe": "/usr/lib/systemd/systemd", "/proc/1/fd/50": "socket:[1001]",
        "/proc/600/exe": "/usr/lib/systemd/systemd-resolved", "/proc/600/fd/11": "socket:[777]",
        "/proc/700/exe": "/usr/sbin/avahi-daemon", "/proc/700/fd/12": "socket:[555]", "/proc/700/fd/13": "socket:[556]",
        "/proc/900/exe": "/usr/sbin/sshd", "/proc/900/fd/3": "socket:[1001]",
        "/proc/950/exe": "/usr/sbin/sshd", "/proc/950/fd/4": "socket:[1002]",
        "/proc/951/exe": "/usr/sbin/sshd", "/proc/951/fd/4": "socket:[1002]",
        "/proc/4242/exe": "/usr/bin/python3.12", "/proc/4242/fd/0": "/dev/null", "/proc/4242/fd/3": "socket:[11111]",
        "/proc/4242/fd/4": "socket:[44444]", "/proc/4242/fd/5": "socket:[44445]",
        "/proc/5000/exe": "/usr/lib/firefox/firefox", "/proc/5000/fd/7": "anon_inode:[eventpoll]",
        "/proc/5000/fd/8": "pipe:[9999]", "/proc/5000/fd/40": "socket:[22222]", "/proc/5000/fd/41": "socket:[22223]",
        "/proc/5000/fd/42": "socket:[666]",
    }
    return files, links


class FakeFiles:
    """/proc stood in for: files and links in dicts. A file not in them is not there (""), as ProcFiles says of one;
    one in `refused` is there and cannot be read (None). `hidden`: the processes of other users, whose descriptors
    and whose program's path the kernel does not show an ordinary user. Everything asked for is noted."""

    def __init__(self, files=None, links=None, hidden=OTHERS):
        made = proc()
        self.files = made[0] if files is None else files
        self.links = made[1] if links is None else links
        self.hidden = {str(pid) for pid in hidden}
        self.refused: set[str] = set()
        self.reads: list[str] = []
        self.lists: list[str] = []
        self.linked: list[str] = []

    def _kept_out(self, path: str) -> bool:
        parts = path.split("/")
        return len(parts) > 3 and parts[2] in self.hidden and parts[3] in ("fd", "exe")

    def read(self, path):
        self.reads.append(path)
        return None if path in self.refused else self.files.get(path, "")

    def listdir(self, path):
        self.lists.append(path)
        if self._kept_out(path):
            return []
        prefix = path.rstrip("/") + "/"
        return sorted({p[len(prefix):].split("/", 1)[0] for p in [*self.files, *self.links] if p.startswith(prefix)})

    def readlink(self, path):
        self.linked.append(path)
        return None if self._kept_out(path) else self.links.get(path)

    def end(self, pid: int) -> None:
        """Process `pid` ends: its /proc folder goes."""
        for path in [p for p in [*self.files, *self.links] if p.startswith(f"/proc/{pid}/")]:
            self.files.pop(path, None)
            self.links.pop(path, None)

    def walked(self) -> list[str]:
        """The descriptor folders listed so far: a walk of /proc/<pid>/fd lists every process's."""
        return [path for path in self.lists if path.endswith("/fd")]


def user_of(uid: int) -> str:
    return USERS.get(uid, str(uid))


def reading(files=None, owners=None, at=NOW, uid=1000, **more):
    files = FakeFiles(hidden=() if uid == 0 else OTHERS) if files is None else files
    return sockets.read_linux(files, owners=Owners() if owners is None else owners, clock=lambda: at, uid=uid,
                              user_of=more.pop("user_of", user_of), awake=more.pop("awake", lambda: 4321.5),
                              ticks=100, **more)


def one(rows, proto, local_port, remote_port=0, family=None):
    found = [r for r in rows if (r["proto"], r["local_port"], r["remote_port"]) == (proto, local_port, remote_port)
             and family in (None, r["family"])]
    assert len(found) == 1, found
    return found[0]


def connections(inodes, holder=5000, first_port=41000) -> str:
    """This user's connections to the web, one for each of `inodes`, as /proc/net/tcp lists them."""
    return TCP_HEAD + "".join(line(n, LAN, first_port + n, WEB, 443, 0x01, 1000, inode)
                              for n, inode in enumerate(inodes))


# -- the four files ----------------------------------------------------------------------------------------------------
def test_the_four_files_are_read_into_rows_each_with_its_user_and_its_inode():
    asked = []

    def counting(uid):
        asked.append(uid)
        return user_of(uid)
    found = reading(user_of=counting)
    assert list(found) == ["system", "at", "awake", "took", "root", "starts", "read", "cut", "rows", "notes"]
    assert (found["system"], found["at"], found["awake"], found["root"], found["starts"]) == ("linux", NOW, 4321.5,
                                                                                               False, False)
    assert found["read"] == ("tcp4", "tcp6", "udp4", "udp6") and found["cut"] is False and found["took"] >= 0
    assert found["notes"] == [
        "Read as ada: the kernel lists every socket here and names the program of your own alone.",
        "Linux does not say when a connection began: Since is when it was first seen here."]
    rows = found["rows"]
    assert [(r["proto"], r["family"], r["state"], r["local"], r["local_port"], r["remote"], r["remote_port"],
             r["inode"], r["user"]) for r in rows] == [
        ("tcp", 4, "listening", "0.0.0.0", 22, "", 0, 1001, "root"),
        ("tcp", 4, "listening", "127.0.0.1", 8765, "", 0, 11111, "ada"),
        ("tcp", 4, "established", LAN, 51000, WEB, 443, 22222, "ada"),
        ("tcp", 4, "time-wait", LAN, 51001, WEB, 443, 0, ""),  # the kernel's uid 0 there stands for no one
        ("tcp", 4, "established", LAN, 40001, "192.168.1.9", 445, 33333, "ada"),
        ("tcp", 4, "established", LAN, 22, "203.0.113.9", 60122, 1002, "root"),
        ("tcp", 6, "listening", "::", 8080, "", 0, 44444, "ada"),
        ("tcp", 6, "established", LAN, 8080, PEER, 50123, 44445, "ada"),  # said as IPv4; its family stays its file's
        ("tcp", 6, "established", LAN6, 51002, WEB6, 443, 22223, "ada"),
        ("udp", 4, "bound", "0.0.0.0", 5353, "", 0, 555, "avahi"),  # 07: no peer
        ("udp", 4, "connected", LAN, 40000, "142.250.1.1", 443, 666, "ada"),  # 01: connected, with its peer
        ("udp", 4, "bound", "127.0.0.53", 53, "", 0, 777, "999"),  # a user with no name: its number
        ("udp", 6, "bound", "::", 5353, "", 0, 556, "avahi")]
    assert all(list(r) == KEYS for r in rows)
    assert all(r["started"] is None and r["seen"] == NOW and r["count"] == 1 and r["service_title"] == ""
               for r in rows)
    assert sorted(asked) == [0, 107, 999, 1000]  # each user's name asked once a reading
    json.dumps(found, allow_nan=False)
    assert end("127.0.0.1", 8765) == "0100007F:223D" and end("::1", 8080) == "00000000000000000000000001000000:1F90"
    assert end(f"::ffff:{LAN}", 80).startswith("0000000000000000FFFF0000")  # as the kernel writes a mapped address


def test_an_own_socket_has_its_program_its_path_its_unit_and_its_start():
    rows = reading()["rows"]
    listener = one(rows, "tcp", 8765)
    assert listener == {"proto": "tcp", "family": 4, "state": "listening", "local": "127.0.0.1", "local_port": 8765,
                        "remote": "", "remote_port": 0, "pid": 4242, "pids": [4242], "program": "python3",
                        "path": "/usr/bin/python3.12", "service": "liminal-platform.service", "service_title": "",
                        "user": "ada", "started": None, "process_started": BOOT + 3600.0, "count": 1, "inode": 11111,
                        "seen": NOW, "unread": {}}
    for mine in (one(rows, "tcp", 8080), one(rows, "tcp", 8080, 50123)):
        assert (mine["pid"], mine["program"], mine["service"]) == (4242, "python3", "liminal-platform.service")
    for port, remote in ((51000, 443), (51002, 443)):
        browser = one(rows, "tcp", port, remote)
        assert (browser["pid"], browser["pids"], browser["program"], browser["path"]) == (5000, [5000], "firefox",
                                                                                          "/usr/lib/firefox/firefox")
        assert browser["service"] == "" and browser["unread"] == {}  # a session's program runs in no service
        assert browser["process_started"] == BOOT + 3700.0  # stat's field 22, past a name with spaces and parentheses
    quic = one(rows, "udp", 40000, 443)
    assert (quic["state"], quic["remote"], quic["program"]) == ("connected", "142.250.1.1", "firefox")


def test_what_a_row_cannot_read_is_said_in_words():
    rows = reading()["rows"]
    for port, user in ((22, "root"), (5353, "avahi"), (53, "999")):
        for other in (r for r in rows if r["local_port"] == port):
            assert (other["pid"], other["pids"], other["program"], other["path"], other["user"]) == (0, [], "", "",
                                                                                                     user)
            assert other["unread"] == {"program": f"another user's ({user}): only root reads which program holds it"}
    unowned = one(rows, "tcp", 40001, 445)  # another distribution's, a container's, or a program not to be looked at
    assert (unowned["pid"], unowned["pids"], unowned["program"], unowned["user"]) == (0, [], "", "ada")
    assert unowned["unread"] == {"program": NOT_HELD} and sockets.NOT_HELD == NOT_HELD
    closing = one(rows, "tcp", 51001, 443)  # inode 0: said so, not taken for root's
    assert (closing["inode"], closing["pid"], closing["user"]) == (0, 0, "")
    assert closing["unread"] == {"program": NO_SOCKET, "user": NO_USER}
    # a program whose path is not said, and a process gone between the table and the look at it
    files = FakeFiles()
    del files.links["/proc/5000/exe"], files.files["/proc/4242/comm"], files.links["/proc/4242/exe"]
    rows = reading(files)["rows"]
    assert one(rows, "tcp", 51000, 443)["program"] == "firefox"
    assert one(rows, "tcp", 51000, 443)["unread"] == {"path": "Linux did not say where this program is on disk"}
    gone = one(rows, "tcp", 8765)
    assert (gone["pid"], gone["program"]) == (4242, "") and gone["unread"] == {
        "program": "process 4242 ended while the table was read"}
    # rows share no `unread`
    owners = Owners()
    one(reading(owners=owners)["rows"], "tcp", 40001, 445)["unread"]["program"] = "changed"
    assert one(reading(owners=owners)["rows"], "tcp", 40001, 445)["unread"] == {"program": NOT_HELD}


def test_the_kernel_keeps_no_user_for_a_socket_no_program_holds():
    files = FakeFiles()
    files.files["/proc/net/tcp"] = TCP_HEAD + (
        line(0, LAN, 51001, WEB, 443, 0x06, 0, 0, timer=3)  # TIME_WAIT: a minisock, which keeps no owner
        + line(1, LAN, 51002, WEB, 443, 0x05, 0, 0, timer=3)  # a FIN_WAIT2 whose program let go: a minisock too
        + line(2, LAN, 51003, WEB, 443, 0x04, 0, 0, timer=1)  # FIN_WAIT1, let go: uid 0 for no one before Linux 6.17
        + line(3, LAN, 51004, WEB, 443, 0x04, 1000, 0, timer=1)  # the same from 6.17, which keeps its owner
        + line(4, LAN, 8765, "192.168.1.1", 50500, 0x03, 1000, 0, timer=1)  # SYN_RECV: the listener's user
        + line(5, LAN, 51005, WEB, 443, 0x01, 0, 0)  # accepted by the kernel, not yet by its program (before 6.17)
        + line(6, "0.0.0.0", 22, "", 0, 0x0A, 0, 1001))  # root's own listener: root's
    rows = reading(files)["rows"][:7]
    assert [(r["local_port"], r["user"], r["unread"].get("user")) for r in rows] == [
        (51001, "", NO_USER), (51002, "", NO_USER), (51003, "", NO_USER), (51004, "ada", None), (8765, "ada", None),
        (51005, "", NO_USER), (22, "root", None)]
    assert all(r["unread"]["program"] == NO_SOCKET and r["pid"] == 0 for r in rows[:6])
    assert rows[6]["unread"] == {"program": "another user's (root): only root reads which program holds it"}


def test_root_reads_every_sockets_program():
    files = FakeFiles(hidden=())
    files.files["/proc/net/tcp"] += line(6, "0.0.0.0", 631, "", 0, 0x0A, 0, 1003)
    files.links["/proc/1/fd/51"] = "socket:[1003]"  # one the init alone holds, for a service not started yet
    found = reading(files, uid=0)
    assert found["root"] is True and found["notes"] == [
        "Read as root: every socket's program is read.",
        "Linux does not say when a connection began: Since is when it was first seen here."]
    rows = found["rows"]
    ssh = one(rows, "tcp", 22)  # held by the init and by sshd: the service's own process is the one named
    assert (ssh["pid"], ssh["pids"], ssh["program"], ssh["path"], ssh["service"]) == (900, [1, 900], "sshd",
                                                                                     "/usr/sbin/sshd", "ssh.service")
    assert ssh["process_started"] == BOOT + 12.0 and ssh["user"] == "root" and ssh["unread"] == {}
    session = one(rows, "tcp", 22, 60122)  # one socket, two processes: the first named, both listed
    assert (session["pid"], session["pids"], session["service"]) == (950, [950, 951], "")
    alone = one(rows, "tcp", 631)
    assert (alone["pid"], alone["pids"], alone["program"], alone["service"]) == (1, [1], "systemd", "")
    for mdns in (one(rows, "udp", 5353, family=4), one(rows, "udp", 5353, family=6)):
        assert (mdns["pid"], mdns["program"], mdns["service"], mdns["user"]) == (700, "avahi-daemon",
                                                                                 "avahi-daemon.service", "avahi")
    resolver = one(rows, "udp", 53)  # comm is 15 characters at most; the path says the rest
    assert (resolver["program"], resolver["path"], resolver["service"]) == (
        "systemd-resolve", "/usr/lib/systemd/systemd-resolved", "systemd-resolved.service")
    assert one(rows, "tcp", 8765)["program"] == "python3"  # another user's, to root: read like its own
    # not even root finds a process: another distribution's or a container's, or the kernel's own (a mount's)
    assert one(rows, "tcp", 40001, 445)["unread"] == {"program": NOT_HELD_ROOT}
    assert sockets.NOT_HELD_ROOT == NOT_HELD_ROOT
    assert one(rows, "tcp", 51001, 443)["unread"] == {"program": NO_SOCKET, "user": NO_USER}
    assert not [r for r in rows if "another user's" in str(r["unread"])]


def test_the_unit_a_process_runs_in():
    for cgroup, unit in (
            ("0::/system.slice/ssh.service\n", "ssh.service"),
            ("0::/system.slice/system-getty.slice/getty@tty1.service\n", "getty@tty1.service"),
            ("0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox.scope\n", ""),  # a scope's
            ("0::/user.slice/user-1000.slice/user@1000.service/init.scope\n", ""),
            ("0::/user.slice/user-1000.slice/session-3.scope\n", ""),
            ("0::/\n", ""), ("", ""), ("nonsense\n", ""),  # no systemd (a WSL distribution without it), no file
            ("12:pids:/system.slice/cron.service\n1:name=systemd:/system.slice/cron.service\n0::/\n", "cron.service"),
            ("5:cpu,cpuacct:/docker/abc.service\n0::/system.slice/docker-abc.scope\n", "")):  # systemd's line alone
        assert sockets._unit(cgroup) == unit, cgroup


# -- the walk, and what is kept between readings -----------------------------------------------------------------------
def test_the_walk_is_made_once_and_not_again_for_a_socket_nobody_here_holds():
    owners, files = Owners(), FakeFiles()
    reading(files, owners)
    assert files.lists.count("/proc") == 1 and owners.walks == 1 and owners.asked == 2  # python3 and firefox, once each
    assert sorted({p for p in files.reads if p.endswith("/comm")}) == ["/proc/4242/comm", "/proc/5000/comm"]
    reads, lists, linked = len(files.reads), len(files.lists), len(files.linked)
    second = reading(files, owners, at=NOW + 3)
    assert files.reads[reads:] == [f"/proc/net/{name}" for name in ("tcp", "tcp6", "udp", "udp6")]  # the tables
    # and the processes' list alone, to know that every holder is still there: no /proc/<pid>/fd again
    assert files.lists[lists:] == ["/proc"] and len(files.linked) == linked and owners.walks == 1
    assert one(second["rows"], "tcp", 8765)["program"] == "python3"
    assert one(second["rows"], "tcp", 40001, 445)["unread"] == {"program": NOT_HELD}  # kept as not found
    # another user's new socket is no reason to walk: only root could find its process
    files.files["/proc/net/udp"] += line(3, "0.0.0.0", 68, "", 0, 0x07, 0, 888, udp=True)
    walked = len(files.walked())
    reading(files, owners, at=NOW + 6)
    assert owners.walks == 1 and len(files.walked()) == walked
    # a new socket of this user's: one walk more, for it alone
    files.files["/proc/net/tcp"] += line(6, LAN, 51009, WEB, 443, 0x01, 1000, 22229)
    files.links["/proc/5000/fd/43"] = "socket:[22229]"
    lists = len(files.lists)
    third = reading(files, owners, at=NOW + 9)
    assert owners.walks == 2 and files.lists[lists:].count("/proc") == 1 and owners.asked == 3  # the list, used twice
    assert one(third["rows"], "tcp", 51009, 443)["program"] == "firefox"
    assert files.reads.count("/proc/4242/comm") == 1  # the others were not asked for again
    reading(files, owners, at=NOW + 12)
    assert owners.walks == 2
    # with every own socket known, a reading asks for nothing but the four tables and the list, whoever reads
    root_files, root_owners = FakeFiles(hidden=()), Owners()
    reading(root_files, root_owners, uid=0)
    walked = len(root_files.walked())
    assert root_owners.walks == 1 and walked > 0
    reading(root_files, root_owners, uid=0)
    assert root_owners.walks == 1 and len(root_files.walked()) == walked


def test_more_own_sockets_than_owners_kept_are_walked_for_once():
    # on Linux what is kept between readings is each socket's holders, as many as a reading has rows, not OWNERS
    inodes = range(70_001, 70_011)
    files = FakeFiles()
    files.files["/proc/net/tcp"] = connections(inodes)
    files.links.update({f"/proc/5000/fd/{60 + n}": f"socket:[{inode}]" for n, inode in enumerate(inodes)})
    owners = Owners(most=4)
    for at in (NOW, NOW + 3, NOW + 6):
        rows = reading(files, owners, at=at)["rows"]
    assert owners.walks == 1 and len(owners) == 10 + 4  # those ten and the four others of this user's
    assert {r["program"] for r in rows if r["local_port"] in range(41000, 41010)} == {"firefox"}


def test_what_closed_is_dropped_from_a_table_read_whole_whatever_another_table_did():
    # a Linux with IPv6 switched off has no tcp6 or udp6 at all: they hold nothing, so they are read whole and empty
    files = FakeFiles()
    del files.files["/proc/net/tcp6"], files.files["/proc/net/udp6"]
    found = reading(files)
    assert found["read"] == sockets.TABLES and len(found["rows"]) == 9 and len(found["notes"]) == 2
    # one there and not readable is left out of read, and said
    files.refused.add("/proc/net/udp")
    found = reading(files)
    assert found["read"] == ("tcp4", "tcp6", "udp6") and len(found["rows"]) == 6
    assert found["notes"][2:] == ["Linux's UDP (IPv4) table could not be read here (/proc/net/udp)."]
    # in both, the sockets that close are dropped reading after reading, so new ones find room and are walked for once
    for refused in ((), ("/proc/net/udp",)):
        owners, walks = Owners(most=4, rows=8), []
        files = FakeFiles(files={"/proc/stat": f"btime {BOOT}\n", "/proc/5000/comm": "firefox\n",
                                 "/proc/5000/stat": stat_line(5000, "firefox", 370000), "/proc/net/udp": UDP_HEAD},
                          links={"/proc/5000/exe": "/usr/lib/firefox/firefox"})
        files.refused.update(refused)
        for n, inodes in enumerate([(1, 2, 3, 4)] + [(5, 6, 7, 8)] * 4):
            files.files["/proc/net/tcp"] = connections(inodes)
            files.links.update({f"/proc/5000/fd/{inode}": f"socket:[{inode}]" for inode in inodes})
            seen = reading(files, owners, at=NOW + 5 * n)["rows"][0]["seen"]
            walks.append(owners.walks)
        assert walks == [1, 2, 2, 2, 2] and len(owners) == 4 and seen == NOW + 5, refused
    # a table that cannot be read in one reading drops none of its sockets: they may still be there
    owners, files = Owners(), FakeFiles()
    reading(files, owners)
    kept = len(owners)
    files.refused.add("/proc/net/tcp6")
    assert reading(files, owners)["read"] == ("tcp4", "udp4", "udp6") and len(owners) == kept
    files.refused.clear()
    assert one(reading(files, owners)["rows"], "tcp", 8080)["program"] == "python3" and owners.walks == 1


def test_none_of_the_four_files_there_is_said_and_a_header_alone_is_a_table_read_whole():
    empty = FakeFiles(files={}, links={})
    found = reading(empty)
    assert found == {"system": "linux", "at": NOW, "awake": 4321.5, "took": found["took"], "root": False,
                     "starts": False, "read": (), "cut": False, "rows": [],
                     "notes": ["This Linux lists no sockets in /proc/net."]}
    assert empty.lists == [] and empty.linked == []  # and nothing is walked for
    refused = FakeFiles(files={}, links={})
    refused.refused.update(f"/proc/net/{name}" for name in ("tcp", "tcp6", "udp", "udp6"))
    assert reading(refused)["notes"] == ["The socket tables in /proc/net could not be read here."]
    files = FakeFiles(files={"/proc/net/tcp": TCP_HEAD, "/proc/net/udp": UDP_HEAD}, links={})
    found = reading(files)
    assert found["rows"] == [] and found["read"] == sockets.TABLES and len(found["notes"]) == 2


def test_a_socket_whose_holder_has_ended_is_walked_for_again():
    # a server that forked: its child holds the listener too, then the parent ends
    files, owners = FakeFiles(), Owners()
    files.files.update({"/proc/4300/comm": "python3\n", "/proc/4300/stat": stat_line(4300, "python3", 360500),
                        "/proc/4300/cgroup": files.files["/proc/4242/cgroup"]})
    files.links.update({"/proc/4300/exe": "/usr/bin/python3.12", "/proc/4300/fd/3": "socket:[11111]"})
    first = one(reading(files, owners)["rows"], "tcp", 8765)
    assert (first["pid"], first["pids"]) == (4242, [4242, 4300])
    files.end(4242)
    second = reading(files, owners, at=NOW + 3)["rows"]
    listener = one(second, "tcp", 8765)
    assert (listener["pid"], listener["pids"], listener["process_started"]) == (4300, [4300], BOOT + 3605.0)
    assert one(second, "tcp", 8080)["unread"] == {"program": NOT_HELD}  # 4242's alone: held by nobody here now
    assert owners.walks == 2
    reading(files, owners, at=NOW + 6)  # every holder still there: nothing walked for
    assert owners.walks == 2


def test_a_socket_the_init_alone_held_is_asked_again_at_the_next_walk():
    files, owners = FakeFiles(hidden=()), Owners()
    files.files["/proc/net/tcp"] += line(6, "0.0.0.0", 631, "", 0, 0x0A, 0, 1003)
    files.links["/proc/1/fd/51"] = "socket:[1003]"  # socket activation: the init holds it until a client comes
    assert one(reading(files, owners, uid=0)["rows"], "tcp", 631)["program"] == "systemd"
    reading(files, owners, at=NOW + 3, uid=0)
    assert owners.walks == 1  # nothing new: no walk for it alone
    # a client came: the service took the socket, and its connection is a socket of its own, which is walked for
    files.files.update({"/proc/980/comm": "cupsd\n", "/proc/980/stat": stat_line(980, "cupsd", 5000),
                        "/proc/980/cgroup": "0::/system.slice/cups.service\n"})
    files.links.update({"/proc/980/exe": "/usr/sbin/cupsd", "/proc/980/fd/5": "socket:[1003]",
                        "/proc/980/fd/6": "socket:[1004]"})
    files.files["/proc/net/tcp"] += line(7, "127.0.0.1", 631, "127.0.0.1", 50600, 0x01, 0, 1004)
    rows = reading(files, owners, at=NOW + 6, uid=0)["rows"]
    listener = one(rows, "tcp", 631)
    assert (listener["program"], listener["pids"], listener["service"]) == ("cupsd", [1, 980], "cups.service")
    assert one(rows, "tcp", 631, 50600)["program"] == "cupsd" and owners.walks == 2


def test_when_a_socket_was_first_seen_is_kept_while_it_is_listed():
    owners, files = Owners(), FakeFiles()
    first = reading(files, owners, at=NOW)
    assert {r["seen"] for r in first["rows"]} == {NOW} and len(owners) == 7  # this user's seven sockets with an inode
    second = reading(files, owners, at=NOW + 5)
    assert {r["seen"] for r in second["rows"]} == {NOW}  # the row waiting to close too, by its two ends
    kept = files.files["/proc/net/tcp"]
    files.files["/proc/net/tcp"] = TCP_HEAD + line(0, "0.0.0.0", 22, "", 0, 0x0A, 0, 1001)
    third = reading(files, owners, at=NOW + 10)
    assert len(third["rows"]) == 8 and len(owners) == 4  # what closed is dropped, its owner too
    files.files["/proc/net/tcp"] = kept
    fourth = reading(files, owners, at=NOW + 15)
    assert one(fourth["rows"], "tcp", 22)["seen"] == NOW and one(fourth["rows"], "tcp", 8080)["seen"] == NOW
    for back in (one(fourth["rows"], "tcp", 8765), one(fourth["rows"], "tcp", 51001, 443)):
        assert back["seen"] == NOW + 15  # listed again: seen anew
    assert owners.walks == 2  # the walk at the first reading, and one for the sockets that came back


def test_a_connection_that_begins_to_close_keeps_when_it_was_first_seen():
    files, owners = FakeFiles(), Owners()
    assert one(reading(files, owners)["rows"], "tcp", 51000, 443)["seen"] == NOW
    # firefox closed it: the kernel lists its two ends on, with no socket (inode 0), until it has closed for good
    files.files["/proc/net/tcp"] = files.files["/proc/net/tcp"].replace(
        line(2, LAN, 51000, WEB, 443, 0x01, 1000, 22222), line(2, LAN, 51000, WEB, 443, 0x06, 0, 0, timer=3))
    for at in (NOW + 5, NOW + 10):
        closing = one(reading(files, owners, at=at)["rows"], "tcp", 51000, 443)
        assert (closing["inode"], closing["seen"]) == (0, NOW)
    # one never listed with a socket is first seen when it is first listed
    assert one(reading(FakeFiles(), Owners(), at=NOW + 15)["rows"], "tcp", 51001, 443)["seen"] == NOW + 15


def test_rows_past_the_most_are_cut_and_the_reading_says_so(monkeypatch):
    monkeypatch.setattr(sockets, "MAX_ROWS", 7)
    owners = Owners()
    found = reading(owners=owners)
    assert len(found["rows"]) == 7 and found["cut"] is True and found["read"] == ("tcp4",)
    assert found["notes"][-1] == sockets.CUT_NOTE
    kept = len(owners)
    monkeypatch.setattr(sockets, "MAX_ROWS", 2)
    found = reading(owners=owners)
    assert len(found["rows"]) == 2 and found["read"] == () and len(owners) == kept  # a cut reading drops no owner


def test_a_line_that_is_no_row_is_passed_over():
    files = FakeFiles()
    good = line(1, "127.0.0.1", 8765, "", 0, 0x0A, 1000, 11111)
    files.files["/proc/net/tcp"] = (TCP_HEAD + "   9: 0100007F:223D 00000000:0000 0A\n"  # cut short
                                    + good.replace("0100007F:223D", "0100007:223D")  # no address
                                    + good.replace(" 11111 ", " eleven ")  # no inode
                                    + good.replace(" 0A ", " ZZ ")  # no state
                                    + "\n" + good)
    for name in ("tcp6", "udp", "udp6"):
        del files.files[f"/proc/net/{name}"]
    found = reading(files)
    assert [(r["local"], r["local_port"], r["program"]) for r in found["rows"]] == [("127.0.0.1", 8765, "python3")]
    assert found["read"] == sockets.TABLES  # the three not there hold nothing
    # a state the kernel adds later is said as it is written
    files.files["/proc/net/tcp"] = TCP_HEAD + good.replace(" 0A ", " 0C ")
    files.files["/proc/net/udp"] = UDP_HEAD + line(0, "0.0.0.0", 68, "", 0, 0x02, 1000, 999, udp=True)
    assert [(r["proto"], r["state"], r["remote"]) for r in reading(files)["rows"]] == [("tcp", "0C", ""),
                                                                                       ("udp", "02", "")]


def test_read_takes_linuxs_reader_and_its_stand_ins(monkeypatch):
    found = READ("linux", files=FakeFiles(), owners=Owners(), clock=lambda: NOW, uid=1000, user_of=user_of,
                 awake=lambda: 7.0, ticks=100)
    assert (found["system"], found["at"], found["awake"], len(found["rows"])) == ("linux", NOW, 7.0, 13)
    monkeypatch.setattr(sockets.sys, "platform", "linux")
    kept = Owners()
    monkeypatch.setitem(sockets._SHARED, "linux", kept)  # with no owners given, the process's own are used
    found = READ(files=FakeFiles(), uid=1000, user_of=user_of, ticks=100, proc="/proc")
    assert found["system"] == "linux" and len(kept) == 7 and found["awake"] > 0  # the system's own clock
    # /proc elsewhere (a test's folder, a container's view): every path is under it
    files, links = proc()
    moved = FakeFiles({p.replace("/proc/", "/x/"): text for p, text in files.items()},
                      {p.replace("/proc/", "/x/"): target for p, target in links.items()}, hidden=())
    found = sockets.read_linux(moved, proc="/x", owners=Owners(), uid=1000, user_of=user_of, ticks=100)
    assert one(found["rows"], "tcp", 8765)["program"] == "python3" and all(p.startswith("/x/") for p in moved.reads)


def test_the_files_a_reading_reads_are_the_ones_the_module_names():
    files = FakeFiles(hidden=())
    reading(files, uid=0)
    asked = set()
    for path in (*files.reads, *files.lists, *files.linked):
        if path == "/proc":
            continue  # the folder itself, for its processes
        name = re.sub(r"^\d+", "<pid>", path.removeprefix("/proc/"))
        asked.add(re.sub(r"/fd/\d+$", "/fd", name))
    assert asked == set(sockets.LINUX_FILES) and len(sockets.LINUX_FILES) == 10
    assert sockets.PROC_FILES == {"tcp4": "tcp", "tcp6": "tcp6", "udp4": "udp", "udp6": "udp6"}


# -- the real files' reader, on a folder of the test's -----------------------------------------------------------------
def test_the_files_are_read_whole_lines_at_a_time_and_a_missing_one_is_empty(tmp_path, monkeypatch):
    files = sockets.ProcFiles()
    (tmp_path / "net").mkdir()
    lines = [line(n, "127.0.0.1", 8000 + n, "", 0, 0x0A, 1000, 100 + n) for n in range(6)]
    path = tmp_path / "net" / "tcp"
    path.write_bytes((TCP_HEAD + "".join(lines)).encode())
    assert REAL["read"](files, str(path)) == TCP_HEAD + "".join(lines)
    longest = line(4000, LAN6, 65535, WEB6, 65535, 0x01, 4_294_967_294, 4_294_967_295)
    assert len(longest) < 400 and sockets.ProcFiles.MOST == sockets.MAX_ROWS * 400  # room for more rows than are kept
    monkeypatch.setattr(sockets.ProcFiles, "MOST", len(TCP_HEAD) + 2 * len(lines[0]) + 40)
    assert REAL["read"](files, str(path)) == TCP_HEAD + "".join(lines[:2])  # cut after its last whole line
    # not there ("": a Linux without IPv6 has no tcp6), or there and not readable (None: a folder stands in for it)
    assert REAL["read"](files, str(tmp_path / "net" / "udp")) == ""
    assert REAL["read"](files, str(tmp_path / "net")) is None
    assert REAL["listdir"](files, str(tmp_path)) == ["net"] and REAL["listdir"](files, str(tmp_path / "none")) == []
    assert REAL["readlink"](files, str(path)) is None and REAL["readlink"](files, str(tmp_path / "none")) is None
    try:
        os.symlink("socket:[11111]", tmp_path / "3")
    except (OSError, NotImplementedError):
        return  # this account may make no links here (Windows without the right)
    assert REAL["readlink"](files, str(tmp_path / "3")).endswith("socket:[11111]")
