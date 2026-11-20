"""The socket table with the program behind each socket, for the firewalls' Netstat tab and their hosts database (the
user, 2026-11-16: "the firewall app should have a 'netstat' like interface for looking at active ports and what apps
they are attached to, and the hosts that they connect to across the lan or wan. the firewall app should also have a
globe that can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they are
connected to *this *computer"; and of that globe: "so i can view apps connected to hosts all across the globe, or ports
talking to all hosts").

A reading (`read`) is this system's own socket table, asked of the system itself. Nothing is captured, no administrator
and no password is asked, no process is started, no window opens, no name is looked up and nothing is sent anywhere.

    {"system": "windows" | "linux" | "", "at": seconds since 1970, "awake": seconds on a clock that leaves sleep out,
     "took": seconds, "root": bool, "starts": bool (the system says when a socket began), "read": the tables read
     whole, of TABLES, "cut": bool (rows were left out past MAX_ROWS), "rows": [row], "notes": [words]}

A row is one socket (a row's table is its `proto` and `family`: "tcp4" is tcp, 4):

    {"proto": "tcp" | "udp", "family": 4 | 6, "state", "local", "local_port", "remote" ("" when it has none),
     "remote_port", "pid" (0: none known), "pids", "program", "path", "service", "service_title", "user" ("" where
     the system keeps none), "started" (seconds since 1970, or None), "process_started", "count" (equal rows folded
     into one), "inode" (Linux: the socket's own number, 0 where it has none; Windows: always 0), "seen" (the
     socket's start where the system says it, else when a reading first listed it, or the connection it was before
     it began to close), "unread": {key: why}}

Addresses are written without brackets, and an IPv4 address written as IPv6 (::ffff:a.b.c.d) is said as IPv4; the
family stays the table's. What a row could not read is said in `unread`, in words, under the key it is missing
("program", "path", "service", "user"): never guessed.

- Windows (`read_windows`, through a `WindowsApi`): the four tables of GetExtendedTcpTable and GetExtendedUdpTable in
  their OWNER_MODULE class, which give every socket its process, its start and its service's tag, to any account. A
  program's name comes from one snapshot of the processes; where it is on disk and which service is behind a socket
  are asked once for each owner (`Owners`) with documented calls alone, so the path of a service's or of Windows' own
  process is said as not readable. Windows lists no remote host for a UDP socket.
- Linux (`read_linux`, through `ProcFiles`): /proc/net/tcp, tcp6, udp and udp6 list every socket with its user, where
  the kernel keeps one. The program behind one is found through /proc/<pid>/fd, which an account may read for its own
  processes alone (root for all): one walk a reading, and only while a socket is new or its holder has ended. Linux
  does not say when a socket began.

`judge` then says of each row where its remote host is (this machine, the local network or the internet), which way
the connection goes, which port is the service's, the place of an internet host (from a lookup the caller gives: none
is made here) and its name where the system's own hosts file has one (`known_names`). `under_wsl` is the tab's table of
what running inside a WSL distribution changes.

Bounds: MAX_ROWS rows a reading. Between readings (`Owners`): OWNERS owners on Windows, and on Linux the holders of
MAX_ROWS sockets; when each of MAX_ROWS sockets was first listed. What a reading did not list from a table it read
whole is dropped, and when full, what was listed longest ago makes room. NAMES names of HOSTS_BYTES of the hosts file.
The module imports on Windows and on Linux alike: the system's libraries are loaded at the first reading, and a test
stands in for them (`WindowsApi`'s methods, `ProcFiles`' three)."""
from __future__ import annotations

import collections
import ctypes
import functools
import ipaddress
import os
import socket
import struct
import sys
import threading
import time

from . import netpath, ports
from .resources import LINUX_TCP_STATES, TCP_STATES, _hex_address

READ_S = 2.5  # a reading younger than this is shared by everyone who asks (the Netstat tab, the hosts database)
MAX_ROWS = 20_000  # rows in one reading; what is past it is left out, and the reading says `cut`
OWNERS = 2048  # owners kept between two readings (Windows)
NAMES = 4096  # names taken from the hosts file
WHERE = ("this machine", "local network", "internet")
UP = frozenset({"established", "close-wait", "fin-wait-1", "fin-wait-2", "closing", "last-ack"})  # a TCP connection up
TABLES = ("tcp4", "tcp6", "udp4", "udp6")
TABLE_WORDS = {"tcp4": "TCP (IPv4)", "tcp6": "TCP (IPv6)", "udp4": "UDP (IPv4)", "udp6": "UDP (IPv6)"}
LISTENS = ("listening", "bound")  # a socket with no remote that others reach: TCP listening, UDP bound
EVERY_ADDRESS = frozenset({"0.0.0.0", "::"})  # a listener's local address for every address of its table's family
HOSTS_BYTES = 1 << 20  # of the hosts file, read at most
NAME_CHARS = 253  # of a name in it (a host name's most)
LOCALHOST = ("localhost", "ip6-localhost", "ip6-loopback")  # the names of this machine a hosts file gives

# what a row could not read, in words (its `unread`)
GONE = "its owner has ended: the connection is only waiting to close"
NO_OWNER = "Windows names no process for it"
SYSTEM = "Windows itself holds it (pid 4) for a driver or a service: the table does not say which"
SYSTEM_PATH = "Windows' own kernel process: no program file is named for it"
REFUSED = "Windows does not let this account read where this program is on disk (a service's or Windows' own process)"
NO_SOCKET = "the kernel lists no socket for it (closing, or not open yet)"
NO_USER = "the kernel keeps no user for it (closing, or not open yet)"
NOT_HELD = ("no process this account may look into holds it: another WSL distribution's or a container's, or a "
            "program of yours that does not let itself be looked into")
NOT_HELD_ROOT = "no process here holds it: another WSL distribution's or a container's, or the kernel's own"
NO_PATH = "Linux did not say where this program is on disk"
# a reading's notes
UDP_NOTE = "Windows lists no remote host for a UDP socket: UDP shows as ports only."
NO_PROCESSES_NOTE = ("Windows' list of processes could not be read: a program is named from where it is on disk, "
                     "where that is read.")
NO_PROC_NOTE = "This Linux lists no sockets in /proc/net."
NO_PROC_READ_NOTE = "The socket tables in /proc/net could not be read here."
ROOT_NOTE = "Read as root: every socket's program is read."
NO_START_NOTE = "Linux does not say when a connection began: Since is when it was first seen here."
CUT_NOTE = f"More than {MAX_ROWS:,} sockets are listed: the first {MAX_ROWS:,} are read and the rest left out."

# -- Windows: the tables as iphlpapi writes them -----------------------------------------------------------------------
AF_INET, AF_INET6 = 2, 23  # Windows' own numbers
TCP_OWNER_MODULE_ALL, UDP_OWNER_MODULE = 8, 2  # TCP_TABLE_OWNER_MODULE_ALL, UDP_TABLE_OWNER_MODULE
OWNING = 16  # TCPIP_OWNING_MODULE_SIZE
ROWS_AT = 8  # a table: a DWORD saying how many rows, then the rows at their own alignment (8 in these classes)
SIZES = {"tcp4": 160, "tcp6": 192, "udp4": 160, "udp6": 176}  # a row's bytes, as Windows lays it out
SLACK = 8192  # room for the rows that come between asking a table's size and reading it
MAX_TABLE = 16 << 20  # bytes of one table: a larger one is not read (four times MAX_ROWS of the widest rows)
SERVICES_MOST = 8 << 20  # bytes of the services' listing, at most
MODULE_MOST = 1 << 20  # bytes of an owner module's answer, at most
PATH_CHARS = 32768  # a path's most, in characters
FILETIME_EPOCH = 11644473600  # seconds from 1601 to 1970
SYSTEM_PID = 4
QUERY_LIMITED = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
SC_CONNECT, SC_ENUMERATE = 0x0001, 0x0004  # SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE
WIN32_SERVICES, ACTIVE = 0x30, 1  # SERVICE_WIN32, SERVICE_ACTIVE
ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE, ERROR_INSUFFICIENT_BUFFER = 5, 31, 122
ERROR_MOD_NOT_FOUND, ERROR_MORE_DATA = 126, 234
BAD_LAYOUT, TOO_LARGE = -1, -2  # table()'s own answers (Windows' errors are above 0): rows not as laid out; too big
OWNER_CALLS = {"tcp4": "GetOwnerModuleFromTcpEntry", "tcp6": "GetOwnerModuleFromTcp6Entry",
               "udp4": "GetOwnerModuleFromUdpEntry", "udp6": "GetOwnerModuleFromUdp6Entry"}
# every call a Windows reading makes, all documented (the firewall plugin's card names them): iphlpapi's, kernel32's
# (the snapshot's three are resources.WindowsProbe's), advapi32's and shell32's
WINDOWS_CALLS = ("GetExtendedTcpTable", "GetExtendedUdpTable", *OWNER_CALLS.values(), "CreateToolhelp32Snapshot",
                 "Process32FirstW", "Process32NextW", "OpenProcess", "QueryFullProcessImageNameW", "GetProcessTimes",
                 "CloseHandle", "QueryUnbiasedInterruptTime", "OpenSCManagerW", "EnumServicesStatusExW",
                 "CloseServiceHandle", "IsUserAnAdmin")
# every file a Linux reading reads, under /proc (the firewall plugin's card names them)
LINUX_FILES = ("net/tcp", "net/tcp6", "net/udp", "net/udp6", "<pid>/fd", "<pid>/comm", "<pid>/exe", "<pid>/cgroup",
               "<pid>/stat", "stat")
PROC_FILES = {"tcp4": "tcp", "tcp6": "tcp6", "udp4": "udp", "udp6": "udp6"}  # a table's file in /proc/net
UDP_STATES = {1: "connected", 7: "bound"}  # /proc/net/udp's st: a socket connected to a peer, one with none
TIME_WAIT_TIMER = "03"  # /proc/net/tcp's tr for a TIME_WAIT minisock, which keeps no owner (proc_net_tcp.rst)

U8, U32, U64, I64 = ctypes.c_uint8, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_int64
# The rows are laid out with fixed-width types and their padding written out, so they are the same bytes on every
# system (a DWORD is not ctypes.wintypes' off Windows), and a test checks each size and offset on Linux too.


class Tcp4Row(ctypes.LittleEndianStructure):  # MIB_TCPROW_OWNER_MODULE
    _fields_ = [("state", U32), ("local", U32), ("local_port", U32), ("remote", U32), ("remote_port", U32),
                ("pid", U32), ("created", I64), ("owning", U64 * OWNING)]


class Tcp6Row(ctypes.LittleEndianStructure):  # MIB_TCP6ROW_OWNER_MODULE
    _fields_ = [("local", U8 * 16), ("local_scope", U32), ("local_port", U32), ("remote", U8 * 16),
                ("remote_scope", U32), ("remote_port", U32), ("state", U32), ("pid", U32), ("created", I64),
                ("owning", U64 * OWNING)]


class Udp4Row(ctypes.LittleEndianStructure):  # MIB_UDPROW_OWNER_MODULE
    _fields_ = [("local", U32), ("local_port", U32), ("pid", U32), ("_pad", U32), ("created", I64), ("flags", U32),
                ("_pad2", U32), ("owning", U64 * OWNING)]


class Udp6Row(ctypes.LittleEndianStructure):  # MIB_UDP6ROW_OWNER_MODULE
    _fields_ = [("local", U8 * 16), ("local_scope", U32), ("local_port", U32), ("pid", U32), ("_pad", U32),
                ("created", I64), ("flags", U32), ("_pad2", U32), ("owning", U64 * OWNING)]


LAYOUTS = {"tcp4": Tcp4Row, "tcp6": Tcp6Row, "udp4": Udp4Row, "udp6": Udp6Row}


class _Module(ctypes.Structure):  # TCPIP_OWNER_MODULE_BASIC_INFO: two strings inside the buffer it comes in
    _fields_ = [("name", ctypes.c_wchar_p), ("path", ctypes.c_wchar_p)]


class _Service(ctypes.Structure):  # ENUM_SERVICE_STATUS_PROCESSW: two names, then SERVICE_STATUS_PROCESS' nine DWORDs
    _fields_ = [("name", ctypes.c_wchar_p), ("title", ctypes.c_wchar_p), ("type", U32), ("state", U32),
                ("controls", U32), ("exit", U32), ("specific", U32), ("checkpoint", U32), ("wait", U32), ("pid", U32),
                ("flags", U32)]


def _port(value: int) -> int:
    """A port as Windows' tables hold it: in network byte order in the low 16 bits (socket.ntohs(value & 0xFFFF))."""
    return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)


def _four(value: int) -> str:
    """An IPv4 address as Windows' tables hold it: a DWORD whose bytes are the address in order."""
    return socket.inet_ntoa(struct.pack("<I", value))


@functools.lru_cache(maxsize=4096)
def _six(raw: bytes) -> str:
    """An IPv6 address from its 16 bytes; an IPv4 address written as IPv6 is said as IPv4."""
    ip = ipaddress.IPv6Address(raw)
    return str(ip.ipv4_mapped or ip)


@functools.lru_cache(maxsize=4096)
def _address(text: str) -> str:
    """An address as the rows say it: no brackets, no zone, an IPv4 address written as IPv6 as IPv4; "" for what is
    no address."""
    try:
        ip = ipaddress.ip_address(str(text).strip().strip("[]").split("%")[0])
    except ValueError:
        return ""
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def _epoch(filetime: int) -> float | None:
    """A FILETIME (100 ns since 1601) as seconds since 1970; None for 0, which is Windows' word for not known."""
    return filetime / 1e7 - FILETIME_EPOCH if filetime else None


def decode(name: str, data, most: int | None = None) -> list[dict]:
    """The rows of one of Windows' four tables (`name`, of TABLES) from the bytes its call wrote: `most` of them at
    most. Each is {"state", "local", "local_port", "remote", "remote_port", "pid", "created" (the socket's start as
    Windows gives it, a FILETIME; 0 when it gives none), "tag" (its service's tag, the low 32 bits of
    OwningModuleInfo[0]; 0 for a program's own socket), "raw" (the row itself, for WindowsApi.owner)}. A TCP listener
    has no remote ("" and 0); a UDP row is "bound" and never has one. ValueError when the bytes cannot hold the rows
    they say they hold: nothing of such a table is believed."""
    layout = LAYOUTS[name]
    size, tcp, v6 = ctypes.sizeof(layout), name.startswith("tcp"), name.endswith("6")
    if len(data) < 4:
        raise ValueError(f"{len(data)} bytes are no table")
    count = struct.unpack_from("<I", data, 0)[0]
    if count and ROWS_AT + count * size > len(data):
        raise ValueError(f"{len(data)} bytes cannot hold the {count} rows of {size} bytes they say they hold")
    out = []
    for i in range(count if most is None else min(count, most)):
        r = layout.from_buffer_copy(data, ROWS_AT + i * size)
        row = {"state": "bound", "local": _six(bytes(r.local)) if v6 else _four(r.local),
               "local_port": _port(r.local_port), "remote": "", "remote_port": 0, "pid": int(r.pid),
               "created": int(r.created), "tag": int(r.owning[0]) & 0xFFFFFFFF, "raw": r}
        if tcp:
            row["state"] = TCP_STATES.get(r.state, str(r.state))
            remote, remote_port = (_six(bytes(r.remote)) if v6 else _four(r.remote)), _port(r.remote_port)
            if row["state"] != "listening" and (remote_port or remote not in ports.EVERY):
                row["remote"], row["remote_port"] = remote, remote_port
        out.append(row)
    return out


class WindowsApi:
    """Windows' own calls behind a reading, each library loaded at its first use (so this module imports anywhere). A
    test gives a stand-in with these methods: table, names, image, owner, services, and awake and elevated (a
    stand-in without the last two is read with the process's own clock, as not an administrator)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._libraries: dict[str, object] = {}
        self._probe = None

    def _library(self, name: str):
        """One of Windows' libraries, loaded once, its calls given their arguments' types."""
        with self._lock:
            if name not in self._libraries:
                library = ctypes.WinDLL(name, use_last_error=True)
                _PROTOTYPES[name](library)
                self._libraries[name] = library
            return self._libraries[name]

    def table(self, name: str) -> tuple[int, list[dict]]:
        """(status, rows) of one table (`name`, of TABLES), as `decode` reads them: the size is asked first, and the
        table read up to three times, for it can grow in between. Status 0, Windows' own error, BAD_LAYOUT (a row is
        not the size Windows documents here, or the rows do not fit their bytes: none is believed) or TOO_LARGE. One
        row more than a reading keeps is handed over at most, so the reading knows that it was not handed all."""
        if ctypes.sizeof(LAYOUTS[name]) != SIZES[name]:
            return BAD_LAYOUT, []
        try:
            library = self._library("iphlpapi")
            tcp = name.startswith("tcp")
            call = library.GetExtendedTcpTable if tcp else library.GetExtendedUdpTable
            family = AF_INET6 if name.endswith("6") else AF_INET
            kind = TCP_OWNER_MODULE_ALL if tcp else UDP_OWNER_MODULE
            size, buf = U32(0), None
            status = call(None, ctypes.byref(size), 0, family, kind, 0)
            for _ in range(3):
                if status != ERROR_INSUFFICIENT_BUFFER:
                    break
                if size.value > MAX_TABLE:
                    return TOO_LARGE, []
                buf = ctypes.create_string_buffer(size.value + SLACK)
                size = U32(len(buf))
                status = call(buf, ctypes.byref(size), 0, family, kind, 0)
        except (OSError, AttributeError) as e:  # no such library or call here
            return getattr(e, "winerror", None) or ERROR_MOD_NOT_FOUND, []
        if status != 0 or buf is None:
            return int(status), []
        try:
            return 0, decode(name, buf, MAX_ROWS + 1)
        except ValueError:
            return BAD_LAYOUT, []

    def names(self) -> dict[int, str]:
        """Every process's program (its executable's file name) by pid: one snapshot of the processes, for which no
        rights are needed (resources.WindowsProbe's)."""
        if self._probe is None:
            from .resources import WindowsProbe

            self._probe = WindowsProbe()
        return self._probe.program_names()

    def image(self, pid: int) -> tuple[str, float | None, int]:
        """(where process `pid`'s program is on disk, when the process started, the error) through a handle that asks
        for PROCESS_QUERY_LIMITED_INFORMATION alone: QueryFullProcessImageNameW and GetProcessTimes. A service's
        process and Windows' own refuse the handle to an ordinary account (error 5): "", None and the error."""
        try:
            k32 = self._library("kernel32")
        except (OSError, AttributeError) as e:
            return "", None, getattr(e, "winerror", None) or ERROR_MOD_NOT_FOUND
        handle = k32.OpenProcess(QUERY_LIMITED, 0, int(pid))
        if not handle:
            return "", None, ctypes.get_last_error() or ERROR_GEN_FAILURE
        try:
            buf, size = ctypes.create_unicode_buffer(PATH_CHARS), U32(PATH_CHARS)
            ok = k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
            error = 0 if ok else (ctypes.get_last_error() or ERROR_GEN_FAILURE)
            times = (U64 * 4)()  # creation, exit, kernel, user: four FILETIMEs
            started = None
            if k32.GetProcessTimes(handle, *(ctypes.byref(times, 8 * i) for i in range(4))):
                started = _epoch(int(times[0]))
            return (buf.value if ok else ""), started, error
        finally:
            k32.CloseHandle(handle)

    def owner(self, name: str, raw) -> tuple[int, str, str]:
        """(status, module name, module path) of one row as its table gave it (`raw`), from
        GetOwnerModuleFromTcpEntry or its sibling for the table: a program's file name and where it is on disk; for a
        row with a service's tag, the service's short name in both. Error 5 where the process cannot be opened."""
        try:
            call = getattr(self._library("iphlpapi"), OWNER_CALLS[name])
        except (OSError, AttributeError) as e:
            return getattr(e, "winerror", None) or ERROR_MOD_NOT_FOUND, "", ""
        size = U32(0)
        status = call(ctypes.byref(raw), 0, None, ctypes.byref(size))  # 0: TCPIP_OWNER_MODULE_INFO_BASIC
        if status != ERROR_INSUFFICIENT_BUFFER or not ctypes.sizeof(_Module) <= size.value <= MODULE_MOST:
            return int(status), "", ""
        buf = ctypes.create_string_buffer(size.value)
        status = call(ctypes.byref(raw), 0, buf, ctypes.byref(size))
        if status != 0:
            return int(status), "", ""
        info = _Module.from_buffer(buf)
        return 0, info.name or "", info.path or ""

    def services(self) -> tuple[dict[int, list[tuple[str, str]]], int]:
        """({pid: [(a service's short name, its display name)]} of the running services, the error when they cannot
        be listed): EnumServicesStatusExW, which the service manager answers to an interactive user."""
        try:
            adv = self._library("advapi32")
        except (OSError, AttributeError) as e:
            return {}, getattr(e, "winerror", None) or ERROR_MOD_NOT_FOUND
        manager = adv.OpenSCManagerW(None, None, SC_CONNECT | SC_ENUMERATE)
        if not manager:
            return {}, ctypes.get_last_error() or ERROR_GEN_FAILURE
        try:
            need, count, resume = U32(0), U32(0), U32(0)
            asked = (ctypes.byref(need), ctypes.byref(count), ctypes.byref(resume), None)
            if adv.EnumServicesStatusExW(manager, 0, WIN32_SERVICES, ACTIVE, None, 0, *asked):
                return {}, 0  # nothing runs
            error = ctypes.get_last_error()
            if error != ERROR_MORE_DATA or need.value > SERVICES_MOST:
                return {}, error or ERROR_GEN_FAILURE
            buf = ctypes.create_string_buffer(need.value + 65536)  # room for a service started in between
            resume.value = 0
            if not adv.EnumServicesStatusExW(manager, 0, WIN32_SERVICES, ACTIVE, buf, len(buf), *asked):
                return {}, ctypes.get_last_error() or ERROR_GEN_FAILURE
            found: dict[int, list[tuple[str, str]]] = {}
            for entry in (_Service * count.value).from_buffer(buf):
                found.setdefault(int(entry.pid), []).append((entry.name or "", entry.title or ""))
            return found, 0
        finally:
            adv.CloseServiceHandle(manager)

    def awake(self) -> float:
        """Seconds this system has been awake since it started: QueryUnbiasedInterruptTime, which leaves out the time
        it slept, so the time a connection was up is not counted through a night's sleep."""
        try:
            value = U64(0)
            if self._library("kernel32").QueryUnbiasedInterruptTime(ctypes.byref(value)):
                return value.value / 1e7
        except (OSError, AttributeError):
            pass
        return time.monotonic()

    def elevated(self) -> bool:
        """Whether this process runs as an administrator, as shell32's IsUserAnAdmin says (said in a reading's notes;
        the tables and the programs' names are read either way); not one where there is no shell32."""
        try:
            shell = self._library("shell32")
            return bool(shell.IsUserAnAdmin())
        except (OSError, AttributeError):
            return False


def _iphlpapi(library) -> None:
    for call in (library.GetExtendedTcpTable, library.GetExtendedUdpTable):
        call.argtypes = [ctypes.c_void_p, ctypes.POINTER(U32), ctypes.c_int, U32, ctypes.c_int, U32]
        call.restype = U32
    for name in OWNER_CALLS.values():
        call = getattr(library, name, None)
        if call is not None:
            call.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(U32)]
            call.restype = U32


def _kernel32(library) -> None:
    library.OpenProcess.argtypes = [U32, ctypes.c_int, U32]
    library.OpenProcess.restype = ctypes.c_void_p
    library.CloseHandle.argtypes = [ctypes.c_void_p]
    library.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, U32, ctypes.c_wchar_p, ctypes.POINTER(U32)]
    library.QueryFullProcessImageNameW.restype = ctypes.c_int
    library.GetProcessTimes.argtypes = [ctypes.c_void_p] * 5
    library.GetProcessTimes.restype = ctypes.c_int
    library.QueryUnbiasedInterruptTime.argtypes = [ctypes.POINTER(U64)]
    library.QueryUnbiasedInterruptTime.restype = ctypes.c_int


def _advapi32(library) -> None:
    library.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, U32]
    library.OpenSCManagerW.restype = ctypes.c_void_p
    library.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    library.EnumServicesStatusExW.argtypes = [ctypes.c_void_p, ctypes.c_int, U32, U32, ctypes.c_void_p, U32,
                                              ctypes.POINTER(U32), ctypes.POINTER(U32), ctypes.POINTER(U32),
                                              ctypes.c_wchar_p]
    library.EnumServicesStatusExW.restype = ctypes.c_int


def _shell32(library) -> None:
    library.IsUserAnAdmin.argtypes = []
    library.IsUserAnAdmin.restype = ctypes.c_int


_PROTOTYPES = {"iphlpapi": _iphlpapi, "kernel32": _kernel32, "advapi32": _advapi32, "shell32": _shell32}


# -- Linux: /proc's files ----------------------------------------------------------------------------------------------
class ProcFiles:
    """/proc's files as a Linux reading asks for them. A test stands in for them with these three methods (as
    resources.LinuxProbe's _read, _listdir and _readlink)."""
    MOST = MAX_ROWS * 400  # bytes read of one file: more than MAX_ROWS of /proc/net's lines, each well under 400

    def read(self, path: str) -> str | None:
        """A file's text, MOST bytes of it at most (cut after its last whole line): "" when it is not there (a Linux
        with IPv6 switched off has no /proc/net/tcp6), None when it is there and cannot be read."""
        try:
            with open(path, "rb") as f:
                data = f.read(self.MOST + 1)
        except FileNotFoundError:
            return ""
        except OSError:
            return None
        if len(data) > self.MOST:
            data = data[:data.rfind(b"\n", 0, self.MOST) + 1]
        return data.decode("utf-8", "replace")

    def listdir(self, path: str) -> list[str]:
        """A folder's names; [] when it cannot be listed (another user's /proc/<pid>/fd)."""
        try:
            return os.listdir(path)
        except OSError:
            return []

    def readlink(self, path: str) -> str | None:
        """Where a link points ("socket:[11111]" for a socket's descriptor); None when it cannot be read."""
        try:
            return os.readlink(path)
        except OSError:
            return None


# -- what is kept between readings -------------------------------------------------------------------------------------
_SETS: dict[frozenset, frozenset] = {}  # one frozenset for each set of tables a key was listed in (16 of TABLES')
_EMPTY = frozenset()


def _tables_set(tables) -> frozenset:
    found = frozenset(tables)
    return _SETS.setdefault(found, found)


class _Kept:
    """Keys a reading keeps for the next ones, `most` of them at most, each with the tables it was listed in. A key a
    reading did not list is dropped when every table it was last listed in was read whole: it is gone. One whose
    table was not read whole (it failed, or its rows were cut) stays, for it may still be there. When full, the key
    listed longest ago makes room for a new one, unless this reading listed it too: the new one is then not kept."""

    def __init__(self, most: int) -> None:
        self.most = most
        self._values: collections.OrderedDict = collections.OrderedDict()  # the one listed longest ago first
        self._tables: dict = {}  # each key's tables, as the readings that listed it found it
        self._listed: dict = {}  # this reading's keys, each with the tables it was listed in

    def __len__(self) -> int:
        return len(self._values)

    def get(self, key, table: str):
        """What is kept for `key`, or None; a key kept counts as listed by this reading in `table`."""
        if key not in self._values:
            return None
        self._list(key, table)
        return self._values[key]

    def put(self, key, value, table: str) -> bool:
        """Keep `value` for `key`, listed by this reading in `table`; False when there is no room for it."""
        if key not in self._values and len(self._values) >= self.most:
            oldest = next(iter(self._values), None)
            if oldest is None or oldest in self._listed:
                return False  # every key kept was listed by this reading
            del self._values[oldest]
            self._tables.pop(oldest, None)
        self._values[key] = value
        self._list(key, table)
        return True

    def _list(self, key, table: str) -> None:
        self._values.move_to_end(key)
        listed = self._listed.get(key, _EMPTY)
        if table not in listed:
            self._listed[key] = _tables_set((*listed, table))

    def begin(self) -> None:
        """A reading begins: nothing is listed yet (what a reading that failed half way listed does not count)."""
        self._listed = {}

    def settle(self, whole) -> None:
        """A reading is over, which read the tables `whole` whole: what it did not list of those is gone."""
        whole = frozenset(whole)
        for key in [k for k in self._values if k not in self._listed]:
            if self._tables.get(key, _EMPTY) <= whole:
                del self._values[key]
                self._tables.pop(key, None)
        for key, tables in self._listed.items():
            if key in self._values:  # a table this reading did not read whole may still hold it, as before
                before = self._tables.get(key, _EMPTY) - whole
                self._tables[key] = _tables_set(tables | before) if before else tables
        self._listed = {}


class Owners:
    """What readings keep for the next ones, so a reading asks only for what it has not seen. On Windows the owners,
    by (pid, name, tag), OWNERS at most, each with when it was asked. On Linux the holders of each socket, by its
    inode, `rows` (MAX_ROWS) at most: one found to have none is kept too, as not found, so /proc/<pid>/fd is not walked
    for it again. And when each socket whose system gives it no start was first listed, `rows` at most, with the
    connections of the last reading, so one that begins to close keeps its time. After a reading, what it did not
    list from a table it read whole is dropped; when full, what was listed longest ago makes room. One reading at a
    time holds `lock`."""

    def __init__(self, most: int = OWNERS, rows: int = MAX_ROWS) -> None:
        self.lock = threading.RLock()
        self.most, self.rows = most, rows
        self.asked = 0  # owners asked of the system so far (Linux: processes)
        self.walks = 0  # walks of /proc/<pid>/fd so far (Linux)
        self._owners = _Kept(most)
        self._held = _Kept(rows)
        self._seen = _Kept(rows)
        self._ends: dict = {}  # the last reading's connections: (table, their two ends) -> when each was first seen
        self._ends_now: dict = {}  # this reading's

    def __len__(self) -> int:
        return len(self._owners) + len(self._held)

    def begin(self) -> None:
        """A reading begins."""
        with self.lock:
            for kept in (self._owners, self._held, self._seen):
                kept.begin()
            self._ends_now = {}

    def get(self, key, table: str):
        """What was kept of the owner `key` (Windows: its facts and when they were asked), or None: it is to be
        asked. It counts as listed by this reading in `table`."""
        with self.lock:
            return self._owners.get(key, table)

    def put(self, key, kept, table: str) -> None:
        """Keep what was asked of the owner `key`; with no room for it, it is asked again at the next reading."""
        with self.lock:
            self._owners.put(key, kept, table)

    def held(self, inode: int, table: str):
        """Who held the socket `inode` when it was last walked for (Linux), or None: it is to be walked for."""
        with self.lock:
            return self._held.get(inode, table)

    def hold(self, inode: int, holders, table: str) -> None:
        """Keep who holds the socket `inode` (Linux)."""
        with self.lock:
            self._held.put(inode, holders, table)

    def first(self, key, at: float, table: str, ends: tuple | None = None) -> float:
        """When the socket `key` of `table` was first listed: `at` the first time it is asked, that time from then
        on. `ends`, for a connection with no identity of its own (a start, an inode) any more, as one that begins to
        close: the time of the connection the last reading listed with those two ends, where it listed one."""
        with self.lock:
            seen = self._seen.get(key, table)
            if seen is None:
                seen = self._ends.get((table, ends), at) if ends else at
                self._seen.put(key, seen, table)
            return seen

    def connected(self, table: str, ends: tuple, seen: float) -> None:
        """A connection of `table` with an identity of its own was listed, first seen at `seen`: the next reading
        knows its time should it list those two ends without one."""
        with self.lock:
            if len(self._ends_now) < self.rows:
                self._ends_now[(table, ends)] = seen

    def settle(self, whole=TABLES) -> None:
        """A reading is over, which read the tables `whole` whole: what it did not list of those is dropped (an
        owner whose sockets are gone, a socket that closed); what it listed is kept for the next."""
        with self.lock:
            for kept in (self._owners, self._held, self._seen):
                kept.settle(whole)
            self._ends, self._ends_now = self._ends_now, {}


_SHARED: dict[str, object] = {}  # the process's own WindowsApi and its Owners for each system, made at first use
_SHARED_LOCK = threading.Lock()


def _shared(name: str, make):
    with _SHARED_LOCK:
        if name not in _SHARED:
            _SHARED[name] = make()
        return _SHARED[name]


# -- a reading ---------------------------------------------------------------------------------------------------------
def _system(name: str | None = None) -> str:
    """"windows", "linux" or "" for a system's name (sys.platform's own word, or one of the two); this one's
    without a name."""
    name = (sys.platform if name is None else str(name)).lower()
    if name in ("windows", "win32"):
        return "windows"
    return "linux" if name.startswith("linux") else ""


def read(system: str | None = None, *, owners: Owners | None = None, clock=time.time, **outside) -> dict:
    """This system's socket table as a reading (the module's docstring has its shape): Windows' through
    `read_windows`, Linux's through `read_linux`; `outside` is handed to that reader (a test's stand-ins). On any
    other system no rows, and a note saying that none is read there. `owners`: what is kept between readings (the
    process's own when none is given); `clock`: the time of day."""
    kind = _system(system)
    if kind == "windows":
        return read_windows(owners=owners, clock=clock, **outside)
    if kind == "linux":
        return read_linux(owners=owners, clock=clock, **outside)
    name = sys.platform if system is None else str(system)
    name = {"darwin": "macOS", "cygwin": "Cygwin"}.get(name.lower(), name)
    return {"system": "", "at": clock(), "awake": time.monotonic(), "took": 0.0, "root": False, "starts": False,
            "read": (), "cut": False, "rows": [], "notes": [f"No socket table is read on {name}."]}


def _row(proto: str, family: int, state: str, local: str, local_port: int, remote: str, remote_port: int) -> dict:
    """A row with nothing known of its owner yet."""
    return {"proto": proto, "family": family, "state": state, "local": local, "local_port": local_port,
            "remote": remote, "remote_port": remote_port, "pid": 0, "pids": [], "program": "", "path": "",
            "service": "", "service_title": "", "user": "", "started": None, "process_started": None, "count": 1,
            "inode": 0, "seen": None, "unread": {}}


def _ends(row: dict) -> tuple:
    return row["proto"], row["local"], row["local_port"], row["remote"], row["remote_port"]


def _table(row: dict) -> str:
    """A row's table, of TABLES: its protocol and its family."""
    return f"{row['proto']}{row['family']}"


def _status_words(status: int) -> str:
    if status == BAD_LAYOUT:
        return "its rows are not laid out as this reader expects"
    if status == TOO_LARGE:
        return f"it is larger than the {MAX_TABLE >> 20} MB a reading takes"
    return f"error {status}"


def _is_path(text: str) -> bool:
    return "\\" in text or "/" in text


def _several(found: list[tuple[str, str]]) -> str:
    """The words for a socket of a process that hosts several services, none of them tagged on the row."""
    names = sorted(name for name, _title in found)
    listed = ", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else "")
    return f"one of the {len(names)} services of this process ({listed}): the table does not say which"


class _WindowsOwners:
    """One Windows reading's asks for the program and the service behind a row: each owner asked once and kept, with
    when that was (`at`). Windows gives a pid that is free again to the next process, which may be the same program:
    so a socket an owner made since it was asked has its process's start asked again, and a start that differs is a
    new process's, asked for anew."""

    def __init__(self, api, owners: Owners, names: dict[int, str], services: dict[int, list[tuple[str, str]]],
                 at: float):
        self.api, self.owners, self.names, self.services, self.at = api, owners, names, services, at
        self.titles = {name.lower(): title for found in services.values() for name, title in found}
        self.mine: dict[tuple, dict] = {}  # this reading's answers, by owner: none is asked twice

    def of(self, table: str, r: dict) -> dict:
        """{"program", "path", "service", "service_title", "process_started", "unread"} for one row of a table."""
        pid, tag = r["pid"], r["tag"]
        if pid == 0:  # the table keeps both ends of a connection until it has closed for good; its owner is gone
            return {"unread": {"program": GONE if r["remote"] else NO_OWNER}}
        if pid == SYSTEM_PID:
            return {"program": self.names.get(pid) or "System", "unread": {"service": SYSTEM, "path": SYSTEM_PATH}}
        program = self.names.get(pid, "")
        key = (pid, program, tag)
        kept = self.owners.get(key, table)  # listed by this reading in this table, where it is kept
        if key in self.mine:
            return self.mine[key]
        image = None
        if kept is not None:
            facts, since = kept
            made = _epoch(r["created"])
            if facts["process_started"] is None or made is None or made <= since:
                self.mine[key] = facts  # an older socket: the process that held it then holds it now
                return facts
            image = self.api.image(pid)  # a socket made since: the pid may be another process's now
            if image[1] == facts["process_started"]:
                self.mine[key] = facts
                self.owners.put(key, (facts, self.at), table)
                return facts
        facts = self.mine[key] = self._ask(table, r, pid, program, tag, image)
        self.owners.put(key, (facts, self.at), table)
        return facts

    def _ask(self, table: str, r: dict, pid: int, program: str, tag: int, image=None) -> dict:
        self.owners.asked += 1
        path, process_started, error = self.api.image(pid) if image is None else image
        status, module, module_path = self.api.owner(table, r["raw"])
        hosted = self.services.get(pid, [])
        service, title, unread = "", "", {}
        if tag:  # a service's socket: the owner module is the service, by its short name
            if status == 0 and module:
                service = next((name for name, _ in hosted if name.lower() == module.lower()), module)
            elif len(hosted) == 1:
                service = hosted[0][0]
            elif hosted:
                unread["service"] = _several(hosted)
            else:
                unread["service"] = f"Windows did not name the service behind it (error {status})"
        else:  # a program's own socket: the owner module is the program, where the process can be opened
            if status == 0 and _is_path(module_path):
                path = module_path
            if len(hosted) == 1:
                service = hosted[0][0]
            elif hosted:
                unread["service"] = _several(hosted)
        if service:
            title = next((t for name, t in hosted if name.lower() == service.lower()), "") or \
                self.titles.get(service.lower(), "")
        if not program:  # not in the snapshot, which was taken after the tables
            program = os.path.basename(path.replace("\\", "/")) or ("" if tag or _is_path(module) else module)
        if not program and self.names:
            unread["program"] = f"no process {pid} is listed any more: it ended while the table was read"
        elif not program:
            unread["program"] = "Windows' list of processes could not be read here"
        elif not path:
            code = error or status
            unread["path"] = (REFUSED if code == ERROR_ACCESS_DENIED else
                              f"Windows did not say where this program is on disk (error {code})")
        return {"program": program, "path": path, "service": service, "service_title": title,
                "process_started": process_started, "unread": unread}


def read_windows(api=None, *, owners: Owners | None = None, clock=time.time) -> dict:
    """Windows' socket table as a reading: the four OWNER_MODULE tables through `api` (a WindowsApi; a test's
    stand-in), with the program behind each socket. A table that cannot be read is left out with a note, the others
    kept, and `read` names the ones read whole: not one handed over at more rows than a reading keeps, for the rest
    of it was not handed over at all. A socket's start is the table's own (`starts` is True). A UDP socket is "bound"
    and has no remote: Windows lists none; the same process, address and port listed several times is one row whose
    `count` says how many, since the oldest of them. An owner is asked once for each (pid, name, tag) and kept in
    `owners`, its process's start asked again for a socket it made since: its path from the owner module of a row
    without a tag, else from its image; its service from the owner module of a row with a tag (its display name
    from the services' listing), else the process's one service. What is not read is said in the row's `unread`."""
    api = _shared("api", WindowsApi) if api is None else api
    owners = _shared("windows", Owners) if owners is None else owners
    began = time.perf_counter()
    with owners.lock:
        owners.begin()
        at = clock()
        awake = getattr(api, "awake", time.monotonic)()
        elevated = getattr(api, "elevated", None)
        root = bool(elevated()) if callable(elevated) else False
        notes, found = [UDP_NOTE], {}
        for name in TABLES:
            status, table = api.table(name)
            if status != 0:
                notes.append(f"Windows' {TABLE_WORDS[name]} table could not be read here ({_status_words(status)})")
                continue
            found[name] = table
        names = api.names() if found else {}  # after the tables: a process missing from it has ended since
        services, error = api.services() if found else ({}, 0)
        asks = _WindowsOwners(api, owners, names, services or {}, at)
        rows, whole, cut = [], [], False
        for name, table in found.items():
            proto, family, folded = name[:3], int(name[3]), {}
            fits = len(table) <= MAX_ROWS  # handed over at one row more: what came after it was not handed over
            for r in table:
                started = _epoch(r["created"])
                same = (r["local"], r["local_port"], r["pid"], r["tag"])
                if proto == "udp" and same in folded:  # the same process, address and port, listed again
                    row = folded[same]
                    row["count"] += 1
                    if started is not None and (row["started"] is None or started < row["started"]):
                        row["started"] = row["seen"] = started
                    continue
                if len(rows) >= MAX_ROWS:
                    fits = False
                    break
                row = _row(proto, family, r["state"], r["local"], r["local_port"], r["remote"], r["remote_port"])
                facts = asks.of(name, r)
                row.update({k: v for k, v in facts.items() if k != "unread"}, unread=dict(facts["unread"]))
                row["pid"], row["pids"], row["started"] = r["pid"], ([r["pid"]] if r["pid"] else []), started
                ends = _ends(row) if row["remote"] else None
                if started is not None:
                    row["seen"] = started
                    if ends:
                        owners.connected(name, ends, started)
                else:
                    row["seen"] = owners.first((*_ends(row), r["pid"]), at, name, ends)
                rows.append(row)
                if proto == "udp":
                    folded[same] = row
            if fits:
                whole.append(name)
            else:
                cut = True
        owners.settle(whole)
        if found and not names:
            notes.append(NO_PROCESSES_NOTE)
        if error:
            notes.append(f"The services could not be listed (error {error}): a service's process shows by its "
                         "program alone.")
        if cut:
            notes.append(CUT_NOTE)
        notes.insert(1, f"Read as {'an administrator' if root else 'not an administrator'}: every socket and its "
                        "program's name are read either way.")
    return {"system": "windows", "at": at, "awake": awake, "took": time.perf_counter() - began, "root": root,
            "starts": True, "read": tuple(whole), "cut": cut, "rows": rows, "notes": notes}


def _awake() -> float:
    """Seconds on a clock that leaves out the time this system slept: Linux's CLOCK_MONOTONIC."""
    gettime = getattr(time, "clock_gettime", None)
    return gettime(time.CLOCK_MONOTONIC) if gettime is not None else time.monotonic()


def _uid() -> int:
    """This process's user, as Linux numbers it (-1 where a system has no such number)."""
    return os.getuid() if hasattr(os, "getuid") else -1


def _user_of(uid: int) -> str:
    """A user's name by number; the number itself where it has no name."""
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError, OSError, OverflowError):
        return str(uid)


def _unit(cgroup: str) -> str:
    """The service a process runs in, from its /proc/<pid>/cgroup: the systemd unit its group ends in
    ("ssh.service"); "" for a session's or a scope's process and where systemd does not run."""
    for line in cgroup.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[1] in ("", "name=systemd"):
            unit = parts[2].rstrip("/").rsplit("/", 1)[-1]
            if unit.endswith(".service"):
                return unit
    return ""


def _proc_row(line: str, proto: str, v6: bool) -> tuple[dict, int, str] | None:
    """One line of a /proc/net table as (its row, its uid, its timer: the tr column); None for a line that is none."""
    f = line.split()
    if len(f) < 10:
        return None
    try:
        (local, local_port), (remote, remote_port) = (ports.endpoint(_hex_address(f[i], v6)) for i in (1, 2))
        number, owner, inode = int(f[3], 16), int(f[7]), int(f[9])
    except (ValueError, TypeError, OSError):
        return None  # no row of the table: a line cut short, a header
    local, remote = _address(local) or local, _address(remote) or remote
    state = LINUX_TCP_STATES.get(number, f[3]) if proto == "tcp" else UDP_STATES.get(number, f[3])
    if state in LISTENS or (not remote_port and remote in ports.EVERY):
        remote, remote_port = "", 0
    row = _row(proto, 6 if v6 else 4, state, local, local_port, remote, remote_port)
    row["inode"] = inode
    return row, owner, f[5][:2]


def _no_user(row: dict, owner: int, timer: str) -> bool:
    """Whether the uid the kernel lists for a TCP socket no program holds (inode 0) stands for no one: a TIME_WAIT
    minisock (its timer 03) keeps no owner and is listed as uid 0, and before Linux 6.17 so is any socket its program
    let go of or has not taken up yet. A SYN_RECV row's uid is its listener's, and one that is not 0 is real."""
    if row["proto"] != "tcp" or row["inode"]:
        return False
    return timer == TIME_WAIT_TIMER or (owner == 0 and row["state"] != "syn-received")


def _holders(files, proc: str, wanted: set[int], listing=None) -> dict[int, list[int]]:
    """One walk of /proc/<pid>/fd: the processes that hold each socket of `wanted`, by the socket's inode. Only the
    processes this account may look into are seen: its own, or every one for root. `listing`: /proc's names, when
    this reading listed them already."""
    found: dict[int, list[int]] = {}
    for name in files.listdir(proc) if listing is None else listing:
        if not name.isdigit():
            continue
        for fd in files.listdir(f"{proc}/{name}/fd"):
            link = files.readlink(f"{proc}/{name}/fd/{fd}") or ""
            if link.startswith("socket:[") and link[8:-1].isdigit() and int(link[8:-1]) in wanted:
                found.setdefault(int(link[8:-1]), []).append(int(name))
    return found


def _boot(files, proc: str) -> float:
    """When this Linux started (btime in /proc/stat), seconds since 1970; 0.0 when it does not say."""
    for line in (files.read(f"{proc}/stat") or "").splitlines():
        if line.startswith("btime "):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return 0.0
    return 0.0


def _process(files, proc: str, pid: int, boot: float, ticks: int) -> dict:
    """A process as /proc says it: its program (comm), where that is on disk (exe), the service it runs in (cgroup)
    and when it started (stat's field 22, in ticks after the system's start)."""
    program = (files.read(f"{proc}/{pid}/comm") or "").strip()
    path = files.readlink(f"{proc}/{pid}/exe") or ""
    started, stat = None, files.read(f"{proc}/{pid}/stat") or ""
    if boot and ")" in stat:
        try:
            started = boot + int(stat[stat.rindex(")") + 2:].split()[19]) / ticks
        except (IndexError, ValueError):
            started = None
    unread = {}
    if not program and not path:
        unread["program"] = f"process {pid} ended while the table was read"
    elif not path:
        unread["path"] = NO_PATH
    return {"program": program or os.path.basename(path), "path": path,
            "service": _unit(files.read(f"{proc}/{pid}/cgroup") or ""), "service_title": "",
            "process_started": started, "unread": unread}


def _walk(files, proc: str, owners: Owners, mine: list[dict], known: dict, ticks: int | None) -> None:
    """Who holds this reading's own sockets (`mine`: this account's, or every one for root), into `known` by inode as
    (the pid named, every pid, the process's facts; None for none found). A socket is walked for when it is new, when
    one of its holders has ended since (a parent that forked), and, at a walk made anyway, when the init alone held
    it (a socket the init holds for a service until it starts). One walk at most, one look at /proc's list."""
    wanted: set[int] = set()
    for row in mine:
        inode = row["inode"]
        if inode not in known and inode not in wanted:
            entry = owners.held(inode, _table(row))
            if entry is None:
                wanted.add(inode)
            else:
                known[inode] = entry
    listing = None
    if any(entry[1] for entry in known.values()):  # held by processes when asked: are they all still there?
        listing = files.listdir(proc)
        alive = {int(name) for name in listing if name.isdigit()}
        wanted.update(inode for inode, entry in known.items() if not alive.issuperset(entry[1]))
    if not wanted:
        return
    wanted.update(inode for inode, entry in known.items() if entry[1] == (1,))
    owners.walks += 1
    holders = _holders(files, proc, wanted, listing)
    boot = _boot(files, proc) if holders else 0.0
    rate = ticks or (os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100)
    tables = {row["inode"]: _table(row) for row in mine if row["inode"] in wanted}
    processes: dict[int, dict] = {}
    for inode in sorted(wanted):
        pids = tuple(sorted(holders.get(inode, ())))
        if pids:
            pid = next((p for p in pids if p != 1), pids[0])
            if pid not in processes:
                owners.asked += 1
                processes[pid] = _process(files, proc, pid, boot, rate)
            entry = (pid, pids, processes[pid])
        else:  # kept as not found, so the next reading does not walk for it again
            entry = (0, (), None)
        known[inode] = entry
        owners.hold(inode, entry, tables[inode])


def read_linux(files=None, *, proc: str = "/proc", owners: Owners | None = None, clock=time.time,
               uid: int | None = None, user_of=None, awake=None, ticks: int | None = None) -> dict:
    """Linux's socket table as a reading: /proc/net/tcp, tcp6, udp and udp6 through `files` (a ProcFiles; a test's
    stand-in), every socket with its user where the kernel keeps one. A file that is not there holds no socket (IPv6
    switched off) and is read whole, while another of the four is there; one that cannot be read is left out of
    `read`, with a note; with none of the four, a note says so. A UDP socket is "bound", or "connected" with its
    peer. The program behind a socket is found through /proc/<pid>/fd in one walk a reading, made only while a
    socket of this user (`uid`; of any user, for root) is not in `owners` yet or its holder has ended: its program
    (comm), its path (exe), its service (the unit in cgroup) and its start. A socket several processes hold names
    the first of them, the init (pid 1) only when it alone holds it, and lists them all in `pids`. Another user's
    socket, one no process here holds and one the kernel lists without a socket are said so in `unread`. Linux gives
    no socket a start (`starts` is False): `seen` is when a reading first listed it. `user_of`: a user's name by
    number; `awake`: the clock that leaves sleep out; `ticks`: the kernel's clock ticks a second."""
    files = ProcFiles() if files is None else files
    owners = _shared("linux", Owners) if owners is None else owners
    uid = _uid() if uid is None else int(uid)
    user_of = _user_of if user_of is None else user_of
    began = time.perf_counter()
    with owners.lock:
        owners.begin()
        at, awake_at = clock(), (_awake if awake is None else awake)()
        root, users = uid == 0, {}

        def user(number: int) -> str:
            if number not in users:
                users[number] = str(user_of(number))
            return users[number]
        rows, more, whole, absent, refused, cut = [], [], set(), [], [], False
        for name in TABLES:
            text = files.read(f"{proc}/net/{PROC_FILES[name]}")
            if not text:  # "": not there, so no such socket can be; None: there, and not readable
                (absent if text == "" else refused).append(name)
                continue
            proto, v6, fits = name[:3], name.endswith("6"), True
            for line in text.splitlines()[1:]:
                found = _proc_row(line, proto, v6)
                if found is None:
                    continue
                if len(rows) >= MAX_ROWS:
                    fits = False
                    break
                rows.append(found[0])
                more.append(found[1:])
            if fits:
                whole.add(name)
            else:
                cut = True
        present = len(absent) + len(refused) < len(TABLES)
        if present:
            whole.update(absent)
        read = tuple(name for name in TABLES if name in whole)
        known: dict[int, tuple] = {}  # who holds each socket this account may ask for, by its inode
        mine = [row for row, (owner, _timer) in zip(rows, more) if row["inode"] and (root or owner == uid)]
        if mine:
            _walk(files, proc, owners, mine, known, ticks)
        not_held = NOT_HELD_ROOT if root else NOT_HELD
        for row, (owner, timer) in zip(rows, more):
            inode, table = row["inode"], _table(row)
            if _no_user(row, owner, timer):
                row["unread"] = {"program": NO_SOCKET, "user": NO_USER}
            else:
                row["user"] = user(owner)
                if not inode:
                    row["unread"] = {"program": NO_SOCKET}
                elif inode not in known:
                    row["unread"] = {"program": f"another user's ({row['user']}): only root reads which program "
                                                "holds it"}
                elif known[inode][2] is None:
                    row["unread"] = {"program": not_held}
                else:
                    pid, pids, facts = known[inode]
                    row.update({k: v for k, v in facts.items() if k != "unread"}, pid=pid, pids=list(pids),
                               unread=dict(facts["unread"]))
            ends = _ends(row) if row["remote"] else None
            if inode:
                row["seen"] = owners.first(inode, at, table)
                if ends:
                    owners.connected(table, ends, row["seen"])
            else:
                row["seen"] = owners.first(_ends(row), at, table, ends)
        owners.settle(read)
        if not present:
            notes = [NO_PROC_READ_NOTE if refused else NO_PROC_NOTE]
        else:
            notes = [ROOT_NOTE if root else f"Read as {user(uid)}: the kernel lists every socket here and names the "
                     "program of your own alone.", NO_START_NOTE]
            notes += [f"Linux's {TABLE_WORDS[name]} table could not be read here (/proc/net/{PROC_FILES[name]})."
                      for name in refused]
            if cut:
                notes.append(CUT_NOTE)
    return {"system": "linux", "at": at, "awake": awake_at, "took": time.perf_counter() - began, "root": root,
            "starts": False, "read": read, "cut": cut, "rows": rows, "notes": notes}


# -- what a reading's rows are judged to be ----------------------------------------------------------------------------
def _local(address: str) -> bool:
    """Whether a remote host is the local network's, never placed on a globe: private, loopback, link-local and a
    carrier's shared addresses (netpath.kind), multicast, broadcast, unspecified and reserved ones. It is the globe's
    own test (machines.world's _local_peer), kept here too so that judging a reading needs nothing of machines, which
    brings pandas with it; a test holds the two the same."""
    if netpath.kind(address) != "public":
        return True
    try:
        ip = ipaddress.ip_address(str(address).split("%")[0])
    except ValueError:
        return True
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_multicast or ip.is_unspecified or ip.is_reserved or str(ip) == "255.255.255.255"


_SERVICES: dict[tuple, str] = {}  # what a port is for, as this system's services file says: (port, protocol) -> name


def service_name(port, proto) -> str:
    """What a port is for, as this system's own services file names it (\"https\" for 443/tcp); \"\" where it names
    none (1.68.0). Read on this machine alone: nothing is asked of anyone. 4096 answers kept at most."""
    try:
        key = (int(port), str(proto or "").lower()[:8])
    except (TypeError, ValueError):
        return ""
    if key not in _SERVICES:
        if len(_SERVICES) >= 4096:
            _SERVICES.clear()
        try:
            _SERVICES[key] = socket.getservbyport(*key)[:64] if 0 < key[0] <= 65535 else ""
        except (OSError, OverflowError, TypeError, ValueError):
            _SERVICES[key] = ""
    return _SERVICES[key]


def judge(reading: dict, *, places=None, names=None) -> list[dict]:
    """A reading's rows, each a new dict with six keys more:

    - "where": "" for a row without a remote; "this machine" for a loopback remote and for one of this machine's own
      addresses (every local address of the reading but 0.0.0.0 and ::, so a row whose other end is a row of the same
      reading is this machine's too); "local network" for what is never placed on a globe (private, link-local, a
      carrier's shared addresses, multicast and broadcast: the globe's own test, `_local`); else "internet".
    - "direction": "" without a remote; "local" on this machine; "in" when a listener of the reading of the row's
      protocol and family holds its local port on the row's own local address or on every address (0.0.0.0, ::):
      the tables list a connection in its listener's family, so an IPv4 listener accepted no IPv6 connection, and
      :: holds the IPv4 ones its table writes as IPv6; else "out".
    - "port": the service's: the local port for in, the remote one for out; on this machine whichever of the two a
      listener holds; the local one for a row without a remote.
    - "place": `places(remote)` for an internet host, asked once a host; None for every other row, and without
      `places`.
    - "name": `names[remote]` (the hosts file's, as known_names gives them), else "".
    - "port_name": what the service's port is for, as this system's services file says (`service_name`), else ""
      (1.68.0)."""
    rows = list(reading.get("rows") or ())
    names = names or {}
    own = {r["local"] for r in rows} - set(ports.EVERY) - {""}
    listeners: dict[tuple, set[str]] = {}
    for r in rows:
        if not r["remote"] and r["state"] in LISTENS:
            listeners.setdefault((r["proto"], r.get("family"), r["local_port"]), set()).add(r["local"])
    kinds: dict[str, str] = {}
    placed: dict[str, object] = {}

    def kind(address: str) -> str:  # by the address alone
        if address not in kinds:
            if address in own or ports.is_loopback(address):
                kinds[address] = WHERE[0]
            else:
                kinds[address] = WHERE[1] if _local(address) else WHERE[2]
        return kinds[address]

    def listened(r: dict) -> bool:
        held = listeners.get((r["proto"], r.get("family"), r["local_port"]), set())
        return r["local"] in held or not EVERY_ADDRESS.isdisjoint(held)
    out = []
    for r in rows:
        remote = r["remote"]
        where, direction, port, place = "", "", r["local_port"], None
        if remote:
            where, accepted = kind(remote), listened(r)
            direction = "local" if where == WHERE[0] else "in" if accepted else "out"
            port = r["local_port"] if accepted else r["remote_port"]
            if where == WHERE[2] and places is not None:
                if remote not in placed:
                    placed[remote] = places(remote)
                place = placed[remote]
        out.append({**r, "pids": list(r["pids"]), "unread": dict(r["unread"]), "where": where, "direction": direction,
                    "port": port, "place": place, "name": str(names.get(remote) or "") if remote else "",
                    "port_name": service_name(port, r["proto"]) if remote else ""})
    return out


def _hosts_text(system: str) -> str:
    """The system's own hosts file, HOSTS_BYTES of it at most (cut after its last whole line); "" when it cannot be
    read."""
    if system == "windows":
        path = os.path.join(os.environ.get("SystemRoot") or "C:\\Windows", "System32", "drivers", "etc", "hosts")
    else:
        path = "/etc/hosts"
    try:
        with open(path, "rb") as f:
            data = f.read(HOSTS_BYTES + 1)
    except OSError:
        return ""
    if len(data) > HOSTS_BYTES:
        data = data[:data.rfind(b"\n", 0, HOSTS_BYTES) + 1]
    return data.decode("utf-8-sig", "replace")


def _localhost(name: str) -> bool:
    """Whether a name in a hosts file is one of this machine's: localhost and its kin."""
    name = name.lower().rstrip(".")
    return name in LOCALHOST or name.startswith("localhost.") or name.endswith(".localhost")


def known_names(text: str | None = None, system: str | None = None) -> dict[str, str]:
    """The names this system already knows for addresses, {address: name}, from its own hosts file (`text` stands in
    for it; `system`: whose file, this system's without one): the only names a row is given, since nothing is looked
    up (no reverse lookup, no name server asked). An address's name is the first one on the first line that has it,
    NAME_CHARS of it at most; addresses are written as the rows write them. A loopback address is named only as this
    machine is (localhost and its kin), for a blocking list sends every name it blocks to 127.0.0.1 or 0.0.0.0; an
    address for every address (0.0.0.0, ::) is never a remote and is named nothing. NAMES names at most."""
    if text is None:
        text = _hosts_text(_system(system))
    found: dict[str, str] = {}
    for line in str(text).splitlines():
        words = line.split("#", 1)[0].split()
        if len(words) < 2:
            continue
        address = _address(words[0])
        if not address or address in found or address in EVERY_ADDRESS:
            continue
        if ports.is_loopback(address):
            name = next((word for word in words[1:] if _localhost(word)), "")
            if not name:
                continue
        else:
            name = words[1]
        found[address] = name[:NAME_CHARS]
        if len(found) >= NAMES:
            break
    return found


def under_wsl(release: str | None = None, env=None, *, root: bool | None = None) -> dict | None:
    """What running inside a WSL distribution changes for the Netstat tab, as a table for its page (the user,
    2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some capability this
    should reflect in the plugin"). None on a machine of its own and off Linux. `release` and `env` stand in for the
    kernel's release and the environment in tests (machines.linux.wsl, wsl_generation), `root` for whether the
    platform runs as root. Read only: nothing is run."""
    from .machines import linux

    name = linux.wsl(release, env)
    if not name:
        return None
    root = _uid() == 0 if root is None else bool(root)
    not_listed = ["Not listed", "Windows' programs", "what Windows' own programs listen on and connect to is the "
                  "Windows firewall plugin's Netstat to list"]
    programs = (["Programs", "all named", "the platform runs as root here, so every socket's program is read"] if root
                else ["Programs", "yours named", "the platform does not run as root, so the reading is yours: root's "
                      "services show as another user's"])
    if linux.wsl_generation(release) == 1:
        rows = [["This Linux", f"WSL 1: {name}", "a WSL distribution on Windows, with no Linux kernel of its own"],
                ["Listed", "what WSL 1 gives", "it has no Linux kernel: its /proc/net may be empty"],
                not_listed, programs]
    else:
        rows = [["This Linux", f"WSL 2: {name}", "a WSL distribution on Windows: the sockets listed are its own"],
                not_listed, programs]
    return {"title": "Under WSL", "note": "What running inside a WSL distribution changes for this tab.",
            "columns": [{"title": "What"}, {"title": "Here"}, {"title": "What it means"}], "rows": rows}
