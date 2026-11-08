"""Resources: what the app's processes use (CPU, memory, disk reads and writes, network
connections), the machine's CPU, memory, bandwidth and disks, and the data files' sizes and growth.
Sampled by the chart app in the background.

Bandwidth is the machine's (its network adapters' bytes in and out): Windows counts network bytes
per process only with administrator tracing, so each process shows its connections instead.

Cadence: every BACKGROUND_S while nobody looks, every VIEWING_S while the Resources view is open
(it asks at least every VIEW_TTL_S). The monitor's own limit is the user's: at most CPU_LIMIT of
one core and a small share of memory. It measures the CPU time each sample costs and stretches its
interval to stay under CPU_BUDGET (half the limit, leaving the rest for answering the view), and
its history is capped (RECENT, HISTORY samples; MEMORY_CAP bytes).

Process details come from the system itself, with no extra package: on Windows from kernel32,
ntdll and iphlpapi (WindowsProbe), on Linux from /proc and /sys (LinuxProbe, the same figures); and
only for the processes asked for (`match`: the charts app's by default, Python running liminal; the
platform's hw-stats plugin asks for every Liminal app's, `is_framework`). Elsewhere the disks and files
are shown, and this process alone.
"""
from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

BACKGROUND_S = 30.0  # nobody looking
VIEWING_S = 2.0  # the Resources view open
VIEW_TTL_S = 10.0  # the view asks every VIEWING_S: without a request this long, back to BACKGROUND_S
CPU_LIMIT = 0.10  # the user's limit for the monitor: a tenth of one core
CPU_BUDGET = 0.05  # what sampling may take (the rest of the limit: answering the view)
RECENT = 300  # every sample: ten minutes while viewed, longer in the background
RECENT_S = 600.0  # the view's short range
HISTORY = 2880  # one sample per BACKGROUND_S: a day
MEMORY_CAP = 16 * 2**20  # the samples kept, at most (oldest history dropped first)
FILES_S = 60.0  # the data files are listed this often in the background (every 10 s while viewed)
FILES_VIEWING_S = 10.0
FILE_HISTORY = 61  # file sizes kept per FILES_S: growth over the last hour
TRACKED_FILES = 300  # the largest files tracked one by one (the rest by folder)
MAX_FILES = 20000  # files listed at most (a folder of tick files must not make each scan slow)

ROLES = {"gui": "Chart app", "sync": "Fetcher (sync)", "live": "Live recorder"}


@dataclass(frozen=True)
class Proc:
    """One process as Windows counts it: totals since it started."""
    pid: int
    parent: int
    command: str  # its command line
    started: float  # epoch seconds
    cpu_s: float  # kernel and user time so far
    memory: int  # working set (bytes in RAM)
    private: int  # private bytes (its commit)
    read: int  # bytes read so far
    write: int  # bytes written so far
    threads: int
    handles: int


@dataclass(frozen=True)
class Machine:
    cpus: int
    busy_s: float  # all cores' busy time so far
    total_s: float  # all cores' time so far
    memory_total: int
    memory_available: int
    commit_total: int  # RAM plus the page file
    commit_available: int


@dataclass(frozen=True)
class Net:
    """The network adapters' totals so far (hardware adapters that are up; not loopback)."""
    received: int
    sent: int
    link_bps: int  # the fastest adapter's link speed (bits a second)
    adapters: tuple[str, ...]


@dataclass(frozen=True)
class Conn:
    """One TCP connection or listening socket."""
    pid: int
    state: str
    local: str  # address:port
    remote: str  # address:port ("" while listening)


TCP_STATES = {1: "closed", 2: "listening", 3: "syn-sent", 4: "syn-received", 5: "established", 6: "fin-wait-1",
              7: "fin-wait-2", 8: "close-wait", 9: "closing", 10: "last-ack", 11: "time-wait", 12: "delete-tcb"}
LOOPBACK = ("127.", "::1", "0.0.0.0", "::")
REMOTES = 6  # remote endpoints listed per process (the busiest)


# the charts app's module (python -m liminal_charts ...) and its console script (liminal-charts ...); the names
# from before the rename (liminal_app, liminal: a task registered on them, a process started before) read the same
APP_WORDS = ("liminal_charts", "liminal-charts", "liminal_app", "liminal")


def _app_index(words: list[str]) -> int | None:
    """Where the app's name sits in a command line: `python -m liminal_charts gui`, `liminal-charts gui`,
    `C:\\...\\Scripts\\liminal-charts.exe gui` (the console script; the old module name is read the same way)."""
    for i, word in enumerate(words):
        name = word.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
        if name in APP_WORDS:
            return i
    return None


def app_args(command: str) -> list[str] | None:
    """The words after the app's name in a command line (`gui --port 8765` of `python -m liminal_charts
    gui --port 8765`); None when the command is not the app's."""
    words = command.replace('"', " ").split()
    at = _app_index(words)
    return None if at is None else words[at + 1:]


def role_of(command: str) -> tuple[str, str, str]:
    """(role, label, args) of a liminal command line: `gui` is the chart app, `sync` the
    fetcher (with --source NAME --only, one feed's run: the feeds run side by side; with
    --tickers, a run for symbols opened in the chart), `live` the live recorder."""
    args = app_args(command)
    if args is None:
        return "other", "Python", ""
    feed = args[1] if args[:1] == ["--source"] and len(args) > 1 else None
    rest = args[2:] if feed else args  # the options before the command
    sub = rest[0] if rest else ""
    label = ROLES.get(sub, f"{sub or 'liminal'} command")
    if sub == "sync" and "--tickers" in rest:
        label = "Fetcher: run for opened symbols"
    elif sub == "sync" and feed and "--only" in rest:
        label = f"Fetcher: {feed}"
    elif sub == "host" and len(rest) > 1:  # the fetcher's host and each feed's (host fetcher, host feed-massive)
        label = f"Host: {rest[1]}"
    if sub == "gui" and "--port" in args[:-1]:
        label += f" · port {args[args.index('--port') + 1]}"
    return sub or "other", label, " ".join(args)


def is_app(command: str) -> bool:
    return _app_index(command.replace('"', " ").split()) is not None


# every Liminal app's module and console script by its role: the platform's monitor reports them all
FRAMEWORK = {"liminal_integrator": ("integrator", "Integrator"), "liminal-integrator": ("integrator", "Integrator"),
             "liminal_login": ("login", "Login"), "liminal-login": ("login", "Login"),
             "liminal_platform": ("platform", "Platform"), "liminal-platform": ("platform", "Platform")}


def _framework_index(words: list[str]) -> tuple[int, str] | None:
    for i, word in enumerate(words):
        name = word.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
        if name in FRAMEWORK:
            return i, name
    return None


def is_framework(command: str) -> bool:
    """Any Liminal app's process: the charts app's (is_app), the integrator's, the login's, the platform's."""
    return is_app(command) or _framework_index(command.replace('"', " ").split()) is not None


def framework_role(command: str) -> tuple[str, str, str]:
    """(role, label, args) of any Liminal app's command line: the charts app's as role_of says; the
    integrator's (a daemon said so), the login's and the platform's by their app, with their port."""
    if is_app(command):
        return role_of(command)
    words = command.replace('"', " ").split()
    found = _framework_index(words)
    if found is None:
        return "other", "Python", ""
    at, name = found
    role, label = FRAMEWORK[name]
    args = words[at + 1:]
    if role == "integrator" and "--daemon" in args:
        label += " (daemon)"
    if "--port" in args[:-1]:
        label += f" · port {args[args.index('--port') + 1]}"
    return role, label, " ".join(args)


def is_local(address: str) -> bool:
    """A loopback address (the browser talking to the chart app, say)."""
    a = address.strip("[").removeprefix("::ffff:")
    return a.startswith(("127.", "::1]", "localhost"))


# -- Windows ---------------------------------------------------------------------------------

class WindowsProbe:
    """The app's processes and the machine, from kernel32 and ntdll (a few milliseconds a sample); `match`
    picks the processes reported (the charts app's by default)."""

    def __init__(self, match=None) -> None:
        import ctypes

        self.match = match or is_app
        from ctypes import wintypes as w

        self.ct, self.w = ctypes, w
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.nt = ctypes.WinDLL("ntdll")

        class ENTRY(ctypes.Structure):
            _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ProcessID", w.DWORD),
                        ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", w.DWORD), ("cntThreads", w.DWORD),
                        ("th32ParentProcessID", w.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", w.DWORD),
                        ("szExeFile", ctypes.c_wchar * 260)]

        class MEMORY(ctypes.Structure):
            _fields_ = [("cb", w.DWORD), ("PageFaultCount", w.DWORD)] + [(n, ctypes.c_size_t) for n in (
                "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
                "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
                "PrivateUsage")]

        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class STATUS(ctypes.Structure):
            _fields_ = [("dwLength", w.DWORD), ("dwMemoryLoad", w.DWORD)] + [(n, ctypes.c_ulonglong) for n in (
                "ullTotalPhys", "ullAvailPhys", "ullTotalPageFile", "ullAvailPageFile",
                "ullTotalVirtual", "ullAvailVirtual", "ullAvailExtendedVirtual")]

        class USTR(ctypes.Structure):
            _fields_ = [("Length", w.USHORT), ("MaximumLength", w.USHORT), ("Buffer", ctypes.c_void_p)]

        class GUID(ctypes.Structure):
            _fields_ = [("a", w.DWORD), ("b", w.WORD), ("c", w.WORD), ("d", ctypes.c_ubyte * 8)]

        class IFROW(ctypes.Structure):  # MIB_IF_ROW2 (1352 bytes)
            _fields_ = [("InterfaceLuid", ctypes.c_ulonglong), ("InterfaceIndex", w.ULONG), ("InterfaceGuid", GUID),
                        ("Alias", ctypes.c_wchar * 257), ("Description", ctypes.c_wchar * 257),
                        ("PhysicalAddressLength", w.ULONG), ("PhysicalAddress", ctypes.c_ubyte * 32),
                        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32), ("Mtu", w.ULONG), ("Type", w.ULONG),
                        ("TunnelType", ctypes.c_int), ("MediaType", ctypes.c_int), ("PhysicalMediumType", ctypes.c_int),
                        ("AccessType", ctypes.c_int), ("DirectionType", ctypes.c_int), ("Flags", ctypes.c_ubyte),
                        ("OperStatus", ctypes.c_int), ("AdminStatus", ctypes.c_int), ("MediaConnectState", ctypes.c_int),
                        ("NetworkGuid", GUID), ("ConnectionType", ctypes.c_int),
                        ("TransmitLinkSpeed", ctypes.c_ulonglong), ("ReceiveLinkSpeed", ctypes.c_ulonglong)]
            _fields_ += [(n, ctypes.c_ulonglong) for n in (
                "InOctets", "InUcastPkts", "InNUcastPkts", "InDiscards", "InErrors", "InUnknownProtos", "InUcastOctets",
                "InMulticastOctets", "InBroadcastOctets", "OutOctets", "OutUcastPkts", "OutNUcastPkts", "OutDiscards",
                "OutErrors", "OutUcastOctets", "OutMulticastOctets", "OutBroadcastOctets", "OutQLen")]

        class TCP4(ctypes.Structure):  # MIB_TCPROW_OWNER_PID
            _fields_ = [(n, w.DWORD) for n in ("state", "laddr", "lport", "raddr", "rport", "pid")]

        class TCP6(ctypes.Structure):  # MIB_TCP6ROW_OWNER_PID
            _fields_ = [("laddr", ctypes.c_ubyte * 16), ("lscope", w.DWORD), ("lport", w.DWORD),
                        ("raddr", ctypes.c_ubyte * 16), ("rscope", w.DWORD), ("rport", w.DWORD),
                        ("state", w.DWORD), ("pid", w.DWORD)]

        self.ENTRY, self.MEMORY, self.IO, self.STATUS, self.USTR = ENTRY, MEMORY, IO, STATUS, USTR
        self.IFROW, self.TCP4, self.TCP6 = IFROW, TCP4, TCP6
        try:
            self.ip = ctypes.WinDLL("iphlpapi")
            self.ip.GetIfTable2.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
            self.ip.FreeMibTable.argtypes = [ctypes.c_void_p]
            self.ip.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.DWORD), w.BOOL, w.ULONG,
                                                    ctypes.c_int, w.ULONG]
        except (OSError, AttributeError):
            self.ip = None
        if ctypes.sizeof(IFROW) != 1352:  # not the layout Windows uses here: no bandwidth rather than nonsense
            self.IFROW = None
        self.k32.CreateToolhelp32Snapshot.restype = w.HANDLE
        self.k32.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
        self.k32.OpenProcess.restype = w.HANDLE
        self.k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.k32.CloseHandle.argtypes = [w.HANDLE]
        self.nt.NtQueryInformationProcess.argtypes = [w.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                                      ctypes.POINTER(ctypes.c_ulong)]
        self.nt.NtQueryInformationProcess.restype = ctypes.c_long
        self._commands: dict[tuple[int, float], str] = {}  # (pid, started) -> command line (read once)

    @staticmethod
    def _seconds(ft) -> float:  # a FILETIME duration (100 ns units)
        return ((ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 1e7

    def _command(self, handle) -> str:
        """The command line (ProcessCommandLineInformation, Windows 8.1 and later)."""
        ct = self.ct
        size = ct.c_ulong(0)
        buf = ct.create_string_buffer(1024)
        for _ in range(2):
            status = self.nt.NtQueryInformationProcess(handle, 60, buf, len(buf), ct.byref(size))
            if status == 0:
                s = self.USTR.from_buffer(buf)
                return ct.wstring_at(s.Buffer, s.Length // 2) if s.Buffer else ""
            if size.value <= len(buf):
                return ""
            buf = ct.create_string_buffer(size.value)
        return ""

    def _snapshot(self) -> list[tuple[int, int, int, str]]:
        """(pid, parent, threads, exe) of every process."""
        snap = self.k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
        if not snap or snap == self.w.HANDLE(-1).value:
            return []
        out = []
        try:
            e = self.ENTRY()
            e.dwSize = self.ct.sizeof(e)
            ok = self.k32.Process32FirstW(snap, self.ct.byref(e))
            while ok:
                out.append((e.th32ProcessID, e.th32ParentProcessID, e.cntThreads, e.szExeFile))
                ok = self.k32.Process32NextW(snap, self.ct.byref(e))
        finally:
            self.k32.CloseHandle(snap)
        return out

    def processes(self) -> list[Proc]:
        """The app's processes: Python running liminal (and this one)."""
        ct, w = self.ct, self.w
        me, out, alive = os.getpid(), [], set()
        for pid, parent, threads, exe in self._snapshot():
            if not exe.lower().startswith("python"):
                continue
            h = self.k32.OpenProcess(0x1000 | 0x0010, False, pid)  # QUERY_LIMITED_INFORMATION | VM_READ
            if not h:
                continue
            try:
                times = [w.FILETIME() for _ in range(4)]
                if not self.k32.GetProcessTimes(h, *(ct.byref(t) for t in times)):
                    continue
                created = self._seconds(times[0]) - 11644473600  # 1601 -> 1970
                key = (pid, created)
                alive.add(key)
                if key not in self._commands:
                    self._commands[key] = self._command(h)
                command = self._commands[key]
                if pid != me and not self.match(command):
                    continue
                mem = self.MEMORY()
                mem.cb = ct.sizeof(mem)
                self.k32.K32GetProcessMemoryInfo(h, ct.byref(mem), mem.cb)
                io = self.IO()
                self.k32.GetProcessIoCounters(h, ct.byref(io))
                handles = w.DWORD(0)
                self.k32.GetProcessHandleCount(h, ct.byref(handles))
                out.append(Proc(pid, parent, command, created, self._seconds(times[2]) + self._seconds(times[3]),
                                mem.WorkingSetSize, mem.PrivateUsage, io.ReadTransferCount, io.WriteTransferCount,
                                threads, handles.value))
            finally:
                self.k32.CloseHandle(h)
        for key in set(self._commands) - alive:  # ended: its command line is forgotten
            del self._commands[key]
        return out

    def machine(self) -> Machine | None:
        ct, w = self.ct, self.w
        idle, kernel, user = w.FILETIME(), w.FILETIME(), w.FILETIME()
        st = self.STATUS()
        st.dwLength = ct.sizeof(st)
        if not self.k32.GetSystemTimes(ct.byref(idle), ct.byref(kernel), ct.byref(user)) \
                or not self.k32.GlobalMemoryStatusEx(ct.byref(st)):
            return None
        total = self._seconds(kernel) + self._seconds(user)  # kernel time includes idle time
        return Machine(os.cpu_count() or 1, total - self._seconds(idle), total, st.ullTotalPhys, st.ullAvailPhys,
                       st.ullTotalPageFile, st.ullAvailPageFile)

    def network(self) -> Net | None:
        """Bytes in and out of the hardware adapters that are up (GetIfTable2): filter drivers and
        loopback are left out, so nothing is counted twice."""
        if self.ip is None or self.IFROW is None:
            return None
        ct = self.ct
        table = ct.c_void_p()
        if self.ip.GetIfTable2(ct.byref(table)) != 0 or not table.value:
            return None
        try:
            n = ct.c_ulong.from_address(table.value).value
            rows = (self.IFROW * n).from_address(table.value + 8)  # the rows are 8-byte aligned
            received = sent = link = 0
            names = []
            for r in rows:
                hardware, filtered = r.Flags & 1, r.Flags & 2
                if hardware and not filtered and r.OperStatus == 1 and r.Type != 24:
                    received += r.InOctets
                    sent += r.OutOctets
                    link = max(link, r.ReceiveLinkSpeed, r.TransmitLinkSpeed)
                    names.append(r.Alias)
            return Net(received, sent, link, tuple(names))
        finally:
            self.ip.FreeMibTable(table)

    def connections(self) -> list[Conn]:
        """Every TCP connection and listening socket on the machine, with its process
        (GetExtendedTcpTable, IPv4 and IPv6)."""
        if self.ip is None:
            return []
        import socket

        ct, w = self.ct, self.w
        out = []

        def port(p: int) -> int:  # network byte order
            return ((p & 0xFF) << 8) | ((p >> 8) & 0xFF)

        for family, row in ((2, self.TCP4), (23, self.TCP6)):
            size = w.DWORD(0)
            buf = None
            for _ in range(3):  # the table can grow between asking its size and reading it
                status = self.ip.GetExtendedTcpTable(buf, ct.byref(size), False, family, 5, 0)  # OWNER_PID_ALL
                if status == 0:
                    break
                if status != 122:  # ERROR_INSUFFICIENT_BUFFER
                    buf = None
                    break
                buf = ct.create_string_buffer(size.value + 4096)
            if buf is None or status != 0:
                continue
            n = ct.c_ulong.from_buffer(buf).value
            for r in (row * n).from_buffer(buf, 4):
                if family == 2:
                    la = socket.inet_ntoa(r.laddr.to_bytes(4, "little"))
                    ra = socket.inet_ntoa(r.raddr.to_bytes(4, "little"))
                    local, remote = f"{la}:{port(r.lport)}", f"{ra}:{port(r.rport)}"
                else:
                    la = socket.inet_ntop(socket.AF_INET6, bytes(r.laddr))
                    ra = socket.inet_ntop(socket.AF_INET6, bytes(r.raddr))
                    local, remote = f"[{la}]:{port(r.lport)}", f"[{ra}]:{port(r.rport)}"
                state = TCP_STATES.get(r.state, str(r.state))
                out.append(Conn(r.pid, state, local, "" if state == "listening" else remote))
        return out


# -- Linux -----------------------------------------------------------------------------------

LINUX_TCP_STATES = {1: "established", 2: "syn-sent", 3: "syn-received", 4: "fin-wait-1", 5: "fin-wait-2", 6: "time-wait",
                    7: "closed", 8: "close-wait", 9: "last-ack", 10: "listening", 11: "closing"}
VIRTUAL_NET = ("lo", "docker", "veth", "br-", "virbr", "vnet", "tun", "tap", "wg", "zt", "cni", "flannel", "kube")


def _fields(text: str) -> list[tuple[str, str]]:
    """`Key:  value` lines (/proc/<pid>/status, /proc/meminfo, /proc/<pid>/io)."""
    out = []
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            out.append((key.strip(), value.strip()))
    return out


def _kb(value: str | None) -> int:
    """"16384 kB" as bytes (0 when absent)."""
    words = (value or "").split()
    return int(words[0]) * (1024 if len(words) > 1 and words[1].lower() == "kb" else 1) if words and words[0].isdigit() else 0


def _hex_address(text: str, v6: bool) -> str:
    """An address as /proc/net/tcp writes it (0100007F:1F90) as address:port (127.0.0.1:8080)."""
    import socket

    host, _, port = text.partition(":")
    raw = bytes.fromhex(host)
    if not v6:
        return f"{socket.inet_ntoa(raw[::-1])}:{int(port, 16)}"
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))  # four 32-bit words, each little-endian
    return f"[{socket.inet_ntop(socket.AF_INET6, words)}]:{int(port, 16)}"


class LinuxProbe:
    """The app's processes and the machine, from /proc and /sys (no extra package; a few milliseconds a
    sample): the figures the Windows probe gives, so the monitor reads both alike. `match` picks the processes
    reported (the charts app's by default; the platform's hw-stats plugin asks for the framework's); `proc` and
    `net` are where /proc and /sys/class/net are, and the reads go through _read, _listdir and _readlink, so a
    test stands in for the files."""

    def __init__(self, match=None, proc: str = "/proc", net: str = "/sys/class/net", ticks: int | None = None) -> None:
        self.match = match or is_app
        self.proc, self.net = proc, net
        self.ticks = ticks or (os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100)
        self._commands: dict[tuple[int, float], str] = {}  # (pid, started) -> command line (read once)
        self._pids: set[int] = set()  # the processes reported last (their sockets are the ones attributed)
        self._boot = self._boot_time()

    # the files (a test stands in for them)
    def _read(self, path: str) -> str | None:
        try:
            with open(path, "rb") as f:
                return f.read().decode("utf-8", "replace")
        except OSError:
            return None

    def _listdir(self, path: str) -> list[str]:
        try:
            return os.listdir(path)
        except OSError:
            return []

    def _readlink(self, path: str) -> str | None:
        try:
            return os.readlink(path)
        except OSError:
            return None

    def _boot_time(self) -> float:
        for line in (self._read(f"{self.proc}/stat") or "").splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
        return 0.0

    def processes(self) -> list[Proc]:
        """The processes `match` picks (and this one): their CPU time, memory, I/O, threads and open files."""
        me, out, alive, pids = os.getpid(), [], set(), set()
        for name in self._listdir(self.proc):
            if not name.isdigit():
                continue
            pid = int(name)
            stat = self._read(f"{self.proc}/{pid}/stat")
            if not stat or ")" not in stat:
                continue
            fields = stat[stat.rindex(")") + 2:].split()  # after "pid (comm) ": the name may hold spaces and parentheses
            try:
                parent, utime, stime = int(fields[1]), int(fields[11]), int(fields[12])
                threads, start = int(fields[17]), int(fields[19])
            except (IndexError, ValueError):
                continue
            started = self._boot + start / self.ticks
            key = (pid, started)
            alive.add(key)
            if key not in self._commands:
                self._commands[key] = (self._read(f"{self.proc}/{pid}/cmdline") or "").replace("\x00", " ").strip()
            command = self._commands[key]
            if pid != me and not self.match(command):
                continue
            status = dict(_fields(self._read(f"{self.proc}/{pid}/status") or ""))
            io = dict(_fields(self._read(f"{self.proc}/{pid}/io") or ""))
            private = _kb(status.get("RssAnon")) + _kb(status.get("VmSwap"))
            out.append(Proc(pid, parent, command, started, (utime + stime) / self.ticks, _kb(status.get("VmRSS")),
                            private, int(io.get("rchar", "0") or 0), int(io.get("wchar", "0") or 0), threads,
                            len(self._listdir(f"{self.proc}/{pid}/fd"))))
            pids.add(pid)
        for key in set(self._commands) - alive:  # ended: its command line is forgotten
            del self._commands[key]
        self._pids = pids
        return out

    def machine(self) -> Machine | None:
        stat = self._read(f"{self.proc}/stat") or ""
        cpu = next((line.split()[1:] for line in stat.splitlines() if line.startswith("cpu ")), None)
        mem = dict(_fields(self._read(f"{self.proc}/meminfo") or ""))
        if not cpu or "MemTotal" not in mem:
            return None
        ticks = [int(x) for x in cpu[:8]]  # user nice system idle iowait irq softirq steal (guest time is in user)
        total = sum(ticks) / self.ticks
        idle = (ticks[3] + ticks[4]) / self.ticks
        cores = sum(1 for line in stat.splitlines() if line.startswith("cpu") and line[3:4].isdigit())
        memory = _kb(mem.get("MemTotal"))
        available = _kb(mem.get("MemAvailable")) or (_kb(mem.get("MemFree")) + _kb(mem.get("Cached")) + _kb(mem.get("Buffers")))
        swap = _kb(mem.get("SwapTotal"))
        return Machine(cores or os.cpu_count() or 1, total - idle, total, memory, available, memory + swap,
                       available + _kb(mem.get("SwapFree")))

    def network(self) -> Net | None:
        """Bytes in and out of the adapters that are up: the hardware ones (a device behind them), else every
        one that is not loopback or a bridge, tunnel or container's (WSL's and a VM's adapters have no device)."""
        rows: dict[str, tuple[int, int]] = {}
        for line in (self._read(f"{self.proc}/net/dev") or "").splitlines()[2:]:
            name, sep, rest = line.partition(":")
            values = rest.split()
            if sep and len(values) >= 9:
                rows[name.strip()] = (int(values[0]), int(values[8]))
        if not rows:
            return None
        up = [n for n in rows if not n.startswith(VIRTUAL_NET)
              and (self._read(f"{self.net}/{n}/operstate") or "up").strip() in ("up", "unknown")]
        hardware = [n for n in up if self._readlink(f"{self.net}/{n}/device") is not None] or up
        speeds = [int(s) for n in hardware if (s := (self._read(f"{self.net}/{n}/speed") or "").strip()).isdigit()]
        return Net(sum(rows[n][0] for n in hardware), sum(rows[n][1] for n in hardware),
                   max(speeds, default=0) * 1_000_000, tuple(hardware))

    def connections(self) -> list[Conn]:
        """Every TCP connection and listening socket (/proc/net/tcp, tcp6), each with its process when it is
        one of those reported (their open sockets read from /proc/<pid>/fd); another's with pid 0."""
        owner: dict[str, int] = {}
        for pid in self._pids:
            for fd in self._listdir(f"{self.proc}/{pid}/fd"):
                link = self._readlink(f"{self.proc}/{pid}/fd/{fd}") or ""
                if link.startswith("socket:["):
                    owner[link[8:-1]] = pid
        out = []
        for name, v6 in (("tcp", False), ("tcp6", True)):
            for line in (self._read(f"{self.proc}/net/{name}") or "").splitlines()[1:]:
                f = line.split()
                if len(f) < 10:
                    continue
                try:
                    state = LINUX_TCP_STATES.get(int(f[3], 16), f[3])
                    local, remote = _hex_address(f[1], v6), _hex_address(f[2], v6)
                except (ValueError, OSError):
                    continue
                out.append(Conn(owner.get(f[9], 0), state, local, "" if state == "listening" else remote))
        return out


class OwnProbe:
    """Neither Windows nor Linux: this process alone (its CPU time), and no machine figures."""

    def processes(self) -> list[Proc]:
        t = os.times()
        return [Proc(os.getpid(), os.getppid(), " ".join(["liminal", *sys.argv[1:]]),
                     _STARTED, t.user + t.system, 0, 0, 0, 0, threading.active_count(), 0)]

    def machine(self) -> Machine | None:
        return None

    def network(self) -> Net | None:
        return None

    def connections(self) -> list[Conn]:
        return []


_STARTED = time.time()


def default_probe(match=None):
    """This system's probe (Windows', Linux's, else this process alone), reporting the processes `match` picks."""
    if sys.platform == "win32":
        try:
            return WindowsProbe(match)
        except (OSError, AttributeError):
            pass
    elif sys.platform.startswith("linux") and os.path.isdir("/proc"):
        try:
            return LinuxProbe(match)
        except OSError:
            pass
    return OwnProbe()


# -- the monitor ----------------------------------------------------------------------------

def _size(o, seen=None) -> int:
    """Bytes a sample holds (its dicts, tuples, numbers and strings)."""
    n = sys.getsizeof(o)
    if isinstance(o, dict):
        n += sum(_size(k) + _size(v) for k, v in o.items())
    elif isinstance(o, (tuple, list)):
        n += sum(_size(v) for v in o)
    return n


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds")


class Monitor:
    """Samples in a thread of its own (start), at the cadence of whoever looks (view)."""

    def __init__(self, data_dir: Path, probe=None, clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time, cpu_clock: Callable[[], float] = time.thread_time,
                 roles: Callable[[str], tuple[str, str, str]] | None = None, own: tuple[str, str] = ("gui", "Chart app")) -> None:
        self.data_dir = Path(data_dir)
        self.probe = probe if probe is not None else default_probe()
        self.roles = roles or role_of  # a process's (role, label, args): the charts app's by default
        self.own = own  # this process's role and label when its command line says nothing (a test, a one-off)
        self.clock, self.wall, self.cpu_clock = clock, wall, cpu_clock
        self.recent: deque = deque(maxlen=RECENT)
        self.history: deque = deque(maxlen=HISTORY)
        self._bytes = 0  # what recent and history hold (_size)
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._viewed_at = float("-inf")
        self._prev: dict[tuple[int, float], tuple[float, Proc]] = {}  # (pid, started) -> (when, totals)
        self._machine_prev: tuple[float, Machine] | None = None
        self._net_prev: tuple[float, Net] | None = None
        self._groups: list[dict] = []
        self._machine: dict | None = None
        self._net: dict | None = None
        self._links: dict | None = None
        self._error: str | None = None  # the last sample's failure, shown in the view
        self._costs: deque = deque(maxlen=120)  # (when, CPU seconds) of sampling and answering
        self._last_cost = 0.0
        self._files: dict | None = None
        self._files_at = float("-inf")
        self._file_sizes: deque = deque(maxlen=FILE_HISTORY)  # (when, {path: size}, {folder: size})
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()  # set by stop(): the sampling thread ends

    # cadence
    def viewing(self) -> bool:
        return self.clock() - self._viewed_at < VIEW_TTL_S

    def interval(self) -> float:
        base = VIEWING_S if self.viewing() else BACKGROUND_S
        return max(base, self._last_cost / CPU_BUDGET)  # a slow sample waits longer: the budget holds

    def start(self) -> None:
        if self._thread is None and not self._stop.is_set():
            self._thread = threading.Thread(target=self._run, daemon=True, name="resources")
            self._thread.start()

    def stop(self) -> None:
        """End the sampling (the chart app going quiet): a new Monitor samples the next time."""
        self._stop.set()
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample()
            except Exception as e:  # a failed sample is shown, and the next one tried
                self._error = f"{type(e).__name__}: {e}"
            self._wake.wait(self.interval())
            self._wake.clear()

    # sampling
    def sample(self) -> dict:
        began = self.cpu_clock()
        now, at = self.clock(), self.wall()
        procs = self.probe.processes()
        machine = self.probe.machine()
        net, conns = self.probe.network(), self.probe.connections()
        groups = self._group(procs, now)
        links = self._connect(groups, conns)
        mrow = self._machine_row(machine, now)
        nrow = self._net_row(net, now)
        roles = {g["key"]: (g["cpu"], g["memory"], g["private"], g["readRate"], g["writeRate"]) for g in groups}
        point = {"t": at, "cpu": mrow["cpu"] if mrow else None, "mem": mrow["memoryUsed"] if mrow else None,
                 "in": nrow["in"] if nrow else None, "out": nrow["out"] if nrow else None, "roles": roles}
        files_every = FILES_VIEWING_S if self.viewing() else FILES_S
        if now - self._files_at >= files_every:
            self._files_at = now
            files = self._scan(at)
        else:
            files = None
        with self._lock:
            self._groups, self._machine, self._net, self._links = groups, mrow, nrow, links
            if files is not None:
                self._files = files
            self._keep(self.recent, point)
            if not self.history or at - self.history[-1]["t"] >= BACKGROUND_S - 0.5:
                self._keep(self.history, point)
            while self._bytes > MEMORY_CAP and self.history:
                self._bytes -= _size(self.history.popleft())
        cost = self.cpu_clock() - began
        self._last_cost = cost
        self._costs.append((now, cost))
        self._error = None
        return point

    def _keep(self, ring: deque, point: dict) -> None:
        if len(ring) == ring.maxlen:
            self._bytes -= _size(ring[0])
        ring.append(point)
        self._bytes += _size(point)

    def _group(self, procs: list[Proc], now: float) -> list[dict]:
        """One row per program: Windows' venv launcher (the parent with the same command line) is
        counted with the interpreter it started."""
        by_pid = {p.pid: p for p in procs}

        def root(p: Proc) -> Proc:
            while p.parent in by_pid and by_pid[p.parent].command == p.command and by_pid[p.parent] is not p:
                p = by_pid[p.parent]
            return p

        rows: dict[int, dict] = {}
        seen = set()
        me = os.getpid()
        for p in sorted(procs, key=lambda p: p.started):
            key = (p.pid, p.started)
            seen.add(key)
            prev = self._prev.get(key)
            self._prev[key] = (now, p)
            dt = now - prev[0] if prev else 0.0
            r = root(p)
            role, label, args = self.roles(r.command)
            if r.pid == me and role == "other":
                role, label, args = self.own[0], self.own[1], ""
            row = rows.setdefault(r.pid, {
                "key": f"{role}:{r.pid}", "role": role, "label": label, "command": args, "pids": [],
                "started": _iso(r.started), "self": False, "cpu": None, "memory": 0, "private": 0,
                "readRate": None, "writeRate": None, "read": 0, "write": 0, "threads": 0, "handles": 0})
            row["pids"].append(p.pid)
            row["self"] = row["self"] or p.pid == me
            for k, v in (("memory", p.memory), ("private", p.private), ("read", p.read), ("write", p.write),
                         ("threads", p.threads), ("handles", p.handles)):
                row[k] += v
            if dt > 0:
                for k, v in (("cpu", (p.cpu_s - prev[1].cpu_s) / dt), ("readRate", (p.read - prev[1].read) / dt),
                             ("writeRate", (p.write - prev[1].write) / dt)):
                    row[k] = (row[k] or 0.0) + max(v, 0.0)
        for key in set(self._prev) - seen:  # ended
            del self._prev[key]
        order = {"gui": 0, "sync": 1, "live": 2, "integrator": 3, "login": 4, "platform": 5}
        return sorted(rows.values(), key=lambda r: (order.get(r["role"], 6), r["started"]))

    @staticmethod
    def _connect(groups: list[dict], conns: list[Conn]) -> dict:
        """Each program's TCP connections (by state, and its busiest remote ends), and the
        machine's counts."""
        owner = {pid: g for g in groups for pid in g["pids"]}
        ends: dict[str, dict[tuple[str, str], int]] = {}
        for g in groups:
            g["connections"] = {"established": 0, "listening": 0, "other": 0}
        machine = {"established": 0, "listening": 0, "other": 0, "app": 0}
        for c in conns:
            kind = c.state if c.state in ("established", "listening") else "other"
            machine[kind] += 1
            g = owner.get(c.pid)
            if g is None:
                continue
            g["connections"][kind] += 1
            machine["app"] += kind == "established"
            if c.remote:
                e = ends.setdefault(g["key"], {})
                e[(c.remote, c.state)] = e.get((c.remote, c.state), 0) + 1
        for g in groups:
            e = ends.get(g["key"], {})
            g["remotes"] = [{"remote": a, "state": s, "count": n, "local": is_local(a)}
                            for (a, s), n in sorted(e.items(), key=lambda kv: (-kv[1], kv[0]))[:REMOTES]]
            g["remoteCount"] = len(e)
        return machine

    def _net_row(self, net: Net | None, now: float) -> dict | None:
        if net is None:
            return None
        prev, self._net_prev = self._net_prev, (now, net)
        rate_in = rate_out = None
        if prev and now > prev[0]:  # an adapter turned off makes the totals drop: no negative rate
            rate_in = max(net.received - prev[1].received, 0) / (now - prev[0])
            rate_out = max(net.sent - prev[1].sent, 0) / (now - prev[0])
        return {"in": rate_in, "out": rate_out, "received": net.received, "sent": net.sent,
                "link": net.link_bps, "adapters": list(net.adapters)}

    def _machine_row(self, m: Machine | None, now: float) -> dict | None:
        if m is None:
            return None
        prev, self._machine_prev = self._machine_prev, (now, m)
        cpu = None
        if prev and m.total_s > prev[1].total_s:
            cpu = (m.busy_s - prev[1].busy_s) / (m.total_s - prev[1].total_s)
        return {"cpus": m.cpus, "cpu": cpu, "memoryTotal": m.memory_total,
                "memoryUsed": m.memory_total - m.memory_available, "commitTotal": m.commit_total,
                "commitUsed": m.commit_total - m.commit_available}

    def _scan(self, at: float) -> dict:
        """The data folder's files by folder, the largest one by one, with growth over the last
        hour; and the disks holding the data and the app."""
        files: list[tuple[str, int, float]] = []
        stack = [self.data_dir]
        while stack and len(files) < MAX_FILES:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            if e.is_dir(follow_symlinks=False):
                                stack.append(Path(e.path))
                            elif e.is_file(follow_symlinks=False):
                                st = e.stat(follow_symlinks=False)
                                files.append((Path(e.path).relative_to(self.data_dir).as_posix(), st.st_size,
                                              st.st_mtime))
                        except OSError:
                            continue
            except OSError:
                continue
        folders: dict[str, int] = {}
        counts: dict[str, int] = {}
        for path, size, _ in files:
            folder = path.split("/", 1)[0] if "/" in path else "."
            folders[folder] = folders.get(folder, 0) + size
            counts[folder] = counts.get(folder, 0) + 1
        largest = sorted(files, key=lambda f: -f[1])[:TRACKED_FILES]
        self._file_sizes.append((at, {p: s for p, s, _ in largest}, dict(folders)))
        then_at, then_files, then_folders = self._file_sizes[0]
        span = at - then_at

        def growth(now_size: int, then_size: int | None) -> float | None:
            return None if then_size is None or span < FILES_S - 1 else (now_size - then_size) * 3600 / span

        groups = []
        for folder, size in sorted(folders.items(), key=lambda kv: -kv[1]):
            groups.append({"name": folder, "size": size, "count": counts[folder],
                           "growth": growth(size, then_folders.get(folder)),
                           "files": [{"path": p, "size": s, "modified": _iso(m), "growth": growth(s, then_files.get(p))}
                                     for p, s, m in largest if (p.split("/", 1)[0] if "/" in p else ".") == folder][:12]})
        disks, anchors = [], {}
        system = Path(os.environ["SystemDrive"] + os.sep) if os.environ.get("SystemDrive") else Path("/")  # never "//"
        for what, path in (("data", self.data_dir), ("app", Path(__file__).resolve()), ("system", system)):
            anchors.setdefault(path.anchor or "/", []).append(what)
        for anchor, holds in anchors.items():
            try:
                u = shutil.disk_usage(anchor)
            except OSError:
                continue
            disks.append({"path": anchor, "holds": holds, "total": u.total, "used": u.used, "free": u.free})
        return {"root": str(self.data_dir), "total": sum(folders.values()), "count": len(files),
                "capped": len(files) >= MAX_FILES, "span": span, "groups": groups, "disks": disks}

    # the view
    def view(self, span: str = "recent") -> dict:
        """What the Resources view shows; asking keeps the cadence at VIEWING_S for VIEW_TTL_S."""
        began = self.cpu_clock()
        was = self.viewing()
        self._viewed_at = self.clock()
        if not was:
            self._files_at = float("-inf")  # the files listed afresh for whoever opened the view
            if self._thread is not None:
                self._wake.set()  # sampled now, then every VIEWING_S
            elif not self.recent:
                self.sample()  # no thread (tests, a one-off) and nothing sampled yet: sampled here
        with self._lock:
            points = list(self.history if span == "day" else self.recent)
            groups, machine, files = [dict(g) for g in self._groups], self._machine, self._files
            net, links = self._net, self._links
            kept, held = len(self.recent) + len(self.history), self._bytes
        if span != "day" and points:
            points = [p for p in points if p["t"] >= points[-1]["t"] - RECENT_S]
        keys = [g["key"] for g in groups]
        series = {"t": [p["t"] for p in points], "cpu": [p["cpu"] for p in points], "memory": [p["mem"] for p in points],
                  "in": [p.get("in") for p in points], "out": [p.get("out") for p in points],
                  "processes": {k: {"cpu": [p["roles"].get(k, (None,) * 5)[0] for p in points],
                                    "memory": [p["roles"].get(k, (None,) * 5)[1] for p in points]} for k in keys}}
        self._costs.append((self.clock(), self.cpu_clock() - began))
        window = [c for c in self._costs if c[0] >= self.clock() - 60]
        elapsed = max(self.clock() - window[0][0], self.interval()) if window else 1.0
        return {
            "sampledAt": _iso(points[-1]["t"]) if points else None,
            "viewing": True, "interval": round(self.interval(), 2), "span": "day" if span == "day" else "recent",
            "cadence": {"viewing": VIEWING_S, "background": BACKGROUND_S, "files": FILES_VIEWING_S},
            "monitor": {"cpu": sum(c[1] for c in window) / elapsed, "limit": CPU_LIMIT, "budget": CPU_BUDGET,
                        "memory": held, "memoryCap": MEMORY_CAP, "samples": kept, "maxSamples": RECENT + HISTORY,
                        "error": self._error},
            "machine": machine, "network": net, "connections": links, "processes": groups, "files": files,
            "series": series,
            "windows": isinstance(self.probe, WindowsProbe),
            "system": "windows" if isinstance(self.probe, WindowsProbe) else "linux" if isinstance(self.probe, LinuxProbe) else "other",
        }
