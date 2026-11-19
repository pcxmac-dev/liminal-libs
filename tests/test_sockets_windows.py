"""Windows' socket table with the program behind each socket (liminal_libs.sockets: decode, read_windows, Owners; the
user, 2026-11-16: "the firewall app should have a 'netstat' like interface for looking at active ports and what apps
they are attached to, and the hosts that they connect to across the lan or wan"). The four tables are written here
byte for byte as Windows writes them (a count, then rows of 160, 192, 160 and 176 bytes: the shapes measured on this
PC) and read back through the module's own layouts, so every test runs on Linux as on Windows. The calls behind a
reading are a stand-in's (FakeApi): the tables, the snapshot's names, each process's image, each row's owner module
and the services; the real table() and elevated() run over stand-ins of iphlpapi and shell32 (FakeIphlpapi, Shell).

Nothing real is reached: no library of Windows' is loaded, no process is listed or started, no socket is opened and
nothing is asked of the network (this file's own fixture and the library's shared guard, `no_outside`, fail a test
that does)."""
from __future__ import annotations

import ast
import ctypes
import inspect
import ipaddress
import json
import re
import socket
import struct
import subprocess
import textwrap
import urllib.request

import pytest

from liminal_libs import resources, sockets
from liminal_libs.sockets import BAD_LAYOUT, TOO_LARGE, Owners

pytestmark = pytest.mark.usefixtures("no_outside")

READ = sockets.read  # the real one, over stand-ins only (the suite's own guard may refuse the module's name for it)
ELEVATED = sockets.WindowsApi.elevated  # the real one, over a stand-in shell32 only (this file's guard refuses it)
BOOT = 1_794_842_175.0  # when the stand-in PC started, seconds since 1970
NOW = BOOT + 56_000.0
LAN, LAN6, PEER, WEB, WEB6 = "192.168.1.20", "2001:db8:1::20", "192.168.1.7", "93.184.216.34", "2606:4700::1111"
PYTHON, EDGE = "C:\\Python315\\python.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
STATES = {word: number for number, word in resources.TCP_STATES.items()}
KEYS = ["proto", "family", "state", "local", "local_port", "remote", "remote_port", "pid", "pids", "program", "path",
        "service", "service_title", "user", "started", "process_started", "count", "inode", "seen", "unread"]


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch):
    """Nothing real is reached: no child process, no download, no socket, none of Windows' libraries, no snapshot of
    this machine's processes, no /proc, no hosts file (each reach is noted, so one that was caught is seen too). No
    owner is kept from one test to the next."""
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


# -- the tables as Windows writes them ---------------------------------------------------------------------------------
def filetime(epoch: float) -> int:
    """Seconds since 1970 as Windows writes a socket's start: 100 ns since 1601."""
    return int(round((epoch + 11644473600) * 10_000_000))


def port(number: int) -> int:
    """A port as a table holds it: in network byte order in a DWORD's low 16 bits."""
    return ((number & 0xFF) << 8) | (number >> 8)


def four(address: str) -> int:
    return struct.unpack("<I", ipaddress.IPv4Address(address).packed)[0]


def six(address: str) -> bytes:
    return ipaddress.IPv6Address(address).packed


def tcp4(state, local, local_port, remote="0.0.0.0", remote_port=0, pid=0, created=0.0, tag=0) -> bytes:
    """A MIB_TCPROW_OWNER_MODULE: 160 bytes."""
    return struct.pack("<6IqQ", STATES[state], four(local), port(local_port), four(remote), port(remote_port), pid,
                       filetime(created) if created else 0, tag) + bytes(120)


def tcp6(state, local, local_port, remote="::", remote_port=0, pid=0, created=0.0, tag=0) -> bytes:
    """A MIB_TCP6ROW_OWNER_MODULE: 192 bytes."""
    return struct.pack("<16sII16sIIIIqQ", six(local), 0, port(local_port), six(remote), 0, port(remote_port),
                       STATES[state], pid, filetime(created) if created else 0, tag) + bytes(120)


def udp4(local, local_port, pid=0, created=0.0, tag=0, flags=1) -> bytes:
    """A MIB_UDPROW_OWNER_MODULE: 160 bytes, four of them padding before the start and four after the flags."""
    return struct.pack("<IIIIqIIQ", four(local), port(local_port), pid, 0xAAAAAAAA, filetime(created) if created else 0,
                       flags, 0xBBBBBBBB, tag) + bytes(120)


def udp6(local, local_port, pid=0, created=0.0, tag=0, flags=1) -> bytes:
    """A MIB_UDP6ROW_OWNER_MODULE: 176 bytes."""
    return struct.pack("<16sIIIIqIIQ", six(local), 0, port(local_port), pid, 0xAAAAAAAA,
                       filetime(created) if created else 0, flags, 0xBBBBBBBB, tag) + bytes(120)


def table(*rows: bytes, slack: int = 64) -> bytes:
    """A table as its call leaves the buffer: how many rows, four bytes of padding, the rows, and room to spare."""
    return struct.pack("<II", len(rows), 0) + b"".join(rows) + bytes(slack)


TABLES = {
    "tcp4": table(
        tcp4("listening", "0.0.0.0", 135, pid=1200, created=BOOT + 1, tag=196),
        tcp4("listening", "0.0.0.0", 445, pid=4, created=BOOT + 15),
        tcp4("listening", "127.0.0.1", 8775, pid=4242, created=BOOT + 3000),
        tcp4("established", LAN, 51000, WEB, 443, pid=5000, created=BOOT + 5000.5),
        tcp4("time-wait", LAN, 51001, WEB, 443),
        tcp4("listening", "0.0.0.0", 49664, pid=800, created=BOOT + 2),
        tcp4("established", "127.0.0.1", 8775, "127.0.0.1", 51010, pid=4242, created=BOOT + 5100),
        tcp4("established", "127.0.0.1", 51010, "127.0.0.1", 8775, pid=5000, created=BOOT + 5100)),
    "tcp6": table(
        tcp6("listening", "::", 135, pid=1200, created=BOOT + 1, tag=196),
        tcp6("established", f"::ffff:{LAN}", 8443, f"::ffff:{PEER}", 50123, pid=4242, created=BOOT + 5200),
        tcp6("established", LAN6, 51002, WEB6, 443, pid=5000, created=BOOT + 5300)),
    "udp4": table(
        udp4("0.0.0.0", 5353, pid=5000, created=BOOT + 5010),
        udp4("0.0.0.0", 53, pid=1300, created=BOOT + 20, tag=77),
        udp4("0.0.0.0", 5353, pid=5000, created=BOOT + 5005),
        udp4(LAN, 137, pid=4, created=BOOT + 16),
        udp4("0.0.0.0", 5353, pid=5000, created=BOOT + 5020)),
    "udp6": table(
        udp6("::", 5353, pid=5000, created=BOOT + 5011),
        udp6("fe80::1", 546, pid=1400, created=BOOT + 30),
        udp6("::", 5353, pid=5000, created=BOOT + 5012)),
}
NAMES = {0: "[System Process]", 4: "System", 800: "lsass.exe", 1200: "svchost.exe", 1300: "svchost.exe",
         1400: "svchost.exe", 4242: "python.exe", 5000: "msedge.exe"}
IMAGES = {4242: (PYTHON, BOOT + 2990, 0), 5000: (EDGE, BOOT + 4000, 0)}  # the others refuse their handle: error 5
MODULES = {(4242, 0): (0, "python.exe", PYTHON), (5000, 0): (0, "msedge.exe", EDGE),
           (1200, 196): (0, "RpcEptMapper", "RpcEptMapper"), (1300, 77): (0, "Dnscache", "Dnscache")}
SERVICES = {1200: [("RpcEptMapper", "RPC Endpoint Mapper"), ("RpcSs", "Remote Procedure Call (RPC)")],
            1300: [("Dnscache", "DNS Client")], 1400: [("Dhcp", "DHCP Client")],
            800: [("VaultSvc", "Credential Manager"), ("KeyIso", "CNG Key Isolation"),
                  ("SamSs", "Security Accounts Manager")]}


class FakeApi:
    """Windows' calls stood in for: each table as the bytes Windows would write (or the error it fails with), the
    snapshot's names, each process's image, each row's owner module by its pid and tag, the services. Every call is
    noted."""

    def __init__(self, tables=None, names=None, images=None, modules=None, services=None, services_error=0,
                 elevated=False, awake=56_000.0):
        self.tables = dict(TABLES if tables is None else tables)
        self.program_names = dict(NAMES if names is None else names)
        self.images = dict(IMAGES if images is None else images)
        self.modules = dict(MODULES if modules is None else modules)
        self.hosted = dict(SERVICES if services is None else services)
        self.services_error, self.is_elevated, self.awake_s = services_error, elevated, awake
        self.calls: list[tuple] = []

    def table(self, name):
        self.calls.append(("table", name))
        found = self.tables.get(name, table())
        return (found, []) if isinstance(found, int) else (0, sockets.decode(name, found))

    def names(self):
        self.calls.append(("names",))
        return dict(self.program_names)

    def image(self, pid):
        self.calls.append(("image", pid))
        return self.images.get(pid, ("", None, 5))

    def owner(self, name, raw):
        assert isinstance(raw, sockets.LAYOUTS[name])  # the row itself, as its table gave it
        key = (int(raw.pid), int(raw.owning[0]) & 0xFFFFFFFF)
        self.calls.append(("owner", name, *key))
        return self.modules.get(key, (5, "", ""))

    def services(self):
        self.calls.append(("services",))
        return ({}, self.services_error) if self.services_error else (dict(self.hosted), 0)

    def awake(self):
        return self.awake_s

    def elevated(self):
        return self.is_elevated

    def asked(self, what: str) -> list[tuple]:
        return [call[1:] for call in self.calls if call[0] == what]


class FakeIphlpapi:
    """iphlpapi's two table calls as Windows answers them: asked with no buffer, or one too small, they say the size
    and answer 122; asked with room enough, they write the table's bytes. `grow`: bytes the table grows by at each
    call after the first; `status`: Windows' error, answered at once. Every call is noted: (table, the buffer's
    size, the size said, the order, the class, the reserved word)."""

    def __init__(self, tables=None, grow=0, status=0):
        self.tables = dict(TABLES if tables is None else tables)
        self.grow, self.status, self.calls = grow, status, []

    def _answer(self, proto, buf, size_ref, order, family, kind, reserved):
        name = f"{proto}{6 if family == sockets.AF_INET6 else 4}"
        size = size_ref._obj  # what ctypes.byref points at: the call's own U32
        self.calls.append((name, None if buf is None else len(buf), size.value, order, kind, reserved))
        if self.status:
            return self.status
        data = self.tables.get(name, table()) + bytes(self.grow * (len(self.calls) - 1))
        if buf is None or size.value < len(data):
            size.value = len(data)
            return sockets.ERROR_INSUFFICIENT_BUFFER
        ctypes.memmove(buf, data, len(data))
        size.value = len(data)
        return 0

    def GetExtendedTcpTable(self, *args):  # noqa: N802 - Windows' own name
        return self._answer("tcp", *args)

    def GetExtendedUdpTable(self, *args):  # noqa: N802 - Windows' own name
        return self._answer("udp", *args)


class Shell:
    """shell32's one call a reading makes: whether this process is an administrator's."""

    def __init__(self, answer: int):
        self.answer = answer

    def IsUserAnAdmin(self):  # noqa: N802 - Windows' own name
        return self.answer


class RealApi(sockets.WindowsApi):
    """The real WindowsApi, its libraries stood in for (`libraries`, by name; one not given is not there): its own
    table() and elevated(); the snapshot, the images, the owner modules and the services are a FakeApi's."""

    def __init__(self, libraries, fake=None):
        super().__init__()
        self.libraries, self.fake = libraries, FakeApi() if fake is None else fake

    def _library(self, name):
        if name not in self.libraries:
            raise OSError(f"no {name} here")
        return self.libraries[name]

    def names(self):
        return self.fake.names()

    def image(self, pid):
        return self.fake.image(pid)

    def owner(self, name, raw):
        return self.fake.owner(name, raw)

    def services(self):
        return self.fake.services()

    def awake(self):
        return self.fake.awake()

    def elevated(self):
        return self.fake.elevated()


def reading(api=None, owners=None, at=NOW):
    return sockets.read_windows(FakeApi() if api is None else api, owners=Owners() if owners is None else owners,
                                clock=lambda: at)


def one(rows, proto, local_port, remote_port=0, family=None):
    """The one row of a protocol on a local port (and to a remote port, and of a family, when given)."""
    found = [r for r in rows if (r["proto"], r["local_port"], r["remote_port"]) == (proto, local_port, remote_port)
             and family in (None, r["family"])]
    assert len(found) == 1, found
    return found[0]


# -- the layouts -------------------------------------------------------------------------------------------------------
def test_the_rows_are_laid_out_as_windows_lays_them_out_on_every_system():
    offsets = {
        "tcp4": {"state": 0, "local": 4, "local_port": 8, "remote": 12, "remote_port": 16, "pid": 20, "created": 24,
                 "owning": 32},
        "tcp6": {"local": 0, "local_scope": 16, "local_port": 20, "remote": 24, "remote_scope": 40, "remote_port": 44,
                 "state": 48, "pid": 52, "created": 56, "owning": 64},
        "udp4": {"local": 0, "local_port": 4, "pid": 8, "created": 16, "flags": 24, "owning": 32},
        "udp6": {"local": 0, "local_scope": 16, "local_port": 20, "pid": 24, "created": 32, "flags": 40, "owning": 48}}
    assert tuple(sockets.LAYOUTS) == sockets.TABLES == ("tcp4", "tcp6", "udp4", "udp6")
    assert sockets.SIZES == {"tcp4": 160, "tcp6": 192, "udp4": 160, "udp6": 176} and sockets.ROWS_AT == 8
    for name, layout in sockets.LAYOUTS.items():
        assert ctypes.sizeof(layout) == sockets.SIZES[name], name
        for field, offset in offsets[name].items():
            assert getattr(layout, field).offset == offset, (name, field)
        sizes = {field: getattr(layout, field).size for field in offsets[name]}
        assert sizes.pop("created") == 8 and sizes.pop("owning") == 16 * 8  # a FILETIME; TCPIP_OWNING_MODULE_SIZE
        wide = {"local", "remote"} if name.endswith("6") else set()
        assert all(size == (16 if field in wide else 4) for field, size in sizes.items()), (name, sizes)
    # each helper writes exactly one row, so the tables below are Windows' bytes
    assert [len(row) for row in (tcp4("listening", "0.0.0.0", 1), tcp6("listening", "::", 1), udp4("0.0.0.0", 1),
                                 udp6("::", 1))] == [160, 192, 160, 176]
    # what the owner module and the services' listing come back as: pointers, so their size is the system's
    pointer = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(sockets._Module) == 2 * pointer and sockets._Module.path.offset == pointer
    assert sockets._Service.pid.offset == 2 * pointer + 7 * 4  # dwProcessId: the status's eighth DWORD
    assert ctypes.sizeof(sockets._Service) == (56 if pointer == 8 else 44)
    # fixed widths only: a DWORD of ctypes.wintypes is 8 bytes on a 64-bit Linux
    source = inspect.getsource(sockets)
    assert "wintypes." not in source and "import wintypes" not in source and "c_ulong" not in source


def test_a_table_whose_rows_are_another_size_is_not_believed(monkeypatch):
    api = sockets.WindowsApi()
    monkeypatch.setitem(sockets.SIZES, "udp6", 168)  # as if Windows documented another row
    assert api.table("udp6") == (BAD_LAYOUT, [])  # said before anything of Windows' is loaded
    with pytest.raises(ValueError, match="cannot hold the 3 rows of 160 bytes"):
        sockets.decode("tcp4", struct.pack("<II", 3, 0) + tcp4("listening", "0.0.0.0", 80) * 2)
    with pytest.raises(ValueError, match="no table"):
        sockets.decode("tcp4", b"\x01")
    assert sockets.decode("udp4", struct.pack("<I", 0)) == [] and sockets.decode("tcp6", table()) == []


# -- the real call, over a stand-in iphlpapi ---------------------------------------------------------------------------
def test_the_real_table_call_asks_the_size_first_and_tries_three_times(monkeypatch):
    fake = FakeIphlpapi()
    status, rows = RealApi({"iphlpapi": fake}).table("tcp6")
    assert status == 0 and [r["local_port"] for r in rows] == [135, 8443, 51002]
    size = len(TABLES["tcp6"]) + sockets.SLACK  # what was said, and room for rows that come in between
    assert fake.calls == [("tcp6", None, 0, 0, 8, 0), ("tcp6", size, size, 0, 8, 0)]  # unsorted, OWNER_MODULE_ALL
    fake = FakeIphlpapi()
    assert [r["local_port"] for r in RealApi({"iphlpapi": fake}).table("udp4")[1]] == [5353, 53, 5353, 137, 5353]
    assert [call[4] for call in fake.calls] == [2, 2]  # UDP's own class, UDP_TABLE_OWNER_MODULE
    # a table that grows in between: within the room given, read; past it at every call, given up after three tries
    assert RealApi({"iphlpapi": FakeIphlpapi(grow=sockets.SLACK)}).table("tcp4")[0] == 0
    fake = FakeIphlpapi(grow=sockets.SLACK + 1)
    assert RealApi({"iphlpapi": fake}).table("tcp4") == (sockets.ERROR_INSUFFICIENT_BUFFER, []) and len(fake.calls) == 4
    # Windows' own error; a table larger than a reading takes, refused before anything is made for it; no library
    assert RealApi({"iphlpapi": FakeIphlpapi(status=87)}).table("tcp4") == (87, [])
    monkeypatch.setattr(sockets, "MAX_TABLE", len(TABLES["tcp4"]) - 1)
    fake = FakeIphlpapi()
    assert RealApi({"iphlpapi": fake}).table("tcp4") == (TOO_LARGE, []) and len(fake.calls) == 1
    assert RealApi({}).table("tcp4") == (sockets.ERROR_MOD_NOT_FOUND, [])
    # rows that do not fit the bytes they say they are in, the room given included: none is believed
    lying = struct.pack("<II", 1000, 0) + tcp4("listening", "0.0.0.0", 80)
    assert RealApi({"iphlpapi": FakeIphlpapi({"tcp4": lying})}).table("tcp4") == (BAD_LAYOUT, [])


def test_one_row_more_than_a_reading_keeps_is_handed_over_and_the_table_is_then_not_whole(monkeypatch):
    monkeypatch.setattr(sockets, "MAX_ROWS", 3)
    mdns = [udp4("0.0.0.0", 5353, pid=5000, created=BOOT + 9)] * 4
    fake = FakeIphlpapi({"udp4": table(*mdns, udp4("0.0.0.0", 9999, pid=4242, created=BOOT + 9))})
    assert [r["local_port"] for r in RealApi({"iphlpapi": fake}).table("udp4")[1]] == [5353] * 4  # MAX_ROWS + 1
    # those four fold into one row: what came after them (port 9999) was never handed over, so the table was not
    # read whole and the reading was cut, though it holds fewer rows than it may
    found = sockets.read_windows(RealApi({"iphlpapi": fake}), owners=Owners(), clock=lambda: NOW)
    assert [(r["local_port"], r["count"]) for r in found["rows"]] == [(5353, 4)]
    assert found["cut"] is True and found["read"] == ("tcp4", "tcp6", "udp6")
    assert found["notes"][-1] == sockets.CUT_NOTE


# -- the tables decoded ------------------------------------------------------------------------------------------------
def test_ports_addresses_starts_and_tags_are_decoded():
    rows = sockets.decode("tcp4", TABLES["tcp4"])
    assert [(r["state"], r["local"], r["local_port"], r["remote"], r["remote_port"], r["pid"]) for r in rows] == [
        ("listening", "0.0.0.0", 135, "", 0, 1200),  # a listener has no remote
        ("listening", "0.0.0.0", 445, "", 0, 4),
        ("listening", "127.0.0.1", 8775, "", 0, 4242),
        ("established", LAN, 51000, WEB, 443, 5000),
        ("time-wait", LAN, 51001, WEB, 443, 0),
        ("listening", "0.0.0.0", 49664, "", 0, 800),
        ("established", "127.0.0.1", 8775, "127.0.0.1", 51010, 4242),
        ("established", "127.0.0.1", 51010, "127.0.0.1", 8775, 5000)]
    assert port(443) == 0xBB01 and sockets._port(0xBB01) == 443 == socket.ntohs(0xBB01)  # network order, low 16 bits
    assert sockets._port(0xFFFF0000 | port(8775)) == 8775  # the high bits are not the port's
    assert [r["tag"] for r in rows] == [196, 0, 0, 0, 0, 0, 0, 0]
    assert rows[3]["created"] == filetime(BOOT + 5000.5) and rows[4]["created"] == 0  # as Windows gives it
    assert sockets._epoch(rows[3]["created"]) == BOOT + 5000.5 and sockets._epoch(0) is None
    assert isinstance(rows[0]["raw"], sockets.Tcp4Row) and rows[0]["raw"].pid == 1200
    assert set(rows[0]) == {"state", "local", "local_port", "remote", "remote_port", "pid", "created", "tag", "raw"}
    # the tag is the low 32 bits of OwningModuleInfo[0]
    high = sockets.decode("tcp4", table(tcp4("listening", "0.0.0.0", 80, pid=9, tag=(7 << 32) | 196)))
    assert high[0]["tag"] == 196
    # a state Windows adds later is said by its number; a remote of all zeroes is none, whatever the state
    odd = bytearray(tcp4("closed", LAN, 51003))
    odd[0:4] = struct.pack("<I", 99)
    assert [(r["state"], r["remote"]) for r in sockets.decode("tcp4", table(bytes(odd)))] == [("99", "")]
    assert [r["local_port"] for r in sockets.decode("tcp4", TABLES["tcp4"], 2)] == [135, 445]  # `most` rows alone
    # a ctypes buffer, as the real call fills it, reads the same
    buffer = ctypes.create_string_buffer(TABLES["tcp4"], len(TABLES["tcp4"]))
    assert [r["local_port"] for r in sockets.decode("tcp4", buffer)] == [r["local_port"] for r in rows]


def test_ipv6_rows_and_an_ipv4_peer_in_the_ipv6_table():
    rows = sockets.decode("tcp6", TABLES["tcp6"])
    assert [(r["state"], r["local"], r["local_port"], r["remote"], r["remote_port"], r["pid"]) for r in rows] == [
        ("listening", "::", 135, "", 0, 1200),
        ("established", LAN, 8443, PEER, 50123, 4242),  # ::ffff:192.168.1.20 and ::ffff:192.168.1.7, said as IPv4
        ("established", LAN6, 51002, WEB6, 443, 5000)]
    assert rows[0]["tag"] == 196 and sockets._epoch(rows[2]["created"]) == BOOT + 5300
    found = one(reading()["rows"], "tcp", 8443, 50123)
    assert (found["family"], found["local"], found["remote"]) == (6, LAN, PEER)  # its family stays its table's


def test_udp_rows_are_bound_and_have_no_remote():
    rows = sockets.decode("udp4", TABLES["udp4"])
    assert [(r["state"], r["local"], r["local_port"], r["remote"], r["remote_port"], r["pid"], r["tag"])
            for r in rows] == [
        ("bound", "0.0.0.0", 5353, "", 0, 5000, 0), ("bound", "0.0.0.0", 53, "", 0, 1300, 77),
        ("bound", "0.0.0.0", 5353, "", 0, 5000, 0), ("bound", LAN, 137, "", 0, 4, 0),
        ("bound", "0.0.0.0", 5353, "", 0, 5000, 0)]
    assert sockets._epoch(rows[1]["created"]) == BOOT + 20  # read past the padding
    six_rows = sockets.decode("udp6", TABLES["udp6"])
    assert [(r["local"], r["local_port"], r["pid"]) for r in six_rows] == [("::", 5353, 5000), ("fe80::1", 546, 1400),
                                                                           ("::", 5353, 5000)]
    assert sockets._epoch(six_rows[1]["created"]) == BOOT + 30 and isinstance(six_rows[0]["raw"], sockets.Udp6Row)


# -- a reading ---------------------------------------------------------------------------------------------------------
def test_a_reading_names_the_program_behind_each_socket():
    api = FakeApi()
    found = reading(api)
    assert list(found) == ["system", "at", "awake", "took", "root", "starts", "read", "cut", "rows", "notes"]
    assert (found["system"], found["at"], found["awake"], found["root"], found["starts"]) == ("windows", NOW, 56_000.0,
                                                                                               False, True)
    assert found["read"] == ("tcp4", "tcp6", "udp4", "udp6") and found["cut"] is False and found["took"] >= 0
    assert found["notes"] == [
        "Windows lists no remote host for a UDP socket: UDP shows as ports only.",
        "Read as not an administrator: every socket and its program's name are read either way."]
    rows = found["rows"]
    assert all(list(r) == KEYS for r in rows) and len(rows) == 8 + 3 + 3 + 2
    assert [(r["proto"], r["family"]) for r in rows] == [("tcp", 4)] * 8 + [("tcp", 6)] * 3 + [("udp", 4)] * 3 + \
        [("udp", 6)] * 2
    web = one(rows, "tcp", 51000, 443)
    assert web == {"proto": "tcp", "family": 4, "state": "established", "local": LAN, "local_port": 51000,
                   "remote": WEB, "remote_port": 443, "pid": 5000, "pids": [5000], "program": "msedge.exe",
                   "path": EDGE, "service": "", "service_title": "", "user": "", "started": BOOT + 5000.5,
                   "process_started": BOOT + 4000, "count": 1, "inode": 0, "seen": BOOT + 5000.5, "unread": {}}
    listener = one(rows, "tcp", 8775)
    assert (listener["state"], listener["remote"], listener["program"], listener["path"]) == ("listening", "",
                                                                                              "python.exe", PYTHON)
    assert listener["started"] == BOOT + 3000 and listener["process_started"] == BOOT + 2990
    assert all(r["inode"] == 0 and r["user"] == "" for r in rows)  # Linux's alone
    assert all(r["seen"] == r["started"] for r in rows if r["started"] is not None)
    json.dumps(found, allow_nan=False)  # a page can send it as it is: no row keeps its table's bytes
    # the tables first, then the snapshot (a process missing from it has ended since), then the services
    order = [call[0] for call in api.calls if call[0] in ("table", "names", "services")]
    assert order == ["table"] * 4 + ["names", "services"]


def test_udps_repeats_are_folded_into_one_row_that_counts_them():
    rows = reading()["rows"]
    mdns = one(rows, "udp", 5353, family=4)
    assert (mdns["state"], mdns["count"], mdns["program"], mdns["remote"]) == ("bound", 3, "msedge.exe", "")
    assert mdns["started"] == mdns["seen"] == BOOT + 5005  # since the oldest of the three
    assert one(rows, "udp", 5353, family=6)["count"] == 2 and one(rows, "udp", 5353, family=6)["started"] == BOOT + 5011
    assert one(rows, "udp", 53)["count"] == 1 and all(r["count"] == 1 for r in rows if r["proto"] == "tcp")
    # the same port held by another process, or by another service of the same process, is a row of its own
    api = FakeApi(tables={"udp4": table(udp4("0.0.0.0", 5353, pid=5000), udp4("0.0.0.0", 5353, pid=4242),
                                        udp4("0.0.0.0", 5353, pid=1300, tag=77),
                                        udp4("0.0.0.0", 5353, pid=1300, tag=78),
                                        udp4("127.0.0.1", 5353, pid=5000), udp4("0.0.0.0", 5353, pid=4242))})
    assert [(r["pid"], r["local"], r["count"]) for r in reading(api)["rows"]] == [
        (5000, "0.0.0.0", 1), (4242, "0.0.0.0", 2), (1300, "0.0.0.0", 1), (1300, "0.0.0.0", 1), (5000, "127.0.0.1", 1)]


def test_what_a_row_cannot_read_is_said_in_words():
    rows = reading()["rows"]
    waiting = one(rows, "tcp", 51001, 443)  # pid 0: both ends are kept, the owner is gone
    assert (waiting["pid"], waiting["pids"], waiting["program"], waiting["started"]) == (0, [], "", None)
    assert waiting["unread"] == {"program": "its owner has ended: the connection is only waiting to close"}
    assert waiting["seen"] == NOW  # Windows gives it no start: when it was first listed
    for system in (one(rows, "tcp", 445), one(rows, "udp", 137)):  # pid 4
        assert (system["program"], system["path"], system["pids"]) == ("System", "", [4])
        assert system["unread"] == {
            "service": "Windows itself holds it (pid 4) for a driver or a service: the table does not say which",
            "path": "Windows' own kernel process: no program file is named for it"}
    refused = one(rows, "tcp", 135, family=4)  # a service's process refuses its handle: error 5
    assert (refused["program"], refused["path"], refused["process_started"]) == ("svchost.exe", "", None)
    assert refused["unread"] == {"path": "Windows does not let this account read where this program is on disk (a "
                                 "service's or Windows' own process)"}
    several = one(rows, "tcp", 49664)  # no tag on the row, and its process hosts three services
    assert (several["program"], several["service"], several["service_title"]) == ("lsass.exe", "", "")
    assert several["unread"] == {
        "service": "one of the 3 services of this process (KeyIso, SamSs, VaultSvc): the table does not say which",
        "path": sockets.REFUSED}
    # rows share no `unread`: changing one row's leaves the next reading's alone
    owners = Owners()
    first = reading(owners=owners)["rows"]
    one(first, "tcp", 135, family=4)["unread"]["path"] = "changed"
    assert one(reading(owners=owners)["rows"], "tcp", 135, family=4)["unread"] == {"path": sockets.REFUSED}


def test_a_process_that_ended_meanwhile_and_one_windows_says_nothing_of():
    tables = {"tcp4": table(tcp4("fin-wait-2", LAN, 51005, WEB, 443, pid=6000, created=BOOT + 9),
                            tcp4("established", LAN, 51006, WEB, 443, pid=6001, created=BOOT + 9),
                            tcp4("listening", "0.0.0.0", 9000, pid=6002, created=BOOT + 9),
                            tcp4("listening", "0.0.0.0", 9001)),
              "udp4": table(udp4("0.0.0.0", 9002))}
    api = FakeApi(tables, names={6001: "odd.exe", 6002: "many.exe"}, modules={},
                  images={6000: ("", BOOT + 5, 31), 6001: ("", None, 31), 6002: ("C:\\many.exe", BOOT, 0)},
                  services={6002: [(f"Svc{n:02}", f"Service {n}") for n in range(11)]})
    rows = reading(api)["rows"]
    ended = one(rows, "tcp", 51005, 443)  # exited, and no longer in the snapshot taken after the tables
    assert (ended["pid"], ended["program"], ended["path"], ended["process_started"]) == (6000, "", "", BOOT + 5)
    assert ended["unread"] == {"program": "no process 6000 is listed any more: it ended while the table was read"}
    odd = one(rows, "tcp", 51006, 443)  # neither refused nor answered
    assert odd["program"] == "odd.exe" and odd["unread"] == {"path": "Windows did not say where this program is on "
                                                             "disk (error 31)"}
    many = one(rows, "tcp", 9000)
    assert many["unread"] == {"service": "one of the 11 services of this process (Svc00, Svc01, Svc02, Svc03, Svc04, "
                              "Svc05, Svc06, Svc07 and 3 more): the table does not say which"}
    # a row with no remote and no owner: never seen on this PC, and not said to be closing
    for nobody in (one(rows, "tcp", 9001), one(rows, "udp", 9002)):
        assert nobody["pid"] == 0 and nobody["unread"] == {"program": "Windows names no process for it"}
    # the snapshot itself not read: a program is named from its path, and the reading says so
    api = FakeApi(tables, names={}, modules={(6002, 0): (0, "many.exe", "C:\\many.exe")}, images={}, services={})
    found = sockets.read_windows(api, owners=Owners(), clock=lambda: NOW)
    assert one(found["rows"], "tcp", 9000)["program"] == "many.exe" and sockets.NO_PROCESSES_NOTE in found["notes"]
    assert one(found["rows"], "tcp", 51006, 443)["unread"] == {"program": "Windows' list of processes could not be "
                                                               "read here"}


def test_a_tagged_socket_names_its_service_and_an_untagged_one_its_process_one_service():
    api = FakeApi()
    rows = reading(api)["rows"]
    for tagged in (one(rows, "tcp", 135, family=4), one(rows, "tcp", 135, family=6)):  # tag 196, of two services there
        assert (tagged["program"], tagged["service"], tagged["service_title"]) == ("svchost.exe", "RpcEptMapper",
                                                                                   "RPC Endpoint Mapper")
        assert "service" not in tagged["unread"]
    dns = one(rows, "udp", 53)
    assert (dns["service"], dns["service_title"], dns["count"]) == ("Dnscache", "DNS Client", 1)
    dhcp = one(rows, "udp", 546)  # no tag: the one service its process hosts
    assert (dhcp["program"], dhcp["service"], dhcp["service_title"]) == ("svchost.exe", "Dhcp", "DHCP Client")
    assert one(rows, "tcp", 8775)["service"] == ""  # a program of the user's hosts none
    # the service's short name is the owner module of the tagged row, asked with the row itself
    assert ("tcp4", 1200, 196) in api.asked("owner") and ("udp4", 1300, 77) in api.asked("owner")
    # the services not listed (a platform started before anyone signed in): the tag still names its service
    api = FakeApi(services_error=5)
    found = reading(api)
    assert found["notes"][-1] == ("The services could not be listed (error 5): a service's process shows by its "
                                  "program alone.")
    tagged = one(found["rows"], "tcp", 135, family=4)
    assert (tagged["service"], tagged["service_title"]) == ("RpcEptMapper", "")
    assert one(found["rows"], "udp", 546)["service"] == "" and one(found["rows"], "tcp", 49664)["unread"] == {
        "path": sockets.REFUSED}
    # a tag the owner module does not name: the process's one service, or the words for several, or the error
    api = FakeApi(modules={})
    rows = reading(api)["rows"]
    assert one(rows, "udp", 53)["service"] == "Dnscache"
    assert one(rows, "tcp", 135, family=4)["unread"]["service"] == (
        "one of the 2 services of this process (RpcEptMapper, RpcSs): the table does not say which")
    rows = reading(FakeApi(modules={}, services={}))["rows"]
    assert one(rows, "udp", 53)["unread"]["service"] == "Windows did not name the service behind it (error 5)"


def test_an_owner_module_that_answers_nothing_falls_back_to_the_image():
    # Windows' documentation has an administrator who is not elevated get empty strings: the image still says the path
    api = FakeApi(modules={(4242, 0): (0, "", ""), (5000, 0): (1168, "", "")})
    rows = reading(api)["rows"]
    assert one(rows, "tcp", 8775)["path"] == PYTHON and one(rows, "tcp", 8775)["unread"] == {}
    assert one(rows, "tcp", 51000, 443)["path"] == EDGE and one(rows, "tcp", 51000, 443)["program"] == "msedge.exe"
    # and the other way about: the image refused, the owner module answering
    api = FakeApi(images={})
    rows = reading(api)["rows"]
    assert (one(rows, "tcp", 8775)["path"], one(rows, "tcp", 8775)["process_started"]) == (PYTHON, None)
    # what the owner module calls a path must be one: a name alone is not taken for it
    api = FakeApi(modules={(4242, 0): (0, "python.exe", "python.exe")}, images={4242: ("", None, 5)})
    assert one(reading(api)["rows"], "tcp", 8775)["unread"] == {"path": sockets.REFUSED}


def test_a_table_that_fails_is_noted_the_rest_is_read_and_read_leaves_it_out():
    api = FakeApi({**TABLES, "tcp6": 5})
    found = reading(api)
    assert found["read"] == ("tcp4", "udp4", "udp6") and found["cut"] is False
    assert found["notes"][2:] == ["Windows' TCP (IPv6) table could not be read here (error 5)"]
    assert {(r["proto"], r["family"]) for r in found["rows"]} == {("tcp", 4), ("udp", 4), ("udp", 6)}
    assert len(found["rows"]) == 8 + 3 + 2
    api = FakeApi({**TABLES, "udp4": BAD_LAYOUT, "udp6": TOO_LARGE, "tcp4": 87})
    found = reading(api)
    assert found["read"] == ("tcp6",) and found["notes"][2:] == [
        "Windows' TCP (IPv4) table could not be read here (error 87)",
        "Windows' UDP (IPv4) table could not be read here (its rows are not laid out as this reader expects)",
        "Windows' UDP (IPv6) table could not be read here (it is larger than the 16 MB a reading takes)"]
    # none of the four: no rows, nothing else asked
    api = FakeApi(dict.fromkeys(sockets.TABLES, 5))
    found = reading(api)
    assert found["rows"] == [] and found["read"] == () and len(found["notes"]) == 2 + 4
    assert api.asked("names") == [] and api.asked("services") == []


def test_owners_are_kept_through_a_reading_that_missed_a_table():
    owners, api = Owners(), FakeApi()
    reading(api, owners)
    asked = len(api.asked("image"))
    assert asked == len(owners) == 6  # 1200 with its tag, 800, 4242, 5000, 1300 with its tag, 1400: no pid 0 or 4
    api.tables["tcp4"] = 5  # one table fails: what it alone listed may still be there, so nothing is dropped
    assert reading(api, owners)["read"] == ("tcp6", "udp4", "udp6") and len(owners) == 6
    api.tables["tcp4"] = TABLES["tcp4"]
    reading(api, owners)
    assert len(api.asked("image")) == asked  # and nobody is asked for again


def test_owners_go_with_their_table_while_another_table_fails_at_every_reading():
    owners, api = Owners(), FakeApi({**TABLES, "tcp6": 5})
    reading(api, owners)
    assert len(owners) == 6
    # tcp4 read whole again, with only the python listener: the owners it alone listed (svchost's RPC listener, whose
    # tcp6 socket was never read, and lsass) are gone, though tcp6 is never read whole
    api.tables["tcp4"] = table(tcp4("listening", "127.0.0.1", 8775, pid=4242, created=BOOT + 3000))
    reading(api, owners, at=NOW + 3)
    assert len(owners) == 4
    asked = len(api.asked("image"))
    api.tables["tcp4"] = TABLES["tcp4"]
    reading(api, owners, at=NOW + 6)
    assert api.asked("image")[asked:] == [(1200,), (800,)]  # back, and asked for again
    # an owner listed last in a table that then failed stays, for it may still be there
    api.tables["tcp4"] = 5
    reading(api, owners, at=NOW + 9)
    assert len(owners) == 6


def test_when_the_owners_kept_are_full_the_one_listed_longest_ago_makes_room():
    owners = Owners(most=2)
    two = table(tcp4("listening", "127.0.0.1", 8775, pid=4242, created=BOOT + 3000),
                tcp4("established", LAN, 51000, WEB, 443, pid=5000, created=BOOT + 5000.5))
    api = FakeApi({"tcp4": two, "tcp6": table(), "udp4": table(), "udp6": table()})
    reading(api, owners)
    assert len(owners) == 2 and owners.asked == 2
    # tcp4 fails from now on, so its two owners stay; a new owner comes, and takes the place of the older
    api.tables.update({"tcp4": 5, "udp4": table(udp4("0.0.0.0", 53, pid=1300, created=BOOT + 20, tag=77))})
    for at in (NOW + 3, NOW + 6, NOW + 9):
        reading(api, owners, at=at)
    assert len(owners) == 2 and owners.asked == 3 and api.asked("image").count((1300,)) == 1  # asked once
    # one reading's own owners are never put out for each other: past the room, the next is asked again
    three = FakeApi({"tcp4": table(*(tcp4("listening", "0.0.0.0", 9000 + n, pid=7000 + n, created=BOOT + n)
                                     for n in range(3)))}, names={7000 + n: f"p{n}.exe" for n in range(3)})
    owners = Owners(most=2)
    reading(three, owners)
    reading(three, owners)
    assert owners.asked == 3 + 1 and three.asked("image")[3:] == [(7002,)]


def test_rows_past_the_most_are_cut_and_the_reading_says_so(monkeypatch):
    monkeypatch.setattr(sockets, "MAX_ROWS", 10)
    found = reading()
    assert len(found["rows"]) == 10 and found["cut"] is True
    assert found["read"] == ("tcp4",)  # the table the cut fell in and the ones after it were not read whole
    assert found["notes"][-1] == sockets.CUT_NOTE == ("More than 20,000 sockets are listed: the first 20,000 are read "
                                                     "and the rest left out.")
    monkeypatch.setattr(sockets, "MAX_ROWS", 11)  # exactly the two TCP tables: a table with nothing in it is whole
    found = reading(FakeApi({"tcp4": TABLES["tcp4"], "tcp6": TABLES["tcp6"]}))
    assert len(found["rows"]) == 11 and found["cut"] is False and found["read"] == sockets.TABLES
    owners = Owners()
    monkeypatch.setattr(sockets, "MAX_ROWS", 4)
    reading(owners=owners)
    kept = len(owners)
    monkeypatch.setattr(sockets, "MAX_ROWS", 1)  # a reading that was cut drops no owner either
    reading(owners=owners)
    assert len(owners) == kept > 0


def test_an_owner_is_asked_once_over_two_readings():
    owners, api = Owners(), FakeApi()
    first = reading(api, owners)
    images, modules = api.asked("image"), api.asked("owner")
    assert sorted(images) == [(800,), (1200,), (1300,), (1400,), (4242,), (5000,)] and owners.asked == 6
    assert len(modules) == 6  # one row of each owner, with its tag: not one for every row
    second = reading(api, owners, at=NOW + 3)
    assert api.asked("image") == images and api.asked("owner") == modules and owners.asked == 6
    assert [{**r, "seen": None} for r in second["rows"]] == [{**r, "seen": None} for r in first["rows"]]
    assert len(api.asked("names")) == 2  # the snapshot is each reading's: it says whose a pid is now
    # a new program is asked for; one whose sockets are gone is dropped, and asked again when it is back
    api.tables["tcp4"] = table(tcp4("listening", "0.0.0.0", 9100, pid=7000, created=NOW))
    api.program_names[7000] = "new.exe"
    api.images[7000] = ("C:\\new.exe", NOW - 1, 0)
    third = reading(api, owners, at=NOW + 6)
    assert one(third["rows"], "tcp", 9100)["path"] == "C:\\new.exe" and api.asked("image")[len(images):] == [(7000,)]
    assert len(owners) == 6  # 800 had its socket in that table alone: dropped, and the new one kept
    api.tables["tcp4"] = TABLES["tcp4"]
    reading(api, owners, at=NOW + 9)
    assert api.asked("image")[len(images) + 1:] == [(800,)] and len(owners) == 6
    # a pid that is another program now is another owner
    api.program_names[4242] = "other.exe"
    api.images[4242] = ("C:\\other.exe", NOW, 0)
    api.modules[(4242, 0)] = (0, "other.exe", "C:\\other.exe")
    again = reading(api, owners, at=NOW + 12)
    assert (one(again["rows"], "tcp", 8775)["program"], one(again["rows"], "tcp", 8775)["path"]) == ("other.exe",
                                                                                                    "C:\\other.exe")
    assert api.asked("image")[-1] == (4242,)


def test_a_pid_a_new_process_of_the_same_program_was_given_is_asked_for_again():
    owners = Owners()
    api = FakeApi({"tcp4": table(tcp4("listening", "127.0.0.1", 8775, pid=4242, created=BOOT + 3000))})
    assert one(reading(api, owners)["rows"], "tcp", 8775)["path"] == PYTHON
    # that python.exe ended, and another python.exe, from another folder, was given its pid: a socket made since it
    # was asked has its process's start asked, and a start that differs is another process
    api.tables["tcp4"] = table(tcp4("listening", "127.0.0.1", 9000, pid=4242, created=NOW + 1))
    api.images[4242] = ("C:\\venv-b\\python.exe", NOW + 0.5, 0)
    api.modules[(4242, 0)] = (0, "python.exe", "C:\\venv-b\\python.exe")
    again = one(reading(api, owners, at=NOW + 3)["rows"], "tcp", 9000)
    assert (again["path"], again["process_started"]) == ("C:\\venv-b\\python.exe", NOW + 0.5)
    # the same process making two sockets more: its start is asked once, and found the same, nothing else is
    images, modules = len(api.asked("image")), len(api.asked("owner"))
    api.tables["tcp4"] = table(tcp4("established", "127.0.0.1", 51000, "127.0.0.1", 9000, pid=4242, created=NOW + 4),
                               tcp4("established", "127.0.0.1", 51001, "127.0.0.1", 9000, pid=4242, created=NOW + 5),
                               tcp4("listening", "127.0.0.1", 9000, pid=4242, created=NOW + 1))
    reading(api, owners, at=NOW + 6)
    assert len(api.asked("image")) == images + 1 and len(api.asked("owner")) == modules and owners.asked == 2
    reading(api, owners, at=NOW + 9)  # no socket made since: nothing asked
    assert len(api.asked("image")) == images + 1
    # an older socket of the pid's listed first: the process that held it then holds it now, so nothing is asked
    api.tables["tcp4"] = table(tcp4("listening", "127.0.0.1", 9000, pid=4242, created=NOW + 1),
                               tcp4("established", "127.0.0.1", 51002, "127.0.0.1", 9000, pid=4242, created=NOW + 10))
    reading(api, owners, at=NOW + 12)
    assert len(api.asked("image")) == images + 1
    # a process whose start cannot be read (a service's) is not asked again: it could not be told apart that way
    api = FakeApi({"tcp4": table(tcp4("listening", "0.0.0.0", 49664, pid=800, created=BOOT + 2))})
    owners = Owners()
    reading(api, owners)
    api.tables["tcp4"] = table(tcp4("listening", "0.0.0.0", 49665, pid=800, created=NOW + 1))
    reading(api, owners, at=NOW + 3)
    assert api.asked("image") == [(800,)]


def test_owners_are_bounded_and_a_socket_without_a_start_keeps_when_it_was_first_seen():
    owners = Owners(most=2)
    api = FakeApi()
    reading(api, owners)
    assert len(owners) == 2 and owners.asked == 6
    reading(api, owners)
    assert len(owners) == 2 and owners.asked == 6 + 4  # the ones that found no room are asked again
    assert Owners().most == sockets.OWNERS == 2048 and Owners().rows == sockets.MAX_ROWS == 20_000
    # first seen, for the rows Windows gives no start: kept while the row is listed, dropped with it
    owners = Owners()
    assert one(reading(owners=owners, at=NOW)["rows"], "tcp", 51001, 443)["seen"] == NOW
    assert one(reading(owners=owners, at=NOW + 5)["rows"], "tcp", 51001, 443)["seen"] == NOW
    gone = FakeApi({**TABLES, "tcp4": table()})
    reading(gone, owners, at=NOW + 10)
    assert one(reading(owners=owners, at=NOW + 15)["rows"], "tcp", 51001, 443)["seen"] == NOW + 15
    small = Owners(rows=1)
    assert small.first("a", 1.0, "tcp4") == 1.0 and small.first("b", 2.0, "tcp4") == 2.0
    assert small.first("b", 3.0, "tcp4") == 3.0 and small.first("a", 9.0, "tcp4") == 1.0  # the one with room is kept


def test_a_connection_waiting_to_close_keeps_when_it_was_first_seen():
    owners = Owners()
    api = FakeApi({"tcp4": table(tcp4("established", LAN, 51000, WEB, 443, pid=5000, created=BOOT + 5000.5))})
    assert reading(api, owners)["rows"][0]["seen"] == BOOT + 5000.5
    # its program closed it: Windows lists it on with no owner and no start until it has closed for good
    api.tables["tcp4"] = table(tcp4("time-wait", LAN, 51000, WEB, 443))
    for at in (NOW + 3, NOW + 6):
        assert reading(api, owners, at=at)["rows"][0]["seen"] == BOOT + 5000.5
    # one never seen with a start is first seen when it is first listed
    api.tables["tcp4"] = table(tcp4("time-wait", LAN, 51000, WEB, 443), tcp4("time-wait", LAN, 51007, WEB, 443))
    assert [r["seen"] for r in reading(api, owners, at=NOW + 9)["rows"]] == [BOOT + 5000.5, NOW + 9]


def test_the_reading_says_how_long_the_system_was_awake_and_who_read_it():
    assert reading(FakeApi(awake=123.5))["awake"] == 123.5  # the clock that leaves sleep out, as Windows gives it
    found = reading(FakeApi(elevated=True))
    assert found["root"] is True and found["notes"][1] == (
        "Read as an administrator: every socket and its program's name are read either way.")

    class Five:
        """A stand-in with the plan's five methods alone."""
        def __init__(self):
            self.api = FakeApi()

        def __getattr__(self, name):
            if name in ("table", "names", "image", "owner", "services"):
                return getattr(self.api, name)
            raise AttributeError(name)
    found = sockets.read_windows(Five(), owners=Owners(), clock=lambda: NOW)
    assert found["root"] is False and found["awake"] > 0 and len(found["rows"]) == 16


def test_whether_it_reads_as_an_administrator_is_asked_of_shell32_itself():
    # shell32's own IsUserAnAdmin, loaded as the module's other libraries are: no other module of the library is
    # imported for it (machines.windows would bring in pandas with it)
    assert ELEVATED(RealApi({"shell32": Shell(1)})) is True
    assert ELEVATED(RealApi({"shell32": Shell(0)})) is False
    assert ELEVATED(RealApi({})) is False  # no shell32 here (another system): not an administrator
    tree = ast.parse(textwrap.dedent(inspect.getsource(ELEVATED)))
    assert not [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]


def test_read_takes_this_systems_reader_and_says_so_where_there_is_none(monkeypatch):
    api = FakeApi()
    for system in ("windows", "win32", "Windows"):
        found = READ(system, api=api, owners=Owners(), clock=lambda: NOW)
        assert found["system"] == "windows" and found["at"] == NOW and len(found["rows"]) == 16
    monkeypatch.setattr(sockets.sys, "platform", "win32")
    assert READ(api=api, owners=Owners())["system"] == "windows"
    kept = sockets.Owners()
    monkeypatch.setitem(sockets._SHARED, "windows", kept)  # with no owners given, the process's own are used
    READ(api=api)
    assert len(kept) == 6
    for system, name in (("darwin", "macOS"), ("freebsd14", "freebsd14")):
        found = READ(system, clock=lambda: NOW)
        assert found == {"system": "", "at": NOW, "awake": found["awake"], "took": 0.0, "root": False, "starts": False,
                         "read": (), "cut": False, "rows": [], "notes": [f"No socket table is read on {name}."]}
    monkeypatch.setattr(sockets.sys, "platform", "darwin")
    assert READ()["notes"] == ["No socket table is read on macOS."] and sockets.judge(READ()) == []


def test_only_documented_calls_are_made_and_the_module_names_them_all():
    source = inspect.getsource(sockets)
    made = set(re.findall(r"\b(?:library|k32|adv|shell)\.([A-Z]\w+)\b", source)) | set(sockets.OWNER_CALLS.values())
    # the program names come from the library's own snapshot of the processes, whose calls are a reading's too
    assert "self._probe.program_names()" in source
    assert "self._snapshot()" in inspect.getsource(resources.WindowsProbe.program_names)
    made |= set(re.findall(r"\bk32\.([A-Z]\w+)\b", inspect.getsource(resources.WindowsProbe._snapshot)))
    assert made == set(sockets.WINDOWS_CALLS) and len(sockets.WINDOWS_CALLS) == 18
    assert {"CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW", "IsUserAnAdmin"} <= made
    assert sockets.OWNER_CALLS == {"tcp4": "GetOwnerModuleFromTcpEntry", "tcp6": "GetOwnerModuleFromTcp6Entry",
                                   "udp4": "GetOwnerModuleFromUdpEntry", "udp6": "GetOwnerModuleFromUdp6Entry"}
    for undocumented in ("NtQuery", "ntdll", "I_QueryTagInformation", "GetPerTcpConnectionEStats"):
        assert undocumented not in source
    assert "WinDLL" not in "".join(line for line in source.splitlines() if not line.startswith(" "))  # none at import
    # no capture, no child process, no elevation, no name looked up, no address of anyone's
    for word in ("subprocess", "Popen", "runas", "ShellExecute", "gethostbyaddr", "getnameinfo", "pcap", "://"):
        assert word not in source, word
