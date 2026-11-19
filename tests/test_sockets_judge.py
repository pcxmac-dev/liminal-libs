"""What a socket reading's rows are judged to be (liminal_libs.sockets: judge, known_names, under_wsl; the user,
2026-11-16: "looking at active ports and what apps they are attached to, and the hosts that they connect to across the
lan or wan", "so i can view apps connected to hosts all across the globe, or ports talking to all hosts"): where each
remote host is (this machine, the local network, the internet), which way a connection goes, which port is the
service's, a place for an internet host alone, a name where the system's own hosts file has one, and the tab's table of
what running inside a WSL distribution changes. The rows are made here as the readers make them; the lookup of places
is a stand-in, and so are the hosts file and the kernel's release.

Nothing real is reached: no socket table, no hosts file of this machine's, no GeoIP file, no name server, no process
(this file's own fixture and the library's shared guard, `no_outside`, fail a test that does)."""
from __future__ import annotations

import ast
import inspect
import ipaddress
import json
import pathlib
import socket
import subprocess
import sys
import textwrap
import urllib.request

import pytest

from liminal_libs import geo, netpath, sockets

pytestmark = pytest.mark.usefixtures("no_outside")

HOSTS_TEXT = sockets._hosts_text  # the real reader of a hosts file, run on a file of the test's alone
LAN, LAN6, PEER = "192.168.1.20", "fd00:1::20", "192.168.1.7"
LONDON, CHANGCHUN, NUREMBERG6 = "81.2.69.142", "175.16.199.5", "2a01:4f8:c17:1::5"  # public addresses
PLACES = {LONDON: geo.Place("GB", "United Kingdom", "London", 51.5142, -0.0931),
          NUREMBERG6: geo.Place("DE", "Germany", "Nuremberg", 49.4478, 11.0683)}
WSL2, WSL1, OWN = "5.15.167.4-microsoft-standard-WSL2", "4.4.0-19041-Microsoft", "6.8.0-45-generic"


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch):
    """Nothing real is reached: no child process, no download, no socket, none of Windows' libraries, not this
    machine's /proc, its hosts file or its user (each reach is noted, so one that was caught is seen too)."""
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


def row(proto="tcp", local="0.0.0.0", local_port=0, remote="", remote_port=0, state="", **more) -> dict:
    """A row as the readers make one: a listener (a UDP socket: bound) without a remote, else a connection. Its
    family is its local address's, unless one is given (an IPv4 address in the IPv6 table: 6)."""
    state = state or ("established" if remote else "listening" if proto == "tcp" else "bound")
    made = sockets._row(proto, 6 if ":" in local else 4, state, local, local_port, remote, remote_port)
    made.update(more)
    return made


def judged(*rows, **more) -> list[dict]:
    return sockets.judge({"system": "windows", "rows": list(rows)}, **more)


def said(found: dict) -> tuple:
    return found["where"], found["direction"], found["port"]


LISTENERS = (row(local="0.0.0.0", local_port=443),  # on every IPv4 address
             row(local="127.0.0.1", local_port=8775),  # for this machine alone
             row(local=LAN, local_port=5000),  # on one address
             row(local="::", local_port=22),  # on every address of IPv6's table, IPv4's written as IPv6 too
             row("udp", "0.0.0.0", 53))


def test_the_plans_words_and_bounds():
    assert sockets.WHERE == ("this machine", "local network", "internet")
    assert sockets.UP == {"established", "close-wait", "fin-wait-1", "fin-wait-2", "closing", "last-ack"}
    assert (sockets.READ_S, sockets.MAX_ROWS, sockets.OWNERS, sockets.NAMES) == (2.5, 20_000, 2048, 4096)
    assert sockets.TABLES == ("tcp4", "tcp6", "udp4", "udp6")


def test_no_line_of_the_module_or_of_its_tests_is_longer_than_120_characters():
    here = pathlib.Path(__file__).parent
    paths = [pathlib.Path(sockets.__file__), *(here / f"test_sockets_{name}.py" for name in ("windows", "linux",
                                                                                            "judge"))]
    longer = [f"{path.name}:{n} ({len(line)})" for path in paths
              for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1) if len(line) > 120]
    assert longer == []


def test_where_each_remote_host_is():
    hosts = {"127.0.0.1": "this machine", "127.0.0.53": "this machine", "::1": "this machine",
             LAN: "this machine", LAN6: "this machine",  # this machine's own addresses: local ones of the reading
             PEER: "local network", "10.0.0.5": "local network", "172.29.152.1": "local network",
             "100.64.3.4": "local network",  # a carrier's shared addresses
             "169.254.7.7": "local network", "fe80::1": "local network", "fd00:1::7": "local network",
             "224.0.0.251": "local network", "ff02::fb": "local network", "255.255.255.255": "local network",
             "192.0.2.1": "local network",  # never a place on a globe
             LONDON: "internet", CHANGCHUN: "internet", NUREMBERG6: "internet", "8.8.8.8": "internet"}
    rows = [row(local=LAN6 if ":" in host else LAN, local_port=50000 + n, remote=host, remote_port=443)
            for n, host in enumerate(hosts)]
    found = judged(*rows)
    assert {r["remote"]: r["where"] for r in found} == hosts
    assert all(r["where"] in sockets.WHERE for r in found)
    # a socket without a remote is nowhere, and goes no way
    assert [said(r) for r in judged(*LISTENERS)] == [("", "", 443), ("", "", 8775), ("", "", 5000), ("", "", 22),
                                                     ("", "", 53)]
    # 0.0.0.0 and :: stand for every address, and are none of this machine's own: a remote written so is not taken
    # for this machine because a listener's local address is written the same way
    every = judged(row(local="0.0.0.0", local_port=9), row(local="::", local_port=9),
                   row(local=LAN, local_port=50000, remote="0.0.0.0", remote_port=53),
                   row(local=LAN6, local_port=50001, remote="::", remote_port=53))
    assert [r["where"] for r in every] == ["", "", "local network", "local network"]
    # both ends of a connection inside this machine are rows of the same reading, each the other's own address
    pair = judged(row(local=LONDON, local_port=51040, remote=LONDON, remote_port=443),
                  row(local=LONDON, local_port=443, remote=LONDON, remote_port=51040))
    assert [r["where"] for r in pair] == ["this machine", "this machine"]
    assert judged(row(local=LAN, local_port=51041, remote=LONDON, remote_port=443))[0]["where"] == "internet"


def test_judging_a_reading_needs_nothing_of_machines(monkeypatch):
    # machines' package brings pandas with it, and cannot be imported everywhere (a test that stands in for another
    # system's sys.platform): judge works without it
    monkeypatch.setitem(sys.modules, "liminal_libs.machines.world", None)  # an import of it would fail
    found = judged(row(local=LAN, local_port=51000, remote=LONDON, remote_port=443),
                   row(local=LAN, local_port=51004, remote=PEER, remote_port=445))
    assert [r["where"] for r in found] == ["internet", "local network"]
    for code in (sockets.judge, sockets._local):  # and it imports nothing at all
        tree = ast.parse(textwrap.dedent(inspect.getsource(code)))
        assert not [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))], code


def test_the_local_network_is_the_globes_own_test():
    # the globe keeps its test of what is never placed in machines.world (_local_peer): judge's is the same, read here
    # from world.py's own source (importing it would bring pandas)
    path = pathlib.Path(sockets.__file__).with_name("machines") / "world.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    peer = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_local_peer")
    space = {"ipaddress": ipaddress}
    exec(compile(ast.Module(body=[peer], type_ignores=[]), str(path), "exec"), space)
    addresses = ("127.0.0.1", "::1", LAN, PEER, "10.0.0.5", "172.29.152.1", "100.64.3.4", "169.254.7.7", "fe80::1",
                 "fe80::1%eth0", "fd00:1::7", "224.0.0.251", "ff02::fb", "255.255.255.255", "0.0.0.0", "::",
                 "240.0.0.1", "192.0.2.1", "198.51.100.7", "2001:db8::1", LONDON, CHANGCHUN, NUREMBERG6, "8.8.8.8",
                 "::ffff:81.2.69.142", "::ffff:192.168.1.7", "2606:4700::1111", "not-an-address", "")
    for address in addresses:
        globe = space["_local_peer"]({"network": netpath.kind(address), "address": address})
        assert sockets._local(address) == globe, address
    assert not sockets._local(LONDON) and sockets._local(PEER)


def test_which_way_a_connection_goes():
    cases = (
        (row(local=LAN, local_port=443, remote=LONDON, remote_port=50001), ("internet", "in", 443)),
        (row(local=LAN, local_port=51000, remote=CHANGCHUN, remote_port=443), ("internet", "out", 443)),
        # a listener for this machine alone on 8775 does not make a connection from the LAN address's port 8775 "in"
        (row(local=LAN, local_port=8775, remote="192.168.1.9", remote_port=445), ("local network", "out", 445)),
        (row(local=LAN, local_port=5000, remote=PEER, remote_port=50123), ("local network", "in", 5000)),  # its own
        (row(local="10.8.0.2", local_port=5000, remote="10.8.0.9", remote_port=50124),
         ("local network", "out", 50124)),
        # :: is every address of IPv6's table, the IPv4 ones it writes as IPv6 too; a socket of IPv4's own table
        # was never accepted by it (the tables list a connection in its listener's family)
        (row(local=LAN, local_port=22, remote=PEER, remote_port=50200, family=6), ("local network", "in", 22)),
        (row(local=LAN, local_port=22, remote=PEER, remote_port=50203), ("local network", "out", 50203)),
        (row(local=LAN6, local_port=22, remote=NUREMBERG6, remote_port=50201), ("internet", "in", 22)),
        # and 0.0.0.0 is every IPv4 address alone: an IPv6 connection on its port was not its
        (row(local=LAN6, local_port=443, remote=NUREMBERG6, remote_port=50202), ("internet", "out", 50202)),
        # the protocol counts: UDP's port 53 is listened on, TCP's is not
        (row("udp", LAN, 53, LONDON, 40000, "connected"), ("internet", "in", 53)),
        (row(local=LAN, local_port=53, remote=CHANGCHUN, remote_port=40001), ("internet", "out", 40001)),
        (row("udp", LAN, 40002, CHANGCHUN, 443, "connected"), ("internet", "out", 443)),
        # a connection only waiting to close is judged like any other: the table does not say who began
        (row(local=LAN, local_port=51050, remote=LONDON, remote_port=443, state="time-wait"),
         ("internet", "out", 443)),
        (row(local=LAN, local_port=443, remote=LONDON, remote_port=50002, state="time-wait"),
         ("internet", "in", 443)))
    found = judged(*LISTENERS, *(made for made, _ in cases))[len(LISTENERS):]
    assert [said(r) for r in found] == [expected for _, expected in cases]
    # without its listener in the reading, the same connection reads out
    assert said(judged(cases[0][0])[0]) == ("internet", "out", 50001)
    # a listener of IPv6's table on an IPv4 address written as IPv6 (::ffff:0.0.0.0, said as 0.0.0.0) holds that
    # table's connections on its port
    mapped = judged(row(local="0.0.0.0", local_port=8443, family=6),
                    row(local=LAN, local_port=8443, remote=PEER, remote_port=50300, family=6))
    assert said(mapped[1]) == ("local network", "in", 8443)


def test_on_this_machine_the_direction_is_local_and_the_port_the_listeners():
    found = judged(*LISTENERS,
                   row(local="127.0.0.1", local_port=8775, remote="127.0.0.1", remote_port=51010),  # the accepted end
                   row(local="127.0.0.1", local_port=51010, remote="127.0.0.1", remote_port=8775),  # the end that began
                   row(local=LAN, local_port=51020, remote=LAN, remote_port=443),  # to its own address
                   row(local=LAN, local_port=443, remote=LAN, remote_port=51020),
                   row(local="::1", local_port=51030, remote="::1", remote_port=9999))  # nobody listens there
    assert [said(r) for r in found[len(LISTENERS):]] == [
        ("this machine", "local", 8775), ("this machine", "local", 8775), ("this machine", "local", 443),
        ("this machine", "local", 443), ("this machine", "local", 9999)]


def test_a_place_for_an_internet_host_alone_asked_once_a_host():
    asked = []

    def places(address):
        asked.append(address)
        return PLACES.get(address)
    rows = [*LISTENERS,
            row(local=LAN, local_port=51000, remote=LONDON, remote_port=443),
            row(local=LAN, local_port=51001, remote=LONDON, remote_port=443),
            row(local=LAN, local_port=443, remote=LONDON, remote_port=50001),
            row(local=LAN6, local_port=51002, remote=NUREMBERG6, remote_port=443),
            row(local=LAN, local_port=51003, remote=CHANGCHUN, remote_port=443),  # no place known for it
            row(local=LAN, local_port=51004, remote=PEER, remote_port=445),
            row(local="127.0.0.1", local_port=51005, remote="127.0.0.1", remote_port=8775),
            row(local=LAN, local_port=51006, remote="224.0.0.251", remote_port=5353)]
    found = judged(*rows, places=places)
    assert asked == [LONDON, NUREMBERG6, CHANGCHUN]  # the internet's alone, and each host once
    assert [r["place"] for r in found[5:]] == [PLACES[LONDON]] * 3 + [PLACES[NUREMBERG6], None, None, None, None]
    assert all(r["place"] is None for r in found[:5]) and found[5]["place"].label == "London, United Kingdom"
    assert all(r["place"] is None for r in judged(*rows))  # no lookup given: no place, and nothing asked
    assert asked == [LONDON, NUREMBERG6, CHANGCHUN]


def test_a_name_where_the_hosts_file_has_one():
    names = {PEER: "nas", "127.0.0.1": "localhost", LONDON: "london.example", "0.0.0.0": "blocked.example"}
    found = judged(row(local=LAN, local_port=51004, remote=PEER, remote_port=445),
                   row(local="127.0.0.1", local_port=51005, remote="127.0.0.1", remote_port=8775),
                   row(local=LAN, local_port=51000, remote=LONDON, remote_port=443),
                   row(local=LAN, local_port=51003, remote=CHANGCHUN, remote_port=443),
                   row(local="0.0.0.0", local_port=443), names=names)
    assert [r["name"] for r in found] == ["nas", "localhost", "london.example", "", ""]
    assert [r["name"] for r in judged(row(local=LAN, local_port=1, remote=PEER, remote_port=2))] == [""]


def test_a_judged_row_is_the_row_and_five_keys_more_and_the_reading_stays_as_it_was():
    reading = {"system": "linux", "at": 5.0, "rows": [
        row(local="0.0.0.0", local_port=443, pid=10, pids=[10], program="nginx"),
        row(local=LAN, local_port=443, remote=LONDON, remote_port=50001, pid=11, pids=[10, 11], program="nginx",
            unread={"path": "not said"})]}
    before = json.dumps(reading, sort_keys=True)
    found = sockets.judge(reading, places=PLACES.get, names={LONDON: "london.example"})
    assert json.dumps(reading, sort_keys=True) == before
    for made, given in zip(found, reading["rows"]):
        assert made is not given and list(made) == [*given, "where", "direction", "port", "place", "name"]
        assert {key: made[key] for key in given} == given
    found[1]["unread"]["path"] = "changed"
    found[1]["pids"].append(12)
    assert reading["rows"][1]["unread"] == {"path": "not said"} and reading["rows"][1]["pids"] == [10, 11]
    assert (found[1]["where"], found[1]["direction"], found[1]["port"], found[1]["name"]) == ("internet", "in", 443,
                                                                                               "london.example")
    assert found[1]["place"] is PLACES[LONDON]
    assert sockets.judge({"rows": []}) == [] and sockets.judge({}) == []


# -- the names the system already knows --------------------------------------------------------------------------------
HOSTS = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#      102.54.94.97     rhino.acme.com          # source server
127.0.0.1       localhost
::1             localhost ip6-localhost ip6-loopback
192.168.1.7     nas nas.lan   # the storage box
192.168.1.7     other-name
0.0.0.0         blocked.example
fe80::1%eth0    router
[fd00:1::7]     bracketed
::ffff:192.168.1.9  mapped
not-an-address  name
10.0.0.1
   # an indented comment
\t2a01:4f8:c17:1::5\tNuremberg.Example\t
"""


def test_the_hosts_files_names():
    assert sockets.known_names(HOSTS) == {
        "127.0.0.1": "localhost", "::1": "localhost",  # the first name of a line
        "192.168.1.7": "nas",  # the first line that has an address
        "fe80::1": "router",  # written as the rows write addresses: no zone,
        "fd00:1::7": "bracketed", "192.168.1.9": "mapped",  # no brackets, an IPv4 address written as IPv6 as IPv4
        "2a01:4f8:c17:1::5": "Nuremberg.Example"}  # and 0.0.0.0, never a remote, is no one's name
    assert sockets.known_names("") == {} and sockets.known_names("# nothing\n\n") == {}
    assert sockets.known_names("10.0.0.1 a\r\n10.0.0.2 b\r\n") == {"10.0.0.1": "a", "10.0.0.2": "b"}  # Windows' ends
    assert sockets.known_names("10.0.0.1 " + "n" * 300) == {"10.0.0.1": "n" * 253}  # a name's most


def test_a_loopback_address_is_named_only_as_this_machine():
    # a blocking list sends its names to 127.0.0.1 or 0.0.0.0: none of them is a name of this machine's
    blocking = ("# blocked\n127.0.0.1 telemetry.example\n127.0.0.1 ads.example\n127.0.0.1 localhost\n"
                "::1 ip6-localhost ip6-loopback\n0.0.0.0 tracker.example\n:: tracker6.example\n")
    names = sockets.known_names(blocking)
    assert names == {"127.0.0.1": "localhost", "::1": "ip6-localhost"}
    loopback = judged(row(local="127.0.0.1", local_port=51010, remote="127.0.0.1", remote_port=8775), names=names)
    assert loopback[0]["name"] == "localhost"
    # Windows' own file has its localhost lines commented out: a blocked name alone names no loopback address
    assert sockets.known_names("# 127.0.0.1 localhost\n127.0.0.1 telemetry.example\n::1 ads.example\n") == {}
    assert sockets.known_names("127.0.0.1 localhost.localdomain localhost\n127.0.0.2 x.localhost\n") == {
        "127.0.0.1": "localhost.localdomain", "127.0.0.2": "x.localhost"}


def test_the_names_are_bounded(monkeypatch):
    monkeypatch.setattr(sockets, "NAMES", 3)
    many = "".join(f"10.0.{n // 256}.{n % 256} host{n}\n" for n in range(600))
    assert sockets.known_names(many) == {"10.0.0.0": "host0", "10.0.0.1": "host1", "10.0.0.2": "host2"}
    # a blocking list's thousand names for one address take no place
    assert sockets.known_names("".join(f"0.0.0.0 ad{n}.example\n" for n in range(1000)) + "10.0.0.1 kept\n") == {
        "10.0.0.1": "kept"}


def test_this_systems_own_hosts_file_is_the_one_read(monkeypatch, tmp_path):
    asked = []

    def text_of(system):
        asked.append(system)
        return "10.0.0.1 here\n"
    monkeypatch.setattr(sockets, "_hosts_text", text_of)
    assert sockets.known_names(system="windows") == {"10.0.0.1": "here"} == sockets.known_names(system="linux")
    with monkeypatch.context() as patch:
        for platform in ("win32", "linux", "darwin"):
            patch.setattr(sockets.sys, "platform", platform)
            sockets.known_names()
    assert asked == ["windows", "linux", "windows", "linux", ""]
    sockets.known_names(HOSTS)  # a text given: no file read
    assert len(asked) == 5
    # the real reader, on a folder of the test's standing in for Windows' own: a byte order mark dropped, the file
    # read up to its bound and cut after its last whole line, "" where there is none
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    assert HOSTS_TEXT("windows") == ""
    folder = tmp_path / "System32" / "drivers" / "etc"
    folder.mkdir(parents=True)
    (folder / "hosts").write_bytes(b"\xef\xbb\xbf10.0.0.1 one\n10.0.0.2 two\n10.0.0.3 three\n")
    assert HOSTS_TEXT("windows") == "10.0.0.1 one\n10.0.0.2 two\n10.0.0.3 three\n"
    assert sockets.HOSTS_BYTES == 1 << 20
    monkeypatch.setattr(sockets, "HOSTS_BYTES", 32)
    assert HOSTS_TEXT("windows") == "10.0.0.1 one\n10.0.0.2 two\n"
    assert sockets.known_names(HOSTS_TEXT("windows")) == {"10.0.0.1": "one", "10.0.0.2": "two"}


# -- under WSL ---------------------------------------------------------------------------------------------------------
def test_under_wsl_2_the_tab_says_whose_sockets_these_are():
    table = sockets.under_wsl(WSL2, {"WSL_DISTRO_NAME": "Ubuntu"}, root=False)
    assert table["title"] == "Under WSL" and [c["title"] for c in table["columns"]] == ["What", "Here", "What it means"]
    assert table["note"] == "What running inside a WSL distribution changes for this tab."
    assert table["rows"] == [
        ["This Linux", "WSL 2: Ubuntu", "a WSL distribution on Windows: the sockets listed are its own"],
        ["Not listed", "Windows' programs", "what Windows' own programs listen on and connect to is the Windows "
         "firewall plugin's Netstat to list"],
        ["Programs", "yours named", "the platform does not run as root, so the reading is yours: root's services show "
         "as another user's"]]
    assert "sudo" not in json.dumps(table) and "relay" not in json.dumps(table)  # nothing that was not confirmed
    as_root = sockets.under_wsl(WSL2, {"WSL_DISTRO_NAME": "Liminal-Ubuntu"}, root=True)
    assert as_root["rows"][0][1] == "WSL 2: Liminal-Ubuntu" and as_root["rows"][-1] == [
        "Programs", "all named", "the platform runs as root here, so every socket's program is read"]
    # a kernel that does not say which WSL it is, is taken as WSL 2; one that does not say its name is "WSL"
    unnamed = sockets.under_wsl("6.6.0-custom", {"WSL_INTEROP": "/run/WSL/8_interop"}, root=False)
    assert unnamed["rows"][0][1] == "WSL 2: WSL" and len(unnamed["rows"]) == 3
    json.dumps(table, allow_nan=False)


def test_under_wsl_1_and_on_a_machine_of_its_own(monkeypatch):
    table = sockets.under_wsl(WSL1, {"WSL_DISTRO_NAME": "Debian"}, root=False)
    assert table["rows"] == [
        ["This Linux", "WSL 1: Debian", "a WSL distribution on Windows, with no Linux kernel of its own"],
        ["Listed", "what WSL 1 gives", "it has no Linux kernel: its /proc/net may be empty"],
        ["Not listed", "Windows' programs", "what Windows' own programs listen on and connect to is the Windows "
         "firewall plugin's Netstat to list"],
        ["Programs", "yours named", "the platform does not run as root, so the reading is yours: root's services show "
         "as another user's"]]
    assert sockets.under_wsl(OWN, {}) is None and sockets.under_wsl(OWN, {}, root=True) is None  # nothing to say
    # without a word on it, whether the platform runs as root is this process's own user
    for uid, here in ((0, "all named"), (1000, "yours named")):
        monkeypatch.setattr(sockets, "_uid", lambda uid=uid: uid)
        assert sockets.under_wsl(WSL2, {"WSL_DISTRO_NAME": "Ubuntu"})["rows"][-1][1] == here
