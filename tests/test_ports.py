"""Ports checked (liminal_libs.ports): the ports as typed, what listens here read from a probe's sockets and a
connection out to a host the caller names, each over stand-ins: nothing is sent anywhere (an autouse fixture refuses
every connection)."""
from __future__ import annotations

import os
import socket
import sys

import pytest

from liminal_libs import ports
from liminal_libs.ports import Outcome, parse_ports
from liminal_libs.resources import Conn

OUT = "ports.example.test"  # a server answering on every port, as the caller names it


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refused(*a, **k):
        raise AssertionError("a test reached for the network")
    monkeypatch.setattr(ports.socket, "create_connection", refused)


def test_the_ports_as_typed():
    assert parse_ports("25, 80 443;8765-8767") == (25, 80, 443, 8765, 8766, 8767)
    assert parse_ports([443, 80, 80]) == (80, 443) and parse_ports(8765) == (8765,) and parse_ports(" 25 ") == (25,)
    for bad, words in (("", "no port given"), ("http", "not a port"), ("0", "1 to 65535"), ("70000", "1 to 65535"),
                       ("90-80", "runs upward"), ("1-65535", "at most 12"), (" ".join(map(str, range(1, 14))), "at most 12")):
        with pytest.raises(ValueError, match=words):
            parse_ports(bad)
    assert parse_ports("1-20", most=20)[-1] == 20
    assert ports.tally([Outcome("open", ""), Outcome("blocked", ""), Outcome("open", "")]) == "2 open, 1 blocked" and ports.tally([]) == "none"


def test_what_listens_here_is_read_from_the_sockets():
    conns = [Conn(10, "listening", "127.0.0.1:8765", ""), Conn(10, "established", "127.0.0.1:8765", "127.0.0.1:50000"),
             Conn(20, "listening", "0.0.0.0:25", ""), Conn(20, "listening", "[::]:25", ""),
             Conn(30, "listening", "192.168.1.5:80", ""), Conn(0, "listening", "[::1]:631", ""),
             Conn(40, "listening", "[::ffff:127.0.0.1]:9000", ""), Conn(50, "established", "10.0.0.2:443", "10.0.0.9:51000")]
    found = ports.here(conns, [8765, 25, 80, 631, 443, 9000], {10: "Charts (pid 10)", 20: "smtpd.exe (pid 20)"}, at=5.0)
    assert found[8765] == Outcome("listening", "listening: Charts (pid 10), this machine only", 5.0, ("Charts (pid 10), this machine only",))
    assert found[25].said == "listening: smtpd.exe (pid 20), every address"  # IPv4 and IPv6 alike
    assert found[80].said == "listening: pid 30, 192.168.1.5"
    assert found[631].said == "listening: a program not named (another user's), this machine only"
    assert found[9000].said == "listening: pid 40, this machine only"  # an IPv4 address mapped into IPv6
    assert found[443] == Outcome("free", "free: nothing listens on it here", 5.0)  # a connection out is no listener
    assert ports.endpoint("bad") is None and ports.endpoint("[::1]:80") == ("::1", 80) and ports.endpoint("1.2.3.4:x") is None
    assert found[25].why == "smtpd.exe (pid 20), every address" and found[25].as_dict()["state"] == "listening"
    assert ports.listening_pids(conns, [8765, 25, 631, 443]) == {10, 20}  # an owner not known (0) left out


def test_a_connection_out_open_refused_or_blocked_and_the_server_not_reached():
    tried = []

    def connect(host, port, timeout):
        tried.append(port)
        assert host == OUT and timeout == 5.0
        if port == 25:
            raise TimeoutError("timed out")
        if port == 23:
            raise ConnectionRefusedError(10061, "No connection could be made because the target machine actively refused it")
        if port == 99:
            raise OSError(10065, "A socket operation was attempted to an unreachable host")
    found = ports.reach_out([443, 25, 23, 99], OUT, connect=connect, clock=lambda: 7.0)
    assert tried[0] == 80 and sorted(tried[1:]) == [23, 25, 99, 443]  # its port 80 first
    assert {p: o.state for p, o in found.items()} == {443: "open", 25: "blocked", 23: "closed", 99: "failed"}
    assert found[443] == Outcome("open", f"open: {OUT} answered on 443", 7.0)
    assert found[25].said == f"blocked: no answer from {OUT} in 5 s (dropped on the way out: a firewall or the ISP)"
    assert found[99].said == "failed: A socket operation was attempted to an unreachable host"

    def unknown(host, port, timeout):
        raise socket.gaierror(11001, "getaddrinfo failed")
    [(port, o)] = ports.reach_out([25], OUT, connect=unknown, clock=lambda: 7.0).items()
    assert port == 25 and o.state == "failed"
    assert o.said == (f"failed: {OUT} was not reached on its port 80 ({OUT} could not be found: getaddrinfo failed), so "
                      "nothing is known of 25 out")
    assert ports.reach_out([], OUT, connect=lambda h, p, t: None) == {}
    assert ports.reach_out([25], OUT, connect=lambda h, p, t: None, control=443)[25].state == "open"


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows probe")
def test_the_windows_probe_names_a_process():
    from liminal_libs.resources import WindowsProbe

    names = WindowsProbe().program_names([os.getpid()])
    assert list(names) == [os.getpid()] and names[os.getpid()].lower().startswith("python")
