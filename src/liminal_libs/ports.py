"""Ports checked, for the platform's hw-stats plugin (the user, 2026-11-08: "verify that 'selected' ports are
available or blocked"; "there should be a way to check ports"): the ports as typed (`parse_ports`), what listens on
each here (`here`: each program, and whether it can be reached on every address or from this machine only, read from
a probe's sockets: resources.WindowsProbe, LinuxProbe; nothing is sent anywhere) and whether this machine can open a
connection out on each (`reach_out`, to a host the caller names: a server answering on every TCP port). A check from
the internet is a service's, so it is its plugin's (the hw-stats plugin asks check-host.net); its outcomes are these.

Out and from the internet, a port comes back as an `Outcome`: open (a connection was made), closed (refused:
something answered, nothing accepted the port), blocked (no answer in time: dropped on the way) or failed (the check
itself could not be made); here, listening or free."""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

MAX_PORTS = 12  # ports in one check
CONTROL = 80  # tried first out: when even it gets no answer, nothing is said of the others
CONNECT_S = 5.0  # a connection's wait out
STATES = ("open", "closed", "blocked", "failed", "listening", "free")  # in the order counted
EVERY = ("0.0.0.0", "::", "*")


@dataclass(frozen=True)
class Outcome:
    """One port as one check found it: open | closed | blocked | failed (out, from the internet); listening | free
    (here). `said`: the state and why, in words; `at`: when (seconds since 1970); `detail`: what each server said (from
    the internet), each program listening (here)."""
    state: str
    said: str
    at: float = 0.0
    detail: tuple[str, ...] = ()

    @property
    def why(self) -> str:
        """The words after the state ("no answer in 5 s" of "blocked: no answer in 5 s")."""
        return self.said.split(": ", 1)[1] if ": " in self.said else ""

    def as_dict(self) -> dict:
        return {"state": self.state, "said": self.said, "at": self.at, "detail": list(self.detail)}


def parse_ports(text, most: int = MAX_PORTS) -> tuple[int, ...]:
    """Ports as typed ("25, 80 443; 8765-8768": commas, spaces or semicolons, a range with a dash; or numbers in a
    list), sorted, each once; ValueError in words for anything else, a port outside 1 to 65535, none at all, or more
    than `most`."""
    if isinstance(text, int):
        text = str(text)
    elif isinstance(text, (list, tuple, set)):
        text = " ".join(str(p) for p in text)
    found: set[int] = set()
    for word in re.split(r"[,;\s]+", str(text or "").strip()):
        if not word:
            continue
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", word)
        if not m:
            raise ValueError(f"not a port: {word!r} (a number, or a range as 8765-8768)")
        low, high = int(m.group(1)), int(m.group(2) or m.group(1))
        if not 1 <= low <= 65535 or not 1 <= high <= 65535:
            raise ValueError(f"a port is 1 to 65535, not {word}")
        if high < low:
            raise ValueError(f"a range runs upward ({high}-{low}), not {word}")
        if high - low >= most or len(found | set(range(low, high + 1))) > most:
            raise ValueError(f"at most {most} ports at once")
        found.update(range(low, high + 1))
    if not found:
        raise ValueError("no port given")
    return tuple(sorted(found))


def tally(outcomes) -> str:
    """Outcomes counted in words, in STATES' order: "2 open, 1 blocked"."""
    states = [o.state for o in outcomes]
    return ", ".join(f"{states.count(s)} {s}" for s in STATES if states.count(s)) or "none"


# -- here: the probe's sockets --------------------------------------------------------------------------------

def endpoint(text: str) -> tuple[str, int] | None:
    """"127.0.0.1:8765" or "[::1]:8765" (a resources.Conn's address) as (address, port); None for anything else."""
    host, sep, port = str(text).rpartition(":")
    if not sep or not port.isdigit():
        return None
    return host.strip("[]"), int(port)


def is_loopback(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address == "localhost"
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def reach(addresses) -> str:
    """Where a listener can be reached from, in words: every address, this machine only, or its addresses."""
    found = set(addresses)
    if found & set(EVERY):
        return "every address"
    if found and all(is_loopback(a) for a in found):
        return "this machine only"
    return ", ".join(sorted(found))


def listening_pids(conns, ports) -> set[int]:
    """The processes listening on any of `ports` (pid 0, an owner not known, left out)."""
    wanted = {int(p) for p in ports}
    return {c.pid for c in conns if c.state == "listening" and c.pid and (e := endpoint(c.local)) and e[1] in wanted}


def here(conns, ports, names=None, at: float | None = None) -> dict[int, Outcome]:
    """What listens on each of `ports` on this machine, from a probe's sockets (`conns`: resources.Conn, the listening
    ones read): listening (each program, with where it can be reached from) or free. `names`: pid -> a program's name
    (a Liminal app's label, an executable's name); another pid is said as "pid N", pid 0 as a program not named (on
    Linux, another user's: its sockets' owner is not readable)."""
    names = names or {}
    at = time.time() if at is None else at
    by: dict[int, dict[str, set[str]]] = {int(p): {} for p in ports}
    for c in conns:
        if c.state != "listening":
            continue
        found = endpoint(c.local)
        if found is None or found[1] not in by:
            continue
        who = names.get(c.pid) or (f"pid {c.pid}" if c.pid else "a program not named (another user's)")
        by[found[1]].setdefault(who, set()).add(found[0])
    out = {}
    for p, programs in by.items():
        if not programs:
            out[p] = Outcome("free", "free: nothing listens on it here", at)
            continue
        detail = tuple(f"{who}, {reach(addresses)}" for who, addresses in sorted(programs.items()))
        out[p] = Outcome("listening", "listening: " + "; ".join(detail), at, detail)
    return out


# -- out: a connection from this machine ----------------------------------------------------------------------

def connect(host: str, port: int, timeout: float) -> None:
    """One TCP connection opened and closed (OSError when it cannot be: refused, timed out, no route)."""
    with socket.create_connection((host, port), timeout=timeout):
        pass


def attempt(port: int, host: str, timeout: float = CONNECT_S, connect=connect, clock=time.time) -> Outcome:
    """One connection out to `host` on `port`, as an outcome."""
    try:
        connect(host, port, timeout)
        return Outcome("open", f"open: {host} answered on {port}", clock())
    except ConnectionRefusedError:
        return Outcome("closed", f"closed: refused on the way to {host} (a firewall rejecting it, or nothing answering there)", clock())
    except TimeoutError:  # socket.timeout too
        return Outcome("blocked", f"blocked: no answer from {host} in {timeout:g} s (dropped on the way out: a firewall or the ISP)", clock())
    except socket.gaierror as e:
        return Outcome("failed", f"failed: {host} could not be found: {e.strerror or e}", clock())
    except OSError as e:
        return Outcome("failed", f"failed: {e.strerror or e}", clock())


def reach_out(ports, host: str, timeout: float = CONNECT_S, connect=connect, clock=time.time,
              control: int = CONTROL) -> dict[int, Outcome]:
    """Each of `ports` tried out from this machine to `host` (a server answering on every TCP port: the caller's),
    eight at most at once; its port `control` first: when even that one is not answered, each port says the check
    could not be made rather than that it is blocked."""
    ports = tuple(int(p) for p in ports)
    first = attempt(control, host, timeout, connect, clock)
    if first.state != "open":
        return {p: Outcome("failed", f"failed: {host} was not reached on its port {control} ({first.why}), so nothing "
                                     f"is known of {p} out", first.at) for p in ports}
    if not ports:
        return {}
    with ThreadPoolExecutor(max_workers=min(8, len(ports))) as pool:
        found = list(pool.map(lambda p: attempt(p, host, timeout, connect, clock), ports))
    return dict(zip(ports, found))
