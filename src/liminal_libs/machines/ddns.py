"""Dynamic DNS for a platform plugin whose provider holds the DNS (a cloud's: DigitalOcean, Linode, Vultr, Route 53,
Azure DNS, Cloud DNS): hosts kept at this network's public IPv4 address, the way Namecheap's plugin keeps its own.

The plugin says how a host's A record is read and set through its provider's API (`read`, `write`) and which name
servers tell an asker its own address (`servers`, as dns.public_address takes them: the plugin names them, the library
names no host). A pass asks this network's address, then each host's A record, and sets the ones that differ (every one
with `force`, the page's Update DNS now); what each host's record held and what was done is kept for the page.

    keeper = Keeper(read=lambda h: [...addresses...], write=lambda h, ip: "set", servers=PUBLIC_IPV4)
    hosts, wrong = hosts_of("home.example.com, @.example.net", zones=("example.com", "example.net"))
    keeper.run_pass(hosts)
"""
from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from .. import dns

FRESH_S = 600.0  # this network's address asked again after this long
MINUTES = (1.0, 1440.0, 5.0)  # a check's minutes: the least, the most, unless set


@dataclass(frozen=True)
class Host:
    """A host kept at this network's address: its full name, the provider's zone it is in, its name in that zone ("@"
    for the zone itself)."""

    fqdn: str
    zone: str
    name: str


def split_host(text: str, zones: Iterable[str]) -> Host:
    """A host as typed (home.example.com, @.example.com for the zone itself, example.com) as its zone (the longest of
    `zones` it ends with) and its name there. ValueError when it is in none of them."""
    name = str(text or "").strip().rstrip(".").lower()
    if name.startswith("@."):
        name = name[2:]
    if not name or " " in name:
        raise ValueError(f"{text!r} is not a host name")
    best = ""
    for zone in zones:
        z = str(zone or "").strip().rstrip(".").lower()
        if z and (name == z or name.endswith("." + z)) and len(z) > len(best):
            best = z
    if not best:
        raise ValueError(f"{name} is in none of the account's domains")
    return Host(name, best, "@" if name == best else name[: -len(best) - 1])


def hosts_of(text: str, zones: Iterable[str]) -> tuple[list[Host], list[str]]:
    """The hosts of a setting (comma or space separated) and, in words, the ones that are in no zone of the account."""
    zones = [z for z in zones]
    found: list[Host] = []
    wrong: list[str] = []
    for part in str(text or "").replace(";", ",").replace(" ", ",").split(","):
        if not part.strip():
            continue
        try:
            h = split_host(part, zones)
        except ValueError as e:
            wrong.append(str(e))
            continue
        if h.fqdn not in {x.fqdn for x in found}:
            found.append(h)
    return found, wrong


def minutes_of(text: str | None) -> float:
    """The minutes between checks as set (MINUTES: 1 to 1440, 5 unless set or when it is no number)."""
    least, most, default = MINUTES
    try:
        value = float(str(text).strip()) if text not in (None, "") else default
    except ValueError:
        return default
    return min(most, max(least, value))


@dataclass
class HostState:
    """What a host's A record held when last read, what was done about it, when."""

    fqdn: str
    address: str | None = None
    checked_at: float | None = None
    updated_at: float | None = None
    result: str = "not checked yet"
    ok: bool | None = None

    def describe(self) -> dict:
        return {"host": self.fqdn, "address": self.address, "checkedAt": self.checked_at, "updatedAt": self.updated_at,
                "result": self.result, "ok": self.ok}


class Keeper:
    """The hosts' records kept at this network's public IPv4 address (module docstring). `read(host)` -> the addresses
    of its A record ([] when it has none; None when it could not be read, its trouble raised instead is said too);
    `write(host, address)` -> words of what was done (a record set, or made); `public()` -> (address, whose) stands in
    for asking `servers` (a test's)."""

    def __init__(self, read: Callable[[Host], list[str] | None], write: Callable[[Host, str], str],
                 servers: Sequence[tuple[str, str, str, str]] = (), public: Callable[[], tuple[str | None, str]] | None = None,
                 clock: Callable[[], float] = time.time, on_pass: Callable[[], None] | None = None):
        self._read = read
        self._on_pass = on_pass  # at the start of each pass (a provider's cache of zones cleared, 1.49.1)
        self._write = write
        self._servers = tuple(servers)
        self._public = public or (lambda: dns.public_address(4, self._servers))
        self._clock = clock
        self._lock = threading.Lock()
        self._passing = threading.Lock()
        self._states: dict[str, HostState] = {}
        self.public: str | None = None
        self.public_why = ""
        self.public_at: float | None = None

    def states(self) -> list[HostState]:
        with self._lock:
            return list(self._states.values())

    def state(self, fqdn: str) -> HostState | None:
        with self._lock:
            return self._states.get(fqdn.lower())

    def address(self, fresh_s: float = FRESH_S) -> str | None:
        """This network's public IPv4 address (kept `fresh_s`); None, with why in `public_why`, when none came back."""
        now = self._clock()
        with self._lock:
            if self.public and self.public_at is not None and now - self.public_at < fresh_s:
                return self.public
        try:
            ip, whose = self._public()
        except Exception as e:  # noqa: BLE001 - why there is no address is the answer
            ip, whose = None, f"{type(e).__name__}: {e}"
        if ip:
            try:
                ok = ipaddress.ip_address(ip).version == 4
            except ValueError:
                ok = False
            if not ok:
                ip, whose = None, f"{ip} is not an IPv4 address"
        with self._lock:
            self.public = ip
            if ip:
                self.public_at, self.public_why = now, ""
            else:
                self.public_why = str(whose or "no answer")
            return ip

    def run_pass(self, hosts: Iterable[Host], force: bool = False, wait: float = 120.0) -> list[dict]:
        """A pass now over `hosts` (another under way: waited for at most `wait` s, else a RuntimeError); each host's state."""
        if not self._passing.acquire(timeout=max(0.0, wait)):
            raise RuntimeError("a Dynamic DNS pass is under way")
        try:
            hosts = list(hosts)
            if self._on_pass is not None:
                self._on_pass()
            ip = self.address(fresh_s=0.0 if force else FRESH_S)
            for h in hosts:
                self._one(h, ip, force)
            return [self._states[h.fqdn].describe() for h in hosts if h.fqdn in self._states]
        finally:
            self._passing.release()

    def _one(self, h: Host, ip: str | None, force: bool) -> None:
        now = self._clock()
        with self._lock:
            st = self._states.setdefault(h.fqdn, HostState(h.fqdn))
        if not ip:
            st.checked_at, st.ok, st.result = now, False, f"this network's address was not found: {self.public_why or 'no answer'}"
            return
        try:
            held = self._read(h)
        except Exception as e:  # noqa: BLE001 - the provider's trouble is the host's result
            st.checked_at, st.ok, st.result = now, False, f"its record could not be read: {e}"
            return
        if held is None:
            st.checked_at, st.ok, st.result = now, False, "its record could not be read"
            return
        st.address = held[0] if held else None
        if not force and held == [ip]:
            st.checked_at, st.ok, st.result = now, True, "current"
            return
        try:
            done = self._write(h, ip)
        except Exception as e:  # noqa: BLE001 - said as the host's result; the next pass tries again
            st.checked_at, st.ok, st.result = now, False, f"not updated: {e}"
            return
        st.checked_at = st.updated_at = now
        st.address, st.ok = ip, True
        st.result = str(done or ("set" if held else "made")) + ("" if held == [ip] else f" (was {', '.join(held) or 'none'})")

    def table(self, hosts: Iterable[Host], minutes: float, attached: bool = True, when=None, empty: str | None = None) -> dict:
        """The page's Dynamic DNS table (a platform plugin's status.tables entry) for `hosts`; `empty`, what it says
        with none (the account's domains not read yet, say)."""
        when = when or _when
        rows = []
        for h in hosts:
            s = self.state(h.fqdn)
            rows.append([h.fqdn, (s.address if s else None) or "–", when(s.checked_at if s else None),
                         when(s.updated_at if s else None), s.result if s else "not checked yet"])
        every = f"every {minutes:g} min" + ("" if attached else ", once attached")
        return {"title": "Dynamic DNS", "note": f"{every} · this network's address: {self.public or 'not found yet'}",
                "columns": [{"title": "Host"}, {"title": "Address"}, {"title": "Checked"}, {"title": "Updated"},
                            {"title": "Result"}],
                "rows": rows, "empty": empty or "No host is set to be kept at this network's address."}


def _when(t: float | None) -> str:
    return "–" if not t else time.strftime("%b %d %H:%M", time.localtime(t))
