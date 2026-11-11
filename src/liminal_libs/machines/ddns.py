"""Dynamic DNS for a platform plugin whose provider holds the DNS (a cloud's: DigitalOcean, Linode, Vultr, Route 53,
Azure DNS, Cloud DNS): hosts kept at this network's public IPv4 address, the way Namecheap's plugin keeps its own.

The plugin says how a host's A record is read and set through its provider's API (`read`, `write`) and which name
servers tell an asker its own address (`servers`, as dns.public_address takes them: the plugin names them, the library
names no host). A pass asks this network's address, then each host's A record, and sets the ones that are its own to
keep and differ (every one of them with `force`, the page's Update DNS now); what each host's record held and what was
done is kept for the page.

What is the keeper's to change (1.49.2; an audit before any key went in: a host listed in the settings had its live
record pointed at home within a minute, unasked): a host with no A record (it is made), one holding exactly the
address the keeper last set or found there as this network's (its own: kept current), and one the user let it take
over (`take_over`, after the page's confirmation, which says what the record holds and that it will point here). Any
other record (another address, or several) is left as it is and said so ("holds 198.51.100.7, not this network's
address"), with a Take over… on the page; several addresses are never cut to one unasked. Just before a write the
address is asked again, and nothing is written if it changed meanwhile. What the keeper holds as its own and what it
was let take over is kept in a small JSON file the plugin names (`state`: its folder under the platform's), so a
restart after the network's address changed still knows its own record.

    keeper = Keeper(read=lambda h: [...addresses...], write=lambda h, ip: "set", servers=PUBLIC_IPV4, state=path)
    hosts, wrong = hosts_of("home.example.com, @.example.net", zones=("example.com", "example.net"))
    keeper.run_pass(hosts)
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .. import dns

FRESH_S = 600.0  # this network's address asked again after this long (always again just before a write)
MINUTES = (1.0, 1440.0, 5.0)  # a check's minutes: the least, the most, unless set
TAKE_FORM = "ddns-take"  # the page's form taking a host over (take_form), and the Update DNS now one (now_form)
NOW_FORM = "ddns-now"


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
    """What a host's A record held when last read, what was done about it, when; `foreign`: it holds what is not the
    keeper's to change (another address, or several), so it was left as it is until the user takes it over."""

    fqdn: str
    address: str | None = None
    checked_at: float | None = None
    updated_at: float | None = None
    result: str = "not checked yet"
    ok: bool | None = None
    holds: tuple[str, ...] = ()
    foreign: bool = False

    def describe(self) -> dict:
        return {"host": self.fqdn, "address": self.address, "checkedAt": self.checked_at, "updatedAt": self.updated_at,
                "result": self.result, "ok": self.ok, "holds": list(self.holds), "foreign": self.foreign}


class Keeper:
    """The hosts' records kept at this network's public IPv4 address (module docstring). `read(host)` -> the addresses
    of its A record ([] when it has none; None when it could not be read, its trouble raised instead is said too);
    `write(host, address)` -> words of what was done (the host's A record set to that one address, or made); `public()`
    -> (address, whose) stands in for asking `servers` (a test's); `state`: the JSON file of what is its own and what it
    was let take over (None: kept in memory only); `on_pass`: called at the start of each pass."""

    def __init__(self, read: Callable[[Host], list[str] | None], write: Callable[[Host, str], str],
                 servers: Sequence[tuple[str, str, str, str]] = (), public: Callable[[], tuple[str | None, str]] | None = None,
                 clock: Callable[[], float] = time.time, on_pass: Callable[[], None] | None = None,
                 state: Path | str | None = None):
        self._read = read
        self._on_pass = on_pass  # at the start of each pass (a provider's cache of zones cleared, 1.49.1)
        self._write = write
        self._servers = tuple(servers)
        self._public = public or (lambda: dns.public_address(4, self._servers))
        self._clock = clock
        self._lock = threading.Lock()
        self._passing = threading.Lock()
        self._states: dict[str, HostState] = {}
        self._file = Path(state) if state is not None else None
        self._own: dict[str, str] = {}  # fqdn -> the address the keeper last set or found there as this network's
        self._taken: set[str] = set()  # the hosts the user let it take over
        self._load()
        self.public: str | None = None
        self.public_why = ""
        self.public_at: float | None = None

    # -- what is its own, kept --------------------------------------------------------------------------------------------
    def _load(self) -> None:
        if self._file is None or not self._file.is_file():
            return
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return  # an unreadable file: nothing taken as its own (the safe way: a record is left as it is)
        own = data.get("own") if isinstance(data, dict) else None
        taken = data.get("taken") if isinstance(data, dict) else None
        if isinstance(own, dict):
            self._own = {str(k).lower(): str(v) for k, v in own.items() if isinstance(v, str)}
        if isinstance(taken, list):
            self._taken = {str(x).lower() for x in taken}

    def _save(self) -> None:
        if self._file is None:
            return
        with self._lock:
            data = {"own": dict(sorted(self._own.items())), "taken": sorted(self._taken)}
        try:
            self._file.parent.mkdir(parents=True, exist_ok=True)
            part = self._file.with_name(self._file.name + ".part")
            part.write_text(json.dumps(data, indent=1), encoding="utf-8")
            os.replace(part, self._file)
        except OSError:
            pass  # kept in memory; said nowhere worse than before

    def own(self, fqdn: str) -> str | None:
        """The address the keeper last set at `fqdn`, or found there as this network's (None: none of its own)."""
        with self._lock:
            return self._own.get(fqdn.lower())

    def taken(self, fqdn: str) -> bool:
        with self._lock:
            return fqdn.lower() in self._taken

    def take_over(self, fqdn: str) -> None:
        """The user let the keeper take `fqdn` over (the page's Take over…, once confirmed): its next pass points the
        host's A record at this network's address whatever it holds."""
        with self._lock:
            self._taken.add(fqdn.lower())
        self._save()

    def known(self) -> list[str]:
        """Every host the keeper holds as its own or was let take over (1.49.4): a plugin lets go of those no longer in
        its settings, a change made while it was not running too."""
        with self._lock:
            return sorted(set(self._own) | self._taken)

    def let_go(self, fqdn: str) -> None:
        """`fqdn` no longer the keeper's: neither taken over nor its own (a host taken out of the settings)."""
        with self._lock:
            self._taken.discard(fqdn.lower())
            self._own.pop(fqdn.lower(), None)
        self._save()

    def _mark_own(self, fqdn: str, ip: str) -> None:
        with self._lock:
            changed = self._own.get(fqdn) != ip
            self._own[fqdn] = ip
        if changed:
            self._save()

    # -- what the page shows ----------------------------------------------------------------------------------------------
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

    # -- a pass ------------------------------------------------------------------------------------------------------------
    def run_pass(self, hosts: Iterable[Host], force: bool = False, wait: float = 120.0,
                 stop: threading.Event | None = None) -> list[dict]:
        """A pass now over `hosts` (another under way: waited for at most `wait` s, else a RuntimeError); each host's state.
        `force` writes every host of its own whether it differs or not (never one that is not its own); `stop` set (the
        plugin detached) ends the pass before its next write."""
        if not self._passing.acquire(timeout=max(0.0, wait)):
            raise RuntimeError("a Dynamic DNS pass is under way")
        try:
            hosts = list(hosts)
            if self._on_pass is not None:
                self._on_pass()
            ip = self.address(fresh_s=0.0 if force else FRESH_S)
            for h in hosts:
                if stop is not None and stop.is_set():
                    break
                self._one(h, ip, force, stop)
            return [self._states[h.fqdn].describe() for h in hosts if h.fqdn in self._states]
        finally:
            self._passing.release()

    def _one(self, h: Host, ip: str | None, force: bool, stop: threading.Event | None) -> None:
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
        held = [str(a) for a in held]
        st.holds, st.address = tuple(held), (held[0] if held else None)
        taken, own = self.taken(h.fqdn), self.own(h.fqdn)
        if held == [ip]:
            self._mark_own(h.fqdn, ip)  # pointing here already: its own to keep from now on
            if not force:
                st.checked_at, st.ok, st.result, st.foreign = now, True, "current", False
                return
        mine = not held or held == [ip] or (len(held) == 1 and held[0] == own)
        if not mine and not taken:
            st.checked_at, st.ok, st.foreign = now, False, True
            st.result = ((f"holds {held[0]}, not this network's address" if len(held) == 1 else
                          f"holds {len(held)} addresses ({', '.join(held)})") + ": left as it is (Take over… to point it here)")
            return
        if stop is not None and stop.is_set():
            return
        again = self.address(fresh_s=0.0)  # asked again just before writing: a stale address is never written back
        if again != ip:
            st.checked_at, st.ok = now, False
            st.result = (f"this network's address changed to {again} during the pass: set on the next one" if again else
                         f"this network's address could not be asked again: {self.public_why or 'no answer'}")
            return
        if stop is not None and stop.is_set():  # detached while the address was asked again: nothing written (1.49.4)
            st.checked_at, st.ok, st.result = now, False, "not updated: the plugin was detached: nothing written"
            return
        try:
            done = self._write(h, ip)
        except Exception as e:  # noqa: BLE001 - said as the host's result; the next pass tries again
            st.checked_at, st.ok, st.result = now, False, f"not updated: {e}"
            return
        self._mark_own(h.fqdn, ip)
        st.checked_at = st.updated_at = now
        st.address, st.ok, st.foreign, st.holds = ip, True, False, (ip,)
        st.result = str(done or ("set" if held else "made")) + ("" if held == [ip] else f" (was {', '.join(held) or 'none'})")

    # -- the page's pieces -----------------------------------------------------------------------------------------------
    def table(self, hosts: Iterable[Host], minutes: float, attached: bool = True, when=None, empty: str | None = None,
              take: bool = False) -> dict:
        """The page's Dynamic DNS table (a platform plugin's status.tables entry) for `hosts`; `empty`, what it says with
        none (the account's domains not read yet, say); `take`: a Take over… button on each host left as it is (the
        plugin offers take_form() and asks take_over on its confirmation)."""
        when = when or _when
        rows = []
        for h in hosts:
            s = self.state(h.fqdn)
            row = [h.fqdn, (", ".join(s.holds) if s and s.holds else s.address if s else None) or "–",
                   when(s.checked_at if s else None), when(s.updated_at if s else None), s.result if s else "not checked yet"]
            if take:
                row.append({"form": TAKE_FORM, "title": "Take over…", "label": f"Take over {h.fqdn}",
                            "values": {"host": h.fqdn, "holds": ", ".join(s.holds)}} if s and s.foreign else "")
            rows.append(row)
        every = f"every {minutes:g} min" + ("" if attached else ", once attached")
        return {"title": "Dynamic DNS",
                "note": f"{every} · this network's address: {self.public or 'not found yet'} · a host holding another "
                        "address is left as it is until you take it over",
                "columns": [{"title": "Host"}, {"title": "Address"}, {"title": "Checked"}, {"title": "Updated"},
                            {"title": "Result"}, *([{"title": ""}] if take else [])],
                "rows": rows, "empty": empty or "No host is set to be kept at this network's address."}

    def take_form(self, hook: str = "ddns_take_over") -> dict:
        """The page's form taking a host over (its row's Take over… fills it): asked once the user has confirmed, in words
        naming what the record holds and what follows."""
        return {"id": TAKE_FORM, "hook": hook, "title": "Take a host over for Dynamic DNS",
                "fields": [{"name": "host", "label": "Host", "type": "fixed"}, {"name": "holds", "label": "It holds", "type": "fixed"}],
                "confirm": {"title": "Point {host} at this network?",
                            "words": ("{host} holds {holds}, which is not this network's address. Taken over, its A record is set "
                                      "to this network's address on the next pass and kept there; what it holds now is dropped, "
                                      "so whatever answers at that address (a server, a website) stops answering at {host}."),
                            "yes": "Take it over", "danger": True}}

    def now_form(self, hook: str = "ddns_update") -> dict:
        """The page's Update DNS now (a form with nothing to fill: straight to its confirmation)."""
        return {"id": NOW_FORM, "hook": hook, "title": "Update DNS now", "fields": [],
                "confirm": {"title": "Update the Dynamic DNS hosts now?",
                            "words": ("Each host that is Dynamic DNS's own (made by it, already pointing at this network, or taken "
                                      "over) is set to this network's address now, even where it already holds it. A host holding "
                                      "another address is left as it is."),
                            "yes": "Update now"}}


def _when(t: float | None) -> str:
    return "–" if not t else time.strftime("%b %d %H:%M", time.localtime(t))
