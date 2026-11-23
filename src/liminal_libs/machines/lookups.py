"""Each router's name and network, looked up while the World Wide Web tab is shown (1.72.0; the user, 2026-11-22: "it
will take a lot of looking over and using reverse lookups, and whois to figure out as much info as possible on the
nodes. if there are frequency limits on sources, please hold to those limits as not to get banned").

- Its name: the reverse DNS of its address (its PTR record), asked of this machine's own resolver
  (socket.gethostbyaddr), PTR_PER_S a second at most. A router's name often says its city or its airport
  (ae-1.r20.sttlwa01.us.bb.gin.ntt.net); reading those is next.
- Its network: RDAP, the registries' own WHOIS over https. Which registry holds an address comes from IANA's
  bootstrap files (one https GET each, kept BOOTSTRAP_S), whose addresses the plugin names (1.72.1: its
  RDAP_BOOTSTRAP; no outside host is named in the library, and without them no registry is asked); then one https
  GET of that registry for the address. The answer's range is kept (RANGES), so a router within one already known
  asks nothing. Each registry is asked RDAP_PER_MIN times a minute and RDAP_PER_HOUR an hour at most: the strictest
  limits any registry publishes (LACNIC's, without a key), held for every one; after an answer of 429 none is asked
  for its Retry-After's seconds (BACKOFF_S without one), nor for BACKOFF_S after a refusal of 403. Only https, only
  the registries' own hosts (those the bootstrap files name), a redirect followed only to one of them (REDIRECTS at
  most).
- What is found is kept in the composite database as evidence ("ptr", "rdap": with their sources' words) and handed
  to the page: each hop's name and network on its hover. Nothing is asked twice within KEEP_S; a failure is kept and
  tried again after KEEP_S. 1.75.1: after a restart, what was found within KEEP_S is put back from that evidence
  (`seed`, at the tab's first ask), so no registry is asked again for it; a part not found then is still asked.
- One thread, while the tab is shown (as the routes' tracing): started by the tab's ask, ended TIMEOUT_S after the
  last one, and for good when the plugin is detached. No user's word goes out: only the routers' addresses, to this
  machine's resolver and to the registry that holds each, with a User-Agent naming the library alone."""
from __future__ import annotations

import ipaddress
import math
import socket
import threading
import time
from collections import OrderedDict, deque
from typing import Iterable
from urllib.parse import urljoin, urlsplit

PTR_PER_S = 2  # reverse DNS asked of this machine's resolver, a second at most
RDAP_PER_MIN = 10  # a registry asked, a minute at most (LACNIC's published limit without a key, held for all)
RDAP_PER_HOUR = 1000  # and an hour
BACKOFF_S = 300.0  # a registry not asked this long after a 429 without Retry-After, or a 403
MAX_RETRY_AFTER_S = 3600.0  # a Retry-After longer than this is taken as this
KEEP_S = 86_400.0  # an address is not asked again for a day; a failure is tried again after it
BOOTSTRAP_S = 7 * 86_400.0  # IANA's bootstrap files are read again a week after
TIMEOUT_S = 20.0  # looking up stops this long after the tab was last asked (as the routes' tracing)
GAP_S = 0.5  # the pause between two lookups
MAX_KNOWN = 4096  # addresses kept in memory, the least recently looked up let go first
MAX_WAITING = 1024  # addresses waiting at most
MAX_RANGES = 4096  # registries' ranges kept, to answer the addresses within them
REDIRECTS = 3
TIMEOUT_HTTP_S = 15.0
AGENT = "liminal-libs (router lookups)"
PTR_WORDS = "the DNS, as this machine's resolver answered"
NAME_WORDS = "its name, read with the airports' and the cities' lists (their licences)"  # 1.73.0
RDAP_WORDS = "the registry's RDAP answer: its terms of use"


class Limit:
    """How often one source may be asked: `per` times in each of `windows` seconds (pairs), none until `held` after a
    refusal."""

    def __init__(self, pairs, clock):
        self.pairs = tuple(pairs)
        self.clock = clock
        self.asked: deque[float] = deque()
        self.held = -math.inf

    def wait(self) -> float:
        """Seconds until it may be asked again (0: now)."""
        now, longest = self.clock(), max(w for _, w in self.pairs)
        while self.asked and now - self.asked[0] >= longest:
            self.asked.popleft()
        due = max(0.0, self.held - now)
        for per, window in self.pairs:
            inside = [t for t in self.asked if now - t < window]
            if len(inside) >= per:
                due = max(due, inside[-per] + window - now)
        return due

    def take(self) -> None:
        self.asked.append(self.clock())

    def hold(self, seconds: float) -> None:
        self.held = max(self.held, self.clock() + min(max(0.0, seconds), MAX_RETRY_AFTER_S))


def _ptr(address: str) -> str:
    """The reverse DNS of an address, from this machine's resolver ("" when it has none). Looked up when called, so
    the suite's guard stands in for it."""
    try:
        return socket.gethostbyaddr(address)[0]
    except (socket.herror, socket.gaierror):
        return ""


def _get(url: str):
    """One https GET (no redirect followed here): (status, headers, JSON or None, its Location). Looked up when called,
    so the suite's guard stands in for it."""
    import requests
    r = requests.get(url, timeout=TIMEOUT_HTTP_S, allow_redirects=False,
                     headers={"Accept": "application/rdap+json, application/json", "User-Agent": AGENT})
    try:
        doc = r.json() if r.status_code == 200 else None
    except ValueError:
        doc = None
    return r.status_code, dict(r.headers), doc, r.headers.get("Location", "")


def _vcard_name(entity) -> str:
    """An RDAP entity's name, from its vCard's fn."""
    card = entity.get("vcardArray") if isinstance(entity, dict) else None
    if isinstance(card, list) and len(card) == 2 and isinstance(card[1], list):
        for item in card[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn" and isinstance(item[3], str):
                return item[3][:120]
    return ""


def network_of(doc) -> dict:
    """What an RDAP answer for an address says of its network: {"network", "handle", "org", "country", "range"}."""
    if not isinstance(doc, dict):
        return {}
    org = ""
    for entity in doc.get("entities") or ():
        if isinstance(entity, dict) and any(r in ("registrant", "administrative") for r in entity.get("roles") or ()):
            org = _vcard_name(entity)
            if org:
                break
    start, end = str(doc.get("startAddress") or ""), str(doc.get("endAddress") or "")
    return {"network": str(doc.get("name") or "")[:120], "handle": str(doc.get("handle") or "")[:80], "org": org,
            "country": str(doc.get("country") or "")[:8], "range": f"{start} - {end}" if start and end else ""}


class Lookups:
    """The routers' names and networks (the module's docstring). `claims(address, source, words, said)` is told each
    finding (the composite database's keeper); the stand-ins of a test are `clock`, `sleep`, `start`."""

    def __init__(self, *, claims=None, clock=None, sleep=None, start=None, timeout: float = TIMEOUT_S,
                 bootstrap: Iterable = ()):
        self._claims = claims
        self.bootstrap = tuple(str(u) for u in bootstrap if str(u).startswith("https://"))  # the plugin's
        self.clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._start = start or self._thread
        self.timeout = timeout
        self._lock = threading.Lock()
        self._known: OrderedDict[str, tuple[float, dict]] = OrderedDict()  # address -> (when, what is known)
        self._waiting: OrderedDict[str, None] = OrderedDict()
        self._ranges: OrderedDict[tuple, dict] = OrderedDict()  # (first, last) as ints -> the network
        self._bootstrap: list[tuple] = []  # (network, its base URL, its registry's host)
        self._bootstrap_at = -math.inf
        self._hosts: set[str] = set()
        self._limits: dict[str, Limit] = {}
        self._ptr_limit = Limit(((PTR_PER_S, 1.0),), self.clock)
        self._asked = -math.inf
        self._running = False
        self.closed = False
        self.asked = {"ptr": 0, "rdap": 0, "bootstrap": 0}
        # 1.73.0: (address, name) -> where the name says it is, or None (Routes' gazetteer); asks no one
        self.decode = None

    @staticmethod
    def _thread(work) -> None:
        threading.Thread(target=work, name="liminal-lookups", daemon=True).start()

    def known(self, address) -> dict:
        """What is known of a router now: {"name", "network", "org", "country", "range"} (a part not known: absent)."""
        with self._lock:
            kept = self._known.get(str(address))
        return dict(kept[1]) if kept else {}

    def want(self, addresses: Iterable) -> None:
        """The tab was asked, and these routers are on its routes: each not looked up within KEEP_S waits to be; the
        thread is started when it is not running."""
        now = self.clock()
        with self._lock:
            if self.closed:
                return
            self._asked = now
            for a in addresses:
                try:
                    a = str(ipaddress.ip_address(str(a)))
                except ValueError:
                    continue
                kept = self._known.get(a)
                # 1.75.1: a router known within KEEP_S is not asked again, unless a part of it was never asked (one
                # put back with its name and no network, say)
                whole = kept is not None and "name" in kept[1] and "network" in kept[1]
                if (whole and now - kept[0] < KEEP_S) or a in self._waiting:
                    continue
                if len(self._waiting) >= MAX_WAITING:
                    break
                self._waiting[a] = None
            start = bool(self._waiting) and not self._running
            if start:
                self._running = True
        if start:
            try:
                self._start(self._loop)
            except Exception:  # noqa: BLE001 - no thread: started again at the next ask
                with self._lock:
                    self._running = False

    def seed(self, found: dict, wall: float) -> int:
        """1.75.1: what was found before put back ({address: (when it was said, on the wall clock `wall` is read
        from, what was found)}: the composite database's evidence, Composite.lookups): each said within KEEP_S kept
        as of then, so it is not asked again before its day is out, and a part missing still is; its range answers
        the addresses within it. Never over what this process found itself. How many were put back."""
        now, put = self.clock(), 0
        with self._lock:
            if self.closed:
                return 0
            for address, (said, what) in (found or {}).items():
                try:
                    address = str(ipaddress.ip_address(str(address)))
                    age = max(0.0, float(wall) - float(said))
                except (TypeError, ValueError):
                    continue
                if age >= KEEP_S or address in self._known or not isinstance(what, dict):
                    continue
                self._known[address] = (now - age, dict(what))
                put += 1
                span = _span(what.get("range"))
                if span is not None and (what.get("network") or what.get("org")) and span not in self._ranges:
                    self._ranges[span] = {k: str(what.get(k) or "") for k in ("network", "handle", "org", "country",
                                                                             "range")}
            while len(self._known) > MAX_KNOWN:
                self._known.popitem(last=False)
            while len(self._ranges) > MAX_RANGES:
                self._ranges.popitem(last=False)
        return put

    def names(self) -> list[tuple[str, str]]:
        """The routers' names known now: [(address, name)] (1.73.0: read again when the lists come)."""
        with self._lock:
            return [(a, kept[1]["name"]) for a, kept in self._known.items() if kept[1].get("name")]

    def close(self) -> None:
        with self._lock:
            self.closed = True
            self._waiting.clear()

    def describe(self) -> dict:
        with self._lock:
            return {"known": len(self._known), "waiting": len(self._waiting), "ranges": len(self._ranges),
                    "running": self._running, **{f"asked_{k}": v for k, v in self.asked.items()}}

    def _loop(self) -> None:
        try:
            while self.step():
                self._sleep(GAP_S)
        except BaseException:
            with self._lock:
                self._running = False
            raise

    def step(self) -> bool:
        """The oldest router waiting looked up: its name, then its network (each within its limits; one whose source
        must wait is put back at the end). False when none waits, the tab was not asked within the timeout, or the
        lookups were closed."""
        with self._lock:
            if self.closed or not self._waiting or self.clock() - self._asked > self.timeout:
                self._running = False
                return False
            address, _ = self._waiting.popitem(last=False)
            kept = self._known.get(address)  # what was found within KEEP_S is not asked again; older, all is
            have = dict(kept[1]) if kept is not None and self.clock() - kept[0] < KEEP_S else {}
        found = dict(have)
        if "name" not in have:
            wait = self._ptr_limit.wait()
            if wait > 0:
                self._sleep(min(wait, 1.0))
            self._ptr_limit.take()
            self.asked["ptr"] += 1
            try:
                found["name"] = _ptr(address)
            except OSError:
                found["name"] = ""
            if found["name"]:
                self._claim(address, "ptr", PTR_WORDS, {"name": found["name"]})
                place = None
                try:
                    place = self.decode(address, found["name"]) if self.decode is not None else None
                except Exception:  # noqa: BLE001 - a name not read places nothing
                    place = None
                if place:
                    self._claim(address, "name", NAME_WORDS, place)
        if "network" not in have:
            net, later = self._network(address)
            if later:
                with self._lock:  # its registry must wait: asked again later, its name kept meanwhile
                    self._remember(address, found)
                    if not self.closed:
                        self._waiting[address] = None
                return True
            found.update(net)
            if net.get("network") or net.get("org"):
                self._claim(address, "rdap", RDAP_WORDS, net)
            found.setdefault("network", "")
        with self._lock:
            self._remember(address, found)
        return True

    def _remember(self, address: str, found: dict) -> None:
        self._known[address] = (self.clock(), found)
        self._known.move_to_end(address)
        while len(self._known) > MAX_KNOWN:
            self._known.popitem(last=False)

    def _claim(self, address: str, source: str, words: str, said: dict) -> None:
        if self._claims is None:
            return
        try:
            self._claims(address, source, words, said)
        except Exception:  # noqa: BLE001 - a keeper that fails costs the lookup nothing
            pass

    # -- RDAP -------------------------------------------------------------------------------------------------------
    def _in_ranges(self, ip) -> dict | None:
        n = int(ip)
        with self._lock:
            for (first, last), net in self._ranges.items():
                if first <= n <= last:
                    return dict(net)
        return None

    def _load_bootstrap(self) -> bool:
        if self.clock() - self._bootstrap_at < BOOTSTRAP_S and self._bootstrap:
            return True
        found, hosts = [], set()
        for url in self.bootstrap:
            self.asked["bootstrap"] += 1
            try:
                status, _, doc, _ = _get(url)
            except Exception:  # noqa: BLE001 - no bootstrap now: tried again at the next lookup
                return False
            if status != 200 or not isinstance(doc, dict):
                return False
            for service in doc.get("services") or ():
                if not (isinstance(service, list) and len(service) == 2):
                    continue
                bases = [u for u in service[1] if isinstance(u, str) and u.startswith("https://")]
                if not bases:
                    continue
                base = bases[0] if bases[0].endswith("/") else bases[0] + "/"
                host = urlsplit(base).hostname or ""
                hosts.add(host)
                for prefix in service[0]:
                    try:
                        found.append((ipaddress.ip_network(prefix, strict=False), base, host))
                    except ValueError:
                        continue
        found.sort(key=lambda x: -x[0].prefixlen)  # the most specific first
        self._bootstrap, self._hosts, self._bootstrap_at = found, hosts, self.clock()
        return True

    def _network(self, address: str) -> tuple[dict, bool]:
        """(What RDAP says of the address's network, whether to try it later). Its range known: no question asked."""
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return {"network": "", "org": "", "country": ""}, False
        net = self._in_ranges(ip)
        if net is not None:
            return net, False
        if not self.bootstrap:  # the plugin names no bootstrap: no registry is asked
            return {"network": "", "org": "", "country": ""}, False
        if not self._load_bootstrap():
            return {}, True
        entry = next((e for e in self._bootstrap if ip.version == e[0].version and ip in e[0]), None)
        if entry is None:
            return {"network": "", "org": "", "country": ""}, False
        url, host = urljoin(entry[1], f"ip/{address}"), entry[2]
        for _ in range(REDIRECTS + 1):
            limit = self._limits.setdefault(host, Limit(((RDAP_PER_MIN, 60.0), (RDAP_PER_HOUR, 3600.0)), self.clock))
            if limit.wait() > 0:
                return {}, True
            limit.take()
            self.asked["rdap"] += 1
            try:
                status, headers, doc, location = _get(url)
            except Exception:  # noqa: BLE001 - a registry that does not answer: tried again after KEEP_S
                return {"network": "", "org": "", "country": ""}, False
            if status == 429:
                limit.hold(_seconds(headers.get("Retry-After"), BACKOFF_S))
                return {}, True
            if status == 403:
                limit.hold(BACKOFF_S)
                return {}, True
            if status in (301, 302, 303, 307, 308) and location:
                url = urljoin(url, location)
                parts = urlsplit(url)
                host = parts.hostname or ""
                if parts.scheme != "https" or host not in self._hosts:  # only the registries' own hosts
                    return {"network": "", "org": "", "country": ""}, False
                continue
            net = network_of(doc) if status == 200 else {}
            if net:
                self._keep_range(doc, net)
                return net, False
            return {"network": "", "org": "", "country": ""}, False
        return {"network": "", "org": "", "country": ""}, False

    def _keep_range(self, doc, net: dict) -> None:
        try:
            first = int(ipaddress.ip_address(str(doc.get("startAddress"))))
            last = int(ipaddress.ip_address(str(doc.get("endAddress"))))
        except (TypeError, ValueError):
            return
        with self._lock:
            self._ranges[(first, last)] = dict(net)
            while len(self._ranges) > MAX_RANGES:
                self._ranges.popitem(last=False)


def _span(said) -> tuple[int, int] | None:
    """1.75.1: a range as network_of says it ("62.0.0.0 - 62.0.255.255") as (first, last), or None."""
    try:
        start, end = (ipaddress.ip_address(p.strip()) for p in str(said or "").split(" - "))
    except ValueError:
        return None
    first, last = int(start), int(end)
    return (first, last) if start.version == end.version and first <= last else None


def _seconds(value, default: float) -> float:
    """A Retry-After in seconds (its number form; a date or nothing: `default`)."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
