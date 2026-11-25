"""Services' networks through the firewall (1.93.0; service-containers-networking-2026-11-23.md §4 to §9). The user,
2026-11-23: "all services/containers will use the firewall app to create routing for the IP ranges of the containers,
and the firewall app will provide name resolution for local services/containers all as an API"; "they do need to make
sure that there is a route from the OS firewall, to the virtual bridge (layer2) that connects each segment of
containers"; "the firewall app will know it's domain, and have name resolution to each container, reverse lookup for
all containers, and contain DHCP records for dynamically assigned addresses"; "all this is mediated between the
firewall API and the containers (plugin to plugin)".

The words that cross (`Want`, `Member`, `Segment`, `Route`, `NameRecord`, `Lease`, each with as_dict and of), the pool
(`Pool`: 10.77.0.0/16, the Windows platform's half 10.77.0.0/17 and the Linux suite's 10.77.128.0/17, a /24 a
segment), the names (`names_for`, `ptr_of`) and the firewall's network part, `NetworkHost`: the base a firewall plugin
is built on for routes, names and DHCP records. A container plugin asks it, as its owner, for each service's network
(`network_plan`); you approve that plan on the page (its own approve_plan, page-only); the container plugin's work then
carries it out (`apply_network`), and the firewall's own steps run inside that work alone (`run_steps`, the subclass's:
UAC on Windows, root on Linux). The firewall hands out and never takes: a prefix, an address, a next hop or a name.

This release builds the base and its words; the two firewall plugins' steps (New-NetRoute, the port proxy, ip route)
come with their own releases. machines/standins.py's StandInNetworkHost carries every step out in memory for tests."""
from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
from dataclasses import asdict, dataclass, field, fields
from typing import Callable, Mapping

from ..apps import asking
from ..instances import Refusal, Store
from . import netguard
from .containers import SEGMENTS, network_name, split_sid
from .plans import Accept, Cancelled, Plans, Work, Works
from .plugin import MachinePlugin

STACKS = ("windows", "wsl", "linux")  # this PC's Windows; WSL 2's one VM; a Linux machine's own
KINDS = ("docker-bridge", "hns-nat", "incus-bridge", "k8s-pods", "k8s-services", "desktop", "nested")
# who gave a member its address: the firewall's ("reserved"), or the runtime's own (1.95.0: "kubernetes", any cluster's)
ASSIGNS = ("reserved", "docker", "hns", "incus", "k3s", "dhcp", "kubernetes")
VIEWS = ("inside", "lan", "wan")
# 1.95.0: "add", a part added to a service whose network is made (its address and names beside the others')
NET_ACTIONS = ("install", "start", "expose", "conceal", "remove", "delete_data", "add")
POOL = "10.77.0.0/16"
HALVES = {"windows": "10.77.0.0/17", "linux": "10.77.128.0/17"}  # N5: each platform allocates its own half
SEGMENT_PREFIX, WIDEST = 24, netguard.WIDEST
DOMAIN = "home.arpa"  # until you choose (N13)
DOMAIN_VAR = "LIMINAL_NET_DOMAIN"
DOCKER_LEAST = (28, 2, 0)  # trusted_host_interfaces
UAC_WAIT_S = 120.0
NO_LISTEN = netguard.NO_LISTEN_PORTS
FIRST_PART = 10  # .10 to .49: each part's fixed address, in the order of the spec's parts
# never handed out: carriers' NAT and Tailscale, k3s' pods and Services, WSL's DNS tunnel, Docker Desktop's
RESERVED = ("100.64.0.0/10", "10.42.0.0/16", "10.43.0.0/16", "10.255.255.254/32", "192.168.65.0/24")
NETWORK_HOST, RESOLVER_FOR, NAME_RECORDS = "network_host", "resolver_for", "name_records"
RESOLVE, REVERSE, LEASES, LAN_OPEN = "resolve_name", "reverse_name", "leases", "lan_open"
NET_PLAN, APPLY_NET, NET_WORK, NET_CANCEL = "network_plan", "apply_network", "network_work", "network_cancel"
PLAN_WORDS, APPROVE, DECLINE = "plan_words", "approve_plan", "decline_plan"
NET_GRANT, NET_REVOKE, SET_DOMAIN, WITHDRAW = "grant_network", "revoke_network", "set_domain", "withdraw"
WSL_NETWORK = "wsl_network"
ACCEPT_LAN, ACCEPT_SHARED, ACCEPT_WAN = "accept_lan", "accept_shared", "accept_wan"


def _of(cls, m):
    known = {f.name for f in fields(cls)}
    data = {k: v for k, v in dict(m or {}).items() if k in known}
    for f in fields(cls):
        if f.name in data and isinstance(data[f.name], list):
            data[f.name] = tuple(data[f.name])
    return cls(**data)


@dataclass(frozen=True)
class Want:
    """What a container plugin asks for: never a prefix, an address or a name of its own to be handed out. Since
    1.95.0 it may say what its engine has already, to be reserved and recorded as it is (Runtime.network_want):

    - `found`: a prefix its engine's own network has (Windows' one NAT network, a cluster's pod range): reserved for
      this service, never handed out of the pool, never routed unless `route`;
    - `assigns`: who gives the parts their addresses: "reserved" (the firewall, from `found` or the pool) or the
      runtime's own word of ASSIGNS ("hns", "kubernetes", "incus", "docker"): the firewall then hands none out and
      records the members' addresses as the container plugin's segments() read them;
    - `shared`: the found network is shared by several services (Windows' nat): each reserves it, none frees it;
    - `route`: whether a route to it is wanted from this machine's own stack (False: a cluster's pods, N27 (a));
    - `behind`: the address a nested segment sits behind (LXD's Docker inside liminal-oci: liminal-oci's address on
      its bridge): the route's next hop on the target's own stack, instead of none.
    Each published port may carry `here`: where this machine reaches it (a NodePort at the node's address), so that
    an Expose's proxy points there and not at 127.0.0.1:<host>."""

    stack: str
    target: str
    network: str  # "liminal-jenkins-ci"
    parts: tuple  # ("controller",): an address and names each
    ports: tuple = ()  # the published ports, each {"name", "host", "protocol"} (and "here", 1.95.0)
    lan: bool = False  # the form's "your network"
    needs: tuple = ()  # the sids it must reach (later, with agents across services)
    found: str = ""
    assigns: str = "reserved"
    shared: bool = False
    route: bool = True
    behind: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        return {k: list(v) if isinstance(v, tuple) else v for k, v in d.items()}

    @classmethod
    def of(cls, m) -> "Want":
        w = _of(cls, m)
        if w.stack not in STACKS:
            raise Refusal(f"a network is wanted on one of {', '.join(STACKS)}, not {str(w.stack)[:20]!r}")
        if not w.parts or any(not isinstance(p, str) for p in w.parts):
            raise Refusal("a network is wanted for one part at least")
        if w.needs:
            raise Refusal("reaching another service comes later (with agents across services)")
        if w.assigns not in ASSIGNS:
            raise Refusal(f"a network's addresses are given by one of {', '.join(ASSIGNS)}, not {str(w.assigns)[:20]!r}")
        for word, value in (("found", w.found), ("behind", w.behind)):
            if value:
                try:
                    (ipaddress.ip_network if word == "found" else ipaddress.ip_address)(str(value))
                except ValueError:
                    raise Refusal(f"a network's {word} is {'a prefix' if word == 'found' else 'an address'}, not "
                                  f"{str(value)[:40]!r}") from None
        if w.shared and not w.found:
            raise Refusal("a shared network is one its engine has: say its prefix (found)")
        return w


@dataclass(frozen=True)
class Member:
    """One container's place on a segment, as its engine says."""

    sid: str
    part: str
    container: str
    hostname: str = ""
    mac: str = ""
    ipv4: str = ""
    ipv6: str = ""
    assigned: str = "docker"
    until: float | None = None
    running: bool = False

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def of(cls, m) -> "Member":
        return _of(cls, m)


@dataclass(frozen=True)
class Segment:
    """One layer-2 network containers sit on, as its container plugin reads it."""

    segment: str  # "docker/wsl-ubuntu/liminal-jenkins-ci"
    plugin: str
    target: str
    network: str
    kind: str
    bridge: str
    stack: str
    platform: str = ""
    sid: str = ""  # "" for a found segment
    subnets: tuple = ()
    gateways: tuple = ()
    mode: str = "nat"
    trusted: tuple = ()
    assigns: str = "docker"
    layer2: str = "internal"  # "lan" is refused (rule 12)
    names: str = ""
    members: tuple = ()
    stable: bool = True

    def as_dict(self) -> dict:
        d = asdict(self)
        d["members"] = [m if isinstance(m, Mapping) else m.as_dict() for m in self.members]
        return {k: list(v) if isinstance(v, tuple) else v for k, v in d.items()}

    @classmethod
    def of(cls, m) -> "Segment":
        s = _of(cls, m)
        return Segment(**{**asdict(s), "members": tuple(Member.of(x) if isinstance(x, Mapping) else x
                                                       for x in s.members)})


@dataclass(frozen=True)
class Route:
    stack: str
    prefix: str
    next_hop: str
    interface: int
    segment: str
    made: float
    state: str = "current"

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class NameRecord:
    name: str
    type: str
    value: str
    view: str = "inside"
    sid: str = ""
    part: str = ""
    found: bool = False
    ttl: int = 30

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Lease:
    segment: str
    address: str
    mac: str
    hostname: str
    assigned: str
    since: float
    until: float | None
    seen: float
    state: str = "current"

    def as_dict(self) -> dict:
        return asdict(self)


def ptr_of(address: str) -> str:
    """An address's reverse name: 10.77.1.10 -> 10.1.77.10.in-addr.arpa."""
    return ipaddress.ip_address(address).reverse_pointer


def names_for(sid: str, parts, domain: str = DOMAIN, addresses: Mapping[str, str] | None = None,
              linux: bool = False) -> list[NameRecord]:
    """A service's names (N14): <owner>-<name>.<domain> for the service (its first part's address),
    <part>.<owner>-<name>.<domain> for each part, each address's reverse name its part's; the Linux suite's under
    linux.<domain>. Every label fits in 63 characters."""
    owner, name = split_sid(sid)
    base = f"{owner}-{name}." + (f"linux.{domain}" if linux else domain)
    out: list[NameRecord] = []
    addresses = dict(addresses or {})
    for i, part in enumerate(parts):
        address = addresses.get(part, "")
        full = f"{part}.{base}"
        if any(len(label) > 63 for label in full.split(".")):
            raise Refusal(f"the name {full} has a label longer than 63 characters")
        if not address:
            continue
        if i == 0:
            out.append(NameRecord(base, "A", address, sid=sid, part=part))
        out.append(NameRecord(full, "A", address, sid=sid, part=part))
        out.append(NameRecord(ptr_of(address), "PTR", full, sid=sid, part=part))
    return out


def aliases_for(sid: str, part: str, first: bool, domain: str = DOMAIN, linux: bool = False) -> list[str]:
    """The names a container is given inside its own network (Docker's --network-alias)."""
    owner, name = split_sid(sid)
    base = f"{owner}-{name}." + (f"linux.{domain}" if linux else domain)
    return [f"{part}.{base}", *([base] if first else [])]


class Pool:
    """The pool's half of one platform, handing out a /24 that meets none of the networks to avoid."""

    def __init__(self, half: str, size: int = SEGMENT_PREFIX):
        self.half = ipaddress.ip_network(half)
        self.size = size

    def allocate(self, avoid=()) -> tuple[str, list[str]]:
        """The first /24 of the half meeting nothing in `avoid` (plus RESERVED), and what the ones skipped met. A
        Refusal in words when none is clear."""
        skipped: list[str] = []
        blocked = [*avoid, *RESERVED]
        for subnet in self.half.subnets(new_prefix=self.size):
            if subnet.network_address == self.half.network_address and self.half == ipaddress.ip_network(HALVES["windows"]):
                continue  # 10.77.0.0/24 is the names network's (N17), kept
            met = netguard.overlaps(subnet, blocked)
            if not met:
                return str(subnet), skipped
            if len(skipped) < 8:
                skipped.append(f"{subnet} meets {', '.join(met[:3])}")
        raise Refusal(f"no /{self.size} of {self.half} is clear: " + "; ".join(skipped[:4]))


def addresses_in(subnet: str, parts) -> tuple[str, dict[str, str]]:
    """A segment's gateway (.1) and each part's fixed address (.10 and on, in order)."""
    net = ipaddress.ip_network(subnet)
    base = int(net.network_address)
    if len(parts) > 40:
        raise Refusal("a segment holds 40 parts' fixed addresses at most")
    return str(ipaddress.ip_address(base + 1)), {p: str(ipaddress.ip_address(base + FIRST_PART + i))
                                                 for i, p in enumerate(parts)}


@dataclass
class Allocation:
    """A prefix handed out: held by a plan not yet carried out (`state` "held"), made, removed (its route gone, kept
    for Install again), or freed."""

    prefix: str
    stack: str
    segment: str
    sid: str
    plugin: str
    platform: str
    gateway: str
    addresses: dict
    state: str = "held"
    plan: str = ""
    route: dict | None = None  # the route made: {"next_hop", "interface"}
    exposed: list = field(default_factory=list)  # the ports opened to your network
    made: float = 0.0
    found: bool = False  # 1.95.0: a prefix its engine has, reserved (never handed out of the pool)
    shared: bool = False  # 1.95.0: that found network is shared by several services
    assigns: str = "reserved"  # 1.95.0: who gives its members their addresses

    def as_dict(self) -> dict:
        return asdict(self)


class MemoryBook:
    """Where a NetworkHost keeps its allocations and records: in memory, for the stand-ins and until a firewall's own
    network database (netbook, one SQLite file per system) comes with its release."""

    def __init__(self):
        self.lock = threading.Lock()
        self.allocations: dict[str, Allocation] = {}  # by sid
        self.changes: list[dict] = []

    def of_sid(self, sid: str) -> Allocation | None:
        with self.lock:
            return self.allocations.get(sid)

    def all(self) -> list[Allocation]:
        with self.lock:
            return list(self.allocations.values())

    def put(self, a: Allocation) -> None:
        with self.lock:
            self.allocations[a.sid] = a

    def free(self, sid: str) -> None:
        with self.lock:
            self.allocations.pop(sid, None)

    def note(self, at: float, plan: str, owner: str, action: str, words: str) -> None:
        with self.lock:
            self.changes.append({"at": at, "plan": plan, "owner": owner, "action": action, "words": words})
            del self.changes[:-500]


@dataclass(frozen=True)
class Step:
    """One of a firewall's own steps, run only inside an approved plan's work (`run_steps`): its kind (route, unroute,
    proxy, unproxy, rule, unrule), its words, and what the subclass builds it from."""

    kind: str
    words: str
    detail: Mapping = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"kind": self.kind, "words": self.words, "detail": dict(self.detail)}


class _NetState:
    def __init__(self, clock):
        self.plans = Plans("n-", clock)
        self.works = Works("nw-", clock, "liminal-network-work")
        self.lock = threading.Lock()


class NetworkHost(MachinePlugin):
    """The firewall's network part: routes, names and DHCP records for the container plugins' segments. A subclass (a
    firewall plugin) gives its system's own facts and steps; this base holds the plans, the grants, the domain, the
    allocations and the records, and its gates. Neither declares CONTRACT, so their hooks count as answered."""

    HOOKS = (*MachinePlugin.HOOKS, NETWORK_HOST, RESOLVER_FOR, NAME_RECORDS, RESOLVE, REVERSE, LEASES, LAN_OPEN,
             NET_PLAN, PLAN_WORDS, APPROVE, DECLINE, APPLY_NET, NET_WORK, NET_CANCEL, NET_GRANT, NET_REVOKE,
             SET_DOMAIN, WITHDRAW)
    READ_HOOKS = (NETWORK_HOST, RESOLVER_FOR, NAME_RECORDS, RESOLVE, REVERSE, LEASES, LAN_OPEN, PLAN_WORDS, NET_WORK)
    SERVICE_HOOKS = (NETWORK_HOST, RESOLVER_FOR, NAME_RECORDS, RESOLVE, REVERSE, LEASES, LAN_OPEN, NET_PLAN,
                     PLAN_WORDS, DECLINE, APPLY_NET, NET_WORK, NET_CANCEL)
    PLUGIN_ONLY_HOOKS = (NET_PLAN, APPLY_NET, NET_WORK)
    PAGE_ONLY_HOOKS = (APPROVE, NET_GRANT, NET_REVOKE, SET_DOMAIN, WITHDRAW)
    ASKS = (("", SEGMENTS, "each container plugin's segments and members: what it routes, names and records"),
            ("", WSL_NETWORK, "WSL's mode and the VM's address, a route's next hop; read only while a distribution runs"))

    def __init__(self, clock: Callable[[], float] | None = None, wall: Callable[[], float] | None = None,
                 book: MemoryBook | None = None, platform: str = ""):
        self._net = _NetState(clock or time.monotonic)
        self._net_wall = wall or time.time
        self._book = book or MemoryBook()
        self._net_platform = platform

    # -- what a subclass gives --------------------------------------------------------------------------------------
    def stacks(self) -> dict:
        """{"own": "windows", "routes_to": ("wsl",)}: the stack it owns and those it routes to."""
        return {"own": "windows", "routes_to": ()}

    def networks_here(self) -> list[str]:
        """Every prefix on its interfaces and routes, read with no rights: what an allocation must not meet."""
        return []

    def next_hop(self, stack: str) -> tuple[str, int, str]:
        """(the next hop's address, its interface's index, "") for a route to a segment on `stack`, or ("", 0, why
        not). The base routes nothing to its own stack (a bridge on its own host is a connected route)."""
        return "", 0, f"{self.title or self.name} routes to no {stack} segment yet"

    def lan_state(self, port: int, protocol: str) -> dict:
        """Whether this machine's firewall lets `port` in from your network now: {"state": one of "lan", "wider",
        "closed", "past", "unknown", "words"}, from its own kept read."""
        return {"state": "unknown", "words": "not known"}

    def run_steps(self, steps: list[Step], line: Callable[[str], None], cancelled: Callable[[], bool]) -> None:
        """Its steps carried out, inside an approved plan's work alone (one elevated script on Windows, root's sh on
        Linux). The base carries out none."""
        raise Refusal(f"{self.title or self.name} carries out no network step yet (its release brings them)")

    def view_value(self, view: str, a: Allocation, part: str) -> str:
        """What a name answers in a view other than "inside": nothing in this release (N19, N20)."""
        return ""

    # -- the plain parts ----------------------------------------------------------------------------------------------
    def _platform(self) -> str:
        if self._net_platform:
            return self._net_platform
        from .. import claims

        return claims.instance()

    def _half(self) -> str:
        """Its platform's half of the pool (N5): the Linux half for a firewall that owns a Linux stack, or owns WSL's
        from a Linux platform inside it (1.95.0: every Linux inside WSL is the stack "wsl"), the Windows half
        otherwise."""
        own = str(self.stacks().get("own") or "windows")
        if own == "linux" or (own == "wsl" and str(self._platform()).lower().startswith("linux")):
            return HALVES["linux"]
        return HALVES["windows"]

    def _var(self, what: str) -> str:
        return f"{self.name.upper().replace('-', '_')}_{what}"

    def _store(self, what: str) -> Store:
        return Store(self._var(what), lambda: self.login)

    def domain(self) -> str:
        try:
            got = (self.login.variables([DOMAIN_VAR]).get(DOMAIN_VAR, "") if self.login is not None else "") or ""
        except Exception:  # noqa: BLE001 - a login that cannot be asked: the default domain
            got = ""
        return got.strip().lower() or DOMAIN

    def network_grants(self) -> list[str]:
        try:
            data = json.loads(self._store("NETWORK_GRANTS").text() or "{}")
        except (ValueError, Exception):  # noqa: BLE001 - nothing kept, or not readable: no grant
            return []
        return sorted(str(p) for p in data.get("plugins", []) if isinstance(p, str))

    def _owner(self, hook: str) -> str:
        """The plugin asking, for a hook only a granted container plugin asks: refused in words otherwise."""
        who = asking.asker()
        if who is None:
            raise Refusal(f"{self.name}'s {hook} names no asker: only a container plugin you let asks it")
        if who == asking.PAGE:
            raise Refusal(f"{self.name}'s {hook} is asked by a container plugin alone, never from a page")
        if who not in self.network_grants():
            raise Refusal(f"{who} may not ask {self.title or self.name} for networks: let it on the firewall's "
                          "Networks tab first", )
        app = self.app
        hooks = []
        try:
            hooks = list(((app.plugins() or {}).get(who) or {}).get("hooks") or []) if app is not None else []
        except Exception:  # noqa: BLE001 - an app that cannot list its plugins: no container plugin is known
            hooks = []
        if SEGMENTS not in hooks:
            raise Refusal(f"{who} is no container plugin (its hooks list no {SEGMENTS})")
        return who

    def _page_or_owner(self, owner: str, hook: str) -> str:
        who = asking.asker()
        if who == asking.PAGE or (who is not None and who == owner):
            return who
        raise Refusal(f"{self.name}'s {hook} is asked from its page or by the plan's owner ({owner}), "
                      f"not by {who or 'no one'}")

    def _facts(self, sid: str, stack: str) -> dict:
        hop, iface, why = self.next_hop(stack) if stack != self.stacks().get("own") else ("", 0, "")
        a = self._book.of_sid(sid)
        return {"next_hop": hop, "interface": iface, "hop_why": why, "domain": self.domain(),
                "allocation": a.prefix if a else "", "route": dict(a.route) if a and a.route else None}

    # -- the hooks -----------------------------------------------------------------------------------------------------
    def network_host(self) -> dict:
        """The stack it owns and those it routes to, its domain, its half of the pool, how names are served, its
        grants, and whether it can carry out its steps now (and why not)."""
        st = self.stacks()
        return {"plugin": self.name, "title": self.title or self.name, "own": st.get("own"),
                "routes_to": list(st.get("routes_to") or ()), "domain": self.domain(), "half": self._half(),
                "names": "records alone: no name server in this release (N16)", "grants": self.network_grants(),
                "dhcp": "records only (N21)"}

    def resolver_for(self, target: str = "", needs=()) -> dict:
        """What a container on that target is given: its search domain, a server (none in this release), and the
        --add-host lines for the sids it needs (none yet)."""
        return {"domain": self.domain(), "server": None, "add_hosts": [],
                "words": "names are answered inside each service's own network by its engine; no server of Liminal's"}

    def name_records(self, view: str = "inside", sid: str = "") -> dict:
        """The A, AAAA and PTR records of a view (inside; lan and wan hold none in this release), one sid's alone when named."""
        if view not in VIEWS:
            raise Refusal(f"a view is one of {', '.join(VIEWS)}, not {str(view)[:20]!r}")
        out: list[dict] = []
        for a in self._book.all():
            if sid and a.sid != sid or a.state not in ("made", "removed"):
                continue
            if view == "inside":
                out += [r.as_dict() for r in names_for(a.sid, list(a.addresses), self.domain(), a.addresses,
                                                       linux=self.stacks().get("own") == "linux")]
        words = "" if view == "inside" else ("names on your network are your router's in this release (N19)"
                                             if view == "lan" else "no public name until a TLS front exists (N20)")
        return {"view": view, "records": out, "words": words}

    def resolve_name(self, name: str, view: str = "inside") -> dict:
        """One name's addresses, from the records alone: no server is asked."""
        key = str(name or "").strip().lower().rstrip(".")
        found = [r for r in self.name_records(view)["records"] if r["name"] == key and r["type"] in ("A", "AAAA")]
        return {"name": key, "addresses": [r["value"] for r in found]}

    def reverse_name(self, address: str) -> dict:
        """One address's name, from the records alone."""
        try:
            ptr = ptr_of(str(address))
        except ValueError:
            raise Refusal(f"{str(address)[:40]!r} is not an address") from None
        found = [r for r in self.name_records("inside")["records"] if r["name"] == ptr]
        return {"address": str(address), "name": found[0]["value"] if found else ""}

    def leases(self, segment: str = "") -> dict:
        """The DHCP records: each address handed out, as its allocation holds it (the engines' own leases with each
        container plugin's segments read)."""
        rows = []
        for a in self._book.all():
            seg = f"{a.plugin}/{a.segment}"
            if segment and segment not in (seg, a.segment):
                continue
            for part, addr in a.addresses.items():
                rows.append(Lease(seg, addr, "", part, "reserved", a.made, None, a.made,
                                  "current" if a.state == "made" else a.state).as_dict())
        return {"leases": rows}

    def lan_open(self, ports, protocol: str = "tcp") -> dict:
        """Per port, whether this machine's firewall lets it in from your network now, from its own kept read."""
        out = {}
        for p in list(ports or ())[:64]:
            try:
                port = int(p)
            except (TypeError, ValueError):
                continue
            out[str(port)] = self.lan_state(port, str(protocol))
        return {"ports": out}

    def network_plan(self, action: str, sid: str, want) -> dict:
        """The network part of a container plugin's plan, held in the firewall's own words: the segment's prefix and
        each part's address handed out (held meanwhile), the route from this machine's stack, the names. Answers
        `nothing` (in words) when nothing changes, `narrows` when it only takes away."""
        owner = self._owner(NET_PLAN)
        act = str(action or "")
        if act not in NET_ACTIONS:
            raise Refusal(f"a network is planned for one of {', '.join(NET_ACTIONS)}, not {act[:20]!r}")
        sid_owner, name = split_sid(sid)
        w = Want.of(want)
        st = self.stacks()
        own, routes = str(st.get("own")), tuple(st.get("routes_to") or ())
        if w.stack != own and w.stack not in routes:
            raise Refusal(f"{self.title or self.name} routes and names {own}"
                          + (f" and {', '.join(routes)}" if routes else "") + f" segments, not {w.stack}'s")
        title = f"{self.title or self.name}: the network of {sid} ({act})"
        a = self._book.of_sid(sid)
        facts = self._facts(sid, w.stack)
        steps: list[Step] = []
        accepts: list[Accept] = []
        narrows = act in ("remove", "delete_data", "conceal")
        extra: dict = {"stack": w.stack, "network": w.network, "segment": f"{owner}/{w.target}/{w.network}"}
        if act == "install":
            if w.found:
                subnet, gateway, addresses = self._reserve_found(sid, w)
                extra["found"] = (f"{subnet}, {w.target}'s own network, reserved for {sid}"
                                  + (" (shared with the other services there)" if w.shared else "")
                                  + ("" if w.assigns == "reserved" else f"; its addresses given by {w.assigns}"))
            elif a is not None and a.state in ("made", "removed") and set(a.addresses) == set(w.parts):
                subnet, gateway, addresses = a.prefix, a.gateway, dict(a.addresses)
                extra["kept"] = f"{subnet}, kept from before (the same addresses and names)"
            else:
                if a is not None and a.state == "held" and a.plan and self._held(a.plan):
                    raise Refusal(f"a plan for {sid}'s network waits already ({a.plan}): approve or decline it")
                avoid = [*self.networks_here(), *(x.prefix for x in self._book.all() if x.sid != sid)]
                subnet, skipped = Pool(self._half()).allocate(avoid)
                gateway, addresses = addresses_in(subnet, list(w.parts))
                if skipped:
                    extra["skipped"] = skipped
            facts["allocation"] = subnet
            extra.update({"subnet": subnet, "gateway": gateway, "addresses": addresses, "assigns": w.assigns,
                          "shared": w.shared, "is_found": bool(w.found)})
            if w.behind and w.stack != own:
                raise Refusal(f"{sid}'s segment sits behind {w.behind} on {w.stack}: a nested segment is routed by the "
                              f"firewall of its own stack ({w.stack}) alone in this release")
            if w.behind and w.route:
                route = Route(w.stack, subnet, w.behind, 0, extra["segment"], self._net_wall())
                steps.append(Step("route", f"a route to {subnet} through {w.behind} (the instance it sits behind)",
                                  route.as_dict()))
                extra["routes"] = [route.as_dict()]
            elif w.stack != own and w.route:
                hop, iface, why = facts["next_hop"], facts["interface"], facts["hop_why"]
                if not hop:
                    raise Refusal(f"no route can be made to {sid}'s segment: {why}")
                route = Route(w.stack, subnet, hop, iface, extra["segment"], self._net_wall())
                steps.append(Step("route", f"a route to {subnet} through {hop} (the {w.stack} VM)", route.as_dict()))
                extra["routes"] = [route.as_dict()]
            elif not w.route:
                extra["no_route"] = f"no route to {subnet} is made: {w.target}'s engine reaches it its own way"
            if w.lan and w.ports:
                steps += self._lan_steps(sid, w, make=True)
                accepts.append(self._lan_accept(w))
            names = names_for(sid, list(w.parts), self.domain(), addresses, linux=own == "linux")
            extra["names"] = [r.as_dict() for r in names]
        elif act == "add":
            if a is None or a.state != "made":
                raise Refusal(f"{sid} has no network made by {self.title or self.name}: install it first")
            new = [p for p in w.parts if p not in a.addresses]
            if not new and not (a.assigns != "reserved" and w.lan and w.ports):
                return {"nothing": f"every part of {sid} has its place on {a.prefix} already", "plan": "",
                        "narrows": False, "subnet": a.prefix, "gateway": a.gateway, "addresses": dict(a.addresses)}
            addresses = dict(a.addresses)
            if a.assigns == "reserved":
                addresses.update(self._more_addresses(a, new))
            extra.update({"subnet": a.prefix, "gateway": a.gateway, "addresses": addresses, "adds": new})
            if w.lan and w.ports:
                steps += self._lan_steps(sid, w, make=True)
                accepts.append(self._lan_accept(w))
            names = names_for(sid, [*a.addresses, *new], self.domain(), addresses, linux=own == "linux")
            extra["names"] = [r.as_dict() for r in names if r.part in new]
        elif act == "start":
            if a is None or a.state != "made":
                return {"nothing": f"{sid} has no network made by {self.title or self.name}: install it first",
                        "plan": "", "narrows": False}
            extra.update({"subnet": a.prefix, "gateway": a.gateway, "addresses": dict(a.addresses)})
            if w.stack != own:
                hop, iface = facts["next_hop"], facts["interface"]
                if not hop:
                    raise Refusal(f"{sid}'s route cannot be made again now: {facts['hop_why']}")
                if a.route and a.route.get("next_hop") == hop:
                    return {"nothing": f"the route to {a.prefix} goes through {hop}, as it should",
                            "plan": "", "narrows": False, **extra}
                route = Route(w.stack, a.prefix, hop, iface, extra["segment"], self._net_wall())
                steps.append(Step("route", f"the route to {a.prefix} pointed again at {hop}", route.as_dict()))
                extra["routes"] = [route.as_dict()]
            else:
                return {"nothing": "a segment on this machine's own stack needs no route", "plan": "",
                        "narrows": False, **extra}
        elif act == "expose":
            if a is None:
                raise Refusal(f"{sid} has no network made by {self.title or self.name}: install it first")
            steps += self._lan_steps(sid, w, make=True)
            accepts.append(self._lan_accept(w))
        else:  # conceal, remove, delete_data: only takes away
            if a is None:
                return {"nothing": f"{sid} has no network kept by {self.title or self.name}", "plan": "",
                        "narrows": True}
            if a.exposed:
                steps += self._lan_steps(sid, w, make=False)
            if act != "conceal" and a.route:
                steps.append(Step("unroute", f"the route to {a.prefix} taken away", dict(a.route)))
            if act == "delete_data":
                extra["frees"] = f"{a.prefix} and its addresses freed, its names forgotten"
            if not steps and act == "conceal":
                return {"nothing": f"{sid} is not open to your network", "plan": "", "narrows": True}
        words = self._words(act, sid, w, extra, steps)
        plan = self._net.plans.hold(owner=owner, action=act, subject=sid, target=w.target, title=title, words=words,
                                    facts=facts, steps=[s.words for s in steps], accepts=accepts, narrows=narrows,
                                    extra={**extra, "_steps": [s.as_dict() for s in steps], "want": w.as_dict()})
        if act == "install" and "kept" not in extra:
            self._book.put(Allocation(extra["subnet"], w.stack, extra["segment"], sid, owner, self._platform(),
                                      extra["gateway"], extra["addresses"], "held", plan.plan, found=bool(w.found),
                                      shared=w.shared, assigns=w.assigns))
        out = plan.as_dict(self._net.plans.clock())
        out.pop("_steps", None)
        return out

    def _reserve_found(self, sid: str, w: Want) -> tuple[str, str, dict]:
        """A prefix its engine has (Want.found), reserved for `sid` as it is (1.95.0): refused where it meets another
        service's allocation, unless both say the one same shared network. Its gateway and addresses are handed out
        only when the firewall gives the addresses (assigns "reserved")."""
        net = ipaddress.ip_network(str(w.found), strict=False)
        subnet = str(net)
        for x in self._book.all():
            if x.sid == sid or not netguard.overlaps(net, [x.prefix]):
                continue
            if w.shared and x.shared and x.prefix == subnet:
                continue
            raise Refusal(f"{subnet} meets {x.prefix}, {x.sid}'s network: it is not reserved for {sid}")
        if w.assigns != "reserved":
            return subnet, "", {}
        gateway, addresses = addresses_in(subnet, list(w.parts))
        return subnet, gateway, addresses

    def _more_addresses(self, a: Allocation, parts: list[str]) -> dict[str, str]:
        """The next free fixed addresses of a made segment (.10 and on) for parts added to its service."""
        net = ipaddress.ip_network(a.prefix)
        used = set(a.addresses.values())
        out: dict[str, str] = {}
        n = FIRST_PART
        for part in parts:
            while str(ipaddress.ip_address(int(net.network_address) + n)) in used:
                n += 1
            if n >= FIRST_PART + 40:
                raise Refusal("a segment holds 40 parts' fixed addresses at most")
            addr = str(ipaddress.ip_address(int(net.network_address) + n))
            out[part] = addr
            used.add(addr)
        return out

    def _held(self, plan: str) -> bool:
        try:
            self._net.plans.get(plan)
            return True
        except Refusal:
            return False

    def _lan_accept(self, w: Want) -> Accept:
        ports = ", ".join(f"{str(p.get('protocol', 'tcp')).upper()} {p.get('host')}" for p in w.ports)
        return Accept(ACCEPT_LAN, "Open it to your network?",
                      f"{ports} reached from your network (your local subnet alone, on the Private and Domain profiles; "
                      "plain http crosses your network in the clear)", "Open it")

    def _lan_steps(self, sid: str, w: Want, make: bool) -> list[Step]:
        kind = "proxy" if make else "unproxy"
        return [Step(kind, f"{'open' if make else 'close'} {str(p.get('protocol', 'tcp')).upper()} {p.get('host')} "
                     f"{'to' if make else 'from'} your network", {"sid": sid, **dict(p)}) for p in w.ports]

    def _words(self, act: str, sid: str, w: Want, extra: dict, steps: list[Step]) -> str:
        said = [f"{self.title or self.name} {'makes' if act in ('install', 'start', 'expose') else 'takes away'} "
                f"{sid}'s network on {w.target} ({w.stack})"]
        if extra.get("found"):
            said.append(f"its segment {extra['found']}")
        elif extra.get("subnet"):
            said.append(f"its segment {extra['subnet']} (gateway {extra.get('gateway')}), "
                        + ", ".join(f"{p} at {a}" for p, a in (extra.get("addresses") or {}).items()))
        if extra.get("no_route"):
            said.append(extra["no_route"])
        said += [s.words for s in steps]
        if extra.get("names"):
            said.append("its names: " + ", ".join(r["name"] for r in extra["names"] if r["type"] == "A"))
        return "; ".join(said) + "."

    def plan_words(self, plan: str) -> dict:
        """What the approval draws (as a container plugin's plan_words), its `approve_args` in approve_plan's order."""
        p = self._net.plans.get(plan)
        self._page_or_owner(p.owner, PLAN_WORDS)
        out = p.as_dict(self._net.plans.clock())
        out.pop("_steps", None)
        return {**out, "approve_args": [ACCEPT_LAN, ACCEPT_SHARED, ACCEPT_WAN], "plugin": self.name}

    def approve_plan(self, plan: str, accept_lan=False, accept_shared=False, accept_wan=False) -> dict:
        """Your approval of a network plan, from the page alone: refused, naming the accept it lacks, until each
        accept it names is exactly True."""
        if asking.asker() != asking.PAGE:
            raise Refusal(f"{self.name}'s approve_plan is yours, from the page alone: "
                          f"{asking.asker() or 'no one'} asked it")
        p = self._net.plans.approve(plan, {ACCEPT_LAN: accept_lan, ACCEPT_SHARED: accept_shared,
                                           ACCEPT_WAN: accept_wan})
        return {"said": f"approved: {p.title}", "ok": True, "plan": p.plan}

    def decline_plan(self, plan: str) -> dict:
        """Forgets a network plan and frees the prefix it held: from the page or its owner."""
        p = self._net.plans.get(plan)
        self._page_or_owner(p.owner, DECLINE)
        self._net.plans.decline(plan)
        a = self._book.of_sid(p.subject)
        if a is not None and a.state == "held" and a.plan == p.plan:
            self._book.free(p.subject)
        return {"said": f"declined: {p.title}", "ok": True}

    def apply_network(self, plan: str) -> dict:
        """An approved plan (or one that only narrows) begun, once, as a work: its facts read again first."""
        owner = self._owner(APPLY_NET)
        p = self._net.plans.get(plan)
        if p.owner != owner:
            raise Refusal(f"{p.title}: that plan is {p.owner}'s")
        if p.narrows and p.accepts:
            raise Refusal(f"{p.title}: a plan that takes away holds nothing that opens")
        facts = self._facts(p.subject, str(p.extra.get("stack")))
        if p.action == "install":
            facts["allocation"] = str(p.extra.get("subnet"))
        taken: list = []

        def ready() -> None:
            taken.append(self._net.plans.take(plan, owner, facts))
        w = self._net.works.begin(p, str(p.extra.get("stack")), lambda work: self._carry(work, taken[0]),
                                  lambda s: s, ready)
        return {"work": w.work}

    def _carry(self, work: Work, p) -> dict:
        steps = [Step(s["kind"], s["words"], s.get("detail") or {}) for s in p.extra.get("_steps") or []]
        work.line(p.title)
        if steps:
            work.check()
            self.run_steps(steps, work.line, work.cancelled)
        sid = p.subject
        a = self._book.of_sid(sid)
        now = self._net_wall()
        if p.action == "install":
            route = (p.extra.get("routes") or [None])[0]
            if a is None:
                a = Allocation(str(p.extra["subnet"]), str(p.extra["stack"]), str(p.extra["segment"]), sid, p.owner,
                               self._platform(), str(p.extra["gateway"]), dict(p.extra["addresses"]),
                               found=bool(p.extra.get("is_found")), shared=bool(p.extra.get("shared")),
                               assigns=str(p.extra.get("assigns") or "reserved"))
            a.state, a.plan, a.made = "made", p.plan, a.made or now
            a.route = {"next_hop": route["next_hop"], "interface": route["interface"]} if route else a.route
            a.exposed = [s.detail for s in steps if s.kind == "proxy"] or a.exposed
            self._book.put(a)
        elif a is not None:
            if p.action == "add":
                a.addresses = dict(p.extra.get("addresses") or a.addresses)
                a.exposed = [*a.exposed, *(s.detail for s in steps if s.kind == "proxy")]
            if p.action == "start" and p.extra.get("routes"):
                r = p.extra["routes"][0]
                a.route = {"next_hop": r["next_hop"], "interface": r["interface"]}
            elif p.action == "expose":
                a.exposed = [s.detail for s in steps if s.kind == "proxy"]
            elif p.action == "conceal":
                a.exposed = []
            elif p.action == "remove":
                a.exposed, a.route, a.state = [], None, "removed"
            if p.action == "delete_data":
                self._book.free(sid)
            else:
                self._book.put(a)
        self._book.note(now, p.plan, p.owner, p.action, p.words)
        work.line("done")
        return {"said": f"{p.title}: done", "ok": True}

    def network_work(self, work: str, after: int = 0) -> dict:
        """A network work's lines after `after`, whether it is done, and its answer: its owner's alone."""
        owner = self._owner(NET_WORK)
        w = self._net.works.get(work)
        if w.owner != owner:
            raise Refusal(f"that work is {w.owner}'s")
        return w.page(after)

    def network_cancel(self, work: str) -> dict:
        """Asks a network work to stop between its steps: from the page or its owner."""
        w = self._net.works.get(work)
        self._page_or_owner(w.owner, NET_CANCEL)
        w.cancel.set()
        return {"said": "asked to stop between its steps", "ok": True}

    def grant_network(self, plugin: str) -> dict:
        """Lets a container plugin ask for networks (N3), from the page alone: kept through your login."""
        return self._grant(plugin, True)

    def revoke_network(self, plugin: str) -> dict:
        """Stops letting a container plugin ask for networks, from the page alone."""
        return self._grant(plugin, False)

    def _grant(self, plugin: str, on: bool) -> dict:
        if asking.asker() != asking.PAGE:
            raise Refusal(f"{self.name}'s grants are yours, from the page alone")
        name = str(plugin or "").strip()
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", name):
            raise Refusal(f"not a plugin's name: {name[:40]!r}")
        grants = set(self.network_grants())
        grants = grants | {name} if on else grants - {name}
        where = self._store("NETWORK_GRANTS").put(json.dumps({"v": 1, "plugins": sorted(grants)}))
        return {"said": f"{name} {'may' if on else 'may no longer'} ask {self.title or self.name} for networks",
                "ok": True, "lines": [where]}

    def set_domain(self, domain: str) -> dict:
        """The domain its names are made in (home.arpa until you choose), kept through the login: from the page alone."""
        if asking.asker() != asking.PAGE:
            raise Refusal(f"{self.name}'s domain is yours, from the page alone")
        d = str(domain or "").strip().lower().rstrip(".")
        if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z]{2,63}", d) or \
                d.endswith(".local") or d == "local":
            raise Refusal(f"a domain is letters, digits, dashes and dots, never .local (mDNS's): not {d[:60]!r}")
        if self.login is None:
            raise Refusal("the domain is kept through the platform's login, and this plugin has none")
        where = self.login.save(DOMAIN_VAR, d)
        return {"said": f"the domain is {d}", "ok": True, "lines": [where]}

    def withdraw(self, segment: str) -> dict:
        """A gone segment's route, proxy and names taken away (the steps are the subclass's): its records kept,
        marked gone. From the page alone."""
        if asking.asker() != asking.PAGE:
            raise Refusal(f"{self.name}'s withdraw is yours, from the page alone")
        raise Refusal(f"{self.title or self.name} withdraws no segment yet (its release brings it)")

    # -- its own end ----------------------------------------------------------------------------------------------------
    def network_stopping(self) -> None:
        """Turned off, or the platform stops: every network work asked to stop and joined. Its plans forgotten."""
        self._net.works.cancel_all()
        self._net.plans.forget_all()
        for a in self._book.all():
            if a.state == "held":
                self._book.free(a.sid)

    def app_stopping(self) -> None:
        """The platform stops: its network works asked to stop and joined, its plans forgotten."""
        self.network_stopping()
        parent = getattr(super(), "app_stopping", None)
        if callable(parent):
            parent()

    def detach(self) -> None:
        self._net.plans.forget_all()
        for a in self._book.all():
            if a.state == "held":
                self._book.free(a.sid)
        off = False
        try:
            off = self.name in (self.app.disabled() if callable(getattr(self.app, "disabled", None)) else ())
        except Exception:  # noqa: BLE001 - a platform that cannot say: not turned off
            off = False
        if off:
            self._net.works.cancel_all()
        super().detach()


def network_name_of(sid: str) -> str:
    return network_name(sid)


__all__ = ["ACCEPT_LAN", "ACCEPT_SHARED", "ACCEPT_WAN", "Allocation", "DOMAIN", "HALVES", "Lease", "Member",
           "MemoryBook", "NameRecord", "NetworkHost", "POOL", "Pool", "Route", "Segment", "Step", "Want",
           "addresses_in", "aliases_for", "names_for", "ptr_of", "Cancelled"]
