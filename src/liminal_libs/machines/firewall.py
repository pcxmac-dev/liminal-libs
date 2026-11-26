"""A firewall as a machine plugin's base (the user, 2026-11-07: "i also need a windows and linux firewall
plugin for the platform"; the platform is "the interface for the software/hardware which facilitates the
liminal framework"). What the framework asks of a firewall: that it is on; that no rule lets another machine
reach the framework's own pages (they answer this machine only, at 127.0.0.1); and that the services this
machine runs for the framework, a domain login's mail server container, can be reached on their ports.
Every rule the framework makes is its own, marked as Liminal's (Windows' rule group "Liminal", a Linux
comment or service named liminal...), so it is listed, changed and removed apart from every other rule; a
rule that is not Liminal's is only ever read. A subclass drives one firewall (Windows Defender Firewall; ufw,
firewalld or nftables) through the backend methods; this base holds the rules, the framework's ports, the
status and the setup.

1.101.0 (Monday list item 20; the user, 2026-11-19: "add a way to download different GEOIP sources"): a subclass may
name GeoIP sources (GEOIP_SOURCES, machines/geosources.py), places and networks chosen apart, the first the default.
Three hooks only a person signed in at the platform's page may ask (PAGE_ONLY_HOOKS, and each refuses any other ask
itself): world_geoip_get (a job: the keys read through the asking person's login, the licence's acceptance kept in
their own login store or the download refused), world_geoip_use and world_geoip_remove (asked twice). The older
installs world_geoip and world_asn and a data set's download world_layer_get are named page-only by the base too, so
every firewall plugin has them so; a data set's licence accepted by a person signed in at the page is kept in their own
login store as licence-<its id>, as DB-IP's are (any other ask records nothing). 1.105.0: all of these, and 1.104.0's
sky (the sgp4 package's download and removal, the satellites' places, the orbits' refresh, the layers read by area),
left with the World Wide Web tab for machines/worldweb.py; this base keeps the rules, the Netstat tab and the hosts' recording, and
answers what the World Wide Web plugin asks of a firewall."""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass

from .. import hostbook as hostbook_module, sockets
from ..apps.tabs import Tab
from ..hostbook import HOSTS_KEY
from ..sources.keys import KeyVar
from . import asks, geosources, netstat, world as world_module
from .hostsvia import PlacesVia
from .netstat import NetstatView
from .plugin import CommandError, MachinePlugin
from .rulegroups import RuleGroups, Sorted

# 1.74.0 (the user, 2026-11-22: "lets have a selectable switch on firewall which allows it to run while not selected
# as far as monitoring traffic"): the traffic watched only while the World Wide Web tab is shown, or all the time
# the platform runs; kept through the plugin's login, as the hosts' recording is
WATCH_HOOK, WATCH_FORM, WATCH_VAR = "world_watching", "world-watching", "LIMINAL_TRAFFIC_WATCHING"
WATCH_WORDS = {"shown": "only while this tab is shown", "always": "all the time the platform runs"}
WATCH_READ_S = 10.0  # the setting read again through the login this long after, at the soonest
# set on the World Wide Web tab's form, or on the plugin's page beside the hosts' recording (one of its keys)
WATCH_KEY = KeyVar(WATCH_VAR, label="Watching the traffic", secret=False,
                   hint="optional: always keeps the World Wide Web tab's capture at this machine's adapter running "
                        "all the time the platform runs (its packets, ports and places counted with no page open); "
                        "shown, or nothing, only while the tab is shown")

GROUP = "Liminal"  # Windows' rule group; a rule's display name is "Liminal: <name>"
PREFIX = "liminal"  # a Linux rule's comment (liminal:<name>) or service (liminal-<name>)
STEPS = ("enable", "exposure", "rules")
DIRECTIONS = ("in", "out")
ACTIONS = ("allow", "block")
PROTOCOLS = ("tcp", "udp", "any")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
LOOPBACK = ("127.0.0.1", "::1", "localhost")
APP_PORTS = (  # the framework's own pages: (the app, the variable moving it, its default port)
    ("charts", "LIMINAL_CHARTS_PORT", 8765),
    ("platform", "LIMINAL_PLATFORM_PORT", 8775),
    ("integrator", "LIMINAL_FETCHER_PORT", 8785),
    ("login", "LIMINAL_LOGIN_PORT", 8795),
)  # these four and no other (the user, 2026-11-14: "i only want ports for liminal-login ; liminal-platform ;
# liminal-charts ; liminal-integrator"; 1.52.0: the integrator's login at 8796 gone, a login inherited is an object in
# its app, at that app's port)
# 1.105.0: what the World Wide Web plugin may ask of the hosts database (Firewall.hosts_found), and its bounds
HOSTS_FOUND = ("places", "programs", "ports", "hosts", "sums", "describe", "changes", "unplaced", "unplaced_hosts")
HOSTS_QUERY = ("program", "proto", "port", "direction", "since", "limit", "most", "stamp")
MAX_HOPS = 64  # hops of a route kept (as HostBook.keep_route keeps them)
PLACES_MOST = 2000  # places handed in one ask, at most
RULES_COVERING = 200  # rules covering a port, at most
SERVICE_READS = ("netstat_seen", "hosts_found", "hosts_routes", "rules_covering")
SERVICE_CHANGES = ("hosts_keep_route", "hosts_keep_places", "hosts_clear_places")
SERVICES = (*SERVICE_READS, *SERVICE_CHANGES)
PLACES_HOOK = "places"  # the World Wide Web plugin's, asked for the Netstat tab's place column
MOVED = ("the World Wide Web tab is plugin-platform-worldwideweb's since liminal-libs 1.105.0: a firewall has no view of "
         "it")
NO_PLACES = "the World Wide Web plugin is not attached (it places the hosts with its GeoIP files)"
_NETSTAT_LOCK = threading.Lock()  # a plugin's NetstatView made once, however many asks come at once


def _plain(value):
    """1.105.0: an answer to another plugin as plain JSON (tuples as lists, anything else as its words)."""
    return json.loads(json.dumps(value, default=str))


def _count(value, default: int) -> int:
    """A count another plugin asked (limit, most): a whole number from 1 to `default`, else `default`."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return default
    return min(value, default)


class FirewallError(CommandError):
    pass


class FirewallNotNeeded(FirewallError):
    """Nothing to do because nothing filters (no firewall filtering what comes in): reported as skipped."""


@dataclass(frozen=True)
class Rule:
    """A firewall rule as the framework sees it. `owned`: one of Liminal's own (its name then is short, letters,
    digits and dashes); a rule that is not is listed for reading only."""

    name: str
    ports: tuple = ()  # the local ports; () for every port
    protocol: str = "tcp"  # tcp | udp | any
    direction: str = "in"  # in | out
    action: str = "allow"  # allow | block
    remote: str = "any"  # any, or an address or a network (10.0.0.0/8)
    enabled: bool = True
    owned: bool = True
    detail: str = ""  # what it is for, or the backend's own words

    def __post_init__(self):
        if self.direction not in DIRECTIONS:
            raise ValueError(f"direction is in or out, not {self.direction!r}")
        if self.action not in ACTIONS:
            raise ValueError(f"action is allow or block, not {self.action!r}")
        if self.protocol not in PROTOCOLS:
            raise ValueError(f"protocol is tcp, udp or any, not {self.protocol!r}")
        for p in self.ports:
            if not isinstance(p, int) or not 0 < p < 65536:
                raise ValueError(f"a port is a number from 1 to 65535, not {p!r}")
        if self.owned:
            if not NAME.match(self.name):
                raise ValueError(f"a Liminal rule's name is lowercase letters, digits and dashes (48 at most), not {self.name!r}")
            if self.ports and self.protocol == "any":
                raise ValueError("ports need a protocol: tcp or udp")

    @property
    def label(self) -> str:
        """Its name in the firewall: "Liminal: mail-example-test" for one of Liminal's."""
        return f"{GROUP}: {self.name}" if self.owned else self.name

    def describe(self) -> dict:
        return {"name": self.name, "label": self.label, "ports": list(self.ports), "protocol": self.protocol,
                "direction": self.direction, "action": self.action, "remote": self.remote, "enabled": self.enabled,
                "owned": self.owned, "detail": self.detail}


def geosources_pair(variable: str) -> str:
    """A key's pair in a login store, by its variable (IPINFO_TOKEN is ipinfo-token)."""
    from ..apps.authorization import pair_name

    return pair_name(variable)


def app_ports(env=None) -> dict[str, int]:
    """The framework's own pages' ports by app (their variables moving them)."""
    env = os.environ if env is None else env
    out: dict[str, int] = {}
    for app, var, default in APP_PORTS:
        raw = (env.get(var) or "").strip() if var else ""
        out[app] = int(raw) if raw.isdecimal() else default
    return out


def host_port(spec: str) -> int | None:
    """The host port a `docker run -p` entry publishes on every address (25:25 -> 25, 0.0.0.0:25:25 -> 25);
    None for one published on this machine only (127.0.0.1:8025:25), one Docker picks (25), or a range."""
    spec = spec.strip()
    if spec.startswith("["):  # [::]:25:25, [::1]:8025:25
        address, _, rest = spec[1:].partition("]:")
        port = rest.split(":", 1)[0]
    else:
        parts = spec.split(":")
        if len(parts) == 2:
            address, port = "", parts[0]
        elif len(parts) == 3:
            address, port = parts[0], parts[1]
        else:
            return None
    if address in LOOPBACK:
        return None
    return int(port) if port.isdecimal() and 0 < int(port) < 65536 else None


def service_rules(scope=None) -> list[Rule]:
    """The rules the framework's services on this machine need: a domain login's mail server container, its
    [server] ports published on every address, when its engine is this machine's (an engine elsewhere, a
    context or a host, sits behind that machine's own firewall)."""
    if scope is None:
        from ..apps.scope import Scope

        try:
            scope = Scope.find()
        except Exception:  # noqa: BLE001 - no login file to read: nothing needed
            return []
    if scope is None or scope.kind != "domain":
        return []
    sec = scope.server
    instance = (sec.get("instance") or "").strip()
    if sec.get("context") or sec.get("host") or instance.startswith("context:") or instance == "host":
        return []
    svc = scope.service()
    if svc is None:
        return []
    ports = tuple(sorted({p for spec in svc.ports if (p := host_port(spec)) is not None}))
    if not ports:
        return []
    name = ("mail-" + scope.name.replace(".", "-"))[:48].rstrip("-")
    return [Rule(name, ports=ports, protocol="tcp", detail=f"the mail server container {svc.name} for {scope.domain}")]


class Firewall(MachinePlugin):
    """The base of the firewall plugins. A subclass drives one firewall through the backend methods below;
    the hooks (status, setup) and the platform's asks (allow, remove, wanted) are this base's, and so are the rules'
    groups (1.35.0, rulegroups: System, Application, Other and the user's labels; a subclass sorts its rules with
    `sorted_rules` and draws its rules table through `groups.table`).

    1.55.0: the World Wide Web tab is this base's too (machines/world.py; the user, 2026-11-14: "so for the firewall's
    both are going to get a 'world wide web view' that shows the globe and the routes incoming all traffic, as well as
    monitoring port traffic stats"): its hook `world` (a read, asked every two seconds while the tab is shown), the
    GeoIP file's install (`world_geoip`, a change asked from its form alone, run as a job: JOB_HOOKS), and the watching
    stopped on detach. A subclass names its GeoIP download (GEOIP_URL, GEOIP_LICENCE), the attribution of its places
    (ATTRIBUTION) and the name servers asked for this network's public address (PUBLIC_DNS), and makes a capture of its
    own in make_world_view when it needs one; what asks nothing (its API card's facts) reads the tab's view through
    world_view(make=False). 1.105.0 (Monday list item 33): that tab is plugin-platform-worldwideweb's now
    (machines/worldweb.py: its code moved there whole), and it asks a firewall what only a firewall knows through the
    platform: the socket table's reading, the hosts recorded, the routes kept, the rules covering a port (the services
    below). world_view() is kept for a firewall plugin written before, and answers none.

    1.65.0: the Netstat tab, the hosts database and the globe's filters and layers are this base's too
    (machines/netstat.py; the user, 2026-11-16: "the firewall app should have a 'netstat' like interface for looking at
    active ports and what apps they are attached to, and the hosts that they connect to across the lan or wan", "geoip'd
    hosts are databased for the apps they talk to, the time they are connected to *this *computer", "the globe-firewall
    should allow filtering", "have all the backbones,ibones, major internet infrastructure, (as many as possible)
    datacenter locations"). Its hook `netstat` (a read, the tab's, asked every three seconds while it is shown) reads
    this machine's socket table with no capture and no administrator; the hosts are recorded only while one of its two
    tabs is shown, or all the time the platform runs where the user chose it (LIMINAL_HOSTS_RECORDING, set through the
    hook `hosts_recording` or the page's Settings, kept through the login); the globe shows the traffic watched or the
    hosts recorded (`world_show`, `world_direction`, `world_within`, `world_pick`) and draws the infrastructure of the
    data sets a subclass names (INFRASTRUCTURE), each downloaded on the user's word as a job (`world_layer_get`) and
    read back by layer (`world_layer`, a read). What asks nothing reads the view through netstat_view(make=False). On
    a machine the plugin is not for (not_for_here), each of these hooks refuses in words (`netstat` answers a page
    saying so), before any view is made: nothing is read, recorded, kept, forgotten or removed there. 1.105.0: the
    globe's choices and layers left with the World Wide Web tab; the Netstat tab's places are that plugin's (`places`)."""

    HOOKS = (*MachinePlugin.HOOKS, "allow", "remove", "wanted",  # what the platform may ask by name (Plugin.ask)
             "move_rules", "new_label", "rename_label", "remove_label",
             # 1.65.0: netstat, the Netstat tab's page (a read); hosts_recording and hosts_forget, the hosts database's
             # recording set and its rows forgotten (1.105.0: the globe's hooks left with the World Wide Web tab)
             *netstat.FIREWALL_HOOKS,
             # 1.105.0: what the World Wide Web plugin asks of a firewall (SERVICE_HOOKS)
             *SERVICES)
    # its reads beside MachinePlugin's (Plugin.READ_HOOKS): netstat reads as its tab's hook; 1.105.0: the services' reads
    READ_HOOKS = ("wanted", *SERVICE_READS)
    # 1.105.0: other plugins ask these through the platform (the World Wide Web plugin, plugin-platform-worldwideweb);
    # the changes among them only another plugin may ask, never a page
    SERVICE_HOOKS = SERVICES
    PLUGIN_ONLY_HOOKS = SERVICE_CHANGES
    STEPS = STEPS
    ICON = "shield"
    GROUPS_VARIABLE = ""  # where the user's labels and moves are kept through the login: "" for <NAME>_GROUPS
    # -- the Netstat tab (1.65.0), after Main, External API and Internal API, asked every 3 s while shown; 1.105.0: the
    # World Wide Web tab is plugin-platform-worldwideweb's (machines/worldweb.py)
    TABS = (Tab(netstat.TAB, netstat.TITLE, netstat.HOOK, netstat.EVERY),)
    # 1.105.0: none of its own now (they were the World Wide Web tab's), kept for a firewall plugin written before,
    # which builds its own from them (firewall-linux 0.12.0's JOB_HOOKS, firewall-windows 0.9.0's data sets)
    JOB_HOOKS: tuple = ()
    CANCEL_HOOKS: tuple = ()
    INFRASTRUCTURE: tuple = ()
    # set on the plugin's page and read through the login, optional: LIMINAL_HOSTS_RECORDING (1.65.0), when the hosts are
    # recorded: shown (nothing set) or always. 1.105.0: the globe's home and the traffic's watching are the World Wide Web
    # plugin's keys, by the same names
    keys = (HOSTS_KEY,)

    # -- the backend: a subclass's -----------------------------------------------------------------
    def backend(self) -> str:
        """The firewall's name, and where it is when that matters (ufw in WSL's Ubuntu)."""
        raise NotImplementedError

    def state(self) -> dict:
        """{"enabled": on everywhere, "profiles": {a profile, zone or table: on}}."""
        raise NotImplementedError

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        raise NotImplementedError

    def add_rule(self, rule: Rule) -> None:
        raise NotImplementedError

    def delete_rule(self, name: str) -> bool:
        raise NotImplementedError

    def enable(self) -> None:
        raise NotImplementedError

    def can_enable(self) -> bool:
        """Whether the firewall has a switch to turn on (nftables has none: its rules filter or not)."""
        return True

    def exposing(self, ports) -> list[tuple[int, str]]:
        """The rules letting another machine reach any of `ports` inbound: (the port, the rule's name)."""
        raise NotImplementedError

    # -- the rules' groups (the user: "for both firewalls, i need to have groups, like system or application and then
    # unassociated rules not tied to a specific application or system process can be in an other, i can create labels,
    # like system or application, as well and move the rules in to that") ---------------------------------------------
    @property
    def groups(self) -> RuleGroups:
        """The user's labels and moves for this firewall's rules, kept through the plugin's login (FIREWALL_WINDOWS_GROUPS ...)."""
        variable = self.GROUPS_VARIABLE or re.sub(r"[^A-Z0-9]+", "_", str(self.name or "firewall").upper()).strip("_") + "_GROUPS"
        return RuleGroups(variable, lambda: getattr(self, "login", None))

    @property
    def KEEPS(self) -> tuple:
        """What it keeps through its login beside its keys (Plugin.KEEPS, for its Internal API tab): the user's labels
        and the moves of its rules, under the variable its `groups` are kept in. Said by name: no login is asked.
        1.105.0: the GeoIP sources chosen and the licences accepted are the World Wide Web plugin's."""
        return ((self.groups.variable, "the labels and the moves of its rules"),)

    def _declared_keys(self) -> list[str]:
        return [str(getattr(k, "name", k)) for k in (getattr(self, "keys", None) or ())]

    def sorted_rules(self) -> dict[str, Sorted]:
        """Every rule this firewall reads, by its key (rulegroups.key_of), with the group found for it: a subclass's."""
        return {}

    def move_rules(self, keys, group) -> dict:
        """Rules moved into a group: a label of the user's, system, application or other, or own (back to their own)."""
        return self.groups.move(keys, group, self.sorted_rules())

    def new_label(self, name) -> dict:
        """A label of the user's made, for rules moved into it."""
        return self.groups.new_label(name)

    def rename_label(self, name, to) -> dict:
        """A label of the user's renamed, the rules moved into it staying in it under the new name (nothing in the
        firewall changes)."""
        return self.groups.rename_label(name, to)

    def remove_label(self, name) -> dict:
        """A label removed, its rules back in their own groups (nothing in the firewall changes)."""
        return self.groups.remove_label(name)

    # -- what the platform asks ---------------------------------------------------------------------
    def wanted(self) -> list[Rule]:
        """The rules the framework's services on this machine need (service_rules)."""
        return service_rules()

    def allow(self, name: str, ports, protocol: str = "tcp", remote: str = "any", detail: str = "") -> Rule:
        """One of Liminal's own rules letting `ports` in; FirewallError when one of that name is there."""
        rule = Rule(name, ports=tuple(int(p) for p in ports), protocol=protocol, remote=remote, detail=detail)
        if any(r.name == name for r in self.list_rules()):
            raise FirewallError(f"a Liminal rule named {name} is there already: remove it first")
        self.add_rule(rule)
        return rule

    def remove(self, name: str) -> bool:
        """One of Liminal's own rules removed (never another's); False when there is none of that name."""
        return self.delete_rule(name)

    # -- the hooks ----------------------------------------------------------------------------------
    def status(self) -> dict:
        """What the firewall is and how it does, for the platform's page: its backend, on or off in each profile
        (`enabled`, `profiles`), Liminal's own rules, and whether the rules the framework's services need (`wanted`) are
        there. Valid when it is Liminal's, on and holds Liminal's rules, none of those missing; `why` says what is not,
        `problem` what could not be read. Not for this machine, not on Liminal's or not present: said, nothing asked."""
        here = self.not_for_here()
        if here:  # not for this machine at all (a Linux plugin on Windows or macOS): asked nothing, no setup offered
            return self.not_here_status(here, backend="", enabled=False, profiles={}, rules=[])
        note = self.scope_note()
        if note:  # not Liminal's (the user's own distribution): asked nothing at all
            return {"present": False, "backend": "", "enabled": False, "profiles": {}, "rules": [], "summary": "not on Liminal's",
                    "valid": False, "why": note}
        if not self.present():
            return {"present": False, "backend": "", "enabled": False, "profiles": {}, "rules": [], "summary": "not present",
                    "valid": False, "why": "not present"}
        try:
            backend = self.backend()
            st = self.state()
            rules = [r.describe() for r in self.list_rules()]
            wanted = self.wanted()
        except CommandError as e:
            return {"present": True, "backend": "", "enabled": False, "profiles": {}, "rules": [], "problem": str(e),
                    "summary": f"cannot be read: {e}", "valid": False, "why": f"cannot be read: {e}"}
        profiles = st.get("profiles", {})
        on = [n for n, v in profiles.items() if v]
        off = [n for n, v in profiles.items() if not v]
        where = (f" ({', '.join(on)} on" + (f"; {', '.join(off)} off" if off else "") + ")") if on else (f" ({', '.join(off)} off)" if off else "")
        summary = f"{backend}: {'on' if st.get('enabled') else 'off'}{where}; {len(rules)} Liminal rule(s)"
        scoped, place = self.scope()
        missing = [w.name for w in wanted if w.name not in {r["name"] for r in rules}]
        why = (f"{place} is not Liminal's" if not scoped else "off: its setup turns it on" if not st.get("enabled")
               else f"{len(missing)} of the framework's rules missing: its setup adds them" if missing
               else "no Liminal rules: nothing of the framework's is exposed here (a domain login's mail server would be)"
               if not rules else "")
        return {"present": True, "backend": backend, **st, "rules": rules, "summary": summary, "valid": not why, "why": why}

    def setup(self, log=print, steps=None) -> list[dict]:
        """`enable` (the firewall on where it is off), `exposure` (no rule lets another machine reach the
        framework's pages; a finding, never a change), `rules` (the services' rules added where missing;
        Liminal's other rules left alone); each reported. A firewall error ends it."""
        wanted = tuple(steps) if steps else self.STEPS
        done: list[dict] = []

        def step(what: str, ok: bool | None, detail: str) -> None:
            done.append({"step": what, "ok": ok, "detail": detail})
            log(f"{self.name}: {what}: {'ok' if ok else 'skipped' if ok is None else 'FAILED'}: {detail}")

        note = self.not_for_here() or self.scope_note()
        if note:  # not for this machine, or the user's own: nothing changed
            step(wanted[0] if wanted else "setup", False, note)
            return done
        if not self.present():
            step(wanted[0] if wanted else "setup", False, "no firewall here this plugin drives")
            return done
        current = wanted[0] if wanted else "setup"
        try:
            if "enable" in wanted:
                current = "enable"
                st = self.state()
                off = [n for n, v in st.get("profiles", {}).items() if not v]
                if st.get("enabled") and not off:
                    step("enable", None, "on: " + (", ".join(st.get("profiles", {})) or self.backend()))
                elif not self.can_enable():
                    step("enable", None, f"{self.backend()} has no switch: its rules filter or not")
                else:
                    self.enable()
                    step("enable", True, "turned on" + (f" for {', '.join(off)}" if off else ""))
            if "exposure" in wanted:
                current = "exposure"
                ports = app_ports()
                st = self.state()
                if not st.get("enabled"):
                    step("exposure", None, "the firewall is off: only the apps' own binding to 127.0.0.1 keeps other machines out")
                else:
                    hits = self.exposing(sorted(set(ports.values())))
                    names = {p: a for a, p in ports.items()}
                    if hits:
                        step("exposure", False, "rules let other machines reach the framework's pages: "
                             + "; ".join(f"{names.get(p, p)} ({p}) by {label}" for p, label in hits)
                             + "; the apps answer this machine only, so remove those rules or keep them knowingly")
                    else:
                        step("exposure", True, "no rule lets another machine reach the framework's pages ("
                             + ", ".join(f"{a} {p}" for a, p in ports.items()) + ")")
            if "rules" in wanted:
                current = "rules"
                need = self.wanted()
                if not need:
                    step("rules", None, "no service of the framework on this machine needs a rule")
                else:
                    have = {r.name for r in self.list_rules()}
                    missing = [r for r in need if r.name not in have]
                    for r in missing:
                        self.add_rule(r)
                    if missing:
                        step("rules", True, "added: " + "; ".join(f"{r.label} ({', '.join(map(str, r.ports))}/{r.protocol} in)" for r in missing))
                    else:
                        step("rules", None, "there already: " + ", ".join(r.label for r in need))
        except FirewallNotNeeded as e:
            step(current, None, str(e))
        except CommandError as e:
            step(current, False, str(e))
        return done

    # -- 1.105.0: the World Wide Web tab is plugin-platform-worldwideweb's --------------------------------------------
    def world_view(self, make: bool = True):
        """None: the World Wide Web tab left the firewalls in liminal-libs 1.105.0 (plugin-platform-worldwideweb draws
        it, machines/worldweb.py), so a firewall has no view of it. Kept for a firewall plugin written before: what
        asks nothing (its API card's facts, `make=False`) reads none, as before the tab's first ask; `make=True` is
        refused in words."""
        if make:
            raise LookupError(MOVED)
        return None

    # -- the Netstat tab and the hosts database (1.65.0; machines/netstat.py) -------------------------------------------
    def netstat_view(self, make: bool = True) -> NetstatView | None:
        """This plugin's Netstat tab and hosts recording: made when first asked (make_netstat_view), kept until the
        plugin is detached. `make=False`: the view there is, or None, never making one (for what asks nothing: the
        plugin's API card's facts)."""
        view = self.__dict__.get("_netstat")
        if view is None and make:
            with _NETSTAT_LOCK:
                view = self.__dict__.get("_netstat")
                if view is None:
                    view = self.__dict__["_netstat"] = self.make_netstat_view()
        return view

    def make_netstat_view(self) -> NetstatView:
        """The NetstatView the tab reads with: this machine's socket table (sockets.read), the hosts database in the
        data folder (hostbook.book), the plugin's login and the listeners its own read names (netstat_listeners). A
        subclass with stand-ins of its own (its tests) makes it here. 1.105.0: no data sets (the globe's layers are the
        World Wide Web plugin's)."""
        return NetstatView(self.name, login_of=lambda: getattr(self, "login", None), listeners=self.netstat_listeners,
                           app_ports=app_ports, agent=netstat.agent_of(self.name, self.version))

    def netstat_listeners(self) -> dict[tuple[str, int], str]:
        """The listening sockets this plugin's own read names that the socket table does not ({(proto, port):
        program}, another user's, as a root read of the firewall sees them): none here. Asking nothing: what a read
        made already."""
        return {}

    def _only_here(self) -> None:
        """A ValueError in words on a machine this plugin is not for (not_for_here), asked first by every hook of the
        Netstat tab, the hosts database and the services: there none of them makes a view, reads the socket table,
        starts the recording, keeps a setting or forgets the hosts (the plugin this machine is for keeps them; the hosts
        database is this system's, not a plugin's)."""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")

    def netstat(self) -> dict:
        """The Netstat tab's page: the listening ports and the open connections with the program behind each.

        Asked every three seconds while the tab is shown (a read): this machine's socket table, read with no capture, no
        administrator and no window, each socket with its program, pid and service, the remote host and port, whether
        that host is this machine's, the local network's or the internet's, its name or its GeoIP place, and how long it
        has been up where the system says; the hosts database (recorded meanwhile, unless always) and its forms. Inside
        a WSL distribution, what WSL changes for it after its tables. Not for this machine: a page saying so, nothing
        read. 1.105.0: the places are the World Wide Web plugin's (its `places`, asked once for the page through
        hostsvia.PlacesVia); with that plugin not attached, the column is empty and the note says why."""
        here = self.not_for_here()
        if here:
            return {"title": netstat.TITLE, "note": f"Not for this machine: {here}. Nothing is read here."}
        view = self.netstat_view()
        seen = view.touch()  # the reading the page is made of (shared, so the page reads none anew)
        via = PlacesVia(self._places, lambda: self._wanted_places(view, seen))
        page = view.page(via)
        internet = any(isinstance(r, dict) and r.get("where") == sockets.WHERE[2] for r in seen.get("rows") or ())
        if internet and via.why:
            page["note"] = f"{page.get('note') or ''} No place is shown: {via.why}.".strip()
        under = sockets.under_wsl()
        if under is not None and isinstance(page.get("tables"), list):
            page["tables"].append(under)
        return page

    def _wanted_places(self, view, seen) -> list[str]:
        """The addresses a Netstat page asks places of: the reading's internet hosts, then the hosts the database has
        no place for as of the stamp last answered."""
        rows = [r.get("remote") for r in seen.get("rows") or ()
                if isinstance(r, dict) and r.get("remote") and r.get("where") == sockets.WHERE[2]]
        try:
            rows += view.book.unplaced_hosts(str(self.__dict__.get("_places_stamp") or ""))
        except Exception:  # noqa: BLE001 - the database's own words say why
            pass
        return list(dict.fromkeys(rows))[:PLACES_MOST]

    def _places(self, addresses) -> dict:
        """The World Wide Web plugin's places of `addresses`, asked through the platform: the first attached plugin
        offering `places` (LookupError, in words, when none is attached)."""
        app = getattr(self, "app", None)
        try:
            faces = dict(app.plugins() or {}) if app is not None else {}
        except Exception:  # noqa: BLE001 - an app that cannot list its plugins: none
            faces = {}
        for name, face in faces.items():
            if name != self.name and isinstance(face, dict) and PLACES_HOOK in (face.get("hooks") or ()):
                got = asks.ask(self, name, PLACES_HOOK, list(addresses))
                if isinstance(got, dict) and got.get("stamp"):
                    self.__dict__["_places_stamp"] = str(got["stamp"])
                return got
        raise LookupError(NO_PLACES)

    def hosts_recording(self, mode) -> dict:
        """When the hosts are recorded: "shown" (only while its Netstat or World Wide Web tab is shown) or "always".

        Kept through the plugin's login (LIMINAL_HOSTS_RECORDING), from the hosts database's Recording form; recording
        all the time starts at once (a reading every few seconds on a thread of its own), and stops when it is set
        back. ValueError, in words, for any other word, no login, a database kept on another system's drive, or a
        machine the plugin is not for (nothing is kept or started there)."""
        self._only_here()
        return self.netstat_view().set_mode(mode)

    def hosts_forget(self, accept_forget=False) -> dict:
        """Every host recorded forgotten, on the user's word asked twice.

        hostbook.ForgetRefused (naming accept_forget, which the page asks as a second confirmation) unless it is exactly
        True; then every row of the hosts database is removed, nothing of them left in the file. ValueError on a
        machine the plugin is not for: the hosts this system's own plugin recorded are left as they are."""
        self._only_here()
        return self.netstat_view().forget(accept_forget)

    # -- 1.105.0: what the World Wide Web plugin asks of a firewall (Monday list item 33) ------------------------------
    # plugin-platform-worldwideweb draws the World Wide Web tab; what only a firewall knows it asks through the platform,
    # never importing a firewall. Each hook refuses on a machine the plugin is not for, asks no other plugin and holds
    # none of this plugin's locks while another plugin asks it, so the two cannot wait on each other.
    def netstat_seen(self) -> dict:
        """The socket table's reading now, as the Netstat tab has it, for the World Wide Web tab: its open connections.

        A read for another plugin (SERVICE_HOOKS): one reading shared with this plugin's own tabs (NetstatView.touch),
        which counts as a tab shown for the hosts' recording, as the World Wide Web tab of this plugin counted until
        1.105.0. Its rows are cut at netstat.FLOW_ROWS and are plain JSON: {"reading", "rows", "error"}."""
        self._only_here()
        seen = self.netstat_view().touch()
        rows = list(seen.get("rows") or ())[:netstat.FLOW_ROWS]
        return _plain({"reading": seen.get("reading"), "rows": rows, "error": seen.get("error") or ""})

    def hosts_found(self, what, query=None):
        """The hosts recorded, as the World Wide Web tab's hosts view asks the hosts database (a read for another plugin).

        `what` is one of HOSTS_FOUND: the places, programs, ports or hosts that pass the filters in `query` (program,
        proto, port, direction, since, and limit or most), their sums, the database's facts (with the recording's mode
        and why it is kept elsewhere, if it is), how many rows are not placed as of a GeoIP stamp, or those hosts. Plain
        JSON; a ValueError, in words, for anything else."""
        self._only_here()
        word = str(what or "").strip()
        if word not in HOSTS_FOUND:
            raise ValueError(f"the hosts found are {', '.join(HOSTS_FOUND)}, not {world_module._shown(what)}")
        q = dict(query) if isinstance(query, dict) else {}
        unknown = sorted(set(q) - set(HOSTS_QUERY))
        if unknown:
            raise ValueError(f"a hosts query names {', '.join(HOSTS_QUERY)}, not {', '.join(map(str, unknown))}")
        net = self.netstat_view()
        book = net.book
        filters = {k: q[k] for k in ("program", "proto", "port", "direction", "since") if k in q}
        if word == "describe":
            facts = dict(book.describe() or {})
            return _plain({**facts, "mode": net.mode(), "elsewhere": net.elsewhere(), "changes": book.changes})
        if word == "changes":
            return int(book.changes)
        if word in ("unplaced", "unplaced_hosts"):
            stamp = str(q.get("stamp") or "")
            if word == "unplaced":
                return int(book.unplaced(stamp))
            return list(book.unplaced_hosts(stamp, _count(q.get("most"), hostbook_module.PLACE_ROWS)))
        net._flush()  # what is pending written first, as the view's own hosts view does
        if word == "places":
            drawn, rest = book.places(**filters, most=_count(q.get("most"), world_module.MAX_DRAWN))
            return _plain([drawn, rest])
        if word == "sums":
            return _plain(book.sums(**filters))
        limit = _count(q.get("limit"), netstat.MOST)
        if word == "hosts":
            return _plain(book.hosts(**filters, limit=limit))
        return _plain(getattr(book, word)(limit=limit, **filters))  # programs, ports

    def hosts_routes(self, addresses=None):
        """The routes traced and kept in the hosts database, read back for the World Wide Web tab (a read).

        With no addresses, the hosts that have a route (each is not traced again); with addresses, their routes as the
        last check found them (HostBook.routes_of)."""
        self._only_here()
        book = self.netstat_view().book
        if addresses is None:
            return sorted(book.routed())
        if not isinstance(addresses, (list, tuple)):
            raise ValueError("the routes are asked of a list of addresses")
        return _plain(book.routes_of([str(a) for a in addresses[:hostbook_module.ROUTES_OF] if a]))

    def hosts_keep_route(self, remote, traced, reached, how, hops, way) -> dict:
        """A route the World Wide Web plugin traced, kept in this plugin's hosts database (asked only by another plugin).

        Plain values only, at most MAX_HOPS hops, each a mapping: a ValueError, in words, otherwise. Kept with the
        database's next write (HostBook.keep_route)."""
        self._only_here()
        if not isinstance(remote, str) or not remote or not isinstance(hops, (list, tuple)):
            raise ValueError("a route is kept of an address and its hops")
        if len(hops) > MAX_HOPS or any(not isinstance(h, dict) for h in hops):
            raise ValueError(f"a route has at most {MAX_HOPS} hops, each a mapping")
        if isinstance(traced, bool) or not isinstance(traced, (int, float)):
            raise ValueError("a route's time is a number of seconds")
        self.netstat_view().book.keep_route(remote, traced, bool(reached), str(how or ""), _plain(list(hops)),
                                            str(way or ""))
        return {"ok": True}

    def hosts_keep_places(self, stamp, places) -> dict:
        """The places the World Wide Web plugin's GeoIP files gave the hosts this database has none for, kept (asked
        only by another plugin).

        `places` is {address: a place's mapping (country, country_name, city, lat, lon, asn, org) or None}, of the hosts
        hosts_found("unplaced_hosts") named for `stamp`; the rows are placed as of `stamp` (HostBook.place)."""
        self._only_here()
        if not isinstance(places, dict):
            raise ValueError("the places are a mapping of addresses")
        found = {str(k): (v if isinstance(v, dict) else None) for k, v in list(places.items())[:PLACES_MOST]}
        view = self.netstat_view()
        if view.elsewhere():
            return {"ok": False, "placed": 0}
        placed = view.book.place(found.get, str(stamp or ""), only=found) if found else 0
        view.replaced()
        return {"ok": True, "placed": int(placed)}

    def hosts_clear_places(self, role, pattern, bare=False) -> dict:
        """The places a GeoIP source gave, cleared from the hosts database when the World Wide Web plugin removed its file
        (asked only by another plugin): placed again at the next ask (HostBook.clear_places)."""
        self._only_here()
        if role not in geosources.ROLES or not isinstance(pattern, str) or not pattern:
            raise ValueError("places are cleared of a role (places or networks) and a stamp's pattern")
        view = self.netstat_view()
        if view.elsewhere():
            return {"ok": False, "cleared": 0}
        cleared = view.book.clear_places(role, pattern, bare=bool(bare))
        view.replaced()
        return {"ok": True, "cleared": int(cleared or 0)}

    def rules_covering(self, port, proto="tcp") -> list[dict]:
        """The firewall's rules covering a port, for the World Wide Web tab's port picked (a read).

        Every rule this firewall lists (Liminal's and the others'), whose ports name the port or that names none, of the
        protocol or of any: [{name, label, direction, action, enabled, owned, group, why}], RULES_COVERING at most. A
        subclass that knows more of its rules (their programs, their remote addresses) refines it."""
        self._only_here()
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise ValueError(f"a port is a number from 1 to 65535, not {world_module._shown(port)}")
        if proto not in ("tcp", "udp"):
            raise ValueError(f"a port's protocol is tcp or udp, not {world_module._shown(proto)}")
        out = []
        for rule in self.list_rules(owned_only=False):
            if rule.protocol not in (proto, "any") or (rule.ports and port not in rule.ports):
                continue
            out.append({"name": rule.name, "label": rule.label, "direction": rule.direction, "action": rule.action,
                        "enabled": rule.enabled, "owned": rule.owned, "group": "",
                        "why": f"port {port}/{proto}" if rule.ports else "every port"})
            if len(out) >= RULES_COVERING:
                break
        return out


    # -- attached, told, detached --------------------------------------------------------------------------------------
    def attach(self, app, login=None) -> dict:
        """Attached by its app as every plugin is; then, on a machine it is for, the hosts' recording follows its
        setting: all the time where the user chose always (never in a one-shot app: `once`), else nothing runs."""
        out = super().attach(app, login)
        if not self.not_for_here():
            try:
                self.netstat_view().follow(once=bool(getattr(app, "once", False)))
            except Exception:  # noqa: BLE001 - a view that cannot be made or read: its tab says why when it is asked
                pass
        return out

    def app_stopping(self) -> None:
        """The platform stops (liminal-platform 0.31.0): the hosts' recording thread ended and what it read written. It
        bears a second call."""
        view = self.netstat_view(make=False)
        if view is not None:
            view.stop()

    def settings_changed(self) -> None:
        """The platform kept one of this plugin's settings (its page's Settings): the hosts' recording follows its
        setting at once."""
        net = self.netstat_view(make=False)
        if net is not None:
            net.forget_setting()
        if not self.not_for_here():
            try:
                self.netstat_view().follow()
            except Exception:  # noqa: BLE001 - a view that cannot be made or read: its tab says why when it is asked
                pass

    def detach(self) -> None:
        """Detached by its app: the hosts' recording ended for good (NetstatView.close: its thread gone, what it read
        written, the file let go) and forgotten; then the plugin detached as every plugin is."""
        with _NETSTAT_LOCK:
            net = self.__dict__.pop("_netstat", None)
        if net is not None:
            net.close()
        super().detach()
