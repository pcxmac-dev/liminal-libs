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

1.102.0 (Monday list item 20; the user, 2026-11-19: "add a way to download different GEOIP sources"): a subclass may
name GeoIP sources (GEOIP_SOURCES, machines/geosources.py), places and networks chosen apart, the first the default.
Three hooks only a person signed in at the platform's page may ask (PAGE_ONLY_HOOKS, and each refuses any other ask
itself): world_geoip_get (a job: the keys read through the asking person's login, the licence's acceptance kept in
their own login store or the download refused), world_geoip_use and world_geoip_remove (asked twice)."""
from __future__ import annotations

import json
import math
import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .. import sockets
from ..apps import asking
from ..apps.authorization import PREFERENCE, Unauthorized, accept_licence as keep_licence, asking_login, keep, keeps, recall
from ..apps.tabs import Tab
from ..hostbook import HOSTS_KEY
from ..sources.keys import KeyVar
from . import geosources, netstat, routes as routes_module, world as world_module
from .infrastructure import DataSet, Index
from .netstat import NetstatView
from .plugin import CommandError, MachinePlugin
from .rulegroups import RuleGroups, Sorted
from .world import (ASN_HOOK, GEOIP_GET_HOOK, GEOIP_HOOK, GEOIP_REMOVE_HOOK, GEOIP_USE_HOOK, HOME_KEY, HOME_PLACE_VAR,
                    HOOK as WORLD_HOOK, LICENCE_FIRST, SETTING_S, TAB as WORLD_TAB, TIMEOUT_S, TITLE as WORLD_TITLE,
                    LicenceRefused, WorldView, not_here_page)

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
_WORLD_LOCK = threading.Lock()  # a plugin's WorldView made once, however many asks come at once
_NETSTAT_LOCK = threading.Lock()  # ... and its NetstatView


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
    world_view(make=False).

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
    saying so), before any view is made: nothing is read, recorded, kept, forgotten or removed there."""

    HOOKS = (*MachinePlugin.HOOKS, "allow", "remove", "wanted",  # what the platform may ask by name (Plugin.ask)
             "move_rules", "new_label", "rename_label", "remove_label",
             # 1.55.0: world, the World Wide Web tab's page (a read); world_geoip, its GeoIP file's install (a change)
             WORLD_HOOK, GEOIP_HOOK, WATCH_HOOK,  # 1.74.0: world_watching, the traffic watched all the time or not
             ASN_HOOK,  # 1.75.0: world_asn, the ASN file's install
             # 1.102.0: a GeoIP source's file downloaded (a job), used for its role, and removed
             GEOIP_GET_HOOK, GEOIP_USE_HOOK, GEOIP_REMOVE_HOOK,
             # 1.65.0: netstat, the Netstat tab's page (a read); hosts_recording and hosts_forget, the hosts database's
             # recording set and its rows forgotten; world_show, world_direction, world_within and world_pick, what the
             # globe shows; world_layer, a layer's geometry (a read); world_layer_get and world_layer_remove, a data
             # set downloaded (a job) and removed
             *netstat.HOOKS)
    # its reads beside MachinePlugin's (Plugin.READ_HOOKS): world and netstat read as its tabs' hooks; world_layer reads
    # a layer's file on this machine for the globe (the page asks it, and it writes no log line)
    READ_HOOKS = ("wanted", netstat.LAYER_HOOK)
    STEPS = STEPS
    ICON = "shield"
    GROUPS_VARIABLE = ""  # where the user's labels and moves are kept through the login: "" for <NAME>_GROUPS
    # -- the World Wide Web tab (1.55.0) and the Netstat tab (1.65.0) --------------------------------------------------
    # after Main, External API and Internal API: the World Wide Web tab asked every 2 s while shown, Netstat every 3 s
    TABS = (Tab(WORLD_TAB, WORLD_TITLE, WORLD_HOOK, 2.0), Tab(netstat.TAB, netstat.TITLE, netstat.HOOK, netstat.EVERY))
    # hooks the platform runs as a job (liminal-platform 0.19.0), their lines followed in the plugin's panel: the GeoIP
    # file's install, a download of about 60 MB that would otherwise hold the form's dialog for minutes; and a data
    # set's download (1.65.0), which the page may ask to stop (CANCEL_HOOKS: liminal-platform 0.31.0's Cancel)
    JOB_HOOKS = (GEOIP_HOOK, netstat.GET_HOOK, ASN_HOOK,  # 1.75.0: the ASN file's install, a job as the GeoIP file's
                 GEOIP_GET_HOOK)  # 1.102.0: a GeoIP source's file, a job its Cancel stops
    CANCEL_HOOKS = (netstat.GET_HOOK, GEOIP_GET_HOOK)
    # 1.102.0: what only a person at the platform's page may ask: the GeoIP sources' download, use and removal (each
    # refuses any other ask itself too: geosources.NotAsked)
    PAGE_ONLY_HOOKS = (GEOIP_GET_HOOK, GEOIP_USE_HOOK, GEOIP_REMOVE_HOOK)
    # 1.102.0: the GeoIP sources a subclass names (geosources.of's plain dicts, every host and licence its own): places
    # and networks chosen apart, the first the default; () keeps the GEOIP_URL and GEOIP_ASN_URL installs as before
    GEOIP_SOURCES: tuple = ()
    # the internet infrastructure the globe may draw (1.65.0): the plugin's data sets, each a plain dict of
    # infrastructure.DataSet's keys (its address, query, licence and credit are the plugin's, in its apis.py); none here
    INFRASTRUCTURE: tuple = ()
    # this month's GeoIP file, {year} and {month} filled in (2026, 11): an https address of the plugin's own ("" offers
    # no download); last month's is tried when this month's is not out yet
    GEOIP_URL = ""
    # 1.72.1: IANA's RDAP bootstrap files (IPv4, IPv6) the routers' networks are looked up from: the plugin's (no
    # outside host is named in the library); none, and no registry is asked (the routers' names still are)
    RDAP_BOOTSTRAP: tuple = ()
    GEOIP_LICENCE = ""  # the licence's words, shown before the download and accepted in so many words
    # 1.75.0: the ASN file the plugin names beside it (each network's AS number and organisation), and its licence's
    # words: "" offers none
    GEOIP_ASN_URL = ""
    GEOIP_ASN_LICENCE = ""
    ATTRIBUTION: dict = {}  # {text, url}: drawn wherever places are ("IP Geolocation by DB-IP" with DB-IP's link)
    # the name servers asked for this network's public address, which places home when the user set none: each in
    # dns.public_address's shape, (the name, its type, the server, whose), split by the server's IP version; or
    # {4: (...), 6: (...)}. () asks none: home is then the user's place, or none
    PUBLIC_DNS: tuple = ()
    WORLD_TIMEOUT = TIMEOUT_S  # watching stops this long after the tab was last asked
    # set on the plugin's page and read through the login, all optional: LIMINAL_HOME_PLACE, the globe's home;
    # LIMINAL_HOSTS_RECORDING (1.65.0), when the hosts are recorded, and LIMINAL_TRAFFIC_WATCHING (1.74.0), when the
    # traffic is watched: shown (nothing set) or always
    keys = (HOME_KEY, HOSTS_KEY, WATCH_KEY)

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
        and the moves of its rules, under the variable its `groups` are kept in; 1.102.0: the GeoIP sources chosen, and
        each offered file's licence acceptance (in the asking person's own store). Said by name: no login is asked."""
        kept = [(self.groups.variable, "the labels and the moves of its rules")]
        if self.GEOIP_SOURCES:
            kept.append((geosources.VAR, "the GeoIP sources chosen for places and for networks"))
            read, _ = geosources.read(self.GEOIP_SOURCES, self._declared_keys())
            for source in read:
                if source.offered:
                    kept += [(f"licence-{f.licence.pair}", f"your acceptance of {f.title}'s licence, in your own "
                              "login store") for f in source.files]
        return tuple(kept)

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

    # -- the World Wide Web tab (1.55.0; machines/world.py) -----------------------------------------------------------
    def world_view(self, make: bool = True) -> WorldView | None:
        """This plugin's World Wide Web tab: made when first asked (make_world_view), kept until the plugin is detached.
        `make=False`: the view there is, or None, never making one (for what asks nothing: the plugin's API card's facts,
        before the tab was first asked since the plugin was attached)."""
        view = self.__dict__.get("_world")
        if view is None and make:
            with _WORLD_LOCK:
                view = self.__dict__.get("_world")
                if view is None:
                    view = self.__dict__["_world"] = self.make_world_view()
        return view

    def make_world_view(self) -> WorldView:
        """The WorldView the tab watches with: every packet at the adapter of this machine's way out (world.default_capture),
        the GeoIP files in the data folder, WORLD_TIMEOUT seconds of watching after the last ask. A subclass with a capture
        of its own (another adapter, a stand-in in its tests) makes it here."""
        return WorldView(self.name, timeout=self.WORLD_TIMEOUT, sources=self.world_sources())

    # -- 1.102.0: the GeoIP sources ----------------------------------------------------------------------------------
    def world_sources(self):
        """What a WorldView is given of the GeoIP sources (its `sources`): (those that read, what was wrong with the
        others, the choice's reader); None when the plugin names none."""
        if not self.GEOIP_SOURCES:
            return None
        read, refused = geosources.read(self.GEOIP_SOURCES, self._declared_keys())
        return read, refused, self.geoip_choice

    def geoip_choice(self, fresh: bool = False) -> dict:
        """The GeoIP sources chosen, {"places": id, "networks": id} ({} for the default's), kept per machine through
        the plugin's login (geosources.SETTING where it keeps settings, else its own LIMINAL_GEOIP_SOURCES), read at
        most every world.SETTING_S."""
        kept = self.__dict__.get("_geoip_choice")
        if not fresh and kept is not None and time.monotonic() - kept[0] < SETTING_S:
            return dict(kept[1])
        login = getattr(self, "login", None)

        def from_variable():
            try:
                raw = (login.variables([geosources.VAR]) or {}).get(geosources.VAR) if login is not None else None
                return json.loads(raw) if raw else None
            except Exception:  # noqa: BLE001 - nothing kept, or nothing that reads: the default's
                return None
        try:
            value = recall(login, geosources.SETTING, from_variable) if login is not None else None
        except Exception:  # noqa: BLE001 - a login that cannot say: the default's
            value = None
        choice = {r: str(value[r]) for r in geosources.ROLES if isinstance(value, dict) and isinstance(value.get(r), str)}
        self.__dict__["_geoip_choice"] = (time.monotonic(), choice)
        return dict(choice)

    @staticmethod
    def _at_the_page() -> bool:
        """Whether this ask is a person's, signed in at the platform's page: the page asks it (asking.PAGE), and the
        asking login keeps settings (a person's own store, not the platform's EnvironmentLogin)."""
        return asking.asker() == asking.PAGE and keeps(asking_login())

    def _geoip_gate(self, source, role, *, offered: bool = True):
        """The checks every GeoIP sources hook makes first, each local and in words: not for this machine; no sources,
        or a source or role the plugin does not name (or, with `offered`, does not offer); not a person signed in at
        the platform's page (geosources.NotAsked). (the view, the source, its file)"""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")
        if not self.GEOIP_SOURCES:
            raise ValueError(f"{self.title or self.name} names no GeoIP sources")
        view = self.world_view()
        named, file = view.source(source), view.file_of(source, role)
        if file is None:
            raise ValueError(f"{self.title or self.name} names no {world_module._shown(role)} file of a GeoIP source "
                             f"{world_module._shown(source)}")
        if offered and not named.offered:
            raise ValueError(f"{named.title} is not offered: waiting for your word")
        if not self._at_the_page():
            raise geosources.NotAsked()
        return view, named, file

    def _geoip_replaced(self, view) -> None:
        view.replaced()
        net = self.netstat_view(make=False)
        if net is not None:
            net.replaced()

    def world_geoip_get(self, source, role, accept_licence=False, log=None) -> dict:
        """A GeoIP source's file downloaded, on the word of a person signed in at the platform's page: run as a job
        (`log` its panel; Cancel stops it). Refused first, each in words and before anything is read or asked of
        anyone: not for this machine; a source or role not named or not offered; not a person at the page; a key not
        set in their login store (by name, no value read); the licence not accepted (world.LicenceRefused, naming
        accept_licence: the page asks it as a second confirmation with the licence's words); another download under
        way. Then, in the job: the keys read through the asking person's login and checked, the acceptance kept in
        their own login store (a store that refuses ends it, nothing fetched), and the download (WorldView.get)."""
        view, named, file = self._geoip_gate(source, role)
        login = asking_login()
        if named.keys:
            try:
                have = login.names()
            except Exception:  # noqa: BLE001 - a store that cannot list: the job reads them and says
                have = None
            missing = [n for n in named.keys if have is not None and geosources_pair(n) not in have]
            if missing:
                raise ValueError(f"{', '.join(missing)} is not set in your login store: add it "
                                 f"{geosources.WHERE_KEYS}")
        if accept_licence is not True:
            raise LicenceRefused(f"{file.title} is downloaded only once you accept its licence.")
        if view._installing.locked():
            raise ValueError("a GeoIP file is being downloaded already: wait for it to finish")
        return self._geoip_download(view, named, file, login, log)

    def _geoip_download(self, view, named, file, login, log) -> dict:
        secrets = geosources.credentials(named, login)
        now = datetime.fromtimestamp(view.wall(), timezone.utc)
        built = now.strftime("%Y-%m") if file.monthly else now.strftime("%Y-%m-%d")
        said = geosources.licence_of(file, built)
        try:
            keep_licence(login, said.pop("name"), **said, file=False)
        except Unauthorized as e:
            raise ValueError(f"your acceptance of {file.title}'s licence could not be kept in your login store "
                             f"({e.reason}): nothing was downloaded") from None
        out = view.get(named.id, file.role, secrets, log=log,
                       cancel=lambda: bool(getattr(log, "cancelled", False)))
        self._geoip_replaced(view)
        out.setdefault("lines", []).append("your acceptance of its licence is kept in your own login store")
        return out

    def world_geoip_use(self, source, role) -> dict:
        """A GeoIP source's file, installed already, used for its role from now on, on this machine (the choice kept
        through the plugin's login, as the traffic's watching is): asked by a person signed in at the platform's page.
        The hosts are placed again from it at the next ask."""
        view, named, file = self._geoip_gate(source, role)
        if view.installed(named.id, role) is None:
            raise ValueError(f"{file.title} is not installed: download it first")
        login = getattr(self, "login", None)
        if login is None:
            raise ValueError("no login to keep the choice through: sign in first")
        if named.id != view.default and not keeps(login) and sys.platform != "win32":
            raise ValueError("the choice cannot be kept here: the platform's login on this system keeps a setting only "
                             "until the platform stops, so the default source stays in use")
        choice = {**self.geoip_choice(fresh=True), role: named.id}

        def to_variable(value) -> None:
            login.save(geosources.VAR, json.dumps(value, sort_keys=True))
        try:
            where = keep(login, geosources.SETTING, choice, to_variable, PREFERENCE, "the GeoIP sources chosen")
        except Exception as e:  # noqa: BLE001 - a login that keeps nothing: its own words
            raise ValueError(f"the choice could not be kept: {e}") from None
        self.__dict__.pop("_geoip_choice", None)
        self._geoip_replaced(view)
        return {"said": f"{file.title} is used for {role}", "ok": True,
                "lines": [f"kept in {where}", "the hosts are placed again from it at the next ask"]}

    def world_geoip_remove(self, source, role, accept_removal=False) -> dict:
        """A GeoIP source's file removed, with its notes, on the word of a person signed in at the platform's page,
        asked twice (geosources.RemovalRefused, naming accept_removal, until the second). A source no longer offered
        may still be removed. The places it gave are cleared from the hosts database where no file in use gives
        them, and placed again at the next ask."""
        view, named, file = self._geoip_gate(source, role, offered=False)
        if accept_removal is not True:
            raise geosources.RemovalRefused(f"{file.title} is removed only once you confirm it a second time.")
        out = view.remove(named.id, role)
        if out.get("ok") and view.chosen()[role]["source"] != named.id:
            net = self.netstat_view(make=False)
            if net is not None and not net.elsewhere():
                net.book.clear_places(role, geosources.cleared(role, named.id))
        self._geoip_replaced(view)
        return out

    def world_routes(self) -> routes_module.Routes:
        """The routes of this plugin's World Wide Web tab (1.67.0, machines/routes.py): made when first asked, closed
        when the plugin is detached or the platform stops."""
        routes = self.__dict__.get("_routes")
        if routes is None:
            with _WORLD_LOCK:
                routes = self.__dict__.get("_routes")
                if routes is None:
                    routes = self.__dict__["_routes"] = self.make_world_routes()
        return routes

    def make_world_routes(self) -> routes_module.Routes:
        """The Routes the tab traces with: the system's own (netpath.trace), each route kept in the hosts database
        (1.68.0). A subclass's tests hand a stand-in."""
        return routes_module.Routes(keep=self._keep_route, bootstrap=self.RDAP_BOOTSTRAP, known=self._routed,
                                    stored=self._stored_routes)

    def _routed(self) -> set[str]:
        """1.74.0: the hosts the hosts database has a route to: each is not traced again."""
        return set() if self.not_for_here() else self.netstat_view().book.routed()

    def _stored_routes(self, addresses) -> dict:
        """1.74.1: the routes the hosts database keeps of these hosts, read back for the tab (HostBook.routes_of);
        none on a machine the plugin is not for."""
        return {} if self.not_for_here() else self.netstat_view().book.routes_of(addresses)

    def _keep_route(self, *route) -> None:
        """A traced route into this plugin's hosts database (hostbook.HostBook.keep_route); nothing on a machine the
        plugin is not for."""
        if not self.not_for_here():
            self.netstat_view().book.keep_route(*route)

    def world_home(self, view: WorldView | None = None):
        """The place the user set for this machine on the globe (LIMINAL_HOME_PLACE, "lat,lon[,label]"), read through this
        plugin's login, the one way to a setting, at most every world.SETTING_S; None when none is set, nobody is signed in
        or the login cannot say."""
        login = getattr(self, "login", None)
        if login is None:
            return None

        def read():
            try:
                return (login.variables([HOME_PLACE_VAR]) or {}).get(HOME_PLACE_VAR) or None
            except Exception:  # noqa: BLE001 - a login that cannot say: no place set
                return None
        return (view or self.world_view()).setting(read)

    def world(self) -> dict:
        """The World Wide Web tab's page (apps/tabs.py), asked every two seconds while the tab is shown. Each ask reads
        the socket table for the hosts database (netstat_view: recorded while this tab or Netstat is shown, unless
        always) and, while the globe shows the traffic, keeps the watching going: a capture at this machine's adapter,
        which stops by itself WORLD_TIMEOUT seconds after the last ask, and on detach. The page is what has been
        counted: the globe with the places traffic came from and went to (placed by the GeoIP file on this machine) and
        their routes to home, the busiest ports' charts, the ports and the places tabled, and the GeoIP file's install
        form while none is installed; or, while it shows the hosts recorded, each program's remote hosts by place,
        filtered as chosen, with no traffic page made for it. Always what the globe shows and the internet
        infrastructure's layers and data sets (NetstatView.onto). Not for this machine (not_for_here): a page saying
        so, and nothing started."""
        here = self.not_for_here()
        if here:
            return not_here_page(here)
        view = self.world_view()
        net = self.netstat_view()
        seen = net.touch()
        # 1.67.0: every connection open now to an address on the internet has its route traced while the tab is
        # shown (the user, 2026-11-19: "trace all connections"); a place's line then runs through its hops
        remotes = [r.get("remote") for r in seen.get("rows") or ()
                   if isinstance(r, dict) and r.get("remote") and r.get("where") == sockets.WHERE[2]]
        routes = self.world_routes()
        try:
            if not getattr(view, "closed", False):  # a view a detach under way closed: nothing started for it
                routes.want(remotes)
        except Exception:  # noqa: BLE001 - the routes never cost the tab its page
            pass
        attribution = dict(self.ATTRIBUTION) if isinstance(self.ATTRIBUTION, dict) and self.ATTRIBUTION else None
        if getattr(view, "sources", None):  # 1.102.0: the places file's in use
            attribution = (view.credits() or {}).get("places") or attribution
        frame = {"home": self.world_home(view), "public": self.PUBLIC_DNS, "attribution": attribution,
                 "can_install": bool(self.GEOIP_URL), "licence": self.GEOIP_LICENCE, "source": self.GEOIP_URL,
                 "asn_source": self.GEOIP_ASN_URL, "asn_licence": self.GEOIP_ASN_LICENCE}  # 1.75.0
        page = None
        if net.shows() == "traffic":
            view.touch()
            page = view.page(**frame, keys=self._geoip_keys(view))
        page = net.onto(page, view, **frame)
        try:
            routes.onto(page, view.geoip(), remotes, index=net.index, licence=frame["licence"])  # 1.69.0, 1.71.0
        except Exception:  # noqa: BLE001 - the routes never cost the tab its page
            pass
        finally:
            view.rest()  # the GeoIP file let go again unless the capture runs (WorldView.rest)
        try:  # 1.74.0: the switch of the traffic's watching, its table and its form (kept through a login: with one)
            if getattr(self, "login", None) is not None:
                table, form = self._watch_table()
                page.setdefault("tables", []).append(table)
                page.setdefault("forms", []).append(form)
        except Exception:  # noqa: BLE001 - the switch never costs the tab its page
            pass
        under = world_module.under_wsl()  # inside a WSL distribution: what WSL changes for the tab, after its own tables
        if under is not None and isinstance(page.get("tables"), list):
            page["tables"].append(under)
        return page

    def _geoip_keys(self, view) -> set | None:
        """1.102.0: the keys the offered sources need that the asking person's login store holds, by name alone (never
        a value); None when none is asked of anyone or the store cannot list."""
        wanted = [n for s in getattr(view, "sources", None) or () if s.offered for n in s.keys]
        if not wanted:
            return None
        login = asking_login()
        if not keeps(login):
            return set()
        try:
            have = login.names()
        except Exception:  # noqa: BLE001 - a store that cannot list: not known
            return None
        return None if have is None else {n for n in wanted if geosources_pair(n) in have}

    # -- 1.74.0: the traffic watched all the time, on the user's switch -------------------------------------------
    def world_watch_mode(self, fresh: bool = False) -> str:
        """When the traffic is watched, as the login says (WATCH_VAR, read every WATCH_READ_S at most): "shown" (also
        with no login or nothing set) or "always"."""
        kept = self.__dict__.get("_watch")
        if not fresh and kept is not None and time.monotonic() - kept[0] < WATCH_READ_S:
            return kept[1]
        login = getattr(self, "login", None)
        try:
            raw = (login.variables([WATCH_VAR]) or {}).get(WATCH_VAR) if login is not None else None
        except Exception:  # noqa: BLE001 - a login that cannot say: shown
            raw = None
        mode = "always" if str(raw or "").strip().lower() == "always" else "shown"
        self.__dict__["_watch"] = (time.monotonic(), mode)
        return mode

    def world_watch_follow(self) -> None:
        """The watching follows its setting: always, started now and never stopped for want of an ask (only by the
        plugin's detach or the platform's stop); shown, stopped WORLD_TIMEOUT after the tab's last ask, as before.
        Only the capture: the routes are still traced only while the tab is shown. Nothing on a machine the plugin is
        not for."""
        if self.not_for_here():
            return
        try:
            if self.world_watch_mode(fresh=True) == "always":
                view = self.world_view()
                view.watcher.timeout = math.inf
                view.touch()
            else:
                view = self.world_view(make=False)
                if view is not None:
                    view.watcher.timeout = view.timeout
        except Exception:  # noqa: BLE001 - a capture that cannot start: its tab says why when it is asked
            pass

    def world_watching(self, mode) -> dict:
        """The traffic watched "shown" (only while the World Wide Web tab is shown) or "always" (all the time the
        platform runs, with no page open), kept through the plugin's login (WATCH_VAR); the watching follows at
        once. ValueError, in words: neither word, no login, a login that keeps nothing, a machine not for it."""
        self._only_here()
        word = str(mode or "").strip().lower()
        if word not in WATCH_WORDS:
            raise ValueError(f"the traffic is watched shown or always, not {world_module._shown(mode)}")
        login = getattr(self, "login", None)
        if login is None:
            raise ValueError("no login to keep the setting through: sign in first")
        try:
            where = login.save(WATCH_VAR, word)
        except Exception as e:  # noqa: BLE001 - a login that keeps nothing: its own words
            raise ValueError(f"the setting could not be kept: {e}") from None
        self.world_watch_follow()
        return {"said": f"the traffic watched {WATCH_WORDS[word]}", "ok": True, "lines": [f"kept in {where}"]}

    def _watch_table(self) -> tuple[dict, dict]:
        """The World Wide Web tab's table of the switch, and its form."""
        mode = self.world_watch_mode()
        form = {"id": WATCH_FORM, "hook": WATCH_HOOK, "title": "Watching the traffic",
                "fields": [{"name": "mode", "label": "Watch the traffic", "type": "choice", "value": mode,
                            "choices": [{"value": "shown", "title": "Only while this tab is shown"},
                                        {"value": "always", "title": "All the time the platform runs",
                                         "note": "the capture keeps running with no page open"}]}],
                "confirm": {"title": "Change when the traffic is watched?", "yes": "Change it", "words": (
                    "Watching is set to {mode}. Always keeps the capture at this machine's adapter running for as long "
                    "as the platform runs, with no page open too, counting the packets, the ports and the places as "
                    "this tab does; nothing is sent anywhere. The routes are still traced only while this tab is "
                    "shown. The choice is kept through your login.")}}
        table = {"title": "Watching the traffic", "note": "Whether the capture keeps running while this tab is not "
                 "shown (the switch is kept through your login).", "columns": [{"title": "Watched"}, {"title": ""}],
                 "rows": [[WATCH_WORDS[mode], {"form": WATCH_FORM, "title": "Change…"}]]}
        return table, form

    def world_geoip(self, accept_licence=False, log=None) -> dict:
        """The GeoIP file installed for the World Wide Web tab, on the user's word: a change, asked only from the tab's
        install form, never by the page on its own, and run by the platform as a job (JOB_HOOKS: `log` is its panel,
        given each step and the bytes downloaded with their percent, at most every two seconds). Refused before anything
        is said or done (world.LicenceRefused, naming accept_licence, which the platform's page asks as a second, explicit
        confirmation with the licence's words) unless `accept_licence` is exactly True. Then this month's file at
        GEOIP_URL is downloaded (last month's when this month's is not out yet) and put in place (WorldView.install: one
        deadline for all of it, https on every hop from the plugin's own host); what was installed, in words."""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")
        if self.GEOIP_SOURCES:  # 1.102.0: the default source's places file
            return self._default_install("places", accept_licence, log, LICENCE_FIRST)
        if not self.GEOIP_URL:
            raise ValueError(f"{self.title or self.name} offers no GeoIP file to download")
        if accept_licence is not True:
            raise LicenceRefused(LICENCE_FIRST)
        return self.world_view().install(self.GEOIP_URL, log=log)

    def world_asn(self, accept_licence=False, log=None) -> dict:
        """1.75.0: the ASN file installed beside the GeoIP file, on the user's word, as world_geoip installs that:
        asked only from its form, run as a job, refused (world.LicenceRefused) unless `accept_licence` is exactly
        True; then this month's file at GEOIP_ASN_URL (last month's while this month's is not out) put in the GeoIP
        folder's asn/, and each place's network read from it from then on."""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")
        if self.GEOIP_SOURCES:  # 1.102.0: the default source's networks file
            return self._default_install("networks", accept_licence, log,
                                         "The ASN file is downloaded only once you accept its licence.")
        if not self.GEOIP_ASN_URL:
            raise ValueError(f"{self.title or self.name} offers no ASN file to download")
        if accept_licence is not True:
            raise LicenceRefused("The ASN file is downloaded only once you accept its licence.")
        return self.world_view().install(self.GEOIP_ASN_URL, log=log, kind="asn")

    def _default_install(self, role: str, accept_licence, log, first: str) -> dict:
        """1.102.0: world_geoip and world_asn with GEOIP_SOURCES: the default source's file of `role`. Its acceptance is
        kept only for a person signed in at the platform's page (in their own login store, or nothing is downloaded);
        any other ask downloads as before 1.102.0 and records nothing."""
        view = self.world_view()
        named, file = view.source(view.default), view.file_of(view.default, role)
        if file is None:
            raise ValueError(f"{self.title or self.name} offers no {role} file to download")
        if named.keys:
            raise ValueError(f"{file.title} needs a key: ask it from the GeoIP sources table")
        if accept_licence is not True:
            raise LicenceRefused(first)
        if self._at_the_page():
            return self._geoip_download(view, named, file, asking_login(), log)
        out = view.get(named.id, role, log=log, cancel=lambda: bool(getattr(log, "cancelled", False)))
        self._geoip_replaced(view)
        return out

    # -- the Netstat tab, the hosts database and the globe's filters and layers (1.65.0; machines/netstat.py) ---------
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
        """The NetstatView the tabs read with: this machine's socket table (sockets.read), the hosts database in the
        data folder (hostbook.book), the data sets of INFRASTRUCTURE (each read by infrastructure.DataSet.of; one that
        does not read is left out and said in its table), the plugin's login and the listeners its own read names
        (netstat_listeners). A subclass with stand-ins of its own (its tests) makes it here."""
        sets, refused, ids = [], [], set()
        for said in self.INFRASTRUCTURE or ():
            try:
                found = DataSet.of(said)
            except ValueError as e:
                refused.append(str(e))
                continue
            if found.id in ids:
                refused.append(f"the data set {found.id} is named twice: its first is kept")
                continue
            ids.add(found.id)
            sets.append(found)
        return NetstatView(self.name, login_of=lambda: getattr(self, "login", None), listeners=self.netstat_listeners,
                           app_ports=app_ports, index=Index(datasets=sets), refused=refused,
                           agent=netstat.agent_of(self.name, self.version))

    def netstat_listeners(self) -> dict[tuple[str, int], str]:
        """The listening sockets this plugin's own read names that the socket table does not ({(proto, port):
        program}, another user's, as a root read of the firewall sees them): none here. Asking nothing: what a read
        made already."""
        return {}

    def _only_here(self) -> None:
        """A ValueError in words on a machine this plugin is not for (not_for_here), asked first by every hook of the
        Netstat tab, the hosts database and the globe's choices and layers: there none of them makes a view, reads
        the socket table, starts the recording, keeps a setting, forgets the hosts or removes a data set (the plugin
        this machine is for keeps them; the hosts database and the layers' folder are this system's, not a plugin's)."""
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
        read."""
        here = self.not_for_here()
        if here:
            return {"title": netstat.TITLE, "note": f"Not for this machine: {here}. Nothing is read here."}
        page = self.netstat_view().page(self.world_view())
        under = sockets.under_wsl()
        if under is not None and isinstance(page.get("tables"), list):
            page["tables"].append(under)
        return page

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

    def world_show(self, what) -> dict:
        """What the globe shows: "traffic" (watched now, the default) or "hosts" (recorded in the hosts database).

        A choice of its page, kept in this plugin until it is detached; its answer says the filter in words. ValueError
        on a machine the plugin is not for, as for every choice of the globe."""
        self._only_here()
        return self.netstat_view().show(what)

    def world_direction(self, direction) -> dict:
        """The hosts recorded of one direction on the globe: "out", "in", or "" for both (the globe shows the hosts)."""
        self._only_here()
        return self.netstat_view().direction(direction)

    def world_within(self, within) -> dict:
        """The hosts last seen within "hour", "day", "week" or "month", or "" for any time, on the globe.

        The globe shows the hosts recorded."""
        self._only_here()
        return self.netstat_view().within(within)

    def world_pick(self, choice) -> dict:
        """A program's hosts on the globe (program=<name>), every host on a port (port=<tcp|udp>/<number>), or clear.

        program= and port= alone pick every program, every port; clear takes every filter back. The globe shows the
        hosts recorded."""
        self._only_here()
        return self.netstat_view().pick(choice)

    def world_layer(self, layer) -> dict:
        """One infrastructure layer's geometry for the globe, read from this machine's files (a read).

        The page asks it once a layer's version, with the layer's id (Index.layer); LookupError when none is
        installed, ValueError on a machine the plugin is not for."""
        self._only_here()
        return self.netstat_view().layer(layer)

    def world_layer_get(self, dataset, accept_licence=False, log=None) -> dict:
        """A data set of INFRASTRUCTURE downloaded on the user's word, run by the platform as a job (Cancel stops it).

        Refused (world.LicenceRefused, naming accept_licence, asked by the page as a second confirmation with the
        licence's words) until its licence is accepted; then one https request to the data set's own host, read under
        one deadline and kept on this machine's disk in place of any older copy (infrastructure.install). ValueError for
        a data set this plugin does not name, and on a machine it is not for."""
        self._only_here()
        return self.netstat_view().get(dataset, accept_licence, log)

    def world_layer_remove(self, dataset) -> dict:
        """A data set's file removed from this machine, confirmed on the page: the globe no longer draws its layers.

        ValueError on a machine the plugin is not for: the layers' folder is this system's, and its own plugin's
        files are left as they are."""
        self._only_here()
        return self.netstat_view().drop(dataset)

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
            if not getattr(app, "once", False):
                self.world_watch_follow()  # 1.74.0
        return out

    def app_stopping(self) -> None:
        """The platform stops (liminal-platform 0.31.0): the hosts' recording thread ended and what it read written. It
        bears a second call."""
        view = self.netstat_view(make=False)
        if view is not None:
            view.stop()
        with _WORLD_LOCK:  # let go of: a platform stopped may start again in this process, and trace anew
            routes = self.__dict__.pop("_routes", None)
        if routes is not None:
            routes.close()

    def settings_changed(self) -> None:
        """The platform kept one of this plugin's settings (its page's Settings): the home the user set is read anew at the
        tab's next ask, and the hosts' recording and the traffic's watching (1.74.0) follow their settings at once."""
        view = self.world_view(make=False)
        if view is not None:
            view.forget_setting()
        self.__dict__.pop("_geoip_choice", None)  # 1.102.0: the GeoIP sources chosen, read anew
        net = self.netstat_view(make=False)
        if net is not None:
            net.forget_setting()
        if not self.not_for_here():
            try:
                self.netstat_view().follow()
            except Exception:  # noqa: BLE001 - a view that cannot be made or read: its tab says why when it is asked
                pass
            self.world_watch_follow()  # 1.74.0 (it catches its own)

    def detach(self) -> None:
        """Detached by its app: the hosts' recording ended for good (NetstatView.close: its thread gone, what it read
        written, the file let go), then the World Wide Web tab's watching (WorldView.close: its capture closed, its
        thread gone, its GeoIP file let go, an ask still under way starting nothing), both forgotten; then the plugin
        detached as every plugin is."""
        with _NETSTAT_LOCK:
            net = self.__dict__.pop("_netstat", None)
        if net is not None:
            net.close()
        with _WORLD_LOCK:
            view = self.__dict__.pop("_world", None)
            routes = self.__dict__.pop("_routes", None)
        if view is not None:
            view.close()
        if routes is not None:
            routes.close()
        super().detach()
