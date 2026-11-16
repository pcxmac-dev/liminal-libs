"""A firewall as a machine plugin's base (the user, 2026-11-07: "i also need a windows and linux firewall
plugin for the platform"; the platform is "the interface for the software/hardware which facilitates the
liminal framework"). What the framework asks of a firewall: that it is on; that no rule lets another machine
reach the framework's own pages (they answer this machine only, at 127.0.0.1); and that the services this
machine runs for the framework, a domain login's mail server container, can be reached on their ports.
Every rule the framework makes is its own, marked as Liminal's (Windows' rule group "Liminal", a Linux
comment or service named liminal...), so it is listed, changed and removed apart from every other rule; a
rule that is not Liminal's is only ever read. A subclass drives one firewall (Windows Defender Firewall; ufw,
firewalld or nftables) through the backend methods; this base holds the rules, the framework's ports, the
status and the setup."""
from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass

from ..apps.tabs import Tab
from . import world as world_module
from .plugin import CommandError, MachinePlugin
from .rulegroups import RuleGroups, Sorted
from .world import (GEOIP_HOOK, HOME_KEY, HOME_PLACE_VAR, HOOK as WORLD_HOOK, LICENCE_FIRST, TAB as WORLD_TAB, TIMEOUT_S,
                    TITLE as WORLD_TITLE, LicenceRefused, WorldView, not_here_page)

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
    world_view(make=False)."""

    HOOKS = (*MachinePlugin.HOOKS, "allow", "remove", "wanted",  # what the platform may ask by name (Plugin.ask)
             "move_rules", "new_label", "rename_label", "remove_label",
             # 1.55.0: world, the World Wide Web tab's page (a read); world_geoip, its GeoIP file's install (a change)
             WORLD_HOOK, GEOIP_HOOK)
    STEPS = STEPS
    ICON = "shield"
    GROUPS_VARIABLE = ""  # where the user's labels and moves are kept through the login: "" for <NAME>_GROUPS
    # -- the World Wide Web tab (1.55.0) -------------------------------------------------------------------------------
    TABS = (Tab(WORLD_TAB, WORLD_TITLE, WORLD_HOOK, 2.0),)  # after Main and API: asked every 2 s while it is shown
    # hooks the platform runs as a job (liminal-platform 0.19.0), their lines followed in the plugin's panel: the GeoIP
    # file's install, a download of about 60 MB that would otherwise hold the form's dialog for minutes
    JOB_HOOKS = (GEOIP_HOOK,)
    # this month's GeoIP file, {year} and {month} filled in (2026, 11): an https address of the plugin's own ("" offers
    # no download); last month's is tried when this month's is not out yet
    GEOIP_URL = ""
    GEOIP_LICENCE = ""  # the licence's words, shown before the download and accepted in so many words
    ATTRIBUTION: dict = {}  # {text, url}: drawn wherever places are ("IP Geolocation by DB-IP" with DB-IP's link)
    # the name servers asked for this network's public address, which places home when the user set none: each in
    # dns.public_address's shape, (the name, its type, the server, whose), split by the server's IP version; or
    # {4: (...), 6: (...)}. () asks none: home is then the user's place, or none
    PUBLIC_DNS: tuple = ()
    WORLD_TIMEOUT = TIMEOUT_S  # watching stops this long after the tab was last asked
    keys = (HOME_KEY,)  # LIMINAL_HOME_PLACE (optional), set on the plugin's page: the globe's home, read through the login

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
        return WorldView(self.name, timeout=self.WORLD_TIMEOUT)

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
        """The World Wide Web tab's page (apps/tabs.py), asked every two seconds while the tab is shown. Each ask keeps the
        watching going: a capture at this machine's adapter, which stops by itself WORLD_TIMEOUT seconds after the last ask,
        and on detach. The page is what has been counted: the globe with the places traffic came from and went to (placed
        by the GeoIP file on this machine) and their routes to home, the busiest ports' charts, the ports and the places
        tabled, and the GeoIP file's install form while none is installed. Not for this machine (not_for_here): a page
        saying so, and nothing started."""
        here = self.not_for_here()
        if here:
            return not_here_page(here)
        view = self.world_view()
        view.touch()
        attribution = dict(self.ATTRIBUTION) if isinstance(self.ATTRIBUTION, dict) and self.ATTRIBUTION else None
        page = view.page(home=self.world_home(view), public=self.PUBLIC_DNS, attribution=attribution,
                         can_install=bool(self.GEOIP_URL), licence=self.GEOIP_LICENCE, source=self.GEOIP_URL)
        under = world_module.under_wsl()  # inside a WSL distribution: what WSL changes for the tab, after its own tables
        if under is not None and isinstance(page.get("tables"), list):
            page["tables"].append(under)
        return page

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
        if not self.GEOIP_URL:
            raise ValueError(f"{self.title or self.name} offers no GeoIP file to download")
        if accept_licence is not True:
            raise LicenceRefused(LICENCE_FIRST)
        return self.world_view().install(self.GEOIP_URL, log=log)

    def settings_changed(self) -> None:
        """The platform kept one of this plugin's settings (its page's Settings): the home the user set is read anew at the
        tab's next ask."""
        view = self.world_view(make=False)
        if view is not None:
            view.forget_setting()

    def detach(self) -> None:
        """Detached by its app: the World Wide Web tab's watching ended for good (WorldView.close: its capture closed, its
        thread gone, its GeoIP file let go, an ask still under way starting nothing) and forgotten, then the plugin detached
        as every plugin is."""
        with _WORLD_LOCK:
            view = self.__dict__.pop("_world", None)
        if view is not None:
            view.close()
        super().detach()
