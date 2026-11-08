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
from dataclasses import dataclass

from .plugin import CommandError, MachinePlugin

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
    ("the integrator's login", "", 8796),
)


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
    the hooks (status, setup) and the platform's asks (allow, remove, wanted) are this base's."""

    HOOKS = (*MachinePlugin.HOOKS, "allow", "remove", "wanted")  # what the platform may ask by name (Plugin.ask)
    STEPS = STEPS
    ICON = "shield"

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
        if not self.present():
            return {"present": False, "backend": "", "enabled": False, "profiles": {}, "rules": [], "summary": "not present"}
        try:
            backend = self.backend()
            st = self.state()
            rules = [r.describe() for r in self.list_rules()]
        except CommandError as e:
            return {"present": True, "backend": "", "enabled": False, "profiles": {}, "rules": [], "problem": str(e),
                    "summary": f"cannot be read: {e}"}
        profiles = st.get("profiles", {})
        on = [n for n, v in profiles.items() if v]
        off = [n for n, v in profiles.items() if not v]
        where = (f" ({', '.join(on)} on" + (f"; {', '.join(off)} off" if off else "") + ")") if on else (f" ({', '.join(off)} off)" if off else "")
        summary = f"{backend}: {'on' if st.get('enabled') else 'off'}{where}; {len(rules)} Liminal rule(s)"
        return {"present": True, "backend": backend, **st, "rules": rules, "summary": summary}

    def setup(self, log=print, steps=None) -> list[dict]:
        """`enable` (the firewall on where it is off), `exposure` (no rule lets another machine reach the
        framework's pages; a finding, never a change), `rules` (the services' rules added where missing;
        Liminal's other rules left alone); each reported. A firewall error ends it."""
        wanted = tuple(steps) if steps else self.STEPS
        done: list[dict] = []

        def step(what: str, ok: bool | None, detail: str) -> None:
            done.append({"step": what, "ok": ok, "detail": detail})
            log(f"{self.name}: {what}: {'ok' if ok else 'skipped' if ok is None else 'FAILED'}: {detail}")

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
