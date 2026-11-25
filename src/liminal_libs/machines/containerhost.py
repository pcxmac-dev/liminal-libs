"""`ContainerHost`: the base every container plugin is built on (1.93.0; service-containers-design §3.5 to §3.7, and
the networking design's §8.4). Docker, Windows containers, Kubernetes and LXD each give their targets and, for each
target, a `Runtime` (containers.py); this base answers the hooks and holds every rule:

- **Who asks.** service_plan, apply_plan, service_work, hosted_file and release_owned: a plugin alone, and only the
  service's owner. approve_plan, grant_service, revoke_service and forget_volume: the page alone (PAGE_ONLY_HOOKS, which
  the platform refuses to every plugin, and checked again here). hosted_logs, plan_words, decline_plan and
  service_cancel: the page or the owner. An ask that names no asker is refused, in words.
- **Grants.** A plan for a (plugin, target) is refused until you let that plugin use that target on this plugin's page,
  kept through the login (<NAME>_SERVICE_GRANTS). Stop letting it… leaves its services as they are.
- **Plans** (machines/plans.py): in memory alone, MAX_PLANS at most, PLAN_S each, used once, forgotten at a detach; the
  facts read again at apply, under the target's one work at a time.
- **Works**: one per target at a time; reads never wait on them; turning the plugin off and the platform's stop cancel
  and join them; a detach for invalidity cancels nothing.
- **Secrets**: named by their variable under the owner's stem, read through this plugin's login only when the work
  begins, handed to the runtime by environment alone, masked out of every word, never in a label, a plan or an answer.
- **Ports**: 1024 to 65535; never the four apps' pages or the Linux suite's; never another Liminal service's, a model
  server's, another program's (the socket table) or one Windows reserves; one opened to your network asks accept_lan.
- **Data**: named, labelled volumes; only an install makes one (or finds it from before); only a delete_data plan with
  accept_data, or Forget… asked twice, deletes one, never while a container uses it; an update backs up first or asks
  accept_no_backup; a failed or cancelled work never removes a volume.
- **The container's shape**: by digest alone, with a memory limit and the labels; `--restart no` always (never
  on-failure: a restart after a crash is never made, the user's "Never"); service mode (start at boot) is provided for
  in the words and refused until it is offered.
- **Targets**: only this machine's; a target that is not ready refuses every plan before any runtime command, and
  nothing here starts an engine (the user's "No").
- **Lifecycle**: a service runs from your Start to your Stop: stopped at the platform's stop (app_stopping, attached or
  not), when you turn this plugin off, and when you turn its owner off (release_owned); never at a detach for
  invalidity. A service inside WSL holds its distribution up through its WSL plugin while it runs.
- **Networks**: each service gets its own network, its prefix and addresses handed out by the firewall plugin that
  routes its target's stack (machines/segments.py), in that firewall's own plan, approved on the page beside this one's.
  No firewall answering refuses the plan, naming the firewall's page (N12). Since 1.95.0 a runtime may say what its
  engine has already (`Runtime.network_want`: Windows' one NAT network, a cluster's pods), which the firewall reserves
  and records as it is; a network that is not the service's own is never dropped.
- **Yours to define** (1.95.0; the user, 2026-11-25: "user has to define these things before creating instances"): a
  container plugin declares the places and sizes of yours it needs per target (`TARGET_SETTINGS`, or
  `target_settings(target)`: containers.Setting); Liminal picks none of them; until each is set on its page
  (set_target_setting, page-only, kept through the login as <NAME>_TARGET_SETTINGS) every plan on that target is
  refused in words.
- **Its own accepts** (1.95.0): a container plugin may add a second confirmation of its own to a plan
  (`MORE_ACCEPTS`, `more_accepts`), asked and approved as the base's are.
- **Parts added** (1.95.0): an update whose spec adds a part and changes no other is planned as that part's addition
  alone (its own steps and accepts: nothing stopped, nothing backed up); one that also changes another part is refused
  (two plans: the update, then the addition); one that drops a part is refused.

The honest limit: these gates keep an honest plugin, or one with a bug, from doing what you did not approve. They are
not a wall against hostile code in the same process."""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shutil
import socket
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Mapping

from ..apps import asking
from ..instances import Refusal, Store
from . import containers as C
from .containers import (ACCEPT_DATA, ACCEPT_DIFFERS, ACCEPT_KEPT_SECRET, ACCEPT_LAN, ACCEPT_NO_BACKUP, Aspect, Fit,
                         ImagePin, Part, Port, Seed, ServiceSpec, Target, Volume)
from .plans import Accept, Cancelled, Plan, Plans, Work, Works, digest
from .plugin import MachinePlugin

NET_PLAN, APPLY_NET, NET_WORK, NET_CANCEL, NETWORK_HOST = ("network_plan", "apply_network", "network_work",
                                                           "network_cancel", "network_host")
NET_ACTIONS = {"install": "install", "start": "start", "restart": "start", "expose": "expose", "remove": "remove",
               "delete_data": "delete_data"}
FOLLOW_S = 0.5  # how often a work follows a firewall's work
HEALTH_EVERY_S = 2.0


def _iso(wall: float) -> str:
    return _dt.datetime.fromtimestamp(wall, _dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _health_check(host: str, port: int, path: str, timeout: float = 3.0) -> bool:
    """The base's own health check, from this machine: a TCP connect; with a path, an http GET answering below 500."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if not path:
                return True
            s.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii"))
            head = s.recv(64).decode("latin-1", "replace")
    except OSError:
        return False
    m = re.match(r"HTTP/\d\.\d (\d{3})", head)
    return bool(m) and int(m.group(1)) < 500


@dataclass
class Outside:
    """What the base reaches outside itself, each a test's stand-in where given: clocks, the health check, who holds a
    port of this machine (words, [] when none), the platform's instance name, the platform's folder for backups, and
    the sleep a work waits with."""

    clock: Callable[[], float] = time.monotonic
    wall: Callable[[], float] = time.time
    health: Callable[[str, int, str], bool] | None = None
    holders: Callable[[int], list] | None = None
    platform: str = ""
    folder: Path | None = None
    sleep: Callable[[float], None] = time.sleep
    env: Mapping | None = None


@dataclass(frozen=True)
class Create:
    """One container made: what a runtime is handed. `secret_env` is never put on a command line."""

    name: str
    part: Part
    labels: Mapping
    volumes: tuple  # (volume name, path inside)
    ports: tuple  # Port
    env: Mapping
    secret_env: Mapping = field(default_factory=dict, repr=False)
    network: str = ""
    address: str = ""
    hostname: str = ""
    aliases: tuple = ()
    add_hosts: tuple = ()
    restart: str = "no"

    @property
    def pinned(self) -> str:
        return self.part.image.pinned


class Runtime:
    """One target's mechanism, as the base asks it. Every method may raise in words (its engine's own); none starts an
    engine. A container plugin gives one per target (`runtime_of`): DockerRuntime, or a mechanism of its own."""

    mechanism = ""

    def fit(self, spec: ServiceSpec | None) -> Fit:
        return Fit()

    def hosted(self) -> list[dict]:
        """Liminal's services on this target, read back from their labels: [{"sid", "parts": [{"name", "container",
        "role", "state", "exit", "health", "image", "digest", "since"}], "spec" (as labelled), "spec_sha", "platform",
        "lifecycle", "made"}]."""
        return []

    def volumes(self) -> list[dict]:
        """Liminal's volumes here, by their labels: [{"name", "sid", "volume", "used_by": [...], "size", "made"}]."""
        return []

    def facts(self, spec: ServiceSpec | None, sid: str) -> dict:
        """What a plan rests on: each image present by digest, each volume's presence and labels, the service's
        containers and their states, its network."""
        return {}

    def has_image(self, pin: ImagePin) -> bool:
        return False

    def pull(self, pin: ImagePin, line, cancelled) -> str:
        """The image pulled by digest, its lines to `line`; the digest found after."""
        raise NotImplementedError

    def make_volume(self, name: str, labels: Mapping) -> bool:
        """The volume made (True), or found from before (False)."""
        raise NotImplementedError

    def make_volume_for(self, name: str, labels: Mapping, volume: Volume) -> bool:
        """1.95.0: the volume made for the spec's `volume` (its owner uid, the least it needs), or found: what the base
        asks. By default make_volume(name, labels); a runtime that gives a volume its owner (LXD's initial.uid) or a
        size (a claim) answers this one."""
        return self.make_volume(name, labels)

    def network_want(self, spec: ServiceSpec | None, sid: str) -> dict:
        """1.95.0: what this engine has already for the service's network, laid over the base's Want
        (segments.Want): {} by default (a network of the service's own, its prefix and addresses the firewall's).
        Keys: "network" (the network its containers join, when it is not containers.network_name(sid): Windows'
        "nat"), "found" (that network's prefix, to be reserved), "assigns" (who gives the addresses: "hns",
        "kubernetes", "incus"), "shared" (several services on it: never dropped), "route" (False: no route wanted),
        "behind" (the address a nested segment sits behind)."""
        return {}

    def data_root(self) -> str:
        """1.95.0: where the engine keeps its data, as it says (docker info's DockerRootDir): "" when not read; said
        beside the Target's where_data on every plan."""
        return ""

    def kept_secret_words(self, spec: ServiceSpec) -> str:
        """1.95.0: who can read a secret this engine is handed, for accept_kept_secret's words ("": the base's own,
        or the plugin's _kept_secret_words)."""
        return ""

    def backup_kind(self, part: Part) -> str:
        """1.95.0: how this engine backs up the part's volumes before an update (containers.BACKUP_KINDS): "tar"
        through the image's own tar into a file here (the default; an image without tar asks accept_no_backup),
        "snapshot" by the engine's own snapshot (backup() answers its words, kept beside the tars in
        <volume>.snapshot.json, which restore() is handed), "none" (asks accept_no_backup)."""
        return "tar"

    def make_network(self, name: str, grant: Mapping, labels: Mapping) -> bool:
        raise NotImplementedError

    def create(self, c: Create) -> None:
        raise NotImplementedError

    def seed(self, container: str, seeds: list[tuple[str, Seed, int | None]], line) -> None:
        """Each (its path inside the container, the seed, its volume's owner uid or None) written into a new volume
        before the first start, never over a file already there."""
        raise NotImplementedError

    def start(self, container: str) -> None:
        raise NotImplementedError

    def stop(self, container: str, seconds: int) -> None:
        raise NotImplementedError

    def rename(self, container: str, new: str) -> None:
        raise NotImplementedError

    def remove(self, container: str) -> None:
        """The container alone: never a volume."""
        raise NotImplementedError

    def state(self, container: str) -> dict | None:
        """{"state", "exit", "health", "digest"}; None when it is not there."""
        return None

    def drop_volumes(self, names: list[str]) -> None:
        raise NotImplementedError

    def drop_network(self, name: str) -> None:
        raise NotImplementedError

    def backup(self, volume: str, pinned: str, into: Path, line, cancelled) -> int | str:
        """The volume backed up into `into` (a tar here): its bytes. A "snapshot" runtime answers its own words (the
        snapshot's name), which the base keeps in <volume>.snapshot.json."""
        raise NotImplementedError

    def restore(self, volume: str, pinned: str, source: Path, line, cancelled) -> int:
        raise NotImplementedError

    def logs(self, container: str, lines: int) -> list[str]:
        return []

    def read(self, container: str, path: str, most: int) -> bytes:
        raise NotImplementedError

    def segments(self) -> list[dict]:
        return []

    def boot(self, container: str, on: bool) -> None:
        """Service mode on or off (start at boot): provided for, never asked in this release."""
        raise Refusal(C.SERVICE_MODE_WORDS)

    def here(self, port: int) -> str:
        return f"127.0.0.1:{port}"

    def lan(self, port: int, protocol: str = "tcp") -> tuple[str, str]:
        return "direct", "published on every address of this machine"


class _SvcState:
    def __init__(self, clock):
        self.lock = threading.Lock()
        self.plans = Plans("p-", clock)
        self.works = Works("w-", clock, "liminal-service-work")
        self.targets: tuple[float, list[Target]] | None = None
        self.askers: set[str] = set()
        self.secrets: list[str] = []  # values read, to mask
        self.held: dict[str, set[str]] = {}  # a WSL distribution -> the sids holding it up
        self.reads: dict[str, tuple[float, list, list | None]] = {}  # a target -> (when, its services, its volumes)


class ContainerHost(MachinePlugin):
    """The base of a container plugin. A subclass sets RUNTIME, spreads these words into its own
    (`HOOKS = (*ContainerHost.HOOKS, ...)`), calls `ContainerHost.__init__(self, outside)` and gives `runtime_targets`
    and `runtime_of`. Its own status merges `service_status()`."""

    SECTION = "virtualization"
    RUNTIME = ""
    HOOKS = (*MachinePlugin.HOOKS, C.HOSTING, C.HOSTED, C.HOSTED_LOGS, C.EXPOSURES, C.PLAN_WORDS, C.WORK, C.PLAN,
             C.APPROVE, C.DECLINE, C.APPLY, C.CANCEL, C.HOSTED_FILE, C.RELEASE, C.GRANT, C.REVOKE, C.FORGET_VOLUME,
             C.SEGMENTS)
    READ_HOOKS = (C.HOSTING, C.HOSTED, C.HOSTED_LOGS, C.EXPOSURES, C.PLAN_WORDS, C.WORK, C.SEGMENTS)
    SERVICE_HOOKS = (C.HOSTING, C.HOSTED, C.HOSTED_LOGS, C.EXPOSURES, C.PLAN_WORDS, C.WORK, C.PLAN, C.DECLINE,
                     C.APPLY, C.CANCEL, C.HOSTED_FILE, C.RELEASE, C.SEGMENTS)
    PLUGIN_ONLY_HOOKS = (C.WORK, C.PLAN, C.APPLY, C.HOSTED_FILE, C.RELEASE)
    PAGE_ONLY_HOOKS = (C.APPROVE, C.GRANT, C.REVOKE, C.FORGET_VOLUME)
    # 1.95.0: the places and sizes of yours its targets need (containers.Setting), none picked for you; a subclass
    # whose targets differ answers target_settings(target) instead. A plugin that declares any spreads SETTING_HOOKS
    # into its HOOKS and its PAGE_ONLY_HOOKS (opted into, so that a plugin built on 1.93.0 declares exactly what it did)
    TARGET_SETTINGS: tuple = ()
    SETTING_HOOKS = (C.SET_SETTING,)
    # 1.95.0: its own second confirmations (accept_<word>), added to a plan by more_accepts and taken by approve_plan
    # after the base's, in this order
    MORE_ACCEPTS: tuple = ()
    ASKS = (("", C.LAN_OPEN, "whether this machine's firewall lets a service's ports in from your network now"),
            ("", NETWORK_HOST, "which firewall routes and names a target's stack"),
            ("", NET_PLAN, "a service's network: its prefix, addresses, route and names, in the firewall's plan"),
            ("", C.PLAN_WORDS, "whether you approved the firewall's plan"),
            ("", APPLY_NET, "the firewall's approved plan carried out inside this plugin's work"),
            ("", NET_WORK, "its lines"), ("", NET_CANCEL, "your Cancel"), ("", C.DECLINE, "a plan you left"),
            ("", C.HOLD, "a WSL distribution held up while a service runs in it"),
            ("", C.LET_GO, "that distribution let go once its last service stops"),
            ("", C.SERVING, "the model servers' ports, so that no service takes one"),
            ("", C.HOSTING, "the other container plugins' services, so that no two take one port"),
            ("", C.EXCLUDED, "the port ranges Windows keeps for Hyper-V and WSL"))

    def __init__(self, outside: Outside | None = None):
        self.out = outside or Outside()
        self._svc = _SvcState(self.out.clock)

    # -- what a subclass gives ------------------------------------------------------------------------------------------
    def runtime_targets(self) -> list[Target]:
        """Its targets, from its own reading (kept READ_S by the base): starts nothing."""
        return []

    def runtime_of(self, target: Target) -> Runtime:
        raise Refusal(f"{self.title or self.name} hosts no service on {target.id}")

    def excluded_ranges(self) -> list[tuple[int, int]]:
        """The port ranges this system keeps for itself (Windows' excluded port ranges for Hyper-V and WSL), as the
        plugins that read them answer EXCLUDED (the Windows firewall plugin, which reads this machine's networking);
        none known when none answers."""
        out: list[tuple[int, int]] = []
        for _name, answer, _e in self.ask_others(C.EXCLUDED):
            for r in (answer or {}).get("ranges") or [] if isinstance(answer, Mapping) else []:
                try:
                    lo, hi = int(r[0]), int(r[1])
                except (TypeError, ValueError, IndexError):
                    continue
                out.append((lo, hi))
        return out

    # -- small parts -------------------------------------------------------------------------------------------------
    @property
    def KEEPS(self):  # noqa: N802 - read as a declared word
        out = [(self._grants_var(), "which service plugins may plan on which of its targets")]
        if self.TARGET_SETTINGS:
            out.append((self._settings_var(), "the places and sizes you defined for its targets"))
        return tuple(out)

    def _grants_var(self) -> str:
        return f"{self.name.upper().replace('-', '_')}_SERVICE_GRANTS"

    def _settings_var(self) -> str:
        return f"{self.name.upper().replace('-', '_')}_TARGET_SETTINGS"

    def _platform(self) -> str:
        if self.out.platform:
            return self.out.platform
        from .. import claims

        return claims.instance(self.out.env)

    def _now(self) -> str:
        return _iso(self.out.wall())

    def _mask(self, text: str) -> str:
        with self._svc.lock:
            values = sorted(self._svc.secrets, key=len, reverse=True)
        for v in values:
            text = text.replace(v, "<hidden>")
        return text

    def _keep_secret(self, value: str) -> None:
        if isinstance(value, str) and len(value) >= 4:
            with self._svc.lock:
                if value not in self._svc.secrets:
                    self._svc.secrets.append(value)
                    del self._svc.secrets[:-64]

    def _asker(self) -> str | None:
        return asking.asker()

    def _need_owner(self, hook: str, owner: str) -> str:
        """The asker, who must be the plugin `owner`: refused in words otherwise (the page, no one, another plugin)."""
        who = asking.asker()
        if who is None:
            raise Refusal(f"{self.name}'s {hook} names no asker: only the service's own plugin asks it")
        if who == asking.PAGE:
            raise Refusal(f"{self.name}'s {hook} is asked by the service's own plugin alone, never from a page")
        if who != owner:
            raise Refusal(f"{self.name}'s {hook}: {owner}'s service is asked of by {owner} alone, not by {who}")
        return who

    def _need_page(self, hook: str) -> None:
        who = asking.asker()
        if who != asking.PAGE:
            raise Refusal(f"{self.name}'s {hook} is yours, from its page alone: {who or 'no one'} asked it")

    def _page_or(self, hook: str, owner: str) -> str:
        who = asking.asker()
        if who == asking.PAGE or (who is not None and who == owner):
            return who
        raise Refusal(f"{self.name}'s {hook} is asked from its page or by {owner}, not by {who or 'no one'}")

    # -- targets and grants -------------------------------------------------------------------------------------------
    def targets(self, fresh: bool = False) -> list[Target]:
        with self._svc.lock:
            kept = self._svc.targets
        now = self.out.clock()
        if kept is not None and not fresh and now - kept[0] < C.READ_S:
            return list(kept[1])
        got = list(self.runtime_targets())
        with self._svc.lock:
            self._svc.targets = (now, got)
        return got

    def forget_targets(self) -> None:
        with self._svc.lock:
            self._svc.targets = None
            self._svc.reads.clear()

    def keep_targets(self, targets: list[Target]) -> None:
        """1.95.0: targets its plugin read already (for its own status), kept READ_S as if runtime_targets had
        answered them: the base's reads then ask the engine nothing more. service_status(targets=...) does it."""
        with self._svc.lock:
            self._svc.targets = (self.out.clock(), list(targets))

    def no_spec_fit(self, target: Target, owner: str) -> Fit | None:
        """1.95.0: what a target says to a service plugin whose recipe has no spec of its system (hosting): None by
        default (its page says "its recipe has no ... image"); a plugin answers a Fit whose `takes` says why in its own
        words (Windows containers: "not yet", decision 14)."""
        return None

    # -- what you define before any instance (1.95.0) ------------------------------------------------------------------
    def target_settings(self, target: Target) -> tuple:
        """The settings of yours a target needs (containers.Setting): TARGET_SETTINGS by default."""
        return tuple(C.Setting.of(s) for s in self.TARGET_SETTINGS)

    def setting_values(self, tid: str) -> dict:
        """What you set for a target: {name: value}, and {name: {sid: value}} for a per-service one."""
        try:
            data = json.loads(Store(self._settings_var(), lambda: self.login).text() or "{}")
        except Exception:  # noqa: BLE001 - nothing kept, or not readable: nothing set
            return {}
        got = dict((data.get("targets") or {}).get(str(tid)) or {}) if isinstance(data, Mapping) else {}
        return {str(k): v for k, v in got.items() if isinstance(v, (str, dict))}

    def setting_value(self, tid: str, name: str, sid: str = "") -> str:
        """One setting's value for a target ("" when not set); a per-service one's for that service."""
        v = self.setting_values(tid).get(name, "")
        if isinstance(v, dict):
            return str(v.get(sid, "")) if sid else ""
        return str(v or "")

    def unset_settings(self, target: Target, sid: str = "") -> list:
        """The required settings of a target not set yet (per-service ones only when `sid` is named). A plugin that
        keeps its settings its own way (Kubernetes' set_cluster) answers this one from them."""
        out = []
        for s in self.target_settings(target):
            if not s.required or (s.per_service and not sid):
                continue
            if not self.setting_value(target.id, s.name, sid if s.per_service else ""):
                out.append(s)
        return out

    def check_target_setting(self, target: Target, setting, value: str, sid: str, confirm: bool) -> list[str]:
        """1.95.0: a value you set, checked by its plugin before it is kept: its lines, or a Refusal in words (with
        `accept="confirm"` when a second confirmation lets it, as "the namespace will be made"). The base checks the
        kind and the choices alone."""
        return []

    def set_target_setting(self, target, setting, value, service="", confirm=False) -> dict:
        """One place or size of yours for a target (a namespace, a storage class, a service's claim size), from its page
        alone, kept through the login; "" clears it. Its plugin checks it first (check_target_setting)."""
        self._need_page(C.SET_SETTING)
        t = self.target(str(target or ""))
        s = next((x for x in self.target_settings(t) if x.name == str(setting or "")), None)
        if s is None:
            raise Refusal(f"{t.id} has no setting {str(setting)[:32]!r}: "
                          + (", ".join(x.name for x in self.target_settings(t)) or "none"))
        sid = ""
        if s.per_service:
            sid = str(service or "").strip()
            C.split_sid(sid)
        v = str(value if value is not None else "").strip()
        if len(v) > 253 or C._controls(v):
            raise Refusal(f"{s.label} is plain text of 253 characters at most")
        lines: list[str] = []
        if v:
            if s.kind == "number" and not re.fullmatch(r"[0-9]{1,12}", v):
                raise Refusal(f"{s.label} is a whole number, not {v[:20]!r}")
            if s.kind == "size":
                C.size_bytes(v)
            if s.choices and v not in s.choices:
                raise Refusal(f"{s.label} is one of {', '.join(map(str, s.choices[:12]))}, not {v[:40]!r}")
            lines += list(self.check_target_setting(t, s, v, sid, confirm is True) or [])
        try:
            data = json.loads(Store(self._settings_var(), lambda: self.login).text() or "{}")
        except Exception:  # noqa: BLE001 - nothing kept yet
            data = {}
        targets = dict(data.get("targets") or {}) if isinstance(data, Mapping) else {}
        mine = dict(targets.get(t.id) or {})
        if s.per_service:
            per = dict(mine.get(s.name) or {}) if isinstance(mine.get(s.name), dict) else {}
            per.pop(sid, None) if not v else per.__setitem__(sid, v)
            mine[s.name] = per
        elif v:
            mine[s.name] = v
        else:
            mine.pop(s.name, None)
        targets[t.id] = mine
        lines.append(Store(self._settings_var(), lambda: self.login).put(json.dumps({"v": 1, "targets": targets},
                                                                                     sort_keys=True)))
        whose = f" for {sid}" if sid else ""
        said = f"{s.label}{whose} on {t.id} is {v}" if v else f"{s.label}{whose} on {t.id} is not set any more"
        return {"said": said, "ok": True, "lines": [x for x in lines if x]}

    def _settings_refusal(self, t: Target, sid: str = "") -> None:
        missing = self.unset_settings(t, sid)
        if missing:
            raise Refusal(f"set {', '.join(s.label for s in missing)} for {t.id}"
                          + (f" ({sid})" if any(s.per_service for s in missing) else "")
                          + f" on {self.title or self.name}'s page first: Liminal picks none of them for you")

    def service_reads_wanted(self) -> bool:
        """Whether its page's tables read its targets' services now: always by default. A subclass that can tell from
        what it read already that no service of Liminal's is there says False, and its page asks nothing more."""
        return True

    def _read_target(self, t: Target, rt: Runtime, volumes: bool = False) -> tuple[list, list]:
        """A target's services (and its volumes, when asked), as its runtime read them, kept READ_S."""
        now = self.out.clock()
        with self._svc.lock:
            kept = self._svc.reads.get(t.id)
        if kept is not None and now - kept[0] < C.READ_S and (not volumes or kept[2] is not None):
            return kept[1], kept[2] or []
        rows = rt.hosted()
        vols = rt.volumes() if volumes else None
        with self._svc.lock:
            self._svc.reads[t.id] = (now, rows, vols)
        return rows, vols or []

    def target(self, tid: str) -> Target:
        t = next((x for x in self.targets() if x.id == tid), None)
        if t is None:
            raise Refusal(f"{self.title or self.name} has no target {str(tid)[:40]!r}: "
                          + (", ".join(x.id for x in self.targets()) or "none here"))
        return t

    def grants(self) -> dict[str, list[str]]:
        try:
            data = json.loads(Store(self._grants_var(), lambda: self.login).text() or "{}")
        except (ValueError, Exception):  # noqa: BLE001 - nothing kept, or not readable: no grant
            return {}
        out = {}
        for plugin, targets in dict(data.get("grants") or {}).items():
            if isinstance(plugin, str) and isinstance(targets, list):
                out[plugin] = sorted(str(t) for t in targets if isinstance(t, str))
        return out

    def granted(self, plugin: str, target: str) -> bool:
        return target in self.grants().get(plugin, [])

    def grant_service(self, plugin, target) -> dict:
        """Lets that service plugin plan on that target (decision 3: once per plugin and target), from the page alone;
        kept through the login."""
        return self._grant(plugin, target, True)

    def revoke_service(self, plugin, target) -> dict:
        """Stops letting it: its services stay as they are (decision 3)."""
        return self._grant(plugin, target, False)

    def _grant(self, plugin, target, on: bool) -> dict:
        self._need_page(C.GRANT if on else C.REVOKE)
        name, tid = str(plugin or "").strip(), str(target or "").strip()
        if not C.NAME.match(name):
            raise Refusal(f"not a service plugin's name: {name[:40]!r}")
        if on:
            self.target(tid)
        g = self.grants()
        now = set(g.get(name, []))
        now = now | {tid} if on else now - {tid}
        if now:
            g[name] = sorted(now)
        else:
            g.pop(name, None)
        where = Store(self._grants_var(), lambda: self.login).put(json.dumps({"v": 1, "grants": g}, sort_keys=True))
        said = (f"{name} may run its services on {tid}" if on else
                f"{name} may no longer plan on {tid}: its services there stay as they are")
        return {"said": said, "ok": True, "lines": [where]}

    # -- reads --------------------------------------------------------------------------------------------------------
    def _rows(self, owner: str = "") -> list[dict]:
        """Every service on every ready target, as its runtime reads it, with what the base adds: its ports' here and
        lan words, whether this platform made it, its volumes."""
        out = []
        mine = self._platform()
        for t in self.targets():
            if not t.ready:
                continue
            try:
                rt = self.runtime_of(t)
                rows, _ = self._read_target(t, rt)
            except Exception:  # noqa: BLE001 - a target that cannot be read now lists nothing
                continue
            for r in rows:
                if owner and not str(r.get("sid", "")).startswith(owner + "/"):
                    continue
                out.append(self._hosted_row(t, rt, r, mine))
        return out

    def _hosted_row(self, t: Target, rt: Runtime, r: dict, mine: str) -> dict:
        try:
            spec = ServiceSpec.of(r.get("spec") or {})
        except Refusal:
            spec = None
        current = [p for p in r.get("parts") or [] if p.get("role", "current") == "current"]
        previous = [p for p in r.get("parts") or [] if p.get("role") == "previous"]
        states = [str(p.get("state")) for p in current]
        if not current:
            state = "missing"
        elif all(s == "running" for s in states):
            state = "unhealthy" if any(p.get("health") == "unhealthy" for p in current) else "running"
        elif any(s in ("running", "restarting", "created") for s in states):
            state = "starting"
        else:
            state = "stopped"
        ports = []
        for p in (spec.ports() if spec else []):
            path, words = rt.lan(p.host, p.protocol) if p.lan else ("none", "on this machine alone")
            ports.append({"name": p.name, "host": p.host, "container": p.container, "protocol": p.protocol,
                          "bind": "every address" if p.lan else "this machine", "lan": p.lan,
                          "here": f"http://{rt.here(p.host)}", "path": path, "lan_words": words})
        sid = str(r.get("sid", ""))
        owner, name = (sid.split("/", 1) + [""])[:2]
        exits = [f"{p.get('name')} exited with {p.get('exit')}" for p in current if p.get("state") == "exited"
                 and p.get("exit") not in (None, 0)]
        return {"sid": sid, "owner": owner, "name": name, "title": spec.title if spec else sid,
                "plugin": self.name, "target": t.id, "state": state, "why": "; ".join(exits),
                "lifecycle": r.get("lifecycle", "page"), "platform": r.get("platform", ""),
                "mine": r.get("platform", "") == mine, "made": r.get("made", ""), "spec": r.get("spec_sha", ""),
                "drift": "" if not spec or not current or all(p.get("digest") in ("", None, (spec.part(p.get("name")) or
                                                                                    spec.parts[0]).image.digest)
                                                             for p in current) else "a container runs another image",
                "parts": current, "ports": ports,
                "volumes": [{"name": v.name, "volume": C.volume_name(sid, v.name), "path": v.path, "holds": v.holds,
                             "where": t.where_data} for v in (spec.volumes() if spec else [])],
                "previous": {"parts": previous} if previous else None,
                "work": next((w.work for w in self._svc.works.running() if w.sid == sid), None)}

    def hosting(self, owner: str = "", specs=None) -> dict:
        """Its targets, each with its fit for the asker's spec of that target's system (`specs`: {"linux": ...,
        "windows": ...}), and Liminal's services it hosts (the owner's alone, when named). Kept READ_S; starts
        nothing. Who asked is noted for its Service plugins table."""
        who = asking.asker()
        if who and who != asking.PAGE:
            with self._svc.lock:
                self._svc.askers.add(who)
        parsed = {}
        for system, raw in dict(specs or {}).items():
            if system in C.SYSTEMS and raw:
                parsed[system] = ServiceSpec.of(raw)
        g = self.grants()
        out = []
        for t in self.targets():
            row = t.as_dict()
            row["granted"] = sorted(p for p, ts in g.items() if t.id in ts)
            spec = parsed.get(t.system)
            if spec is not None:
                row["fit"] = self._fit(t, spec).as_dict()
            else:
                try:
                    said = self.no_spec_fit(t, who if who and who != asking.PAGE else str(owner or ""))
                except Exception:  # noqa: BLE001 - not said: none
                    said = None
                row["fit"] = said.as_dict() if isinstance(said, Fit) else None
            try:
                unset = self.unset_settings(t)
                row["settings"] = [{**s.as_dict(), "value": self.setting_value(t.id, s.name)}
                                   for s in self.target_settings(t)]
            except Exception:  # noqa: BLE001 - not read: none said
                unset, row["settings"] = [], []
            row["unset"] = [s.label for s in unset]
            out.append(row)
        return {"plugin": self.name, "title": self.title or self.name, "runtime": self.RUNTIME, "targets": out,
                "services": self._rows(owner)}

    def _fit(self, t: Target, spec: ServiceSpec | None) -> Fit:
        """The runtime's fit, with what the base knows besides: a target that is not here or not ready, and a WSL
        distribution its plugin cannot hold up yet."""
        if not t.here:
            return Fit({"target": Aspect("cannot", t.why or "it is not on this machine: its data would live there")},
                       t.why or "it is not on this machine")
        try:
            fit = self.runtime_of(t).fit(spec) if t.ready else Fit()
        except Exception as e:  # noqa: BLE001 - a fit that cannot be read: not offered, in words
            return Fit({"target": Aspect("cannot", str(e)[:200])}, str(e)[:200])
        parts = dict(fit.parts)
        if t.wsl and not self._wsl_holds(t):
            parts["lifecycle"] = (Aspect("differs", f"{t.wsl} cannot be held up while the service runs (its "
                                                            "WSL plugin has no hold yet): it may stop when nothing "
                                                            "else keeps it running"))
        return Fit.judged(parts)

    def _wsl_holds(self, t: Target) -> bool:
        if not t.wsl:
            return True
        app = self.app
        try:
            face = (app.plugins() or {}).get(t.wsl_plugin) if app is not None and getattr(t, "wsl_plugin", "") else None
        except Exception:  # noqa: BLE001 - an app that cannot list its plugins: no hold
            face = None
        hooks = (face or {}).get("hooks") or [] if isinstance(face, Mapping) else []
        return C.HOLD in hooks and C.LET_GO in hooks

    def hosted(self, sid: str) -> dict:
        """One service as its runtime reads it, by its labels."""
        C.split_sid(sid)
        row = next((r for r in self._rows() if r["sid"] == sid), None)
        if row is None:
            return {"sid": sid, "plugin": self.name, "state": "missing",
                    "why": f"no container of {sid} is on a target of {self.title or self.name} that answers now"}
        return row

    def hosted_logs(self, sid: str, part: str = "", lines: int = 100) -> dict:
        """Its last 1 to LOG_MOST lines, output and errors in the order written, the spec's secrets masked. Asked by
        the page or the service's owner alone (a log may hold what the software prints itself)."""
        owner, _ = C.split_sid(sid)
        self._page_or(C.HOSTED_LOGS, owner)
        try:
            n = int(lines)
        except (TypeError, ValueError):
            raise Refusal(f"lines is a whole number, not {lines!r}") from None
        if not 1 <= n <= C.LOG_MOST:
            raise Refusal(f"a log is read 1 to {C.LOG_MOST:,} lines at a time")
        t, rt, row, spec = self._found(sid)
        pick = part or (spec.parts[0].name if spec else "")
        if spec is not None and spec.part(pick) is None:
            raise Refusal(f"{sid} has no part {pick[:20]!r}")
        if spec is not None:
            self._read_secrets(spec)
        got = [self._mask(line) for line in rt.logs(C.container_name(sid, pick), n)][-n:]
        return {"sid": sid, "part": pick, "lines": got}

    def exposures(self) -> dict:
        """What Liminal's services here publish beyond this machine, running or not: one Exposure each."""
        out = []
        for r in self._rows():
            lan = [p for p in r["ports"] if p["lan"]]
            if not lan:
                continue
            for proto in sorted({p["protocol"] for p in lan}):
                ps = [p for p in lan if p["protocol"] == proto]
                t = next((x for x in self.targets() if x.id == r["target"]), None)
                out.append({"rule": C.rule_name(r["sid"]), "ports": [p["host"] for p in ps], "protocol": proto,
                            "remote": "lan", "system": t.firewall if t else "", "path": ps[0]["path"],
                            "past_firewall": False, "sid": r["sid"], "title": r["title"], "plugin": self.name,
                            "target": r["target"], "running": r["state"] == "running", "words": ps[0]["lan_words"]})
        return {"exposures": out}

    def segments(self, sid: str = "", fresh: bool = False) -> dict:
        """Its segments on its own targets, Liminal's and the engines' own, each with its members. Starts nothing."""
        out = []
        for t in self.targets(fresh=bool(fresh)):
            if not t.ready:
                continue
            try:
                for s in self.runtime_of(t).segments():
                    if not sid or s.get("sid") == sid:
                        out.append({**s, "plugin": self.name, "target": t.id, "stack": t.stack})
            except Exception:  # noqa: BLE001 - a target that cannot be read lists no segment
                continue
        return {"segments": out}

    APPROVE_ARGS = (ACCEPT_LAN, ACCEPT_KEPT_SECRET, ACCEPT_DIFFERS, C.ACCEPT_BOOT, ACCEPT_NO_BACKUP, ACCEPT_DATA)

    def plan_words(self, plan: str) -> dict:
        """What the approval draws: its title, words and steps, the accepts it needs in turn, whether it is approved,
        when it expires; and `approve_args`, approve_plan's accepts in the order it takes them (the page's dialog sends
        them so). Asked by the page or the plan's owner."""
        p = self._svc.plans.get(plan)
        self._page_or(C.PLAN_WORDS, p.owner)
        return {**p.as_dict(self.out.clock()), "approve_args": [*self.APPROVE_ARGS, *self.MORE_ACCEPTS],
                "plugin": self.name}

    def service_work(self, work: str, after: int = 0) -> dict:
        """A work's lines after `after`, whether it is done, and its answer: asked by the plan's owner alone."""
        w = self._svc.works.get(work)
        self._need_owner(C.WORK, w.owner)
        return w.page(after)

    def service_cancel(self, work: str) -> dict:
        """Asks a work to stop between its steps (a pull's child is ended): from the page or the owner."""
        w = self._svc.works.get(work)
        self._page_or(C.CANCEL, w.owner)
        w.cancel.set()
        for n in (w.plan.extra.get("network") or []):
            if n.get("work"):
                try:
                    self.ask_plugin(n["plugin"], NET_CANCEL, n["work"])
                except Exception:  # noqa: BLE001 - its own work ends with its step
                    pass
        return {"said": "asked to stop between its steps", "ok": True}

    # -- finding a service -------------------------------------------------------------------------------------------
    def _found(self, sid: str):
        """(target, runtime, its row, its spec as labelled) of a service hosted here; a Refusal when none is."""
        for t in self.targets():
            if not t.ready:
                continue
            try:
                rt = self.runtime_of(t)
                rows = rt.hosted()
            except Exception:  # noqa: BLE001 - not read now
                continue
            for r in rows:
                if r.get("sid") == sid:
                    try:
                        spec = ServiceSpec.of(r.get("spec") or {})
                    except Refusal:
                        spec = None
                    return t, rt, r, spec
        raise Refusal(f"{sid} is not hosted on a target of {self.title or self.name} that answers now")

    def _data_target(self, sid: str, given: str = "") -> Target:
        """The target that keeps a service's volumes (its containers may be gone): a Refusal when none does."""
        for t in self.targets():
            if not t.ready or (given and t.id != given):
                continue
            try:
                if self._volumes_of(self.runtime_of(t), sid):
                    return t
            except Exception:  # noqa: BLE001 - not read now
                continue
        raise Refusal(f"no target of {self.title or self.name} that answers now keeps {sid}'s data")

    def _volumes_of(self, rt: Runtime, sid: str) -> list[dict]:
        return [v for v in rt.volumes() if v.get("sid") == sid]

    # -- the plan -----------------------------------------------------------------------------------------------------
    def service_plan(self, action: str, sid: str, spec=None, target: str = "", options=None) -> dict:
        """A plan of `action` for the service `sid`, in this plugin's words, held for your approval; or one whose
        `refused` says why it cannot be done. Changes nothing on an engine. Asked by the service's own plugin alone."""
        owner, name = C.split_sid(sid)
        who = self._need_owner(C.PLAN, owner)
        act = str(action or "")
        if act not in C.ACTIONS:
            raise Refusal(f"a service is planned for one of {', '.join(C.ACTIONS)}, not {act[:20]!r}")
        if act == "boot":
            raise Refusal(C.SERVICE_MODE_WORDS)
        opts = dict(options or {})
        if not all(isinstance(k, str) for k in opts) or len(json.dumps(opts, default=str)) > 4096:
            raise Refusal("options are a small object of plain words")
        new_spec = ServiceSpec.of(spec) if spec is not None else None
        if new_spec is not None and (new_spec.owner != who or new_spec.sid != sid):
            raise Refusal(f"the spec is {new_spec.sid}'s, and {who} asked for {sid}")
        if act in ("install", "update") and new_spec is None:
            raise Refusal(f"{act} needs the service's spec")
        if act == "install":
            t = self.target(str(target or ""))
            existing = None
            try:
                existing = self._found(sid)
            except Refusal:
                existing = None
            if existing is not None:
                raise Refusal(f"{sid} is hosted already on {existing[0].id}: plan a change of it instead")
        elif act == "delete_data":
            t = self._data_target(sid, str(target or ""))
            new_spec = None
        else:
            t, rt0, row0, labelled = self._found(sid)
            if target and target != t.id:
                raise Refusal(f"{sid} is hosted on {t.id}, not {target}")
            if row0.get("platform") and row0.get("platform") != self._platform():
                raise Refusal(f"{sid} was made by the platform {row0.get('platform')}: only that platform changes it")
            if act == "update":
                if labelled is not None and new_spec is not None and new_spec.system != labelled.system:
                    raise Refusal("an update keeps its system")
                if labelled is not None and new_spec is not None:
                    opts = {**opts, **self._parts_added(sid, labelled, new_spec)}
            elif act == "expose":
                lan = opts.get("lan")
                if not isinstance(lan, bool):
                    raise Refusal("expose takes options {\"lan\": true} to open it to your network, false to close it")
                base = new_spec or labelled
                if base is None:
                    raise Refusal(f"{sid}'s spec cannot be read back from its labels: plan a remove and an install")
                new_spec = replace(base, parts=tuple(replace(p, ports=tuple(replace(x, lan=lan) for x in p.ports))
                                                     for p in base.parts))
            else:
                new_spec = labelled
            if new_spec is None and act not in ("remove", "delete_data", "stop"):
                raise Refusal(f"{sid}'s spec cannot be read back from its labels")
        if not t.here:
            raise Refusal(f"{t.id} is not on this machine: only this machine's engines host services (its data would "
                          "live there)")
        if not t.ready:
            raise Refusal(f"{t.title} is {t.state}: {t.why or 'not ready'}. Nothing here starts it: start it on its "
                          "own page" + (f" ({t.wsl}'s WSL plugin)" if t.wsl else ""))
        self._settings_refusal(t, sid)
        if not self.granted(who, t.id):
            raise Refusal(f"{who} may not plan on {t.id} yet: let it on {self.title or self.name}'s page first "
                          "(Service plugins, Let it…)")
        rt = self.runtime_of(t)
        return self._planned(act, sid, who, t, rt, new_spec, opts)

    def _parts_added(self, sid: str, labelled: ServiceSpec, new: ServiceSpec) -> dict:
        """1.95.0: an update's parts against those it runs: {} for a plain update; {"adds": [names]} for one that adds
        a part and changes no other (its own plan); refused for one that drops a part, or adds one and changes another
        too (two plans)."""
        had = {p.name: p for p in labelled.parts}
        now = {p.name: p for p in new.parts}
        dropped = [n for n in had if n not in now]
        if dropped:
            raise Refusal(f"an update keeps every part of {sid}: {', '.join(dropped)} would be left behind (Remove… and "
                          "Install… again to run it without)")
        added = [n for n in now if n not in had]
        if not added:
            return {}
        changed = [n for n, p in had.items() if not C.same_part(p, now[n])]
        if changed:
            raise Refusal(f"an update that adds {', '.join(added)} to {sid} changes no other part: update "
                          f"{', '.join(changed)} first (its own plan), then add {', '.join(added)}")
        if [p.name for p in new.parts][:len(had)] != [p.name for p in labelled.parts]:
            raise Refusal(f"a part added to {sid} comes after its parts, in their order")
        return {"adds": added}

    def _planned(self, act: str, sid: str, who: str, t: Target, rt: Runtime, spec: ServiceSpec | None,
                 opts: dict) -> dict:
        accepts: list[Accept] = []
        steps: list[str] = []
        keeps: list[str] = []
        loses: list[str] = []
        danger = False
        fit = self._fit(t, spec) if spec is not None and act in ("install", "update", "expose") else Fit()
        if fit.takes:
            raise Refusal(f"{t.title} cannot take {sid}: {fit.takes}")
        if fit.differs():
            accepts.append(Accept(ACCEPT_DIFFERS, "Done differently: accept it?", "; ".join(fit.differs()),
                                  "Accept the difference"))
        facts = rt.facts(spec, sid)
        facts["target"] = {"id": t.id, "state": t.state}
        lan_words = []
        adds = list(opts.get("adds") or []) if act == "update" else []
        new_parts = [p for p in spec.parts if p.name in adds] if spec is not None else []
        if spec is not None and act in ("install", "update", "expose"):
            self._check_ports(sid, spec, t, act)
            self._check_secrets(spec, who)
            self._check_sizes(t, sid, spec)
            secrets = [s for p in new_parts for s in p.secrets] if adds else spec.secrets()
            if secrets:
                accepts.append(Accept(ACCEPT_KEPT_SECRET, "A secret kept by the engine: accept it?",
                                      self._secret_words(t, rt, spec), "Accept"))
            lan_new = [x for p in new_parts for x in p.ports if x.lan]
            if (spec.lan_ports() and act != "update") or lan_new:
                opened = lan_new if adds else [p for p in spec.lan_ports()]
                fw = self._lan_open_words(opened)
                for p in opened:
                    path, words = rt.lan(p.host, p.protocol)
                    lan_words.append(f"{p.protocol.upper()} {p.host} ({p.about or p.name}): {words}"
                                     + (f"; the firewall: {fw.get(str(p.host))}" if fw.get(str(p.host)) else ""))
                if act in ("install", "expose") or lan_new:
                    accepts.append(Accept(ACCEPT_LAN, "Published to your network: accept it?",
                                          "Published on every address: " + "; ".join(lan_words)
                                          + ". Plain http crosses your network in the clear.", "Publish it"))
        title = f"{act.replace('_', ' ').capitalize()} {spec.title if spec else sid} ({sid.split('/', 1)[1]}) in " \
                f"{self.title or self.name} on {t.id}"
        if act == "install":
            steps, keeps = self._install_words(sid, t, rt, spec, facts)
        elif act == "start":
            steps = [f"start {C.container_name(sid, p.name)}" for p in spec.parts] if spec else []
            if t.wsl:
                steps.append(f"keep {t.wsl} running while it runs (its WSL plugin holds it)")
        elif act == "stop":
            parts = spec.parts if spec else ()
            steps = [f"stop {C.container_name(sid, p.name)}: it is given {p.stop_s} s to end on its own" for p in parts]
        elif act == "restart":
            steps = [f"stop, then start {C.container_name(sid, p.name)}" for p in spec.parts]
        elif act == "update" and adds:
            title = (f"Add {', '.join(adds)} to {spec.title} ({sid.split('/', 1)[1]}) in {self.title or self.name} on "
                     f"{t.id}")
            steps, keeps = self._add_words(sid, t, rt, spec, adds, facts)
        elif act == "update":
            steps, keeps, loses, need_no_backup = self._update_words(sid, t, rt, spec, facts)
            if need_no_backup:
                accepts.append(Accept(ACCEPT_NO_BACKUP, "No backup can be made: update anyway?",
                                      "its image has no tar, so its data is not backed up before the update: going "
                                      "back may not be possible", "Update without a backup"))
        elif act == "rollback":
            choice = str(opts.get("choice", "as-is"))
            if choice not in ("as-is", "backup"):
                raise Refusal("a rollback is on the data as it is (as-is) or with the update's backup put back (backup)")
            if not any(c.get("role") == "previous" for c in facts.get("containers", {}).values()):
                raise Refusal(f"{sid} has no previous container to go back to")
            names = set(facts.get("containers", {}))
            lacking = [p.name for p in (spec.parts if spec else ()) if C.previous_name(sid, p.name) not in names]
            if lacking:
                raise Refusal(f"{sid}'s {', '.join(lacking)} has no previous container (added after its last update): "
                              "a rollback goes back with every part or not at all")
            steps = ["stop and remove the current container", "name the previous one back and start it"]
            if choice == "backup":
                latest = self._latest_backup(sid)
                if latest is None:
                    raise Refusal(f"{sid} has no backup to put back")
                steps.insert(1, f"put back the backup of {latest.name}")
                loses.append("what was written since that backup")
                accepts.append(Accept(ACCEPT_DATA, "Put the backup back?", f"the data goes back to {latest.name}: what "
                                      "was written since is lost", "Put it back"))
                danger = True
                facts["backup"] = latest.name
        elif act == "expose":
            steps = ["stop it, make its container again with its ports " + ("on every address" if opts["lan"] else
                     "on this machine alone") + ", and start it again (a short restart)"]
        elif act == "remove":
            names = sorted(facts.get("containers", {}))
            if not names:
                raise Refusal(f"{sid} has no container to remove")
            steps = [f"stop and remove {n}" for n in names] + ["remove its network"]
            vols = self._volumes_of(rt, sid)
            keeps = [f"the volume {v['name']} ({v.get('size') or 'its size not read'}): Install… uses it again"
                     for v in vols] + ["its image", "its backups"]
        elif act == "delete_data":
            if facts.get("containers"):
                raise Refusal(f"{sid}'s containers still use its volumes: plan its Remove first")
            vols = self._volumes_of(rt, sid)
            if not vols:
                raise Refusal(f"{sid} keeps no volume on {t.id}")
            backups = str(opts.get("backups", "keep"))
            if backups not in ("keep", "delete"):
                raise Refusal("its backups are kept (keep) or deleted with it (delete)")
            steps = [f"delete the volume {v['name']} ({v.get('size') or 'its size not read'})" for v in vols]
            loses = [f"{v['name']}: everything it holds" for v in vols]
            if backups == "delete":
                steps.append(f"delete its backups in {self._backups_of(sid)}")
                loses.append("its backups")
            else:
                keeps.append(f"its backups in {self._backups_of(sid)}")
            accepts.append(Accept(ACCEPT_DATA, "Delete its data?", "; ".join(loses) + ": this cannot be undone",
                                  "Delete it"))
            danger = True
        if act in NET_ACTIONS or adds:
            network = self._network_plans(act, sid, who, t, spec, opts, rt)
        else:
            network = []
        facts["network"] = [n["plan"] for n in network]
        accepts += self._more_accepts(act, sid, t, rt, spec, facts)
        words = self._words(title, steps, keeps, loses, lan_words, t, network, rt)
        plan = self._svc.plans.hold(owner=who, action=act, subject=sid, target=t.id, title=title, words=words,
                                    facts=facts, steps=steps, accepts=accepts, danger=danger,
                                    bound=digest({"spec": spec.sha() if spec else "", "options": opts}),
                                    extra={"keeps": keeps, "loses": loses, "lan": lan_words, "network": network,
                                           "fit": fit.as_dict(), "spec": spec.as_dict() if spec else None,
                                           "options": opts})
        out = plan.as_dict(self.out.clock())
        out["approve"] = [{"plugin": self.name, "plan": plan.plan}] + [
            {"plugin": n["plugin"], "plan": n["plan"]} for n in network if n.get("plan") and not n.get("narrows")]
        return out

    def _words(self, title, steps, keeps, loses, lan_words, t: Target, network, rt: Runtime | None = None) -> str:
        said = [f"{title}?"] + [s[0].upper() + s[1:] + "." for s in steps if s]
        if keeps:
            said.append("It keeps " + "; ".join(keeps) + ".")
        if loses:
            said.append("It loses " + "; ".join(loses) + ".")
        root = ""
        try:
            root = str(rt.data_root() or "") if rt is not None else ""
        except Exception:  # noqa: BLE001 - not read: the target's own words alone
            root = ""
        if t.where_data or root:
            said.append(f"Its data lives {t.where_data or 'on its engine'}" + (f" ({root})" if root else "") + ".")
        for n in network:
            said.append(f"{n.get('title') or n['plugin']}: {n.get('words') or ''}")
        said.append("It starts and stops with the platform; nothing restarts it after a crash.")
        return " ".join(said)

    def _install_words(self, sid, t: Target, rt: Runtime, spec: ServiceSpec, facts: dict):
        steps, keeps = [], []
        images = facts.get("images", {})
        for p in spec.parts:
            pin = p.image
            size = f"{pin.size / 1e6:,.0f} MB" if pin.size else "its size not pinned"
            here = "on this engine already" if images.get(pin.digest) else "not on this engine yet"
            steps.append(f"pull {pin.pinned} ({size}{', ' + pin.licence if pin.licence else ''}; {here})")
        found = {v["volume"]: v for v in self._volumes_of(rt, sid)}
        for v in spec.volumes():
            name = C.volume_name(sid, v.name)
            if v.name in found:
                was = found[v.name]
                steps.append(f"use the volume {name} from before ({was.get('size') or 'its size not read'}, made "
                             f"{was.get('made') or 'when not known'}): {v.holds}")
            else:
                steps.append(f"make the volume {name}, new: {v.holds}")
        for p in spec.parts:
            ports = ", ".join(f"{x.protocol.upper()} {x.host} on " + ("every address" if x.lan else "this machine")
                              for x in p.ports) or "no port"
            steps.append(f"create {C.container_name(sid, p.name)}: at most {p.memory >> 20:,} MB of memory, {ports}, "
                         "--restart no")
        if t.wsl:
            steps.append(f"start it, and keep {t.wsl} running while it runs (its WSL plugin holds it)")
        else:
            steps.append("start it, and wait for it to answer")
        return steps, keeps

    def _add_words(self, sid, t: Target, rt: Runtime, spec: ServiceSpec, adds: list, facts: dict):
        """An update that adds parts: what is pulled, made and started; nothing it ran before is stopped."""
        steps, keeps = [], []
        images = facts.get("images", {})
        found = {v["volume"]: v for v in self._volumes_of(rt, sid)}
        for p in spec.parts:
            if p.name not in adds:
                continue
            pin = p.image
            size = f"{pin.size / 1e6:,.0f} MB" if pin.size else "its size not pinned"
            here = "on this engine already" if images.get(pin.digest) else "not on this engine yet"
            steps.append(f"pull {pin.pinned} ({size}{', ' + pin.licence if pin.licence else ''}; {here})")
            for v in p.volumes:
                name = C.volume_name(sid, v.name)
                steps.append(f"use the volume {name} from before: {v.holds}" if v.name in found else
                             f"make the volume {name}, new: {v.holds}")
            ports = ", ".join(f"{x.protocol.upper()} {x.host} on " + ("every address" if x.lan else "this machine")
                              for x in p.ports) or "no port"
            steps.append(f"create {C.container_name(sid, p.name)} on {sid}'s network: at most {p.memory >> 20:,} MB of "
                         f"memory, {ports}, --restart no")
            steps.append(f"start {C.container_name(sid, p.name)}, and wait for it")
        keeps = [f"{C.container_name(sid, p.name)} as it runs: it is not stopped" for p in spec.parts
                 if p.name not in adds]
        return steps, keeps

    def _backup_kinds(self, rt: Runtime, spec: ServiceSpec) -> dict:
        """Each part's backup kind (Runtime.backup_kind), "tar" where the runtime cannot say."""
        out = {}
        for p in spec.parts:
            try:
                kind = str(rt.backup_kind(p) or "tar")
            except Exception:  # noqa: BLE001 - not said: the base's own
                kind = "tar"
            out[p.name] = kind if kind in C.BACKUP_KINDS else "tar"
        return out

    def _update_words(self, sid, t, rt, spec: ServiceSpec, facts):
        steps, keeps, loses = [], [], []
        kinds = self._backup_kinds(rt, spec)
        no_tar = [p for p in spec.parts if p.volumes and (kinds[p.name] == "none" or
                                                          (kinds[p.name] == "tar" and not p.image.tar))]
        for p in spec.parts:
            for v in p.volumes:
                if no_tar:
                    steps.append(f"no backup of {C.volume_name(sid, v.name)} ("
                                 + ("its engine makes none" if kinds[p.name] == "none" else "its image has no tar") + ")")
                elif kinds[p.name] == "snapshot":
                    steps.append(f"snapshot the volume {C.volume_name(sid, v.name)} (its engine's own; noted in "
                                 f"{self._backups_of(sid)})")
                else:
                    steps.append(f"back up the volume {C.volume_name(sid, v.name)} into {self._backups_of(sid)}")
        for p in spec.parts:
            steps.append(f"pull {p.image.pinned}" + (f" ({p.image.size / 1e6:,.0f} MB)" if p.image.size else ""))
        steps += ["stop it, and keep the current container as …-previous", "make a new container on the same volumes "
                  "and choices, start it, and wait for it: undone if it is not healthy in time"]
        keeps = ["the previous container and its image, until the next update or Remove",
                 f"the last {C.BACKUPS_KEPT} backups (a backup holds whatever the service keeps, its own secrets too)"]
        loses = ["a newer version may convert its data on its first start: going back may need the backup"]
        return steps, keeps, loses, bool(no_tar)

    def _secret_words(self, t: Target, rt: Runtime, spec: ServiceSpec) -> str:
        """accept_kept_secret's words: its runtime's (Runtime.kept_secret_words), else the plugin's own
        _kept_secret_words."""
        try:
            said = str(rt.kept_secret_words(spec) or "")
        except Exception:  # noqa: BLE001 - not said: the plugin's own
            said = ""
        return said or self._kept_secret_words(t, spec)

    def more_accepts(self, act: str, sid: str, t: Target, rt: Runtime, spec: ServiceSpec | None,
                     facts: dict) -> list[Accept]:
        """1.95.0: its own second confirmations for this plan (each named in MORE_ACCEPTS): none by default."""
        return []

    def _more_accepts(self, act, sid, t, rt, spec, facts) -> list[Accept]:
        got = list(self.more_accepts(act, sid, t, rt, spec, facts) or [])
        for a in got:
            if a.name not in self.MORE_ACCEPTS or a.name in C.ACCEPTS or not C.MORE_ACCEPT.match(a.name):
                raise Refusal(f"{self.name} asks an accept it does not declare ({a.name[:40]}): MORE_ACCEPTS names "
                              "each of its own")
        return got

    def _kept_secret_words(self, t: Target, spec: ServiceSpec) -> str:
        names = ", ".join(f"{s.variable} (as {s.env})" for s in spec.secrets())
        return (f"{names}: handed to the container by environment alone; the engine keeps it in the container's "
                "settings, which anyone who may use the engine can read (docker inspect)")

    # -- the plan's checks ---------------------------------------------------------------------------------------------
    def _check_ports(self, sid: str, spec: ServiceSpec, t: Target, act: str) -> None:
        from . import firewall

        apps = {p: a for a, p in firewall.app_ports(self.out.env).items()}
        taken = self._other_ports(sid)
        ranges = []
        try:
            ranges = list(self.excluded_ranges())
        except Exception:  # noqa: BLE001 - not readable: nothing excluded is known
            ranges = []
        for p in spec.ports():
            if not C.PORTS[0] <= p.host <= C.PORTS[1]:
                raise Refusal(f"port {p.host} is outside {C.PORTS[0]} to {C.PORTS[1]}")
            if p.host in apps:
                raise Refusal(f"port {p.host} is Liminal's {apps[p.host]} page")
            if p.host in C.SUITE_PORTS:
                raise Refusal(f"port {p.host} is one of the Linux suite's pages (9765 to 9795)")
            if (p.host, p.protocol) in taken:
                raise Refusal(f"port {p.host} is {taken[(p.host, p.protocol)]}'s")
            for lo, hi in ranges:
                if lo <= p.host <= hi:
                    raise Refusal(f"port {p.host} is inside {lo} to {hi}, a range Windows keeps for Hyper-V and WSL: "
                                  "pick another")
            if act == "install" and self.out.holders is not None:
                held = [h for h in (self.out.holders(p.host) or []) if h]
                if held:
                    raise Refusal(f"port {p.host} is held here by {'; '.join(str(h) for h in held[:3])}"
                                  + (": WSL's relay could not bring the service to 127.0.0.1" if t.wsl else ""))

    def _other_ports(self, sid: str) -> dict:
        """The ports other Liminal services publish (on this plugin's targets and the other container plugins') and the
        model servers serve: {(port, protocol): whose}."""
        out: dict = {}
        for r in self._rows():
            if r["sid"] != sid:
                for p in r["ports"]:
                    out[(p["host"], p["protocol"])] = f"the service {r['sid']} on {r['target']}"
        for name, answer, _e in self.ask_others(C.HOSTING):
            if isinstance(answer, Mapping):
                for r in answer.get("services") or []:
                    if r.get("sid") != sid:
                        for p in r.get("ports") or []:
                            out[(p.get("host"), p.get("protocol", "tcp"))] = f"{name}'s service {r.get('sid')}"
        for name, answer, _e in self.ask_others(C.SERVING):
            if isinstance(answer, Mapping):
                for row in answer.get("instances") or []:
                    port = row.get("port")
                    if isinstance(port, int) and row.get("local", True):
                        out[(port, "tcp")] = f"{answer.get('title') or name}'s model server {row.get('name', '')}"
        return out

    def _check_sizes(self, t: Target, sid: str, spec: ServiceSpec) -> None:
        """1.95.0: a volume's least against the size you set for it on this target (a "size" setting), when both say."""
        sizes = [s for s in self.target_settings(t) if s.kind == "size"]
        for s in sizes:
            v = self.setting_value(t.id, s.name, sid if s.per_service else "")
            if not v:
                continue
            have = C.size_bytes(v)
            for vol in spec.volumes():
                if vol.least and have < vol.least:
                    raise Refusal(f"{s.label} on {t.id} is {v}, and {sid}'s {vol.name} needs {vol.least >> 20:,} MiB at "
                                  "least: set a larger one on its page")

    def _check_secrets(self, spec: ServiceSpec, who: str) -> None:
        others = self._others_declare(who)
        values = []
        for s in spec.secrets():
            if s.variable in others:
                raise Refusal(f"the secret {s.variable} is {others[s.variable]}'s pair, not {who}'s")
            value = self._pair(s.variable)
            if not value:
                raise Refusal(f"{s.variable} is not set: set it on {who}'s page first")
            values.append(value)
        for part in spec.parts:
            for k, v in part.env.items():
                if any(val and val in v for val in values):
                    raise Refusal(f"the setting {k} holds a secret's value: a secret goes as a secret alone")
            for seed in part.seeds:
                if any(val and val in seed.text for val in values):
                    raise Refusal(f"the seed {seed.path} holds a secret's value: seed a hash, never the secret")

    def _others_declare(self, who: str = "") -> dict[str, str]:
        """The pairs other plugins declare among their keys: {variable: plugin}. The asker's own (`who`) are left out:
        a secret its own Settings set is its own to hand over (1.95.0; 1.93.0 refused it)."""
        out: dict[str, str] = {}
        app = self.app
        plugins = []
        try:
            known = getattr(app, "known_plugins", None) if app is not None else None
            plugins = list(known()) if callable(known) else []
        except Exception:  # noqa: BLE001 - an app that cannot say: nothing declared is known
            plugins = []
        for p in plugins:
            pname = str(getattr(p, "name", ""))
            if who and pname == who:
                continue
            for k in list(getattr(p, "keys", ()) or ()):
                for n in getattr(k, "names", (getattr(k, "name", ""),)):
                    if n:
                        out.setdefault(str(n), pname)
        return out

    def _pair(self, variable: str) -> str:
        try:
            value = (self.login.variables([variable]) or {}).get(variable, "") if self.login is not None else ""
        except Exception:  # noqa: BLE001 - a login that cannot be asked: not set
            value = ""
        self._keep_secret(value)
        return value or ""

    def _read_secrets(self, spec: ServiceSpec) -> dict[str, str]:
        return {s.env: self._pair(s.variable) for s in spec.secrets()}

    def _lan_open_words(self, ports: list[Port]) -> dict:
        out = {}
        for name, answer, _e in self.ask_others(C.LAN_OPEN, [p.host for p in ports], "tcp"):
            if isinstance(answer, Mapping):
                for port, said in dict(answer.get("ports") or {}).items():
                    if isinstance(said, Mapping):
                        out[str(port)] = f"{name}: {said.get('words') or said.get('state')}"
        return out

    def _firewall_for(self, stack: str) -> tuple[str, dict] | None:
        for name, answer, _e in self.ask_others(NETWORK_HOST):
            if isinstance(answer, Mapping) and (answer.get("own") == stack or stack in (answer.get("routes_to") or [])):
                return name, dict(answer)
        return None

    def _want(self, sid: str, t: Target, spec: ServiceSpec | None, act: str, opts: dict,
              rt: Runtime | None = None) -> dict:
        parts = [p.name for p in spec.parts] if spec else ["main"]
        adds = list(opts.get("adds") or []) if act == "update" else []
        lan_ports = [x for p in spec.parts if p.name in adds for x in p.ports if x.lan] if adds else (
            spec.lan_ports() if spec else [])
        ports = []
        part_of = {(x.name, x.host): q.name for q in spec.parts for x in q.ports} if spec else {}
        for p in lan_ports:
            # 1.96.0: the container's own port and its part too, where an Expose's proxy connects (its address)
            row = {"name": p.name, "host": p.host, "protocol": p.protocol, "container": p.container,
                   "part": part_of.get((p.name, p.host), "")}
            try:
                here = rt.here(p.host) if rt is not None else ""
            except Exception:  # noqa: BLE001 - not said
                here = ""
            if here and here != f"127.0.0.1:{p.host}":
                row["here"] = here  # 1.95.0: where this machine reaches it (a NodePort at its node's address)
            ports.append(row)
        lan = bool(ports) and (act != "expose" or bool(opts.get("lan")))
        want = {"stack": t.stack, "target": t.id, "network": C.network_name(sid), "parts": parts,
                "ports": ports, "lan": lan}
        want.update(self._net_want(rt, spec, sid))
        return want

    def _net_want(self, rt: Runtime | None, spec, sid: str) -> dict:
        """What the runtime says its engine has for the service's network (Runtime.network_want), its words only."""
        if rt is None:
            return {}
        try:
            got = dict(rt.network_want(spec, sid) or {})
        except Exception:  # noqa: BLE001 - not said: the service's own network
            got = {}
        return {k: got[k] for k in ("network", "found", "assigns", "shared", "route", "behind") if k in got}

    def _net_name(self, rt: Runtime, spec, sid: str) -> tuple[str, bool]:
        """(the network the service's containers join, whether it is the service's own: dropped with it)."""
        want = self._net_want(rt, spec, sid)
        name = str(want.get("network") or C.network_name(sid))
        return name, name == C.network_name(sid) and not want.get("shared")

    def _network_plans(self, act: str, sid: str, who: str, t: Target, spec, opts, rt: Runtime | None = None) -> list[dict]:
        """The firewall's plans this plan rests on (N2: two approvals). No firewall answering for the target's stack
        refuses (N12)."""
        fw = self._firewall_for(t.stack)
        if fw is None:
            raise Refusal(f"no firewall plugin routes and names {t.stack} segments now (N12: every service's network "
                          "goes through the firewall): turn on the firewall plugin for "
                          + ("Windows" if t.stack in ("windows", "wsl") else "Linux")
                          + " and let this plugin ask it on its Networks tab")
        net_act = "add" if act == "update" and opts.get("adds") else NET_ACTIONS[act]
        if act == "expose":
            net_act = "expose" if opts.get("lan") else "conceal"
        answer = self.ask_plugin(fw[0], NET_PLAN, net_act, sid, self._want(sid, t, spec, act, opts, rt))
        if not isinstance(answer, Mapping):
            raise Refusal(f"{fw[0]} answered no network plan")
        if answer.get("refused"):
            raise Refusal(f"{fw[0]}: {answer['refused']}")
        if answer.get("nothing") and not answer.get("plan"):
            return [{"plugin": fw[0], "plan": "", "nothing": answer["nothing"], "narrows": True,
                     "subnet": answer.get("subnet", ""), "gateway": answer.get("gateway", ""),
                     "addresses": dict(answer.get("addresses") or {}), "words": answer["nothing"]}]
        return [{"plugin": fw[0], "plan": str(answer.get("plan")), "narrows": bool(answer.get("narrows")),
                 "title": answer.get("title", ""), "words": answer.get("words", ""),
                 "subnet": answer.get("subnet", ""), "gateway": answer.get("gateway", ""),
                 "addresses": dict(answer.get("addresses") or {}), "names": list(answer.get("names") or [])}]

    # -- approve, decline, apply --------------------------------------------------------------------------------------
    def approve_plan(self, plan, accept_lan=False, accept_kept_secret=False, accept_differs=False, accept_boot=False,
                     accept_no_backup=False, accept_data=False, *more, **named) -> dict:
        """Your approval, from the page alone: refused, naming the accept it lacks, until every accept the plan needs
        is exactly True. Used once, until the plan expires. The plugin's own accepts (MORE_ACCEPTS) come after the
        base's, in that order (`more`), or by name."""
        self._need_page(C.APPROVE)
        unknown = [k for k in named if k not in self.MORE_ACCEPTS]
        if unknown or len(more) > len(self.MORE_ACCEPTS):
            raise Refusal(f"{self.name}'s approve_plan takes no {', '.join(unknown) or 'more accepts'}")
        answers = {ACCEPT_LAN: accept_lan, ACCEPT_KEPT_SECRET: accept_kept_secret, ACCEPT_DIFFERS: accept_differs,
                   C.ACCEPT_BOOT: accept_boot, ACCEPT_NO_BACKUP: accept_no_backup, ACCEPT_DATA: accept_data}
        answers.update(dict(zip(self.MORE_ACCEPTS, more)))
        answers.update(named)
        p = self._svc.plans.approve(plan, answers)
        return {"said": f"approved: {p.title}", "ok": True, "plan": p.plan}

    def decline_plan(self, plan) -> dict:
        """Forgets the plan, and the firewall's plans it rests on."""
        p = self._svc.plans.get(plan)
        self._page_or(C.DECLINE, p.owner)
        self._svc.plans.decline(plan)
        for n in p.extra.get("network") or []:
            if n.get("plan"):
                try:
                    self.ask_plugin(n["plugin"], C.DECLINE, n["plan"])
                except Exception:  # noqa: BLE001 - one that expired already
                    pass
        return {"said": f"declined: {p.title}", "ok": True}

    def apply_plan(self, plan) -> dict:
        """Begins an approved plan, once, as a work this plugin owns: {"work": id} at once. The firewall's plans it
        rests on must be approved first (asked before any runtime command); the facts are read again, and anything that
        differs refuses."""
        p = self._svc.plans.get(plan)
        who = self._need_owner(C.APPLY, p.owner)
        if not p.approved:
            raise Refusal(f"{p.title}: not approved yet: approve it on the page first")
        for n in p.extra.get("network") or []:
            if n.get("plan") and not n.get("narrows"):
                said = self.ask_plugin(n["plugin"], C.PLAN_WORDS, n["plan"])
                if not (isinstance(said, Mapping) and said.get("approved") is True):
                    raise Refusal(f"{n['plugin']}'s plan for its network is not approved yet: approve it too")
        t = self.target(p.target)
        if not t.ready:
            raise Refusal(f"{t.title} is {t.state} now: {t.why}")
        rt = self.runtime_of(t)
        spec = ServiceSpec.of(p.extra["spec"]) if p.extra.get("spec") else None
        taken: list[Plan] = []

        def ready() -> None:
            facts = rt.facts(spec, p.subject)
            facts["target"] = {"id": t.id, "state": t.state}
            facts["network"] = [n["plan"] for n in p.extra.get("network") or []]
            if p.extra.get("options", {}).get("choice") == "backup":
                latest = self._latest_backup(p.subject)
                facts["backup"] = latest.name if latest else ""
            taken.append(self._svc.plans.take(plan, who, facts))
        w = self._svc.works.begin(p, t.id, lambda work: self._carry(work, taken[0], t, rt), self._mask, ready)
        return {"work": w.work}

    # -- carrying it out ------------------------------------------------------------------------------------------------
    def _carry(self, work: Work, p: Plan, t: Target, rt: Runtime):
        try:
            return self._carry_out(work, p, t, rt)
        finally:
            self.forget_targets()  # what it changed is read anew

    def _carry_out(self, work: Work, p: Plan, t: Target, rt: Runtime):
        spec = ServiceSpec.of(p.extra["spec"]) if p.extra.get("spec") else None
        act, sid = p.action, p.subject
        work.line(p.title)
        if act == "install":
            return self._do_install(work, p, t, rt, spec)
        if act == "start":
            return self._do_start(work, p, t, rt, spec)
        if act == "stop":
            return self._do_stop(work, t, rt, spec, sid)
        if act == "restart":
            self._do_stop(work, t, rt, spec, sid)
            return self._do_start(work, p, t, rt, spec)
        if act == "update" and p.extra.get("options", {}).get("adds"):
            return self._do_add(work, p, t, rt, spec, list(p.extra["options"]["adds"]))
        if act == "update":
            return self._do_update(work, p, t, rt, spec)
        if act == "rollback":
            return self._do_rollback(work, p, t, rt)
        if act == "expose":
            return self._do_expose(work, p, t, rt, spec)
        if act == "remove":
            return self._do_remove(work, p, t, rt, sid)
        if act == "delete_data":
            return self._do_delete(work, p, t, rt, sid)
        raise Refusal(f"{act} is not carried out here")

    def _apply_network(self, work: Work, p: Plan) -> None:
        for n in p.extra.get("network") or []:
            if not n.get("plan"):
                continue
            work.check()
            started = self.ask_plugin(n["plugin"], APPLY_NET, n["plan"])
            nid = str((started or {}).get("work", ""))
            n["work"] = nid
            after = 0
            while True:
                page = self.ask_plugin(n["plugin"], NET_WORK, nid, after)
                for line in page.get("lines") or []:
                    work.line(f"{n['plugin']}: {line}")
                after = int(page.get("next") or after)
                if page.get("done"):
                    if page.get("ok") is False:
                        raise Refusal(f"{n['plugin']}: {(page.get('answer') or {}).get('said') or 'its step failed'}")
                    break
                if work.cancelled():
                    try:
                        self.ask_plugin(n["plugin"], NET_CANCEL, nid)
                    except Exception:  # noqa: BLE001 - its step ends on its own
                        pass
                self.out.sleep(FOLLOW_S)

    def _grant_of(self, p: Plan) -> dict:
        n = next((x for x in p.extra.get("network") or [] if x.get("subnet")), None)
        return dict(n) if n else {}

    def _create(self, t: Target, rt: Runtime, sid: str, spec: ServiceSpec, part: Part, grant: dict, role: str,
                name: str | None = None) -> str:
        cname = name or C.container_name(sid, part.name)
        labels = C.labels(spec, part.name, role, self._platform(), self._now())
        secret_env = self._read_secrets(replace(spec, parts=(part,)))
        missing = [s.variable for s in part.secrets if not secret_env.get(s.env)]
        if missing:
            raise Refusal(f"{', '.join(missing)} is not set any more: set it on {spec.owner}'s page")
        from .segments import aliases_for

        first = spec.parts[0].name == part.name
        rt.create(Create(cname, part, labels, tuple((C.volume_name(sid, v.name), v.path) for v in part.volumes),
                         tuple(part.ports), dict(part.env), secret_env, self._net_name(rt, spec, sid)[0],
                         str((grant.get("addresses") or {}).get(part.name, "")), part.hostname or part.name,
                         tuple(aliases_for(sid, part.name, first)) if grant else (), (), "no"))
        return cname

    def _wait_healthy(self, work: Work, t: Target, rt: Runtime, spec: ServiceSpec, part: Part, cname: str) -> None:
        h = part.health
        deadline = self.out.clock() + (h.ready_s if h else 60.0)
        port = next((x for x in part.ports if h and x.name == h.port), None)
        while True:
            work.check()
            st = rt.state(cname) or {}
            if st.get("state") == "exited":
                raise Refusal(f"{cname} exited with {st.get('exit')}: its log says why (nothing restarts it)")
            if st.get("state") == "running":
                if port is None:
                    return
                host, _, number = rt.here(port.host).rpartition(":")
                check = self.out.health or _health_check
                if check(host, int(number), h.path if h else ""):
                    work.line(f"{cname} answers at {host}:{number}")
                    return
            if self.out.clock() > deadline:
                raise Refusal(f"{cname} did not answer within {h.ready_s if h else 60:g} s")
            self.out.sleep(HEALTH_EVERY_S)

    def _hold(self, work: Work, t: Target, sid: str) -> None:
        if not t.wsl or not self._wsl_holds(t):
            if t.wsl:
                work.line(f"{t.wsl} is not held up (its WSL plugin has no hold yet)")
            return
        with self._svc.lock:
            holders = self._svc.held.setdefault(t.wsl, set())
            first = not holders
            holders.add(sid)
        if first:
            self.ask_plugin(t.wsl_plugin, C.HOLD, t.wsl)
            work.line(f"{t.wsl} held up while {sid} runs")

    def _let_go(self, t: Target, sid: str, line=None) -> None:
        if not t.wsl:
            return
        with self._svc.lock:
            holders = self._svc.held.get(t.wsl, set())
            holders.discard(sid)
            last = not holders
        if last and self._wsl_holds(t):
            try:
                self.ask_plugin(t.wsl_plugin, C.LET_GO, t.wsl)
                if line:
                    line(f"{t.wsl} let go: no service of Liminal's runs there now")
            except Exception:  # noqa: BLE001 - the WSL plugin turned off meanwhile
                pass

    def _pulled(self, work: Work, t: Target, rt: Runtime, part: Part) -> None:
        """A part's image on its engine: found, or pulled and its digest checked; a runtime whose engine pulls by
        digest itself answers containers.PULLED_BY_ENGINE, said as such (1.95.0). Any other digest is refused."""
        if rt.has_image(part.image):
            work.line(f"{part.image.pinned} is on {t.id} already")
            return
        got = rt.pull(part.image, work.line, work.cancelled)
        if got == C.PULLED_BY_ENGINE:
            work.line(f"{part.image.ref}: pulled by its engine by its digest when it is made (not checked here)")
            return
        if got != part.image.digest:
            raise Refusal(f"{part.image.ref} came as {got}, not its pinned {part.image.digest}")
        work.line(f"{part.image.ref}: the digest checked")

    def _volumes_made(self, work: Work, rt: Runtime, sid: str, volumes) -> set:
        new_volumes = set()
        for v in volumes:
            work.check()
            name = C.volume_name(sid, v.name)
            if rt.make_volume_for(name, C.volume_labels(sid, v.name, self._platform(), self._now()), v):
                new_volumes.add(v.name)
                work.line(f"the volume {name} made")
            else:
                work.line(f"the volume {name} found from before: used as it is")
        return new_volumes

    def _do_install(self, work: Work, p: Plan, t: Target, rt: Runtime, spec: ServiceSpec):
        sid = p.subject
        made_containers: list[str] = []
        made_network = False
        grant = self._grant_of(p)
        network, own_network = self._net_name(rt, spec, sid)
        try:
            for part in spec.parts:
                work.check()
                self._pulled(work, t, rt, part)
            new_volumes = self._volumes_made(work, rt, sid, spec.volumes())
            work.check()
            if grant:
                made_network = rt.make_network(network, grant, C.segment_labels(sid, self._platform()))
                made_network = made_network and own_network
                work.line(f"its network {network} " + ("made" if made_network else "found") +
                          f" ({grant.get('subnet')})" + ("" if own_network else ": its engine's own, shared"))
            for part in spec.parts:
                work.check()
                cname = self._create(t, rt, sid, spec, part, grant, "current")
                made_containers.append(cname)
                work.line(f"{cname} made, --restart no")
                seeds = [(f"{v.path.rstrip('/')}/{s.path}", s, v.owner) for s in part.seeds
                         for v in part.volumes if v.name == s.volume and v.name in new_volumes]
                if seeds:
                    rt.seed(cname, seeds, work.line)
                    work.line(f"{len(seeds)} file{'s' if len(seeds) != 1 else ''} seeded into its new volume")
            self._apply_network(work, p)
            self._hold(work, t, sid)
            for part in spec.parts:
                work.check()
                cname = C.container_name(sid, part.name)
                rt.start(cname)
                work.line(f"{cname} started")
                self._wait_healthy(work, t, rt, spec, part, cname)
        except BaseException:
            for cname in reversed(made_containers):
                try:
                    rt.remove(cname)
                    work.line(f"undone: {cname} removed (its volumes kept, the image kept)")
                except Exception as e:  # noqa: BLE001 - said, and left
                    work.line(f"{cname} could not be removed: {e}")
            if made_network:
                try:
                    rt.drop_network(network)
                    work.line(f"undone: its network {network} removed")
                except Exception:  # noqa: BLE001 - said by its absence
                    pass
            self._let_go(t, sid, work.line)
            raise
        finally:
            self.forget_targets()
        return {"said": f"{spec.title} ({sid.split('/', 1)[1]}) runs on {t.id}", "ok": True,
                "here": {x.name: f"http://{rt.here(x.host)}" for x in spec.ports()}}

    def _do_add(self, work: Work, p: Plan, t: Target, rt: Runtime, spec: ServiceSpec, adds: list):
        """Parts added to a service that runs: their images, volumes and containers on its network, the firewall's
        plan for their addresses and names, their seeds into their new volumes, their start. Nothing it ran before is
        stopped; a failure or a Cancel removes what this made (its volumes and images kept)."""
        sid = p.subject
        made: list[str] = []
        grant = self._grant_of(p) or self._grant_from_hosted(rt, sid)
        parts = [x for x in spec.parts if x.name in adds]
        try:
            for part in parts:
                work.check()
                self._pulled(work, t, rt, part)
            new_volumes = self._volumes_made(work, rt, sid, [v for x in parts for v in x.volumes])
            for part in parts:
                work.check()
                cname = self._create(t, rt, sid, spec, part, grant, "current")
                made.append(cname)
                work.line(f"{cname} made, --restart no")
                seeds = [(f"{v.path.rstrip('/')}/{s.path}", s, v.owner) for s in part.seeds
                         for v in part.volumes if v.name == s.volume and v.name in new_volumes]
                if seeds:
                    rt.seed(cname, seeds, work.line)
            self._apply_network(work, p)
            for part in parts:
                work.check()
                cname = C.container_name(sid, part.name)
                rt.start(cname)
                work.line(f"{cname} started")
                self._wait_healthy(work, t, rt, spec, part, cname)
        except BaseException:
            for cname in reversed(made):
                try:
                    st = rt.state(cname) or {}
                    if st.get("state") in ("running", "restarting", "paused"):
                        rt.stop(cname, 30)
                    rt.remove(cname)
                    work.line(f"undone: {cname} removed (its volumes kept, the image kept)")
                except Exception as e:  # noqa: BLE001 - said, and left
                    work.line(f"{cname} could not be removed: {e}")
            raise
        finally:
            self.forget_targets()
        return {"said": f"{', '.join(adds)} added to {sid} on {t.id}", "ok": True,
                "here": {x.name: f"http://{rt.here(x.host)}" for x in spec.ports()}}

    def _do_start(self, work, p, t, rt, spec):
        sid = p.subject
        self._apply_network(work, p)
        self._hold(work, t, sid)
        try:
            for part in spec.parts:
                work.check()
                cname = C.container_name(sid, part.name)
                st = rt.state(cname) or {}
                if st.get("state") != "running":
                    rt.start(cname)
                    work.line(f"{cname} started")
                self._wait_healthy(work, t, rt, spec, part, cname)
        except BaseException:
            self._let_go(t, sid, work.line)
            raise
        return {"said": f"{sid} runs on {t.id}", "ok": True}

    def _do_stop(self, work, t, rt, spec, sid):
        parts = spec.parts if spec else ()
        for part in reversed(parts):
            cname = C.container_name(sid, part.name)
            st = rt.state(cname) or {}
            if st.get("state") in ("running", "restarting", "paused"):
                rt.stop(cname, part.stop_s)
                work.line(f"{cname} stopped (given {part.stop_s} s to end on its own)")
        self._let_go(t, sid, work.line)
        return {"said": f"{sid} stopped on {t.id}", "ok": True}

    def _backups_of(self, sid: str) -> Path:
        owner, name = C.split_sid(sid)
        base = self.out.folder
        if base is None:
            from .ai import platform_folder

            base = platform_folder(self.out.env)
        return Path(base) / "containers" / "backups" / f"{owner}-{name}"

    def _latest_backup(self, sid: str) -> Path | None:
        folder = self._backups_of(sid)
        try:
            kept = sorted((d for d in folder.iterdir() if d.is_dir()), key=lambda d: d.name)
        except OSError:
            return None
        return kept[-1] if kept else None

    def _do_update(self, work, p, t, rt, spec: ServiceSpec):
        sid = p.subject
        backup_dir = None
        kinds = self._backup_kinds(rt, spec)
        if all(kinds[part.name] == "snapshot" or (kinds[part.name] == "tar" and part.image.tar)
               for part in spec.parts if part.volumes) and spec.volumes():
            stamp = _dt.datetime.fromtimestamp(self.out.wall(), _dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup_dir = self._backups_of(sid) / stamp
            backup_dir.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(backup_dir, 0o700)
            labelled = self._found(sid)[3]
            for part in spec.parts:
                for v in part.volumes:
                    work.check()
                    old = labelled.part(part.name) if labelled else None
                    pinned = (old or part).image.pinned
                    n = rt.backup(C.volume_name(sid, v.name), pinned, backup_dir / f"{v.name}.tar", work.line,
                                  work.cancelled)
                    if kinds[part.name] == "snapshot" or isinstance(n, str):
                        (backup_dir / f"{v.name}.snapshot.json").write_text(json.dumps(
                            {"kind": "snapshot", "volume": C.volume_name(sid, v.name), "said": str(n)}), "utf-8")
                        work.line(f"the volume {C.volume_name(sid, v.name)} snapshotted by its engine: {n}")
                    else:
                        work.line(f"the volume {C.volume_name(sid, v.name)} backed up: {n:,} bytes in {backup_dir}")
            self._prune_backups(sid)
        for part in spec.parts:
            work.check()
            if not rt.has_image(part.image):
                got = rt.pull(part.image, work.line, work.cancelled)
                if got != part.image.digest:
                    raise Refusal(f"{part.image.ref} came as {got}, not its pinned {part.image.digest}")
        grant = self._grant_from_hosted(rt, sid)
        renamed: list[tuple[str, str]] = []
        made: list[str] = []
        try:
            for part in spec.parts:
                work.check()
                cname, prev = C.container_name(sid, part.name), C.previous_name(sid, part.name)
                st = rt.state(cname) or {}
                if st.get("state") in ("running", "restarting", "paused"):
                    rt.stop(cname, part.stop_s)
                    work.line(f"{cname} stopped")
                if rt.state(prev) is not None:
                    rt.remove(prev)
                    work.line(f"the older {prev} removed")
                rt.rename(cname, prev)
                renamed.append((cname, prev))
                work.line(f"{cname} kept as {prev}")
                self._create(t, rt, sid, spec, part, grant, "current")
                made.append(cname)
                rt.start(cname)
                self._wait_healthy(work, t, rt, spec, part, cname)
        except BaseException:
            for cname in made:
                try:
                    rt.remove(cname)
                    work.line(f"undone: the new {cname} removed")
                except Exception:  # noqa: BLE001 - said by its absence
                    pass
            for cname, prev in reversed(renamed):
                try:
                    rt.rename(prev, cname)
                    rt.start(cname)
                    work.line(f"undone: {prev} named back {cname} and started as it was")
                except Exception as e:  # noqa: BLE001 - said
                    work.line(f"{prev} could not be named back: {e}")
            if backup_dir is not None:
                work.line(f"its backup is {backup_dir}: the new version may already have changed the data")
            raise
        finally:
            self.forget_targets()
        return {"said": f"{sid} updated on {t.id}", "ok": True, "backup": str(backup_dir) if backup_dir else ""}

    def _grant_from_hosted(self, rt: Runtime, sid: str) -> dict:
        for s in rt.segments():
            if s.get("sid") == sid:
                addresses = {m.get("part"): m.get("ipv4") for m in s.get("members") or [] if m.get("ipv4")}
                return {"subnet": (s.get("subnets") or [""])[0], "gateway": (s.get("gateways") or [""])[0],
                        "addresses": addresses}
        return {}

    def _prune_backups(self, sid: str) -> None:
        folder = self._backups_of(sid)
        try:
            kept = sorted((d for d in folder.iterdir() if d.is_dir()), key=lambda d: d.name)
        except OSError:
            return
        for d in kept[:-C.BACKUPS_KEPT]:
            shutil.rmtree(d, ignore_errors=True)

    def _do_rollback(self, work, p, t, rt):
        sid = p.subject
        _, _, row, spec = self._found(sid)
        choice = p.extra.get("options", {}).get("choice", "as-is")
        for part in spec.parts:
            work.check()
            cname, prev = C.container_name(sid, part.name), C.previous_name(sid, part.name)
            if rt.state(prev) is None:
                raise Refusal(f"{prev} is not there any more")
            st = rt.state(cname) or {}
            if st.get("state") in ("running", "restarting", "paused"):
                rt.stop(cname, part.stop_s)
            rt.remove(cname)
            work.line(f"{cname} removed")
            rt.rename(prev, cname)
            work.line(f"{prev} named back {cname}")
        if choice == "backup":
            latest = self._latest_backup(sid)
            labelled = self._found(sid)[3] or spec
            for part in labelled.parts:
                for v in part.volumes:
                    source = latest / f"{v.name}.tar"
                    if not source.exists() and (latest / f"{v.name}.snapshot.json").exists():
                        source = latest / f"{v.name}.snapshot.json"  # 1.95.0: the engine's own snapshot
                    n = rt.restore(C.volume_name(sid, v.name), part.image.pinned, source, work.line, work.cancelled)
                    work.line(f"the volume {C.volume_name(sid, v.name)} put back from {latest.name} ("
                              + (f"{n:,} bytes" if isinstance(n, int) else str(n)) + ")")
        labelled = self._found(sid)[3] or spec
        self._hold(work, t, sid)
        for part in labelled.parts:
            cname = C.container_name(sid, part.name)
            rt.start(cname)
            self._wait_healthy(work, t, rt, labelled, part, cname)
        self.forget_targets()
        return {"said": f"{sid} rolled back on {t.id}", "ok": True}

    def _do_expose(self, work, p, t, rt, spec):
        sid = p.subject
        grant = self._grant_from_hosted(rt, sid)
        for part in spec.parts:
            work.check()
            cname = C.container_name(sid, part.name)
            st = rt.state(cname) or {}
            if st.get("state") in ("running", "restarting", "paused"):
                rt.stop(cname, part.stop_s)
            rt.remove(cname)
            self._create(t, rt, sid, spec, part, grant, "current")
            work.line(f"{cname} made again with its ports " + ("on every address" if any(x.lan for x in part.ports)
                                                                  else "on this machine alone"))
        self._apply_network(work, p)
        self._hold(work, t, sid)
        for part in spec.parts:
            cname = C.container_name(sid, part.name)
            rt.start(cname)
            self._wait_healthy(work, t, rt, spec, part, cname)
        self.forget_targets()
        return {"said": f"{sid} " + ("open to" if spec.lan_ports() else "closed to") + " your network", "ok": True}

    def _do_remove(self, work, p, t, rt, sid):
        facts = rt.facts(None, sid)
        for cname, c in sorted(facts.get("containers", {}).items()):
            work.check()
            if c.get("state") in ("running", "restarting", "paused"):
                rt.stop(cname, 30)
            rt.remove(cname)
            work.line(f"{cname} removed (never its volumes)")
        self._let_go(t, sid, work.line)
        network, own = self._net_name(rt, None, sid)
        if own:
            try:
                rt.drop_network(network)
                work.line(f"its network {network} removed")
            except Exception as e:  # noqa: BLE001 - one that was not there
                work.line(f"its network: {e}")
        else:
            work.line(f"its engine's own network {network} is left as it is (shared)")
        self._apply_network(work, p)
        self.forget_targets()
        return {"said": f"{sid} removed from {t.id}: its data kept", "ok": True}

    def _do_delete(self, work, p, t, rt, sid):
        vols = [v["name"] for v in self._volumes_of(rt, sid)]
        if any(v.get("used_by") for v in self._volumes_of(rt, sid)):
            raise Refusal(f"a container uses {sid}'s volumes now: nothing deleted")
        rt.drop_volumes(vols)
        work.line("deleted: " + ", ".join(vols))
        if p.extra.get("options", {}).get("backups") == "delete":
            shutil.rmtree(self._backups_of(sid), ignore_errors=True)
            work.line(f"its backups deleted ({self._backups_of(sid)})")
        self._apply_network(work, p)
        return {"said": f"{sid}'s data deleted from {t.id}", "ok": True}

    # -- files, release, volumes ---------------------------------------------------------------------------------------
    def hosted_file(self, sid, part, readable) -> dict:
        """A file the service's spec names as readable (as labelled on its container), FILE_MOST at most: never a path
        the asker types. Asked by its owner alone, and logged (it is no read)."""
        owner, _ = C.split_sid(sid)
        self._need_owner(C.HOSTED_FILE, owner)
        t, rt, row, spec = self._found(sid)
        if spec is None or spec.part(str(part)) is None:
            raise Refusal(f"{sid} has no part {str(part)[:20]!r}")
        p = spec.part(str(part))
        r = next((x for x in p.readable if x.name == str(readable)), None)
        if r is None:
            raise Refusal(f"{sid}'s {p.name} names no readable file {str(readable)[:20]!r}")
        v = next(x for x in p.volumes if x.name == r.volume)
        raw = rt.read(C.container_name(sid, p.name), f"{v.path.rstrip('/')}/{r.path}", C.FILE_MOST)
        return {"sid": sid, "part": p.name, "readable": r.name, "text": raw[:C.FILE_MOST].decode("utf-8", "replace")}

    def release_owned(self) -> dict:
        """Stops the asker's "page" services (asked when you turn that plugin off)."""
        who = asking.asker()
        if who is None or who == asking.PAGE:
            raise Refusal(f"{self.name}'s release_owned is asked by a service plugin alone, for its own")
        lines = self._stop_page_services(lambda sid: sid.startswith(who + "/"))
        return {"said": f"{who}'s services stopped", "ok": True, "lines": lines}

    def forget_volume(self, target, volume, accept_data=False) -> dict:
        """Deletes a Liminal volume that no container uses, from the page alone, asked twice."""
        self._need_page(C.FORGET_VOLUME)
        t = self.target(str(target or ""))
        if not t.ready:
            raise Refusal(f"{t.title} is {t.state}: {t.why}")
        rt = self.runtime_of(t)
        v = next((x for x in rt.volumes() if x.get("name") == str(volume)), None)
        if v is None:
            raise Refusal(f"{str(volume)[:60]} is no volume of Liminal's on {t.id}")
        if v.get("used_by"):
            raise Refusal(f"{v['name']} is used by {', '.join(v['used_by'])}: nothing deleted")
        if accept_data is not True:
            raise Refusal(f"{v['name']} ({v.get('sid')}: {v.get('size') or 'its size not read'}) is deleted for good",
                          accept=ACCEPT_DATA)
        rt.drop_volumes([v["name"]])
        return {"said": f"{v['name']} deleted from {t.id}", "ok": True}

    # -- the plugin's end ----------------------------------------------------------------------------------------------
    def _stop_page_services(self, which: Callable[[str], bool] = lambda sid: True) -> list[str]:
        lines: list[str] = []
        for t in self.targets(fresh=True):
            if not t.ready:
                continue
            try:
                rt = self.runtime_of(t)
                rows = rt.hosted()
            except Exception:  # noqa: BLE001 - not read now: nothing to stop there
                continue
            for r in rows:
                sid = str(r.get("sid", ""))
                if not which(sid) or r.get("lifecycle", "page") != "page" or r.get("platform") not in ("",
                                                                                                         self._platform()):
                    continue
                for part in r.get("parts") or []:
                    if part.get("role", "current") == "current" and part.get("state") in ("running", "restarting"):
                        try:
                            rt.stop(part["container"], 30)
                            lines.append(f"{part['container']} stopped")
                        except Exception as e:  # noqa: BLE001 - said
                            lines.append(f"{part['container']} could not be stopped: {e}")
                self._let_go(t, sid)
        self.forget_targets()
        return lines

    def _turned_off(self) -> bool:
        app = self.app
        try:
            return self.name in (app.disabled() if app is not None and callable(getattr(app, "disabled", None))
                                 else ())
        except Exception:  # noqa: BLE001 - a platform that cannot say: not turned off
            return False

    def services_stopping(self) -> None:
        """The platform stops, or you turned this plugin off: every work asked to stop and joined, every "page" service
        stopped, every plan forgotten."""
        self._svc.works.cancel_all()
        self._svc.plans.forget_all()
        self._stop_page_services()

    def app_stopping(self) -> None:
        self.services_stopping()
        parent = getattr(super(), "app_stopping", None)
        if callable(parent):
            parent()

    def detach(self) -> None:
        """Plans are forgotten at every detach; only a detach because you turned it off cancels works and stops
        services (a detach for invalidity stops nothing)."""
        if self._turned_off():
            self.services_stopping()
        self._svc.plans.forget_all()
        super().detach()

    # -- the page ------------------------------------------------------------------------------------------------------
    def service_status(self, targets: list[Target] | None = None) -> dict:
        """What the base adds to its plugin's page: its tables (Liminal's services, Service plugins, Waiting for your
        answer, Kept data; Yours to define when it declares settings) and its forms (Approve…, Decline…, Let it…, Stop
        letting it…, Forget…, Set…). Never raises. `targets` (1.95.0): those its plugin read for its own status, kept
        (keep_targets) so that nothing is read twice."""
        if targets is not None:
            self.keep_targets(targets)
        try:
            return self._service_status()
        except Exception as e:  # noqa: BLE001 - a status never raises
            return {"tables": [], "forms": [], "problem": f"its services could not be read: {e}"}

    def _service_status(self) -> dict:
        rows = []
        wanted = self.service_reads_wanted()
        for r in (self._rows() if wanted else []):
            rows.append([{"text": r["title"], "sub": r["sid"]}, r["target"], {"text": r["state"], "sub": r["why"] or None},
                         ", ".join(f"{p['host']}/{p['protocol']} at {p['here']}" for p in r["ports"]) or "–",
                         ", ".join(v["volume"] for v in r["volumes"]) or "–", r["work"] or "–"])
        waiting = []
        for p in self._svc.plans.waiting():
            waiting.append([{"text": p.title, "sub": p.words[:300]}, p.owner,
                            "approved: its plugin carries it out" if p.approved else
                            (", ".join(p.needs()) or "your approval"),
                            {"form": "approve", "title": "Approve…", "values": {"plan": p.plan},
                             "label": f"Approve {p.title}", "disabled": p.approved},
                            {"form": "decline", "title": "Decline…", "values": {"plan": p.plan}}])
        g = self.grants()
        with self._svc.lock:
            askers = sorted(self._svc.askers | set(g))
        plugins_rows = []
        for a in askers:
            plugins_rows.append([a, ", ".join(g.get(a, [])) or "none yet",
                                 {"form": "grant", "title": "Let it…", "values": {"plugin": a}},
                                 {"form": "revoke", "title": "Stop letting it…", "values": {"plugin": a}}])
        kept = []
        for t in (self.targets() if wanted else []):
            if not t.ready:
                continue
            try:
                _, vols = self._read_target(t, self.runtime_of(t), volumes=True)
            except Exception:  # noqa: BLE001 - not read now
                continue
            for v in vols:
                if not v.get("used_by"):
                    kept.append([v["name"], v.get("sid", ""), t.id, v.get("size") or "–", v.get("made") or "–",
                                 {"form": "forget", "title": "Forget…", "values": {"target": t.id,
                                                                                    "volume": v["name"]}}])
        targets = [{"value": t.id, "title": t.id, "note": f"{t.state} · {t.title}"} for t in self.targets()]
        defined = []
        for t in self.targets():
            try:
                declared = self.target_settings(t)
            except Exception:  # noqa: BLE001 - not said: none
                declared = ()
            for s in declared:
                v = self.setting_values(t.id).get(s.name, "")
                shown = (", ".join(f"{k}: {x}" for k, x in sorted(v.items())) or "none set") if isinstance(v, dict) \
                    else (v or "not set")
                defined.append([t.id, {"text": s.label, "sub": s.about or None}, shown,
                                {"form": "setting", "title": "Set…", "values": {"target": t.id, "setting": s.name}}])
        tables = [
            {"title": "Liminal's services", "rows": rows, "empty": "No service of Liminal's runs here.",
             "columns": [{"title": "Service"}, {"title": "Target"}, {"title": "State"}, {"title": "Ports"},
                         {"title": "Volumes"}, {"title": "Work"}],
             "note": "Start, Stop and every other change are asked on the service's own page."},
            {"title": "Waiting for your answer", "rows": waiting, "empty": "No plan waits for you.",
             "columns": [{"title": "Plan"}, {"title": "Asked by"}, {"title": "Needs"}, {"title": "Approve"},
                         {"title": "Decline"}]},
            {"title": "Service plugins", "rows": plugins_rows, "empty": "No service plugin has asked yet.",
             "columns": [{"title": "Plugin"}, {"title": "Let on"}, {"title": "Let"}, {"title": "Stop"}]},
            {"title": "Kept data", "rows": kept, "empty": "No volume of Liminal's is left without its container.",
             "columns": [{"title": "Volume"}, {"title": "Service"}, {"title": "Target"}, {"title": "Size"},
                         {"title": "Made"}, {"title": "Forget"}]},
        ]
        if defined:
            tables.append({"title": "Yours to define", "rows": defined, "empty": "",
                           "columns": [{"title": "Target"}, {"title": "Setting"}, {"title": "Value"}, {"title": "Set"}],
                           "note": "Liminal picks none of these for you: every plan on a target waits until each is "
                                   "set."})
        accept = [{"name": n, "type": "accept", "title": title, "yes": yes, "words": words} for n, title, yes, words in (
            (ACCEPT_LAN, "Published to your network?", "Publish it", "Its ports are published on every address."),
            (ACCEPT_KEPT_SECRET, "A secret kept by the engine?", "Accept", "The engine keeps a secret it is handed."),
            (ACCEPT_DIFFERS, "Done differently?", "Accept the difference", "A part is done otherwise than asked."),
            (C.ACCEPT_BOOT, "Service mode?", "Accept", C.SERVICE_MODE_WORDS),
            (ACCEPT_NO_BACKUP, "No backup?", "Update without a backup", "No backup can be made first."),
            (ACCEPT_DATA, "Data deleted or replaced?", "Go on", "Data is deleted or put back: it cannot be undone."),
            *((n, f"{n[len('accept_'):].replace('_', ' ').capitalize()}?", "Accept", "Asked by this plugin's own plan.")
              for n in self.MORE_ACCEPTS))]
        forms = [
            {"id": "approve", "hook": C.APPROVE, "title": "Approve a plan", "submit": "Review",
             "fields": [{"name": "plan", "label": "Plan", "type": "fixed"}, *accept],
             "confirm": {"title": "Approve {plan}?", "words": "The plan is carried out by the plugin that asked for it, "
                         "once, within ten minutes: each second confirmation it needs is asked in turn.",
                         "yes": "Approve"}},
            {"id": "decline", "hook": C.DECLINE, "title": "Decline a plan",
             "fields": [{"name": "plan", "label": "Plan", "type": "fixed"}],
             "confirm": {"title": "Decline {plan}?", "words": "Nothing is done; the plan is forgotten.",
                         "yes": "Decline"}},
            {"id": "grant", "hook": C.GRANT, "title": "Let a service plugin use a target",
             "fields": [{"name": "plugin", "label": "Plugin", "type": "fixed"},
                        {"name": "target", "label": "Target", "type": "choice", "choices": targets}],
             "confirm": {"title": "Let {plugin} run its services on {target}?",
                         "words": "Kept through your login until you stop letting it. Each change it asks for is still "
                                  "a plan you approve.", "yes": "Let it"}},
            {"id": "revoke", "hook": C.REVOKE, "title": "Stop letting a service plugin use a target",
             "fields": [{"name": "plugin", "label": "Plugin", "type": "fixed"},
                        {"name": "target", "label": "Target", "type": "choice", "choices": targets}],
             "confirm": {"title": "Stop letting {plugin} plan on {target}?",
                         "words": "Its services there stay as they are.", "yes": "Stop letting it"}},
        ]
        if defined and C.SET_SETTING in getattr(self, "HOOKS", ()):
            forms.append(
            {"id": "setting", "hook": C.SET_SETTING, "title": "Define a setting of a target",
             "fields": [{"name": "target", "label": "Target", "type": "fixed"},
                        {"name": "setting", "label": "Setting", "type": "fixed"},
                        {"name": "value", "label": "Value", "type": "text"},
                        {"name": "service", "label": "Service (for a setting of one service)", "type": "text"},
                        {"name": "confirm", "type": "accept", "title": "Go on?", "yes": "Go on",
                         "words": "Asked when the plugin needs a second confirmation for it."}],
             "confirm": {"title": "Set {setting} on {target}?", "words": "Kept through your login; Liminal picks "
                         "none of these for you.", "yes": "Set it"}})
        forms += [
            {"id": "forget", "hook": C.FORGET_VOLUME, "title": "Forget a kept volume",
             "fields": [{"name": "target", "label": "Target", "type": "fixed"},
                        {"name": "volume", "label": "Volume", "type": "fixed"},
                        {"name": "accept_data", "type": "accept", "title": "Delete it for good?", "yes": "Delete it",
                         "words": "{volume} is deleted with everything it holds: this cannot be undone."}],
             "confirm": {"title": "Forget {volume} on {target}?", "words": "Its data is deleted.", "yes": "Forget it",
                         "danger": True}},
        ]
        return {"tables": tables, "forms": forms}

    # -- other plugins, asked through the app ---------------------------------------------------------------------------
    def ask_plugin(self, name: str, hook: str, *args):
        """Another plugin's hook asked through the app: the platform's ask(name, hook, args) or the frame's
        ask(name, hook, *args). Holds no lock while it asks."""
        app = self.app
        if app is None:
            raise Refusal(f"{self.name} is not attached: it asks no other plugin")
        import inspect

        try:
            spread = inspect.signature(app.ask).parameters.get("args")
        except (TypeError, ValueError):
            spread = None
        if spread is not None and spread.kind is inspect.Parameter.VAR_POSITIONAL:
            return app.ask(name, hook, *args)
        return app.ask(name, hook, list(args))

    def ask_others(self, hook: str, *args) -> list[tuple[str, object, BaseException | None]]:
        """Each other attached plugin whose hooks list `hook`, asked it with no lock held: [(name, answer, error)]."""
        app = self.app
        if app is None:
            return []
        try:
            faces = dict(app.plugins() or {})
        except Exception:  # noqa: BLE001 - an app that cannot list its plugins asks none
            return []
        out = []
        for name, face in faces.items():
            hooks = face.get("hooks") if isinstance(face, Mapping) else None
            if name == self.name or not hooks or hook not in hooks:
                continue
            try:
                out.append((name, self.ask_plugin(name, hook, *args), None))
            except Exception as e:  # noqa: BLE001 - one that refuses is left out, in its words
                out.append((name, None, e))
        return out


__all__ = ["ContainerHost", "Create", "Outside", "Runtime", "Cancelled"]
