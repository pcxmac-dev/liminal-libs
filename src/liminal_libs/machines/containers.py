"""The one "run a service" interface between service plugins and container plugins (1.93.0; Monday list items 34 and
35; the designs service-containers-design-2026-11-23.md §3 and service-containers-networking-2026-11-23.md §8, with
the user's answers of 2026-11-23 and 2026-11-25).

The user: "all services will be in docker", "either on windows or linux"; "actually all services can run on all
container plugin types", "so there should be mechanisms for all types"; 2026-11-25: "Containers only" (no native
install), agents and workers "Containers too", "plugins either start or stop with platform or their respective app,
unless they are running in daemon/service mode ... provision must be for them to start and stop in server/service mode
eventually", a restart after a crash "Never", an engine that is off "No" (never started by a plan).

What crosses between plugins, all plain JSON (`as_dict`, `of`):
- the words: the hooks' names (so neither side spells them), the actions, the paths a port meets your network by, the
  accepts a plan may ask, the limits;
- the spec a service plugin hands over (`ServiceSpec`, its `Part`s, each image pinned by digest: `ImagePin`), refused in
  words before any plan is made (`ServiceSpec.of`, `problems`);
- what a container plugin answers: its `Target`s, each with its `Fit` for a spec (exact, differs, cannot, part by part).
- `Runtime`: what a container plugin gives for each of its targets (machines/dockerruntime.py: DockerRuntime);
- the names every runtime gives what it makes (`container_name`, `volume_name`, `network_name`, `rule_name`) and the
  labels it marks them with (`labels`): the runtime holds the truth, read back from the labels.

The base a container plugin is built on, `ContainerHost`, is in machines/containerhost.py; machines/plans.py holds its
plans; machines/segments.py the networking words and the firewall's `NetworkHost`; machines/standins.py the stand-ins
every plugin's tests use; `conformance` (machines/containerhost.py) the run every container plugin's tests make.

The standard library and the library's own plain modules only."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, fields
from typing import Mapping

from ..instances import Refusal

SPEC_V = 1
RUNTIMES = ("docker", "windows-containers", "kubernetes", "lxd")  # a container plugin's RUNTIME
MECHANISMS = ("docker", "docker-windows", "nerdctl", "kubernetes", "incus-oci", "lxd-docker")
SYSTEMS = ("linux", "windows")  # what an image runs on
ACTIONS = ("install", "start", "stop", "restart", "update", "rollback", "expose", "boot", "remove", "delete_data")
# page: from your Start to your Stop, stopped with its app (the platform); service: started at boot and left running
# after sign-off, the user's service/daemon mode (2026-11-25): provided for in every word here, off, and not offered yet
LIFECYCLES = ("page", "service")
SERVICE_MODE_OFFERED = False
SERVICE_MODE_WORDS = ("service mode (started at boot, left running after you sign off) is provided for, and not offered "
                      "yet: every service starts and stops with its app")
PATHS = ("direct", "wsl-nat", "wsl-mirrored", "cluster-lb", "node-port", "none")  # how a port meets your network
FITS = ("exact", "differs", "cannot")
STATES = ("ready", "stopped", "idle", "not answering", "no rights", "not here")  # a target's
HOSTED_STATES = ("running", "starting", "stopped", "unhealthy", "missing", "not asked")
ACCEPT_LAN, ACCEPT_KEPT_SECRET, ACCEPT_DIFFERS = "accept_lan", "accept_kept_secret", "accept_differs"
ACCEPT_BOOT, ACCEPT_NO_BACKUP, ACCEPT_DATA = "accept_boot", "accept_no_backup", "accept_data"
ACCEPTS = (ACCEPT_LAN, ACCEPT_KEPT_SECRET, ACCEPT_DIFFERS, ACCEPT_BOOT, ACCEPT_NO_BACKUP, ACCEPT_DATA)
READ_S = 30.0  # what a runtime said is kept this long
WORK_LINES, WORK_KEEP_S = 2000, 600.0  # a work's lines kept; a finished work kept ten minutes
PORTS = (1024, 65535)  # a published host port
SUITE_PORTS = (9765, 9775, 9785, 9795)  # the Linux suite's pages, reserved beside firewall.app_ports' four
MEMORY_LEAST = 256 << 20  # every part has a memory limit, at least this
FILE_MOST = 64 << 10  # bytes hosted_file gives at most
LOG_MOST = 2000  # lines hosted_logs gives at most
SEED_MOST = 64 << 10
MOST = {"parts": 8, "ports": 16, "volumes": 8, "env": 32, "secrets": 8, "seeds": 16, "readable": 8, "command": 32}
BACKUPS_KEPT = 2

# the hooks' names, so that neither side spells them
HOSTING, HOSTED, HOSTED_LOGS, EXPOSURES = "hosting", "hosted", "hosted_logs", "exposures"
PLAN_WORDS, WORK, PLAN, APPROVE, DECLINE = "plan_words", "service_work", "service_plan", "approve_plan", "decline_plan"
APPLY, CANCEL, HOSTED_FILE, RELEASE = "apply_plan", "service_cancel", "hosted_file", "release_owned"
GRANT, REVOKE, FORGET_VOLUME, SEGMENTS = "grant_service", "revoke_service", "forget_volume", "segments"
# and those a container plugin asks of others: the firewalls' (machines/segments.py), the WSL plugins', the model servers'
LAN_OPEN, HOLD, LET_GO, SERVING = "lan_open", "hold", "let_go", "serving"
EXCLUDED = "excluded_ports"  # {"ranges": [[low, high], ...]}: the port ranges this system keeps (a firewall plugin's)

NAME = re.compile(r"^[a-z][a-z0-9-]{0,15}$")  # an owner's, a service's, a port's name
PART = re.compile(r"^[a-z][a-z0-9-]{0,11}$")  # a part's, a volume's, a readable's
VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REF = re.compile(r"^(?:[a-z0-9](?:[a-z0-9.-]{0,252}[a-z0-9])?(?::[0-9]{1,5})?/)?[a-z0-9]+(?:[._/-][a-z0-9]+)*"
                 r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$")
PLATFORM = re.compile(r"^(linux|windows)/[a-z0-9]+(?:/[a-z0-9]+)?$")
ENV_CHARS = 4096
TEXT_CHARS = 400


def _controls(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def _texts(value, path: str, out: list[str], keep_newlines: bool = False) -> None:
    """Every text inside a value checked for control characters (a seed's own text may hold newlines and tabs)."""
    if isinstance(value, str):
        bad = [c for c in value if (ord(c) < 32 and not (keep_newlines and c in "\n\r\t")) or ord(c) == 127]
        if bad:
            out.append(f"{path} holds a control character")
    elif isinstance(value, Mapping):
        for k, v in value.items():
            _texts(str(k), f"{path} (a name)", out)
            _texts(v, f"{path}.{k}", out, keep_newlines)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _texts(v, f"{path}[{i}]", out, keep_newlines)


def stem(owner: str) -> str:
    """The stem an owner's pairs are named under: jenkins's JENKINS_."""
    return str(owner).strip().upper().replace("-", "_") + "_"


def _exact_keys(cls, m, path: str) -> None:
    if not isinstance(m, Mapping):
        raise Refusal(f"{path} is an object, not {type(m).__name__}")
    known = {f.name for f in fields(cls)}
    unknown = sorted(str(k) for k in m if k not in known)
    if unknown:
        raise Refusal(f"{path} has no field {', '.join(unknown[:4])}: a container is never given more than the spec "
                      "says (no privileged mode, capability, host path, Docker socket or host namespace)")


def _int(m, key, default, path):
    v = m.get(key, default)
    if isinstance(v, bool) or not isinstance(v, int):
        raise Refusal(f"{path}.{key} is a whole number, not {v!r}"[:200])
    return v


def _num(m, key, default, path):
    v = m.get(key, default)
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise Refusal(f"{path}.{key} is a number, not {v!r}"[:200])
    return float(v)


def _str(m, key, default, path, most=TEXT_CHARS):
    v = m.get(key, default)
    if not isinstance(v, str):
        raise Refusal(f"{path}.{key} is text, not {type(v).__name__}")
    if len(v) > most:
        raise Refusal(f"{path}.{key} is {most:,} characters at most")
    return v


def _bool(m, key, default, path):
    v = m.get(key, default)
    if not isinstance(v, bool):
        raise Refusal(f"{path}.{key} is true or false, not {v!r}"[:200])
    return v


def _list(m, key, path):
    v = m.get(key, ())
    if not isinstance(v, (list, tuple)):
        raise Refusal(f"{path}.{key} is a list")
    return tuple(v)


@dataclass(frozen=True)
class ImagePin:
    """An image pinned by digest in its plugin's release: what is pulled, and checked after. `tar`: whether its image
    has tar, pinned with it (a backup before an update is made through the image's own tar; without one an update asks
    accept_no_backup)."""

    ref: str  # "docker.io/jenkins/jenkins:2.528.2-lts-jdk21": registry, repository and tag
    digest: str  # "sha256:" + 64 hex
    system: str = "linux"
    platforms: tuple = ("linux/amd64",)
    os_build: int = 0
    version: str = ""
    size: int = 0  # compressed bytes (0: not known, and the plan says so)
    licence: str = ""
    page: str = ""
    tar: bool = True
    shell: bool | None = None  # 1.95.0: whether the image has a shell (None: not said; a runtime takes `tar` as the sign)

    @property
    def pinned(self) -> str:
        """What is pulled and run: <ref>@<digest>."""
        return f"{self.ref}@{self.digest}"

    def as_dict(self) -> dict:
        d = asdict(self)
        d["platforms"] = list(self.platforms)
        if self.shell is None:  # 1.95.0's word left out unless said: a 1.93.0 spec's sha stays what it was
            d.pop("shell")
        return d

    @property
    def has_shell(self) -> bool:
        """Whether a runtime may run the image's shell (its `shell`, or its `tar` when that is not said)."""
        return self.tar if self.shell is None else self.shell

    @classmethod
    def of(cls, m, path: str = "image") -> "ImagePin":
        _exact_keys(cls, m, path)
        ref = _str(m, "ref", "", path, 255)
        dig = _str(m, "digest", "", path, 80)
        if "@" in ref:
            raise Refusal(f"{path}.ref is a reference without its digest ({ref[:80]}): the digest is its own field")
        if not REF.match(ref):
            raise Refusal(f"{path}.ref is not an image reference: {ref[:80]!r}")
        if not DIGEST.match(dig):
            raise Refusal(f"{path}: {ref} has no digest (sha256: and 64 hexadecimal digits): a tag alone is refused, "
                          "since what it names can change")
        system = _str(m, "system", "linux", path)
        if system not in SYSTEMS:
            raise Refusal(f"{path}.system is linux or windows, not {system!r}")
        platforms = tuple(str(p) for p in _list(m, "platforms", path)) or (f"{system}/amd64",)
        for p in platforms:
            if not PLATFORM.match(p) or not p.startswith(system + "/"):
                raise Refusal(f"{path}.platforms: {p[:40]!r} is not a {system} platform (as {system}/amd64)")
        size = _int(m, "size", 0, path)
        if size < 0:
            raise Refusal(f"{path}.size is 0 or more")
        shell = m.get("shell")
        if shell is not None and not isinstance(shell, bool):
            raise Refusal(f"{path}.shell is true, false or null, not {shell!r}"[:200])
        return cls(ref, dig, system, platforms, _int(m, "os_build", 0, path), _str(m, "version", "", path),
                   size, _str(m, "licence", "", path), _str(m, "page", "", path), _bool(m, "tar", True, path), shell)


@dataclass(frozen=True)
class Port:
    name: str
    container: int
    host: int
    protocol: str = "tcp"
    lan: bool = True  # published on every address (the user's rule); False: on this machine alone
    about: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def of(cls, m, path: str = "port") -> "Port":
        _exact_keys(cls, m, path)
        name = _str(m, "name", "", path)
        if not NAME.match(name):
            raise Refusal(f"{path}.name is lowercase letters, digits and dashes, 16 at most, not {name[:40]!r}")
        container, host = _int(m, "container", 0, path), _int(m, "host", 0, path)
        if not 1 <= container <= 65535:
            raise Refusal(f"{path}: the container's port {container} is 1 to 65535")
        if not PORTS[0] <= host <= PORTS[1]:
            raise Refusal(f"{path}: the host port {host} is outside {PORTS[0]} to {PORTS[1]}")
        protocol = _str(m, "protocol", "tcp", path)
        if protocol not in ("tcp", "udp"):
            raise Refusal(f"{path}.protocol is tcp or udp, not {protocol!r}")
        return cls(name, container, host, protocol, _bool(m, "lan", True, path), _str(m, "about", "", path))


@dataclass(frozen=True)
class Volume:
    name: str
    path: str
    holds: str  # what it holds, said on every plan naming it
    owner: int | None = None
    # 1.95.0: the least it needs, in bytes (0: not said). Never a size given to it: where a runtime asks a size (a
    # Kubernetes claim), the size is yours to set on the container plugin's page (the user, 2026-11-25: "user has to
    # define these things before creating instances"); a plan whose size is below this is refused.
    least: int = 0

    def as_dict(self) -> dict:
        d = asdict(self)
        if not self.least:  # left out unless said: a 1.93.0 spec's sha stays what it was
            d.pop("least")
        return d

    @classmethod
    def of(cls, m, path: str = "volume") -> "Volume":
        _exact_keys(cls, m, path)
        name = _str(m, "name", "", path)
        if not PART.match(name):
            raise Refusal(f"{path}.name is lowercase letters, digits and dashes, 12 at most, not {name[:40]!r}")
        where = _str(m, "path", "", path, 255)
        if not (where.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", where)) or ".." in where.replace("\\", "/").split("/"):
            raise Refusal(f"{path}.path is the image's own absolute path, with no '..': not {where[:80]!r}")
        holds = _str(m, "holds", "", path)
        if not holds.strip():
            raise Refusal(f"{path}.holds says what the volume holds (said on every plan naming it)")
        owner = m.get("owner")
        if owner is not None and (isinstance(owner, bool) or not isinstance(owner, int) or owner < 0):
            raise Refusal(f"{path}.owner is a uid (0 or more) or null")
        least = _int(m, "least", 0, path)
        if least < 0:
            raise Refusal(f"{path}.least is 0 or more bytes")
        return cls(name, where, holds, owner, least)


@dataclass(frozen=True)
class Secret:
    variable: str  # its pair, read through the login: under the owner's stem (JENKINS_...), never LIMINAL_*
    env: str  # handed to the software as this environment variable
    about: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def of(cls, m, path: str = "secret") -> "Secret":
        _exact_keys(cls, m, path)
        variable, env = _str(m, "variable", "", path), _str(m, "env", "", path)
        if not VARIABLE.match(variable):
            raise Refusal(f"{path}.variable is a pair's name (A-Z, 0-9 and _), not {variable[:40]!r}")
        if not ENV.match(env):
            raise Refusal(f"{path}.env is an environment variable's name, not {env[:40]!r}")
        return cls(variable, env, _str(m, "about", "", path))


@dataclass(frozen=True)
class Seed:
    """Written into a new, empty volume before the first start; never over a file already there."""

    volume: str
    path: str
    text: str
    mode: int = 0o640

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def of(cls, m, path: str = "seed") -> "Seed":
        _exact_keys(cls, m, path)
        rel = _str(m, "path", "", path, 255)
        if not rel or rel.startswith(("/", "\\")) or ".." in rel.replace("\\", "/").split("/") or ":" in rel:
            raise Refusal(f"{path}.path is a path inside its volume, with no '..': not {rel[:80]!r}")
        text = m.get("text", "")
        if not isinstance(text, str):
            raise Refusal(f"{path}.text is text")
        if len(text.encode("utf-8")) > SEED_MOST:
            raise Refusal(f"{path}: a seed is {SEED_MOST // 1024} KB at most")
        mode = _int(m, "mode", 0o640, path)
        if not 0 <= mode <= 0o777:
            raise Refusal(f"{path}.mode is a file's mode, 0 to 0o777")
        return cls(_str(m, "volume", "", path), rel, text, mode)


@dataclass(frozen=True)
class Readable:
    """A file its owner may read back through hosted_file, by this name alone."""

    name: str
    volume: str
    path: str
    about: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def of(cls, m, path: str = "readable") -> "Readable":
        _exact_keys(cls, m, path)
        name = _str(m, "name", "", path)
        if not PART.match(name):
            raise Refusal(f"{path}.name is lowercase letters, digits and dashes, 12 at most")
        rel = _str(m, "path", "", path, 255)
        if not rel or rel.startswith(("/", "\\")) or ".." in rel.replace("\\", "/").split("/"):
            raise Refusal(f"{path}.path is a path inside its volume, with no '..'")
        return cls(name, _str(m, "volume", "", path), rel, _str(m, "about", "", path))


@dataclass(frozen=True)
class Health:
    """The base's own check, from this machine: an http GET answering below 500 at that port's "here"; no path: a TCP
    connect."""

    port: str = ""
    path: str = ""
    ready_s: float = 300.0

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def of(cls, m, path: str = "health") -> "Health":
        _exact_keys(cls, m, path)
        p = _str(m, "path", "", path, 200)
        if p and not p.startswith("/"):
            raise Refusal(f"{path}.path begins with /")
        ready = _num(m, "ready_s", 300.0, path)
        if not 1.0 <= ready <= 3600.0:
            raise Refusal(f"{path}.ready_s is 1 to 3,600 seconds")
        return cls(_str(m, "port", "", path), p, ready)


@dataclass(frozen=True)
class Part:
    """One container of a service: its server, or an agent or worker beside it (the user, 2026-11-25: "Containers
    too")."""

    name: str
    image: ImagePin
    ports: tuple = ()
    volumes: tuple = ()
    env: Mapping = field(default_factory=dict)  # plain settings only: never a secret's value
    secrets: tuple = ()
    seeds: tuple = ()
    readable: tuple = ()
    memory: int = 0  # bytes at most: required, MEMORY_LEAST at least
    cpus: float = 0.0
    shm: int = 0
    hostname: str = ""
    command: tuple = ()
    health: Health | None = None
    stop_s: int = 30

    def as_dict(self) -> dict:
        return {"name": self.name, "image": self.image.as_dict(), "ports": [p.as_dict() for p in self.ports],
                "volumes": [v.as_dict() for v in self.volumes], "env": dict(self.env),
                "secrets": [s.as_dict() for s in self.secrets], "seeds": [s.as_dict() for s in self.seeds],
                "readable": [r.as_dict() for r in self.readable], "memory": self.memory, "cpus": self.cpus,
                "shm": self.shm, "hostname": self.hostname, "command": list(self.command),
                "health": self.health.as_dict() if self.health is not None else None, "stop_s": self.stop_s}

    @classmethod
    def of(cls, m, path: str = "part") -> "Part":
        _exact_keys(cls, m, path)
        name = _str(m, "name", "", path)
        if not PART.match(name):
            raise Refusal(f"{path}.name is lowercase letters, digits and dashes, 12 at most, not {name[:40]!r}")
        img = m.get("image")
        if isinstance(img, Mapping) and "steps" in img:
            raise Refusal(f"{path}: an image built here (a Build) comes later (decision 14): pin a maker's image by "
                          "digest")
        image = ImagePin.of(img, f"{path}.image")
        lists = {k: _list(m, k, path) for k in ("ports", "volumes", "secrets", "seeds", "readable", "command")}
        for k, items in lists.items():
            if len(items) > MOST[k]:
                raise Refusal(f"{path}: {MOST[k]} {k} at most, not {len(items)}")
        env = m.get("env", {})
        if not isinstance(env, Mapping):
            raise Refusal(f"{path}.env is an object of settings")
        if len(env) > MOST["env"]:
            raise Refusal(f"{path}: {MOST['env']} settings at most, not {len(env)}")
        for k, v in env.items():
            if not isinstance(k, str) or not ENV.match(k):
                raise Refusal(f"{path}.env: {str(k)[:40]!r} is not an environment variable's name")
            if not isinstance(v, str) or len(v) > ENV_CHARS:
                raise Refusal(f"{path}.env.{k} is text of {ENV_CHARS:,} characters at most")
            if k.startswith("LIMINAL_"):
                raise Refusal(f"{path}.env.{k}: Liminal's own variables never reach a container")
        memory = _int(m, "memory", 0, path)
        if memory < MEMORY_LEAST:
            raise Refusal(f"{path}: every part has a memory limit of {MEMORY_LEAST >> 20} MB at least"
                          + (f", not {memory >> 20} MB" if memory else ": none was given"))
        cpus = _num(m, "cpus", 0.0, path)
        if not 0.0 <= cpus <= 256.0:
            raise Refusal(f"{path}.cpus is 0 (no limit) to 256")
        shm = _int(m, "shm", 0, path)
        if shm < 0:
            raise Refusal(f"{path}.shm is 0 or more")
        hostname = _str(m, "hostname", "", path, 63)
        if hostname and not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", hostname):
            raise Refusal(f"{path}.hostname is one label of letters, digits and dashes")
        command = tuple(lists["command"])
        if any(not isinstance(c, str) or len(c) > 1024 for c in command):
            raise Refusal(f"{path}.command is a list of words, each 1,024 characters at most")
        stop_s = _int(m, "stop_s", 30, path)
        if not 1 <= stop_s <= 600:
            raise Refusal(f"{path}.stop_s is 1 to 600 seconds")
        health = m.get("health")
        return cls(name, image, tuple(Port.of(x, f"{path}.ports[{i}]") for i, x in enumerate(lists["ports"])),
                   tuple(Volume.of(x, f"{path}.volumes[{i}]") for i, x in enumerate(lists["volumes"])), dict(env),
                   tuple(Secret.of(x, f"{path}.secrets[{i}]") for i, x in enumerate(lists["secrets"])),
                   tuple(Seed.of(x, f"{path}.seeds[{i}]") for i, x in enumerate(lists["seeds"])),
                   tuple(Readable.of(x, f"{path}.readable[{i}]") for i, x in enumerate(lists["readable"])),
                   memory, cpus, shm, hostname, command,
                   Health.of(health, f"{path}.health") if health is not None else None, stop_s)


@dataclass(frozen=True)
class ServiceSpec:
    """What a service plugin hands a container plugin: one spec per system its service runs on."""

    owner: str
    name: str
    title: str
    system: str
    parts: tuple
    v: int = SPEC_V

    @property
    def sid(self) -> str:
        return f"{self.owner}/{self.name}"

    def as_dict(self) -> dict:
        return {"owner": self.owner, "name": self.name, "title": self.title, "system": self.system,
                "parts": [p.as_dict() for p in self.parts], "v": self.v}

    def sha(self) -> str:
        raw = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def part(self, name: str) -> Part | None:
        return next((p for p in self.parts if p.name == name), None)

    def ports(self) -> list[Port]:
        return [p for part in self.parts for p in part.ports]

    def lan_ports(self) -> list[Port]:
        return [p for p in self.ports() if p.lan]

    def volumes(self) -> list[Volume]:
        return [v for part in self.parts for v in part.volumes]

    def secrets(self) -> list[Secret]:
        return [s for part in self.parts for s in part.secrets]

    def problems(self) -> list[str]:
        """What is wrong with a spec made in code ([] when it is sound): `of` of its own dict."""
        try:
            ServiceSpec.of(self.as_dict())
        except Refusal as e:
            return [str(e)]
        return []

    @classmethod
    def of(cls, m) -> "ServiceSpec":
        """A spec from what crossed an ask, refused in words (a Refusal) before any plan is made: see the design's
        §3.3. Every name made from its names, `...-previous` included, stays within the 63 characters LXD and
        Kubernetes hold names to."""
        if isinstance(m, ServiceSpec):
            m = m.as_dict()
        _exact_keys(cls, m, "spec")
        out: list[str] = []
        _texts({k: v for k, v in m.items() if k != "parts"}, "spec", out)
        for i, part in enumerate(_list(m, "parts", "spec")):
            if isinstance(part, Mapping):
                _texts({k: v for k, v in part.items() if k != "seeds"}, f"spec.parts[{i}]", out)
                _texts(part.get("seeds", ()), f"spec.parts[{i}].seeds", out, keep_newlines=True)
        if out:
            raise Refusal(out[0])
        v = _int(m, "v", SPEC_V, "spec")
        if v != SPEC_V:
            raise Refusal(f"spec is version {SPEC_V} here, not {v}: update the library or the plugin")
        owner, name = _str(m, "owner", "", "spec"), _str(m, "name", "", "spec")
        for word, value in (("owner", owner), ("name", name)):
            if not NAME.match(value):
                raise Refusal(f"spec.{word} is lowercase letters, digits and dashes, 16 at most, starting with a "
                              f"letter: not {value[:40]!r}")
        system = _str(m, "system", "", "spec")
        if system not in SYSTEMS:
            raise Refusal(f"spec.system is linux or windows, not {system!r}")
        raw_parts = _list(m, "parts", "spec")
        if not raw_parts:
            raise Refusal("spec has no part: a service is one container at least")
        if len(raw_parts) > MOST["parts"]:
            raise Refusal(f"spec: {MOST['parts']} parts at most")
        parts = tuple(Part.of(p, f"spec.parts[{i}]") for i, p in enumerate(raw_parts))
        spec = cls(owner, name, _str(m, "title", "", "spec", 60) or name, system, parts, v)
        spec._check()
        return spec

    def _check(self) -> None:
        seen_parts, seen_ports, seen_names, seen_volumes, seen_env = set(), set(), set(), set(), set()
        st = stem(self.owner)
        for part in self.parts:
            if part.name in seen_parts:
                raise Refusal(f"spec: the part {part.name} twice")
            seen_parts.add(part.name)
            if part.image.system != self.system:
                raise Refusal(f"spec: {part.name}'s image is a {part.image.system} image, and the spec is for {self.system}")
            own_volumes = {v.name for v in part.volumes}
            for vol in part.volumes:
                if vol.name in seen_volumes:
                    raise Refusal(f"spec: the volume {vol.name} twice (a volume is one part's)")
                seen_volumes.add(vol.name)
            for p in part.ports:
                key = (p.host, p.protocol)
                if key in seen_ports or p.name in seen_names:
                    raise Refusal(f"spec: the port {p.name} ({p.host}/{p.protocol}) twice")
                seen_ports.add(key)
                seen_names.add(p.name)
            envs = set(part.env)
            for s in part.secrets:
                if not s.variable.startswith(st) or s.variable == st:
                    raise Refusal(f"spec: the secret {s.variable} is not under {self.owner}'s stem {st}: a plugin "
                                  "names only its own pairs")
                if s.variable.startswith("LIMINAL_"):
                    raise Refusal(f"spec: the secret {s.variable} is one of Liminal's own variables")
                if s.env in envs:
                    raise Refusal(f"spec: {s.env} is both a setting and a secret")
                envs.add(s.env)
            for seed in part.seeds:
                if seed.volume not in own_volumes:
                    raise Refusal(f"spec: a seed for the volume {seed.volume}, which {part.name} does not have")
            for r in part.readable:
                if r.volume not in own_volumes:
                    raise Refusal(f"spec: the readable {r.name} is in the volume {r.volume}, which {part.name} does "
                                  "not have")
            if part.health is not None and part.health.port and part.health.port not in {p.name for p in part.ports}:
                raise Refusal(f"spec: {part.name}'s health names the port {part.health.port}, which it does not "
                              "publish")
            seen_env |= envs
        for made in (container_name(self.sid, max(seen_parts, key=len)) + "-previous",):
            if len(made) > 63:
                raise Refusal(f"spec: the names made from it would be longer than 63 characters ({made})")


# -- the names and labels every runtime gives what it makes ------------------------------------------------------------
def split_sid(sid: str) -> tuple[str, str]:
    """A service's sid, <owner>/<name>, as its two names: a Refusal when it is not one."""
    owner, _, name = str(sid or "").partition("/")
    if not NAME.match(owner) or not NAME.match(name):
        raise Refusal(f"a service is named <its plugin>/<a name of yours> (jenkins/ci), not {str(sid)[:40]!r}")
    return owner, name


def _flat(sid: str) -> str:
    owner, name = split_sid(sid)
    return f"{owner}-{name}"


def container_name(sid: str, part: str) -> str:
    return f"liminal-{_flat(sid)}-{part}"


def previous_name(sid: str, part: str) -> str:
    return container_name(sid, part) + "-previous"


def volume_name(sid: str, volume: str) -> str:
    return f"liminal-{_flat(sid)}-{volume}"


def network_name(sid: str) -> str:
    return f"liminal-{_flat(sid)}"


def rule_name(sid: str) -> str:
    """Its firewall rule: svc-<owner>-<name>, which Liminal's naming makes `Liminal: svc-jenkins-ci`."""
    return f"svc-{_flat(sid)}"


def labels(spec: ServiceSpec, part: str, role: str, platform: str, made: str, lifecycle: str = "page") -> dict:
    """The labels a service's container carries: what the runtime reads back as the truth."""
    return {"liminal": "service", "liminal.service": spec.sid, "liminal.owner": spec.owner, "liminal.part": part,
            "liminal.role": role, "liminal.lifecycle": lifecycle, "liminal.made": made, "liminal.platform": platform,
            "liminal.spec": json.dumps(spec.as_dict(), sort_keys=True, separators=(",", ":")),
            "liminal.spec-sha": spec.sha()}


def volume_labels(sid: str, volume: str, platform: str, made: str) -> dict:
    owner, _ = split_sid(sid)
    return {"liminal": "volume", "liminal.service": sid, "liminal.owner": owner, "liminal.volume": volume,
            "liminal.platform": platform, "liminal.made": made}


def segment_labels(sid: str, platform: str) -> dict:
    return {"liminal": "segment", "liminal.service": sid, "liminal.platform": platform}


# -- what a container plugin answers -------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Aspect:
    fit: str
    words: str = ""

    def as_dict(self) -> dict:
        return {"fit": self.fit, "words": self.words}


@dataclass(frozen=True)
class Fit:
    """How exactly a target takes a spec, part by part: exact (done as asked), differs (done otherwise: the plan says
    how and asks accept_differs), cannot (that target is not offered for it, and why)."""

    parts: Mapping = field(default_factory=dict)  # aspect -> Aspect
    takes: str = ""  # "" or why this target is not offered for it

    @classmethod
    def judged(cls, aspects: Mapping[str, Aspect]) -> "Fit":
        cannot = [f"{k}: {a.words}" for k, a in aspects.items() if a.fit == "cannot"]
        return cls(dict(aspects), "; ".join(cannot))

    def differs(self) -> list[str]:
        return [f"{k}: {a.words}" for k, a in self.parts.items() if a.fit == "differs"]

    def as_dict(self) -> dict:
        return {"takes": self.takes, "parts": {k: a.as_dict() for k, a in self.parts.items()}}

    @classmethod
    def of(cls, m) -> "Fit":
        if m is None:
            return cls()
        return cls({k: Aspect(str(v.get("fit", "exact")), str(v.get("words", ""))) for k, v in
                    dict(m.get("parts") or {}).items()}, str(m.get("takes", "")))


@dataclass(frozen=True)
class Target:
    """One engine (or cluster) a container plugin can host services on."""

    id: str
    plugin: str
    title: str
    mechanism: str
    system: str
    arch: str = "amd64"
    here: bool = True  # on this machine: only these host services
    state: str = "ready"
    why: str = ""
    reach: str = "127.0.0.1"  # where this machine reaches a published port
    path: str = "direct"  # how a published port meets your network
    lan_words: str = ""
    firewall: str = ""  # which system's firewall decides
    wsl: str = ""  # its WSL distribution, when it runs inside one
    wsl_plugin: str = ""  # the WSL plugin that offers that distribution's engine (asked hold and let_go)
    stack: str = "windows"  # its network stack (segments.STACKS)
    platform: str = ""
    where_data: str = ""  # where its volumes live, in words
    version: str = ""
    os_build: int = 0  # 1.95.0: a Windows host's build (20348, 26100...): what a Windows pin is chosen by (choose_pin)
    isolation: str = ""  # 1.95.0: a Windows engine's isolation for a pin of its own build ("process" or "hyperv")

    @property
    def ready(self) -> bool:
        return self.here and self.state == "ready"

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def of(cls, m) -> "Target":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in dict(m).items() if k in known})


def choose_pin(pins, target) -> ImagePin:
    """The pin of a part for one target, from the pins a recipe has for it (1.95.0): on a Windows target, the newest pin
    whose os_build is the target's own (process isolation), else the newest one older than it (Hyper-V isolation runs
    an older build on a newer host), else a Refusal in words; on a Linux target, the first pin published for its
    architecture. `pins`: ImagePins or their dicts; `target`: a Target or its dict. A service plugin asks this rather
    than importing a container plugin."""
    got = [p if isinstance(p, ImagePin) else ImagePin.of(p) for p in pins or ()]
    t = target if isinstance(target, Target) else Target.of(target or {})
    if not got:
        raise Refusal("no pin was given to choose from")
    if t.system == "windows":
        build = int(t.os_build or 0)
        mine = [p for p in got if p.system == "windows"]
        if not mine:
            raise Refusal(f"no Windows image is pinned for {t.id or 'this target'}")
        if not build:
            raise Refusal(f"{t.id or 'this target'} does not say its Windows build: no pin is chosen for it")
        same = [p for p in mine if p.os_build == build]
        older = sorted((p for p in mine if 0 < p.os_build < build), key=lambda p: p.os_build)
        if same:
            return same[0]
        if older:
            return older[-1]
        raise Refusal(f"no pinned image runs on Windows build {build}: " + ", ".join(
            f"{p.ref} is for {p.os_build or 'no build said'}" for p in mine[:4]))
    for p in got:
        if p.system == "linux" and any(x.split("/")[1] == t.arch for x in p.platforms):
            return p
    raise Refusal(f"no pinned Linux image is published for {t.arch}")


# -- what you define on a container plugin's page before any instance (1.95.0) ------------------------------------------
SET_SETTING = "set_target_setting"
SETTING_KINDS = ("text", "number", "size", "choice")
SETTING_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


@dataclass(frozen=True)
class Setting:
    """A place or a size of the user's that a container plugin needs for a target, which Liminal never picks for you
    (the user, 2026-11-25: "user has to define these things before creating instances"): a Kubernetes namespace, a
    storage class, a claim's size. Kept through the login as the container plugin's <NAME>_TARGET_SETTINGS; until each
    `required` one is set, every plan on that target (or, `per_service`, of that service) is refused in words.
    `choices`: what may be picked (the storage classes the cluster has), () for any value its plugin's check takes."""

    name: str  # "namespace"
    label: str  # "Namespace"
    about: str = ""
    kind: str = "text"
    per_service: bool = False  # one value per service on that target (a claim's size)
    required: bool = True
    choices: tuple = ()
    example: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        d["choices"] = list(self.choices)
        return d

    @classmethod
    def of(cls, m) -> "Setting":
        if isinstance(m, Setting):
            return m
        _exact_keys(cls, m, "setting")
        s = cls(**{**dict(m), "choices": tuple(m.get("choices") or ())})
        if not SETTING_NAME.match(s.name) or s.kind not in SETTING_KINDS:
            raise Refusal(f"a setting is named a-z, 0-9 and _ and is one of {', '.join(SETTING_KINDS)}: not "
                          f"{s.name[:32]!r} ({s.kind[:16]!r})")
        return s


SIZE = re.compile(r"^([1-9][0-9]{0,6})(Mi|Gi|Ti)$")
_SIZE_UNITS = {"Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40}


def size_bytes(text: str) -> int:
    """A size as you set it (20Gi; Mi, Gi or Ti) in bytes; a Refusal in words otherwise."""
    m = SIZE.match(str(text or "").strip())
    if not m:
        raise Refusal(f"a size is a whole number of Mi, Gi or Ti (20Gi), not {str(text)[:20]!r}")
    return int(m.group(1)) * _SIZE_UNITS[m.group(2)]


# -- 1.95.0: words a runtime answers the base with -----------------------------------------------------------------------
# pull's answer when its engine pulls <ref>@<digest> itself when the container is made (a cluster's kubelet): the base
# says "pulled by its engine by digest" instead of "the digest checked". "" (or any other digest) is still refused.
PULLED_BY_ENGINE = "pulled-by-engine"
# how a runtime backs up a volume before an update (Runtime.backup_kind): through the image's own tar into a file here
# (an image without tar asks accept_no_backup), by the engine's own snapshot (no tar needed; its words kept in a
# <volume>.snapshot.json beside the tars), or not at all (asks accept_no_backup)
BACKUP_KINDS = ("tar", "snapshot", "none")
# A container plugin's own accepts (MORE_ACCEPTS): named accept_<word>, never one of ACCEPTS
MORE_ACCEPT = re.compile(r"^accept_[a-z][a-z0-9_]{1,30}$")

# The stack a target names (segments.STACKS), decided 2026-11-25 for every container plugin: the network stack a
# packet lands in. Every Linux inside WSL 2 shares one VM's stack, so a target there (Docker in Liminal-Ubuntu, LXD or
# k3s in your Ubuntu, from the Windows platform or from the Linux suite inside WSL) is "wsl"; "linux" is a Linux
# machine's own kernel outside WSL; "windows" this PC's own. The firewall plugin of the platform that runs inside WSL
# owns "wsl" (and takes the Linux half of the pool by its platform, segments.NetworkHost._half).
STACK_WORDS = ("wsl: any Linux inside WSL 2 (one VM's network); linux: a Linux machine's own, outside WSL; "
               "windows: this PC's own")


def stack_of(system_is_linux: bool, in_wsl: bool) -> str:
    """The stack a target on this machine names (STACK_WORDS): every container plugin says it alike."""
    return "wsl" if in_wsl else "linux" if system_is_linux else "windows"


def same_part(a: Part, b: Part) -> bool:
    """Whether two parts are the same but for their seeds' texts (a runtime's label leaves those out)."""
    def flat(p: Part) -> dict:
        d = p.as_dict()
        for s in d.get("seeds") or []:
            s["text"] = ""
        return d

    return flat(a) == flat(b)


def labelled_spec_of(rows: list[Mapping]) -> Mapping | None:
    """Of a service's current containers' labels ({"spec": ..., "made": ...} each), the spec the service is now: the
    one with the most parts, then the newest made (a part added by an update is labelled with the whole spec; the
    parts made before keep their older label). A runtime's hosted() answers it as the service's spec."""
    best, key = None, None
    for r in rows:
        spec = r.get("spec")
        if not isinstance(spec, Mapping):
            continue
        k = (len(spec.get("parts") or ()), str(r.get("made") or ""))
        if key is None or k > key:
            best, key = r, k
    return best


def approval_answer(plugin: str, plans: list[str], then: dict | None, said: str) -> dict:
    """What a service plugin answers its page when a change waits for your approval: the plans to approve, in order
    (the container plugin's, then a firewall's), and the job that carries them out once approved. A platform that
    draws the approval dialog (liminal-platform 0.37.0) asks each plan's plan_words, its accepts in turn, then
    approve_plan as the page, then starts `then`; an older one shows `said`."""
    return {"approve": [{"plugin": plugin, "plan": p} if isinstance(p, str) else dict(p) for p in plans],
            "then": then, "said": said, "ok": True}
