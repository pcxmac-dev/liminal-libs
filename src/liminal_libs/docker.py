"""Docker in the framework (the user, 2026-11-07: "i want to integrate docker with the liminal framework";
2026-11-06: "the container or email server, would be responsible for services rendered outside the local
domain"): the containers an app or a plugin needs (a mail server, a database), declared as a `Service`,
run and stopped with the app, on this machine's Docker or another's through a Docker context (a VPS over
SSH: `docker context create vps --docker host=ssh://user@vps`). Everything goes through the docker command
itself, windowless, so nothing here needs a package; a test's stand-in runner answers in its place. The
rule of the plugin lifecycle holds: nothing runs when nothing uses it (an app stops its services when it
stops, unless told to leave them)."""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field, replace

CONTEXT_VAR = "LIMINAL_DOCKER_CONTEXT"  # a docker context's name (`docker context ls`): where the containers run
HOST_VAR = "LIMINAL_DOCKER_HOST"  # or a Docker host outright: ssh://user@vps, tcp://host:2376, npipe:////./pipe/docker_engine
COMMAND_VAR = "LIMINAL_DOCKER_COMMAND"  # the command: docker (Docker Desktop, Rancher Desktop's dockerd), nerdctl (Rancher's containerd), podman
TIMEOUT_S = 120.0


class DockerError(Exception):
    pass


@dataclass(frozen=True)
class Instance:
    """A Docker engine the framework may use, by name (the user, 2026-11-07: "allow different docker instances
    to support the liminal framework"): this machine's (`local`), a context's (`context:<name>`), a host's, or
    one a machine plugin runs (`wsl-ubuntu`: `wsl -d Ubuntu docker`). `translate` turns a host path into the
    engine's own view of it (a Windows path under WSL: /mnt/c/...)."""

    name: str
    where: str
    command: str = "docker"
    context: str = ""
    host: str = ""
    source: str = ""  # what offers it: the machine, a context, a plugin's name
    translate: object = None  # callable(host path) -> the engine's path, when they differ

    def describe(self) -> dict:
        return {"name": self.name, "where": self.where, "command": self.command, "context": self.context, "host": self.host,
                "source": self.source}


@dataclass(frozen=True)
class Service:
    """A container an app needs, as `docker run` would make it."""

    name: str
    image: str
    ports: tuple[str, ...] = ()  # "25:25", "127.0.0.1:8025:25"
    env: dict = field(default_factory=dict)
    volumes: tuple[str, ...] = ()  # "C:/data/mail:/data", "maildata:/data" (a named volume)
    hostname: str = ""
    restart: str = "unless-stopped"
    command: tuple[str, ...] = ()
    labels: dict = field(default_factory=dict)

    def run_args(self) -> list[str]:
        out = ["run", "-d", "--name", self.name]
        if self.restart:
            out += ["--restart", self.restart]
        if self.hostname:
            out += ["--hostname", self.hostname]
        for p in self.ports:
            out += ["-p", p]
        for k, v in self.env.items():
            out += ["-e", f"{k}={v}"]
        for v in self.volumes:
            out += ["-v", v]
        for k, v in {"liminal": "service", **self.labels}.items():
            out += ["--label", f"{k}={v}"]
        return [*out, self.image, *self.command]

    def describe(self) -> dict:
        return {"name": self.name, "image": self.image, "ports": list(self.ports), "volumes": list(self.volumes),
                "hostname": self.hostname, "restart": self.restart, "env": sorted(self.env), "command": list(self.command)}


@dataclass(frozen=True)
class Container:
    """A container as `docker ps` lists it."""

    id: str
    name: str
    image: str
    state: str  # created, running, paused, restarting, exited, dead
    status: str  # "Up 3 minutes (healthy)", "Exited (1) 2 hours ago"
    ports: str = ""

    @property
    def running(self) -> bool:
        return self.state == "running"

    @classmethod
    def from_ps(cls, row: dict) -> "Container":
        return cls(id=row.get("ID", ""), name=row.get("Names", ""), image=row.get("Image", ""),
                   state=row.get("State", ""), status=row.get("Status", ""), ports=row.get("Ports", ""))

    def describe(self) -> dict:
        return {"id": self.id, "name": self.name, "image": self.image, "state": self.state, "status": self.status,
                "ports": self.ports, "running": self.running}


class Docker:
    """The docker command, on this machine or where a context or host says (`where`). `runner(args,
    timeout) -> (code, stdout, stderr)` stands in for the command in tests."""

    def __init__(self, context: str | None = None, host: str | None = None, runner=None, log=None, env=None, command: str | None = None,
                 translate=None):
        env = os.environ if env is None else env
        self.context = (context or env.get(CONTEXT_VAR) or "").strip() or None
        self.host = (host or env.get(HOST_VAR) or "").strip() or None
        self._runner = runner
        self.log = log or (lambda m: None)
        # the command, with a prefix when the engine is reached through another program: `wsl -d Ubuntu docker`
        self.argv = shlex.split((command or env.get(COMMAND_VAR) or "docker").strip() or "docker")
        self.name = self.argv[0]  # the command's name
        self.command = shutil.which(self.name) or self.name  # its path when found
        self.translate = translate  # a host path as the engine sees it (a Windows path under WSL)

    @property
    def where(self) -> str:
        return f"context {self.context}" if self.context else (f"host {self.host}" if self.host else "this machine")

    def installed(self) -> bool:
        return self._runner is not None or shutil.which(self.name) is not None

    def _run(self, *args: str, timeout: float = TIMEOUT_S, check: bool = True, stdin: str | None = None) -> str:
        full = [self.command, *self.argv[1:], *(("--context", self.context) if self.context else ()), *(("-H", self.host) if self.host else ()), *args]
        if self._runner is not None:
            code, out, err = self._runner(full, timeout)
        else:
            if shutil.which(self.name) is None:
                raise DockerError(f"{self.name} is not installed on this machine (Docker Desktop or Rancher Desktop give the docker "
                                  f"command; Rancher's containerd gives nerdctl: {COMMAND_VAR}=nerdctl), and no context or host names "
                                  f"another ({CONTEXT_VAR}, {HOST_VAR})")
            try:
                done = subprocess.run(full, capture_output=True, text=True, timeout=timeout, input=stdin, **_no_window())
            except subprocess.TimeoutExpired:
                raise DockerError(f"{self.name} {' '.join(args[:2])} took more than {timeout:g} s on {self.where}") from None
            except OSError as e:
                raise DockerError(f"{self.name} could not run: {e}") from None
            code, out, err = done.returncode, done.stdout or "", done.stderr or ""
        if code != 0 and check:
            raise DockerError((err or out or f"{self.name} {' '.join(args[:2])} failed ({code})").strip())
        return out

    def available(self) -> bool:
        """Whether the command is there and a Docker engine answers on `where`."""
        if not self.installed():
            return False
        try:
            self.version()
        except DockerError:
            return False
        return True

    def version(self) -> dict:
        """The client's and the engine's versions."""
        raw = self._run("version", "--format", "{{json .}}", timeout=30)
        data = json.loads(raw or "{}")
        client, server = data.get("Client") or {}, data.get("Server") or {}
        if not server:
            raise DockerError(f"no Docker engine answers on {self.where} (is Docker running?)")
        return {"client": client.get("Version", ""), "engine": server.get("Version", ""), "os": server.get("Os", ""),
                "arch": server.get("Arch", ""), "where": self.where}

    def containers(self, all: bool = True) -> list[Container]:
        raw = self._run("ps", *(("-a",) if all else ()), "--no-trunc", "--format", "{{json .}}")
        return [Container.from_ps(json.loads(line)) for line in raw.splitlines() if line.strip().startswith("{")]

    def container(self, name: str) -> Container | None:
        return next((c for c in self.containers() if c.name == name), None)

    def pull(self, image: str) -> str:
        self.log(f"docker: pulling {image} on {self.where}")
        return self._run("pull", image, timeout=600)

    def run(self, service: Service) -> Container:
        """A new container from `service` (it must not be there yet); its volumes' host paths as the engine
        sees them (`translate`)."""
        if self.translate is not None:
            service = replace(service, volumes=tuple(self._volume(v) for v in service.volumes))
        self.log(f"docker: running {service.name} ({service.image}) on {self.where}")
        self._run(*service.run_args(), timeout=600)
        found = self.container(service.name)
        if found is None:
            raise DockerError(f"{service.name} was run but is not listed")
        return found

    def ensure(self, service: Service) -> tuple[Container, str]:
        """The service's container running: made when absent, started when stopped, left when running;
        returns it and what was done (made, started, running)."""
        found = self.container(service.name)
        if found is None:
            return self.run(service), "made"
        if found.running:
            return found, "running"
        self.start(service.name)
        found = self.container(service.name)
        return (found if found is not None else Container("", service.name, service.image, "running", "started")), "started"

    def start(self, name: str) -> None:
        self.log(f"docker: starting {name}")
        self._run("start", name)

    def stop(self, name: str, seconds: int = 20) -> bool:
        """The container stopped (its data kept); False when it is not there."""
        if self.container(name) is None:
            return False
        self.log(f"docker: stopping {name}")
        self._run("stop", "-t", str(seconds), name)
        return True

    def remove(self, name: str, force: bool = False) -> bool:
        if self.container(name) is None:
            return False
        self.log(f"docker: removing {name}")
        self._run("rm", *(("-f",) if force else ()), name)
        return True

    def logs(self, name: str, tail: int = 100) -> str:
        return self._run("logs", "--tail", str(tail), name, check=False)

    def exec(self, name: str, *command: str, stdin: str | None = None) -> str:
        """A command inside the container, its output."""
        return self._run("exec", *(("-i",) if stdin is not None else ()), name, *command, stdin=stdin)

    def inspect(self, name: str) -> dict:
        raw = self._run("inspect", "--format", "{{json .}}", name)
        data = json.loads(raw or "{}")
        return data[0] if isinstance(data, list) and data else data

    def health(self, name: str) -> str:
        """healthy, unhealthy, starting (a container with a health check), else its state."""
        state = self.inspect(name).get("State") or {}
        return (state.get("Health") or {}).get("Status") or state.get("Status", "")

    def compose(self, file: str, *args: str, timeout: float = 600) -> str:
        """`docker compose -f FILE ARGS` (up -d, down, ps, logs)."""
        return self._run("compose", "-f", str(file), *args, timeout=timeout)

    def _volume(self, volume: str) -> str:
        """A -v entry with its host side translated; a named volume (no path) stays."""
        host_side, sep, rest = volume.partition(":")
        if len(volume) > 1 and volume[1] == ":":  # a Windows drive: C:/x:/y
            host_side, sep, rest = volume[:2] + rest.partition(":")[0], ":", rest.partition(":")[2]
        if not sep or not ("/" in host_side or "\\" in host_side):
            return volume
        return f"{self.translate(host_side)}:{rest}"

    @classmethod
    def for_instance(cls, instance: Instance, **kw) -> "Docker":
        return cls(context=instance.context or None, host=instance.host or None, command=instance.command,
                   translate=instance.translate, env={}, **kw)

    def describe(self) -> dict:
        out: dict = {"where": self.where, "command": " ".join(self.argv), "installed": self.installed(), "available": False}
        if not out["installed"] and not self.context and not self.host and os.name == "nt":
            out["wsl"] = wsl()  # what a local engine would run in
        if out["installed"]:
            try:
                out.update(self.version())
                out["available"] = True
            except DockerError as e:
                out["problem"] = str(e)
        return out


def instances(machines=None, env=None) -> list[Instance]:
    """The Docker instances there are, by name: this machine's `local` (the docker command, when installed),
    its contexts (`context:<name>`), one named by LIMINAL_DOCKER_HOST (`host`), and what the machine plugins
    run (`machines`: the registry's unless given)."""
    env = os.environ if env is None else env
    out: list[Instance] = []
    local = Docker(env={}, command=(env.get(COMMAND_VAR) or "docker"))
    if local.installed():
        out.append(Instance("local", "this machine", command=" ".join(local.argv), source="the docker command"))
        try:
            raw = local._run("context", "ls", "--format", "{{json .}}", timeout=30)
            for line in raw.splitlines():
                if line.strip().startswith("{"):
                    row = json.loads(line)
                    name = row.get("Name", "")
                    if name and name != "default":
                        out.append(Instance(f"context:{name}", row.get("DockerEndpoint", "") or f"context {name}",
                                            command=" ".join(local.argv), context=name, source="a docker context"))
        except DockerError:
            pass
    host = (env.get(HOST_VAR) or "").strip()
    if host:
        out.append(Instance("host", host, command=" ".join(local.argv), host=host, source=HOST_VAR))
    if machines is None:
        try:
            from .sources.registry import machines as found

            machines = found().values()
        except Exception:  # noqa: BLE001 - no registry here
            machines = ()
    for m in machines:
        try:
            out.extend(m.instances())
        except Exception as e:  # noqa: BLE001 - one plugin's trouble is not the list's
            out.append(Instance(m.name, f"{m.name}: {type(e).__name__}: {e}", source=m.name))
    return out


def instance(name: str, machines=None, env=None, **kw) -> Docker:
    """The Docker of the instance named (`local`, `context:<name>`, `host`, a machine plugin's)."""
    for i in instances(machines, env):
        if i.name == name:
            return Docker.for_instance(i, **kw)
    raise DockerError(f"no Docker instance named {name!r}: " + (", ".join(i.name for i in instances(machines, env)) or "none at all"))


def wsl() -> dict | None:
    """Windows only: whether WSL 2 is there, which is what Docker Desktop and Rancher Desktop run their Linux
    VM in (the user, 2026-11-07: "a hard constraint for liminal framework, is WSL is required": for containers
    on a Windows PC, not for the framework; a context to another machine needs none). None elsewhere."""
    if os.name != "nt":
        return None
    try:
        done = subprocess.run(["wsl", "--status"], capture_output=True, timeout=15, **_no_window())
    except (OSError, subprocess.SubprocessError):
        return {"present": False, "version": "", "distribution": ""}
    raw = done.stdout or b""
    text = raw.decode("utf-16-le", "ignore") if b"\x00" in raw else raw.decode("utf-8", "ignore")
    fields = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip().lower()] = v.strip()
    return {"present": done.returncode == 0 and bool(text.strip()), "version": fields.get("default version", ""),
            "distribution": fields.get("default distribution", "")}


def command_line(service: Service, command: str = "docker") -> str:
    """What `docker run` (or nerdctl's) would be asked, for a page or a log."""
    return f"{command} " + " ".join(shlex.quote(a) for a in service.run_args())


def _no_window() -> dict:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}  # CREATE_NO_WINDOW: no console pops up
