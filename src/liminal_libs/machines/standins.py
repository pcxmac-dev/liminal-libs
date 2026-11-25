"""Stand-ins every plugin's tests use for the one service interface (1.93.0), so that no plugin imports another
plugin's tests and no test starts a process, pulls an image, opens a port or runs WSL:

- `FakeDocker`: the docker command as a runner and a streamer (DockerRuntime's), answering from memory: containers,
  volumes, networks and images, each command recorded with the environment and standard input it was given (`calls`).
  `before` runs a test's function before a command (a barrier, to force a race's order); `fail` makes one fail.
- `StandInHost`: a container plugin on ContainerHost with stand-in targets, each on a DockerRuntime over a FakeDocker.
- `StandInNetworkHost`: a firewall plugin on NetworkHost that carries out its steps in memory, counting each
  elevation it would ask (`elevations`).
- `StandInWsl`: a WSL plugin's hold and let_go, recorded.
- `login(pairs)`: a login holding only the pairs given (EnvironmentLogin over its own variables)."""
from __future__ import annotations

import io
import json
import secrets as _secrets
import tarfile
import threading
from pathlib import Path
from typing import Callable

from ..apps.authorization import EnvironmentLogin
from .containerhost import ContainerHost, Outside
from .containers import Target
from .dockerruntime import DockerRuntime
from .plugin import MachinePlugin
from .segments import NetworkHost, Step


def login(pairs: dict | None = None) -> EnvironmentLogin:
    """A login holding the pairs given alone (none of this user's)."""
    return EnvironmentLogin(env=dict(pairs or {}))


def _labels_of(args: list[str]) -> dict:
    out = {}
    for i, a in enumerate(args):
        if a == "--label" and i + 1 < len(args):
            k, _, v = args[i + 1].partition("=")
            out[k] = v
    return out


def _opt(args: list[str], name: str, default=None):
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            return args[i + 1]
    return default


def _opts(args: list[str], name: str) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == name and i + 1 < len(args)]


class FakeDocker:
    """The docker command, answered from memory. Call it as DockerRuntime's runner; `stream` is its streamer."""

    VALUED = ("--name", "--label", "--restart", "--memory", "--cpus", "--shm-size", "--hostname", "--network", "--ip",
              "--network-alias", "--add-host", "-p", "-v", "-e", "--entrypoint", "-t", "--filter", "--format",
              "--driver", "--subnet", "--gateway", "--ip-range", "-o", "--type", "-C")

    def __init__(self, version: str = "28.5.1", arch: str = "amd64"):
        self.lock = threading.RLock()
        self.version, self.arch = version, arch
        self.containers: dict[str, dict] = {}
        self.volumes: dict[str, dict] = {}
        self.networks: dict[str, dict] = {}
        self.images: dict[str, str] = {}  # pinned ref -> its digest as found after a pull
        self.calls: list[dict] = []
        self.before: dict[str, Callable] = {}  # a command's first word (or two: "volume create") -> fn(argv)
        self.fail: dict[str, str] = {}  # a command -> the words it fails with
        self.exits_on_start: dict[str, int] = {}  # a container name -> the code it exits with when started
        self.pulled_as: dict[str, str] = {}  # a pinned ref -> the digest a pull finds instead
        self.logs: dict[str, list[str]] = {}

    # -- the runner -------------------------------------------------------------------------------------------------
    def _words(self, argv) -> list[str]:
        argv = [str(a) for a in argv]
        i = next((k for k, a in enumerate(argv) if a.rsplit("/", 1)[-1].lower() in ("docker", "docker.exe")), -1)
        return argv[i + 1:]

    def _key(self, args: list[str]) -> str:
        if args and args[0] in ("volume", "network", "image") and len(args) > 1:
            return f"{args[0]} {args[1]}"
        return args[0] if args else ""

    def __call__(self, argv, timeout, stdin=None, env=None, binary=False, out=None):
        args = self._words(argv)
        key = self._key(args)
        self.calls.append({"argv": [str(a) for a in argv], "env": dict(env or {}), "stdin": stdin, "key": key})
        fn = self.before.get(key)
        if fn is not None:
            fn(args)
        if key in self.fail:
            return 1, b"" if binary else "", f"Error: {self.fail[key]}"
        with self.lock:
            code, text, err = self._answer(key, args, stdin, env or {}, out)
        if binary and isinstance(text, str):
            text = text.encode("utf-8")
        return code, text, err

    def stream(self, argv, timeout, line, stop=None):
        args = self._words(argv)
        self.calls.append({"argv": [str(a) for a in argv], "env": {}, "stdin": None, "key": "pull"})
        fn = self.before.get("pull")
        if fn is not None:
            fn(args)
        if "pull" in self.fail:
            return 1, f"Error: {self.fail['pull']}"
        ref = args[-1]
        for n in range(3):
            if stop is not None and stop():
                from ..docker import DockerError

                raise DockerError(f"docker pull {ref} was asked to stop: stopped")
            line(f"layer {n}: Pull complete")
        with self.lock:
            self.images[ref] = self.pulled_as.get(ref, ref.split("@", 1)[1] if "@" in ref else "")
        line(f"Digest: {self.images[ref]}")
        return 0, ""

    # -- the answers ----------------------------------------------------------------------------------------------------
    def _find(self, name: str) -> dict | None:
        c = self.containers.get(name)
        if c is not None:
            return c
        return next((c for c in self.containers.values() if c["id"].startswith(name) and len(name) >= 12), None)

    def _inspect_container(self, c: dict) -> dict:
        nets = {}
        if c.get("network"):
            nets[c["network"]] = {"IPAddress": c.get("ip", "")}
        return {"Id": c["id"], "Name": "/" + c["name"],
                "Config": {"Labels": dict(c["labels"]), "Image": c["image"], "Env": list(c["env_names"])},
                "State": {"Status": c["state"], "ExitCode": c.get("exit", 0), "StartedAt": c.get("started", "")},
                "Mounts": [{"Type": "volume", "Name": v, "Destination": p} for v, p in c["mounts"]],
                "NetworkSettings": {"Networks": nets}, "HostConfig": {"RestartPolicy": {"Name": c["restart"]}}}

    def _answer(self, key, args, stdin, env, out):
        if key == "version":
            return 0, json.dumps({"Client": {"Version": self.version}, "Server": {"Version": self.version, "Os": "linux",
                                                                                 "Arch": self.arch}}), ""
        if key == "ps":
            rows = [c for c in self.containers.values()
                    if "label=liminal=service" not in args or c["labels"].get("liminal") == "service"]
            if "-q" in args:
                return 0, "\n".join(c["id"] for c in rows), ""
            return 0, "\n".join(json.dumps({"ID": c["id"], "Names": c["name"], "Image": c["image"],
                                            "State": c["state"], "Status": c["state"], "Labels": ",".join(
                                                f"{k}={v}" for k, v in c["labels"].items() if k != "liminal.spec")})
                                for c in rows), ""
        if key == "images":
            return 0, "\n".join(json.dumps({"Repository": ref.split("@", 1)[0].rsplit(":", 1)[0],
                                            "Tag": ref.split("@", 1)[0].rsplit(":", 1)[-1], "ID": digest,
                                            "Size": "300MB"}) for ref, digest in self.images.items()), ""
        if key == "inspect":
            names = [a for a in args[1:] if not a.startswith("-") and a != "container"]
            found = [self._find(n) for n in names]
            got = [self._inspect_container(c) for c in found if c is not None]
            return (0 if all(found) else 1), json.dumps(got), ("" if all(found) else "Error: No such container")
        if key == "volume ls":
            return 0, "\n".join(json.dumps({"Name": n, "Driver": "local"}) for n, v in self.volumes.items()
                                if "label=liminal=volume" not in args or v["labels"].get("liminal") == "volume"), ""
        if key == "volume inspect":
            names = args[2:]
            got = [{"Name": n, "Labels": dict(self.volumes[n]["labels"])} for n in names if n in self.volumes]
            return (0 if len(got) == len(names) else 1), json.dumps(got), ""
        if key == "volume create":
            name = args[-1]
            self.volumes[name] = {"labels": _labels_of(args), "files": {}}
            return 0, name, ""
        if key == "volume rm":
            for n in args[2:]:
                if any(n == v for c in self.containers.values() for v, _ in c["mounts"]):
                    return 1, "", f"Error: volume is in use - {n}"
            for n in args[2:]:
                self.volumes.pop(n, None)
            return 0, "", ""
        if key == "network ls":
            rows = [n for n, x in self.networks.items()
                    if "label=liminal=segment" not in args or x["labels"].get("liminal") == "segment"]
            if "-q" in args:
                return 0, "\n".join(self.networks[n]["id"] for n in rows), ""
            return 0, "\n".join(json.dumps({"Name": n}) for n in rows), ""
        if key == "network inspect":
            got = []
            for want in args[2:]:
                n = next((x for x, v in self.networks.items() if x == want or v["id"] == want), None)
                if n is None:
                    continue
                v = self.networks[n]
                members = {c["id"]: {"Name": c["name"], "IPv4Address": f"{c['ip']}/24" if c.get("ip") else "",
                                     "MacAddress": "02:42:00:00:00:01"}
                           for c in self.containers.values() if c.get("network") == n}
                got.append({"Name": n, "Id": v["id"], "Labels": dict(v["labels"]), "Options": dict(v["options"]),
                            "IPAM": {"Config": [{"Subnet": v["subnet"], "Gateway": v["gateway"]}]},
                            "Containers": members})
            return (0 if len(got) == len(args[2:]) else 1), json.dumps(got), ""
        if key == "network create":
            name = args[-1]
            options = dict(o.partition("=")[::2] for o in _opts(args, "-o"))
            self.networks[name] = {"id": _secrets.token_hex(32), "labels": _labels_of(args), "options": options,
                                   "subnet": _opt(args, "--subnet", ""), "gateway": _opt(args, "--gateway", ""),
                                   "ip_range": _opt(args, "--ip-range", ""), "driver": _opt(args, "--driver", "")}
            return 0, name, ""
        if key == "network rm":
            name = args[-1]
            if name not in self.networks:
                return 1, "", f"Error: network {name} not found"
            del self.networks[name]
            return 0, "", ""
        if key == "image inspect":
            ref = args[-1]
            if ref in self.images:
                repo = ref.split("@", 1)[0].rsplit(":", 1)[0]
                return 0, json.dumps([f"{repo}@{self.images[ref]}"]), ""
            return 1, "[]", f"Error: No such image: {ref}"
        if key == "create":
            return self._create(args, env)
        if key == "start":
            c = self._find(args[-1])
            if c is None:
                return 1, "", "Error: No such container"
            if c["name"] in self.exits_on_start:
                c["state"], c["exit"] = "exited", self.exits_on_start[c["name"]]
            else:
                c["state"], c["exit"], c["started"] = "running", 0, "2026-11-25T10:00:00Z"
            return 0, c["name"], ""
        if key == "stop":
            c = self._find(args[-1])
            if c is None:
                return 1, "", "Error: No such container"
            c["state"], c["exit"] = "exited", 143
            return 0, c["name"], ""
        if key == "rename":
            c = self.containers.pop(args[1], None)
            if c is None:
                return 1, "", "Error: No such container"
            c["name"] = args[2]
            self.containers[args[2]] = c
            return 0, "", ""
        if key == "rm":
            if "-v" in args or "--volumes" in args:
                return 2, "", "the stand-in refuses rm -v: a service's volumes are never removed with it"
            c = self._find(args[-1])
            if c is None:
                return 1, "", "Error: No such container"
            if c["state"] == "running":
                return 1, "", "Error: cannot remove a running container"
            del self.containers[c["name"]]
            return 0, "", ""
        if key == "cp":
            return self._cp(args, stdin)
        if key == "exec":
            c = self._find(args[1])
            if c is None or c["state"] != "running":
                return 1, "", "Error: container is not running"
            data = self._read_path(c, args[-1])
            return (0, data, "") if data is not None else (1, b"", "cat: no such file")
        if key == "logs":
            c = self._find(args[-1])
            if c is None:
                return 1, "", "Error: No such container"
            n = int(_opt(args, "--tail", "100"))
            return 0, "\n".join(self.logs.get(c["name"], [])[-n:]), ""
        if key == "run":
            return self._run(args, stdin, out)
        return 1, "", f"the stand-in docker knows no {key!r}"

    def _create(self, args, env):
        name = _opt(args, "--name")
        if name in self.containers:
            return 1, "", f"Error: the container name {name} is already in use"
        for bad in ("--privileged", "--cap-add", "--pid", "--ipc", "--userns", "--device"):
            if bad in args:
                return 2, "", f"the stand-in refuses {bad}"
        if _opt(args, "--network") == "host":
            return 2, "", "the stand-in refuses --network host"
        mounts = []
        for v in _opts(args, "-v"):
            vol, _, path = v.partition(":")
            if "/" in vol or "\\" in vol or vol.endswith("docker.sock"):
                return 2, "", "the stand-in refuses a host path"
            if vol not in self.volumes:
                self.volumes[vol] = {"labels": {}, "files": {}}
            mounts.append((vol, path.split(":")[0]))
        env_names = []
        for e in _opts(args, "-e"):
            k, eq, v = e.partition("=")
            if not eq:
                if k not in env:
                    return 1, "", f"the stand-in: {k} is named without a value, and its environment has none"
            env_names.append(k)
        # the image: the first word after the options that is no option's value
        rest, i = [], 1
        while i < len(args):
            if args[i] in self.VALUED:
                i += 2
                continue
            if args[i].startswith("-"):
                i += 1
                continue
            rest = args[i:]
            break
        image = rest[0] if rest else ""
        c = {"id": _secrets.token_hex(32), "name": name, "labels": _labels_of(args), "image": image,
             "state": "created", "exit": 0, "mounts": mounts, "network": _opt(args, "--network", ""),
             "ip": _opt(args, "--ip", ""), "ports": _opts(args, "-p"), "env_names": env_names,
             "restart": _opt(args, "--restart", "no"), "memory": _opt(args, "--memory", ""), "argv": list(args),
             "secret_values": {k: env[k] for k in env_names if k in env}}
        self.containers[name] = c
        return 0, c["id"], ""

    def _volume_at(self, c: dict, path: str):
        best = None
        for vol, mount in c["mounts"]:
            m = mount.rstrip("/")
            if path == m or path.startswith(m + "/"):
                if best is None or len(m) > len(best[1]):
                    best = (vol, m)
        return best

    def _read_path(self, c: dict, path: str):
        found = self._volume_at(c, path)
        if found is None:
            return None
        vol, mount = found
        return self.volumes.get(vol, {}).get("files", {}).get(path[len(mount):].lstrip("/"))

    def _cp(self, args, stdin):
        words = [a for a in args[1:] if a != "-a"]
        src, dst = words[0], words[1]
        if src == "-":
            c = self._find(dst.split(":", 1)[0])
            if c is None:
                return 1, "", "Error: No such container"
            with tarfile.open(fileobj=io.BytesIO(stdin or b""), mode="r:") as tar:
                for m in tar.getmembers():
                    if not m.isfile():
                        continue
                    path = "/" + m.name
                    found = self._volume_at(c, path)
                    if found is None:
                        return 1, "", f"the stand-in writes seeds into volumes alone, not {path}"
                    vol, mount = found
                    rel = path[len(mount):].lstrip("/")
                    files = self.volumes[vol]["files"]
                    if rel in files:
                        return 1, "", f"the stand-in: {path} is there already"
                    files[rel] = tar.extractfile(m).read()
                    self.volumes[vol].setdefault("owners", {})[rel] = (m.uid, m.mode)
            return 0, "", ""
        c = self._find(src.split(":", 1)[0])
        if c is None:
            return 1, b"", "Error: No such container"
        data = self._read_path(c, src.split(":", 1)[1])
        if data is None:
            return 1, b"", "Error: no such file"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(src.rsplit("/", 1)[-1])
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return 0, buf.getvalue(), ""

    def _run(self, args, stdin, out):
        if "--rm" not in args:
            return 2, "", "the stand-in runs throwaway containers alone (--rm)"
        entry = _opt(args, "--entrypoint")
        vol = _opt(args, "-v", "").split(":")[0]
        if vol not in self.volumes:
            return 1, "", f"Error: no volume {vol}"
        files = self.volumes[vol]["files"]
        if entry == "tar" and "-cf" in args:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tar:
                for rel, data in sorted(files.items()):
                    info = tarfile.TarInfo(rel)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            if out:
                Path(out).write_bytes(buf.getvalue())
                return 0, b"", ""
            return 0, buf.getvalue(), ""
        if entry == "find":
            files.clear()
            return 0, "", ""
        if entry == "tar" and "-xf" in args:
            with tarfile.open(fileobj=io.BytesIO(stdin or b""), mode="r:") as tar:
                for m in tar.getmembers():
                    if m.isfile():
                        files[m.name] = tar.extractfile(m).read()
            return 0, "", ""
        return 2, "", f"the stand-in runs no {entry!r}"

    # -- for tests ------------------------------------------------------------------------------------------------------
    def argv_of(self, key: str) -> list[list[str]]:
        return [c["argv"] for c in self.calls if c["key"] == key]

    def changes(self) -> list[str]:
        reads = ("ps", "inspect", "volume ls", "volume inspect", "network ls", "network inspect", "image inspect",
                 "logs", "version", "exec")
        return [c["key"] for c in self.calls if c["key"] not in reads and not (c["key"] == "cp" and c["stdin"] is None)]


class StandInHost(ContainerHost):
    """A container plugin on stand-in targets: {target id: (Target, FakeDocker)}."""

    name, title, about, api, order = "standin-host", "A stand-in host", "a stand-in container plugin", "2.2", 990
    RUNTIME = "docker"

    def __init__(self, targets: dict | None = None, outside: Outside | None = None, name: str | None = None):
        out = outside or Outside(sleep=lambda s: None, health=lambda h, p, path: True, platform="windows::TEST")
        if out.folder is None:  # a stand-in never writes into the platform's own folder
            import tempfile

            out.folder = Path(tempfile.mkdtemp(prefix="liminal-standin-"))
        ContainerHost.__init__(self, out)
        if name:
            self.name = name
        self.fakes: dict[str, FakeDocker] = {}
        self._targets: dict[str, Target] = {}
        for tid, (target, fake) in (targets or {}).items():
            self._targets[tid], self.fakes[tid] = target, fake

    def runtime_targets(self) -> list[Target]:
        return list(self._targets.values())

    def runtime_of(self, target: Target) -> DockerRuntime:
        fake = self.fakes[target.id]
        return DockerRuntime(["docker"], fake, fake.stream, version=fake.version, arch=fake.arch,
                             wsl=bool(target.wsl), lan=(target.path, target.lan_words), where_data=target.where_data)

    def present(self) -> bool:
        """Always there: a stand-in."""
        return True

    def status(self) -> dict:
        """Valid, with nothing to say: a stand-in's status."""
        return {"present": True, "valid": True, "summary": "", "why": "", **self.service_status()}


def target(tid: str = "wsl-ubuntu", plugin: str = "standin-host", **kw) -> Target:
    """A ready stand-in target: Docker inside Liminal-Ubuntu under WSL's NAT by default."""
    base = dict(id=tid, plugin=plugin, title=f"Docker 28 in {tid}", mechanism="docker", system="linux",
                state="ready", reach="127.0.0.1", path="wsl-nat", stack="wsl", firewall="windows",
                lan_words="Windows reaches it at 127.0.0.1 through WSL's relay; your network does not (WSL's NAT)",
                where_data="inside Liminal-Ubuntu's virtual disk (unregistering Liminal-Ubuntu deletes it)",
                wsl="Liminal-Ubuntu", wsl_plugin="wsl-standin")
    base.update(kw)
    return Target(**base)


class StandInNetworkHost(NetworkHost):
    """A firewall plugin's network part, its steps carried out in memory: each plan's steps one elevation."""

    name, title, about, api, order = "standin-firewall", "A stand-in firewall", "a stand-in firewall", "2.2", 991

    def __init__(self, own: str = "windows", routes_to=("wsl",), hop: str = "172.31.0.5", **kw):
        NetworkHost.__init__(self, platform="windows::TEST", **kw)
        self.own, self.routes, self.hop = own, tuple(routes_to), hop
        self.ran: list[list[dict]] = []
        self.elevations = 0
        self.here_networks: list[str] = ["192.168.50.0/24", "172.31.0.0/20", "172.27.144.0/20"]
        self.before_steps: Callable | None = None

    def present(self) -> bool:
        """Always there: a stand-in."""
        return True

    def status(self) -> dict:
        """Valid, with nothing to say: a stand-in's status."""
        return {"present": True, "valid": True, "summary": "", "why": ""}

    def stacks(self) -> dict:
        return {"own": self.own, "routes_to": self.routes}

    def networks_here(self) -> list[str]:
        return list(self.here_networks)

    def next_hop(self, stack: str):
        if stack in self.routes and self.hop:
            return self.hop, 42, ""
        return "", 0, f"no {stack} VM runs now"

    def run_steps(self, steps: list[Step], line, cancelled) -> None:
        if self.before_steps is not None:
            self.before_steps(steps)
        self.elevations += 1
        self.ran.append([s.as_dict() for s in steps])
        for s in steps:
            line(f"done: {s.words}")


class StandInWsl(MachinePlugin):
    """A WSL plugin's hold and let_go (PLUGIN_ONLY), recorded."""

    name, title, about, api, order = "wsl-standin", "A stand-in WSL plugin", "a stand-in", "2.2", 992
    HOOKS = (*MachinePlugin.HOOKS, "hold", "let_go")
    PLUGIN_ONLY_HOOKS = ("hold", "let_go")

    def __init__(self):
        self.asked: list[tuple[str, str]] = []

    def present(self) -> bool:
        """Always there: a stand-in."""
        return True

    def status(self) -> dict:
        """Valid, with nothing to say: a stand-in's status."""
        return {"present": True, "valid": True, "summary": "", "why": ""}

    def hold(self, distribution):
        """The distribution held up: recorded."""
        self.asked.append(("hold", distribution))
        return {"ok": True}

    def let_go(self, distribution):
        """The distribution let go: recorded."""
        self.asked.append(("let_go", distribution))
        return {"ok": True}


class ServiceOwner(MachinePlugin):
    """A service plugin's stand-in: asks a container plugin's hooks through its app, as its owner (`call`)."""

    api, order = "2.2", 993
    about = "a stand-in service plugin"

    def __init__(self, name: str = "jenkins", host: str = "standin-host"):
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "title", name.capitalize())
        self.host = host

    def present(self) -> bool:
        """Always there: a stand-in."""
        return True

    def status(self) -> dict:
        """Valid, with nothing to say: a stand-in's status."""
        return {"present": True, "valid": True, "summary": "", "why": ""}

    def call(self, hook: str, *args, plugin: str | None = None):
        """`hook` of the container plugin (or `plugin`) asked through its app, as the frame's ask(name, hook, *args) or
        the platform's ask(name, hook, args) takes it."""
        import inspect

        try:
            spread = inspect.signature(self.app.ask).parameters.get("args")
        except (TypeError, ValueError):
            spread = None
        if spread is not None and spread.kind is inspect.Parameter.VAR_POSITIONAL:
            return self.app.ask(plugin or self.host, hook, *args)
        return self.app.ask(plugin or self.host, hook, list(args))


ACCEPTS_ALL = {"accept_lan": True, "accept_kept_secret": True, "accept_differs": True, "accept_no_backup": True,
               "accept_data": True}


def conformance(owner: ServiceOwner, page: Callable, spec: dict, target_id: str, wait: Callable[[str], dict],
                accepts: dict | None = None) -> list[str]:
    """The one sequence every container plugin's tests run on its recorded answers: install, its state, stop, start,
    expose (closed, then open), update (healthy), rollback, remove keeping the data, install again finding it, remove,
    and delete_data. `owner` asks as the service's plugin; `page(plugin, hook, *args)` asks as the page; `wait(work)`
    waits for a work's end and answers its last page. Each step's name is answered once it held; an AssertionError
    names the one that did not."""
    import copy

    sid = f"{spec['owner']}/{spec['name']}"
    done: list[str] = []
    yes = dict(ACCEPTS_ALL if accepts is None else accepts)

    def carry(action, spec_=None, target="", options=None):
        plan = owner.call("service_plan", action, sid, spec_, target, options or {})
        assert plan.get("plan") and not plan.get("refused"), f"{action}: no plan: {plan}"
        for a in plan["approve"]:
            words = page(a["plugin"], "plan_words", a["plan"])
            names = [x["name"] for x in words.get("accepts") or []]
            args = {k: yes.get(k, False) for k in names}
            page(a["plugin"], "approve_plan", a["plan"], *[args.get(k, False) for k in words["approve_args"]])
        work = owner.call("apply_plan", plan["plan"])["work"]
        end = wait(work)
        assert end.get("done") and end.get("ok"), f"{action}: the work did not end well: {end}"
        done.append(action)
        return end

    def state():
        return owner.call("hosted", sid)["state"]

    carry("install", spec, target_id)
    assert state() == "running", "install: not running"
    carry("stop")
    assert state() == "stopped", "stop: not stopped"
    carry("start")
    assert state() == "running", "start: not running"
    carry("expose", None, "", {"lan": False})
    carry("expose", None, "", {"lan": True})
    newer = copy.deepcopy(spec)
    for p in newer["parts"]:
        p["image"]["digest"] = "sha256:" + "b" * 64
    carry("update", newer)
    assert state() == "running", "update: not running"
    carry("rollback", None, "", {"choice": "as-is"})
    carry("remove")
    assert state() == "missing", "remove: still there"
    carry("install", spec, target_id)
    carry("remove")
    carry("delete_data", None, "", {"backups": "delete"})
    done.append("conformance")
    return done


# approve_plan's accepts, in its arguments' order: a container plugin's, then a firewall's
_ACCEPT_ORDER = {True: ("accept_lan", "accept_kept_secret", "accept_differs", "accept_boot", "accept_no_backup",
                        "accept_data"),
                 False: ("accept_lan", "accept_shared", "accept_wan")}
