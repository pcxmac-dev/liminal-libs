"""`DockerRuntime`: the docker command's mapping of the one service interface (1.93.0; service-containers-design §4.1
and the networking design's §5.1). Docker's Linux engines (Docker inside Liminal-Ubuntu, on this PC; a Linux machine's
own dockerd), and later the Windows containers plugin at its pipes and LXD's Docker inside liminal-oci, share it.

Every command goes through the runner its plugin hands it (windowless, its output as text), a test's stand-in
otherwise: `runner(argv, timeout, stdin=None, env=None, binary=False, out=None) -> (code, out, err)`, `stdin` bytes
given to the command, `env` laid over its environment (a secret's value travels there alone), `binary` its output as
bytes, `out` a path its output is written to (a backup). A pull is streamed: `streamer(argv, timeout, line, stop) ->
(code, errors)`. `prefix` is the docker command as its engine is reached (["docker"], or ["wsl", "-d",
"Liminal-Ubuntu", "--exec", "docker"]); through WSL a secret is named in WSLENV (NAME/u) so that it crosses into the
distribution by environment, never on a command line.

What it runs, and nothing else (the plugin's API card names the same):
- read: `info --format {{json .DockerRootDir}}` (where its data lives, 1.95.0), `ps -a --filter label=liminal=service -q`, `inspect --type container`, `volume ls --filter label=liminal=volume`,
  `volume inspect`, `network ls --filter label=liminal=segment -q`, `network inspect`, `image inspect`, `logs --tail
  --timestamps`, `exec <c> cat <path>` (a running container's readable file) and `cp <c>:<path> -` (a stopped one's);
- change, inside an approved plan's work alone: `pull <ref>@<digest>`, `volume create --label ...`, `network create
  --driver bridge --subnet --gateway --ip-range -o com.docker.network.bridge.name=lim-... -o
  com.docker.network.bridge.trusted_host_interfaces=eth0 --label ...`, `create --name --label ... --restart no --memory
  ...`, `cp - <c>:/` (the seeds, a tar on standard input), `start`, `stop -t`, `rename`, `rm` (never -v), `volume rm`,
  `network rm`, and an update's backup and a rollback's restore through the service's own image (`run --rm --network
  none --entrypoint tar` / `find`).
Never `--privileged`, `--cap-add`, a host path, the Docker socket, `--network host`, `--pid`, `--ipc`, `--restart
on-failure` or `unless-stopped` (service mode is not offered yet), `nat-unprotected`, or `docker0`."""
from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from pathlib import Path
from typing import Callable, Mapping

from ..instances import Refusal
from . import containers as C
from .containerhost import Create, Runtime
from .containers import Aspect, Fit, ImagePin, ServiceSpec

READ_S = 60.0
CHANGE_S = 300.0
PULL_S = 1800.0
BACKUP_S = 3600.0
ARGV_MOST = 30000  # characters of one command line at most (Windows holds one to 32,767)
STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) ?(.*)$")
LEAST = (28, 2, 0)  # trusted_host_interfaces: the route from this machine reaches a published port


class DockerFailed(RuntimeError):
    """A docker command that failed, in docker's own last words."""


def version_of(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(text or ""))[:3]) or (0,)


def bridge_name(network: str) -> str:
    """The bridge's name: lim- and 11 hex characters of the network's sha256 (Linux holds one to 15)."""
    return "lim-" + hashlib.sha256(network.encode("utf-8")).hexdigest()[:11]


def _label_args(labels: Mapping) -> list[str]:
    out = []
    for k, v in labels.items():
        out += ["--label", f"{k}={v}"]
    return out


def _labelled_spec(spec: ServiceSpec) -> str:
    """The spec as a container's label holds it: seeds' texts left out (they are written once, at install; the label
    keeps the spec's own sha beside it)."""
    d = spec.as_dict()
    for p in d["parts"]:
        for s in p.get("seeds") or []:
            s["text"] = ""
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


class DockerRuntime(Runtime):
    """One Docker engine's mechanism. `target` its Target; `version` the engine's ("28.5.1"); `trusted`: the interfaces
    routed traffic comes in on (eth0 inside WSL); `lan` (path, words): how a published port meets your network there."""

    mechanism = "docker"

    def __init__(self, prefix, runner: Callable, streamer: Callable | None = None, *, version: str = "",
                 arch: str = "amd64", wsl: bool = False, trusted=("eth0",), lan=("direct", ""),
                 where_data: str = "in the engine's own disk"):
        self.prefix = [str(a) for a in prefix]
        self._runner, self._streamer = runner, streamer
        self.version, self.arch, self.wsl = str(version or ""), str(arch or "amd64"), bool(wsl)
        self.trusted = tuple(trusted)
        self.lan_path, self.lan_words = lan
        self.where_data = where_data

    # -- the runner ----------------------------------------------------------------------------------------------------
    def _argv(self, *args) -> list[str]:
        argv = [*self.prefix, *[str(a) for a in args]]
        if sum(len(a) + 1 for a in argv) > ARGV_MOST:
            raise Refusal(f"docker {args[0] if args else ''}: its command line would be longer than {ARGV_MOST:,} "
                          "characters (its settings or labels are too long)")
        return argv

    def _env(self, secret_env: Mapping[str, str]) -> dict | None:
        if not secret_env:
            return None
        env = dict(secret_env)
        if self.wsl:
            env["WSLENV"] = ":".join(f"{k}/u" for k in secret_env)
        return env

    def run(self, *args, timeout: float = READ_S, check: bool = True, stdin: bytes | None = None,
            env: Mapping | None = None, binary: bool = False, out: str | None = None):
        argv = self._argv(*args)
        code, stdout, stderr = self._runner(argv, timeout, stdin=stdin, env=env, binary=binary, out=out)
        if check and code != 0:
            words = (stderr if isinstance(stderr, str) else (stderr or b"").decode("utf-8", "replace")).strip()
            raise DockerFailed(words.splitlines()[-1] if words else f"docker {args[0]} failed ({code})")
        return code, stdout, stderr

    def _json_lines(self, *args) -> list[dict]:
        _, out, _ = self.run(*args, "--format", "{{json .}}")
        rows = []
        for line in str(out or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
        return rows

    def _inspect(self, kind: str, *names) -> list[dict]:
        if not names:
            return []
        code, out, _ = self.run(*(("inspect", "--type", kind) if kind == "container" else (kind, "inspect")), *names,
                                check=False)
        if code != 0 and not str(out or "").strip().startswith("["):
            return []
        try:
            data = json.loads(out or "[]")
        except ValueError:
            return []
        return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []

    # -- what it reads ------------------------------------------------------------------------------------------------
    def fit(self, spec: ServiceSpec | None) -> Fit:
        aspects: dict[str, Aspect] = {}
        if self.version and version_of(self.version) < LEAST:
            aspects["network"] = Aspect("cannot", f"Docker {self.version} is older than 28.2.0, which a service's own "
                                                  "routed network needs (trusted_host_interfaces)")
        if spec is not None:
            for p in spec.parts:
                if p.image.system != "linux":
                    aspects["image"] = Aspect("cannot", "a Linux engine runs Linux images alone")
                elif not any(x.split("/")[1] == self.arch for x in p.image.platforms):
                    aspects["image"] = Aspect("cannot", f"{p.image.ref} is not published for {self.arch}")
            aspects.setdefault("image", Aspect("exact"))
            aspects.setdefault("ports", Aspect("exact"))
            aspects["volumes"] = Aspect("exact", f"named volumes, {self.where_data}")
            aspects["lifecycle"] = Aspect("exact", "--restart no: it stays stopped through an engine restart")
        return Fit.judged(aspects)

    def _containers(self) -> list[dict]:
        _, out, _ = self.run("ps", "-a", "--no-trunc", "--filter", "label=liminal=service", "-q")
        ids = [x.strip() for x in str(out or "").split() if x.strip()]
        return self._inspect("container", *ids)

    @staticmethod
    def _part_row(c: dict) -> dict:
        name = str(c.get("Name") or "").lstrip("/")
        labels = (c.get("Config") or {}).get("Labels") or {}
        state = c.get("State") or {}
        image = str((c.get("Config") or {}).get("Image") or "")
        return {"name": labels.get("liminal.part", ""), "container": name,
                "role": "previous" if name.endswith("-previous") else "current",
                "state": str(state.get("Status") or ""), "exit": state.get("ExitCode"),
                "health": str((state.get("Health") or {}).get("Status") or ""),
                "image": image.split("@", 1)[0], "digest": image.split("@", 1)[1] if "@" in image else "",
                "since": str(state.get("StartedAt") or "")}

    def hosted(self) -> list[dict]:
        """Liminal's services here by their labels. The service's spec is its current containers' newest whole one
        (containers.labelled_spec_of: a part added by an update carries the whole spec, the parts before keep theirs);
        a previous container's only while no current one is there."""
        by: dict[str, dict] = {}
        labelled: dict[str, list[dict]] = {}
        for c in self._containers():
            labels = (c.get("Config") or {}).get("Labels") or {}
            sid = labels.get("liminal.service", "")
            if not sid:
                continue
            row = by.setdefault(sid, {"sid": sid, "parts": [], "spec": None, "spec_sha": "", "platform": "",
                                      "lifecycle": "page", "made": ""})
            part = self._part_row(c)
            row["parts"].append(part)
            try:
                spec = json.loads(labels.get("liminal.spec") or "null")
            except ValueError:
                spec = None
            labelled.setdefault(sid, []).append({
                "current": part["role"] == "current", "spec": spec, "spec_sha": labels.get("liminal.spec-sha", ""),
                "platform": labels.get("liminal.platform", ""), "lifecycle": labels.get("liminal.lifecycle", "page"),
                "made": labels.get("liminal.made", "")})
        for sid, row in by.items():
            rows = labelled.get(sid) or []
            pick = C.labelled_spec_of([r for r in rows if r["current"]]) or C.labelled_spec_of(rows) or (
                rows[0] if rows else None)
            if pick is not None:
                row.update({k: pick[k] for k in ("spec", "spec_sha", "platform", "lifecycle", "made")})
        return list(by.values())

    def data_root(self) -> str:
        """Where this engine keeps its data (docker info's DockerRootDir), read once: "" when it does not say."""
        if getattr(self, "_root", None) is None:
            code, out, _ = self.run("info", "--format", "{{json .DockerRootDir}}", check=False)
            try:
                got = json.loads(str(out or "").strip() or '""') if code == 0 else ""
            except ValueError:
                got = ""
            self._root = got if isinstance(got, str) else ""
        return self._root

    def volumes(self) -> list[dict]:
        rows = self._json_lines("volume", "ls", "--filter", "label=liminal=volume")
        names = [str(r.get("Name") or "") for r in rows if r.get("Name")]
        details = {str(v.get("Name")): v for v in self._inspect("volume", *names)}
        users: dict[str, list[str]] = {}
        for c in self._containers():
            for m in c.get("Mounts") or []:
                if m.get("Type") == "volume":
                    users.setdefault(str(m.get("Name")), []).append(str(c.get("Name") or "").lstrip("/"))
        out = []
        for n in names:
            labels = (details.get(n) or {}).get("Labels") or {}
            out.append({"name": n, "sid": labels.get("liminal.service", ""), "volume": labels.get("liminal.volume", ""),
                        "made": labels.get("liminal.made", ""), "platform": labels.get("liminal.platform", ""),
                        "used_by": users.get(n, []), "size": ""})
        return out

    def facts(self, spec: ServiceSpec | None, sid: str) -> dict:
        images = {}
        for p in (spec.parts if spec else ()):
            images[p.image.digest] = self.has_image(p.image)
        containers = {}
        for r in self.hosted():
            if r["sid"] == sid:
                for part in r["parts"]:
                    containers[part["container"]] = {"state": part["state"], "role": part["role"],
                                                     "digest": part["digest"]}
        volumes = {v["name"]: {"sid": v["sid"], "used": bool(v["used_by"])} for v in self.volumes()
                   if v["sid"] == sid}
        nets = [s["network"] for s in self.segments() if s.get("sid") == sid]
        return {"images": images, "containers": containers, "volumes": volumes, "networks": sorted(nets)}

    def has_image(self, pin: ImagePin) -> bool:
        code, out, _ = self.run("image", "inspect", "--format", "{{json .RepoDigests}}", pin.pinned, check=False)
        return code == 0

    def state(self, container: str) -> dict | None:
        found = self._inspect("container", container)
        if not found:
            return None
        return self._part_row(found[0])

    def segments(self) -> list[dict]:
        _, out, _ = self.run("network", "ls", "--no-trunc", "--filter", "label=liminal=segment", "-q")
        ids = [x.strip() for x in str(out or "").split() if x.strip()]
        rows = []
        for n in self._inspect("network", *ids):
            labels = n.get("Labels") or {}
            name = str(n.get("Name") or "")
            ipam = [c for c in ((n.get("IPAM") or {}).get("Config") or []) if isinstance(c, dict)]
            members = []
            for _cid, m in dict(n.get("Containers") or {}).items():
                cname = str(m.get("Name") or "")
                part = cname[len(name) + 1:] if cname.startswith(name + "-") else ""
                members.append({"sid": labels.get("liminal.service", ""), "part": part, "container": cname,
                                "mac": str(m.get("MacAddress") or ""),
                                "ipv4": str(m.get("IPv4Address") or "").split("/")[0], "assigned": "reserved"})
            rows.append({"segment": name, "network": name, "kind": "docker-bridge",
                         "bridge": (n.get("Options") or {}).get("com.docker.network.bridge.name", ""),
                         "sid": labels.get("liminal.service", ""), "platform": labels.get("liminal.platform", ""),
                         "subnets": [c.get("Subnet", "") for c in ipam], "gateways": [c.get("Gateway", "") for c in ipam],
                         "trusted": list(self.trusted), "members": members})
        return rows

    def logs(self, container: str, lines: int) -> list[str]:
        _, out, err = self.run("logs", "--tail", str(int(lines)), "--timestamps", container)
        rows = []
        for n, stream in enumerate((str(out or ""), str(err or ""))):
            for i, line in enumerate(stream.splitlines()):
                m = STAMP.match(line)
                rows.append(((m.group(1) if m else ""), n, i, m.group(2) if m else line))
        rows.sort(key=lambda r: (r[0], r[1], r[2]))
        return [(f"{r[0][11:19]} " if r[0] else "") + r[3] for r in rows if r[3].strip()]

    def read(self, container: str, path: str, most: int) -> bytes:
        st = self.state(container) or {}
        if st.get("state") == "running":
            _, out, _ = self.run("exec", container, "cat", path, binary=True)
            return bytes(out or b"")[:most]
        _, out, _ = self.run("cp", f"{container}:{path}", "-", binary=True)
        with tarfile.open(fileobj=io.BytesIO(bytes(out or b"")), mode="r:") as tar:
            member = next((m for m in tar.getmembers() if m.isfile()), None)
            f = tar.extractfile(member) if member is not None else None
            return f.read(most) if f is not None else b""

    def here(self, port: int) -> str:
        return f"127.0.0.1:{port}"

    def lan(self, port: int, protocol: str = "tcp") -> tuple[str, str]:
        return self.lan_path, self.lan_words or "published on every address"

    # -- what it changes, inside an approved plan's work alone ------------------------------------------------------------
    def pull(self, pin: ImagePin, line, cancelled) -> str:
        if self._streamer is None:
            raise Refusal("this engine's pulls are not streamed: no pull is made")
        try:
            code, errors = self._streamer(self._argv("pull", pin.pinned), PULL_S, line, cancelled)
        except Exception:
            if cancelled():
                from .plans import Cancelled

                raise Cancelled(f"the pull of {pin.ref} was cancelled: its child ended") from None
            raise
        if code != 0:
            raise DockerFailed((errors or f"docker pull {pin.ref} failed ({code})").strip().splitlines()[-1])
        _, out, _ = self.run("image", "inspect", "--format", "{{json .RepoDigests}}", pin.pinned)
        try:
            digests = json.loads(str(out or "[]").strip() or "[]")
        except ValueError:
            digests = []
        found = [d.split("@", 1)[1] for d in digests or [] if isinstance(d, str) and "@" in d]
        return pin.digest if pin.digest in found else (found[0] if found else "")

    def make_volume(self, name: str, labels: Mapping) -> bool:
        found = self._inspect("volume", name)
        if found:
            had = (found[0].get("Labels") or {}).get("liminal.service", "")
            if had != labels.get("liminal.service"):
                raise Refusal(f"a volume named {name} is there and is not {labels.get('liminal.service')}'s: "
                              "nothing is made over it")
            return False
        self.run("volume", "create", *_label_args(labels), name, timeout=CHANGE_S)
        return True

    def make_network(self, name: str, grant: Mapping, labels: Mapping) -> bool:
        if self._inspect("network", name):
            return False
        subnet, gateway = str(grant.get("subnet") or ""), str(grant.get("gateway") or "")
        if not subnet or not gateway:
            raise Refusal(f"{name}: no subnet was handed out for it")
        base = subnet.split("/")[0].rsplit(".", 1)[0]
        args = ["network", "create", "--driver", "bridge", "--subnet", subnet, "--gateway", gateway,
                "--ip-range", f"{base}.128/25", "-o", f"com.docker.network.bridge.name={bridge_name(name)}"]
        for iface in self.trusted:
            args += ["-o", f"com.docker.network.bridge.trusted_host_interfaces={iface}"]
        self.run(*args, *_label_args(labels), name, timeout=CHANGE_S)
        return True

    def create(self, c: Create) -> None:
        part = c.part
        labels = dict(c.labels)
        if "liminal.spec" in labels:
            labels["liminal.spec"] = _labelled_spec(ServiceSpec.of(json.loads(labels["liminal.spec"])))
        args = ["create", "--name", c.name, *_label_args(labels), "--restart", "no", "--memory", str(part.memory)]
        if part.cpus:
            args += ["--cpus", f"{part.cpus:g}"]
        if part.shm:
            args += ["--shm-size", str(part.shm)]
        args += ["--hostname", c.hostname or part.name]
        if c.network:
            args += ["--network", c.network]
            if c.address:
                args += ["--ip", c.address]
            for a in c.aliases:
                args += ["--network-alias", a]
        for h in c.add_hosts:
            args += ["--add-host", h]
        for p in c.ports:
            bind = "" if p.lan else "127.0.0.1:"
            args += ["-p", f"{bind}{p.host}:{p.container}/{p.protocol}"]
        for vol, path in c.volumes:
            args += ["-v", f"{vol}:{path}"]
        for k, v in c.env.items():
            args += ["-e", f"{k}={v}"]
        for k in c.secret_env:
            args += ["-e", k]
        args += [c.pinned, *part.command]
        self.run(*args, timeout=CHANGE_S, env=self._env(c.secret_env))

    def seed(self, container: str, seeds, line) -> None:
        """Each (path inside the container, seed, the volume's owner uid or None) in one tar on standard input; owned by
        that uid (docker cp -a keeps a tar's owners) where the volume names one."""
        buf = io.BytesIO()
        keep_owner = False
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for path, seed, owner in seeds:
                raw = seed.text.encode("utf-8")
                info = tarfile.TarInfo(path.lstrip("/"))
                info.size, info.mode, info.mtime = len(raw), seed.mode, 0
                if owner is not None:
                    info.uid = info.gid = int(owner)
                    keep_owner = True
                tar.addfile(info, io.BytesIO(raw))
        self.run("cp", *(("-a",) if keep_owner else ()), "-", f"{container}:/", stdin=buf.getvalue(), timeout=CHANGE_S)

    def start(self, container: str) -> None:
        self.run("start", container, timeout=CHANGE_S)

    def stop(self, container: str, seconds: int) -> None:
        self.run("stop", "-t", str(int(seconds)), container, timeout=float(seconds) + CHANGE_S)

    def rename(self, container: str, new: str) -> None:
        self.run("rename", container, new, timeout=CHANGE_S)

    def remove(self, container: str) -> None:
        self.run("rm", container, timeout=CHANGE_S)

    def drop_volumes(self, names) -> None:
        if names:
            self.run("volume", "rm", *names, timeout=CHANGE_S)

    def drop_network(self, name: str) -> None:
        self.run("network", "rm", name, timeout=CHANGE_S)

    def backup(self, volume: str, pinned: str, into: Path, line, cancelled) -> int:
        self.run("run", "--rm", "--network", "none", "--entrypoint", "tar", "-v", f"{volume}:/v:ro", pinned,
                 "-C", "/v", "-cf", "-", ".", timeout=BACKUP_S, binary=True, out=str(into))
        try:
            return Path(into).stat().st_size
        except OSError:
            return 0

    def restore(self, volume: str, pinned: str, source: Path, line, cancelled) -> int:
        raw = Path(source).read_bytes()
        self.run("run", "--rm", "--network", "none", "--entrypoint", "find", "-v", f"{volume}:/v", pinned,
                 "/v", "-mindepth", "1", "-delete", timeout=BACKUP_S)
        self.run("run", "--rm", "-i", "--network", "none", "--entrypoint", "tar", "-v", f"{volume}:/v", pinned,
                 "-C", "/v", "-xf", "-", timeout=BACKUP_S, stdin=raw)
        return len(raw)
