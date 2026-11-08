"""WSL and a Linux distribution in it, with Docker inside, as a machine plugin's base (the user, 2026-11-07:
"the scope of the plugin is setting up WSL/Ubuntu and supporting docker for the platform"; "the ubuntu
plugin needs to be able to install docker (do everything manually) and allow different docker instances
to support the liminal framework"; "then create a gentoo and fedora plugin as well, same scope/function").
`Wsl` drives the wsl command (windowless; a runner stands in for it in tests); `WslDistribution` is the
plugin base: present, status, setup (the WSL feature, its update, version 2, the distribution installed or
imported, systemd and the default user in wsl.conf, Docker installed by the family's package manager,
the engine started and enabled, the user in the docker group), run (a command in the distribution, as a
user or as root), instances (the engine as a Docker instance named after the plugin, reached as
`wsl -d <distribution> docker`, Windows paths under /mnt). Everything runs as root inside the distribution
through `wsl -u root`, so no password is asked. Off Windows nothing is present."""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .. import layout
from ..docker import Instance
from .plugin import MachinePlugin

TIMEOUT_S = 600.0
INSTALL_TIMEOUT_S = 7200.0  # Gentoo compiles Docker
FAMILIES = ("apt", "dnf", "emerge")
DOCKER_PACKAGES = "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
STEPS = ("wsl", "update", "version", "distribution", "conf", "docker", "engine", "user")

# Docker's own repositories, as its documentation gives them (2026-11-07)
INSTALL_SCRIPTS = {
    "apt": (
        "set -e\n"
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update\n"
        "apt-get install -y ca-certificates curl\n"
        "install -m 0755 -d /etc/apt/keyrings\n"
        "curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc\n"
        "chmod a+r /etc/apt/keyrings/docker.asc\n"
        ". /etc/os-release\n"
        "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] "
        "https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable\" > /etc/apt/sources.list.d/docker.list\n"
        "apt-get update\n"
        f"apt-get install -y {DOCKER_PACKAGES}\n"
    ),
    "dnf": (
        "set -e\n"
        "dnf -y install dnf-plugins-core\n"
        "dnf -y config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo "
        "|| dnf -y config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo\n"
        f"dnf -y install {DOCKER_PACKAGES}\n"
    ),
    "emerge": (
        "set -e\n"
        "emerge --sync --quiet || emerge-webrsync\n"
        "emerge --quiet-build=y app-containers/docker app-containers/docker-cli app-containers/docker-buildx app-containers/docker-compose\n"
    ),
}
ENGINE_SCRIPT = (
    "set -e\n"
    "if [ -d /run/systemd/system ]; then systemctl enable --now docker; echo systemd;\n"
    "elif command -v rc-service >/dev/null 2>&1; then rc-update add docker default; rc-service docker start; echo openrc;\n"
    "else service docker start; echo service; fi\n"
)


class WslError(Exception):
    pass


@dataclass(frozen=True)
class Distribution:
    name: str
    state: str  # Running | Stopped
    version: str  # 1 | 2
    default: bool = False


class Wsl:
    """The wsl command. `runner(args, timeout) -> (code, stdout bytes, stderr bytes)` stands in for it."""

    def __init__(self, runner=None, log=None):
        self._runner = runner
        self.log = log or (lambda m: None)

    @property
    def here(self) -> bool:
        """Whether this is Windows with the wsl command (or a stand-in)."""
        return self._runner is not None or (os.name == "nt" and _which("wsl") is not None)

    def _run(self, args: list[str], timeout: float = TIMEOUT_S, stdin: str | None = None) -> tuple[int, bytes, bytes]:
        if self._runner is not None:
            return self._runner(args, timeout)
        if not self.here:
            raise WslError("WSL is not here: this is not Windows, or the wsl command is missing")
        try:
            done = subprocess.run(args, capture_output=True, timeout=timeout, input=stdin.encode() if stdin is not None else None,
                                  **_no_window())
        except subprocess.TimeoutExpired:
            raise WslError(f"{' '.join(args[:3])} took more than {timeout:g} s") from None
        except OSError as e:
            raise WslError(f"wsl could not run: {e}") from None
        return done.returncode, done.stdout or b"", done.stderr or b""

    def own(self, *args: str, timeout: float = TIMEOUT_S) -> str:
        """One of wsl's own commands (--status, --list ...): its text (UTF-16 on Windows)."""
        code, out, err = self._run(["wsl", *args], timeout)
        text = _text(out)
        if code != 0:
            raise WslError((_text(err) or text or f"wsl {' '.join(args[:2])} failed ({code})").strip())
        return text

    def status(self) -> dict:
        """Whether WSL 2 is there: {"present", "version", "distribution"} (the default one)."""
        try:
            text = self.own("--status", timeout=30)
        except WslError as e:
            return {"present": False, "version": "", "distribution": "", "problem": str(e)}
        fields = {}
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip().lower()] = v.strip()
        return {"present": bool(text.strip()), "version": fields.get("default version", ""), "distribution": fields.get("default distribution", "")}

    def distributions(self) -> list[Distribution]:
        """The distributions installed, from `wsl --list --verbose`."""
        try:
            text = self.own("--list", "--verbose", timeout=30)
        except WslError:
            return []
        out = []
        for line in text.splitlines()[1:]:
            default = line.strip().startswith("*")
            parts = line.replace("*", " ").split()
            if len(parts) >= 3:
                out.append(Distribution(parts[0], parts[1], parts[2], default))
        return out

    def distribution(self, name: str) -> Distribution | None:
        return next((d for d in self.distributions() if d.name.lower() == name.lower()), None)

    def online(self) -> list[str]:
        """The distributions `wsl --install -d` can fetch (`wsl --list --online`), by name."""
        try:
            text = self.own("--list", "--online", timeout=60)
        except WslError:
            return []
        names = []
        seen_header = False
        for line in text.splitlines():
            if line.strip().upper().startswith("NAME"):
                seen_header = True
                continue
            if seen_header and line.strip():
                names.append(line.split()[0])
        return names

    def install_feature(self) -> str:
        """WSL itself, without a distribution (Windows asks to confirm with elevation; a restart may follow)."""
        return self.own("--install", "--no-distribution", timeout=INSTALL_TIMEOUT_S)

    def update(self) -> str:
        return self.own("--update", timeout=INSTALL_TIMEOUT_S)

    def set_default_version(self, version: int = 2) -> str:
        return self.own("--set-default-version", str(version), timeout=60)

    def install(self, name: str) -> str:
        """A distribution from Microsoft's list, not launched (its user made by the plugin)."""
        return self.own("--install", "-d", name, "--no-launch", timeout=INSTALL_TIMEOUT_S)

    def import_(self, name: str, folder: Path, tarball: Path) -> str:
        """A distribution from a root file system tarball (Gentoo's stage3), kept in `folder`."""
        Path(folder).mkdir(parents=True, exist_ok=True)
        return self.own("--import", name, str(folder), str(tarball), "--version", "2", timeout=INSTALL_TIMEOUT_S)

    def terminate(self, name: str) -> str:
        return self.own("--terminate", name, timeout=60)

    def run(self, name: str, *command: str, user: str | None = None, stdin: str | None = None, timeout: float = TIMEOUT_S) -> str:
        """A command in the distribution (as `user`, root when said), its output; WslError with the error's
        words when it fails."""
        args = ["wsl", "-d", name, *(("-u", user) if user else ()), "--", *command]
        code, out, err = self._run(args, timeout, stdin)
        text = out.decode("utf-8", "replace")
        if code != 0:
            raise WslError((err.decode("utf-8", "replace") or text or f"{' '.join(command[:2])} failed ({code}) in {name}").strip())
        return text

    def script(self, name: str, text: str, user: str | None = "root", timeout: float = TIMEOUT_S) -> str:
        """A shell script in the distribution, given on its standard input."""
        return self.run(name, "sh", "-s", user=user, stdin=text, timeout=timeout)

    def write_file(self, name: str, path: str, text: str) -> None:
        """A file written in the distribution, as root."""
        self.run(name, "sh", "-c", f"cat > {shlex.quote(path)}", user="root", stdin=text)


def wsl_path(windows_path: str) -> str:
    """A Windows path as the distribution sees it: C:\\Users\\x -> /mnt/c/Users/x; a path without a drive stays."""
    p = re.sub(r"/+", "/", str(windows_path).replace("\\", "/"))  # doubled separators collapsed
    m = re.match(r"^([A-Za-z]):/?(.*)$", p)
    return f"/mnt/{m.group(1).lower()}/{m.group(2)}".rstrip("/") if m else p


class WslDistribution(MachinePlugin):
    """The base of the distribution plugins: a subclass names the distribution (`distribution`: its WSL name),
    its package family (`family`: apt, dnf or emerge) and how it is got (`install_name` for Microsoft's list,
    else `tarball_url()` to import from a root file system tarball)."""

    STEPS = STEPS
    distribution = ""  # the WSL name: Ubuntu, FedoraLinux-42, Gentoo
    family = ""  # apt | dnf | emerge
    install_name = ""  # what `wsl --install -d` takes; "" to import a tarball
    default_user = "liminal"  # the user made in the distribution, in the docker group
    DISTRIBUTION_VAR = ""  # the variable overriding the WSL name (WSL_UBUNTU_DISTRIBUTION)
    USER_VAR = ""  # the variable overriding the user (WSL_UBUNTU_USER)

    def __init__(self, wsl: Wsl | None = None, data: Path | None = None, fetch=None):
        self.wsl = wsl if wsl is not None else Wsl(log=lambda m: None)
        self._data = data
        self._fetch = fetch  # (url, path) -> None: a download, for a tarball; urllib unless given

    @property
    def options(self) -> tuple[str, ...]:
        return tuple(v for v in (self.DISTRIBUTION_VAR, self.USER_VAR) if v)

    @property
    def distribution_name(self) -> str:
        named = (os.environ.get(self.DISTRIBUTION_VAR) or "").strip() if self.DISTRIBUTION_VAR else ""
        return named or self.distribution

    @property
    def user(self) -> str:
        return ((os.environ.get(self.USER_VAR) or "").strip() if self.USER_VAR else "") or self.default_user

    @property
    def data(self) -> Path:
        """Where this plugin keeps what it downloads and imports: the data folder's platform/wsl/<name>."""
        return self._data if self._data is not None else layout.data_dir() / "platform" / "wsl" / self.name

    # -- the hooks ---------------------------------------------------------------------------------
    def present(self) -> bool:
        return self.wsl.here and self.wsl.distribution(self.distribution_name) is not None

    def status(self) -> dict:
        wsl = self.wsl.status() if self.wsl.here else {"present": False, "version": "", "distribution": ""}
        d = self.wsl.distribution(self.distribution_name) if wsl.get("present") else None
        out = {"present": d is not None, "wsl": wsl, "distribution": self.distribution_name, "family": self.family,
               "state": d.state if d else "", "version": d.version if d else "", "user": self.user,
               "engine": {"installed": False, "version": "", "running": False}}
        if d is not None:
            out["engine"] = self.engine()
        e = out["engine"]
        out["summary"] = (f"{self.distribution_name} ({d.state}, WSL {d.version}); Docker inside: "
                          + (("running " if e["running"] else "installed, not running ") + e["version"] if e["installed"] else "none")
                          if d is not None else ("not installed" if wsl.get("present") else "WSL is not here"))
        return out

    def engine(self) -> dict:
        """Docker inside: installed (its version), and the daemon answering."""
        try:
            version = self.wsl.run(self.distribution_name, "docker", "--version", timeout=60).strip()
        except WslError:
            return {"installed": False, "version": "", "running": False}
        m = re.search(r"Docker version ([^,\s]+)", version)
        try:
            self.wsl.run(self.distribution_name, "docker", "info", "--format", "{{.ServerVersion}}", timeout=60)
            running = True
        except WslError:
            running = False
        return {"installed": True, "version": m.group(1) if m else version, "running": running}

    def setup(self, log=print, steps=None) -> list[dict]:
        """Everything, in order, each step reported; `steps`: only these. A step that fails ends it."""
        wanted = tuple(steps) if steps else STEPS
        done: list[dict] = []
        name = self.distribution_name

        def step(what: str, ok: bool | None, detail: str) -> bool:
            done.append({"step": what, "ok": ok, "detail": detail})
            log(f"{self.name}: {what}: {'ok' if ok else 'skipped' if ok is None else 'FAILED'}: {detail}")
            return ok is not False

        try:
            if "wsl" in wanted:
                if not self.wsl.here:
                    return done if step("wsl", False, "this is not Windows, or the wsl command is missing") else done
                st = self.wsl.status()
                if st.get("present"):
                    step("wsl", None, f"WSL is there (default version {st.get('version') or '?'})")
                else:
                    self.wsl.install_feature()
                    step("wsl", True, "WSL installed (Windows may ask to restart before a distribution runs)")
            if "update" in wanted:
                self.wsl.update()
                step("update", True, "WSL updated")
            if "version" in wanted:
                self.wsl.set_default_version(2)
                step("version", True, "new distributions get WSL 2")
            if "distribution" in wanted:
                if self.wsl.distribution(name) is not None:
                    step("distribution", None, f"{name} is installed")
                elif self.install_name:
                    self.wsl.install(self.install_name)
                    step("distribution", True, f"{self.install_name} installed from Microsoft's list, not launched")
                else:
                    tarball = self.tarball()
                    self.wsl.import_(name, self.data / "root", tarball)
                    step("distribution", True, f"{name} imported from {tarball.name} into {self.data / 'root'}")
            if "conf" in wanted:
                self.wsl.write_file(name, "/etc/wsl.conf", f"[boot]\nsystemd=true\n\n[user]\ndefault={self.user}\n")
                self.wsl.script(name, f"id -u {shlex.quote(self.user)} >/dev/null 2>&1 || useradd -m -s /bin/bash {shlex.quote(self.user)}\n")
                self.wsl.terminate(name)
                step("conf", True, f"/etc/wsl.conf: systemd on, default user {self.user} (made when absent); {name} restarted")
            if "docker" in wanted:
                if self.engine()["installed"]:
                    step("docker", None, "Docker is installed inside")
                else:
                    if self.family not in INSTALL_SCRIPTS:
                        return done if step("docker", False, f"no install recipe for the family {self.family!r}") else done
                    self.wsl.script(name, INSTALL_SCRIPTS[self.family], timeout=INSTALL_TIMEOUT_S)
                    step("docker", True, f"Docker installed by {self.family} from Docker's own repository")
            if "engine" in wanted:
                how = self.wsl.script(name, ENGINE_SCRIPT, timeout=600).strip().splitlines()
                step("engine", True, f"the engine started and enabled ({how[-1] if how else 'started'})")
            if "user" in wanted:
                self.wsl.script(name, f"groupadd -f docker\nusermod -aG docker {shlex.quote(self.user)}\n")
                step("user", True, f"{self.user} in the docker group")
        except WslError as e:
            step(wanted[len(done)] if len(done) < len(wanted) else "setup", False, str(e))
        return done

    def run(self, *command: str, user: str | None = None, stdin: str | None = None, timeout: float = TIMEOUT_S) -> str:
        return self.wsl.run(self.distribution_name, *command, user=user, stdin=stdin, timeout=timeout)

    def instances(self) -> tuple[Instance, ...]:
        if not self.present() or not self.engine()["installed"]:
            return ()
        name = self.distribution_name
        return (Instance(self.name, f"Docker in {name} under WSL 2", command=f"wsl -d {name} docker", source=self.name, translate=wsl_path),)

    # -- a distribution imported from a tarball (Gentoo) --------------------------------------------
    def tarball_url(self) -> str:
        """Where the root file system tarball comes from; a subclass that imports says."""
        raise WslError(f"{self.name} has no tarball to import and no name on Microsoft's list")

    def tarball(self) -> Path:
        """The tarball downloaded into the plugin's data folder, once."""
        url = self.tarball_url()
        path = self.data / url.rsplit("/", 1)[-1]
        if not path.is_file():
            path.parent.mkdir(parents=True, exist_ok=True)
            (self._fetch or _download)(url, path)
        return path


def _download(url: str, path: Path) -> None:
    import urllib.request

    with urllib.request.urlopen(url, timeout=120) as r, open(path, "wb") as f:  # noqa: S310 - the plugin's own url
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)


def _text(raw: bytes) -> str:
    """wsl's own output: UTF-16 on Windows (NULs between the letters), UTF-8 otherwise."""
    return raw.decode("utf-16-le", "ignore") if b"\x00" in raw else raw.decode("utf-8", "ignore")


def _which(name: str):
    import shutil

    return shutil.which(name)


def _no_window() -> dict:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}
