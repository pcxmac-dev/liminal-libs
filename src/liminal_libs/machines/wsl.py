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
through `wsl -u root`, so no password is asked. Off Windows nothing is present.

The plugin also checks whether this PC can install its system at all (`check`: the user, 2026-11-07, "each plugin
should have a scheme for checking the environment to see if it supports installing the operating system it has in
its name"), streams what its commands print while they run (a setup's `log` with a `write`: the platform's terminal
panel), updates the system's packages (`update_packages`) and gives the command of a login terminal into it
(`terminal`)."""
from __future__ import annotations

import codecs
import os
import platform as py_platform
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .. import layout
from ..docker import Instance
from .plugin import LIMINAL_PREFIX, MachinePlugin, liminal_scoped

TIMEOUT_S = 600.0
INSTALL_TIMEOUT_S = 7200.0  # Gentoo compiles Docker
FAMILIES = ("apt", "dnf", "emerge")
DOCKER_PACKAGES = "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
STEPS = ("wsl", "update", "version", "distribution", "conf", "docker", "engine", "user")
MIN_NAMED = (2, 4, 4)  # the WSL that installs a distribution from Microsoft's list under a name of its own (--name)
MIN_BUILD = 19041  # the Windows build WSL 2 runs on (Windows 10 2004; every Windows 11)
ONLINE_S = 60.0  # Microsoft's list of distributions is read again after this long
# the packages brought up to date by each family's manager, as root
UPDATE_SCRIPTS = {
    "apt": "set -e\nexport DEBIAN_FRONTEND=noninteractive\napt-get update\napt-get -y upgrade\n",
    "dnf": "set -e\ndnf -y upgrade --refresh\n",
    "emerge": "set -e\nemerge --sync --quiet || emerge-webrsync\nemerge --update --deep --newuse --quiet-build=y @world\n",
}
# a login shell with a terminal of its own inside Linux (script, else Python's pty), for the platform's terminal panel
LOGIN = ("export TERM=xterm-256color; command -v script >/dev/null 2>&1 && "
         "exec script -qfc 'stty cols 120 rows 32 2>/dev/null; exec bash -l' /dev/null; "
         "exec python3 -c 'import pty; pty.spawn([\"bash\", \"-l\"])'")

# Docker's own repositories, as its documentation gives them (2026-11-07). `{repository}` is the plugin's
# `docker_repository` (Docker's for that distribution): the plugins name the hosts, the library none.
INSTALL_SCRIPTS = {
    "apt": (
        "set -e\n"
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update\n"
        "apt-get install -y ca-certificates curl\n"
        "install -m 0755 -d /etc/apt/keyrings\n"
        "curl -fsSL {repository}/gpg -o /etc/apt/keyrings/docker.asc\n"
        "chmod a+r /etc/apt/keyrings/docker.asc\n"
        ". /etc/os-release\n"
        "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] "
        "{repository} ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable\" > /etc/apt/sources.list.d/docker.list\n"
        "apt-get update\n"
        f"apt-get install -y {DOCKER_PACKAGES}\n"
    ),
    "dnf": (
        "set -e\n"
        "dnf -y install dnf-plugins-core\n"
        "dnf -y config-manager addrepo --from-repofile={repository}/docker-ce.repo "
        "|| dnf -y config-manager --add-repo {repository}/docker-ce.repo\n"
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
        self._online: tuple[float, list[str]] | None = None

    @property
    def here(self) -> bool:
        """Whether this is Windows with the wsl command (or a stand-in)."""
        return self._runner is not None or (os.name == "nt" and _which("wsl") is not None)

    def _run(self, args: list[str], timeout: float = TIMEOUT_S, stdin: str | None = None, out=None) -> tuple[int, bytes, bytes]:
        """A command; with `out`, what it prints given to `out` as it comes (the platform's terminal panel)."""
        if self._runner is not None:
            code, so, se = self._runner(args, timeout)
            if out is not None and so:
                out(_text(so) if isinstance(so, bytes) else str(so))
            return code, so, se
        if not self.here:
            raise WslError("WSL is not here: this is not Windows, or the wsl command is missing")
        if out is not None:
            return self._stream(args, timeout, stdin, out)
        try:
            done = subprocess.run(args, capture_output=True, timeout=timeout, input=stdin.encode() if stdin is not None else None,
                                  **_no_window())
        except subprocess.TimeoutExpired:
            raise WslError(f"{' '.join(args[:3])} took more than {timeout:g} s") from None
        except OSError as e:
            raise WslError(f"wsl could not run: {e}") from None
        return done.returncode, done.stdout or b"", done.stderr or b""

    def _stream(self, args: list[str], timeout: float, stdin: str | None, out) -> tuple[int, bytes, bytes]:
        env = dict(os.environ, WSL_UTF8="1")  # wsl's own words in UTF-8, as the commands inside print theirs
        try:
            proc = subprocess.Popen(args, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, bufsize=0, env=env, **_no_window())
        except OSError as e:
            raise WslError(f"wsl could not run: {e}") from None
        if stdin is not None:
            try:
                proc.stdin.write(stdin.encode())
                proc.stdin.close()
            except OSError:
                pass
        killed = threading.Event()
        timer = threading.Timer(timeout, lambda: (killed.set(), proc.kill()))
        timer.daemon = True
        timer.start()
        decode, got = codecs.getincrementaldecoder("utf-8")("replace"), bytearray()
        try:
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                got += chunk
                out(decode.decode(chunk))
            out(decode.decode(b"", final=True))
            proc.wait()
        finally:
            timer.cancel()
        if killed.is_set():
            raise WslError(f"{' '.join(args[:3])} took more than {timeout:g} s")
        return proc.returncode, bytes(got), b""

    def own(self, *args: str, timeout: float = TIMEOUT_S, out=None) -> str:
        """One of wsl's own commands (--status, --list ...): its text (UTF-16 on Windows)."""
        code, out, err = self._run(["wsl", *args], timeout, out=out)
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

    def version(self) -> dict:
        """`wsl --version`: {"wsl": "2.6.3.0", "kernel": "6.6.87.2-1"} ({} when it cannot say: an old WSL has no
        --version)."""
        try:
            text = self.own("--version", timeout=30)
        except WslError:
            return {}
        pairs = [(k.strip().lower(), v.strip()) for k, _, v in (line.partition(":") for line in text.splitlines()) if v.strip()]
        found = {"wsl": next((v for k, v in pairs if k.startswith("wsl")), ""),
                 "kernel": next((v for k, v in pairs if k.startswith("kernel")), "")}
        if not found["wsl"] and pairs:  # another language: the first line is WSL's, the second the kernel's
            found = {"wsl": pairs[0][1], "kernel": pairs[1][1] if len(pairs) > 1 else ""}
        return {k: v for k, v in found.items() if v}

    def online(self) -> list[str]:
        """The distributions `wsl --install -d` can fetch (`wsl --list --online`), by name; kept ONLINE_S."""
        if self._online is not None and time.monotonic() - self._online[0] < ONLINE_S:
            return list(self._online[1])
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
        self._online = (time.monotonic(), names)
        return names

    def install_feature(self) -> str:
        """WSL itself, without a distribution (Windows asks to confirm with elevation; a restart may follow)."""
        return self.own("--install", "--no-distribution", timeout=INSTALL_TIMEOUT_S)

    def update(self) -> str:
        return self.own("--update", timeout=INSTALL_TIMEOUT_S)

    def set_default_version(self, version: int = 2) -> str:
        return self.own("--set-default-version", str(version), timeout=60)

    def install(self, source: str, name: str | None = None, location: Path | None = None, out=None) -> str:
        """A distribution from Microsoft's list (`source`), not launched (its user made by the plugin); with `name`,
        installed under that name (a distribution of Liminal's own beside the user's: WSL 2.4.4 or later), its disk
        in `location`."""
        if not name:
            return self.own("--install", "-d", source, "--no-launch", timeout=INSTALL_TIMEOUT_S, out=out)
        extra = ("--location", str(location)) if location is not None else ()
        if location is not None:
            Path(location).mkdir(parents=True, exist_ok=True)
        return self.own("--install", source, "--name", name, *extra, "--no-launch", timeout=INSTALL_TIMEOUT_S, out=out)

    def import_(self, name: str, folder: Path, tarball: Path, out=None) -> str:
        """A distribution from a root file system tarball (Gentoo's stage3), kept in `folder`."""
        Path(folder).mkdir(parents=True, exist_ok=True)
        return self.own("--import", name, str(folder), str(tarball), "--version", "2", timeout=INSTALL_TIMEOUT_S, out=out)

    def terminate(self, name: str) -> str:
        return self.own("--terminate", name, timeout=60)

    def run(self, name: str, *command: str, user: str | None = None, stdin: str | None = None, timeout: float = TIMEOUT_S, out=None) -> str:
        """A command in the distribution (as `user`, root when said), its output; WslError with the error's
        words when it fails."""
        args = ["wsl", "-d", name, *(("-u", user) if user else ()), "--exec", *command]  # as they are: no shell between
        code, so, err = self._run(args, timeout, stdin, out=out)
        text = so.decode("utf-8", "replace")
        if code != 0:
            raise WslError((err.decode("utf-8", "replace") or text or f"{' '.join(command[:2])} failed ({code}) in {name}").strip())
        return text

    def script(self, name: str, text: str, user: str | None = "root", timeout: float = TIMEOUT_S, out=None) -> str:
        """A shell script in the distribution, given on its standard input."""
        return self.run(name, "sh", "-s", user=user, stdin=text, timeout=timeout, out=out)

    def write_file(self, name: str, path: str, text: str) -> None:
        """A file written in the distribution, as root."""
        self.run(name, "sh", "-c", f"cat > {shlex.quote(path)}", user="root", stdin=text)


def wsl_path(windows_path: str) -> str:
    """A Windows path as the distribution sees it: C:\\Users\\x -> /mnt/c/Users/x; a path without a drive stays."""
    p = re.sub(r"/+", "/", str(windows_path).replace("\\", "/"))  # doubled separators collapsed
    m = re.match(r"^([A-Za-z]):/?(.*)$", p)
    return f"/mnt/{m.group(1).lower()}/{m.group(2)}".rstrip("/") if m else p


class WslDistribution(MachinePlugin):
    """The base of the distribution plugins: a subclass names the distribution (`distribution`: its WSL name, one of
    Liminal's own, LIMINAL_PREFIX + the distribution: Liminal-Ubuntu; the user's own distributions are never taken),
    its package family (`family`: apt, dnf or emerge), Docker's repository for it (`docker_repository`, for apt
    and dnf) and how it is got (`install_name` for Microsoft's list, else `tarball_url()` to import from a
    root file system tarball)."""

    STEPS = STEPS
    ICON = "terminal"
    distribution = ""  # the WSL name, Liminal's own: Liminal-Ubuntu, Liminal-Fedora, Liminal-Gentoo
    family = ""  # apt | dnf | emerge
    install_name = ""  # what `wsl --install` takes from Microsoft's list (Ubuntu), installed as `distribution`; "" to import a tarball
    docker_repository = ""  # Docker's package repository for the distribution (apt, dnf); emerge needs none
    default_user = "liminal"  # the user made in the distribution, in the docker group
    space_gb = 4.0  # the free space its install needs on the data folder's drive
    architectures = ("AMD64", "x86_64", "ARM64", "aarch64")  # the processors its system is built for
    HOOKS = (*MachinePlugin.HOOKS, "check", "update_packages", "terminal")
    DISTRIBUTION_VAR = ""  # the variable overriding the WSL name (WSL_UBUNTU_DISTRIBUTION)
    USER_VAR = ""  # the variable overriding the user (WSL_UBUNTU_USER)

    def __init__(self, wsl: Wsl | None = None, data: Path | None = None, fetch=None, system=None, free=None):
        self.wsl = wsl if wsl is not None else Wsl(log=lambda m: None)
        self._data = data
        self._fetch = fetch  # (url, path) -> None: a download, for a tarball; urllib unless given
        self._system = system  # () -> {"windows", "build", "machine"}: a test's; this PC's otherwise
        self._free = free  # (path) -> bytes free: a test's; the disk's otherwise

    def install_script(self) -> str:
        """The family's Docker install, from the plugin's `docker_repository` (WslError: no recipe for the
        family, or a recipe needing a repository the plugin does not name)."""
        if self.family not in INSTALL_SCRIPTS:
            raise WslError(f"no install recipe for the family {self.family!r}")
        script = INSTALL_SCRIPTS[self.family]
        if "{repository}" in script and not self.docker_repository:
            raise WslError(f"{self.name or type(self).__name__} names no Docker repository for {self.family}")
        return script.replace("{repository}", self.docker_repository.rstrip("/"))

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

    # -- this PC ----------------------------------------------------------------------------------------
    def system(self) -> dict:
        """This PC: Windows or not, its build, its processor."""
        if self._system is not None:
            return self._system()
        windows = os.name == "nt"
        return {"windows": windows, "build": sys.getwindowsversion().build if windows else 0, "machine": py_platform.machine()}

    def free_bytes(self) -> int:
        """The free space on the drive the plugin's data folder (its distribution's disk) is on."""
        place = Path(self.data)
        while not place.exists() and place != place.parent:
            place = place.parent
        if self._free is not None:
            return int(self._free(place))
        try:
            return shutil.disk_usage(place).free
        except OSError:
            return 0

    def source_check(self) -> tuple[bool, str]:
        """Whether its system is on offer: on Microsoft's list (`install_name`), or its tarball found (`tarball_url`)."""
        if self.install_name:
            listed = self.wsl.online()
            if self.install_name in listed:
                return True, f"{self.install_name} is on Microsoft's list"
            return False, (f"{self.install_name} is not on Microsoft's list" if listed else "Microsoft's list of distributions cannot be read (offline?)")
        try:
            return True, f"its root file system: {self.tarball_url()}"
        except Exception as e:  # noqa: BLE001 - not found, offline: said
            return False, f"its root file system cannot be found: {e}"

    def check(self) -> dict:
        """Whether this PC can install the plugin's system (the user, 2026-11-07: \"each plugin should have a scheme for
        checking the environment to see if it supports installing the operating system it has in its name, if the
        criteria are met according to the O/S, then the install method should be not locked out\"): each criterion with
        its words; `ready` when every one is met and Liminal's own is not installed yet, `installed` once it is."""
        criteria: list[dict] = []

        def criterion(name: str, title: str, ok, detail: str) -> None:
            criteria.append({"name": name, "title": title, "ok": bool(ok), "detail": detail})

        here = self.system()
        criterion("windows", "Windows that runs WSL 2", here["windows"] and here["build"] >= MIN_BUILD,
                  f"Windows build {here['build']}" + ("" if here["build"] >= MIN_BUILD else f": {MIN_BUILD} or later is needed")
                  if here["windows"] else "this is not Windows")
        st = self.wsl.status() if self.wsl.here else {"present": False}
        criterion("wsl", "WSL installed", st.get("present"), f"default version {st.get('version') or '?'}" if st.get("present")
                  else "WSL is not installed: its setup's wsl step installs it (Windows asks, then a restart)")
        version = self.wsl.version() if st.get("present") else {}
        criterion("kernel", "WSL 2's Linux kernel", version.get("kernel"), f"kernel {version['kernel']}" if version.get("kernel")
                  else "no WSL 2 kernel answers: `wsl --update` brings it")
        if self.install_name:  # under a name of Liminal's own, from Microsoft's list
            have = _version(version.get("wsl", ""))
            criterion("version", f"WSL {'.'.join(map(str, MIN_NAMED))} or later", have >= MIN_NAMED,
                      f"WSL {version.get('wsl') or 'of no known version'}" + ("" if have >= MIN_NAMED else ": `wsl --update` brings a newer one"))
        ok, detail = self.source_check() if st.get("present") else (False, "WSL first")
        criterion("source", f"{self.title.replace('WSL ', '')} on offer", ok, detail)
        criterion("architecture", "A processor it is built for", here["machine"] in self.architectures,
                  f"{here['machine'] or 'unknown'}" + ("" if here["machine"] in self.architectures else f": built for {', '.join(self.architectures)}"))
        free = self.free_bytes()
        criterion("space", f"{self.space_gb:g} GB free for it", free >= self.space_gb * 2**30,
                  f"{free / 2**30:.1f} GB free on the drive of {self.data}")
        installed = bool(st.get("present")) and self.wsl.distribution(self.distribution_name) is not None
        failing = next((c for c in criteria if not c["ok"]), None)
        return {"ready": failing is None and not installed, "installed": installed, "distribution": self.distribution_name,
                "criteria": criteria, "why": (f"{failing['title']}: {failing['detail']}" if failing
                                               else f"{self.distribution_name} is installed" if installed else "")}

    def update_packages(self, log=print) -> list[dict]:
        """The packages of Liminal's own distribution brought up to date by its family's manager, as root, what it prints
        given to the log as it comes (the user: \"after the install is complete, the user can use the plugin to update
        the environment's packages\")."""
        name, done = self.distribution_name, []

        def step(ok, detail: str) -> list[dict]:
            done.append({"step": "packages", "ok": ok, "detail": detail})
            log(f"{self.name}: packages: {'ok' if ok else 'FAILED'}: {detail}")
            return done

        if not liminal_scoped(name) or not self.wsl.here or self.wsl.distribution(name) is None:
            return step(False, f"{name} is not installed: install it first")
        script = UPDATE_SCRIPTS.get(self.family)
        if not script:
            return step(False, f"no update recipe for the family {self.family!r}")
        try:
            self.wsl.script(name, script, timeout=INSTALL_TIMEOUT_S, out=getattr(log, "write", None))
        except WslError as e:
            return step(False, str(e))
        return step(True, f"{name}'s packages brought up to date by {self.family}")

    def terminal(self, user: str | None = None) -> list[str]:
        """The command of a login terminal into Liminal's own distribution, as its default user (or `user`): a shell with
        a terminal of its own inside Linux, for the platform's terminal panel (the user: \"the plugin also allows for a
        user to login through a terminal in to the environment\")."""
        name = self.distribution_name
        if not liminal_scoped(name) or not self.wsl.here or self.wsl.distribution(name) is None:
            raise WslError(f"{name} is not installed: install it first")
        return ["wsl", "-d", name, *(("-u", user) if user else ()), "--cd", "~", "--exec", "sh", "-c", LOGIN]

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
        name = self.distribution_name
        out["summary"] = (f"{name} ({d.state}, WSL {d.version}); Docker inside: "
                          + (("running " if e["running"] else "installed, not running ") + e["version"] if e["installed"] else "none")
                          if d is not None else ("not installed" if wsl.get("present") else "WSL is not here"))
        out["why"] = ("WSL is not here" if not wsl.get("present")
                      else f"{name} is not one of Liminal's own distributions (named {LIMINAL_PREFIX}...)" if not liminal_scoped(name)
                      else f"no Liminal install: its setup installs {name}" if d is None else "")
        out["valid"] = not out["why"]
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
        stream = getattr(log, "write", None)  # the platform's terminal panel: the long commands' output as it comes

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
                    self.wsl.install(self.install_name, name=name, location=self.data / "root", out=stream)
                    step("distribution", True, f"{name} installed from Microsoft's {self.install_name} into {self.data / 'root'}, not launched")
                else:
                    tarball = self.tarball()
                    self.wsl.import_(name, self.data / "root", tarball, out=stream)
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
                    self.wsl.script(name, self.install_script(), timeout=INSTALL_TIMEOUT_S, out=stream)
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
        return (Instance(self.name, f"Docker in {name} under WSL 2", command=f"wsl -d {name} --exec docker", source=self.name, translate=wsl_path),)

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


def _version(text: str) -> tuple[int, ...]:
    """\"2.6.3.0\" -> (2, 6, 3, 0); () when there is none."""
    return tuple(int(n) for n in re.findall(r"\d+", text)[:4])


def _text(raw: bytes) -> str:
    """wsl's own output: UTF-16 on Windows (NULs between the letters), UTF-8 otherwise."""
    return raw.decode("utf-16-le", "ignore") if b"\x00" in raw else raw.decode("utf-8", "ignore")


def _which(name: str):
    import shutil

    return shutil.which(name)


def _no_window() -> dict:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}
