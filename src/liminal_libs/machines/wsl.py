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
(`terminal`). Its services (`services`; the user, 2026-11-08: "a breakdown of the major services running"): the init
system found (systemd or OpenRC, or SysV scripts) and the services that run, the major ones apart from the system's own
(machines.services); scanned only while the distribution runs: a status, a scan, the Docker check or the instance list
never starts a stopped one.

Every install of its system (1.36.0; the user, 2026-11-08: "for the WSL plugins, they need to list all the 'operating
systems' that are installed under the plugin's regime, like ubuntu shows all ubuntu installs, fedora -- installs, gentoo
-- installs"): `Wsl.installed` reads WSL's own record of each distribution installed for this Windows user (its Lxss
registry key: the flavor and OS version WSL read from its os-release when it installed it, its Store package, its folder
and disk) beside `wsl --list --verbose` (its state, the default), starting none; the plugin's status lists those of its
system (`owns`: the flavor, else the name or the Store package) as a table, Liminal's own and the user's alike. A
selector chooses one of them (the user: "also the ability to uninstall and select which one to terminal in to";
"basically a selector for different installs"): the platform's terminal opens into the install chosen, and Uninstall
unregisters it (`wsl --unregister`: its disk deleted for good), one of the user's own only after a second confirmation
(`accept_risk`). Nothing else of the user's own installs is changed."""
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
from .services import SCRIPT as SCAN_SCRIPT, Scan, parse as parse_scan

TIMEOUT_S = 600.0
SCAN_S = 30.0  # a services scan is kept this long: the platform asks the status every few seconds
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


class UninstallRefused(ValueError):
    """An uninstall of one of the user's own distributions, refused until accepted in so many words (`accept`: the
    argument that accepts it; the platform asks a second time)."""

    accept = "accept_risk"


@dataclass(frozen=True)
class Distribution:
    name: str
    state: str  # Running | Stopped
    version: str  # 1 | 2
    default: bool = False


LXSS = r"Software\Microsoft\Windows\CurrentVersion\Lxss"  # under HKEY_CURRENT_USER: WSL's record of each distribution
KEEP_RUNNING = ("sh", "-c", "while :; do sleep 3600; done")  # a started install's session: WSL stops one with none
NO_SYSTEMD = "LIMINAL-NO-SYSTEMD"
# a pause: each running service but the system's own plumbing frozen by systemd's cgroup freezer (systemd 246+, cgroup v2)
FREEZE_SCRIPT = (
    f'[ "$(cat /proc/1/comm 2>/dev/null)" = systemd ] || {{ echo {NO_SYSTEMD}; exit 0; }}; '
    "for u in $(systemctl list-units --type=service --state=running --plain --no-legend --no-pager | awk '{print $1}'); do "
    'case "$u" in systemd-*|dbus*|user@*|*getty*|polkit.service) continue;; esac; '
    'if systemctl freeze "$u" >/dev/null 2>&1; then echo "frozen $u"; else echo "failed $u"; fi; done')
# a resume: the services named (its arguments) thawed, then any other service still frozen (a pause before a restart)
THAW_SCRIPT = r"""for u in "$@"; do if systemctl thaw "$u" >/dev/null 2>&1; then echo "thawed $u"; fi; done
for u in $(systemctl show -p Id -p FreezerState --type=service '*' 2>/dev/null | awk -F= '/^Id=/{id=$2} /^FreezerState=frozen/{print id}'); do
  if systemctl thaw "$u" >/dev/null 2>&1; then echo "thawed $u"; fi
done"""


@dataclass(frozen=True)
class Installed:
    """A distribution installed for this Windows user, as WSL records it and `wsl --list --verbose` says: its name, state
    (Running, Stopped...), WSL version, whether it is the default; the flavor and OS version WSL read from its os-release
    when it installed it (ubuntu 24.04; none for one imported from a tarball by an older way), its Store package (a Store
    install's), its folder and its disk (the file and its size in bytes, None when not read)."""

    name: str
    state: str = ""
    version: str = ""
    default: bool = False
    flavor: str = ""
    os_version: str = ""
    package: str = ""
    folder: str = ""
    disk: str = ""
    size: int | None = None

    def describe(self) -> dict:
        return {"name": self.name, "state": self.state, "version": self.version, "default": self.default, "flavor": self.flavor,
                "osVersion": self.os_version, "package": self.package, "folder": self.folder, "disk": self.disk, "size": self.size}


def lxss_registry() -> list[dict]:
    """WSL's record of each distribution installed for this Windows user: its Lxss key's values (DistributionName,
    Flavor, OsVersion, Version, BasePath, VhdFileName, PackageFamilyName...); [] off Windows or unreadable. A read of the
    registry alone: no distribution is started."""
    if os.name != "nt":
        return []
    try:
        import winreg

        out = []
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, LXSS) as root:
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                values = {"guid": guid}
                try:
                    with winreg.OpenKey(root, guid) as key:
                        j = 0
                        while True:
                            try:
                                name, value, _kind = winreg.EnumValue(key, j)
                            except OSError:
                                break
                            j += 1
                            values[name] = value
                except OSError:
                    continue
                out.append(values)
        return out
    except OSError:
        return []


class Wsl:
    """The wsl command. `runner(args, timeout) -> (code, stdout bytes, stderr bytes)` stands in for it."""

    def __init__(self, runner=None, log=None, registry=None, spawn=None):
        self._runner = runner
        self._spawn = spawn  # (args) -> a process: a stand-in for keep_running's; else subprocess, windowless
        self.log = log or (lambda m: None)
        self._online: tuple[float, list[str]] | None = None
        # WSL's record of the distributions (lxss_registry); a stand-in runner's tests read none unless given one
        self._registry = registry if registry is not None else (lambda: []) if runner is not None else lxss_registry

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

    def installed(self, listed: list[Distribution] | None = None) -> list[Installed]:
        """Every distribution installed for this Windows user, nothing started: `wsl --list --verbose` (`listed`, when
        read already) joined by name with WSL's own record of each (lxss_registry), in the list's order; one the record
        lacks is still listed, one the list lacks (being installed or removed) too."""
        listed = self.distributions() if listed is None else listed
        try:
            records = {str(r.get("DistributionName") or "").lower(): r for r in self._registry() if r.get("DistributionName")}
        except Exception:  # noqa: BLE001 - a record that cannot be read: the list alone
            records = {}
        out = []
        for d in listed:
            out.append(_installed(d.name, records.pop(d.name.lower(), {}), d))
        out += [_installed(str(r["DistributionName"]), r, None) for r in records.values()]
        return out

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

    def update(self, out=None) -> str:
        return self.own("--update", timeout=INSTALL_TIMEOUT_S, out=out)

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

    def keep_running(self, name: str):
        """A windowless session holding `name` up (WSL stops a distribution with no session): started, not waited for;
        it ends when the distribution is stopped. A stand-in's spawner in tests."""
        args = ["wsl", "-d", name, "--exec", *KEEP_RUNNING]
        if self._spawn is not None:
            return self._spawn(args)
        return subprocess.Popen([_which("wsl") or "wsl", *args[1:]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, **_no_window())

    def unregister(self, name: str) -> str:
        """A distribution unregistered: its disk and everything in it deleted for good (one that runs is stopped first)."""
        return self.own("--unregister", name, timeout=600)

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


def _installed(name: str, r: dict, d: Distribution | None) -> Installed:
    folder = str(r.get("BasePath") or "")
    if folder.startswith("\\\\?\\"):
        folder = folder[4:]
    disk = str(Path(folder) / str(r.get("VhdFileName") or "ext4.vhdx")) if folder else ""
    try:
        size = os.stat(disk).st_size if disk else None
    except OSError:
        size = None
    version = d.version if d else str(r.get("Version") or "")
    return Installed(name, d.state if d else "not listed by wsl", version, d.default if d else False, str(r.get("Flavor") or "").lower(),
                     str(r.get("OsVersion") or ""), str(r.get("PackageFamilyName") or ""), folder, disk, size)


def _count(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def size_words(n: int | None) -> str:
    """Bytes as GB (or MB under one GB); "not read" for None."""
    if n is None:
        return "not read"
    return f"{n / 1024 ** 3:.1f} GB" if n >= 1024 ** 3 else f"{n / 1024 ** 2:.0f} MB"


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
    HOOKS = (*MachinePlugin.HOOKS, "check", "update_packages", "terminal", "services", "pick_install", "uninstall",
             "start_install", "pause_install", "stop_install")
    DISTRIBUTION_VAR = ""  # the variable overriding the WSL name (WSL_UBUNTU_DISTRIBUTION)
    USER_VAR = ""  # the variable overriding the user (WSL_UBUNTU_USER)
    # its system's installs (1.36.0): those WSL records with one of these flavors, else named or packaged so (any case);
    # () for the system's own name, from `distribution` (Liminal-Ubuntu: ubuntu)
    FLAVORS: tuple = ()
    NAMES: tuple = ()
    PACKAGES: tuple = ()

    def __init__(self, wsl: Wsl | None = None, data: Path | None = None, fetch=None, system=None, free=None):
        self.wsl = wsl if wsl is not None else Wsl(log=lambda m: None)
        self._data = data
        self._fetch = fetch  # (url, path) -> None: a download, for a tarball; urllib unless given
        self._system = system  # () -> {"windows", "build", "machine"}: a test's; this PC's otherwise
        self._free = free  # (path) -> bytes free: a test's; the disk's otherwise
        self._scan: tuple[float, Scan] | None = None  # the last services scan (monotonic time, scan), kept SCAN_S
        self._pick = {"name": ""}  # the install chosen (pick_install); a dict, so the registry's copies share it
        self._tasks = {"kept": {}, "paused": {}}  # the sessions holding started installs up; the services paused, by install
        self._engine_seen: dict | None = None  # Docker inside as last seen while it ran (a stopped one is not asked)

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
        log(f"{self.name}: packages: updating {name}'s packages by {self.family}; its output follows...")
        try:
            self.wsl.script(name, script, timeout=INSTALL_TIMEOUT_S, out=getattr(log, "write", None))
        except WslError as e:
            return step(False, str(e))
        return step(True, f"{name}'s packages brought up to date by {self.family}")

    def terminal(self, user: str | None = None) -> list[str]:
        """The command of a login terminal into the install chosen (Liminal's own unless another is: `chosen`), as its
        default user (or `user`): a shell with a terminal of its own inside Linux, for the platform's terminal panel (the
        user: \"the plugin also allows for a user to login through a terminal in to the environment\"; \"select which one
        to terminal in to\"). A stopped one starts: the user asked for it."""
        name = self.chosen() if self.wsl.here else ""
        if not name or self.wsl.distribution(name) is None:
            raise WslError(f"{name or self.distribution_name} is not installed: install it first")
        return ["wsl", "-d", name, *(("-u", user) if user else ()), "--cd", "~", "--exec", "sh", "-c", LOGIN]

    def terminal_title(self) -> str:
        """Whose terminal into which install, for the terminal panel's head."""
        name = self.chosen() if self.wsl.here else self.distribution_name
        return f"{self.user} in {name}" if name.lower() == self.distribution_name.lower() else f"{name}, as its default user"

    # -- the hooks ---------------------------------------------------------------------------------
    def present(self) -> bool:
        return self.wsl.here and self.wsl.distribution(self.distribution_name) is not None

    # -- every install of its system (the user: "they need to list all the 'operating systems' that are installed under
    # the plugin's regime, like ubuntu shows all ubuntu installs") ------------------------------------------------------
    @property
    def system_name(self) -> str:
        """Its system's name: Ubuntu for Liminal-Ubuntu."""
        d = self.distribution
        return d[len(LIMINAL_PREFIX):] if d.lower().startswith(LIMINAL_PREFIX.lower()) else d

    def owns(self, i: Installed) -> bool:
        """Whether an install is of this plugin's system: its own distribution; one WSL records with the system's flavor;
        one with no flavor recorded, named or packaged as the system (Ubuntu-22.04, FedoraLinux-42, CanonicalGroupLimited...)."""
        if i.name.lower() == self.distribution_name.lower():
            return True
        own = self.system_name.lower()
        flavors = tuple(f.lower() for f in (self.FLAVORS or (own,)))
        if i.flavor:
            return i.flavor in flavors
        names = tuple(n.lower() for n in (self.NAMES or (own,)))
        packages = tuple(p.lower() for p in self.PACKAGES)
        return i.name.lower().startswith(names) or bool(packages and i.package.lower().startswith(packages))

    def installs(self, listed: list[Distribution] | None = None) -> list[Installed]:
        """Every install of its system for this Windows user, Liminal's own and the user's, nothing started."""
        return [i for i in self.wsl.installed(listed) if self.owns(i)] if self.wsl.here else []

    def chosen(self, installs: list[Installed] | None = None) -> str:
        """The install chosen: the one the user picked (pick_install) while it is installed, else Liminal's own when it
        is; "" for none (one of the user's own is never chosen for them)."""
        names = [i.name for i in (self.installs() if installs is None else installs)]
        picked = (self._pick.get("name") or "").lower()
        own = self.distribution_name.lower()
        return next((n for n in names if n.lower() == picked), None) or next((n for n in names if n.lower() == own), None) or ""

    def pick_install(self, name) -> dict:
        """An install of its system chosen: the terminal opens into it, Uninstall names it."""
        found = next((i for i in self.installs() if i.name.lower() == str(name or "").strip().lower()), None)
        if found is None:
            raise LookupError(f"no {self.system_name} install named {name!r} here")
        self._pick["name"] = found.name
        return {"said": f"{found.name} chosen: a terminal opens into it", "ok": True}

    def uninstall(self, name, accept_risk=False) -> dict:
        """An install of its system unregistered from WSL (`wsl --unregister`): its disk and everything in it deleted for
        good, stopped first if it runs. One of the user's own only once accepted in so many words (`accept_risk`); what
        Liminal downloaded for its own (a tarball) is kept, so its setup installs it again."""
        target = next((i for i in self.installs() if i.name.lower() == str(name or "").strip().lower()), None)
        if target is None:
            raise LookupError(f"no {self.system_name} install named {name!r} here")
        ours = target.name.lower() == self.distribution_name.lower()
        if not ours and accept_risk is not True:
            raise UninstallRefused(
                f"{target.name} is yours, not Liminal's: unregistering it deletes its disk ({size_words(target.size)}) and everything "
                "in it, your files, your packages and your home folder, for good"
                + (f"; its Store app ({target.package}) stays installed, and opening it installs a fresh one" if target.package else ""))
        self.wsl.unregister(target.name)
        self._tasks["paused"].pop(target.name.lower(), None)
        self._tasks["kept"].pop(target.name.lower(), None)
        if (self._pick.get("name") or "").lower() == target.name.lower():
            self._pick["name"] = ""
        if ours:
            self._scan, self._engine_seen = None, None
        left = any(i.name.lower() == target.name.lower() for i in self.installs())
        return {"said": f"{target.name} is still installed" if left else f"{target.name} uninstalled", "ok": not left,
                "lines": [f"its disk was {size_words(target.size)}" + (f" in {target.folder}" if target.folder else "")]
                + ([f"{self.distribution_name}'s setup installs it again"] if ours else [])}

    def install_forms(self) -> list[dict]:
        """The installs' forms: Uninstall (a second confirmation for one of the user's own: the refusal's accept_risk)."""
        return [{"id": "uninstall", "hook": "uninstall", "title": "Uninstall a distribution",
                 "fields": [{"name": "name", "label": "Distribution", "type": "fixed"},
                            {"name": "accept_risk", "type": "accept", "title": "Delete your own distribution?", "yes": "Delete it for good",
                             "words": "It is yours, not Liminal's: everything in it is deleted for good, and nothing here can put it back."}],
                 "confirm": {"title": "Uninstall {name}?",
                             "words": "{name} is unregistered from WSL: its disk and everything in it are deleted for good, stopped first "
                                      "if it runs. This cannot be undone.",
                             "yes": "Uninstall it", "danger": True}}]

    # -- the installs' tasks (1.37.0; the user: "instead of chosen, put task and for the tasks lets do terminal, start, pause,
    # stop, allow selection of the linux install by clicking on the list"; "tasks also include uninstall") --------------
    def _install(self, name) -> Installed:
        found = next((i for i in self.installs() if i.name.lower() == str(name or "").strip().lower()), None)
        if found is None:
            raise LookupError(f"no {self.system_name} install named {name!r} here")
        return found

    def paused(self, name: str) -> list[str]:
        """The services this plugin paused in `name` (frozen while it runs); [] when none."""
        return list(self._tasks["paused"].get(name.lower(), []))

    def start_install(self, name) -> dict:
        """An install started and kept running (WSL stops one with no session: a windowless session holds it, until Stop);
        one paused, its services resumed. The user's own too: the user asked."""
        target = self._install(name)
        if target.state == "Running" and self.paused(target.name):
            text = self.wsl.run(target.name, "sh", "-c", THAW_SCRIPT, "sh", *self.paused(target.name), user="root", timeout=120)
            thawed = [line.split(" ", 1)[1] for line in text.splitlines() if line.startswith("thawed ")]
            self._tasks["paused"].pop(target.name.lower(), None)
            return {"said": f"{target.name} resumed: {_count(len(thawed), 'service')} running again", "ok": True,
                    "lines": [", ".join(thawed)] if thawed else []}
        if target.state == "Running":
            return {"said": f"{target.name} is running already", "ok": True}
        self._tasks["kept"][target.name.lower()] = self.wsl.keep_running(target.name)
        for _ in range(60):
            d = self.wsl.distribution(target.name)
            if d is not None and _running(d):
                return {"said": f"{target.name} started: it runs until Stop", "ok": True}
            time.sleep(0.5)
        return {"said": f"{target.name} did not say it runs yet: Refresh shows it", "ok": False}

    def pause_install(self, name) -> dict:
        """An install's services paused: each running service but the system's own plumbing (systemd's, D-Bus, the
        sessions) frozen by systemd's cgroup freezer, its terminals left as they are; Start resumes them. WSL itself
        cannot pause a distribution; one without systemd as its init cannot be paused this way."""
        target = self._install(name)
        if target.state != "Running":
            raise ValueError(f"{target.name} is not running: nothing to pause")
        text = self.wsl.run(target.name, "sh", "-c", FREEZE_SCRIPT, user="root", timeout=120)
        if NO_SYSTEMD in text:
            raise ValueError(f"{target.name} does not run systemd as its init: its services cannot be paused, only stopped")
        frozen = [line.split(" ", 1)[1] for line in text.splitlines() if line.startswith("frozen ")]
        failed = [line.split(" ", 1)[1] for line in text.splitlines() if line.startswith("failed ")]
        if frozen:
            self._tasks["paused"][target.name.lower()] = frozen
        return {"said": f"{target.name} paused: {_count(len(frozen), 'service')} frozen" if frozen else f"{target.name}: no service to pause",
                "ok": bool(frozen) or not failed,
                "lines": ([", ".join(frozen)] if frozen else []) + ([f"not paused: {', '.join(failed)}"] if failed else [])}

    def stop_install(self, name) -> dict:
        """An install stopped (`wsl --terminate`): every program in it ends; Start brings it back."""
        target = self._install(name)
        if target.state != "Running":
            return {"said": f"{target.name} is stopped already", "ok": True}
        self.wsl.terminate(target.name)
        self._tasks["paused"].pop(target.name.lower(), None)
        held = self._tasks["kept"].pop(target.name.lower(), None)
        if held is not None and hasattr(held, "poll"):
            held.poll()
        if target.name.lower() == self.distribution_name.lower():
            self._scan = None
        return {"said": f"{target.name} stopped", "ok": True}

    def installs_table(self, installs: list[Installed]) -> dict:
        """The installs of its system as a table to choose from by a click (`select`: its row's key is its name), each its
        state (paused when its services are), its system and version as WSL recorded it, WSL 1 or 2, the default or not,
        its disk, and whose; above it the tasks of the one chosen (`tasks`: Terminal, Start, Pause, Stop, Uninstall)."""
        rows = []
        for i in installs:
            ours = i.name.lower() == self.distribution_name.lower()
            system = f"{i.flavor.capitalize() if i.flavor else self.system_name} {i.os_version}".strip()
            state = "Paused" if i.state == "Running" and self.paused(i.name) else i.state or "?"
            rows.append({"key": i.name, "cells": [
                {"text": i.name, "sub": i.package} if i.package else i.name,
                {"text": state, "sub": f"{_count(len(self.paused(i.name)), 'service')} frozen"} if state == "Paused" else state,
                system if i.flavor else {"text": system, "sub": "its version not recorded by WSL"},
                f"WSL {i.version}" if i.version else "?", "yes" if i.default else "",
                {"text": size_words(i.size), "sub": i.folder} if i.folder else size_words(i.size),
                "Liminal's: this plugin's" if ours else {"text": "yours", "sub": "changed only by a task you choose"}]})
        theirs = [i.name for i in installs if i.name.lower() != self.distribution_name.lower()]
        chosen = self.chosen(installs)
        picked = next((i for i in installs if i.name == chosen), None)
        out = {"title": f"{self.system_name} installs",
               "note": (f"every {self.system_name} distribution installed for this Windows user, from WSL's own record (none started "
                        f"to look); click one to choose it for the tasks; this plugin sets up {self.distribution_name} alone"
                        + (f"; yours: {', '.join(theirs)}" if theirs else "")),
               "columns": [{"title": "Distribution"}, {"title": "State"}, {"title": "System"}, {"title": "WSL"}, {"title": "Default"},
                           {"title": "Disk"}, {"title": "Whose"}],
               "rows": rows, "empty": f"No {self.system_name} distribution installed here.",
               "select": {"hook": "pick_install", "value": chosen, "title": "Choose an install"}}
        if picked is not None:
            running, paused = picked.state == "Running", bool(self.paused(picked.name))
            out["tasks"] = {"title": "Task", "subject": picked.name, "actions": [
                {"terminal": True, "title": "Terminal", "note": f"a terminal into {picked.name}" + ("" if running else ", which starts it")},
                {"hook": "start_install", "args": [picked.name], "title": "Start", "disabled": running and not paused,
                 "note": f"resumes {picked.name}'s services" if paused else f"starts {picked.name} and keeps it running until Stop"},
                {"hook": "pause_install", "args": [picked.name], "title": "Pause", "disabled": not running or paused,
                 "note": "freezes its running services (systemd's freezer); Start resumes them"},
                {"form": "stop", "title": "Stop…", "values": {"name": picked.name}, "disabled": not running, "label": f"Stop {picked.name}"},
                {"form": "uninstall", "title": "Uninstall…", "values": {"name": picked.name}, "label": f"Uninstall {picked.name}"}]}
        return out

    def task_forms(self) -> list[dict]:
        """The tasks' forms: Stop (confirmed) and Uninstall (install_forms)."""
        return [{"id": "stop", "hook": "stop_install", "title": "Stop a distribution", "fields": [{"name": "name", "label": "Distribution", "type": "fixed"}],
                 "confirm": {"title": "Stop {name}?", "words": "Every program running in {name} ends now (wsl --terminate); Start brings it back.",
                             "yes": "Stop it"}}, *self.install_forms()]

    def status(self) -> dict:
        wsl = self.wsl.status() if self.wsl.here else {"present": False, "version": "", "distribution": ""}
        listed = self.wsl.distributions() if wsl.get("present") else []  # one list for its own and its system's installs
        d = next((x for x in listed if x.name.lower() == self.distribution_name.lower()), None)
        out = {"present": d is not None, "wsl": wsl, "distribution": self.distribution_name, "family": self.family,
               "state": d.state if d else "", "version": d.version if d else "", "user": self.user,
               "engine": {"installed": False, "version": "", "running": False}}
        name = self.distribution_name
        ours = liminal_scoped(name)
        scan = None
        installs = self.installs(listed) if wsl.get("present") else []
        if wsl.get("present"):
            out["installs"] = (", ".join(f"{i.name} ({'Liminal' if i.name.lower() == name.lower() else 'yours'}, {i.state.lower()})"
                                         for i in installs) or f"no {self.system_name} distribution")
            out["tables"] = [self.installs_table(installs)]
            for i in installs:  # a paused install seen stopped: nothing paused any more
                if i.state != "Running":
                    self._tasks["paused"].pop(i.name.lower(), None)
            out["forms"] = self.task_forms()
            out["terminalInto"] = self.chosen(installs)
        if d is not None and ours and _running(d):  # asked inside only while it runs: a status never starts it
            out["engine"] = self._engine_seen = self.engine()
            scan = self._scan_of(d)
            out["services"] = scan.describe()
            out["tables"] = [*out.get("tables", []), scan.table(name)]
        elif d is not None:
            seen = getattr(self, "_engine_seen", None) if ours else None
            out["engine"] = {**seen, "running": False} if seen else {"asked": False, "running": False}  # asking would start it
            out["services"] = {"scanned": False, "why": (f"{name} is not running: nothing runs in it, and a status does not start it"
                                                          if ours else f"{name} is not Liminal's: nothing is asked inside it")}
        e = out["engine"]
        if d is None:
            out["summary"] = "not installed" if wsl.get("present") else "WSL is not here"
        elif scan is not None:
            out["summary"] = (f"{name} ({d.state}, WSL {d.version}); Docker inside: "
                              + (("running " if e["running"] else "installed, not running ") + e["version"] if e["installed"] else "none")
                              + f"; services: {scan.summary()}")
        elif not ours:
            out["summary"] = f"{name} ({d.state}, WSL {d.version}): not Liminal's, nothing asked inside"
        else:
            seen = getattr(self, "_engine_seen", None)
            out["summary"] = (f"{name} ({d.state}, WSL {d.version}): not started to look; Docker inside: "
                              + ("not asked while it is stopped" if seen is None else f"installed {e['version']}" if e["installed"] else "none"))
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

    def services(self, fresh=False) -> dict:
        """What runs in Liminal's own distribution (the user, 2026-11-08: "a breakdown of the major services running"): its
        init system (systemd or OpenRC, or SysV scripts), the major services online apart from the system's own
        (machines.services); scanned only while it runs, kept SCAN_S (`fresh`: scanned again now)."""
        name = self.distribution_name
        d = self.wsl.distribution(name) if self.wsl.here and liminal_scoped(name) else None
        if d is None:
            return {"scanned": False, "why": f"{name} is not installed" if liminal_scoped(name) else f"{name} is not Liminal's: nothing is asked inside it"}
        scan = self._scan_of(d, fresh=fresh is True or str(fresh).lower() in ("1", "true", "yes"))
        if scan is None:
            return {"scanned": False, "why": f"{name} is not running: nothing to scan, and a scan does not start it"}
        return scan.describe()

    def _scan_of(self, d: Distribution, fresh: bool = False) -> Scan | None:
        """The services scan, kept SCAN_S; None while the distribution is not running (a scan never starts it)."""
        if d is None or not _running(d):
            return None
        kept = getattr(self, "_scan", None)
        if kept is not None and not fresh and time.monotonic() - kept[0] < SCAN_S:
            return kept[1]
        name = self.distribution_name
        try:  # one script on standard input, as root; the argument only names it (a stand-in's wsl tells it apart)
            scan = parse_scan(self.wsl.run(name, "sh", "-s", "liminal-scan", user="root", stdin=SCAN_SCRIPT, timeout=60))
        except WslError as e:
            scan = Scan(problem=f"the scan could not run in {name}: {e}", at=time.time())
        self._scan = (time.monotonic(), scan)
        return scan

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

        def begin(what: str, doing: str) -> None:  # said before a step runs: a quiet one does not look stuck
            log(f"{self.name}: {what}: {doing}...")

        try:
            if "wsl" in wanted:
                begin("wsl", "looking for WSL")
                if not self.wsl.here:
                    return done if step("wsl", False, "this is not Windows, or the wsl command is missing") else done
                st = self.wsl.status()
                if st.get("present"):
                    step("wsl", None, f"WSL is there (default version {st.get('version') or '?'})")
                else:
                    self.wsl.install_feature()
                    step("wsl", True, "WSL installed (Windows may ask to restart before a distribution runs)")
            if "update" in wanted:
                begin("update", "updating WSL (wsl --update): it can say nothing for a minute or two")
                self.wsl.update(out=stream)
                step("update", True, "WSL updated")
            if "version" in wanted:
                begin("version", "making WSL 2 the version new distributions get")
                self.wsl.set_default_version(2)
                step("version", True, "new distributions get WSL 2")
            if "distribution" in wanted:
                if self.wsl.distribution(name) is not None:
                    step("distribution", None, f"{name} is installed")
                elif self.install_name:
                    begin("distribution", f"installing {name} from Microsoft's {self.install_name} (wsl --install); the download follows")
                    self.wsl.install(self.install_name, name=name, location=self.data / "root", out=stream)
                    step("distribution", True, f"{name} installed from Microsoft's {self.install_name} into {self.data / 'root'}, not launched")
                else:
                    begin("distribution", f"getting {name}'s root file system")
                    tarball = self.tarball(out=stream)
                    begin("distribution", f"importing {name} from {tarball.name}")
                    self.wsl.import_(name, self.data / "root", tarball, out=stream)
                    step("distribution", True, f"{name} imported from {tarball.name} into {self.data / 'root'}")
            if "conf" in wanted:
                begin("conf", f"writing /etc/wsl.conf (systemd, the default user {self.user}) and restarting {name}")
                self.wsl.write_file(name, "/etc/wsl.conf", f"[boot]\nsystemd=true\n\n[user]\ndefault={self.user}\n")
                self.wsl.script(name, f"id -u {shlex.quote(self.user)} >/dev/null 2>&1 || useradd -m -s /bin/bash {shlex.quote(self.user)}\n")
                self.wsl.terminate(name)
                step("conf", True, f"/etc/wsl.conf: systemd on, default user {self.user} (made when absent); {name} restarted")
            if "docker" in wanted:
                if self.engine()["installed"]:
                    step("docker", None, "Docker is installed inside")
                else:
                    begin("docker", f"installing Docker by {self.family} from Docker's own repository; its output follows")
                    self.wsl.script(name, self.install_script(), timeout=INSTALL_TIMEOUT_S, out=stream)
                    step("docker", True, f"Docker installed by {self.family} from Docker's own repository")
            if "engine" in wanted:
                begin("engine", "starting the engine and enabling it at boot")
                how = self.wsl.script(name, ENGINE_SCRIPT, timeout=600).strip().splitlines()
                step("engine", True, f"the engine started and enabled ({how[-1] if how else 'started'})")
            if "user" in wanted:
                begin("user", f"adding {self.user} to the docker group")
                self.wsl.script(name, f"groupadd -f docker\nusermod -aG docker {shlex.quote(self.user)}\n")
                step("user", True, f"{self.user} in the docker group")
        except WslError as e:
            step(wanted[len(done)] if len(done) < len(wanted) else "setup", False, str(e))
        return done

    def run(self, *command: str, user: str | None = None, stdin: str | None = None, timeout: float = TIMEOUT_S) -> str:
        return self.wsl.run(self.distribution_name, *command, user=user, stdin=stdin, timeout=timeout)

    def instances(self) -> tuple[Instance, ...]:
        name = self.distribution_name
        d = self.wsl.distribution(name) if self.wsl.here else None
        if d is None:
            return ()
        if _running(d):
            self._engine_seen = self.engine()
        seen = getattr(self, "_engine_seen", None)
        if seen is not None and not seen["installed"]:
            return ()  # seen without Docker; a stopped one is not started to ask: its instance starts it when used
        return (Instance(self.name, f"Docker in {name} under WSL 2", command=f"wsl -d {name} --exec docker", source=self.name, translate=wsl_path),)

    # -- a distribution imported from a tarball (Gentoo) --------------------------------------------
    def tarball_url(self) -> str:
        """Where the root file system tarball comes from; a subclass that imports says."""
        raise WslError(f"{self.name} has no tarball to import and no name on Microsoft's list")

    def tarball(self, out=None) -> Path:
        """The tarball downloaded into the plugin's data folder, once; with `out`, how far the download has got."""
        url = self.tarball_url()
        path = self.data / url.rsplit("/", 1)[-1]
        if not path.is_file():
            path.parent.mkdir(parents=True, exist_ok=True)
            if self._fetch is not None:
                self._fetch(url, path)
            else:
                _download(url, path, out=out)
        return path


def _download(url: str, path: Path, out=None) -> None:
    """`url` saved as `path` (a part file renamed once whole); with `out`, how far it has got, on one line rewritten."""
    import urllib.request

    part = path.with_name(path.name + ".part")
    with urllib.request.urlopen(url, timeout=120) as r, open(part, "wb") as f:  # noqa: S310 - the plugin's own url
        total = int(r.headers.get("Content-Length") or 0)
        got, said = 0, -1.0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
            got += len(chunk)
            now = time.monotonic()
            if out is not None and now - said >= 1.0:
                said = now
                out(f"\rdownloading {path.name}: {got / 2**20:.0f} MB" + (f" of {total / 2**20:.0f} MB ({got * 100 // total}%)" if total else ""))
        if out is not None:
            out(f"\rdownloaded {path.name}: {got / 2**20:.0f} MB" + " " * 24 + "\n")
    os.replace(part, path)


def _running(d) -> bool:
    """Whether WSL lists the distribution as running (a stopped one is never started to look inside it)."""
    return str(getattr(d, "state", "")).lower() == "running"


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
