"""A private Node.js and its npm, for the plugins whose software is a Node.js program (1.66.0; the user, 2026-11-18:
"top 4 inference engines, top 4 agentic harnesses (open source)"; "both linux and windows compatibility"): Pi's,
Cline's, the MCP catalogue's Node.js servers and Continue's. Lifted from plugin-platform-continue 0.1.0, which proved
it: its Node.js archive, npm-cli.js, the settings npm is run without (DROP), the empty npmrc and the check of the top
package's sha512 in npm's lock.

Each plugin brings its own copy of Node.js, on the line its users ask for (NODE_LINE, 24: its LTS; Node.js 22's ends
on 2027-04-30, and the MCP reference servers ask for 24), from the address, the size and the sha256 it pins (its own
download.Source: no host is named here). Its archives (`archive`, STRIP, `programs`): node-v<version>-win-<machine>.zip
on Windows and node-v<version>-linux-<machine>.tar.xz on Linux, each one folder named as the archive (unpacked with
strip 1), with node and npm-cli.js where Node.js's packaging puts them. Node.js publishes no build for a musl Linux
(`musl_here`). npm is always run as that node with that npm-cli.js, both by their whole paths: never a node or an npm
found on PATH, and never npm.cmd, which needs cmd.exe.

What npm is run with (`environment`, `child_env`, `write_npmrc`): its cache where the plugin says (in its downloads/,
so an install that failed or was cancelled leaves it for the next try), an empty user and global configuration (no
.npmrc of the user's is read), the registry the plugin names (its constant), and none of the user's npm or Node.js
settings: every npm_config_* name whatever its case, NODE_*, the proxy variables npm's agent reads and OpenSSL's
configuration (DROP). Proxies and certificate authorities of the user's own are left out, as the library's own
downloads leave them. The environment is made whole here and handed to `install` and `ci`, which refuse to run
without one: AiPlugin's child_env() takes out the plugins' names alone.

Every npm command has FLAGS, word for word: --ignore-scripts (no package's script runs: npm install and npm ci both
run install scripts unless told not to), --no-audit (no report of the tree goes to the registry), --no-fund and
--no-update-notifier (no notice, and no ask of the registry for a newer npm).

What is checked. A plugin pins its top package (`Pin`: its name, its exact version and the sha512 the registry gives
for it), and `install` puts it into a folder of its own (--prefix, --save-exact). npm checks every package it
downloads against the sum the registry gives for it. The top package's sha512, as npm's lock records it, is compared
with the plugin's pin before anything is put in use (`checked`): another sum, or none, and nothing is. Its
dependencies are resolved by npm from the registry on the day and checked against the registry's own sums alone:
none of them is pinned in the plugin, since no lock can be made for it without running npm (`checked_words` says so
on the page).

The kept lock (`put`, `lock_folder`, `keep_lock`, `lock_holds`, `restore_lock`): the package.json and the
package-lock.json npm wrote are kept in the plugin's own folder (home/config/npm/<the pin>), which an uninstall leaves.
A repair or a reinstall of the same pin installs exactly that tree again with `npm ci` from them, each package checked
against the sum the lock records. Each command's lines go to `log` as they come; `cancel` is handed to the runner,
which ends npm and what it started; a command that does not end with 0 raises NpmError in its words. The runner is
children.stream, taken when a command is run: a plugin hands its own (`stream`), as it does to uv.py's commands."""
from __future__ import annotations

import json
import os
import platform
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit

from . import children
from .download import PART, DownloadError
from .plugin import CommandError
from .terminal import Cancelled

NODE_LINE = 24  # the Node.js line the plugins pin: its LTS
# every npm command's switches, word for word (the module's words)
FLAGS = ("--ignore-scripts", "--no-audit", "--no-fund", "--no-update-notifier")
# What npm and the Node.js it runs on read from the environment as a setting, taken out of npm's environment whatever a
# name's case (npm's own four come over it): npm's settings (npm_config_*: its config page says their case does not
# count), Node.js's own variables (NODE_OPTIONS, NODE_TLS_REJECT_UNAUTHORIZED, NODE_EXTRA_CA_CERTS and the rest), the
# proxy variables npm's agent reads in any case (https_proxy, http_proxy, proxy, no_proxy) and the OpenSSL
# configuration Node.js loads at its start
DROP = ("npm_config_*", "NODE_*", "HTTPS_PROXY", "HTTP_PROXY", "PROXY", "NO_PROXY", "OPENSSL_CONF")
NPM_S = 900.0  # seconds an npm command is given at the most
STRIP = 1  # leading folders left out when Node.js's archive is unpacked: its one top folder
MACHINES = {"amd64": "x64", "x86_64": "x64", "x64": "x64", "em64t": "x64", "arm64": "arm64", "aarch64": "arm64",
            "arm64e": "arm64"}  # a processor as Python says it, as Node.js's archives name it
ARCHIVED = ("x64", "arm64")  # the processors an archive is named for here, on both systems
KINDS = {"windows": ("win", ".zip"), "linux": ("linux", ".tar.xz")}  # (the system's word, the archive's kind)
# where Node.js's packaging puts node and npm-cli.js, under the folder its archive was unpacked into (strip 1)
PROGRAM = {"windows": ("node.exe",), "linux": ("bin", "node")}
NPM_CLI = {"windows": ("node_modules", "npm", "bin", "npm-cli.js"),
           "linux": ("lib", "node_modules", "npm", "bin", "npm-cli.js")}
MANIFEST = "package.json"
LOCK = "package-lock.json"
HIDDEN_LOCK = ("node_modules", ".package-lock.json")  # the lock npm keeps of what node_modules holds
NPMRC = ("config", "npmrc")  # npm's user and global configuration, empty, under a plugin's folder
LOCKS = ("config", "npm")  # the kept locks, under a plugin's folder: one folder for each pin
JSON_MOST = 4 << 20  # bytes of a package.json or a lock read at the most
TAIL = 8  # the lines kept for an error's words
SAID = 300  # characters of a line in an error's words
WHOLE_LOG = "A complete log of this run"  # npm's last line on a failure: never its words
# a package's name on the registry (name, or @scope/name, as npm's rules have it for a new one), its exact version
# (never a range or a tag) and the sha512 the registry gives for it (dist.integrity)
NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
NAME_MOST = 214
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
VERSION_MOST = 80
INTEGRITY = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")


class NpmError(CommandError):
    """An npm command that did not do what was asked, or an install that is not what is pinned, in words."""


# -- this machine and Node.js's archives -------------------------------------------------------------------------------
def machine_word(raw=None) -> str:
    """This machine's processor as Node.js's archives name it ("x64", "arm64"), else as Python says it, lowered
    (`raw`: None, this machine's)."""
    said = str(platform.machine() if raw is None else raw or "").strip().lower()
    return MACHINES.get(said, said or "unknown")


def musl_here(*, system: str | None = None, exists: Callable = os.path.exists,
              libc: Callable = platform.libc_ver) -> bool:
    """Whether this is a musl Linux, for which Node.js publishes no build: /etc/alpine-release is there, or Python's
    own word on its C library does not name glibc. Never on Windows. Told without running anything; `system`,
    `exists` and `libc` are a test's stand-ins."""
    if (system or children.this_system()) == "windows":
        return False
    if exists("/etc/alpine-release"):
        return True
    try:
        library, _ = libc()
    except (OSError, ValueError):
        return False
    return library != "glibc"


def _version(version) -> str:
    text = str(version or "").strip()
    text = text[1:] if text[:1] in ("v", "V") else text
    if len(text) > VERSION_MOST or not VERSION.fullmatch(text):
        raise ValueError(f"a version of Node.js is three numbers (24.11.1), not {str(version or '')[:40]!r}")
    return text


def archive(version, system: str, machine: str | None = None) -> str:
    """The name of Node.js's archive of `version` (24.11.1) for a system: node-v24.11.1-win-x64.zip on Windows,
    node-v24.11.1-linux-x64.tar.xz on Linux. `machine` as platform.machine() says it (None: this one's). ValueError
    for a version that is no version and for a system or a processor no archive is named for here: Windows or Linux
    on x86-64 or ARM64."""
    text = _version(version)
    which = str(system or "").strip().lower()
    arch = machine_word(machine)
    if which not in KINDS or arch not in ARCHIVED:
        raise ValueError(f"no archive of Node.js is named here for {system!r} on {machine or platform.machine()!r}: "
                         "Windows or Linux on x86-64 or ARM64")
    word, kind = KINDS[which]
    return f"node-v{text}-{word}-{arch}{kind}"


def programs(folder, system: str, archive_name: str = "") -> tuple[Path, Path]:
    """node and npm-cli.js in the folder Node.js's archive was unpacked into (with STRIP), where Node.js's packaging
    puts them: node.exe and node_modules/npm/bin/npm-cli.js on Windows, bin/node and lib/node_modules/npm/bin/npm-cli.js
    on Linux. DownloadError in words when one of them is not there (`archive_name`: the archive's, for the words)."""
    root = Path(os.path.abspath(folder))
    which = "windows" if str(system or "").strip().lower() == "windows" else "linux"
    node, npm = root.joinpath(*PROGRAM[which]), root.joinpath(*NPM_CLI[which])
    named = archive_name or "Node.js's archive"
    for what, path in (("node", node), ("npm-cli.js", npm)):
        if not path.is_file():
            raise DownloadError(f"{named} holds no {what} where Node.js's packaging puts it "
                                f"({path.relative_to(root).as_posix()}): nothing is installed")
    return node, npm


# -- what npm is run with ----------------------------------------------------------------------------------------------
def reads(name) -> bool:
    """Whether npm or the Node.js it runs on reads the variable `name` as a setting (DROP), whatever its case."""
    upper = str(name).upper()
    return any(upper.startswith(p[:-1].upper()) if p.endswith("*") else upper == p.upper() for p in DROP)


def dropped(env: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """What npm is run without: DROP, then each name of `env` (this process's environment unless given) that npm or
    its Node.js reads, as it is written there. On Linux a name's case counts, and npm still reads npm_config_* and
    the proxy variables in any case."""
    base = os.environ if env is None else env
    return tuple(dict.fromkeys([*DROP, *(str(n) for n in base if reads(n))]))


def _registry(address) -> str:
    """The registry npm asks: an https address with a host and no name or password in it, else ValueError. Its words
    never repeat the address: a refused one may hold what it should not."""
    text = str(address or "").strip()
    if not text:
        raise ValueError("npm asks the registry the plugin names, and none was named")
    if re.search(r"//[^/?#]*@", text):
        raise ValueError("npm's registry is named without a name or a password in its address")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("npm's registry is one address, with no space or control character in it")
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        parts, host = None, None
    if parts is None or parts.scheme.lower() != "https" or not host:
        raise ValueError("npm's registry is asked over https alone: give its whole https address")
    return text


def environment(cache, npmrc, registry: str) -> dict[str, str]:
    """npm's own variables for a command (each said beside it), laid over an environment without any setting of the
    user's (`child_env` makes the whole of it)."""
    rc = os.path.abspath(os.fspath(npmrc))
    return {
        "npm_config_cache": os.path.abspath(os.fspath(cache)),  # what it downloads: the plugin's folder's
        "npm_config_userconfig": rc,  # the user's configuration ...
        "npm_config_globalconfig": rc,  # ... and the global one: the one empty file (write_npmrc)
        "npm_config_registry": _registry(registry),  # the plugin's constant: no setting of the user's moves it
    }


def child_env(cache, npmrc, registry: str, *, base: Mapping[str, str] | None = None, drop: str | Iterable[str] = (),
              system: str | None = None) -> dict[str, str]:
    """The whole environment `install`, `ci` and `put` are handed: `base` (this process's own unless given: a
    plugin's Outside env) without what npm or its Node.js reads as a setting (`dropped`), without every LIMINAL_*
    name and without what `drop` names (an AI plugin hands its dropped(): every variable an installed plugin
    declares), each a name or a prefix ending "*"; then `environment(...)` laid over it. On Windows (`system`: this
    one unless given) names are told apart without regard to case, as Windows does (children.environment)."""
    given = os.environ if base is None else base
    named = (drop,) if isinstance(drop, str) else tuple(drop or ())
    launch = children.Launch((), env=environment(cache, npmrc, registry),
                             drop=(*dropped(given), "LIMINAL_*", *(str(n) for n in named if str(n).strip())))
    return children.environment(launch, base=given, system=system)


def _write_whole(path: Path, text: str) -> None:
    """A file written whole: a part file beside it, renamed over it once written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_name(path.name + PART)
    with open(part, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(part, path)


def write_npmrc(home) -> Path:
    """npm's user and global configuration for a plugin: home/config/npmrc, an empty file written whole, so that no
    setting of the user's reaches npm. Its path."""
    path = Path(os.path.abspath(home)).joinpath(*NPMRC)
    _write_whole(path, "")
    return path


# -- a pinned package --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Pin:
    """A top package as its plugin pins it: its `name` on the registry (name, or @scope/name), its exact `version`
    (1.5.47: never a range or a tag) and `integrity`, the sha512 the registry gives for it (dist.integrity: "sha512-"
    and 88 characters of base64). ValueError in words when one of them cannot be."""

    name: str
    version: str
    integrity: str

    def __post_init__(self):
        name, version, integrity = (str(v or "").strip() for v in (self.name, self.version, self.integrity))
        if len(name) > NAME_MOST or not NAME.fullmatch(name):
            raise ValueError(f"a pinned package is named as the registry names it (name, or @scope/name: lowercase "
                             f"letters, digits, . _ ~ -), not {name[:60]!r}")
        if len(version) > VERSION_MOST or not VERSION.fullmatch(version):
            raise ValueError(f"a pinned package's version is an exact one (1.5.47), never a range or a tag: not "
                             f"{version[:40]!r}")
        if not INTEGRITY.fullmatch(integrity):
            raise ValueError(f"a pinned package's sum is the sha512 the registry gives for it (sha512- and 88 "
                             f"characters of base64), not {integrity[:20]!r}…")
        for key, value in (("name", name), ("version", version), ("integrity", integrity)):
            object.__setattr__(self, key, value)

    @property
    def spec(self) -> str:
        """What npm is asked to install: name@version."""
        return f"{self.name}@{self.version}"

    @property
    def folder(self) -> str:
        """The name of its kept lock's folder: scope+name@version (no slash, and no name npm allows holds a +)."""
        return f"{self.name.lstrip('@').replace('/', '+')}@{self.version}"

    def where(self, prefix) -> Path:
        """Its folder once npm installed it into `prefix`: prefix/node_modules/<its name>."""
        return Path(os.path.abspath(prefix)).joinpath("node_modules", *self.name.split("/"))


def checked_words(title: str) -> str:
    """What of an install by npm is checked, in words for a Package's `checked` (after the plugin's own words on its
    Node.js archive): `title`, the pinned package's own name in words."""
    return (f"npm, given none of your npm or Node.js settings and no proxy, checks every package against the sum the "
            f"registry gives for it; {title}'s own sha512, as npm's lock records it, is compared with the one pinned "
            "in this plugin before it is put in use, and nothing is put in use without that comparison. The packages "
            f"npm resolves for {title} on the day are pinned in no file of this plugin's: a repair or a reinstall of "
            "the same pin installs exactly those again, from the lock kept at its first install.")


# -- what npm wrote ----------------------------------------------------------------------------------------------------
def _read(path: Path, most: int = JSON_MOST) -> str | None:
    """A small file's text; None when it is not there, too large or not text."""
    try:
        if path.stat().st_size > most:
            return None
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return None


def _json(path: Path):
    text = _read(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def entry_of(package, command: str = "") -> tuple[Path, str] | None:
    """The program a package's package.json names under bin (`command`'s, where bin names several; its one program
    where bin is a text or names one alone), and the package's version: None when that program is not there, or is
    named outside the package's folder."""
    folder = Path(os.path.abspath(package))
    manifest = _json(folder / MANIFEST)
    if not isinstance(manifest, dict):
        return None
    named = manifest.get("bin")
    if isinstance(named, dict):
        named = named.get(command) if command else (next(iter(named.values())) if len(named) == 1 else None)
    if not isinstance(named, str) or not named.strip():
        return None
    parts = named.replace("\\", "/").split("/")
    if named.startswith(("/", "\\")) or ".." in parts or ":" in named:
        return None
    entry = folder.joinpath(*[p for p in parts if p and p != "."])
    return (entry, str(manifest.get("version") or "")) if entry.is_file() else None


def recorded(prefix, pin: Pin) -> str:
    """The sums npm's lock records for the top package `pin` names, as one text ("" for none): its package-lock.json
    first, then the lock it keeps in node_modules."""
    root = Path(os.path.abspath(prefix))
    for lock in (root / LOCK, root.joinpath(*HIDDEN_LOCK)):
        data = _json(lock)
        packages = data.get("packages") if isinstance(data, dict) else None
        row = packages.get(f"node_modules/{pin.name}") if isinstance(packages, dict) else None
        if isinstance(row, dict) and isinstance(row.get("integrity"), str):
            return row["integrity"]
    return ""


def checked(prefix, pin: Pin, command: str = "") -> str:
    """The package npm installed into `prefix`, looked at before it is put in use: its version, the program `command`
    names in its package.json (when one is given), and its sha512 as npm's lock records it, against the pin. Its line
    when all hold; NpmError in words when one does not, and when no lock records its sha512 (it is then not compared,
    so nothing is put in use)."""
    package = pin.where(prefix)
    manifest = _json(package / MANIFEST)
    if not isinstance(manifest, dict) or (command and entry_of(package, command) is None):
        whole = "its package.json and the program it names" if command else "its package.json"
        raise NpmError(f"npm ended, and {pin.name} is not in {package} whole ({whole}): nothing is put in use")
    version = str(manifest.get("version") or "")
    if version != pin.version:
        raise NpmError(f"npm installed {pin.name} {version or '(no version)'}, not {pin.version}: nothing is put in "
                       "use")
    sums = recorded(prefix, pin).split()
    if pin.integrity in sums:
        return f"{pin.name} {pin.version}: its sha512, as npm's lock file records it, is the one pinned in this plugin"
    if any(s.startswith("sha512-") for s in sums):
        raise NpmError(f"npm installed {pin.name} {pin.version} with another sha512 than the one pinned in this "
                       "plugin: nothing is put in use")
    raise NpmError(f"npm's lock file records no sha512 of {pin.name} {pin.version}, so it cannot be compared with the "
                   "one pinned in this plugin: nothing is put in use")


# -- the kept lock -----------------------------------------------------------------------------------------------------
def lock_folder(home, pin: Pin) -> Path:
    """Where the lock of `pin` is kept under a plugin's folder: home/config/npm/<scope+name@version>, which an
    uninstall leaves."""
    return Path(os.path.abspath(home)).joinpath(*LOCKS, pin.folder)


def _os_words(e: OSError) -> str:
    said = e.strerror or str(e) or type(e).__name__
    return f"{said}: {e.filename}" if e.filename else said


def _forget_kept(target: Path) -> None:
    """What is kept in `target` of an earlier install forgotten (its lock first), so that none of it stands for the
    one that could not be kept: as far as it can be."""
    for name in (LOCK, MANIFEST):
        try:
            (target / name).unlink()
        except OSError:
            pass


def keep_lock(prefix, folder) -> list[str]:
    """The package.json and the package-lock.json npm wrote in `prefix` kept in `folder` (each written whole), for a
    repair or a reinstall of the same pin: its line. Where npm wrote no lock, or it cannot be kept, that is said and
    nothing is kept (what an earlier install kept there is forgotten): a repair then resolves the packages again."""
    source, target = Path(os.path.abspath(prefix)), Path(os.path.abspath(folder))
    texts: dict[str, str] = {}
    for name in (MANIFEST, LOCK):
        text = _read(source / name)
        if text is None:
            _forget_kept(target)
            return [f"npm wrote no {name} in {source}: no lock is kept, and a repair resolves its packages again"]
        texts[name] = text
    try:
        for name in (MANIFEST, LOCK):  # (the lock last: a folder holding it holds both)
            _write_whole(target / name, texts[name])
    except OSError as e:
        _forget_kept(target)
        return [f"npm's lock could not be kept in {target} ({_os_words(e)}): a repair resolves its packages again"]
    return [f"npm's lock is kept in {target}: a repair or a reinstall of the same pin installs the same packages "
            "from it (npm ci)"]


def lock_holds(folder, pin: Pin) -> str:
    """"" when the lock kept in `folder` is `pin`'s: its package.json names that one package at that very version,
    and its package-lock.json records that version and the pinned sha512. Otherwise why not, in words."""
    root = Path(os.path.abspath(folder))
    if not os.path.lexists(root / MANIFEST) and not os.path.lexists(root / LOCK):
        return f"no lock of {pin.spec} is kept in {root}"
    manifest, lock = _json(root / MANIFEST), _json(root / LOCK)
    if not isinstance(manifest, dict) or not isinstance(lock, dict):
        return f"the lock kept in {root} is not whole: its {MANIFEST} and its {LOCK} are not both readable"
    wanted = manifest.get("dependencies")
    if not isinstance(wanted, dict) or wanted != {pin.name: pin.version}:
        return f"the lock kept in {root} is not {pin.spec}'s alone"
    packages = lock.get("packages")
    row = packages.get(f"node_modules/{pin.name}") if isinstance(packages, dict) else None
    if not isinstance(row, dict) or row.get("version") != pin.version:
        return f"the lock kept in {root} records no {pin.spec}"
    if pin.integrity not in str(row.get("integrity") or "").split():
        return f"the lock kept in {root} records another sha512 of {pin.spec} than the one pinned in this plugin"
    return ""


def restore_lock(folder, prefix) -> None:
    """The lock kept in `folder` (its package.json and package-lock.json) written whole into `prefix`, made when it is
    not there: what `ci` installs. OSError as the system says it."""
    source, target = Path(os.path.abspath(folder)), Path(os.path.abspath(prefix))
    for name in (MANIFEST, LOCK):
        text = _read(source / name)
        if text is None:
            raise OSError(f"{source / name} could not be read")
        _write_whole(target / name, text)


# -- its commands ------------------------------------------------------------------------------------------------------
def _whole(path, what: str) -> str:
    text = os.fspath(path) if path else ""
    if not text or not os.path.dirname(text):
        raise ValueError(f"the private Node.js's {what} is named by its whole path: a bare name would be whichever one "
                         "is on PATH")
    return os.path.abspath(text)


def _said(last: Iterable[str]) -> str:
    """npm's own last word on a failure: its last line that says something, its pointer to its log left out."""
    for text in reversed(list(last)):
        if text.strip() and WHOLE_LOG not in text:
            return text.strip()[:SAID]
    return ""


def _ready(node, npm, env: Mapping[str, str] | None, cancel, name: str) -> tuple[str, str]:
    """node's and npm-cli.js's whole paths, once a command `name` may be run: ValueError without its environment or
    for a bare name, Cancelled when its user cancelled (nothing is made, said or run then)."""
    if env is None:
        raise ValueError("npm is run with an environment given whole (child_env): without one it would inherit every "
                         "setting of yours and every pair the platform keeps")
    program, cli = _whole(node, "node"), _whole(npm, "npm-cli.js")
    if cancel is not None and cancel():
        raise Cancelled(f"cancelled before `{name}` was started")
    return program, cli


def _run(node, npm, args: list[str], name: str, first: str, failed: str, *, env: Mapping[str, str] | None, log,
         cancel, timeout: float, stream, cwd: Path) -> None:
    """One npm command run to its end in a folder of the plugin's own (`cwd`, made when it is not there), what it is
    about (`first`) and then its lines to `log`. NpmError when it does not end with 0 (`failed`, its words, then npm's
    last), Cancelled when its user cancelled (before it starts: nothing is made, said or run; or from the runner)."""
    program, cli = _ready(node, npm, env, cancel, name)
    try:
        cwd.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise NpmError(f"`{name}` was not started: {cwd} could not be made ({_os_words(e)})") from None
    if log is not None:
        log(first)
    last: deque[str] = deque(maxlen=TAIL)

    def line(text) -> None:
        said = str(text).rstrip("\r\n")
        last.append(said)
        if log is not None:
            log(said)

    run = stream if stream is not None else children.stream
    code = run([program, cli, *args], line, env=dict(env), cwd=str(cwd), timeout=timeout, cancel=cancel)
    if code != 0:
        said = _said(last)
        raise NpmError(f"npm ended with exit code {code}: {failed} ("
                       + (f"its last line: {said}" if said else "npm's lines are in the panel") + ")")


def install(node, npm, prefix, pin: Pin, *, env: Mapping[str, str], log, cancel, timeout: float = NPM_S,
            stream: Callable | None = None) -> None:
    """`pin` installed by npm into `prefix`, a project of its own (its folder, made when it is not there):
    `NODE NPM-CLI.JS install --prefix PREFIX --save-exact --ignore-scripts --no-audit --no-fund --no-update-notifier
    NAME@VERSION`, run in that folder. npm checks each package against the sum the registry gives for it; what it
    installed is the caller's to check (`checked`) before anything is put in use."""
    target = Path(os.path.abspath(prefix))
    _run(node, npm, ["install", "--prefix", str(target), "--save-exact", *FLAGS, pin.spec], f"npm install {pin.spec}",
         f"npm: {pin.spec} into {target}; npm resolves its dependencies from the registry and checks each against "
         "the registry's own sum (none of them is pinned in this plugin)",
         f"{pin.name} {pin.version} is not installed", env=env, log=log, cancel=cancel, timeout=timeout,
         stream=stream, cwd=target)


def ci(node, npm, prefix, pin: Pin, *, env: Mapping[str, str], log, cancel, timeout: float = NPM_S,
       stream: Callable | None = None) -> None:
    """Exactly the packages of the lock in `prefix` installed again by npm (a repair, a reinstall of the same pin):
    `NODE NPM-CLI.JS ci --prefix PREFIX --ignore-scripts --no-audit --no-fund --no-update-notifier`, run in that
    folder. npm checks each package against the sum the lock records; what it installed is the caller's to check
    (`checked`) before anything is put in use."""
    target = Path(os.path.abspath(prefix))
    _run(node, npm, ["ci", "--prefix", str(target), *FLAGS], f"npm ci {pin.spec}",
         f"npm: the packages of the lock kept for {pin.spec} into {target} (npm ci), each checked against the sum the "
         "lock records", f"{pin.name} {pin.version} is not installed from its lock", env=env, log=log, cancel=cancel,
         timeout=timeout, stream=stream, cwd=target)


def _nothing_in(folder: Path) -> None:
    """NpmError unless nothing is at `folder`, or an empty folder: npm installs a pin only into a folder of its own."""
    try:
        empty = not folder.exists() or (folder.is_dir() and next(folder.iterdir(), None) is None)
    except OSError as e:
        raise NpmError(f"{folder} could not be looked at: {_os_words(e)}") from None
    if not empty:
        raise NpmError(f"{folder} is not empty: npm installs a pinned package only where there is nothing yet (what an "
                       "install that did not end left there is removed first)")


def put(node, npm, prefix, pin: Pin, *, kept, env: Mapping[str, str], log, cancel, command: str = "",
        fresh: bool = False, timeout: float = NPM_S, stream: Callable | None = None) -> list[str]:
    """`pin` installed into `prefix`, a folder where nothing is yet, and checked before anything is put in use: from
    the lock kept in `kept` with `npm ci` when that lock is the pin's (`lock_holds`) and `fresh` is not asked; else
    with `npm install` of the pin, whose lock is then kept in `kept` (`lock_folder` names a plugin's) for the next
    repair or reinstall. Then `checked`: its version, the program `command` names (when one is given) and its sha512
    as npm's lock records it. Its lines, for the install's answer. NpmError in words for an npm that failed or an
    install that is not what is pinned (no lock is kept from it then), Cancelled when its user cancelled; `prefix` is
    the caller's to remove after either."""
    target, folder = Path(os.path.abspath(prefix)), Path(os.path.abspath(kept))
    _nothing_in(target)
    why = "a fresh install was asked" if fresh else lock_holds(folder, pin)
    lines: list[str] = []
    if not why:
        _ready(node, npm, env, cancel, f"npm ci {pin.spec}")  # (before the lock is put there: nothing made for naught)
        try:
            restore_lock(folder, target)
        except OSError as e:
            raise NpmError(f"the lock kept in {folder} could not be put in {target}: {_os_words(e)}") from None
        ci(node, npm, target, pin, env=env, log=log, cancel=cancel, timeout=timeout, stream=stream)
        return [f"{pin.spec}: installed again from the lock kept in {folder}, the packages of its first install",
                checked(target, pin, command)]
    if os.path.lexists(folder / LOCK) or fresh:
        lines.append(f"{why}: npm resolved {pin.spec}'s packages again")
    install(node, npm, target, pin, env=env, log=log, cancel=cancel, timeout=timeout, stream=stream)
    lines.append(checked(target, pin, command))
    return [*lines, *keep_lock(target, folder)]
