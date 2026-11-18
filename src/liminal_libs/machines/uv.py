"""uv, for the plugins whose software is a Python program installed into an environment of its own (1.62.0; the
user, 2026-11-16: "all three plugins need to allow installation and configuration of their respective code"): vLLM's
and Aider's. Each plugin brings its own copy of uv from the address, the size and the sum it pins (no host is named
here); what they ask of it is spelled here once, as its maker documents it (uv's reference pages for its environment
variables, its command line, its storage, its authentication and its installer, read at uv 0.13.8, and its source at
that tag where the pages say nothing).

Its archives (`archive`, `strip_of`, `program_in`): Windows' .zip holds uv.exe at its root (unpacked with strip 0),
Linux's .tar.gz one folder named as the archive, holding uv (strip 1). One strip for both would leave nothing, or uv
one folder down. A plugin keys its pin (the size and the sha256 its maker publishes) by the archive's name.

`environment(home)` is what uv is run with, so that everything it keeps lies in one folder of the plugin's own,
`home`/uv (its cache where `cache` says, when that is given), and nothing of the user's own uv is read or touched:
each variable it sets is said there, beside it.

`uv self update` refuses to run for a copy its installer did not put there (no install receipt: its maker's source),
which is how a plugin brings its copy, and nothing here runs it; its maker documents no switch that turns it off, so
UV_INSTALL_DIR and UV_NO_MODIFY_PATH only bound what a later uv might write. A variable of the user's own would still
reach uv (UV_CONFIG_FILE names a configuration file by itself; UV_INDEX_URL, UV_PYTHON, a PYTHONPATH; PYX_API_KEY, a
token for Astral's own index), so the child's environment is the platform's without `DROP`, with `environment(home)`
over it. `child_env(home, base=..., drop=...)` makes it so (children.environment does both), every LIMINAL_* name and
what the plugin drops (an AI plugin hands its dropped(): every variable an installed plugin declares) taken out too,
and it is handed to `venv` and `pip_install` whole: they refuse to run without one. It is never made by AiPlugin's
child_env() or stream(), which take out the plugin's names alone and would lay this one over the platform's UV_*.
What is left of the user's passes as it is: proxies (HTTPS_PROXY ...) and certificates (SSL_CERT_FILE, SSL_CERT_DIR)
for a network that needs them (a user's UV_SYSTEM_CERTS goes with the rest of UV_*: uv then trusts the roots built
into it), and the user's netrc (~/.netrc, or the file NETRC names), which uv reads whatever it is told (its maker's
page: always on; a NETRC naming a file that is not there falls back to ~/.netrc, its source) and which only ever
hands a host the login written for that host.

Where its Python comes from: uv 0.13.8 asks Astral's own mirror of the Python builds first and GitHub's releases only
when that fails (its source), and checks each against the sum built into it. A plugin names both among the hosts it
says before an install, or holds uv to one address with `environment(home, python_mirror=...)`
(UV_PYTHON_INSTALL_MIRROR: then only that address is asked). Which Python a version means is fixed by the uv pinned:
at uv 0.13.8 "3.12" is CPython 3.12.16, build 20261110 (what a plugin's words can name). Its packages come from the
default index (PyPI) and the one more index a plugin may name (`index`), each over https alone.

What is installed is checked against sums a plugin pins only through a requirements file of the plugin's
(`pip_install(..., requirements=FILE)`): uv's hash-checking mode (--require-hashes) then refuses every file whose
sha256 is not in it and every package it does not list, so it holds the whole tree, each package pinned with == and
followed by its --hash=sha256 sums (as `uv pip compile --generate-hashes` writes one). Without one uv takes each
package as its index gives it over https and no sum pinned here checks it: the log's first line says which it was.

`home` is the folder the install is built in (app/<pin>, the base's one layout: A-revisions M11), so that its
Python leaves with it, with `cache` outside it: the plugin's downloads/uv (A-inference's UV_CACHE_DIR), where the
base's words after a cancel and its forget_downloads look, so that a cancelled or failed install, whose folder the
base removes, leaves what uv downloaded (gigabytes, for vLLM) for the next try. Without `cache`, uv's cache is
`home`/uv/cache and leaves with that folder: the next try downloads it all again, and nothing may say it was kept.
The plugin's own folder may be `home` instead: everything uv keeps is then kept from one pin to the next, and the
plugin's uninstall (its remove_from) removes `home`/uv. Each command's lines go to `log` as they come; `cancel` is
handed to the runner, which ends the command and what it started; a command that does not end with 0 raises UvError
with its last line, and the runner's own failures (uv that cannot be started, a command past its time) come as it
raises them (children.ChildError). The runner is children.stream, taken when a command is run: a test hands its own
(`stream`)."""
from __future__ import annotations

import os
import platform
import re
from collections import deque
from pathlib import Path
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit

from .plugin import CommandError
from .terminal import Cancelled

FOLDER = "uv"  # under the home given: everything uv keeps
VENV_S = 600.0  # an environment: a Python downloaded and unpacked
INSTALL_S = 3600.0  # an install: gigabytes, for some
# of the platform's own environment, never uv's to read (laid over by `environment`): uv's own, pip's, another
# environment's, Python's, and the tokens of Astral's own index
DROP = ("UV_*", "PIP_*", "VIRTUAL_ENV", "CONDA_*", "PYTHON*", "PYX_*")
TAIL = 5  # the lines kept for an error's words
LINE = 300  # characters of a line in an error's words
# uv's release archives a plugin may pin, by system, machine and C library (the six of its maker's release that run
# here); Windows' .zip holds uv.exe at its root, Linux's .tar.gz one folder named as the archive
ARCHIVES = {
    ("windows", "x86_64", ""): "uv-x86_64-pc-windows-msvc.zip",
    ("windows", "aarch64", ""): "uv-aarch64-pc-windows-msvc.zip",
    ("linux", "x86_64", "gnu"): "uv-x86_64-unknown-linux-gnu.tar.gz",
    ("linux", "aarch64", "gnu"): "uv-aarch64-unknown-linux-gnu.tar.gz",
    ("linux", "x86_64", "musl"): "uv-x86_64-unknown-linux-musl.tar.gz",
    ("linux", "aarch64", "musl"): "uv-aarch64-unknown-linux-musl.tar.gz",
}
MACHINES = {"amd64": "x86_64", "x86_64": "x86_64", "x64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}
LAYOUTS = ((".zip", 0), (".tar.gz", 1))  # an archive's leading folders left out when it is unpacked


class UvError(CommandError):
    """A uv command that did not do what was asked, in its own last words."""


# -- its archives ------------------------------------------------------------------------------------------------------
def archive(system: str, machine: str | None = None, libc: str = "gnu") -> str:
    """The name of uv's release archive for a system: `system` "windows" or "linux"; `machine` as platform.machine()
    says it (AMD64, x86_64, ARM64, aarch64; None: this one's); `libc` on Linux "gnu" (glibc) or "musl". ValueError
    for one its maker builds no archive of."""
    which = str(system or "").strip().lower()
    arch = MACHINES.get(str(platform.machine() if machine is None else machine or "").strip().lower(), "")
    lib = "" if which == "windows" else str(libc or "").strip().lower()
    name = ARCHIVES.get((which, arch, lib))
    if name is None:
        raise ValueError(f"uv's maker builds no archive here for {system!r} on {machine or platform.machine()!r}"
                         + (f" with {libc!r}" if which == "linux" else "")
                         + ": Windows or Linux on x86-64 or ARM64 (Linux with glibc or musl)")
    return name


def strip_of(name: str) -> int:
    """The leading folders left out when uv's archive `name` is unpacked (download.unpack's `strip`): 0 for
    Windows' .zip (uv.exe at its root), 1 for Linux's .tar.gz (its one folder). ValueError for another kind."""
    low = str(name or "").strip().lower()
    for end, strip in LAYOUTS:
        if low.endswith(end):
            return strip
    raise ValueError(f"{name!r} is not one of uv's archives: a .zip (Windows) or a .tar.gz (Linux)")


def program_in(folder, windows: bool | None = None) -> Path:
    """uv itself in the folder its archive was unpacked into (with `strip_of`): uv.exe on Windows, uv elsewhere
    (`windows`: None, this system's way)."""
    windows = os.name == "nt" if windows is None else windows
    return Path(folder) / ("uv.exe" if windows else "uv")


# -- what it is run with -----------------------------------------------------------------------------------------------
def folders(home) -> dict[str, Path]:
    """Where uv keeps things under `home` (a whole path is made of it): cache, python, tools, bin, credentials. Naming
    them makes none."""
    root = Path(os.path.abspath(home)) / FOLDER
    return {"cache": root / "cache", "python": root / "python", "tools": root / "tools", "bin": root / "bin",
            "credentials": root / "credentials"}


def cache(home) -> Path:
    """uv's cache under `home`: nothing an environment needs once it is made, so an install may remove it."""
    return folders(home)["cache"]


def _https(address, what: str) -> str:
    """`address` when it is an https address with a host and no name or password in it ("" stays ""), else
    ValueError. Its words never repeat the address: a refused one may hold what it should not."""
    text = str(address or "").strip()
    if not text:
        return ""
    if re.search(r"//[^/?#]*@", text):
        raise ValueError(f"{what} is named without a name or a password in its address: every program on this "
                         "machine can read a command line")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError(f"{what} is one address, with no space or control character in it")
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        parts, host = None, None
    if parts is None or parts.scheme.lower() != "https" or not host or parts.username is not None:
        raise ValueError(f"{what} is asked over https alone: give its whole https address")
    return text


def environment(home, *, python_mirror: str = "", cache=None) -> dict[str, str]:
    """The variables uv is run with (each said beside it): everything it keeps under `home`/uv, nothing of the user's
    own uv read, lines fit for a log. Laid over the platform's environment without `DROP` (`child_env` makes the whole
    of it).
    `python_mirror`: the one address uv downloads its Python from (UV_PYTHON_INSTALL_MIRROR, https alone: the
    plugin's constant, in place of GitHub's releases of the Python builds); without it uv asks Astral's mirror first
    and GitHub after a failure. `cache`: the folder of what uv downloads and builds (UV_CACHE_DIR, made whole), in
    place of `home`/uv/cache: one outside the folder an install is built in keeps it for the next try (the module's
    words)."""
    at = {name: str(path) for name, path in folders(home).items()}
    if cache is not None:
        named = os.fspath(cache)
        if not str(named).strip():
            raise ValueError("uv's cache is named by its folder, and none was given")
        at["cache"] = str(Path(os.path.abspath(named)))
    env = {
        "UV_CACHE_DIR": at["cache"],  # what it downloads and builds (see `cache`): removable after an install
        "UV_PYTHON_INSTALL_DIR": at["python"],  # the Pythons it downloads
        "UV_PYTHON_BIN_DIR": at["bin"],  # their links, were one made ...
        "UV_PYTHON_INSTALL_BIN": "0",  # ... and none is
        "UV_PYTHON_INSTALL_REGISTRY": "0",  # no Python of its own is written into Windows' registry (with the next)
        "UV_PYTHON_NO_REGISTRY": "1",
        "UV_PYTHON_PREFERENCE": "only-managed",  # its own Pythons only, never the system's
        "UV_TOOL_DIR": at["tools"],  # its tools ...
        "UV_TOOL_BIN_DIR": at["bin"],  # ... and their programs
        "UV_CREDENTIALS_DIR": at["credentials"],  # no index login the user kept with `uv auth` is read (none is there)
        "UV_INSTALL_DIR": at["bin"],  # the installer's and `self update`'s folder (the module's words) ...
        "UV_NO_MODIFY_PATH": "1",  # ... the PATH untouched
        "UV_NO_CONFIG": "1",  # no uv.toml or pyproject.toml is read: not the folder's, not the user's
        "UV_NO_HF_TOKEN": "1",  # no Hugging Face token is sent by uv, even with HF_TOKEN set
        "UV_MALWARE_CHECK": "0",  # its check against the OSV database (after `uv sync`, which nothing here runs) off
        "UV_LINK_MODE": "copy",  # an environment holds its own files, so the cache can go
        "UV_NO_PROGRESS": "1",  # lines for a log: no progress bars ...
        "NO_COLOR": "1",  # ... and no colours
    }
    mirror = _https(python_mirror, "the address uv downloads its Python from")
    if mirror:
        env["UV_PYTHON_INSTALL_MIRROR"] = mirror
    return env


def child_env(home, *, base: Mapping[str, str] | None = None, drop: str | Iterable[str] = (), system: str | None = None,
              python_mirror: str = "", cache=None) -> dict[str, str]:
    """The whole environment `venv` and `pip_install` are handed: `base` (this process's own unless given: a
    plugin's Outside env) without DROP, without every LIMINAL_* name and without what `drop` names (an AI plugin hands
    its dropped(): every variable an installed plugin declares), each a name or a prefix ending "*", then
    `environment(home, python_mirror=..., cache=...)` laid over it. On Windows (`system`: this one unless given)
    names are told apart without regard to case, as Windows does (children.environment)."""
    from . import children  # (taken when it is asked, as the runner is)

    named = (drop,) if isinstance(drop, str) else tuple(drop or ())
    launch = children.Launch((), env=environment(home, python_mirror=python_mirror, cache=cache),
                             drop=(*DROP, "LIMINAL_*", *(str(n) for n in named if str(n).strip())))
    return children.environment(launch, base=base, system=system)


def python_of(venv, windows: bool | None = None) -> Path:
    """An environment's own Python: Scripts/python.exe on Windows, bin/python elsewhere (`windows`: None, this
    system's way)."""
    windows = os.name == "nt" if windows is None else windows
    return Path(venv) / ("Scripts" if windows else "bin") / ("python.exe" if windows else "python")


# -- its commands ------------------------------------------------------------------------------------------------------
def _program(uv) -> str:
    text = os.fspath(uv) if uv else ""
    if not text:
        raise ValueError("uv's own program is named by its path, and none was given")
    return os.path.abspath(text) if os.path.dirname(text) else text  # a bare name is looked for on PATH


def _stream() -> Callable:
    from .children import stream  # the library's runner of an installer's command, its lines as they come

    return stream


def _os_words(e: OSError) -> str:
    said = e.strerror or str(e) or type(e).__name__
    return f"{said}: {e.filename}" if e.filename else said


def _run(uv, args: list[str], name: str, first: str, *, env: Mapping[str, str] | None, log, cancel, timeout: float,
         stream, cwd: Path, make: bool = False) -> None:
    """One uv command run to its end in a folder of the plugin's own (`cwd`; `make`: made when it is not there), what
    it is about (`first`) and then its lines to `log`; UvError when it does not end with 0, Cancelled when its user
    cancelled (before it starts: nothing is made, said or run; or from the runner)."""
    if env is None:
        raise ValueError("uv is run with an environment given whole (the platform's without DROP, environment(home) "
                         "over it): without one it would inherit every pair the platform keeps")
    program = _program(uv)
    if cancel is not None and cancel():
        raise Cancelled(f"cancelled before `{name}` was started")
    if make:
        try:
            cwd.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise UvError(f"`{name}` was not started: {cwd} could not be made ({_os_words(e)})") from None
    if log is not None:
        log(first)
    last: deque[str] = deque(maxlen=TAIL)

    def line(text) -> None:
        said = str(text).rstrip("\r\n")
        last.append(said)
        if log is not None:
            log(said)

    run = stream if stream is not None else _stream()
    code = run([program, *args], line, env=dict(env), cwd=str(cwd) if cwd.is_dir() else None, timeout=timeout,
               cancel=cancel)
    if code != 0:
        said = next((s.strip() for s in reversed(last) if s.strip()), "")
        raise UvError(f"`{name}` ended with {code}" + (f": {said[:LINE]}" if said else ""))


def _empty(folder: Path) -> bool:
    """Whether nothing is at `folder`, or an empty folder (uv makes an environment only there)."""
    try:
        return not folder.exists() or (folder.is_dir() and next(folder.iterdir(), None) is None)
    except OSError as e:
        raise UvError(f"{folder} could not be looked at: {_os_words(e)}") from None


def venv(uv, folder, python: str, *, env: Mapping[str, str], log, cancel, seed: bool = False, timeout: float = VENV_S,
         stream: Callable | None = None) -> Path:
    """An environment made in `folder` on a Python of uv's own, downloaded when it is not there yet:
    `uv venv --python PYTHON --managed-python --no-project --no-config [--seed] FOLDER`. `python`: the version asked
    ("3.12"); `seed`: pip put into it too (for a program that installs its own parts). No project and no
    configuration of the folder it runs in is looked at. The folder must be missing or empty (uv refuses another
    without a terminal to ask on; UvError says so before anything runs: a half-made one is the caller's to remove).
    The environment's folder, as a whole path."""
    target, wanted = Path(os.path.abspath(folder)), str(python or "").strip()
    if not wanted or wanted.startswith("-"):
        raise ValueError(f"an environment is made on a Python named by its version (3.12), not {python!r}")
    if not _empty(target):
        raise UvError(f"{target} is not empty: uv makes an environment only where there is nothing yet (one left by "
                      "an install that did not end is removed first)")
    args = ["venv", "--python", wanted, "--managed-python", "--no-project", "--no-config"]
    if seed:
        args.append("--seed")
    _run(uv, [*args, str(target)], "uv venv", f"uv: an environment in {target}, on a Python {wanted} of uv's own",
         env=env, log=log, cancel=cancel, timeout=timeout, stream=stream, cwd=target.parent, make=True)
    return target


def _requirements(what: str | Iterable[str] | None) -> list[str]:
    wanted = [str(w).strip() for w in ([what] if isinstance(what, str) else what or [])]
    if not all(wanted):
        raise ValueError("an install names what is installed (vllm==0.33.0), and nothing was named")
    switch = next((w for w in wanted if w.startswith("-")), None)
    if switch is not None:
        raise ValueError(f"{switch!r} is a switch, not something to install: switches are given as `extra`, a "
                         "requirements file as `requirements`")
    return wanted


def _pinned(requirements) -> Path:
    path = Path(os.path.abspath(os.fspath(requirements)))
    if not path.is_file():
        raise ValueError(f"the requirements file {path} is not there: an install against pinned sums reads them from "
                         "a file of the plugin's")
    return path


def pip_install(uv, venv, what: str | Iterable[str] = (), *, env: Mapping[str, str], log, cancel, index: str = "",
                extra: Iterable[str] = (), requirements=None, timeout: float = INSTALL_S,
                stream: Callable | None = None) -> None:
    """Packages installed into the environment `venv` (its folder), named to uv by its own Python:
    `uv pip install --python VENV'S-PYTHON --no-config [--index INDEX] [--require-hashes --requirements FILE]
    [EXTRA ...] [WHAT ...]`.

    `requirements`: a requirements file of the plugin's holding the whole tree, each package pinned with == and its
    --hash=sha256 sums: installed in uv's hash-checking mode, every file checked against a sum in it and every package
    it does not list refused. `what` is then empty (a command line carries no sum). Without one, `what` names one
    requirement or several (aider-chat==0.86.2), taken as their index gives them: nothing pinned here checks them.
    `index`: one more index beside the default, by its https address (the plugin's constant; none with a name or a
    password in it: a command line is no place for them). `extra`: switches as uv spells them (--torch-backend=cu130,
    a preview switch of 0.13.8's, read again when a plugin's pin of uv moves)."""
    target, wanted, switches = Path(os.path.abspath(venv)), _requirements(what), [str(s) for s in extra]
    address = _https(index, "an index")
    pinned = _pinned(requirements) if requirements is not None else None
    if pinned is not None and wanted:
        raise ValueError(f"with a requirements file of pinned sums everything installed is in it ({pinned.name}): "
                         f"{', '.join(wanted)} on the command line would carry no sum")
    if pinned is None and not wanted:
        raise ValueError("an install names what is installed (vllm==0.33.0), and nothing was named")
    args = ["pip", "install", "--python", str(python_of(target)), "--no-config"]
    if address:
        args += ["--index", address]
    if pinned is not None:
        args += ["--require-hashes", "--requirements", str(pinned)]
        first = f"uv: the packages pinned in {pinned.name} into {target}, each checked against its sum pinned there"
    else:
        first = f"uv: {', '.join(wanted)} into {target}, as its index gives it: no sum pinned here checks it"
    _run(uv, [*args, *switches, *wanted], "uv pip install", first, env=env, log=log, cancel=cancel, timeout=timeout,
         stream=stream, cwd=target.parent)
