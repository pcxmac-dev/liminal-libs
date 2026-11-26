"""The Linux kernel, WSL and the container this Linux is, from files' texts and the environment alone.

One reading for both of the library's readers of this machine (the linuxperm plan's 3.11): linuxsys's facts hand it
the files its probe printed, and the needs reader opens the same files itself. Neither reads these three facts another
way. `read` starts nothing and opens nothing: it is a function of `files` ({path: its text, "" for a folder or a file
that is there and cannot be read, None or no key when it is not there}), of the environment, and of the machine's name
where the kernel's own file for it is missing (/proc/sys/kernel/arch is Linux 6.1's and later).

What it tells:
- the kernel: its release and the machine (x86_64, aarch64);
- WSL: the distribution's name ("WSL" when the environment does not say) and its generation (1, 2, or 0 when the
  release does not tell: taken as 2 by its readers, since every distribution installed today is);
- the container: docker, podman, lxc, nspawn, or other; "" on a machine of its own and in a WSL distribution. systemd
  writes the word `wsl` into /run/systemd/container inside WSL, and that is no container.
A container on a WSL kernel (Docker inside a WSL distribution) is both: its kernel is WSL's, and it is a container.
"""
from __future__ import annotations

from dataclasses import dataclass

OSRELEASE = "/proc/sys/kernel/osrelease"
ARCH = "/proc/sys/kernel/arch"
SYSTEMD_CONTAINER = "/run/systemd/container"
CONTAINERENV = "/run/.containerenv"
DOCKERENV = "/.dockerenv"
WSL_MARKS = ("/proc/sys/fs/binfmt_misc/WSLInterop", "/proc/sys/fs/binfmt_misc/WSLInterop-late", "/run/WSL")
# every file `read` looks at, for the probe to print and the needs reader to open; then the variables
FILES = (OSRELEASE, ARCH, SYSTEMD_CONTAINER, CONTAINERENV, DOCKERENV, *WSL_MARKS)
ENV = ("WSL_DISTRO_NAME", "WSL_INTEROP", "container")
# systemd's and the container managers' own words for what started this system (systemd-detect-virt's names)
_CONTAINERS = {"docker": "docker", "podman": "podman", "lxc": "lxc", "lxc-libvirt": "lxc", "systemd-nspawn": "nspawn",
               "nspawn": "nspawn", "oci": "other", "rkt": "other"}


@dataclass(frozen=True)
class KernelFacts:
    """What `read` found. `notes`: what could not be told, in words."""

    release: str = ""
    machine: str = ""
    wsl: str = ""
    wsl_generation: int = 0
    container: str = ""
    notes: tuple[str, ...] = ()

    def describe(self) -> dict:
        return {"release": self.release, "machine": self.machine, "wsl": self.wsl,
                "wsl_generation": self.wsl_generation, "container": self.container, "notes": list(self.notes)}


def _first_line(text) -> str:
    lines = (text or "").strip().splitlines()
    return lines[0].strip() if lines else ""


def wsl_generation(release: str) -> int:
    """WSL 1 or WSL 2, by the kernel's release (WSL 2's is Microsoft's own Linux kernel, `...-microsoft-standard-WSL2`;
    WSL 1 has no Linux kernel and says `...-Microsoft`); 0 when the release does not tell."""
    low = release.lower()
    if "wsl2" in low or "microsoft-standard" in low:
        return 2
    return 1 if release.endswith("-Microsoft") else 0


def read(files, env=None, machine: str = "") -> KernelFacts:
    """The kernel, WSL and container facts of the Linux whose `files` and `env` these are (the module's words say what
    each is). `machine`: the machine's name as `uname -m` or platform.machine() gave it, used where the kernel's own
    file for it is not there."""
    files = files or {}
    env = env or {}
    there = lambda path: files.get(path) is not None  # noqa: E731
    notes: list[str] = []
    release = _first_line(files.get(OSRELEASE))
    if not release:
        notes.append(f"the kernel's release could not be read ({OSRELEASE})")
    machine = _first_line(files.get(ARCH)) or (machine or "").strip()
    low = release.lower()
    in_wsl = ("microsoft" in low or "wsl" in low or any(there(p) for p in WSL_MARKS)
              or bool(env.get("WSL_DISTRO_NAME")) or bool(env.get("WSL_INTEROP")))
    name = (str(env.get("WSL_DISTRO_NAME") or "").strip() or "WSL") if in_wsl else ""
    generation = wsl_generation(release) if in_wsl else 0
    word = _first_line(files.get(SYSTEMD_CONTAINER)).lower()
    if word and word != "wsl":
        container = _CONTAINERS.get(word, "other")
    elif there(CONTAINERENV):
        container = "podman"
    elif there(DOCKERENV):
        container = "docker"
    else:
        said = str(env.get("container") or "").strip().lower()
        container = _CONTAINERS.get(said, "other") if said and said != "wsl" else ""
    return KernelFacts(release, machine, name, generation, container, tuple(notes))
