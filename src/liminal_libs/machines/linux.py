"""Linux for the machine plugins (the firewall and admin plugins of the platform): commands on a Linux
machine, this one (with sudo when the platform is not root: never a password asked, `sudo -n`) or a WSL
distribution on this Windows PC (as root through `wsl -u root`, no password either). A plugin names its target
by its own variable: `local`, `wsl` (the default distribution) or `wsl:<distribution>`; on Linux `local` is
the default, on Windows `wsl`. A runner stands in for the commands in tests."""
from __future__ import annotations

import os
import shutil
import subprocess

from .plugin import CommandError

TIMEOUT_S = 120.0
DENIED = ("a password is required", "a terminal is required", "permission denied", "must be root", "are you root",
          "operation not permitted", "need to be root", "you need root")


class Shell:
    """Commands on the target. `runner(args, timeout) -> (code, stdout bytes or text, stderr bytes or text)`."""

    def __init__(self, target: str | None = None, runner=None):
        raw = (target or "").strip()
        self.target = raw if raw else ("wsl" if os.name == "nt" else "local")
        if not (self.target == "local" or self.target == "wsl" or self.target.startswith("wsl:")):
            raise CommandError(f"a target is local, wsl or wsl:<distribution>, not {self.target!r}")
        self._runner = runner

    @property
    def distribution(self) -> str:
        return self.target[4:] if self.target.startswith("wsl:") else ""

    @property
    def where(self) -> str:
        if self.target == "local":
            return "this machine"
        return f"WSL's {self.distribution}" if self.distribution else "WSL's default distribution"

    @property
    def here(self) -> bool:
        if self._runner is not None:
            return True
        if self.target == "local":
            return os.name != "nt"
        return os.name == "nt" and shutil.which("wsl") is not None

    def root(self) -> bool:
        """Whether a command here runs as root without asking: WSL's root; this machine's when the platform is root."""
        if self.target != "local":
            return True
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def prefix(self, root: bool = True) -> list[str]:
        if self.target == "local":
            return ["sudo", "-n"] if root and not self.root() else []
        return ["wsl", *(("-d", self.distribution) if self.distribution else ()), *(("-u", "root") if root else ()), "--"]

    def run(self, *command: str, root: bool = True, timeout: float = TIMEOUT_S, check: bool = True, stdin: str | None = None) -> str:
        """The command's output (as root unless said); CommandError in its own words, denied when it needed root."""
        args = [*self.prefix(root), *command]
        if self._runner is not None:
            code, out, err = self._runner(args, timeout)
        else:
            if not self.here:
                raise CommandError(f"no {self.where} to reach from here")
            try:
                done = subprocess.run(args, capture_output=True, timeout=timeout,
                                      input=stdin.encode() if stdin is not None else None, **_no_window())
            except subprocess.TimeoutExpired:
                raise CommandError(f"{command[0]} took more than {timeout:g} s on {self.where}") from None
            except OSError as e:
                raise CommandError(f"{command[0]} could not run on {self.where}: {e}") from None
            code, out, err = done.returncode, done.stdout, done.stderr
        out, err = _text(out), _text(err)
        if code != 0 and check:
            words = (err.strip() or out.strip() or f"{command[0]} failed ({code}) on {self.where}")
            last = words.splitlines()[-1].strip()
            denied = any(d in words.lower() for d in DENIED)
            if denied and self.target == "local" and not self.root():
                raise CommandError(f"{command[0]} needs root on {self.where}: run the platform as root, or let sudo run it "
                                   f"without a password ({last})", denied=True)
            raise CommandError(last, denied=denied)
        return out

    def sh(self, script: str, root: bool = True, timeout: float = TIMEOUT_S, check: bool = True) -> str:
        """A shell script on the target."""
        return self.run("sh", "-c", script, root=root, timeout=timeout, check=check)


def _text(raw) -> str:
    """A command's output: UTF-8, or UTF-16 for wsl's own messages (NULs between the letters)."""
    if isinstance(raw, str):
        return raw
    raw = raw or b""
    return raw.decode("utf-16-le", "ignore") if b"\x00" in raw else raw.decode("utf-8", "replace")


def _no_window() -> dict:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}
