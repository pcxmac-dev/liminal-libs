"""The machine kind of platform plugin (the user, 2026-11-07: "the platform is the interface for the
software/hardware which facilitates the liminal framework"; "the scope of the plugin is setting up
WSL/Ubuntu and supporting docker for the platform"): what a plugin that stands for a piece of software or
hardware offers the platform. Its hooks: `present` (is it there), `status` (what it is and how it does: a
`summary` line for the platform's page), `setup` (set it up, as far as the plugin can; its `STEPS`, each
reported), `run` (a command on it), `instances` (the Docker instances it runs: docker.Instance), `scan` and
`settings` as every plugin. `CommandError` is what the machines' commands raise (windows.PowerShell,
linux.Shell), `denied` when it wanted an administrator's or root's rights."""
from __future__ import annotations

from ..sources.plugin import PlatformPlugin


class CommandError(Exception):
    """A machine's command failed, in its own words; `denied`: it needed an administrator's (root's) rights."""

    def __init__(self, message: str, denied: bool = False):
        super().__init__(message)
        self.denied = denied


class MachinePlugin(PlatformPlugin):
    """A machine plugin. A subclass sets `name`, `title`, `about`, its `STEPS` and overrides the hooks it answers."""

    CONTRACT = True
    KIND = "machine"
    HOOKS = ("present", "status", "setup", "run", "instances", "scan", "settings")
    STEPS: tuple = ()  # the setup's steps, in order: what the platform's page offers one at a time
    ICON = "chip"  # its icon in the platform's tray (icons.js) when it is active

    def present(self) -> bool:
        """Whether the software or hardware is there."""
        return False

    def status(self) -> dict:
        """What it is and how it does, for the platform's page and a check ("summary": one line of it)."""
        present = self.present()
        return {"present": present, "summary": "present" if present else "not present"}

    def setup(self, log=print, steps=None) -> list[dict]:
        """Set it up, as far as the plugin can (`steps`: only these, by name); each step done, skipped or
        failed reported as {"step", "ok", "detail"}. Nothing to set up by default."""
        return []

    def run(self, *command: str, **options) -> str:
        """A command on it, its output."""
        raise CommandError(f"{self.name} runs no commands")

    def instances(self) -> tuple:
        """The Docker instances this machine runs (docker.Instance), none by default."""
        return ()
