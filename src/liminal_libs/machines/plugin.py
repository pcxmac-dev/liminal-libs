"""The machine kind of platform plugin (the user, 2026-11-07: "the platform is the interface for the
software/hardware which facilitates the liminal framework"; "the scope of the plugin is setting up
WSL/Ubuntu and supporting docker for the platform"): what a plugin that stands for a piece of software or
hardware offers the platform. Its hooks: `present` (is it there), `status` (what it is and how it does: a
`summary` line for the platform's page), `setup` (set it up, as far as the plugin can; its `STEPS`, each
reported), `run` (a command on it), `instances` (the Docker instances it runs: docker.Instance), `scan` and
`settings` as every plugin. `CommandError` is what the machines' commands raise (windows.PowerShell,
linux.Shell), `denied` when it wanted an administrator's or root's rights.

A status may say whether the plugin is valid: set up for Liminal, on something of Liminal's own (the user,
2026-11-07: "if a plugin is not in a valid state it has to be disabled"; "there are no WSL-liminally scoped
installs, so all three WSL plugins are invalid"): `valid` (bool) and `why` (the words, when not). The platform
disables a plugin that is not valid until it is; without them, present and no `problem` is valid. A plugin that
is not for this machine at all says why in `not_for_here()` (the Linux plugins, through linux.why_not_native, on
Windows, macOS or in WSL; the user, 2026-11-08: "the scope of linux administration is only on native linux O/S",
"Yes, firewall too"): its status says `applies` False beside them (`not_here_status`), its setup changes nothing,
and the platform offers no setup for it, since none can make it valid here. A WSL distribution of Liminal's own is named with LIMINAL_PREFIX
(Liminal-Ubuntu): the user's own is never taken."""
from __future__ import annotations

from ..sources.plugin import PlatformPlugin

LIMINAL_PREFIX = "Liminal-"  # a WSL distribution of Liminal's own: Liminal-Ubuntu, Liminal-Fedora, Liminal-Gentoo


def liminal_scoped(name: str) -> bool:
    """Whether a WSL distribution's name is one of Liminal's own (Liminal-...)."""
    return bool(name) and name.lower().startswith(LIMINAL_PREFIX.lower())


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

    def not_for_here(self) -> str:
        """Why this machine is not one the plugin is for at all, in words ("" when it is): a Linux plugin on Windows,
        macOS or in a WSL distribution (linux.why_not_native). Honored before anything else by this base's status and
        by the Admin and Firewall bases' status and setup: nothing asked, nothing changed, `applies` False."""
        return ""

    def not_here_status(self, note: str, **empty) -> dict:
        """The status of a plugin not for this machine (`note`: why): nothing asked, not valid, `applies` False;
        `empty`: the keys a subclass's status always has, empty."""
        return {"present": False, **empty, "summary": "not for this machine", "valid": False, "why": note, "applies": False}

    def status(self) -> dict:
        """What it is and how it does, for the platform's page and a check ("summary": one line of it)."""
        note = self.not_for_here()
        if note:
            return self.not_here_status(note)
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

    def scope(self) -> tuple[bool, str]:
        """Whether what it works on is Liminal's, and where that is in words: this machine by default; a Linux
        plugin's target (its `shell`, a linux.Shell): this Linux machine, or a WSL distribution of Liminal's own."""
        from .linux import Shell

        try:
            sh = getattr(self, "shell", None)
        except CommandError:
            return False, "its target"
        if isinstance(sh, Shell):
            return sh.scoped, sh.where
        return True, "this machine"

    def scope_note(self) -> str:
        """Why what it works on is not Liminal's, in words ("" when it is): a Linux plugin's target."""
        from .linux import Shell

        try:
            sh = getattr(self, "shell", None)
        except CommandError as e:
            return f"its target: {e}"
        return sh.scope_note if isinstance(sh, Shell) else ""
