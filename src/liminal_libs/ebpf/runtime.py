"""The eBPF runtime: what the eBPF plugin reads and does on this machine, one base with a Linux and a Windows
subclass (the user, 2026-11-14: "we need an ebpf api plugin, that shows the difference between windows and linux
capabilities as well as basic functionality"). The comparison (`capabilities`) is the same on both and comes from
`capabilities.py`; everything else differs by system.

A runtime reads freely, and every change is confirmed and elevated by the plugin before it calls load, attach,
detach or unload (the design: "Loading eBPF programs is a confirmed action"): these methods only build and run the
commands; the plugins gate the confirmation. The library never asks for a password: Linux goes through
`machines.linux.Shell` with `sudo -n`, Windows through the read-only queries its subclass lists. A command that
fails raises `CommandError` in its own words (`denied` when it wanted root or an administrator)."""
from __future__ import annotations

from ..machines.plugin import CommandError
from . import capabilities


class Runtime:
    """The base: the shared comparison, and the read and change hooks a subclass fills in. `system` is "linux" or
    "windows"; the base is neither and answers only `applies` and `capabilities`."""

    system = ""

    def applies(self) -> tuple[bool, str]:
        """Whether this runtime is for this machine, and why not in words ("" when it is): the Linux runtime is for
        a native Linux machine only (never Windows, never WSL), the Windows runtime for Windows."""
        return True, ""

    def capabilities(self, sources=None) -> list[dict]:
        """The Linux-against-Windows comparison, the same wherever it is read: rows of area, item, linux, windows.
        `sources`, the plugin's links keyed by (area, item), adds each row's "source"; the library holds none."""
        return capabilities.rows(sources)

    # -- read (a subclass answers these) ---------------------------------------------------------------------

    def status(self) -> dict:
        """What the runtime is and how it stands on this machine, for the plugin's page: at least `present`,
        `version`, `applies`, a `summary` line and, when it cannot run, `why`."""
        raise NotImplementedError

    def programs(self) -> list[dict]:
        """The loaded programs, one row each."""
        raise NotImplementedError

    def maps(self) -> list[dict]:
        """The maps, one row each."""
        raise NotImplementedError

    def links(self) -> list[dict]:
        """The links (attachments), one row each."""
        raise NotImplementedError

    def program(self, prog_id) -> dict:
        """One program by id, with its detail ({} when there is none by that id)."""
        raise NotImplementedError

    def dump_map(self, map_id, limit: int = 1000) -> list[dict]:
        """A map's first `limit` entries by id: a map can hold millions, and the page shows the first ones."""
        raise NotImplementedError

    # -- change (confirmed and elevated by the plugin, then run here) ----------------------------------------

    def load(self, path, **options) -> str:
        """Load a pre-built program from `path` and pin it. A confirmed, elevated action."""
        raise CommandError(self.no_change())

    def attach(self, **options) -> str:
        """Attach a loaded or pinned program to its target. A confirmed, elevated action."""
        raise CommandError(self.no_change())

    def detach(self, **options) -> str:
        """Detach an attachment. A confirmed, elevated action."""
        raise CommandError(self.no_change())

    def unload(self, **options) -> str:
        """Unload a program (drop its pin, so its last reference goes). A confirmed, elevated action."""
        raise CommandError(self.no_change())

    def no_change(self) -> str:
        """Why this runtime loads and attaches nothing, in words."""
        return f"this eBPF runtime ({self.system or 'the base'}) loads and attaches no programs"
