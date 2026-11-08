"""The machine plugins (plugin API 2.1; the user, 2026-11-07: "the platform is the interface for the
software/hardware which facilitates the liminal framework"): a piece of software or hardware the framework
runs on, set up and driven by its plugin (plugin-platform-wsl-ubuntu: WSL and Ubuntu, and Docker in it),
found by the registry like every plugin (`machines()`), each offering the Docker instances it runs
(`liminal_libs.docker.instances`)."""
from __future__ import annotations

from .plugin import MachinePlugin  # noqa: F401


def machines() -> dict:
    """The machine plugins by name, in their order (the registry's)."""
    from ..sources.registry import machines as found

    return found()
