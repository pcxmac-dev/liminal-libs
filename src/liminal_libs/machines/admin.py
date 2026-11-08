"""The machine's administration for the framework, as a machine plugin's base (the user, 2026-11-07: "a windows
and linux admin plugin for platform"; the platform is "the interface for the software/hardware which
facilitates the liminal framework"): whether the platform has an administrator's (root's) rights and how
they are had; the system services the framework relies on (WSL, Docker, the firewall, DNS), their state,
started when stopped; the framework's own startups (a scheduled task at logon or a systemd user unit per
app: charts, integrator, login, platform), read, run, ended, made or removed when asked; the framework's
processes running. The setup reports the rights, starts the services it may that are stopped, and reports
the startups: it makes no startup on its own (the plugin lifecycle: nothing runs while the user is not using
it), and an SSH server is never started by it."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from .plugin import CommandError, MachinePlugin

STEPS = ("privileges", "services", "startup")
APPS = {  # the framework's apps: their module, and how each one is started for good
    "charts": ("liminal_charts", ("gui", "--no-browser", "--port", "8765")),
    "integrator": ("liminal_integrator", ("service", "run", "--daemon")),
    "login": ("liminal_login", ("serve", "--no-browser")),
    "platform": ("liminal_platform", ("serve", "--no-browser")),
}
SERVICE_ACTIONS = ("start", "stop", "restart")
STARTUP_ACTIONS = ("run", "end", "enable", "disable")
STOPPED = ("stopped", "inactive", "failed", "dead", "exited")


class AdminError(CommandError):
    pass


@dataclass(frozen=True)
class SystemService:
    """A system service as the framework sees it."""

    name: str
    title: str
    state: str  # running | stopped | absent | another word the system uses
    startup: str = ""  # automatic, manual, disabled; enabled, static ...
    used_for: str = ""
    may_start: bool = True  # the setup starts it when stopped (an SSH server: never on its own)

    @property
    def present(self) -> bool:
        return self.state != "absent"

    @property
    def running(self) -> bool:
        return self.state in ("running", "active")

    def describe(self) -> dict:
        return {"name": self.name, "title": self.title, "state": self.state, "startup": self.startup,
                "usedFor": self.used_for, "mayStart": self.may_start}


@dataclass(frozen=True)
class Startup:
    """One app's startup registration: a scheduled task at logon (Windows), a systemd user unit (Linux)."""

    app: str
    name: str
    state: str  # ready | running | disabled | absent | another word the system uses
    command: str = ""
    detail: str = ""

    @property
    def present(self) -> bool:
        return self.state != "absent"

    def describe(self) -> dict:
        return {"app": self.app, "name": self.name, "state": self.state, "command": self.command, "detail": self.detail}


def app_of(command: str) -> str:
    """Which of the framework's apps a command line runs ("" for none)."""
    for app, (module, _) in APPS.items():
        if f"-m {module}" in command or f"{module}\\__main__" in command or f"{module}/__main__" in command:
            return app
    return ""


def start_command(app: str, python: str | None = None) -> list[str]:
    """The command that starts `app` for good: this Python's (pythonw on Windows: no window), its module."""
    if app not in APPS:
        raise AdminError(f"no app named {app!r}: {', '.join(APPS)}")
    module, args = APPS[app]
    exe = Path(python or sys.executable)
    quiet = exe.with_name("pythonw.exe")
    return [str(quiet if quiet.exists() else exe), "-m", module, *args]


class Admin(MachinePlugin):
    """The base of the admin plugins. A subclass drives one system through the backend methods below; the hooks
    (status, setup) and the checks of what is asked are this base's."""

    HOOKS = (*MachinePlugin.HOOKS, "service", "startup", "register", "unregister", "processes")  # what the platform may ask by name
    STEPS = STEPS
    SERVICES: tuple = ()  # (name, title, what of the framework uses it, may the setup start it)

    # -- the backend: a subclass's -----------------------------------------------------------------
    def elevated(self) -> bool:
        """Whether the platform has an administrator's (root's) rights now."""
        raise NotImplementedError

    def elevation(self) -> str:
        """How the rights are had, in words (elevated; a UAC prompt; sudo without a password ...)."""
        raise NotImplementedError

    def services(self) -> list[SystemService]:
        """The SERVICES as they are (absent when not installed)."""
        raise NotImplementedError

    def _service_action(self, name: str, action: str) -> None:
        raise NotImplementedError

    def startups(self) -> list[Startup]:
        """One per app (absent when it has none)."""
        raise NotImplementedError

    def _startup_action(self, app: str, action: str) -> None:
        raise NotImplementedError

    def _register(self, app: str, command: list[str]) -> None:
        raise NotImplementedError

    def _unregister(self, app: str) -> bool:
        raise NotImplementedError

    def processes(self) -> list[dict]:
        """The framework's processes running: {"pid", "app", "command", "memoryMb"}."""
        raise NotImplementedError

    # -- what the platform asks, checked here -------------------------------------------------------
    def service(self, name: str, action: str) -> None:
        """start, stop or restart one of the framework's services (SERVICES), never another."""
        if action not in SERVICE_ACTIONS:
            raise AdminError(f"a service is {', '.join(SERVICE_ACTIONS)}ed, not {action!r}")
        known = {s[0] for s in self.SERVICES}
        if name not in known:
            raise AdminError(f"{name} is not one of the framework's services here: {', '.join(sorted(known))}")
        self._service_action(name, action)

    def startup(self, app: str, action: str) -> None:
        """run, end, enable or disable an app's startup."""
        if action not in STARTUP_ACTIONS:
            raise AdminError(f"a startup is {', '.join(STARTUP_ACTIONS)}, not {action!r}")
        if app not in APPS:
            raise AdminError(f"no app named {app!r}: {', '.join(APPS)}")
        self._startup_action(app, action)

    def register(self, app: str, python: str | None = None) -> Startup:
        """The app started at the user's logon from now on (made, not run)."""
        self._register(app, start_command(app, python))
        return next((s for s in self.startups() if s.app == app), Startup(app, "", "unknown"))

    def unregister(self, app: str) -> bool:
        if app not in APPS:
            raise AdminError(f"no app named {app!r}: {', '.join(APPS)}")
        return self._unregister(app)

    # -- the hooks ----------------------------------------------------------------------------------
    def status(self) -> dict:
        if not self.present():
            return {"present": False, "elevated": False, "elevation": "", "services": [], "startups": [], "processes": [],
                    "summary": "not present"}
        try:
            elevated, how = self.elevated(), self.elevation()
            services, startups, processes = self.services(), self.startups(), self.processes()
        except CommandError as e:
            return {"present": True, "elevated": False, "elevation": "", "services": [], "startups": [], "processes": [],
                    "problem": str(e), "summary": f"cannot be read: {e}"}
        running = [s.name for s in services if s.running]
        stopped = [s.name for s in services if s.present and not s.running]
        made = [s.app for s in startups if s.present]
        summary = (f"{'elevated' if elevated else 'not elevated'}; services: {len(running)} running"
                   + (f", stopped: {', '.join(stopped)}" if stopped else "")
                   + f"; startups: {', '.join(made) or 'none'}; {len(processes)} Liminal process(es)")
        return {"present": True, "elevated": elevated, "elevation": how, "services": [s.describe() for s in services],
                "startups": [s.describe() for s in startups], "processes": processes, "summary": summary}

    def setup(self, log=print, steps=None) -> list[dict]:
        """`privileges` (reported), `services` (the framework's stopped services it may start, started),
        `startup` (reported: it makes none; `register` does when asked); each reported."""
        wanted = tuple(steps) if steps else self.STEPS
        done: list[dict] = []

        def step(what: str, ok: bool | None, detail: str) -> None:
            done.append({"step": what, "ok": ok, "detail": detail})
            log(f"{self.name}: {what}: {'ok' if ok else 'skipped' if ok is None else 'FAILED'}: {detail}")

        if not self.present():
            step(wanted[0] if wanted else "setup", False, "not the system this plugin drives")
            return done
        current = wanted[0] if wanted else "setup"
        try:
            if "privileges" in wanted:
                current = "privileges"
                step("privileges", True if self.elevated() else None, self.elevation())
            if "services" in wanted:
                current = "services"
                services = self.services()
                waiting = [s for s in services if s.present and not s.running and s.may_start and s.startup.lower() != "disabled"]
                if not waiting:
                    step("services", None, "running: " + (", ".join(s.name for s in services if s.running) or "none of them installed"))
                else:
                    started, refused = [], []
                    for s in waiting:
                        try:
                            self._service_action(s.name, "start")
                            started.append(s.name)
                        except CommandError as e:
                            refused.append(f"{s.name} ({e})")
                    if refused:
                        step("services", False, (f"started: {', '.join(started)}; " if started else "") + "not started: " + "; ".join(refused))
                    else:
                        step("services", True, "started: " + ", ".join(started))
            if "startup" in wanted:
                current = "startup"
                startups = self.startups()
                made = [f"{s.app} ({s.name}: {s.state})" for s in startups if s.present]
                missing = [s.app for s in startups if not s.present]
                step("startup", None, ("at logon: " + ", ".join(made) if made else "no app starts at logon")
                     + (f"; not registered: {', '.join(missing)} (`register` makes one when you want it)" if missing else ""))
        except CommandError as e:
            step(current, False, str(e))
        return done
