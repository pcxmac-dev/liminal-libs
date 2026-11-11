"""The machine's administration for the framework, as a machine plugin's base (the user, 2026-11-07: "a windows
and linux admin plugin for platform"; the platform is "the interface for the software/hardware which
facilitates the liminal framework"): whether the platform has an administrator's (root's) rights and how
they are had; the system services the framework relies on (WSL, Docker, the firewall, DNS), their state,
started when stopped; the framework's own startups (a scheduled task at logon or a systemd user unit per
app: charts, integrator, login, platform), read, run, ended, made or removed when asked; the framework's
processes running. The setup reports the rights, starts the services it may that are stopped, and reports
the startups: it makes no startup on its own (the plugin lifecycle: nothing runs while the user is not using
it), and an SSH server is never started by it.

The boot services (1.47.0; the user, 2026-11-11: "also windows and linux admin, need sections for starting the
platform, or an app that inherits the platform object as a service, headless"; "on boot"): the platform, or an app
whose App class inherits the platform's (PLATFORM_APP: the app a plugin is attached to, or one an installed
distribution names under the `liminal.apps` entry points), started when the machine starts, before anyone signs in,
as `python -m <module> serve --no-browser --port N` (no browser, no window, never --until-quiet), as the platform's
own user and never root, started again after a failure. The startups' own hooks take them with `at="boot"`:
`register(app, "boot", port)` makes one (made, not run), `startup(app, "start" | "stop", "boot")` runs or stops it,
`unregister(app, "boot", accept_removal)` removes it, asked twice (refused until accepted: RemovalRefused). A
subclass makes them on its system (BOOT_SERVICES: a scheduled task At startup on Windows, a system unit or an OpenRC
service on Linux); the page's section is this base's: the status's `boot`, a table under `tables` and its forms under
`forms`, each change confirmed in the page's dialog.

The page (1.48.0; the user: "the administration plugins don't seem to work right especially linux which doesn't say
anything about startup"): an admin plugin is valid whenever it can read (the rights are a fact: each change asks for
them, Windows' prompt or sudo without a password, or says it needs them: `rights_words`), and its status is its own
tables with their confirmed forms: the services, the startups at logon, the boot services, the processes. Where it is not
for this machine, `elsewhere()` says what it does on one it is for."""
from __future__ import annotations

import importlib
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

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
AT = ("logon", "boot")  # when a startup starts its app: at the user's logon, or at boot, before anyone signs in (1.47.0)
BOOT_ACTIONS = ("start", "stop")
BOOT_SYNONYMS = {"run": "start", "end": "stop"}  # a logon startup's words for them
BOOT_UP = ("running", "starting", "restarting")  # a boot service's states while it runs (Stop… is offered)
PLATFORM_APP = "liminal_platform.app.PlatformApp"  # the App class a boot service's app is or inherits (named here, never imported for it)
APP_ENTRY_POINTS = "liminal.apps"  # an installed app's App class, named by its distribution: lab = "liminal_lab.app:LabApp"
BOOT_NAME = re.compile(r"[a-z][a-z0-9]*")  # an app's NAME a boot service can be named by
PORTS = (1024, 65535)  # a boot service's port: one any user's program may take
ACCEPT_REMOVAL = "accept_removal"  # the argument accepting a boot service's removal: it is asked twice
FOUND_S = 60.0  # the apps installed are looked for again after this long
_installed: tuple[float, list] | None = None


class AdminError(CommandError):
    pass


class BootRefused(AdminError, ValueError):
    """A boot service's change refused before anything is done (an app no boot service starts, a port out of range or
    another's): the platform says it as a refusal and offers the form again."""


class RemovalRefused(BootRefused):
    """A boot service's removal, refused until accepted in so many words (`accept`: the argument that accepts it; the
    platform asks a second time)."""

    accept = ACCEPT_REMOVAL


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
    """One app's startup registration: a scheduled task at logon (Windows), a systemd user unit (Linux); or, `at` boot,
    its boot service (1.47.0: a scheduled task At startup, a system unit, an OpenRC service), with who it runs as,
    where its output goes and its port."""

    app: str
    name: str
    state: str  # ready | running | stopped | starting | disabled | unknown | absent | another word the system uses
    command: str = ""  # what it runs (a boot service not registered: what registering it would run)
    detail: str = ""
    at: str = "logon"  # logon: at the user's logon; boot: at boot, before anyone signs in
    account: str = ""  # who it runs as (a boot service's)
    log: str = ""  # where its output goes (a boot service's)
    port: int = 0  # where its page answers (a boot service's)

    @property
    def present(self) -> bool:
        return self.state != "absent"

    def describe(self) -> dict:
        return {"app": self.app, "name": self.name, "state": self.state, "command": self.command, "detail": self.detail,
                "at": self.at, "account": self.account, "log": self.log, "port": self.port}


@dataclass(frozen=True)
class BootApp:
    """An app a boot service may start: the platform, or an app whose App class inherits the platform's."""

    name: str  # its App's NAME: its boot service is named by it
    title: str
    module: str  # what `python -m` runs: its package
    port: int  # where it serves unless told otherwise: its PORT_VAR in the environment, else its PORT
    cls: str = ""  # its App class, module.qualname
    log: str = ""  # its own log, when known (the platform's platform.log)

    @property
    def platform(self) -> bool:
        return self.cls == PLATFORM_APP

    def describe(self) -> dict:
        return {"name": self.name, "title": self.title, "module": self.module, "port": self.port, "cls": self.cls,
                "log": self.log, "platform": self.platform}


def app_of(command: str) -> str:
    """Which of the framework's apps a command line runs ("" for none)."""
    for app, (module, _) in APPS.items():
        if f"-m {module}" in command or f"{module}\\__main__" in command or f"{module}/__main__" in command:
            return app
    return ""


def interpreter(python: str | None = None) -> str:
    """The Python an app is started with: this one (`python`: another, as given), its pythonw.exe beside it on Windows (no
    window)."""
    exe = str(python or sys.executable)
    quiet = Path(exe).with_name("pythonw.exe")
    return str(quiet) if quiet.exists() else exe


def start_command(app: str, python: str | None = None) -> list[str]:
    """The command that starts `app` for good: this Python's (pythonw on Windows: no window), its module."""
    if app not in APPS:
        raise AdminError(f"no app named {app!r}: {', '.join(APPS)}")
    module, args = APPS[app]
    return [interpreter(python), "-m", module, *args]


def boot_command(app: BootApp, port: int, python: str | None = None) -> list[str]:
    """What a boot service runs: `python -m <module> serve --no-browser --port N` (this Python; pythonw on Windows),
    headless (no browser, no window) and kept up until stopped (never --until-quiet)."""
    return [interpreter(python), "-m", app.module, "serve", "--no-browser", "--port", str(int(port))]


# -- the apps a boot service may start (1.47.0) ----------------------------------------------------------------------
def class_path(cls) -> str:
    """A class by its module and name: liminal_platform.app.PlatformApp."""
    return f"{getattr(cls, '__module__', '')}.{getattr(cls, '__qualname__', '')}"


def inherits_platform(cls) -> bool:
    """Whether `cls` is the platform's App class or inherits it (by its classes' names: the platform is never imported for it)."""
    return isinstance(cls, type) and any(class_path(c) == PLATFORM_APP for c in cls.__mro__)


def platform_class(attached=None):
    """The platform's App class: among the classes of the app a plugin is attached to, else liminal_platform's when it
    is installed here; None without it."""
    if attached is not None:
        for c in type(attached).__mro__:
            if class_path(c) == PLATFORM_APP:
                return c
    module_name, _, name = PLATFORM_APP.rpartition(".")
    try:
        module = importlib.import_module(module_name)
    except Exception:  # noqa: BLE001 - not installed, or not importable here: no platform
        return None
    found = getattr(module, name, None)
    return found if isinstance(found, type) else None


def installed_apps(found=None) -> list:
    """The App classes installed apps name under the `liminal.apps` entry points (APP_ENTRY_POINTS), loaded (one that
    does not load is left out); looked for again after FOUND_S. `found`: a test's classes."""
    global _installed
    if found is not None:
        return [c for c in found if isinstance(c, type)]
    now = time.monotonic()
    if _installed is not None and now - _installed[0] < FOUND_S:
        return list(_installed[1])
    out: list = []
    try:
        from importlib.metadata import entry_points

        named = list(entry_points(group=APP_ENTRY_POINTS))
    except Exception:  # noqa: BLE001 - the metadata cannot be read: none named
        named = []
    for ep in named:
        try:
            cls = ep.load()
        except Exception:  # noqa: BLE001 - an app that does not load is left out
            continue
        if isinstance(cls, type):
            out.append(cls)
    _installed = (now, out)
    return list(out)


def platform_logs(platform=None) -> Path:
    """Where the platform keeps its logs, and the boot services theirs: its folder's logs/ (liminal_platform.app's
    platform_dir(), LIMINAL_PLATFORM_DIR), else the data folder's platform/logs."""
    module = sys.modules.get(getattr(platform, "__module__", "") or "")
    folder = getattr(module, "platform_dir", None)
    if callable(folder):
        try:
            return Path(folder()) / "logs"
        except Exception:  # noqa: BLE001 - its folder cannot be said: the data folder's
            pass
    from .. import layout

    return layout.data_dir() / "platform" / "logs"


def boot_app_of(cls, env=None, logs: Path | None = None) -> BootApp | None:
    """An App class as a boot service starts it: its NAME (None when no service can be named by it: BOOT_NAME), its
    title, the package `python -m` runs, its port (its PORT_VAR in `env`, else its PORT); its own log for the platform
    (`logs`: the platform's logs folder)."""
    name = str(getattr(cls, "NAME", "") or "")
    if not BOOT_NAME.fullmatch(name):
        return None
    env = os.environ if env is None else env
    var = str(getattr(cls, "PORT_VAR", "") or "")
    raw = str(env.get(var) or "").strip() if var else ""
    port = int(raw) if raw.isdecimal() else int(getattr(cls, "PORT", 0) or 0)
    path = class_path(cls)
    own = str(Path(logs) / f"{name}.log") if logs is not None and path == PLATFORM_APP else ""
    return BootApp(name, str(getattr(cls, "TITLE", "") or name), str(cls.__module__).split(".")[0], port, path, own)


def boot_apps(attached=None, found=None, env=None, logs: Path | None = None) -> list[BootApp]:
    """The apps a boot service may start, the platform first: the platform (when installed), then each app known whose
    App class inherits the platform's: the one a plugin is attached to, and those installed apps name under
    APP_ENTRY_POINTS (`found`: a test's classes). Each once by its NAME: one naming itself as an earlier one is left out."""
    classes = []
    base = platform_class(attached)
    if base is not None:
        classes.append(base)
    if attached is not None and inherits_platform(type(attached)):
        classes.append(type(attached))
    classes += [c for c in installed_apps(found) if inherits_platform(c)]
    out: list[BootApp] = []
    for c in classes:
        app = boot_app_of(c, env, logs)
        if app is not None and all(a.name != app.name for a in out):
            out.append(app)
    return out


def page_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/" if port else "its port"


class Admin(MachinePlugin):
    """The base of the admin plugins. A subclass drives one system through the backend methods below; the hooks
    (status, setup) and the checks of what is asked are this base's."""

    HOOKS = (*MachinePlugin.HOOKS, "service", "startup", "register", "unregister", "processes")  # what the platform may ask by name
    STEPS = STEPS
    ICON = "wrench"
    SERVICES: tuple = ()  # (name, title, what of the framework uses it, may the setup start it)
    BOOT_SERVICES = False  # whether it makes boot services (1.47.0): the backend's boot_* methods below

    # -- the backend: a subclass's -----------------------------------------------------------------
    def elevated(self) -> bool:
        """Whether the platform has an administrator's (root's) rights now."""
        raise NotImplementedError

    def elevation(self) -> str:
        """How the rights are had, in words (elevated; a UAC prompt; sudo without a password ...)."""
        raise NotImplementedError

    def may_elevate(self) -> bool:
        """Whether a change needing an administrator's (root's) rights can have them when it is asked (Windows' prompt on
        a desktop; sudo without a password): what a change's words say. None by default."""
        return False

    def rights_words(self, kind: str) -> str:
        """How a change of `kind` (service, logon, boot) has its rights, in words for the page ("" when nothing is asked:
        the platform has them, or none are needed)."""
        return ""

    def elsewhere(self) -> tuple[str, list[dict]]:
        """What this plugin does on a machine it is for, said where it does not apply (not_for_here): a few words added
        to the reason, and tables describing its sections. Nothing by default."""
        return "", []

    def services(self) -> list[SystemService]:
        """The SERVICES as they are (absent when not installed)."""
        raise NotImplementedError

    def _service_action(self, name: str, action: str) -> None:
        raise NotImplementedError

    def _service_change(self, name: str, action: str) -> None:
        """A service started, stopped or restarted as the user asked on the page (the setup's own starts go through
        _service_action): the same by default; a subclass may ask for the rights here (Windows' prompt)."""
        self._service_action(name, action)

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

    # the boot services' backend (BOOT_SERVICES)
    def boot_how(self) -> str:
        """How this system starts an app at boot, in a few words for the page's section; BootRefused when it makes none
        here (an init it does not know)."""
        raise BootRefused(f"{self.name} makes no boot services")

    def boot_details(self) -> str:
        """How a boot service is made here, in full (who it runs as and what that allows, how it is started again after
        a failure), for the form registering one."""
        return ""

    def boot_stopping(self) -> str:
        """How a boot service is stopped, in words."""
        return "ended"

    def boot_startups(self, apps: list[BootApp]) -> list[Startup]:
        """One per app (`at` "boot"; absent when it has none: what registering it would make, at its own port), then
        those registered for apps not known here."""
        return []

    def _boot_register(self, app: BootApp, port: int, python: str | None = None) -> None:
        raise BootRefused(f"{self.name} makes no boot services")

    def _boot_action(self, boot: Startup, action: str) -> None:
        raise BootRefused(f"{self.name} makes no boot services")

    def _boot_unregister(self, boot: Startup) -> bool:
        raise BootRefused(f"{self.name} makes no boot services")

    def boot_env(self):
        """The environment an app's port variable is read from."""
        return os.environ

    def boot_logs(self) -> Path:
        """Where the boot services' logs go: the platform's logs folder (platform_logs)."""
        return platform_logs(platform_class(self.app))

    def boot_apps(self) -> list[BootApp]:
        """The apps a boot service may start here, the platform first (boot_apps: the platform, the app this plugin is
        attached to when it inherits the platform, the installed apps naming themselves)."""
        return boot_apps(self.app, env=self.boot_env(), logs=self.boot_logs())

    # -- what the platform asks, checked here -------------------------------------------------------
    @staticmethod
    def _at(at) -> str:
        word = str(at or "logon").strip().lower()
        if word not in AT:
            raise BootRefused(f"a startup is at logon or at boot, not {at!r}")
        return word

    def service(self, name: str, action: str) -> None:
        """start, stop or restart one of the framework's services (SERVICES), never another."""
        if action not in SERVICE_ACTIONS:
            raise AdminError(f"a service is {', '.join(SERVICE_ACTIONS)}ed, not {action!r}")
        known = {s[0] for s in self.SERVICES}
        if name not in known:
            raise AdminError(f"{name} is not one of the framework's services here: {', '.join(sorted(known))}")
        self._service_change(name, action)

    def startup(self, app: str, action: str, at: str = "logon"):
        """run, end, enable or disable an app's startup at logon; `at` "boot": start or stop its boot service (its
        answer in words for the page)."""
        if self._at(at) == "boot":
            act = BOOT_SYNONYMS.get(str(action), str(action))
            if act not in BOOT_ACTIONS:
                raise BootRefused(f"a boot service is started or stopped, not {action!r}")
            self.boot_how()
            boot = self._registered_boot(app)
            self._boot_action(boot, act)
            if act == "start":
                return {"said": f"{boot.name} started", "ok": True,
                        "lines": [f"its page: {page_url(boot.port)} once it is up", f"its log: {boot.log}"]}
            return {"said": f"{boot.name} stopped", "ok": True, "lines": ["it stays registered: Start, or the next boot, runs it again"]}
        if action not in STARTUP_ACTIONS:
            raise AdminError(f"a startup is {', '.join(STARTUP_ACTIONS)}, not {action!r}")
        if app not in APPS:
            raise AdminError(f"no app named {app!r}: {', '.join(APPS)}")
        self._startup_action(app, action)
        return None

    def register(self, app: str, at: str = "logon", port=None, python: str | None = None) -> Startup:
        """The app started from now on (made, not run): at the user's logon; `at` "boot": at boot, before anyone signs
        in, the platform or an app inheriting it, at `port` (its own by default; one no other boot service has)."""
        if self._at(at) == "logon":
            self._register(app, start_command(app, python))
            return next((s for s in self.startups() if s.app == app), Startup(app, "", "unknown"))
        self.boot_how()
        known = self._boot_app(app)
        port = self._boot_port(known, port, self.boot_startups(self.boot_apps()))
        self._boot_register(known, port, python)
        return next((b for b in self.boot_startups(self.boot_apps()) if b.app == known.name),
                    Startup(known.name, "", "unknown", at="boot", port=port))

    def unregister(self, app: str, at: str = "logon", accept_removal=False):
        """An app's startup at logon removed (whether it had one); `at` "boot": its boot service stopped and removed, once
        accepted a second time (`accept_removal`: RemovalRefused before), its answer in words for the page."""
        if self._at(at) == "logon":
            if app not in APPS:
                raise AdminError(f"no app named {app!r}: {', '.join(APPS)}")
            return self._unregister(app)
        self.boot_how()
        boot = self._registered_boot(app)
        title = self._title_of(boot.app)
        if accept_removal is not True:
            raise RemovalRefused(f"{boot.name} is removed only once you say so a second time: {title} would no longer "
                                 "start at boot, before anyone signs in")
        removed = self._boot_unregister(boot)
        return {"said": f"{boot.name} removed: {title} no longer starts at boot" if removed else f"{boot.name} was not registered",
                "ok": removed, "removed": removed, "lines": [f"its log stays: {boot.log}"] if removed and boot.log else []}

    def _title_of(self, app: str) -> str:
        return next((a.title for a in self.boot_apps() if a.name == app), app)

    def _boot_app(self, app) -> BootApp:
        name = str(app or "").strip()
        apps = self.boot_apps()
        found = next((a for a in apps if a.name == name), None)
        if found is None:
            raise BootRefused(f"{name or 'that'} is not an app a boot service starts here (the platform, or an app inheriting it): "
                              + (", ".join(a.name for a in apps) or "the platform is not installed"))
        return found

    @staticmethod
    def _boot_port(app: BootApp, port, boots: list[Startup]) -> int:
        if port is None or (isinstance(port, str) and not port.strip()):
            port = app.port
        if isinstance(port, bool) or (isinstance(port, float) and not port.is_integer()):
            raise BootRefused(f"a port is a whole number, not {port!r}")
        try:
            n = int(port)
        except (TypeError, ValueError):
            raise BootRefused(f"a port is a whole number, not {port!r}") from None
        if not PORTS[0] <= n <= PORTS[1]:
            raise BootRefused(f"a boot service's port is from {PORTS[0]} to {PORTS[1]}, not {n}")
        other = next((b for b in boots if b.present and b.app != app.name and b.port == n), None)
        if other is not None:
            raise BootRefused(f"port {n} is {other.app}'s boot service's ({other.name}): choose another")
        return n

    def _registered_boot(self, app) -> Startup:
        name = str(app or "").strip()
        found = next((b for b in self.boot_startups(self.boot_apps()) if b.app == name and b.present), None)
        if found is None:
            raise BootRefused(f"{name or 'that app'} has no boot service registered here")
        return found

    # -- the hooks ----------------------------------------------------------------------------------
    def status(self) -> dict:
        """What the plugin reads, valid whenever it can read it (the rights are a fact: each change asks for them, or says
        it needs them): the elevation, the summary, the raw lists (frameworkServices, logonStartups, bootServices,
        frameworkProcesses) and the page's own tables and forms (the platform's status contract; its older admin tables,
        drawn from `services`, `startups` and `processes` with buttons asking at once, are no longer sent)."""
        empty = {"frameworkServices": [], "logonStartups": [], "bootServices": [], "frameworkProcesses": []}
        here = self.not_for_here()
        if here:  # not for this machine at all (a Linux plugin on Windows or in WSL): asked nothing, no setup offered
            words, described = self.elsewhere()  # what it does on a machine it is for, said here
            return self.not_here_status(f"{here}. {words}" if words else here, elevated=False, elevation="", **empty,
                                        tables=described, forms=[])
        note = self.scope_note()
        if note:  # not Liminal's (the user's own distribution): asked nothing at all
            return {"present": False, "elevated": False, "elevation": "", **empty, "summary": "not on Liminal's", "valid": False, "why": note}
        if not self.present():
            return {"present": False, "elevated": False, "elevation": "", **empty, "summary": "not present", "valid": False, "why": "not present"}
        try:
            elevated, how = self.elevated(), self.elevation()
            services, startups, processes = self.services(), self.startups(), self.processes()
        except CommandError as e:
            return {"present": True, "elevated": False, "elevation": "", **empty, "problem": str(e), "summary": f"cannot be read: {e}",
                    "valid": False, "why": f"cannot be read: {e}"}
        boots, boot_section = self._boot_status(startups)
        running = [s.name for s in services if s.running]
        stopped = [s.name for s in services if s.present and not s.running]
        made = [s.app for s in startups if s.present]
        at_boot = [f"{b.app} ({b.state})" for b in boots if b.present]
        summary = (f"{'elevated' if elevated else 'not elevated'}; services: {len(running)} running"
                   + (f", stopped: {', '.join(stopped)}" if stopped else "")
                   + f"; startups: {', '.join(made) or 'none'}" + (f"; at boot: {', '.join(at_boot)}" if at_boot else "")
                   + f"; {len(processes)} Liminal process(es)")
        scoped, place = self.scope()
        why = "" if scoped else f"{place} is not Liminal's"
        sections = [self.services_section(services), self.logon_section(startups)]
        if boot_section is not None:
            sections.append(boot_section)
        return {"present": True, "elevated": elevated, "elevation": how, "summary": summary, "valid": not why, "why": why,
                "frameworkServices": [s.describe() for s in services], "logonStartups": [s.describe() for s in startups],
                "bootServices": [b.describe() for b in boots], "frameworkProcesses": processes,
                "tables": [t for t, _ in sections] + [self.processes_table(processes)], "forms": [f for _, fs in sections for f in fs]}

    def _boot_status(self, logon: list[Startup]) -> tuple[list[Startup], tuple[dict, list[dict]] | None]:
        """The boot services and the page's section for them (None: this plugin makes none)."""
        if not self.BOOT_SERVICES:
            return [], None
        try:
            how = self.boot_how()
        except CommandError as e:  # none made here (an init neither systemd nor OpenRC): the section says why
            return [], self.boot_section([], [], logon, "", str(e))
        apps: list[BootApp] = []
        boots: list[Startup] = []
        problem = ""
        try:
            apps = self.boot_apps()
            boots = self.boot_startups(apps)
        except CommandError as e:
            problem = f"the boot services cannot be read: {e}"
        return boots, self.boot_section(apps, boots, logon, how, problem)

    def setup(self, log=print, steps=None) -> list[dict]:
        """`privileges` (reported), `services` (the framework's stopped services it may start, started),
        `startup` (reported: it makes none, at logon or at boot; `register` does when asked); each reported."""
        wanted = tuple(steps) if steps else self.STEPS
        done: list[dict] = []

        def step(what: str, ok: bool | None, detail: str) -> None:
            done.append({"step": what, "ok": ok, "detail": detail})
            log(f"{self.name}: {what}: {'ok' if ok else 'skipped' if ok is None else 'FAILED'}: {detail}")

        note = self.not_for_here() or self.scope_note()
        if note:  # not for this machine, or the user's own: nothing changed
            step(wanted[0] if wanted else "setup", False, note)
            return done
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
                     + (f"; not registered: {', '.join(missing)} (`register` makes one when you want it)" if missing else "")
                     + self._boot_said())
        except CommandError as e:
            step(current, False, str(e))
        return done

    def _boot_said(self) -> str:
        """The boot services in the setup's words ("" when this plugin makes none)."""
        if not self.BOOT_SERVICES:
            return ""
        try:
            self.boot_how()
            boots = [b for b in self.boot_startups(self.boot_apps()) if b.present]
        except CommandError as e:
            return f"; at boot: {e}"
        if not boots:
            return "; nothing starts at boot (a boot service is made only when you register one)"
        return "; at boot: " + ", ".join(f"{b.app} ({b.name}: {b.state})" for b in boots)

    # -- the page: its tables and forms (status `tables` and `forms`; platform 0.7.0's cells and actions) --------------
    def services_section(self, services: list[SystemService]) -> tuple[dict, list[dict]]:
        """The services the framework relies on as a table (a row each: its state, how it starts, what uses it, its
        buttons) and the form changing one, confirmed with the exact change."""
        rights = self.rights_words("service")
        asked = f" {rights}." if rights else ""
        rows = []
        for s in services:
            up = s.running
            rows.append([{"text": s.name, "sub": s.title}, s.state, s.startup or "–", s.used_for or "–",
                         {"form": "service", "title": "Stop…" if up else "Start…", "values": {"name": s.name, "action": "stop" if up else "start"},
                          "label": f"{'Stop' if up else 'Start'} {s.name}"} if s.present else "",
                         {"form": "service", "title": "Restart…", "values": {"name": s.name, "action": "restart"},
                          "label": f"Restart {s.name}"} if up else ""])
        present = [s for s in services if s.present]
        table = {"title": "Services the framework relies on", "rows": rows,
                 "note": f"The setup starts those stopped it may, never an SSH server; each change here is confirmed first.{asked}",
                 "columns": [{"title": "Service"}, {"title": "State"}, {"title": "Starts"}, {"title": "For"}, {"title": "Change"},
                             {"title": "Restart"}],
                 "empty": "None of them here."}
        if not present:
            return table, []
        table["actions"] = [{"form": "service", "title": "Start, stop or restart a service…"}]
        form = {"id": "service", "hook": "service", "title": "Start, stop or restart a service", "submit": "Review",
                "note": f"One of the services the framework relies on, never another.{asked}",
                "fields": [{"name": "name", "label": "Service", "type": "choice", "value": present[0].name,
                            "choices": [{"value": s.name, "title": f"{s.name} ({s.title})",
                                         "note": f"{s.state}; {s.used_for}" + ("" if s.may_start else "; started only when you ask")}
                                        for s in present]},
                           {"name": "action", "label": "Change", "type": "choice", "value": "start", "choices": [
                               {"value": "start", "title": "Start", "note": "runs it"},
                               {"value": "stop", "title": "Stop", "note": "what relies on it stops working until it starts again"},
                               {"value": "restart", "title": "Restart", "note": "stopped, then started again"}]}],
                "confirm": {"title": "{action} {name}?", "yes": "Confirm",
                            "words": "The service {name}: {action}. Only that service changes." + asked}}
        return table, [form]

    def logon_section(self, startups: list[Startup]) -> tuple[dict, list[dict]]:
        """The apps' startups at the user's logon as a table (a row each: its task or unit, what it runs, its state, its
        buttons; another of the same app, an integrator of its own, shown only) and the forms: Register… (each app
        without one), Run…/End… (and enable, disable), Remove…, each confirmed with the exact change."""
        rights = self.rights_words("logon")
        asked = f" {rights}." if rights else ""
        main: dict[str, Startup] = {}
        for s in startups:
            main.setdefault(s.app, s)  # the app's own: an integrator of its own (LiminalIntegrator-<name>) comes after it
        fixed_at = {"name": "at", "label": "Starts", "type": "fixed", "value": "logon", "choices": [{"value": "logon", "title": "at your logon"}]}
        rows, forms = [], []
        for s in startups:
            own = main.get(s.app) is s and s.app in APPS
            command = s.command or (" ".join(start_command(s.app, getattr(self, "_python", None))) if s.app in APPS else "")
            rows.append([s.app, {"text": s.name or "–", "sub": command if s.present else (f"would run {command}" if command else "")},
                         {"text": s.state, "sub": s.detail} if s.detail else ("not registered" if not s.present else s.state),
                         ({"form": "logon-startup", "title": "End…" if s.state == "running" else "Run…",
                           "values": {"app": s.app, "action": "end" if s.state == "running" else "run"}, "label": f"Run or end {s.app}"}
                          if own and s.present else {"form": f"logon-register:{s.app}", "title": "Register…", "label": f"Start {s.app} at your logon"}
                          if own else ""),
                         {"form": "logon-remove", "title": "Remove…", "values": {"app": s.app}, "label": f"Remove {s.app}'s startup"}
                         if own and s.present else ""])
            if own and not s.present:
                forms.append({"id": f"logon-register:{s.app}", "hook": "register", "title": f"Start {s.app} at your logon",
                              "fields": [{"name": "app", "label": "App", "type": "fixed", "value": s.app}, fixed_at],
                              "confirm": {"title": f"Start {s.app} at your logon?", "yes": "Register it",
                                          "words": (f"{s.name or 'Its startup'} starts {s.app} each time you sign in: {command}. Made, not run: "
                                                    f"Run… runs it now.{asked}")}})
        made = [s for s in startups if main.get(s.app) is s and s.app in APPS and s.present]
        if made:
            pick = {"name": "app", "label": "App", "type": "choice", "value": made[0].app,
                    "choices": [{"value": s.app, "title": s.app, "note": f"{s.name}: {s.state}"} for s in made]}
            forms.append({"id": "logon-startup", "hook": "startup", "title": "Run, end, enable or disable a startup at your logon",
                          "submit": "Review", "note": f"The app's startup at your logon, as it is registered.{asked}",
                          "fields": [pick, {"name": "action", "label": "Change", "type": "choice", "value": "run", "choices": [
                              {"value": "run", "title": "Run", "note": "starts it now, as at your logon"},
                              {"value": "end", "title": "End", "note": "ends it now; it starts again at your next logon"},
                              {"value": "disable", "title": "Disable", "note": "it no longer starts at your logon, until enabled"},
                              {"value": "enable", "title": "Enable", "note": "it starts at your logon again"}]}, fixed_at],
                          "confirm": {"title": "{action} {app}'s startup at your logon?", "yes": "Confirm",
                                      "words": "The startup of {app} at your logon: {action}." + asked}})
            forms.append({"id": "logon-remove", "hook": "unregister", "title": "Remove a startup at your logon",
                          "submit": "Review", "fields": [pick, fixed_at],
                          "confirm": {"title": "Remove {app}'s startup at your logon?", "yes": "Remove it", "danger": True,
                                      "words": "The startup of {app} at your logon is removed: {app} no longer starts when you sign in; "
                                               "Register… makes it again." + asked}})
        table = {"title": "Startups at your logon", "rows": rows,
                 "note": ("Each app started when you sign in, made only when you ask (the setup makes none); its own task or unit, "
                          f"on your desktop.{asked}"),
                 "columns": [{"title": "App"}, {"title": "Startup"}, {"title": "State"}, {"title": "Change"}, {"title": "Remove"}],
                 "empty": "None read."}
        if made:
            table["actions"] = [{"form": "logon-startup", "title": "Run, end, enable or disable…"}]
        return table, forms

    @staticmethod
    def processes_table(processes: list[dict]) -> dict:
        """The framework's processes running, as a table (shown only)."""
        return {"title": "The framework's processes", "rows": [[str(p.get("pid", "")), p.get("app") or "–", f"{p.get('memoryMb', 0)} MB",
                                                                 str(p.get("command", ""))] for p in processes],
                "columns": [{"title": "Process", "num": True}, {"title": "App"}, {"title": "Memory", "num": True}, {"title": "Command"}],
                "empty": "None running."}

    # -- the page's section for the boot services ------------------------------------------------------------------
    def _served_port(self) -> int:
        """The port the app this plugin is attached to answers at now (0: not attached, or not serving)."""
        served = getattr(self.app, "served", None)
        try:
            return int(urlsplit(served).port or 0) if served else 0
        except ValueError:
            return 0

    def boot_section(self, apps: list[BootApp], boots: list[Startup], logon: list[Startup], how: str,
                     problem: str = "") -> tuple[dict, list[dict]]:
        """The boot services as the page draws them: a table (an app a row, the platform first: its boot service, the
        command, its state, who it runs as, its log, and its buttons) and the forms its buttons open: Register… (the
        port), Start…, Stop…, Remove… (asked twice), each confirmed in the page's dialog with the exact change."""
        known = {a.name: a for a in apps}
        rights = self.rights_words("boot")
        asked = f" {rights}." if rights else ""
        here, mine = self._served_port(), str(getattr(self.app, "NAME", "") or "")
        logon_of = {s.app: s for s in logon if s.present}
        details = self.boot_details() if how else ""
        note = (f"The platform, or an app inheriting it, started when this machine starts, before anyone signs in: headless "
                f"(no browser, no window), kept up until you stop or remove it. Unlike the startups at your logon (Startups, "
                f"above), it runs whether anyone is signed in or not" + (f": {how}." if how else ".")
                + f" Each change is confirmed first, a removal twice.{asked}")

        def log_cell(b: Startup, a: BootApp | None):
            """Its log by its file's name, the folder under it (a journal's command as it is), with the app's own log."""
            own = f"its own: {a.log}" if a is not None and a.log else ""
            parts = re.split(r"[\\/]", b.log) if b.log and not b.log.startswith("journalctl") else []
            if len(parts) > 1:
                folder = b.log[:len(b.log) - len(parts[-1])].rstrip("\\/")
                return {"text": parts[-1], "sub": f"in {folder}" + (f"; {own}" if own else "")}
            return {"text": b.log, "sub": own} if b.log and own else (b.log or "–")
        rows: list[list] = []
        forms: list[dict] = []
        actions: list[dict] = []
        for b in boots:
            a = known.get(b.app)
            title = a.title if a is not None else b.app
            fixed_app = {"name": "app", "label": "App", "type": "fixed", "value": b.app, "choices": [{"value": b.app, "title": title}]}
            fixed_at = {"name": "at", "label": "Starts", "type": "fixed", "value": "boot",
                        "choices": [{"value": "boot", "title": "at boot, before anyone signs in"}]}
            # what else wants a port: said beside the register form's port, and in a confirmation only where it is the same
            at_logon = logon_of.get(b.app)
            logon_port = 0
            if at_logon is not None:
                found = re.search(r"--port\s+(\d+)", at_logon.command)
                logon_port = int(found.group(1)) if found else (a.port if a is not None else 0)
            taken = ([f"{here} (the {title} serving this page)"] if here and b.app == mine else []) + \
                ([f"{logon_port} ({at_logon.name}, at your logon)"] if at_logon is not None and logon_port else [])
            clash = ""
            if b.present and here and here == b.port and b.app == mine:
                clash += f" The {title} serving this page answers at port {here} now: the boot service cannot take it while it does."
            if b.present and at_logon is not None and logon_port == b.port:
                clash += f" {at_logon.name} starts it at your logon at the same port: whichever starts second finds it taken."
            serving = bool(here) and here == b.port and b.state in BOOT_UP
            rows.append([
                {"text": title, "sub": f"{b.app} · python -m {a.module}" if a is not None else f"{b.app} · not installed here"},
                {"text": b.name, "sub": (b.command if b.present else f"would run {b.command}") if b.command else ""},
                {"text": b.state if b.present else "not registered", "sub": b.detail} if b.detail else (b.state if b.present else "not registered"),
                b.account or "–",
                log_cell(b, a),
                ({"form": f"boot-register:{b.app}", "title": "Register…", "label": f"Register {title} at boot"} if not b.present and a is not None
                 else "" if not b.present
                 else {"form": f"boot-stop:{b.app}", "title": "Stop…", "label": f"Stop {title}'s boot service"} if b.state in BOOT_UP
                 else {"form": f"boot-start:{b.app}", "title": "Start…", "label": f"Start {title}'s boot service"}),
                {"form": f"boot-remove:{b.app}", "title": "Remove…", "label": f"Remove {title}'s boot service"} if b.present else "",
            ])
            if a is not None:
                port = b.port or a.port
                would = re.sub(r"--port \d+", "--port {port}", b.command) if b.command else f"python -m {a.module} serve --no-browser --port {{port}}"
                forms.append({"id": f"boot-register:{b.app}", "hook": "register", "title": f"Start {title} at boot", "submit": "Review",
                              "note": (f"{details[0].upper()}{details[1:]}." if details else f"{how[0].upper()}{how[1:]}." if how else ""),
                              "fields": [fixed_app, fixed_at,
                                         {"name": "port", "label": "Port", "type": "number", "value": port, "min": PORTS[0], "max": PORTS[1],
                                          "required": True, "note": f"where its page answers, on this machine only ({PORTS[0]} to {PORTS[1]}; "
                                                                    f"its own: {a.port})" + (f"; in use: {', '.join(taken)}" if taken else "")}],
                              "confirm": {"title": f"Start {title} at boot?", "yes": "Register it",
                                          "words": (f"{b.name} starts {title} at every boot, before anyone signs in: {would}, as {b.account or 'you'}. "
                                                    "Its page answers at http://127.0.0.1:{port}/" + (f"; its log: {b.log}" if b.log else "")
                                                    + ". Made, not run: Start runs it."
                                                    + (f" It replaces the one registered now (port {b.port})." if b.present else "")
                                                    + asked)}})
                if b.present:
                    actions.append({"form": f"boot-register:{b.app}", "title": f"Change {title}'s port…"})
            if not b.present:
                continue
            if b.state == "unknown":
                actions.append({"form": f"boot-stop:{b.app}", "title": f"Stop {title}…"})
            for action, verb, words in (
                    ("start", "Start", f"{b.name} runs now, as it does at boot: {b.command or 'its command'}, as {b.account or 'its account'}, "
                                       f"headless. Its page answers at {page_url(b.port)} once it is up" + (f"; its log: {b.log}." if b.log else ".") + clash),
                    ("stop", "Stop", f"{b.name} is stopped ({self.boot_stopping()}): {title}'s page at {page_url(b.port)} stops answering "
                                     "until the next boot or Start. It stays registered.")):
                forms.append({"id": f"boot-{action}:{b.app}", "hook": "startup", "title": f"{verb} {title}'s boot service",
                              "fields": [fixed_app, {"name": "action", "label": "Action", "type": "fixed", "value": action,
                                                     "choices": [{"value": action, "title": f"{action} it now"}]}, fixed_at],
                              "confirm": {"title": f"{verb} {title}'s boot service?", "words": words + asked, "yes": f"{verb} it"}})
            forms.append({"id": f"boot-remove:{b.app}", "hook": "unregister", "title": f"Remove {title}'s boot service",
                          "fields": [fixed_app, fixed_at,
                                     {"name": ACCEPT_REMOVAL, "type": "accept", "title": f"Remove {b.name} for good?", "yes": "Remove it for good",
                                      "words": f"Once {b.name} is gone, nothing starts {title} before anyone signs in; registering it again makes a new one."
                                               + (" This page may be the one it serves: it stops answering." if serving else "")}],
                          "confirm": {"title": f"Remove {title}'s boot service?", "yes": "Remove it", "danger": True,
                                      "words": f"{b.name} is stopped and removed: {title} no longer starts at boot." + (" Its log stays." if b.log else "") + asked}})
        table = {"title": "At boot, before anyone signs in", "note": note,
                 "columns": [{"title": "App"}, {"title": "Boot service"}, {"title": "State"}, {"title": "Runs as"}, {"title": "Log"},
                             {"title": ""}, {"title": ""}],
                 "rows": rows, "actions": actions,
                 "empty": problem or "No app to start at boot here: the platform is not installed."}
        return table, forms
