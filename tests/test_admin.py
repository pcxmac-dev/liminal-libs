"""The admin base of the platform's plugins (liminal_libs.machines.admin): the framework's apps and how each is
started, which app a command line runs, and the base's checks, status and setup over a stand-in system."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from liminal_libs.machines.admin import APPS, Admin, AdminError, Startup, SystemService, app_of, start_command
from liminal_libs.machines.plugin import CommandError
from liminal_libs.sources.conformance import problems


class FakeAdmin(Admin):
    name = "fake-admin"
    title = "A stand-in system"
    about = "services and startups kept in memory"
    api = "2.1"
    order = 960
    SERVICES = (("docker", "Docker Engine", "the containers", True), ("sshd", "OpenSSH server", "remote access", False),
                ("dns", "DNS", "lookups", True))

    def __init__(self, elevated=False, states=None):
        self._elevated = elevated
        self.states = dict(states or {"docker": "stopped", "sshd": "stopped", "dns": "running"})
        self.made: dict[str, list[str]] = {}
        self.actions: list = []
        self.refuse = False

    def present(self):
        return True

    def elevated(self):
        return self._elevated

    def elevation(self):
        return "elevated" if self._elevated else "not elevated: run the platform as administrator"

    def services(self):
        return [SystemService(n, t, self.states.get(n, "absent"), "manual", u, m) for n, t, u, m in self.SERVICES]

    def _service_action(self, name, action):
        if self.refuse:
            raise CommandError("Access is denied", denied=True)
        self.actions.append((name, action))
        self.states[name] = "running" if action in ("start", "restart") else "stopped"

    def startups(self):
        return [Startup(app, f"Liminal{app.capitalize()}", "ready", " ".join(self.made[app])) if app in self.made
                else Startup(app, "", "absent") for app in APPS]

    def _startup_action(self, app, action):
        self.actions.append((app, action))

    def _register(self, app, command):
        self.made[app] = command

    def _unregister(self, app):
        return self.made.pop(app, None) is not None

    def processes(self):
        return [{"pid": 1, "app": "charts", "command": "pythonw -m liminal_charts gui", "memoryMb": 100}]


def test_the_apps_and_how_each_is_started():
    assert set(APPS) == {"charts", "integrator", "login", "platform"}
    cmd = start_command("charts", python=sys.executable)
    assert cmd[1:] == ["-m", "liminal_charts", "gui", "--no-browser", "--port", "8765"] and Path(cmd[0]).name.lower().startswith("python")
    assert start_command("integrator", python=sys.executable)[1:] == ["-m", "liminal_integrator", "service", "run", "--daemon"]
    with pytest.raises(AdminError):
        start_command("nothing")
    assert app_of('"C:\\venv\\pythonw.exe" -m liminal_charts gui --no-browser --port 8765') == "charts"
    assert app_of("/usr/bin/python3 -m liminal_integrator service run --daemon") == "integrator"
    assert app_of("python -m somethingelse") == ""


def test_the_admin_plugin_conforms_checks_what_is_asked_and_reports():
    a = FakeAdmin()
    assert problems(a) == [] and a.STEPS == ("privileges", "services", "startup") and a.KIND == "machine"
    assert {"service", "startup", "register", "unregister", "processes"} <= set(a.interface()["hooks"])
    a.service("docker", "start")
    assert a.actions[-1] == ("docker", "start")
    with pytest.raises(AdminError):
        a.service("docker", "explode")
    with pytest.raises(AdminError):
        a.service("spooler", "stop")  # not one of the framework's: never touched
    a.startup("charts", "run")
    assert a.actions[-1] == ("charts", "run")
    for bad in (("charts", "explode"), ("nothing", "run")):
        with pytest.raises(AdminError):
            a.startup(*bad)
    made = a.register("platform", python=sys.executable)
    assert made.app == "platform" and made.state == "ready" and "liminal_platform serve --no-browser" in made.command
    assert a.unregister("platform") and not a.unregister("platform")
    with pytest.raises(AdminError):
        a.unregister("nothing")
    st = a.status()
    assert st["present"] and st["elevated"] is False and st["processes"][0]["app"] == "charts"
    assert st["summary"] == "not elevated; services: 2 running, stopped: sshd; startups: none; 1 Liminal process(es)"


def test_the_setup_starts_what_it_may_and_registers_nothing():
    a = FakeAdmin(elevated=True)
    lines: list[str] = []
    done = a.setup(log=lines.append)
    assert [(d["step"], d["ok"]) for d in done] == [("privileges", True), ("services", True), ("startup", None)]
    assert a.actions == [("docker", "start")] and a.states["sshd"] == "stopped"  # never an SSH server on its own
    assert "not registered: charts, integrator, login, platform" in done[2]["detail"] and a.made == {}
    assert a.setup(log=lines.append, steps=("services",))[0]["ok"] is None  # all it may start runs
    refusing = FakeAdmin()
    refusing.refuse = True
    out = refusing.setup(log=lines.append, steps=("privileges", "services"))
    assert [(d["step"], d["ok"]) for d in out] == [("privileges", None), ("services", False)] and "Access is denied" in out[1]["detail"]
