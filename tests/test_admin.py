"""The admin base of the platform's plugins (liminal_libs.machines.admin): the framework's apps and how each is
started, which app a command line runs, and the base's checks, status and setup over a stand-in system; the boot
services (1.47.0): the apps a boot service may start (the platform and the apps inheriting it, named, never
imported), the startups' hooks `at` boot, the page's section and its forms, all over stand-ins (nothing made)."""
from __future__ import annotations

import inspect
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from liminal_libs.machines import admin as admin_mod
from liminal_libs.machines.admin import (ACCEPT_REMOVAL, APPS, PLATFORM_APP, Admin, AdminError, BootApp, BootRefused,
                                         RemovalRefused, Startup, SystemService, app_of, boot_app_of, boot_apps,
                                         boot_command, inherits_platform, platform_class, start_command)
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
    assert st["present"] and st["elevated"] is False and st["frameworkProcesses"][0]["app"] == "charts"
    assert st["summary"] == "not elevated; services: 2 running, stopped: sshd; startups: none; 1 Liminal process(es)"
    # valid whenever it reads (1.47.0): the rights are a fact beside it, each change asking for them or saying it needs them
    assert st["valid"] is True and st["why"] == "" and st["elevation"].startswith("not elevated")
    assert FakeAdmin(elevated=True).status()["valid"] is True
    # the raw lists under keys the platform's page draws nothing for: its tables are the plugin's own
    assert not {"services", "startups", "processes"} & set(st)
    assert [s["name"] for s in st["frameworkServices"]] == ["docker", "sshd", "dns"] and len(st["logonStartups"]) == len(APPS)


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


def test_on_a_target_not_liminals_the_admin_asks_nothing_and_changes_nothing():
    """The user's own distribution is never taken: its status and setup run no command there."""
    from liminal_libs.machines.linux import Shell

    ran: list = []
    a = FakeAdmin(elevated=True)
    a.shell = Shell("wsl:Ubuntu", runner=lambda args, timeout: ran.append(args) or (0, b"", b""))
    st = a.status()
    assert (st["present"], st["valid"], st["summary"]) == (False, False, "not on Liminal's") and "WSL's Ubuntu is not Liminal's" in st["why"]
    done = a.setup(log=lambda m: None)
    assert [d["ok"] for d in done] == [False] and "is not Liminal's" in done[0]["detail"] and ran == []


def test_an_admin_not_for_this_machine_asks_nothing_and_changes_nothing():
    """Not for this machine at all (Linux administration on Windows or in WSL; 1.27.0): applies False, nothing asked."""
    a = FakeAdmin(elevated=True)
    a.not_for_here = lambda: "for a native Linux machine"
    a.services = a.startups = a.processes = a.elevated = a.present = lambda: pytest.fail("asked")
    assert a.status() == {"present": False, "elevated": False, "elevation": "", "frameworkServices": [], "logonStartups": [],
                          "bootServices": [], "frameworkProcesses": [], "tables": [], "forms": [],
                          "summary": "not for this machine", "valid": False, "why": "for a native Linux machine", "applies": False}
    said: list = []
    assert a.setup(log=said.append) == [{"step": "privileges", "ok": False, "detail": "for a native Linux machine"}]
    assert said == ["fake-admin: privileges: FAILED: for a native Linux machine"] and a.actions == []
    # what it does on a machine it is for, said where it does not act: words after the reason, its sections as tables
    a.elsewhere = lambda: ("On a native Linux machine it shows its services", [{"title": "What it does", "columns": [], "rows": []}])
    st = a.status()
    assert st["why"] == "for a native Linux machine. On a native Linux machine it shows its services" and st["applies"] is False
    assert [t["title"] for t in st["tables"]] == ["What it does"] and st["forms"] == [] and a.actions == []


def table_of(st, title):
    return next(t for t in st["tables"] if t["title"] == title)


def test_the_page_draws_the_services_and_the_startups_as_tables_with_confirmed_forms():
    a = FakeAdmin()
    a.register("platform", python="python")  # a startup at logon for the platform
    st = a.status()
    assert [t["title"] for t in st["tables"]] == ["Services the framework relies on", "Startups at your logon", "The framework's processes"]
    forms = {f["id"]: f for f in st["forms"]}
    assert set(forms) == {"service", "logon-register:charts", "logon-register:integrator", "logon-register:login", "logon-startup", "logon-remove"}
    for f in forms.values():  # each form's fields are its hook's arguments, in order, and each change is confirmed
        assert f["hook"] in a.HOOKS and [x["name"] for x in f["fields"]] == list(inspect.signature(getattr(a, f["hook"])).parameters)[:len(f["fields"])]
        assert f["confirm"]["words"] and f["confirm"]["yes"]
    services = table_of(st, "Services the framework relies on")
    by_name = {r[0]["text"]: r for r in services["rows"]}
    assert by_name["docker"][4] == {"form": "service", "title": "Start…", "values": {"name": "docker", "action": "start"}, "label": "Start docker"}
    assert by_name["dns"][4]["title"] == "Stop…" and by_name["dns"][5]["values"] == {"name": "dns", "action": "restart"}
    assert [c["value"] for c in forms["service"]["fields"][0]["choices"]] == ["docker", "sshd", "dns"]
    assert "started only when you ask" in forms["service"]["fields"][0]["choices"][1]["note"]  # an SSH server: never by the setup
    logon = table_of(st, "Startups at your logon")
    rows = {r[0]: r for r in logon["rows"]}
    assert rows["platform"][3]["form"] == "logon-startup" and rows["platform"][4] == {"form": "logon-remove", "title": "Remove…",
                                                                                       "values": {"app": "platform"}, "label": "Remove platform's startup"}
    assert rows["charts"][3]["form"] == "logon-register:charts" and rows["charts"][4] == "" and rows["charts"][2] == "not registered"
    assert "-m liminal_charts gui --no-browser --port 8765" in rows["charts"][1]["sub"] and rows["charts"][1]["sub"].startswith("would run ")
    assert forms["logon-remove"]["confirm"]["danger"] and [c["value"] for c in forms["logon-startup"]["fields"][0]["choices"]] == ["platform"]
    assert [x["value"] for x in forms["logon-register:charts"]["fields"]] == ["charts", "logon"]
    assert table_of(st, "The framework's processes")["rows"] == [["1", "charts", "100 MB", "pythonw -m liminal_charts gui"]]
    # a change from the page goes through _service_change (a subclass asks for the rights there); the setup's own starts do not
    a._service_change = lambda name, action: a.actions.append(("asked", name, action))
    a.service("docker", "start")
    assert a.actions[-1] == ("asked", "docker", "start")


# -- the boot services (1.47.0) ----------------------------------------------------------------------------------------
class PlatformStandIn:
    """Stands in for liminal_platform.app.PlatformApp: named as it, so nothing of the platform is imported."""

    NAME = "platform"
    TITLE = "Liminal Platform"
    PORT = 8775
    PORT_VAR = "LIMINAL_PLATFORM_PORT"
    served = None


PlatformStandIn.__module__, PlatformStandIn.__qualname__ = "liminal_platform.app", "PlatformApp"


class LabApp(PlatformStandIn):
    """An app inheriting the platform."""

    NAME = "lab"
    TITLE = "Liminal Lab"
    PORT = 8790
    PORT_VAR = "LIMINAL_LAB_PORT"


LabApp.__module__, LabApp.__qualname__ = "liminal_lab.app", "LabApp"


class Again(PlatformStandIn):  # inherits the platform and names itself as it: left out
    pass


class Unnamed(PlatformStandIn):
    NAME = "my-lab"  # no service is named by it


class Charts:  # an app not inheriting the platform
    NAME = "charts"
    PORT = 8765


LOGS = Path("/stand-in/platform/logs")


class FakeBootAdmin(FakeAdmin):
    """The stand-in system with boot services kept in memory."""

    BOOT_SERVICES = True

    def __init__(self, elevated=False, may=True, apps=None):
        super().__init__(elevated=elevated)
        self.may = may
        self.apps = apps if apps is not None else boot_apps(PlatformStandIn(), found=[LabApp], env={}, logs=LOGS)
        self.boots: dict[str, Startup] = {}
        self.calls: list = []

    def may_elevate(self):
        return self.may

    def boot_apps(self):
        return list(self.apps)

    def boot_how(self):
        return "a stand-in service at boot"

    def rights_words(self, kind):
        if kind == "logon" or self._elevated:
            return ""
        return "The stand-in asks you first" if self.may else "It needs rights the stand-in cannot ask for here"

    def _made(self, app, port, state):
        return Startup(app.name, f"Liminal{app.name.capitalize()}Boot", state, " ".join(boot_command(app, port, "python")), "",
                       "boot", "me", f"/stand-in/{app.name}-boot.log", port)

    def boot_startups(self, apps):
        names = {a.name for a in apps}
        return [self.boots.get(a.name) or self._made(a, a.port, "absent") for a in apps] + \
            [b for app, b in self.boots.items() if app not in names]

    def _boot_register(self, app, port, python=None):
        self.calls.append(("register", app.name, port))
        self.boots[app.name] = self._made(app, port, "stopped")

    def _boot_action(self, boot, action):
        self.calls.append((action, boot.app))
        self.boots[boot.app] = replace(boot, state="running" if action == "start" else "stopped")

    def _boot_unregister(self, boot):
        self.calls.append(("remove", boot.app))
        return self.boots.pop(boot.app, None) is not None


def reg_note_of(st, app):
    return next(f for f in st["forms"] if f["id"] == f"boot-register:{app}")["note"]


def test_the_apps_a_boot_service_starts_are_the_platform_and_those_inheriting_it(monkeypatch):
    assert inherits_platform(PlatformStandIn) and inherits_platform(LabApp) and not inherits_platform(Charts)
    assert not inherits_platform(PlatformStandIn())  # a class, not an instance
    found = boot_apps(PlatformStandIn(), found=[Charts, LabApp, Again, Unnamed], env={}, logs=LOGS)
    assert [(a.name, a.module, a.port, a.platform) for a in found] == [("platform", "liminal_platform", 8775, True),
                                                                        ("lab", "liminal_lab", 8790, False)]
    assert found[0].log == str(LOGS / "platform.log") and found[1].log == "" and found[0].title == "Liminal Platform"
    moved = boot_apps(PlatformStandIn(), found=[], env={"LIMINAL_PLATFORM_PORT": "8780"}, logs=LOGS)
    assert [(a.name, a.port) for a in moved] == [("platform", 8780)]  # its port variable, as the app reads it
    # attached to an app inheriting the platform: the platform, then that app, from the app's own classes
    assert [a.name for a in boot_apps(LabApp(), found=[], env={})] == ["platform", "lab"]
    assert platform_class(LabApp()) is PlatformStandIn and boot_app_of(Unnamed, {}) is None
    assert boot_command(found[0], 8780, python=sys.executable)[1:] == ["-m", "liminal_platform", "serve", "--no-browser", "--port", "8780"]
    assert PLATFORM_APP == "liminal_platform.app.PlatformApp"

    # no platform installed, nothing attached: none (and the platform is only ever imported by its module's name)
    def missing(name):
        raise ImportError(name)
    monkeypatch.setattr(admin_mod.importlib, "import_module", missing)
    assert platform_class() is None and boot_apps(found=[Charts], env={}) == []


def test_a_boot_service_is_registered_started_stopped_and_removed_through_the_startups_hooks():
    a = FakeBootAdmin()
    made = a.register("platform", "boot", 8780)
    assert a.calls == [("register", "platform", 8780)] and made.at == "boot" and made.port == 8780 and made.state == "stopped"
    assert "-m liminal_platform serve --no-browser --port 8780" in made.command and made.account == "me"
    said = a.startup("platform", "start", "boot")
    assert said["ok"] and said["said"] == "LiminalPlatformBoot started" and "http://127.0.0.1:8780/" in said["lines"][0]
    assert a.boots["platform"].state == "running" and a.startup("platform", "end", "boot")["said"] == "LiminalPlatformBoot stopped"
    with pytest.raises(RemovalRefused) as refused:  # asked twice: refused until accepted
        a.unregister("platform", "boot")
    assert refused.value.accept == ACCEPT_REMOVAL and isinstance(refused.value, ValueError) and "a second time" in str(refused.value)
    assert "platform" in a.boots
    gone = a.unregister("platform", "boot", True)
    assert gone["removed"] and gone["said"].startswith("LiminalPlatformBoot removed") and "platform" not in a.boots
    # refused before anything is done: the platform says each as a refusal (a ValueError), the form offered again
    a.register("platform", "boot")  # its own port by default
    assert a.boots["platform"].port == 8775
    for bad in (lambda: a.register("lab", "boot", 8775),  # the platform's boot service's port
                lambda: a.register("lab", "boot", 80), lambda: a.register("lab", "boot", "eighty"),
                lambda: a.register("lab", "boot", 8790.5), lambda: a.register("lab", "boot", True),
                lambda: a.register("charts", "boot", 9000),  # not the platform, nor inheriting it
                lambda: a.startup("lab", "start", "boot"),  # none registered
                lambda: a.startup("platform", "explode", "boot"), lambda: a.unregister("lab", "boot", True),
                lambda: a.register("platform", "sometime")):
        with pytest.raises(BootRefused):
            bad()
    assert issubclass(BootRefused, ValueError) and issubclass(BootRefused, CommandError)
    assert a.register("lab", "boot", "8791").port == 8791  # a number as the page may send it
    # the logon startups as they were
    assert a.register("charts", python=sys.executable).at == "logon" and a.startup("charts", "run") is None and a.unregister("charts")


def test_the_page_section_offers_each_change_as_a_confirmed_form():
    a = FakeBootAdmin()
    st = a.status()
    assert st["valid"] and st["why"] == ""  # not elevated: a fact, each change asking for the rights
    assert [(b["app"], b["state"], b["at"]) for b in st["bootServices"]] == [("platform", "absent", "boot"), ("lab", "absent", "boot")]
    assert [t["title"] for t in st["tables"]] == ["Services the framework relies on", "Startups at your logon",
                                                  "At boot, before anyone signs in", "The framework's processes"]
    table = table_of(st, "At boot, before anyone signs in")
    assert "a stand-in service at boot" in table["note"]
    assert "Unlike the startups at your logon" in table["note"] and "a removal twice" in table["note"]
    assert [c["title"] for c in table["columns"]][:5] == ["App", "Boot service", "State", "Runs as", "Log"]
    forms = {f["id"]: f for f in st["forms"] if f["id"].startswith("boot-")}
    assert set(forms) == {"boot-register:platform", "boot-register:lab"}
    first = table["rows"][0]
    assert first[0] == {"text": "Liminal Platform", "sub": "platform · python -m liminal_platform"} and first[2] == "not registered"
    assert first[1]["sub"].startswith("would run ") and first[5]["form"] == "boot-register:platform" and first[6] == ""
    assert first[4] == {"text": "platform-boot.log", "sub": f"in /stand-in; its own: {LOGS / 'platform.log'}"}
    assert reg_note_of(st, "platform") == "A stand-in service at boot."  # no details: the few words, as a sentence
    reg = forms["boot-register:platform"]
    assert [f["name"] for f in reg["fields"]] == ["app", "at", "port"] and reg["fields"][2]["value"] == 8775
    assert "--port {port}" in reg["confirm"]["words"] and "http://127.0.0.1:{port}/" in reg["confirm"]["words"]
    assert reg["confirm"]["words"].endswith("The stand-in asks you first.")
    a.register("platform", "boot", 8775)
    a.startup("platform", "start", "boot")
    st = a.status()
    assert st["summary"].endswith("; startups: none; at boot: platform (running); 1 Liminal process(es)")
    forms = {f["id"]: f for f in st["forms"] if f["id"].startswith("boot-")}
    assert set(forms) == {"boot-register:platform", "boot-register:lab", "boot-start:platform", "boot-stop:platform", "boot-remove:platform"}
    table = table_of(st, "At boot, before anyone signs in")
    row = table["rows"][0]
    assert row[2] == "running" and row[5]["form"] == "boot-stop:platform" and row[6]["form"] == "boot-remove:platform"
    assert {"form": "boot-register:platform", "title": "Change Liminal Platform's port…"} in table["actions"]
    # each form's fields are its hook's arguments, in order; a removal's second confirmation is its accept field
    for f in forms.values():
        hook = getattr(a, f["hook"])
        assert f["hook"] in a.HOOKS and [x["name"] for x in f["fields"]] == list(inspect.signature(hook).parameters)[:len(f["fields"])]
        assert f["confirm"]["words"] and f["confirm"]["yes"]
    remove = forms["boot-remove:platform"]
    assert remove["confirm"]["danger"] and [x["type"] for x in remove["fields"]] == ["fixed", "fixed", "accept"]
    assert remove["fields"][2]["name"] == ACCEPT_REMOVAL and "for good" in remove["fields"][2]["yes"]
    assert [x["value"] for x in forms["boot-stop:platform"]["fields"]] == ["platform", "stop", "boot"]
    # without the rights and none to ask for, still valid: each change says what it needs
    unasked = FakeBootAdmin(may=False).status()
    assert unasked["valid"] is True and "cannot ask for here" in table_of(unasked, "At boot, before anyone signs in")["note"]
    assert "cannot ask for here" in next(f for f in unasked["forms"] if f["id"] == "service")["confirm"]["words"]


def test_what_else_wants_a_port_is_said_beside_it_and_a_clash_only_when_it_is_the_same():
    from types import SimpleNamespace

    a = FakeBootAdmin()
    a.app = SimpleNamespace(NAME="platform", served="http://127.0.0.1:8775/")  # the platform serving this page, at 8775
    a.register("platform", python="python")  # and its task at your logon, at its own port
    port = next(f for f in a.status()["forms"] if f["id"] == "boot-register:platform")["fields"][2]
    assert port["note"].endswith("; in use: 8775 (the Liminal Platform serving this page), 8775 (LiminalPlatform, at your logon)")
    a.register("platform", "boot", 8781)
    start = next(f for f in a.status()["forms"] if f["id"] == "boot-start:platform")["confirm"]["words"]
    assert "serving this page" not in start and "at your logon" not in start  # another port: nothing in the way
    a.register("platform", "boot", 8775)
    start = next(f for f in a.status()["forms"] if f["id"] == "boot-start:platform")["confirm"]["words"]
    assert "The Liminal Platform serving this page answers at port 8775 now" in start
    assert "LiminalPlatform starts it at your logon at the same port" in start
    with pytest.raises(RemovalRefused, match="Liminal Platform would no longer start at boot"):
        a.unregister("platform", "boot")
    assert a.unregister("platform", "boot", True)["said"] == "LiminalPlatformBoot removed: Liminal Platform no longer starts at boot"


def test_a_registered_boot_service_of_an_app_not_known_is_shown_and_may_be_removed():
    a = FakeBootAdmin()
    a.boots["gone"] = Startup("gone", "LiminalGoneBoot", "stopped", "pythonw -m liminal_gone serve --no-browser --port 8799", "",
                              "boot", "me", "/stand-in/gone-boot.log", 8799)
    st = a.status()
    row = next(r for r in table_of(st, "At boot, before anyone signs in")["rows"] if r[1]["text"] == "LiminalGoneBoot")
    assert row[0] == {"text": "gone", "sub": "gone · not installed here"} and row[6]["form"] == "boot-remove:gone"
    ids = {f["id"] for f in st["forms"]}
    assert "boot-remove:gone" in ids and "boot-register:gone" not in ids  # never registered again: no app to run
    with pytest.raises(BootRefused):
        a.register("lab", "boot", 8799)  # its port is still taken
    assert a.unregister("gone", "boot", accept_removal=True)["removed"]


def test_the_setup_reports_the_boot_services_and_makes_none():
    a = FakeBootAdmin(elevated=True)
    done = a.setup(log=lambda m: None, steps=("startup",))
    assert "nothing starts at boot" in done[0]["detail"] and a.calls == []
    a.register("platform", "boot", 8775)
    assert "at boot: platform (LiminalPlatformBoot: stopped)" in a.setup(log=lambda m: None, steps=("startup",))[0]["detail"]


def test_a_system_that_makes_no_boot_services_says_why_in_the_section():
    class NoInit(FakeBootAdmin):
        def boot_how(self):
            raise BootRefused("this machine's init is neither systemd nor OpenRC: no boot service is made here")

    st = NoInit().status()
    assert st["bootServices"] == [] and not [f for f in st["forms"] if f["id"].startswith("boot-")]
    assert "neither systemd nor OpenRC" in table_of(st, "At boot, before anyone signs in")["empty"]
    with pytest.raises(BootRefused, match="neither systemd"):
        NoInit().register("platform", "boot", 8775)
    plain = FakeAdmin().status()  # a plugin making none: no boot section
    assert "At boot, before anyone signs in" not in [t["title"] for t in plain["tables"]] and plain["bootServices"] == []
