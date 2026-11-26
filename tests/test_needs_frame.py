"""The frame's needs (1.103.0; the needs plan's revision 2, 3.6): App.needs_of, machine_facts, needs_report and GET
/api/needs, answered through App.api with no listener (M31), every fact a recorded machine's (conftest's
stand_in_facts: this-pc, or the machine a test names)."""
from __future__ import annotations

import pytest

from liminal_libs import facts, needs, needs_machines
from liminal_libs.apps import App, EnvironmentLogin, Refused
from liminal_libs.machines.plugin import MachinePlugin

pytestmark = pytest.mark.usefixtures("no_outside")


class HyperV(MachinePlugin):
    name, title = "hyperv", "Hyper-V"
    ICON = "server"
    SECTION = "virtualization"
    NEEDS = (("kernel", "windows", "required", "Hyper-V is Windows' own"),
             ("windows.feature", "Microsoft-Hyper-V", "required", "an edition whose Windows Features list Hyper-V"),
             ("virtualization", "slat", "required", "second level address translation"),
             ("memory", ">= 4 GiB", "required", "Microsoft: at least 4 GB"))

    def __init__(self, **kw):
        super().__init__(**kw)
        self.statuses = 0
        self.asked_here = 0

    def status(self):
        self.statuses += 1
        return {"present": True, "valid": True}

    def not_for_here(self):
        self.asked_here += 1
        return ""


class LinuxOnly(MachinePlugin):
    name, title = "linux-only", "Linux only"

    def not_for_here(self):
        return "this is Windows: a Linux plugin"


class Silent(MachinePlugin):
    name, title = "silent", "Silent"


class Knowing(App):
    """An app that knows plugins it has not attached, as the platform does."""

    NAME, TITLE, ICON = "knowing", "Knowing", "chip"

    def __init__(self, known=(), **kw):
        super().__init__(**kw)
        self._known = list(known)

    def known_plugins(self) -> list:
        return [*super().known_plugins(), *[p for p in self._known if p.app is None]]


def made(*known) -> Knowing:
    return Knowing(known, log=lambda m: None, login=EnvironmentLogin(env={}))


def test_needs_of_a_plugin_not_attached_asks_nothing_but_not_for_here_m24():
    hv = HyperV()
    app = made(hv)
    answer = app.needs_of("hyperv")
    assert answer["met"] is True and answer["declared"] is True and hv.app is None
    assert hv.statuses == 0 and hv.asked_here == 1
    assert [r["state"] for r in answer["rows"]] == ["met", "met", "met", "met"]
    with pytest.raises(LookupError):
        app.needs_of("nobody")


def test_needs_of_against_another_recorded_machine():
    app = made(HyperV(), LinuxOnly())
    before = facts.use(needs_machines.reader("windows-11-home"))
    try:
        answer = app.needs_of("hyperv")
        assert answer["met"] is False and answer["sort"] == "machine" and "Windows 11 Home" in answer["why"]
        facts.use(needs_machines.reader("wsl-ubuntu-24.04"))
        assert app.needs_of("hyperv")["sort"] == "machine"
    finally:
        facts.use(before)
    linux = app.needs_of("linux-only")
    assert linux["met"] is False and linux["declared"] is False and "a Linux plugin" in linux["why"]


def test_get_api_needs_through_the_frames_api_m31():
    hv, silent = HyperV(), Silent()
    app = made(hv)
    app.attach(silent)
    status, data = app.api(None, "GET", "/api/needs", {}, None)[:2]
    assert status == 200 and data["v"] == 1 and data["held"] is False and data["switch"] is False
    assert data["internet"] == {"rule": "system", "by": "Windows' own judgement (NCSI)", "switch": False,
                                "offline": None}
    rows = {p["name"]: p for p in data["plugins"]}
    assert set(rows) == {"hyperv", "silent"} and rows["silent"]["state"] == "attached" and rows["hyperv"]["state"] == ""
    assert rows["silent"]["needs"]["why"] == needs.NOT_SAID and rows["silent"]["needs"]["met"] is None
    assert rows["hyperv"]["section"] == "virtualization" and rows["hyperv"]["icon"] == "server"
    assert data["facts"]["system"] == "windows" and hv.statuses == 0
    one = app.api(None, "GET", "/api/needs", {"plugin": "hyperv"}, None)[1]
    assert [p["name"] for p in one["plugins"]] == ["hyperv"]
    with pytest.raises(Refused) as e:
        app.api(None, "GET", "/api/needs", {"plugin": "nobody"}, None)
    assert e.value.status == 404


def test_fresh_reads_again_and_the_frame_judges_offline_none():
    reads = []

    class Counting(facts.StandIn):
        def read(self, attributes=None, fresh=False, *, names=None):
            reads.append((fresh, sorted(attributes or ()), names))
            return super().read(attributes, fresh, names=names)

    app = made(HyperV())
    before = facts.use(Counting(needs_machines.facts_of("this-pc")))
    try:
        app.api(None, "GET", "/api/needs", {"fresh": "1"}, None)
        app.api(None, "GET", "/api/needs", {}, None)
    finally:
        facts.use(before)
    assert [r[0] for r in reads] == [True, False]
    assert "windows.feature" in reads[0][1] and reads[0][2]["windows.feature"] == ["Microsoft-Hyper-V"]
    assert app.offline() is None and app.internet_rule() == "system"


def test_the_platform_core_leaves_an_unmet_plugin_detached():
    from liminal_libs.apps.platform import Platform

    app = type("P", (Platform,), {"NAME": "p"})(log=lambda m: None, login=EnvironmentLogin(env={}))
    before = facts.use(needs_machines.reader("wsl-ubuntu-24.04"))
    try:
        assert app._unmet_here(HyperV()) is True and app._unmet_here(Silent()) is False
    finally:
        facts.use(before)


def test_the_internal_api_says_the_rows_as_declared_and_never_judges_them_s6():
    import ast
    import inspect

    from liminal_libs import internal

    assert internal.internal_of(HyperV())["needs"][0] == ["kernel", "windows", "required", "Hyper-V is Windows' own"]
    assert internal.internal_of(Silent())["needs"] is None
    assert internal.internal_of(type("N", (MachinePlugin,), {"name": "n", "NEEDS": ()})())["needs"] == []
    tree = ast.parse(inspect.getsource(internal))
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    assert "needs" not in imported and "facts" not in imported
    app = made(HyperV())
    said = internal.app_internal(app)["needs"]
    assert said["route"] == "/api/needs" and [r[0] for r in said["reads"]] == [r[0] for r in facts.READS]
    assert ("GET", "/api/needs") in {r[:2] for r in internal.FRAME_ROUTES}
    assert {"needs_of", "machine_facts", "needs_report"} <= set(internal.OFFERS)


def test_the_internal_tabs_fold_of_what_it_needs():
    from liminal_libs.ui import STATIC

    js = (STATIC / "internal.js").read_text(encoding="utf-8")
    body = js[js.index("  function needsHtml("):js.index("  function howHtml(")]
    assert "'What it needs of this machine'" in body and "It has not said what it needs yet." in body
    assert "It needs nothing of this machine." in body
    assert "j.strength === 'required' && j.state === 'unmet'" in body and "rows.map(rowHtml).join(''), unmet)" in body
    assert "if (d.needs === undefined) return '';" in body  # a server from before: no fold
