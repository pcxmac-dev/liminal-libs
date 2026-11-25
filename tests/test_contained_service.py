"""1.94.0: `ContainedService`, the base of a service plugin (machines/containedservice.py; service-containers-design
§3.8), and its stand-ins (machines/servicestandins.py). Every rule through a real apps.App on stand-ins alone: a
FakeDocker under a stand-in container plugin, a stand-in firewall and WSL plugin; no process, socket or image (the
no_outside guard). Each gate has a test that fails when the gate is taken out: the declared word (the frame's
AskRefused) and the hook's own check (a Refusal, asked past the frame) apart."""
from __future__ import annotations

import threading
import time

import pytest

from liminal_libs import internal
from liminal_libs.apps import asking
from liminal_libs.apps.asking import AskRefused
from liminal_libs.instances import Refusal
from liminal_libs.machines import containedservice as CS
from liminal_libs.machines import containers as C
from liminal_libs.machines.containedservice import ContainedService, Pace
from liminal_libs.machines.containers import ServiceSpec
from liminal_libs.machines.servicestandins import JobLog, ServiceWorld

import svcworld as W

pytestmark = pytest.mark.usefixtures("no_outside")


class Clock:
    """A monotonic clock a sleep moves on (with a short real sleep: the container plugin's work runs in a thread)."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, s):
        self.now += s
        time.sleep(0.002)


class Svc(ContainedService):
    """A service plugin on the base, its recipe the interface's tests' Jenkins spec."""

    name, title, about, api, order = "jenkins", "Jenkins", "a stand-in service plugin", "2.2", 994

    def __init__(self, lan_first=True, digest=W.DIG):
        self.clock = Clock()
        ContainedService.__init__(self, Pace(clock=self.clock, sleep=self.clock.sleep))
        self.LAN_FIRST = lan_first
        self.digest = digest
        self.up, self.signed_in, self.afters = [True], [True], []

    def present(self) -> bool:
        """Always: a stand-in."""
        return True

    def status(self) -> dict:
        """Its page: the base's tables and forms."""
        return {"present": True, "valid": self.service_valid(), "summary": "", **self.service_status()}

    def spec_for(self, system, name, options):
        ports = list(options.get("ports") or [])
        return ServiceSpec.of(W.spec(name=name, lan=bool(options.get("lan")), host=ports[0] if ports else 8080,
                                     digest=self.digest))

    def ready(self, hosted):
        return (self.up[0], "" if self.up[0] else "it does not answer yet")

    def lan_ready(self, hosted):
        return (self.signed_in[0], "" if self.signed_in[0] else "its sign-in does not answer yet")

    def after(self, action, hosted, line):
        self.afters.append(action)
        return [f"after {action}"]


@pytest.fixture
def svc():
    return Svc()


@pytest.fixture
def world(svc, tmp_path):
    return ServiceWorld(svc, folder=tmp_path)


def installed(world):
    end = world.install("ci", "yes", "no", 2048, 8080)
    assert end["ok"], end
    return end


# -- the words ----------------------------------------------------------------------------------------------------------
def test_its_words_are_sound_and_its_changes_the_pages_alone(svc):
    assert internal.problems(svc) == []
    assert set(internal.page_only(svc)) == {CS.INSTALL, CS.CHANGE, CS.CARRY, CS.LOG, CS.FORGET}
    assert svc.JOB_HOOKS == (CS.CARRY,) and svc.CANCEL_HOOKS == (CS.CARRY,)
    assert set(svc.interface()["hooks"]) >= {CS.HOSTS, CS.INSTALL, CS.CHANGE, CS.CARRY, CS.LOG, CS.FORGET}
    assert svc.KEEPS == (("JENKINS_SERVICES", svc.KEEPS[0][1]),)


@pytest.mark.parametrize("hook, args", [
    (CS.INSTALL, ("standin-host", "wsl-ubuntu")), (CS.CHANGE, ("stop",)), (CS.CARRY, ("standin-host", "p-x")),
    (CS.LOG, ()), (CS.FORGET, ())])
def test_a_plugin_is_refused_its_changes_by_the_frame(world, hook, args):
    with pytest.raises(AskRefused):  # asked by another plugin (the stand-in container plugin), through the app
        world.host.ask_plugin("jenkins", hook, *args)


@pytest.mark.parametrize("hook, args", [
    ("service_install", ("standin-host", "wsl-ubuntu")), ("service_change", ("stop",)),
    ("service_carry", ("standin-host", "p-x")), ("service_log", ()), ("service_forget", ())])
def test_each_change_checks_its_asker_itself_past_the_frame(svc, world, hook, args):
    for who in ("standin-host", None):
        with asking.asking(who), pytest.raises(Refusal, match="from its page alone"):
            getattr(svc, hook)(*args)


# -- where it can run -----------------------------------------------------------------------------------------------------
def _target(world, fresh=True):
    info = world.ask("hosts", fresh)
    row = next(r for r in info["plugins"] if r["plugin"] == "standin-host")
    return row["targets"][0]


def test_hosts_asks_hosting_with_its_spec_and_offers_a_granted_target(world):
    t = _target(world)
    assert t["fit"] is not None and "not let Jenkins" in t["offer"]
    world.grant()
    t = _target(world)
    assert t["offer"] == "" and "jenkins" in t["granted"]
    assert "jenkins" in world.host._svc.askers  # it asked hosting as itself


def test_hosts_is_kept_and_asked_again_when_fresh(world, svc):
    calls = []
    real = world.host.hosting
    world.host.hosting = lambda *a, **k: calls.append(1) or real(*a, **k)
    world.ask("hosts")
    world.ask("hosts")
    assert len(calls) == 1
    world.ask("hosts", True)
    assert len(calls) == 2


def test_a_target_reached_at_another_address_is_not_offered_while_its_token_goes_over_plain_http(svc, tmp_path):
    w = ServiceWorld(svc, folder=tmp_path, reach="172.27.150.3")
    w.grant()
    assert "over plain http to this machine alone" in _target(w)["offer"]
    with pytest.raises(Refusal, match="over plain http"):
        w.ask("service_install", "standin-host", "wsl-ubuntu")
    svc.NEEDS_LOOPBACK = False
    assert _target(w)["offer"] == ""


def test_a_stopped_target_is_not_offered_and_nothing_is_asked_of_its_engine(svc, tmp_path):
    w = ServiceWorld(svc, folder=tmp_path, ready=False)
    w.grant_ok = True
    w.page("standin-host", "grant_service", "jenkins", "wsl-ubuntu")
    assert "stopped" in _target(w)["offer"] and "nothing here starts it" in _target(w)["offer"]
    with pytest.raises(Refusal, match="stopped"):
        w.ask("service_install", "standin-host", "wsl-ubuntu")
    assert w.fake.calls == []


def test_a_container_plugin_known_and_not_attached_is_listed_with_the_platforms_word(world):
    from liminal_libs.machines.standins import StandInHost

    other = StandInHost(name="docker-off")
    world.app.known.append(other)
    world.app.states["docker-off"] = {"state": "disabled", "why": "turned off in the tray", "page": "#docker-off"}
    row = next(r for r in world.ask("hosts", True)["plugins"] if r["plugin"] == "docker-off")
    assert row["state"] == "disabled" and row["why"] == "not active: turned off in the tray" and row["targets"] == []
    with pytest.raises(Refusal, match="turned off in the tray"):
        world.ask("service_install", "docker-off", "wsl-ubuntu")


# -- install, approve, carry ----------------------------------------------------------------------------------------------
def test_install_answers_the_plans_to_approve_and_the_job_that_carries_them_out(world):
    world.grant()
    a = world.ask("service_install", "standin-host", "wsl-ubuntu", "ci", "yes", "no", 2048, 8080)
    assert a["ok"] and a["approve"][0] == {"plugin": "standin-host", "plan": a["plan"]}
    assert [x["plugin"] for x in a["approve"]] == ["standin-host", "standin-firewall"]
    assert a["then"] == {"hook": "service_carry", "args": ["standin-host", a["plan"]], "job": True}
    assert world.fake.changes() == []  # nothing changed before your approval


def test_a_carry_is_refused_before_its_first_line_until_the_plan_is_approved(world):
    world.grant()
    a = world.ask("service_install", "standin-host", "wsl-ubuntu")
    log = JobLog()
    applied = []
    real = world.host.apply_plan
    world.host.apply_plan = lambda p: applied.append(p) or real(p)
    with pytest.raises(Refusal, match="not approved yet: approve it first"):
        world.carry(a, log)
    assert log.lines == [] and world.fake.changes() == [] and applied == []
    end = world.through(a, log)
    assert end["ok"] and any("made, --restart no" in x for x in log.lines)


def test_a_carry_is_refused_for_a_plan_of_another_service(world, svc, monkeypatch):
    world.grant()
    a = world.ask("service_install", "standin-host", "wsl-ubuntu")
    world.approve(a)
    real = world.host.plan_words
    monkeypatch.setattr(world.host, "plan_words", lambda p: {**real(p), "sid": "gocd/ci"})
    with pytest.raises(Refusal, match="not of jenkins's"):
        world.carry(a)


def test_an_install_runs_keeps_its_placement_and_waits_for_its_software(world, svc):
    end = installed(world)
    placed = svc.placement("ci")
    assert placed["state"] == CS.INSTALLED and placed["plugin"] == "standin-host" and placed["target"] == "wsl-ubuntu"
    assert placed["image"] == {"controller": W.DIG} and placed["ports"] == [8080] and placed["lan"] is True
    assert placed["here"] == {"web": "http://127.0.0.1:8080"} and svc.address() == "http://127.0.0.1:8080"
    assert world.host.hosted("jenkins/ci")["state"] == "running"
    assert svc.afters == ["install"] and "after install" in end["lines"]
    assert '"JENKINS_SERVICES"' not in end["said"] and world.login.env["JENKINS_SERVICES"]


def test_a_software_that_does_not_answer_is_said_and_waited_for_no_longer_than_ready_s(world, svc):
    svc.up[0] = False
    end = installed(world)
    assert "does not answer yet" in end["said"] and svc.clock.now >= CS.READY_S


def test_install_twice_is_refused_while_it_is_placed(world):
    installed(world)
    with pytest.raises(Refusal, match="placed already"):
        world.ask("service_install", "standin-host", "wsl-ubuntu")


def test_service_mode_is_provided_for_and_refused(world):
    world.grant()
    with pytest.raises(Refusal, match="not offered yet"):
        world.ask("service_install", "standin-host", "wsl-ubuntu", "ci", "yes", "yes")
    installed(world)
    asked = []
    real = world.host.service_plan
    world.host.service_plan = lambda *a, **k: asked.append(a) or real(*a, **k)
    with pytest.raises(Refusal, match="not offered yet"):
        world.ask("service_change", "boot", "ci", "on")
    assert asked == []  # refused here, before its container plugin is asked anything


def test_an_image_not_pinned_yet_is_refused_before_any_plan(tmp_path):
    s = Svc(digest=CS.UNREAD)
    w = ServiceWorld(s, folder=tmp_path)
    w.grant()
    with pytest.raises(Refusal, match="not pinned by digest yet"):
        w.ask("service_install", "standin-host", "wsl-ubuntu")
    assert w.host._svc.plans.waiting() == []


def test_a_pc_only_service_installs_on_this_pc_alone_and_opens_once_its_sign_in_answers(tmp_path):
    s = Svc(lan_first=False)
    w = ServiceWorld(s, folder=tmp_path)
    w.grant()
    with pytest.raises(Refusal, match="this PC alone first"):
        w.ask("service_install", "standin-host", "wsl-ubuntu", "ci", "yes")
    assert w.install("ci", "no")["ok"]
    assert "-p 127.0.0.1:8080:8080/tcp" in " ".join(w.fake.argv_of("create")[0])
    s.signed_in[0] = False
    with pytest.raises(Refusal, match="its sign-in does not answer yet"):
        w.ask("service_change", "expose", "ci", "on")
    s.signed_in[0] = True
    assert w.through(w.ask("service_change", "expose", "ci", "on"))["ok"]
    assert s.placement("ci")["lan"] is True
    assert "-p 8080:8080/tcp" in " ".join(w.fake.argv_of("create")[-1])


def test_cancel_is_passed_on_once_and_the_work_is_undone(world, svc, monkeypatch):
    world.grant()
    a = world.ask("service_install", "standin-host", "wsl-ubuntu")
    world.approve(a)
    asked, go = [], threading.Event()
    real = world.host.service_cancel

    def cancel(work):
        asked.append(work)
        go.set()
        return real(work)

    monkeypatch.setattr(world.host, "service_cancel", cancel)
    world.fake.before["pull"] = lambda args: go.wait(5)
    log = JobLog()
    log.cancelled = True
    end = world.carry(a, log)
    assert len(asked) == 1 and end["ok"] is False and any("Cancel was passed on" in x for x in log.lines)
    assert svc.placement("ci") is None and "create" not in world.fake.changes()


# -- every other change ---------------------------------------------------------------------------------------------------
def test_stop_start_and_restart_through_its_container_plugin(world, svc):
    installed(world)
    assert world.through(world.ask("service_change", "stop"))["ok"]
    assert world.host.hosted("jenkins/ci")["state"] == "stopped"
    assert world.through(world.ask("service_change", "start"))["ok"]
    assert world.through(world.ask("service_change", "restart"))["ok"]
    assert world.host.hosted("jenkins/ci")["state"] == "running"


def test_an_update_needs_a_newer_pin(world, svc):
    installed(world)
    with pytest.raises(Refusal, match="runs this plugin's pins already"):
        world.ask("service_change", "update")
    svc.digest = "sha256:" + "b" * 64
    assert world.through(world.ask("service_change", "update"))["ok"]
    assert svc.placement("ci")["image"] == {"controller": svc.digest}
    assert world.through(world.ask("service_change", "rollback", "ci", "as-is"))["ok"]
    assert svc.placement("ci")["image"] == {}


def test_remove_keeps_the_data_then_delete_data_forgets_the_placement(world, svc):
    installed(world)
    assert world.through(world.ask("service_change", "remove"))["ok"]
    assert svc.placement("ci")["state"] == CS.REMOVED
    with pytest.raises(Refusal, match="removed and its data kept"):
        world.ask("service_change", "start")
    assert world.through(world.ask("service_change", "delete_data", "ci", "delete"))["ok"]
    assert svc.placement("ci") is None and world.fake.volumes == {}


def test_a_change_of_nothing_placed_and_a_wrong_choice_are_refused(world):
    with pytest.raises(Refusal, match="placed nowhere"):
        world.ask("service_change", "stop")
    installed(world)
    with pytest.raises(Refusal, match="as-is or backup"):
        world.ask("service_change", "rollback", "ci", "maybe")


def test_its_log_is_read_as_its_owner_for_its_page(world):
    installed(world)
    world.fake.logs["liminal-jenkins-ci-controller"] = ["started"]
    assert world.ask("service_log")["lines"] == ["started"]


def test_forget_is_refused_while_its_service_is_there_and_deletes_nothing(world, svc):
    installed(world)
    with pytest.raises(Refusal, match="still there"):
        world.ask("service_forget")
    world.fake.containers.clear()
    world.host.forget_targets()
    said = world.ask("service_forget")
    assert "nothing was deleted" in said["said"] and svc.placement("ci") is None and world.fake.volumes


# -- its end ----------------------------------------------------------------------------------------------------------------
def test_turned_off_it_releases_its_services(world, svc):
    installed(world)
    world.app.off.add("jenkins")
    svc.detach()
    assert world.host.hosted("jenkins/ci")["state"] == "stopped"


def test_a_detach_for_invalidity_asks_nothing(world, svc):
    installed(world)
    asked = []
    real = world.host.release_owned
    world.host.release_owned = lambda: asked.append(1) or real()
    svc.detach()
    assert asked == [] and world.host.hosted("jenkins/ci")["state"] == "running"


# -- its page and the helpers ---------------------------------------------------------------------------------------------
def test_its_page_offers_install_then_its_changes(world, svc):
    page = svc.status()
    first = page["tables"][0]
    assert first["title"] == "Run Jenkins in a container" and page["valid"] is True
    assert {f["id"] for f in page["forms"]} >= {"install", "stop", "expose", "carry", "log", "forget"}
    install = next(f for f in page["forms"] if f["id"] == "install")
    assert [x["name"] for x in install["fields"]] == ["plugin", "target", "name", "lan", "boot", "memory_mb", "port_web"]
    assert [c["value"] for c in install["fields"][4]["choices"]] == ["no"]
    installed(world)
    page = svc.status()
    rows = next(t for t in page["tables"] if t["title"] == "Its services")["rows"]
    assert rows[0][0]["text"] == "jenkins/ci" and rows[0][1]["text"] == "running"
    assert svc.service_present()


def test_loopback_and_hashes():
    assert all(CS.loopback(x) for x in ("127.0.0.1", "127.0.0.1:8080", "http://127.0.0.1:8153/go", "[::1]:80",
                                        "localhost", "::1"))
    assert not any(CS.loopback(x) for x in ("172.27.150.3", "192.168.1.5:8080", "", "localhost.example"))
    h = CS.pbkdf2_hash("correct horse", rounds=1000)
    assert h.startswith("pbkdf2_sha256$1000$") and "correct horse" not in h
    assert CS.pbkdf2_check("correct horse", h) and not CS.pbkdf2_check("wrong", h)
    import base64
    import hashlib

    assert CS.sha1_b64("my-password") == base64.b64encode(hashlib.sha1(b"my-password").digest()).decode()
