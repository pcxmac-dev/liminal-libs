"""1.93.0: the one "run a service" interface (machines/containers.py, plans.py, containerhost.py, dockerruntime.py,
standins.py; service-containers-design §3 and the user's answers of 2026-11-23 and 2026-11-25).

Every rule of the base is tested here through a real apps.App, so the asker's gates are the real ones, on stand-ins
alone: a FakeDocker answers every docker command from memory; no process is started, no image pulled, no port opened,
WSL never run (no_outside fails a test that reaches any). A race is tested by forcing its order with a barrier inside
a stand-in. Each gate has a test that fails when the gate is taken out: the declared word (the frame's AskRefused) and
the hook's own check (a Refusal, asked past the frame) are tested apart."""
from __future__ import annotations

import json
import threading

import pytest

from liminal_libs import internal
from liminal_libs.apps import asking
from liminal_libs.apps.asking import AskRefused
from liminal_libs.instances import Refusal
from liminal_libs.machines import containers as C
from liminal_libs.machines import plans as P
from liminal_libs.machines import standins
from liminal_libs.machines.containers import ServiceSpec

import svcworld as W

pytestmark = pytest.mark.usefixtures("no_outside", "stand_in_environment")


@pytest.fixture
def world(tmp_path):
    return W.World(folder=tmp_path)


def _sound():
    return ServiceSpec.of(W.spec())


# -- the spec -----------------------------------------------------------------------------------------------------------
def test_a_sound_spec_round_trips_with_a_stable_sha():
    s = _sound()
    assert s.problems() == []
    again = ServiceSpec.of(json.loads(json.dumps(s.as_dict())))
    assert again == s and again.sha() == s.sha() and len(s.sha()) == 64
    assert s.sid == "jenkins/ci" and s.parts[0].image.pinned.endswith("@" + W.DIG)


@pytest.mark.parametrize("change, words", [
    (lambda d: d["parts"][0]["image"].update(digest=""), "a tag alone is refused"),
    (lambda d: d["parts"][0]["image"].update(ref="docker.io/jenkins/jenkins@" + W.DIG), "without its digest"),
    (lambda d: d["parts"][0].update(privileged=True), "no field privileged"),
    (lambda d: d["parts"][0].update(volumes=[{"name": "sock", "path": "/var/run/docker.sock", "holds": "x",
                                              "host": "/var/run/docker.sock"}]), "no field host"),
    (lambda d: d["parts"][0].update(memory=0), "memory limit"),
    (lambda d: d["parts"][0].update(memory=100 << 20), "memory limit"),
    (lambda d: d["parts"][0]["ports"][0].update(host=80), "outside 1024 to 65535"),
    (lambda d: d["parts"][0]["ports"].append(dict(d["parts"][0]["ports"][0], name="again")), "twice"),
    (lambda d: d["parts"][0].update(secrets=[{"variable": "GOCD_ADMIN_PASSWORD", "env": "X"}]), "not under jenkins"),
    (lambda d: d["parts"][0].update(secrets=[{"variable": "LIMINAL_KEY", "env": "X"}]), "not under jenkins"),
    (lambda d: d["parts"][0]["env"].update(LIMINAL_PLATFORM_DIR="x"), "Liminal's own variables"),
    (lambda d: d["parts"][0].update(seeds=[{"volume": "home", "path": "../etc/passwd", "text": "x"}]), "no '..'"),
    (lambda d: d["parts"][0].update(seeds=[{"volume": "home", "path": "a", "text": "x" * (65 << 10)}]), "64 KB"),
    (lambda d: d.update(title="Jen\x07kins"), "control character"),
    (lambda d: d.update(system="windows"), "linux image"),
    (lambda d: d["parts"][0].update(image={"steps": "RUN x"}), "says `build` (a BuildPin)"),  # 1.97.0's words
    (lambda d: d["parts"][0]["health"].update(port="nope"), "does not publish"),
    (lambda d: d.update(parts=d["parts"] * 9), "8 parts at most"),
    (lambda d: d.update(owner="Jenkins"), "lowercase"),
])
def test_every_refusal_of_a_spec_is_in_words(change, words):
    d = W.spec()
    change(d)
    with pytest.raises(Refusal) as e:
        ServiceSpec.of(d)
    assert words in str(e.value)


def test_the_names_made_from_a_sid():
    assert C.container_name("jenkins/ci", "controller") == "liminal-jenkins-ci-controller"
    assert C.previous_name("jenkins/ci", "controller").endswith("-previous")
    assert C.volume_name("jenkins/ci", "home") == "liminal-jenkins-ci-home"
    assert C.rule_name("jenkins/ci") == "svc-jenkins-ci"
    with pytest.raises(Refusal):
        C.split_sid("jenkins")


# -- plans --------------------------------------------------------------------------------------------------------------
def _plans():
    now = [0.0]
    return P.Plans(clock=lambda: now[0]), now


def _held(ps, **kw):
    base = dict(owner="jenkins", action="install", subject="jenkins/ci", target="t", title="Install", words="w",
                facts={"a": 1}, accepts=[P.Accept("accept_lan", "Lan?", "its ports")])
    base.update(kw)
    return ps.hold(**base)


def test_an_approval_takes_each_accept_exactly_true_and_is_used_once():
    ps, _ = _plans()
    p = _held(ps)
    for not_true in ("true", 1, "yes", None, False):
        with pytest.raises(Refusal) as e:
            ps.approve(p.plan, {"accept_lan": not_true})
        assert e.value.accept == "accept_lan"
    ps.approve(p.plan, {"accept_lan": True})
    with pytest.raises(Refusal, match="approved already"):
        ps.approve(p.plan, {"accept_lan": True})
    assert ps.take(p.plan, "jenkins", {"a": 1}).used
    with pytest.raises(Refusal, match="no plan"):
        ps.take(p.plan, "jenkins", {"a": 1})


def test_a_plan_is_taken_by_its_owner_alone_once_approved_and_only_on_the_same_facts():
    ps, now = _plans()
    p = _held(ps, accepts=[])
    with pytest.raises(Refusal, match="not approved"):
        ps.take(p.plan, "jenkins", {"a": 1})
    ps.approve(p.plan, {})
    with pytest.raises(Refusal, match="jenkins's"):
        ps.take(p.plan, "gocd", {"a": 1})
    with pytest.raises(Refusal, match="not what is there now"):
        ps.take(p.plan, "jenkins", {"a": 2})
    with pytest.raises(Refusal, match="no plan"):  # dropped once its facts differed
        ps.take(p.plan, "jenkins", {"a": 1})
    q = _held(ps)
    now[0] = P.PLAN_S + 1
    with pytest.raises(Refusal, match="no plan"):
        ps.get(q.plan)


def test_plans_held_are_capped():
    ps, _ = _plans()
    for _ in range(P.MAX_PLANS):
        _held(ps)
    with pytest.raises(Refusal, match="wait for an answer"):
        _held(ps)


# -- who asks: the declared words (the frame's gate) and each hook's own check ----------------------------------------
def test_the_bases_declare_their_gates_and_are_sound():
    h, f = standins.StandInHost(), standins.StandInNetworkHost()
    assert internal.problems(h) == [] and internal.problems(f) == []
    assert set(internal.page_only(h)) == {C.APPROVE, C.GRANT, C.REVOKE, C.FORGET_VOLUME}
    # 1.97.0: the stand-in opts into hosted_run; the base itself declares it nowhere (a plugin opts in)
    assert set(internal.plugin_only(h)) == {C.WORK, C.PLAN, C.APPLY, C.HOSTED_FILE, C.RELEASE, C.HOSTED_RUN}
    assert C.HOSTED_RUN not in standins.ContainerHost.HOOKS + standins.ContainerHost.PLUGIN_ONLY_HOOKS
    assert {"approve_plan", "grant_network", "set_domain"} <= set(internal.page_only(f))
    assert {"network_plan", "apply_network", "network_work"} <= set(internal.plugin_only(f))
    assert set(h.interface()["hooks"]) >= set(C.__dict__[k] for k in ("HOSTING", "PLAN", "APPROVE", "APPLY"))


def test_approve_plan_is_refused_to_a_plugin_by_the_frame(world):
    world.grant()
    plan = world.plan()
    with pytest.raises(AskRefused):
        world.jenkins.call("approve_plan", plan["plan"], True, True, True, False, True, True)


def test_approve_plan_checks_its_asker_itself_past_the_frame(world):
    world.grant()
    plan = world.plan()
    for who in ("jenkins", None):
        with asking.asking(who), pytest.raises(Refusal, match="from its page alone"):
            world.host.approve_plan(plan["plan"], accept_lan=True)


def test_grants_are_the_pages_alone(world):
    with pytest.raises(AskRefused):
        world.jenkins.call("grant_service", "jenkins", "wsl-ubuntu")
    with asking.asking("jenkins"), pytest.raises(Refusal, match="from its page alone"):
        world.host.grant_service("jenkins", "wsl-ubuntu")
    assert world.host.grants() == {}


def test_a_plan_is_asked_by_its_owner_alone(world):
    world.grant()
    with pytest.raises(AskRefused):  # the page: the frame refuses a PLUGIN_ONLY hook
        world.page("standin-host", "service_plan", "install", "jenkins/ci", W.spec(), "wsl-ubuntu", {})
    with pytest.raises(Refusal, match="jenkins alone, not by gocd"):
        world.gocd.call("service_plan", "install", "jenkins/ci", W.spec(), "wsl-ubuntu", {})
    with pytest.raises(Refusal, match="spec is gocd/ci's"):
        world.jenkins.call("service_plan", "install", "jenkins/ci", W.spec(owner="gocd"), "wsl-ubuntu", {})
    with asking.asking(None), pytest.raises(Refusal, match="names no asker"):
        world.host.service_plan("install", "jenkins/ci", W.spec(), "wsl-ubuntu", {})
    with asking.asking(asking.PAGE), pytest.raises(Refusal, match="never from a page"):
        world.host.service_plan("install", "jenkins/ci", W.spec(), "wsl-ubuntu", {})


def test_apply_and_work_are_the_owners_alone(world):
    world.grant()
    plan = world.plan()
    world.approve_all(plan)
    with pytest.raises(AskRefused):
        world.page("standin-host", "apply_plan", plan["plan"])
    with pytest.raises(Refusal, match="jenkins alone"):
        world.gocd.call("apply_plan", plan["plan"])
    work = world.jenkins.call("apply_plan", plan["plan"])["work"]
    world.wait(work)
    with pytest.raises(Refusal, match="jenkins alone"):
        world.gocd.call("service_work", work, 0)


def test_logs_plan_words_decline_and_cancel_are_the_page_or_the_owner(world):
    world.installed()
    world.fake.logs["liminal-jenkins-ci-controller"] = ["2026-11-25T10:00:00Z started"]
    assert world.page("standin-host", "hosted_logs", "jenkins/ci")["lines"]
    assert world.jenkins.call("hosted_logs", "jenkins/ci")["lines"]
    with pytest.raises(Refusal, match="from its page or by jenkins"):
        world.gocd.call("hosted_logs", "jenkins/ci")
    plan = world.plan("stop")
    with pytest.raises(Refusal, match="from its page or by jenkins"):
        world.gocd.call("plan_words", plan["plan"])
    with pytest.raises(Refusal, match="from its page or by jenkins"):
        world.gocd.call("decline_plan", plan["plan"])
    assert world.page("standin-host", "decline_plan", plan["plan"])["ok"]


# -- grants, targets, the engine off -------------------------------------------------------------------------------------
def test_a_plan_without_the_grant_is_refused_and_stop_letting_it_leaves_its_service(world):
    with pytest.raises(Refusal, match="may not plan on wsl-ubuntu"):
        world.plan()
    world.installed()
    world.page("standin-host", "revoke_service", "jenkins", "wsl-ubuntu")
    assert world.jenkins.call("hosted", "jenkins/ci")["state"] == "running"
    with pytest.raises(Refusal, match="may not plan"):
        world.plan("stop")


def test_an_engine_that_is_off_is_never_started_and_never_asked(tmp_path):
    w = W.World(ready=False, folder=tmp_path)
    w.grant_ok = True
    w.page("standin-host", "grant_service", "jenkins", "wsl-ubuntu")
    w.page("standin-firewall", "grant_network", "standin-host")
    with pytest.raises(Refusal, match="Nothing here starts it"):
        w.plan()
    assert w.fake.calls == []


def test_service_mode_is_provided_for_and_not_offered(world):
    world.installed()
    with pytest.raises(Refusal, match="not offered yet"):
        world.plan("boot")
    assert not C.SERVICE_MODE_OFFERED and "service" in C.LIFECYCLES


def test_no_firewall_refuses_the_plan(tmp_path):
    w = W.World(firewall=False, folder=tmp_path)
    w.page("standin-host", "grant_service", "jenkins", "wsl-ubuntu")
    with pytest.raises(Refusal, match="no firewall plugin routes and names wsl"):
        w.plan()


# -- the install, exactly -------------------------------------------------------------------------------------------------
def test_an_install_makes_exactly_what_its_plan_said(world):
    end = world.installed()
    assert end["answer"]["here"] == {"web": "http://127.0.0.1:8080"}
    create = world.fake.argv_of("create")[0]
    line = " ".join(create)
    assert "--restart no" in line and "on-failure" not in line and "unless-stopped" not in line
    assert "-p 8080:8080/tcp" in line  # every address: no address before the port
    assert f"--memory {2 << 30}" in line and "-v liminal-jenkins-ci-home:/var/jenkins_home" in line
    assert "--label liminal=service" in line and "--label liminal.service=jenkins/ci" in line
    assert "--network liminal-jenkins-ci" in line and "--ip 10.77.1.10" in line
    assert "--network-alias controller.jenkins-ci.home.arpa" in line
    assert create[-1].endswith("@" + W.DIG)
    net = " ".join(world.fake.argv_of("network create")[0])
    assert "--subnet 10.77.1.0/24" in net and "trusted_host_interfaces=eth0" in net and "lim-" in net
    assert len(world.fake.networks["liminal-jenkins-ci"]["options"]["com.docker.network.bridge.name"]) <= 15
    assert world.firewall.elevations == 1 and world.firewall.ran[0][0]["kind"] == "route"
    assert world.wsl.asked == [("hold", "Liminal-Ubuntu")]
    for never in ("--privileged", "--cap-add", "--network host", "docker.sock", "nat-unprotected", "docker0"):
        assert all(never not in " ".join(c["argv"]) for c in world.fake.calls)


def test_a_port_kept_on_this_machine_binds_loopback_alone(world):
    world.grant()
    end = world.carry("install", spec_=W.spec(lan=False))
    assert end["ok"]
    assert "-p 127.0.0.1:8080:8080/tcp" in " ".join(world.fake.argv_of("create")[0])


def test_publishing_to_your_network_asks_accept_lan(world):
    world.grant()
    plan = world.plan()
    words = world.page("standin-host", "plan_words", plan["plan"])
    assert "accept_lan" in [a["name"] for a in words["accepts"]]
    with pytest.raises(Refusal) as e:
        world.page("standin-host", "approve_plan", plan["plan"])
    assert e.value.accept == "accept_lan"


def test_apply_refuses_before_any_change_while_the_firewalls_plan_waits(world):
    world.grant()
    plan = world.plan()
    world.page("standin-host", "approve_plan", plan["plan"], True)  # the container plugin's alone
    before = len(world.fake.changes())
    with pytest.raises(Refusal, match="its network is not approved"):
        world.jenkins.call("apply_plan", plan["plan"])
    assert len(world.fake.changes()) == before == 0


def test_apply_refuses_when_the_facts_changed_since_the_approval(world):
    world.grant()
    plan = world.plan()
    world.approve_all(plan)
    world.fake.volumes["liminal-jenkins-ci-home"] = {"labels": {"liminal": "volume", "liminal.service": "jenkins/ci"},
                                                     "files": {}}
    with pytest.raises(Refusal, match="not what is there now"):
        world.jenkins.call("apply_plan", plan["plan"])
    assert world.fake.changes() == []


# -- secrets, with a canary value -----------------------------------------------------------------------------------------
def test_a_secret_travels_by_environment_alone_and_is_masked_everywhere(world):
    world.grant()
    s = W.spec(secrets=[{"variable": "JENKINS_ADMIN_PASSWORD", "env": "ADMIN_PASSWORD"}])
    plan = world.plan(spec_=s)
    words = world.page("standin-host", "plan_words", plan["plan"])
    assert "accept_kept_secret" in [a["name"] for a in words["accepts"]]
    world.approve_all(plan)
    work = world.jenkins.call("apply_plan", plan["plan"])["work"]
    end = world.wait(work)
    assert end["ok"], end
    create = next(c for c in world.fake.calls if c["key"] == "create")
    assert "ADMIN_PASSWORD" in create["argv"] and W.SECRET not in " ".join(create["argv"])
    assert create["env"]["ADMIN_PASSWORD"] == W.SECRET and create["env"]["WSLENV"] == "ADMIN_PASSWORD/u"
    container = world.fake.containers["liminal-jenkins-ci-controller"]
    assert W.SECRET not in json.dumps(container["labels"])
    world.fake.logs["liminal-jenkins-ci-controller"] = [f"2026-11-25T10:00:00Z the password is {W.SECRET}"]
    logs = world.jenkins.call("hosted_logs", "jenkins/ci")
    said = json.dumps([plan, words, end, logs, world.jenkins.call("hosted", "jenkins/ci"),
                       world.page("standin-host", "status")])
    assert W.SECRET not in said and "<hidden>" in json.dumps(logs)
    others = [c for c in world.fake.calls if c["key"] != "create"]
    assert all(W.SECRET not in json.dumps({"argv": c["argv"], "env": c["env"]}) for c in others)


def test_a_secret_unset_another_plugins_or_held_in_a_setting_is_refused(world):
    world.grant()
    with pytest.raises(Refusal, match="not set"):
        world.plan(spec_=W.spec(secrets=[{"variable": "JENKINS_TOKEN", "env": "T"}]))
    with pytest.raises(Refusal, match="holds a secret's value"):
        world.plan(spec_=W.spec(secrets=[{"variable": "JENKINS_ADMIN_PASSWORD", "env": "P"}],
                                env={"OPTS": f"-Dpw={W.SECRET}"}))
    with pytest.raises(Refusal, match="seed a hash"):
        world.plan(spec_=W.spec(secrets=[{"variable": "JENKINS_ADMIN_PASSWORD", "env": "P"}],
                                seeds=[{"volume": "home", "path": "p.txt", "text": W.SECRET}]))
    from liminal_libs.sources.keys import KeyVar

    world.gocd.keys = (KeyVar("JENKINS_SHARED_KEY"),)
    world.login.env["JENKINS_SHARED_KEY"] = "abcd-value"
    with pytest.raises(Refusal, match="gocd's pair"):
        world.plan(spec_=W.spec(secrets=[{"variable": "JENKINS_SHARED_KEY", "env": "K"}]))


# -- ports ----------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("port, words", [(8775, "Liminal's platform page"), (9775, "Linux suite's pages")])
def test_the_apps_pages_are_never_a_services(world, port, words):
    world.grant()
    with pytest.raises(Refusal, match=words):
        world.plan(spec_=W.spec(host=port))


def test_another_services_a_model_servers_a_programs_and_windows_reserved_ports_are_refused(world, tmp_path):
    world.installed()
    with pytest.raises(Refusal, match="the service jenkins/ci"):
        world.plan(sid="gocd/ci", spec_=W.spec(owner="gocd"), who=world.gocd) if world.host.granted("gocd", "x") else \
            (world.page("standin-host", "grant_service", "gocd", "wsl-ubuntu"),
             world.plan(sid="gocd/ci", spec_=W.spec(owner="gocd"), who=world.gocd))
    world.holders[8090] = ["java.exe (pid 4242), reachable from every address"]
    with pytest.raises(Refusal, match="held here by java.exe"):
        world.plan(sid="gocd/ci", spec_=W.spec(owner="gocd", host=8090), who=world.gocd)
    world.host.excluded_ranges = lambda: [(49900, 50099)]
    with pytest.raises(Refusal, match="Windows keeps for Hyper-V and WSL"):
        world.plan(sid="gocd/ci", spec_=W.spec(owner="gocd", host=50000), who=world.gocd)

    from liminal_libs.machines.plugin import MachinePlugin

    class Models(MachinePlugin):
        name, title, about, api, order = "ollama", "Ollama", "a stand-in model server", "2.2", 995
        HOOKS = (*MachinePlugin.HOOKS, "serving")

        def serving(self, name=""):
            return {"plugin": "ollama", "title": "Ollama", "instances": [{"name": "main", "port": 11434, "local": True}]}
    world.app.attach(Models())
    with pytest.raises(Refusal, match="Ollama's model server"):
        world.plan(sid="gocd/ci", spec_=W.spec(owner="gocd", host=11434), who=world.gocd)


# -- the data ---------------------------------------------------------------------------------------------------------------
def test_remove_keeps_the_data_and_install_again_finds_it_unseeded(world):
    world.grant()
    seeded = W.spec(seeds=[{"volume": "home", "path": "config.xml", "text": "<config/>", "mode": 0o640}])
    assert world.carry("install", spec_=seeded)["ok"]
    files = world.fake.volumes["liminal-jenkins-ci-home"]["files"]
    assert files == {"config.xml": b"<config/>"}
    assert world.fake.volumes["liminal-jenkins-ci-home"]["owners"]["config.xml"][0] == 1000
    assert world.carry("remove")["ok"]
    assert "liminal-jenkins-ci-home" in world.fake.volumes
    assert not world.fake.argv_of("volume rm") and all("-v" not in a[2:] for a in world.fake.argv_of("rm"))
    plan = world.plan(spec_=seeded)
    assert "from before" in plan["words"]
    world.approve_all(plan)
    end = world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])
    assert end["ok"] and len([c for c in world.fake.calls if c["key"] == "cp" and c["stdin"]]) == 1


def test_delete_data_asks_accept_data_always_and_refuses_while_containers_use_it(world):
    world.installed()
    with pytest.raises(Refusal, match="plan its Remove first"):
        world.plan("delete_data")
    world.carry("remove")
    plan = world.plan("delete_data", options={"backups": "keep"})
    assert plan["danger"] and "accept_data" in [a["name"] for a in plan["accepts"]]
    with pytest.raises(Refusal) as e:
        world.page("standin-host", "approve_plan", plan["plan"])
    assert e.value.accept == "accept_data"
    world.approve_all(plan)
    assert world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])["ok"]
    assert "liminal-jenkins-ci-home" not in world.fake.volumes


def test_forget_volume_is_asked_twice_and_never_while_used(world):
    world.installed()
    with pytest.raises(Refusal, match="is used by"):
        world.page("standin-host", "forget_volume", "wsl-ubuntu", "liminal-jenkins-ci-home", True)
    world.carry("remove")
    with pytest.raises(Refusal) as e:
        world.page("standin-host", "forget_volume", "wsl-ubuntu", "liminal-jenkins-ci-home")
    assert e.value.accept == "accept_data"
    with asking.asking("jenkins"), pytest.raises(Refusal, match="from its page alone"):
        world.host.forget_volume("wsl-ubuntu", "liminal-jenkins-ci-home", True)
    assert world.page("standin-host", "forget_volume", "wsl-ubuntu", "liminal-jenkins-ci-home", True)["ok"]


def test_an_update_backs_up_before_it_stops_and_keeps_the_previous(world, tmp_path):
    world.installed()
    world.fake.volumes["liminal-jenkins-ci-home"]["files"]["jobs.xml"] = b"<jobs/>"
    end = world.carry("update", spec_=W.newer())
    assert end["ok"], end
    keys = [c["key"] for c in world.fake.calls]
    first_run = keys.index("run")
    assert first_run < keys.index("stop") and keys.index("pull", first_run) > first_run
    backups = list((tmp_path / "containers" / "backups" / "jenkins-ci").rglob("home.tar"))
    assert len(backups) == 1 and backups[0].stat().st_size > 0
    assert "liminal-jenkins-ci-controller-previous" in world.fake.containers
    assert world.fake.containers["liminal-jenkins-ci-controller"]["image"].endswith("b" * 64)


def test_an_unhealthy_update_is_undone_in_order(world):
    world.installed()
    world.fake.exits_on_start["liminal-jenkins-ci-controller"] = 1
    end = world.carry("update", spec_=W.newer())
    assert end["ok"] is False
    lines = " ".join(end["lines"])
    assert "undone: the new liminal-jenkins-ci-controller removed" in lines
    assert "named back liminal-jenkins-ci-controller and started" in lines and "its backup is" in lines
    c = world.fake.containers["liminal-jenkins-ci-controller"]
    assert c["image"].endswith(W.DIG) and "liminal-jenkins-ci-controller-previous" not in world.fake.containers


def test_an_image_without_tar_asks_accept_no_backup(world):
    world.installed()
    plan = world.plan("update", spec_=W.newer(W.spec(tar=False)))
    assert "accept_no_backup" in [a["name"] for a in plan["accepts"]]


def test_a_failure_mid_install_removes_what_it_made_and_keeps_the_volume(world):
    world.grant()
    world.fake.fail["start"] = "port is already allocated"
    end = world.carry("install")
    assert end["ok"] is False
    assert "liminal-jenkins-ci-controller" not in world.fake.containers
    assert "liminal-jenkins-ci-home" in world.fake.volumes and world.fake.images
    assert any("undone" in line for line in end["lines"])


def test_a_digest_that_differs_after_the_pull_fails_the_install(world):
    world.grant()
    pinned = W.spec()["parts"][0]["image"]
    world.fake.pulled_as[f"{pinned['ref']}@{pinned['digest']}"] = "sha256:" + "c" * 64
    end = world.carry("install")
    assert end["ok"] is False and "not its pinned" in end["answer"]["said"]


def test_rollback_with_the_backup_asks_accept_data(world):
    world.installed()
    world.carry("update", spec_=W.newer())
    plan = world.plan("rollback", options={"choice": "backup"})
    assert "accept_data" in [a["name"] for a in plan["accepts"]] and plan["danger"]
    world.approve_all(plan)
    assert world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])["ok"]
    assert world.fake.containers["liminal-jenkins-ci-controller"]["image"].endswith(W.DIG)


# -- works: cancel, races, the plugin's end ------------------------------------------------------------------------------
def test_a_cancel_lands_inside_a_pull_and_undoes_nothing_it_did_not_make(world):
    world.grant()
    plan = world.plan()
    world.approve_all(plan)
    inside, go = threading.Event(), threading.Event()

    def held(args):
        inside.set()
        go.wait(10)
    world.fake.before["pull"] = held
    work = world.jenkins.call("apply_plan", plan["plan"])["work"]
    assert inside.wait(10)
    world.jenkins.call("service_cancel", work)
    go.set()
    end = world.wait(work)
    assert end["ok"] is False and end["answer"]["said"] == "cancelled"
    assert world.fake.containers == {} and world.fake.changes() == ["pull"]


def test_two_applies_on_one_target_are_one_at_a_time_by_their_order(world):
    world.installed()
    world.carry("stop")
    first, second = world.plan("start"), world.plan("restart")
    world.approve_all(first)
    world.approve_all(second)
    inside, go = threading.Event(), threading.Event()

    def held(args):
        inside.set()
        go.wait(10)
    world.fake.before["start"] = held
    work = world.jenkins.call("apply_plan", first["plan"])["work"]
    assert inside.wait(10)
    with pytest.raises(Refusal, match="one change at a time"):
        world.jenkins.call("apply_plan", second["plan"])
    go.set()
    assert world.wait(work)["ok"]


def test_one_plan_applied_twice_at_once_is_carried_out_once(world):
    world.grant()
    plan = world.plan()
    world.approve_all(plan)
    barrier = threading.Barrier(2, timeout=10)
    answers: list = []
    original = world.firewall.plan_words

    def words(plan_id):
        barrier.wait()  # both asks are inside apply, past its first checks, before either holds the target
        return original(plan_id)
    world.firewall.plan_words = words

    def ask():
        try:
            answers.append(world.jenkins.call("apply_plan", plan["plan"]))
        except Refusal as e:
            answers.append(e)
    ts = [threading.Thread(target=ask) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(15)
    works = [a for a in answers if isinstance(a, dict)]
    refused = [str(a) for a in answers if isinstance(a, Refusal)]
    assert len(works) == 1 and len(refused) == 1, answers
    assert "one change at a time" in refused[0] or "no plan" in refused[0]
    world.wait(works[0]["work"])
    assert len(world.fake.argv_of("create")) == 1


def test_turning_it_off_cancels_and_joins_works_and_stops_page_services(world):
    world.installed()
    world.app.off.add("standin-host")
    world.app.detach("standin-host")
    assert world.fake.containers["liminal-jenkins-ci-controller"]["state"] == "exited"
    assert world.host._svc.plans.waiting() == [] and not world.host._svc.works.running()


def test_a_detach_for_invalidity_stops_nothing(world):
    world.installed()
    world.app.detach("standin-host")  # not turned off: the platform detached it for being invalid
    assert world.fake.containers["liminal-jenkins-ci-controller"]["state"] == "running"


def test_the_platforms_stop_stops_page_services(world):
    world.installed()
    world.host.app_stopping()
    assert world.fake.containers["liminal-jenkins-ci-controller"]["state"] == "exited"


def test_release_owned_stops_the_askers_services_alone(world):
    world.installed()
    world.page("standin-host", "grant_service", "gocd", "wsl-ubuntu")
    plan = world.plan(sid="gocd/ci", spec_=W.spec(owner="gocd", host=8153), who=world.gocd)
    world.approve_all(plan)
    world.wait(world.gocd.call("apply_plan", plan["plan"])["work"], who=world.gocd)
    world.gocd.call("release_owned")
    assert world.fake.containers["liminal-gocd-ci-controller"]["state"] == "exited"
    assert world.fake.containers["liminal-jenkins-ci-controller"]["state"] == "running"
    with pytest.raises(AskRefused):
        world.page("standin-host", "release_owned")


def test_hosted_file_gives_a_readable_alone(world):
    world.installed()
    world.fake.volumes["liminal-jenkins-ci-home"]["files"]["secrets/initialAdminPassword"] = b"unlock-1234"
    got = world.jenkins.call("hosted_file", "jenkins/ci", "controller", "unlock")
    assert got["text"] == "unlock-1234"
    with pytest.raises(Refusal, match="names no readable"):
        world.jenkins.call("hosted_file", "jenkins/ci", "controller", "../../etc/shadow")
    with pytest.raises(Refusal, match="jenkins alone"):
        world.gocd.call("hosted_file", "jenkins/ci", "controller", "unlock")


def test_no_thread_is_left_and_every_answer_is_json(world):
    before = set(threading.enumerate())
    done = standins.conformance(world.jenkins, world.page, W.spec(), "wsl-ubuntu", world.wait) if world.grant() is None \
        else None
    assert done and done[-1] == "conformance"
    left = [t for t in threading.enumerate() if t not in before and t.is_alive()]
    assert left == []
    for answer in (world.jenkins.call("hosting", "jenkins", {"linux": W.spec()}), world.page("standin-host", "status"),
                   world.jenkins.call("exposures"), world.jenkins.call("segments")):
        assert json.loads(json.dumps(answer)) == answer


def test_hosting_says_each_targets_fit_and_notes_who_asked(world):
    got = world.jenkins.call("hosting", "jenkins", {"linux": W.spec()})
    t = got["targets"][0]
    assert t["id"] == "wsl-ubuntu" and t["fit"]["takes"] == "" and t["granted"] == []
    assert "jenkins" in world.host._svc.askers


def test_a_wsl_plugin_without_hold_is_said_as_differs(tmp_path):
    w = W.World(wsl_holds=False, folder=tmp_path)
    got = w.jenkins.call("hosting", "jenkins", {"linux": W.spec()})
    assert got["targets"][0]["fit"]["parts"]["lifecycle"]["fit"] == "differs"
    w.grant()
    plan = w.plan()
    assert "accept_differs" in [a["name"] for a in plan["accepts"]]


def test_an_old_docker_cannot_host_a_service(world):
    world.fake.version = "27.5.1"
    got = world.jenkins.call("hosting", "jenkins", {"linux": W.spec()})
    assert "older than 28.2.0" in got["targets"][0]["fit"]["takes"]


def test_the_conformance_sequence_runs_on_the_stand_in(world):
    world.grant()
    assert standins.conformance(world.jenkins, world.page, W.spec(), "wsl-ubuntu", world.wait)[-1] == "conformance"
    assert world.fake.containers == {} and world.fake.volumes == {} and world.fake.networks == {}
