"""1.95.0: the gaps the container-plugin builders found in the one "run a service" interface (1.93.0, 1.94.0), each
closed by a hook with a default, on the same stand-ins as test_service_containers.py (a real apps.App, a FakeDocker, a
stand-in firewall): the asker's own secret, the settings you define before any instance, a container plugin's own
accepts, an update that adds a part, the engine's own network (found, shared, assigned by the engine, nested), where
this machine reaches a port, a fit said without a spec, targets handed by the plugin's own status, the data root,
pulls by the engine, backups by snapshot, a volume's owner and least, kept-secret words, pins chosen by Windows build,
WSL's one stack, and FakeWindowsDocker. Each new gate has a test here that fails when the gate is taken out."""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from liminal_libs.apps import asking
from liminal_libs.apps.asking import AskRefused
from liminal_libs.instances import Refusal
from liminal_libs.machines import containers as C
from liminal_libs.machines import segments as S
from liminal_libs.machines import standins
from liminal_libs.machines.containerhost import Fit, Aspect
from liminal_libs.machines.containers import ImagePin, ServiceSpec, Setting, Target
from liminal_libs.machines.dockerruntime import DockerRuntime
from liminal_libs.machines.plans import Accept

import svcworld as W

pytestmark = pytest.mark.usefixtures("no_outside")
DIG2 = "sha256:" + "c" * 64
AGENT_SECRET = "agent-Qz71-never-shown"


class Runtime(DockerRuntime):
    """A DockerRuntime whose 1.95.0 hooks a test sets (`said`)."""

    said: dict = {}

    def network_want(self, spec, sid):
        return dict(self.said.get("want") or {})

    def backup_kind(self, part):
        return self.said.get("backup", "tar")

    def backup(self, volume, pinned, into, line, cancelled):
        if self.said.get("backup") == "snapshot":
            return f"snapshot {volume}-before"
        return super().backup(volume, pinned, into, line, cancelled)

    def kept_secret_words(self, spec):
        return self.said.get("secret_words", "")

    def pull(self, pin, line, cancelled):
        if "pull" in self.said:
            return self.said["pull"]
        return super().pull(pin, line, cancelled)

    def make_volume_for(self, name, labels, volume):
        self.said.setdefault("volumes", []).append((name, volume.owner, volume.least))
        return super().make_volume_for(name, labels, volume)


class Host(standins.StandInHost):
    """The stand-in container plugin with the 1.95.0 hooks a test sets."""

    TARGET_SETTINGS = ()
    MORE_ACCEPTS = ()
    said: dict = {}

    def runtime_of(self, target):
        fake = self.fakes[target.id]
        rt = Runtime(["docker"], fake, fake.stream, version=fake.version, arch=fake.arch, wsl=bool(target.wsl),
                     lan=(target.path, target.lan_words), where_data=target.where_data)
        rt.said = self.said
        return rt

    def runtime_targets(self):
        self.said["read"] = self.said.get("read", 0) + 1
        return super().runtime_targets()

    def more_accepts(self, act, sid, t, rt, spec, facts):
        return list(self.said.get("more", {}).get(act, []))

    def check_target_setting(self, target, setting, value, sid, confirm):
        if setting.name == "namespace" and value == "new" and not confirm:
            raise Refusal(f"{target.id} has no namespace new: it is made for Liminal's alone", accept="confirm")
        return [f"checked {setting.name}"]

    def no_spec_fit(self, target, owner):
        if self.said.get("not_yet"):
            return Fit.judged({"image": Aspect("cannot", f"not yet: {owner} has no image for this target")})
        return None


@pytest.fixture
def world(tmp_path, monkeypatch):
    Host.said = {}
    Host.TARGET_SETTINGS = ()
    Host.MORE_ACCEPTS = ()
    monkeypatch.setattr(W, "StandInHost", Host)
    w = W.World(folder=tmp_path, pairs={"JENKINS_AGENT_SECRET": AGENT_SECRET})
    w.jenkins.keys = (SimpleNamespace(name="JENKINS_AGENT_SECRET"), SimpleNamespace(name="JENKINS_ADMIN_PASSWORD"))
    return w


def agent(digest=DIG2, secret=True, lan=False, port=None):
    part = {"name": "agent", "image": {"ref": "docker.io/jenkins/inbound-agent:latest-jdk21", "digest": digest,
                                       "system": "linux", "platforms": ["linux/amd64"], "tar": True},
            "env": {"JENKINS_URL": "http://liminal-jenkins-ci-controller:8080/", "JENKINS_WEB_SOCKET": "true"},
            "secrets": [{"variable": "JENKINS_AGENT_SECRET", "env": "JENKINS_SECRET"}] if secret else [],
            "volumes": [{"name": "work", "path": "/home/jenkins/agent", "holds": "its workspaces", "owner": 1000}],
            "memory": 512 << 20}
    if port:
        part["ports"] = [{"name": "agent-web", "container": 9000, "host": port, "lan": lan}]
    return part


def with_agent(base=None, **kw):
    s = copy.deepcopy(base or W.spec())
    s["parts"].append(agent(**kw))
    return s


def approve(world, plan, **refuse):
    """Every plan of an answer approved as the page, by its approve_args (the container plugin's own accepts too)."""
    for a in plan["approve"]:
        words = world.page(a["plugin"], "plan_words", a["plan"])
        needed = {x["name"] for x in words["accepts"]}
        world.page(a["plugin"], "approve_plan", a["plan"],
                   *[(k in needed and not refuse.get(k, False)) for k in words["approve_args"]])


def carried(world, plan):
    approve(world, plan)
    return world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])


# -- the asker's own secret (the 1.93.0 bug) ------------------------------------------------------------------------------
def test_a_secret_the_asker_itself_declares_is_its_own_to_hand_over(world):
    world.grant()
    end = carried(world, world.plan(spec_=with_agent()))
    assert end["ok"], end
    made = world.fake.containers["liminal-jenkins-ci-agent"]
    assert made["secret_values"] == {"JENKINS_SECRET": AGENT_SECRET}
    assert all(AGENT_SECRET not in " ".join(argv) for argv in world.fake.argv_of("create"))


def test_a_secret_another_plugin_declares_is_still_refused(world):
    world.grant()
    world.gocd.keys = (SimpleNamespace(name="JENKINS_AGENT_SECRET"),)
    with pytest.raises(Refusal, match="gocd's pair"):
        world.plan(spec_=with_agent())


# -- what you define before any instance -----------------------------------------------------------------------------------
SETTINGS = (Setting("namespace", "Namespace", "where its objects go"), Setting("storage", "Storage class", kind="choice",
                                                                               choices=("local-path", "fast")),
            Setting("size", "Claim size", kind="size", per_service=True))


def test_every_plan_on_a_target_waits_for_the_settings_you_define(world):
    Host.TARGET_SETTINGS = SETTINGS
    world.grant()
    with pytest.raises(Refusal, match=r"set Namespace, Storage class, Claim size for wsl-ubuntu \(jenkins/ci\) on .* "
                                      "page first"):
        world.plan()
    rows = world.jenkins.call("hosting", "jenkins", {})["targets"]
    assert rows[0]["unset"] == ["Namespace", "Storage class"]
    world.page("standin-host", "set_target_setting", "wsl-ubuntu", "namespace", "ci-things")
    world.page("standin-host", "set_target_setting", "wsl-ubuntu", "storage", "fast")
    with pytest.raises(Refusal, match=r"Claim size for wsl-ubuntu \(jenkins/ci\)"):
        world.plan()
    world.page("standin-host", "set_target_setting", "wsl-ubuntu", "size", "20Gi", "jenkins/ci")
    assert world.plan()["plan"]
    assert world.fake.changes() == []
    assert world.host.setting_value("wsl-ubuntu", "size", "jenkins/ci") == "20Gi"
    stored = json.loads(world.login.env["STANDIN_HOST_TARGET_SETTINGS"])
    assert stored["targets"]["wsl-ubuntu"]["namespace"] == "ci-things"


def test_a_setting_is_the_pages_alone_and_checked_before_it_is_kept(world):
    Host.TARGET_SETTINGS = SETTINGS
    with pytest.raises(AskRefused):
        world.jenkins.call("set_target_setting", "wsl-ubuntu", "namespace", "x")
    with asking.asking("jenkins"):
        with pytest.raises(Refusal, match="from its page alone"):
            world.host.set_target_setting("wsl-ubuntu", "namespace", "x")
    with pytest.raises(Refusal) as e:
        world.page("standin-host", "set_target_setting", "wsl-ubuntu", "namespace", "new")
    assert e.value.accept == "confirm" and world.host.setting_value("wsl-ubuntu", "namespace") == ""
    said = world.page("standin-host", "set_target_setting", "wsl-ubuntu", "namespace", "new", "", True)
    assert "checked namespace" in said["lines"]
    with pytest.raises(Refusal, match="one of local-path, fast"):
        world.page("standin-host", "set_target_setting", "wsl-ubuntu", "storage", "slow")
    with pytest.raises(Refusal, match="Mi, Gi or Ti"):
        world.page("standin-host", "set_target_setting", "wsl-ubuntu", "size", "20GB", "jenkins/ci")
    world.page("standin-host", "set_target_setting", "wsl-ubuntu", "namespace", "")
    assert world.host.setting_value("wsl-ubuntu", "namespace") == ""


def test_a_size_you_set_below_a_volumes_least_is_refused(world):
    Host.TARGET_SETTINGS = (Setting("size", "Claim size", kind="size", per_service=True),)
    world.grant()
    world.page("standin-host", "set_target_setting", "wsl-ubuntu", "size", "1Gi", "jenkins/ci")
    s = W.spec()
    s["parts"][0]["volumes"][0]["least"] = 2 << 30
    with pytest.raises(Refusal, match="needs 2,048 MiB at least"):
        world.plan(spec_=s)


def test_the_settings_are_drawn_on_its_page(world):
    Host.TARGET_SETTINGS = SETTINGS
    st = world.page("standin-host", "status")
    table = next(t for t in st["tables"] if t["title"] == "Yours to define")
    assert len(table["rows"]) == 3 and any(f["id"] == "setting" for f in st["forms"])


# -- a container plugin's own accepts ---------------------------------------------------------------------------------------
def test_its_own_accept_is_asked_and_taken_after_the_bases(world):
    Host.MORE_ACCEPTS = ("accept_namespace",)
    Host.said["more"] = {"install": [Accept("accept_namespace", "Make the namespace?", "the namespace ci is made",
                                            "Make it")]}
    world.grant()
    plan = world.plan()
    words = world.page("standin-host", "plan_words", plan["plan"])
    assert words["approve_args"][-1] == "accept_namespace"
    with pytest.raises(Refusal) as e:
        approve(world, plan, accept_namespace=True)
    assert e.value.accept == "accept_namespace"
    approve(world, plan)
    assert world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])["ok"]


def test_an_accept_it_does_not_declare_is_refused(world):
    Host.said["more"] = {"install": [Accept("accept_namespace", "Make it?", "w", "Make it")]}
    world.grant()
    with pytest.raises(Refusal, match="does not declare"):
        world.plan()


# -- an update that adds a part ---------------------------------------------------------------------------------------------
def test_an_update_that_adds_a_part_is_its_own_plan_and_stops_nothing(world, tmp_path):
    world.installed()
    before = len(world.fake.calls)
    plan = world.plan("update", spec_=with_agent())
    assert plan["title"].startswith("Add agent to Jenkins")
    assert [a["name"] for a in plan["accepts"]] == ["accept_kept_secret"]
    assert not any("back up" in s for s in plan["steps"])
    fw = next(a for a in plan["approve"] if a["plugin"] == "standin-firewall")
    assert world.page("standin-firewall", "plan_words", fw["plan"])["action"] == "add"
    end = carried(world, plan)
    assert end["ok"], end
    keys = [c["key"] for c in world.fake.calls[before:]]
    assert "stop" not in keys and "rename" not in keys and "run" not in keys
    a = world.fake.containers["liminal-jenkins-ci-agent"]
    c = world.fake.containers["liminal-jenkins-ci-controller"]
    assert a["network"] == c["network"] == "liminal-jenkins-ci" and a["ip"].endswith(".11") and c["ip"].endswith(".10")
    assert not (tmp_path / "containers" / "backups").exists()
    hosted = world.jenkins.call("hosted", "jenkins/ci")
    assert hosted["state"] == "running" and {p["name"] for p in hosted["parts"]} == {"controller", "agent"}
    names = world.page("standin-firewall", "name_records", "inside", "jenkins/ci")["records"]
    assert any(r["name"].startswith("agent.jenkins-ci.") for r in names)
    end = world.carry("stop")  # the labelled spec is the whole one: the agent stops too
    assert world.fake.containers["liminal-jenkins-ci-agent"]["state"] == "exited", end


def test_an_update_that_adds_and_changes_or_drops_a_part_is_refused(world):
    world.installed()
    with pytest.raises(Refusal, match="update controller first"):
        world.plan("update", spec_=with_agent(W.newer()))
    end = carried(world, world.plan("update", spec_=with_agent()))
    assert end["ok"]
    with pytest.raises(Refusal, match="agent would be left behind"):
        world.plan("update", spec_=W.newer())


def test_a_part_added_with_a_port_on_your_network_asks_accept_lan(world):
    world.installed()
    plan = world.plan("update", spec_=with_agent(lan=True, port=9000))
    assert "accept_lan" in [a["name"] for a in plan["accepts"]]


def test_a_rollback_needs_a_previous_container_of_every_part(world):
    world.installed()
    assert world.carry("update", spec_=W.newer())["ok"]
    assert carried(world, world.plan("update", spec_=with_agent(W.newer())))["ok"]
    with pytest.raises(Refusal, match="agent has no previous container"):
        world.plan("rollback", options={"choice": "as-is"})
    assert "liminal-jenkins-ci-controller" in world.fake.containers


def test_the_hosted_spec_is_the_newest_whole_one_whatever_the_order():
    rows = [{"spec": {"parts": [1, 2]}, "made": "2026-11-25T10:00:00Z"},
            {"spec": {"parts": [1]}, "made": "2026-11-25T11:00:00Z"}]
    assert C.labelled_spec_of(rows)["spec"]["parts"] == [1, 2]
    assert C.labelled_spec_of(list(reversed(rows)))["spec"]["parts"] == [1, 2]


# -- the engine's own network ---------------------------------------------------------------------------------------------
def test_a_found_shared_network_is_reserved_its_addresses_the_engines_and_never_dropped(world):
    Host.said["want"] = {"network": "nat", "found": "172.29.16.0/20", "assigns": "hns", "shared": True}
    world.fake.networks["nat"] = {"id": "e" * 64, "labels": {}, "options": {}, "subnet": "172.29.16.0/20",
                                  "gateway": "172.29.16.1", "ip_range": "", "driver": "nat"}
    world.grant()
    world.grant("gocd")
    end = world.carry("install")
    assert end["ok"], end
    a = world.firewall._book.of_sid("jenkins/ci")
    assert a.prefix == "172.29.16.0/20" and a.addresses == {} and a.found and a.shared and a.assigns == "hns"
    assert world.fake.containers["liminal-jenkins-ci-controller"]["network"] == "nat"
    assert "network create" not in world.fake.changes()
    g = world.gocd.call("service_plan", "install", "gocd/ci", W.spec(owner="gocd", host=8153), "wsl-ubuntu", {})
    assert g["plan"]
    plan = world.plan("remove")
    approve(world, plan)
    assert world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])["ok"]
    assert "nat" in world.fake.networks and "network rm" not in world.fake.changes()


def test_a_found_network_that_meets_another_services_is_refused(world):
    world.grant()
    assert world.carry("install")["ok"]
    taken = world.firewall._book.of_sid("jenkins/ci").prefix
    Host.said["want"] = {"found": taken, "assigns": "hns"}
    world.grant("gocd")
    with pytest.raises(Refusal, match="it is not reserved for gocd/ci"):
        world.gocd.call("service_plan", "install", "gocd/ci", W.spec(owner="gocd", host=8153), "wsl-ubuntu", {})


def test_a_segment_behind_an_instance_is_routed_through_it_on_its_own_stack():
    f = standins.StandInNetworkHost(own="linux", routes_to=())
    want = S.Want.of({"stack": "linux", "target": "lxd", "network": "liminal-jenkins-ci", "parts": ["controller"],
                      "behind": "10.120.5.7"})
    f._owner = lambda hook: "lxd"  # past the asker's gate (tested in test_service_network.py): the route alone here
    plan = f.network_plan("install", "jenkins/ci", want.as_dict())
    held = f._net.plans.get(plan["plan"])
    assert held.extra["routes"][0]["next_hop"] == "10.120.5.7"
    w = standins.StandInNetworkHost(own="windows", routes_to=("wsl",))
    w._owner = lambda hook: "lxd"
    with pytest.raises(Refusal, match="routed by the firewall of its own stack"):
        w.network_plan("install", "jenkins/ci", {**want.as_dict(), "stack": "wsl"})


def test_a_want_says_where_this_machine_reaches_a_port_and_the_proxy_points_there(world):
    world.grant()
    orig = Runtime.here
    Runtime.here = lambda self, port: f"172.31.0.9:{port + 22000}"
    try:
        plan = world.plan()
    finally:
        Runtime.here = orig
    fw = next(a for a in plan["approve"] if a["plugin"] == "standin-firewall")
    held = world.firewall._net.plans.get(fw["plan"])
    proxy = next(s for s in held.extra["_steps"] if s["kind"] == "proxy")
    assert proxy["detail"]["here"] == "172.31.0.9:30080"


def test_a_want_refuses_a_word_it_does_not_know():
    base = {"stack": "wsl", "target": "t", "network": "n", "parts": ["a"]}
    with pytest.raises(Refusal, match="given by one of"):
        S.Want.of({**base, "assigns": "magic"})
    with pytest.raises(Refusal, match="say its prefix"):
        S.Want.of({**base, "shared": True})
    with pytest.raises(Refusal, match="a prefix"):
        S.Want.of({**base, "found": "nope"})
    assert "kubernetes" in S.ASSIGNS


def test_a_no_route_want_makes_no_route(world):
    Host.said["want"] = {"found": "10.42.0.0/16", "assigns": "kubernetes", "shared": True, "route": False}
    world.grant()
    plan = world.plan()
    fw = next(a for a in plan["approve"] if a["plugin"] == "standin-firewall")
    held = world.firewall._net.plans.get(fw["plan"])
    assert not [s for s in held.extra["_steps"] if s["kind"] == "route"] and "no route" in held.words


def test_the_linux_platform_inside_wsl_owns_wsl_and_takes_the_linux_half():
    inside = standins.StandInNetworkHost(own="wsl", routes_to=())
    inside._net_platform = "linux::Ubuntu"
    assert inside._half() == S.HALVES["linux"]
    assert standins.StandInNetworkHost(own="windows")._half() == S.HALVES["windows"]
    assert C.stack_of(True, True) == "wsl" and C.stack_of(True, False) == "linux" and C.stack_of(False, False) == "windows"


# -- reads: a fit without a spec, targets handed over, the data root -------------------------------------------------------
def test_a_target_may_say_why_without_a_spec_of_its_system(world):
    Host.said["not_yet"] = True
    rows = world.jenkins.call("hosting", "jenkins", {})["targets"]
    assert rows[0]["fit"]["takes"].startswith("image: not yet: jenkins")
    Host.said["not_yet"] = False
    assert world.jenkins.call("hosting", "jenkins", {})["targets"][0]["fit"] is None


def test_targets_its_status_read_are_kept_and_not_read_again(world):
    world.host.forget_targets()
    Host.said["read"] = 0
    world.host.service_status(targets=world.host._targets and list(world.host._targets.values()))
    assert Host.said["read"] == 0
    world.host.forget_targets()
    world.host.service_status()
    assert Host.said["read"] == 1


def test_a_plan_says_where_the_engine_keeps_its_data(world):
    world.grant()
    world.fake.root = "/srv/docker-data"
    plan = world.plan()
    assert "(/srv/docker-data)" in plan["words"]


# -- pulls, backups, volumes, kept-secret words ------------------------------------------------------------------------------
def test_a_pull_by_the_engine_is_said_so_and_any_other_digest_still_fails(world):
    world.grant()
    Host.said["pull"] = C.PULLED_BY_ENGINE
    end = world.carry("install")
    assert end["ok"] and any("pulled by its engine by its digest" in x for x in end["lines"])
    w2 = W.World()
    w2.grant()
    Host.said["pull"] = ""
    end = w2.carry("install")
    assert end["ok"] is False


def test_a_snapshot_backup_needs_no_tar_and_is_noted(world, tmp_path):
    world.installed()
    Host.said["backup"] = "snapshot"
    plan = world.plan("update", spec_=W.newer(W.spec(tar=False)))
    assert "accept_no_backup" not in [a["name"] for a in plan["accepts"]]
    assert any("snapshot the volume" in s for s in plan["steps"])
    end = carried(world, plan)
    assert end["ok"], end
    noted = list((tmp_path / "containers" / "backups" / "jenkins-ci").rglob("home.snapshot.json"))
    assert len(noted) == 1 and "snapshot liminal-jenkins-ci-home-before" in noted[0].read_text("utf-8")
    assert any("snapshotted by its engine" in x for x in end["lines"])


def test_a_runtime_that_backs_up_nothing_asks_accept_no_backup(world):
    world.installed()
    Host.said["backup"] = "none"
    plan = world.plan("update", spec_=W.newer())
    assert "accept_no_backup" in [a["name"] for a in plan["accepts"]]


def test_a_volume_is_made_for_its_spec_with_its_owner_and_least(world):
    world.grant()
    s = W.spec()
    s["parts"][0]["volumes"][0]["least"] = 1 << 30
    assert world.carry("install", spec_=s)["ok"]
    assert Host.said["volumes"] == [("liminal-jenkins-ci-home", 1000, 1 << 30)]


def test_the_runtime_says_who_can_read_a_kept_secret(world):
    world.grant()
    Host.said["secret_words"] = "kept in a Secret in the namespace ci"
    plan = world.plan(spec_=with_agent())
    words = next(a for a in plan["accepts"] if a["name"] == "accept_kept_secret")
    assert words["words"] == "kept in a Secret in the namespace ci"


# -- the spec's new words ---------------------------------------------------------------------------------------------------
def test_the_new_words_are_left_out_unless_said_so_a_specs_sha_stays():
    s = ServiceSpec.of(W.spec())
    d = s.as_dict()
    assert "least" not in d["parts"][0]["volumes"][0] and "shell" not in d["parts"][0]["image"]
    raw = W.spec()
    raw["parts"][0]["image"]["shell"] = False
    raw["parts"][0]["volumes"][0]["least"] = 5
    t = ServiceSpec.of(raw)
    assert t.parts[0].image.has_shell is False and t.parts[0].volumes[0].least == 5 and t.sha() != s.sha()
    assert ServiceSpec.of(W.spec(tar=False)).parts[0].image.has_shell is False
    with pytest.raises(Refusal, match="shell is true, false or null"):
        ServiceSpec.of({**raw, "parts": [{**raw["parts"][0], "image": {**raw["parts"][0]["image"], "shell": "y"}}]})


def test_a_windows_pin_is_chosen_by_the_targets_build():
    def pin(build):
        return {"ref": f"docker.io/jenkins/jenkins:ltsc-{build}", "digest": W.DIG, "system": "windows",
                "platforms": ["windows/amd64"], "os_build": build}

    pins = [pin(17763), pin(20348)]
    win = {"id": "w", "plugin": "p", "title": "t", "mechanism": "docker-windows", "system": "windows"}
    assert C.choose_pin(pins, {**win, "os_build": 20348}).os_build == 20348
    assert C.choose_pin(pins, {**win, "os_build": 26100}).os_build == 20348  # Hyper-V isolation on a newer host
    with pytest.raises(Refusal, match="no pinned image runs on Windows build 14393"):
        C.choose_pin(pins, {**win, "os_build": 14393})
    with pytest.raises(Refusal, match="does not say its Windows build"):
        C.choose_pin(pins, win)
    linux = [W.spec()["parts"][0]["image"]]
    assert C.choose_pin(linux, Target("l", "p", "t", "docker", "linux")).ref.endswith("jdk21")
    assert Target.of({**win, "os_build": 20348, "isolation": "process"}).isolation == "process"


# -- FakeWindowsDocker ------------------------------------------------------------------------------------------------------
def test_the_windows_stand_in_answers_as_docker_exe_at_a_pipe():
    fake = standins.FakeWindowsDocker(build=20348)
    rt = DockerRuntime(["docker.exe", "-H", "npipe:////./pipe/docker_engine"], fake, fake.stream)
    assert rt.data_root() == "C:\\ProgramData\\docker"
    assert "nat" in fake.networks and fake.networks["nat"]["gateway"] == "172.29.16.1"
    code, out, _ = fake(["docker.exe", "-H", "npipe:////./pipe/docker_engine", "version", "--format", "{{json .}}"],
                        10)
    assert json.loads(out)["Server"]["Os"] == "windows"
    fake.volumes["v"] = {"labels": {}, "files": {}}
    fake(["docker.exe", "-H", "p", "create", "--name", "c", "--isolation", "process", "--network", "nat", "-v",
          "v:C:\\data", "img@" + W.DIG], 10)
    assert fake.containers["c"]["ip"] == "172.29.16.11" and fake.containers["c"]["mounts"] == [("v", "C:\\data")]


# -- ContainedService on the new hooks ---------------------------------------------------------------------------------------
from liminal_libs.machines.containedservice import ContainedService, Pace  # noqa: E402
from liminal_libs.machines.servicestandins import ServiceWorld  # noqa: E402


class Svc(ContainedService):
    """A service plugin whose recipe grows an agent once `agent` is set, and whose pins can move."""

    name, title, about, api, order = "jenkins", "Jenkins", "a stand-in service plugin", "2.2", 994

    def __init__(self):
        ContainedService.__init__(self, Pace(sleep=lambda s: __import__("time").sleep(0.002)))
        self.agent, self.digest, self.seen = False, W.DIG, []

    def present(self) -> bool:
        """Always: a stand-in."""
        return True

    def status(self) -> dict:
        """Its page: the base's."""
        return {"present": True, "valid": True, "summary": "", **self.service_status()}

    def spec_for(self, system, name, options):
        self.seen.append(dict(options))
        s = W.spec(name=name, lan=bool(options.get("lan")), digest=self.digest)
        return ServiceSpec.of(with_agent(s, secret=False) if self.agent else s)


@pytest.fixture
def sworld(tmp_path):
    return ServiceWorld(Svc(), folder=tmp_path)


def test_install_hands_the_recipe_its_target_and_waits_for_the_settings_you_define(sworld):
    sworld.grant()
    assert sworld.service.hosts(fresh=True)["plugins"][0]["targets"][0]["offer"] == ""
    sworld.host.TARGET_SETTINGS = (Setting("namespace", "Namespace"),)
    try:
        t = sworld.service.hosts(fresh=True)["plugins"][0]["targets"][0]
        assert t["offer"].startswith("set Namespace for wsl-ubuntu on")
        with pytest.raises(Refusal, match="set Namespace"):
            sworld.ask("service_install", sworld.HOST, sworld.TARGET)
    finally:
        sworld.host.TARGET_SETTINGS = ()
    sworld.service._forget_hosts()
    assert sworld.through(sworld.ask("service_install", sworld.HOST, sworld.TARGET))["ok"]
    assert sworld.service.seen[-1]["target"]["id"] == "wsl-ubuntu"


def test_an_update_that_adds_a_part_and_changes_one_goes_as_two_plans_in_turn(sworld):
    sworld.grant()
    assert sworld.through(sworld.ask("service_install", sworld.HOST, sworld.TARGET))["ok"]
    sworld.service.agent, sworld.service.digest = True, "sha256:" + "b" * 64
    first = sworld.ask("service_change", "update", "ci")
    assert not first["title"].startswith("Add") and sworld.through(first)["ok"]
    assert "liminal-jenkins-ci-agent" not in sworld.fake.containers
    second = sworld.ask("service_change", "update", "ci")
    assert second["title"].startswith("Add agent") and sworld.through(second)["ok"]
    assert "liminal-jenkins-ci-agent" in sworld.fake.containers
    assert set(sworld.service.placement("ci")["image"]) == {"controller", "agent"}
    with pytest.raises(Refusal, match="runs this plugin's pins already"):
        sworld.ask("service_change", "update", "ci")
