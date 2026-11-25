"""1.97.0: the service interface's last library pass (INTERFACE-GAPS.md P1 to P5 and S1 to S5) and an image built
here (SERVICE-INTERFACE.md §10), on the stand-ins alone: a real apps.App, a FakeDocker, a stand-in firewall, a
FakeFetch for a build's pinned files (no network). Each new gate has a test here that fails when it is taken out."""
from __future__ import annotations

import copy
import hashlib
import time
from types import SimpleNamespace

import pytest

from liminal_libs.apps import asking
from liminal_libs.apps.asking import AskRefused
from liminal_libs.instances import Refusal
from liminal_libs.machines import containers as C
from liminal_libs.machines import segments as S
from liminal_libs.machines import standins
from liminal_libs.machines.containedservice import UNREAD, ContainedService, Pace, unread_pins
from liminal_libs.machines.containers import ServiceSpec, Setting
from liminal_libs.machines.dockerruntime import DockerRuntime
from liminal_libs.machines.servicestandins import ServiceWorld

import svcworld as W

pytestmark = pytest.mark.usefixtures("no_outside")

WHEEL = b"a pinned wheel's bytes " * 64
SHA = hashlib.sha256(WHEEL).hexdigest()
URL = "https://files.pythonhosted.org/packages/7a/8c/merc-7.2.4-py3-none-any.whl"
NAME = "merc-7.2.4-py3-none-any.whl"
BASE = {"ref": "docker.io/library/python:3.13.18-slim-trixie", "digest": "sha256:" + "e" * 64, "system": "linux",
        "platforms": ["linux/amd64"], "size": 43_062_348, "licence": "PSF-2.0"}
DOCKERFILE = (f"FROM docker.io/library/python@{BASE['digest']}\n"
              f"COPY {NAME} /tmp/{NAME}\n"
              f"RUN python -m pip install --no-index --no-deps /tmp/{NAME} \\\n    && rm /tmp/{NAME}\n"
              "USER 1000\n")


def build(sha=SHA, dockerfile=DOCKERFILE, base=None, tag="liminal/jenkins-controller:1.0", version="1.0", **kw):
    return {"base": dict(base or BASE), "dockerfile": dockerfile, "tag": tag, "version": version, "tar": True,
            "files": [{"name": NAME, "url": URL, "sha256": sha, "size": len(WHEEL), "licence": "GPL-2.0-or-later"}],
            **kw}


def built_spec(**kw):
    s = W.spec()
    part = s["parts"][0]
    del part["image"]
    part["build"] = build(**kw)
    return s


def approve(world, plan, **refuse):
    for a in plan["approve"]:
        words = world.page(a["plugin"], "plan_words", a["plan"])
        needed = {x["name"] for x in words["accepts"]}
        world.page(a["plugin"], "approve_plan", a["plan"],
                   *[(k in needed and not refuse.get(k, False)) for k in words["approve_args"]])


def carried(world, plan):
    approve(world, plan)
    return world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])


@pytest.fixture
def world(tmp_path):
    w = W.World(folder=tmp_path)
    w.host.out.fetch = standins.FakeFetch({URL: WHEEL})
    return w


class WantRuntime(DockerRuntime):
    said: dict = {}

    def network_want(self, spec, sid):
        return dict(self.said.get("want") or {})

    def pull(self, pin, line, cancelled):
        if "pull" in self.said:
            return self.said["pull"]
        return super().pull(pin, line, cancelled)


class Host(standins.StandInHost):
    said: dict = {}
    TARGET_SETTINGS = ()
    HOOKS = (*standins.StandInHost.HOOKS, *standins.ContainerHost.SETTING_HOOKS)
    PAGE_ONLY_HOOKS = standins.ContainerHost.SETTING_HOOKS
    builds = True

    def runtime_of(self, target):
        fake = self.fakes[target.id]
        rt = WantRuntime(["docker"], fake, fake.stream, version=fake.version, arch=fake.arch, wsl=bool(target.wsl),
                         lan=(target.path, target.lan_words), where_data=target.where_data, builds=self.builds)
        rt.said = self.said
        return rt


@pytest.fixture
def hworld(tmp_path, monkeypatch):
    Host.said, Host.TARGET_SETTINGS, Host.builds = {}, (), True
    monkeypatch.setattr(W, "StandInHost", Host)
    w = W.World(folder=tmp_path)
    w.host.out.fetch = standins.FakeFetch({URL: WHEEL})
    return w


# -- P1: an update's pull goes through _pulled -------------------------------------------------------------------------
def test_an_updates_pull_by_its_engine_is_taken_as_an_installs_is(hworld):
    hworld.installed()
    Host.said["pull"] = C.PULLED_BY_ENGINE
    end = hworld.carry("update", spec_=W.newer())
    assert end["ok"], end
    assert any("pulled by its engine by its digest" in x for x in end["lines"])


def test_an_updates_pull_of_another_digest_is_still_refused(hworld):
    hworld.installed()
    Host.said["pull"] = "sha256:" + "d" * 64
    end = hworld.carry("update", spec_=W.newer())
    assert end["ok"] is False and "not its pinned" in str(end["answer"])


# -- P2: shared is not "not its own" ----------------------------------------------------------------------------------
def test_a_services_own_network_on_a_shared_prefix_is_dropped_with_it(hworld):
    # a prefix shared by several services (the firewall's word), and an object named for the service on it (a
    # Docker bridge here, a cluster's NetworkPolicy there): that object is the service's own
    Host.said["want"] = {"found": "10.42.0.0/24", "shared": True, "route": False}
    hworld.grant()
    assert hworld.carry("install")["ok"]
    assert "liminal-jenkins-ci" in hworld.fake.networks
    plan = hworld.plan("remove")
    assert carried(hworld, plan)["ok"]
    assert "network rm" in hworld.fake.changes() and "liminal-jenkins-ci" not in hworld.fake.networks


def test_an_engines_own_network_under_another_name_is_still_never_dropped(hworld):
    Host.said["want"] = {"network": "nat", "found": "172.29.16.0/20", "assigns": "hns", "shared": True}
    hworld.fake.networks["nat"] = {"id": "e" * 64, "labels": {}, "options": {}, "subnet": "172.29.16.0/20",
                                   "gateway": "172.29.16.1", "ip_range": "", "driver": "nat"}
    hworld.grant()
    assert hworld.carry("install")["ok"]
    assert carried(hworld, hworld.plan("remove"))["ok"]
    assert "nat" in hworld.fake.networks and "network rm" not in hworld.fake.changes()


# -- P3: several prefixes found ------------------------------------------------------------------------------------------
def test_a_want_may_find_several_prefixes_and_each_is_reserved(hworld):
    w = S.Want.of({"stack": "wsl", "target": "t", "network": "n", "parts": ["a"],
                   "found": ["10.42.0.0/24", "10.42.1.0/24"], "assigns": "kubernetes"})
    assert w.found == "10.42.0.0/24" and w.found_all == ("10.42.0.0/24", "10.42.1.0/24")
    assert S.Want.of(w.as_dict()) == w
    assert "found_more" not in S.Want.of({"stack": "wsl", "target": "t", "network": "n", "parts": ["a"]}).as_dict()
    with pytest.raises(Refusal, match="a prefix"):
        S.Want.of({**w.as_dict(), "found": ["10.42.0.0/24", "nope"]})
    Host.said["want"] = {"found": ["10.42.0.0/24", "10.42.1.0/24"], "route": False}
    hworld.grant()
    assert hworld.carry("install")["ok"]
    a = hworld.firewall._book.of_sid("jenkins/ci")
    assert a.prefix == "10.42.0.0/24" and a.found_more == ["10.42.1.0/24"]
    hworld.grant("gocd")
    for found in (["10.42.1.0/24"], ["10.43.0.0/24", "10.42.1.0/24"]):  # their second prefix; the asker's second
        Host.said["want"] = {"found": found, "route": False}
        with pytest.raises(Refusal, match="10.42.1.0/24 meets 10.42.1.0/24, jenkins/ci's network"):
            hworld.gocd.call("service_plan", "install", "gocd/ci", W.spec(owner="gocd", host=8153), "wsl-ubuntu", {})


def test_the_pool_avoids_every_prefix_found(hworld):
    first = S.Pool(hworld.firewall._half()).allocate(hworld.firewall.networks_here())[0]
    Host.said["want"] = {"found": ["10.200.0.0/24", first], "route": False}
    hworld.grant()
    assert hworld.carry("install")["ok"]
    Host.said["want"] = {}
    hworld.grant("gocd")
    hworld.gocd.call("service_plan", "install", "gocd/ci", W.spec(owner="gocd", host=8153), "wsl-ubuntu", {})
    assert hworld.firewall._book.of_sid("gocd/ci").prefix not in (first, "10.200.0.0/24")


# -- P4: a per-service size is asked only of a service with volumes ---------------------------------------------------------
def test_a_per_service_size_is_not_asked_of_a_service_without_volumes(hworld):
    Host.TARGET_SETTINGS = (Setting("size", "Claim size", kind="size", per_service=True),)
    hworld.grant()
    s = W.spec()
    s["parts"][0]["volumes"], s["parts"][0]["readable"] = [], []
    assert hworld.plan(spec_=s)["plan"]
    with pytest.raises(Refusal, match="set Claim size"):
        hworld.plan(sid="jenkins/other", spec_={**W.spec(), "name": "other"})


def test_an_override_of_unset_settings_without_the_spec_still_answers(hworld):
    seen = []

    def old(target, sid=""):
        seen.append(sid)
        return []

    hworld.host.unset_settings = old
    hworld.grant()
    assert hworld.plan()["plan"] and seen == ["jenkins/ci"]


# -- P5: choices read lazily ------------------------------------------------------------------------------------------------
def test_a_settings_choices_are_read_only_when_a_value_is_checked(hworld):
    reads = []

    def classes():
        reads.append(1)
        return ("local-path", "fast")

    Host.TARGET_SETTINGS = (Setting("storage", "Storage class", kind="choice", choices=classes),)
    hworld.jenkins.call("hosting", "jenkins", {})
    hworld.page("standin-host", "status")
    assert reads == []
    with pytest.raises(Refusal, match="one of local-path, fast"):
        hworld.page("standin-host", "set_target_setting", "wsl-ubuntu", "storage", "slow")
    assert reads == [1]
    assert Setting("s", "S", choices=classes).as_dict()["choices"] == ["local-path", "fast"]


# -- the service plugin's side: S1, S2, S3, S4 ------------------------------------------------------------------------------
COMMAND = {"name": "mkrepo", "title": "Make a repository", "argv": ["hg", "init", "/srv/hg/{repo}"],
           "args": [{"name": "repo", "label": "Repository"}], "about": "a new empty repository"}


class Svc(ContainedService):
    name, title, about, api, order = "jenkins", "Jenkins", "a stand-in service plugin", "2.2", 994
    HOOKS = (*ContainedService.HOOKS, *ContainedService.RUN_HOOKS)
    PAGE_ONLY_HOOKS = ContainedService.RUN_HOOKS

    def __init__(self, pace=None):
        ContainedService.__init__(self, pace or Pace(sleep=lambda s: time.sleep(0.002)))
        self.ssh, self.answers, self.exposed, self.built = False, True, {}, None

    def present(self) -> bool:
        """Always: a stand-in."""
        return True

    def status(self) -> dict:
        """Its page: the base's."""
        return {"present": True, "valid": True, "summary": "", **self.service_status()}

    def spec_for(self, system, name, options):
        if self.built is not None:
            s = copy.deepcopy(self.built)
            s["name"] = name
        else:
            s = W.spec(name=name, lan=bool(options.get("lan")))
        part = s["parts"][0]
        part["commands"] = [COMMAND]
        if self.ssh:
            part["ports"].insert(0, {"name": "ssh", "container": 22, "host": 2424, "lan": False})
        return ServiceSpec.of(s)

    def ready(self, hosted):
        return (True, "") if self.answers else (False, "still starting")

    def after_expose(self, hosted):
        return self.exposed


@pytest.fixture
def sworld(tmp_path):
    return ServiceWorld(Svc(), folder=tmp_path, files={URL: WHEEL})


def test_its_address_is_its_named_web_port_not_the_first_kept(sworld):
    sworld.service.ssh = True
    assert sworld.install()["ok"]
    assert list(sworld.service.placement("ci")["here"]) == ["ssh", "web"]
    assert sworld.service.address() == "http://127.0.0.1:2424"  # neither said: the first, as before
    sworld.service.WEB_PORT = "web"
    assert sworld.service.address() == "http://127.0.0.1:8080"
    assert sworld.service.address(sworld.ask("hosts", True)["services"][0]) == "http://127.0.0.1:8080"
    sworld.service.WEB_PORT, sworld.service.WEB_PART = "", "controller"
    assert sworld.service.web_port() == "ssh"  # the part's first port, in its recipe


def test_a_plugins_own_ready_wait_is_its_own(tmp_path):
    now = [0.0]

    def sleep(s):
        now[0] += s
        time.sleep(0.001)

    svc = Svc(Pace(clock=lambda: now[0], sleep=sleep))
    svc.answers, svc.READY_S = False, 6.0
    w = ServiceWorld(svc, folder=tmp_path)
    end = w.install()
    assert end["ok"] and "does not answer yet: still starting" in end["said"]
    assert now[0] < 60.0  # its own 6 s, not the base's 300


def test_a_recipes_command_runs_in_its_running_part_confirmed_each_time(sworld):
    assert sworld.install()["ok"]
    with pytest.raises(Refusal) as e:
        sworld.ask("service_run", "ci", "mkrepo", False, "second")
    assert e.value.accept == "confirm" and "hg init /srv/hg/second" in str(e.value)
    assert sworld.fake.execs == []
    said = sworld.ask("service_run", "ci", "mkrepo", True, "second")
    assert said["ok"] and sworld.fake.execs == [{"container": "liminal-jenkins-ci-controller",
                                                 "argv": ["hg", "init", "/srv/hg/second"]}]
    for bad in ("../etc", "-rf", "a b", "x;rm", ""):
        with pytest.raises(Refusal, match="Repository is a name"):
            sworld.ask("service_run", "ci", "mkrepo", True, bad)
    with pytest.raises(Refusal, match="declares no command"):
        sworld.ask("service_run", "ci", "rm", True, "x")
    with pytest.raises(Refusal, match="takes 1 argument"):
        sworld.ask("service_run", "ci", "mkrepo", True)
    assert len(sworld.fake.execs) == 1
    forms = sworld.ask("status")["forms"]
    assert any(f["id"] == "run-mkrepo" and f["hook"] == "service_run" for f in forms)


def test_a_command_is_the_pages_and_its_owners_alone_and_the_labelled_recipes(sworld):
    assert sworld.install()["ok"]
    with pytest.raises(AskRefused):
        with asking.asking("gocd"):
            sworld.app.ask("jenkins", "service_run", "ci", "mkrepo", True, "x")
    with asking.asking(asking.PAGE):
        with pytest.raises(Refusal, match="by the service's own plugin alone"):
            sworld.host.hosted_run("jenkins/ci", "controller", "mkrepo", "x")
    with asking.asking("gocd"):
        with pytest.raises(Refusal, match="asked of by jenkins alone"):
            sworld.host.hosted_run("jenkins/ci", "controller", "mkrepo", "x")
    with asking.asking("jenkins"):
        with pytest.raises(Refusal, match="declares no command 'sh'"):
            sworld.host.hosted_run("jenkins/ci", "controller", "sh", "x")
        with pytest.raises(Refusal, match="Repository is a name"):
            sworld.host.hosted_run("jenkins/ci", "controller", "mkrepo", "--help")
        sworld.fake.containers["liminal-jenkins-ci-controller"]["state"] = "exited"
        with pytest.raises(Refusal, match="is not running"):
            sworld.host.hosted_run("jenkins/ci", "controller", "mkrepo", "x")
    assert sworld.fake.execs == []


def test_a_command_is_declared_soundly_or_refused():
    def cmd(**kw):
        return C.Command.of({**COMMAND, **kw})

    with pytest.raises(Refusal, match="its program"):
        cmd(argv=["{repo}", "x"])
    with pytest.raises(Refusal, match="each argument is used"):
        cmd(argv=["hg", "init"])
    with pytest.raises(Refusal, match="each argument is used"):
        cmd(argv=["hg", "init", "{other}"])
    assert cmd(args=[{"name": "repo", "label": "R", "kind": "choice", "choices": ["a", "b"]}]).argv_for(["b"])[-1] == \
        "/srv/hg/b"
    with pytest.raises(Refusal, match="one of a, b"):
        cmd(args=[{"name": "repo", "label": "R", "kind": "choice", "choices": ["a", "b"]}]).argv_for(["c"])
    assert "commands" not in ServiceSpec.of(W.spec()).parts[0].as_dict()


def test_a_runtime_without_exec_refuses_in_words():
    from liminal_libs.machines.containerhost import Runtime

    with pytest.raises(Refusal, match="runs no command"):
        Runtime().exec("c", ["x"], 5)


def test_an_expose_changes_its_own_settings_inside_its_own_plan(sworld):
    assert sworld.install()["ok"]
    sworld.service.exposed = {"controller": {"JAVA_OPTS": "-Dexternal=http://pc.lan:8080"}}
    answer = sworld.ask("service_change", "expose", "ci", "on")
    plan = sworld.page("standin-host", "plan_words", answer["plan"])
    assert any("JAVA_OPTS = -Dexternal=http://pc.lan:8080" in s for s in plan["steps"])
    assert sworld.through(answer)["ok"]
    argv = " ".join(sworld.fake.argv_of("create")[-1])
    assert "-e JAVA_OPTS=-Dexternal=http://pc.lan:8080" in argv and "-p 8080:8080/tcp" in argv


@pytest.mark.parametrize("own, words", [
    ({"controller": {"NEW_ONE": "x"}}, "settings it has already"),
    ({"controller": {"LIMINAL_TOKEN": "x"}}, "settings it has already"),
    ({"agent": {"JAVA_OPTS": "x"}}, "no part 'agent'"),
    ({"controller": {"JAVA_OPTS": "a\nb"}}, "plain text"),
])
def test_an_expose_changes_nothing_but_its_own_settings(sworld, own, words):
    assert sworld.install()["ok"]
    sworld.service.exposed = own
    with pytest.raises(Refusal, match=words):
        sworld.ask("service_change", "expose", "ci", "on")


# -- §10: an image built here ---------------------------------------------------------------------------------------------
def test_a_build_is_planned_whole_and_nothing_is_fetched_before_approval(world):
    world.grant()
    plan = world.plan(spec_=built_spec())
    step = next(s for s in plan["steps"] if s.startswith("build liminal/jenkins-controller:1.0 here"))
    assert f"pull its base {BASE['ref']}@{BASE['digest']} by digest" in step
    assert f"fetch {NAME} from files.pythonhosted.org" in step and SHA in step and "GPL-2.0-or-later" in step
    assert DOCKERFILE.strip() in step
    assert "accept_build" in [a["name"] for a in plan["accepts"]]
    assert world.page("standin-host", "plan_words", plan["plan"])["approve_args"][-1] == "accept_build"
    assert world.host.out.fetch.asked == [] and world.fake.changes() == []
    with pytest.raises(Refusal) as e:
        approve(world, plan, accept_build=True)
    assert e.value.accept == "accept_build"


def test_an_image_is_built_here_from_its_pinned_files_alone_and_its_id_labelled(world):
    world.grant()
    spec = ServiceSpec.of(built_spec())
    end = carried(world, world.plan(spec_=built_spec()))
    assert end["ok"], end
    [b] = world.fake.builds
    assert set(b["files"]) == {"Dockerfile", NAME} and b["files"][NAME] == WHEEL
    assert b["dockerfile"] == DOCKERFILE and b["tag"] == "liminal/jenkins-controller:1.0"
    assert "--pull=false" in b["argv"] and "--network=default" in b["argv"]
    ctx = spec.parts[0].build.context()
    assert b["labels"] == {"liminal": "build", "liminal.build-sha": ctx}
    assert f"{BASE['ref']}@{BASE['digest']}" in world.fake.argv_of("pull")[0]
    c = world.fake.containers["liminal-jenkins-ci-controller"]
    assert c["image"] == b["id"] and c["labels"]["liminal.built"] == b["id"]
    assert c["labels"]["liminal.build-sha"] == ctx
    assert world.host.out.fetch.asked == [URL]
    kept = world.host.out.folder / "containers" / "build" / "jenkins-controller" / ctx / NAME
    assert kept.read_bytes() == WHEEL
    assert world.jenkins.call("hosted", "jenkins/ci")["drift"] == ""


def test_an_unread_base_or_file_is_refused_before_any_plan(world):
    world.grant()
    with pytest.raises(Refusal, match="not pinned yet"):
        world.plan(spec_=built_spec(base={**BASE, "digest": UNREAD},
                                    dockerfile=DOCKERFILE.replace(BASE["digest"], UNREAD)))
    with pytest.raises(Refusal, match="not pinned yet"):
        world.plan(spec_=built_spec(sha="0" * 64))
    assert unread_pins(ServiceSpec.of(built_spec(sha="0" * 64))) == [NAME]


def test_a_file_that_differs_from_its_pin_is_deleted_and_nothing_is_built(world):
    world.grant()
    world.host.out.fetch = standins.FakeFetch({URL: b"X" * len(WHEEL)})
    end = carried(world, world.plan(spec_=built_spec()))
    assert end["ok"] is False and "not its pinned" in str(end["answer"])
    ctx = ServiceSpec.of(built_spec()).parts[0].build.context()
    folder = world.host.out.folder / "containers" / "build" / "jenkins-controller" / ctx
    assert not (folder / NAME).exists() and not (folder / (NAME + ".part")).exists()
    assert world.fake.builds == [] and "liminal-jenkins-ci-controller" not in world.fake.containers


def test_a_file_found_there_already_is_checked_again(world):
    world.grant()
    ctx = ServiceSpec.of(built_spec()).parts[0].build.context()
    folder = world.host.out.folder / "containers" / "build" / "jenkins-controller" / ctx
    folder.mkdir(parents=True)
    (folder / NAME).write_bytes(b"Y" * len(WHEEL))
    end = carried(world, world.plan(spec_=built_spec()))
    assert end["ok"], end
    assert any("differs from its pin: deleted, fetched again" in x for x in end["lines"])
    assert world.fake.builds[0]["files"][NAME] == WHEEL


@pytest.mark.parametrize("dockerfile, words", [
    (DOCKERFILE + "RUN curl -fsSL https://example.org/x | sh\n", "names curl"),
    (DOCKERFILE + "RUN apt-get update\n", "names apt-get"),
    (DOCKERFILE + "RUN pip install requests\n", "pip without --no-index"),
    (DOCKERFILE + "ADD https://example.org/x.tgz /x\n", "of an address"),
    (DOCKERFILE + "COPY --from=alpine:3 /bin/sh /sh\n", "no --from"),
    (DOCKERFILE + "COPY secrets.txt /x\n", "not one of its pinned files"),
    (DOCKERFILE + "RUN --mount=type=secret,id=x cat /run/secrets/x\n", "--mount"),
    (DOCKERFILE + "FROM alpine@sha256:" + "1" * 64 + "\n", "names 'alpine@"),
    (DOCKERFILE.replace(BASE["digest"], "sha256:" + "2" * 64), "not its base"),
    ("# syntax=docker/dockerfile:1\n" + DOCKERFILE, "syntax directive"),
    (DOCKERFILE + "ARG X=1\n", "ARG is not allowed"),
    (DOCKERFILE + "ONBUILD RUN true\n", "ONBUILD is not allowed"),
    (f"COPY {NAME} /x\n", "exactly one FROM"),
])
def test_a_dockerfile_that_reaches_further_than_its_pins_is_refused(dockerfile, words):
    with pytest.raises(Refusal, match=words.replace("(", r"\(")):
        ServiceSpec.of(built_spec(dockerfile=dockerfile))


@pytest.mark.parametrize("change, words", [
    (lambda b: b.update(tag="liminal/jenkins-other:1.0"), "is tagged liminal/jenkins-controller:1.0"),
    (lambda b: b["base"].update(platforms=["linux/amd64", "linux/arm64"]), "one platform"),
    (lambda b: b["files"][0].update(url="http://files.pythonhosted.org/x"), "an https address"),
    (lambda b: b["files"][0].update(name="../x"), "a file's name"),
    (lambda b: b["files"][0].update(name="Dockerfile"), "not Dockerfile"),
    (lambda b: b.update(files=b["files"] * 5), "4 files at most"),
    (lambda b: b["files"][0].update(sha256="ABC"), "64 lowercase"),
])
def test_a_build_pin_is_refused_in_words(change, words):
    s = built_spec()
    change(s["parts"][0]["build"])
    with pytest.raises(Refusal, match=words):
        ServiceSpec.of(s)


def test_a_built_part_names_its_build_in_place_of_an_image():
    s = built_spec()
    s["parts"][0]["image"] = W.spec()["parts"][0]["image"]
    with pytest.raises(Refusal, match="says `build` in place of `image`"):
        ServiceSpec.of(s)
    spec = ServiceSpec.of(built_spec())
    assert ServiceSpec.of(spec.as_dict()) == spec and spec.parts[0].image.digest == "sha256:" + \
        spec.parts[0].build.context()


def test_a_container_running_another_image_than_its_build_is_drift(world):
    world.grant()
    assert carried(world, world.plan(spec_=built_spec()))["ok"]
    world.fake.containers["liminal-jenkins-ci-controller"]["image_id"] = "sha256:" + "9" * 64
    assert "another image than the one built here" in world.jenkins.call("hosted", "jenkins/ci")["drift"]
    with pytest.raises(Refusal, match="drift"):
        world.plan("restart")


def test_the_same_pins_are_never_built_twice_and_new_ones_rebuild_as_an_update(world, tmp_path):
    world.grant()
    assert carried(world, world.plan(spec_=built_spec()))["ok"]
    first = world.fake.builds[0]["id"]
    assert carried(world, world.plan("remove"))["ok"]
    again = world.plan(spec_=built_spec())
    assert "accept_build" not in [a["name"] for a in again["accepts"]]
    assert any(s.startswith("use liminal/jenkins-controller:1.0, built here before") for s in again["steps"])
    assert carried(world, again)["ok"] and len(world.fake.builds) == 1
    newer = built_spec(dockerfile=DOCKERFILE + "ENV HGPLAIN=1\n")
    plan = world.plan("update", spec_=newer)
    assert any(s.startswith("rebuild liminal/jenkins-controller:1.0 here") for s in plan["steps"])
    assert any(s.startswith("back up the volume") for s in plan["steps"])
    assert "accept_build" in [a["name"] for a in plan["accepts"]]
    end = carried(world, plan)
    assert end["ok"], end
    assert len(world.fake.builds) == 2 and world.fake.builds[1]["id"] != first
    assert world.fake.containers["liminal-jenkins-ci-controller"]["labels"]["liminal.built"] == world.fake.builds[1]["id"]
    assert world.fake.containers["liminal-jenkins-ci-controller-previous"]["image"] == first
    backup = list((tmp_path / "containers" / "backups" / "jenkins-ci").rglob("home.tar"))
    assert backup and any(first in " ".join(a) for a in world.fake.argv_of("run"))


def test_a_target_whose_engine_builds_nothing_is_not_offered_a_build(hworld):
    Host.builds = False
    hworld.grant()
    fit = hworld.jenkins.call("hosting", "jenkins", {"linux": built_spec()})["targets"][0]["fit"]
    assert C.BUILD_NOT_YET in fit["takes"]
    with pytest.raises(Refusal, match="builds no image"):
        hworld.plan(spec_=built_spec())


def test_a_runtime_builds_nothing_by_default():
    from liminal_libs.machines.containerhost import Runtime

    assert Runtime().can_build() is False and Runtime().built_image(None) == ""
    with pytest.raises(Refusal, match="builds no image"):
        Runtime().build(None, None, print, lambda: False)
    fake = standins.FakeDocker()
    assert DockerRuntime(["docker"], fake, fake.stream).can_build() is False


def test_the_service_plugin_keeps_its_built_image_and_never_rebuilds_the_same_pins(sworld):
    sworld.service.built = built_spec()
    assert sworld.install()["ok"]
    placed = sworld.service.placement("ci")
    ctx = ServiceSpec.of(built_spec()).parts[0].build.context()
    assert placed["image"]["controller"] == sworld.fake.builds[0]["id"]
    assert placed["build"] == {"controller": "sha256:" + ctx}
    with pytest.raises(Refusal, match="runs this plugin's pins already"):
        sworld.ask("service_change", "update", "ci")
    sworld.service.built = built_spec(dockerfile=DOCKERFILE + "ENV HGPLAIN=1\n")
    assert sworld.through(sworld.ask("service_change", "update", "ci"))["ok"]
    assert len(sworld.fake.builds) == 2
    assert sworld.service.placement("ci")["image"]["controller"] == sworld.fake.builds[1]["id"]


def test_a_fetch_follows_no_redirect_to_another_host():
    from liminal_libs.machines import builds

    h = builds._SameHost("files.pythonhosted.org")
    with pytest.raises(Refusal, match="from its own host alone"):
        h.redirect_request(SimpleNamespace(), None, 302, "Found", {}, "https://evil.example/x")
    with pytest.raises(Refusal, match="from its own host alone"):
        h.redirect_request(SimpleNamespace(), None, 302, "Found", {}, "http://files.pythonhosted.org/x")
    with pytest.raises(Refusal, match="over https alone"):
        list(builds.https_fetch("http://files.pythonhosted.org/x", 10))


def test_only_the_last_two_contexts_of_a_part_are_kept(tmp_path):
    from liminal_libs.machines import builds

    for i, name in enumerate(("a", "b", "c", "d")):
        (tmp_path / name).mkdir()
        import os

        os.utime(tmp_path / name, (1000 + i, 1000 + i))
    builds.prune(tmp_path, keep="a")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a", "d"]


def test_a_command_is_refused_inside_the_plugin_too_and_while_a_work_runs(sworld, monkeypatch):
    assert sworld.install()["ok"]
    with asking.asking("gocd"):
        with pytest.raises(Refusal, match="from its page alone"):
            sworld.service.service_run("ci", "mkrepo", True, "x")
    monkeypatch.setattr(sworld.host._svc.works, "running", lambda: [SimpleNamespace(key="wsl-ubuntu")])
    with asking.asking("jenkins"):
        with pytest.raises(Refusal, match="runs on wsl-ubuntu now"):
            sworld.host.hosted_run("jenkins/ci", "controller", "mkrepo", "x")
    assert sworld.fake.execs == []


def test_a_start_checks_its_built_image_again_when_it_is_carried_out(world):
    world.grant()
    assert carried(world, world.plan(spec_=built_spec()))["ok"]
    assert carried(world, world.plan("stop"))["ok"]
    plan = world.plan("start")
    approve(world, plan)
    world.fake.containers["liminal-jenkins-ci-controller"]["image_id"] = "sha256:" + "9" * 64
    end = world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])
    assert end["ok"] is False and "drift" in str(end["answer"])
    assert world.fake.containers["liminal-jenkins-ci-controller"]["state"] == "exited"


def test_a_part_built_here_is_never_made_without_its_built_image(world):
    spec = ServiceSpec.of(built_spec())
    t = world.host.targets()[0]
    with pytest.raises(Refusal, match="no image was built here for it"):
        world.host._create(t, world.host.runtime_of(t), "jenkins/ci", spec, spec.parts[0], {}, "current")
    assert world.fake.changes() == []


def test_an_expose_of_a_part_built_here_makes_it_again_from_its_built_image(world):
    world.grant()
    assert carried(world, world.plan(spec_=built_spec()))["ok"]
    built = world.fake.builds[0]["id"]
    assert carried(world, world.plan("expose", options={"lan": False}))["ok"]
    c = world.fake.containers["liminal-jenkins-ci-controller"]
    assert c["image"] == built and c["labels"]["liminal.built"] == built and len(world.fake.builds) == 1


def test_the_approve_form_is_approve_plans_arguments_in_order_and_a_stand_ins_read_is_still_a_read(world):
    import inspect

    form = next(f for f in world.page("standin-host", "status")["forms"] if f["id"] == "approve")
    params = [p for p in inspect.signature(world.host.approve_plan).parameters if p not in ("more", "named")]
    assert [f["name"] for f in form["fields"]] == params  # accept_build goes by the dialog's approve_args alone
    world.grant()
    assert world.carry("install")["ok"]
    world.fake.volumes["liminal-jenkins-ci-home"]["files"]["x.txt"] = b"kept"
    code, said, _ = world.fake(["docker", "exec", "liminal-jenkins-ci-controller", "cmd", "/c", "type",
                                "/var/jenkins_home/x.txt"], 5)
    assert (code, said) == (0, b"kept") and world.fake.execs == []
