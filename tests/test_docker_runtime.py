"""1.93.0: DockerRuntime, the docker command's mapping of the service interface, on a FakeDocker alone."""
from __future__ import annotations

import json

import pytest

from liminal_libs.instances import Refusal
from liminal_libs.machines import containers as C
from liminal_libs.machines.containerhost import Create
from liminal_libs.machines.dockerruntime import DockerRuntime, bridge_name
from liminal_libs.machines.standins import FakeDocker

import svcworld as W

pytestmark = pytest.mark.usefixtures("no_outside")


def _rt(fake=None, **kw):
    fake = fake or FakeDocker()
    return DockerRuntime(["wsl", "-d", "Liminal-Ubuntu", "--exec", "docker"], fake, fake.stream,
                         version=fake.version, wsl=True, **kw), fake


def _create(rt, spec=None, **kw):
    s = C.ServiceSpec.of(spec or W.spec(seeds=[{"volume": "home", "path": "a.cfg", "text": "x" * 100}]))
    part = s.parts[0]
    c = Create(C.container_name(s.sid, part.name), part, C.labels(s, part.name, "current", "windows::T", "now"),
               ((C.volume_name(s.sid, "home"), "/var/jenkins_home"),), part.ports, dict(part.env), kw.get("secrets", {}))
    rt.create(c)
    return s


def test_every_command_goes_through_the_engines_prefix():
    rt, fake = _rt()
    _create(rt)
    assert all(c["argv"][:5] == ["wsl", "-d", "Liminal-Ubuntu", "--exec", "docker"] for c in fake.calls)


def test_the_label_holds_the_spec_without_its_seeds_texts():
    rt, fake = _rt()
    s = _create(rt)
    labels = fake.containers["liminal-jenkins-ci-controller"]["labels"]
    held = json.loads(labels["liminal.spec"])
    assert held["parts"][0]["seeds"][0]["text"] == "" and labels["liminal.spec-sha"] == s.sha()
    rows = rt.hosted()
    assert rows[0]["sid"] == "jenkins/ci" and rows[0]["parts"][0]["role"] == "current"


def test_a_renamed_container_is_read_back_as_the_previous():
    rt, fake = _rt()
    _create(rt)
    rt.rename("liminal-jenkins-ci-controller", "liminal-jenkins-ci-controller-previous")
    assert rt.hosted()[0]["parts"][0]["role"] == "previous"


def test_a_command_line_too_long_is_refused_in_words():
    rt, fake = _rt()
    with pytest.raises(Refusal, match="longer than"):
        _create(rt, W.spec(env={f"K{i}": "v" * 4000 for i in range(9)}))
    assert fake.calls == []


def test_logs_are_merged_in_the_order_written():
    rt, fake = _rt()
    _create(rt)
    fake.logs["liminal-jenkins-ci-controller"] = ["2026-11-25T10:00:02Z second", "2026-11-25T10:00:01Z first"]
    assert rt.logs("liminal-jenkins-ci-controller", 10) == ["10:00:01 first", "10:00:02 second"]


def test_a_stopped_containers_file_is_read_through_cp():
    rt, fake = _rt()
    _create(rt)
    fake.volumes["liminal-jenkins-ci-home"]["files"]["secrets/p"] = b"pw"
    assert rt.read("liminal-jenkins-ci-controller", "/var/jenkins_home/secrets/p", 100) == b"pw"
    assert fake.argv_of("cp")[-1][-2:] == ["liminal-jenkins-ci-controller:/var/jenkins_home/secrets/p", "-"]


def test_the_bridge_name_fits_linux():
    assert len(bridge_name("liminal-" + "x" * 60)) == 15


def test_a_volume_of_another_service_is_never_made_over():
    rt, fake = _rt()
    fake.volumes["liminal-jenkins-ci-home"] = {"labels": {"liminal.service": "gocd/ci"}, "files": {}}
    with pytest.raises(Refusal, match="is not jenkins/ci's"):
        rt.make_volume("liminal-jenkins-ci-home", C.volume_labels("jenkins/ci", "home", "p", "now"))


def test_remove_never_takes_the_volumes():
    rt, fake = _rt()
    _create(rt)
    rt.remove("liminal-jenkins-ci-controller")
    assert fake.argv_of("rm")[-1][-2:] == ["rm", "liminal-jenkins-ci-controller"]
    assert "liminal-jenkins-ci-home" in fake.volumes
