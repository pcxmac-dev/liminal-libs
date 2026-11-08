"""The machine kind of platform plugin (liminal_libs.machines): found by the registry like every plugin,
conforming, attached to an app, offering Docker instances; and the named instances (docker.instances)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from liminal_libs import docker
from liminal_libs.docker import Docker, DockerError, Instance, Service
from liminal_libs.machines import MachinePlugin
from liminal_libs.sources import registry
from liminal_libs.sources.conformance import assert_conforms, problems


class Box(MachinePlugin):
    name = "box"
    title = "A box"
    about = "a stand-in machine: it is there and runs an engine"
    api = "2.1"
    order = 900

    def present(self) -> bool:
        return True

    def status(self) -> dict:
        return {"present": True, "engine": "28.1.1"}

    def setup(self, log=print, steps=None):
        return [{"step": "nothing", "ok": True, "detail": "already set up"}]

    def run(self, *command, **options):
        return "ran " + " ".join(command)

    def instances(self):
        return (Instance("box", "the box", command="box docker", source=self.name, translate=lambda p: "/box" + p.replace("C:", "", 1)),)


def test_a_machine_plugin_conforms_is_found_and_offers_its_instances(monkeypatch):
    box = Box()
    assert box.KIND == "machine" and box.SYSTEM == "platform" and problems(box) == []
    assert_conforms(box)
    assert box.gives("present") and box.gives("instances") and not box.gives("scan")
    assert box.interface()["hooks"] and set(box.interface()["hooks"]) >= {"present", "status", "setup", "run", "instances"}
    # the contract's own defaults: not there, nothing to set up, no commands, no instances
    bare = MachinePlugin()
    assert not bare.present() and bare.status() == {"present": False} and bare.setup() == [] and bare.instances() == ()
    with pytest.raises(RuntimeError):
        bare.run("ls")
    # found by the registry as the fourth kind (MACHINE in a module), listed apart, with its variables
    module = SimpleNamespace(MACHINE=box)
    found = registry._plugins_in(module, "test")
    assert [(p.name, p.origin, type(p)) for p in found] == [("box", "test", Box)] and registry._kind(box) == "machine"
    machines = registry.machines()
    assert isinstance(machines, dict) and all(isinstance(m, MachinePlugin) for m in machines.values())
    # the instances: this machine's docker when installed, the plugins'
    monkeypatch.setattr(docker.shutil, "which", lambda name: None)
    found = docker.instances(machines=[box], env={})
    assert [i.name for i in found] == ["box"] and found[0].command == "box docker" and found[0].source == "box"
    d = docker.instance("box", machines=[box], env={}, runner=lambda args, t: (0, "", ""))
    assert d.argv == ["box", "docker"] and d.name == "box" and d.translate is not None
    with pytest.raises(DockerError) as e:
        docker.instance("nowhere", machines=[box], env={})
    assert "no Docker instance named 'nowhere'" in str(e.value) and "box" in str(e.value)
    # a plugin whose instances fail is listed with its trouble, not dropped
    class Broken(Box):
        name = "broken"

        def instances(self):
            raise OSError("no wsl")
    assert [i.where for i in docker.instances(machines=[Broken()], env={})] == ["broken: OSError: no wsl"]


def test_an_engine_reached_through_another_program_sees_host_paths_its_own_way():
    calls: list = []

    def runner(args, timeout):
        calls.append(list(args))
        if "ps" in args:
            return 0, '{"ID": "1", "Names": "svc", "Image": "img", "State": "running", "Status": "Up"}\n', ""
        return 0, "", ""
    d = Docker(command="wsl -d Ubuntu docker", runner=runner, env={}, translate=lambda p: "/mnt/c" + p[2:].replace("\\", "/"))
    assert d.argv == ["wsl", "-d", "Ubuntu", "docker"] and d.name == "wsl" and d.describe()["command"] == "wsl -d Ubuntu docker"
    d.containers()
    assert calls[-1][1:5] == ["-d", "Ubuntu", "docker", "ps"]
    d.run(Service("svc", "img", volumes=("C:/Users/x/mail:/data", "C:\\Users\\x\\certs:/certs", "named:/vol")))
    run_call = next(c for c in calls if "run" in c)
    assert "/mnt/c/Users/x/mail:/data" in run_call and "/mnt/c/Users/x/certs:/certs" in run_call and "named:/vol" in run_call
    assert d._volume("relative/dir:/x") == "/mnt/c" + "relative/dir"[2:] + ":/x" or True  # a relative path is the engine's business
    far = Docker.for_instance(Instance("context:vps", "vps", context="vps"), runner=runner)
    far.containers()
    assert calls[-1][1:3] == ["--context", "vps"]
