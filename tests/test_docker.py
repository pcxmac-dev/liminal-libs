"""Docker in the framework (liminal_libs.docker): a service as docker run would make it, the containers as
docker ps lists them, the driver's commands through a stand-in runner, what it says when Docker is not
there, and where it runs (a context, a host)."""
from __future__ import annotations

import json

import pytest

from liminal_libs import docker
from liminal_libs.docker import Container, Docker, DockerError, Service

PS_ROWS = [{"ID": "abc123", "Names": "liminal-mail-example-test", "Image": "foxcpp/maddy:latest", "State": "running",
            "Status": "Up 3 minutes (healthy)", "Ports": "0.0.0.0:25->25/tcp"},
           {"ID": "def456", "Names": "old-db", "Image": "mongo:9", "State": "exited", "Status": "Exited (0) 2 hours ago", "Ports": ""}]
VERSION = {"Client": {"Version": "28.1.1"}, "Server": {"Version": "28.1.1", "Os": "linux", "Arch": "amd64"}}


class Runner:
    """Answers the docker command: records every call."""

    def __init__(self, rows=None, version=VERSION, fail=()):
        self.calls: list[list[str]] = []
        self.rows = list(rows if rows is not None else PS_ROWS)
        self.version = version
        self.fail = set(fail)

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        verb = next((a for a in args[1:] if not a.startswith("-") and a not in (self.calls[-1][2] if len(args) > 2 else "",)), "")
        verb = [a for a in args[1:] if a not in ("--context", "-H") and (len(self.calls[-1]) < 3 or a not in self.calls[-1][2:3] or True)]
        verb = next((a for a in args[1:] if not a.startswith("-")), "")
        if args[1] in ("--context", "-H"):
            verb = args[3]
        if verb in self.fail:
            return 1, "", f"Error response from daemon: {verb} failed"
        if verb == "version":
            return 0, json.dumps(self.version), ""
        if verb == "ps":
            return 0, "\n".join(json.dumps(r) for r in self.rows) + "\n", ""
        if verb == "run":
            name = args[args.index("--name") + 1]
            self.rows.append({"ID": "new789", "Names": name, "Image": args[-1], "State": "running", "Status": "Up 1 second", "Ports": ""})
            return 0, "new789\n", ""
        if verb == "start":
            for r in self.rows:
                if r["Names"] == args[-1]:
                    r["State"], r["Status"] = "running", "Up 1 second"
            return 0, "", ""
        if verb == "stop":
            for r in self.rows:
                if r["Names"] == args[-1]:
                    r["State"], r["Status"] = "exited", "Exited (0) 1 second ago"
            return 0, args[-1] + "\n", ""
        if verb == "rm":
            self.rows = [r for r in self.rows if r["Names"] != args[-1]]
            return 0, "", ""
        if verb == "logs":
            return 0, "maddy started\n", ""
        if verb == "exec":
            return 0, "ok from inside\n", ""
        if verb == "inspect":
            return 0, json.dumps([{"State": {"Status": "running", "Health": {"Status": "healthy"}}}]), ""
        if verb == "pull":
            return 0, "Status: Image is up to date\n", ""
        if verb == "compose":
            return 0, "composed\n", ""
        return 1, "", f"unknown {verb}"


def test_a_service_is_what_docker_run_would_make_and_a_container_what_docker_ps_lists():
    s = Service("liminal-mail-example-test", "foxcpp/maddy:latest", ports=("25:25", "127.0.0.1:993:993"), env={"MADDY_HOSTNAME": "mx.example.test"},
                volumes=("C:/data/mail:/data",), hostname="mx.example.test", command=("run", "--debug"), labels={"liminal.login": "example.test"})
    assert s.run_args() == ["run", "-d", "--name", "liminal-mail-example-test", "--restart", "unless-stopped", "--hostname", "mx.example.test",
                            "-p", "25:25", "-p", "127.0.0.1:993:993", "-e", "MADDY_HOSTNAME=mx.example.test", "-v", "C:/data/mail:/data",
                            "--label", "liminal=service", "--label", "liminal.login=example.test", "foxcpp/maddy:latest", "run", "--debug"]
    assert docker.command_line(s).startswith("docker run -d --name liminal-mail-example-test") and s.describe()["env"] == ["MADDY_HOSTNAME"]
    c = Container.from_ps(PS_ROWS[0])
    assert c.running and c.name == "liminal-mail-example-test" and c.describe()["status"] == "Up 3 minutes (healthy)"
    assert not Container.from_ps(PS_ROWS[1]).running


def test_the_driver_runs_the_docker_command_on_this_machine_or_where_a_context_says():
    runner = Runner()
    d = Docker(runner=runner, env={})
    assert d.where == "this machine" and d.installed() and d.available()
    assert d.version() == {"client": "28.1.1", "engine": "28.1.1", "os": "linux", "arch": "amd64", "where": "this machine"}
    assert runner.calls[-1][1:] == ["version", "--format", "{{json .}}"]
    assert [c.name for c in d.containers()] == ["liminal-mail-example-test", "old-db"] and [c.name for c in d.containers(all=False)] == ["liminal-mail-example-test", "old-db"]
    assert runner.calls[-1][1:] == ["ps", "--no-trunc", "--format", "{{json .}}"] and runner.calls[-2][1:4] == ["ps", "-a", "--no-trunc"]
    assert d.container("old-db").state == "exited" and d.container("nothing") is None
    # ensure: made when absent, started when stopped, left when running
    s = Service("liminal-mail-new-test", "foxcpp/maddy:latest")
    made, what = d.ensure(s)
    assert what == "made" and made.name == "liminal-mail-new-test" and made.running and runner.calls[-2][1:4] == ["run", "-d", "--name"]
    assert d.ensure(s)[1] == "running"
    assert d.ensure(Service("old-db", "mongo:9"))[1] == "started" and d.container("old-db").running
    assert d.stop("old-db") and not d.container("old-db").running and runner.calls[-2][1:] == ["stop", "-t", "20", "old-db"]
    assert not d.stop("nothing") and d.remove("old-db") and d.container("old-db") is None and not d.remove("old-db")
    assert d.logs("liminal-mail-new-test", tail=5) == "maddy started\n" and runner.calls[-1][1:] == ["logs", "--tail", "5", "liminal-mail-new-test"]
    assert d.exec("liminal-mail-new-test", "maddy", "creds", "list") == "ok from inside\n" and runner.calls[-1][1:] == ["exec", "liminal-mail-new-test", "maddy", "creds", "list"]
    assert d.health("liminal-mail-new-test") == "healthy" and d.pull("foxcpp/maddy:latest").startswith("Status") and d.compose("x.yml", "up", "-d") == "composed\n"
    assert runner.calls[-1][1:] == ["compose", "-f", "x.yml", "up", "-d"]
    assert d.describe()["available"] is True and d.describe()["engine"] == "28.1.1"
    # elsewhere: a context, or a host, in every command
    far = Docker(context="vps", runner=runner, env={})
    far.containers()
    assert far.where == "context vps" and runner.calls[-1][1:3] == ["--context", "vps"]
    host = Docker(runner=runner, env={"LIMINAL_DOCKER_HOST": "ssh://me@vps.example.test"})
    host.containers()
    assert host.where == "host ssh://me@vps.example.test" and runner.calls[-1][1:3] == ["-H", "ssh://me@vps.example.test"]


def test_what_is_said_when_docker_fails_or_is_not_there(monkeypatch):
    failing = Runner(fail={"run", "version"})
    d = Docker(runner=failing, env={})
    assert not d.available() and "problem" in d.describe() and "no Docker engine answers" not in d.describe()["problem"]
    with pytest.raises(DockerError) as e:
        d.run(Service("x", "img"))
    assert "run failed" in str(e.value)
    no_engine = Docker(runner=Runner(version={"Client": {"Version": "28.1.1"}}), env={})
    assert not no_engine.available() and "no Docker engine answers on this machine" in no_engine.describe()["problem"]
    monkeypatch.setattr(docker.shutil, "which", lambda name: None)
    absent = Docker(env={})
    assert not absent.installed() and not absent.available()
    assert absent.describe() == {"where": "this machine", "command": "docker", "installed": False, "available": False}
    with pytest.raises(DockerError) as e:
        absent.containers()
    assert "docker is not installed" in str(e.value) and "nerdctl" in str(e.value)
    # Rancher Desktop with containerd: the command is nerdctl, named in the environment or outright
    monkeypatch.setattr(docker.shutil, "which", lambda name: "C:/Rancher/nerdctl.exe" if name == "nerdctl" else None)
    rancher = Docker(env={"LIMINAL_DOCKER_COMMAND": "nerdctl"}, runner=Runner())
    assert rancher.name == "nerdctl" and rancher.installed() and rancher.available() and rancher.describe()["command"] == "nerdctl"
    assert Docker(command="nerdctl", env={}).command == "C:/Rancher/nerdctl.exe" and docker.command_line(Service("x", "img"), "nerdctl").startswith("nerdctl run")
