"""The stand-in world the service interface's tests share (1.93.0): a real apps.App with a stand-in container
plugin, a stand-in firewall, a stand-in WSL plugin and two stand-in service plugins attached, so that the asker's
gates are the real ones. Nothing here starts a process or opens a socket."""
from __future__ import annotations

import copy

from liminal_libs.apps import App
from liminal_libs.apps import asking
from liminal_libs.machines import standins
from liminal_libs.machines.standins import (FakeDocker, ServiceOwner, StandInHost, StandInNetworkHost, StandInWsl,
                                            target)

DIG = "sha256:" + "a" * 64
SECRET = "canary-Vx93-never-shown"


class Frame(App):
    NAME = "frame"

    def __init__(self, login):
        super().__init__(log=lambda m: None, login=login)
        self.off: set[str] = set()

    def disabled(self):
        return set(self.off)

    def known_plugins(self):
        return list(self._plugins.values())


def spec(owner="jenkins", name="ci", lan=True, host=8080, secrets=(), seeds=(), tar=True, digest=DIG, env=None,
         parts=None):
    part = {"name": "controller",
            "image": {"ref": "docker.io/jenkins/jenkins:2.528.2-lts-jdk21", "digest": digest, "system": "linux",
                      "platforms": ["linux/amd64"], "size": 300_000_000, "licence": "MIT", "tar": tar},
            "ports": [{"name": "web", "container": 8080, "host": host, "lan": lan, "about": "its pages"}],
            "volumes": [{"name": "home", "path": "/var/jenkins_home", "holds": "its jobs and history", "owner": 1000}],
            "env": dict(env if env is not None else {"JAVA_OPTS": "-Dhudson.model.UsageStatistics.disabled=true"}),
            "secrets": list(secrets), "seeds": list(seeds),
            "readable": [{"name": "unlock", "volume": "home", "path": "secrets/initialAdminPassword",
                          "about": "its unlock password"}],
            "memory": 2 << 30, "health": {"port": "web", "path": "/login", "ready_s": 30}}
    return {"owner": owner, "name": name, "title": owner.capitalize(), "system": "linux",
            "parts": parts if parts is not None else [part]}


class World:
    def __init__(self, pairs=None, firewall=True, ready=True, wsl_holds=True, health=None, folder=None):
        self.login = standins.login({"JENKINS_ADMIN_PASSWORD": SECRET, **dict(pairs or {})})
        self.app = Frame(self.login)
        self.fake = FakeDocker()
        t = target() if ready else target(state="stopped", why="Liminal-Ubuntu is stopped, and a look never starts it")
        out = standins.Outside(sleep=lambda s: None, health=health or (lambda h, p, path: True),
                               platform="windows::TEST", holders=lambda port: self.holders.get(port, []),
                               folder=folder)
        self.holders: dict = {}
        self.host = StandInHost({"wsl-ubuntu": (t, self.fake)}, outside=out)
        self.firewall = StandInNetworkHost() if firewall else None
        self.wsl = StandInWsl() if wsl_holds else None
        self.jenkins, self.gocd = ServiceOwner("jenkins"), ServiceOwner("gocd")
        for p in (self.host, self.firewall, self.wsl, self.jenkins, self.gocd):
            if p is not None:
                self.app.attach(p)

    def page(self, plugin, hook, *args):
        with asking.asking(asking.PAGE):
            return self.app.ask(plugin, hook, *args)

    def grant(self, plugin="jenkins", tid="wsl-ubuntu"):
        self.page("standin-host", "grant_service", plugin, tid)
        if self.firewall is not None and "standin-host" not in self.firewall.network_grants():
            self.page("standin-firewall", "grant_network", "standin-host")

    def plan(self, action="install", sid="jenkins/ci", spec_=None, target_id="wsl-ubuntu", options=None, who=None):
        s = spec() if spec_ is None and action == "install" else spec_
        return (who or self.jenkins).call("service_plan", action, sid, s, target_id if action == "install" else "",
                                          options or {})

    def approve_all(self, plan, **accepts):
        yes = {**standins.ACCEPTS_ALL, **accepts}
        for a in plan["approve"]:
            words = self.page(a["plugin"], "plan_words", a["plan"])
            order = standins._ACCEPT_ORDER[a["plugin"] == "standin-host"]
            needed = {x["name"] for x in words["accepts"]}
            self.page(a["plugin"], "approve_plan", a["plan"], *[yes.get(k, False) if k in needed else False
                                                                 for k in order])

    def wait(self, work, who=None):
        w = self.host._svc.works.get(work)
        w.thread.join(20)
        assert not w.thread.is_alive(), "the work never ended"
        return (who or self.jenkins).call("service_work", work, 0)

    def carry(self, action="install", spec_=None, options=None, **accepts):
        plan = self.plan(action, spec_=spec_, options=options)
        self.approve_all(plan, **accepts)
        work = self.jenkins.call("apply_plan", plan["plan"])["work"]
        return self.wait(work)

    def installed(self):
        self.grant()
        end = self.carry("install")
        assert end["ok"], end
        return end


def newer(s=None):
    s = copy.deepcopy(s or spec())
    for p in s["parts"]:
        p["image"]["digest"] = "sha256:" + "b" * 64
    return s
