"""Stand-ins a service plugin's tests use (1.94.0), beside machines/standins.py's: a real apps.App (`Frame`) with a
stand-in container plugin, a stand-in firewall and a stand-in WSL plugin attached around the service plugin under test
(`ServiceWorld`), so that the asker's gates are the real ones; and a job's output (`JobLog`) with the platform's
`cancelled`. Nothing here starts a process, opens a socket, pulls an image or runs WSL: the container plugin's targets
are FakeDocker's. Jenkins, GoCD and Buildbot (item 34) and the source-control servers (item 35) test on it."""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from ..apps import App, asking
from . import standins
from .containerhost import Outside
from .standins import FakeDocker, StandInHost, StandInNetworkHost, StandInWsl, target


class Frame(App):
    """An app that says which plugins are turned off (`off`), knows every plugin attached (and `known`, not
    attached), and the platform's last word on one (`states`)."""

    NAME = "frame"

    def __init__(self, login):
        super().__init__(log=lambda m: None, login=login)
        self.off: set[str] = set()
        self.known: list = []
        self.states: dict[str, dict] = {}

    def disabled(self):
        return set(self.off)

    def known_plugins(self):
        return [*self._plugins.values(), *self.known]

    def plugin_state(self, name):
        return self.states.get(name, {"name": name, "state": "unknown", "why": "", "page": f"#{name}"})


class JobLog:
    """A job's output as the platform hands it to a job hook: called with each line; `cancelled` set by Cancel."""

    def __init__(self):
        self.lines: list[str] = []
        self.cancelled = False

    def __call__(self, line):
        self.lines.append(str(line))


def quick_pace():
    """A carry's clocks for a test: a short real sleep (the container plugin's work runs in its own thread)."""
    from .containedservice import Pace

    return Pace(sleep=lambda s: time.sleep(0.005))


class ServiceWorld:
    """The service plugin under test (`service`) attached to a Frame beside a stand-in container plugin (`host`,
    named standin-host, its one target wsl-ubuntu on a FakeDocker: `fake`), a stand-in firewall (`firewall`) and a
    stand-in WSL plugin (`wsl`). `pairs`: the login's (the service's settings)."""

    HOST, TARGET, FIREWALL = "standin-host", "wsl-ubuntu", "standin-firewall"

    def __init__(self, service, pairs=None, ready=True, firewall=True, health=None, folder=None, reach="127.0.0.1"):
        self.login = standins.login(dict(pairs or {}))
        self.app = Frame(self.login)
        self.fake = FakeDocker()
        t = (target(reach=reach) if ready else
             target(state="stopped", why="Liminal-Ubuntu is stopped, and a look never starts it", reach=reach))
        out = Outside(sleep=lambda s: None, health=health or (lambda h, p, path: True), platform="windows::TEST",
                      holders=lambda port: [], folder=Path(folder) if folder else Path(tempfile.mkdtemp(
                          prefix="liminal-standin-")))
        self.host = StandInHost({self.TARGET: (t, self.fake)}, outside=out)
        self.firewall = StandInNetworkHost() if firewall else None
        self.wsl = StandInWsl()
        self.service = service
        for p in (self.host, self.firewall, self.wsl, service):
            if p is not None:
                self.app.attach(p)

    def page(self, plugin, hook, *args, **kwargs):
        """A hook asked as the page."""
        with asking.asking(asking.PAGE):
            return self.app.ask(plugin, hook, *args, **kwargs)

    def ask(self, hook, *args, **kwargs):
        """The service plugin's hook asked as the page."""
        return self.page(self.service.name, hook, *args, **kwargs)

    def grant(self):
        self.page(self.HOST, "grant_service", self.service.name, self.TARGET)
        if self.firewall is not None and self.HOST not in self.firewall.network_grants():
            self.page(self.FIREWALL, "grant_network", self.HOST)
        self.service._forget_hosts()

    def approve(self, answer, **refuse):
        """Every plan of an approval answer approved as the page, each accept it needs True (those named in `refuse`
        False)."""
        for a in answer["approve"]:
            words = self.page(a["plugin"], "plan_words", a["plan"])
            needed = {x["name"] for x in words["accepts"]}
            self.page(a["plugin"], "approve_plan", a["plan"],
                      *[(k in needed and not refuse.get(k, False)) for k in words["approve_args"]])

    def carry(self, answer, log=None):
        """The answer's job (service_carry) run as the page, as the platform's job runs it."""
        then = answer["then"]
        return self.ask(then["hook"], *then["args"], log=log if log is not None else JobLog())

    def through(self, answer, log=None):
        """Approved, then carried out."""
        self.approve(answer)
        return self.carry(answer, log)

    def install(self, *args):
        """Granted, then Install… on the stand-in target approved and carried out."""
        self.grant()
        return self.through(self.ask("service_install", self.HOST, self.TARGET, *args))


__all__ = ["Frame", "JobLog", "ServiceWorld", "quick_pace"]
