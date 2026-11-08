"""The firewall base of the platform's plugins (liminal_libs.machines.firewall): a rule as the framework sees
it, the framework's own ports, the ports a mail server container publishes, the rules a login's services
need, and the base's status and setup over a stand-in firewall."""
from __future__ import annotations

import pytest

from liminal_libs.apps import Scope
from liminal_libs.machines.firewall import (APP_PORTS, Firewall, FirewallError, FirewallNotNeeded, Rule, app_ports, host_port,
                                            service_rules)
from liminal_libs.machines.plugin import CommandError
from liminal_libs.sources.conformance import problems


class FakeFirewall(Firewall):
    name = "fake-firewall"
    title = "A stand-in firewall"
    about = "rules kept in memory"
    api = "2.1"
    order = 950

    def __init__(self, profiles=None, exposed=(), can=True, need=()):
        self.profiles = dict(profiles if profiles is not None else {"Domain": True, "Private": True, "Public": True})
        self.rules: dict[str, Rule] = {}
        self.exposed = list(exposed)
        self.can = can
        self.need = list(need)
        self.enabled_calls = 0
        self.denied = False

    def present(self) -> bool:
        return True

    def backend(self) -> str:
        return "the stand-in"

    def state(self) -> dict:
        return {"enabled": bool(self.profiles) and all(self.profiles.values()), "profiles": dict(self.profiles)}

    def list_rules(self, owned_only=True):
        return list(self.rules.values())

    def add_rule(self, rule):
        if self.denied:
            raise FirewallError("this needs an administrator", denied=True)
        self.rules[rule.name] = rule

    def delete_rule(self, name):
        return self.rules.pop(name, None) is not None

    def enable(self):
        self.enabled_calls += 1
        self.profiles = {k: True for k in self.profiles}

    def can_enable(self):
        return self.can

    def exposing(self, ports):
        return [(p, label) for p, label in self.exposed if p in ports]

    def wanted(self):
        return list(self.need)


def test_a_rule_as_the_framework_sees_it():
    r = Rule("mail-example-test", ports=(25, 587), detail="the mail server")
    assert r.label == "Liminal: mail-example-test" and r.describe()["ports"] == [25, 587] and r.describe()["owned"] is True
    for bad in (dict(name="Bad Name"), dict(name="ok", ports=(0,)), dict(name="ok", ports=(70000,)), dict(name="ok", protocol="icmp"),
                dict(name="ok", direction="sideways"), dict(name="ok", action="maybe"), dict(name="ok", ports=(25,), protocol="any")):
        with pytest.raises(ValueError):
            Rule(**bad)
    theirs = Rule("Remote Desktop - User Mode (TCP-In)", ports=(3389,), protocol="any", owned=False)
    assert theirs.label == "Remote Desktop - User Mode (TCP-In)"  # another's rule: read as it is


def test_the_frameworks_ports_and_what_a_container_publishes():
    assert app_ports({}) == {a: p for a, _, p in APP_PORTS}
    assert app_ports({"LIMINAL_CHARTS_PORT": "9000", "LIMINAL_LOGIN_PORT": "x"})["charts"] == 9000
    assert app_ports({"LIMINAL_LOGIN_PORT": "x"})["login"] == 8795
    cases = {"25:25": 25, "0.0.0.0:587:587": 587, "127.0.0.1:8025:25": None, "localhost:8025:25": None, "25": None,
             "[::]:993:993": 993, "[::1]:8993:993": None, "8000-8010:8000-8010": None, "a:b:c:d": None}
    assert {spec: host_port(spec) for spec in cases} == cases


def test_the_rules_a_logins_services_need_on_this_machine(tmp_path):
    text = ("[login]\nscope = https://example.test\nadmin = admin@liminal.example.test\n\n[server]\nimage = foxcpp/maddy:0.8\n"
            "ports = 25:25, 587:587, 127.0.0.1:8080:80, 0.0.0.0:993:993\n")
    (rule,) = service_rules(Scope.parse(text))
    assert rule.name == "mail-example-test" and rule.ports == (25, 587, 993) and rule.protocol == "tcp" and "example.test" in rule.detail
    assert service_rules(Scope.parse(text + "instance = wsl-ubuntu\n"))[0].ports == (25, 587, 993)  # a machine plugin's engine: this machine
    for elsewhere in ("context = vps\n", "host = ssh://me@vps.example.test\n", "instance = context:vps\n"):
        assert service_rules(Scope.parse(text + elsewhere)) == []  # another machine's engine, behind its own firewall
    assert service_rules(Scope.local(tmp_path)) == [] and service_rules(Scope.for_domain("example.test")) == []


def test_the_firewall_plugin_conforms_and_reports():
    fw = FakeFirewall()
    assert problems(fw) == [] and fw.STEPS == ("enable", "exposure", "rules") and fw.KIND == "machine"
    assert {"allow", "remove", "wanted", "status", "setup"} <= set(fw.interface()["hooks"])  # asked by name (Plugin.ask)
    assert fw.ask("allow", "asked", [9000]).name == "asked" and fw.ask("remove", "asked") is True
    fw.allow("web", (8443,), detail="a test")
    with pytest.raises(FirewallError):
        fw.allow("web", (8443,))
    st = fw.status()
    assert st["present"] and st["enabled"] and st["rules"][0]["label"] == "Liminal: web"
    assert st["summary"] == "the stand-in: on (Domain, Private, Public on); 1 Liminal rule(s)"
    assert st["valid"] is True and st["why"] == "" and fw.scope() == (True, "this machine")  # on, with Liminal's rules
    assert fw.remove("web") and not fw.remove("web")
    assert fw.status()["valid"] is False and fw.status()["why"].startswith("no Liminal rules")  # nothing of Liminal's here
    fw.profiles["Public"] = False
    assert fw.status()["summary"] == "the stand-in: off (Domain, Private on; Public off); 0 Liminal rule(s)"
    assert fw.status()["why"] == "off: its setup turns it on"


def test_the_setup_turns_it_on_finds_exposure_and_adds_the_services_rules():
    need = [Rule("mail-example-test", ports=(25, 587), detail="mail")]
    fw = FakeFirewall(profiles={"Domain": True, "Private": True, "Public": False}, exposed=[(8765, "Python (all ports)")], need=need)
    lines: list[str] = []
    done = fw.setup(log=lines.append)
    assert [(d["step"], d["ok"]) for d in done] == [("enable", True), ("exposure", False), ("rules", True)]
    assert fw.enabled_calls == 1 and "Public" in done[0]["detail"] and "charts (8765) by Python (all ports)" in done[1]["detail"]
    assert "Liminal: mail-example-test (25, 587/tcp in)" in done[2]["detail"] and "mail-example-test" in fw.rules
    again = fw.setup(log=lines.append)
    assert [(d["step"], d["ok"]) for d in again] == [("enable", None), ("exposure", False), ("rules", None)]
    fw.exposed = []
    assert fw.setup(log=lines.append, steps=("exposure",)) == [{"step": "exposure", "ok": True, "detail": fw.setup(log=lines.append, steps=("exposure",))[0]["detail"]}]
    # nothing needed; no switch; off: said, not failed
    assert FakeFirewall().setup(log=lines.append, steps=("rules",))[0]["ok"] is None
    off = FakeFirewall(profiles={"nftables": False}, can=False)
    assert [(d["step"], d["ok"]) for d in off.setup(log=lines.append, steps=("enable", "exposure"))] == [("enable", None), ("exposure", None)]
    # a refusal ends it with the firewall's words
    denied = FakeFirewall(need=need)
    denied.denied = True
    out = denied.setup(log=lines.append, steps=("rules",))
    assert out == [{"step": "rules", "ok": False, "detail": "this needs an administrator"}]
    assert issubclass(FirewallError, CommandError) and issubclass(FirewallNotNeeded, FirewallError)


def test_on_a_target_not_liminals_the_firewall_asks_nothing_and_changes_nothing():
    """The user's own distribution is never taken: its status and setup run no command there."""
    from liminal_libs.machines.linux import Shell

    ran: list = []
    fw = FakeFirewall()
    fw.shell = Shell("wsl:Ubuntu", runner=lambda args, timeout: ran.append(args) or (0, b"", b""))
    st = fw.status()
    assert (st["present"], st["valid"], st["summary"]) == (False, False, "not on Liminal's") and "is not Liminal's" in st["why"]
    done = fw.setup(log=lambda m: None)
    assert [d["ok"] for d in done] == [False] and ran == []


def test_a_firewall_not_for_this_machine_asks_nothing_and_changes_nothing():
    """Not for this machine at all (the Linux firewall on Windows or in WSL; 1.27.0): applies False, nothing asked."""
    fw = FakeFirewall()
    fw.not_for_here = lambda: "for a native Linux machine"
    fw.backend = fw.state = fw.list_rules = fw.enable = fw.present = lambda *a: pytest.fail("asked")
    assert fw.status() == {"present": False, "backend": "", "enabled": False, "profiles": {}, "rules": [], "summary": "not for this machine",
                           "valid": False, "why": "for a native Linux machine", "applies": False}
    assert fw.setup(log=lambda m: None) == [{"step": "enable", "ok": False, "detail": "for a native Linux machine"}]
    assert fw.rules == {} and fw.enabled_calls == 0
