"""1.93.0: services' networks through the firewall (machines/segments.py, netguard.py; service-containers-networking
§8): the firewall's NetworkHost on its stand-in, attached to a real apps.App beside a stand-in container plugin.
Nothing changes a route, opens a socket or starts a process; the stand-in firewall counts the elevations it would ask."""
from __future__ import annotations

import json

import pytest

from liminal_libs.apps.asking import AskRefused
from liminal_libs.apps import asking
from liminal_libs.instances import Refusal
from liminal_libs.machines import netguard
from liminal_libs.machines import segments as S

import svcworld as W

pytestmark = pytest.mark.usefixtures("no_outside")

WANT = {"stack": "wsl", "target": "wsl-ubuntu", "network": "liminal-jenkins-ci", "parts": ["controller"],
        "ports": [{"name": "web", "host": 8080, "protocol": "tcp"}], "lan": False}


@pytest.fixture
def world(tmp_path):
    return W.World(folder=tmp_path)


def _as_host(world, hook, *args):
    """The stand-in container plugin asking the firewall, as its own code does (its ask_plugin)."""
    return world.host.ask_plugin("standin-firewall", hook, *args)


def test_network_plan_is_a_granted_container_plugins_alone(world):
    with pytest.raises(Refusal, match="let it on the firewall's Networks tab"):
        _as_host(world, "network_plan", "install", "jenkins/ci", WANT)
    world.page("standin-firewall", "grant_network", "standin-host")
    with pytest.raises(AskRefused):
        world.page("standin-firewall", "network_plan", "install", "jenkins/ci", WANT)
    world.page("standin-firewall", "grant_network", "jenkins")
    with pytest.raises(Refusal, match="no container plugin"):
        world.jenkins.call("network_plan", "install", "jenkins/ci", WANT, plugin="standin-firewall")
    with asking.asking(None), pytest.raises(Refusal, match="names no asker"):
        world.firewall.network_plan("install", "jenkins/ci", WANT)
    plan = _as_host(world, "network_plan", "install", "jenkins/ci", WANT)
    assert plan["subnet"] == "10.77.1.0/24" and plan["addresses"] == {"controller": "10.77.1.10"}


def test_the_grants_the_domain_and_approval_are_the_pages_alone(world):
    for hook, args in (("grant_network", ("standin-host",)), ("set_domain", ("lan.example",)),
                       ("approve_plan", ("n-x",))):
        with pytest.raises(AskRefused):
            world.jenkins.call(hook, *args, plugin="standin-firewall")
        with asking.asking("jenkins"), pytest.raises(Refusal, match="page alone"):
            getattr(world.firewall, hook)(*args)


def test_the_firewall_hands_out_and_takes_nothing(world):
    world.page("standin-firewall", "grant_network", "standin-host")
    wrong = dict(WANT, subnet="0.0.0.0/0")
    with pytest.raises(TypeError):  # a prefix is no field of a Want: it cannot even be said
        S.Want(**wrong)
    plan = _as_host(world, "network_plan", "install", "jenkins/ci", wrong)  # an unknown key is dropped, never taken
    assert plan["subnet"].startswith("10.77.") and plan["routes"][0]["next_hop"] == "172.31.0.5"
    names = [r["name"] for r in plan["names"]]
    assert names[:2] == ["jenkins-ci.home.arpa", "controller.jenkins-ci.home.arpa"]


def test_the_pool_skips_what_this_machine_holds_and_the_halves_never_meet():
    pool = S.Pool(S.HALVES["windows"])
    got, skipped = pool.allocate(["10.77.1.0/24", "10.77.2.0/23"])
    assert got == "10.77.4.0/24" and len(skipped) == 3
    linux, _ = S.Pool(S.HALVES["linux"]).allocate([])
    assert linux.startswith("10.77.128.") and not netguard.overlaps(got, [S.HALVES["linux"]])
    with pytest.raises(Refusal, match="is clear"):
        S.Pool("10.77.0.0/23").allocate(["10.77.0.0/24", "10.77.1.0/24"])


def test_a_hop_that_moved_between_approve_and_apply_refuses_with_no_step(world):
    world.page("standin-firewall", "grant_network", "standin-host")
    plan = _as_host(world, "network_plan", "install", "jenkins/ci", WANT)
    world.page("standin-firewall", "approve_plan", plan["plan"])
    world.firewall.hop = "172.31.0.9"
    with pytest.raises(Refusal, match="next_hop"):
        _as_host(world, "apply_network", plan["plan"])
    assert world.firewall.elevations == 0


def test_a_decline_frees_its_prefix(world):
    world.page("standin-firewall", "grant_network", "standin-host")
    plan = _as_host(world, "network_plan", "install", "jenkins/ci", WANT)
    assert world.firewall._book.of_sid("jenkins/ci").state == "held"
    _as_host(world, "decline_plan", plan["plan"])
    assert world.firewall._book.of_sid("jenkins/ci") is None


def test_lan_asks_accept_lan_and_narrowing_needs_no_approval(world):
    world.page("standin-firewall", "grant_network", "standin-host")
    plan = _as_host(world, "network_plan", "install", "jenkins/ci", dict(WANT, lan=True))
    assert [a["name"] for a in plan["accepts"]] == ["accept_lan"]
    with pytest.raises(Refusal) as e:
        world.page("standin-firewall", "approve_plan", plan["plan"])
    assert e.value.accept == "accept_lan"
    world.page("standin-firewall", "approve_plan", plan["plan"], True)
    work = _as_host(world, "apply_network", plan["plan"])["work"]
    world.firewall._net.works.get(work).thread.join(10)
    assert world.firewall.elevations == 1
    gone = _as_host(world, "network_plan", "remove", "jenkins/ci", WANT)
    assert gone["narrows"] and not gone["accepts"]
    work = _as_host(world, "apply_network", gone["plan"])["work"]  # no approval asked
    world.firewall._net.works.get(work).thread.join(10)
    kinds = [s["kind"] for s in world.firewall.ran[-1]]
    assert kinds == ["unproxy", "unroute"] and world.firewall._book.of_sid("jenkins/ci").state == "removed"


def test_records_names_and_leases_after_an_install(world):
    world.installed()
    recs = world.page("standin-firewall", "name_records", "inside")["records"]
    assert {"jenkins-ci.home.arpa", "controller.jenkins-ci.home.arpa", "10.1.77.10.in-addr.arpa"} <= \
        {r["name"] for r in recs}
    assert world.page("standin-firewall", "resolve_name", "jenkins-ci.home.arpa")["addresses"] == ["10.77.1.10"]
    assert world.page("standin-firewall", "reverse_name", "10.77.1.10")["name"] == "controller.jenkins-ci.home.arpa"
    assert world.page("standin-firewall", "leases")["leases"][0]["address"] == "10.77.1.10"
    assert world.page("standin-firewall", "name_records", "lan")["records"] == []
    segs = world.jenkins.call("segments", "jenkins/ci")["segments"]
    assert segs[0]["subnets"] == ["10.77.1.0/24"] and segs[0]["members"][0]["ipv4"] == "10.77.1.10"
    for answer in (recs, segs, world.page("standin-firewall", "network_host")):
        assert json.loads(json.dumps(answer)) == answer


def test_a_stale_route_is_pointed_again_inside_the_starts_own_plan(world):
    world.installed()
    world.carry("stop")
    plan = world.plan("start")
    assert all(a["plugin"] == "standin-host" for a in plan["approve"])  # the route is current: nothing to approve
    world.page("standin-host", "decline_plan", plan["plan"])
    world.firewall.hop = "172.31.0.77"
    plan = world.plan("start")
    assert [a["plugin"] for a in plan["approve"]] == ["standin-host", "standin-firewall"]
    world.approve_all(plan)
    assert world.wait(world.jenkins.call("apply_plan", plan["plan"])["work"])["ok"]
    assert world.firewall._book.of_sid("jenkins/ci").route["next_hop"] == "172.31.0.77"


@pytest.mark.parametrize("address, word", [("10.1.2.3", "private"), ("100.64.1.1", "shared"), ("127.0.0.1", "loopback"),
                                           ("169.254.1.1", "link-local"), ("192.0.2.1", "documentation"),
                                           ("fd00::1", "private"), ("fe80::1", "link-local")])
def test_public_only_refuses_every_inside_range(address, word):
    assert word in netguard.public_only(address)


def test_public_only_takes_a_public_address():
    assert netguard.public_only("8.8.8.8") == ""


@pytest.mark.parametrize("prefix", ["0.0.0.0/0", "10.0.0.0/8", "8.8.8.0/24", "192.168.50.0/24"])
def test_a_found_segment_is_routed_only_when_private_narrow_and_clear(prefix):
    assert netguard.routable_found(prefix, ["192.168.50.0/24"]) != ""


def test_listeners_never_take_every_address_or_53():
    assert "every address" in netguard.listener_refusal("0.0.0.0", 8080)
    assert "never listened" in netguard.listener_refusal("10.77.0.53", 53)
    assert netguard.listener_refusal("10.77.0.53", 53, allowed=[("10.77.0.53", 53)]) == ""


def test_names_fit_their_labels_and_a_suite_name_is_under_linux():
    recs = S.names_for("jenkins/ci", ["controller"], "home.arpa", {"controller": "10.77.129.10"}, linux=True)
    assert recs[0].name == "jenkins-ci.linux.home.arpa"
    assert S.ptr_of("10.77.1.10") == "10.1.77.10.in-addr.arpa"
