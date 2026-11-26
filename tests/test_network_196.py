"""1.96.0: the firewall's own release on the library's side (service-containers-networking §7 to §9): the network
database (netbook.py), the DHCP records and found containers' reverse names, no domain until you set one (N12), an
Expose's details from the firewall, the Networks tab and the page's own changes; and the WSL base's holds, WSL's one
network, the one-engine check and the guarded Uninstall. Stand-ins alone: nothing starts, no route changes, no wsl."""
from __future__ import annotations

import os

import pytest

from liminal_libs import netbook
from liminal_libs.apps import asking
from liminal_libs.apps.asking import AskRefused
from liminal_libs.instances import Refusal
from liminal_libs.machines import segments as S
from liminal_libs.machines import standins, wsl as wsl_mod
from liminal_libs.machines.wsl import Asked, UninstallRefused, Wsl

import svcworld as W
from test_wsl import FakeWsl, UbuntuLike

pytestmark = pytest.mark.usefixtures("no_outside", "stand_in_environment")


class Firewall(standins.StandInNetworkHost):
    DOMAIN_DEFAULT = None  # a firewall plugin's: no domain until you set one

    def __init__(self, book=None):
        super().__init__(book=book)
        self.made: list[dict] = []

    def lan_detail(self, sid, port, address):
        return {"listen": "192.168.50.228", "connect": address, "words": f"192.168.50.228 to {address}"}

    def made_here(self):
        return list(self.made)

    def leftover_steps(self, item):
        return [S.Step("unroute", f"{item['words']} taken away", item["detail"])]


def world(tmp_path, book=None, domain="home.arpa"):
    w = W.World(folder=tmp_path, firewall=False, pairs={S.DOMAIN_VAR: domain} if domain else None)
    w.firewall = Firewall(book=book)
    w.app.attach(w.firewall)
    return w


# -- the network database ---------------------------------------------------------------------------------------------
def _allocation(sid="jenkins/ci", state="made"):
    return S.Allocation("10.77.1.0/24", "wsl", "standin-host/wsl-ubuntu/liminal-jenkins-ci", sid, "standin-host",
                        "windows::TEST", "10.77.1.1", {"controller": "10.77.1.10"}, state)


def test_the_network_database_is_made_by_a_write_alone_and_keeps_what_it_is_given(tmp_path):
    f = tmp_path / "network" / "network.db"
    book = netbook.NetBook(f)
    assert book.all() == [] and book.of_sid("jenkins/ci") is None and book.members() == [] and not f.exists()
    book.put(_allocation(state="held"))
    assert not f.exists() and book.of_sid("jenkins/ci").state == "held"  # a plan's hold: memory alone
    book.put(_allocation())
    again = netbook.NetBook(f)
    assert again.of_sid("jenkins/ci").addresses == {"controller": "10.77.1.10"}
    if os.name != "nt":
        assert (f.stat().st_mode & 0o777) == 0o600 and (f.parent.stat().st_mode & 0o777) == 0o700
    again.free("jenkins/ci")
    assert again.of_sid("jenkins/ci") is None and again.all() == []
    assert again._read("SELECT state FROM allocations") == [("freed",)]  # marked, never deleted


def test_records_end_gone_and_only_forget_takes_them_away(tmp_path):
    book = netbook.NetBook(tmp_path / "n.db")
    m = S.Member("", "", "web-1", "web-1", "02:42:ac:11:00:02", "172.17.0.2", assigned="docker", running=True)
    book.seen([("docker/wsl-ubuntu/bridge", m)], {"docker/wsl-ubuntu/bridge"}, 100.0)
    book.seen([], {"docker/wsl-ubuntu/bridge"}, 200.0)
    (row,) = book.members()
    assert row["state"] == "gone" and row["gone"] == 200.0 and row["since"] == 100.0
    assert book.forget_members() == 1 and book.members() == []


def test_another_systems_drive_is_never_written(tmp_path, monkeypatch):
    monkeypatch.setattr(netbook, "foreign", lambda p=None: "it is Windows' drive")
    book = netbook.NetBook(tmp_path / "n.db")
    assert book.all() == []
    with pytest.raises(Refusal, match="Windows' drive"):
        book.put(_allocation())
    assert not (tmp_path / "n.db").exists()


# -- no domain until you set one (N12) ----------------------------------------------------------------------------------
def test_with_no_domain_set_an_install_is_refused_naming_the_networks_tab(tmp_path):
    w = world(tmp_path, domain="")
    w.grant()
    with pytest.raises(Refusal, match="set one on the firewall's Networks tab"):
        w.plan()
    assert w.firewall.name_records()["records"] == [] and "no domain" in w.firewall.name_records()["words"]
    w.page("standin-firewall", "set_domain", "lan.example")
    plan = w.plan()
    assert plan["plan"] and plan["approve"][-1]["plugin"] == "standin-firewall"


# -- the conformance sequence with a firewall that names (the end to end) -----------------------------------------------
def test_the_conformance_sequence_runs_with_a_firewall_that_routes_and_names(tmp_path):
    w = world(tmp_path, book=netbook.NetBook(tmp_path / "network.db"))
    w.grant()
    done = standins.conformance(w.jenkins, w.page, W.spec(), "wsl-ubuntu", w.wait)
    assert done[-1] == "conformance"
    kinds = [s["kind"] for ran in w.firewall.ran for s in ran]
    assert kinds.count("route") == 2 and "proxy" in kinds and "unproxy" in kinds and "unroute" in kinds
    proxies = [s for ran in w.firewall.ran for s in ran if s["kind"] == "proxy"]
    assert all(p["detail"]["listen"] == "192.168.50.228" and p["detail"]["connect"] == "10.77.1.10"
               and p["detail"]["container"] == 8080 and p["detail"]["part"] == "controller" for p in proxies)
    assert w.firewall._book.of_sid("jenkins/ci") is None  # delete_data freed it


def test_an_expose_of_what_is_open_already_is_nothing_and_closing_takes_exactly_what_was_opened(tmp_path):
    w = world(tmp_path)
    w.installed()
    a = w.firewall._book.of_sid("jenkins/ci")
    assert [d["listen"] for d in a.exposed] == ["192.168.50.228"]
    plan = w.plan("expose", options={"lan": True})
    assert all(n["plugin"] != "standin-firewall" or not n.get("plan") for n in plan["network"])
    end = w.carry("expose", options={"lan": False})
    assert end["ok"]
    last = w.firewall.ran[-1]
    assert [s["kind"] for s in last] == ["unproxy"] and last[0]["detail"]["listen"] == "192.168.50.228"


# -- the DHCP records and the found containers' names (N15, N21) ----------------------------------------------------------
def test_leases_hold_every_member_the_container_plugins_read_and_reverse_names_answer_found_ones(tmp_path):
    w = world(tmp_path)
    w.installed()
    w.fake.containers["web-1"] = {"name": "web-1", "image": "nginx", "state": "running", "labels": {},
                                  "networks": {"bridge": {"IPAddress": "172.17.0.2", "MacAddress": "02:42:ac:11:00:02"}}}
    w.host.segments = lambda sid="", fresh=False: {"segments": [S.Segment(
        "docker/wsl-ubuntu/bridge", "standin-host", "wsl-ubuntu", "bridge", "docker-bridge", "docker0", "wsl",
        subnets=("172.17.0.0/16",), members=(S.Member("", "", "web-1", "web-1", "02:42:ac:11:00:02", "172.17.0.2",
                                                     running=True),)).as_dict()]}
    leases = w.firewall.leases()["leases"]
    assert any(x["address"] == "10.77.1.10" and x["assigned"] == "reserved" for x in leases)
    found = next(x for x in leases if x["address"] == "172.17.0.2")
    assert found["mac"] == "02:42:ac:11:00:02" and found["state"] == "current"
    assert w.firewall.reverse_name("172.17.0.2") == {"address": "172.17.0.2", "name": "web-1", "found": True,
                                                     "segment": found["segment"]}
    assert not any("web-1" in r["name"] for r in w.firewall.name_records()["records"])  # never named in your domain


# -- the Networks tab and the page's own changes ------------------------------------------------------------------------
def test_the_pages_own_changes_are_refused_to_a_plugin(tmp_path):
    w = world(tmp_path)
    for hook, args in (("repoint", ()), ("withdraw", ("jenkins/ci",)), ("remove_leftover", ("x",)),
                       ("forget_records", ())):
        with pytest.raises(AskRefused):
            w.jenkins.call(hook, *args, plugin="standin-firewall")
        with asking.asking("jenkins"), pytest.raises(Refusal, match="page alone"):
            getattr(w.firewall, hook)(*args)


def test_repoint_makes_every_stale_route_again_in_one_elevation(tmp_path):
    w = world(tmp_path)
    w.installed()
    before = w.firewall.elevations
    assert w.page("standin-firewall", "repoint")["said"].startswith("every route")
    w.firewall.hop = "172.31.9.9"
    w.page("standin-firewall", "repoint")
    assert w.firewall.elevations == before + 1
    assert w.firewall._book.of_sid("jenkins/ci").route["next_hop"] == "172.31.9.9"
    tab = w.firewall.container_networks()
    seg = next(t for t in tab["tables"] if t["title"] == "Segments by stack")
    assert "172.31.9.9 (current)" in seg["rows"][0][5]


def test_withdraw_takes_the_route_and_proxy_away_and_keeps_the_records_gone(tmp_path):
    w = world(tmp_path)
    w.installed()
    w.page("standin-firewall", "withdraw", "jenkins/ci")
    assert [s["kind"] for s in w.firewall.ran[-1]] == ["unproxy", "unroute"]
    a = w.firewall._book.of_sid("jenkins/ci")
    assert a.state == "gone" and a.route is None and not a.exposed
    w.page("standin-firewall", "forget_records", "jenkins/ci")
    assert w.firewall._book.of_sid("jenkins/ci") is None


def test_leftovers_are_what_no_allocation_accounts_for(tmp_path):
    w = world(tmp_path)
    w.installed()
    w.firewall.made = [{"id": "r1", "key": ["route", "10.77.1.0/24"], "words": "a route to 10.77.1.0/24", "detail": {}},
                       {"id": "r2", "key": ["route", "10.77.9.0/24"], "words": "a route to 10.77.9.0/24",
                        "detail": {"prefix": "10.77.9.0/24"}}]
    assert [m["id"] for m in w.firewall.leftovers()["leftovers"]] == ["r2"]
    w.page("standin-firewall", "remove_leftover", "r2")
    assert w.firewall.ran[-1][0]["detail"] == {"prefix": "10.77.9.0/24"}


# -- the WSL base: holds, WSL's one network, one engine, the guarded Uninstall ------------------------------------------
class Spawned:
    def __init__(self, args):
        self.args, self.ended = args, False

    def poll(self):
        return None

    def terminate(self):
        self.ended = True


class Ubuntu(UbuntuLike):
    WSLCONFIG = None


def _wsl(tmp_path, state="Running", docker=True):
    fake = FakeWsl(distributions=[("Ubuntu", "Running", "2"), ("Liminal-Ubuntu", state, "2")], docker_installed=docker)
    spawned: list = []
    wsl = Wsl(runner=fake, registry=lambda: [], spawn=lambda args: spawned.append(Spawned(args)) or spawned[-1])
    p = Ubuntu(wsl=wsl, data=tmp_path)
    p.WSLCONFIG = tmp_path / ".wslconfig"
    return p, fake, spawned


def test_a_hold_never_starts_a_stopped_distribution(tmp_path):
    p, fake, spawned = _wsl(tmp_path, state="Stopped")
    with asking.asking("docker"), pytest.raises(Refusal, match="never starts"):
        p.hold("Liminal-Ubuntu")
    assert spawned == [] and not any(c[1] == "-d" for c in fake.calls)


def test_one_session_holds_for_every_holder_and_the_last_let_go_ends_it(tmp_path):
    p, fake, spawned = _wsl(tmp_path)
    with asking.asking("docker"):
        p.hold("Liminal-Ubuntu")
    with asking.asking("lxd"):
        p.hold("Liminal-Ubuntu")
    assert len(spawned) == 1 and p.held_by("Liminal-Ubuntu") == ["docker", "lxd"]
    with asking.asking("docker"):
        p.let_go("Liminal-Ubuntu")
    assert not spawned[0].ended
    with asking.asking("lxd"):
        p.let_go("Liminal-Ubuntu")
    assert spawned[0].ended and p.held_by("Liminal-Ubuntu") == []
    for who in (asking.PAGE, None):
        with asking.asking(who), pytest.raises(Refusal, match="container plugin alone"):
            p.hold("Liminal-Ubuntu")


def test_stopping_a_held_distribution_is_asked_twice(tmp_path):
    p, fake, _ = _wsl(tmp_path)
    with asking.asking("docker"):
        p.hold("Liminal-Ubuntu")
    with pytest.raises(Asked, match="docker") as e:
        p.stop_install("Liminal-Ubuntu")
    assert e.value.accept == "accept_held" and not any(c[1] == "--terminate" for c in fake.calls)
    assert p.stop_install("Liminal-Ubuntu", accept_held=True)["ok"] and p.held_by("Liminal-Ubuntu") == []


def test_wsl_network_runs_nothing_in_a_stopped_distribution(tmp_path):
    p, fake, _ = _wsl(tmp_path, state="Stopped")
    got = p.wsl_network()
    assert got["mode"] == "nat" and got["vm_address"] == "" and "stopped" in got["why"]
    assert not any(c[1] == "-d" for c in fake.calls)
    (tmp_path / ".wslconfig").write_text("[wsl2]\nnetworkingMode = mirrored\n")
    assert p.wsl_network()["mode"] == "mirrored"


def test_wsl_network_reads_the_vm_address_inside_its_own_running_distribution_alone(tmp_path):
    p, fake, _ = _wsl(tmp_path)
    real = fake.__call__

    def answer(args, timeout):
        if args[1] == "-d" and args[args.index("--exec") + 1:][:2] == ["ip", "-4"]:
            fake.calls.append(list(args))
            return 0, b"4: eth0    inet 172.31.5.9/20 brd 172.31.15.255 scope global eth0\n", b""
        if args[1] == "-d" and args[args.index("--exec") + 1:][:2] == ["ip", "-o"]:
            fake.calls.append(list(args))
            return 0, b"1: lo: <LOOPBACK>\n2: eth0: <UP>\n5: docker0: <UP>\n", b""
        return real(args, timeout)
    p.wsl._runner = answer
    got = p.wsl_network()
    assert got["vm_address"] == "172.31.5.9" and got["prefix"] == "172.31.5.9/20" and got["links"] == ["docker0"]
    assert got["engines"] == {"Liminal-Ubuntu": True}
    assert {c[2] for c in fake.calls if c[1] == "-d"} == {"Liminal-Ubuntu"}  # never in your own Ubuntu


def test_a_second_engine_in_wsls_one_network_is_asked_twice(tmp_path, monkeypatch):
    p, fake, spawned = _wsl(tmp_path, state="Stopped")
    monkeypatch.setattr(p, "engines_elsewhere", lambda: ["Liminal-Fedora"])
    with pytest.raises(Asked, match="Liminal-Fedora") as e:
        p.start_install("Liminal-Ubuntu")
    assert e.value.accept == "accept_second_engine" and spawned == []
    monkeypatch.setattr(wsl_mod.time, "sleep", lambda s: None)
    p.start_install("Liminal-Ubuntu", accept_second_engine=True)
    assert len(spawned) == 1


def test_the_engine_step_refuses_beside_another_engine(tmp_path, monkeypatch):
    p, fake, _ = _wsl(tmp_path)
    monkeypatch.setattr(p, "engines_elsewhere", lambda: ["Liminal-Fedora"])
    done = p.setup(log=lambda m: None, steps=["engine"])
    assert done[-1]["ok"] is False and "one engine" in done[-1]["detail"]
    assert not any(wsl_mod.ENGINE_SCRIPT in str(c) for c in fake.calls)


def test_uninstalling_liminals_own_distribution_with_services_is_asked_twice(tmp_path, monkeypatch):
    p, fake, _ = _wsl(tmp_path)
    monkeypatch.setattr(p, "goes_with", lambda name: "the services jenkins/ci (docker)")
    with pytest.raises(UninstallRefused, match="jenkins/ci"):
        p.uninstall("Liminal-Ubuntu")
    assert not any(c[1] == "--unregister" for c in fake.calls)


def test_goes_with_names_the_services_and_their_networks(tmp_path):
    w = world(tmp_path)
    w.installed()
    p, _fake, _ = _wsl(tmp_path)
    w.app.attach(p)
    said = p.goes_with("Liminal-Ubuntu")
    assert "jenkins/ci (standin-host)" in said and "10.77.1.0/24" in said and "Withdraw" in said


def test_every_change_of_the_wsl_plugins_is_the_pages_alone():
    for hook in ("uninstall", "start_install", "stop_install", "update_packages", "rename_install"):
        assert hook in wsl_mod.WslDistribution.PAGE_ONLY_HOOKS
    assert set(wsl_mod.WslDistribution.PLUGIN_ONLY_HOOKS) == {"hold", "let_go"}
    assert "wsl_network" in wsl_mod.WslDistribution.READ_HOOKS
