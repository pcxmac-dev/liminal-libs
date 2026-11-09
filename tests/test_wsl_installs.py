"""Every install of a WSL plugin's system (1.36.0; the user: "for the WSL plugins, they need to list all the 'operating
systems' that are installed under the plugin's regime, like ubuntu shows all ubuntu installs, fedora -- installs, gentoo
-- installs"; "also the ability to uninstall and select which one to terminal in to"; "basically a selector for different
installs"): read from WSL's own record (a stand-in's here) and `wsl --list --verbose`, none started; the install chosen,
the terminal into it, and Uninstall, the user's own only after a second confirmation. Nothing here touches this PC's WSL."""
from __future__ import annotations

import pytest

from liminal_libs.machines.wsl import Installed, UninstallRefused, Wsl, WslDistribution, WslError, size_words

from test_wsl import FakeWsl, UbuntuLike


class Unregistering(FakeWsl):
    """The stand-in also unregisters (`wsl --unregister NAME`): the distribution gone from its list."""

    def __call__(self, args, timeout):
        if args[1] == "--unregister":
            self.calls.append(list(args))
            self.distributions = [d for d in self.distributions if d[0] != args[2]]
            self.unregistered.add(args[2])  # WSL's record of it gone too
            return 0, "The operation completed successfully.\r\n".encode("utf-16-le"), b""
        return super().__call__(args, timeout)


    unregistered: set = set()


class FedoraLike(UbuntuLike):
    name = "wsl-fedora"
    distribution = "Liminal-Fedora"
    family = "dnf"


def record(name, folder=None, **values):
    return {"DistributionName": name, "BasePath": str(folder) if folder else "", "VhdFileName": "ext4.vhdx", "Version": 2, **values}


@pytest.fixture
def machine(tmp_path):
    disk = tmp_path / "ubuntu"
    disk.mkdir()
    (disk / "ext4.vhdx").write_bytes(b"\0" * 2048)
    fake = Unregistering(distributions=[("Ubuntu", "Running", "2"), ("Liminal-Ubuntu", "Stopped", "2"), ("Ubuntu-22.04", "Stopped", "2"),
                                        ("Debian", "Stopped", "2"), ("FedoraLinux-42", "Stopped", "2"), ("Liminal-Gentoo", "Stopped", "2")])
    registry = [record("Ubuntu", disk, Flavor="ubuntu", OsVersion="24.04", PackageFamilyName="CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc"),
                record("Liminal-Ubuntu", tmp_path / "liminal", Flavor="ubuntu", OsVersion="26.04"),
                record("Debian", Flavor="debian", OsVersion="13"), record("Liminal-Gentoo"), record("Half-Gone", Flavor="ubuntu")]
    fake.unregistered = set()
    wsl = Wsl(runner=fake, registry=lambda: [r for r in registry if r["DistributionName"] not in fake.unregistered])
    return fake, wsl, tmp_path


def test_every_install_of_its_system_listed_from_wsls_own_record_none_started(machine):
    fake, wsl, tmp_path = machine
    ubuntu = UbuntuLike(wsl=wsl, data=tmp_path)
    found = {i.name: i for i in wsl.installed()}
    assert found["Ubuntu"] == Installed("Ubuntu", "Running", "2", True, "ubuntu", "24.04", "CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc",
                                        str(tmp_path / "ubuntu"), str(tmp_path / "ubuntu" / "ext4.vhdx"), 2048)
    assert found["Half-Gone"].state == "not listed by wsl" and found["Liminal-Ubuntu"].size is None  # its disk not there
    assert [i.name for i in ubuntu.installs()] == ["Ubuntu", "Liminal-Ubuntu", "Ubuntu-22.04", "Half-Gone"]  # by flavor, else by name
    assert [i.name for i in FedoraLike(wsl=wsl, data=tmp_path).installs()] == ["FedoraLinux-42"]  # no flavor recorded: its name
    assert all(c[1] != "-d" for c in fake.calls)  # nothing asked inside: none started
    st = ubuntu.status()
    table = st["tables"][0]
    assert table["title"] == "Ubuntu installs" and "this plugin sets up Liminal-Ubuntu alone" in table["note"]
    rows = {r[0]["text"] if isinstance(r[0], dict) else r[0]: r for r in table["rows"]}
    assert rows["Ubuntu"][1:5] == ["Running", "Ubuntu 24.04", "WSL 2", "yes"] and rows["Ubuntu"][6]["text"] == "yours"
    assert rows["Liminal-Ubuntu"][6] == "Liminal's: this plugin's" and rows["Ubuntu-22.04"][2] == {"text": "Ubuntu", "sub": "its version not recorded by WSL"}
    assert st["installs"].startswith("Ubuntu (yours, running), Liminal-Ubuntu (Liminal, stopped)")
    assert size_words(2048) == "0 MB" and size_words(3 * 1024 ** 3) == "3.0 GB" and size_words(None) == "not read"
    assert Wsl(runner=fake).installed()[0].flavor == ""  # a stand-in reads no registry unless given one


def test_a_selector_chooses_the_install_a_terminal_opens_into(machine):
    fake, wsl, tmp_path = machine
    p = UbuntuLike(wsl=wsl, data=tmp_path)
    assert p.chosen() == "Liminal-Ubuntu"  # Liminal's own until another is picked
    assert p.terminal()[:3] == ["wsl", "-d", "Liminal-Ubuntu"] and p.terminal_title() == "liminal in Liminal-Ubuntu"
    table = p.status()["tables"][0]
    assert table["options"][0]["hook"] == "pick_install" and table["options"][0]["value"] == "Liminal-Ubuntu"
    assert [c["value"] for c in table["options"][0]["choices"]] == ["Ubuntu", "Liminal-Ubuntu", "Ubuntu-22.04", "Half-Gone"]
    assert table["options"][0]["choices"][0]["note"] == "Ubuntu 24.04 · yours · running"
    assert p.pick_install("ubuntu")["said"] == "Ubuntu chosen: a terminal opens into it"
    assert p.terminal()[:3] == ["wsl", "-d", "Ubuntu"] and p.terminal_title() == "Ubuntu, as its default user"
    st = p.status()
    assert st["terminalInto"] == "Ubuntu" and [a.get("title") for a in st["tables"][0]["actions"]] == ["Open a terminal in Ubuntu", "Uninstall Ubuntu…"]
    assert st["tables"][0]["actions"][0]["terminal"] is True and st["forms"][0]["id"] == "uninstall"
    with pytest.raises(LookupError):
        p.pick_install("Debian")  # not of its system
    nothing = UbuntuLike(wsl=Wsl(runner=FakeWsl(distributions=[("Ubuntu", "Running", "2")])), data=tmp_path)
    assert nothing.chosen() == ""  # the user's own is never chosen for them
    with pytest.raises(WslError, match="not installed"):
        nothing.terminal()
    assert {"pick_install", "uninstall"} <= set(WslDistribution.HOOKS)


def test_uninstall_unregisters_and_the_users_own_only_after_a_second_confirmation(machine):
    fake, wsl, tmp_path = machine
    p = UbuntuLike(wsl=wsl, data=tmp_path)
    with pytest.raises(UninstallRefused, match="Ubuntu is yours, not Liminal's") as refused:
        p.uninstall("Ubuntu")
    assert refused.value.accept == "accept_risk" and "Store app (CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc) stays installed" in str(refused.value)
    assert not any(c[1] == "--unregister" for c in fake.calls)  # refused: nothing run
    p.pick_install("Ubuntu")
    said = p.uninstall("Ubuntu", accept_risk=True)
    assert said["ok"] and said["said"] == "Ubuntu uninstalled" and ["wsl", "--unregister", "Ubuntu"] in fake.calls
    assert p.chosen() == "Liminal-Ubuntu"  # the pick gone with it
    own = p.uninstall("Liminal-Ubuntu")  # its own: one confirmation (the form's) is enough
    assert own["ok"] and own["lines"][-1] == "Liminal-Ubuntu's setup installs it again"
    with pytest.raises(LookupError):
        p.uninstall("Debian")
