"""Every install of a WSL plugin's system (1.36.0; the user: "for the WSL plugins, they need to list all the 'operating
systems' that are installed under the plugin's regime, like ubuntu shows all ubuntu installs, fedora -- installs, gentoo
-- installs") and its tasks (1.37.0: "instead of chosen, put task and for the tasks lets do terminal, start, pause, stop,
allow selection of the linux install by clicking on the list"; "tasks also include uninstall"): read from WSL's own
record (a stand-in's here) and `wsl --list --verbose`, none started; an install chosen by a click on its row, a terminal
into it, Start, Pause, Stop, and Uninstall, the user's own only after a second confirmation. Nothing here touches this
PC's WSL."""
from __future__ import annotations

import pytest

from liminal_libs.machines import wsl as wsl_mod
from liminal_libs.machines.wsl import Installed, UninstallRefused, Wsl, WslDistribution, WslError, size_words

from test_wsl import FakeWsl, UbuntuLike


class Machine(FakeWsl):
    """The stand-in also unregisters, terminates, and answers a pause and a resume inside (systemd as the init unless told)."""

    def __init__(self, *a, systemd=True, **kw):
        super().__init__(*a, **kw)
        self.unregistered: set = set()
        self.systemd = systemd
        self.frozen: list = []

    def _set(self, name, state):
        self.distributions = [(n, state if n == name else s, v) for n, s, v in self.distributions]

    def __call__(self, args, timeout):
        if args[1] == "--unregister":
            self.calls.append(list(args))
            self.distributions = [d for d in self.distributions if d[0] != args[2]]
            self.unregistered.add(args[2])  # WSL's record of it gone too
            return 0, "The operation completed successfully.\r\n".encode("utf-16-le"), b""
        if args[1] == "--terminate":
            self.calls.append(list(args))
            self._set(args[2], "Stopped")
            return 0, b"", b""
        if args[1] == "-d" and "--exec" in args:
            command = args[args.index("--exec") + 1:]
            if command[:2] == ["sh", "-c"] and command[2] == wsl_mod.FREEZE_SCRIPT:
                self.calls.append(list(args))
                if not self.systemd:
                    return 0, f"{wsl_mod.NO_SYSTEMD}\n".encode(), b""
                self.frozen = ["docker.service", "cron.service"]
                return 0, b"frozen docker.service\nfrozen cron.service\nfailed odd.service\n", b""
            if command[:2] == ["sh", "-c"] and command[2] == wsl_mod.THAW_SCRIPT:
                self.calls.append(list(args))
                thawed, self.frozen = list(command[4:]), []
                return 0, "".join(f"thawed {u}\n" for u in thawed).encode(), b""
        return super().__call__(args, timeout)


class FedoraLike(UbuntuLike):
    name = "wsl-fedora"
    distribution = "Liminal-Fedora"
    family = "dnf"


def record(name, folder=None, **values):
    return {"guid": "{" + name.lower() + "}", "DistributionName": name, "BasePath": str(folder) if folder else "", "VhdFileName": "ext4.vhdx",
            "Version": 2, **values}


@pytest.fixture
def machine(tmp_path):
    disk = tmp_path / "ubuntu"
    disk.mkdir()
    (disk / "ext4.vhdx").write_bytes(b"\0" * 2048)
    fake = Machine(distributions=[("Ubuntu", "Running", "2"), ("Liminal-Ubuntu", "Stopped", "2"), ("Ubuntu-22.04", "Stopped", "2"),
                                  ("Debian", "Stopped", "2"), ("FedoraLinux-42", "Stopped", "2"), ("Liminal-Gentoo", "Stopped", "2")])
    registry = [record("Ubuntu", disk, Flavor="ubuntu", OsVersion="24.04", PackageFamilyName="CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc"),
                record("Liminal-Ubuntu", tmp_path / "liminal", Flavor="ubuntu", OsVersion="26.04"),
                record("Debian", Flavor="debian", OsVersion="13"), record("Liminal-Gentoo"), record("Half-Gone", Flavor="ubuntu")]
    spawned: list = []

    def spawn(args):  # a started install's session: the stand-in marks it running at once
        spawned.append(args)
        fake._set(args[2], "Running")
        return None
    def rename(key, name):  # WSL's record changed, and its list follows it
        r = next(r for r in registry if r["guid"] == key)
        fake.distributions = [(name if n == r["DistributionName"] else n, s, v) for n, s, v in fake.distributions]
        r["DistributionName"] = name
        fake.renamed.append((key, name))
    fake.renamed = []
    wsl = Wsl(runner=fake, registry=lambda: [r for r in registry if r["DistributionName"] not in fake.unregistered], spawn=spawn,
              rename=rename)
    return fake, wsl, tmp_path, spawned


def keys(table) -> list:
    return [r["key"] for r in table["rows"]]


def cells(table, name) -> list:
    return next(r["cells"] for r in table["rows"] if r["key"] == name)


def test_every_install_of_its_system_listed_from_wsls_own_record_none_started(machine):
    fake, wsl, tmp_path, _ = machine
    ubuntu = UbuntuLike(wsl=wsl, data=tmp_path)
    found = {i.name: i for i in wsl.installed()}
    assert found["Ubuntu"] == Installed("Ubuntu", "Running", "2", True, "ubuntu", "24.04", "CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc",
                                        str(tmp_path / "ubuntu"), str(tmp_path / "ubuntu" / "ext4.vhdx"), 2048, "{ubuntu}")
    assert found["Half-Gone"].state == "not listed by wsl" and found["Liminal-Ubuntu"].size is None  # its disk not there
    assert [i.name for i in ubuntu.installs()] == ["Ubuntu", "Liminal-Ubuntu", "Ubuntu-22.04", "Half-Gone"]  # by flavor, else by name
    assert [i.name for i in FedoraLike(wsl=wsl, data=tmp_path).installs()] == ["FedoraLinux-42"]  # no flavor recorded: its name
    assert all(c[1] != "-d" for c in fake.calls)  # nothing asked inside: none started
    st = ubuntu.status()
    table = st["tables"][0]
    assert table["title"] == "Ubuntu installs" and "this plugin sets up Liminal-Ubuntu alone" in table["note"]
    assert keys(table) == ["Ubuntu", "Liminal-Ubuntu", "Ubuntu-22.04", "Half-Gone"]
    assert cells(table, "Ubuntu")[1:5] == ["Running", "Ubuntu 24.04", "WSL 2", "yes"] and cells(table, "Ubuntu")[6]["text"] == "yours"
    assert cells(table, "Liminal-Ubuntu")[6] == "Liminal's: this plugin's"
    assert cells(table, "Ubuntu-22.04")[2] == {"text": "Ubuntu", "sub": "its version not recorded by WSL"}
    assert st["installs"].startswith("Ubuntu (yours, running), Liminal-Ubuntu (Liminal, stopped)")
    assert size_words(2048) == "0 MB" and size_words(3 * 1024 ** 3) == "3.0 GB" and size_words(None) == "not read"
    assert Wsl(runner=fake).installed()[0].flavor == ""  # a stand-in reads no registry unless given one


def test_an_install_is_chosen_by_a_click_on_its_row_and_its_tasks_follow(machine):
    fake, wsl, tmp_path, _ = machine
    p = UbuntuLike(wsl=wsl, data=tmp_path)
    assert p.chosen() == "Liminal-Ubuntu"  # Liminal's own until another is picked
    assert p.terminal()[:3] == ["wsl", "-d", "Liminal-Ubuntu"] and p.terminal_title() == "liminal in Liminal-Ubuntu"
    table = p.status()["tables"][0]
    assert table["select"] == {"hook": "pick_install", "value": "Liminal-Ubuntu", "title": "Choose an install"} and "options" not in table
    tasks = table["tasks"]
    assert tasks["title"] == "Task" and tasks["subject"] == "Liminal-Ubuntu"
    assert [a["title"] for a in tasks["actions"]] == ["Terminal", "Start", "Pause", "Stop…", "Update packages", "Rename…", "Uninstall…"]
    assert [a.get("disabled", False) for a in tasks["actions"]] == [False, False, True, True, False, False, False]  # stopped: Start, not Pause or Stop
    assert tasks["actions"][4]["job"] == "update"  # the packages' update: a job, its output in the terminal panel
    assert p.pick_install("ubuntu")["said"] == "Ubuntu chosen: a terminal opens into it"
    assert p.terminal()[:3] == ["wsl", "-d", "Ubuntu"] and p.terminal_title() == "Ubuntu, as its default user"
    st = p.status()
    tasks = st["tables"][0]["tasks"]
    assert st["terminalInto"] == "Ubuntu" and tasks["subject"] == "Ubuntu"
    assert [a.get("disabled", False) for a in tasks["actions"]] == [False, True, False, False, False, False, False]  # running: Pause and Stop
    assert tasks["actions"][0]["terminal"] is True and {f["id"] for f in st["forms"]} == {"stop", "rename", "uninstall"}
    with pytest.raises(LookupError):
        p.pick_install("Debian")  # not of its system
    nothing = UbuntuLike(wsl=Wsl(runner=FakeWsl(distributions=[("Ubuntu", "Running", "2")])), data=tmp_path)
    assert nothing.chosen() == "" and "tasks" not in nothing.status()["tables"][0]  # the user's own is never chosen for them
    with pytest.raises(WslError, match="not installed"):
        nothing.terminal()
    assert {"pick_install", "uninstall", "start_install", "pause_install", "stop_install", "rename_install"} <= set(WslDistribution.HOOKS)


def test_start_pause_resume_and_stop(machine, monkeypatch):
    fake, wsl, tmp_path, spawned = machine
    monkeypatch.setattr(wsl_mod.time, "sleep", lambda s: None)
    p = UbuntuLike(wsl=wsl, data=tmp_path)
    with pytest.raises(ValueError, match="not running: nothing to pause"):
        p.pause_install("Liminal-Ubuntu")
    assert p.start_install("Liminal-Ubuntu")["said"] == "Liminal-Ubuntu started: it runs until Stop"
    assert spawned == [["wsl", "-d", "Liminal-Ubuntu", "--exec", *wsl_mod.KEEP_RUNNING]]  # a session holds it up
    assert p.start_install("Liminal-Ubuntu")["said"] == "Liminal-Ubuntu is running already"
    paused = p.pause_install("Liminal-Ubuntu")
    assert paused["said"] == "Liminal-Ubuntu paused: 2 services frozen" and paused["lines"] == ["docker.service, cron.service", "not paused: odd.service"]
    assert p.paused("Liminal-Ubuntu") == ["docker.service", "cron.service"]
    st = p.status()
    assert cells(st["tables"][0], "Liminal-Ubuntu")[1] == {"text": "Paused", "sub": "2 services frozen"}
    assert [a.get("disabled", False) for a in st["tables"][0]["tasks"]["actions"]][1:4] == [False, True, False]  # Start resumes it
    resumed = p.start_install("Liminal-Ubuntu")
    assert resumed["said"] == "Liminal-Ubuntu resumed: 2 services running again" and p.paused("Liminal-Ubuntu") == [] and fake.frozen == []
    assert p.stop_install("Liminal-Ubuntu")["said"] == "Liminal-Ubuntu stopped" and ["wsl", "--terminate", "Liminal-Ubuntu"] in fake.calls
    assert p.stop_install("Liminal-Ubuntu")["said"] == "Liminal-Ubuntu is stopped already"
    fake.systemd = False
    with pytest.raises(ValueError, match="does not run systemd"):
        p.pause_install("Ubuntu")  # the user's own, running without systemd


def test_uninstall_unregisters_and_the_users_own_only_after_a_second_confirmation(machine):
    fake, wsl, tmp_path, _ = machine
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


def test_an_install_renamed_in_wsls_own_record_and_liminals_own_followed_through_the_login(machine):
    """The user: "lets allow renaming the o/s on all three plugins". WSL 3.0.3 has no rename: WSL's record of it changes
    (a stand-in's here), stopped first when it runs; Liminal's own keeps Liminal- in front and the plugin follows it."""
    from liminal_libs.apps.authorization import EnvironmentLogin

    fake, wsl, tmp_path, _ = machine
    p = UbuntuLike(wsl=wsl, data=tmp_path)
    p.pick_install("Ubuntu")
    said = p.rename_install("Ubuntu", "Ubuntu-Work")  # the user's own, running: stopped first
    assert said["ok"] and said["said"] == "Ubuntu is Ubuntu-Work now" and said["lines"][0] == "Ubuntu stopped first"
    assert ["wsl", "--terminate", "Ubuntu"] in fake.calls and fake.renamed == [("{ubuntu}", "Ubuntu-Work")]
    assert p.chosen() == "Ubuntu-Work" and [i.name for i in p.installs()][0] == "Ubuntu-Work"  # the choice follows it
    for bad, words in (("Ubuntu Work", "letters, digits"), ("-x", "letters, digits"), ("ubuntu-22.04", "named Ubuntu-22.04 already")):
        with pytest.raises(ValueError, match=words):
            p.rename_install("Ubuntu-Work", bad)
    with pytest.raises(ValueError, match="kept through the platform's login"):
        p.rename_install("Liminal-Ubuntu", "Liminal-Ubuntu-Dev")  # its own, with no login to keep its new name in
    p.login = EnvironmentLogin(env={})
    with pytest.raises(ValueError, match="keeps Liminal- in front"):
        p.rename_install("Liminal-Ubuntu", "Dev-Box")
    own = p.rename_install("Liminal-Ubuntu", "Liminal-Ubuntu-Dev")
    assert own["ok"] and p.login.env == {"WSL_UBUNTU_DISTRIBUTION": "Liminal-Ubuntu-Dev"}
    assert p.distribution_name == "Liminal-Ubuntu-Dev" and p.status()["valid"]  # the plugin follows its own
    assert p.rename_install("Liminal-Ubuntu-Dev", "Liminal-Ubuntu-Dev")["said"] == "Liminal-Ubuntu-Dev is named so already"


def test_update_packages_updates_the_install_chosen(machine):
    """The user: "move the update packages on to the TASK": the chosen install's packages brought up to date by its family's
    manager, as root; Liminal's own unless the user chose another."""
    fake, wsl, tmp_path, _ = machine
    p = UbuntuLike(wsl=wsl, data=tmp_path)
    lines: list = []
    done = p.update_packages(log=lines.append)
    assert done[-1]["ok"] and "Liminal-Ubuntu's packages brought up to date by apt" in done[-1]["detail"]
    assert any(c[:3] == ["wsl", "-d", "Liminal-Ubuntu"] and "sh" in c for c in fake.calls)
    p.pick_install("Ubuntu")
    done = p.update_packages(log=lines.append)
    assert done[-1]["ok"] and done[-1]["detail"] == "Ubuntu's packages brought up to date by apt"
    assert any(c[:3] == ["wsl", "-d", "Ubuntu"] and "sh" in c for c in fake.calls)  # the user's own: they chose it
