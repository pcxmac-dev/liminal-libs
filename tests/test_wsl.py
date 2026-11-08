"""A distribution in WSL with Docker inside, as a machine plugin (liminal_libs.machines.wsl): the wsl command
through a stand-in, the status, every setup step for the three families, a command run inside, the
engine as a named Docker instance, Windows paths under /mnt."""
from __future__ import annotations

from pathlib import Path

import pytest

from liminal_libs.machines import wsl as wsl_mod
from liminal_libs.machines.wsl import Wsl, WslDistribution, WslError, wsl_path
from liminal_libs.sources.conformance import problems


def u16(text: str) -> bytes:
    return text.encode("utf-16-le")


class FakeWsl:
    """Answers the wsl command: WSL there or not, the distributions, what runs inside."""

    def __init__(self, present=True, distributions=(), docker_installed=False, daemon=True):
        self.present = present
        self.distributions = list(distributions)  # (name, state, version)
        self.docker_installed = docker_installed
        self.daemon = daemon
        self.calls: list = []
        self.scripts: list = []
        self.files: dict = {}

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        if args[1] == "--status":
            return (0, u16("Default Distribution: Ubuntu\r\nDefault Version: 2\r\n"), b"") if self.present else (1, b"", u16("not installed"))
        if args[1:3] == ["--list", "--verbose"]:
            rows = "  NAME            STATE           VERSION\r\n" + "".join(f"{'*' if i == 0 else ' '} {n:<15} {s:<15} {v}\r\n" for i, (n, s, v) in enumerate(self.distributions))
            return 0, u16(rows), b""
        if args[1:3] == ["--list", "--online"]:
            return 0, u16("The following is a list of valid distributions.\r\nNAME                FRIENDLY NAME\r\nUbuntu              Ubuntu\r\nFedoraLinux-42      Fedora Linux 42\r\n"), b""
        if args[1] in ("--install", "--update", "--set-default-version", "--terminate", "--import"):
            if args[1] == "--install" and "--name" in args:
                self.distributions.append((args[args.index("--name") + 1], "Stopped", "2"))
            elif args[1] == "--install" and "-d" in args:
                self.distributions.append((args[args.index("-d") + 1], "Stopped", "2"))
            if args[1] == "--import":
                self.distributions.append((args[2], "Stopped", "2"))
            return 0, u16("done"), b""
        if args[1] == "-d":
            name = args[2]
            command = args[args.index("--exec") + 1:]
            if not any(n == name for n, _, _ in self.distributions):
                return 1, b"", b"no such distribution"
            if command[:2] == ["docker", "--version"]:
                return (0, b"Docker version 28.1.1, build 4eba377\n", b"") if self.docker_installed else (127, b"", b"docker: command not found")
            if command[:2] == ["docker", "info"]:
                return (0, b"28.1.1\n", b"") if self.docker_installed and self.daemon else (1, b"", b"Cannot connect to the Docker daemon")
            if command[:2] == ["sh", "-s"]:
                self.scripts.append(("root" if "-u" in args and args[args.index("-u") + 1] == "root" else "user", "script"))
                return 0, b"systemd\n", b""
            if command[:2] == ["sh", "-c"]:
                self.files[command[2]] = "written"
                return 0, b"", b""
            return 0, (" ".join(command) + "\n").encode(), b""
        return 1, b"", b"unknown"


class UbuntuLike(WslDistribution):
    name = "wsl-ubuntu"
    title = "WSL Ubuntu"
    about = "Ubuntu in WSL 2 with Docker inside"
    api = "2.1"
    order = 700
    distribution = "Liminal-Ubuntu"
    family = "apt"
    install_name = "Ubuntu"
    docker_repository = "https://repository.test/linux/ubuntu/"
    DISTRIBUTION_VAR = "WSL_UBUNTU_DISTRIBUTION"
    USER_VAR = "WSL_UBUNTU_USER"


class GentooLike(WslDistribution):
    name = "wsl-gentoo"
    title = "WSL Gentoo"
    about = "Gentoo in WSL 2 with Docker inside"
    api = "2.1"
    order = 702
    distribution = "Liminal-Gentoo"
    family = "emerge"

    def tarball_url(self) -> str:
        return "https://distfiles.gentoo.org/releases/amd64/autobuilds/x/stage3-amd64-systemd-x.tar.xz"


def test_the_wsl_command_is_read_through_the_stand_in_and_a_windows_path_goes_under_mnt():
    fake = FakeWsl(distributions=[("Ubuntu", "Running", "2"), ("Gentoo", "Stopped", "2")])
    w = Wsl(runner=fake)
    assert w.here and w.status() == {"present": True, "version": "2", "distribution": "Ubuntu"}
    assert [(d.name, d.state, d.version, d.default) for d in w.distributions()] == [("Ubuntu", "Running", "2", True), ("Gentoo", "Stopped", "2", False)]
    assert w.distribution("ubuntu").name == "Ubuntu" and w.distribution("Fedora") is None and w.online() == ["Ubuntu", "FedoraLinux-42"]
    assert w.run("Ubuntu", "echo", "hi") == "echo hi\n" and fake.calls[-1] == ["wsl", "-d", "Ubuntu", "--exec", "echo", "hi"]
    assert w.run("Ubuntu", "id", user="root") and fake.calls[-1][1:5] == ["-d", "Ubuntu", "-u", "root"]
    with pytest.raises(WslError) as e:
        w.run("Nowhere", "ls")
    assert "no such distribution" in str(e.value)
    assert Wsl(runner=FakeWsl(present=False)).status()["present"] is False
    assert wsl_path("C:\\Users\\x\\mail") == "/mnt/c/Users/x/mail" and wsl_path("D:/data/") == "/mnt/d/data" and wsl_path("relative/x") == "relative/x"


def test_a_distribution_plugin_conforms_reports_sets_up_and_offers_its_engine(monkeypatch, tmp_path):
    fake = FakeWsl(present=True, distributions=[], docker_installed=False)
    p = UbuntuLike(wsl=Wsl(runner=fake), data=tmp_path)
    assert problems(p) == [] and p.KIND == "machine" and p.SYSTEM == "platform" and p.options == ("WSL_UBUNTU_DISTRIBUTION", "WSL_UBUNTU_USER")
    assert {"present", "status", "setup", "run", "instances"} <= set(p.interface()["hooks"])  # the base gives them: a plugin of its own, not the contract
    assert not p.present() and p.status()["present"] is False and p.status()["wsl"]["present"] is True and p.instances() == ()
    assert p.status()["valid"] is False and p.status()["why"] == "no Liminal install: its setup installs Liminal-Ubuntu"
    # the whole setup on a machine with WSL and no Ubuntu: each step reported
    lines: list = []
    done = p.setup(log=lines.append)
    assert [(d["step"], d["ok"]) for d in done] == [("wsl", None), ("update", True), ("version", True), ("distribution", True), ("conf", True),
                                                   ("docker", True), ("engine", True), ("user", True)]
    assert ["wsl", "--install", "Ubuntu", "--name", "Liminal-Ubuntu", "--location", str(tmp_path / "root"), "--no-launch"] in fake.calls
    assert ["wsl", "--set-default-version", "2"] in fake.calls  # Liminal's own beside the user's, never the user's
    assert fake.files == {"cat > /etc/wsl.conf": "written"} and ["wsl", "--terminate", "Liminal-Ubuntu"] in fake.calls
    assert len(fake.scripts) == 4 and all(who == "root" for who, _ in fake.scripts)  # the user, Docker, the engine, the group
    assert any("Docker installed by apt" in d["detail"] for d in done) and any("liminal in the docker group" in d["detail"] for d in done)
    # with Docker inside, the plugin is present and offers the engine as a named instance
    fake.docker_installed = True
    assert p.present() and p.status()["engine"] == {"installed": True, "version": "28.1.1", "running": True}
    assert p.status()["summary"] == "Liminal-Ubuntu (Stopped, WSL 2); Docker inside: running 28.1.1" and p.STEPS == wsl_mod.STEPS
    assert p.status()["valid"] is True and p.status()["why"] == ""
    (inst,) = p.instances()
    assert inst.name == "wsl-ubuntu" and inst.command == "wsl -d Liminal-Ubuntu --exec docker" and inst.translate("C:\\x") == "/mnt/c/x" and inst.source == "wsl-ubuntu"
    assert p.run("ls", "/") == "ls /\n"
    assert p.setup(log=lines.append, steps=("docker",)) == [{"step": "docker", "ok": None, "detail": "Docker is installed inside"}]
    fake.daemon = False
    assert p.status()["engine"]["running"] is False
    # the names from the environment
    monkeypatch.setenv("WSL_UBUNTU_DISTRIBUTION", "Ubuntu-24.04")
    monkeypatch.setenv("WSL_UBUNTU_USER", "ciara")
    assert p.distribution_name == "Ubuntu-24.04" and p.user == "ciara"
    # the user's own distribution is never Liminal's: named by the variable, the plugin is not valid
    mine = UbuntuLike(wsl=Wsl(runner=FakeWsl(distributions=[("Ubuntu-24.04", "Running", "2")])), data=tmp_path)
    assert mine.present() and mine.status()["valid"] is False and "not one of Liminal's own" in mine.status()["why"]
    # without WSL at all: said at the first step, nothing else tried
    absent = UbuntuLike(wsl=Wsl(runner=FakeWsl(present=False)), data=tmp_path)
    assert [(d["step"], d["ok"]) for d in absent.setup(log=lambda m: None)] == [("wsl", False)] or absent.setup(log=lambda m: None)[0]["ok"] is True


def test_a_distribution_imported_from_a_tarball_and_the_families_recipes(tmp_path):
    fake = FakeWsl(present=True, distributions=[])
    got: list = []

    def fetch(url, path):
        got.append(url)
        Path(path).write_bytes(b"tarball")
    g = GentooLike(wsl=Wsl(runner=fake), data=tmp_path, fetch=fetch)
    done = g.setup(log=lambda m: None, steps=("distribution", "docker", "engine"))
    assert [(d["step"], d["ok"]) for d in done] == [("distribution", True), ("docker", True), ("engine", True)]
    assert got == ["https://distfiles.gentoo.org/releases/amd64/autobuilds/x/stage3-amd64-systemd-x.tar.xz"] and (tmp_path / "stage3-amd64-systemd-x.tar.xz").is_file()
    assert ["wsl", "--import", "Liminal-Gentoo", str(tmp_path / "root"), str(tmp_path / "stage3-amd64-systemd-x.tar.xz"), "--version", "2"] in fake.calls
    assert "emerge" in wsl_mod.INSTALL_SCRIPTS["emerge"] and "app-containers/docker" in wsl_mod.INSTALL_SCRIPTS["emerge"]
    assert "{repository}/gpg" in wsl_mod.INSTALL_SCRIPTS["apt"] and "{repository}/docker-ce.repo" in wsl_mod.INSTALL_SCRIPTS["dnf"]
    assert "download.docker.com" not in "".join(wsl_mod.INSTALL_SCRIPTS.values())  # the plugins name the hosts
    ubuntu = UbuntuLike(wsl=Wsl(runner=fake), data=tmp_path).install_script()
    assert "curl -fsSL https://repository.test/linux/ubuntu/gpg " in ubuntu and "] https://repository.test/linux/ubuntu ${UBUNTU_CODENAME" in ubuntu
    assert g.install_script() == wsl_mod.INSTALL_SCRIPTS["emerge"]  # emerge: Gentoo's own tree, no repository
    nameless = UbuntuLike(wsl=Wsl(runner=FakeWsl(distributions=[("Liminal-Ubuntu", "Running", "2")])), data=tmp_path).with_(docker_repository="")
    with pytest.raises(WslError, match="names no Docker repository for apt"):
        nameless.install_script()
    assert [(d["step"], d["ok"]) for d in nameless.setup(log=lambda m: None, steps=("docker",))] == [("docker", False)]
    assert all(wsl_mod.DOCKER_PACKAGES in wsl_mod.INSTALL_SCRIPTS[f] for f in ("apt", "dnf")) and set(wsl_mod.INSTALL_SCRIPTS) == set(wsl_mod.FAMILIES)
    assert "systemctl enable --now docker" in wsl_mod.ENGINE_SCRIPT and "rc-service docker start" in wsl_mod.ENGINE_SCRIPT
    with pytest.raises(WslError):
        UbuntuLike(wsl=Wsl(runner=fake), data=tmp_path).tarball_url()
