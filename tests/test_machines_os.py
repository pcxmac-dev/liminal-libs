"""Windows and Linux for the machine plugins (liminal_libs.machines.windows, .linux): PowerShell with an
encoded, wrapped script and its failures in its own words, elevation asked only when the user says so; Linux
commands as root here (sudo -n) or in a WSL distribution (wsl -u root). Nothing runs: stand-in runners."""
from __future__ import annotations

import json
import sys

import pytest

from liminal_libs.machines import linux, windows
from liminal_libs.machines.linux import Shell
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.windows import ERROR_MARK, PowerShell, decoded, quote


def script_of(args) -> str:
    assert args[:6] == ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"]
    return decoded(args[6])


def test_powershell_runs_an_encoded_wrapped_script_and_reads_json():
    seen: list[str] = []

    def runner(args, timeout):
        s = script_of(args)
        seen.append(s)
        if "Get-Things" in s:
            return 0, json.dumps({"Name": "one"}), ""
        if "Get-Many" in s:
            return 0, json.dumps([{"Name": "a"}, {"Name": "b"}]), ""
        if "Get-None" in s:
            return 0, "", ""
        if "Fail-Denied" in s:
            return 1, ERROR_MARK + "Access is denied.\r\n", "#< CLIXML\r\n<Objs Version=\"1.1.0.1\">"
        if "Fail-Plain" in s:
            return 1, "", "#< CLIXML\r\nthe thing went wrong\r\n"
        return 0, "done\n", ""
    ps = PowerShell(runner=runner, env={})
    assert ps.here and ps.run("Write-Output 'x'") == "done\n"
    assert seen[-1].startswith("$ErrorActionPreference = 'Stop'") and "try {" in seen[-1] and ERROR_MARK in seen[-1]
    assert ps.json("Get-Things") == [{"Name": "one"}] and ps.json("Get-Many") == [{"Name": "a"}, {"Name": "b"}] and ps.json("Get-None") == []
    assert "ConvertTo-Json -Compress" in seen[-1] and "@(Get-None)" in seen[-1]
    with pytest.raises(CommandError) as e:
        ps.run("Fail-Denied")
    assert str(e.value) == "Access is denied." and e.value.denied
    with pytest.raises(CommandError) as e:
        ps.run("Fail-Plain")
    assert str(e.value) == "the thing went wrong" and not e.value.denied
    # an administrator's step: said how to give the rights, unless the user asked to be prompted
    with pytest.raises(CommandError) as e:
        ps.run_admin("Fail-Denied")
    assert e.value.denied and "LIMINAL_ELEVATE=prompt" in str(e.value) and "Access is denied" in str(e.value)
    assert quote("it's") == "'it''s'" and windows.is_elevated() in (True, False)


def test_an_elevated_script_goes_through_start_process_and_a_file(monkeypatch, tmp_path):
    monkeypatch.setattr(windows.tempfile, "gettempdir", lambda: str(tmp_path))
    calls: list[str] = []

    def runner(args, timeout):
        s = script_of(args)
        calls.append(s)
        if "Fail-Denied" in s and "Start-Process" not in s:
            return 1, ERROR_MARK + "Access is denied.", ""
        if "Start-Process" in s:
            assert "-Verb RunAs" in s
            inner = decoded(s.split("'-EncodedCommand','", 1)[1].split("'", 1)[0])
            out_file = inner.split("Out-File -FilePath '", 1)[1].split("'", 1)[0]
            open(out_file, "w", encoding="utf-8").write("rule added\n")
            return 0, "exit 0\n", ""
        return 0, "", ""
    ps = PowerShell(runner=runner, env={"LIMINAL_ELEVATE": "prompt"})
    assert ps.run_admin("Fail-Denied") == "rule added\n" and any("Start-Process" in c for c in calls)
    assert list(tmp_path.iterdir()) == []  # the output file removed


def test_without_a_desktop_windows_is_not_asked_and_nothing_waits():
    """A platform on no desktop (a boot service, before anyone signs in; 1.47.0): Windows' prompt cannot show, so an
    elevated script is refused at once, denied, and powershell.exe is never started for it."""
    calls: list = []
    headless = PowerShell(runner=lambda args, timeout: calls.append(args) or (0, "exit 0\n", ""), interactive=False)
    assert headless.can_ask() is False and PowerShell(runner=lambda a, t: (0, "", "")).can_ask() is True
    with pytest.raises(CommandError) as e:
        headless.run_elevated("Register-ScheduledTask")
    assert e.value.denied and "cannot ask you (UAC)" in str(e.value) and calls == []
    with pytest.raises(CommandError):  # an administrator's step asked to prompt, on no desktop: refused the same way
        PowerShell(runner=lambda args, timeout: (1, ERROR_MARK + "Access is denied.", ""), env={"LIMINAL_ELEVATE": "prompt"},
                   interactive=False).run_admin("Fail-Denied")
    assert windows.interactive() in (True, False)
    if sys.platform != "win32":
        assert windows.interactive() is False


def test_linux_commands_run_as_root_here_or_in_wsl(monkeypatch):
    got: list = []

    def runner(args, timeout):
        got.append(list(args))
        if args[-1] == "needs-password":
            return 1, b"", b"sudo: a password is required\n"
        if args[-1] == "fails":
            return 2, b"", b"something\nthe last line\n"
        if args[-1] == "utf16":
            return 0, "hello".encode("utf-16-le"), b""
        return 0, b"ok\n", b""
    monkeypatch.setattr(linux.os, "geteuid", lambda: 1000, raising=False)
    local = Shell("local", runner=runner)
    assert local.where == "this machine" and not local.root() and local.run("ufw", "status") == "ok\n" and got[-1] == ["sudo", "-n", "--", "ufw", "status"]
    assert local.run("id", root=False) and got[-1] == ["id"]
    with pytest.raises(CommandError) as e:
        local.run("needs-password")
    assert e.value.denied and "needs root on this machine" in str(e.value) and "sudo" in str(e.value)
    with pytest.raises(CommandError) as e:
        local.run("fails")
    assert str(e.value) == "the last line" and not e.value.denied
    monkeypatch.setattr(linux.os, "geteuid", lambda: 0, raising=False)
    assert Shell("local", runner=runner).run("ufw", "status") and got[-1] == ["ufw", "status"]  # root already: no sudo
    wsl = Shell("wsl:Ubuntu", runner=runner)
    assert wsl.where == "WSL's Ubuntu" and wsl.root() and wsl.run("ufw", "status") and got[-1] == ["wsl", "-d", "Ubuntu", "-u", "root", "--exec", "ufw", "status"]
    assert Shell("wsl", runner=runner).sh("echo hi") and got[-1] == ["wsl", "-u", "root", "--exec", "sh", "-c", "echo hi"]
    assert wsl.run("utf16") == "hello"  # wsl's own messages come in UTF-16
    with pytest.raises(CommandError):
        Shell("ssh:vps")


def test_a_linux_target_is_liminals_own_or_not():
    """This Linux machine, or a WSL distribution of Liminal's own, is Liminal's; WSL's default distribution and the user's
    own named ones are not (1.24.0: a plugin on them is not valid)."""
    from liminal_libs.machines import MachinePlugin
    from liminal_libs.machines.plugin import liminal_scoped

    assert Shell("local").scoped and Shell("wsl:Liminal-Ubuntu").scoped and Shell("wsl:liminal-gentoo").scoped
    assert not Shell("wsl").scoped and not Shell("wsl:Ubuntu").scoped and Shell("local").scope_note == ""
    assert "WSL's default distribution is not Liminal's" in Shell("wsl").scope_note and liminal_scoped("Liminal-Fedora")
    assert not liminal_scoped("Ubuntu") and not liminal_scoped("")

    class OnWsl(MachinePlugin):
        name, title, about, api = "on-wsl", "On WSL", "a plugin on a Linux target", "2.1"
        shell = Shell("wsl:Ubuntu")
    assert OnWsl().scope() == (False, "WSL's Ubuntu") and MachinePlugin().scope() == (True, "this machine")


def test_on_windows_a_linux_target_is_liminals_own_distribution_and_never_the_users(monkeypatch):
    """No target named: on Windows, Liminal's own distribution when one is installed (Ubuntu's first), else none; the
    user's own distribution is never taken for it."""
    from liminal_libs.machines import linux

    monkeypatch.setattr(linux, "_on_windows", lambda: True)
    assert linux.liminal_distribution(["Ubuntu", "Liminal-Gentoo", "Liminal-Ubuntu"]) == "Liminal-Ubuntu"
    assert linux.liminal_distribution(["Ubuntu", "Liminal-Gentoo", "liminal-fedora"]) == "liminal-fedora"
    assert linux.liminal_distribution(["Ubuntu", "Debian"]) == "" and linux.liminal_distribution(["Liminal-Arch"]) == "Liminal-Arch"
    sh = Shell(None, distributions=lambda: ["Ubuntu", "Liminal-Ubuntu"])
    assert (sh.target, sh.scoped, sh.scope_note, sh.liminal_missing) == ("wsl:Liminal-Ubuntu", True, "", False)
    none = Shell(None, distributions=lambda: ["Ubuntu"])
    assert (none.target, none.scoped, none.liminal_missing) == ("wsl", False, True)
    assert none.scope_note == "no Liminal distribution in WSL yet: a WSL plugin's setup installs one (Liminal-Ubuntu)"
    assert Shell(None, runner=lambda a, t: (0, b"", b"")).target == "wsl"  # a stand-in: nothing listed
    assert Shell("wsl:Ubuntu").target == "wsl:Ubuntu"  # named by its variable: as named (and not Liminal's)
    monkeypatch.setattr(linux, "_on_windows", lambda: False)
    assert Shell(None).target == "local" and Shell(None).scoped


def test_the_linux_plugins_work_on_any_linux_and_say_what_wsl_changes():
    """The user, 2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some
    capability this should reflect in the plugin" (1.57.0; a WSL kernel was refused outright until then, which read
    "it's not for administrating WSL instances" of 2026-11-08 too widely: that ruled out a platform on Windows
    reaching into a WSL distribution, and still does). why_not_native says why a machine is not Linux (Windows,
    macOS), "" on Linux of any kind; wsl() names the distribution the platform runs inside; wsl_table says what WSL
    changes; a plugin not for this machine says applies False and is asked nothing (1.27.0)."""
    from liminal_libs.machines import MachinePlugin

    assert linux.why_not_native("The Linux firewall", "win32", "10", {}) == (
        "The Linux firewall is for the Linux the platform runs on, and this one runs Windows; Liminal's WSL distributions are the WSL plugins'")
    assert linux.why_not_native("Linux administration", "darwin", "24.1.0", {}) == (
        "Linux administration is for the Linux the platform runs on, and this one runs macOS")
    two, one = "6.18.54.1-microsoft-standard-WSL2", "4.4.0-19041-Microsoft"
    for release, env in ((two, {"WSL_DISTRO_NAME": "Ubuntu"}), (one, {}), ("6.8.0-48-generic", {"WSL_INTEROP": "/run/WSL/1_interop"}),
                         ("6.8.0-48-generic", {})):
        assert linux.why_not_native("Linux administration", "linux", release, env) == ""  # Linux, WSL's or its own
    assert linux.wsl(two, {"WSL_DISTRO_NAME": "Ubuntu"}) == "Ubuntu" and linux.wsl(one, {}) == "WSL"
    assert linux.wsl("6.8.0-48-generic", {"WSL_INTEROP": "/run/WSL/1_interop"}) == "WSL" and linux.wsl("6.8.0-48-generic", {}) == ""
    assert (linux.wsl_generation(two), linux.wsl_generation(one), linux.wsl_generation("6.8.0-48-generic")) == (2, 1, 0)
    assert linux.wsl_table("admin", "6.8.0-48-generic", {}) is None and linux.wsl_table("firewall", "6.8.0-48-generic", {}) is None
    admin = linux.wsl_table("admin", two, {"WSL_DISTRO_NAME": "Ubuntu"}, systemd=True)
    assert admin["title"] == "Under WSL" and [r[0] for r in admin["rows"]] == ["This Linux", "Init", "Running", "At boot"]
    assert admin["rows"][0][1] == "WSL 2: Ubuntu" and admin["rows"][1][1] == "systemd" and "as on any Linux" in admin["rows"][1][2]
    off = linux.wsl_table("admin", two, {"WSL_DISTRO_NAME": "Ubuntu"}, systemd=False)["rows"][1]
    assert off[1] == "not systemd" and "systemd=true" in off[2] and "/etc/wsl.conf" in off[2]
    fw = linux.wsl_table("firewall", two, {"WSL_DISTRO_NAME": "Ubuntu"})
    assert [r[0] for r in fw["rows"]] == ["This Linux", "Packet filter", "Network"] and "once their tools are installed" in fw["rows"][1][2]
    assert "Windows' firewall first" in fw["rows"][2][2]
    old = linux.wsl_table("firewall", one, {})["rows"]
    assert old[0][1] == "WSL 1: WSL" and old[1][1] == "none" and "no firewall can run" in old[1][2]
    if not sys.platform.startswith("linux"):
        assert linux.wsl() == "" and linux.wsl_table("admin") is None  # asked on Windows: not WSL, whatever its variables
    if sys.platform == "win32":
        assert "and this one runs Windows" in linux.why_not_native("X")

    class Elsewhere(MachinePlugin):
        name, title, about, api = "elsewhere", "Elsewhere", "a plugin for another machine", "2.1"

        def not_for_here(self):
            return "for another machine"

        def present(self):
            raise AssertionError("asked")
    assert MachinePlugin().not_for_here() == "" and Elsewhere().status() == {
        "present": False, "summary": "not for this machine", "valid": False, "why": "for another machine", "applies": False}
