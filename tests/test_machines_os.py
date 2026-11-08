"""Windows and Linux for the machine plugins (liminal_libs.machines.windows, .linux): PowerShell with an
encoded, wrapped script and its failures in its own words, elevation asked only when the user says so; Linux
commands as root here (sudo -n) or in a WSL distribution (wsl -u root). Nothing runs: stand-in runners."""
from __future__ import annotations

import json

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
    assert local.where == "this machine" and not local.root() and local.run("ufw", "status") == "ok\n" and got[-1] == ["sudo", "-n", "ufw", "status"]
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
