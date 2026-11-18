"""A model server started by the system when its user signs in (liminal_libs.machines.autostart, 1.62.0): the script
PowerShell is given (a task at this user's logon running the command itself at the normal priority, never the
highest run level, never through Windows' prompt; a path or a description holding any of PowerShell's five single
quotes carried exactly, as its tokenizer reads them), the user unit's text on a temporary home (the start limit, the
launcher alone told to stop, the command as systemd reads it) and the commands that enable it (never sudo), a unit's
file that cannot be written or removed said in words, a plugin's registrations read in one command, started, stopped
and removed, the names a task or a unit may carry, and the words of `how` and `why_not`.

Nothing is registered and nothing runs here: stand-ins answer for powershell.exe and for this Linux's commands, and
the shared guard (conftest.py) fails a test that starts a process or opens a connection."""
from __future__ import annotations

import fnmatch
import json
import os
import pathlib
import re
import shlex
import subprocess

import pytest

from liminal_libs.machines import autostart
from liminal_libs.machines.admin import Startup
from liminal_libs.machines.linux import Shell
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.windows import ERROR_MARK, PowerShell, decoded

from test_systemd import read_exec

pytestmark = pytest.mark.usefixtures("no_outside")

PYTHONW = r"C:\Program Files\Liminal\.venv\Scripts\pythonw.exe"
SERVE = [PYTHONW, "-m", "liminal_libs.machines.launch", "serve", "ollama", "default",
         "--home", r"C:\Users\some one\AppData\Local\Liminal\platform", "--plugins", r"C:\liminal\incoming"]
TASK = "LiminalAI-ollama-default"
PYTHON = "/home/me/my venv/bin/python"
SERVE_LINUX = [PYTHON, "-m", "liminal_libs.machines.launch", "serve", "vllm", "gpu-0",
               "--home", "/home/me/.local/share/liminal/platform", "--plugins", "/home/me/liminal/incoming"]
SERVE_LINUX_SHOWN = " ".join(SERVE_LINUX)  # as `systemctl show` writes a command: its words, spaces between
UNIT = "liminal-ai-vllm-gpu-0.service"
NAMED_BY = "a start at boot is named by its"
WHICH_SYSTEM = "made on Windows .a scheduled task. or on Linux .a systemd user unit., not on"


# -- stand-ins ---------------------------------------------------------------------------------------------------------
def unquoted(text: str) -> str:
    return text.replace("''", "'")


class Tasks:
    """A stand-in for powershell.exe: Task Scheduler's tasks kept in memory, every script it was given decoded."""

    QUOTED = r"'((?:[^']|'')*)'"
    ARGS = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"]

    def __init__(self, tasks=None, says=None):
        self.tasks: dict[str, dict] = dict(tasks or {})
        self.says = says  # an answer given to every script in place of its own
        self.scripts: list[str] = []
        self.timeouts: list[float] = []

    def __call__(self, args, timeout):
        assert args[:6] == self.ARGS
        s = decoded(args[6])
        self.scripts.append(s)
        self.timeouts.append(timeout)
        if self.says is not None:
            return self.says
        named = re.search(r"-TaskName " + self.QUOTED, s)
        name = unquoted(named.group(1)) if named else ""
        if "Register-ScheduledTask" in s:
            argument = re.search(r"-Argument " + self.QUOTED, s)
            self.tasks[name] = {"State": "Ready", "RunLevel": "Limited", "LastRun": "1999-11-30 00:00",
                                "Execute": unquoted(re.search(r"-Execute " + self.QUOTED, s).group(1)),
                                "Arguments": unquoted(argument.group(1)) if argument else "", "LastResult": "267011"}
            return 0, "", ""
        if "Unregister-ScheduledTask" in s:
            return 0, ("removed\r\n" if self.tasks.pop(name, None) else "absent\r\n"), ""
        verb = re.search(r"; (Start|Stop)-ScheduledTask -TaskPath '\\' -TaskName ", s)
        if verb:
            if name not in self.tasks:  # the script's own throw, as PowerShell's catch prints it
                return 1, ERROR_MARK + unquoted(re.search(r"throw " + self.QUOTED, s).group(1)) + "\r\n", ""
            self.tasks[name]["State"] = "Running" if verb.group(1) == "Start" else "Ready"
            return 0, "", ""
        assert "Get-ScheduledTask" in s and "ConvertTo-Json" in s
        rows = [{"Name": n, **t} for n, t in self.tasks.items() if fnmatch.fnmatchcase(n.lower(), name.lower())]
        return 0, (json.dumps(rows[0] if len(rows) == 1 else rows) if rows else ""), ""  # one object alone: no list


class Plain(PowerShell):
    """A PowerShell that fails a test asking for an administrator's rights: a start at boot never does."""

    def run_elevated(self, script, timeout=600.0):
        raise AssertionError("a start at boot asked Windows for an administrator")

    def run_admin(self, script, timeout=120.0):
        raise AssertionError("a start at boot asked Windows for an administrator")


def windows(tasks=None, says=None):
    fake = Tasks(tasks, says)
    return fake, Plain(runner=fake, env={})


class Systemd:
    """A stand-in for this Linux's commands: the user's units as systemd would have them (their files are the
    temporary home's), every command it was given."""

    def __init__(self, units_dir, fails=(), bus=True):
        self.dir = units_dir
        self.fails = set(fails)  # the systemctl words that fail
        self.bus = bus
        self.enabled: set[str] = set()
        self.states: dict[str, dict] = {}
        self.calls: list[list[str]] = []
        self.scripts: list[str] = []

    def shown(self, f) -> str:
        """A unit as `systemctl show` writes it: its command's words, read as systemd reads them, spaces between."""
        argv = read_exec(re.search(r"^ExecStart=(.*)$", f.read_text(encoding="utf-8"), re.M).group(1))
        st = self.states.get(f.name, {})
        return (f"== {f.name}\nLoadState={st.get('load', 'loaded')}\nActiveState={st.get('active', 'inactive')}\n"
                f"SubState=dead\nUnitFileState={'enabled' if f.name in self.enabled else 'disabled'}\n"
                f"Result={st.get('result', 'success')}\n"
                f"ExecStart={{ path={argv[0]} ; argv[]={' '.join(argv)} ; ignore_errors=no ; start_time=[n/a] }}\n")

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        if args[:2] == ["sh", "-c"]:
            self.scripts.append(args[2])
            stem = re.search(r"for u in (\S+)\*\.service; do", args[2]).group(1)
            out = []
            for f in sorted(self.dir.glob(f"{stem}*.service")) if self.dir.is_dir() else []:
                if not self.bus:
                    return 1, "".join(out), "Failed to connect to bus: No medium found\n"
                out.append(self.shown(f))
            return 0, "".join(out), ""
        assert args[:2] == ["systemctl", "--user"], args
        word, unit = args[2], args[-1]
        if word in self.fails:
            return 1, "", f"Failed to {word} unit: Unit {unit} is refused for the test.\n"
        if word == "enable":
            self.enabled.add(unit)
        elif word == "disable":
            assert args[3] == "--now"
            self.enabled.discard(unit)
            self.states.setdefault(unit, {})["active"] = "inactive"
        elif word in ("start", "stop"):
            self.states.setdefault(unit, {})["active"] = "active" if word == "start" else "inactive"
        elif word == "reset-failed":
            self.states.setdefault(unit, {})["result"] = "success"
        else:
            assert args[2:] == ["daemon-reload"], args
        return 0, "", ""


def linux(tmp_path, **kw):
    fake = Systemd(tmp_path / ".config" / "systemd" / "user", **kw)
    return fake, Shell("local", runner=fake)


def systemctl(fake) -> list[list[str]]:
    """What systemctl was asked, without its `--user`."""
    return [c[2:] for c in fake.calls if c[0] == "systemctl"]


def on_linux(units, sh, tmp_path, plugin="vllm", instance="gpu-0", about="vLLM"):
    return autostart.register(plugin, instance, SERVE_LINUX, about, system="linux", shell=sh, home=tmp_path)


# -- names -------------------------------------------------------------------------------------------------------------
def test_a_task_and_a_unit_are_named_by_the_plugin_and_the_instance():
    assert autostart.name_of("ollama", "default", "windows") == "LiminalAI-ollama-default"
    assert autostart.name_of("llamacpp", "gpu-box-2", "linux") == "liminal-ai-llamacpp-gpu-box-2.service"
    assert autostart.name_of("vllm", "0", " Windows ") == "LiminalAI-vllm-0"


@pytest.mark.parametrize("plugin, instance", [
    ("admin-linux", "default"), ("Ollama", "default"), ("", "default"), ("a b", "x"), ("9lives", "x"), ("o" * 33, "x"),
    ("x'; Remove-Item C:\\ -Recurse #", "default"), ("ollama", "Default"), ("ollama", "a b"), ("ollama", ""),
    ("ollama", "-x"), ("ollama", "x" * 33), ("ollama", "$(reboot)"), ("ollama", "*"), ("ollama", "../up"),
    ("ollama", "default\n"), ("ollama\n", "default"), ("ollama", "default\r\n")])
def test_a_name_neither_can_carry_reaches_no_script(plugin, instance, tmp_path):
    tasks, ps = windows()
    units, sh = linux(tmp_path)
    for system, outside in (("windows", {"powershell": ps}), ("linux", {"shell": sh})):
        home = {} if system == "windows" else {"home": tmp_path}
        with pytest.raises(ValueError, match=NAMED_BY):
            autostart.name_of(plugin, instance, system)
        with pytest.raises(ValueError, match=NAMED_BY):
            autostart.register(plugin, instance, SERVE, "about", system=system, **outside, **home)
        with pytest.raises(ValueError, match=NAMED_BY):
            autostart.remove(plugin, instance, system=system, **outside, **home)
        with pytest.raises(ValueError, match=NAMED_BY):
            autostart.act(plugin, instance, "start", system=system, **outside)
        if plugin != "ollama":
            with pytest.raises(ValueError, match="named by its plugin"):
                autostart.read(plugin, system=system, **outside)
    assert tasks.scripts == [] and units.calls == [] and list(tmp_path.iterdir()) == []


def test_a_system_that_is_neither_is_refused_in_words():
    tasks, ps = windows()
    for call in (lambda: autostart.name_of("ollama", "default", "darwin"), lambda: autostart.how("freebsd"),
                 lambda: autostart.read("ollama", system="", powershell=ps),
                 lambda: autostart.register("ollama", "default", SERVE, "about", system="darwin", powershell=ps),
                 lambda: autostart.remove("ollama", "default", system=None, powershell=ps),
                 lambda: autostart.act("ollama", "default", "start", system="macos", powershell=ps)):
        with pytest.raises(ValueError, match=WHICH_SYSTEM):
            call()
    assert tasks.scripts == []


# -- Windows: the task -------------------------------------------------------------------------------------------------
def test_the_task_is_registered_at_this_users_logon_and_runs_the_command_itself():
    tasks, ps = windows()
    got = autostart.register("ollama", "default", SERVE, "Ollama's server default", system="windows", powershell=ps)
    script = tasks.scripts[0]
    assert script.startswith("$ErrorActionPreference = 'Stop'")  # PowerShell.run's own wrapping
    # at this user's logon, as the admin plugin's logon task
    assert "$t = New-ScheduledTaskTrigger -AtLogOn -User \"$env:USERDOMAIN\\$env:USERNAME\"; " in script
    # ... and at the normal priority a program its user starts has: Task Scheduler's own default, 7, is below normal
    assert ("$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew "
            "-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority 5; ") in script
    assert autostart.PRIORITY == 5 and script.count("-Priority") == 1
    assert (f"Register-ScheduledTask -TaskPath '\\' -TaskName '{TASK}' -Action $a -Trigger $t -Settings $s "
            "-Description 'Ollama''s server default (made by the Liminal platform)' -Force | Out-Null") in script
    # its action is the command it was given and nothing wrapped around it: no keeper, no log
    arguments = subprocess.list2cmdline(SERVE[1:])
    assert f"$a = New-ScheduledTaskAction -Execute '{PYTHONW}' -Argument '{arguments}'; " in script
    assert arguments.endswith(
        '--home "C:\\Users\\some one\\AppData\\Local\\Liminal\\platform" --plugins C:\\liminal\\incoming')
    assert "machines.keep" not in script and "--log" not in script and script.count("liminal_libs.") == 1
    # with the user's ordinary rights: no run level, no principal, no password, no other trigger, nothing elevated
    for word in ("Highest", "RunLevel", "Principal", "RunAs", "S4U", "-Password", "-AtStartup", "Start-Process",
                 "-Verb"):
        assert word not in script, word
    # made, not run, and read back in one more command
    assert len(tasks.scripts) == 2 and not any("Start-ScheduledTask" in s for s in tasks.scripts)
    assert got == Startup("default", TASK, "ready", f"{PYTHONW} {arguments}", "last run never, result not run yet")
    assert got.present and got.at == "logon"


def test_a_command_of_one_word_has_no_argument_and_a_description_is_one_plain_line():
    tasks, ps = windows()
    program = "C:\\ollama\\serve.exe"
    autostart.register("ollama", "big", [program], "A server\r\nof 100%\x07 mine", system="windows", powershell=ps)
    assert "$a = New-ScheduledTaskAction -Execute 'C:\\ollama\\serve.exe'; $t = " in tasks.scripts[0]
    assert "-Argument" not in tasks.scripts[0]
    assert "-Description 'A server of 100% mine (made by the Liminal platform)' -Force" in tasks.scripts[0]
    autostart.register("ollama", "big", program, "x" * 500, system="windows", powershell=ps)  # one word, not a list
    assert "-Description '" + "x" * 120 + " (made by the Liminal platform)'" in tasks.scripts[2]
    autostart.register("ollama", "big", ["serve.exe"], "", system="windows", powershell=ps)
    assert "-Description 'A model server (made by the Liminal platform)'" in tasks.scripts[4]


PS_QUOTES = "'\u2018\u2019\u201a\u201b"  # what PowerShell ends a single-quoted string at: ' and the typographic four


def read_after(script: str, flag: str) -> str:
    """The single-quoted string right after `flag`, read as PowerShell's tokenizer reads one: it ends at any of its
    five quotes, and two of them in a row stand for the second."""
    i = script.index(flag + " ") + len(flag) + 1
    assert script[i] in PS_QUOTES, script[i:i + 20]
    text, i = [], i + 1
    while True:
        c = script[i]
        if c in PS_QUOTES:
            if script[i + 1] in PS_QUOTES:
                text.append(script[i + 1])
                i += 2
                continue
            return "".join(text)
        text.append(c)
        i += 1


def test_a_typographic_quote_in_a_path_or_a_description_stays_inside_its_string():
    # a folder named with a curled apostrophe, a title typed on a keyboard that curls its quotes: each is carried as
    # it is, and nothing after it is read as a command (windows.quote doubles all five)
    tasks, ps = windows()
    folder = "C:\\Users\\O\u2019Neil \u2018one\u2019 \u201atwo\u201b 'three'\\AppData\\Local\\Liminal"
    command = [folder + "\\.venv\\Scripts\\pythonw.exe", "-m", "liminal_libs.machines.launch", "serve", "ollama",
               "default", "--home", folder + "\\platform"]
    about = "Bob\u2019s GPU box \u2018fast\u2019 \u201alow\u201b 'plain'; Remove-Item C:\\ -Recurse #"
    autostart.register("ollama", "default", command, about, system="windows", powershell=ps)
    script = tasks.scripts[0]
    assert read_after(script, "-Execute") == command[0]
    assert read_after(script, "-Argument") == subprocess.list2cmdline(command[1:])
    assert read_after(script, "-Description") == f"{about} (made by the Liminal platform)"
    assert read_after(script, "-TaskName") == TASK
    assert script.count("Remove-Item") == 1  # only inside the description's string


def test_a_command_that_cannot_be_carried_is_refused_before_anything_is_written(tmp_path):
    tasks, ps = windows()
    units, sh = linux(tmp_path)
    for bad, words in (([], "none was given"), ([""], "none was given"), (None, "none was given"),
                       ([PYTHONW, "two\nlines"], "control character"), ([PYTHON, "a\x00b"], "control character")):
        with pytest.raises(ValueError, match=words):
            autostart.register("ollama", "default", bad, "about", system="windows", powershell=ps)
        with pytest.raises(ValueError, match=words):
            autostart.register("ollama", "default", bad, "about", system="linux", shell=sh, home=tmp_path)
    assert tasks.scripts == [] and units.calls == [] and list(tmp_path.iterdir()) == []


def test_a_plugins_tasks_are_read_in_one_command_by_instance():
    mine = {"State": "Running", "Execute": PYTHONW, "Arguments": "-m liminal_libs.machines.launch serve ollama default",
            "RunLevel": "Limited", "LastRun": "2026-11-16 07:14", "LastResult": "267009"}
    tasks, ps = windows({
        TASK: mine,
        "LiminalAI-ollama-gpu-box": {**mine, "State": "Disabled", "LastRun": "", "LastResult": "0"},
        "liminalai-OLLAMA-old": {**mine, "State": "Ready", "RunLevel": "Highest", "LastResult": "2147942402"},
        "LiminalAI-ollama-Not An Instance": mine,  # no instance is named so: not one of them
        "LiminalAI-ollamax-default": mine, "LiminalAI-vllm-default": mine, "LiminalPlatform": mine})
    got = autostart.read("ollama", system="windows", powershell=ps)
    assert len(tasks.scripts) == 1 and tasks.timeouts == [autostart.READ_S]
    assert ("Get-ScheduledTask -TaskPath '\\' -TaskName 'LiminalAI-ollama-*' -ErrorAction SilentlyContinue | "
            "ForEach-Object { ") in tasks.scripts[0]
    assert sorted(got) == ["default", "gpu-box", "old"]
    assert got["default"] == Startup("default", TASK, "running", f"{PYTHONW} {mine['Arguments']}",
                                     "last run 2026-11-16 07:14, result running")
    assert (got["gpu-box"].state, got["gpu-box"].detail) == ("disabled", "last run never, result 0 (ok)")
    assert got["old"].name == "liminalai-OLLAMA-old" and got["old"].detail == (
        "last run 2026-11-16 07:14, result 0x80070002; it runs with the highest rights, which a start at boot never "
        "asks for: remove it and register it again")
    assert autostart.read("vllm", system="windows", powershell=ps)["default"].name == "LiminalAI-vllm-default"
    assert autostart.read("aider", system="windows", powershell=ps) == {}  # none registered: nothing, and no failure


def test_tasks_that_cannot_be_read_are_said_in_words():
    tasks, ps = windows(says=(0, "not the tasks' JSON", ""))
    with pytest.raises(CommandError, match="Task Scheduler's answer could not be read"):
        autostart.read("ollama", system="windows", powershell=ps)
    tasks, ps = windows(says=(1, ERROR_MARK + "Access is denied.", ""))
    with pytest.raises(CommandError, match="Access is denied") as e:
        autostart.register("ollama", "default", SERVE, "about", system="windows", powershell=ps)
    assert e.value.denied and len(tasks.scripts) == 1  # said as it is: nobody is asked for an administrator


def test_a_task_is_started_and_stopped_as_the_system_does():
    tasks, ps = windows()
    autostart.register("ollama", "default", SERVE, "Ollama", system="windows", powershell=ps)
    assert autostart.act("ollama", "default", "start", system="windows", powershell=ps) is None
    assert tasks.tasks[TASK]["State"] == "Running"
    assert tasks.scripts[-1].count(f"Start-ScheduledTask -TaskPath '\\' -TaskName '{TASK}'") == 1
    assert autostart.read("ollama", system="windows", powershell=ps)["default"].state == "running"
    autostart.act("ollama", "default", "stop", system="windows", powershell=ps)
    assert f"; Stop-ScheduledTask -TaskPath '\\' -TaskName '{TASK}'" in tasks.scripts[-1]
    assert tasks.tasks[TASK]["State"] == "Ready"
    with pytest.raises(CommandError, match="^LiminalAI-ollama-gone is not registered here$"):
        autostart.act("ollama", "gone", "start", system="windows", powershell=ps)
    before = len(tasks.scripts)
    for action in ("restart", "run", "", None, "Start"):
        with pytest.raises(ValueError, match="started or stopped, not"):
            autostart.act("ollama", "default", action, system="windows", powershell=ps)
    assert len(tasks.scripts) == before


def test_a_task_is_stopped_then_removed():
    tasks, ps = windows()
    autostart.register("ollama", "default", SERVE, "Ollama", system="windows", powershell=ps)
    assert autostart.remove("ollama", "default", system="windows", powershell=ps) is True
    script = tasks.scripts[-1]
    stop, gone = script.index("Stop-ScheduledTask"), script.index("Unregister-ScheduledTask")
    assert stop < gone and "-Confirm:$false" in script and tasks.tasks == {}
    assert autostart.remove("ollama", "default", system="windows", powershell=ps) is False  # there was none


# -- Linux: the user unit ----------------------------------------------------------------------------------------------
def test_the_unit_is_written_into_the_users_own_units_and_enabled(tmp_path):
    units, sh = linux(tmp_path)
    got = on_linux(units, sh, tmp_path, about="vLLM's server gpu-0: 100% of the card")
    path = tmp_path / ".config" / "systemd" / "user" / UNIT
    assert path.read_bytes().decode("utf-8") == (
        "[Unit]\n"
        "Description=vLLM's server gpu-0: 100%% of the card (made by the Liminal platform)\n"
        "StartLimitIntervalSec=600\n"
        "StartLimitBurst=5\n"
        "\n"
        "[Service]\n"
        'ExecStart="/home/me/my venv/bin/python" -m liminal_libs.machines.launch serve vllm gpu-0 '
        "--home /home/me/.local/share/liminal/platform --plugins /home/me/liminal/incoming\n"
        "Restart=on-failure\n"
        "RestartSec=10\n"
        "KillMode=mixed\n"
        "KillSignal=SIGINT\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n")
    assert [p.name for p in path.parent.iterdir()] == [UNIT]  # written whole: no part left beside it
    # read by systemd and enabled as the user, never root: no sudo, nothing started
    assert systemctl(units) == [["daemon-reload"], ["enable", UNIT]]
    assert all(c[0] in ("systemctl", "sh") for c in units.calls) and len(units.scripts) == 1
    assert got == Startup("gpu-0", UNIT, "ready", SERVE_LINUX_SHOWN, "enabled")


def test_the_units_command_is_the_one_given_as_systemd_reads_it_and_its_start_limit_is_the_units():
    text = autostart.unit_text("Ollama's server default", SERVE_LINUX)
    sections: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.startswith("["):
            current = sections.setdefault(line, [])
        elif line:
            current.append(line)
    assert list(sections) == ["[Unit]", "[Service]", "[Install]"]
    assert sections["[Unit]"][1:] == ["StartLimitIntervalSec=600", "StartLimitBurst=5"]  # where systemd reads them
    service = dict(line.split("=", 1) for line in sections["[Service]"])
    assert read_exec(service.pop("ExecStart")) == SERVE_LINUX  # nothing wrapped around it
    # a stop tells the launcher alone (SIGINT), which ends its server in order: not every process of the unit at once
    assert service == {"Restart": "on-failure", "RestartSec": "10", "KillMode": "mixed", "KillSignal": "SIGINT"}
    assert sections["[Install]"] == ["WantedBy=default.target"]
    assert "keep" not in text and "--log" not in text and "User=" not in text and "sudo" not in text
    odd = [PYTHON, "-m", "x", "--home", "/data/50% off/$HOME"]
    assert read_exec(autostart.unit_text("x", odd).split("ExecStart=")[1].splitlines()[0]) == odd


def test_a_unit_systemd_refuses_is_taken_away_again(tmp_path):
    units, sh = linux(tmp_path, fails=("enable",))
    with pytest.raises(CommandError, match="Failed to enable unit"):
        on_linux(units, sh, tmp_path)
    assert list((tmp_path / ".config" / "systemd" / "user").iterdir()) == []
    assert systemctl(units) == [["daemon-reload"], ["enable", UNIT], ["daemon-reload"]]
    units, sh = linux(tmp_path, fails=("daemon-reload",))  # no systemd to talk to at all
    with pytest.raises(CommandError, match="Failed to daemon-reload"):
        on_linux(units, sh, tmp_path)
    assert list((tmp_path / ".config" / "systemd" / "user").iterdir()) == []


def test_a_units_file_that_cannot_be_written_or_removed_is_said_in_words(tmp_path, monkeypatch):
    # a file where the folder of units would be: said as a CommandError, as every other failure here is
    units, sh = linux(tmp_path)
    (tmp_path / ".config").write_text("not a folder", encoding="utf-8")
    with pytest.raises(CommandError) as e:
        on_linux(units, sh, tmp_path)
    assert str(e.value).startswith(f"the unit {UNIT} could not be written into ") and ".config" in str(e.value)
    assert units.calls == []  # systemd is told nothing of a unit that is not there
    (tmp_path / ".config").unlink()
    # a disk that fills while the unit is written: the half-written part is taken away again
    real_write, real_unlink = pathlib.Path.write_text, pathlib.Path.unlink

    def full(self, data, *args, **kwargs):
        real_write(self, data[:10], encoding="utf-8")
        raise OSError(28, "No space left on device", str(self))
    with monkeypatch.context() as m:
        m.setattr(pathlib.Path, "write_text", full)
        with pytest.raises(CommandError, match="could not be written into .*: No space left on device: "):
            on_linux(units, sh, tmp_path)
    assert list(units.dir.iterdir()) == [] and units.calls == []
    # one that cannot be removed: stopped and disabled, then the file's refusal said, the file left as it is
    on_linux(units, sh, tmp_path)
    units.calls.clear()

    def refused(self, missing_ok=False):
        if self.name == UNIT:
            raise PermissionError(13, "Permission denied", str(self))
        return real_unlink(self, missing_ok=missing_ok)
    with monkeypatch.context() as m:
        m.setattr(pathlib.Path, "unlink", refused)
        with pytest.raises(CommandError, match=f"^the unit {UNIT} could not be removed from .*: Permission denied: "):
            autostart.remove("vllm", "gpu-0", system="linux", shell=sh, home=tmp_path)
    assert systemctl(units) == [["disable", "--now", UNIT]] and (units.dir / UNIT).is_file()
    assert autostart.remove("vllm", "gpu-0", system="linux", shell=sh, home=tmp_path) is True  # it can be now


def test_a_plugins_units_are_read_in_one_command_by_instance(tmp_path):
    units, sh = linux(tmp_path)
    for instance in ("a", "b", "c", "d", "e"):
        on_linux(units, sh, tmp_path, instance=instance)
    on_linux(units, sh, tmp_path, plugin="ollama", instance="a", about="Ollama")
    other = units.dir / "liminal-ai-vllm-Not An Instance.service"  # no instance is named so: not one of them
    other.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    units.states.update({"liminal-ai-vllm-a.service": {"active": "active"},
                         "liminal-ai-vllm-b.service": {"active": "activating"},
                         "liminal-ai-vllm-c.service": {"active": "failed", "result": "start-limit-hit"},
                         "liminal-ai-vllm-e.service": {"load": "masked"}})
    units.enabled.discard("liminal-ai-vllm-d.service")
    units.calls.clear()
    units.scripts.clear()
    got = autostart.read("vllm", system="linux", shell=sh, home=tmp_path)
    assert units.calls == [["sh", "-c", units.scripts[0]]]  # one command, as the user: no sudo in front
    assert {k: (v.state, v.detail) for k, v in got.items()} == {
        "a": ("running", "enabled"), "b": ("starting", "enabled"),
        "c": ("failed", "enabled; last result start-limit-hit"), "d": ("disabled", "disabled"),
        "e": ("unknown", "enabled; systemd says masked")}
    assert got["a"] == Startup("a", "liminal-ai-vllm-a.service", "running", SERVE_LINUX_SHOWN, "enabled")
    assert sorted(autostart.read("ollama", system="linux", shell=sh, home=tmp_path)) == ["a"]
    assert autostart.read("aider", system="linux", shell=sh, home=tmp_path) == {}


def test_the_units_are_looked_for_where_they_are_written(tmp_path, monkeypatch):
    # the folder `register` writes in (units_dir) is the one `read` looks in, however XDG_CONFIG_HOME is set: a
    # relative one names none (XDG's rule and systemd's), and the shell is never left to read it another way
    units, sh = linux(tmp_path)
    mine = autostart.Path.home() / ".config"
    for named, folder in ((None, mine), ("", mine), ("relative/cfg", mine), ("/home/me/cfg", "/home/me/cfg")):
        if named is None:
            monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        else:
            monkeypatch.setenv("XDG_CONFIG_HOME", named)
        assert autostart.read("vllm", system="linux", shell=sh) == {}
        where = autostart.Path(folder, "systemd", "user").as_posix()
        assert autostart.units_dir().as_posix() == where  # what register writes into, without a home
        assert units.scripts[-1].startswith(f"cd {shlex.quote(where)} 2>/dev/null || exit 0\n"), named
    script = units.scripts[0]
    assert "for u in liminal-ai-vllm-*.service; do\n" in script and '[ -f "$u" ] || continue' in script
    assert ('systemctl --user show -p LoadState,ActiveState,SubState,UnitFileState,Result,ExecStart "$u" '
            "|| exit $?") in script
    home = tmp_path / "it's mine"
    autostart.read("vllm", system="linux", shell=sh, home=home)
    where = (home / ".config" / "systemd" / "user").as_posix()
    assert units.scripts[-1].startswith("cd '" + where.replace("'", "'\"'\"'") + "' 2>/dev/null || exit 0\n")
    # the folder itself
    assert autostart.units_dir(tmp_path) == tmp_path / ".config" / "systemd" / "user"
    assert autostart.units_dir(env={"XDG_CONFIG_HOME": "/home/me/cfg"}).as_posix() == "/home/me/cfg/systemd/user"
    for unset in ({}, {"XDG_CONFIG_HOME": ""}, {"XDG_CONFIG_HOME": "relative/cfg"}):
        assert autostart.units_dir(env=unset) == autostart.Path.home() / ".config" / "systemd" / "user"


def test_units_that_cannot_be_read_are_said_in_systemds_words(tmp_path):
    units, sh = linux(tmp_path)
    on_linux(units, sh, tmp_path)
    units.bus = False
    with pytest.raises(CommandError, match="Failed to connect to bus: No medium found"):
        autostart.read("vllm", system="linux", shell=sh, home=tmp_path)
    # a registration that cannot be read back is still said as made
    units, sh = linux(tmp_path, bus=False)
    got = on_linux(units, sh, tmp_path, instance="gpu-1")
    assert (got.app, got.name, got.state) == ("gpu-1", "liminal-ai-vllm-gpu-1.service", "unknown")
    assert got.command.startswith("'/home/me/my venv/bin/python' -m liminal_libs.machines.launch serve vllm gpu-0")
    assert got.detail == "registered; it could not be read back: Failed to connect to bus: No medium found"


def test_a_unit_is_started_and_stopped_as_the_user(tmp_path):
    units, sh = linux(tmp_path)
    on_linux(units, sh, tmp_path)
    units.states[UNIT] = {"active": "failed", "result": "start-limit-hit"}
    units.calls.clear()
    assert autostart.act("vllm", "gpu-0", "start", system="linux", shell=sh) is None
    assert systemctl(units) == [["reset-failed", UNIT], ["start", UNIT]]  # left failed by its limit: its user asked
    assert autostart.read("vllm", system="linux", shell=sh, home=tmp_path)["gpu-0"].state == "running"
    units.calls.clear()
    autostart.act("vllm", "gpu-0", "stop", system="linux", shell=sh)
    assert units.calls == [["systemctl", "--user", "stop", UNIT]]
    units, sh = linux(tmp_path, fails=("start", "reset-failed"))
    with pytest.raises(CommandError, match="Failed to start unit"):
        autostart.act("vllm", "gpu-0", "start", system="linux", shell=sh)
    with pytest.raises(ValueError, match="started or stopped, not 'enable'"):
        autostart.act("vllm", "gpu-0", "enable", system="linux", shell=sh)


def test_a_unit_is_stopped_then_removed(tmp_path):
    units, sh = linux(tmp_path)
    on_linux(units, sh, tmp_path)
    units.calls.clear()
    assert autostart.remove("vllm", "gpu-0", system="linux", shell=sh, home=tmp_path) is True
    assert systemctl(units) == [["disable", "--now", UNIT], ["daemon-reload"], ["reset-failed", UNIT]]
    assert list(units.dir.iterdir()) == [] and units.enabled == set()
    assert autostart.read("vllm", system="linux", shell=sh, home=tmp_path) == {}
    # none there: nothing to remove, and a systemd that says no is not a failure of the tidying
    units, sh = linux(tmp_path, fails=("disable", "daemon-reload", "reset-failed"))
    assert autostart.remove("vllm", "gpu-0", system="linux", shell=sh, home=tmp_path) is False


def test_a_linux_reached_from_outside_is_refused(tmp_path):
    units = Systemd(tmp_path)
    outside = Shell("wsl:Ubuntu", runner=units)
    for call in (lambda: autostart.read("vllm", system="linux", shell=outside),
                 lambda: on_linux(units, outside, tmp_path),
                 lambda: autostart.remove("vllm", "gpu-0", system="linux", shell=outside, home=tmp_path),
                 lambda: autostart.act("vllm", "gpu-0", "start", system="linux", shell=outside)):
        with pytest.raises(CommandError, match="the Linux the platform itself runs on, never on WSL's Ubuntu"):
            call()
    assert units.calls == [] and list(tmp_path.iterdir()) == []


# -- what a command is run with ----------------------------------------------------------------------------------------
class Ran:
    """subprocess.run as this module's own runner calls it, stood in for: how each command was started (nothing
    runs), and the answer it gives, or what it raises."""

    def __init__(self, raises=None):
        self.calls: list[tuple[list[str], dict]] = []
        self.raises = raises

    def __call__(self, args, **how):
        self.calls.append((list(args), how))
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(args, 0, b"", b"")


def test_no_pair_of_liminals_reaches_a_command_it_runs(tmp_path, monkeypatch):
    ran = Ran()
    monkeypatch.setattr(autostart.subprocess, "run", ran)
    monkeypatch.setenv("LIMINAL_AI_OLLAMA_DEFAULT_KEY", "sk-not-for-a-child")  # a pair, as the Login keeps one
    monkeypatch.setenv("Liminal_Platform_Dir", "C:\\somewhere")  # any case: Windows does not tell names apart by it
    monkeypatch.setenv("SOMETHING_OF_THE_USERS", "kept")
    here = "windows" if os.name == "nt" else "linux"
    plugin, instance, command = ("ollama", "default", SERVE) if here == "windows" else ("vllm", "gpu-0", SERVE_LINUX)
    # no PowerShell or Shell handed in: this module's own runner, windowless, nothing typed into the command
    assert autostart.read(plugin, system=here, home=tmp_path) == {}
    args, how = ran.calls[0]
    assert args[0] == ("powershell.exe" if here == "windows" else "sh") and how["timeout"] == autostart.READ_S
    assert how["capture_output"] is True and how["stdin"] is subprocess.DEVNULL
    assert how.get("creationflags") == (0x08000000 if os.name == "nt" else None)
    # ... and without an environment given, this process's own without any LIMINAL_* name (a net only)
    assert not any(name.upper().startswith("LIMINAL_") for name in how["env"])
    assert "sk-not-for-a-child" not in how["env"].values() and how["env"]["SOMETHING_OF_THE_USERS"] == "kept"
    # the environment a plugin hands in (its child_env(): every pair of every plugin taken out) is the whole of it,
    # for every command of every call
    given = {"PATH": "/usr/bin", "SYSTEMROOT": "C:\\Windows"}
    ran.calls.clear()
    autostart.register(plugin, instance, command, "about", system=here, home=tmp_path, env=given)
    autostart.act(plugin, instance, "start", system=here, env=given)
    autostart.remove(plugin, instance, system=here, home=tmp_path, env=given)
    autostart.read(plugin, system=here, home=tmp_path, env=given)
    assert len(ran.calls) >= 4 and all(how["env"] == given and how["env"] is not given for _, how in ran.calls)
    assert autostart.environment(given) == given and autostart.environment()["SOMETHING_OF_THE_USERS"] == "kept"


def test_a_command_this_module_cannot_run_is_said_in_words(tmp_path, monkeypatch):
    here = "windows" if os.name == "nt" else "linux"
    plugin = "ollama" if here == "windows" else "vllm"
    for raises, words in ((subprocess.TimeoutExpired(["x"], 30), "took more than 30 s$"),
                          (FileNotFoundError(2, "No such file or directory"), "could not run: .*No such file")):
        monkeypatch.setattr(autostart.subprocess, "run", Ran(raises))
        with pytest.raises(CommandError, match=words):
            autostart.read(plugin, system=here, home=tmp_path)
    ran = Ran()
    monkeypatch.setattr(autostart.subprocess, "run", ran)
    other = autostart._runner(os.name != "nt")  # the other system's: said, and nothing started
    with pytest.raises(CommandError, match="this is not Windows" if os.name != "nt" else "and this is Windows$"):
        other(["anything"], 1.0)
    assert ran.calls == []
    assert autostart._runner(os.name == "nt")(["anything"], 1.0, "fed") == (0, "", "")  # what is handed to it, fed
    assert ran.calls[0][1]["input"] == b"fed" and "stdin" not in ran.calls[0][1]


# -- the words ---------------------------------------------------------------------------------------------------------
def test_how_it_is_started_is_said_for_a_confirmation():
    task = autostart.how("windows")
    assert task == ("A scheduled task of yours is registered, run at your logon with your ordinary rights: no "
                    "administrator is asked and no password is kept")
    unit = autostart.how("linux")
    assert unit == "A systemd user unit of yours is written (~/.config/systemd/user) and enabled: no root is asked"
    assert autostart.how("linux", "Ubuntu") == unit + (
        "; it starts when this distribution starts and you are signed in to it, not when the PC does")
    assert autostart.how("windows", "Ubuntu") == task  # Windows is not inside a distribution
    assert not task.endswith(".") and not unit.endswith(".")  # a sentence the confirmation ends itself


def test_why_none_can_be_registered_here(monkeypatch):
    assert autostart.why_not("windows") == "" and autostart.why_not("windows", systemd=False, wsl="Ubuntu") == ""
    assert autostart.why_not("linux", systemd=True) == "" and autostart.why_not("linux", True, "Ubuntu") == ""
    assert autostart.why_not("linux", systemd=False, wsl="Ubuntu") == (
        "start at boot needs systemd, which is off in this distribution: `[boot]` `systemd=true` in /etc/wsl.conf "
        "turns it on (then `wsl --shutdown` from Windows)")
    assert autostart.why_not("linux", systemd=False, wsl="") == (
        "start at boot needs systemd's user units, and this machine's init is not systemd")
    assert autostart.why_not("darwin").startswith("a start at boot is made on Windows")
    # not said: read from this Linux
    monkeypatch.setattr(autostart.linux, "systemd_runs", lambda: False)
    monkeypatch.setattr(autostart.linux, "wsl", lambda: "Ubuntu")
    assert "in this distribution" in autostart.why_not("linux")
    monkeypatch.setattr(autostart.linux, "wsl", lambda: "")
    assert autostart.why_not("linux").endswith("this machine's init is not systemd")
    monkeypatch.setattr(autostart.linux, "systemd_runs", lambda: True)
    assert autostart.why_not("linux") == ""


def test_the_module_names_no_host():
    text = autostart.Path(autostart.__file__).read_text(encoding="utf-8")
    assert re.search(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]", text) is None
