"""A model server started by the system when its user signs in (1.62.0; the user, 2026-11-16: "the plugins manage
the services, the app can be started @ boot like a service, ports can be configured via the plugin, the plugin should
report conflicts."). One instance of a plugin, one registration, made only when its user confirms it on the page:

- Windows: a scheduled task `LiminalAI-<plugin>-<instance>` at this user's logon, as the admin plugin's logon task
  is made: with the user's ordinary rights (never the highest run level, never through Windows' prompt), no time
  limit, never a second copy while one runs, on batteries too, and at the normal priority of a program its user
  starts (PRIORITY: Task Scheduler's own default, 7, is below normal, and the server would inherit it).
- Linux: a systemd user unit `liminal-ai-<plugin>-<instance>.service` in the user's own units
  ($XDG_CONFIG_HOME/systemd/user, ~/.config/systemd/user without it or with a relative one: `units_dir`, the one
  folder both `register` and `read` use), enabled for default.target, started again
  10 s after a failure and left failed after 5 starts in 600 s. A stop sends SIGINT to the launcher alone
  (KillMode=mixed), which ends its server in order and then itself; what is left after it, systemd ends. No root, no
  sudo. Only on the Linux the platform itself runs on: a WSL distribution is never reached from Windows.

What a task or a unit runs is the command it is given and nothing wrapped around it: the launcher's `serve`
(machines/launch.py) supervises itself, reads the instance through the login at each start and names no key, so
nothing written here goes stale and no secret is in a task, a unit or a command line. That is also why `register`
takes no log, unlike the first sketch of this module: there is no keeper around `serve` to hand one to, and `serve`
notes its own starts and ends. A registration is made, not run: `act` starts or stops it, as the system would.
`read` is one command for all of a plugin's instances.

A stop on Windows is Task Scheduler's (`act(..., "stop")`, and `remove` before it unregisters): the task's process
is ended at once and the server with it, through the launcher's job object, with no time to end by itself. A plugin
that wants its server's own clean end interrupts the server first (children.Child.adopt(...).stop()), then stops the
task while the launcher waits to start it again.

Each call raises CommandError in the system's own words when its command fails (windows.PowerShell, linux.Shell) or
a unit's file cannot be written or removed, and ValueError for a name, a system or an action that is not one. A
runner stands in for the commands in tests.

Every command runs windowless with the environment it is given whole (`env`: an AI plugin hands its child_env()),
else this process's own without any LIMINAL_* name (terminal.inherited: a net only, since the other plugins' pairs
are not known here). A PowerShell or a Shell handed in runs as it runs (a test's)."""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from collections.abc import Mapping
from pathlib import Path

from ..instances import NAME as INSTANCE, has_control
from ..proc import no_window
from ..systemd import command as unit_command
from . import linux
from .admin import Startup
from .linux import Shell
from .plugin import CommandError
from .terminal import inherited
from .windows import PowerShell, quote

SYSTEMS = ("windows", "linux")
ACTIONS = ("start", "stop")
PLUGIN = re.compile(r"[a-z][a-z0-9]{0,31}")  # a plugin a task or a unit is named by, as admin.BOOT_NAME names an app
TASK = "LiminalAI-"  # LiminalAI-<plugin>-<instance>
UNIT = "liminal-ai-"  # liminal-ai-<plugin>-<instance>.service
MADE_BY = "made by the Liminal platform"
ABOUT_MOST = 120  # characters of a description
RESTART_S = 10  # a unit is started again this long after a failure
START_LIMIT = (600, 5)  # ... and left failed after 5 starts in 600 s: one that can never start is not started for ever
PRIORITY = 5  # a task's priority: 4 to 6 are the normal class (Task Scheduler's own 7 is below normal)
READ_S = 30.0
ACT_S = 120.0  # a stop may wait for the server to end
TASK_VERBS = {"start": "Start-ScheduledTask", "stop": "Stop-ScheduledTask"}
RESULTS = {0: "0 (ok)", 0x41301: "running", 0x41303: "not run yet", 0x41306: "ended by request"}  # a task's last result
TASKS_READ = ("Get-ScheduledTask -TaskPath '\\' -TaskName @NAME@ -ErrorAction SilentlyContinue | ForEach-Object { "
              "$i = $_ | Get-ScheduledTaskInfo; "
              "[pscustomobject]@{ Name = [string]$_.TaskName; State = $_.State.ToString(); "
              "Execute = [string]$_.Actions[0].Execute; Arguments = [string]$_.Actions[0].Arguments; "
              "RunLevel = [string]$_.Principal.RunLevel; "
              "LastRun = $(if ($i.LastRunTime) { $i.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { '' }); "
              "LastResult = [string]$i.LastTaskResult } }")
UNITS_SHOWN = "LoadState,ActiveState,SubState,UnitFileState,Result,ExecStart"  # what is read of a unit
UNITS_READ = ("cd @DIR@ 2>/dev/null || exit 0\n"
              "for u in @STEM@*.service; do\n"
              "  [ -f \"$u\" ] || continue\n"
              "  echo \"== $u\"\n"
              f"  systemctl --user show -p {UNITS_SHOWN} \"$u\" || exit $?\n"
              "done\n")


# -- names and words -----------------------------------------------------------------------------------------------
def _system(system) -> str:
    word = str(system or "").strip().lower()
    if word not in SYSTEMS:
        raise ValueError(f"a start at boot is made on Windows (a scheduled task) or on Linux (a systemd user unit), "
                         f"not on {system!r}")
    return word


def _plugin(plugin) -> str:
    text = str(plugin or "")
    if not PLUGIN.fullmatch(text):
        raise ValueError("a start at boot is named by its plugin, lowercase letters and digits starting with a letter, "
                         f"32 at most: not {text[:40]!r}")
    return text


def _instance(instance) -> str:
    text = str(instance or "")
    if not INSTANCE.fullmatch(text):  # (its `$` alone would let a name ending in a line break through)
        raise ValueError("a start at boot is named by its instance, lowercase letters, digits and dashes, 32 at most: "
                         f"not {text[:40]!r}")
    return text


def name_of(plugin: str, instance: str, system: str) -> str:
    """The task (LiminalAI-<plugin>-<instance>) or the unit (liminal-ai-<plugin>-<instance>.service) that starts an
    instance. ValueError for a name neither can carry: nothing but these names reaches a script."""
    which, plugin, instance = _system(system), _plugin(plugin), _instance(instance)
    return f"{TASK}{plugin}-{instance}" if which == "windows" else f"{UNIT}{plugin}-{instance}.service"


def how(system: str, wsl: str = "") -> str:
    """How an instance is started at boot on this system, for a confirmation's words: one sentence, without its full
    stop. `wsl`: the WSL distribution this Linux is, "" on a machine of its own."""
    if _system(system) == "windows":
        return ("A scheduled task of yours is registered, run at your logon with your ordinary rights: no "
                "administrator is asked and no password is kept")
    words = "A systemd user unit of yours is written (~/.config/systemd/user) and enabled: no root is asked"
    if wsl:
        words += "; it starts when this distribution starts and you are signed in to it, not when the PC does"
    return words


def why_not(system: str, systemd: bool | None = None, wsl: str | None = None) -> str:
    """Why no start at boot can be registered here, in words ("" when one can): Linux without systemd as its init.
    `systemd`: whether it runs, `wsl`: the WSL distribution this Linux is (each read here when not given)."""
    try:
        which = _system(system)
    except ValueError as e:
        return str(e)
    if which == "windows" or (linux.systemd_runs() if systemd is None else systemd):
        return ""
    if linux.wsl() if wsl is None else wsl:
        return ("start at boot needs systemd, which is off in this distribution: `[boot]` `systemd=true` in "
                "/etc/wsl.conf turns it on (then `wsl --shutdown` from Windows)")
    return "start at boot needs systemd's user units, and this machine's init is not systemd"


def _about(about) -> str:
    """A description on one line, cut at ABOUT_MOST, no control character in it."""
    text = " ".join("".join(c if ord(c) >= 32 and ord(c) != 127 else " " for c in str(about or "")).split())
    return f"{text[:ABOUT_MOST] or 'A model server'} ({MADE_BY})"


def _words(command) -> list[str]:
    """The command as its words; ValueError for none, or for one neither a task nor a unit can carry."""
    words = [str(w) for w in ([command] if isinstance(command, str) else command or [])]
    if not words or not words[0].strip():
        raise ValueError("a start at boot runs a command, and none was given")
    for w in words:
        if has_control(w):
            raise ValueError(f"{w!r} cannot be written into a task or a unit: it holds a control character")
    return words


def _line(words: list[str], which: str) -> str:
    return subprocess.list2cmdline(words) if which == "windows" else shlex.join(words)


# -- how a command is run -------------------------------------------------------------------------------------------
environment = inherited  # a command's whole environment: `env` as given, else this process's without LIMINAL_*


def _runner(windows: bool, env: Mapping[str, str] | None = None):
    """What runs this module's commands when no PowerShell or Shell is handed in (windows.PowerShell and linux.Shell
    take it as their runner): the command windowless, nothing typed into it but what it is handed, its environment
    `environment(env)`, what it says as text. CommandError in words when it is not this system's, cannot be started
    or takes too long."""
    def run(args, timeout, stdin=None):
        args = [str(a) for a in args]
        name = "PowerShell" if windows else (args[0] if args else "the command")
        if windows != (os.name == "nt"):
            raise CommandError("Windows PowerShell is not here (this is not Windows)" if windows else
                               "a start at boot on Linux is made on the Linux the platform itself runs on, and this is "
                               "Windows")
        fed = {"input": str(stdin).encode("utf-8")} if stdin is not None else {"stdin": subprocess.DEVNULL}
        try:
            done = subprocess.run(args, capture_output=True, timeout=timeout, env=environment(env), **fed,
                                  **no_window())
        except subprocess.TimeoutExpired:
            raise CommandError(f"{name} took more than {timeout:g} s") from None
        except (OSError, ValueError) as e:  # (ValueError: a NUL in a word or a variable)
            raise CommandError(f"{name} could not run: {e}") from None
        return (done.returncode, (done.stdout or b"").decode("utf-8", "replace"),
                (done.stderr or b"").decode("utf-8", "replace"))
    return run


def _powershell(powershell, env: Mapping[str, str] | None = None) -> PowerShell:
    """The PowerShell handed in (a test's), else this module's own (`_runner`)."""
    return powershell if powershell is not None else PowerShell(runner=_runner(True, env))


# -- Windows: a scheduled task at this user's logon -----------------------------------------------------------------
def task_script(task: str, command: list[str], description: str) -> str:
    """The PowerShell that registers the task, as the admin plugin's logon task is registered: at this user's logon,
    no time limit, never a second copy, on batteries too, at PRIORITY; its action the command itself, its arguments
    quoted as Windows reads a command line. No principal is named: the task is its user's, with the user's ordinary
    rights."""
    exe, *args = command
    action = f"$a = New-ScheduledTaskAction -Execute {quote(exe)}"
    if args:
        action += f" -Argument {quote(subprocess.list2cmdline(args))}"
    return (f"{action}; "
            "$t = New-ScheduledTaskTrigger -AtLogOn -User \"$env:USERDOMAIN\\$env:USERNAME\"; "
            "$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew "
            f"-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority {PRIORITY}; "
            f"Register-ScheduledTask -TaskPath '\\' -TaskName {quote(task)} -Action $a -Trigger $t -Settings $s "
            f"-Description {quote(description)} -Force | Out-Null")


def _result(value) -> str:
    """A task's last result in words: ok, not run yet, running, else Windows' own code in hexadecimal."""
    try:
        code = int(str(value).strip())
    except (TypeError, ValueError):
        return str(value or "")
    return RESULTS.get(code, f"0x{code & 0xFFFFFFFF:08X}")


def _read_tasks(plugin: str, ps) -> dict[str, Startup]:
    stem = f"{TASK}{plugin}-"
    try:
        rows = ps.json(TASKS_READ.replace("@NAME@", quote(stem + "*")), READ_S)
    except ValueError as e:  # an answer that is not the tasks' JSON
        raise CommandError(f"Task Scheduler's answer could not be read: {e}") from None
    out: dict[str, Startup] = {}
    for r in rows:
        name = str(r.get("Name") or "")
        instance = name[len(stem):]
        if name[:len(stem)].lower() != stem.lower() or not INSTANCE.fullmatch(instance):
            continue  # not an instance's task
        last = str(r.get("LastRun") or "")
        when = "never" if not last or last[:4] < "2000" else last  # Windows writes 1999 for a task never run
        notes = [f"last run {when}, result {_result(r.get('LastResult'))}"]
        if str(r.get("RunLevel") or "").lower() == "highest":
            notes.append("it runs with the highest rights, which a start at boot never asks for: remove it and "
                         "register it again")
        out[instance] = Startup(instance, name, str(r.get("State") or "").lower() or "unknown",
                                f"{r.get('Execute') or ''} {r.get('Arguments') or ''}".strip(), "; ".join(notes))
    return out


# -- Linux: a systemd user unit -------------------------------------------------------------------------------------
def units_dir(home: Path | str | None = None, env=None) -> Path:
    """Where the user's own units are: `home`/.config/systemd/user; without `home`, $XDG_CONFIG_HOME/systemd/user
    when that names a whole path, else under the user's home (a relative one names none, by XDG's rule and
    systemd's; `env`: the environment, a test's). `register` writes there, and `read` looks there."""
    if home is None:
        named = str((os.environ if env is None else env).get("XDG_CONFIG_HOME") or "")
        if named.startswith("/"):
            return Path(named) / "systemd" / "user"
        home = Path.home()
    return Path(home) / ".config" / "systemd" / "user"


def unit_text(about: str, command: list[str]) -> str:
    """The user unit: the command as systemd reads it (systemd.command), started again RESTART_S after a failure and
    left failed after START_LIMIT, wanted by default.target. Stopped by SIGINT to the launcher alone (KillMode=mixed:
    with systemd's own control-group every process of the unit would be told at once, the server's workers before
    the launcher could end them in order); what is left once the launcher has ended, systemd ends. ValueError for a
    word a unit cannot carry."""
    said = _about(about).replace("%", "%%")  # a % would be read as one of systemd's specifiers
    return ("[Unit]\n"
            f"Description={said}\n"
            f"StartLimitIntervalSec={START_LIMIT[0]}\n"
            f"StartLimitBurst={START_LIMIT[1]}\n\n"
            "[Service]\n"
            f"ExecStart={unit_command(_words(command))}\n"
            "Restart=on-failure\n"
            f"RestartSec={RESTART_S}\n"
            "KillMode=mixed\n"
            "KillSignal=SIGINT\n\n"
            "[Install]\n"
            "WantedBy=default.target\n")


def _local(shell, env: Mapping[str, str] | None = None) -> Shell:
    """This Linux's commands as the platform's user (the Shell handed in, else one on this module's own `_runner`);
    refused for a Linux reached from outside (a WSL distribution from Windows)."""
    sh = shell if shell is not None else Shell("local", runner=_runner(False, env))
    if getattr(sh, "target", "local") != "local":
        raise CommandError(f"a start at boot is made on the Linux the platform itself runs on, never on {sh.where}")
    return sh


def _systemctl(sh: Shell, *words: str, quietly: bool = False) -> None:
    """`systemctl --user ...` as the platform's user, never root; `quietly`: what it says and whether it ran are not
    looked at (tidying up, where there may be nothing to tidy)."""
    try:
        sh.run("systemctl", "--user", *words, root=False, timeout=ACT_S, check=not quietly)
    except CommandError:
        if not quietly:
            raise


def _unit_state(fields: dict) -> str:
    load, active = fields.get("LoadState", ""), fields.get("ActiveState", "")
    if load != "loaded":
        return "unknown"  # its file is there and systemd does not have it (masked, in error, not read yet)
    if active in ("active", "reloading"):
        return "running"
    if active == "activating":
        return "starting"
    if active == "failed":
        return "failed"
    return "ready" if fields.get("UnitFileState") == "enabled" else "disabled"


def _read_units(plugin: str, sh: Shell, home) -> dict[str, Startup]:
    stem = f"{UNIT}{plugin}-"
    where = shlex.quote(units_dir(home).as_posix())  # the folder register writes in, as this process names it
    text = sh.sh(UNITS_READ.replace("@DIR@", where).replace("@STEM@", stem), root=False, timeout=READ_S)
    found: dict[str, dict[str, str]] = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("== "):
            current = found.setdefault(line[3:].strip(), {})
        elif current is not None and "=" in line:
            key, _, value = line.partition("=")
            current[key] = value
    out: dict[str, Startup] = {}
    for unit, fields in found.items():
        instance = unit[len(stem):-len(".service")] if unit.startswith(stem) and unit.endswith(".service") else ""
        if not INSTANCE.fullmatch(instance):
            continue  # not an instance's unit
        ran = re.search(r"argv\[\]=([^;]*)", fields.get("ExecStart", ""))
        load, result = fields.get("LoadState", ""), fields.get("Result", "")
        notes = [fields.get("UnitFileState") or "not enabled"]
        if load != "loaded":
            notes.append(f"systemd says {load or 'nothing of it'}")
        if result not in ("", "success"):
            notes.append(f"last result {result}")
        out[instance] = Startup(instance, unit, _unit_state(fields), ran.group(1).strip() if ran else "",
                                "; ".join(notes))
    return out


def _os_words(e: OSError) -> str:
    """What the system said, and of which path."""
    said = e.strerror or str(e) or type(e).__name__
    return f"{said}: {e.filename}" if e.filename else said


def _gone(path: Path) -> None:
    """A file taken away, tidying up: one that is not there, or cannot be removed, is left as it is."""
    try:
        path.unlink()
    except OSError:
        pass


def _write_unit(path: Path, text: str, sh: Shell) -> None:
    """The unit written whole (a file beside it moved into place), read by systemd and enabled; when it cannot be
    written (CommandError in the system's words: a folder that is a file, a disk that is full, no right to write) or
    systemd refuses it, what was written is taken away again, so that nothing half made is left."""
    part = path.with_name(path.name + ".part")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        part.write_text(text, encoding="utf-8", newline="\n")
        os.replace(part, path)
    except OSError as e:
        _gone(part)
        raise CommandError(f"the unit {path.name} could not be written into {path.parent}: {_os_words(e)}") from None
    try:
        _systemctl(sh, "daemon-reload")
        _systemctl(sh, "enable", path.name)
    except CommandError:
        _gone(path)
        _systemctl(sh, "daemon-reload", quietly=True)
        raise


# -- what a plugin asks ---------------------------------------------------------------------------------------------
def read(plugin: str, *, system: str, powershell=None, shell=None, home=None,
         env: Mapping[str, str] | None = None) -> dict[str, Startup]:
    """A plugin's registrations by instance, in one command: each a Startup (admin.Startup) with the instance as its
    `app`, the task's or the unit's name, its state (ready, running, starting, failed, disabled, unknown ...), what
    it runs and a few words more. An instance without one is not among them. `home`: where the units are (a test's
    folder; the user's own without it: units_dir, the folder `register` writes in). `env`: the command's whole
    environment (the module's words)."""
    which, plugin = _system(system), _plugin(plugin)
    if which == "windows":
        return _read_tasks(plugin, _powershell(powershell, env))
    return _read_units(plugin, _local(shell, env), home)


def register(plugin: str, instance: str, command: list[str], about: str, *, system: str, powershell=None, shell=None,
             home=None, env: Mapping[str, str] | None = None) -> Startup:
    """The instance started from now on when its user signs in: made, not run. `command`: what is run, as it is given
    (the launcher's `serve`, which supervises itself); `about`: a few words for the task's or the unit's description.
    No log is given: nothing is wrapped around the command to write one, and `serve` notes its own starts and ends. An
    earlier one of that name is replaced. The registration as it is read back (state "unknown" when it cannot be).
    `env`: the commands' whole environment (the module's words)."""
    which, name, words = _system(system), name_of(plugin, instance, system), _words(command)
    if which == "windows":
        _powershell(powershell, env).run(task_script(name, words, _about(about)), ACT_S)
    else:
        _write_unit(units_dir(home) / name, unit_text(about, words), _local(shell, env))
    try:
        found = read(plugin, system=which, powershell=powershell, shell=shell, home=home, env=env).get(instance)
        problem = "registered, but not found when read back"
    except CommandError as e:
        found, problem = None, f"registered; it could not be read back: {e}"
    return found if found is not None else Startup(instance, name, "unknown", _line(words, which), problem)


def remove(plugin: str, instance: str, *, system: str, powershell=None, shell=None, home=None,
           env: Mapping[str, str] | None = None) -> bool:
    """The instance's start at boot stopped, then removed; whether there was one. On Windows the stop is Task
    Scheduler's, at once (the module's words say what a plugin does first for a clean end). `env`: the commands'
    whole environment (the module's words)."""
    which, name = _system(system), name_of(plugin, instance, system)
    if which == "windows":
        task = quote(name)
        out = _powershell(powershell, env).run(
            f"if (Get-ScheduledTask -TaskPath '\\' -TaskName {task} -ErrorAction SilentlyContinue) {{ "
            f"Stop-ScheduledTask -TaskPath '\\' -TaskName {task} -ErrorAction SilentlyContinue; "
            f"Unregister-ScheduledTask -TaskPath '\\' -TaskName {task} -Confirm:$false; 'removed' }} "
            "else { 'absent' }", ACT_S)
        return "removed" in out
    sh, path = _local(shell, env), units_dir(home) / name
    try:
        existed = path.is_file()
    except OSError as e:
        raise CommandError(f"the unit {name} could not be looked for in {path.parent}: {_os_words(e)}") from None
    _systemctl(sh, "disable", "--now", name, quietly=True)
    if existed:
        try:
            path.unlink()
        except FileNotFoundError:
            pass  # gone already: what was asked
        except OSError as e:
            raise CommandError(f"the unit {name} could not be removed from {path.parent}: {_os_words(e)}") from None
    _systemctl(sh, "daemon-reload", quietly=True)
    _systemctl(sh, "reset-failed", name, quietly=True)
    return existed


def act(plugin: str, instance: str, action: str, *, system: str, powershell=None, shell=None,
        env: Mapping[str, str] | None = None) -> None:
    """The registration started or stopped now, as the system does it at a logon: `action` is "start" or "stop". A
    unit left failed by its start limit is started all the same: its user asked. A stop on Windows ends the task at
    once, its server with it; on Linux systemd tells the launcher, which ends its server in order (the module's
    words say what a plugin does first on Windows for a clean end). `env`: the commands' whole environment (the
    module's words)."""
    which, name = _system(system), name_of(plugin, instance, system)
    if action not in ACTIONS:
        raise ValueError(f"a start at boot is started or stopped, not {action!r}")
    if which == "windows":
        task = quote(name)
        _powershell(powershell, env).run(
            f"if (-not (Get-ScheduledTask -TaskPath '\\' -TaskName {task} -ErrorAction SilentlyContinue)) "
            f"{{ throw {quote(name + ' is not registered here')} }}; "
            f"{TASK_VERBS[action]} -TaskPath '\\' -TaskName {task}", ACT_S)
        return
    sh = _local(shell, env)
    if action == "start":
        _systemctl(sh, "reset-failed", name, quietly=True)
    _systemctl(sh, action, name)
