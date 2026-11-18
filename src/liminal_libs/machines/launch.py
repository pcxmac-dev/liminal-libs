"""What a model server's start at boot runs (1.62.0; the user, 2026-11-16: "the app can be started @ boot like a
service"):

    python -m liminal_libs.machines.launch serve PLUGIN INSTANCE [--home FOLDER] [--plugins FOLDER]

A scheduled task at the user's logon (Windows) or a systemd user unit (Linux) runs it, as machines/autostart.py
registers it, and nothing is wrapped around it: `serve` supervises itself (keep.keep with its own `run`), so there is
one supervisor, not two. It sets LIMINAL_PLATFORM_DIR and LIMINAL_PLUGINS from its switches (`--home`: the platform's
folder; `--plugins`: the plugins' folder), finds the plugin in the registry, reads the instance through the user's
login (EnvironmentLogin over the saved variables: what the platform's page keeps), and runs the plugin's launch as a
children.Child with the same log and pidfile as a click's Start, started again after a failure (10 s at first, up to
10 minutes while it keeps failing soon after its start; keep's notes go to home/logs/<instance>.boot.log). Each round
reads the instance and its key again where the page keeps them: on Windows the user's saved variables, the copies of
the AI plugins' pairs (LIMINAL_AI_*) its own environment was started with being taken out first (an EnvironmentLogin
reads the process's environment over the saved one, and those copies are as the pairs were when its task started;
they are read only under the saved ones, for a pair those do not hold). So a port, a setting or a key changed on the
page is what the next round starts. What a task or a unit holds is the plugin's and the instance's names, the two
folders and the Python, read when At boot is turned on: a changed LIMINAL_PLATFORM_DIR, LIMINAL_PLUGINS or Python
needs At boot turned off and on again. No key is in a task, a unit or a command line: the server is given it by its
environment.

It ends 0, its words in the instance's log (home/logs/<instance>.log), when there is nothing it can ever start: an
unknown plugin or instance, an instance that no longer starts at boot, the software not installed or unable to run
here; so neither the keeper of Windows nor systemd starts it again and again. What cannot be read now (a login that
does not answer, a kept value that is not readable, a fault of the plugin's own code) is no such thing: the round
says it and is tried again after the keeper's wait. It ends when its server ends well (exit 0), when its server was
stopped from the platform's page (the stop marker home/run/<instance>.stop), and when it is asked to end: Ctrl+C or
Ctrl+Break, SIGINT (systemd's stop: the unit's KillSignal), SIGTERM and SIGHUP (POSIX: a `kill`, a closed terminal),
each an orderly stop of its server (asked to end, then ended with what it started), then 0. On Windows Task
Scheduler's stop ends it at once and its server with it, through the child's job object.

`command()` is the line a task or a unit is given. A harness's window is console.py's (`python -m liminal_libs.console
hold`), not this module's."""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from .. import instances, layout
from .ai import PLATFORM_DIR_VAR, STEM, _stem, _words, platform_folder
from .autostart import PLUGIN  # a plugin a task or a unit is named by

MODULE = "liminal_libs.machines.launch"
STEP_S = 0.5  # seconds between two looks at the server and at the signals
POSIX_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP")  # ended as Ctrl+C is: an orderly stop of the server
WINDOWS_SIGNALS = ("SIGINT", "SIGBREAK")  # Ctrl+C and Ctrl+Break in a console it was started from
WHY = {"SIGINT": "Ctrl+C, or its unit stopped", "SIGTERM": "SIGTERM, sent by kill or another program",
       "SIGHUP": "its terminal closed", "SIGBREAK": "Ctrl+Break"}
PAIRS = _stem(STEM)  # the AI plugins' pairs (LIMINAL_AI_<NAME>_<WHAT>: AiPlugin.variable), kept by the page


class Ended(Exception):
    """`serve` was asked to end (a signal), or its server was stopped as asked: no round is started again."""


class Ending:
    """The signal a serve was asked to end by: a handler only sets a flag (it takes no lock, raises nothing and prints
    nothing, whatever the main thread is doing when it lands), which the rounds look at every STEP_S."""

    def __init__(self):
        self.by = ""  # the first signal that came ("SIGTERM"), "" while none has
        self.quieted = False

    def is_set(self) -> bool:
        return bool(self.by)

    def end(self, name: str, quiet: Callable[[], None] | None = None) -> None:
        if quiet is not None and not self.quieted:
            self.quieted = True
            try:
                quiet()
            except Exception:  # noqa: BLE001 - its output stays where it was
                pass
        if not self.by:
            self.by = name or "a signal"


def silence(fds: tuple[int, ...] = (1, 2)) -> None:
    """This process's output and errors sent to the null device (after SIGHUP: its terminal is gone, and a write to
    it would fail)."""
    null = os.open(os.devnull, os.O_WRONLY)
    try:
        for fd in fds:
            os.dup2(null, fd)
    finally:
        os.close(null)


def listen(ending: Ending, *, signals=None, posix: bool | None = None, quiet: Callable[[], None] | None = None
           ) -> tuple[str, ...]:
    """The signals that end a serve made to set `ending` (POSIX: SIGINT, SIGTERM, SIGHUP; Windows: SIGINT, SIGBREAK),
    from the main thread alone; one this process was started with ignored (nohup's SIGHUP) or handled by someone
    else's handler is left as it was. After SIGHUP the output is let go first (`quiet`; silence's by default). The
    names set. `signals`: the signal module (a test's stand-in); `posix`: whether this is POSIX (os.name's)."""
    signals = signal if signals is None else signals
    posix = os.name == "posix" if posix is None else bool(posix)
    if threading.current_thread() is not threading.main_thread():
        return ()
    quiet = silence if quiet is None else quiet
    default = (getattr(signals, "SIG_DFL", None), getattr(signals, "default_int_handler", None), None)
    names: dict[int, str] = {}
    for name in POSIX_SIGNALS if posix else WINDOWS_SIGNALS:
        number = getattr(signals, name, None)
        if number is None:
            continue
        try:
            now = signals.getsignal(number)
        except (OSError, ValueError, TypeError):
            continue
        if not any(now is d for d in default):
            continue  # ignored, or someone's own handler: left as it is
        names[number] = name

    def handler(number, frame=None) -> None:
        name = names.get(number) or f"signal {number}"
        ending.end(name, quiet if name == "SIGHUP" else None)

    done = []
    for number, name in names.items():
        try:
            signals.signal(number, handler)
        except (OSError, ValueError, RuntimeError):
            continue
        done.append(name)
    return tuple(done)


def _names(plugin, instance) -> tuple[str, str]:
    p, i = str(plugin or ""), str(instance or "")
    if not PLUGIN.fullmatch(p):
        raise ValueError("a start at boot names its plugin by lowercase letters and digits, starting with a letter, "
                         f"32 at most: not {p[:40]!r}")
    if not instances.NAME.fullmatch(i):
        raise ValueError("a start at boot names its instance by lowercase letters, digits and dashes, 32 at most: not "
                         f"{i[:40]!r}")
    return p, i


def command(plugin: str, instance: str, home, plugins=None, python: str | None = None) -> list[str]:
    """The line a task or a unit runs for one instance: this Python (pythonw.exe beside it on Windows: no window,
    admin.interpreter), `-m liminal_libs.machines.launch serve PLUGIN INSTANCE --home FOLDER [--plugins FOLDER]`.
    No key and no setting is in it: `serve` reads them at each start. ValueError for a name a task or a unit cannot
    carry, or a folder that is not a whole path."""
    from .admin import interpreter

    p, i = _names(plugin, instance)
    folders = [("--home", home), *((("--plugins", plugins),) if plugins else ())]
    out = [interpreter(python), "-m", MODULE, "serve", p, i]
    for switch, folder in folders:
        path = Path(folder)
        if not path.is_absolute():
            raise ValueError(f"{switch} is a whole path, not {str(folder)[:80]!r}")
        out += [switch, str(path)]
    return out


def _stamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def note(log: Path, line: str) -> None:
    """A line of serve's own in a log (never raises: a log that cannot be written is skipped), the log moved to
    <log>.1 first once it is past keep's size: a round tried again and again while its server never starts (a port
    held, a value not readable) adds a line each time, and no server's start moves it then. serve writes no line
    while its server writes there (only just after its start, when the server has moved it itself)."""
    from . import keep

    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        keep.rotate(log)
        with log.open("a", encoding="utf-8") as f:
            f.write(f"{_stamp()} liminal: serve: {line}\n")
    except OSError:
        pass


def _machine(name: str):
    from ..sources import registry  # when serve runs: it loads every plugin, as the platform does

    return registry.machine(name)


def _login(inherited: dict[str, str] | None = None):
    """serve's login: EnvironmentLogin over the user's saved variables (what the platform's page keeps), read again at
    each ask; `inherited` (forget_inherited's, on Windows) read under them, for a pair the saved ones do not hold (a
    saved variable that could not be read): an instance is never taken for forgotten for that."""
    from ..apps.authorization import EnvironmentLogin, saved_variables

    under = dict(inherited or {})
    if not under:
        return EnvironmentLogin(saved=saved_variables)
    return EnvironmentLogin(saved=lambda: {**under, **saved_variables()})


def forget_inherited(env=None) -> dict[str, str]:
    """The AI plugins' pairs (LIMINAL_AI_*) taken out of serve's own environment (`env`: os.environ), as serve does
    on Windows: there they are the user's saved variables as they were when its task started, read over the saved
    ones by its login, so every change the page made since would be hidden. Its login then reads them where the page
    keeps them, at each ask, these under them. No child is given them either way (children.environment drops
    LIMINAL_*). What was taken out, by name."""
    env = os.environ if env is None else env
    taken = {str(n): str(env[n]) for n in list(env) if str(n).upper().startswith(PAIRS)}
    for n in taken:
        env.pop(n, None)
    return taken


class Round:
    """One start of the server and its watch until it ends (keep.keep's `run`): its exit code for the keeper, 0 when
    there is nothing it can ever start or it was stopped as asked; Ended once serve is asked to end."""

    def __init__(self, server, name: str, ending: Ending, say: Callable[[str], None], *,
                 sleep: Callable[[float], None] | None = None, clock: Callable[[], float] | None = None):
        self.server, self.name, self.ending = server, name, ending
        self._say, self._sleep, self._clock = say, sleep, clock

    def say(self, line: str) -> None:
        """Its words in the instance's log, every secret its plugin read through the login taken out (a refusal or a
        failure may quote what it was given)."""
        scrub = getattr(self.server, "_scrubbed", None)
        self._say(scrub(line) if callable(scrub) else line)

    def never(self, kept=None) -> str:
        """"" or why its server can never be started as things are, in words (`kept`: its plugin's instances as just
        read; read now when not given). An instance not among them is forgotten only when they were read whole: one
        that could not be read now (a login that did not answer, a value that is not readable) is no reason, and the
        round tries again after the keeper's wait."""
        s, title = self.server, self.server.title or self.server.name
        kept = s.kept_instances() if kept is None else kept
        instance = kept.instances.get(self.name)
        if instance is None:
            if kept.problem:
                return ""
            return (f"{title} has no instance {self.name} (forgotten on its page?): nothing is started; its start at "
                    "boot is removed there")
        if not instance.boot:
            return (f"{self.name} does not start at boot (At boot is off on {title}'s page): nothing is started; its "
                    "start at boot is removed there")
        why = s.startable(instance)
        return f"{self.name} is not started: {why}" if why else ""

    def __call__(self) -> int:
        try:
            return self._round()
        except Ended:
            raise
        except Exception as e:  # noqa: BLE001 - what failed, in words: the keeper starts it again after its wait
            self.say(f"{self.name}: its round failed ({type(e).__name__}: {' '.join(str(e).split())}): it is tried "
                     "again later")
            return 1

    def _round(self) -> int:
        if self.ending.is_set():
            raise Ended(f"asked to end ({WHY.get(self.ending.by, self.ending.by)})")
        s = self.server
        kept = s.kept_instances()  # read once for the round: never raises, says what it could not read
        why = self.never(kept)
        if why:
            self.say(why)
            return 0
        instance = kept.instances.get(self.name)
        if instance is None:
            self.say(f"{self.name} is not started now: {kept.problem}: it is tried again later")
            return 1
        marker = s.stop_marker(self.name)
        try:
            marker.unlink()  # one left by a stop of an earlier start
        except OSError:
            pass
        problem = s.conflict(instance, ask=True)
        if problem:
            self.say(f"{self.name} is not started now: {problem}")
            return 1
        try:
            child = s.child(instance, s.prepared(instance))
            pid = child.start()
        except Exception as e:  # noqa: BLE001 - its refusal or its failure, in words: started again later
            self.say(f"{self.name} is not started now: {_words(e, (BaseException,))}")
            return 1
        self.say(f"{self.name} started (pid {pid}) by its start at boot, at {s.address(instance)}")
        while child.alive:
            if self.ending.is_set():
                try:
                    how = child.stop()
                except Exception as e:  # noqa: BLE001 - what could not be ended is said
                    how = f"could not be ended: {e}"
                raise Ended(f"asked to end ({WHY.get(self.ending.by, self.ending.by)}): {self.name} {how}")
            child.wait(STEP_S)
        code = child.code
        if marker.exists():
            try:
                marker.unlink()
            except OSError:
                pass
            self.say(f"{self.name} was stopped from the platform's page (exit code {code}): not started again")
            return 0
        self.say(f"{self.name} ended by itself (exit code {code})")
        return code if isinstance(code, int) else 1

    def pause(self, seconds: float) -> None:
        """The keeper's wait before it starts the server again, cut short (Ended) once serve is asked to end."""
        sleep, clock = self._sleep or time.sleep, self._clock or time.monotonic
        until = clock() + max(0.0, float(seconds))
        while not self.ending.is_set():
            left = until - clock()
            if left <= 0:
                return
            sleep(min(STEP_S, left))
        raise Ended(f"asked to end ({WHY.get(self.ending.by, self.ending.by)}) while it waited to start the server "
                    "again")


def serve(plugin: str, instance: str, home=None, plugins=None, *, find: Callable | None = None, login=None,
          signals=None, posix: bool | None = None, sleep: Callable[[float], None] | None = None,
          clock: Callable[[], float] | None = None) -> int:
    """One instance's server run and kept running until it ends well, is stopped as asked or serve is asked to end
    (the module's words): 0 then, and 0 with its words in the instance's log when there is nothing it can ever start;
    2 for names no task or unit carries. `find(name) -> plugin`, `login`, `signals`, `posix`, `sleep` and `clock`
    stand in for the registry, the user's login, the signal module, the system and the keeper's wait in tests."""
    try:
        name, inst = _names(plugin, instance)
    except ValueError as e:
        print(f"serve: {e}", file=sys.stderr)
        return 2
    if home is not None:
        os.environ[PLATFORM_DIR_VAR] = str(home)
    if plugins is not None:
        os.environ[layout.PLUGINS_VAR] = str(plugins)
    log = platform_folder() / "ai" / name / "logs" / f"{inst}.log"
    say = lambda line: note(log, line)  # noqa: E731 - its words, in the instance's log
    try:
        found = (find or _machine)(name)
    except Exception as e:  # noqa: BLE001 - plugins that cannot be found: said
        say(f"the plugins could not be read ({' '.join(str(e).split())}): nothing is started")
        return 0
    from .modelserver import ModelServer

    if found is None or not isinstance(found, ModelServer):
        what = "no plugin" if found is None else "no model server's plugin"
        say(f"{what} named {name} is installed here: nothing is started; its start at boot is removed on the "
            "platform's page, or once the plugin is installed again")
        return 0
    # on Windows its copies of the page's pairs as of its start: its login reads them where the page keeps them
    inherited = forget_inherited() if found.system == "windows" else {}
    found.login = login if login is not None else _login(inherited)
    ending = Ending()
    listen(ending, signals=signals, posix=posix)
    rounds = Round(found, inst, ending, say, sleep=sleep, clock=clock)
    try:
        why = rounds.never()
    except Exception:  # noqa: BLE001 - a fault of the plugin's own: the round says it, and the keeper tries again
        why = ""
    if why:
        say(why)
        return 0
    from . import keep

    try:
        return keep.keep([f"{name}/{inst}"], found.boot_log(inst), run=rounds, sleep=rounds.pause)
    except Ended as e:
        rounds.say(f"{e}: not started again")
        keep.note(found.boot_log(inst), f"serve: {e}: not started again")  # the keeper's own log says its end too
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=f"python -m {MODULE}",
                                     description="What a model server's start at boot runs: serve one instance.")
    sub = parser.add_subparsers(dest="command")
    s = sub.add_parser("serve", help="run one instance's server, started again after a failure")
    s.add_argument("plugin", help="the model server's plugin: ollama, llamacpp, vllm")
    s.add_argument("instance", help="its instance, as its page names it")
    s.add_argument("--home", help="the platform's folder (LIMINAL_PLATFORM_DIR)")
    s.add_argument("--plugins", help="the plugins' folder (LIMINAL_PLUGINS)")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, int) else 2
    if args.command != "serve":
        parser.print_usage(sys.stderr)
        return 2
    return serve(args.plugin, args.instance, args.home, args.plugins)


if __name__ == "__main__":
    sys.exit(main())
