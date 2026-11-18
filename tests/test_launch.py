"""What a model server's start at boot runs (liminal_libs.machines.launch, 1.62.0): `command()`'s line, with no key
in it; `serve` ending 0 with its words in the instance's log when there is nothing it can ever start (S4); its rounds
under keep.keep (S6): a server that ends well, one started again after the keeper's wait, the instance read again at
each round (on Windows where the page keeps it, not from the copies serve was started with), a stop from the
platform's page; a login that does not answer, a kept value that cannot be read and a fault of the plugin's own tried
again after the keeper's wait, never taken for an instance forgotten; its own lines keeping its log bounded; SIGTERM
(and SIGINT, and a signal while the keeper waits) as an orderly stop of its server; the signals it listens to and the
ones it leaves; its command line.

Nothing is started here: stand-ins answer for the registry, the login, the children, the socket table and the signal
module, and the shared guard (conftest.py) fails a test that starts a process or opens a connection."""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

import liminal_libs
from liminal_libs import mounts
from liminal_libs.apps.authorization import EnvironmentLogin, Login, Unauthorized, pair_name, variable_name
from liminal_libs.machines import children, keep, launch
from liminal_libs.machines.ai import Installed, Outside
from liminal_libs.machines.modelserver import Instance, Kept, ModelServer
from liminal_libs.resources import Conn
from liminal_libs.sources.apis import Api, Link

pytestmark = pytest.mark.usefixtures("no_outside")

HTTPS = "https:" + "//"
CARD = Api("Stand-in server", "Its maker", "What the stand-in server offers the platform", kind="rest",
           links=(Link("Its documentation", HTTPS + "docs.example.test/server"),), verified="2026-11-17")
KEY = "sk-stand-in-key-0123456789"
SIGINT, SIGTERM, SIGHUP, SIGBREAK = 2, 15, 1, 21


class Pairs(Login):
    def __init__(self, kept=None):
        self.kept: dict[str, str] = dict(kept or {})

    def user(self) -> dict:
        return {"name": "someone"}

    def vector(self, name: str) -> str:
        variable = variable_name(name)
        if variable not in self.kept:
            raise Unauthorized(f"no {name}", 404)
        return self.kept[variable]

    def names(self) -> set[str]:
        return {pair_name(v) for v in self.kept}

    def save(self, variable: str, value: str | None) -> str:
        if value is None:
            self.kept.pop(variable, None)
        else:
            self.kept[variable] = value
        return "the test's pairs"


class Signals:
    """The signal module as a test has it: the handlers set, and a way to send one."""

    SIG_DFL, SIG_IGN = object(), object()
    default_int_handler = object()

    def __init__(self, posix=True, ignored=()):
        self.SIGINT = SIGINT
        if posix:
            self.SIGTERM, self.SIGHUP = SIGTERM, SIGHUP
        else:
            self.SIGBREAK = SIGBREAK
        self.handlers = {n: self.SIG_DFL for n in (SIGTERM, SIGHUP, SIGBREAK)}
        self.handlers[SIGINT] = self.default_int_handler
        for n in ignored:
            self.handlers[n] = self.SIG_IGN

    def getsignal(self, n):
        return self.handlers.get(n, self.SIG_DFL)

    def signal(self, n, handler):
        self.handlers[n] = handler

    def send(self, n):
        self.handlers[n](n, None)


class Server(ModelServer):
    name = "tool"
    title = "Tool"
    about = "A stand-in model server for the launcher's tests"
    order = 510
    LIBS_FLOOR = "1.62.0"
    apis = (CARD,)
    DEFAULT_PORT = 11434
    READY_S = 60.0

    def __init__(self, outside=None):
        super().__init__(outside)
        self.have: Installed | None = Installed("1.2.3", "C:/tools/tool/tool.exe", "plugin")
        self.here = ""
        self.refuses: list[Exception] = []
        self.launched: list = []

    def installed(self):
        return self.have

    def runs_here(self):
        return self.here

    def launch(self, instance, key=""):
        if self.refuses:
            raise self.refuses.pop(0)
        self.launched.append((self.port_of(instance), bool(key)))
        return children.Launch(("tool", "serve", "--port", str(self.port_of(instance))),
                               env={"TOOL_API_KEY": key} if key else {})


class Probe:
    def __init__(self):
        self.conns: list[Conn] = []

    def connections(self):
        return list(self.conns)

    def program_names(self, pids=None):
        return {p: "ollama.exe" for p in (pids or ())}


class World:
    """A stand-in server found by `serve`, its children scripted: each child's waits, in order: ("run",) stays up,
    ("end", code) ends it, ("signal", n) sends n, ("marker",) leaves the page's stop marker."""

    def __init__(self, tmp: Path, monkeypatch, system="windows"):
        self.tmp, self.signals = tmp, Signals(posix=system != "windows")
        # (restored after it: serve sets both, from its switches; a path made before it lands in the same folder)
        monkeypatch.setenv("LIMINAL_PLATFORM_DIR", str(tmp / "platform"))
        monkeypatch.setenv("LIMINAL_PLUGINS", str(tmp / "elsewhere"))
        for name in [n for n in os.environ if n.upper().startswith("LIMINAL_AI_")]:
            monkeypatch.delenv(name)  # (restored after it: serve on Windows takes the AI plugins' pairs out)
        self.now = 1000.0
        self.slept: list[float] = []
        self.probe = Probe()
        self.server = Server(Outside(env={"PATH": "C:/tools", "MASSIVE_API_KEY": "m-key-1"}, system=system, wsl="",
                                     probe=self.probe, listening=lambda host, port: False,
                                     variables=lambda: ("MASSIVE_API_KEY",), clock=lambda: self.now))
        self.scripts: list[list[tuple]] = []
        self.made: list = []
        world = self

        class Child:
            def __init__(self, name, launch, log, pidfile, *, popen=None, system=None, **kw):
                self.name, self.launch, self.log, self.pidfile = name, launch, Path(log), Path(pidfile)
                self.alive, self.pid, self.code, self.since, self.note, self.stops = False, None, None, None, "", 0
                self.plan = list(world.scripts.pop(0)) if world.scripts else [("end", 0)]
                world.made.append(self)

            def start(self):
                self.alive, self.pid, self.since = True, 4300 + len(world.made), world.now
                return self.pid

            @classmethod
            def adopt(cls, *a, **k):
                return None

            def owns(self, pid):
                return pid == self.pid

            def wait(self, timeout=None):
                event = self.plan.pop(0) if self.plan else ("run",)
                if event[0] == "end":
                    self.alive, self.code = False, event[1]
                elif event[0] == "signal":
                    world.signals.send(event[1])
                elif event[0] == "marker":
                    world.server.stop_marker(self.name).parent.mkdir(parents=True, exist_ok=True)
                    world.server.stop_marker(self.name).write_text("stopped from the platform's page\n")
                return self.code

            def stop(self, grace=8.0):
                self.stops += 1
                self.alive, self.code = False, 0
                return "ended when asked (SIGTERM), after 0.1 s"

            def tail(self, lines=40):
                return []

        self.server.CHILD = Child
        self.login = Pairs()
        self.keep_instances(Instance("default", boot=True, keyed=True))
        self.login.kept[self.server.key_variable("default")] = KEY

    def keep_instances(self, *kept: Instance) -> None:
        self.login.kept[self.server.variable("instances")] = Kept({i.name: i for i in kept}).text()

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def serve(self, plugin="tool", instance="default", find=None, **more) -> int:
        return launch.serve(plugin, instance, self.tmp / "platform", self.tmp / "plugins",
                            find=find or (lambda name: self.server if name == "tool" else None), login=self.login,
                            signals=self.signals, posix=isinstance(getattr(self.signals, "SIGTERM", None), int),
                            sleep=self.sleep, clock=lambda: self.now, **more)

    @property
    def home(self) -> Path:
        return self.tmp / "platform" / "ai" / "tool"

    def log(self, name="default") -> str:
        path = self.home / "logs" / f"{name}.log"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def boot_log(self, name="default") -> str:
        path = self.home / "logs" / f"{name}.boot.log"
        return path.read_text(encoding="utf-8") if path.exists() else ""


@pytest.fixture(autouse=True)
def this_library(monkeypatch):
    monkeypatch.setattr(liminal_libs, "__version__", "1.62.0")
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: False)


@pytest.fixture
def world(tmp_path, monkeypatch):
    return World(tmp_path, monkeypatch)


# -- the line a task or a unit runs ------------------------------------------------------------------------------------
def test_command_is_serve_alone_and_holds_no_key(tmp_path):
    python = str(tmp_path / "py" / "python.exe")  # no pythonw.exe beside it: this one
    line = launch.command("ollama", "default", tmp_path / "platform", tmp_path / "plugins", python=python)
    assert line == [python, "-m", "liminal_libs.machines.launch", "serve", "ollama", "default",
                    "--home", str(tmp_path / "platform"), "--plugins", str(tmp_path / "plugins")]
    assert launch.command("vllm", "gpu-1", tmp_path, python=python)[-2:] == ["--home", str(tmp_path)]
    quiet = tmp_path / "venv" / "pythonw.exe"
    quiet.parent.mkdir()
    quiet.write_text("")
    assert launch.command("ollama", "default", tmp_path, python=str(quiet.with_name("python.exe")))[0] == str(quiet)


@pytest.mark.parametrize("plugin, instance, home, words", [
    ("Ollama", "default", None, "lowercase letters and digits"), ("ollama", "Default", None, "dashes"),
    ("ollama", "default\n", None, "dashes"), ("ollama", "default", "relative/folder", "a whole path")])
def test_command_refuses_what_a_task_cannot_carry(tmp_path, plugin, instance, home, words):
    with pytest.raises(ValueError) as caught:
        launch.command(plugin, instance, home or tmp_path, python="C:/py/python.exe")
    assert words in str(caught.value)


# -- nothing it can ever start: 0, its words in the instance's log (S4) ------------------------------------------------
def test_an_unknown_plugin_ends_serve_with_0_and_its_words(world):
    assert world.serve("ghost", "default") == 0
    said = (world.tmp / "platform" / "ai" / "ghost" / "logs" / "default.log").read_text(encoding="utf-8")
    assert "liminal: serve: no plugin named ghost is installed here: nothing is started" in said
    assert world.made == []


def test_a_plugin_that_is_no_model_server_ends_serve_with_0(world):
    assert world.serve(find=lambda name: object()) == 0
    assert "no model server's plugin named tool" in world.log()


@pytest.mark.parametrize("change, words", [
    (lambda w: w.keep_instances(), "Tool has no instance default (forgotten on its page?): nothing is started"),
    (lambda w: w.keep_instances(Instance("default")), "default does not start at boot (At boot is off"),
    (lambda w: setattr(w.server, "have", None), "default is not started: Tool is not installed here"),
    (lambda w: setattr(w.server, "here", "vLLM runs on Linux alone"), "default is not started: vLLM runs on Linux"),
    (lambda w: w.keep_instances(Instance("default", "found", boot=True)), "default does not start at boot")])
def test_nothing_it_can_ever_start_ends_serve_with_0_and_its_words(world, change, words):
    change(world)
    assert world.serve() == 0
    assert words in world.log() and world.made == [] and world.boot_log() == ""  # never started again


def test_serve_sets_the_platforms_and_the_plugins_folders(world):
    world.serve()
    assert os.environ["LIMINAL_PLATFORM_DIR"] == str(world.tmp / "platform")
    assert os.environ["LIMINAL_PLUGINS"] == str(world.tmp / "plugins")


# -- its rounds --------------------------------------------------------------------------------------------------------
def test_a_server_that_ends_well_ends_serve(world):
    world.scripts = [[("run",), ("end", 0)]]
    assert world.serve() == 0
    child = world.made[0]
    assert (child.log, child.pidfile) == (world.home / "logs" / "default.log", world.home / "run" / "default.pid")
    assert child.launch.argv == ("tool", "serve", "--port", "11434") and KEY not in " ".join(child.launch.argv)
    assert child.launch.secret == ("TOOL_API_KEY",) and "MASSIVE_API_KEY" in child.launch.drop
    said = world.log()
    assert f"default started (pid {child.pid}) by its start at boot, at 127.0.0.1:11434" in said
    assert "default ended by itself (exit code 0)" in said and KEY not in said
    assert "keep: starting tool/default" in world.boot_log()
    assert "it ended well (exit 0): not started again" in world.boot_log()


def test_a_failing_server_is_started_again_after_the_keepers_wait(world):
    world.scripts = [[("end", 3)], [("run",), ("end", 0)]]
    assert world.serve() == 0
    assert len(world.made) == 2 and sum(world.slept) == pytest.approx(10.0)  # keep's first wait
    assert "default ended by itself (exit code 3)" in world.log()
    assert "it ended with 3 after" in world.boot_log() and "started again in 10 s" in world.boot_log()


def changed_while_the_keeper_waits(world, change) -> None:
    """The keeper's wait made the moment the page changes something (no server runs then: the page allows it)."""
    def sleep(seconds):
        world.slept.append(seconds)
        world.now += seconds
        change()

    world.sleep = sleep


def test_the_instance_is_read_again_at_each_round(world):
    world.scripts = [[("end", 1)], [("end", 0)]]
    changed_while_the_keeper_waits(world, lambda: world.keep_instances(Instance("default", port=11500, boot=True,
                                                                                 keyed=True)))
    assert world.serve() == 0
    assert world.server.launched == [(11434, True), (11500, True)]


def test_on_windows_each_round_reads_what_the_page_keeps_not_what_serve_was_started_with(world, monkeypatch):
    """serve's own environment holds the AI plugins' pairs as they were when its task started (Task Scheduler hands
    it the user's saved variables of then), and its login reads that environment over the saved variables: those
    copies are taken out at its start, so each round reads the pairs where the page keeps them now."""
    variable, key = world.server.variable("instances"), world.server.key_variable("default")
    old = Kept({"default": Instance("default", boot=True, keyed=True)}).text()
    new = Kept({"default": Instance("default", port=11500, boot=True)}).text()
    monkeypatch.setenv(variable, old)  # what serve was started with
    monkeypatch.setenv(key, KEY)
    saved = {variable: old, key: KEY}  # the user's saved variables (the Environment key), where the page keeps them
    world.login = EnvironmentLogin(saved=lambda: dict(saved))  # serve's own kind of login
    world.scripts = [[("end", 1)], [("end", 0)]]

    def change():  # the port changed and the key forgotten on the page while the keeper waits
        saved[variable] = new
        saved.pop(key, None)

    changed_while_the_keeper_waits(world, change)
    assert world.serve() == 0
    assert world.server.launched == [(11434, True), (11500, False)]
    assert variable not in os.environ and key not in os.environ  # its own copies, taken out
    assert os.environ["LIMINAL_PLUGINS"] == str(world.tmp / "plugins")  # what it set itself stays


def test_serves_own_login_reads_the_saved_pairs_and_what_it_inherited_only_under_them(monkeypatch):
    """What serve took out of its environment is read only for a pair the saved variables do not hold (they could not
    be read): an instance still kept is never taken for forgotten for that."""
    from liminal_libs.apps import authorization

    variable = "LIMINAL_AI_TOOL_INSTANCES"
    monkeypatch.delenv(variable, raising=False)
    saved = {variable: "as the page keeps it now"}
    monkeypatch.setattr(authorization, "saved_variables", lambda: dict(saved))  # (the Environment key, stood in)
    login = launch._login({variable: "as serve was started with"})
    assert login.variables([variable]) == {variable: "as the page keeps it now"}
    saved.clear()  # the saved variables cannot be read now
    assert login.variables([variable]) == {variable: "as serve was started with"}
    assert launch.forget_inherited({variable: "x", "LIMINAL_PLUGINS": "y", "PATH": "z"}) == {variable: "x"}


def test_on_linux_its_environment_is_where_its_pairs_are(tmp_path, monkeypatch):
    """Off Windows nothing is saved to read instead (the Login's store on Linux is not built): its environment stays."""
    world = World(tmp_path, monkeypatch, system="linux")
    variable = world.server.variable("instances")
    monkeypatch.setenv(variable, Kept({"default": Instance("default", port=11500, boot=True)}).text())
    world.login = EnvironmentLogin(saved=lambda: {})
    world.scripts = [[("end", 0)]]
    assert world.serve() == 0 and world.server.launched == [(11500, False)] and variable in os.environ


def test_a_stop_from_the_page_ends_serve_with_its_server(world):
    world.scripts = [[("run",), ("marker",), ("end", 1)]]
    assert world.serve() == 0
    assert "was stopped from the platform's page (exit code 1): not started again" in world.log()
    assert not world.server.stop_marker("default").exists() and len(world.made) == 1


def test_a_stale_stop_marker_is_removed_before_a_start(world):
    marker = world.server.stop_marker("default")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("an earlier stop\n")
    world.scripts = [[("end", 0)]]
    assert world.serve() == 0 and not marker.exists() and "ended by itself (exit code 0)" in world.log()


def test_sigterm_is_an_orderly_stop_of_its_server(world):
    world.signals = Signals(posix=True)
    world.scripts = [[("run",), ("signal", SIGTERM), ("run",)]]
    assert world.serve() == 0
    child = world.made[0]
    assert child.stops == 1 and len(world.made) == 1
    said = world.log()
    ended = "asked to end (SIGTERM, sent by kill or another program): default ended when asked (SIGTERM), after 0.1 s"
    assert f"{ended}: not started again" in said
    assert f"keep: serve: {ended}" in world.boot_log()  # its end there


def test_sigint_from_its_unit_stops_its_server_too(world):
    world.signals = Signals(posix=True)
    world.scripts = [[("signal", SIGINT)]]
    assert world.serve() == 0 and world.made[0].stops == 1
    assert "asked to end (Ctrl+C, or its unit stopped)" in world.log()


def test_a_signal_while_the_keeper_waits_ends_serve(world):
    world.signals = Signals(posix=True)
    world.scripts = [[("end", 2)]]

    def sleep(seconds):
        world.slept.append(seconds)
        world.now += seconds
        if len(world.slept) == 3:
            world.signals.send(SIGTERM)

    world.sleep = sleep
    assert world.serve() == 0 and len(world.made) == 1
    assert "while it waited to start the server again: not started again" in world.log()


def test_a_conflict_or_a_refused_launch_is_tried_again_later(world):
    world.probe.conns.append(Conn(4321, "listening", "127.0.0.1:11434", ""))
    world.server.refuses = [ValueError("its models folder is not there yet")]
    world.scripts = [[("end", 0)]]
    original = world.server.conflict

    def conflict(instance, port=None, *, ask=False):
        found = original(instance, port, ask=ask)
        world.probe.conns.clear()  # the other program ends before the next round
        return found

    world.server.conflict = conflict
    world.now += 10
    assert world.serve() == 0 and len(world.made) == 1
    said = world.log()
    assert "default is not started now: port 11434 is held by ollama.exe (pid 4321)" in said
    assert "default is not started now: its models folder is not there yet" in said
    assert "ended by itself (exit code 0)" in said


class Unanswering(Pairs):
    """A login that does not answer its first `fails` asks (the login of a sign-in not ready yet)."""

    def __init__(self, kept, fails: int):
        super().__init__(kept)
        self.fails = fails

    def variables(self, wanted):
        if self.fails > 0:
            self.fails -= 1
            raise RuntimeError("the login did not answer")
        return super().variables(wanted)


def test_a_login_that_does_not_answer_is_asked_again_after_the_keepers_wait(world):
    """A kept value that cannot be read now is no instance forgotten: serve's own look and its first round are not
    answered, the keeper waits, and the next round starts the server."""
    world.login = Unanswering(world.login.kept, fails=2)
    world.scripts = [[("end", 0)]]
    assert world.serve() == 0 and len(world.made) == 1 and sum(world.slept) == pytest.approx(10.0)
    said = world.log()
    assert "forgotten" not in said and ("default is not started now: what is kept of the instances could not be read: "
                                        "RuntimeError: the login did not answer: it is tried again later") in said
    assert "started again in 10 s" in world.boot_log()


def test_a_kept_value_that_cannot_be_read_is_read_again_after_the_keepers_wait(world):
    variable = world.server.variable("instances")
    good, world.login.kept[variable] = world.login.kept[variable], "{broken"
    world.scripts = [[("end", 0)]]
    changed_while_the_keeper_waits(world, lambda: world.login.kept.update({variable: good}))  # added again
    assert world.serve() == 0 and len(world.made) == 1 and sum(world.slept) == pytest.approx(10.0)
    said = world.log()
    assert "forgotten" not in said
    assert "default is not started now: what is kept of the instances is not readable" in said


def test_a_fault_of_the_plugins_own_is_tried_again_after_the_keepers_wait(world):
    """What a plugin's own code raises (its installed() reading its folder) before the keeper runs is tried again too:
    serve does not end with it."""
    original, calls = world.server.installed, []

    def installed():
        calls.append(1)
        if len(calls) <= 2:  # serve's own look, then the first round's
            raise PermissionError("its folder could not be read")
        return original()

    world.server.installed = installed
    world.scripts = [[("end", 0)]]
    assert world.serve() == 0 and len(world.made) == 1 and sum(world.slept) == pytest.approx(10.0)
    assert ("default: its round failed (PermissionError: its folder could not be read): it is tried again "
            "later") in world.log()


def test_serves_own_lines_keep_its_log_bounded(tmp_path):
    """A round tried again and again while its server never starts adds a line each time: the log is moved aside past
    keep's size, as a server's start would move it."""
    log = tmp_path / "logs" / "default.log"
    log.parent.mkdir()
    log.write_bytes(b"x" * keep.LOG_MAX_BYTES)
    launch.note(log, "default is not started now: port 11434 is held by ollama.exe (pid 4321)")
    assert log.with_name("default.log.1").stat().st_size == keep.LOG_MAX_BYTES
    said = log.read_text(encoding="utf-8")
    assert said.endswith("serve: default is not started now: port 11434 is held by ollama.exe (pid 4321)\n")
    assert said.count("\n") == 1


def test_words_that_quote_the_key_are_said_without_it(world):
    world.server.refuses = [ValueError(f"its key {KEY} is refused")]  # a plugin's mistake, quoting what it was given
    world.scripts = [[("end", 0)]]
    assert world.serve() == 0
    assert KEY not in world.log() and "its key <hidden> is refused" in world.log()


# -- its signals -------------------------------------------------------------------------------------------------------
def test_listen_sets_the_signals_that_end_a_serve_and_leaves_an_ignored_one():
    posix = Signals(posix=True)
    assert launch.listen(launch.Ending(), signals=posix, posix=True) == ("SIGINT", "SIGTERM", "SIGHUP")
    nohup = Signals(posix=True, ignored=(SIGHUP,))
    assert launch.listen(launch.Ending(), signals=nohup, posix=True) == ("SIGINT", "SIGTERM")
    assert nohup.handlers[SIGHUP] is Signals.SIG_IGN
    windows = Signals(posix=False)
    assert launch.listen(launch.Ending(), signals=windows, posix=False) == ("SIGINT", "SIGBREAK")
    off: list = []
    thread = threading.Thread(target=lambda: off.append(launch.listen(launch.Ending(), signals=Signals(), posix=True)))
    thread.start()
    thread.join()
    assert off == [()]  # a handler is set from the main thread alone


def test_sighup_lets_the_output_go_first_and_the_first_signal_is_the_one_said():
    signals, ending, quieted = Signals(posix=True), launch.Ending(), []
    launch.listen(ending, signals=signals, posix=True, quiet=lambda: quieted.append(True))
    signals.send(SIGHUP)
    signals.send(SIGTERM)
    signals.send(SIGHUP)
    assert ending.by == "SIGHUP" and quieted == [True] and ending.is_set()


# -- its command line --------------------------------------------------------------------------------------------------
def test_main_runs_serve_with_its_switches(monkeypatch):
    asked = []
    monkeypatch.setattr(launch, "serve", lambda *a: asked.append(a) or 0)
    assert launch.main(["serve", "ollama", "default", "--home", "C:/x/platform", "--plugins", "C:/x/plugins"]) == 0
    assert asked == [("ollama", "default", "C:/x/platform", "C:/x/plugins")]
    assert launch.main([]) == 2 and launch.main(["serve"]) == 2 and launch.main(["hold", "--", "x"]) == 2


def test_serve_refuses_names_no_task_carries(world):
    assert launch.serve("Bad Name", "default") == 2 and world.made == []
