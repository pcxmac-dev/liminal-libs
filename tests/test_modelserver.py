"""A model server's plugin (liminal_libs.machines.modelserver, 1.62.0): a stand-in subclass that conforms with one
card; the kept JSON's round trip, a broken value and the caps; an instance hashed; each hook of the plan's table with
its refusals and the `accept` it names; an address typed with its /v1; every conflict's words (a Liminal port, another
instance of its own and of another plugin, a program by name and pid, WSL's relay, one not named, one that answers
unlisted); two changes at once, ordered by the test (a change beside a key and At boot, two instances on one port);
`status()` and `serving()` asking no transport and connecting nowhere, and `serving()` starting no boot read; the
Models tab asking once per SEEN_S; Try it's long answer; Start and Stop of a click's server, of one its start at boot
runs and of its task while it waits to start the server again; a boot read that fails said; `app_stopping()` stopping
a click's child and leaving a boot one; `lasting()` on both systems; two stand-in servers asking each other's
`serving` from two threads at once; and no key in any answer.

Nothing is started, installed, downloaded or asked here: stand-ins answer for the login, the children, the socket
table, the transport, the GPU's command, the boot registrations and the app, and the shared guard (conftest.py) fails a
test that starts a process or opens a connection."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from urllib.parse import urlsplit

import pytest

import liminal_libs
from liminal_libs import instances, mounts
from liminal_libs.apps.authorization import EnvironmentLogin, Login, Unauthorized, pair_name, variable_name
from liminal_libs.machines import autostart, children, modelserver
from liminal_libs.machines.admin import Startup
from liminal_libs.machines.ai import LASTING, Installed, Outside, Setting
from liminal_libs.machines.endpoint import Reply
from liminal_libs.machines.modelserver import (ACCEPT_PLAIN, ACCEPT_SHARE, MAX_INSTANCES, SEEN_S, SERVING, TABLE_S,
                                               Holder, Instance, Kept, ModelServer, Seen, held_words, holders,
                                               reserved)
from liminal_libs.machines.plugin import CommandError
from liminal_libs.resources import Conn
from liminal_libs.sources import conformance
from liminal_libs.sources.apis import Api, Link

pytestmark = pytest.mark.usefixtures("no_outside")

HTTPS = "https:" + "//"  # an address's start, put together here: no file names a host whole
CARD = Api("Stand-in server", "Its maker", "What the stand-in server offers the platform", kind="rest",
           links=(Link("Its documentation", HTTPS + "docs.example.test/server"),), verified="2026-11-17")
KEY = "sk-stand-in-key-0123456789"  # a key a test keeps: it is in no answer
DECLARED = ("MASSIVE_API_KEY", "OPENAI_API_KEY")  # what the registry says the installed plugins declare
NOW = 1_763_400_000.0  # the stand-in clock's start
PORT = 11434
GPU_LINE = "0, NVIDIA GeForce RTX 5090, 24564, 1000, 23564, 595.71\n"


class Pairs(Login):
    """The platform's login as a test has it: pairs kept in memory, each save noted."""

    def __init__(self):
        self.kept: dict[str, str] = {}
        self.saved: list[tuple[str, bool]] = []

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
        self.saved.append((variable, value is not None))
        if value is None:
            self.kept.pop(variable, None)
        else:
            self.kept[variable] = value
        return "the test's pairs"


class Clock:
    def __init__(self, now: float = NOW):
        self.now = now

    def __call__(self) -> float:
        return self.now


class Probe:
    """This system's socket table as a test sets it: its listening sockets and their programs' names."""

    def __init__(self):
        self.conns: list[Conn] = []
        self.names: dict[int, str] = {}
        self.reads = 0

    def listen(self, pid: int, port: int, name: str = "", address: str = "127.0.0.1") -> None:
        self.conns.append(Conn(pid, "listening", f"{address}:{port}", ""))
        if name:
            self.names[pid] = name

    def connections(self):
        self.reads += 1
        return list(self.conns)

    def program_names(self, pids=None):
        return {p: n for p, n in self.names.items() if pids is None or p in pids}


class Transport:
    """http as a test answers it: by method and path, each ask noted."""

    def __init__(self):
        self.asked: list[tuple[str, str, dict, bytes | None]] = []
        self.answers: dict[tuple[str, str], tuple[int, object]] = {}

    def __call__(self, method, url, headers, body, timeout, stream):
        self.asked.append((method, url, dict(headers), body))
        status, data = self.answers.get((method, urlsplit(url).path), (404, {"error": "not here"}))
        return Reply(status, {"content-type": "application/json"}, [json.dumps(data).encode()])


class Kids:
    """A stand-in children.Child class, its own for each test: what it started, what an earlier run left running."""

    def __init__(self, clock: Clock):
        made: list = []
        adoptable: dict = {}
        self.made, self.adoptable = made, adoptable

        class Child:
            def __init__(self, name, launch, log, pidfile, *, popen=None, interrupt=None, clock=None, sleep=None,
                         system=None):
                self.name, self.launch, self.log, self.pidfile = name, launch, Path(log), Path(pidfile)
                self.system = system
                self.alive, self.pid, self.code, self.since, self.note = False, None, None, None, ""
                self.stops, self.kids = 0, set()
                made.append(self)

            def start(self):
                self.alive, self.pid, self.since = True, 4300 + len(made), clock()
                self.pidfile.parent.mkdir(parents=True, exist_ok=True)
                self.pidfile.write_text(f"{self.pid} 1 99 1", encoding="ascii")
                return self.pid

            @classmethod
            def adopt(cls, name, log, pidfile, **kw):
                found = adoptable.get(str(Path(pidfile)))
                return found if found is not None and found.alive else None

            def owns(self, pid):
                return pid == self.pid or pid in self.kids

            def stop(self, grace=8.0):
                self.stops += 1
                self.alive, self.code = False, 0
                return "ended when asked (Ctrl+C), after 0.2 s"

            def wait(self, timeout=None):
                return self.code

            def tail(self, lines=40):
                return ["its last line"][-lines:]

        self.Child = Child

    def running(self, pidfile: Path, pid: int, note: str = ""):
        """A server an earlier run (or a boot task's launcher) left running, found by its pidfile."""
        child = self.Child("earlier", children.Launch(()), pidfile.with_suffix(".log"), pidfile)
        child.alive, child.pid, child.since, child.note = True, pid, NOW - 600, note
        self.adoptable[str(Path(pidfile))] = child
        return child


class Server(ModelServer):
    """A stand-in model server plugin: what is installed, what it refuses and what it adds are the test's to set."""

    name = "tool"
    title = "Tool"
    about = "A stand-in model server for the base's tests"
    order = 510
    LIBS_FLOOR = "1.62.0"
    apis = (CARD,)
    DEFAULT_PORT = PORT
    NATIVE = "tool"
    READY_S = 60.0
    SETTINGS = (Setting("context", "Context length (tokens)", "number", min=2048, max=1_048_576),
                Setting("keep", "Keep a model loaded", "text", default="5m"))
    MODEL_COLUMNS = ("Load",)

    def __init__(self, outside=None):
        super().__init__(outside)
        self.have: Installed | None = Installed("1.2.3", "C:/tools/tool/tool.exe", "plugin")
        self.here = ""
        self.refuses: Exception | None = None  # what launch() raises
        self.in_argv = False  # launch() puts the key on the command line (a plugin's mistake)
        self.launched: list = []
        self.more_asked: list = []
        self.main_fails: Exception | None = None

    def installed(self):
        return self.have

    def runs_here(self):
        return self.here

    def launch(self, instance, key=""):
        self.launched.append((instance.name, bool(key)))
        if self.refuses is not None:
            raise self.refuses
        env = {"TOOL_HOST": f"{'0.0.0.0' if instance.shared else '127.0.0.1'}:{self.port_of(instance)}"}
        if key:
            env["TOOL_API_KEY"] = key
        argv = ("tool", "serve", *((f"--api-key={key}",) if self.in_argv else ()))
        return children.Launch(argv, env=env, drop=("TOOL_*",))

    def start_words(self, instance):
        return "Its stand-in switch is off."

    def model_cells(self, instance, model):
        return [{"form": "model-load", "title": "Load…", "values": {"name": instance.name, "model": model["id"]}}]

    def more(self, shown, seen):
        self.more_asked.append((shown.name if shown else None, seen))
        return {"tables": [{"title": "Find a model", "columns": [{"title": "Model"}], "rows": []}]}

    def main_more(self):
        if self.main_fails is not None:
            raise self.main_fails
        return {"tables": [{"title": "What leaves this machine", "columns": [{"title": "What"}],
                            "rows": [["nothing"]]}]}


class Other(Server):
    """A second inference plugin, for what the two ask of each other."""

    name = "other"
    title = "Other"
    DEFAULT_PORT = 9931


class App:
    """The platform as a plugin reaches it: its plugins' interfaces, and ask(name, hook, args)."""

    def __init__(self, *plugins, once=False, barrier: threading.Barrier | None = None):
        self.by = {p.name: p for p in plugins}
        self.once = once
        self.asked: list[tuple[str, str]] = []
        self.barrier = barrier

    def plugins(self):
        return {n: p.interface() for n, p in self.by.items()}

    def ask(self, name, hook, args):
        self.asked.append((name, hook))
        if self.barrier is not None and hook == SERVING:
            try:
                self.barrier.wait(5)
            except threading.BrokenBarrierError:
                pass
        return self.by[name].ask(hook, *args)


class Boot:
    """autostart as a test has it: each call noted, the registrations kept here."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.kept: dict[str, Startup] = {}

    def register(self, plugin, instance, command, about, *, system, powershell=None, shell=None, home=None):
        self.calls.append(("register", plugin, instance, list(command), system))
        found = Startup(instance, autostart.name_of(plugin, instance, system), "ready", " ".join(command))
        self.kept[instance] = found
        return found

    def remove(self, plugin, instance, *, system, powershell=None, shell=None, home=None):
        self.calls.append(("remove", plugin, instance, system))
        return self.kept.pop(instance, None) is not None

    def act(self, plugin, instance, action, *, system, powershell=None, shell=None):
        self.calls.append(("act", plugin, instance, action, system))

    def read(self, plugin, *, system, powershell=None, shell=None, home=None):
        self.calls.append(("read", plugin, system))
        return dict(self.kept)


@pytest.fixture(autouse=True)
def this_library(monkeypatch):
    monkeypatch.setattr(liminal_libs, "__version__", "1.62.0")
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: False)


@pytest.fixture
def boot(monkeypatch):
    b = Boot()
    for name in ("register", "remove", "act", "read"):
        monkeypatch.setattr(autostart, name, getattr(b, name))
    return b


@pytest.fixture
def world(tmp_path, boot):
    """Everything outside a stand-in server, with it."""
    clock, probe, transport = Clock(), Probe(), Transport()
    kids = Kids(clock)
    heard: list = []
    listening = {"answers": False}

    def listen(host, port):
        heard.append((host, port))
        return listening["answers"]

    ran: list = []

    def runner(args, timeout):
        ran.append(list(args))
        return 0, GPU_LINE, ""

    def which(name, *a, **k):
        return "C:/tools/nvidia-smi.exe" if name == "nvidia-smi" else None

    def outside(system="windows", **more):
        env = {"PATH": "C:/tools", "MASSIVE_API_KEY": "m-key-1", "LIMINAL_AI_TOOL_INSTANCES": "kept elsewhere",
               "TOOL_HOST": "0.0.0.0:1", "LIMINAL_PLATFORM_DIR": str(tmp_path / "platform"),
               "LIMINAL_PLUGINS": str(tmp_path / "plugins")}
        given = dict(env=env, system=system, wsl="", clock=clock, which=which, probe=probe, transport=transport,
                     runner=runner, listening=listen, variables=lambda: DECLARED)
        given.update(more)
        return Outside(**given)

    def server(cls=Server, system="windows", attach=True, **more):
        p = cls(outside(system, home=tmp_path / "platform" / "ai" / cls.name, **more))
        p.CHILD = kids.Child
        p.login = Pairs()
        if attach:
            p.app = App(p)
        return p

    class World:
        pass

    w = World()
    w.clock, w.probe, w.transport, w.kids, w.heard, w.listening, w.ran = clock, probe, transport, kids, heard, \
        listening, ran
    w.server, w.boot, w.tmp = server, boot, tmp_path
    return w


def refusal(call) -> instances.Refusal:
    with pytest.raises(instances.Refusal) as caught:
        call()
    return caught.value


def kept_json(p: ModelServer) -> dict:
    return json.loads(p.login.kept[p.variable("instances")])


def boot_read(p: ModelServer) -> None:
    """The boot registrations read again as a status reads them (one command, in its thread), and waited for."""
    with p._rt.lock:
        p._rt.boot = None
    p._boot_states()
    if p._rt.boot_thread is not None:
        p._rt.boot_thread.join(5)


def cells(out: dict, name: str) -> list:
    """An instance's cells in a status's Instances table."""
    return next(r["cells"] for r in out["tables"][0]["rows"] if r["key"] == name)


def buttons(out: dict) -> dict:
    """The shown instance's buttons in a status's Instances table, by title."""
    return {b["title"]: b for b in out["tables"][0]["tasks"]["actions"]}


# -- the contract ------------------------------------------------------------------------------------------------------
def test_a_stand_in_server_conforms_with_one_card(world):
    p = world.server()
    assert conformance.problems(p) == []
    said = (p.KIND, p.SYSTEM, p.SECTION, p.GROUP, p.api, p.TABS[0].as_dict())
    assert said == ("machine", "platform", "ai", "inference", "2.2",
                    {"id": "models", "title": "Models", "hook": "models", "every": 15.0})
    hooks = set(p.interface()["hooks"])
    assert hooks == {"present", "status", "refresh", "install", "uninstall", "choose", "add_instance",
                     "change_instance", "remove_instance", "set_key", "forget_key", "share", "start", "stop", "boot",
                     "log_of", "models", "try_it", SERVING, "models_of"}
    assert "instances" not in hooks and p.instances() == ()  # Docker's hook: a server there would be an engine
    assert ModelServer.HOOKS[-2:] == (SERVING, "models_of") and p.JOB_HOOKS == ("install",)
    assert set(ModelServer.READ_HOOKS) <= set(ModelServer.HOOKS) and ModelServer.SERVICE_HOOKS == (SERVING, "models_of")
    assert modelserver.Setting is Setting  # (M3: defined in ai.py, imported here)


def test_the_pairs_are_named_under_liminal_ai(world):
    p = world.server()
    assert p.variable("instances") == "LIMINAL_AI_TOOL_INSTANCES"
    assert p.key_variable("default") == "LIMINAL_AI_TOOL_DEFAULT_KEY"
    assert p.log_path("default") == p.home / "logs" / "default.log"
    assert p.boot_log("default") == p.home / "logs" / "default.boot.log"
    assert p.pidfile("default") == p.home / "run" / "default.pid"


# -- how instances are kept --------------------------------------------------------------------------------------------
def test_the_kept_json_round_trip_keeps_what_differs():
    local = Instance("default", settings={"context": 32768, "keep": "10m", "bad name": 1, "empty": "  "})
    remote = Instance("gpu", "remote", host="GPU-Box.", port=8000, tls=True, prefix="/v1/", title="The GPU box")
    plain = Instance("lab", "remote", host="10.0.0.5", port=8000, plain=True)
    assert local.kept() == {"name": "default", "settings": {"context": 32768, "keep": "10m"}}
    assert remote.kept() == {"name": "gpu", "where": "remote", "host": "gpu-box", "port": 8000, "title": "The GPU box",
                             "tls": True, "prefix": "/v1"}
    assert plain.kept()["plain"] is True
    assert Instance("s", "remote", host="h", port=1, tls=True, plain=True).plain is False
    kept = Kept({i.name: i for i in (local, remote, plain)})
    again = Kept.of(kept.text())
    assert again.problem == "" and again.instances == kept.instances
    assert json.loads(kept.text())["v"] == 1
    assert Kept().text() is None and Kept.of(None).instances == {} and Kept.of("  ").problem == ""
    found = Instance("wsl", "found", host="elsewhere", port=PORT, shared=True, boot=True, tls=True)
    assert (found.host, found.shared, found.boot, found.tls) == ("127.0.0.1", False, False, False)


def test_an_instance_can_be_hashed_and_equal_ones_hash_alike():
    """A frozen instance is a key, a set's member, a cache's argument; its settings are compared, never hashed."""
    one, again = Instance("default", settings={"context": 4096}), Instance("default", settings={"context": 4096})
    assert hash(one) == hash(again) and {one, again} == {one} and {one: "kept"}[again] == "kept"
    assert Instance("default", settings={"context": 8192}) != one and Instance("other") not in {one}


def test_a_broken_value_and_a_broken_instance_are_said_and_the_caps_hold():
    assert "not readable" in Kept.of("{not json").problem and Kept.of("{not json").instances == {}
    assert "not a list" in Kept.of('{"v": 1}').problem
    text = json.dumps({"v": 1, "instances": [{"name": "good"}, {"name": "Bad Name"}, {"name": "good"},
                                             {"name": "x", "where": "elsewhere"}, "nothing"]})
    kept = Kept.of(text)
    assert list(kept.instances) == ["good"]
    assert kept.problem == "4 of the kept instances could not be read and are left out"
    many = json.dumps({"v": 1, "instances": [{"name": f"i{n}"} for n in range(MAX_INSTANCES + 3)]})
    assert len(Kept.of(many).instances) == MAX_INSTANCES


@pytest.mark.parametrize("fields, words", [
    ({"name": "Bad"}, "lowercase"), ({"name": "x", "where": "cloud"}, "local, found or remote"),
    ({"name": "x", "port": 70000}, "65535"), ({"name": "x", "port": True}, "port"),
    ({"name": "x", "where": "remote", "host": "gpu-box"}, "names its port"),
    ({"name": "x", "where": "remote", "host": "localhost", "port": 8000}, "this machine"),
    ({"name": "x", "where": "remote", "host": "no host!", "port": 8000}, "no host"),
    ({"name": "x", "boot": "yes"}, "true or false")])
def test_an_instance_refuses_what_it_cannot_be(fields, words):
    with pytest.raises(ValueError) as caught:
        Instance(**fields)
    assert words in str(caught.value)


def test_a_broken_value_is_started_again_by_the_next_change(world):
    p = world.server()
    p.login.kept[p.variable("instances")] = "{broken"
    out = p.status()
    assert out["valid"] is True and "not readable" in out["problem"]
    p.add_instance("default")
    assert list(kept_json(p)["instances"][0]) == ["name", "at"]


# -- adding, changing, forgetting --------------------------------------------------------------------------------------
def test_add_instance_of_each_kind(world):
    p = world.server()
    said = p.add_instance("Default", "local", None, None, False, 32768, None)
    assert said["ok"] and "default added (run here, 127.0.0.1:11434): kept in the test's pairs" == said["said"]
    p.add_instance("wsl", "found", None, 11500)
    p.add_instance("gpu", "remote", HTTPS + "gpu-box:8443/llm")  # a proxy's sub-path
    rows = kept_json(p)["instances"]
    assert rows[0] == {"name": "default", "at": "2025-11-17T17:20:00Z", "settings": {"context": 32768}}
    assert rows[1] == {"name": "wsl", "where": "found", "port": 11500, "at": "2025-11-17T17:20:00Z"}
    assert rows[2]["host"] == "gpu-box" and rows[2]["tls"] is True and rows[2]["prefix"] == "/llm"
    assert world.heard == [("127.0.0.1", PORT)]  # a local one's port asked on the click alone (a found one is
    # expected to answer there)
    assert world.transport.asked == [] and p.shown().name == "gpu"


def test_plain_http_to_another_machine_is_asked_twice(world):
    p = world.server()
    r = refusal(lambda: p.add_instance("lab", "remote", "10.0.0.5:8000"))
    assert r.accept == ACCEPT_PLAIN and "plain http" in str(r) and "lab" not in p.kept_instances().instances
    p.add_instance("lab", "remote", "10.0.0.5:8000", None, True)
    assert p.instance("lab").plain is True and p.base(p.instance("lab")) == "http:" + "//10.0.0.5:8000"


def test_an_address_typed_with_its_v1_is_kept_without_it(world):
    """vLLM, llama.cpp and Ollama document their OpenAI-compatible base as .../v1, and every ask adds /v1 itself."""
    p = world.server()
    said = p.add_instance("gpu", "remote", HTTPS + "gpu-box:8443/v1")
    assert p.instance("gpu").prefix == "" and p.base(p.instance("gpu")) == HTTPS + "gpu-box:8443"
    assert said["lines"][-1] == ("its address is kept without its last /v1: every ask adds it (/v1/models, "
                                 "/v1/chat/completions)")
    assert p.serving("gpu")["instances"][0]["openai"] == HTTPS + "gpu-box:8443/v1"
    p.add_instance("proxy", "remote", HTTPS + "gpu-box:8443/llm/v1/")  # under a proxy's sub-path
    assert p.instance("proxy").prefix == "/llm"
    p.models()  # proxy, the instance shown
    assert world.transport.asked[-1][1] == HTTPS + "gpu-box:8443/llm/v1/models"
    changed = p.change_instance("gpu", HTTPS + "gpu-box:9443/v1")
    assert p.instance("gpu").port == 9443 and p.instance("gpu").prefix == "" and "without its last /v1" in str(changed)
    assert "/v1" not in str(p.add_instance("plain", "remote", HTTPS + "gpu-box:7443")["lines"])
    fields = {f["id"]: {x["name"]: x for x in f["fields"]} for f in p.status()["forms"]}
    assert all("without /v1" in fields[form]["address"]["note"] for form in ("ai-add", "ai-change"))


@pytest.mark.parametrize("args, words", [
    (("Not A Name",), "lowercase letters"), (("x", "cloud"), "not 'cloud'"),
    (("x", "local", None, 8775), "Liminal's platform page's own"), (("x", "local", None, 80), "1024 to 65535"),
    (("x", "local", None, "port"), "whole number"), (("x", "remote", "localhost:8000"), "this machine"),
    (("x", "remote", ""), "no address"), (("x", "remote", "ftp:" + "//gpu-box"), "http or https"),
    (("x", "local", None, None, False, 12), "Context length (tokens) is a whole number from 2,048")])
def test_add_instance_refuses_in_words(world, args, words):
    assert words in str(refusal(lambda: world.server().add_instance(*args)))


def test_add_instance_refuses_a_taken_name_more_than_sixteen_and_what_cannot_run_here(world):
    p = world.server()
    p.add_instance("default")
    assert "already" in str(refusal(lambda: p.add_instance("default", "found", None, 11500)))
    for n in range(1, MAX_INSTANCES):
        p.add_instance(f"i{n}", "remote", f"{HTTPS}gpu-{n}")
    assert f"{MAX_INSTANCES} instances at most" in str(refusal(lambda: p.add_instance("more", "remote", HTTPS + "x")))
    q = world.server()
    q.here = "this plugin starts its server on Linux alone"
    assert str(refusal(lambda: q.add_instance("default"))) == q.here
    assert q.add_instance("found", "found")["ok"]  # found and remote ones are held wherever


def test_change_instance(world):
    p = world.server()
    p.add_instance("default", "local", None, None, False, 32768, "10m")
    said = p.change_instance("default", None, 11600, False, None, "1h")
    assert said["ok"] and p.instance("default").port == 11600 and dict(p.instance("default").settings) == {"keep": "1h"}
    assert "nothing changed" in p.change_instance("default", None, 11600, False, None, "1h")["said"]
    p.add_instance("gpu", "remote", HTTPS + "gpu-box")
    assert "nothing changed" in p.change_instance("gpu", "  ")["said"]  # an address left empty stays
    r = refusal(lambda: p.change_instance("gpu", "10.0.0.7:8000"))
    assert r.accept == ACCEPT_PLAIN
    p.change_instance("gpu", "10.0.0.7:8000", None, True)
    assert (p.instance("gpu").host, p.instance("gpu").plain) == ("10.0.0.7", True)
    p.add_instance("other", "local", None, 11700)
    assert "Tool's instance default already" in str(refusal(lambda: p.change_instance("other", None, 11600)))
    p.start("default")
    assert "stop default first" in str(refusal(lambda: p.change_instance("default", None, 11650)))


def held_in_its_port_check(p: ModelServer):
    """The plugin's port check made to wait, once it has looked, until the test lets it go on: the order two clicks at
    once can take, set by the test and not left to luck. (looked, go on)"""
    original, looked, go_on = p.conflict, threading.Event(), threading.Event()

    def conflict(instance, port=None, *, ask=False):
        found = original(instance, port, ask=ask)
        looked.set()
        assert go_on.wait(5), "the test never let the port check go on"
        return found

    p.conflict = conflict
    return looked, go_on


def in_a_thread(call) -> tuple[threading.Thread, list]:
    """`call` run in a thread of its own: the thread, and a list that gets what it answered or raised."""
    out: list = []

    def run():
        try:
            out.append(call())
        except Exception as e:  # noqa: BLE001 - what it raised is the test's to look at
            out.append(e)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, out


def test_a_change_beside_a_key_and_at_boot_keeps_all_three(world):
    """A change lays the fields it changes over the instance as it is kept when it keeps it: a key and At boot kept
    while it looked at its port are not lost."""
    p = world.server()
    p.add_instance("default")
    looked, go_on = held_in_its_port_check(p)
    thread, out = in_a_thread(lambda: p.change_instance("default", None, 11600))
    assert looked.wait(5)
    p.set_key("default", KEY)
    p.boot("default", "yes")
    go_on.set()
    thread.join(5)
    now = p.instance("default")
    assert out[0]["ok"] and (now.port, now.keyed, now.boot) == (11600, True, True) and p.key_of(now) == KEY


def test_two_instances_on_one_port_at_once_keep_one(world):
    """Two adds (or an add and a change) at once on one port: each has looked before either keeps, and the port is
    looked at again among the kept instances as each keeps."""
    p = world.server()
    looked, go_on = held_in_its_port_check(p)
    one, said_one = in_a_thread(lambda: p.add_instance("one", "local", None, 11600))
    assert looked.wait(5)
    looked.clear()
    two, said_two = in_a_thread(lambda: p.add_instance("two", "local", None, 11600))
    assert looked.wait(5)
    go_on.set()
    one.join(5)
    two.join(5)
    said = said_one + said_two
    refused = [s for s in said if isinstance(s, instances.Refusal)]
    assert len(p.kept_instances().instances) == 1 and len(refused) == 1
    assert str(refused[0]).startswith("port 11600 is Tool's instance ") and str(refused[0]).endswith(" already")
    q = world.server()
    q.add_instance("one", "local", None, 11700)
    looked, go_on = held_in_its_port_check(q)
    change, said = in_a_thread(lambda: q.change_instance("one", None, 11800))
    assert looked.wait(5)
    del q.conflict  # the class's own again: the add's check is not held
    q.add_instance("two", "local", None, 11800)
    go_on.set()
    change.join(5)
    assert str(said[0]) == "port 11800 is Tool's instance two already" and q.instance("one").port == 11700


def test_remove_instance_forgets_its_key_and_its_start_at_boot(world):
    p = world.server()
    p.add_instance("default")
    p.set_key("default", KEY)
    p.boot("default", "yes")
    p.start("default")  # by its task: nothing of this process runs it
    said = p.remove_instance("default")
    assert said["ok"] and p.kept_instances().instances == {} and p.key_variable("default") not in p.login.kept
    assert ("remove", "tool", "default", "windows") in world.boot.calls and "its key is forgotten" in said["lines"]
    p.add_instance("busy")
    p.start("busy")
    assert "stop busy first" in str(refusal(lambda: p.remove_instance("busy")))


# -- conflicts ---------------------------------------------------------------------------------------------------------
def test_every_conflict_in_words(world):
    p = world.server()
    q = world.server(Other, attach=False)
    p.app = App(p, q)
    q.add_instance("router", "local", None, 9940)
    p.add_instance("default")
    one = p.instance("default")
    assert p.conflict(one) == ""
    assert p.conflict(one, 80) == "a port is a whole number from 1024 to 65535, not 80"
    assert p.conflict(one, 8765) == "port 8765 is Liminal's charts page's own: choose another"
    p.add_instance("wsl", "found", None, 11500)
    assert p.conflict(one, 11500) == "port 11500 is Tool's instance wsl already"
    assert p.conflict(one, 9940) == "port 9940 is Other's instance router already"  # asked through the app
    world.probe.listen(4321, PORT, "ollama.exe", "0.0.0.0")
    world.clock.now += TABLE_S
    assert p.conflict(one) == "port 11434 is held by ollama.exe (pid 4321), reachable from every address"
    world.probe.conns.clear()
    world.probe.listen(9876, PORT, "wslrelay.exe")
    world.clock.now += TABLE_S
    relay = p.conflict(one)
    assert relay.startswith("port 11434 is held by WSL's relay (wslrelay.exe, pid 9876): a server inside a WSL")
    assert relay.endswith("Windows reaches it at 127.0.0.1:11434. Add it as a found instance, or choose another port")
    world.probe.conns.clear()
    world.probe.listen(0, PORT)
    world.clock.now += TABLE_S
    assert p.conflict(one) == "port 11434 is held by a program not named (another user's)"
    world.probe.conns.clear()
    world.clock.now += TABLE_S
    world.listening["answers"] = True
    assert p.conflict(one) == ""  # nothing is connected to but on a click
    assert p.conflict(one, ask=True).startswith("something answers at 127.0.0.1:11434 that no program here is listed")
    assert p.conflict(p.instance("wsl")) == "" and p.conflict(Instance("r", "remote", host="h", port=8775)) == ""


def test_its_own_server_holding_its_port_is_no_conflict(world):
    p = world.server()
    p.add_instance("default")
    p.start("default")
    child = world.kids.made[-1]
    world.probe.listen(child.pid, PORT, "tool.exe")
    child.kids.add(5555)
    world.probe.listen(5555, PORT, "tool-runner.exe", "[::1]")
    world.clock.now += TABLE_S
    assert p.conflict(p.instance("default")) == "" and p.state(p.instance("default"))["state"] == "running"


def test_holders_reserved_and_held_words():
    probe = Probe()
    probe.listen(9876, PORT, "wslrelay.exe")
    probe.listen(0, PORT, address="[::]")
    probe.listen(4321, 8000, "vllm")
    probe.conns.append(Conn(1, "established", "127.0.0.1:11434", "127.0.0.1:50000"))
    found = holders(PORT, probe)
    assert found == [Holder(9876, "wslrelay.exe", "this machine only", True), Holder(0, "", "every address")]
    assert held_words(PORT, found) == ("WSL's relay (wslrelay.exe, pid 9876): a server inside a WSL distribution "
                                       "listens there; a program not named (another user's), reachable from every "
                                       "address")
    assert held_words(9, []) == "nothing listens on port 9 here"
    assert reserved(8775) == "platform" and reserved(8795) == "login" and reserved(11434) == ""
    assert reserved(9775, {"LIMINAL_PLATFORM_PORT": "9775"}) == "platform"


# -- Main --------------------------------------------------------------------------------------------------------------
def test_status_asks_no_transport_and_connects_nowhere(world):
    p = world.server()
    p.add_instance("default")
    p.add_instance("wsl", "found", None, 11500)
    p.add_instance("gpu", "remote", HTTPS + "gpu-box")
    world.heard.clear()
    for _ in range(3):
        out = p.status()
        p.serving()
    assert world.transport.asked == [] and world.heard == [] and world.ran == []
    assert world.probe.reads == 1  # the socket table, kept TABLE_S
    world.clock.now += TABLE_S
    p.status()
    assert world.probe.reads == 2 and out["valid"] is True


def test_one_socket_table_serves_every_plugin_reading_it_through_one_probe(world):
    """A status and the other plugin's `serving` its conflicts ask read one table per TABLE_S, not one each."""
    a, b = world.server(attach=False), world.server(Other, attach=False)
    a.app = b.app = App(a, b)
    a.add_instance("default")
    b.add_instance("router", "local", None, 9940)
    world.clock.now += TABLE_S
    reads = world.probe.reads
    a.status()  # its own table, and b's rows (asked through the app) from the same one
    b.status()
    assert world.probe.reads == reads + 1
    world.clock.now += TABLE_S
    b.status()
    assert world.probe.reads == reads + 2
    other = Probe()  # a plugin reading another probe reads its own table
    a.out.probe = other
    a.status()
    assert other.reads == 1 and world.probe.reads == reads + 2


def test_one_status_reads_its_instances_and_its_install_once(world):
    p = world.server()
    p.add_instance("default")
    p.add_instance("second", "local", None, 11600)
    p.add_instance("wsl", "found", None, 11500)
    p.add_instance("gpu", "remote", HTTPS + "gpu-box")
    p.start("default")
    p.choose("default")
    asked: list[str] = []
    for name in ("kept_instances", "installed", "running", "boot_names"):
        real = getattr(p, name)
        setattr(p, name, lambda real=real, name=name: asked.append(name) or real())
    out = p.status()
    assert sorted(asked) == ["installed", "kept_instances"] and out["running"] == "1 of 2"
    assert buttons(out)["Start"]["note"] == "it runs" and "problem" not in out


def test_status_draws_main(world):
    p = world.server()
    p.add_instance("default", "local", None, None, False, 32768)
    p.add_instance("second", "local", None, 11600)
    p.add_instance("gpu", "remote", HTTPS + "gpu-box")
    p.choose("default")
    p.start("default")
    world.probe.listen(world.kids.made[-1].pid, PORT, "tool.exe")
    world.probe.listen(9876, 11600, "wslrelay.exe")
    world.clock.now += TABLE_S  # the socket table read again
    out = p.status()
    assert (out["present"], out["valid"], out["running"]) == (True, True, "1 of 2")
    assert out["summary"].endswith("1 of 2 running here") and out["system"] == "Windows"
    assert out["problem"] == "second: " + p.conflict(p.instance("second")) and "WSL's relay" in out["problem"]
    table = out["tables"][0]
    assert table["title"] == "Instances" and [c["title"] for c in table["columns"]] == [
        "Instance", "Where", "Address", "State", "At boot", "Key"]
    assert table["select"] == {"hook": "choose", "value": "default", "title": "Show its models"}
    rows = {r["key"]: r["cells"] for r in table["rows"]}
    assert rows["default"][1:3] == ["run here", "127.0.0.1:11434"] and rows["default"][3]["text"] == "running"
    assert rows["gpu"][3]["text"] == "unasked" and rows["gpu"][4] == "–" and rows["second"][3]["text"] == "stopped"
    tasks = {b["title"]: b for b in table["tasks"]["actions"]}
    assert table["tasks"]["subject"] == "default" and list(tasks) == [
        "Start", "Stop", "Change…", "Key…", "Share…", "At boot…", "Log", "Forget…"]
    assert tasks["Start"]["disabled"] and tasks["Start"]["note"] == "it runs" and "disabled" not in tasks["Stop"]
    assert tasks["Change…"]["values"] == {"name": "default", "port": PORT, "context": 32768}
    assert tasks["Share…"]["values"] == {"name": "default", "on": "yes"}
    forms = {f["id"]: f for f in out["forms"]}
    assert {"ai-add", "ai-change", "ai-remove", "ai-key", "ai-key-forget", "ai-share", "ai-start", "ai-stop", "ai-boot",
            "ai-log"} <= set(forms)
    assert [f["name"] for f in forms["ai-add"]["fields"]] == ["name", "where", "address", "port", ACCEPT_PLAIN,
                                                              "context", "keep"]
    assert forms["ai-add"]["fields"][5]["when"] == {"where": ["local"]}  # a setting's field by its name (S1.3)
    assert [f["name"] for f in forms["ai-change"]["fields"]] == ["name", "address", "port", ACCEPT_PLAIN, "context",
                                                                 "keep"]
    assert "Its stand-in switch is off." in forms["ai-start"]["confirm"]["words"]
    costs = ("Its task runs one program of the platform's beside the server for as long as it runs (launch serve, "
             "which loads the platform's plugins).")  # what a start at boot costs, said before it is turned on
    assert costs in forms["ai-boot"]["confirm"]["words"]
    assert forms["ai-log"]["confirm"] is False and forms["ai-key"]["fields"][1]["type"] == "password"
    assert [t["title"] for t in out["tables"]][-1] == "What leaves this machine"  # main_more, at every draw


def test_what_answers_on_the_makers_port_is_offered_as_found(world):
    p = world.server()
    world.probe.listen(9876, PORT, "wslrelay.exe")
    out = p.status()
    answering = next(t for t in out["tables"] if t["title"] == "Answering on this machine")
    address, held, cell = answering["rows"][0]
    assert address == "127.0.0.1:11434" and held.startswith("WSL's relay (wslrelay.exe, pid 9876)")
    assert cell["form"] == "ai-add" and cell["values"] == {"name": "wsl", "where": "found", "port": PORT}
    p.add_instance("wsl", "found")
    world.clock.now += TABLE_S
    assert "Answering on this machine" not in [t["title"] for t in p.status()["tables"]]
    assert p.state(p.instance("wsl"))["state"] == "answering"


def test_a_status_whose_parts_raise_is_valid_with_a_problem(world):
    p = world.server()
    p.add_instance("default")
    p.main_fails = RuntimeError(f"broke with {KEY}")
    p.pair(p.key_variable("default"))  # (nothing kept: nothing remembered)
    out = p.status()
    assert out["valid"] is True and "its own part of this page could not be drawn" in out["problem"]
    bad = world.server()

    def broken():
        raise OSError("no table")

    bad.out.probe = type("Broken", (), {"connections": staticmethod(broken)})()
    bad.add_instance("default")
    world.clock.now += TABLE_S
    st = bad.status()
    assert st["valid"] is True and bad.state(bad.instance("default"))["state"] == "stopped"
    assert bad._table().problem == "this system's socket table could not be read: OSError: no table"


# -- Start, Stop, and the children -------------------------------------------------------------------------------------
def test_start_and_stop_of_a_click(world):
    p = world.server()
    p.add_instance("default")
    p.set_key("default", KEY)
    world.heard.clear()
    said = p.start("default")
    child = world.kids.made[-1]
    assert said["ok"] and said["said"] == f"default started (pid {child.pid}) at 127.0.0.1:11434"
    assert world.heard == [("127.0.0.1", PORT)]  # its port asked on the click
    assert (child.log, child.pidfile) == (p.log_path("default"), p.pidfile("default"))
    launch = child.launch
    assert launch.secret == ("TOOL_API_KEY",) and KEY not in " ".join(launch.argv)
    assert {"TOOL_*", "MASSIVE_API_KEY", "OPENAI_API_KEY", "LIMINAL_*"} <= set(launch.drop)
    env = children.environment(launch, base=p.out.env, system="windows")
    assert "MASSIVE_API_KEY" not in env and "LIMINAL_AI_TOOL_INSTANCES" not in env and env["TOOL_API_KEY"] == KEY
    assert env["TOOL_HOST"] == "127.0.0.1:11434"  # its own, over what the platform's environment held
    assert p.state(p.instance("default"))["state"] == "starting"
    assert "runs already" in str(refusal(lambda: p.start("default")))
    world.clock.now += 61
    world.probe.listen(child.pid, PORT, "tool.exe")
    assert p.state(p.instance("default"))["state"] == "running" and p.running() == ["default"]
    stopped = p.stop("default")
    assert stopped["said"] == "default ended when asked (Ctrl+C), after 0.2 s" and child.stops == 1
    assert "is not running" in str(refusal(lambda: p.stop("default")))
    assert p.state(p.instance("default"))["state"] == "stopped" and p.running() == []


def test_a_server_that_ended_by_itself_is_said_exited(world):
    p = world.server()
    p.add_instance("default")
    p.start("default")
    child = world.kids.made[-1]
    child.alive, child.code = False, 3
    st = p.state(p.instance("default"))
    assert st["state"] == "exited" and st["said"] == "exited (code 3): its last line"


@pytest.mark.parametrize("change, words", [
    (lambda p: setattr(p, "have", None), "Tool is not installed here: Install… first"),
    (lambda p: setattr(p, "here", "it does not run under WSL 1"), "it does not run under WSL 1"),
    (lambda p: setattr(p, "app", None), "is started from the platform's page"),
    (lambda p: setattr(p, "app", App(p, once=True)), "a command that answers and ends would end it"),
    (lambda p: setattr(p, "refuses", instances.Refusal("its models folder is on another system's drive")),
     "its models folder is on another system's drive"),  # launch()'s own refusal, as the start's (S1.1)
    (lambda p: setattr(p, "in_argv", True), "key on its command line")])
def test_start_refuses_in_words(world, change, words):
    p = world.server()
    p.add_instance("default")
    p.set_key("default", KEY)
    change(p)
    r = refusal(lambda: p.start("default"))
    assert words in str(r) and KEY not in str(r) and world.kids.made == []


def test_found_and_remote_instances_are_not_started_or_stopped_here(world):
    p = world.server()
    p.add_instance("wsl", "found")
    p.add_instance("gpu", "remote", HTTPS + "gpu-box")
    for name in ("wsl", "gpu"):
        assert "it is started where it runs" in str(refusal(lambda: p.start(name)))
        assert "it is stopped where it was started" in str(refusal(lambda: p.stop(name)))
        assert "only a server run here" in str(refusal(lambda: p.boot(name, "yes")))
        assert "only a server run here" in str(refusal(lambda: p.share(name, "yes")))


def test_a_conflict_refuses_a_start(world):
    p = world.server()
    p.add_instance("default")
    world.probe.listen(4321, PORT, "ollama.exe")
    world.clock.now += TABLE_S
    assert "held by ollama.exe (pid 4321)" in str(refusal(lambda: p.start("default")))


def test_an_earlier_runs_server_is_found_by_its_pidfile(world):
    p = world.server()
    p.add_instance("default")
    earlier = world.kids.running(p.pidfile("default"), 7777, note=children.adopted_words("windows"))
    st = p.state(p.instance("default"))
    assert (st["state"], st["by"], st["pid"]) == ("running", "earlier", 7777)
    assert "does not listen on port 11434" in st["said"]  # started 10 minutes ago, past its READY_S
    assert "started by an earlier run of the platform" in st["said"] and "reaches no log" in st["said"]
    assert "runs already (pid 7777)" in str(refusal(lambda: p.start("default")))
    assert p.stop("default")["ok"] and earlier.stops == 1


# -- at boot -----------------------------------------------------------------------------------------------------------
def test_boot_on_registers_serve_and_off_removes_it(world):
    p = world.server()
    p.add_instance("default")
    p.set_key("default", KEY)
    said = p.boot("default", "yes")
    assert said["ok"] and said["said"] == "default starts at boot from now on: its task LiminalAI-tool-default (ready)"
    call = next(c for c in world.boot.calls if c[0] == "register")
    command = call[3]
    assert command[1:6] == ["-m", "liminal_libs.machines.launch", "serve", "tool", "default"]
    assert command[6:] == ["--home", str(world.tmp / "platform"), "--plugins", str(world.tmp / "plugins")]
    assert all(KEY not in word for word in command) and p.instance("default").boot is True
    assert p.boot_names() == ["default"]
    assert "turn At boot off for default first" in str(refusal(lambda: p.uninstall(True)))  # S4
    off = p.boot("default", "no")
    assert off["ok"] and "its task is removed" in off["lines"] and p.instance("default").boot is False
    assert "choose yes or no" in str(refusal(lambda: p.boot("default", "maybe")))


def test_boot_is_refused_in_words(world, monkeypatch):
    p = world.server()
    p.add_instance("default")
    p.have = None
    assert "not installed" in str(refusal(lambda: p.boot("default", True)))
    q = world.server(system="linux", wsl="Ubuntu")
    q.systemd_runs = lambda: False
    q.add_instance("default")
    assert "systemd=true" in str(refusal(lambda: q.boot("default", "yes")))
    r = world.server(system="linux", wsl="Ubuntu")
    r.systemd_runs = lambda: True
    r.login = EnvironmentLogin()  # off Windows: kept in this process alone
    monkeypatch.setenv(r.variable("instances"), Kept({"default": Instance("default")}).text())
    assert r.lasting() == LASTING
    words = str(refusal(lambda: r.boot("default", "yes")))
    assert words.startswith("start at boot needs default kept across a restart, and on this system the Login keeps")
    assert world.boot.calls == [c for c in world.boot.calls if c[0] == "read"]  # nothing was registered


def test_lasting_on_both_systems(world):
    assert world.server().lasting() == ""  # the platform's login keeps what it is given
    w = world.server(system="windows")
    w.login = EnvironmentLogin()
    assert w.lasting() == ""  # on Windows a pair is a user variable
    lin = world.server(system="linux")
    lin.login = EnvironmentLogin()
    assert lin.lasting() == LASTING


def test_a_boot_instance_is_started_and_stopped_by_its_task(world):
    p = world.server()
    p.add_instance("default")
    p.boot("default", "yes")
    said = p.start("default")
    assert said["said"] == "default is started by its task, as at boot" and world.kids.made == []
    assert ("act", "tool", "default", "start", "windows") in world.boot.calls
    server = world.kids.running(p.pidfile("default"), 8888)  # its launcher's child, its starter still running
    st = p.state(p.instance("default"))
    assert st["by"] == "system" and "started by its task at boot" in st["said"]
    stopped = p.stop("default")
    assert server.stops == 1 and p.stop_marker("default").read_text(encoding="utf-8").startswith("stopped")
    assert ("act", "tool", "default", "stop", "windows") in world.boot.calls and stopped["ok"]


def test_a_boot_instance_between_two_starts_of_its_server_is_said_so_and_stopped_by_its_task(world):
    """Its task's `launch serve` waits to start the server again (it ended, or a round was refused): no server and no
    pidfile, the task running. The page says that, the hooks refuse what the page's buttons hold back, and Stop stops
    the task."""
    p = world.server()
    p.add_instance("default")
    p.set_key("default", KEY)
    p.boot("default", "yes")
    world.boot.kept["default"] = Startup("default", "LiminalAI-tool-default", "running", "pythonw ... serve")
    boot_read(p)
    out = p.status()
    state = cells(out, "default")[3]
    assert state == {"text": "starting", "sub": "not running now: its task LiminalAI-tool-default runs, and starts it "
                                                "or waits to start it again (Log says why)"}
    tasks = buttons(out)
    assert "disabled" not in tasks["Stop"] and tasks["Start"]["note"] == "its task runs it"
    assert all(tasks[t]["note"] == "stop it first" for t in ("Change…", "Key…", "Forget the key…", "Share…"))
    for words, call in (("its settings are read when it starts", lambda: p.change_instance("default", None, 11600)),
                        ("its key is read when it starts", lambda: p.set_key("default", KEY + "x")),
                        ("its key is read when it starts", lambda: p.forget_key("default")),
                        ("where it listens is read when it starts", lambda: p.share("default", "yes", True))):
        assert str(refusal(call)) == f"stop default first: {words}"
    assert "its task runs already" in str(refusal(lambda: p.start("default")))
    assert p.running() == ["default"]  # Install and Uninstall wait for it, as its state says
    idle = "default is not running now: its task starts it, or waits to start it again (its Log says why)"
    assert str(refusal(lambda: p.try_it("default", "m", "hi"))) == idle and p.models_of("default")["said"] == idle
    assert p.models()["note"].startswith(idle) and world.transport.asked == []  # nothing listens: not asked
    world.boot.calls.clear()
    said = p.stop("default")
    assert said["ok"] and said["said"] == "default's task is stopped: its server was not running"
    assert world.boot.calls == [("act", "tool", "default", "stop", "windows")] and world.kids.made == []
    assert p.stop_marker("default").exists() and p._rt.boot is None  # read again by the next status
    world.boot.kept["default"] = Startup("default", "LiminalAI-tool-default", "ready", "pythonw ... serve")
    boot_read(p)
    assert cells(p.status(), "default")[3]["text"] == "stopped" and p.change_instance("default", None, 11600)["ok"]
    assert "is not running" in str(refusal(lambda: p.stop("default"))) and p.running() == []


def test_serving_starts_no_boot_read_and_a_status_does(world):
    """serving (other plugins' ask) uses the boot registrations as last read and runs nothing; a status reads them."""
    p = world.server()
    p.add_instance("default")
    p.boot("default", "yes")
    world.boot.calls.clear()
    with p._rt.lock:
        p._rt.boot = None
    p.serving()
    p.serving("default")
    assert p._rt.boot_thread is None and world.boot.calls == []
    p.status()
    p._rt.boot_thread.join(5)
    assert world.boot.calls == [("read", "tool", "windows")]


def test_a_boot_read_that_fails_is_said(world, monkeypatch):
    p = world.server()
    p.add_instance("default")
    p.boot("default", "yes")

    def broken(*args, **kwargs):
        raise CommandError("Get-ScheduledTask is not recognized")

    monkeypatch.setattr(autostart, "read", broken)
    boot_read(p)
    out = p.status()
    said = "its starts at boot could not be read: Get-ScheduledTask is not recognized"
    assert cells(out, "default")[3] == {"text": "stopped", "sub": f"stopped · {said}"} and said in out["problem"]


def test_at_boot_turned_on_while_a_clicks_server_runs_says_it_still_stops_with_the_platform(world):
    p = world.server()
    p.add_instance("default")
    p.start("default")
    clicked = world.kids.made[-1]
    forms = {f["id"]: f for f in p.status()["forms"]}
    now = ("The server running now was started from this page: it still stops with the platform, and its task "
           "starts it from your next sign-in.")
    assert now in forms["ai-boot"]["confirm"]["words"]
    said = p.boot("default", "yes")
    assert said["ok"] and (f"the server running now (pid {clicked.pid}) was started from this page: it still stops "
                           "when the platform stops, and its task starts it from your next sign-in") in said["lines"]
    p.app_stopping()
    assert clicked.stops == 1  # as said
    forms = {f["id"]: f for f in p.status()["forms"]}
    p._rt.boot_thread.join(5)  # (the status read the boot registrations: done before the stand-ins go)
    assert now not in forms["ai-boot"]["confirm"]["words"]  # nothing of this page's runs now


def test_a_boot_instance_is_started_by_its_task_from_a_command_that_answers_and_ends(world):
    """A one-shot platform (`once`) would end a child of its own with itself; a task's server is not its child."""
    p = world.server()
    p.add_instance("default")
    p.boot("default", "yes")
    p.app = App(p, once=True)
    assert p.start("default")["said"] == "default is started by its task, as at boot"
    p.app = None
    assert p.start("default")["ok"] and world.kids.made == []
    assert [c[3] for c in world.boot.calls if c[0] == "act"] == ["start", "start"]
    p.add_instance("click", "local", None, 11600)
    assert "a command that answers and ends would end it" in str(refusal(lambda: p.start("click")))  # (no app)


def test_on_linux_a_boot_instance_is_stopped_by_its_unit_alone(world):
    p = world.server(system="linux", wsl="Ubuntu")
    p.systemd_runs = lambda: True
    p.add_instance("default")
    p.boot("default", "yes")
    server = world.kids.running(p.pidfile("default"), 8888)
    p.stop("default")
    assert server.stops == 0 and ("act", "tool", "default", "stop", "linux") in world.boot.calls  # SIGINT to serve


def test_app_stopping_stops_a_clicks_child_and_leaves_a_boot_one(world):
    p = world.server()
    p.add_instance("click")
    p.add_instance("left", "local", None, 11600)
    p.add_instance("boot", "local", None, 11700)
    p.boot("boot", "yes")
    p.start("click")
    clicked = world.kids.made[-1]
    orphan = world.kids.running(p.pidfile("left"), 7777, note=children.adopted_words("windows"))
    system = world.kids.running(p.pidfile("boot"), 8888)
    p.app_stopping()
    assert (clicked.stops, orphan.stops, system.stops) == (1, 1, 0)
    p.app_stopping()  # it bears a second call
    assert (clicked.stops, orphan.stops, system.stops) == (1, 1, 0)
    p.start("click")
    again = world.kids.made[-1]
    p.detach()  # turned off: told it stops first
    assert again.stops == 1 and system.alive and p.app is None


def test_a_server_that_cannot_be_ended_is_said_by_the_next_status(world):
    p = world.server()
    p.add_instance("default")
    p.start("default")
    stuck = world.kids.made[-1]
    stuck.stop = lambda grace=8.0: (_ for _ in ()).throw(children.ChildError("default could not be ended"))
    p.detach()
    p.login = Pairs()
    p.login.kept = {}
    assert "its last stop could not end everything: default could not be ended" in p.status()["problem"]


# -- keys and sharing --------------------------------------------------------------------------------------------------
def test_set_key_and_forget_key(world):
    p = world.server()
    p.add_instance("default")
    said = p.set_key("default", f"  {KEY}  ")
    assert said["said"] == ("a key is kept for default as its own pair, LIMINAL_AI_TOOL_DEFAULT_KEY: kept in the "
                            "test's pairs")
    assert p.login.kept["LIMINAL_AI_TOOL_DEFAULT_KEY"] == KEY and KEY not in p.login.kept[p.variable("instances")]
    assert p.instance("default").keyed is True
    for bad, words in ((None, "type the key first"), ("", "nothing typed"), ("a\nb", "line break")):
        assert words in str(refusal(lambda: p.set_key("default", bad)))
    assert p.forget_key("default")["ok"] and "LIMINAL_AI_TOOL_DEFAULT_KEY" not in p.login.kept
    assert p.instance("default").keyed is False
    p.start("default")
    assert "stop default first" in str(refusal(lambda: p.set_key("default", KEY)))


def test_forget_key_waits_for_its_local_server_to_stop(world):
    """A running server keeps checking the key it was started with: forgotten now, the harnesses would be told none."""
    p = world.server()
    p.add_instance("default")
    p.set_key("default", KEY)
    p.add_instance("gpu", "remote", HTTPS + "gpu-box")
    p.set_key("gpu", KEY)
    p.start("default")
    assert str(refusal(lambda: p.forget_key("default"))) == "stop default first: its key is read when it starts"
    p.choose("default")
    forget = buttons(p.status())["Forget the key…"]
    assert forget["disabled"] and forget["note"] == "stop it first" and p.instance("default").keyed
    assert p.forget_key("gpu")["ok"]  # a remote one is sent its key with each ask: forgotten whenever
    p.stop("default")
    assert p.forget_key("default")["ok"] and p.serving("default")["instances"][0]["key"] == ""


def test_a_server_that_checks_no_key_keeps_none_for_one_run_here(world):
    class Keyless(Server):
        KEYED = False

    p = world.server(Keyless)
    p.add_instance("default")
    p.add_instance("gpu", "remote", HTTPS + "gpu-box")
    assert str(refusal(lambda: p.set_key("default", KEY))) == ("Tool's server checks no key: none is kept for one "
                                                               "run here")  # M10
    assert p.set_key("gpu", KEY)["ok"]  # a proxy in front of a remote one may want one
    assert "has no key of its own" in str(refusal(lambda: p.share("default", "yes")))


def test_share_is_asked_twice_and_needs_its_key(world):
    p = world.server()
    p.add_instance("default")
    assert "keep a key for default first" in str(refusal(lambda: p.share("default", "yes")))
    p.set_key("default", KEY)
    r = refusal(lambda: p.share("default", "yes"))
    assert r.accept == ACCEPT_SHARE and str(r).startswith("Every machine that reaches this one's port 11434")
    assert "Windows may ask once" in str(r) and p.instance("default").shared is False
    assert p.share("default", "yes", True)["ok"] and p.instance("default").shared is True
    assert p.address(p.instance("default")) == "every address of this machine, port 11434"
    assert "turn Share off first" in str(refusal(lambda: p.forget_key("default")))
    assert p.share("default", "no")["ok"] and p.instance("default").shared is False


# -- the Models tab, Try it, serving -----------------------------------------------------------------------------------
def answers_models(world, *ids):
    world.transport.answers[("GET", "/v1/models")] = (200, {"data": [{"id": i, "owned_by": "me"} for i in ids]})


def test_the_models_tab_asks_once_per_seen_s(world):
    p = world.server()
    p.add_instance("default")
    p.start("default")
    answers_models(world, "qwen3:8b", "llama3.2")
    page = p.models()
    p.models()
    assert len(world.transport.asked) == 1 and world.transport.asked[0][1].endswith("127.0.0.1:11434/v1/models")
    world.clock.now += SEEN_S
    p.models()
    assert len(world.transport.asked) == 2
    table = page["tables"][0]
    assert [c["title"] for c in table["columns"]] == ["Model", "Size", "Context", "Loaded", "Fits this GPU", "Load"]
    assert table["rows"][0][0] == {"text": "qwen3:8b", "sub": "me"} and table["rows"][0][5]["form"] == "model-load"
    assert page["tables"][1]["title"] == "This machine's GPU" and "RTX 5090" in page["tables"][1]["rows"][0][0]["text"]
    assert page["forms"][0]["id"] == "ai-try" and page["forms"][0]["fields"][1]["choices"][0] == {"value": "qwen3:8b"}
    assert p.more_asked[0][0] == "default" and p.more_asked[0][1].ok  # more(), at every draw
    assert page["tables"][-1]["title"] == "Find a model"


def test_a_stopped_local_instance_is_not_asked_and_more_is_asked_with_none(world):
    p = world.server()
    assert p.models()["note"].startswith("No instance yet") and p.more_asked == [(None, None)]
    p.add_instance("default")
    page = p.models()
    assert world.transport.asked == [] and page["note"].startswith("default is not running: start it")
    assert p.more_asked[-1] == ("default", None) and page["tables"][0]["actions"][0]["disabled"]


def test_a_remote_instances_fit_is_its_machines(world):
    p = world.server()
    p.add_instance("gpu", "remote", HTTPS + "gpu-box:8443")
    p.set_key("gpu", KEY)
    answers_models(world, "big")
    world.transport.answers[("GET", "/v1/models")][1]["data"][0]["max_model_len"] = 32768
    page = p.models()
    assert page["tables"][0]["rows"][0][2] == "32,768"
    assert page["tables"][0]["rows"][0][4] == "the other machine's GPU is not read from here"
    assert world.ran == [] and "This machine's GPU" not in [t["title"] for t in page["tables"]]  # not read for
    # another machine's
    assert world.transport.asked[0][2]["Authorization"] == f"Bearer {KEY}"
    assert KEY not in json.dumps(page) and KEY not in json.dumps(p.serving())


def test_a_look_that_fails_is_said(world):
    p = world.server()
    p.add_instance("wsl", "found")
    page = p.models()
    assert page["note"].startswith("wsl did not answer as expected: GET /v1/models: HTTP 404")
    assert p.state(p.instance("wsl"))["state"] == "silent"


def test_try_it(world):
    p = world.server()
    p.add_instance("default")
    assert "is not running: start it first" in str(refusal(lambda: p.try_it("default", "qwen3:8b", "hello")))
    p.start("default")
    assert "type a prompt first" in str(refusal(lambda: p.try_it("default", "qwen3:8b", "  ")))
    assert "4,001 characters long: 4,000 at most" in str(refusal(lambda: p.try_it("default", "m", "x" * 4001)))  # M10
    assert "name a model" in str(refusal(lambda: p.try_it("default", "", "hello")))
    world.transport.answers[("POST", "/v1/chat/completions")] = (200, {
        "model": "qwen3:8b", "choices": [{"message": {"content": "Hello.\nAnd more."}, "finish_reason": "length"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 512}})
    said = p.try_it("default", "qwen3:8b", "hello")
    assert said["said"].startswith("qwen3:8b answered in ") and said["said"].endswith(" s (512 tokens)")
    assert said["lines"] == ["Hello.", "And more.", "… it stopped at 512 tokens"]
    asked = json.loads(world.transport.asked[-1][3])
    assert asked["messages"][-1] == {"role": "user", "content": "hello"} and asked["max_tokens"] == 512
    world.transport.answers.pop(("POST", "/v1/chat/completions"))
    failed = p.try_it("default", "qwen3:8b", "hello")
    assert failed["ok"] is False and "did not answer" in failed["said"]


def test_try_its_long_answer_is_cut_and_said_so(world):
    p = world.server()
    p.add_instance("default")
    p.start("default")
    long = "\n".join(f"line {n:04d} " + "x" * 40 for n in range(200))  # about 10,000 characters
    world.transport.answers[("POST", "/v1/chat/completions")] = (200, {
        "model": "qwen3:8b", "choices": [{"message": {"content": long}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 400}})
    said = p.try_it("default", "qwen3:8b", "hello")  # 79 lines in its first 4,000 characters: more than one answer
    # holds (60), and what is said of the cut is kept, after them
    assert said["ok"] and len(said["lines"]) == 60 and said["lines"][0] == "line 0000 " + "x" * 40
    assert said["lines"][-2:] == ["… and 21 more lines", "… its answer is cut here, at 4,000 characters"]


def test_serving_and_models_of(world):
    p = world.server()
    p.add_instance("default", "local", None, None, False, 32768)
    p.set_key("default", KEY)
    p.add_instance("gpu", "remote", HTTPS + "gpu-box:8443")
    served = p.serving()
    assert (served["plugin"], served["title"], served["native"]) == ("tool", "Tool", "tool")
    row = served["instances"][0]
    assert row == {"name": "default", "title": "", "where": "local", "local": True,
                   "base": "http:" + "//127.0.0.1:11434", "openai": "http:" + "//127.0.0.1:11434/v1", "plain": False,
                   "state": "stopped", "key": "LIMINAL_AI_TOOL_DEFAULT_KEY", "model": "", "context": 32768,
                   "models": [], "asked": "", "port": PORT}
    assert served["instances"][1]["state"] == "unasked" and served["instances"][1]["local"] is False
    assert p.serving("gpu")["instances"][0]["name"] == "gpu"
    with pytest.raises(LookupError):
        p.serving("none")
    stopped = p.models_of("default")
    assert stopped["ok"] is False and world.transport.asked == []  # a stopped local one is not asked
    answers_models(world, "big")
    asked = p.models_of("gpu")
    assert asked["ok"] and asked["models"] == [{"id": "big", "context": None, "tools": None}]
    assert asked["asked"] == "2025-11-17T17:20:00Z" and len(world.transport.asked) == 1
    p.models_of("gpu")
    assert len(world.transport.asked) == 2  # asked now, each time
    assert p.serving("gpu")["instances"][0]["models"] == [{"id": "big", "context": None, "tools": None}]
    assert KEY not in json.dumps(served)


def test_two_servers_asking_each_other_from_two_threads_end(world):
    """S3: each one's status asks the other's `serving` (through the app) while the other asks its own, at once."""
    a = world.server(attach=False)
    b = world.server(Other, attach=False)
    app = App(a, b)
    a.app = b.app = app
    a.add_instance("default", "local", None, 9940)
    b.login.kept[b.variable("instances")] = Kept({"router": Instance("router", port=9940)}).text()  # (its add would
    # have been refused: the port is a's)
    app.asked.clear()
    a._rt.others = b._rt.others = None
    app.barrier = threading.Barrier(2)  # each ask of the other's `serving` waits until the other asks too
    said: dict = {}

    def status(p):
        said[p.name] = p.status()

    threads = [threading.Thread(target=status, args=(p,), daemon=True) for p in (a, b)]  # (daemons: a deadlock
    # fails this test, and does not hold the run)
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert not any(t.is_alive() for t in threads), "the two statuses waited on each other"
    assert said["tool"]["problem"] == "default: port 9940 is Other's instance router already"
    assert said["other"]["problem"] == "router: port 9940 is Tool's instance default already"
    assert sorted(app.asked) == [("other", SERVING), ("tool", SERVING)]


def test_serving_never_asks_conflict_and_another_app_form_is_asked_as_it_takes_it(world):
    p = world.server()
    p.add_instance("default")
    p.conflict = lambda *a, **k: (_ for _ in ()).throw(AssertionError("serving asked conflict"))
    assert p.serving()["instances"][0]["state"] == "stopped"  # S3: the state's word alone

    class FrameApp:  # the frame's App: ask(name, hook, *args)
        def __init__(self, *plugins):
            self.by = {q.name: q for q in plugins}

        def plugins(self):
            return {n: q.interface() for n, q in self.by.items()}

        def ask(self, name, hook, *args, **kwargs):
            return self.by[name].ask(hook, *args, **kwargs)

    a, b = world.server(attach=False), world.server(Other, attach=False)
    a.app = b.app = FrameApp(a, b)
    b.add_instance("router", "local", None, 9940)
    a.add_instance("x")
    assert a.conflict(a.instance("x"), 9940) == "port 9940 is Other's instance router already"


# -- the rest of the page's hooks --------------------------------------------------------------------------------------
def test_choose_and_log_of(world):
    p = world.server()
    p.add_instance("default")
    p.add_instance("second", "local", None, 11600)
    assert p.shown().name == "second"
    p.choose("default")
    assert p.shown().name == "default" and p.status()["tables"][0]["select"]["value"] == "default"
    with pytest.raises(LookupError):
        p.choose("none")
    log = p.log_path("default")
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("".join(f"line {n}\n" for n in range(60)), encoding="utf-8")
    said = p.log_of("default")
    assert said["said"] == str(log) and said["lines"][0] == "line 20" and len(said["lines"]) == 40
    p.boot("default", "yes")
    p.boot_log("default").write_text("keep: starting tool/default\n", encoding="utf-8")
    assert p.log_of("default")["lines"][-1] == "keep: starting tool/default"
    assert p.log_of("second")["lines"] == ["nothing is in it yet"]


def test_no_key_in_any_answer(world):
    p = world.server()
    p.add_instance("default")
    p.set_key("default", KEY)
    p.add_instance("gpu", "remote", HTTPS + "gpu-box")
    p.set_key("gpu", KEY)
    answers_models(world, "m")
    said = [p.status(), p.serving(), p.models(), p.models_of("gpu"), p.start("default"), p.log_of("default"),
            p.state(p.instance("default")), p.boot("default", "yes"), p.choose("gpu"), p.models(),
            p.try_it("gpu", "m", "hi"), p.stop("default"), p.remove_instance("gpu")]
    text = json.dumps(said, default=str)
    assert KEY not in text and "LIMINAL_AI_TOOL_DEFAULT_KEY" in text  # its pair's name, never its value
    assert all(KEY not in word for c in world.boot.calls for word in map(str, c))


def test_a_stops_trouble_is_said_once_then_dropped_while_nothing_runs(world):
    # The base notes a status that has said what the last stop could not end (AiPlugin._said, held to every status by
    # _steady); a model server's own one-line helper once shadowed it, so the trouble was said for ever.
    from liminal_libs.machines.ai import AiPlugin

    assert ModelServer._said is AiPlugin._said
    server = world.server()
    with server._rt.lock:
        server._rt.trouble, server._rt.trouble_said = "its last stop could not end everything: stand-in", False
    first = server.status()
    assert "its last stop could not end everything" in str(first.get("problem") or "")
    second = server.status()
    assert "its last stop could not end everything" not in str(second.get("problem") or "")

