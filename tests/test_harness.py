"""What every harness plugin of the platform shares (liminal_libs.machines.harness, 1.62.0): a stand-in subclass that
conforms with one card; its hooks (never a terminal); the model servers asked through a stand-in platform (only those
that answer `serving`, kept SERVING_S, a refusal left out with its words, no lock held while another plugin is asked);
Use… and the choice kept through the login (its JSON's round trip, a broken value, the caps, its options); Open… on
Windows with a desktop (one console window, held by the console's `hold`) and without one, and on Linux (the lines to
paste); Command… on both; each refusal in words and in its order (a folder on another system's drive, a local server
that is not running or a found one that answers nothing: Open… only); the window out of a job the platform is held
in; the shown lines unsetting what `drop` names as a new terminal has it and never holding a secret's value, a short
key told apart from a folder's name, and a word PowerShell 5.1 would not pass refused; a curly quote in the folder;
what it says it reads, asks and keeps; Ask…; Main; and no key in any answer.

Nothing is installed, downloaded, started or asked over the network here: stand-ins answer for the login, the platform,
the window's process and the clock, and the shared guard (conftest.py) fails a test that starts a process or opens a
connection."""
from __future__ import annotations

import copy
import json
import re
import shlex
import threading
from pathlib import Path

import pytest

import liminal_libs
from conftest import Reached
from liminal_libs import console, instances, mounts
from liminal_libs.apps import Refused, authorization
from liminal_libs.apps.authorization import EnvironmentLogin, Login, Unauthorized, pair_name, variable_name
from liminal_libs.machines import ai, children, harness, windows
from liminal_libs.machines.ai import Outside, Package, Setting
from liminal_libs.machines.children import PLACEHOLDER, Launch
from liminal_libs.machines.harness import (CHOOSE, NEW_CONSOLE, NO_APP, OPENS, RUN_IT, SERVING_S, Harness, HarnessRun,
                                           Use, clean_model, model_ids, server_words, split_server)
from liminal_libs.sources import conformance
from liminal_libs.sources.apis import Api, Link

pytestmark = pytest.mark.usefixtures("no_outside")

HTTP, HTTPS = "http:" + "//", "https:" + "//"  # an address's start, put together here: no file names a host whole
CARD = Api("Stand-in harness", "Its maker", "What the stand-in harness offers the platform", kind="command",
           links=(Link("Its documentation", HTTPS + "docs.example.test/harness"),), verified="2026-11-17")
PACKAGE = Package("Tool", "1.0", 10_485_760, "MIT (its maker's).", ("downloads.example.test",))
KEY = "sk-llama-key-0123456789"  # the key llama.cpp's plugin kept for its instance gpu: in no answer, no line
KEY_VARIABLE = "LIMINAL_AI_LLAMACPP_GPU_KEY"  # the pair it is kept under, as the `serving` row names it
DECLARED = ("MASSIVE_API_KEY", "GROK_API_KEY")  # what the registry says the installed plugins declare
ENV = {"PATH": "/usr/bin", "HOME": "/home/someone", "MASSIVE_API_KEY": "m-key-1", "OPENAI_API_KEY": "o-key-1",
       "LIMINAL_AI_TOOL_USE": "{}", "LIMINAL_PLATFORM_DIR": "/data/platform", KEY_VARIABLE: KEY}  # (as on Windows)
DROPPED = ["LIMINAL_AI_LLAMACPP_GPU_KEY", "LIMINAL_AI_TOOL_USE", "LIMINAL_PLATFORM_DIR", "MASSIVE_API_KEY",
           "OPENAI_API_KEY"]  # the names of ENV that the tool's launch, the registry and Liminal's own drop, in order
MODEL = "Qwen3-8B-Q4_K_M"


def row(name, **given) -> dict:
    """One instance as a model server's `serving` says it (machines/modelserver.py's shape)."""
    out = {"name": name, "title": "", "where": "local", "local": True, "base": HTTP + "127.0.0.1:9931",
           "openai": HTTP + "127.0.0.1:9931/v1", "plain": False, "state": "running", "key": "", "model": "",
           "context": None, "models": [], "asked": ""}
    out.update(given)
    return out


def serving() -> dict:
    """What three inference plugins say they serve: a found Ollama without a key, a llama.cpp with a key (and one of
    its instances stopped), a remote vLLM over plain http whose model says nothing of its tools."""
    return {
        "ollama": {"plugin": "ollama", "title": "Ollama", "native": "ollama", "instances": [
            row("default", where="found", base=HTTP + "127.0.0.1:11434", openai=HTTP + "127.0.0.1:11434/v1",
                state="answering", asked="2026-11-17T20:00:00Z",
                models=[{"id": "qwen3:8b", "context": 40960, "tools": True},
                        {"id": "llama3.2:3b", "context": 131072, "tools": True}])]},
        "llamacpp": {"plugin": "llamacpp", "title": "llama.cpp", "native": "llamacpp", "instances": [
            row("gpu", title="The GPU", key=KEY_VARIABLE, model=MODEL,
                models=[{"id": MODEL, "context": 32768, "tools": True}]),
            row("cpu", state="stopped", base=HTTP + "127.0.0.1:9932", openai=HTTP + "127.0.0.1:9932/v1")]},
        "vllm": {"plugin": "vllm", "title": "vLLM", "native": "vllm", "instances": [
            row("box", where="remote", local=False, base=HTTP + "gpu-box.example.test:8000",
                openai=HTTP + "gpu-box.example.test:8000/v1", plain=True, state="unasked",
                models=[{"id": "Qwen/Qwen3-8B", "context": 32768, "tools": None}])]},
    }


class HookRefused(Refused):
    """The platform's refusal of a plugin's hook (liminal-platform's): its own words beside the frame's reason."""

    def __init__(self, status: int, reason: str, words: str):
        super().__init__(status, reason)
        self.words = words


class App:
    """The platform as a harness asks it: the plugins attached with their hooks, and `ask(name, hook, args)` (its
    form: the arguments as one list), each ask noted."""

    def __init__(self):
        self.serving = serving()
        listed = [{"id": MODEL, "size": 5_000_000_000, "context": 32768, "loaded": True, "tools": True, "detail": ""},
                  {"id": "tiny.gguf", "size": None, "context": None, "loaded": False, "tools": None, "detail": ""}]
        self.models = {"llamacpp": {"said": "llama.cpp / gpu lists 2 models", "ok": True,
                                    "asked": "2026-11-17T21:00:00Z", "models": listed}}
        self.refusing: dict[str, BaseException] = {}
        self.asked: list[tuple[str, str, list]] = []

    def plugins(self) -> dict:
        faces = {name: {"name": name, "hooks": {"present": "()", "status": "()", "serving": "(name='')",
                                                "models_of": "(name)"}} for name in self.serving}
        faces["hwstats"] = {"name": "hwstats", "hooks": {"present": "()", "status": "()"}}  # serves nothing
        faces["tool"] = {"name": "tool", "hooks": {"use": "(server, model, *values)"}}  # the harness itself
        return faces

    def ask(self, name: str, hook: str, args: list):
        self.asked.append((name, hook, list(args)))
        if name in self.refusing:
            raise self.refusing[name]
        if hook == "serving" and name in self.serving:
            return copy.deepcopy(self.serving[name])
        if hook == "models_of" and name in self.models:
            return copy.deepcopy(self.models[name])
        raise LookupError(f"{name} offers no {hook!r}")

    def served(self) -> list[str]:
        return [name for name, hook, _ in self.asked if hook == "serving"]


class Pairs(Login):
    """The platform's login as a test has it: pairs kept in memory, each read and each save noted."""

    def __init__(self):
        self.kept: dict[str, str] = {}
        self.read: list[str] = []
        self.saved: list[tuple[str, bool]] = []

    def user(self) -> dict:
        return {"name": "someone"}

    def vector(self, name: str) -> str:
        self.read.append(name)
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


class Window:
    """A stand-in for a window's process: its number, and its exit code once it has ended (None: open)."""

    def __init__(self, pid: int):
        self.pid, self.code = pid, None

    def poll(self):
        return self.code


class Popen:
    """A stand-in for subprocess.Popen: what each start was given, and the window it made."""

    def __init__(self):
        self.made: list[dict] = []
        self.windows: list[Window] = []
        self.fails: BaseException | None = None

    def __call__(self, argv, **kw):
        if self.fails is not None:
            raise self.fails
        self.made.append({"argv": list(argv), **kw})
        self.windows.append(Window(4321 + len(self.windows)))
        return self.windows[-1]


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


class Asked(BaseException):
    """A stand-in asked that must not be: a BaseException, so no `except Exception` of the code can swallow it."""


def never(what):
    def stand_in(*args, **kwargs):
        raise Asked(f"{what} was asked: it must not be")
    return stand_in


class Tool(Harness):
    """A stand-in harness: what its launch is given, what it refuses and what it says are the test's to set."""

    name = "tool"
    title = "Tool"
    about = "A stand-in harness for the base's tests"
    order = 520
    LIBS_FLOOR = "1.62.0"
    apis = (CARD,)
    OPTIONS = (Setting("context", "Context", "number", min=2048, max=2_000_000, note="tokens"),
               Setting("commits", "Commits", "choice", "no", choices=("no", "yes")))

    def __init__(self, outside=None):
        super().__init__(outside)
        self.made: list[dict] = []  # what each launch was given
        self.refuse: BaseException | None = None  # what launch raises
        self.instead: object = None  # what launch answers in place of a Launch
        self.on_command_line = False  # a launch that puts the key on its command line (a plugin's fault)
        self.marks_secret = True  # whether its launch names its key's variable secret itself
        self.here = ""
        self.before = " Tool writes into the folder's files without asking."
        self.more: object = {"tables": [{"title": "Before you use it",
                                         "columns": [{"title": "What"}, {"title": "Said"}],
                                         "rows": [["Local only", "Nothing leaves this machine."]]}],
                             "forms": [], "actions": [{"hook": "refresh", "args": [], "title": "Look again"}]}

    def package(self):
        return PACKAGE

    def runs_here(self):
        return self.here

    def program(self) -> str:
        return str(self.home / "app" / "1.0" / "tool.exe")

    def launch(self, folder, use, at, key=""):
        self.made.append({"folder": folder, "use": use, "at": at, "key": key})
        if self.refuse is not None:
            raise self.refuse
        if self.instead is not None:
            return self.instead
        argv = [self.program(), "--model", use.model, "--base", at["openai"]]
        if self.on_command_line and key:
            argv += ["--api-key", key]
        env = {"TOOL_CONFIG_DIR": str(self.home / "config")}
        if key:
            env["TOOL_SERVER_KEY"] = key
        secret = ("TOOL_SERVER_KEY",) if key and self.marks_secret else ()
        return Launch(argv, env=env, drop=("OPENAI_*",), secret=secret)

    def open_words(self, use, at):
        if isinstance(self.before, BaseException):
            raise self.before
        return self.before

    def main_more(self):
        if isinstance(self.more, BaseException):
            raise self.more
        return self.more


@pytest.fixture(autouse=True)
def this_library(monkeypatch):
    """The release these bases come in (a stand-in version), on this system's own disk unless a test says otherwise
    (a stand-in mounts.foreign)."""
    monkeypatch.setattr(liminal_libs, "__version__", "1.62.0")
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: False)


@pytest.fixture
def tool(tmp_path):
    out = Outside(env=dict(ENV), system="windows", home=tmp_path / "tool", clock=Clock(), interactive=lambda: True,
                  popen=Popen(), variables=lambda: DECLARED)
    p = Tool(out)
    p.attach(App(), Pairs())
    p.login.kept[KEY_VARIABLE] = KEY  # kept by llama.cpp's plugin for its instance gpu, through the same login
    return p


@pytest.fixture
def project(tmp_path) -> Path:
    folder = tmp_path / "project"
    folder.mkdir()
    return folder


def installed(p: Harness) -> None:
    app = p.home / "app"
    (app / "1.0").mkdir(parents=True, exist_ok=True)
    (app / "1.0" / "tool.exe").write_text("a stand-in program", encoding="utf-8")
    (app / "CURRENT").write_text("1.0\n", encoding="utf-8")


def chosen(p: Harness, server="llamacpp/gpu", model=MODEL, folder="", **options) -> None:
    p.login.kept[p.variable("use")] = json.dumps({"v": 1, "server": server, "model": model, "folder": str(folder),
                                                  "options": options})


def refusal(call) -> instances.Refusal:
    with pytest.raises(instances.Refusal) as caught:
        call()
    return caught.value


def ps_lines(p: Tool, folder: Path, key: str = PLACEHOLDER) -> list[str]:
    q = windows.quote
    argv = [p.program(), "--model", MODEL, "--base", HTTP + "127.0.0.1:9931/v1"]
    return [*(f"Remove-Item Env:{n} -ErrorAction SilentlyContinue" for n in DROPPED),
            f"$env:TOOL_CONFIG_DIR = {q(str(p.home / 'config'))}", f"$env:TOOL_SERVER_KEY = {q(key)}",
            f"Set-Location -LiteralPath {q(str(folder))}", "& " + " ".join(q(w) for w in argv)]


def sh_lines(p: Tool, folder: Path) -> list[str]:
    argv = [p.program(), "--model", MODEL, "--base", HTTP + "127.0.0.1:9931/v1"]
    return [*(f"unset {n}" for n in DROPPED), f"export TOOL_CONFIG_DIR={shlex.quote(str(p.home / 'config'))}",
            f"export TOOL_SERVER_KEY={shlex.quote(PLACEHOLDER)}", f"cd {shlex.quote(str(folder))}", shlex.join(argv)]


def table(status: dict, title: str) -> dict:
    return next(t for t in status["tables"] if t["title"] == title)


def form(status: dict, form_id: str) -> dict:
    return next(f for f in status["forms"] if f["id"] == form_id)


def button(status: dict, form_id: str) -> dict:
    return next(a for a in status["actions"] if a.get("form") == form_id)


# -- the contract ------------------------------------------------------------------------------------------------------
def test_a_stand_in_harness_conforms_with_one_card(tool):
    assert conformance.problems(tool) == []
    said = (tool.KIND, tool.SYSTEM, tool.SECTION, tool.GROUP, tool.api)
    assert said == ("machine", "platform", "ai", "harness", "2.2") and Harness.GROUP == "harness"


def test_its_hooks_are_the_bases_and_no_terminal(tool):
    hooks = tool.interface()["hooks"]
    assert set(hooks) == {"present", "status", "refresh", "install", "uninstall", "use", "open", "command",
                          "ask_models"}
    assert Harness.HOOKS == (*ai.AiPlugin.HOOKS, "use", "open", "command", "ask_models")
    assert hooks["use"] == "(server, model, *values) -> 'dict'" and hooks["ask_models"] == "(server) -> 'dict'"
    assert hooks["open"] == "(folder=None) -> 'dict'" and hooks["command"] == "(folder=None) -> 'dict'"
    assert "terminal" not in Harness.HOOKS and not hasattr(Harness, "terminal")  # M1: no page terminal
    assert not hasattr(Harness, "PAGE_TERMINAL")
    assert harness.Setting is ai.Setting and Harness.OPTIONS == () and tool.JOB_HOOKS == ("install",)
    copied = tool.with_(origin="the plugin directory's checkout")
    assert isinstance(tool._rt, HarnessRun) and copied._rt is tool._rt and copied.out is tool.out


def test_it_says_what_it_only_reads_what_it_asks_and_what_it_keeps(tool):
    # the contract's words the Internal API tab reads by name (C-api-tabs-plan 2.3, given to A's bases): a hook a
    # read is never drawn as a change, and the platform logs no read as an ask
    assert Harness.READ_HOOKS == ("command", "ask_models") and set(Harness.READ_HOOKS) <= set(Harness.HOOKS)
    assert [ask[:2] for ask in Harness.ASKS] == [("", "serving"), ("", "models_of")]  # "": whichever answers it
    assert all(len(ask) == 3 and all(isinstance(x, str) for x in ask) and ask[2] for ask in Harness.ASKS)
    assert tool.KEEPS == (("LIMINAL_AI_TOOL_USE", "what it is started against: the model server, the model, the "
                                                  "folder last opened and its options"),)
    assert tool.KEEPS[0][0] == tool.variable("use") and getattr(tool, "SERVICE_HOOKS", ()) == ()  # it serves none


# -- the model servers -------------------------------------------------------------------------------------------------
def test_the_model_servers_are_asked_through_the_platform_and_kept(tool):
    served = tool.servers()
    assert [a["plugin"] for a in served] == ["ollama", "llamacpp", "vllm"]
    assert tool.app.asked == [("ollama", "serving", []), ("llamacpp", "serving", []), ("vllm", "serving", [])]
    served[0]["instances"].clear()  # a copy: what is kept is not touched
    tool.servers()[1]["instances"].clear()  # nor through what is answered from what is kept
    assert [len(a["instances"]) for a in tool.servers()] == [1, 2, 1]
    tool.out.clock.now += SERVING_S - 1
    assert tool.servers()[0]["instances"][0]["name"] == "default" and len(tool.app.asked) == 3  # kept
    tool.out.clock.now += 2
    tool.servers()
    assert len(tool.app.asked) == 6  # asked again once SERVING_S passed
    tool.servers(fresh=True)
    assert len(tool.app.asked) == 9  # and at a click
    at = tool.serving_of("llamacpp/gpu")
    assert {k: at[k] for k in ("plugin", "native", "plugin_title", "server", "name", "key", "openai")} == {
        "plugin": "llamacpp", "native": "llamacpp", "plugin_title": "llama.cpp", "server": "llamacpp/gpu",
        "name": "gpu", "key": KEY_VARIABLE, "openai": HTTP + "127.0.0.1:9931/v1"}
    assert tool.serving_of("llamacpp/none") is None and server_words(at) == "llama.cpp / gpu"
    assert SERVING_S == 30.0


def test_a_plugin_that_refuses_is_left_out_with_its_words(tool):
    app = tool.app
    app.refusing["ollama"] = HookRefused(400, "ValueError: too old", "Ollama needs liminal-libs 1.62.0 or newer")
    app.refusing["vllm"] = Refused(503, "the platform is stopping")
    app.serving["llamacpp"] = ["not", "a", "dict"]
    status = tool.status()
    servers = table(status, "Model servers")
    assert servers["rows"] == [] and servers["empty"].startswith("No model server is offered here")
    note = servers["note"]
    assert "ollama did not say what it serves: Ollama needs liminal-libs 1.62.0 or newer." in note
    assert "vllm did not say what it serves: the platform is stopping." in note
    assert "llamacpp's answer is not what a model server serves: it is left out." in note
    app.refusing = {"ollama": LookupError("no plugin 'ollama' is attached to platform")}
    app.serving["llamacpp"] = {"plugin": "llamacpp", "instances": [{"name": "Not A Name"}, "x", row("gpu")]}
    del app.serving["vllm"]
    assert [a["plugin"] for a in tool.servers(fresh=True)] == ["llamacpp"]
    assert tool.servers()[0]["instances"][0]["name"] == "gpu"  # an instance without a sound name is left out
    assert "ollama did not say what it serves: no plugin 'ollama' is attached to platform" in table(
        tool.status(), "Model servers")["note"]


def test_without_the_platform_nothing_is_asked(tmp_path, project):
    p = Tool(Outside(env={}, system="windows", home=tmp_path / "alone", variables=lambda: ()))
    p.login = Pairs()
    installed(p)
    chosen(p, folder=project)
    assert p.servers() == [] and NO_APP in table(p.status(), "Model servers")["note"]
    for call in (lambda: p.use("llamacpp/gpu", MODEL), lambda: p.open(str(project)), lambda: p.command(),
                 lambda: p.ask_models("llamacpp/gpu")):
        assert str(refusal(call)) == NO_APP


def test_no_lock_is_held_while_another_plugin_is_asked(tool):
    inner: dict = {}
    real = tool.app.ask

    def ask(name, hook, args):
        if name == "ollama" and not inner:  # once: the page asks the harness's status meanwhile, from another thread
            inner["started"] = True
            worker = threading.Thread(target=lambda: inner.update(status=tool.status()))
            worker.start()
            worker.join(5)
            inner["waited"] = worker.is_alive()
        return real(name, hook, args)

    tool.app.ask = ask
    assert [a["plugin"] for a in tool.servers(fresh=True)] == ["ollama", "llamacpp", "vllm"]
    assert inner["waited"] is False and inner["status"]["valid"] is True


# -- Use… --------------------------------------------------------------------------------------------------------------
def test_use_keeps_the_choice_through_the_login(tool):
    answer = tool.ask("use", "llamacpp/gpu", MODEL, "32768", "yes")
    assert answer == {"said": f"From now on Tool is started against llama.cpp / gpu with {MODEL}", "ok": True,
                      "lines": ["kept in the test's pairs"]}
    kept = json.loads(tool.login.kept["LIMINAL_AI_TOOL_USE"])
    assert kept == {"v": 1, "server": "llamacpp/gpu", "model": MODEL, "folder": "",
                    "options": {"context": 32768, "commits": "yes"}}
    assert tool.use_kept() == Use("llamacpp/gpu", MODEL, "", {"context": 32768, "commits": "yes"})
    assert tool.app.served()[-3:] == ["ollama", "llamacpp", "vllm"]  # asked now: the choice is of what is offered now
    chosen(tool, folder="C:\\work\\x")
    tool.use("ollama/default", "qwen3:8b", None)  # a value left empty: the tool's own default
    assert tool.use_kept() == Use("ollama/default", "qwen3:8b", "C:\\work\\x", {})  # the folder kept stays
    tool.use("vllm/box", "Qwen/Qwen3-8B")
    assert tool.use_kept().server == "vllm/box"


def test_use_through_a_login_that_keeps_a_pair_only_until_a_restart_says_so(tool):
    tool.login = EnvironmentLogin(env={})  # variables of its own: kept in that mapping alone, as off Windows
    answer = tool.use("ollama/default", "qwen3:8b")
    assert answer["lines"] == ["kept in the login's variables", ai.LASTING]
    assert json.loads(tool.login.env["LIMINAL_AI_TOOL_USE"])["server"] == "ollama/default"


def test_use_is_refused_in_words(tool):
    def refused(words, *args):
        e = refusal(lambda: tool.use(*args))
        assert words in str(e), str(e)

    refused("choose a model server: one of the instances the Model servers table lists", "", MODEL)
    refused("choose a model server", None, MODEL)
    refused("a model server is named <plugin>/<instance> (ollama/default), not 'llama'", "llama", MODEL)
    refused("llamacpp/none is not offered now: choose one of the instances", "llamacpp/none", MODEL)
    refused("choose a model of llama.cpp / gpu: its id, as the server lists it", "llamacpp/gpu", " ")
    refused("a model's id is 256 characters at most, without a line break", "llamacpp/gpu", "a\nb")
    refused("a model's id is 256 characters at most", "llamacpp/gpu", "x" * 257)
    refused(f"llama.cpp / gpu lists no model 'llama3' (it lists {MODEL}): Ask… reads its list again",
            "llamacpp/gpu", "llama3")
    refused("Tool takes 2 options, not 3", "ollama/default", "qwen3:8b", 4096, "no", "x")
    refused("Context is a whole number, not 'big'", "ollama/default", "qwen3:8b", "big")
    refused("Context is a whole number from 2,048 to 2,000,000, not 100", "ollama/default", "qwen3:8b", 100)
    refused("Commits is one of no, yes, not 'maybe'", "ollama/default", "qwen3:8b", None, "maybe")
    tool.app.serving["vllm"]["instances"][0]["openai"] = ""
    refused("Tool needs an OpenAI-compatible address, and vLLM / box gives none", "vllm/box", "Qwen/Qwen3-8B")
    assert "LIMINAL_AI_TOOL_USE" not in tool.login.kept  # nothing kept by a refusal
    assert tool.use("llamacpp/cpu", "anything.gguf")["ok"] is True  # a server that has listed nothing: as typed


def test_a_kept_choice_that_cannot_be_read_is_said(tool, project):
    installed(tool)
    variable = tool.variable("use")
    for text, why in (("not json", "it is not JSON"), ("[1]", "it is not a JSON object"),
                      ('{"v": 2, "server": "a/b", "model": "m"}', "it is of version 2"),
                      ('{"v": 1, "server": 3, "model": "m"}', "its server, model and folder are texts"),
                      ('{"v": 1, "server": "a", "model": "m"}', "a model server is named <plugin>/<instance>"),
                      ('{"v": 1, "server": "a/b", "model": ""}', "choose a model of its server"),
                      ('{"v": 1, "server": "a/b", "model": "m", "folder": "a\\nb"}', "its folder is 1,024")):
        tool.login.kept[variable] = text
        assert tool.use_kept() is None, text
        status = tool.status()
        assert f"the choice kept in {variable} could not be read ({why}" in status["problem"], text
        assert status["problem"].endswith("Use… keeps a new one") and status["uses"] == "nothing yet"
    assert str(refusal(lambda: tool.open(str(project)))).startswith(f"{CHOOSE} (the choice kept in {variable} could")
    tool.use("ollama/default", "qwen3:8b")
    assert tool.use_kept() is not None and "problem" not in tool.status()  # Use… kept a new one


def test_kept_options_are_read_by_the_options_of_now(tool):
    chosen(tool, context=4096, commits="maybe", gone=1)
    assert tool.use_kept().options == {"context": 4096}  # an option this version lacks, or a value it refuses: dropped
    chosen(tool, context=100, commits="yes")
    assert tool.use_kept().options == {"commits": "yes"}
    use = Use("llamacpp/gpu", MODEL, "C:\\Users\\Ciara’s\\x", {"context": 8192})
    assert Use.of(use.text()) == use and hash(use) == hash(Use.of(use.text()))
    assert json.loads(use.text()) == {"v": 1, "server": "llamacpp/gpu", "model": MODEL,
                                      "folder": "C:\\Users\\Ciara’s\\x", "options": {"context": 8192}}


# -- Open… -------------------------------------------------------------------------------------------------------------
def test_open_on_windows_with_a_desktop_starts_one_window(tool, project):
    installed(tool)
    chosen(tool)
    answer = tool.ask("open", str(project))
    popen = tool.out.popen
    assert len(popen.made) == 1
    made = popen.made[0]
    argv = [tool.program(), "--model", MODEL, "--base", HTTP + "127.0.0.1:9931/v1"]
    assert made["argv"] == console.hold_command(argv) and made["argv"][1:6] == ["-P", "-m", "liminal_libs.console",
                                                                                "hold", "--"]
    # its own console, and out of any job the platform is held in (a keeper's ends what it holds with itself)
    assert made["creationflags"] == NEW_CONSOLE | harness.BREAKAWAY == 0x01000010 and made["cwd"] == str(project)
    assert made["env"] == {"PATH": "/usr/bin", "HOME": "/home/someone", "TOOL_CONFIG_DIR": str(tool.home / "config"),
                           "TOOL_SERVER_KEY": KEY}  # no pair of Liminal's, nor what the tool drops; its key alone
    assert tool.made[-1]["key"] == KEY and tool.made[-1]["folder"] == str(project)
    assert tool.made[-1]["at"]["server"] == "llamacpp/gpu" and tool.made[-1]["at"]["native"] == "llamacpp"
    assert answer == {"said": f"Tool opened in a window of its own in {project}, started against llama.cpp / gpu with "
                              f"{MODEL}", "ok": True,
                      "lines": ["its window's process: 4321", "closing the window ends it"]}
    assert KEY not in json.dumps(answer) and tool.use_kept().folder == str(project)  # the folder kept for next time
    assert tool.running() == [f"the window open in {project}"]
    assert f"stop the window open in {project} first" in str(refusal(lambda: tool.uninstall(True)))
    status = tool.status()
    assert button(status, "ai-uninstall")["note"] == f"stop the window open in {project} first"
    tool.app_stopping()  # the platform stops: a window is its user's, and stays
    assert tool.running() == [f"the window open in {project}"]
    popen.windows[0].code = 0  # closed
    assert tool.running() == []


def test_a_window_the_platforms_job_will_not_let_go_is_opened_in_it_and_that_is_said(tool, project):
    class Held(Popen):
        """A platform held in a job object that lets nothing leave it (a keeper's, keep.py's): Windows refuses a
        start that asks to leave it (ERROR_ACCESS_DENIED)."""

        def __call__(self, argv, **kw):
            if kw["creationflags"] & harness.BREAKAWAY:
                raise PermissionError(13, "Access is denied")
            return super().__call__(argv, **kw)

    installed(tool)
    chosen(tool)
    tool.out.popen = held = Held()
    answer = tool.open(str(project))
    assert [m["creationflags"] for m in held.made] == [NEW_CONSOLE]  # opened all the same, in its own console
    assert answer["lines"] == ["its window's process: 4321", "closing the window ends it", harness.HELD_WORDS]
    assert "ends when that program ends" in harness.HELD_WORDS and tool.running() == [f"the window open in {project}"]


def test_open_on_windows_without_a_desktop_shows_powershell_lines(tool, project):
    installed(tool)
    chosen(tool)
    tool.out.interactive = lambda: False  # a platform without a desktop: a boot service's
    answer = tool.open(str(project))
    assert tool.out.popen.made == [] and answer == {"said": RUN_IT, "ok": True, "lines": ps_lines(tool, project)}
    assert RUN_IT == "Run it in a terminal of yours"
    assert tool.made[-1]["key"] == PLACEHOLDER and pair_name(KEY_VARIABLE) not in tool.login.read  # the key unread
    assert tool.use_kept().folder == str(project)


def test_open_on_linux_shows_sh_lines(tool, project):
    installed(tool)
    chosen(tool)
    tool.out.system = "linux"
    tool.out.interactive = never("whether a window can be shown (not Windows)")
    answer = tool.open(str(project))
    assert tool.out.popen.made == [] and answer == {"said": RUN_IT, "ok": True, "lines": sh_lines(tool, project)}
    assert tool.status()["opens"] == OPENS[False]


def test_open_is_refused_in_words_and_in_its_order(tool, project, tmp_path, monkeypatch):
    def refused(words, folder=str(project)):
        e = refusal(lambda: tool.open(folder))
        assert str(e) == words, str(e)

    refused("Tool is not installed here: Install… first")
    installed(tool)
    tool.here = "Tool runs on x86-64 only"
    refused("Tool runs on x86-64 only")
    tool.here = ""
    tool._rt.changing.acquire()
    try:
        refused("Tool is being installed or removed: wait for that to end")
    finally:
        tool._rt.changing.release()
    refused(CHOOSE)
    chosen(tool)
    refused("give the folder to open Tool in: a whole path, such as C:\\Users\\you\\project", None)
    refused("give the folder to open Tool in: a whole path, such as C:\\Users\\you\\project", "  ")
    refused("relative is not a whole path: give it from its drive, such as C:\\Users\\you\\project", "relative")
    refused("a folder is a whole path of 1,024 characters at most, without a line break or a control character",
            str(project) + "\nx")
    missing = tmp_path / "missing"
    refused(f"there is no folder {missing} here", str(missing))
    (tmp_path / "a-file").write_text("x", encoding="utf-8")
    refused(f"there is no folder {tmp_path / 'a-file'} here", str(tmp_path / "a-file"))
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: True)
    refused(f"{missing} is on another system's drive: open it from that system's platform", str(missing))
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: False)
    chosen(tool, server="llamacpp/gone")
    refused("llamacpp/gone is not offered now (its plugin is off, or the instance was removed): Use… chooses another")
    tool.app.serving["vllm"]["instances"][0]["openai"] = ""
    chosen(tool, server="vllm/box", model="Qwen/Qwen3-8B")
    refused("Tool needs an OpenAI-compatible address, and vLLM / box gives none")
    chosen(tool, server="llamacpp/cpu", model="any.gguf")
    refused("llama.cpp / cpu is not running: start it on llama.cpp's page first")
    tool.app.serving["llamacpp"]["instances"][1]["state"] = "exited"
    refused("llama.cpp / cpu is not running: start it on llama.cpp's page first")
    assert tool.out.popen.made == [] and tool.made == []  # nothing prepared, nothing started


def test_open_is_refused_against_a_server_found_here_that_answers_nothing_now(tool, project):
    installed(tool)
    found = tool.app.serving["ollama"]["instances"][0]
    found.update(state="silent", port=11434)  # found running here once; nothing listens on its port now
    chosen(tool, server="ollama/default", model="qwen3:8b")
    words = "Ollama / default answers nothing on port 11434 here: start it first"
    assert str(refusal(lambda: tool.open(str(project)))) == words
    assert button(tool.status(), "ai-open") == {"form": "ai-open", "title": "Open…", "disabled": True, "note": words}
    assert tool.command(str(project))["ok"] is True and tool.out.popen.made == []  # the lines are for later
    del found["port"]  # (a row of a server that names no port)
    assert str(refusal(lambda: tool.open(str(project)))) == "Ollama / default answers nothing here: start it first"
    found["state"] = "answering"
    assert tool.open(str(project))["ok"] is True and len(tool.out.popen.made) == 1
    tool.app.serving["vllm"]["instances"][0]["state"] = "silent"  # one on another machine is the tool's to ask
    chosen(tool, server="vllm/box", model="Qwen/Qwen3-8B")
    assert tool.open(str(project))["ok"] is True


def test_a_folder_pasted_with_its_quotes_and_the_kept_folder(tool, project):
    installed(tool)
    chosen(tool, folder=project)
    tool.out.interactive = lambda: False
    assert tool.open(f'"{project}"')["lines"] == ps_lines(tool, project)
    assert tool.open(None)["lines"] == ps_lines(tool, project)  # left empty: the folder kept
    assert tool.open("")["lines"] == ps_lines(tool, project)
    other = project / "other"
    other.mkdir()
    assert tool.open(other)["lines"] == ps_lines(tool, other)  # a Path, as plugin code may give it
    assert tool.use_kept().folder == str(other)


def test_the_plugins_own_refusal_passes_through(tool, project):
    installed(tool)
    chosen(tool)
    tool.refuse = instances.Refusal("Qwen3 needs a context of 16,384 at least", accept="accept_small")
    e = refusal(lambda: tool.open(str(project)))
    assert str(e) == "Qwen3 needs a context of 16,384 at least" and e.accept == "accept_small"
    tool.refuse = ValueError(f"the key {KEY} is refused by the tool")  # the real key, read for the window
    e = refusal(lambda: tool.open(str(project)))
    assert str(e) == "the key <hidden> is refused by the tool" and e.accept is None
    tool.refuse = OSError("disk full")
    with pytest.raises(children.ChildError) as caught:
        tool.command(str(project))
    assert str(caught.value) == "Tool could not be prepared: OSError: disk full"
    tool.refuse, tool.instead = None, ["tool.exe"]
    with pytest.raises(children.ChildError) as caught:
        tool.open(str(project))
    assert str(caught.value) == "Tool's launch is list, not a children.Launch"
    tool.instead = Launch(())
    with pytest.raises(children.ChildError, match="names no program"):
        tool.open(str(project))
    assert tool.out.popen.made == []


def test_a_launch_that_puts_the_key_on_its_command_line_is_refused(tool, project):
    installed(tool)
    chosen(tool)
    tool.on_command_line = True
    words = ("Tool would put llama.cpp / gpu's key on its command line, where every program here can read it: it is "
             "not started (its plugin hands a key over in the environment)")
    assert str(refusal(lambda: tool.open(str(project)))) == words
    assert str(refusal(lambda: tool.command(str(project)))) == words  # the placeholder there would be typed in too
    tool.out.interactive = lambda: False
    assert str(refusal(lambda: tool.open(str(project)))) == words
    assert tool.out.popen.made == []


def test_a_window_that_cannot_open_is_said(tool, project):
    installed(tool)
    chosen(tool)
    tool.out.popen.fails = OSError("[WinError 2] The system cannot find the file specified")
    with pytest.raises(children.ChildError) as caught:
        tool.open(str(project))
    assert str(caught.value) == ("Tool's window could not be opened: [WinError 2] The system cannot find the file "
                                 "specified")
    assert tool.use_kept().folder == "" and tool.running() == []  # nothing opened: nothing kept


def test_the_window_is_started_through_popen_looked_up_when_it_opens(tool, project, no_outside):
    installed(tool)
    chosen(tool)
    tool.out.popen = None  # the real one: the guard stands in for it, so it is looked up at the start
    with pytest.raises(Reached):
        tool.open(str(project))
    assert no_outside and no_outside[0].startswith("subprocess.Popen")
    no_outside.clear()  # (reached on purpose)


def test_a_key_that_cannot_be_read_is_said_before_a_window_opens(tool, project):
    installed(tool)
    chosen(tool)
    del tool.login.kept[KEY_VARIABLE]
    words = ("llama.cpp / gpu is asked with a key, and none could be read through your login: sign in, or keep its "
             "key again on llama.cpp's page")
    assert str(refusal(lambda: tool.open(str(project)))) == words
    tool.app.serving["llamacpp"]["instances"][0]["key"] = "not a variable"
    assert "is not the name of a pair" in str(refusal(lambda: tool.open(str(project))))
    assert tool.command(str(project))["ok"] is True  # the lines need no key: its placeholder is typed


# -- Command… ----------------------------------------------------------------------------------------------------------
def test_command_answers_the_lines_on_both_systems(tool, project):
    installed(tool)
    chosen(tool, folder=project)
    answer = tool.ask("command", None)  # the folder kept from the last Open…
    assert answer == {"said": RUN_IT, "ok": True, "lines": ps_lines(tool, project)}
    assert tool.out.popen.made == [] and tool.made[-1]["key"] == PLACEHOLDER  # nothing started, with a desktop too
    assert pair_name(KEY_VARIABLE) not in tool.login.read  # a read: the key is never read for it
    tool.out.system = "linux"
    assert tool.command(str(project))["lines"] == sh_lines(tool, project)
    other = project / "other"
    other.mkdir()
    tool.command(str(other))
    assert tool.use_kept().folder == str(project)  # a read keeps nothing
    assert len(tool.out.popen.made) == 0


def test_command_shows_a_stopped_servers_lines_and_refuses_the_rest(tool, project, monkeypatch):
    assert str(refusal(lambda: tool.command(str(project)))) == "Tool is not installed here: Install… first"
    installed(tool)
    assert str(refusal(lambda: tool.command(str(project)))) == CHOOSE
    chosen(tool, server="llamacpp/cpu", model="any.gguf")
    assert tool.command(str(project))["ok"] is True  # not running: the lines are for later
    assert "give the folder to open Tool in" in str(refusal(lambda: tool.command()))
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: True)
    assert str(refusal(lambda: tool.command(str(project)))) == (f"{project} is on another system's drive: open it from "
                                                                 "that system's platform")


def test_a_curly_quote_in_the_folder(tool, tmp_path):
    folder = tmp_path / "Ciara’s project ‘one’"
    folder.mkdir()
    installed(tool)
    chosen(tool)
    tool.open(str(folder))
    assert tool.out.popen.made[0]["cwd"] == str(folder)  # as it is: no shell reads it
    assert tool.use_kept().folder == str(folder)  # and kept as it is
    tool.out.interactive = lambda: False
    lines = tool.open(str(folder))["lines"]
    assert lines == ps_lines(tool, folder)
    place = lines[-2]
    assert place == "Set-Location -LiteralPath '" + str(folder).replace("’", "’’").replace("‘", "‘‘") + "'"
    tool.out.system = "linux"
    assert tool.command(str(folder))["lines"][-2] == f"cd {shlex.quote(str(folder))}"


# -- what reaches the tool ---------------------------------------------------------------------------------------------
def test_shown_lines_unset_what_drop_names_and_never_hold_a_secret(tool, project):
    installed(tool)
    chosen(tool)
    for system, unset in (("windows", "Remove-Item Env:{} -ErrorAction SilentlyContinue"), ("linux", "unset {}")):
        tool.out.system = system
        tool.marks_secret = system == "windows"  # a launch that forgets to name its key's variable secret, on Linux
        lines = tool.command(str(project))["lines"]
        for name in DROPPED:  # every one set here that the tool's drop, the registry or Liminal's own names
            assert unset.format(name) in lines, (system, name)
        assert unset.format("PATH") not in lines and unset.format("HOME") not in lines  # not dropped: left as it is
        for value in (KEY, "m-key-1", "o-key-1", "/data/platform"):
            assert not any(value in line for line in lines), (system, value)
        assert sum(PLACEHOLDER in line for line in lines) == 1
    launch = tool._launch(str(project), tool.use_kept(), tool.serving_of("llamacpp/gpu"), KEY)
    assert launch.secret == ("TOOL_SERVER_KEY",) and launch.cwd == str(project)  # the base names it when it forgot
    assert launch.drop == ("OPENAI_*", *DECLARED, "LIMINAL_*")


def test_the_lines_unset_a_pair_saved_since_the_platform_started_as_a_new_terminal_has_it(tool, project, monkeypatch):
    installed(tool)
    chosen(tool)
    tool.out.env = None  # the platform's own environment, as it runs
    # saved by another program (the charts, the login, tools/set-key.ps1) after the platform started: every new
    # terminal of the user's has it, this process has not; one name in two cases is unset once
    monkeypatch.setattr(authorization, "saved_variables", lambda: {"GROK_API_KEY": "g-key-1", "openai_api_key": "o"})
    monkeypatch.delenv("GROK_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "o-key-1")
    lines = tool.command(str(project))["lines"]
    assert "Remove-Item Env:GROK_API_KEY -ErrorAction SilentlyContinue" in lines
    assert sum(line.upper().startswith("REMOVE-ITEM ENV:OPENAI_API_KEY ") for line in lines) == 1
    assert not any(value in line for line in lines for value in ("g-key-1", "o-key-1"))
    tool.out.system = "linux"  # Linux keeps no saved variables of the user's: what this process has, alone
    assert "unset GROK_API_KEY" not in tool.command(str(project))["lines"]
    monkeypatch.setattr(authorization, "saved_variables", never("the user's saved variables (not Windows)"))
    tool.command(str(project))


def test_lines_powershell_would_not_hand_their_words_as_they_are_are_refused_in_words(tool, project):
    installed(tool)
    chosen(tool)
    for system in ("windows", "linux"):
        tool.out.system = system
        tool.out.interactive = lambda: False
        tool.instead = Launch((tool.program(), "--model", "openai/x", "--read", "C:\\my dir\\", "--no-auto-commits"))
        if system == "linux":  # sh's lines take every word as it is
            assert shlex.split(tool.command(str(project))["lines"][-1]) == list(tool.instead.argv)
            continue
        words = ("tool's command cannot be pasted into PowerShell as it is: its word 'C:\\\\my dir\\\\' would not "
                 "reach it as it is (it holds a space and ends in a backslash, which escapes the quote PowerShell 5.1 "
                 "closes it with)")
        assert str(refusal(lambda: tool.command(str(project)))) == words
        assert str(refusal(lambda: tool.open(str(project)))) == words  # without a desktop: the same lines
        tool.out.interactive = lambda: True
        assert tool.open(str(project))["ok"] is True  # with one, its words are handed over by Windows' own quoting
    # a model id a server lists with a double quote: refused at Use…, before it could reach a command
    tool.app.serving["llamacpp"]["instances"][0]["models"].append({"id": 'x" --yes-always "y'})
    assert '(")' in str(refusal(lambda: tool.use("llamacpp/gpu", 'x" --yes-always "y')))


def test_a_short_key_is_told_apart_from_a_folders_name_and_the_lines_stay_the_command(tool, tmp_path):
    installed(tool)
    chosen(tool)
    for key, folder in (("test", "my-test-app"), ("config", "app")):  # (keys.clean takes a key of any length)
        tool.login.kept[KEY_VARIABLE] = key
        project = tmp_path / folder
        project.mkdir()
        before = tool.command(str(project))["lines"]
        assert before == ps_lines(tool, project)
        assert tool.open(str(project))["ok"] is True and tool.made[-1]["key"] == key  # its letters are no key there
        assert tool.command(str(project))["lines"] == before  # the key read now: the lines are the command still
    # a secret read through the login that a launch slips into its command by itself: the placeholder in the lines,
    # as a whole word, after a word's "=", inside a word or a value when it is long enough to be told apart
    tool.login.kept[KEY_VARIABLE] = KEY
    tool.open(str(project))
    tool.instead = Launch((tool.program(), "--token", KEY, f"--key={KEY}", f"x{KEY}y", "--note", "configured"),
                          env={"A": KEY, "B": f"k:{KEY}", "C": "configured", "D": "config"})
    lines = tool.command(str(project))["lines"]
    assert not any(KEY in line for line in lines) and lines[-1].endswith(" '--note' 'configured'")
    assert f"$env:A = '{PLACEHOLDER}'" in lines and f"$env:B = 'k:{PLACEHOLDER}'" in lines
    assert "$env:C = 'configured'" in lines  # the short key "config" read before, inside other text: left
    assert f"$env:D = '{PLACEHOLDER}'" in lines  # and as a whole value: its placeholder
    assert f"'--token' '{PLACEHOLDER}' '--key={PLACEHOLDER}' 'x{PLACEHOLDER}y'" in lines[-1]
    assert harness.KEY_INSIDE == 16 and len(KEY) >= harness.KEY_INSIDE > len("config")


# -- Ask… --------------------------------------------------------------------------------------------------------------
def test_ask_models_asks_the_server_now_through_its_plugin(tool):
    tool.servers()
    assert tool.app.served() == ["ollama", "llamacpp", "vllm"]
    answer = tool.ask("ask_models", "llamacpp/gpu")
    assert ("llamacpp", "models_of", ["gpu"]) in tool.app.asked
    assert answer == {"said": "llama.cpp / gpu lists 2 models", "ok": True,
                      "lines": [f"{MODEL} · context 32,768 · calls tools", "tiny.gguf"], "models": [MODEL, "tiny.gguf"],
                      "asked": "2026-11-17T21:00:00Z"}
    tool.servers()
    assert tool.app.served() == ["ollama", "llamacpp", "vllm"] * 2  # what it serves read again after the ask
    tool.app.refusing["ollama"] = HookRefused(400, "ValueError: ...", "default is not answering")
    e = refusal(lambda: tool.ask_models("ollama/default"))
    assert str(e) == "ollama/default could not be asked for its models: default is not answering"
    tool.app.refusing = {}
    assert "could not be asked for its models: vllm offers no 'models_of'" in str(refusal(
        lambda: tool.ask_models("vllm/box")))
    tool.app.models["vllm"] = ["not", "an", "answer"]
    assert str(refusal(lambda: tool.ask_models("vllm/box"))) == "vllm/box's answer is not a list of models"
    assert "a model server is named <plugin>/<instance>" in str(refusal(lambda: tool.ask_models("vllm")))
    tool.app.models["vllm"] = {"ok": False, "said": "box did not answer within 3 s", "models": []}
    assert tool.ask_models("vllm/box") == {"said": "box did not answer within 3 s", "ok": False, "lines": [],
                                           "models": []}


# -- Main --------------------------------------------------------------------------------------------------------------
def test_main_draws_the_model_servers_and_asks_nothing_outside(tool):
    for what in ("transport", "opener", "streamer", "runner", "listening", "powershell", "shell"):
        setattr(tool.out, what, never(what))
    tool.out.popen = never("popen")
    status = tool.status()
    assert status["valid"] is True and status["uses"] == "nothing yet" and status["opens"] == OPENS[True]
    assert "opensIn" not in status and "problem" not in status
    assert [t["title"] for t in status["tables"]] == ["Before you use it", "Model servers"]  # its own first
    servers = table(status, "Model servers")
    assert [c["title"] for c in servers["columns"]] == ["Server", "Instance", "Address", "State", "Models", "", ""]
    assert [r[0]["text"] + " / " + r[1]["text"] for r in servers["rows"]] == [
        "Ollama / default", "llama.cpp / gpu", "llama.cpp / cpu", "vLLM / box"]
    gpu, cpu, box = servers["rows"][1], servers["rows"][2], servers["rows"][3]
    assert gpu[:5] == [{"text": "llama.cpp", "sub": "llamacpp"}, {"text": "gpu", "sub": "The GPU · runs here"},
                       {"text": HTTP + "127.0.0.1:9931", "sub": ""}, {"text": "running", "sub": ""},
                       {"text": MODEL, "sub": ""}]
    assert gpu[5] == {"form": "ai-use", "title": "Use…", "label": "Use llama.cpp / gpu",
                      "values": {"server": "llamacpp/gpu", "model": MODEL}}
    assert gpu[6] == {"form": "ai-models", "title": "Ask…", "label": "Ask llama.cpp / gpu for its models now",
                      "values": {"server": "llamacpp/gpu"}}
    assert cpu[3] == {"text": "stopped", "sub": "start it on llama.cpp's page"} and cpu[4]["text"] == "not listed yet"
    assert box[2]["sub"] == "plain http to another machine" and box[1]["sub"] == "on another machine"
    assert servers["rows"][0][4] == {"text": "qwen3:8b, llama3.2:3b", "sub": "listed 2026-11-17T20:00:00Z"}
    assert [f["id"] for f in status["forms"]] == ["ai-install", "ai-use", "ai-open", "ai-command", "ai-models"]
    assert [a.get("form") or a.get("hook") for a in status["actions"]] == [
        "refresh", "ai-install", "ai-use", "ai-open", "ai-command", "refresh"]  # the last: its own (main_more)
    assert button(status, "ai-open") == {"form": "ai-open", "title": "Open…", "disabled": True,
                                         "note": "Tool is not installed here: Install… first"}
    assert button(status, "ai-use") == {"form": "ai-use", "title": "Use…",
                                        "values": {"server": "ollama/default", "model": "qwen3:8b"}}
    use = form(status, "ai-use")
    assert [f["name"] for f in use["fields"]] == ["server", "model", "context", "commits"]
    assert [c["value"] for c in use["fields"][0]["choices"]] == ["ollama/default", "llamacpp/gpu", "llamacpp/cpu",
                                                                  "vllm/box"]
    assert use["fields"][0]["choices"][1] == {"value": "llamacpp/gpu", "title": "llama.cpp / gpu",
                                              "note": "running · runs here · " + HTTP + "127.0.0.1:9931"}
    assert use["fields"][3] == {"name": "commits", "label": "Commits", "type": "choice", "value": "no",
                                "choices": [{"value": "no", "title": "no", "note": ""},
                                            {"value": "yes", "title": "yes", "note": ""}]}
    assert use["confirm"] == {"title": "Use {server} with {model}?", "yes": "Use it",
                              "words": "From now on Tool is started against it: kept through your login, given at "
                                       "each start, nothing written into Tool's own configuration."}
    assert form(status, "ai-command")["confirm"] is False and form(status, "ai-models")["confirm"] is False
    assert form(status, "ai-models")["fields"] == [{"name": "server", "label": "Model server", "type": "fixed"}]
    assert tool.app.served() == ["ollama", "llamacpp", "vllm"]  # asked of their plugins through the platform alone
    assert tool.status() == status and tool.app.served() == ["ollama", "llamacpp", "vllm"]  # drawn again: kept


def test_main_once_installed_and_chosen(tool, project):
    installed(tool)
    chosen(tool, folder=project, context=32768)
    status = tool.status()
    assert status["uses"] == f"llama.cpp / gpu: {MODEL}" and status["opensIn"] == str(project)
    assert button(status, "ai-open") == {"form": "ai-open", "title": "Open…"}
    assert button(status, "ai-command") == {"form": "ai-command", "title": "Command…"}
    opening = form(status, "ai-open")
    assert opening["fields"][0]["value"] == str(project) and opening["fields"][0]["required"] is True
    assert opening["confirm"] == {"title": "Open Tool in {folder}?", "yes": "Open it",
                                  "words": "A terminal window opens there with Tool started against llama.cpp / gpu. "
                                           "Closing it ends it. Tool writes into the folder's files without asking."}
    assert form(status, "ai-use")["fields"][2]["value"] == 32768
    gpu = table(status, "Model servers")["rows"][1]
    assert gpu[1]["sub"] == "The GPU · runs here · in use"
    tool.out.interactive = lambda: False
    words = form(tool.status(), "ai-open")["confirm"]
    assert words["words"] == ("No window can be opened from here: the command is shown, to run in a terminal of yours. "
                              "Tool writes into the folder's files without asking.")
    assert words["yes"] == "Show the command"
    tool.before = "It asks before each edit."  # without its space: one is put before it
    assert form(tool.status(), "ai-open")["confirm"]["words"].endswith("yours. It asks before each edit.")
    chosen(tool, server="llamacpp/cpu", model="any.gguf")
    status = tool.status()
    assert button(status, "ai-open")["note"] == "llama.cpp / cpu is not running: start it on llama.cpp's page first"
    assert button(status, "ai-command") == {"form": "ai-command", "title": "Command…"}
    chosen(tool, server="llamacpp/gone")
    status = tool.status()
    assert status["uses"] == f"llamacpp/gone: {MODEL} (not offered now)"
    assert button(status, "ai-open")["note"] == button(status, "ai-command")["note"] == (
        "llamacpp/gone is not offered now: Use… chooses another")


def test_with_no_server_use_is_disabled_in_words(tool):
    tool.app.serving = {}
    status = tool.status()
    assert button(status, "ai-use") == {"form": "ai-use", "title": "Use…", "values": {}, "disabled": True,
                                        "note": harness.NO_SERVER}
    assert form(status, "ai-use")["fields"][0]["choices"] == [] and "value" not in form(status, "ai-use")["fields"][0]


def test_a_plugins_own_part_that_fails_is_a_problem_said(tool):
    tool.more = RuntimeError("its notes could not be read")
    status = tool.status()
    assert status["valid"] is True and status["problem"] == ("part of Tool's page could not be drawn: RuntimeError: "
                                                             "its notes could not be read")
    assert [t["title"] for t in status["tables"]] == ["Model servers"]
    tool.more = ["not", "a", "dict"]
    assert tool.status()["problem"] == "part of Tool's page could not be drawn: main_more answered list"
    tool.more = {}
    chosen(tool)
    tool.before = KeyError("words")
    status = tool.status()
    assert status["problem"] == "what Tool says before it starts could not be read: KeyError: 'words'"
    assert form(status, "ai-open")["confirm"]["words"].endswith("Closing it ends it.")
    tool.before = ""
    installed(tool)
    tool.fits = lambda at: (_ for _ in ()).throw(RuntimeError("no word for " + at["server"]))
    status = tool.status()
    gpu = table(status, "Model servers")["rows"][1][5]
    assert gpu["disabled"] is True and gpu["note"] == ("whether Tool can use llama.cpp / gpu could not be told: "
                                                       "RuntimeError: no word for llamacpp/gpu")
    assert button(status, "ai-open")["note"] == gpu["note"] and "problem" not in status
    tool.app.plugins = lambda: (_ for _ in ()).throw(RuntimeError("its registry is being read"))
    tool.refresh()
    status = tool.status()  # never raises (a status that raised would take the plugin off the page)
    assert status["valid"] is True and Harness.status.steady and table(status, "Model servers")["rows"] == []
    assert "the platform could not list its plugins: RuntimeError: its registry is being read." in table(
        status, "Model servers")["note"]


def test_refresh_reads_what_the_servers_serve_again(tool):
    tool.servers()
    tool.refresh()
    tool.servers()
    assert tool.app.served() == ["ollama", "llamacpp", "vllm"] * 2


def test_a_library_too_old_refuses_every_hook(tool, project, monkeypatch):
    installed(tool)
    chosen(tool)
    monkeypatch.setattr(liminal_libs, "__version__", "1.61.2")
    words = "Tool needs liminal-libs 1.62.0 or newer, and this is 1.61.2: update the library"
    for hook, args in (("use", ("llamacpp/gpu", MODEL)), ("open", (str(project),)), ("command", ()),
                       ("ask_models", ("llamacpp/gpu",))):
        assert str(refusal(lambda: tool.ask(hook, *args))) == words
        assert str(refusal(lambda: getattr(tool, hook)(*args))) == words
    status = tool.status()
    assert status["valid"] is False and status["forms"] == [] and "uses" not in status
    assert tool.app.asked == [] and tool.out.popen.made == []


# -- no key in any answer ----------------------------------------------------------------------------------------------
def test_no_key_in_any_answer(tool, project):
    installed(tool)
    answers = [tool.status(), tool.use("llamacpp/gpu", MODEL)]
    answers += [tool.open(str(project)), tool.status(), tool.command(str(project)), tool.ask_models("llamacpp/gpu")]
    tool.out.interactive = lambda: False
    answers += [tool.open(str(project)), tool.status()]
    tool.app.refusing["vllm"] = HookRefused(400, "ValueError", f"the key {KEY} was refused")  # once read, never said
    answers += [tool.refresh(), tool.status()]
    note = table(answers[-1], "Model servers")["note"]
    assert "vllm did not say what it serves: the key <hidden> was refused." in note
    tool.refuse = ValueError(f"no access with {KEY}")
    tool.out.interactive = lambda: True
    answers.append({"refused": str(refusal(lambda: tool.open(str(project))))})
    for answer in answers:
        assert KEY not in json.dumps(answer, ensure_ascii=False), answer
    assert tool.out.popen.made[0]["env"]["TOOL_SERVER_KEY"] == KEY  # (where it is meant to be: the tool's own)


# -- the pieces --------------------------------------------------------------------------------------------------------
def test_the_bases_fits_wants_an_openai_compatible_address(tool):
    at = tool.serving_of("ollama/default")
    assert Harness.fits(tool, at) == ""
    assert Harness.fits(tool, {**at, "openai": " "}) == ("Tool needs an OpenAI-compatible address, and Ollama / "
                                                          "default gives none")
    assert Harness.open_words(tool, None, at) == "" and Harness.main_more(tool) == {}
    with pytest.raises(NotImplementedError, match="Tool says nothing of how it is started"):
        Harness.launch(tool, "C:\\x", Use("a/b", "m"), at)


def test_names_and_ids():
    assert split_server(" ollama/default ") == ("ollama", "default")
    for bad in ("", None, "ollama", "Ollama/default", "ollama/default/x", "/default", "ollama/", "ollama/a b",
                "ollama/" + "x" * 33):
        with pytest.raises(instances.Refusal):
            split_server(bad)
    assert clean_model("  qwen3:8b ") == "qwen3:8b" and clean_model("hf.co/x/y:Q4_K_M") == "hf.co/x/y:Q4_K_M"
    for bad in ("", None, "a\tb", "x" * 257, 'openai/x"y'):  # (a double quote: children.not_passed)
        with pytest.raises(instances.Refusal):
            clean_model(bad)
    assert clean_model("a “quoted” 'one'") == "a “quoted” 'one'"  # PowerShell passes these on
    assert model_ids({"models": [{"id": "a"}, "b", {"id": "a"}, {"id": ""}, 3, {"name": "c"}]}) == ["a", "b"]
    assert server_words({"plugin": "ollama", "name": "default"}) == "ollama / default"
    assert Use(" a/b ", " m ", None, None) == Use("a/b", "m", "", {})


def test_the_module_and_its_test_name_no_host():
    written = re.compile(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]")
    for path in (Path(harness.__file__), Path(__file__)):
        found = [line for line in path.read_text(encoding="utf-8").splitlines() if written.search(line)]
        assert found == [], path.name
