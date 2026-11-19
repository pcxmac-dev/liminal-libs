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

1.66.0: a window on Linux (a display and a terminal; neither; a boot service; shutil.which alone, and nothing started
by a status; each terminal handed the command word by word, as its manual says; x-terminal-emulator only through a
link to a known terminal; the display's variables kept). Liminal's MCP (off; on, with an offer; the MCP plugin absent
or refusing; the wire chosen; a launch token for each Open… that opens a window and none for Command… or the lines;
the token ended once its window is gone, or at once when the start goes no further; the token in no argument, file,
answer or line). Values a harness would read as more than text (${, $(, {env:, {file:, ${{, a leading !) refused.

Nothing is installed, downloaded, started or asked over the network here: stand-ins answer for the login, the platform,
the window's process and the clock, and the shared guard (conftest.py) fails a test that starts a process or opens a
connection."""
from __future__ import annotations

import copy
import json
import re
import shlex
import subprocess
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


# -- a window on Linux (1.66.0) ----------------------------------------------------------------------------------------
DESKTOP = {"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000",
           "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}  # as WSLg sets them
# each terminal's words before the command, as its own manual gives them (read 2026-11-19); {folder}: the folder
MANUALS = {
    "gnome-terminal": ["--wait", "--working-directory={folder}", "--"],
    "ptyxis": ["-d", "{folder}", "--"],
    "xfce4-terminal": ["--disable-server", "--working-directory={folder}", "-x"],
    "konsole": ["--separate", "--workdir", "{folder}", "-e"],
    "kitty": ["--directory", "{folder}"],
    "alacritty": ["--working-directory", "{folder}", "-e"],
    "foot": ["--working-directory={folder}"],
    "xterm": ["-e"],
}


class Which:
    """shutil.which as a stand-in: the programs on PATH, each look noted (a look at files: never a process)."""

    def __init__(self, found: dict):
        self.found, self.looked = dict(found), []

    def __call__(self, name, mode=None, path=None):
        self.looked.append((name, path))
        return self.found.get(name)


@pytest.fixture
def linux(tool, monkeypatch):
    """The stand-in harness on Linux, with a display (as WSLg gives one) and xterm on the platform's PATH; no link is
    read for real. A Linux machine of its own unless a test says it is WSL: whether this machine is WSL is never read
    (inside WSL the words would differ)."""
    tool.out.system = "linux"
    tool.out.wsl = ""
    tool.out.env = {**ENV, **DESKTOP}
    tool.out.interactive = never("whether a window can be shown (not Windows)")
    tool.out.which = Which({"xterm": "/usr/bin/xterm"})
    monkeypatch.setattr(harness, "_link_target", never("a link read (no x-terminal-emulator here)"))
    monkeypatch.setattr(ai.linux, "wsl", never("whether this machine is WSL, read for real"))
    return tool


def argv_of(p: Tool) -> list[str]:
    return [p.program(), "--model", MODEL, "--base", HTTP + "127.0.0.1:9931/v1"]


def test_on_linux_a_display_and_a_terminal_open_a_window(linux, project):
    installed(linux)
    chosen(linux)
    answer = linux.open(str(project))
    made = linux.out.popen.made[0]
    assert made["argv"] == ["/usr/bin/xterm", "-e", *console.hold_command(argv_of(linux))]
    assert made["start_new_session"] is True and "creationflags" not in made and made["cwd"] == str(project)
    assert (made["stdin"], made["stdout"], made["stderr"]) == (subprocess.DEVNULL,) * 3
    assert made["env"] == {"PATH": "/usr/bin", "HOME": "/home/someone", **DESKTOP,
                           "TOOL_CONFIG_DIR": str(linux.home / "config"), "TOOL_SERVER_KEY": KEY}
    assert answer == {"said": f"Tool opened in a window of its own in {project}, started against llama.cpp / gpu with "
                              f"{MODEL}", "ok": True,
                      "lines": ["its window's process: 4321", "closing the window ends it"]}
    assert linux.running() == [f"the window open in {project}"] and linux.use_kept().folder == str(project)
    status = linux.status()
    assert status["opens"] == "in a terminal window of its own (xterm), in the folder you give"
    words = form(status, "ai-open")["confirm"]["words"]
    assert words.startswith("A terminal window (xterm) opens there with Tool started against llama.cpp / gpu. Closing")
    linux.out.wsl = "Ubuntu"  # under WSLg the window shows on Windows' desktop, and the words say so
    status = linux.status()
    assert status["opens"] == ("in a terminal window of its own (xterm), on Windows' desktop (WSLg), in the folder "
                               "you give")
    words = form(status, "ai-open")["confirm"]["words"]
    assert "It opens on Windows' desktop, through WSLg. Closing it ends it." in words
    linux.out.popen.windows[0].code = 0  # closed
    assert linux.running() == []


def test_on_linux_the_terminal_keeps_the_displays_variables_whatever_the_launch_drops(linux, project):
    installed(linux)
    chosen(linux)
    linux.instead = Launch(argv_of(linux), env={"TOOL_CONFIG_DIR": "c", "DISPLAY": ":1"}, drop=("*",))
    linux.open(str(project))
    env = linux.out.popen.made[0]["env"]
    assert env == {"TOOL_CONFIG_DIR": "c", "DISPLAY": ":1", "WAYLAND_DISPLAY": "wayland-0",
                   "XDG_RUNTIME_DIR": "/run/user/1000", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
    assert harness.DESKTOP_KEEPS == ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")


def test_on_linux_without_a_display_or_a_terminal_the_lines_are_shown(linux, project):
    installed(linux)
    chosen(linux)
    linux.out.env = dict(ENV)  # no display: nothing is looked for
    linux.out.which = never("a program looked for without a display")
    assert linux.open(str(project)) == {"said": RUN_IT, "ok": True, "lines": sh_lines(linux, project)}
    assert linux.status()["opens"] == OPENS[False]
    # a boot service: its session's folder and its unit's mark, and no display: no window, xterm or not
    linux.out.env = {**ENV, "XDG_RUNTIME_DIR": "/run/user/1000", "INVOCATION_ID": "0123abcd"}
    assert linux.open(str(project))["said"] == RUN_IT and linux.status()["opens"] == OPENS[False]
    # a display, and no terminal program installed (the user's Ubuntu, likely): the lines, and what to install
    linux.out.env = {**ENV, **DESKTOP}
    linux.out.which = Which({})
    assert linux.open(str(project))["lines"] == sh_lines(linux, project)
    status = linux.status()
    names = ", ".join(MANUALS)
    missing = (f"no terminal program to open a window with is installed here ({names}): installing one, such as xterm, "
               "is a step for root")
    assert status["opens"] == f"{OPENS[False]} ({missing})"
    words = form(status, "ai-open")["confirm"]["words"]
    assert f"the command is shown, to run in a terminal of yours. N{missing[1:]}." in words
    assert linux.out.popen.made == []


def test_a_linux_status_looks_at_files_alone_and_starts_nothing(linux):
    for what in ("transport", "opener", "streamer", "runner", "listening", "powershell", "shell"):
        setattr(linux.out, what, never(what))
    linux.out.popen = never("popen")
    status = linux.status()
    assert status["valid"] is True and status["opens"].endswith("(xterm), in the folder you give")
    # x-terminal-emulator first, then each terminal in its order until one is found: all on the platform's PATH
    assert linux.out.which.looked == [(name, "/usr/bin") for name in ("x-terminal-emulator", *MANUALS)]
    linux.out.which = Which({"x-terminal-emulator": None, "gnome-terminal": "/usr/bin/gnome-terminal"})
    linux.status()
    assert linux.out.which.looked == [("x-terminal-emulator", "/usr/bin"), ("gnome-terminal", "/usr/bin")]


def test_a_terminal_is_looked_for_in_linuxs_own_folders_alone(linux, monkeypatch):
    """WSL puts Windows' own folders on Linux's PATH (on its drives, under /mnt): no Linux terminal is there, and each
    look in one crosses to Windows (about 170 ms a status for 38 of them, measured in the user's Ubuntu). So a status
    looks in this system's own folders alone."""
    linux.out.env = {**ENV, **DESKTOP,
                     "PATH": "/usr/local/bin:/mnt/c/WINDOWS/system32:/usr/bin:/mnt/c/Program Files/Git/cmd:/bin"}
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: str(path).startswith("/mnt/"))
    assert linux.status()["opens"].endswith("(xterm), in the folder you give")
    assert {path for _, path in linux.out.which.looked} == {"/usr/local/bin:/usr/bin:/bin"}
    linux.out.env = {**ENV, **DESKTOP, "PATH": "/mnt/c/WINDOWS/system32"}  # none of its own: nothing is looked for
    linux.out.which = Which({"xterm": "/mnt/c/WINDOWS/system32/xterm"})
    assert linux.status()["opens"].startswith(OPENS[False]) and linux.out.which.looked == []


def test_each_terminal_is_handed_the_command_word_by_word(linux, tmp_path):
    folder = tmp_path / "my project; $(rm -rf ~)"
    folder.mkdir()
    installed(linux)
    chosen(linux)
    assert [t.name for t in harness.TERMINALS] == list(MANUALS) and set(harness.BY_NAME) == set(MANUALS)
    words = [linux.program(), "--model", "qwen3 8b; reboot", "--note", "$HOME `id` 'one' \"two\"", "--empty", ""]
    linux.instead = Launch(words)
    for name, before in MANUALS.items():
        linux.out.which = Which({name: f"/usr/bin/{name}"})
        linux.open(str(folder))
        made = linux.out.popen.made[-1]
        expected = [f"/usr/bin/{name}", *(word.format(folder=str(folder)) for word in before)]
        assert made["argv"] == [*expected, *console.hold_command(words)], name  # each word a word of its own
        assert made["cwd"] == str(folder)
    assert len(linux.out.popen.made) == len(MANUALS)


def test_x_terminal_emulator_is_used_only_through_a_link_to_a_known_terminal(linux, project, monkeypatch):
    installed(linux)
    chosen(linux)
    linux.out.which = Which({"x-terminal-emulator": "/usr/bin/x-terminal-emulator",
                             "gnome-terminal": "/usr/bin/gnome-terminal", "kitty": "/usr/bin/kitty"})
    links = {"/usr/bin/x-terminal-emulator": "/usr/bin/kitty"}  # its user chose kitty (update-alternatives)
    monkeypatch.setattr(harness, "_link_target", lambda path: links[str(path)])
    linux.open(str(project))
    assert linux.out.popen.made[-1]["argv"][:3] == ["/usr/bin/kitty", "--directory", str(project)]
    assert "(kitty)" in linux.status()["opens"]
    for target in ("/usr/bin/gnome-terminal.wrapper", "/usr/bin/lxterm", "/usr/bin/x-terminal-emulator"):
        links["/usr/bin/x-terminal-emulator"] = target  # a wrapper or another program: its flags are not known
        linux.open(str(project))
        assert linux.out.popen.made[-1]["argv"][:2] == ["/usr/bin/gnome-terminal", "--wait"], target

    def unreadable(path):
        raise OSError("a loop of links")
    monkeypatch.setattr(harness, "_link_target", unreadable)
    linux.open(str(project))
    assert linux.out.popen.made[-1]["argv"][0] == "/usr/bin/gnome-terminal"


def test_a_linux_window_that_cannot_open_is_said(linux, project):
    installed(linux)
    chosen(linux)
    linux.out.popen.fails = FileNotFoundError(2, "No such file or directory", "/usr/bin/xterm")
    with pytest.raises(children.ChildError) as caught:
        linux.open(str(project))
    assert str(caught.value) == ("Tool's window could not be opened: [Errno 2] No such file or directory: "
                                 "'/usr/bin/xterm'")
    assert linux.use_kept().folder == "" and linux.running() == []


# -- Liminal's MCP (1.66.0) --------------------------------------------------------------------------------------------
BRIDGE = ["C:\\Python\\python.exe", "-I", "-S", "C:\\plugins\\plugin-platform-mcp\\bridge.py", "--port", "8775"]
ENDPOINT = HTTP + "127.0.0.1:8775/api/machines/mcp/rpc"
TOKEN_VARIABLE = "LIMINAL_MCP_TOKEN"


class McpApp(App):
    """The platform with the MCP plugin attached beside the model servers: what it offers (its plugin's offer, and the
    variable, hold and agent the protocol base adds: machines/protocol.py's client_offer), the tokens it minted and
    those it was asked to end. Every ask is noted, as App's."""

    def __init__(self):
        super().__init__()
        self.offer: object = {"wires": ["stdio", "http"], "bridge": list(BRIDGE), "endpoint": ENDPOINT,
                              "headers": {"X-Liminal-Charts": "1"},
                              "revisions": ["2026-07-28", "2025-11-25", "2025-06-18"],
                              "variable": TOKEN_VARIABLE, "hold_s": 50, "agent": "tool"}
        self.minted: list[str] = []
        self.ended: list[str] = []
        self.mcp_refusing: dict[str, BaseException] = {}  # by hook

    def plugins(self) -> dict:
        faces = super().plugins()
        faces["mcp"] = {"name": "mcp", "hooks": {"present": "()", "status": "()", "client_offer": "()",
                                                 "ensure_client": "(title)", "launch_token": "()",
                                                 "end_launch": "(token)"}}
        return faces

    def ask(self, name: str, hook: str, args: list):
        if name != "mcp":
            return super().ask(name, hook, args)
        self.asked.append((name, hook, list(args)))
        if hook in self.mcp_refusing:
            raise self.mcp_refusing[hook]
        if hook == "client_offer":
            return copy.deepcopy(self.offer)
        if hook == "ensure_client":
            return {"said": f"{args[0]}'s agent tool is kept, granted nothing yet", "ok": True, "agent": "tool"}
        if hook == "launch_token":
            self.minted.append(f"launch{len(self.minted):02d}-" + "Ab9_" * 10)
            return {"token": self.minted[-1], "agent": "tool", "variable": TOKEN_VARIABLE, "hold_s": 50}
        if hook == "end_launch":
            self.ended.append(args[0])
            return {"ok": True}
        raise LookupError(f"mcp offers no {hook!r}")

    def mcp_asks(self) -> list[tuple[str, list]]:
        return [(hook, args) for name, hook, args in self.asked if name == "mcp"]


class Wired(Tool):
    """A stand-in harness wired to Liminal's MCP by the bridge: its launch asks `mcp_wiring` and writes the MCP part
    of its configuration into a file of its folder, naming the token's variable and never the token. What it does
    wrong is the test's to set."""

    OPTIONS = (*Tool.OPTIONS, harness.MCP_OPTION)
    MCP_WIRES = ("stdio",)
    ASKS = (*Harness.ASKS, *harness.MCP_ASKS)
    INTERNAL_NOTES = (*Harness.INTERNAL_NOTES, *harness.MCP_NOTES)

    def __init__(self, outside=None):
        super().__init__(outside)
        self.wirings: list = []
        self.slip = ""  # where its launch puts the token by mistake: "argv", "env"; "own": in its variable itself
        self.leaves_out = False  # it forgets Liminal's MCP
        self.after: BaseException | None = None  # what it raises once the wiring is asked

    def config(self) -> Path:
        return self.home / "config" / "mcp.json"

    def launch(self, folder, use, at, key=""):
        made = super().launch(folder, use, at, key)
        if self.leaves_out or not isinstance(made, Launch):
            return made
        wiring = self.mcp_wiring(use)
        self.wirings.append(wiring)
        if self.after is not None:
            raise self.after
        if wiring is None:
            return made
        self.config().parent.mkdir(parents=True, exist_ok=True)
        part = {"command": list(wiring.argv), "url": wiring.url, "headers": dict(wiring.headers),
                "env": {wiring.token_variable: "${" + wiring.token_variable + "}"}, "timeout": wiring.timeout_s}
        self.config().write_text(json.dumps(part), encoding="utf-8")
        argv, env = list(made.argv), {**made.env, "TOOL_MCP_CONFIG": str(self.config())}
        if wiring.token and self.slip == "argv":
            argv += ["--mcp-token", wiring.token]
        if wiring.token and self.slip == "env":
            env["TOOL_MCP_HEADERS"] = "Authorization: Bearer " + wiring.token
        if self.slip == "own":
            env[wiring.token_variable] = wiring.token  # (as a plugin may write it; "" for the lines)
        return Launch(argv, env=env, drop=made.drop, secret=made.secret)


@pytest.fixture
def wired(tmp_path):
    out = Outside(env=dict(ENV), system="windows", home=tmp_path / "tool", clock=Clock(), interactive=lambda: True,
                  popen=Popen(), variables=lambda: DECLARED)
    p = Wired(out)
    p.attach(McpApp(), Pairs())
    p.login.kept[KEY_VARIABLE] = KEY
    installed(p)
    return p


def test_a_harness_that_declares_nothing_asks_nothing_of_liminals_mcp(tool, project):
    installed(tool)
    on = Use("llamacpp/gpu", MODEL, "", {"mcp": "on"})  # (a choice that says on, as a plugin's own code may make one)
    assert Harness.MCP_WIRES == () and harness.MCP_OPTION not in Tool.OPTIONS and not tool.mcp_on(on)
    assert tool.mcp_wiring(on) is None
    tool.use("llamacpp/gpu", MODEL, None, "no")
    chosen(tool, mcp="on")  # a value kept for an option it does not have is dropped
    assert tool.use_kept().options == {} and tool.mcp_wiring() is None
    tool.open(str(project))
    tool.command(str(project))
    assert [name for name, _, _ in tool.app.asked if name == "mcp"] == []
    assert harness.MCP_VARIABLE not in tool.out.popen.made[0]["env"] and tool.ASKS == Harness.ASKS


def test_liminals_mcp_is_off_unless_use_turns_it_on(wired, project):
    field = form(wired.status(), "ai-use")["fields"][-1]
    assert field == {"name": "mcp", "label": "Liminal's MCP", "type": "choice", "value": "off",
                     "note": harness.MCP_OPTION.note,
                     "choices": [{"value": "off", "title": "off", "note": "it reaches no MCP server of Liminal's"},
                                 {"value": "on", "title": "on", "note": "it reaches Liminal's MCP plugin, which "
                                                                        "decides what it may list and call"}]}
    for value in (None, "off"):
        answer = wired.use("llamacpp/gpu", MODEL, None, None, value)
        assert answer["lines"] == ["kept in the test's pairs"]
    wired.open(str(project))
    wired.command(str(project))
    assert wired.app.mcp_asks() == [] and wired.wirings == [None, None]
    assert TOKEN_VARIABLE not in wired.out.popen.made[0]["env"] and not wired.config().exists()


def test_use_turning_it_on_asks_how_it_is_reached_and_for_its_agent_before_anything_is_kept(wired):
    saved_before: list = []
    real_ask = wired.app.ask

    def ask(name, hook, args):
        saved_before.append((hook, len(wired.login.saved)))
        return real_ask(name, hook, args)
    wired.app.ask = ask
    answer = wired.use("llamacpp/gpu", MODEL, None, None, "on")
    assert wired.app.mcp_asks() == [("client_offer", []), ("ensure_client", ["Tool"])]
    assert [n for hook, n in saved_before if hook in ("client_offer", "ensure_client")] == [0, 0]  # asked first
    assert answer["lines"] == [
        "kept in the test's pairs", "Liminal's MCP: Tool's agent tool is kept, granted nothing yet",
        "each window it opens reaches it by the MCP plugin's bridge (stdio), with a token of its own"]
    assert wired.use_kept().options == {"mcp": "on"} and wired.app.minted == []  # no token at Use…


def test_each_open_asks_a_token_for_its_window_alone_and_command_none(wired, project):
    chosen(wired, mcp="on")
    answer = wired.open(str(project))
    assert wired.app.mcp_asks() == [("client_offer", []), ("launch_token", [])]
    token = wired.app.minted[0]
    made = wired.out.popen.made[0]
    assert made["env"][TOKEN_VARIABLE] == token and made["env"]["TOOL_SERVER_KEY"] == KEY  # its variable alone
    assert not any(token in word for word in made["argv"]) and token not in made["cwd"]
    assert sum(token in value for value in made["env"].values()) == 1
    written = wired.config().read_text("utf-8")
    assert token not in written and "${LIMINAL_MCP_TOKEN}" in written  # the file names its variable, never the token
    wiring = wired.wirings[0]
    assert wiring.token == token and wiring.wire == "stdio" and wiring.argv == tuple(BRIDGE) and wiring.url == ""
    assert wiring.token_variable == TOKEN_VARIABLE and wiring.timeout_s == 110 and token not in repr(wiring)
    assert answer["lines"] == ["its window's process: 4321", "closing the window ends it",
                               "Liminal's MCP: the window has a token of its own, ended once it is gone"]
    assert token not in json.dumps(answer)
    wired.open(str(project))  # each Open… its own
    assert len(wired.app.minted) == 2 and wired.out.popen.made[1]["env"][TOKEN_VARIABLE] == wired.app.minted[1]
    lines = wired.command(str(project))  # Command…: no token is asked, and its words say where one is given
    assert len(wired.app.minted) == 2
    assert lines["said"] == f"{RUN_IT} ({harness.MCP_LINES.format(variable=TOKEN_VARIABLE)})"
    assert not any(TOKEN_VARIABLE in line for line in lines["lines"]) and wired.wirings[-1].token == ""
    wired.out.interactive = lambda: False  # Open… without a desktop: the lines, and no token either
    shown = wired.open(str(project))
    assert len(wired.app.minted) == 2 and shown["said"] == lines["said"] and shown["lines"] == lines["lines"]
    for minted in wired.app.minted:
        assert not any(minted in line for line in [*lines["lines"], *shown["lines"]])


def test_a_launch_that_writes_its_variable_itself_is_taken_as_it_is_and_an_empty_one_is_dropped(wired, project):
    chosen(wired, mcp="on")
    wired.slip = "own"
    wired.open(str(project))
    assert wired.out.popen.made[0]["env"][TOKEN_VARIABLE] == wired.app.minted[0]
    lines = wired.command(str(project))["lines"]
    assert not any(TOKEN_VARIABLE in line for line in lines)  # its "" is not written, and nothing unsets yours


def test_a_windows_token_is_ended_once_the_window_is_gone(wired, project):
    chosen(wired, mcp="on")
    wired.open(str(project))
    wired.open(str(project))
    first, second = wired.app.minted
    wired.status()
    assert wired.app.ended == []  # both open
    wired.out.popen.windows[0].code = 0
    wired.status()  # seen at a status
    assert wired.app.ended == [first]
    wired.out.popen.windows[1].code = 1
    wired.app_stopping()  # or at the platform's stop
    assert wired.app.ended == [first, second]
    wired.status()
    wired.app_stopping()
    assert wired.app.ended == [first, second]  # each once


def test_a_window_no_longer_followed_still_has_its_token_ended_once_it_is_gone(wired, project):
    """Past WINDOWS_KEPT windows the oldest is no longer followed for Install and Uninstall, but its token still is:
    a token outlives no window."""
    chosen(wired, mcp="on")
    for _ in range(harness.WINDOWS_KEPT + 1):
        wired.open(str(project))
    assert len(wired.running()) == harness.WINDOWS_KEPT and wired.app.ended == []
    wired.out.popen.windows[0].code = 0  # the first window, no longer among those followed, is closed
    wired.status()
    assert wired.app.ended == [wired.app.minted[0]]


def test_past_tokens_kept_the_oldest_windows_token_is_ended_at_once(wired, project, monkeypatch):
    monkeypatch.setattr(harness, "TOKENS_KEPT", 2)
    chosen(wired, mcp="on")
    for _ in range(3):
        wired.open(str(project))
    assert wired.app.ended == [wired.app.minted[0]]  # its window still open: its token ended all the same
    for window in wired.out.popen.windows:
        window.code = 0
    wired.status()
    assert wired.app.ended == wired.app.minted  # each once


def test_the_windows_followed_are_each_its_process_and_its_folder(tool, project):
    """What a harness follows of each window it opened is its process and its folder, as before Liminal's MCP: a
    plugin's own tests read it so (plugin-platform-continue 0.1.0's test_install)."""
    installed(tool)
    chosen(tool)
    tool.open(str(project))
    assert tool._rt.windows == [(tool.out.popen.windows[0], str(project))]
    for child, folder in tool._rt.windows:
        assert child.poll() is None and folder == str(project)


def test_a_token_goes_at_once_when_its_start_goes_no_further(wired, project):
    chosen(wired, mcp="on")
    wired.out.popen.fails = OSError("[WinError 2] The system cannot find the file specified")
    with pytest.raises(children.ChildError, match="window could not be opened"):
        wired.open(str(project))
    assert wired.app.ended == wired.app.minted and len(wired.app.minted) == 1
    wired.out.popen.fails = None
    wired.slip = "argv"
    words = ("Tool would put its token for Liminal's MCP on its command line, where every program here can read it: "
             "it is not started")
    assert str(refusal(lambda: wired.open(str(project)))) == words
    wired.slip = "env"
    assert str(refusal(lambda: wired.open(str(project)))) == ("Tool would hand its token for Liminal's MCP over in "
                                                               "TOOL_MCP_HEADERS, and only LIMINAL_MCP_TOKEN carries "
                                                               "it: it is not started")
    wired.slip, wired.after = "", ValueError("its configuration could not be written")
    assert str(refusal(lambda: wired.open(str(project)))) == "its configuration could not be written"
    assert wired.app.ended == wired.app.minted and len(wired.app.minted) == 4 and wired.out.popen.made == []
    assert wired.running() == []


def test_mcp_on_with_its_plugin_absent_or_refusing_is_refused_in_words(wired, project):
    lead = "Liminal's MCP is on for Tool (Use…), and the MCP plugin "
    tail = ". Nothing was started: turn the MCP plugin on (AI plugins, Protocols), or turn Liminal's MCP off under Use…"
    wired.app.mcp_refusing["client_offer"] = LookupError("no plugin 'mcp' is attached to platform")
    e = refusal(lambda: wired.use("llamacpp/gpu", MODEL, None, None, "on"))
    assert str(e) == f"{lead}did not say how it is reached: no plugin 'mcp' is attached to platform{tail}"
    assert wired.variable("use") not in wired.login.kept  # nothing kept
    chosen(wired, mcp="on")  # kept from before: Open… and Command… are refused the same way
    for call in (lambda: wired.open(str(project)), lambda: wired.command(str(project))):
        assert str(refusal(call)) == str(e)
    wired.app.mcp_refusing = {"ensure_client": HookRefused(400, "ValueError", "16 agents at most")}
    assert str(refusal(lambda: wired.use("llamacpp/gpu", MODEL, None, None, "on"))) == (
        f"{lead}did not make Tool's agent: 16 agents at most{tail}")
    wired.app.mcp_refusing = {"launch_token": HookRefused(400, "ValueError", "32 tokens at most")}
    assert str(refusal(lambda: wired.open(str(project)))) == (
        f"{lead}gave no token for the window: 32 tokens at most{tail}")
    wired.app.mcp_refusing = {}
    wired.app.offer = ["not", "an", "offer"]
    assert str(refusal(lambda: wired.open(str(project)))) == (
        f"{lead}answered something that is not how it is reached{tail}")
    wired.app.offer = {"wires": ["http"], "endpoint": ENDPOINT, "headers": {}}  # the route alone, no bridge
    assert str(refusal(lambda: wired.open(str(project)))) == (
        f"{lead}serves the MCP plugin's address on the platform (HTTP) here, and Tool reaches it by the MCP plugin's "
        f"bridge (stdio) alone{tail}")
    wired.app.offer = {"wires": ["stdio"], "bridge": list(BRIDGE), "variable": "OPENAI_API_KEY"}  # not Liminal's
    assert "answered something that is not how it is reached" in str(refusal(lambda: wired.open(str(project))))
    wired.app.offer = {"problem": "its bridge is not found", "variable": TOKEN_VARIABLE, "hold_s": 50, "agent": ""}
    assert str(refusal(lambda: wired.open(str(project)))) == (
        f"{lead}could not say how it is reached: its bridge is not found{tail}")  # (the protocol base's own words)
    wired.app.offer = McpApp().offer
    real_ask = wired.app.ask
    wired.app.ask = lambda name, hook, args: "short" if hook == "launch_token" else real_ask(name, hook, args)
    assert str(refusal(lambda: wired.open(str(project)))) == (
        f"{lead}gave nothing that can be a token for the window{tail}")
    assert wired.out.popen.made == []
    alone = Wired(Outside(env={}, system="windows", home=wired.home, variables=lambda: ()))
    alone.login = Pairs()
    assert str(refusal(lambda: alone.mcp_wiring(Use("llamacpp/gpu", MODEL, "", {"mcp": "on"})))) == (
        f"{lead}cannot be asked: this plugin is not attached to the platform{tail}")


def test_the_wire_is_the_first_of_its_own_the_mcp_plugin_serves(wired, project):
    chosen(wired, mcp="on")
    wired.MCP_WIRES = ("http", "stdio")  # (as Codex CLI: the route where it is served, the bridge otherwise)
    wired.command(str(project))
    wiring = wired.wirings[-1]
    assert (wiring.wire, wiring.url, wiring.headers, wiring.argv) == ("http", ENDPOINT, {"X-Liminal-Charts": "1"}, ())
    assert wiring.revisions == ("2026-07-28", "2025-11-25", "2025-06-18") and wiring.hold_s == 50
    wired.app.offer = {**wired.app.offer, "wires": ["stdio"], "hold_s": 120}
    wired.command(str(project))
    assert wired.wirings[-1].wire == "stdio" and wired.wirings[-1].timeout_s == 180
    wired.app.offer = {**wired.app.offer, "wires": ["stdio", "http"], "endpoint": "", "hold_s": True}
    wired.command(str(project))
    assert wired.wirings[-1].wire == "stdio" and wired.wirings[-1].hold_s == harness.HOLD_S  # no address: no route
    wired.MCP_WIRES = ()  # a harness that cannot be wired: Use… says so, and nothing is asked
    assert str(refusal(lambda: wired.use("llamacpp/gpu", MODEL, None, None, "on"))) == (
        "Tool cannot reach Liminal's MCP from here: turn Liminal's MCP off under Use…")
    assert wired.mcp_wiring() is None


def test_a_launch_that_leaves_liminals_mcp_out_while_it_is_on_is_not_started(wired, project):
    chosen(wired, mcp="on")
    wired.leaves_out = True
    for call in (lambda: wired.open(str(project)), lambda: wired.command(str(project))):
        with pytest.raises(children.ChildError) as caught:
            call()
        assert str(caught.value) == ("Tool's launch leaves Liminal's MCP out, and it is on for it (Use…): it is not "
                                     "started")
    assert wired.app.minted == [] and wired.out.popen.made == []


def test_the_offers_values_are_checked_as_every_written_value_is(wired, project):
    chosen(wired, mcp="on")
    wired.app.offer = {**wired.app.offer, "bridge": ["C:\\{env:USERPROFILE}\\python.exe", "bridge.py"]}
    assert str(refusal(lambda: wired.open(str(project)))) == (
        "the MCP plugin's bridge cannot be written into a harness's configuration as it is: it holds '{env:', which a "
        "harness reads as a variable, a file or a command")
    wired.app.offer = {**McpApp().offer, "headers": {"X-Liminal-Charts": "${{ secrets.X }}"}}
    assert "it holds '${{'" in str(refusal(lambda: wired.open(str(project))))
    wired.app.offer = {**McpApp().offer, "headers": {"X-Liminal-Charts": "1\r\nX-Other: 2"}}
    assert "answered something that is not how it is reached" in str(refusal(lambda: wired.open(str(project))))
    assert wired.app.minted == []


def test_no_launch_token_in_any_answer_or_status(wired, project):
    answers = [wired.use("llamacpp/gpu", MODEL, None, None, "on"), wired.open(str(project)), wired.status(),
               wired.command(str(project)), wired.open(str(project))]
    wired.out.popen.windows[0].code = 0
    answers.append(wired.status())
    live = wired.app.minted[1]  # (its window is still open)
    wired.app.mcp_refusing = {"launch_token": HookRefused(400, "ValueError", f"refused: {live}")}
    answers.append({"refused": str(refusal(lambda: wired.open(str(project))))})
    assert len(wired.app.minted) == 2
    for answer in answers:
        text = json.dumps(answer, ensure_ascii=False)
        assert not any(token in text for token in wired.app.minted), answer
    assert "refused: <hidden>" in answers[-1]["refused"]  # a live token is taken out of every word
    # an ended one leaves the secrets taken out of words (32 at most), so that it pushes no key out of them
    assert wired.app.minted[0] not in wired._rt.secrets and live in wired._rt.secrets and KEY in wired._rt.secrets


def test_the_mcp_words_a_plugin_declares(wired):
    assert conformance.problems(wired) == []
    assert [row[:2] for row in harness.MCP_ASKS] == [("mcp", "client_offer"), ("mcp", "ensure_client"),
                                                      ("mcp", "launch_token"), ("mcp", "end_launch")]
    assert all(len(row) == 3 and row[2] for row in harness.MCP_ASKS) and len(harness.MCP_NOTES[0]) <= 400
    assert harness.MCP_OPTION.name == "mcp" and harness.MCP_OPTION.default == "off"
    assert harness.MCP_VARIABLE == TOKEN_VARIABLE and harness.MCP_SLACK_S == 60 and harness.WIRES == ("stdio", "http")
    wiring = harness.McpWiring(token="x" * 43, headers={"A": 1})
    assert harness.McpWiring().timeout_s == 110 and wiring == harness.McpWiring(token="x" * 43, headers={"A": "1"})
    assert "x" * 43 not in repr(wiring) and wiring.headers == {"A": "1"}


# -- values a harness would read as more than text (1.66.0) ------------------------------------------------------------
EVALUATED = ("${HOME}", "x$(id)", "{env:OPENAI_API_KEY}", "a{file:~/.ssh/id_rsa", "${{ secrets.LIMINAL_MCP_TOKEN }}",
             "!curl evil", "  !rm -rf ~", "half ${ open")
PLAIN = ("qwen3:8b", "a!b", "cost$5", "{env}", "env:", "hf.co/x/y:Q4_K_M", "a$b", "{files}", "x!")


def test_values_a_harness_would_read_as_more_than_text_are_refused():
    assert harness.OPENERS == ("${", "$(", "{env:", "{file:", "${{") and harness.RUNS == "!"
    for bad in EVALUATED:
        assert harness.evaluated(bad), bad
        with pytest.raises(instances.Refusal) as caught:
            clean_model(bad)
        assert str(caught.value).startswith("a model's id is written into its harness's configuration, and this one "
                                            "cannot be: it "), bad
        with pytest.raises(instances.Refusal, match="^its address cannot be written into a harness's configuration"):
            harness.clean_value(bad, "its address")
    for good in PLAIN:
        assert harness.evaluated(good) == "" and harness.clean_value(good, "it") == good
    assert clean_model("qwen3:8b") == "qwen3:8b"
    assert harness.evaluated("${{ x }}") == "it holds '${{', which a harness reads as a variable, a file or a command"
    assert harness.evaluated("!x") == "it begins with '!', which a harness runs as a command"
    assert harness.evaluated(None) == "" and harness.clean_value(5, "it") == "5"


def test_use_refuses_such_a_model_and_a_kept_one_is_not_read(tool):
    tool.app.serving["llamacpp"]["instances"][0]["models"].append({"id": "$(curl x)"})  # a server's list: anything
    assert "cannot be: it holds '$('" in str(refusal(lambda: tool.use("llamacpp/gpu", "$(curl x)")))
    chosen(tool, model="{env:OPENAI_API_KEY}")
    assert tool.use_kept() is None
    assert "could not be read (a model's id is written into its harness's configuration, and this one cannot be: it " \
           "holds '{env:'" in tool.status()["problem"]


def test_a_harness_adds_its_own_openers_and_text_options_are_checked(tmp_path, project):
    class Secretive(Tool):
        OPENERS = (*Harness.OPENERS, "{secret:")
        OPTIONS = (*Tool.OPTIONS, Setting("agent", "Agent", "text"))

    out = Outside(env=dict(ENV), system="windows", home=tmp_path / "secretive", clock=Clock(),
                  interactive=lambda: True, popen=Popen(), variables=lambda: DECLARED)
    p = Secretive(out)
    p.attach(App(), Pairs())
    assert "it holds '{secret:'" in str(refusal(lambda: p.use("llamacpp/cpu", "a{secret:b}")))
    assert tool_accepts("a{secret:b}", tmp_path)  # (another harness's tool reads it as text)
    assert "Agent cannot be written into a harness's configuration as it is: it holds '${'" in str(
        refusal(lambda: p.use("llamacpp/cpu", "any.gguf", None, None, "${HOME}")))
    assert p.use("llamacpp/cpu", "any.gguf", None, None, "build")["ok"] is True
    assert p.use_kept().options == {"agent": "build"}
    chosen(p, server="llamacpp/cpu", model="any.gguf", agent="!run")  # a text kept from before: dropped when read
    assert p.use_kept().options == {}
    chosen(p, server="llamacpp/cpu", model="x{secret:y}")
    assert p.use_kept() is None
    assert "it holds '{secret:'" in str(refusal(lambda: p.clean_value("x{secret:y}", "its folder")))


def tool_accepts(model: str, tmp_path) -> bool:
    out = Outside(env=dict(ENV), system="windows", home=tmp_path / "plain", clock=Clock(), interactive=lambda: True,
                  popen=Popen(), variables=lambda: DECLARED)
    p = Tool(out)
    p.attach(App(), Pairs())
    return p.use("llamacpp/cpu", model)["ok"] is True
