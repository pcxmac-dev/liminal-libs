"""The parts of the AI top-four and MCP release held together where they meet (the user, 2026-11-18: "now i need an
MCP plugin for platform, basically a protocol plugin that mediates MCP connections to resources by local AI agents";
"top 4 inference engines, top 4 agentic harnesses (open source)"). Each part's own tests stand in for the others. Here
the library's own protocol base (machines/protocol.py), harness base (machines/harness.py) and frame (apps/app.py,
apps/asking.py) are attached to one app, with no stand-in between them: a harness asks the protocol plugin through
App.ask, and the frame names who asks.

The plan's checks of the whole (its order, step 6), held where the parts meet:
- no token's text is in any pair, nor in any answer but token_once's (and launch_token's, to its own plugin alone);
- no hook only the page asks (PAGE_ONLY_HOOKS) is answered to a plugin;
- no hook only other plugins ask (PLUGIN_ONLY_HOOKS) is answered to the page;
- an ask that names no asker is refused for every gated hook, in a thread too.

Everything outside is a stand-in: the login keeps its pairs in memory, a window is a stand-in process, the model
server is a plugin of the test's, and the platform's route is the test handing rpc a request. Nothing is started or
reached (the shared guard, conftest.py). Each thread is joined."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from liminal_libs import mounts
from liminal_libs.apps import App, asking
from liminal_libs.apps.authorization import Login, Unauthorized, pair_name, variable_name
from liminal_libs.machines import harness
from liminal_libs.machines.ai import Outside, Package
from liminal_libs.machines.children import Launch
from liminal_libs.machines.harness import Harness
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.machines.protocol import ProtocolPlugin, Refusal

pytestmark = pytest.mark.usefixtures("no_outside")

HTTP = "http:" + "//"  # an address's start, put together here: no file names a host whole
MODEL = "qwen3-8b"
PAGE_ONLY, PLUGIN_ONLY = ProtocolPlugin.PAGE_ONLY_HOOKS, ProtocolPlugin.PLUGIN_ONLY_HOOKS
ARGS = {"add_client": ("bob",), "forget_client": ("alice",), "grant": ("alice", "server:git", "ask"),
        "token_once": ("alice", 30, True), "revoke": ("alice",), "waiting_call": ("t",), "decide": ("t", "once"),
        "ensure_client": ("Tool",), "launch_token": (), "end_launch": ("a-token",)}  # each gated hook's arguments


class Pairs(Login):
    """The platform's login as a test has it: pairs kept in memory."""

    def __init__(self):
        self.kept: dict[str, str] = {}

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


class Window:
    """A window's process, a stand-in: open until its exit code is set."""

    def __init__(self, pid: int):
        self.pid, self.code = pid, None

    def poll(self):
        return self.code


class Popen:
    """subprocess.Popen as a stand-in: what each start was given, and the window it made."""

    def __init__(self):
        self.made: list[dict] = []
        self.windows: list[Window] = []

    def __call__(self, argv, **kw):
        self.made.append({"argv": list(argv), **kw})
        self.windows.append(Window(4321 + len(self.windows)))
        return self.windows[-1]


class Gate(ProtocolPlugin):
    """A protocol plugin as plugin-platform-mcp will be one: its offer in the words a harness reads (`offer`), its
    protocol answering whom it served."""

    name, title, about, order, version = "mcp", "MCP", "A stand-in protocol plugin", 530, "0.1.0"

    def serve(self, method, headers, body, client, gone):
        return 200, {"client": client}, {}

    def offer(self, client):
        return {"wires": ["stdio", "http"], "bridge": ["python", "-I", "-S", "bridge.py"],
                "endpoint": HTTP + "127.0.0.1:8775/api/machines/mcp/rpc", "headers": {"X-Liminal-Charts": "1"},
                "revisions": ["2026-07-28", "2025-11-25"]}

    def grantable(self):
        return {"server:git": ("allow", "ask", "ask twice", "deny")}


class Server(MachinePlugin):
    """A model server as a harness finds one: llama.cpp's instance gpu, running, serving MODEL."""

    name, title = "llamacpp", "llama.cpp"
    HOOKS = (*MachinePlugin.HOOKS, "serving")
    READ_HOOKS = SERVICE_HOOKS = ("serving",)  # as ModelServer declares it (closed by default, 1.107.0)

    def serving(self, name=""):
        """What it serves, as machines/modelserver.py says it."""
        base = HTTP + "127.0.0.1:9931"
        return {"plugin": "llamacpp", "title": "llama.cpp", "native": "llamacpp", "instances": [
            {"name": "gpu", "title": "", "where": "local", "local": True, "base": base, "openai": base + "/v1",
             "plain": False, "state": "running", "key": "", "model": MODEL, "context": 32768,
             "models": [{"id": MODEL, "context": 32768, "tools": True}], "asked": "", "port": 9931,
             "speaks": ["chat"]}]}


class Tool(Harness):
    """A harness wired to Liminal's MCP by its bridge: its launch asks how (`mcp_wiring`) and names the bridge in its
    configuration's variable, never the token."""

    name, title, about, order, LIBS_FLOOR = "tool", "Tool", "A stand-in harness", 520, "1.62.0"
    OPTIONS = (harness.MCP_OPTION,)
    MCP_WIRES = ("stdio",)
    ASKS = (*Harness.ASKS, *harness.MCP_ASKS)

    def package(self):
        return Package("Tool", "1.0", 1_000_000, "MIT (its maker's).", ("downloads.example.test",))

    def runs_here(self):
        return ""

    def launch(self, folder, use, at, key=""):
        wiring = self.mcp_wiring(use)
        env = {"TOOL_MCP_BRIDGE": " ".join(wiring.argv)} if wiring is not None else {}
        return Launch([str(self.home / "app" / "1.0" / "tool.exe"), "--model", use.model], env=env)

    def asks_mcp(self, hook, *args):
        """Not a hook: one of the MCP plugin's asked through the app, as this plugin's own code asks it."""
        return self.app.ask("mcp", hook, *args)


class Platform(App):
    NAME, TITLE, ICON = "platform", "Platform", "chip"


def clock() -> float:
    return 1_800_000_000.0


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: False)  # this system's own disk
    login, popen = Pairs(), Popen()
    app = Platform(log=lambda m: None, login=login)
    gate = Gate(Outside(env={}, system="windows", home=tmp_path / "mcp", clock=clock))
    tool = Tool(Outside(env={"PATH": "/usr/bin"}, system="windows", home=tmp_path / "tool", clock=clock,
                        interactive=lambda: True, popen=popen, variables=lambda: ()))
    for plugin in (gate, Server(), tool):
        app.attach(plugin)
    program = tool.home / "app" / "1.0" / "tool.exe"  # installed as its base installs it
    program.parent.mkdir(parents=True)
    program.write_text("a stand-in program", encoding="utf-8")
    (tool.home / "app" / "CURRENT").write_text("1.0\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    return SimpleNamespace(app=app, gate=gate, tool=tool, login=login, popen=popen, project=project)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_a_harness_reaches_the_protocol_plugin_through_the_frame_and_no_token_shows(world):
    app, gate, tool, login, popen = world.app, world.gate, world.tool, world.login, world.popen
    used = tool.use("llamacpp/gpu", MODEL, "on")  # Liminal's MCP on: its agent made for it, granted nothing
    assert any(line.startswith("Liminal's MCP: Tool (tool) made for tool") for line in used["lines"])
    [agent] = gate.clients()
    assert (agent["name"], agent["by"], agent["grants"], agent["token"]) == ("tool", "tool", 0, "none")
    opened = tool.open(str(world.project))  # a window: a token for it alone, in its variable alone
    made = popen.made[0]
    token = made["env"]["LIMINAL_MCP_TOKEN"]
    assert made["env"]["TOOL_MCP_BRIDGE"] == "python -I -S bridge.py"
    assert not any(token in word for word in made["argv"]) and token not in str(made["cwd"])
    assert gate.rpc("POST", bearer(token), {})[:2] == (200, {"client": "tool"})  # the agent its harness's
    with asking.asking(asking.PAGE):  # a hand-wired agent, from the page: its token shown once
        gate.add_client("alice")
        shown = gate.token_once("alice", 30, True)
    hand = shown["token"]
    assert gate.rpc("POST", bearer(hand), {})[:2] == (200, {"client": "alice"})
    answers = [used, opened, tool.status(), tool.command(str(world.project)), gate.status(), gate.clients(),
               gate.pending(), gate.calls(), app.traffic.snapshot(), tool.asks_mcp("client_offer")]
    with asking.asking(asking.PAGE):
        answers += [gate.client_offer(), gate.revoke("tool")]
    said = json.dumps([login.kept, answers], default=str)
    assert token not in said and hand not in said  # in no pair, and in no answer but token_once's
    assert gate.rpc("POST", bearer(token), {})[0] == 401  # revoked from the page
    with asking.asking(asking.PAGE):
        assert gate.revoke("alice")["ok"] and gate.rpc("POST", bearer(hand), {})[0] == 401


def test_a_windows_token_ends_once_the_harness_sees_it_gone(world):
    gate, tool, popen = world.gate, world.tool, world.popen
    tool.use("llamacpp/gpu", MODEL, "on")
    tool.open(str(world.project))
    tool.open(str(world.project))
    first, second = (made["env"]["LIMINAL_MCP_TOKEN"] for made in popen.made)
    assert first != second
    popen.windows[0].code = 0  # the first window closed
    tool.status()
    assert gate.rpc("POST", bearer(first), {})[0] == 401 and gate.rpc("POST", bearer(second), {})[0] == 200
    gate.app_stopping()  # the platform stops: every launch token ends with it
    assert gate.rpc("POST", bearer(second), {})[0] == 401


def test_a_harnesss_agent_forgotten_is_made_again_by_its_use_alone_as_its_words_say(world):
    gate, tool = world.gate, world.tool
    tool.use("llamacpp/gpu", MODEL, "on")
    with asking.asking(asking.PAGE):
        gate.forget_client("tool")
    words = next(f for f in gate.status()["forms"] if f["id"] == "ai-forget-agent")["confirm"]["words"]
    assert words.endswith("A harness that made it makes it again, granted nothing, when its Use… turns Liminal's MCP "
                          "on again.")
    with pytest.raises(Refusal, match="tool has no agent of its own here"):  # its next Open… gets no token
        tool.open(str(world.project))
    assert world.popen.made == [] and gate.clients() == []
    tool.use("llamacpp/gpu", MODEL, "on")  # its Use… again: made again, granted nothing
    [agent] = gate.clients()
    assert (agent["name"], agent["by"], agent["grants"]) == ("tool", "tool", 0)
    tool.open(str(world.project))
    assert gate.rpc("POST", bearer(world.popen.made[0]["env"]["LIMINAL_MCP_TOKEN"]), {})[0] == 200


def test_no_gated_hook_is_answered_to_an_asker_it_does_not_take(world):
    app, gate, tool, login = world.app, world.gate, world.tool, world.login
    with asking.asking(asking.PAGE):
        gate.add_client("alice")  # someone for each page-only hook to act on
    kept = dict(login.kept)
    for hook in PAGE_ONLY:  # a plugin's ask, through the app: refused, in words
        with pytest.raises(asking.AskRefused, match=f"mcp's {hook} is asked only from its page, never by another "
                                                    "plugin: tool asked it"):
            tool.asks_mcp(hook, *ARGS[hook])
    with asking.asking(asking.PAGE):  # the page's: refused every hook only another plugin asks
        for hook in PLUGIN_ONLY:
            with pytest.raises(asking.AskRefused, match="never from a page or by a program"):
                app.ask("mcp", hook, *ARGS[hook])
    for hook in (*PAGE_ONLY, *PLUGIN_ONLY):  # the app's own code, with no one named: refused both kinds
        with pytest.raises(asking.AskRefused, match="This ask names no asker"):
            app.ask("mcp", hook, *ARGS[hook])
    answered: list[str] = []

    def bare():  # a thread started inside the page's ask and handed nothing: no asker, through the app or not
        for hook in (*PAGE_ONLY, *PLUGIN_ONLY):
            try:
                app.ask("mcp", hook, *ARGS[hook])
                answered.append(f"{hook}, through the app")
            except asking.AskRefused:
                pass
            try:
                getattr(gate, hook)(*ARGS[hook])
                answered.append(f"{hook}, by the plugin itself")
            except Refusal:
                pass

    with asking.asking(asking.PAGE):
        thread = threading.Thread(target=bare, name="handed-nothing", daemon=True)
        thread.start()
        thread.join(10)
    assert not thread.is_alive() and answered == []
    assert login.kept == kept  # nothing of it was kept
    job_said: list = []
    with asking.asking(asking.PAGE):  # a job the page started, handed its asker in so many words: it may
        job = threading.Thread(target=asking.handed(lambda: job_said.append(app.ask("mcp", "grant", *ARGS["grant"]))),
                               name="a-job", daemon=True)
        job.start()
        job.join(10)
    assert not job.is_alive() and job_said and job_said[0]["ok"]
    assert gate.grants_of("alice") == {"server:git": "ask"}
    assert tool.asks_mcp("ensure_client", "Tool")["agent"] == "tool"  # what a plugin may ask, for itself alone
    assert Path(tool.asks_mcp("client_offer")["bridge"][-1]).name == "bridge.py"
