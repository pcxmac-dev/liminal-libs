"""Who may ask an AI plugin's changes (1.99.0; the sweep after the review's finding PLT-H1, 2026-11-25). The platform
hands an ask from any program on this PC to a plugin's hook, so the two AI bases say which of theirs only the page asks
(PAGE_ONLY_HOOKS, as apps/asking.py and liminal-platform 0.34.0 read them). A harness's: its install and its removal,
the choice Use… keeps and the window Open… starts. A model server's: its install and its removal, an instance added,
changed or removed, its key kept or forgotten, its sharing, its start, its stop, its start at boot, and a prompt sent
to it. Another plugin's ask of one is refused, and so is an ask that names no one: nothing is kept, started or sent.
The page's ask reaches the plugin as before. Their reads are answered to anyone, a model server's two services among
them (serving and models_of, which a harness asks through the platform), and a harness asked by another plugin asks
the model server as itself. A plugin that adds changes of its own names those alone: the base's stay.

Asked through the library's own App (its ask names who asks as the platform's does), over the bases' own stand-ins
(tests/test_harness.py, tests/test_modelserver.py): no window opens, no server starts, nothing is installed and
nothing is reached; the shared guard (conftest.py) fails a test that starts a process or opens a connection."""
from __future__ import annotations

import json

import pytest

from liminal_libs import internal, mounts
from liminal_libs.apps import App, asking
from liminal_libs.machines.ai import Outside
from liminal_libs.machines.harness import Harness
from liminal_libs.machines.modelserver import ModelServer
from liminal_libs.machines.plugin import MachinePlugin
from test_harness import DECLARED, ENV, KEY, KEY_VARIABLE, MODEL, Clock, Pairs, Popen, Tool, installed
from test_harness import serving as served
from test_modelserver import Server, boot, kept_json, world  # noqa: F401 - a model server's, and its fixtures

pytestmark = pytest.mark.usefixtures("no_outside")

# each base's hooks, every one of them named: a change only its page asks, or a read anyone asks
HARNESS_CHANGES = ("install", "uninstall", "use", "open")
HARNESS_READS = ("present", "status", "refresh", "command", "ask_models")
SERVER_CHANGES = ("install", "uninstall", "add_instance", "change_instance", "remove_instance", "set_key",
                  "forget_key", "share", "start", "stop", "boot", "try_it")
SERVER_READS = ("present", "status", "refresh", "choose", "log_of", "models", "serving", "models_of")
ONLY_PAGE = "is asked only from its page"


class Neighbour(MachinePlugin):
    """Another plugin of the platform, asking an AI plugin through its app as any plugin may (a container plugin, or
    the MCP plugin for a local agent)."""

    name, title = "neighbour", "Neighbour"

    def wants(self, name, hook, *args):
        """Not a hook: another plugin's hook asked through the app."""
        return self.app.ask(name, hook, *args)


class Serves(MachinePlugin):
    """A model server as a harness asks it through the app: what test_harness's llama.cpp says it serves (its instance
    gpu, keyed), and who asked. A harness asks in the platform's form, the arguments as one list, which the library's
    own App hands on as one argument."""

    name, title = "llamacpp", "llama.cpp"
    HOOKS = (*MachinePlugin.HOOKS, "serving", "models_of")
    READ_HOOKS = ("serving", "models_of")
    SERVICE_HOOKS = ("serving", "models_of")

    def __init__(self):
        super().__init__()
        self.asked: list[tuple[str | None, str]] = []  # (who asked, the hook)

    def serving(self, name=""):
        """What it serves: its instances, as a model server's plugin says them."""
        self.asked.append((asking.asker(), "serving"))
        return served()["llamacpp"]

    def models_of(self, name):
        """One instance's models, asked now."""
        self.asked.append((asking.asker(), "models_of"))
        return {"said": "llama.cpp / gpu lists 1 model", "ok": True, "asked": "",
                "models": [{"id": MODEL, "context": 32768, "tools": True}]}


class Platform(App):
    """The library's App asking as the platform does: from its page's route, the page named in so many words, or from
    its own code, no one named."""

    NAME, TITLE, ICON = "platform", "Platform", "chip"

    def from_page(self, name, hook, *args):
        """As the page's route asks a hook."""
        with asking.asking(asking.PAGE):
            return self.ask(name, hook, *args)

    def on_its_own(self, name, hook, *args):
        """As the app's own code asks a hook."""
        return self.ask(name, hook, *args)


class Pulls(Server):
    """A model server's plugin with hooks of its own, as Ollama's has them: a lookup anyone asks, and a download it
    says only its page asks. It names that one alone."""

    name, title = "pulls", "Pulls"
    HOOKS = (*Server.HOOKS, "find", "pull")
    READ_HOOKS = ("find",)
    PAGE_ONLY_HOOKS = ("pull",)

    def __init__(self, outside=None):
        super().__init__(outside)
        self.pulled: list[str] = []

    def find(self, words):
        """Models looked up by a word: a read."""
        return {"found": [str(words)]}

    def pull(self, model):
        """A model downloaded: a change of its own."""
        self.pulled.append(str(model))
        return {"said": f"{model} is downloaded", "ok": True}


class Extends(Tool):
    """A harness's plugin with a change of its own, as Continue's has (its editor's extension), saying the base's
    words again beside it: each name is read once."""

    name, title = "extends", "Extends"
    HOOKS = (*Tool.HOOKS, "extension_install")
    PAGE_ONLY_HOOKS = (*Harness.PAGE_ONLY_HOOKS, "extension_install")

    def extension_install(self):
        """Its editor's extension installed: a change of its own."""
        return {"said": "its extension is installed", "ok": True}


class Quiet(Tool):
    """A harness's plugin that says none of its hooks is the page's alone: the base's stay all the same."""

    name, title = "quiet", "Quiet"
    PAGE_ONLY_HOOKS = ()


@pytest.fixture(autouse=True)
def on_this_disk(monkeypatch):
    """Each stand-in's folder on this system's own disk (a stand-in mounts.foreign), as the bases' own tests have it."""
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: False)


@pytest.fixture
def harness(tmp_path):
    """A stand-in harness, installed, on the library's App beside a model server it can be started against and another
    plugin; that server's key kept through the same login, as its plugin keeps it; and a folder to open it in."""
    tool = Tool(Outside(env=dict(ENV), system="windows", home=tmp_path / "tool", clock=Clock(),
                        interactive=lambda: True, popen=Popen(), variables=lambda: DECLARED))
    serves, neighbour = Serves(), Neighbour()
    app = Platform(log=lambda m: None, login=Pairs())
    for plugin in (tool, serves, neighbour):
        app.attach(plugin)
    app.login.kept[KEY_VARIABLE] = KEY
    installed(tool)
    folder = tmp_path / "project"
    folder.mkdir()
    return app, tool, serves, neighbour, str(folder)


def attached(server) -> tuple[Platform, Neighbour]:
    """A stand-in model server on the library's App, with its own login, beside another plugin."""
    app, neighbour = Platform(log=lambda m: None, login=server.login), Neighbour()
    app.attach(server)
    app.attach(neighbour)
    return app, neighbour


def askers(app: Platform, neighbour: Neighbour, name: str) -> tuple:
    """The two askers a change refuses, each as a call of (hook, *args): another plugin, and the app's own code."""
    return (lambda hook, *args: neighbour.wants(name, hook, *args),
            lambda hook, *args: app.on_its_own(name, hook, *args))


def test_each_base_says_its_changes_are_asked_only_from_its_page_and_its_reads_by_anyone(harness, world):
    assert Harness.PAGE_ONLY_HOOKS == HARNESS_CHANGES and ModelServer.PAGE_ONLY_HOOKS == SERVER_CHANGES
    assert not set(SERVER_CHANGES) & set(ModelServer.SERVICE_HOOKS)  # what a harness asks of it stays a plugin's to ask
    for plugin, changes, reads in ((harness[1], HARNESS_CHANGES, HARNESS_READS),
                                   (world.server(), SERVER_CHANGES, SERVER_READS)):
        assert set(internal.page_only(plugin)) == set(changes)  # what the frame and the platform read
        assert internal.plugin_only(plugin) == () and internal.problems(plugin) == []
        assert set(plugin.interface()["hooks"]) == {*changes, *reads}  # every hook it answers is one or the other
        for hook in changes:
            assert asking.refusal(plugin, hook, asking.PAGE) == ""
            assert asking.refusal(plugin, hook, "neighbour") == (f"tool's {hook} is asked only from its page, never "
                                                                 "by another plugin: neighbour asked it.")
            assert asking.refusal(plugin, hook, None) == (f"tool's {hook} is asked only from its page. This ask names "
                                                          "no asker: neither the page nor a plugin.")
        for hook in reads:
            assert {asking.refusal(plugin, hook, who) for who in (asking.PAGE, "neighbour", None)} == {""}


def test_another_plugin_or_no_one_asking_a_harnesss_change_opens_and_keeps_nothing_and_its_page_does(harness):
    app, tool, serves, neighbour, folder = harness
    changes = (("install", True),  # its licence accepted: an argument the asker sets
               ("uninstall", True),  # and its second confirmation
               ("use", "llamacpp/gpu", MODEL), ("open", folder))
    assert {hook for hook, *_ in changes} == set(HARNESS_CHANGES)
    for ask in askers(app, neighbour, "tool"):
        for hook, *args in changes:
            with pytest.raises(asking.AskRefused, match=ONLY_PAGE):
                ask(hook, *args)
    assert tool.out.popen.made == [] and tool.made == [] and serves.asked == []  # no window, no launch, no one asked
    assert app.login.saved == [] and tool.use_kept() is None and tool.installed() is not None  # nothing kept or removed
    assert app.from_page("tool", "use", "llamacpp/gpu", MODEL)["ok"] and tool.use_kept().model == MODEL
    # its reads, asked by a plugin as before: nothing is started for them, and it asks the model server as itself
    lines = neighbour.wants("tool", "command", folder)
    assert lines["ok"] and tool.out.popen.made == [] and KEY not in json.dumps(lines)
    assert neighbour.wants("tool", "ask_models", "llamacpp/gpu")["models"] == [MODEL]
    assert neighbour.wants("tool", "refresh")["ok"] and isinstance(neighbour.wants("tool", "status"), dict)
    assert ("tool", "models_of") in serves.asked and {who for who, _ in serves.asked} == {"tool"}
    said = app.from_page("tool", "open", folder)  # the page's Open…: the stand-in window, its server's key handed over
    assert said["ok"] and [made["cwd"] for made in tool.out.popen.made] == [folder]
    assert tool.made[-1]["key"] == KEY and KEY not in json.dumps(said)


def test_another_plugin_or_no_one_asking_a_model_servers_change_runs_nothing_and_its_page_does(world):
    server = world.server(attach=False)
    app, neighbour = attached(server)
    assert app.from_page("tool", "add_instance", "one")["ok"]  # the page's form: kept through the login
    kept, saved = kept_json(server), list(server.login.saved)
    changes = (("install", True), ("uninstall", True), ("add_instance", "two"), ("change_instance", "one", None, 11500),
               ("remove_instance", "one"), ("set_key", "one", KEY), ("forget_key", "one"),
               ("share", "one", "yes", True),  # its second confirmation said: an argument the asker sets
               ("start", "one"), ("stop", "one"), ("boot", "one", "yes"), ("try_it", "one", MODEL, "hello"))
    assert {hook for hook, *_ in changes} == set(SERVER_CHANGES)
    for ask in askers(app, neighbour, "tool"):
        for hook, *args in changes:
            with pytest.raises(asking.AskRefused, match=ONLY_PAGE):
                ask(hook, *args)
    assert kept_json(server) == kept and server.login.saved == saved  # nothing kept: no instance, no key
    assert world.kids.made == [] and world.transport.asked == []  # nothing started, nothing sent
    assert [call for call in world.boot.calls if call[0] != "read"] == []  # no task registered, started or removed
    # its reads and its services, asked by a plugin as before (a harness's asks, through the platform)
    assert [row["name"] for row in neighbour.wants("tool", "serving")["instances"]] == ["one"]
    assert neighbour.wants("tool", "models_of", "one")["ok"] is False and world.transport.asked == []  # stopped
    assert neighbour.wants("tool", "choose", "one")["ok"] and neighbour.wants("tool", "log_of", "one")["ok"]
    assert isinstance(neighbour.wants("tool", "status"), dict)
    assert app.from_page("tool", "set_key", "one", KEY)["ok"] and server.login.kept[server.key_variable("one")] == KEY
    assert app.from_page("tool", "start", "one")["ok"]  # the page's Start: the stand-in child
    child, = world.kids.made
    with pytest.raises(asking.AskRefused, match=ONLY_PAGE):
        neighbour.wants("tool", "stop", "one")
    assert child.alive and child.stops == 0
    assert app.from_page("tool", "stop", "one")["ok"] and child.stops == 1 and not child.alive


def test_a_plugin_names_only_the_changes_it_adds_and_the_bases_stay(world):
    assert internal.page_only(Extends) == (*HARNESS_CHANGES, "extension_install")  # said again: each name once
    assert set(internal.page_only(Quiet)) == set(HARNESS_CHANGES)  # a subclass takes back nothing its base says
    assert internal.problems(Extends) == [] == internal.problems(Quiet)
    pulls = world.server(cls=Pulls, attach=False)
    assert set(internal.page_only(pulls)) == {*SERVER_CHANGES, "pull"} and internal.problems(pulls) == []
    app, neighbour = attached(pulls)
    for ask in askers(app, neighbour, "pulls"):
        for hook, *args in (("pull", "qwen3:8b"), ("add_instance", "one")):  # its own, and its base's all the same
            with pytest.raises(asking.AskRefused, match=ONLY_PAGE):
                ask(hook, *args)
    assert pulls.pulled == [] and pulls.login.saved == []
    assert neighbour.wants("pulls", "find", "qwen") == {"found": ["qwen"]}  # its own read, asked by anyone
    assert app.from_page("pulls", "pull", "qwen3:8b")["ok"] and pulls.pulled == ["qwen3:8b"]
    assert app.from_page("pulls", "add_instance", "one")["ok"] and list(pulls.kept_instances().instances) == ["one"]
