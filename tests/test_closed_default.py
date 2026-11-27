"""Closed by default (1.107.0; the user, 2026-11-26: "Yes, closed by default"). A security sweep found that a plugin's
change hooks were open to any program on the machine asking over HTTP unless the plugin named them in
PAGE_ONLY_HOOKS. Now every hook a plugin answers and declares for no one is its page's alone: internal.closed lists
them, internal.page_alone holds them beside the declared ones, apps.asking refuses them to anyone but the page, and the
contract's own ask by name (Plugin.ask) holds them too. A hook is declared a read anyone here may ask (READ_HOOKS, a
tab of its own), one other plugins ask through the app (SERVICE_HOOKS, PLUGIN_ONLY_HOOKS), its page's
(PAGE_ONLY_HOOKS) or its route's (RPC_HOOK); those words keep their meaning.

Stand-in plugins and an app asked directly: nothing is served, started or reached, and no clock is read."""
from __future__ import annotations

import importlib
import inspect
import pkgutil

import pytest

import liminal_libs
from liminal_libs import internal
from liminal_libs.apps import App, asking
from liminal_libs.apps.tabs import Tab
from liminal_libs.machines import containers as C
from liminal_libs.machines.containerhost import NET_PLAN, ContainerHost
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.machines.segments import NetworkHost
from liminal_libs.sources import conformance
from liminal_libs.sources.plugin import FeedPlugin, Plugin

pytestmark = pytest.mark.usefixtures("no_outside")

NOBODY = "This ask names no asker: neither the page nor a plugin."
HOW = ("A read anyone on this machine may ask is named in its READ_HOOKS, one other plugins ask through the app in "
       "its SERVICE_HOOKS.")


class Mixed(MachinePlugin):
    """One hook of each audience, and two it declares for no one (a change and a job)."""

    name, title, about, api = "mixed", "Mixed", "a stand-in with every audience", "2.2"
    HOOKS = (*MachinePlugin.HOOKS, "look", "serve", "mint", "decide", "page_of", "rpc", "change", "fetch")
    READ_HOOKS = ("look",)
    SERVICE_HOOKS = ("serve",)
    PLUGIN_ONLY_HOOKS = ("mint",)
    PAGE_ONLY_HOOKS = ("decide",)
    JOB_HOOKS = ("fetch",)
    TABS = (Tab("more", "More", "page_of", 5.0),)
    RPC_HOOK = "rpc"

    def __init__(self):
        self.changed: list = []

    def present(self):
        return True

    def status(self):
        return {"present": True}

    def setup(self, log=None, steps=None):
        """Its setup: the contract's own, run by the app's route."""
        return {"ok": True}

    def look(self):
        """A read."""
        return {"by": asking.asker()}

    def serve(self):
        """A service other plugins ask."""
        return {"by": asking.asker()}

    def mint(self):
        """Only another plugin asks it."""
        return {"by": asking.asker()}

    def decide(self):
        """Only its page asks it."""
        return {"by": asking.asker()}

    def page_of(self):
        """Its tab's page."""
        return {"by": asking.asker()}

    def rpc(self, *args):
        """Its route's."""
        return {"by": asking.asker()}

    def change(self, value):
        """A change it never declared."""
        self.changed.append((value, asking.asker()))
        return {"by": asking.asker()}

    def fetch(self, log=None):
        """A job it never declared."""
        self.changed.append(("fetch", asking.asker()))
        return {"by": asking.asker()}


class Old(MachinePlugin):
    """A plugin written before any of the words: it declares nothing of its own."""

    name, title, about, api = "old", "Old", "a stand-in on the old contract", "2.2"
    HOOKS = (*MachinePlugin.HOOKS, "view", "apply")

    def present(self):
        return True

    def status(self):
        return {"present": True}

    def view(self):
        """What its page draws."""
        return {"by": asking.asker()}

    def apply(self, what):
        """A change."""
        return {"applied": what, "by": asking.asker()}


class Asker(MachinePlugin):
    """A plugin that asks the others through its app."""

    name, title, about, api = "asker", "Asker", "a stand-in that asks", "2.2"

    def wants(self, plugin, hook, *args):
        """Not a hook: another plugin's hook asked through the app."""
        return self.app.ask(plugin, hook, *args)


class Demo(App):
    NAME, TITLE, ICON = "demo", "Demo", "chip"

    def route(self, name, hook, *args):
        """As an app's route for its page asks a hook: the page named, in so many words."""
        with asking.asking(asking.PAGE):
            return self.ask(name, hook, *args)

    def tick(self, name, hook, *args):
        """As the app's own code asks a hook on its own: no one named."""
        return self.ask(name, hook, *args)


def demo():
    app = Demo(log=lambda m: None)
    mixed, old, asker = Mixed(), Old(), Asker()
    for plugin in (mixed, old, asker):
        app.attach(plugin)
    return app, mixed, old, asker


# -- what a plugin declares, read ------------------------------------------------------------------------------------
def test_a_hook_declared_for_no_one_is_closed_and_every_declared_one_keeps_its_audience():
    mixed = Mixed()
    assert internal.closed(mixed) == ("setup", "change", "fetch")  # in its HOOKS' order; a job is no declaration
    assert internal.undeclared(mixed) == ("change", "fetch")  # the contract's own setup is not the plugin's to declare
    assert {h: internal.audience(mixed, h) for h in mixed.interface()["hooks"]} == {
        "present": "read", "status": "read", "setup": "page", "look": "read", "serve": "plugin", "mint": "plugin",
        "decide": "page", "page_of": "read", "rpc": "route", "change": "page", "fetch": "page"}
    said = internal.audiences(mixed)
    assert said["change"] == {"audience": "page", "declared": False, "only": False}
    assert said["decide"] == {"audience": "page", "declared": True, "only": True}
    assert said["mint"] == {"audience": "plugin", "declared": True, "only": True}
    assert said["serve"] == {"audience": "plugin", "declared": True, "only": False}
    assert said["look"] == {"audience": "read", "declared": True, "only": False}
    # the declared words read as before; the gate's reading holds the closed ones beside them
    assert internal.declared(mixed, internal.PAGE_ONLY) == ("decide",)
    assert internal.page_only(mixed) == ("decide",)  # what it says, as its own tests read it
    assert internal.page_alone(mixed) == ("decide", "setup", "change", "fetch")  # what a gate holds to its page
    assert internal.plugin_only(mixed) == ("mint",)


def test_a_narrowing_word_wins_over_a_read_and_a_plugin_that_answers_nothing_has_nothing_closed():
    class Narrow(Mixed):
        name = "narrow"
        READ_HOOKS = ("decide", "mint", "serve")

    narrow = Narrow()
    assert [internal.audience(narrow, h) for h in ("decide", "mint", "serve")] == ["page", "plugin", "read"]
    assert internal.closed(MachinePlugin) == () and internal.closed(Plugin) == () and internal.closed(FeedPlugin) == ()
    assert internal.audience(Mixed(), "no_such_hook") == "page"  # what nothing declares is no one's but the page's


def test_what_an_apps_code_calls_on_a_kind_is_closed_and_not_the_plugins_to_declare():
    from liminal_libs.sources.publisher import PublisherPlugin
    from liminal_libs.storage.databases import DatabasePlugin

    class Engine(DatabasePlugin):
        name = "engine"
        HOOKS = (*DatabasePlugin.HOOKS, "vacuum")

        def open(self, *args):
            """A connection."""

        def make(self, *args):
            """A database made."""

        def own_port(self, *args):
            """Its port."""

        def vacuum(self):
            """A change of its own."""

    class Paper(PublisherPlugin):
        name = "paper"

        def read(self, *args):
            """Its pages read: requests spent."""

    assert internal.closed(Engine) == ("open", "make", "own_port", "vacuum")  # closed all the same
    assert internal.undeclared(Engine) == ("vacuum",)  # its own is the one it is asked to declare
    assert internal.closed(Paper) == ("read",) and internal.undeclared(Paper) == ()
    assert internal.undeclared(Mixed) == ("change", "fetch")  # another kind's names are no one's to leave out

    class Opens(Mixed):
        name = "opens"
        HOOKS = (*Mixed.HOOKS, "open", "read")

        def open(self):
            """A machine plugin's own open."""

        def read(self):
            """And its own read."""

    assert internal.undeclared(Opens) == ("change", "fetch", "open", "read")


def test_words_that_cannot_be_read_close_every_hook():
    class Unreadable(Mixed):
        name = "unreadable"
        SERVICE_HOOKS = "serve"

    plugin = Unreadable()
    with pytest.raises(ValueError, match="SERVICE_HOOKS must be a tuple of str"):
        internal.closed(plugin)
    assert internal.undeclared(plugin) == () and internal.audiences(plugin) == {}  # problems() says why
    for hook in ("look", "serve", "change"):
        assert "who may ask its hooks cannot be read" in asking.refusal(plugin, hook, "asker"), hook
        with pytest.raises(asking.AskRefused, match="who may ask its hooks cannot be read"):
            plugin.ask(hook, *(("x",) if hook == "change" else ()))


# -- the gate ----------------------------------------------------------------------------------------------------------
def test_an_undeclared_hook_is_refused_to_a_plugin_and_to_no_one_in_words_that_say_how_it_is_declared():
    mixed = Mixed()
    said = "mixed's change is asked only from its page: mixed declares it for no one else."
    assert asking.refusal(mixed, "change", asking.PAGE) == ""
    assert asking.refusal(mixed, "change", None) == f"{said} {HOW} {NOBODY}"
    assert asking.refusal(mixed, "change", "asker") == f"{said} {HOW} asker asked it."
    assert asking.refusal(mixed, "change", "mixed") == f"{said} {HOW} mixed asked it."  # nor its own plugin
    assert asking.refusal(mixed, "fetch", "asker").startswith("mixed's fetch is asked only from its page")
    # a declared word keeps its words and its meaning
    assert asking.refusal(mixed, "decide", "asker") == ("mixed's decide is asked only from its page, never by another "
                                                        "plugin: asker asked it.")
    assert asking.refusal(mixed, "mint", "asker") == ""
    for hook in ("look", "serve", "page_of", "rpc", "status", "present"):  # declared for others: never refused here
        assert all(asking.refusal(mixed, hook, who) == "" for who in (None, asking.PAGE, "asker", "mixed")), hook


def test_through_the_app_only_the_page_asks_an_undeclared_hook():
    app, mixed, _old, asker = demo()
    assert app.route("mixed", "change", 1) == {"by": "page"}
    with pytest.raises(asking.AskRefused) as by_plugin:
        asker.wants("mixed", "change", 2)
    assert by_plugin.value.asker == "asker" and by_plugin.value.hook == "change" and by_plugin.value.status == 403
    with pytest.raises(asking.AskRefused) as by_no_one:
        app.tick("mixed", "change", 3)
    assert by_no_one.value.asker is None and str(by_no_one.value).endswith(NOBODY)
    assert mixed.changed == [(1, "page")]  # asked once: by the page
    failed = [r for r in app.traffic.recent() if r["to"] == "mixed" and not r["ok"]]
    assert {(r["from"], r["what"]) for r in failed} == {("asker", "change"), ("demo", "change")}  # noted as failed asks
    # what it declares for plugins and for anyone is asked as before
    assert asker.wants("mixed", "serve") == {"by": "asker"} and asker.wants("mixed", "mint") == {"by": "asker"}
    assert asker.wants("mixed", "look") == {"by": "asker"} and app.tick("mixed", "look") == {"by": None}
    assert app.tick("mixed", "serve") == {"by": None} and asker.wants("mixed", "page_of") == {"by": "asker"}


def test_a_plugin_on_the_old_contract_keeps_its_page_and_says_why_anyone_else_is_refused():
    app, _mixed, old, asker = demo()
    assert internal.closed(old) == ("view", "apply") == internal.undeclared(old)
    assert app.route("old", "view") == {"by": "page"} and app.route("old", "apply", "x") == {"applied": "x", "by": "page"}
    assert app.tick("old", "status") == {"present": True}  # the contract's own reads stay anyone's
    assert asker.wants("old", "present") is True
    for hook, args in (("view", ()), ("apply", ("y",))):
        with pytest.raises(asking.AskRefused) as refused:
            asker.wants("old", hook, *args)
        assert str(refused.value) == (f"old's {hook} is asked only from its page: old declares it for no one else. "
                                      f"{HOW} asker asked it.")


def test_the_contracts_own_ask_by_name_holds_the_default_itself():
    """Plugin.ask: an app that asks a plugin by name without asking.check cannot leave an undeclared hook open."""
    mixed, old = Mixed(), Old()
    with pytest.raises(asking.AskRefused) as refused:
        mixed.ask("change", 1)
    assert refused.value.asker is None and refused.value.plugin == "mixed" and str(refused.value).endswith(NOBODY)
    with asking.asking("asker"), pytest.raises(asking.AskRefused, match="asker asked it"):
        old.ask("apply", "x")
    assert mixed.changed == []
    with asking.asking(asking.PAGE):
        assert mixed.ask("change", 2) == {"by": "page"} and old.ask("apply", "x") == {"applied": "x", "by": "page"}
        assert mixed.ask("fetch") == {"by": "page"}
    # the method itself is no ask by name, and what it declares is asked as it always was
    assert mixed.change(3) == {"by": None} and mixed.ask("look") == {"by": None} and mixed.ask("serve") == {"by": None}
    assert mixed.ask("rpc", "POST") == {"by": None} and old.ask("status") == {"present": True}
    with pytest.raises(LookupError):
        mixed.ask("no_such_hook")
    asking.check_closed(mixed, "decide", None)  # a declared word is the app's to hold (asking.check), as before
    asking.check_closed(mixed, "change", asking.PAGE)


def test_a_job_started_from_the_page_asks_an_undeclared_hook_in_its_own_thread_and_a_bare_thread_does_not():
    import threading

    mixed, got = Mixed(), {}

    def work():
        try:
            got["answer"] = mixed.ask("change", 9)
        except asking.AskRefused as e:
            got["refused"] = e

    with asking.asking(asking.PAGE):
        handed, bare = threading.Thread(target=asking.handed(work)), threading.Thread(target=work)
    handed.start()
    handed.join(10)
    assert got == {"answer": {"by": "page"}}
    got.clear()
    bare.start()
    bare.join(10)
    assert set(got) == {"refused"} and got["refused"].asker is None


# -- the Internal API tab says each hook's audience ---------------------------------------------------------------------
def test_each_hook_of_the_internal_api_says_who_may_ask_it():
    import json
    from pathlib import Path

    got = internal.internal_of(Mixed())
    assert json.loads(json.dumps(got)) == got
    by = {h["name"]: (h["audience"], h["declared"]) for h in got["hooks"]}
    assert by == {"present": ("read", True), "status": ("read", True), "setup": ("page", False), "run": ("", True),
                  "instances": ("", True), "scan": ("", True), "settings": ("", True), "look": ("read", True),
                  "serve": ("plugin", True), "mint": ("plugin", True), "decide": ("page", True),
                  "page_of": ("read", True), "rpc": ("route", True), "change": ("page", False),
                  "fetch": ("page", False)}
    old = {h["name"]: (h["audience"], h["declared"], h["pageOnly"]) for h in internal.internal_of(Old())["hooks"]}
    assert old["apply"] == ("page", False, False) and old["view"] == ("page", False, False)  # no word said: the default
    # the page draws it by the same names, beside the two words it drew before
    js = (Path(internal.__file__).parent / "ui" / "static" / "internal.js").read_text(encoding="utf-8")
    tag = js[js.index("  function audienceTag(h) {"):js.index('  // "tab World Wide Web')]
    for line in ("if (h.pluginOnly === true || h.pageOnly === true || !text(h.answered)) return null;",
                 "case 'read': return ['asked by anyone here', 'in-read'];",
                 "case 'plugin': return ['asked by other plugins and its page', ''];",
                 "case 'page': return h.declared === false ? ['asked only from its page: declared for no one', "
                 "'in-only'] : null;",
                 "case 'route': return ['asked only through its route', ''];"):
        assert line in tag, line
    tags = js[js.index("  function tagsHtml(h, c) {"):js.index("  function audienceTag(h) {")]
    assert "const audience = audienceTag(h);\r\n    if (audience) tags.push(audience);".replace("\r\n", "\n") in tags.replace("\r\n", "\n")
    who = js[js.index("  function whoHtml(h, c) {"):js.index("  function answeredWords(h) {")]
    assert "if (h.audience === 'page' && h.declared === false && h.users === 'named') {" in who
    assert "const closedLines = ['asked by name: from its page alone, as it declares the hook for no one'];" in who
    assert who.index("h.declared === false && h.users === 'named'") < who.index("const app = 'used by '")


# -- conformance's warning list --------------------------------------------------------------------------------------
def test_conformance_lists_the_hooks_left_undeclared_as_warnings_and_none_for_a_plugin_that_declares_them():
    assert conformance.warnings(Mixed()) == [
        "mixed: hook 'change' declares no audience, so it is asked only from its page (closed by default): name it "
        "in READ_HOOKS (a read anyone on this machine may ask), SERVICE_HOOKS (other plugins ask it through the "
        "app) or PAGE_ONLY_HOOKS (its page alone)",
        "mixed: hook 'fetch' declares no audience, so it is asked only from its page (closed by default): name it "
        "in READ_HOOKS (a read anyone on this machine may ask), SERVICE_HOOKS (other plugins ask it through the "
        "app) or PAGE_ONLY_HOOKS (its page alone)"]
    assert [w.split(":")[1].split("'")[1] for w in conformance.warnings(Old())] == ["view", "apply"]

    class Said(Mixed):
        name = "said"
        PAGE_ONLY_HOOKS = ("change", "fetch")

    assert conformance.warnings(Said()) == [] and internal.undeclared(Said()) == ()
    assert conformance.warnings(object()) == []  # what is no plugin has nothing to declare (problems says so)
    assert not any("audience" in w for w in conformance.problems(Mixed()))  # a warning is no problem: nothing fails on it


def test_every_hook_the_library_answers_itself_is_declared_by_the_library():
    """A library base that left a hook of its own undeclared would hand every plugin built on it a warning it cannot
    answer: the contract's own scan, setup and run, and each kind's own (KIND_RUN), aside."""
    found = {}
    for info in pkgutil.walk_packages(liminal_libs.__path__, "liminal_libs."):
        if "standins" in info.name or info.name.endswith("__main__"):
            continue
        try:
            module = importlib.import_module(info.name)
        except Exception:  # noqa: BLE001 - a module that needs what this machine lacks declares nothing here
            continue
        for value in vars(module).values():
            if inspect.isclass(value) and issubclass(value, Plugin) and value.__module__ == module.__name__:
                found[value] = internal.undeclared(value)
    assert len(found) > 15 and {c.__name__ for c in found} >= {"Firewall", "Admin", "ContainerHost", "ModelServer"}
    # AiPlugin's install and uninstall are named by ModelServer and Harness: a ProtocolPlugin's HOOKS leave both out
    assert {c.__name__: left for c, left in found.items() if left} == {"AiPlugin": ("install", "uninstall")}


# -- the asks between plugins that worked before work still --------------------------------------------------------------
def test_the_service_interface_and_the_firewalls_plan_are_declared_for_plugins():
    for hook in (C.PLAN, C.APPLY, C.WORK, C.HOSTED_FILE, C.RELEASE, C.DECLINE, C.CANCEL, C.HOSTING, C.HOSTED,
                 C.HOSTED_LOGS, C.EXPOSURES, C.PLAN_WORDS, C.SEGMENTS):
        assert hook in internal.declared(ContainerHost, "SERVICE_HOOKS"), hook
        assert internal.audience(ContainerHost, hook) in ("plugin", "read"), hook
    assert C.PLAN == "service_plan" and internal.audience(ContainerHost, C.PLAN) == "plugin"
    assert NET_PLAN == "network_plan" and internal.audience(NetworkHost, NET_PLAN) in ("plugin", "read")
    for name in internal.declared(NetworkHost, "SERVICE_HOOKS"):
        assert internal.audience(NetworkHost, name) in ("plugin", "read") or name in internal.declared(
            NetworkHost, internal.PAGE_ONLY), name
    # every hook a library base asks of another plugin (its ASKS) is one some library base declares for plugins
    offered = {}
    for base in (ContainerHost, NetworkHost, *_bases()):
        for hook in getattr(base, "HOOKS", ()):
            offered.setdefault(hook, []).append(internal.audience(base, hook))
    asked = {(base.__name__, row[1]) for base in _bases() for row in (getattr(base, "ASKS", ()) or ())}
    assert asked and {pair for pair in asked if pair[1] in offered and "page" in offered[pair[1]]
                      and not {"plugin", "read"} & set(offered[pair[1]])} == set()


def _bases():
    from liminal_libs.machines.containedservice import ContainedService
    from liminal_libs.machines.harness import Harness
    from liminal_libs.machines.modelserver import ModelServer
    from liminal_libs.machines.protocol import ProtocolPlugin
    from liminal_libs.machines.wsl import WslDistribution

    return (ContainedService, ContainerHost, NetworkHost, Harness, ModelServer, ProtocolPlugin, WslDistribution)
