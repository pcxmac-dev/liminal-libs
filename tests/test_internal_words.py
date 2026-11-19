"""Two words a plugin says of its hooks (liminal_libs.internal; the user, 2026-11-18: "now i need an MCP plugin for
platform, basically a protocol plugin that mediates MCP connections to resources by local AI agents"):
PLUGIN_ONLY_HOOKS, its hooks only another plugin asks through its app, never a page or a program; and
PAGE_ONLY_HOOKS, its hooks only its page asks, never another plugin. Both are () unless a plugin says them, both join
DECLARED, problems() checks them, the Internal API says them for each hook, and ui/static/internal.js draws them.

A plugin that says neither stays exactly as it was: no new problem, the same rows. On stand-ins written here, every
hook of which raises if it is called: nothing of a plugin is called, no process starts and nothing is reached."""
from __future__ import annotations

import importlib
import json
import re

import pytest

from liminal_libs import internal
from liminal_libs.apps.tabs import Tab
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.sources.plugin import Plugin
from liminal_libs.ui import STATIC

pytestmark = pytest.mark.usefixtures("no_outside")

# the modules that hold the library's plugin bases, imported before any guard (as tests/test_internal.py does)
BASES = ("liminal_libs.sources.publisher", "liminal_libs.sources.registry", "liminal_libs.assistants.plugin",
         "liminal_libs.machines.admin", "liminal_libs.machines.firewall", "liminal_libs.machines.wsl",
         "liminal_libs.machines.ai", "liminal_libs.machines.modelserver", "liminal_libs.machines.harness",
         "liminal_libs.storage.databases")
for _name in BASES:
    importlib.import_module(_name)
WORDS = ("PLUGIN_ONLY_HOOKS", "PAGE_ONLY_HOOKS")
BEFORE = ("READ_HOOKS", "SERVICE_HOOKS", "JOB_HOOKS", "CANCEL_HOOKS")  # DECLARED as it was before the two words
CALLED: list[str] = []


class Called(BaseException):
    """A stand-in's hook was called (a BaseException, so no `except Exception` of the code under test hides it)."""


def called(name: str):
    CALLED.append(name)
    raise Called(name)


@pytest.fixture(autouse=True)
def nothing_called():
    CALLED.clear()
    yield
    assert CALLED == [], f"internal.py called a plugin's {CALLED}"


class Gated(MachinePlugin):
    """A plugin with hooks of both words (as the MCP plugin has them), a service, a plain hook and a tab."""

    name, title = "gated", "Gated"
    HOOKS = (*MachinePlugin.HOOKS, "decide", "grant", "waiting", "board", "mint", "end", "offer", "plain")
    READ_HOOKS = ("waiting", "board", "offer")
    SERVICE_HOOKS = ("offer", "mint")
    PLUGIN_ONLY_HOOKS = ("mint", "end")
    PAGE_ONLY_HOOKS = ("decide", "grant", "waiting", "board")
    TABS = (Tab("board", "Its board", "board", 5.0),)

    def decide(self, ticket, answer, accept=False):
        """The page's answer to a call that waits."""
        called("decide")

    def grant(self, name, what, how):
        """What an agent is granted."""
        called("grant")

    def waiting(self, ticket):
        """A call that waits, whole."""
        called("waiting")

    def board(self):
        """Its tab's board."""
        called("board")

    def mint(self):
        """A token for the asking plugin's agent."""
        called("mint")

    def end(self, token):
        """A token ended."""
        called("end")

    def offer(self):
        """How an agent is wired to it."""
        called("offer")

    def plain(self):
        """A hook anyone may ask."""
        called("plain")


class Asker(MachinePlugin):
    """A plugin asking two of Gated's hooks, and a hook only Gated's page asks of whichever plugin offers it."""

    name, title = "asker", "Asker"
    ASKS = (("gated", "decide", "it would decide for the page"), ("gated", "mint", "a token for its agent"),
            ("gated", "plain"), ("", "decide"), ("", "mint"))


class Plain(MachinePlugin):
    """A plugin that says neither word: a read, a change, a service and a tab."""

    name, title = "plain", "Plain"
    HOOKS = (*MachinePlugin.HOOKS, "look", "poke", "lend", "page")
    READ_HOOKS = ("look",)
    SERVICE_HOOKS = ("lend",)
    TABS = (Tab("page", "Its page", "page", 3.0),)

    def look(self):
        """What it holds."""
        called("look")

    def poke(self, what):
        """A change."""
        called("poke")

    def lend(self, what):
        """What it lends other plugins."""
        called("lend")

    def page(self):
        """Its tab's page."""
        called("page")


def rows(got: dict) -> dict:
    return {h["name"]: h for h in got["hooks"]}


# -- the words, declared ---------------------------------------------------------------------------------------------
def test_both_words_join_the_declared_words_after_the_four_there_were():
    assert internal.DECLARED == (*BEFORE, *WORDS)
    assert (internal.PLUGIN_ONLY, internal.PAGE_ONLY) == WORDS
    assert internal.plugin_only(Gated()) == ("mint", "end")
    assert internal.page_only(Gated()) == ("decide", "grant", "waiting", "board")
    # a plugin that says neither has none, a class as an instance
    for plugin in (Plain(), Plain, Asker(), MachinePlugin(), Plugin()):
        assert internal.plugin_only(plugin) == () and internal.page_only(plugin) == ()
        assert internal.declared(plugin, internal.PLUGIN_ONLY) == () == internal.declared(plugin, internal.PAGE_ONLY)


def test_a_subclass_adds_to_its_bases_words_and_cannot_take_them_back():
    class More(Gated):
        name = "more"
        HOOKS = (*Gated.HOOKS, "revoke")
        PLUGIN_ONLY_HOOKS = ()  # says nothing more: the base's stay
        PAGE_ONLY_HOOKS = ("revoke", "decide")

        def revoke(self, name):
            """Its tokens revoked."""
            called("revoke")

    assert internal.plugin_only(More()) == ("mint", "end")
    assert internal.page_only(More()) == ("revoke", "decide", "grant", "waiting", "board")
    one = More()
    one.PAGE_ONLY_HOOKS = ("plain",)  # the instance's own come first, the classes' all the same
    assert internal.page_only(one) == ("plain", "revoke", "decide", "grant", "waiting", "board")
    assert internal.problems(More()) == []


def test_a_word_that_cannot_be_read_is_refused_by_its_readers_and_said_by_problems():
    class Loose(Gated):
        name = "loose"
        PAGE_ONLY_HOOKS = "decide"  # a str, not a tuple of str: as good as nothing to declared(), so a gate refuses

    class Failing(Gated):
        name = "failing"

        @property
        def PLUGIN_ONLY_HOOKS(self):  # noqa: N802 - a declared word, read as one
            raise RuntimeError("its tokens' table is not there")

    with pytest.raises(ValueError, match=r"^PAGE_ONLY_HOOKS must be a tuple of str$"):
        internal.page_only(Loose())
    assert internal.plugin_only(Loose()) == ("mint", "end")
    with pytest.raises(ValueError, match=r"^PLUGIN_ONLY_HOOKS cannot be read \(RuntimeError: its tokens"):
        internal.plugin_only(Failing())
    assert internal.declared(Loose(), internal.PAGE_ONLY) == ("decide", "grant", "waiting", "board")  # (Gated's)
    assert internal.declared(Failing(), internal.PLUGIN_ONLY) == ("mint", "end")  # lenient, as it always was
    assert "plugin 'loose': PAGE_ONLY_HOOKS must be a tuple of str" in internal.problems(Loose())
    assert internal.problems(Failing()) == [
        "plugin 'failing': PLUGIN_ONLY_HOOKS cannot be read (RuntimeError: its tokens' table is not there)"]
    # its Internal API is made all the same, without raising
    assert json.loads(json.dumps(internal.internal_of(Failing())))["name"] == "failing"


# -- the words, checked ----------------------------------------------------------------------------------------------
def test_problems_holds_each_word_to_its_hooks_and_the_two_apart():
    assert internal.problems(Gated()) == []

    class Wrong(Gated):
        name = "wrong"
        SERVICE_HOOKS = ("grant",)  # a service other plugins ask, yet its page alone may
        PLUGIN_ONLY_HOOKS = ("ghost", "plain")
        PAGE_ONLY_HOOKS = ("phantom", "plain")
        TABS = (Tab("board", "Its board", "board", 5.0), Tab("tokens", "Tokens", "mint", 5.0))

    assert internal.problems(Wrong()) == [
        "plugin 'wrong': PLUGIN_ONLY_HOOKS names 'ghost', which is not among its HOOKS",
        "plugin 'wrong': PAGE_ONLY_HOOKS names 'phantom', which is not among its HOOKS",
        "plugin 'wrong': 'plain' is said to be asked only by other plugins (PLUGIN_ONLY_HOOKS) and only from its page "
        "(PAGE_ONLY_HOOKS): no one could ask it",
        "plugin 'wrong': 'grant' is a service other plugins ask (SERVICE_HOOKS), yet only its page may ask it "
        "(PAGE_ONLY_HOOKS)",
        "plugin 'wrong': tab 'tokens': its hook 'mint' is asked only by other plugins (PLUGIN_ONLY_HOOKS), yet its "
        "page asks a tab's hook"]

    class Shapeless(MachinePlugin):
        name = "shapeless"
        PLUGIN_ONLY_HOOKS = ["status", 7]
        PAGE_ONLY_HOOKS = None

    assert internal.problems(Shapeless()) == ["plugin 'shapeless': PLUGIN_ONLY_HOOKS must be a tuple of str",
                                              "plugin 'shapeless': PAGE_ONLY_HOOKS must be a tuple of str"]


def test_a_plugin_that_says_neither_word_has_the_problems_it_had():
    """What problems() said before the two words, it says now: no rule of theirs bites a plugin that says neither."""

    class Unsound(MachinePlugin):
        name = "unsound"
        HOOKS = (*MachinePlugin.HOOKS, "poke", "mute")
        READ_HOOKS = ("poke", "ghost")
        SERVICE_HOOKS = "poke"
        TABS = (Tab("nowhere", "Nowhere", "absent", 5.0),)

        def poke(self, what, accept_risk=False):
            """A change asked twice."""
            called("poke")

        def mute(self):
            called("mute")

    said = ["plugin 'unsound': SERVICE_HOOKS must be a tuple of str",
            "plugin 'unsound': READ_HOOKS names 'ghost', which is not among its HOOKS",
            "plugin 'unsound': 'poke' is said to only read (READ_HOOKS) yet takes 'accept_risk': an argument that "
            "accepts a refusal belongs to a change",
            "plugin 'unsound': hook 'mute' says nothing of itself: the first sentence of its docstring is its line on "
            "the Internal API tab",
            "plugin 'unsound': tab 'nowhere': its hook 'absent' is not a hook"]
    assert internal.problems(Unsound()) == said
    assert internal.problems(Plain()) == [] == internal.problems(Asker())


def _library_plugin_classes() -> list[type]:
    """The library's plugin classes: Plugin's subclasses defined in liminal_libs, those of the modules BASES names and
    whatever else is loaded (a test's own subclasses are left out)."""
    found, todo = [], [Plugin]
    while todo:
        for sub in todo.pop().__subclasses__():
            if sub not in found and (sub.__module__ or "").startswith("liminal_libs."):
                found.append(sub)
                todo.append(sub)
    return found


def test_every_plugin_class_of_the_library_that_says_neither_word_is_read_as_it_was(monkeypatch):
    classes = [c for c in _library_plugin_classes() if not any(w in vars(k) for k in c.__mro__ for w in WORDS)]
    assert len(classes) >= 10 and MachinePlugin in classes
    for cls in classes:
        assert internal.plugin_only(cls) == () and internal.page_only(cls) == (), cls
        assert not any(h["pluginOnly"] or h["pageOnly"] for h in internal.internal_of(cls)["hooks"]), cls
    now = {cls: internal.problems(cls) for cls in classes}
    monkeypatch.setattr(internal, "DECLARED", BEFORE)  # problems() as it read them before the two words
    assert {cls: internal.problems(cls) for cls in classes} == now


# -- the words, said for each hook -----------------------------------------------------------------------------------
def test_each_hook_says_whether_only_other_plugins_or_only_its_page_may_ask_it():
    got = internal.internal_of(Gated(), reads=("present",))
    assert json.loads(json.dumps(got)) == got
    by = rows(got)
    assert {n for n, h in by.items() if h["pluginOnly"]} == {"mint", "end"}
    assert {n for n, h in by.items() if h["pageOnly"]} == {"decide", "grant", "waiting", "board"}
    assert all(type(h["pluginOnly"]) is bool and type(h["pageOnly"]) is bool for h in by.values())
    # only other plugins ask it: used by "plugins", a service or not (`end` says it is no service)
    assert (by["mint"]["users"], by["mint"]["kind"]) == ("plugins", "service")
    assert (by["end"]["users"], by["end"]["kind"], by["end"]["askable"]) == ("plugins", "change", True)
    # its page alone asks it: by name, or as its tab's
    assert (by["decide"]["users"], by["decide"]["kind"], by["decide"]["askable"]) == ("named", "change", True)
    assert (by["waiting"]["users"], by["waiting"]["reads"]) == ("named", True)
    assert (by["board"]["users"], by["board"]["tab"]) == ("app", "board")
    assert (by["plain"]["users"], by["plain"]["pluginOnly"], by["plain"]["pageOnly"]) == ("named", False, False)
    # an app that does not ask a hook only other plugins ask (the platform's asks leave them out): still theirs
    askable = [n for n in internal.answers(Gated()) if n not in ("mint", "end")]
    narrowed = rows(internal.internal_of(Gated(), askable=askable))
    assert (narrowed["end"]["askable"], narrowed["end"]["users"]) == (False, "plugins")
    assert (narrowed["decide"]["askable"], narrowed["decide"]["users"]) == (True, "named")


def test_a_plugin_that_says_neither_word_has_its_rows_as_they_were():
    got = internal.internal_of(Plain(), reads=("present",), askable=["look", "poke"])
    by = rows(got)
    assert not any(h["pluginOnly"] or h["pageOnly"] for h in by.values())
    users = {n: h["users"] for n, h in by.items() if n in ("look", "poke", "lend", "page")}
    assert users == {"look": "named", "poke": "named", "lend": "plugins", "page": "app"}
    assert rows(internal.internal_of(Plain()))["status"]["users"] == ""  # left to the contract: not used here


def test_an_ask_of_a_hook_only_its_page_asks_is_said_to_be_refused_there():
    got = internal.internal_of(Asker(), known=[Gated(), Asker(), Plain()])
    here = {(a["plugin"], a["hook"]): a["here"] for a in got["asks"]}
    assert here[("gated", "decide")] == "gated answers decide only from its page: it refuses other plugins"
    assert here[("gated", "mint")] == "offered"
    assert here[("gated", "plain")] == "a hook there, not said to be a service"
    assert here[("", "decide")] == "no plugin offers it here"  # one its page alone asks is not counted
    assert here[("", "mint")] == "1 plugin offers it here"
    # Gated's decide is asked by no other plugin it would answer: whoever says so is listed, and refused (the tab)
    assert rows(internal.internal_of(Gated(), known=[Gated(), Asker()]))["decide"]["askedBy"] == ["asker"]


# -- the words, drawn ------------------------------------------------------------------------------------------------
JS = STATIC / "internal.js"


def _body(js: str, name: str) -> str:
    """A function's text, from `function name(` to the next line that starts another at its depth."""
    start = js.index(f"  function {name}(")
    rest = js[start + 2:]
    end = re.search(r"\n  (?:function |const |let |// )", rest)
    return rest[: end.start()] if end else rest


def test_the_internal_api_tab_draws_both_words():
    js = JS.read_text(encoding="utf-8")
    tags = _body(js, "tagsHtml")
    for line in ("if (h.pluginOnly === true) tags.push(['asked only by other plugins', 'in-only']);",
                 "if (h.pageOnly === true) tags.push(['asked only from its page', 'in-only']);"):
        assert line in tags, line
    assert tags.index("'asked twice: '") < tags.index("'asked only by other plugins'") < tags.index("its page asks it")
    who = _body(js, "whoHtml")
    assert "if (h.pageOnly === true && h.users === 'named') {" in who
    assert "const pageLines = ['asked by name: from its page alone, never by another plugin'];" in who
    assert "if (by.length) pageLines.push('other plugins here say they ask it, and are refused: ' + and(by));" in who
    assert "return pageLines.map((w) => `<span class=\"in-who\">${esc(w)}</span>`).join('');" in who
    # what an ask finds there that will not answer it is a warning
    assert ("const WARN_HERE = /^no plugin offers|offers no |not installed|not said to be a service|only from its "
            "page/;") in js
    assert "const hereCls = (w) => (WARN_HERE.test(w) ? 'in-warn'" in _body(js, "asksHtml")
    css = js.split("const STYLE = `", 1)[1].split("`;", 1)[0]
    assert ".in-tag.in-only{border-color:var(--accent);color:var(--accent)}" in css
    # the words come from the rows internal.py sends, by the same names
    row = rows(internal.internal_of(Gated()))["mint"]
    assert {"pluginOnly", "pageOnly"} <= set(row) and "h.pluginOnly" in js and "h.pageOnly" in js
