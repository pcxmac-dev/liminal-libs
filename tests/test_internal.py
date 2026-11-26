"""liminal_libs.internal, a plugin's side (liminal-libs 1.63.0): what a plugin shares with the rest of its app, read
from the object itself (DECISIONS.md part C; addendum 14: every plugin is middleware, so its base's standard interface
comes first, then its own hooks, and each hook says who uses it). On stand-ins written here, every hook of which
raises if it is called: nothing of a plugin is called or evaluated, no process is started and nothing is reached."""
from __future__ import annotations

import ast
import enum
import inspect
import json
import re
import sys
from pathlib import Path

import pytest

from liminal_libs import internal
from liminal_libs.apps.tabs import Tab
from liminal_libs.assistants.plugin import AssistantPlugin
from liminal_libs.machines.admin import Admin
from liminal_libs.machines.firewall import Firewall
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.machines.wsl import WslDistribution
from liminal_libs.sources.apis import Api
from liminal_libs.sources.keys import KeyVar
from liminal_libs.sources.plugin import FeedPlugin
from liminal_libs.sources.publisher import Policy, Publisher, PublisherPlugin
from liminal_libs.sources.registry import Provider
from liminal_libs.storage.databases import DatabasePlugin

pytestmark = pytest.mark.usefixtures("no_outside")

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


class Shared(MachinePlugin):
    """A machine plugin with a hook of every kind, every one of which raises if it is called."""

    name, title = "shared", "Shared"
    HOOKS = (*MachinePlugin.HOOKS, "refresh", "poke", "risky", "fetch", "page", "serve", "offer", "lend", "quiet")
    READ_HOOKS = ("refresh", "status")
    SERVICE_HOOKS = ("serve", "offer", "lend")
    JOB_HOOKS = ("fetch", "lend")
    CANCEL_HOOKS = ("fetch",)
    TABS = (Tab("page", "Its page", "page", 3.0),)
    keys = (KeyVar("SHARED_API_KEY", label="Shared's key", hint="from its console"),
            KeyVar("SHARED_ACCOUNT", label="account", secret=False))
    plan_vars = ("SHARED_PLAN",)
    options = ("SHARED_DEPTH", "SHARED_PLAN")
    ASKS = (("other", "lend", "what it lends"), ("other", "plain"), ("other", "absent"), ("ghost", "watch"),
            ("", "plain"), ("", "nowhere"))
    KEEPS = (("SHARED_STATE", "its state between starts"),)
    INTERNAL_NOTES = ("Its watch stops itself a minute after its last read.",)
    STEPS = ("one", "two")
    SECTION = "os"
    ICON = "shared"
    apis = (Api("Its command line", "Its maker", "what it runs"), Api("Its kernel interface", "Its maker", "the rest"))

    def status(self) -> dict:
        """Its state, for the platform's page.

        A second paragraph its line leaves out."""
        called("status")

    def refresh(self) -> dict:
        """What it reads, read again now (the page's
        Read again). Its second sentence."""
        called("refresh")

    def poke(self, what, times=1) -> dict:
        """A change of what it holds."""
        called("poke")

    def risky(self, what, accept_risk=False, *, accept_loss=False) -> dict:
        """A change asked twice."""
        called("risky")

    def fetch(self, url="", log=print) -> dict:
        """A download, run as a job."""
        called("fetch")

    def page(self) -> dict:
        """Its tab's page."""
        called("page")

    def serve(self, watch_id, since=0) -> dict:
        """What other plugins ask, and the app's code too."""
        called("serve")

    def offer(self, kinds) -> dict:
        """What only other plugins ask."""
        called("offer")

    def lend(self, what) -> dict:
        """A service that is also a job."""
        called("lend")

    def quiet(self) -> dict:
        """A hook the app does not ask here."""
        called("quiet")

    def settings_changed(self) -> None:
        """Its settings were kept: what it reads, read again."""
        called("settings_changed")


class Other(MachinePlugin):
    """A second plugin, offering a service and a plain hook, and asking two of Shared's."""

    name, title = "other", "Other"
    HOOKS = (*MachinePlugin.HOOKS, "lend", "plain")
    SERVICE_HOOKS = ("lend",)
    ASKS = (("shared", "offer", "its kinds"), ("", "serve"))

    def lend(self, what):
        """What it lends."""
        called("other.lend")

    def plain(self):
        """A hook of its own."""
        called("other.plain")


class Third(MachinePlugin):
    """A third plugin, offering the plain hook too."""

    name = "third"
    HOOKS = (*MachinePlugin.HOOKS, "plain")

    def plain(self):
        """Its plain hook."""
        called("third.plain")


class Wall(Firewall):
    """A firewall built on the library's Firewall: its hooks, its tab and its job are the base's."""

    name, title = "wall", "Wall"
    HOOKS = (*Firewall.HOOKS, "refresh")

    def status(self) -> dict:
        called("wall.status")

    def refresh(self) -> dict:
        """The rules read again now."""
        called("wall.refresh")


CALLS = {"present": "whether it is there", "status": "its state, with each status", "serve": "its watch, for the page",
         "fetch": "as a job", "page": "its tab", "settings_changed": "after its settings were kept",
         "attach": "while it is enabled", "nothing_here": "a name it has not"}
ASKABLE = {"refresh", "poke", "risky", "fetch", "page", "serve", "offer", "lend"}


def rows(got: dict) -> dict:
    return {h["name"]: h for h in got["hooks"]}


# -- what kind of middleware it is: its base, the base's line, the standard interfaces ------------------------------
def test_a_firewall_is_built_on_firewall_and_implements_its_three_standard_layers_before_its_own():
    got = internal.internal_of(Wall())
    assert got["builtOn"]["class"] == "Firewall" and got["builtOn"]["module"] == "liminal_libs.machines.firewall"
    assert got["builtOn"]["line"].startswith("The base of the firewall plugins.")
    assert [c["class"] for c in got["chain"]] == ["Firewall", "MachinePlugin", "PlatformPlugin", "Plugin"]
    adds = [h for h in Firewall.HOOKS if h not in MachinePlugin.HOOKS]
    # the critique's count, Firewall's 9, and 1.65.0's 10 more (the Netstat tab, the hosts' recording, the globe's
    # filters and its layers' data sets), 1.74.0's world_watching, 1.75.0's world_asn and 1.101.0's three GeoIP sources'
    # hooks (download, use, remove), 1.104.0's three of the sky, 1.105.0's seven services the World Wide Web plugin asks,
    # and the seventeen of the tab and its globe (the sky's three among them) gone with it (machines/worldweb.py):
    # Firewall's 17, MachinePlugin's 5, Plugin's 2
    assert len(adds) == 17 and "netstat_seen" in adds and "hosts_keep_route" in adds
    assert not {"world", "world_watching", "world_asn", "world_geoip_get", "world_layer"} & set(adds)
    assert [(s["class"], s["hooks"]) for s in got["standard"]] == [
        ("Firewall", adds), ("MachinePlugin", ["present", "status", "setup", "run", "instances"]),
        ("Plugin", ["scan", "settings"])]
    assert [h["name"] for h in got["hooks"]] == [*adds, "present", "status", "setup", "run", "instances", "scan",
                                                 "settings", "refresh"]
    by = rows(got)
    assert (by["netstat"]["layer"], by["netstat"]["answered"]) == ("Firewall", "Firewall")  # the base's code answers
    assert (by["status"]["layer"], by["status"]["answered"]) == ("MachinePlugin", "itself")  # its own override
    assert (by["instances"]["layer"], by["instances"]["answered"]) == ("MachinePlugin", "")  # the contract's default
    assert (by["refresh"]["layer"], by["refresh"]["answered"]) == ("", "itself")  # its own hook
    assert by["status"]["line"] == internal.line_of(Firewall.status.__doc__)  # an override without one: its base's
    assert by["netstat_seen"]["kind"] == "service" and by["hosts_keep_route"]["kind"] == "service"
    assert by["rename_label"]["line"], "Firewall.rename_label says what it does (its line on every firewall's tab)"
    # 1.65.0: the Netstat tab's hook is a tab's; forgetting the hosts asked twice; the recording a change
    assert (by["netstat"]["kind"], by["netstat"]["tab"], by["netstat"]["every"]) == ("tab", "netstat", 3.0)
    assert by["hosts_forget"]["twice"] == ["accept_forget"]
    assert {by[h]["kind"] for h in ("hosts_recording", "hosts_forget")} == {"change"}
    assert all(by[h]["line"] for h in adds), "each of the base's hooks says what it does"
    # 1.105.0: the seven services in, the World Wide Web tab's seventeen out (1.104.0's sky among them)
    assert got["counts"]["standard"] == 24 and got["counts"]["own"] == 1
    assert got["left"] == ["present", "run", "instances", "scan", "settings"]  # MachinePlugin's defaults (CONTRACT)


def test_a_record_is_built_on_its_record_form_its_callbacks_its_own_and_the_rest_the_contracts():
    rec = Provider(name="rec", title="Rec", build=lambda settings, budget: None, assets=frozenset({"stock"}),
                   view=lambda base: base, keys=(KeyVar("REC_API_KEY"),))
    got = internal.internal_of(rec)
    assert got["builtOn"]["class"] == "Provider" and got["kind"] == "feed" and got["system"] == "integrator"
    assert [c["class"] for c in got["chain"]] == ["Provider", "FeedPlugin", "IntegratorPlugin", "Plugin"]
    assert [s["class"] for s in got["standard"]] == ["FeedPlugin", "Plugin"]
    by = rows(got)
    assert (by["build"]["answered"], by["build"]["args"], by["build"]["layer"]) == ("itself", "(settings, budget)",
                                                                                    "FeedPlugin")
    assert by["build"]["line"] == internal.line_of(FeedPlugin.build.__doc__)  # a callback without a docstring
    assert by["view"]["answered"] == "itself" and by["view"]["args"] == "(base)"
    assert (by["rate"]["answered"], by["rate"]["args"]) == ("", "(settings)")  # left: the contract's method
    assert "rate" in got["left"] and "build" not in got["left"] and "scan" in got["left"]
    assert got["settings"] == [{"variable": "REC_API_KEY", "pair": "rec-api-key", "label": "API key", "secret": True,
                                "hint": ""}]
    assert internal.problems(rec) == []
    pub = Publisher(name="pub", title="Pub", about="a publisher", feeds=(), policy=Policy(), moments=lambda day: ())
    got = internal.internal_of(pub)
    assert got["builtOn"]["class"] == "Publisher" and rows(got)["moments"]["answered"] == "itself"
    assert rows(got)["calendar"]["answered"] == "" and rows(got)["calendar"]["args"] == "(today)"
    assert internal.problems(pub) == []


# -- each hook: its kind, who uses it, its words ------------------------------------------------------------------
def test_a_hooks_kind_is_the_first_that_holds_and_who_uses_it_is_said_for_each():
    got = internal.internal_of(Shared(), reads=("present",), calls=CALLS, askable=ASKABLE)
    by = rows(got)
    kinds = {n: h["kind"] for n, h in by.items()}
    assert kinds == {"present": "own", "status": "own", "setup": "change", "run": "change", "instances": "change",
                     "scan": "change", "settings": "change", "refresh": "read", "poke": "change", "risky": "change",
                     "fetch": "job", "page": "tab", "serve": "service", "offer": "service", "lend": "service",
                     "quiet": "change"}
    assert by["lend"]["job"] and not by["serve"]["job"]  # a service that is a job keeps its job flag
    assert by["fetch"]["cancels"] and not by["lend"]["cancels"]
    users = {n: h["users"] for n, h in by.items()}
    assert users["serve"] == "both" and users["offer"] == "plugins" and users["lend"] == "plugins"
    assert users["status"] == "app" and users["page"] == "app" and users["fetch"] == "app" and users["present"] == "app"
    assert users["refresh"] == "named" and users["poke"] == "named" and users["quiet"] == "" and users["scan"] == ""
    assert set(users.values()) == set(internal.USERS)
    assert by["status"]["how"] == "its state, with each status" and by["poke"]["how"] == ""
    assert by["quiet"]["askable"] is False and by["poke"]["askable"] is True
    assert by["page"]["tab"] == "page" and by["page"]["every"] == 3.0 and by["page"]["reads"]
    assert by["refresh"]["reads"] and by["present"]["reads"] and not by["poke"]["reads"]
    assert by["risky"]["twice"] == ["accept_risk", "accept_loss"] and by["poke"]["twice"] == []
    # with no askable said, every hook it answers is asked by name (the frame's ask)
    plain = rows(internal.internal_of(Shared()))
    assert plain["quiet"]["users"] == "named" and plain["quiet"]["askable"] and not plain["present"]["askable"]
    assert plain["status"]["kind"] == "read" and plain["serve"]["users"] == "plugins"


def test_the_counts_say_its_hooks_layers_and_kinds():
    got = internal.internal_of(Shared(), reads=("present",), calls=CALLS, askable=ASKABLE)
    assert got["counts"] == {"hooks": 16, "answered": 10, "standard": 7, "own": 9, "left": 6,
                             "kinds": {"read": 1, "tab": 1, "change": 3, "job": 1, "service": 3, "own": 1}}
    assert got["left"] == ["present", "setup", "run", "instances", "scan", "settings"]
    assert [h["name"] for h in got["hooks"]][:7] == ["present", "status", "setup", "run", "instances", "scan",
                                                     "settings"]


def test_what_the_apps_code_calls_outside_its_hooks_is_an_also_row_when_it_has_it():
    got = internal.internal_of(Shared(), calls=CALLS)
    assert [(a["name"], a["how"]) for a in got["also"]] == [("settings_changed", "after its settings were kept"),
                                                             ("attach", "while it is enabled")]
    attach = got["also"][1]
    assert attach["args"] == "(app, login)" and attach["line"].startswith("Attached by `app`")
    assert got["also"][0]["line"] == "Its settings were kept: what it reads, read again."


def test_the_words_the_app_is_asked_in_are_carried_as_calls():
    words = {"plugins": "self.app.ask('shared', hook, [arguments])", "terms": "a machine plugin's hooks", 3: "x",
             "clients": None}
    got = internal.internal_of(Shared(), words=words)
    assert got["calls"] == {"plugins": "self.app.ask('shared', hook, [arguments])", "terms": "a machine plugin's hooks"}
    assert internal.internal_of(Shared())["calls"] == {}


def test_a_hooks_line_is_its_first_sentence_and_its_doc_the_whole_docstring():
    by = rows(internal.internal_of(Shared()))
    assert by["refresh"]["line"] == "What it reads, read again now (the page's Read again)."  # over two lines
    assert by["status"]["line"] == "Its state, for the platform's page."  # the first paragraph only
    assert by["status"]["doc"] == "Its state, for the platform's page.\n\nA second paragraph its line leaves out."
    assert internal.line_of(None) == "" and internal.line_of("   ") == "" and internal.doc_of(None) == ""
    assert internal.line_of("One `thing`. `Two` more.") == "One `thing`."
    assert internal.line_of("Ends (in brackets). (Then more.)") == "Ends (in brackets)."
    assert internal.line_of("A version 1.2 stays. Then") == "A version 1.2 stays."
    cut = internal.line_of("word " * 100)
    assert len(cut) == internal.LINE_CHARS and cut.endswith("…")
    long = internal.doc_of("A first line.\n\n" + "more " * 400)
    assert len(long) == internal.DOC_CHARS and long.endswith("…") and long.startswith("A first line.\n\n")

    class Over(Shared):
        def poke(self, what, times=1):
            called("over.poke")

    assert rows(internal.internal_of(Over()))["poke"]["line"] == "A change of what it holds."  # a base's, inherited


class Color(enum.IntEnum):
    RED = 1


class Thing:
    pass


class Arguments(MachinePlugin):
    """Hooks with arguments of every form."""

    name = "arguments"
    HOOKS = (*MachinePlugin.HOOKS, "plain", "starred", "keyword", "positional", "defaults", "long", "objects", "static",
             "klass", "prop")

    def plain(self, name, ports, protocol: str = "tcp") -> list:
        """Plain."""

    def starred(self, *command: str, **options) -> str:
        """Starred."""

    def keyword(self, path, *, pin=None, accept_load=False):
        """Keyword only."""

    def positional(self, a, b=2, /, c=3):
        """Positional only."""

    def defaults(self, log=print, steps=None, flag=True, n=-1.5, empty=(), mapping={}, kind=dict):  # noqa: B006
        """Defaults said by their repr or name."""

    def long(self, words="x" * 60):
        """A long default, cut."""

    def objects(self, color=Color.RED, thing=Thing(), fn=lambda: 0, items=("a",)):  # noqa: B008
        """Objects, never their repr."""

    @staticmethod
    def static(a, b=1):
        """A static method."""

    @classmethod
    def klass(cls, a):
        """A class method."""

    @property
    def prop(self):
        """A property, never read."""
        called("prop")


def test_a_hooks_arguments_are_said_as_it_is_called_never_an_objects_repr():
    by = rows(internal.internal_of(Arguments()))
    said = {n: by[n]["args"] for n in Arguments.HOOKS if n not in MachinePlugin.HOOKS}
    assert said == {"plain": "(name, ports, protocol='tcp')", "starred": "(*command, **options)",
                    "keyword": "(path, *, pin=None, accept_load=False)", "positional": "(a, b=2, /, c=3)",
                    "defaults": "(log=print, steps=None, flag=True, n=-1.5, empty=(), mapping={}, kind=dict)",
                    "long": "(words='" + "x" * 37 + "...')", "objects": "(color=..., thing=..., fn=..., items=...)",
                    "static": "(a, b=1)", "klass": "(a)", "prop": ""}
    assert by["prop"]["property"] is True and by["prop"]["line"] == "A property, never read."
    assert by["keyword"]["twice"] == ["accept_load"]
    assert internal.args_of(Arguments().plain) == "(name, ports, protocol='tcp')"  # a bound method: no self
    assert internal.args_of(Arguments.plain) == "(self, name, ports, protocol='tcp')"  # the function as it is
    assert internal.args_of(len) == "(obj, /)"  # a builtin's, from its text signature
    assert internal.args_of(print).startswith("(*") and "sep=' '" in internal.args_of(print)
    assert internal.args_of(object()) == "" and internal.args_of(None) == ""

    class Unreadable:
        def __call__(self, *a):
            pass

        @property
        def __signature__(self):
            raise ValueError("no signature")

    assert internal.args_of(Unreadable()) == "(...)"


@pytest.mark.skipif(sys.version_info < (3, 14), reason="annotations are deferred from Python 3.14 on")
def test_a_hooks_annotations_are_never_evaluated():
    space: dict = {}
    source = "def hook(self, x: Nowhere = 1) -> Nowhere:\n    'A hook whose annotations name nothing.'\n"
    exec(compile(source, "<a plugin's module>", "exec", dont_inherit=True), space)  # (not this file's __future__)
    with pytest.raises(NameError):
        inspect.signature(space["hook"])  # what reading them would do
    assert internal.args_of(space["hook"]) == "(self, x=1)"

    class Annotated(MachinePlugin):
        name = "annotated"
        HOOKS = (*MachinePlugin.HOOKS, "hook")
        hook = space["hook"]

    assert rows(internal.internal_of(Annotated()))["hook"]["args"] == "(x=1)"


# -- nothing of a plugin evaluated --------------------------------------------------------------------------------
class Touchy(MachinePlugin):
    """Properties that must never be read: a hook that is one, one counting its reads, and one the app reads by name."""

    name = "touchy"
    HOOKS = (*MachinePlugin.HOOKS, "peek", "gauge")
    seen: list = []

    @property
    def peek(self):
        """A hook that is a property, raising when it is read."""
        called("peek")

    @property
    def gauge(self):
        """A property counting its reads."""
        Touchy.seen.append("gauge")
        return 1

    @property
    def distribution_name(self):
        """An attribute the app reads by name."""
        called("distribution_name")

    @property
    def ICON(self):
        """A class constant made a property: not a constant, so not given by value."""
        called("ICON")


def test_a_property_is_said_as_one_and_never_read():
    Touchy.seen.clear()
    got = internal.internal_of(Touchy(), calls={"gauge": "its gauge", "distribution_name": "its name"},
                               attributes=("name", "distribution_name", "ICON"), known=[Touchy(), Shared()])
    by = rows(got)
    assert by["peek"]["property"] and by["peek"]["args"] == "" and by["peek"]["line"].startswith("A hook that is")
    assert by["gauge"]["property"] and by["gauge"]["how"] == "its gauge"
    assert [(a["name"], a["property"]) for a in got["also"]] == [("distribution_name", True)]
    assert got["attributes"] == ["name", "distribution_name", "ICON"] and "ICON" not in got["declares"]
    assert "ICON" not in internal.internal_of(Touchy())["declares"]
    assert internal.problems(Touchy()) == []
    assert Touchy.seen == []


def test_nothing_of_a_plugin_is_called_and_the_answer_is_plain_json():
    for plugin in (Shared(), Other(), Wall(), Arguments(), Touchy()):
        got = internal.internal_of(plugin, reads=("present", "status"), calls=CALLS, askable=ASKABLE,
                                   known=[Shared(), Other(), Wall()], words={"terms": "any hook"},
                                   attributes=("name", "SECTION"))
        assert json.loads(json.dumps(got)) == got  # plain JSON: no tuple, no set, no object
        assert got["v"] == internal.VERSION and got["of"] == "plugin"
        assert internal.problems(plugin) == []
    # (the autouse fixture asserts that no hook of theirs was called)


def test_an_object_that_is_no_plugin_or_a_class_still_gets_an_answer():
    got = internal.internal_of(object())
    assert got["hooks"] == [] and got["builtOn"] == {"class": "", "module": "", "line": ""} and got["name"] == ""
    assert internal.problems(object()) == []
    of_class = internal.internal_of(Shared)
    assert rows(of_class)["poke"]["args"] == "(what, times=1)" and of_class["name"] == "shared"

    class Broken(Shared):
        @property
        def keys(self):
            raise RuntimeError("its keys cannot be made")

    got = internal.internal_of(Broken())
    assert got["settings"] == [] and len(got["hooks"]) == 16  # the part that cannot be read is left empty


def test_the_hooks_listed_are_at_most_max_hooks():
    names = [f"hook{i}" for i in range(internal.MAX_HOOKS + 10)]

    def make(n):
        def hook(self):
            called(n)
        hook.__doc__ = f"Hook {n}."
        return hook

    many = type("Many", (MachinePlugin,), {"name": "many", "HOOKS": (*MachinePlugin.HOOKS, *names),
                                           **{n: make(n) for n in names}})
    got = internal.internal_of(many())
    assert len(got["hooks"]) == internal.MAX_HOOKS == got["counts"]["hooks"]
    assert len(json.dumps(got)) < 200_000


# -- what it reads, keeps and asks; its tabs, steps, notes; what it sits on --------------------------------------------
def test_reads_are_the_apps_its_tabs_and_what_it_says_only_reads():
    assert internal.reads_of(Shared()) == ("page", "refresh", "status")
    tabs = [{"id": "x", "title": "X", "hook": "elsewhere", "every": 5.0}]
    assert internal.reads_of(Shared(), reads=("present", "status"), tabs=tabs) == ("present", "status", "elsewhere",
                                                                                   "refresh")

    class Mixed(Shared):
        HOOKS = (*Shared.HOOKS, "outside")
        READ_HOOKS = ("fetch", "instances", "absent")  # a job, one left to the contract, one not among its HOOKS

        def absent(self):
            """Not among its HOOKS."""

    assert internal.reads_of(Mixed()) == ("page", "refresh", "status")
    assert internal.reads_of(MachinePlugin()) == ()  # a plugin that says nothing: the app's reads and its tabs'
    assert internal.reads_of(MachinePlugin(), reads=("present", "status")) == ("present", "status")


class Slip(MachinePlugin):
    """A plugin that says, by mistake, that a change asked twice only reads."""

    name = "slip"
    HOOKS = (*MachinePlugin.HOOKS, "wipe", "look")
    READ_HOOKS = ("wipe", "look")

    def wipe(self, what, accept_loss=False):
        """Wipes what it holds, asked a second time when the loss is accepted."""
        called("wipe")

    def look(self):
        """What it holds."""
        called("look")


def test_a_read_that_accepts_a_refusal_is_no_read_whatever_its_plugin_says():
    """A wrong READ_HOOKS would take a change asked twice out of the app's log (the platform's reads_of is this one):
    problems() says so, and reads_of leaves it out all the same, as it leaves out a job."""
    reads = ("present", "status")
    assert internal.reads_of(Slip(), reads) == ("present", "status", "look")
    by = rows(internal.internal_of(Slip(), reads=reads))
    assert (by["wipe"]["reads"], by["wipe"]["kind"], by["wipe"]["twice"]) == (False, "change", ["accept_loss"])
    assert (by["look"]["reads"], by["look"]["kind"]) == (True, "read")
    assert internal.problems(Slip()) == [
        "plugin 'slip': 'wipe' is said to only read (READ_HOOKS) yet takes 'accept_loss': an argument that accepts a "
        "refusal belongs to a change"]


def test_what_the_frame_reads_of_a_plugin_is_read_as_it_is_declared():
    """answers, kind_of and tabs_key, which the frame's askable and plugin_internal use (apps/app.py): what a plugin
    answers itself (Plugin.gives' rule), its KIND, and an app's list of its tabs as a key; a property never read."""
    Touchy.seen.clear()
    assert internal.answers(Shared()) == ("status", "refresh", "poke", "risky", "fetch", "page", "serve", "offer",
                                          "lend", "quiet")
    assert set(internal.answers(Shared())) == set(Shared().interface()["hooks"])  # what the frame's ask takes
    assert internal.answers(Touchy()) == ("peek", "gauge") and Touchy.seen == []  # its properties are not read
    assert internal.answers(MachinePlugin()) == () and internal.answers(object()) == ()
    rec = Provider(name="rec", title="Rec", build=lambda settings, budget: None, assets=frozenset({"stock"}))
    assert (internal.kind_of(Shared()), internal.kind_of(rec), internal.kind_of(object())) == ("machine", "feed", "")
    assert internal.tabs_key(Shared()) is None and internal.tabs_key(Shared(), []) == ()
    given = [Tab("page", "Page", "page", 9.0), {"id": "x", "title": "X", "hook": "poke"}, {"id": "none"}]
    assert internal.tabs_key(Shared(), given) == (("page", "Page", "page", 9.0), ("x", "X", "poke", None))
    assert internal.tabs_key(Shared(), tuple(given)) == internal.tabs_key(Shared(), given)  # by what they say


def test_declarations_of_names_add_to_their_bases_and_one_that_is_no_tuple_counts_as_none():
    class Sub(Shared):
        READ_HOOKS = ("poke",)

    assert internal.declared(Sub(), "READ_HOOKS")[:3] == ("poke", "refresh", "status")  # a base's names stay its own

    class Loose(Shared):
        READ_HOOKS = "poke"  # a str, not a tuple: nothing

    assert "poke" not in internal.declared(Loose(), "READ_HOOKS")
    assert rows(internal.internal_of(Loose()))["poke"]["kind"] == "change"
    assert "plugin 'shared': READ_HOOKS must be a tuple of str" in internal.problems(Loose())


def test_settings_options_keeps_steps_notes_tabs_and_what_it_sits_on():
    got = internal.internal_of(Shared())
    assert got["settings"] == [
        {"variable": "SHARED_API_KEY", "pair": "shared-api-key", "label": "Shared's key", "secret": True,
         "hint": "from its console"},
        {"variable": "SHARED_ACCOUNT", "pair": "shared-account", "label": "account", "secret": False, "hint": ""}]
    assert got["options"] == ["SHARED_PLAN", "SHARED_DEPTH"]
    assert got["keeps"] == [{"variable": "SHARED_STATE", "pair": "shared-state", "about": "its state between starts"}]
    assert got["steps"] == ["one", "two"] and got["notes"] == list(Shared.INTERNAL_NOTES)
    assert got["tabs"] == [{"id": "page", "title": "Its page", "hook": "page", "every": 3.0}]
    assert got["sitsOn"] == ["Its command line", "Its kernel interface"]
    assert got["declares"] == {"SECTION": "os", "ICON": "shared", "STEPS": ["one", "two"],
                               "JOB_HOOKS": ["fetch", "lend"]}
    named = internal.internal_of(Shared(), attributes=("name", "SECTION", "STEPS", "user"))
    assert named["attributes"] == ["name", "SECTION", "STEPS", "user"]
    assert named["declares"] == {"SECTION": "os", "STEPS": ["one", "two"]}  # the class constants among them, by value
    # the app's own list of its tabs, when it gives one (the platform's tabs_of)
    shown = internal.internal_of(Shared(), tabs=[{"id": "page", "title": "Page", "hook": "page", "every": 9.0}])
    assert shown["tabs"] == [{"id": "page", "title": "Page", "hook": "page", "every": 9.0}]
    flowing = internal.internal_of(Shared(), tabs=iter([{"id": "page", "title": "Page", "hook": "page", "every": 9.0}]))
    assert flowing["tabs"] == shown["tabs"] and rows(flowing)["page"]["reads"]  # an iterator, read once for both

    class Keeper(Shared):
        @property
        def KEEPS(self):
            return ((f"{self.name.upper()}_GROUPS", "its groups"), ("SHARED_STATE", "kept"))

    assert internal.internal_of(Keeper())["keeps"] == [
        {"variable": "SHARED_GROUPS", "pair": "shared-groups", "about": "its groups"},
        {"variable": "SHARED_STATE", "pair": "shared-state", "about": "kept"}]  # a property's rows, as it has them


def test_what_it_asks_says_what_it_finds_here_and_who_asks_its_hooks():
    known = [Shared(), Other(), Third()]
    got = internal.internal_of(known[0], known=known)
    assert [(a["plugin"], a["hook"], a["why"], a["here"]) for a in got["asks"]] == [
        ("other", "lend", "what it lends", "offered"),
        ("other", "plain", "", "a hook there, not said to be a service"),
        ("other", "absent", "", "other offers no absent here"),
        ("ghost", "watch", "", "not installed here"),
        ("", "plain", "", "2 plugins offer it here"),
        ("", "nowhere", "", "no plugin offers it here")]
    assert internal.internal_of(known[0], known=known[:2])["asks"][4]["here"] == "1 plugin offers it here"
    by = rows(got)
    assert by["offer"]["askedBy"] == ["other"] and by["serve"]["askedBy"] == ["other"] and by["poke"]["askedBy"] == []
    # the app said nothing of its plugins: nothing found, nobody known to ask
    alone = internal.internal_of(Shared())
    assert {a["here"] for a in alone["asks"]} == {""} and all(h["askedBy"] == [] for h in alone["hooks"])
    none_here = internal.internal_of(Shared(), known=())
    assert none_here["asks"][0]["here"] == "not installed here"
    assert none_here["asks"][5]["here"] == "no plugin offers it here"
    other = internal.internal_of(Other(), known={"shared": Shared(), "other": Other()})  # a mapping: by its values
    assert [(a["plugin"], a["hook"], a["here"]) for a in other["asks"]] == [("shared", "offer", "offered"),
                                                                            ("", "serve", "1 plugin offers it here")]


# -- problems: what a plugin's own test holds it to ---------------------------------------------------------------
class Bad(MachinePlugin):
    """Everything a plugin can say wrong of its Internal API."""

    name = "bad"
    HOOKS = (*MachinePlugin.HOOKS, "refresh", "grab", "risky", "silent", "missing", "job_read")
    READ_HOOKS = ("refresh", "elsewhere", "job_read", "risky")
    SERVICE_HOOKS = ("nowhere",)
    JOB_HOOKS = ("job_read",)
    CANCEL_HOOKS = "job_read"
    TABS = (Tab("tab", "Tab", "untold", 5.0),)
    ASKS = (("a",), ("ebpf", "watch_start"), ("ebpf", "watch_start", "again"), ("x", 3))
    KEEPS = (("ONLY",), ("V", "about"), ("V", "again"))
    INTERNAL_NOTES = ("x" * (internal.NOTE_CHARS + 1),)

    def refresh(self):
        """Reads."""

    def grab(self):
        """Grabs."""

    def risky(self, accept_risk=False):
        """Asked twice."""

    def silent(self):
        pass

    def job_read(self, log=print):
        """A job."""


def test_every_problem_is_said_in_words():
    assert internal.problems(Bad()) == [
        "plugin 'bad': CANCEL_HOOKS must be a tuple of str",
        "plugin 'bad': READ_HOOKS names 'elsewhere', which is not among its HOOKS",
        "plugin 'bad': SERVICE_HOOKS names 'nowhere', which is not among its HOOKS",
        "plugin 'bad': 'job_read' is said to only read (READ_HOOKS) and is one of its jobs",
        "plugin 'bad': 'risky' is said to only read (READ_HOOKS) yet takes 'accept_risk': an argument that accepts a "
        "refusal belongs to a change",
        "plugin 'bad': hook 'silent' says nothing of itself: the first sentence of its docstring is its line on the "
        "Internal API tab",
        "plugin 'bad': HOOKS names 'missing', which nothing of it defines",
        "plugin 'bad': ASKS: ('a',) is not (plugin, hook) or (plugin, hook, why), each a str",
        "plugin 'bad': ASKS: ('ebpf', 'watch_start') given twice",
        "plugin 'bad': ASKS: ('x', 3) is not (plugin, hook) or (plugin, hook, why), each a str",
        "plugin 'bad': KEEPS: ('ONLY',) is not (variable, about), each a str",
        "plugin 'bad': KEEPS: 'V' given twice",
        "plugin 'bad': INTERNAL_NOTES is a tuple of lines of at most 400 characters",
        "plugin 'bad': tab 'tab': its hook 'untold' is not a hook"]


def test_problems_of_a_declarations_form_and_size():
    class NoHooks(MachinePlugin):
        name = "nohooks"
        HOOKS = "present"

    said = internal.problems(NoHooks())
    assert said[0] == "plugin 'nohooks': HOOKS must be a tuple of str"
    assert said[1:] == [f"plugin 'nohooks': READ_HOOKS names {n!r}, which is not among its HOOKS"
                        for n in internal.declared(NoHooks(), "READ_HOOKS")]  # (its bases' reads: none is a hook now)

    class Loud(Shared):
        ASKS = tuple((f"p{i}", "hook") for i in range(internal.MAX_WORDS + 1))
        KEEPS = "SHARED_STATE"
        INTERNAL_NOTES = tuple(f"line {i}" for i in range(internal.MAX_WORDS + 1))

    assert internal.problems(Loud()) == [
        "plugin 'shared': ASKS holds 41 rows: the first 40 are read",
        "plugin 'shared': KEEPS is a tuple of rows, each (variable, about)",
        "plugin 'shared': INTERNAL_NOTES holds 41 lines: the first 40 are read"]

    class Failing(Shared):
        @property
        def KEEPS(self):
            raise RuntimeError("no login here")

    assert internal.problems(Failing()) == ["plugin 'shared': KEEPS cannot be read (RuntimeError: no login here)"]
    assert internal.internal_of(Failing())["keeps"] == []


def _subclass(base, **attributes):
    return type(f"Some{base.__name__}", (base,), {"__doc__": "A subclass that says nothing of its own.", **attributes})


@pytest.mark.parametrize("plugin", [
    _subclass(FeedPlugin, name="feed")(), _subclass(PublisherPlugin, name="pub")(),
    _subclass(AssistantPlugin, name="assistant", vendor="Its vendor")(), _subclass(MachinePlugin, name="machine")(),
    _subclass(Firewall, name="wall")(), _subclass(Admin, name="admin")(),
    _subclass(WslDistribution, name="wsl-x", distribution="Liminal-X")(), _subclass(DatabasePlugin, name="db")(),
], ids=lambda p: type(p).__mro__[1].__name__)
def test_a_plugin_of_each_kind_that_says_nothing_of_its_own_has_nothing_wrong(plugin):
    assert internal.problems(plugin) == []
    got = internal.internal_of(plugin)
    assert got["builtOn"]["class"] == type(plugin).__mro__[1].__name__
    assert json.loads(json.dumps(got)) == got and got["hooks"]
    assert all(h["answered"] != "itself" for h in got["hooks"])  # every hook its base's code or the contract's
    assert [n for layer in got["standard"] for n in layer["hooks"]] == [h["name"] for h in got["hooks"]]


def test_the_module_is_plain_the_standard_library_alone_and_names_no_host():
    source = Path(internal.__file__).read_text(encoding="utf-8")
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "no relative import: nothing of the contract or the apps comes with it"
            imported.add((node.module or "").split(".")[0])
    assert imported - {"__future__"} <= set(sys.stdlib_module_names), imported
    assert not re.search(r"[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9]", source)
    assert all(len(line) <= 120 for line in source.splitlines())
