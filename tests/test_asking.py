"""Who asks a hook (liminal_libs.apps.asking; the user, 2026-11-18: "now i need an MCP plugin for platform, basically
a protocol plugin that mediates MCP connections to resources by local AI agents"), and the frame's parts beside it
(apps/app.py): App.ask names the plugin that asks, App.present says whether the person at the page is shown to be
there, and App.start serves with web.Server.

The asker is handed over in so many words and never inherited: a thread started inside an ask has none, even one
started in a copy of its starter's context, as Python 3.14 can start one. A hook only its page may ask
(PAGE_ONLY_HOOKS), or only other plugins (PLUGIN_ONLY_HOOKS), is refused to anyone else, an asker that is not set
included. No clock is read here: each thread is joined, and where two run at once their order is forced with events.
No server is started, no login of Liminal's is made, and nothing is reached."""
from __future__ import annotations

import contextvars
import inspect
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace

import pytest

import liminal_libs.apps.app as frame
from liminal_libs import web
from liminal_libs.apps import App, PortTaken, asking
from liminal_libs.machines.plugin import MachinePlugin

pytestmark = pytest.mark.usefixtures("no_outside")

NOBODY = "This ask names no asker: neither the page nor a plugin."
INHERITS = "context" in inspect.signature(threading.Thread.__init__).parameters  # Python 3.14 and later


class Job:
    """A job as the platform runs one (its Setup): made where it is asked, the asker read there (asking.handed), its
    work run in a thread of its own, and joined."""

    def __init__(self, work):
        self.work = asking.handed(work)
        self.answer = self.refused = None
        self.thread = threading.Thread(target=self._run, name="a-job", daemon=True)

    def _run(self) -> None:
        try:
            self.answer = self.work()
        except asking.AskRefused as e:
            self.refused = e

    def start(self) -> "Job":
        self.thread.start()
        return self

    def joined(self) -> "Job":
        self.thread.join(10)
        assert not self.thread.is_alive()
        return self


class Gated(MachinePlugin):
    """A plugin with a hook only its page asks, one only other plugins ask, a plain one and a job of its own."""

    name, title = "gated", "Gated"
    HOOKS = (*MachinePlugin.HOOKS, "decide", "mint", "plain", "start")
    PAGE_ONLY_HOOKS = ("decide",)
    PLUGIN_ONLY_HOOKS = ("mint",)

    def decide(self, ticket):
        """The page's answer to a call that waits, and who asked it."""
        return {"ticket": ticket, "by": asking.asker()}

    def mint(self):
        """A token for the asking plugin's agent: the agent is the asker, never an argument."""
        return {"for": asking.asker()}

    def plain(self):
        """A hook anyone may ask, and who asked it."""
        return {"by": asking.asker()}

    def start(self, work):
        """A job of its own, started where it is asked."""
        return Job(work).start()

    def mint_own(self):
        """Not a hook: its own mint asked through its app."""
        return self.app.ask("gated", "mint")


class Harness(MachinePlugin):
    """A plugin that asks Gated through the app, as a harness asks the MCP plugin."""

    name, title = "harness", "Harness"

    def wants(self, hook, *args):
        """Not a hook: one of Gated's asked through the app."""
        return self.app.ask("gated", hook, *args)

    def begins(self, work):
        """Not a hook: Gated's job started on this plugin's ask."""
        return self.app.ask("gated", "start", work)

    def asks_of(self, name, hook, *args):
        """Not a hook: another plugin's hook asked through the app."""
        return self.app.ask(name, hook, *args)


class Open(MachinePlugin):
    """A plugin that says neither word."""

    name, title = "open", "Open"
    HOOKS = (*MachinePlugin.HOOKS, "look")

    def look(self):
        """What it holds, and who asked."""
        return {"by": asking.asker()}


class Demo(App):
    NAME, TITLE, ICON = "demo", "Demo", "chip"

    def route(self, name, hook, *args):
        """As an app's route for its page asks a hook: the page named, in so many words."""
        with asking.asking(asking.PAGE):
            return self.ask(name, hook, *args)

    def tick(self, name, hook, *args):
        """As the app's own code asks a hook on its own: no one named."""
        return self.ask(name, hook, *args)


def demo() -> tuple[Demo, Gated, Harness]:
    app = Demo(log=lambda m: None)
    gated, harness = Gated(), Harness()
    for plugin in (gated, harness, Open()):
        app.attach(plugin)
    return app, gated, harness


def asks(app, hook, *args):
    """The work of a job or of a bare thread: one of Gated's hooks asked through the app, by code no plugin owns."""
    return lambda: app.ask("gated", hook, *args)


def in_thread(fn, how: str = "bare"):
    """`fn` run in a thread of its own, joined: (its answer, its refusal). `how`: "bare", a thread as 3.12 and 3.13
    start one; "copied", one that runs in a copy of its starter's context (what asyncio.to_thread does, and what 3.14
    can do for any thread); "inherited", 3.14's threading.Thread(context=...); "pool", a pool's worker."""
    got: dict = {}

    def run():
        try:
            got["answer"] = fn()
        except asking.AskRefused as e:
            got["refused"] = e

    if how == "pool":
        with ThreadPoolExecutor(1) as pool:
            pool.submit(run).result(10)
        return got.get("answer"), got.get("refused")
    if how == "copied":
        context = contextvars.copy_context()
        thread = threading.Thread(target=lambda: context.run(run), daemon=True)
    elif how == "inherited":
        thread = threading.Thread(target=run, daemon=True, context=contextvars.copy_context())
    else:
        thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(10)
    assert not thread.is_alive()
    return got.get("answer"), got.get("refused")


THREADS = ("bare", "copied", "pool", *(("inherited",) if INHERITS else ()))


# -- the asker ---------------------------------------------------------------------------------------------------------
def test_no_one_asks_until_someone_is_named_and_a_block_puts_back_the_one_before():
    assert asking.asker() is None and asking.PAGE == "page"
    with asking.asking(asking.PAGE) as who:
        assert who == "page" == asking.asker()
        with asking.asking("harness"):
            assert asking.asker() == "harness"
            with asking.asking(None):  # a block that must carry no asker
                assert asking.asker() is None
            assert asking.asker() == "harness"
        assert asking.asker() == "page"
        with pytest.raises(KeyError):
            with asking.asking("harness"):
                raise KeyError("the hook failed")
        assert asking.asker() == "page"  # put back after a failure too
    assert asking.asker() is None
    for bad in ("", 7, b"page", object()):
        with pytest.raises(ValueError, match="an asker is 'page', a plugin's name or None"):
            with asking.asking(bad):
                pass
    assert asking.asker() is None


def test_a_thread_never_takes_an_asker_from_what_it_inherits():
    """ai-build-notes, L14: what a thread started inside a context sees differs across 3.12 to 3.15, so no gate may
    depend on it. In the thread that set it, a copy of its context still carries it."""
    for who in (asking.PAGE, "harness"):
        with asking.asking(who):
            for how in THREADS:
                assert in_thread(asking.asker, how) == (None, None), (who, how)
            assert contextvars.copy_context().run(asking.asker) == who  # the same thread: its own


def test_two_threads_asking_at_once_each_keep_their_own():
    first_set, second_done = threading.Event(), threading.Event()
    seen: dict = {}

    def first():
        with asking.asking("one"):
            first_set.set()
            seen["waited"] = second_done.wait(10)
            seen["first"] = asking.asker()
        seen["first after"] = asking.asker()

    def second():
        seen["began"] = first_set.wait(10)  # the first has set its own, and holds it, before this one sets another
        with asking.asking("two"):
            seen["second"] = asking.asker()
        seen["second after"] = asking.asker()
        second_done.set()

    threads = [threading.Thread(target=first, daemon=True), threading.Thread(target=second, daemon=True)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert not any(t.is_alive() for t in threads)
    assert seen == {"began": True, "waited": True, "first": "one", "first after": None, "second": "two",
                    "second after": None}


def test_a_job_carries_the_asker_it_was_started_with_into_its_thread():
    with asking.asking("harness"):
        run = asking.handed(asking.asker)
    with asking.asking(None):
        unnamed = asking.handed(asking.asker)
    for how in THREADS:
        assert in_thread(run, how) == ("harness", None), how
        assert in_thread(unnamed, how) == (None, None), how
    with asking.asking(asking.PAGE):
        assert run() == "harness"  # the record, in whatever thread runs it, this one too
        assert asking.asker() == "page"  # and put back after
    assert run.__name__ == asking.asker.__name__ and run.__wrapped__ is asking.asker


# -- a gated hook, held to its asker ---------------------------------------------------------------------------------
def test_who_may_ask_a_gated_hook_said_in_words():
    gated, open_ = Gated(), Open()
    page_only = "gated's decide is asked only from its page"
    plugins_only = "gated's mint is asked only by another plugin"
    cases = {
        ("decide", "page"): "", ("decide", None): f"{page_only}. {NOBODY}",
        ("decide", "harness"): f"{page_only}, never by another plugin: harness asked it.",
        ("mint", "harness"): "", ("mint", None): f"{plugins_only}. {NOBODY}",
        ("mint", "page"): f"{plugins_only}, never from a page or by a program.",
        ("mint", "gated"): f"{plugins_only}, not by gated itself.",
        ("plain", None): "", ("plain", "page"): "", ("plain", "harness"): ""}
    for (hook, who), words in cases.items():
        assert asking.refusal(gated, hook, who) == words, (hook, who)
    assert all(asking.refusal(open_, "look", who) == "" for who in (None, "page", "harness", "open"))

    class Both(Gated):
        name = "both"
        PAGE_ONLY_HOOKS = ("mint",)

    for who in (None, "page", "harness"):
        assert asking.refusal(Both(), "mint", who) == ("both's mint is said to be asked only by other plugins and only "
                                                       "from its page, so no one can ask it.")
    with asking.asking("harness"):  # the asker of this moment by default
        assert asking.refusal(gated, "mint") == "" and asking.refusal(gated, "decide").endswith("harness asked it.")
        asking.check(gated, "mint")
        with pytest.raises(asking.AskRefused) as refused:
            asking.check(gated, "decide")
    e = refused.value
    assert isinstance(e, PermissionError) and str(e) == e.words
    assert e.words == f"{page_only}, never by another plugin: harness asked it."
    assert (e.plugin, e.hook, e.asker, e.status) == ("gated", "decide", "harness", 403)


def test_a_job_started_on_a_plugins_ask_is_refused_a_hook_only_its_page_asks():
    app, _gated, harness = demo()
    job = harness.begins(asks(app, "decide", 7)).joined()
    assert job.answer is None and isinstance(job.refused, asking.AskRefused)
    assert str(job.refused) == "gated's decide is asked only from its page, never by another plugin: harness asked it."
    assert job.refused.asker == "harness"
    # the same job asks the hook only other plugins ask: answered, for harness's agent
    assert harness.begins(asks(app, "mint")).joined().answer == {"for": "harness"}


def test_the_same_job_started_from_the_page_may_ask_it():
    app, _gated, _harness = demo()
    job = app.route("gated", "start", asks(app, "decide", 7)).joined()
    assert job.refused is None and job.answer == {"ticket": 7, "by": "page"}
    # and the page's job is refused the hook only other plugins ask
    job = app.route("gated", "start", asks(app, "mint")).joined()
    assert str(job.refused) == "gated's mint is asked only by another plugin, never from a page or by a program."


def test_a_thread_handed_no_asker_is_refused_both_kinds_of_gated_hook():
    app, _gated, harness = demo()
    words = {"decide": f"gated's decide is asked only from its page. {NOBODY}",
             "mint": f"gated's mint is asked only by another plugin. {NOBODY}"}
    for who in (asking.PAGE, "harness"):
        with asking.asking(who):
            for how in THREADS:
                for hook, said in words.items():
                    answer, refused = in_thread(asks(app, hook, *(("t",) if hook == "decide" else ())), how)
                    assert answer is None and str(refused) == said and refused.asker is None, (who, how, hook)
                # a hook in neither word is asked as before, by no one
                assert in_thread(asks(app, "plain"), how) == ({"by": None}, None), (who, how)


# -- App.ask ---------------------------------------------------------------------------------------------------------
def test_the_plugin_that_asks_is_the_asker_for_that_call_alone():
    app, _gated, harness = demo()
    assert harness.wants("mint") == {"for": "harness"} and harness.wants("plain") == {"by": "harness"}
    assert asking.asker() is None
    with asking.asking(asking.PAGE):  # a plugin asking inside the page's request is the plugin
        assert harness.wants("plain") == {"by": "harness"}
        assert asking.asker() == "page"
    # the app's own code asks as whoever it asks for: the page in its route, else no one
    assert app.route("gated", "plain") == {"by": "page"} and app.tick("gated", "plain") == {"by": None}
    assert app.route("gated", "decide", 3) == {"ticket": 3, "by": "page"}


def test_a_gated_hook_is_refused_to_any_other_asker_and_noted_as_an_ask_that_failed():
    app, gated, harness = demo()
    with pytest.raises(asking.AskRefused) as refused:
        harness.wants("decide", 1)
    said = "gated's decide is asked only from its page, never by another plugin: harness asked it."
    assert str(refused.value) == said
    with asking.asking(asking.PAGE), pytest.raises(asking.AskRefused, match="harness asked it"):
        harness.wants("decide", 1)  # inside the page's request all the same
    with pytest.raises(asking.AskRefused, match="never from a page or by a program"):
        app.route("gated", "mint")
    with pytest.raises(asking.AskRefused, match=NOBODY):
        app.tick("gated", "mint")
    with pytest.raises(asking.AskRefused, match=NOBODY):
        app.tick("gated", "decide", 1)
    with pytest.raises(asking.AskRefused, match="not by gated itself"):
        gated.mint_own()
    rows = {(r["from"], r["what"]): r for r in app.connections()["recent"] if r["to"] == "gated"}
    assert (rows[("harness", "decide")]["kind"], rows[("harness", "decide")]["ok"]) == ("ask", False)
    assert not rows[("demo", "mint")]["ok"] and not rows[("gated", "mint")]["ok"]
    links = {(k["from"], k["to"], k["kind"]): k for k in app.connections()["links"]}
    assert (links[("harness", "gated", "ask")]["count"], links[("harness", "gated", "ask")]["failed"]) == (2, 2)


def test_a_plugin_that_says_neither_word_is_asked_as_before():
    app, _gated, harness = demo()
    assert app.tick("open", "look") == {"by": None} and app.route("open", "look") == {"by": "page"}
    assert harness.asks_of("open", "look") == {"by": "harness"}
    for how in THREADS:
        assert in_thread(lambda: app.ask("open", "look"), how) == ({"by": None}, None), how
    callers = {r["from"] for r in app.connections()["recent"] if r["to"] == "open"}
    assert callers == {"demo", "harness"}  # noted as asked by the app, else the plugin that asks, as before
    with pytest.raises(LookupError, match="no plugin 'nobody' is attached to demo"):
        app.tick("nobody", "look")


def test_a_plugin_that_took_the_pages_name_asks_as_no_one():
    class Named(Harness):
        name = "page"

    app, _gated, _harness = demo()
    named = Named()
    app.attach(named)
    assert named.wants("plain") == {"by": None}
    with asking.asking(asking.PAGE), pytest.raises(asking.AskRefused, match=NOBODY):
        named.wants("decide", 1)


def test_a_gate_that_cannot_read_its_word_refuses_every_hook_of_that_plugin():
    class Loose(Gated):
        name = "loose"
        PAGE_ONLY_HOOKS = "decide"  # a str: read as nothing, so a gate would let it through

    app, _gated, _harness = demo()
    app.attach(Loose())
    words = ("loose: who may ask its hooks cannot be read (PAGE_ONLY_HOOKS must be a tuple of str), so it is asked "
             "nothing")
    for hook in ("decide", "plain", "mint"):
        with pytest.raises(asking.AskRefused) as refused:
            app.route("loose", hook, *((1,) if hook == "decide" else ()))
        assert str(refused.value) == words


# -- App.present -----------------------------------------------------------------------------------------------------
COOKIE = "liminal_login_demo=tok"


def browser(signed_in: bool = True):
    return SimpleNamespace(headers={"Cookie": COOKIE if signed_in else "other=1"})


class StandInLogin:
    """A login object as an app that inherits one makes it (make_login: log= and superclass=): a session by cookie."""

    def __init__(self, log=print, superclass=None):
        self.superclass = superclass

    def session(self, handler):
        return "a session" if COOKIE in (handler.headers.get("Cookie") or "") else None


class Proving(StandInLogin):
    """A login that offers its own proof of presence, answering as told."""

    answer: object = True
    asked: list = []

    def present(self, handler):
        Proving.asked.append(handler)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


class Broken(StandInLogin):
    def session(self, handler):
        raise OSError("its store cannot be opened")


class AppLogin(App):
    """A login object that is itself an app (as liminal-login's is): it has the frame's present() too."""

    NAME = "login"

    def __init__(self, log=print, superclass=None):
        super().__init__(log)

    def session(self, handler):
        return StandInLogin.session(self, handler)


def inheriting(monkeypatch, login_class) -> App:
    class Inheriting(App):
        NAME, TITLE = "inheriting", "Inheriting"
        LOGIN, LOGIN_VAR, LOGIN_CLASS = True, "LIMINAL_ASKING_TEST_LOGIN", login_class

    monkeypatch.delenv("LIMINAL_ASKING_TEST_LOGIN", raising=False)
    return Inheriting(log=lambda m: None)


def test_present_is_the_logins_own_proof_when_it_offers_one(monkeypatch):
    Proving.asked = []
    for answer, said in ((True, True), (False, False), (None, False), ("yes", False), (1, False),
                         (RuntimeError("no proof"), False)):
        monkeypatch.setattr(Proving, "answer", answer)
        app = inheriting(monkeypatch, Proving)
        handler = browser(signed_in=True)
        assert app.present(handler) is said, answer
        assert Proving.asked[-1] is handler
    # signed in or not, only the proof counts
    monkeypatch.setattr(Proving, "answer", False)
    assert inheriting(monkeypatch, Proving).present(browser(signed_in=True)) is False


def test_present_is_whether_the_browser_is_signed_in_when_the_login_offers_no_proof(monkeypatch):
    app = inheriting(monkeypatch, StandInLogin)
    assert app.present(browser(True)) is True and app.present(browser(False)) is False
    assert inheriting(monkeypatch, Broken).present(browser(True)) is False  # a login that cannot say: no proof
    # a login object that is an app: its own present() is the frame's, not a proof, so its session is asked
    app = inheriting(monkeypatch, AppLogin)
    assert isinstance(app.login_object(), App)
    assert app.present(browser(True)) is True and app.present(browser(False)) is False

    class Flag(StandInLogin):
        present = True  # not a proof that can be asked: the session is

    assert inheriting(monkeypatch, Flag).present(browser(False)) is False


def test_present_is_none_without_a_login(monkeypatch):
    assert Demo(log=lambda m: None).present(browser(True)) is None
    off = inheriting(monkeypatch, StandInLogin)
    monkeypatch.setenv("LIMINAL_ASKING_TEST_LOGIN", "off")
    assert off.present(browser(True)) is None

    class Unmade:
        def __init__(self, **kwargs):
            raise ImportError("liminal-login is not installed")

    said: list = []
    unmade = inheriting(monkeypatch, Unmade)
    unmade.log = said.append
    assert unmade.present(browser(True)) is None and "could not be made" in said[0]

    class Front(App):  # an app whose signed_in is its own, with no login object (the charts' front asks the charts)
        NAME, answer = "front", None

        def signed_in(self, handler):
            return self.answer

    front = Front(log=lambda m: None)
    for answer in (True, False, None):
        front.answer = answer
        assert front.present(browser(True)) is answer


# -- App.start -------------------------------------------------------------------------------------------------------
class StandInServer:
    """web.Server as App.start uses it, binding nothing: made with its address and handler class, serving until it is
    shut down, then closed."""

    made: list = []
    refuse: OSError | None = None

    def __init__(self, address, handler):
        StandInServer.made.append((address, handler, self))
        if StandInServer.refuse is not None:
            raise StandInServer.refuse
        self.server_address = (address[0], address[1] or 54321)
        self.ended, self.closed = threading.Event(), False

    def serve_forever(self):
        self.ended.wait(10)

    def shutdown(self):
        self.ended.set()

    def server_close(self):
        self.closed = True


def test_the_frame_serves_with_web_server(monkeypatch):
    monkeypatch.setattr(web, "Server", StandInServer, raising=False)
    monkeypatch.setattr(StandInServer, "made", [])
    monkeypatch.setattr(StandInServer, "refuse", None)
    said: list = []
    app = Demo(log=said.append)
    assert app.start(0) == "http://127.0.0.1:54321/" == app.served
    [(address, handler, server)] = StandInServer.made
    assert address == ("127.0.0.1", 0) and issubclass(handler, BaseHTTPRequestHandler)
    assert handler.server_version == "liminal-demo" and said == ["demo: its page at http://127.0.0.1:54321/"]
    app.stop()
    assert server.ended.is_set() and server.closed and StandInServer.made == [(address, handler, server)]
    assert "ThreadingHTTPServer" not in vars(frame)  # the frame makes no server of another class


def test_a_port_taken_is_refused_and_never_traded_for_another(monkeypatch):
    monkeypatch.setattr(web, "Server", StandInServer, raising=False)
    monkeypatch.setattr(StandInServer, "made", [])
    monkeypatch.setattr(StandInServer, "refuse", OSError(10048, "only one usage of each socket address"))
    monkeypatch.setattr(web, "listening", lambda port: False)
    app = Demo(log=lambda m: None)
    with pytest.raises(PortTaken) as taken:
        app.start(50123)
    assert taken.value.port == 50123 and "Demo: port 50123 is taken" in str(taken.value)
    assert [a for a, _h, _s in StandInServer.made] == [("127.0.0.1", 50123)] and app.served is None
    # something answers there already: refused in words before any server is made
    monkeypatch.setattr(StandInServer, "made", [])
    monkeypatch.setattr(StandInServer, "refuse", None)
    monkeypatch.setattr(web, "listening", lambda port: True)
    with pytest.raises(PortTaken):
        app.start(50123)
    assert StandInServer.made == []
