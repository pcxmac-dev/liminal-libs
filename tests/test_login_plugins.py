"""The login's plugins (1.92.0; Monday list item 12, item 30 step 8): the LoginPlugin kind, the Viewer it is handed (never a
value), the registry's dict of them, the conformance, and attach_registry leaving them to the login."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from liminal_libs import layout
from liminal_libs.apps.app import App, attach_registry
from liminal_libs.sources import conformance, registry
from liminal_libs.sources.apis import Api, Link
from liminal_libs.sources.plugin import Keystore, LoginPlugin, LoginRefusal, LoginTab, UsersPlace, Viewer

pytestmark = pytest.mark.usefixtures("stand_in_environment")  # its code reads this process's environment

CARD = (Api(name="SQLite", maker="The SQLite project", about="The login's users file and keystores.", kind="sdk",
            links=(Link("SQLite", "https://www.sqlite.org/docs.html", "docs"),), verified="2026-11-25"),)


class Store(LoginPlugin):
    name, title, about, api, version = "datastore", "Datastore", "where the users are", "2.4", "0.1.0"
    apis = CARD
    TABS = (LoginTab("mine", "Mine"), LoginTab("global", "Global", admin=True))

    def page(self, tab, viewer):
        return {"title": tab, "who": viewer.name}


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(layout, "plugins_dir", lambda: None)

    def install(*plugins):
        eps = [SimpleNamespace(name=f"p{i}", value=f"fake_{i}:LOGIN", load=(lambda p=p: SimpleNamespace(LOGIN=p)))
               for i, p in enumerate(plugins)]
        monkeypatch.setattr(registry, "_entry_points", lambda: eps)
        return registry.reload()

    yield install
    registry._providers = None


def test_a_login_plugin_is_a_kind_of_its_own_found_with_the_others(installed):
    installed(Store)
    assert list(registry.logins()) == ["datastore"] and registry.login_plugin("datastore").origin.startswith("package:")
    p = registry.login_plugin("datastore")
    assert registry.errors() == [] and registry._kind(p) == "login plugin"
    assert (p.KIND, p.SYSTEM) == ("login", "login") and p.tab("global").admin and p.tab("nope") is None
    for others in (registry.providers(), registry.publishers(), registry.assistants(), registry.machines(),
                   registry.databases(), registry.auditors()):
        assert "datastore" not in others
    assert len(registry.discover_everything()) == 5 and len(registry.discover_all()) == 3  # the older finders as they were
    assert "datastore" in registry.plugins_loaded() and registry.plugin_keys("datastore") == []
    assert registry.select("none").everything is False and registry.logins() == {}
    registry.select(None)
    assert list(registry.logins()) == ["datastore"]
    registry.leave_out("datastore", "it failed")
    assert registry.logins() == {} and registry.errors()[-1][1] == "datastore: it failed"


def test_a_second_of_one_name_is_left_out(installed):
    class Again(Store):
        order = 200

    installed(Store, Again)
    assert list(registry.logins()) == ["datastore"]
    assert any("a second login plugin named 'datastore'" in why for _, why in registry.errors())


def test_only_the_login_system_attaches_them(installed):
    class Charts(App):
        NAME = "charts"

    class Login(App):
        NAME = "login"

    installed(Store)
    assert "datastore" not in attach_registry(Charts())  # everything an app attaches: never a login's plugin
    assert "datastore" not in attach_registry(Charts(), only="platform")
    login = Login()
    assert attach_registry(login, only="login") == ["datastore"] and registry.login_plugin("datastore").app is login
    registry.login_plugin("datastore").detach()


def test_the_viewer_carries_no_value():
    store = Keystore("ann", "C:/x/ann.db", pairs=({"name": "a-key", "kind": "key", "label": "", "value": "SECRET",
                                                   "sealed": b"x", "updatedAt": "2026-11-25T00:00:00Z"},))
    assert dict(store.pairs[0]) == {"name": "a-key", "kind": "key", "label": "", "updatedAt": "2026-11-25T00:00:00Z"}
    assert "SECRET" not in repr(store) and "SECRET" not in str(store.as_dict())
    with pytest.raises(TypeError):
        store.pairs[0]["value"] = "again"  # read-only
    v = Viewer("ann", keystore=store)
    assert v.admin is False and v.place == UsersPlace() and v.place.own and dict(v.kept) == {}
    assert UsersPlace(own=False, pointer={"engine": "sqlite", "instance": "c"}).as_dict()["pointer"] == {
        "engine": "sqlite", "instance": "c"}


def test_its_refusal_and_its_tabs():
    r = LoginRefusal("asked twice", 409, accept="accept_point")
    assert isinstance(r, ValueError) and r.answer() == {"error": "asked twice", "accept": "accept_point"} and r.status == 409
    assert LoginRefusal("no").answer() == {"error": "no"}
    with pytest.raises(ValueError):
        LoginTab("a b", "Bad")
    with pytest.raises(ValueError):
        LoginTab("ok", " ")
    assert LoginTab("mine", "Mine").as_dict() == {"id": "mine", "title": "Mine", "admin": False, "hook": "page"}
    with pytest.raises(LoginRefusal):  # the contract's change: nothing to change
        Store().change("mine", Viewer("ann"), {})
    assert Store().place({}) is None


def test_what_the_contract_holds_a_login_plugin_to():
    assert conformance.problems(Store()) == []

    class NoTabs(Store):
        TABS = ()

    class Blank(LoginPlugin):
        name, title, about, api = "blank", "Blank", "nothing", "2.4"
        apis = CARD
        TABS = (LoginTab("mine", "Mine"), LoginTab("Mine", "Again"), "global")

    class Elsewhere(Store):
        SYSTEM = "platform"

    assert any("TABS must be a non-empty tuple" in w for w in conformance.problems(NoTabs()))
    said = conformance.problems(Blank())
    assert any("must give page" in w for w in said) and any("another of its tabs'" in w for w in said)
    assert any("is not a LoginTab" in w for w in said)
    assert any("SYSTEM 'login'" in w for w in conformance.problems(Elsewhere()))
