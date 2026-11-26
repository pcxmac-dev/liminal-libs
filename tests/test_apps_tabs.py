"""A plugin's own tabs (apps/tabs.py; the user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web
view'"; "there needs to be a way to 'filter' (another tab)"): a Tab is its id in the page's address, its title, the read
hook answering its page and the seconds between asks while it is shown; anything else is refused as it is made. A machine
plugin declares none by default."""
from __future__ import annotations

import dataclasses
import json
import math

import pytest

from liminal_libs.apps.tabs import ID, MIN_EVERY, Tab
from liminal_libs.machines.plugin import MachinePlugin


def test_a_tab_says_itself_as_it_travels():
    t = Tab("world", "World Wide Web", "world", 2.0)
    assert t.as_dict() == {"id": "world", "title": "World Wide Web", "hook": "world", "every": 2.0}
    assert json.loads(json.dumps(t.as_dict())) == t.as_dict()  # what the platform sends in a plugin's status
    assert Tab("filter", "Filter", "filter").every == 5.0  # asked every five seconds unless it says
    assert isinstance(Tab("compare", "Compare", "compare", 3).every, float)  # a whole number of seconds kept as seconds
    with pytest.raises(dataclasses.FrozenInstanceError):
        t.every = 0.1  # frozen: nothing changes it after it is checked


@pytest.mark.parametrize("tab_id", ["world", "filter", "two-words", "under_score", "Scope", "a", "x" * 40, "0day"])
def test_an_id_is_url_safe(tab_id):
    assert Tab(tab_id, "A tab", "page").id == tab_id and ID.fullmatch(tab_id)


@pytest.mark.parametrize("tab_id", ["", "two words", "a/b", "world#", "?q", "émoji", "x" * 41, "a.b", "%20", None, 7])
def test_an_id_the_address_cannot_carry_is_refused(tab_id):
    with pytest.raises(ValueError, match="url-safe"):
        Tab(tab_id, "A tab", "page")


@pytest.mark.parametrize("hook", ["", "two words", "world()", "9lives", "class", "a-b", None, 3])
def test_a_hook_is_a_name(hook):
    with pytest.raises(ValueError, match="hook"):
        Tab("world", "World", hook)


@pytest.mark.parametrize("every", [0, 0.5, 0.999, -2, math.inf, math.nan, "5", None, True])
def test_every_is_a_number_of_seconds_at_least_one(every):
    with pytest.raises(ValueError, match="every"):
        Tab("world", "World", "world", every)


def test_a_tab_has_a_title():
    for title in ("", "   ", None):
        with pytest.raises(ValueError, match="title"):
            Tab("world", title, "world")
    assert Tab("world", "World", "world", MIN_EVERY).every == MIN_EVERY  # the most often a tab is asked


def test_a_machine_plugin_declares_no_tabs_by_default_and_its_own_when_it_has_them():
    assert MachinePlugin.TABS == ()

    class Walled(MachinePlugin):
        name, title, about = "walled", "Walled", "a stand-in with tabs of its own"
        HOOKS = (*MachinePlugin.HOOKS, "world", "filter")
        TABS = (Tab("world", "World Wide Web", "world", 2.0), Tab("filter", "Filter", "filter", 2.0))

        def world(self):
            return {"title": "Who reaches this machine"}

        def filter(self):
            return {"flows": {"rows": []}}

    w = Walled()
    assert [t.id for t in w.TABS] == ["world", "filter"] and all(t.hook in w.interface()["hooks"] for t in w.TABS)
    assert w.ask("world") == {"title": "Who reaches this machine"}  # its hook asked by name, as the platform asks it


def test_a_rows_detail_is_plain_words_cut_at_its_caps():
    """1.105.0 (Monday list item 31): what a row picked tells in the right-hand menu, as plain JSON, cut at the caps."""
    from liminal_libs.apps import tabs

    d = tabs.detail("443/tcp", [("Port", 443), ("Service", "https"), ("Empty", ""), ("None", None), ("Share", 0.5)],
                    sub="this machine's port", note="a note", sections=[("Counted", [("In", "1 KB")]), ("Nothing", [])])
    assert d == {"key": "443/tcp", "title": "443/tcp", "facts": [["Port", "443"], ["Service", "https"], ["Share", "0.5"]],
                 "sub": "this machine's port", "sections": [{"title": "Counted", "facts": [["In", "1 KB"]]}],
                 "note": "a note"}
    assert tabs.detail("t", key="here:443/tcp")["key"] == "here:443/tcp"
    long = tabs.detail("x" * 500, [("v", "y" * 1000)] * 100, sections=[("s", [("a", "b")])] * 20)
    assert len(long["title"]) == tabs.DETAIL_TITLE and long["title"].endswith("…")
    assert len(long["facts"]) == tabs.DETAIL_FACTS and len(long["facts"][0][1]) == tabs.DETAIL_VALUE
    assert "sections" not in long  # the facts' budget is spent on the first part
    for bad in ({"a": 1}, ["a"], object(), True):
        with pytest.raises(ValueError):
            tabs.detail("t", [("k", bad)])
    with pytest.raises(ValueError):
        tabs.detail("t", [("only one",)])
    with pytest.raises(ValueError):
        tabs.detail("t", sections=["not a pair"])
