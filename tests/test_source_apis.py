"""What a plugin attaches to (plugin API 2.2, sources/apis.py): the declarations, their check, the pages' JSON, the
conformance rule (the user, 2026-11-11: "each plugin should reflect the the API its attached to, and present links that
provide documentation"; "ensure this is true")."""
from __future__ import annotations

from datetime import date

from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.sources import apis as A
from liminal_libs.sources.conformance import problems
from liminal_libs.sources.registry import PLUGIN_API, api_refusal

DOCS = "https://docs.example.org/api"


def an_api(**changes) -> A.Api:
    base = dict(
        name="Example API", maker="Example", about="The account's things, read and changed over HTTPS.", kind="rest",
        base="https://api.example.org/v2", version="v2", auth="a bearer token", limits="250 a minute",
        costs="a thing bills until it is removed",
        links=(A.Link("API reference", DOCS, "reference"), A.Link("Rate limits", "https://docs.example.org/limits", "limits"),
               A.Link("Status", "https://status.example.org", "status")),
        areas=(A.Area("Things", "the account's things", "https://docs.example.org/things", covered="read; power on and off"),
               A.Area("Billing", "invoices and the balance")),
        calls=(A.Call("GET /v2/things", "lists the things", "Things", used="the Things table"),
               A.Call("POST /v2/things", "makes a thing", "Things", writes=True, costs=True)),
        verified="2026-11-11")
    base.update(changes)
    return A.Api(**base)


def test_a_sound_declaration_has_no_problems_and_reads_as_the_page_wants():
    api = an_api()
    assert A.problems((api,), today=date(2026, 11, 11)) == []
    d = api.as_dict()
    assert d["docs"] == DOCS and d["kindWords"] == "REST API over HTTPS"
    assert d["counts"] == {"areas": 2, "covered": 1, "calls": 2, "used": 1}
    assert [x["kindWords"] for x in d["links"]] == ["Reference", "Limits", "Status"]
    assert d["calls"][1] == {"name": "POST /v2/things", "about": "makes a thing", "area": "Things", "used": "",
                             "docs": "", "writes": True, "costs": True}
    assert api.link("status") == "https://status.example.org" and api.link("pricing") == ""
    assert A.urls((api,)) == [DOCS, "https://docs.example.org/limits", "https://status.example.org",
                              "https://docs.example.org/things"]


def test_what_a_declaration_must_hold():
    today = date(2026, 11, 11)
    said = lambda **c: " | ".join(A.problems((an_api(**c),), today=today))  # noqa: E731
    assert "no documentation link" in said(links=(A.Link("Status", "https://status.example.org", "status"),))
    assert "is not an https address" in said(links=(A.Link("Docs", "http://docs.example.org", "docs"),))
    assert "is not an https address" in said(links=(A.Link("Docs", "https://docs.example.org/a b", "docs"),))
    assert "kind 'blog'" in said(links=(A.Link("Docs", DOCS, "docs"), A.Link("Blog", "https://blog.example.org", "blog")))
    assert "given twice" in said(links=(A.Link("Docs", DOCS, "docs"), A.Link("Again", DOCS, "reference")))
    assert "no maker" in said(maker="") and "no about" in said(about=" ")
    assert "not an ISO date" in said(verified="last week") and "after today" in said(verified="2026-12-01")
    assert "'Things' given twice" in said(areas=(A.Area("Things"), A.Area("Things")))
    assert "not an https address" in said(calls=(A.Call("GET /x", docs="ftp://x.example.org"),))
    assert "writes and costs are bools" in said(calls=(A.Call("GET /x", writes="yes"),))
    assert A.problems([an_api()]) == ["apis must be a tuple of sources.apis.Api, not list"]
    assert "declared twice" in " ".join(A.problems((an_api(), an_api()), today=today))


def test_facts_of_reads_what_a_plugin_learned_and_never_fails_a_page():
    class Learned:
        def api_facts(self):
            return {"Example API": {"Requests": 3, "Left": None}, "junk": "not a mapping"}

    class Broken:
        def api_facts(self):
            raise RuntimeError("no")

    assert A.facts_of(Learned()) == {"Example API": {"Requests": "3", "Left": ""}}
    assert A.facts_of(Broken()) == {}


def test_dead_links_asks_each_address_once_and_counts_a_refusal_as_there():
    asked = []

    def get(url, timeout):
        asked.append(url)
        if "limits" in url:
            return 404
        if "status" in url:
            return 403  # a page refusing automated readers is there
        if "things" in url:
            raise ConnectionError("no route")
        return 200

    dead = A.dead_links((an_api(), an_api(name="Again")), get=get)
    assert asked == [DOCS, "https://docs.example.org/limits", "https://status.example.org", "https://docs.example.org/things"]
    assert dead == [("https://docs.example.org/limits", "HTTP 404"),
                    ("https://docs.example.org/things", "ConnectionError: no route")]


class Machine(MachinePlugin):
    name = "example-cloud"
    title = "Example cloud"
    api = "2.2"
    apis = (an_api(),)

    def status(self):
        return {"present": False}


def test_the_conformance_rule_a_plugin_written_for_2_2_says_what_it_attaches_to():
    assert PLUGIN_API == "2.2" and api_refusal("2.2") is None and api_refusal("2.1") is None
    assert problems(Machine()) == []
    bare = Machine().with_(apis=())
    assert any("declares no API it attaches to" in p for p in problems(bare))
    older = Machine().with_(api="2.1")
    assert any("declares apis (plugin API 2.2) but is written for 2.1" in p for p in problems(older))
    assert problems(Machine().with_(api="2.1", apis=())) == []  # a 2.1 plugin loads unchanged
    wrong = Machine().with_(apis=(an_api(links=()),))
    assert any("no documentation link" in p for p in problems(wrong))
    assert Machine().api_facts() == {} and Machine().interface()["apis"] == ["Example API"]
