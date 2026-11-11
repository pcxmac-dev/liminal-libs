"""The platform plugins' JSON REST client (machines/rest.py) and Dynamic DNS keeper (machines/ddns.py), on stand-ins:
nothing sent, no process started."""
from __future__ import annotations

import json

import pytest

from liminal_libs.machines import ddns
from liminal_libs.machines.rest import RestClient, RestError, TokenSource, bearer, scrub

TOKEN = "dop_v1_secret-token-0123456789"


class Transport:
    """Answers in order; keeps what was sent."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.sent = []

    def __call__(self, method, url, headers, body, timeout):
        self.sent.append((method, url, dict(headers), body))
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        status, headers, data = a
        body = data if isinstance(data, bytes) else json.dumps(data).encode() if data is not None else b""
        return status, {"Content-Type": "application/json", **headers}, body


def client(t, **kw):
    return RestClient("https://api.example.org/v2", auth=bearer(TOKEN), secrets=(TOKEN,), transport=t,
                      sleep=lambda s: kw.setdefault("slept", []).append(s), **{k: v for k, v in kw.items() if k != "slept"})


def test_a_request_is_borne_its_answer_read_and_its_limits_kept():
    t = Transport((200, {"RateLimit-Limit": "5000", "RateLimit-Remaining": "4999", "Other": "x"}, {"account": {"email": "a@b"}}))
    api = client(t)
    assert api.get("/account", params={"page": 1, "skip": None}) == {"account": {"email": "a@b"}}
    method, url, headers, body = t.sent[0]
    assert (method, url) == ("GET", "https://api.example.org/v2/account?page=1")
    assert headers["Authorization"] == f"Bearer {TOKEN}" and headers["Accept"] == "application/json" and body is None
    facts = api.facts({"ratelimit-remaining": "Left this hour"})
    assert facts["Requests"] == "1 made" and facts["Left this hour"] == "4999" and facts["Last answer"].startswith("HTTP 200")
    assert "other" not in api.seen.limits and api.seen.limits["ratelimit-limit"] == "5000"


def test_a_write_sends_json_and_is_never_sent_twice_on_a_broken_connection():
    t = Transport((201, {}, {"id": 7}))
    api = client(t)
    assert api.post("/things", {"name": "a"}) == {"id": 7}
    assert t.sent[0][3] == b'{"name":"a"}' and t.sent[0][2]["Content-Type"] == "application/json"
    t2 = Transport(ConnectionError("reset"), (201, {}, {"id": 8}))
    with pytest.raises(RestError) as e:
        client(t2).post("/things", {"name": "b"})
    assert "ConnectionError: reset" in str(e.value) and len(t2.sent) == 1  # a write that may have been done: once


def test_a_read_is_tried_again_and_a_rate_limit_waited_out():
    slept: list = []
    t = Transport((503, {}, {"message": "busy"}), (429, {"Retry-After": "2"}, {"id": "too_many_requests"}), (200, {}, {"ok": 1}))
    api = RestClient("https://api.example.org", transport=t, sleep=slept.append)
    assert api.get("/x") == {"ok": 1} and len(t.sent) == 3 and slept[1] == 2.0
    t2 = Transport((429, {"Retry-After": "120"}, {"message": "API rate limit exceeded."}))
    with pytest.raises(RestError) as e:
        RestClient("https://api.example.org", transport=t2, sleep=slept.append).post("/y", {})
    assert e.value.status == 429 and e.value.retry_after == 120.0 and "API rate limit exceeded." in str(e.value)


def test_errors_are_worded_with_the_secrets_taken_out():
    t = Transport((401, {"X-Request-Id": "r-1"}, {"id": "unauthorized", "message": f"bad token {TOKEN}"}))
    refused = []
    api = RestClient("https://api.example.org", auth=bearer(TOKEN), secrets=(TOKEN,), transport=t, on_refused=lambda: refused.append(1))
    with pytest.raises(RestError) as e:
        api.get("/account")
    assert TOKEN not in str(e.value) and "bad token •••" in str(e.value) and e.value.refused and e.value.request_id == "r-1"
    assert e.value.code == "unauthorized" and refused == [1]
    linode = lambda a: ("; ".join(x.get("reason", "") for x in a.data.get("errors", [])), "")  # noqa: E731
    t2 = Transport((400, {}, {"errors": [{"reason": "label is taken", "field": "label"}]}))
    with pytest.raises(RestError, match="label is taken"):
        RestClient("https://api.example.org", transport=t2, error=linode).put("/z", {})
    assert scrub("a abc abcd", ["abc", "abcd"]) == "a abc •••"  # a secret shorter than four characters is no secret
    with pytest.raises(ValueError):
        RestClient("http://api.example.org")


def test_pages_follows_a_list_to_its_last_page():
    t = Transport((200, {}, {"things": [1, 2], "links": {"pages": {"next": "https://api.example.org/v2/things?page=2"}}}),
                  (200, {}, {"things": [3], "links": {}}))
    api = client(t)
    nxt = lambda data, params: ((data["links"]["pages"]["next"], {}) if data.get("links", {}).get("pages", {}).get("next") else None)  # noqa: E731
    assert list(api.pages("/things", {"per_page": 2}, items="things", next_of=nxt)) == [1, 2, 3]
    assert t.sent[1][1] == "https://api.example.org/v2/things?page=2"


def test_a_token_source_keeps_its_token_until_a_minute_before_it_ends():
    now = [1000.0]
    fetched = []

    def fetch():
        fetched.append(now[0])
        return f"t{len(fetched)}", 3600

    source = TokenSource(fetch, clock=lambda: now[0])
    assert source() == "t1" and source() == "t1"
    now[0] += 3600 - 59
    assert source() == "t2"
    source.forget()
    assert source() == "t3" and len(fetched) == 3


def test_dynamic_dns_sets_only_the_hosts_that_differ():
    records = {"home.example.com": ["198.51.100.7"], "example.net": ["203.0.113.9"], "new.example.com": []}
    written = []

    def write(h, ip):
        written.append((h.zone, h.name, ip))
        records[h.fqdn] = [ip]
        return "set"

    keeper = ddns.Keeper(read=lambda h: records[h.fqdn], write=write, public=lambda: ("203.0.113.9", "a stand-in"))
    hosts, wrong = ddns.hosts_of("home.example.com, @.example.net; new.example.com other.org", ["example.com", "example.net"])
    assert [(h.zone, h.name) for h in hosts] == [("example.com", "home"), ("example.net", "@"), ("example.com", "new")]
    assert wrong == ["other.org is in none of the account's domains"]
    out = keeper.run_pass(hosts)
    assert written == [("example.com", "home", "203.0.113.9"), ("example.com", "new", "203.0.113.9")]
    assert [o["result"] for o in out] == ["set (was 198.51.100.7)", "current", "set (was none)"]
    written.clear()
    keeper.run_pass(hosts)
    assert written == []
    keeper.run_pass(hosts, force=True)
    assert len(written) == 3
    table = keeper.table(hosts, 5)
    assert table["title"] == "Dynamic DNS" and table["rows"][0][:2] == ["home.example.com", "203.0.113.9"]
    assert ddns.minutes_of("0.2") == 1.0 and ddns.minutes_of("") == 5.0 and ddns.minutes_of("x") == 5.0


def test_dynamic_dns_without_an_address_or_a_record_says_so():
    keeper = ddns.Keeper(read=lambda h: None, write=lambda h, ip: "set", public=lambda: (None, "no server answered"))
    hosts, _ = ddns.hosts_of("home.example.com", ["example.com"])
    assert keeper.run_pass(hosts)[0]["result"] == "this network's address was not found: no server answered"
    keeper2 = ddns.Keeper(read=lambda h: None, write=lambda h, ip: "set", public=lambda: ("2001:db8::1", "v6"))
    assert keeper2.run_pass(hosts)[0]["ok"] is False  # an IPv6 answer is no IPv4 address
    keeper3 = ddns.Keeper(read=lambda h: None, write=lambda h, ip: "set", public=lambda: ("203.0.113.9", "x"))
    assert keeper3.run_pass(hosts)[0]["result"] == "its record could not be read"
