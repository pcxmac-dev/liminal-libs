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


def test_dynamic_dns_keeps_its_own_hosts_and_leaves_anothers_until_taken_over(tmp_path):
    """1.49.2 (an audit before any key went in: a host listed in the settings had its live record pointed at home within a
    minute, unasked): a host holding another address is left as it is until the user takes it over; one with no record
    is made; one already pointing here, or at the address the keeper set last, is its own to keep current."""
    records = {"home.example.com": ["198.51.100.7"], "example.net": ["203.0.113.9"], "new.example.com": []}
    written = []

    def write(h, ip):
        written.append((h.zone, h.name, ip))
        records[h.fqdn] = [ip]
        return "set"

    public = ["203.0.113.9"]
    state = tmp_path / "digitalocean" / "ddns.json"
    keeper = ddns.Keeper(read=lambda h: records[h.fqdn], write=write, public=lambda: (public[0], "a stand-in"), state=state)
    hosts, wrong = ddns.hosts_of("home.example.com, @.example.net; new.example.com other.org", ["example.com", "example.net"])
    assert [(h.zone, h.name) for h in hosts] == [("example.com", "home"), ("example.net", "@"), ("example.com", "new")]
    assert wrong == ["other.org is in none of the account's domains"]
    out = keeper.run_pass(hosts)
    assert written == [("example.com", "new", "203.0.113.9")]  # the live record at home.example.com left as it is
    assert [o["result"] for o in out] == [
        "holds 198.51.100.7, not this network's address: left as it is (Take over… to point it here)", "current", "set (was none)"]
    assert out[0]["foreign"] and out[0]["holds"] == ["198.51.100.7"] and not out[1]["foreign"]
    table = keeper.table(hosts, 5, take=True)
    assert table["rows"][0][5] == {"form": "ddns-take", "title": "Take over…", "label": "Take over home.example.com",
                                   "values": {"host": "home.example.com", "holds": "198.51.100.7"}} and table["rows"][1][5] == ""
    assert keeper.take_form()["confirm"]["danger"] and keeper.now_form()["fields"] == []
    keeper.take_over("home.example.com")  # the page's Take over…, confirmed
    written.clear()
    assert keeper.run_pass(hosts)[0]["result"] == "set (was 198.51.100.7)" and written == [("example.com", "home", "203.0.113.9")]
    written.clear()
    keeper.run_pass(hosts)
    assert written == []
    keeper.run_pass(hosts, force=True)
    assert len(written) == 3  # every host of its own, Update DNS now
    # the network's address moves: each host still holding the address the keeper set is its own, kept current, after
    # a restart too (its own kept in the state file)
    public[0] = "203.0.113.10"
    written.clear()
    again = ddns.Keeper(read=lambda h: records[h.fqdn], write=write, public=lambda: (public[0], "a stand-in"), state=state)
    assert again.own("example.net") == "203.0.113.9" and again.taken("home.example.com")
    again.run_pass(hosts)
    assert sorted(written) == [("example.com", "home", "203.0.113.10"), ("example.com", "new", "203.0.113.10"),
                               ("example.net", "@", "203.0.113.10")]
    again.let_go("home.example.com")
    assert not again.taken("home.example.com") and again.own("home.example.com") is None
    assert ddns.minutes_of("0.2") == 1.0 and ddns.minutes_of("") == 5.0 and ddns.minutes_of("x") == 5.0


def test_dynamic_dns_never_cuts_several_addresses_writes_a_stale_one_or_runs_on_once_stopped():
    import threading

    records = {"lb.example.com": ["203.0.113.9", "198.51.100.1"], "home.example.com": []}
    written = []
    keeper = ddns.Keeper(read=lambda h: records[h.fqdn], write=lambda h, ip: written.append(h.fqdn) or "set",
                         public=lambda: ("203.0.113.9", "x"))
    hosts, _ = ddns.hosts_of("lb.example.com", ["example.com"])
    r = keeper.run_pass(hosts)[0]
    assert written == [] and r["foreign"] and r["result"].startswith("holds 2 addresses (203.0.113.9, 198.51.100.1)")
    answers = iter(["203.0.113.9", "203.0.113.11"])  # the address changes between the pass's ask and its write
    stale = ddns.Keeper(read=lambda h: records[h.fqdn], write=lambda h, ip: written.append(h.fqdn) or "set",
                        public=lambda: (next(answers), "x"))
    home, _ = ddns.hosts_of("home.example.com", ["example.com"])
    assert stale.run_pass(home)[0]["result"] == "this network's address changed to 203.0.113.11 during the pass: set on the next one"
    assert written == []
    stop = threading.Event()
    stop.set()
    fresh = ddns.Keeper(read=lambda h: records[h.fqdn], write=lambda h, ip: written.append(h.fqdn) or "set",
                        public=lambda: ("203.0.113.9", "x"))
    assert fresh.run_pass(home, stop=stop) == [] and written == []  # detached: nothing written
    late = threading.Event()  # detached while the address is asked again just before the write (1.49.4)
    asked = iter(["203.0.113.9", "203.0.113.9"])

    def public():
        ip = next(asked)
        if late.is_set() is False and not hasattr(public, "once"):
            public.once = True
        else:
            late.set()
        return ip, "x"

    slow = ddns.Keeper(read=lambda h: records[h.fqdn], write=lambda h, ip: written.append(h.fqdn) or "set", public=public)
    slow.run_pass(home, stop=late)
    assert written == [] and late.is_set()
    assert slow.known() == [] and keeper.known() == []  # nothing its own yet: none written, none taken
    keeper.take_over("lb.example.com")
    assert keeper.known() == ["lb.example.com"]


def test_a_secret_pasted_with_its_line_break_is_scrubbed_and_never_sent():
    from liminal_libs.machines.rest import scrub

    token = "dop_v1_secret-token-0123456789\r\n"
    said = "InvalidHeader: Invalid return character in header value: 'Bearer dop_v1_secret-token-0123456789\r\n'"
    assert "secret-token" not in scrub(said, [token])
    key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n"
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" not in scrub("the key MIIEvQIBADANBgkqhkiG9w0BAQEFAASC was refused", [key])
    with pytest.raises(ValueError, match="space or a line break"):
        bearer("abc def")("GET", "https://api.example.org/x", {}, b"")
    assert bearer(" tok \n")("GET", "https://api.example.org/x", {}, b"")["Authorization"] == "Bearer tok"


def test_the_helpers_asks_of_1_49_1():
    # a 403 is a right missing: the token is kept; a 401 drops it
    refused = []
    t = Transport((403, {}, {"message": "AuthorizationFailed"}), (401, {}, {"message": "expired"}))
    api = RestClient("https://api.example.org", transport=t, on_refused=lambda: refused.append(1))
    for _ in range(2):
        with pytest.raises(RestError):
            api.get("/x")
    assert refused == [1]
    # a vendor's own "slow down" (Route 53's 400 Throttling) waited out like a 429, a raw XML body sent as it is
    slept: list = []
    t = Transport((400, {}, b"<ErrorResponse><Error><Code>Throttling</Code></Error></ErrorResponse>"), (200, {}, b"<ok/>"))
    api = RestClient("https://api.example.org", transport=t, sleep=slept.append, throttled=lambda a: b"Throttling" in a.body)
    got = api.request("POST", "/zone", data=b"<Change/>", headers={"Content-Type": "application/xml"})
    assert got.body == b"<ok/>" and t.sent[0][3] == b"<Change/>" and t.sent[0][2]["Content-Type"] == "application/xml"
    assert len(slept) == 1
    with pytest.raises(ValueError):
        api.request("POST", "/zone", data=b"x", json={})
    # the limits of reads and of writes kept both; a reset's epoch said as a clock time; a vendor's own retry-after
    t = Transport((200, {"X-Ms-Ratelimit-Remaining-Subscription-Reads": "11999"}, {}),
                  (200, {"X-Ms-Ratelimit-Remaining-Subscription-Writes": "1199", "RateLimit-Reset": "1800000000"}, {}),
                  (429, {"x-ms-ratelimit-microsoft.costmanagement-qpu-retry-after": "7"}, {}), (200, {}, {}))
    slept.clear()
    api = RestClient("https://api.example.org", transport=t, sleep=slept.append)
    api.get("/a"), api.post("/b", {}), api.get("/c")
    assert set(api.seen.limits) >= {"x-ms-ratelimit-remaining-subscription-reads", "x-ms-ratelimit-remaining-subscription-writes"}
    from liminal_libs.machines.rest import clock_of

    assert api.facts()["ratelimit-reset"] == "1800000000" and slept == [7.0]  # as given: a plugin words it
    assert clock_of("ratelimit-reset", "1800000000").endswith("(1800000000)") and clock_of("x", "5") == "5"
    # pages send their filter header with each page
    t = Transport((200, {}, {"data": [1], "page": 1, "pages": 2}), (200, {}, {"data": [2], "page": 2, "pages": 2}))
    api = RestClient("https://api.example.org", transport=t)
    nxt = lambda d, p: ("/l", {**p, "page": d["page"] + 1}) if d["page"] < d["pages"] else None  # noqa: E731
    assert list(api.pages("/l", {"page": 1}, items="data", next_of=nxt, headers={"X-Filter": "{}"})) == [1, 2]
    assert all(s[2]["X-Filter"] == "{}" for s in t.sent)
    # the keeper's start of a pass, its own empty words
    passes = []
    keeper = ddns.Keeper(read=lambda h: [], write=lambda h, ip: "made", public=lambda: ("203.0.113.9", "x"),
                         on_pass=lambda: passes.append(1))
    keeper.run_pass([])
    assert passes == [1] and keeper.table([], 5, empty="The domains are not read yet.")["empty"] == "The domains are not read yet."


def test_the_link_check_asks_a_page_once_and_knows_an_error_page():
    from liminal_libs.sources import apis as A

    api = A.Api(name="x", maker="x", about="x", verified="2026-11-11",
                links=(A.Link("Ref", "https://docs.example.org/api#one", "reference"),
                       A.Link("Two", "https://docs.example.org/api#two", "guide"),
                       A.Link("Gone", "https://www.example.org/old", "docs")))
    asked = []

    def get(url, timeout):
        asked.append(url)
        return (200, "https://www.example.org/errors/404") if url.endswith("/old") else 200

    assert A.dead_links((api,), get=get) == [("https://www.example.org/old",
                                              "sent on to an error page: https://www.example.org/errors/404")]
    assert asked == ["https://docs.example.org/api", "https://www.example.org/old"]


def test_dynamic_dns_without_an_address_or_a_record_says_so():
    keeper = ddns.Keeper(read=lambda h: None, write=lambda h, ip: "set", public=lambda: (None, "no server answered"))
    hosts, _ = ddns.hosts_of("home.example.com", ["example.com"])
    assert keeper.run_pass(hosts)[0]["result"] == "this network's address was not found: no server answered"
    keeper2 = ddns.Keeper(read=lambda h: None, write=lambda h, ip: "set", public=lambda: ("2001:db8::1", "v6"))
    assert keeper2.run_pass(hosts)[0]["ok"] is False  # an IPv6 answer is no IPv4 address
    keeper3 = ddns.Keeper(read=lambda h: None, write=lambda h, ip: "set", public=lambda: ("203.0.113.9", "x"))
    assert keeper3.run_pass(hosts)[0]["result"] == "its record could not be read"


def test_what_the_audit_found_in_the_client_1_49_3():
    # a vendor's "slow down" reader never makes a 5xx on a write send it again (it may have been done)
    t = Transport((503, {}, {"message": "Throttling maybe"}), (200, {}, {"ok": 1}))
    api = RestClient("https://api.example.org", transport=t, sleep=lambda s: None, throttled=lambda a: True)
    with pytest.raises(RestError):
        api.post("/w", {})
    assert len(t.sent) == 1
    # a list's next page given whole on another host is never sent the token
    t = Transport((200, {}, {"things": [1], "next": "https://evil.example.net/v2/things?page=2"}))
    api = RestClient("https://api.example.org/v2", auth=bearer(TOKEN), transport=t)
    nxt = lambda data, params: (data["next"], {}) if data.get("next") else None  # noqa: E731
    with pytest.raises(RestError, match="another host"):
        list(api.pages("/things", items="things", next_of=nxt))
    assert len(t.sent) == 1
    # the same host with its port named is the same host (Azure's price list: prices.azure.com:443, 1.49.5)
    t = Transport((200, {}, {"things": [1], "next": "https://api.example.org:443/v2/things?page=2"}), (200, {}, {"things": [2]}))
    api = RestClient("https://api.example.org/v2", auth=bearer(TOKEN), transport=t)
    assert list(api.pages("/things", items="things", next_of=nxt)) == [1, 2]
    # an error's raw words are cut after the secrets are taken out: a secret across the old 200th character never shows
    body = ("x" * 190 + TOKEN).encode()
    t = Transport((400, {"Content-Type": "text/plain"}, body))
    with pytest.raises(RestError) as e:
        RestClient("https://api.example.org", transport=t, secrets=(TOKEN,)).get("/x")
    assert TOKEN[:12] not in str(e.value) and "•••" in str(e.value)
