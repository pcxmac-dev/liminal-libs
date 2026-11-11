"""Who talks to whom (liminal_libs.apps.traffic): each interaction noted in its class, the same one said again counted on
its row, a count per link; a login lent noting what is read and kept by name, never a value; an app noting its page's
requests and its plugins attached, asked and detached; the programs and hosts owned code reaches, named by who called.
The audit events are raised by the tests themselves: no process starts, nothing leaves this machine."""
from __future__ import annotations

import json
import sys
from http.client import HTTPConnection

import pytest

from liminal_libs.apps import CLASSES, App, Login, RecordingLogin, Traffic, Unauthorized, node_of, program_name
from liminal_libs.apps import traffic as traffic_mod
from liminal_libs.sources.plugin import FeedPlugin

T0 = 1_800_000_000.0


class Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_each_interaction_is_noted_in_its_class_and_the_same_one_again_counted_on_its_row():
    clock = Clock()
    t = Traffic(keep=5, links=3, clock=clock)
    t.record("page", "demo", "read", "GET /api/status", 2.0)
    clock.t += 2
    t.record("page", "demo", "read", "GET /api/status", 4.0)
    t.record("demo", "acme", "status??", "status", ok=False)  # a class it does not know is a read
    rows = t.recent()
    assert [r["what"] for r in rows] == ["status", "GET /api/status"]  # the newest first
    assert rows[1]["times"] == 2 and rows[1]["ms"] == 4.0 and rows[1]["first"] == T0 and rows[1]["at"] == T0 + 2
    assert rows[0]["kind"] == "read" and rows[0]["ok"] is False and rows[0]["failed"] == 1
    links = {(k["from"], k["to"], k["kind"]): k for k in t.links()}
    assert links[("page", "demo", "read")]["count"] == 2 and links[("page", "demo", "read")]["ms"] == 3.0
    clock.t += traffic_mod.SAME_S + 1  # said again after a pause: a row of its own
    t.record("page", "demo", "read", "GET /api/status")
    assert [r["times"] for r in t.recent()] == [1, 1, 2]
    for i in range(6):  # the rows kept and the links counted are capped: the oldest out first
        t.record("a", f"b{i}", "ask", "x")
    assert len(t.recent()) == 5 and len(t.links()) == 3 and {k["to"] for k in t.links()} == {"b3", "b4", "b5"}
    snap = t.snapshot(2)
    assert snap["classes"] == CLASSES and len(snap["recent"]) == 2 and snap["seq"] == 10 and snap["since"] == T0
    assert list(CLASSES) == ["read", "change", "ask", "stream", "attach", "login", "process", "network"]


def test_a_timed_call_is_noted_when_it_ends_and_one_that_raises_as_failed():
    t = Traffic()
    with t.timed("demo", "acme", "ask", "check"):
        pass
    with pytest.raises(ValueError):
        with t.timed("demo", "acme", "ask", "check"):
            raise ValueError("no")
    row = t.recent()[0]
    assert row["times"] == 2 and row["failed"] == 1 and row["ok"] is False and row["ms"] >= 0


class Pairs(Login):
    """A stand-in login holding pairs."""

    def __init__(self, pairs: dict):
        self.pairs, self.kept = dict(pairs), {}

    def user(self) -> dict:
        return {"name": "ada"}

    def vector(self, name: str) -> str:
        if name not in self.pairs:
            raise Unauthorized(f"no pair {name}", 404)
        return self.pairs[name]

    def save(self, variable: str, value: str | None) -> str:
        self.kept[variable] = value
        return "a test's pairs"


def test_a_login_lent_notes_what_is_read_and_kept_by_name_never_a_value():
    t = Traffic()
    inner = Pairs({"acme-api-key": "s3cret-value", "acme-account-name": "ada"})
    login = RecordingLogin(inner, "acme", t)
    assert login.vector("acme-api-key") == "s3cret-value"
    with pytest.raises(Unauthorized):
        login.key("acme")  # acme-account-api-key: none, noted as failed
    assert login.variables(["ACME_API_KEY", "ACME_ACCOUNT_NAME", "B", "C"]) == {"ACME_API_KEY": "s3cret-value",
                                                                                 "ACME_ACCOUNT_NAME": "ada"}
    assert login.save("ACME_API_KEY", "n3w-value") == "a test's pairs" and inner.kept == {"ACME_API_KEY": "n3w-value"}
    login.save("ACME_API_KEY", None)
    assert login.may("acme", "fetch") is True and login.signed_in and login.describe()["kind"] == "Pairs"
    assert login.pairs is inner.pairs and isinstance(login, Login)  # the realization's own attributes, through
    rows = t.recent()
    whats = [r["what"] for r in rows]
    assert {"read acme-api-key", "read acme-account-api-key", "read ACME_API_KEY, ACME_ACCOUNT_NAME, B and 1 more",
            "keep ACME_API_KEY", "forget ACME_API_KEY", "may acme fetch?"} == set(whats)
    assert all(r["from"] == "acme" and r["to"] == "login" and r["kind"] == "login" for r in rows)
    assert [r["ok"] for r in rows if r["what"] == "read acme-account-api-key"] == [False]
    text = json.dumps(t.snapshot())
    assert "s3cret" not in text and "n3w" not in text


class AcmePlugin(FeedPlugin):
    name, title, api = "acme", "Acme", "2.0"
    assets = frozenset({"stock"})
    provides = {"stock": ("day",)}

    def build(self, settings, request_budget):
        return request_budget

    def serves(self, settings):
        return frozenset()


class TracingApp(App):
    NAME, TITLE, ICON = "demo", "Demo", "plug"
    TRACE_LOGIN = True
    READ_HOOKS = ("serves",)


def test_an_app_notes_its_pages_requests_and_its_plugins_attached_asked_and_detached(tmp_path):
    TracingApp.STATIC = tmp_path
    app = TracingApp(log=lambda m: None, login=Pairs({"acme-api-key": "k"}))
    p = AcmePlugin()
    app.attach(p)
    assert isinstance(p.login, RecordingLogin) and p.login.inner is app.login and p.login.name == "acme"
    assert app.ask("acme", "build", None, 3) == 3 and app.ask("acme", "serves", None) == frozenset()
    assert app.classify("GET", "/api/x") == "read" and app.classify("POST", "/api/x") == "change"
    app.start(0)
    try:
        port = int(app.served.rstrip("/").rsplit(":", 1)[1])
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        page = {"Sec-Fetch-Site": "same-origin"}
        for path, headers in (("/api/plugins", {}), ("/api/tray", page), ("/api/nothing", page), ("/api/traffic?last=50", page)):
            conn.request("GET", path, headers=headers)
            body = conn.getresponse().read()
        snap = json.loads(body)
    finally:
        app.stop()
    links = {(k["from"], k["to"], k["kind"]): k for k in snap["links"]}
    assert links[("client", "demo", "read")]["what"] == "GET /api/plugins"  # a program: no browser's headers
    assert links[("page", "demo", "read")]["count"] == 2 and links[("page", "demo", "read")]["failed"] == 1  # the 404
    assert ("demo", "acme", "attach") in links and links[("demo", "acme", "ask")]["what"] == "build"
    assert links[("demo", "acme", "read")]["what"] == "serves"  # a hook that only reads
    assert not any("/api/traffic" in k["what"] for k in snap["links"])  # the picture's own reads are not noted
    nodes = {n["id"]: n for n in snap["nodes"]}
    assert nodes["demo"]["role"] == "app" and nodes["login"]["role"] == "login" and nodes["acme"]["role"] == "plugin"
    assert nodes["acme"]["attached"] is True and nodes["page"]["role"] == "caller" and nodes["client"]["role"] == "caller"
    assert snap["app"] == "demo" and snap["classes"] == CLASSES and len(snap["recent"]) <= 50
    assert app.detach("acme") and app.traffic.recent()[0]["what"] == "detached"


class Prober:
    """A plugin's code reaching out: the audit events raised by hand (nothing starts, nothing is sent)."""

    def run(self, argv):
        sys.audit("subprocess.Popen", None, argv, None, None)

    def reach(self, name, address):
        sys.audit("socket.getaddrinfo", name, address[1], 0, 0, 0)
        sys.audit("socket.connect", None, address)

    def send(self, address):
        sys.audit("socket.sendto", None, address)


def test_the_programs_and_hosts_owned_code_reaches_are_noted_by_who_called_never_an_argument():
    t = Traffic()
    plugin, itself, nobody = Prober(), Prober(), Prober()
    t.own(plugin, "acme")
    t.own(itself, "demo")
    t.me = "demo"
    t.watch({8795: "login", 8775: "demo"})
    plugin.run([r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-EncodedCommand", "c2VjcmV0"])
    plugin.run('"C:\\Program Files\\Docker\\docker.exe" ps --format json')
    plugin.reach("updates.invalid", ("192.0.2.10", 443))
    plugin.reach("localhost", ("127.0.0.1", 8795))
    plugin.reach("localhost", ("127.0.0.1", 9))
    plugin.send(("239.255.255.250", 1900))
    itself.reach("localhost", ("127.0.0.1", 8775))  # the app at its own port: a call to itself, not drawn
    nobody.run(["notepad.exe"])  # code no one owns: not noted
    sys.audit("subprocess.Popen", None, ["calc.exe"], None, None)  # nor the test's own
    t.unwatch()
    plugin.run(["wsl.exe"])  # no longer watched
    assert {(k["from"], k["to"], k["kind"]): k["what"] for k in t.links()} == {
        ("acme", "process:powershell", "process"): "started",
        ("acme", "process:docker", "process"): "started",
        ("acme", "host:updates.invalid", "network"): "connect :443",
        ("acme", "app:login", "network"): "connect :8795",
        ("acme", "host:this machine", "network"): "connect :9",
        ("acme", "host:239.255.255.250", "network"): "send :1900",
    }
    text = json.dumps(t.snapshot())
    assert "c2VjcmV0" not in text and "--format" not in text and "Program Files" not in text


class Host:
    """An app's own code calling its plugin."""

    def call(self, plugin):
        plugin.run(["wsl.exe", "-l"])


def test_of_two_apps_watching_in_one_process_each_names_its_own():
    first, second = Traffic(), Traffic()
    first.owners_by_package[Host.__module__.partition(".")[0]] = "first"  # the first owns this code's package
    plugin = Prober()
    second.own(plugin, "acme")  # the second owns the plugin itself
    first.watch()
    second.watch()
    try:
        Host().call(plugin)  # the innermost owner names it: the plugin's own frame, the second's
        assert [(k["from"], k["to"]) for k in second.links()] == [("acme", "process:wsl")] and first.links() == []
        second.unwatch()
        Host().call(plugin)
        assert second.links()[0]["count"] == 1 and [k["from"] for k in first.links()] == ["first"]
    finally:
        first.unwatch()
        second.unwatch()


def test_a_program_is_named_without_its_folder_or_arguments_and_each_end_drawn_as_what_it_is():
    assert program_name(None, ["/usr/bin/nslookup", "-type=TXT", "x"]) == "nslookup"
    assert program_name("C:\\Windows\\system32\\wsl.exe", ["wsl", "-d", "Liminal-Ubuntu"]) == "wsl"
    assert program_name(None, '"C:\\Program Files\\Git\\bin\\bash.exe" -lc "echo $SECRET"') == "bash"
    assert program_name(None, "ping -n 1 192.0.2.1") == "ping" and program_name(None, b"tracert -d 1.1.1.1") == "tracert"
    assert program_name(None, []) == "" and program_name(None, None) == ""
    assert node_of("process:wsl")["role"] == "outside" and node_of("host:updates.invalid")["icon"] == "globe"
    assert node_of("app:login")["icon"] == "lambda" and node_of("page")["role"] == "caller" and node_of("acme")["role"] == "plugin"
