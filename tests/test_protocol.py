"""What every protocol plugin of the platform shares (liminal_libs.machines.protocol, 1.66.0): a stand-in subclass
that conforms and declares its contract words (the hooks only another plugin asks, the hooks only its page asks); its
software a part of it, said so and with nothing to install or remove; its agents and their grants kept through the
login (a round trip, the names, the names no agent takes, every pair at its cap), read once and used from memory, a
pair changed outside the plugin not used and said; tokens kept as their sha256 alone and compared with
hmac.compare_digest (a hand-wired one shown once and ending, a launch token the asking plugin's alone, ended by
end_launch, by a stop and by the 33rd); the route's hook (401 without a known token, the token never handed on, an
agent's rate, a protocol's faults, every request noted); calls held for the user's answer (answered, timed out on a
stand-in clock, dropped by gone(), cancelled, ended by a stop or by the agent forgotten, asked twice, allowed for a
session, 4 for one agent and 16 in all, arguments past 16 KiB refused); the audit (the ring, the log moved aside, no
argument on disk, secrets masked) and the platform's traffic rows; and its Main.

Who asks is the platform's to say (apps/asking.py): a stand-in for protocol.asker says it here. Nothing is started or
reached: the login is a stand-in, the clock is one where a test waits on it, a held call's waits are the test's, and
the shared guard (conftest.py) fails a test that starts a process or opens a connection. Threads stand for the
requests a call is held in, and each is waited for in order: a call is answered only once it is known to wait."""
from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import re
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from liminal_libs import instances, internal
from liminal_libs.apps.authorization import Login, Unauthorized, pair_name, variable_name
from liminal_libs.apps.traffic import Traffic
from liminal_libs.machines import protocol
from liminal_libs.machines.ai import AiPlugin, Installed, Outside, Package
from liminal_libs.machines.protocol import (ACCEPT_SHOWN, ACCEPT_TWICE, DAYS_MOST, HOLD_MOST, MAX_CLIENTS, MAX_GRANTS,
                                            MAX_HELD, MAX_HELD_EACH, MAX_LAUNCH, POLL_S, RATE_MOST, RULES, SESSION_S,
                                            Held, ProtocolPlugin, Refusal, agent_of, clients_of, clients_text,
                                            digest_of, grants_of, grants_text, visible)

pytestmark = pytest.mark.usefixtures("no_outside")

WRITTEN = re.compile(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]")  # a scheme, then a host (test_ai_boundary.py's)
CLIENTS = "LIMINAL_AI_GATE_CLIENTS"
SECRET = "sk-server-secret-0123456789"  # a server's key the plugin knows: masked wherever it would show


class Pairs(Login):
    """The platform's login as a test has it: pairs kept in memory, each read counted."""

    def __init__(self):
        self.kept: dict[str, str] = {}
        self.reads = 0

    def user(self) -> dict:
        return {"name": "someone"}

    def vector(self, name: str) -> str:
        self.reads += 1
        variable = variable_name(name)
        if variable not in self.kept:
            raise Unauthorized(f"no {name}", 404)
        return self.kept[variable]

    def names(self) -> set[str]:
        return {pair_name(v) for v in self.kept}

    def save(self, variable: str, value: str | None) -> str:
        if value is None:
            self.kept.pop(variable, None)
        else:
            self.kept[variable] = value
        return "the test's pairs"


class App:
    """The platform as a plugin attached to it sees it here: its traffic alone."""

    def __init__(self):
        self.traffic = Traffic()


class Who:
    """Who asks, as the platform would hand it over (protocol.asker's stand-in)."""

    def __init__(self):
        self.who: str | None = None

    def __call__(self) -> str | None:
        return self.who


class Clock:
    def __init__(self, now: float = 1_800_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class Waits:
    """A held call's waits, the test's: each one noted (a call has reached its wait), then waited out on the call's own
    event, a bounded real time, so that a test that never answers fails rather than hangs."""

    def __init__(self):
        self.seen = threading.Condition()
        self.arrived = 0

    def __call__(self, event: threading.Event, seconds: float) -> bool:
        with self.seen:
            self.arrived += 1
            self.seen.notify_all()
        if not event.wait(10):
            raise AssertionError("a held call was never answered")
        return True

    def until(self, n: int) -> None:
        """Until `n` calls wait: answering one before is the race a test does not leave to luck."""
        with self.seen:
            assert self.seen.wait_for(lambda: self.arrived >= n, 10), f"{n} calls never came to wait"


class Gate(ProtocolPlugin):
    """A stand-in protocol plugin: its protocol notes each request and answers with whom it served, unless the test
    says otherwise."""

    name = "gate"
    title = "Gate"
    about = "A stand-in protocol plugin for the base's tests"
    order = 530
    version = "0.1.0"

    def __init__(self, outside=None):
        super().__init__(outside)
        self.served: list[tuple] = []  # (method, headers, body, client)
        self.answer = None  # what serve answers; None: 200, with whom it served
        self.fails: BaseException | None = None
        self.notes = True  # whether serve notes the request itself
        self.offered = {"server:git": RULES, "status:docker": {"title": "Docker's status", "hows": ("on", "off")}}

    def serve(self, method, headers, body, client, gone):
        self.served.append((method, dict(headers), body, client))
        if self.fails is not None:
            raise self.fails
        if self.notes:
            self.record(client, method, "tools/list", "answered", era="2025-11-25", kind="read", arguments=body)
        if self.answer is not None:
            return self.answer
        return 200, {"client": client}, {"Mcp-Session-Id": "s1"}

    def offer(self, client):  # (in the words a harness reads: machines/harness.py's _offer_of)
        return {"bridge": ["python", "-I", "-S", "bridge.py", "--port", "8775"], "endpoint": "/api/machines/gate/rpc",
                "headers": {"X-Liminal-Charts": "1"}, "revisions": ["2026-07-28", "2025-11-25"],
                "wires": ["stdio", "http"]}

    def grantable(self):
        return self.offered


def made(tmp_path, clock, cls=Gate, login=None, app=None):
    plugin = cls(Outside(env={}, home=tmp_path / cls.name, clock=clock))
    plugin.attach(app or App(), login if login is not None else Pairs())
    return plugin


@pytest.fixture
def asking(monkeypatch):
    who = Who()
    monkeypatch.setattr(protocol, "asker", who)
    return who


@pytest.fixture
def world(tmp_path, asking):
    clock, login, app = Clock(), Pairs(), App()
    gate = made(tmp_path, clock, login=login, app=app)
    return SimpleNamespace(g=gate, clock=clock, login=login, app=app, asking=asking, home=tmp_path / "gate")


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def held(plugin, *args, **kwargs):
    """A call held in a thread of its own, as a request's is: (the thread, what it ends with)."""
    out: dict = {}
    thread = threading.Thread(target=lambda: out.setdefault("held", plugin.hold(*args, **kwargs)), daemon=True)
    thread.start()
    return thread, out


def ended(thread, out) -> Held:
    thread.join(10)
    assert not thread.is_alive(), "the held call never ended"
    return out["held"]


# -- what it is ------------------------------------------------------------------------------------------------------
def test_the_base_is_a_standard_interface_of_its_own(world):
    g = world.g
    assert internal.problems(g) == []
    assert (g.SECTION, g.GROUP, g.RPC_HOOK) == ("ai", "protocol", "rpc")
    assert "rpc" in g.HOOKS and not {"install", "uninstall"} & set(g.HOOKS)
    plugins, page = internal.declared(g, "PLUGIN_ONLY_HOOKS"), internal.declared(g, "PAGE_ONLY_HOOKS")
    assert plugins == ("ensure_client", "launch_token", "end_launch")
    assert page == ("add_client", "forget_client", "grant", "token_once", "revoke", "waiting_call", "decide")
    assert not set(plugins) & set(page) and set(plugins) | set(page) <= set(g.HOOKS)
    assert internal.declared(g, "SERVICE_HOOKS") == ("client_offer", "ensure_client", "launch_token", "end_launch")
    reads = internal.declared(g, "READ_HOOKS")
    assert {"clients", "pending", "calls", "client_offer", "waiting_call", "refresh", "status"} <= set(reads)
    assert "rpc" not in reads and not set(plugins) & set(reads)
    got = internal.internal_of(g)
    assert [s["class"] for s in got["standard"]] == ["ProtocolPlugin", "AiPlugin", "MachinePlugin", "Plugin"]
    assert [k["variable"] for k in got["keeps"]] == [CLIENTS, "LIMINAL_AI_GATE_AGENT_<A>_GRANTS"]
    assert any("sha256" in n for n in got["notes"]) and json.loads(json.dumps(got)) == got
    assert g.token_variable == "LIMINAL_GATE_TOKEN"
    assert g.grants_variable("alice") == "LIMINAL_AI_GATE_AGENT_ALICE_GRANTS"


def test_its_software_is_part_of_it_with_nothing_to_install(world, tmp_path):
    g = world.g
    have = g.installed()
    assert (have.how, have.version, have.path, g.package()) == ("part", "0.1.0", str(Path(__file__).parent), None)
    words = "Gate 0.1.0: part of this plugin, nothing to install"
    out = g.status()
    assert out["installed"] == words and out["valid"] and "problem" not in out
    assert not [f for f in out["forms"] if f["hook"] in ("install", "uninstall")]
    assert not [a for a in out["actions"] if a.get("form") in ("ai-install", "ai-uninstall", "ai-forget-download")]
    assert g.refresh()["said"] == f"read again: {words}"
    for hook in ("install", "uninstall"):
        with pytest.raises(LookupError):
            g.ask(hook)
    with pytest.raises(Refusal, match="Gate is part of this plugin: there is nothing to install"):
        AiPlugin.install(g, accept_licence=True)
    with pytest.raises(Refusal, match="Gate is part of this plugin: there is nothing to remove"):
        AiPlugin.uninstall(g, accept_removal=True)
    assert not (world.home / "app").exists()
    assert Installed("", "/x", "part").how == "part"
    with pytest.raises(ValueError, match="a part of the plugin"):
        Installed("1", "/x", "borrowed")

    class Bundled(AiPlugin):  # any AI plugin whose software is a part of it: no Install… even with a package
        name, title = "bundled", "Bundled"

        def package(self):
            return Package("Bundled", "2.0", 0, "MIT.", ())

        def installed(self):
            return Installed("", "/x", "part")

    main = Bundled(Outside(env={}, home=tmp_path / "bundled")).base_status()
    assert main["installed"] == main["summary"] == "Bundled: part of this plugin, nothing to install"
    assert [a["title"] for a in main["actions"]] == ["Read again"] and main["forms"] == []


# -- its agents and their grants --------------------------------------------------------------------------------------
def test_agents_and_their_grants_are_kept_through_the_login(world, tmp_path):
    g, login = world.g, world.login
    world.asking.who = "page"
    said = g.add_client("Alice", "Alice's agent")
    assert said["ok"] and "granted nothing" in said["said"]
    kept = json.loads(login.kept[CLIENTS])
    assert kept["v"] == 1 and list(kept["clients"]) == ["alice"]
    entry = kept["clients"]["alice"]
    assert (entry["title"], entry["by"], entry["digest"], entry["expires"], entry["hold_s"], entry["rate"]) == (
        "Alice's agent", "", "", 0, 50, 60)
    assert g.grants_of("alice") == {} and g.clients()[0]["grants"] == 0  # a new agent is granted nothing
    g.grant("alice", "server:git", "ask")
    g.grant("alice", "status:docker", "on")
    g.grant("alice", "hold", 120)
    g.grant("alice", "rate", "30")
    assert json.loads(login.kept["LIMINAL_AI_GATE_AGENT_ALICE_GRANTS"]) == {
        "v": 1, "grants": {"server:git": "ask", "status:docker": "on"}}
    again = made(tmp_path / "again", world.clock, login=login)  # the platform started again: read once, at attach
    assert again.grants_of("alice") == {"server:git": "ask", "status:docker": "on"}
    row = again.clients()[0]
    assert (row["name"], row["title"], row["hold_s"], row["rate"], row["grants"], row["token"]) == (
        "alice", "Alice's agent", 120, 30, 2, "none")
    for what, how in (("server:hg", "ask"), ("server:git", "sometimes"), ("hold", 5), ("hold", 601), ("rate", 0),
                      ("rate", "x"), ("status:docker", "ask")):
        with pytest.raises(Refusal):
            g.grant("alice", what, how)
    with pytest.raises(LookupError, match="no agent 'nobody'"):
        g.grant("nobody", "server:git", "ask")
    g.grant("alice", "server:git", "")  # empty: forgotten, so not granted
    g.grant("alice", "status:docker", None)
    assert "LIMINAL_AI_GATE_AGENT_ALICE_GRANTS" not in login.kept
    with pytest.raises(Refusal, match="nothing to forget"):
        g.grant("alice", "server:git", None)
    said = g.forget_client("alice")
    assert said["ok"] and CLIENTS not in login.kept and g.clients() == [] and g.agents() == []
    with pytest.raises(LookupError):
        g.forget_client("alice")


def test_names_and_the_names_no_agent_takes(world):
    g = world.g
    world.asking.who = "page"
    for bad in ("codex-cli", "a" * 25, "", "  ", "al ice", "élan", None, "x_y"):
        with pytest.raises(Refusal, match="1 to 24 lowercase letters and digits, with no hyphen"):
            g.add_client(bad)
    for reserved in ("platform", "mcp", "liminal", "page", "MCP"):
        with pytest.raises(Refusal, match="no agent takes"):
            g.add_client(reserved)
    g.add_client("BOB1")
    assert g.agents() == ["bob1"]
    with pytest.raises(Refusal, match="an agent here already"):
        g.add_client("bob1")
    assert agent_of("codex-cli") == "codexcli" and agent_of("Open-Code") == "opencode"
    for plugin in ("a-very-long-plugin-name-indeed", "mcp", "liminal", "plug_in"):
        world.asking.who = plugin
        with pytest.raises(Refusal, match="cannot have an agent here"):
            g.ensure_client("Its title")
    assert g.agents() == ["bob1"]
    # what was kept and cannot be read is said, and left out
    assert clients_of('{"v": 1, "clients": {"ok": {"title": "Ok"}, "Bad-Name": {}, "mcp": {}}}')[0].keys() == {"ok"}
    assert "2 of its kept agents could not be read and are left out" in clients_of(
        '{"v": 1, "clients": {"ok": {}, "Bad-Name": {}, "mcp": {}}}')[1]
    assert clients_of("not json")[1].startswith("what is kept of its agents is not readable")
    assert grants_of('{"v": 1, "grants": {"server:git": "ask", "": "x", "a b": "allow"}}')[0] == {"server:git": "ask"}


def test_every_pair_is_kept_whole_at_its_cap(world):
    g, login = world.g, world.login
    world.asking.who = "page"
    for i in range(MAX_CLIENTS):
        g.add_client(f"agent{i:02d}", "T" * instances.MAX_TITLE)
    with pytest.raises(Refusal, match=f"{MAX_CLIENTS} agents at most"):
        g.add_client("onemore")
    world.asking.who = "codex-cli"
    with pytest.raises(Refusal, match=f"{MAX_CLIENTS} agents at most"):
        g.ensure_client("Codex CLI")
    world.asking.who = "page"
    for name in g.agents():
        g.token_once(name, DAYS_MOST, True)
        g.grant(name, "hold", HOLD_MOST)
        g.grant(name, "rate", RATE_MOST)
    assert len(login.kept[CLIENTS]) < instances.MAX_KEPT
    # the fullest the kept value holds: every word at its longest
    whole = {f"a{i:023d}": {"title": "T" * instances.MAX_TITLE, "made": "2026-11-18T23:59:59Z", "by": "p" * 64,
                            "digest": "f" * 64, "expires": 2 ** 53, "hold_s": HOLD_MOST, "rate": RATE_MOST}
             for i in range(MAX_CLIENTS)}
    text = clients_text(whole)
    assert len(text) < instances.MAX_KEPT and clients_of(text) == (whole, "")
    # an agent's grants at their cap: MAX_GRANTS of the longest names, each taken as its longest how
    g.offered = {f"tool:{'x' * 150}{i:05d}": ("ask twice", "x" * 16) for i in range(MAX_GRANTS + 1)}
    agent, whats = g.agents()[0], list(g.offered)
    for what in whats[:MAX_GRANTS]:
        g.grant(agent, what, "x" * 16)
    with pytest.raises(Refusal, match=f"{MAX_GRANTS} grants at most"):
        g.grant(agent, whats[-1], "ask twice")
    kept = login.kept[g.grants_variable(agent)]
    assert len(kept) < instances.MAX_KEPT and grants_of(kept) == ({w: "x" * 16 for w in whats[:MAX_GRANTS]}, "")
    assert grants_text({}) is None and clients_text({}) is None


def test_its_pairs_are_read_once_and_one_changed_outside_is_not_used(world, tmp_path):
    g, login = world.g, world.login
    world.asking.who = "page"
    g.add_client("alice")
    alice = g.token_once("alice", 30, True)["token"]
    g.grant("alice", "server:git", "allow")
    reads = login.reads
    assert [g.rpc("POST", bearer(alice), {})[0] for _ in range(3)] == [200, 200, 200]
    assert login.reads == reads  # used from memory: no request asks the login
    # a program of the user's writes the agents' pair: an agent of its own, with a token it knows
    token = "an-outsiders-token-0123456789"
    outside = json.loads(login.kept[CLIENTS])
    outside["clients"]["mallory"] = {"title": "Mallory", "made": "", "by": "", "digest": digest_of(token),
                                     "expires": 2 ** 40, "hold_s": 50, "rate": 60}
    login.kept[CLIENTS] = json.dumps(outside)
    login.kept[g.grants_variable("alice")] = grants_text({"server:git": "allow", "status:docker": "on"})
    assert g.rpc("POST", bearer(token), {})[0] == 401 and g.agents() == ["alice"]
    assert g.grants_of("alice") == {"server:git": "allow"}
    problem = g.status()["problem"]
    assert ("LIMINAL_AI_GATE_CLIENTS and LIMINAL_AI_GATE_AGENT_ALICE_GRANTS were changed outside Gate since it read "
            "them: that is not used") in problem
    g.add_client("bob")  # its own write: what it uses is kept again, the outside agent with it gone
    assert "mallory" not in json.loads(login.kept[CLIENTS])["clients"]
    problem = g.status()["problem"]
    assert "LIMINAL_AI_GATE_AGENT_ALICE_GRANTS was changed outside" in problem and CLIENTS not in problem
    g.grant("alice", "server:git", "ask")
    assert "problem" not in g.status()
    login.kept[g.grants_variable("bob")] = grants_text({"server:git": "allow"})  # a new agent's, never kept here
    assert g.grants_of("bob") == {} and "LIMINAL_AI_GATE_AGENT_BOB_GRANTS was changed outside" in g.status()["problem"]
    login.kept.pop(g.grants_variable("bob"))
    login.kept[CLIENTS] = json.dumps(outside)
    g.attach(world.app, login)  # turned off and on: read anew, and used
    assert "mallory" in g.agents() and g.rpc("POST", bearer(token), {})[1] == {"client": "mallory"}


# -- tokens -----------------------------------------------------------------------------------------------------------
def test_a_hand_wired_token_is_shown_once_and_kept_as_its_digest(world):
    g, login, clock = world.g, world.login, world.clock
    world.asking.who = "page"
    g.add_client("alice")
    with pytest.raises(Refusal) as refused:
        g.token_once("alice")
    assert refused.value.accept == ACCEPT_SHOWN and "shown once" in str(refused.value)
    assert json.loads(login.kept[CLIENTS])["clients"]["alice"]["digest"] == ""  # nothing was made
    shown = g.token_once("alice", 30, True)
    token = shown["token"]
    assert len(token) >= 43 and any(token in line for line in shown["lines"]) and shown["agent"] == "alice"
    entry = json.loads(login.kept[CLIENTS])["clients"]["alice"]
    assert entry["digest"] == hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert entry["expires"] == int(clock.now) + 30 * 86400 and token not in login.kept[CLIENTS]
    status, body, headers = g.rpc("POST", {**bearer(token), "Content-Type": "application/json"}, {"jsonrpc": "2.0"})
    assert (status, body, headers) == (200, {"client": "alice"}, {"Mcp-Session-Id": "s1"})
    method, handed, sent, client = g.served[-1]
    assert (method, client, sent) == ("POST", "alice", {"jsonrpc": "2.0"})
    assert handed == {"content-type": "application/json"}  # its token is never handed on
    second = g.token_once("alice", 1, True)["token"]
    assert g.rpc("POST", bearer(token), {})[0] == 401  # the token shown before stops working
    assert g.rpc("POST", {"authorization": f"bearer {second}"}, {})[0] == 200  # (the scheme's case does not matter)
    clock.now += 86400 + 1
    status, body, headers = g.rpc("POST", bearer(second), {})
    assert status == 401 and "expired" in body["error"] and headers == {"WWW-Authenticate": "Bearer"}
    assert g.clients()[0]["token"] == "expired"
    for days in (0, DAYS_MOST + 1, "x", 1.5, True):
        with pytest.raises(Refusal, match="a token's days"):
            g.token_once("alice", days, True)
    everything = json.dumps([login.kept, g.clients(), g.status(), g.calls(500), g.pending(), g.client_offer()])
    log = (world.home / "logs" / "calls.log").read_text(encoding="utf-8")
    assert all(t not in everything and t not in log for t in (token, second))


def test_every_digest_is_compared_with_compare_digest(world, monkeypatch):
    g = world.g
    world.asking.who = "page"
    tokens = {}
    for name in ("alice", "bob", "carol"):
        g.add_client(name)
        tokens[name] = g.token_once(name, 30, True)["token"]
    world.asking.who = "codex-cli"
    g.ensure_client("Codex CLI")
    launch = g.launch_token()["token"]
    compared, real = [], hmac.compare_digest

    def spy(a, b):
        compared.append(a)
        return real(a, b)

    monkeypatch.setattr(protocol.hmac, "compare_digest", spy)
    assert g.rpc("POST", bearer(tokens["alice"]), {})[:2] == (200, {"client": "alice"})
    assert compared == [digest_of(tokens["alice"])] * 4  # every digest known, the first matching or not
    assert g.rpc("POST", bearer(launch), {})[1] == {"client": "codexcli"}


def test_a_launch_token_is_the_asking_plugins_alone(world):
    g = world.g
    world.asking.who = None
    with pytest.raises(Refusal, match="names none"):
        g.ensure_client("Codex CLI")
    world.asking.who = "page"
    with pytest.raises(Refusal, match="never from a page"):
        g.launch_token()
    world.asking.who = "codex-cli"
    with pytest.raises(Refusal, match="no agent of its own"):
        g.launch_token()
    made_now = g.ensure_client("Codex CLI")
    assert (made_now["agent"], made_now["made"], made_now["variable"]) == ("codexcli", True, "LIMINAL_GATE_TOKEN")
    assert g.grants_of("codexcli") == {} and g.client_of("codexcli")["by"] == "codex-cli"
    assert g.ensure_client("Codex CLI")["made"] is False
    first = g.launch_token()
    token = first["token"]
    assert (first["agent"], first["variable"]) == ("codexcli", "LIMINAL_GATE_TOKEN")
    assert token not in json.dumps(world.login.kept) and digest_of(token) not in json.dumps(world.login.kept)
    assert g.rpc("POST", bearer(token), {})[1] == {"client": "codexcli"}
    world.asking.who = "open-code"  # another plugin ends nothing of codex-cli's
    g.ensure_client("OpenCode")
    assert g.end_launch(token) == {"ended": False, "agent": "opencode"}
    assert g.rpc("POST", bearer(token), {})[0] == 200
    world.asking.who = "codex-cli"
    assert g.end_launch(token) == {"ended": True, "agent": "codexcli"}
    assert g.rpc("POST", bearer(token), {})[0] == 401
    assert g.end_launch(token)["ended"] is False and g.end_launch(None)["ended"] is False
    minted = [g.launch_token()["token"] for _ in range(MAX_LAUNCH + 1)]  # the 33rd pushes out the oldest
    assert g.rpc("POST", bearer(minted[0]), {})[0] == 401
    assert [g.rpc("POST", bearer(t), {})[0] for t in minted[1:]] == [200] * MAX_LAUNCH
    assert next(c for c in g.clients() if c["name"] == "codexcli")["launch"] == MAX_LAUNCH
    g.app_stopping()  # the stop ends every one
    assert g.rpc("POST", bearer(minted[-1]), {})[0] == 401
    with pytest.raises(Refusal, match="stopping"):
        g.launch_token()
    g.attach(world.app, world.login)
    assert g.rpc("POST", bearer(g.launch_token()["token"]), {})[0] == 200
    world.asking.who = "page"  # an agent added on the page is no plugin's
    g.add_client("cline")
    world.asking.who = "cline"
    with pytest.raises(Refusal, match="made on its page"):
        g.ensure_client("Cline")
    with pytest.raises(Refusal, match="no agent of its own"):
        g.launch_token()


def test_revoke_ends_every_token_and_keeps_the_grants(world):
    g = world.g
    world.asking.who = "codex-cli"
    g.ensure_client("Codex CLI")
    launch = g.launch_token()["token"]
    world.asking.who = "page"
    hand = g.token_once("codexcli", 30, True)["token"]
    g.grant("codexcli", "server:git", "allow")
    said = g.revoke("codexcli")
    assert said["ok"] and "1 launch token ended" in said["lines"]
    assert [g.rpc("POST", bearer(t), {})[0] for t in (launch, hand)] == [401, 401]
    assert g.grants_of("codexcli") == {"server:git": "allow"}
    assert json.loads(world.login.kept[CLIENTS])["clients"]["codexcli"]["digest"] == ""


@pytest.mark.parametrize("hook,args", [("add_client", ("alice",)), ("forget_client", ("alice",)),
                                       ("grant", ("alice", "server:git", "ask")), ("token_once", ("alice", 30, True)),
                                       ("revoke", ("alice",)), ("waiting_call", ("ticket",)),
                                       ("decide", ("ticket", "once"))])
def test_a_page_only_hook_is_refused_unless_its_page_asks(world, hook, args):
    g = world.g
    world.asking.who = "page"
    if hook != "add_client":
        g.add_client("alice")
    before = dict(world.login.kept)
    for who, said in ((None, "does not say that it comes from there"),
                      ("codex-cli", "never by another plugin (codex-cli)")):
        world.asking.who = who
        with pytest.raises(Refusal, match=re.escape(said)):
            getattr(g, hook)(*args)
        with pytest.raises(Refusal, match=re.escape(said)):
            g.ask(hook, *args)
    assert world.login.kept == before


@pytest.mark.parametrize("hook,args", [("ensure_client", ("Codex CLI",)), ("launch_token", ()),
                                       ("end_launch", ("a-token",))])
def test_a_plugin_only_hook_is_refused_unless_a_plugin_asks(world, hook, args):
    g = world.g
    for who, said in ((None, "names none"), ("page", "never from a page"), ("gate", "not by Gate itself")):
        world.asking.who = who
        with pytest.raises(Refusal, match=said):
            getattr(g, hook)(*args)
    assert world.login.kept == {}


# -- the route's hook -------------------------------------------------------------------------------------------------
def test_the_routes_hook_answers_in_words_and_never_raises(world, tmp_path):
    g = world.g
    world.asking.who = "page"
    g.add_client("alice")
    token = g.token_once("alice", 30, True)["token"]
    status, body, headers = g.rpc("POST", {}, {})
    assert (status, headers) == (401, {"WWW-Authenticate": "Bearer"}) and "no bearer token" in body["error"]
    for said in ({"Authorization": "Bearer nonsense"}, {"Authorization": "Basic abc"},
                 {"Authorization": "Bearer " + "x" * 600}, {"Authorization": "Bearer"}):
        assert g.rpc("POST", said, {})[0] == 401
    assert g.rpc(None, None, None)[0] == 401 and g.rpc("POST", "not headers", 5)[0] == 401
    assert g.served == []  # nothing reached its protocol
    g.fails = RuntimeError(f"its protocol broke, holding {SECRET}")
    g.remember_secret(SECRET)
    status, body, _ = g.rpc("POST", bearer(token), {})
    assert status == 500 and "its protocol broke" in body["error"] and SECRET not in body["error"]
    assert g.calls()[0]["decision"] == "failed"
    g.fails, g.answer = None, ("bad",)
    assert g.rpc("POST", bearer(token), {})[0] == 500
    g.answer = (202, None, {})
    assert g.rpc("POST", bearer(token), {}) == (202, None, {})
    g.answer = (204, None)
    assert g.rpc("DELETE", bearer(token), None) == (204, None, {})
    g.notes, g.answer = False, None  # a request its protocol notes nothing of is noted all the same, once
    before = len(g.calls(500))
    g.rpc("get", bearer(token), None)
    assert len(g.calls(500)) == before + 1 and (g.calls()[0]["method"], g.calls()[0]["decision"]) == ("GET",
                                                                                                    "answered")

    class Bare(ProtocolPlugin):  # the base's own protocol: none
        name, title = "bare", "Bare"

    bare = made(tmp_path, world.clock, cls=Bare)
    bare.add_client("alice")
    status, body, _ = bare.rpc("POST", bearer(bare.token_once("alice", 30, True)["token"]), {})
    assert status == 501 and "speaks no protocol" in body["error"]


def test_an_agent_is_held_to_its_rate(world):
    g, clock = world.g, world.clock
    world.asking.who = "page"
    g.add_client("alice")
    g.grant("alice", "rate", 2)
    token = g.token_once("alice", 30, True)["token"]
    assert [g.rpc("POST", bearer(token), {})[0] for _ in range(2)] == [200, 200]
    status, body, headers = g.rpc("POST", bearer(token), {})
    assert (status, headers) == (429, {"Retry-After": "60"}) and "rate" in body["error"]
    assert g.calls()[0]["decision"] == "too many" and len(g.served) == 2
    clock.now += 30
    assert g.rpc("POST", bearer(token), {})[2] == {"Retry-After": "30"}
    clock.now += 30
    assert g.rpc("POST", bearer(token), {})[0] == 200


# -- calls held for the user's answer ---------------------------------------------------------------------------------
def test_a_held_call_waits_for_your_answer(world):
    g, waits = world.g, Waits()
    g.waits = waits
    world.asking.who = "page"
    g.add_client("alice", "Alice")
    thread, out = held(g, "alice", "git__git_add", {"path": "notes.txt"}, words="git_add of the server git")
    waits.until(1)
    [row] = g.pending()
    assert (row["agent"], row["title"], row["what"], row["twice"], row["left_s"]) == (
        "alice", "Alice", "git__git_add", False, 50)
    assert "arguments" not in row and "notes.txt" not in json.dumps(row)  # without its arguments
    whole = g.waiting_call(row["ticket"])
    assert whole["arguments"] == json.dumps({"path": "notes.txt"}, indent=1) and whole["said"] == (
        "Alice (alice) asks git__git_add")
    assert any("notes.txt" in line for line in whole["lines"])
    assert "notes.txt" in json.dumps(g.status()["tables"])  # its first characters, masked, on Main
    assert g.decide(row["ticket"], "once")["ok"]
    assert ended(thread, out) == Held("once", "", row["ticket"]) and out["held"].allowed
    with pytest.raises(LookupError, match="no call waits"):
        g.decide(row["ticket"], "deny")
    with pytest.raises(LookupError, match="no call waits"):
        g.waiting_call(row["ticket"])
    with pytest.raises(Refusal, match="answered once, session or deny"):
        g.decide(row["ticket"], "maybe")
    assert g.pending() == []
    thread, out = held(g, "alice", "git__git_reset", {})
    waits.until(2)
    g.decide(g.pending()[0]["ticket"], "deny")
    denied = ended(thread, out)
    assert (denied.answer, denied.words, denied.allowed) == ("deny", "denied on Liminal's page: nothing was done",
                                                             False)


def test_an_unanswered_call_times_out_on_its_clock_and_a_closed_one_is_dropped(world):
    g, clock = world.g, world.clock
    looked: list[float] = []

    def waits(event, seconds):  # no time passes for real: the clock moves on instead
        looked.append(seconds)
        clock.now += seconds
        return False

    g.waits = waits
    world.asking.who = "page"
    g.add_client("alice")
    g.grant("alice", "hold", 10)
    began = clock.now
    got = g.hold("alice", "git__git_add", {})
    assert (got.answer, got.words) == ("timeout", "not answered on Liminal's page within 10 s: nothing was done")
    assert clock.now - began == 10 and set(looked) == {POLL_S} and g.pending() == []
    probed: list[float] = []

    def gone():
        probed.append(clock.now)
        return len(probed) >= 3

    got = g.hold("alice", "git__git_add", {}, gone=gone)
    assert got.answer == "gone" and "dropped" in got.words and len(probed) == 3
    assert [b - a for a, b in zip(probed, probed[1:])] == [POLL_S, POLL_S]  # looked at every half a second

    def broken():
        raise OSError("the connection cannot say")

    assert g.hold("alice", "git__git_add", {}, gone=broken).answer == "gone"


def test_a_call_ends_by_its_agents_cancel_by_a_stop_and_by_its_agent_forgotten(world):
    g, waits = world.g, Waits()
    g.waits = waits
    world.asking.who = "page"
    g.add_client("alice")
    thread, out = held(g, "alice", "x", {}, key="s1:7")
    waits.until(1)
    assert not g.cancel_held("alice", "s1:8") and not g.cancel_held("bob", "s1:7") and not g.cancel_held("alice", "")
    assert g.cancel_held("alice", "s1:7")
    assert ended(thread, out).answer == "cancelled" and "cancelled by its agent" in out["held"].words
    thread, out = held(g, "alice", "x", {})
    waits.until(2)
    g.app_stopping()
    assert ended(thread, out).answer == "stopped" and "Gate stopped before it was answered" in out["held"].words
    assert g.hold("alice", "x", {}).answer == "stopped"  # none is held until it is attached again
    g.app_stopping()  # (it bears a second call)
    g.attach(world.app, world.login)
    thread, out = held(g, "alice", "x", {})
    waits.until(3)
    g.forget_client("alice")
    assert ended(thread, out).answer == "deny" and "Alice" not in out["held"].words
    assert out["held"].words == "alice was forgotten on Liminal's page: nothing was done"


def test_four_calls_wait_for_one_agent_and_sixteen_in_all(world):
    g, waits = world.g, Waits()
    g.waits = waits
    world.asking.who = "page"
    names = [f"agent{i}" for i in range(5)]
    for name in names:
        g.add_client(name)
    calls = [held(g, name, f"call {i}", {}) for name in names[:4] for i in range(MAX_HELD_EACH)]
    waits.until(MAX_HELD)
    fifth = g.hold("agent0", "one more", {})
    assert fifth.answer == "refused" and f"{MAX_HELD_EACH} calls of agent0 wait" in fifth.words
    other = g.hold("agent4", "one more", {})
    assert other.answer == "refused" and f"{MAX_HELD} calls wait" in other.words
    assert len(g.pending()) == MAX_HELD
    assert g.hold("nobody", "x", {}).answer == "refused"
    g.app_stopping()
    assert [ended(thread, out).answer for thread, out in calls] == ["stopped"] * MAX_HELD


def test_a_call_whose_rule_asks_twice_is_allowed_only_once_confirmed(world):
    g, waits = world.g, Waits()
    g.waits = waits
    world.asking.who = "page"
    g.add_client("alice")
    thread, out = held(g, "alice", "fs__write_file", {"path": ".git/config", "text": "a‮b"}, twice=True)
    waits.until(1)
    [row] = g.pending()
    assert row["twice"]
    with pytest.raises(Refusal, match="never for a session"):
        g.decide(row["ticket"], "session")
    with pytest.raises(Refusal) as asked:
        g.decide(row["ticket"], "once")
    assert asked.value.accept == ACCEPT_TWICE == "accept"
    assert ".git/config" in str(asked.value) and "<U+202E>" in str(asked.value)  # its exact arguments, every character
    assert g.pending() and thread.is_alive()  # still waiting
    g.decide(row["ticket"], "once", accept=True)
    assert ended(thread, out).answer == "once"


def test_a_call_allowed_for_this_session_runs_again_without_asking(world):
    g, waits, clock = world.g, Waits(), world.clock
    g.waits = waits
    world.asking.who = "page"
    g.add_client("alice")
    thread, out = held(g, "alice", "git__status", {}, session="s1")
    waits.until(1)
    g.decide(g.pending()[0]["ticket"], "session")
    assert ended(thread, out).answer == "session"
    assert g.hold("alice", "git__status", {}, session="s1") == Held("session")  # at once: nothing is asked
    assert g.allowed("alice", "git__status", "s1") and not g.allowed("alice", "git__status", "s2")
    assert not g.allowed("alice", "git__log", "s1") and not g.allowed("bob", "git__status", "s1")
    thread, out = held(g, "alice", "git__status", {}, session="s1", twice=True)  # asking twice: asked every time
    waits.until(2)
    g.decide(g.pending()[0]["ticket"], "deny")
    assert ended(thread, out).answer == "deny"
    g.end_session("alice", "s1")
    assert not g.allowed("alice", "git__status", "s1")
    thread, out = held(g, "alice", "git__status", {}, session="s2")
    waits.until(3)
    g.decide(g.pending()[0]["ticket"], "session")
    ended(thread, out)
    clock.now += SESSION_S  # ten minutes at most
    assert not g.allowed("alice", "git__status", "s2")


def test_a_call_too_long_to_be_shown_whole_cannot_be_allowed(world):
    g = world.g
    world.asking.who = "page"
    g.add_client("alice")
    big = g.hold("alice", "x", {"text": "x" * (16 << 10)})
    assert big.answer == "refused" and "more than 16 KiB" in big.words and g.pending() == []
    assert visible("a‮b​ cㅤ\n\x07 d") == "a<U+202E>b<U+200B><U+00A0>c<U+3164>\n<U+0007> d"


# -- the audit --------------------------------------------------------------------------------------------------------
def test_the_ring_and_the_calls_log_mask_and_never_write_an_argument(world, tmp_path, monkeypatch):
    monkeypatch.setattr(protocol, "RING", 3)
    monkeypatch.setattr(protocol, "LOG_MAX", 600)
    g = made(tmp_path / "small", world.clock)
    world.asking.who = "page"
    g.add_client("alice")
    g.remember_secret(SECRET)
    for i in range(5):
        g.record("alice", "tools/call", f"git__git_add {SECRET}", "asked and allowed", era="2025-11-25",
                 arguments={"path": f"file-{i}.txt", "key": SECRET, "long": "y" * 400}, size=10, digest="ab" * 12)
    rows = g.calls()
    assert len(rows) == 3 and [r["arguments"].split('"path":"')[1][:10] for r in rows] == [
        "file-4.txt", "file-3.txt", "file-2.txt"]  # the newest first, RING kept
    for r in rows:
        assert SECRET not in json.dumps(r) and "<hidden>" in r["arguments"] and len(r["arguments"]) <= 200
        assert (r["what"], r["decision"], r["era"], r["size"]) == ("git__git_add <hidden>", "asked and allowed",
                                                                   "2025-11-25", 10)
    log = tmp_path / "small" / "gate" / "logs" / "calls.log"
    aside = log.with_name("calls.log.1")
    assert aside.exists() and log.stat().st_size < 600  # moved aside past its size, as a child's log is
    text = log.read_text(encoding="utf-8") + aside.read_text(encoding="utf-8")
    lines = [json.loads(line) for line in text.splitlines()]
    assert lines and all("arguments" not in line and line["agent"] == "alice" for line in lines)
    assert "file-" not in text and "yyyy" not in text and SECRET not in text and "<hidden>" in text
    assert g.calls(0) == [] and len(g.calls("x")) == 3
    odd = g.record("alice", "tools/call", ms=float("nan"), size="big", arguments=object())  # noted all the same
    assert (odd["ms"], odd["size"]) == (0.0, 0) and g.calls(1)[0]["arguments"].startswith('"<object object')


def test_each_call_is_a_row_of_the_platforms_traffic(world):
    g = world.g
    world.asking.who = "page"
    g.add_client("alice")
    token = g.token_once("alice", 30, True)["token"]
    g.rpc("POST", bearer(token), {"method": "tools/list"})
    g.rpc("POST", {}, {})  # no token: no agent's row
    mine = [link for link in world.app.traffic.links() if link["from"].startswith("agent:")]
    assert [(link["from"], link["to"], link["kind"], link["what"], link["count"]) for link in mine] == [
        ("agent:alice", "gate", "read", "tools/list", 1)]
    seen = g.clients()[0]
    assert seen["calls"] == 1 and seen["last"]


# -- what it offers, and its Main -------------------------------------------------------------------------------------
def test_how_an_agent_is_wired_is_said_without_a_token(world):
    g = world.g
    world.asking.who = "codex-cli"
    g.ensure_client("Codex CLI")
    token = g.launch_token()["token"]
    offer = g.client_offer()
    assert (offer["agent"], offer["variable"], offer["hold_s"], offer["wires"]) == (
        "codexcli", "LIMINAL_GATE_TOKEN", 50, ["stdio", "http"])
    assert token not in json.dumps(offer) and "problem" not in offer
    world.asking.who = None
    assert g.client_offer()["agent"] == ""
    world.asking.who = "pi"  # no agent of its own yet: the hold every agent starts with
    assert (g.client_offer()["agent"], g.client_offer()["hold_s"]) == ("", 50)


def test_an_offer_names_only_the_ways_a_harness_reaches_it(world, monkeypatch):
    """A harness reaches a protocol plugin by the bridge ("stdio") or by the platform's route ("http"): the words
    machines/harness.py reads. A way the subclass's offer names otherwise is left out, and said."""
    from liminal_libs.machines import harness
    assert protocol.WIRES == harness.WIRES == ("stdio", "http")
    g, said = world.g, {}
    monkeypatch.setattr(g, "offer", lambda client: dict(said))
    for wires, kept in ((["route", "bridge"], []), (["stdio", "route", "stdio"], ["stdio"]), ([{"x": 1}], []),
                        ({"stdio": 1}, [])):
        said.update(wires=wires)
        offer = g.client_offer()
        assert offer["wires"] == kept
        assert offer["problem"].startswith("Gate's offer names a way no harness reaches it by (")
        assert offer["problem"].endswith("): a harness reaches it by stdio (its bridge) or http (the platform's route)")
    said.update(wires="http")  # one way said alone
    assert (g.client_offer()["wires"], "problem" in g.client_offer()) == (["http"], False)
    said.update(wires=["http"], problem="its bridge is not there")  # the subclass's own words are kept first
    offer = g.client_offer()
    assert (offer["wires"], offer["problem"]) == (["http"], "its bridge is not there")
    said.clear()
    assert "wires" not in g.client_offer() and "problem" not in g.client_offer()


def test_main_draws_its_agents_and_the_calls_waiting(world):
    g, waits = world.g, Waits()
    g.waits = waits
    world.asking.who = "page"
    g.add_client("alice", "Alice")
    g.token_once("alice", 30, True)
    thread, out = held(g, "alice", "git__git_add", {"path": "x" * 300})
    waits.until(1)
    status = g.status()
    assert status["summary"] == "1 agent, 1 call waiting for you" and status["valid"] and "problem" not in status
    assert (status["agents"], status["waiting"]) == (f"1 of {MAX_CLIENTS} at most", "1 call")
    tables = {t["title"]: t for t in status["tables"]}
    [agent], [call] = tables["Agents"]["rows"], tables["Waiting for you"]["rows"]
    assert agent[0] == {"text": "Alice", "sub": "alice"} and agent[4]["text"].startswith("until ")
    assert len(call[2]) <= 200 and call[2].endswith("…") and call[4] == "ask"
    forms = {f["id"]: f for f in status["forms"]}
    for f in forms.values():  # each form's fields are its hook's arguments, in their order
        params = list(inspect.signature(getattr(g, f["hook"])).parameters)
        assert [x["name"] for x in f["fields"]] == params[:len(f["fields"])], f["id"]
    buttons = [c for row in [*tables["Agents"]["rows"], *tables["Waiting for you"]["rows"]] for c in row
               if isinstance(c, dict) and "form" in c]
    assert buttons and all(b["form"] in forms for b in buttons)
    assert all(a["form"] in forms for a in status["actions"] if a.get("form"))
    assert json.loads(json.dumps(status)) == status
    g.app_stopping()
    ended(thread, out)
    g.main_more = lambda: 1 / 0  # a subclass's part that fails: the rest is drawn, the fault said
    status = g.status()
    assert status["valid"] and "part of its page could not be drawn: ZeroDivisionError" in status["problem"]


def test_a_subclass_stop_ends_the_held_calls_first(world, tmp_path):
    class Stopper(Gate):
        stops = 0

        def app_stopping(self):  # no super(): the base's part runs all the same
            type(self).stops += 1

    s, waits = made(tmp_path, world.clock, cls=Stopper), Waits()
    s.waits = waits
    world.asking.who = "page"
    s.add_client("alice")
    world.asking.who = "codex-cli"
    s.ensure_client("Codex CLI")
    token = s.launch_token()["token"]
    thread, out = held(s, "alice", "x", {})
    waits.until(1)
    s.app_stopping()
    assert ended(thread, out).answer == "stopped" and Stopper.stops == 1
    assert s.rpc("POST", bearer(token), {})[0] == 401
    s.detach()  # turned off: told it stops again
    assert Stopper.stops == 2 and s.app is None


def test_the_new_module_writes_out_no_address():
    path = Path(protocol.__file__)
    found = [f"{n}: {line.strip()}" for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
             if WRITTEN.search(line)]
    assert found == []
