"""The review of 2026-11-21, item 26 (1.80.0): what its findings 8 to 13 asked of the library, each pinned by a test
that fails on 1.79.0. A cancel is never undone (11); the window kept is never looser than the plugin's own (13); an
AI answer is waited for, and a POST never sent again on a 5xx (12); Dynamic DNS writes only a record still as it was
read (10); a timeout ends the whole tree, and an elevated change past its wait is said to be possibly applied (8, 9).
Every process here is a stand-in: nothing is started."""
from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from liminal_libs import docker as dockermod
from liminal_libs import proctree
from liminal_libs.errors import SourceError
from liminal_libs.machines import ddns, linux, windows, wsl
from liminal_libs.machines.plugin import CommandError
from liminal_libs.ratelimit import RateLimiter
from liminal_libs.sources.http import HttpClient
from liminal_libs.sources.plugin import within
from liminal_libs.storage import Store

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)


# -- 11: a cancel is never undone ---------------------------------------------------------------------------------------

def test_a_cancelled_request_is_never_moved_on_and_the_caller_is_told(tmp_path):
    with Store(tmp_path / "liminal.db") as store:
        r = store.request_put("AAPL", by="chart", now=NOW)
        assert store.request_next(NOW)["id"] == r["id"]  # the fetcher took it (assessing)
        assert store.request_cancel(r["id"], now=NOW)  # the user takes it back meanwhile
        after = store.request_update(r["id"], state="collecting", detail="on massive", now=NOW)  # the fetcher's write
        assert after["state"] == "cancelled" and after["detail"] == "cancelled" and after["applied"] is False
        for state in ("done", "failed"):  # a feed's run serving it, the auditors settling it: neither undoes the cancel
            assert store.request_update(r["id"], state=state, detail="served", now=NOW)["applied"] is False
        assert store.request_get(r["id"])["state"] == "cancelled"
        # an open one is moved as before, and says so
        other = store.request_put("MSFT", by="chart", now=NOW)
        assert store.request_update(other["id"], state="collecting", now=NOW)["applied"] is True
        done = store.request_update(other["id"], state="done", now=NOW)
        assert done["state"] == "done" and done["applied"] is True
        assert store.request_update(other["id"], state="failed", now=NOW)["state"] == "done"  # an ending is written once


# -- 13: never looser than the plugin's own window ----------------------------------------------------------------------

def test_the_window_kept_is_never_looser_than_the_plugins_own():
    n, s = within(200, 60.0, [(10.0, 1.0)])  # the server's 10 a second, the plugin's 200 a minute
    assert n / s * 60.0 <= 200 + 1e-9 and n <= 10 * 0.95
    assert within(190, 60.0, [(200, 60)]) == (190, 60.0)  # already inside: as it was
    assert within(8, 1.0, [(30, 60)]) == (1, 3.0)


def test_tighten_refuses_a_higher_rate_and_keeps_the_burst():
    client = HttpClient("https://x.example", rate_limiter=RateLimiter(200, 60.0))
    assert not client.tighten(9, 1.0)  # 540 a minute: looser by rate, though its burst is smaller
    assert (client._limiter.max_calls, client._limiter.period) == (200, 60.0)
    assert client.tighten(300, 120.0)  # a lower rate (2.5 a second) in a larger burst: the burst of 200 kept
    assert client._limiter.max_calls == 200 and client._limiter.period == pytest.approx(80.0)
    assert client.tighten(1, 3.0) and (client._limiter.max_calls, client._limiter.period) == (1, 3.0)


# -- 12: an AI answer is waited for; a POST is not sent twice -------------------------------------------------------------

class _Answer:
    def __init__(self, status, headers=None, body=None):
        self.status_code, self.headers, self._body = status, headers or {}, body if body is not None else {}
        self.text = str(self._body)

    def json(self):
        return self._body


class _Session:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def post(self, url, params=None, json=None, headers=None, timeout=None):
        self.calls.append(("POST", timeout))
        return self.answers.pop(0)

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(("GET", timeout))
        return self.answers.pop(0)


def test_an_assistants_post_waits_for_its_answer_and_a_get_keeps_its_timeout():
    from liminal_libs.assistants.assistant import AssistantClient

    vendor = SimpleNamespace(limit_prefixes=(), error=lambda *a: None, final=lambda *a: False)
    session = _Session(_Answer(200, body={"ok": 1}), _Answer(200, body={"data": []}))
    client = AssistantClient("https://ai.example", {}, ("k",), vendor, session=session, sleep=lambda s: None)
    client.post("/v1/responses", {"input": "x"})
    client.get("/v1/models")
    assert session.calls == [("POST", 300.0), ("GET", 30.0)]


def test_a_post_is_never_sent_again_on_a_5xx_but_a_429_is_waited_out():
    session = _Session(_Answer(504), _Answer(200, body={"ok": 1}))
    client = HttpClient("https://ai.example", session=session, sleep=lambda s: None)
    with pytest.raises(SourceError):
        client.post("/v1/responses", {"input": "x"})
    assert len(session.calls) == 1  # the gateway's 504 may follow the vendor's work: never billed twice
    session = _Session(_Answer(429, {"Retry-After": "1"}), _Answer(200, body={"ok": 1}))
    client = HttpClient("https://ai.example", session=session, sleep=lambda s: None)
    assert client.post("/v1/responses", {"input": "x"}) == {"ok": 1} and len(session.calls) == 2
    session = _Session(_Answer(502), _Answer(200, body={"ok": 1}))
    client = HttpClient("https://x.example", session=session, sleep=lambda s: None)
    assert client.get("/v1/bars") == {"ok": 1} and len(session.calls) == 2  # a GET is tried again, as before


# -- 10: Dynamic DNS writes only a record still as it was read -------------------------------------------------------------

def test_dynamic_dns_writes_nothing_when_the_record_changed_during_the_pass():
    records = {"home.example.com": ["203.0.113.9"]}  # the keeper's own, from an earlier pass
    written, asked = [], []

    def public():
        asked.append(1)
        if len(asked) == 2:  # asked again just before the write: the user points the record elsewhere meanwhile
            records["home.example.com"] = ["198.51.100.50"]
        return "203.0.113.10", "a stand-in"

    keeper = ddns.Keeper(read=lambda h: list(records[h.fqdn]), write=lambda h, ip: written.append((h.fqdn, ip)) or "set",
                         public=public)
    keeper._own["home.example.com"] = "203.0.113.9"
    hosts, _ = ddns.hosts_of("home.example.com", ["example.com"])
    out = keeper.run_pass(hosts)[0]
    assert written == [] and len(asked) == 2
    assert out["result"].startswith("its record changed during the pass (it holds 198.51.100.50 now, 203.0.113.9 before)")
    assert out["holds"] == ["198.51.100.50"] and not out["ok"]
    # the next pass sees a foreign record and leaves it, as the keeper's rule says
    out = keeper.run_pass(hosts)[0]
    assert written == [] and out["foreign"] and out["result"].startswith("holds 198.51.100.50")


# -- 8, 9: a timeout ends the whole tree -----------------------------------------------------------------------------------

class _Proc:
    """A stand-in Popen: `hangs` runs past every timeout; everything made is kept in `made`."""

    made: list = []

    def __init__(self, args, **kw):
        self.args, self.kw, self.pid, self.returncode = list(args), kw, 4321, None
        self.killed = False
        _Proc.made.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def hangs(self) -> bool:
        return self.args[0] != "taskkill" and not self.killed

    def communicate(self, input=None, timeout=None):
        if self.hangs():
            raise subprocess.TimeoutExpired(self.args, timeout)
        self.returncode = 0 if self.returncode is None else self.returncode
        return (b"" if not self.kw.get("text") else ""), (b"" if not self.kw.get("text") else "")

    def wait(self, timeout=None):
        if self.hangs():
            raise subprocess.TimeoutExpired(self.args, timeout)
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed, self.returncode = True, -9


@pytest.fixture
def stand_in(monkeypatch):
    _Proc.made = []
    monkeypatch.setattr(subprocess, "Popen", _Proc)
    return _Proc.made


def _taskkills(made):
    return [p.args for p in made if p.args[0] == "taskkill"]


def test_on_windows_a_timeout_ends_powershells_whole_tree(stand_in, monkeypatch):
    monkeypatch.setattr(proctree, "_nt", lambda: True)
    monkeypatch.setattr(windows.PowerShell, "here", property(lambda self: True))
    with pytest.raises(CommandError, match="took more than 5 s") as err:
        windows.PowerShell().run("Start-VM x", timeout=5)
    assert _taskkills(stand_in) == [["taskkill", "/T", "/F", "/PID", "4321"]]
    assert type(err.value).__name__ == "TimedOut"
    assert stand_in[1].kw.get("creationflags") == proctree.CREATE_NO_WINDOW  # the taskkill windowless too


def test_docker_and_wsl_timeouts_end_the_tree(stand_in, monkeypatch):
    monkeypatch.setattr(proctree, "_nt", lambda: True)
    monkeypatch.setattr(dockermod.shutil, "which", lambda name: "docker")
    with pytest.raises(dockermod.DockerError, match="took more than"):
        dockermod.Docker()._run("pull", "x", timeout=5)
    monkeypatch.setattr(wsl.Wsl, "here", property(lambda self: True))
    with pytest.raises(wsl.WslError, match="took more than"):
        wsl.Wsl()._run(["wsl", "--update"], timeout=5)
    assert _taskkills(stand_in) == [["taskkill", "/T", "/F", "/PID", "4321"]] * 2


def test_on_linux_a_timeout_stops_the_commands_group_through_sudo_then_kills_it(stand_in, monkeypatch):
    signals = []
    monkeypatch.setattr(proctree, "_nt", lambda: False)
    monkeypatch.setattr(proctree.os, "killpg", lambda pid, sig: signals.append((pid, sig)), raising=False)
    monkeypatch.setattr(linux.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(linux.Shell, "here", property(lambda self: True))
    monkeypatch.setattr(proctree, "TERM_GRACE_S", 0.0)
    with pytest.raises(CommandError, match="took more than 5 s"):
        linux.Shell("local").run("apt-get", "upgrade", timeout=5)
    assert stand_in[0].args[:3] == ["sudo", "-n", "--"] and stand_in[0].kw.get("start_new_session") is True
    kill = getattr(proctree.signal, "SIGKILL", proctree.signal.SIGTERM)
    assert signals == [(4321, proctree.signal.SIGTERM), (4321, kill)] and stand_in[0].killed


def test_sudos_prefix_ends_its_options_before_the_command():
    got = []
    shell = linux.Shell("local", runner=lambda args, timeout: got.append(list(args)) or (0, b"", b""))
    shell.root = lambda: False
    shell.run("-u", "x")
    assert got[-1] == ["sudo", "-n", "--", "-u", "x"]


def _out_file(args) -> str:
    """The output file an elevated run names, read out of the scripts it hands PowerShell (two encodings deep)."""
    outer = windows.decoded(args[-1])
    inner = windows.decoded(re.search(r"'-EncodedCommand','([A-Za-z0-9+/=]+)'", outer).group(1))
    return re.search(r"-FilePath '([^']+)'", inner).group(1)


def test_an_elevated_change_past_its_wait_is_said_to_be_possibly_applied_and_its_file_handled(tmp_path, monkeypatch):
    monkeypatch.setattr(windows.tempfile, "gettempdir", lambda: str(tmp_path))
    old = tmp_path / "liminal-elevated-old.txt"  # left by an elevated script that outlived an earlier wait
    old.write_text("x")
    os.utime(old, (1.0, 1.0))
    fresh = tmp_path / "liminal-elevated-fresh.txt"  # one maybe still being written: left to it
    fresh.write_text("x")
    named = []

    def timed_out(args, timeout):
        named.append(_out_file(args))
        raise subprocess.TimeoutExpired(args, timeout)

    with pytest.raises(CommandError) as err:
        windows.PowerShell(runner=timed_out).run_elevated("Set-NetFirewallRule x", timeout=5)
    words = str(err.value)
    assert "the change may still be applied" in words and "before trying again" in words
    assert not old.exists() and fresh.exists()  # swept once old; a recent one left alone

    def answered(args, timeout):  # the elevated script ran: it wrote its file, and Start-Process -Wait returned
        path = _out_file(args)
        named.append(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write("done\n")
        return 0, "exit 0\n", ""

    assert windows.PowerShell(runner=answered).run_elevated("Set-NetFirewallRule x", timeout=5) == "done\n"
    assert not os.path.exists(named[-1])  # read, then removed: nothing left behind
