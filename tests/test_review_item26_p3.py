"""The review of 2026-11-21, item 26 (1.83.0): the library's P3 findings, each pinned by a test that fails on 1.81.0.
The history triggers are made again in one transaction (1); the collector's clock counts a machine's sleep (2); the
IPC key is owner-only from the start and never replaced by a second first start (3); a 429 in a plugin's own fetching
stops its pass and strikes it (4); no child inherits the LIMINAL_* names (5); a Windows path to docker is kept whole
(6); Start thaws what a pause from before a restart left frozen (7); a WSL rename whose new name the login could not
keep is undone (8). Every process here is a stand-in: nothing is started."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta, timezone

import pytest

from liminal_libs import collector, killswitch, proctree, runner
from liminal_libs import docker as dockermod
from liminal_libs import host as hosting
from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.errors import RateLimited
from liminal_libs.machines import linux, terminal, windows, wsl
from liminal_libs.machines.plugin import CommandError
from liminal_libs.sources.fetching import Fetched, Job
from liminal_libs.storage import Store, history

from test_wsl import UbuntuLike
from test_wsl_installs import Machine, machine  # noqa: F401 - the fixture, used by name

pytestmark = pytest.mark.usefixtures("stand_in_environment")  # its code reads this process's environment

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)


# -- 1: the history triggers made again with no gap -------------------------------------------------------------------

def test_a_write_while_the_triggers_are_made_again_still_marks_its_month_stale(tmp_path):
    path = tmp_path / "feed.db"
    lo, hi = history.bounds("2026-09")
    with sqlite3.connect(path) as setup:
        setup.executescript(f"""
            CREATE TABLE bars (ticker TEXT, timespan TEXT, multiplier INTEGER, ts INTEGER);
            CREATE TABLE built_bars (ticker TEXT, timespan TEXT, multiplier INTEGER, ts INTEGER);
            CREATE TABLE changes (minute INTEGER);
            CREATE TABLE history (month TEXT PRIMARY KEY, lo_ms INTEGER NOT NULL, hi_ms INTEGER NOT NULL,
                file TEXT NOT NULL, bars INTEGER NOT NULL, built INTEGER NOT NULL, checksum TEXT NOT NULL,
                bytes INTEGER NOT NULL, archived_at INTEGER NOT NULL, seconds REAL, stale INTEGER NOT NULL DEFAULT 0);
            INSERT INTO history VALUES ('2026-09', {lo}, {hi}, 'x.duckdb', 1, 0, '', 1, 0, 1.0, 0);
            CREATE TRIGGER history_stale_bars_insert AFTER INSERT ON bars  -- an older version's: made again
            BEGIN UPDATE history SET stale=1 WHERE lo_ms <= new.ts AND hi_ms > new.ts; END;
        """)
    wrote = []

    def another_process_writes():  # a bar in the archived month, from another connection
        if not wrote:
            wrote.append(True)
            with sqlite3.connect(path) as other:
                other.execute("INSERT INTO bars VALUES ('AAPL', 'minute', 1, ?)", (lo + 60_000,))

    class Watched(sqlite3.Connection):
        """The other process's write lands the moment the file is open to it while triggers are being made."""

        def executescript(self, script):
            if "CREATE TRIGGER" in script and not self.in_transaction:
                another_process_writes()
            return super().executescript(script)

        def execute(self, sql, *args):
            if sql.lstrip().upper().startswith("CREATE TRIGGER") and not self.in_transaction:
                another_process_writes()
            return super().execute(sql, *args)

    conn = sqlite3.connect(path, factory=Watched)
    try:
        history.ensure(conn)
        another_process_writes()  # no gap: it lands after
        assert conn.execute("SELECT stale FROM history WHERE month='2026-09'").fetchone() == (1,)
        assert len(conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()) == 6
    finally:
        conn.close()


# -- 2: the collector's clock across a sleep --------------------------------------------------------------------------

def test_the_collectors_clock_counts_the_time_the_machine_slept(monkeypatch):
    c = collector.Collector.__new__(collector.Collector)
    c.now, c.started = NOW, 100.0
    mono, wall = [100.0], [5_000.0]
    monkeypatch.setattr(collector, "monotonic", lambda: mono[0])
    monkeypatch.setattr(time, "time", lambda: wall[0])
    assert c.clock() == NOW
    mono[0], wall[0] = 160.0, 5_000.0 + 3_660  # awake a minute, asleep an hour: Linux's monotonic clock stopped
    assert c.clock() == NOW + timedelta(seconds=3_660)
    mono[0], wall[0] = 220.0, 0.0  # the wall clock set back: the monotonic step still counts
    assert c.clock() == NOW + timedelta(seconds=3_720)


# -- 3: the IPC key ---------------------------------------------------------------------------------------------------

def test_two_first_starts_end_with_one_key_owner_only(monkeypatch, tmp_path):
    monkeypatch.setenv("LIMINAL_IPC_DIR", str(tmp_path / "ipc"))
    real = os.urandom
    first: list = []

    def urandom(n):  # the second start made its key: the first start's runs whole at that moment
        if not first:
            first.append(None)
            first[0] = hosting.key()
        return real(n)

    monkeypatch.setattr(hosting.os, "urandom", urandom)
    second = hosting.key()
    assert first[0] == second == (tmp_path / "ipc" / "key").read_bytes().strip() and len(second) == 64
    assert [p.name for p in (tmp_path / "ipc").iterdir()] == ["key"]  # no part file left
    if os.name != "nt":
        assert (tmp_path / "ipc" / "key").stat().st_mode & 0o077 == 0


# -- 4: a 429 in a plugin's own fetching ------------------------------------------------------------------------------

class _Limited:
    """Three jobs against one server, which answers 429 to the first."""

    def __init__(self):
        self.asked: list = []

    def plan(self, ctx):
        return [Job("document", k, priority=i) for i, k in enumerate(("a", "b", "c"))]

    def fetch(self, ctx, job):
        self.asked.append(job.key)
        raise RateLimited(429, "too many requests", retry_after=900)


def test_a_429_in_a_plugins_own_fetching_stops_its_pass_and_strikes_it(tmp_path):
    with Store(tmp_path / "liminal.db") as store:
        fetcher = _Limited()
        out = runner.Runner(lambda: store, None, lambda m: None).plugin("acme", [("docs", fetcher)], store, clock=lambda: NOW)
        assert fetcher.asked == ["a"]  # b and c never sent to the server that said 429
        assert out["failed"] == 0 and "rate limited" in out["stopped"]
        kill = killswitch.killed(store, "acme", "fetch", NOW)
        assert kill is not None and datetime.fromisoformat(kill["until"]) >= NOW + timedelta(seconds=900)
        assert runner.stopped(store, "acme", now=NOW).startswith("acme:")  # the next pass stops before asking


# -- 5: no child inherits the LIMINAL_* names -------------------------------------------------------------------------

def test_no_child_started_by_the_machines_or_docker_inherits_liminals_names(monkeypatch):
    monkeypatch.setenv("LIMINAL_SECRET_KEY", "s3cret")
    monkeypatch.setenv("DOCKER_CONFIG", "/home/u/.docker")  # docker's own: kept
    monkeypatch.setenv("WSLENV", "USERPROFILE/p")  # WSL's own: kept
    envs: list = []

    def run(args, timeout, input=None, text=False, env=None, **kw):
        envs.append(env)
        raise OSError("a stand-in")

    class Popen:
        def __init__(self, args, env=None, **kw):
            envs.append(env)
            raise OSError("a stand-in")

    monkeypatch.setattr(proctree, "run", run)
    monkeypatch.setattr(subprocess, "Popen", Popen)
    monkeypatch.setattr(windows.PowerShell, "here", property(lambda self: True))
    with pytest.raises(CommandError):
        windows.PowerShell().run("Get-Date")
    monkeypatch.setattr(linux.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(linux.Shell, "here", property(lambda self: True))
    with pytest.raises(CommandError):
        linux.Shell("local").run("true")
    monkeypatch.setattr(dockermod.shutil, "which", lambda name: "docker")
    with pytest.raises(dockermod.DockerError):
        dockermod.Docker()._run("version")
    monkeypatch.setattr(wsl.Wsl, "here", property(lambda self: True))
    with pytest.raises(wsl.WslError):
        wsl.Wsl()._run(["wsl", "--status"])
    with pytest.raises(wsl.WslError):
        wsl.Wsl()._run(["wsl", "--update"], out=lambda s: None)  # streamed to the terminal panel
    with pytest.raises(OSError):
        terminal.Terminal(["wsl", "-d", "Ubuntu"])
    assert len(envs) == 6
    for env in envs:
        assert env is not None and not any(n.upper().startswith("LIMINAL_") for n in env)
        assert env["DOCKER_CONFIG"] == "/home/u/.docker" and env["WSLENV"] == "USERPROFILE/p"
    assert envs[-1]["WSL_UTF8"] == envs[-2]["WSL_UTF8"] == "1"  # what the call adds, still added


# -- 6: a Windows path to docker --------------------------------------------------------------------------------------

def test_a_windows_path_to_docker_is_kept_whole(tmp_path):
    exe = tmp_path / "Program Files" / "Docker" / "docker.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")
    assert dockermod.split_command(str(exe), windows=True) == [str(exe)]  # spaces and backslashes: one word
    assert dockermod.split_command(f'"{exe}"', windows=True) == [str(exe)]
    quoted = r'"C:\Program Files\Docker\Docker\resources\bin\docker.exe" --log-level warn'
    assert dockermod.split_command(quoted, windows=True) == [r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
                                                             "--log-level", "warn"]
    assert dockermod.split_command("wsl -d Ubuntu docker", windows=True) == ["wsl", "-d", "Ubuntu", "docker"]
    assert dockermod.split_command("wsl -d 'My Box' docker", windows=False) == ["wsl", "-d", "My Box", "docker"]
    if os.name == "nt":
        assert dockermod.Docker(env={}, command=str(exe)).argv == [str(exe)]


# -- 7: a pause from before a restart ---------------------------------------------------------------------------------

class _FrozenBefore(Machine):
    """Services frozen by a pause the plugin no longer remembers; THAW_SCRIPT thaws those named and any still frozen."""

    def __call__(self, args, timeout):
        if args[1] == "-d" and "--exec" in args:
            command = args[args.index("--exec") + 1:]
            if command[:2] == ["sh", "-c"] and command[2] == wsl.THAW_SCRIPT:
                self.calls.append(list(args))
                thawed, self.frozen = list(dict.fromkeys([*command[4:], *self.frozen])), []
                return 0, "".join(f"thawed {u}\n" for u in thawed).encode(), b""
        return super().__call__(args, timeout)


def test_start_thaws_services_a_pause_from_before_a_restart_left_frozen(tmp_path):
    fake = _FrozenBefore(distributions=[("Ubuntu", "Running", "2")])
    fake.frozen = ["docker.service", "cron.service"]
    p = UbuntuLike(wsl=wsl.Wsl(runner=fake), data=tmp_path)  # a plugin just started: nothing paused in its memory
    assert p.paused("Ubuntu") == []
    said = p.start_install("Ubuntu")
    assert said["said"] == "Ubuntu resumed: 2 services running again" and fake.frozen == []
    assert p.start_install("Ubuntu")["said"] == "Ubuntu is running already"  # nothing frozen any more


# -- 8: a WSL rename the login could not keep -------------------------------------------------------------------------

class _NoSave(EnvironmentLogin):
    def save(self, variable, value):
        raise OSError("the login's database is locked")


def test_a_rename_whose_name_the_login_cannot_keep_is_undone_and_said(machine):  # noqa: F811
    fake, w, tmp_path, _ = machine
    p = UbuntuLike(wsl=w, data=tmp_path)
    p.login = _NoSave(env={})
    with pytest.raises(wsl.WslError, match="was not renamed: .*database is locked.*named Liminal-Ubuntu still"):
        p.rename_install("Liminal-Ubuntu", "Liminal-Ubuntu-Dev")
    assert fake.renamed == [("{liminal-ubuntu}", "Liminal-Ubuntu-Dev"), ("{liminal-ubuntu}", "Liminal-Ubuntu")]
    assert "Liminal-Ubuntu" in [i.name for i in p.installs()] and p.distribution_name == "Liminal-Ubuntu"
    undo = w._rename

    def fails_back(key, name):
        if name == "Liminal-Ubuntu":
            raise wsl.WslError("WSL's record of it could not be changed: access denied")
        undo(key, name)

    w._rename = fails_back
    with pytest.raises(wsl.WslError, match="database is locked.*renaming it back failed too.*access denied.*named "
                                           "Liminal-Ubuntu-Dev now"):
        p.rename_install("Liminal-Ubuntu", "Liminal-Ubuntu-Dev")
