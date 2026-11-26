"""What a process that reaches its databases through the link takes from the files' own system besides the files
(1.57.0): the user's saved settings (the keys: told over the pipe, kept nowhere here), the clock that stamps what is
stored, and a log file of its own beside the other system's. The helper is a thread of the test's process
(Link.loopback); "another system's drive" is mounts.foreign standing in; no process is started."""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from liminal_libs import config, logs, mounts
from liminal_libs.storage import common
from liminal_libs.storage import link as lk
from liminal_libs.storage.link import Link

pytestmark = pytest.mark.usefixtures("stand_in_environment")  # its code reads this process's environment


@pytest.fixture
def linked(tmp_path, monkeypatch):
    """This process's link to the files' own system: a helper in a thread that tells the settings saved there."""
    saved = {"MASSIVE_API_KEY": "a-test-key", "MASSIVE_PLAN": "advanced", "EMPTY": ""}
    link = Link.loopback([tmp_path], saved=lambda names: {n: saved[n] for n in names if n in saved})
    link.name = "Windows"
    monkeypatch.setattr(lk, "_links", {"owner": link})
    yield link
    link.close()


def test_the_saved_settings_are_those_of_the_system_that_holds_the_database(linked, tmp_path, monkeypatch):
    main = tmp_path / "liminal.db"
    env = config.UserEnvironment(names=("MASSIVE_API_KEY", "MASSIVE_PLAN", "EMPTY", "TIINGO_API_KEY"))
    monkeypatch.delenv("LIMINAL_DB", raising=False)
    assert env.linked() == {}  # no database named: nothing to ask of anyone
    monkeypatch.setenv("LIMINAL_DB", str(main))
    assert env.linked() == {}  # a database of this system's own: its settings are this system's
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: True)  # the database on Windows' drive, seen from WSL
    assert env.linked() == {"MASSIVE_API_KEY": "a-test-key", "MASSIVE_PLAN": "advanced"}  # by name, the set ones
    assert not list(tmp_path.rglob("*a-test-key*")) and "a-test-key" not in repr(linked.info)  # kept nowhere here
    linked.close()  # the helper gone: no settings, and the database will say why it cannot be opened
    assert env.linked() == {}
    if config.os.name != "nt":  # (on Windows a save is its own registry's: not tried here)
        with pytest.raises(config.ConfigError, match="save it there"):
            config.UserEnvironment().save("X", "y")  # nothing is saved from this side: set where the data is


@pytest.mark.skipif(config.os.name == "nt", reason="on Windows the saved settings are its own registry's")
def test_off_windows_the_saved_settings_come_over_the_link(linked, tmp_path, monkeypatch):
    monkeypatch.setenv("LIMINAL_DB", str(tmp_path / "liminal.db"))
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: True)
    assert config.UserEnvironment(names=("MASSIVE_API_KEY",)).saved() == {"MASSIVE_API_KEY": "a-test-key"}
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: False)
    assert config.UserEnvironment(names=("MASSIVE_API_KEY",)).saved() == {}  # its own database: nothing saved off Windows


def test_what_is_stored_is_stamped_by_the_clock_of_the_system_that_owns_the_files(linked, monkeypatch):
    linked.skew, linked.heard = 12.0, time.monotonic()  # WSL's clock twelve seconds behind Windows'
    ahead = (common.utc_now() - datetime.now(timezone.utc)).total_seconds()
    assert 11 < ahead < 13 and common.utc_now().tzinfo is timezone.utc
    stamp = datetime.fromisoformat(common._now())
    assert 10 < (stamp - datetime.now(timezone.utc)).total_seconds() < 13 and "." not in common._now()
    assert "." in common._now_precise()
    monkeypatch.setattr(lk, "_links", {})  # a process with no link: its own clock
    assert abs((common.utc_now() - datetime.now(timezone.utc)).total_seconds()) < 1
    monkeypatch.setattr(lk, "_links", {"owner": linked})
    linked.close()  # a link that ended: its own clock again (it can write nothing there any more)
    assert abs((common.utc_now() - datetime.now(timezone.utc)).total_seconds()) < 1


def test_nothing_is_fetched_while_the_two_clocks_disagree(tmp_path, monkeypatch):
    main = tmp_path / "liminal.db"
    monkeypatch.delenv(lk.FORCE_VAR, raising=False)
    monkeypatch.setattr(lk, "_links", {})
    assert lk.clock_off(main) == ""  # this system's own file: its own clock is the clock
    link = Link.loopback([tmp_path])
    link.name = "Windows"
    monkeypatch.setattr(lk, "_links", {"owner": link})
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: True)
    try:
        assert lk.clock_off(main) == ""  # the same machine here: the clocks agree
        monkeypatch.setattr(lk, "_here", lambda: time.time() - 9.0)  # this system's clock nine seconds behind
        said = lk.clock_off(main)
        assert said.startswith("this system's clock is 9.0 s behind the clock of Windows, which holds the data")
        assert "nothing is fetched from here until they agree to within 1 s" in said
        monkeypatch.setattr(lk, "_here", lambda: time.time() + 4.0)
        assert "4.0 s ahead of the clock of Windows" in lk.clock_off(main)
    finally:
        link.close()


def test_a_log_beside_another_systems_database_is_a_file_of_this_systems_own(tmp_path, monkeypatch, capsys):
    own = logs.log_to(tmp_path / "liminal.db")
    assert own.path == tmp_path / "logs" / "liminal.log"
    own("as always")
    assert "as always" in own.path.read_text(encoding="utf-8")
    monkeypatch.setattr(mounts, "foreign", lambda p, mounts=None: True)
    there = logs.log_to(tmp_path / "liminal.db")
    name = f"liminal-{logs._system()}.log"
    assert there.path == tmp_path / "logs" / name and name in ("liminal-windows.log", "liminal-linux.log", "liminal-macos.log")
    there("from the other side")
    assert "from the other side" in there.path.read_text(encoding="utf-8")
    assert "from the other side" not in own.path.read_text(encoding="utf-8")  # two systems never append to one file
    assert logs.Logger(None).path is None
    capsys.readouterr()
