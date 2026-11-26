"""Preferences and licences through the login (1.88.0; Monday list item 21; the user, 2026-11-19: "preferences, keys,
licenses all get stored in the individual's login db"): the theme and a licence accepted are the signed-in user's,
kept as pairs of their own kinds in a stand-in login's store; a second user reads their own; an EnvironmentLogin
keeps none, so the files are read and written as before; a file's value is copied into a user's store once, the file
left as it was. Every file in the test's own folder; nothing started."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

import pytest

from liminal_libs import ui
from liminal_libs.apps import (LICENCE, PREFERENCE, App, EnvironmentLogin, Login, RecordingLogin, Traffic, Unauthorized,
                               accept_licence, as_user, asking_login, keeps, licence, recall)
from liminal_libs.apps.authorization import WORDS_KEPT

pytestmark = pytest.mark.usefixtures("stand_in_environment")  # its code reads this process's environment


class StoreLogin(Login):
    """A stand-in for the login app's session: one user's pairs in a dict, of the kinds the vault keeps."""

    keeps_settings = True

    def __init__(self, name: str):
        self.name, self.pairs = name, {}

    def user(self) -> dict:
        return {"name": self.name}

    def vector(self, name: str) -> str:
        if name not in self.pairs:
            raise Unauthorized("no such pair", 404)
        return self.pairs[name][1]

    def setting(self, name: str):
        if name not in self.pairs:
            return None
        kind, raw = self.pairs[name]
        if kind not in (PREFERENCE, LICENCE):
            raise Unauthorized(f"{name} is a {kind}", 409)
        return json.loads(raw)

    def keep_setting(self, name, value, kind=PREFERENCE, label=""):
        self.pairs[name] = (kind, json.dumps(value))
        return {"name": name, "kind": kind, "label": label}


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.setenv(ui.UI_VAR, str(tmp_path / "ui.json"))
    monkeypatch.setenv("LIMINAL_LICENCES_FILE", str(tmp_path / "licences.json"))
    return tmp_path


def test_each_user_keeps_their_own_theme_in_their_login(files):
    alice, bob = StoreLogin("alice"), StoreLogin("bob")
    assert ui.save_preferences(login=alice, theme="paper")["theme"] == "paper"
    assert alice.pairs["ui-theme"] == (PREFERENCE, '"paper"')
    assert ui.preferences(login=alice)["store"] == "login"
    assert ui.preferences(login=bob)["theme"] == "dark"  # bob's own: none kept yet, nor in the file
    ui.save_preferences(login=bob, theme="midnight")
    assert (ui.preferences(login=alice)["theme"], ui.preferences(login=bob)["theme"]) == ("paper", "midnight")
    assert not (files / "ui.json").exists()  # neither went to the file
    # the asking person's, when no login is given (what a hook asked from their page reads)
    with as_user(bob):
        assert ui.preferences()["theme"] == "midnight"
        ui.save_preferences(theme="graphite")
    assert bob.pairs["ui-theme"][1] == '"graphite"' and ui.preferences()["theme"] == "dark"


def test_an_environment_login_keeps_none_so_the_file_is_read_and_written_as_before(files):
    env = EnvironmentLogin(env={})
    assert not keeps(env)
    assert ui.save_preferences(login=env, theme="light")["store"] == "file"
    assert json.loads((files / "ui.json").read_text(encoding="utf-8")) == {"theme": "light"}
    assert ui.preferences(login=env)["theme"] == "light" and ui.preferences()["theme"] == "light"
    with pytest.raises(Unauthorized):
        env.setting("ui-theme")


def test_the_files_theme_is_copied_into_a_users_store_once_and_the_file_left_as_it_was(files):
    (files / "ui.json").write_text(json.dumps({"theme": "midnight"}), encoding="utf-8")
    alice = StoreLogin("alice")
    assert ui.preferences(login=alice)["theme"] == "midnight"
    assert alice.pairs["ui-theme"] == (PREFERENCE, '"midnight"')
    (files / "ui.json").write_text(json.dumps({"theme": "paper"}), encoding="utf-8")  # the file changed after
    assert ui.preferences(login=alice)["theme"] == "midnight"  # once: hers is read from then on
    assert json.loads((files / "ui.json").read_text(encoding="utf-8")) == {"theme": "paper"}  # the file as it was
    assert ui.preferences(login=StoreLogin("bob"))["theme"] == "paper"  # each user's store once


def test_a_store_that_refuses_falls_back_to_the_file(files):
    class Down(StoreLogin):
        def setting(self, name):
            raise Unauthorized("no login app answers", 503)

        def keep_setting(self, name, value, kind=PREFERENCE, label=""):
            raise Unauthorized("no login app answers", 503)

    down = Down("alice")
    ui.save_preferences(login=down, theme="paper")
    assert ui.preferences(login=down)["theme"] == "paper" and json.loads((files / "ui.json").read_text())["theme"] == "paper"


def test_a_licence_accepted_is_kept_with_what_when_and_by_whom(files):
    alice = StoreLogin("alice")
    at = datetime(2026, 11, 24, 9, 30, tzinfo=timezone.utc)
    words = "Creative Commons Attribution 4.0 International. " * 60
    rec = accept_licence(alice, "dbip-lite", title="DB-IP IP to City Lite", version="2026-11",
                         url="https://db-ip.com/db/download/ip-to-city-lite", words=words, at=at)
    assert rec["kept"] == "your login's store"
    kept = licence(alice, "dbip-lite")
    assert kept == {k: v for k, v in rec.items() if k != "kept"}
    assert alice.pairs["licence-dbip-lite"][0] == LICENCE
    assert (kept["licence"], kept["title"], kept["version"]) == ("licence-dbip-lite", "DB-IP IP to City Lite", "2026-11")
    assert kept["url"] == "https://db-ip.com/db/download/ip-to-city-lite"
    assert kept["acceptedAt"] == "2026-11-24T09:30:00Z" and kept["acceptedBy"] == "alice" and kept["login"] == "StoreLogin"
    assert len(kept["words"]) == WORDS_KEPT and len(kept["wordsSha256"]) == 64
    assert licence(StoreLogin("bob"), "dbip-lite") is None  # bob accepted nothing
    assert not (files / "licences.json").exists()


def test_a_licence_without_a_store_goes_to_the_licences_file_and_moves_in_once(files):
    env = EnvironmentLogin(env={})
    rec = accept_licence(env, "licence-dbip-lite", title="DB-IP Lite", version="2026-11", by="the user, in chat")
    assert rec["kept"] == "the file" and rec["acceptedBy"] == "the user, in chat"
    saved = json.loads((files / "licences.json").read_text(encoding="utf-8"))
    assert saved["licence-dbip-lite"]["title"] == "DB-IP Lite"
    assert licence(env, "dbip-lite")["version"] == "2026-11"
    alice = StoreLogin("alice")
    assert licence(alice, "dbip-lite")["acceptedBy"] == "the user, in chat"  # copied into her store, once
    assert alice.pairs["licence-dbip-lite"][0] == LICENCE and "licence-dbip-lite" in json.loads((files / "licences.json").read_text())


def test_a_key_is_never_read_as_a_setting(files):
    alice = StoreLogin("alice")
    alice.pairs["ui-theme"] = ("key", "paper")
    assert recall(alice, "ui-theme", lambda: "light") == "light"  # refused (409): the file's, the key untouched
    assert alice.pairs["ui-theme"] == ("key", "paper")


def test_the_recording_login_passes_the_settings_through(files):
    alice, traffic = StoreLogin("alice"), Traffic()
    lent = RecordingLogin(alice, "preferences", traffic)
    assert keeps(lent)
    ui.save_preferences(login=lent, theme="paper")
    assert ui.preferences(login=lent)["theme"] == "paper" and alice.pairs["ui-theme"][1] == '"paper"'


def test_the_asking_login_is_this_threads_alone(files):
    alice, seen = StoreLogin("alice"), []
    with as_user(alice):
        assert asking_login() is alice
        t = threading.Thread(target=lambda: seen.append(asking_login()))
        t.start()
        t.join()
    assert seen == [None] and asking_login() is None


def test_an_app_answers_each_browser_with_its_own_users_theme(files):
    users = {"a": StoreLogin("alice"), "b": StoreLogin("bob")}

    class Inherited:  # the login object an app inherits: a Login for the browser's session
        def user_login(self, handler):
            return users.get(handler.headers.get("who"))

    class Tiny(App):
        NAME, TITLE, ICON, PORT, LOGIN = "tiny", "Tiny", "chip", 0, True

        def make_login(self):
            return Inherited()

    class Asking:
        def __init__(self, who):
            self.headers = {"who": who}

    app = Tiny(log=lambda m: None, login=EnvironmentLogin(env={}))
    ui.save_preferences(login=users["a"], theme="paper")
    assert app.api(Asking("a"), "GET", "/api/ui", {}, None)[1]["theme"] == "paper"
    assert app.api(Asking("b"), "GET", "/api/ui", {}, None)[1]["theme"] == "dark"
    assert app.user_login(Asking("nobody")) is app.login  # nobody signed in there: the app's login (the file)
    assert app.api(Asking("nobody"), "GET", "/api/ui", {}, None)[1]["store"] == "file"
