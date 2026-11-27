"""An app's code base (apps/codebase.py, 1.59.0; the user, 2026-11-16: "i want to add another functional class called
codebase, which has the associated repositories (git/svn/,,,) if there are, also the code base, and stats like how
much is rust %, javascript %, etc..."; "this class will be added to all the 'apps' just like connections"; "it will
also say how far it is behind the remote").

The working copies are folders the tests make, with a mark of their kind and no history; git, svn and hg are a
stand-in that answers what each would (no process is started, no remote is asked)."""
from __future__ import annotations

import os
import time

import pytest

from liminal_libs.apps import codebase as cb
from liminal_libs.apps.codebase import Codebase

STATUS = b"""# branch.oid 3e065510b014c6f062bc2afb8b8f50cfae329920
# branch.head release/0.2.0
# branch.upstream origin/release/0.2.0
# branch.ab +2 -5
1 .M N... 100644 100644 100644 1111111 2222222 src/a.py
2 R. N... 100644 100644 100644 1111111 2222222 R100 src/b.py\tsrc/old.py
? notes.txt
? scratch.py
"""


class Tools:
    """git, svn and hg standing in: what each answers, by the folder it is asked in and its first words."""

    def __init__(self):
        self.answers: dict[tuple[str, str], tuple[int, bytes, bytes]] = {}
        self.asked: list[tuple[str, str]] = []

    def say(self, folder: str, command: str, out: bytes = b"", code: int = 0, err: bytes = b"") -> None:
        self.answers[(folder, command)] = (code, out, err)

    def __call__(self, args, cwd, timeout):
        command = " ".join(args)
        self.asked.append((os.path.basename(cwd), command))
        for (folder, begins), answer in self.answers.items():
            if folder == os.path.basename(cwd) and command.startswith(begins):
                return answer
        return 1, b"", b"not answered here"

    def git(self, folder: str, files: list[str], status: bytes = b"# branch.head main\n", remote: str = "") -> None:
        self.say(folder, "git status", status)
        self.say(folder, "git log", b"3e06551\x1f2026-11-16T00:02:30-08:00\x1f1.55.0: the firewalls' World Wide Web tab\n")
        self.say(folder, "git ls-files", "\0".join(files).encode() + b"\0")
        if remote:
            self.say(folder, "git config --get remote.origin.url", remote.encode() + b"\n")
            self.say(folder, "git config --get-regexp", f"remote.origin.url {remote}\n".encode())


def _files(top, files: dict[str, bytes | str]) -> None:
    for rel, text in files.items():
        path = top / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode())


@pytest.fixture
def workspace(tmp_path):
    """A workspace of four: a git repository, a Subversion and a Mercurial working copy, and a folder in none."""
    ws = tmp_path / "liminal"
    for name, mark in (("common", ".git"), ("legacy", ".svn"), ("plugins/tool", ".hg")):
        (ws / name / mark).mkdir(parents=True)
    _files(ws / "common", {
        "src/a.py": "import os\n\n\ndef a():\n    return 1\n",  # 5 lines
        "src/b.py": "x = 1",  # one line, no newline at its end
        "src/page.js": "const a = 1;\nconst b = 2;\n",
        "src/core.rs": "fn main() {\n}\n",
        "src/look.css": "a{color:red}\n",
        "README.md": "# Common\n\nWords.\n",
        "pyproject.toml": "[project]\nname = 'x'\n",
        "scratch.py": "never_committed = True\n",  # not tracked: no part of the code base
        "src/vendor/big.js": "x\n" * 500,
        "src/app.min.js": "y\n",
        "Cargo.lock": "z\n",
        "src/image.py": b"\0\0binary named like code\n",
        "src/huge.py": b"#\n" * (cb.LARGE // 2 + 1),
        "LICENSE": "words\n",
    })
    _files(ws / "legacy", {"old.py": "print(1)\nprint(2)\n", "node_modules/dep/index.js": "x\n", "notes.txt": "a\n"})
    _files(ws / "plugins/tool", {"tool.sh": "#!/bin/sh\necho hi\n", "Dockerfile": "FROM scratch\n"})
    _files(ws / "loose", {"run.ps1": "Write-Output 1\n"})
    (ws / ".venv" / "lib" / ".git").mkdir(parents=True)  # never looked into
    (ws / "a" / "b" / "c" / "deep" / ".git").mkdir(parents=True)  # too far down to be one of the workspace's
    return ws


@pytest.fixture
def tools():
    t = Tools()
    t.git("common", ["src/a.py", "src/b.py", "src/page.js", "src/core.rs", "src/look.css", "README.md", "pyproject.toml",
                     "src/vendor/big.js", "src/app.min.js", "Cargo.lock", "src/image.py", "src/huge.py", "LICENSE"],
          status=STATUS, remote="https://someone:ghp_SECRETTOKEN@github.com/pcxmac-dev/liminal-libs.git")
    t.say("legacy", "svn info", b"Path: .\nURL: https://svn.example.org/repos/legacy/trunk\nRelative URL: ^/trunk\n"
                                b"Revision: 412\nLast Changed Date: 2026-10-01 10:00:00 +0000 (Thu, 01 Oct 2026)\n")
    t.say("legacy", "svn status", b"M       old.py\n")
    t.say("tool", "hg id", b"a1b2c3d4e5f6+ default\n")
    t.say("tool", "hg paths", b"https://name:pw@hg.example.org/tool\n")
    return t


def _base(workspace, tools, **kw) -> Codebase:
    return Codebase(roots=[workspace], runner=tools, own_parts=lambda: [("the library", workspace / "common" / "src"),
                                                                        ("the platform app", workspace / "loose")], **kw)


def _row(got: dict, name: str) -> dict:
    return next(r for r in got["repositories"] if r["name"] == name)


def test_the_working_copies_are_found_by_their_kind_and_a_part_in_none_is_listed(workspace, tools):
    found = {top.name: (kind, used) for top, kind, used in _base(workspace, tools).find()}
    assert found == {"common": ("git", ["the library"]), "legacy": ("svn", []), "tool": ("hg", []),
                     "loose": ("", ["the platform app"])}  # nothing under .venv, nothing four folders down
    assert cb.top_of(workspace / "common" / "src" / "a.py") == (workspace / "common", "git")
    assert cb.top_of(workspace / "loose") is None and cb.kind_of(workspace / "legacy") == "svn"


def test_a_repository_says_where_it_stands_and_how_far_it_is_behind_its_remote(workspace, tools):
    asked_at = time.time() - 3600
    (workspace / "common" / ".git" / "FETCH_HEAD").write_text("x")
    os.utime(workspace / "common" / ".git" / "FETCH_HEAD", (asked_at, asked_at))
    got = _base(workspace, tools).read()
    common = _row(got, "common")
    assert (common["kind"], common["branch"], common["commit"]) == ("git", "release/0.2.0", "3e06551")
    assert common["subject"] == "1.55.0: the firewalls' World Wide Web tab" and common["when"].startswith("2026-11-16T00:02:30")
    assert (common["upstream"], common["ahead"], common["behind"]) == ("origin/release/0.2.0", 2, 5)
    assert (common["changed"], common["untracked"]) == (2, 2) and abs(common["asked"] - asked_at) < 2
    # where the remote is, never what opens it
    assert common["remote"] == "https://github.com/pcxmac-dev/liminal-libs.git" and "SECRETTOKEN" not in repr(got)
    legacy, tool, loose = _row(got, "legacy"), _row(got, "tool"), _row(got, "loose")
    assert (legacy["kind"], legacy["commit"], legacy["branch"], legacy["changed"]) == ("svn", "r412", "trunk", 1)
    assert legacy["remote"] == "https://svn.example.org/repos/legacy/trunk" and legacy["behind"] is None  # its server is not asked
    assert (tool["kind"], tool["commit"], tool["branch"], tool["changed"]) == ("hg", "a1b2c3d4e5f6", "default", 1)
    assert tool["remote"] == "https://hg.example.org/tool"
    assert (loose["kind"], loose["remote"], loose["behind"], loose["used"]) == ("", "", None, ["the platform app"])
    assert got["totals"]["repositories"] == 4 and got["totals"]["behind"] == 1 and got["totals"]["ahead"] == 1
    assert got["totals"]["changed"] == 3 and got["workspace"] == str(workspace)
    assert not [c for _, c in tools.asked if "fetch" in c or "pull" in c or "incoming" in c or "-u" in c.split()]  # no remote asked
    detached = Tools()
    detached.git("common", ["src/a.py"], status=b"# branch.oid abc\n# branch.head (detached)\n")
    lone = Codebase(roots=[workspace / "common"], runner=detached, own_parts=lambda: []).read()["repositories"][0]
    assert (lone["branch"], lone["upstream"], lone["behind"], lone["remote"]) == ("", "", None, "")  # follows nothing


def test_the_code_is_counted_by_language_and_the_shares_are_of_code_and_markup(workspace, tools):
    got = _base(workspace, tools).read()
    common = _row(got, "common")
    by = {r["name"]: r for r in common["languages"]}
    assert (by["Python"]["files"], by["Python"]["lines"]) == (2, 6)  # the tracked ones: scratch.py is no part of it
    assert by["Python"]["bytes"] == len("import os\n\n\ndef a():\n    return 1\n") + len("x = 1")
    assert (by["JavaScript"]["files"], by["JavaScript"]["lines"]) == (1, 2) and (by["Rust"]["lines"], by["CSS"]["lines"]) == (2, 1)
    assert by["Markdown"]["kind"] == "prose" and by["TOML"]["kind"] == "data" and by["Markdown"]["share"] is None
    counted = [r for r in common["languages"] if r["share"] is not None]
    assert [r["name"] for r in counted] == ["Python", "JavaScript", "Rust", "CSS"]  # the largest first, then prose and data
    assert abs(sum(r["share"] for r in counted) - 100.0) < 0.3 and counted[0]["share"] > 40
    # vendored and generated files, a binary one and a very large one are not its own writing; LICENSE is no language
    assert common["leftOut"] == {"vendored": 3, "binary": 1, "large": 1, "other": 1, "unread": 0}
    assert (common["files"], common["lines"]) == (7, 16)
    # a working copy that is not git's is walked, the folders that hold none of its writing left out
    assert {r["name"]: r["lines"] for r in _row(got, "legacy")["languages"]} == {"Python": 2, "Text": 1}
    assert {r["name"] for r in _row(got, "tool")["languages"]} == {"Shell", "Dockerfile"}
    whole = {r["name"]: r for r in got["languages"]}
    assert whole["Python"]["files"] == 3 and whole["PowerShell"]["lines"] == 1 and got["totals"]["files"] == 7 + 2 + 2 + 1
    mine = {r["name"]: r["files"] for r in got["mine"]["languages"]}  # what this app runs from: common and loose
    assert mine["Python"] == 2 and mine["PowerShell"] == 1 and "Shell" not in mine and got["mine"]["repositories"] == 2
    assert cb.language_of("Makefile") == ("Makefile", "code") and cb.language_of("photo.png") is None
    assert cb.not_its_own("src/vendor/x.js") and cb.not_its_own("pkg.egg-info/PKG-INFO") and not cb.not_its_own("src/data.py")


def test_a_tool_that_is_not_installed_is_said_and_the_code_is_still_counted(workspace):
    none = Tools()  # nothing answers: as on a machine with none of the three
    none.say("common", "git status", code=127, err=b"git is not installed here")
    none.say("legacy", "svn info", code=127)
    none.say("tool", "hg id", code=127)
    got = Codebase(roots=[workspace], runner=none, own_parts=lambda: []).read()
    assert _row(got, "common")["problem"] == "git is not installed here: this working copy is not read"
    assert "Subversion (svn) is not installed here" in _row(got, "legacy")["problem"]
    assert "Mercurial (hg) is not installed here" in _row(got, "tool")["problem"]
    # counted all the same, by walking: every file there, tracked or not (git could not say which)
    assert {r["name"]: r["files"] for r in _row(got, "common")["languages"]}["Python"] == 3
    broken = Tools()
    broken.say("common", "git status", code=128, err=b"fatal: detected dubious ownership in repository\n")
    row = Codebase(roots=[workspace / "common"], runner=broken, own_parts=lambda: []).read()["repositories"][0]
    assert row["problem"] == "git could not read it: fatal: detected dubious ownership in repository"


def test_it_is_read_in_a_thread_kept_and_read_again_when_asked_or_old(workspace, tools):
    now = [1000.0]
    base = _base(workspace, tools, clock=lambda: now[0])
    first = base.snapshot()
    assert first["state"] == "reading" and first["repositories"] == []  # asked for the first time: begun, not waited for
    got = base.wait()
    assert got["state"] == "ready" and len(got["repositories"]) == 4 and got["at"] == 1000.0 and got["fetching"] is None
    asked = len(tools.asked)
    now[0] += cb.KEEP_S - 1
    assert base.snapshot()["state"] == "ready" and len(tools.asked) == asked  # kept: nothing asked again
    now[0] += 2
    again = base.snapshot()
    assert again["state"] == "reading" and len(again["repositories"]) == 4  # too old: read again, the old one shown meanwhile
    assert base.wait()["at"] == now[0] and len(tools.asked) > asked
    asked = len(tools.asked)
    assert base.snapshot(fresh=True)["state"] == "reading"
    assert base.wait()["state"] == "ready" and len(tools.asked) > asked

    def failing(args, cwd, timeout):
        raise RuntimeError("the disk went away")

    said = Codebase(roots=[workspace], runner=failing, own_parts=lambda: [])
    said.snapshot()
    assert "could not be read: RuntimeError: the disk went away" in said.wait()["problem"]


def test_the_remotes_are_asked_only_when_told_and_what_fails_is_said_without_a_token(workspace, tools):
    (workspace / "second" / ".git").mkdir(parents=True)
    tools.git("second", [], remote="https://someone:ghp_OTHERTOKEN@github.com/pcxmac-dev/second.git")
    (workspace / "alone" / ".git").mkdir(parents=True)
    tools.git("alone", [])  # a repository with no remote: nothing to ask
    tools.say("common", "git fetch", b"")
    tools.say("second", "git fetch", code=128,
              err=b"fatal: unable to access 'https://someone:ghp_OTHERTOKEN@github.com/pcxmac-dev/second.git/': timed out\n")
    base = _base(workspace, tools)
    base.read()
    assert not [c for _, c in tools.asked if c.startswith("git fetch")]  # a reading asks no remote
    assert base.fetch() == {"started": True}
    end = time.monotonic() + 10
    while time.monotonic() < end and not (base.snapshot().get("fetching") or {}).get("ended"):
        time.sleep(0.01)
    got = base.wait()
    assert sorted(f for f, c in tools.asked if c.startswith("git fetch")) == ["common", "second"]  # not the one without a remote
    fetching = got["fetching"]
    assert (fetching["done"], fetching["total"], fetching["ended"]) == (3, 3, True)
    assert [e["name"] for e in fetching["errors"]] == ["second"] and "timed out" in fetching["errors"][0]["why"]
    assert "OTHERTOKEN" not in repr(got) and got["state"] == "ready"  # read again after the remotes answered
    tools.asked.clear()
    (workspace / "plugins" / "common" / ".git").mkdir(parents=True)  # another of the same name, elsewhere
    tools.git("common", [], remote="https://github.com/pcxmac-dev/liminal-libs.git")
    tools.say("common", "git fetch", b"")
    assert base.fetch(paths=[workspace / "common"]) == {"started": True}  # told by where it is, not by its name
    end = time.monotonic() + 10
    while time.monotonic() < end and not (base.snapshot().get("fetching") or {}).get("ended"):
        time.sleep(0.01)
    base.wait()
    assert [f for f, c in tools.asked if c.startswith("git fetch")] == ["common"]


def test_a_remotes_address_is_shown_without_what_opens_it():
    assert cb.plain_address("https://name:token@github.com/o/r.git") == "https://github.com/o/r.git"
    assert cb.plain_address("https://token@github.com/o/r.git") == "https://github.com/o/r.git"
    assert cb.plain_address("ssh://git@github.com/o/r.git") == "ssh://github.com/o/r.git"
    assert cb.plain_address("git@github.com:o/r.git") == "git@github.com:o/r.git"  # no secret in it: as it is
    assert cb.plain_address("/mnt/c/Users/x/source/liminal/common") == "/mnt/c/Users/x/source/liminal/common"
    assert cb.plain_address("") == ""
    # a tool's own words repeat the address as it was given (found by the test of a fetch that fails)
    said = "fatal: unable to access 'https://name:ghp_TOKEN@github.com/o/r.git/': timed out; see https://u:p@other.example/x"
    assert cb.plain_address(said) == "fatal: unable to access 'https://github.com/o/r.git/': timed out; see https://other.example/x"


def test_the_real_runner_starts_git_without_a_window_a_lock_or_a_question(monkeypatch, stand_in_environment):
    started: list[dict] = []

    class Done:
        returncode, stdout, stderr = 0, b"ok", b""

    def fake_run(args, **kw):
        started.append({"args": args, **kw})
        if args[0] == "missing":
            raise FileNotFoundError
        if args[0] == "slow":
            raise cb.subprocess.TimeoutExpired(args, kw["timeout"])
        return Done()

    monkeypatch.setattr(cb.subprocess, "run", fake_run)
    assert cb.run(["git", "status"], ".", 5.0) == (0, b"ok", b"")
    kw = started[0]
    assert kw["env"]["GIT_OPTIONAL_LOCKS"] == "0" and kw["env"]["GIT_TERMINAL_PROMPT"] == "0" and kw["timeout"] == 5.0
    assert kw["stdin"] == cb.subprocess.DEVNULL and kw.get("creationflags", 0) == (0x08000000 if os.name == "nt" else 0)
    assert cb.run(["missing"], ".", 1.0)[0] == 127 and cb.run(["slow"], ".", 1.0)[0] == 124


def test_every_app_holds_one_and_answers_it_at_its_own_address(workspace, tools, tmp_path):
    """As every app holds its connections (apps.traffic): the frame makes it, the frame answers it."""
    import json
    from http.client import HTTPConnection

    from liminal_libs import web
    from liminal_libs.apps import App
    from liminal_libs.apps.app import CODEBASE_PATH

    class Demo(App):
        NAME, TITLE, ICON = "demo", "Demo", "plug"

    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    Demo.STATIC = tmp_path
    app = Demo(log=lambda m: None)
    assert isinstance(app.codebase, Codebase) and app.codebase.app is app and app.codebase._kept is None  # nothing read yet
    app.codebase._roots, app.codebase.runner = [workspace], tools
    parts = dict(app.codebase.parts())
    assert set(parts) == {"the demo app", "the library"} and parts["the library"].name == "liminal_libs"
    # from here its parts are the test's own folders (the real ones are this library's checkout, wherever the tests run)
    app.codebase._own_parts = lambda: [("the demo app", workspace / "loose"), ("the library", workspace / "common" / "src")]
    app.start(0)
    try:
        port = int(app.served.split("127.0.0.1:", 1)[1].split("/", 1)[0])

        def ask(method, path, body=None, headers=None):
            conn = HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers or {})
            r = conn.getresponse()
            raw = r.read()
            return r.status, json.loads(raw) if raw[:1] == b"{" else {}  # (a refusal is said in plain words)

        status, first = ask("GET", CODEBASE_PATH)
        assert status == 200 and first["state"] == "reading"
        app.codebase.wait()
        status, got = ask("GET", CODEBASE_PATH)
        assert status == 200 and got["state"] == "ready" and got["app"] == "demo"
        assert {r["name"] for r in got["repositories"]} >= {"common", "legacy", "tool"} and "SECRETTOKEN" not in json.dumps(got)
        assert ask("GET", CODEBASE_PATH + "?fresh=1")[1]["state"] == "reading"
        app.codebase.wait()
        # asking the remotes is a write: only this app's own page may (the frame's header), as any change
        refused, _ = ask("POST", CODEBASE_PATH + "/fetch", {})
        assert refused == 403 and not [c for _, c in tools.asked if c.startswith("git fetch")]
        tools.say("common", "git fetch", b"")
        status, began = ask("POST", CODEBASE_PATH + "/fetch", {"paths": [str(workspace / "common")]},
                            {"Content-Type": "application/json", web.WRITE_HEADER: "1"})
        assert status == 202 and began == {"started": True}
        end = time.monotonic() + 10
        while time.monotonic() < end and not (app.codebase.snapshot().get("fetching") or {}).get("ended"):
            time.sleep(0.01)
        app.codebase.wait()
        assert [f for f, c in tools.asked if c.startswith("git fetch")] == ["common"]
    finally:
        app.stop()


def test_the_remotes_are_asked_only_by_a_person_at_the_page():
    """POST /api/codebase/fetch (the sweep of 2026-11-26): any program on the machine could have git ask every
    remote. Refused (401) when the login says no one is shown to be there; asked when it says so, or with no login."""
    from liminal_libs.apps import Refused

    from liminal_libs.apps import App

    class Demo(App):
        NAME, TITLE, ICON = "demo", "Demo", "plug"

    app, asked, shown = Demo(log=lambda m: None), [], []
    app.codebase.fetch = lambda paths=None: asked.append(paths) or {"fetching": True}  # no git is run here
    request = object()
    app.present = lambda handler: shown.append(handler) or False
    with pytest.raises(Refused) as refused:
        app.api(request, "POST", "/api/codebase/fetch", {}, {"paths": ["C:/x"]})
    assert refused.value.status == 401 and "asked only from this app's page" in refused.value.reason
    assert asked == [] and shown == [request]  # the login was shown this request, and git was asked nothing
    for said in (True, None):  # a person shown to be there; an app that holds no login, as before
        app.present = lambda handler, said=said: said
        assert app.api(request, "POST", "/api/codebase/fetch", {}, {"paths": ["C:/x"]}) == (202, {"fetching": True})
    assert app.api(request, "POST", "/api/codebase/fetch", {}, {}) == (202, {"fetching": True})
    assert asked == [["C:/x"], ["C:/x"], None]


def test_the_drawing_and_its_icon_come_with_the_library():
    """codebase.js is the library's, served beside every app's page (ui.STATIC): the same picture in each."""
    from liminal_libs import ui

    js = (ui.STATIC / "codebase.js").read_text(encoding="utf-8")
    assert "window.LiminalCodebase = { html, side, mount, unmount, colorOf, parts, repoSpec };" in js
    assert "/api/codebase" in js and "/api/codebase/fetch" in js and "'X-Liminal-Charts': '1'" in js  # a write is the page's own
    # a language keeps its colour whatever its rank: the themes' series in a fixed order, the rest together
    assert "const ORDER = ['Python', 'JavaScript', 'Rust', 'CSS', 'HTML', 'TypeScript', 'Shell'];" in js
    assert "var(--series-${i + 1})" in js and "'Other'" in js and "'< 0.1 %'" in js
    assert "await m.confirm(" in js and js.index("await m.confirm(") < js.index("m.send('/api/codebase/fetch'")  # asked first
    assert "http://" not in js and "https://" not in js  # it names no place outside the app
    assert "    branch: '<g stroke-width=" in (ui.STATIC / "icons.js").read_text(encoding="utf-8")


def test_with_a_panel_the_side_is_the_tool_and_the_repository_picked_is_told_under_it():
    """1.105.0 (Monday list item 31; docs/PAGES.md): mounted with a LiminalSide panel, the side's whole is the panel's top
    and a repository picked in the middle is the pick, told in full; without one, as before."""
    from liminal_libs import ui

    js = (ui.STATIC / "codebase.js").read_text(encoding="utf-8")
    assert "panel: o.panel && window.LiminalSide ? o.panel : null, scope: o.scope || 'codebase'" in js
    draw = js.split("function draw() {", 1)[1].split("\n  }", 1)[0]
    assert "m.panel.tool(m.scope, side(m.d, { ...m.view, picked: undefined }));" in draw
    assert "window.LiminalSide.rows(m.dataEl, { selector: 'tr[data-pick]'" in draw and "m.panel.refresh(" in draw
    assert "if (m.sideEl) m.sideEl.innerHTML = side(m.d, m.view);" in draw  # no panel: as before
    assert 'data-pick="${esc(`repo:${r.path || r.name}`)}"' in js
    assert "if (repo && m.panel) return;  // picked by LiminalSide.rows" in js
    spec = js.split("function repoSpec(r) {", 1)[1].split("\n  }", 1)[0]
    for fact in ("'Where'", "'Branch'", "'Commit'", "'Remote'", "'From its remote'", "'Not committed'", "'Its languages'"):
        assert fact in spec, fact
    assert "far.html.replace(/<[^>]*>/g, '')" in spec  # its own markup as words: side.js escapes everything it is given
