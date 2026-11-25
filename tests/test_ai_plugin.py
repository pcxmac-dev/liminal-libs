"""What every AI plugin of the platform shares (liminal_libs.machines.ai, 1.62.0): a stand-in subclass that conforms
with one card; the hooks it offers (never Docker's `instances`); Install and Uninstall, each refusal in words before a
job's first line and the second confirmation each names (accept_licence, accept_removal); the cancelled answer and a
failure's, the half-built folder removed and the one in use kept, and what is said once the new pin is in use; the one
install layout (app/<pin>/, app/CURRENT) on a temporary folder, told by its pin and never built over the one in use; a
start and an install or an uninstall excluding each other (a model server's start among them); what never reaches a
child (`dropped`, and the environment of every stream, unpack and short command) and what a short command keeps;
whether a pair lasts on both systems; a library older than the floor (a stand-in version); a folder on another
system's drive (a stand-in mounts.foreign); a status whose parts raise, answered valid with a problem; the facts, forms
and actions of Main, what is checked against a pinned sum among them; a download fetched into its folder, what a
cancel kept said as it is and forgotten from the page; a detach cancelling an install; and no key in any answer, a
streamed line's included.

Nothing is installed, downloaded or run here: stand-ins answer for the login, the registry, the web, the streams and
the short commands, and the shared guard (conftest.py) fails a test that starts a process or opens a connection."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import threading
from pathlib import Path

import pytest

import liminal_libs
from liminal_libs import instances, mounts
from liminal_libs.apps.authorization import EnvironmentLogin, Login, Unauthorized, pair_name, variable_name
from liminal_libs.apps.traffic import RecordingLogin, Traffic
from liminal_libs.machines import ai, children, download
from liminal_libs.machines.ai import (ACCEPT_LICENCE, ACCEPT_REMOVAL, CANCELLED, CANCELLED_AFRESH, LASTING, UNCHECKED,
                                      AiPlugin, Installed, Outside, Package, Setting, exactly, lasts)
from liminal_libs.machines.endpoint import Reply
from liminal_libs.machines.terminal import Cancelled, Output
from liminal_libs.sources import conformance, registry
from liminal_libs.sources.apis import Api, Link
from test_modelserver import Server as StandInServer, boot, world  # noqa: F401 - a model server's, and its fixtures

pytestmark = pytest.mark.usefixtures("no_outside")

HTTPS = "https:" + "//"  # an address's start, put together here: no file names a host whole
CARD = Api("Stand-in tool", "Its maker", "What the stand-in tool offers the platform", kind="command",
           links=(Link("Its documentation", HTTPS + "docs.example.test/tool"),), verified="2026-11-16")
KEY = "sk-stand-in-1234567890"  # a key a test keeps: it is in no answer
TOKEN = "hf_stand_in_token_0123456789"  # a token a streamed command is given: it is in no line of its panel
PACKAGE = Package("Tool", "1.2.3", 52_428_800, "MIT (its maker's).", ("downloads.example.test", "cdn.example.test"),
                  parts="Tool's standalone archive tool-1.2.3.zip", keeps="Its models and your instances stay.")
DECLARED = ("MASSIVE_API_KEY", "OPENAI_API_KEY", "TOOL_PLAN")  # what the registry says the installed plugins declare
BEING_CHANGED = "Tool is being installed or removed: wait for that to end"  # what a start says meanwhile

def hold_login(plugin):
    """A plugin given a login as its app lends one (1.86.0: a plugin holding none refuses to be asked)."""
    from liminal_libs.apps.authorization import NoLogin

    object.__setattr__(plugin, "login", NoLogin())
    return plugin


class Pairs(Login):
    """The platform's login as a test has it: pairs kept in memory, each save noted."""

    def __init__(self):
        self.kept: dict[str, str] = {}
        self.saved: list[tuple[str, bool]] = []

    def user(self) -> dict:
        return {"name": "someone"}

    def vector(self, name: str) -> str:
        variable = variable_name(name)
        if variable not in self.kept:
            raise Unauthorized(f"no {name}", 404)
        return self.kept[variable]

    def names(self) -> set[str]:
        return {pair_name(v) for v in self.kept}

    def save(self, variable: str, value: str | None) -> str:
        self.saved.append((variable, value is not None))
        if value is None:
            self.kept.pop(variable, None)
        else:
            self.kept[variable] = value
        return "the test's pairs"


class Tool(AiPlugin):
    """A stand-in AI plugin: what it brings, what is found, what runs and what fails are the test's to set."""

    name = "tool"
    title = "Tool"
    about = "A stand-in AI plugin for the base's tests"
    order = 520
    GROUP = "harness"
    LIBS_FLOOR = "1.62.0"
    apis = (CARD,)

    def __init__(self, outside=None):
        super().__init__(outside)
        self.brings: Package | None = PACKAGE
        self.found: Installed | None = None  # an install of the user's own
        self.here = ""  # why it cannot run here
        self.busy: list[str] = []  # what of it runs
        self.boot: list[str] = []  # what of it starts at boot
        self.version_said = "1.2.3 (read)"
        self.reads = 0  # how often its version was read
        self.fails: BaseException | None = None  # what install_into raises once it has built its folder
        self.cancel_after_build = False  # the user's Cancel, clicked while it builds
        self.adopts = True

    def package(self):
        return self.brings

    def installed(self):
        return self.found if self.found is not None else super().installed()

    def read_version(self, installed):
        self.reads += 1
        if isinstance(self.version_said, BaseException):
            raise self.version_said
        return self.version_said

    def runs_here(self):
        return self.here

    def running(self):
        return list(self.busy)

    def boot_names(self):
        return list(self.boot)

    def install_into(self, log, cancel):
        folder = self.building(PACKAGE.version)
        (folder / "tool.exe").write_text("a stand-in program", encoding="utf-8")
        downloads = self.home / "downloads"
        downloads.mkdir(parents=True, exist_ok=True)
        (downloads / "tool-1.2.3.zip.part").write_bytes(b"part of it")
        if callable(log):
            log("tool-1.2.3.zip: 50 MB downloaded")
        if self.cancel_after_build:
            log.cancel()  # the page's Cancel, as the job's panel takes it
        if cancel():
            raise Cancelled("cancelled at 3.1 MB of tool-1.2.3.zip: what came is kept, and the next download goes on")
        if self.fails is not None:
            raise self.fails
        return self.adopt(PACKAGE.version) if self.adopts else ["unpacked"]


class Starts(Tool):
    """A stand-in with a start and an open of its own, as a model server's and a harness's are: one named "held"
    waits for `go` (it is under way meanwhile), one named "fails" raises."""

    HOOKS = (*Tool.HOOKS, "start", "open")

    def __init__(self, outside=None):
        super().__init__(outside)
        self.started: list[str] = []
        self.under_way, self.go = threading.Event(), threading.Event()

    def start(self, name):
        """A stand-in start: noted."""
        if name == "held":
            self.under_way.set()
            assert self.go.wait(5)
        if name == "fails":
            raise RuntimeError("it would not start")
        self.started.append(name)
        return {"said": f"{name} started", "ok": True, "lines": []}

    def open(self, folder=None):
        """A stand-in open: noted."""
        self.started.append(f"opened in {folder}")
        return {"said": "opened", "ok": True, "lines": []}


@pytest.fixture(autouse=True)
def this_library(monkeypatch):
    """The release these bases come in (a stand-in version: the worktree's says the one before it), on this
    system's own disk unless a test says otherwise (a stand-in mounts.foreign)."""
    monkeypatch.setattr(liminal_libs, "__version__", "1.62.0")
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: False)


@pytest.fixture
def tool(tmp_path):
    p = Tool(Outside(env={"PATH": "/usr/bin", "MASSIVE_API_KEY": "m-key-1", "LIMINAL_AI_TOOL_USE": "{}",
                          "HOME": "/home/someone"},
                     system="windows", home=tmp_path / "tool", variables=lambda: DECLARED))
    p.login = Pairs()
    return p


def made(cls, tmp_path, name: str = "tool"):
    """A stand-in of `cls` on its own folder, with a login and no installed plugin's variables."""
    p = cls(Outside(env={}, system="windows", home=tmp_path / name, variables=lambda: ()))
    p.login = Pairs()
    return p


def installed_at(p: AiPlugin, *pins: str, current: str | None = None) -> None:
    """Installs of `pins` laid out as an install leaves them, `current` named in use."""
    app = p.home / "app"
    for pin in pins:
        (app / pin).mkdir(parents=True, exist_ok=True)
        (app / pin / "tool.exe").write_text("a stand-in program", encoding="utf-8")
    if current is not None:
        (app / "CURRENT").write_text(current + "\n", encoding="utf-8")


def refusal(call) -> instances.Refusal:
    with pytest.raises(instances.Refusal) as caught:
        call()
    return caught.value


def form_of(p: AiPlugin, form: str) -> dict:
    return next(f for f in p.status()["forms"] if f["id"] == form)


def titles(p: AiPlugin) -> list[str]:
    return [a.get("title") for a in p.status()["actions"]]


def web_of(address: str, data: bytes, *, then=None, piece: int = 1000):
    """https as download.fetch asks it, a stand-in: `address` answered 200 with `data`, `piece` bytes at a time, and
    `then()` called once its first piece was taken (the user's Cancel, clicked as it downloads); anything else 404."""
    asked: list[str] = []

    def opener(url, headers, timeout):
        asked.append(url)
        if url != address:
            return Reply(404, {}, iter(()))

        def chunks():
            for at in range(0, len(data), piece):
                yield data[at:at + piece]
                if at == 0 and then is not None:
                    then()
        return Reply(200, {"Content-Length": str(len(data))}, chunks())

    opener.asked = asked
    return opener


def popen_of(out: bytes = b"", err: bytes = b"", code: int = 0, *, hangs: bool = False):
    """subprocess.Popen as a short command's stand-in: what it was given, what it writes and its exit code; one that
    `hangs` ends only once it is killed."""
    made_: list = []

    class Ran:
        def __init__(self, argv, **kw):
            self.argv, self.kw, self.killed, self.waited = list(argv), kw, False, []
            self.stdout, self.stderr = io.BytesIO(out), io.BytesIO(err)
            made_.append(self)

        def wait(self, timeout=None):
            self.waited.append(timeout)
            if hangs and not self.killed:
                raise subprocess.TimeoutExpired(self.argv, timeout)
            return -9 if self.killed else code

        def kill(self):
            self.killed = True

    Ran.made = made_
    return Ran


# -- the contract ------------------------------------------------------------------------------------------------------
def test_a_stand_in_plugin_conforms_with_one_card(tool):
    assert conformance.problems(tool) == []
    said = (tool.KIND, tool.SYSTEM, tool.SECTION, tool.GROUP, tool.api)
    assert said == ("machine", "platform", "ai", "harness", "2.2")
    assert AiPlugin.SECTION == "ai" and AiPlugin.GROUP == "" and AiPlugin.LIBS_FLOOR == ""


def test_its_hooks_are_the_bases_and_never_dockers_instances(tool):
    hooks = tool.interface()["hooks"]
    assert set(hooks) == {"present", "status", "refresh", "install", "uninstall"}
    assert hooks["install"] == "(accept_licence=False, log=None) -> 'dict'" and hooks["status"] == "() -> 'dict'"
    assert AiPlugin.HOOKS[-3:] == ("refresh", "install", "uninstall")
    assert tool.JOB_HOOKS == ("install",) and tool.CANCEL_HOOKS == ("install",)
    assert AiPlugin.READ_HOOKS == ("refresh",) and AiPlugin.START_HOOKS == ("start", "open")
    assert not tool.gives("instances") and tool.instances() == ()  # Docker would take it for an engine
    assert not tool.gives("setup") and not tool.gives("run")


def test_one_run_state_across_the_registry_s_copies(tool):
    copy = tool.with_(origin="the plugin directory's checkout")
    assert copy._rt is tool._rt and copy.out is tool.out
    installed_at(tool, "1.2.3", current="1.2.3")
    copy.refresh()
    assert tool._rt.versions == {str(tool.home / "app" / "1.2.3"): "1.2.3 (read)"}


def test_a_subclass_may_keep_more_in_the_one_run_state(tmp_path):
    class More(ai.Run):
        def __init__(self):
            super().__init__()
            self.servers = {}

    class Server(Tool):
        RUN_STATE = More

    p = Server(Outside(env={}, home=tmp_path))
    assert isinstance(p._rt, More) and p._rt.servers == {} and p._rt.versions == {} and p._rt.starts == 0


# -- Install -----------------------------------------------------------------------------------------------------------
def test_install_runs_as_a_job_and_puts_its_pin_in_use(tool):
    out = Output()
    answer = tool.ask("install", True, log=out)  # as the platform asks a job: the page's args, then its panel
    assert answer["ok"] is True and answer["said"] == f"Tool 1.2.3 (read) installed in {tool.home / 'app' / '1.2.3'}"
    assert (tool.home / "app" / "CURRENT").read_text(encoding="utf-8") == "1.2.3\n"
    assert answer["lines"][0] == f"in use now: {tool.home / 'app' / '1.2.3'}"
    assert answer["lines"][-1] == "nothing was started"
    said = out.text.splitlines()
    assert said[0] == f"installing Tool 1.2.3 into {tool.home}" and said[-1] == answer["said"]
    assert tool.reads == 1  # read once, inside the job
    status = tool.status()
    assert status["installed"].startswith("1.2.3, installed by this plugin in ")
    assert tool.reads == 1  # a status reads no version
    assert tool._rt.job is None and not tool._rt.changing.locked()  # nothing of the job is held once it has ended


@pytest.mark.parametrize("given", [False, None, "true", 1, "yes"])
def test_install_asks_its_licence_in_a_second_confirmation(tool, given):
    out = Output()
    e = refusal(lambda: tool.install(given, log=out))
    assert e.accept == ACCEPT_LICENCE == "accept_licence" and "licence of Tool 1.2.3 is not accepted yet" in str(e)
    assert out.end == 0 and not (tool.home / "app").exists()  # before its first line: the page asks it again


def test_install_is_refused_in_words_before_its_first_line(tool, monkeypatch):
    def refused(setup, words):
        out = Output()
        setup()
        e = refusal(lambda: tool.install(True, log=out))
        assert words in str(e) and e.accept is None and out.end == 0, str(e)

    tool.brings = None
    refused(lambda: None, "Tool is not installed from here on this system")
    tool.brings, tool.here = PACKAGE, "this plugin installs Tool for x86-64 only"
    refused(lambda: None, "this plugin installs Tool for x86-64 only")
    tool.here = ""
    tool.found = Installed("", "C:/Users/someone/bin/tool.exe", "found")
    refused(lambda: None, "Tool at C:/Users/someone/bin/tool.exe is your own install: it is used as it is, never "
                          "replaced from here")
    tool.found = None
    installed_at(tool, "1.2.3", current="1.2.3")
    refused(lambda: None, "Tool 1.2.3 is installed already")
    (tool.home / "app" / "CURRENT").write_text("1.2.2", encoding="utf-8")
    installed_at(tool, "1.2.2")
    tool.busy = ["default", "gpu-0"]
    refused(lambda: None, "stop default and gpu-0 first")
    tool.busy = []
    tool._rt.starts = 1  # a start of it under way
    refused(lambda: None, "Tool is being started: it is not changed while it runs")
    tool._rt.starts = 0
    tool._rt.changing.acquire()
    try:
        refused(lambda: None, "Tool is being installed or removed already")
    finally:
        tool._rt.changing.release()
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: True)
    refused(lambda: None, f"its folder {tool.home} is on another system's drive: set LIMINAL_PLATFORM_DIR to a folder")
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: False)
    monkeypatch.setattr(liminal_libs, "__version__", "1.61.2")
    refused(lambda: None, "Tool needs liminal-libs 1.62.0 or newer, and this is 1.61.2")
    assert not tool._rt.changing.locked() and tool._rt.job is None


def test_a_cancelled_install_installs_nothing_and_keeps_its_download(tool):
    installed_at(tool, "1.2.2", current="1.2.2")
    tool.cancel_after_build = True
    out = Output()
    answer = tool.install(True, log=out)
    assert answer["said"] == CANCELLED
    assert CANCELLED == "cancelled: nothing was installed (what was downloaded is kept for the next try)"
    assert answer["ok"] is False and answer["lines"] == [f"the half-built {tool.home / 'app' / '1.2.3'} was removed"]
    assert not (tool.home / "app" / "1.2.3").exists() and (tool.home / "downloads" / "tool-1.2.3.zip.part").exists()
    assert (tool.home / "app" / "CURRENT").read_text(encoding="utf-8").strip() == "1.2.2"  # what was in use stays
    assert out.text.splitlines()[-1] == CANCELLED and tool._rt.building is None


def test_a_failed_install_is_answered_in_its_words_and_the_one_in_use_kept(tool):
    installed_at(tool, "1.2.2", current="1.2.2")
    tool.fails = download.ChecksumError("tool-1.2.3.zip is not the file pinned: removed, nothing was installed")
    answer = tool.install(True, log=Output())
    assert answer == {"said": "Tool 1.2.3 was not installed: tool-1.2.3.zip is not the file pinned: removed, nothing "
                              "was installed", "ok": False,
                      "lines": [f"the half-built {tool.home / 'app' / '1.2.3'} was removed"]}
    assert tool.installed().version == "1.2.2" and not tool._rt.changing.locked()
    tool.fails = OSError("disk full")
    assert tool.install(True)["said"] == "Tool 1.2.3 was not installed: OSError: disk full"


@pytest.mark.parametrize("late, words", [
    (OSError("tool-1.2.3.zip could not be removed: it is open in another program"),
     "but a last step failed: OSError: tool-1.2.3.zip could not be removed: it is open in another program"),
    (Cancelled("cancelled at the last step"), "but it was in use before Cancel was seen")])
def test_a_failure_or_a_cancel_once_the_new_pin_is_in_use_is_said_as_installed(tmp_path, late, words):
    class After(Tool):
        def install_into(self, log, cancel):
            super().install_into(log, cancel)  # 1.2.3 built and put in use, 1.2.2 removed
            raise late

    p = made(After, tmp_path)
    installed_at(p, "1.2.2", current="1.2.2")
    out = Output()
    answer = p.install(True, log=out)
    assert answer["ok"] is True
    assert answer["said"] == f"Tool 1.2.3 (read) is installed in {p.home / 'app' / '1.2.3'}, {words}"
    assert answer["lines"] == ["nothing was started"] and out.text.splitlines()[-1] == answer["said"]
    assert p.current().name == "1.2.3" and not (p.home / "app" / "1.2.2").exists()


def test_an_install_not_put_in_use_is_said_and_its_folder_removed(tool):
    tool.adopts = False
    answer = tool.install(True)
    assert answer["ok"] is False and answer["said"].startswith("Tool 1.2.3 was not put in use")
    assert not (tool.home / "app" / "1.2.3").exists()


def test_an_update_puts_the_new_pin_in_use_and_removes_the_older(tool):
    installed_at(tool, "1.2.2", current="1.2.2")
    form = form_of(tool, "ai-install")
    assert form["title"] == "Update Tool to 1.2.3" and form["confirm"]["title"] == "Update Tool 1.2.2 to 1.2.3?"
    assert form["confirm"]["yes"] == "Update" and "Update to 1.2.3…" in titles(tool)
    out = Output()
    answer = tool.install(True, log=out)
    assert answer["ok"] is True and "removed 1.2.2 (18 B)" in answer["lines"]
    assert out.text.splitlines()[0] == f"updating Tool 1.2.3 (from 1.2.2) into {tool.home}"
    assert sorted(p.name for p in (tool.home / "app").iterdir()) == ["1.2.3", "CURRENT"]


def test_an_older_pin_is_offered_as_going_back(tool):
    installed_at(tool, "1.2.4", current="1.2.4")  # the plugin was rolled back: it pins 1.2.3 again
    form = form_of(tool, "ai-install")
    assert form["title"] == "Go back to Tool 1.2.3" and form["confirm"]["yes"] == "Replace"
    assert form["confirm"]["title"] == "Replace Tool 1.2.4 with the older 1.2.3?"
    assert "Go back to 1.2.3…" in titles(tool)
    out = Output()
    assert tool.install(True, log=out)["ok"] is True
    assert out.text.splitlines()[0] == f"going back to Tool 1.2.3 (from 1.2.4) into {tool.home}"


# -- told by its pin ---------------------------------------------------------------------------------------------------
class Llama(Tool):
    """As llama.cpp's plan has it: its version said "1.0.0 (b12359)", its install's folder named by the build's pin."""

    def __init__(self, outside=None):
        super().__init__(outside)
        self.brings = Package("llama.cpp", "1.0.0 (b12359)", 600 << 20, "MIT.", ("github.com",), pin="b12359")
        self.cancel_mid = False

    def installed(self):
        folder = self.current()
        return None if folder is None else Installed("b12359", str(folder / "llama-server.exe"))

    def install_into(self, log, cancel):
        folder = self.building(self.brings.pin)
        (folder / "llama-server.exe").write_text("a stand-in program", encoding="utf-8")
        if self.cancel_mid:
            log.cancel()
        if cancel():
            raise Cancelled("cancelled at 120 MB of 600 MB")
        return self.adopt(self.brings.pin)


def test_whether_the_pinned_install_is_in_use_is_told_by_its_pin_not_its_words(tmp_path):
    p = made(Llama, tmp_path, "llamacpp")
    assert p.install(True, log=Output())["ok"] is True
    assert titles(p) == ["Read again", "Uninstall…"]  # nothing offered again
    assert "ai-install" not in {f["id"] for f in p.status()["forms"]}
    assert str(refusal(lambda: p.install(True))) == "llama.cpp 1.0.0 (b12359) is installed already"
    # another build of the same version is another pin: offered, and a cancel keeps the one in use whole
    p.brings = Package("llama.cpp", "1.0.0 (b12359, Vulkan)", 600 << 20, "MIT.", ("github.com",), pin="b12359-vulkan")
    assert "Update to 1.0.0 (b12359, Vulkan)…" in titles(p)
    p.cancel_mid = True
    answer = p.install(True, log=Output())
    assert answer["ok"] is False
    assert answer["lines"] == [f"the half-built {p.home / 'app' / 'b12359-vulkan'} was removed"]
    assert p.current().name == "b12359" and p.installed() is not None
    assert sorted(x.name for x in (p.home / "app").iterdir()) == ["CURRENT", "b12359"]


def test_a_package_names_its_pin_or_says_its_version_as_one():
    assert Package("Tool", "1.2.3", 0, "MIT.", ()).pin == "1.2.3"  # the version itself
    assert Package("llama.cpp", "1.0.0 (b12359)", 0, "MIT.", (), pin=" b12359 ").pin == "b12359"
    for version, pin in (("1.0.0 (b12359)", ""), ("1.2.3", "1.2."), ("1.2.3", "CURRENT"), ("1.2.3", "a/b"),
                         ("1.2.3", "x.part"), ("", "")):
        with pytest.raises(ValueError, match="pin"):
            Package("Tool", version, 0, "MIT.", (), pin=pin)


def test_the_install_in_use_is_never_built_again_over_itself(tmp_path, monkeypatch):
    p = made(Llama, tmp_path, "llamacpp")
    p.install(True, log=Output())
    with pytest.raises(ValueError, match="is the install in use"):
        p.building("b12359")
    assert p.current().name == "b12359" and (p.home / "app" / "b12359" / "llama-server.exe").is_file()
    monkeypatch.setattr(Llama, "installed", lambda self: None)  # its program gone: a broken install is built again
    assert list(p.building("b12359").iterdir()) == [] and p.current() is None


# -- what is checked ---------------------------------------------------------------------------------------------------
def test_the_install_says_what_is_checked_against_a_pinned_sum(tool):
    def words():
        return form_of(tool, "ai-install")["confirm"]["words"]

    assert UNCHECKED == "It is not checked against a pinned sum."
    assert f"Cancel stops it. {UNCHECKED} Its licence, first:" in words() and "sha256" not in words()
    tool.brings = Package("Tool", "1.2.3", 1000, "MIT.", ("downloads.example.test",),
                          checked="It is checked against the sha256 pinned in this plugin.")
    assert "Cancel stops it. It is checked against the sha256 pinned in this plugin. Its licence" in words()
    tool.brings = Package("Aider", "0.86.2", 0, "Apache-2.0.", ("pypi.org", "files.pythonhosted.org"),
                          parts="uv, a CPython of uv's and aider-chat 0.86.2 with the 108 packages it pins",
                          checked="uv's archive is checked against its pinned sha256; the 108 packages uv resolves "
                                  "from  PyPI are not checked against a pinned sum")
    assert ("uv's archive is checked against its pinned sha256; the 108 packages uv resolves from PyPI are not checked "
            "against a pinned sum. Its licence, first: Apache-2.0.") in words()  # its words on one line, ended


# -- a start and an install exclude each other -------------------------------------------------------------------------
def test_a_start_is_refused_while_an_install_runs_and_holds_one_off_while_it_runs(tmp_path):
    entered, go = threading.Event(), threading.Event()

    class Slow(Starts):
        def install_into(self, log, cancel):
            entered.set()
            assert go.wait(5)
            return super().install_into(log, cancel)

    p = made(Slow, tmp_path)
    installed_at(p, "1.2.2", current="1.2.2")
    assert p.changing_words() == ""
    worker = threading.Thread(target=lambda: p.install(True, log=Output()))
    worker.start()
    try:
        assert entered.wait(5)
        assert p.changing_words() == BEING_CHANGED
        assert str(refusal(lambda: p.start("default"))) == BEING_CHANGED
        assert str(refusal(lambda: p.ask("open", "C:/work"))) == BEING_CHANGED  # as the page asks it
        assert p.started == [] and p._rt.starts == 0
    finally:
        go.set()
        worker.join(5)
    assert not worker.is_alive() and p.current().name == "1.2.3" and p.changing_words() == ""
    # a start under way holds an install and an uninstall off; another start may run beside it
    p.brings = Package("Tool", "1.2.4", 1000, "MIT.", ("downloads.example.test",))
    starter = threading.Thread(target=lambda: p.start("held"))
    starter.start()
    try:
        assert p.under_way.wait(5) and p._rt.starts == 1
        assert str(refusal(lambda: p.install(True))) == "Tool is being started: it is not changed while it runs"
        assert str(refusal(lambda: p.uninstall(True))) == "Tool is being started: it is not removed while it runs"
        assert p.start("beside")["ok"] is True
    finally:
        p.go.set()
        starter.join(5)
    assert not starter.is_alive() and p.started == ["beside", "held"] and p._rt.starts == 0
    with pytest.raises(RuntimeError):
        p.start("fails")
    assert p._rt.starts == 0 and not p._rt.changing.locked()  # a start that failed holds nothing off


def test_a_hook_that_starts_keeps_its_signature_and_its_words(tmp_path):
    p = made(Starts, tmp_path)
    assert p.interface()["hooks"]["start"] == "(name)" and p.interface()["hooks"]["open"] == "(folder=None)"
    assert Starts.start.held and Starts.start.__doc__ == "A stand-in start: noted." and Starts.start.__name__ == "start"

    class Again(Starts):  # its own start, over its base's: held too, and the two nest
        def start(self, name):
            assert self._rt.starts == 1
            return super().start(name)

    q = made(Again, tmp_path, "again")
    assert q.start("default")["ok"] is True and q._rt.starts == 0 and Again.start.held

    class Helper(Tool):  # an `open` that is no hook of its own is left as it is
        def open(self, path):
            return path

    assert not getattr(Helper.open, "held", False) and made(Helper, tmp_path, "helper").open("x") == "x"


def test_a_model_servers_start_is_refused_while_its_update_runs(world):  # noqa: F811 - test_modelserver's fixture
    entered, go = threading.Event(), threading.Event()

    class Laid(StandInServer):
        """The model-server stand-in on the base's own layout, its update held mid-way."""

        def installed(self):
            return AiPlugin.installed(self)

        def package(self):
            return Package("Tool", "1.2.3", 1000, "MIT.", ("downloads.example.test",))

        def install_into(self, log, cancel):
            folder = self.building("1.2.3")
            (folder / "tool.exe").write_text("new", encoding="utf-8")
            entered.set()  # the download and the unpacking take minutes: the user clicks Start meanwhile
            assert go.wait(5)
            return self.adopt("1.2.3")

    p = world.server(Laid)
    installed_at(p, "1.2.2", current="1.2.2")
    p.add_instance("default")
    answers = {}
    job = threading.Thread(target=lambda: answers.setdefault("install", p.install(True, log=Output())))
    job.start()
    try:
        assert entered.wait(5)
        assert str(refusal(lambda: p.start("default"))) == BEING_CHANGED
        assert world.kids.made == []  # nothing was started from the folder the update removes
    finally:
        go.set()
        job.join(5)
    assert answers["install"]["ok"] is True and not (p.home / "app" / "1.2.2").exists()
    assert p.start("default")["ok"] is True and len(world.kids.made) == 1  # from the new folder, once it is in use


# -- Uninstall ---------------------------------------------------------------------------------------------------------
def test_uninstall_is_refused_in_words_and_asked_twice(tool, monkeypatch):
    assert "there is nothing to remove" in str(refusal(lambda: tool.uninstall(True)))
    tool.found = Installed("0.9", "/usr/bin/tool", "found")
    assert "Tool at /usr/bin/tool is your own install: it is never removed from here" in str(
        refusal(lambda: tool.uninstall(True)))
    tool.found = None
    installed_at(tool, "1.2.3", current="1.2.3")
    tool.busy = ["default"]
    assert "stop default first" in str(refusal(lambda: tool.uninstall(True)))
    tool.busy, tool.boot = [], ["default", "night"]
    assert "turn At boot off for default and night first" in str(refusal(lambda: tool.uninstall(True)))
    tool.boot = []
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: True)
    assert "is on another system's drive" in str(refusal(lambda: tool.uninstall(True)))
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: False)
    for given in (False, "yes", 1):
        e = refusal(lambda: tool.uninstall(given))
        assert e.accept == ACCEPT_REMOVAL == "accept_removal" and (tool.home / "app" / "1.2.3").is_dir()
    answer = tool.ask("uninstall", True)
    assert answer["ok"] is True and answer["said"] == f"Tool 1.2.3 removed from {tool.home}"
    assert tool.installed() is None and not (tool.home / "app").exists()
    assert not tool._rt.changing.locked()


def test_an_uninstall_that_leaves_the_install_is_said(tool, monkeypatch):
    installed_at(tool, "1.2.3", current="1.2.3")
    monkeypatch.setattr(Tool, "remove_from", lambda self: ["nothing could be removed"])
    answer = tool.uninstall(True)
    assert answer["ok"] is False and "is still there" in answer["said"]
    monkeypatch.setattr(Tool, "remove_from", lambda self: (_ for _ in ()).throw(OSError("in use")))
    assert tool.uninstall(True) == {"said": "Tool 1.2.3 was not removed whole: OSError: in use", "ok": False,
                                    "lines": []}


# -- a download, and what a cancel kept ------------------------------------------------------------------------------
class Fetches(Tool):
    """A stand-in whose install fetches one pinned file into its downloads/ (AiPlugin.fetch), then puts it in use."""

    source: download.Source

    def install_into(self, log, cancel):
        archive = self.fetch(self.source, log=log)
        folder = self.building("1.2.3")
        (folder / "tool.exe").write_bytes(archive.read_bytes()[:16])
        return self.adopt("1.2.3")


@pytest.mark.parametrize("pinned", [True, False])
def test_fetch_downloads_into_its_folder_and_a_cancel_says_what_it_kept(tmp_path, pinned):
    data = bytes(range(256)) * 20
    address = HTTPS + "downloads.example.test/tool-1.2.3.zip"
    sha = hashlib.sha256(data).hexdigest() if pinned else ""
    out = Output()
    p = made(Fetches, tmp_path)
    p.source = download.Source(address, "tool-1.2.3.zip", len(data), sha, ("downloads.example.test",))
    p.out.opener = web_of(address, data, then=out.cancel)  # Cancel, clicked as it downloads
    answer = p.install(True, log=out)
    left = sorted(x.name for x in (p.home / "downloads").iterdir())
    assert answer["ok"] is False and p.installed() is None
    if pinned:  # its part is gone on from next time: kept, and said so
        assert answer["said"] == CANCELLED and left == ["tool-1.2.3.zip.part"]
    else:  # nothing could tell the rest of the same file from another's: nothing is kept, and that is said
        assert answer["said"] == CANCELLED_AFRESH and left == []
        assert CANCELLED_AFRESH == ("cancelled: nothing was installed (nothing was kept: the next try downloads it "
                                    "again)")
    assert out.text.splitlines()[-1] == answer["said"]
    p.out.opener = web_of(address, data)  # whole this time: into its downloads/ by default, then put in use
    again = p.install(True, log=Output())
    assert again["ok"] is True and (p.home / "downloads" / "tool-1.2.3.zip").read_bytes() == data
    assert (p.home / "app" / "1.2.3" / "tool.exe").read_bytes() == data[:16]


def test_what_a_cancel_kept_is_forgotten_from_the_page_and_an_uninstall_removes_downloads(tmp_path):
    data = b"y" * 5000
    address = HTTPS + "downloads.example.test/tool-1.2.3.zip"
    out = Output()
    p = made(Fetches, tmp_path)
    p.source = download.Source(address, "tool-1.2.3.zip", len(data), hashlib.sha256(data).hexdigest(),
                               ("downloads.example.test",))
    p.out.opener = web_of(address, data, then=out.cancel)
    assert p.install(True, log=out)["said"] == CANCELLED
    downloads = p.home / "downloads"
    assert "Forget the download…" in titles(p)  # nothing installed, yet a part is kept: it can be taken back
    form = form_of(p, "ai-forget-download")
    assert form["hook"] == "uninstall" and form["fields"] == [] and form["confirm"]["danger"] is True
    assert form["confirm"]["title"] == "Forget what was downloaded for Tool?" and form["confirm"]["yes"] == "Forget"
    assert form["confirm"]["words"] == (f"tool-1.2.3.zip.part (2.0 KB), kept in {downloads} for the next try, is "
                                        "deleted. Nothing of Tool is installed, and nothing else is changed: an "
                                        "install downloads it again from the start.")
    # should an install come while its dialog is open, the form's ask (no field: no accept_removal) removes nothing
    installed_at(p, "1.2.3", current="1.2.3")
    e = refusal(lambda: p.ask("uninstall"))
    assert e.accept == ACCEPT_REMOVAL and not any(x["name"] == e.accept for x in form["fields"])
    assert (p.home / "app" / "1.2.3").is_dir() and (downloads / "tool-1.2.3.zip.part").is_file()
    p.forget_install()
    answer = p.ask("uninstall")  # as the page asks it: its one confirmation given
    assert answer["ok"] is True and answer["said"] == f"what was downloaded for Tool is removed from {downloads}"
    assert answer["lines"] == ["removed downloads (2.0 KB)"] and not downloads.exists()
    assert "Forget the download…" not in titles(p) and "nothing to remove" in str(refusal(lambda: p.uninstall(True)))
    # installed, an uninstall removes what was downloaded for it with the install (the base's remove_from)
    p.out.opener = web_of(address, data)
    assert p.install(True, log=Output())["ok"] is True and (downloads / "tool-1.2.3.zip").is_file()
    assert "Forget the download…" not in titles(p)  # installed: its Uninstall… takes it all
    words = form_of(p, "ai-uninstall")["fields"][0]["words"]
    assert words.startswith(f"Its files are deleted from {p.home / 'app'}, and what was downloaded for it from "
                            f"{downloads}:")
    gone = p.uninstall(True)
    assert gone["ok"] is True and "removed downloads (4.9 KB)" in gone["lines"]
    assert not downloads.exists() and not (p.home / "app").exists()


# -- turned off while it installs; asked without a job ---------------------------------------------------------------
@pytest.mark.parametrize("job", [True, False])
def test_turning_it_off_cancels_its_install(tmp_path, job):
    entered, go = threading.Event(), threading.Event()
    seen = {}

    class Slow(Tool):
        def install_into(self, log, cancel):
            entered.set()
            assert go.wait(5)
            seen["cancelled"] = cancel()
            return super().install_into(log, cancel)

    p = made(Slow, tmp_path)
    p.attach(object(), Pairs())
    out = Output() if job else None
    answers = {}
    worker = threading.Thread(target=lambda: answers.setdefault("a", p.install(True, log=out)))
    worker.start()
    try:
        assert entered.wait(5)
        p.detach()  # the switch on its page: turned off
    finally:
        go.set()
        worker.join(5)
    assert seen["cancelled"] is True and answers["a"]["ok"] is False and answers["a"]["said"] == CANCELLED
    assert (out.cancelled if job else True) and p.installed() is None and p._rt.job is None


def test_install_asked_without_a_job_gives_install_into_a_panel_all_the_same(tmp_path):
    class Logs(Tool):
        def install_into(self, log, cancel):
            log("downloading")  # as its docstring has it: callable, whoever asked
            assert log.cancelled is False and cancel() is False and log.wait_cancelled(0) is False
            return super().install_into(log, cancel)

    p = made(Logs, tmp_path)
    answer = p.ask("install", True)  # the platform's plain ask, or another plugin: no job's panel
    assert answer["ok"] is True and answer["said"].startswith("Tool 1.2.3 (read) installed in ")
    lines: list[str] = []
    q = made(Logs, tmp_path, "lines")
    assert q.install(True, log=lines.append)["ok"] is True  # a plain callable: its lines still said to it
    assert lines[0] == f"installing Tool 1.2.3 into {q.home}" and "downloading" in lines


# -- the one layout ----------------------------------------------------------------------------------------------------
def test_the_layouts_four_helpers_on_a_temporary_folder(tool, monkeypatch):
    app = tool.home / "app"
    assert tool.current() is None
    app.mkdir(parents=True)
    for written in ("1.2.3", "../outside", "CURRENT", "", "1.2."):
        (app / "CURRENT").write_text(written, encoding="utf-8")
        assert tool.current() is None  # nothing there, or nothing that names a folder of its own
    folder = tool.building("1.2.3")
    assert folder == app / "1.2.3" and folder.is_dir() and list(folder.iterdir()) == []
    (folder / "half.bin").write_bytes(b"half")
    assert list(tool.building("1.2.3").iterdir()) == []  # what a try left there is removed first
    installed_at(tool, "1.2.1", "1.2.2")
    (app / "stray.txt").write_text("x", encoding="utf-8")
    real = download.remove_tree

    def stuck(path, inside):
        if Path(path).name == "1.2.1":
            raise OSError("a program runs from it")
        return real(path, inside)

    monkeypatch.setattr(download, "remove_tree", stuck)
    lines = tool.adopt("1.2.3")
    assert tool.current() == app / "1.2.3" and (app / "CURRENT").read_text(encoding="utf-8") == "1.2.3\n"
    assert lines[0] == f"in use now: {app / '1.2.3'}"
    assert "removed 1.2.2 (18 B)" in lines and "removed stray.txt (1 B)" in lines
    assert any(x.startswith(f"{app / '1.2.1'} could not be removed (a program runs from it)") for x in lines)
    assert (app / "1.2.1").is_dir()  # left for the next install or uninstall
    with pytest.raises(ValueError, match="is the install in use"):
        tool.building("1.2.3")  # the one in use, whole: never built again over itself
    found = Tool.installed
    monkeypatch.setattr(Tool, "installed", lambda self: None)  # its program gone: a broken install is built again
    assert tool.building("1.2.3") == app / "1.2.3" and tool.current() is None  # rebuilt: nothing in use until adopt
    monkeypatch.setattr(Tool, "installed", found)
    monkeypatch.setattr(download, "remove_tree", real)
    tool.adopt("1.2.3")
    gone = tool.forget_install()
    assert gone[0] == f"{app / 'CURRENT'} removed: nothing of Tool is in use" and not app.exists()
    assert tool.forget_install() == [f"nothing was installed in {app}"]
    for pin in ("", "..", "a/b", "a\\b", "CURRENT", "1.2.3.part", "-x", "x" * 81, "1.2.", "a."):
        with pytest.raises(ValueError):
            tool.building(pin)
    with pytest.raises(ValueError):
        tool.adopt("9.9.9")  # not there: nothing is put in use


@pytest.mark.skipif(os.name != "nt", reason="only Windows takes two names that differ in case for one folder")
def test_adopt_keeps_the_folder_it_puts_in_use_in_whatever_case_windows_has_it(tool):
    (tool.home / "app" / "B12359").mkdir(parents=True)
    (tool.home / "app" / "B12359" / "tool.exe").write_text("x", encoding="utf-8")
    lines = tool.adopt("b12359")
    assert (tool.home / "app" / "B12359").is_dir() and tool.current() is not None, lines


def test_the_layout_refuses_a_folder_on_another_systems_drive(tool, monkeypatch):
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: True)
    with pytest.raises(mounts.NotHere):
        tool.building("1.2.3")


# -- what reaches a child ----------------------------------------------------------------------------------------------
def test_dropped_names_every_declared_variable_and_liminals_own(tool, monkeypatch):
    assert tool.dropped() == (*DECLARED, "LIMINAL_*")
    tool.out.variables = lambda: (_ for _ in ()).throw(RuntimeError("no registry here"))
    assert tool.dropped() == ("LIMINAL_*",)
    tool.out.variables = None
    monkeypatch.setattr(registry, "variables", lambda: ("GROK_API_KEY", "LIMINAL_X"))
    assert tool.dropped() == ("GROK_API_KEY", "LIMINAL_X", "LIMINAL_*")  # the registry's, asked when needed


def test_no_pair_of_liminals_reaches_a_child(tool, monkeypatch):
    env = tool.child_env({"TOOL_HOME": "/x"})
    assert env == {"PATH": "/usr/bin", "HOME": "/home/someone", "TOOL_HOME": "/x"}
    launch = tool.dropping(children.Launch(("tool", "serve"), env={"A": "1"}, drop=("TOOL_*",)))
    assert launch.drop == ("TOOL_*", *DECLARED, "LIMINAL_*") and launch.argv == ("tool", "serve")
    streamed = []

    def streamer(argv, line, *, env, cwd, timeout, cancel):
        streamed.append({"argv": argv, "env": env, "cwd": cwd, "timeout": timeout, "cancelled": cancel()})
        line("Installed 3 packages")
        return 0

    tool.out.streamer = streamer
    out = Output()
    assert tool.stream(["uv", "pip", "install", "tool==1.2.3"], out, env={"UV_NO_PROGRESS": "1"}, timeout=60) == 0
    assert streamed[0]["env"] == {"PATH": "/usr/bin", "HOME": "/home/someone", "UV_NO_PROGRESS": "1"}
    assert streamed[0]["cancelled"] is False and out.text == "Installed 3 packages\n"
    out.cancel()
    tool.stream(["uv", "venv"], out)
    assert streamed[1]["cancelled"] is True  # the job's Cancel, looked at by the command's watcher
    unpacked = []
    monkeypatch.setattr(download, "unpack", lambda archive, into, **kw: unpacked.append(kw) or 3)
    assert tool.unpack(tool.home / "downloads" / "tool.tar.zst", tool.home / "app" / "1.2.3", strip=1) == 3
    assert unpacked[0]["env"] == {"PATH": "/usr/bin", "HOME": "/home/someone"} and unpacked[0]["strip"] == 1
    ran = popen_of(b"tool 1.2.3\n")
    monkeypatch.setattr(ai.subprocess, "Popen", ran)
    assert tool.short(["tool", "--version"]) == (0, "tool 1.2.3\n", "")
    given = ran.made[0].kw
    assert given["env"] == {"PATH": "/usr/bin", "HOME": "/home/someone"} and ran.made[0].waited[0] == 10.0
    assert given["stdin"] == subprocess.DEVNULL and given["stdout"] == given["stderr"] == subprocess.PIPE
    assert given.get("creationflags", 0) == (children.NO_WINDOW if os.name == "nt" else 0)  # windowless
    tool.out.runner = lambda argv, timeout: (0, f"{argv[0]} {timeout:g}", "")
    assert tool.short(["tool", "-v"], 3) == (0, "tool 3", "")


def test_a_short_command_keeps_a_bounded_part_of_what_it_writes(tool, monkeypatch):
    ran = popen_of(b"x" * (5 << 20), b"e" * (1 << 20), code=3)  # far more than a version's read ever needs
    monkeypatch.setattr(ai.subprocess, "Popen", ran)
    code, out, err = tool.short(["tool", "--version"])
    assert code == 3 and out == "x" * ai.SHORT_KEPT and err == "e" * ai.SHORT_KEPT and ai.SHORT_KEPT == 64 << 10
    hangs = popen_of(b"tool 1.2.3\n", hangs=True)
    monkeypatch.setattr(ai.subprocess, "Popen", hangs)
    with pytest.raises(children.ChildError, match="took more than 3 s"):
        tool.short(["tool", "--version"], 3)
    assert hangs.made[0].killed is True  # ended, not left running
    monkeypatch.setattr(ai.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(OSError("no such program")))
    with pytest.raises(children.ChildError, match="could not run: no such program"):
        tool.short(["tool", "--version"])


def test_a_streamed_command_on_its_own_is_childrens_with_this_systems_flags(tool, monkeypatch):
    seen = {}
    monkeypatch.setattr(children, "stream", lambda argv, line, **kw: seen.update(kw) or 0)
    tool.stream(["npm", "ci"], None)
    assert seen["system"] == "windows" and seen["popen"] is None and "MASSIVE_API_KEY" not in seen["env"]


# -- the login's pairs -------------------------------------------------------------------------------------------------
def test_its_pairs_are_named_under_liminal_ai_and_kept_through_its_login(tool):
    assert tool.variable("instances") == instances.variable_of("liminal-ai-tool") == "LIMINAL_AI_TOOL_INSTANCES"
    assert tool.variable("use") == "LIMINAL_AI_TOOL_USE"
    assert tool.variable("default-key") == "LIMINAL_AI_TOOL_DEFAULT_KEY"
    for bad in ("", "a b", "x;y", "-x"):
        with pytest.raises(ValueError):
            tool.variable(bad)
    assert tool.keep_pair(tool.variable("use"), '{"v": 1}') == "the test's pairs"
    assert tool.pair(tool.variable("use")) == '{"v": 1}' and tool.pair("LIMINAL_AI_TOOL_NONE") == ""
    tool.keep_pair(tool.variable("use"), None)
    assert tool.pair(tool.variable("use")) == ""
    with pytest.raises(instances.Refusal):
        tool.keep_pair(tool.variable("use"), "x" * (instances.MAX_KEPT + 1))


def test_a_login_that_keeps_nothing_is_a_refusal_in_words(tool):
    class Keeps(Pairs):
        def save(self, variable, value):
            raise Unauthorized(f"{variable} could not be kept: {value} was refused", 500)

    tool.login = Keeps()
    e = refusal(lambda: tool.keep_pair(tool.variable("default-key"), KEY))
    assert KEY not in str(e) and "LIMINAL_AI_TOOL_DEFAULT_KEY is not kept" in str(e)


def test_lasting_on_both_systems(tool):
    windows, linux = Outside(env={}, system="windows"), Outside(env={}, system="linux")
    users = EnvironmentLogin(saved=lambda: {})  # the platform's: the process's variables over the user's saved ones
    for out, login, said in ((windows, users, ""), (linux, users, LASTING), (windows, Pairs(), ""),
                             (linux, Pairs(), ""), (windows, EnvironmentLogin(env={}), LASTING),
                             (linux, RecordingLogin(users, "tool", Traffic()), LASTING),
                             (windows, RecordingLogin(users, "tool", Traffic()), "")):
        tool.out, tool.login = out, login
        assert tool.lasting() == said, (out.system, login)
    tool.login = None
    assert tool.lasting() == LASTING  # no login lent: the given environment's own, which lasts nowhere
    assert lasts(None, "windows") is False
    assert LASTING == ("On this system the Login keeps a pair only until the platform restarts: what is added here "
                       "is gone after a restart.")


def test_whether_a_pair_lasts_asks_the_login_app_nothing():
    asked = []

    class App(Pairs):  # a login app's client: describe() would ask it over http
        def describe(self):
            asked.append("describe")
            raise AssertionError("a status asked the login app")

    assert lasts(RecordingLogin(App(), "tool", Traffic()), "linux") is True and asked == []

    class Says:  # no Login at all: what it says it is decides
        def __init__(self, kind):
            self.kind = kind

        def describe(self):
            return {"kind": self.kind}

    assert lasts(Says("EnvironmentLogin"), "linux") is False and lasts(Says("EnvironmentLogin"), "windows") is True
    assert lasts(Says("LoginClient"), "linux") is True


def test_lasting_is_said_on_main(tool):
    tool.out.system, tool.login = "linux", EnvironmentLogin(saved=lambda: {})
    assert tool.status()["kept"] == LASTING
    tool.out.system = "windows"
    assert "kept" not in tool.status()


# -- the library's floor -----------------------------------------------------------------------------------------------
@pytest.mark.parametrize("version, old", [("1.61.2", True), ("1.62.0", False), ("1.62", False), ("1.62.1", False),
                                          ("2.0", False), ("1.9.9", True), ("", True)])
def test_too_old_with_a_stand_in_version(tool, monkeypatch, version, old):
    monkeypatch.setattr(liminal_libs, "__version__", version)
    words = tool.too_old()
    assert bool(words) is old and tool.present() is not old
    status = tool.status()
    assert status["valid"] is not old and status["present"] is not old
    if old:
        assert words.startswith("Tool needs liminal-libs 1.62.0 or newer, and this is ") and status["why"] == words
        assert status["forms"] == [] and status["actions"] == []
        for hook, args in (("install", (True,)), ("uninstall", (True,)), ("refresh", ())):
            assert str(refusal(lambda: tool.ask(hook, *args))) == words
    tool.LIBS_FLOOR = ""
    assert tool.too_old() == ""


def test_a_subclasses_own_hooks_refuse_with_a_library_too_old(tmp_path, monkeypatch):
    class Puller(Tool):
        HOOKS = (*Tool.HOOKS, "pull")

        def pull(self, model, log=None):
            return {"said": f"{model} pulled", "ok": True}

    p = Puller(Outside(env={}, home=tmp_path, variables=lambda: ()))
    hold_login(p)  # asked as an attached plugin is: holding a login (1.86.0)
    assert p.ask("pull", "qwen3:8b")["ok"] is True
    monkeypatch.setattr(liminal_libs, "__version__", "1.61.2")
    assert "Tool needs liminal-libs 1.62.0 or newer" in str(refusal(lambda: p.ask("pull", "qwen3:8b")))
    assert p.ask("status")["valid"] is False and p.ask("present") is False  # still read: the page says why


# -- a folder on another system's drive --------------------------------------------------------------------------------
def test_a_folder_on_another_systems_drive_is_said_and_refused(tool, monkeypatch):
    asked = []
    monkeypatch.setattr(mounts, "foreign", lambda path, *a, **k: asked.append(Path(path)) or True)
    words = (f"its folder {tool.home} is on another system's drive: set LIMINAL_PLATFORM_DIR to a folder on this "
             "system's own disk")
    status = tool.status()
    assert status["valid"] is True and status["problem"] == words and asked[0] == tool.home
    button = next(a for a in status["actions"] if a.get("form") == "ai-install")
    assert button["disabled"] is True and button["note"] == words
    assert str(refusal(lambda: tool.install(True))) == words


# -- a status that never raises ----------------------------------------------------------------------------------------
def test_a_status_whose_parts_raise_is_valid_with_a_problem(tool, monkeypatch):
    monkeypatch.setattr(Tool, "installed", lambda self: (_ for _ in ()).throw(OSError("a pidfile half written")))
    status = tool.status()
    assert status["valid"] is True and status["present"] is True
    assert status["problem"] == "part of Tool's state could not be read: OSError: a pidfile half written"
    assert status["summary"] == "Tool: its state could not be read whole"
    assert status["actions"][0]["hook"] == "refresh"  # Read again is still offered


def test_a_subclasses_own_status_is_held_to_it_too(tmp_path):
    class Server(Tool):
        def status(self):
            out = self.base_status()
            out["tables"].append({"title": "Instances", "rows": self.rows()})
            return out

        def rows(self):
            raise KeyError("default")

    class Wrong(Tool):
        def status(self):
            return ["not", "a", "dict"]

    server = Server(Outside(env={}, home=tmp_path / "s", variables=lambda: ()))
    status = server.status()
    assert status["valid"] is True
    assert "part of Tool's state could not be read: KeyError: 'default'" in status["problem"]
    assert any(f["id"] == "ai-install" for f in status["forms"])  # the base's part still drawn
    wrong = Wrong(Outside(env={}, home=tmp_path / "w", variables=lambda: ()))
    assert "its status is list, not a dict" in wrong.status()["problem"]
    assert Server.status.steady and Server.status.__wrapped__.__name__ == "status"


def test_a_status_that_cannot_say_anything_still_answers(tool, monkeypatch):
    monkeypatch.setattr(Tool, "base_status", lambda self: (_ for _ in ()).throw(RuntimeError("everything failed")))
    status = tool.status()
    assert status["valid"] is True and "RuntimeError: everything failed" in status["problem"]
    assert status["actions"][0]["hook"] == "refresh"


def test_what_is_not_an_exception_is_not_swallowed(tool, monkeypatch):
    class Stop(BaseException):
        pass

    monkeypatch.setattr(Tool, "installed", lambda self: (_ for _ in ()).throw(Stop()))
    with pytest.raises(Stop):  # the guard's own (conftest.Reached) gets through: a reach for real fails its test
        tool.status()


# -- Main ------------------------------------------------------------------------------------------------------------
def test_main_says_the_install_and_offers_its_form(tool):
    status = tool.status()
    assert {k: status[k] for k in ("present", "valid", "why", "summary", "system", "folder")} == {
        "present": True, "valid": True, "why": "", "summary": "not installed", "system": "Windows",
        "folder": str(tool.home)}
    assert status["installed"] == "not installed: Install… brings Tool 1.2.3 (about 50.0 MB)"
    form = next(f for f in status["forms"] if f["id"] == "ai-install")
    assert form["hook"] == "install" and form["job"] is True and form["title"] == "Install Tool 1.2.3"
    assert form["fields"] == [{"name": ACCEPT_LICENCE, "type": "accept", "title": "Accept Tool's licence?",
                               "yes": "Accept and install",
                               "words": "MIT (its maker's). Accepted, Tool 1.2.3 is installed now."}]
    words = form["confirm"]["words"]
    assert form["confirm"]["title"] == "Install Tool 1.2.3?" and words.startswith(
        "Tool's standalone archive tool-1.2.3.zip is downloaded from downloads.example.test and cdn.example.test "
        f"(about 50.0 MB) and unpacked into {tool.home}, for you alone: no administrator is asked.")
    assert "Cancel stops it. It is not checked against a pinned sum." in words
    assert words.endswith("Its licence, first: MIT (its maker's). You are asked to accept it next.")
    assert [a.get("hook") or a.get("form") for a in status["actions"]] == ["refresh", "ai-install"]
    assert "ai-uninstall" not in {f["id"] for f in status["forms"]} and "kept" not in status


def test_main_without_a_size_or_a_package(tool):
    tool.brings = Package("Tool", "1.2.3", 0, "MIT.", ())
    words = next(f for f in tool.status()["forms"] if f["id"] == "ai-install")["confirm"]["words"]
    assert words.startswith("Tool 1.2.3 is downloaded from its maker's servers (its size is not known until it is "
                            "downloaded)")
    tool.brings = None
    status = tool.status()
    assert status["forms"] == [] and status["installed"] == ("not installed, and nothing is installed from here on "
                                                             "this system")
    tool.brings, tool.here = PACKAGE, "Tool runs on Linux only"
    status = tool.status()
    assert status["summary"] == "not installed: Tool runs on Linux only"
    button = next(a for a in status["actions"] if a.get("form") == "ai-install")
    assert button == {"form": "ai-install", "title": "Install…", "disabled": True, "note": "Tool runs on Linux only"}


def test_main_with_this_plugins_install_offers_uninstall_asked_twice(tool):
    installed_at(tool, "1.2.3", current="1.2.3")
    status = tool.status()
    assert status["summary"] == "Tool 1.2.3" and "ai-install" not in {f["id"] for f in status["forms"]}
    form = next(f for f in status["forms"] if f["id"] == "ai-uninstall")
    assert form["confirm"]["danger"] is True and form["confirm"]["title"] == "Uninstall Tool?"
    assert form["confirm"]["words"] == (f"Tool 1.2.3 is removed from {tool.home}. Its models and your instances stay. "
                                        "You are asked a second time.")
    assert form["fields"][0]["name"] == ACCEPT_REMOVAL and form["fields"][0]["type"] == "accept"
    tool.boot = ["default"]
    button = next(a for a in tool.status()["actions"] if a.get("form") == "ai-uninstall")
    assert button["disabled"] is True and button["note"] == "turn At boot off for default first"


def test_a_found_install_shows_its_note_and_its_version_only_once_read(tool):
    note = "it came with its maker's desktop app, which starts its own server when you sign in"
    tool.found = Installed("", "C:/Users/someone/AppData/Local/Programs/Tool/tool.exe", "found", note)
    status = tool.status()
    assert status["installed"] == ("version not read yet at C:/Users/someone/AppData/Local/Programs/Tool/tool.exe: "
                                   f"your own install, used as it is and never replaced from here · {note}")
    assert tool.reads == 0  # nothing is run for a status
    button = next(a for a in status["actions"] if a.get("form") == "ai-install")
    assert button["disabled"] is True and "is used as it is, never replaced from here" in button["note"]
    answer = tool.refresh()
    assert answer["ok"] is True and tool.reads == 1 and answer["said"].startswith("read again: Tool 1.2.3 (read) at ")
    assert tool.status()["installed"].startswith("1.2.3 (read) at ") and tool.reads == 1  # kept until the next refresh
    tool.version_said = OSError("it would not start")
    assert tool.refresh()["lines"] == ["its version could not be read: OSError: it would not start"]
    assert tool.status()["installed"].startswith("version not read yet at ")


def test_main_says_this_system(tool):
    tool.out.system, tool.out.wsl = "linux", "Ubuntu"
    assert tool.status()["system"] == "Linux, inside WSL (Ubuntu)"
    tool.out.wsl = ""
    assert tool.status()["system"] == "Linux" and tool.system == "linux" and tool.wsl == ""


def test_its_folder_is_the_platforms_by_its_rule(tmp_path, monkeypatch):
    p = Tool(Outside(env={"LIMINAL_PLATFORM_DIR": str(tmp_path / "platform")}))
    assert p.home == tmp_path / "platform" / "ai" / "tool"
    monkeypatch.setenv("LIMINAL_PLATFORM_DIR", str(tmp_path / "elsewhere"))
    assert Tool(Outside(env={})).home == tmp_path / "elsewhere" / "ai" / "tool"  # this process's, as the platform's


def test_its_folder_is_worked_out_once_while_its_variables_stay(tmp_path, monkeypatch):
    """The data folder's rule looks at the workspace's folders: asked once, not at every look at its folder."""
    monkeypatch.delenv("LIMINAL_PLATFORM_DIR", raising=False)
    asked = []
    monkeypatch.setattr(ai.layout, "data_dir", lambda: asked.append(1) or tmp_path / "data")
    p = Tool(Outside(env={}))
    assert p.home == p.home == tmp_path / "data" / "platform" / "ai" / "tool" and len(asked) == 1
    assert p.with_().home == p.home and len(asked) == 1  # (the registry's copies share it)
    monkeypatch.setenv("LIMINAL_PLATFORM_DIR", str(tmp_path / "elsewhere"))  # a variable changed: followed
    assert p.home == tmp_path / "elsewhere" / "ai" / "tool"
    monkeypatch.delenv("LIMINAL_PLATFORM_DIR")
    monkeypatch.setenv("LIMINAL_HOME", str(tmp_path / "workspace"))
    assert p.home == tmp_path / "data" / "platform" / "ai" / "tool" and len(asked) == 2


def test_the_other_plugins_are_asked_through_the_app_in_its_order(tool):
    """Every other plugin that lists the hook, asked in the platform's form (the arguments as one list), a refusal
    kept with its name; none without an app (machines/modelserver.py's conflicts ask `serving` so)."""
    class Platform:
        def __init__(self):
            self.asked: list = []

        def plugins(self):
            return {"tool": {"hooks": ["serving"]}, "a": {"hooks": ["serving"]}, "b": {"hooks": ["status"]},
                    "c": {"hooks": ["serving"]}, "d": None}

        def ask(self, name, hook, args):
            self.asked.append((name, hook, args))
            if name == "c":
                raise LookupError("c refuses")
            return {"from": name}

    assert tool.app is None and tool._ask_others("serving") == []
    tool.app = Platform()
    said = tool._ask_others("serving", 1)
    assert [(name, answer) for name, answer, _ in said] == [("a", {"from": "a"}), ("c", None)]
    assert said[0][2] is None and str(said[1][2]) == "c refuses"
    assert tool.app.asked == [("a", "serving", [1]), ("c", "serving", [1])]


# -- no key in any answer ----------------------------------------------------------------------------------------------
def test_no_key_and_no_secret_in_any_answer(tool, monkeypatch):
    login, panels = tool.login, [Output(), Output(), Output()]
    variable = tool.variable("default-key")
    tool.keep_pair(variable, KEY)
    assert tool.pair(variable) == KEY and ("LIMINAL_AI_TOOL_DEFAULT_KEY", True) in login.saved
    answers = [tool.status(), tool.refresh()]
    tool.fails = OSError(f"the server refused the key {KEY}")
    answers.append(tool.install(True, log=panels[0]))
    assert "the server refused the key <hidden>" in answers[-1]["said"]
    tool.fails, tool.version_said = None, ValueError(f"tool printed {KEY}")
    answers.append(tool.install(True, log=panels[1]))
    assert "its version could not be read: tool printed <hidden>" in panels[1].text
    answers.append(tool.refresh())
    monkeypatch.setattr(Tool, "running", lambda self: (_ for _ in ()).throw(RuntimeError(f"no answer for {KEY}")))
    answers.append(tool.status())
    assert "<hidden>" in answers[-1]["problem"]

    def streamer(argv, line, *, env, cwd, timeout, cancel):  # what a tool may print of what it was given
        line(f"401 for the token {env['HF_TOKEN']}, the key {KEY} and {env['NPM_AUTH']}")
        return 1

    tool.out.streamer = streamer
    assert tool.stream(["hf", "download", "org/model"], panels[2], env={"HF_TOKEN": TOKEN, "NPM_AUTH": "npm-auth-0123"},
                       secret=("NPM_AUTH",)) == 1
    assert panels[2].text == "401 for the token <hidden>, the key <hidden> and <hidden>\n"
    for answer in answers:
        assert KEY not in json.dumps(answer), answer
    assert all(KEY not in panel.text and TOKEN not in panel.text for panel in panels)


# -- the stop ----------------------------------------------------------------------------------------------------------
def test_detach_tells_it_first_and_bears_a_stop_that_fails(tool):
    told = []

    class Stops(Tool):
        def app_stopping(self):
            told.append(self.app is not None)
            if len(told) in (2, 4):
                raise RuntimeError("default would not end")

    p = Stops(tool.out)
    p.attach(object(), Pairs())
    p.detach()
    assert told == [True] and p.app is None and p.login is None
    p.attach(object(), Pairs())
    p.busy = ["default"]  # what would not end runs on
    p.detach()
    words = "its last stop could not end everything: RuntimeError: default would not end"
    assert p.app is None and p.status()["problem"] == words and p.status()["problem"] == words  # said while it runs
    p.busy = []  # it has ended since
    assert "problem" not in p.status()
    p.busy = ["default"]  # started again later: no stop of the plugin's failed this time
    assert "problem" not in p.status()
    p.detach()  # a third: nothing left to say
    assert "problem" not in p.status() and len(told) == 3
    p.busy = []
    p.detach()  # a fourth that fails with nothing said to run (its instances not read): said once all the same
    assert p.status()["problem"] == words and "problem" not in p.status() and len(told) == 4
    AiPlugin.app_stopping(tool)  # the base's: nothing runs, a second call too
    AiPlugin.app_stopping(tool)


def test_a_stops_trouble_is_said_by_a_status_that_falls_back_after_the_base_drew_it(tool):
    class Fails(Tool):
        breaks = True

        def app_stopping(self):
            raise RuntimeError("default would not end")

        def status(self):
            out = self.base_status()  # the base drew it once already
            if self.breaks:
                raise KeyError("its own part")
            return out

    p = Fails(tool.out)
    p.detach()
    words = "its last stop could not end everything: RuntimeError: default would not end"
    first = p.status()  # its own part failed: the fallback draws the base's part again, the trouble with it
    assert words in first["problem"] and "KeyError: 'its own part'" in first["problem"]
    p.breaks = False
    assert "problem" not in p.status()  # said once, and nothing of it runs: dropped


def test_an_install_and_an_uninstall_take_turns(tool):
    started, go = threading.Event(), threading.Event()

    class Slow(Tool):
        def install_into(self, log, cancel):
            started.set()
            go.wait(5)
            return super().install_into(log, cancel)

    p = Slow(tool.out)
    p.login = Pairs()
    installed_at(p, "1.2.2", current="1.2.2")  # an update: an uninstall would have something to remove
    worker = threading.Thread(target=lambda: p.install(True, log=Output()))
    worker.start()
    try:
        assert started.wait(5)
        under_way = "an install or an uninstall is under way"
        actions = {a.get("form"): a for a in p.status()["actions"]}
        assert actions["ai-install"] == {"form": "ai-install", "title": "Update to 1.2.3…", "disabled": True,
                                         "note": under_way}
        assert actions["ai-uninstall"] == {"form": "ai-uninstall", "title": "Uninstall…", "disabled": True,
                                           "note": under_way}
        assert "being installed or removed already" in str(refusal(lambda: p.install(True)))
        assert "being installed or removed already" in str(refusal(lambda: p.uninstall(True)))
        assert (p.home / "app" / "1.2.2").is_dir()
    finally:
        go.set()
        worker.join(5)
    assert not worker.is_alive() and p.current().name == "1.2.3"


# -- the pieces --------------------------------------------------------------------------------------------------------
def test_exactly_is_true_alone():
    assert exactly(True) and not any(exactly(v) for v in (1, "true", "True", "yes", [True], None, False))


def test_a_package_and_an_install_say_what_they_hold():
    assert Package("Tool", "1", 0, "MIT.", "one.example.test").hosts == ("one.example.test",)
    for size in (-1, 1.5, True, "3"):
        with pytest.raises(ValueError):
            Package("Tool", "1", size, "MIT.", ())
    assert Package("Tool", "1", 0, "MIT.", (), checked="  It is   checked ").checked == "It is checked."
    with pytest.raises(ValueError):
        Installed("1", "/x", "borrowed")
    assert Installed("1", Path("/x/tool")).path == str(Path("/x/tool"))  # said as words, kept as text


def test_a_setting_as_a_field_and_as_kept():
    context = Setting("context", "Context", "number", 4096, note="tokens", min=512, max=131072)
    assert context.field() == {"name": "context", "label": "Context", "type": "number", "value": 4096, "note": "tokens",
                               "min": 512, "max": 131072}
    assert context.field(8192)["value"] == 8192
    kept = [context.clean(v) for v in ("", None, "8192", 8192, 8192.0, " 1024 ")]
    assert kept == [None, None, 8192, 8192, 8192, 1024]
    for bad in ("big", 100, 1 << 20, True, 1.5):
        with pytest.raises(instances.Refusal):
            context.clean(bad)
    kind = Setting("cache", "KV cache", "choice", "f16", choices=("f16", ("q8_0", "8-bit", "half the memory")))
    assert kind.field()["choices"] == [{"value": "f16", "title": "f16", "note": ""},
                                       {"value": "q8_0", "title": "8-bit", "note": "half the memory"}]
    assert kind.clean("q8_0") == "q8_0"
    with pytest.raises(instances.Refusal):
        kind.clean("q4")
    flags = Setting("flags", "More switches")
    assert flags.field() == {"name": "flags", "label": "More switches", "type": "text",
                             "placeholder": "left empty: the tool's own default"}
    assert flags.clean("  --no-mmap ") == "--no-mmap" and flags.clean("--alias=café") == "--alias=café"
    # line breaks of every kind (Unicode's own among them), C0 and C1 controls, and format characters (a direction's
    # override shows a switch otherwise than it is)
    for bad in ("a\nb", "a\tb", "x" * 401, "--a\u2028--b", "--a\u2029--b", "--a\u0085--b", "--a\u009b--b",
                "--a\u202e--b", "--a\x1c--b"):
        with pytest.raises(instances.Refusal, match="no line break or control character"):
            flags.clean(bad)
    for wrong in (dict(name="Context", label="x"), dict(name="c", label="x", kind="list"),
                  dict(name="c", label="x", kind="choice"), dict(name="c", label="x", min=9, max=1),
                  dict(name="c", label="x", min=1.5)):
        with pytest.raises(ValueError):
            Setting(**wrong)


def test_the_module_and_its_test_name_no_host():
    written = re.compile(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]")
    for path in (Path(ai.__file__), Path(__file__)):
        found = [line for line in path.read_text(encoding="utf-8").splitlines() if written.search(line)]
        assert found == [], path.name
