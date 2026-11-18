"""The contracts' own words (liminal-libs 1.63.0): what each of the library's plugin classes says of the interface its
plugins share with the rest of the app (Plugin.READ_HOOKS, SERVICE_HOOKS, ASKS, KEEPS, INTERNAL_NOTES), held to the
hooks it has. A declared name that is not one of its hooks, a read that is a job or takes an `accept_*` argument, a
base hook with no words of its own: each would put a wrong line on every plugin's Internal API tab."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
from pathlib import Path

import pytest

import liminal_libs
from liminal_libs.assistants.plugin import AssistantPlugin
from liminal_libs.machines.admin import Admin
from liminal_libs.machines.ai import AiPlugin
from liminal_libs.machines.firewall import Firewall
from liminal_libs.machines.harness import Harness
from liminal_libs.machines.modelserver import ModelServer
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.machines.wsl import WslDistribution
from liminal_libs.sources import plugin as contract
from liminal_libs.sources.plugin import FeedPlugin, Plugin
from liminal_libs.sources.publisher import Publisher, PublisherPlugin
from liminal_libs.sources.registry import Provider
from liminal_libs.storage.databases import DatabasePlugin

pytestmark = pytest.mark.usefixtures("no_outside")


def _the_whole_library() -> tuple[str, ...]:
    """Every module of the library imported once, as this file is collected (outside any test's guard, as each import
    of a test file is): so library_classes() sees every plugin class the library defines however the suite is run,
    this file alone or the whole in any order, a base no import above names included."""
    names = []
    for info in pkgutil.walk_packages(liminal_libs.__path__, "liminal_libs."):
        importlib.import_module(info.name)
        names.append(info.name)
    return tuple(names)


MODULES = _the_whole_library()
NAMES = ("READ_HOOKS", "SERVICE_HOOKS")  # declarations of hook names, each class's adding to its bases'
WORDS = ("READ_HOOKS", "SERVICE_HOOKS", "ASKS", "KEEPS", "INTERNAL_NOTES")
# the standard interfaces of this release: the library's bases whose own HOOKS their plugins answer (DECISIONS addendum
# 14); a base the library adds later is found by standard() and held to the same words with nothing named here
BASES = (Plugin, FeedPlugin, PublisherPlugin, AssistantPlugin, MachinePlugin, Firewall, Admin, WslDistribution,
         DatabasePlugin, AiPlugin, ModelServer, Harness)  # the last three 1.62.0's


def standard() -> list[type]:
    """The standard interfaces: every plugin class of the library whose own HOOKS its plugins answer, each a base
    adding hooks to its bases' (a record or an archive's feed class declares none of its own)."""
    return [cls for cls in library_classes() if "HOOKS" in cls.__dict__]


def library_classes() -> list[type]:
    """Every plugin class the library itself defines (the bases, the records, the archive feeds' classes), each once."""
    out: list[type] = []
    todo = [Plugin]
    while todo:
        cls = todo.pop()
        if cls not in out and (cls.__module__ or "").startswith("liminal_libs."):
            out.append(cls)
            todo += cls.__subclasses__()
    return sorted(out, key=lambda c: (c.__module__, c.__qualname__))


def joined(cls: type, attr: str) -> tuple[str, ...]:
    """A declaration of names as a plugin of this class has it: every class's own along its line, each name once."""
    out: list[str] = []
    for c in cls.__mro__:
        value = c.__dict__.get(attr, ())
        out += [n for n in (value if isinstance(value, tuple) else ()) if n not in out]
    return tuple(out)


def test_the_library_classes_include_every_kind():
    found = library_classes()
    assert {*BASES, Provider, Publisher} <= set(found)
    assert set(BASES) <= set(standard()) and not {Provider, Publisher} & set(standard())
    assert all(hasattr(cls, attr) for cls in found for attr in WORDS)  # a plugin of any kind reads and declares them


def test_every_module_of_the_library_is_read_however_the_suite_is_run():
    """library_classes() reads what is imported: every module of the library is (MODULES), so a plugin class of a
    module no other import of this file brings is held to the contract's words all the same."""
    root = Path(liminal_libs.__file__).parent
    on_disk = set()
    for path in root.rglob("*.py"):
        parts = path.relative_to(root).with_suffix("").parts
        on_disk.add(".".join(("liminal_libs", *(parts[:-1] if parts[-1] == "__init__" else parts))))
    assert on_disk - {"liminal_libs"} <= set(MODULES), sorted(on_disk - set(MODULES))


def test_a_class_names_only_hooks_it_has():
    wrong = []
    for cls in library_classes():
        for attr in NAMES:
            own = cls.__dict__.get(attr, ())
            if not isinstance(own, tuple) or not all(isinstance(n, str) for n in own):
                wrong.append(f"{cls.__qualname__}.{attr} is not a tuple of str: {own!r}")
            stranger = [n for n in joined(cls, attr) if n not in cls.HOOKS]
            if stranger:
                wrong.append(f"{cls.__qualname__}.{attr} names {stranger}, not among its HOOKS")
    assert not wrong, wrong


def test_a_class_names_only_its_own():
    """Each class names what it adds: its bases' names come to it by themselves (a base's stay its subclasses')."""
    again = []
    for cls in library_classes():
        for attr in NAMES:
            above = {n for base in cls.__mro__[1:] for n in joined(base, attr)}
            twice = [n for n in cls.__dict__.get(attr, ()) if n in above]
            if twice:
                again.append(f"{cls.__qualname__}.{attr} names {twice} again")
    assert not again, again


def test_a_read_is_no_job_and_accepts_no_refusal():
    wrong = []
    for cls in library_classes():
        jobs = set(getattr(cls, "JOB_HOOKS", ()) or ())
        for name in joined(cls, "READ_HOOKS"):
            if name in jobs:
                wrong.append(f"{cls.__qualname__}: {name} is said to only read and is one of its jobs")
            given = getattr(cls, name, None)
            if inspect.isfunction(given):
                accepts = [p for p in inspect.signature(given).parameters if p.startswith("accept_")]
                if accepts:
                    wrong.append(f"{cls.__qualname__}: {name} is said to only read and takes {accepts}")
    assert not wrong, wrong


def test_what_spends_requests_or_changes_something_is_never_a_read():
    """Plugin.READ_HOOKS' rule: a scan and a publisher's read spend a provider's requests; a setup and a command change
    the machine. DatabasePlugin's reads are as agreed with the session of storage/databases.py (2026-11-16): own_port
    keeps a port through the login, open hands back a live connection, make makes a database."""
    for cls in library_classes():
        assert "scan" not in joined(cls, "READ_HOOKS"), cls
    assert "settings" in joined(FeedPlugin, "READ_HOOKS") and "settings" in joined(Provider, "READ_HOOKS")
    assert "read" not in joined(PublisherPlugin, "READ_HOOKS") and "read" not in joined(Publisher, "READ_HOOKS")
    for cls in (MachinePlugin, Firewall, Admin, WslDistribution, AiPlugin, ModelServer, Harness):
        assert not {"setup", "run"} & set(joined(cls, "READ_HOOKS")), cls
        assert {"present", "status", "instances"} <= set(joined(cls, "READ_HOOKS")), cls
    # an AI plugin's: what starts or stops a server or a tool, starts one at boot, shares one or has a model answer
    # a prompt (try_it) is never a read; a pick of which instance its page shows (until the platform restarts) is
    # one, and so are the lines to paste (command)
    assert not {"start", "stop", "boot", "share", "try_it"} & set(joined(ModelServer, "READ_HOOKS"))
    assert not {"use", "open", "install", "uninstall"} & set(joined(Harness, "READ_HOOKS"))
    assert "choose" in ModelServer.READ_HOOKS and "command" in Harness.READ_HOOKS
    assert {"builtin", "probe"} <= set(joined(DatabasePlugin, "READ_HOOKS"))
    assert not {"open", "make", "own_port"} & set(joined(DatabasePlugin, "READ_HOOKS"))


def test_every_hook_a_base_answers_says_what_it_does():
    """The first sentence of a hook's own docstring is its line on the Internal API tab: a base's hook without one
    would show its parent's general line (Firewall's rename_label and status, WslDistribution's present, status, run
    and instances had none)."""
    mute = [f"{cls.__qualname__}.{name}" for cls in standard() for name in cls.HOOKS
            if inspect.isfunction(cls.__dict__.get(name)) and not inspect.cleandoc(cls.__dict__[name].__doc__ or "")]
    assert not mute, mute


def _rule() -> str:
    """Plugin.READ_HOOKS' rule, the comment above it in the contract, on one line."""
    source = Path(contract.__file__).read_text(encoding="utf-8")
    block = source.split("# What it says of the interface it shares", 1)[1].split("READ_HOOKS: tuple", 1)[0]
    return " ".join(line.strip().lstrip("#").strip() for line in block.splitlines())


def test_the_read_rule_lets_a_command_read_and_keeps_out_what_keeps_running():
    """The rule the plugins' READ_HOOKS are classified by (the plan's 4.1: "it may ask a provider or run a command to
    read, or change only what the page shows until the platform restarts"): a command that reads and ends is a read,
    as the library's own are (WslDistribution's check runs wsl.exe); what keeps running once started, a listener, a
    cost or a provider's requests spent is not."""
    rule = _rule()
    for words in ("A read changes nothing here, at a provider or in what is kept through the login",
                  "it may run a command that reads and ends",
                  "ask a provider without spending its requests or quota",
                  "or change only what its page shows until the app restarts",
                  "A hook that spends them (a scan, a publisher's `read`), costs money, starts a program that keeps "
                  "running (a server, a daemon, a stopped distribution) or opens a listener is not one",
                  "nor is a hook taking an `accept_*` argument", "or one of its JOB_HOOKS"):
        assert words in rule, words
    assert "starts a program or opens a listener" not in rule
    assert "check" in WslDistribution.READ_HOOKS  # a read that runs a command and ends (wsl --version, --list)


def test_no_library_source_says_a_page_has_main_and_api_alone():
    """A plugin's page has Main, External API and Internal API (liminal-platform 0.32.0): no comment or docstring of
    the library still says its own tabs come after "Main and API" (its history aside: "Main and API before it")."""
    root = Path(liminal_libs.__file__).parent
    stale = [f"{path.relative_to(root).as_posix()}:{n}" for path in sorted(root.rglob("*.py"))
             for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
             if re.search(r"\bMain and API\b(?! before)", line)]
    assert stale == [], stale


def test_the_words_are_rows_of_words():
    """What a class declares as plain words is in the shapes the Internal API tab reads (a property is read on a
    plugin, below)."""
    wrong = []
    for cls in library_classes():
        asks, keeps, notes = (inspect.getattr_static(cls, attr) for attr in ("ASKS", "KEEPS", "INTERNAL_NOTES"))
        if not isinstance(asks, property) and not (isinstance(asks, tuple) and all(
                isinstance(r, tuple) and len(r) in (2, 3) and all(isinstance(x, str) for x in r) for r in asks)):
            wrong.append(f"{cls.__qualname__}.ASKS: {asks!r}")
        if not isinstance(keeps, property) and not (isinstance(keeps, tuple) and all(
                isinstance(r, tuple) and len(r) == 2 and all(isinstance(x, str) and x for x in r) for r in keeps)):
            wrong.append(f"{cls.__qualname__}.KEEPS: {keeps!r}")
        if not isinstance(notes, property) and not (isinstance(notes, tuple) and all(
                isinstance(n, str) and n.strip() and len(n) <= 400 for n in notes)):
            wrong.append(f"{cls.__qualname__}.INTERNAL_NOTES: {notes!r}")
    assert not wrong, wrong
    assert WslDistribution.INTERNAL_NOTES and "DISTRIBUTION_VAR" in WslDistribution.INTERNAL_NOTES[0]


class _Wall(Firewall):
    name = "firewall-test"
    title = "A firewall"


class _Watched:
    """A login that notes every name asked of it and answers none."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def __getattr__(self, name):
        self.asked.append(name)
        raise AttributeError(name)


def test_a_firewall_says_where_it_keeps_its_groups_and_asks_no_login_to_say_it():
    wall, login = _Wall(), _Watched()
    wall.login = login
    assert wall.KEEPS == (("FIREWALL_TEST_GROUPS", "the labels and the moves of its rules"),)
    assert wall.KEEPS[0][0] == wall.groups.variable
    assert login.asked == []  # said by name: nothing read, nothing kept
    named = type("Named", (_Wall,), {"GROUPS_VARIABLE": "MY_RULE_GROUPS"})()
    assert named.KEEPS == (("MY_RULE_GROUPS", "the labels and the moves of its rules"),)
    plain = type("Plain", (_Wall,), {"KEEPS": (("OTHER_GROUPS", "its own words"),)})()
    assert plain.KEEPS == (("OTHER_GROUPS", "its own words"),)  # a subclass's words replace the base's
