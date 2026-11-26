"""The contract's needs (1.103.0; the needs plan's revision 2, 3.2, S9): Plugin itself declares none, so a plugin that
says nothing is told apart from one that needs nothing; the bases that speak for a whole kind declare their rows once,
in the getattr idiom; conformance checks the rows' shape of a plugin that declares any."""
from __future__ import annotations

import ast
import inspect

import pytest

from liminal_libs import needs, needs_machines
from liminal_libs.assistants.plugin import AssistantPlugin
from liminal_libs.auditing import AuditorPlugin
from liminal_libs.machines import wsl
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.sources import conformance
from liminal_libs.sources.plugin import FeedPlugin, IntegratorPlugin, PlatformPlugin, Plugin
from liminal_libs.sources.publisher import PublisherPlugin

from test_needs import DECLARING
from test_plugin_classes import AcmeFeed, AcmeNews, acme_record

pytestmark = pytest.mark.usefixtures("no_outside")


def test_plugin_and_the_bases_that_leave_it_to_each_plugin_declare_none_s9():
    for base in (Plugin, IntegratorPlugin, PlatformPlugin, MachinePlugin):
        assert "NEEDS" not in vars(base) and not needs.says(base), base
    assert not hasattr(Plugin, "NEEDS")


@pytest.mark.parametrize("base,rows", [
    (FeedPlugin, [("internet", "yes", "part")]),
    (PublisherPlugin, [("internet", "yes", "part")]),
    (AssistantPlugin, [("internet", "yes", "required")]),
    (AuditorPlugin, []),
])
def test_each_bases_rows(base, rows):
    assert [(r["attribute"], r["value"], r["strength"]) for r in needs.declared(base)] == rows
    assert needs.says(base) and needs.problems(base) == []


def test_the_wsl_base_shares_its_rows_its_build_from_min_build():
    rows = needs.declared(wsl.WslDistribution)
    assert [(r["attribute"], r["value"], r["strength"]) for r in rows] == [
        ("kernel", "windows", "required"), ("windows.build", f">= {wsl.MIN_BUILD}", "required"),
        ("virtualization", "extensions", "required"), ("virtualization", "slat", "required"),
        ("virtualization", "firmware", "required"), ("internet", "yes", "part"), ("desktop", "yes", "part")]
    assert needs.problems(wsl.WslDistribution) == []
    judged = {m: needs.judge(rows, needs_machines.facts_of(m))["met"] for m in needs_machines.names()}
    assert judged["this-pc"] is True and judged["windows-hyperv-off"] is True
    assert judged["wsl-ubuntu-24.04"] is False and judged["windows-firmware-off"] is False
    assert judged["windows-arm-hyperv-off"] is not False and judged["windows-vm-no-nesting"] is not False  # S2


def test_the_bases_add_to_theirs_only_through_getattr_b2():
    for module in (inspect.getmodule(FeedPlugin), inspect.getmodule(PublisherPlugin), inspect.getmodule(wsl),
                   inspect.getmodule(AssistantPlugin), inspect.getmodule(AuditorPlugin)):
        tree = ast.parse(inspect.getsource(module))
        assert not [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == "NEEDS"], module
        assert not [n for n in ast.walk(tree) if isinstance(n, ast.AnnAssign)
                    and getattr(n.target, "id", "") == "NEEDS"], module


def test_the_librarys_own_test_plugins_have_no_needs_problem_and_inherit_their_bases():
    for p in (AcmeFeed(), AcmeNews(), acme_record()):
        assert needs.problems(p) == [] and needs.says(p)
        assert [r["attribute"] for r in needs.declared(p)] == ["internet"]
        assert not [w for w in conformance.problems(p) if "NEEDS" in w or "row " in w]


def test_conformance_names_a_rows_wrong_shape_and_takes_the_four_declaring_plugins_rows():
    class Bad(type(AcmeFeed())):
        NEEDS = (("internet",), ("kernel", "windows", "must"))
    said = conformance.problems(Bad())
    assert any("not two to four words" in w for w in said) and any("strength 'must'" in w for w in said)

    class Values(type(AcmeFeed())):
        NEEDS = (("architecture", "ppc"),)  # a value the vocabulary does not know: its own package's test's to hold
    assert not [w for w in conformance.problems(Values()) if "architecture" in w]
    for where, rows in DECLARING.items():
        P = type("P", (type(AcmeFeed()),), {"NEEDS": rows})
        assert not [w for w in conformance.problems(P()) if "row " in w or "NEEDS" in w], where
