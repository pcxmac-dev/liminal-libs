"""liminal_libs.needs: the declaration, its problems and the judgement (1.103.0; the needs plan's revision 2, 3.2-3.5,
with the critiques' points named where each is held). Pure: facts written here, nothing read of this machine."""
from __future__ import annotations

import random

import pytest

from liminal_libs import needs

pytestmark = pytest.mark.usefixtures("no_outside")


def windows(**over):
    f = {"system": "windows", "kernel": {"name": "windows"}, "architecture": "x86-64",
         "windows": {"build": 26300, "ubr": 9974, "edition": "Professional", "product": "Windows 11 Pro",
                     "server": False, "features": {"Microsoft-Hyper-V": 1, "Containers": 2}, "featuresRead": True},
         "cpu": {"avx": True, "avx2": True, "avx512f": False, "sse4.2": True, "nx": True, "nxHardware": True},
         "virtualization": {"extensions": False, "slat": False, "firmware": False, "hypervisor": True, "vm": "",
                            "nested": None, "kvm": None},
         "memory": {"installed": 64 * 2**30, "usable": 63 * 2**30},
         "internet": {"state": "yes", "ipv4": True, "ipv6": False, "by": "Windows' own judgement (NCSI)",
                      "readings": [[100.0, "yes"]]},
         "wsl": "none", "linux": {}, "init": "", "library": "1.103.0", "desktop": True,
         "disk": {"free": 500 * 2**30, "path": "C:\\"}, "tools": {"npcap": False}, "read": "2026-11-26T00:00:00Z"}
    for k, v in over.items():
        f[k] = {**f[k], **v} if isinstance(v, dict) and isinstance(f.get(k), dict) else v
    return f


def linux(**over):
    f = {"system": "linux", "kernel": {"name": "linux", "release": "6.18.58.1-microsoft-standard-WSL2"},
         "architecture": "x86-64", "windows": {},
         "cpu": {"avx": True, "avx2": True, "avx512f": False, "sse4.2": True, "nx": True},
         "virtualization": {"extensions": True, "slat": True, "firmware": None, "hypervisor": None,
                            "vm": "a virtual machine", "nested": True, "kvm": True},
         "memory": {"installed": None, "usable": 31 * 2**30}, "internet": {"state": "unknown", "readings": []},
         "wsl": "2", "linux": {"netfilter": True, "ebpf": True}, "init": "systemd", "library": "1.103.0",
         "desktop": False, "disk": {"free": 100 * 2**30, "path": "/"}, "tools": {}}
    for k, v in over.items():
        f[k] = {**f[k], **v} if isinstance(v, dict) and isinstance(f.get(k), dict) else v
    return f


def one(attribute, value, facts, strength="required", **kw):
    answer = needs.judge([{"attribute": attribute, "value": value, "strength": strength, "words": "w"}], facts, **kw)
    return answer["rows"][0], answer


# -- the declaration ---------------------------------------------------------------------------------------------------
class Silent:
    name = "silent"


class Nothing:
    name = "nothing"
    NEEDS = ()


class Base:
    NEEDS = (("kernel", "windows"),)


class Child(Base):
    name = "child"
    NEEDS = (*getattr(Base, "NEEDS", ()), ("disk", ">= 4 GiB", "part", "its install"))


class Inherits(Base):
    name = "inherits"


def test_said_or_silent_by_a_class_of_its_line_s9():
    assert not needs.says(Silent()) and needs.rows_of(Silent()) is None
    assert needs.says(Nothing()) and needs.declared(Nothing()) == []
    assert needs.says(Inherits()) and needs.declared(Inherits())[0]["attribute"] == "kernel"
    answer = needs.judge(needs.declared(Silent()), windows(), declared=False)
    assert answer["met"] is None and answer["why"] == needs.NOT_SAID and answer["rows"] == []
    answer = needs.judge([], windows(), declared=True)
    assert answer["met"] is True and answer["why"] == needs.NOTHING


def test_declared_normalizes_and_takes_a_required_part_only_attribute_as_a_part():
    class P:
        NEEDS = (("Architecture", "AMD64|aarch64"), ("tool", "npcap", "required"), ("kernel", "windows"),
                 ("kernel", "windows"), ("bad",), ("x:kernel", "linux"))
    rows = needs.declared(P())
    assert rows[0] == {"attribute": "architecture", "value": "x86-64|arm64", "strength": "required", "words": ""}
    assert rows[1]["strength"] == "part" and len(rows) == 3


def test_problems_of_a_well_said_and_a_silent_plugin():
    assert needs.problems(Child()) == [] and needs.problems(Silent()) == [] and needs.problems(Nothing()) == []


def test_a_needs_method_is_not_judged_q2():
    class M:
        name = "m"

        def needs(self):
            return []
    said = needs.problems(M())
    assert len(said) == 1 and "declare NEEDS" in said[0] and "plugin 'm'" in said[0]


def test_a_property_needs_is_a_problem_b2():
    class Prop:
        name = "prop"

        @property
        def NEEDS(self):  # noqa: N802
            return (("kernel", "windows"),)
    said = needs.problems(Prop())
    assert said and "property" in said[0]


def test_an_annotated_needs_is_a_problem_b2():
    class Annotated:
        name = "annotated"
        NEEDS: tuple = (("kernel", "windows"),)
    assert any("annotated" in p for p in needs.problems(Annotated()))


@pytest.mark.parametrize("rows,words", [
    ([("kernel", "windows")], "tuple of rows"),
    ((("kernel",),), "two to four words"),
    ((("kernel", "windows", "must"),), "strength 'must'"),
    ((("disk", ">= 4 GiB", "part"),), "which part"),
    ((("internet", "yes", "preferred"),), "what it gains"),
    ((("rights", "administrator", "required"),), "never required"),
    ((("kernel", "windows"), ("kernel", "Windows")), "given twice"),
    ((("kernel", "windows", "part", "x" * 201),), "over 200"),
    ((("other:kernel", "windows"),), "prefix 'other'"),
    ((("architecture", "x86_64|ppc"),), "not a value of architecture"),
    ((("library", ">= 1.103.0"),), "at or below 1.103.0"),
    (tuple(("tool", f"t{i}", "part", "w") for i in range(41)), "more than 40"),
])
def test_problems_say_each_wrong(rows, words):
    P = type("P", (), {"name": "p", "NEEDS": rows})
    said = needs.problems(P())
    assert any(words in p for p in said), said
    assert all(p.startswith("plugin 'p'") for p in said)


def test_values_false_checks_the_shape_alone():
    P = type("P", (), {"name": "p", "NEEDS": (("architecture", "ppc"),)})
    assert needs.problems(P(), values=False) == [] and needs.problems(P())


def test_an_unknown_attribute_is_never_a_problem_but_unknown_m16():
    P = type("P", (), {"name": "p", "NEEDS": (("gpu", "nvidia", "part", "its models"),)})
    assert needs.problems(P()) == []
    assert needs.unknown(needs.declared(P())) == ["gpu"]
    row, answer = one("gpu", "nvidia", windows(), strength="part")
    assert row["state"] == "unknown" and "vocabulary 1" in row["said"] and answer["met"] is True


# the four plugins that declared NEEDS before this module (each 0.1.0 in incoming, on a 1.99.0 floor): their rows as
# they are written, copied as data, so the day this module lands their own tests' `problems() == []` holds
DECLARING = {
    "codex-cli (plugin_platform_codex_cli/__init__.py:159)": (
        ("architecture", "x86-64", "part", "its install: only the x86-64 packages are pinned in 0.1.0"),
        ("desktop", "yes", "part", "its window on Windows; elsewhere Open… gives the lines to paste"),
        ("windows.build", ">=26100.9278 (24H2) or >=26200.9278 (25H2)", "part",
         "MXC, its sandbox on Windows: without it every command fails"),
        ("tool", "bwrap", "part", "bubblewrap on Linux (its package's own needs unprivileged user namespaces: "
                                  "linux.feature userns, proposed to the needs release)"),
        ("internet", "yes", "part", "its install, on a click")),
    "lmdeploy (plugin_platform_lmdeploy/__init__.py:108)": (
        ("architecture", "x86-64", "part", "LMDeploy's wheels are built for x86-64 alone"),
        ("gpu", "nvidia", "part", "TurboMind runs on an NVIDIA GPU"),
        ("gpu.driver", ">=572.61 (Windows), >=570.124.06 (Linux)", "part", "what CUDA 12.8 needs"),
        ("libc", "glibc>=2.28", "part", "its Linux wheels are manylinux_2_28"),
        ("wsl", "none|2", "part", "WSL 1 has no GPU"),
        ("disk", ">=20 GiB", "part", "the install at its peak, uv's cache beside the environment"),
        ("internet", "yes", "part", "the install and a model's download, on a click")),
    "mcp (plugin_platform_mcp/__init__.py:76)": (
        ("internet", "yes", "part", "a server held by its address on another machine, and the catalogue's "
                                    "downloads"),),
    "pi (plugin_platform_pi/__init__.py:144)": (
        ("architecture", "x86-64|arm64", "part", "its Node.js: the builds Node.js publishes"),
        ("libc", "glibc", "part", "Node.js 24's Linux builds: none for a musl Linux"),
        ("tool", "bash", "part", "its shell: on Windows Git for Windows' bash, never WSL's launcher"),
        ("internet", "yes", "part", "its install, on a click")),
}


@pytest.mark.parametrize("where", sorted(DECLARING))
def test_the_four_declaring_plugins_rows_have_no_problem(where):
    P = type("P", (), {"name": where.split()[0], "NEEDS": DECLARING[where]})
    assert needs.problems(P()) == []
    answer = needs.judge(needs.declared(P()), windows())
    assert answer["met"] is True  # parts only: never out of the list


def test_builds_of_codex_clis_value_q8():
    assert needs.builds_of(">=26100.9278 (24H2) or >=26200.9278 (25H2)") == [(26100, 9278, "24H2"),
                                                                             (26200, 9278, "25H2")]
    assert needs.builds_of(">= 19041") == [(19041, 0, "")]
    assert needs.builds_of("19041") is None and needs.builds_of(">= 1.2.3") is None
    value = ">=26100.9278 (24H2) or >=26200.9278 (25H2)"
    assert one("windows.build", value, windows())[0]["state"] == "met"  # 26300: above every alternative
    assert "later Windows" in one("windows.build", value, windows())[0]["said"]
    assert one("windows.build", value, windows(windows={"build": 26100, "ubr": 9300}))[0]["state"] == "met"
    row = one("windows.build", value, windows(windows={"build": 26100, "ubr": 9000}))[0]
    assert row["state"] == "unmet" and row["sort"] == "moment" and "Windows Update" in row["how"]
    assert one("windows.build", value, windows(windows={"build": 22631, "ubr": 5000}))[0]["state"] == "unmet"
    assert one("windows.build", ">= 19041", windows(windows={"build": 19041, "ubr": None}))[0]["state"] == "met"


def test_sizes_and_architectures():
    assert needs.size_of(">= 4 GiB") == 4 * 2**30 == needs.size_of(">=4GiB") and needs.size_of("512 MiB") == 2**29
    assert needs.size_of("lots") is None
    assert [needs.normal_architecture(w) for w in ("AMD64", "x86_64", "ARM64", "aarch64", "i686", "ppc64le")] == [
        "x86-64", "x86-64", "arm64", "arm64", "x86", ""]


# -- S1's sorts, one by one --------------------------------------------------------------------------------------------
def test_the_kernel_is_of_the_machine():
    row, answer = one("kernel", "windows", linux())
    assert (row["state"], row["sort"], answer["met"], answer["sort"]) == ("unmet", "machine", False, "machine")
    assert one("kernel", "linux", windows())[0]["sort"] == "machine"


def test_wsl1_meets_kernel_linux_and_says_so_m19():
    row = one("kernel", "linux", linux(wsl="1"))[0]
    assert row["state"] == "met" and "WSL 1" in row["said"]


def test_a_running_hypervisor_on_bare_metal_meets_the_three_flags():
    for v in ("extensions", "slat", "firmware"):
        row = one("virtualization", v, windows())[0]
        assert row["state"] == "met" and "hypervisor runs" in row["said"]


def test_bare_metal_without_a_hypervisor():
    off = windows(virtualization={"hypervisor": False, "extensions": False, "slat": False, "firmware": True})
    assert one("virtualization", "extensions", off)[0]["sort"] == "machine"
    assert one("virtualization", "slat", off)[0]["sort"] == "machine"
    fw = windows(virtualization={"hypervisor": False, "extensions": True, "slat": True, "firmware": False})
    row = one("virtualization", "firmware", fw)[0]
    assert row["sort"] == "moment" and "firmware" in row["how"]
    both = windows(virtualization={"hypervisor": False, "extensions": False, "slat": False, "firmware": False})
    assert one("virtualization", "extensions", both)[0]["sort"] == "moment"  # while the firmware reads off
    row = one("virtualization", "hypervisor", off)[0]
    assert row["sort"] == "moment" and "Windows Features" in row["how"]


def test_nx_off_with_the_hardware_having_it_is_of_the_moment():
    row = one("cpu", "nx", windows(cpu={"nx": False, "nxHardware": True}))[0]
    assert row["sort"] == "moment" and "bcdedit" in row["how"]
    assert one("cpu", "nx", windows(cpu={"nx": False, "nxHardware": False}))[0]["sort"] == "machine"
    assert one("cpu", "avx512f", windows())[0]["sort"] == "machine"


def test_linux_without_vmx_is_of_the_moment_and_kvm_says_how():
    bare = linux(wsl="none", virtualization={"vm": "", "extensions": False, "slat": False, "kvm": False})
    assert one("virtualization", "extensions", bare)[0]["sort"] == "moment"
    row = one("virtualization", "kvm", bare)[0]
    assert row["sort"] == "moment" and "firmware" in row["how"]
    nomod = linux(wsl="none", virtualization={"vm": "", "kvm": False})
    assert "modprobe" in one("virtualization", "kvm", nomod)[0]["how"]
    nested = linux(virtualization={"extensions": False, "kvm": False})
    assert "nestedVirtualization" in one("virtualization", "kvm", nested)[0]["how"]
    assert "set-version" in one("virtualization", "kvm", linux(wsl="1", virtualization={"kvm": False}))[0]["how"]
    assert one("virtualization", "kvm", linux())[0]["state"] == "met"
    assert one("virtualization", "kvm", windows())[0]["state"] == "na"


def test_memory_of_the_machine_wsl_or_a_vm():
    assert one("memory", ">= 4 GiB", windows())[0]["state"] == "met"
    small = windows(memory={"installed": 2 * 2**30})
    assert one("memory", ">= 4 GiB", small)[0]["sort"] == "machine"
    assert "wslconfig" in one("memory", ">= 64 GiB", linux())[0]["how"]
    assert one("memory", ">= 64 GiB", linux())[0]["sort"] == "moment"


def test_inside_a_vm_cpu_and_memory_are_the_hosts_m33():
    vm = windows(virtualization={"vm": "Hyper-V Virtual Machine", "hypervisor": False}, memory={"installed": 2**31},
                 cpu={"avx2": False})
    row = one("memory", ">= 4 GiB", vm)[0]
    assert row["sort"] == "moment" and "host" in row["how"]
    assert one("cpu", "avx2", vm)[0]["sort"] == "moment"
    assert one("architecture", "arm64", vm)[0]["sort"] == "machine"


def test_s2_a_false_never_seen_read_right_is_unknown():
    arm = windows(architecture="arm64", virtualization={"hypervisor": False}, cpu={"avx": False})
    for v in ("extensions", "slat", "firmware"):
        assert one("virtualization", v, arm)[0]["state"] == "unknown"
    assert one("cpu", "avx", arm)[0]["state"] == "unknown"
    vm = windows(virtualization={"vm": "VMware Virtual Platform", "hypervisor": False})
    nested_on = windows(virtualization={"vm": "Virtual Machine", "hypervisor": True})
    for facts in (vm, nested_on):
        for v in ("extensions", "slat", "firmware"):
            assert one("virtualization", v, facts)[0]["state"] == "unknown"


def test_features_absent_off_and_on_decision_18(monkeypatch):
    assert one("windows.feature", "Microsoft-Hyper-V", windows())[0]["state"] == "met"
    row = one("windows.feature", "Containers|Containers-DisposableClientVM", windows())[0]
    assert row["state"] == "unmet" and row["sort"] == "moment" and "Windows Features" in row["how"]
    home = windows(windows={"features": {}, "product": "Windows 11 Home"})
    row = one("windows.feature", "Microsoft-Hyper-V", home)[0]
    assert row["sort"] == "machine" and "Windows 11 Home" in row["said"]
    server = windows(windows={"features": {}, "server": True})
    assert one("windows.feature", "Microsoft-Hyper-V", server)[0]["state"] == "unknown"
    unread = windows(windows={"featuresRead": False})
    assert one("windows.feature", "Microsoft-Hyper-V", unread)[0]["state"] == "unknown"
    monkeypatch.setattr(needs, "OFF_FEATURE", "validity")
    assert one("windows.feature", "Containers", windows())[0]["state"] == "met"
    assert one("windows.feature", "Containers", linux())[0]["state"] == "na"


def test_the_other_systems_attributes_and_a_prefix_are_na_m1():
    assert one("linux.feature", "netfilter", windows())[0]["state"] == "na"
    assert one("init", "systemd", windows())[0]["state"] == "na"
    assert one("windows:architecture", "x86-64", linux(architecture="arm64"))[0]["state"] == "na"
    assert one("windows:architecture", "x86-64", windows(architecture="arm64"))[0]["state"] == "unmet"


def test_linux_features_init_and_wsl():
    assert one("linux.feature", "netfilter", linux(wsl="1"))[0]["sort"] == "moment"
    assert one("linux.feature", "ebpf", linux(wsl="none", linux={"ebpf": False}))[0]["sort"] == "machine"
    assert one("linux.feature", "ebpf", linux(linux={"ebpf": None}))[0]["state"] == "unknown"
    assert one("init", "systemd|openrc", linux(init="openrc"))[0]["state"] == "met"
    assert one("init", "systemd", linux(init="sysv"))[0]["sort"] == "moment"  # under WSL: /etc/wsl.conf
    assert one("init", "systemd", linux(wsl="none", init="sysv"))[0]["sort"] == "machine"
    assert one("wsl", "none|2", windows())[0]["state"] == "met"
    row = one("wsl", "none|2", linux(wsl="1"))[0]
    assert row["sort"] == "moment" and "set-version" in row["how"]


# -- the internet (S3, M9, decisions 3 and 5) --------------------------------------------------------------------------
def test_the_internet_met_unknown_and_the_switch():
    assert one("internet", "yes", windows())[0]["state"] == "met"
    assert one("internet", "ipv4", windows())[0]["state"] == "met"
    assert one("internet", "ipv6", windows())[0]["state"] == "unmet"
    proxied = windows(internet={"state": "unknown", "why": "a proxy is set", "readings": [[1.0, "unknown"]]})
    row = one("internet", "yes", proxied)[0]
    assert row["state"] == "unknown" and "proxy" in row["said"]
    row = one("internet", "yes", proxied, internet="there")[0]
    assert row["state"] == "met" and "your switch" in row["said"]


def test_offline_wins_over_the_switch_decision_5():
    row, answer = one("internet", "yes", windows(), internet="there", offline="LIMINAL_OFFLINE")
    assert row["state"] == "unmet" and "LIMINAL_OFFLINE" in row["said"] and answer["held"] is True


def test_two_readings_fifteen_seconds_apart_before_no_m9():
    first_no = windows(internet={"state": "no", "readings": [[0.0, "no"]]})
    assert one("internet", "yes", first_no)[0]["state"] == "unknown"
    was_yes = windows(internet={"state": "no", "readings": [[0.0, "yes"], [20.0, "no"]]})
    assert one("internet", "yes", was_yes)[0]["state"] == "met"
    close = windows(internet={"state": "no", "readings": [[0.0, "yes"], [20.0, "no"], [30.0, "no"]]})
    assert one("internet", "yes", close)[0]["state"] == "met"
    apart = windows(internet={"state": "no", "readings": [[0.0, "yes"], [20.0, "no"], [35.0, "no"]]})
    row, answer = one("internet", "yes", apart)
    assert row["state"] == "unmet" and row["sort"] == "moment" and answer["held"] is True
    back = windows(internet={"state": "yes", "readings": [[20.0, "no"], [35.0, "no"], [36.0, "yes"]]})
    assert one("internet", "yes", back)[0]["state"] == "met"


# -- the answer --------------------------------------------------------------------------------------------------------
def test_own_words_are_an_unmet_row_of_the_machine():
    class Own:
        name = "own"

        def not_for_here(self):
            return "this is Linux: Hyper-V is Windows' own"
    answer = needs.judge([], windows(), own=needs.own_words(Own()), declared=False)
    assert answer["met"] is False and answer["sort"] == "machine" and "Hyper-V" in answer["why"]

    class Raises:
        def not_for_here(self):
            raise RuntimeError("no")
    assert needs.own_words(Raises()) == "" and needs.own_words(Silent()) == ""


def test_parts_never_hide_and_unknown_never_hides_decision_10():
    rows = [{"attribute": "tool", "value": "npcap", "strength": "part", "words": "the capture"},
            {"attribute": "memory", "value": ">= 4 GiB", "strength": "required", "words": "w"}]
    answer = needs.judge(rows, windows(memory={"installed": None, "usable": None}))
    assert answer["rows"][0]["state"] == "unmet" and answer["met"] is None and answer["sort"] == ""


def test_held_for_and_state_of():
    net = {"rows": [{"attribute": "internet", "strength": "required", "state": "unmet"},
                    {"attribute": "tool", "strength": "part", "state": "unmet"}]}
    assert needs.held_for(net) is True
    both = {"rows": [*net["rows"], {"attribute": "kernel", "strength": "required", "state": "unmet"}]}
    assert needs.held_for(both) is False and needs.held_for({"rows": []}) is False
    assert needs.state_of(False, {"met": False}, True) == "disabled"
    assert needs.state_of(True, {"met": False}, True) == "unmet"
    assert needs.state_of(True, {"met": True}, False) == "invalid"
    assert needs.state_of(True, {"met": None}, None) == "active"


def test_plugin_rows():
    rows = [{"attribute": "windows:plugin", "value": "wsl-ubuntu|wsl-fedora", "strength": "preferred", "words": "w"}]
    assert needs.judge(rows, windows(), plugins={"wsl-ubuntu": "active"})["rows"][0]["state"] == "met"
    assert needs.judge(rows, windows(), plugins={"wsl-ubuntu": "disabled"})["rows"][0]["state"] == "unmet"
    every = {"wsl-ubuntu": "cannot", "wsl-fedora": "cannot"}
    assert needs.judge(rows, windows(), plugins=every)["rows"][0]["state"] == "na"
    assert needs.judge(rows, windows())["rows"][0]["state"] == "unknown"


def test_the_answers_keys():
    answer = needs.judge(needs.declared(Child()), windows())
    assert set(answer) == {"v", "vocabulary", "declared", "met", "sort", "why", "read", "held", "rows"}
    assert set(answer["rows"][0]) == {"attribute", "value", "strength", "words", "state", "sort", "said", "how"}
    assert answer["read"] == "2026-11-26T00:00:00Z" and answer["met"] is True


def test_judge_never_raises_on_garbage():
    rng = random.Random(19)
    junk = [None, 1, "x", [], {}, {"a": 1}, -1.5, True, ("t",), {"state": object()}]
    rows = [{"attribute": a, "value": v, "strength": "required", "words": ""}
            for a in needs.ATTRIBUTES for v in ("windows", "yes", ">= 4 GiB", "x86-64", "kvm", ">= 1.200.0")]
    for _ in range(300):
        facts = {k: rng.choice(junk) for k in ("system", "kernel", "windows", "architecture", "cpu", "virtualization",
                                                "memory", "internet", "wsl", "linux", "init", "library", "desktop",
                                                "disk", "tools", "rights", "why")}
        answer = needs.judge(rows, facts, plugins=rng.choice(junk))
        assert answer["met"] in (True, False, None)
    assert needs.judge("nonsense", "facts")["met"] in (True, None)
