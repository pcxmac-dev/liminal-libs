"""liminal_libs.needs_machines: the recorded machines the needs tests judge against (1.103.0; the needs plan's revision
2, 3.12, B4's one set). Nothing of this machine is read."""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from liminal_libs import facts, needs, needs_machines
from liminal_libs.linuxsys import standin

pytestmark = pytest.mark.usefixtures("no_outside")
SHAPE = {"system", "kernel", "windows", "architecture", "cpu", "virtualization", "memory", "internet", "wsl",
         "container", "linux", "init", "library", "desktop", "disk", "tools", "rights", "read", "why"}


def test_every_linuxsys_machine_has_a_row_of_its_own_name_b4():
    assert standin.machines() and set(standin.machines()) <= set(needs_machines.LINUX)
    for name, (machine, overlay, *_rest) in needs_machines.LINUX.items():
        assert machine in standin.machines() and (overlay is None or overlay in standin.overlays(machine))
        if name in standin.machines():
            assert machine == name and overlay is None


@pytest.mark.parametrize("name", standin.machines())
def test_one_reading_two_readers_kernel_wsl_and_container(name):
    k = standin.Machine(name).facts().kernel
    f = needs_machines.facts_of(name)
    assert f["kernel"]["release"] == k.release and f["container"] == k.container
    assert f["wslName"] == k.wsl and f["wsl"] == ("none" if not k.wsl else str(k.wsl_generation or 2))
    assert f["architecture"] == needs.normal_architecture(k.machine)


@pytest.mark.parametrize("name", needs_machines.names())
def test_each_machine_has_the_facts_shape_and_says_where_it_comes_from(name):
    f = needs_machines.facts_of(name)
    assert SHAPE <= set(f), SHAPE - set(f)
    assert f["system"] in ("windows", "linux") and needs_machines.source(name)
    assert isinstance(needs_machines.reader(name), facts.StandIn)
    assert needs_machines.reader(name).read() == f


def test_this_pc_as_the_map_read_it():
    f = needs_machines.facts_of("this-pc")
    assert f["windows"]["build"] == 26300 and f["windows"]["product"] == "Windows 11 Pro"
    assert f["virtualization"]["hypervisor"] is True and f["virtualization"]["vm"] == ""
    assert f["internet"]["state"] == "yes" and f["architecture"] == "x86-64"
    hyperv = [{"attribute": "virtualization", "value": v, "strength": "required", "words": ""}
              for v in ("extensions", "slat", "firmware")]
    assert needs.judge(hyperv, f)["met"] is True


def test_the_variants():
    wsl1 = needs_machines.facts_of("wsl1")
    assert wsl1["wsl"] == "1" and wsl1["init"] == "wsl" and wsl1["virtualization"]["kvm"] is False
    assert needs_machines.facts_of("wsl-ubuntu-24.04")["virtualization"]["kvm"] is True
    assert needs_machines.facts_of("wsl2-no-nesting")["virtualization"]["extensions"] is False
    assert needs_machines.facts_of("ubuntu-nm")["internet"]["state"] == "yes"
    assert needs_machines.facts_of("linux-no-route")["internet"]["state"] == "no"
    assert needs_machines.facts_of("linux-proxy")["internet"]["state"] == "unknown"
    small = needs_machines.facts_of("linux-vm-small")
    assert small["virtualization"]["vm"] and small["memory"]["usable"] == 2 * 2**30
    assert needs_machines.facts_of("windows-11-home")["windows"]["server"] is False
    assert needs_machines.facts_of("windows-server-hyperv")["windows"]["server"] is True
    assert needs_machines.facts_of("windows-arm-hyperv-off")["architecture"] == "arm64"
    assert needs_machines.facts_of("windows-proxy")["internet"]["state"] == "unknown"
    assert needs_machines.facts_of("windows-ncsi-sunk")["internet"]["state"] == "unknown"
    with pytest.raises(KeyError):
        needs_machines.facts_of("nowhere")


def test_no_host_name_is_written_here():
    tree = ast.parse(Path(needs_machines.__file__).read_text(encoding="utf-8"))
    host = re.compile(r"\b[a-z0-9-]+\.(com|net|org|io|dev|cloud)\b", re.IGNORECASE)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert "://" not in node.value and not host.search(node.value), node.value
