"""The eBPF layer (liminal_libs.ebpf): the Linux and Windows runtimes read through stand-in bpftool, service and
signing runners; the capabilities comparison carries no outside host; a BpftraceWatch parses recorded bpftrace JSON
into a bounded ring, stops itself after its timeout, and ends and reaps its process on stop. The bpftrace scripts
themselves run here in `BpftraceSim`, a small bpftrace over recorded kernel events, so what they print is checked,
not only their text. Nothing real is ever started: every runner and every bpftrace process is a stand-in."""
from __future__ import annotations

import itertools
import json
import operator
import queue
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

import liminal_libs.ebpf as ebpf
import liminal_libs.ebpf.watch as watchmod
from liminal_libs.ebpf import capabilities
from liminal_libs.ebpf.linux import LinuxRuntime
from liminal_libs.ebpf.watch import BpftraceWatch, Event, Watch, make_watch, watch_system
from liminal_libs.ebpf.windows import WindowsRuntime
from liminal_libs.machines.linux import Shell
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.windows import PowerShell, decoded

EBPF_DIR = Path(ebpf.__file__).resolve().parent


# -- capabilities: no outside host ---------------------------------------------------------------------------

def test_the_capabilities_rows_name_no_host_or_url():
    scheme = re.compile(r"(?:https?|wss?|ftp)://", re.I)
    domain = re.compile(r"\b[a-z0-9-]+\.(?:com|org|io|net|dev|gov|edu|mil|co|uk|us)\b", re.I)
    assert len(capabilities.CAPABILITIES) > 20
    for c in capabilities.CAPABILITIES:
        blob = " ".join((c.area, c.item, c.linux, c.windows))
        assert not scheme.search(blob), c.item
        assert not domain.search(blob), (c.item, domain.search(blob).group())
        assert set(c.as_dict()) == {"area", "item", "linux", "windows"}  # no source field in the library
    # the Linux and Windows cells are both filled, so the comparison really compares
    assert all(c.linux and c.windows for c in capabilities.CAPABILITIES)
    rows = capabilities.rows()
    assert rows == ebpf.Runtime().capabilities() and rows[0]["area"] == "Install and status"
    by_area = capabilities.by_area()
    assert [g["area"] for g in by_area] == list(capabilities.AREAS)
    assert sum(len(g["rows"]) for g in by_area) == len(rows)


def test_no_url_in_any_ebpf_source_file():
    scheme = re.compile(r"(?:https?|wss?|ftp)://", re.I)
    files = list(EBPF_DIR.rglob("*.py")) + list(EBPF_DIR.rglob("*.bt"))
    assert len(files) >= 9  # six modules, three scripts
    for path in files:
        assert not scheme.search(path.read_text(encoding="utf-8")), path.name


# -- Linux runtime: bpftool through a stand-in shell ---------------------------------------------------------

VERSION = {"version": "7.8.1", "libbpf_version": "1.8.0", "features": {"libbfd": True, "skeletons": True, "llvm": False}}
PROGS = [{"id": 12, "type": "cgroup_sock_addr", "name": "connect4", "tag": "a1b2"},
         {"id": 13, "type": "sock_ops", "name": "track", "tag": "c3d4"}]
MAPS = [{"id": 5, "type": "lru_hash", "name": "flows", "max_entries": 1024}]
LINKS = [{"id": 2, "type": "cgroup", "prog_id": 12, "attach_type": "connect4"}]
MAPDUMP = [{"key": ["0x0a", "0x00"], "value": ["0x01"]}]


def _tail(args):
    a = list(args)
    return a[2:] if a[:2] == ["sudo", "-n"] else a


def linux_runner(replies=None):
    seen = []

    def runner(args, timeout):
        seen.append(list(args))
        tail = _tail(args)
        joined = " ".join(tail)
        if tail[:2] == ["sh", "-c"]:  # a read bounded by `| head -c N` (the map dump): the command before the pipe
            joined = tail[2].split(" 2>&1")[0].split(" |")[0]
        table = {
            "uname -r": "6.8.0-48-generic\n",
            "bpftrace -V": "bpftrace v0.21.2\n",
            "cat /proc/sys/kernel/unprivileged_bpf_disabled": "2\n",
            "cat /proc/sys/net/core/bpf_jit_enable": "1\n",
            "bpftool -j version": json.dumps(VERSION),
            "bpftool -j prog show": json.dumps(PROGS),
            "bpftool -j map show": json.dumps(MAPS),
            "bpftool -j link show": json.dumps(LINKS),
            "bpftool -j prog show id 12": json.dumps([PROGS[0]]),
            "bpftool -j map dump id 5": json.dumps(MAPDUMP),
        }
        if replies and joined in replies:
            return replies[joined]
        if joined in table:
            return 0, table[joined], ""
        return 0, "ok\n", ""

    return runner, seen


def test_linux_runtime_reads_status_programs_maps_and_links():
    runner, seen = linux_runner()
    rt = LinuxRuntime(Shell("local", runner=runner), system="linux", release="6.8.0-48-generic", env={})
    assert rt.applies() == (True, "")
    status = rt.status()
    assert status["present"] and status["applies"] and status["kernel"] == "6.8.0-48-generic"
    assert status["bpftool"] == "7.8.1" and status["libbpf"] == "1.8.0" and "skeletons" in status["features"]
    assert status["unprivileged_bpf_disabled"] == 2 and status["bpf_jit_enable"] == 1
    assert status["bpftrace_present"] and "bpftrace" in status["summary"]
    # the /proc reads and tool versions are read without root; bpftool show goes through sudo -n
    assert ["uname", "-r"] in seen and ["cat", "/proc/sys/kernel/unprivileged_bpf_disabled"] in seen
    assert rt.programs() == PROGS and rt.maps() == MAPS and rt.links() == LINKS
    assert rt.program(12) == PROGS[0] and rt.dump_map(5) == MAPDUMP
    assert ["sudo", "-n", "bpftool", "-j", "prog", "show"] in seen


def test_linux_runtime_builds_the_confirmed_change_commands():
    runner, seen = linux_runner()
    rt = LinuxRuntime(Shell("local", runner=runner), system="linux", release="6.8.0-48-generic", env={})
    rt.load("/tmp/track.o", type="sock_ops")  # pinned as Liminal's own unless said: /sys/fs/bpf/liminal_<stem>
    assert ["sudo", "-n", "bpftool", "prog", "load", "/tmp/track.o", "/sys/fs/bpf/liminal_track", "type", "sock_ops"] in seen
    rt.attach(kind="connect4", target="/sys/fs/cgroup", pin="/sys/fs/bpf/track")
    assert ["sudo", "-n", "bpftool", "cgroup", "attach", "/sys/fs/cgroup", "connect4", "pinned", "/sys/fs/bpf/track"] in seen
    rt.attach(kind="xdp", target="eth0", prog_id=12)
    assert ["sudo", "-n", "bpftool", "net", "attach", "xdp", "id", "12", "dev", "eth0"] in seen
    rt.detach(link_id=2)
    assert ["sudo", "-n", "bpftool", "link", "detach", "id", "2"] in seen
    rt.unload(pin="/sys/fs/bpf/track")
    assert ["sudo", "-n", "rm", "-f", "/sys/fs/bpf/track"] in seen
    with pytest.raises(CommandError):
        rt.attach(kind="connect4", target="/sys/fs/cgroup")  # no program named
    with pytest.raises(CommandError):
        rt.unload()


def test_linux_runtime_is_for_linux_and_not_for_windows():
    """On Windows it does not apply. On Linux it does, inside a WSL distribution too since 1.57.0 (the user,
    2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some capability
    this should reflect in the plugin": machines.linux.why_not_native no longer refuses a WSL kernel)."""
    runner, _ = linux_runner()
    on_windows = LinuxRuntime(Shell("local", runner=runner), system="win32", release="10", env={})
    applies, why = on_windows.applies()
    assert not applies and "this one runs Windows" in why
    status = on_windows.status()
    assert status == {"present": False, "system": "linux", "applies": False, "version": "", "why": why,
                      "summary": "not for this machine"}
    in_wsl = LinuxRuntime(Shell("local", runner=runner), system="linux",
                          release="6.6-microsoft-standard-WSL2", env={"WSL_DISTRO_NAME": "Liminal-Ubuntu"})
    assert in_wsl.applies() == (True, "")  # Linux like any other: what WSL lacks is said by what it reads


def test_linux_runtime_says_when_bpftool_is_missing():
    def runner(args, timeout):
        tail = _tail(args)
        if tail[:2] == ["bpftool", "-j"]:
            return 1, "", "bpftool: command not found"
        if tail == ["uname", "-r"]:
            return 0, "6.8.0\n", ""
        return 0, "", ""
    rt = LinuxRuntime(Shell("local", runner=runner), system="linux", release="6.8.0", env={})
    status = rt.status()
    assert not status["present"] and "bpftool did not answer" in status["why"]


# -- Windows runtime: service, netsh and signing through a stand-in PowerShell -------------------------------

def win_runner(services, version="1.7.0", programs="", facts=None, deny_netsh=False):
    seen = []

    def runner(args, timeout):
        script = decoded(args[6])
        seen.append(script)
        if "Get-Service" in script and "eBPFCore" in script:
            payload = {"Services": services, "Version": version}
            return 0, json.dumps(payload), ""
        if "netsh ebpf show programs" in script:
            if deny_netsh:
                return 1, "LIMINAL-ERROR: Access is denied.\r\n", ""
            return 0, programs, ""
        if "Confirm-SecureBootUEFI" in script:
            return 0, json.dumps(facts or {}), ""
        return 0, "", ""

    return runner, seen


def _svc(name, present=True, status="Running", start="Auto"):
    return {"Name": name, "Present": present, "Status": status if present else "", "StartType": start if present else ""}


NETSH_PROGRAMS = (
    "\n    ID  Pins  Links  Mode    Type            Name\n"
    "========  ====  =====  ======  ==============  ==========\n"
    "       1     1      1  JIT     sock_ops        track\n"
    "       2     0      1  NATIVE  bind            guard\n")


def test_windows_runtime_reads_services_version_and_programs():
    services = [_svc("eBPFCore"), _svc("NetEbpfExt"), _svc("eBPFSvc", status="Stopped")]
    runner, seen = win_runner(services, version="1.7.0", programs=NETSH_PROGRAMS)
    rt = WindowsRuntime(PowerShell(runner=runner))
    status = rt.status()
    assert status["present"] and status["installed"] and status["version"] == "1.7.0"
    assert [s["name"] for s in status["services"]] == ["eBPFCore", "NetEbpfExt", "eBPFSvc"]
    assert status["services"][2]["status"] == "Stopped"
    assert "test-signed pre-release" in status["why"] and "installed" in status["summary"]
    # the core service runs, so the program listing was read and parsed to rows
    assert status["programs"] and status["programs"][0]["name"] == "track" and status["programs"][1]["type"] == "bind"
    assert any("Get-Service" in s for s in seen) and any("netsh ebpf show programs" in s for s in seen)


def test_windows_runtime_when_nothing_is_installed():
    services = [_svc(n, present=False) for n in ("eBPFCore", "NetEbpfExt", "eBPFSvc")]
    runner, seen = win_runner(services, version="")
    rt = WindowsRuntime(PowerShell(runner=runner))
    status = rt.status()
    assert not status["present"] and status["programs"] == []
    assert "not installed" in status["summary"]
    # with no core service, netsh is never asked
    assert not any("netsh ebpf show programs" in s for s in seen)


def test_windows_program_listing_needs_an_administrator():
    services = [_svc("eBPFCore"), _svc("NetEbpfExt"), _svc("eBPFSvc")]
    runner, _ = win_runner(services, programs="", deny_netsh=True)
    rt = WindowsRuntime(PowerShell(runner=runner))
    status = rt.status()
    assert status["present"] and status["programs"] == [] and "administrator" in status["programs_note"]
    assert rt.programs() == [] and rt.dump_map(5) == []


def test_windows_why_not_here_reads_secure_boot_hvci_and_test_signing():
    facts = {"SecureBoot": True, "SecureBootSource": "firmware", "Hvci": True,
             "TestSigning": False, "TestSigningReadable": True, "TestSigningSource": "boot options"}
    runner, _ = win_runner([_svc("eBPFCore")], facts=facts)
    rt = WindowsRuntime(PowerShell(runner=runner))
    why = rt.why_not_here()
    assert why["secure_boot"] is True and why["hvci"] is True and why["test_signing"] is False
    assert why["test_signing_readable"] is True and why["test_signing_source"] == "boot options"
    assert why["blocked"] is True
    assert "cannot load here" in why["words"] and "Secure Boot is on" in why["words"]
    assert "memory integrity is on" in why["words"] and "test-signed pre-release" in why["words"]
    assert "test signing is off, read from this boot's start options" in why["words"]


def test_windows_why_not_here_when_test_signing_is_on_and_integrity_off():
    facts = {"SecureBoot": False, "SecureBootSource": "registry", "Hvci": False,
             "TestSigning": True, "TestSigningReadable": True, "TestSigningSource": "bcdedit"}
    runner, _ = win_runner([_svc("eBPFCore")], facts=facts)
    why = WindowsRuntime(PowerShell(runner=runner)).why_not_here()
    assert why["blocked"] is False and "could load" in why["words"]
    assert "test signing is on, read from bcdedit's entry for this Windows" in why["words"]
    assert why["test_signing_source"] == "bcdedit"


def test_windows_why_not_here_when_facts_cannot_be_read():
    # null facts (nothing readable unelevated): tri-state stays None, and the caveat is still said
    runner, _ = win_runner([_svc("eBPFCore")], facts={"SecureBoot": None, "Hvci": None,
                                                      "TestSigning": None, "TestSigningReadable": False,
                                                      "TestSigningSource": "unknown"})
    why = WindowsRuntime(PowerShell(runner=runner)).why_not_here()
    assert why["secure_boot"] is None and why["hvci"] is None
    assert why["test_signing"] is None and not why["test_signing_readable"] and why["test_signing_source"] == "unknown"
    assert "could not be read" in why["words"] and "test-signed pre-release" in why["words"]
    assert "neither this boot's start options nor bcdedit answered" in why["words"]


def test_test_signing_is_never_said_from_a_read_with_no_source():
    # 1.60.0: unelevated, bcdedit printed an error where its entry goes, and that was read as test signing off.
    # A read carrying no source the script names, or no value, is no read at all: nothing is said of test signing from
    # it, not even in the verdict's head, which says what Secure Boot alone settles.
    for odd in ({"TestSigning": False, "TestSigningReadable": True},
                {"TestSigning": False, "TestSigningReadable": True, "TestSigningSource": "the screen"},
                {"TestSigning": None, "TestSigningReadable": True, "TestSigningSource": "boot options"}):
        runner, _ = win_runner([_svc("eBPFCore")], facts={"SecureBoot": True, "Hvci": True, **odd})
        why = WindowsRuntime(PowerShell(runner=runner)).why_not_here()
        assert why["test_signing"] is None and not why["test_signing_readable"]
        assert why["test_signing_source"] == "unknown" and "could not be read here" in why["words"]
        assert why["blocked"] is True and "test signing is off" not in why["words"]
        assert why["words"].startswith("the test-signed runtime cannot load here: Secure Boot is on, which keeps "
                                       "test-signing mode off (")


def test_the_facts_script_reads_this_boots_options_first_and_bcdedit_only_when_it_answered():
    # The registry's SystemStartOptions any user may read, and it is this boot's: TESTSIGNING while in test mode.
    # bcdedit only where it cannot be read, and its words only when it exited 0 and printed the {current} entry
    # (without an administrator it prints an error where the entry would be, its words differing between builds,
    # and exits 1).
    w = ebpf.windows
    script = w.FACTS_READ
    boot, bcd = script.index(f"-Name {w.BOOT_OPTIONS_VALUE}"), script.index("bcdedit /enum {current}")
    assert boot < bcd and "if (-not $out.TestSigningReadable)" in script[boot:bcd]
    assert "$LASTEXITCODE -eq 0 -and $bcd -match '\\{current\\}'" in script
    assert "TestSigningSource = 'boot options'" in script and "TestSigningSource = 'bcdedit'" in script
    assert set(w.SIGNING_SOURCES) == {"boot options", "bcdedit"}


def test_the_facts_script_reads_the_value_it_names_and_matches_test_signing_as_said():
    # Nothing starts PowerShell here, so the script's test-signing lines are pinned whole, and their patterns are tried
    # with Python's re on what Windows gives, ignoring case as PowerShell's -match does.
    w = ebpf.windows
    # Windows' own names, spelt out: a misspelt key or value reads nothing, and the read falls to bcdedit
    assert w.BOOT_OPTIONS_KEY == r"HKLM:\SYSTEM\CurrentControlSet\Control"
    assert w.BOOT_OPTIONS_VALUE == "SystemStartOptions"
    lines = [line.strip() for line in w.FACTS_READ.splitlines()]
    assert not any(mark in w.FACTS_READ for mark in ("@KEY@", "@VALUE@", "@OPTION@", "@BCD@"))
    assert (f"$control = Get-ItemProperty -Path '{w.BOOT_OPTIONS_KEY}' -Name {w.BOOT_OPTIONS_VALUE} -ErrorAction Stop"
            in lines)
    assert f"$opts = $control.{w.BOOT_OPTIONS_VALUE}" in lines
    boot_value = f"$out.TestSigning = [bool]([string]$opts -match '{w.TESTSIGNING_OPTION}')"
    bcd_value = f"$out.TestSigning = [bool]($bcd -match '{w.BCD_TESTSIGNING}')"
    # each value is worked out before the read is called readable: a match that throws leaves nothing said read
    # (and bcdedit still asked), never a source with no value
    assert lines.index(boot_value) + 1 == lines.index(
        "$out.TestSigningReadable = $true; $out.TestSigningSource = 'boot options'")
    assert lines.index(bcd_value) + 1 == lines.index(
        "$out.TestSigningReadable = $true; $out.TestSigningSource = 'bcdedit'")
    assert "-notmatch" not in w.FACTS_READ
    option = re.compile(w.TESTSIGNING_OPTION, re.IGNORECASE)
    assert option.search(" TESTSIGNING  NOEXECUTE=OPTIN") and option.search(" NOEXECUTE=OPTIN  testsigning")
    assert option.search("TESTSIGNING")
    assert not option.search(" NOEXECUTE=OPTIN  HYPERVISORLAUNCHTYPE=AUTO  FVEBOOT=2666496  NOVGA")  # this PC's
    assert not option.search(" NOTESTSIGNING  NOVGA") and not option.search(" TESTSIGNINGS")
    entry = ("Windows Boot Loader\r\n-------------------\r\nidentifier              {current}\r\n"
             "testsigning             Yes\r\nnx                      OptIn\r\n")
    bcd = re.compile(w.BCD_TESTSIGNING, re.IGNORECASE)
    assert bcd.search(entry) and not bcd.search(entry.replace("Yes", "No"))


# -- the watch base and the bpftrace backend -----------------------------------------------------------------

def bpftrace_line(**fields) -> str:
    """One bpftrace -f json printf line wrapping our event object, as bpftrace emits it."""
    return json.dumps({"type": "printf", "data": json.dumps(fields)})


class FakeProc:
    """A stand-in bpftrace process: yields the recorded lines, then blocks until killed (as a live one would). No
    real process is ever started."""

    def __init__(self, lines):
        self._q: queue.Queue = queue.Queue()
        for ln in lines:
            self._q.put(ln)
        self.killed = threading.Event()
        self.kills = 0

    @property
    def stdout(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            try:
                return self._q.get(timeout=0.02)
            except queue.Empty:
                if self.killed.is_set():
                    raise StopIteration

    def feed(self, line):
        self._q.put(line)

    def kill(self):
        self.kills += 1
        self.killed.set()


def _wait(predicate, seconds=3.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_bpftrace_watch_parses_lines_into_events_and_builds_the_command():
    proc = FakeProc([
        json.dumps({"type": "attached_probes", "data": {"probes": 4}}),  # skipped
        bpftrace_line(evt="net", act="connect", pid=900, comm="curl", proto="tcp",
                      saddr="10.0.0.2", sport=51000, daddr="93.1.2.3", dport=443),
        bpftrace_line(evt="process", act="exec", pid=901, ppid=900, comm="sh", path="/bin/sh"),
        bpftrace_line(evt="file", act="open", pid=901, comm="sh", path="/etc/hosts", flags=0),
        "not json at all",  # skipped
    ])
    made = []
    w = BpftraceWatch({"net", "process", "file"}, runner=lambda argv: made.append(argv) or proc, timeout=5.0)
    assert w.argv()[:6] == ["sudo", "-n", "bpftrace", "-f", "json", "-e"]
    assert "inet_sock_set_state" in w.script() and "sched_process_exec" in w.script() and "sys_enter_openat" in w.script()
    w.start()
    assert _wait(lambda: w.read(0)[0] == 3), "all three events parsed"
    seq, events = w.read(0)
    assert seq == 3 and [e.kind for e in events] == ["net", "process", "file"]
    net = events[0]
    assert net.action == "connect" and net.pid == 900 and net.program == "curl" and net.proto == "tcp"
    assert net.remote == "93.1.2.3:443" and net.local == "10.0.0.2:51000"
    assert events[1].ppid == 900 and events[1].path == "/bin/sh"
    assert events[2].extra == {"flags": 0}
    # read since a sequence returns only the newer ones
    assert w.read(2)[1] == [events[2]]
    w.stop()
    assert proc.kills == 1 and made and made[0][2] == "bpftrace"


def test_bpftrace_watch_ring_is_bounded():
    proc = FakeProc([bpftrace_line(evt="net", act="connect", pid=i, comm="x", proto="tcp") for i in range(5)])
    w = BpftraceWatch({"net"}, runner=lambda argv: proc, ring=3, timeout=5.0)
    w.start()
    assert _wait(lambda: w.read(0)[0] == 5), "five events seen"
    seq, events = w.read(0)
    assert seq == 5 and len(events) == 3 and [e.seq for e in events] == [3, 4, 5]  # only the last three kept
    w.stop()


def test_a_watch_stops_itself_after_its_timeout_and_leaves_no_thread():
    proc = FakeProc([bpftrace_line(evt="net", act="connect", pid=1, comm="x", proto="tcp")])
    w = BpftraceWatch({"net"}, runner=lambda argv: proc, timeout=0.15)
    w.start()
    assert _wait(lambda: w.read(0)[0] == 1)
    assert _wait(lambda: w.stopped, seconds=3.0), "self-stopped after the viewing timeout"
    assert proc.kills == 1  # the process was killed when it stopped itself
    assert _wait(lambda: not any(t.name in ("ebpf-watch", "ebpf-bpftrace") and t.is_alive()
                                 for t in threading.enumerate())), "no watcher thread left behind"


def test_a_watch_kills_its_process_on_stop_and_touch_keeps_it_alive():
    proc = FakeProc([])
    w = BpftraceWatch({"net"}, runner=lambda argv: proc, timeout=0.2, clock=time.monotonic)
    w.start()
    # touch repeatedly across more than the timeout: it must not self-stop while touched
    for _ in range(6):
        time.sleep(0.05)
        w.touch()
        assert not w.stopped
    w.stop()
    assert w.stopped and proc.kills == 1
    w.stop()  # idempotent
    assert proc.kills == 1


def test_event_as_dict_round_trips_the_fields():
    e = Event(1, 12.5, "net", "connect", pid=5, ppid=4, program="curl", remote="1.2.3.4:443", proto="tcp", bytes=120)
    d = e.as_dict()
    assert d["seq"] == 1 and d["kind"] == "net" and d["remote"] == "1.2.3.4:443" and d["bytes"] == 120
    assert set(d) == {"seq", "time", "kind", "action", "pid", "ppid", "program", "path", "local", "remote",
                      "proto", "bytes", "extra"}


def test_make_watch_picks_the_backend_for_the_machine():
    assert watch_system(system="linux") == "linux" and watch_system(system="windows") == "windows"

    class R:
        system = "linux"

    assert watch_system(R()) == "linux"
    w = make_watch({"net"}, {"peer": "x"}, system="linux")
    assert isinstance(w, BpftraceWatch) and w.kinds == frozenset({"net"}) and w.spec == {"peer": "x"}
    assert not w.stopped  # nothing started until start()


def test_an_empty_or_registry_only_watch_has_a_valid_script():
    # registry has no Linux script; the script falls back to a valid no-op probe rather than empty
    w = BpftraceWatch({"registry"}, runner=lambda argv: FakeProc([]))
    assert w.script().strip() != "" and "BEGIN" in w.script()
    assert isinstance(w, Watch)


# -- a small bpftrace, to run the real scripts over recorded kernel events -----------------------------------

class U16(int):
    """A 16-bit value as read from the kernel (a port in network order), so bswap knows its width."""


_BT_TOKEN = re.compile(r"""
    (?P<ws>\s+|//[^\n]*)
  | (?P<str>"(?:\\.|[^"\\\n])*")
  | (?P<num>0x[0-9a-fA-F]+|\d+)
  | (?P<pos>\$\d+)
  | (?P<var>\$[A-Za-z_]\w*)
  | (?P<map>@[A-Za-z_]\w*)
  | (?P<id>[A-Za-z_]\w*)
  | (?P<op>->|==|!=|<=|>=|&&|\|\||[{}()\[\];,.:/=<>!&+\-*])
""", re.X)
_BT_TYPES = {"uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64"}
_BT_BUILTINS = {"pid", "tid", "comm", "nsecs", "arg0", "arg1", "args", "curtask"}
_BT_FUNCS = {"printf", "str", "ntop", "bswap", "delete", "clear"}
_BT_ATTACH = re.compile(r"(?:tracepoint:\w+:\w+|kprobe:\w+|interval:s:\d+|BEGIN|END)$")
_BT_OPS = {"==": operator.eq, "!=": operator.ne, "<": operator.lt, ">": operator.gt, "<=": operator.le,
           ">=": operator.ge, "&": operator.and_, "+": operator.add, "-": operator.sub}


def _bt_unescape(body: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), body)


class _BTParser:
    """The part of the bpftrace language our scripts use, and nothing more: what it does not know it refuses, so a
    script cannot drift into syntax these tests were not written for."""

    def __init__(self, text: str):
        self.toks, pos = [], 0
        while pos < len(text):
            m = _BT_TOKEN.match(text, pos)
            if m is None:
                raise SyntaxError(f"bpftrace: cannot read {text[pos:pos + 30]!r}")
            pos = m.end()
            if m.lastgroup != "ws":
                self.toks.append((m.lastgroup, m.group()))
        self.i = 0

    def peek(self, k: int = 0):
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else (None, None)

    def at(self, value) -> bool:
        return self.peek()[1] == value

    def take(self, value=None) -> str:
        tok = self.peek()
        if tok[0] is None or (value is not None and tok[1] != value):
            raise SyntaxError(f"bpftrace: wanted {value!r}, found {tok[1]!r}")
        self.i += 1
        return tok[1]

    def program(self):
        probes = []
        while self.peek()[0] is not None:
            attach = ""
            while not (self.at("/") or self.at("{")):
                kind, value = self.peek()
                if kind not in ("id", "num") and value != ":":
                    raise SyntaxError(f"bpftrace: a probe name, not {value!r}")
                attach += self.take()
            if not _BT_ATTACH.match(attach):
                raise SyntaxError(f"bpftrace: no probe {attach!r} here")
            predicate = None
            if self.at("/"):
                self.take("/")
                predicate = self.expr()
                self.take("/")
            probes.append((attach, predicate, self.block()))
        return probes

    def block(self):
        self.take("{")
        body = []
        while not self.at("}"):
            body.append(self.statement())
        self.take("}")
        return body

    def statement(self):
        if self.at("if"):
            self.take("if")
            self.take("(")
            cond = self.expr()
            self.take(")")
            then, other = self.block(), []
            if self.at("else"):
                self.take("else")
                other = [self.statement()] if self.at("if") else self.block()
            return ("if", cond, then, other)
        target = self.postfix()
        if self.at("="):
            if target[0] not in ("var", "map"):
                raise SyntaxError("bpftrace: only a variable or a map takes a value")
            self.take("=")
            value = self.expr()
            self.take(";")
            return ("set", target, value)
        if target[0] != "call":
            raise SyntaxError("bpftrace: a statement is an if, an assignment or a call")
        self.take(";")
        return ("do", target)

    def expr(self):
        node = self.conj()
        while self.at("||"):
            self.take()
            node = ("or", node, self.conj())
        return node

    def conj(self):
        node = self.comparison()
        while self.at("&&"):
            self.take()
            node = ("and", node, self.comparison())
        return node

    def comparison(self):
        node = self.bits()
        if self.peek()[1] in ("==", "!=", "<", ">", "<=", ">="):
            op = self.take()
            node = ("bin", op, node, self.bits())
        return node

    def bits(self):
        node = self.sum()
        while self.at("&"):
            self.take()
            node = ("bin", "&", node, self.sum())
        return node

    def sum(self):
        node = self.unary()
        while self.peek()[1] in ("+", "-"):
            op = self.take()
            node = ("bin", op, node, self.unary())
        return node

    def unary(self):
        if self.at("!"):
            self.take()
            return ("not", self.unary())
        if self.at("(") and (self.peek(1)[1] in _BT_TYPES or self.peek(1)[1] == "struct"):
            self.take("(")
            if self.at("struct"):
                self.take("struct")
                kind = f"struct {self.take()} *"
                self.take("*")
            else:
                kind = self.take()
            self.take(")")
            return ("cast", kind, self.unary())
        return self.postfix()

    def postfix(self):
        node = self.primary()
        while True:
            if self.at("->") or self.at("."):
                self.take()
                if self.peek()[0] != "id":
                    raise SyntaxError("bpftrace: a field name")
                node = ("field", node, self.take())
            elif self.at("[") and node[0] != "map":
                self.take("[")
                index = self.expr()
                self.take("]")
                node = ("index", node, index)
            else:
                return node

    def primary(self):
        kind, value = self.peek()
        if kind == "num":
            self.take()
            return ("num", int(value, 16) if value.startswith("0x") else int(value))
        if kind == "str":
            self.take()
            return ("str", _bt_unescape(value[1:-1]))
        if kind == "pos":
            self.take()
            return ("pos", int(value[1:]))
        if kind == "var":
            self.take()
            return ("var", value)
        if kind == "map":
            self.take()
            keys = []
            if self.at("["):
                self.take("[")
                keys.append(self.expr())
                while self.at(","):
                    self.take()
                    keys.append(self.expr())
                self.take("]")
            return ("map", value, tuple(keys))
        if kind == "id" and self.peek(1)[1] == "(":
            if value not in _BT_FUNCS:
                raise SyntaxError(f"bpftrace: no function {value!r} here")
            self.take()
            self.take("(")
            args = []
            if not self.at(")"):
                args.append(self.expr())
                while self.at(","):
                    self.take()
                    args.append(self.expr())
            self.take(")")
            return ("call", value, tuple(args))
        if kind == "id" and value in _BT_BUILTINS:
            self.take()
            return ("builtin", value)
        if value == "(":
            self.take()
            node = self.expr()
            self.take(")")
            return node
        raise SyntaxError(f"bpftrace: did not expect {value!r}")


def _bt_ntop(af, addr) -> str:
    """bpftrace's ntop: IPv4 from a network-order integer or from bytes, IPv6 from bytes. Given fewer bytes than the
    family needs, the rest of its buffer is zeros (so a 4-byte field read as IPv6 comes out as 4 bytes and 12
    zeros, as bpftrace does)."""
    raw = (int(addr) & 0xFFFFFFFF).to_bytes(4, "little") if isinstance(addr, int) else bytes(addr)
    if af == 2:
        return socket.inet_ntop(socket.AF_INET, (raw + bytes(4))[:4])
    if af == 10:
        return socket.inet_ntop(socket.AF_INET6, (raw + bytes(16))[:16])
    raise ValueError(f"ntop: family {af}")


class BpftraceSim:
    """Runs a bpftrace program, as the watch builds it, over recorded kernel events. `fire(probe, **ctx)` runs each
    block of that probe whose predicate holds, `ctx` giving the builtins (pid, tid, comm, args, arg0, curtask) and
    `mem` the kernel structs a pointer cast reads; it returns the lines printed. Maps behave as bpftrace's: a
    missing key reads 0 ("" for a map of strings), and a map at max_map_keys (4096) takes no new key. It holds the
    program to bpftrace's own rules too: one BEGIN and one END at most, no map read that the program never writes,
    one key count per map, a variable read only inside the block that set it, printf's conversions matching its
    arguments, and $N only when the command line passes it."""

    MAX_KEYS = 4096

    def __init__(self, script: str, params=()):
        self.probes = _BTParser(script).program()
        self.params = [str(p) for p in params]
        self.maps: dict[str, dict] = {}
        self.strings: set[str] = set()
        self.out: list[str] = []
        self._check()

    def _check(self) -> None:
        attaches = [p[0] for p in self.probes]
        assert attaches.count("BEGIN") <= 1 and attaches.count("END") <= 1, "bpftrace takes one BEGIN and one END"
        written, used, arity = set(), set(), {}

        def walk(node, role="use"):
            if isinstance(node, list):
                for n in node:
                    walk(n)
            elif isinstance(node, tuple) and node:
                if node[0] == "map":
                    (written if role == "set" else used).add(node[1])
                    if role != "clear":
                        arity.setdefault(node[1], set()).add(len(node[2]))
                    walk(list(node[2]))
                elif node[0] == "set":
                    walk(node[1], "set")
                    walk(node[2])
                elif node[0] == "call" and node[1] == "clear":
                    walk(node[2][0], "clear")
                else:
                    for part in node[1:]:
                        walk(part)

        for _, predicate, body in self.probes:
            walk(predicate)
            walk(body)
        assert not used - written, f"maps read but never written (undefined in bpftrace): {sorted(used - written)}"
        mixed = {m: k for m, k in arity.items() if len(k) > 1}
        assert not mixed, f"maps used with different key counts: {mixed}"

    def fire(self, probe: str, mem=None, **ctx) -> list[str]:
        ctx["mem"] = mem or {}
        start = len(self.out)
        for attach, predicate, body in self.probes:
            if attach != probe:
                continue
            scopes = [{}]
            if predicate is not None and not self._eval(predicate, ctx, scopes):
                continue
            self._run(body, ctx, scopes)
        return self.out[start:]

    def held(self) -> dict:
        """The maps that still hold something (what bpftrace would print as it exits)."""
        return {name: m for name, m in self.maps.items() if m}

    def _run(self, body, ctx, scopes) -> None:
        for st in body:
            if st[0] == "if":
                branch = st[2] if self._eval(st[1], ctx, scopes) else st[3]
                scopes.append({})
                try:
                    self._run(branch, ctx, scopes)
                finally:
                    scopes.pop()
            elif st[0] == "set":
                target, value = st[1], self._eval(st[2], ctx, scopes)
                if target[0] == "var":
                    for scope in reversed(scopes):
                        if target[1] in scope:
                            scope[target[1]] = value
                            break
                    else:
                        scopes[-1][target[1]] = value
                else:
                    m = self.maps.setdefault(target[1], {})
                    key = self._key(target, ctx, scopes)
                    if key in m or len(m) < self.MAX_KEYS:
                        m[key] = value
                    if isinstance(value, str):
                        self.strings.add(target[1])
            else:
                self._eval(st[1], ctx, scopes)

    def _key(self, node, ctx, scopes):
        return tuple(self._eval(k, ctx, scopes) for k in node[2])

    def _eval(self, node, ctx, scopes):
        tag = node[0]
        if tag in ("num", "str"):
            return node[1]
        if tag == "pos":
            assert node[1] <= len(self.params), f"${node[1]} is read but the command line passes none"
            text = self.params[node[1] - 1]
            return int(text) if text.isdigit() else text
        if tag == "var":
            for scope in reversed(scopes):
                if node[1] in scope:
                    return scope[node[1]]
            raise NameError(f"{node[1]} is read outside the block that set it")
        if tag == "map":
            return self.maps.get(node[1], {}).get(self._key(node, ctx, scopes),
                                                  "" if node[1] in self.strings else 0)
        if tag == "builtin":
            assert node[1] in ctx, f"this probe has no {node[1]} here"
            return ctx[node[1]]
        if tag == "field":
            return self._eval(node[1], ctx, scopes)[node[2]]
        if tag == "index":
            return self._eval(node[1], ctx, scopes)[self._eval(node[2], ctx, scopes)]
        if tag == "cast":
            value = self._eval(node[2], ctx, scopes)
            if node[1].startswith("struct "):
                return ctx["mem"][value]
            bits = int(re.sub(r"\D", "", node[1]))
            value = int(value) & ((1 << bits) - 1)
            return value - (1 << bits) if node[1].startswith("int") and value >= 1 << (bits - 1) else value
        if tag == "not":
            return int(not self._eval(node[1], ctx, scopes))
        if tag == "or":
            return int(bool(self._eval(node[1], ctx, scopes)) or bool(self._eval(node[2], ctx, scopes)))
        if tag == "and":
            return int(bool(self._eval(node[1], ctx, scopes)) and bool(self._eval(node[2], ctx, scopes)))
        if tag == "bin":
            left, right = self._eval(node[2], ctx, scopes), self._eval(node[3], ctx, scopes)
            assert isinstance(left, str) == isinstance(right, str), f"bpftrace: {left!r} {node[1]} {right!r}"
            return int(_BT_OPS[node[1]](left, right))
        if tag == "call":
            return self._call(node[1], node[2], ctx, scopes)
        raise SyntaxError(tag)

    def _call(self, name, args, ctx, scopes):
        if name == "printf":
            assert args and args[0][0] == "str", "printf takes a literal format"
            fmt, values = args[0][1], [self._eval(a, ctx, scopes) for a in args[1:]]
            specs = [s for s in re.findall(r"%[-+ 0-9.]*[a-zA-Z%]", fmt) if s != "%%"]
            assert len(specs) == len(values), f"printf: {len(specs)} conversions, {len(values)} arguments"
            for spec, value in zip(specs, values):
                assert (spec[-1] == "s") == isinstance(value, str), f"printf: {spec} given {value!r}"
            self.out.append((fmt % tuple(values)).rstrip("\n"))
            return 0
        if name in ("delete", "clear"):
            (target,) = args
            assert target[0] == "map" and bool(target[2]) == (name == "delete"), f"{name}() of {target}"
            m = self.maps.setdefault(target[1], {})
            if name == "delete":
                m.pop(self._key(target, ctx, scopes), None)
            else:
                m.clear()
            return 0
        if name == "str":
            (arg,) = args
            value = self._eval(arg, ctx, scopes)
            assert isinstance(value, str)
            return value[:63]  # bpftrace's default string length, 64 with its NUL
        if name == "ntop":
            af, addr = (self._eval(a, ctx, scopes) for a in args)
            return _bt_ntop(af, addr)
        if name == "bswap":
            (arg,) = args
            value = self._eval(arg, ctx, scopes)
            assert isinstance(value, U16), "bswap of a 16-bit port, here"
            return int.from_bytes(int(value).to_bytes(2, "little"), "big")
        raise SyntaxError(name)


# Recorded kernel events, as the tracepoints and kprobes see them.

def _v6(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip)


def _be32(raw: bytes) -> int:
    """Four address bytes as the kernel keeps them (network order), read as a little-endian u32."""
    return int.from_bytes(raw, "little")


def _in6(raw: bytes) -> dict:
    return {"in6_u": {"u6_addr8": raw, "u6_addr32": [_be32(raw[i:i + 4]) for i in range(0, 16, 4)]}}


def opened(pid, comm, path, flags=0, tid=None):
    return {"pid": pid, "tid": tid or pid, "comm": comm, "args": {"filename": path, "flags": flags}}


def forked(parent, child, comm="make"):
    return {"pid": parent, "tid": parent, "comm": comm, "args": {"parent_pid": parent, "child_pid": child}}


def ended(pid, tid=None, comm="x", ppid=1):
    return {"pid": pid, "tid": tid or pid, "comm": comm, "curtask": {"real_parent": {"tgid": ppid}}}


def execd(pid, ppid, comm, path):
    return {"pid": pid, "tid": pid, "comm": comm, "args": {"filename": path},
            "curtask": {"real_parent": {"tgid": ppid}}}


def tcp_change(old, new, *, family=2, src="10.0.0.2", dst="93.1.2.3", sport=51000, dport=443, sk=0xffff0001,
               pid=0, comm="swapper/0", four=None):
    """An inet_sock_set_state record as the kernel fills it: saddr/daddr from inet_saddr/inet_daddr, and the
    16-byte fields from the v6 addresses for an AF_INET6 socket, v4-mapped for an AF_INET one. For an AF_INET6
    socket the 4-byte fields hold 0 for a native peer (tcp_v6_connect never sets them), the IPv4 address for a
    v4-mapped one, or whatever `four` says (127.0.0.6 on accept)."""
    if family == 2:
        s4, d4 = socket.inet_aton(src), socket.inet_aton(dst)
        s6, d6 = _v6("::ffff:" + src), _v6("::ffff:" + dst)
    else:
        s6, d6 = _v6(src), _v6(dst)
        mapped = s6[:12] == bytes(10) + b"\xff\xff"
        s4, d4 = (s6[12:], d6[12:]) if mapped else (bytes(4), bytes(4))
        if four is not None:
            s4 = d4 = four
    args = {"skaddr": sk, "oldstate": old, "newstate": new, "sport": sport, "dport": dport, "family": family,
            "protocol": 6, "saddr": s4, "daddr": d4, "saddr_v6": s6, "daddr_v6": d6}
    return {"pid": pid, "tid": pid, "comm": comm, "args": args}


def udp_send(sk, *, family=2, src="10.0.0.2", dst="1.1.1.1", sport=40000, dport=53, pid=700, comm="resolved"):
    """A udp_sendmsg / udpv6_sendmsg call: arg0 the socket, its sock_common in `mem`."""
    if family == 2:
        s4, d4, s6, d6 = socket.inet_aton(src), socket.inet_aton(dst), bytes(16), bytes(16)
    else:
        s6, d6 = _v6(src), _v6(dst)
        mapped = d6[:12] == bytes(10) + b"\xff\xff"
        s4, d4 = (s6[12:], d6[12:]) if mapped else (bytes(4), bytes(4))
    common = {"skc_family": family, "skc_daddr": _be32(d4), "skc_rcv_saddr": _be32(s4), "skc_num": sport,
              "skc_dport": U16(int.from_bytes(dport.to_bytes(2, "big"), "little")),
              "skc_v6_rcv_saddr": _in6(s6), "skc_v6_daddr": _in6(d6)}
    return {"pid": pid, "tid": pid, "comm": comm, "arg0": sk, "mem": {sk: {"__sk_common": common}}}


def sim_for(kinds, spec=None):
    """The program the watch would run for these kinds and spec, loaded in the simulator with the parameters its
    command line passes; and that command line."""
    argv = BpftraceWatch(kinds, spec).argv()
    assert argv[:6] == ["sudo", "-n", "bpftrace", "-f", "json", "-e"]
    return BpftraceSim(argv[6], argv[7:]), argv


def watch_of(lines, kinds=("net", "process", "file")):
    """A watch that has read these script lines (wrapped as bpftrace -f json prints them), every one an event."""
    proc = FakeProc([json.dumps({"type": "printf", "data": ln + "\n"}) for ln in lines])
    w = BpftraceWatch(set(kinds), runner=lambda argv: proc, timeout=5.0)
    w.start()
    assert _wait(lambda: w.read(0)[0] == len(lines)), "every line read"
    return w


OPENAT = "tracepoint:syscalls:sys_enter_openat"
TCP_CHANGE = "tracepoint:sock:inet_sock_set_state"


# -- file.bt: low-rate (F1) ----------------------------------------------------------------------------------

def test_file_opens_machine_wide_are_low_rate_and_leave_room_for_the_rest():
    # F1: one line per openat machine-wide let a build's burst of opens push the rare exec and connect events out
    # of the ring. Now: a program's path once, at most 50 lines a second, and the rest said as a count.
    sim, argv = sim_for({"net", "process", "file"})
    assert argv[7:] == ["0"]  # no target: $1 is 0, every process
    sim.fire("tracepoint:sched:sched_process_exec", **execd(901, 900, "cc1", "/usr/lib/gcc/cc1"))
    sim.fire(TCP_CHANGE, **tcp_change(7, 2, pid=900, comm="cargo"))
    sim.fire(TCP_CHANGE, **tcp_change(2, 1))
    burst = [sim.fire(OPENAT, **opened(901, "cc1", f"/tmp/b/{i}.o", flags=0o1101)) for i in range(2500)]
    assert sum(len(lines) for lines in burst) == 50
    assert [json.loads(x) for x in sim.fire("interval:s:1")] == [{"evt": "file", "act": "skipped", "count": 2450}]
    # the next second: the same header opened 300 times is one line, and a second way of opening it one more
    repeats = [sim.fire(OPENAT, **opened(901, "cc1", "/usr/include/stdio.h")) for _ in range(300)]
    assert sum(len(lines) for lines in repeats) == 1
    assert len(sim.fire(OPENAT, **opened(901, "cc1", "/usr/include/stdio.h", flags=0o101))) == 1
    assert sim.fire("interval:s:1") == []  # nothing held back this second
    # a minute on, the seen map is cleared: the header is said again, once
    sim.fire("interval:s:60")
    assert len(sim.fire(OPENAT, **opened(901, "cc1", "/usr/include/stdio.h"))) == 1
    # through the watch, with the default ring: the exec and the connect are still there
    w = watch_of(sim.out)
    seq, events = w.read(0)
    assert seq == len(sim.out) == 56
    assert any(e.kind == "process" and e.action == "exec" and e.pid == 901 for e in events)
    assert any(e.kind == "net" and e.action == "connect" and e.pid == 900 for e in events)
    assert [e.extra for e in events if e.action == "skipped"] == [{"count": 2450}]
    first = next(e for e in events if e.kind == "file" and e.action == "open")
    assert first.pid == 901 and first.program == "cc1" and first.path == "/tmp/b/0.o" and first.extra == {"flags": 577}
    w.stop()


def test_file_opens_follow_only_the_target_and_the_children_it_forks():
    # F1: trapdoor names the program it scopes; the watch passes it to bpftrace as $1 and the probe filters on it
    sim, argv = sim_for({"file"}, {"pid": 4242})
    assert argv[7:] == ["4242"]
    assert sim.fire(OPENAT, **opened(777, "updatedb", "/var/lib/plocate/db")) == []  # not the target
    assert len(sim.fire(OPENAT, **opened(4242, "make", "/src/Makefile"))) == 1
    assert len(sim.fire(OPENAT, **opened(4242, "make", "/src/a.c", tid=4250))) == 1  # one of its threads
    sim.fire("tracepoint:sched:sched_process_fork", **forked(4242, 4300))  # it forks a compiler
    sim.fire("tracepoint:sched:sched_process_fork", **forked(777, 5000, comm="updatedb"))  # another program forks
    assert json.loads(sim.fire(OPENAT, **opened(4300, "cc1", "/src/a.h"))[0])["path"] == "/src/a.h"
    assert sim.fire(OPENAT, **opened(5000, "sort", "/tmp/x")) == []  # not of the target's tree
    sim.fire("tracepoint:sched:sched_process_fork", **forked(4300, 4301, comm="cc1"))  # a grandchild
    assert len(sim.fire(OPENAT, **opened(4301, "as", "/tmp/a.s"))) == 1
    sim.fire("tracepoint:sched:sched_process_exit", **ended(4300, comm="cc1", ppid=4242))  # the compiler ends
    assert sim.fire(OPENAT, **opened(4300, "other", "/etc/shadow")) == []  # its pid, reused, is not followed
    assert {k[0] for k in sim.held()["@file_tree"]} == {4301}


@pytest.mark.parametrize("given, passed", [
    (4242, "4242"), ("4242", "4242"), (" 17 ", "17"), (None, "0"), (0, "0"), (-5, "0"), (True, "0"),
    ("4242; reboot", "0"), ("-1", "0"), ("--help", "0"), ("\u0661\u0662", "0"), (4194305, "0"), ("9" * 5000, "0"),
    (12.0, "0"), ([1], "0")])
def test_only_a_plain_pid_reaches_bpftraces_command_line(given, passed):
    argv = BpftraceWatch({"file"}, {"pid": given}).argv()
    assert argv[7:] == [passed]


KIND_MIXES = [set(c) for n in (1, 2, 3) for c in itertools.combinations(("net", "process", "file"), n)]


@pytest.mark.parametrize("kinds", KIND_MIXES, ids=["+".join(sorted(k)) for k in KIND_MIXES])
def test_every_mix_of_kinds_is_one_valid_program_that_prints_nothing_as_it_exits(kinds):
    sim, argv = sim_for(kinds, {"pid": 77})
    code = watchmod._bare(argv[6])
    assert ("file" in kinds) == bool(re.search(r"\$1\b", code)) == (argv[7:] == ["77"])
    keeps_maps = kinds != {"process"}  # process.bt keeps no map, so it needs no END
    assert len(re.findall(r"(?m)^\s*END\b", code)) == int(keeps_maps) and not re.search(r"(?m)^\s*BEGIN\b", code)
    # give every probe something to hold, then end: END clears it all, so bpftrace prints no map as it exits
    sim.fire(OPENAT, **opened(77, "x", "/etc/hosts"))
    sim.fire("tracepoint:sched:sched_process_fork", **forked(77, 78))
    sim.fire(TCP_CHANGE, **tcp_change(7, 2, pid=77, comm="x"))
    sim.fire("kprobe:udp_sendmsg", **udp_send(0x10))
    assert bool(sim.held()) == keeps_maps
    assert sim.fire("END") == [] and sim.held() == {}


def test_the_scripts_keep_no_begin_or_end_of_their_own():
    # bpftrace takes one END; the watch adds it to the joined program
    for name in watchmod.SCRIPTS.values():
        code = watchmod._bare((watchmod.SCRIPTS_DIR / name).read_text(encoding="utf-8"))
        assert not re.search(r"(?m)^\s*(?:BEGIN|END)\b", code), name


def test_the_scripts_kprobes_name_the_kernels_own_functions():
    # 1.60.0: net.bt probed udp_v6_sendmsg, a name no kernel has (net/ipv6/udp.c calls it udpv6_sendmsg), and
    # bpftrace refuses a probe it cannot attach, so every net watch ended at its start. Nothing here has a kernel to
    # look in, so the kprobes the scripts use are pinned to the kernel's own (net/ipv4/udp.c, net/ipv6/udp.c).
    kprobes: set[str] = set()
    for name in watchmod.SCRIPTS.values():
        code = watchmod._bare((watchmod.SCRIPTS_DIR / name).read_text(encoding="utf-8"))
        kprobes |= set(re.findall(r"(?m)^\s*k(?:ret)?probe:([A-Za-z0-9_.]+)", code))
    assert kprobes == {"udp_sendmsg", "udpv6_sendmsg"}


# -- net.bt: IPv6 addresses (F2), UDP low-rate, and who owns a TCP socket -------------------------------------

def test_tcp_lines_carry_ipv6_addresses_from_the_v6_fields():
    # F2: ntop(args->family, args->saddr) read the 4-byte field as IPv6, so every IPv6 peer came out wrong
    sim, _ = sim_for({"net"})
    native = sim.fire(TCP_CHANGE, **tcp_change(2, 1, family=10, src="2001:db8::2",
                                               dst="2606:2800:220:1:248:1893:25c8:1946", sk=1))
    accepted = sim.fire(TCP_CHANGE, **tcp_change(3, 1, family=10, src="2001:db8::2", dst="2001:db8:ff::9", sport=443,
                                                 dport=51000, sk=2, four=socket.inet_aton("127.0.0.6")))
    dual = sim.fire(TCP_CHANGE, **tcp_change(2, 1, family=10, src="::ffff:192.168.1.5", dst="::ffff:93.184.216.34",
                                             sk=3))
    plain = sim.fire(TCP_CHANGE, **tcp_change(2, 1, src="10.0.0.2", dst="93.1.2.3", sk=4))
    lines = [x[0] for x in (native, accepted, dual, plain)]
    assert [(json.loads(x)["saddr"], json.loads(x)["daddr"]) for x in lines] == [
        ("2001:db8::2", "2606:2800:220:1:248:1893:25c8:1946"),
        ("2001:db8::2", "2001:db8:ff::9"),
        ("::ffff:192.168.1.5", "::ffff:93.184.216.34"),  # an IPv4 client of a dual-stack socket, as v4-mapped
        ("10.0.0.2", "93.1.2.3")]
    w = watch_of(lines, kinds={"net"})
    events = w.read(0)[1]
    assert [e.action for e in events] == ["connect", "accept", "connect", "connect"]
    assert events[0].local == "[2001:db8::2]:51000" and events[0].remote == "[2606:2800:220:1:248:1893:25c8:1946]:443"
    assert events[1].remote == "[2001:db8:ff::9]:51000"
    assert events[2].remote == "[::ffff:93.184.216.34]:443" and events[3].remote == "93.1.2.3:443"
    w.stop()


def test_tcp_lines_name_the_sockets_owner_or_say_the_pid_is_approximate():
    # the last change of a handshake or a teardown runs in softirq, on whatever task was interrupted
    sim, _ = sim_for({"net"})
    assert sim.fire(TCP_CHANGE, **tcp_change(7, 2, sk=0xA, pid=900, comm="curl")) == []  # connect(), in curl
    connect = sim.fire(TCP_CHANGE, **tcp_change(2, 1, sk=0xA, pid=31, comm="ksoftirqd/3"))
    accept = sim.fire(TCP_CHANGE, **tcp_change(3, 1, sk=0xB, src="10.0.0.2", dst="10.0.0.9", sport=22, dport=40100,
                                               pid=0, comm="swapper/1"))
    assert sim.fire(TCP_CHANGE, **tcp_change(1, 4, sk=0xB, pid=950, comm="sshd")) == []  # its close(), in sshd
    close = sim.fire(TCP_CHANGE, **tcp_change(5, 7, sk=0xB, pid=0, comm="swapper/1"))
    lines = [x[0] for x in (connect, accept, close)]
    assert [(json.loads(x)["pid"], json.loads(x)["comm"], json.loads(x)["approx"]) for x in lines] == [
        (900, "curl", 0), (0, "swapper/1", 1), (950, "sshd", 0)]
    assert 0xB not in {k[0] for k in sim.held().get("@net_pid", {})}  # forgotten once closed
    w = watch_of(lines, kinds={"net"})
    events = w.read(0)[1]
    assert [(e.action, e.pid, e.program) for e in events] == [
        ("connect", 900, "curl"), ("accept", 0, "swapper/1"), ("close", 950, "sshd")]
    assert [e.extra for e in events] == [{}, {"approx": True}, {}]
    w.stop()


def test_udp_sends_are_said_once_per_socket_and_peer_within_a_budget():
    # F1 (net.bt): the UDP kprobes fire per datagram; a QUIC stream must not be a line per datagram
    sim, _ = sim_for({"net"})
    send4, send6 = "kprobe:udp_sendmsg", "kprobe:udpv6_sendmsg"
    quic = [sim.fire(send4, **udp_send(0x100, dst="142.250.1.1", dport=443, comm="chrome")) for _ in range(1000)]
    assert sum(len(x) for x in quic) == 1
    line = json.loads(quic[0][0])
    assert (line["saddr"], line["sport"], line["daddr"], line["dport"]) == ("10.0.0.2", 40000, "142.250.1.1", 443)
    six = sim.fire(send6, **udp_send(0x200, family=10, src="2001:db8::2", dst="2001:4860:4860::8888"))
    assert [(json.loads(x)["daddr"], json.loads(x)["dport"]) for x in six] == [("2001:4860:4860::8888", 53)]
    # an IPv4 peer of an AF_INET6 socket: udpv6_sendmsg hands it to udp_sendmsg, and it is said once
    mapped = udp_send(0x300, family=10, src="::ffff:10.0.0.2", dst="::ffff:1.1.1.1")
    assert [json.loads(x)["daddr"] for x in sim.fire(send6, **mapped) + sim.fire(send4, **mapped)] == ["::ffff:1.1.1.1"]
    # 60 new sockets in the same second: 50 lines in all for the second, the rest counted
    many = [sim.fire(send4, **udp_send(0x1000 + i, dst="10.9.0.1", dport=5353)) for i in range(60)]
    assert sum(len(x) for x in many) == 50 - 3
    tick = sim.fire("interval:s:1")
    assert [json.loads(x) for x in tick] == [{"evt": "net", "act": "skipped", "proto": "udp", "count": 13}]
    sim.fire("interval:s:60")  # a minute on, the stream is said again, once
    assert len(sim.fire(send4, **udp_send(0x100, dst="142.250.1.1", dport=443, comm="chrome"))) == 1
    w = watch_of(quic[0] + tick, kinds={"net"})
    events = w.read(0)[1]
    assert [(e.action, e.proto, e.remote) for e in events] == [("udp_send", "udp", "142.250.1.1:443"),
                                                               ("skipped", "udp", "")]
    assert events[1].extra == {"count": 13}
    w.stop()


# -- process.bt ----------------------------------------------------------------------------------------------

def test_a_thread_ending_is_not_said_as_its_programs_exit():
    sim, _ = sim_for({"process"})
    exit_ = "tracepoint:sched:sched_process_exit"
    assert sim.fire(exit_, **ended(900, tid=912, comm="firefox")) == []  # one of firefox's threads
    assert [json.loads(x) for x in sim.fire(exit_, **ended(900, comm="firefox"))] == [
        {"evt": "process", "act": "exit", "pid": 900, "ppid": 1, "comm": "firefox"}]
    assert json.loads(sim.fire("tracepoint:sched:sched_process_exec", **execd(901, 900, "sh", "/bin/sh"))[0]) == {
        "evt": "process", "act": "exec", "pid": 901, "ppid": 900, "comm": "sh", "path": "/bin/sh"}


# -- the reader: lost events, crafted keys, bpftrace ending, and the process's end -------------------------------

def test_lost_events_are_counted_and_lines_with_crafted_keys_are_dropped():
    def printed(text):
        return json.dumps({"type": "printf", "data": text + "\n"})

    w = BpftraceWatch({"file"}, runner=lambda argv: FakeProc([
        json.dumps({"type": "lost_events", "data": {"events": 7}}),
        # files named so as to close the path and add keys of their own: a new key, and keys given twice
        printed('{"evt":"file","act":"open","pid":5,"comm":"x","path":"a","ppid":1,"flags":0}'),
        printed('{"evt":"file","act":"open","pid":5,"comm":"x","path":"a","comm":"sshd","flags":0}'),
        printed('{"evt":"file","act":"open","pid":5,"comm":"x","path":"a","evt":"process","act":"exec","flags":0}'),
        printed('{"evt":"file","act":"open","pid":5,"comm":"cat","path":"/etc/hosts","flags":0}'),
        json.dumps({"type": "lost_events", "data": {"events": 3}}),
    ]), timeout=5.0)
    w.start()
    assert _wait(lambda: w.lost == 10), "both lost-events lines counted"
    seq, events = w.read(0)
    assert seq == 1 and (events[0].program, events[0].path, events[0].ppid) == ("cat", "/etc/hosts", None)
    w.stop()


class FakePopen(FakeProc):
    """A stand-in for the Popen of sudo bpftrace: terminate (SIGTERM) ends it unless it ignores that, kill always
    does, and wait reaps it, or times out as a real one does while it runs. No process is started."""

    def __init__(self, lines=(), ignores_term=False):
        super().__init__(lines)
        self.calls = []
        self.ignores_term = ignores_term

    def terminate(self):
        self.calls.append("terminate")
        if not self.ignores_term:
            self.killed.set()

    def kill(self):
        self.calls.append("kill")
        super().kill()

    def wait(self, timeout=None):
        self.calls.append("wait")
        if not self.killed.is_set():
            raise subprocess.TimeoutExpired("bpftrace", timeout)
        return 0


def test_stop_ends_bpftrace_with_sigterm_and_reaps_it():
    # a SIGKILL would end sudo alone (bpftrace could run on as root), and an unreaped child is a zombie
    proc = FakePopen([bpftrace_line(evt="net", act="connect", pid=1, comm="x", proto="tcp")])
    w = BpftraceWatch({"net"}, runner=lambda argv: proc, timeout=5.0)
    w.start()
    assert _wait(lambda: w.read(0)[0] == 1)
    w.stop()
    assert proc.calls == ["terminate", "wait"]
    assert _wait(lambda: not any(t.name in ("ebpf-watch", "ebpf-bpftrace") and t.is_alive()
                                 for t in threading.enumerate()))


def test_stop_kills_and_still_reaps_a_bpftrace_that_ignores_sigterm():
    proc = FakePopen(ignores_term=True)
    w = BpftraceWatch({"net"}, runner=lambda argv: proc, timeout=5.0)
    w.start()
    w.stop()
    assert proc.calls == ["terminate", "wait", "kill", "wait"]


def test_bpftrace_is_spawned_in_its_own_session_with_its_words_on_the_pipe():
    calls = []

    def popen(argv, **kw):  # stands in for subprocess.Popen; nothing is started
        calls.append((argv, kw))
        return "proc"

    assert watchmod._spawn(["sudo", "-n", "bpftrace"], popen=popen, windows=False) == "proc"
    kw = calls[-1][1]
    assert kw["start_new_session"] is True and "creationflags" not in kw  # so sudo passes SIGTERM on
    assert (kw["stdin"], kw["stdout"], kw["stderr"]) == (subprocess.DEVNULL, subprocess.PIPE, subprocess.STDOUT)
    assert "bufsize" not in kw  # a binary pipe has no line buffering
    watchmod._spawn(["sudo"], popen=popen, windows=True)
    assert calls[-1][1]["creationflags"] == 0x08000000 and "start_new_session" not in calls[-1][1]


class EndedProc:
    """bpftrace that ended on its own: its last words, then the end of its stream."""

    def __init__(self, lines, code=1):
        self.stdout = list(lines)
        self.code = code
        self.calls = []

    def terminate(self):
        self.calls.append("terminate")

    def kill(self):
        self.calls.append("kill")

    def wait(self, timeout=None):
        self.calls.append("wait")
        return self.code


def test_a_bpftrace_that_ends_on_its_own_says_why_and_the_watch_stops():
    proc = EndedProc([json.dumps({"type": "attached_probes", "data": {"probes": 3}}) + "\n",
                      "stdin:3:5-12: ERROR: Unknown identifier: 'foo'\n", "    foo = 1;\n"])
    w = BpftraceWatch({"net"}, runner=lambda argv: proc, timeout=30.0)
    w.start()
    assert _wait(lambda: w.stopped), "stopped without waiting out its viewing timeout"
    assert w.error == "bpftrace ended (exit code 1): stdin:3:5-12: ERROR: Unknown identifier: 'foo' | foo = 1;"
    assert _wait(lambda: not any(t.name in ("ebpf-watch", "ebpf-bpftrace") and t.is_alive()
                                 for t in threading.enumerate())), "no watcher thread left behind"
    sudo = EndedProc([b"sudo: a password is required\n"])
    w2 = BpftraceWatch({"net"}, runner=lambda argv: sudo, timeout=30.0)
    w2.start()
    assert _wait(lambda: w2.stopped) and w2.error == "bpftrace ended (exit code 1): sudo: a password is required"


def test_a_stop_while_a_start_is_opening_its_source_waits_then_closes_it():
    """1.54.0: start's _begin and stop's _end never overlap. A stop that comes while a start is still opening its source
    (a bpftrace process, an ETW session) waits for it and then closes it, so no source is left open after a stop, and a
    stop never joins a watchdog thread that was not yet started."""
    order, opening, release = [], threading.Event(), threading.Event()

    class Slow(Watch):
        def _begin(self):
            opening.set()
            assert release.wait(5)
            order.append("begun")

        def _end(self):
            order.append("ended")

    w = Slow({"net"}, timeout=60.0)
    errors = []

    def run(step):
        try:
            step()
        except Exception as e:  # noqa: BLE001 - the test says what went wrong
            errors.append(e)

    starter = threading.Thread(target=run, args=(w.start,))
    starter.start()
    assert opening.wait(5)
    stopper = threading.Thread(target=run, args=(w.stop,))
    stopper.start()
    time.sleep(0.2)
    assert order == [] and stopper.is_alive()  # the stop waits for the start's open
    release.set()
    starter.join(5)
    stopper.join(5)
    assert errors == [] and order == ["begun", "ended"] and w.stopped
    w.start()  # a stopped watch never opens again
    assert order == ["begun", "ended"]
