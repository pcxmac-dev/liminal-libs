"""liminal_libs.facts: this machine's facts, read without sending anything (1.103.0; the needs plan's revision 2, 3.4).
No real read is made here: under a test the real reads refuse (M25), and where a test lifts that it stands in for each
reader first. The parsers are fed stand-in files and readings."""
from __future__ import annotations

import ast
import importlib.util
import inspect
import sys
import threading
from pathlib import Path

import pytest

from liminal_libs import facts, needs
from liminal_libs.linuxsys import kernel
from liminal_libs.machines import windows as machines_windows

pytestmark = pytest.mark.usefixtures("no_outside")
SRC = Path(facts.__file__).parent


@pytest.fixture
def fresh_reader():
    before = facts.use(None)
    yield
    facts.use(before)


def test_real_reads_refuse_while_a_test_runs_m25(monkeypatch):
    called = []
    for name in ("win_version", "win_native", "win_os", "win_pf", "win_virtualization", "win_memory", "win_internet",
                 "open_files", "nmcli", "disk", "tools", "rights"):
        real = getattr(facts, name)
        monkeypatch.setattr(facts, name, lambda *a, _r=real, _n=name, **k: (called.append(_n), _r(*a, **k))[1])
    monkeypatch.delenv(facts.REAL, raising=False)
    assert facts.refused()
    for system in ("windows", "linux"):
        monkeypatch.setattr(facts, "system", lambda s=system: s)
        out = facts.Reader().read()
        assert out["system"] == system
        why = out["why"]
        assert why.get("cpu") == facts.NOT_READ and why.get("disk") == facts.NOT_READ
        assert out["internet"]["state"] == "unknown"
    assert called  # each was asked, and each refused before reading anything


def test_liminal_real_facts_lifts_the_refusal_with_every_reader_stood_in(monkeypatch):
    monkeypatch.setenv(facts.REAL, "1")
    assert not facts.refused()
    monkeypatch.setattr(facts, "system", lambda: "windows")
    stand = {"win_version": lambda: {"build": 26300, "ubr": 9974, "edition": "Professional", "display": "26H2",
                                     "installation": "Client", "productType": 1},
             "win_native": lambda: 0x8664,
             "win_os": lambda: {"caption": "Microsoft Windows 11 Pro", "productType": 1, "dep": True},
             "win_pf": lambda: {"nx": True, "sse4.2": True, "avx": True, "avx2": True, "avx512f": False},
             "win_virtualization": lambda: {"hypervisor": True, "model": "Precision", "manufacturer": "Dell Inc.",
                                            "extensions": False, "slat": False, "firmware": False},
             "win_memory": lambda: {"installed": 64 * 2**30, "usable": 68137205760},
             "win_internet": lambda: {"nlm": 0x42, "probing": True, "proxy": "", "sunk": "", "why": ""},
             "desktop": lambda: True, "disk": lambda: {"free": 2**40, "path": "C:\\"},
             "rights": lambda: {"administrator": False, "root": False, "groups": []}}
    for name, fn in stand.items():
        monkeypatch.setattr(facts, name, fn)
    r = facts.Reader()
    monkeypatch.setattr(r, "_features_read", lambda names: {n: (1 if n == "Microsoft-Hyper-V" else 2) for n in names})
    first = r.read(names={"windows.feature": ["Microsoft-Hyper-V", "Containers"]})
    assert r.features_ready(2.0)
    out = r.read(names={"windows.feature": ["Microsoft-Hyper-V", "Containers"]})
    assert first["windows"]["featuresRead"] is False and out["windows"]["featuresRead"] is True
    assert out["windows"]["features"] == {"Microsoft-Hyper-V": 1, "Containers": 2}
    assert out["windows"]["product"] == "Windows 11 Pro" and out["windows"]["server"] is False
    assert out["architecture"] == "x86-64" and out["cpu"]["nxHardware"] is True
    assert out["internet"]["state"] == "yes" and out["internet"]["ipv4"] and not out["internet"]["ipv6"]
    assert out["virtualization"]["vm"] == "" and out["virtualization"]["hypervisor"] is True
    rows = needs.declared(type("H", (), {"NEEDS": (("windows.feature", "Microsoft-Hyper-V"), ("virtualization", "slat"),
                                                   ("memory", ">= 4 GiB"), ("cpu", "nx"))})())
    assert needs.judge(rows, out)["met"] is True


def test_one_read_in_flight_for_each_slow_read_m7():
    gate, entered = threading.Event(), threading.Event()
    calls = []

    class Slow(facts.Reader):
        def _read(self, group):
            calls.append(group)
            entered.set()
            gate.wait(5)
            return {"nlm": 0x40, "probing": True, "proxy": "", "sunk": "", "why": ""}

    r = Slow()
    t = threading.Thread(target=r._group, args=("internet", False), daemon=True)
    t.start()
    assert entered.wait(5)
    assert r._group("internet", False) is None  # in flight: nothing kept yet, so nothing, at once
    gate.set()
    t.join(5)
    assert calls == ["internet"]
    assert r._group("internet", False) == {"nlm": 0x40, "probing": True, "proxy": "", "sunk": "", "why": ""}
    assert calls == ["internet"]  # kept for INTERNET_S


def test_the_internet_is_read_again_past_its_time_and_its_readings_kept():
    now = [0.0]

    class Count(facts.Reader):
        n = 0

        def _read(self, group):
            Count.n += 1
            return {"nlm": 0x40, "probing": True, "proxy": "", "sunk": "", "why": ""}

    r = Count(clock=lambda: now[0], wall=lambda: now[0])
    if facts.system() != "windows":
        pytest.skip("the readings' state is parsed by this system's own parser")
    r._group("internet", False)
    now[0] = 5.0
    r._group("internet", False)
    now[0] = 20.0
    r._group("internet", False)
    assert Count.n == 2 and [s for _t, s in r._readings] == ["yes", "yes"]


def test_quick_fresh_reads_keep_a_confirmed_no_until_a_reading_that_is_not_no_m9(monkeypatch):
    now, level = [0.0], [0x40]

    class Net(facts.Reader):
        def _read(self, group):
            return {"nlm": level[0], "probing": True, "proxy": "", "sunk": "", "why": ""}

    monkeypatch.setattr(facts, "system", lambda: "windows")
    r = Net(clock=lambda: now[0], wall=lambda: now[0])

    def judged():
        return needs.internet_now({"internet": {"state": r._readings[-1][1], "readings": list(r._readings)}})[0]

    r._group("internet", True)
    level[0] = 0  # off line: no IPv4 nor IPv6 internet
    now[0] = 10.0
    r._group("internet", True)
    assert judged() == "yes"  # one reading says no: judged as before
    now[0] = 10.0 + needs.INTERNET_APART_S
    r._group("internet", True)
    assert judged() == "no"
    for k in range(1, 7):  # "Read again" pressed six times within seconds
        now[0] = 25.0 + k
        r._group("internet", True)
        assert judged() == "no", r._readings
        assert len(r._readings) <= facts.READINGS
    level[0] = 0x40
    now[0] = 40.0
    r._group("internet", True)
    assert judged() == "yes"  # back at the first reading that is not no


def test_the_readings_kept_hold_the_current_runs_first_m9():
    keep = facts.keep_readings
    assert keep([[0, "yes"], [1, "no"]]) == [[0, "yes"], [1, "no"]]
    six = [[0, "yes"], [10, "no"], [25, "no"], [26, "no"], [27, "no"], [28, "no"]]
    assert keep(six) == [[0, "yes"], [10, "no"], [27, "no"], [28, "no"]]
    assert keep([[t, "no"] for t in range(6)]) == [[0, "no"], [3, "no"], [4, "no"], [5, "no"]]
    turned = [[0, "no"], [20, "no"], [21, "no"], [22, "no"], [23, "yes"], [24, "yes"]]
    assert keep(turned) == turned[-facts.READINGS:]


def test_an_import_without_the_windows_modules_m8(monkeypatch):
    import ctypes

    monkeypatch.setitem(sys.modules, "winreg", None)
    monkeypatch.setitem(sys.modules, "_wmi", None)
    monkeypatch.delattr(ctypes, "windll", raising=False)
    spec = importlib.util.spec_from_file_location("liminal_libs._facts_m8", SRC / "facts.py")
    copy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copy)
    monkeypatch.setenv(facts.REAL, "1")
    monkeypatch.setattr(copy, "system", lambda: "windows")
    monkeypatch.setattr(copy, "win_native", lambda: 0x8664)  # kernel32 itself is this system's: stood in
    monkeypatch.setattr(copy, "win_pf", lambda: {})
    monkeypatch.setattr(copy, "win_memory", lambda: {})
    monkeypatch.setattr(copy, "win_nlm", lambda: 0x40)
    monkeypatch.setattr(copy, "desktop", lambda: True)
    monkeypatch.setattr(copy, "rights", lambda: {})
    monkeypatch.setattr(copy, "disk", lambda: {"free": 1, "path": "x"})
    out = copy.Reader().read()
    assert out["windows"]["build"] is None and "winreg" in out["why"]["windows"]
    assert out["virtualization"]["hypervisor"] is None and out["why"]["virtualization"]


def _function(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name)


def test_the_copied_lines_are_held_to_their_originals():
    original = Path(machines_windows.__file__)
    for name in ("interactive", "_ObjectFlags"):
        assert ast.dump(_function(SRC / "facts.py", name)) == ast.dump(_function(original, name)), name


@pytest.mark.parametrize("module", ["facts.py", "needs.py", "needs_machines.py"])
def test_nothing_is_sent_by_these_modules(module):
    path = SRC / module
    if not path.is_file():
        pytest.skip(f"{module} is not built yet")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    banned = {"socket", "http", "urllib", "requests", "httpx", "aiohttp", "ssl", "ftplib", "smtplib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {a.name.split(".")[0] for a in node.names} & banned, ast.dump(node)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            assert (node.module or "").split(".")[0] not in banned, node.module
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert "://" not in node.value, node.value


def test_nmcli_through_a_stand_in_spawn_and_its_row_let_go_m26(monkeypatch):
    from liminal_libs import lifecycle

    monkeypatch.setenv(facts.REAL, "1")
    started, ended = [], []

    class Child:
        def communicate(self, timeout=None):
            assert timeout == facts.NMCLI_S
            return "full\n", ""

    monkeypatch.setattr(facts.shutil, "which", lambda name: "/usr/bin/nmcli")
    monkeypatch.setattr(lifecycle, "spawn", lambda args, owner, kind, **kw: (started.append((args, owner, kind)),
                                                                             Child())[1])
    monkeypatch.setattr(lifecycle, "end_owned", lambda owner, sig, deadline, **kw: ended.append((owner, sig)) or [])
    assert facts.nmcli() == "full"
    assert started == [(list(facts.NMCLI), "facts", "read")] and ended == [("facts", lifecycle.Signal.TERM)]
    assert "check" not in facts.NMCLI  # it reads the last verdict, and asks for none


def test_nmcli_is_never_asked_inside_wsl_nor_without_networkmanager(monkeypatch):
    asked = []
    monkeypatch.setattr(facts, "nmcli", lambda: asked.append(1) or "full")
    monkeypatch.setattr(facts, "open_files", lambda paths: {p: None for p in paths})
    for files in ({"/proc/sys/kernel/osrelease": "6.18.58.1-microsoft-standard-WSL2", "/run/NetworkManager": ""},
                  {"/proc/sys/kernel/osrelease": "6.12.0-1-amd64"}):
        r = facts.Reader()
        r._kept["os"] = (0.0, files)
        assert r._linux_internet()["nmcli"] is None
    r = facts.Reader()
    r._kept["os"] = (0.0, {"/proc/sys/kernel/osrelease": "6.12.0-1-amd64", "/run/NetworkManager": ""})
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.delenv("WSL_INTEROP", raising=False)
    assert r._linux_internet()["nmcli"] == "full" and asked == [1]


BASE = {"/proc/sys/kernel/osrelease": "6.12.0-1-amd64", "/proc/cpuinfo": "processor\t: 0\nflags\t\t: fpu nx sse4_2 avx avx2 vmx\nvmx flags\t: ept vpid\n",
        "/proc/meminfo": "MemTotal:       16384000 kB\n", "/proc/net/route":
        "Iface\tDestination\tGateway\nens3\t00000000\t0101A8C0\n", "/proc/net/ipv6_route": ""}


@pytest.mark.parametrize("comm,marks,init", [
    ("systemd", (), "systemd"), ("init", ("/run/openrc",), "openrc"), ("openrc-init", (), "openrc"),
    ("runit", (), "runit"), ("s6-svscan", (), "s6"), ("dinit", (), "dinit"), ("busybox", (), "busybox"),
    (None, ("/run/systemd/system",), "systemd"), ("init", (), ""),
])
def test_init_read_from_stand_in_files(comm, marks, init):
    files = {**BASE, "/proc/1/comm": comm, **{m: "" for m in marks}}
    assert facts.parse_linux(files, {}, "x86_64")["init"] == init


def test_wsls_own_init():
    files = {**BASE, "/proc/sys/kernel/osrelease": "6.18.58.1-microsoft-standard-WSL2", "/proc/1/comm": "init"}
    out = facts.parse_linux(files, {"WSL_DISTRO_NAME": "Ubuntu"}, "x86_64")
    assert out["init"] == "wsl" and out["wsl"] == "2" and out["internet"]["state"] == "unknown"


def test_the_linux_kernel_facts_are_kernel_reads(monkeypatch):
    seen = []
    real = kernel.read
    monkeypatch.setattr(facts.kernel, "read", lambda files, env=None, machine="": (seen.append((dict(files), env,
                                                                                                machine)),
                                                                                    real(files, env, machine))[1])
    files = {**BASE, "/proc/sys/kernel/osrelease": "4.4.0-26300-Microsoft", "/dev/kvm": None}
    out = facts.parse_linux(files, {"WSL_DISTRO_NAME": "Ubuntu"}, "x86_64")
    assert seen and seen[0][0]["/proc/sys/kernel/osrelease"] == "4.4.0-26300-Microsoft" and seen[0][2] == "x86_64"
    assert out["wsl"] == "1" and out["kernel"]["release"] == "4.4.0-26300-Microsoft"
    assert out["linux"] == {"netfilter": False, "ebpf": False}
    assert set(kernel.FILES) <= set(facts.LINUX_FILES)


def test_linux_processor_memory_and_kvm():
    out = facts.parse_linux({**BASE, "/dev/kvm": ""}, {}, "x86_64")
    assert out["architecture"] == "x86-64" and out["cpu"]["sse4.2"] and out["cpu"]["nx"] and not out["cpu"]["avx512f"]
    assert out["virtualization"]["extensions"] and out["virtualization"]["slat"] and out["virtualization"]["kvm"]
    assert out["virtualization"]["vm"] == "" and out["memory"]["usable"] == 16384000 * 1024
    guest = facts.parse_linux({**BASE, "/proc/cpuinfo": "flags : fpu hypervisor\n", "/dev/kvm": None}, {}, "aarch64")
    assert guest["virtualization"]["vm"] == "a virtual machine" and guest["virtualization"]["kvm"] is False
    assert guest["architecture"] == "arm64" and guest["virtualization"]["extensions"] is False


@pytest.mark.parametrize("over,env,word,state", [
    ({}, {}, "full", "yes"), ({}, {}, "limited", "no"), ({}, {}, None, "unknown"),
    ({"/proc/net/route": "Iface\tDestination\n", "/proc/net/ipv6_route": ""}, {}, None, "no"),
    ({}, {"https_proxy": "http-proxy"}, "full", "unknown"),
])
def test_the_linux_internet(over, env, word, state):
    out = facts.parse_linux({**BASE, **over}, env, "x86_64", nmcli=word)
    assert out["internet"]["state"] == state
    if state == "yes":
        assert out["internet"]["ipv4"] is True and out["internet"]["ipv6"] is None


def test_the_windows_internet_proxy_sunk_and_probing():
    def net(**kw):
        return facts.parse_windows({"internet": {"nlm": 0x42, "probing": True, "proxy": "", "sunk": "", **kw}})[
            "internet"]
    assert net()["state"] == "yes"
    assert net(proxy="HTTPS_PROXY is set")["state"] == "unknown"
    assert net(sunk="www.msftconnecttest.com")["state"] == "unknown"
    assert net(nlm=0x1, probing=False)["state"] == "unknown"
    assert net(nlm=0x1)["state"] == "no"
    assert facts.parse_windows({})["internet"]["state"] == "unknown"


def test_sunk_host_and_proxies():
    text = "# comment\n127.0.0.1 localhost\n0.0.0.0 www.msftconnecttest.com # blocked\n10.0.0.1 dns.msftncsi.com\n"
    assert facts.sunk_host(text, {"www.msftconnecttest.com"}) == "www.msftconnecttest.com"
    assert facts.sunk_host(text, {"dns.msftncsi.com"}) == ""
    assert facts.proxy_words({"all_proxy": "x"}) == "all_proxy is set" and facts.proxy_words({}) == ""


def test_windows_vm_and_server():
    out = facts.parse_windows({"virtualization": {"model": "Virtual Machine", "manufacturer": "Microsoft Corporation",
                                                  "hypervisor": False}, "os": {"productType": 3}})
    assert out["virtualization"]["vm"] and out["windows"]["server"] is True


def test_wanted_and_the_one_reader(fresh_reader):
    attrs, names = facts.wanted([{"attribute": "windows.feature", "value": "Containers|Containers-DisposableClientVM"},
                                 {"attribute": "windows:tool", "value": "npcap"}, "junk"])
    assert attrs == {"windows.feature", "tool"} and names == {"windows.feature": ["Containers",
                                                                                   "Containers-DisposableClientVM"],
                                                              "tool": ["npcap"]}
    first = facts.reader()
    assert facts.reader() is first and isinstance(first, facts.Reader)
    stand = facts.StandIn({"system": "linux"})
    assert facts.use(stand) is first and facts.reader() is stand
    assert stand.read() == {"system": "linux"} and stand.reads == 1


def test_reads_name_each_read():
    assert all(len(r) == 3 and all(isinstance(x, str) and x for x in r) for r in facts.READS)
    top = ast.parse(inspect.getsource(facts)).body  # plain at module level: lifecycle only inside nmcli's reader
    names = {a.name for n in top if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    assert names <= {"annotations", "ctypes", "logging", "os", "shutil", "sys", "threading", "time", "needs", "kernel"}
