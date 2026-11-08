"""The resources monitor on Linux (liminal_libs.resources.LinuxProbe): the processes asked for, the machine, the
network and the connections read from a stand-in /proc and /sys, so this runs on Windows as on Linux; every
Liminal app's processes and their roles (is_framework, framework_role); the monitor over the Linux probe."""
from __future__ import annotations

import sys

import pytest

from liminal_libs import resources as res
from liminal_libs.resources import LinuxProbe, Monitor, framework_role, is_framework


def stat_line(pid, comm, ppid=1, utime=250, stime=50, threads=12, start=360000):
    return f"{pid} ({comm}) S {ppid} 0 0 0 -1 0 0 0 0 0 {utime} {stime} 0 0 20 0 {threads} 0 {start} 0 0\n"


def files():
    f = {
        "/proc/stat": "cpu  1000 0 500 8000 500 0 0 0 0 0\ncpu0 500 0 250 4000 250 0 0 0 0 0\ncpu1 500 0 250 4000 250 0 0 0 0 0\nbtime 1800000000\n",
        "/proc/meminfo": "MemTotal:       16384000 kB\nMemFree:         1000000 kB\nMemAvailable:    8192000 kB\nSwapTotal:       2048000 kB\nSwapFree:        1024000 kB\n",
        "/proc/4242/stat": stat_line(4242, "python3"),
        "/proc/4242/cmdline": "/usr/bin/python3\x00-m\x00liminal_charts\x00gui\x00--port\x008765\x00",
        "/proc/4242/status": "Name:\tpython3\nVmRSS:\t  524288 kB\nRssAnon:\t  400000 kB\nVmSwap:\t       0 kB\n",
        "/proc/4242/io": "rchar: 1000000\nwchar: 2000\nread_bytes: 4096\n",
        "/proc/4300/stat": stat_line(4300, "python3", utime=100, stime=0, threads=8, start=370000),
        "/proc/4300/cmdline": "python3\x00-m\x00liminal_integrator\x00service\x00run\x00--daemon\x00",
        "/proc/4300/status": "VmRSS:\t  102400 kB\nRssAnon:\t   90000 kB\nVmSwap:\t    1000 kB\n",
        "/proc/5000/stat": stat_line(5000, "python3"),
        "/proc/5000/cmdline": "python3\x00-m\x00http.server\x00",
        "/proc/6000/stat": stat_line(6000, "a (strange) name", ppid=4242),
        "/proc/6000/cmdline": "",
        "/proc/net/dev": ("Inter-|   Receive                                                |  Transmit\n"
                          " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
                          "    lo:   9990      99    0    0    0     0          0         0     9990      99    0    0    0     0       0          0\n"
                          "  eth0:   5000      10    0    0    0     0          0         0     3000       8    0    0    0     0       0          0\n"
                          "docker0:   7770      77    0    0    0     0          0         0      770       7    0    0    0     0       0          0\n"),
        "/sys/class/net/eth0/operstate": "up\n",
        "/sys/class/net/eth0/speed": "1000\n",
        "/proc/net/tcp": ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                          "   0: 0100007F:223D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0 100 0 0 10 0\n"
                          "   1: 0100007F:223D 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0 20 4 30 10 -1\n"),
        "/proc/net/tcp6": ("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                           "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0 100 0 0 10 0\n"),
    }
    links = {"/proc/4242/fd/0": "/dev/null", "/proc/4242/fd/5": "socket:[11111]", "/proc/4300/fd/0": "/dev/null",
             "/sys/class/net/eth0/device": "../../../0000:00:1f.6"}
    return f, links


class FakeProc(LinuxProbe):
    """The Linux probe over a stand-in /proc and /sys: files and symbolic links in dicts."""

    def __init__(self, files_, links, match=None):
        self.files, self.links = files_, links
        super().__init__(match=match, ticks=100)

    def _read(self, path):
        return self.files.get(path)

    def _listdir(self, path):
        prefix = path.rstrip("/") + "/"
        return sorted({p[len(prefix):].split("/", 1)[0] for p in [*self.files, *self.links] if p.startswith(prefix)})

    def _readlink(self, path):
        return self.links.get(path)


def test_the_processes_asked_for_with_their_cpu_memory_io_threads_and_open_files():
    f, links = files()
    probe = FakeProc(f, links, match=is_framework)
    procs = {p.pid: p for p in probe.processes()}
    assert set(procs) == {4242, 4300}  # Liminal's, not another Python program
    p = procs[4242]
    assert (p.parent, p.cpu_s, p.memory, p.private, p.read, p.write, p.threads, p.handles) == (1, 3.0, 524288 * 1024, 400000 * 1024, 1000000, 2000, 12, 2)
    assert p.started == 1800000000 + 3600 and p.command == "/usr/bin/python3 -m liminal_charts gui --port 8765"
    assert procs[4300].private == (90000 + 1000) * 1024 and procs[4300].handles == 1
    assert {p.pid for p in FakeProc(f, links).processes()} == {4242}  # the charts app's alone, by default
    everyone = {p.pid: p for p in FakeProc(f, links, match=lambda c: True).processes()}
    assert everyone[6000].parent == 4242 and everyone[6000].threads == 12  # a name with spaces and parentheses


def test_the_machine_and_its_network():
    f, links = files()
    probe = FakeProc(f, links)
    m = probe.machine()
    assert (m.cpus, m.total_s, m.busy_s) == (2, 100.0, 15.0)
    assert (m.memory_total, m.memory_available) == (16384000 * 1024, 8192000 * 1024)
    assert (m.commit_total, m.commit_available) == ((16384000 + 2048000) * 1024, (8192000 + 1024000) * 1024)
    n = probe.network()
    assert (n.received, n.sent, n.link_bps, n.adapters) == (5000, 3000, 1_000_000_000, ("eth0",))  # not lo, not docker0
    del links["/sys/class/net/eth0/device"]  # WSL, a VM: no device behind the adapter, still counted
    assert FakeProc(f, links).network().adapters == ("eth0",)
    assert FakeProc({}, {}).machine() is None and FakeProc({}, {}).network() is None


def test_every_connection_with_its_process_when_it_is_one_reported():
    f, links = files()
    probe = FakeProc(f, links, match=is_framework)
    probe.processes()
    conns = probe.connections()
    assert [(c.pid, c.state, c.local, c.remote) for c in conns] == [
        (4242, "listening", "127.0.0.1:8765", ""),
        (0, "established", "127.0.0.1:8765", "127.0.0.1:50000"),
        (0, "listening", "[::1]:8080", "")]
    assert res._hex_address("0100007F:1F90", False) == "127.0.0.1:8080"


def test_every_liminal_apps_process_and_its_role():
    assert is_framework("python -m liminal_integrator service run --daemon") and is_framework("liminal-login serve --port 8795")
    assert is_framework("python -m liminal_charts gui") and not is_framework("python -m pytest")
    assert not res.is_app("python -m liminal_integrator serve")  # the charts app's own view stays its own
    assert framework_role("pythonw.exe -m liminal_integrator service run --daemon")[:2] == ("integrator", "Integrator (daemon)")
    assert framework_role("/venv/bin/liminal-login serve --no-browser --port 8796")[:2] == ("login", "Login · port 8796")
    assert framework_role('"C:\\venv\\Scripts\\pythonw.exe" -m liminal_platform serve')[:2] == ("platform", "Platform")
    assert framework_role("python -m liminal_charts gui --port 8765")[:2] == ("gui", "Chart app · port 8765")
    assert framework_role("python -m something")[0] == "other"
    assert framework_role("pythonw.exe -m liminal_charts host feed-massive")[:2] == ("host", "Host: feed-massive")  # not "host command"


def test_the_system_disk_is_listed_once(tmp_path, monkeypatch):
    monkeypatch.delenv("SystemDrive", raising=False)  # Linux: no drive letters
    f, links = files()
    view = Monitor(tmp_path, probe=FakeProc(f, links)).view()
    paths = [d["path"] for d in view["files"]["disks"]]
    assert "//" not in paths and len(paths) == len(set(paths))


def test_the_monitor_reads_linux_as_it_reads_windows(tmp_path):
    f, links = files()
    probe = FakeProc(f, links, match=is_framework)
    t = [100.0]
    m = Monitor(tmp_path, probe=probe, clock=lambda: t[0], wall=lambda: 1800010000.0 + t[0], cpu_clock=lambda: 0.0,
                roles=framework_role, own=("platform", "Platform"))
    m.sample()
    f["/proc/stat"] = "cpu  1100 0 550 8150 550 0 0 0 0 0\ncpu0 0\ncpu1 0\nbtime 1800000000\n"  # 1 s more busy of 3.5 s
    f["/proc/4242/stat"] = stat_line(4242, "python3", utime=300, stime=50)  # half a second of CPU in 2 s
    t[0] = 102.0
    m.sample()
    view = m.view()
    assert view["system"] == "linux" and view["windows"] is False
    assert view["machine"]["cpus"] == 2 and view["machine"]["cpu"] == pytest.approx(1.5 / 3.5)
    labels = {g["label"]: g for g in view["processes"]}
    assert set(labels) == {"Chart app · port 8765", "Integrator (daemon)"}
    assert labels["Chart app · port 8765"]["cpu"] == pytest.approx(0.25) and labels["Chart app · port 8765"]["connections"]["listening"] == 1
    assert view["network"]["received"] == 5000 and view["connections"]["established"] == 1


def test_the_whole_disks_bytes_and_the_monitors_disk_rates(tmp_path):
    """The disks' I/O, hardware only (the user: "lets get disk io ... in hwstats"; "the platform only cares about
    hardware"): each whole disk's bytes read and written, partitions and loop devices left out; the rates a second."""
    f, links = files()
    f["/proc/diskstats"] = ("   8       0 sda 1000 0 2048 100 500 0 4096 50 0 150 150 0 0 0 0\n"
                            "   8       1 sda1 900 0 2000 90 400 0 4000 40 0 130 130 0 0 0 0\n"
                            "   7       0 loop0 10 0 20 1 0 0 0 0 0 1 1 0 0 0 0\n"
                            " 259       0 nvme0n1 10 0 100 1 10 0 200 1 0 2 2 0 0 0 0\n")
    for name in ("sda", "nvme0n1", "loop0"):
        f[f"/sys/block/{name}/size"] = "1\n"
    probe = FakeProc(f, links)
    assert [(d.name, d.read, d.written) for d in probe.disks()] == [("sda", 2048 * 512, 4096 * 512), ("nvme0n1", 100 * 512, 200 * 512)]
    bare = {k: v for k, v in f.items() if not k.startswith("/sys/block")}  # no /sys/block: partitions told by their names
    assert [d.name for d in FakeProc(bare, links).disks()] == ["sda", "nvme0n1"]
    t = [100.0]
    m = Monitor(tmp_path, probe=probe, clock=lambda: t[0], wall=lambda: 1_800_010_000.0 + t[0], cpu_clock=lambda: 0.0, roles=framework_role)
    m.sample()
    f["/proc/diskstats"] = f["/proc/diskstats"].replace("sda 1000 0 2048", "sda 1000 0 6144").replace("500 0 4096", "500 0 8192")
    t[0] = 102.0
    m.sample()
    v = m.view()
    assert v["disk"]["read"] == pytest.approx(4096 * 512 / 2) and v["disk"]["write"] == pytest.approx(4096 * 512 / 2)
    assert [(r["name"], r["readTotal"]) for r in v["disk"]["disks"]] == [("sda", 6144 * 512), ("nvme0n1", 100 * 512)]
    assert v["series"]["diskRead"] == [None, pytest.approx(4096 * 512 / 2)] and v["series"]["diskWrite"][0] is None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows' own disk counters")
def test_this_windows_machines_disks_are_read_without_rights():
    from liminal_libs.resources import Disk, WindowsProbe

    found = WindowsProbe().disks()
    assert isinstance(found, list) and all(isinstance(d, Disk) and d.name.endswith(":") and d.read >= 0 for d in found)


def test_a_process_is_named_by_its_comm_for_a_ports_listener():
    f, links = files()
    f.update({"/proc/4242/comm": "python3\n", "/proc/5000/comm": "nginx\n"})
    probe = FakeProc(f, links)
    assert probe.program_names() == {4242: "python3", 5000: "nginx"}  # 4300 and 6000 have no comm here
    assert probe.program_names([5000, 7777]) == {5000: "nginx"}
