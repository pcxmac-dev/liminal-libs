"""The services scan (liminal_libs.machines.services): systemd's units and memory, OpenRC's rc-status, SysV's
service --status-all, the major services apart from the system's own; all from answers given here (nothing runs)."""
from __future__ import annotations

from liminal_libs.machines.services import MARK, SCRIPT, classify, parse

SYSTEMD = """== liminal-scan 1
== init systemd systemd
== units
\u25cf getty@tty1.service   loaded    failed   failed  Getty on tty1
docker.service          loaded    active   running Docker Application Container Engine
liminal-charts.service  loaded    active   running The Liminal charts app (made by the Liminal platform)
postgresql@16-main.service loaded active running PostgreSQL Cluster 16-main
mystery.service         loaded    active   running Something of the user's
ufw.service             loaded    active   exited  Uncomplicated firewall
user@1000.service       loaded    active   running User Manager for UID 1000
nginx.service           masked    inactive dead    nginx.service
== memory
Id=docker.service
MainPID=289
MemoryCurrent=154206208

Id=liminal-charts.service
MainPID=900
MemoryCurrent=18446744073709551615
Id=mystery.service
MainPID=0
MemoryCurrent=1048576
== processes
      1 15752 systemd         /sbin/init
== end
"""

OPENRC = ("== liminal-scan 1\n== init openrc init\n== openrc\nRunlevel: default\n"
          " sshd                 \x1b[0;32m[  started  ]\x1b[0m\n docker               [  started 00:12:03 (0) ]\n"
          " netmount             [  started  ]\n local                [  started  ]\nDynamic Runlevel: hotplugged\n"
          "Dynamic Runlevel: needed/wanted\n sysfs                [  started  ]\n udev                 [  started  ]\n"
          " nginx                [  crashed  ]\nDynamic Runlevel: manual\n mysql                [  stopped  ]\n"
          " sshd                 [  stopped  ]\n== processes\n    1  1200 init            /sbin/init\n== end\n")

SYSV = ("== liminal-scan 1\n== init sysvinit init\n== sysv\n [ + ]  cron\n [ - ]  dbus\n [ + ]  docker\n [ ? ]  hwclock.sh\n"
        " [ + ]  postgresql\n== processes\n== end\n")


def test_systemd_services_are_sorted_into_major_other_and_the_systems_own():
    scan = parse(SYSTEMD, now=0)
    assert (scan.init, scan.pid1, scan.problem) == ("systemd", "systemd", "")
    assert [(s.name, s.state, s.kind, s.what) for s in scan.major] == [
        ("docker", "running", "major", "containers: Docker Engine"),
        ("liminal-charts", "running", "major", "Liminal's charts app"),
        ("postgresql@16-main", "running", "major", "database: PostgreSQL"),
        ("ufw", "on", "major", "the firewall: ufw"),
        ("mystery", "running", "other", "Something of the user's")]
    assert [s.name for s in scan.system] == ["user@1000"] and [s.name for s in scan.failed] == ["getty@tty1"]
    by = {s.name: s for s in scan.services}
    assert (by["docker"].memory, by["docker"].pid) == (154206208, 289)
    assert by["liminal-charts"].memory is None and by["liminal-charts"].pid == 900  # no accounting: no number made up
    assert by["mystery"].pid is None and "nginx" not in by  # masked: nothing that runs
    assert scan.summary() == "docker, liminal-charts, postgresql@16-main, ufw, mystery (+1 of the system's own)"
    table = scan.table("Liminal-Ubuntu")
    assert table["rows"][0] == ["docker", "running", "containers: Docker Engine", "147 MB"]
    assert table["rows"][-1][0] == {"text": "mystery", "sub": "not one Liminal knows"}
    assert table["note"] == "systemd (PID 1: systemd) · the system's own running: 1 (user@1000) · failed: getty@tty1 · 1 processes, 15 MB resident"
    assert [c["title"] for c in table["columns"]] == ["Service", "State", "What it is", "Memory"] and table["columns"][3]["num"]


def test_openrc_services_from_rc_status_with_its_colours():
    scan = parse(OPENRC, now=0)
    assert (scan.init, scan.pid1) == ("openrc", "init")
    assert [(s.name, s.state) for s in scan.major] == [("docker", "running"), ("sshd", "running"), ("nginx", "failed")]
    assert [s.name for s in scan.system] == ["local", "netmount", "sysfs", "udev"]
    assert "mysql" in {s.name for s in scan.services} and "mysql" not in {s.name for s in scan.major}  # stopped: not online
    assert scan.summary() == "docker, sshd, nginx (failed) (+4 of the system's own)" and scan.note().startswith("OpenRC (PID 1: init)")


def test_sysv_scripts_through_the_service_command():
    scan = parse(SYSV, now=0)
    assert scan.init == "sysvinit" and [s.name for s in scan.major] == ["docker", "postgresql"] and [s.name for s in scan.system] == ["cron"]
    assert scan.note().startswith("no service manager running: SysV scripts through the service command (PID 1: init)")


def test_an_answer_not_the_scripts_is_said_never_guessed():
    scan = parse("sh -s liminal-scan\n", now=0)
    assert scan.problem == "the scan's answer was not understood" and scan.services == [] and not scan.describe()["scanned"]
    assert scan.table("X")["empty"] == "the scan's answer was not understood" and scan.summary() == scan.problem
    assert SCRIPT.startswith("echo '" + MARK + "'") and "systemctl list-units" in SCRIPT and "rc-status --all" in SCRIPT
    assert "service --status-all" in SCRIPT and "ps -eo" in SCRIPT


def test_what_is_major_and_what_is_the_systems_own():
    assert classify("docker.service") == ("major", "containers: Docker Engine")
    assert classify("wg-quick@wg0") == ("major", "VPN: WireGuard") and classify("openvpn-client@x")[0] == "major"
    assert classify("liminal-integrator") == ("major", "Liminal's integrator app") and classify("mongod")[1] == "database: MongoDB"
    own = ("systemd-journald", "getty@tty1", "user@1000", "snapd.seeded", "wsl-pro", "chrony", "udev-trigger", "net.lo")
    assert [classify(n)[0] for n in own] == ["system"] * len(own)
    assert classify("my-own-daemon") == ("other", "")
