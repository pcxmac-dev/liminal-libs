"""What runs in a Linux system, read with one script (the user, 2026-11-08: "lets have, in the WSL plugins, a
breakdown of the major services running, the 'scanning function' should be capable of using openrc or systemd to look
for init type and differentiate between somewhat trivial processes and major services that are online").

`SCRIPT` (POSIX sh, run as root through any shell: a WSL distribution's, a Linux machine's) says which init system
runs (systemd, OpenRC, SysV scripts through the service command, or none) and what PID 1 is, then lists every service
that init system knows with its state (systemd: each unit's load, active and sub state, its description, and the memory
of those running; OpenRC: `rc-status --all`; SysV: `service --status-all`), and the processes. `parse` reads that into a
`Scan`, and `classify` sorts each service: a major one (what the framework or its user runs: Docker, databases, web,
mail and DNS servers, SSH, VPNs, the firewall, Liminal's own apps), another (one not known here: shown with its own
description, so nothing that might matter is hidden), or the system's own (logging, time, devices, D-Bus, logins,
package and update daemons, the WSL bridge: counted and named in a note). `Scan.table` is a table for the platform's
page (a status's `tables`)."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

MARK = "== liminal-scan 1"  # the first line of the script's answer: anything else was not this script
SCRIPT = r"""echo '== liminal-scan 1'
p1=$(cat /proc/1/comm 2>/dev/null || echo unknown)
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then init=systemd
elif command -v rc-status >/dev/null 2>&1 && { [ -d /run/openrc ] || [ "$p1" = openrc-init ]; }; then init=openrc
elif command -v service >/dev/null 2>&1; then init=sysvinit
else init=none; fi
echo "== init $init $p1"
case $init in
systemd)
  echo '== units'
  systemctl list-units --type=service --all --no-legend --plain --no-pager 2>/dev/null
  echo '== memory'
  running=$(systemctl list-units --type=service --state=running --no-legend --plain --no-pager 2>/dev/null | awk '{print $1}')
  [ -n "$running" ] && systemctl show -p Id -p MainPID -p MemoryCurrent $running 2>/dev/null
  ;;
openrc)
  echo '== openrc'
  rc-status --all 2>/dev/null
  ;;
sysvinit)
  echo '== sysv'
  service --status-all 2>&1
  ;;
esac
echo '== processes'
ps -eo pid=,rss=,comm=,args= 2>/dev/null
echo '== end'
"""

# The system's own: what every Linux runs for itself, counted rather than listed (names without .service).
SYSTEM_NAMES = frozenset({
    # logging, time, scheduling
    "rsyslog", "syslog-ng", "sysklogd", "metalog", "chrony", "chronyd", "ntp", "ntpd", "ntpsec", "openntpd", "cron", "crond",
    "cronie", "anacron", "atd", "fcron", "dcron",
    # the bus, logins, devices, power
    "dbus", "dbus-broker", "polkit", "elogind", "accounts-daemon", "rtkit-daemon", "udisks2", "upower", "thermald",
    "irqbalance", "acpid", "smartd", "multipathd", "dm-event", "mdmonitor", "rngd", "haveged", "uuidd", "gpm",
    # networking's plumbing
    "networkd-dispatcher", "NetworkManager", "ModemManager", "wpa_supplicant", "avahi-daemon", "bluetooth", "connman",
    "dhcpcd", "netplan-configure",
    # packages and updates
    "snapd", "packagekit", "unattended-upgrades", "apport", "whoopsie", "kerneloops", "fwupd", "dnf-makecache",
    "ubuntu-advantage", "landscape-client", "motd-news",
    # WSL's own
    "wsl-pro", "wslg", "wsl-mnt-guard",
    # security plumbing that serves nobody else
    "auditd", "gssproxy", "sssd", "nscd", "apparmor",
    # printing, consoles
    "cups", "cups-browsed", "console-getty", "agetty", "getty", "console-setup", "keyboard-setup", "setvtrgb",
    "kmod-static-nodes",
    # OpenRC's boot services
    "sysfs", "devfs", "procfs", "udev", "udev-trigger", "udev-settle", "udev-postmount", "hwclock", "swclock", "osclock",
    "modules", "modules-load", "fsck", "root", "mtab", "localmount", "netmount", "swap", "hostname", "bootmisc", "binfmt",
    "termencoding", "keymaps", "consolefont", "loopback", "urandom", "seedrng", "sysctl", "savecache", "killprocs",
    "mount-ro", "local", "cgroups", "machine-id", "staticroute", "save-keymaps", "save-termencoding", "dmesg",
})
SYSTEM_PREFIXES = ("systemd-", "getty@", "serial-getty@", "container-getty@", "autovt@", "user@", "user-runtime-dir@",
                   "modprobe@", "snapd.", "apt-", "plymouth", "lvm2-", "ua-", "initrd-", "dracut-", "e2scrub", "agetty.",
                   "net.", "sshd-keygen", "ssh-keygen", "polkit", "fstrim", "logrotate", "man-db", "dpkg-", "ldconfig")

# Major services: what the framework or its user runs, with what each is.
ROLES = {
    "docker": "containers: Docker Engine", "containerd": "containers: Docker's runtime", "podman": "containers: Podman",
    "ssh": "remote access: OpenSSH server", "sshd": "remote access: OpenSSH server", "xrdp": "remote desktop: xrdp",
    "mysql": "database: MySQL", "mysqld": "database: MySQL", "mariadb": "database: MariaDB", "mongod": "database: MongoDB",
    "mongodb": "database: MongoDB", "redis": "database: Redis", "redis-server": "database: Redis", "valkey": "database: Valkey",
    "valkey-server": "database: Valkey", "memcached": "cache: memcached", "influxdb": "database: InfluxDB",
    "clickhouse-server": "database: ClickHouse", "elasticsearch": "search: Elasticsearch", "opensearch": "search: OpenSearch",
    "nginx": "web server: nginx", "apache2": "web server: Apache", "httpd": "web server: Apache", "caddy": "web server: Caddy",
    "lighttpd": "web server: lighttpd", "haproxy": "proxy: HAProxy", "traefik": "proxy: Traefik", "squid": "proxy: Squid",
    "postfix": "mail server: Postfix", "exim4": "mail server: Exim", "exim": "mail server: Exim",
    "opensmtpd": "mail server: OpenSMTPD", "maddy": "mail server: Maddy", "dovecot": "mailboxes: Dovecot",
    "named": "DNS server: BIND", "bind9": "DNS server: BIND", "unbound": "DNS server: Unbound", "dnsmasq": "DNS server: dnsmasq",
    "pdns": "DNS server: PowerDNS", "pdns-recursor": "DNS server: PowerDNS", "coredns": "DNS server: CoreDNS",
    "smbd": "file sharing: Samba", "nmbd": "file sharing: Samba", "samba": "file sharing: Samba",
    "nfs-server": "file sharing: NFS", "nfs-kernel-server": "file sharing: NFS", "vsftpd": "file transfer: vsftpd",
    "libvirtd": "virtual machines: libvirt", "k3s": "Kubernetes: k3s", "kubelet": "Kubernetes: kubelet",
    "ollama": "local AI models: Ollama", "grafana-server": "dashboards: Grafana", "grafana": "dashboards: Grafana",
    "rabbitmq-server": "queue: RabbitMQ", "mosquitto": "queue: Mosquitto (MQTT)", "tailscaled": "VPN: Tailscale",
    "zerotier-one": "VPN: ZeroTier", "fail2ban": "security: Fail2ban", "firewalld": "the firewall: firewalld",
    "ufw": "the firewall: ufw", "nftables": "the firewall: nftables", "iptables": "the firewall: iptables",
    "cloudflared": "tunnel: Cloudflare Tunnel", "jenkins": "builds: Jenkins", "gitea": "code: Gitea", "forgejo": "code: Forgejo",
}
ROLE_PREFIXES = (("postgresql", "database: PostgreSQL"), ("prometheus", "metrics: Prometheus"), ("jupyter", "notebooks: Jupyter"),
                 ("wg-quick@", "VPN: WireGuard"), ("openvpn", "VPN: OpenVPN"))
ONLINE = ("running", "starting")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
OPENRC_ROW = re.compile(r"^\s*(\S+)\s+\[\s*([A-Za-z]+)")
SYSV_ROW = re.compile(r"^\s*\[\s*([+?-])\s*\]\s+(\S+)")
OPENRC_STATES = {"started": "running", "starting": "starting", "crashed": "failed", "failed": "failed", "stopping": "stopping"}
SYSV_STATES = {"+": "running", "-": "stopped", "?": "unknown"}
INIT_WORDS = {"systemd": "systemd", "openrc": "OpenRC", "sysvinit": "no service manager running: SysV scripts through the service command",
              "none": "no init system found", "unknown": "the init system could not be told"}


def classify(name: str) -> tuple[str, str]:
    """A service's kind and what it is: ("major", "containers: Docker Engine"), ("system", "") or ("other", "")."""
    n = name[:-8] if name.endswith(".service") else name
    base = n.split("@", 1)[0]
    if n.startswith("liminal-"):
        return "major", f"Liminal's {n[8:] or 'own'} app"
    if n in ROLES or base in ROLES:
        return "major", ROLES.get(n) or ROLES[base]
    for prefix, role in ROLE_PREFIXES:
        if n.startswith(prefix):
            return "major", role
    if n in SYSTEM_NAMES or base in SYSTEM_NAMES or n.startswith(SYSTEM_PREFIXES):
        return "system", ""
    return "other", ""


@dataclass(frozen=True)
class Service:
    """A service as its init system says it is: `state` running | on (a one-shot done: a firewall's rules loaded) |
    starting | stopping | failed | stopped | unknown."""

    name: str  # without .service
    state: str
    description: str = ""
    kind: str = "other"  # major | other | system
    role: str = ""
    memory: int | None = None  # bytes (systemd's accounting), when known
    pid: int | None = None

    @property
    def online(self) -> bool:
        return self.state in ONLINE or (self.state == "on" and self.kind == "major")

    @property
    def what(self) -> str:
        return self.role or self.description

    def describe(self) -> dict:
        return {"name": self.name, "state": self.state, "kind": self.kind, "what": self.what, "description": self.description,
                "memoryMb": None if self.memory is None else round(self.memory / 2**20), "pid": self.pid}


@dataclass
class Scan:
    """What one run of SCRIPT found."""

    init: str = "unknown"  # systemd | openrc | sysvinit | none | unknown
    pid1: str = ""
    services: list[Service] = field(default_factory=list)
    processes: int = 0
    resident: int = 0  # bytes, every process's resident memory
    at: float = 0.0
    problem: str = ""

    @property
    def major(self) -> list[Service]:
        """The services that matter, online or failed: the major ones first, then the others; the heaviest first."""
        found = [s for s in self.services if s.kind != "system" and (s.online or s.state == "failed")]
        return sorted(found, key=lambda s: (s.kind != "major", s.state == "failed", -(s.memory or 0), s.name))

    @property
    def system(self) -> list[Service]:
        """The system's own services running."""
        return sorted((s for s in self.services if s.kind == "system" and s.state in ONLINE), key=lambda s: s.name)

    @property
    def failed(self) -> list[Service]:
        return sorted((s for s in self.services if s.state == "failed"), key=lambda s: s.name)

    def summary(self) -> str:
        if self.problem:
            return self.problem
        names = ", ".join(s.name + ("" if s.state != "failed" else " (failed)") for s in self.major) or "none of note"
        return f"{names} (+{len(self.system)} of the system's own)"

    def note(self) -> str:
        parts = [INIT_WORDS.get(self.init, self.init) + (f" (PID 1: {self.pid1})" if self.pid1 else "")]
        if self.problem:
            parts.append(self.problem)
        system = [s.name for s in self.system]
        if system:
            parts.append(f"the system's own running: {len(system)} ({', '.join(system[:8])}{', ...' if len(system) > 8 else ''})")
        failed = [s.name for s in self.failed if s.kind == "system"]
        if failed:
            parts.append(f"failed: {', '.join(failed)}")
        if self.processes:
            parts.append(f"{self.processes} processes, {round(self.resident / 2**20)} MB resident")
        if self.at:
            parts.append("scanned " + time.strftime("%H:%M:%S", time.localtime(self.at)))
        return " · ".join(parts)

    def describe(self) -> dict:
        return {"scanned": not self.problem, "init": self.init, "pid1": self.pid1, "major": [s.describe() for s in self.major],
                "system": [s.name for s in self.system], "failed": [s.name for s in self.failed], "processes": self.processes,
                "residentMb": round(self.resident / 2**20), "at": self.at, "problem": self.problem, "summary": self.summary()}

    def table(self, where: str) -> dict:
        """The platform page's table (status.tables): the major services, the system's own in the note."""
        rows = []
        for s in self.major:
            name = {"text": s.name, "sub": "not one Liminal knows"} if s.kind == "other" else s.name
            rows.append([name, s.state, s.what, "" if s.memory is None else f"{round(s.memory / 2**20)} MB"])
        return {"title": f"Services in {where}", "note": self.note(),
                "columns": [{"title": "Service"}, {"title": "State"}, {"title": "What it is"}, {"title": "Memory", "num": True}],
                "rows": rows, "empty": self.problem or "No major service running: only the system's own (in the note above)."}


def parse(text: str, now: float | None = None) -> Scan:
    """SCRIPT's answer as a Scan; one whose first line is not the script's is a problem, never a guess."""
    scan = Scan(at=time.time() if now is None else now)
    text = text or ""
    if MARK not in text:
        scan.problem = "the scan's answer was not understood"
        return scan
    section = ""
    units: dict[str, tuple[str, str, str, str]] = {}  # systemd: name -> (load, active, sub, description)
    memory: dict[str, tuple[int | None, int | None]] = {}  # systemd: name -> (MainPID, MemoryCurrent)
    found: dict[str, Service] = {}  # OpenRC and SysV: by name
    block: dict[str, str] = {}

    def flush() -> None:
        if block.get("Id"):
            memory[_unit(block["Id"])] = (_number(block.get("MainPID")), _number(block.get("MemoryCurrent")))
        block.clear()

    for raw in text.splitlines():
        line = ANSI.sub("", raw).rstrip()
        if line.startswith("== "):
            flush()
            head = line[3:].split()
            section = head[0] if head else ""
            if section == "init":
                scan.init = head[1] if len(head) > 1 else "unknown"
                scan.pid1 = " ".join(head[2:])
            continue
        if section == "units":
            parts = line.split(None, 4)
            if parts and parts[0] in ("●", "*", "×"):
                parts = line.split(None, 5)[1:]
            if len(parts) >= 4 and parts[0].endswith(".service"):
                units[_unit(parts[0])] = (parts[1], parts[2], parts[3], parts[4].strip() if len(parts) > 4 else "")
        elif section == "memory":
            if not line.strip():
                flush()
            elif "=" in line:
                k, _, v = line.partition("=")
                if k == "Id" and block.get("Id"):
                    flush()
                block[k.strip()] = v.strip()
        elif section in ("openrc", "sysv"):
            m = (OPENRC_ROW if section == "openrc" else SYSV_ROW).match(line)
            if not m:
                continue
            if section == "openrc":
                name, state = m.group(1), OPENRC_STATES.get(m.group(2).lower(), "stopped")
            else:
                name, state = m.group(2), SYSV_STATES[m.group(1)]
            kind, role = classify(name)
            if name not in found or found[name].state not in ONLINE + ("failed",):  # listed in two runlevels: the live state kept
                found[name] = Service(name, state, "", kind, role)
        elif section == "processes":
            parts = line.split(None, 3)
            if len(parts) >= 2 and parts[0].isdigit():
                scan.processes += 1
                scan.resident += int(parts[1]) * 1024 if parts[1].isdigit() else 0
    flush()
    for name, (load, active, sub, description) in units.items():
        state = _systemd_state(active, sub)
        if load == "not-found" or (load == "masked" and state != "failed"):
            continue  # named somewhere, not installed (or masked): nothing that runs
        kind, role = classify(name)
        pid, mem = memory.get(name, (None, None))
        found[name] = Service(name, state, description, kind, role, mem, pid or None)
    scan.services = sorted(found.values(), key=lambda s: s.name)
    return scan


def _systemd_state(active: str, sub: str) -> str:
    if active == "active":
        return "on" if sub == "exited" else "running"
    if active == "failed":
        return "failed"
    if active in ("activating", "reloading"):
        return "starting"
    if active == "deactivating":
        return "stopping"
    return "stopped"


def _unit(name: str) -> str:
    return name[:-8] if name.endswith(".service") else name


def _number(text: str | None) -> int | None:
    """systemd's number: None for [not set], an empty value, or the 'infinity' of no accounting."""
    if not text or not text.isdigit():
        return None
    n = int(text)
    return n if n < 2**63 else None
