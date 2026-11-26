"""This Linux's facts as release one needs them, from one POSIX sh read as the platform's user (the linuxperm plan's
PLAN 1.2, revised: 3.4, M1, M3, M14, M21, S2, S4).

PROBE never runs sudo, but `sudo -V`, which asks nothing and logs nothing; it changes nothing and reads only what the
platform's user may read. Its answer is lines of `@@ <what> ...` and the files' texts between `@@ file <path>` and
`@@ end`, in a format the stand-in writes too (`block`, `line`), so the same `parse` reads a real machine and a
recorded one.

What it reads: the files of kernel.FILES (kernel.read takes them: the linuxperm plan's 3.11) and os-release,
login.defs, /etc/group and /etc/passwd, /proc/mounts, its own /proc/self/status (the platform's user's ids, groups and
capabilities, inherited), pid 1's name, SELinux's and AppArmor's state, NixOS's and ostree's marks, the journal and
Liminal's sysusers file; WSL's and the container's variables; who it runs as; every program of plan.TOOLS found in
/run/wrappers/bin (NixOS's set-uid wrappers: S2) or the fixed PATH, with the file each one is (BusyBox's applets are
links to it); the first line of `sudo -V`, `systemd-sysusers --version`, `systemctl --version`, `flock --version`,
`ls --version` and `busybox`, each only where it is; `rpm -q sudo-policy-wheel-auth-self` where rpm is (whose
password openSUSE's sudo asks: M21); the owner, group and mode of each folder a change writes in (the chain) and of
Liminal's own folders; `getent` for the group and the user `liminal` (an account NSS knows that /etc does not); and
the processes running as `liminal`, where it is there (undo refuses while one runs).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from . import journal, kernel, plan
from .shared import ROOT_PATH

PROBE_S = 20.0  # seconds the probe may take; it reads files and asks a few tools their version
NAME = "liminal"  # Liminal's group and user (the user's answer 8: always liminal)
SYSUSERS = "/etc/sysusers.d/liminal.conf"
HOME = "/var/lib/liminal"
HELPERS_FOLDER = "/usr/local/libexec/liminal"  # the firewall's grant makes it root:liminal 0750 (release two moves it)
OS_RELEASE = ("/etc/os-release", "/usr/lib/os-release")
FILES = (*kernel.FILES, *OS_RELEASE, "/etc/login.defs", "/etc/group", "/etc/passwd", "/proc/mounts",
         "/proc/self/status", "/proc/1/comm", "/sys/fs/selinux/enforce", "/etc/selinux/config",
         "/sys/module/apparmor/parameters/enabled", "/run/ostree-booted", "/run/current-system", "/etc/NIXOS",
         "/run/systemd/system", journal.PATH, SYSUSERS)
ENV = kernel.ENV
NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin", "/run/current-system/sw/bin/nologin",
           "/bin/false")
# the folders whose owner and mode the probe reads: every folder of the chains, then Liminal's own
FOLDERS = tuple(dict.fromkeys([p for c in plan.CHAINS for p in plan.prefixes(c)]
                              + ["/usr", "/usr/local", "/usr/local/libexec", HELPERS_FOLDER, HOME]))
VERSIONS = (("sudo", "-V"), ("systemd-sysusers", "--version"), ("systemctl", "--version"), ("flock", "--version"),
            ("ls", "--version"), ("busybox",))
SEARCH = ("/run/wrappers/bin", *ROOT_PATH.split(":"))
FAMILIES = ("debian", "fedora", "rhel", "suse", "arch", "alpine", "gentoo", "void", "nixos", "slackware")


def line(what: str, *words) -> str:
    """One line of the probe's answer: `@@ <what> <words>`."""
    return " ".join(["@@", what, *(str(w) for w in words)]) + "\n"


def block(path: str, text) -> str:
    """A file as the probe prints it: its text between `@@ file` and `@@ end`; None: absent. A folder, or a file there
    that its user cannot read, is `line("there", path)`."""
    if text is None:
        return line("absent", path)
    return line("file", path) + text + "\n" + "@@ end\n"


def _probe() -> str:
    tools = " ".join(sorted({t[0] for t in plan.TOOLS} | {"busybox", "systemctl", "openrc", "run0", "pkexec",
                                                          "readlink"}))
    out = ["exec </dev/null", f"PATH=/run/wrappers/bin:{ROOT_PATH}; export PATH", "LC_ALL=C; export LC_ALL",
           "lm_file() {",
           "  if [ -f \"$1\" ] && [ -r \"$1\" ]; then printf '@@ file %s\\n' \"$1\"; cat \"$1\"; printf '\\n@@ end\\n'",
           "  elif [ -e \"$1\" ]; then printf '@@ there %s\\n' \"$1\"",
           "  else printf '@@ absent %s\\n' \"$1\"; fi",
           "}",
           f"for lm_f in {' '.join(FILES)}; do lm_file \"$lm_f\"; done"]
    out += [f"[ -n \"${{{v}+x}}\" ] && printf '@@ env {v} %s\\n' \"${v}\"" for v in ENV]
    out += ["printf '@@ id %s %s\\n' \"$(id -u)\" \"$(id -un 2>/dev/null)\"",
            "printf '@@ groups %s\\n' \"$(id -G 2>/dev/null)\"",
            "printf '@@ groupnames %s\\n' \"$(id -Gn 2>/dev/null)\"",
            f"for lm_t in {tools}; do",
            f"  for lm_d in {' '.join(SEARCH)}; do",
            "    if [ -x \"$lm_d/$lm_t\" ] && [ ! -d \"$lm_d/$lm_t\" ]; then",
            "      printf '@@ tool %s %s %s\\n' \"$lm_t\" \"$lm_d/$lm_t\" "
            "\"$(readlink -f \"$lm_d/$lm_t\" 2>/dev/null)\"",
            "      break",
            "    fi",
            "  done",
            "done",
            f"for lm_p in {' '.join(NOLOGIN)}; do [ -x \"$lm_p\" ] && printf '@@ exec %s\\n' \"$lm_p\"; done",
            "lm_version() {",
            "  command -v \"$1\" >/dev/null 2>&1 || return 0",
            "  printf '@@ version %s %s\\n' \"$1\" \"$(\"$@\" 2>&1 </dev/null | head -n 1)\"",
            "}"]
    out += [f"lm_version {' '.join(v)}" for v in VERSIONS]
    out += ["if command -v rpm >/dev/null 2>&1; then",
            "  printf '@@ version rpm-wheel-auth-self %s\\n' "
            "\"$(rpm -q sudo-policy-wheel-auth-self 2>&1 | head -n 1)\"",
            "fi",
            f"for lm_p in {' '.join(FOLDERS)}; do",
            "  if [ -L \"$lm_p\" ]; then lm_l=$(stat -c %u \"$lm_p\" 2>/dev/null || printf '?'); else lm_l=-; fi",
            "  if [ -e \"$lm_p\" ]; then",
            "    printf '@@ folder %s %s %s\\n' \"$lm_p\" \"$(stat -L -c '%u %g %a' \"$lm_p\" 2>/dev/null || "
            "printf '? ? ?')\" \"$lm_l\"",
            "  else printf '@@ folder %s absent\\n' \"$lm_p\"; fi",
            "done",
            "if command -v getent >/dev/null 2>&1; then",
            f"  printf '@@ getent group %s\\n' \"$(getent group {NAME})\"",
            f"  printf '@@ getent passwd %s\\n' \"$(getent passwd {NAME})\"",
            "fi",
            f"lm_u=$(awk -F: '$1 == \"{NAME}\" {{ print $3; exit }}' /etc/passwd 2>/dev/null)",
            "if [ -n \"$lm_u\" ]; then",
            "  awk -v u=\"$lm_u\" 'FNR == 1 { n = \"\" } /^Name:/ { n = $2 } /^Uid:/ { if ($2 == u) print \"@@ proc \" "
            "FILENAME \" \" n }' /proc/[0-9]*/status 2>/dev/null",
            "fi",
            "printf '@@ probe end\\n'"]
    return "\n".join(out) + "\n"


PROBE = _probe()
ARGV = ("/bin/sh", "-c", PROBE, "liminal-probe")


# ---- what it found -----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Group:
    name: str
    gid: int
    members: tuple[str, ...] = ()


@dataclass(frozen=True)
class User:
    name: str
    uid: int
    gid: int
    comment: str = ""
    home: str = ""
    shell: str = ""


@dataclass(frozen=True)
class SystemFacts:
    """What the probe found. `os` {id, like, version, pretty, family}; `kernel` (kernel.KernelFacts); `init` {pid1,
    systemd}; `layout` {read_only {path: bool}, ostree, nixos, nologin, folders {path: plan.Folder or None}};
    `security` {selinux, apparmor, restorecon}; `accounts` {tool, sysusers, logindefs, uid_min, gid_min,
    usergroups, groups {name: Group}, users {name: User}}; `elevation` {euid, user, gids, groupnames, sudo, sudo_kind,
    sudo_version, doas, su, pkexec, run0, wheel_auth_self, caps, no_new_privs}; `liminal` {group, user, getent_group,
    getent_passwd, journal, sysusers, processes}; `tools` {name: (path, the file it is)}; `coreutils` (gnu, uutils,
    busybox, ""); `versions` {tool: first line}; `notes`: what could not be read, and why."""

    os: dict = field(default_factory=dict)
    kernel: kernel.KernelFacts = kernel.KernelFacts()
    init: dict = field(default_factory=dict)
    layout: dict = field(default_factory=dict)
    security: dict = field(default_factory=dict)
    accounts: dict = field(default_factory=dict)
    elevation: dict = field(default_factory=dict)
    liminal: dict = field(default_factory=dict)
    tools: dict = field(default_factory=dict)
    coreutils: str = ""
    versions: dict = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    @property
    def lock(self) -> str:
        """The lock's form a script takes here: flock where flock(1) is (util-linux's or BusyBox's), else a folder."""
        return "flock" if "flock" in self.tools else "mkdir"

    def chain(self, path: str) -> str:
        """plan.chain's words for `path` on this machine, as its user read the folders."""
        return plan.chain(path, self.layout.get("folders", {}))

    def system_account(self, user: User | None) -> bool:
        """Whether `user` is a system account: a uid below UID_MIN (1000 when login.defs says none), Liminal's user,
        or a nologin shell (B2)."""
        if user is None:
            return False
        return (user.uid < self.accounts.get("uid_min", 1000) or user.name == NAME
                or user.shell.rsplit("/", 1)[-1] in ("nologin", "false"))

    def here(self) -> journal.Here:
        """What journal.fold reads Liminal's lines against."""
        groups = {g.name: (g.gid, g.members) for g in self.accounts.get("groups", {}).values()}
        users = {u.name: (u.uid, u.gid) for u in self.accounts.get("users", {}).values()}
        paths: dict = {}
        for path, f in self.layout.get("folders", {}).items():
            if f is not None:
                paths[path] = ""
        if self.liminal.get("sysusers") is not None:
            paths[SYSUSERS] = hashlib.sha256(self.liminal["sysusers"].encode("utf-8")).hexdigest()
        if self.liminal.get("journal") is not None:
            paths[journal.PATH] = journal.digest(self.liminal["journal"])
        return journal.Here(groups, users, paths)

    def made(self) -> journal.Made:
        """What the journal says Liminal made here, folded against what is here now."""
        return journal.fold(self.liminal.get("journal"), self.here(), NAME)

    def describe(self) -> dict:
        """The facts as JSON, for the page's tables and the command's `facts`."""
        def plain(v):
            if isinstance(v, (Group, User, plan.Folder)):
                return {k: plain(x) for k, x in v.__dict__.items()}
            if isinstance(v, dict):
                return {k: plain(x) for k, x in v.items()}
            if isinstance(v, (list, tuple)):
                return [plain(x) for x in v]
            return v
        return {"v": 1, "os": plain(self.os), "kernel": self.kernel.describe(), "init": plain(self.init),
                "layout": plain(self.layout), "security": plain(self.security), "accounts": plain(self.accounts),
                "elevation": plain(self.elevation), "liminal": plain(self.liminal), "tools": plain(self.tools),
                "coreutils": self.coreutils, "versions": dict(self.versions), "lock": self.lock,
                "made": self.made().describe(), "notes": list(self.notes)}


def read(runner) -> SystemFacts:
    """This Linux's facts, by PROBE run through `runner(argv, timeout)`, which answers as subprocess.run does
    (`returncode`, `stdout` as text). LinuxAdmin hands it proctree.run with the frame's environment; the command,
    subprocess's. Never a WSL target from outside (M3): the runner runs on this Linux."""
    done = runner(list(ARGV), PROBE_S)
    facts = parse(done.stdout or "")
    if done.returncode not in (0, None) and "@@ probe end" not in (done.stdout or ""):
        facts = _with_note(facts, f"the probe ended with exit {done.returncode} before its end")
    return facts


def _with_note(facts: SystemFacts, note: str) -> SystemFacts:
    from dataclasses import replace
    return replace(facts, notes=(*facts.notes, note))


# ---- reading the answer ------------------------------------------------------------------------------------------


def sections(text: str) -> dict:
    """The probe's answer as data: files {path: text, "" there and unread, None absent}, unread (the paths there and
    not read: a folder, a file its user may not read), env, id, groups, groupnames, tools {name: (path, real)},
    execs, versions, folders {path: words}, getent, procs, end."""
    out = {"files": {}, "unread": set(), "env": {}, "id": ("", ""), "groups": "", "groupnames": "", "tools": {},
           "execs": [],
           "versions": {}, "folders": {}, "getent": {}, "procs": [], "end": False}
    lines = (text or "").split("\n")
    i = 0
    while i < len(lines):
        row = lines[i]
        i += 1
        if not row.startswith("@@ "):
            continue
        what, _, rest = row[3:].partition(" ")
        if what == "file":
            body = []
            while i < len(lines) and lines[i] != "@@ end":
                body.append(lines[i])
                i += 1
            i += 1
            out["files"][rest] = "\n".join(body)
        elif what in ("there", "absent"):
            out["files"][rest] = "" if what == "there" else None
            if what == "there":
                out["unread"].add(rest)
        elif what == "env":
            name, _, value = rest.partition(" ")
            out["env"][name] = value
        elif what == "id":
            uid, _, name = rest.partition(" ")
            out["id"] = (uid, name)
        elif what in ("groups", "groupnames"):
            out[what] = rest
        elif what == "tool":
            name, _, paths = rest.partition(" ")
            path, _, real = paths.partition(" ")
            out["tools"][name] = (path, real or path)
        elif what == "exec":
            out["execs"].append(rest)
        elif what == "version":
            name, _, value = rest.partition(" ")
            out["versions"][name] = value.strip()
        elif what == "folder":
            path, _, words = rest.partition(" ")
            out["folders"][path] = words
        elif what == "getent":
            kind, _, value = rest.partition(" ")
            out["getent"][kind] = value.strip()
        elif what == "proc":
            out["procs"].append(rest)
        elif what == "probe" and rest == "end":
            out["end"] = True
    return out


def _keyvalues(text) -> dict:
    out = {}
    for row in (text or "").splitlines():
        key, eq, value = row.partition("=")
        if eq and key.strip() and not key.strip().startswith("#"):
            out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _logindefs(text) -> dict:
    out = {}
    for row in (text or "").splitlines():
        parts = row.split()
        if len(parts) >= 2 and not parts[0].startswith("#"):
            out[parts[0]] = parts[1]
    return out


def _int(text, default: int) -> int:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def _groups(text) -> dict:
    out = {}
    for row in (text or "").splitlines():
        p = row.split(":")
        if len(p) >= 4 and p[2].strip().isdigit() and p[0] not in out:
            out[p[0]] = Group(p[0], int(p[2]), tuple(m for m in p[3].strip().split(",") if m))
    return out


def _users(text) -> dict:
    out = {}
    for row in (text or "").splitlines():
        p = row.split(":")
        if len(p) >= 7 and p[2].isdigit() and p[3].isdigit() and p[0] not in out:
            out[p[0]] = User(p[0], int(p[2]), int(p[3]), p[4], p[5], p[6].strip())
    return out


def _mounts(text) -> list[tuple[str, bool]]:
    out = []
    for row in (text or "").splitlines():
        p = row.split()
        if len(p) >= 4:
            out.append((p[1].replace("\\040", " "), "ro" in p[3].split(",")))
    return out


def read_only(mounts: list[tuple[str, bool]], path: str) -> bool | None:
    """Whether the mount covering `path` is read-only (the last mounted of the longest point that holds it), None
    when no line covers it."""
    best: tuple[int, bool] | None = None
    for point, ro in mounts:
        inside = path == point or path.startswith(point.rstrip("/") + "/") or point == "/"
        if inside and (best is None or len(point) >= best[0]):
            best = (len(point), ro)
    return None if best is None else best[1]


def _family(osr: dict) -> str:
    ids = [osr.get("ID", "").lower(), *osr.get("ID_LIKE", "").lower().split()]
    for i in ids:
        for fam in FAMILIES:
            if i == fam or (fam == "suse" and i.startswith(("opensuse", "sles", "suse"))) or (
                    fam == "rhel" and i in ("centos", "rocky", "almalinux")):
                return fam
        if i == "ubuntu":
            return "debian"
    return ""


def _status(text) -> dict:
    out = {}
    for row in (text or "").splitlines():
        key, _, value = row.partition(":")
        out[key.strip()] = value.strip()
    return out


def _systemd_version(line: str) -> int:
    """systemd's own version, from `systemd 255 (255.4-1ubuntu8)`; 0 for any other answer (Debian's opensysusers)."""
    m = re.match(r"systemd (\d+)\b", line or "")
    return int(m.group(1)) if m else 0


def _folder(words: str):
    if words == "absent":
        return None
    p = words.split()
    if len(p) != 4 or not all(x.isdigit() for x in p[:2]) or not re.fullmatch(r"[0-7]+", p[2]):
        return "?"
    return plan.Folder(int(p[0]), int(p[1]), int(p[2], 8), None if p[3] == "-" else _int(p[3], -1))


def parse(text: str) -> SystemFacts:
    """The facts from the probe's answer, a real machine's or the stand-in's."""
    s = sections(text)
    files, notes = s["files"], []
    if not s["end"]:
        notes.append("the probe's answer was cut off before its end: what follows it is not known")
    osr = _keyvalues(files.get(OS_RELEASE[0]) or files.get(OS_RELEASE[1]))
    family = _family(osr)
    if not osr:
        notes.append("os-release could not be read: the distribution is not known")
    elif not family:
        notes.append(f"the distribution {osr.get('ID', '?')} is none Liminal knows the family of")
    k = kernel.read(files, s["env"])
    defs = _logindefs(files.get("/etc/login.defs"))
    groups, users = _groups(files.get("/etc/group")), _users(files.get("/etc/passwd"))
    if files.get("/etc/group") is None or files.get("/etc/passwd") is None:
        notes.append("/etc/group or /etc/passwd could not be read")
    tools = s["tools"]
    versions = s["versions"]
    sysusers = _systemd_version(versions.get("systemd-sysusers", ""))
    nixos = files.get("/etc/NIXOS") is not None or osr.get("ID") == "nixos"
    busybox = lambda name: name in tools and tools[name][1].endswith("/busybox")  # noqa: E731
    if nixos:
        tool = "nix"
    elif "systemd-sysusers" in tools and sysusers >= 255:
        tool = "sysusers"
    elif all(t in tools and not busybox(t) for t in ("groupadd", "useradd", "gpasswd", "userdel", "groupdel")):
        tool = "shadow"
    elif all(busybox(t) for t in ("addgroup", "adduser", "deluser", "delgroup")):
        tool = "busybox"
    else:
        tool = "none"
    if "systemd-sysusers" in tools and 0 < sysusers < 255:
        notes.append(f"systemd-sysusers here is systemd {sysusers}'s: Liminal takes it from 255 on")
    elif "systemd-sysusers" in tools and not sysusers:
        notes.append("the systemd-sysusers here is not systemd's own: shadow's tools are taken")
    ls = versions.get("ls", "")
    coreutils = ("gnu" if "GNU coreutils" in ls else "uutils" if "uutils" in ls
                 else "busybox" if busybox("ls") else "")
    status = _status(files.get("/proc/self/status"))
    uid, name = s["id"]
    sudo_version = versions.get("sudo", "")
    mounts = _mounts(files.get("/proc/mounts"))
    folders = {}
    for path, words in s["folders"].items():
        f = _folder(words)
        if f == "?":
            notes.append(f"{path} could not be read (its owner and mode)")
        else:
            folders[path] = f
    enforce = files.get("/sys/fs/selinux/enforce")
    selinux = ("absent" if enforce is None and files.get("/etc/selinux/config") is None
               else "enforcing" if (enforce or "").strip() == "1" else "permissive" if (enforce or "").strip() == "0"
               else "disabled")
    apparmor = files.get("/sys/module/apparmor/parameters/enabled")
    systemctl = _systemd_version(versions.get("systemctl", ""))
    lim_group = groups.get(NAME)
    lim_user = users.get(NAME)
    journal_text = files.get(journal.PATH)
    if journal.PATH in s["unread"]:
        notes.append(f"{journal.PATH} is there and could not be read")
        journal_text = None
    return SystemFacts(
        os={"id": osr.get("ID", ""), "like": tuple(osr.get("ID_LIKE", "").split()),
            "version": osr.get("VERSION_ID", ""),
            "variant": osr.get("VARIANT_ID", ""), "pretty": osr.get("PRETTY_NAME", ""), "family": family},
        kernel=k,
        init={"pid1": (files.get("/proc/1/comm") or "").strip(),
              "systemd": files.get("/run/systemd/system") is not None,
              "version": systemctl},
        layout={"read_only": {p: read_only(mounts, p) for p in ("/", "/etc", "/var/lib", "/usr", "/usr/local")},
                "ostree": files.get("/run/ostree-booted") is not None, "nixos": nixos,
                "nologin": next((p for p in NOLOGIN if p in s["execs"]), ""), "folders": folders},
        security={"selinux": selinux, "apparmor": "absent" if apparmor is None else
                  "on" if apparmor.strip().upper().startswith("Y") else "off", "restorecon": "restorecon" in tools},
        accounts={"tool": tool, "sysusers": sysusers, "logindefs": defs, "uid_min": _int(defs.get("UID_MIN"), 1000),
                  "gid_min": _int(defs.get("GID_MIN"), 1000),
                  "usergroups": defs.get("USERGROUPS_ENAB", "yes").lower() == "yes", "groups": groups, "users": users},
        elevation={"euid": _int(uid, -1), "user": name, "gids": tuple(_int(g, -1) for g in s["groups"].split()),
                   "groupnames": tuple(s["groupnames"].split()), "sudo": tools.get("sudo", ("", ""))[0],
                   "sudo_kind": ("" if "sudo" not in tools else "sudo-rs" if "sudo-rs" in sudo_version.lower()
                                 else "sudo"),
                   "sudo_version": sudo_version, "doas": tools.get("doas", ("", ""))[0],
                   "su": tools.get("su", ("", ""))[0], "pkexec": tools.get("pkexec", ("", ""))[0],
                   "run0": tools.get("run0", ("", ""))[0] if systemctl >= 256 else "",
                   "wheel_auth_self": _wheel(versions.get("rpm-wheel-auth-self")),
                   "running_gids": tuple(_int(g, -1) for g in status.get("Groups", "").split()),
                   "caps": {k: status.get(k, "") for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
                   "no_new_privs": status.get("NoNewPrivs", "") == "1"},
        liminal={"group": lim_group, "user": lim_user, "getent_group": s["getent"].get("group", ""),
                 "getent_passwd": s["getent"].get("passwd", ""), "journal": journal_text,
                 "sysusers": files.get(SYSUSERS), "processes": tuple(s["procs"])},
        tools=dict(tools), coreutils=coreutils, versions=dict(versions), notes=tuple(notes + list(k.notes)))


def _wheel(answer: str | None) -> bool | None:
    """Whether sudo-policy-wheel-auth-self is installed (openSUSE: wheel's members then type their own password),
    from rpm's answer; None where rpm is not here."""
    if answer is None:
        return None
    return not ("not installed" in answer or not answer.strip())
