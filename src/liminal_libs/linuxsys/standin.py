"""A recorded machine that stands in for a real Linux in every suite that tests linuxsys and Linux administration (the
linuxperm plan's 3.4 and 3.9: Tier A only, the user's answer 14). It runs nothing: no process, no sh, no socket.

`Machine(name, overlay=None)` loads `recorded/<name>/machine.json` (and the overlay `recorded/<name>/overlays/
<overlay>.json` over it: a few files changed, its own `source`), with the SOURCE beside it that says where it comes
from ("written <date> from <sources>", or "captured <date>"). It holds a tree: the files the probe reads, /etc/group
and /etc/passwd among them, and the folders with their owner and mode. Then:

- it answers PROBE (`answer`, and `run` with facts.ARGV) from the tree as it is now, in the probe's own format;
- it plays a plan's Actions as root on the tree (`play`, or `run` with `/bin/sh -c <script> liminal <nonce>` as root,
  or a sudo conversation's script), with their tools' side effects as the tools' sources have them, and writes the
  journal's lines, the markers and the exit code the script would. The plan is found by its script (plan.known);
- it plays sudo's conversation as a process with byte pipes (`spawn`): the prompt with the marker, the password read
  from standard input only, the retry words of classic sudo or sudo-rs, a second factor's second prompt, end of input
  at a prompt (recorded: `eof_at_prompt`, which no caller may cause), SIGKILL and TERM;
- it stops a run after any step at three points ("before" its tool, "tool": after it, "done": after its done line):
  `stop_at` kills the run there (as SIGKILL would), `term_at` tells it TERM there (it finishes the step and exits 7),
  `hold_at` leaves it running there until the caller ends or resumes it (two runs at once: the lock);
- it records every argv, environment and standard input it is handed (`calls`), and every program a played step
  ran (`programs`, for the API cards), and how many sudo conversations reached their script (`sudo_runs`).

The tools' side effects it plays:
- shadow's groupadd and useradd take a system id from SYS_GID_MAX (SYS_UID_MAX) down; systemd-sysusers from 999
  down, a user's uid the same as its group's gid where that is free, and it skips a name that is there and never
  removes; BusyBox's addgroup -S and adduser -S take the first free id from 100 up;
- shadow's userdel takes the user out of every group and removes the group of the user's name when USERGROUPS_ENAB
  is yes, the group is the user's primary group, no member is left in it and no other user has it as primary group
  (userdel.c `remove_usergroup`); BusyBox's deluser removes that group whatever its members, unless another user has
  it as primary group (deluser.c); both refuse (8) while a process of the user runs;
- gpasswd -d (and BusyBox's delgroup user group) fails (3) on a user who is no member; groupdel refuses (8) a group
  that is a user's primary group; a tool not on the machine fails as sh does (127).
An Action names its tool in `tool` (shadow, busybox, sysusers). The account kinds' arguments: group(name),
user(name, group, comment, home, shell), sysusers(path, name, absent), member and unmember(user, group), unuser(name),
ungroup(name), move(name, gid).
"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import threading
import time
from pathlib import Path

from . import facts, journal, plan

RECORDED = Path(__file__).parent / "recorded"
PASSWORD = "stand-in words"  # the one password the stand-in's sudo takes: a test's, of no account anywhere
PROMPT_WAIT_S = 10.0  # how long a read of a stand-in's pipe waits before it says the caller would wait forever
CLASSIC_RETRY = "Sorry, try again."
RS_RETRY = "Authentication failed, try again."
POINTS = ("before", "tool", "done")
# the program each Action's tool runs, by its kind and tool
PROGRAMS = {
    ("group", "shadow"): "groupadd", ("group", "busybox"): "addgroup",
    ("user", "shadow"): "useradd", ("user", "busybox"): "adduser",
    ("sysusers", "sysusers"): "systemd-sysusers",
    ("member", "shadow"): "gpasswd", ("member", "sysusers"): "gpasswd", ("member", "busybox"): "addgroup",
    ("unmember", "shadow"): "gpasswd", ("unmember", "sysusers"): "gpasswd", ("unmember", "busybox"): "delgroup",
    ("unuser", "shadow"): "userdel", ("unuser", "sysusers"): "userdel", ("unuser", "busybox"): "deluser",
    ("ungroup", "shadow"): "groupdel", ("ungroup", "sysusers"): "groupdel", ("ungroup", "busybox"): "delgroup",
    ("move", "shadow"): "usermod", ("move", "sysusers"): "usermod",
}
GENERIC = {"folder": ("install",), "file": ("chmod", "sync", "mv"), "unfile": ("rm",), "unfolder": ("rmdir",),
           "regroup": ("chgrp",), "relabel": ("restorecon",), "adopt": (), "unjournal": ("rm", "rmdir")}


def machines() -> list[str]:
    """The recorded machines' names."""
    return sorted(p.name for p in RECORDED.iterdir() if (p / "machine.json").is_file()) if RECORDED.is_dir() else []


def overlays(name: str) -> list[str]:
    folder = RECORDED / name / "overlays"
    return sorted(p.stem for p in folder.glob("*.json")) if folder.is_dir() else []


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            for k, v in value.items():
                if v is None and key not in ("files",):
                    out[key].pop(k, None)
                else:
                    out[key][k] = v
        else:
            out[key] = copy.deepcopy(value)
    return out


class Machine:
    """A recorded Linux, played (the module's words say how)."""

    def __init__(self, name: str, overlay: str | None = None, *, password: str = PASSWORD):
        folder = RECORDED / name
        data = json.loads((folder / "machine.json").read_text(encoding="utf-8"))
        self.name, self.overlay = name, overlay
        self.source = (folder / "SOURCE").read_text(encoding="utf-8").strip()
        if overlay:
            over = json.loads((folder / "overlays" / f"{overlay}.json").read_text(encoding="utf-8"))
            self.source += "\n" + str(over.pop("source", f"overlay {overlay}"))
            data = _merge(data, over)
        self.data = data
        self.files: dict = dict(data.get("files", {}))
        self.folders: dict = {p: facts._folder(w) for p, w in data.get("folders", {}).items()}
        self.unread: set = set(data.get("unread", ()))
        self.password = password
        self.calls: list[dict] = []
        self.programs: list[str] = []
        self.sudo_runs = 0
        self.eof_at_prompt = False
        self.stop_at: tuple[int, str] | None = None
        self.term_at: tuple[int, str] | None = None
        self.hold_at: tuple[int, str] | None = None
        self.clock = data.get("time", 1764000000)
        self._flock: int | None = None
        self._live: set[int] = set()
        self._next_pid = 4000

    # ---- what it is ------------------------------------------------------------------------------------------

    @property
    def euid(self) -> int:
        return int(str(self.data.get("id", "1000 user")).split()[0])

    @property
    def tools(self) -> dict:
        return dict(self.data.get("tools", {}))

    @property
    def sudo(self) -> dict:
        """How its sudo behaves: kind (sudo, sudo-rs), asks (a password), whose (the user the prompt names),
        second_factor, listing (`sudo -n -l`'s answer), refuses (`sudo -n`'s words where it asks)."""
        return dict(self.data.get("sudo", {}))

    def facts(self) -> facts.SystemFacts:
        return facts.parse(self.answer())

    def groups(self) -> dict:
        return facts._groups(self.files.get("/etc/group"))

    def users(self) -> dict:
        return facts._users(self.files.get("/etc/passwd"))

    def snapshot(self) -> dict:
        """The tree as a restart leaves it (/run set aside, and /proc and /sys, which are the kernel's): what apply
        then undo must give back."""
        keep = lambda p: not p.startswith(("/run/", "/proc/", "/sys/")) and p != "/run"  # noqa: E731
        return {"files": {p: t for p, t in sorted(self.files.items()) if keep(p) and t is not None},
                "folders": {p: f for p, f in sorted(self.folders.items()) if keep(p) and f is not None}}

    # ---- the probe ---------------------------------------------------------------------------------------------

    def answer(self) -> str:
        """PROBE's answer, from the tree as it is now."""
        d = self.data
        out = ""
        for path in facts.FILES:
            if path in self.unread or (path not in self.files and self.folders.get(path) is not None):
                out += facts.line("there", path)
            else:
                out += facts.block(path, self.files.get(path))
        for k, v in d.get("env", {}).items():
            out += facts.line("env", k, v)
        out += facts.line("id", d.get("id", "1000 user"))
        out += facts.line("groups", d.get("groups", "")) + facts.line("groupnames", d.get("groupnames", ""))
        for name, words in self.tools.items():
            path, _, real = words.partition(" ")
            out += facts.line("tool", name, path, real or path)
        out += "".join(facts.line("exec", e) for e in d.get("execs", ()))
        for k, v in d.get("versions", {}).items():
            out += facts.line("version", k, v)
        for path in facts.FOLDERS:
            f = self.folders.get(path)
            out += facts.line("folder", path, "absent" if f is None else
                              f"{f.uid} {f.gid} {f.mode:o} {'-' if f.link_uid is None else f.link_uid}")
        if "getent" in self.tools:
            nss = d.get("nss", {})
            g, u = self.groups().get(facts.NAME), self.users().get(facts.NAME)
            out += facts.line("getent", "group", nss.get("group") or (
                f"{g.name}:x:{g.gid}:{','.join(g.members)}" if g else ""))
            out += facts.line("getent", "passwd", nss.get("passwd") or (
                f"{u.name}:x:{u.uid}:{u.gid}:{u.comment}:{u.home}:{u.shell}" if u else ""))
        if self.users().get(facts.NAME):
            out += "".join(facts.line("proc", p) for p in d.get("procs", ()))
        return out + facts.line("probe", "end")

    # ---- the runner ---------------------------------------------------------------------------------------------

    def run(self, argv, timeout=None, input=None, env=None, **_kw) -> subprocess.CompletedProcess:
        """As proctree.run or subprocess.run would answer, for what it was recorded to answer: the probe; sudo's
        listing (`env LC_ALL=C sudo -n -l`); a plan's script run as root (`/bin/sh -c <script> liminal <nonce>`, when
        the machine's user is root). Anything else is not recorded: 127, and said."""
        argv = list(argv)
        self.calls.append({"argv": argv, "env": dict(env or {}), "stdin": input})
        if tuple(argv) == facts.ARGV:
            return subprocess.CompletedProcess(argv, 0, self.answer(), "")
        if argv[-3:] == ["sudo", "-n", "-l"] or argv[-2:] == ["-n", "-l"]:
            listing = self.sudo.get("listing")
            if listing is None:
                return subprocess.CompletedProcess(argv, 1, "", self.sudo.get("refuses", "sudo: a password is "
                                                                                       "required\n"))
            return subprocess.CompletedProcess(argv, 0, listing, "")
        if len(argv) == 5 and argv[:2] == ["/bin/sh", "-c"] and argv[3] == "liminal":
            if self.euid != 0:
                return subprocess.CompletedProcess(argv, 1, "", "standin: only root runs a plan's script here\n")
            out, err = [], []
            code = self._drive(self._script(argv[2], argv[4], self._pid(), out.append, err.append), None)
            return subprocess.CompletedProcess(argv, code, "".join(out), "".join(err))
        return subprocess.CompletedProcess(argv, 127, "", f"standin: {argv[:1]} is not recorded on {self.name}\n")

    def play(self, a_plan: plan.Plan, nonce: str = "0123456789abcdef") -> tuple[int, str, str]:
        """Play `a_plan` as root, as its script would run: (exit code, standard output, standard error)."""
        out, err = [], []
        code = self._drive(self._script(a_plan.script(), nonce, self._pid(), out.append, err.append), None)
        return code, "".join(out), "".join(err)

    def spawn(self, argv, env=None, **_kw) -> "Process":
        """sudo's conversation (`... sudo -S -k -u root -p <prompt> -- /bin/sh -c <script> liminal <nonce>`), or a
        root shell's script on a machine whose user is root (`/bin/sh -c <script> liminal <nonce>`), as a
        process with byte pipes, as lifecycle.spawn would start it. Its pipes' reads block, as a real pipe's do, so
        a caller reads them from threads."""
        argv = list(argv)
        self.calls.append({"argv": argv, "env": dict(env or {}), "stdin": b""})
        return Process(self, argv, self.calls[-1])

    def _pid(self) -> int:
        self._next_pid += 1
        return self._next_pid

    # ---- a script, played ----------------------------------------------------------------------------------------

    def _drive(self, run, process: "Process | None", word: str | None = None) -> int | None:
        """Drive a played script from where it stands (`word`: what it is told at the point it was held at; None to
        start it) to its end, and its exit code; at a hold point with a process, leave it held there (None)."""
        while True:
            try:
                point = run.send(word)
                if point == self.stop_at:
                    run.throw(_Killed)
            except StopIteration as done:
                return done.value
            word = "term" if point == self.term_at else "go"
            if point == self.hold_at and process is not None:
                process._held = run
                return None

    def _script(self, script: str, nonce: str, pid: int, out, err):
        """The generator that plays `script`'s plan: it yields at each stop point, (step, point), and is told "go"
        or "term" back, or thrown _Killed (SIGKILL)."""
        the_plan = plan.known(script)
        err(f"@@ liminal-begin {nonce}\n")
        if the_plan is None:
            err("standin: this script is no plan made in this process\n")
            return 2
        self._live.add(pid)
        killed = False
        lock_dir = plan.LOCK
        try:
            if the_plan.lock == "flock":
                if "flock" not in self.tools:
                    err("sh: flock: not found\n")
                    out("@@ refused lock held\n")
                    return 2
                if self._flock is not None and self._flock in self._live:
                    out("@@ refused lock held\n")
                    return 2
                self._flock = pid
            else:
                if self.folders.get(lock_dir) is not None:
                    held = (self.files.get(lock_dir + "/pid") or "").strip()
                    alive = not held or (held.isdigit() and int(held) in self._live)
                    out(f"@@ refused lock {'held' if alive else 'stale'} {held}\n")
                    return 2
                self.folders[lock_dir] = plan.Folder(0, 0, 0o700)
                self.files[lock_dir + "/pid"] = f"{pid}\n"
            for path in the_plan.chains:
                for p in plan.prefixes(path):  # lm_safe on each folder: the first one that fails is named
                    if plan.chain(p, {q: self.folders.get(q) for q in plan.prefixes(p)}):
                        out(f"@@ refused chain {p}\n")
                        return 5
            if self.folders.get(journal.FOLDER) is None:
                self.folders[journal.FOLDER] = plan.Folder(0, 0, 0o755)
            if self.files.get(journal.PATH) is None:
                self.files[journal.PATH] = ""
            for n, guard in enumerate(the_plan.guards, 1):
                if guard.value[0] == "grants":
                    named = self.grants(guard.value[1])
                    if named:
                        out(f"@@ refused grants {' '.join(named)}\n")
                        return 2
                    continue
                if self._value(*guard.value) != guard.expected:
                    out(f"@@ refused guard {n}\n")
                    return 2
            self._journal(f"run {nonce} {the_plan.what} {self.clock}")
            for n, step in enumerate(the_plan.steps, 1):
                stop = False
                if self._there(step.action):
                    out(f"@@ step {n} there 0\n")
                else:
                    begin, done = step.lines(n)
                    if begin is not None:
                        self._journal(begin.fill(self._value).text())
                    stop = (yield (n, "before")) == "term" or stop
                    code = self._do(step.action)
                    if code:
                        out(f"@@ step {n} failed {code}\n")
                        self._journal(f"end {nonce} 1")
                        return 1
                    stop = (yield (n, "tool")) == "term" or stop
                    for d in done:
                        self._journal(d.fill(self._value).text())
                    stop = (yield (n, "done")) == "term" or stop
                    out(f"@@ step {n} done 0\n")
                if stop:
                    out("@@ stopped\n")
                    self._journal(f"end {nonce} 7")
                    return 7
            self._journal(f"end {nonce} 0")
            return 0
        except _Killed:
            killed = True
            return -9
        finally:
            self._live.discard(pid)
            if self._flock == pid:
                self._flock = None  # the kernel lets go of an flock when its holder ends, SIGKILL included
            if not killed and (self.files.get(lock_dir + "/pid") or "").strip() == str(pid):
                self.files.pop(lock_dir + "/pid", None)  # the script's EXIT trap; a SIGKILL leaves the lock
                self.folders.pop(lock_dir, None)

    def grants(self, name: str) -> list[str]:
        """The files of sudo's and doas's rules that name the group `name`, as the grants guard reads them as root."""
        out = []
        for path in sorted(self.files):
            text = self.files[path]
            ours = (path in ("/etc/sudoers", "/etc/doas.conf") or path.startswith("/etc/sudoers.d/")
                    or (path.startswith("/etc/doas.d/") and path.endswith(".conf")))
            if text is None or not ours:
                continue
            rules = [r for r in text.splitlines() if not r.lstrip(" \t").startswith("#")]
            if any(f"%{name}" in r or f":{name}" in r for r in rules):
                out.append(path)
        return out

    def _journal(self, text: str) -> None:
        if self.files.get(journal.PATH) is not None:
            self.files[journal.PATH] += text + "\n"

    def _value(self, helper: str, arg: str) -> str:
        """What the script's lm_<helper> gives for `arg` on the tree now."""
        if helper == "gid":
            g = self.groups().get(arg)
            return "" if g is None else str(g.gid)
        if helper in ("uid", "ugid"):
            u = self.users().get(arg)
            return "" if u is None else str(u.uid if helper == "uid" else u.gid)
        if helper == "members":
            g = self.groups().get(arg)
            return "" if g is None else ",".join(sorted(g.members))
        if helper == "sha":
            text = self.files.get(arg)
            return "" if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()
        raise ValueError(helper)

    # ---- the Actions --------------------------------------------------------------------------------------------

    def _there(self, a: plan.Action) -> bool:
        k, groups, users = a.kind, self.groups(), self.users()
        if k == "folder":
            return self.folders.get(a["path"]) is not None
        if k == "file":
            return self._value("sha", a["path"]) == a["sha"]
        if k == "unfile":
            return self.files.get(a["path"]) is None
        if k == "unfolder":
            return self.folders.get(a["path"]) is None or bool(self._inside(a["path"]))
        if k == "regroup":
            f = self.folders.get(a["path"])
            return f is not None and f.gid == 0
        if k == "unjournal":
            return self.files.get(journal.PATH) is None
        if k == "group":
            return a["name"] in groups
        if k == "user":
            return a["name"] in users
        if k == "sysusers":
            return all((a["name"] in groups) if o == "group" else (a["name"] in users) for o in a["absent"].split())
        if k == "member":
            return a["group"] in groups and a["user"] in groups[a["group"]].members
        if k == "unmember":
            return a["group"] not in groups or a["user"] not in groups[a["group"]].members
        if k == "unuser":
            return a["name"] not in users
        if k == "ungroup":
            return a["name"] not in groups
        if k == "move":
            return a["name"] in users and str(users[a["name"]].gid) == a["gid"]
        return False  # relabel, adopt: always run

    def _do(self, a: plan.Action) -> int:
        """Play one Action on the tree: 0, or the exit code its tool would fail with."""
        programs = GENERIC[a.kind] if a.kind in GENERIC else (PROGRAMS.get((a.kind, a.get("tool"))),)
        if None in programs:
            return 127
        for p in programs:
            self.programs.append(p)
            if p not in self.tools:
                return 127
        k = a.kind
        if k == "folder":
            self.folders[a["path"]] = plan.Folder(0, 0, int(a["mode"], 8))
        elif k == "file":
            self.files[a["path"]] = a["text"]
        elif k == "unfile":
            self.files.pop(a["path"], None)
        elif k == "unfolder":
            if self._inside(a["path"]):
                return 1
            self.folders[a["path"]] = None
        elif k == "regroup":
            f = self.folders.get(a["path"])
            if f is None:
                return 1
            self.folders[a["path"]] = plan.Folder(f.uid, 0, f.mode, f.link_uid)
        elif k == "unjournal":
            self.files.pop(journal.PATH, None)
            self.folders[journal.FOLDER] = None
        elif k in ("relabel", "adopt"):
            pass
        else:
            return self._account(a)
        return 0

    def _inside(self, folder: str) -> list[str]:
        return [p for p in [*self.files, *self.folders] if p.startswith(folder.rstrip("/") + "/")
                and (self.files.get(p) is not None or self.folders.get(p) is not None)]

    def _account(self, a: plan.Action) -> int:
        k, tool = a.kind, a.get("tool")
        groups, users = self.groups(), self.users()
        if k == "group":
            if a["name"] in groups:
                return 9  # groupadd: the group exists
            self._add_group(a["name"], self._free_id(groups.values(), "gid", tool))
        elif k == "user":
            if a["name"] in users:
                return 9
            if a["group"] not in groups:
                return 6
            self._add_user(a["name"], self._free_id(users.values(), "uid", tool), groups[a["group"]].gid,
                           a.get("comment"), a.get("home"), a.get("shell"))
        elif k == "sysusers":
            text = self.files.get(a["path"])
            if text is None:
                return 1
            for row in text.splitlines():
                p = row.split()
                if not p or p[0].startswith("#"):
                    continue
                groups, users = self.groups(), self.users()
                if p[0] == "g" and p[1] not in groups:  # skips a name that is there; never removes
                    self._add_group(p[1], self._free_id(groups.values(), "gid", "sysusers"))
                elif p[0] == "u" and p[1] not in users:
                    group = p[2].split(":", 1)[1] if ":" in p[2] else p[1]
                    if group not in groups:
                        return 1  # "created explicitly, or it must already exist" (sysusers.d(5))
                    gid = groups[group].gid
                    uid = gid if all(u.uid != gid for u in users.values()) else self._free_id(users.values(), "uid",
                                                                                            "sysusers")
                    self._add_user(p[1], uid, gid, p[3] if len(p) > 3 else "", p[4] if len(p) > 4 else "/",
                                   p[5] if len(p) > 5 else "")
        elif k == "member":
            if a["user"] not in users or a["group"] not in groups:
                return 3
            if a["user"] not in groups[a["group"]].members:
                self._members(a["group"], (*groups[a["group"]].members, a["user"]))
        elif k == "unmember":
            if a["group"] not in groups or a["user"] not in groups[a["group"]].members:
                return 3  # gpasswd -d: the user is no member
            self._members(a["group"], tuple(m for m in groups[a["group"]].members if m != a["user"]))
        elif k == "move":
            u = users.get(a["name"])
            if u is None:
                return 6
            self._set_user(u.name, gid=int(a["gid"]))
        elif k == "unuser":
            u = users.get(a["name"])
            if u is None:
                return 6
            if u.name == facts.NAME and self.data.get("procs"):
                return 8  # userdel: the user is used by a process
            self._remove_user(u, tool)
        elif k == "ungroup":
            g = groups.get(a["name"])
            if g is None:
                return 6
            if any(u.gid == g.gid for u in users.values()):
                return 8  # groupdel: the primary group of a user
            self._remove_group(g.name)
        else:
            return 127
        return 0

    def _limits(self) -> tuple[int, int]:
        defs = facts._logindefs(self.files.get("/etc/login.defs"))
        return facts._int(defs.get("SYS_GID_MIN"), 100), facts._int(defs.get("SYS_GID_MAX"), 999)

    def _free_id(self, rows, kind: str, tool: str) -> int:
        taken = {getattr(r, kind) for r in rows}
        low, high = self._limits() if tool == "shadow" else (100, 999)
        order = range(low, high + 1) if tool == "busybox" else range(high, low - 1, -1)
        return next(i for i in order if i not in taken)

    def _lines(self, path: str) -> list[str]:
        return [x for x in (self.files.get(path) or "").splitlines()]

    def _write(self, path: str, rows: list[str]) -> None:
        self.files[path] = "".join(r + "\n" for r in rows)

    def _add_group(self, name: str, gid: int) -> None:
        self._write("/etc/group", [*self._lines("/etc/group"), f"{name}:x:{gid}:"])

    def _add_user(self, name, uid, gid, comment, home, shell) -> None:
        self._write("/etc/passwd", [*self._lines("/etc/passwd"), f"{name}:x:{uid}:{gid}:{comment}:{home}:{shell}"])

    def _members(self, group: str, members: tuple) -> None:
        rows = []
        for r in self._lines("/etc/group"):
            p = r.split(":")
            rows.append(":".join([*p[:3], ",".join(members)]) if p[0] == group and len(p) >= 4 else r)
        self._write("/etc/group", rows)

    def _set_user(self, name: str, gid: int) -> None:
        rows = []
        for r in self._lines("/etc/passwd"):
            p = r.split(":")
            rows.append(":".join([*p[:3], str(gid), *p[4:]]) if p[0] == name else r)
        self._write("/etc/passwd", rows)

    def _remove_group(self, name: str) -> None:
        self._write("/etc/group", [r for r in self._lines("/etc/group") if r.split(":")[0] != name])

    def _remove_user(self, u: facts.User, tool: str) -> None:
        self._write("/etc/passwd", [r for r in self._lines("/etc/passwd") if r.split(":")[0] != u.name])
        for g in self.groups().values():
            if u.name in g.members:
                self._members(g.name, tuple(m for m in g.members if m != u.name))
        own = self.groups().get(u.name)
        if own is None:
            return
        others = [x for x in self.users().values() if x.gid == own.gid]
        if tool == "busybox":
            if not others:
                self._remove_group(own.name)  # deluser: whatever its members
            return
        usergroups = facts._logindefs(self.files.get("/etc/login.defs")).get("USERGROUPS_ENAB", "yes").lower()
        if usergroups == "yes" and own.gid == u.gid and not own.members and not others:
            self._remove_group(own.name)  # userdel's remove_usergroup


class _Killed(Exception):
    """SIGKILL, thrown into a played script."""


class Pipe:
    """The read end of a stand-in's pipe: bytes, a read blocks until there are some or the writer is gone."""

    def __init__(self):
        self._buf = bytearray()
        self._eof = False
        self._cv = threading.Condition()

    def _put(self, data: bytes) -> None:
        with self._cv:
            self._buf += data
            self._cv.notify_all()

    def _end(self) -> None:
        with self._cv:
            self._eof = True
            self._cv.notify_all()

    def _wait(self) -> None:
        if not self._cv.wait_for(lambda: self._buf or self._eof, PROMPT_WAIT_S):
            raise RuntimeError("a read of the stand-in's pipe would wait forever: nothing more is written to it")

    def read1(self, n: int = -1) -> bytes:
        with self._cv:
            self._wait()
            n = len(self._buf) if n is None or n < 0 else n
            data = bytes(self._buf[:n])
            del self._buf[:n]
            return data

    def read(self, n: int = -1) -> bytes:
        if n is not None and n >= 0:
            return self.read1(n)
        with self._cv:
            if not self._cv.wait_for(lambda: self._eof, PROMPT_WAIT_S):
                raise RuntimeError("a read to the end of the stand-in's pipe would wait forever")
            data = bytes(self._buf)
            self._buf.clear()
            return data

    def readline(self) -> bytes:
        with self._cv:
            while b"\n" not in self._buf and not self._eof:
                self._wait()
                if b"\n" not in self._buf and not self._eof:
                    continue
            i = self._buf.find(b"\n")
            n = len(self._buf) if i < 0 else i + 1
            data = bytes(self._buf[:n])
            del self._buf[:n]
            return data

    def close(self) -> None:
        pass


class _Stdin:
    """The write end of the stand-in sudo's standard input: what is written is the conversation's."""

    def __init__(self, process: "Process"):
        self._process = process
        self.closed = False

    def write(self, data: bytes) -> int:
        if self.closed:
            raise ValueError("write to a closed pipe")
        if self._process.returncode is not None:
            raise BrokenPipeError(32, "the stand-in's sudo has ended")
        self._process._stdin(bytes(data))
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._process._stdin_closed()


class Process:
    """sudo's conversation on a stand-in machine, as a Popen would be: pid, args, stdin, stdout, stderr, poll, wait,
    kill, terminate, send_signal, returncode; `resume()` lets a held run go on."""

    def __init__(self, machine: Machine, argv: list, call: dict):
        self.machine, self.args, self._call = machine, argv, call
        self.pid = machine._pid()
        machine._live.add(self.pid)
        self.stdin, self.stdout, self.stderr = _Stdin(self), Pipe(), Pipe()
        self.returncode: int | None = None
        self.tries = 0
        self.state = "prompt"
        self._line = b""
        self._held = None
        self._killed_at = ""
        sudo = machine.sudo
        self.kind = sudo.get("kind", "sudo")
        if machine.euid == 0 and len(argv) == 5 and argv[:2] == ["/bin/sh", "-c"] and argv[3] == "liminal":
            self.prompt, self.script, self.nonce = "", argv[2], argv[4]  # a root shell's script: nothing is asked
            self._begin()
            return
        try:
            dash = argv.index("--")
            prompt = argv[argv.index("-p") + 1]
            shell = argv[dash + 1:]
            ok = (shell[:2] == ["/bin/sh", "-c"] and len(shell) == 5 and shell[3] == "liminal"
                  and "-S" in argv[:dash] and argv[argv.index("-u") + 1] == "root")
        except (ValueError, IndexError):
            ok = False
        if not ok:
            self._err(f"standin: {argv[:1]} is no sudo conversation recorded on {machine.name}\n")
            self._end(1)
            return
        self.prompt = prompt.replace("%p", "root" if sudo.get("whose") == "root" else str(
            machine.data.get("id", "1000 user").split()[-1]))
        self.script, self.nonce = shell[2], shell[4]
        if machine.euid == 0 or not sudo.get("asks", True):
            self._begin()
        else:
            self._err(self.prompt)

    # ---- the pipes -------------------------------------------------------------------------------------------

    def _err(self, text: str) -> None:
        self.stderr._put(text.encode("utf-8"))

    def _out(self, text: str) -> None:
        self.stdout._put(text.encode("utf-8"))

    def _end(self, code: int) -> None:
        self.returncode = code
        self.state = "ended"
        self.machine._live.discard(self.pid)
        self.stdout._end()
        self.stderr._end()

    def _stdin(self, data: bytes) -> None:
        self._call["stdin"] += data
        if self.state != "prompt":
            return  # the script reads /dev/null: what comes after the password is no one's
        self._line += data
        while b"\n" in self._line and self.state == "prompt":
            word, _, self._line = self._line.partition(b"\n")
            self._answer(word.decode("utf-8", "replace"))

    def _answer(self, word: str) -> None:
        self.tries += 1
        sudo = self.machine.sudo
        if word == self.machine.password:
            if sudo.get("second_factor") and self.tries == 1:
                self._err(self.prompt)  # PAM's next module asks again: no retry words
                return
            self._begin()
            return
        if self.tries >= 3:
            self._err(("sudo: 3 incorrect password attempts\n" if self.kind == "sudo" else
                       "sudo: maximum 3 incorrect authentication attempts\n"))
            self._end(1)
            return
        self._err((CLASSIC_RETRY if self.kind == "sudo" else RS_RETRY) + "\n" + self.prompt)

    def _stdin_closed(self) -> None:
        if self.state == "prompt":
            self.machine.eof_at_prompt = True  # sudo read end of input at its prompt: a try PAM may count
            self._err("sudo: no password was provided\n" if self.kind == "sudo" else
                      "sudo: Authentication required but not attempted\n")
            self._end(1)

    def _begin(self) -> None:
        self.state = "script"
        self.machine.sudo_runs += 1
        run = self.machine._script(self.script, self.nonce, self.pid, self._out, self._err)
        self._go(run)

    def _go(self, run, word: str | None = None) -> None:
        code = self.machine._drive(run, self, word)
        if code is not None:
            self._end(code)

    # ---- as Popen --------------------------------------------------------------------------------------------

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.args, timeout or 0)
        return self.returncode

    def resume(self) -> None:
        """Let a run held at `hold_at` go on to its end."""
        run, self._held = self._held, None
        if run is not None:
            self.machine.hold_at = None
            self._go(run, "go")

    def kill(self) -> None:
        if self.returncode is not None:
            return
        self._killed_at = self.state
        if self._held is not None:
            try:
                self._held.throw(_Killed)
            except StopIteration:
                pass
            self._held = None
        self._end(-9)

    def terminate(self) -> None:
        if self.returncode is not None:
            return
        if self._held is not None:
            run, self._held = self._held, None
            self.machine.hold_at = None
            self._go(run, "term")  # the script's trap: it finishes its step, then exits 7
            return
        self._end(-15)  # sudo at its prompt, told TERM: whether PAM counts the try is to check (risk 6)

    def send_signal(self, sig: int) -> None:
        if sig == 9:
            self.kill()
        else:
            self.terminate()

    @property
    def killed_at(self) -> str:
        """Where a SIGKILL found it: "prompt" (sudo waiting: nothing ran), "script", or "" (never killed)."""
        return self._killed_at


def wait_for(process: Process, seconds: float = 1.0) -> int | None:
    """A test's wait: the process's code once it ended, polling a stand-in's (which ends in the caller's thread)."""
    end = time.monotonic() + seconds
    while process.poll() is None and time.monotonic() < end:
        time.sleep(0.001)
    return process.poll()
