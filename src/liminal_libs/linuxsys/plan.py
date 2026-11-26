"""A change to this Linux as data: its steps, each an Action its tool renders into sh and the stand-in plays, and the
one script that runs them as root (the linuxperm plan's 3.4 and 3.6).

A Plan is built in Python from fresh facts, as the platform's user, by the page's hooks and by the root command alike,
and its script is the same bytes for both (PLAN 3.6): its nonce reaches it as `$1`, so the text does not change from
one run to the next, and its sha256 is the digest a confirmation carries (S16). The facts it rests on are written into
it as guards and checked again as root, so what root alone sees can narrow what runs, never widen it.

Every script runs, in order: ROOT_HEAD; `set -u`; HUP and PIPE ignored (its tools inherit both: a closed pipe is an
error, a hang-up nothing); a TERM or an INT stops it after the step it is in; `@@ liminal-begin <nonce>` on standard
error (the conversation's begin line); the helpers; the lock (S14); the chain check (every folder to the journal's
and to /etc/sysusers.d root's alone); the journal's folder and file where they are missing; the guards; the run line.
Then each step: its check (what it makes is there already: `@@ step <n> there 0`, and nothing is written), else its
`begin` line, synced, its tool with fd 9 closed, its `done` lines, synced, and `@@ step <n> done 0` on standard output.
It stops at the first failure (`@@ step <n> failed <code>`), and after a step when it was told to stop or its parent
is gone (sudo ended: /proc/$$/stat no longer names the parent it began under). Exit codes: 0 done; 1 a step failed;
2 refused by a guard or the lock; 5 the chain; 7 stopped after a step. No password is ever in one.

The stand-in plays Actions, never sh, since no test may start a process; each tool's sh is snapshot-tested instead,
and undo's choices are made in Python from the folded journal, so the sh holds only fixed guards and straight-line
steps.
"""
from __future__ import annotations

import hashlib
import posixpath
import re
from dataclasses import dataclass

from . import journal
from .shared import ROOT_HEAD, Refused, clean_words, sh_word

__all__ = ["Action", "Step", "Guard", "Plan", "Outcome", "Folder", "Refused", "WrongPassword", "chain", "prefixes",
           "TOOLS", "SCRIPT_MAX", "CHAINS", "LOCK", "known"]

SCRIPT_MAX = 96 * 1024  # bytes: Linux takes 128 KiB in one argument (MAX_ARG_STRLEN), and sudo logs the whole of it
LOCK = "/run/liminal-linux.lock"
# The folders a release-one change writes in, as root: the journal's, and systemd-sysusers' own
CHAINS = (journal.FOLDER, "/etc/sysusers.d")
TOO_LARGE = "this change is too large to hand to sudo in one piece"
CHANGED = "this system changed since you confirmed: review it again"
HELD = "another Linux administration change is running"


KNOWN_MAX = 32
_KNOWN: dict = {}  # the plans whose script was made last, by its sha256: the stand-in plays the plan of a script


def known(script: str) -> "Plan | None":
    """The Plan whose script this is, among the last KNOWN_MAX made in this process; None for any other text. The
    stand-in machine plays a script's Actions by it, since no test may run sh."""
    return _KNOWN.get(hashlib.sha256(script.encode("utf-8")).hexdigest())


class WrongPassword(Refused):
    """sudo said the password was wrong: one failed sign-in, and the form is offered again."""


# Every program a probe or a script of linuxsys runs, with who makes it and what it is run for. admin-linux's API
# cards are derived from it (the second critique's point 20), and its tests hold that every program the stand-in
# records is here. The coreutils are GNU's, uutils' (Ubuntu 26.04) or BusyBox's; a script uses only the options all
# three have (M14)
TOOLS = (
    ("sh", "the system's POSIX shell (dash, bash, BusyBox ash)", "runs the probe and every script"),
    ("install", "coreutils (GNU, uutils) or BusyBox", "makes a folder or a file with its mode and owner"),
    ("mkdir", "coreutils or BusyBox", "the lock where flock is missing"),
    ("mv", "coreutils or BusyBox", "puts a file written beside its place into it"),
    ("rm", "coreutils or BusyBox", "removes a file Liminal wrote, the lock"),
    ("rmdir", "coreutils or BusyBox", "removes a folder Liminal made, once empty"),
    ("stat", "coreutils or BusyBox", "reads a folder's owner and mode (`stat -c`)"),
    ("sync", "coreutils or BusyBox", "puts each journal line on the disk (`sync FILE`)"),
    ("sha256sum", "coreutils or BusyBox", "a file's digest"),
    ("chmod", "coreutils or BusyBox", "a file's mode"),
    ("chgrp", "coreutils or BusyBox", "gives a folder root's group back before the group goes"),
    ("cat", "coreutils or BusyBox", "the probe's reads of files"),
    ("ls", "coreutils or BusyBox", "the probe's reads of folders"),
    ("id", "coreutils or BusyBox", "who the platform runs as"),
    ("uname", "coreutils or BusyBox", "the machine, where the kernel has no file for it"),
    ("date", "coreutils or BusyBox", "the time on a journal's run line"),
    ("cut", "coreutils or BusyBox", "a field of a line"),
    ("sort", "coreutils or BusyBox", "a group's members, in one order"),
    ("tr", "coreutils or BusyBox", "a group's members, one to a line"),
    ("sed", "GNU sed or BusyBox", "the parent's process id, a list's last comma"),
    ("awk", "gawk, mawk or BusyBox", "a field of /etc/group and /etc/passwd"),
    ("flock", "util-linux or BusyBox", "the lock (S14)"),
    ("getent", "glibc or musl-utils", "the probe's read of an account through NSS"),
    ("groupadd", "shadow", "makes the group"),
    ("useradd", "shadow", "makes the user"),
    ("usermod", "shadow", "moves the user onto another primary group before userdel"),
    ("gpasswd", "shadow", "adds and removes a member"),
    ("userdel", "shadow", "removes the user"),
    ("groupdel", "shadow", "removes the group"),
    ("addgroup", "BusyBox", "makes the group, adds a member"),
    ("adduser", "BusyBox", "makes the user"),
    ("deluser", "BusyBox", "removes the user, removes a member"),
    ("delgroup", "BusyBox", "removes the group"),
    ("systemd-sysusers", "systemd (255 or later)", "makes the group and the user from /etc/sysusers.d/liminal.conf"),
    ("sudo", "sudo (classic) or sudo-rs", "runs a change as root after the password; `sudo -V` and `sudo -l` read"),
    ("doas", "OpenDoas", "found and named: a change through it is the terminal's (the user's answer 7)"),
    ("su", "util-linux or shadow", "found and named: a change through it is the terminal's"),
    ("rpm", "RPM", "`rpm -q sudo-policy-wheel-auth-self`: whose password openSUSE's sudo asks (M21)"),
    ("restorecon", "policycoreutils", "the SELinux label of what Liminal wrote, where SELinux enforces (M9)"),
    ("env", "coreutils or BusyBox", "sudo's words in English (LC_ALL=C)"),
)

# The helpers every script defines after its begin line. A slot of a journal line is one of lm_gid, lm_uid, lm_ugid
# and lm_sha (journal._SLOT)
HELPERS = r"""J=/var/lib/liminal-linux/MADE
lm_journal=0
lm_exit() {
  if [ "$lm_journal" = 1 ] && [ -f "$J" ]; then printf 'end %s %s\n' "$nonce" "$1" >>"$J"; sync "$J"; fi
  exit "$1"
}
lm_field() { awk -F: -v n="$2" -v f="$3" '$1 == n { print $f; exit }' "$1"; }
lm_gid() { lm_field /etc/group "$1" 3; }
lm_uid() { lm_field /etc/passwd "$1" 3; }
lm_ugid() { lm_field /etc/passwd "$1" 4; }
lm_members() { lm_field /etc/group "$1" 4 | tr ',' '\n' | sed '/^$/d' | sort | tr '\n' ',' | sed 's/,$//'; }
lm_sha() { if [ -f "$1" ]; then sha256sum "$1" | cut -d ' ' -f 1; fi; }
lm_ppid() { sed 's/^.*) //' "/proc/$$/stat" | cut -d ' ' -f 2; }
lm_parent=$(lm_ppid)
lm_next() {
  if [ "$stop" != 0 ] || [ "$(lm_ppid)" != "$lm_parent" ]; then printf '@@ stopped\n'; lm_exit 7; fi
}
lm_safe() {
  if [ -L "$1" ]; then
    [ "$(stat -c %u "$1")" = 0 ] || return 1
  elif [ ! -e "$1" ]; then
    return 0
  fi
  lm_s=$(stat -L -c '%u %g %a' "$1") || return 1
  set -- $lm_s
  [ "$1" = 0 ] && [ $((0$3 & 2)) = 0 ] && { [ "$2" = 0 ] || [ $((0$3 & 16)) = 0 ]; }
}"""


@dataclass(frozen=True)
class Action:
    """What a step does, as data: its kind (journal's kinds: group, user, sysusers, member, unmember, folder, file,
    unfile, unfolder, ungroup, unuser, move, regroup, adopt, relabel, unjournal) and its arguments, `tool` among them
    where a tool's own rules decide its side effects (shadow, busybox, sysusers). Its tool renders it into sh; the
    stand-in plays it on a file tree."""

    kind: str
    args: tuple[tuple[str, str], ...] = ()

    @classmethod
    def of(cls, kind: str, **args) -> "Action":
        return cls(kind, tuple((k, str(v)) for k, v in sorted(args.items())))

    def __getitem__(self, key: str) -> str:
        return dict(self.args)[key]

    def get(self, key: str, default: str = "") -> str:
        return dict(self.args).get(key, default)

    def as_dict(self) -> dict:
        return dict(self.args)


@dataclass(frozen=True)
class Step:
    """One step: its words for the page, its Action, `check` (sh that succeeds when what the step makes is there
    already) and `do` (the tool's sh, whose status is the step's)."""

    words: str
    action: Action
    check: str
    do: str

    def lines(self, n: int) -> tuple[journal.Line | None, tuple[journal.Line, ...]]:
        """Its journal lines, as step `n`."""
        return journal.lines(n, self.action.kind, self.action.as_dict())

    def sh(self, n: int) -> str:
        begin, done = self.lines(n)
        out = [f"if {self.check}; then", f"  printf '@@ step {n} there 0\\n'", "else"]
        if begin is not None:
            out.append(f"  {begin.sh()} || {{ printf '@@ step {n} failed journal\\n'; lm_exit 1; }}")
        out += ["  {", self.do, "  } 9>&-", "  lm_c=$?",  # the tool's sh as it is: a file's text is in it
                f"  if [ \"$lm_c\" != 0 ]; then printf '@@ step {n} failed %s\\n' \"$lm_c\"; lm_exit 1; fi"]
        out += [f"  {d.sh()} || {{ printf '@@ step {n} failed journal\\n'; lm_exit 1; }}" for d in done]
        out += [f"  printf '@@ step {n} done 0\\n'", "fi", "lm_next"]
        return "\n".join(out)


@dataclass(frozen=True)
class Guard:
    """A fact a plan rests on, checked again as root: `value`, one of the helpers with its argument (("gid",
    "liminal"), ("members", "liminal"), ("sha", path)), must give `expected` ("" for absent). `words` say the fact."""

    words: str
    value: tuple[str, str]
    expected: str

    def sh(self, n: int) -> str:
        helper, arg = self.value
        if helper == "grants":
            return _grants_sh(arg)
        if helper not in ("gid", "uid", "ugid", "members", "sha"):
            raise ValueError(f"a guard reads gid, uid, ugid, members, sha or grants, not {helper!r}")
        expected = "''" if self.expected == "" else sh_word(self.expected, "a guard's value")
        return (f"[ \"$(lm_{helper} {sh_word(arg, 'a guard')})\" = {expected} ] || "
                f"{{ printf '@@ refused guard {n}\\n'; lm_exit 2; }}")


def group_guard(name: str, gid) -> Guard:
    return Guard(f"the group {name} is {'absent' if gid is None else f'there with gid {gid}'}", ("gid", name),
                 "" if gid is None else str(gid))


def user_guard(name: str, uid, gid=None) -> tuple[Guard, ...]:
    if uid is None:
        return (Guard(f"the user {name} is absent", ("uid", name), ""),)
    return (Guard(f"the user {name} is there with uid {uid}", ("uid", name), str(uid)),
            Guard(f"the user {name}'s primary group is {gid}", ("ugid", name), str(gid)))


# Where sudo and doas take their rules from: sudoers, the files and folders its include lines name (@include,
# #include, @includedir, #includedir; one level, as Liminal's own files are), sudoers.d, doas.conf and doas.d
GRANT_FILES = ("/etc/sudoers", "/etc/sudoers.d", "/etc/doas.conf", "/etc/doas.d")


def grants_guard(name: str) -> Guard:
    """No rule of sudo's or doas's names the group `name` (`%liminal`, `:liminal`), read as root: undo refuses while
    one does, naming each file (B4's last paragraph)."""
    return Guard(f"no rule of sudo's or doas's names the group {name}", ("grants", clean_words(name, "a group")), "")


def _grants_sh(name: str) -> str:
    q = sh_word(name, "a group")
    return ("lm_g=''\n"
            "for lm_f in /etc/sudoers /etc/doas.conf $(awk '$1 == \"@include\" || $1 == \"#include\" { print $2 } "
            "$1 == \"@includedir\" || $1 == \"#includedir\" { print $2 \"/*\" }' /etc/sudoers 2>/dev/null) "
            "/etc/sudoers.d/* /etc/doas.d/*.conf; do\n"
            "  [ -f \"$lm_f\" ] || continue\n"
            f"  if awk -v g={q} '/^[ \\t]*#/ {{ next }} {{ if (index($0, \"%\" g) || index($0, \":\" g)) f = 1 }} "
            "END { exit !f }' \"$lm_f\"; then\n"
            "    case \" $lm_g \" in *\" $lm_f \"*) ;; *) lm_g=\"$lm_g $lm_f\";; esac\n"
            "  fi\n"
            "done\n"
            "[ -z \"$lm_g\" ] || { printf '@@ refused grants%s\\n' \"$lm_g\"; lm_exit 2; }")


def members_guard(name: str, members) -> Guard:
    listed = ",".join(sorted(members))
    return Guard(f"the group {name} holds {listed or 'no member'}", ("members", name), listed)


def file_guard(path: str, sha: str | None, what: str = "") -> Guard:
    return Guard(what or (f"{path} is absent" if not sha else f"{path} has the digest {sha}"), ("sha", path),
                 sha or "")


@dataclass(frozen=True)
class Plan:
    """A change: what it is (apply, member, undo), its steps, the refusal that stands in for them (its words: no script
    is then made), notes for the page, the guards, the lock's form ("flock", else "mkdir": the probe records which is
    there), and the folders whose chain is checked as root."""

    what: str
    steps: tuple[Step, ...] = ()
    refused: str = ""
    notes: tuple[str, ...] = ()
    guards: tuple[Guard, ...] = ()
    lock: str = "flock"
    chains: tuple[str, ...] = CHAINS

    @property
    def nothing(self) -> bool:
        """Whether there is nothing to do: no step and no refusal (apply run twice: the second plan)."""
        return not self.steps and not self.refused

    def words(self) -> list[str]:
        """What the plan does, for a confirmation: its refusal alone, or each step numbered, then the notes."""
        if self.refused:
            return [self.refused]
        out = [f"{n}. {s.words}" for n, s in enumerate(self.steps, 1)] or ["nothing to do: it is all here"]
        return out + list(self.notes)

    def script(self) -> str:
        """The one sh script that runs the plan as root, `sh -c <script> liminal <nonce>`. A refused plan has none
        (Refused, in its words); one above SCRIPT_MAX bytes is refused too (S9)."""
        if self.refused:
            raise Refused(self.refused)
        if self.what not in journal.WHATS:
            raise ValueError(f"a plan is one of {', '.join(journal.WHATS)}, not {self.what!r}")
        out = [*ROOT_HEAD, "set -u", "trap '' PIPE HUP", "stop=0; trap 'stop=1' TERM INT",
               "printf '@@ liminal-begin %s\\n' \"$1\" >&2", "nonce=$1", HELPERS, _lock(self.lock), _chain(self.chains),
               f"[ -d {journal.FOLDER} ] || install -d -m {journal.FOLDER_MODE} -o root -g root {journal.FOLDER} "
               f"|| exit 1",
               f"[ -f \"$J\" ] || install -m {journal.MODE} -o root -g root /dev/null \"$J\" || exit 1",
               *(g.sh(n) for n, g in enumerate(self.guards, 1)),
               f"{journal.run_line(self.what)} || exit 1", "lm_journal=1",
               *(s.sh(n) for n, s in enumerate(self.steps, 1)), "lm_exit 0"]
        text = "\n".join(out) + "\n"
        if len(text.encode("utf-8")) > SCRIPT_MAX:
            raise Refused(TOO_LARGE)
        _KNOWN[hashlib.sha256(text.encode("utf-8")).hexdigest()] = self
        while len(_KNOWN) > KNOWN_MAX:
            del _KNOWN[next(iter(_KNOWN))]
        return text

    @property
    def digest(self) -> str:
        """The plan's sha256: of its script, or of its refusal's words. A form carries it; the change refuses when the
        plan it builds again has another (S16)."""
        text = ("refused: " + self.refused) if self.refused else self.script()
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def said(self, output: str, code: int | None) -> tuple[list["Outcome"], str]:
        """Each step's Outcome and the run's words, from the script's standard output and its exit code."""
        outcomes = {o.index: o for o in Outcome.parse(output)}
        total = len(self.steps)
        out = [outcomes.get(n) or Outcome(n, "stopped" if code == 7 else "not run", "")
               for n in range(1, total + 1)]
        reported = [o for o in out if o.state in ("done", "there")]
        refused = _refusal(output)
        if code == 0:
            words = "done" if self.steps else "nothing to do"
        elif refused:
            words = refused
        elif code == 1:
            failed = next((o for o in out if o.state == "failed"), None)
            n = failed.index if failed else len(reported) + 1
            what = self.steps[n - 1].words if 0 < n <= total else "a step"
            detail = failed.detail if failed else "?"
            words = (f"step {n} of {total} failed ({what}): exit {detail}; what was done before it is journaled, "
                     "and running it again goes on from there")
        elif code == 7:
            words = f"stopped after step {len(reported)} of {total}: running it again finishes it"
        else:
            words = f"the script ended with exit {code} before its steps"
        return out, words


def _lock(form: str) -> str:
    if form == "flock":
        return (f"exec 9>>{LOCK}\n"
                f"flock -n 9 || {{ printf '@@ refused lock held\\n'; exit 2; }}")
    if form != "mkdir":
        raise ValueError(f"a lock is flock or mkdir, not {form!r}")
    return (f"if mkdir {LOCK} 2>/dev/null; then\n"
            f"  printf '%s\\n' \"$$\" >{LOCK}/pid\n"
            f"  trap 'rm -rf {LOCK}' EXIT\n"
            "else\n"
            f"  lm_held=$(cat {LOCK}/pid 2>/dev/null || :)\n"
            "  if [ -z \"$lm_held\" ] || [ -d \"/proc/$lm_held\" ]; then\n"
            "    printf '@@ refused lock held %s\\n' \"$lm_held\"\n"
            "  else printf '@@ refused lock stale %s\\n' \"$lm_held\"; fi\n"
            "  exit 2\n"
            "fi")


def prefixes(path: str) -> list[str]:
    """Every folder from / to `path`, `path` included: "/var/lib/x" gives /, /var, /var/lib, /var/lib/x."""
    path = posixpath.normpath(path)
    out, here = ["/"], ""
    for part in [p for p in path.split("/") if p]:
        here += "/" + part
        out.append(here)
    return out


def _chain(paths) -> str:
    folders: list[str] = []
    for path in paths:
        folders += [p for p in prefixes(path) if p not in folders]
    words = " ".join(sh_word(p, "a folder of the chain") for p in folders)
    return (f"for lm_p in {words}; do\n"
            "  lm_safe \"$lm_p\" || { printf '@@ refused chain %s\\n' \"$lm_p\"; exit 5; }\n"
            "done")


_REFUSED = re.compile(r"^@@ refused (lock held|lock stale|guard|chain|grants) ?(.*)$", re.M)
TAKE_BACK = "/usr/local/libexec/liminal/{grant}/take-back"


def grants_words(files) -> str:
    """Undo's refusal while a rule names the group: each file, and for Liminal's own grants (sudoers.d/liminal-<grant>)
    the helper that takes it back."""
    named = []
    for path in files:
        base = posixpath.basename(path)
        grant = base[len("liminal-"):] if base.startswith("liminal-") else ""
        named.append(f"{path} (Liminal's grant {grant}: {TAKE_BACK.format(grant=grant)} takes it back, or the "
                     "plugin's own switch)" if grant else path)
    return ("take the grants back first: " + "; ".join(named) + " name the group liminal, and a number given out "
            "again would inherit them; nothing was changed")


def _refusal(output: str) -> str:
    m = _REFUSED.search(output or "")
    if not m:
        return ""
    kind, rest = m.group(1), m.group(2).strip()
    if kind == "lock held":
        return HELD + (f" (process {rest})" if rest else "")
    if kind == "lock stale":
        return (f"a change was stopped without letting go of its lock (process {rest} no longer runs): nothing was "
                f"changed; remove the lock as root with `rm -r {LOCK}` (a restart empties /run), then try again")
    if kind == "guard":
        return CHANGED
    if kind == "grants":
        return grants_words(rest.split())
    return (f"{rest} is not root's alone, so another account could replace what root writes under it: nothing was "
            "changed; make it root's, written by no group but root's and by no one else")


@dataclass(frozen=True)
class Outcome:
    """What a step came to: done, there (it was there already), failed (`detail`: its exit code, or "journal" when a
    line could not be written), stopped, or not run."""

    index: int
    state: str
    detail: str = ""

    @staticmethod
    def parse(output: str) -> list["Outcome"]:
        """The steps' outcomes from a script's standard output, in its order; a marker torn or not Liminal's is
        skipped."""
        out = []
        for m in re.finditer(r"^@@ step (\d+) (there|done|failed) (\S+)$", output or "", re.M):
            out.append(Outcome(int(m.group(1)), m.group(2), "" if m.group(3) == "0" else m.group(3)))
        return out


# ---- the chain, read from the probe's facts ----------------------------------------------------------------------


@dataclass(frozen=True)
class Folder:
    """A folder as the probe read it (`stat -L -c '%u %g %a'`, and the link's own owner where it is a link):
    owner, group, mode (an int), the link's owner (None: no link)."""

    uid: int
    gid: int
    mode: int
    link_uid: int | None = None


def chain(path: str, folders) -> str:
    """"" when every folder from / to `path` is root's alone, else why not, in words: each one there must be owned by
    root, written by no group but root's and by no one else; a link must be root's (ostree's /usr/local to
    /var/usrlocal is), its target as the kernel follows it held to the same rule. A folder not there yet passes (root
    makes it, 0755). `folders`: {path: Folder, or None where it is not there}; a folder it does not name was not read,
    and is said so."""
    for p in prefixes(path):
        if p not in folders:
            return f"{p} could not be read, so whether only root writes under it is not known: nothing was changed"
        f = folders[p]
        if f is None:
            return ""
        if f.link_uid not in (None, 0):
            return (f"{p} is a link owned by uid {f.link_uid}, not root: another account could point it elsewhere; "
                    "nothing was changed")
        if f.uid != 0 or f.mode & 0o002 or (f.mode & 0o020 and f.gid != 0):
            return (f"{p} is not root's alone (owner uid {f.uid}, group gid {f.gid}, mode {f.mode:o}), so another "
                    "account could replace what root writes under it: nothing was changed; make it root's, written "
                    "by no group but root's and by no one else")
    return ""


# ---- the steps every tool shares ----------------------------------------------------------------------------------


def folder(path: str, mode: str = "0755") -> Step:
    """Make a folder, root's, with its mode (the umask would make it 0700)."""
    q = sh_word(path, "a folder")
    return Step(f"make the folder {path} ({mode}, root's)", Action.of("folder", path=path, mode=_mode(mode)),
                f"[ -d {q} ]", f"install -d -m {mode} -o root -g root {q}")


def file(path: str, text: str, mode: str = "0644") -> Step:
    """Write a file of root's: beside its place, its mode set and synced, then moved in, so it is whole or absent.
    Each of its lines is clean_words' (or empty), so it is plain words in a single-quoted sh word."""
    for line in text.splitlines():
        if line:
            clean_words(line, f"a line of {path}")
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    q, new = sh_word(path, "a file"), sh_word(path + ".liminal-new", "a file")
    return Step(f"write {path} ({mode}, root's)", Action.of("file", path=path, text=text, mode=_mode(mode), sha=sha),
                f"[ \"$(lm_sha {q})\" = '{sha}' ]",
                f"printf '%s' '{text}' >{new} && chmod {mode} {new} && sync {new} && mv -f {new} {q}")


def unfile(path: str) -> Step:
    q = sh_word(path, "a file")
    return Step(f"remove {path}", Action.of("unfile", path=path), f"[ ! -e {q} ] && [ ! -L {q} ]", f"rm -f {q}")


def unfolder(path: str) -> Step:
    """Remove a folder Liminal made, once empty. One that holds another file now is kept (the step finds it "there"):
    it is no longer Liminal's alone."""
    q = sh_word(path, "a folder")
    return Step(f"remove the folder {path}, if empty", Action.of("unfolder", path=path),
                f"{{ [ ! -d {q} ] || [ -n \"$(ls -A {q})\" ]; }}", f"rmdir {q}")


def regroup(path: str) -> Step:
    """Give a folder root's group back, before the group `liminal` goes: a number given out again inherits nothing."""
    q = sh_word(path, "a folder")
    return Step(f"give {path} root's group back", Action.of("regroup", path=path), f"[ \"$(stat -c %g {q})\" = 0 ]",
                f"chgrp root {q}")


def relabel(paths) -> Step:
    """restorecon -F on what Liminal wrote, where SELinux enforces (M9): no journal line, it makes nothing."""
    words = " ".join(sh_word(p, "a path") for p in paths)
    return Step(f"give {', '.join(paths)} their SELinux labels", Action.of("relabel", paths=" ".join(paths)),
                "false", f"restorecon -F {words}")


def adopt(name: str, uid: int, gid: int) -> Step:
    """Write down that the user `name` here (a Liminal WSL distribution's login user) is adopted as Liminal's: never
    removed by undo (the user's answer 4)."""
    return Step(f"take the user {name} (uid {uid}) as Liminal's own; it is never removed",
                Action.of("adopt", name=clean_words(name, "a user"), uid=int(uid), gid=int(gid)), "false", ":")


def unjournal() -> Step:
    """Remove the journal and its folder: undo's last step, only when everything the journal names is gone."""
    return Step(f"remove the journal {journal.PATH} and its folder", Action.of("unjournal"), "[ ! -e \"$J\" ]",
                f"rm -f \"$J\" && rmdir {journal.FOLDER}")


def _mode(mode: str) -> str:
    if not re.fullmatch(r"0[0-7]{3}", mode):
        raise ValueError(f"a mode is four octal digits from 0, not {mode!r}")
    return mode
