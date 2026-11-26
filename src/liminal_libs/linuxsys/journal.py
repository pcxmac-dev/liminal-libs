"""The journal of what Liminal made on this Linux: /var/lib/liminal-linux/MADE, written as a change goes (the linuxperm
plan's B4, the second critique's blocker 2: a record written last did not survive a failure, and undo then kept what
an apply stopped part way had made, for good).

Every root script writes a line before each step (`begin`, with the facts the step rests on) and one after it (`done`,
with what it made: the gid, the uid, the digest), each one whole printf, then `sync` on the journal. A run's first and
last lines are `run <nonce> apply|member|undo <unix time>` and `end <nonce> <code>`. The folder is root's, 0755, and
the journal 0644 (the user's answer 3, 2026-11-25: readable by all), so the platform reads it as well as root and undo
is decided here, in Python, tested on every recorded machine. Its lines are names, numbers, paths and digests, which
/etc shows to everyone already; it holds no choice of the user's.

`fold` reads it back. An object Liminal made, added or adopted is known by its lines; one with no line was found. A
`begin` without its `done` counts as Liminal's when the object is there now (the plan rested on its absence, and the
lock kept other runs out), and as nothing when it is not. A `done ... removed` ends what is known of it. So a run
stopped after any step, then run again, keeps what the first made as made, never as found.

The lines, by the kind of a step's Action (plan.Action): `begin`'s words, then `done`'s, a `{slot}` filled as root
when the line is written (`{gid NAME}`, `{uid NAME}`, `{ugid NAME}`: a group's id, a user's id and its primary group's,
from /etc/group and /etc/passwd; `{sha PATH}`: a file's sha256):

    begin <n> make group liminal (absent)           done <n> made group liminal <gid>
    begin <n> make user liminal (absent)            done <n> made user liminal <uid> <gid>
    begin <n> sysusers liminal (absent: group user) done <n> made group liminal <gid> | made user liminal <uid> <gid>
    begin <n> add member <user>                     done <n> added member <user>
    begin <n> make folder <path>                    done <n> made folder <path> <mode>
    begin <n> write file <path> <sha256>            done <n> wrote file <path> <sha256>
    begin <n> remove <object>                       done <n> removed <object>
    begin <n> move user liminal <gid>               done <n> moved user liminal <gid>
    begin <n> regroup folder <path> root            done <n> regrouped folder <path> root
    adopted user liminal <uid> <gid>
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .shared import clean_words

FOLDER = "/var/lib/liminal-linux"
PATH = FOLDER + "/MADE"
FOLDER_MODE = "0755"  # the user's answer 3 (a): readable by all, written by root alone
MODE = "0644"
WHATS = ("apply", "member", "undo")
# A slot: filled as root when the line is written. Its value is the shell's (`lm_gid`, plan.HELPERS), never Python's
_SLOT = re.compile(r"\{(gid|uid|ugid|sha) ([^{}\s]+)\}")


@dataclass(frozen=True)
class Line:
    """One line of the journal: its kind (run, begin, done, adopted, end), its step's number (None for run, adopted
    and end), and its words, which may hold slots before it is written."""

    kind: str
    n: int | None
    words: str

    def text(self) -> str:
        return " ".join(str(p) for p in (self.kind, self.n, self.words) if p is not None and p != "")

    def fill(self, value) -> "Line":
        """The line with each slot filled by `value(slot, argument)` (the stand-in's, from its tree)."""
        return Line(self.kind, self.n, _SLOT.sub(lambda m: str(value(m.group(1), m.group(2))), self.words))

    def sh(self) -> str:
        """The line as one whole printf appended to the journal, then `sync` on it: its fixed words single-quoted
        (clean_words keeps every quote out of them), each slot the shell's own value. A line that cannot be written
        fails the step it belongs to."""
        text = self.text()
        parts, last = [], 0
        for m in _SLOT.finditer(text):
            if m.start() > last:
                parts.append(_quoted(text[last:m.start()]))
            parts.append(f'"$(lm_{m.group(1)} {_quoted(m.group(2))})"')
            last = m.end()
        if last < len(text):
            parts.append(_quoted(text[last:]))
        return f"printf '%s\\n' {''.join(parts)} >>\"$J\" && sync \"$J\""


def _quoted(text: str) -> str:
    return "'" + clean_words(text, "a journal line's words") + "'"


# A step's lines, by its Action's kind: (begin, (done, ...)), each a format of the Action's arguments
_LINES = {
    "group": ("make group {name} (absent)", ("made group {name} {{gid {name}}}",)),
    "user": ("make user {name} (absent)", ("made user {name} {{uid {name}}} {{ugid {name}}}",)),
    "member": ("add member {user}", ("added member {user}",)),
    "unmember": ("remove member {user}", ("removed member {user}",)),
    "folder": ("make folder {path}", ("made folder {path} {mode}",)),
    "file": ("write file {path} {sha}", ("wrote file {path} {sha}",)),
    "unfile": ("remove file {path}", ("removed file {path}",)),
    "unfolder": ("remove folder {path}", ("removed folder {path}",)),
    "ungroup": ("remove group {name}", ("removed group {name}",)),
    "unuser": ("remove user {name}", ("removed user {name}",)),
    "move": ("move user {name} {gid}", ("moved user {name} {gid}",)),
    "regroup": ("regroup folder {path} root", ("regrouped folder {path} root",)),
}
NO_LINES = ("relabel", "unjournal")  # restorecon changes no object; the journal's own removal is its last act


def lines(n: int, kind: str, args: dict) -> tuple[Line | None, tuple[Line, ...]]:
    """The `begin` line and the `done` lines of step `n`, whose Action is `kind` with `args`."""
    if kind in NO_LINES:
        return None, ()
    if kind == "adopt":
        return None, (Line("adopted", None, "user {name} {uid} {gid}".format(**args)),)
    if kind == "sysusers":
        absent = str(args["absent"]).split()
        done = []
        if "group" in absent:
            done.append(Line("done", n, "made group {name} {{gid {name}}}".format(**args)))
        if "user" in absent:
            done.append(Line("done", n, "made user {name} {{uid {name}}} {{ugid {name}}}".format(**args)))
        return Line("begin", n, "sysusers {name} (absent: {absent})".format(**args)), tuple(done)
    begin, done = _LINES[kind]
    return Line("begin", n, begin.format(**args)), tuple(Line("done", n, d.format(**args)) for d in done)


def run_line(what: str) -> str:
    """The sh of a run's first line: its nonce (the script's `$nonce`), what it is, and the time."""
    if what not in WHATS:
        raise ValueError(f"a run is one of {', '.join(WHATS)}, not {what!r}")
    return f"printf 'run %s {what} %s\\n' \"$nonce\" \"$(date +%s)\" >>\"$J\" && sync \"$J\""


# ---- reading it back ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Here:
    """What is on this Linux now, as fold needs it: groups {name: (gid, members)}, users {name: (uid, gid)}, and paths
    {path: a file's sha256, or "" for a folder} (what is not there has no key)."""

    groups: dict = field(default_factory=dict)
    users: dict = field(default_factory=dict)
    paths: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Run:
    """One run the journal holds: its nonce, what it was, when (unix time), its steps' words and state ("done", or
    "begun": its begin line without a done), and its end's code (None: it never ended, it was stopped)."""

    nonce: str
    what: str
    time: int
    steps: tuple[tuple[int, str, str], ...] = ()
    code: int | None = None


@dataclass(frozen=True)
class Made:
    """What the journal says Liminal made, added or adopted here and has not taken away: the group's gid, the user's
    (uid, gid), the members added, the folders made {path: mode}, the files written {path: sha256}, the user adopted
    (uid, gid); the journal's sha256 (undo's guard), its runs, and what could not be read of it (`notes`)."""

    group: int | None = None
    user: tuple[int, int] | None = None
    members: tuple[str, ...] = ()
    folders: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)
    adopted: tuple[int, int] | None = None
    digest: str = hashlib.sha256(b"").hexdigest()
    runs: tuple[Run, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def nothing(self) -> bool:
        return (self.group is None and self.user is None and not self.members and not self.folders
                and not self.files and self.adopted is None)

    @property
    def last(self) -> Run | None:
        return self.runs[-1] if self.runs else None

    @property
    def stopped(self) -> bool:
        """Whether the last run was stopped part way: it has no end line, or it ended with a step's failure or a stop
        (1, 7)."""
        last = self.last
        return last is not None and (last.code is None or last.code in (1, 7))

    def describe(self) -> dict:
        last = self.last
        return {"group": self.group, "user": list(self.user) if self.user else None, "members": list(self.members),
                "folders": dict(self.folders), "files": dict(self.files),
                "adopted": list(self.adopted) if self.adopted else None, "digest": self.digest,
                "stopped": self.stopped, "notes": list(self.notes),
                "last": None if last is None else {"what": last.what, "time": last.time, "code": last.code,
                                                    "steps": [list(s) for s in last.steps]}}


_RUN = re.compile(r"run (\S+) (apply|member|undo) (\d+)")
_END = re.compile(r"end (\S+) (\d+)")
_STEP = re.compile(r"(begin|done) (\d+) (.+)")
_ADOPTED = re.compile(r"adopted user (\S+) (\d+) (\d+)")
_BEGIN = re.compile(r"make (group|user) \S+ \(absent\)|sysusers \S+ \(absent: [a-z ]+\)|(add|remove) member \S+"
                    r"|make folder \S+|write file \S+ [0-9a-f]+|remove (group|user|file|folder) \S+"
                    r"|move user \S+ \d+|regroup folder \S+ root")


def digest(text: str | None) -> str:
    """The journal's sha256 as `lm_sha` gives it as root: of its bytes, an absent journal's that of no bytes."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def fold(text: str | None, here: Here, name: str = "liminal") -> Made:
    """What the journal `text` says Liminal made, added or adopted, against what is `here` now (B4 2). `name` is
    Liminal's group and user (the user's answer 8: always `liminal`)."""
    state = {"group": None, "user": None, "members": {}, "folders": {}, "files": {}, "adopted": None}
    runs: list[dict] = []
    notes: list[str] = []
    begun: dict = {}  # the last run's begin lines without their done, by their step's number
    for number, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if m := _RUN.fullmatch(line):
            _settle(begun, state, here, name)
            runs.append({"nonce": m.group(1), "what": m.group(2), "time": int(m.group(3)), "steps": {}, "code": None})
        elif m := _END.fullmatch(line):
            _settle(begun, state, here, name)
            if runs and runs[-1]["nonce"] == m.group(1):
                runs[-1]["code"] = int(m.group(2))
        elif m := _STEP.fullmatch(line):
            n, words = int(m.group(2)), m.group(3)
            if m.group(1) == "begin":
                if not _BEGIN.fullmatch(words):
                    notes.append(f"line {number} of the journal is not one Liminal writes: {line[:120]}")
                    continue
                begun[n] = words
                if runs:
                    runs[-1]["steps"][n] = (words, "begun")
            else:
                _ended(begun, n, words)
                if runs and n in runs[-1]["steps"]:
                    runs[-1]["steps"][n] = (runs[-1]["steps"][n][0], "done")
                if not _done(words, state, name):
                    notes.append(f"line {number} of the journal is not one Liminal writes: {line[:120]}")
        elif m := _ADOPTED.fullmatch(line):
            if m.group(1) == name:
                state["adopted"] = (int(m.group(2)), int(m.group(3)))
        else:
            notes.append(f"line {number} of the journal is not one Liminal writes: {line[:120]}")
    _settle(begun, state, here, name)
    return Made(state["group"], state["user"], tuple(state["members"]), dict(state["folders"]), dict(state["files"]),
                state["adopted"], digest(text),
                tuple(Run(r["nonce"], r["what"], r["time"], tuple((n, *r["steps"][n]) for n in sorted(r["steps"])),
                          r["code"]) for r in runs), tuple(notes))


def _ended(begun: dict, n: int, words: str) -> None:
    """Step `n`'s begin line answered by a done line. sysusers' one begin has a done line for each object it made, so
    it stays begun for the objects whose line has not come (a run cut off between its two done lines)."""
    begin = begun.get(n)
    if begin is None:
        return
    if begin.startswith("sysusers ") and "(absent:" in begin:
        made = words.split()[1:2]  # "made group liminal 999": group
        head, _, absent = begin.partition("(absent:")
        left = [a for a in absent.rstrip(")").split() if a not in made]
        if left:
            begun[n] = f"{head}(absent: {' '.join(left)})"
            return
    del begun[n]


def _done(words: str, state: dict, name: str) -> bool:
    """A done line's words taken into `state`; False when they are no line Liminal writes."""
    p = words.split()
    if p[:3] == ["made", "group", name] and len(p) == 4 and p[3].isdigit():
        state["group"] = int(p[3])
    elif p[:3] == ["made", "user", name] and len(p) == 5 and p[3].isdigit() and p[4].isdigit():
        state["user"] = (int(p[3]), int(p[4]))
    elif p[:2] == ["added", "member"] and len(p) == 3:
        state["members"][p[2]] = True
    elif p[:2] == ["made", "folder"] and len(p) == 4:
        state["folders"][p[2]] = p[3]
    elif p[:2] == ["wrote", "file"] and len(p) == 4:
        state["files"][p[2]] = p[3]
    elif p[:3] == ["moved", "user", name] and len(p) == 4 and p[3].isdigit():
        if state["user"] is not None:
            state["user"] = (state["user"][0], int(p[3]))
    elif p[:2] == ["regrouped", "folder"] and len(p) == 4:
        pass  # root's group given back: nothing of Liminal's is made or ended by it
    elif p[0] == "removed" and len(p) == 3:
        _removed(p[1], p[2], state, name)
    else:
        return False
    return True


def _removed(kind: str, what: str, state: dict, name: str) -> None:
    if kind == "group" and what == name:
        state["group"] = None
    elif kind == "user" and what == name:
        state["user"] = None
    elif kind == "member":
        state["members"].pop(what, None)
    elif kind == "folder":
        state["folders"].pop(what, None)
    elif kind == "file":
        state["files"].pop(what, None)


def _settle(begun: dict, state: dict, here: Here, name: str) -> None:
    """The begin lines left without their done when a run ended or was cut off: each counts as done when what it
    makes is there now (or, for a removal, gone now), and as nothing when it is not."""
    for words in [begun[n] for n in sorted(begun)]:
        p = words.split()
        group, user = here.groups.get(name), here.users.get(name)
        if p[:3] == ["make", "group", name] and group is not None:
            state["group"] = int(group[0])
        elif p[:3] == ["make", "user", name] and user is not None:
            state["user"] = (int(user[0]), int(user[1]))
        elif p[:2] == ["sysusers", name]:
            absent = words.partition("(absent:")[2].rstrip(")").split()
            if "group" in absent and group is not None:
                state["group"] = int(group[0])
            if "user" in absent and user is not None:
                state["user"] = (int(user[0]), int(user[1]))
        elif p[:2] == ["add", "member"] and len(p) == 3 and group is not None and p[2] in group[1]:
            state["members"][p[2]] = True
        elif p[:2] == ["make", "folder"] and len(p) == 3 and p[2] in here.paths:
            state["folders"][p[2]] = "?"
        elif p[:2] == ["write", "file"] and len(p) == 4 and here.paths.get(p[2]) == p[3]:
            state["files"][p[2]] = p[3]
        elif p[:3] == ["move", "user", name] and len(p) == 4 and user is not None and str(user[1]) == p[3]:
            if state["user"] is not None:
                state["user"] = (state["user"][0], int(p[3]))
        elif p[0] == "remove" and len(p) == 3 and _gone(p[1], p[2], here, name):
            _removed(p[1], p[2], state, name)
    begun.clear()


def _gone(kind: str, what: str, here: Here, name: str) -> bool:
    if kind == "group":
        return what not in here.groups
    if kind == "user":
        return what not in here.users
    if kind == "member":
        return what not in (here.groups.get(name) or (0, ()))[1]
    return what not in here.paths  # a folder, a file
