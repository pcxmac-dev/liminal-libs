"""How root is had on this Linux, and the sudo conversation that runs a plan's script as root (the linuxperm plan's
S1, B2, M5, M19, M21; the user's answer 7: doas and su get a terminal in the page later, and until then the page shows
the one command).

`elevation(facts, listing)` picks one Elevation from the facts and sudo's listing as LinuxSystem read it:
- AsRoot: the platform is root; the script runs as `/bin/sh -c <script> liminal <nonce>`, nothing asked;
- Sudo: classic sudo or sudo-rs, each with its words; the field is "no" where the listing shows a password-free rule
  for ALL or /bin/sh as root (the last match deciding), or `Defaults !authenticate`, else "yes";
- Doas, Su: they take a password only from a terminal: "terminal", and the one command;
- Unusable: run0 or pkexec only, which ask through a polkit agent the page is not: "impossible";
- NoElevation: nothing here gives root: "impossible".
A platform that runs as a system account (a uid below UID_MIN, Liminal's user, a nologin shell) has no password to
type, so its field is "impossible" whatever the tool (B2).

The conversation (`converse`), in full: `<env> LC_ALL=C <sudo> -S -k -u root -p '<<liminal-sudo:<nonce>:%p>>' --
/bin/sh -c <script> liminal <nonce>`, started through the `spawn` it is handed (LinuxAdmin's: lifecycle.spawn, owned
by the plugin; the command's: subprocess). Both pipes are read as bytes, at once, from threads. At the marker the
password and one line end are written, once, and the pipe is kept open: closing it would let sudo read end of input
at a second prompt, inside PAM's next try, which pam_faillock may count as a second failed sign-in. At the script's
begin line the pipe is closed (the script reads /dev/null already). A second marker means sudo waits at its prompt
and nothing has run: sudo is ended with SIGKILL at once, then the pipe is closed; after sudo's retry words it was a
wrong password (WrongPassword: one failed sign-in, the form is offered again), without them a second factor. A first
marker naming another account than the field's (root's, under targetpw) is ended before anything is written. Neither
marker nor begin line within CONVERSE_S: SIGKILL. sudo ending before the begin line: its words, scrubbed whole. A
stop before the begin line ends sudo with SIGKILL (nothing has run: a script sudo had already started sees its parent,
$PPID, gone at its first stop check, before the lock, and exits 7); after it, the script is told TERM once and
finishes the step it is in. The password is never in an argument, the environment, a log line or any words this
module gives back.
"""
from __future__ import annotations

import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass

from . import plan as plans
from .shared import (PASSWORD_REFUSED, SUDO_RETRY, Refused, listed, password_problem, runs_free, scrub)

__all__ = ["Elevation", "AsRoot", "Sudo", "Doas", "Su", "Unusable", "NoElevation", "elevation", "converse",
           "Talked", "Ran", "WhosePassword", "PasswordNeeded", "CONVERSE_S", "STEP_S", "RUN_S", "MARKER",
           "command_line"]

CONVERSE_S = 30.0  # seconds sudo has to show its marker, or to take or refuse the password
STEP_S = 0.1  # the slices every wait is cut in, each looking at the stop
RUN_S = 600.0  # seconds a script that has begun may run before it is ended: its steps are a few accounts' tools
MARKER = "<<liminal-sudo:{nonce}:%p>>"
ENTRY = "-I -B -m liminal_libs.linuxsys"
STOPPED = "the platform stopped before the change began: nothing was changed"
SECOND_FACTOR = ("this system's sudo asks for more than a password (a one-time code, a second factor): sudo was "
                 "ended at its second prompt and nothing was changed; run this once in a terminal: {line}")
TIMEOUT = "sudo neither asked for the password nor began the change within {s:g} s: it was ended, nothing was changed"
TIMEOUT_AFTER = "sudo neither took nor refused the password within {s:g} s: it was ended, nothing was changed"
WRONG = ("sudo said the password was wrong: one failed sign-in, and nothing was changed; type it again, or run this "
         "once in a terminal: {line}")
ENDED = "sudo ended before the change began (exit {code}): {words}; nothing was changed"
NOTE = "used for this once, never kept; one try: a wrong one counts as a failed sign-in"
LOGGED = "sudo writes each change's script into this system's log"


class WhosePassword(Refused):
    """sudo's prompt named another account than the field's label (root's, under targetpw): nothing was written to
    it. `whose` is the account it named; the form is offered again with that label."""

    def __init__(self, words: str, whose: str):
        super().__init__(words)
        self.whose = whose


class PasswordNeeded(Refused):
    """sudo asked for a password where none was given (its listing said none was needed): the form is offered again
    with its field (M5)."""


@dataclass(frozen=True)
class Talked:
    """What a conversation came to: the script's exit code (None: it never began), its standard output and standard
    error, scrubbed whole of the password."""

    code: int | None
    out: str
    err: str


@dataclass(frozen=True)
class Ran:
    """A plan run as root: its exit code, each step's Outcome, the run's words, and the script's output."""

    code: int | None
    outcomes: tuple
    said: str
    out: str = ""
    err: str = ""


def command_line(tool: str, args: str = "apply", python: str | None = None) -> str:
    """The one command that makes the change as root from a terminal, for `tool` (root, sudo, sudo-rs, doas, su, run0,
    or anything else: the command as root)."""
    py = python or sys.executable or "python3"
    entry = f"{py} {ENTRY} {args}".rstrip()
    if tool in ("sudo", "sudo-rs"):
        return f"sudo {entry}"
    if tool == "doas":
        return f"doas {entry}"
    if tool == "su":
        return f"su -c '{entry}'"
    if tool == "run0":
        return f"run0 {entry}"
    return entry


# ---- the conversation --------------------------------------------------------------------------------------------


class _Reader:
    """One pipe read as bytes, at once, from a thread of its own: what came, and whether it ended."""

    def __init__(self, pipe, cv: threading.Condition):
        self.data = bytearray()
        self.ended = pipe is None
        self._pipe, self._cv = pipe, cv
        if pipe is not None:
            self._thread = threading.Thread(target=self._run, name="liminal-linuxsys-pipe", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        read = getattr(self._pipe, "read1", None) or self._pipe.read
        try:
            while True:
                chunk = read(65536)
                if not chunk:
                    break
                with self._cv:
                    self.data += chunk
                    self._cv.notify_all()
        except Exception:  # noqa: BLE001 - a pipe torn by a kill is an end like any other
            pass
        finally:
            with self._cv:
                self.ended = True
                self._cv.notify_all()

    def join(self, seconds: float) -> None:
        if self._pipe is not None:
            self._thread.join(seconds)


def _close(proc) -> None:
    try:
        if proc.stdin is not None:
            proc.stdin.close()
    except (OSError, ValueError):
        pass


def _kill(proc) -> None:
    try:
        proc.kill()
    except OSError:
        pass
    _close(proc)


def _ended(proc) -> int | None:
    try:
        return proc.poll()
    except OSError:
        return None


def converse(argv, password: str | None, nonce: str, *, spawn, whose: str = "", line: str = "",
             clock=time.monotonic, stop: threading.Event | None = None, converse_s: float = CONVERSE_S,
             run_s: float = RUN_S) -> Talked:
    """Run `argv` (sudo's conversation, or a root shell's script) through `spawn(argv)` and hold its conversation, as
    the module's words say. `whose` is the account the field asked the password of ("" where any is taken), `line`
    the one command its refusals name. A refusal is a Refused (WrongPassword, WhosePassword, PasswordNeeded among
    them), raised only where nothing has run."""
    if password is not None and (problem := password_problem(password)):
        raise Refused(problem)
    stop = stop or threading.Event()
    if stop.is_set():
        raise Refused(STOPPED)
    proc = spawn(list(argv))
    cv = threading.Condition()
    out, err = _Reader(proc.stdout, cv), _Reader(proc.stderr, cv)
    marker = re.compile(rb"<<liminal-sudo:" + re.escape(nonce.encode()) + rb":([^>\n]*)>>")
    begin = f"@@ liminal-begin {nonce}\n".encode()
    deadline = clock() + converse_s
    written = begun = termed = False

    def said() -> str:
        return scrub(bytes(err.data).decode("utf-8", "replace"), password)

    try:
        while True:
            with cv:
                cv.wait(STEP_S)
                e = bytes(err.data)
                piped = out.ended and err.ended
            if not begun and begin in e:
                begun = True
                _close(proc)
                deadline = clock() + run_s
            if begun:
                if piped and _ended(proc) is not None:
                    break
                if stop.is_set() and not termed:
                    termed = True
                    try:
                        proc.terminate()  # sudo passes it on: the script finishes its step, then exits 7
                    except OSError:
                        pass
                if clock() > deadline:
                    _kill(proc)
                    break
                continue
            if stop.is_set():
                _kill(proc)
                raise Refused(STOPPED)
            code = _ended(proc)
            if code is not None and err.ended:
                words = said()
                low = words.lower()
                if written and any(w in low for w in PASSWORD_REFUSED):
                    raise plans.WrongPassword(WRONG.format(line=line))
                raise Refused(ENDED.format(code=code, words=" ".join(words.split())[:400] or "nothing said"))
            found = list(marker.finditer(e))
            if found and not written:
                who = found[0].group(1).decode("utf-8", "replace")
                if who and who != "%p" and whose and who != whose:
                    _kill(proc)
                    raise WhosePassword(f"this system's sudo asks for {who}'s password here, not {whose}'s: nothing "
                                        f"was typed to it; type {who}'s password", who)
                if password is None:
                    _kill(proc)
                    raise PasswordNeeded("sudo asks for a password here after all: nothing was changed; type it in "
                                         "the field")
                try:
                    proc.stdin.write(password.encode("utf-8") + b"\n")
                    proc.stdin.flush()
                except (OSError, ValueError):
                    pass  # sudo ended: said at the next look
                written = True
                deadline = clock() + converse_s
                continue
            if written and len(found) >= 2:
                _kill(proc)  # sudo waits at its prompt again: never let it read end of input there
                between = e[found[0].end():found[1].start()].decode("utf-8", "replace").lower()
                if any(w in between for w in SUDO_RETRY):
                    raise plans.WrongPassword(WRONG.format(line=line))
                raise Refused(SECOND_FACTOR.format(line=line))
            if clock() > deadline:
                _kill(proc)
                raise Refused((TIMEOUT_AFTER if written else TIMEOUT).format(s=converse_s))
    finally:
        if _ended(proc) is None and not begun:
            _kill(proc)
        out.join(1.0)
        err.join(1.0)
    code = _ended(proc)
    if code is None:
        try:
            code = proc.wait(STEP_S * 10)
        except Exception:  # noqa: BLE001 - a stand-in's wait, or a real one torn: the code is not known
            code = None
    return Talked(code, scrub(bytes(out.data).decode("utf-8", "replace"), password), said())


# ---- the ways root is had ----------------------------------------------------------------------------------------


def _authenticate_off(text: str) -> bool:
    """Whether sudo's listing's Defaults hold `!authenticate` (no password asked of anyone it lets in)."""
    head = text.split(" may run the following commands", 1)[0]
    return bool(re.search(r"(^|[\s,])!authenticate([\s,]|$)", head))


class Elevation:
    """How root is had here: `tool`, its version, whose password it asks ("self", "root", ""), the field's label;
    field() -> "no" | "yes" | "terminal" | "impossible"; words() for the page's "How root is had"; run(plan, ...)."""

    tool = "none"
    asks = "impossible"

    def __init__(self, facts, listing=None, *, python: str | None = None):
        self.facts = facts
        self.listing = listing  # (code, stdout, stderr) of `env LC_ALL=C sudo -n -l`, or None: not read
        self.python = python
        el = facts.elevation if facts is not None else {}
        self.user = el.get("user", "")
        self.version = ""
        self.whose = ""

    # what the page shows

    def system_account(self) -> bool:
        if self.facts is None or self.facts.elevation.get("euid") == 0:
            return False
        return self.facts.system_account(self.facts.accounts.get("users", {}).get(self.user))

    def field(self) -> str:
        return self.asks

    @property
    def label(self) -> str:
        if self.whose == "root":
            return "root's password (this system's sudo asks for it)"
        return f"Your password for {self.tool}" if self.tool in ("sudo", "sudo-rs") else ""

    def line(self, args: str = "apply") -> str:
        return command_line(self.tool if self.tool != "none" else "", args, self.python)

    def why(self) -> str:
        """Why no change is made from the page here, in words ("" when one is)."""
        if self.system_account():
            who = "Liminal's service account" if self.user == "liminal" else f"{self.user}, a system account"
            return (f"the platform runs as {who}, which has no password: make this change from the platform run as "
                    f"yourself, or run this once as root in a terminal: {self.line()}")
        return ""

    def words(self) -> dict:
        field = "impossible" if self.system_account() else self.field()
        return {"tool": self.tool, "version": self.version, "whose": self.whose, "field": field,
                "label": self.label if field == "yes" else "", "note": NOTE if field == "yes" else "",
                "logged": LOGGED if self.tool in ("sudo", "sudo-rs") else "", "why": self.why() or self._why(),
                "line": self.line()}

    def _why(self) -> str:
        return ""

    # running a plan

    def argv(self, script: str, nonce: str) -> list[str]:
        raise Refused(self.why() or self._why() or "nothing here gives root: nothing was changed")

    def run(self, a_plan: plans.Plan, password: str | None = None, *, spawn, stop=None,
            clock=time.monotonic, nonce: str | None = None) -> Ran:
        """Run `a_plan`'s script as root through this way, holding the conversation; its outcomes and words."""
        if a_plan.refused:
            raise Refused(a_plan.refused)
        if why := self.why():
            raise Refused(why)
        if self.field() == "yes" and not password:
            raise PasswordNeeded(f"{self.label or 'a password'} is needed for this change: nothing was changed")
        script = a_plan.script()
        nonce = nonce or secrets.token_hex(8)
        argv = self.argv(script, nonce)
        talked = converse(argv, password if self.field() == "yes" else None, nonce, spawn=spawn,
                          whose=self._whose_name(), line=self.line(), clock=clock, stop=stop)
        outcomes, said = a_plan.said(talked.out, talked.code)
        return Ran(talked.code, tuple(outcomes), said, talked.out, talked.err)

    def _whose_name(self) -> str:
        return {"root": "root", "self": self.user}.get(self.whose, "")


class AsRoot(Elevation):
    """The platform, or the command, runs as root: the script runs as a root shell's, nothing asked."""

    tool = "root"
    asks = "no"

    def argv(self, script: str, nonce: str) -> list[str]:
        return ["/bin/sh", "-c", script, "liminal", nonce]

    def line(self, args: str = "apply") -> str:
        return command_line("root", args, self.python)


class Sudo(Elevation):
    """Classic sudo or sudo-rs (Ubuntu 25.10 and later), each with its own words."""

    def __init__(self, facts, listing=None, **kw):
        super().__init__(facts, listing, **kw)
        el = facts.elevation
        self.tool = el.get("sudo_kind") or "sudo"
        self.version = el.get("sudo_version", "")
        self.path = el.get("sudo") or "/usr/bin/sudo"
        self.whose = _whose(facts)

    def field(self) -> str:
        if self.listing is not None:
            code, text, _ = self.listing
            if code == 0 and (runs_free(listed(text or ""), ("/bin/sh", "-c", "liminal")) or
                              _authenticate_off(text or "")):
                return "no"
        return "yes"

    def argv(self, script: str, nonce: str) -> list[str]:
        env = (self.facts.tools.get("env") or ("/usr/bin/env",))[0]
        return [env, "LC_ALL=C", self.path, "-S", "-k", "-u", "root", "-p", MARKER.format(nonce=nonce), "--",
                "/bin/sh", "-c", script, "liminal", nonce]


def _whose(facts) -> str:
    """Whose password sudo asks, before the first click (M21): root's on openSUSE (targetpw) unless
    sudo-policy-wheel-auth-self is installed and the user is in wheel; the user's own elsewhere. The marker confirms
    it."""
    if facts.os.get("family") == "suse":
        wheel = "wheel" in facts.elevation.get("groupnames", ())
        return "self" if facts.elevation.get("wheel_auth_self") and wheel else "root"
    return "self"


class _Terminal(Elevation):
    asks = "terminal"

    def _why(self) -> str:
        return (f"this system's {self.tool} takes a password only from a terminal: run this once in a terminal: "
                f"{self.line()}")

    def argv(self, script: str, nonce: str) -> list[str]:
        raise Refused(self._why())


class Doas(_Terminal):
    """OpenDoas (Alpine's): a password only from a terminal; the page shows the one command (the user's answer 7)."""

    tool = "doas"


class Su(_Terminal):
    """su (Debian without sudo): root's password, only from a terminal."""

    tool = "su"

    def __init__(self, facts, listing=None, **kw):
        super().__init__(facts, listing, **kw)
        self.whose = "root"


class Unusable(Elevation):
    """run0 or pkexec only: they ask through a polkit agent, which the page is not."""

    def __init__(self, facts, listing=None, **kw):
        super().__init__(facts, listing, **kw)
        self.tool = "run0" if facts.elevation.get("run0") else "pkexec"

    def _why(self) -> str:
        return (f"this system gives root through {self.tool} alone, which asks through a polkit agent, not this page: "
                f"run this once in a terminal: {self.line()}")


class NoElevation(Elevation):
    """Nothing here gives root to the platform's user: no sudo, doas, su, run0 or pkexec."""

    def _why(self) -> str:
        return ("nothing here gives root to the platform's user (no sudo, doas, su, run0 or pkexec): run this once "
                f"as root: {self.line()}")


def elevation(facts, listing=None, *, python: str | None = None) -> Elevation:
    """The way root is had here, from the facts and sudo's listing ((code, stdout, stderr) of `sudo -n -l`, or None).
    Where sudo and doas are both there, the one this user has rules in: sudo's "may not run sudo" means doas (M19)."""
    el = facts.elevation
    if el.get("euid") == 0:
        return AsRoot(facts, listing, python=python)
    refused = (listing[2] or "").lower() if listing else ""
    if el.get("sudo") and not ("may not run sudo" in refused and el.get("doas")):
        return Sudo(facts, listing, python=python)
    if el.get("doas"):
        return Doas(facts, listing, python=python)
    if el.get("su"):
        return Su(facts, listing, python=python)
    if el.get("run0") or el.get("pkexec"):
        return Unusable(facts, listing, python=python)
    return NoElevation(facts, listing, python=python)
