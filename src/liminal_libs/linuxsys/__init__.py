"""Linux as Liminal administers it, plain: this system's facts, a change as a plan, the journal of what Liminal
made, and a stand-in machine for every suite that tests on it (Monday list item 19: Liminal's own `liminal` user and
group, made, changed and removed from the Linux administration plugin's page or by one root command).

Plain means the standard library, this package's own modules and `proctree`, nothing more: no plugin contract, no
app's frame, no process ledger, no `machines/` (whose every module loads all three). The one root command runs from
here (`python -I -B -m liminal_libs.linuxsys`), and it runs no frame as root. tests/test_linuxsys_plain.py holds every
module to it, by its imports and by what loading it brings in.

- `shared`: what this package and `machines/linux.py` both use (sudo's words, the head of every root script, the
  reader of sudo's listing, the cleaner of every word that goes into a root's file or script).
- `kernel`: the Linux kernel, WSL and container facts, from files' texts and the environment alone.
- `facts`: PROBE, one POSIX sh read as the platform's user, and SystemFacts, what it found.
- `plan`: a change as data: its steps, each an Action its tool renders into sh and the stand-in plays; the one script;
  the chain of folders a root's file rests on.
- `journal`: /var/lib/liminal-linux/MADE, a line before each step and one after it, and what they add up to.
- `elevation`: how root is had here, and the sudo conversation that runs a plan's script as root.
- `accounts`: Liminal's group and user, made, changed and taken back, by this system's account tool.
- `cli`, `__main__`: the root command.
- `standin`: a recorded machine that answers PROBE, plays a plan's Actions on a file tree with their tools' side
  effects, and plays sudo's conversation over byte pipes. It runs nothing.
- `recorded/`: the recorded machines, each with its SOURCE.

`system(runner, spawn)` gives a LinuxSystem: the facts (kept FACTS_S, read again after any plan), sudo's listing (read
at most once per SUDO_S, whatever `fresh` says: each read writes a line in auth.log on sudo 1.9.15), the Elevation,
the AccountTool, and the plans of Make them..., Add and Remove a member... and Remove them..., applied under its own
lock, one sudo per confirmed click.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time

from . import accounts as _accounts
from . import elevation as _elevation
from . import facts as _facts
from .plan import CHANGED, HELD
from .shared import SUDO_LIST, Refused, why_not_native

__all__ = ["system", "LinuxSystem", "FACTS_S", "SUDO_S", "UNASKED"]

FACTS_S = 300.0  # seconds the facts are kept between two reads
SUDO_S = 300.0  # seconds sudo's listing is kept: every read of it may write a line in the system's log
LISTING_S = 10.0  # seconds `sudo -n -l` may take
UNASKED = "no password is asked here, so this page cannot show that it is you who asks"  # the user's answer 6


def _run(argv, timeout=None):
    return subprocess.run(list(argv), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
                          check=False)


def _spawn(argv):
    return subprocess.Popen(list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            bufsize=0)


class LinuxSystem:
    """This Linux, as release one changes it. `runner(argv, timeout)` answers as subprocess.run does (the probe, sudo's
    listing); `spawn(argv)` starts a process with byte pipes (sudo's conversation, a root shell's script). `command`:
    the root command's (no "asked twice where no password is asked": the one who typed sudo is there), with `who`, the
    one who ran it, in the place of the platform's user."""

    def __init__(self, runner, spawn, *, clock=time.monotonic, python: str | None = None, command: bool = False,
                 who: str | None = None):
        self.runner, self.spawn, self.clock = runner, spawn, clock
        self.python, self.command, self.who = python, command, who
        self._facts = None
        self._facts_at = 0.0
        self._listing = None
        self._listing_at: float | None = None
        self._asked_at: float | None = None  # when sudo asked for a password its listing said it would not (M5)
        self._lock = threading.Lock()

    # ---- what it knows ------------------------------------------------------------------------------------------

    def facts(self, fresh: bool = False):
        now = self.clock()
        if fresh or self._facts is None or now - self._facts_at > FACTS_S:
            self._facts, self._facts_at = _facts.read(self.runner), now
        return self._facts

    def listing(self):
        """sudo's listing, (code, stdout, stderr), read at most once per SUDO_S; None where there is no sudo to ask or
        the platform is root."""
        f = self.facts()
        if f.elevation.get("euid") == 0 or not f.elevation.get("sudo"):
            return None
        now = self.clock()
        if self._listing_at is None or now - self._listing_at > SUDO_S:
            try:
                done = self.runner(list(SUDO_LIST), LISTING_S)
                self._listing = (done.returncode, done.stdout or "", done.stderr or "")
            except (OSError, subprocess.SubprocessError) as e:
                self._listing = (None, "", str(e))
            self._listing_at = now
        return self._listing

    def elevation(self) -> _elevation.Elevation:
        """The way root is had, from the facts and the listing. Where sudo asked for a password its listing said it
        would not (PasswordNeeded), the listing is not taken for SUDO_S after, so the form is offered with its field
        and the password typed there reaches sudo (M5)."""
        listing = self.listing()
        if self._asked_at is not None and self.clock() - self._asked_at <= SUDO_S:
            listing = None
        return _elevation.elevation(self.facts(), listing, python=self.python)

    def accounts(self) -> _accounts.AccountTool:
        return _accounts.tool(self.facts(), self.who)

    @property
    def made(self):
        return self.facts().made()

    def forget(self) -> None:
        """Drop the kept facts and the kept listing: after any plan, and after a digest refusal (S16)."""
        self._facts = None
        self._listing, self._listing_at = None, None

    def describe(self) -> dict:
        el = self.elevation()
        return {"facts": self.facts().describe(), "elevation": el.words(), "accounts": self.accounts().state(),
                "lines": {"apply": el.line("apply"), "undo": el.line("undo --yes")}}

    # ---- the plans -----------------------------------------------------------------------------------------------

    def platform_member(self) -> str | None:
        """Who Make them... adds: the platform's user, none when it is root (the command names one with --for)."""
        f = self.facts()
        if self.who:
            return self.who
        return None if f.elevation.get("euid") == 0 else (f.elevation.get("user") or None)

    def plan_make(self, parts=_accounts.PARTS, member: str | None = None) -> _accounts.Change:
        return self._asked(self.accounts().make(parts, member if member is not None else self.platform_member()))

    def plan_member(self, user: str, action: str) -> _accounts.Change:
        return self._asked(self.accounts().member(user, action))

    def plan_undo(self) -> _accounts.Change:
        return self._asked(self.accounts().undo())

    def _asked(self, change: _accounts.Change) -> _accounts.Change:
        """The change with the user's answer 6 added: where no password is asked, every change is asked twice."""
        if self.command or change.plan.refused or change.plan.nothing:
            return change
        if self.elevation().field() == "no":
            return change.with_ask("accept_unasked", UNASKED)
        return change

    # ---- running one ---------------------------------------------------------------------------------------------

    def apply(self, change: _accounts.Change, password: str | None = None, *, digest: str | None = None,
              stop: threading.Event | None = None, **accepts) -> dict:
        """Run `change` as root: refused on a digest other than the one confirmed (the facts and the listing then
        dropped), or while one of its asks is not accepted, both before sudo is started; nothing is run for a plan of
        nothing. Its answer: {said, lines, code}. The facts and the listing are dropped after the run."""
        if digest is not None and digest != change.digest:
            self.forget()
            raise Refused(CHANGED)
        change.check(**accepts)
        a_plan = change.plan
        if a_plan.nothing:
            return {"said": "nothing to do: it is all here", "lines": a_plan.words(), "code": 0}
        if not self._lock.acquire(blocking=False):
            raise Refused(HELD)
        try:
            ran = self.elevation().run(a_plan, password, spawn=self.spawn, stop=stop, clock=self.clock)
        except _elevation.PasswordNeeded:
            self.forget()
            self._asked_at = self.clock()
            raise
        finally:
            self._lock.release()
        self.forget()
        lines = [f"{o.index}. {a_plan.steps[o.index - 1].words}: {o.state}" for o in ran.outcomes]
        return {"said": ran.said, "lines": lines, "code": ran.code}


def system(runner=None, spawn=None, *, fresh: bool = False, command: bool = False, who: str | None = None,
           python: str | None = None) -> LinuxSystem:
    """This Linux as a LinuxSystem, through the runner and spawn it is handed (LinuxAdmin's, on proctree and
    lifecycle; the command's, subprocess's, the defaults). Never a WSL target from outside (M3): off Linux, with no
    runner handed, it raises in why_not_native's words."""
    if runner is None and (why := why_not_native("Linux administration")):
        raise Refused(why)
    s = LinuxSystem(runner or _run, spawn or _spawn, command=command, who=who, python=python or sys.executable)
    if fresh:
        s.facts(fresh=True)
    return s
