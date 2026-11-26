"""The root command: `<python> -I -B -m liminal_libs.linuxsys ...` (the linuxperm plan's 3.7 and S8).

    facts | check | plan [PARTS] [--for USER]
    | apply [PARTS] [--for USER] [--unattended] [--yes] | member add|remove USER [--yes] | undo --yes

`facts`, `check` and `plan` need no root. `apply`, `member` and `undo` run as root, the same plans the page runs (the
same bytes), through a root shell (AsRoot), started with subprocess, never through the process ledger. PARTS are
accounts and service-user, both by default. `--for` names the member Make them... adds; else SUDO_USER, DOAS_USER or
PKEXEC_UID; never root, and none with `--unattended`. `--yes` is the second confirmation the page asks: for undo, for
a member other than the one who runs it, for a found group holding persons' accounts.

Exit codes: 0 done or nothing to do; 1 a step failed (what was done is said and journaled, and running it again goes
on from there); 2 refused; 3 not root (it says how to run it here); 4 a usage error; 5 stopped after a step (a TERM,
an INT, or nobody reading), and running it again finishes it.

It asks nothing and downloads nothing. As root it ignores HUP and PIPE; at INT or TERM it tells the script, which
stops after its step, and says how far it got. It writes nothing outside its plan: no ledger row, no log file, no
claims file, and no bytecode (main() sets sys.dont_write_bytecode before anything else; `-B` covers the imports before
it). Everything the platform's user can write (the venv, its .pth files, the editable checkout) is trusted by it, so
only the person who would type sudo anyway runs it, from their own terminal.
"""
from __future__ import annotations

import sys

USAGE = ("usage: python -I -B -m liminal_libs.linuxsys facts | check | plan [PARTS] [--for USER]\n"
         "       | apply [PARTS] [--for USER] [--unattended] [--yes] | member add|remove USER [--yes] | undo --yes\n"
         "PARTS: accounts, service-user (both by default)\n")
ACCEPTS = ("accept_members", "accept_member", "accept_removal")
EXIT = {0: 0, 1: 1, 2: 2, 5: 2, 7: 5}


class _Usage(Exception):
    pass


def _args(argv: list[str]) -> dict:
    if not argv or argv[0] in ("-h", "--help", "help"):
        raise _Usage("")
    what, rest = argv[0], argv[1:]
    out = {"what": what, "parts": [], "for": None, "unattended": False, "yes": False, "user": None, "action": None}
    if what not in ("facts", "check", "plan", "apply", "member", "undo"):
        raise _Usage(f"no command {what!r}")
    i = 0
    while i < len(rest):
        word = rest[i]
        if word == "--for" and what in ("plan", "apply"):
            if i + 1 >= len(rest):
                raise _Usage("--for names a user")
            out["for"], i = rest[i + 1], i + 2
            continue
        if word == "--unattended" and what == "apply":
            out["unattended"] = True
        elif word == "--yes" and what in ("apply", "member", "undo"):
            out["yes"] = True
        elif word in ("accounts", "service-user") and what in ("plan", "apply"):
            out["parts"].append(word)
        elif what == "member" and out["action"] is None and word in ("add", "remove"):
            out["action"] = word
        elif what == "member" and out["action"] is not None and out["user"] is None and not word.startswith("-"):
            out["user"] = word
        else:
            raise _Usage(f"{word!r} is not one of {what}'s words")
        i += 1
    if what == "member" and (out["action"] is None or out["user"] is None):
        raise _Usage("member add|remove USER")
    if out["unattended"] and out["for"]:
        raise _Usage("--unattended adds no member, so it takes no --for")
    return out


def _who(args: dict, env: dict, facts) -> str | None:
    """The member Make them... adds, and the one who runs the command: --for, else SUDO_USER, DOAS_USER or PKEXEC_UID
    (a uid, named from /etc/passwd)."""
    if args["unattended"]:
        return None
    if args["for"]:
        return args["for"]
    for var in ("SUDO_USER", "DOAS_USER"):
        if env.get(var):
            return env[var]
    uid = env.get("PKEXEC_UID", "")
    if uid.isdigit():
        return next((u.name for u in facts.accounts.get("users", {}).values() if u.uid == int(uid)), None)
    return None


def _signals(stop) -> None:
    """As root: HUP and PIPE ignored; INT and TERM tell the script, which stops after its step."""
    import signal
    try:
        for name in ("SIGHUP", "SIGPIPE"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), signal.SIG_IGN)
        for name in ("SIGINT", "SIGTERM"):
            signal.signal(getattr(signal, name), lambda *_: stop.set())
    except (ValueError, OSError):
        pass  # not the main thread: the caller holds the signals


def main(argv: list[str] | None = None, *, system=None, euid: int | None = None, env: dict | None = None,
         out=None, err=None, signals: bool | None = None) -> int:
    """The command. `system`, `euid` and `env` stand in for this Linux, os.geteuid() and os.environ in tests."""
    sys.dont_write_bytecode = True  # before anything else: nothing imported from here on writes bytecode (S8)
    import json
    import os
    import threading

    from . import elevation as _elevation
    from . import system as _system
    from .shared import Refused

    out, err = out or sys.stdout, err or sys.stderr
    argv = sys.argv[1:] if argv is None else list(argv)
    env = dict(os.environ) if env is None else env

    def say(text: str, to=None) -> None:
        (to or out).write(text.rstrip("\n") + "\n")

    try:
        args = _args(argv)
    except _Usage as e:
        if str(e):
            say(f"linuxsys: {e}", err)
        say(USAGE, err if str(e) else out)
        return 4 if str(e) else 0
    real = system is None
    if euid is None:
        euid = os.geteuid() if hasattr(os, "geteuid") else -1
    try:
        s = system or _system(command=True)
        f = s.facts()
        who = _who(args, env, f)
        if who == "root" or (who and who.isdigit() and int(who) == 0):
            say("linuxsys: root is never a member of liminal: name the user with --for", err)
            return 2
        s.who = s.who or who
        s.command = True
        what = args["what"]
        if what == "facts":
            say(json.dumps(s.describe(), indent=1, sort_keys=True, default=str))
            return 0
        if what in ("check", "plan"):
            change = s.plan_make(args["parts"] or None, who)
            el = s.elevation().words()
            say(f"root here: {el['tool']} ({el['field']}); account tool: {s.accounts().kind}")
            for line in change.words():
                say(line)
            if what == "plan" and not change.plan.refused:
                say(f"digest {change.digest}")
            say(f"to make it as root: {_elevation.command_line(el['tool'], 'apply', s.python)}")
            return 2 if change.plan.refused else 0
        if euid != 0:
            words = f"{what}{' --yes' if what == 'undo' else ''}"
            say(f"linuxsys: {what} runs as root: run it as {s.elevation().line(words)}", err)
            return 3
        if signals if signals is not None else real:
            stop = threading.Event()
            _signals(stop)
        else:
            stop = threading.Event()
        if what == "apply":
            change = s.plan_make(args["parts"] or None, who)
        elif what == "member":
            change = s.plan_member(args["user"], args["action"])
        else:
            change = s.plan_undo()
        for line in change.words():
            say(line)
        accepts = {a: True for a in ACCEPTS} if args["yes"] else {}
        try:
            done = s.apply(change, None, stop=stop, **accepts)
        except Refused as e:
            if e.accept:
                say(f"linuxsys: {e} (add --yes to go on)", err)
            else:
                say(f"linuxsys: {e}", err)
            return 2
        for line in done["lines"]:
            say(line)
        say(done["said"])
        return EXIT.get(done["code"], 1)
    except Refused as e:
        say(f"linuxsys: {e}", err)
        return 2
