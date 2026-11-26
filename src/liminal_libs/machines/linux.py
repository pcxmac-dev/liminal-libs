"""Linux for the machine plugins (the firewall and admin plugins of the platform): commands on a Linux
machine, this one (with sudo when the platform is not root) or a WSL distribution on this Windows PC (as root
through `wsl -u root`). A command reads without a password where it can (`sudo -n`); where root is needed and a
password was typed on the plugin's page, it is handed to `sudo -S` on standard input for that one action (the
user, 2026-11-17: "the plugin needs to be able to handle permissions if required", "A field on its page";
`Shell.run`'s `password`). A plugin can also make a narrow grant so its own read runs without a password after
that (`grant`, `revoke`, `granted`, `needs_password`): the read script installed root-owned as a helper that sets
its own PATH and takes no arguments (`helper_text`), and a sudoers rule allowing exactly it, never `NOPASSWD: ALL`.
The Linux plugins work on the Linux the platform itself runs on, and only there (`why_not_native`): a machine of
its own, or a WSL distribution the platform runs inside (the user, 2026-11-15: "wsl and firewall linux should
always work under linux, if wsl prevents or misses some capability this should reflect in the plugin": `wsl`,
`wsl_table`). A platform on Windows does not administer a WSL distribution from outside (the user, 2026-11-08:
"it's not for administrating WSL instances"; until 1.57.0 that was read as refusing any WSL kernel, the
platform's own included).
They give their shell `local`. Without a target named, `local` on Linux, and on Windows Liminal's own distribution
when one is installed (Liminal-Ubuntu, then Liminal-Fedora, Liminal-Gentoo), never the user's own. A runner stands
in for the commands in tests (the password never reaches it in an argument: it is on standard input)."""
from __future__ import annotations

import base64
import inspect
import os
import platform
import shutil
import subprocess
import sys
import time

from .. import proctree
# what the plain package linuxsys shares with this module lives there (1.102.0: the root command loads no plugin
# contract, so nothing it needs may live under machines/); it is imported back under the names it had here
from ..linuxsys.shared import (  # noqa: F401 - DENIED to why_not_native are read from here by the plugins
    DENIED, GRANT_TAGS, PASSWORD_MAX, PASSWORD_REFUSED, ROOT_HEAD, ROOT_PATH, SUDO_LIST, why_not_native,
)
from ..linuxsys.shared import Listed as _Listed, listed as _listed, matches as _matches  # noqa: F401
from ..linuxsys.shared import password_problem as _password_problem, runs_free as _runs_free, scrub as _scrub_whole
from .plugin import LIMINAL_PREFIX, CommandError, liminal_scoped
from .terminal import inherited  # a child's environment: no LIMINAL_* name (the review of 2026-11-21, item 26)

TIMEOUT_S = 120.0
FOUND_S = 30.0  # the WSL distributions listed are kept this long
PREFERRED = ("Ubuntu", "Fedora", "Gentoo")  # Liminal's distributions in the order a target takes them
_found: tuple[float, list[str]] | None = None
# Liminal's root-owned helpers and the sudoers drop-in a grant writes (DECISIONS 2026-11-17, addenda 9 and 10)
LIBEXEC = "/usr/local/libexec/liminal"
SUDOERS_D = "/etc/sudoers.d"
TAKE_BACK = "take-back"  # the helper a grant writes so a later revoke needs no password
class PasswordRefused(CommandError):
    """sudo did not accept the password handed to `Shell.run` on standard input (wrong, empty or missing)."""

    def __init__(self, message: str = "sudo did not accept the password"):
        super().__init__(message, denied=False)


def _accepts_stdin(runner) -> bool:
    """Whether a stand-in runner takes the command's standard input as a third argument (so a test can read what
    reaches the process on stdin, the password included); the older two-argument runners do not and are called as
    before. A callable whose signature cannot be read is treated as two-argument."""
    try:
        params = list(inspect.signature(runner).parameters.values())
    except (TypeError, ValueError):
        return False
    positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    return len(positional) >= 3 or any(p.kind == p.VAR_POSITIONAL for p in params)


def _scrub(text: str, secret: str | None) -> str:
    """The text, or fixed words in its place when the password is anywhere in it, so it never reaches a log, an answer
    or an error's words (shared.scrub: the whole text goes, since stars in its place would tell where it was and how
    long it is)."""
    return _scrub_whole(text, secret)


def _check_password(password: str) -> None:
    """Refuse, before sudo is asked, a password it could not read as one line on its standard input: one holding a
    line break (sudo reads up to it, and the rest would be read as another try or reach the command) or a NUL, one of
    PASSWORD_MAX bytes or more (PAM refuses it), or one that is no UTF-8 text (linuxperm PLAN 1.7 step 1; the check
    is shared.password_problem's)."""
    problem = _password_problem(password)
    if problem:
        raise PasswordRefused(problem)


def _on_windows() -> bool:
    return os.name == "nt"


def wsl(release: str | None = None, env=None) -> str:
    """The WSL distribution this Linux is, by name ("Ubuntu"; "WSL" when it does not say), or "" on a machine of its
    own: told by the kernel's release (it names Microsoft or WSL) or by WSL's variables. `release` and `env` stand in
    for the kernel's release and the environment in tests."""
    if release is None and not sys.platform.startswith("linux"):
        return ""
    env = os.environ if env is None else env
    release = (platform.release() if release is None else release).lower()
    if "microsoft" in release or "wsl" in release or env.get("WSL_DISTRO_NAME") or env.get("WSL_INTEROP"):
        return str(env.get("WSL_DISTRO_NAME") or "WSL")
    return ""


def wsl_generation(release: str | None = None) -> int:
    """WSL 1 or WSL 2, by the kernel's release (WSL 2's is Microsoft's own Linux kernel, `...-microsoft-standard-WSL2`;
    WSL 1 has no Linux kernel and says `...-Microsoft`); 0 when the release does not tell (taken as WSL 2: every
    distribution installed today is)."""
    text = platform.release() if release is None else release
    if "wsl2" in text.lower() or "microsoft-standard" in text.lower():
        return 2
    return 1 if text.endswith("-Microsoft") else 0


def systemd_runs() -> bool:
    """Whether systemd is this Linux's init (a WSL distribution runs it only when /etc/wsl.conf says so)."""
    return os.path.isdir("/run/systemd/system")


def wsl_table(kind: str, release: str | None = None, env=None, systemd: bool | None = None) -> dict | None:
    """What running inside WSL changes or lacks, as a table for a Linux plugin's page (the user, 2026-11-15: "if wsl
    prevents or misses some capability this should reflect in the plugin"): for `kind` "admin" or "firewall". None
    on a machine of its own. `systemd`: whether systemd runs (a test's)."""
    name = wsl(release, env)
    if not name:
        return None
    generation = wsl_generation(release)
    rows = [["This Linux", f"WSL {generation or 2}: {name}", "a WSL distribution on Windows: its kernel and its network are WSL's"]]
    if kind == "admin":
        runs = systemd_runs() if systemd is None else systemd
        rows.append(["Init", "systemd" if runs else "not systemd",
                     "services and startups are read and changed as on any Linux" if runs else
                     "systemd is off in this distribution: `[boot]` `systemd=true` in /etc/wsl.conf turns it on (then "
                     "`wsl --shutdown` from Windows); until then units cannot be made or started here"])
        rows.append(["Running", "while Windows keeps it started",
                     "Windows starts a WSL distribution when something asks for it and stops it once nothing uses it: "
                     "what runs here stops with it"])
        rows.append(["At boot", "when the distribution starts",
                     "a service enabled at boot here starts when this distribution starts, not when the PC does: "
                     "starting the distribution at Windows' logon or boot is Windows' to do"])
    else:
        rows.append(["Packet filter", "the kernel's own" if generation != 1 else "none",
                     "nftables and iptables work here once their tools are installed" if generation != 1 else
                     "WSL 1 has no packet filter of its own: no firewall can run in this distribution, and Windows' "
                     "firewall is the one that filters"])
        rows.append(["Network", "WSL's own, behind Windows",
                     "it filters what reaches this distribution; what comes from outside the PC passes Windows' firewall "
                     "first, and Windows reaches this distribution's ports at its own localhost"])
    return {"title": "Under WSL", "note": "What running inside a WSL distribution changes for this plugin.",
            "columns": [{"title": "What"}, {"title": "Here"}, {"title": "What it means"}], "rows": rows}


def wsl_distributions() -> list[str]:
    """The WSL distributions installed (`wsl --list --quiet`, windowless); [] when WSL cannot say. Kept FOUND_S."""
    global _found
    now = time.monotonic()
    if _found is not None and now - _found[0] < FOUND_S:
        return list(_found[1])
    names: list[str] = []
    if _on_windows() and shutil.which("wsl"):
        try:
            out = subprocess.run(["wsl", "--list", "--quiet"], capture_output=True, timeout=30, env=inherited(),
                                 **_no_window()).stdout or b""
            text = out.decode("utf-16-le", "replace") if b"\x00" in out else out.decode("utf-8", "replace")
            names = [n.strip().lstrip("\ufeff") for n in text.replace("\x00", "").splitlines() if n.strip()]
        except (OSError, subprocess.TimeoutExpired):
            names = []
    _found = (now, names)
    return names


def liminal_distribution(names) -> str:
    """Liminal's own WSL distribution a Linux target takes: Liminal-Ubuntu, then Liminal-Fedora, Liminal-Gentoo, then
    any other of Liminal's; "" when none is installed."""
    own = [n for n in names if liminal_scoped(n)]
    for d in PREFERRED:
        for n in own:
            if n.lower() == f"{LIMINAL_PREFIX}{d}".lower():
                return n
    return own[0] if own else ""


class Shell:
    """Commands on the target. `runner(args, timeout) -> (code, stdout bytes or text, stderr bytes or text)`."""

    def __init__(self, target: str | None = None, runner=None, distributions=None):
        raw = (target or "").strip()
        self.liminal_missing = False  # no target named, on Windows, and no distribution of Liminal's installed
        if raw:
            self.target = raw
        elif not _on_windows():
            self.target = "local"
        else:  # Liminal's own distribution when one is installed: `distributions` lists them (a test's); with a runner, none
            listed = distributions if distributions is not None else (wsl_distributions if runner is None else None)
            name = liminal_distribution(listed()) if listed is not None else ""
            self.target = f"wsl:{name}" if name else "wsl"
            self.liminal_missing = listed is not None and not name
        if not (self.target == "local" or self.target == "wsl" or self.target.startswith("wsl:")):
            raise CommandError(f"a target is local, wsl or wsl:<distribution>, not {self.target!r}")
        self._runner = runner
        self._runner_stdin = _accepts_stdin(runner) if runner is not None else False

    @property
    def distribution(self) -> str:
        return self.target[4:] if self.target.startswith("wsl:") else ""

    @property
    def scoped(self) -> bool:
        """Whether the target is Liminal's: this Linux machine, or a WSL distribution of Liminal's own
        (wsl:Liminal-Ubuntu); WSL's default distribution is the user's own."""
        return self.target == "local" or liminal_scoped(self.distribution)

    @property
    def scope_note(self) -> str:
        """Why the target is not Liminal's, in words ("" when it is)."""
        if self.scoped:
            return ""
        if self.liminal_missing:
            return f"no Liminal distribution in WSL yet: a WSL plugin's setup installs one ({LIMINAL_PREFIX}Ubuntu)"
        return (f"{self.where} is not Liminal's: its target is a WSL distribution of Liminal's own "
                f"(wsl:{LIMINAL_PREFIX}Ubuntu, set up by a WSL plugin) or a Linux machine")

    @property
    def where(self) -> str:
        if self.target == "local":
            return "this machine"
        return f"WSL's {self.distribution}" if self.distribution else "WSL's default distribution"

    @property
    def here(self) -> bool:
        if self._runner is not None:
            return True
        if self.target == "local":
            return not _on_windows()
        return _on_windows() and shutil.which("wsl") is not None

    def root(self) -> bool:
        """Whether a command here runs as root without asking: WSL's root; this machine's when the platform is root."""
        if self.target != "local":
            return True
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def prefix(self, root: bool = True) -> list[str]:
        if self.target == "local":
            # -- (1.80.0): a command beginning with a dash (-u, say) is the command's, never read as sudo's option
            return ["sudo", "-n", "--"] if root and not self.root() else []
        # --exec: the arguments reach the command as they are (with --, the distribution's default shell would
        # expand $variables and split words before the command ran)
        return ["wsl", *(("-d", self.distribution) if self.distribution else ()), *(("-u", "root") if root else ()), "--exec"]

    def run(self, *command: str, root: bool = True, timeout: float = TIMEOUT_S, check: bool = True,
            stdin: str | None = None, password: str | None = None) -> str:
        """The command's output (as root unless said); CommandError in its own words, denied when it needed root.

        Without `password` the reading is as it always was: `sudo -n` when the platform is not root, so a command
        that would prompt fails rather than hang. With `password` and the platform not root on this machine, the
        password is handed to `sudo -S -k -p "" --` on standard input, alone (the user, 2026-11-17: a password field
        on the page, not sudo's prompt): nothing follows it, so a wrong one is one try and never the next line read
        as more, and a command run so takes no input of its own (`stdin` with a password is refused: the input goes
        inside the script). A password sudo could not read as one line (a line break or a NUL in it, PASSWORD_MAX
        bytes or more) is refused before sudo is asked. It never goes into an argument, the environment, a log, the
        answer or an error's words (scrubbed), and `PasswordRefused` says so when sudo turns it down.
        sudo reads the password only where it asks for one (with `-k`: where no NOPASSWD rule runs the command), and
        it is written without waiting for sudo's prompt: hand one only for what needs_password says needs it. A
        command that reads its standard input would get the line sudo left; a script for `sh -c` beginning with
        ROOT_HEAD reads none of it (the grant's and the take-back's do). Waiting for the prompt before writing is the
        conversation of linuxsys/elevation.py (`converse`: the password only after sudo's own marker, once), which
        Liminal's account changes run through; this road is the firewall's grant's until it moves there too. As
        root, or for a WSL target (always root through `wsl -u root`), `password` is ignored."""
        use_password = password is not None and root and self.target == "local" and not self.root()
        if use_password:
            _check_password(password)
            if stdin is not None:
                raise CommandError(f"{command[0]} takes no input of its own when a password is handed to sudo: the "
                                   "password is on the same standard input, so the input goes inside the script")
            args = ["sudo", "-S", "-k", "-p", "", "--", *command]
            feed = f"{password}\n"  # alone: sudo reads it as the password, and nothing after it is read as a try
        else:
            args = [*self.prefix(root), *command]
            feed = stdin
        code, out, err = self._exec(args, timeout, feed, command)
        if code != 0 and check:
            raw = err.strip() or out.strip() or f"{command[0]} failed ({code}) on {self.where}"
            # what sudo said is told apart before it is scrubbed: a password that is a word of sudo's refusal
            # ("sorry", "try", "again") would scrub it whole, and the refusal would go unknown
            low = raw.lower()
            if use_password and any(m in low for m in PASSWORD_REFUSED):
                raise PasswordRefused()
            denied = any(d in low for d in DENIED)
            last = _scrub(raw.splitlines()[-1].strip(), password if use_password else None)
            if denied and self.target == "local" and not self.root():
                raise CommandError(f"{command[0]} needs root on {self.where}: run the platform as root, or let sudo "
                                   f"run it without a password ({last})", denied=True)
            raise CommandError(last, denied=denied)
        return out

    def _exec(self, args: list[str], timeout: float, feed: str | None, command) -> tuple[int, str, str]:
        """Run `args`, feeding `feed` on standard input; (exit code, output, errors) as text, raising only when the
        command could not run at all (no target, a timeout, the spawn failed). `run`, `needs_password`, `grant`,
        `revoke` and `granted` are built on it; it never raises for a non-zero exit, so a caller can read the code."""
        if self._runner is not None:
            got = self._runner(args, timeout, feed) if self._runner_stdin else self._runner(args, timeout)
            code, out, err = got
        else:
            if not self.here:
                raise CommandError(f"no {self.where} to reach from here")
            try:  # a timeout ends the command with what it started, sudo's command asked to stop through sudo (1.80.0)
                done = proctree.run(args, timeout, input=feed.encode() if feed is not None else None,
                                    env=inherited())  # no LIMINAL_* name (the review of 2026-11-21, item 26)
            except subprocess.TimeoutExpired:
                raise CommandError(f"{command[0]} took more than {timeout:g} s on {self.where}") from None
            except OSError as e:
                raise CommandError(f"{command[0]} could not run on {self.where}: {e}") from None
            code, out, err = done.returncode, done.stdout, done.stderr
        return code, _text(out), _text(err)

    def sh(self, script: str, root: bool = True, timeout: float = TIMEOUT_S, check: bool = True) -> str:
        """A shell script on the target."""
        return self.run("sh", "-c", script, root=root, timeout=timeout, check=check)


def needs_password(shell: Shell, *command: str) -> bool:
    """Whether sudo would ask for a password to run `command` as root here. False when the shell is already root
    (this machine run as root, or a WSL target). Otherwise False only where sudo's listing of what this user may run
    (SUDO_LIST: `sudo -n -l`, which runs nothing) shows the rule that decides `command` running it, or ALL, as root
    with NOPASSWD (`_runs_free`); True whenever that cannot be shown: sudo will not list without a password, the
    listing is not one read here, or a rule that may decide the command asks for one. The exit code of
    `sudo -n -l <command>` cannot say it: sudoers' listpw (`any` by default) lets the listing be read without a
    password once any rule without one applies, and the code then says only whether the command is allowed at all.
    A plugin shows its Root-access switch, and a change's form its password field, only where this is True for what
    it runs (DECISIONS addendum 9)."""
    if shell.root():
        return False
    return not _runs_free(_sudo_listing(shell), command)


def _sudo_listing(shell: Shell) -> list[_Listed] | None:
    """sudo's listing of what this user may run here (SUDO_LIST), as its commands in sudoers' order; None when sudo
    will not list them without a password (no rule without one applies: sudoers' listpw), could not be asked, or
    answered with something else than its listing."""
    try:
        code, out, _err = shell._exec(list(SUDO_LIST), TIMEOUT_S, None, ("sudo",))
    except CommandError:
        return None
    return _listed(out) if code == 0 else None


class Granted(list):
    """What `grant` installed: its paths (the files, then the take-back helper), as a list, and `notes`, what it said
    of how it made the rule, in words (this system's visudo refused NOSETENV and EXEC: NOPASSWD alone)."""

    def __init__(self, paths=(), notes=()):
        super().__init__(paths)
        self.notes = list(notes)


def grant_paths(name: str) -> tuple[str, str, str]:
    """Where a grant for `name` lives: its helpers' folder, the take-back helper in it, and its sudoers rule."""
    name = _clean_name(name)
    return f"{LIBEXEC}/{name}", f"{LIBEXEC}/{name}/{TAKE_BACK}", f"{SUDOERS_D}/liminal-{name}"


def grant(shell: Shell, name: str, files: dict, *, password: str, group: str, why: str = "",
          timeout: float = TIMEOUT_S) -> Granted:
    """Make a narrow grant so that, from now on, the members of `group` run `files` through sudo without a password
    (DECISIONS 2026-11-17, addenda 9 and 10: the rules name the system group `liminal`, never a person; the group must
    exist already, and no member is added here). Each of `files` ({basename: a POSIX sh body}) is installed as its
    helper_text in the grant's folder (grant_paths), with a take-back helper so `revoke` needs no password, and a
    sudoers rule lets the group run exactly those, with no arguments: all by one script run once as root through
    `sudo -S` with `password` (_grant_script says what it checks and how the rule is made; ROOT_HEAD, how the
    password is kept from it). `why` (one printable line of at most 120 characters, no backslash) is said in the
    rule's comment. Returns the paths installed (the files, then the take-back helper) with the script's notes
    (`Granted`). Raises `PasswordRefused` when sudo turns the password down, or `CommandError` in the script's own
    words; a name, a file's name, a body, a group or a why it cannot take is refused before sudo is asked."""
    name = _clean_name(name)
    why = _clean_words(why, "a grant's why")
    group = _clean_principal(group)
    entries = [(_clean_basename(b), helper_text(name, t)) for b, t in sorted(files.items())]
    if any(b == TAKE_BACK for b, _ in entries):
        raise CommandError(f"{TAKE_BACK} is the name of the grant's own helper, not one of its files")
    folder, take_back = grant_paths(name)[:2]
    installed = [f"{folder}/{b}" for b, _ in entries] + [take_back]
    rules = [_sudoers_rule(name, group, installed, why, tags) for tags in (GRANT_TAGS, "NOPASSWD:")]
    script = _grant_script(name, entries + [(TAKE_BACK, _take_back_text(name))], group, *rules)
    out = shell.run("sh", "-c", script, password=password, timeout=timeout)
    return Granted(installed, [line.strip()[len("liminal: "):] for line in out.splitlines()
                               if line.strip().startswith("liminal: ")])


def revoke(shell: Shell, name: str, *, password: str | None = None, timeout: float = TIMEOUT_S) -> None:
    """Take a grant back: remove only Liminal's sudoers rule and helper folder for `name`, by the take-back helper the
    grant left (`sudo -n`: the grant allows it without a password); where it cannot run, by the same removal as root
    with `password` (_cleanup_script), and without one it raises."""
    name = _clean_name(name)
    try:
        shell.run(grant_paths(name)[1], timeout=timeout)
        return
    except CommandError:
        if password is None:
            raise
    shell.run("sh", "-c", _cleanup_script(name), password=password, timeout=timeout)


def granted(shell: Shell, name: str, files: dict) -> dict:
    """What a grant for `name` looks like now, read without root: for each of `files` whether it is installed,
    whether the installed text is the one `grant` would install for it (its helper_text: a member of the grant's
    group can read the files), and whether sudo runs it without a password
    (sudo's listing, read once for all of them: needs_password's way); the same for the take-back helper; a
    `missing` list in words; and `complete` when nothing is missing. The firewall compares its installed read
    script with its own copy at every read this way (B-revisions R: a mismatch is an older plugin's, or a helper
    from before helper_text, and the grant is offered again)."""
    name = _clean_name(name)
    folder, helper = grant_paths(name)[:2]
    out: dict = {"files": {}, "missing": []}
    wanted = {_clean_basename(b): helper_text(name, t) for b, t in files.items()}
    root = shell.root()
    listing = None if root else _sudo_listing(shell)

    def _nopasswd(path: str) -> bool:  # True as root; else the listing's rule for exactly `path`, no arguments
        return root or _runs_free(listing, (path,))

    for b in sorted(wanted):
        path = f"{folder}/{b}"
        have = _read(shell, path)
        matches = None if have is None else (have == wanted[b])
        nopw = _nopasswd(path)
        out["files"][b] = {"path": path, "installed": have is not None, "matches": matches, "nopasswd": nopw}
        if have is None:
            out["missing"].append(f"{path} is not installed")
        elif matches is False:
            out["missing"].append(f"{path} is not the text this plugin would install (an older plugin's)")
        if have is not None and not nopw:
            out["missing"].append(f"sudo still asks for a password to run {path}")
    out["take_back"] = {"path": helper, "installed": _read(shell, helper) is not None, "nopasswd": _nopasswd(helper)}
    out["complete"] = not out["missing"] and out["take_back"]["installed"]
    return out


def _read(shell: Shell, path: str) -> str | None:
    """The file's text, read without root (the helpers are readable by the process), or None when it cannot be
    read (missing, or not readable from here yet: a group membership takes effect only after a restart). On the
    Linux the platform runs on the process opens it itself, no `cat` started; through a runner (a test's) or in a
    WSL distribution, `cat` reads it. Either way its bytes are read as a command's output is (_text)."""
    if shell._runner is None and shell.target == "local" and shell.here:
        try:
            with open(path, "rb") as f:
                return _text(f.read())
        except OSError:
            return None
    code, text, _err = shell._exec([*shell.prefix(False), "cat", "--", path], TIMEOUT_S, None, ("cat",))
    return text if code == 0 else None


def _clean_name(name: str) -> str:
    """A grant's name, safe as a path component and a sudoers filename: lowercase letters, digits and hyphens."""
    name = (name or "").strip()
    if not name or len(name) > 64 or not all(c.islower() or c.isdigit() or c == "-" for c in name) or name[0] == "-":
        raise CommandError(f"a grant's name is lowercase letters, digits and hyphens, not {name!r}")
    return name


def _clean_basename(base: str) -> str:
    """A helper file's basename, safe as a path component: letters, digits, dot, underscore and hyphen, no slash."""
    base = (base or "").strip()
    ok = base and base not in (".", "..") and "/" not in base and len(base) <= 64
    if not ok or not all(c.isalnum() or c in "._-" for c in base) or base.startswith("-"):
        raise CommandError(f"a helper file's name is letters, digits, '.', '_' and '-', not {base!r}")
    return base


def _clean_principal(who: str) -> str:
    """A user or group name for a sudoers rule: letters, digits, underscore and hyphen (a trailing $ allowed)."""
    who = (who or "").strip()
    core = who[:-1] if who.endswith("$") else who
    if not core or len(who) > 64 or not all(c.isalnum() or c in "_-" for c in core) or core[0] == "-":
        raise CommandError(f"a sudoers principal is letters, digits, '_' and '-', not {who!r}")
    return who


def _clean_words(text: str, what: str) -> str:
    """Words that go into a file root reads (a sudoers rule's comment): one line of printable characters, no
    backslash, at most 120 of them, a last full stop left to the line they go in (linuxperm CRITIQUE S5: a line break
    would let them write a rule of their own). `what` names them in the refusal."""
    text = (text or "").strip()
    if len(text) > 120 or not text.isprintable() or "\\" in text:
        raise CommandError(f"{what} is one line of at most 120 printable characters and no backslash, not {text!r}")
    return text.rstrip(".")


def helper_text(name: str, body: str) -> str:
    """A helper's text as a grant installs it, the same for every helper of every grant (linuxperm PLAN 1.8):
    `#!/bin/sh`; a line naming its grant and saying it takes no arguments; ROOT_HEAD (standard input /dev/null, the
    fixed ROOT_PATH, LC_ALL=C, umask 077, `cd /`); a refusal of any argument; then `body`, a POSIX sh body (a
    `#!/bin/sh` line of its own is the head's; one for another interpreter is refused). sudo hands a helper the
    caller's PATH where sudoers sets no secure_path, so a helper never looks a tool up there. A text that is a
    helper's already is given back as it is, so a body is wrapped once; `granted` compares an installed helper with
    this text."""
    name = _clean_name(name)
    head = _helper_head(name)
    if body.startswith(head):
        return body
    if body.startswith("#!"):
        first, _, rest = body.partition("\n")
        if first.strip() != "#!/bin/sh":
            raise CommandError(f"a helper is a POSIX sh body, run by /bin/sh, not one for {first[2:].strip()!r}")
        body = rest
    return head + body + ("" if not body or body.endswith("\n") else "\n")


def _helper_head(name: str) -> str:
    return "".join(f"{line}\n" for line in (
        "#!/bin/sh", f"# Liminal's helper for the grant {name}: run as root by its sudoers rule, it takes no "
                     "arguments.",
        *ROOT_HEAD, 'if [ "$#" -ne 0 ]; then echo "liminal: this helper takes no arguments" >&2; exit 2; fi'))


def _sudoers_rule(name: str, group: str, paths: list[str], why: str = "", tags: str = GRANT_TAGS) -> str:
    """The grant's sudoers rule (grant_paths): the members of `group` may run exactly `paths`, each with no arguments
    (the `""`), as root, without a password, with no variable of the caller's set past env_reset, its tools free to
    run (GRANT_TAGS; `tags` "NOPASSWD:" alone where visudo refuses the others). Its comment says what the grant is
    for, in the caller's words (`why`, cleaned), and how to take it back. Never `NOPASSWD: ALL`."""
    commands = ", ".join(f'{p} ""' for p in paths)
    return (f"# Installed by the Liminal platform for {name}{f': {why}' if why else ''}. It lets the group {group} "
            "run these helpers as root without a password, with no arguments.\n"
            f"# Remove it with: sudo {grant_paths(name)[1]}\n"
            f"%{group} ALL=(root) {tags} {commands}\n")


def _removal(name: str) -> tuple[str, ...]:
    """What takes a grant back, as root: its sudoers rule, then its helpers' folder (grant_paths), nothing else."""
    folder, _helper, rule = grant_paths(name)
    return "set -eu", f"rm -f '{rule}'", f"rm -rf '{folder}'"


def _take_back_text(name: str) -> str:
    """The take-back helper's text (a helper_text): as root, remove Liminal's rule and helper folder for this name."""
    return helper_text(name, f"# Liminal's take-back for {name}: remove the sudoers rule and the helper folder.\n"
                             + "".join(f"{line}\n" for line in _removal(name)))


def _cleanup_script(name: str) -> str:
    """The script `revoke` runs as root with a password where the take-back helper cannot run: ROOT_HEAD, then the
    take-back's own removal."""
    return "".join(f"{line}\n" for line in (*ROOT_HEAD, *_removal(name)))


def _grant_script(name: str, entries: list, group: str, rule: str, plain: str) -> str:
    """The one fixed sh script a grant runs as root, the argument of `sh -c` (ROOT_HEAD first). It checks that the
    helper folder and its parents are owned by root, writable neither by others nor by a group other than root's
    (Debian's opt-in staff group makes /usr/local root:staff 2775, and a member of it could replace the helpers sudo
    runs as root: refused in linuxperm PLAN 1.12's words), and no symlink on the way; installs each helper from its
    base64 text (no quoting can break), root:<group> 0750 so only members run them; and installs the sudoers rule
    only after `visudo -cf` passes: `rule` (GRANT_TAGS), or `plain` (NOPASSWD alone) only where visudo refuses the
    tags, which it then says on its output. A symlink is looked for before a folder not there yet is passed over:
    `[ -e ]` follows a link, so one to nothing would seem missing and be passed over, refused only by a later
    install's own words. No password is ever in it."""
    dirp, _helper, rule_path = grant_paths(name)
    lines = [
        *ROOT_HEAD, "set -eu",
        f'for d in /usr /usr/local /usr/local/libexec {LIBEXEC} {dirp}; do',
        '  if [ -L "$d" ]; then echo "liminal: $d is a symlink" >&2; exit 5; fi',
        '  [ -e "$d" ] || continue',
        '  o=$(stat -c %u "$d" 2>/dev/null || echo -1); g=$(stat -c %g "$d" 2>/dev/null || echo -1)',
        '  p=$(stat -c %a "$d" 2>/dev/null || echo 777)',
        '  if [ "$o" != 0 ]; then echo "liminal: $d is not owned by root" >&2; exit 5; fi',
        '  case "$p" in *[2367]) echo "liminal: $d is writable by others" >&2; exit 5;; esac',
        '  case "$g:$p" in 0:*) ;; *:*[2367]?) n=$(stat -c %G "$d" 2>/dev/null || echo "$g")',
        '    w="$d is writable by the group $n: a member of it could replace Liminal\'s helpers, so none is installed"',
        '    if [ "$n" = staff ]; then w="$w (Debian\'s opt-in: remove /etc/staff-group-for-usr-local)"; fi',
        '    echo "liminal: $w; set it back to root:root 0755" >&2; exit 5;;',
        "  esac",
        "done",
        "[ -d /usr/local/libexec ] || install -d -o root -g root -m 0755 /usr/local/libexec",
        f"install -d -o root -g {group} -m 0750 {LIBEXEC}",
        f"install -d -o root -g {group} -m 0750 {dirp}",
    ]
    for base, text in entries:
        blob = base64.b64encode(text.encode("utf-8")).decode("ascii")
        path = f"{dirp}/{base}"
        lines += [f"rm -f '{path}'", f"printf %s '{blob}' | base64 -d > '{path}'",
                  f"chown root:{group} '{path}'", f"chmod 0750 '{path}'"]
    tagged, untagged = (base64.b64encode(r.encode("utf-8")).decode("ascii") for r in (rule, plain))
    lines += [
        "t=$(mktemp)", f"printf %s '{tagged}' | base64 -d > \"$t\"", 'chmod 0440 "$t"',
        'if visudo -cf "$t" >/dev/null 2>&1; then said=""',
        "else",
        ("  said=\"liminal: this system's visudo refused NOSETENV and EXEC in the rule: the rule was made with "
         "NOPASSWD alone\""),
        f"  printf %s '{untagged}' | base64 -d > \"$t\"; chmod 0440 \"$t\"",
        '  if ! visudo -cf "$t"; then rm -f "$t"; echo "liminal: the sudoers rule did not pass visudo" >&2; exit 6; fi',
        "fi",
        f'install -o root -g root -m 0440 "$t" \'{rule_path}\'; rm -f "$t"',
        'if [ -n "$said" ]; then echo "$said"; fi', "echo liminal-granted",
    ]
    return "\n".join(lines) + "\n"


def _text(raw) -> str:
    """A command's output: UTF-8, or UTF-16 for wsl's own messages (NULs between the letters)."""
    if isinstance(raw, str):
        return raw
    raw = raw or b""
    return raw.decode("utf-16-le", "ignore") if b"\x00" in raw else raw.decode("utf-8", "replace")


def _no_window() -> dict:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}
