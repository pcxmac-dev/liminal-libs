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
import posixpath
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass

from .. import proctree
from .plugin import LIMINAL_PREFIX, CommandError, liminal_scoped
from .terminal import inherited  # a child's environment: no LIMINAL_* name (the review of 2026-11-21, item 26)

TIMEOUT_S = 120.0
FOUND_S = 30.0  # the WSL distributions listed are kept this long
PREFERRED = ("Ubuntu", "Fedora", "Gentoo")  # Liminal's distributions in the order a target takes them
_found: tuple[float, list[str]] | None = None
DENIED = ("a password is required", "a terminal is required", "permission denied", "must be root", "are you root",
          "operation not permitted", "need to be root", "you need root")
# sudo -S said the password was wrong, empty or missing (its own words; a refused read, not a policy failure)
PASSWORD_REFUSED = ("incorrect password", "sorry, try again", "no password was provided", "1 incorrect password")
# Liminal's root-owned helpers and the sudoers drop-in a grant writes (DECISIONS 2026-11-17, addenda 9 and 10)
LIBEXEC = "/usr/local/libexec/liminal"
SUDOERS_D = "/etc/sudoers.d"
TAKE_BACK = "take-back"  # the helper a grant writes so a later revoke needs no password
# The PATH every script and helper Liminal runs as root sets for itself, root's own folders alone: sudo's secure_path
# differs from one system to another or is not set at all (Slackware's template, sudo-rs without one), and then the
# caller's PATH reaches the command; WSL appends Windows' folders to it (linuxperm PLAN 1.1)
ROOT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin"
# What every script run as root begins with: its standard input /dev/null (nothing it runs reads a password sudo did
# not take), that PATH, its tools' words in English, files of root's alone, and no folder of the caller's
ROOT_HEAD = ("exec </dev/null", f"PATH={ROOT_PATH}; export PATH", "LC_ALL=C; export LC_ALL", "umask 077",
             "cd / || exit 1")
# A grant's rule: no password; no variable of the caller's set for its helpers past env_reset (a site's `Defaults
# setenv` would pass LD_PRELOAD); its helpers free to run their tools (a site's `Defaults noexec`). sudoers(5)
GRANT_TAGS = "NOPASSWD:NOSETENV:EXEC:"
PASSWORD_MAX = 512  # bytes: PAM refuses a response this long (PAM_MAX_RESP_SIZE); sudo reads one up to a line end
# sudo's listing of what this user may run here (`sudo -l`: it runs nothing), in English whatever the user's language
# (sudo translates its words); needs_password and granted read it for the rule that decides a command
SUDO_LIST = ("env", "LC_ALL=C", "sudo", "-n", "-l")


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
    """The text with the password taken out of it, so it never reaches a log, an answer or an error's words."""
    return text.replace(secret, "***") if secret else text


def _check_password(password: str) -> None:
    """Refuse, before sudo is asked, a password it could not read as one line on its standard input: one holding a
    line break (sudo reads up to it, and the rest would be read as another try or reach the command) or a NUL, one of
    PASSWORD_MAX bytes or more (PAM refuses it), or one that is no UTF-8 text (linuxperm PLAN 1.7 step 1)."""
    try:
        size = len(password.encode("utf-8"))
    except UnicodeEncodeError:
        size = PASSWORD_MAX
    if size >= PASSWORD_MAX or any(c in password for c in "\r\n\x00"):
        raise PasswordRefused(f"a password with a line break or a NUL in it, or of {PASSWORD_MAX} bytes or more, "
                              "cannot be handed to sudo: nothing was run")


def _on_windows() -> bool:
    return os.name == "nt"


def why_not_native(what: str, system: str | None = None, release: str | None = None, env=None) -> str:
    """Why the machine the platform runs on is not one the Linux plugins work on, in words naming `what` (Linux
    administration, the Linux firewall): "" on Linux, any Linux: a machine of its own, or a WSL distribution the
    platform runs inside (1.57.0; what WSL lacks or changes is said by the plugin: wsl_table). Windows and macOS are
    not Linux: a platform there does not reach into a WSL distribution from outside. `system`, `release` and `env`
    stand in for sys.platform, the kernel's release and the environment in tests (the last two are no longer read).
    The name is from when a WSL kernel was refused too."""
    system = sys.platform if system is None else system
    if not system.startswith("linux"):
        name = {"win32": "Windows", "cygwin": "Windows", "darwin": "macOS"}.get(system, system)
        return (f"{what} is for the Linux the platform runs on, and this one runs {name}"
                + ("; Liminal's WSL distributions are the WSL plugins'" if name == "Windows" else ""))
    return ""


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
        conversation of linuxperm PLAN 1.7, not built yet. As root, or for a WSL target (always root through
        `wsl -u root`), `password` is ignored."""
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
            words = _scrub(err.strip() or out.strip() or f"{command[0]} failed ({code}) on {self.where}",
                           password if use_password else None)
            last = words.splitlines()[-1].strip()
            low = words.lower()
            if use_password and any(m in low for m in PASSWORD_REFUSED):
                raise PasswordRefused()
            denied = any(d in low for d in DENIED)
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


@dataclass(frozen=True)
class _Listed:
    """One command of sudo's listing: whether its rule runs it as root ("yes", "no", or "maybe": a negation, a group's
    members), without a password (NOPASSWD), whether it is refused (`!`), the command (None: ALL) and its arguments as
    sudoers keeps them (None: any; '""': none at all). `pattern`: the command is a pattern or a folder, its name not
    to be compared; `args_pattern`: so are its arguments; `unsure`: what it takes in is not told by the listing (a
    digest, a time window, a chroot)."""

    root: str
    nopasswd: bool
    negated: bool
    command: str | None
    args: str | None
    pattern: bool = False
    args_pattern: bool = False
    unsure: bool = False


_LISTED = re.compile(r"User \S+ may run the following commands on \S+:")  # the listing's head, sudo's C words
_TAG = re.compile(r"[A-Z_]+: ")  # NOPASSWD:, PASSWD:, SETENV:, NOEXEC:, LOG_OUTPUT:, ... ahead of a command
_OPTION = re.compile(r'[A-Z_]+=(?:"[^"]*"|\S+) ')  # ROLE=, TYPE=, TIMEOUT=, CWD=, CHROOT=, NOTBEFORE=, ...
_UNSURE = ("NOTBEFORE=", "NOTAFTER=", "CHROOT=")  # a rule that may not hold now, or runs another tree's command
_DIGEST = re.compile(r"(?:sha224|sha256|sha384|sha512):\S*")
_PLAIN_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\$?|#[0-9]+")
_GLOB = frozenset("*?[")
_VERBS = ("sudoedit", "list")  # what sudoers names in a command's place that is no program's path


def _sudo_listing(shell: Shell) -> list[_Listed] | None:
    """sudo's listing of what this user may run here (SUDO_LIST), as its commands in sudoers' order; None when sudo
    will not list them without a password (no rule without one applies: sudoers' listpw), could not be asked, or
    answered with something else than its listing."""
    try:
        code, out, _err = shell._exec(list(SUDO_LIST), TIMEOUT_S, None, ("sudo",))
    except CommandError:
        return None
    return _listed(out) if code == 0 else None


def _listed(text: str) -> list[_Listed] | None:
    """The commands of sudo's listing (`sudo -l`, its short form: sudo(8), sudoers(5)), or None when `text` is not
    one. After its head every line is `    (<runas users>[ : <runas groups>]) <commands>`: the commands separated
    by commas (a comma of a command's own escaped `\\,`), each after the tags that hold from it to the line's end; a
    line sudo wrapped at a terminal's width goes on indented further. Anything else is not read as a listing."""
    lines = text.splitlines()
    head = next((i for i, line in enumerate(lines) if _LISTED.fullmatch(line.strip())), None)
    if head is None:
        return None
    rows: list[str] = []
    for line in lines[head + 1:]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 4 and line[4] == "(":
            rows.append(line.strip())
        elif indent > 4 and rows:
            rows[-1] += " " + line.strip()
        else:
            return None
    out: list[_Listed] = []
    for row in rows:
        close = row.find(")")
        if close < 0:
            return None
        users = [u.strip() for u in row[1:close].split(" : ", 1)[0].split(",")]
        out += _commands(_runs_as_root(users), row[close + 1:])
    return out


def _runs_as_root(users: list[str]) -> str:
    """Whether a rule's runas users take in root: "yes" (ALL, root, #0), "no" (users named, root not among them), or
    "maybe" (a negation, a group's members, a netgroup: what the listing does not settle)."""
    if any(u.startswith("!") for u in users):
        return "maybe"
    if any(u in ("ALL", "root", "#0") for u in users):
        return "yes"
    return "no" if all(_PLAIN_USER.fullmatch(u) for u in users) else "maybe"


def _commands(root: str, text: str) -> list[_Listed]:
    """A listing line's commands, its tags and options carried from each command to the next as sudo prints them."""
    out: list[_Listed] = []
    nopasswd = unsure = False
    for item in _split(text):
        while True:
            tag = _TAG.match(item)
            option = None if tag else _OPTION.match(item)
            if tag:
                nopasswd = {"NOPASSWD": True, "PASSWD": False}.get(tag.group()[:-2], nopasswd)
                item = item[tag.end():]
            elif option:
                unsure = unsure or option.group().startswith(_UNSURE)
                item = item[option.end():]
            else:
                break
        out.append(_command(item, root, nopasswd, unsure))
    return out


def _command(item: str, root: str, nopasswd: bool, unsure: bool) -> _Listed:
    """A command as the listing prints it: its digests if any, `!` if refused, then ALL, or a path (sudo escapes its
    spaces, tabs, `:`, `,`, `=` and `#`) and its arguments (their `:`, `,`, `=` and `#`; `""`: none allowed)."""
    while (digest := _DIGEST.match(item)) is not None:  # known by its digest too: whether the file here is it, untold
        unsure, item = True, item[digest.end():].lstrip()
    negated = item.startswith("!")
    item = item[1:] if negated else item
    if item == "ALL":
        return _Listed(root, nopasswd, negated, None, None, unsure=unsure)
    raw, raw_args = _split_word(item)
    path, odd = _unescape(raw, ":,= \t#")
    args, odd_args = _unescape(raw_args, ":,=#") if raw_args is not None else (None, False)
    named = path.startswith("/") or path in _VERBS  # a command's own path (a regular expression begins with ^)
    pattern = odd or not named or path.endswith("/") or bool(_GLOB & set(path))
    args_pattern = args is not None and args != '""' and (odd_args or args.startswith("^") or bool(_GLOB & set(args)))
    return _Listed(root, nopasswd, negated, path, args, pattern, args_pattern, unsure)


def _split(text: str) -> list[str]:
    """`text` split at each comma sudo did not escape."""
    out: list[str] = []
    word, i = "", 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            word, i = word + text[i:i + 2], i + 2
        elif text[i] == ",":
            out, word, i = [*out, word.strip()], "", i + 1
        else:
            word, i = word + text[i], i + 1
    return [*out, word.strip()]


def _split_word(text: str) -> tuple[str, str | None]:
    """A listed command's path and its arguments (None when it names none), split at the first space or tab sudo did
    not escape."""
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
        elif text[i] in " \t":
            return text[:i], text[i + 1:].strip() or None
        else:
            i += 1
    return text, None


def _unescape(text: str, quoted: str) -> tuple[str, bool]:
    """The listing's text with sudo's backslash before each of `quoted` taken out, and whether a backslash before
    anything else is left (sudoers keeps one before a pattern's character: what it matches is no plain text)."""
    out, odd, i = "", False, 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text) and text[i + 1] in quoted:
            out, i = out + text[i + 1], i + 2
        else:
            out, odd, i = out + text[i], odd or text[i] == "\\", i + 1
    return out, odd


def _matches(listed: _Listed, command: tuple[str, ...]) -> str:
    """Whether a listed command takes in `command` as sudo matches them: "yes", "no", or "maybe" (a pattern, a command
    named without its folder or by another folder of the same name, what the listing does not tell). sudo compares a
    command's name first, then its folder; arguments named must be the same words, `""` none at all."""
    if listed.command is None:
        return "maybe" if listed.unsure else "yes"
    if listed.command in _VERBS:
        return "no"  # sudo's own verbs: no command of a plugin's
    name, given = command[0], " ".join(command[1:])
    if not listed.pattern and posixpath.basename(listed.command) != posixpath.basename(name):
        return "no"
    if listed.args == '""' and given:
        return "no"  # no arguments allowed, and there are some
    if listed.args not in (None, '""') and not listed.args_pattern and listed.args != given:
        return "no"
    sure = not (listed.pattern or listed.args_pattern or listed.unsure) and listed.command == name
    return "yes" if sure else "maybe"


def _runs_free(listing: list[_Listed] | None, command: tuple[str, ...]) -> bool:
    """Whether sudo's listing shows `command` run as root without a password. Where several rules match a command, the
    last one decides (sudoers(5)), so this holds only when a rule that surely takes the command in runs it as root
    with NOPASSWD, not refused, and no rule after it that may take it in asks for a password or refuses it; False
    whenever that cannot be shown (no listing, no command)."""
    if not listing or not command:
        return False
    free = False
    for listed in listing:
        took = "no" if listed.root == "no" else _matches(listed, command)
        if took == "no":
            continue
        asks_none = listed.nopasswd and not listed.negated
        if took == "yes" and listed.root == "yes":
            free = asks_none
        elif not asks_none:
            free = False
    return free


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
