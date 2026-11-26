"""What Liminal's Linux code shares, plain: the standard library and nothing else of the library's.

`linuxsys` is the package Liminal's root command runs from (`python -I -B -m liminal_libs.linuxsys`), so nothing in it
may load the plugin contract, an app's frame or the process ledger: a module under `machines/` loads all three before
its own first line (machines/__init__.py imports the plugin base, which imports `sources/` and `apps/`). So what the
machine plugins' `machines/linux.py` and this package both need lives here, and linux.py imports it back under the
names it had there (1.102.0): sudo's words, the PATH and the head of every script run as root, a grant's tags, the
password's check, the scrub, why a machine is no Linux, and the reader of sudo's listing.

New with it: sudo-rs's words beside classic sudo's (Ubuntu 25.10 and later run sudo-rs as `sudo`; read from its
0.2.15 source, Ubuntu 26.04 has 0.2.13), a scrub that replaces the whole text, and the one cleaner for every word
that goes from outside a plan's fixed text into a file root writes or a script root runs (`clean_words`,
`clean_user`, `sh_word`).
"""
from __future__ import annotations

import posixpath
import re
import sys
from dataclasses import dataclass

# What a command says when it needed root and was not given it. "interactive authentication is required" is sudo-rs's
# for `sudo -n` where a password would be asked (classic sudo: "a password is required")
DENIED = ("a password is required", "a terminal is required", "permission denied", "must be root", "are you root",
          "operation not permitted", "need to be root", "you need root", "interactive authentication is required")
# sudo -S said the password was wrong, empty or missing (its own words; a refused read, not a policy failure). Classic
# sudo's, then sudo-rs's: "Authentication failed, try again.", "Authentication required but not attempted" (nothing to
# read), "maximum 3 incorrect authentication attempts"
PASSWORD_REFUSED = ("incorrect password", "sorry, try again", "no password was provided", "1 incorrect password",
                    "authentication failed, try again", "authentication required but not attempted",
                    "incorrect authentication attempt")
# What sudo says between two tries of a password: the one before it was wrong (classic sudo's, sudo-rs's)
SUDO_RETRY = ("sorry, try again", "authentication failed, try again")
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
# What takes the place of a text the password was found in
SCRUBBED = "what was said held the password that was typed, so it is not shown"
WORDS_MAX = 120  # characters of one cleaned text
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


class Refused(ValueError):
    """A refusal in words: nothing was done, and the words say why and what to do instead. `accept` names the
    argument that accepts it where asking once more is enough (a second confirmation), else it is ""."""

    def __init__(self, words: str, accept: str = ""):
        super().__init__(words)
        self.accept = accept


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


def password_problem(password: str) -> str:
    """Why sudo could not read `password` as one line on its standard input, in words, or "": one holding a line
    break (sudo reads up to it, and the rest would be read as another try or reach the command) or a NUL, one of
    PASSWORD_MAX bytes or more (PAM refuses it), or one that is no UTF-8 text. Asked before sudo is."""
    try:
        size = len(password.encode("utf-8"))
    except UnicodeEncodeError:
        size = PASSWORD_MAX
    if size >= PASSWORD_MAX or any(c in password for c in "\r\n\x00"):
        return (f"a password with a line break or a NUL in it, or of {PASSWORD_MAX} bytes or more, "
                "cannot be handed to sudo: nothing was run")
    return ""


def scrub(text: str, secret: str | None) -> str:
    """`text`, or SCRUBBED in its place when the password is anywhere in it. The whole text is replaced: stars where
    the password stood would tell where it was and how long it is, and a short password is then all but told (the
    linuxperm critique's M6). So a password never reaches a log, an answer or an error's words, in part either."""
    return SCRUBBED if secret and secret in text else text


def clean_words(text: str, what: str) -> str:
    """Words from outside a plan's own fixed text (a path found, a name read from the system), checked before they go
    into a file root writes or a script root runs: one line of at most WORDS_MAX printable characters, with no
    backslash and no quote of any kind (', ", `), so no file format and no single-quoted sh word can be broken out of
    (the linuxperm critique's S5). A `%` or a `$` is let through: Liminal's files are written by `printf '%s'` and its
    script words are single-quoted, where both are plain text. `what` names the words in the refusal."""
    text = "" if text is None else str(text)
    if not text or len(text) > WORDS_MAX or not text.isprintable() or any(c in text for c in "\\'\"`"):
        raise Refused(f"{what} is one line of 1 to {WORDS_MAX} printable characters with no backslash and no quote, "
                      f"not {text[:WORDS_MAX]!r}: nothing was changed")
    return text


def clean_user(name: str) -> str:
    """A user's or a group's name as Liminal takes one: a lowercase letter or an underscore, then lowercase letters,
    digits, underscores and hyphens, 32 characters at most (shadow's own rule for a new name). A name of another shape
    is refused in words, never quoted into a script."""
    name = "" if name is None else str(name)
    if not _USER.fullmatch(name):
        raise Refused(f"a user's name here is a lowercase letter or an underscore, then lowercase letters, digits, "
                      f"underscores and hyphens, 32 characters at most, not {name[:WORDS_MAX]!r}: nothing was changed")
    return name


def sh_word(text: str, what: str = "a word of a script") -> str:
    """`text` as one single-quoted POSIX sh word, after clean_words: nothing in it is the shell's to read."""
    return f"'{clean_words(text, what)}'"


@dataclass(frozen=True)
class Listed:
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


def listed(text: str) -> list[Listed] | None:
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
    out: list[Listed] = []
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


def _commands(root: str, text: str) -> list[Listed]:
    """A listing line's commands, its tags and options carried from each command to the next as sudo prints them."""
    out: list[Listed] = []
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


def _command(item: str, root: str, nopasswd: bool, unsure: bool) -> Listed:
    """A command as the listing prints it: its digests if any, `!` if refused, then ALL, or a path (sudo escapes its
    spaces, tabs, `:`, `,`, `=` and `#`) and its arguments (their `:`, `,`, `=` and `#`; `""`: none allowed)."""
    while (digest := _DIGEST.match(item)) is not None:  # known by its digest too: whether the file here is it, untold
        unsure, item = True, item[digest.end():].lstrip()
    negated = item.startswith("!")
    item = item[1:] if negated else item
    if item == "ALL":
        return Listed(root, nopasswd, negated, None, None, unsure=unsure)
    raw, raw_args = _split_word(item)
    path, odd = _unescape(raw, ":,= \t#")
    args, odd_args = _unescape(raw_args, ":,=#") if raw_args is not None else (None, False)
    named = path.startswith("/") or path in _VERBS  # a command's own path (a regular expression begins with ^)
    pattern = odd or not named or path.endswith("/") or bool(_GLOB & set(path))
    args_pattern = args is not None and args != '""' and (odd_args or args.startswith("^") or bool(_GLOB & set(args)))
    return Listed(root, nopasswd, negated, path, args, pattern, args_pattern, unsure)


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


def matches(listed: Listed, command: tuple[str, ...]) -> str:
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


def runs_free(listing: list[Listed] | None, command: tuple[str, ...]) -> bool:
    """Whether sudo's listing shows `command` run as root without a password. Where several rules match a command, the
    last one decides (sudoers(5)), so this holds only when a rule that surely takes the command in runs it as root
    with NOPASSWD, not refused, and no rule after it that may take it in asks for a password or refuses it; False
    whenever that cannot be shown (no listing, no command)."""
    if not listing or not command:
        return False
    free = False
    for listed in listing:
        took = "no" if listed.root == "no" else matches(listed, command)
        if took == "no":
            continue
        asks_none = listed.nopasswd and not listed.negated
        if took == "yes" and listed.root == "yes":
            free = asks_none
        elif not asks_none:
            free = False
    return free
