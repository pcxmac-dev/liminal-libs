"""The Linux plugins handling the rights they need (the user, 2026-11-17: "the plugin needs to be able to handle
permissions if required", "A field on its page"; DECISIONS 2026-11-16 addenda 9 and 10, B-revisions "R: rights").

A password typed on the plugin's page is handed to `sudo -S` on standard input for one action only; it is never in
an argument, the environment, a log, the answer or an error's words. A plugin can make a narrow grant so its own
read runs without a password after that, and take it back without one. Whether sudo needs a password for a command
is read from sudo's listing, for the rule that decides it. Nothing runs: a stand-in runner records every argv, the
standard input it is fed, and (by never being handed one) that no environment carries the password.
"""
from __future__ import annotations

import base64
import fnmatch
import re

import pytest

from liminal_libs.linuxsys.shared import SCRUBBED
from liminal_libs.machines import linux
from liminal_libs.machines.linux import (
    LIBEXEC, SUDO_LIST, SUDOERS_D, TAKE_BACK, CommandError, PasswordRefused, Shell, grant, granted, needs_password,
    revoke,
)

# Every test here runs entirely through stand-in runners; the shared guard fails any that reaches a real
# process, socket or name resolution (it raises a BaseException no `except Exception` can swallow).
pytestmark = pytest.mark.usefixtures("no_outside")

PW = "hunter2-the-secret"  # a stand-in password; it must never appear in an argv, an env, a log or an error


class Recorder:
    """A stand-in runner that records every call's argv and the standard input it was fed (its third argument), and
    answers from `replies` (a list of (match, (code, out, err)); the first whose words are a prefix of the argv
    after any `sudo -n`/`sudo -S ... --` wins) or 0/empty by default."""

    def __init__(self, replies=None):
        self.calls: list[tuple[list[str], str | None]] = []
        self.replies = list(replies or [])

    def __call__(self, args, timeout, stdin=None):
        self.calls.append((list(args), stdin))
        bare = _bare(args)
        for match, reply in self.replies:
            if tuple(bare[:len(match)]) == tuple(match):
                return reply
        return 0, b"", b""

    @property
    def argv(self) -> list[list[str]]:
        return [a for a, _ in self.calls]

    @property
    def stdins(self) -> list[str | None]:
        return [s for _, s in self.calls]


def _bare(args) -> list[str]:
    """The command without its sudo prefix, for matching: `sudo -n ...`, `sudo -n -l -- ...`, `sudo -S -k -p "" --`."""
    a = list(args)
    if a[:3] == ["sudo", "-n", "--"]:  # Shell.prefix's, with -- since 1.80.0
        a = a[3:]
    elif a[:2] == ["sudo", "-n"]:
        a = a[2:]
        if a[:2] == ["-l", "--"]:
            a = a[2:]
    elif a[:1] == ["sudo"]:
        if "--" in a:
            a = a[a.index("--") + 1:]
    return a


def not_root(monkeypatch):
    monkeypatch.setattr(linux.os, "geteuid", lambda: 1000, raising=False)


def as_root(monkeypatch):
    monkeypatch.setattr(linux.os, "geteuid", lambda: 0, raising=False)


# --- Shell.run with a password -------------------------------------------------------------------------------------

def test_a_password_is_handed_to_sudo_on_standard_input_and_never_in_an_argument(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder()
    out = Shell("local", runner=rec).run("nft", "list", "ruleset", password=PW)
    assert out == ""
    argv, stdin = rec.calls[-1]
    # sudo -S -k -p "" -- : reads the password from stdin, resets any cached one, no prompt, then the command
    assert argv == ["sudo", "-S", "-k", "-p", "", "--", "nft", "list", "ruleset"]
    # the password is standard input's one line, nothing after it (a wrong one is one try, never more read)
    assert stdin == f"{PW}\n"
    # and it is nowhere in the argument vector
    assert not any(PW in part for part in argv)


def test_the_runner_is_never_handed_an_environment_so_the_password_cannot_leak_through_one(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder()
    Shell("local", runner=rec).run("sh", "-c", "echo hi", password=PW)
    # the runner is called with (args, timeout, stdin) only: no environment is built or passed, so none carries it
    assert rec.calls and all(PW not in str(a) for a in rec.argv)


def test_as_root_the_password_is_ignored_and_no_sudo_is_used(monkeypatch):
    as_root(monkeypatch)
    rec = Recorder()
    Shell("local", runner=rec).run("ufw", "status", password=PW)
    argv, stdin = rec.calls[-1]
    assert argv == ["ufw", "status"] and stdin is None  # already root: no sudo, no password on stdin


def test_a_wsl_target_is_left_exactly_as_it_is_the_password_ignored(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder()
    Shell("wsl:Ubuntu", runner=rec).run("nft", "list", "ruleset", password=PW)
    argv, stdin = rec.calls[-1]
    assert argv == ["wsl", "-d", "Ubuntu", "-u", "root", "--exec", "nft", "list", "ruleset"] and stdin is None


def test_without_a_password_the_reading_is_sudo_n_as_before(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder()
    Shell("local", runner=rec).run("nft", "list", "ruleset")
    assert rec.argv[-1] == ["sudo", "-n", "--", "nft", "list", "ruleset"] and rec.stdins[-1] is None


def test_a_refused_password_is_its_own_error_and_says_so(monkeypatch):
    not_root(monkeypatch)
    for words in (b"Sorry, try again.\nsudo: 1 incorrect password attempt",
                  b"sudo: no password was provided", b"sudo: 3 incorrect password attempts",
                  # sudo-rs's (Ubuntu 25.10 and later run it as sudo): a wrong one, none to read, three wrong
                  b"sudo: Authentication failed, try again.", b"sudo: Authentication required but not attempted",
                  b"sudo: maximum 3 incorrect authentication attempts"):
        rec = Recorder([(["id"], (1, b"", words))])
        with pytest.raises(PasswordRefused) as e:
            Shell("local", runner=rec).run("id", password=PW)
        assert str(e.value) == "sudo did not accept the password" and not e.value.denied


def test_a_password_that_is_a_word_of_sudo_s_refusal_is_still_refused(monkeypatch):
    # sudo's words are told apart before the scrub: a password such as "pass", "try" or "sorry" is in them, so the
    # whole text is scrubbed, and the refusal must still be known as one (the form offered again)
    not_root(monkeypatch)
    refusal = b"Sorry, try again.\nsudo: no password was provided\nsudo: 1 incorrect password attempt"
    for pw in ("pass", "try", "sorry", "again"):
        rec = Recorder([(["id"], (1, b"", refusal))])
        with pytest.raises(PasswordRefused) as e:
            Shell("local", runner=rec).run("id", password=pw)
        assert str(e.value) == "sudo did not accept the password"


def test_the_password_is_scrubbed_from_an_error_s_words(monkeypatch):
    not_root(monkeypatch)
    # a command that fails and (however unlikely) echoes the password: it must not reach the raised words
    rec = Recorder([(["sh"], (2, b"", f"boom {PW} boom".encode()))])
    with pytest.raises(CommandError) as e:
        Shell("local", runner=rec).run("sh", "-c", "false", password=PW)
    # the whole text goes (1.101.0): stars in the password's place would tell where it stood and how long it is
    assert str(e.value) == SCRUBBED and PW not in str(e.value) and "boom" not in str(e.value)
    assert not isinstance(e.value, PasswordRefused)
    # a text the password is not in is said as it is
    rec = Recorder([(["sh"], (2, b"", b"boom"))])
    with pytest.raises(CommandError) as e:
        Shell("local", runner=rec).run("sh", "-c", "false", password=PW)
    assert str(e.value) == "boom"


def test_sudo_rs_s_refusal_without_a_password_is_a_denial(monkeypatch):
    """sudo-rs says "interactive authentication is required" where classic sudo says "a password is required":
    both mean the command needed root and sudo would have asked."""
    not_root(monkeypatch)
    for words in (b"sudo: a password is required", b"sudo: interactive authentication is required"):
        rec = Recorder([(["nft"], (1, b"", words))])
        with pytest.raises(CommandError) as e:
            Shell("local", runner=rec).run("nft", "list", "ruleset")
        assert e.value.denied and "needs root on this machine" in str(e.value)


def test_an_old_two_argument_runner_still_works_and_never_sees_the_stdin(monkeypatch):
    not_root(monkeypatch)
    seen: list = []
    sh = Shell("local", runner=lambda args, timeout: seen.append(list(args)) or (0, b"ok\n", b""))
    assert sh.run("id", root=False) == "ok\n" and seen[-1] == ["id"]
    # a password with a two-argument runner: the argv still carries no password (it would be on stdin, unseen here)
    sh.run("nft", "list", "ruleset", password=PW)
    assert all(PW not in str(part) for part in seen[-1])


# --- needs_password: sudo's listing, read for the rule that decides a command ---------------------------------------

READ = f"{LIBEXEC}/firewall-linux/read"
HELPER = f"{LIBEXEC}/firewall-linux/{TAKE_BACK}"
# What `sudo -n -l` answers, as (exit code, output, errors). NONE was recorded in the user's Ubuntu 24.04 (sudo
# 1.9.15p5) on 2026-11-17: no rule without a password applies to the user there, so sudo will not even list. The others
# are written as that sudo prints its listing (`sudo -l`'s short form; its quoting as sudo 1.9.15's fmtsudoers.c has
# it): there is no such rule there to record them from.
NONE = (1, b"", b"sudo: a password is required\n")
DEFAULTS = ("Matching Defaults entries for sysop on liminal-test:\n"
            "    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin"
            "\\:/bin\\:/snap/bin, use_pty\n\n")
HEAD = "User sysop may run the following commands on liminal-test:\n"
OWN_ALL = "(ALL : ALL) ALL"  # Ubuntu's rule for the group sudo: everything, a password asked
GRANT = f'(root) NOPASSWD: {READ} "", {HELPER} ""'  # the grant's %liminal rule, once the platform has the group


def listing(*rules: str, defaults: str = DEFAULTS) -> tuple[int, bytes, bytes]:
    """sudo's answer to `sudo -n -l` listing `rules` (each a line of it: `(<runas>) <commands>`), in their order."""
    return 0, (defaults + HEAD + "".join(f"    {r}\n" for r in rules)).encode(), b""


class Sudo:
    """A stand-in for sudo answering as sudo 1.9.15 does: `sudo -n -l` (SUDO_LIST) with `answer`; and what the exit
    code the library read before (`sudo -n -l -- <command>`) says: 0 whenever the listing may be read and any rule
    allows the command at all (listpw `any`), a password asked or not. Every argv it is given is kept in `asked`."""

    def __init__(self, answer):
        self.answer, self.asked = answer, []

    def __call__(self, args, timeout, stdin=None):
        self.asked.append(list(args))
        code, out, err = self.answer
        if list(args) == list(SUDO_LIST):
            return code, out, err
        if args[:4] == ["sudo", "-n", "-l", "--"]:
            if code != 0:
                return code, out, err
            text = out.decode()
            allowed = ") ALL\n" in text or "NOPASSWD: ALL" in text or f" {args[4]}" in text
            return (0, f"{args[4]}\n".encode(), b"") if allowed else (1, b"", b"")
        return 0, b"", b""


def test_needs_password_reads_sudos_listing_and_runs_nothing(monkeypatch):
    not_root(monkeypatch)
    sudo = Sudo(listing(OWN_ALL, GRANT))
    assert needs_password(Shell("local", runner=sudo), READ) is False
    # one listing (-l: it runs nothing), its words in English whatever the user's language (sudo translates them)
    assert sudo.asked == [["env", "LC_ALL=C", "sudo", "-n", "-l"]]


def test_where_sudo_will_not_even_list_without_a_password_one_is_needed(monkeypatch):
    not_root(monkeypatch)
    sh = Shell("local", runner=Sudo(NONE))  # the user's Ubuntu today, as recorded
    assert needs_password(sh, READ) is True and needs_password(sh, "nft", "list", "ruleset") is True


def test_the_grants_rule_lets_its_two_files_alone_run_without_a_password(monkeypatch):
    """The review of 2026-11-17: with the grant's rule in force sudo lists without a password (listpw `any`), so the
    exit code of `sudo -n -l <command>` was 0 for every command the user's own ALL rule allows, which asks for one."""
    not_root(monkeypatch)
    sh = Shell("local", runner=Sudo(listing(OWN_ALL, GRANT)))
    assert needs_password(sh, READ) is False and needs_password(sh, HELPER) is False
    assert needs_password(sh, READ, "--anything") is True  # "": the rule allows them with no arguments alone
    for command in (("nft", "list", "ruleset"), ("/usr/sbin/nft", "-f", "-"), ("sh", "-s"), ("/usr/bin/id",)):
        assert needs_password(sh, *command) is True, command  # the user's own rule decides them, and it asks


def test_a_nopasswd_all_rule_runs_everything_without_a_password(monkeypatch):
    not_root(monkeypatch)
    sh = Shell("local", runner=Sudo(listing(OWN_ALL, "(root) NOPASSWD: ALL")))
    for command in ((READ,), ("nft", "list", "ruleset"), ("sh", "-s"), ("env", "LC_ALL=C", "apt-get", "install")):
        assert needs_password(sh, *command) is False, command


def test_an_all_rule_that_asks_needs_a_password_for_everything(monkeypatch):
    not_root(monkeypatch)
    # listed without a password only because listpw says never: the rule itself asks for one
    asks = listing(OWN_ALL, defaults=DEFAULTS.replace(", use_pty", ", use_pty, listpw=never"))
    sh = Shell("local", runner=Sudo(asks))
    assert needs_password(sh, READ) is True and needs_password(sh, "nft", "list", "ruleset") is True


def test_the_last_rule_that_matches_decides(monkeypatch):
    not_root(monkeypatch)
    # a rule that asks, read after the grant's (an include folder read before the user's own rules): it decides
    assert needs_password(Shell("local", runner=Sudo(listing(GRANT, OWN_ALL))), READ) is True
    # a tag holds for the commands after it on its line, until another is said
    sh = Shell("local", runner=Sudo(listing("(root) NOPASSWD: /usr/bin/id, /usr/bin/uptime, PASSWD: /usr/bin/who")))
    assert needs_password(sh, "/usr/bin/id") is False and needs_password(sh, "/usr/bin/uptime") is False
    assert needs_password(sh, "/usr/bin/who") is True
    # refused after ALL (!): never run without a password, nor one named without its folder that may be it
    sh = Shell("local", runner=Sudo(listing("(root) NOPASSWD: ALL, !/usr/sbin/nft")))
    assert needs_password(sh, "/usr/sbin/nft") is True and needs_password(sh, "nft") is True
    assert needs_password(sh, "/usr/bin/id") is False


def test_what_the_listing_does_not_settle_is_taken_as_needing_a_password(monkeypatch):
    not_root(monkeypatch)
    for answer, command in (
            (listing("(sysop : wheel) NOPASSWD: ALL"), (READ,)),  # it runs as the user, not as root
            (listing(OWN_ALL, "(%admins) NOPASSWD: ALL"), (READ,)),  # as a group's members: is root one?
            (listing(OWN_ALL, "(root) NOPASSWD: /usr/sbin/nft"), ("nft",)),  # named without its folder: that nft?
            (listing(OWN_ALL, "(root) NOPASSWD: /usr/local/libexec/liminal/*"), (READ,)),  # a pattern
            (listing(OWN_ALL, f"(root) NOPASSWD: sha256:{'0' * 64} {READ}"), (READ,)),  # a digest: is it that file?
            ((0, (HEAD + "\nSudoers entry: /etc/sudoers\n    RunAsUsers: ALL\n").encode(), b""), (READ,)),  # -ll's
            ((0, b"User sysop is not allowed to run sudo on liminal-test.\n", b""), (READ,)),
            ((0, b"something else altogether\n", b""), (READ,))):
        assert needs_password(Shell("local", runner=Sudo(answer)), *command) is True, (answer, command)


def test_a_wrapped_line_and_sudos_escapes_are_read_as_sudo_meant_them(monkeypatch):
    not_root(monkeypatch)
    # sudo wraps a long line at a terminal's width: it goes on indented by eight
    wrapped = (0, (DEFAULTS + HEAD + f'    {OWN_ALL}\n    (root) NOPASSWD: {READ} "",\n        {HELPER} ""\n').encode(),
               b"")
    sh = Shell("local", runner=Sudo(wrapped))
    assert needs_password(sh, READ) is False and needs_password(sh, HELPER) is False
    # a comma, a colon or an equals sign of a command's own is escaped (\,), and so is a space in its path
    own = r"(root) NOPASSWD: /usr/bin/printf a\,b\:c\=d, /opt/my\ tools/run, /usr/bin/id"
    sh = Shell("local", runner=Sudo(listing(OWN_ALL, own)))
    assert needs_password(sh, "/usr/bin/printf", "a,b:c=d") is False and needs_password(sh, "/usr/bin/id") is False
    assert needs_password(sh, "/opt/my tools/run") is False
    assert needs_password(sh, "/usr/bin/printf", "a") is True  # other arguments: the user's own rule, which asks


def test_needs_password_is_false_as_root(monkeypatch):
    as_root(monkeypatch)
    rec = Recorder()
    assert needs_password(Shell("local", runner=rec), "nft", "list") is False
    assert rec.calls == []  # root: nothing is asked of sudo at all


# --- grant ---------------------------------------------------------------------------------------------------------

def _grant_script(rec) -> str:
    """The one sh script a grant ran, pulled back off the recorder (the argument of `sh -c`)."""
    argv, stdin = rec.calls[-1]
    assert argv[:-1] == ["sudo", "-S", "-k", "-p", "", "--", "sh", "-c"]
    assert stdin == f"{PW}\n"  # the password alone on standard input, read by sudo; the script is an argument
    return argv[-1]


def _blobs(script: str) -> list[str]:
    """Every base64 payload the script decodes (`printf %s '<blob>' | base64 -d`), in order."""
    found = re.findall(r"printf %s '([A-Za-z0-9+/=]*)' \| base64 -d", script)
    return [base64.b64decode(m).decode("utf-8") for m in found]


def test_a_grant_installs_the_files_and_a_narrow_sudoers_rule_for_the_liminal_group(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder()
    paths = grant(Shell("local", runner=rec), "firewall-linux", {"read": "#!/bin/sh\nnft list ruleset\n"},
                  password=PW, group="liminal")
    assert paths == [f"{LIBEXEC}/firewall-linux/read", f"{LIBEXEC}/firewall-linux/{TAKE_BACK}"]
    assert linux.grant_paths("firewall-linux") == (f"{LIBEXEC}/firewall-linux", f"{LIBEXEC}/firewall-linux/{TAKE_BACK}",
                                                   f"{SUDOERS_D}/liminal-firewall-linux")
    script = _grant_script(rec)
    # the files' texts travel as base64 (the read script and the take-back helper, each a helper_text, then the
    # sudoers rule, and the same rule with NOPASSWD alone for a visudo that refuses the other tags)
    blobs = _blobs(script)
    assert blobs[0] == linux.helper_text("firewall-linux", "#!/bin/sh\nnft list ruleset\n")
    assert blobs[1].startswith("#!/bin/sh") and "rm -f '/etc/sudoers.d/liminal-firewall-linux'" in blobs[1]
    rule = blobs[2]
    assert rule == (  # addendum 10: the group, never a person
        "# Installed by the Liminal platform for firewall-linux. It lets the group liminal run these helpers as root "
        "without a password, with no arguments.\n"
        f"# Remove it with: sudo {LIBEXEC}/firewall-linux/{TAKE_BACK}\n"
        f'%liminal ALL=(root) NOPASSWD:NOSETENV:EXEC: {LIBEXEC}/firewall-linux/read "", '
        f'{LIBEXEC}/firewall-linux/{TAKE_BACK} ""\n')
    assert blobs[3] == rule.replace("NOPASSWD:NOSETENV:EXEC: ", "NOPASSWD: ") and len(blobs) == 4
    # the rule is checked by visudo before it is put in place; the drop-in itself root:root 0440 whatever the group
    assert 'visudo -cf "$t"' in script
    assert f"install -o root -g root -m 0440 \"$t\" '{SUDOERS_D}/liminal-firewall-linux'" in script
    # addendum 10: the folder and files are root:liminal 0750, so a non-member cannot even run them
    assert f"install -d -o root -g liminal -m 0750 {LIBEXEC}/firewall-linux" in script
    assert "chown root:liminal" in script and "chmod 0750" in script and "chown root:root" not in script
    assert PW not in script  # the password is never written into the script


def test_the_grant_script_refuses_a_symlink_or_a_world_writable_folder_on_the_way(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder()
    grant(Shell("local", runner=rec), "firewall-linux", {"read": "x"}, password=PW, group="liminal")
    script = _grant_script(rec)
    # the fixed script checks every parent before it writes anything (only running it as root proves the refusal;
    # here the guard's presence is asserted): a symlink, a non-root owner, or writable-by-others each exit non-zero
    assert f"for d in /usr /usr/local /usr/local/libexec {LIBEXEC} {LIBEXEC}/firewall-linux; do" in script
    assert 'if [ -L "$d" ]; then echo "liminal: $d is a symlink" >&2; exit 5; fi' in script
    assert 'if [ "$o" != 0 ]; then echo "liminal: $d is not owned by root" >&2; exit 5; fi' in script
    # the last octal digit's write bit: writable by others; the one before it: by a group other than root's
    assert '  case "$p" in *[2367]) echo "liminal: $d is writable by others" >&2; exit 5;; esac' in script
    assert '  case "$g:$p" in 0:*) ;; *:*[2367]?) ' in script
    # it begins with ROOT_HEAD: standard input /dev/null, its own PATH, LC_ALL=C, umask 077, cd /
    assert script.startswith("".join(f"{line}\n" for line in (*linux.ROOT_HEAD, "set -eu")))


def test_a_symlink_on_the_way_is_looked_for_before_a_missing_folder_is_passed_over(monkeypatch):
    """`[ -e ]` follows a link, so a link to nothing seems missing to it. Looked for first, a dangling symlink on the
    way is refused in the script's own words, not passed over to fail later in an install's (the review, 2026-11-17)."""
    not_root(monkeypatch)
    rec = Recorder()
    grant(Shell("local", runner=rec), "firewall-linux", {"read": "x"}, password=PW, group="liminal")
    loop = _grant_script(rec).split("; do\n", 1)[1].split("\ndone\n", 1)[0].splitlines()
    assert loop[0] == '  if [ -L "$d" ]; then echo "liminal: $d is a symlink" >&2; exit 5; fi'
    assert loop[1] == '  [ -e "$d" ] || continue'


def test_a_grant_refuses_an_unsafe_name_or_file(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder()
    sh = Shell("local", runner=rec)
    for bad in ("../escape", "Firewall", "with/slash", "", "-lead"):
        with pytest.raises(CommandError, match="a grant's name"):
            grant(sh, bad, {"read": "x"}, password=PW, group="liminal")
    with pytest.raises(CommandError, match="a helper file's name"):
        grant(sh, "firewall-linux", {"../read": "x"}, password=PW, group="liminal")
    with pytest.raises(CommandError, match="the name of the grant's own helper"):  # written over by the take-back
        grant(sh, "firewall-linux", {TAKE_BACK: "x"}, password=PW, group="liminal")
    with pytest.raises(CommandError, match="a sudoers principal"):
        grant(sh, "firewall-linux", {"read": "x"}, password=PW, group="liminal ALL=(ALL) ALL")
    with pytest.raises(TypeError):  # addendum 10: a grant is a group's, never a person's: there is no default
        grant(sh, "firewall-linux", {"read": "x"}, password=PW)
    assert rec.calls == []  # each refused before sudo is asked


def test_a_refused_password_stops_a_grant(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder([(["sh"], (1, b"", b"sudo: 1 incorrect password attempt"))])
    with pytest.raises(PasswordRefused):
        grant(Shell("local", runner=rec), "firewall-linux", {"read": "x"}, password=PW, group="liminal")


# --- revoke --------------------------------------------------------------------------------------------------------

def test_revoke_runs_the_take_back_helper_without_a_password(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder()
    revoke(Shell("local", runner=rec), "firewall-linux")
    argv, stdin = rec.calls[-1]
    assert argv == ["sudo", "-n", "--", f"{LIBEXEC}/firewall-linux/{TAKE_BACK}"] and stdin is None


def test_revoke_falls_back_to_the_password_when_the_helper_is_gone(monkeypatch):
    not_root(monkeypatch)
    helper = f"{LIBEXEC}/firewall-linux/{TAKE_BACK}"
    rec = Recorder([([helper], (1, b"", b"sudo: a password is required"))])  # the helper is no longer allowed/there
    revoke(Shell("local", runner=rec), "firewall-linux", password=PW)
    argv, stdin = rec.calls[-1]
    assert argv[:-1] == ["sudo", "-S", "-k", "-p", "", "--", "sh", "-c"] and stdin == f"{PW}\n"
    head = "".join(f"{line}\n" for line in linux.ROOT_HEAD)
    assert argv[-1] == (f"{head}set -eu\nrm -f '{SUDOERS_D}/liminal-firewall-linux'\n"
                        f"rm -rf '{LIBEXEC}/firewall-linux'\n")


def test_revoke_without_a_password_raises_when_the_helper_is_gone(monkeypatch):
    not_root(monkeypatch)
    helper = f"{LIBEXEC}/firewall-linux/{TAKE_BACK}"
    rec = Recorder([([helper], (1, b"", b"sudo: a password is required"))])
    with pytest.raises(CommandError):
        revoke(Shell("local", runner=rec), "firewall-linux")


# --- granted -------------------------------------------------------------------------------------------------------

def _granted_runner(installed: dict, nopasswd: set, asked: list | None = None):
    """A runner answering `granted`'s reads: a `cat -- <path>` gives the installed text (or 'missing' rc 1), and
    sudo's listing (SUDO_LIST) holds the user's own rule (a password asked), then the grant's for the paths in
    `nopasswd`; with none, sudo will not list at all. Every argv is kept in `asked` when it is given."""
    def run(args, timeout, stdin=None):
        if asked is not None:
            asked.append(list(args))
        bare = _bare(args)
        if bare[:2] == ["cat", "--"]:
            path = bare[2]
            return (0, installed[path].encode(), b"") if path in installed else (1, b"", b"No such file")
        if list(args) == list(SUDO_LIST):
            if not nopasswd:
                return NONE
            return listing(OWN_ALL, "(root) NOPASSWD: " + ", ".join(f'{p} ""' for p in sorted(nopasswd)))
        return 0, b"", b""
    return run


def test_granted_reports_each_file_installed_matching_and_nopasswd(monkeypatch):
    not_root(monkeypatch)
    read = f"{LIBEXEC}/firewall-linux/read"
    helper = f"{LIBEXEC}/firewall-linux/{TAKE_BACK}"
    installed = linux.helper_text("firewall-linux", "the-script")  # as grant installs it
    runner = _granted_runner({read: installed, helper: "#!/bin/sh\n"}, {read, helper})
    out = granted(Shell("local", runner=runner), "firewall-linux", {"read": "the-script"})
    assert out["files"]["read"] == {"path": read, "installed": True, "matches": True, "nopasswd": True}
    assert out["take_back"] == {"path": helper, "installed": True, "nopasswd": True}
    assert out["complete"] is True and out["missing"] == []


def test_granted_says_what_is_missing_or_stale(monkeypatch):
    not_root(monkeypatch)
    read = f"{LIBEXEC}/firewall-linux/read"
    # installed but an older plugin's text, and sudo still asks; the take-back helper is gone
    runner = _granted_runner({read: "old-script"}, set())
    out = granted(Shell("local", runner=runner), "firewall-linux", {"read": "new-script"})
    assert out["files"]["read"]["installed"] is True and out["files"]["read"]["matches"] is False
    assert out["files"]["read"]["nopasswd"] is False and out["complete"] is False
    assert any("older plugin's" in m for m in out["missing"])
    assert any("still asks for a password" in m for m in out["missing"])
    assert out["take_back"]["installed"] is False


def test_granted_handles_a_file_it_cannot_read_yet(monkeypatch):
    not_root(monkeypatch)
    # root:liminal 0750 and this process not a member yet (membership takes effect after a restart): cat fails
    runner = _granted_runner({}, set())
    out = granted(Shell("local", runner=runner), "firewall-linux", {"read": "x"})
    assert out["files"]["read"]["installed"] is False and out["files"]["read"]["matches"] is None
    assert any("not installed" in m for m in out["missing"])


def test_granted_is_true_everywhere_as_root(monkeypatch):
    as_root(monkeypatch)
    read = f"{LIBEXEC}/firewall-linux/read"
    helper = f"{LIBEXEC}/firewall-linux/{TAKE_BACK}"
    asked: list = []
    # as root, nopasswd is true without asking sudo
    runner = _granted_runner({read: linux.helper_text("firewall-linux", "s"), helper: "h"}, set(), asked)
    out = granted(Shell("local", runner=runner), "firewall-linux", {"read": "s"})
    assert out["files"]["read"]["nopasswd"] is True and out["take_back"]["nopasswd"] is True and out["complete"]
    assert list(SUDO_LIST) not in asked


def test_granted_reads_sudos_listing_once_and_the_rule_that_decides_says_it(monkeypatch):
    not_root(monkeypatch)
    asked: list = []
    texts = {READ: linux.helper_text("firewall-linux", "s"), HELPER: "h"}

    def run(args, timeout, stdin=None):
        asked.append(list(args))
        if args[:2] == ["cat", "--"]:
            return 0, texts[args[2]].encode(), b""
        if list(args) == list(SUDO_LIST):  # the grant's rule read before the user's own, which then decides: it asks
            return listing(GRANT, OWN_ALL)
        return 0, b"", b""  # where `sudo -n -l -- <path>` was asked, its 0 said "no password" for either file

    out = granted(Shell("local", runner=run), "firewall-linux", {"read": "s"})
    assert out["files"]["read"]["nopasswd"] is False and out["take_back"]["nopasswd"] is False
    assert any("still asks for a password" in m for m in out["missing"]) and out["complete"] is False
    assert asked.count(list(SUDO_LIST)) == 1 and not any(a[:4] == ["sudo", "-n", "-l", "--"] for a in asked)


def test_on_the_linux_the_platform_runs_on_granted_reads_the_helpers_itself_and_starts_no_cat(monkeypatch, tmp_path):
    """The helpers are readable by the process, so it opens them itself rather than start a `cat` for each one at
    every read (the simplification review, 2026-11-18); a runner (a test's) or a WSL target still has `cat` read them.
    As root sudo's listing is not asked either, so nothing at all runs here (the guard would fail the test)."""
    as_root(monkeypatch)
    monkeypatch.setattr(linux, "_on_windows", lambda: False)  # this machine a Linux, wherever the test runs
    monkeypatch.setattr(linux, "LIBEXEC", str(tmp_path))  # grant_paths reads it when it is called
    (tmp_path / "firewall-linux").mkdir()
    (tmp_path / "firewall-linux" / "read").write_bytes(linux.helper_text("firewall-linux", "s").encode())
    out = granted(Shell("local"), "firewall-linux", {"read": "s"})
    assert out["files"]["read"]["installed"] is True and out["files"]["read"]["matches"] is True
    assert out["take_back"]["installed"] is False and out["complete"] is False  # not there: not readable from here
    (tmp_path / "firewall-linux" / "read").write_bytes(b"#!/bin/sh\n\xff an older read\n")  # read as cat's output is
    assert granted(Shell("local"), "firewall-linux", {"read": "s"})["files"]["read"]["matches"] is False


# --- the release review (2026-11-18): the chain, the helpers, the rule, the password's road ---------------------------

def _chain(script: str) -> list[str]:
    """The grant script's chain check: the lines of its loop over the helper folder and its parents."""
    lines = script.splitlines()
    start = next(i for i, x in enumerate(lines) if x.startswith("for d in "))
    end = next(i for i in range(start, len(lines)) if lines[i] == "done")
    return lines[start + 1:end]


def _case_verdict(loop: list[str], gid: int, mode: str) -> str:
    """What the chain check's own `case` lines decide for a root-owned folder of group `gid` and mode `mode` (as
    `stat -c %a` prints it): each case read as sh reads it, its word with $g and $p given, its patterns globs (`|`
    between alternatives), the first arm that matches taken; "refused" when that arm exits."""
    text = "\n".join(loop)
    for m in re.finditer(r'case "([^"]*)" in (.*?)\besac\b', text, re.S):
        word = m.group(1).replace("$g", str(gid)).replace("$p", mode)
        for arm in m.group(2).split(";;"):
            pattern, _, commands = arm.strip().partition(")")
            if arm.strip() and any(fnmatch.fnmatchcase(word, p.strip()) for p in pattern.split("|")):
                if "exit 5" in commands:
                    return "refused"
                break
    return "passes"


def test_the_chain_check_refuses_a_folder_its_group_may_write_unless_that_group_is_roots(monkeypatch):
    """A folder on the way that a group other than root's may write (Debian's opt-in staff group makes /usr/local
    root:staff 2775) lets that group's members replace the helpers sudo then runs as root: the grant refuses it, in
    the words of linuxperm PLAN 1.12 (the release review, 2026-11-18: only the others' digit was looked at)."""
    not_root(monkeypatch)
    rec = Recorder()
    grant(Shell("local", runner=rec), "firewall-linux", {"read": "x"}, password=PW, group="liminal")
    loop = _chain(_grant_script(rec))
    for gid, mode in ((50, "2775"), (50, "775"), (991, "770"), (1000, "3775")):
        assert _case_verdict(loop, gid, mode) == "refused", (gid, mode)
    for gid, mode in ((0, "1777"), (0, "757"), (50, "2777")):
        assert _case_verdict(loop, gid, mode) == "refused", (gid, mode)  # writable by others, as before
    for gid, mode in ((0, "755"), (0, "750"), (0, "775"), (0, "2755"), (0, "4755"), (0, "711"), (50, "755")):
        assert _case_verdict(loop, gid, mode) == "passes", (gid, mode)  # root's own group may write: only root's
    words = "\n".join(loop)
    assert "a member of it could replace Liminal's helpers, so none is installed" in words
    assert "remove /etc/staff-group-for-usr-local" in words and "set it back to root:root 0755" in words
    assert '  if [ "$o" != 0 ]; then echo "liminal: $d is not owned by root" >&2; exit 5; fi' in loop


def test_every_helper_a_grant_installs_sets_its_own_path_and_takes_no_arguments(monkeypatch):
    """sudo hands a helper the caller's PATH where sudoers sets no secure_path (Slackware's template, sudo-rs without
    one): a helper finding its tools there would let a member choose what runs as root. Each helper sets its own (the
    release review, 2026-11-18; linuxperm PLAN 1.1 and 1.8's helper_text, CRITIQUE B3 fix 7)."""
    not_root(monkeypatch)
    rec = Recorder()
    grant(Shell("local", runner=rec), "firewall-linux", {"read": "#!/bin/sh\nnft list ruleset\n"}, password=PW,
          group="liminal")
    helpers = [b for b in _blobs(_grant_script(rec)) if b.startswith("#!")]
    assert len(helpers) == 2  # the read, then the take-back
    for text in helpers:
        assert re.search(r"^PATH=/\S+; export PATH$", text, re.M), text[:200]
        lines = text.splitlines()
        assert lines[0] == "#!/bin/sh" and "takes no arguments" in lines[1]
        assert lines[2:8] == ["exec </dev/null", f"PATH={linux.ROOT_PATH}; export PATH", "LC_ALL=C; export LC_ALL",
                              "umask 077", "cd / || exit 1",
                              'if [ "$#" -ne 0 ]; then echo "liminal: this helper takes no arguments" >&2; exit 2; fi']
    read, take_back = helpers
    assert read.splitlines()[8:] == ["nft list ruleset"]  # the body after the head; its own #!/bin/sh is the head's
    assert read == linux.helper_text("firewall-linux", "#!/bin/sh\nnft list ruleset\n")
    assert take_back.splitlines()[-2:] == ["rm -f '/etc/sudoers.d/liminal-firewall-linux'",
                                           "rm -rf '/usr/local/libexec/liminal/firewall-linux'"]
    # the fixed PATH holds root's own folders alone: never ".", an empty part (the folder sh is in), nor a relative one
    parts = linux.ROOT_PATH.split(":")
    assert all(p.startswith("/") and len(p) > 1 and "." not in p.split("/") for p in parts)
    assert parts == ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
                     "/run/current-system/sw/bin"]
    # wrapping is done once: a helper's text given again is taken as it is; a body for another interpreter is refused
    assert linux.helper_text("firewall-linux", read) == read
    with pytest.raises(CommandError, match="a helper is a POSIX sh body"):
        linux.helper_text("firewall-linux", "#!/usr/bin/python3\nprint('x')\n")


def test_granted_takes_an_installed_helper_as_current_only_when_it_is_the_hardened_text(monkeypatch):
    not_root(monkeypatch)
    body = "#!/bin/sh\nnft list ruleset\n"
    runner = _granted_runner({READ: body, HELPER: "#!/bin/sh\n"}, {READ, HELPER})
    out = granted(Shell("local", runner=runner), "firewall-linux", {"read": body})
    assert out["files"]["read"]["matches"] is False  # the body as it was installed before: not this library's helper
    assert any("not the text this plugin would install" in m for m in out["missing"]) and not out["complete"]
    hardened = linux.helper_text("firewall-linux", body)
    runner = _granted_runner({READ: hardened, HELPER: "#!/bin/sh\n"}, {READ, HELPER})
    out = granted(Shell("local", runner=runner), "firewall-linux", {"read": body})
    assert out["files"]["read"]["matches"] is True and out["complete"] is True


def test_the_grants_rule_carries_nosetenv_and_exec_and_drops_them_only_where_visudo_refuses_them(monkeypatch):
    """NOSETENV keeps a site's `Defaults setenv` from passing a caller's variables (LD_PRELOAD) to a helper, EXEC a
    site's `Defaults noexec` from stopping its tools (the release review, 2026-11-18; linuxperm PLAN 1.8). Where this
    system's visudo refuses the tags (sudo-rs 0.2.13 is unknown), the rule is made with NOPASSWD alone and said."""
    not_root(monkeypatch)
    rec = Recorder()
    grant(Shell("local", runner=rec), "firewall-linux", {"read": "x"}, password=PW, group="liminal")
    script = _grant_script(rec)
    rules = [b for b in _blobs(script) if "ALL=(root)" in b]
    paths = f'{READ} "", {HELPER} ""'
    assert rules[0].splitlines()[-1] == f"%liminal ALL=(root) NOPASSWD:NOSETENV:EXEC: {paths}"
    assert rules[1].splitlines()[-1] == f"%liminal ALL=(root) NOPASSWD: {paths}"  # the fallback, nothing wider
    assert rules[0].splitlines()[:-1] == rules[1].splitlines()[:-1] and len(rules) == 2
    lines = script.splitlines()
    tried = [i for i, x in enumerate(lines) if "visudo -cf" in x]
    assert len(tried) == 2 and 'if visudo -cf "$t" >/dev/null 2>&1; then' in lines[tried[0]]
    fallback = "\n".join(lines[tried[0]:tried[1] + 1])
    assert "NOSETENV and EXEC" in fallback and "the rule was made with NOPASSWD alone" in fallback
    # sudo lists the tagged rule as its printer writes it (cvtsudoers -f sudoers on the user's Ubuntu, 2026-11-18):
    # the tags in their own order, NOPASSWD last; the two helpers still run without a password, and nothing else
    sh = Shell("local", runner=Sudo(listing(OWN_ALL, f'(root) NOSETENV: EXEC: NOPASSWD: {paths}')))
    assert needs_password(sh, READ) is False and needs_password(sh, HELPER) is False
    assert needs_password(sh, "/usr/sbin/nft", "list", "ruleset") is True
    # what the script says of how it made the rule comes back with the paths installed (`Granted.notes`)
    said = "liminal: this system's visudo refused NOSETENV and EXEC in the rule: the rule was made with NOPASSWD alone"
    rec = Recorder([(["sh", "-c"], (0, f"/tmp/tmp.x: parsed OK\n{said}\nliminal-granted\n".encode(), b""))])
    made = grant(Shell("local", runner=rec), "firewall-linux", {"read": "x"}, password=PW, group="liminal")
    assert list(made) == [READ, HELPER] and made.notes == [said.removeprefix("liminal: ")]
    assert grant(Shell("local", runner=Recorder()), "firewall-linux", {"read": "x"}, password=PW,
                 group="liminal").notes == []


def test_a_grant_hands_sudo_the_password_alone_and_its_script_as_an_argument(monkeypatch):
    """Fed after the password on one standard input, the script was read by `sh -s` as root, so where sudo asks for
    nothing (a NOPASSWD rule) the password was the shell's first command, and after a wrong one sudo read the script's
    lines as further tries (the release review, 2026-11-18; linuxperm PLAN 4.1 item 1). Now nothing follows the
    password, the script is `sh -c`'s argument, and its first line points its standard input at /dev/null, so no
    command of it can read a password sudo left unread."""
    not_root(monkeypatch)
    rec = Recorder()
    grant(Shell("local", runner=rec), "firewall-linux", {"read": "x"}, password=PW, group="liminal")
    argv, stdin = rec.calls[-1]
    assert stdin == f"{PW}\n"
    assert argv[:8] == ["sudo", "-S", "-k", "-p", "", "--", "sh", "-c"] and len(argv) == 9
    assert argv[8].splitlines()[0] == "exec </dev/null" and PW not in argv[8]
    # a take-back by password, where the helper cannot run: the same way
    rec = Recorder([([HELPER], (1, b"", b"sudo: a password is required"))])
    revoke(Shell("local", runner=rec), "firewall-linux", password=PW)
    argv, stdin = rec.calls[-1]
    assert stdin == f"{PW}\n" and argv[:8] == ["sudo", "-S", "-k", "-p", "", "--", "sh", "-c"] and len(argv) == 9
    assert argv[8].splitlines()[0] == "exec </dev/null"
    assert argv[8].splitlines()[-2:] == [f"rm -f '{SUDOERS_D}/liminal-firewall-linux'",
                                         f"rm -rf '{LIBEXEC}/firewall-linux'"]


def test_a_password_is_never_followed_by_input_of_the_commands_own(monkeypatch):
    not_root(monkeypatch)
    rec = Recorder()
    with pytest.raises(CommandError, match="takes no input of its own"):
        Shell("local", runner=rec).run("nft", "-f", "-", password=PW, stdin="add rule inet filter input accept")
    assert rec.calls == []  # refused before sudo is asked


def test_a_password_sudo_could_not_read_as_one_line_is_refused_before_sudo(monkeypatch):
    """sudo reads a password up to a line end, and PAM refuses one of 512 bytes or more: what is left would be read
    as further tries or reach the command (linuxperm PLAN 1.7 step 1)."""
    not_root(monkeypatch)
    rec = Recorder()
    for bad in ("two\nlines", "a\rreturn", "a\x00nul", "x" * 512, "é" * 256):
        with pytest.raises(PasswordRefused, match="cannot be handed to sudo"):
            Shell("local", runner=rec).run("id", password=bad)
    assert rec.calls == []
    Shell("local", runner=rec).run("id", password="x" * 511)
    assert rec.calls[-1][1] == "x" * 511 + "\n"


def test_the_rules_comment_says_the_grants_own_why_and_no_other_plugins(monkeypatch):
    """The rule's comment named the firewall for every grant (the release review, 2026-11-18). It says the why the
    caller gives, cleaned like every text Liminal writes into a file root reads: one printable line, no backslash, at
    most 120 characters (linuxperm CRITIQUE S5: a line break would let a why write a rule of its own)."""
    not_root(monkeypatch)
    rec = Recorder()
    grant(Shell("local", runner=rec), "ollama-models", {"list": "ls"}, password=PW, group="liminal")
    rule = next(b for b in _blobs(_grant_script(rec)) if "ALL=(root)" in b)
    assert "firewall" not in rule
    assert rule.splitlines()[0] == ("# Installed by the Liminal platform for ollama-models. It lets the group liminal "
                                    "run these helpers as root without a password, with no arguments.")
    grant(Shell("local", runner=rec), "firewall-linux", {"read": "x"}, password=PW, group="liminal",
          why="the Linux firewall's read of its rules")
    rule = next(b for b in _blobs(_grant_script(rec)) if "ALL=(root)" in b)
    assert rule.splitlines()[0] == ("# Installed by the Liminal platform for firewall-linux: the Linux firewall's read "
                                    "of its rules. It lets the group liminal run these helpers as root without a "
                                    "password, with no arguments.")
    before = len(rec.calls)
    for bad in ("two\n%liminal ALL=(ALL) NOPASSWD: ALL", "a\\back", "a\ttab", "x" * 121, "a\x00nul"):
        with pytest.raises(CommandError, match="a grant's why"):
            grant(Shell("local", runner=rec), "firewall-linux", {"read": "x"}, password=PW, group="liminal", why=bad)
    assert len(rec.calls) == before  # refused before sudo is asked
