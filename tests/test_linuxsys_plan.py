"""A change as data, and the journal of what Liminal made (liminal_libs.linuxsys.plan and .journal; the linuxperm plan's
3.4 and 3.6, B4). No script is run here: no test starts a process. What is held is the script's text (its order, its
markers, its guards, its size) and the journal read back after every way a run can stop."""
from __future__ import annotations

import hashlib

import pytest

from liminal_libs.linuxsys import journal, plan, shared
from liminal_libs.linuxsys.journal import Here, Line
from liminal_libs.linuxsys.plan import Action, Folder, Outcome, Plan, Refused

pytestmark = pytest.mark.usefixtures("no_outside")

EMPTY = hashlib.sha256(b"").hexdigest()


def _two_steps(**kw) -> Plan:
    return Plan("apply", (plan.folder("/etc/sysusers.d"),
                          plan.file("/etc/sysusers.d/liminal.conf", "# Liminal\ng liminal -\n")), **kw)


# ---- Action and the shared steps ---------------------------------------------------------------------------------


def test_an_action_is_data_with_its_arguments_as_words():
    a = Action.of("member", user="alice", group="liminal", tool="shadow")
    assert a.kind == "member" and a["user"] == "alice" and a.get("tool") == "shadow" and a.get("none") == ""
    assert a == Action.of("member", tool="shadow", group="liminal", user="alice")  # the same, whatever the order
    assert a.as_dict() == {"group": "liminal", "tool": "shadow", "user": "alice"}
    hash(a)  # frozen: a plan can be compared and kept


def test_a_folder_is_made_with_its_mode_by_root():
    s = plan.folder("/var/lib/liminal-linux")
    assert s.check == "[ -d '/var/lib/liminal-linux' ]"
    assert s.do == "install -d -m 0755 -o root -g root '/var/lib/liminal-linux'"
    with pytest.raises(ValueError):
        plan.folder("/x", mode="755")


def test_a_file_is_written_beside_its_place_then_moved_in():
    text = "# Liminal\ng liminal -\nu liminal -:liminal Liminal /var/lib/liminal /usr/sbin/nologin\n"
    s = plan.file("/etc/sysusers.d/liminal.conf", text)
    sha = hashlib.sha256(text.encode()).hexdigest()
    assert s.action["sha"] == sha and s.action["mode"] == "0644"
    assert s.check == f"[ \"$(lm_sha '/etc/sysusers.d/liminal.conf')\" = '{sha}' ]"
    new = "'/etc/sysusers.d/liminal.conf.liminal-new'"
    assert s.do == (f"printf '%s' '{text}' >{new} && chmod 0644 {new} && sync {new} && "
                    f"mv -f {new} '/etc/sysusers.d/liminal.conf'")


@pytest.mark.parametrize("bad", ["it's", 'say "x"', "back\\slash", "tick`", "nul\x00", "a" * 121])
def test_a_file_s_lines_are_plain_words(bad):
    with pytest.raises(Refused):
        plan.file("/etc/x", f"ok\n{bad}\n")


def test_a_percent_and_a_dollar_are_plain_text_in_a_file_and_a_journal_line():
    """`printf '%s'` writes the file, and its text is one single-quoted word: neither is read by anyone."""
    s = plan.file("/etc/x", "100% $HOME\n")
    assert "printf '%s' '100% $HOME\n'" in s.do
    line = Line("begin", 1, "make folder /srv/100%$x").sh()
    assert line.startswith("printf '%s\\n' 'begin 1 make folder /srv/100%$x'")


@pytest.mark.parametrize("bad", ["/etc/it's", "/etc/a\nb", "/etc/a\\b", '/etc/"x"'])
def test_every_word_from_outside_is_cleaned_in_each_format(bad):
    for make in (plan.folder, plan.unfile, plan.unfolder, plan.regroup, lambda p: plan.relabel([p])):
        with pytest.raises(Refused):
            make(bad)
    with pytest.raises(Refused):
        plan.Guard("x", ("sha", bad), "").sh(1)
    with pytest.raises(Refused):
        Line("begin", 1, f"make folder {bad}").sh()
    with pytest.raises(Refused):
        Plan("apply", chains=(bad,)).script()


def test_the_steps_for_undo_and_root_s_group():
    assert plan.unfile("/etc/sysusers.d/liminal.conf").do == "rm -f '/etc/sysusers.d/liminal.conf'"
    assert plan.unfolder("/etc/sysusers.d").do == "rmdir '/etc/sysusers.d'"
    r = plan.regroup("/usr/local/libexec/liminal")
    assert (r.check, r.do) == ("[ \"$(stat -c %g '/usr/local/libexec/liminal')\" = 0 ]",
                               "chgrp root '/usr/local/libexec/liminal'")
    assert plan.relabel(["/etc/sysusers.d/liminal.conf", "/var/lib/liminal-linux"]).do == (
        "restorecon -F '/etc/sysusers.d/liminal.conf' '/var/lib/liminal-linux'")
    assert plan.unjournal().do == "rm -f \"$J\" && rmdir /var/lib/liminal-linux"
    a = plan.adopt("liminal", 1000, 1000)
    assert a.action == Action.of("adopt", name="liminal", uid=1000, gid=1000) and a.do == ":"


# ---- the script --------------------------------------------------------------------------------------------------


def test_the_script_runs_its_parts_in_the_plan_s_order():
    p = _two_steps(guards=(plan.group_guard("liminal", None),))
    text = p.script()
    order = ["exec </dev/null", "LC_ALL=C; export LC_ALL", "umask 077", "set -u", "trap '' PIPE HUP",
             "stop=0; trap 'stop=1' TERM INT", "printf '@@ liminal-begin %s\\n' \"$1\" >&2", "lm_safe() {",
             "exec 9>>/run/liminal-linux.lock", "flock -n 9", "for lm_p in", "install -d -m 0755 -o root -g root "
             "/var/lib/liminal-linux", "install -m 0644 -o root -g root /dev/null \"$J\"", "@@ refused guard 1",
             "printf 'run %s apply %s\\n'", "lm_journal=1", "@@ step 1 there", "@@ step 2 there", "lm_exit 0"]
    at = [text.index(o) for o in order]
    assert at == sorted(at), [o for o, a, b in zip(order, at, sorted(at)) if a != b]
    assert text.startswith("exec </dev/null\n") and text.endswith("lm_exit 0\n")
    # the chain: every folder from / to the journal's and to sysusers', once each
    assert ("for lm_p in '/' '/var' '/var/lib' '/var/lib/liminal-linux' '/etc' '/etc/sysusers.d'; do") in text
    # every step's tool runs with the lock's fd closed, and every step is followed by the stop check
    assert text.count("} 9>&-") == 2 and text.count("\nlm_next\n") == 2


def test_each_step_is_checked_journaled_run_and_journaled_again():
    s = plan.folder("/etc/sysusers.d")
    assert s.sh(3) == "\n".join([
        "if [ -d '/etc/sysusers.d' ]; then",
        "  printf '@@ step 3 there 0\\n'",
        "else",
        "  printf '%s\\n' 'begin 3 make folder /etc/sysusers.d' >>\"$J\" && sync \"$J\" || "
        "{ printf '@@ step 3 failed journal\\n'; lm_exit 1; }",
        "  {",
        "install -d -m 0755 -o root -g root '/etc/sysusers.d'",
        "  } 9>&-",
        "  lm_c=$?",
        "  if [ \"$lm_c\" != 0 ]; then printf '@@ step 3 failed %s\\n' \"$lm_c\"; lm_exit 1; fi",
        "  printf '%s\\n' 'done 3 made folder /etc/sysusers.d 0755' >>\"$J\" && sync \"$J\" || "
        "{ printf '@@ step 3 failed journal\\n'; lm_exit 1; }",
        "  printf '@@ step 3 done 0\\n'",
        "fi",
        "lm_next"])


def test_the_script_is_the_same_bytes_every_time_and_holds_no_nonce():
    a, b = _two_steps(), _two_steps()
    assert a.script() == b.script() and a.digest == b.digest
    assert a.digest == hashlib.sha256(a.script().encode()).hexdigest()
    assert "nonce=$1" in a.script()  # the nonce is the script's argument, never its text


def test_a_guard_changes_the_digest_and_is_checked_as_root():
    absent, there = _two_steps(guards=(plan.group_guard("liminal", None),)), _two_steps(
        guards=(plan.group_guard("liminal", 999),))
    assert absent.digest != there.digest
    assert "[ \"$(lm_gid 'liminal')\" = '' ] || { printf '@@ refused guard 1\\n'; lm_exit 2; }" in absent.script()
    assert "[ \"$(lm_gid 'liminal')\" = '999' ]" in there.script()
    g = plan.members_guard("liminal", ["zed", "alice"])
    assert g.expected == "alice,zed" and g.value == ("members", "liminal")
    assert [x.value for x in plan.user_guard("liminal", 998, 998)] == [("uid", "liminal"), ("ugid", "liminal")]
    assert plan.file_guard(journal.PATH, EMPTY).value == ("sha", journal.PATH)
    with pytest.raises(ValueError):
        plan.Guard("x", ("rm", "-rf"), "").sh(1)


def test_the_lock_without_flock_is_a_folder_never_taken_over():
    text = _two_steps(lock="mkdir").script()
    assert "if mkdir /run/liminal-linux.lock 2>/dev/null; then" in text
    assert "trap 'rm -rf /run/liminal-linux.lock' EXIT" in text
    assert "flock" not in text
    # a pid that no longer runs is said, never taken over: the script exits 2 either way
    lock = text[text.index("if mkdir"):text.index("for lm_p")]
    assert "@@ refused lock stale" in lock and lock.count("exit 2") == 1 and "rm -r" not in lock.replace("rm -rf", "")
    with pytest.raises(ValueError):
        _two_steps(lock="lockf").script()


def test_a_refused_plan_has_no_script_and_too_large_a_one_is_refused():
    no = Plan("apply", refused="NixOS declares its users")
    assert no.words() == ["NixOS declares its users"] and not no.nothing
    with pytest.raises(Refused, match="NixOS"):
        no.script()
    assert no.digest == hashlib.sha256(b"refused: NixOS declares its users").hexdigest()
    big = Plan("apply", tuple(plan.file(f"/etc/f{i}", ("x" * 100 + "\n") * 40) for i in range(25)))
    with pytest.raises(Refused, match="too large to hand to sudo in one piece"):
        big.script()
    assert len(Plan("apply", big.steps[:15]).script().encode()) <= plan.SCRIPT_MAX
    with pytest.raises(ValueError):
        Plan("format").script()


def test_nothing_to_do_and_the_words_of_a_plan():
    assert Plan("apply").nothing and Plan("apply").words() == ["nothing to do: it is all here"]
    p = _two_steps(notes=("sudo writes this change's script into the system's log",))
    assert p.words() == ["1. make the folder /etc/sysusers.d (0755, root's)",
                         "2. write /etc/sysusers.d/liminal.conf (0644, root's)",
                         "sudo writes this change's script into the system's log"]


def test_what_a_run_came_to_by_its_markers_and_its_code():
    p = _two_steps()
    out = "@@ step 1 done 0\n@@ step 2 there 0\n"
    outcomes, words = p.said(out, 0)
    assert [(o.index, o.state) for o in outcomes] == [(1, "done"), (2, "there")] and words == "done"
    outcomes, words = p.said("@@ step 1 done 0\n@@ step 2 failed 3\n", 1)
    assert outcomes[1] == Outcome(2, "failed", "3")
    assert words.startswith("step 2 of 2 failed (write /etc/sysusers.d/liminal.conf (0644, root's)): exit 3;")
    outcomes, words = p.said("@@ step 1 done 0\n@@ stopped\n", 7)
    assert [o.state for o in outcomes] == ["done", "stopped"]
    assert words == "stopped after step 1 of 2: running it again finishes it"
    assert p.said("@@ refused guard 1\n", 2)[1] == plan.CHANGED
    assert p.said("@@ refused lock held\n", 2)[1] == plan.HELD
    assert p.said("@@ refused lock held 4242\n", 2)[1] == plan.HELD + " (process 4242)"
    stale = p.said("@@ refused lock stale 4242\n", 2)[1]
    assert "process 4242 no longer runs" in stale and "rm -r /run/liminal-linux.lock" in stale
    assert p.said("@@ refused chain /etc/sysusers.d\n", 5)[1].startswith("/etc/sysusers.d is not root's alone")
    assert [o.state for o in p.said("", 2)[0]] == ["not run", "not run"]
    assert Plan("apply").said("", 0)[1] == "nothing to do"
    assert Outcome.parse("@@ step 1 do\n@@ step x done 0\n@@ step 4 done 0") == [Outcome(4, "done")]


# ---- the chain ---------------------------------------------------------------------------------------------------

ROOTS = {"/": Folder(0, 0, 0o755), "/var": Folder(0, 0, 0o755), "/var/lib": Folder(0, 0, 0o755)}


def test_the_chain_passes_root_s_folders_and_one_not_there_yet():
    assert plan.prefixes("/var/lib/liminal-linux/") == ["/", "/var", "/var/lib", "/var/lib/liminal-linux"]
    assert plan.chain("/var/lib/liminal-linux", {**ROOTS, "/var/lib/liminal-linux": None}) == ""
    assert plan.chain("/var/lib/liminal-linux", {**ROOTS, "/var/lib/liminal-linux": Folder(0, 0, 0o755)}) == ""
    # written by root's own group: Fedora's and openSUSE's /etc/sudoers.d at 0750 or 0770 root:root pass too
    assert plan.chain("/var/lib", {**ROOTS, "/var/lib": Folder(0, 0, 0o775)}) == ""


@pytest.mark.parametrize("folder, said", [
    (Folder(1000, 0, 0o755), "owner uid 1000"),
    (Folder(0, 50, 0o775), "group gid 50, mode 775"),  # Debian's staff group, opted in
    (Folder(0, 0, 0o757), "mode 757"),
    (Folder(0, 0, 0o1777), "mode 1777"),
    (Folder(0, 0, 0o755, link_uid=1000), "a link owned by uid 1000"),
])
def test_the_chain_refuses_a_folder_another_account_could_write(folder, said):
    words = plan.chain("/var/lib/liminal-linux", {**ROOTS, "/var/lib": folder, "/var/lib/liminal-linux": None})
    assert words.startswith("/var/lib ") and said in words and "nothing was changed" in words


def test_the_chain_follows_root_s_link_and_says_what_it_could_not_read():
    # ostree: /var/usrlocal reached through root's link, its target's stat as the kernel follows it
    assert plan.chain("/usr/local", {"/": Folder(0, 0, 0o755), "/usr": Folder(0, 0, 0o755),
                                     "/usr/local": Folder(0, 0, 0o755, link_uid=0)}) == ""
    words = plan.chain("/var/lib/liminal-linux", {"/": Folder(0, 0, 0o755)})
    assert words == "/var could not be read, so whether only root writes under it is not known: nothing was changed"


def test_the_script_s_chain_check_holds_the_same_rule():
    """The sh twin of chain(): a link root's, then its target's owner root, no write by others, and a group's write
    only for root's group (0o020 is 16)."""
    h = plan.HELPERS
    assert "[ \"$(stat -c %u \"$1\")\" = 0 ] || return 1" in h and "stat -L -c '%u %g %a'" in h
    assert "[ \"$1\" = 0 ] && [ $((0$3 & 2)) = 0 ] && { [ \"$2\" = 0 ] || [ $((0$3 & 16)) = 0 ]; }" in h


def test_tools_name_every_program_the_scripts_run():
    names = {t[0] for t in plan.TOOLS}
    text = _two_steps(guards=(plan.members_guard("liminal", ()),)).script() + plan.unjournal().do
    for word in ("install", "flock", "stat", "sync", "sha256sum", "awk", "sed", "cut", "sort", "tr", "chmod", "mv",
                 "date", "rmdir", "rm"):
        assert word in names and word in text, word
    assert {"groupadd", "useradd", "gpasswd", "userdel", "groupdel", "usermod", "addgroup", "adduser", "deluser",
            "delgroup", "systemd-sysusers", "getent", "sudo", "doas", "su", "rpm", "restorecon", "chgrp"} <= names
    assert len(names) == len(plan.TOOLS)


# ---- the journal -------------------------------------------------------------------------------------------------


def test_a_journal_line_is_one_printf_its_slots_the_shell_s():
    line = Line("done", 2, "made user liminal {uid liminal} {ugid liminal}")
    assert line.sh() == ("printf '%s\\n' 'done 2 made user liminal '\"$(lm_uid 'liminal')\"' '\"$(lm_ugid "
                         "'liminal')\" >>\"$J\" && sync \"$J\"")
    assert line.fill(lambda slot, arg: {"uid": 998, "ugid": 997}[slot]).text() == "done 2 made user liminal 998 997"
    assert Line("adopted", None, "user liminal 1000 1000").text() == "adopted user liminal 1000 1000"
    assert journal.run_line("undo") == ("printf 'run %s undo %s\\n' \"$nonce\" \"$(date +%s)\" >>\"$J\" && "
                                        "sync \"$J\"")
    with pytest.raises(ValueError):
        journal.run_line("format")


def test_each_kind_has_its_lines():
    def words(kind, **args):
        begin, done = journal.lines(4, kind, args)
        return (begin.text() if begin else None, [d.text() for d in done])
    assert words("group", name="liminal") == ("begin 4 make group liminal (absent)",
                                              ["done 4 made group liminal {gid liminal}"])
    assert words("user", name="liminal") == ("begin 4 make user liminal (absent)",
                                             ["done 4 made user liminal {uid liminal} {ugid liminal}"])
    assert words("sysusers", name="liminal", absent="group user") == (
        "begin 4 sysusers liminal (absent: group user)",
        ["done 4 made group liminal {gid liminal}", "done 4 made user liminal {uid liminal} {ugid liminal}"])
    assert words("sysusers", name="liminal", absent="user")[1] == ["done 4 made user liminal {uid liminal} "
                                                                    "{ugid liminal}"]
    assert words("member", user="alice") == ("begin 4 add member alice", ["done 4 added member alice"])
    assert words("unmember", user="alice") == ("begin 4 remove member alice", ["done 4 removed member alice"])
    assert words("file", path="/etc/x", sha="ab") == ("begin 4 write file /etc/x ab", ["done 4 wrote file /etc/x ab"])
    assert words("unuser", name="liminal") == ("begin 4 remove user liminal", ["done 4 removed user liminal"])
    assert words("move", name="liminal", gid=65534) == ("begin 4 move user liminal 65534",
                                                        ["done 4 moved user liminal 65534"])
    assert words("regroup", path="/usr/local/libexec/liminal")[1] == [
        "done 4 regrouped folder /usr/local/libexec/liminal root"]
    assert words("adopt", name="liminal", uid=1000, gid=1000) == (None, ["adopted user liminal 1000 1000"])
    assert words("relabel", paths="/etc/x") == (None, []) and words("unjournal") == (None, [])


APPLY = """run 1a2b apply 1764000000
begin 1 make folder /etc/sysusers.d
done 1 made folder /etc/sysusers.d 0755
begin 2 write file /etc/sysusers.d/liminal.conf ab12
done 2 wrote file /etc/sysusers.d/liminal.conf ab12
begin 3 sysusers liminal (absent: group user)
done 3 made group liminal 999
done 3 made user liminal 998 999
begin 4 add member ciara
done 4 added member ciara
end 1a2b 0
"""
HERE = Here({"liminal": (999, ("ciara",))}, {"liminal": (998, 999), "ciara": (1000, 1000)},
            {"/etc/sysusers.d": "", "/etc/sysusers.d/liminal.conf": "ab12"})


def test_fold_reads_what_a_whole_run_made():
    made = journal.fold(APPLY, HERE)
    assert (made.group, made.user, made.members) == (999, (998, 999), ("ciara",))
    assert made.folders == {"/etc/sysusers.d": "0755"} and made.files == {"/etc/sysusers.d/liminal.conf": "ab12"}
    assert not made.nothing and not made.stopped and made.notes == ()
    assert made.digest == hashlib.sha256(APPLY.encode()).hexdigest()
    assert made.last.what == "apply" and made.last.code == 0 and made.last.time == 1764000000
    assert made.last.steps[2] == (3, "sysusers liminal (absent: group user)", "done")
    d = made.describe()
    assert d["user"] == [998, 999] and d["last"]["code"] == 0 and d["stopped"] is False


def test_no_journal_is_nothing_made():
    for text in (None, ""):
        made = journal.fold(text, Here())
        assert made.nothing and made.digest == EMPTY and made.last is None and not made.stopped


@pytest.mark.parametrize("cut", range(1, 12))
def test_a_run_cut_off_after_any_line_keeps_what_it_made_as_made(cut):
    """Cut after each line: a begin without its done is Liminal's when the object is there now, nothing when not."""
    text = "".join(APPLY.splitlines(True)[:cut])
    lines = text.splitlines()
    # what the tree holds after the cut: everything whose tool ran, whether its done line was written or not
    began = [line for line in lines if line.startswith("begin")]
    groups = {"liminal": (999, ("ciara",) if len(began) >= 4 else ())} if len(began) >= 3 else {}
    users = {"liminal": (998, 999)} if len(began) >= 3 else {}
    paths = {"/etc/sysusers.d": ""} if began else {}
    if len(began) >= 2:
        paths["/etc/sysusers.d/liminal.conf"] = "ab12"
    made = journal.fold(text, Here(groups, {**users, "ciara": (1000, 1000)}, paths))
    assert (made.group is not None) == (len(began) >= 3)
    assert (made.user is not None) == (len(began) >= 3)
    assert made.members == (("ciara",) if len(began) >= 4 else ())
    assert made.stopped == (cut < 11)


def test_a_begin_whose_object_is_not_there_counts_as_nothing():
    text = "run 9 apply 1\nbegin 1 sysusers liminal (absent: group user)\n"
    assert journal.fold(text, Here()).nothing
    made = journal.fold(text, Here({"liminal": (999, ())}, {}))  # the tool made the group, then was killed
    assert made.group == 999 and made.user is None and made.stopped
    assert journal.fold("run 9 apply 1\nbegin 1 add member bob\n", Here({"liminal": (999, ())})).members == ()
    assert journal.fold("run 9 apply 1\nbegin 1 write file /etc/x ab\n", Here(paths={"/etc/x": "zz"})).files == {}


def test_removed_ends_what_is_known_and_an_unfinished_removal_counts_when_it_is_gone():
    undo = ("run 7 undo 2\nbegin 1 remove file /etc/sysusers.d/liminal.conf\n"
            "done 1 removed file /etc/sysusers.d/liminal.conf\nbegin 2 remove member ciara\n"
            "done 2 removed member ciara\nbegin 3 remove user liminal\n")
    gone = Here({"liminal": (999, ())}, {}, {"/etc/sysusers.d": ""})
    made = journal.fold(APPLY + undo, gone)
    assert made.files == {} and made.members == () and made.user is None and made.group == 999
    assert made.stopped and made.last.what == "undo" and made.last.code is None
    still = Here({"liminal": (999, ())}, {"liminal": (998, 999)}, {"/etc/sysusers.d": ""})
    assert journal.fold(APPLY + undo, still).user == (998, 999)  # its tool never ran: the user is still Liminal's


def test_a_user_moved_onto_another_group_is_still_liminal_s_with_its_new_group():
    text = APPLY + "run 8 undo 3\nbegin 1 move user liminal 65534\ndone 1 moved user liminal 65534\nend 8 1\n"
    made = journal.fold(text, HERE)
    assert made.user == (998, 65534) and made.stopped  # ended 1: a step failed after it


def test_adopted_is_kept_and_lines_not_liminal_s_are_said():
    text = "adopted user liminal 1000 1000\nrun 1 apply 1\nsomething else\ndone 1 made group other 5\nend 1 0\n"
    made = journal.fold(text, Here())
    assert made.adopted == (1000, 1000) and not made.nothing and made.group is None
    assert made.notes == ("line 3 of the journal is not one Liminal writes: something else",
                          "line 4 of the journal is not one Liminal writes: done 1 made group other 5")


def test_a_torn_last_line_is_said_not_read():
    made = journal.fold(APPLY + "begin 5 make fol", HERE)
    assert made.notes == ("line 12 of the journal is not one Liminal writes: begin 5 make fol",)
    assert made.group == 999 and made.last.steps[-1][0] == 4


def test_the_journal_s_path_and_modes_are_the_user_s_answer():
    assert (journal.PATH, journal.FOLDER_MODE, journal.MODE) == ("/var/lib/liminal-linux/MADE", "0755", "0644")
    assert journal.digest(None) == EMPTY == journal.digest("")
    assert shared.clean_words("begin 1 make folder /etc/sysusers.d", "x")
