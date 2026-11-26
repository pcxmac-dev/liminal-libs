"""The recorded-machine stand-in (liminal_libs.linuxsys.standin): it answers the probe from its tree, plays a plan's
Actions as root with their tools' side effects, plays sudo's conversation over byte pipes, and stops a run after any
step. It runs nothing. The plans here are written by hand from plan.py's shapes; the accounts' own plans
(accounts.py) are tested on the same machines in their own file."""
from __future__ import annotations

import pytest

from liminal_libs.linuxsys import facts, journal, plan, shared, standin
from liminal_libs.linuxsys.plan import Action, Plan, Step

pytestmark = pytest.mark.usefixtures("no_outside")

UBUNTU = "wsl-ubuntu-24.04"
CONF = "# Liminal: its group and user\ng liminal -\nu liminal -:liminal Liminal /var/lib/liminal /usr/sbin/nologin\n"


def step(kind: str, **args) -> Step:
    """An account step as accounts.py makes one: its Action is what the stand-in plays; its sh is not run here."""
    return Step(f"{kind} {args}", Action.of(kind, **args), "false", f": {kind}")


def make_plan(m: standin.Machine, member: str = "pat") -> Plan:
    f = m.facts()
    g = f.liminal["group"]
    return Plan("apply", (plan.folder("/etc/sysusers.d"), plan.file(facts.SYSUSERS, CONF),
                          step("sysusers", path=facts.SYSUSERS, name="liminal", absent="group user", tool="sysusers"),
                          step("member", user=member, group="liminal", tool="sysusers")),
                guards=(plan.group_guard("liminal", g.gid if g else None),), lock=f.lock)


def undo_plan(m: standin.Machine) -> Plan:
    made = m.facts().made()
    return Plan("undo", (plan.unfile(facts.SYSUSERS), step("unmember", user="pat", group="liminal", tool="sysusers"),
                         step("unuser", name="liminal", tool="sysusers"), step("ungroup", name="liminal",
                                                                                tool="sysusers"),
                         plan.unfolder("/etc/sysusers.d"), plan.unjournal()),
                guards=(plan.file_guard(journal.PATH, made.digest),), lock="flock")


# ---- the machines ------------------------------------------------------------------------------------------------


def test_every_recorded_machine_says_where_it_comes_from_and_loads():
    names = standin.machines()
    assert UBUNTU in names
    for name in names:
        for overlay in (None, *standin.overlays(name)):
            m = standin.Machine(name, overlay)
            assert m.source.startswith(("written 20", "captured 20")), name
            if overlay:
                assert m.source.splitlines()[-1].startswith("overlay"), (name, overlay)
            f = m.facts()
            assert "@@ probe end" in m.answer() and not [n for n in f.notes if "cut off" in n], (name, overlay)


def test_the_user_s_ubuntu_as_recorded():
    m = standin.Machine(UBUNTU)
    f = m.facts()
    assert (f.os["id"], f.kernel.wsl, f.accounts["tool"], f.lock, f.elevation["sudo_kind"]) == (
        "ubuntu", "Ubuntu", "sysusers", "flock", "sudo")
    assert f.liminal["group"] is None and f.made().nothing and f.chain(journal.FOLDER) == ""
    assert standin.overlays(UBUNTU) == ["firewall-group", "nopasswd-all"]


def test_it_answers_the_probe_and_sudo_s_listing_as_a_runner():
    m = standin.Machine(UBUNTU)
    done = m.run(list(facts.ARGV), facts.PROBE_S)
    assert done.returncode == 0 and done.stdout == m.answer()
    assert facts.read(m.run).accounts["tool"] == "sysusers"
    refused = m.run(list(shared.SUDO_LIST))
    assert refused.returncode == 1 and "a password is required" in refused.stderr
    free = standin.Machine(UBUNTU, "nopasswd-all").run(list(shared.SUDO_LIST))
    assert shared.runs_free(shared.listed(free.stdout), ("/bin/sh", "-c", "x"))
    other = m.run(["ls", "/root"])
    assert other.returncode == 127 and "not recorded" in other.stderr
    assert [c["argv"][0] for c in m.calls] == ["/bin/sh", "/bin/sh", "env", "ls"]


# ---- a plan, played as root --------------------------------------------------------------------------------------


def test_apply_plays_the_tools_and_writes_the_journal_as_it_goes():
    m = standin.Machine(UBUNTU)
    first = m.snapshot()
    p = make_plan(m)
    code, out, err = m.play(p, "a1b2")
    assert code == 0 and err.startswith("@@ liminal-begin a1b2\n")
    assert out == "".join(f"@@ step {n} done 0\n" for n in range(1, 5))
    groups, users = m.groups(), m.users()
    assert groups["liminal"] == facts.Group("liminal", 994, ("pat",))  # sysusers: the highest free id below 1000
    assert users["liminal"] == facts.User("liminal", 994, 994, "Liminal", "/var/lib/liminal", "/usr/sbin/nologin")
    made = m.facts().made()
    assert (made.group, made.user, made.members) == (994, (994, 994), ("pat",))
    assert made.files == {facts.SYSUSERS: p.steps[1].action["sha"]} and made.folders == {"/etc/sysusers.d": "0755"}
    assert m.files[journal.PATH].splitlines()[0] == f"run a1b2 apply {m.clock}"
    assert m.files[journal.PATH].endswith("end a1b2 0\n")
    assert m.programs == ["install", "chmod", "sync", "mv", "systemd-sysusers", "gpasswd"]
    assert m.snapshot() != first


def test_apply_twice_finds_it_all_there_and_undo_gives_the_first_snapshot_back():
    m = standin.Machine(UBUNTU)
    first = m.snapshot()
    m.play(make_plan(m))
    lines = m.files[journal.PATH].count("\n")
    again = Plan("apply", make_plan(m).steps, lock="flock")  # no guard: its group is there now
    code, out, _ = m.play(again)
    assert code == 0 and out == "".join(f"@@ step {n} there 0\n" for n in range(1, 5))
    assert m.files[journal.PATH].count("\n") == lines + 2  # its run line and its end line, no step's
    code, out, _ = m.play(undo_plan(m))
    assert code == 0, out
    assert "@@ step 4 there 0" in out  # userdel took the group of the user's name with it (USERGROUPS_ENAB yes)
    assert m.snapshot() == first


@pytest.mark.parametrize("n", [1, 2, 3, 4])
@pytest.mark.parametrize("point", standin.POINTS)
def test_apply_killed_after_any_step_then_again_then_undo_gives_the_first_snapshot(n, point):
    m = standin.Machine(UBUNTU)
    first = m.snapshot()
    m.stop_at = (n, point)
    code, out, _ = m.play(make_plan(m))
    assert code == -9 and "end " not in m.files[journal.PATH].splitlines()[-1]
    made = m.facts().made()
    assert made.stopped
    if n >= 3 and point != "before":
        assert made.group == 994 and made.user == (994, 994)  # the tool ran: Liminal's, not found
    m.stop_at = None
    assert m.play(make_plan(m))[0] == 0
    made = m.facts().made()
    assert (made.group, made.user, made.members) == (994, (994, 994), ("pat",))
    assert m.play(undo_plan(m))[0] == 0
    assert m.snapshot() == first


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("point", standin.POINTS)
def test_undo_killed_after_any_step_then_undo_again_gives_the_first_snapshot(n, point):
    m = standin.Machine(UBUNTU)
    first = m.snapshot()
    m.play(make_plan(m))
    m.stop_at = (n, point)
    code, out, _ = m.play(undo_plan(m))
    assert code == -9 or (code == 0 and f"@@ step {n} there 0" in out)  # step 4: userdel took the group already
    m.stop_at = None
    code, out, _ = m.play(undo_plan(m))
    assert code == 0, out
    assert m.snapshot() == first


def test_a_term_lets_the_step_finish_then_stops_with_7():
    m = standin.Machine(UBUNTU)
    m.term_at = (3, "before")
    p = make_plan(m)
    code, out, _ = m.play(p)
    assert code == 7 and out.endswith("@@ step 3 done 0\n@@ stopped\n")
    assert m.files[journal.PATH].endswith("done 3 made user liminal 994 994\nend 0123456789abcdef 7\n")
    assert p.said(out, code)[1] == "stopped after step 3 of 4: running it again finishes it"


def test_a_guard_that_no_longer_holds_refuses_before_the_run_line():
    m = standin.Machine(UBUNTU, "firewall-group")
    p = Plan("apply", make_plan(standin.Machine(UBUNTU)).steps, guards=(plan.group_guard("liminal", None),))
    code, out, _ = m.play(p)
    assert (code, out) == (2, "@@ refused guard 1\n") and m.files[journal.PATH] == ""
    assert p.said(out, code)[1] == plan.CHANGED


def test_a_folder_another_account_writes_stops_it_at_the_chain():
    m = standin.Machine(UBUNTU)
    m.folders["/var/lib"] = plan.Folder(0, 50, 0o775)
    code, out, _ = m.play(make_plan(m))
    assert (code, out) == (5, "@@ refused chain /var/lib\n") and journal.PATH not in m.files


def test_a_tool_that_is_not_there_fails_as_sh_does():
    m = standin.Machine(UBUNTU)
    del m.data["tools"]["systemd-sysusers"]
    code, out, _ = m.play(make_plan(m))
    assert code == 1 and out.endswith("@@ step 3 failed 127\n")


# ---- the tools' own rules ----------------------------------------------------------------------------------------


def _user_in_found_group(tool: str) -> standin.Machine:
    m = standin.Machine(UBUNTU, "firewall-group")  # the group liminal is there, pat in it
    code, out, _ = m.play(Plan("apply", (step("user", name="liminal", group="liminal", comment="Liminal",
                                              home="/var/lib/liminal", shell="/usr/sbin/nologin", tool=tool),)))
    assert code == 0, out
    # shadow: the highest free system uid (999: systemd-journal is a group alone); BusyBox: the first free from 100
    assert m.users()["liminal"].uid == {"shadow": 999, "busybox": 102}[tool]
    return m


def test_shadow_s_userdel_keeps_a_group_with_members_busybox_s_deluser_does_not():
    m = _user_in_found_group("shadow")
    m.play(Plan("undo", (step("unuser", name="liminal", tool="shadow"),)))
    assert m.groups()["liminal"].members == ("pat",)  # pat is still in it: userdel keeps it
    m = _user_in_found_group("busybox")
    m.play(Plan("undo", (step("unuser", name="liminal", tool="busybox"),)))
    assert "liminal" not in m.groups()  # deluser removes it whatever its members


def test_shadow_s_userdel_removes_its_emptied_usergroup_and_moving_the_user_first_keeps_it():
    m = standin.Machine(UBUNTU)
    m.play(Plan("apply", (step("group", name="liminal", tool="shadow"),
                          step("user", name="liminal", group="liminal", tool="shadow"))))
    gid = m.groups()["liminal"].gid
    assert gid == 994 and m.users()["liminal"].gid == gid
    m.play(Plan("undo", (step("move", name="liminal", gid=65534, tool="shadow"),
                         step("unuser", name="liminal", tool="shadow"))))
    assert "liminal" in m.groups()  # no longer the user's primary group: kept


def test_gpasswd_d_fails_on_no_member_and_groupdel_on_a_primary_group():
    m = standin.Machine(UBUNTU, "firewall-group")
    # the step's check finds no member there; the tool itself, asked anyway, fails
    assert m._do(Action.of("unmember", user="nobody", group="liminal", tool="shadow")) == 3
    assert m._do(Action.of("member", user="nobody", group="liminal", tool="shadow")) == 0
    assert m._do(Action.of("member", user="nobody", group="liminal", tool="shadow")) == 0  # once only
    assert m.groups()["liminal"].members == ("pat", "nobody")
    m = _user_in_found_group("shadow")
    code, out, _ = m.play(Plan("undo", (step("ungroup", name="liminal", tool="shadow"),)))
    assert code == 1 and "failed 8" in out


def test_sysusers_skips_what_is_there_and_takes_a_found_group():
    m = standin.Machine(UBUNTU, "firewall-group")
    p = Plan("apply", (plan.folder("/etc/sysusers.d"), plan.file(facts.SYSUSERS, CONF),
                       step("sysusers", path=facts.SYSUSERS, name="liminal", absent="user", tool="sysusers")))
    assert m.play(p)[0] == 0
    assert m.groups()["liminal"] == facts.Group("liminal", 994, ("pat",))
    assert m.users()["liminal"].gid == 994


# ---- sudo's conversation -----------------------------------------------------------------------------------------


def _argv(p: Plan, nonce: str = "feed") -> list[str]:
    return ["/usr/bin/env", "LC_ALL=C", "/usr/bin/sudo", "-S", "-k", "-u", "root", "-p",
            f"<<liminal-sudo:{nonce}:%p>>", "--", "/bin/sh", "-c", p.script(), "liminal", nonce]


def test_the_conversation_takes_the_password_on_standard_input_alone():
    m = standin.Machine(UBUNTU)
    proc = m.spawn(_argv(make_plan(m)), env={"LC_ALL": "C"})
    assert proc.stderr.read1() == b"<<liminal-sudo:feed:pat>>" and proc.poll() is None
    proc.stdin.write(standin.PASSWORD.encode() + b"\n")
    assert proc.poll() == 0 and m.sudo_runs == 1
    assert proc.stderr.read() == b"@@ liminal-begin feed\n"
    assert proc.stdout.read().count(b"done 0") == 4
    call = m.calls[-1]
    assert call["stdin"] == standin.PASSWORD.encode() + b"\n"
    assert standin.PASSWORD not in " ".join(call["argv"]) and standin.PASSWORD not in str(call["env"])
    with pytest.raises(BrokenPipeError):
        proc.stdin.write(b"x")  # sudo has ended
    proc.stdin.close()  # after the begin line: no prompt is read
    assert not m.eof_at_prompt


@pytest.mark.parametrize("kind, retry", [("sudo", standin.CLASSIC_RETRY), ("sudo-rs", standin.RS_RETRY)])
def test_a_wrong_password_is_said_with_sudo_s_retry_words_and_a_second_marker(kind, retry):
    m = standin.Machine(UBUNTU)
    m.data["sudo"]["kind"] = kind
    proc = m.spawn(_argv(make_plan(m)))
    proc.stderr.read1()
    proc.stdin.write(b"wrong\n")
    assert proc.stderr.read1() == f"{retry}\n<<liminal-sudo:feed:pat>>".encode() and proc.tries == 1
    proc.kill()  # the caller ends it at the second marker: sudo never reads end of input there
    assert proc.poll() == -9 and proc.killed_at == "prompt" and not m.eof_at_prompt and m.sudo_runs == 0
    assert journal.PATH not in m.files  # nothing ran
    assert shared.PASSWORD_REFUSED and retry.lower().rstrip(".") in shared.SUDO_RETRY


def test_end_of_input_at_a_prompt_is_recorded_for_the_test_that_forbids_it():
    m = standin.Machine(UBUNTU)
    proc = m.spawn(_argv(make_plan(m)))
    proc.stdin.close()
    assert m.eof_at_prompt and proc.poll() == 1 and b"no password was provided" in proc.stderr.read()


def test_a_second_factor_asks_again_without_retry_words():
    m = standin.Machine(UBUNTU)
    m.data["sudo"]["second_factor"] = True
    proc = m.spawn(_argv(make_plan(m)))
    proc.stderr.read1()
    proc.stdin.write(standin.PASSWORD.encode() + b"\n")
    assert proc.stderr.read1() == b"<<liminal-sudo:feed:pat>>" and proc.poll() is None
    proc.kill()
    assert m.sudo_runs == 0


def test_root_s_password_under_targetpw_names_root_in_the_marker():
    m = standin.Machine(UBUNTU)
    m.data["sudo"]["whose"] = "root"
    assert m.spawn(_argv(make_plan(m))).stderr.read1() == b"<<liminal-sudo:feed:root>>"


def test_no_password_asked_runs_at_once_and_an_argv_not_sudo_s_is_refused():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    proc = m.spawn(_argv(make_plan(m)))
    assert proc.poll() == 0 and proc.stderr.read().startswith(b"@@ liminal-begin feed")
    bad = m.spawn(["/usr/bin/sudo", "/bin/sh", "-c", "id"])
    assert bad.poll() == 1 and b"no sudo conversation" in bad.stderr.read()


# ---- two runs at once --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("lock", ["flock", "mkdir"])
def test_a_held_run_keeps_the_lock_and_a_killed_one_lets_go_only_of_flock(lock):
    m = standin.Machine(UBUNTU, "nopasswd-all")
    p = Plan("apply", make_plan(m).steps, lock=lock)
    m.hold_at = (3, "tool")
    a = m.spawn(_argv(p, "aaaa"))
    assert a.poll() is None  # A holds, inside step 3
    code, out, _ = m.play(p, "bbbb")
    assert code == 2 and out.startswith("@@ refused lock held")
    assert p.said(out, code)[1].startswith(plan.HELD)
    a.kill()
    code, out, _ = m.play(p, "cccc")
    if lock == "flock":
        assert code == 0, out  # the kernel let go of A's lock: B takes it
    else:
        assert code == 2 and out == f"@@ refused lock stale {a.pid}\n"
        assert f"rm -r {plan.LOCK}" in p.said(out, code)[1]
        m.folders.pop(plan.LOCK)
        m.files.pop(plan.LOCK + "/pid")
        assert m.play(p, "dddd")[0] == 0


def test_a_held_run_told_term_finishes_its_step_and_one_resumed_ends():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    p = make_plan(m)
    m.hold_at = (2, "before")
    a = m.spawn(_argv(p, "aaaa"))
    a.terminate()
    assert a.poll() == 7 and a.stdout.read().endswith(b"@@ step 2 done 0\n@@ stopped\n")
    m.hold_at = (3, "tool")
    b = m.spawn(_argv(make_plan(m), "bbbb"))
    b.resume()
    assert b.poll() == 0
    assert m.facts().made().members == ("pat",)


def test_wait_for_answers_once_ended():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    assert standin.wait_for(m.spawn(_argv(make_plan(m)))) == 0
