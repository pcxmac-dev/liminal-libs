"""Liminal's group and user (liminal_libs.linuxsys.accounts) on every recorded machine: the tool chosen, every refusal's
words, the plans' scripts, apply twice, apply then undo, and apply and undo stopped after each step at three points
then run again, each giving the first snapshot back (the linuxperm plan's 3.2, 3.6, 3.9 and B4). The stand-in plays
each step's Action; nothing runs."""
from __future__ import annotations

import pytest

from liminal_libs.linuxsys import accounts, facts, journal, plan, shared, standin

pytestmark = pytest.mark.usefixtures("no_outside")

UBUNTU = "wsl-ubuntu-24.04"
# the machines a whole round trip runs on: (name, overlay, the tool)
ROUND = [(UBUNTU, None, "sysusers"), (UBUNTU, "nopasswd-all", "sysusers"), ("ubuntu-26.04", None, "sysusers"),
         ("debian-13", None, "sysusers"), ("fedora-45", None, "sysusers"), ("opensuse-tumbleweed", None, "sysusers"),
         ("alpine-3.24", None, "busybox"), ("collision", None, "sysusers"), ("shadow", None, "shadow"),
         (UBUNTU, "firewall-group", "sysusers")]


def machine(name: str, overlay: str | None = None) -> standin.Machine:
    """A recorded machine; "shadow" is Debian 13 with another sysusers under systemd's name (opensysusers), so shadow's
    tools are taken; firewall-group's grant is taken back first, as undo asks."""
    if name == "shadow":
        m = standin.Machine("debian-13")
        m.data["versions"]["systemd-sysusers"] = "opensysusers 0.7.3"
        return m
    m = standin.Machine(name, overlay)
    if overlay == "firewall-group":
        m.files.pop("/etc/sudoers.d/liminal-firewall")
    return m


def tool(m: standin.Machine) -> accounts.AccountTool:
    return accounts.tool(m.facts())


def member(m: standin.Machine) -> str | None:
    f = m.facts()
    return None if f.elevation["euid"] == 0 else f.elevation["user"]


def make(m: standin.Machine) -> accounts.Change:
    return tool(m).make(member=member(m))


# ---- the tool and the refusals -----------------------------------------------------------------------------------


@pytest.mark.parametrize("name, overlay, kind", ROUND)
def test_the_tool_chosen(name, overlay, kind):
    assert tool(machine(name, overlay)).kind == kind


def test_the_user_s_ubuntu_gets_the_sysusers_file_and_one_gpasswd():
    m = machine(UBUNTU)
    c = make(m)
    assert [s.action.kind for s in c.plan.steps] == ["folder", "file", "sysusers", "member"]
    assert c.plan.steps[1].action["text"] == accounts.conf_text(True, "/usr/sbin/nologin")
    assert c.plan.steps[2].do == "systemd-sysusers /etc/sysusers.d/liminal.conf"
    assert c.plan.steps[3].do == "gpasswd -a 'pat' liminal" and c.asks == ()
    script = c.plan.script()
    assert "/usr/local" not in script.replace("/usr/local/sbin:/usr/local/bin:", "")  # release one writes none there
    assert accounts.conf_text(True, "/usr/sbin/nologin") == standin.Machine("service-account").files[facts.SYSUSERS]


def test_shadow_s_commands_are_each_checked_first_and_never_usermod_g_without_a():
    m = machine("shadow")
    c = make(m)
    assert [s.action.kind for s in c.plan.steps] == ["group", "user", "member"]
    group, user, add = c.plan.steps
    assert group.do == "groupadd --system liminal" and group.check == "[ -n \"$(lm_gid liminal)\" ]"
    assert user.do == ("useradd --system --gid liminal --no-create-home --home-dir /var/lib/liminal --shell "
                       "'/usr/sbin/nologin' --comment Liminal --expiredate '' liminal")
    assert add.do == "gpasswd -a 'pat' liminal"
    m.play(c.plan)
    script = tool(m).undo().plan.script()
    assert "usermod -G" not in script and "userdel liminal" in script and "groupdel liminal" in script


def test_busybox_s_applets():
    c = make(machine("alpine-3.24"))
    assert [s.do for s in c.plan.steps] == [
        "addgroup -S liminal", "adduser -S -D -H -h /var/lib/liminal -s '/sbin/nologin' -G liminal -g Liminal liminal",
        "addgroup 'pat' liminal"]


@pytest.mark.parametrize("name, overlay, words", [
    ("nixos-26.05", None, "users.users.pat.extraGroups = [ \"liminal\" ];"),
    ("container-bare", None, "no account tool Liminal knows is here"),
    ("collision", "group-1001", "a group named liminal is here and is not a system group (gid 1001)"),
    ("collision", "person-user", "a user named liminal is here and is a person's account (uid 1001)"),
    ("collision", "system-group-mixed", "has the member www-data, a system account"),
])
def test_what_is_refused_and_its_words(name, overlay, words):
    c = make(machine(name, overlay))
    assert words in c.plan.refused and not c.plan.steps
    with pytest.raises(shared.Refused):
        c.plan.script()


def test_nixos_is_told_the_lines_and_nixos_rebuild():
    refused = make(machine("nixos-26.05")).plan.refused
    assert "/etc/nixos/configuration.nix" in refused and "nixos-rebuild switch" in refused
    assert "users.groups.liminal = { };" in refused


def test_a_read_only_etc_is_refused():
    m = machine(UBUNTU)
    m.files["/proc/mounts"] = "overlay / overlay ro,relatime 0 0\n"
    assert make(m).plan.refused.startswith("/etc is read-only here")


def test_a_found_system_group_with_a_person_in_it_is_asked_twice_by_name():
    m = machine("collision", "system-group-mixed")
    m.files["/etc/group"] = m.files["/etc/group"].replace("liminal:x:990:alice,www-data", "liminal:x:990:alice")
    c = make(m)
    assert not c.plan.refused and c.asks == (("accept_members", "the group liminal is here already with alice in it: "
                                                                "once a grant names %liminal, alice gets every "
                                                                "Liminal privilege"),)
    with pytest.raises(shared.Refused) as e:
        c.check()
    assert e.value.accept == "accept_members" and "alice" in str(e.value)
    c.check(accept_members=True)


def test_names_from_outside_are_cleaned_before_any_script():
    m = machine(UBUNTU)
    for bad in ("pat'x", "pat\nroot", "a$b", "%s", "Pat"):
        with pytest.raises(shared.Refused, match="lowercase letter"):
            tool(m).make(member=bad)
        with pytest.raises(shared.Refused, match="lowercase letter"):
            tool(m).member(bad, "add")
    assert tool(m).make(member="nosuch").plan.refused == "no user named nosuch is here: nothing was changed"


def test_root_and_system_accounts_are_never_members():
    m = machine(UBUNTU)
    m.play(make(m).plan)
    t = tool(m)
    assert t.member("root", "add").plan.refused.startswith("root is never a member")
    assert "is a system account" in t.member("www-data", "add").plan.refused


# ---- apply, apply again, undo ------------------------------------------------------------------------------------


@pytest.mark.parametrize("name, overlay, kind", ROUND)
def test_apply_twice_then_undo_gives_the_first_snapshot(name, overlay, kind):
    m = machine(name, overlay)
    first = m.snapshot()
    c = make(m)
    code, out, _ = m.play(c.plan)
    assert code == 0, out
    again = make(m)
    assert again.plan.nothing and again.asks == (), again.plan.words()
    undo = tool(m).undo()
    code, out, _ = m.play(undo.plan)
    assert code == 0, out
    if overlay == "firewall-group":
        # the group was the firewall's: it stays, with its members; Liminal's user left it first, and the journal
        # with the folders went
        assert m.groups()["liminal"].members == ("pat",) and "liminal" not in m.users()
        assert any("was here before Liminal" in n for n in undo.plan.notes)
    assert m.snapshot() == first
    assert tool(m).undo().plan.nothing


def _stops(name, overlay):
    m = machine(name, overlay)
    return [(name, overlay, n, point) for n in range(1, len(make(m).plan.steps) + 1) for point in standin.POINTS]


@pytest.mark.parametrize("name, overlay, n, point", [s for r in ROUND for s in _stops(*r[:2])])
def test_apply_stopped_after_any_step_then_again_then_undo_gives_the_first_snapshot(name, overlay, n, point):
    m = machine(name, overlay)
    first = m.snapshot()
    m.stop_at = (n, point)
    assert m.play(make(m).plan)[0] == -9
    m.stop_at = None
    assert tool(m).state()["stopped"] is not None
    code, out, _ = m.play(make(m).plan)
    assert code == 0, out
    assert make(m).plan.nothing
    code, out, _ = m.play(tool(m).undo().plan)
    assert code == 0, out
    assert m.snapshot() == first


def _undo_stops(name, overlay):
    m = machine(name, overlay)
    m.play(make(m).plan)
    return [(name, overlay, n, point) for n in range(1, len(tool(m).undo().plan.steps) + 1)
            for point in standin.POINTS]


@pytest.mark.parametrize("name, overlay, n, point", [s for r in ROUND for s in _undo_stops(*r[:2])])
def test_undo_stopped_after_any_step_then_undo_again_gives_the_first_snapshot(name, overlay, n, point):
    m = machine(name, overlay)
    first = m.snapshot()
    m.play(make(m).plan)
    m.stop_at = (n, point)
    code, _, _ = m.play(tool(m).undo().plan)
    m.stop_at = None
    assert code in (-9, 0)  # a step that found its work done already (userdel took the group) runs no tool
    again = tool(m).undo().plan
    if code == 0:
        assert again.nothing
    if not again.nothing:  # a plan of nothing is never run: its script would make the journal's folder again
        code, out, _ = m.play(again)
        assert code == 0, out
    assert m.snapshot() == first


def test_a_term_while_apply_runs_finishes_the_step_and_the_next_status_says_what_is_left():
    m = machine(UBUNTU)
    m.term_at = (2, "tool")
    c = make(m)
    code, out, _ = m.play(c.plan)
    assert code == 7 and c.plan.said(out, code)[1] == "stopped after step 2 of 4: running it again finishes it"
    stopped = tool(m).state()["stopped"]
    assert stopped["code"] == 7 and [s[2] for s in stopped["steps"]] == ["done", "done"]
    m.term_at = None
    assert [s.action.kind for s in make(m).plan.steps] == ["sysusers", "member"]


# ---- what undo keeps, and when it refuses ------------------------------------------------------------------------


def test_undo_refuses_while_a_grant_names_the_group_and_names_its_take_back_helper():
    m = standin.Machine(UBUNTU, "firewall-group")
    m.play(make(m).plan)
    undo = tool(m).undo()
    code, out, _ = m.play(undo.plan)
    assert code == 2 and out == "@@ refused grants /etc/sudoers.d/liminal-firewall\n"
    words = undo.plan.said(out, code)[1]
    assert words.startswith("take the grants back first: /etc/sudoers.d/liminal-firewall")
    assert "/usr/local/libexec/liminal/firewall/take-back" in words
    assert "liminal" in m.users()  # nothing was changed


def test_a_firewall_group_s_folder_gets_root_s_group_back_only_when_the_group_goes():
    m = machine(UBUNTU)
    m.play(make(m).plan)
    gid = m.groups()["liminal"].gid
    m.folders["/usr/local/libexec/liminal"] = plan.Folder(0, gid, 0o750)
    m.folders.setdefault("/usr/local/libexec", plan.Folder(0, 0, 0o755))
    steps = tool(m).undo().plan.steps
    assert [s.action.kind for s in steps].index("regroup") < [s.action.kind for s in steps].index("ungroup")
    assert m.play(tool(m).undo().plan)[0] == 0
    assert m.folders["/usr/local/libexec/liminal"].gid == 0


def test_busybox_keeps_a_user_made_in_a_group_it_found_and_says_why():
    m = machine("alpine-3.24")
    m.files["/etc/group"] += "liminal:x:150:pat\n"
    c = make(m)
    assert [s.action.kind for s in c.plan.steps] == ["user"]
    m.play(c.plan)
    undo = tool(m).undo()
    assert "unuser" not in [s.action.kind for s in undo.plan.steps]
    assert any("BusyBox's deluser would also remove the group liminal" in n for n in undo.plan.notes)
    m.play(undo.plan)
    assert "liminal" in m.users() and "liminal" in m.groups()
    assert m.files.get(journal.PATH) is not None  # the journal keeps what it could not take back


def test_busybox_undo_keeps_the_user_while_its_group_holds_a_member_liminal_did_not_add():
    # BusyBox's deluser removes the group of the user's name whatever its members: so no deluser while pat, added
    # with no journal line (by hand, or by the firewall's switch), is in Liminal's group
    m = machine("alpine-3.24")
    c = make(m)
    m.play(plan.Plan(c.plan.what, tuple(s for s in c.plan.steps if s.action.kind != "member"), guards=c.plan.guards,
                     lock=c.plan.lock))
    gid = m.groups()["liminal"].gid
    m.files["/etc/group"] = m.files["/etc/group"].replace(f"liminal:x:{gid}:", f"liminal:x:{gid}:pat")
    assert "pat" in m.groups()["liminal"].members
    undo = tool(m).undo()
    kinds = [s.action.kind for s in undo.plan.steps]
    assert "unuser" not in kinds and "ungroup" not in kinds and "unjournal" not in kinds
    assert any("BusyBox's deluser would also remove the group liminal, which pat is in" in n
               for n in undo.plan.notes)
    m.play(undo.plan)
    assert "liminal" in m.users() and "pat" in m.groups()["liminal"].members


def test_undo_keeps_a_group_holding_members_liminal_did_not_add():
    m = machine(UBUNTU)
    m.play(make(m).plan)
    t = tool(m)
    m.files["/etc/group"] = m.files["/etc/group"].replace(f"liminal:x:{t.group.gid}:pat",
                                                            f"liminal:x:{t.group.gid}:pat,syslog")
    undo = tool(m).undo()
    assert "ungroup" not in [s.action.kind for s in undo.plan.steps] and "unjournal" not in [
        s.action.kind for s in undo.plan.steps]
    assert any("syslog is in it and Liminal did not add them" in n for n in undo.plan.notes)


def test_undo_refuses_while_a_process_of_liminal_runs():
    m = machine(UBUNTU)
    m.play(make(m).plan)
    m.data["procs"] = ["/proc/812/status liminal-integrator"]
    assert tool(m).undo().plan.refused.startswith("a process of the user liminal runs (/proc/812/status")


def test_without_a_journal_undo_keeps_the_group_and_says_so():
    m = machine(UBUNTU)
    m.play(make(m).plan)
    m.files.pop(journal.PATH)
    undo = tool(m).undo()
    assert [s.action.kind for s in undo.plan.steps] == ["unfile", "move", "unuser"]
    assert any("no journal of Liminal's is here" in n for n in undo.plan.notes)


def test_undo_is_always_asked_twice():
    m = machine(UBUNTU)
    m.play(make(m).plan)
    undo = tool(m).undo()
    with pytest.raises(shared.Refused) as e:
        undo.check()
    assert e.value.accept == "accept_removal" and str(e.value).startswith("it removes what Liminal made here")


# ---- adoption, members -------------------------------------------------------------------------------------------


def test_liminal_s_own_wsl_distribution_adopts_its_login_user_and_never_removes_it():
    m = machine("liminal-ubuntu")
    first = m.snapshot()
    c = tool(m).make(member="liminal")
    assert [s.action.kind for s in c.plan.steps] == ["adopt"]
    assert m.play(c.plan)[0] == 0
    t = tool(m)
    assert t.made.adopted == (1000, 1000) and t.state()["user"]["by"] == "adopted"
    assert tool(m).make(member="liminal").plan.nothing
    assert "takes no member but Liminal's own" in t.member("syslog", "add").plan.refused
    undo = tool(m).undo()
    assert undo.plan.nothing and any("never removed" in n for n in undo.plan.notes)
    assert {p: x for p, x in m.snapshot()["files"].items() if p != journal.PATH} == first["files"]


def test_adding_and_removing_a_member_and_what_is_asked_twice():
    m = machine(UBUNTU)
    m.files["/etc/passwd"] += "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n"
    m.files["/etc/group"] += "alice:x:1001:\n"
    m.play(make(m).plan)
    t = tool(m)
    add = t.member("alice", "add")
    assert add.asks == (("accept_member", "it gives alice every Liminal privilege"),)
    m.play(add.plan)
    assert "alice" in m.groups()["liminal"].members
    assert tool(m).member("alice", "add").plan.nothing
    mine = tool(m).member("pat", "remove")
    assert mine.asks == (("accept_member", "the platform's Liminal rights end at its next start"),)
    assert tool(m).member("alice", "remove").asks == ()
    m.play(tool(m).member("alice", "remove").plan)
    assert m.groups()["liminal"].members == ("pat",)
    assert tool(m).member("alice", "remove").plan.nothing


def test_a_member_on_a_system_with_no_group_yet_is_told_to_make_them_first():
    refused = tool(machine(UBUNTU)).member("pat", "add").plan.refused
    assert refused == "the group liminal is not here: Make them... first"


def test_every_plan_s_script_is_under_the_limit_and_holds_its_guards():
    m = machine(UBUNTU)
    c = make(m)
    script = c.plan.script()
    assert len(script.encode()) < plan.SCRIPT_MAX and "@@ refused guard" in script
    m.play(c.plan)
    undo = tool(m).undo().plan.script()
    assert "@@ refused grants" in undo and undo.index("refused grants") < undo.index("lm_journal=1")
