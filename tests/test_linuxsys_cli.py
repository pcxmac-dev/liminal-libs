"""The system and the root command (liminal_libs.linuxsys.system, LinuxSystem, cli, __main__): the facts and the
listing kept, the digest, one sudo per confirmed click, asked twice where no password is asked, the lock; the
command's words and exit codes on stand-in machines, the same script as the page's, what its entry loads and what it
writes (the linuxperm plan's 3.5, 3.7, 3.9, S8, S14, S16, M5). Nothing here runs a process."""
from __future__ import annotations

import io
import runpy
import sys

import pytest

import liminal_libs.linuxsys as linuxsys
from liminal_libs.linuxsys import accounts, cli, elevation, journal, plan, shared, standin

pytestmark = pytest.mark.usefixtures("no_outside")

UBUNTU = "wsl-ubuntu-24.04"
NEVER = ("liminal_libs.apps", "liminal_libs.sources", "liminal_libs.machines", "liminal_libs.lifecycle",
         "liminal_libs.claims", "liminal_libs.layout", "liminal_libs.storage", "liminal_libs.internal",
         "liminal_libs.nodes", "liminal_libs.stop")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def page(m: standin.Machine, clock=None) -> linuxsys.LinuxSystem:
    return linuxsys.LinuxSystem(m.run, m.spawn, clock=clock or Clock(), python="/opt/py/bin/python")


def root(name: str = UBUNTU, overlay=None) -> standin.Machine:
    m = standin.Machine(name, overlay)
    m.data["id"] = "0 root"
    return m


def command(m: standin.Machine, *argv, env=None, euid=0):
    out, err = io.StringIO(), io.StringIO()
    s = linuxsys.LinuxSystem(m.run, m.spawn, clock=Clock(), python="/opt/py/bin/python", command=True)
    code = cli.main(list(argv), system=s, euid=euid, env=env or {}, out=out, err=err, signals=False)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture(autouse=True)
def _bytecode(monkeypatch):
    monkeypatch.setattr(sys, "dont_write_bytecode", sys.dont_write_bytecode)


# ---- LinuxSystem -------------------------------------------------------------------------------------------------


def test_the_facts_and_sudo_s_listing_are_kept_and_the_listing_read_once_per_sudo_s():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    clock = Clock()
    s = page(m, clock)
    for _ in range(3):
        s.facts(fresh=True)
        s.elevation()
    listings = [c for c in m.calls if c["argv"] == list(shared.SUDO_LIST)]
    assert len(listings) == 1  # whatever `fresh` says
    clock.now += linuxsys.SUDO_S + 1
    s.elevation()
    assert len([c for c in m.calls if c["argv"] == list(shared.SUDO_LIST)]) == 2
    probes = len([c for c in m.calls if c["argv"][0] == "/bin/sh"])
    s.facts()
    assert len([c for c in m.calls if c["argv"][0] == "/bin/sh"]) == probes  # kept FACTS_S


def test_a_change_runs_one_sudo_per_confirmed_click_and_reads_the_facts_again():
    m = standin.Machine(UBUNTU)
    s = page(m)
    change = s.plan_make()
    done = s.apply(change, standin.PASSWORD, digest=change.digest)
    assert done["code"] == 0 and done["said"] == "done" and m.sudo_runs == 1
    assert done["lines"][0].startswith("1. make the folder /etc/sysusers.d")
    assert s.made.members == ("pat",) and s.plan_make().plan.nothing


def test_a_digest_other_than_the_one_confirmed_is_refused_before_sudo_and_the_facts_dropped():
    m = standin.Machine(UBUNTU)
    s = page(m)
    change = s.plan_make()
    probes = len(m.calls)
    with pytest.raises(shared.Refused, match="this system changed since you confirmed"):
        s.apply(change, standin.PASSWORD, digest="0" * 64)
    assert m.sudo_runs == 0 and len(m.calls) == probes
    s.facts()
    assert len(m.calls) == probes + 1  # read again


def test_an_ask_not_accepted_is_refused_before_sudo_starts():
    m = standin.Machine(UBUNTU)
    s = page(m)
    s.apply(s.plan_make(), standin.PASSWORD)
    undo = s.plan_undo()
    spawns = m.sudo_runs
    with pytest.raises(shared.Refused) as e:
        s.apply(undo, standin.PASSWORD, digest=undo.digest)
    assert e.value.accept == "accept_removal" and m.sudo_runs == spawns
    assert len([c for c in m.calls if c["argv"][0] == "/usr/bin/env" and "-S" in c["argv"]]) == 1
    s.apply(undo, standin.PASSWORD, digest=undo.digest, accept_removal=True)
    assert m.sudo_runs == spawns + 1 and s.facts().liminal["group"] is None


def test_where_no_password_is_asked_every_change_is_asked_twice_on_the_page():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    s = page(m)
    change = s.plan_make()
    assert ("accept_unasked", linuxsys.UNASKED) in change.asks
    with pytest.raises(shared.Refused) as e:
        s.apply(change)
    assert e.value.accept == "accept_unasked" and m.sudo_runs == 0
    assert s.apply(change, accept_unasked=True)["code"] == 0


def test_one_second_confirmation_holds_every_sentence_of_a_click():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    m.files["/etc/passwd"] += "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n"
    s = page(m)
    s.apply(s.plan_make(), accept_unasked=True)
    add = s.plan_member("alice", "add")
    with pytest.raises(shared.Refused) as e:
        add.check()
    assert e.value.accept == "accept_member accept_unasked"
    assert "it gives alice every Liminal privilege." in str(e.value) and linuxsys.UNASKED in str(e.value)


def test_a_plan_of_nothing_runs_nothing():
    m = standin.Machine("service-account")
    s = page(m)
    change = s.plan_make()
    assert change.plan.nothing
    assert s.apply(change)["said"].startswith("nothing to do") and m.sudo_runs == 0


def test_a_change_while_another_runs_is_refused_by_the_system_s_own_lock():
    m = standin.Machine(UBUNTU)
    s = page(m)
    assert s._lock.acquire(blocking=False)
    try:
        with pytest.raises(shared.Refused, match=plan.HELD):
            s.apply(s.plan_make(), standin.PASSWORD)
    finally:
        s._lock.release()
    assert m.sudo_runs == 0


def test_a_wrong_password_changes_nothing_and_can_be_typed_again():
    m = standin.Machine(UBUNTU)
    s = page(m)
    change = s.plan_make()
    with pytest.raises(plan.WrongPassword):
        s.apply(change, "not it")
    assert s.apply(change, standin.PASSWORD)["code"] == 0


def test_describe_holds_the_way_the_accounts_and_the_lines():
    d = page(standin.Machine(UBUNTU)).describe()
    assert d["elevation"]["field"] == "yes" and d["accounts"]["tool"] == "sysusers"
    assert d["lines"]["apply"] == "sudo /opt/py/bin/python -I -B -m liminal_libs.linuxsys apply"
    assert d["facts"]["made"]["group"] is None


def test_system_off_linux_without_a_runner_says_why(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(shared.Refused, match="runs Windows"):
        linuxsys.system()
    assert isinstance(linuxsys.system(standin.Machine(UBUNTU).run), linuxsys.LinuxSystem)


# ---- the command ------------------------------------------------------------------------------------------------


def test_the_command_s_script_is_the_page_s_byte_for_byte():
    user = standin.Machine(UBUNTU)
    as_root = root()
    mine = page(user).plan_make().plan.script()
    s = linuxsys.LinuxSystem(as_root.run, as_root.spawn, clock=Clock(), command=True, who="pat")
    assert s.plan_make().plan.script() == mine


def test_apply_as_root_makes_them_for_sudo_user_and_again_is_nothing():
    m = root()
    first = m.snapshot()
    code, out, err = command(m, "apply", env={"SUDO_USER": "pat"})
    assert code == 0, err
    assert m.groups()["liminal"].members == ("pat",) and "liminal" in m.users()
    assert out.rstrip().endswith("done") and m.calls[-1]["argv"][:2] == ["/bin/sh", "-c"]
    assert command(m, "apply", env={"SUDO_USER": "pat"})[1].rstrip().endswith("nothing to do: it is all here")
    code, out, err = command(m, "undo")
    assert code == 2 and "--yes" in err
    assert command(m, "undo", "--yes")[0] == 0
    assert m.snapshot() == first


def test_apply_unattended_adds_no_member_and_accounts_alone_makes_no_user():
    m = root()
    assert command(m, "apply", "accounts", "--unattended")[0] == 0
    assert m.groups()["liminal"].members == () and "liminal" not in m.users()


def test_the_member_is_never_root_and_pkexec_s_uid_is_named():
    m = root()
    assert command(m, "apply", "--for", "root")[0] == 2
    assert command(m, "apply", env={"PKEXEC_UID": "1000"})[0] == 0
    assert m.groups()["liminal"].members == ("pat",)


def test_member_add_of_someone_else_needs_yes():
    m = root()
    m.files["/etc/passwd"] += "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n"
    command(m, "apply", env={"SUDO_USER": "pat"})
    code, _, err = command(m, "member", "add", "alice", env={"SUDO_USER": "pat"})
    assert code == 2 and "every Liminal privilege" in err and "--yes" in err
    assert command(m, "member", "add", "alice", "--yes", env={"SUDO_USER": "pat"})[0] == 0
    assert m.groups()["liminal"].members == ("pat", "alice")


def test_not_root_is_3_and_says_how_to_run_it_here():
    code, _, err = command(standin.Machine(UBUNTU), "apply", euid=1000)
    assert code == 3 and "sudo /opt/py/bin/python -I -B -m liminal_libs.linuxsys apply" in err


def test_facts_check_and_plan_need_no_root():
    m = standin.Machine(UBUNTU)
    code, out, _ = command(m, "facts", euid=1000)
    assert code == 0 and '"tool": "sysusers"' in out
    code, out, _ = command(m, "plan", "--for", "pat", euid=1000)
    assert code == 0 and "digest " in out and "1. make the folder /etc/sysusers.d" in out
    code, out, _ = command(standin.Machine("nixos-26.05"), "check", euid=1000)
    assert code == 2 and "configuration.nix" in out


@pytest.mark.parametrize("argv", [["nothing"], ["apply", "--bogus"], ["member", "add"], ["apply", "--for"],
                                  ["apply", "--unattended", "--for", "pat"]])
def test_a_usage_error_is_4(argv):
    assert command(root(), *argv)[0] == 4


def test_a_stop_after_a_step_is_5_and_a_failed_step_is_1():
    m = root()
    m.term_at = (2, "tool")
    code, out, _ = command(m, "apply", "--for", "pat")
    assert code == 5 and "stopped after step 2 of 4" in out
    m.term_at = None
    m.data["tools"].pop("gpasswd")
    code, out, _ = command(m, "apply", "--for", "pat")
    assert code == 1 and "failed" in out
    m.data["tools"]["gpasswd"] = "/usr/bin/gpasswd"
    assert command(m, "apply", "--for", "pat")[0] == 0  # it goes on from there


def test_a_refused_plan_is_2():
    code, _, err = command(root("container-bare"), "apply")
    assert code == 2 and "no account tool" in err


def test_the_command_writes_nothing_outside_its_plan(tmp_path, monkeypatch):
    for var in ("HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "LOCALAPPDATA", "APPDATA"):
        (tmp_path / var).mkdir()
        monkeypatch.setenv(var, str(tmp_path / var))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "dont_write_bytecode", False)
    m = root()
    before = sorted(p.name for p in tmp_path.rglob("*"))
    assert command(m, "apply", "--for", "pat")[0] == 0
    assert sys.dont_write_bytecode is True
    assert sorted(p.name for p in tmp_path.rglob("*")) == before


def test_the_real_entry_loads_no_frame_plugin_or_ledger(monkeypatch):
    saved = {k: v for k, v in sys.modules.items() if k == "liminal_libs" or k.startswith("liminal_libs.")}
    for k in saved:
        del sys.modules[k]
    monkeypatch.setattr(sys, "argv", ["linuxsys", "--help"])
    try:
        with pytest.raises(SystemExit) as e:
            runpy.run_module("liminal_libs.linuxsys", run_name="__main__")
        loaded = {k for k in sys.modules if k.startswith("liminal_libs.")}
        assert e.value.code == 0
        assert not [k for k in loaded if k.startswith(NEVER)], loaded
        assert sys.dont_write_bytecode is True
    finally:
        for k in [k for k in sys.modules if k == "liminal_libs" or k.startswith("liminal_libs.")]:
            del sys.modules[k]
        sys.modules.update(saved)


def test_main_runs_only_as_the_program():
    import importlib
    importlib.import_module("liminal_libs.linuxsys.__main__")  # imported, as tests/test_imports.py does: runs nothing


def test_the_words_of_every_change_are_free_of_the_password():
    m = standin.Machine(UBUNTU)
    s = page(m)
    with pytest.raises(plan.WrongPassword) as e:
        s.apply(s.plan_make(), "a wrong one")
    assert "a wrong one" not in str(e.value)
    done = s.apply(s.plan_make(), standin.PASSWORD)
    assert standin.PASSWORD not in repr(done)
    assert all(standin.PASSWORD not in " ".join(c["argv"]) for c in m.calls)
    assert isinstance(elevation.NOTE, str) and accounts.PARTS == ("accounts", "service-user")
    assert journal.PATH == "/var/lib/liminal-linux/MADE"
