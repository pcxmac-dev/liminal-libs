"""The Linux standard interface (liminal_libs.machines.linuxadmin, LinuxAdmin): its hooks and gates, the page's two
sections and their forms sent as the platform's page sends them, one sudo per confirmed click, asked twice where no
password is asked, the digest, the found group, the password field offered again, app_stopping inside the platform's
stop, and the contract's node check (the linuxperm plan's 3.5, 3.9, B1 fix 5, M5, S16). Every machine is a recorded
one; nothing here runs a process."""
from __future__ import annotations

import inspect
import json
import threading
import time

import pytest

from liminal_libs import internal, lifecycle
from liminal_libs.apps import asking
from liminal_libs.linuxsys import elevation, plan, shared, standin
from liminal_libs.linuxsys.accounts import Change
from liminal_libs.machines import linuxadmin
from liminal_libs.machines.linuxadmin import LinuxAdmin
from liminal_libs.sources import conformance

pytestmark = pytest.mark.usefixtures("no_outside")

UBUNTU = "wsl-ubuntu-24.04"
ALICE = "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n"


class Linux(LinuxAdmin):
    """A Linux administration on a recorded machine: its reads and sudo the stand-in's."""

    name = "linux-test"
    title = "Linux test"
    about = "A LinuxAdmin on a recorded machine"
    api = "2.1"  # no API cards: admin-linux's are its own

    def __init__(self, machine: standin.Machine | None = None, native: str = ""):
        self._m = machine or standin.Machine(UBUNTU)
        self._native = native
        self._python = "/opt/py/bin/python"

    def linux_run(self, argv, timeout):
        return self._m.run(argv, timeout)

    def linux_spawn(self, argv):
        return self._m.spawn(argv)

    def not_for_here(self) -> str:
        return self._native

    def present(self) -> bool:
        return not self._native

    def elevated(self) -> bool:
        return self._m.euid == 0

    def elevation(self) -> str:
        return "the platform runs as root" if self._m.euid == 0 else "not root"

    def services(self):
        return []

    def startups(self):
        return []

    def processes(self):
        return []


def forms(p: LinuxAdmin) -> dict:
    return {f["id"]: f for f in p.status()["forms"]}


def args_of(form: dict, accepted=(), password=None) -> list:
    """The hook's arguments as the platform's page sends them (platform.js argsOf): each field in order, an accept
    true only through its own confirmation, a password only where the form has its field."""
    out = []
    for x in form["fields"]:
        if x["type"] == "accept":
            out.append(x["name"] in accepted)
        elif x["type"] == "password":
            out.append(password)
        else:
            out.append(x["value"])
    return out


def send(p: LinuxAdmin, form: dict, accepted=(), password=None):
    with asking.asking(asking.PAGE):
        return getattr(p, form["hook"])(*args_of(form, accepted, password))


def click(p: LinuxAdmin, form: dict, password=None):
    """One confirmed click as the page makes it: sent; a refusal naming an accept of the form, confirmed once, then
    sent again with it."""
    try:
        return send(p, form, (), password)
    except shared.Refused as e:
        names = [x["name"] for x in form["fields"] if x["type"] == "accept"]
        if not e.accept or e.accept not in names:
            raise
        return send(p, form, (e.accept,), password)


# ---- the hooks and their gates ---------------------------------------------------------------------------------------


def test_its_hooks_their_gates_and_their_arguments_are_words():
    p = Linux()
    for hook in ("linux_facts", "linux_apply", "linux_member", "linux_undo"):
        assert hook in p.HOOKS and p.gives(hook)
    assert set(internal.page_only(p)) >= {"linux_apply", "linux_member", "linux_undo"}
    assert internal.plugin_only(p) == ()  # none carries a command (B1)
    assert "linux_facts" in internal.declared(p, "READ_HOOKS")
    assert "linux_facts" in internal.declared(p, "SERVICE_HOOKS")
    for hook in ("linux_facts", "linux_apply", "linux_member", "linux_undo"):
        for param in inspect.signature(getattr(p, hook)).parameters.values():
            assert param.default is inspect.Parameter.empty or param.default in (False, None), (hook, param)
            assert param.kind is param.POSITIONAL_OR_KEYWORD


@pytest.mark.parametrize("who", ["firewall-linux", None])
def test_a_change_asked_by_another_plugin_or_by_no_one_is_refused_in_words(who):
    m = standin.Machine(UBUNTU)
    p = Linux(m)
    form = forms(p)["linux-make"]
    calls = len(m.calls)
    with asking.asking(who), pytest.raises(asking.AskRefused, match="asked only from its page"):
        p.linux_apply(*args_of(form, password=standin.PASSWORD))
    with pytest.raises(asking.AskRefused):  # no asker handed over at all
        p.linux_undo("0" * 64)
    assert m.sudo_runs == 0 and len(m.calls) == calls  # nothing read, nothing started


def test_linux_facts_is_anyone_s_read_and_holds_json():
    m = standin.Machine(UBUNTU)
    p = Linux(m)
    with asking.asking("firewall-linux"):
        facts = p.linux_facts()
    assert facts["applies"] and facts["elevation"]["field"] == "yes" and facts["accounts"]["group"] is None
    assert json.loads(json.dumps(facts)) == facts
    assert Linux(native="Linux administration is for the Linux the platform runs on").linux_facts()["applies"] is False


# ---- the page ------------------------------------------------------------------------------------------------------


def test_the_page_draws_its_two_sections_first_and_this_linux_last():
    p = Linux()
    status = p.status()
    titles = [t["title"] for t in status["tables"]]
    assert titles[:2] == ["How root is had", "Liminal's user and group"] and titles[-1] == "This Linux"
    assert "Services the framework relies on" in titles
    root = status["tables"][0]["rows"][0]
    assert root[0]["text"] == "sudo" and root[1]["text"].startswith("a password")
    assert root[2] == elevation.LOGGED
    make = forms(p)["linux-make"]
    assert [x["name"] for x in make["fields"]] == ["parts", "digest", "accept_members", "accept_unasked", "password"]
    assert make["fields"][-1]["type"] == "password" and make["fields"][-1]["label"] == "Your password for sudo"
    assert "linux-undo" not in forms(p)  # nothing of Liminal's to take back yet
    assert status["summary"].endswith(f"the group {linuxadmin.NAME}: not here")


def test_make_them_runs_one_sudo_and_the_next_status_says_start_the_platform_again():
    m = standin.Machine(UBUNTU)
    p = Linux(m)
    done = click(p, forms(p)["linux-make"], standin.PASSWORD)
    assert done["ok"] and done["said"] == "done" and m.sudo_runs == 1
    assert standin.PASSWORD not in json.dumps(done)
    status = p.status()
    rows = status["tables"][1]["rows"]
    assert rows[0][1]["sub"].startswith("a system group; made by Liminal")
    pat = next(r for r in rows if isinstance(r[0], dict) and r[0]["text"] == "pat")
    assert pat[1] == "a member; not yet in the running platform: start the platform again from a new terminal tab"
    assert "linux-make" not in forms(p) and "linux-undo" in forms(p)
    assert pat[2]["form"] == "linux-member-remove:pat"


def test_apply_then_remove_them_gives_the_first_tree_back():
    m = standin.Machine(UBUNTU)
    first = m.snapshot()
    p = Linux(m)
    click(p, forms(p)["linux-make"], standin.PASSWORD)
    undo = forms(p)["linux-undo"]
    with pytest.raises(shared.Refused) as e:  # always asked twice
        send(p, undo, (), standin.PASSWORD)
    assert e.value.accept == "accept_removal" and m.sudo_runs == 1
    done = send(p, undo, ("accept_removal",), standin.PASSWORD)
    assert done["ok"] and m.sudo_runs == 2 and m.snapshot() == first


def test_a_digest_other_than_the_one_confirmed_is_refused_before_sudo_and_the_facts_are_read_again():
    m = standin.Machine(UBUNTU)
    p = Linux(m)
    form = forms(p)["linux-make"]
    args = args_of(form, password=standin.PASSWORD)
    args[1] = "f" * 64
    with asking.asking(asking.PAGE), pytest.raises(shared.Refused, match="changed since you confirmed"):
        p.linux_apply(*args)
    with asking.asking(asking.PAGE), pytest.raises(shared.Refused, match="sha256"):
        p.linux_apply(args[0], "not a digest", False, False, standin.PASSWORD)
    assert m.sudo_runs == 0 and click(p, forms(p)["linux-make"], standin.PASSWORD)["ok"]


def test_where_no_password_is_asked_every_change_is_asked_twice_and_sudo_runs_once():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    p = Linux(m)
    make = forms(p)["linux-make"]
    assert "password" not in [x["name"] for x in make["fields"]]
    assert p.status()["tables"][0]["rows"][0][1]["text"] == linuxadmin.ASKS["no"]
    with pytest.raises(shared.Refused) as e:
        send(p, make)
    assert e.value.accept == "accept_unasked" and str(e.value).startswith("no password is asked here")
    assert m.sudo_runs == 0
    assert send(p, make, ("accept_unasked",))["ok"] and m.sudo_runs == 1


def test_a_click_gets_one_second_confirmation_for_every_sentence_it_asks():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    m.files["/etc/passwd"] += ALICE
    p = Linux(m)
    click(p, forms(p)["linux-make"])
    add = forms(p)["linux-member-add:alice"]
    with pytest.raises(shared.Refused) as e:
        send(p, add)
    assert e.value.accept == "accept_member"  # one plain name, as the platform's page takes it
    assert "it gives alice every Liminal privilege" in str(e.value) and "no password is asked here" in str(e.value)
    runs = m.sudo_runs
    assert send(p, add, (e.value.accept,))["ok"] and m.sudo_runs == runs + 1
    assert "alice" in m.groups()["liminal"].members


def test_the_accepts_count_from_the_first_one_given():
    steps = (plan.Step("a step", plan.Action.of("member", user="pat", group="liminal", tool="sysusers"), "false",
                       ": a"),)
    change = Change(plan.Plan("member", steps), (("accept_member", "one"), ("accept_unasked", "two")))
    assert linuxadmin._accepts(change, {"accept_member": True}) == {"accept_member": True, "accept_unasked": True}
    assert linuxadmin._accepts(change, {"accept_unasked": True}) == {"accept_member": False, "accept_unasked": True}
    with pytest.raises(shared.Refused) as e:
        change.check(**linuxadmin._accepts(change, {"accept_unasked": True}))
    assert linuxadmin._one_accept(e.value).accept == "accept_member" and str(e.value) == "one."
    with pytest.raises(shared.Refused) as e:
        change.check(**linuxadmin._accepts(change, {}))
    one = linuxadmin._one_accept(e.value)
    assert one.accept == "accept_member" and str(one) == "one. two."


def test_a_wrong_password_is_one_failed_try_and_the_form_is_offered_again():
    m = standin.Machine(UBUNTU)
    p = Linux(m)
    make = forms(p)["linux-make"]
    with pytest.raises(plan.WrongPassword) as e:
        send(p, make, (), "not it")
    assert isinstance(e.value, ValueError) and "not it" not in str(e.value) and not m.eof_at_prompt
    assert m.calls[-1]["stdin"] == b"not it\n" and m.sudo_runs == 0
    assert click(p, forms(p)["linux-make"], standin.PASSWORD)["ok"]


def test_sudo_asking_where_its_listing_said_none_offers_the_field_and_takes_the_password():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    m.data["sudo"]["asks"] = True  # the listing says NOPASSWD: ALL, yet sudo asks (a rule after it, a PAM stack)
    p = Linux(m)
    with pytest.raises(elevation.PasswordNeeded):
        click(p, forms(p)["linux-make"])
    make = forms(p)["linux-make"]
    assert make["fields"][-1]["type"] == "password"
    assert click(p, make, standin.PASSWORD)["ok"] and m.sudo_runs == 1


def test_where_a_terminal_or_nothing_gives_root_the_page_shows_the_command_and_no_form():
    for name, why in (("alpine-3.24", "takes a password only from a terminal"),
                      ("service-account", "Liminal's service account, which has no password")):
        p = Linux(standin.Machine(name))
        assert not [f for f in forms(p) if f.startswith("linux-")]
        rows = p.status()["tables"][1]["rows"]
        assert any(r[0] == "Changes here" and why in r[1] for r in rows)
        assert rows[-1][0] == "The one command" and "-I -B -m liminal_libs.linuxsys apply" in rows[-1][1]["text"]


def test_not_for_here_asks_nothing_and_refuses_a_change():
    p = Linux(native="Linux administration is for the Linux the platform runs on, and this one runs Windows")
    assert p.status()["applies"] is False and p._m.calls == []
    with asking.asking(asking.PAGE), pytest.raises(shared.Refused, match="runs Windows"):
        p.linux_undo("0" * 64)


# ---- the stop ------------------------------------------------------------------------------------------------------


def test_a_stop_while_sudo_waits_at_its_marker_kills_it_and_every_change_then_refuses():
    m = standin.Machine(UBUNTU)
    p = Linux(m)
    form = forms(p)["linux-make"]
    procs, stoppers = [], []

    def spawn(argv):
        procs.append(m.spawn(argv))
        stoppers.append(threading.Thread(target=p.app_stopping))  # the platform's TERM, sudo at its prompt
        stoppers[-1].start()
        time.sleep(0.05)
        return procs[-1]

    p.linux_spawn = spawn
    with pytest.raises(shared.Refused, match="stopped before the change began"):
        send(p, form, (), standin.PASSWORD)
    stoppers[0].join(2)
    assert not stoppers[0].is_alive() and procs[0].killed_at == "prompt" and m.sudo_runs == 0
    assert m.files.get("/var/lib/liminal-linux/MADE") is None
    with pytest.raises(shared.Refused, match=linuxadmin.STOPPING):
        send(p, form, (), standin.PASSWORD)
    p.attach(None, None)  # a platform started again in this process
    del p.linux_spawn
    assert click(p, forms(p)["linux-make"], standin.PASSWORD)["ok"]


def test_a_stop_while_the_script_runs_lets_its_step_finish_and_the_next_status_says_what_is_left():
    m = standin.Machine(UBUNTU)
    m.hold_at = (2, "tool")
    p = Linux(m)
    form = forms(p)["linux-make"]
    stopper = threading.Timer(0.3, p.app_stopping)
    stopper.start()
    try:
        done = send(p, form, (), standin.PASSWORD)
    finally:
        stopper.join(linuxadmin.STEP_WAIT_S + 1)
    assert not done["ok"] and done["said"] == "stopped after step 2 of 4: running it again finishes it"
    assert not stopper.is_alive()
    p.attach(None, None)
    rows = p.status()["tables"][1]["rows"]
    stopped = next(r for r in rows if r[0] == "A change stopped part way")
    assert stopped[1].startswith("Make them... stopped part way")
    assert stopped[1].endswith("Make them... again finishes it")
    assert click(p, forms(p)["linux-make"], standin.PASSWORD)["ok"]


def test_app_stopping_waits_at_most_step_wait_s_inside_the_platform_s_deadline():
    assert linuxadmin.STEP_WAIT_S < lifecycle.PLUGINS_DEADLINE_S
    p = Linux()
    p.STEP_WAIT_S = 0.2
    st = p._linux_state()
    st.busy = 1  # a change that does not finish
    began = time.monotonic()
    p.app_stopping()
    assert 0.15 <= time.monotonic() - began < 1.0 and st.stop.is_set()
    p.app_stopping()  # it bears a second call


def test_a_copy_has_its_own_stop_and_system():
    p = Linux()
    p.linux_system()
    copy = p.with_()
    copy.app_stopping()
    assert copy.linux_system() is not p.linux_system() and not p._linux_state().stop.is_set()


# ---- the contract --------------------------------------------------------------------------------------------------


def test_it_conforms_and_serves_as_a_node():
    p = Linux()
    assert conformance.problems(p) == []
    assert conformance.node_problems(p) == []
