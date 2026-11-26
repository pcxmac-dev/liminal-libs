"""How root is had (liminal_libs.linuxsys.elevation): the way picked on each recorded machine, the field and its label,
and the sudo conversation played over the stand-in's byte pipes (the linuxperm plan's S1, B2, M5, M19, M21). Nothing
here runs a process: every sudo is the stand-in's."""
from __future__ import annotations

import threading

import pytest

from liminal_libs.linuxsys import elevation, facts, plan, shared, standin
from liminal_libs.linuxsys.plan import Action, Plan, Step

pytestmark = pytest.mark.usefixtures("no_outside")

UBUNTU = "wsl-ubuntu-24.04"
CONF = "# Liminal: its group and user\ng liminal -\nu liminal -:liminal Liminal /var/lib/liminal /usr/sbin/nologin\n"


def step(kind: str, **args) -> Step:
    return Step(f"{kind} {args}", Action.of(kind, **args), "false", f": {kind}")


def make_plan(m: standin.Machine) -> Plan:
    f = m.facts()
    return Plan("apply", (plan.folder("/etc/sysusers.d"), plan.file(facts.SYSUSERS, CONF),
                          step("sysusers", path=facts.SYSUSERS, name="liminal", absent="group user", tool="sysusers"),
                          step("member", user="pat", group="liminal", tool="sysusers")),
                guards=(plan.group_guard("liminal", None),), lock=f.lock)


def way(m: standin.Machine) -> elevation.Elevation:
    return elevation.elevation(m.facts(), _listing(m), python="/opt/py/bin/python")


def _listing(m: standin.Machine):
    if not m.facts().elevation.get("sudo"):
        return None
    done = m.run(list(shared.SUDO_LIST))
    return done.returncode, done.stdout, done.stderr


# ---- the way, per machine ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("name, overlay, kind, field, whose", [
    (UBUNTU, None, elevation.Sudo, "yes", "self"),
    (UBUNTU, "nopasswd-all", elevation.Sudo, "no", "self"),
    ("ubuntu-26.04", None, elevation.Sudo, "yes", "self"),
    ("debian-13", None, elevation.Sudo, "yes", "self"),
    ("debian-13-su", None, elevation.Su, "terminal", "root"),
    ("fedora-45", None, elevation.Sudo, "yes", "self"),
    ("opensuse-tumbleweed", None, elevation.Sudo, "yes", "root"),
    ("alpine-3.24", None, elevation.Doas, "terminal", ""),
    ("nixos-26.05", None, elevation.Sudo, "yes", "self"),
    ("container-bare", None, elevation.AsRoot, "no", ""),
    ("service-account", None, elevation.Sudo, "impossible", "self"),
    ("liminal-ubuntu", None, elevation.Sudo, "impossible", "self"),
])
def test_the_way_root_is_had_on_each_machine(name, overlay, kind, field, whose):
    w = way(standin.Machine(name, overlay))
    assert type(w) is kind and w.words()["field"] == field and w.whose == whose
    if field == "yes":
        assert w.words()["note"] == elevation.NOTE and w.words()["logged"] == elevation.LOGGED
    if field in ("terminal", "impossible"):
        assert w.words()["why"] and "/opt/py/bin/python -I -B -m liminal_libs.linuxsys apply" in w.words()["why"]


def test_the_field_s_label_and_the_tools_by_their_paths():
    assert way(standin.Machine(UBUNTU)).label == "Your password for sudo"
    rs = way(standin.Machine("ubuntu-26.04"))
    assert rs.tool == "sudo-rs" and rs.label == "Your password for sudo-rs"
    assert way(standin.Machine("opensuse-tumbleweed")).label == "root's password (this system's sudo asks for it)"
    nix = way(standin.Machine("nixos-26.05"))
    assert nix.path == "/run/wrappers/bin/sudo"  # NixOS's set-uid wrapper first (S2)
    argv = nix.argv("SCRIPT", "feed")
    assert argv[1:9] == ["LC_ALL=C", "/run/wrappers/bin/sudo", "-S", "-k", "-u", "root", "-p",
                         "<<liminal-sudo:feed:%p>>"]
    assert argv[9:] == ["--", "/bin/sh", "-c", "SCRIPT", "liminal", "feed"]


def test_a_service_account_has_no_field_and_is_told_the_root_command():
    w = way(standin.Machine("service-account"))
    assert w.words()["field"] == "impossible" and w.words()["label"] == ""
    assert w.why().startswith("the platform runs as Liminal's service account, which has no password")
    with pytest.raises(shared.Refused, match="Liminal's service account"):
        w.run(make_plan(standin.Machine(UBUNTU)), "x", spawn=lambda argv: pytest.fail("no sudo is started"))


def test_may_not_run_sudo_means_doas_where_both_are_there():
    m = standin.Machine("alpine-3.24")
    f = m.facts()
    el = dict(f.elevation, sudo="/usr/bin/sudo", sudo_kind="sudo")
    from dataclasses import replace
    both = replace(f, elevation=el)
    assert type(elevation.elevation(both, (1, "", "Sorry, user pat may not run sudo on alpine.\n"))) is elevation.Doas
    assert type(elevation.elevation(both, (1, "", "sudo: a password is required\n"))) is elevation.Sudo


def test_the_one_command_for_each_tool():
    py = "/v/bin/python"
    assert elevation.command_line("sudo", "apply", py) == "sudo /v/bin/python -I -B -m liminal_libs.linuxsys apply"
    assert elevation.command_line("doas", "undo --yes", py).startswith("doas /v/bin/python -I -B")
    assert elevation.command_line("su", "apply", py) == "su -c '/v/bin/python -I -B -m liminal_libs.linuxsys apply'"
    assert elevation.command_line("run0", "apply", py).startswith("run0 ")
    assert elevation.command_line("root", "apply", py) == "/v/bin/python -I -B -m liminal_libs.linuxsys apply"


# ---- the conversation --------------------------------------------------------------------------------------------


def test_the_password_goes_on_standard_input_alone_after_the_marker_once():
    m = standin.Machine(UBUNTU)
    ran = way(m).run(make_plan(m), standin.PASSWORD, spawn=m.spawn, nonce="feed")
    assert ran.code == 0 and [o.state for o in ran.outcomes] == ["done"] * 4 and ran.said == "done"
    call = m.calls[-1]
    assert call["stdin"] == standin.PASSWORD.encode() + b"\n"  # once, then the pipe closed at the begin line
    assert standin.PASSWORD not in " ".join(call["argv"]) and standin.PASSWORD not in str(call["env"])
    assert standin.PASSWORD not in ran.out + ran.err + ran.said
    assert m.sudo_runs == 1 and not m.eof_at_prompt
    assert m.facts().made().members == ("pat",)


@pytest.mark.parametrize("name", [UBUNTU, "ubuntu-26.04"])
def test_a_wrong_password_is_one_try_and_sudo_is_killed_at_its_second_prompt(name):
    m = standin.Machine(name)
    procs = []

    def spawn(argv):
        procs.append(m.spawn(argv))
        return procs[-1]

    with pytest.raises(plan.WrongPassword, match="one failed sign-in"):
        way(m).run(make_plan(m), "not it", spawn=spawn)
    assert procs[0].tries == 1 and procs[0].killed_at == "prompt"
    assert not m.eof_at_prompt and m.sudo_runs == 0 and m.facts().liminal["group"] is None


def test_a_second_factor_is_said_and_never_read_as_a_wrong_password():
    m = standin.Machine(UBUNTU)
    m.data["sudo"] = dict(m.sudo, second_factor=True)
    with pytest.raises(shared.Refused) as e:
        way(m).run(make_plan(m), standin.PASSWORD, spawn=m.spawn)
    assert not isinstance(e.value, plan.WrongPassword) and "second factor" in str(e.value)
    assert not m.eof_at_prompt and m.sudo_runs == 0


def test_a_marker_naming_root_is_ended_before_anything_is_written():
    m = standin.Machine("opensuse-tumbleweed")
    w = elevation.elevation(m.facts(), None)
    w.whose = "self"  # the field asked the user's own; the marker says root's
    with pytest.raises(elevation.WhosePassword) as e:
        w.run(make_plan(m), standin.PASSWORD, spawn=m.spawn)
    assert e.value.whose == "root" and m.calls[-1]["stdin"] == b"" and not m.eof_at_prompt
    w.whose = "root"
    assert w.run(make_plan(m), standin.PASSWORD, spawn=m.spawn).code == 0


def test_no_password_asked_closes_the_pipe_at_the_begin_line():
    m = standin.Machine(UBUNTU, "nopasswd-all")
    w = way(m)
    assert w.field() == "no"
    ran = w.run(make_plan(m), "ignored", spawn=m.spawn)
    assert ran.code == 0 and m.calls[-1]["stdin"] == b""  # the field was "no": nothing was written


def test_sudo_asking_where_its_listing_said_none_offers_the_field_again():
    listed_free = way(standin.Machine(UBUNTU, "nopasswd-all"))
    m = standin.Machine(UBUNTU)  # this one asks
    listed_free.facts = m.facts()
    with pytest.raises(elevation.PasswordNeeded):
        listed_free.run(make_plan(m), None, spawn=m.spawn)
    assert m.calls[-1]["stdin"] == b"" and not m.eof_at_prompt


def test_a_field_asked_with_no_password_starts_no_sudo():
    m = standin.Machine(UBUNTU)
    with pytest.raises(elevation.PasswordNeeded):
        way(m).run(make_plan(m), "", spawn=lambda argv: pytest.fail("no sudo is started"))


def test_a_password_sudo_cannot_read_is_refused_before_sudo_starts():
    m = standin.Machine(UBUNTU)
    with pytest.raises(shared.Refused, match="line break"):
        way(m).run(make_plan(m), "two\nlines", spawn=lambda argv: pytest.fail("no sudo is started"))


def test_a_stop_while_sudo_waits_at_its_marker_kills_it_and_nothing_runs():
    m = standin.Machine(UBUNTU)
    stop = threading.Event()
    procs = []

    def spawn(argv):
        procs.append(m.spawn(argv))
        stop.set()  # the platform's TERM arrives while sudo waits at its prompt
        return procs[-1]

    with pytest.raises(shared.Refused, match="stopped before the change began"):
        way(m).run(make_plan(m), standin.PASSWORD, spawn=spawn, stop=stop)
    assert procs[0].killed_at == "prompt" and m.sudo_runs == 0 and m.calls[-1]["stdin"] == b""
    assert not m.eof_at_prompt and m.files.get("/var/lib/liminal-linux/MADE") is None


def test_a_sudo_killed_before_its_begin_line_was_read_leaves_a_script_that_changes_nothing():
    # the script's first lm_next, before the lock: its parent is gone (or it was told TERM), so it exits 7 before
    # the journal, the guards and step 1
    m = standin.Machine(UBUNTU)
    m.term_at = (0, "begun")
    ran = way(m).run(make_plan(m), standin.PASSWORD, spawn=m.spawn)
    assert ran.code == 7 and ran.said == "stopped after step 0 of 4: running it again finishes it"
    assert m.files.get("/var/lib/liminal-linux/MADE") is None and "liminal" not in m.groups()


def test_a_stop_while_the_script_runs_lets_its_step_finish_then_it_stops():
    m = standin.Machine(UBUNTU)
    m.hold_at = (2, "tool")
    stop = threading.Event()
    timer = threading.Timer(0.3, stop.set)
    timer.start()
    try:
        ran = way(m).run(make_plan(m), standin.PASSWORD, spawn=m.spawn, stop=stop)
    finally:
        timer.cancel()
    assert ran.code == 7 and ran.said == "stopped after step 2 of 4: running it again finishes it"
    made = m.facts().made()
    assert made.stopped and made.files and made.group is None


class _Silent:
    """A sudo that says nothing and never ends until it is killed."""

    def __init__(self, err: bytes = b"", code: int | None = None):
        self.stdin, self.stdout, self.stderr = _In(), standin.Pipe(), standin.Pipe()
        self.returncode = code
        self.killed = False
        if err:
            self.stderr._put(err)
        if code is not None:
            self.stdout._end()
            self.stderr._end()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.stdout._end()
        self.stderr._end()

    def terminate(self):
        self.kill()


class _In:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        self.data += data

    def flush(self):
        pass

    def close(self):
        self.closed = True


def _clock(step: float = 40.0):
    now = [0.0]

    def clock():
        now[0] += step
        return now[0]
    return clock


def test_neither_marker_nor_begin_line_in_time_kills_sudo():
    proc = _Silent()
    with pytest.raises(shared.Refused, match="within 30 s"):
        elevation.converse(["sudo"], "pw", "feed", spawn=lambda argv: proc, clock=_clock())
    assert proc.killed and proc.stdin.data == b""


def test_sudo_ending_before_the_begin_line_is_said_scrubbed_whole():
    proc = _Silent(b"sudo: pw is not in the sudoers file\n", code=1)
    with pytest.raises(shared.Refused) as e:
        elevation.converse(["sudo"], "pw", "feed", spawn=lambda argv: proc)
    assert "pw" not in str(e.value) and shared.SCRUBBED in str(e.value)
    proc = _Silent(b"sudo: a terminal is required to read the password\n", code=1)
    with pytest.raises(shared.Refused, match="a terminal is required"):
        elevation.converse(["sudo"], "secret", "feed", spawn=lambda argv: proc)


class _Refuses(_Silent):
    """A sudo that asks once at its marker and, given a password, ends with its refusal (PAM's one try)."""

    def __init__(self, nonce: str, refusal: bytes):
        super().__init__(f"<<liminal-sudo:{nonce}:pat>>".encode())
        proc = self

        class _Typed(_In):
            def write(self, data):
                super().write(data)
                proc.stderr._put(refusal)
                proc.returncode = 1
                proc.stdout._end()
                proc.stderr._end()
        self.stdin = _Typed()


def test_a_password_that_is_a_word_of_sudo_s_refusal_is_still_a_wrong_password():
    # told apart before the scrub: "pass" is in sudo's words, which are then scrubbed whole
    for pw in ("pass", "incorrect", "attempt"):
        proc = _Refuses("feed", b"\nsudo: 1 incorrect password attempt\n")
        with pytest.raises(plan.WrongPassword):
            elevation.converse(["sudo"], pw, "feed", spawn=lambda argv: proc)


def test_a_root_shell_runs_the_script_on_a_root_machine():
    m = standin.Machine(UBUNTU)
    m.data["id"] = "0 root"
    w = elevation.elevation(m.facts(), None)
    assert type(w) is elevation.AsRoot and w.field() == "no"
    ran = w.run(make_plan(m), None, spawn=m.spawn)
    assert ran.code == 0 and m.calls[-1]["argv"][:2] == ["/bin/sh", "-c"] and m.sudo_runs == 1


def test_doas_and_su_show_the_command_and_run_nothing():
    for name in ("alpine-3.24", "debian-13-su"):
        m = standin.Machine(name)
        with pytest.raises(shared.Refused, match="only from a terminal"):
            way(m).run(make_plan(standin.Machine(UBUNTU)), "x", spawn=lambda argv: pytest.fail("nothing starts"))
