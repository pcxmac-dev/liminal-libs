"""This Linux's facts (liminal_libs.linuxsys.facts): the probe's text, and what `parse` makes of its answer on the
systems the recorded machines stand for. No probe is run here: the answers are written in the probe's own format
(facts.block, facts.line), as the stand-in writes them."""
from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

from liminal_libs.linuxsys import facts, journal, kernel, plan
from liminal_libs.linuxsys.facts import block, line

pytestmark = pytest.mark.usefixtures("no_outside")

UBUNTU = 'PRETTY_NAME="Ubuntu 24.04.3 LTS"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n'
GROUP = "root:x:0:\nsudo:x:27:ciara\nciara:x:1000:\n"
PASSWD = ("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
          "ciara:x:1000:1000:,,,:/home/ciara:/bin/bash\n")
MOUNTS = "none / ext4 rw,relatime 0 0\nnone /usr/lib/wsl/drivers 9p ro,relatime 0 0\n"
STATUS = "Name:\tcat\nUid:\t1000\t1000\t1000\t1000\nGroups:\t27 1000\nCapEff:\t0000000000000000\nNoNewPrivs:\t0\n"
ROOT_FOLDERS = {"/": "0 0 755 -", "/var": "0 0 755 -", "/var/lib": "0 0 755 -", "/etc": "0 0 755 -",
                "/usr": "0 0 755 -", "/usr/local": "0 0 755 -"}
GNU = {"ls": "/usr/bin/ls", "install": "/usr/bin/install", "stat": "/usr/bin/stat", "flock": "/usr/bin/flock",
       "getent": "/usr/bin/getent", "groupadd": "/usr/sbin/groupadd", "useradd": "/usr/sbin/useradd",
       "gpasswd": "/usr/bin/gpasswd", "userdel": "/usr/sbin/userdel", "groupdel": "/usr/sbin/groupdel",
       "usermod": "/usr/sbin/usermod", "sudo": "/usr/bin/sudo", "systemd-sysusers": "/usr/bin/systemd-sysusers",
       "systemctl": "/usr/bin/systemctl", "su": "/usr/bin/su"}
VERSIONS = {"sudo": "Sudo version 1.9.15p5", "systemd-sysusers": "systemd 255 (255.4-1ubuntu8.11)",
            "systemctl": "systemd 255 (255.4-1ubuntu8.11)", "flock": "flock from util-linux 2.39.3",
            "ls": "ls (GNU coreutils) 9.4"}


def answer(files=None, env=None, tools=None, versions=None, folders=None, uid="1000 ciara", groups="27 1000",
           names="sudo ciara", execs=("/usr/sbin/nologin", "/bin/false"), getent=None, procs=(), end=True,
           there=()) -> str:
    """A probe's answer in its own format."""
    base = {kernel.OSRELEASE: "6.6.87.2-microsoft-standard-WSL2\n", kernel.SYSTEMD_CONTAINER: "wsl\n",
            "/etc/os-release": UBUNTU, "/etc/login.defs": "UID_MIN\t\t\t 1000\nGID_MIN\t\t\t 1000\n"
            "USERGROUPS_ENAB yes\n", "/etc/group": GROUP, "/etc/passwd": PASSWD, "/proc/mounts": MOUNTS,
            "/proc/self/status": STATUS, "/proc/1/comm": "systemd\n", "/sys/module/apparmor/parameters/enabled": "Y\n"}
    base.update(files or {})
    out = ""
    for path in facts.FILES:
        out += line("there", path) if path in there else block(path, base.get(path))
    for k, v in (env if env is not None else {"WSL_DISTRO_NAME": "Ubuntu"}).items():
        out += line("env", k, v)
    out += line("id", *uid.split()) + line("groups", groups) + line("groupnames", names)
    for name, path in (tools if tools is not None else GNU).items():
        path, _, real = path.partition(" ")
        out += line("tool", name, path, real or path)
    out += "".join(line("exec", e) for e in execs)
    for k, v in (versions if versions is not None else VERSIONS).items():
        out += line("version", k, v)
    for path in facts.FOLDERS:
        out += line("folder", path, (folders if folders is not None else ROOT_FOLDERS).get(path, "absent"))
    for kind, value in (getent or {"group": "", "passwd": ""}).items():
        out += line("getent", kind, value)
    out += "".join(line("proc", p) for p in procs)
    return out + (line("probe", "end") if end else "")


# ---- the probe ---------------------------------------------------------------------------------------------------


def _run() -> str:
    """The probe but its list of the tools it looks for: what it runs."""
    return "\n".join(ln for ln in facts.PROBE.splitlines() if not ln.startswith("for lm_t in"))


def test_the_probe_never_runs_sudo_but_sudo_v():
    runs = [ln.strip() for ln in facts.PROBE.splitlines()
            if (" sudo " in f" {ln} " or ln.strip().startswith("sudo")) and not ln.startswith("for lm_t in")]
    assert runs == ["lm_version sudo -V"]
    for word in (" -S", "sudo -l", "sudo -n", "doas ", "su -", "pkexec ", "run0 "):
        assert word not in _run().replace("sudo-policy", ""), word


def test_the_probe_reads_what_the_kernel_reading_and_the_plan_need():
    assert facts.PROBE.startswith("exec </dev/null\nPATH=/run/wrappers/bin:" + facts.ROOT_PATH + "; export PATH\n")
    loop = next(ln for ln in facts.PROBE.splitlines() if ln.startswith("for lm_f in"))
    assert all(f" {p} " in loop or loop.endswith(f" {p}; do lm_file \"$lm_f\"; done") for p in kernel.FILES)
    assert journal.PATH in loop and facts.SYSUSERS in loop
    tools = next(ln for ln in facts.PROBE.splitlines() if ln.startswith("for lm_t in")).removesuffix("; do").split()
    assert {t[0] for t in plan.TOOLS} <= set(tools)
    assert facts.FOLDERS[:6] == ("/", "/var", "/var/lib", "/var/lib/liminal-linux", "/etc", "/etc/sysusers.d")
    assert facts.ARGV == ("/bin/sh", "-c", facts.PROBE, "liminal-probe")
    # it changes nothing: no tool that writes is run, no redirection into a file
    for word in ("install ", "mkdir ", "rm ", "mv ", "chmod ", "groupadd", " >/etc", " >>"):
        assert word not in _run().replace("2>/dev/null", "").replace(">/dev/null", ""), word


# ---- what it makes of an answer ----------------------------------------------------------------------------------


def test_the_user_s_ubuntu_under_wsl():
    f = facts.parse(answer())
    assert f.os["id"] == "ubuntu" and f.os["family"] == "debian" and f.os["version"] == "24.04"
    assert (f.kernel.wsl, f.kernel.wsl_generation, f.kernel.container) == ("Ubuntu", 2, "")
    assert f.accounts["tool"] == "sysusers" and f.accounts["sysusers"] == 255
    assert (f.accounts["uid_min"], f.accounts["gid_min"], f.accounts["usergroups"]) == (1000, 1000, True)
    assert f.coreutils == "gnu" and f.lock == "flock"
    e = f.elevation
    assert (e["euid"], e["user"], e["sudo"], e["sudo_kind"]) == (1000, "ciara", "/usr/bin/sudo", "sudo")
    assert e["gids"] == (27, 1000) and e["running_gids"] == (27, 1000) and e["groupnames"] == ("sudo", "ciara")
    assert e["run0"] == "" and e["wheel_auth_self"] is None and e["no_new_privs"] is False
    assert f.layout["read_only"] == {"/": False, "/etc": False, "/var/lib": False, "/usr": False, "/usr/local": False}
    assert f.layout["nologin"] == "/usr/sbin/nologin" and not f.layout["nixos"] and not f.layout["ostree"]
    assert f.security == {"selinux": "absent", "apparmor": "on", "restorecon": False}
    assert f.chain(journal.FOLDER) == "" and f.chain("/etc/sysusers.d") == ""
    assert f.liminal["group"] is None and f.liminal["user"] is None and f.liminal["journal"] is None
    assert f.made().nothing and f.notes == ()
    assert f.init == {"pid1": "systemd", "systemd": False, "version": 255}
    json.dumps(f.describe())  # the page's and the command's JSON
    assert f.describe()["v"] == 1 and f.describe()["lock"] == "flock"


def test_liminal_s_accounts_and_journal_are_read_back():
    group = GROUP + "liminal:x:999:ciara\n"
    passwd = PASSWD + "liminal:x:998:999:Liminal:/var/lib/liminal:/usr/sbin/nologin\n"
    conf = "# Liminal\ng liminal -\n"
    sha = hashlib.sha256(conf.encode()).hexdigest()
    made = (f"run a1 apply 1764000000\nbegin 1 write file {facts.SYSUSERS} {sha}\n"
            f"done 1 wrote file {facts.SYSUSERS} {sha}\nbegin 2 sysusers liminal (absent: group user)\n"
            "done 2 made group liminal 999\ndone 2 made user liminal 998 999\nend a1 0\n")
    f = facts.parse(answer({"/etc/group": group, "/etc/passwd": passwd, facts.SYSUSERS: conf, journal.PATH: made},
                           folders={**ROOT_FOLDERS, journal.FOLDER: "0 0 755 -", "/etc/sysusers.d": "0 0 755 -"},
                           procs=("/proc/4242/status sleep",)))
    assert f.liminal["group"] == facts.Group("liminal", 999, ("ciara",))
    assert f.liminal["user"] == facts.User("liminal", 998, 999, "Liminal", "/var/lib/liminal", "/usr/sbin/nologin")
    assert f.system_account(f.liminal["user"]) and not f.system_account(f.accounts["users"]["ciara"])
    assert f.system_account(f.accounts["users"]["nobody"]) and not f.system_account(None)
    assert f.liminal["processes"] == ("/proc/4242/status sleep",)
    here = f.here()
    assert here.groups["liminal"] == (999, ("ciara",)) and here.users["liminal"] == (998, 999)
    assert here.paths[facts.SYSUSERS] == sha and here.paths[journal.FOLDER] == ""
    m = f.made()
    assert (m.group, m.user, m.files) == (999, (998, 999), {facts.SYSUSERS: sha})
    assert m.digest == hashlib.sha256(made.encode()).hexdigest()


def test_an_empty_journal_is_read_an_unreadable_one_is_said():
    assert facts.parse(answer({journal.PATH: ""})).liminal["journal"] == ""
    f = facts.parse(answer(there=(journal.PATH,)))
    assert f.liminal["journal"] is None and f"{journal.PATH} is there and could not be read" in f.notes


def test_ubuntu_26_04_runs_sudo_rs_and_uutils():
    f = facts.parse(answer({"/etc/os-release": 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="26.04"\n'},
                           versions={**VERSIONS, "sudo": "sudo-rs 0.2.13", "ls": "ls (uutils coreutils) 0.2.2",
                                     "systemd-sysusers": "systemd 258 (258.1-1ubuntu1)",
                                     "systemctl": "systemd 258 (258.1-1ubuntu1)"},
                           tools={**GNU, "run0": "/usr/bin/run0"}))
    assert f.elevation["sudo_kind"] == "sudo-rs" and f.coreutils == "uutils" and f.accounts["sysusers"] == 258
    assert f.elevation["run0"] == "/usr/bin/run0"  # systemd 256 and later


def test_alpine_s_busybox_and_doas():
    bb = "/bin/busybox"
    tools = {n: f"/bin/{n} {bb}" for n in ("ls", "install", "stat", "addgroup", "adduser", "deluser", "delgroup",
                                           "flock")}
    tools["doas"] = "/usr/bin/doas"
    f = facts.parse(answer({"/etc/os-release": "ID=alpine\nVERSION_ID=3.24.0\n", "/etc/login.defs": None,
                            kernel.OSRELEASE: "6.12.1-0-lts\n", kernel.SYSTEMD_CONTAINER: None},
                           env={}, tools=tools, versions={"busybox": "BusyBox v1.37.0 (2025-10-01) multi-call binary."},
                           execs=("/sbin/nologin",)))
    assert f.os["family"] == "alpine" and f.accounts["tool"] == "busybox" and f.coreutils == "busybox"
    assert f.accounts["uid_min"] == 1000 and f.lock == "flock" and f.layout["nologin"] == "/sbin/nologin"
    assert f.elevation["sudo"] == "" and f.elevation["doas"] == "/usr/bin/doas" and f.kernel.wsl == ""
    del tools["flock"]
    assert facts.parse(answer(tools=tools, versions={})).lock == "mkdir"


def test_nixos_declares_its_users_and_its_sudo_is_a_wrapper():
    f = facts.parse(answer({"/etc/os-release": "ID=nixos\nVERSION_ID=26.05\n", "/etc/NIXOS": "",
                            "/run/current-system": ""}, tools={**GNU, "sudo": "/run/wrappers/bin/sudo"}))
    assert f.accounts["tool"] == "nix" and f.layout["nixos"] and f.os["family"] == "nixos"
    assert f.elevation["sudo"] == "/run/wrappers/bin/sudo"


@pytest.mark.parametrize("version, note", [
    ("systemd 254 (254.5-1)", "systemd-sysusers here is systemd 254's: Liminal takes it from 255 on"),
    ("opensysusers 0.7.3", "the systemd-sysusers here is not systemd's own: shadow's tools are taken"),
])
def test_only_systemd_s_own_sysusers_from_255_is_taken(version, note):
    f = facts.parse(answer(versions={**VERSIONS, "systemd-sysusers": version}))
    assert f.accounts["tool"] == "shadow" and note in f.notes


def test_no_account_tool_is_none():
    f = facts.parse(answer(tools={"ls": "/bin/ls"}, versions={}))
    assert f.accounts["tool"] == "none" and f.elevation["sudo"] == "" and f.lock == "mkdir"


def test_fedora_with_selinux_enforcing_and_opensuse_s_wheel_rule():
    fedora = facts.parse(answer({"/etc/os-release": 'ID=fedora\nVERSION_ID=45\n', "/sys/fs/selinux/enforce": "1",
                                 "/etc/selinux/config": "SELINUX=enforcing\n"},
                                tools={**GNU, "restorecon": "/usr/sbin/restorecon"}))
    assert fedora.security["selinux"] == "enforcing" and fedora.security["restorecon"]
    assert fedora.os["family"] == "fedora"
    suse = facts.parse(answer({"/etc/os-release": 'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n'},
                              versions={**VERSIONS, "rpm-wheel-auth-self": "package sudo-policy-wheel-auth-self is "
                                        "not installed"}))
    assert suse.os["family"] == "suse" and suse.elevation["wheel_auth_self"] is False
    assert facts._wheel("sudo-policy-wheel-auth-self-0.1-1.noarch") is True


def test_a_container_and_a_read_only_root():
    f = facts.parse(answer({kernel.SYSTEMD_CONTAINER: None, kernel.DOCKERENV: "", kernel.OSRELEASE: "6.8.0-50\n",
                            "/proc/mounts": "overlay / overlay ro,relatime 0 0\ntmpfs /run tmpfs rw 0 0\n"
                                            "/dev/sda1 /var/lib ext4 rw 0 0\n"}, env={}))
    assert f.kernel.container == "docker"
    assert f.layout["read_only"]["/etc"] is True and f.layout["read_only"]["/var/lib"] is False
    assert facts.read_only([("/", False), ("/", True)], "/etc") is True  # the last mounted over the same point
    assert facts.read_only([], "/etc") is None


def test_a_folder_another_account_writes_breaks_the_chain():
    f = facts.parse(answer(folders={**ROOT_FOLDERS, "/var/lib": "0 50 775 -"}))
    assert f.chain(journal.FOLDER).startswith("/var/lib is not root's alone") and f.chain("/etc/sysusers.d") == ""
    f = facts.parse(answer(folders={**ROOT_FOLDERS, "/etc": "? ? ? -"}))
    assert "/etc could not be read (its owner and mode)" in f.notes
    assert f.chain("/etc/sysusers.d").startswith("/etc could not be read")


def test_what_could_not_be_read_is_said():
    f = facts.parse(answer({"/etc/os-release": None}, end=False))
    assert "the probe's answer was cut off before its end: what follows it is not known" in f.notes
    assert "os-release could not be read: the distribution is not known" in f.notes
    f = facts.parse("")
    assert f.accounts["tool"] == "none" and "/etc/group or /etc/passwd could not be read" in f.notes


def test_read_runs_the_probe_through_the_runner_it_is_handed():
    seen = []

    def runner(argv, timeout):
        seen.append((argv, timeout))
        return subprocess.CompletedProcess(argv, 0, answer(), "")

    f = facts.read(runner)
    assert seen == [(list(facts.ARGV), facts.PROBE_S)] and f.accounts["tool"] == "sysusers"
    cut = facts.read(lambda argv, timeout: subprocess.CompletedProcess(argv, 137, answer(end=False), ""))
    assert "the probe ended with exit 137 before its end" in cut.notes


def test_a_file_s_text_comes_back_as_it_was():
    for text in ("a\n", "a", "", "two\nlines\n\n", "@@ not a marker\n"):
        s = facts.sections(block("/etc/x", text) + line("probe", "end"))
        assert s["files"]["/etc/x"] == text and s["end"]
