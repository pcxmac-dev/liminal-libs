"""A private Node.js and its npm as the plugins run them (liminal_libs.machines.node, 1.66.0): Node.js's archives' names
and where node and npm-cli.js are in them; this machine's processor and a musl Linux told without running anything;
the settings npm is run without, whatever a name's case, and its own four over them; the empty npmrc; a pin, and what
it refuses; npm's two command lines word for word, --ignore-scripts, --no-audit, --no-fund and --no-update-notifier in
every one; the environment, the folder, the time allowed and the cancel handed on to the runner; a failure in npm's
own last words; the top package's sha512 as npm's lock records it, against the pin (the same, another, none); and the
kept lock: kept after an install, used by `npm ci` for a repair, left for a fresh install, never kept from an install
that is not what is pinned.

Node.js and npm are not here and nothing runs: a stand-in takes the place of children.stream (the library's runner of
an installer's command) and writes what npm would, and the shared guard (conftest.py) fails a test that starts a
process or opens a connection."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from liminal_libs.machines import node
from liminal_libs.machines.download import DownloadError
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.terminal import Cancelled
from test_ai_boundary import WRITTEN

pytestmark = pytest.mark.usefixtures("no_outside")

HTTPS = "https:" + "//"  # an address's start, put together here: no file names a host whole
REGISTRY = HTTPS + "registry.example.test/"
# @continuedev/cli 1.5.47's sha512, as the registry gives it (dist.integrity, plugin-platform-continue's pin)
CN_SUM = "sha512-gtpewV3RoIOD9dyTtKIBi1SY0VOHRu3Ehe7C/mmnswm+j34MPyrcQhQaWj/m+jdfGO4fNIKdrgGIlLso1ULDFw=="
OTHER_SUM = "sha512-" + "A" * 86 + "=="  # a sum of the right shape that is not the pin's
CN = node.Pin("@continuedev/cli", "1.5.47", CN_SUM)
ENV = {"PATH": "C:/tools", "SystemRoot": "C:/Windows"}  # an environment as child_env gives it whole
EVERY = list(node.FLAGS)


def never() -> bool:
    return False


class Npm:
    """A stand-in for children.stream running the private Node.js's npm: what it was asked to run and how (and what
    its folder held when it was), the lines it says, how it ends, and what npm would leave on the disk. `install`
    writes the package, its package.json, its lock and the lock npm keeps in node_modules; `ci` writes the packages
    the lock in the folder names, and no lock (npm ci never writes one)."""

    def __init__(self, *, code=0, lines=(), raises=None, version=None, integrity=None, lock=True, hidden=False,
                 program=True):
        self.code, self.lines, self.raises = code, list(lines), raises
        self.version, self.integrity = version, integrity  # what an install records, when not the asked ones
        self.lock, self.hidden, self.program = lock, hidden, program
        self.calls: list[dict] = []

    def __call__(self, argv, line, *, env=None, cwd=None, timeout=1800.0, cancel=None):
        prefix = Path(argv[argv.index("--prefix") + 1])
        there = sorted(p.name for p in prefix.iterdir()) if prefix.is_dir() else None
        self.calls.append({"argv": list(argv), "env": env, "cwd": cwd, "timeout": timeout, "cancel": cancel,
                           "there": there, "texts": {n: (prefix / n).read_text(encoding="utf-8") for n in there or ()
                                                     if (prefix / n).is_file()}})
        for text in self.lines:
            line(text)
        if self.raises is not None:
            raise self.raises
        if self.code == 0:
            if argv[2] == "install":
                name, _, version = argv[-1].rpartition("@")
                self.installed(prefix, name, version)
            elif argv[2] == "ci":
                lock = json.loads((prefix / node.LOCK).read_text(encoding="utf-8"))
                for key, row in lock["packages"].items():
                    if key:
                        self.package(prefix, key[len("node_modules/"):], row["version"])
        return self.code

    def package(self, prefix: Path, name: str, version: str) -> None:
        folder = prefix.joinpath("node_modules", *name.split("/"))
        (folder / "dist").mkdir(parents=True, exist_ok=True)
        (folder / "package.json").write_text(json.dumps({"name": name, "version": version,
                                                         "bin": {"cn": "dist/cn.js"}}), encoding="utf-8")
        if self.program:
            (folder / "dist" / "cn.js").write_text("#!/usr/bin/env node\n", encoding="utf-8")

    def installed(self, prefix: Path, name: str, version: str) -> None:
        got = self.version or version
        self.package(prefix, name, got)
        self.package(prefix, "fzf", "0.5.2")
        packages = {"": {"dependencies": {name: version}},
                    f"node_modules/{name}": {"version": got, "integrity": self.integrity if self.integrity is not None
                                             else CN_SUM},
                    "node_modules/fzf": {"version": "0.5.2", "integrity": "sha512-" + "f" * 86 + "=="}}
        (prefix / "package.json").write_text(json.dumps({"dependencies": {name: version}}, indent=2),
                                             encoding="utf-8")
        text = json.dumps({"name": "cli", "lockfileVersion": 3, "requires": True, "packages": packages}, indent=2)
        if self.lock:
            (prefix / node.LOCK).write_text(text, encoding="utf-8")
        if self.hidden:
            prefix.joinpath(*node.HIDDEN_LOCK).write_text(text, encoding="utf-8")


@pytest.fixture
def programs(tmp_path):
    """The private Node.js's two programs, by their whole paths (the stand-in runs neither)."""
    folder = tmp_path / "app" / "1.5.47" / "node"
    return folder / "node.exe", folder / "node_modules" / "npm" / "bin" / "npm-cli.js"


def put(programs, prefix, kept, npm, **kw):
    return node.put(*programs, prefix, CN, kept=kept, env=ENV, log=kw.pop("log", None), cancel=kw.pop("cancel", never),
                    command=kw.pop("command", "cn"), stream=npm, **kw)


# -- this machine and Node.js's archives -------------------------------------------------------------------------------
def test_the_archives_are_named_for_each_system_and_processor():
    assert node.NODE_LINE == 24 and node.STRIP == 1
    assert node.archive("24.11.1", "windows", "AMD64") == "node-v24.11.1-win-x64.zip"
    assert node.archive("v24.11.1", "Windows", "ARM64") == "node-v24.11.1-win-arm64.zip"
    assert node.archive("24.11.1", "linux", "x86_64") == "node-v24.11.1-linux-x64.tar.xz"
    assert node.archive("24.11.1", "linux", "aarch64") == "node-v24.11.1-linux-arm64.tar.xz"
    assert node.archive("24.11.1", "linux" if os.name != "nt" else "windows").startswith("node-v24.11.1-")
    for system, machine in (("windows", "x86"), ("linux", "armv7l"), ("linux", "riscv64"), ("darwin", "arm64"),
                            ("", "x86_64")):
        with pytest.raises(ValueError, match="no archive of Node.js is named here"):
            node.archive("24.11.1", system, machine)
    for version in ("24", "24.11", "latest", "^24.11.1", "", None, "24.11.1; rm"):
        with pytest.raises(ValueError, match="three numbers"):
            node.archive(version, "windows", "AMD64")


@pytest.mark.parametrize("raw, word", [("AMD64", "x64"), ("x86_64", "x64"), ("ARM64", "arm64"), ("aarch64", "arm64"),
                                       ("armv7l", "armv7l"), ("i686", "i686"), ("", "unknown")])
def test_the_processor_is_named_as_nodes_archives_name_it(raw, word):
    assert node.machine_word(raw) == word
    assert node.machine_word() == node.machine_word(__import__("platform").machine())  # this one's, by itself


def test_a_musl_linux_is_told_without_running_anything():
    alpine = {"/etc/alpine-release"}

    def exists(path):
        return path in alpine

    def glibc():
        return "glibc", "2.39"

    def raises():
        raise OSError("not readable")

    assert node.musl_here(system="windows", exists=lambda p: True, libc=lambda: ("", "")) is False
    assert node.musl_here(system="linux", exists=exists, libc=glibc) is True  # /etc/alpine-release is there
    alpine.clear()
    assert node.musl_here(system="linux", exists=exists, libc=glibc) is False
    assert node.musl_here(system="linux", exists=exists, libc=lambda: ("", "")) is True  # no glibc named
    assert node.musl_here(system="linux", exists=exists, libc=raises) is False


@pytest.mark.parametrize("system, node_at, npm_at", [
    ("windows", ("node.exe",), ("node_modules", "npm", "bin", "npm-cli.js")),
    ("linux", ("bin", "node"), ("lib", "node_modules", "npm", "bin", "npm-cli.js")),
])
def test_node_and_npm_are_where_nodes_packaging_puts_them(tmp_path, system, node_at, npm_at):
    folder = tmp_path / "node"
    for parts in (node_at, npm_at):
        folder.joinpath(*parts).parent.mkdir(parents=True, exist_ok=True)
        folder.joinpath(*parts).write_bytes(b"stand-in")
    assert node.programs(folder, system) == (folder.joinpath(*node_at), folder.joinpath(*npm_at))
    folder.joinpath(*npm_at).unlink()
    with pytest.raises(DownloadError) as caught:
        node.programs(folder, system, "node-v24.11.1-win-x64.zip")
    assert str(caught.value) == ("node-v24.11.1-win-x64.zip holds no npm-cli.js where Node.js's packaging puts it "
                                 f"({'/'.join(npm_at)}): nothing is installed")
    folder.joinpath(*node_at).unlink()
    with pytest.raises(DownloadError, match=r"^Node\.js's archive holds no node where"):
        node.programs(folder, system)


# -- what npm is run with ----------------------------------------------------------------------------------------------
# what npm and the Node.js it runs on would read as a setting of yours (plugin-platform-continue's review's cases)
YOURS = {"npm_config_strict_ssl": "false", "NPM_CONFIG_GLOBAL": "true", "npm_config_package_lock": "false",
         "npm_config_@continuedev:registry": HTTPS + "mirror.example.test/", "Npm_Config_Cafile": "ca-of-yours.pem",
         "npm_config_ignore_scripts": "false", "NODE_TLS_REJECT_UNAUTHORIZED": "0",
         "NODE_OPTIONS": "--require preload-of-yours.js", "NODE_EXTRA_CA_CERTS": "ca-of-yours.pem",
         "NODE_PATH": "modules-of-yours", "NODE_ENV": "production", "HTTPS_PROXY": "proxy-of-yours",
         "http_proxy": "proxy-of-yours", "No_Proxy": "*", "proxy": "proxy-of-yours", "OPENSSL_CONF": "openssl.cnf"}


def test_what_npm_is_run_without_is_told_whatever_the_case():
    assert node.DROP == ("npm_config_*", "NODE_*", "HTTPS_PROXY", "HTTP_PROXY", "PROXY", "NO_PROXY", "OPENSSL_CONF")
    dropped = node.dropped({"Npm_Config_Foo": "1", "node_options": "x", "HTTPS_PROXY": "y", "https_proxy": "z",
                            "NO_PROXY": "*", "Openssl_Conf": "c", "PATH": "/bin", "NODEJS_HOME": "kept",
                            "MY_NODE_OPTIONS": "kept", "GITHUB_TOKEN": "kept"})
    assert dropped == (*node.DROP, "Npm_Config_Foo", "node_options", "https_proxy", "Openssl_Conf")
    assert all(node.reads(n) for n in YOURS) and not any(node.reads(n) for n in ("NODEJS_HOME", "GITHUB_TOKEN"))


@pytest.mark.parametrize("system", ["windows", "linux"])
def test_npm_is_given_none_of_your_settings_and_its_own_four_over_them(tmp_path, system):
    base = {**ENV, **YOURS, "GITHUB_TOKEN": "gh-kept-as-in-your-terminal", "LIMINAL_PLATFORM_DIR": "C:/platform",
            "MASSIVE_API_KEY": "m-key", "npm_config_cache": "C:/caches/of-yours"}
    cache, npmrc = tmp_path / "downloads" / "npm-cache", tmp_path / "config" / "npmrc"
    env = node.child_env(cache, npmrc, REGISTRY, base=base, drop=("MASSIVE_API_KEY",), system=system)
    reached = sorted(n for n in env if n.upper() in {y.upper() for y in YOURS})
    assert reached == [], reached
    assert {n: env[n] for n in env if n.lower().startswith("npm_config_")} == {
        "npm_config_cache": str(cache), "npm_config_userconfig": str(npmrc), "npm_config_globalconfig": str(npmrc),
        "npm_config_registry": REGISTRY}  # npm's own four, over the user's own cache
    assert node.environment(cache, npmrc, REGISTRY) == {k: v for k, v in env.items() if k.startswith("npm_config_")}
    assert env["GITHUB_TOKEN"] == "gh-kept-as-in-your-terminal" and env["PATH"] == "C:/tools"  # no setting of npm's
    assert "LIMINAL_PLATFORM_DIR" not in env and "MASSIVE_API_KEY" not in env
    assert list(tmp_path.iterdir()) == []  # naming the folders makes none


def test_the_registry_is_asked_over_https_alone_and_never_said_back(tmp_path):
    secret = "s3cret-token"
    for bad in ("http:" + "//registry.example.test/", "registry.example.test", HTTPS, "", None,
                HTTPS + "registry.example.test/a b", "file:" + "///C:/registry"):
        with pytest.raises(ValueError, match="https alone|no space or control|none was named"):
            node.environment(tmp_path / "cache", tmp_path / "npmrc", bad)
    with pytest.raises(ValueError, match="without a name or a password") as caught:
        node.environment(tmp_path / "cache", tmp_path / "npmrc", HTTPS + f"me:{secret}@registry.example.test/")
    assert secret not in str(caught.value)


def test_the_npmrc_is_one_empty_file_written_whole(tmp_path):
    path = node.write_npmrc(tmp_path / "home")
    assert path == tmp_path / "home" / "config" / "npmrc" and path.read_bytes() == b""
    path.write_text("registry=elsewhere\n", encoding="utf-8")  # something of the user's put there
    assert node.write_npmrc(tmp_path / "home").read_bytes() == b"" and sorted(os.listdir(path.parent)) == ["npmrc"]


# -- a pin -------------------------------------------------------------------------------------------------------------
def test_a_pin_names_an_exact_version_and_its_sha512():
    assert (CN.spec, CN.folder) == ("@continuedev/cli@1.5.47", "continuedev+cli@1.5.47")
    assert CN.where("C:/x") == Path(os.path.abspath("C:/x")) / "node_modules" / "@continuedev" / "cli"
    plain = node.Pin(" cline ", " 3.0.74 ", f" {CN_SUM} ")
    assert (plain.name, plain.version, plain.spec, plain.folder) == ("cline", "3.0.74", "cline@3.0.74",
                                                                      "cline@3.0.74")
    assert node.Pin("@cline/cli-windows-x64", "3.0.74-rc.1+build.5", CN_SUM).folder == \
        "cline+cli-windows-x64@3.0.74-rc.1+build.5"
    for version in ("^1.5.47", "~1.5", "1.5", "latest", "1.x", ">=1.5.47", "", "1.5.47 || 2"):
        with pytest.raises(ValueError, match="an exact one"):
            node.Pin("@continuedev/cli", version, CN_SUM)
    for name in ("@Continuedev/cli", "../cli", "a/b", "@a/b/c", "@/cli", ".hidden", "_x", "", "x" * 215, "a b"):
        with pytest.raises(ValueError, match="as the registry names it"):
            node.Pin(name, "1.5.47", CN_SUM)
    for integrity in ("sha1-" + "a" * 27 + "=", "sha512-short==", CN_SUM[:-2], "sha256-" + "a" * 43 + "=", ""):
        with pytest.raises(ValueError, match="the sha512 the registry gives"):
            node.Pin("@continuedev/cli", "1.5.47", integrity)


def test_its_checked_words_say_what_is_pinned_and_what_is_not():
    words = node.checked_words("Continue's CLI")
    assert "Continue's CLI's own sha512, as npm's lock records it, is compared with the one pinned" in words
    assert "nothing is put in use without that comparison" in words and "pinned in no file of this plugin's" in words
    assert words.endswith(".") and "  " not in words


# -- npm's commands ----------------------------------------------------------------------------------------------------
def test_an_install_runs_this_command_word_for_word(tmp_path, programs):
    prefix, npm, said = tmp_path / "app" / "1.5.47" / "cli", Npm(lines=["added 11 packages in 3s\n"]), []
    node.install(*programs, prefix, CN, env=ENV, log=said.append, cancel=never, stream=npm)
    call, = npm.calls
    assert call["argv"] == [str(programs[0]), str(programs[1]), "install", "--prefix", str(prefix), "--save-exact",
                            "--ignore-scripts", "--no-audit", "--no-fund", "--no-update-notifier",
                            "@continuedev/cli@1.5.47"]
    assert call["env"] == ENV and call["env"] is not ENV  # the environment given, whole, and a copy of it
    assert call["cwd"] == str(prefix) and call["there"] == [] and call["timeout"] == 900.0 == node.NPM_S
    assert call["cancel"] is never
    assert said == [f"npm: @continuedev/cli@1.5.47 into {prefix}; npm resolves its dependencies from the registry "
                    "and checks each against the registry's own sum (none of them is pinned in this plugin)",
                    "added 11 packages in 3s"]


def test_a_ci_runs_this_command_word_for_word(tmp_path, programs):
    prefix, npm = tmp_path / "cli", Npm()
    Npm().installed(prefix, CN.name, CN.version)
    node.ci(*programs, prefix, CN, env=ENV, log=None, cancel=None, timeout=60.0, stream=npm)
    call, = npm.calls
    assert call["argv"] == [str(programs[0]), str(programs[1]), "ci", "--prefix", str(prefix), "--ignore-scripts",
                            "--no-audit", "--no-fund", "--no-update-notifier"]
    assert call["timeout"] == 60.0 and call["cancel"] is None and call["cwd"] == str(prefix)


def test_npm_is_never_run_without_its_environment_or_by_a_bare_name(tmp_path, programs):
    npm = Npm()
    with pytest.raises(ValueError, match="an environment given whole"):
        node.install(*programs, tmp_path / "cli", CN, env=None, log=None, cancel=None, stream=npm)
    for bare in (("node", programs[1]), (programs[0], "npm-cli.js"), ("", programs[1]), (None, programs[1])):
        with pytest.raises(ValueError, match="named by its whole path"):
            node.install(*bare, tmp_path / "cli", CN, env=ENV, log=None, cancel=None, stream=npm)
    assert npm.calls == [] and not (tmp_path / "cli").exists()


def test_a_cancel_before_npm_starts_runs_nothing_and_one_meanwhile_is_npms(tmp_path, programs):
    npm, said = Npm(), []
    with pytest.raises(Cancelled, match="before `npm install @continuedev/cli@1.5.47` was started"):
        node.install(*programs, tmp_path / "cli", CN, env=ENV, log=said.append, cancel=lambda: True, stream=npm)
    assert npm.calls == [] and said == [] and not (tmp_path / "cli").exists()
    ended = Npm(raises=Cancelled("node npm-cli.js install was cancelled: ended with what it started"))
    with pytest.raises(Cancelled, match="ended with what it started"):
        node.install(*programs, tmp_path / "cli", CN, env=ENV, log=None, cancel=never, stream=ended)


def test_a_failed_npm_is_said_in_its_own_last_words(tmp_path, programs):
    failing = Npm(code=1, lines=["npm error code E404", "npm error 404 Not Found - GET of @continuedev/cli",
                                 "npm error A complete log of this run can be found in: C:/x/_logs/debug-0.log"])
    with pytest.raises(node.NpmError) as caught:
        node.install(*programs, tmp_path / "cli", CN, env=ENV, log=None, cancel=never, stream=failing)
    assert str(caught.value) == ("npm ended with exit code 1: @continuedev/cli 1.5.47 is not installed (its last "
                                 "line: npm error 404 Not Found - GET of @continuedev/cli)")
    assert isinstance(caught.value, CommandError)
    with pytest.raises(node.NpmError) as caught:
        node.ci(*programs, tmp_path / "cli", CN, env=ENV, log=None, cancel=never, stream=Npm(code=243))
    assert str(caught.value) == ("npm ended with exit code 243: @continuedev/cli 1.5.47 is not installed from its "
                                 "lock (npm's lines are in the panel)")


# -- what is checked ---------------------------------------------------------------------------------------------------
def test_the_package_installed_is_checked_against_the_pin(tmp_path):
    prefix = tmp_path / "cli"
    Npm().installed(prefix, CN.name, CN.version)
    assert node.recorded(prefix, CN) == CN_SUM
    assert node.checked(prefix, CN, "cn") == ("@continuedev/cli 1.5.47: its sha512, as npm's lock file records it, is "
                                              "the one pinned in this plugin")
    assert node.checked(prefix, CN) == node.checked(prefix, CN, "cn")
    entry, version = node.entry_of(CN.where(prefix), "cn")
    assert entry == CN.where(prefix) / "dist" / "cn.js" and version == "1.5.47"
    assert node.entry_of(CN.where(prefix)) == (entry, version)  # (bin names one program alone)


@pytest.mark.parametrize("npm, words", [
    (Npm(integrity=OTHER_SUM), "with another sha512 than the one pinned in this plugin: nothing is put in use"),
    (Npm(integrity=f"{OTHER_SUM} sha1-" + "b" * 27 + "="), "with another sha512 than the one pinned in this plugin"),
    (Npm(integrity=""), "npm's lock file records no sha512 of @continuedev/cli 1.5.47, so it cannot be compared"),
    (Npm(lock=False), "npm's lock file records no sha512 of @continuedev/cli 1.5.47"),
    (Npm(version="1.5.46"), "npm installed @continuedev/cli 1.5.46, not 1.5.47: nothing is put in use"),
    (Npm(program=False), "is not in"),
])
def test_what_is_not_the_pin_is_not_put_in_use(tmp_path, npm, words):
    prefix = tmp_path / "cli"
    npm.installed(prefix, CN.name, CN.version)
    with pytest.raises(node.NpmError) as caught:
        node.checked(prefix, CN, "cn")
    assert words in str(caught.value)


def test_the_lock_npm_keeps_in_node_modules_is_read_when_there_is_no_other(tmp_path):
    prefix = tmp_path / "cli"
    Npm(lock=False, hidden=True).installed(prefix, CN.name, CN.version)
    assert node.recorded(prefix, CN) == CN_SUM and "is the one pinned" in node.checked(prefix, CN)
    assert node.recorded(tmp_path / "nothing", CN) == ""


def test_a_program_named_outside_its_package_is_none(tmp_path):
    package = tmp_path / "node_modules" / "x"
    package.mkdir(parents=True)
    (tmp_path / "evil.js").write_text("", encoding="utf-8")
    for named in ("../../evil.js", "/evil.js", "C:/evil.js", {"x": "..\\..\\evil.js"}, {"a": "a.js", "b": "b.js"}, 7):
        (package / "package.json").write_text(json.dumps({"version": "1.0.0", "bin": named}), encoding="utf-8")
        assert node.entry_of(package, "x" if isinstance(named, dict) and "x" in named else "") is None, named


# -- the kept lock -----------------------------------------------------------------------------------------------------
def test_an_install_keeps_its_lock_and_a_repair_installs_from_it_with_npm_ci(tmp_path, programs):
    """The plan's case: the lock npm wrote is kept in the plugin's folder, and a repair of the same pin (its folder
    removed and built again, as Install does with a half-built one) is `npm ci --ignore-scripts` from it."""
    home, prefix = tmp_path / "ai" / "continue", tmp_path / "ai" / "continue" / "app" / "1.5.47" / "cli"
    kept, npm = node.lock_folder(home, CN), Npm()
    assert kept == home / "config" / "npm" / "continuedev+cli@1.5.47"
    first = put(programs, prefix, kept, npm)
    assert first == ["@continuedev/cli 1.5.47: its sha512, as npm's lock file records it, is the one pinned in this "
                     "plugin",
                     f"npm's lock is kept in {kept}: a repair or a reinstall of the same pin installs the same "
                     "packages from it (npm ci)"]
    assert sorted(os.listdir(kept)) == sorted([node.MANIFEST, node.LOCK])
    for name in (node.MANIFEST, node.LOCK):
        assert (kept / name).read_text(encoding="utf-8") == (prefix / name).read_text(encoding="utf-8")
    assert node.lock_holds(kept, CN) == ""
    lock = (kept / node.LOCK).read_text(encoding="utf-8")
    for path in sorted(prefix.rglob("*"), reverse=True):  # the install's folder removed: a repair builds it again
        path.unlink() if path.is_file() else path.rmdir()
    prefix.rmdir()
    again = put(programs, prefix, kept, npm)
    assert [c["argv"][2] for c in npm.calls] == ["install", "ci"]
    repair = npm.calls[1]
    assert repair["argv"][3:] == ["--prefix", str(prefix), *EVERY]
    assert repair["there"] == [node.LOCK, node.MANIFEST]  # the kept lock was in its folder when npm ci ran
    assert repair["texts"][node.LOCK] == lock
    assert again == [f"@continuedev/cli@1.5.47: installed again from the lock kept in {kept}, the packages of its "
                     "first install",
                     "@continuedev/cli 1.5.47: its sha512, as npm's lock file records it, is the one pinned in this "
                     "plugin"]
    assert (kept / node.LOCK).read_text(encoding="utf-8") == lock  # (npm ci writes no lock: the kept one stays)


def test_every_npm_command_has_ignore_scripts_no_audit_no_fund_and_no_update_notifier(tmp_path, programs):
    kept, npm = tmp_path / "kept", Npm()
    put(programs, tmp_path / "one", kept, npm)  # an install, its lock kept
    put(programs, tmp_path / "two", kept, npm)  # npm ci from it
    put(programs, tmp_path / "three", kept, npm, fresh=True)  # an install again
    node.install(*programs, tmp_path / "four", CN, env=ENV, log=None, cancel=None, stream=npm)
    node.ci(*programs, tmp_path / "two", CN, env=ENV, log=None, cancel=None, stream=npm)
    assert [c["argv"][2] for c in npm.calls] == ["install", "ci", "install", "install", "ci"]
    for call in npm.calls:
        assert all(call["argv"].count(flag) == 1 for flag in EVERY), call["argv"]
        assert call["argv"][3:5] == ["--prefix", call["cwd"]] and call["env"] == ENV


def test_a_fresh_install_resolves_again_and_keeps_the_new_lock(tmp_path, programs):
    kept, npm = tmp_path / "kept", Npm()
    put(programs, tmp_path / "one", kept, npm)
    (kept / node.LOCK).write_text((kept / node.LOCK).read_text(encoding="utf-8") + "\n", encoding="utf-8")
    lines = put(programs, tmp_path / "two", kept, npm, fresh=True)
    assert npm.calls[-1]["argv"][2] == "install"
    assert lines[0] == "a fresh install was asked: npm resolved @continuedev/cli@1.5.47's packages again"
    assert (kept / node.LOCK).read_text(encoding="utf-8") == (tmp_path / "two" / node.LOCK).read_text(encoding="utf-8")


@pytest.mark.parametrize("change, words", [
    (lambda m, lk: lk["packages"]["node_modules/@continuedev/cli"].update(integrity=OTHER_SUM),
     "records another sha512 of @continuedev/cli@1.5.47 than the one pinned in this plugin"),
    (lambda m, lk: lk["packages"]["node_modules/@continuedev/cli"].update(version="1.5.46"),
     "records no @continuedev/cli@1.5.47"),
    (lambda m, lk: m["dependencies"].update(left="1.0.0"), "is not @continuedev/cli@1.5.47's alone"),
    (lambda m, lk: m.update(dependencies={"@continuedev/cli": "^1.5.47"}), "is not @continuedev/cli@1.5.47's alone"),
])
def test_a_kept_lock_that_is_not_the_pins_is_not_used(tmp_path, programs, change, words):
    kept, npm = tmp_path / "kept", Npm()
    put(programs, tmp_path / "one", kept, npm)
    manifest = json.loads((kept / node.MANIFEST).read_text(encoding="utf-8"))
    lock = json.loads((kept / node.LOCK).read_text(encoding="utf-8"))
    change(manifest, lock)
    (kept / node.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    (kept / node.LOCK).write_text(json.dumps(lock), encoding="utf-8")
    assert words in node.lock_holds(kept, CN)
    lines = put(programs, tmp_path / "two", kept, npm)
    assert npm.calls[-1]["argv"][2] == "install" and words in lines[0] and "npm resolved" in lines[0]
    assert node.lock_holds(kept, CN) == ""  # the new one kept in its place


def test_a_lock_not_whole_or_not_there_is_said(tmp_path):
    none = tmp_path / "none"
    assert node.lock_holds(none, CN) == f"no lock of @continuedev/cli@1.5.47 is kept in {none}"
    (tmp_path / "half").mkdir()
    (tmp_path / "half" / node.LOCK).write_text("{", encoding="utf-8")  # broken off, its package.json gone
    assert "is not whole" in node.lock_holds(tmp_path / "half", CN)


def test_an_install_that_is_not_the_pin_keeps_no_lock(tmp_path, programs):
    kept = tmp_path / "kept"
    with pytest.raises(node.NpmError, match="another sha512"):
        put(programs, tmp_path / "one", kept, Npm(integrity=OTHER_SUM))
    assert not kept.exists()
    with pytest.raises(node.NpmError, match="npm ended with exit code 1"):
        put(programs, tmp_path / "two", kept, Npm(code=1))
    assert not kept.exists()


def test_npm_writing_no_lock_is_said_and_keeps_nothing(tmp_path, programs):
    kept = tmp_path / "kept"
    lines = put(programs, tmp_path / "one", kept, Npm(lock=False, hidden=True))
    assert "is the one pinned" in lines[0]
    assert lines[1] == (f"npm wrote no {node.LOCK} in {tmp_path / 'one'}: no lock is kept, and a repair resolves its "
                        "packages again")
    assert not kept.exists()


def test_a_lock_that_cannot_be_kept_leaves_no_earlier_one_standing_for_it(tmp_path, programs, monkeypatch):
    kept = tmp_path / "kept"
    put(programs, tmp_path / "one", kept, Npm())
    lines = put(programs, tmp_path / "two", kept, Npm(lock=False, hidden=True), fresh=True)
    assert "no lock is kept" in lines[-1] and node.lock_holds(kept, CN).startswith("no lock of")
    put(programs, tmp_path / "three", kept, Npm())  # kept again
    real = node._write_whole

    def failing(path, text):
        if path == kept / node.LOCK:
            raise PermissionError(13, "denied", str(path))
        return real(path, text)

    monkeypatch.setattr(node, "_write_whole", failing)
    lines = put(programs, tmp_path / "four", kept, Npm(), fresh=True)
    assert lines[-1] == (f"npm's lock could not be kept in {kept} (denied: {kept / node.LOCK}): a repair resolves its "
                         "packages again")
    assert node.lock_holds(kept, CN).startswith("no lock of") and list(kept.iterdir()) == []


def test_a_folder_that_holds_something_is_refused_before_npm_runs(tmp_path, programs):
    prefix, npm = tmp_path / "cli", Npm()
    prefix.mkdir()
    (prefix / "package.json").write_text('{"dependencies": {"left": "1.0.0"}}', encoding="utf-8")
    with pytest.raises(node.NpmError, match="is not empty: npm installs a pinned package only where there is nothing"):
        put(programs, prefix, tmp_path / "kept", npm)
    assert npm.calls == []


def test_a_repair_cancelled_or_given_no_environment_puts_nothing_in_its_folder(tmp_path, programs):
    kept, npm = tmp_path / "kept", Npm()
    put(programs, tmp_path / "one", kept, npm)
    with pytest.raises(Cancelled, match="before `npm ci @continuedev/cli@1.5.47` was started"):
        put(programs, tmp_path / "two", kept, npm, cancel=lambda: True)
    with pytest.raises(ValueError, match="an environment given whole"):
        node.put(*programs, tmp_path / "two", CN, kept=kept, env=None, log=None, cancel=None, stream=npm)
    assert not (tmp_path / "two").exists() and len(npm.calls) == 1


def test_a_failed_npm_ci_says_so_and_leaves_the_kept_lock(tmp_path, programs):
    kept = tmp_path / "kept"
    put(programs, tmp_path / "one", kept, Npm())
    with pytest.raises(node.NpmError, match="is not installed from its lock"):
        put(programs, tmp_path / "two", kept, Npm(code=1))
    assert node.lock_holds(kept, CN) == ""


def test_the_module_writes_out_no_address():
    found = [line.strip() for line in Path(node.__file__).read_text(encoding="utf-8").splitlines()
             if WRITTEN.search(line)]
    assert found == []
