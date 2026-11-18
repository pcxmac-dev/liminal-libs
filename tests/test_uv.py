"""uv as the plugins run it (liminal_libs.machines.uv, 1.62.0): its release archives' names and their two layouts; the
variables it is run with, each by the name its maker documents, every folder of them under the home given, and the
one address its Python may be held to; the command lines word for word, an install against a requirements file of
pinned sums among them; an index over https alone; the environment, the time allowed and the cancel handed on to the
runner; a command's lines to the log, the first saying whether a pinned sum checks what is installed, and its failure
in its own last words.

uv is not here and nothing runs: a stand-in takes the place of children.stream (the library's runner of an installer's
command), and the shared guard (conftest.py) fails a test that starts a process or opens a connection."""
from __future__ import annotations

import ast
import fnmatch
import os
import re
import sys
import types
from pathlib import Path

import pytest

from liminal_libs.machines import uv
from liminal_libs.machines.children import ChildError
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.terminal import Cancelled

pytestmark = pytest.mark.usefixtures("no_outside")

HTTPS = "https:" + "//"  # an address's start, put together here: no file names a host whole
INDEX = HTTPS + "wheels.example.test/simple"
MIRROR = HTTPS + "mirror.example.test/python-build-standalone/releases/download"
ENV = {"PATH": "/usr/bin", "UV_NO_CONFIG": "1"}
# a requirements file of pinned sums, as `uv pip compile --generate-hashes` writes one (the sums are made up)
PINNED = ("aider-chat==0.86.2 \\\n    --hash=sha256:" + "a" * 64 + "\n"
          "aiohttp==3.12.15 \\\n    --hash=sha256:" + "b" * 64 + " \\\n    --hash=sha256:" + "c" * 64 + "\n")


class Stream:
    """A stand-in for children.stream: what it was asked to run and how, the lines the command says, how it ends."""

    def __init__(self, lines=(), code=0, raises=None):
        self.lines, self.code, self.raises = list(lines), code, raises
        self.calls: list[dict] = []

    def __call__(self, argv, line, *, env=None, cwd=None, timeout=1800.0, cancel=None):
        self.calls.append({"argv": list(argv), "env": env, "cwd": cwd, "timeout": timeout, "cancel": cancel})
        for text in self.lines:
            line(text)
        if self.raises is not None:
            raise self.raises
        return self.code


def never() -> bool:
    return False


@pytest.fixture
def program(tmp_path):
    return tmp_path / "app" / "1.0" / "uv" / ("uv.exe" if os.name == "nt" else "uv")


@pytest.fixture
def pinned(tmp_path):
    path = tmp_path / "requirements-aider-chat-0.86.2.txt"
    path.write_text(PINNED, encoding="utf-8")
    return path


# -- its archives ------------------------------------------------------------------------------------------------------
def test_its_archives_are_named_for_each_system_and_unpacked_each_its_own_way(tmp_path):
    assert uv.archive("windows", "AMD64") == "uv-x86_64-pc-windows-msvc.zip"
    assert uv.archive("Windows", "ARM64") == "uv-aarch64-pc-windows-msvc.zip"
    assert uv.archive("windows", "AMD64", libc="musl") == "uv-x86_64-pc-windows-msvc.zip"  # (no C library to choose)
    assert uv.archive("linux", "x86_64") == "uv-x86_64-unknown-linux-gnu.tar.gz"
    assert uv.archive("linux", "aarch64") == "uv-aarch64-unknown-linux-gnu.tar.gz"
    assert uv.archive("linux", "x86_64", "musl") == "uv-x86_64-unknown-linux-musl.tar.gz"
    assert uv.archive("linux", "aarch64", "musl") == "uv-aarch64-unknown-linux-musl.tar.gz"
    assert uv.archive("linux" if os.name != "nt" else "windows") in uv.ARCHIVES.values()  # this machine's, by itself
    for system, machine, libc in (("darwin", "arm64", "gnu"), ("linux", "riscv64", "gnu"),
                                  ("linux", "x86_64", "uclibc"), ("windows", "x86", "gnu"), ("", "x86_64", "gnu")):
        with pytest.raises(ValueError, match="builds no archive here"):
            uv.archive(system, machine, libc)
    # Windows' .zip holds uv.exe at its root; Linux's .tar.gz one folder named as the archive
    for name in uv.ARCHIVES.values():
        assert uv.strip_of(name) == (0 if name.endswith(".zip") else 1)
    assert uv.strip_of("UV-X86_64-PC-WINDOWS-MSVC.ZIP") == 0
    for other in ("uv-x86_64-unknown-linux-gnu.tar.xz", "uv.exe", "", None):
        with pytest.raises(ValueError, match="not one of uv's archives"):
            uv.strip_of(other)
    assert uv.program_in(tmp_path, windows=True) == tmp_path / "uv.exe"
    assert uv.program_in(tmp_path, windows=False) == tmp_path / "uv"
    assert uv.program_in(tmp_path) == tmp_path / ("uv.exe" if os.name == "nt" else "uv")


# -- the environment ---------------------------------------------------------------------------------------------------
def test_the_environment_names_what_uvs_maker_documents_and_keeps_everything_under_the_home(tmp_path):
    root = tmp_path / "uv"
    env = uv.environment(tmp_path)
    assert env == {
        "UV_CACHE_DIR": str(root / "cache"),  # "uv will use this directory for caching instead of the default"
        "UV_PYTHON_INSTALL_DIR": str(root / "python"),  # "the directory for storing managed Python installations"
        "UV_PYTHON_BIN_DIR": str(root / "bin"),  # "to place links to installed, managed Python executables"
        "UV_PYTHON_INSTALL_BIN": "0",  # `--no-bin`: "This can also be set with UV_PYTHON_INSTALL_BIN=0"
        "UV_PYTHON_INSTALL_REGISTRY": "0",  # `--no-registry`: "This can also be set with UV_PYTHON_INSTALL_REGISTRY=0"
        "UV_PYTHON_NO_REGISTRY": "1",  # "managed Python installations will not be registered in the Windows registry"
        "UV_PYTHON_PREFERENCE": "only-managed",  # "Only use managed Python installations; never use system Python"
        "UV_TOOL_DIR": str(root / "tools"),  # "the directory where uv stores managed tools"
        "UV_TOOL_BIN_DIR": str(root / "bin"),  # 'the "bin" directory for installing tool executables'
        "UV_CREDENTIALS_DIR": str(root / "credentials"),  # "storage of credentials when using a plain text backend"
        "UV_INSTALL_DIR": str(root / "bin"),  # where "the standalone installer and `self update` feature" install uv
        "UV_NO_MODIFY_PATH": "1",  # "Avoid modifying the PATH ... standalone installer and `self update` feature"
        "UV_NO_CONFIG": "1",  # "uv will not read any configuration files"
        "UV_NO_HF_TOKEN": "1",  # "Disable Hugging Face authentication, even if HF_TOKEN is set"
        "UV_MALWARE_CHECK": "0",  # "Set this variable to 0 to opt out"
        "UV_LINK_MODE": "copy",
        "UV_NO_PROGRESS": "1",  # "Disables all progress output. For example, spinners and progress bars."
        "NO_COLOR": "1",  # "Disables colored output"
    }
    folders = [v for k, v in env.items() if k.endswith("_DIR")]
    assert len(folders) == 7 and all(Path(v).is_absolute() and Path(v).is_relative_to(tmp_path) for v in folders)
    assert all(isinstance(v, str) and "//" not in v for v in env.values())  # no address among them
    assert list(tmp_path.iterdir()) == []  # naming the folders makes none
    assert uv.folders(tmp_path) == {"cache": root / "cache", "python": root / "python", "tools": root / "tools",
                                    "bin": root / "bin", "credentials": root / "credentials"}
    assert uv.cache(tmp_path) == root / "cache" and uv.FOLDER == "uv"


def test_its_python_may_be_held_to_one_address_over_https_alone(tmp_path):
    env = uv.environment(tmp_path, python_mirror=MIRROR)
    assert env["UV_PYTHON_INSTALL_MIRROR"] == MIRROR  # then the only address its Python is asked of
    assert env == {**uv.environment(tmp_path), "UV_PYTHON_INSTALL_MIRROR": MIRROR}
    assert "UV_PYTHON_INSTALL_MIRROR" not in uv.environment(tmp_path, python_mirror="  ")
    secret = "s3cret"
    for bad in ("http:" + "//mirror.example.test/x", "file:" + "///C:/pythons", "ftp:" + "//mirror.example.test/x",
                "mirror.example.test/x", HTTPS, HTTPS + "/x", HTTPS + "mirror.example.test/a b", "C:\\pythons"):
        with pytest.raises(ValueError, match="over https alone|no space or control character"):
            uv.environment(tmp_path, python_mirror=bad)
    with pytest.raises(ValueError, match="without a name or a password") as e:
        uv.environment(tmp_path, python_mirror=HTTPS + f"me:{secret}@mirror.example.test/x")
    assert secret not in str(e.value)


def test_a_home_given_short_is_made_whole_and_the_platforms_own_uv_variables_are_dropped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env, whole = uv.environment("ai/aider/app/0.86.2"), tmp_path / "ai" / "aider" / "app" / "0.86.2"
    assert env["UV_CACHE_DIR"] == str(whole / "uv" / "cache")
    assert all(Path(v).is_relative_to(whole) for k, v in env.items() if k.endswith("_DIR"))
    # what is taken out of the platform's own environment first: a variable of the user's would be read before these
    assert uv.DROP == ("UV_*", "PIP_*", "VIRTUAL_ENV", "CONDA_*", "PYTHON*", "PYX_*")
    for name in ("UV_CONFIG_FILE", "UV_INDEX_URL", "UV_PYTHON", "UV_SYSTEM_CERTS", "PIP_INDEX_URL", "VIRTUAL_ENV",
                 "CONDA_PREFIX", "PYTHONPATH", "PYTHONHOME", "PYX_API_KEY", "PYX_AUTH_TOKEN",
                 *(n for n in env if n != "NO_COLOR")):
        assert any(fnmatch.fnmatchcase(name, pattern) for pattern in uv.DROP), name
    # what a network may need, and the user's netrc (read by uv whatever it is told), pass as they are
    for name in ("PATH", "HOME", "USERPROFILE", "TMP", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "NO_PROXY",
                 "NETRC"):
        assert not any(fnmatch.fnmatchcase(name, pattern) for pattern in uv.DROP), name


# -- an environment made -----------------------------------------------------------------------------------------------
def test_an_environment_is_made_with_this_command_word_for_word(tmp_path, program):
    folder = tmp_path / "app" / "1.0" / "venv"
    stream = Stream(["Using CPython 3.12.16\n", "Creating virtual environment at: venv\r\n"])
    said: list[str] = []
    got = uv.venv(program, folder, "3.12", env=ENV, log=said.append, cancel=never, stream=stream)
    call = stream.calls[0]
    assert call["argv"] == [str(program), "venv", "--python", "3.12", "--managed-python", "--no-project", "--no-config",
                            str(folder)]
    assert call["env"] == ENV and call["env"] is not ENV  # the environment given, whole, and a copy of it
    assert call["cwd"] == str(folder.parent) and folder.parent.is_dir()  # run in the plugin's own folder, made for it
    assert not folder.exists()  # the environment itself is uv's to make
    assert call["timeout"] == 600.0 == uv.VENV_S and call["cancel"] is never
    assert got == folder and len(stream.calls) == 1
    assert said == [f"uv: an environment in {folder}, on a Python 3.12 of uv's own", "Using CPython 3.12.16",
                    "Creating virtual environment at: venv"]


def test_an_environment_may_be_seeded_given_more_time_and_asked_without_a_log(tmp_path, program):
    stream = Stream()
    uv.venv(program, tmp_path / "venv-0.33.0", " 3.12 ", env=ENV, log=None, cancel=None, seed=True, timeout=90.0,
            stream=stream)
    call = stream.calls[0]
    assert call["argv"][1:] == ["venv", "--python", "3.12", "--managed-python", "--no-project", "--no-config", "--seed",
                                str(tmp_path / "venv-0.33.0")]
    assert call["timeout"] == 90.0 and call["cancel"] is None and call["cwd"] == str(tmp_path)
    for bad in ("", " ", None, "--python-preference=system", "-p"):
        with pytest.raises(ValueError, match="named by its version"):
            uv.venv(program, tmp_path / "venv", bad, env=ENV, log=None, cancel=None, stream=stream)
    assert len(stream.calls) == 1


def test_an_environment_is_made_only_where_there_is_nothing_yet(tmp_path, program):
    stream = Stream()
    (tmp_path / "empty").mkdir()
    assert uv.venv(program, tmp_path / "empty", "3.12", env=ENV, log=None, cancel=None, stream=stream) == (
        tmp_path / "empty")
    left = tmp_path / "left"  # what an install that did not end left behind
    (left / "Lib").mkdir(parents=True)
    said: list[str] = []
    with pytest.raises(uv.UvError, match="is not empty: uv makes an environment only where there is nothing yet"):
        uv.venv(program, left, "3.12", env=ENV, log=said.append, cancel=None, stream=stream)
    (tmp_path / "a file").write_text("x", encoding="utf-8")
    with pytest.raises(uv.UvError, match="is not empty"):
        uv.venv(program, tmp_path / "a file", "3.12", env=ENV, log=said.append, cancel=None, stream=stream)
    assert len(stream.calls) == 1 and said == []  # nothing run and nothing said for either
    # the folder it runs in cannot be made: said in words, nothing run
    (tmp_path / "taken").write_text("a file where a folder would be", encoding="utf-8")
    with pytest.raises(uv.UvError, match="`uv venv` was not started: .* could not be made"):
        uv.venv(program, tmp_path / "taken" / "venv", "3.12", env=ENV, log=said.append, cancel=None, stream=stream)
    assert len(stream.calls) == 1 and said == []


def test_a_short_folder_is_made_whole_before_the_command_runs_elsewhere(tmp_path, program, monkeypatch):
    monkeypatch.chdir(tmp_path)
    stream = Stream()
    whole = tmp_path / "one" / "venv"
    assert uv.venv(program, "one/venv", "3.12", env=ENV, log=None, cancel=None, stream=stream) == whole
    assert stream.calls[0]["argv"][-1] == str(whole) and stream.calls[0]["cwd"] == str(tmp_path / "one")
    uv.pip_install("tools/uv", "one/venv", "x==1", env=ENV, log=None, cancel=None, stream=stream)
    assert stream.calls[1]["argv"][0] == str(tmp_path / "tools" / "uv")  # the program too: it runs in another folder
    assert stream.calls[1]["argv"][4] == str(uv.python_of(whole))
    uv.pip_install("uv", "one/venv", "x==1", env=ENV, log=None, cancel=None, stream=stream)
    assert stream.calls[2]["argv"][0] == "uv"  # a bare name is looked for on PATH
    for none in ("", None):
        with pytest.raises(ValueError, match="named by its path"):
            uv.pip_install(none, "one/venv", "x==1", env=ENV, log=None, cancel=None, stream=stream)


# -- an install into it ------------------------------------------------------------------------------------------------
def test_an_install_is_this_command_word_for_word(tmp_path, program):
    venv = tmp_path / "app" / "0.86.2" / "venv"
    venv.mkdir(parents=True)
    stream = Stream(["Resolved 108 packages in 1.2s", "Installed 108 packages in 4.1s"])
    said: list[str] = []
    done = uv.pip_install(program, venv, "aider-chat==0.86.2", env=ENV, log=said.append, cancel=never, stream=stream)
    call = stream.calls[0]
    python = venv / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    assert call["argv"] == [str(program), "pip", "install", "--python", str(python), "--no-config",
                            "aider-chat==0.86.2"]
    assert call["env"] == ENV and call["env"] is not ENV and call["cwd"] == str(venv.parent)
    assert call["timeout"] == 3600.0 == uv.INSTALL_S and call["cancel"] is never and done is None
    # said as it is: what is taken as its index gives it is checked against no sum pinned here
    assert said == [f"uv: aider-chat==0.86.2 into {venv}, as its index gives it: no sum pinned here checks it",
                    "Resolved 108 packages in 1.2s", "Installed 108 packages in 4.1s"]


def test_an_install_against_pinned_sums_reads_them_from_a_file_of_the_plugins(tmp_path, program, pinned, monkeypatch):
    monkeypatch.chdir(tmp_path)
    venv = tmp_path / "venv"
    stream = Stream(["Installed 109 packages in 5.0s"])
    said: list[str] = []
    uv.pip_install(program, venv, env=ENV, log=said.append, cancel=never, requirements=pinned, stream=stream)
    assert stream.calls[0]["argv"] == [str(program), "pip", "install", "--python", str(uv.python_of(venv)),
                                       "--no-config", "--require-hashes", "--requirements", str(pinned)]
    assert said[0] == (f"uv: the packages pinned in {pinned.name} into {venv}, each checked against its sum pinned "
                       "there")
    # with an index and switches too; a file named short is made whole (uv runs in another folder)
    uv.pip_install(program, venv, (), env=ENV, log=None, cancel=None, index=INDEX, extra=("--torch-backend=cu130",),
                   requirements=pinned.name, stream=stream)
    assert stream.calls[1]["argv"][5:] == ["--no-config", "--index", INDEX, "--require-hashes", "--requirements",
                                           str(pinned), "--torch-backend=cu130"]
    # everything installed is in the file: a command line carries no sum
    with pytest.raises(ValueError, match="everything installed is in it .requirements-aider-chat-0.86.2.txt.: "
                                         "aider-chat==0.86.2 on the command line would carry no sum"):
        uv.pip_install(program, venv, "aider-chat==0.86.2", env=ENV, log=None, cancel=None, requirements=pinned,
                       stream=stream)
    with pytest.raises(ValueError, match="is not there: an install against pinned sums reads them from a file"):
        uv.pip_install(program, venv, env=ENV, log=None, cancel=None, requirements=tmp_path / "gone.txt",
                       stream=stream)
    with pytest.raises(ValueError, match="is not there"):
        uv.pip_install(program, venv, env=ENV, log=None, cancel=None, requirements=tmp_path, stream=stream)  # a folder
    with pytest.raises(ValueError, match="a requirements file as `requirements`"):
        uv.pip_install(program, venv, ["-r", str(pinned)], env=ENV, log=None, cancel=None, stream=stream)
    assert len(stream.calls) == 2


def test_an_install_takes_one_more_index_and_switches_as_uv_spells_them(tmp_path, program):
    venv = tmp_path / "venv-0.33.0"
    stream = Stream()
    uv.pip_install(program, venv, ["vllm==0.33.0", " flashinfer-python==0.9.1 "], env=ENV, log=None, cancel=None,
                   index=INDEX, extra=("--torch-backend=cu130",), timeout=7200.0, stream=stream)
    call = stream.calls[0]
    assert call["argv"] == [str(program), "pip", "install", "--python", str(uv.python_of(venv)), "--no-config",
                            "--index", INDEX, "--torch-backend=cu130", "vllm==0.33.0", "flashinfer-python==0.9.1"]
    assert call["timeout"] == 7200.0
    assert call["cwd"] == str(tmp_path)
    uv.pip_install(program, tmp_path / "gone" / "venv", "x==1", env=ENV, log=None, cancel=None, stream=stream)
    assert stream.calls[1]["cwd"] is None  # no folder to run in: the runner's own
    assert uv.python_of("v", windows=True) == Path("v") / "Scripts" / "python.exe"
    assert uv.python_of("v", windows=False) == Path("v") / "bin" / "python"


def test_an_index_is_asked_over_https_alone_and_never_with_a_login(tmp_path, program):
    stream = Stream()
    for bad in ("http:" + "//wheels.example.test/simple", "file:" + "///C:/wheels", "ftp:" + "//wheels.example.test",
                "wheels.example.test/simple", "./wheels", "C:\\wheels", HTTPS, "https:wheels.example.test",
                "sk-abc123:" + "x"):
        with pytest.raises(ValueError, match="an index is asked over https alone") as e:
            uv.pip_install(program, tmp_path, "x==1", env=ENV, log=None, cancel=None, index=bad, stream=stream)
        assert "sk-abc123" not in str(e.value)  # the words never repeat what was refused
    with pytest.raises(ValueError, match="no space or control character"):
        uv.pip_install(program, tmp_path, "x==1", env=ENV, log=None, cancel=None, index=INDEX + "\n--index-url=x",
                       stream=stream)
    keyed = HTTPS + "me:s3cret@wheels.example.test/simple"
    with pytest.raises(ValueError, match="without a name or a password in its address") as e:
        uv.pip_install(program, tmp_path, "x==1", env=ENV, log=None, cancel=None, index=keyed, stream=stream)
    assert "s3cret" not in str(e.value) and stream.calls == []
    uv.pip_install(program, tmp_path, "x==1", env=ENV, log=None, cancel=None, index="  " + INDEX + " ", stream=stream)
    assert stream.calls[0]["argv"][6:8] == ["--index", INDEX]
    assert ("HTTPS:" + "//wheels.example.test") == uv._https("HTTPS:" + "//wheels.example.test", "an index")


def test_what_is_installed_is_named_and_a_switch_is_not_a_package(tmp_path, program):
    stream = Stream()
    for nothing in ("", " ", [], None, (), ["x==1", ""]):
        with pytest.raises(ValueError, match="nothing was named"):
            uv.pip_install(program, tmp_path, nothing, env=ENV, log=None, cancel=None, stream=stream)
    with pytest.raises(ValueError, match="nothing was named"):
        uv.pip_install(program, tmp_path, env=ENV, log=None, cancel=None, stream=stream)
    for switch in ("--index-url=x", ["x==1", "-e"], ["-r", "requirements.txt"]):
        with pytest.raises(ValueError, match="is a switch, not something to install"):
            uv.pip_install(program, tmp_path, switch, env=ENV, log=None, cancel=None, stream=stream)
    assert stream.calls == []


def test_the_whole_environment_is_the_platforms_without_uvs_and_pips_and_every_pair(tmp_path, monkeypatch, program):
    # what a plugin hands venv and pip_install: the platform's (its Outside's env) without DROP, LIMINAL_* and what
    # it drops (an AI plugin's dropped()), uv's own over it. AiPlugin.child_env would keep the user's UV_INSECURE_HOST
    # (TLS checks off for a host), UV_INDEX_URL and PYTHONPATH: it takes out the plugin's names alone
    proxy, certs = "proxy.example.test:3128", "/etc/ssl/certs/ca-certificates.crt"
    base = {"PATH": "/usr/bin", "HOME": "/home/me", "HTTPS_PROXY": proxy, "SSL_CERT_FILE": certs, "NETRC": "/home/me/n",
            "UV_INSECURE_HOST": "files.example.test", "UV_INDEX_URL": "elsewhere", "UV_CONFIG_FILE": "/home/me/uv.toml",
            "PIP_INDEX_URL": "elsewhere", "VIRTUAL_ENV": "/home/me/venv", "CONDA_PREFIX": "/opt/conda",
            "PYTHONPATH": "x", "PYTHONHOME": "y", "PYX_API_KEY": "pyx-token", "LIMINAL_AI_VLLM_GPU_KEY": "sk-not-uvs",
            "NAMECHEAP_API_KEY": "nc-not-uvs", "OLLAMA_HOST": "o", "OLLAMA_MODELS": "m"}
    env = uv.child_env(tmp_path, base=base, drop=("NAMECHEAP_API_KEY", "OLLAMA_*"), system="linux")
    assert env == {"PATH": "/usr/bin", "HOME": "/home/me", "HTTPS_PROXY": proxy, "SSL_CERT_FILE": certs,
                   "NETRC": "/home/me/n", **uv.environment(tmp_path)}
    assert uv.child_env(tmp_path, base=base, drop="NAMECHEAP_API_KEY", system="linux").get("OLLAMA_HOST") == "o"
    assert "NAMECHEAP_API_KEY" in uv.child_env(tmp_path, base=base, system="linux")  # dropped only when named
    # on Windows names are told apart without regard to case, as Windows does
    odd = {"Path": "C:\\Windows", "uv_insecure_host": "x", "Pythonpath": "y", "Liminal_Platform_Dir": "z",
           "uv_cache_dir": "the user's own cache"}
    assert uv.child_env(tmp_path, base=odd, system="windows") == {"Path": "C:\\Windows", **uv.environment(tmp_path)}
    assert uv.child_env(tmp_path, base={}, python_mirror=MIRROR, system="linux") == uv.environment(
        tmp_path, python_mirror=MIRROR)
    monkeypatch.setenv("UV_INDEX_URL", "elsewhere")  # without a base: this process's own, the same way
    monkeypatch.setenv("LIMINAL_AI_VLLM_GPU_KEY", "sk-not-uvs")
    mine = uv.child_env(tmp_path)
    assert mine["UV_CACHE_DIR"] == str(tmp_path / "uv" / "cache") and "UV_INDEX_URL" not in mine
    assert not any(name.upper().startswith("LIMINAL_") for name in mine)
    stream = Stream()  # ... and it is what the command is handed, whole
    uv.venv(program, tmp_path / "venv", "3.12", env=env, log=None, cancel=None, stream=stream)
    assert stream.calls[0]["env"] == env


def test_uvs_cache_may_lie_outside_the_folder_an_install_is_built_in(tmp_path, monkeypatch):
    # built in app/<pin> (its Python leaves with it), its cache in the plugin's downloads/: a cancelled or failed
    # install, whose folder the base removes, leaves what uv downloaded for the next try
    building, kept = tmp_path / "ai" / "vllm" / "app" / "0.33.0", tmp_path / "ai" / "vllm" / "downloads" / "uv"
    env = uv.environment(building, cache=kept)
    assert env == {**uv.environment(building), "UV_CACHE_DIR": str(kept)}
    assert all(Path(v).is_relative_to(building) for k, v in env.items() if k.endswith("_DIR") and k != "UV_CACHE_DIR")
    assert uv.child_env(building, base={"UV_CACHE_DIR": "the user's"}, cache=kept, system="linux")["UV_CACHE_DIR"] == (
        str(kept))
    monkeypatch.chdir(tmp_path)  # a short one is made whole
    assert uv.environment(building, cache="ai/vllm/downloads/uv")["UV_CACHE_DIR"] == str(kept)
    for none in ("", "  "):
        with pytest.raises(ValueError, match="uv's cache is named by its folder"):
            uv.environment(building, cache=none)
    assert list(tmp_path.iterdir()) == []  # naming them makes none


# -- the environment given whole, the cancel handed on -----------------------------------------------------------------
def test_uv_is_never_run_with_the_platforms_whole_environment(tmp_path, program, pinned):
    stream = Stream()
    with pytest.raises(ValueError, match="an environment given whole"):
        uv.venv(program, tmp_path / "venv", "3.12", env=None, log=None, cancel=None, stream=stream)
    with pytest.raises(ValueError, match="an environment given whole"):
        uv.pip_install(program, tmp_path / "venv", "x==1", env=None, log=None, cancel=None, stream=stream)
    with pytest.raises(ValueError, match="an environment given whole"):
        uv.pip_install(program, tmp_path / "venv", env=None, log=None, cancel=None, requirements=pinned, stream=stream)
    assert stream.calls == []
    uv.venv(program, tmp_path / "venv", "3.12", env={}, log=None, cancel=None, stream=stream)  # an empty one is one
    assert stream.calls[0]["env"] == {}


def test_a_cancel_is_handed_on_and_one_already_asked_starts_nothing(tmp_path, program):
    asked: list[int] = []

    def cancel() -> bool:
        asked.append(1)
        return len(asked) > 1
    stream = Stream()
    uv.venv(program, tmp_path / "venv", "3.12", env=ENV, log=None, cancel=cancel, stream=stream)
    assert stream.calls[0]["cancel"] is cancel and asked == [1]  # looked at once here, then the runner's to look at
    said: list[str] = []
    with pytest.raises(Cancelled, match="cancelled before `uv pip install` was started"):
        uv.pip_install(program, tmp_path / "venv", "x==1", env=ENV, log=said.append, cancel=cancel, stream=stream)
    with pytest.raises(Cancelled, match="cancelled before `uv venv` was started"):
        uv.venv(program, tmp_path / "new" / "venv", "3.12", env=ENV, log=said.append, cancel=cancel, stream=stream)
    assert len(stream.calls) == 1 and said == [] and not (tmp_path / "new").exists()  # nothing run, said or made
    # the runner's own cancel (it ends the command and what it started) is not taken for a failure
    stopped = Stream(["Downloading torch (555.0MiB)"], raises=Cancelled("cancelled"))
    with pytest.raises(Cancelled, match="^cancelled$"):
        uv.pip_install(program, tmp_path / "venv", "x==1", env=ENV, log=None, cancel=never, stream=stopped)


# -- how a command ends ------------------------------------------------------------------------------------------------
def test_a_command_that_does_not_end_well_is_said_in_its_own_last_words(tmp_path, program):
    stream = Stream(["Using CPython 3.12.16", "  × No solution found when resolving dependencies:", "", "  \n"], code=1)
    with pytest.raises(uv.UvError) as e:
        uv.pip_install(program, tmp_path, "x==1", env=ENV, log=None, cancel=None, stream=stream)
    assert str(e.value) == "`uv pip install` ended with 1: × No solution found when resolving dependencies:"
    assert isinstance(e.value, CommandError) and not e.value.denied
    with pytest.raises(uv.UvError, match="^`uv venv` ended with 2$"):
        uv.venv(program, tmp_path / "venv", "3.12", env=ENV, log=None, cancel=None, stream=Stream(code=2))
    long = Stream(["error: " + "x" * 2000], code=2)
    with pytest.raises(uv.UvError) as e:
        uv.venv(program, tmp_path / "venv", "3.12", env=ENV, log=None, cancel=None, stream=long)
    assert len(str(e.value)) == len("`uv venv` ended with 2: ") + uv.LINE
    many = Stream([f"line {i}" for i in range(50)], code=3)  # only its last lines are kept: a long install's are many
    with pytest.raises(uv.UvError, match="^`uv venv` ended with 3: line 49$"):
        uv.venv(program, tmp_path / "venv", "3.12", env=ENV, log=None, cancel=None, stream=many)
    # a sum that does not match is uv's refusal, said in its own words like any other
    mismatch = Stream(["error: Hash mismatch for `aiohttp==3.12.15`"], code=2)
    with pytest.raises(uv.UvError, match="ended with 2: error: Hash mismatch for `aiohttp==3.12.15`"):
        uv.pip_install(program, tmp_path, env=ENV, log=None, cancel=None, requirements=__file__, stream=mismatch)


def test_the_runners_own_failures_come_as_it_raises_them(tmp_path, program):
    # children.stream says itself that a program cannot be started (ChildError, a CommandError): its words reach the
    # caller as they are, as do its words for a command it ended at its time limit
    missing = Stream(raises=ChildError("uv.exe could not run: [WinError 2] The system cannot find the file specified"))
    with pytest.raises(ChildError, match="^uv.exe could not run: .*cannot find the file specified$") as e:
        uv.venv(program, tmp_path / "venv", "3.12", env=ENV, log=None, cancel=None, stream=missing)
    assert isinstance(e.value, CommandError) and not isinstance(e.value, uv.UvError)
    slow = Stream(raises=ChildError("uv took more than 600 s and was ended with what it started"))
    with pytest.raises(CommandError, match="^uv took more than 600 s") as e:
        uv.venv(program, tmp_path / "venv", "3.12", env=ENV, log=None, cancel=None, stream=slow)
    assert not isinstance(e.value, uv.UvError)


# -- the runner --------------------------------------------------------------------------------------------------------
def test_the_runner_is_the_librarys_own_taken_when_a_command_is_run(tmp_path, program, monkeypatch):
    tree = ast.parse(Path(uv.__file__).read_text(encoding="utf-8"))
    at_import = [ast.dump(n) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert at_import and not any("children" in n for n in at_import)  # not loaded with the module
    stand_in = types.ModuleType("liminal_libs.machines.children")
    stand_in.stream = Stream(["Using CPython 3.12.16"])
    monkeypatch.setitem(sys.modules, "liminal_libs.machines.children", stand_in)
    said: list[str] = []
    uv.venv(program, tmp_path / "venv", "3.12", env=ENV, log=said.append, cancel=never)
    call = stand_in.stream.calls[0]
    assert call["argv"][:2] == [str(program), "venv"] and call["env"] == ENV and call["cancel"] is never
    assert said[-1] == "Using CPython 3.12.16"
    uv.pip_install(program, tmp_path / "venv", "x==1", env=ENV, log=None, cancel=never)
    assert stand_in.stream.calls[1]["argv"][1:3] == ["pip", "install"]


def test_the_module_names_no_host():
    text = Path(uv.__file__).read_text(encoding="utf-8")
    assert re.search(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]", text) is None
