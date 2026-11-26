"""This machine's NVIDIA cards read through nvidia-smi (liminal_libs.machines.gpu, 1.62.0): the command found on PATH
or at WSL's own place, the one windowless command a reading runs and its environment (no pair of Liminal's), its
answers read (this PC's card as it was recorded, two cards, a figure it does not say, a line that is something else),
its failures said in words and never raised, a stand-in runner never looked for on this machine, a reading kept while
it is fresh and only for what it was read through, what fits a card in words, and the table a page draws.

Nothing runs here: a runner stands in for nvidia-smi, and the shared guard (conftest.py) fails a test that starts a
process or opens a connection."""
from __future__ import annotations

import os
import re
import subprocess
import threading

import pytest

from conftest import Reached
from liminal_libs.machines import gpu
from liminal_libs.machines.gpu import Gpu, Gpus

pytestmark = pytest.mark.usefixtures("no_outside", "stand_in_environment")

# this PC's answer to the query, as nvidia-smi wrote it (2026-11-16)
RTX_5090 = "0, NVIDIA GeForce RTX 5090 Laptop GPU, 24463, 2298, 21840, 595.71\n"
CARD = Gpu(0, "NVIDIA GeForce RTX 5090 Laptop GPU", 24463 << 20, 2298 << 20, 21840 << 20, "595.71")
# two cards, a line each, written after the same format (not recorded)
TWO = "0, NVIDIA RTX A6000, 49140, 30000, 18824, 580.88\n1, NVIDIA RTX A6000, 49140, 1024, 47800, 580.88\n"
QUERY = ["--query-gpu=index,name,memory.total,memory.used,memory.free,driver_version", "--format=csv,noheader,nounits"]


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setattr(gpu, "_kept", [])  # no reading is carried from one test into the next


def nowhere(name):
    return None


def never(path):
    return False


class Runner:
    """A stand-in for nvidia-smi: what it was asked with, and the answer it gives (an exception: raised)."""

    def __init__(self, *answers):
        self.answers, self.asked = list(answers), []

    def __call__(self, args, timeout):
        self.asked.append((list(args), timeout))
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, BaseException):
            raise answer
        return answer


class Done:
    returncode, stdout, stderr = 0, RTX_5090.encode(), b""


# -- where the command is ----------------------------------------------------------------------------------------------
def test_the_command_is_found_on_the_path_then_at_wsls_own_place(monkeypatch):
    on_path = r"C:\WINDOWS\system32\nvidia-smi.EXE"
    assert gpu.command(lambda name: on_path if name == "nvidia-smi" else None, never) == on_path
    asked: list[str] = []
    assert gpu.command(nowhere, lambda path: asked.append(path) or True) == "/usr/lib/wsl/lib/nvidia-smi"
    assert asked == ["/usr/lib/wsl/lib/nvidia-smi"] and gpu.WSL_PATH == asked[0]
    assert gpu.command(nowhere, never) == ""
    # PATH is looked at when it is asked, not when the module was loaded
    monkeypatch.setattr(gpu.shutil, "which", lambda name: f"/opt/nvidia/{name}")
    assert gpu.command() == "/opt/nvidia/nvidia-smi"


# -- a reading ---------------------------------------------------------------------------------------------------------
def test_a_reading_asks_one_command_and_reads_this_pcs_card():
    runner = Runner((0, RTX_5090, ""))
    got = gpu.read(runner, clock=lambda: 1000.0)
    assert runner.asked == [(["nvidia-smi", *QUERY], 10.0)]  # by its bare name: the stand-in is the command
    assert got == Gpus((CARD,), "", 1000.0)
    assert got.cards[0].total == 24463 * 1024 * 1024 and got.cards[0].driver == "595.71"
    as_bytes = Runner((0, RTX_5090.encode(), b""))
    assert gpu.read(as_bytes, timeout=3.0, clock=lambda: 5.0) == Gpus((CARD,), "", 5.0) and as_bytes.asked[0][1] == 3.0
    assert gpu.read(Runner((0, RTX_5090, "")), clock=None).cards == (CARD,)  # no clock given: the system's


def test_the_command_itself_runs_windowless_with_nothing_typed_into_it(monkeypatch):
    ran: list = []

    def run(args, **kw):
        ran.append((list(args), kw))
        return Done()
    monkeypatch.setattr(gpu.subprocess, "run", run)
    found = r"C:\WINDOWS\system32\nvidia-smi.EXE"
    assert gpu.read(which=lambda name: found, clock=lambda: 7.0) == Gpus((CARD,), "", 7.0)
    args, kw = ran[0]
    assert args == [found, *QUERY] and kw["timeout"] == 10.0 and "shell" not in kw
    assert kw["stdin"] is subprocess.DEVNULL and kw["stdout"] is subprocess.PIPE and kw["stderr"] is subprocess.PIPE
    assert kw.get("creationflags", 0) == (0x08000000 if os.name == "nt" else 0)  # CREATE_NO_WINDOW on Windows
    for system, flags in (("nt", 0x08000000), ("posix", 0)):  # ... on each system
        with monkeypatch.context() as m:
            m.setattr(gpu.os, "name", system)
            gpu._run([found], 1.0)
        assert ran[-1][1].get("creationflags", 0) == flags


def test_no_pair_of_liminals_reaches_the_command(monkeypatch, stand_in_environment):
    ran: list[dict] = []

    def run(args, **kw):
        ran.append(kw["env"])
        return Done()
    monkeypatch.setattr(gpu.subprocess, "run", run)
    monkeypatch.setenv("LIMINAL_AI_OLLAMA_DEFAULT_KEY", "s3cret")
    monkeypatch.setenv("Liminal_Platform_Dir", "C:\\somewhere")  # any case: Windows' names are not told apart by it
    monkeypatch.setenv("SOMETHING_OF_THE_USERS", "kept")
    found = "/usr/bin/nvidia-smi"
    assert gpu.read(which=lambda name: found).cards == (CARD,)
    names = {k.upper() for k in ran[0]}
    assert not any(k.startswith("LIMINAL_") for k in names) and "SOMETHING_OF_THE_USERS" in names
    assert "s3cret" not in ran[0].values()
    # an environment given (a plugin's, without every name it drops) is the command's whole environment, as it is
    given = {"PATH": "/usr/bin", "SYSTEMROOT": "C:\\Windows"}
    assert gpu.read(which=lambda name: found, env=given).cards == (CARD,)
    assert ran[1] == given and ran[1] is not given
    assert gpu.environment(given) == given and "LIMINAL_AI_OLLAMA_DEFAULT_KEY" not in gpu.environment()
    # a runner is the command's stand-in: what it is handed is its own business, and it is handed no environment
    runner = Runner((0, RTX_5090, ""))
    assert gpu.read(runner, env=given).cards == (CARD,) and runner.asked == [(["nvidia-smi", *QUERY], 10.0)]


def test_without_the_command_nothing_is_run_and_the_reading_says_so():
    assert gpu.read(which=nowhere, exists=never, clock=lambda: 3.0) == Gpus((), "nvidia-smi is not on this system", 3.0)
    runner = Runner((0, RTX_5090, ""))
    assert gpu.read(runner, which=nowhere, exists=never).why == gpu.NOT_HERE and runner.asked == []
    # one stand-in given beside a runner: the lookup not given finds nothing (it is not asked of this machine)
    assert gpu.read(runner, which=nowhere).why == gpu.NOT_HERE and runner.asked == []
    assert gpu.read(runner, exists=never).why == gpu.NOT_HERE and runner.asked == []
    assert gpu.read(runner, which=lambda name: "/opt/bin/nvidia-smi").cards == (CARD,)
    assert runner.asked[0][0][0] == "/opt/bin/nvidia-smi"


def test_under_wsl_the_command_is_run_from_its_own_place():
    runner = Runner((0, RTX_5090, ""))
    assert gpu.read(runner, which=nowhere, exists=lambda path: path == gpu.WSL_PATH).cards == (CARD,)
    assert runner.asked[0][0] == ["/usr/lib/wsl/lib/nvidia-smi", *QUERY]
    assert gpu.read(runner, exists=lambda path: path == gpu.WSL_PATH).cards == (CARD,)  # PATH not asked of this one
    assert runner.asked[1][0][0] == gpu.WSL_PATH


def test_a_stand_in_runner_is_never_looked_for_on_this_machine(monkeypatch):
    # a test that gives a runner alone answers the same here (nvidia-smi on PATH) and in CI (none anywhere): the
    # runner is asked by the bare name, and this machine's PATH and disk are not read for it
    runner = Runner((0, RTX_5090, ""))

    def looked(*args):
        raise AssertionError("this machine's PATH or disk was read for a stand-in")
    with monkeypatch.context() as m:  # a machine with no nvidia-smi, and lookups that fail the test when asked
        m.setattr(gpu.shutil, "which", looked)
        m.setattr(gpu.os.path, "exists", looked)
        assert gpu.read(runner).cards == (CARD,)
        assert gpu.kept(runner=runner, clock=lambda: 1.0).cards == (CARD,)
    assert [a[0][0] for a in runner.asked] == ["nvidia-smi"] * 2


def test_a_failure_is_said_in_words_and_never_raised():
    no_driver = ("NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver. Make sure that the "
                 "latest NVIDIA driver is installed and running.\n")
    assert gpu.read(Runner((9, "", "\n" + no_driver)), clock=lambda: 1.0) == Gpus(
        (), "nvidia-smi ended with 9: " + no_driver.strip(), 1.0)
    assert gpu.read(Runner((9, no_driver, ""))).why.startswith("nvidia-smi ended with 9: NVIDIA-SMI has failed")
    assert gpu.read(Runner((1, "", ""))).why == "nvidia-smi ended with 1"
    assert len(gpu.read(Runner((2, "x" * 5000, ""))).why) == len("nvidia-smi ended with 2: ") + gpu.LINE
    slow = gpu.read(Runner(subprocess.TimeoutExpired(["nvidia-smi"], 10.0)))
    assert slow == Gpus((), "nvidia-smi gave no answer in 10 s", slow.at)
    gone = gpu.read(Runner(FileNotFoundError(2, "No such file or directory")))
    assert gone.cards == () and gone.why.startswith("nvidia-smi could not be run: ") and "No such file" in gone.why
    assert gpu.read(Runner((0, "", ""))).why == "nvidia-smi names no GPU" == gpu.NONE_NAMED
    assert gpu.read(Runner((0, "\n \n", ""))).why == gpu.NONE_NAMED


def test_what_is_not_the_commands_doing_is_not_taken_for_a_failure(no_outside):
    # a reach for the real command is the guard's to fail, and is never said as "nvidia-smi could not be run"
    with pytest.raises(Reached, match="subprocess.run"):
        gpu.read(which=lambda name: "nvidia-smi")
    assert len(no_outside) == 1 and no_outside[0].startswith("subprocess.run")
    no_outside.clear()  # (reached on purpose: the guard's own check at the end stays quiet)
    for stopped in (KeyboardInterrupt(), SystemExit(1)):  # this process told to end: not an answer of the command's
        with pytest.raises(type(stopped)):
            gpu.read(Runner(stopped))


def test_several_cards_a_figure_not_said_and_a_broken_line():
    two = gpu.read(Runner((0, TWO, "")))
    assert [(g.index, g.name, g.used, g.free) for g in two.cards] == [
        (0, "NVIDIA RTX A6000", 30000 << 20, 18824 << 20), (1, "NVIDIA RTX A6000", 1024 << 20, 47800 << 20)]
    assert two.why == ""
    # a figure it does not say is the difference of the two it says
    cards, unread = gpu.parse("0, NVIDIA GeForce RTX 5090 Laptop GPU, 24463, [N/A], 21840, 595.71\n"
                              "1, NVIDIA GeForce RTX 5090 Laptop GPU, 24463, 2298, [Not Supported], [N/A]\n")
    assert [(g.used, g.free, g.driver) for g in cards] == [((24463 - 21840) << 20, 21840 << 20, "595.71"),
                                                           (2298 << 20, (24463 - 2298) << 20, "")]
    assert unread == []
    # any word in brackets is a figure it does not have, an N/A too
    cards, unread = gpu.parse("0, A card, 8192, [Insufficient Permissions], 4096, [Insufficient Permissions]\n"
                              "1, A card, 8192, 0, 8192, N/A\n")
    assert [(g.used, g.driver) for g in cards] == [(4096 << 20, ""), (0, "")] and unread == []
    # neither said: the card is not read, and why is said
    silent = gpu.read(Runner((0, "0, NVIDIA GeForce RTX 5090 Laptop GPU, 24463, [N/A], [N/A], 595.71\n", "")))
    assert silent.cards == ()
    assert silent.why == "nvidia-smi does not say the NVIDIA GeForce RTX 5090 Laptop GPU's memory (24463, [N/A], [N/A])"
    # a line that is something else
    broken = gpu.read(Runner((0, "No devices were found\n", "")))
    assert broken == Gpus((), "nvidia-smi's answer could not be read: No devices were found", broken.at)
    unnumbered = gpu.read(Runner((0, "zero, a card, 1, 1, 1, 1\n", "")))
    assert unnumbered.why == "nvidia-smi's answer could not be read: zero, a card, 1, 1, 1, 1"
    mixed = gpu.read(Runner((0, "Unable to determine the device handle for GPU1\r\n" + RTX_5090, "")))
    assert mixed.cards == (CARD,)
    assert mixed.why == "nvidia-smi's answer could not be read: Unable to determine the device handle for GPU1"
    # a name with a comma in it, and figures written with their unit
    cards, unread = gpu.parse("3, Tesla T4, 16 GB edition, 15360 MiB, 100 MiB, 15260 MiB, 550.54")
    assert cards == (Gpu(3, "Tesla T4, 16 GB edition", 15360 << 20, 100 << 20, 15260 << 20, "550.54"),) and unread == []


# -- kept while it is fresh --------------------------------------------------------------------------------------------
def test_a_reading_is_kept_while_it_is_fresh():
    now = {"at": 100.0}
    runner = Runner((0, RTX_5090, ""))

    def clock():
        return now["at"]
    first = gpu.kept(runner=runner, clock=clock)
    assert first == Gpus((CARD,), "", 100.0) and gpu.kept(runner=runner, clock=clock) is first
    now["at"] = 129.5
    assert gpu.kept(runner=runner, clock=clock) is first and len(runner.asked) == 1
    now["at"] = 130.0  # 30 s later: read again
    again = gpu.kept(runner=runner, clock=clock)
    assert again.at == 130.0 and again is not first and len(runner.asked) == 2 and gpu.KEPT_S == 30.0
    assert gpu.kept(0.0, runner=runner, clock=clock) is not again and len(runner.asked) == 3  # asked now all the same
    assert gpu.kept(600.0, runner=runner, clock=clock).at == 130.0 and len(runner.asked) == 3
    now["at"] = 20.0  # a clock that went back: the reading is not taken for a fresh one
    assert gpu.kept(runner=runner, clock=clock).at == 20.0 and len(runner.asked) == 4
    assert len(gpu._kept) == 1  # one reading for one runner, however often it was read again


def test_a_reading_is_kept_only_for_what_it_was_read_through():
    clock = lambda: 50.0  # noqa: E731
    card, none = Runner((0, RTX_5090, "")), Runner((0, "", ""))
    assert gpu.kept(runner=card, clock=clock).cards == (CARD,)
    assert gpu.kept(runner=none, clock=clock).why == gpu.NONE_NAMED  # another stand-in: never the first one's answer
    assert gpu.kept(runner=card, clock=clock).cards == (CARD,) and len(card.asked) == 1 and len(none.asked) == 1
    # the lookups belong to it too: another stand-in for where the command is reads again
    assert gpu.kept(runner=card, which=nowhere, exists=never, clock=clock).why == gpu.NOT_HERE
    assert gpu.kept(runner=card, clock=clock).cards == (CARD,) and len(card.asked) == 1
    # the real lookups are none given (ModelServer hands None for them), whatever else differs: every plugin's page
    # shares the one reading
    assert gpu._same(gpu._key({"clock": clock, "env": {"PATH": "/usr/bin"}, "timeout": 3.0}), gpu._key({}))
    assert not gpu._same(gpu._key({"runner": card}), gpu._key({"runner": none}))
    # KEPT_MOST at most: the oldest goes first
    others = [Runner((0, TWO, "")) for _ in range(gpu.KEPT_MOST)]
    for other in others:
        gpu.kept(runner=other, clock=clock)
    assert len(gpu._kept) == gpu.KEPT_MOST == 4
    gpu.kept(runner=card, clock=clock)
    assert len(card.asked) == 2  # forgotten, so read again


def test_a_reading_without_a_card_is_kept_too_and_two_threads_make_one():
    asked: list[str] = []

    def which(name):
        asked.append(name)
        return None
    assert gpu.kept(which=which, exists=never, clock=lambda: 9.0).why == gpu.NOT_HERE
    assert gpu.kept(which=which, exists=never, clock=lambda: 12.0).at == 9.0 and asked == ["nvidia-smi"]
    gpu._kept.clear()
    started, go = threading.Event(), threading.Event()
    runs: list[int] = []

    def runner(args, timeout):
        runs.append(1)
        started.set()
        assert go.wait(5.0)
        return 0, RTX_5090, ""
    got: list[Gpus] = []

    def ask():
        got.append(gpu.kept(runner=runner, clock=lambda: 50.0))
    threads = [threading.Thread(target=ask) for _ in range(2)]
    for t in threads:
        t.start()
    assert started.wait(5.0)
    go.set()
    for t in threads:
        t.join(5.0)
    assert len(got) == 2 and got[0] is got[1] and runs == [1]


# -- what fits ---------------------------------------------------------------------------------------------------------
def test_what_fits_is_said_in_four_ways():
    one, name = Gpus((CARD,)), "NVIDIA GeForce RTX 5090 Laptop GPU"
    assert gpu.fit(8 << 30, one) == f"fits: 8.0 GB of the {name}'s 21.3 GB free (23.9 GB in all)"
    assert gpu.fit(21 << 30, one) == f"fits the {name}'s 23.9 GB, not what is free now (21.3 GB)"
    assert gpu.fit(40 << 30, one) == f"larger than the {name}'s 23.9 GB: part of it would run in system memory, slower"
    assert gpu.fit(8 << 30, gpu.read(which=nowhere, exists=never)) == (
        "no NVIDIA GPU is read here (nvidia-smi is not on this system): what fits is not known")
    assert gpu.fit(8 << 30, Gpus()) == "no NVIDIA GPU is read here (nvidia-smi names no GPU): what fits is not known"


def test_a_model_takes_its_size_and_room_beside_it():
    one = Gpus((CARD,))
    free, total = CARD.free, CARD.total
    assert gpu.MARGIN == 1 << 30
    assert gpu.fit(free - gpu.MARGIN, one).startswith("fits: ")
    assert gpu.fit(free - gpu.MARGIN + 1, one).startswith("fits the ")
    assert gpu.fit(free, one, margin=0).startswith("fits: ")
    assert gpu.fit(free + 1, one, margin=0).startswith("fits the ")
    assert gpu.fit(total - gpu.MARGIN, one).startswith("fits the ")
    assert gpu.fit(total - gpu.MARGIN + 1, one).startswith("larger than ")
    assert gpu.fit(total, one, margin=-5).startswith("fits the ")  # a margin below nothing is none
    for unknown in (None, 0, -1, "", "big"):
        assert gpu.fit(unknown, one) == ""  # a size that is not known: nothing is said
    assert gpu.fit("8589934592", one).startswith("fits: 8.0 GB of ")


def test_with_several_cards_the_roomiest_is_the_one_named():
    busy = Gpu(0, "NVIDIA RTX A6000", 49140 << 20, 30000 << 20, 18824 << 20)
    idle = Gpu(1, "NVIDIA RTX 4000", 20470 << 20, 100 << 20, 20000 << 20)
    both = Gpus((busy, idle))
    assert gpu.fit(10 << 30, both) == "fits: 10.0 GB of the NVIDIA RTX 4000's 19.5 GB free (20.0 GB in all)"
    assert gpu.fit(30 << 30, both) == "fits the NVIDIA RTX A6000's 48.0 GB, not what is free now (18.4 GB)"
    assert gpu.fit(60 << 30, both).startswith("larger than the NVIDIA RTX A6000's 48.0 GB")


# -- the page's table --------------------------------------------------------------------------------------------------
def test_the_table_is_a_card_a_row_or_why_none_is_read():
    table = gpu.table(Gpus((CARD,), "", 1.0))
    assert table["title"] == "This machine's GPU"
    assert [c["title"] for c in table["columns"]] == ["GPU", "Memory", "Used", "Free", "Driver"]
    assert [c.get("num", False) for c in table["columns"]] == [False, True, True, True, False]
    assert table["rows"] == [[{"text": "NVIDIA GeForce RTX 5090 Laptop GPU", "sub": "GPU 0"}, "23.9 GB", "2.2 GB",
                              "21.3 GB", "595.71"]]
    assert "nvidia-smi" in table["note"] and "Not all" not in table["note"]
    none = gpu.table(gpu.read(which=nowhere, exists=never))
    assert none["rows"] == [] and none["empty"] == "No NVIDIA GPU is read here: nvidia-smi is not on this system."
    assert gpu.table(Gpus())["empty"] == "No NVIDIA GPU is read here: nvidia-smi names no GPU."
    partly = gpu.table(Gpus((Gpu(0, "A card", 1 << 30, 0, 1 << 30),), "nvidia-smi's answer could not be read: x"))
    assert partly["rows"][0][4] == "–" and partly["note"].endswith(
        "Not all of its answer was read: nvidia-smi's answer could not be read: x.")


def test_the_module_names_no_host():
    with open(gpu.__file__, encoding="utf-8") as f:
        assert re.search(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]", f.read()) is None
