"""This machine's NVIDIA cards, read through nvidia-smi (1.62.0), for a model server's page: "The page says what
fits this machine's GPU (read through nvidia-smi where it exists; said where it does not)" (the decisions of
2026-11-16 for the user's "3 plugins for inference serving local models on the platform").

One short command, windowless, asked for the cards' index, name, memory (total, used, free) and driver as lines of
comma-separated values; nothing is written, nothing is asked of a driver directly, and no other maker's card is
read. `read` never raises for anything the command does: a system without nvidia-smi, a command that fails or says
something else, a card whose memory it does not say are each a `Gpus` with no card and `why` in words, which the
page shows. `kept` hands back the last reading while it is fresh, so a tab asked every few seconds runs the command
once in a while. `fit` says in words whether a model of a size fits a card, and `table` is the reading as the page
draws it.

It is read for a Models tab and inside a job, never for a status: a status runs nothing. Under WSL the command is
Windows' driver's own, at WSL_PATH when it is not on PATH. The command runs with the environment it is given whole
(an AI plugin's child_env()), else this process's own without any LIMINAL_* name (terminal.inherited: a net only, so
a plugin hands its own, as the AI base does).

A runner stands in for the command in tests. A stand-in is never looked for on this machine: with a runner, where
the command is comes only from the stand-ins given beside it (`which`, `exists`), and with none it is asked by its
bare name, so a test answers the same on a machine with nvidia-smi and on one without. The real lookups go with the
real command alone: beside a runner a caller hands stand-ins or nothing (ModelServer hands None for its Outside's own
`which`), since the real ones would read this machine's PATH (a review found a test that did: it passed here and
failed in CI)."""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping

from ..proc import no_window
from .terminal import inherited

NAME = "nvidia-smi"
WSL_PATH = "/usr/lib/wsl/lib/nvidia-smi"  # where WSL keeps Windows' driver's own: not always on PATH there
QUERY = ("index", "name", "memory.total", "memory.used", "memory.free", "driver_version")
FORMAT = "csv,noheader,nounits"  # a card a line, no heading, the memory as numbers of MiB
MIB = 1 << 20
TIMEOUT_S = 10.0
KEPT_S = 30.0  # a reading is kept this long (`kept`)
KEPT_MOST = 4  # readings kept at once, each for the outside things it was read with
MARGIN = 1 << 30  # what a model takes beside its own size: its context and the server's own
LINE = 200  # characters of the command's own words kept in a `why`
NOT_HERE = "nvidia-smi is not on this system"
NONE_NAMED = "nvidia-smi names no GPU"
NOT_SAID = ("", "n/a")  # how it writes a figure it does not have, besides a word in brackets ([N/A], [Not Supported])


@dataclass(frozen=True)
class Gpu:
    """One NVIDIA card as nvidia-smi says it, its memory in bytes."""

    index: int
    name: str
    total: int
    used: int
    free: int
    driver: str = ""  # the driver's version, as written: 595.71


@dataclass(frozen=True)
class Gpus:
    """One reading: the cards; `why`, in words, when there is none (and what of the answer could not be read when
    there are some); `at`, the clock's seconds when it was read."""

    cards: tuple[Gpu, ...] = ()
    why: str = ""
    at: float = 0.0


def command(which: Callable | None = None, exists: Callable | None = None) -> str:
    """Where nvidia-smi is: on PATH, else WSL's own place for it, else "" (`which`, `exists`: shutil.which and
    os.path.exists, looked up when it is asked, unless a test stands in for them)."""
    which = shutil.which if which is None else which
    exists = os.path.exists if exists is None else exists
    found = which(NAME)
    if found:
        return str(found)
    return WSL_PATH if exists(WSL_PATH) else ""


def arguments(program: str = NAME) -> list[str]:
    """The one command a reading runs."""
    return [program, "--query-gpu=" + ",".join(QUERY), "--format=" + FORMAT]


environment = inherited  # the command's whole environment: `env` as given, else this process's without LIMINAL_*


def _run(args: list[str], timeout: float, env: Mapping[str, str] | None = None) -> tuple[int, bytes, bytes]:
    """The command run to its end, windowless, nothing typed into it: its exit code and what it wrote."""
    done = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env=environment(env), **no_window())
    return done.returncode, done.stdout, done.stderr


def _text(raw) -> str:
    return raw if isinstance(raw, str) else (raw or b"").decode("utf-8", "replace")


def _first(*texts: str) -> str:
    """The first line with words in it, cut at LINE."""
    for text in texts:
        for line in text.splitlines():
            if line.strip():
                return line.strip()[:LINE]
    return ""


def _not_said(word: str) -> bool:
    """Whether nvidia-smi wrote that it does not have a figure: N/A, or a word in brackets ([Not Supported],
    [Insufficient Permissions], [Unknown Error])."""
    word = word.strip()
    return word.lower() in NOT_SAID or (word.startswith("[") and word.endswith("]"))


def _mib(value: str) -> int | None:
    """A figure of MiB in bytes; None when nvidia-smi does not say it ([N/A]) or wrote something else."""
    word = value.strip()
    if word.lower().endswith("mib"):
        word = word[:-3].strip()
    if _not_said(word) or not word.isdecimal():
        return None
    return int(word) * MIB


def parse(text: str) -> tuple[tuple[Gpu, ...], list[str]]:
    """The cards an answer names, and what of it could not be read, each in words. A line is `index, name, total,
    used, free, driver`; a name may hold a comma. A card with its total and one of the two others is whole (the
    third is their difference); one whose memory is not said is not read."""
    cards: list[Gpu] = []
    unread: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < len(QUERY) or not parts[0].isdecimal():
            unread.append(f"nvidia-smi's answer could not be read: {line.strip()[:LINE]}")
            continue
        name = ", ".join(parts[1:-4])
        total, used, free = (_mib(p) for p in parts[-4:-1])
        if total is not None and used is None and free is not None:
            used = max(total - free, 0)
        elif total is not None and free is None and used is not None:
            free = max(total - used, 0)
        if total is None or used is None or free is None:
            unread.append(f"nvidia-smi does not say the {name or 'card'}'s memory ({', '.join(parts[-4:-1])})")
            continue
        driver = "" if _not_said(parts[-1]) else parts[-1]
        cards.append(Gpu(int(parts[0]), name, total, used, free, driver))
    return tuple(cards), unread


def _nowhere(name: str) -> None:
    return None


def _never(path: str) -> bool:
    return False


def read(runner: Callable | None = None, timeout: float = TIMEOUT_S, clock: Callable[[], float] | None = time.time, *,
         which: Callable | None = None, exists: Callable | None = None, env: Mapping[str, str] | None = None) -> Gpus:
    """The cards now. It never raises for anything the command does: without the command, when it fails, takes more
    than `timeout` seconds or says something else, the answer has no card and says why.

    Without a runner the command is looked for (`command(which, exists)`) and run windowless with `env` (see
    `environment`). `runner(args, timeout) -> (code, out, err)` stands in for the command: it is asked by the bare
    name, unless stand-ins for `which` or `exists` are given beside it, which then say where it is (one not given is
    taken to find nothing: the module's words)."""
    at = (clock or time.time)()
    if runner is None:
        program = command(which, exists)
    else:
        program = NAME if which is None and exists is None else command(which or _nowhere, exists or _never)
    if not program:
        return Gpus(why=NOT_HERE, at=at)
    try:
        if runner is None:
            code, out, err = _run(arguments(program), timeout, env)
        else:
            code, out, err = runner(arguments(program), timeout)
    except subprocess.TimeoutExpired:
        return Gpus(why=f"nvidia-smi gave no answer in {timeout:g} s", at=at)
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return Gpus(why=f"nvidia-smi could not be run: {e}"[:LINE], at=at)
    out, err = _text(out), _text(err)
    if code != 0:
        said = _first(err, out)
        return Gpus(why=f"nvidia-smi ended with {code}" + (f": {said}" if said else ""), at=at)
    cards, unread = parse(out)
    if not cards:
        return Gpus(why=unread[0] if unread else NONE_NAMED, at=at)
    return Gpus(cards, "; ".join(unread), at)


_lock = threading.Lock()
_kept: list[tuple[tuple, Gpus]] = []  # the last readings, the newest first, each with what it was read through


def _key(outside: dict) -> tuple:
    """What a reading was read through, compared by identity: its runner and its lookups (none of them given for the
    real ones: every plugin's page shares the one reading of this machine)."""
    return outside.get("runner"), outside.get("which"), outside.get("exists")


def _same(a: tuple, b: tuple) -> bool:
    return all(x is y for x, y in zip(a, b))


def kept(max_age: float = KEPT_S, **outside) -> Gpus:
    """The last reading made through the same outside things while it is younger than `max_age` seconds, else a new
    one, kept (one that has no card too: a system without nvidia-smi is not asked at every draw). `outside`: `read`'s
    arguments (a plugin's Outside, a test's runner and clock). Readings are kept by what they were read through, so a
    test's stand-in never answers for another's, and KEPT_MOST at most. Two threads asking at once make one
    reading."""
    clock = outside.get("clock") or time.time
    key = _key(outside)
    with _lock:
        for i, (was, reading) in enumerate(_kept):
            if _same(was, key):
                if 0 <= clock() - reading.at < max_age:
                    return reading
                del _kept[i]
                break
        reading = read(**outside)
        _kept.insert(0, (key, reading))
        del _kept[KEPT_MOST:]
        return reading


def _size(n: int) -> str:
    from .world import size_words  # bytes as the pages say them: 1024 to a KB (loaded when words are wanted)

    return size_words(n)


def fit(size, gpus: Gpus, margin: int = MARGIN) -> str:
    """Whether a model of `size` bytes fits, in words for a model's row. It takes its size and `margin` more (its
    context and the server's own), and that sum is what is held against a card: the one with the most free memory,
    then the largest (a model spread over several cards is not reckoned). "" for a size that is not known."""
    try:
        own = int(size)
    except (TypeError, ValueError):
        return ""
    if own <= 0:
        return ""
    if not gpus.cards:
        return f"no NVIDIA GPU is read here ({gpus.why or NONE_NAMED}): what fits is not known"
    need = own + max(int(margin), 0)
    roomiest = max(gpus.cards, key=lambda g: (g.free, g.total))
    if need <= roomiest.free:
        return (f"fits: {_size(own)} of the {roomiest.name}'s {_size(roomiest.free)} free "
                f"({_size(roomiest.total)} in all)")
    largest = max(gpus.cards, key=lambda g: (g.total, g.free))
    if need <= largest.total:
        return f"fits the {largest.name}'s {_size(largest.total)}, not what is free now ({_size(largest.free)})"
    return f"larger than the {largest.name}'s {_size(largest.total)}: part of it would run in system memory, slower"


def table(gpus: Gpus) -> dict:
    """The reading as a table for a model server's Models tab: a card a row, or why none is read."""
    rows = [[{"text": g.name, "sub": f"GPU {g.index}"}, _size(g.total), _size(g.used), _size(g.free), g.driver or "–"]
            for g in gpus.cards]
    note = "NVIDIA's cards as nvidia-smi says them, read while this tab is shown; no other maker's card is read."
    if gpus.cards and gpus.why:
        note += f" Not all of its answer was read: {gpus.why}."
    return {"title": "This machine's GPU", "note": note, "rows": rows,
            "columns": [{"title": "GPU"}, {"title": "Memory", "num": True}, {"title": "Used", "num": True},
                        {"title": "Free", "num": True}, {"title": "Driver"}],
            "empty": f"No NVIDIA GPU is read here: {gpus.why or NONE_NAMED}."}
