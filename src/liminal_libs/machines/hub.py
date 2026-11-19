"""Hugging Face's cache and its hf command, as the model servers use them (1.66.0; the user, 2026-11-18: "top 4
inference engines, top 4 agentic harnesses (open source)"): vLLM's and LMDeploy's. Lifted from plugin-platform-vllm
0.1.0's models.py, which proved it. Each plugin keeps a models folder of its own (HF_HOME; the cache is its hub/, in
Hugging Face's layout) and names the Hub's address itself: no host is named here.

- A repository's name (`repository`): org/name, each part letters, digits, '.', '_' and '-', never '..' or '--' (the
  Hub's own rule, and what keeps a cache folder's name one way to read).
- The cache (`read`, `find`, `folder_of`, `repo_of`, `scan`, `snapshot`): a folder for each repository,
  models--org--name, holding its blobs, its snapshots (links to the blobs, or copies where this system makes no link)
  and its refs. Each file is counted once, whatever links show it; a download that was stopped leaves .incomplete
  files. Read from the folders themselves: no process is run and nothing is asked.
- A download's progress (`folder_bytes`, `Watch`): the bytes the repository's folder holds, said every EVERY_S by a
  thread of its own while hf runs (hf's progress bars are not lines a panel can show).
- A delete (`delete`): a repository's folder and its lock files, each removed only inside the folder the plugin names
  (download.remove_tree: a link is removed as the link it is).
- What the Hub says of a model (`licence_of`, `gated`, `files_of`, `size_of`, `why`): its card's licence and the page
  its words are on, whether it is gated, its files and its size, from the Hub's API (cardData) or hf's own words
  (card_data); and why the Hub did not say, in words.
- hf, the command (`environment`, `child_env`, `download_argv`, `dry_run_argv`, `dry_run`): its folder the plugin's;
  its telemetry, its update check, the Hub's shared store of files and its progress bars off; the user's token only
  where one is kept (HF_TOKEN, never on its command line), else no token sent at all. A download is
  `hf download REPO --quiet`. Its dry run, `hf download REPO --dry-run --format human`, says what a download would take
  in one line: "[dry-run] Will download N files (out of M) totalling SIZE." SIZE is rounded (one decimal, powers of
  1000), so progress counted against it is approximate. The line is printed only in hf's human and agent formats,
  hence --format human."""
from __future__ import annotations

import os
import re
import stat
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Callable, Iterable

from .. import mounts
from ..instances import Refusal
from . import children, download
from .endpoint import Progress

FOLDER = "hub"  # the cache, under HF_HOME
PREFIX = "models--"  # a repository's folder in it: models--org--name
REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")  # a Hub repository: org/name
REPOS_MOST = 64  # repositories read at most
LOOKS_MOST = 20_000  # entries looked at in one repository's folder at most
EVERY_S = 2.0  # how often a download's progress is said
JOIN_S = 5.0  # what the progress's thread is given to end, once its download has
DRY_RUN_S = 60.0  # what a dry run is given at the most
EXPAND = ("cardData", "gated", "siblings")  # what of a model's information the Hub's API is asked for
# taken out of the platform's environment for hf (every pair of Liminal's besides, and a plugin's own: VLLM_*)
DROP = ("HF_*", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_*", "TRANSFORMERS_*", "PYTHON*", "VIRTUAL_ENV", "CONDA_*")
TOKEN_VARIABLE = "HF_TOKEN"  # the one variable the user's token is handed over in
HTTPS = "https://"  # a licence's own page, where its card names one whole
UNITS = "KMGTPEZY"  # hf's rounded sizes: a unit letter for each power of 1000
DRY_LINE = re.compile(r"Will download (\d+) files? \(out of (\d+)\) total{1,2}ing (.+?)\.?\s*$")
ROUNDED = re.compile(r"(\d+(?:\.\d+)?)([KMGTPEZY]?)")
UNKNOWN = "an unknown size"  # what the dry run says where the Hub gave no size


# -- a repository and its folder ---------------------------------------------------------------------------------------
def repository(text) -> str:
    """A Hub repository's name as typed, checked: `org/name`, each part letters, digits, . _ -, never .. or -- (the
    Hub's own rule). A Refusal in words otherwise."""
    said = " ".join(str(text or "").split())
    if not REPO.fullmatch(said) or ".." in said or "--" in said:
        raise Refusal(f"a model on Hugging Face is named org/name (Qwen/Qwen3-0.6B): letters, digits, '.', '_' and "
                      f"'-', not {said[:80]!r}")
    return said


def folder_of(hub, repo) -> Path:
    """A repository's folder in the cache `hub`: models--org--name (its name checked first: `repository`)."""
    return Path(hub) / (PREFIX + repository(repo).replace("/", "--"))


def repo_of(folder) -> str:
    """A cache folder's repository: models--org--name as org/name (a name without an org as it is)."""
    rest = Path(folder).name[len(PREFIX):]
    return rest.replace("--", "/", 1)


# -- the cache ---------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Entry:
    """A repository downloaded here: its name (org/name, as its folder spells it), its folder, the bytes its files
    hold (each counted once, through its links), how many, the snapshot in use, whether a download of it was stopped
    (.incomplete files), whether all of it was looked at, and what could not be read of it."""

    repo: str
    path: Path
    size: int = 0
    files: int = 0
    snapshot: str = ""
    incomplete: bool = False
    whole: bool = True
    why: str = ""


def scan(folder) -> tuple[int, int, bool, bool]:
    """What a repository's folder holds: (bytes, files, a download stopped, all of it looked at). Each file is
    counted once whatever links show it (a snapshot's links to its blobs, a blob's link into a shared store), by
    what it is; a link that leads nowhere counts nothing, nor do its refs and its .no_exist marks (names, no
    content). LOOKS_MOST entries are looked at, at the most."""
    top = Path(folder)
    total = files = looked = 0
    stopped = False
    seen: set[tuple[int, int]] = set()
    for root, dirs, names in os.walk(top):
        if Path(root) == top:
            dirs[:] = [d for d in dirs if d not in ("refs", ".no_exist")]
        for name in names:
            looked += 1
            if looked > LOOKS_MOST:
                return total, files, stopped, False
            if name.endswith(".incomplete"):
                stopped = True
            try:
                st = os.stat(os.path.join(root, name))
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) in seen:
                continue
            seen.add((st.st_dev, st.st_ino))
            total += st.st_size
            files += 1
    return total, files, stopped, True


def snapshot(folder) -> str:
    """The snapshot a repository's main ref names, else its newest; "" when it has none."""
    top = Path(folder)
    try:
        named = (top / "refs" / "main").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        named = ""
    snapshots = top / "snapshots"
    if named and (snapshots / named).is_dir():
        return named
    try:
        found = [s for s in snapshots.iterdir() if s.is_dir()]
    except OSError:
        return ""
    return max(found, key=lambda s: s.stat().st_mtime).name if found else ""


def read(hub) -> list[Entry]:
    """The repositories downloaded into the cache `hub`, read from its folders now (no process, nothing asked):
    REPOS_MOST at most, by name; none when it is not there."""
    try:
        folders = sorted((f for f in Path(hub).iterdir() if f.name.startswith(PREFIX) and f.is_dir()
                          and not f.is_symlink()), key=lambda f: f.name.lower())
    except OSError:
        return []
    out = []
    for folder in folders[:REPOS_MOST]:
        try:
            size, files, stopped, whole = scan(folder)
            out.append(Entry(repo_of(folder), folder, size, files, snapshot(folder), stopped, whole))
        except OSError as e:
            out.append(Entry(repo_of(folder), folder, why=f"it could not be read: {e}"))
    return out


def find(entries: Iterable[Entry], repo) -> Entry | None:
    """The repository among `entries` by that name (its case as typed or as its folder spells it); None for none."""
    wanted = str(repo or "").strip().lower()
    return next((e for e in entries if e.repo.lower() == wanted), None)


# -- a download's progress ---------------------------------------------------------------------------------------------
def folder_bytes(folder) -> int:
    """The bytes a repository's folder holds now, each file once (`scan`): 0 when it is not there yet."""
    top = Path(folder)
    if not top.is_dir():
        return 0
    return scan(top)[0]


class Watch:
    """A download's progress while it runs: the bytes `folder` holds (folder_bytes) of `size` (None: not known), said
    as `what` to `log` (endpoint.Progress: "what: 12.3 MB of 1.4 GB (0%)") every `every` seconds by a thread of its
    own, from the start of its `with` to its end. Its thread is then stopped and given JOIN_S to end. `tick()` says
    it once; `end(words)` is the last word on it."""

    def __init__(self, folder, size, what: str, log, *, every: float = EVERY_S,
                 clock: Callable[[], float] = time.monotonic):
        self.folder, self.size, self.what = Path(folder), size, what
        self.every = float(every)
        self.progress = Progress(log, every=self.every, clock=clock)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def tick(self) -> None:
        """How far it is, said now (unless it was said less than `every` seconds ago): a folder that cannot be read
        says nothing."""
        try:
            self.progress.say(folder_bytes(self.folder), self.size, self.what)
        except OSError:
            pass

    def _watch(self) -> None:
        while not self._stop.wait(self.every):
            self.tick()

    def __enter__(self) -> "Watch":
        self._stop.clear()
        self._thread = threading.Thread(target=self._watch, daemon=True, name="hub-download-progress")
        self._thread.start()
        return self

    def __exit__(self, *exc) -> bool:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(JOIN_S)
        return False

    def end(self, words: str) -> None:
        """The last word on the download, said whenever it comes."""
        self.progress.end(words)


# -- a delete ----------------------------------------------------------------------------------------------------------
def delete(folder, inside) -> tuple[int, list[str]]:
    """A repository's files deleted from its cache: its folder (models--org--name, an Entry's path), links as links,
    then its lock files (the cache's .locks/models--org--name), each removed only inside `inside`, the plugin's own
    models folder (download.remove_tree). Its answer: (the bytes freed, its lines: lock files that could not be
    removed, and a store of files shared between repositories, which is left). What the folder's removal raises is
    raised, in its words (OSError, ValueError, mounts.NotHere); ValueError for a folder that is no repository's."""
    top = Path(folder)
    if not top.name.startswith(PREFIX) or len(top.name) <= len(PREFIX):
        raise ValueError(f"{top} is no repository's folder of Hugging Face's cache (models--org--name): not deleted")
    cache = top.parent
    freed = download.remove_tree(top, inside)
    lines: list[str] = []
    locks = cache / ".locks" / top.name
    if os.path.lexists(locks):
        try:
            download.remove_tree(locks, inside)
        except (OSError, ValueError, mounts.NotHere) as e:
            lines.append(f"its lock files could not be removed ({e})")
    if (cache / "blobs").is_dir():
        lines.append(f"{cache / 'blobs'} is a store of files shared between repositories (made by another program's "
                     "hf): what of it no repository uses is left, for `hf cache prune`")
    return freed, lines


# -- what the Hub says of a model --------------------------------------------------------------------------------------
def card_of(info) -> Mapping:
    """A model's card data: the Hub's API's cardData, else hf's own card_data; {} for none."""
    if not isinstance(info, Mapping):
        return {}
    for key in ("cardData", "card_data"):
        card = info.get(key)
        if isinstance(card, Mapping):
            return card
    return {}


def licence_of(info, page: str) -> tuple[str, str]:
    """A model's licence in words and the page its words are on, from its card's data (`license`, or `other` with
    `license_name` and `license_link`), else its licence tag; ("", `page`) when it names none. `page`: the model's
    own page at the Hub (the plugin's address and the repository): a link its card gives inside the repository is
    read there."""
    card = card_of(info)
    named = card.get("license")
    if isinstance(named, list):
        named = ", ".join(str(n) for n in named if isinstance(n, str))
    named = str(named or "").strip()
    other = str(card.get("license_name") or "").strip()
    link = str(card.get("license_link") or "").strip()
    if not named and isinstance(info, Mapping):
        tags = info.get("tags") if isinstance(info.get("tags"), list) else []
        named = next((t.split(":", 1)[1] for t in tags if isinstance(t, str) and t.startswith("license:")), "")
    words = (other or "other, named in its card") if named == "other" else named
    if link.startswith(HTTPS):
        where = link
    elif link and not link.startswith(("http:", "/")) and ".." not in link:
        where = f"{page}/blob/main/{link}"
    else:
        where = page
    return words[:200], where


def gated(value) -> bool:
    """Whether the Hub says a model is gated (its `gated`: true, "auto" or "manual")."""
    return value is True or str(value or "").strip().lower() in ("auto", "manual", "true")


def files_of(info) -> int:
    """How many files a model's information lists (its siblings, each by its rfilename)."""
    siblings = info.get("siblings") if isinstance(info, Mapping) else None
    if not isinstance(siblings, list):
        return 0
    return sum(1 for s in siblings if isinstance(s, Mapping) and s.get("rfilename"))


def size_of(answer) -> int | None:
    """A model's size in bytes as the Hub's treesize answer says it ({"path", "size"}); None when it does not."""
    said = answer.get("size") if isinstance(answer, Mapping) else None
    return said if isinstance(said, int) and not isinstance(said, bool) and said > 0 else None


def why(e, token: str, where: str) -> str:
    """Why the Hub did not say what a model is, in words: `e` the ask's EndpointError (by its status), `token` the
    one kept here ("" for none), `where` the Hub's host as the plugin names it."""
    status = getattr(e, "status", 0)
    if status in (401, 403):
        return (f"it is private or gated: {where} shows it only to an account given access, with its token"
                + (", and the token kept here is refused" if token else " (none is kept here: Settings)"))
    if status == 404:
        return f"{where} knows no model by that name"
    if status == 429:
        return f"{where} asks for fewer requests now (429): try again in a few minutes"
    return " ".join(str(e).split())[:300]


# -- hf, the command ---------------------------------------------------------------------------------------------------
def environment(models, token: str = "") -> dict[str, str]:
    """hf's own variables (each said beside it), laid over an environment without the Hub's own (`child_env` makes
    the whole of it)."""
    env = {"HF_HOME": os.path.abspath(os.fspath(models)),  # the plugin's models folder: the cache is its hub/
           "HF_HUB_DISABLE_TELEMETRY": "1",
           "HF_HUB_DISABLE_UPDATE_CHECK": "1",  # no ask of PyPI for a newer hf
           "HF_HUB_DISABLE_SHARED_BLOBS": "1",  # each model's files in its own folder, so a delete frees them
           "HF_HUB_DISABLE_PROGRESS_BARS": "1",  # its progress is the folder's bytes (Watch)
           "DO_NOT_TRACK": "1", "NO_COLOR": "1", "PYTHONUNBUFFERED": "1"}  # lines for a panel, as they come
    if token:
        env[TOKEN_VARIABLE] = token  # the user's, kept through the login: never on a command line
    else:
        env["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"  # no token is sent at all: not one hf kept by itself
    return env


def child_env(models, token: str = "", *, base: Mapping[str, str] | None = None, drop: str | Iterable[str] = (),
              system: str | None = None) -> dict[str, str]:
    """hf's whole environment: `base` (this process's own unless given: a plugin's Outside env) without the Hub's,
    Transformers' and Python's own variables (DROP), every LIMINAL_* name and what `drop` names (an AI plugin hands
    its dropped() and its tool's own: VLLM_*), each a name or a prefix ending "*"; then `environment(models, token)`
    laid over it. The plugin's runner names TOKEN_VARIABLE's value secret, so it reaches no panel."""
    named = (drop,) if isinstance(drop, str) else tuple(drop or ())
    launch = children.Launch((), env=environment(models, token),
                             drop=(*(str(n) for n in named if str(n).strip()), *DROP, "LIMINAL_*"))
    return children.environment(launch, base=base, system=system)


def _program(hf) -> str:
    text = os.fspath(hf) if hf else ""
    if not text or not os.path.dirname(text):
        raise ValueError("hf is named by its whole path, its environment's own: a bare name would be whichever one is "
                         "on PATH")
    return os.path.abspath(text)


def download_argv(hf, repo) -> list[str]:
    """A model's files downloaded into HF_HOME's cache, the path of its snapshot the one line printed:
    `hf download REPO --quiet`."""
    return [_program(hf), "download", repository(repo), "--quiet"]


def dry_run_argv(hf, repo) -> list[str]:
    """What a download of a model would take, in one line (`dry_run` reads it), with nothing downloaded:
    `hf download REPO --dry-run --format human`."""
    return [_program(hf), "download", repository(repo), "--dry-run", "--format", "human"]


@dataclass(frozen=True)
class DryRun:
    """What hf's dry run said a download would take: the `files` it would download, of `total` in the repository,
    and their `size` in bytes as hf rounds it (None: not said), as hf wrote it (`said`: 5.6G)."""

    files: int
    total: int
    size: int | None
    said: str


def rounded(text) -> int | None:
    """A size as hf rounds it (5.6G, 655.2M, 999.0: one decimal, powers of 1000), in bytes; None for anything else,
    such as "an unknown size"."""
    found = ROUNDED.fullmatch(str(text or "").strip())
    if found is None:
        return None
    power = UNITS.index(found.group(2)) + 1 if found.group(2) else 0
    return int(Decimal(found.group(1)) * 1000 ** power)  # (exactly what it says: no float's drift)


def dry_run(lines) -> DryRun | None:
    """What hf's dry run said, from what it printed (a text, or its lines one by one): None when none of them is its
    line ("[dry-run] Will download N files (out of M) totalling SIZE.")."""
    texts = lines.splitlines() if isinstance(lines, str) else [str(x) for x in (lines or ())]
    for text in texts:
        found = DRY_LINE.search(text.strip())
        if found is not None:
            said = found.group(3).strip()
            return DryRun(int(found.group(1)), int(found.group(2)), None if said == UNKNOWN else rounded(said), said)
    return None
