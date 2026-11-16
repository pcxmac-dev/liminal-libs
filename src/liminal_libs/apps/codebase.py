"""An app's code base: the repositories it is made of, the code in them, and how much of it is which language.

The user, 2026-11-16: "i want to add another functional class called codebase, which has the associated repositories
(git/svn/,,,) if there are, also the code base, and stats like how much is rust %, javascript %, etc..."; "this class
will be added to all the 'apps' just like connections"; "it will also say how far it is behind the remote".

Every app of the frame holds one (`App.codebase`, as it holds its `Traffic`) and answers it at `GET /api/codebase`:

- **The repositories**: every working copy in the workspace (git, Subversion, Mercurial; `layout.home()`), and the
  folders this app's own code runs from when they are in none ("if there are"). Each says its branch, the commit
  checked out, its remote (never a name or a token in its address), what is changed and not committed, and how far it
  is ahead of and behind the branch it follows there, as of when that remote was last asked.
- **The code**: the files of each (the tracked ones of a git repository), their lines and bytes by language.
  Vendored and generated files (vendor/, node_modules/, target/, a *.min.js, a lock file), binary files and very
  large ones are not this code base's own writing: counted apart, not in any language.
- **The shares**: of the bytes of code and markup, as a repository's language bar is counted elsewhere: prose
  (Markdown) and data (JSON, TOML, YAML) are counted and shown, and are no part of the percentages.

Read when first asked, in a thread of its own (a few processes per repository, every file read once), kept KEEP_S and
read again when asked `fresh`. Nothing here reaches a remote by itself: how far behind is what the working copy knew
when it last asked. `fetch()` asks the remotes (git fetch: its remote-tracking branches move, nothing checked out
does), and is run only when the user asks for it on the page.

Every command goes through one `runner` (windowless, with a time limit; a test's stand-in), and git is told to take
no lock and ask nothing at a terminal.
"""
from __future__ import annotations

import inspect
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from .. import layout
from ..proc import no_window

KEEP_S = 600.0  # a reading kept this long before it is made again (a page that stays open asks every few seconds)
WORKERS = 6  # repositories read at once (each waits on its own commands)
COMMAND_S = 20.0  # a command's time limit; asking a remote: FETCH_S
FETCH_S = 90.0
DEPTH = 3  # how far below the workspace a working copy is looked for (plugins/<name> is two down)
LARGE = 2_000_000  # a file past this many bytes was not written by hand: counted apart
SNIFF = 8192  # a zero byte in a file's first bytes: binary

VCS = (("git", ".git"), ("svn", ".svn"), ("hg", ".hg"))  # a working copy's mark, by kind
TOOLS = {"git": "git", "svn": "Subversion (svn)", "hg": "Mercurial (hg)"}

# Folders that hold no writing of this code base's own, wherever they are
SKIP_DIRS = frozenset({".git", ".svn", ".hg", ".venv", "venv", "env", "node_modules", "vendor", "third_party", "dist", "build",
                       "target", "__pycache__", "site-packages", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".idea",
                       ".vscode", ".eggs", "data"})
SKIP_NAMES = frozenset({"cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "pipfile.lock"})
SKIP_ENDS = (".min.js", ".min.css", ".map", ".egg-info")

CODE, MARKUP, PROSE, DATA = "code", "markup", "prose", "data"
COUNTED = (CODE, MARKUP)  # what the shares are of
LANGUAGES: dict[str, tuple[str, str]] = {}  # a file name's ending -> (language, kind)
for _name, _kind, _ends in (
        ("Python", CODE, "py pyi pyw"), ("Rust", CODE, "rs"), ("JavaScript", CODE, "js mjs cjs jsx"), ("TypeScript", CODE, "ts tsx"),
        ("HTML", MARKUP, "html htm"), ("CSS", MARKUP, "css scss less"), ("Shell", CODE, "sh bash zsh"),
        ("PowerShell", CODE, "ps1 psm1 psd1"), ("Batch", CODE, "bat cmd"), ("C", CODE, "c h"), ("C++", CODE, "cpp cc cxx hpp hh"),
        ("C#", CODE, "cs"), ("Go", CODE, "go"), ("Java", CODE, "java"), ("Kotlin", CODE, "kt kts"), ("Swift", CODE, "swift"),
        ("Ruby", CODE, "rb"), ("PHP", CODE, "php"), ("Lua", CODE, "lua"), ("R", CODE, "r"), ("SQL", CODE, "sql"),
        ("Markdown", PROSE, "md markdown"), ("Text", PROSE, "txt rst"), ("JSON", DATA, "json"), ("TOML", DATA, "toml"),
        ("YAML", DATA, "yaml yml"), ("INI", DATA, "ini cfg conf"), ("CSV", DATA, "csv tsv"), ("XML", DATA, "xml"),
        ("SVG", DATA, "svg")):
    for _end in _ends.split():
        LANGUAGES["." + _end] = (_name, _kind)
BY_NAME = {"dockerfile": ("Dockerfile", CODE), "makefile": ("Makefile", CODE)}
KIND_OF = {name: kind for name, kind in [*LANGUAGES.values(), *BY_NAME.values()]}

Runner = Callable[[list, str, float], tuple]


def run(args: list, cwd: str, timeout: float) -> tuple[int, bytes, bytes]:
    """One command in a folder: (its exit code, its output, its errors); 127 when there is no such program, 124 when it
    took too long. No window, nothing to read at a terminal; git takes no lock (its status would write the index) and
    asks for no password (a remote that wants one is said, not waited on)."""
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never",
           "GIT_SSH_COMMAND": os.environ.get("GIT_SSH_COMMAND") or "ssh -oBatchMode=yes", "LC_ALL": "C"}
    try:
        done = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL, env=env, **no_window())
    except FileNotFoundError:
        return 127, b"", f"{args[0]} is not installed here".encode()
    except subprocess.TimeoutExpired:
        return 124, b"", f"{args[0]} took more than {timeout:g} s".encode()
    except OSError as e:
        return 126, b"", str(e).encode()
    return done.returncode, done.stdout or b"", done.stderr or b""


def plain_address(text: str) -> str:
    """A remote's address without the name or the token someone put in it (`name:token@` before the host, in an
    address that begins with a scheme): what is shown of a remote is where it is, never what opens it. Any text is
    taken: a tool's own words repeat the address it could not reach, as it was given."""
    return re.sub(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s'\"]+@", r"\1", (text or "").strip())


def kind_of(folder: Path) -> str:
    """Which kind of working copy a folder is the top of: git, svn or hg; "" when it is none."""
    for kind, mark in VCS:
        if (folder / mark).exists():
            return kind
    return ""


def top_of(path: Path) -> tuple[Path, str] | None:
    """The working copy a path is in: (its top folder, its kind), looked for upward; None when it is in none."""
    path = Path(path)
    for folder in (path, *path.parents):
        kind = kind_of(folder)
        if kind:
            return folder, kind
    return None


def language_of(name: str) -> tuple[str, str] | None:
    """A file's language and its kind (code, markup, prose, data) by its name; None for one this does not count."""
    low = name.lower()
    if low in BY_NAME:
        return BY_NAME[low]
    return LANGUAGES.get(os.path.splitext(low)[1])


def not_its_own(rel: str) -> bool:
    """Whether a file (its path inside the working copy, with /) is vendored or generated: not this code base's own."""
    parts = rel.lower().split("/")
    return (any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts[:-1]) or parts[-1] in SKIP_NAMES
            or parts[-1].endswith(SKIP_ENDS))


class Counts:
    """Files, lines and bytes by language, and what was left out of them."""

    def __init__(self):
        self.languages: dict[str, list[int]] = {}  # name -> [files, lines, bytes]
        self.left_out = {"vendored": 0, "binary": 0, "large": 0, "other": 0, "unread": 0}

    def file(self, root: Path, rel: str) -> None:
        """One file counted: by its name its language; its lines by reading it once."""
        if not_its_own(rel):
            self.left_out["vendored"] += 1
            return
        found = language_of(rel.rsplit("/", 1)[-1])
        if found is None:
            self.left_out["other"] += 1
            return
        try:
            data = (root / rel).read_bytes() if (root / rel).stat().st_size <= LARGE else None
        except OSError:
            self.left_out["unread"] += 1
            return
        if data is None:
            self.left_out["large"] += 1
            return
        if b"\0" in data[:SNIFF]:
            self.left_out["binary"] += 1
            return
        got = self.languages.setdefault(found[0], [0, 0, 0])
        got[0] += 1
        got[1] += data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
        got[2] += len(data)

    def add(self, other: "Counts") -> None:
        for name, (files, lines, size) in other.languages.items():
            got = self.languages.setdefault(name, [0, 0, 0])
            got[0] += files
            got[1] += lines
            got[2] += size
        for what, n in other.left_out.items():
            self.left_out[what] += n

    def rows(self) -> list[dict]:
        """Each language with its share of the code and markup (their bytes, in percent, one decimal; prose and data
        have none), the largest first."""
        counted = sum(size for name, (_, _, size) in self.languages.items() if KIND_OF.get(name) in COUNTED)
        rows = []
        for name, (files, lines, size) in self.languages.items():
            kind = KIND_OF.get(name, CODE)
            share = round(100.0 * size / counted, 1) if counted and kind in COUNTED else None
            rows.append({"name": name, "kind": kind, "files": files, "lines": lines, "bytes": size, "share": share})
        return sorted(rows, key=lambda r: (r["kind"] not in COUNTED, -r["bytes"], r["name"]))

    def totals(self) -> dict:
        return {"files": sum(v[0] for v in self.languages.values()), "lines": sum(v[1] for v in self.languages.values()),
                "bytes": sum(v[2] for v in self.languages.values())}


def _words(raw: bytes) -> str:
    return (raw or b"").decode("utf-8", "replace").strip()


def _last_asked(top: Path) -> float | None:
    """When a git working copy last asked its remote: its FETCH_HEAD's time (a worktree's or a submodule's is where
    its .git file points, or in the repository it shares). None when it never did."""
    mark = top / ".git"
    folders = [mark]
    try:
        if mark.is_file():
            named = mark.read_text(encoding="utf-8", errors="replace").strip()
            if named.startswith("gitdir:"):
                own = (top / named[7:].strip()).resolve()
                folders = [own]
                shared = own / "commondir"
                if shared.is_file():
                    folders.append((own / shared.read_text(encoding="utf-8", errors="replace").strip()).resolve())
        times = [f.stat().st_mtime for f in (d / "FETCH_HEAD" for d in folders) if f.is_file()]
    except OSError:
        return None
    return max(times) if times else None


class Codebase:
    """The code base of one app. `app`: the app (its own code, its plugins' and the login's it holds name what "this
    app" runs from); None for a code base on its own. `roots`: the folders looked in for working copies, the
    workspace by default. `runner`, `clock`, `own_parts`: a test's stand-ins."""

    def __init__(self, app=None, roots=None, runner: Runner | None = None, clock: Callable[[], float] = time.time,
                 own_parts: Callable[[], list[tuple[str, Path]]] | None = None):
        self.app = app
        self._roots = [Path(r) for r in roots] if roots is not None else None
        self.runner = runner or run
        self.clock = clock
        self._own_parts = own_parts
        self._lock = threading.Lock()
        self._kept: dict | None = None  # the last reading
        self._reading: threading.Thread | None = None
        self._progress = {"done": 0, "total": 0}
        self._fetching: dict | None = None  # {"done", "total", "errors"} while the remotes are asked, and after

    # -- what it covers -------------------------------------------------------------------------------------------------
    def roots(self) -> list[Path]:
        """Where working copies are looked for: the workspace (layout.home()), when there is one."""
        if self._roots is not None:
            return list(self._roots)
        home = layout.home()
        return [home] if home is not None else []

    def parts(self) -> list[tuple[str, Path]]:
        """What this app runs from: (what it is, the folder of its code) for the app itself, the library, each plugin
        attached and the login it holds. A part whose code cannot be found is left out."""
        if self._own_parts is not None:
            return list(self._own_parts())
        out: list[tuple[str, Path]] = []

        def part(what: str, obj) -> None:
            try:
                module = sys.modules.get(obj.__module__ if inspect.isclass(obj) else type(obj).__module__)
                file = getattr(module, "__file__", None)
                if file:
                    out.append((what, Path(file).resolve().parent))
            except Exception:  # noqa: BLE001 - a part that cannot say where it is
                pass

        app = self.app
        if app is not None:
            part(f"the {getattr(app, 'NAME', '') or 'app'} app", app)
        out.append(("the library", Path(__file__).resolve().parents[1]))
        if app is not None:
            for name, plugin in sorted(dict(getattr(app, "_plugins", {}) or {}).items()):
                part(f"plugin {name}", plugin)
            held = getattr(app, "_login_object", None)
            if held is not None:
                part("the login it holds", held)
        return out

    def find(self) -> list[tuple[Path, str, list[str]]]:
        """Every working copy under the roots, and the folders of this app's own parts that are in none: (its top
        folder, its kind or "", what of this app runs from it), by name."""
        found: dict[Path, str] = {}
        for root in self.roots():
            stack = [(Path(root), 0)]
            while stack:
                folder, depth = stack.pop()
                kind = kind_of(folder)
                if kind:
                    found[folder.resolve()] = kind
                    continue
                if depth >= DEPTH:
                    continue
                try:
                    below = [d for d in folder.iterdir() if d.is_dir() and d.name.lower() not in SKIP_DIRS and not d.name.startswith(".")]
                except OSError:
                    continue
                stack.extend((d, depth + 1) for d in below)
        used: dict[Path, list[str]] = {}
        for what, folder in self.parts():
            top = top_of(folder)
            where = top[0].resolve() if top else Path(folder).resolve()
            if top:
                found.setdefault(where, top[1])
            else:
                found.setdefault(where, "")
            if what not in used.setdefault(where, []):
                used[where].append(what)
        return sorted(((top, kind, used.get(top, [])) for top, kind in found.items()), key=lambda r: (r[0].name.lower(), str(r[0])))

    # -- one working copy ------------------------------------------------------------------------------------------------
    def _git(self, top: Path) -> tuple[dict, list[str] | None]:
        """A git working copy as it stands (no remote is asked), and its tracked files."""
        info: dict = {}
        code, out, err = self.runner(["git", "status", "--porcelain=v2", "--branch"], str(top), COMMAND_S)
        if code:
            info["problem"] = "git is not installed here: this working copy is not read" if code == 127 else \
                f"git could not read it: {plain_address(_words(err).splitlines()[-1]) if _words(err) else code}"
            return info, None
        changed = untracked = 0
        for line in _words(out).splitlines():
            if line.startswith("# branch.head "):
                info["branch"] = "" if line[14:] == "(detached)" else line[14:]
            elif line.startswith("# branch.upstream "):
                info["upstream"] = line[18:]
            elif line.startswith("# branch.ab "):
                ahead, behind = line[12:].split()
                info["ahead"], info["behind"] = int(ahead.lstrip("+")), int(behind.lstrip("-"))
            elif line[:2] in ("1 ", "2 ", "u "):
                changed += 1
            elif line.startswith("? "):
                untracked += 1
        info["changed"], info["untracked"] = changed, untracked
        code, out, _ = self.runner(["git", "log", "-1", "--format=%h%x1f%cI%x1f%s"], str(top), COMMAND_S)
        if not code and _words(out):
            info["commit"], info["when"], info["subject"] = (_words(out).split("\x1f") + ["", ""])[:3]
        remote = (info.get("upstream") or "origin/").split("/", 1)[0]
        code, out, _ = self.runner(["git", "config", "--get", f"remote.{remote}.url"], str(top), COMMAND_S)
        if not code and _words(out):
            info["remote"], info["remoteName"] = plain_address(_words(out)), remote
            info["asked"] = _last_asked(top)
        code, out, _ = self.runner(["git", "ls-files", "-z"], str(top), COMMAND_S)
        files = None if code else [f for f in out.decode("utf-8", "replace").split("\0") if f]
        return info, files

    def _svn(self, top: Path) -> dict:
        """A Subversion working copy as it stands (its server is not asked: how far behind is not known here)."""
        code, out, _ = self.runner(["svn", "info"], str(top), COMMAND_S)
        if code:
            return {"problem": "Subversion (svn) is not installed here: this working copy is not read" if code == 127
                    else "svn could not read it"}
        said = dict(line.split(": ", 1) for line in _words(out).splitlines() if ": " in line)
        info = {"remote": plain_address(said.get("URL", "")), "commit": "r" + said["Revision"] if said.get("Revision") else "",
                "when": said.get("Last Changed Date", "")[:25], "branch": said.get("Relative URL", "").lstrip("^/")}
        code, out, _ = self.runner(["svn", "status", "-q"], str(top), COMMAND_S)
        info["changed"] = 0 if code else len([line for line in _words(out).splitlines() if line.strip()])
        return info

    def _hg(self, top: Path) -> dict:
        """A Mercurial working copy as it stands (its remote is not asked)."""
        code, out, _ = self.runner(["hg", "id", "-i", "-b"], str(top), COMMAND_S)
        if code:
            return {"problem": "Mercurial (hg) is not installed here: this working copy is not read" if code == 127
                    else "hg could not read it"}
        commit, _, branch = _words(out).partition(" ")
        info = {"commit": commit.rstrip("+"), "branch": branch, "changed": 1 if commit.endswith("+") else 0}
        code, out, _ = self.runner(["hg", "paths", "default"], str(top), COMMAND_S)
        if not code:
            info["remote"] = plain_address(_words(out))
        return info

    def _walked(self, top: Path) -> list[str]:
        """The files under a folder that is no git working copy, the folders that hold none of its writing left out."""
        files: list[str] = []
        for folder, dirs, names in os.walk(top):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and not d.endswith(".egg-info")]
            base = Path(folder).relative_to(top).as_posix()
            files.extend(f"{base}/{n}" if base != "." else n for n in names)
        return files

    def repository(self, top: Path, kind: str, used: list[str]) -> tuple[dict, Counts]:
        """One working copy (or plain folder) read: what it is and where it stands, and its code counted."""
        row: dict = {"name": top.name, "path": str(top), "kind": kind, "tool": TOOLS.get(kind, ""), "used": list(used),
                     "branch": "", "commit": "", "when": "", "subject": "", "remote": "", "upstream": "", "ahead": None,
                     "behind": None, "asked": None, "changed": 0, "untracked": 0, "problem": ""}
        files = None
        if kind == "git":
            info, files = self._git(top)
            row.update(info)
        elif kind == "svn":
            row.update(self._svn(top))
        elif kind == "hg":
            row.update(self._hg(top))
        counts = Counts()
        for rel in files if files is not None else self._walked(top):
            counts.file(top, rel)
        row.update(counts.totals())
        row["languages"] = counts.rows()
        row["leftOut"] = dict(counts.left_out)
        return row, counts

    # -- everything ------------------------------------------------------------------------------------------------------
    def read(self) -> dict:
        """Everything read now: every repository, the code of all of them and of this app's own parts. Slow (a few
        processes a repository, every file read once): `snapshot` does it in a thread."""
        found = self.find()
        with self._lock:
            self._progress = {"done": 0, "total": len(found)}

        def one(item) -> tuple[dict, Counts]:
            got = self.repository(*item)
            with self._lock:
                self._progress["done"] += 1
            return got

        # A few at a time: measured on a workspace of 49 repositories, 4.0 s of a 4.25 s reading was waiting for its
        # 196 git commands one after another (20 ms each), 0.2 s reading the files
        with ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="codebase") as pool:
            read = list(pool.map(one, found))
        rows, whole, mine = [], Counts(), Counts()
        for row, counts in read:
            rows.append(row)
            whole.add(counts)
            if row["used"]:
                mine.add(counts)
        roots = self.roots()
        return {"state": "ready", "at": self.clock(), "app": getattr(self.app, "NAME", "") or "",
                "workspace": str(roots[0]) if roots else None, "repositories": rows,
                "languages": whole.rows(), "totals": {**whole.totals(), "repositories": len(rows),
                                                      "behind": sum(1 for r in rows if r["behind"]),
                                                      "ahead": sum(1 for r in rows if r["ahead"]),
                                                      "changed": sum(1 for r in rows if r["changed"] or r["untracked"])},
                "mine": {**mine.totals(), "languages": mine.rows(), "repositories": sum(1 for r in rows if r["used"])},
                "leftOut": dict(whole.left_out)}

    def snapshot(self, fresh: bool = False) -> dict:
        """What the page draws. The last reading while it is not older than KEEP_S; else (and when `fresh`) a reading
        is begun in a thread of its own and this says so: {"state": "reading", "progress": {done, total}} with the
        reading before it, if there was one, so the page keeps what it shows."""
        with self._lock:
            kept, reading = self._kept, self._reading is not None and self._reading.is_alive()
            stale = kept is None or fresh or self.clock() - kept["at"] > KEEP_S
            if stale and not reading:
                self._progress = {"done": 0, "total": 0}
                self._reading = threading.Thread(target=self._read_kept, name="codebase", daemon=True)
                self._reading.start()
                reading = True
            progress, fetching = dict(self._progress), dict(self._fetching) if self._fetching else None
        if reading:
            return {**(kept or {"repositories": [], "languages": [], "totals": {}, "mine": {}, "leftOut": {}}),
                    "state": "reading", "progress": progress, "fetching": fetching}
        return {**kept, "fetching": fetching}

    def _read_kept(self) -> None:
        try:
            got = self.read()
        except Exception as e:  # noqa: BLE001 - said on the page; the next ask tries again
            got = {"state": "ready", "at": self.clock(), "app": getattr(self.app, "NAME", "") or "", "workspace": None,
                   "repositories": [], "languages": [], "totals": {}, "mine": {}, "leftOut": {},
                   "problem": f"the code base could not be read: {type(e).__name__}: {e}"}
        with self._lock:
            self._kept = got

    def wait(self, seconds: float = 60.0) -> dict:
        """The reading under way waited for (a test's, a command line's), then what `snapshot` gives."""
        thread = self._reading
        if thread is not None:
            thread.join(seconds)
        return self.snapshot()

    # -- asking the remotes (the user's own click) ---------------------------------------------------------------------
    def fetch(self, paths=None) -> dict:
        """The remotes asked what they have (git fetch: the remote-tracking branches move, nothing checked out does),
        for every git working copy that has one, or the ones at `paths` (a repository is told by where it is: two
        of one name are not rare, a plugin's checkout and its clone); then everything is read again. In a thread:
        `snapshot` says how far it is (`fetching`: done, total, the ones that could not be asked). Asked for by the
        user on the page, never by itself."""
        wanted = {str(Path(p)) for p in paths} if paths else None
        with self._lock:
            if self._fetching is not None and not self._fetching.get("ended"):
                return {"started": False, "why": "the remotes are being asked already"}
            self._fetching = {"done": 0, "total": 0, "errors": [], "ended": False}
        threading.Thread(target=self._fetch_all, args=(wanted,), name="codebase-fetch", daemon=True).start()
        return {"started": True}

    def _fetch_all(self, wanted: set | None) -> None:
        errors: list[dict] = []
        try:
            tops = [top for top, kind, _ in self.find() if kind == "git" and (wanted is None or str(top) in wanted)]
            with self._lock:
                self._fetching["total"] = len(tops)
            for top in tops:
                code, out, _ = self.runner(["git", "config", "--get-regexp", r"^remote\..*\.url$"], str(top), COMMAND_S)
                if not code and _words(out):  # a working copy with no remote has nothing to ask
                    code, _, err = self.runner(["git", "fetch", "--quiet"], str(top), FETCH_S)
                    if code:
                        said = _words(err).splitlines()
                        errors.append({"name": top.name, "why": plain_address(said[-1]) if said else f"git fetch failed ({code})"})
                with self._lock:
                    self._fetching["done"] += 1
                    self._fetching["errors"] = list(errors)
        finally:
            with self._lock:
                self._fetching["ended"] = True
                self._fetching["at"] = self.clock()
        self._read_kept()
