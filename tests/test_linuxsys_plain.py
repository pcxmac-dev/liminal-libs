"""The package `liminal_libs.linuxsys` is plain (Monday list item 19; the linuxperm plan's S8 and M2).

Liminal's one root command runs from it (`python -I -B -m liminal_libs.linuxsys`), so loading it must bring in no
plugin contract, no app's frame and no process ledger: a module under `machines/` loads all three before its own first
line, and that code would then run as root. Two things hold it here. Every module's imports are read (the standard
library, this package and `proctree`, nothing more), and every module is loaded in this process with the library taken
out of `sys.modules` first, to see what comes in with it.
"""
from __future__ import annotations

import ast
import importlib
import pkgutil
import sys
from pathlib import Path

import liminal_libs
from liminal_libs import linuxsys

# what a module of linuxsys may import of the library's own, besides the package itself
ALLOWED = ("liminal_libs.linuxsys", "liminal_libs.proctree")
# what must never be loaded with it: the plugin contract, the frame, the machine plugins, the ledger and its files
NEVER = ("liminal_libs.apps", "liminal_libs.sources", "liminal_libs.machines", "liminal_libs.lifecycle",
         "liminal_libs.claims", "liminal_libs.layout", "liminal_libs.storage", "liminal_libs.internal",
         "liminal_libs.nodes", "liminal_libs.stop")
FOLDER = Path(linuxsys.__file__).parent


def _modules() -> list[str]:
    return ["liminal_libs.linuxsys"] + sorted(m.name for m in pkgutil.walk_packages(linuxsys.__path__,
                                                                                     "liminal_libs.linuxsys."))


def _imports(path: Path, package: tuple = ("liminal_libs", "linuxsys")) -> list[str]:
    """Every module `path` imports, by its full name (a relative import resolved against its `package`)."""
    out: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                out.append(node.module or "")
            else:
                base = list(package)[:len(package) + 1 - node.level]  # `.x` is linuxsys.x, `..x` is liminal_libs.x
                names = [node.module] if node.module else [a.name for a in node.names]
                out += [".".join([*base, n]) for n in names]
    return out


def test_every_module_imports_only_the_standard_library_the_package_and_proctree():
    files = sorted(FOLDER.glob("*.py"))
    assert {f.name for f in files} >= {"__init__.py", "shared.py"}
    for f in files:
        for name in _imports(f):
            top = name.split(".")[0]
            if top == "liminal_libs":
                assert name.startswith(ALLOWED), f"{f.name} imports {name}"
            else:
                assert top == "__future__" or top in sys.stdlib_module_names, f"{f.name} imports {name}"


def test_no_module_imports_what_only_linux_has_at_its_top():
    """The package loads on Windows too (the library's own CI, a plugin's suite on this PC): pwd, grp, fcntl, pty and
    termios are imported where they are used, never at a module's top."""
    for f in sorted(FOLDER.glob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        names = {a.name.split(".")[0] for n in top if isinstance(n, ast.Import) for a in n.names}
        names |= {(n.module or "").split(".")[0] for n in top if isinstance(n, ast.ImportFrom) and n.level == 0}
        assert not names & {"pwd", "grp", "fcntl", "pty", "termios", "resource"}, f.name


def test_loading_the_package_brings_in_no_frame_no_plugin_contract_and_no_ledger():
    kept = {name: mod for name, mod in sys.modules.items()
            if name == "liminal_libs" or name.startswith("liminal_libs.")}
    for name in kept:
        del sys.modules[name]
    try:
        for name in _modules():
            if name.endswith(".__main__"):
                continue  # the entry is run, not imported: tests/test_linuxsys_cli.py runs it the same way
            importlib.import_module(name)
        loaded = sorted(n for n in sys.modules if n == "liminal_libs" or n.startswith("liminal_libs."))
    finally:
        for name in [n for n in sys.modules if n == "liminal_libs" or n.startswith("liminal_libs.")]:
            del sys.modules[name]
        sys.modules.update(kept)
    assert "liminal_libs.linuxsys.shared" in loaded
    for name in loaded:
        assert not name.startswith(NEVER), f"loading linuxsys loaded {name}"
        assert name == "liminal_libs" or name.startswith(ALLOWED), f"loading linuxsys loaded {name}"
    # and the check can see a breach: machines/linux.py, which imports the shared names back, does load them all
    assert liminal_libs.__name__ == "liminal_libs" and "liminal_libs.linuxsys.shared" in sys.modules


def test_the_check_would_see_a_module_of_the_plugin_contract():
    """The same reading on machines/linux.py finds what linuxsys must not have: so the check above is no empty one."""
    names = _imports(Path(liminal_libs.__file__).parent / "machines" / "linux.py", ("liminal_libs", "machines"))
    assert "liminal_libs.machines.plugin" in names and "liminal_libs.linuxsys.shared" in names
    assert any(n.startswith(NEVER) for n in names)


def test_its_two_starts_open_no_window(monkeypatch):
    """The system's runner and spawn (linuxsys._run, ._spawn) say how a console window is kept away, as every start in
    the library does (the charts' test_no_console_windows reads each call's text): CREATE_NO_WINDOW on Windows, 0
    elsewhere, so a sudo or probe started by a console-less platform pops no Terminal window (1.104.0)."""
    import subprocess

    from liminal_libs import proctree
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: seen.append(("run", kw)))
    monkeypatch.setattr(subprocess, "Popen", lambda args, **kw: seen.append(("Popen", kw)))
    for nt, flags in ((True, 0x08000000), (False, 0)):
        monkeypatch.setattr(proctree, "_nt", lambda nt=nt: nt)
        seen.clear()
        linuxsys._run(["true"], timeout=1)
        linuxsys._spawn(["true"])
        assert [(k, kw.get("creationflags", "missing")) for k, kw in seen] == [("run", flags), ("Popen", flags)]
