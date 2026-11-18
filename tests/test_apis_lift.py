"""The cards lifted (liminal_libs/apis.py, 1.63.0): every name sources/apis.py had is the same object in
liminal_libs.apis, defined there alone, and the lifted module is plain (the standard library only), so an app that
holds no plugin (the login, the charts' front) says what it attaches to without loading the registry, pandas or numpy.
internal.py, which the Internal API tab is made from, is held to the same.

What a module loads is read from its source, not imported: this process has the whole library loaded by the other
tests, and a test starts no process to look in a fresh one."""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

import liminal_libs
from liminal_libs import apis as lifted
from liminal_libs.sources import apis as cards

pytestmark = pytest.mark.usefixtures("no_outside")

SRC = Path(liminal_libs.__file__).parent
LIFTED = ("Link", "Area", "Call", "Api", "LINK_KINDS", "DOCS_KINDS", "API_KINDS", "HTTPS", "ALIVE", "ERROR_PAGE",
          "CHECK_AGENT", "as_dicts", "facts_of", "is_https", "problems", "_links", "_named", "_verified", "urls",
          "dead_links")  # the whole of sources/apis.py until 1.63.0
DEFINED = ("Link", "Area", "Call", "Api", "as_dicts", "facts_of", "is_https", "problems", "_links", "_named",
           "_verified", "urls", "dead_links")  # its classes and functions
STDLIB = frozenset(sys.stdlib_module_names)


# -- the same objects, importable as before ----------------------------------------------------------------------------
def test_every_name_of_the_cards_is_the_same_object_in_both_places():
    for name in LIFTED:
        assert getattr(cards, name) is getattr(lifted, name), name
    for name in DEFINED:
        assert getattr(lifted, name).__module__ == "liminal_libs.apis", name  # its code is there, and only there


def test_the_old_place_holds_nothing_of_its_own():
    # a name given to sources/apis.py alone would be a second copy of the cards, drifting from the first
    own = sorted(n for n in vars(cards) if not n.startswith("__") and getattr(lifted, n, None) is not getattr(cards, n))
    assert own == []


def test_a_card_made_in_either_place_is_one_kind_and_is_checked_in_the_same_words():
    made = lifted.Api(name="Example", maker="Example", about="the example's things")
    assert type(made) is cards.Api and isinstance(made, cards.Api)
    assert cards.as_dicts((made,)) == lifted.as_dicts((made,)) == [made.as_dict()]
    # the words stay those plugins' tests pin (sources.apis is where a plugin still takes the cards from)
    assert lifted.problems([made]) == ["apis must be a tuple of sources.apis.Api, not list"]
    said = cards.problems((made,))
    assert any("no documentation link" in s for s in said) and any("is not an ISO date" in s for s in said)


def test_the_cards_modules_name_no_host():
    # the user's rule (2026-10-31): the library's code names no outside host; a card's addresses are written in its
    # plugin's or its app's own package (the charts' boundary test reads the library's modules too)
    url = re.compile(r"\b(?:https?|wss?|ftp)://[A-Za-z0-9]", re.I)
    for path in (SRC / "apis.py", SRC / "sources" / "apis.py"):
        assert not url.search(path.read_text(encoding="utf-8")), path


# -- plain: what importing it loads ------------------------------------------------------------------------------------
def _file_of(module: str) -> Path | None:
    rel = Path(*module.split(".")[1:])
    for candidate in (SRC / rel / "__init__.py", (SRC / rel).with_suffix(".py")):
        if candidate.is_file():
            return candidate
    return None


def _run_at_import(tree: ast.Module):
    """The import statements a module runs when it is imported: every one but those inside a function."""
    todo: list[ast.AST] = list(tree.body)
    while todo:
        node = todo.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        todo.extend(ast.iter_child_nodes(node))


def _names(module: str, package: bool, node: ast.Import | ast.ImportFrom):
    """Every module an import statement of `module` may load, by its whole name."""
    if isinstance(node, ast.Import):
        yield from (alias.name for alias in node.names)
        return
    if node.level:
        base = module.split(".") if package else module.split(".")[:-1]
        base = base[:len(base) - (node.level - 1)]
        stem = ".".join(base + ([node.module] if node.module else []))
    else:
        stem = node.module or ""
    yield stem
    yield from (f"{stem}.{alias.name}" for alias in node.names)  # a submodule, when it is one


def loaded_by(name: str) -> tuple[set[str], set[str]]:
    """What importing `name` loads, read from the sources: the library's modules (each package on the way to one, and
    what each imports outside its functions), and the top names of everything else they import."""
    library: set[str] = set()
    outside: set[str] = set()
    todo = [name]
    while todo:
        parts = todo.pop().split(".")
        if parts[0] != "liminal_libs":
            outside.add(parts[0])
            continue
        for i in range(1, len(parts) + 1):
            module = ".".join(parts[:i])
            source = _file_of(module)
            if module in library or source is None:
                continue
            library.add(module)
            for node in _run_at_import(ast.parse(source.read_text(encoding="utf-8"))):
                todo.extend(_names(module, source.name == "__init__.py", node))
    return library, outside


def test_the_lifted_cards_load_the_standard_library_alone():
    library, outside = loaded_by("liminal_libs.apis")
    assert library == {"liminal_libs", "liminal_libs.apis"}
    assert outside <= STDLIB, sorted(outside - STDLIB)


def test_the_internal_api_module_is_as_plain():
    if _file_of("liminal_libs.internal") is None:
        pytest.skip("liminal_libs/internal.py is not in this tree")
    library, outside = loaded_by("liminal_libs.internal")
    assert library <= {"liminal_libs", "liminal_libs.internal", "liminal_libs.apis"}, sorted(library)
    assert outside <= STDLIB, sorted(outside - STDLIB)


def test_the_reader_sees_what_a_module_loads():
    # the two tests above are worth what this reader is: it follows a package's imports, finds what comes from outside
    # the standard library, and skips a function's
    library, outside = loaded_by("liminal_libs.sources.apis")  # why the cards moved: through sources/__init__.py
    assert {"liminal_libs.apis", "liminal_libs.sources", "liminal_libs.sources.registry"} <= library
    assert {"pandas", "numpy"} <= outside
    tree = ast.parse("import a.b\nfrom . import c\nfrom ..d import e\nfrom __future__ import annotations\n"
                     "def f():\n    import g\nclass H:\n    import i\n")
    found = {n for node in _run_at_import(tree) for n in _names("p.q.r", False, node)}
    assert found == {"a.b", "p.q", "p.q.c", "p.d", "p.d.e", "__future__", "__future__.annotations", "i"}
