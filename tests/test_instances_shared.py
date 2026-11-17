"""What every kind of instance shares (liminal_libs/instances.py, 1.62.0): the names lifted out of
storage/instances.py are the same objects wherever they were importable before, the module is plain (the standard
library and `layout` only: the link's helper loads it at every start), and `Store` keeps one value through a login.

No process, no socket: `listening` is asked over a stand-in for the socket module's connect."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

import liminal_libs
from liminal_libs import instances as shared
from liminal_libs.storage import databases
from liminal_libs.storage import instances as kept

SRC = Path(liminal_libs.__file__).parent
LIFTED = ("NAME", "MAX_KEPT", "MAX_TITLE", "VERSION", "HEARD_S", "Refusal", "variable_of", "credential_variables",
          "now_iso", "clean_name", "clean_title", "is_local")
ADDED = ("Store", "secret_variable")


# -- the same objects, importable as before ----------------------------------------------------------------------------
def test_every_lifted_name_is_the_same_object_where_it_was_importable_before():
    for name in LIFTED:
        assert getattr(kept, name) is getattr(shared, name), name
    for name in set(LIFTED) - {"HEARD_S"}:  # (the plugins never took HEARD_S from storage/databases.py)
        assert getattr(databases, name) is getattr(shared, name), name
    for name in ADDED:
        assert getattr(kept, name) is getattr(shared, name), name
    assert kept._heard is shared._heard  # one memory of what listens, unless a test puts another in its place
    assert databases.listening is kept.listening  # the plugins' is storage/instances.py's, as before
    assert issubclass(kept.Instances, shared.Store)
    assert kept.Instances.text is shared.Store.text  # the value's text is read one way


def test_the_variables_are_named_as_before():
    assert shared.variable_of("sqlite") == "SQLITE_INSTANCES"
    assert shared.variable_of(" liminal-ai-ollama ") == "LIMINAL_AI_OLLAMA_INSTANCES"
    assert shared.credential_variables("mongodb", "atlas") == ("MONGODB_ATLAS_USER", "MONGODB_ATLAS_PASSWORD")
    assert shared.secret_variable("liminal-ai-vllm", "gpu-box", "key") == "LIMINAL_AI_VLLM_GPU_BOX_KEY"
    assert shared.credential_variables("a-b", "c-d") == (shared.secret_variable("a-b", "c-d", "user"),
                                                         shared.secret_variable("a-b", "c-d", "password"))


def test_a_refusal_names_what_accepts_it():
    plain, asked = shared.Refusal("no"), shared.Refusal("not without a yes", accept="accept_remote")
    assert isinstance(plain, ValueError) and plain.accept is None and str(plain) == "no"
    assert asked.accept == "accept_remote"
    with pytest.raises(shared.Refusal, match="lowercase letters, digits and dashes"):
        shared.clean_name("Not A Name")
    assert shared.clean_name(" GPU-box ") == "gpu-box" and shared.clean_title("  a   title ") == "a title"
    with pytest.raises(shared.Refusal, match="60 characters at most"):
        shared.clean_title("x" * 61)


# -- plain: what importing it loads ------------------------------------------------------------------------------------
def _file_of(name: str) -> Path | None:
    rel = Path(*name.split(".")[1:])
    for candidate in (SRC / rel / "__init__.py", (SRC / rel).with_suffix(".py")):
        if candidate.is_file():
            return candidate
    return None


def _at_import(tree: ast.Module):
    """The import statements a module runs when it is imported: every one but those inside a function."""
    todo: list[ast.AST] = list(tree.body)
    while todo:
        node = todo.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        todo.extend(ast.iter_child_nodes(node))


def _named(module: str, package: bool, node: ast.Import | ast.ImportFrom):
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


def _outside(name: str) -> set[str]:
    """What a module of the library imports, when it is imported, that is not the library's: by its top name."""
    tree = ast.parse(_file_of(name).read_text(encoding="utf-8"))
    package = _file_of(name).name == "__init__.py"
    return {n.split(".")[0] for node in _at_import(tree) for n in _named(name, package, node)} - {"liminal_libs", ""}


def loaded_by(name: str) -> set[str]:
    """The library's modules that importing `name` loads, read from the source: each module's imports outside its
    functions, and every package on the way to it. (Read, not imported: this process has the whole library loaded by
    the other tests, and a test starts no process to look in a fresh one.)"""
    seen: set[str] = set()
    todo = [name]
    while todo:
        parts = todo.pop().split(".")
        if parts[0] != "liminal_libs":
            continue
        for i in range(1, len(parts) + 1):
            module = ".".join(parts[:i])
            source = _file_of(module)
            if module in seen or source is None:
                continue
            seen.add(module)
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in _at_import(tree):
                todo.extend(_named(module, source.name == "__init__.py", node))
    return seen


def test_the_shared_module_is_plain_the_standard_library_and_layout_only():
    assert loaded_by("liminal_libs.instances") == {"liminal_libs", "liminal_libs.instances", "liminal_libs.layout"}
    for module in ("liminal_libs.instances", "liminal_libs.layout", "liminal_libs"):
        assert _outside(module) <= set(sys.stdlib_module_names), (module, _outside(module))


def test_importing_the_kept_instances_loads_nothing_of_the_apps_or_the_plugin_contract():
    # the link's helper imports storage/instances.py at every start (storage/link.py, main): what it loads, every
    # Linux process that reaches Windows' files pays
    loaded = loaded_by("liminal_libs.storage.instances")
    assert {"liminal_libs.instances", "liminal_libs.storage.instances", "liminal_libs.layout"} <= loaded
    heavy = sorted(m for m in loaded if m.split(".")[1:2] in (["apps"], ["sources"], ["machines"]))
    assert heavy == []


def test_the_reader_of_imports_sees_what_a_module_loads():
    # the two tests above are worth what this reader is: it finds an import made on the way, and skips a function's
    assert "liminal_libs.sources.plugin" in loaded_by("liminal_libs.storage.databases")  # (its module-level import)
    assert "liminal_libs.config" not in loaded_by("liminal_libs.instances")
    tree = ast.parse("import a.b\nfrom . import c\nfrom ..d import e\n"
                     "def f():\n    import g\nclass H:\n    import i\n")
    found = {n for node in _at_import(tree) for n in _named("p.q.r", False, node)}
    assert found == {"a.b", "p.q", "p.q.c", "p.d", "p.d.e", "i"}


# -- what listens ------------------------------------------------------------------------------------------------------
class Answers:
    """A stand-in for the socket module's connect: port 4000 answers, any other refuses; each ask is noted."""

    def __init__(self, asked: list, address):
        asked.append(address)
        if address[1] != 4000:
            raise ConnectionRefusedError("nothing there")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def asked(monkeypatch):
    out: list = []
    clock = {"now": 50.0}
    monkeypatch.setattr(shared.socket, "create_connection", lambda address, timeout=None: Answers(out, address))
    monkeypatch.setattr(shared.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(shared, "_heard", {})
    monkeypatch.setattr(kept, "_heard", {})
    out_clock = out, clock
    return out_clock


def test_what_listens_on_this_machine_is_remembered_in_the_memory_given(asked):
    seen, clock = asked
    mine: dict = {}
    assert shared.listening("127.0.0.1", 9931, heard=mine) is False
    assert shared.listening("127.0.0.1", 9931, heard=mine) is False  # remembered: not asked again
    assert seen == [("127.0.0.1", 9931)] and list(mine) == [("127.0.0.1", 9931)] and shared._heard == {}
    assert shared.listening("127.0.0.1", 9931) is False and len(seen) == 2  # the module's own memory knew nothing of it
    assert shared.listening("localhost", 4000) is True and shared.listening("LOCALHOST", 4000, fresh=True) is True
    assert len(seen) == 4  # asked now all the same
    clock["now"] += shared.HEARD_S
    assert shared.listening("127.0.0.1", 9931, heard=mine) is False and len(seen) == 5  # the moment is over
    assert shared.listening("gpu-box.example", 4000) is True and ("gpu-box.example", 4000) not in shared._heard
    assert shared.listening("127.0.0.1", "not a port") is False and shared.listening("127.0.0.1", True) is False
    assert len(seen) == 6  # another machine is never remembered; what is no port is asked of nobody


def test_another_machine_is_asked_every_time(asked):
    seen, _ = asked
    assert shared.listening("gpu-box.example", 4000) is True and shared.listening("gpu-box.example", 4000) is True
    assert seen == [("gpu-box.example", 4000)] * 2 and shared._heard == {}


def test_the_databases_listening_remembers_in_its_own_modules_memory(asked):
    seen, _ = asked
    assert kept.listening("127.0.0.1", 27017) is False and kept.listening("127.0.0.1", 27017) is False
    assert seen == [("127.0.0.1", 27017)]
    assert ("127.0.0.1", 27017) in kept._heard and shared._heard == {}  # in the one a test of the databases replaced


# -- one value kept through a login ------------------------------------------------------------------------------------
class Login:
    def __init__(self, **pairs):
        self.pairs = dict(pairs)
        self.asked: list = []

    def variables(self, wanted):
        self.asked.append(tuple(wanted))
        return {name: self.pairs[name] for name in wanted if name in self.pairs}

    def save(self, variable, value):
        if value is None:
            self.pairs.pop(variable, None)
        else:
            self.pairs[variable] = value
        return "the stand-in's pairs"


def test_a_store_reads_and_keeps_one_value_through_the_login():
    login = Login(X_INSTANCES='{"v":1}')
    store = shared.Store("X_INSTANCES", lambda: login)
    assert store.text() == '{"v":1}' and login.asked == [("X_INSTANCES",)]
    assert store.put('{"v":1,"instances":[]}') == "the stand-in's pairs" and login.pairs["X_INSTANCES"].endswith("[]}")
    assert store.put(None) == "the stand-in's pairs" and store.text() == "" and "X_INSTANCES" not in login.pairs


def test_a_store_without_a_login_keeps_nothing_and_says_so():
    store = shared.Store("X_INSTANCES", lambda: None)
    assert store.text() == ""
    with pytest.raises(shared.Refusal, match="this plugin has none"):
        store.put("{}")


def test_a_store_refuses_more_than_one_variable_holds():
    login = Login()
    store = shared.Store("X_INSTANCES", lambda: login)
    with pytest.raises(shared.Refusal, match="too much to keep"):
        store.put("x" * (shared.MAX_KEPT + 1))
    assert login.pairs == {}
    assert store.put("x" * shared.MAX_KEPT) == "the stand-in's pairs"


def test_a_store_of_another_systems_value_asks_that_system_and_never_this_login():
    login = Login(X_INSTANCES="this system's")
    store = shared.Store("X_INSTANCES", lambda: login, saved=lambda: {"X_INSTANCES": "the other system's"})
    assert store.text() == "the other system's" and login.asked == []
    assert shared.Store("X_INSTANCES", lambda: login, saved=dict).text() == ""


def test_the_databases_instances_are_a_store_with_their_own_words():
    login = Login()
    mine = kept.Instances("SQLITE_INSTANCES", lambda: login, "sqlite")
    assert mine.engine == "sqlite" and mine.variable == "SQLITE_INSTANCES" and mine.text() == ""
    assert mine.read().instances == {} and mine.keep(kept.Kept()) == "the stand-in's pairs"
    with pytest.raises(shared.Refusal, match="the integrator's login"):
        kept.Instances("SQLITE_INSTANCES", lambda: None, "sqlite").keep(kept.Kept())
