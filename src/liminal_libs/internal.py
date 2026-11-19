"""What a plugin shares with the rest of its app, and what an app offers its plugins and other apps: their Internal API
(liminal-libs 1.63.0; DECISIONS.md part C, with its addenda 13 and 14).

The user, 2026-11-16: "for all apps, and all plugins, there should be an external api tab, and an internal api tab, the
internal api is for interfaces the plugin shares with the rest of the app, the external should be all the SDKs/APIs the
plugin associates with"; 2026-11-17: "a second tab for all plugins which describe the internal API like structure that
the app code can work with", "all plugins all apps"; and "all plugins are middleware", "even for other plugins", "and
then the app object code".

So a plugin is read as middleware, from the object itself, so that what is said of it cannot go stale (`internal_of`):
- what it sits on: its `apis`, which its External API tab shows (`sitsOn`);
- what kind of middleware it is: the library base it is built on (`builtOn`) and that base's line up to Plugin
  (`chain`), and so the standard interface it implements, the same for every plugin of its kind: each base's HOOKS, a
  layer each, nearest first (`standard`);
- each of its hooks, the standard ones first, then its own: its arguments, its docstring's first sentence (`line`) and
  the whole of it (`doc`); the layer naming it (`layer`); whose code answers it (`answered`: "itself", the library class
  whose code does, or "" for the contract's default); whether it only reads (`reads`), runs as a job (`job`,
  `cancels`), is a tab's page (`tab`, `every`), or is asked twice (`twice`: its `accept_*` arguments); and who uses it
  here (`users`): the app's object code (`how`, in the app's words), other plugins (its SERVICE_HOOKS, and `askedBy`:
  the plugins whose ASKS name it), both, or the app by name for its page, a client or another plugin (`askable`);
- how the app is asked for it (`calls`, the app's words: App.call_words), what it asks of other plugins (`asks`, each
  with what it finds here), what it reads and keeps through the login (`settings`, `options`, `keeps`), what the app
  reads of it by name (`attributes`, and the class constants among them by value: `declares`), its tabs, its setup's
  steps and a few notes of its own.

What a plugin says of itself is plain tuples of words on its class (sources/plugin.py: READ_HOOKS, SERVICE_HOOKS, ASKS,
KEEPS, INTERNAL_NOTES; JOB_HOOKS, CANCEL_HOOKS and TABS as before), read by name, so a plugin imports nothing for them:
one that says nothing has both tabs all the same, each hook of its own listed as a change until it says it only reads.
Two more say who may ask a hook (2026-11-18, for the MCP plugin): PLUGIN_ONLY_HOOKS, asked only by another plugin
through its app, never by a page or a program; and PAGE_ONLY_HOOKS, asked only from its page, never by another plugin.
Plugin declares neither: a plugin that says neither has none (`plugin_only`, `page_only`), and apps.asking holds an
ask to them. `problems(plugin)` is what a plugin's own test holds it to. `reads_of` is what an app asks as reads (the
platform's log), and `answers`, `kind_of` and `tabs_key` what the frame reads of a plugin for its own parts
(App.askable, App.plugin_internal), each as the plugin declares it. `answered_by` is the contract's own rule
(Plugin.gives asks it): whose code answers a hook.

Nothing of a plugin is called or evaluated here. Its hooks and what the app calls on it are looked up as they are
declared (inspect.getattr_static's way: the instance's own attributes, then its classes'): a function gives its
arguments and its docstring, a property is said as one and never read, and no annotation is evaluated. Only its declared
words (DECLARED, ASKS, KEEPS, INTERNAL_NOTES, TABS, STEPS) and its `keys`, `plan_vars`, `options` and `apis` are read
with getattr, each in its own try, as the platform reads its keys. Every answer is plain JSON and is made without
raising: a part that cannot be read is left empty.

An app's (`app_internal`) is its object code's side: what it calls and reads on its plugins of each kind (App.CALLS,
App.ATTRIBUTES) and the words it is asked in; what it offers them and other apps (interface()'s methods, the login it
lends, and for code plugin_internal, internal and own_apis); its routes (its own, App.routes(), then the frame's:
FRAME_ROUTES, and LOGIN_ROUTES while it inherits a login), the login it includes, the apps it links and its plugins.
`literals_in` and `route_problems` hold a table of routes to the code answering them (a test's).

This module is plain: the standard library alone, nothing of the plugin contract or of the apps (it knows their classes
by name), so the login and the charts' front can say theirs without loading the registry."""
from __future__ import annotations

import ast
import functools
import inspect
import math
import os
import re
import sys
import textwrap
import types
from collections.abc import Mapping

VERSION = 1  # of the answers' shape: their "v"
LINE_CHARS = 240  # a hook's line, the first sentence of its docstring, cut here with "…"
DOC_CHARS = 1200  # a hook's whole docstring (`doc`), and the words an app is asked in, cut here with "…"
MAX_HOOKS = 120  # hooks listed at the most
MAX_WORDS = 40  # rows read of each of ASKS, KEEPS and INTERNAL_NOTES (and of an app's LINKED) at the most
NOTE_CHARS = 400  # a line of INTERNAL_NOTES at the most
DEFAULT_CHARS = 40  # a str default among a hook's arguments, at the most
MAX_KNOWN = 400  # plugins an app is read as knowing at the most
KINDS = ("read", "tab", "change", "job", "service", "own")  # a hook's kind (the first that holds), the page's tag order
USERS = ("both", "plugins", "app", "named", "")  # who uses a hook here (the first that holds)
PLUGIN_ONLY = "PLUGIN_ONLY_HOOKS"  # its hooks only another plugin asks, through its app: never a page or a program
PAGE_ONLY = "PAGE_ONLY_HOOKS"  # its hooks only its page asks: never another plugin
DECLARED = ("READ_HOOKS", "SERVICE_HOOKS", "JOB_HOOKS", "CANCEL_HOOKS", PLUGIN_ONLY,
            PAGE_ONLY)  # the declarations made of hooks' names
CONSTANTS = ("SECTION", "ICON", "STEPS", "JOB_HOOKS")  # the class constants an app reads, given by value (`declares`)
APP_METHODS = ("describe", "tray", "plugins", "attach", "detach", "ask", "interface", "connections")  # interface()'s
OFFERS = ("plugin_internal", "internal", "own_apis")  # what an app offers code besides them (kept out of interface())
ROUTE_METHODS = ("GET", "POST", "PUT", "DELETE", "ANY")
ROUTE_KINDS = ("read", "change", "ask", "stream")  # a route's class, as who talks to whom notes it (apps/traffic.py)
ROUTE_WHO = ("page", "client", "plugin", "app", "login")  # who asks a route
NAME = "NAME"  # the part of the words an app is asked in that names the plugin, in an app's own Internal API

# the frame's own routes (apps/app.py: App.api and its request handler), as an app's Internal API lists them after the
# app's own: (method, path, what it is, its class, who asks it); `{...}` is a part that varies
FRAME_ROUTES = (  # answered by every app
    ("GET", "/api/tray", "its tray: its own icon, then its plugins'", "read", "page"),
    ("GET", "/api/app", "what a client or another app learns of it first: its name, title, icon, API, port and "
                        "address", "read", "client"),
    ("GET", "/api/app/apis", "its own External and Internal API; with ?plugin=NAME, an attached plugin's", "read",
     "page"),
    ("GET", "/api/plugins", "the plugins attached, each with the hooks it answers", "read", "client"),
    ("GET", "/api/interface", "what it offers a plugin or another app: its API, its login and the methods they may "
                              "call", "read", "client"),
    ("GET", "/api/login/pairs", "the pairs its plugins ask for, asked by the login it inherits", "read", "login"),
    ("GET", "/api/traffic", "who talks to whom: its page, its login, its plugins and what they reached (?last=)",
     "read", "page"),
    ("GET", "/api/codebase", "the code it is made of: its repositories and their languages (?fresh=1 reads them "
                             "again)", "read", "page"),
    ("POST", "/api/codebase/fetch", "its repositories' remotes asked what they have, on the user's click", "change",
     "page"),
    ("GET", "/api/ui", "the UI's preferences every page applies", "read", "page"),
)
LOGIN_ROUTES = (  # answered only while the app inherits a login (App.inherits_login)
    ("GET", "/api/trays", "the trays of what it holds besides its own: the login it inherits", "read", "page"),
    ("ANY", "/login/{rest}", "the login it inherits, an object here: its page, its sign-in and its API", "change",
     "page"),
)

_LIBRARY = "liminal_libs"
_PLUGIN = ("liminal_libs.sources.plugin", "Plugin")  # the contract's root, known by name: nothing is imported for it
_LOGIN = ("liminal_libs.apps.authorization", "Login")  # the authorization interface a login is
_FRAME = "liminal_libs.apps.app"  # the frame's module (its LOGIN_PREFIX), loaded wherever an App is
_REGISTRY = "liminal_libs.sources.registry"  # the registry's (its PLUGIN_API), named only when it is loaded already
_END = re.compile(r"(?<=[^.\s][.!?])\s+(?=[A-Z`\"'(\[])")  # a sentence's end: a stop, a capital, a quote or a bracket
_PARAGRAPH = re.compile(r"\n[ \t]*\n")
_QUOTED = re.compile(r"""["'](/api/[^"'\s]*)["']""")
_MISSING = object()
_KIND_OF = {inspect.Parameter.POSITIONAL_ONLY: "posonly", inspect.Parameter.POSITIONAL_OR_KEYWORD: "pos",
            inspect.Parameter.VAR_POSITIONAL: "varargs", inspect.Parameter.KEYWORD_ONLY: "kwonly",
            inspect.Parameter.VAR_KEYWORD: "varkw"}


# -- the words of a docstring and of a call ---------------------------------------------------------------------------
def line_of(doc: str | None) -> str:
    """A docstring's first sentence, of its first paragraph, on one line: a sentence ends at a stop followed by a space
    and a capital, a quote or an opening bracket (a docstring's first line alone often stops mid-sentence). LINE_CHARS
    at the most, cut with "…"; "" for none."""
    if not isinstance(doc, str) or not doc.strip():
        return ""
    paragraph = " ".join(_PARAGRAPH.split(inspect.cleandoc(doc).strip(), 1)[0].split())
    return _cut(_END.split(paragraph, 1)[0], LINE_CHARS)


def doc_of(doc: str | None) -> str:
    """A docstring as a whole (inspect.cleandoc), DOC_CHARS at the most, cut with "…"; "" for none."""
    if not isinstance(doc, str) or not doc.strip():
        return ""
    return _cut(inspect.cleandoc(doc).strip(), DOC_CHARS)


def args_of(given) -> str:
    """A callable's arguments as the Internal API tab shows them: "(name, ports, protocol='tcp')", "(log=print,
    steps=None)", "(*command, **options)"; a bound method's without its self. Annotations are dropped and never
    evaluated; a default is shown as its repr only for None, a bool, a number, a str (DEFAULT_CHARS at the most) or an
    empty container, as its name for a function or a class, else as "...": no object's repr is sent. "(...)" when they
    cannot be read; "" for what is not called (a property, a value)."""
    return _call(given, False)[0]


def _cut(text: str, chars: int) -> str:
    return text if len(text) <= chars else text[:chars - 1].rstrip() + "…"


def _default(value) -> str:
    if value is None or type(value) in (bool, int, float):
        return repr(value)
    if type(value) is str:
        return repr(value) if len(value) <= DEFAULT_CHARS else repr(value[:DEFAULT_CHARS - 3] + "...")
    if type(value) in (tuple, list, dict, set, frozenset) and not value:
        return repr(value)
    try:
        name = value.__name__ if isinstance(value, (type, types.FunctionType, types.BuiltinFunctionType)) else ""
    except Exception:  # noqa: BLE001 - a default that cannot say its name: "..."
        name = ""
    return name if isinstance(name, str) and name.isidentifier() else "..."


def _code_params(fn) -> list[tuple] | None:
    """A function's parameters, (kind, name, whether it has a default, the default), read from its code object: so no
    annotation is evaluated (under deferred annotations inspect.signature evaluates them, and a name a module imports
    only for type checking fails there)."""
    code = getattr(fn, "__code__", None)
    if not isinstance(code, types.CodeType):
        return None
    names, npos, nposonly, nkw = code.co_varnames, code.co_argcount, code.co_posonlyargcount, code.co_kwonlyargcount
    defaults = getattr(fn, "__defaults__", None) or ()
    kwdefaults = getattr(fn, "__kwdefaults__", None) or {}
    first = npos - len(defaults)
    out = [("posonly" if i < nposonly else "pos", names[i], i >= first, defaults[i - first] if i >= first else None)
           for i in range(npos)]
    at = npos + nkw
    if code.co_flags & inspect.CO_VARARGS:
        out.append(("varargs", names[at], False, None))
        at += 1
    out += [("kwonly", n, n in kwdefaults, kwdefaults.get(n)) for n in names[npos:npos + nkw]]
    if code.co_flags & inspect.CO_VARKEYWORDS:
        out.append(("varkw", names[at], False, None))
    return out


def _text_of(params) -> str:
    parts, starred = [], False
    for i, (kind, name, has, default) in enumerate(params):
        if kind == "varargs":
            parts.append(f"*{name}")
            starred = True
        elif kind == "varkw":
            parts.append(f"**{name}")
        else:
            if kind == "kwonly" and not starred:
                parts.append("*")
                starred = True
            parts.append(name + (f"={_default(default)}" if has else ""))
        if kind == "posonly" and (i + 1 == len(params) or params[i + 1][0] != "posonly"):
            parts.append("/")
    return f"({', '.join(parts)})"


def _call(value, bound: bool) -> tuple[str, tuple[str, ...]]:
    """A definition as it is called: its arguments as text and their names. `bound`: it was found on a class, where a
    function takes the object it is called on first (left out, as a classmethod's class and a bound method's self are);
    ("", ()) for what is not called (a property, a value), ("(...)", ()) when its arguments cannot be read."""
    if value is None or value is _MISSING or _is_property(value):
        return "", ()
    drop = isinstance(value, (classmethod, types.MethodType)) or (bound and isinstance(value, types.FunctionType))
    fn = value.__func__ if isinstance(value, (staticmethod, classmethod, types.MethodType)) else value
    rows = None
    if isinstance(fn, types.FunctionType):
        try:
            fn = inspect.unwrap(fn)
        except Exception:  # noqa: BLE001 - a loop of __wrapped__: the function as it is
            pass
        rows = _code_params(fn)
    if rows is None:
        if not callable(fn):
            return "", ()
        try:
            rows = [(_KIND_OF[p.kind], p.name, p.default is not p.empty, None if p.default is p.empty else p.default)
                    for p in inspect.signature(fn).parameters.values()]
        except Exception:  # noqa: BLE001 - a builtin without a text signature, an annotation that cannot be read
            return "(...)", ()
    if drop and rows and rows[0][0] in ("posonly", "pos"):
        rows = rows[1:]
    return _text_of(rows), tuple(r[1] for r in rows)


# -- reading an object as it is declared: nothing of it evaluated -----------------------------------------------------
def _try(fn, default):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - a part that cannot be read is left empty: an answer is made without raising
        return default


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _library(cls) -> bool:
    module = getattr(cls, "__module__", "") or ""
    return isinstance(module, str) and (module == _LIBRARY or module.startswith(_LIBRARY + "."))


def _is(cls, where: tuple[str, str]) -> bool:
    """Whether a class is, or comes from, the library class `where` names (module, name): known by name, so nothing of
    the contract or the apps is imported here."""
    try:
        return any(getattr(c, "__module__", "") == where[0] and c.__name__ == where[1] for c in cls.__mro__)
    except Exception:  # noqa: BLE001 - not a class
        return False


def _mro(obj) -> tuple:
    """The classes of an object's line, its own first; of an object given as a class, that class's."""
    try:
        return tuple((obj if isinstance(obj, type) else type(obj)).__mro__)
    except Exception:  # noqa: BLE001
        return ()


def _own(obj) -> Mapping:
    """An instance's own attributes (a record's fields, what __init__, attach or with_ set), read without a descriptor;
    none for an object given as a class."""
    if isinstance(obj, type):
        return {}
    try:
        own = object.__getattribute__(obj, "__dict__")
    except Exception:  # noqa: BLE001 - no __dict__ (slots)
        return {}
    return own if isinstance(own, Mapping) else {}


def _descriptor(value) -> bool:
    """Whether a declared value is a descriptor (a property, a function, a staticmethod): what reading it would run."""
    try:
        return hasattr(type(value), "__get__")
    except Exception:  # noqa: BLE001
        return True


def _is_property(value) -> bool:
    return isinstance(value, (property, functools.cached_property))


def _static(obj, name: str, default=None):
    """An attribute as it is declared, never evaluated (inspect.getattr_static); `default` for a descriptor (a
    property, a method) and for one that is not there."""
    try:
        value = inspect.getattr_static(obj, name)
    except Exception:  # noqa: BLE001 - AttributeError, or an object that cannot be looked into
        return default
    return default if _descriptor(value) else value


def _holders(obj, name: str):
    """What declares a name along an object's line, nearest first: (its value, None) for the instance's own, then (its
    value, the class) for each class whose own attributes hold it. A value None drops a base's."""
    own = _own(obj)
    if name in own:
        yield own[name], None
    for cls in _mro(obj):
        if name in cls.__dict__:
            yield cls.__dict__[name], cls


def answered_by(obj, name: str) -> str:
    """Whose code answers a hook: "itself" (the instance, or a class of its own package), the library class whose code
    does (Firewall for `world`), or "" for the contract's default (a CONTRACT class's method, or a None in its place).
    The nearest declaration decides. This is Plugin.gives' rule (gives is whether it names anyone), so what the Internal
    API tab and App.askable say a plugin answers is what its interface lists and the frame's ask takes."""
    value, where = next(_holders(obj, name), (_MISSING, None))
    if value is _MISSING or value is None:
        return ""
    if where is None:
        return "itself"
    if "CONTRACT" in where.__dict__:
        return ""
    return where.__name__ if _library(where) else "itself"


def _definition(obj, name: str):
    """The code a hook is called with, or, left to the contract, the contract's own: (its value, the class it is in, or
    None for the instance's own); (None, None) when nothing defines it."""
    return next(((value, where) for value, where in _holders(obj, name) if value is not None), (None, None))


def _own_doc(value) -> str:
    if _is_property(value):
        doc = value.__doc__  # its getter's, unless it was given one
    else:
        fn = value.__func__ if isinstance(value, (staticmethod, classmethod, types.MethodType)) else value
        if isinstance(fn, functools.partial):
            fn = fn.func
        if isinstance(fn, types.FunctionType):
            fn = _try(lambda: inspect.unwrap(fn), fn)
        doc = fn.__doc__ if isinstance(fn, (types.FunctionType, types.BuiltinFunctionType)) else None
    return doc if isinstance(doc, str) and doc.strip() else ""


def _doc(obj, name: str) -> str:
    """A hook's docstring: its definition's own, else the nearest base's for the same name (inspect.getdoc's way, so a
    few say what their base does). A None nearer than its definition says nothing."""
    for value, _where in _holders(obj, name):
        doc = _own_doc(value)
        if doc:
            return doc
    return ""


def _values(obj, attr: str) -> tuple[list, str]:
    """Every declaration of `attr` along an object's line, each object once: the instance's own, what getattr reads (a
    property's value: a declared word is read so), then each class's own, nearest first, a descriptor left out. With the
    words of a failure to read it ("" when none failed)."""
    found, failed = [], ""
    own = _own(obj)
    if attr in own:
        found.append(own[attr])
    try:
        value = getattr(obj, attr)
        if not _descriptor(value):
            found.append(value)
    except AttributeError:
        pass
    except Exception as e:  # noqa: BLE001 - a property of the plugin's own that fails: problems() says so
        failed = f"{type(e).__name__}: {e}"[:200]
    for cls in _mro(obj):
        if attr in cls.__dict__ and not _descriptor(cls.__dict__[attr]):
            found.append(cls.__dict__[attr])
    out: list = []
    for value in found:
        if not any(value is seen for seen in out):
            out.append(value)
    return out, failed


def _word(obj, attr: str):
    """A declared word as the plugin has it (getattr, in its own try: a property's value; a subclass's replaces its
    base's): (its value or None, the words of a failure to read it)."""
    try:
        value = getattr(obj, attr)
    except AttributeError:
        return None, ""
    except Exception as e:  # noqa: BLE001 - a property of the plugin's own that fails: problems() says so
        return None, f"{type(e).__name__}: {e}"[:200]
    return (None, "") if _descriptor(value) else (value, "")


def _names(value) -> tuple[str, ...] | None:
    """A declaration of names as a tuple; None when it is not a tuple or a list of str."""
    if isinstance(value, (tuple, list)) and all(isinstance(v, str) for v in value):
        return tuple(value)
    return None


def _strs(value) -> list[str]:
    """The names a collection an app gives holds (its str, not empty), each once, in order; none of a lone str."""
    if isinstance(value, (str, bytes)) or value is None:
        return []
    return list(dict.fromkeys(v for v in list(value)[:MAX_KNOWN] if isinstance(v, str) and v))


def declared(plugin, attr: str) -> tuple[str, ...]:
    """A declaration made of hooks' names (READ_HOOKS, SERVICE_HOOKS, JOB_HOOKS, CANCEL_HOOKS) as a plugin's line makes
    it: the instance's own, then every class's (getattr's, then each class's own, nearest first), each name once. So a
    base's names stay its subclasses': a subclass names only what it adds, and cannot take back what a base says.
    Anything that is not a tuple or a list of str counts as nothing (problems() says so)."""
    return _declared(plugin, attr)[0]


def _declared(plugin, attr: str) -> tuple[tuple[str, ...], str]:
    """declared()'s names, with the words of what kept it from reading them all ("" when nothing did): a failure to
    read the word, or a declaration that is not a tuple or a list of str."""
    values, failed = _values(plugin, attr)
    out: list[str] = []
    for value in values:
        names = _names(value)
        if names is None:
            failed = failed or f"{attr} must be a tuple of str"
        for name in names or ():
            if name and name not in out:
                out.append(name)
    return tuple(out), failed


def _gated(plugin, attr: str) -> tuple[str, ...]:
    names, failed = _declared(plugin, attr)
    if failed:  # a gate that cannot read its word refuses rather than lets through
        raise ValueError(failed if failed.startswith(attr) else f"{attr} cannot be read ({failed})")
    return names


def plugin_only(plugin) -> tuple[str, ...]:
    """The hooks a plugin says only another plugin asks, through its app (PLUGIN_ONLY_HOOKS, as declared() reads it):
    never its page or a program. () when it says none. A ValueError when the word cannot be read, or is not a tuple
    of str, so a gate that asks it refuses rather than lets through (problems() says the same in words)."""
    return _gated(plugin, PLUGIN_ONLY)


def page_only(plugin) -> tuple[str, ...]:
    """The hooks a plugin says only its page asks (PAGE_ONLY_HOOKS, as declared() reads it): never another plugin. ()
    when it says none. A ValueError when the word cannot be read, or is not a tuple of str (as plugin_only)."""
    return _gated(plugin, PAGE_ONLY)


def _hooks(plugin) -> list[str]:
    """Its HOOKS as it has them (the instance's, else its class's), each name once; none when they cannot be read."""
    return list(dict.fromkeys(n for n in (_names(_static(plugin, "HOOKS", ())) or ()) if n))


def answers(plugin) -> tuple[str, ...]:
    """The hooks of its HOOKS a plugin answers itself, not left to the contract's default (answered_by, the rule
    Plugin.gives asks): so those Plugin.interface lists and the frame's ask takes. Read as they are declared: nothing
    of the plugin is called or evaluated (a hook that is a property is not read)."""
    hooks = _try(lambda: _hooks(plugin), [])
    return tuple(n for n in hooks if _try(lambda: answered_by(plugin, n), ""))


def kind_of(plugin) -> str:
    """A plugin's KIND as it is declared ("machine", "feed"), never evaluated; "" for none."""
    return _text(_static(plugin, "KIND", ""))


def _accepts(plugin, name: str) -> str:
    """The first `accept_*` argument a hook's definition takes, "" for none: what a refusal asked a second time sets
    (a refusal's `.accept`), so the hook belongs to a change, whatever its plugin says of it."""
    value, where = _definition(plugin, name)
    return next((p for p in _call(value, where is not None)[1] if p.startswith("accept_")), "")


def _tabs(plugin, tabs=None) -> list[dict]:
    """Its tabs, {id, title, hook, every}: the app's own list of them when it gives one (the platform's tabs_of), else
    its TABS, each as Tab.as_dict() says it (a mapping as it is); a tab naming no hook is left out."""
    source = tabs if tabs is not None else _word(plugin, "TABS")[0]
    if isinstance(source, (str, bytes)) or source is None:
        return []
    items = _try(lambda: list(source)[:64], [])
    out = []
    for t in items:
        d = _try(lambda: t.as_dict() if callable(getattr(t, "as_dict", None)) else t, None)
        hook = d.get("hook") if isinstance(d, Mapping) else None
        if not isinstance(hook, str) or not hook:
            continue
        every = d.get("every")
        out.append({"id": _text(d.get("id")), "title": _text(d.get("title")), "hook": hook,
                    "every": float(every) if type(every) in (int, float) and math.isfinite(every) else None})
    return out


def tabs_key(plugin, tabs=None) -> tuple | None:
    """What an app's own list of a plugin's tabs says, as internal_of reads it, in a form kept as a key and compared
    (App.plugin_internal): each tab's (id, title, hook, every); None when the app gives none (the plugin's TABS are
    read then). Nothing of the plugin is read for it."""
    if tabs is None:
        return None
    return tuple((t["id"], t["title"], t["hook"], t["every"]) for t in _try(lambda: _tabs(plugin, tabs), []))


def reads_of(plugin, reads=(), tabs=None) -> tuple[str, ...]:
    """The hooks of a plugin its app asks as reads (noted as reads in who talks to whom, kept out of its log), each
    once: `reads`, the app's own (App.READ_HOOKS); then its tabs' hooks (`tabs`: the app's own list of them, else its
    TABS); then the READ_HOOKS it says only read, among its HOOKS, that it answers (not left to the contract's
    default), that are not its jobs and that take no `accept_*` argument (a change asked twice, whatever it says:
    problems() says so of both). For a plugin that says nothing of its own: the app's reads and its tabs'."""
    out: list[str] = []
    for name in ((reads,) if isinstance(reads, str) else _try(lambda: tuple(reads or ()), ())):
        if isinstance(name, str) and name and name not in out:
            out.append(name)
    for tab in _tabs(plugin, tabs):
        if tab["hook"] not in out:
            out.append(tab["hook"])
    hooks, jobs = _hooks(plugin), declared(plugin, "JOB_HOOKS")
    for name in declared(plugin, "READ_HOOKS"):
        if name in out or name not in hooks or name in jobs or not answered_by(plugin, name):
            continue
        if not _accepts(plugin, name):  # one that accepts a refusal changes something: never kept out of the log
            out.append(name)
    return tuple(out)


def _plugin_classes(plugin) -> list:
    """The library's plugin classes of its line, nearest first (its own when it is one: a record's Provider)."""
    return [c for c in _mro(plugin) if _library(c) and _is(c, _PLUGIN)]


def _class_row(cls) -> dict:
    return {"class": cls.__name__, "module": cls.__module__, "line": line_of(cls.__dict__.get("__doc__"))}


def built_on(plugin) -> dict:
    """The library class a plugin is built on, the nearest of its line, {class, module, line}; empty words for an object
    that is no plugin."""
    classes = _plugin_classes(plugin)
    return _class_row(classes[0]) if classes else {"class": "", "module": "", "line": ""}


def _standard(plugin, hooks: list[str]) -> list[dict]:
    """The standard interfaces it implements: one layer for each library class of its line whose own HOOKS there are,
    nearest first, each naming the hooks that class adds to its bases' (among the plugin's HOOKS), {class, module,
    hooks}: for a firewall Firewall's nine, MachinePlugin's five, Plugin's two."""
    layers, seen = [], set()
    for cls in reversed([c for c in _plugin_classes(plugin) if "HOOKS" in c.__dict__]):
        adds = [n for n in dict.fromkeys(_names(cls.__dict__["HOOKS"]) or ()) if n and n not in seen]
        seen.update(adds)
        layers.append({"class": cls.__name__, "module": cls.__module__, "hooks": [n for n in adds if n in hooks]})
    return layers[::-1]


def _rows(value, sizes: tuple[int, ...], needed: tuple[int, ...]) -> list[tuple[str, ...]]:
    """The sound rows of a declaration made of rows (ASKS, KEEPS): each a tuple of str of one of `sizes`, those at
    `needed` not empty, each trimmed."""
    if not isinstance(value, (tuple, list)):
        return []
    return [tuple(w.strip() for w in row) for row in value if _sound(row, sizes, needed)]


def _sound(row, sizes, needed) -> bool:
    return (isinstance(row, (tuple, list)) and len(row) in sizes and all(isinstance(w, str) for w in row)
            and all(row[i].strip() for i in needed))


def _asks(plugin) -> list[tuple[str, str, str]]:
    """What a plugin asks of other plugins, (plugin, hook, why), the first of each (plugin, hook), MAX_WORDS at most."""
    out: dict[tuple[str, str], str] = {}
    for row in _rows(_word(plugin, "ASKS")[0], (2, 3), (1,))[:MAX_WORDS]:
        out.setdefault((row[0], row[1]), row[2] if len(row) > 2 else "")
    return [(p, h, why) for (p, h), why in out.items()]


def _pair(variable: str) -> str:
    """A variable's pair in the login's store (apps/authorization.py pair_name's rule): massive-api-key."""
    return variable.strip().lower().replace("_", "-")


def _plain(value):
    """A class constant given by value when it is plain (a str, a number, a bool, or a tuple or a list of those, as a
    list); _MISSING otherwise."""
    if type(value) in (str, bool, int, float):
        return value
    if isinstance(value, (tuple, list)) and all(type(v) in (str, bool, int, float) for v in value):
        return list(value)
    return _MISSING


def _known(known) -> list | None:
    """The plugins an app knows, as a list (a mapping's values); None when it gives none."""
    if known is None:
        return None
    try:
        items = known.values() if isinstance(known, Mapping) else known
        return [p for p in list(items)[:MAX_KNOWN] if p is not None]
    except Exception:  # noqa: BLE001 - what cannot be listed is not known
        return None


def _offers(plugin, hook: str) -> bool:
    return hook in _hooks(plugin) and bool(answered_by(plugin, hook))


def _page_alone(plugin, hook: str) -> bool:
    """Whether a plugin says only its page asks `hook` (PAGE_ONLY_HOOKS), so another plugin's ask of it is refused."""
    return hook in _try(lambda: declared(plugin, PAGE_ONLY), ())


def _asked_by(plugin, others: list) -> dict[str, list[str]]:
    """For each hook of `plugin`, the plugins among `others` whose ASKS name it (by its name, or "" for whichever)."""
    me = _text(_static(plugin, "name", ""))
    out: dict[str, list[str]] = {}
    for other in others:
        name = _text(_static(other, "name", ""))
        if other is plugin or not name or name == me:
            continue
        for target, hook, _why in _try(lambda: _asks(other), []):
            if target in ("", me):
                who = out.setdefault(hook, [])
                if name not in who:
                    who.append(name)
    return out


def _here(plugin, target: str, hook: str, others: list | None) -> str:
    """What one of a plugin's asks finds among the app's plugins, in words ("" when the app gave none)."""
    if others is None:
        return ""
    if not target:  # (one its page alone asks does not count: it refuses other plugins)
        n = sum(1 for o in others if o is not plugin and _offers(o, hook) and not _page_alone(o, hook))
        return ("no plugin offers it here" if n == 0 else "1 plugin offers it here" if n == 1
                else f"{n} plugins offer it here")
    there = next((o for o in [plugin, *others] if _text(_static(o, "name", "")) == target), None)
    if there is None:
        return "not installed here"
    if not _offers(there, hook):
        return f"{target} offers no {hook} here"
    if _page_alone(there, hook):
        return f"{target} answers {hook} only from its page: it refuses other plugins"
    return "offered" if hook in declared(there, "SERVICE_HOOKS") else "a hook there, not said to be a service"


def _words(words) -> dict[str, str]:
    """The words an app is asked in (App.call_words): {plugins, clients, jobs, terms}, each a str, DOC_CHARS at most."""
    if not isinstance(words, Mapping):
        return {}
    return {k: _cut(v, DOC_CHARS) for k, v in list(words.items())[:16] if isinstance(k, str) and isinstance(v, str)}


def _calls(calls) -> dict[str, str]:
    """What the app's code calls on a plugin of this kind, {name: how} (App.CALLS[KIND]); names alone: {name: ""}."""
    if isinstance(calls, Mapping):
        return {k: v if isinstance(v, str) else "" for k, v in calls.items() if isinstance(k, str) and k}
    if isinstance(calls, (tuple, list, set, frozenset)):
        return {k: "" for k in calls if isinstance(k, str) and k}
    return {}


# -- a plugin's Internal API -----------------------------------------------------------------------------------------
def _hook_row(plugin, name: str, layer: str, ctx: types.SimpleNamespace) -> dict:
    answered = answered_by(plugin, name)
    value, where = _definition(plugin, name)
    args, params = _call(value, where is not None)
    doc = _doc(plugin, name)
    service, job, tab = name in ctx.services, name in ctx.jobs, ctx.tab_of.get(name)
    by_app = name in ctx.how or tab is not None
    kind = ("service" if service else "job" if job else "tab" if tab else "own" if name in ctx.how
            else "read" if name in ctx.reads else "change")
    askable = name in ctx.askable if ctx.askable is not None else bool(answered)
    users = ("both" if service and by_app else "plugins" if service else "app" if by_app else "named" if askable
             else "")
    plugin_alone, page_alone = name in ctx.plugin_only, name in ctx.page_only
    if plugin_alone and users in ("named", ""):  # only other plugins ask it, whether or not it says it is a service
        users = "plugins"
    return {"name": name, "args": args, "line": line_of(doc), "doc": doc_of(doc), "layer": layer, "answered": answered,
            "kind": kind, "reads": name in ctx.reads, "job": job, "cancels": name in ctx.cancels,
            "twice": [p for p in params if p.startswith("accept_")], "tab": tab["id"] if tab else "",
            "every": tab["every"] if tab else None, "how": ctx.how.get(name, ""), "users": users, "askable": askable,
            "askedBy": list(ctx.asked_by.get(name, ())), "property": _is_property(value), "pluginOnly": plugin_alone,
            "pageOnly": page_alone}


def _also_row(plugin, name: str, how: str) -> dict | None:
    value, where = _definition(plugin, name)
    if value is None:
        return None
    args, _ = _call(value, where is not None)
    doc = _doc(plugin, name)
    return {"name": name, "args": args, "line": line_of(doc), "doc": doc_of(doc), "how": how,
            "property": _is_property(value)}


def _settings(plugin) -> list[dict]:
    """Its keys (KeyVar): what the user sets for it, each read through the login by its pair's name."""
    keys = _word(plugin, "keys")[0]
    out = []
    for k in _try(lambda: list(keys or ())[:MAX_WORDS], []):
        variable = _text(_try(lambda: k.name, ""))
        if not variable:
            continue
        out.append({"variable": variable, "pair": _text(_try(lambda: k.pair, "")) or _pair(variable),
                    "label": _text(_try(lambda: k.label, "")), "secret": bool(_try(lambda: k.secret, True)),
                    "hint": _text(_try(lambda: k.hint, ""))})
    return out


def _options(plugin) -> list[str]:
    out: list[str] = []
    for attr in ("plan_vars", "options"):
        for name in _names(_word(plugin, attr)[0]) or ():
            if name and name not in out:
                out.append(name)
    return out


def _keeps(plugin) -> list[dict]:
    out: dict[str, dict] = {}
    for row in _rows(_word(plugin, "KEEPS")[0], (2,), (0,))[:MAX_WORDS]:
        out.setdefault(row[0], {"variable": row[0], "pair": _pair(row[0]), "about": row[1]})
    return list(out.values())


def _notes(value) -> list[str]:
    if not isinstance(value, (tuple, list)):
        return []
    return [_cut(n.strip(), NOTE_CHARS) for n in value if isinstance(n, str) and n.strip()][:MAX_WORDS]


def _sits_on(plugin) -> list[str]:
    """The names of what it attaches to, its `apis` (its External API tab), each once."""
    apis = _static(plugin, "apis", _MISSING)
    if apis is _MISSING:  # a property: read as the platform reads it for the External API tab
        apis = _word(plugin, "apis")[0]
    out: list[str] = []
    for api in (list(apis)[:64] if isinstance(apis, (tuple, list)) else ()):
        name = _text(_static(api, "name", ""))
        if name and name not in out:
            out.append(name)
    return out


def internal_of(plugin, *, reads=(), calls=None, askable=None, tabs=None, known=None, words=None,
                attributes=None) -> dict:
    """A plugin's Internal API, as its app's object code and its other plugins work with it (the module's docstring
    says what each part is), plain JSON:

        {"v": 1, "of": "plugin", "name", "title", "kind", "system", "pluginApi",
         "builtOn": {class, module, line}, "chain": [{class, module, line}, ...], "sitsOn": [api names],
         "standard": [{class, module, hooks: [names]}, ...], "calls": {plugins, clients, jobs, terms},
         "hooks": [{name, args, line, doc, layer, answered, kind, reads, job, cancels, twice, tab, every, how, users,
                    askable, askedBy, property, pluginOnly, pageOnly}, ...],
         "counts": {hooks, answered, standard, own, left, kinds: {read, tab, change, job, service, own}},
         "left": [names], "also": [{name, args, line, doc, how, property}], "attributes": [names], "declares": {...},
         "tabs": [{id, title, hook, every}], "settings": [{variable, pair, label, secret, hint}], "options": [names],
         "keeps": [{variable, pair, about}], "asks": [{plugin, hook, why, here}], "steps": [names], "notes": [lines]}

    What the app says, each optional: `reads`, the hooks it asks as reads (App.READ_HOOKS); `calls`, what its code calls
    on a plugin of this kind, {name: how} (App.CALLS[KIND]): a name among HOOKS gives that hook its `how`, one outside
    them that the plugin has is an `also` row; `askable`, the hooks it asks by name for its page or a client (None:
    every hook the plugin answers, as the frame's ask does); `tabs`, its own list of the plugin's tabs (else the
    plugin's TABS); `known`, its plugins, which `askedBy` and the asks' `here` are read from (None: not said); `words`,
    how it is asked for this plugin (App.call_words), carried as `calls`; `attributes`, what it reads of the plugin by
    name (App.ATTRIBUTES[KIND]), listed by name and never read, the class constants among them (CONSTANTS, all of them
    when it names none) given by value as `declares`.

    A hook's `kind` is the first that holds: "service" (SERVICE_HOOKS), "job" (JOB_HOOKS), "tab" (a tab's hook), "own"
    (the app's code calls it: `calls`), "read" (reads_of), else "change"; and `users` the first that holds: "both" (a
    service the app's code or a tab uses too), "plugins" (a service), "app" (`calls` or a tab), "named" (`askable`), ""
    (nothing here uses it). `counts.kinds` counts the hooks it answers. `pluginOnly` and `pageOnly` say whether the
    hook is among its PLUGIN_ONLY_HOOKS or its PAGE_ONLY_HOOKS; a hook only other plugins ask is used by "plugins"
    where it would be "named" or "". Nothing of the plugin is called or evaluated."""
    out: dict = {"v": VERSION, "of": "plugin", "name": "", "title": "", "kind": "", "system": "", "pluginApi": "",
                 "builtOn": {"class": "", "module": "", "line": ""}, "chain": [], "sitsOn": [], "standard": [],
                 "calls": {}, "hooks": [], "counts": {"hooks": 0, "answered": 0, "standard": 0, "own": 0, "left": 0,
                                                      "kinds": {k: 0 for k in KINDS}},
                 "left": [], "also": [], "attributes": [], "declares": {}, "tabs": [], "settings": [], "options": [],
                 "keeps": [], "asks": [], "steps": [], "notes": []}
    for key, attr in (("name", "name"), ("title", "title"), ("kind", "KIND"), ("system", "SYSTEM")):
        out[key] = _text(_static(plugin, attr, ""))
    if tabs is not None and not isinstance(tabs, (tuple, list)):  # listed once: its tabs and its reads both read them
        given = tabs
        tabs = _try(lambda: [] if isinstance(given, (str, bytes, Mapping)) else list(given), [])
    api = _static(plugin, "api", "")
    out["pluginApi"] = api if isinstance(api, str) else str(api) if type(api) in (int, float) else ""
    classes = _try(lambda: _plugin_classes(plugin), [])
    if classes:
        out["builtOn"] = _class_row(classes[0])
        out["chain"] = [_class_row(c) for c in classes]
    hooks = _try(lambda: _hooks(plugin), [])
    out["standard"] = standard = _try(lambda: _standard(plugin, hooks), [])
    layer_of = {n: layer["class"] for layer in standard for n in layer["hooks"]}
    order = [*layer_of, *(n for n in hooks if n not in layer_of)][:MAX_HOOKS]
    out["tabs"] = _try(lambda: _tabs(plugin, tabs), [])
    others = _known(known)
    ctx = types.SimpleNamespace(
        services=set(_try(lambda: declared(plugin, "SERVICE_HOOKS"), ())),
        jobs=set(_try(lambda: declared(plugin, "JOB_HOOKS"), ())),
        cancels=set(_try(lambda: declared(plugin, "CANCEL_HOOKS"), ())),
        plugin_only=set(_try(lambda: declared(plugin, PLUGIN_ONLY), ())),
        page_only=set(_try(lambda: declared(plugin, PAGE_ONLY), ())),
        tab_of={t["hook"]: t for t in reversed(out["tabs"])},
        reads=set(_try(lambda: reads_of(plugin, reads, tabs), ())), how=_try(lambda: _calls(calls), {}),
        askable=None if askable is None else set(_try(lambda: _strs(askable), [])),
        asked_by=_try(lambda: _asked_by(plugin, others), {}) if others is not None else {})
    rows = [row for row in (_try(lambda: _hook_row(plugin, n, layer_of.get(n, ""), ctx), None) for n in order) if row]
    out["hooks"] = rows
    gone = {r["name"] for r in rows if not r["answered"]}
    out["left"] = [n for n in order if n in gone]
    out["counts"] = {"hooks": len(rows), "answered": len(rows) - len(gone),
                     "standard": sum(1 for r in rows if r["layer"]), "own": sum(1 for r in rows if not r["layer"]),
                     "left": len(gone), "kinds": {k: sum(1 for r in rows if r["answered"] and r["kind"] == k)
                                                  for k in KINDS}}
    named = set(hooks)
    out["also"] = [row for row in (_try(lambda: _also_row(plugin, n, h), None) for n, h in ctx.how.items()
                                   if n not in named) if row]
    wanted = _try(lambda: _strs(attributes), []) if attributes is not None else []
    out["attributes"] = wanted
    for name in ([c for c in CONSTANTS if c in wanted] if wanted else CONSTANTS):
        value = _plain(_static(plugin, name, _MISSING))
        if value is not _MISSING:
            out["declares"][name] = value
    out["sitsOn"] = _try(lambda: _sits_on(plugin), [])
    out["calls"] = _try(lambda: _words(words), {})
    out["settings"] = _try(lambda: _settings(plugin), [])
    out["options"] = _try(lambda: _options(plugin), [])
    out["keeps"] = _try(lambda: _keeps(plugin), [])
    out["asks"] = _try(lambda: [{"plugin": p, "hook": h, "why": why, "here": _here(plugin, p, h, others)}
                                for p, h, why in _asks(plugin)], [])
    steps = _word(plugin, "STEPS")[0]
    out["steps"] = [s for s in steps if isinstance(s, str)][:MAX_HOOKS] if isinstance(steps, (tuple, list)) else []
    out["notes"] = _notes(_word(plugin, "INTERNAL_NOTES")[0])
    return out


def problems(plugin) -> list[str]:
    """What is wrong with what a plugin says of the interface it shares, in words, each naming it (`plugin 'name'`):
    empty when it is sound, as a plugin's own test asserts (internal.problems(MACHINE) == []). A declaration of hooks'
    names that is not a tuple of str, or names one outside its HOOKS; a read that is one of its jobs or takes an
    `accept_*` argument (a refusal's second ask belongs to a change); a hook of its own package's whose docstring says
    nothing (its first sentence is the hook's line on the tab), or one its HOOKS names and nothing defines; a row of
    ASKS or KEEPS of the wrong shape, or given twice; notes too long; a tab whose hook is not among its HOOKS. Of who
    may ask a hook: a hook both PLUGIN_ONLY_HOOKS and PAGE_ONLY_HOOKS name (no one could ask it), a service only its
    page asks, a tab whose hook only other plugins ask (a tab is its page's). A plugin that says neither word gets none
    of these. Nothing of the plugin is called."""
    tag = f"plugin {_text(_static(plugin, 'name', ''))!r}"
    out: list[str] = []
    if _names(_static(plugin, "HOOKS", ())) is None:
        out.append(f"{tag}: HOOKS must be a tuple of str")
    hooks = _try(lambda: _hooks(plugin), [])
    for attr in DECLARED:
        values, failed = _values(plugin, attr)
        if failed:
            out.append(f"{tag}: {attr} cannot be read ({failed})")
        if any(_names(v) is None for v in values):
            out.append(f"{tag}: {attr} must be a tuple of str")
    reads, services, jobs = (declared(plugin, a) for a in ("READ_HOOKS", "SERVICE_HOOKS", "JOB_HOOKS"))
    out += [f"{tag}: READ_HOOKS names {n!r}, which is not among its HOOKS" for n in reads if n not in hooks]
    out += [f"{tag}: SERVICE_HOOKS names {n!r}, which is not among its HOOKS" for n in services if n not in hooks]
    by_plugins, by_page = declared(plugin, PLUGIN_ONLY), declared(plugin, PAGE_ONLY)
    out += [f"{tag}: {PLUGIN_ONLY} names {n!r}, which is not among its HOOKS" for n in by_plugins if n not in hooks]
    out += [f"{tag}: {PAGE_ONLY} names {n!r}, which is not among its HOOKS" for n in by_page if n not in hooks]
    out += [f"{tag}: {n!r} is said to be asked only by other plugins ({PLUGIN_ONLY}) and only from its page "
            f"({PAGE_ONLY}): no one could ask it" for n in by_plugins if n in by_page]
    out += [f"{tag}: {n!r} is a service other plugins ask (SERVICE_HOOKS), yet only its page may ask it ({PAGE_ONLY})"
            for n in services if n in by_page]
    for name in reads:
        if name in jobs:
            out.append(f"{tag}: {name!r} is said to only read (READ_HOOKS) and is one of its jobs")
        accept = _accepts(plugin, name)
        if accept:
            out.append(f"{tag}: {name!r} is said to only read (READ_HOOKS) yet takes {accept!r}: an argument that "
                       "accepts a refusal belongs to a change")
    for name in hooks:
        if _definition(plugin, name)[0] is None:
            out.append(f"{tag}: HOOKS names {name!r}, which nothing of it defines")
        elif answered_by(plugin, name) == "itself" and not line_of(_doc(plugin, name)):
            out.append(f"{tag}: hook {name!r} says nothing of itself: the first sentence of its docstring is its line "
                       "on the Internal API tab")
    out += _row_problems(plugin, tag, "ASKS", (2, 3), (1,), "(plugin, hook) or (plugin, hook, why)")
    out += _row_problems(plugin, tag, "KEEPS", (2,), (0,), "(variable, about)")
    notes, failed = _word(plugin, "INTERNAL_NOTES")
    if failed:
        out.append(f"{tag}: INTERNAL_NOTES cannot be read ({failed})")
    elif notes is not None:
        if not isinstance(notes, (tuple, list)) or any(not isinstance(n, str) or len(n) > NOTE_CHARS for n in notes):
            out.append(f"{tag}: INTERNAL_NOTES is a tuple of lines of at most {NOTE_CHARS} characters")
        elif len(notes) > MAX_WORDS:
            out.append(f"{tag}: INTERNAL_NOTES holds {len(notes)} lines: the first {MAX_WORDS} are read")
    for tab in _tabs(plugin):
        if tab["hook"] not in hooks:
            out.append(f"{tag}: tab {tab['id']!r}: its hook {tab['hook']!r} is not a hook")
        elif tab["hook"] in by_plugins:
            out.append(f"{tag}: tab {tab['id']!r}: its hook {tab['hook']!r} is asked only by other plugins "
                       f"({PLUGIN_ONLY}), yet its page asks a tab's hook")
    return out


def _row_problems(plugin, tag: str, attr: str, sizes, needed, shape: str) -> list[str]:
    value, failed = _word(plugin, attr)
    if failed:
        return [f"{tag}: {attr} cannot be read ({failed})"]
    if value is None:
        return []
    if not isinstance(value, (tuple, list)):
        return [f"{tag}: {attr} is a tuple of rows, each {shape}"]
    out, seen = [], set()
    for row in value:
        if not _sound(row, sizes, needed):
            shown = repr(row)
            out.append(f"{tag}: {attr}: {_cut(shown, 120)} is not {shape}, each a str")
            continue
        key = (row[0].strip(), row[1].strip()) if attr == "ASKS" else row[0].strip()
        if key in seen:
            said = f"{tag}: {attr}: {key!r} given twice"
            if said not in out:
                out.append(said)
        seen.add(key)
    if len(value) > MAX_WORDS:
        out.append(f"{tag}: {attr} holds {len(value)} rows: the first {MAX_WORDS} are read")
    return out


# -- an app's Internal API -------------------------------------------------------------------------------------------
def _route_parts(row):
    """A row of a routes table as its five parts (method, path, about, kind, who), kind and who as given (None when it
    gives none); None for what is not a row: a tuple (method, path, about[, kind[, who]]) or a mapping of those keys."""
    if isinstance(row, Mapping):
        parts = [row.get(k) for k in ("method", "path", "about", "kind", "who")]
    elif isinstance(row, (tuple, list)) and 3 <= len(row) <= 5:
        parts = [*row, None, None][:5]
    else:
        return None
    method, path, about = parts[:3]
    if not (isinstance(method, str) and method and isinstance(path, str) and path.startswith("/")
            and isinstance(about, str)):
        return None
    return [method.upper(), path, about, parts[3], parts[4]]


def _route(row) -> dict | None:
    """A row of a routes table as {method, path, about, kind, who}: kind a GET's "read" and any other method's "change"
    unless it says one of ROUTE_KINDS (as App.classify reads a request), who "page" unless it says one of ROUTE_WHO."""
    parts = _route_parts(row)
    if parts is None:
        return None
    method, path, about, kind, who = parts
    kind = kind if isinstance(kind, str) and kind in ROUTE_KINDS else "read" if method == "GET" else "change"
    return {"method": method, "path": path, "about": about, "kind": kind,
            "who": who if isinstance(who, str) and who in ROUTE_WHO else "page"}


def _rows_of(value) -> list:
    if isinstance(value, (str, bytes, Mapping)) or value is None:
        return []
    return _try(lambda: list(value)[:400], [])


def _app_routes(app, inherits: bool) -> list[dict]:
    """Its routes: its own (App.routes(), else its ROUTES), then the frame's, then those of the login it inherits; each
    (method, path) once, its own first."""
    get = _try(lambda: getattr(app, "routes", None), None)
    own = _try(get, ()) if callable(get) else _static(app, "ROUTES", ())
    out, seen = [], set()
    for rows, mine in ((_rows_of(own), True), (FRAME_ROUTES, False), (LOGIN_ROUTES if inherits else (), False)):
        for row in rows:
            route = _route(row)
            if route is None or (route["method"], route["path"]) in seen:
                continue
            seen.add((route["method"], route["path"]))
            out.append({**route, "own": mine})
    return out


def _method_rows(obj, names) -> list[dict]:
    out = []
    for name in names:
        value, where = _definition(obj, name)
        if value is None:
            continue
        args, _ = _call(value, where is not None)
        out.append({"name": name, "args": args, "line": line_of(_doc(obj, name)),
                    "property": _is_property(value)})
    return out


def _lends(app) -> dict | None:
    """The login it lends its plugins: whether it notes what they read and keep there (TRACE_LOGIN), and the interface
    a login is (the library's Login, by name), its public methods with a line each."""
    login = _own(app).get("login")
    if login is None:
        return None
    cls = next((c for c in _mro(login) if c.__module__ == _LOGIN[0] and c.__name__ == _LOGIN[1]), type(login))
    names = [n for n, v in cls.__dict__.items() if not n.startswith("_") and (callable(v) or _is_property(v))]
    return {"traced": bool(_static(app, "TRACE_LOGIN", False)), "kind": type(login).__name__,
            "interface": _method_rows(cls, names)}


def _includes(app) -> list[dict]:
    """The login it includes (1.52.0: an object of the login class, made for it in its process), if it declares one.
    `variable` is the switch that turns it off (LOGIN_VAR, else LOGIN_URL_VAR); while it is off, the one that says so,
    its words quoted (App.inherits_login's "none" or "off")."""
    if not (_static(app, "LOGIN", False) or _static(app, "LOGIN_URL", "")):
        return []
    prefix = (_text(getattr(sys.modules.get(_FRAME), "LOGIN_PREFIX", "")) or "/login").rstrip("/") + "/"
    cls = _static(app, "LOGIN_CLASS", "")
    named = cls if isinstance(cls, str) else f"{getattr(cls, '__module__', '')}:{getattr(cls, '__qualname__', '')}"
    switches = [v for v in (_text(_static(app, "LOGIN_VAR", "")), _text(_static(app, "LOGIN_URL_VAR", ""))) if v]
    variable = switches[0] if switches else ""
    on = _try(lambda: bool(app.inherits_login()), False)
    how = (f"an object of the login class, made for it here in its process: its page and its API under {prefix} at "
           "its own port, its tray at /api/trays, the pairs its plugins ask for asked of it; nothing is started for it "
           "and it has no port of its own")
    said = [(v, (os.environ.get(v) or "").strip()) for v in switches] if not on else []
    off = next(((v, w) for v, w in said if w.lower() in ("none", "off")), None)
    if off is not None:
        variable = off[0]
        how += f" (off here: {off[0]} says {off[1]!r})"
    return [{"name": "login", "on": on, "prefix": prefix, "variable": variable, "class": named, "how": how}]


def _linked(app) -> list[dict]:
    out = []
    for row in _rows_of(_static(app, "LINKED", ()))[:MAX_WORDS]:
        if isinstance(row, (tuple, list)) and 2 <= len(row) <= 4 and all(isinstance(w, str) for w in row):
            name, how, variable, prefix = (*row, "", "")[:4]
            out.append({"name": name, "how": how, "variable": variable, "prefix": prefix})
    return out


def _app_plugins(app) -> list:
    """The plugins it knows (App.known_plugins(), else those attached)."""
    get = _try(lambda: getattr(app, "known_plugins", None), None)
    found = _try(get, None) if callable(get) else None
    if found is None:
        found = _own(app).get("_plugins")
    return _known(found) or []


class _Named:
    """A plugin seen under the name NAME, every other attribute read of the plugin itself (isinstance holds of it as of
    the plugin): asked of it, an app's words for one plugin (App.call_words) say NAME wherever they name the plugin,
    with nothing replaced in them afterwards, so no other part of them is taken for its name."""

    __slots__ = ("_plugin",)

    def __init__(self, plugin) -> None:
        object.__setattr__(self, "_plugin", plugin)

    @property
    def __class__(self):  # isinstance(it, MachinePlugin) holds as it does of the plugin
        return type(object.__getattribute__(self, "_plugin"))

    def __getattr__(self, attr: str):
        if attr == "name":
            return NAME
        return getattr(object.__getattribute__(self, "_plugin"), attr)


def app_internal(app) -> dict:
    """An app's own Internal API, its object code's side (the module's docstring says what each part is), plain JSON:

        {"v": 1, "of": "app", "name", "title", "icon", "api", "port", "portVar", "url", "pluginApi", "login",
         "calls": {KIND: {name: how}}, "attributes": {KIND: [names]}, "words": {KIND: {plugins, clients, jobs, terms}},
         "reads": [names], "methods": [{name, args, line, property}], "offers": [{name, args, line, property}],
         "lends": {traced, kind, interface: [{name, args, line, property}]} or None,
         "routes": [{method, path, about, kind, who, own}], "includes": [{name, on, prefix, variable, class, how}],
         "linked": [{name, how, variable, prefix}], "plugins": [{name, title, kind, system, pluginApi, attached,
         builtOn}], "counts": {routes, own, plugins}, "notes": [lines]}

    `words` are the app's (App.call_words) for one plugin of each kind it knows, asked of that plugin seen under the
    name NAME (every other attribute its own), so they say NAME where they name it. `pluginApi` is the registry's
    PLUGIN_API when the registry is loaded already (it is never imported here). Nothing of a plugin is asked, and
    nothing is imported."""
    out: dict = {"v": VERSION, "of": "app", "name": "", "title": "", "icon": "", "api": "", "port": None, "portVar": "",
                 "url": "", "pluginApi": "", "login": None, "calls": {}, "attributes": {}, "words": {}, "reads": [],
                 "methods": [], "offers": [], "lends": None, "routes": [], "includes": [], "linked": [],
                 "plugins": [], "counts": {"routes": 0, "own": 0, "plugins": 0}, "notes": []}
    for key, attr in (("name", "NAME"), ("title", "TITLE"), ("icon", "ICON"), ("api", "API"), ("portVar", "PORT_VAR")):
        out[key] = _text(_static(app, attr, ""))
    port = _try(lambda: app.port(), None)
    out["port"] = port if type(port) is int else None
    out["url"] = _text(_own(app).get("served")) or _text(_try(lambda: app.url(), ""))
    out["pluginApi"] = _text(getattr(sys.modules.get(_REGISTRY), "PLUGIN_API", ""))
    said = _try(lambda: _own(app).get("login").describe(), None) if _own(app).get("login") is not None else None
    if isinstance(said, Mapping):
        out["login"] = {k: v for k, v in said.items()
                        if isinstance(k, str) and (v is None or type(v) in (str, bool, int))}
    calls = _static(app, "CALLS", {})
    if isinstance(calls, Mapping):
        out["calls"] = {k: _calls(v) for k, v in calls.items() if isinstance(k, str) and isinstance(v, Mapping)}
    attributes = _static(app, "ATTRIBUTES", {})
    if isinstance(attributes, Mapping):
        out["attributes"] = {k: list(_names(v) or ()) for k, v in attributes.items() if isinstance(k, str)}
    plugins = _try(lambda: _app_plugins(app), [])
    kinds = list(dict.fromkeys([*out["calls"], *out["attributes"],
                                *(_text(_static(p, "KIND", "")) for p in plugins)]))
    say = _try(lambda: getattr(app, "call_words", None), None)
    for kind in (k for k in kinds if k and callable(say)):
        example = next((p for p in plugins if _text(_static(p, "KIND", "")) == kind), None)
        if example is None:
            continue
        words = _words(_try(lambda: say(_Named(example)), None))
        if words:
            out["words"][kind] = words
    out["reads"] = list(_names(_static(app, "READ_HOOKS", ())) or ())
    out["methods"] = _try(lambda: _method_rows(app, APP_METHODS), [])
    out["offers"] = _try(lambda: _method_rows(app, OFFERS), [])
    out["lends"] = _try(lambda: _lends(app), None)
    inherits = _try(lambda: bool(app.inherits_login()), False)
    out["routes"] = _try(lambda: _app_routes(app, inherits), [])
    out["includes"] = _try(lambda: _includes(app), [])
    out["linked"] = _try(lambda: _linked(app), [])
    out["plugins"] = [{"name": _text(_static(p, "name", "")), "title": _text(_static(p, "title", "")),
                       "kind": _text(_static(p, "KIND", "")), "system": _text(_static(p, "SYSTEM", "")),
                       "pluginApi": _text(_static(p, "api", "")), "attached": _static(p, "app") is app,
                       "builtOn": _try(lambda: built_on(p), {"class": "", "module": "", "line": ""})} for p in plugins]
    out["counts"] = {"routes": len(out["routes"]), "own": sum(1 for r in out["routes"] if r["own"]),
                     "plugins": len(out["plugins"])}
    out["notes"] = _notes(_static(app, "INTERNAL_NOTES", ()))
    return out


# -- a table of routes held to its code ------------------------------------------------------------------------------
def _path_like(text) -> bool:
    return (isinstance(text, str) and text.startswith("/api/") and text != "/api/" and len(text) <= 200
            and not any(c.isspace() for c in text))


def literals_in(*sources: str) -> set[str]:
    """The paths a source names: its "/api/..." string literals (a constant's too, when the source is its whole module;
    the bare "/api/" left out), and its lists of a path's parts, ["", "api", "plugins", "plan"] as "/api/plugins/plan"
    (the data API's writes). A source that is not Python (or a part of one that cannot be parsed alone) is read for
    quoted paths instead."""
    out: set[str] = set()
    for source in sources:
        text = textwrap.dedent(source or "")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            out |= {m for m in _QUOTED.findall(text) if _path_like(m)}
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and _path_like(node.value):
                out.add(node.value)
            elif (isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) >= 3
                  and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts)):
                parts = [e.value for e in node.elts]
                if parts[0] == "" and parts[1] == "api" and _path_like("/".join(parts)):
                    out.add("/".join(parts))
    return out


def _continues(path: str, literal: str) -> bool:
    """Whether a path is a literal's, or one under it (/api/machines/{name} under /api/machines/ and /api/machines)."""
    return path == literal or path.startswith(literal if literal.endswith("/") else literal + "/")


def route_problems(routes, literals) -> list[str]:
    """A table of routes (rows as FRAME_ROUTES') held to the code answering them (`literals`: literals_in of its
    source), in words, empty when they agree: a literal path (but the bare "/api/") that no row is, or is under; an
    /api/ row whose path, up to its first "{", is no literal's nor under one; a row that is not one, given twice, or
    whose method, class or caller is not one of ROUTE_METHODS, ROUTE_KINDS or ROUTE_WHO. What a chain tells apart below
    a literal (an action word, a path's later parts) is not seen."""
    out, rows, seen = [], [], set()
    for row in _rows_of(routes):
        parts = _route_parts(row)
        if parts is None:
            out.append(f"the table's row {_cut(repr(row), 120)} is not (method, path, about[, kind[, who]])")
            continue
        method, path, _about, kind, who = parts
        if (method, path) in seen:
            out.append(f"the table lists {method} {path} twice")
        seen.add((method, path))
        if method not in ROUTE_METHODS:
            out.append(f"the table's {method} {path}: its method is not one of {', '.join(ROUTE_METHODS)}")
        if kind is not None and kind not in ROUTE_KINDS:
            out.append(f"the table's {method} {path}: its class {kind!r} is not one of {', '.join(ROUTE_KINDS)}")
        if who is not None and who not in ROUTE_WHO:
            out.append(f"the table's {method} {path}: who asks it, {who!r}, is not one of {', '.join(ROUTE_WHO)}")
        rows.append((method, path))
    paths = sorted({p for p in _rows_of(literals) if _path_like(p)})
    for literal in paths:
        if not any(_continues(path, literal) for _m, path in rows):
            out.append(f"the code answers {literal}, which the table does not list")
    for method, path in rows:
        if path.startswith("/api/") and not any(_continues(path.split("{", 1)[0], lit) for lit in paths):
            out.append(f"the table lists {method} {path}, which the code does not answer")
    return out
