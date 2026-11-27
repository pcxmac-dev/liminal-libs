"""Who asks a hook: the app's page, or the plugin that asks. The user, 2026-11-18: "now i need an MCP plugin for
platform, basically a protocol plugin that mediates MCP connections to resources by local AI agents". Such a plugin
has hooks only its page may ask (a decision, a grant) and hooks only another plugin may ask (a token for that plugin's
own agent). It says which in two words of its class, PAGE_ONLY_HOOKS and PLUGIN_ONLY_HOOKS (liminal_libs.internal
reads them), and this module holds an ask to them.

The asker is handed over in so many words, by whoever hands a hook its call:
- an app's route for its page sets PAGE ("page") around the hook it calls: `with asking(PAGE): ...`;
- App.ask, and the platform's own ask, set the plugin that asks (as traffic.actor names it), for that call alone;
- a job reads the asker where it is started and sets it inside its own thread from that record (`handed`).

It is never taken from what a thread happens to inherit. Python 3.14 can start a thread in a copy of its starter's
context (threading.Thread(context=...), and sys.flags.thread_inherit_context, on by default in free-threaded builds);
3.12 and 3.13 never do. So the asker is kept in a context variable together with a mark of the thread that set it.
The context variable keeps an async task's ask its own; the mark keeps every other thread out. A thread that is not
handed an asker has none, on every Python the project runs.

An unset asker is neither the page nor a plugin. A gated hook asked with none is refused, in words (`refusal`,
`check`).

Closed by default (1.107.0; the user, 2026-11-26: "Yes, closed by default"): a hook a plugin answers and declares for
no one is its page's alone, exactly as if PAGE_ONLY_HOOKS named it (internal.closed, internal.page_alone). It declares
a hook a read anyone here may ask (READ_HOOKS, or a tab of its own), or one other plugins ask through the app
(SERVICE_HOOKS); those are never refused here, as before. So a plugin written before this still has its page, which
asks as the page; another plugin's ask, and an ask that names no one, of a hook it never declared is refused in words
that say how it is declared. The contract itself holds an ask by name to the default too (Plugin.ask: `check_closed`),
so an app that asks a plugin without this module's `check` cannot leave it open.

Plain: the standard library and liminal_libs.internal, which is plain too."""
from __future__ import annotations

import contextlib
import contextvars
import functools
import threading
from collections.abc import Callable, Iterator

from .. import internal

PAGE = "page"  # the asker of a request from the app's page, and of a job that request started
_NOW = object()  # refusal's and check's default: the asker of this moment
# how a hook left undeclared is declared, said in its refusal (the closed default, 1.107.0)
UNDECLARED = ("A read anyone on this machine may ask is named in its READ_HOOKS, one other plugins ask through the "
              "app in its SERVICE_HOOKS.")
_HELD: contextvars.ContextVar[tuple[str | None, object] | None] = contextvars.ContextVar("liminal_asker", default=None)
_THREAD = threading.local()  # each thread's own mark (`_mark`)


class AskRefused(PermissionError):
    """A gated hook asked by an asker it does not take. Its words name the plugin, the hook and who asked; `asker` is
    None when no one was named. `status` is what an app answers over HTTP: 403."""

    status = 403

    def __init__(self, words: str, *, plugin: str = "", hook: str = "", asker: str | None = None) -> None:
        super().__init__(words)
        self.words, self.plugin, self.hook, self.asker = words, plugin, hook, asker


def _mark() -> object:
    """This thread's own mark: made for it when it is first asked for, and never another thread's."""
    try:
        return _THREAD.mark
    except AttributeError:
        mark = _THREAD.mark = object()
        return mark


def asker() -> str | None:
    """Who asks the hook being answered here: PAGE, the name of the plugin that asks, or None. None when no one was
    named in this thread: one that was handed no asker, or code that sets none."""
    held = _HELD.get()
    return held[0] if held is not None and held[1] is _mark() else None


@contextlib.contextmanager
def asking(who: str | None) -> Iterator[str | None]:
    """The asker for the block, in this thread alone, put back as it was after the block. `who` is PAGE, a plugin's
    name, or None (no one: a block that must not carry an asker sets that). Anything else is a ValueError."""
    if who is not None and not (isinstance(who, str) and who):
        raise ValueError(f"an asker is {PAGE!r}, a plugin's name or None, not {who!r}")
    token = _HELD.set((who, _mark()))
    try:
        yield who
    finally:
        _HELD.reset(token)


def handed(target: Callable) -> Callable:
    """`target`, carrying the asker of this moment to whatever thread runs it: a job's hand-over, in so many words.
    The asker is read now, where the job is started. Each run of `target` has it set, in the thread that runs it, and
    put back after."""
    who = asker()

    @functools.wraps(target)
    def run(*args, **kwargs):
        with asking(who):
            return target(*args, **kwargs)

    return run


def _name(plugin) -> str:
    try:
        name = getattr(plugin, "name", "")
    except Exception:  # noqa: BLE001 - a plugin that cannot say its name is said as one
        name = ""
    return name if isinstance(name, str) and name else "a plugin"


def refusal(plugin, hook: str, who=_NOW) -> str:
    """Why `who` may not ask `plugin`'s `hook`, in words; "" when it may. `who` is the asker of this moment unless
    given. One in PLUGIN_ONLY_HOOKS takes another plugin's ask alone: never the page's, its own plugin's or no
    one's. One in PAGE_ONLY_HOOKS takes the page's alone. One in both takes no one's. A hook it declares a read
    (READ_HOOKS, a tab of its own), a service (SERVICE_HOOKS) or its route's (RPC_HOOK) is never refused. Any other
    hook it answers is closed by default (1.107.0): the page's alone, as one in PAGE_ONLY_HOOKS, in words that say it
    was never declared. When a word cannot be read, every hook of that plugin is refused (internal.problems says
    why)."""
    who = asker() if who is _NOW else who
    try:
        by_plugins, by_page = internal.plugin_only(plugin), internal.page_alone(plugin)
        default = hook in by_page and hook in internal.closed(plugin)
    except ValueError as e:
        return f"{_name(plugin)}: who may ask its hooks cannot be read ({e}), so it is asked nothing"
    plugins_only, page_only = hook in by_plugins, hook in by_page
    if not (plugins_only or page_only):
        return ""
    name = _name(plugin)
    said = f"{name}'s {hook}"
    nobody = "This ask names no asker: neither the page nor a plugin."
    if plugins_only and page_only:
        return f"{said} is said to be asked only by other plugins and only from its page, so no one can ask it."
    if page_only:
        if who == PAGE:
            return ""
        if default:
            asked = nobody if who is None else f"{who} asked it."
            return f"{said} is asked only from its page: {name} declares it for no one else. {UNDECLARED} {asked}"
        if who is None:
            return f"{said} is asked only from its page. {nobody}"
        return f"{said} is asked only from its page, never by another plugin: {who} asked it."
    if who is None:
        return f"{said} is asked only by another plugin. {nobody}"
    if who == PAGE:
        return f"{said} is asked only by another plugin, never from a page or by a program."
    if who == name:
        return f"{said} is asked only by another plugin, not by {name} itself."
    return ""


def check_closed(plugin, hook: str, who=_NOW) -> None:
    """The closed default alone, held by the contract itself (Plugin.ask): an AskRefused when `hook` is one `plugin`
    answers and declares for no one (internal.closed) and `who` (the asker of this moment unless given) is not the
    page, or when its words cannot be read; nothing otherwise. What its words do declare (PLUGIN_ONLY_HOOKS,
    PAGE_ONLY_HOOKS) is the app's to hold, with `check`, as before."""
    who = asker() if who is _NOW else who
    if who == PAGE:
        return
    try:
        left = hook in internal.closed(plugin)
    except ValueError:
        left = True
    if left:
        raise AskRefused(refusal(plugin, hook, who), plugin=_name(plugin), hook=hook, asker=who)


def check(plugin, hook: str, who=_NOW) -> None:
    """`refusal` raised as an AskRefused when there is one; nothing when `who` (the asker of this moment unless given)
    may ask `plugin`'s `hook`."""
    who = asker() if who is _NOW else who
    words = refusal(plugin, hook, who)
    if words:
        raise AskRefused(words, plugin=_name(plugin), hook=hook, asker=who)
