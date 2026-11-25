"""Plugins and apps as liminal-net nodes, told to end and asked what they are (1.86.0, Monday list item 38).

The user, 2026-11-24: "replace that with a command that inherits the node class, and is able to attach to a plugin,
and send a 'kill' signal graceful, force, etc..."; "all plugins, need a login-app class attached/inherited"; "make
sure that all plugins can be started and terminated in a timely fashion and safe".

A plugin is served as a node (NETWORK.md §4.9: a Python object is a node's code) by PluginHillock: its interface is
its hooks (each with the signature its page shows) and the lifecycle's three requests, which any node may send:
- `term(timeout)`: TERM, graceful: what it is doing finished, its data secured, its claims given back, what it started
  ended with its trees (TERM, KILL at its STOP_DEADLINE_S); then the node ends;
- `kill()`: KILL, forced: what it started ended with its trees now; then the node ends (its process too, when the
  node is a process of its own);
- `ask(what)`: status, interface, apis, needs, mode (its mode and deadlines), processes, node: read only.
It fires `lifecycle` (a stream signal: {"stage", "signal", "why"}) as it ends, to every node linked for it.

A plugin node is on demand (lifecycle.ON_DEMAND, the only mode allowed): started when reached (`launcher`, by
lifecycle.spawn, written in the ledger), ended by liminal-net when nobody has been attached for its grace, its data
secured first (`shutdown`). The plugin is attached to the node's own app, and holds that app's login, as every plugin.
A start that misses the plugin's START_DEADLINE_S is reported and what was started for it ended with its tree
(reach_or_start).

Why requests and not signals: liminal-net's signals (idl.SignalKind: state, stream) go out along a node's axon to the
nodes linked for them; nothing sends one *to* a node. TERM, KILL and ASK are what a node is asked, so they are methods
of its interface, and `lifecycle` is the signal it gives as it ends.
"""
from __future__ import annotations

import inspect
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from . import lifecycle
from .lifecycle import Signal

TRAIT = "liminal.PluginNode"
APP_TRAIT = "liminal.AppNode"
LIFECYCLE_METHODS = {
    "term": {"args": [{"name": "timeout", "type": "float|null", "default": None}], "returns": "map",
             "signature": "(timeout=None)"},
    "kill": {"args": [], "returns": "map", "signature": "()"},
    "ask": {"args": [{"name": "what", "type": "text"}], "returns": "map", "signature": "(what)"},
}
SIGNALS = {"lifecycle": {"kind": "stream", "data": "map"}}
ASKS = ("status", "interface", "apis", "needs", "mode", "processes", "node")
KILL_EXIT = 137  # a node process's exit after KILL (128 + 9, as Linux says it)


def node_name(plugin: str) -> str:
    """A plugin's node, by its name: plugin-<name>."""
    return f"plugin-{plugin}"


def app_node_name(app: str) -> str:
    """An app's node: app-<name> (login, platform, charts, integrator)."""
    return f"app-{app}"


def default_scope() -> Path:
    """The scope every Liminal node of this machine is reached in: the data folder (layout.data_dir)."""
    from . import layout

    return layout.data_dir()


def _arg(param: inspect.Parameter) -> dict | None:
    if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
        return None
    out: dict = {"name": param.name, "type": "any"}
    if param.default is not param.empty:
        if param.default is None or isinstance(param.default, (bool, int, float, str)):
            out["default"] = param.default
        else:
            out["default"] = None
    return out


def interface_of(plugin) -> dict:
    """A plugin's node interface (NETWORK.md §6): each hook it answers, with the signature its page shows, then the
    lifecycle's requests (term, kill, ask) and its `lifecycle` signal."""
    kind = getattr(plugin, "KIND", "") or "plugin"
    methods: dict[str, dict] = {}
    for hook, signature in (plugin.interface().get("hooks") or {}).items():
        if hook in LIFECYCLE_METHODS:
            continue
        given = plugin.__dict__.get(hook) if hook in getattr(plugin, "__dict__", {}) else getattr(plugin, hook, None)
        args: list[dict] = []
        try:
            for p in inspect.signature(given).parameters.values():
                a = _arg(p)
                if a is not None:
                    args.append(a)
        except (TypeError, ValueError):
            pass
        methods[hook] = {"args": args, "returns": "any", "signature": signature or "(...)"}
    methods.update(LIFECYCLE_METHODS)
    return {"trait": f"liminal.plugin.{plugin.name}", "base": [TRAIT, f"liminal.{kind.capitalize()}Plugin"],
            "methods": methods, "signals": dict(SIGNALS)}


class Refused(Exception):
    """A request a node refuses, in words (it crosses as a record: its class's name, its words, its status)."""

    def __init__(self, words: str, status: int = 409):
        super().__init__(words)
        self.status = status


class PluginHillock:
    """A plugin as a node's code (liminal_net.Node's hillock). `app` holds the plugin attached (its login with it); a
    signal reaches the plugin only through that app (App.signal_plugin). `own_process`: the node is a process of its
    own (`serve`), which KILL ends too (`exit`)."""

    def __init__(self, plugin, app, *, own_process: bool = False, exit: Callable[[int], None] = os._exit,
                 later: Callable[[Callable[[], None]], None] | None = None):
        self.plugin, self.app = plugin, app
        self.name = plugin.name
        self.own_process = own_process
        self._exit = exit
        self._later = later or (lambda fn: threading.Timer(0.25, fn).start())
        self.node = None  # the liminal_net.Node serving it, once made (serve_plugin)
        self.peers: dict[int, dict] = {}
        self._lock = threading.Lock()
        self.ended: dict | None = None  # what its end came to, once ended
        self.interface = interface_of(plugin)

    # -- liminal-net's calls ------------------------------------------------------------------------------------------
    def request(self, peer, method: str, args, kwargs):
        args, kwargs = list(args or ()), dict(kwargs or {})
        if method == "term":
            return self.term(*args, **kwargs)
        if method == "kill":
            return self.kill()
        if method == "ask":
            return self.ask(*args, **kwargs)
        if self.ended is not None:
            raise Refused(f"{self.name} is ending: nothing new is taken", 503)
        return self.app.ask(self.name, method, *args, **kwargs)

    def attach(self, peer) -> None:
        with self._lock:
            self.peers[int((peer or {}).get("pid") or 0)] = dict(peer or {})

    def detach(self, peer) -> None:
        with self._lock:
            self.peers.pop(int((peer or {}).get("pid") or 0), None)

    def shutdown(self) -> None:
        """liminal-net's end of an on-demand node (nobody attached for its grace, or stopped): TERM, its data secured."""
        self._end(Signal.TERM, "nobody is attached")

    # -- the lifecycle's requests ------------------------------------------------------------------------------------
    def _end(self, sig: Signal, why: str) -> dict:
        with self._lock:
            if self.ended is not None and not (sig is Signal.KILL and self.ended.get("signal") == "TERM"):
                return self.ended
            self.ended = {"name": self.name, "signal": sig.value, "stage": "ending", "why": why}
        self._fire({"stage": "ending", "signal": sig.value, "why": why})
        try:
            out = self.app.signal_plugin(self.name, sig) if self.app.plugin(self.name) is self.plugin else \
                {"name": self.name, "how": "nothing", "why": "it was let go already"}
        except Exception as e:  # noqa: BLE001 - said, and the node ends all the same
            out = {"name": self.name, "how": "failed", "why": f"{type(e).__name__}: {e}"}
        if self.own_process:
            lifecycle.give_back_claims()
        out = {**out, "signal": sig.value, "stage": "ended", "claims": lifecycle.claims_held()}
        with self._lock:
            self.ended = out
        self._fire({"stage": "ended", "signal": sig.value, "why": why})
        return out

    def term(self, timeout=None) -> dict:
        """TERM: the plugin's own end through its app, within its own STOP_DEADLINE_S (the app enforces it: KILL of
        its trees past it; `timeout`, the caller's, is how long the caller waits), then the node stopped once this
        is answered."""
        out = self._end(Signal.TERM, "asked: TERM")
        self._later(lambda: self._stop("TERM"))
        return out

    def kill(self) -> dict:
        """KILL: what it started ended with its trees now; the node stopped, and its process ended when it is one."""
        out = self._end(Signal.KILL, "asked: KILL")
        self._later(lambda: self._stop("KILL", exit_code=KILL_EXIT if self.own_process else None))
        return out

    def ask(self, what: str = "status") -> dict:
        """What it is, read only (lifecycle.ask_of through its app; `node`: its node's own state)."""
        if what == "node":
            node = self.node
            return {"name": self.name, "node": node_name(self.name), "peers": sorted(self.peers),
                    "stage": _stage(node), "pid": os.getpid(), **lifecycle.mode_of(self.plugin)}
        if what not in ASKS:
            raise Refused(f"nothing {what!r} to ask: {', '.join(ASKS)}", 400)
        if self.app.plugin(self.name) is not self.plugin:
            return {"name": self.name, "why": "it is let go (ended)", **lifecycle.mode_of(self.plugin)}
        return self.app.ask_plugin(self.name, what)

    def _stop(self, why: str, exit_code: int | None = None) -> None:
        if self.node is not None:
            try:
                self.node.stop(why)
            except Exception:  # noqa: BLE001 - a node already ended
                pass
        if exit_code is not None:
            self._exit(exit_code)

    def _fire(self, data: dict) -> None:
        if self.node is None:
            return
        try:
            self.node.fire("lifecycle", {"node": node_name(self.name), **data})
        except Exception:  # noqa: BLE001 - nobody linked, or the node ended: nothing to tell
            pass


def _stage(node) -> str:
    try:
        return str(node.stage()) if node is not None else "not served"
    except Exception:  # noqa: BLE001
        return "unknown"


class AppHillock:
    """An app as a node's code (opt-in: App.serve_node): TERM, KILL and ASK for the app itself and for any plugin it
    holds, by name, through the app."""

    def __init__(self, app, later: Callable[[Callable[[], None]], None] | None = None):
        self.app = app
        self._later = later or (lambda fn: threading.Timer(0.25, fn).start())
        self.node = None
        self.interface = {
            "trait": f"liminal.app.{app.NAME}", "base": [APP_TRAIT],
            "methods": {**LIFECYCLE_METHODS,
                        "plugins": {"args": [], "returns": "map", "signature": "()"},
                        "plugin_signal": {"args": [{"name": "name", "type": "text"}, {"name": "signal", "type": "text"}],
                                          "returns": "map", "signature": "(name, signal)"},
                        "plugin_ask": {"args": [{"name": "name", "type": "text"}, {"name": "what", "type": "text"}],
                                       "returns": "map", "signature": "(name, what)"}},
            "signals": dict(SIGNALS)}

    def term(self, timeout=None) -> dict:
        if isinstance(timeout, (int, float)) and timeout >= 0:
            self.app.stop_timeout = float(timeout)
        self._later(self.app.stop)
        return {"app": self.app.NAME, "signal": "TERM", "pid": os.getpid(), "plugins": sorted(self.app.plugins())}

    def kill(self) -> dict:
        self._later(lambda: self.app.terminate(Signal.KILL, 0))
        return {"app": self.app.NAME, "signal": "KILL", "pid": os.getpid()}

    def ask(self, what: str = "processes") -> dict:
        if what == "processes":
            return {"app": self.app.NAME, "pid": os.getpid(), "processes": lifecycle.shown_rows(lifecycle.mine())}
        if what == "plugins":
            return self.plugins()
        raise Refused(f"nothing {what!r} to ask of an app: processes, plugins", 400)

    def plugins(self) -> dict:
        return {"plugins": {n: {**lifecycle.mode_of(self.app.plugin(n))} for n in self.app.plugins()}}

    def plugin_signal(self, name: str, signal: str) -> dict:
        return self.app.signal_plugin(name, signal)

    def plugin_ask(self, name: str, what: str) -> dict:
        return self.app.ask_plugin(name, what)

    def shutdown(self) -> None:
        pass  # an app's node ends with the app; its end is the app's (stop)


def make_node(name: str, kind: str, hillock, interface: dict, scope: Path | None = None, node_factory=None, timing=None):
    """A liminal-net node over `hillock` (node_factory: liminal_net.Node, or a test's stand-in)."""
    if node_factory is None:
        from liminal_net import Node as node_factory  # the bridge, installed in the venv
    node = node_factory(name, kind, str(scope or default_scope()), hillock, interface, None, timing)
    hillock.node = node
    return node


def serve_app(app, scope: Path | None = None, node_factory=None):
    """An app served as its node too (app-<NAME>), in the background (node.start()): what the command reaches first."""
    hillock = AppHillock(app)
    node = make_node(app_node_name(app.NAME), "app", hillock, hillock.interface, scope, node_factory)
    node.start()
    return node


def plugin_node(plugin, app, scope: Path | None = None, node_factory=None, own_process: bool = False, timing=None):
    """`plugin` attached to `app` (its login with it) and its node made, not served yet: (node, hillock)."""
    if app.plugin(plugin.name) is not plugin:
        app.attach(plugin)
    hillock = PluginHillock(plugin, app, own_process=own_process)
    node = make_node(node_name(plugin.name), "plugin", hillock, hillock.interface, scope, node_factory, timing)
    return node, hillock


def launcher(name: str, scope: Path | None = None, spawn=None, python: str | None = None) -> Callable[[], None]:
    """What starts plugin `name`'s node when nobody answers: `python -m liminal_libs.nodes serve NAME --scope S`,
    windowless, written in the ledger (owner node:NAME, kind plugin-node), outliving its starter (it ends when nobody
    is attached)."""
    spawn = spawn or lifecycle.spawn
    exe = python or _pythonw()
    scope = str(scope or default_scope())

    def launch() -> None:
        spawn([exe, "-m", "liminal_libs.nodes", "serve", name, "--scope", scope], owner=f"node:{name}",
              kind="plugin-node", tied=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
              stderr=subprocess.DEVNULL, close_fds=True)

    return launch


def _pythonw() -> str:
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    return str(w if os.name == "nt" and w.exists() else exe)


def reach_or_start(me, name: str, scope: Path | None = None, *, start: bool = True, deadline_s: float | None = None,
                   launch: Callable[[], None] | None = None, ledger=None, table=None, killer=None) -> dict:
    """Plugin `name`'s node reached from node `me` (a liminal_net.Node): the one answering, or (`start`) one started by
    its launcher. A start not answering within `deadline_s` (its START_DEADLINE_S, 10 s by default) is reported, and
    what was started for it (the ledger's rows owned by node:NAME, started since) ended with its tree. Returns {"remote"}
    or {"remote": None, "why", "ended"}."""
    deadline_s = lifecycle.START_DEADLINE_S if deadline_s is None else deadline_s
    began = time.time()
    box: dict = {}

    def run() -> None:
        try:
            box["remote"] = me.reach(node_name(name), str(scope or default_scope()),
                                     (launch or launcher(name, scope)) if start else None)
        except Exception as e:  # noqa: BLE001 - nobody answers, refused, a start that failed
            box["why"] = f"{type(e).__name__}: {e}"

    worker = threading.Thread(target=run, name=f"liminal-reach-{name}", daemon=True)
    worker.start()
    worker.join(deadline_s)
    if "remote" in box:
        return {"remote": box["remote"]}
    why = box.get("why") or f"it did not answer within its start deadline ({deadline_s:g} s)"
    ended: list = []
    if start:
        try:
            rows = [r for r in (ledger or lifecycle.Ledger(table=table)).rows()
                    if r.owner == f"node:{name}" and r.at >= began - 1]
        except OSError:
            rows = []
        if rows:
            ended = lifecycle.end_trees([r.as_proc() for r in rows], Signal.KILL, 0, table=table, killer=killer,
                                        protect={os.getpid()})
    return {"remote": None, "why": why, "ended": ended}


def serve(name: str, scope: Path | None = None, node_factory=None) -> str:
    """`python -m liminal_libs.nodes serve NAME`: plugin `name` (as the registry finds it) served as its node in this
    process until nobody is attached (or TERM, KILL): its own app holding it, with the user's login (their environment
    variables, as the platform's)."""
    from .apps.app import App
    from .apps.authorization import EnvironmentLogin, saved_variables
    from .sources import registry

    found = None
    for group in (registry.providers, registry.publishers, registry.assistants, registry.machines, registry.databases,
                  registry.auditors):
        found = group().get(name) or found
    if found is None:
        return f"no plugin {name!r} is installed here"

    class NodeApp(App):
        NAME, TITLE, ICON = f"node-{name}", f"{name}'s node", "plug"

    app = NodeApp(log=lambda m: None, login=EnvironmentLogin(saved=saved_variables))
    node, hillock = plugin_node(found, app, scope, node_factory, own_process=True)
    restore = lifecycle.install_handlers(_Termer(hillock))
    try:
        why = node.serve()
    finally:
        restore()
        if hillock.ended is None:
            hillock.shutdown()
        app.terminate(Signal.TERM)
    return why


class _Termer:
    def __init__(self, hillock: PluginHillock):
        self.hillock = hillock

    def signal(self, sig, deadline, sender=None):  # noqa: ARG002 - the lifecycle's signature
        return self.hillock.term() if Signal.of(sig) is Signal.TERM else self.hillock.kill()


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m liminal_libs.nodes", description="serve a plugin as its node")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("name")
    s.add_argument("--scope", default=None)
    args = ap.parse_args(argv)
    why = serve(args.name, Path(args.scope) if args.scope else None)
    print(why)
    return 0


if __name__ == "__main__":
    sys.exit(main())
