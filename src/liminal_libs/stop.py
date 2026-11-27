"""liminal-signal and liminal-stop: every Liminal app, plugin and process on this machine told to end, or asked what
it is (1.86.0, Monday list item 38).

    liminal-signal TERM (--all | --app NAME ... | --plugin NAME | --pid N) [--kill] [--timeout S] [--list]
    liminal-signal KILL ... --kill      (KILL forces: it is refused without --kill)
    liminal-signal ASK --plugin NAME [status|interface|apis|needs|mode|processes|node]
    liminal-signal ASK --all            (also --check): every app and plugin, its mode, deadlines and what runs of it
    liminal-stop [--kill] [--pid N] [--list] [--timeout S] [--app NAME]   (liminal-signal TERM --all; python -m liminal_libs.stop)

The command is a liminal-net node of its own (the user, 2026-11-24: "a command that inherits the node class, and is
able to attach to a plugin, and send a 'kill' signal graceful, force, etc..."): it reaches each app's node
(app-<name>) and each plugin's (plugin-<name>) and asks it `term`, `kill` or `ask` (nodes.py), authenticated by
liminal-net's own handshake with this user's key. An app that is no node yet is asked through its route
(App: POST /api/app/signal, with the proof of the same key). Then whatever of Liminal's still runs is asked to end by
its whole tree, TERM: the ledger's processes (lifecycle.Ledger) and the processes that are Liminal's by what they run
(a python of Liminal's venv running `-m liminal_...`: lifecycle.is_liminal), each checked by its start time before
every signal, so an id the system gave again is never touched, and never this command or what started it. `--list`
says what it would end and changes nothing.

1.88.4 (the user, 2026-11-24: "all shutdowns need to be clean"): TERM, and nothing else, unless --kill is given. What
is still running after the timeout is reported (its id, what it runs, its owner, how long it was asked) with exit code 1
and a line saying to run again with --kill; nothing is killed. With --kill, what is left after the timeout is forced,
but only what holds no data: a data holder (mongod, the MongoDB host, a ledger row written as holding data) is asked
to end in its own clean way (mongod: MongoDB's shutdown command), never forced, unless it is named: --pid N --kill.

Exit codes: 0, everything asked ended (or, for --list and ASK, was answered); 1, something did not end, or an ASK found
nothing to answer; 2, the command was not understood; 3, a node or an app refused it.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from . import lifecycle
from .lifecycle import Signal

# the four apps and their ports (each app's own PORT and PORT_VAR)
APPS = {"login": ("LIMINAL_LOGIN_PORT", 8795), "platform": ("LIMINAL_PLATFORM_PORT", 8775),
        "charts": ("LIMINAL_CHARTS_PORT", 8765), "integrator": ("LIMINAL_FETCHER_PORT", 8785)}
WRITE_HEADER = "X-Liminal-Charts"  # web.WRITE_HEADER (not imported: the command loads no server)
REACH_WAIT_S = 2.0  # what a node that is not running is given to answer the command
EXIT_OK, EXIT_LEFT, EXIT_USAGE, EXIT_REFUSED = 0, 1, 2, 3


def app_port(name: str, env=None) -> int:
    env = os.environ if env is None else env
    var, port = APPS[name]
    raw = (env.get(var) or "").strip()
    return int(raw) if raw.isdecimal() else port


def _http(method: str, url: str, headers: dict, body: dict | None, timeout: float = 5.0) -> tuple[int, dict]:
    """One request to an app on this machine, never through a proxy: (status, its JSON), status 0 when nothing answers."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", **headers,
                                 **({"Content-Type": "application/json"} if data is not None else {})})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": str(e.reason)}
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return 0, {}


@dataclass
class Line:
    """One thing the command did or found, as it prints it."""

    who: str
    how: str  # asked, terminated, killed, gone, left, refused, not running, would end, answered
    pid: int | None = None
    why: str = ""

    def text(self) -> str:
        pid = f" (pid {self.pid})" if self.pid else ""
        why = f": {self.why}" if self.why else ""
        return f"{self.who}{pid}: {self.how}{why}"


class SignalCommand:
    """The command: a liminal-net node's code (its hillock), reaching the others as their client. Everything it uses
    of this machine is given or made here, so a test gives stand-ins: `node` (a liminal_net.Node, or one with reach),
    `http`, `table`, `killer`, `ledger`, `key`, `clock` and `sleep`."""

    interface = {"trait": "liminal.SignalCommand", "methods": {}, "signals": {}}

    def __init__(self, *, node=None, node_factory=None, http: Callable | None = None, table=None, killer=None,
                 ledger=None, key: bytes | None = None, scope=None, env=None, venvs=None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 out: Callable[[str], None] = print, set_event: Callable[[str], bool] | None = None):
        self.table = table or lifecycle.OsTable()
        self.killer = killer or lifecycle.OsKiller()
        self.ledger = ledger or lifecycle.Ledger(table=self.table)
        self.http = http or _http
        self.env = os.environ if env is None else env
        self.venvs = venvs if venvs is not None else lifecycle.venv_folders()
        self.clock, self.sleep, self.out = clock, sleep, out
        self._key = key
        self._scope = scope
        self._node = node
        self._node_factory = node_factory
        self.lines: list[Line] = []
        self.set_event = set_event or lifecycle.set_stop_event  # an app's stop event (Windows), set before any kill

    # -- its own node -------------------------------------------------------------------------------------------------
    @property
    def node(self):
        """Its liminal-net node (signal-<pid>), made when first needed; None where the bridge is not installed (the
        command then reaches the apps through their routes alone)."""
        if self._node is None:
            try:
                from . import nodes

                self._node = nodes.make_node(f"signal-{os.getpid()}", "command", self, self.interface, self._scope,
                                             self._node_factory, {"reach_wait": REACH_WAIT_S})
            except Exception:  # noqa: BLE001 - no bridge here (ImportError), or a key folder that cannot be read
                self._node = False
        return self._node or None

    def key(self) -> bytes:
        if self._key is None:
            from .host import key

            self._key = key()
        return self._key

    def _reach(self, name: str):
        node = self.node
        if node is None:
            return None
        from . import nodes

        try:
            return node.reach(name, str(self._scope or nodes.default_scope()), None)
        except Exception:  # noqa: BLE001 - nobody answers (NetworkError), or refused
            return None

    def say(self, line: Line) -> Line:
        self.lines.append(line)
        self.out(line.text())
        return line

    # -- what runs ----------------------------------------------------------------------------------------------------
    def protected(self) -> set[int]:
        """This command and what started it (a console script's launcher, the shell): never signalled."""
        rows = {p.pid: p.ppid for p in self.table.list()}
        out, pid = set(), os.getpid()
        while pid and pid not in out:
            out.add(pid)
            pid = rows.get(pid, 0)
        return out

    def liminal_processes(self, app: str | None = None, plugin: str | None = None) -> list[lifecycle.Proc]:
        """What of Liminal's runs: the ledger's rows (each its owner's: `app`, `plugin` or node:plugin when named) and,
        for every app at once, the processes Liminal's by what they run. Never this command or its parents."""
        protect = self.protected()
        rows = self.ledger.rows()
        if plugin is not None:
            rows = [r for r in rows if r.owner in (plugin, f"node:{plugin}")]
        elif app is not None:
            rows = [r for r in rows if r.owner == app]
        found: dict[int, lifecycle.Proc] = {}
        table = {p.pid: p for p in self.table.list()}
        for r in rows:
            p = table.get(r.pid)
            if p is not None and p.started == r.started and p.pid not in protect:
                found[p.pid] = p
        if app is None and plugin is None:
            for p in table.values():
                if p.pid not in protect and lifecycle.is_liminal(p, self.venvs):
                    found.setdefault(p.pid, p)
        return list(found.values())

    # -- the apps -----------------------------------------------------------------------------------------------------
    def _url(self, name: str, path: str) -> str:
        return f"http://127.0.0.1:{app_port(name, self.env)}{path}"

    def _proved(self, write: bool = False) -> dict:
        headers = {lifecycle.PROOF_HEADER: lifecycle.proof(self.key())}
        if write:
            headers[WRITE_HEADER] = "1"
        return headers

    def running_apps(self, names) -> dict[str, dict]:
        """Which of `names` answer: by its node (app-<name>), else by its page's /api/app."""
        from . import nodes

        out: dict[str, dict] = {}
        for name in names:
            remote = self._reach(nodes.app_node_name(name))
            if remote is not None:
                out[name] = {"by": "node", "remote": remote, "pid": _pid_of(remote)}
                continue
            status, data = self.http("GET", self._url(name, "/api/app"), {}, None)
            if status == 200 and isinstance(data, dict) and data.get("app") == name:
                out[name] = {"by": "route", "pid": None}
        return out

    def ask_app(self, name: str, held: dict, sig: Signal, timeout: float) -> Line:
        """One app told `sig`: through its node, else its route. Its pid, from its answer, is waited for after."""
        if held["by"] == "node":
            try:
                answer = held["remote"].request("term", timeout) if sig is Signal.TERM else held["remote"].request("kill")
            except Exception as e:  # noqa: BLE001 - refused, or it ended while asked
                return self.say(Line(f"app {name}", "refused", held.get("pid"), f"{type(e).__name__}: {e}"))
            pid = (answer or {}).get("pid") or held.get("pid")
            return self.say(Line(f"app {name}", "asked", pid, f"{sig.value} through its node"))
        status, data = self.http("POST", self._url(name, "/api/app/signal"), self._proved(write=True),
                                 {"signal": sig.value, "timeout": timeout})
        if status == 202:
            return self.say(Line(f"app {name}", "asked", data.get("pid"), f"{sig.value} through its route"))
        if status in (401, 403):
            return self.say(Line(f"app {name}", "refused", None, str(data.get("error") or status)))
        return self.say(Line(f"app {name}", "not asked", None, f"its route answered {status or 'nothing'}"))

    def wait_gone(self, pids, deadline: float) -> None:
        pids = [p for p in pids if p]
        while pids and self.clock() < deadline:
            pids = [p for p in pids if self.table.alive(p)]
            if pids:
                self.sleep(lifecycle.STEP_S)

    # -- the verbs -----------------------------------------------------------------------------------------------------
    def signal(self, sig: Signal, apps=None, plugin: str | None = None, timeout: float = lifecycle.TERM_TIMEOUT_S,
               listing: bool = False, kill: bool = False, pid: int | None = None) -> int:
        """TERM or KILL to `apps` (names; None: every app) or one plugin; then what of theirs still runs asked to end by
        its tree (TERM), and what has not ended after the timeout reported, not killed (1.88.4). `kill` (--kill): what
        is left then, holding no data, is forced; KILL (asked for outright) forces it at once. `pid`: that process alone
        (one of Liminal's), which `kill` may force even while it holds data. `listing`: what it would end, nothing
        changed."""
        from . import nodes

        if pid is not None:
            return self.one(int(pid), sig, timeout, listing, kill)
        every = apps is None and plugin is None
        names = list(APPS) if apps is None else list(apps)
        began = self.clock()
        given = max(timeout, 0.0)  # what a data holder asked to end cleanly is given, a KILL's too
        timeout = 0.0 if sig is Signal.KILL else max(timeout, 0.0)
        deadline = self.clock() + timeout
        refused = False
        waited: list[int] = []
        if plugin is None:
            held = self.running_apps(names)
            for name in names:
                if name not in held:
                    if not listing:
                        self.say(Line(f"app {name}", "not running"))
                    continue
                if listing:
                    self.say(Line(f"app {name}", "would be asked", held[name].get("pid"), f"{sig.value} by its {held[name]['by']}"))
                    continue
                line = self.ask_app(name, held[name], sig, timeout)
                refused |= line.how == "refused"
                waited.append(line.pid or 0)
        targets = [plugin] if plugin is not None else (
            sorted({r.owner[len("node:"):] for r in self.ledger.rows() if r.owner.startswith("node:")}) if every else [])
        for name in targets:
            if plugin is not None and not listing:  # first through an app that holds it
                for app in self.running_apps(list(APPS)):
                    status, data = self.http("POST", self._url(app, f"/api/plugins/{name}/signal"),
                                             self._proved(write=True), {"signal": sig.value})
                    if status == 200:
                        self.say(Line(f"plugin {name}", "asked", None, f"{sig.value} through {app}: {data.get('how')}"))
                    elif status in (401, 403):
                        refused = True
                        self.say(Line(f"plugin {name}", "refused", None, f"by {app}: {data.get('error')}"))
            remote = self._reach(nodes.node_name(name))
            if remote is None:
                continue
            if listing:
                self.say(Line(f"plugin {name}", "would be asked", _pid_of(remote), f"{sig.value} by its node"))
                continue
            try:
                remote.request("term", timeout) if sig is Signal.TERM else remote.request("kill")
                self.say(Line(f"plugin {name}", "asked", _pid_of(remote), f"{sig.value} through its node"))
                waited.append(_pid_of(remote) or 0)
            except Exception as e:  # noqa: BLE001
                refused = True
                self.say(Line(f"plugin {name}", "refused", _pid_of(remote), f"{type(e).__name__}: {e}"))
        if not listing and plugin is None and sig is Signal.TERM:
            # each app's stop event set before anything is ended (1.87.0): a console-less pythonw hears only this
            told = [name for name in names if self.set_event(lifecycle.stop_event_name(name))]
            for name in told:
                self.say(Line(f"app {name}", "asked", None, "TERM by its stop event"))
            while told and self.clock() < deadline and self.running_apps(told):
                self.sleep(lifecycle.STEP_S)
        if not listing:
            self.wait_gone(waited, deadline)
        # what is left, ended by its tree
        roots: list[lifecycle.Proc] = []
        if every:
            roots = self.liminal_processes()
        elif plugin is not None:
            roots = self.liminal_processes(plugin=plugin)
        else:
            for name in names:
                roots += self.liminal_processes(app=name)
            alive = {p.pid: p for p in self.table.list()}
            for pid in waited:  # the apps asked, whose own process is still there past the timeout
                p = alive.get(pid)
                if p is not None and lifecycle.is_liminal(p, self.venvs):
                    roots.append(p)
        if listing:
            for p in roots:
                self.say(Line(_said(p), "would end", p.pid))
            return EXIT_OK
        left = False
        if roots:
            # TERM's time: what the apps left of the timeout, and at least a grace for what is asked only now
            wait = given if sig is Signal.KILL else max(deadline - self.clock(), 0.0) + lifecycle.GRACE_S
            left = self.end(roots, sig, wait, began, force=kill or sig is Signal.KILL)
        if not roots and not self.lines:
            self.say(Line("Liminal", "nothing running"))
        return EXIT_REFUSED if refused else EXIT_LEFT if left else EXIT_OK

    def end(self, roots: list, sig: Signal, wait: float, began: float, force: bool, named: set | None = None) -> bool:
        """`roots` asked to end by their trees (lifecycle.end_trees): TERM and `wait` (KILL: what holds no data at
        once, a data holder asked cleanly and given `wait`); `force` (--kill, or KILL): what holds no data and is
        still running after it is forced; `named`, ids that may be forced while they hold data. What is left is said
        with its owner and how long it was asked. Whether anything is left."""
        rows = self.ledger.rows()
        of = {r.pid: r for r in rows}
        pids = {p.pid for p in roots}
        jobs = {r.pid: lifecycle.job_of(r.tie) for r in rows if r.pid in pids and lifecycle.job_of(r.tie)}
        out = lifecycle.end_trees(roots, Signal.KILL if sig is Signal.KILL else Signal.TERM, wait, table=self.table,
                                  killer=self.killer, clock=self.clock, sleep=self.sleep, protect=self.protected(),
                                  rows=rows, escalate=force and sig is not Signal.KILL, force=named or ())
        known = {p.pid: p for p in roots} | {p.pid: p for p in self.table.list()}
        left = held = False
        for r in out:
            p = known.get(r["pid"])
            if r["how"] != "left":
                self.say(Line(_said(p) if p else "a child", r["how"], r["pid"], r.get("why", "")))
                continue
            left = True
            held |= bool(r.get("holdsData"))
            row = of.get(r["pid"])
            owner = row.owner if row is not None else "Liminal's by what it runs" if p is not None and \
                lifecycle.is_liminal(p, self.venvs) else "started by one of Liminal's"
            self.say(Line(_said(p) if p else "a child", "left", r["pid"],
                          f"{r.get('why', '')}; owner {owner}; asked {max(self.clock() - began, 0.0):.1f} s ago"))
        # what a row's own job holds (the interpreter its redirector started): ended at once, read from the ledger
        # before the trees were ended (1.87.0); 1.88.4: only when forcing, and never a data holder's job; 1.110.0
        # (item 14): nor the job of a starter a data holder could not leave (it runs inside it), named or not
        end_job = getattr(self.killer, "end_job", None)
        inside = lifecycle.inside_jobs(rows, self.table.list()) if force and callable(end_job) and jobs else set()
        for pid, job in jobs.items() if force and callable(end_job) else ():
            row = of.get(pid)
            if row is not None and lifecycle.row_holds_data(row) and pid not in (named or ()):
                continue
            if row is not None and (row.pid, row.started) in inside:
                self.say(Line(f"job {job}", "left", pid, "a data holder runs inside it (it could not leave its "
                                                         "starter's job): never forced"))
                continue
            if end_job(job):
                self.say(Line(f"job {job}", "killed", pid, "everything in it"))
        if left and not force:
            self.say(Line("Liminal", "not ended", None, f"what is left was asked and not killed: {lifecycle.KILL_HINT} "
                                                         "(a data holder only when named: --pid N --kill)"))
        elif held:
            self.say(Line("Liminal", "not ended", None, "a data holder is never forced: name it (--pid N --kill) to "
                                                         "force it"))
        return left

    def one(self, pid: int, sig: Signal, timeout: float, listing: bool = False, kill: bool = False) -> int:
        """--pid N: that process and what it started asked to end (TERM; mongod, its shutdown); `kill`: what is left
        of them after the timeout forced, the process named even while it holds data (what it started that holds data
        is not). Only a process of Liminal's (the ledger's, or Liminal's by what it runs), never this command."""
        began = self.clock()
        p = next((x for x in self.table.list() if x.pid == pid), None)
        if p is None:
            self.say(Line("process", "not running", pid))
            return EXIT_LEFT
        row = next((r for r in self.ledger.rows() if r.pid == pid and r.started == p.started), None)
        if pid in self.protected():
            self.say(Line(_said(p), "refused", pid, "this command, or what started it"))
            return EXIT_REFUSED
        if row is None and not lifecycle.is_liminal(p, self.venvs):
            self.say(Line(_said(p), "refused", pid, "not Liminal's (in no ledger row, nor Liminal's by what it runs): "
                                                    "never touched"))
            return EXIT_REFUSED
        if listing:
            self.say(Line(_said(p), "would end", pid))
            return EXIT_OK
        if sig is Signal.KILL and not kill:
            sig = Signal.TERM
        return EXIT_LEFT if self.end([p], sig, max(timeout, 0.0), began, force=kill, named={pid} if kill else None) \
            else EXIT_OK

    def ask(self, plugin: str | None, what: str = "status", every: bool = False) -> int:
        """ASK: one plugin asked what it is (through an app holding it, else its node, started on demand within its start
        deadline); `every`: every app and every plugin, its mode, deadlines and what runs of it."""
        from . import nodes

        if every:
            held = self.running_apps(list(APPS))
            for name in APPS:
                if name not in held:
                    self.say(Line(f"app {name}", "not running"))
                    continue
                status, data = self.http("GET", self._url(name, "/api/plugins"), {}, None)
                plugins = (data or {}).get("plugins") or {}
                self.say(Line(f"app {name}", "answered", held[name].get("pid"), f"{len(plugins)} plugins"))
                for p in sorted(plugins):
                    _, mode = self.http("GET", self._url(name, f"/api/plugins/{p}/mode"), self._proved(), None)
                    _, procs = self.http("GET", self._url(name, f"/api/plugins/{p}/processes"), self._proved(), None)
                    running = len((procs or {}).get("processes") or [])
                    self.say(Line(f"  plugin {p}", "answered", None,
                                  f"{(mode or {}).get('mode', '?')}, start {(mode or {}).get('startDeadline', '?')} s, "
                                  f"stop {(mode or {}).get('stopDeadline', '?')} s, {running} processes running"))
            for r in self.ledger.rows():
                self.say(Line(f"ledger {r.owner}", "running", r.pid, f"{r.kind}: {' '.join(lifecycle.scrub_command(r.command))[:120]}"))
            return EXIT_OK
        if not plugin:
            self.say(Line("ASK", "not understood", None, "name a plugin (--plugin NAME), or --all"))
            return EXIT_USAGE
        for app in self.running_apps(list(APPS)):
            status, data = self.http("GET", self._url(app, "/api/plugins"), {}, None)
            if plugin in ((data or {}).get("plugins") or {}):
                status, data = self.http("GET", self._url(app, f"/api/plugins/{plugin}/{what}"), self._proved(), None)
                if status in (401, 403):
                    self.say(Line(f"plugin {plugin}", "refused", None, str((data or {}).get("error"))))
                    return EXIT_REFUSED
                self.out(json.dumps(data, indent=1, default=str))
                self.lines.append(Line(f"plugin {plugin}", "answered", None, f"through {app}"))
                return EXIT_OK if status == 200 else EXIT_LEFT
        node = self.node
        if node is None:
            self.say(Line(f"plugin {plugin}", "not found", None, "no app holds it, and liminal-net is not installed here"))
            return EXIT_LEFT
        reached = nodes.reach_or_start(node, plugin, self._scope, start=True, ledger=self.ledger, table=self.table,
                                       killer=self.killer)
        if reached["remote"] is None:
            self.say(Line(f"plugin {plugin}", "not answered", None, reached["why"]))
            return EXIT_LEFT
        try:
            answer = reached["remote"].request("ask", what)
        except Exception as e:  # noqa: BLE001
            self.say(Line(f"plugin {plugin}", "refused", None, f"{type(e).__name__}: {e}"))
            return EXIT_REFUSED
        finally:
            try:
                reached["remote"].detach()  # let go: an on-demand node ends once nobody holds it
            except Exception:  # noqa: BLE001
                pass
        self.out(json.dumps(answer, indent=1, default=str))
        self.lines.append(Line(f"plugin {plugin}", "answered", None, "through its node"))
        return EXIT_OK


def _pid_of(remote) -> int | None:
    try:
        return int(remote.pid())
    except Exception:  # noqa: BLE001
        return None


def _said(p) -> str:
    if p is None:
        return "a process"
    words = (p.cmdline or p.exe or "").split()
    return " ".join(words[:4])[:80] or f"process {p.pid}"


def signal_main(argv: list[str] | None = None, command: SignalCommand | None = None) -> int:
    ap = argparse.ArgumentParser(prog="liminal-signal", description="TERM, KILL or ASK Liminal's apps and plugins")
    ap.add_argument("signal", help="TERM (graceful), KILL (force) or ASK (read only); SIGTERM, 15, SIGKILL, 9 too")
    ap.add_argument("what", nargs="?", default="status", help="for ASK: status, interface, apis, needs, mode, processes, node")
    ap.add_argument("--all", action="store_true", help="every app and plugin on this machine")
    ap.add_argument("--app", action="append", choices=sorted(APPS), help="this app (more than once: these)")
    ap.add_argument("--plugin", help="this plugin")
    ap.add_argument("--pid", type=int, help="this process of Liminal's (and what it started) alone")
    ap.add_argument("--timeout", type=float, default=lifecycle.TERM_TIMEOUT_S,
                    help="seconds TERM is given; what is left then is reported (forced only with --kill)")
    ap.add_argument("--kill", action="store_true",
                    help="force what is left after the timeout, if it holds no data (with --pid N: that process too)")
    ap.add_argument("--list", action="store_true", help="say what would be ended, and change nothing")
    ap.add_argument("--check", action="store_true", help="ASK --all: every plugin, its mode and deadlines, what runs")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return EXIT_USAGE if e.code else EXIT_OK
    command = command or SignalCommand()
    word = str(args.signal).strip().upper()
    if word == "ASK" or args.check:
        return command.ask(args.plugin, args.what, every=args.all or args.check)
    try:
        sig = Signal.of(word)
    except ValueError as e:
        print(f"liminal-signal: {e}", file=sys.stderr)
        return EXIT_USAGE
    if sig is Signal.KILL and not args.kill:
        print("liminal-signal: KILL forces: say --kill as well (TERM, the default, asks and reports what is left)",
              file=sys.stderr)
        return EXIT_USAGE
    if not (args.all or args.app or args.plugin or args.pid is not None):
        print("liminal-signal: say what to signal: --all, --app NAME, --plugin NAME or --pid N", file=sys.stderr)
        return EXIT_USAGE
    return command.signal(sig, apps=None if args.all else args.app, plugin=None if args.all else args.plugin,
                          timeout=args.timeout, listing=args.list, kill=args.kill, pid=args.pid)


def stop_main(argv: list[str] | None = None, command: SignalCommand | None = None) -> int:
    """liminal-stop: liminal-signal TERM --all (--kill: what is left after the timeout forced, if it holds no data;
    --app NAME: those apps only; --pid N: that process alone, which --kill may force even while it holds data)."""
    ap = argparse.ArgumentParser(prog="liminal-stop", description="end every Liminal app, plugin and process here")
    ap.add_argument("--kill", action="store_true",
                    help="force what is left after the timeout, if it holds no data (with --pid N: that process too)")
    ap.add_argument("--pid", type=int, help="this process of Liminal's (and what it started) alone")
    ap.add_argument("--list", action="store_true", help="say what would be ended, and change nothing")
    ap.add_argument("--timeout", type=float, default=lifecycle.TERM_TIMEOUT_S)
    ap.add_argument("--app", action="append", choices=sorted(APPS))
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return EXIT_USAGE if e.code else EXIT_OK
    command = command or SignalCommand()
    return command.signal(Signal.TERM, apps=args.app, timeout=args.timeout, listing=args.list, kill=args.kill,
                          pid=args.pid)


if __name__ == "__main__":
    sys.exit(stop_main())
