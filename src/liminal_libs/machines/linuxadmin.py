"""The Linux standard interface: Linux administration's base over Admin (1.102.0; Monday list item 19, release one: the
user, 2026-11-25, "Accounts and elevation": Liminal's own `liminal` user and group on Linux, made, changed and removed
from the Linux administration plugin's page or by one root command).

`LinuxAdmin` holds what the plain package `liminal_libs.linuxsys` knows of this Linux (its facts, the way root is had,
the account tool, the journal of what Liminal made) and gives it to the page and to the other plugins:
- `linux_facts(fresh)`, a read any plugin may ask through the platform (SERVICE_HOOKS): the facts, the elevation, the
  accounts and the journal as JSON;
- `linux_apply`, `linux_member` and `linux_undo`, Make them..., Add or Remove a member... and Remove them..., asked
  only from its page (PAGE_ONLY_HOOKS; the user's answer 6). The base holds each of them to that itself, as
  machines/protocol.py does: another plugin's ask, and one that names no asker (a node's, a program's), is refused in
  words. Their arguments are words: parts, a user's name, an action, the plan's sha256, an accept, the password. None
  carries a command (PLUGIN_ONLY_HOOKS is empty: release two's linux_run and linux_grant will be its).

Each change builds its plan again from fresh facts and refuses on a digest other than the one its form confirmed (S16).
Every ask it holds (a found group's persons, a member other than the platform's user, the undo, and, where no password
is asked, every change: the user's answer 6) is raised before sudo starts, so one confirmed click asks sudo once. A
click gets one second confirmation at most: the refusal names the first argument left to accept and holds every
sentence left, and that one accepted counts for them all. The password, where the field asks one, goes to sudo only
after its own prompt, once (linuxsys.elevation), and is never kept.

When it is told to end (Plugin.signal's TERM: the platform's stop, liminal-stop), `app_stopping` sets its stop: every
change refuses from then on, a conversation still before its script's begin line is ended with SIGKILL (nothing ran),
and one whose script has begun is told TERM and finishes the step it is in. It waits for that at most STEP_WAIT_S,
inside the platform's PLUGINS_DEADLINE_S, then returns; the journal says how far a change got, and the next status says
what is left.

The page: "How root is had" and "Liminal's user and group" come first, then the Admin base's sections, and a "This
Linux" table last, after the plugin's own (Under WSL). A subclass (admin-linux) hands its stand-ins through
`linux_run` and `linux_spawn`; by default they are proctree.run with the frame's environment and lifecycle.spawn, owned
by the plugin's name."""
from __future__ import annotations

import contextlib
import re
import subprocess
import sys
import threading
import time

from .. import linuxsys, proctree
from ..apps import asking
from ..linuxsys import accounts as _accounts
from ..linuxsys import elevation as _elevation
from ..linuxsys.shared import Refused
from .admin import Admin
from .terminal import inherited

__all__ = ["LinuxAdmin", "STEP_WAIT_S", "STOPPING", "KIND"]

STEP_WAIT_S = 5.0  # seconds app_stopping waits for a change's step to finish (under lifecycle.PLUGINS_DEADLINE_S)
STOPPING = "the platform is stopping: nothing was changed"
KIND = "linux-root"  # what the ledger's row of sudo's conversation says it is
NAME = _accounts.NAME
DIGEST = re.compile(r"[0-9a-f]{64}")
CANDIDATES_MAX = 24  # persons' accounts offered as members at the most
_STATE = "_linux_held"  # where each plugin keeps its _State: its own, never a copy's (__copy__)
_STATES = threading.Lock()

TOOLS = {"root": "the platform runs as root", "sudo": "sudo", "sudo-rs": "sudo-rs", "doas": "doas", "su": "su",
         "run0": "run0 only", "pkexec": "pkexec only", "none": "nothing here gives root"}
ASKS = {"no": "nothing: no password is asked here", "yes": "a password, typed on the change's form",
        "terminal": "a terminal: run the one command there", "impossible": "it cannot be made from this page"}
BY = {"liminal": "made by Liminal", "adopted": "adopted: this Liminal distribution's login user, never removed",
      "found": "found here: undo keeps it"}
WHAT = {"apply": "Make them...", "member": "Add or Remove a member...", "undo": "Remove them..."}
ACCOUNT_TOOLS = {"sysusers": "systemd-sysusers", "shadow": "shadow's groupadd and useradd",
                 "busybox": "BusyBox's addgroup and adduser", "nix": "NixOS's configuration (declared)",
                 "none": "none Liminal knows"}


class _State:
    """A LinuxAdmin's own: its LinuxSystem, its stop, the changes running, whose password sudo's prompt named."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.cv = threading.Condition()
        self.stop = threading.Event()
        self.busy = 0
        self.system: linuxsys.LinuxSystem | None = None
        self.whose = ""  # the account sudo's marker named, where it was not the field's (WhosePassword)


# ---- the hooks' words ----------------------------------------------------------------------------------------------


def _parts(parts) -> tuple[str, ...]:
    """The parts of Make them..., as a form's fixed field gives them ("accounts service-user") or as a list."""
    if parts is None:
        return _accounts.PARTS
    if isinstance(parts, str):
        words = tuple(w for w in re.split(r"[\s,]+", parts) if w)
    elif isinstance(parts, (list, tuple)) and all(isinstance(p, str) for p in parts):
        words = tuple(parts)
    else:
        raise Refused(f"the parts are words ({' and '.join(_accounts.PARTS)}): nothing was changed")
    if not words or any(w not in _accounts.PARTS for w in words):
        shown = " ".join(words)[:80] or "none"
        raise Refused(f"the parts are {' and '.join(_accounts.PARTS)}, not {shown}: nothing was changed")
    return tuple(dict.fromkeys(words))


def _digest(digest) -> str:
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise Refused("a change is confirmed by its plan's sha256, as its form shows it: review it again; nothing was "
                      "changed")
    return digest


def _password(password) -> str | None:
    if password is None or password == "":
        return None
    if not isinstance(password, str):
        raise Refused("a password is words: nothing was changed")
    return password


def _accepts(change: _accounts.Change, given: dict) -> dict:
    """What the click accepted, for each of `change`'s asks in order: an ask counts as accepted once it, or an ask
    before it, was. The refusal names the first ask left and holds every sentence left, so the one second confirmation
    that accepts it has shown them all."""
    out: dict[str, bool] = {}
    seen = False
    for name, _ in change.asks:
        seen = seen or given.get(name) is True
        out[name] = seen
    return out


def _one_accept(e: Refused) -> Refused:
    """The refusal with one argument to accept (the platform's page offers one, a plain name): its first."""
    names = (e.accept or "").split()
    if len(names) <= 1:
        return e
    return Refused(str(e), names[0])


def _sentence(text: str) -> str:
    text = str(text).strip()
    return text if text.endswith((".", ":")) else f"{text}."


def _fixed(name: str, label: str, value: str, title: str) -> dict:
    return {"name": name, "label": label, "type": "fixed", "value": value,
            "choices": [{"value": value, "title": title}]}


def _accept(name: str, title: str, yes: str, words: str = "") -> dict:
    return {"name": name, "type": "accept", "title": title, "yes": yes, "words": words}


# ---- the base ------------------------------------------------------------------------------------------------------


class LinuxAdmin(Admin):
    """The Linux standard interface: Linux administration's base, the accounts and the elevation over Admin."""

    HOOKS = (*Admin.HOOKS, "linux_facts", "linux_apply", "linux_member", "linux_undo")
    READ_HOOKS = ("linux_facts",)
    SERVICE_HOOKS = ("linux_facts",)  # other plugins ask it through the platform
    PAGE_ONLY_HOOKS = ("linux_apply", "linux_member", "linux_undo")  # the user's answer 6
    PLUGIN_ONLY_HOOKS = ()  # none carries a command (B1): release two's linux_run and linux_grant will
    INTERNAL_NOTES = (
        "A password is never kept: one try per click, handed to sudo on its standard input only after its own prompt.",
        "The facts are kept 300 s, and sudo's listing is read at most once in 300 s (each read may write a line in the "
        "system's log).",
        "What Liminal made is in /var/lib/liminal-linux/MADE, a journal root writes as a change goes and anyone reads.",
    )
    STEP_WAIT_S = STEP_WAIT_S

    # -- the backend: what a subclass hands (its stand-ins in tests) ---------------------------------------------------
    def linux_run(self, argv, timeout):
        """A read on this Linux as the platform's user (the probe, sudo's listing), answering as subprocess.run does,
        with text."""
        return proctree.run(list(argv), timeout, text=True, env=inherited())  # no LIMINAL_* name

    def linux_spawn(self, argv):
        """sudo's conversation started with byte pipes, owned by this plugin in the process ledger, so its stop ends
        what is left of it (lifecycle.end_owned)."""
        from .. import lifecycle

        return lifecycle.spawn(list(argv), self.name or "linux-admin", KIND, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, env=inherited())

    def linux_python(self) -> str:
        """The Python the one root command names: this one (a subclass's test gives another)."""
        return str(getattr(self, "_python", None) or sys.executable)

    # -- its own state ---------------------------------------------------------------------------------------------
    def _linux_state(self) -> _State:
        st = self.__dict__.get(_STATE)
        if st is None:
            with _STATES:
                st = self.__dict__.setdefault(_STATE, _State())
        return st

    def __copy__(self):
        """A copy (Plugin.with_) has a LinuxSystem, a stop and changes of its own, never this one's."""
        out = type(self).__new__(type(self))
        out.__dict__.update({k: v for k, v in self.__dict__.items() if k != _STATE})
        return out

    def linux_system(self) -> linuxsys.LinuxSystem:
        """This Linux as linuxsys knows it, through linux_run and linux_spawn: one for the plugin, kept."""
        st = self._linux_state()
        with st.lock:
            if st.system is None:
                # looked up at each call, so what a subclass or a test hands later is what runs
                st.system = linuxsys.LinuxSystem(lambda argv, timeout=None: self.linux_run(argv, timeout),
                                                 lambda argv: self.linux_spawn(argv), python=self.linux_python())
            return st.system

    def attach(self, app, login) -> dict:
        """Attached by its app: a stop of before (a platform stopped, started again in this process) no longer
        holds."""
        out = super().attach(app, login)
        self._linux_state().stop.clear()
        return out

    def app_stopping(self) -> None:
        """Told to end (Plugin.signal's TERM): every change refuses from now on; a conversation before its script's
        begin line is ended (nothing ran), and one whose script has begun finishes its step. It waits for that at most
        STEP_WAIT_S, then returns: what was started for the plugin is ended after it (lifecycle.end_owned). It bears a
        second call."""
        parent = getattr(super(), "app_stopping", None)
        if callable(parent):
            parent()
        st = self._linux_state()
        st.stop.set()
        end = time.monotonic() + float(self.STEP_WAIT_S)
        with st.cv:
            while st.busy and (left := end - time.monotonic()) > 0:
                st.cv.wait(min(left, _elevation.STEP_S))

    @contextlib.contextmanager
    def _changing(self):
        st = self._linux_state()
        with st.cv:
            if st.stop.is_set():
                raise Refused(STOPPING)
            st.busy += 1
        try:
            yield st
        finally:
            with st.cv:
                st.busy -= 1
                st.cv.notify_all()

    # -- the hooks -------------------------------------------------------------------------------------------------
    def linux_facts(self, fresh: bool = False) -> dict:
        """This Linux's facts, the way root is had, Liminal's accounts and what its journal says, as JSON (`fresh`: read
        again now; sudo's listing stays kept for its 300 s)."""
        note = self.not_for_here()
        if note:
            return {"applies": False, "why": note}
        s = self.linux_system()
        if fresh is True:
            s.facts(fresh=True)
        return {"applies": True, **s.describe()}

    def linux_apply(self, parts, digest, accept_members: bool = False, accept_unasked: bool = False,
                    password: str | None = None) -> dict:
        """Make them...: the group liminal with the platform's user in it, and (part "service-user") Liminal's own
        system user, as the confirmed plan of sha256 `digest` says; asked only from the page."""
        asking.check(self, "linux_apply")
        wanted = _parts(parts)
        return self._change(lambda s: s.plan_make(wanted), digest, password,
                            {"accept_members": accept_members, "accept_unasked": accept_unasked})

    def linux_member(self, user, action, digest, accept_member: bool = False, accept_unasked: bool = False,
                     password: str | None = None) -> dict:
        """Add or Remove a member...: `user` added to the group liminal or taken out of it (`action` add or remove; in
        liminal only), as the confirmed plan of sha256 `digest` says; asked only from the page."""
        asking.check(self, "linux_member")
        if not isinstance(user, str) or not isinstance(action, str):
            raise Refused("a member is a user's name and add or remove: nothing was changed")
        return self._change(lambda s: s.plan_member(user, action), digest, password,
                            {"accept_member": accept_member, "accept_unasked": accept_unasked})

    def linux_undo(self, digest, accept_removal: bool = False, accept_unasked: bool = False,
                   password: str | None = None) -> dict:
        """Remove them...: what the journal says Liminal made or added here and that still matches, taken back, as the
        confirmed plan of sha256 `digest` says; always asked twice, and only from the page."""
        asking.check(self, "linux_undo")
        return self._change(lambda s: s.plan_undo(), digest, password,
                            {"accept_removal": accept_removal, "accept_unasked": accept_unasked})

    def _change(self, build, digest, password, given: dict) -> dict:
        """A change built from fresh facts, its asks and its digest held before sudo starts, run as root; its answer
        {said, lines, ok}."""
        note = self.not_for_here()
        if note:
            raise Refused(note)
        digest, password = _digest(digest), _password(password)
        with self._changing() as st:
            s = self.linux_system()
            s.facts(fresh=True)
            change = build(s)
            try:
                done = s.apply(change, password, digest=digest, stop=st.stop, **_accepts(change, given))
            except _elevation.WhosePassword as e:
                st.whose = e.whose
                raise
            except Refused as e:
                raise _one_accept(e) from None
            st.whose = ""
        return {"said": done["said"], "lines": list(done["lines"]), "ok": done["code"] == 0}

    # -- the page --------------------------------------------------------------------------------------------------
    def status(self) -> dict:
        """The Admin base's status, with "How root is had" and "Liminal's user and group" first, their forms, and
        "This Linux" last."""
        out = super().status()
        if not out.get("present") or out.get("applies") is False:
            return out
        try:
            tables, forms, this, state = self.linux_sections()
        except Exception as e:  # noqa: BLE001 - a read that fails is said on the page, the base's sections stay
            tables = [{"title": "Liminal's user and group", "columns": [{"title": "What"}], "rows": [],
                       "empty": f"cannot be read: {type(e).__name__}: {e}"[:400]}]
            forms, this, state = [], None, None
        out["tables"] = [*tables, *out.get("tables", []), *([this] if this else [])]
        out["forms"] = [*forms, *out.get("forms", [])]
        if state is not None:
            out["linuxAccounts"] = state
            out["summary"] = (f"{out.get('summary', '')}; the group {NAME}: "
                              + ("here" if state.get("group") else "not here"))
        return out

    def linux_sections(self) -> tuple[list[dict], list[dict], dict, dict]:
        """The two tables of release one, their forms, the This Linux table and the accounts' state."""
        s = self.linux_system()
        f = s.facts()
        el = s.elevation()
        said = el.words()
        tool = s.accounts()
        state = tool.state()
        table, forms = self.accounts_section(s, tool, state, said)
        return [self.root_table(said), table], forms, self.this_linux_table(f), state

    def root_table(self, said: dict) -> dict:
        """How root is had: the way, what a change asks here, that sudo logs each change's script."""
        whose = {"self": "your own password", "root": "root's password"}.get(said.get("whose", ""), "")
        tool = said.get("tool", "none")
        field = said.get("field", "impossible")
        row = [{"text": TOOLS.get(tool, tool), "sub": "; ".join(w for w in (said.get("version", ""), whose) if w)},
               {"text": ASKS.get(field, field), "sub": said.get("label") or said.get("why") or ""},
               said.get("logged") or "–"]
        note = ("How a change of Liminal's user and group has root here. " + (said.get("note", "").capitalize() + "."
                                                                              if said.get("note") else ""))
        return {"title": "How root is had", "note": note.strip(), "rows": [row],
                "columns": [{"title": "Root through"}, {"title": "A change asks"}, {"title": "Logged"}]}

    def _password_field(self, said: dict) -> dict:
        whose = self._linux_state().whose
        label = (f"{whose}'s password (this system's sudo asks for it)" if whose else
                 said.get("label") or "Your password for sudo")
        return {"name": "password", "label": label, "type": "password", "required": True,
                "note": said.get("note") or _elevation.NOTE}

    def _form(self, fid: str, hook: str, title: str, fields: list, change: _accounts.Change, said: dict,
              yes: str, danger: bool = False) -> dict:
        """A change's form: its fixed words, then its plan's sha256 (the caller adds the accepts and the password field
        after it, in the hook's order), and its confirmation with the plan's steps and that sudo logs it."""
        out = [*fields, _fixed("digest", "Plan", change.digest, f"sha256 {change.digest[:16]}…")]
        words = " ".join(_sentence(w) for w in change.plan.words())
        if said.get("logged"):
            words += f" {_sentence(said['logged'][:1].upper() + said['logged'][1:])}"
        return {"id": fid, "hook": hook, "title": title, "submit": "Review", "fields": out,
                "confirm": {"title": f"{title}?", "yes": yes, "words": words, **({"danger": True} if danger else {})}}

    def accounts_section(self, s: linuxsys.LinuxSystem, tool: _accounts.AccountTool, state: dict,
                         said: dict) -> tuple[dict, list[dict]]:
        """Liminal's user and group: the group, the user, each member (in the group, and in the running platform),
        a change stopped part way, the one command; and the forms Make them..., Add a member..., Remove a member...,
        Remove them..., where a change can be made from this page."""
        f = s.facts()
        field = said.get("field", "impossible")
        changes = field in ("yes", "no")
        password = [self._password_field(said)] if field == "yes" else []
        platform = s.platform_member()
        g, u = state.get("group"), state.get("user")
        rows: list[list] = []
        forms: list[dict] = []
        actions: list[dict] = []
        unasked = _accept("accept_unasked", "No password is asked here: go on?", "Go on")

        def form(fid, hook, title, fields, accepts, change, yes, danger=False):
            made = self._form(fid, hook, title, fields, change, said, yes, danger)
            made["fields"] = [*made["fields"], *accepts, unasked, *password]
            forms.append(made)
            return made

        # the group and the user
        if g is None:
            rows.append([f"The group {NAME}", "not here", ""])
        else:
            kind = "a system group" if g.get("system") else "not a system group"
            rows.append([f"The group {NAME}", {"text": f"gid {g['gid']}", "sub": f"{kind}; {BY.get(g['by'], g['by'])}"},
                         ""])
        if u is None:
            rows.append([f"The user {NAME}",
                         {"text": "not here", "sub": "Liminal's own system user; nothing runs as it yet"}, ""])
        else:
            kind = "a system account" if u.get("system") else "a person's account"
            rows.append([f"The user {NAME}", {"text": f"uid {u['uid']}",
                                              "sub": f"{kind}; shell {u['shell'] or '–'}; home {u['home'] or '–'}; "
                                                     f"{BY.get(u['by'], u['by'])}"}, ""])
        # the members
        group = tool.group
        running = set(f.elevation.get("running_gids", ()))
        again = "start the platform again from a new terminal" + (" tab" if f.kernel.wsl else "")
        for name in state.get("members", ()):
            listed = group is not None and name in group.members
            how = "a member" if listed else f"{NAME} is its primary group"
            if name == platform:
                how += ("; in the running platform" if group is not None and group.gid in running else
                        f"; not yet in the running platform: {again}")
            cell = ""
            if changes and listed:
                try:
                    change = s.plan_member(name, "remove")
                except Refused:
                    change = None
                if change is not None and change.plan.steps and not change.plan.refused:
                    fid = f"linux-member-remove:{name}"
                    form(fid, "linux_member", f"Take {name} out of the group {NAME}",
                         [_fixed("user", "User", name, name), _fixed("action", "Change", "remove", "take out")],
                         [_accept("accept_member", f"Take {name} out of {NAME}?", "Take it out")], change,
                         "Take it out", True)
                    cell = {"form": fid, "title": "Remove…", "label": f"Take {name} out of {NAME}"}
            rows.append([{"text": name, "sub": "the platform's user" if name == platform else "a member"}, how, cell])
        # a change stopped part way
        stopped = state.get("stopped")
        if stopped:
            title = WHAT.get(stopped.get("what"), "A change")
            done = [w for _, w, st in stopped.get("steps", ()) if st == "done"]
            begun = [w for _, w, st in stopped.get("steps", ()) if st != "done"]
            words = (f"{title} stopped part way" + (f"; done: {', '.join(done)}" if done else "")
                     + (f"; begun, not finished: {', '.join(begun)}" if begun else "") + f"; {title} again finishes it")
            rows.append(["A change stopped part way", words, ""])
        # Make them...
        make = s.plan_make()
        if make.plan.refused:
            rows.append(["Make them…", make.plan.refused, ""])
        elif not make.plan.nothing and changes:
            parts = " ".join(_accounts.PARTS)
            who = f" with {platform} in it" if platform else ""
            form("linux-make", "linux_apply", "Make Liminal's user and group",
                 [_fixed("parts", "Parts", parts, f"the group {NAME}{who}, and Liminal's own system user")],
                 [_accept("accept_members", f"Take the group {NAME} as it is?", "Take it")], make, "Make them")
            actions.append({"form": "linux-make", "title": "Make them…"})
        # Add a member...
        if changes and group is not None:
            members = tool.members()
            offered = 0
            for name in sorted(tool.users):
                account = tool.users[name]
                if (offered >= CANDIDATES_MAX or name in members or name == NAME or account.uid == 0
                        or not (name == platform or tool.login_account(account))):
                    continue
                try:
                    change = s.plan_member(name, "add")
                except Refused:
                    continue
                if change.plan.refused or not change.plan.steps:
                    continue
                offered += 1
                fid = f"linux-member-add:{name}"
                form(fid, "linux_member", f"Add {name} to the group {NAME}",
                     [_fixed("user", "User", name, name), _fixed("action", "Change", "add", "add")],
                     [_accept("accept_member", f"Add {name} to {NAME}?", "Add it")], change, "Add it")
                actions.append({"form": fid, "title": f"Add {name}…"})
        # Remove them...
        undo = s.plan_undo()
        if changes and undo.plan.steps and not undo.plan.refused:
            form("linux-undo", "linux_undo", "Remove what Liminal made",
                 [], [_accept("accept_removal", "Remove them for good?", "Remove them")], undo, "Remove them",
                 True)
            actions.append({"form": "linux-undo", "title": "Remove them…"})
        elif undo.plan.refused and (g is not None or u is not None):
            rows.append(["Remove them…", undo.plan.refused, ""])
        if not changes:
            rows.append(["Changes here", said.get("why") or ASKS.get(field, field), ""])
        line = said.get("line") or ""
        rows.append(["The one command", {"text": line, "sub": "as root, from a terminal: it asks nothing"}, ""])
        notes = list(state.get("notes", ()))
        table = {"title": "Liminal's user and group", "rows": rows,
                 "note": (f"Liminal's own group {NAME}, with the platform's user in it, and its own system user "
                          f"{NAME}, made, changed and taken back here or by the one command; each change is confirmed "
                          "first, with its plan's sha256"
                          + (". " + " ".join(_sentence(n) for n in notes) if notes else ".")),
                 "columns": [{"title": "What"}, {"title": "Here"}, {"title": "Change"}]}
        if actions:
            table["actions"] = actions
        return table, forms

    def this_linux_table(self, f) -> dict:
        """This Linux as the probe read it: the distribution, the kernel, the init, the account tool, the tools, what is
        read-only, the security modules; what could not be read in its note."""
        k = f.kernel
        where = (f"WSL {k.wsl_generation or 2}: {k.wsl}" if k.wsl else f"in a container ({k.container})" if k.container
                 else "a machine of its own")
        read_only = [p for p, ro in (f.layout.get("read_only") or {}).items() if ro]
        layout = [w for w, on in (("ostree", f.layout.get("ostree")), ("NixOS", f.layout.get("nixos"))) if on]
        tool = f.accounts.get("tool", "none")
        sysusers = f.accounts.get("sysusers") or 0
        rows = [["Distribution", f.os.get("pretty") or f.os.get("id") or "–",
                 f"family {f.os.get('family') or '–'}"],
                ["Kernel", f"{k.release or '–'} ({k.machine or '–'})", where],
                ["Init", f.init.get("pid1") or "–",
                 f"systemd {f.init.get('version')}" if f.init.get("systemd") and f.init.get("version") else
                 "systemd" if f.init.get("systemd") else "not systemd"],
                ["Accounts", ACCOUNT_TOOLS.get(tool, tool), f"systemd-sysusers {sysusers}" if sysusers else "–"],
                ["Core tools", f.coreutils or "–", "flock: the lock is the kernel's" if f.lock == "flock" else
                 "no flock: the lock is a folder"],
                ["Read-only", ", ".join(read_only) or "none", ", ".join(layout) or "–"],
                ["Security", f"SELinux {f.security.get('selinux') or '–'}",
                 f"AppArmor {f.security.get('apparmor') or '–'}"]]
        notes = " ".join(_sentence(n) for n in f.notes)
        return {"title": "This Linux", "note": ("What the read found." + (f" Not read: {notes}" if notes else "")),
                "columns": [{"title": "What"}, {"title": "Here"}, {"title": "Details"}], "rows": rows}
