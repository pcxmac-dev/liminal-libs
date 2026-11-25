"""One plan holder for every change one plugin carries out for another (1.93.0; the designs of 2026-11-23,
service-containers-design §3.6 and service-containers-networking §8.2; the user, 2026-11-23: "please more approvals").

A change a plugin asks of another (a container plugin's service installed, a firewall's route made) is first a `Plan`:
the change in the words of the plugin that will carry it out, held in memory (MAX_PLANS at most, PLAN_S each), bound to
its owner (the plugin that asked for it), its action, its subject (a service's sid) and its target, and to a digest of
the facts its words rest on. You approve it from the page alone (the holder's page-only hook), naming each accept the
plan asks in turn: an accept is taken only when it is exactly True. An approval is used once. When its owner asks for
it to be carried out, the facts are read again and compared (`take`): anything that differs refuses and drops the plan,
so what runs is what you approved.

A plan that only takes away (`narrows`: a route taken away at Remove) needs no approval of its own, but may hold
nothing that opens. A plan with nothing to change (`nothing`, in words) is never put to you.

This module holds no thread and starts nothing. Every answer is plain JSON. A refusal is an instances.Refusal in words,
naming the accept it takes (`accept`)."""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Mapping

from ..instances import Refusal

PLAN_S = 600.0  # a plan is approved, and carried out, within ten minutes of being made
MAX_PLANS = 16  # plans held at once, in memory alone, never on disk
GONE = "it expired, was used or declined, or its plugin was turned off since: plan it again"


def digest(facts: Mapping) -> str:
    """The sha256 of facts as canonical JSON (sorted keys, no spaces): the same facts give the same digest."""
    raw = json.dumps(facts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def exactly(value) -> bool:
    """Whether an accepting argument is True itself: a page's true. Nothing else accepts ("true", 1, "yes")."""
    return value is True


@dataclass(frozen=True)
class Accept:
    """A second confirmation a plan needs: its argument's `name` (accept_lan), and what the page asks it with."""

    name: str
    title: str
    words: str
    yes: str = "Accept"

    def as_dict(self) -> dict:
        return {"name": self.name, "title": self.title, "words": self.words, "yes": self.yes}

    @classmethod
    def of(cls, m: Mapping) -> "Accept":
        return cls(str(m["name"]), str(m.get("title", "")), str(m.get("words", "")), str(m.get("yes", "Accept")))


@dataclass(frozen=True)
class Plan:
    """A change held for your approval. `facts` (what its words rest on) never leaves the holder: only its digest is
    said. `extra`: what the plan's words carry besides (its steps' details, the network plans it rests on)."""

    plan: str
    owner: str
    action: str
    subject: str
    target: str
    title: str
    words: str
    made: float
    expires: float
    steps: tuple = ()
    accepts: tuple = ()  # Accept, in the order they are asked
    facts: Mapping = field(default_factory=dict, compare=False, repr=False)
    bound: str = ""  # the digest of what it was made for (a spec's sha, the options): compared at take
    danger: bool = False
    narrows: bool = False
    nothing: str = ""
    refused: str = ""
    approved: bool = False
    used: bool = False
    extra: Mapping = field(default_factory=dict, compare=False)

    @property
    def facts_digest(self) -> str:
        return digest(self.facts)

    def needs(self) -> tuple[str, ...]:
        return tuple(a.name for a in self.accepts)

    def as_dict(self, now: float | None = None) -> dict:
        """What the page and the owner are told of it (plan_words): never its facts, only their digest."""
        left = None if now is None else max(0.0, self.expires - now)
        return {"plan": self.plan, "owner": self.owner, "action": self.action, "sid": self.subject,
                "target": self.target, "title": self.title, "words": self.words, "steps": list(self.steps),
                "accepts": [a.as_dict() for a in self.accepts], "danger": self.danger, "narrows": self.narrows,
                "nothing": self.nothing, "refused": self.refused, "approved": self.approved, "used": self.used,
                "facts": self.facts_digest, "expires_in": left, **{k: v for k, v in dict(self.extra).items()
                                                                     if k not in ("facts",)}}


class Plans:
    """The plans one plugin holds (`prefix` names them: "p-" for a container plugin's, "n-" for a firewall's), with a
    clock that is a test's when given. Thread-safe: every method takes the one lock briefly and asks nothing."""

    def __init__(self, prefix: str = "p-", clock: Callable[[], float] = time.monotonic, most: int = MAX_PLANS,
                 lasting: float = PLAN_S):
        self.prefix, self.clock, self.most, self.lasting = prefix, clock, most, lasting
        self._lock = threading.Lock()
        self._held: dict[str, Plan] = {}

    def _sweep(self, now: float) -> None:
        for k in [k for k, p in self._held.items() if p.expires <= now or p.used]:
            del self._held[k]

    def hold(self, *, owner: str, action: str, subject: str, target: str, title: str, words: str,
             facts: Mapping, steps=(), accepts=(), bound: str = "", danger: bool = False, narrows: bool = False,
             nothing: str = "", refused: str = "", extra: Mapping | None = None) -> Plan:
        """A plan made and held (one that is refused, or has nothing to change, is answered and never held). Refused
        when MAX_PLANS are waiting already."""
        if not owner or not isinstance(owner, str):
            raise Refusal("a plan is held for the plugin that asked for it, and no plugin was named")
        now = self.clock()
        pid = self.prefix + secrets.token_hex(8)
        plan = Plan(pid, owner, action, subject, target, title, words, now, now + self.lasting, tuple(steps),
                    tuple(accepts), dict(facts), bound, danger, narrows, nothing, refused, False, False,
                    dict(extra or {}))
        if refused or nothing:
            return plan
        with self._lock:
            self._sweep(now)
            if len(self._held) >= self.most:
                raise Refusal(f"{self.most} plans wait for an answer already: approve or decline one first")
            self._held[pid] = plan
        return plan

    def get(self, plan: str) -> Plan:
        """The plan held under that id; a Refusal in words when none is."""
        key = str(plan or "")
        with self._lock:
            self._sweep(self.clock())
            found = self._held.get(key)
        if found is None:
            raise Refusal(f"no plan {key[:40]!r} is held: {GONE}")
        return found

    def waiting(self) -> list[Plan]:
        """The plans held now, oldest first."""
        with self._lock:
            self._sweep(self.clock())
            return sorted(self._held.values(), key=lambda p: p.made)

    def words(self, plan: str) -> dict:
        p = self.get(plan)
        return p.as_dict(self.clock())

    def approve(self, plan: str, accepts: Mapping[str, object]) -> Plan:
        """Your approval: refused, naming the first accept it lacks, until every accept the plan names is exactly True.
        A plan that only narrows, or approved already, is refused too (nothing to approve twice)."""
        with self._lock:
            self._sweep(self.clock())
            p = self._held.get(str(plan or ""))
            if p is None:
                raise Refusal(f"no plan {str(plan or '')[:40]!r} is held: {GONE}")
            if p.approved:
                raise Refusal(f"{p.title}: approved already, and an approval is used once")
            for a in p.accepts:
                if not exactly(accepts.get(a.name)):
                    raise Refusal(f"{p.title}: {a.words}", accept=a.name)
            approved = replace(p, approved=True)
            self._held[p.plan] = approved
            return approved

    def decline(self, plan: str) -> Plan | None:
        """The plan forgotten; what it was, or None when it was held no more."""
        with self._lock:
            return self._held.pop(str(plan or ""), None)

    def take(self, plan: str, owner: str, facts: Mapping, bound: str | None = None) -> Plan:
        """The plan, to be carried out now by its owner, once: refused when it is not held, not its owner's, not
        approved (a plan that narrows needs none), made for something else (`bound`), or when the facts read now
        differ from those its words rest on (then it is dropped: plan it again)."""
        key = str(plan or "")
        with self._lock:
            self._sweep(self.clock())
            p = self._held.get(key)
            if p is None:
                raise Refusal(f"no plan {key[:40]!r} is held: {GONE}")
            if p.owner != owner:
                raise Refusal(f"{p.title}: that plan is {p.owner}'s, and {owner or 'no one'} asked for it")
            if not p.approved and not p.narrows:
                raise Refusal(f"{p.title}: not approved yet: approve it on the page first")
            if bound is not None and bound != p.bound:
                raise Refusal(f"{p.title}: it was made for another change: plan it again")
            now_digest = digest(facts)
            if now_digest != p.facts_digest:
                del self._held[key]
                changed = sorted(k for k in set(p.facts) | set(facts) if p.facts.get(k) != facts.get(k))
                raise Refusal(f"what you approved is not what is there now ({', '.join(changed[:6]) or 'its facts'} "
                              "changed): plan it again")
            used = replace(p, used=True)
            del self._held[key]
            return used

    def forget_all(self) -> int:
        """Every plan forgotten (a detach): how many were held."""
        with self._lock:
            n = len(self._held)
            self._held.clear()
            return n


# -- an approved plan carried out: a work, a thread of the holder's own -------------------------------------------------
WORK_LINES, WORK_KEEP_S = 2000, 600.0  # a work's lines kept; a finished work kept ten minutes
JOIN_S = 30.0  # what turning a plugin off waits for each work it cancels


class Cancelled(Exception):
    """A work asked to stop, stopped between its steps (or inside a pull, whose child is ended)."""


class Work:
    """One plan carried out, in a thread of its holder's: its lines (masked by `mask`, WORK_LINES kept), whether it is
    done, ok and its answer. Read by `page(after)`: the lines after `after`, and the number to ask after next."""

    def __init__(self, wid: str, plan: Plan, key: str, mask: Callable[[str], str]):
        self.work, self.plan, self.key, self._mask = wid, plan, key, mask
        self.owner, self.action, self.sid = plan.owner, plan.action, plan.subject
        self._lock = threading.Lock()
        self._lines: list[str] = []
        self._first = 0  # the number of the first line still kept
        self.done, self.ok, self.answer = False, None, None
        self.cancel = threading.Event()
        self.thread: threading.Thread | None = None
        self.ended = 0.0

    def line(self, text) -> None:
        said = self._mask(" ".join(str(text).split("\n"))[:2000])
        with self._lock:
            self._lines.append(said)
            over = len(self._lines) - WORK_LINES
            if over > 0:
                del self._lines[:over]
                self._first += over

    def cancelled(self) -> bool:
        return self.cancel.is_set()

    def check(self) -> None:
        """Between steps: Cancelled once it was asked to stop."""
        if self.cancel.is_set():
            raise Cancelled("cancelled")

    def page(self, after: int = 0) -> dict:
        try:
            after = max(0, int(after))
        except (TypeError, ValueError):
            after = 0
        with self._lock:
            start = max(after, self._first)
            lines = self._lines[start - self._first:]
            return {"work": self.work, "plan": self.plan.plan, "action": self.action, "sid": self.sid, "lines": lines,
                    "next": self._first + len(self._lines), "done": self.done, "ok": self.ok, "answer": self.answer,
                    "cancelling": self.cancel.is_set() and not self.done, "dropped": start - after}


class Works:
    """The works a holder runs: one per key (a target, a stack) at a time; each in a thread of its own that ends with
    it. Finished works are kept WORK_KEEP_S for their owner to read."""

    def __init__(self, prefix: str = "w-", clock: Callable[[], float] = time.monotonic, name: str = "liminal-work"):
        self.prefix, self.clock, self.name = prefix, clock, name
        self._lock = threading.Lock()
        self._all: dict[str, Work] = {}

    def _sweep(self) -> None:
        now = self.clock()
        for k in [k for k, w in self._all.items() if w.done and now - w.ended > WORK_KEEP_S]:
            del self._all[k]

    def busy(self, key: str) -> Work | None:
        with self._lock:
            return next((w for w in self._all.values() if w.key == key and not w.done), None)

    def begin(self, plan: Plan, key: str, run: Callable[[Work], object], mask: Callable[[str], str],
              ready: Callable[[], None] | None = None) -> Work:
        """`run(work)` begun in a thread of its own for `plan`, refused while a work on `key` is under way. `ready`, when
        given, is called once the key is held and before the thread starts (the facts read again and the plan taken
        there): what it raises lets the key go and is raised."""
        with self._lock:
            self._sweep()
            under = next((w for w in self._all.values() if w.key == key and not w.done), None)
            if under is not None:
                raise Refusal(f"{under.plan.title} is being carried out on {key} now: one change at a time there")
            w = Work(self.prefix + secrets.token_hex(6), plan, key, mask)
            self._all[w.work] = w  # the key is held from here: a second begin on it is refused
        if ready is not None:  # outside the lock: a read of the engine never keeps a work's lines from being read
            try:
                ready()
            except BaseException:
                with self._lock:
                    self._all.pop(w.work, None)
                raise

        def body() -> None:
            try:
                answer = run(w)
                w.answer, w.ok = answer, not (isinstance(answer, Mapping) and answer.get("ok") is False)
            except Cancelled:
                w.line("cancelled: what was done is said above, and what was undone")
                w.answer, w.ok = {"said": "cancelled", "ok": False}, False
            except Exception as e:  # noqa: BLE001 - a step's failure, in its own words
                words = " ".join(str(e).split()) or type(e).__name__
                w.line(f"failed: {words}")
                w.answer, w.ok = {"said": w._mask(words), "ok": False}, False
            finally:
                w.ended = self.clock()
                w.done = True
        w.thread = threading.Thread(target=body, name=f"{self.name}-{w.work}", daemon=True)
        w.thread.start()
        return w

    def get(self, work: str) -> Work:
        with self._lock:
            self._sweep()
            w = self._all.get(str(work or ""))
        if w is None:
            raise Refusal(f"no work {str(work or '')[:40]!r} is held (it ended more than {WORK_KEEP_S / 60:g} minutes ago, "
                          "or its plugin was turned off)")
        return w

    def running(self) -> list[Work]:
        with self._lock:
            return [w for w in self._all.values() if not w.done]

    def all(self) -> list[Work]:
        with self._lock:
            self._sweep()
            return list(self._all.values())

    def cancel_all(self, join: float = JOIN_S) -> list[Work]:
        """Every work under way asked to stop, and joined (`join` seconds each at most): those that did not end."""
        under = self.running()
        for w in under:
            w.cancel.set()
        left = []
        for w in under:
            if w.thread is not None and w.thread is not threading.current_thread():
                w.thread.join(join)
                if w.thread.is_alive():
                    left.append(w)
        return left
