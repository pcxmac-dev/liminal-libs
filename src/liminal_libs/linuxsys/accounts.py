"""Liminal's own group and user, `liminal`, made, changed and taken back on this Linux (the linuxperm plan's 3.2, 3.6
and B4; the user's answers 2, 4, 5 and 8: undo deletes what Liminal made, Liminal's own WSL distributions' login user
`liminal` is adopted, systemd-sysusers on Debian and Ubuntu, the names always liminal).

`tool(facts)` gives the AccountTool for this system, by the probe's record (facts.accounts["tool"]):
- Sysusers: systemd's own systemd-sysusers, 255 or later: /etc/sysusers.d/liminal.conf (Liminal's comment,
  `g liminal -`, `u liminal -:liminal Liminal /var/lib/liminal <nologin>`), written beside its place and moved in,
  then `systemd-sysusers /etc/sysusers.d/liminal.conf`, which processes only the file named; members through gpasswd;
- Shadow: groupadd and useradd of a system account (`--gid`, `--no-create-home`, no expiry), gpasswd -a and -d
  (never `usermod -G` without `-a`), userdel, groupdel;
- BusyBox: addgroup -S, adduser -S -D -H, addgroup and delgroup for members, deluser, delgroup;
- NixAccounts: refused, with the lines for configuration.nix; NoAccounts: refused, in words.
Debian's `adduser --system` is not built: the user chose systemd-sysusers (answer 5), and every Debian without it has
shadow's tools.

Every choice is made here, in Python, from the facts and the folded journal (journal.fold); a plan's script holds
fixed guards and straight-line steps, each checked first. Make them... (`make`), Add and Remove a member... (`member`)
and Remove them... (`undo`) each give a Change: its Plan and what must be asked twice (`asks`, raised by `check`
before any conversation starts, so one confirmed click asks sudo once).

A group `liminal` already here is taken as found only when it is a system group whose members are the platform's
user, Liminal's user or persons' accounts; a person's account besides the platform's user is asked twice, by name. A
gid of GID_MIN or more, or root or another system account among its members, is refused. In Liminal's own WSL
distributions the login user `liminal` and its group are adopted: never removed, and no member but Liminal's own.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import journal, plan
from .facts import HELPERS_FOLDER, HOME, NAME, SYSUSERS
from .plan import Action, Plan, Step
from .shared import Refused, clean_user, clean_words, sh_word

__all__ = ["AccountTool", "Sysusers", "Shadow", "BusyBoxAccounts", "NixAccounts", "NoAccounts", "Change", "tool",
           "PARTS", "COMMENT", "conf_text", "WSL_PREFIX"]

PARTS = ("accounts", "service-user")  # the group with the platform's user as a member; Liminal's own system user
COMMENT = "# Liminal: its group and user"
WSL_PREFIX = "Liminal-"  # Liminal's own WSL distributions (L/machines/wsl.py's LIMINAL_PREFIX)
SYSUSERS_FOLDER = "/etc/sysusers.d"
NOLOGIN = "/usr/sbin/nologin"
# Folders within Liminal's own names that may carry the group liminal: each gets root's group back before it goes
OWN_FOLDERS = (HELPERS_FOLDER, HOME, journal.FOLDER)


def conf_text(user: bool, nologin: str) -> str:
    """Liminal's sysusers file: its comment, the group, and (`user`) Liminal's system user in it."""
    rows = [COMMENT, f"g {NAME} -"]
    if user:
        rows.append(f"u {NAME} -:{NAME} Liminal {HOME} {clean_words(nologin, 'a shell')}")
    return "\n".join(rows) + "\n"


@dataclass(frozen=True)
class Change:
    """A plan and what must be asked twice before it runs: (the argument that accepts it, its sentence)."""

    plan: Plan
    asks: tuple[tuple[str, str], ...] = ()

    @property
    def digest(self) -> str:
        return self.plan.digest

    def words(self) -> list[str]:
        return self.plan.words() + [s for _, s in self.asks]

    def with_ask(self, accept: str, sentence: str) -> "Change":
        return Change(self.plan, (*self.asks, (accept, sentence)))

    def check(self, **given) -> None:
        """Refuse, before anything starts, while an ask is not accepted: one refusal holding every sentence not yet
        accepted (a click gets one second confirmation at most), its `accept` the arguments that accept them, one
        space between each."""
        if self.plan.refused:
            raise Refused(self.plan.refused)
        left = [(a, s) for a, s in self.asks if not given.get(a)]
        if left:
            raise Refused(" ".join(s.rstrip(".") + "." for _, s in left), " ".join(dict.fromkeys(a for a, _ in left)))


class AccountTool:
    """The accounts on one system: what is here (`state`), and the plans that change it. A subclass renders each
    account step into its tool's sh; the Action it carries is what the stand-in plays."""

    kind = "none"

    def __init__(self, facts):
        self.facts = facts
        self.made = facts.made()
        acc = facts.accounts
        self.groups, self.users = acc.get("groups", {}), acc.get("users", {})
        self.group, self.user = self.groups.get(NAME), self.users.get(NAME)
        self.nologin = facts.layout.get("nologin") or NOLOGIN

    # ---- what is here ------------------------------------------------------------------------------------------

    def members(self) -> set[str]:
        """The group's members: its list and every user whose primary group it is (PLAN 1.6)."""
        g = self.group
        if g is None:
            return set()
        return set(g.members) | {u.name for u in self.users.values() if u.gid == g.gid}

    def group_ours(self) -> bool:
        return self.group is not None and self.made.group == self.group.gid

    def user_ours(self) -> bool:
        return self.user is not None and self.made.user is not None and self.made.user[0] == self.user.uid

    def adoptable(self) -> bool:
        """Whether this is one of Liminal's own WSL distributions whose login user `liminal`, in its own group, is to
        be adopted as Liminal's account (the user's answer 4)."""
        u, g = self.user, self.group
        return (self.facts.kernel.wsl.startswith(WSL_PREFIX) and u is not None and g is not None and u.gid == g.gid
                and u.uid >= self.facts.accounts.get("uid_min", 1000))

    def adopted(self) -> bool:
        a = self.made.adopted
        return (a is not None and self.user is not None and a[0] == self.user.uid) or self.adoptable()

    def person(self, name: str) -> bool:
        u = self.users.get(name)
        return u is not None and u.uid != 0 and not self.facts.system_account(u)

    def login_account(self, u) -> bool:
        """Whether `u` looks like a person's: a uid of UID_MIN or more and a login shell (whatever its name)."""
        return (u.uid >= self.facts.accounts.get("uid_min", 1000)
                and u.shell.rsplit("/", 1)[-1] not in ("nologin", "false"))

    def state(self) -> dict:
        """What the page's "Liminal's user and group" shows: the group, the user, each member, a change stopped part
        way."""
        g, u, made = self.group, self.user, self.made
        last = made.last
        return {
            "tool": self.kind,
            "group": None if g is None else {"gid": g.gid, "system": g.gid < self.facts.accounts.get("gid_min", 1000),
                                             "by": "liminal" if self.group_ours() else
                                             "adopted" if self.adopted() else "found"},
            "user": None if u is None else {"uid": u.uid, "gid": u.gid, "shell": u.shell, "home": u.home,
                                            "system": self.facts.system_account(u),
                                            "by": "liminal" if self.user_ours() else
                                            "adopted" if self.adopted() else "found"},
            "members": sorted(self.members() - {NAME}),
            "added": list(made.members),
            "stopped": None if not made.stopped or last is None else {
                "what": last.what, "steps": [list(s) for s in last.steps], "code": last.code},
            "notes": list(made.notes),
        }

    # ---- the steps, rendered by each tool ---------------------------------------------------------------------

    def group_step(self) -> Step:
        raise Refused(self.why())

    def user_step(self) -> Step:
        raise Refused(self.why())

    def sysusers_steps(self, need_group: bool, need_user: bool, user_line: bool) -> list[Step]:
        out = []
        if need_group:
            out.append(self.group_step())
        if need_user:
            out.append(self.user_step())
        return out

    def member_step(self, user: str) -> Step:
        q = sh_word(user, "a user")
        return Step(f"add {user} to the group {NAME}", Action.of("member", user=user, group=NAME, tool=self.kind),
                    _is_member(q), f"gpasswd -a {q} {NAME}")

    def unmember_step(self, user: str) -> Step:
        q = sh_word(user, "a user")
        return Step(f"take {user} out of the group {NAME}", Action.of("unmember", user=user, group=NAME,
                                                                       tool=self.kind),
                    f"! {_is_member(q)}", f"gpasswd -d {q} {NAME}")

    def unuser_step(self) -> Step:
        return Step(f"remove the user {NAME}", Action.of("unuser", name=NAME, tool=self.kind),
                    f"[ -z \"$(lm_uid {NAME})\" ]", f"userdel {NAME}")

    def ungroup_step(self) -> Step:
        return Step(f"remove the group {NAME}", Action.of("ungroup", name=NAME, tool=self.kind),
                    f"[ -z \"$(lm_gid {NAME})\" ]", f"groupdel {NAME}")

    def move_step(self, gid: int) -> Step | None:
        gid = int(gid)
        return Step(f"move the user {NAME} onto the group of gid {gid}, so removing it keeps the group {NAME}",
                    Action.of("move", name=NAME, gid=gid, tool=self.kind),
                    f"[ \"$(lm_ugid {NAME})\" = '{gid}' ]", f"usermod -g '{gid}' {NAME}")

    def why(self) -> str:
        return ("no account tool Liminal knows is here (systemd-sysusers 255 or later, shadow's groupadd and useradd, "
                "BusyBox's addgroup and adduser): Liminal's user and group cannot be made here")

    # ---- refusals shared by every change ----------------------------------------------------------------------

    def refusal(self) -> str:
        """Why no change can be made here at all, in words, or ""."""
        f = self.facts
        for path in ("/etc", "/var/lib"):
            if f.layout.get("read_only", {}).get(path):
                return (f"{path} is read-only here: Liminal's user and group cannot be made; give this system a "
                        "writable /etc and /var")
        for path in plan.CHAINS:
            if words := f.chain(path):
                return words
        return ""

    def _found(self, member: str | None) -> tuple[str, tuple[tuple[str, str], ...]]:
        """3.2's rule for what is here under the name liminal and was not made by Liminal: (a refusal, the asks)."""
        f, g, u = self.facts, self.group, self.user
        asks: list[tuple[str, str]] = []
        if u is not None and not self.user_ours() and not self.adopted() and self.login_account(u):
            return (f"a user named {NAME} is here and is a person's account (uid {u.uid}): Liminal's user and group "
                    "are not made; rename that user first"), ()
        if g is None or self.group_ours():
            return "", ()
        if self.adopted():
            others = sorted(self.members() - {NAME})
            if others:
                return (f"the group {NAME} of this Liminal distribution's login user also holds {', '.join(others)}: "
                        "Liminal's own group takes no member but Liminal's own; take them out of it first"), ()
            return "", ()
        if g.gid >= f.accounts.get("gid_min", 1000):
            return (f"a group named {NAME} is here and is not a system group (gid {g.gid}): Liminal's user and group "
                    "are not made; rename that group first"), ()
        platform = f.elevation.get("user", "")
        persons = []
        for name in sorted(self.members()):
            if name in (platform, NAME, member):
                continue
            who = self.users.get(name)
            if who is None or who.uid == 0 or f.system_account(who):
                return (f"the group {NAME} here has the member {name}, "
                        f"{'root' if who is not None and who.uid == 0 else 'a system account'}: it may be another "
                        f"program's group; Liminal's user and group are not made; rename that group first"), ()
            persons.append(name)
        for name in persons:
            asks.append(("accept_members", f"the group {NAME} is here already with {name} in it: once a grant names "
                                           f"%{NAME}, {name} gets every Liminal privilege"))
        return "", tuple(asks)

    # ---- Make them... -----------------------------------------------------------------------------------------

    def make(self, parts=PARTS, member: str | None = None) -> Change:
        """The plan that makes the group (and, with "service-user", Liminal's user) and adds `member` (the platform's
        user; None when it is root and no one is named)."""
        parts = tuple(parts or PARTS)
        if not parts or any(p not in PARTS for p in parts):
            raise Refused(f"the parts are {' and '.join(PARTS)}, not {' '.join(parts) or 'none'}: nothing was changed")
        f = self.facts
        if member is not None:
            member = clean_user(member)
        if (why := self.refusal() or self.tool_refusal(member)):
            return Change(Plan("apply", refused=why, lock=f.lock))
        found, asks = self._found(member)
        if found:
            return Change(Plan("apply", refused=found, lock=f.lock))
        if member is not None and (why := self._member_refusal(member, "add")):
            return Change(Plan("apply", refused=why, lock=f.lock))
        steps: list[Step] = []
        notes: list[str] = []
        if self.adopted():
            a = self.made.adopted
            if a is None or a[0] != self.user.uid:
                steps.append(plan.adopt(NAME, self.user.uid, self.user.gid))
            notes.append(f"the user {NAME} is this Liminal distribution's login user: it is taken as Liminal's own, "
                         "and undo never removes it")
        else:
            need_group = self.group is None
            need_user = "service-user" in parts and self.user is None
            try:
                steps += self.sysusers_steps(need_group, need_user, "service-user" in parts)
            except Refused as e:  # a sysusers file here that is not Liminal's
                return Change(Plan("apply", refused=str(e), lock=f.lock))
            if self.user is not None and not self.user_ours():
                notes.append(f"the user {NAME} was here before Liminal (uid {self.user.uid}): it is taken as it is, "
                             "and undo keeps it")
            if self.group is not None and not self.group_ours():
                notes.append(f"the group {NAME} was here before Liminal (gid {self.group.gid}): it is taken as it is, "
                             "and undo keeps it")
        if member is not None and member != NAME and member not in self.members():
            steps.append(self.member_step(member))
        if steps and f.security.get("selinux") == "enforcing" and f.security.get("restorecon"):
            written = [p for p in (SYSUSERS_FOLDER, SYSUSERS) if any(s.action.get("path") == p for s in steps)]
            steps.append(plan.relabel([*written, journal.FOLDER, journal.PATH]))
        return Change(Plan("apply", tuple(steps), notes=tuple(notes), guards=self.guards(), lock=f.lock),
                      asks if steps else ())

    def tool_refusal(self, member: str | None) -> str:
        return ""

    def guards(self, undo: bool = False) -> tuple[plan.Guard, ...]:
        g, u = self.group, self.user
        out = [plan.group_guard(NAME, None if g is None else g.gid),
               *plan.user_guard(NAME, None if u is None else u.uid, None if u is None else u.gid)]
        if g is not None:
            out.append(plan.members_guard(NAME, g.members))
        return tuple(out)

    # ---- Add a member..., Remove a member... ------------------------------------------------------------------

    def _member_refusal(self, user: str, action: str) -> str:
        if action == "add":
            if user == NAME:
                return ""
            if self.adopted():
                return (f"the group {NAME} is this Liminal distribution's own: it takes no member but Liminal's own; "
                        "nothing was changed")
            who = self.users.get(user)
            if who is None:
                return f"no user named {user} is here: nothing was changed"
            platform = self.facts.elevation.get("user", "")
            if who.uid == 0:
                return f"root is never a member of {NAME}: nothing was changed"
            if user != platform and self.facts.system_account(who):
                return (f"{user} is a system account: a member of {NAME} is the platform's user or a person's account; "
                        "nothing was changed")
        return ""

    def member(self, user: str, action: str) -> Change:
        """Add `user` to the group liminal, or take it out (only liminal: S6)."""
        user = clean_user(user)
        if action not in ("add", "remove"):
            raise Refused(f"a member is added or removed, not {action!r}: nothing was changed")
        f, g = self.facts, self.group
        if why := self.refusal() or self.tool_refusal(None):
            return Change(Plan("member", refused=why, lock=f.lock))
        if g is None:
            return Change(Plan("member", refused=f"the group {NAME} is not here: Make them... first", lock=f.lock))
        if why := self._member_refusal(user, action):
            return Change(Plan("member", refused=why, lock=f.lock))
        platform = f.elevation.get("user", "")
        asks: tuple[tuple[str, str], ...] = ()
        steps: tuple[Step, ...] = ()
        if action == "add" and user not in self.members():
            steps = (self.member_step(user),)
            if user != platform:
                asks = (("accept_member", f"it gives {user} every Liminal privilege"),)
        elif action == "remove" and user in g.members:
            steps = (self.unmember_step(user),)
            if user == platform:
                asks = (("accept_member", "the platform's Liminal rights end at its next start"),)
        elif action == "remove" and user in self.members():
            return Change(Plan("member", refused=f"{NAME} is {user}'s primary group, so it cannot be taken out of it "
                                                 "as a member: nothing was changed", lock=f.lock))
        return Change(Plan("member", steps, guards=(plan.group_guard(NAME, g.gid), plan.members_guard(NAME, g.members)),
                           lock=f.lock), asks)

    # ---- Remove them... ---------------------------------------------------------------------------------------

    def undo(self) -> Change:
        """The plan that takes back what the journal says Liminal made or added and that still matches; anything else
        is named and kept (B4 3 to 7). Always asked twice."""
        f, g, u, made = self.facts, self.group, self.user, self.made
        if why := self.refusal() or self.tool_refusal(None):
            return Change(Plan("undo", refused=why, lock=f.lock))
        procs = f.liminal.get("processes") or ()
        if procs and self.user_ours():
            return Change(Plan("undo", refused=(f"a process of the user {NAME} runs ({'; '.join(procs)[:300]}): stop "
                                                "it first; nothing was changed"), lock=f.lock))
        steps: list[Step] = []
        notes: list[str] = []
        kept = False
        here = f.here()
        has_journal = f.liminal.get("journal") is not None
        conf = f.liminal.get("sysusers")
        # 1. the sysusers file first: a later boot's systemd-sysusers.service cannot make the accounts again
        sha = here.paths.get(SYSUSERS)
        if SYSUSERS in made.files:
            if sha == made.files[SYSUSERS]:
                steps.append(plan.unfile(SYSUSERS))
            elif sha:
                notes.append(f"{SYSUSERS} was changed since Liminal wrote it: it is kept")
                kept = True
        elif not has_journal and conf is not None and conf.startswith(COMMENT):
            steps.append(plan.unfile(SYSUSERS))
        # 2. the members Liminal added
        added = [m for m in made.members if g is not None and m in g.members]
        steps += [self.unmember_step(m) for m in added]
        others = sorted(set(g.members) - set(added) - {NAME}) if g is not None else []
        # 3. the user
        group_found = g is not None and not self.group_ours()
        if not has_journal:
            liminals = (u is not None and f.system_account(u) and u.comment == "Liminal" and not self.adopted())
            if liminals:
                kept |= not self._remove_user(steps, notes, group_found=True)
            if g is not None:
                notes.append(f"no journal of Liminal's is here, so the group {NAME} and its members are kept")
        elif self.user_ours():
            kept |= not self._remove_user(steps, notes, group_found=group_found)
        elif u is not None and self.adopted():
            notes.append(f"the user {NAME} was adopted as Liminal's own: it is never removed")
            kept = True
        elif u is not None:
            notes.append(f"the user {NAME} was here before Liminal: it is kept")
        # 4. the group, after root's group is given back to Liminal's folders
        if has_journal and self.group_ours():
            primary = [x.name for x in self.users.values() if x.gid == g.gid and x.name != NAME]
            if self.user is not None and not self.user_ours() and self.user.gid == g.gid:
                primary.append(NAME)
            if others or primary:
                notes.append(f"the group {NAME} is kept: {', '.join(others + primary)} "
                             f"{'is' if len(others + primary) == 1 else 'are'} in it and Liminal did not add them")
                kept = True
            else:
                for path in OWN_FOLDERS:
                    folder = f.layout.get("folders", {}).get(path)
                    if folder is not None and folder.gid == g.gid:
                        steps.append(plan.regroup(path))
                steps.append(self.ungroup_step())
        elif g is not None and has_journal and not self.adopted():
            notes.append(f"the group {NAME} was here before Liminal: it is kept, with its members")
        # 5. the folders Liminal made, where empty; then the journal, when nothing it names is left
        for path in sorted(made.folders, key=len, reverse=True):
            if path not in (journal.FOLDER,):
                steps.append(plan.unfolder(path))
        if has_journal and not kept and not made.adopted:
            steps.append(plan.unjournal())
        guards = (plan.grants_guard(NAME), plan.file_guard(journal.PATH, made.digest), *self.guards(undo=True))
        a_plan = Plan("undo", tuple(steps), notes=tuple(notes), guards=guards, lock=f.lock)
        if not steps:
            return Change(a_plan)
        return Change(a_plan, (("accept_removal", "it removes what Liminal made here: " +
                                "; ".join(s.words for s in steps)),))

    def _remove_user(self, steps: list, notes: list, *, group_found: bool) -> bool:
        """The steps that remove Liminal's user; False when it is kept (and said)."""
        u, g = self.user, self.group
        if group_found and g is not None and u.gid == g.gid:
            nobody = self.users.get("nobody")
            if nobody is None:
                notes.append(f"the user {NAME} is kept: its primary group {NAME} was here before Liminal, and "
                             "without a user nobody there is no group to move it onto first")
                return False
            steps.append(self.move_step(nobody.gid))
        steps.append(self.unuser_step())
        return True


def _is_member(q: str) -> str:
    return f"case \",$(lm_members {NAME}),\" in *,{q},*) true ;; *) false ;; esac"


class Sysusers(AccountTool):
    """systemd's own systemd-sysusers, 255 or later (the user's answer 5)."""

    kind = "sysusers"

    def sysusers_steps(self, need_group: bool, need_user: bool, user_line: bool) -> list[Step]:
        if not (need_group or need_user):
            return []
        f = self.facts
        text = conf_text(user_line or self.user_ours(), self.nologin)
        out = []
        if f.layout.get("folders", {}).get(SYSUSERS_FOLDER) is None:
            out.append(plan.folder(SYSUSERS_FOLDER))
        here = f.liminal.get("sysusers")
        if here != text:
            if here is not None and SYSUSERS not in self.made.files and not here.startswith(COMMENT):
                raise Refused(f"{SYSUSERS} is here and is not the file Liminal writes: move it away first; nothing "
                              "was changed")
            out.append(plan.file(SYSUSERS, text))
        absent = " ".join(o for o, need in (("group", need_group), ("user", need_user)) if need)
        out.append(Step(f"make {' and '.join(absent.split())} {NAME} with systemd-sysusers from {SYSUSERS}",
                        Action.of("sysusers", path=SYSUSERS, name=NAME, absent=absent, tool="sysusers"),
                        " && ".join(f"[ -n \"$(lm_{'gid' if o == 'group' else 'uid'} {NAME})\" ]"
                                    for o in absent.split()),
                        f"systemd-sysusers {SYSUSERS}"))
        return out

    def guards(self, undo: bool = False) -> tuple[plan.Guard, ...]:
        sha = self.facts.here().paths.get(SYSUSERS)
        return (*super().guards(undo), plan.file_guard(SYSUSERS, sha or None))


class Shadow(AccountTool):
    """shadow's tools, without systemd-sysusers (Gentoo with OpenRC, Void, Devuan): each checked first."""

    kind = "shadow"

    def group_step(self) -> Step:
        return Step(f"make the system group {NAME}", Action.of("group", name=NAME, tool="shadow"),
                    f"[ -n \"$(lm_gid {NAME})\" ]", f"groupadd --system {NAME}")

    def user_step(self) -> Step:
        shell = sh_word(self.nologin, "a shell")
        return Step(f"make the system user {NAME} in the group {NAME}, no home made, no login",
                    Action.of("user", name=NAME, group=NAME, comment="Liminal", home=HOME, shell=self.nologin,
                              tool="shadow"),
                    f"[ -n \"$(lm_uid {NAME})\" ]",
                    f"useradd --system --gid {NAME} --no-create-home --home-dir {HOME} --shell {shell} "
                    f"--comment Liminal --expiredate '' {NAME}")


class BusyBoxAccounts(AccountTool):
    """BusyBox's applets (Alpine). Its deluser also removes the group of the user's name whatever its members, so a
    user made in a group Liminal found is kept (M15)."""

    kind = "busybox"

    def group_step(self) -> Step:
        return Step(f"make the system group {NAME}", Action.of("group", name=NAME, tool="busybox"),
                    f"[ -n \"$(lm_gid {NAME})\" ]", f"addgroup -S {NAME}")

    def user_step(self) -> Step:
        shell = sh_word(self.nologin, "a shell")
        return Step(f"make the system user {NAME} in the group {NAME}, no home made, no login",
                    Action.of("user", name=NAME, group=NAME, comment="Liminal", home=HOME, shell=self.nologin,
                              tool="busybox"),
                    f"[ -n \"$(lm_uid {NAME})\" ]",
                    f"adduser -S -D -H -h {HOME} -s {shell} -G {NAME} -g Liminal {NAME}")

    def member_step(self, user: str) -> Step:
        q = sh_word(user, "a user")
        return Step(f"add {user} to the group {NAME}", Action.of("member", user=user, group=NAME, tool="busybox"),
                    _is_member(q), f"addgroup {q} {NAME}")

    def unmember_step(self, user: str) -> Step:
        q = sh_word(user, "a user")
        return Step(f"take {user} out of the group {NAME}", Action.of("unmember", user=user, group=NAME,
                                                                       tool="busybox"),
                    f"! {_is_member(q)}", f"delgroup {q} {NAME}")

    def unuser_step(self) -> Step:
        return Step(f"remove the user {NAME}", Action.of("unuser", name=NAME, tool="busybox"),
                    f"[ -z \"$(lm_uid {NAME})\" ]", f"deluser {NAME}")

    def ungroup_step(self) -> Step:
        return Step(f"remove the group {NAME}", Action.of("ungroup", name=NAME, tool="busybox"),
                    f"[ -z \"$(lm_gid {NAME})\" ]", f"delgroup {NAME}")

    def _remove_user(self, steps: list, notes: list, *, group_found: bool) -> bool:
        if group_found and self.group is not None:
            notes.append(f"BusyBox's deluser would also remove the group {NAME}, which was here before Liminal: the "
                         f"user {NAME} stays; remove it by hand with the group if you wish")
            return False
        steps.append(self.unuser_step())
        return True


class NixAccounts(AccountTool):
    """NixOS declares its accounts: refused, with the lines to add to configuration.nix."""

    kind = "nix"

    def tool_refusal(self, member: str | None) -> str:
        member = member or self.facts.elevation.get("user", "") or "<you>"
        return ("NixOS declares its accounts, so Liminal makes none itself: add these lines to "
                "/etc/nixos/configuration.nix, then run `sudo nixos-rebuild switch`:\n"
                f"  users.groups.{NAME} = {{ }};\n"
                f"  users.users.{NAME} = {{ isSystemUser = true; group = \"{NAME}\"; description = \"Liminal\"; "
                f"home = \"{HOME}\"; }};\n"
                f"  users.users.{member}.extraGroups = [ \"{NAME}\" ];")


class NoAccounts(AccountTool):
    """No account tool Liminal knows."""

    def tool_refusal(self, member: str | None) -> str:
        return self.why()


def tool(facts) -> AccountTool:
    """The AccountTool for this system, by the probe's record."""
    return {"sysusers": Sysusers, "shadow": Shadow, "busybox": BusyBoxAccounts, "nix": NixAccounts}.get(
        facts.accounts.get("tool"), NoAccounts)(facts)


def digest_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
