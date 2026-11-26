"""The one authorization interface (the user, 2026-11-06: "the app plugins need to use the Abstract
Base Class login as the only way to present an interface for IPC, between plugins and login and the
app as far as AUTHORIZATION"; the login instance of an app "talks to the respective app plugins" with
"its associated plugin requirements like api keys or passwords or what ever").

`Login` is an abstract base class: every plugin and every app holds a realization of it (`Plugin.login`,
`App.login`, set when the plugin is attached by its app), and asks it, and nothing else, for a key, an
account or a password: `login.key("massive")` is the pair `massive-account-api-key` of the signed-in
user of the app's namespace. The realizations: `LoginClient` (apps/login.py), over HTTP to the login
app of that namespace (liminal-login), the proxy over the hosts' pipe to come with the resident
plugins; `EnvironmentLogin` here, reading the user environment variables that are the keys' store
until every plugin is attached through an app (the transition); a test's stand-in. A refusal is
`Unauthorized`.

1.88.0 (Monday list item 21; the user, 2026-11-19: "preferences, keys, licenses all get stored in the individual's
login db"): besides the keys, a login may keep the signed-in user's preferences and the licences they accepted, each
a pair of its own kind (PREFERENCE, LICENCE) holding a JSON value (`setting`, `keep_setting`, `keeps_settings`).
`recall` and `keep` read and write one through a login, and fall back to the file it was kept in before when the
login keeps none (an EnvironmentLogin): the file's value is copied into the user's store the first time one that
keeps them is there, and the file is left as it was. `accept_licence` keeps a licence accepted with what was accepted,
its version and address, when and by whom. `as_user` names, for a request's block, the login of the person asking
(an app sets it from the browser's session: App.user_login), so a second user signed in reads their own."""
from __future__ import annotations

import contextlib
import contextvars
import getpass
import hashlib
import json
import os
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path

PREFERENCE = "preference"  # a pair holding one of the user's preferences (a JSON value): ui-theme, platform-plugins
LICENCE = "licence"  # a pair holding a licence the user accepted (a JSON object: licence_record)
SETTING_KINDS = (PREFERENCE, LICENCE)
LICENCE_PREFIX = "licence-"  # a licence's pair: licence-dbip-lite
WORDS_KEPT = 1500  # the most of a licence's words kept in its record (all of them by their SHA-256)


class Unauthorized(Exception):
    """The login refuses: nobody signed in, no such pair, not allowed."""

    def __init__(self, reason: str, status: int = 401):
        super().__init__(reason)
        self.reason, self.status = reason, status


def pair_name(variable: str) -> str:
    """A plugin's key variable as the login's store names its pair (the user, 2026-11-06: "By the
    variables"): MASSIVE_API_KEY is `massive-api-key`, ALPACA_API_KEY_ID `alpaca-api-key-id`."""
    return str(variable or "").strip().lower().replace("_", "-")


def variable_name(pair: str) -> str:
    """The variable a pair fills: `massive-api-key` is MASSIVE_API_KEY."""
    return str(pair or "").strip().upper().replace("-", "_")


class Login(ABC):
    """What a plugin or an app may ask of the login of its app's namespace. `vector` and `user` are
    the realization's; `key`, `account` and `password` name the pairs by their convention
    (`<plugin>-account-api-key`, `-account-name`, `-account-password`); `may` is the authorization
    policy (everything the signed-in user has, until a policy says less)."""

    NAMESPACE = ""  # the app whose users it serves: charts, integrator (set by the realization)

    @abstractmethod
    def user(self) -> dict:
        """Who is signed in: at least `name`; `email` and `verified` when known. Unauthorized when nobody."""

    @abstractmethod
    def vector(self, name: str) -> str:
        """The value of the pair `name` for the signed-in user. Unauthorized when there is none, or nobody."""

    def key(self, plugin: str) -> str:
        return self.vector(f"{plugin}-account-api-key")

    def account(self, plugin: str) -> str:
        return self.vector(f"{plugin}-account-name")

    def password(self, plugin: str) -> str:
        return self.vector(f"{plugin}-account-password")

    def has(self, name: str) -> bool:
        """Whether the pair `name` can be furnished now (signed in, and the pair is there)."""
        try:
            self.vector(name)
        except Unauthorized:
            return False
        return True

    def may(self, plugin: str, action: str) -> bool:
        """Whether `plugin` may do `action` for the signed-in user (fetch, trade, evaluate ...): a
        policy for the login's realm to refine; everything the user has, by default."""
        return self.signed_in

    def save(self, variable: str, value: str | None) -> str:
        """A setting kept for the signed-in user (the user, 2026-11-08: "i need a way to put my credentials in to the
        namecheap plugin and allow it to function"; "all plugin states/keys will be stored with the associated
        user"): its pair named by the variable (NAMECHEAP_API_KEY is `namecheap-api-key`); `value` None forgets it.
        Where it is kept, in words. Unauthorized when this login keeps none."""
        raise Unauthorized(f"{type(self).__name__} keeps no settings", 405)

    # 1.88.0: the user's preferences and the licences they accepted, a pair each of a kind of its own (SETTING_KINDS)
    keeps_settings = False  # whether this login keeps them for the signed-in user (a realization that does says so)

    def setting(self, name: str):
        """The JSON value the signed-in user keeps under the pair `name` (a preference or a licence: SETTING_KINDS);
        None when they keep none of that name. Unauthorized when nobody is signed in, when this login keeps none
        (405), or when the pair is of another kind (a key is never read as a setting: 409)."""
        raise Unauthorized(f"{type(self).__name__} keeps no preferences or licences", 405)

    def keep_setting(self, name: str, value, kind: str = PREFERENCE, label: str = "") -> dict:
        """`value` (anything JSON holds) kept for the signed-in user as the pair `name` of `kind` (SETTING_KINDS);
        the pair's row (its name, kind, label and dates). Unauthorized as `setting`."""
        raise Unauthorized(f"{type(self).__name__} keeps no preferences or licences", 405)

    def names(self) -> set[str] | None:
        """The pairs the signed-in user has, by name, when the realization can list them (one call
        instead of one per variable); None when it cannot."""
        return None

    def variables(self, wanted) -> dict[str, str]:
        """The variables among `wanted` (a plugin's key names: MASSIVE_API_KEY ...) this login
        furnishes, with their values: what Settings.load merges over the environment when an app has
        a login. Nobody signed in: nothing."""
        wanted = list(wanted)
        if not wanted or not self.signed_in:
            return {}
        have = self.names()
        out: dict[str, str] = {}
        for variable in wanted:
            pair = pair_name(variable)
            if have is not None and pair not in have:
                continue
            try:
                out[variable] = self.vector(pair)
            except Unauthorized:
                continue
        return out

    @property
    def signed_in(self) -> bool:
        try:
            self.user()
        except Unauthorized:
            return False
        return True

    def describe(self) -> dict:
        """What a page or a plugin's view may show: the namespace and whether anyone is signed in."""
        return {"namespace": self.NAMESPACE, "signedIn": self.signed_in, "kind": type(self).__name__}


class EnvironmentLogin(Login):
    """The keys' store until every plugin is attached through an app: the user environment variables
    (the machine's user is the signed-in user). `pairs` maps a pair's name to its variable
    (`massive-account-api-key` -> MASSIVE_API_KEY), built by the app from each plugin's `keys`; a
    name not mapped is read as a variable named after it (MASSIVE_ACCOUNT_API_KEY).

    `saved` (an app's choice, the platform's): with the process's environment (`env` None), the variables saved
    to the user's environment after this process started are read too, under the process's own (`saved_variables`:
    Windows' user Environment key, where `save` and tools/set-key.ps1 keep them), so a setting entered on a page
    holds across a restart however the process was started. Off by default: a plugin's own login and a test read
    the process's environment alone."""

    NAMESPACE = "environment"

    def __init__(self, pairs: Mapping[str, str] | None = None, env: Mapping[str, str] | None = None, saved=None):
        self.pairs = dict(pairs or {})
        self.env = env  # None: the process's environment, read when asked
        self._saved = saved  # None, or () -> {variable: value}: the user's saved variables (saved_variables)

    def user(self) -> dict:
        return {"name": getpass.getuser(), "email": None, "verified": False}

    def _values(self) -> Mapping[str, str]:
        """The variables as this login reads them: the given ones; else this process's, over the user's saved ones."""
        if self.env is not None:
            return self.env
        saved = self._saved() if self._saved is not None else {}
        return {**saved, **os.environ} if saved else os.environ

    def names(self) -> set[str]:
        env = self._values()
        return {pair_name(v) for v, value in env.items() if value} | {p for p, v in self.pairs.items() if env.get(v)}

    def vector(self, name: str) -> str:
        env = self._values()
        variable = self.pairs.get(name) or variable_name(name).replace(".", "_")
        value = env.get(variable)
        if not value:
            raise Unauthorized(f"no {name} here ({variable} is not set)", 404)
        return value

    def save(self, variable: str, value: str | None) -> str:
        """The setting kept as one of the user's environment variables: on Windows in the user Environment key
        (where every plugin's keys are kept until the login app holds them) and in this process, so it holds at
        once and after a restart; elsewhere in this process only, until it ends. A test's `env` is written as is."""
        variable = str(variable or "").strip()
        if not variable or not variable.replace("_", "").isalnum():
            raise Unauthorized(f"not a setting's name: {variable!r}", 400)
        if self.env is not None:
            if not isinstance(self.env, dict):
                raise Unauthorized("this login's variables cannot be changed", 405)
            if value is None:
                self.env.pop(variable, None)
            else:
                self.env[variable] = value
            return "the login's variables"
        if os.name == "nt":
            from ..config import ConfigError, save_user_variable

            try:
                save_user_variable(variable, value)
            except (ConfigError, OSError) as e:
                raise Unauthorized(f"{variable} could not be kept in your user environment variables: {e}", 500) from None
            return "your user environment variables"
        if value is None:
            os.environ.pop(variable, None)
        else:
            os.environ[variable] = value
        return "this process's environment, until it ends (no user environment to keep it in here)"


_LENT: list = []  # the environment's login, made once (lent_login)
_LENT_LOCK = __import__("threading").Lock()


def lent_login() -> "EnvironmentLogin":
    """The login a plugin holds when no app has lent it one (1.86.0; the user, 2026-11-24: every plugin always has a
    login): the user's environment, what every app holds when it has no login of its own (EnvironmentLogin, this
    process's variables). One object, shared: an app given no login lends it, and a plugin asked before it is attached
    is lent it; attached, it holds its app's."""
    with _LENT_LOCK:
        if not _LENT:
            _LENT.append(EnvironmentLogin())
        return _LENT[0]


def saved_variables() -> dict[str, str]:
    """The user's saved environment variables (Windows' user Environment key); {} elsewhere or unreadable."""
    if os.name != "nt":
        return {}
    try:
        import winreg

        out = {}
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            i = 0
            while True:
                try:
                    name, value, kind = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and value:
                    out[name] = str(value)
        return out
    except OSError:
        return {}


# -- 1.88.0: preferences and licences through the login (Monday list item 21) -----------------------------------------
LICENCES_VAR = "LIMINAL_LICENCES_FILE"  # where a licence accepted is kept when the login keeps none (licences_file)


def encode_setting(value) -> str:
    """A setting's value as its pair keeps it: compact JSON (strict: no NaN)."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False)


def decode_setting(raw):
    """A pair's value read back as the setting it holds; None for one that is not JSON (as if none were kept)."""
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def setting_kind(kind) -> str:
    kind = str(kind or "").strip().lower()
    if kind not in SETTING_KINDS:
        raise ValueError(f"a setting's kind is one of {', '.join(SETTING_KINDS)}, not {kind!r}")
    return kind


def keeps(login) -> bool:
    """Whether `login` keeps the signed-in user's preferences and licences now (it says it does, and someone is
    signed in). A login that cannot say keeps none."""
    try:
        return login is not None and bool(login.keeps_settings) and bool(login.signed_in)
    except Exception:  # noqa: BLE001 - a login that cannot say: the file, as before
        return False


def recall(login, name: str, fallback: Callable[[], object], kind: str = PREFERENCE, label: str = ""):
    """The setting `name` of the user `login` serves: theirs when it keeps one; else what `fallback()` reads (the
    file it was kept in before 1.88.0), None for nothing. With a login that keeps settings but holds none of that
    name yet, the file's value is copied into the user's store, once (from then on theirs is read), and the file is
    left as it was, for a login that keeps none. A store that refuses or cannot be reached: the file, as before."""
    if not keeps(login):
        return fallback()
    try:
        value = login.setting(name)
    except Unauthorized:
        return fallback()
    if value is not None:
        return value
    old = fallback()
    if old is not None:
        try:
            login.keep_setting(name, old, kind, label or f"{name} (from the file it was kept in before)")
        except Unauthorized:
            pass  # read from the file again next time, and copied then
    return old


def keep(login, name: str, value, fallback: Callable[[object], None], kind: str = PREFERENCE, label: str = "") -> str:
    """The setting `name` kept: in the store of the user `login` serves when it keeps settings, else (or when the
    store refuses or cannot be reached) by `fallback(value)`, the file it was kept in before. Where, in words."""
    if keeps(login):
        try:
            login.keep_setting(name, value, kind, label)
            return "your login's store"
        except Unauthorized:
            pass
    fallback(value)
    return "the file"


def licence_pair(slug: str) -> str:
    """A licence's pair name: `dbip-lite` is licence-dbip-lite."""
    slug = str(slug or "").strip().lower()
    return slug if slug.startswith(LICENCE_PREFIX) else LICENCE_PREFIX + slug


def licence_record(name: str, *, title: str, version: str = "", url: str = "", words: str = "", by: str = "",
                   at: datetime | None = None, login: str = "") -> dict:
    """What a licence accepted is kept as: its pair's name, what was accepted (its title), its version and address,
    its words (the first WORDS_KEPT characters, and all of them by their SHA-256, so a changed licence is told from
    the one accepted), when (UTC, ISO 8601) and by whom, and through which login."""
    words = str(words or "")
    at = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return {"licence": licence_pair(name), "title": str(title or ""), "version": str(version or ""), "url": str(url or ""),
            "words": words[:WORDS_KEPT], "wordsSha256": hashlib.sha256(words.encode("utf-8")).hexdigest() if words else "",
            "acceptedAt": at.isoformat(timespec="seconds").replace("+00:00", "Z"), "acceptedBy": str(by or ""),
            "login": str(login or "")}


def _who(login) -> str:
    try:
        return str((login.user() or {}).get("name") or "") if login is not None else getpass.getuser()
    except Exception:  # noqa: BLE001 - nobody said: the machine's user
        return getpass.getuser()


def licences_file(path: Path | None = None) -> Path:
    """Where a licence accepted is kept when the login keeps none: `path`, else LIMINAL_LICENCES_FILE, else the data
    folder's licences.json (written only then)."""
    if path is not None:
        return Path(path)
    named = (os.environ.get(LICENCES_VAR) or "").strip()
    if named:
        return Path(named).expanduser()
    from .. import layout

    return layout.data_dir() / "licences.json"


def _licences_read(path: Path | None) -> dict:
    try:
        saved = json.loads(licences_file(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return saved if isinstance(saved, dict) else {}


def write_json(file: Path, value) -> None:
    """`value` written whole to `file` (a part file of this thread's own renamed into place), its folder made."""
    file = Path(file)
    file.parent.mkdir(parents=True, exist_ok=True)
    part = file.with_name(f"{file.name}.{os.getpid()}.{threading.get_ident()}.part")
    part.write_text(json.dumps(value, indent=1), encoding="utf-8")
    os.replace(part, file)


_LICENCES_LOCK = threading.Lock()


def accept_licence(login, name: str, *, title: str, version: str = "", url: str = "", words: str = "", by: str = "",
                   at: datetime | None = None, path: Path | None = None, file: bool = True) -> dict:
    """A licence accepted, kept as a LICENCE pair of the user `login` serves (licence_record: what, its version and
    address, when, by whom); with a login that keeps none, in the licences file (licences_file). Returns the record
    with `kept`: where, in words. `file` False (1.101.0, Monday list item 20): kept in the user's own store or not at
    all: Unauthorized when the login keeps none, and the store's own Unauthorized when it refuses; the licences file
    is never read or written."""
    record = licence_record(name, title=title, version=version, url=url, words=words, by=by or _who(login), at=at,
                            login=type(login).__name__ if login is not None else "")
    if not file:
        if not keeps(login):
            raise Unauthorized("a licence is kept in your own login store: sign in, then accept it again", 401)
        login.keep_setting(record["licence"], record, LICENCE, f"{record['title']} {record['version']}".strip())
        return {**record, "kept": "your login's store"}

    def to_file(value) -> None:
        with _LICENCES_LOCK:
            saved = _licences_read(path)
            saved[record["licence"]] = value
            write_json(licences_file(path), saved)

    where = keep(login, record["licence"], record, to_file, LICENCE, f"{record['title']} {record['version']}".strip())
    return {**record, "kept": where}


def licence(login, name: str, path: Path | None = None) -> dict | None:
    """The record of the licence `name` the user `login` serves accepted (licence_record), None when none was; read
    as `recall` reads (the licences file the fallback, copied into a store that keeps them, once)."""
    pair = licence_pair(name)
    found = recall(login, pair, lambda: _licences_read(path).get(pair), LICENCE)
    return found if isinstance(found, dict) else None


# -- who asks, as a login: the person at the browser of the request being answered ------------------------------------
_ASKING: contextvars.ContextVar[tuple[object, object] | None] = contextvars.ContextVar("liminal_user_login", default=None)
_THREAD = threading.local()


def _mark() -> object:
    try:
        return _THREAD.mark
    except AttributeError:
        mark = _THREAD.mark = object()
        return mark


def asking_login():
    """The login of the person whose request this thread answers (as_user), None when none was named here. Never
    inherited by another thread: one started in a copy of this context has a mark of its own (apps.asking's reason)."""
    held = _ASKING.get()
    return held[0] if held is not None and held[1] is _mark() else None


@contextlib.contextmanager
def as_user(login) -> Iterator[object]:
    """`login` is the asking person's for the block, in this thread alone; put back as it was after."""
    token = _ASKING.set((login, _mark()))
    try:
        yield login
    finally:
        _ASKING.reset(token)
