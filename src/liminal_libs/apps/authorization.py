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
`Unauthorized`."""
from __future__ import annotations

import getpass
import os
from abc import ABC, abstractmethod
from collections.abc import Mapping


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
