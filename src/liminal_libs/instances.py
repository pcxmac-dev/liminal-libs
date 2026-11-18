"""What every kind of instance a plugin keeps has in common (1.62.0).

A plugin can hold instances: the database plugins' databases (storage/instances.py, storage/databases.py) and the
model servers' servers (machines/modelserver.py). Each kind has its own fields; what they share is here: how an
instance is named (`NAME`, `clean_name`, `clean_title`, and `has_control`, which other checks of a text share), the
variables its plugin's pairs are kept under through the login (`variable_of`, `credential_variables`,
`secret_variable`), the refusal a page asks a second time (`Refusal`), whether an address is this machine and whether
something listens there (`is_local`, `listening`), and the one value a plugin's instances are kept in through its
login (`Store`).

These names were storage/instances.py's until 1.62.0 and stay importable from there and from storage/databases.py,
the same objects. This module is plain on purpose: the standard library and `layout` only, nothing of the apps or of
the plugin contract. The link's helper loads storage/instances.py at every start, and so loads this."""
from __future__ import annotations

import re
import socket
import time
from datetime import datetime, timezone
from typing import Callable, Mapping

from . import layout

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")  # an instance's name in its plugin
MAX_KEPT = 30000  # characters of the value kept: an environment variable holds 32,767
MAX_TITLE = 60
VERSION = 1  # of the value kept


class Refusal(ValueError):
    """A change not made, and why, in words: nothing was changed. `accept`: the argument that, set, makes it anyway (an
    instance reached off this machine: accept_remote), which a page asks as a second, explicit confirmation."""

    def __init__(self, message: str, accept: str | None = None):
        super().__init__(message)
        self.accept = accept


def _stem(text) -> str:
    return str(text).strip().upper().replace("-", "_")


def variable_of(plugin: str) -> str:
    """The variable a plugin's instances are kept under, through its login: sqlite's is SQLITE_INSTANCES."""
    return f"{_stem(plugin)}_INSTANCES"


def secret_variable(plugin: str, instance: str, what: str) -> str:
    """The variable one secret of an instance is kept under, through the plugin's login (a pair of its own, never in
    the instances' value or in a file): mongodb's `atlas` keeps its password as MONGODB_ATLAS_PASSWORD."""
    return f"{_stem(plugin)}_{_stem(instance)}_{_stem(what)}"


def credential_variables(plugin: str, instance: str) -> tuple[str, str]:
    """The variables an instance's name and password are kept under, through the plugin's login (pairs, never in a
    file): mongodb's `atlas` signs in with MONGODB_ATLAS_USER and MONGODB_ATLAS_PASSWORD."""
    return secret_variable(plugin, instance, "user"), secret_variable(plugin, instance, "password")


def now_iso(clock: Callable[[], float] = time.time) -> str:
    return datetime.fromtimestamp(clock(), timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def clean_name(name) -> str:
    """An instance's name as typed, checked: lowercase letters, digits and dashes, 32 at most, starting with a letter or
    a digit. Refusal otherwise."""
    text = str(name or "").strip().lower()
    if not NAME.match(text):
        raise Refusal("an instance's name is lowercase letters, digits and dashes, 32 at most, starting with a letter "
                      f"or a digit: not {str(name or '')[:40]!r}")
    return text


def has_control(text: str) -> bool:
    """Whether a text holds a control character (below 32, or DEL): what no title here holds, nor a path an instance
    is asked at, an archive's member name or a word of a command at boot (endpoint, download, autostart)."""
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def clean_title(title) -> str:
    text = " ".join(str(title or "").split())
    if len(text) > MAX_TITLE or has_control(text):
        raise Refusal(f"a title is {MAX_TITLE} characters at most, with no control characters")
    return text


def is_local(host: str) -> bool:
    """Whether a host is this machine (127.0.0.1, localhost, ::1): the only ones reached without being asked twice."""
    return str(host or "").strip().strip("[]").lower() in layout.LOCAL_HOSTS


HEARD_S = 3.0  # whether a port of this machine listens is remembered this long
_heard: dict[tuple[str, int], tuple[float, bool]] = {}


def listening(host: str, port: int, timeout: float = 0.3, fresh: bool = False, *,
              heard: dict[tuple[str, int], tuple[float, bool]] | None = None) -> bool:
    """Whether something listens at host:port. Asked of this machine alone by a page's status; of another only by a
    test the user asked for. A port of this machine that does not listen takes the whole wait to say so (Windows
    tries again before it gives up), so its answer is remembered HEARD_S: a page's asks, a few a second apart, do not
    each wait (`fresh`: asked now all the same). Another machine's is never remembered. `heard`: where the answers
    are remembered, this module's own when not given (storage/instances.py hands its own)."""
    cache = _heard if heard is None else heard
    key = (host.strip("[]").lower(), port) if isinstance(port, int) and not isinstance(port, bool) else None
    local = key is not None and is_local(key[0])
    now = time.monotonic()
    if local and not fresh:
        was = cache.get(key)
        if was is not None and now - was[0] < HEARD_S:
            return was[1]
    try:
        if key is None:
            raise ValueError("not a port")
        with socket.create_connection((key[0], port), timeout=timeout):
            answered = True
    except (OSError, ValueError, TypeError):
        answered = False
    if local:
        if len(cache) > 256:
            cache.clear()
        cache[key] = (now, answered)
    return answered


class Store:
    """One value kept through a login under `variable`: a plugin's instances, as text (`login_of`: the plugin's login
    now, None when it has none: then nothing is kept). `saved`: given only where what is kept is another system's
    (the suite inside WSL on Windows' data): it is then that system's, asked of it (its user's saved variables,
    through the link) and never of this one's login, which keeps none of it."""

    NO_LOGIN = "this is kept through the app's login, and this plugin has none: open it on the app's page"

    def __init__(self, variable: str, login_of: Callable[[], object],
                 saved: Callable[[], Mapping[str, str]] | None = None):
        self.variable, self._login_of, self._saved = variable, login_of, saved

    def text(self) -> str:
        """The value as it is kept now; "" when nothing is, or when there is no login to ask."""
        if self._saved is not None:
            return self._saved().get(self.variable, "") or ""
        login = self._login_of()
        return (login.variables([self.variable]).get(self.variable, "") or "") if login is not None else ""

    def put(self, text: str | None) -> str:
        """`text` kept through the login (None: the variable forgotten); where, in words. Refusal with no login, and
        for a value longer than one variable holds."""
        login = self._login_of()
        if login is None:
            raise Refusal(self.NO_LOGIN)
        if text is not None and len(text) > MAX_KEPT:
            raise Refusal(f"too much to keep ({len(text):,} characters, {MAX_KEPT:,} at most): forget something first")
        return login.save(self.variable, text)
