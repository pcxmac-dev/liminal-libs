"""The Databases section: the database plugins' instances as a page draws them and the page's forms (1.90.0).

Moved here from liminal-integrator 1.12.0's instances.py (Monday list item 30, step 1; the user, 2026-11-24:
"inheritance bro", and 2026-11-25: the instance forms move to the platform's Databases section, the platform the only
writer of instance settings), so the platform base (apps/platform.py: Platform) answers the same two routes with the
same shapes, and the integrator's module can become these names imported:

- `overview(app)`: every database plugin with its instances (`GET /api/databases/plugins`): each plugin's own status,
  its API card and what it knows of its engine, and for a plugin's own instances the figures the app already has of
  the data folder (`app.databases.overview()`, the integrator's Databases view, where the app has one: nothing more is
  opened or asked for them). Who is on this database now, by its claims, is listed for the Share form.
- `ask(app, body)`: one form's answer (`POST /api/databases/instances`): test, new, connect, share, port, credentials,
  forget. A change is made only when the page confirmed it (`confirm`), and a refusal that names what accepts it (a
  server off this machine: `accept_remote`) goes back with that name, for the page's second question. A password is
  never logged, never echoed, and taken out of whatever an engine says of its failure.
- `elsewhere(app)`: the file instances outside the data folder, so a Databases view lists them with the folder's own.

Who may change is not decided here: the integrator's path (it still holds the plugins until step 4) changes as it
did, and the platform base refuses a change where it is not the running platform (Platform.instances_asked).

`app` is any App with `log` and NAME; `db_path` (its database: the data folder beside it) and `databases` (the
folder's figures, with `overview()` and `forget()`) are read when it has them."""
from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
from typing import Callable

from .. import claims, layout
from ..mounts import NotHere
from ..sources import apis
from ..storage.databases import ENGINES, Refusal, data_folder
from .app import Refused

ACTIONS = ("test", "new", "connect", "share", "port", "credentials", "forget")
CHANGES = tuple(a for a in ACTIONS if a != "test")  # what changes an instance's settings (the one writer's alone)
SECRETS = ("password", "admin_password")  # of a form: never logged or echoed
HIDDEN = "(not shown)"


class Asked(Refused):
    """A form's answer refused, in the plugin's own words. `accept`: the argument that, sent true with the same form,
    makes the change anyway (the page asks it as a second, explicit confirmation)."""

    def __init__(self, status: int, reason: str, accept: str | None = None):
        super().__init__(status, reason)
        self.accept = accept

    def answer(self) -> dict:
        out = {"error": self.reason}
        if self.accept:
            out["accept"] = self.accept
        return out


def folder_of(app) -> Path:
    """The data folder this app's database plugins speak of: beside its database when it names one (the integrator's
    db_path), else LIMINAL_DB's folder, else the workspace's (storage.databases.data_folder; design §5: the platform
    finds the same folder as the integrator)."""
    if getattr(app, "db_path", None) is not None:
        return Path(app.db_path).parent
    try:
        return data_folder(app)
    except Exception:  # noqa: BLE001 - a setting that cannot be read: the workspace's
        return layout.data_dir()


def plugins(app) -> dict:
    """The database plugins this app holds, by name, in their order: each attached here at its first ask when nothing
    attached it yet (a page's process attaches its plugins at its start; a test's app at the first ask), so it reads
    and keeps through this app's login. One another app holds is left to it."""
    from ..sources import registry

    found = registry.databases()
    for p in found.values():
        if p.app is None:
            app.attach(p)
    return {name: p for name, p in found.items() if p.app is app}


def _figures(app) -> dict:
    """The data folder's figures the app has (the integrator's Databases view), else none."""
    held = getattr(app, "databases", None)
    listing = getattr(held, "overview", None)
    if not callable(listing):
        return {}
    try:
        return listing()
    except Exception as e:  # noqa: BLE001 - the instances are listed without the folder's figures
        return {"error": f"{type(e).__name__}: {e}"}


def _own_figures(plugin, listing: dict) -> dict:
    """What the app's listing already knows of a plugin's own instance: a file engine's files in the data folder and
    their bytes; the server here's folder, and whether it runs."""
    if plugin.SERVER:
        m = listing.get("mongo") or {} if plugin.ENGINE == "mongodb" else {}
        return {"bytes": m.get("disk"), "files": m.get("diskFiles"), "running": m.get("running"), "serverVersion": m.get("version")}
    mine = [e for e in listing.get("entries") or () if e.get("engine") == plugin.ENGINE and e.get("group") != "instances"]
    if not listing:
        return {}
    return {"bytes": sum(e.get("size") or 0 for e in mine), "files": sum(e.get("files", 1) or 0 for e in mine)}


def suites(app) -> list[str]:
    """Who is on this database now, as its claims name them (linux::Ubuntu, windows::NEPTUNE), this one first: what
    the Share form offers. None but this one when the claims cannot be read."""
    me = claims.instance()
    out = [me]
    try:
        if getattr(app, "db_path", None) is not None:
            out += [h.instance for h in claims.held(app.db_path)]
    except Exception:  # noqa: BLE001 - who else is here is a suggestion: the form takes any name
        pass
    return list(dict.fromkeys(out))


def overview(app, errors: Callable[[], list] | None = None) -> dict:
    folder = folder_of(app)
    listing = _figures(app)
    rows = []
    for name, p in plugins(app).items():
        try:
            status = p.status(folder)
        except Exception as e:  # noqa: BLE001 - one plugin's trouble is its own: said in its place
            rows.append({"name": name, "title": p.title or name, "about": p.about, "engine": p.ENGINE, "instances": [],
                         "error": f"{type(e).__name__}: {e}"})
            continue
        status["apis"] = apis.as_dicts(p.apis)
        status["apiFacts"] = apis.facts_of(p)
        for row in status["instances"]:
            if row.get("builtin"):
                row.update({k: v for k, v in _own_figures(p, listing).items() if v is not None})
        rows.append(status)
    return {"plugins": rows, "me": claims.instance(), "suites": suites(app), "dataFolder": str(folder),
            "errors": load_errors(errors)}


def ours(where: str, why: str) -> bool:
    """Whether a plugin left out at loading is a database plugin: by its words, or its package's name, today's
    (plugin-integrator-sqlite) or the one it is renamed to in step 3 (plugin-platform-sqlite)."""
    low = where.lower()
    return why.startswith("database ") or any(f"plugin-{system}-{e}" in low or f"plugin_{system}_{e}" in low
                                              for e in ENGINES for system in ("integrator", "platform"))


def load_errors(errors: Callable[[], list] | None = None) -> list[str]:
    """The database plugins left out when the plugins were loaded, and why (a driver's package missing, a library too
    old for it): said on the page in place of the plugin. `errors`: the registry's (registry.errors) unless given."""
    if errors is None:
        from ..sources.registry import errors
    return [f"{where}: {why}" for where, why in errors() if ours(where, why)][:8]


def elsewhere(app) -> list[dict]:
    """The file instances the database plugins hold outside the data folder (connected, or made at a whole path): each
    {id, plugin, name, title, engine, path}. One inside the folder is found by the folder's own listing."""
    folder = folder_of(app).resolve()
    out: list[dict] = []
    for name, p in plugins(app).items():
        if p.SERVER:
            continue
        try:
            found = p.instances(folder)
        except Exception:  # noqa: BLE001 - listed without them
            continue
        for inst in found:
            if inst.builtin or inst.folder:
                continue
            path = p.path_of(inst, folder)
            if path is None:
                continue
            try:
                inside = folder == path.resolve().parent or folder in path.resolve().parents
            except (OSError, ValueError):
                continue
            if not inside:
                out.append({"id": f"instance:{name}:{inst.name}", "plugin": name, "name": inst.name,
                            "title": inst.title or inst.name, "engine": p.ENGINE, "path": str(path)})
    return out


def _scrubbed(text: str, body: dict) -> str:
    """What an engine said, without the secrets the form carried."""
    for key in SECRETS:
        secret = body.get(key)
        if isinstance(secret, str) and len(secret) >= 3:
            text = text.replace(secret, HIDDEN)
    return text


def text_of(body: dict, key: str) -> str:
    """A form's field as text, stripped; "" for what is not one."""
    value = body.get(key)
    return str(value or "").strip() if not isinstance(value, (dict, list)) else ""


def ask(app, body: dict) -> dict:
    """One form of the page answered by its plugin; what it said ({"ok", "said", "lines"}). Refused (Asked, or a 404 for
    a plugin or an instance that is not there) in words."""
    text = lambda key: text_of(body, key)  # noqa: E731
    name, action = text("plugin"), text("action")
    p = plugins(app).get(name)
    if p is None:
        raise Refused(HTTPStatus.NOT_FOUND, f"no database plugin {name[:40]!r} here")
    if action not in ACTIONS:
        raise Refused(HTTPStatus.BAD_REQUEST, f"an instance is asked one of: {', '.join(ACTIONS)}")
    if action != "test" and body.get("confirm") is not True:
        raise Refused(HTTPStatus.BAD_REQUEST, "a change to an instance is confirmed on the page first")
    folder = folder_of(app)
    holds = body.get("holds") if isinstance(body.get("holds"), (list, str)) else ()
    secret = lambda key: body.get(key) if isinstance(body.get(key), str) else ""  # noqa: E731 - as typed, not stripped
    server = {"port": body.get("port"), "database": text("database"), "tls": body.get("tls") is True,
              "accept_remote": body.get("accept_remote") is True}
    try:
        if action == "test":
            out = p.test(text("name"), folder)
        elif action == "new":
            admin = {"admin_user": text("admin_user"), "admin_password": secret("admin_password")} if text("admin_user") else {}
            out = p.new_database(text("name"), text("where"), holds, text("title"), folder, **server, **admin)
        elif action == "connect":
            out = p.connect_to(text("name"), text("where"), text("method"), holds, text("title"), folder, **server,
                               user=text("user"), password=secret("password"))
        elif action == "share":
            out = p.share(text("name"), text("who"), text("access"), folder)
        elif action == "port":
            out = p.set_port(text("name"), body.get("port"), folder)
        elif action == "credentials":
            out = p.set_credentials(text("name"), text("user"), secret("password"), folder)
        else:
            out = p.forget(text("name"), folder)
    except Refusal as e:
        raise Asked(HTTPStatus.BAD_REQUEST, _scrubbed(str(e), body), getattr(e, "accept", None)) from None
    except NotHere as e:
        raise Asked(HTTPStatus.CONFLICT, str(e)) from None
    except LookupError as e:
        raise Refused(HTTPStatus.NOT_FOUND, str(e)) from None
    except Refused:
        raise
    except Exception as e:  # noqa: BLE001 - an engine's own failure, in its words (a server's refusal, a full disk)
        raise Asked(HTTPStatus.BAD_GATEWAY, _scrubbed(f"{type(e).__name__}: {e}", body)) from None
    if action != "test":
        app.log(f"{app.NAME or 'platform'}: {name}: {action} {text('name')}: {out.get('said')}")  # (what a plugin says holds no secret)
        forget = getattr(getattr(app, "databases", None), "forget", None)
        if callable(forget):
            forget()  # the folder is listed again at the next ask: a database made or connected shows at once
    return out
