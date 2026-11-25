"""Another plugin's hook asked through the app (1.96.0): the frame's ask(name, hook, *args) or the platform's
ask(name, hook, args), with no lock held, for a base that is not a ContainerHost (NetworkHost, WslDistribution)."""
from __future__ import annotations

import inspect
from collections.abc import Mapping

from ..instances import Refusal


def ask(plugin, name: str, hook: str, *args):
    """`hook` of the plugin `name`, asked as `plugin` through its app."""
    app = getattr(plugin, "app", None)
    if app is None:
        raise Refusal(f"{plugin.name} is not attached: it asks no other plugin")
    try:
        spread = inspect.signature(app.ask).parameters.get("args")
    except (TypeError, ValueError):
        spread = None
    if spread is not None and spread.kind is inspect.Parameter.VAR_POSITIONAL:
        return app.ask(name, hook, *args)
    return app.ask(name, hook, list(args))


def others(plugin, hook: str, *args) -> list[tuple[str, object, BaseException | None]]:
    """Each other attached plugin whose hooks list `hook`, asked it: [(name, answer, error)]."""
    app = getattr(plugin, "app", None)
    if app is None:
        return []
    try:
        faces = dict(app.plugins() or {})
    except Exception:  # noqa: BLE001 - an app that cannot list its plugins asks none
        return []
    out = []
    for name, face in faces.items():
        hooks = face.get("hooks") if isinstance(face, Mapping) else None
        if name == plugin.name or not hooks or hook not in hooks:
            continue
        try:
            out.append((name, ask(plugin, name, hook, *args), None))
        except Exception as e:  # noqa: BLE001 - one that refuses is left out, in its words
            out.append((name, None, e))
    return out
