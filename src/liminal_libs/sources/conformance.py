"""The class contract's conformance check (plugin API 2.0, the data declarations of 2.1): what a plugin must satisfy, by kind, read
from the plugin object alone (no settings, no network, nothing sent). The user, 2026-11-03: "evaluate
each functional piece of software or plugin and verify correctness and valid functionality through
unit tests created to address new class scheme". `problems(plugin)` lists what is wrong;
`assert_conforms(plugin)` and `assert_module_conforms(module)` raise an AssertionError naming it:
every plugin package's tests/test_contract.py calls the latter on its module, and the charts app's
loading test calls the former on every plugin it finds."""
from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date
from types import ModuleType

from ..freshness import Delay
from ..layout import Database
from .fetching import Fetcher
from .keys import APP, KeyVar
from .plugin import FeedPlugin, Plugin
from .publisher import Feed, Policy, PublisherPlugin
from .stream import Live

NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")  # a plugin's name: its files, its variables' stem
VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]*$")  # a user environment variable
ASSETS = frozenset({"stock", "index", "fx", "crypto", "future"})  # sources.base.RESOLUTIONS_BY_ASSET's
RESOLUTIONS = frozenset({"second", "minute", "day"})
FEED_KINDS = frozenset({"exchange", "consolidated", "official", "vendor", "mirror", "research"})
SYSTEMS = frozenset({"integrator", "platform"})
KINDS = {"feed": FeedPlugin, "publisher": PublisherPlugin}  # assistant: looked up when asked (its package imports the client)
FEED_HOOKS = ("build", "view", "rate", "has_keys", "serves", "markets", "carries", "plan_resolutions", "reporter", "scan",
              "settings")
PUBLISHER_HOOKS = ("moments", "calendar", "read", "scan", "settings")
ASSISTANT_HOOKS = ("build", "scan", "settings")
MACHINE_HOOKS = ("present", "status", "setup", "run", "instances", "scan", "settings")
DATABASE_HOOKS = ("builtin", "open", "probe", "make", "own_port", "scan", "settings")
AUDITOR_HOOKS = ("scan", "settings")


def problems(p: object) -> list[str]:
    """Every way `p` falls short of the contract, in words; empty when it conforms."""
    out: list[str] = []
    if not isinstance(p, Plugin):
        return [f"not a plugin: {type(p).__name__} is no Plugin subclass's instance"]
    if "CONTRACT" in type(p).__dict__:
        out.append(f"an instance of the contract's own {type(p).__name__}, not of a plugin's class")
    name = p.name
    if not isinstance(name, str) or not NAME.match(name):
        out.append(f"name {name!r}: lowercase letters, digits and dashes, starting with a letter or digit")
    tag = name if isinstance(name, str) and name else type(p).__name__
    if not isinstance(p.title, str) or not p.title.strip():
        out.append(f"{tag}: no title")
    from .registry import api_refusal  # when asked, not on import

    why = api_refusal(p.api, record=p.is_record)
    if why:
        out.append(f"{tag}: api {p.api!r}: {why}")
    if p.SYSTEM not in SYSTEMS:
        out.append(f"{tag}: SYSTEM {p.SYSTEM!r} is none of {sorted(SYSTEMS)}")
    expected = _kind_of(p)
    if expected is None:
        out.append(f"{tag}: neither a FeedPlugin, a PublisherPlugin, an AssistantPlugin, a MachinePlugin, a "
                   "DatabasePlugin nor an AuditorPlugin")
    elif p.KIND != expected:
        out.append(f"{tag}: KIND {p.KIND!r} for a {expected} plugin")
    refused = p.refusal()
    if refused:
        out.append(f"{tag}: refused: {refused}")
    out += _variables(tag, p)
    if not isinstance(p.order, int):
        out.append(f"{tag}: order {p.order!r} is not an int")
    if not isinstance(p.version, str):
        out.append(f"{tag}: version {p.version!r} is not a str")
    for attr in ("about", "signup", "plan_note", "account", "part_of", "limits", "origin"):
        if not isinstance(getattr(p, attr), str):
            out.append(f"{tag}: {attr} is not a str")
    if not isinstance(p.databases, tuple) or not all(isinstance(d, Database) for d in p.databases):
        out.append(f"{tag}: databases must be a tuple of layout.Database")
    if p.fetcher is not None and not isinstance(p.fetcher, Fetcher):
        out.append(f"{tag}: fetcher is not a sources.fetching.Fetcher")
    hooks = (FEED_HOOKS if expected == "feed" else PUBLISHER_HOOKS if expected == "publisher"
             else MACHINE_HOOKS if expected == "machine" else DATABASE_HOOKS if expected == "database"
             else AUDITOR_HOOKS if expected == "auditor" else ASSISTANT_HOOKS)
    for hook in hooks:
        if p.gives(hook) and not callable(getattr(p, hook, None)):
            out.append(f"{tag}: gives {hook} but it is not callable")
    if p.has_scan != p.gives("scan") or p.has_settings != p.gives("settings"):
        out.append(f"{tag}: has_scan/has_settings disagree with gives()")
    try:
        copy = p.with_(order=p.order)
        if type(copy) is not type(p) or copy.name != p.name or copy.is_record != p.is_record:
            out.append(f"{tag}: with_() does not give a copy of the same kind and name")
    except Exception as e:  # noqa: BLE001 - what with_ raised is the problem
        out.append(f"{tag}: with_() failed: {type(e).__name__}: {e}")
    out += _apis(tag, p)
    out += _lifecycle(tag, p)
    if expected == "feed":
        out += _feed(tag, p)
    elif expected == "publisher":
        out += _publisher(tag, p)
    elif expected == "assistant":
        out += _assistant(tag, p)
    elif expected == "database":
        out += _database(tag, p)
    elif expected == "auditor":
        out += _auditor(tag, p)
    return out


def _apis(tag: str, p: Plugin) -> list[str]:
    """What it attaches to (plugin API 2.2, sources/apis.py): sound declarations whatever its version; declared at all
    only by a plugin written for 2.2, and by every such plugin (the user, 2026-11-11: "each plugin should reflect the
    the API its attached to, and present links that provide documentation"; "ensure this is true")."""
    from .apis import problems as api_problems
    from .registry import api_version

    declared = getattr(p, "apis", ())
    out = [f"{tag}: {why}" for why in api_problems(declared)]
    if not callable(getattr(p, "api_facts", None)):
        out.append(f"{tag}: api_facts is not callable")
    try:
        version = api_version(p.api)
    except ValueError:
        return out  # said by the api check already
    if p.is_record:
        return out
    if version >= (2, 2) and not declared:
        out.append(f"{tag}: written for plugin API {p.api} but declares no API it attaches to "
                   "(apis: an sources.apis.Api for each thing it talks to)")
    elif declared and version < (2, 2):
        out.append(f"{tag}: declares apis (plugin API 2.2) but is written for {p.api}")
    return out


def _kind_of(p: Plugin) -> str | None:
    if isinstance(p, FeedPlugin):
        return "feed"
    if isinstance(p, PublisherPlugin):
        return "publisher"
    from ..assistants.plugin import AssistantPlugin  # when asked, not on import
    from ..machines.plugin import MachinePlugin
    from ..auditing import AuditorPlugin
    from ..storage.databases import DatabasePlugin

    return ("assistant" if isinstance(p, AssistantPlugin) else "machine" if isinstance(p, MachinePlugin)
            else "database" if isinstance(p, DatabasePlugin) else "auditor" if isinstance(p, AuditorPlugin) else None)


def _variables(tag: str, p: Plugin) -> list[str]:
    """Its keys, plan variables and options: user environment variables, each declared once, none
    the app's own."""
    out: list[str] = []
    seen: set[str] = set()
    if not isinstance(p.keys, tuple):
        return [f"{tag}: keys must be a tuple of KeyVar"]
    for k in p.keys:
        if not isinstance(k, KeyVar):
            out.append(f"{tag}: key {k!r} is not a KeyVar")
            continue
        for n in k.names:
            if not VARIABLE.match(n):
                out.append(f"{tag}: key variable {n!r} is not a variable name")
            if n in APP:
                out.append(f"{tag}: key variable {n!r} is the app's own")
            if n in seen:
                out.append(f"{tag}: key variable {n!r} declared twice")
            seen.add(n)
    for attr in ("plan_vars", "options"):
        values = getattr(p, attr)
        if not isinstance(values, tuple):
            out.append(f"{tag}: {attr} must be a tuple")
            continue
        for n in values:
            if not isinstance(n, str) or not VARIABLE.match(n):
                out.append(f"{tag}: {attr} {n!r} is not a variable name")
            elif n in APP:
                out.append(f"{tag}: {attr} {n!r} is the app's own")
            elif n in seen:
                out.append(f"{tag}: {attr} {n!r} declared twice")
            seen.add(n)
    choices = p.plan_choices
    if not isinstance(choices, Mapping):
        out.append(f"{tag}: plan_choices must be a mapping")
    else:
        for var, values in choices.items():
            if var not in p.plan_vars and var not in p.options:
                out.append(f"{tag}: plan_choices for {var!r}, none of its plan_vars or options")
            if not isinstance(values, tuple) or not values or not all(isinstance(v, str) for v in values):
                out.append(f"{tag}: plan_choices[{var!r}] must be a non-empty tuple of str")
    return out


def _feed(tag: str, p: FeedPlugin) -> list[str]:
    out: list[str] = []
    assets = p.assets
    if not isinstance(assets, frozenset) or not assets:
        out.append(f"{tag}: assets must be a non-empty frozenset")
        assets = frozenset()
    elif not assets <= ASSETS:
        out.append(f"{tag}: assets {sorted(assets - ASSETS)} are none of {sorted(ASSETS)}")
    if not isinstance(p.keyless, frozenset) or not p.keyless <= assets:
        out.append(f"{tag}: keyless must be a frozenset within assets")
    if not isinstance(p.reference_for, frozenset) or not p.reference_for <= ASSETS:
        out.append(f"{tag}: reference_for must be a frozenset of asset classes")
    if p.kind not in FEED_KINDS:
        out.append(f"{tag}: kind {p.kind!r} is none of {sorted(FEED_KINDS)}")
    for asset, kind in dict(p.kind_by_asset).items():
        if asset not in ASSETS or kind not in FEED_KINDS:
            out.append(f"{tag}: kind_by_asset {asset!r}: {kind!r}")
    for asset, resolutions in dict(p.provides).items():
        if asset not in assets:
            out.append(f"{tag}: provides {asset!r}, not one of its assets")
        if not isinstance(resolutions, tuple) or not resolutions or not set(resolutions) <= RESOLUTIONS:
            out.append(f"{tag}: provides[{asset!r}] must be a tuple of {sorted(RESOLUTIONS)}")
    for resolution, n in dict(p.per_request).items():
        if resolution not in RESOLUTIONS or not (n is None or (isinstance(n, int) and n > 0)):
            out.append(f"{tag}: per_request {resolution!r}: {n!r}")
    for asset in dict(p.streams):
        if asset not in assets:
            out.append(f"{tag}: streams {asset!r}, not one of its assets")
    if not isinstance(p.live, tuple) or not all(isinstance(x, Live) for x in p.live):
        out.append(f"{tag}: live must be a tuple of sources.stream.Live")
    if not isinstance(p.exchanges, frozenset) or not all(isinstance(x, str) and x.isupper() and 2 <= len(x) <= 4
                                                          for x in p.exchanges):
        out.append(f"{tag}: exchanges must be a frozenset of MICs (or US, the consolidated market)")
    if not isinstance(p.bulk_resolution, (str, Mapping)):
        out.append(f"{tag}: bulk_resolution must be a str or a mapping")
    for attr in ("per_run", "per_day", "symbols_per_month"):
        n = getattr(p, attr)
        if not (n is None or (isinstance(n, int) and n >= 0)):
            out.append(f"{tag}: {attr} {n!r}")
    for attr in ("archival", "partial"):
        if not isinstance(getattr(p, attr), bool):
            out.append(f"{tag}: {attr} is not a bool")
    delays = p.delays
    if not isinstance(delays, Mapping):
        out.append(f"{tag}: delays must map a tier to its delays by asset")
    else:
        for tier, by_asset in delays.items():
            if not isinstance(tier, str) or not isinstance(by_asset, Mapping):
                out.append(f"{tag}: delays[{tier!r}] must map assets to Delay")
                continue
            for asset, delay in by_asset.items():  # an asset class, or a calendar its hours name (overnight)
                if not isinstance(asset, str) or not isinstance(delay, Delay):
                    out.append(f"{tag}: delays[{tier!r}][{asset!r}] is not a Delay by asset or calendar")
    if not isinstance(p.hours, Mapping) or not all(a in ASSETS and isinstance(h, str) for a, h in dict(p.hours).items()):
        out.append(f"{tag}: hours must map assets to a calendar kind")
    if not p.gives("build"):
        out.append(f"{tag}: a feed must give build()")
    out += _data(tag, p, "feed", assets)
    return out


def _publisher(tag: str, p: PublisherPlugin) -> list[str]:
    out: list[str] = []
    if not isinstance(p.feeds, tuple) or not all(isinstance(f, Feed) for f in p.feeds):
        out.append(f"{tag}: feeds must be a tuple of publisher.Feed")
    else:
        keys = [f.key for f in p.feeds]
        if len(set(keys)) != len(keys):
            out.append(f"{tag}: a feed key twice: {keys}")
    if not isinstance(p.policy, Policy):
        out.append(f"{tag}: policy must be a publisher.Policy")
    if not isinstance(p.kind, str) or not p.kind:
        out.append(f"{tag}: kind must be a non-empty str")
    if not isinstance(p.datasets, tuple):
        out.append(f"{tag}: datasets must be a tuple")
    else:
        from .dataset import Dataset

        if not all(isinstance(d, (Dataset, str)) for d in p.datasets):
            out.append(f"{tag}: datasets must hold Dataset definitions or names")
        names = [d.name if isinstance(d, Dataset) else d for d in p.datasets]
        if len(set(names)) != len(names):
            out.append(f"{tag}: a dataset twice: {names}")
    for prop in ("has_moments", "has_calendar", "reads_itself"):
        if not isinstance(getattr(p, prop), bool):
            out.append(f"{tag}: {prop} is not a bool")
    out += _data(tag, p, "publisher", frozenset())
    return out


def _data(tag: str, p: Plugin, kind: str, assets: frozenset) -> list[str]:
    """Its data classes (2.1; sources/data.py): a feed's `data` maps its asset classes to
    TimeSeriesData subclasses of those classes, a publisher's `data` is a DocumentData subclass or
    None; each class the plugin answers with (data_for, document_data) gives its spec and passes its
    own check; a plugin declaring any is written for 2.1 or later."""
    from .data import DocumentData, TimeSeriesData  # when asked, not on import: the specs read the calendars
    from .registry import api_version

    out: list[str] = []
    data = p.data
    if kind == "feed":
        if not isinstance(data, Mapping):
            return [f"{tag}: data must map an asset class to a TimeSeriesData subclass"]
        refused = set()  # the asset classes whose declared class is wrong: data_for is not asked for them
        for asset, cls in data.items():
            if asset not in assets:
                out.append(f"{tag}: data {asset!r}, not one of its assets")
            if not (isinstance(cls, type) and issubclass(cls, TimeSeriesData)):
                out.append(f"{tag}: data[{asset!r}] must be a TimeSeriesData subclass")
                refused.add(asset)
            elif cls.asset != asset:
                out.append(f"{tag}: data[{asset!r}] is {cls.__name__}, {cls.asset or 'no asset class'}'s data")
                refused.add(asset)
        for asset in sorted(assets - refused):
            try:
                d = p.data_for(asset)
                d.spec()
                out += [f"{tag}: data_for({asset!r}): {w}" for w in d.check()]
            except Exception as e:  # noqa: BLE001 - what it raised is the problem
                out.append(f"{tag}: data_for({asset!r}) failed: {type(e).__name__}: {e}")
        declared = bool(data)
    else:
        declared = data is not None
        if data is not None and not (isinstance(data, type) and issubclass(data, DocumentData)):
            out.append(f"{tag}: data must be a DocumentData subclass or None")
        else:
            try:
                d = p.document_data()
                d.spec()
                out += [f"{tag}: document_data(): {w}" for w in d.check()]
            except Exception as e:  # noqa: BLE001 - what it raised is the problem
                out.append(f"{tag}: document_data() failed: {type(e).__name__}: {e}")
    if declared:
        try:
            if api_version(p.api) < (2, 1):
                out.append(f"{tag}: declares data (plugin API 2.1) but is written for {p.api}")
        except ValueError:
            pass  # said already: not a contract version
    return out


def _assistant(tag: str, p) -> list[str]:
    from ..assistants.assistant import Assistant, Caps, Model, Plan, Source

    out: list[str] = []
    if not isinstance(p.vendor, str) or not p.vendor:
        out.append(f"{tag}: no vendor")
    if not (isinstance(p.assistant, type) and issubclass(p.assistant, Assistant)):
        out.append(f"{tag}: assistant must be an Assistant subclass")
    plans, models = p.plans, p.models
    if not isinstance(plans, tuple) or not plans or not all(isinstance(x, Plan) for x in plans):
        out.append(f"{tag}: plans must be a non-empty tuple of Plan")
        plans = ()
    if not isinstance(models, tuple) or not models or not all(isinstance(x, Model) for x in models):
        out.append(f"{tag}: models must be a non-empty tuple of Model")
        models = ()
    plan_names = [x.name for x in plans]
    model_ids = [x.id for x in models]
    if len(set(plan_names)) != len(plan_names):
        out.append(f"{tag}: a plan twice: {plan_names}")
    if len(set(model_ids)) != len(model_ids):
        out.append(f"{tag}: a model twice: {model_ids}")
    for x in plans:
        if not NAME.match(x.name):
            out.append(f"{tag}: plan name {x.name!r} is not a value for its plan variable")
        if not x.title:
            out.append(f"{tag}: plan {x.name!r} has no title")
        if not set(x.models) <= set(model_ids):
            out.append(f"{tag}: plan {x.name!r} unlocks unknown models {sorted(set(x.models) - set(model_ids))}")
        for attr in ("rpm", "tpm", "rpd"):
            n = getattr(x, attr)
            if not (n is None or (isinstance(n, int) and n > 0)):
                out.append(f"{tag}: plan {x.name!r} {attr} {n!r}")
    for x in models:
        if not x.title:
            out.append(f"{tag}: model {x.id!r} has no title")
        if not (x.input_usd >= 0 and x.output_usd >= 0 and (x.cached_usd is None or x.cached_usd >= 0)):
            out.append(f"{tag}: model {x.id!r} has a negative price")
        if not set(x.plans) <= set(plan_names):
            out.append(f"{tag}: model {x.id!r} on unknown plans {sorted(set(x.plans) - set(plan_names))}")
    if p.default_model and p.default_model not in model_ids:
        out.append(f"{tag}: default_model {p.default_model!r} is not in models")
    if not isinstance(p.sources, tuple) or not p.sources or not all(isinstance(x, Source) for x in p.sources):
        out.append(f"{tag}: sources must be a non-empty tuple of Source")
    elif not all(x.url.startswith("https://") and x.holds and x.sentinel for x in p.sources):
        out.append(f"{tag}: every source needs an https url, what it holds and a sentinel")
    try:
        date.fromisoformat(p.verified)
    except (TypeError, ValueError):
        out.append(f"{tag}: verified {p.verified!r} is not an ISO date")
    if not isinstance(p.caps, Caps) or min(p.caps.requests_per_day, p.caps.tokens_per_day, p.caps.max_output_tokens) <= 0:
        out.append(f"{tag}: caps must be a Caps with positive limits")
    if not isinstance(p.efforts, tuple) or not all(isinstance(e, str) for e in p.efforts):
        out.append(f"{tag}: efforts must be a tuple of str")
    if not isinstance(p.key_aliases, tuple) or not all(VARIABLE.match(a) for a in p.key_aliases):
        out.append(f"{tag}: key_aliases must be variable names")
    if not VARIABLE.match(p.key_var) or not VARIABLE.match(p.account_var):
        out.append(f"{tag}: its key and account variables are not variable names")
    return out


def _database(tag: str, p) -> list[str]:
    """A database plugin (2.3; storage/databases.py): written for 2.3, one of the engines, reached by methods that
    are, holding what an instance can hold, its variable declared, and able to open and to test what it holds."""
    from ..storage import databases as d
    from .registry import api_version

    out: list[str] = []
    try:
        if api_version(p.api) < (2, 3):
            out.append(f"{tag}: a database plugin is written for plugin API 2.3, not {p.api}")
    except ValueError:
        pass  # said already: not a contract version
    if p.ENGINE not in d.ENGINES:
        out.append(f"{tag}: ENGINE {p.ENGINE!r} is none of {sorted(d.ENGINES)}")
    for attr in ("METHODS", "HOLDS"):
        values = getattr(p, attr)
        known = d.METHODS if attr == "METHODS" else d.HOLDS
        if not isinstance(values, tuple) or not values or not all(isinstance(v, str) for v in values):
            out.append(f"{tag}: {attr} must be a non-empty tuple of str")
        elif not set(values) <= set(known) or len(set(values)) != len(values):
            out.append(f"{tag}: {attr} {values!r}: each once, of {sorted(known)}")
    methods = p.METHODS if isinstance(p.METHODS, tuple) else ()
    for attr in ("SERVER", "SHARES", "MAKES", "CONNECTS"):
        if not isinstance(getattr(p, attr), bool):
            out.append(f"{tag}: {attr} is not a bool")
    if isinstance(p.SERVER, bool) and methods and all(m in d.METHODS for m in methods):
        if any(d.METHODS[m].address != p.SERVER for m in methods):
            out.append(f"{tag}: SERVER {p.SERVER} with methods {methods!r}: a server's are addresses (socket, tcp), "
                       "a file's are not (file, helper)")
    for attr in ("DRIVER", "DRIVER_HINT", "SHARED", "ICON"):
        if not isinstance(getattr(p, attr), str):
            out.append(f"{tag}: {attr} is not a str")
    if p.SHARES is False and not (isinstance(p.SHARED, str) and p.SHARED.strip()):
        out.append(f"{tag}: it keeps no shares (SHARES False) and does not say who reaches its instances (SHARED)")
    if p.instances_variable not in p.options:
        out.append(f"{tag}: its instances are kept under {p.instances_variable}, which is not among its options")
    for hook in ("open", "probe"):
        if not p.gives(hook):
            out.append(f"{tag}: a database plugin must give {hook}()")
    if p.MAKES is True and not p.gives("make"):
        out.append(f"{tag}: it offers New database (MAKES) and gives no make()")
    return out


def _auditor(tag: str, p) -> list[str]:
    """The auditors' plugin (2.4; auditing.py): written for 2.4, declaring every one of the auditors' options with
    the library's choices for it, and answering `settings` with the Policy they make."""
    from .. import auditing
    from .registry import api_version

    out: list[str] = []
    try:
        if api_version(p.api) < (2, 4):
            out.append(f"{tag}: the auditors' plugin is written for plugin API 2.4, not {p.api}")
    except ValueError:
        pass  # said already: not a contract version
    lacks = [name for name in auditing.CHOICES if name not in p.options]
    if lacks:
        out.append(f"{tag}: its options lack {', '.join(lacks)}")
    for name, choices in auditing.CHOICES.items():
        if tuple(p.plan_choices.get(name, ())) != choices:
            out.append(f"{tag}: {name}'s choices are {', '.join(choices)} (auditing.CHOICES), the default first")
    if not p.gives("settings"):
        out.append(f"{tag}: the auditors' plugin must give settings(): the Policy its options make")
    else:
        try:
            made = p.settings({})
        except Exception as e:  # noqa: BLE001 - said, whatever it is
            made = e
        if not isinstance(made, auditing.Policy):
            out.append(f"{tag}: settings({{}}) must give an auditing.Policy (the defaults), not {made!r}")
    return out


def _lifecycle(tag: str, p: Plugin) -> list[str]:
    """How it runs and ends (1.86.0, liminal_libs.lifecycle): its MODE one of lifecycle.MODES and on demand (service
    mode is refused for now), its START_DEADLINE_S and STOP_DEADLINE_S numbers above nought (its own or the
    contract's), a `signal` it answers, and the login it is attached with kept as given: no class of it makes `login`
    a property or another descriptor of its own."""
    import math as _math

    from .. import lifecycle

    out: list[str] = []
    mode = getattr(p, "MODE", None)
    if mode not in lifecycle.MODES:
        out.append(f"{tag}: MODE {mode!r} is none of {list(lifecycle.MODES)}")
    elif mode == lifecycle.SERVICE:
        out.append(f"{tag}: MODE 'service': {lifecycle.SERVICE_REFUSED}")
    for attr in ("START_DEADLINE_S", "STOP_DEADLINE_S"):
        value = getattr(p, attr, None)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not _math.isfinite(value) or value <= 0:
            out.append(f"{tag}: {attr} {value!r} is not a number of seconds above nought")
    if not callable(getattr(p, "signal", None)):
        out.append(f"{tag}: it answers no signal (TERM, KILL): the contract's `signal` was replaced by something else")
    for cls in type(p).__mro__:
        if cls is Plugin or cls is object:
            break
        held = cls.__dict__.get("login")
        if held is not None and hasattr(type(held), "__get__"):
            out.append(f"{tag}: {cls.__name__} makes `login` its own ({type(held).__name__}): a plugin keeps the login "
                       "its app attached it with")
    return out


class _StandInNode:
    """A liminal-net node as node_problems serves a plugin on: it records what it is told, and opens nothing."""

    def __init__(self, name, kind, scope, hillock, interface, ipc_dir=None, timing=None):
        self.name, self.kind, self.scope, self.hillock, self.interface = name, kind, scope, hillock, interface
        self.stopped: list[str] = []
        self.fired: list[tuple] = []

    def stop(self, reason: str) -> None:
        self.stopped.append(reason)

    def fire(self, signal: str, data) -> None:
        self.fired.append((signal, data))

    def stage(self) -> str:
        return "ended" if self.stopped else "running"


class StandInRefused(OSError):
    """What a plugin served on stand-ins is told when it would start a process or reach a host (node_problems)."""


def _refused(*args, **kwargs):
    raise StandInRefused("a stand-in: nothing is started or reached while a plugin is checked as a node")


class _NothingReal:
    """No process started, no host reached, for the time of a `with` (node_problems): subprocess's Popen and run, the
    socket's connect and create_connection refuse (StandInRefused)."""

    def __enter__(self):
        import socket
        import subprocess

        self.saved = [(subprocess, "Popen", subprocess.Popen), (subprocess, "run", subprocess.run),
                      (socket, "create_connection", socket.create_connection),
                      (socket.socket, "connect", socket.socket.connect),
                      (socket.socket, "connect_ex", socket.socket.connect_ex)]
        for owner, name, _ in self.saved:
            setattr(owner, name, _refused)
        return self

    def __exit__(self, *exc):
        for owner, name, value in self.saved:
            setattr(owner, name, value)
        return False


def node_problems(p: Plugin) -> list[str]:
    """`p` served as its liminal-net node on stand-ins (1.86.0; liminal_libs.nodes), in words, empty when it holds: a
    copy of it attached to a stand-in app (an empty environment's login), a stand-in node, a stand-in process table,
    ledger and clock; no process is started and no host reached (each refused). It must keep the login it is attached
    with and refuse a signal from anyone but its app; answer ASK (interface, mode, processes, node, status) in shape;
    end on TERM within its STOP_DEADLINE_S with nothing left (no child of it in the ledger, none running, no claim
    held, let go of its app and login, its node ended); and, when a child of it ignores TERM, have that child killed
    at its deadline, not before. Each plugin repository's tests/test_contract.py calls it through
    assert_module_serves."""
    import os
    import time

    from .. import lifecycle, nodes
    from ..apps.app import App
    from ..apps.authorization import EnvironmentLogin

    tag = p.name or type(p).__name__
    out: list[str] = []

    class Probe(App):
        NAME, TITLE, ICON = "probe", "Probe", "plug"

    for ignores in (False, True):
        table, clock = lifecycle.FakeTable(), lifecycle.FakeClock()
        ledger = lifecycle.MemoryLedger(table)
        with _NothingReal(), lifecycle.standins(table=table, killer=table, ledger=ledger, clock=clock,
                                                sleep=clock.sleep):
            try:
                probe = p.with_()
            except Exception as e:  # noqa: BLE001
                return [f"{tag}: no copy of it can be made to serve ({type(e).__name__}: {e})"]
            app = Probe(log=lambda m: None, login=EnvironmentLogin(env={}))
            try:
                node, hillock = nodes.plugin_node(probe, app, node_factory=_StandInNode)
            except Exception as e:  # noqa: BLE001
                return [f"{tag}: it cannot be attached and served as a node: {type(e).__name__}: {e}"]
            hillock._later = lambda fn: fn()
            if probe.login is not app.lent_login() or probe.held_login() is not app.login:
                out.append(f"{tag}: it does not hold the login its app attached it with")
            if not ignores:
                try:
                    probe.signal(lifecycle.Signal.TERM, lifecycle.deadline_in(1), sender=object())
                    out.append(f"{tag}: it took a signal from someone who is not its app")
                except lifecycle.SignalRefused:
                    pass
                for what, keys in (("interface", ("hooks",)), ("mode", ("mode", "startDeadline", "stopDeadline")),
                                   ("processes", ("processes",)), ("node", ("node", "stage")), ("status", ("name",))):
                    try:
                        answer = hillock.ask(what)
                    except Exception as e:  # noqa: BLE001
                        out.append(f"{tag}: ASK {what} failed: {type(e).__name__}: {e}")
                        continue
                    if not isinstance(answer, dict) or any(k not in answer for k in keys):
                        out.append(f"{tag}: ASK {what} answered {type(answer).__name__}, not a map with {list(keys)}")
            pid = 990001 + int(ignores)
            table.rows[pid] = lifecycle.Proc(pid, os.getpid(), "stand-in", f"stand-in child of {tag}", 7)
            if ignores:
                table.ignores.add(pid)
            lifecycle.note(lifecycle.Row(pid=pid, started=7, owner=p.name, owner_pid=os.getpid(), owner_started=None,
                                         kind="stand-in", command=["stand-in"], at=time.time()), ledger)
            began, at = time.monotonic(), clock()
            answer = hillock.term()
            took = time.monotonic() - began
            deadline = lifecycle.stop_deadline(probe)
            how = answer.get("how") if isinstance(answer, dict) else None
            if how in ("failed", "late", "refused"):
                out.append(f"{tag}: TERM came to {how}: {answer.get('why')}")
            if took > deadline:
                out.append(f"{tag}: TERM took {took:.1f} s, past its STOP_DEADLINE_S ({deadline:g} s)")
            if pid in table.rows:
                out.append(f"{tag}: TERM left its child running")
            if lifecycle.mine(p.name) or [r for r in ledger.kept if r.owner == p.name]:
                out.append(f"{tag}: TERM left its child in the ledger")
            if lifecycle.claims_held():
                out.append(f"{tag}: TERM left claims held: {lifecycle.claims_held()}")
            if probe.app is not None or probe.login is not None:
                out.append(f"{tag}: TERM did not let go of its app and its login")
            if not node.stopped:
                out.append(f"{tag}: TERM did not end its node")
            if ignores:
                if (pid, "KILL") not in table.sent:
                    out.append(f"{tag}: a child ignoring TERM was not killed")
                elif clock() - at < deadline - 1e-6:
                    out.append(f"{tag}: a child ignoring TERM was killed before its deadline ({clock() - at:g} s)")
            with lifecycle._MINE_LOCK:  # nothing of the check is left behind
                lifecycle._MINE.pop(pid, None)
    return out


def assert_module_serves(module: ModuleType) -> list[Plugin]:
    """Every plugin of a module served as its node on stand-ins holds (node_problems); returns them."""
    found = plugins_of(module)
    assert found, f"{module.__name__} defines no plugin"
    wrong = [w for p in found for w in node_problems(p)]
    assert not wrong, "\n".join(wrong)
    return found


def plugins_of(module: ModuleType) -> list[Plugin]:
    """A module's plugins as the registry reads them (PLUGIN(S), PUBLISHER(S), ASSISTANT(S), MACHINE(S), DATABASE(S),
    AUDITOR(S))."""
    from .registry import _plugins_in

    return _plugins_in(module, module.__name__)


def assert_conforms(p: object) -> None:
    found = problems(p)
    assert not found, "\n".join(found)


def assert_module_conforms(module: ModuleType) -> list[Plugin]:
    """Every plugin of a module conforms; returns them (at least one)."""
    found = plugins_of(module)
    assert found, f"{module.__name__} defines no plugin"
    wrong = [w for p in found for w in problems(p)]
    assert not wrong, "\n".join(wrong)
    return found
