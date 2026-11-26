# How the Liminal repositories fit together

A brief for anyone touching more than one repository (2026-11-03). The long form of each part is
`docs/ARCHITECTURE.md` in liminal-charts; each repository's README and CHANGELOG say what it is and
what changed.

## The pieces

| Repository (pcxmac-dev) | Python package | Command | What it is |
|---|---|---|---|
| `liminal-libs` | `liminal_libs` | – | The library every program and plugin builds on: the stores, the plugin contract and registry, the collector, the delivery scheme, the calendars, the resident hosts, the live recorder, the settings. |
| `liminal-charts` | `liminal_charts` | `liminal-charts` | The charts app: the chart page, its data and monitoring views, the command line; a front that funnels every request of its pages to the fetcher. |
| `liminal-integrator` | `liminal_integrator` | `liminal-integrator` | The fetcher: a stack of requests, an assessment of the work over the plugins, the standing pass, the data API page, a service or daemon from your logon. |
| `plugin-integrator-<name>` (fifteen) | `plugin_integrator_<name>` | – | The stock-data plugins of the integrator: feeds (Massive, Alpaca, Tiingo, the crypto venues, Cboe, TWSE, B3, Alpha Vantage, J-Quants, Twelve Data) and publishers (Federal, Ken French, Datahub). |
| `plugin-platform-<name>` (three) | `plugin_platform_<name>` | – | The AI assistants of the platform: Claude, Grok, Codex, each on your own API key, evaluating standardized arguments. |
| `liminal-login` | `liminal_login` | `liminal-login` | The login app: the users, each with a store of key-vector pairs (API keys, account names, passwords) encrypted from their password; its page at 8795 with the one user icon; what every other app and plugin asks for a key (`liminal_libs.apps.LoginClient`). |

Coming with 0.3.0: `liminal-platform` (the machine's information, the AI plugins' host, the IPC nexus
and the base class of the charts app), `liminal-login` (authorization), `liminal-plugins` (the
plugins-manager serving every plugin of every app), and the charts app's own plugins
`plugin-charts-<name>` (analysis, trading, watchlist, preferences).

## The naming convention

- Apps, the trays in the GUI: `liminal-<app>`, the short name being the app's (charts, integrator,
  platform, login, plugins). The command line is the full name (`liminal-charts gui`,
  `liminal-integrator serve`).
- The one common library: `liminal-libs`.
- Plugins: `plugin-<app>-<name>`, named by the app they plug into: `plugin-integrator-massive`,
  `plugin-platform-claude`, `plugin-charts-analysis`.
- Python packages are the same names with underscores (`liminal_charts`, `plugin_integrator_massive`);
  a plugin's registry name is its own short name (`massive`, `claude`), its entry point under the
  group `liminal.providers`.

## The workspace on disk

One folder holds the four (`liminal_libs.layout`: found by the folders above the library's
checkout, or named by `LIMINAL_HOME`):

```
liminal/
  common/    liminal-libs (this repository)
  app/       liminal-charts (its .venv inside: every program is installed editable there)
  store/     liminal-integrator, with the databases in store/data/ (never in git; LIMINAL_DB overrides)
  plugins/   a checkout per plugin, loaded from there by the registry (LIMINAL_PLUGINS names another folder)
```

On the user's PC the folder names stay `common`, `app`, `store`, `plugins` whatever the repositories are called.

## Who depends on whom

- A plugin depends on `liminal-libs` alone, and no plugin imports another. Its CI installs the
  library from the branch it is tested against (`LIMINAL_LIB_REF`).
- `liminal-integrator` depends on `liminal-libs` and, for the page and data API it serves, on
  `liminal-charts`; `lib.py` is the one place in it that names either. (At 0.3.0 the page front
  moves out of the charts app into the platform, so the integrator stops importing the charts app.)
- `liminal-charts` depends on `liminal-libs`; its `integrator` extra brings the fetcher, its
  `plugins` extra every plugin, each pinned by git reference in `pyproject.toml`.
- Nothing imports a plugin by name (the charts app's tests enforce it). The registry
  (`liminal_libs.sources.registry`) finds plugins through their entry points: the checkouts in
  `plugins/` first, then installed packages; the same plugin is never loaded twice. Which plugins a
  process loads is a selection (`LIMINAL_PLUGINS_LOADED`, the integrator's `--plugins`): every
  plugin found by default, the ones named, or none.

## How a plugin plugs in

The contract is `liminal_libs/sources/plugin.py` (plugin API 2.0): `Plugin` → `IntegratorPlugin`
(`FeedPlugin`, `PublisherPlugin`: the stock-data plugins) and `PlatformPlugin` (`AssistantPlugin`:
the AI plugins), each named for the system it plugs into. A plugin is an instance of a subclass: what
it declares are class attributes (its name, keys, plans, assets, delays, databases), what it does are
methods overriding the contract's defaults (`build`, `view`, `scan`, `settings`, a publisher's
`moments`/`calendar`/`read`, an assistant's models and evaluations). The record form (`Provider`,
`Publisher`, plugin API 1.x) still loads. A plugin fetches on its own through the shared queue when it
has a `Fetcher`, keeps its own databases in the data folder (`layout.Database`), and refreshes its
own plan information with its capability scan.

A database engine is a plugin too (plugin API 2.3, liminal-libs 1.61.0: `liminal_libs/storage/databases.py`,
`DatabasePlugin`, an `IntegratorPlugin`; `plugin-integrator-sqlite`, `-duckdb`, `-mongodb`, then
`-postgres` and `-mariadb`). It holds instances: its own, which are today's databases opened as today,
and the ones you add on the integrator's Databases view, each with what it holds, where it is, the
method it is reached by (`file`, `helper`, `socket`, `tcp`), its port, who else may attach and on a
server the role used there. What you add is kept through the plugin's login (one value under
`<ENGINE>_INSTANCES`, a sign-in as two more pairs), never in a file.

The auditors' options are a plugin's too (plugin API 2.4, liminal-libs 1.64.0: `liminal_libs/auditing.py`,
`AuditorPlugin`, an `IntegratorPlugin`; `plugin-integrator-auditor`, one for an app). The auditors themselves
are the library's and run without it, on the same defaults. What a feed is asked for is a pull: its answers
and the rows made of them are written beside the main file first (`cache/<feed>/<pull>/`: `spool.py`,
`storage/pulls.py`) and the database is loaded from those files. A pull's files go only once the copy audit
held every bar of them against what was stored (`auditing.audit_pull`): a bar missing is put in from the
cache, a bar stored with other values is a finding and is asked for again, and nothing stored is overwritten.
The sweep (`auditing.Sweep`) goes over every watched series in turn for session days that should hold bars
and do not, and for what cut-off pulls left. Findings are the main file's `audit_findings`.
`LIMINAL_FETCH_CACHE=off` writes as before 1.64.0.

The platform's own plugins are machine plugins (`liminal_libs/machines/plugin.py`, `MachinePlugin`, a
`PlatformPlugin`): each a part of this machine or of what it reaches, drawn under its `SECTION` (machine,
virtualization, os, cloud, ai). The AI section's are `AiPlugin`s (`machines/ai.py`, 1.62.0), each in a `GROUP`:
"inference" for a model server (`ModelServer`), "harness" for a coding harness (`Harness`) and, from 1.66.0,
"protocol" for a protocol plugin (`ProtocolPlugin`, `machines/protocol.py`), MCP's first. The user, 2026-11-18: "now
i need an MCP plugin for platform, basically a protocol plugin that mediates MCP connections to resources by local AI
agents". A protocol plugin answers the local AI agents on the platform's own port: liminal-platform 0.34.0 hands each
request whole to the hook its `RPC_HOOK` names (`rpc`), at `/api/machines/<name>/rpc`, and the plugin finds the
agent by its token. Its software is its own code, so there is nothing to install (`Installed.how` "part").

## How the programs talk at run time

- Everything shares the databases in `store/data/`; one process at a time owns a writer, through the
  resident hosts of `liminal_libs.host`: a process that runs only while a client is attached over a
  local pipe (named for the host and the database, this user's key on both ends). The hosts are the
  fetcher (one per database), each feed's run (`feed-<name>`), the closed months' copy to DuckDB, the
  live recorder and the keeper of the MongoDB server. A host nobody holds ends after its idle time.
- Two listeners on the machine (the user, 2026-11-03: "for the webserver / ports, i just integrator,
  and charts"): the integrator's process serves its page and the data API at port 8785
  (LIMINAL_FETCHER_PORT; the charts app's `serve_integrator`, reading the data itself) and holds the
  fetcher host over the pipe while a page is in touch (started if none answers, let go when quiet);
  the fetcher host has no HTTP of its own. The charts app's front at 8765 serves the chart page and
  proxies its pages' data requests to the integrator's port; an integrator that does not answer is
  not running, and nothing starts it from there (1.52.0; the user, 2026-11-14: "don't start any of the
  applications in the background"; "i only want ports for liminal-login ; liminal-platform ;
  liminal-charts ; liminal-integrator"). The integrator's service keeps its page there from your logon; `--daemon` holds the fetcher for good so
  it collects on its own. Several integrators can run at once (`--name`), each on its own database
  and port; a key's machine-wide ledger is shared by key, whichever integrator spends it.
- An AI evaluation runs in the caller's process over HTTPS and is recorded in the main file's
  `evaluations` table; nothing is sent from an offline copy.
- A suite on another system (the one inside WSL) reaches the SQLite files through a helper it starts
  on the system that holds them (`liminal_libs.storage.link`: a private pipe, no port). It says who it
  is, and the helper opens each file as the share set on its instance says: reading and writing,
  reading alone, or not at all; with no share set, as before (1.61.0).
- An audit asked for is a request of the kind `audit` in the requests' ledger (1.64.0). The fetcher hands it
  to a short-lived auditors' process (`liminal-integrator audit run`), one at a time for a database (the claim
  `audit`), which it also starts when the sweep is due; a feed's own run audits each pull as it closes.

## The apps and their trays (liminal-libs 1.7.0)

The user, 2026-11-04: every app (login, charts, platform, integrator, the plugins manager) has its
own web server, its own icon and its own tray of icons on the right of its page; one master icon
controls the app itself (charts: the symbol; integrator: the fetcher; platform: the plugins; login:
the user) and every other icon is a view plugin of that app (`plugin-<app>-<name>`); the data and AI
plugins sit inside their app's Plugins icon. A super app (the charts app) binds the others and draws
their trays under its own, a divider between each; a bound app's views render left of the icons when
one of its icons is picked; the integrator may run as a daemon on another port and still be bound in
"seamlessly like it is local". The library holds the frame (`liminal_libs.apps`: `App`, `Tray`,
`TrayItem`, the server every app runs, `web.py`), the common graphics (`liminal_libs.ui`: `icons.js`,
`liminal.css`) and the clients of the apps (`LoginClient`); what is particular to one app stays in
that app's repository. The binding of trays and the proxies over the hosts' pipe come with 0.3.0;
today the charts front proxies the integrator's data API by hand.

Linked or included (1.52.0; the user, 2026-11-14: "the idea is for an app like charts to be able to 'link' to an app
like platform or an app like integrator or both"; "linking vs including the objects, is so that parts of the code can be
executed remotely, and connected through the icon bridge (far right side)"; "the platform and integrator inherit the
login function, they are separate login instances, class vs object"): an app links another at its address, on this
machine or another, its tray on the far right, its pages passed on (`apps.binding`), never starting it; an app includes
an object, the login it inherits (`App.login_object`), answered at its own port. Only the four apps have ports: charts
8765, platform 8775, integrator 8785, login 8795 (the login on its own, which points to nothing).

## Authorization and IPC (liminal-libs 1.10.0)

The user, 2026-11-06: the login instance of an app furnishes that app's plugins their keys and passwords;
"the app plugins need to use the Abstract Base Class login as the only way to present an interface for
IPC, between plugins and login and the app as far as AUTHORIZATION"; "the plugins use an ABC plugin to
communicate IPC between themselves and the APP for functionality"; "the app itself (either chart or
integrator) has plugin ABC as well"; "the plugin ABC will enumerate attached plugins and their API".
So: `liminal_libs.apps.Login` is the one authorization interface (realized by `LoginClient` over HTTP to
the login app of the app's namespace, by `EnvironmentLogin` for the transition, by a test's stand-in);
a plugin attached by its app (`App.attach`) holds the app and its login and asks `self.login.key(self.name)`
for its key, nothing else; the plugin contract's `interface()` enumerates the hooks a plugin answers
(`Plugin.HOOKS` by kind) and `ask(hook, ...)` calls one by name, the app's `plugins()` enumerating every
plugin attached and its API and `ask(name, hook, ...)` calling across; the app offers its own surface the
same way (`interface()`). In-process today; the proxy over the hosts' pipe comes with the resident plugins.

Since 1.11.0 the pairs are named by the variables (the user, 2026-11-06: "By the variables"): the pair
of `MASSIVE_API_KEY` is `massive-api-key` (`KeyVar.pair`, `apps.pair_name`, `apps.variable_name`), so a
user keeps one key under one name in the login app, the Plugins view and the environment. An app reads
its plugins' keys through its login: `load_settings(login=app.login)` lets the login's pairs win over the
environment (`Login.variables`), and `apps.attach_registry(app)` attaches every plugin the registry loaded
to the app with that login. The integrator's fetcher and the charts app hold an `EnvironmentLogin` until a
daemon can hold a login session of its own; the login app lists the pairs the plugins ask for
(`GET /api/pairs/known`) so a user adds a key under the name the plugin reads.

## The External and Internal API tabs (liminal-libs 1.63.0)

The user, 2026-11-16: "for all apps, and all plugins, there should be an external api tab, and an internal api tab,
the internal api is for interfaces the plugin shares with the rest of the app, the external should be all the
SDKs/APIs the plugin associates with"; 2026-11-17: "all plugins are middleware". So the library gives every app
and every plugin both. The External API is what it associates with: its `apis`, the cards of `liminal_libs.apis` (the
standard library alone; `liminal_libs.sources.apis` names the same objects), and what it learned of them,
`api_facts()`. The Internal API is what it shares with the rest of the app, made from the object itself by
`liminal_libs.internal` (the standard library alone; nothing of a plugin is called or evaluated) and drawn by
`ui/static/internal.js`.

What a plugin says of it, all optional: plain tuples of words on its class, read by name (`sources/plugin.py`; no
plugin API number moved, no floor moved). A plugin that says nothing has both tabs all the same, each hook of its own
listed as a change.
- `READ_HOOKS`: its hooks that only read, beside its bases' (a base's names stay its subclasses'). A read changes
  nothing here, at a provider or in what is kept through the login: it may run a command that reads and ends, ask a
  provider without spending its requests or quota, or change only what its page shows until the app restarts. A
  hook that spends them (a scan, a publisher's `read`), costs money, starts a program that keeps running, opens a
  listener, takes an `accept_*` argument or is a job is not one.
- `SERVICE_HOOKS`: its hooks other plugins ask through the app (`self.app.ask(...)`); its page draws none for them.
- `ASKS`: what it asks of other plugins, rows `(plugin, hook)` or `(plugin, hook, why)`, the plugin `""` for
  whichever offers the hook.
- `KEEPS`: what it keeps through its login beside its keys, rows `(variable, about)`; a property where the variable
  is named after the plugin (a firewall's groups, a model server's instances).
- `INTERNAL_NOTES`: a few lines more, each at most 400 characters (the first 40 are read).
- `PLUGIN_ONLY_HOOKS` (1.66.0): its hooks only another plugin asks, through the app (`self.app.ask(...)`): never its
  page, never a program. liminal-platform 0.34.0 refuses them over HTTP (403) and leaves them out of its page.
- `PAGE_ONLY_HOOKS` (1.66.0): its hooks only its page asks, never another plugin (403). Over HTTP the platform asks
  one when its login says you are there, or when it holds no login (`App.present`), and refuses it (401) when the
  login says you are not. A base may say them for its plugins, as `ContainedService`, `ContainerHost`,
  `ProtocolPlugin` and the WSL base do, and from 1.99.0 `ModelServer` and `Harness` (their changes: an install, a
  start, a stop, a key, a window opened; their reads and a model server's `serving` and `models_of` are asked by
  anyone). The names add up along the class line, so a plugin names only the changes it adds
  (`PAGE_ONLY_HOOKS = ("pull", "delete_model")`). What the login says is that a browser is signed in to it, and a
  local login signs `secret` and `default` in with no password: the word does not stop a program on this machine
  that signs itself in.

Who asks is handed over in so many words (1.66.0, `liminal_libs.apps.asking`), never taken from what a thread
inherits: an app's route for its page sets the page (`asking(PAGE)`), `App.ask` sets the plugin that asks for that
call, and a job takes its asker where it is started and sets it in its own thread (`handed`). A hook reads it with
`asker()`, never from an argument. A gated hook asked with no asker is refused in words (`refusal`, `check`,
`AskRefused`). `internal.plugin_only` and `page_only` read the two words along the class line, and refuse when a word
cannot be read. A plugin that says neither word is asked exactly as before.

Each package's own test holds it to them:

```python
internal = pytest.importorskip("liminal_libs.internal")


def test_what_it_says_of_the_interface_it_shares_is_sound():
    assert internal.problems(MACHINE) == []
```

What the library gives code (`liminal_libs.internal`): `internal_of(plugin, ...)`, a plugin's Internal API as plain
JSON; `app_internal(app)`, an app's; `problems(plugin)`; `reads_of(plugin, reads, tabs)`, what an app asks as reads
(the app's own, its tabs' hooks, then the READ_HOOKS the plugin answers itself, never a job or a read that takes an
`accept_*` argument); `answers(plugin)`, the hooks it answers itself; `answered_by(obj, name)`, whose code answers a
hook (the rule `Plugin.gives` asks); `kind_of(plugin)`; `tabs_key(plugin, tabs)`; and `literals_in` and
`route_problems`, for a test holding a table of routes to the code that answers them.

What an app says and offers (`apps/app.py`): `apis` (a property importing them when asked, where its start must not
load them), `ROUTES` (its own routes beside the frame's, `(method, path, about[, kind[, who]])`), `LINKED` (the apps it
links, `(name, how[, variable[, prefix]])`), `CALLS` (`{kind: {name: how}}`, what its code calls on a plugin of each
kind), `ATTRIBUTES` (`{kind: (name, ...)}`, what it reads of one by name) and `INTERNAL_NOTES`; where it knows more of
its plugins than the frame does, `askable(plugin)`, `known_plugins()` and `call_words(plugin)`; and for code
`plugin_internal(plugin, tabs=None)`, `internal()` and `own_apis()`. Every app answers `GET /api/app/apis` with
`{"app", "internal", "apis", "apiFacts"}`, and `GET /api/app/apis?plugin=NAME` with an attached plugin's `{"name",
"internal", "apis", "apiFacts"}` (404 for any other name). A page draws them with `LiminalApis.html` and
`LiminalInternal.html(d, opts)` (a plugin's `internal`, a list of them, an app's, or null: then `opts.older`);
`LiminalInternal.tabs(list, shown, label)` gives a page with no tabs of its own a row of them, and
`LiminalInternal.style()` its styles. liminal-platform 0.32.0 draws both for its plugins and for itself; the charts,
the integrator and the login follow.

## What a plugin needs of the machine (liminal-libs 1.103.0)

The user, 2026-11-18: every plugin has a "needs" requirement (the operating system, the hardware platform, GPUs, the
internet); a plugin whose needs this machine cannot meet is not shown in the left-most list, and the Connections view
lists every plugin, red for what could be met and is not now, shaded for what never can be here. A plugin says them in
`NEEDS`, plain rows on its class, read by name and never called, so it imports nothing for them:

```python
class UbuntuPlugin(WslDistribution):
    NEEDS = (*getattr(WslDistribution, "NEEDS", ()),
             ("architecture", "x86-64|arm64", "required", "the systems Ubuntu's WSL image is built for"),
             ("disk", ">= 4 GiB", "part", "its install"))
```

- A row is `(attribute, value[, strength[, words]])`: an attribute of `needs.ATTRIBUTES` (a `windows:` or `linux:`
  prefix makes it one system's), its value (`a|b` is any of them), its strength and its words (200 characters at
  most). `required`, unmet: out of the list. `part`, unmet: that part is said unavailable in its words, the plugin
  stays as it is. `preferred`: said, nothing else. A part and a preference need words; tools, rights, other plugins,
  the disk and the desktop are never required (they are a plugin's validity: its page offers what meets them).
- Only the getattr idiom adds to a base's rows; NEEDS is never a property and never annotated. `Plugin` has none: a
  plugin that says nothing is "It has not said what it needs yet", one with `NEEDS = ()` "It needs nothing of this
  machine". A plugin's own `not_for_here()` counts as one more unmet need of the machine, in its words.
- An older library reads nothing of them: no floor moves, and the plugin API stays 2.4.

Each package's own test holds its rows to the vocabulary the installed library knows (an attribute it does not know
is judged unknown, never a problem), then judges them against the recorded machines:

```python
needs = pytest.importorskip("liminal_libs.needs")
needs_machines = pytest.importorskip("liminal_libs.needs_machines")


def test_what_it_needs_is_sound_and_met_where_it_is_for():
    assert needs.problems(MACHINE) == []
    rows = needs.declared(MACHINE)
    assert needs.judge(rows, needs_machines.facts_of("this-pc"))["met"] is True
    assert needs.judge(rows, needs_machines.facts_of("wsl-ubuntu-24.04"))["sort"] == "machine"
```

What an app gives (`apps/app.py`): `needs_of(plugin_or_name, fresh=False)`, `machine_facts(attributes, fresh, names=)`
and `needs_report(fresh, only)`, and `GET /api/needs` (`?fresh=1`, `?plugin=NAME`); a subclass answers
`internet_rule()` and `offline()` where it holds a switch or Settings, and `plugin_states()`. A page draws an answer
with `LiminalNeeds.table(answer)`, `line(answer)` and `style(answer)`. Nothing of it sends anything: `facts.py` reads
the system's own state (Windows' Network List Manager, NetworkManager's last verdict), never asks it to probe, and
under a test reads nothing real at all unless `LIMINAL_REAL_FACTS=1`.

## Containers (liminal-libs 1.18)

`liminal_libs.docker` drives the docker command (or Rancher Desktop's `nerdctl`: LIMINAL_DOCKER_COMMAND) for
the containers an app or a plugin needs, on this machine's engine or another machine's through a Docker
context or host (LIMINAL_DOCKER_CONTEXT, LIMINAL_DOCKER_HOST: a VPS over SSH). The first use is a domain
login's mail server, declared under `[server]` in `liminal-login.cfg`. Containers are optional: every Liminal
app runs without one. What they need (the user, 2026-11-07: "a hard constraint for liminal framework, is WSL
is required"): on a Windows PC, a local engine runs its Linux VM in WSL 2 (Docker Desktop by default, Rancher
Desktop always; Docker Desktop's Hyper-V backend is the one exception), so containers on this PC need WSL 2;
a context to another machine needs none here; on Linux the engine is native. `Docker.describe()` says
whether WSL is there when no engine is installed on Windows.

## Keys and accounts

Keys live only in your user environment variables (the Windows registry's user `Environment` key;
never a file this software writes), declared by each plugin as `KeyVar`s and set from the Plugins view
or `tools/set-key.ps1` in liminal-charts; a plugin's plan is read from its own variables, or found by
its scan. The direction (the user, 2026-11-03): `liminal-login` becomes the root authorization for
all plugins and software integration, providing the key and account infrastructure to the plugins.
Every plugin and software component inherits a login base class that gives it IPC with the running
login app; the login app stores the keys and accounts as key–vector pairs that interrogate the
current logged-in user for a particular account (the key `claude-account-name` or
`claude-account-api-key`; the vector returned is the API key, the account name or the account
password), and only the liminal-login instance can furnish them.

## Branches, versions, releases

Every repository is on `release/0.2.0` for the object-oriented rewrite; the charts app pins the
library, the integrator and the eighteen plugins by that branch. The cut-over sets the library and the
integrator to 0.2.0, moves every pin to the `v0.2.0` tags, merges to `main`, tags and releases each
repository, and the plugins' CI goes back to testing against `main`. Push order when a change crosses
repositories: the library, then the plugins, then the integrator, then the charts app (whose CI installs
all of them). Each repository runs its tests on Windows and Ubuntu over several Python versions.
