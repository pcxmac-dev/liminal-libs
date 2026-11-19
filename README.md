# liminal-libs

The Liminal library: the common code every Liminal program builds on (INTEGRATION.md: how the
repositories fit together; the naming: apps `liminal-<app>`, this library `liminal-libs`, plugins
`plugin-<app>-<name>`).

- [liminal-charts](https://github.com/pcxmac-dev/liminal-charts): the charts app (its front, its pages, the data API and the command line);
- [liminal-integrator](https://github.com/pcxmac-dev/liminal-integrator): the fetcher, which collects the data and serves it;
- the plugins: `plugin-integrator-<name>`, one per data provider, and `plugin-platform-<name>`, the AI
  assistants, the machine plugins and the AI plugins (model servers, coding harnesses and, from 1.66.0, protocol
  plugins), on the contract here (`sources/plugin.py`: the classes; `sources/registry.py`: the registry).

What is here (`src/liminal_libs`): the stores (`storage/`: SQLite, DuckDB and MongoDB by data type), the plugin
contract and the registry (`sources/`), the data specs (`sources/data.py`: what each kind of data a plugin delivers
is, how complete and fresh a frame of it is, whether its rows are sound), the collector (`collector.py`: the finest data each plan allows, as far
back as it allows, within its limits), the delivery scheme by cost and capability (`sourcing.py`), the calendars
and publication delays (`freshness.py`, `sessions.py`), the resident hosts over local pipes (`host.py`), the live
recorder (`live.py`), the composites, derived frames and provenance, the datasets, the publishers, and the settings
(`config.py`: keys only from your environment variables).

Every app and every plugin can show an External API tab and an Internal API tab (1.63.0; liminal-platform 0.32.0
is the first app to draw them). The External API is the cards of what it associates with (`apis.py`: the standard
library alone, so that an app holding no plugin needs neither the registry nor pandas to say it; `sources/apis.py`
names the same objects). The Internal API is made from the object itself by `internal.py` (a plugin as middleware:
the base it is built on and so the standard interface it implements, its hooks and who uses each; an app's: what
its code calls on its plugins and what it offers them, its routes) and drawn by `ui/static/internal.js`. Every app
answers both at `GET /api/app/apis`, and an attached plugin's with `?plugin=NAME` (INTEGRATION.md says what a
plugin and an app may declare for them).

The platform's AI plugins (`machines/ai.py`, 1.62.0) come in groups: the model servers (`ModelServer`), the coding
harnesses (`Harness`) and, from 1.66.0, the protocol plugins (`ProtocolPlugin`, `machines/protocol.py`: MCP's, which
mediates the local AI agents' connections on the platform's own port). What they stand on is here too: a piped child
(`machines/children.py`, `Piped`), a private Node.js and npm (`machines/node.py`), and Hugging Face's cache and its hf
command (`machines/hub.py`). Who may ask a hook is a plugin's word too (1.66.0): `PLUGIN_ONLY_HOOKS`, asked only by
another plugin, and `PAGE_ONLY_HOOKS`, asked only from its page (`apps/asking.py` says who asks; INTEGRATION.md says
the rest).

The workspace (`layout.py`): one folder holds `common/` (this library's checkout), `app/` (the chart app),
`store/` (the integrator, the databases in `store/data/`) and `plugins/` (a checkout per plugin, loaded from
there by the registry). Found by its four folders above this checkout, or named by `LIMINAL_HOME`.

Install: `pip install -e .` (the app and the integrator depend on it). Tests: `python -m pytest -q` (the full
suite still runs in the app's repository, with the library installed; it moves here module by module).
