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

What a plugin needs of the machine it runs on (1.103.0): its `NEEDS` rows, judged by `needs.py` against this
machine's facts, which `facts.py` reads without sending anything (the recorded machines every package's test judges
against are `needs_machines.py`). Every app answers `GET /api/needs`, and `ui/static/needs.js` draws it; a plugin whose
needs this machine cannot meet is left out of the platform's list (INTEGRATION.md says how a plugin declares them).

The platform's AI plugins (`machines/ai.py`, 1.62.0) come in groups: the model servers (`ModelServer`), the coding
harnesses (`Harness`) and, from 1.66.0, the protocol plugins (`ProtocolPlugin`, `machines/protocol.py`: MCP's, which
mediates the local AI agents' connections on the platform's own port). What they stand on is here too: a piped child
(`machines/children.py`, `Piped`), a private Node.js and npm (`machines/node.py`), and Hugging Face's cache and its hf
command (`machines/hub.py`). Who may ask a hook is a plugin's word too (1.66.0): `PLUGIN_ONLY_HOOKS`, asked only by
another plugin, and `PAGE_ONLY_HOOKS`, asked only from its page (`apps/asking.py` says who asks; INTEGRATION.md says
the rest). From 1.99.0 the model servers' and the harnesses' bases say theirs: an install, a start, a stop, a key, a
window opened and every other change is asked only from the page, and their reads by anyone. From 1.107.0 every hook
is closed by default (the user, 2026-11-26: "Yes, closed by default"): one a plugin declares for no one is its page's
alone, a read is opened by `READ_HOOKS` and an ask between plugins by `SERVICE_HOOKS` (`internal.audience`,
`conformance.warnings`; INTEGRATION.md).

An app behind a front (1.98.0). Every app answers 127.0.0.1 alone, and whatever hands requests on to its port (a
reverse proxy beside it, its TLS end) connects from there as a program of the machine does. It must set
`X-Liminal-Front: 1` on every request it hands on, over whatever a client sent (`web.FRONT_HEADER`; Caddy:
`header_up X-Liminal-Front 1`; nginx: `proxy_set_header X-Liminal-Front 1;`): the mark is how `web.from_this_machine`
tells them from a program's here. An app that holds a local login lets a request from this machine in as its secret
user, the admin, without a password, so behind a front with no mark it lets in everyone who reaches the front. A net
under the mark: a request that carries X-Forwarded-For or X-Forwarded-Proto is not this machine's either. That covers a
front that writes them unasked (Caddy) and not one that writes neither (nginx's plain `proxy_pass`, a TCP forward). A
mark does not by itself make an app fit to be reached from elsewhere: the frame's own `/api/` routes ask no session.

The workspace (`layout.py`): one folder holds `common/` (this library's checkout), `app/` (the chart app),
`store/` (the integrator, the databases in `store/data/`) and `plugins/` (a checkout per plugin, loaded from
there by the registry). Found by its four folders above this checkout, or named by `LIMINAL_HOME`.

Install: `pip install -e .` (the app and the integrator depend on it). Tests: `python -m pytest -q` (the full
suite still runs in the app's repository, with the library installed; it moves here module by module).
