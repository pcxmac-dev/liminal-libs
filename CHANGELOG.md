# Changelog

## 1.94.0 (2026-11-25)

`ContainedService`, the base of a service plugin (Monday list item 34, and item 35's next; service-containers-design
§3.8, with the user's answers of 2026-11-25: "Containers only", "Containers too", a service starting and stopping with
its app with service mode provided for and not offered, never a restart after a crash, an engine that is off never
started, "Seeded, PC-only first"). Added beside 1.93.0's interface; nothing of it is changed.
- **`machines/containedservice.py`**: `ContainedService(MachinePlugin)`. A subclass gives `spec_for(system, name,
  options)` and, where its software says more, `ready`, `lan_ready`, `after` and `address`; the base answers `hosts`
  (a read: every attached container plugin asked `hosting` with one spec per system of its recipe, holding no lock,
  kept READ_S; each target offered for Install… only while here, ready, taking the recipe, granted to it, and, while
  `NEEDS_LOOPBACK` holds, reached at a loopback address; every container plugin the platform knows and has not attached
  listed with `plugin_state`'s words), and five changes that are the page's alone (declared PAGE_ONLY_HOOKS and checked
  again inside each): `service_install(plugin, target, name, lan, boot, memory_mb, *ports)`, `service_change(action,
  name, choice)`, `service_carry(plugin, plan, log)` (the job, cancellable: refused before its first line unless the
  plan is approved; its work followed, a Cancel passed on once, its software waited for READY_S at most, the placement
  kept through its login as `<NAME>_SERVICES`, `after` run), `service_log` and `service_forget` (deletes nothing).
  Install… and every change answer `containers.approval_answer` (the plans to approve and `service_carry` as `then`).
  `LAN_FIRST = False` installs on this PC alone and lets Expose… open it only once `lan_ready` says yes; `boot` and At
  boot are refused in the service-mode words; a pin whose digest is `UNREAD` (all zeros: not read from its registry yet)
  is refused before any plan; an update needs pins newer than the placement's. Turned off (its detach while the platform
  says it is disabled), it asks `release_owned` of each container plugin hosting its services; a detach for invalidity
  asks nothing. Its page: Run <it> in a container, Its services (each change's button), Waiting to be carried out, and
  their forms. Helpers a seed may hold: `pbkdf2_hash`/`pbkdf2_check` (salted PBKDF2-SHA256) and `sha1_b64` (GoCD's
  file sign-in); `loopback`, `unread_pins`.
- **`machines/servicestandins.py`**: a service plugin's tests' world: `Frame` (an App saying who is off, who is known and
  the platform's word), `JobLog` (a job's output with `cancelled`), `ServiceWorld` (the plugin under test beside the
  stand-in container plugin over a FakeDocker, the stand-in firewall and WSL plugin; `grant`, `approve`, `carry`,
  `through`, `install`).
- Tests: `test_contained_service.py` (36), through a real apps.App on the stand-ins; each of its 28 gates taken out once
  made a test fail.
- Found, not changed (1.93.0's `ContainerHost._check_secrets`): a secret whose pair the asker itself declares among its
  keys is refused as "another plugin's" (`_others_declare` does not leave the asker out), so a service plugin cannot
  hand a secret it lets you set in its own Settings (Jenkins' agent secret). The fix is one condition: skip `who`.

## 1.93.0 (2026-11-25)

The one "run a service" interface between service plugins and container plugins (Monday list items 34 and 35's
foundation; service-containers-design-2026-11-23.md §3 and service-containers-networking-2026-11-23.md §8, with the
user's answers of 2026-11-23 and 2026-11-25: containers only, agents in containers too, a service starting and stopping
with its app, service mode provided for and not offered yet, never a restart after a crash, an engine that is off never
started, the grant kept). Built beside 1.92.0 (a LoginPlugin kind), each rebased on the other when they land; nothing in
`apps/` or `sources/registry.py` is changed. SERVICE-INTERFACE.md, written with it, is the interface in one page.
- **`machines/containers.py`**: the words that cross (the hooks' names, the actions, the paths a port meets your network
  by, the accepts, the limits), the spec a service plugin hands over (`ServiceSpec` and its `Part`s, `ImagePin` by digest,
  `Port`, `Volume`, `Secret`, `Seed`, `Readable`, `Health`), refused in words before any plan (`ServiceSpec.of`: an
  unknown field is refused, so a privileged mode, a capability, a host path, the Docker socket or a host namespace cannot
  even be said), the names and labels every runtime gives what it makes, `Target` and `Fit`, and `approval_answer`.
- **`machines/plans.py`**: one plan holder for container plugins and firewalls (`Plans`: 16 at most, ten minutes each,
  bound to their owner, approved from the page with each accept exactly True, used once, the facts read again and
  compared when taken) and the works that carry them out (`Works`: one per target at a time, their lines masked and
  paged, cancelled and joined at the end).
- **`machines/containerhost.py`**: `ContainerHost`, the base every container plugin is built on, and `Runtime`, what it
  gives for each target. Hooks: hosting, hosted, hosted_logs, exposures, plan_words, service_work, service_plan,
  approve_plan (page alone), decline_plan, apply_plan, service_cancel, hosted_file, release_owned, grant_service and
  revoke_service (page alone), forget_volume (page alone, asked twice), segments. Every rule of the design's §3.7 is held
  here: who asks, grants, plans, works, secrets by environment alone, ports, data, the container's shape (`--restart no`),
  targets, lifecycle, failures undone in reverse, an unhealthy update undone, a backup before an update.
- **`machines/dockerruntime.py`**: `DockerRuntime`, the docker command's mapping, through a runner its plugin hands it.
- **`machines/segments.py`**: the networking words (`Want`, `Member`, `Segment`, `Route`, `NameRecord`, `Lease`), the
  pool (10.77.0.0/16 in two halves, a /24 a segment), the names (`names_for`, `ptr_of`), and `NetworkHost`, the firewall's
  network part: network_plan, plan_words, approve_plan (page alone), decline_plan, apply_network, network_work,
  network_cancel, the grants and the domain (page alone), name_records, resolve_name, reverse_name, leases, lan_open,
  resolver_for. Its allocations are kept in memory (`MemoryBook`) until a firewall's own network database comes with it.
- **`machines/netguard.py`**: `public_only`, `overlaps`, `routable_found`, `listener_refusal`, `wider_than_lan`.
- **`machines/standins.py`**: `FakeDocker`, `StandInHost`, `StandInNetworkHost`, `StandInWsl`, `ServiceOwner`, `login`
  and `conformance`, the sequence every container plugin's tests run; no plugin imports another's tests.
- Tests: `test_service_containers.py`, `test_service_network.py`, `test_docker_runtime.py` (99), through a real
  apps.App; each of 52 gates taken out once made a test fail.

## 1.91.0 (2026-11-25)

- A store's pick may name an instance (Monday list item 10; item 30, step 7): `engine:instance`, for example
  `postgres:main`, one of the database plugins' instances added on the platform's Databases section. A bare engine
  keeps meaning today's store, its plugin's own instance, so nothing changes for the picks kept (`sqlite:data` and
  `mongodb:local`, the own instances named, are kept as the bare engines). Documents alone go to an instance for now;
  bars and series after.
- The pick is kept where the Store picker keeps every pick (the main file's `store:pick:<plugin>:<type>`), and in
  effect at once (`store:effect:...`): nothing is moved. What the store left holds stays where it is, and only where
  new documents are written changes; they are read from the instance with the SQLite file's copy of the ones before
  (gov.py `items`, markets.py `news`, `latest_news_ms`), and an agency's items are read back from the instance for the
  publications' audit (`items_held`). The hourly `settle` copies nothing for such a plugin. The picker says so
  (`NAMED_MOVES`).
- Storage opens a named instance through its plugin's `open` (`registry.database(engine)`, the class loaded in this
  process, no hop): attached by the app here, with its login; in a process of no app's (the recorder, the sync's
  extras) a copy holding the login every plugin is lent. The instances are read through that login once and kept in
  memory (`NAMED_S`, 60 s; read again at once when the one asked for is not among them, and when a pick is set).
  Connections to a server's instance are kept, at most `POOL_MOST` (8), one call at a time each, a failed one closed.
- Refused in words, when picked and when written to, never replaced by another store (`PickRefused`, a ValueError):
  an instance not there, its plugin not installed here, one holding something else, a folder, its driver missing, a
  bare engine with no store of its own (`postgres`). A server that does not answer is raised as its driver said it:
  the read is tried again at its next due time, its pull kept in the fetch cache.
- A documents backend for PostgreSQL and MariaDB (`storage/documents.py` `SqlDocuments`, through `stores.backend` and
  `named_backend`), the same calls as SQLite's and MongoDB's (put, find, newest, count, every): a table for each kind
  (`liminal_gov_items`, `liminal_news`), its fields as columns, `doc_id` (the key's sha256) the primary key, made when
  first written; `every` reads a batch at a time by key. A SQLite file the user added keeps them the same way, a
  MongoDB instance in a collection. `TYPES["documents"]` lists both engines; the drivers are the plugins' own, imported
  by their `open` only when an instance is used. `Kind.numbers`: a kind's whole numbers (a headline's `published_ms`).
- The Store picker's rows (`plugin_stores`): the bare engines as before (`engines`), and `instances`, each instance
  that can hold the type as engine:instance with its title (`instance_choices`); a pick that cannot be used now says
  why (`refused`); the instance picked is counted with the others.

## 1.90.0 (2026-11-25)

- The platform's core, the base the apps inherit (Monday list item 30, step 1; the user, 2026-11-24: "through the rust
  interface", "inheritance bro"; 2026-11-25: the instance forms move to the platform's Databases section, the platform
  the only writer of instance settings). `apps/platform.py`: `Platform(App)` holds its plugins by section (`sections`:
  a plugin's SECTION, else its kind's), attaches the kinds a subclass declares in `PLATFORM_NEEDS` ("database",
  "machine", "assistant": `attach_needs`, with its own login; one another app holds is left to it) and includes the
  login as every App does. ChartsApp and IntegratorApp inherit it in their next releases (steps 4 and 5), and
  liminal-platform's app in step 2.
- The Databases section in the library (`apps/databases.py`): `overview`, `ask`, `elsewhere`, `plugins`, `suites`,
  `load_errors` and `Asked`, moved from liminal-integrator 1.12.0's instances.py with the same answers (a test asks
  both where the integrator is installed), so its module can become these names imported. A Platform needing
  "database" answers `GET /api/databases/plugins` (the integrator's shape, and `writer`) and
  `POST /api/databases/instances`. A plugin left out at loading is said under the renamed packages' names too
  (plugin-platform-sqlite).
- One writer: a Platform that is not the running platform (`PLATFORM_WRITER`, the flag liminal-platform's app sets, or
  `writer=`) reads the instances and tests them, offers no change (each plugin's `can` says where it is made), and its
  change routes answer 409, "change this on the platform's Databases section"; the platform makes them.
- Through liminal-net: the running platform serves its Databases section as a node (`serve_databases`:
  `platform-databases`, trait liminal.platform.Databases, the reads overview, elsewhere and test, and the change
  `change`; DatabasesHillock refuses a change, 409, once its app is not the platform). A part in another process
  reaches it from a node of its own, never served and never with a launcher (`change_on_platform`, `ask_platform`): a
  platform not running is a 503 in words, never started from here, and the platform's refusal comes back as it was said
  there (status, words, what accepts it). Opening a database stays in each app's own process.
- `DatabasePlugin` is a `PlatformPlugin` (SYSTEM "platform"; KIND "database" kept; SECTION "databases"). The registry
  finds the packages as before, their names and kept settings unchanged; `attach_registry(only="integrator")` still
  attaches them, and `only="platform"` does not, until the integrator inherits the platform (step 4).

## 1.88.4 (2026-11-24)

- Every shutdown is clean (the user, 2026-11-24: "all shutdowns need to be clean"). Nothing is forced by default:
  `lifecycle.end_trees` sends TERM and reports what has not ended in its time ("left"), where it sent KILL after it;
  KILL is sent only when asked for outright, and never to a data holder.
- Data holders: `Row.holds_data` in the process ledger, set by `lifecycle.spawn(holds_data=True)` for mongod and every
  host (`Host.start`: the recorder, the fetcher, the MongoDB keeper); mongod is one by what it runs too, and so is every
  row of `host:mongo` (`lifecycle.holds_data`). One is never sent KILL: it is asked to end in its own clean way
  (`OsKiller.shutdown`: mongod, MongoDB's `shutdown` command on its own port, sent only when the server there says it is
  that process) and reported when it has not ended, unless named by its id (`end_trees(force=)`).
- `liminal-stop` and `liminal-signal`: TERM, and nothing else without `--kill`. What is still running after the timeout
  is reported with its id, what it runs, its owner and how long it was asked, a line says to run again with --kill, and
  the exit code is 1. `--kill` forces what is left after the timeout if it holds no data (a row's job, too, never a
  data holder's); a data holder only when named, `--pid N --kill` (`--pid N` alone: that process asked, TERM; only one
  of Liminal's, never this command). `liminal-signal KILL` is refused without `--kill`.
- An app: a plugin that misses its stop deadline (`deliver(within=)`, `deliver_all`) is reported late and its trees
  are asked again (TERM) and left, their rows kept for liminal-stop; `App.detach`, `App.terminate` and a host's end
  give TERM its deadline and report the rest. An explicit KILL (App.terminate(KILL), a node's `kill`) still kills,
  but never a data holder. A plugin node's start past its deadline is asked to end, not killed. What each is given is
  read before its thread starts (a stand-in clock its own end moved left it none: the conformance's grok check failed
  now and then). The conformance's node check now asks that a child ignoring TERM be given its deadline and then left
  and reported, never killed.
- `mongo.stop()`: its shutdown, then up to 60 s (a look every 0.5 s) for the server's process to exit; still running,
  it is reported and False returned, never killed (1.87.0 killed its tree after 10 s). `keep()`'s end shuts the server
  down the same way and says when it is left.
- Jobs: a data holder is never in a job that ends it with its owner (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE): it gets a
  named job of its own, tied or not, and leaves its starter's jobs (CREATE_BREAKAWAY_FROM_JOB; a job that allows none
  is noted in its row); on Linux no PR_SET_PDEATHSIG. The boot keeper's job (`machines.keep`) allows the breakaway.
  Other children stay tied.
- The library's other forcing places ask and report: `proctree.run`'s timeout asks the tree (taskkill /T without /F,
  SIGTERM to its group) and raises `StillRunning` (a TimeoutExpired) when it is still running, not waited for;
  `proctree.ask_end` for one child; the AI plugins' short commands, zstd's unpacking, the terminal's close (its input
  closed first), the route tracer, the link's helper, the boot keeper's command, bpftrace (`_halt`: SIGTERM and no
  SIGKILL, the watch's error says it is left) and the recorder's strays (asked TERM, never TerminateProcess). Kept:
  a child that could not be resumed after its job (it never ran), and machines/children.py, endpoint.py,
  apps/binding.py and web.py, not changed here.

## 1.88.3 (2026-11-24)

- The closed months' copy to DuckDB is no longer refused for bars before 1970. Its check after the write compares the
  rows read from SQLite with those written, by count, the sum of `ts % 1000003` and the volume. Python's remainder is
  never negative, DuckDB's keeps the sign of `ts`, so a month with negative timestamps (before 1970) never matched
  though the rows were the same. Seen as `tiingo 1969-12 bars: wrote (177, -100842890, ...), read (177, 76157641,
  ...)`: the history host's work failed every hour from 2026-11-22, and no closed month after it was copied. DuckDB's
  side now takes Python's remainder. Found through 1.87.0's logging of a host's failed work.

## 1.88.2 (2026-11-24)

- A test can never reach a running app's stop event. While pytest runs a test (PYTEST_CURRENT_TEST is set), every
  stop event's name (`lifecycle.stop_event_name`) carries the test process's own suffix, so whatever a test makes, opens
  or sets is its own. At 21:36 a run of this suite on the machine the apps run on set the real
  `Local\\liminal-stop-<app>` events (the stop command's test helper set them through kernel32 for real) and stopped all
  four apps, cleanly but unasked. The helper now has its stand-in as well. Outside a test the names are as before.

## 1.88.1 (2026-11-24)

- `mongo.keep` reads `KEEP_SECONDS` when it runs, as it did before 1.87.0: its new `every` defaulted to the value
  at import, so the module's KEEP_SECONDS set afterwards went unheard (the charts' keeper test, which sets it to
  0.05 s, waited 5 s a look, 15 s in all). `every=` given still wins.

## 1.88.0 (2026-11-24)

- Preferences and licences through the login (Monday list item 21; the user, 2026-11-19: "preferences, keys,
  licenses all get stored in the individual's login db"). Two pair kinds beside the keys, `preference` and `licence`
  (`apps.PREFERENCE`, `LICENCE`), each holding a JSON value: `Login.keeps_settings`, `setting(name)` and
  `keep_setting(name, value, kind, label)`, refused (405) by a login that keeps none, an EnvironmentLogin among them;
  `LoginClient` keeps them as the login app's pairs and never reads a key as one (409); `RecordingLogin` passes them
  through, noted by name.
- `apps.recall` and `apps.keep` read and write one through a login and fall back to the file it was kept in before
  when the login keeps none, or refuses, or cannot be reached. A user's store holding none of that name yet is given
  the file's value the first time it is read, once; the file is left as it was.
- The UI's theme is the signed-in user's preference `ui-theme` (`ui.THEME_PAIR`): `ui.preferences(path, login)` and
  `save_preferences(path, login, theme=...)` take the login given, else the asking person's; ui.json as before
  without one; the answer says where it is kept (`store`: login or file).
- The asking person's login (`apps.as_user`, `asking_login`): every app's frame names it for a request's block, from
  the browser's session in the login it inherits (`App.user_login(handler)`: that login object's own `user_login`,
  else the app's login), in that thread alone. `GET /api/ui` answers each browser with its own user's theme, and a
  plugin's hook asked from a page (the Preferences plugin's theme) keeps it for that user.
- A licence accepted (`apps.accept_licence(login, name, title=, version=, url=, words=, by=, at=)`) is kept as the
  pair `licence-<name>` with what was accepted, its version and address, its words (the first 1,500 characters, all
  of them by SHA-256), when (UTC) and by whom; without a login that keeps them, in the data folder's licences.json
  (LIMINAL_LICENCES_FILE), copied into a user's store once as above. `apps.licence(login, name)` reads it back.

## 1.87.0 (2026-11-24)

- What ends promptly when asked (the shutdown audit of 2026-11-24: a stop took 61 s to 47+ min).
- Hosts: a last client that says "detach" ends its host at once (a feed host, the MongoDB keeper: 60 s each until
  now, one after another); one whose process ended without a word, after GONE_SECONDS (5 s); a page in touch keeps it
  its idle time (`Host.idle_for`, `check_idle`). A host's work that fails is logged with its traceback before it goes
  on up (the history host had died every hour since 2026-11-22 with nothing said).
- `RateLimiter.acquire(stop=)` sleeps in slices of at most a second and raises Paused at a stop (one sleep of up to
  an hour on Tiingo's window until now); `HttpClient` passes its `should_stop` (the day's place given back), and a
  streamed download into the cache ends at a stop between two pieces.
- `derive.run` / `Builder.run(stop=)` and `composite.refresh(stop=)` look before each symbol or asset; the
  publications' Reader before each feed (`Reader.stopping`, lent to each read as `Context.stopping`);
  `DatasetFetcher(stop=)` / `datasets.fetch(stop=)` before each dataset, file and commit, and git runs through
  proctree (its tree ended at its timeout); the auditors' `Sweep.run(stop=)` before each series.
- MongoDB: `mongo.stop()` waits up to 10 s for the server's own shutdown, then kills the ledger's mongod by its tree.
  `mongo.keep()` takes the server for gone only after 3 failed pings over 10 s and only when the process it started
  (its id and start time held) is gone too (one failed 500 ms ping at 100% CPU left mongod three hours with no keeper,
  2026-11-23); an orphan is adopted, never started twice; the server it holds is shut down when the keeper ends.
- Jobs: a child is started suspended and resumed once it is in its job, so the base interpreter the venv's pythonw.exe
  redirector starts is in it too. A child meant to outlive its starter (`Host.start`, mongod) gets a named job of its
  own, written in its ledger row; liminal-signal ends everything in it by its name.
- A graceful stop a console-less pythonw hears: each app's named stop event (Windows, `Local\liminal-stop-<app>`),
  waited on by `App.serve` and set by liminal-signal before anything is ended.
- An app's plugins are told TERM together, under one deadline (their own, 10 s at the most) and a grace of 2.5 s
  (`App.STOP_GRACE_S`); one still at it then is late and its trees are killed.

## 1.86.0 (2026-11-24)

- A reliable end for every app, plugin and process of Liminal's (Monday list item 38; the user, 2026-11-24: "there
  needs to be a reliable way to terminate all apps/plugins and related processes safely"). Seen the same day:
  `schtasks /End` on the four apps' tasks left the integrator's `liminal_charts sync --extras-only`, the charts'
  `host mongo` and its mongod running 10-20 minutes, since Windows ends the one process it is told to.
- `lifecycle.py`: `Signal` (TERM: finish, secure the data, give back, detach, end the children; KILL: every child
  tree now), the `signal(sig, deadline, sender)` every stoppable object answers, `deliver` (a deadline enforced: an
  object late past it is reported and its trees killed), `end_trees` (deepest first, TERM then KILL at the timeout,
  each process checked by its start time before every signal: a reused id is never touched), and the process ledger:
  every process `lifecycle.spawn` starts is written with its owner, id, start time, kind and command in
  processes/<installation>.json under the data folder (written whole, stale rows dropped). A tied child is put in its
  owner's job object on Windows (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) and gets PR_SET_PDEATHSIG on Linux when started
  on the main thread; what fails there is noted in its row, never fatal. Hosts (`Host.start`) and mongod are written
  in the ledger, untied (they outlive their starters by design).
- `App.terminate(sig, timeout)`, which `App.stop` now is: nothing new is taken (503), then the login it includes, its
  platform parts (`parts`), every plugin (each within its STOP_DEADLINE_S, then detached), the app objects it owns
  (`owned_apps`), what it started, its server. Safe twice and from any thread; a KILL during a TERM kills at once.
  An app's stop now lets its plugins go, where it left them attached before; an app whose class has a stop of its own
  (the platform's, which tells each machine plugin itself) has them neither told a second time nor let go there.
- Plugins: `MODE` "on_demand" (the only one allowed: "service" is refused by the conformance, "service mode is not
  yet allowed: on demand only"), START_DEADLINE_S 10 and STOP_DEADLINE_S 15 by default, and `Plugin.signal`, taken
  only from the plugin's own app or its login. Every plugin always has a login, `Plugin.held_login()`: attached, its
  app's; before an app attached it, or under an app given none, the user's environment's (`authorization.lent_login`,
  one EnvironmentLogin), said once in the log. `login` itself stays as its app set it, so a plugin answers as before.
  A plugin whose attach puts another login in its place is refused. A detach ends what was started for the plugin.
- `nodes.py`: a plugin served as a liminal-net node (`PluginHillock`: its hooks, and `term`, `kill` and `ask` any
  node may request; its `lifecycle` stream signal as it ends), on demand by a launcher written in the ledger, a start
  past its deadline ended; an app as a node too (`AppHillock`, opt-in `serve_app`).
- `liminal-signal TERM|KILL|ASK` and `liminal-stop` (console scripts; `python -m liminal_libs.stop`): a node of its
  own reaching app-<name> and plugin-<name> nodes, else the apps' new routes (`POST /api/app/signal`,
  `/api/app/stop`, `GET /api/app/processes`, `GET /api/plugins/<name>/<what>`, `POST /api/plugins/<name>/signal`,
  each with the proof of this user's key), then ending what is left of Liminal's by its tree; `--list` changes
  nothing. A host ends at once on a signal (and on SIGTERM), its data secured first.
- The conformance checks the mode, the deadlines, the signal and a login kept; `node_problems` and
  `assert_module_serves` serve a plugin as its node on stand-ins (ASK, TERM within its deadline with nothing left, a
  child ignoring TERM killed at the deadline), and the tests do so for every plugin the registry finds.

## 1.85.0 (2026-11-24)

- An index for a product's futures contracts, `futures_contracts_product (source, product, first_trade)`, made when
  the main file is opened (additive: `CREATE INDEX IF NOT EXISTS`). `Store.contracts(source, product)` had only the
  primary key `(source, ticker)` to go by, so each ask scanned every contract of the feed and sorted them. The charts'
  symbol list asks it once per watched future: on the real data, 1,536 asks over 21,903 contracts took 6.8 s of the
  list's 13 s (Monday list item 16, profiled reading only).

## 1.84.0 (2026-11-24)

- Set-based reads for the charts' symbol list (Monday list item 16). It read a symbol at a time, about seven
  statements each: some 230,000 for 33,145 symbols, 11 s on Windows and two minutes from Linux, where each statement
  crosses the link. `Store.bar_edges_many(source, tickers)`, `newest_many(tickers, timespan, holders)`,
  `probes(source)` and `rolls_of(source)` give what `bar_edges`, `newest_any`, `probe` and `rolls` give one at a time,
  in one statement each however many symbols are asked (one a feed for `newest_many`). Each ticker's ends are still
  index seeks: the tickers go as one JSON list (json_each), each end a MIN or MAX in a correlated subquery.
- The loose index scan behind `stored_series()` (`storage/common._distinct`) is one statement, a recursive CTE whose
  every step seeks past the last key, not a statement a step: one for each series of each bar table, tens of
  thousands once another process had written. The same rows in the same order.

## 1.83.0 (2026-11-24)

- The review of 2026-11-21 (item 26), the library's P3 findings. A feed's history triggers made by an older version
  are dropped and made again in one transaction (`storage/history.ensure`, each statement of SCHEMA run inside it):
  a write to an archived month between the two marked nothing stale.
- The collector's clock (`Collector.clock`) is the monotonic clock corrected against the wall clock: a step in which
  the wall clock went on a second or more past it counts the wall clock's. On Linux (WSL too) the monotonic clock
  stops while the machine sleeps, and a request made after waking was stamped synced before it was made.
- The IPC key file (`host.key`) is made owner-only from the start (O_EXCL, mode 0600) and put in place by a hard link,
  which never replaces a key there: it was written at the umask and chmodded after, and two first starts replaced
  each other's. The second start reads the first's.
- A plugin's own fetching (`runner.Runner`): the server's pause, the request cap or a 429 stops the plugin's pass, the
  jobs left not sent, and a 429 (any StopRun with a strike) strikes the plugin's fetching (killswitch, at least the
  server's Retry-After), as the bars path does; each was one job's failure and the next job went to the same server.
- No child the machines or docker start inherits a LIMINAL_* name (`machines/terminal.inherited`): PowerShell, the
  Linux shell, wsl (run, streamed and the keeping session), the terminal panel's process and docker; what a call adds
  (WSL_UTF8) is still added, and docker's DOCKER_* and WSL's own variables are kept.
- A docker command on Windows (`docker.split_command`: the command given or LIMINAL_DOCKER_COMMAND) is split as
  Windows splits one: a path that is there kept whole, else without POSIX's escapes and with the quotes taken off.
  `C:\Program Files\Docker\...\docker.exe` was split apart at every backslash.
- A WSL plugin's Start thaws a running distribution's services still frozen whatever the plugin remembers (what it
  paused is kept in memory only, and a pause from before a restart was left frozen); Start is never disabled.
- A WSL rename whose new name the login could not keep is renamed back, and the error says so; when the undo fails
  too, it says both and names the distribution as it now is.
- `proctree.run` says its window flags outright in its Popen call (creationflags CREATE_NO_WINDOW on Windows, 0
  elsewhere; start_new_session off Windows), and its docstring no longer reads as a subprocess call: the charts'
  test of every start (`test_no_console_windows`) took the docstring's text for a call with no window flags.

## 1.82.0 (2026-11-24)

- The live recorder and the publishers through the fetch cache (Monday list item 5; until now only the feeds'
  fetches went through it). The recorder's trades (`live.py`): each write of a flush goes to a trades file in its
  stream's pull first (kind `live`, new in `pulls.KINDS`) and the tick file is written from the file read back, as a
  feed's bars are. One pull a stream a minute (`live.PULL_MS`), not one a flush: closed and audited at the first flush
  of the next minute, and at the recorder's stop, then forgotten at once when it passes. A minute's trades are the
  most an audit holds in memory. The cache at its cap, or one that cannot be written, never stops the recorder: that
  minute's trades are written without it and the log says so. At its start the recorder recovers what an earlier
  one left open (a crash mid-minute: its trades files loaded without asking anything again) and audits its feeds'
  pulls (`Recorder.settle_cache`).
- Trades files (`storage/pulls.py` `TRADE_COLUMNS`, ledger kind `trades`; `Pull.rows(table="trades")`;
  `storage/feeds.py` `upsert_trades` through the open pull). The copy audit holds them against ticks.trades key by
  key and value by value with `IS`, in a table of the same types (`auditing.compare_trades`): a trade missing is put
  back from the file unless the exchange withdrew it since (it is in ticks.archived_trades); one stored with other
  values is a `copy-differs` finding (timespan `trades`: never asked of a feed again), nothing stored overwritten.
  A trade a later file of the same pull wrote again is that file's to judge. A file loaded late puts in only what
  is not stored. A pull with trades files is audited, and loaded late, only by a process that opens tick files (not
  in bars-only mode). The recorder's built bars stay out: they are built here from the audited trades, every flush.
- Pulls held open across calls: `auditing.held_open` and `auditing.end`.
- The publishers (`publications.py`): an agency's answer goes to a pull's folder (kind `publication`, by the
  publisher's name) and is parsed from the file read back; the items it stored are then read back
  (`GovDB.items_held`, `GovDB.items_unlike`): a new item must be stored with every field as parsed, one held
  already keeps its own. All as they should be: the pull closes and its file goes. Any other: a `document-differs`
  finding, and the pull is kept with its answer, audited as a mismatch (`Pull.unverified`). A vendor's headlines are
  read inside a pull, so its plugin's HTTP answers go to the folder and are parsed from there; what the plugin
  stores of them is not read back yet, nor are items kept in MongoDB.
- With LIMINAL_FETCH_CACHE=off, in a process that reads only or with no main store, nothing is cached and every
  write is made as before.

## 1.81.0 (2026-11-24)

- The review of 2026-11-21 (Monday list item 4), its five faults. The second-feed audit's queue (`queue_audit`)
  still keeps one entry per series and owner, but a span queued while another waits widens it to cover both (the
  lower start to the higher end): the newer replaced the older, and a span downloaded and not yet audited was never
  audited. `dequeue_audit(end_ms=)` takes off only the span audited, so one widened meanwhile waits on; the
  Auditor audits a queued span from its history floor up (a widened span may reach below it).
- An audit that could not run (`audit_span` returned None: the feed refused or did not answer) stays queued for the
  next pass, its try counted against the run's `queued`, until QUEUE_MAX_AGE expires it; it left the queue as if
  audited. One the second feed had nothing for is recorded as before (verdict no-data) and leaves it.
- An exchange feed's quality (`composite.feed_quality`) is the bar-weighted mean of every ticker's leave-one-out
  score, each ticker's stats and score kept in the details' `tickers`; the last ticker judged set it alone.
- `HttpClient` asks the daily cap (`take_day`) before the rate window: a request it refuses takes no place in the
  window. One counted for the day and paused in the window's wait is given back (`give_day`, set by the feeds'
  `machine_caps` and the assistants: `MachineLedger.charge_day(-1)`).
- A dataset file (`datasets._keep`) is written to a part file beside it, fsynced and renamed into its name
  (spool's `_part` and `_finish`), so it is never found cut off under its finished name; one of the wrong size
  (cut off before) is written again.

## 1.80.0 (2026-11-24)

- The review of 2026-11-21 (Monday list item 26), its findings 8 to 13. A cancel is never undone: `request_update`
  moves only an open request, in one statement, so the fetcher's or the auditors' write after the user's cancel
  leaves it cancelled. An ended request keeps its ending (done and failed too: no caller moves or rewrites one; a
  symbol asked again is a new request). The request it returns says `applied` (False: nothing was written); callers
  that ignore it go on as before.
- The rate window kept is never looser than the plugin's own (`sources/plugin.py` `within`): the server's limits
  only lower it, by rate and by burst. A server's 10 a second made a plugin's 200 a minute 9 a second (540 a
  minute). `HttpClient.tighten` refuses a window of a higher rate, and one of a lower rate in a larger burst keeps
  the burst it had, at the new rate.
- AI answers (`assistants/assistant.py`, `sources/http.py`): an assistant's POST waits 300 s for its answer
  (`ANSWER_TIMEOUT_S`, an Assistant's `answer_timeout`; `HttpClient(post_timeout=)`), not a GET's 30 s: a reasoning
  model's answer was cut off there and could still be billed. A POST is never sent again on a 5xx either: a
  gateway's 502 or 504 may come after the vendor ran it. A 429 is still waited out and sent again.
- Dynamic DNS (`machines/ddns.py`, the Keeper, every cloud plugin's): the record is read again just before the write,
  and written only if it still holds what was read first; else nothing is written and the host's result says the
  record changed during the pass (the next pass judges it as usual: a foreign address is left as it is).
- A timeout ends the whole tree (`proctree.py`, new): PowerShell, the Linux shell, wsl.exe and the docker command
  run through `proctree.run`. On Windows taskkill /T /F by pid (windowless); on Linux the child starts in its own
  session and its group is sent SIGTERM (which sudo passes on to the root command it may not be sent from here),
  then SIGKILL after 5 s. Not reachable from here, and said so: an elevated process (UAC) and the Linux side of
  wsl.exe. `machines/windows.py` `TimedOut` (a CommandError) names a timeout.
- `run_elevated` past its wait: the error says the change may still be applied and to look before trying again (it
  said the change failed). Its output file is no longer removed before the elevated script may write it; it is
  removed once the script has ended, and one left by a script that outlived its wait is swept by a later run once
  six hours old.
- `machines/linux.py` Shell's sudo prefix is `sudo -n --`, so a command beginning with a dash (-u, say) is never read
  as sudo's option (asked for by the session building the children supervisor). Plugins' tests that match
  `["sudo", "-n", <command>]` see `"--"` after `-n` now.

## 1.79.0 (2026-11-24)

- The review of 2026-11-21 on your desktop (Monday list item 26), checked against the checkout: a series' weeks, months and years outlived the daily bars they were built from. `Builder.chain`
  returned at once when its base frame held no bar, before reading the dirty mark, and `Builder.symbol` skipped
  such a frame altogether. So once a series' last base bars went (a composite dropped as one exchange's copy, a
  composite's stale bars removed), what was built from them stayed. Now a base frame that was built from before and
  holds nothing has its built frames above removed and its dirty mark cleared (`Builder._emptied`). Nothing is done
  for a frame never built, or when nothing changed since. `derive.chain_key` names a chain's kv key.

## 1.78.0 (2026-11-24)

- The fetch cache waits out a busy database (storage/pulls.py `_waited`). A write of its ledger that the main
  file's lock refuses past the connection's 30 s wait is tried again, up to three tries, two and then ten seconds
  apart. What a failed try left of its transaction is rolled back first. A pull that only went through after
  waiting says so in its note. A pull's close and its forgetting wait the same way.
- A ledger write still refused after every try stops the run as before (spool.CacheFailed, no strike), and now
  says which write it was (opening a pull, recording a file, marking one loaded), how many tries over how long,
  and what else said it was at work on the database then: each other process's claims (`pulls.at_work`). SQLite
  does not say who holds its lock; the claims are what the processes say of themselves.
- `storage.common.busy(e)`: whether an error is the database being busy (the auditors' `_busy` uses it).
- Monday list item 2: the stop at 08:22:27 on 2026-11-19 ("the fetch cache's ledger could not be written
  (database is locked)") would have been waited out, or said who else was at work.

## 1.77.0 (2026-11-24)

The sweep judges a missing day by that day's own witness. Its second run over the user's data (2026-11-19: 12,994
series, 931 findings) judged a run of missing days as a whole: one bar of another feed anywhere in the run made all
of it one finding (Massive's ABXL: 5,612 days, because Alpaca holds two years of it). Now:

- **A missing day is a hole only if that very day has a witness** (auditing.py `Sweep._witnessed`): its own daily
  bar shows it traded (or its own finer bars are there, for a missing daily bar), a pull cut off covers it, another
  feed of the same market or its own ticks hold bars that day. Witnessed days next to each other are one hole; the
  days between them without a witness are none. The run as a whole is asked first, so a run nothing speaks for is not
  asked day by day.
- **An empty span only if every day of it has a witness**; otherwise its witnessed runs are holes.
- **The findings kept before are judged again by the same rule** (`Sweep._judged_again`): one wider than its
  witnessed days is closed ("judged day by day: N of its M days have a witness of their own") and the runs that do
  have one are kept in its place, in its state (an asked one still empty becomes absent, as the whole would have),
  each naming the finding it came `from`; one of which no day has a witness is closed. Only witnessed days are asked
  of the feed again.
- Five tests (tests/test_auditors.py); each fails with the change undone.

## 1.76.0 (2026-11-23)

The Continuous Integration plugins' marks, and one deadline for the whole of each request through machines/endpoint.py.
The user, 2026-11-22: a Continuous Integration class of platform plugins, with Jenkins, GoCD and Buildbot
(plugin-platform-jenkins, plugin-platform-gocd and plugin-platform-buildbot 0.1.0). Their ICONs, "jenkins", "gocd" and
"buildbot", were names icons.js did not have, so the tray and their pages drew the plug for them. Their reviews found
that a request through machines/endpoint.py had no deadline for the whole of it: each socket operation waited its
timeout, so a TLS handshake or a head given a byte at a time, each byte within that wait, could go on without end. The
Jenkins and GoCD reviewers left that bound to the library, which sends both plugins' requests (Jenkins' client says
so), and the Buildbot plugin keeps one of its own (a threading.Timer over its own urllib requests). No plugin's code
has to change for either, and the plugin API stays 2.4.

- **The Continuous Integration plugins' marks** (`ui/static/icons.js`): `jenkins`, `gocd` and `buildbot`, each its
  maker's mark drawn anew in the set's line and colour from what the mark shows on its maker's own page, nothing
  downloaded or traced. Jenkins' butler: his bald head turned a little to the right, the grey hair behind it and an
  ear, his eyes closed and a smile, his bow tie and his shoulders. GoCD's play sign: one bold rounded stroke, left
  open where it began. Buildbot's nut, turned as its mark has it: the top face and its hole, the near sides below.
  Each was drawn at 15 to 24 px (the platform's lists and its tray) on the dark and the light themes, and by headless
  Edge beside the other marks. A static file: a page shows them once reloaded, with no app restarted. The plugins'
  own tests of their icons pass with it: Jenkins' and GoCD's were skipped until the marks came, and Buildbot's, a
  strict xfail until then, now fails as an unexpected pass until its marker goes.
- **One deadline for the whole of a request** (machines/endpoint.py): its connection (each address its name has, in
  turn), a TLS handshake, the status line and the headers, and the body. An Endpoint ask's is twice its wait, the
  bound its body already had (GoCD's looks 10 s in all, its changes 40 s); a stream's is its own `deadline`.
  `requests_transport` takes one too (`deadline=`, new): given none, twice its timeout for an answer read whole
  (Jenkins' requests, which wait 5 s a socket operation, 10 s in all) and none for a stream (a download, which looks
  at its own deadline after every receive).
- **A watchdog keeps it** (`_Watch`): a thread of the request's own ("endpoint-deadline"), stopped and waited for when
  the reply is let go or the request fails, so that none outlives its request. Once the time is up it shuts every
  socket the request holds: each one held from before it connects (the session's adapter dials as urllib3 does,
  address by address: `_dial`) and, over https, the TLS one from before its handshake (through a context that holds
  it, `_Held`, since ssl detaches the plain socket under it). Each is shut down both ways and, on Windows, a plain
  one is closed as well, by the C socket itself: a wait there ends only once its socket is closed, and socket.close()
  puts that off while http.client's file of the socket is open. A TLS socket is only ever shut down, on Windows too:
  OpenSSL reads and writes through the number it was given, which a close would free for the next socket the process
  makes (Windows gives a number out again at once), and a read or a write waiting in OpenSSL would then go on in that
  socket's connection. A call on it after that ends at once, and one already waiting on Windows ends at its peer's
  next byte or at its own timeout, one wait past the deadline at most. The plain socket is let go before ssl takes
  its number, and the TLS one held in its place.
- **Said as a read that waited too long** (`Overdue`, new: a TimeoutError that carries the deadline's `seconds`):
  `trouble()` says it as it says a slow read, in the deadline's seconds ("no answer from … within N s"). Endpoint says
  a body cut off in its bound's words ("its answer was not whole after N s: not read") and leaves a stream where it
  is, as at its deadline before; a stream whose head has not come by then is an EndpointError. Once the watchdog has
  fired, what a shut socket reads is the deadline's: the nothing it reads is never taken for the body's end, so an
  answer that says no length is not handed back cut short as if it were whole, and a read that fails on a socket it
  closed (Windows) is not said as a connection that broke off.
- **As before**: a name being looked up is not cut short (nothing cuts getaddrinfo short): the request ends once the
  name is found, and no address is tried after the deadline; a name not found is said as one ("… is no name this
  machine finds"), even when its lookup fails only once the deadline has passed (Windows' resolver gives up after some
  10 s), since no socket was shut for it. Only the library's own transport is given the deadline: a stand-in
  transport (the plugins' tests') is asked with the six arguments it takes. A stream given no deadline has no
  watchdog, and its connections are urllib3's own. A running app sends as before until it is restarted.
- **Tests**: test_endpoint (14 new) runs stand-in sockets under the whole real stack (requests, urllib3's
  connections, http.client; TLS through a stand-in context), hung at the connection or at the TLS handshake, or
  giving the head or the body a byte at a time, each byte within the socket's wait, and each shut both as Windows
  shuts a socket (a plain one closed: a call on it then fails) and as Linux does (shut down: a read gets nothing),
  whichever system runs them: the deadline holds, the errors' words are checked, a TLS socket is never closed under
  OpenSSL nor given a number closed under it, a name not found after the deadline is said as one, and no socket and
  no watchdog outlives a request (a fixture looks for watchdogs after every test of the file). Each part of the fix
  undone fails its tests, and the deadline's tests passed 25 runs of 25 in Ubuntu and 20 of 20 on Windows. test_icons
  (1 new) holds each mark to what makes it its maker's: found as a plugin's ICON is, in one colour, inside the box,
  and its shapes (GoCD's stroke bold and open, Jenkins' head an egg with the grey hair behind it and the bow tie below
  his chin, Buildbot's hexagon straight with the hole in it); each of 16 breaks of the marks fails it.

## 1.75.3 (2026-11-22)

A real child's wait, its watcher's on every Python. CI failed on windows-latest with Python 3.12 alone: during a wait
of 0.3 s for a real child (`test_a_real_childs_wait_is_its_watchers_and_looks_at_nothing_meanwhile`), its handle was
asked with a timeout 12,344 times. time.monotonic on Windows before Python 3.13 moves by 15.6 ms (GetTickCount64;
3.13 took QueryPerformanceCounter): the watcher's wait of 0.3 s was over before that clock said so, and the 4 ms it
said were left were looked for on the child's handle, asked with a timeout until the clock moved. The test's
stand-in answers at once, and so does a real handle asked for less than a millisecond (Popen.wait counts whole
milliseconds).

- **The whole wait through its watcher** (machines/children.py `Child.wait`): a real child this process started is
  waited for through its watcher alone until its own clock says the time is over, a coarse clock's rest included;
  only once the watcher has woken (its end seen, or its own wait failed) is what is left looked for every STEP_S, as
  before.
- **A clock that moves in ticks** (tests/test_children.py `Ticks`): half a second a tick, so that every Python and
  system sees what 3.12 on Windows saw, on both systems' waits; the fix undone fails it.

## 1.75.2 (2026-11-22)

JSON's nesting bounded alike on every Python. After the GitHub push of 2026-11-22, CI failed on ubuntu-latest with
Python 3.15 alone: two tests sent JSON 100,000 levels deep, which every other Python's reader refused by its
RecursionError, and 3.15 on Linux, whose guard measures the C stack itself, read whole.

- **`jsonread`** (a new module): `depth`, `too_deep` and `loads`, MAX_DEPTH (512) levels of arrays and objects counted
  outside strings with the bytes' own methods before anything is parsed (never counted for a text with fewer openings
  than the bound); a text past it is refused as no JSON (ValueError), and so is one the parser's stack cannot read.
- **Used by the readers of what comes from outside**: an app's request bodies (apps/app.py: still "the body is not
  JSON", 400), the classification lists and their manifest (classify.py), the infrastructure's downloads
  (machines/infrastructure.py). The infrastructure's kept files, its own and read at every layer the globe loads, are
  read as before.

## 1.75.1 (2026-11-22)

What the lookups found, kept across a restart. The user, 2026-11-22, asked whether the lookups should reload their
saved answers after a restart instead of asking the registries again: "Yes, build it". The routers' names (reverse
DNS) and networks (RDAP) were kept in memory alone, so after each restart the hop table had none of them and every
router was asked again, at the registries' limits, though the composite database held each answer as evidence.

- **Put back at the tab's first ask** (machines/composite.py, machines/lookups.py, machines/routes.py):
  `Composite.lookups(since)` hands back each router's newest ptr and rdap claims said within lookups.KEEP_S (a day),
  and `Lookups.seed` puts them back as of when they were said: not asked again before their day is out, their ranges
  answering the routers within them; a part never found (a name with no network) is still asked. Read once, never over
  what the running process found itself.

## 1.75.0 (2026-11-22)

Each network's number and operator, from an ASN file beside the GeoIP file. The user, 2026-11-22, asked whether to fill
the hop table's empty ASN and Operator columns from DB-IP's free ASN file: "Yes, do it". DB-IP's IP to City Lite (the
GeoIP file in use) holds no networks; its IP to ASN Lite does (485,292 ranges, 9.2 MB, CC BY 4.0, the same credit). The
plugins name its address; the library names no outside host. The platform's page shows it once the platform is
restarted, and the file is downloaded only on your click, its licence shown and accepted first.

- **The ASN file beside the GeoIP file** (geo.py): kept in the GeoIP folder's asn/ (`asn_folder`), its own folder, so
  neither install removes the other's file. `GeoIP.find` opens it too (`find_asn`), and a place the GeoIP file gives
  with no network of its own gets the ASN file's AS number and organisation; the ASN file places nothing by itself. A
  record's network is read under GeoLite2-ASN's names, GeoIP2's traits, or the shorter names (`_network`).
- **Its install** (machines/world.py, machines/firewall.py): `Firewall.GEOIP_ASN_URL` and `GEOIP_ASN_LICENCE`, the
  plugin's; the hook `world_asn` (a job, as `world_geoip`, refused until its licence is accepted); the World Wide Web
  tab offers "Install the ASN file…" once the GeoIP file is in, and "Update…" once a later month's is out.
  `WorldView.install(kind="asn")` downloads it as the GeoIP file is downloaded (one deadline, https on every hop from
  the plugin's host) and opens the GeoIP file again with it.
- **Operators by their names** (machines/routes.py): the hop table compares operators by their names, legal words left
  out (`_operator`: "Charter Communications, Inc." and "Charter Communications LLC" are one), the number alone where no
  name is known: one company runs several AS numbers, and the ASN file and the registries spell its name apart.

## 1.74.3 (2026-11-22)

A carrier link only where the times allow it. On this PC's real routes, 267 of the 335 links 1.74.0 called carrier
links (major hauls) joined hops whose round trips rule their distance out: GeoIP puts many routers at their network's
home, thousands of km from where they are (two Kennewick routers 0.3 ms apart were called a 3,805 km haul). The links
are kept for plotting the infrastructure on the map, so a false haul would draw a line that is not there.

- **The times bound the distance** (machines/routes.py `_link`): two hops of one network are joined by a carrier link
  where the round trip grows by over 10 ms (HAUL_MS), or where they are over 500 km apart (HAUL_KM) and the added
  time allows it (KM_PER_MS 100 km a ms, and SLACK_KM 300 km for the places' own error, as names.py bounds a router
  name's place). A distance the times rule out is not said.
- **The links' rule in their claims**: each link kept in the composite database now says `"rule": 2` (LINK_RULE); the
  claims kept before it (1.74.0 to 1.74.2, no rule) used the distance alone, and whatever plots the links can pass
  them over. Nothing kept is changed or removed.

## 1.74.2 (2026-11-22)

The hop table made on real routes. With 1.74.1's routes read back, the World Wide Web tab's "Routes, hop by hop" and
"Legs waiting for a line" tables were missing from the page: a link inside your ISP (two hops of the first network
met, near each other) is said as a word ("your ISP"), not a record like the others, and keeping it for the map read
it as a record, failing the whole table (the tab passes over a failing table in silence). 1.74.0's test had no link
inside the ISP.

- **Every kind of link kept** (machines/routes.py): your ISP's link kept for the map as the others are, the table
  made with it.

## 1.74.1 (2026-11-22)

The routes kept read back. After 1.74.0 landed and the platform restarted, the World Wide Web tab's Routes table, its
hop table and the globe's routes were empty though the hosts database kept 329 routes: 1.74.0 traces a host once,
never again after a restart (HostBook.routed), and read none of the kept routes back.

- **Read back, once each** (hostbook.py, machines/routes.py, machines/firewall.py): `HostBook.routes_of(remotes)` hands
  back each host's kept routes as its last check found them (the check's other routes from `traces`, the one drawn
  from `routes`, last; 256 hosts a read at most); the tab's routes read them back as the hosts are wanted, once each,
  so they are drawn and tabled again with their own age, never traced or saved again.
- **The Routes table** says so in its note (a host traced once, to its end; its routes kept and read back after a
  restart), and its Traced column says hours and days too (a route read back may be days old).

## 1.74.0 (2026-11-22)

The routes kept whole, checked once, told hop by hop; the traffic watched on a switch. The user, 2026-11-22: "all
routes need to be saved in a database for now"; "make sure all route checks only happen once, to conclusion, and not
every packet or connection, if there are multiple routes to a host, record all applicable routes"; "for each traceroute
show every hop in order with it's IP, round trip time, reverse DNS name, ASN, network operator, hostname, show RDAP
ownership keep missing hops visible. finally highlight where it crosses between network operators"; "for trace routes,
identify exchange IPs, where operators change, try to identify the operator backbone, if it can be proved"; "lets have
a selectable switch on firewall which allows it to run while not selected as far as monitoring traffic". The platform's
page shows it once the platform is restarted.

- **Every route saved** (hostbook.py): a new table `traces`, every trace its own row, however often a host is traced
  again (500,000 at most, the oldest let go first), beside `routes` (the newest a host); the routes of connections
  closed since the last ask saved too, once each.
- **Each check once, to its end** (machines/routes.py): a check traces a host 3 times (CHECKS), each run to its end
  (stopped only by a detach; the tab left, no other begins); every distinct route found is saved its own row, the one
  drawn last; a host traced to its end is not traced again, nor after a restart (HostBook.routed: the hosts the
  database has a route to); a check that failed is tried again after an hour.
- **Routes, hop by hop**: a table after the Routes table: every hop of each route in order (one that did not answer
  kept, as *), its address, its time, its name (reverse DNS), its network's number and operator (the GeoIP file's),
  its holder (RDAP), what it is (an exchange point, or an operator's backbone, only where its registry's words or its
  own name say so, and what says it shown beneath), and where the route crosses between operators (⇄, at an exchange
  point when it is one). The hosts themselves are looked up too, for their names.
- **Each link classified, for the map** (the user: "also for trace routes, with the local ISP, and how they
  connect to an exchange or private link (between routers), also identify the carrier links (major hauls)"): the
  hop table's Link column: your ISP's (inside the first network met), an exchange point's or a private link
  (where networks meet), a carrier link (inside one network, over 500 km or 10 ms between two hops); each link
  kept in the composite database (an entity "link", its "trace" claim) for plotting the infrastructure.
- **Watching the traffic all the time** (machines/firewall.py): LIMINAL_TRAFFIC_WATCHING, "shown" or "always", kept
  through the plugin's login and set from a "Watching the traffic" table and form on the World Wide Web tab (hook
  world_watching) or on the plugin's page, a key beside the hosts' recording (WATCH_KEY), followed at once either
  way. Always: the capture at this machine's adapter starts at once and never stops for want of an ask (only a
  detach or the platform's stop ends it); shown: as before. The routes are still traced only while the tab is shown.

## 1.73.0 (2026-11-22)

Routers' names read for their places. The user, 2026-11-22, asked whether to build it after a router GeoIP put in
Greenville turned out to be named lag-807-10.bbr01sttlwa.netops.charter.com (sttlwa: Seattle, Washington): "Yes, build
it". The platform's page shows it once the platform is restarted and the two lists are installed (each the user's
click; their addresses and licences are the plugins', none named here).

- **Two data sets, two layers** (machines/infrastructure.py): the formats `ourairports` (OurAirports' airports.csv:
  each large or medium airport with a three-letter code, a point of the new layer "airports", named by its code) and
  `geonames` (GeoNames' cities15000.zip, its one text file: each city a point of the new layer "cities", the most
  people first, 20,000 at most, its sub "country-division · people"). Both layers are off at first and drawn when
  switched on: the cities of the world named on the globe as it comes nearer. The globe lists ten layers at most now.
- **`machines/names.py`**: a router's name read with them, its domain left out: a three-letter airport code (words
  routers' names use for their parts left out) gives the airport's town; a six-letter city-and-state code (sttlwa)
  the largest city of that US state whose letters are in it, in order; a city's name in letters that city. A place is
  kept only where the trace's time to the router allows it (100 km a millisecond there and back, and 300 km); the
  router's country (its network's, else the GeoIP file's) first, then the surest way of reading, then the most people.
- **Wired in**: a name found by the lookups is read at once, and its place is a claim in the composite database
  ("name", weight 0.6 against the GeoIP file's 0.3); each router's best estimate is kept in memory (and read back once
  after a restart); a hop is drawn where its best estimate puts it when that is surer than the GeoIP file alone, its
  hover saying what placed it ("placed by its name (sttlwa)").
- A name looked up before the lists were installed is read with them as soon as they are (in memory, asking no one).

## 1.72.1 (2026-11-22)

No outside host named in the library again. 1.72.0's lookups named IANA's RDAP bootstrap files in
machines/lookups.py, which the charts app's boundary test (tests/test_plugin_boundary.py: no provider's host outside
the plugins) refuses. Their addresses are now the plugin's, as its GeoIP file's are: the Firewall base's new
`RDAP_BOOTSTRAP` (none: no registry is asked, and the routers' names are still looked up), handed through
`Routes(bootstrap=)` to `Lookups(bootstrap=)`. Checked with the charts app's own boundary test over this library. Until
both firewall plugins name them, the routers' networks are not looked up.

## 1.72.0 (2026-11-22)

Each router's name and network, looked up within each source's limits. The user, 2026-11-22: "it will take a lot of
looking over and using reverse lookups, and whois to figure out as much info as possible on the nodes. if there are
frequency limits on sources, please hold to those limits as not to get banned", and, asked whether to start them:
"Yes, start them". The platform's page shows it once the platform is restarted.

- **`machines/lookups.py`**: for every router on the routes kept, its name by reverse DNS (this machine's own
  resolver, 2 a second at most) and its network by RDAP, the registries' WHOIS over https: the registry from IANA's
  bootstrap files (read once a week), then one GET of it for the address. Each registry is asked 10 times a minute and
  1,000 an hour at most, the strictest limits any registry publishes (LACNIC's without a key) held for every one; after
  a 429 none is asked for its Retry-After (5 minutes without one, an hour at most), nor for 5 minutes after a 403. The
  answer's range is kept, so a router within one already known asks nothing. Only https, only the hosts the bootstrap
  files name, a redirect followed only to one of them. Nothing is asked twice within a day; a failure is tried again
  after it. One thread while the tab is shown, ended 20 s after its last ask and for good on detach. Only the routers'
  addresses go out, with a User-Agent naming the library alone.
- Each finding is kept in the composite database ("ptr", "rdap", with their sources' words); a claim with no point
  places nothing (it no longer takes a router out of the queue). Each hop on the page carries its `name` and its
  `network` (the network's name, its holder and its country), and its hover says them (liminal-globe.js).
- The suite's guard refuses the real resolver and the real https GET of the lookups, and starts no thread for them.
- Next: reading the city and airport codes in routers' names (with a public-domain list of airports, your download),
  so that a name places its router too.

## 1.71.0 (2026-11-22)

The composite database of the firewalls' World Wide Web tab, its first part. The user, 2026-11-22: "maybe we need to
create a composite database", "we need real world infrastructure to pair against real/virtual network maps", "so we
need both sides to build a composite database", and of the legs not known: "lets keep that in a queue of
places/segments to lookup". The platform's page shows it once the platform is restarted.

- **`machines/composite.py`**: one SQLite file, composite.db, beside the infrastructure layers (the data folder's
  infrastructure/; never written on another system's drive). `entities` (the routers, by address), `evidence` (every
  source's claim, row by row: its source, its licence, what it says, first and last seen), `estimates` (each
  router's best place: the claims within 50 km of one another make a cluster, the heaviest wins, its confidence one
  less the chance that every source in it is wrong, each source's own weight in `SOURCES`) and `queue` (what is not
  known yet: a router with no place, a leg with no way along the lines; with why, the sources left to try, and when
  it was first and last seen; done when found, kept for the record).
- Filled by the tab's asks (Routes.onto): each trace's routers once (their hop, the one before them and the time to
  them, measured here; and the GeoIP file's place, with its licence's words, which the firewall now passes), and the
  network's legs (network.Network.legs: on the lines, or waiting with why). Only what is new or changed is written,
  a row again at most every 5 minutes; the file is open only while a batch is written. The "Legs waiting for a line"
  table says what the database holds.
- Nothing is asked of anyone yet: the GeoIP file is the only source of places. Next: routers' names (reverse DNS) and
  their networks (RDAP, the registries' WHOIS), each within its source's published rate limits, as the user asked
  ("if there are frequency limits on sources, please hold to those limits as not to get banned").

## 1.70.0 (2026-11-22)

The routes on the firewalls' globe are drawn only along real lines, coloured violet to red by how often traffic goes
over them. The user, 2026-11-22: "this clearly shows vectors direct to different places, what i need is real maps of
infrastructure lines, etc, the straightlines are meaningless"; "the vector should literally follow a detailed route
based on geographic data, if it is unknown, any segment with in the route, then lets keep that in a queue of
places/segments to lookup"; "all known routes should have their temperature change (color) based on traffic
frequency"; "we will use the whole color wheel from violet to red (high frequency)", "for the routes". The platform's
page shows it once the platform is restarted (the globe's script keeps drawing an older server's page).

- **Never a straight line** (machines/network.py): a leg is drawn only along the installed lines (cables, lines on
  land, backbones). A leg not known on them is not drawn at all, and waits: `globe.waiting` lists each once, from and
  to by name, with why ("no line layer is installed", "no line within 150 km of …", "both ends are nearest the same
  junction of the lines", "no way along the lines within 2.5 times its distance") and its straight distance; the
  routes table is followed by "Legs waiting for a line". A leg within one city needs no line and does not wait. The
  stretch from a junction to a hop or a host is not drawn either: those are the named points of 1.69.1.
- **How often, not how much**: each edge a route uses gains its place's connections once (`heat_by` is always
  "connections").
- **Violet to red** (liminal-globe.js): the routes' colour runs round the whole wheel, violet (270°) for the least
  through blue, green, yellow and orange to red (0°) for the most, on a log scale, 24 steps; bright on a dark globe
  (90% saturation, 62% lightness) and deeper on a light one (80%, 40%), so every hue shows on both. The width rises
  with it, 1.5 to 4.5 px, and the hottest have a glow of their own colour: the scale reads without its colours too.
  The infrastructure layers keep their grey-blue and the coasts their grey-green. The legend says "Routes by how
  often: connections", with the least and the most, beside a violet-to-red key.
- **Lights into the hosts along the lines**: each place's `tail`, the last 250 km of its way along the lines from the
  junction nearest it (256 points at most), is where its light travels; none where its last leg waits. An older
  server's page keeps its straight last stretch until the platform is restarted.
- Checked in headless Edge over stand-ins: the hottest route drawn red (234/69/69 on the dark globe, 185/29/30 on the
  light one), a quiet one blue (69/115/231, 34/78/187), the legend's words, nothing thrown.
- Still to come: the composite database the plugin keeps, the lookup queue kept in it and worked through (each
  lookup that asks anyone outside your switch), and the data sets the routes can follow (the Monday list's 24, 27-29).

## 1.69.1 (2026-11-22)

The routers' places the routes bend at are drawn and named on the firewalls' globe. The user, 2026-11-22: "there
appears to be verticies without location names or cities, please address that". The globe's script only: a page shows
it once reloaded, with no app restarted.

- With the heat (1.69.0), each router's place a route passes (`via`: its GeoIP place, the router's address, its hop
  number and time) is drawn once, however many routes pass it, as a small white dot under the places' dots, and named
  as the places are: the busiest first, never over another name, 6 of them up to 2x, 16 up to 6x and 40 nearer
  (`HOP_NAMES`; 512 places at most, `MAX_HOPS`). Its name is the GeoIP file's city, else its country, else the
  router's address.
- On hover (a tap with a finger): its place, "a router on the way" with its hop numbers, the addresses seen there, the
  nearest time to it, the places whose routes pass it, and what placed it (the GeoIP file on this machine, often the
  network's home rather than the router). Kept through the page's next answer while a route still passes it.
- Still to come (the Monday list, items 27 and 28): names from more sources than the GeoIP file (the nearest town, the
  router's own name), and the hubs of the installed layers along each route.

## 1.69.0 (2026-11-20)

The routes on the firewalls' World Wide Web globe follow the physical network and are drawn as a heat map. The user,
2026-11-20: "so for the routes, they should try to mirror their physical routing on the map, ie undersea cables, fiber
runs, etc... also, they should look like a heat map, but the actual route between pt a and pt b, doesn't change so more
traffic over this and that, the brighter it gets, lets keep grey scale to white but don't use the current method of
dots flying over existing infrastructure, just use that to the end points/hosts". The platform's page shows it once the
platform is restarted; the globe's script keeps drawing an older server's page as before.

- **The network** (new `machines/network.py`): a graph of the installed line layers (submarine cables, backbones,
  telecom lines on land), built from their files when a page asks and their versions changed, held until they change
  or the plugin is detached. Points on one cell of the files' 0.02 degree grid are one vertex; a line's end is joined to
  the nearest point within 25 km (`JOIN_KM`) of a line not connected to it, and a loose end to any other line's point
  that near; runs with no branch are one edge each. Half a second for a layer's 400,000 points here (20,000 lines at
  random; the joins' pairs weighed a quarter of a million at a time, some 40 MB).
- **Each leg snapped onto it**: home, the route's placed hops and the host, leg by leg, each end to the nearest junction
  within 150 km (`SNAP_KM`), then the shortest way (A*, bounded by the limit and 50,000 junctions looked on from),
  taken when it is no longer than 2.5 times (`DETOUR`) the leg's great circle, the snaps included; else, under 30 km
  (`CITY_KM`, one city's) and where no layer is installed, the leg's great circle. A hop the network meets on both its
  legs is passed through at its junction (no spike out to the router's GeoIP place). Ways and snaps are cached with
  their graph.
- **The heat**: each stretch a route uses gains its place's traffic once, however often the route goes along it (the
  place's bytes where the capture counted any on the page, else its connections); shared stretches are summed. The
  page gets `globe.heat = [{points: [[lat, lon], ...], w}]` (runs of one weight, the heaviest kept first, 4,000 runs and
  200,000 points at most), `globe.heat_by` and each place's `last`: where its route leaves the network, else its last
  hop, else home. `Routes.onto(..., index=)` adds it (the firewall passes its layers' index); a heat that fails is left
  out and the routes are drawn as before. The routes table's note says so.
- **The drawing** (liminal-globe.js): the heat in a layer of its own over the infrastructure and under the places, on
  the globe's surface, from a mid grey to white (on a light page, grey to the text's colour) and 1 to 3 px by the
  traffic on a log scale, 16 shades, the brightest with a faint glow under them. No lights on the network: a light
  travels each place's last stretch alone, from `last` to it. A page without `heat` keeps the lifted routes and their
  lights. Checked in headless Edge over stand-ins: the heat, an older page, the heat again, none, a light page; nothing
  thrown.
- No layer is installed on this machine yet: until one is, every leg is its great circle, drawn as heat.

## 1.68.1 (2026-11-20)

The globe zooms to 1024x. The user, 2026-11-20: "i need zoom up to 1024x". Static files only: a page shows it once
reloaded, with no app restarted.

- `MAX_ZOOM` 1024 (it was 96): some 30 m a pixel on a globe 520 px high. The wheel and two fingers zoom smoothly; + and
  − step by 1.6, fifteen presses from the whole globe. GSHHG's coasts (about 200 m of detail) and the infrastructure
  layers' lines (a point kept every 0.02 degrees, about 2 km) show as straight runs that close; places and marks keep
  their 1e-5 degrees (about a metre). Checked in headless Edge: zoomed in to 1024x and out again, nothing thrown.

## 1.68.0 (2026-11-20)

Every connection in the hosts database. The user, 2026-11-20: "all connections need to be databased, basically who,
what, when, why,where", and, asked whether to record all the time the platform runs: "Yes, always" (their own
Recording setting, now Always). The connections are still found by the socket table's readings, every 5 s while
recording runs all the time; the subscription to the system's own connection events comes next (the user: "we
should be subscribed to the events instead of polling").

- **`connections`** (hostbook.py): each connection its own row, from the reading that first counts it to the first
  reading without it, where the hosts' rows fold a program's connections to a host and a port into one. Who: the
  program, its path, its process, its user, its service and the service's title. What: the protocol and family, both
  ends, the direction, the service's port, the host's name where the system knows one. When: its start where the
  system says one, first and last seen, when it was gone, the seconds connected (counted as the hosts' are: no sleep,
  only while established). Why (`why_of`): in words, from what this machine knows: which way it goes, the port and
  what this system's services file says it is for, the local network or the internet, the service behind it. Where:
  the place, the network and its owner the GeoIP file gives (a new connection takes its host's place when it is
  written; placing a host places its connections), and the route traced to the host. A connection that began and
  ended between two readings is kept too, under "?". Its id is its key and when it was first counted, so one open
  across a restart goes on in the same row.
- **`routes`**: the route traced to each host (machines/routes.py hands each one over once it is placed): when, whether
  it reached the host, how, every hop with its place, the places on its way. `connections()` hands each connection
  out with its host's route.
- **Bounds**: 500,000 connections at most (about 150 MB), the ones that ended longest ago let go first, none kept 90
  days after it ended; 20,000 routes, none past 30 days. `forget` forgets them with the hosts.
- **`sockets.judge`** says what each row's service port is for (`port_name`, `service_name`: this system's own services
  file, nothing asked of anyone).
- **The Netstat tab**: "Connections recorded", the newest 200, under the hosts database's own table (which counts
  them): began, lasted, gone, who, what, where, why. A tab with the GeoIP file open places the connections recorded
  with no place yet, with the file it has open.

## 1.67.0 (2026-11-20)

Every connection's route on the firewalls' World Wide Web globe. The user, 2026-11-19: "also use traceroute or find
the routes that the traffic is being used", then "no, trace all connections". The firewall plugins' tab draws it as it
is: no plugin and no app changes for it.

- **`netpath.trace`**: a whole route to a public address (`traceable`: never a name, never the local network). On
  Windows an IPv4 route goes through its ICMP API (iphlpapi's IcmpSendEcho: no administrator, no process started),
  every hop of a wave of 16 asked at once, about a second a wave, the next wave only when the address did not answer
  within this one; IPv6, and a Windows whose ICMP API cannot be used, through `tracert -d`; elsewhere through
  `traceroute -n`, else `tracepath -n`. Each hop's address and quickest round trip (`Hop`, `Trace`); `parse_trace`
  reads the three tracers' words.
- **`machines/routes.py`** (`Routes`): while a firewall's World Wide Web tab is shown, the remote address of every
  connection open to the internet waits to be traced, one at a time on one thread, a quarter of a second between two.
  A route is kept an hour in memory (1,024 at most), never on disk, and traced again after that while its connection
  is open. The thread ends once nothing waits or the tab has not been asked for 20 s, and for good on detach or when
  the platform stops.
- **The globe**: a place's line runs from home through the placed hops of the route traced to an address there (`via`
  on the place; the hops at home's place, at the place's own, at the place of the hop before and those the GeoIP file
  does not place are left out), each leg a great circle, a small grey-blue dot at each hop. The tab's new table
  **Routes**: each route's address and place, its hops answered, its way through the places, when it was traced. A
  router's place is where the GeoIP file puts its address, often its network's home rather than the router.
- **The firewall base**: `world()` hands the routes the connections' remote addresses at each ask and puts the routes
  on the page; `world_routes()` and `make_world_routes()` (a subclass's tests hand a stand-in); closed on detach and
  in `app_stopping`.
- **After two independent reviews**: an unreachable ends a route where it was said (a router that passes it no
  further, not reached; the target's own, reached), where it had padded the route to 30 hops; a tracer is killed
  once the tab is left or the routes are closed, and the ICMP path asks no further wave then; a tracer that lists no
  hop hands over to the next and says why; a tracer's silent hops past the last answer are left out, as the ICMP
  path's are; the retired site-local and the reserved ranges have no route; a thread that will not start is asked
  for again; the page gets copies of its places; a platform stopped and started traces anew. On the globe a hop
  within a few kilometres of the one before it makes no leg (it had been drawn round the far side), and a route is
  drawn with 128 points at most. The Routes table is the tab's last, so every table before it keeps its place.
- **Tests**: the suite's guard refuses a real trace (the ICMP probe, the tracers, the routes' thread): a test hands its
  own. The globe's script was loaded in headless Edge over stand-ins, routes through hops among them.

## 1.66.1 (2026-11-19)

The globe's look, as the user asked while looking at the firewalls' World Wide Web tab: "only end points of routes are
colored", "the land borders should be green", "lets use faint grey-green, (matrix green)", "use grey blue for the
routes, hubs, bones, underwater cables". Static files only: a page shows it once reloaded, with no app restarted.

- **Coasts and country borders** are drawn in a faint matrix grey-green (`--globe-land` in `liminal.css`: #3edb65
  on the dark themes, #2e8b57 on the light ones, laid on at 55 % and 30 %), in place of the muted grey.
- **Routes and every infrastructure layer** (data centres, exchange points, landing stations, backbones, submarine
  cables, lines on land) are drawn in grey-blue (`--globe-network`: #8fa3bf, light #5b6f8a), the lights moving along
  the routes too. A kind's colour (allowed in, unanswered in, out) now marks only a route's ends: its place's dot and
  the legend's kinds. The layers are told apart by their marks (circle, square, diamond; line, dashed line).
- A page without the variables draws the same colours (the globe's own fallbacks).

## 1.66.0 (2026-11-19)

The MCP plugin's base, and what the top four inference engines and harnesses stand on. The user, 2026-11-18: "now i
need an MCP plugin for platform, basically a protocol plugin that mediates MCP connections to resources by local AI
agents"; "top 4 inference engines, top 4 agentic harnesses (open source)"; "all platform"; "both linux and windows
compatibility". The plugins themselves are packages of their own, built on this release. liminal-platform 0.34.0
gives the protocol plugins their route and holds who may ask a hook. No plugin API number moves, and a plugin that
says none of the new words is asked as before.

- **Protocol plugins** (`machines/protocol.py`: `ProtocolPlugin`, under `AiPlugin`). The base of a plugin that speaks
  a protocol to the local AI agents on the platform's own port, MCP's first. Its group is "protocol": the platform
  draws it as Protocols, after the harnesses. Its software is its own code, so there is nothing to install. A
  subclass says three things: its protocol (`serve`), how an agent is wired to it (`offer`) and what its grants can
  name (`grantable`). The base gives the rest:
  - The route's hook (`RPC_HOOK`, `rpc`). The platform hands it a request whole; it is never asked by name. The agent
    is found by its bearer token: without a token it knows, the answer is 401. Each agent has a rate (60 a minute by
    default): past it, 429. The token is never handed on to the subclass. A fault in the subclass is a 500 in words.
  - Its agents: at most 16, each named by 1 to 24 lowercase letters and digits, kept through the login as one pair
    (`LIMINAL_AI_<NAME>_CLIENTS`). Each agent's grants are a pair of its own, and a new agent is granted nothing. The
    pairs are read once, when the plugin is attached, and used from memory. A pair changed outside the plugin is not
    used, and its page says so.
  - Tokens are never kept as text. A hand-wired token is shown once (`token_once`, asked twice): only its sha256 and
    its expiry are kept (30 days by default). A launch token is made for the asking plugin's own agent and held in
    memory alone (32 at most). It ends by `end_launch`, by a stop, or when newer ones push it out. Every digest is
    compared with `hmac.compare_digest`.
  - Calls held for your answer on its page (`hold`, `decide`): 4 for one agent and 16 in all. Each ends by your
    answer, by its hold running out (50 s by default), by its request gone, by the agent's cancel or by a stop. A call
    that ends unanswered never runs. A call to be asked twice is shown with its exact arguments, and is never allowed
    for a whole session.
  - The audit: the last 500 calls in memory, their arguments masked and cut; a line for each call in
    `home/logs/calls.log`, with no argument text (moved aside past 1 MB); and a row of the platform's traffic
    (`agent:<name>`). Every secret value the plugin knows is masked. Its Main tab has an Agents table and a Waiting
    for you table, with their forms.
- **Who may ask a hook** (`internal.py`, `apps/asking.py`, `App.present`). Two new words on a plugin's class:
  `PLUGIN_ONLY_HOOKS`, asked only by another plugin through its app, never by a page or a program; and
  `PAGE_ONLY_HOOKS`, asked only from its page, never by another plugin. `internal.plugin_only` and `page_only` read
  them along the class line, and refuse when a word cannot be read. `problems()` names a hook that is not among
  HOOKS, a hook in both words, a service only its page asks and a tab only other plugins ask. The Internal API tab
  tags them: "asked only by other plugins", "asked only from its page". Who asks is handed over in so many words and
  never taken from what a thread inherits: a route sets the page (`asking(PAGE)`), `App.ask` sets the plugin that
  asks, and a job takes its asker where it is started (`handed`). A gated hook asked with no asker is refused in
  words (`AskRefused`, a 403). `App.present(handler)` says whether the person at the browser is shown to be there:
  the login's own proof when it has one, else a signed-in browser; None when the app holds no login.
- **A piped child** (`machines/children.py`: `Piped`), for an MCP server over stdio. Its input and output are pipes,
  and each message is one line (at most 4 MiB: a longer one ends it). What it prints as errors goes into its log,
  the launch's secrets masked. It is started as a Child is: no window, a job object on Windows, a session of its own
  on Linux, its pidfile written. It is stopped in the order MCP's stdio transport gives: its input closed, its grace,
  then ended with what it started (its job on Windows; SIGTERM, then SIGKILL, to its group on Linux). One an earlier
  run left running is ended at its next start. `Child` itself is unchanged.
- **Harnesses** (`machines/harness.py`):
  - A window on Linux too, where the platform has a display (DISPLAY or WAYLAND_DISPLAY; under WSLg the window opens
    on Windows' desktop) and one of TERMINALS is found. They are looked for as files, in this system's own folders
    alone: nothing is started for a status. Each terminal is one whose flag hands the rest of the line over as
    separate words; x-terminal-emulator only when its link leads to one of them. Without them, Open… gives the lines
    to paste, as before.
  - Liminal's MCP, for a harness that offers it (`MCP_OPTION`, `MCP_WIRES`), off unless Use… turns it on. Then the
    MCP plugin is asked how it is reached and for this harness's agent. Each Open… that opens a window asks a token
    for that window alone, and ends it once the window is gone. The token reaches the tool in `LIMINAL_MCP_TOKEN`
    alone, a secret of its launch: never on its command line, in a file or in the lines to paste. Command… gives none.
  - Values a harness would read as more than text are refused: a model's id, an option's text and every value a
    plugin writes into its tool's configuration (`clean_value`) may hold none of `${`, `$(`, `{env:`, `{file:` and
    `${{`, and may not begin with `!`. A plugin adds its tool's own (`Harness.OPENERS`).
  - Two of these reach every harness, as the plan chose: on Linux with a display and a terminal, Open… opens a window
    where it gave lines to paste; and a value holding one of those openers is refused.
- **What a server speaks** (`machines/modelserver.py`). Each `serving` row says which families of OpenAI-compatible
  asks its server answers (`speaks`, of `FAMILIES`: chat, completions, responses, messages, embeddings), so a harness
  that asks one family alone can tell before it starts. It is the plugin's word (`SPEAKS`, chat by default;
  `speaks_of` narrows one instance), never asked of the server.
- **A private Node.js and npm** (`machines/node.py`, lifted from plugin-platform-continue 0.1.0), for Pi, Cline, the
  MCP catalogue's Node.js servers and Continue. Each plugin brings its own Node.js (its line, 24, from the archive it
  pins). npm is run by its whole path, always with `--ignore-scripts --no-audit --no-fund --no-update-notifier`, and
  with none of the user's npm or Node.js settings. The top package's sha512 is checked against the plugin's pin
  before anything is put in use; its dependencies are checked against the registry's own sums alone, and the page
  says so. The lock npm wrote is kept, so a repair installs the same tree again with `npm ci`.
- **Hugging Face's cache and its hf command** (`machines/hub.py`, lifted from plugin-platform-vllm 0.1.0), for vLLM and
  LMDeploy: the cache read from its folders, a download's progress, a delete inside the plugin's own folder, what the
  Hub says of a model (its licence, whether it is gated, its files and its size) and hf's dry run. The Hub's address
  is each plugin's.
- **The frame**:
  - `web.Server`, the apps' server, whose port is its own on every system. On Windows it sets SO_EXCLUSIVEADDRUSE
    before its bind, so a second server can no longer share a port an app serves; elsewhere it keeps SO_REUSEADDR,
    and it never sets SO_REUSEPORT. `App.start` uses it.
  - `web.send_json` sends a 202 or a 204 whose data is None with no body: MCP's "202 Accepted with no body".
  - Connections draws an AI agent that asks through the MCP plugin as a caller (`agent:<name>`).
  - `API_KINDS` gains "rpc": JSON-RPC over HTTP or a program's standard input and output.
  - Six makers' marks in `ui/static/icons.js`, drawn anew in the set's line: lmdeploy, codexcli (Codex's own mark,
    not the OpenAI knot), pi, cline, goose, mcp.
- `machines/ai.py`: `Installed.how` "part", said as "{title} {version}: part of this plugin, nothing to install";
  Install… and Uninstall… refuse it in words. `machines/plugin.py`: the group "protocol".
- Not in this release: the frame headers that stop another site framing a page (frame-ancestors, X-Frame-Options).
  They change every answer of every app, so they are put to you first.
- **Tests**: test_protocol, test_asking, test_internal_words, test_node, test_hub, test_web and test_ai_release (the
  real protocol base, a harness and the frame on one app, with no stand-in between them); new tests in
  test_children, test_harness, test_modelserver, test_traffic, test_source_apis and test_icons. All are on stand-ins
  under the shared `no_outside` guard. The one real socket is test_web's: a server on 127.0.0.1, port 0, on a thread.
  Each piece was reviewed, and then the whole: every finding was reproduced first and fixed with a test that fails
  without the fix.
- **A write nested too deep is answered** (every app's frame, `App`'s write handler): a body nested deeper than
  Python's JSON reader recurses (100,000 brackets each way, 200 KB) raised RecursionError, which the frame did not
  catch, so the write got no answer at all and its thread printed a traceback. It is answered 400, "the body is not
  JSON", like any body that is not JSON, and the next request is answered as before. Only a page or program on this
  machine with the app's write header could send one. Found by the platform's review of the MCP route; test_apps
  holds it, with the body made in the test.

## 1.65.1 (2026-11-19)

The globe zooms to 96x, and draws backbone networks. The user, 2026-11-19: "i need to zoom in a few more times maybe
96x"; "also on the firewall theres no real ibone or major hub s drawn on the map, data centers in the world (dataset)
and major network 'bones' need to be displayed on the map"; "also underwater lines". And, 2026-11-16: "the firewall
globe should instead of exchanges, have all the backbones,ibones, major internet infrastructure, (as many as possible)
datacenter locations." plugin-platform-firewall-windows 0.7.1 and plugin-platform-firewall-linux 0.9.1 name the new
data set and need this release. liminal-platform 0.33.0 draws the new layers as it is. The plugin API stays 2.4.

- **The globe zooms to 96x** (`ui/static/liminal-globe.js`: MAX_ZOOM 96, was 12). The wheel, a pinch, two fingers,
  + and − all stop there, and the words say "96×". Past 12x it draws Natural Earth's 1:10m map. Past 24x it draws
  GSHHG's coasts and borders, points some 200 m apart: about 300 m a pixel at 96x on a globe 520 px high. The land
  is still filled from the 1:10m map, since GSHHG's tiles are lines: the fill is within a few pixels of GSHHG's coast
  in most places, further off in fjords and skerries, and small islands and lakes are outlined only.
- **Only what is on the canvas is asked for and drawn.** GSHHG's coasts come in tiles of 10 degrees. Only the tiles
  on the canvas are asked for, the nearest the middle first, each once, four at a time, and none while the globe
  glides. A tile that fails is not asked again for a minute. At most 120 tiles and 1,000,000 points are kept (some
  12 MB), and never more are picked than are kept. The least lately drawn go first, and all go with the last globe.
  The map's own coasts and borders are drawn under the tiles until every tile on the canvas is in. Lines are kept in
  pieces of 128 points; a piece out of sight is skipped, and a run of points off the canvas is cut short. A drag
  costs some 5 ms a move at 96x and 3 ms at 10x, where 1.65.0's script took 49 ms at 10x (headless Edge, over
  Bergen). The view's key is kept to 1e-5 degrees, so a cached layer stays on its routes at 96x.
- **GSHHG is credited** over the map while its tiles are drawn: "Coasts and borders: GSHHG 2.3.7 (LGPL-3.0)".
- **Two maps ship with the library** (`ui/static/vendor/world/`). They are the charts app's own copies, as its
  repository holds them, copied from this PC's disk: nothing was downloaded. `VERSION` gives each file's size and
  sha256.
  - `countries-10m.json`: world-atlas 2.0.2's 1:10m map (ISC), Natural Earth's data (public domain), 3,661,071 bytes.
  - `coast-h/`: GSHHG 2.3.7's high resolution (Wessel and Smith), under the LGPL-3.0: 433 tiles (8,730,088 bytes)
    and `index.json` (25,542 bytes), built by the charts' `tools/build_coastlines.py`. GSHHG's `LICENSE.TXT` and
    `COPYING.LESSERv3` come with them, and `COPYINGv3`: the GPL-3.0's words, which the LGPL-3.0 builds on (the Free
    Software Foundation's text, from this PC's disk).
  - Together they add 12,460,853 bytes (about 12.5 MB) to the package. `pyproject.toml` takes
    `ui/static/vendor/world/coast-h/*` as package data. `.gitattributes` keeps `vendor/**` byte for byte and takes no
    blank of theirs for an error (`-text -whitespace`).
- **A fourth data-set format, `gml`** (`machines/infrastructure.py`): maps of networks in GML, in a tar archive,
  gzipped or not, or one alone. It is for the Internet Topology Zoo's maps. The answer is unpacked in memory only and
  never written out. Of each network, its newest map is drawn, from 2000 on. Its own points of presence with a place
  go to a new layer, `pops`. Each link between two of them goes to a new layer, `backbones`, drawn as the great circle
  between its ends. Both layers' titles say "about 2010-2011". The job's log says how many maps were read, how many
  networks drawn, and which maps were left out and why. `LAYERS` holds 8 now, the globe's MAX_LAYERS.
- **The gml format is bounded.** At most 32 MB unpacked (MAX_UNPACKED), 2,000 files in an archive (MAX_MAPS), 4 MB a
  map (MAX_MAP), 100,000 nodes or edges a map (GML_ITEMS), lists 16 deep (GML_DEPTH). A gzip member is fed to zlib in
  pieces, so many members cost no more than their size (320,000 members: 0.21 s). An archive's maps count against
  32 MB by the sizes they say, before each is read, so a sparse file's zeros count too. An archive whose headers chain
  too deep is refused in words. A map holding a number too long to read is left out and said; the others are drawn.
- The infrastructure table's note names backbones and their points of presence. Three new reasons count what a map
  leaves out: a point with no place, a point outside its network, a link between points not drawn.
- **The data sets the firewall plugins name** (this library names no outside host): the Internet Topology Zoo's
  261 maps of networks, about 2010-2011 (CC BY 4.0, 348,613 bytes), new. OpenStreetMap's submarine cables of all
  eight telecom categories (ODbL 1.0, about 3 MB), now in both plugins. OpenStreetMap's lines on land without those on
  power poles (ODbL 1.0, about 15 MB, was 20 MB). Wikidata's data centres with their subclasses (CC0, about 0.2 MB).
- Left out, and said. No free map of today's backbone fibre routes exists: operators keep them private or sell
  them, so the backbones are the Topology Zoo's logical links. No free world map of undersea cable routes is as
  complete as TeleGeography's, which is sold: OpenStreetMap's are mostly coastal pieces. Wikipedia's list of exchange
  points (CC BY-SA 4.0) and NOAA's cables in US waters (CC0) each need more than one request: not yet. PeeringDB, PCH,
  IXPDB, CAIDA, TeleGeography and the ITU are not free-licensed, and the World Bank's CC BY copies rest on PCH's and
  TeleGeography's data. If "underwater lines" meant sea depths, Natural Earth's bathymetry (public domain) could draw
  them: not done.
- **Tests**: test_ui_globe.py (40: the zoom to 96x, the 1:10m map past 12x, the tiles picked nearest first and no more
  than are kept, every tile read whole, pieces out of sight, the cut pen, precision at 96x, the GSHHG credit, the
  vendored files and their licences); test_infrastructure.py (41: maps of networks read into backbones and points of
  presence, the GML reader, answers refused in words, the bounds above); test_netstat.py follows the format's words.

## 1.65.0 (2026-11-19)

The firewalls' Netstat tab, the hosts database, and the globe's filters and internet infrastructure. The user,
2026-11-16: "the firewall app should have a 'netstat' like interface for looking at active ports and what apps they are
attached to, and the hosts that they connect to across the lan or wan. the firewall app should also have a globe that
can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they are connected to
*this *computer"; "the globe-firewall should allow filtering, so i can view apps connected to hosts all across the
globe, or ports talking to all hosts. The globe should have the same kind of geography associated with the exchanges
globe, but the firewall globe should instead of exchanges, have all the backbones,ibones, major internet
infrastructure, (as many as possible) datacenter locations." All of it is the Firewall base's, so both firewall plugins
have it: plugin-platform-firewall-windows 0.7.0 and plugin-platform-firewall-linux 0.9.0 name the data sets the globe
draws, and liminal-platform 0.33.0 gives the globe its way to load them. The plugin API stays 2.4.

- **The socket table** (`sockets.py`). `read` is this system's own socket table with the program behind each socket,
  asked of the system itself: no capture, no administrator and no password, no process started, no window, no name
  looked up, nothing sent anywhere. On Windows, IP Helper's TCP and UDP tables in their OWNER_MODULE class, one
  snapshot of the processes and the list of services, by documented calls alone (`WINDOWS_CALLS`); on Linux,
  /proc/net/tcp, tcp6, udp and udp6, and /proc/<pid>/fd for the account's own processes (`LINUX_FILES`). What a row
  could not read is said in it, in words (`unread`), never guessed. `judge` says where each remote host is (this
  machine, the local network or the internet), which way the connection goes, which port is the service's, an
  internet host's place (from a lookup the caller gives) and its name in the system's own hosts file; `under_wsl` what
  running inside a WSL distribution changes. A reading says which tables it read whole and whether it was cut
  (MAX_ROWS, 20,000 rows), carries a clock that leaves sleep out (`awake`), and is shared by every ask for 2.5 s.
- **The hosts database** (`hostbook.py`): one small SQLite file for each system on its own disk (the data folder's
  `hosts/hosts.db`; nothing is made, read or written on another system's drive), at most 50,000 rows (about 13 MB
  with ordinary values), the hosts longest unseen pruned first. For each program and remote host, with the protocol,
  the service's port and the direction: the program's path and service, whether the host is on the local network or
  the internet, its name where the system knows one, the first and the last time seen, the time connected to this
  machine, how many connections, and its GeoIP place. Time is counted only while a connection is established and the
  system awake (a night asleep is no time connected, a restart adds nothing), the open connections are kept in the
  file so that a restart goes on where it stopped, and a connection that began and ended between two readings is
  counted once under the program not named. This machine's own connections are never kept, and a local host is never
  placed. `book` hands out one database for a path in a process, so two views never count twice. A file SQLite finds
  damaged is set aside and recording starts anew; `forget` leaves nothing of what it removed in the file. Off Windows
  the folder is made 0700 and the file 0600.
- **The Netstat tab** (`machines/netstat.py`, `NetstatView`): the connections, each with its program, pid and service,
  the remote host and port, whether that host is this machine's, the local network's or the internet's, its name or
  its GeoIP place, its state, since when and how long it has been up where the system says; the listening ports, the
  four Liminal apps' pages named; the hosts database with its two forms, Recording and Forget (asked twice). Recording
  is a setting kept through the login (`LIMINAL_HOSTS_RECORDING`): `shown`, the default, records only while this
  plugin's Netstat or World Wide Web tab is shown, at their asks, the file let go after each; `always` records all the
  time the platform runs, a reading every 5 s on a thread of its own (`<name>-hosts`), never in a one-shot app, on a
  machine the plugin is not for or on another system's drive, and ended when the plugin is detached, when the platform
  stops and when the setting is set back. The page says that a program run by an interpreter shows as the
  interpreter.
- **The globe's filters**: the World Wide Web tab's globe shows the traffic watched now or the hosts recorded, the
  hosts filtered by program (its hosts across the globe), by port (every host on it), by direction and by when they
  were last seen (the last hour, 24 hours, 7 days or 30 days). The eight programs and the eight ports with the most
  hosts are offered right under the globe, with Every program and Every port; Programs, Ports and Hosts tables
  below. The hosts are grouped by point in the database's own query, and the page is made again at most every 10 s
  unless a choice changed; the GeoIP file is opened for them only while a host needs a place.
- **Internet infrastructure** (`machines/infrastructure.py`). A firewall plugin names its data sets
  (`INFRASTRUCTURE`: plain dicts read by `DataSet.of`, so the address, the query, the licence and the credit are the
  plugin's, and no outside host is named here). Three formats are read: an Overpass answer (OpenStreetMap's features by
  their tags), a SPARQL answer (Wikidata's items by their kind) and a GeoJSON FeatureCollection of lines (a WFS's cable
  routes, asked for longitude first). Only free-licensed data: its licence's words are shown whole first and accepted
  in a second confirmation, and its credit is drawn wherever its features are. A download is a job on the user's word
  that Cancel stops: one https request, whose User-Agent is the plugin's name and version and nothing of the user's or
  the machine's, on a thread of its own under one deadline of 10 minutes, a busy server asked once more a minute
  later; at most 32 MB is read, 20,000 points and 400,000 line vertices kept a layer. Each data set is kept in the
  data folder's `infrastructure/`, packed, and read back by layer (exchange points, data centres, cable landing
  stations, ground stations and teleports, submarine cables, telecom lines on land); a download that fails leaves the
  older file as it was.
- **The Firewall base** (`machines/firewall.py`): the Netstat tab after World Wide Web, asked every 3 s while it is
  shown; ten hooks (`netstat`, a read; `hosts_recording` and `hosts_forget`; `world_show`, `world_direction`,
  `world_within` and `world_pick`; `world_layer`, a read; `world_layer_get`, a job that can be cancelled;
  `world_layer_remove`); `INFRASTRUCTURE`; the key `LIMINAL_HOSTS_RECORDING`; and for a subclass `netstat_view`,
  `make_netstat_view` and `netstat_listeners`. Each ask of the World Wide Web tab reads the socket table for the hosts
  database too. On a machine the plugin is not for, every one of these hooks refuses in words before any view is
  made: nothing is read, recorded, kept, forgotten or removed there.
- **The globe** (`ui/static/liminal-globe.js`): `load`, the page's way to a layer's geometry, and `key`, under which
  the layers' switches are remembered in this browser. The layers are drawn where the exchanges globe draws its
  exchanges, with its marks, clusters and name boxes, the equator stressed; each layer is a button in the legend and
  its credit stands beside the places' attribution. A place of the hosts recorded says its hosts, the programs that
  talked to them and the time connected; `showing` says the filter in words.
- `machines/world.py`: the GeoIP file's waiting loop lifted into `run_download`, which a data set's download shares
  (the GeoIP file's install is as it was); `fetch_url` takes the request's `agent`; `WorldView.rest`. `apps/tabs.py`
  names the globe's new keys and the flows' (`since`, `state`, `unread`, the direction `local`; Flagged only only
  where a page's filters name it).
- Left out of this version, and said: day and night on the globe and the sun's mark; PeeringDB, root-server sites and
  cloud regions (not free-licensed, or no licence stated); a Netstat row setting the globe's filter.
- **Tests**: test_sockets_windows, test_sockets_linux and test_sockets_judge (the ctypes layouts' sizes and offsets
  held on both systems), test_hostbook, test_infrastructure, test_netstat, and the globe's in test_ui_globe, on
  stand-ins. tests/conftest.py's autouse `no_real_hosts` beside `no_outside`: in every test the recording setting is
  `shown`, the socket table's reader refuses, and the hosts database and the layers are in the test's own folder. A
  firewall plugin's suite from before plugin-platform-firewall-windows 0.7.0 and plugin-platform-firewall-linux 0.9.0
  has no such guard: run against this library it reads the machine's real socket table, so it is not run on it.
- **A port checked twice in a minute on Linux** (`ports.Listener`): the listener closes each connection it accepts
  before the other side does, so this machine's side of it lingers on the port for about a minute (TIME_WAIT). Linux
  refused to listen on that port again meanwhile ("Address already in use"), so a second "listen on the port" check
  said the port was taken. The listener now sets SO_REUSEADDR on Linux alone, where it never lets two listeners share
  a port; Windows keeps SO_EXCLUSIVEADDRUSE. Found as a test failing now and then in Ubuntu (the other session's
  report); a new test forces the order and failed 3 runs of 3 there without the fix, 20 of 20 passing with it.

## 1.64.1 (2026-11-19)

An empty span is a finding only with evidence, like a hole (the user, 2026-11-19, asked whether the sweep should stop
flagging spans that are empty only because the ticker did not exist yet: "Yes, fix it"). The first sweep of the real
data, the morning 1.64.0 landed, went over 3,148 series and kept 56 findings, every one of the same kind: a span the
coverage ledger holds that has no bar in it, on Alpaca, each the time before a company took its ticker (companies
that came to market through a merger). 1.64.0 took the ledger's word for evidence and would have asked the feed for
each again. The plan's rule is that a feed is asked again only with evidence.

- **The sweep** (`auditing.Sweep._days`): a held span with no bar at all is kept as an empty span only when something
  says bars should be there: the series' own daily bars with volume (its finer bars, for a missing daily span),
  another feed of the same market holding bars there, its ticks, or a pull that was cut off over it. Without that it
  is no finding: the ledger holds the time before a ticker existed, and rightly nothing is there.
- **What 1.64.0 kept on the ledger's word** (`Sweep._ledger_only`, at the start of every run): judged again by that
  rule. One that something speaks for stays, now saying what; the others are closed, with why.
- **Never asked on that word** (`auditing.repulls`): a feed's run does not ask again for an empty span whose only
  evidence is the ledger's, from its next run on, before any sweep has judged it.
- Nothing stored is touched by any of this, and no coverage: findings only.

## 1.64.0 (2026-11-18)

The fetch cache, the auditors, and the auditors' plugin (plugin API 2.4). The user, 2026-11-15: "when the integrator
goes to a source and pulls the data, make sure that the data is stored in a temporary cache (not on ram), until it can
be read in to the symbol database. leave the data in cache until an auditor goes over the symbol and checks the data
bit by bit to ensure it was copied successfully, auditors should run if a symbol is updated, or periodically"; "make
sure that auditing goes over all symbols to look for consistency issues or broken connections that fragmented data";
"For the integrator, there needs to be a plugin called auditor and it will manage the configuration of auditing data";
and 2026-11-18: "an auditor plugin, for auditing sources and maintaining the integrity of the feeds; for the
integrator". liminal-integrator 1.13.0 runs the auditors and answers their page, plugin-integrator-auditor 0.1.0 holds
their options, and the charts' Plugins view draws the page.

- **What a feed is asked for is on disk before the database has it** (`spool.py`, `storage/pulls.py`). One thing asked
  of a feed is a pull (its kinds: bars, future, market_day, grouped_day, download, recheck), with a folder of its own
  beside the main file, `cache/<feed>/<pull>/`. While one is open, every good answer of the feed's HTTP client goes
  into it as it arrives (gzip, with the sha256 of the body as received; a real `requests` session is read in pieces,
  never whole in memory first) and is read back from there; and every bar write (`upsert_bars`, `save_grouped_day`,
  `save_market_day`) writes its rows to a rows file first and loads the database from that file read back. What
  reaches the database is what the cache holds. Only 2xx bodies are kept, and an answer is recorded by its path, never
  its query (a key can be a query parameter). A pull knows whether its pages ended or were cut off (a stop, an error,
  a crash). Its ledger is three new tables of the main file, made when it is opened: `pulls`, `pull_files`,
  `audit_findings`. A pull that asked and got nothing to store leaves nothing behind.
- **Where nothing changes**: outside a pull (the live recorder's writes), in a store in memory, in a process that
  reads only, and with `LIMINAL_FETCH_CACHE=off`, everything is written as before; with the switch off a feed's run
  neither settles nor audits what an earlier one left (the auditors' own process takes it).
- **The copy audit, bit by bit** (`auditing.audit_pull`, `audit_pulls`). A closed pull's rows files are read back, each
  held against the sha256 kept when it was written, and their rows compared with the feed's `bars` inside SQLite,
  every key and every value, by the comparison the write itself uses (`IS`). A bar stored as the file has it passes.
  One a later write replaced passes only when the version the file holds is the one kept as replaced
  (`bar_revisions`, replaced at or after the file was stored). A bar of the file that is not stored is put in from
  the file (never one moved out as another instrument's: `archived_bars`), unless the policy says to flag only. A bar
  stored with other values is a finding: nothing stored is overwritten, coverage is never withdrawn, and the feed is
  asked for it again. A pull that passes has its files removed, or kept the days the policy says; one with a finding
  keeps them as its evidence. What it proves is that the load from the cache was exact, not that the feed's data is
  right: the second-feed audit (`audit.py`) and the sweep look at that.
- **The ledger is no history.** A pull that passed and of which nothing is kept is counted (`cache_verified`: pulls,
  files, bars and bytes verified, today and in all) and forgotten at once: a feed updated all day makes tens of
  thousands of pulls a day, and the main file holds only what is on disk and what is still to be judged. One that was
  cut off stays until the sweep has seen its span held, or a week; its finding is then judged by the span kept with
  the finding itself.
- **One thread of one process at a time audits or recovers a feed's cache** (the claim `cache:<feed>`, and among a
  process's own threads its place in `auditing._held_here`): a feed's run auditing the pull it just closed, the
  auditors' process and a run at the cap never read and remove the same files at once. A pull whose feed is being
  audited elsewhere is left to that process, and one audited meanwhile is not audited twice. A claim the database
  would not take back just then is owed and given back at the next chance; what the audit found stands either way.
- **When**: as each pull closes and after a symbol's fetch, the symbol still claimed (`Audit when a symbol is
  updated`); before a run asks anything, for what earlier runs left (`Collector._settle_cache`, a minute at most); and
  in the sweep.
- **What a crash left** (`auditing.recover`): a pull left open by a process that is gone is closed as cut; a rows file
  written and never loaded is loaded then, without asking the feed again, and its span recorded as held. A file
  loaded late is the answer of the moment it was written: it puts in what is not stored and replaces only what was
  stored before it; a bar stored since (the live recorder's, a later run's) stays, a bar moved out as another
  instrument's is not brought back, and its audit takes a bar stored since for the newer word, not for a difference.
  A pull open in this process, on whatever thread, is never taken for a dead run's (`pulls.live`): it is live until
  its ledger says how it ended.
- **The cap** (`auditing.room`, `Pull.room`): unverified cache at its cap makes a new pull wait: what waits is audited
  at once, and if that frees too little the run stops without a strike against the feed (`spool.CacheFull`). It is
  looked at inside a pull too, each time the pull has written 64 MB more, before a page is written and before the
  HTTP client asks for the next: a long gap ends at the cap as a cut pull, what it loaded is audited and its files
  go, and the next run goes on from there. Unverified data is never deleted; files kept as a finding's evidence do
  not count toward the cap. A process that caches nothing keeps no cap, whatever an earlier run left on disk.
- **When the cache itself fails** (`spool.CacheFailed`: the disk, a path, or its ledger in a database busy past its
  wait): the run stops without a strike, this machine's fault and not the feed's; nothing is stored that the cache
  does not know of, and an answer still on the wire is let go. What ended a pull is what its caller hears: a rate
  limit's strike is never replaced by the ledger's own trouble. Why a pull was cut is kept without the query of any
  address (the HTTP library's errors repeat the whole address, and a key may be in a query).
- **Files that cannot be removed** (on Windows, one another program holds open) are not said to be: the pull stays in
  the ledger with them, and `auditing.tidy` tries again. A feed's run tidies the cache before it asks anything, so
  kept files go when their days are over with the sweep off, too. A pull whose audit fails holds up no other,
  however many fail; a database that is busy ends the pass at once.
- **The sweep** (`auditing.Sweep`): every watched series of every feed in turn, from where the last run stopped, for
  the minutes the policy gives a run, each under its symbol's claim. A series' visit audits what waits of it in the
  cache; keeps a cut-off pull as a finding until the span it asked is held; and, for each frame the feed sends
  (second, minute, day), looks for every session day older than three days inside the spans the coverage ledger says
  were downloaded. A day without bars is a hole only with evidence that bars should be there: the series' own daily
  bar with volume, its own finer bars, another feed of the same market, its ticks, or a cut-off pull over it. A held
  span with no bars at all is an empty span. Each round also reads one month of each series whole and puts it to
  `sources/data.py`'s rules (`integrity`, `assess`: called from here for the first time); what a storage rule catches
  (duplicate, malformed, missing, out of session) is a finding. A finding's life: open, asked, then closed (the bars
  came) or absent (asked for and confirmed not there: remembered, not asked again).
- **Re-pulls** (`auditing.repulls`, `Collector._repull`): a feed's run asks again for what the auditors found missing
  or differing of the symbol it is on, a few spans a run (the policy's `Re-pulls per sweep`), inside its request
  budget like any other ask.
- **An audit asked for** (`storage/requests.py`): a request of the new kind `audit` (`AUDIT`), for a symbol, for every
  series in turn (`EVERYTHING`, "*") or for what waits in the cache (`WAITING`). It never merges with a symbol's fetch
  request.
- **The auditors' plugin** (`auditing.AuditorPlugin`, an `IntegratorPlugin`; `AUDITOR` in its module;
  `registry.auditors()` and `auditor()`, one for an app; plugin API 2.4). It holds the options and nothing else:
  audit when a symbol is updated (on, off), sweep every (24h, 6h, 7d, off), minutes per sweep run (10, 5, 30, 60), on
  a mismatch (repair, flag), keep verified payloads (0, 1, 7, 30 days), cache cap (20, 5, 50, 100 GB), re-pulls per
  sweep (5, 0, 20). Its `settings` are the auditors' `Policy` (`Settings.plugin("auditor")`); a value that is none of
  an option's choices is a `ConfigError` naming them. The auditors are the library's and run without the plugin, on
  the same defaults, so auditing is never off because a package is missing. A command sets its process's policy once
  it knows its settings (`auditing.set_policy(auditing.policy_of(settings))`).
- **For the page** (`auditing.overview`): the policy, the cache by state and size against its cap, the last sweep and
  where the round stands, and the findings.
- **For a plugin, nothing has to change.** A plugin written for 2.0 to 2.3 loads unchanged and no plugin's floor
  moves. A feed's source is unchanged too: the cache sits in the HTTP client and in the store's write functions.
- The open pull is each thread's own (`spool.current`, a `threading.local`): a feed's run on another thread does not
  write into it.
- What "a later write" is rests on the moment each write was stored under, this machine's clock: a clock set back
  between a write and the one that rightly replaced it can make the replacement look like a difference. The cost is
  a finding and one more ask of the feed, never a change to what is stored.
- An independent review of the write path (2026-11-18, in two passes) found the late load replacing newer bars, two
  processes, then two threads of one, able to audit one pull at once, the cap kept with the cache off and not kept
  inside a pull, a ledger's failure taken for a crash, and files said removed that were not: each is fixed above,
  with a test that fails without its fix.
- 102 new tests (`tests/test_fetch_cache.py`, `tests/test_auditors.py`): no process started and no network.

## 1.63.0 (2026-11-18)

An External API tab and an Internal API tab for every plugin and every app. The user, 2026-11-16: "for all apps, and
all plugins, there should be an external api tab, and an internal api tab, the internal api is for interfaces the
plugin shares with the rest of the app, the external should be all the SDKs/APIs the plugin associates with"; and
2026-11-17: "a second tab for all plugins which describe the internal API like structure that the app code can work
with", "all plugins all apps", "all plugins are middleware", "even for other plugins", "and then the app object code".
The External API tab is the API tab's cards, as they were: the SDKs, APIs, commands and data a plugin or an app
associates with. The Internal API tab is what it shares with the rest of the app, made from the object itself so that
it cannot go stale: for a plugin, the middleware it is (its base, and so the standard interface it implements, then
its own hooks, and who uses each); for an app, what its code calls on its plugins and what it offers them. The library
gives both to every app and every plugin; liminal-platform 0.32.0 draws them for its plugins and for itself, and the
charts, the integrator and the login take them up in releases of their own.

- **For a plugin, nothing has to change.** The plugin API stays 2.3 and no plugin's floor moves. A plugin that says
  nothing new has both tabs all the same, each hook of its own listed as a change until it says it only reads. What
  it may say, all optional, are plain tuples of words on its class, read by name (`sources/plugin.py`, on `Plugin`):
  `READ_HOOKS` (its hooks that only read, beside its bases'), `SERVICE_HOOKS` (those other plugins ask through the
  app), `ASKS` (`(plugin, hook[, why])`, the plugin `""` for whichever offers the hook), `KEEPS` (`(variable, about)`:
  what it keeps through its login beside its keys; a property where the variable is named after the plugin) and
  `INTERNAL_NOTES` (a few lines of at most 400 characters). The rule a read is held to: it changes nothing here, at a
  provider or in what is kept through the login; it may run a command that reads and ends, ask a provider without
  spending its requests or quota, or change only what its page shows until the app restarts. A hook that spends them
  (a scan, a publisher's `read`), costs money, starts a program that keeps running, opens a listener, takes an
  `accept_*` argument or is one of its JOB_HOOKS is not one. liminal-platform 0.32.0 asks a read as one (`reads_of`):
  noted so in who talks to whom and kept out of its log. A package's own test holds it to its words:
  `pytest.importorskip("liminal_libs.internal")`, then `assert internal.problems(PLUGIN) == []`.
- **What the bases say**, for every plugin built on them. READ_HOOKS on `FeedPlugin` (every hook but its scan),
  `PublisherPlugin` (`moments`, `calendar`), `AssistantPlugin` (`build`), `MachinePlugin` (`present`, `status`,
  `instances`), `Firewall` (`wanted`), `Admin` (`processes`), `WslDistribution` (`check`, `services`),
  `DatabasePlugin` (`builtin`, `probe`, as agreed with the session of that file), `AiPlugin` (`refresh`), `ModelServer`
  (`choose`, `log_of`, `models`, `serving` and `models_of`, the last two its SERVICE_HOOKS) and `Harness` (`command`,
  `ask_models`). A harness asks every model server's `serving` and an instance's `models_of`, a model server the
  others' `serving` (for a port). `KEEPS`: a firewall's groups, a model server's instances, what a harness's Use...
  keeps. `INTERNAL_NOTES`: a WSL plugin's rename of its install kept as its DISTRIBUTION_VAR, a model server's keys
  each a secret pair of its own, the server's key a harness reads to open a window. Docstrings of their own for
  `Firewall.rename_label` and `status`, and for `WslDistribution`'s `present`, `status`, `run` and `instances`: base
  hooks every firewall and WSL plugin shows.
- **The cards without the registry** (`liminal_libs/apis.py`): the External API's module (`Api`, `Area`, `Call`,
  `Link`, `as_dicts`, `facts_of`, `problems`, `dead_links` and the rest) lifted out of `sources/apis.py` unchanged, into
  a module of the standard library alone, so an app that holds no plugin (the login, the charts' front) says what it
  associates with without loading the registry, pandas or numpy. `sources/apis.py` imports every name back, the same
  objects: no plugin changes an import.
- **A plugin's Internal API** (`liminal_libs/internal.py`, the standard library alone). `internal_of(plugin, ...)`
  reads it as middleware: what it sits on (its `apis`), the library class it is built on and that class's line up to
  `Plugin` (`builtOn`, `chain`), and so the standard interface it implements, each base's HOOKS a layer, nearest first
  (`standard`). Then each hook, the standard ones first and its own after them: its arguments, its docstring's first
  sentence and the whole of it, the layer naming it, whose code answers it (its own, a library class's or the
  contract's default), whether it only reads, is a job (and can be cancelled), a tab's page or asked twice (its
  `accept_*` arguments), and who uses it here: the app's code (in the app's words), other plugins (its SERVICE_HOOKS,
  with the plugins whose ASKS name it), both, or whoever asks it by name. Then how the app is asked for it, what it
  asks of the others (with what each finds here), the settings it reads and keeps through the login, what the app
  reads of it by name, its tabs, its steps and its notes. Nothing of a plugin is called or evaluated: its hooks are
  looked up as they are declared (a property is never read), only its declared words, `keys`, `plan_vars`, `options`
  and `apis` are read, each in its own try, and the answer is plain JSON. Beside it: `problems(plugin)`; `reads_of`
  (what an app asks as reads: never a job, never a read that takes an `accept_*` argument); `answered_by`, the
  contract's rule of whose code answers a hook, which `Plugin.gives` now asks, so that `interface()`, the frame's
  `ask`, the tab and `App.askable` follow one rule; `answers`, `declared`, `kind_of`, `tabs_key`, `line_of`, `doc_of`
  and `args_of`.
- **An app's Internal API** (`app_internal`), its object code's side: what it calls and reads on its plugins of each
  kind (`App.CALLS`, `App.ATTRIBUTES`) and the words it is asked in; what it offers them and other apps (`interface()`'s
  eight methods, the login it lends, and for code `plugin_internal`, `internal` and `own_apis`); its routes (its own,
  then the frame's: `FRAME_ROUTES`, and `LOGIN_ROUTES` while it inherits a login); the login it includes, with the
  switch that turns it off; the apps it links and its plugins. `literals_in` and `route_problems` hold a table of
  routes to the code that answers them (a test's).
- **The frame** (`apps/app.py`): `GET /api/app/apis` answers an app's own two views (`app`, `internal`, `apis`,
  `apiFacts`), and with `?plugin=NAME` an attached plugin's (404 for any other name), so that every app gives its
  plugins' structure to code with no code of its own. New on `App`: `apis`, `ROUTES`, `LINKED`, `CALLS`, `ATTRIBUTES`
  and `INTERNAL_NOTES`; `api_facts`, `routes`, `askable` (read as declared: nothing evaluated), `known_plugins`,
  `call_words`, `plugin_internal` (kept per object and per tabs asked, `KEPT_INTERNAL` at the most), `internal` and
  `own_apis`. `interface()` and `GET /api/plugins` are unchanged.
- **The drawing** (`ui/static/internal.js`): `LiminalInternal.html(d, opts)` for a plugin, a list of them (a plugin of
  several feeds) or an app; `tabs(list, shown, label)` for a page with no tabs of its own; `style()`, its own styles on
  the themes' variables, so that a page without liminal.css or apis.js draws it alike; `KINDS`. A plugin's tab leads
  with what kind of middleware it is and how it is called, then its base's standard interface layer by layer, then its
  own hooks, each saying who uses it. It asks nothing of any server, and what was opened is kept in this browser under
  `liminal:internal:folds` (600 at the most). `apps/tabs.py`: a plugin's page has Main, External API and Internal API,
  and the page's own ids, whatever their case, are main, external, internal and api (an old `#name/api` opens External
  API).
- **Tests**: test_apis_lift, test_contract_words (the whole library imported, every base with HOOKS held to the
  words), test_internal, test_internal_app, test_ui_internal and test_ai_internal (a harness's asks find the model
  servers, a model server's `serving` and `models_of` name who asks them, and what each keeps), on stand-ins, under
  1.62.0's `no_outside` guard.

## 1.62.0 (2026-11-18)

The base under six AI plugins, and root access for the Linux plugins. The user, 2026-11-16: "claude i need 3 plugins
for inference serving local models on the platform, :: lama.cpp, ollama and vLLM, i also need 3 harness plugins for the
platform :: OpenCode, Aider, and Continue"; "they will be classified as AI plugins"; "the plugins manage the services,
the app can be started @ boot like a service, ports can be configured via the plugin, the plugin should report
conflicts". And 2026-11-17, of the Linux firewall that could not be read inside WSL: "the plugin needs to be able to
handle permissions if required"; asked how a password is typed, "A field on its page"; "(enable / disable)", "but
only if required". The six plugins themselves are packages of their own, built on this release.

- **What every kind of instance shares** (`liminal_libs/instances.py`, plain: the standard library and `layout`):
  the names lifted out of `storage/instances.py` (`NAME`, `Refusal`, `variable_of`, `credential_variables`,
  `clean_name`, `clean_title`, `is_local`, `listening`, ...), the same objects from either place, and `Store`, one
  value kept through a login, which the databases' `Instances` now is. `secret_variable` names one secret of an
  instance as a pair of its own.
- **AI plugins** (`machines/ai.py`): `AiPlugin` under `MachinePlugin`, `SECTION = "ai"` and a `GROUP`
  ("inference", "harness"). Valid without its software. Install, update and uninstall from the page as confirmed jobs
  that can be cancelled, with the size and the licence said first, every archive pinned by size and sha256 (or said
  as not checked), into the plugin's own folder: `app/<pin>/` and `app/CURRENT`, the install in use never rebuilt over
  itself. A start and an install exclude each other. Its status never raises. No pair of Liminal's reaches a child it
  starts (`dropped()`: every declared variable, and `LIMINAL_*`). `Setting`, `Package`, `Installed`, `Outside`.
- **Model servers** (`machines/modelserver.py`): `ModelServer` and its instances (run here, found here, remote),
  kept through the login as one value (`LIMINAL_AI_<NAME>_INSTANCES`), a key as its own pair. Start and stop as a
  windowless child the plugin owns; start at boot (a logon task on Windows, a systemd user unit on Linux); a port for
  each instance with its conflicts said (another program by name and pid, WSL's relay, another instance, a Liminal
  app's port); this machine only by default, shared only when asked twice and with a key; plain http to another
  machine asked twice. `serving` and `models_of`, services other plugins ask through the platform; the Models tab, Try
  it. **`python -m liminal_libs.machines.launch serve`**: what a task or a unit runs, supervising itself, ending 0
  with its words in the log when there is nothing it can ever start.
- **Harnesses** (`machines/harness.py`): `Harness`: Use... an instance of an inference plugin (asked through the
  platform), Open... in a folder (a terminal window on Windows, else the lines to paste), Command...; a stopped
  instance or a folder on another system's drive refused.
- **What they stand on**: `machines/children.py` (a child a plugin owns: no window, a job object on Windows that ends
  it with the platform, Ctrl+C then the end, its log rotated and cleaned of secrets; `stream` for an installer's
  lines, its timeout and cancel ending what it started; `shown` for lines to paste, a secret's value never among
  them), `console.py` (the window holder and the Ctrl+C helper, the standard library only), `machines/endpoint.py` (a
  model server asked over http, bounded by bytes and time), `machines/download.py` (https only, redirects to listed
  hosts only, resumed, checked, cancelled; unpacking that refuses a way out), `machines/gpu.py` (nvidia-smi read,
  never for a status), `machines/autostart.py`, `machines/uv.py`. `Output.cancel()`, `.cancelled`,
  `.wait_cancelled()` and `Cancelled` (`machines/terminal.py`): a job's Cancel. `windows.quote` doubles all five of
  PowerShell's single-quote characters. Six makers' marks in `ui/static/icons.js`: llamacpp, ollama, vllm, opencode,
  aider, continuedev (llama.cpp's and OpenCode's drawn anew, not traced from their brand files).
- **Root access for the Linux plugins** (`machines/linux.py`): `Shell.run(..., password=)` hands the user's typed
  password to `sudo -S -k -p ""` on standard input, once, never in an argument, the environment, a log, an answer or
  an error's words; `PasswordRefused`. `needs_password` reads sudo's own listing for a rule that runs the command as
  root without a password (sudoers' `listpw` makes `sudo -n -l <command>`'s exit code say nothing of that).
  `grant`, `revoke`, `granted`: a narrow grant for the group `liminal`, helpers root:liminal 0750 under
  `/usr/local/libexec/liminal/<name>/` and one sudoers rule naming exactly them with no arguments, checked with
  `visudo -cf` before it is put in place, with a take-back helper so that turning it off needs no password. Never
  `NOPASSWD: ALL`.
- **Tests**: a shared guard, `no_outside` (`tests/conftest.py`), that fails a test which starts a process, opens,
  binds or listens on a socket, or looks a name up for real, and that the code's own `except Exception` cannot
  silence. Every new test file asks for it. The release was reviewed area by area; every finding was reproduced
  before it was fixed, with a test that fails without the fix.

## 1.61.2 (2026-11-16)

A request is in the picture before it is answered. Found in Ubuntu: the platform's test of who talks to whom failed
once with a `KeyError` for the request it had just made.

- The frame noted a request (`traffic.record`) after its answer was written. Whoever asked `/api/traffic` on the
  heels of that answer (a page's next request, a test's next line) could be answered first, by another thread, and
  not find it. `_answer` works the answer out, notes the request, then writes the answer. The time noted is the
  app's own work; the writing of the answer is no longer in it.
- An `api()` that returns something else than `(status, data)` or `(status, data, headers)` is the app's fault like
  any other: logged and answered 500. Before, the connection was dropped without an answer.
- The test slows the note, so that the order decides and not the timing: with the answer written first the request
  is missing every run, with the note first never.

## 1.61.1 (2026-11-16)

A refused write is answered, not lost with its connection. Found while the suites were run on a busy machine: one
test of the platform's and one of the login's read a `ConnectionAbortedError` where a 403 had been sent.

- **`web.drain(handler)`**, and `web.refuse(handler, status, body)`: a request's body is read and dropped before an
  answer that does not use it. The frame answered a write it refuses (another site's page, another host's name, no
  write header, no such route) without reading its body. Closed with that body unread, or still arriving, a
  connection is reset on Windows, and the client reads no answer at all. `local_only`, `from_this_app` and the
  frame's own refusals read it first, at most `MAX_BODY` of it; a body larger than that is still refused unread.
- Every app of the frame has it: the platform and the login whole, the charts' data API and its front (the
  integrator's page is the data API) for what the two guards refuse. Their own refusal of a write without the app's
  header is the charts' to read first, in its commit beside this one. What a page of an app's own sends was never
  refused, so nothing a page does changes.
- The one place in the frame that already dropped a body by hand (a login that could not be made here) calls
  `web.drain`.
- The test sends a refused write in two parts and sees nothing come back before all of it is there: without the
  body-drop it fails every run, on any system. Sixty large refused writes follow, none of whose answers is lost
  (left unread, some are and most still arrive: that alone passes more often than not).

## 1.61.0 (2026-11-16)

Database plugins: a plugin for each engine, each holding its instances (plugin API 2.3; the user, 2026-11-15: "for
the integrator i need plugins for each type of database and in each plugin can setup either new databases or
connections to existing databases using many different types of IP or IPC methods. each instance in the plugin has
it's own configuration how it's shared, ports, permissions etc"). The contract, and what keeps to it; the engines'
plugins are packages of their own (SQLite's, DuckDB's and MongoDB's first, then PostgreSQL's and MariaDB's).

- **`storage/databases.py`, `DatabasePlugin`**: the integrator's fifth kind of plugin (`DATABASE` in its module;
  `registry.databases()`, `database(name)`, `database_menu()`; attached by the integrator's frame with its other
  plugins; one plugin an engine). It names its engine, the methods its instances are reached by and what they can
  hold, and answers its hooks: `builtin` (its own instances), `open` (a connection to one), `probe` (one opened for
  reading and asked what it is), `make` (a new database made) and `own_port` (the port of one of its own changed).
- **An instance** (`storage/instances.py`, `Instance`) is a database the plugin made or a connection to one that
  exists, with its own configuration: what it holds, where it is, the method it is reached by (`file`, `helper`,
  `socket`, `tcp`), its port, who else may attach and how far (`Share`: a suite by its name on a database, reading
  only or writing too), and on a server the role used there, its grants and whether it signs in.
- **With nothing set, nothing changes.** A plugin's own instances are today's databases, opened as today. What the
  user adds is kept through the plugin's login as one value under the plugin's variable (`SQLITE_INSTANCES`), never in
  a file of this software's. A sign-in is two more pairs through the login (`<PLUGIN>_<INSTANCE>_USER`,
  `_PASSWORD`): never in the value kept, never in what a page is given.
- **What an app asks of a plugin** is the same for every engine: `instances`, `state` (how each is, nothing opened,
  nothing started; another machine is never asked by a status, and whether a port of this machine listens is
  remembered three seconds, since a port that does not takes the whole wait to say so), `test`, `new_database` (a file in the data folder's
  `instances/`, or at a whole path, never over a file that is there; on a server a database with a role of its own, the
  administrator asked once and not kept), `connect_to` (kept only when it answers; its sign-in given with it, and
  forgotten again when it does not answer), `share`, `set_port` (a port is the instance's own: changed only to one
  that answers), `forget` (what it holds stays), `set_credentials`, `status` (all of it, for a page). The port an
  instance has when none is given is the plugin's to say (`default_port`: the engine's usual one, or the one its own
  server is kept on).
- **Off this machine only when asked twice**: an address that is not this machine's is refused with the argument that
  accepts it (`Refusal.accept`: `accept_remote`, a page's second confirmation), and is then kept only with TLS and a
  sign-in.
- **A change is the owning system's alone** (`mounts.owner_only`). The suite inside WSL reads what Windows keeps
  (asked of it through the link) and changes nothing of it; a path kept on Windows is named where its drive is
  mounted (`mounts.here_path`), or said to be elsewhere.
- **The link's helper keeps to the shares** (`storage/link.py`, `instances.SharePolicy`). The process at the other end
  says who it is with its hello (its suite's name on a database: `linux::Ubuntu`). A file is then opened as the share
  on its instance says: for reading and writing, for reading alone whatever was asked (an attached file too), or not
  at all; an instance the user added and shared, outside the data folder, becomes one of the folders the helper
  opens, and one shared with nobody stays closed to it. With no share set on an instance it is opened as before, so
  nothing changes until one is set. A library from before this one does not say who it is: let in where no share is
  set, refused where one is.
- **Conformance**: a database plugin is written for 2.3, names one of the engines, methods of one family (a server's
  are addresses, a file's are not), what it holds, its variable among its `options`, and gives `open` and `probe`
  (`make` when it offers New database). A plugin written for 2.0 to 2.2 loads unchanged.

The helper loads the plain half alone (`storage/instances.py`): it starts in 0.42 s as before, where the plugin
contract with it would have made it 0.52 s.

## 1.60.0 (2026-11-16)

What building the eBPF plugin found in the library's eBPF layer (plugin-platform-ebpf 0.1.0; the user, 2026-11-14:
"we need an ebpf api plugin, that shows the difference between windows and linux capabilities as well as basic
functionality"), and eBPF's mark.

- **A net watch on Linux starts.** `ebpf/scripts/net.bt` probed `kprobe:udp_v6_sendmsg`, a name no kernel has (the
  kernel's is `udpv6_sendmsg`, net/ipv6/udp.c), and bpftrace refuses a probe it cannot attach: every watch with net
  ended at its start, in bpftrace's words. It probes `udpv6_sendmsg` now, and a test pins the scripts' kprobes to the
  kernel's own functions.
- **Test signing is read, not guessed.** Without an administrator `bcdedit /enum {current}` prints its refusal where
  the entry goes and exits 1, and `WindowsRuntime.why_not_here` read that as test signing off. Test signing comes
  first from this boot's own start options (the registry's `SystemStartOptions`, which any user may read, carries
  `TESTSIGNING` while Windows runs in test-signing mode): what is in effect now, which is what decides whether a
  test-signed driver loads. bcdedit only where that value cannot be read, and its words only when it answered (exit
  0, the `{current}` entry printed). The facts gain `test_signing_source` ("boot options", "bcdedit" or "unknown") and
  the words say where it was read; a read naming no source says nothing of test signing, and where Secure Boot alone
  settles the verdict its head says so ("Secure Boot is on, which keeps test-signing mode off"). Where the registry
  answers, bcdedit is not run at all. The key, the value and both patterns are named constants
  (`BOOT_OPTIONS_KEY`, `BOOT_OPTIONS_VALUE`, `TESTSIGNING_OPTION`, `BCD_TESTSIGNING`), so the tests pin the script's
  lines whole and try the patterns on what Windows gives. The comparison's points say the same: this boot's start
  options need no administrator, bcdedit's setting does.
- **A Windows watch says a source lost under it.** `NpcapEtwWatch` read on after Npcap's capture ended (an adapter
  removed, a read failing) or its ETW session ended (stopped from outside, the consumer failing), and answered reads
  with nothing new, as a quiet machine would. It now says which in `error`, in the source's own words, and stops, as
  `BpftraceWatch` does when bpftrace ends, so its caller can start another. `EtwConsumer.running` (the session up and
  its consumer still reading) and `EtwConsumer.error` (why it ended while still wanted: stopped from outside, or the
  consumer failing, by ProcessTrace's own status or an exception) are new. A stop of the watch's own is never said as
  a loss: the sources are read before the stop flag, which a stop sets before it closes anything, and tests pin both
  the guard and that order.
- `icons.js`: `ebpf`, eBPF's bee (its makers' mark), for the eBPF plugin.

## 1.59.0 (2026-11-16)

Codebase: the repositories an app is made of, the code in them, and how much of it is which language (the user: "i
want to add another functional class called codebase, which has the associated repositories (git/svn/,,,) if there
are, also the code base, and stats like how much is rust %, javascript %, etc..."; "this class will be added to all
the 'apps' just like connections"; "it will also say how far it is behind the remote").

- **`apps/codebase.py`, `Codebase`.** Every app of the frame holds one (`App.codebase`, as it holds its `Traffic`) and
  answers it at `GET /api/codebase`. Nothing is read until a page asks. Then it is read in a thread of its own, kept
  ten minutes, and read again with `?fresh=1`.
- **The repositories**: every working copy in the workspace (git, Subversion, Mercurial), and the folders the app's
  own code runs from when they are in none. Each says its branch, the commit checked out, its remote, what is changed
  and not committed, how far it is ahead of and behind the branch it follows there, and when that remote was last
  asked. A remote's address is shown without the name or token someone put in it, in a tool's own error words too. A
  tool that is not installed is said, and the code is counted all the same.
- **The code**: a git repository's tracked files, any other folder's files, their lines and bytes by language.
  Vendored and generated files, binary files and very large ones are counted apart, in no language.
- **The shares** are of the bytes of code and markup. Prose (Markdown) and data (JSON, TOML, YAML) are listed with
  their lines and have no share.
- **Nothing reaches a remote by itself.** How far behind is what each working copy knew when it last asked.
  `Codebase.fetch()` (`POST /api/codebase/fetch`, a write: the app's own page alone) runs `git fetch` in every
  repository that has a remote and reads everything again; the page asks for it only on the user's click.
- **`ui/static/codebase.js`**, `LiminalCodebase.mount(dataEl, sideEl, {get, send, confirm})`: the same picture in
  every app. One bar by language for the workspace and one for what the app itself runs from (a language keeps its
  colour whatever its rank; slivers under half a percent are drawn together and still named in the table), the
  repositories with filters (behind, changed, this app's), every language, and a picked repository's details. It asks
  again only while a reading or an asking of the remotes is under way.
- `icons.js`: `branch`, Codebase's entry in an app's list.

Measured with Python's profiler on a workspace of 49 repositories (1,327 files, 317,172 lines): 4.0 s of a 4.25 s
reading was waiting for its 196 git commands one after another, 0.2 s reading the files. The repositories are now
read six at a time: 0.9 s.

## 1.58.1 (2026-11-16)

On Windows a path is judged as it really is (`mounts.foreign`, `mounts.foreign_on_windows`). Found by the review of
1.58.0's GeoIP guard, in the check that claims, the link and the stores stand on:

- **A link into a share is the share's.** Windows judged a path by its spelling, so a junction or a link from this
  machine's disk into `\\server\share`, or into WSL's `\\wsl.localhost`, passed for this machine's own. Its links are
  followed first now, as Linux's judgement always did.
- **A local path spelled the long way is local.** Every path beginning `\\` counted as a share's, a local folder
  written `\\?\C:\...` or `\\.\C:\...` too, so work on this machine's own files so spelled was refused
  (`owner_only`), and such a database was not opened. `mounts.plain_windows` reads those spellings as the plain paths
  they are; `\\?\UNC\server\share` is still a share, and a volume named by itself is asked of Windows.

## 1.58.0 (2026-11-16)

GeoIP files on another system's drive are that system's. For the suite run a second time inside WSL, each system's
platform keeps its own state on its own disk, its GeoIP files among them: inside WSL, `layout.data_dir()` is Ubuntu's
own, so the Linux platform installs a copy of its own there. This guards the day a data folder does sit on another
system's drive, through 1.56.0's `mounts`.

- **`geo.foreign(path, what)`.** Why `what` is not done from here with the GeoIP files at `path`, a file or their folder,
  in `mounts.owner_only`'s words; "" when they are this machine's. The path is another system's when `mounts.foreign`
  says so: WSL's /mnt/c, a share, a network drive. On a library without `mounts`, and when the check cannot say, ""
  (as before).
  - It asks about the path as it really is, its links followed. On Windows `mounts` judges a path by its spelling, so a
    link from this machine's disk into a share would have passed for this machine's own.
  - On Windows, an extended-length spelling (`\\?\C:\...`, `\\?\UNC\server\share`) is judged as its plain one: `mounts`
    takes any path that starts with `\\` for a share's.
- **Never read from here.** `GeoIP.find` passes over such a folder without listing it, and `GeoIP(path)` refuses a file
  there (`GeoError`). A reader an install let go never reopens such a copy either (`GeoIP._reopen`). A file mapped from
  here would keep that system's own update from replacing it, so the files there count as none installed.
- **Never installed there.** `install_mmdb` refuses before anything is read or written, and the folder is not even made.
- **The World Wide Web tab** (`WorldView.elsewhere`).
  - It looks nothing up and offers no install. The globe's note says why, and says an install is offered with a data
    folder on this machine's disk only when the plugin names a download.
  - An install asked anyway, its licence accepted, is refused in words before anything is fetched.

Reviewed before landing: three lenses (correctness, the agreed rule, whether the tests can fail), each finding put to a
skeptic. The ten that held (six distinct, all minor) are put right here, and the Windows firewall's API card in its
0.6.1. Two lie in `mounts` itself: its Windows branch judges a path by its spelling, and takes any `\\` for a share's.
This release follows links and plain spellings itself, and leaves `mounts` to its owner.

Tests: `tests/test_geo.py` and `tests/test_world.py`, with `mounts.foreign` stood in for and with a library without
`mounts`; the data folder a firewall's view judges; a reader reopened after a failed install; a link into another
system's drive (a symbolic link, or a junction on Windows).

## 1.57.0 (2026-11-16)

The link: a SQLite file on another system's drive is opened by that system alone (the user: "keep the databases
(sql/duck/etc) in the same place find a way to link linux to windows using an SSHFS or networking arrangement that is
safe and secure"). The suite is to run a second time inside WSL on Windows' own databases. A mount cannot be made safe
for that: SQLite's locks and its write-ahead log's shared memory do not cross from Windows to Linux over /mnt/c, SSHFS
or a share, so two writers, one on each side, would corrupt a file. On a system with its own files nothing changes.

- **`storage/link.py`.** `connect(path, ...)` is now the one way a SQLite file is opened. A file on this system's own
  disk is opened as always. A file on another system's drive (`mounts.foreign`) is opened by a **helper** on that
  system, a process of this library started there (`python -m liminal_libs.storage.link`, through WSL's interop) and
  spoken to over its standard input and output: no port, nothing listening, nothing installed, and it ends with the
  process that started it. There is no falling back to opening such a file directly, and on Linux an audit hook
  refuses a direct `sqlite3.connect` there from any code in the process, a plugin's included.
- **The connection** it gives is shaped like sqlite3's for what this software uses: execute, executemany,
  executescript, cursors read in batches, transactions, `with conn:`, rows by name, ATTACH with the file named as its
  own system names it, `set_trace_callback`, `interrupt`. `frame(sql, conn, params)` reads a query into a DataFrame
  on either kind; `time_limit(conn, seconds)` ends a read that runs too long on either kind.
- **What crosses the pipe** is plain data and nothing else (numbers, text, bytes, tuples, lists, dicts): neither end
  rebuilds a class from it, and what is not plain is refused by the one who gave it before a byte is sent. Each
  request has an id and each connection its own thread in the helper, so one long query does not hold up another.
- **What the helper opens**: files inside the data folder and the ledger folder it was started for, an ATTACH
  included. It makes no file with VACUUM INTO and no backup: those are the work of the system that holds the files.
- **A helper that ends is never started again** by the process that lost it. Its temporary tables, attached files and
  open transactions ended with it; the process says so and is started again by whoever keeps it running.
  A helper that never answers is said with its own last words (a library there from before the link has no such
  module), not as a link that "is gone".
- **A file's layout is its own system's** (`storage.common.owners_layout`, `Behind`). A store brings a file's tables
  up to its software when it opens it, and a process that reads only (LIMINAL_READONLY) did so too before it was
  sealed. From another system that would add a column under the software running where the file is, which writes its
  rows by position. So there the layout part of an open runs query-only: a file that is up to date opens untouched, one
  that is behind is said to be (what it lacks, and that its own system brings it up to date), and no database is made
  on another system's drive. A process that reads only opens such a file read-only as well as sealed, and a file it
  attaches (a feed's ticks) is opened the same way. This covers the main file, the feeds' files and their ticks, the
  datasets' files, the agencies' file and the claims' tables.
- **One clock.** Every answer of the helper carries its clock. What a linked process stamps into a file is stamped by
  the clock of the system that owns it (`storage.common.utc_now`), and `link.clock_off(path)` says in words when the
  two clocks are more than a second apart, so nothing is fetched then. (On the PC this was built on, Windows' clock
  ran 9.1 s fast: its time service had never synchronized, while Ubuntu kept time by NTP. WSL's clock was pulled
  between the two, which is the ten-second jumping seen while the suites ran there.)
- **The user's saved settings**, the keys among them, are read from the system that holds the database
  (`config.UserEnvironment.linked`): asked of the helper by name, kept nowhere on the other side.
- **A log of its own.** Beside a database on another system's drive a process writes `liminal-<system>.log`
  (`liminal-linux.log`), never the file the other system appends to.
- **The Linux plugins work on any Linux**, a WSL distribution included (the user: "wsl and firewall linux should always
  work under linux, if wsl prevents or misses some capability this should reflect in the plugin").
  `machines.linux.why_not_native` refuses only a machine that is not Linux; `wsl()`, `wsl_generation()`,
  `systemd_runs()` and `wsl_table(kind)` say what a distribution under WSL is and lacks, shown as an "Under WSL" table
  (`Admin.machine_tables`). What stays ruled out is a platform on Windows reaching into a distribution from outside.
- **For the tests** the same protocol runs inside one process (`Link.loopback`), and `LIMINAL_LINK=loopback` sends
  every file through it, so a whole suite can be run over the link.

Found by running the charts app's suite over the link, and fixed:
- A price read out of a table (a numpy.float64, which sqlite3 binds as the number it is) went onto the pipe as
  numpy's own class; the helper reads plain data only, so the link ended for the whole process. A value of a class
  built on a number, text or bytes now crosses as what it holds. A numpy integer, which sqlite3 would store as eight
  raw bytes, is refused in sqlite3's words.
- `close()` came back before the helper had closed the file, so the caller found it still open, its last writes
  still in its log.
- The helper was started without the flag that keeps a console window away on Windows (`proc.no_window`).
- A request made on a link that was just ending could wait for ever.

## 1.56.0 (2026-11-16)

Claims: who is working on what, for every process on one database, whichever system it runs on (the user: "If i run
integrator on both sides, there cannot be any conflicts, so if one symbol is being operated on, the other integrator
would have to operate on another symbol"). The suite is to run a second time inside WSL on Windows' own databases.
Until now a run was kept to itself by a lock file naming a process id, which only that process's own system can look
up: from the other system a held lock named a process that "did not exist", so it was taken over and both sides
fetched the same feed. Nothing was claimed by symbol at all. With one installation on a database nothing changes
but the fixes at the end.

- **`claims.py`.** A claim is a row in the main file's `claims` table, taken in one write transaction, naming its key,
  the instance (`windows::NEPTUNE`, `linux::Ubuntu`; `LIMINAL_INSTANCE` to say it outright) and the process holding it.
  A holder of the same instance is judged by its process, as a lock file's was. One of another instance is judged by
  its heartbeat (every 20 s): silent for 90 s it is challenged, and taken over only when still silent 45 s after that.
  A computer asleep wakes both sides with old heartbeats at once; a single check would have let each take the other
  over. Every take has a token one higher than the last, so a holder taken over while it slept finds out before it
  writes on. Every time is the database's own clock, read in SQL (WSL's clock jumped ten seconds, back and forth,
  while the tests ran there). A claim taken `shared` is held by every process of its instance that asks shared.
- **This process's claims** by the database's path: `take`, `release`, `holds`, `held`, `mine`, `lost`, `present`,
  `hold`/`try_hold`/`let_go`, `exclusive`, `feed_runs`. One connection and one heartbeat thread, there only while the
  process holds something; everything is given back at exit. A process that reads only (LIMINAL_READONLY) takes none.
- **Keys.** `feed:<name>` (one run per feed), `symbol:<asset>:<ticker>` (shared inside an installation, held against
  the others), `plugin:<name>` (a plugin's own fetching), `publications`, `live`, `history`, `post`, and
  `process:<instance>:<pid>` (a process at work that holds nothing else says so).
- **The switch-over.** A hold takes the lock file that kept its key until now as well, because processes started
  before this release look at lock files alone. On another system's drive (`mounts.py`: Windows' drive seen from WSL,
  a share) a lock file cannot be judged: none is written there, and one that is there without a claim is held.
  `proc.run_holders` stays the lock files'; `claims.feed_runs` says the runs of every system.
- **A symbol being fetched is claimed** (`Collector._step`, after the skips, so a symbol left alone costs no write;
  the daily-first sweep and `download_bars` too). One another installation is working on goes back to the end of the
  run's line and is taken again after a wait that doubles from 15 s to two minutes; still held ten minutes on, it is
  left for the next run. A symbol opened in the chart waits the same way.
- **A run taken over stores nothing more**: before each page is stored the run asks whether its feed is still its own.
- **A reset takes back only what a process that is gone left** (`claims.gone`). `fetch_requests` and `fetch_queue` rows
  name the installation that took them (`instance`). `request_reset` and `queue_reset` used to reset every row being
  worked on, whoever was at it; `queue_reset(mine_alone=True)` is for the caller whose claim makes the rows its own
  (a feed's run and its bars). `queue_gone(rows)` is the same judgement for a page.
- **One pass per plugin at a time** (`Runner.plugin`): a second is stopped, saying who is at it.
- **The publications' reader, the live recorder and a series' build of derived frames** are held against every
  installation: `publications.take_reader`, `live.take_locks` (its `Locks` carry the hold; `holds_locks` asks the
  claim), `derive.take_lease` (the lease names its installation).
- **Work that is the files' own system's** is refused from another, in words (`mounts.owner_only`, `NotHere`):
  starting MongoDB, moving a plugin's documents between engines (`stores.settle`), the closed months' copy
  (`stores.history_due`). Two systems doing these would undo each other's work on files the other has open.

Fixed on the way:
- Two asks at once each found no open request for a symbol and each made one (`request_put` now takes the write lock
  from its start).
- A plugin's pass starting reset the rows a feed's run of the same plugin was fetching (shown as waiting while they
  were being fetched).

## 1.55.0 (2026-11-16)

The firewalls' World Wide Web tab (`machines/world.py`), the second phase of what the user asked for on 2026-11-14: "so
for the firewall's both are going to get a 'world wide web view' that shows the globe and the routes incoming all
traffic, as well as monitoring port traffic stats". The Firewall base has the tab, so plugin-platform-firewall-windows
0.6.0 and plugin-platform-firewall-linux 0.8.0 carry it. liminal-platform 0.27.0 draws it, and 0.28.0 offers the GeoIP
licence as a second confirmation.

### The tab

- **Watching only while you look.** Each ask (`WorldView.touch`) starts a `traffic.Watcher` around the capture at the
  adapter of this machine's way out, or keeps it going (`default_capture`: TCP and UDP, IPv4 and IPv6, the headers
  alone). It stops 20 s after the last ask (`TIMEOUT_S`), on `stop()`, and for good on `close()`, the plugin's detach. A
  capture that cannot start is tried again `RETRY_S` (15 s) later at the soonest.
- **The page.**
  - The globe: each public network a place, with its kind (allowed in, unanswered in, out), its count, bytes and ports,
    and its route to home. The local network's peers are summed apart. At most `MAX_DRAWN` (300) places are drawn, the
    rest summed as "more".
  - The busiest ports here, charted over ten minutes on the view's own monotonic clock, so a wall clock set back does
    not freeze them.
  - Tables of the busiest ports here, the places and the ports elsewhere.
- **What counts as allowed in.** An inbound attempt not answered yet, or never judged, is drawn unanswered, never
  allowed in.
- **Places stay on this machine.** The GeoIP file is mapped only while the tab is watched or asked. Once watching stops
  it is let go, and opened again at the next ask; `describe()['geoip']` keeps what it was, with `open: False`.
- **Home.**
  - The place the user set (`LIMINAL_HOME_PLACE`, `lat,lon[,label]`, read through the plugin's login).
  - Else where the GeoIP file puts this network's public address, asked of the name servers the plugin names
    (`dns.public_address`). Their names are made absolute, so no search suffix is sent.
  - A value that is no place is shown back cut short (`SHOWN`), and decimal commas are refused in words.
  - Without nslookup, the page says which package to install.
- **Inside WSL** (`under_wsl`). The page ends with what WSL changes for the tab:
  - the distribution's own adapter is watched, and Windows' own traffic is the Windows firewall's tab's;
  - under WSL's NAT networking nothing comes in from the internet but through Windows (mirrored networking aside);
  - under WSL 1 nothing can be watched at all.

  It reads `machines.linux.wsl`, so it says nothing until the library's check stops refusing a WSL kernel. That is
  the next release.

### The GeoIP file's install

- **Only on the user's word.** `Firewall.world_geoip(accept_licence=False, log=None)` refuses (`LicenceRefused`, naming
  `accept_licence`) unless its argument is exactly True. The platform asks that as a second confirmation, with the
  licence's words (`geoip_form`).
- **As a job.** `Firewall.JOB_HOOKS = ("world_geoip",)`. Its progress goes to the platform's panel (`log`), with the
  bytes and the percent at most every `PROGRESS_S`.
- **One deadline for all of it.** `geo.INSTALL_S` covers both months' fetches, with their connections, TLS, headers and
  redirects, and the body.
  - The download runs on a thread of its own. When the time is up, or on detach, its sockets are shut, its reads
    refused, and nothing is put in place.
  - A connection still being made ends at its own timeout (`READ_S` at most).
  - A file read to its end is checked and put in place on this machine, and waited for `LOCAL_S`. Past that the install
    says so, and the file still goes in place if it passes.
- **https on every hop, from the plugin's own host.** `fetch_url` follows a redirect only to the same host over https,
  at most `MAX_REDIRECTS` times. Any other redirect is refused (`RedirectRefused`) before the new address is asked
  anything, and the address the answer came from is checked again.
- **Which file.** This month's file, else last month's on a 404. A month's file is never downloaded twice.
- **Readable later.** `geo.install_mmdb` makes its temporary file with the mode every file of the process gets (0644
  less the umask), not 0600, so a file installed while the platform ran as root is read by its user later. A refusal
  by another account's folder says whose it is (POSIX).

### The right to capture

- **On Linux.** `capture_help` advises the right only when libpcap's own words say it is missing, and only to a
  platform that is not root. The right is CAP_NET_RAW alone, for the platform alone, in one of two ways:
  - under systemd, `AmbientCapabilities=CAP_NET_RAW` in its system unit (`liminal-platform-boot.service`);
  - `setcap cap_net_raw=ep` on a copy of Python that is its own (`python3 -m venv --copies`, `chmod 0750`). Under OpenRC
    or another init, this is the only way.

  It is never given to the system's Python: a venv's `python` links to it, and a hard link to it is the same file. It
  is never CAP_NET_ADMIN, and never a password. As root, a container or a security module is named. Any other failure
  is said in libpcap's own words, without the library's hint.
- **On Windows.** Npcap installed for administrators only is never opened by a platform that is not an administrator
  (`capture.npcap_admin_only`, `capture.administrator`, `ADMIN_ONLY`): opening it would raise a UAC prompt at every
  retry. The page names the installer's option to untick, or running the platform as an administrator.
- **"No adapter holds"** is said as such: Npcap not bound to that adapter, or libpcap's adapter gone or in another
  network namespace. It is no longer said as "connect to a network".

### The Firewall base

- `TABS = (Tab("world", "World Wide Web", "world", 2.0),)`. `HOOKS` gains `world` and `world_geoip`, and `keys` the
  home setting.
- A plugin names its own `GEOIP_URL`, `GEOIP_LICENCE`, `ATTRIBUTION` and `PUBLIC_DNS`. The library names no outside
  host.
- `world_view(make=True)` is the tab's view. `make=False` gives the view there is, or None, and never makes one; the
  plugins' API cards read it that way. A subclass makes its own capture in `make_world_view()`.
- `settings_changed()` reads the home anew. `detach()` ends the watching for good.

### The Linux plugins and WSL

The eBPF runtime's words follow the user's rule of 2026-11-15: "wsl and firewall linux should always work under linux,
if wsl prevents or misses some capability this should reflect in the plugin". The Linux runtime is for the Linux the
platform runs on, a WSL distribution it runs inside included. `machines.linux.why_not_native` decides; the next release
changes it, and this one still refuses a WSL kernel.

### Tests

- `tests/test_world.py` (45 tests): the page from the traffic counted; watching started by an ask and stopped by the
  timeout and the detach; the install's licence, deadline, redirects, progress and fall-back month; the GeoIP file let
  go; the home; the right to capture on each system and init; the platform's own Python told from the system's; WSL's
  table.
- `tests/test_capture_world.py`: Npcap's administrators-only option, read from a stand-in registry.
- `tests/test_geo.py`: the installed file's mode (POSIX only).

No test captures, downloads, asks a name server or starts a process.

## 1.54.0 (2026-11-15)

The pieces that the firewalls' World Wide Web and Filter tabs, the eBPF API plugin and trapdoor are built on. The user,
2026-11-14:
- "so for the firewall's both are going to get a 'world wide web view' that shows the globe and the routes incoming all
  traffic, as well as monitoring port traffic stats";
- "there needs to be a way to 'filter' (another tab) that allows you to monitor send and receive traffic, especially
  traffic that is out of the ordinary";
- "the filter allows (uses ebpf) tracking one off connections";
- "classifying traffic as potential advert/monitoring sites that track users, etc";
- "we need an ebpf api plugin, that shows the difference between windows and linux capabilities as well as basic
  functionality";
- "trapdoor will monitor all processes".

Nothing here runs until a plugin asks: every watch stops itself after its viewing timeout. The tests start no capture,
session or process. The design is the shared notes' firewall-world-filter-DESIGN.md.

### Tabs and the globe

- **A plugin's own tabs (`apps/tabs.py`).** `Tab(id, title, hook, every)`, and `MachinePlugin.TABS`, none by default.
  liminal-platform 0.27.0 shows them after Main and API, and asks the hook, a read, every `every` seconds while the tab
  is shown.
- **The globe (`ui/static/liminal-globe.js`).** It uses world-atlas 2.0.2's countries in `ui/static/vendor/world/`: ISC,
  with Natural Earth's public-domain data. `LiminalGlobe.draw(el, spec)` returns `{update, destroy}`.
  - It is the charts app's orthographic globe, with great-circle arcs from each origin to this machine: allowed,
    unanswered (dashed) and outbound.
  - It draws a legend, a parallel table, and the DB-IP attribution link when given.
  - It updates in place, takes the theme's colours, and stays still under reduced motion.
  - Origins with no usable place are counted and tabled, never dropped.
- **Letting charts go (`charts.js`).** `LiminalCharts.forget(prefix)` lets go of charts a page no longer draws.

### Places and packets

- **GeoIP (`geo.py`).** `GeoIP` reads a local .mmdb (DB-IP Lite City, the user's choice) through maxminddb,
  memory-mapped.
  - Its answer cache is bounded in entries and in size, with each place's text cut short.
  - Local and private addresses are never looked up, including IPv4-compatible and NAT64 forms.
  - `install_mmdb` unpacks a download atomically, within byte, member and time bounds. It checks the file is a sound
    GeoIP file and keeps one copy.
  - maxminddb is the `geo` extra, and part of `dev`.
- **Capture (`capture.py`).** UDP and IPv6 as well as TCP/IPv4.
  - Each packet carries its wire length, its direction (this machine's addresses are read again every 30 s) and its TCP
    flags.
  - It keeps the payloads names need: a DNS message up to 512 bytes, and a TLS ClientHello up to 2,560 bytes, joined
    across segments.
  - The DLL folder is added once per process.
  - On Linux, a read waits on the capture's socket, so a stop is seen within its timeout.
- **Traffic (`traffic.py`).**
  - `TrafficBook` is bounded per port and per remote group: bytes, packets, new connections and unanswered inbound
    attempts.
  - `Watcher` is one thread that stops after its viewing timeout.
- **Names (`names.py`).** `NameBook` ties DNS answers and the TLS server name to the address they name. An answer is
  believed only after its own question was seen, and a server name only on the way out.

### Classification and the baseline

- **Classification (`classify.py`).** It reads the free lists the user chose: EasyList and EasyPrivacy with their
  sections, hosts and domain lists such as hagezi's, and AdGuard's companies.
  - The labels: ads, tracking, analytics, telemetry, cryptomining, email, cname-tracker, social, cdn and hosting.
  - Lists are read in linear time and bounded memory, and a name's length is measured before and after IDNA mapping.
- **The baseline (`baseline.py`).** `Baseline` is one small SQLite file per plugin.
  - After 30 minutes of learning it flags what is "unusual for this machine while Liminal was watching": a new peer,
    port, program, country or network; a one-off; a spike.
  - It never says "malicious".

### eBPF

- **`Runtime`.**
  - `LinuxRuntime` uses bpftool through sudo -n, on native Linux only, never Windows or WSL. It reads, and builds the
    load, attach, detach and unload commands a plugin confirms first. Liminal's pins go under /sys/fs/bpf/liminal_.
  - `WindowsRuntime` is read-only: eBPF for Windows' services and programs, and why it cannot run here. Every build is
    test-signed pre-release, and Secure Boot and memory integrity refuse it.
- **`CAPABILITIES`.** The Linux-against-Windows comparison.
- **`Watch` and `make_watch`.**
  - `BpftraceWatch` on Linux runs the scripts in `ebpf/scripts/`: net, process and file. They are low-rate, and the file
    watch can be narrowed to one process tree. The process stops with the watch.
  - A stop during a start waits for it, so a source that was opened is always closed.

### Windows

- **`EtwConsumer` (`machines/etw.py`).** A real-time ETW session through advapi32 and tdh, covering Kernel-Process,
  -File, -Network and -Registry.
  - It runs unelevated through Performance Log Users.
  - Its queue is bounded, and the session is stopped on every path and at exit.
  - Sessions are named after the process that owns them, with its start time. `reclaim_stale_sessions()`, or the next
    start, stops one that a killed platform left behind.
- **`NpcapEtwWatch` (`ebpf/windows_watch.py`).** The user's choice for Windows until eBPF for Windows is signed. Npcap
  covers the network (UDP and payloads included), joined with ETW for the program, as per-flow events.

### Housekeeping

- `MachinePlugin.SECTION` now names "virtualization" and "os" too, after liminal-platform 0.26.0.
- Package data includes `ui/static/vendor/world/*` and `ebpf/scripts/*.bt`. `.gitattributes` keeps the map files byte
  for byte.

## 1.53.1 (2026-11-15)

What running every suite on Linux found (the user: "check for bugs in the linux environment"), the suite being cloned
into WSL's Ubuntu. Nothing changes on Windows.
- **A socket file left behind no longer stops a host.** A host that ended without closing its socket (killed, a crash)
  left the file, the next host's bind failed on it, and that read as "another host answers": no fetcher came up until
  the file was removed by hand. `host.py` now removes a socket nothing listens on before binding, under a lock so two
  hosts starting at once cannot take each other's. A live host's socket is left alone.
- **A host started off Windows gets a session of its own** (`Host.start`): a terminal closing, or a Ctrl+C there, ended
  the host with no chance to secure its data. On Windows it was already detached from its console.
- **A database is named as its system compares paths** (`host._digest`): the case was folded everywhere, so on Linux
  two databases whose paths differ only in case shared one host. Windows' names are as they were.
- **A unit file's words are written as systemd reads them**: new `systemd.py` (`word`, `command`, `assignment`). The
  integrator's unit wrote its paths bare, so a data folder with a space in its name split `Environment=LIMINAL_DB=` in
  two (liminal-integrator 1.9.1 uses it).
- **A plugin of a kind the registry does not file is left out and said so**, where it used to end discovery for every
  plugin: a bare `IntegratorPlugin` was read as a provider and had no `live`.

## 1.53.0 (2026-11-15)

A linked app is reached at its own address (the user, 2026-11-14: "linking vs including the objects, is so that parts
of the code can be executed remotely, and connected through the icon bridge"): `Binding.reachable()` asks this
machine's port for a loopback address as before, and another machine's over the network (a TCP connection, at most
`REACH_SECONDS`); `Binding.host`, and the port of an address without one is its scheme's (443, 80). Nothing is started
from a link (`module` kept for the callers of 1.9-1.51, unused). `forward(keep_cookies=)`: only the cookies a
linked app owns travel to it (nothing else of the browser's reaches an app that may be on another machine); an https
address is reached over TLS, its certificate checked; the connection is waited for `CONNECT_SECONDS` at the most
(another machine that never answers no longer holds a request for good), the answer as long as it takes.
liminal-charts links the platform with them.

## 1.52.0 (2026-11-14)

Four ports, nothing started in the background, the login an object of the app that inherits it (the user: "i only want
ports for liminal-login ; liminal-platform ; liminal-charts ; liminal-integrator"; "never provide ports for anything
else"; "don't start any of the applications in the background"; "the platform and integrator inherit the login function,
they are separate login instances, class vs object"; "login doesn't point to anything except the app that inherited it";
"linking vs including the objects, is so that parts of the code can be executed remotely, and connected through the icon
bridge").

- The login an app inherits is included, not linked: `App.LOGIN = True` (and `LOGIN_VAR`, "none"/"off" turning it off)
  makes one object of the login class for that app when first asked (`login_object()`, `make_login()`; `LOGIN_CLASS`,
  liminal-login's `LoginApp` by default, made with `superclass=` the app itself: the one thing it points to). Its page
  and API answer under /login/ at the app's own port (`serve_object(handler, obj, method, path)`: the request answered
  by an object held in this process, its checks and cookies its own), its tray at /api/trays, the sign-in until the
  browser is signed in (`signed_in` asks the object). `App.stop()` closes it. A class that still says `LOGIN_URL`
  (1.46-1.51) inherits the login all the same, its address unused.
- Gone: `bound_login`, `start_login`, `login_url` and `binding.start_app` (nothing in the library starts an app any
  more; an app linked is reached at its address, one that does not answer is not running). `Binding`, `forward`,
  `tray_of`, `wait_for` stay for links.
- `App.start` refuses a port another program holds (`PortTaken`, an OSError naming the port and the app) instead of
  taking a free one; 0 (any free one) is still a test's.
- The firewall's list of the framework's ports (`machines.firewall.APP_PORTS`) is the four apps' alone: the integrator's
  login at 8796 is gone.

## 1.51.0 (2026-11-14)

A machine plugin says which section of the platform's list it is drawn under (the user: "classify the cloud plugins under the 'cloud plugins' section which should be on the far left"): `MachinePlugin.SECTION`, "machine"
by default (this machine's own software and hardware) or "cloud" (a cloud provider's account). liminal-platform 0.25.0
draws the Cloud plugins section from it, and the six cloud plugins set it.

## 1.50.0 (2026-11-11)

The API cards fold (the user: "on the APIs organize each API description so that they can expand and contract so they
take up less space, kind of like the firewall"). `LiminalApis.html(apis, facts, {fold: true})` draws each API as one
line: a round (+) as the firewall's groups have, its maker, name, form and version, and how much of it is used here
("11 of 17 parts, 17 of 27 calls used here"). Opened, the line shows what the card showed (the maker's pages, what the
API is about, its facts), and its parts and its calls are two more such lines inside it. Every line is closed at first,
but a plugin's only API, which is open; what was opened or closed is kept across a redraw and in this browser
(`liminal:apis:folds`). They are `<details>`, so a keyboard opens them as a mouse or a finger does. Without the option
the cards are as they were (the charts app's Plugins view asks for none); `LiminalApis.folded` is one API's line.

## 1.49.9 (2026-11-11)

A take-over's consent is bound to the addresses it was given for (Azure's builder: a take-over whose own write
failed kept its consent, and a later pass wrote over whatever the record held by then). `take_over` keeps the addresses
`holds` names (`addresses_in`; refused when it names none), and a pass writes a taken host only while its record holds
exactly those (or already this network's); anything else voids the consent and the host is asked about again. The
state file keeps each take-over's addresses; a list from before carries no consent over.

## 1.49.8 (2026-11-11)

A take-over is single-use (the third round of checks): used up once its write lands, the host then the keeper's own
by its own rule. A host taken out of the setting where no settle saw it (the plugin disabled, the platform stopped, its
domains unread, its key unset) and put back later holding another address is asked about again, never overwritten on
the old consent. settle's docstring says what it covers.

## 1.49.7 (2026-11-11)

What the re-verification of the audit's fixes found in the Dynamic DNS keeper:
- Take over… is asked twice: `Keeper.take_over(fqdn, accept, holds)` refuses (`TakeOverRefused`, its `accept` the argument
  `accept_take_over`) unless accepted exactly true, saying what is dropped; `take_form()` carries that second
  confirmation. A take-over sets the record at once and drops every address it held, so it is never made on one yes.
- `Keeper.settle(hosts)` lets go of every host it holds that is not among the plugin's whole setting (called by the
  serving platform's plugin once the account's domains are read): a host taken out of the setting where a settle sees it
  comes back as not its own (a removal no settle saw: 1.49.8).

## 1.49.6 (2026-11-11)

`machines.rest`'s HTTPS takes nothing from the environment (the audit's note): no `~/.netrc` credentials added to a
request, no proxy or CA bundle from its variables. A request goes as the plugin made it, straight to the API's host.

## 1.49.5 (2026-11-11)

`RestClient.pages`: a next page on the same host with its port named (Azure's price list writes
`prices.azure.com:443`) is the same host, followed as before; only another host is refused. A pass stopped just
before a write says so as the host's result ("not updated: the plugin was detached: nothing written").

## 1.49.4 (2026-11-11)

What the DigitalOcean plugin's builder asked of the Dynamic DNS keeper: the stop is checked again just before a write
(after the address is asked again), and `known()` lists every host it holds as its own or was let take over, so a
plugin lets go of hosts no longer in its settings, a change made while it was not running too.

## 1.49.3 (2026-11-11)

The audit's three small findings in `machines.rest.RestClient`: a vendor's "slow down" reader is never asked of a 5xx (a
write that may have been done is not sent again); a list's next page given whole on another host is not followed, so
it is never sent the client's token; an error's raw words are cut after the secrets are taken out, so a secret across
the cut never shows.

## 1.49.2 (2026-11-11)

What an audit of the cloud plugins found before any key went in (session 87405e6a: eight reviewers, a skeptic per
finding):
- `machines.ddns.Keeper` changes only what is its own: a host with no A record (made), one already pointing at this
  network or at the address it set last (kept current, after a restart too: `state`, a JSON file the plugin names), and
  one the user let it take over (`take_over`, after the page's confirmation). A host holding another address, or several,
  is left as it is and said so (`foreign`, its `holds`), never cut to one address unasked; the page's Take over…
  (`table(take=True)`, `take_form()`) and a confirmed Update DNS now (`now_form()`). Just before a write the address is
  asked again: a stale one is never written back. `run_pass(stop=)` ends before its next write once the plugin detached;
  `let_go` forgets a host.
- `machines.rest`: `scrub` takes out a secret without its surrounding spaces and line breaks and each of its lines (a
  token pasted with its line break, said back in an error's quoting of a header); `bearer` sends a token stripped and
  refuses one holding a space or a line break.

## 1.49.1 (2026-11-11)

What the cloud plugins' builders asked of 1.49.0's helpers:
- `RestClient`: a 403 (a right missing) no longer drops a token, only a 401 does; `throttled(answer)`, a vendor's own
  "slow down" that is no 429 (Route 53's 400 Throttling), waited out like one; `request(data=...)`, a body sent as it is
  (Route 53's XML); `pages(headers=...)` (Linode's X-Filter); the rate limits of reads and of writes kept both (Azure's
  two headers), `clock_of` to say a reset's epoch as this machine's clock time; a vendor's own `...-retry-after` header honored
  (Azure Cost Management's).
- `ddns.Keeper`: `on_pass`, called at the start of each pass (a provider's cache of zones cleared); `table(empty=)`.
- `sources.apis.dead_links`: each page asked once (the addresses of its parts share its answer: Vultr's one-page
  reference was asked 110 times); a page that sends its reader on to an error page (a 200 at .../404 or .../errors/)
  is dead; the docstring says what no status can tell (a site answering every script alike).

## 1.49.0 (2026-11-11)

Plugin API 2.2: what a plugin attaches to (the user: "each plugin should reflect the the API its attached to, and present
links that provide documentation, the plugin interface should more or less contain what it already has, BUT, it should
also expose more of what the API is about"; "please revisit all plugins and the two new ones, and ensure this is true").
- `sources/apis.py`: `Api` (its maker, what it is about, its form, where it is reached, its version, how a caller proves
  who it is, its limits, what costs money, the day its facts were read from the maker's pages), `Link` (the maker's
  pages by kind: documentation, reference, guide, limits, pricing, status, changes, specification, console ...), `Area`
  (every part of the API, covered by the plugin or not) and `Call` (the calls it makes and the others the API offers,
  each saying whether it changes something or costs money); `problems`, `urls`, `facts_of` and `dead_links` (each
  address asked once: the plugins' page check, the only part that sends anything).
- `Plugin.apis` and `Plugin.api_facts()` (what it learned of its APIs while it ran: the server's version, the requests
  left, the last answer, asking nothing to answer it); `interface()` names its APIs.
- `registry.PLUGIN_API` is 2.2. Conformance: a plugin written for 2.2 declares at least one Api, each with a
  documentation link and https addresses only; a plugin declaring apis is written for 2.2; a 2.0 or 2.1 plugin loads
  unchanged.
- `ui/static/apis.js`: `LiminalApis.html(apis, facts)` draws a plugin's APIs on its page (the maker's pages as links
  opening in a tab of their own; the parts and calls it uses first, the rest behind "more of the API", kept open
  across a redraw), its styles on the themes' variables, so the charts app's page draws it alike.

For the cloud plugins (the user: "ALSO i would like to add two new plugins, Digital Ocean and LINODE"; "lets roll
plugins for EC2, vultr, azure and google cloud"):
- `machines/rest.py`: `RestClient`, a JSON REST API over HTTPS for a platform plugin (the plugin names the host and how
  a request proves who sends it: `bearer`, a signer, a `TokenSource` for a token that expires); a rate limit waited out
  (Retry-After), a read tried again, a write never sent twice; errors in words with the secrets taken out; what the
  answers said of the API's limits kept for api_facts (`facts()`); `pages()` for a list across its pages.
- `machines/ddns.py`: `Keeper`, hosts kept at this network's public IPv4 address through the provider's own DNS (the
  plugin reads and sets a host's A record; the name servers asked for the address are the plugin's), `hosts_of`,
  `split_host`, `minutes_of`, and the page's Dynamic DNS table.
- icons.js: the clouds' marks (digitalocean, linode, ec2, vultr, azure, googlecloud).

## 1.48.0 (2026-11-11)

The admin plugins' pages (the user: "the administration plugins don't seem to work right especially linux which doesn't
say anything about startup"). In `machines.admin`:
- An admin plugin is valid whenever it can read what it reads (on Liminal's own): not being elevated (root) no longer
  makes it invalid, so the platform keeps it enabled and in the tray. The rights are a fact beside it (`elevated`,
  `elevation`), and each change asks for them (Windows' prompt, sudo without a password) or says it needs them
  (`rights_words(kind)`, for a service's, a startup's at logon and a boot service's changes).
- Its page is its own tables and their confirmed forms (the platform's status contract): Services the framework relies
  on (Start…, Stop…, Restart…: the form `service`), Startups at your logon (Register… for each app without one, Run… or
  End…, Remove…: `logon-register:<app>`, `logon-startup` with run, end, enable, disable, `logon-remove`; an integrator
  of its own shown only), At boot, before anyone signs in, and The framework's processes. The raw lists move to
  `frameworkServices`, `logonStartups`, `bootServices` and `frameworkProcesses` (the status no longer carries
  `services`, `startups`, `processes` or `boot`, which the platform's page drew as its older admin tables, their buttons
  asking at once).
- A service changed from the page goes through `_service_change` (a subclass asks for the rights there: Windows' prompt
  once Windows wants an administrator); the setup's own starts keep `_service_action`.
- Where a plugin is not for this machine (`not_for_here`), `elsewhere()` says what it does on one it is for: words after
  the reason (the page shows them) and tables describing its sections, sent with no forms.
- `boot_rights()` is `rights_words("boot")`.

## 1.47.0 (2026-11-11)

Boot services for the platform's admin plugins (the user: "also windows and linux admin, need sections for starting
the platform, or an app that inherits the platform object as a service, headless"; "on boot"). In `machines.admin`:
- The apps a boot service may start (`boot_apps`, `BootApp`): the platform (`PLATFORM_APP`,
  liminal_platform.app.PlatformApp, known by its name: found among the classes of the app a plugin is attached to, else
  imported by that name when installed), then each app whose App class inherits it: the app a plugin is attached to,
  and those installed distributions name under the `liminal.apps` entry points (`APP_ENTRY_POINTS`:
  `lab = "liminal_lab.app:LabApp"`), each once by its NAME, its port by its PORT_VAR, else its PORT. `boot_command`:
  `python -m <module> serve --no-browser --port N` (pythonw on Windows; never --until-quiet).
- The startups' own hooks take `at="boot"`: `register(app, "boot", port)` (an app known, a port from 1024 to 65535 no
  other boot service has; made, not run), `startup(app, "start" | "stop", "boot")` and `unregister(app, "boot",
  accept_removal)`, refused until accepted a second time (`RemovalRefused`, its accept `accept_removal`). Their
  refusals are `BootRefused`, an AdminError and a ValueError, so the platform says them as refusals and offers the form
  again. `register`'s second argument is now `at` (`python` the fourth: every caller gave it by name).
- `Startup` carries `at`, `account`, `log` and `port`; the status carries `boot` and, for a plugin making boot services
  (`BOOT_SERVICES`), a table under `tables` (At boot, before anyone signs in: an app a row, the platform first, its
  boot service, the command, its state, who it runs as, its log, its buttons) and its forms under `forms` (Register…
  with the port, Start…, Stop…, Remove… asked twice), each confirmed with the exact change; what else wants a port is
  said beside it, and a clash in a confirmation only when it is the same port. A subclass gives `boot_how`,
  `boot_details`, `boot_rights`, `boot_stopping`, `boot_startups`, `_boot_register`, `_boot_action` and
  `_boot_unregister`. The setup reports the boot services and makes none.
- An admin plugin is valid when the rights can be had as a change asks for them (`may_elevate`: Windows' prompt on a
  desktop, sudo without a password), not only when the platform has them: a non-elevated platform's admin page offers
  its changes, each asking. Without either it is not valid, as before.
- `machines.keep` (new): a command kept running, for a boot task on Windows (Task Scheduler starts a task again only
  when it could not start it, never when its program ends with an error): `python -m liminal_libs.machines.keep --log
  PATH -- COMMAND`, started windowless, again 10 s after a failure, the wait doubling to 10 min while it keeps failing
  and back once a run has lasted 10 min, ended when the command ends well; the command held in a job object that ends
  it with the keeper (ending the task ends the app); its starts, ends and error output in its log, moved aside past 1 MB.
- `machines.windows`: `interactive()` (whether this process has a desktop Windows can ask on) and
  `PowerShell.can_ask()`; `run_elevated` refuses at once, denied, where Windows cannot ask (a boot service's platform,
  on no desktop) rather than waiting for a prompt no one sees.
- `interpreter()`: a Python named as it was given (a POSIX path stays one on Windows).

## 1.46.1 (2026-11-10)

An app's page by its file's own name is the page "/" serves (found by a review of the platform's page asking its login
every minute whether you are still signed in): `/index.html`, or another spelling this machine's file system finds the
same file by (on Windows `/Index.html`, `/index.html.`), was served whatever the sign-in said, so a page opened there
while signed out, told so, reloaded into itself and never showed the sign-in; and `/signin.html` signed in reloaded into
itself, the login saying signed in. Both are now the sign-in until the browser is signed in, then the app's page. An app
that inherits no login serves its page as before. `web.static_target`: the file `static_file` serves for a path.

## 1.46.0 (2026-11-10)

An app that inherits a login app (the user: "we need to shift over to platform, but make sure that the platform inherits
the login app so we can login to platform"; "using secret user"). An `App` naming `LOGIN_URL_VAR` and `LOGIN_URL` (the
platform's: LIMINAL_PLATFORM_LOGIN_URL, 8796; "none" or "off": none):
- `bound_login()`: its login app at that address, or started for it as its superclass when nothing answers
  (`start_login`: `inherited_by` its name, its title and its own address, so the login asks it for its plugins' pairs,
  and the login's file it finds), waited for.
- Its page is `ui/static/signin.html` (+ signin.js) until the browser is signed in there (`signed_in`, asked with that
  browser's login cookies): the login app's page in a frame, its way in the secret user by default; once it says you
  are signed in, the app's page opens. Without a login app answering, the app's page as before.
- `/login/...` passed on to the login app (its answers and its cookies back, the page's origin checked here first),
  writes included; `/api/trays` its tray, for the foot of the app's rail (`trays()`).
- liminal.css: the sign-in page.

## 1.45.0 (2026-11-10)

Where the logins of other domains answer (the user: "make sure every login instance has a database, it's location can
be remote"; "login apps can connect to remote login apps"; "and shift context to the remote execution"; "remote users
are like email format user@remote.domain.tld"; "IPC turns in to encrypted internet comms"): in `apps.scope`,
`remote_url(value)` (a domain alone is its https address; a URL kept as given; over https, http only to this machine),
`remotes_from("host=url;...")` (LIMINAL_LOGIN_REMOTES, `REMOTES_VAR`), and the login file's `[remotes]` section as
`Scope.remotes`, with `Scope.remote_url(host)`: a domain named there answers at its address (assigned here), any other
at https://its.domain (assigned there). `text()` writes the section.

## 1.44.0 (2026-11-10)

Liminal's sign: the `lambda` icon in `ui/static/icons.js` (the user: "the liminal icon is the italic lambda"; "replace
all user icons (login app) with the lambda sign"; then, of the drafts, "M looks good" (the mathematical italic lambda),
"in japanese calligraphy", "with a thick brush, should see hair lines at end of stroke", "now have horse hair brush
strokes"). The mathematical italic lambda's shape written with a simulated horse-hair brush (bristles in a teardrop
held at 45 degrees, the pressure along each stroke, every bristle running dry at its own rate) and traced into one
filled outline with its dry-brush streaks cut out (evenodd), about 4 KB, no font needed. It is the login app's icon
in the connections picture (`apps.traffic.APP_ICONS`, `App.connections`); `user` stays in the set.

## 1.43.0 (2026-11-10)

The login app on its own knows no other app; the app that inherits it says so (the user: "the log-in app should not
point to platform, integrator or charts, it should be standalone"; "when its inherited it can point to it's superclass,
charts, platform, or integrator"). In `apps.login`: `inherited_by(name, title, url)`, the environment an app gives the
login it starts (`LIMINAL_LOGIN_FOR`, `LIMINAL_LOGIN_FOR_TITLE`, `LIMINAL_LOGIN_FOR_URL`: `SUPER_VAR`,
`SUPER_TITLE_VAR`, `SUPER_URL_VAR`); `pairs_wanted(plugins)`, the pairs plugins ask for named by their variables (one
row a pair, a plugin's parts sharing the plugin's row; what the login computed from the registry itself until now);
`PAIRS_PATH`, `/api/login/pairs`. Every `App` answers `GET /api/login/pairs` from the plugins attached to it
(`App.login_pairs`), so charts, the platform or the integrator can each be a login's superclass. `Scope` drops `serves`:
a login's file names no app it serves (an old file's `serves` line is read past, `text()` writes none).

## 1.42.1 (2026-11-10)

Every field typed into looks alike in `ui/static/liminal.css`: email, url, tel and number fields take the border and the
background text, password and search fields have (and the light themes' field color). An email field had neither and
looked missing: the login's first-user form, where a look at the page found it (the user: "Yes, fix them").

## 1.42.0 (2026-11-10)

Touch screens and the on-screen keyboard on every app's page (the user: "let's do an update. I want to support touch as
well as mouse clicking on the interface ... We'll make sure it works across all apps"; "Support for virtual keyboard on
tablets and phones"). A new `ui/static/touch.js` (`LiminalTouch`), which every page loads right after theme.js: whether
the device has a touch screen (`(any-pointer: coarse)`, the class `touch` on `<html>`, kept current); `onLongPress(root,
selector, callback)`, a finger or a pen held still about 500 ms (more than 8 px of movement, a scroll or the lift cancel
it), the click after it swallowed and the browser's own menu and callout stopped there (on a picture inside it too), on
every device (Safari never makes a contextmenu of a long press; Chrome's and Edge's becomes the same long press, once).
While the finger is still down another finger's tap goes through (on the menu it opened, say), and a new tap of the same
kind ends a press whose lift was never seen (what it pressed drawn again under it). The bubble: a long press on anything
with a title (or `data-tip`) shows its words near the finger until the next tap, a scroll or a while, found as a mouse's
hover finds them (a logo or an icon inside a button shows the button's words; a link to nowhere, `href="#"`, has
words), never in an area marked `data-touch-own` (one with gestures of its own: a chart, the globe, a terminal), in a
field, or on a link to an address or a player (their own menus stay); where a long press is served, its words show when
its callback declines it. `.touch-only` and `.mouse-only` words. The keyboard: one name for each kind of field (ticker,
search, number, decimal, signed, secret or key, plain, name, username, email, url, password, code, text, terminal) and
the attributes it sets (`keyboard(kind, more)` for markup, `setKeyboard(el, kind, more)` in place of a kind set before,
`data-keyboard="kind"` filling in only what the field does not say); an API key or a secret is kept out of password
managers (autocomplete off, no capitals, no corrections). A redraw never interrupts typing: `typing(root)` and
`whenIdle(root, fn)` follow the focus and the words a keyboard is composing. No keyboard pops up unasked on a touch
screen: `autofocus(el)` focuses only when the user's last move was not a finger's (typing on the keyboard a finger called
up, its Go or Send included, is still the finger's; a hardware keyboard's keys and a mouse are not), and
`raiseKeyboard(el)` brings the keyboard back from a tap even when the field kept the focus. Room for the keyboard where
it lies over the page (Safari ignores the viewport's interactive-widget): the class `keyboard` on `<html>`, `--vvh` (the
height left above it) and `--vv-top` on `:root`; the field typed in brought into view there, when Chrome shrinks the page
above its keyboard (after a finger's tap only), and for each next field while the keyboard is up. A field in a frame of
the page's own origin (the charts page's bound login) counts as the page's.

`menu.js`: the menus a right click opens on a rail icon open by a long press too, with no wiring in the apps (the
platform's tray, the charts page's rail through panels.js): a contextmenu at the finger (pointerType touch or pen), and
`LiminalMenu.longPress(root, selector)` for other elements. A menu opened so stands beside the finger, its head gives the
pressed icon's own words (its data-tip, else its title), and a scroll closes it only while no finger holds it, a resize
only when the width changes. A page that loads touch.js after menu.js still gets the long press (found once the page is
read), and a page without it a word in the console. A mouse's right click is as it was. `charts.js`: a finger held on a
plot, or a tap, shows the crosshair and the tooltip at its time, the tooltip above the finger; a sideways move scrubs, an
upward or downward swipe still scrolls the page and shows nothing, and the tooltip stays after the lift until a tap
elsewhere or a scroll. `icons.js`: `dataLabel(d)`, a data-state icon's words, and `dataIcon(d, size, {text: true})`
showing them beside it.

`liminal.css`: targets of about 40 px whenever the device has a touch screen (buttons, selects, fields, the switch at
48 by 28, menu items, the charts' ranges and tables, list items, checkboxes at 22 px, room between a row's buttons), the
fields' words at 16 px at least (an iPhone zooms the page into a smaller one), no double-tap zoom on controls, hover
highlights for a mouse only, the bubble, the frame fitted above the keyboard, and below 700 px wide the list, the data
and the specifics in one column, the page scrolling as one and the rail held in view. Larger screens keep their layout.
Two fingers pinch the page over a chart's plot, except on Safari (it knows no `touch-action: pinch-zoom`; a pinch begun
beside the plot zooms there). The charts page's style.css carries the switch's and the menu's rules word for word, as
before (its test compares them): the touch sizes and the menu's hover split from its focus are to be copied there.

## 1.41.0 (2026-11-09)

A firewall's System and Application rules grouped again, by name (the user: "for the windows and linux firewall, lets
have the same system and application and other, but lets group by application under apps or system, try best to
organize under system and applications. Like system has 'core networking' or WSD or UPnP or RA Server or Remote
Assistance or network discovery or ... applications has like starcraft or edge"; "try to group the system by
'services'"). A plugin names the service a System rule belongs to and the application an Application rule belongs to
(`Sorted.name`), and the grouped table gives System and Application a heading per name (`children`, in the order of their
titles; each row's `sub`), which the platform draws with (+) and (−) under its group. A name in any case is one heading.
A rule moved into System or Application keeps its own name there; Other and the user's labels stay single lists. Each
name lists its first rules up to the plugin's limit, so every service and application is listed, where a whole group
listed only its first 100 before.

A rule turned off is listed too, and passed as `(key, Sorted, cells, {"off": True})` so the page shows it dimmed (the
user: "also rules that are turned off should be shown as well").

## 1.40.0 (2026-11-09)

Cursor's mark for its AI assistant (the user: "lets add an AI plugin for cursor"): `cursor` in icons.js among the makers'
marks, drawn in the set's own line and colour from the 2D logomark on Cursor's brand page: the cube's hexagon and the
arrow cut out of it, its top edge level, its tip at the cube's foot, its notch at the cube's centre. The plugin
(plugin-platform-cursor) names it in its `ICON`.

## 1.39.0 (2026-11-09)

Update packages among an install's tasks (the user: "move the update packages on to the TASK"): `update_packages` brings
the install chosen up to date by its family's manager (apt, dnf, emerge) as root, Liminal's own unless the user chose
another, one of the user's own when they did; the Task bar's `{job: "update", title: "Update packages"}` after Stop….

## 1.38.0 (2026-11-09)

An install renamed (the user: "lets allow renaming the o/s on all three plugins"): the Task bar's Rename… (`rename_install`,
its form `rename`, confirmed). WSL 3.0.3 has no command for it (`wsl --manage` moves, resizes, compacts and sets the
user), so the distribution, stopped first when it runs, has its name changed in WSL's own record: its Lxss key's
DistributionName, this Windows user's (`rename_registered`, `Wsl.rename`, `Wsl(rename=)` for a stand-in; each install's
key now in `Installed.key`), then is listed again to be sure. A name WSL takes (letters, digits, dots, dashes,
underscores, 64 at most), not another's. Liminal's own keeps Liminal- in front and the plugin follows it: its
DISTRIBUTION_VAR kept through its login, and `distribution_name` read through the login first. Windows Terminal's
profile and the Start menu's shortcut open a distribution by its id: they keep working, under its old title.

## 1.37.0 (2026-11-09)

The installs' tasks (the user: "instead of chosen, put task and for the tasks lets do terminal, start, pause, stop, allow
selection of the linux install by clicking on the list"; "tasks also include uninstall"). The "<System> installs" table
is chosen from by a click on a row (`select`: {hook pick_install, value}; each row {cells, key}), the selector above it
gone; above it `tasks` for the one chosen: Terminal, Start (`start_install`: a windowless session holds it up until Stop,
WSL stopping one with none: `Wsl.keep_running`, `Wsl(spawn=)` for a stand-in; a paused one's services resumed), Pause
(`pause_install`: each running service but the system's plumbing frozen by systemd's cgroup freezer, `FREEZE_SCRIPT`;
WSL itself cannot pause a distribution; refused where systemd is not the init), Stop… (`stop_install`: `wsl --terminate`,
confirmed) and Uninstall…, each `disabled` where it does not apply now; a paused install says Paused and how many of its
services are frozen (`paused`; `THAW_SCRIPT` thaws them and any other still frozen). `task_forms`: Stop and Uninstall.

## 1.36.0 (2026-11-08)

Every install of a WSL plugin's system, and a selector for them (the user: "for the WSL plugins, they need to list all the
'operating systems' that are installed under the plugin's regime, like ubuntu shows all ubuntu installs, fedora --
installs, gentoo -- installs"; "also the ability to uninstall and select which one to terminal in to"; "basically a
selector for different installs"). `machines.wsl`: `lxss_registry()` reads WSL's own record of each distribution
installed for this Windows user (HKCU's Lxss keys: the flavor and OS version WSL read from its os-release at install, its
Store package, its folder and disk), starting none; `Wsl.installed()` joins it with `wsl --list --verbose` (`Installed`:
name, state, WSL version, default, flavor, OS version, package, folder, disk, size); `Wsl(registry=)` for a stand-in (a
stand-in runner reads none unless given one); `Wsl.unregister`. `WslDistribution`: `owns` (the flavor, else the name or
the Store package: FLAVORS, NAMES, PACKAGES, the system's own name by default), `installs`, the status's table
"<System> installs" first (state, system and version, WSL, default, disk, whose: Liminal's own or the user's),
`installs` in words, one `wsl --list` for both; a selector (`pick_install`, `chosen`: the one picked, else Liminal's own,
never one of the user's chosen for them) whose install the terminal opens into (`terminal`, `terminal_title`, as its
default user; `terminalInto` in the status) and `uninstall` names (`wsl --unregister`, its disk deleted for good; one of
the user's own refused with `UninstallRefused`, `accept = "accept_risk"`, until accepted a second time; its form in
`install_forms`). Nothing else of the user's own installs is asked or changed.

## 1.35.0 (2026-11-08)

A firewall's rules in groups (the user: "for both firewalls, i need to have groups, like system or application and then
unassociated rules not tied to a specific application or system process can be in an other, i can create labels, like
system or application, as well and move the rules in to that"; "just use basic expansion like a (+) to open and close
labels"): `machines/rulegroups.py`. `Sorted(group, why)`: a rule's own group as its plugin finds it (system,
application or other) and why; `key_of(...)`: a rule's key, ten hex digits of what names it; `Grouping`: the user's
labels and the rules moved by hand, kept as one JSON value (`{"v": 1, "labels": [...], "moved": {group: [keys]}}`, under
30,000 characters: an environment variable's room); `RuleGroups(variable, login_of)`: read and kept through the plugin's
login (`Login.save`; nothing kept without a login), `new_label`, `rename_label` (its rules follow it), `remove_label`
(its rules back in their own groups), `move(keys, group, own)` (to a label, to another of the three, or `own`; a rule
moved to its own group is simply back there), `table(base, rows, per_group=, notes=)` (a status table with `groups`,
rows `{cells, key, group, own, why, moved}`, `move` and New label…: what liminal-platform 0.11.0 draws with (+) and (−))
and `forms()` (New label, Rename, Remove). The `Firewall` base offers the hooks `move_rules`, `new_label`,
`rename_label`, `remove_label` over `sorted_rules()` (a subclass's) and keeps them under `<NAME>_GROUPS`
(`GROUPS_VARIABLE`). Nothing of a label or a move changes the firewall.

## 1.34.0 (2026-11-08)

The firewalls' icons the user picked, and libvirt's own: `wallfire` (a brick wall with a flame before it: the user, "use
this icon for linux firewall") and `wallglobe` (a brick wall in three dimensions with the globe behind it: "this one for
windows firewall") take the place of `tuxbricks` and `windowsbricks`, which are gone; `libvirt` (its logo's open tin,
turned, penguins packed head to toe, the lid rolled back on its key: "the platform icon matches libvirt's ... libvirt
has a can of tuna as an icon"), so the libvirt plugin no longer borrows the platform's chip. Each in the set's own line
and colour.

## 1.33.0 (2026-11-08)

The platform's plugins by their makers' marks (the user: "for the icons, WSL, use the distribution's mascot or icon";
"for the firewalls, lets use an icon of TUX penguin or Windows and then convert it to a patchwork of bricks"; "for name
cheap, use it's icon"; "for the AI icons, lets use the respective mascot/icon from the business, logo, etc.."; "for the
docker and kubernetes plugins, use their respective logos"; "same with LXD and hyperv for windows"): fourteen icons in
icons.js, each drawn in the set's own line and colour (currentColor: the theme's) from the mark it stands for:
`ubuntu` (the circle of friends), `fedora` (the bubble and its f), `gentoo` (the g with its hole), `tuxbricks` (Tux, his
body a wall of bricks: the Linux firewall), `windowsbricks` (the four panes of Windows as brick walls: the Windows
firewall), `namecheap` (its N), `claude` (the spark), `openai` (the knot: the Codex plugin's), `grok`, `copilot`
(GitHub Copilot's pilot), `docker` (the whale and its containers), `kubernetes` (the helm), `lxd` (a cube of cubes),
`hyperv` (a machine within a machine). `icon()` draws a name the set lacks as the plug rather than an empty square.

## 1.32.0 (2026-11-08)

Who talks to whom, for an app's connections picture (the user: "the root plugin (platform) will need to visually
illustrate how plugins are connected to each other or to the main app/plugin/icon via IPC, all requests and
interactions should be classified and give the user a way to understand how the app and it's plugins communicate,
visually"):

- `apps/traffic.py`: `Traffic` notes each interaction (from, to, its class, what, how long, whether it went through):
  the latest 400 rows (the same thing said again within 30 s is one row, counted), a count per link (from, to, class:
  how many, how many failed, the mean time, the last), at most 300 links. `CLASSES`: read, change, ask, stream,
  attach, login, process, network. Never a value: a setting by its name, no hook's arguments, a program by its name
  alone, a host by its name or address and port.
- `Traffic.watch()`: the programs started and the hosts reached by an app's code and its plugins' noted, through one
  audit hook per process (`sys.addaudithook`: subprocess.Popen, os.system and the spawns, socket.connect and sendto;
  the name looked up just before a connect names its host). Who reached it is read off the calling code: the innermost
  frame whose `self` is owned (`Traffic.own`: a plugin, the app) or whose module is an owned plugin's package; code of
  no owner (the library alone, a test) is not noted. A link to this machine at a port of the framework's apps is drawn
  as that app.
- `RecordingLogin`: the login as one plugin (or the app itself) is lent it, its reads, listings, policy questions and
  saves noted by name.
- `App`: `traffic`; every request of its page noted (`classify`: a GET reads, anything else changes; a page in a
  browser apart from a program), the plugins attached, detached and asked by name (by whoever asks: a plugin asking
  another through its app names itself); `GET /api/traffic` = `connections()` (nodes: the app, its page, its login,
  its plugins, what they reached; the links; the latest rows); `login_for(name)`; opt-ins `TRACE_LOGIN` (a plugin
  attached is lent a RecordingLogin), `WATCH_OUTSIDE` (watched once served), `READ_HOOKS`, `known_ports()`,
  `plugin_node()`. `interface()` lists `connections`.

## 1.31.0 (2026-11-08)

A setting kept through the login (the user: "i need a way to put my credentials in to the namecheap plugin and allow it
to function"; earlier, "all plugin states/keys will be stored with the associated user", "but we will add login
later"):

- `Login.save(variable, value)`: the setting kept for the signed-in user, its pair named by the variable (None forgets
  it); where, in words. The base refuses (Unauthorized); `EnvironmentLogin` keeps it among the user's environment
  variables (Windows' user Environment key and this process, so it holds at once and after a restart; elsewhere this
  process only); `LoginClient` as a pair of the login app (PUT or DELETE /api/pairs/<pair>).
- `EnvironmentLogin(saved=...)`: an app's choice (the platform's) to read the variables saved after its process
  started too, under the process's own: `saved_variables()` (Windows' user Environment key). Off by default, so a
  plugin's own login and a test read the process's environment alone.

## 1.30.0 (2026-11-08)

A port's way in, checked hop by hop, for the hw-stats plugin's path check (the user: "i have this computer as DMZ host
so, basically the check needs to validate the computer, the router/gateway to the computer, then the internet to the
computer"; "i don't think the plugin is able to check if there is a listener or to listen on the port in order to
validate the traffic"; "if there is a python-tcpdump that would be good ... as a listener"):

- `capture.py`: a tcpdump in Python. Packets on a port watched through libpcap by ctypes, no package: Npcap's
  wpcap.dll on Windows (non-administrators too, unless Npcap was installed for administrators only), libpcap on Linux
  (root or CAP_NET_RAW). `Capture(address, ports)` opens the adapter holding the address (not promiscuous), filters TCP
  on the ports, keeps each packet's addresses, ports and flags (`Packet`; no payload) until `stop()`; `parse` reads
  Ethernet (VLAN tags too), loopback, raw IP and Linux cooked frames, IPv4 and IPv6; `available()`. Packets are seen at
  the adapter, before the firewall decides.
- `netpath.py`: `local_route()` (this machine's address and gateway: GetBestRoute on Windows, /proc/net/route on
  Linux), `ping`, `hops(target, count)` (tracert, else traceroute or tracepath), `kind` (public, private, shared:
  a carrier's NAT, loopback, link-local).
- `ports.Listener`: a port listened on for a while, each connection accepted, noted (`Arrival`) and closed.

## 1.29.0 (2026-11-08)

This network's public address and its ports checked, for the platform's hw-stats plugin (the user: "lets make sure
platform hw stats is able to get the current public IP, and verify that 'selected' ports are available or blocked";
"there should be a way to check ports"):

- `dns.public_address(version, servers)`: the IPv4 or IPv6 address the internet sees, asked directly of the name
  servers the caller names that answer with the asker's own address (an A or AAAA record, or a text record holding
  it); a global address of that version only; (the address, whose answer it was) or (None, why). `dns.query` takes
  the server to ask and nslookup's wait.
- `ports.py`: `parse_ports` ("25, 80 443; 8765-8768", at most 12 at once); `here` (what listens on each port here,
  from a probe's sockets: each program, on every address or this machine's own only); `reach_out` (a connection out
  to a host the caller names, a server answering on every TCP port, its port 80 tried first); `Outcome` (open, closed
  when refused, blocked when nothing answered, failed; listening, free), `tally`, `listening_pids`. The services
  asked (the servers, the port testers) are the plugin's to name, as every outside host is a plugin's.
- `WindowsProbe.program_names` and `LinuxProbe.program_names`: a process's program by pid (a port's listener named).

## 1.28.1 (2026-11-08)

Docker inside a stopped WSL distribution never seen running is said as not asked (`{"asked": false}`): the
platform's page had read "installed: no" for an engine nobody asked about, since asking would start the
distribution; once seen, its version is kept and said with the distribution stopped.

## 1.28.0 (2026-11-08)

The services of a WSL distribution (the user: "lets have, in the WSL plugins, a breakdown of the major services running, the 'scanning function' should be capable of using openrc or systemd to look for init type and differentiate between somewhat trivial processes and major services that are online"): `machines/services.py`, one script run as root (the init
system found and PID 1; systemd's units with the memory of those running, OpenRC's `rc-status --all`, SysV's
`service --status-all`; the processes), `parse`, `classify` (major: Docker, databases, web, mail and DNS servers, SSH,
VPNs, the firewall, Liminal's apps; other: shown with its own description; the system's own: counted and named in a
note) and `Scan.table` for the platform's page; `WslDistribution.services` (a hook; the status carries the breakdown
and its table). Scanned only while the distribution runs, kept 30 s. A status, the Docker check or the instance list
no longer starts a stopped distribution (the plugin lifecycle: nothing runs that nobody uses); Docker inside is said
as last seen.

## 1.27.0 (2026-11-08)

The Linux plugins are for a native Linux machine only (the user: "the scope of linux administration is only on
native linux O/S"; "it's not for administrating WSL instances"; "Yes, firewall too"): `machines.linux.why_not_native(what)`
says why the machine the platform runs on is not one (Windows, macOS, a WSL distribution by its kernel's release or
WSL's variables), "" on a native Linux machine. `MachinePlugin.not_for_here()` ("" by default) is honored first by
the base status and by the Admin and Firewall bases' status and setup: the status says `applies` False with the
reason (`not_here_status`; the key documented since 24a07f6), the setup changes nothing, the platform offers no setup.
plugin-platform-admin-linux 0.4.0 and plugin-platform-firewall-linux 0.3.0 use them.

## 1.26.1 (2026-11-08)

A WSL plugin's setup says each step before it runs (the user: "Yes, do it" to a line when each step starts, so quiet
steps do not look stuck): `wsl --update` streams what it prints, a root file system's download shows how far it has got
on one line rewritten (saved as a part file, renamed once whole), the packages' update says it is starting. The
platform's terminal: a read held until there is output (`Output.wait`, `finish`; `Terminal.read(since, wait)`), so a
page keeps one read open and shows its echo at once (the user: "in the terminal, characters repeat": two reads at once
drew the same output twice).

## 1.26.0 (2026-11-07)

The WSL distribution plugins check this PC before installing their system (the user: "each plugin should have a scheme
for checking the environment to see if it supports installing the operating system it has in its name, if the criteria
are met according to the O/S, then the install method should be not locked out"): `WslDistribution.check()` (Windows
that runs WSL 2, WSL installed, its kernel, WSL 2.4.4 or later for a named install, the system on offer, the processor,
the free space; `ready` and `installed`, why not). Their long commands stream what they print to a setup's log that
has a `write` ("after the install is run a terminal pops up in the plugin and shows the install progress": `Wsl` runs
with `out`, wsl's words in UTF-8 through WSL_UTF8). `update_packages` brings the system's packages up to date by
apt, dnf or emerge ("after the install is complete, the user can use the plugin to update the environment's packages");
`terminal()` gives the command of a login shell into it, with a terminal of its own inside Linux ("the plugin also
allows for a user to login through a terminal in to the environment"); `machines.terminal`: `Terminal` (a process's
output read from an offset, the keys written to it) and `Output`. The resources monitor reads the disks' I/O, hardware
only ("lets get disk io ... in hwstats"; "the platform only cares about hardware"): `Disk`, `WindowsProbe.disks()`
(each fixed drive's counters, no rights needed), `LinuxProbe.disks()` (/proc/diskstats, whole disks), each disk's and
all disks' bytes read and written a second in the view (`disk`) and over time (`diskRead`, `diskWrite`).

## 1.25.0 (2026-11-07)

A Linux target defaults to Liminal's own WSL distribution on Windows (the user: "Yes, do it" to the Linux admin and
firewall plugins targeting Liminal's WSL distribution by default): `linux.Shell` without a target takes the installed
Liminal-Ubuntu, then Liminal-Fedora, Liminal-Gentoo (`wsl_distributions`, `liminal_distribution`), and says when there
is none (`liminal_missing`, `scope_note`). A firewall or admin plugin on a target that is not Liminal's runs no command
there: its status says why (`MachinePlugin.scope_note`) and its setup changes nothing. The user's own distribution is
never taken.

## 1.24.0 (2026-11-07)

A machine plugin says whether it is valid: set up for Liminal, on something of Liminal's own (the user: "if a plugin
is not in a valid state it has to be disabled"; "there are no WSL-liminally scoped installs, so all three WSL
plugins are invalid"; "only hardware stats and preferences seem valid atm"): `valid` and `why` in its status. A WSL
distribution plugin is valid with its own distribution installed, named `LIMINAL_PREFIX` + the distribution
(Liminal-Ubuntu): the user's own is never taken, and the setup installs Liminal's beside it (`wsl --install <source>
--name <name> --location <folder>`, WSL 2.4.4 or later). A firewall is valid on, guarding Liminal's, with Liminal's rules
and none of the framework's missing; an admin with the rights on Liminal's. `MachinePlugin.scope()`, `linux.Shell.scoped`
(this Linux machine, or a WSL distribution of Liminal's own: WSL's default distribution is the user's), `liminal_scoped`.

## 1.23.0 (2026-11-07)

The apps' charts and two controls in `ui/static`, for every app's page (the user: "allow me to right click on
the icons to disable them on the right icon menu, also allow for enable disable switch (left to right) on the
plugin description"): `charts.js` (`LiminalCharts.cards/draw/update`: line charts of series over time by the
data-viz rules, a crosshair and one tooltip for every line, the keyboard's arrows, the samples as a table,
redrawn in place on new samples), `menu.js` (`LiminalMenu.open`: a context menu at the pointer), and in
`liminal.css` the switch, the menu, the charts and the categorical slots `--series-1..7` for the dark and
light themes, validated against the page. The UI's preferences (the user: "add a preferences plugin for the
'UI' and add the different themes"): `ui.THEMES` (Dark, Midnight, Graphite, Light, Paper: liminal.css's),
`ui.preferences()`/`save_preferences()` over one file for every app on the machine (the data folder's
`ui.json`, LIMINAL_UI_FILE), `GET /api/ui` on every app's frame, and `theme.js`, which paints a page in it.
`resources.role_of`: the charts app's host processes are named by what they host ("Host: fetcher", "Host:
feed-massive") rather than "host command".

## 1.22.1 (2026-11-07)

Docker's repository is the distribution plugin's (`WslDistribution.docker_repository`), filled into the
family's recipe by `install_script()`: the library's code names no outside host (the charts app's boundary
rule), as the Gentoo plugin already names its own. A recipe needing a repository the plugin does not name
fails the docker step in those words.

## 1.22.0 (2026-11-07)

The resources monitor on Linux as on Windows (the user: "i need the hardware monitoring that was in charts,
it needs to be windows and linux agnostic, ie it runs on both ... hw-stats platform plugin"): `resources.
LinuxProbe` reads /proc and /sys (the processes' CPU time, memory, I/O, threads and open files; the machine's
CPU and memory; the adapters' bytes and link speed; every TCP connection, each with its process when it is
one reported), the figures `WindowsProbe` gives, so the `Monitor` reads both alike; `default_probe(match)` picks
it on Linux. The processes reported and their roles are parameters: `WindowsProbe(match)`, `LinuxProbe(match)`,
`Monitor(roles=, own=)` (the charts app's by default: `is_app`, `role_of`); `is_framework` and `framework_role`
take every Liminal app (the integrator, the login, the platform with their ports). `view()` says the `system`.
`icons.js`: `gauge`.

## 1.21.1 (2026-11-07)

`liminal.css`: a list item's icon keeps its size beside a long line; a chip stays on one line.

## 1.21.0 (2026-11-07)

The apps' layout as the user gave it: "the specifics are on the right hand side before the icons on the very
right, and the larger window from the left to right is used to describe or display data"; "plugins are
better described as a list of details w/ the specifics in the right hand column, just like the charts had a
right hand column". `liminal.css`: `.app-main.cols` holding `.app-list` (what there is), `.app-data` (the
selected item's data) and `.app-side` (its specifics, before the tray), list items, `.chip`. `icons.js`:
`shield`, `wrench`, `terminal`. Every machine plugin has an `ICON` for the platform's tray ("active plugins,
will be part of the tray on the very right side"): a firewall's the shield, an admin's the wrench, a WSL
distribution's the terminal, the chip otherwise.

## 1.20.2 (2026-11-07)

Commands in a WSL distribution go through `wsl --exec` (machines.linux.Shell, machines.wsl.Wsl, the engine's
instance `wsl -d <distribution> --exec docker`): with `wsl --`, WSL hands the command line to the
distribution's default shell, which expanded `$variables` and split words before the command ran (found on
this PC: a script's `$PRETTY_NAME` came back empty). Scripts and arguments now reach the command as they are.

## 1.20.1 (2026-11-07)

The firewall plugins offer `allow`, `remove` and `wanted`, the admin plugins `service`, `startup`, `register`,
`unregister` and `processes`, by name (`Plugin.ask`, `interface()`): what the platform's page asks of them.

## 1.20.0 (2026-11-07)

The firewall and admin bases of the platform's plugins (the user: "i also need a windows and linux firewall
plugin for the platform"; "and a windows and linux admin plugin for platform"):

- `machines/firewall.py`: `Rule` (one of Liminal's own, or another's read as it is), `app_ports` (the framework's
  pages), `host_port` (what a `docker run -p` entry publishes on every address), `service_rules` (a domain login's
  mail server container on this machine), `Firewall(MachinePlugin)`: the backend a plugin implements (`state`,
  `list_rules`, `add_rule`, `delete_rule`, `enable`, `can_enable`, `exposing`), `allow`/`remove` (Liminal's rules
  only, group "Liminal"), the status and the setup (`enable`, `exposure`: a finding, never a change, `rules`).
- `machines/admin.py`: `SystemService`, `Startup`, `APPS` and `start_command`, `app_of`, `Admin(MachinePlugin)`:
  the rights and how they are had, the framework's services (started when stopped, never an SSH server), the
  apps' startups (read, run, ended, made or removed when asked; the setup makes none), the framework's processes.
- `machines/windows.py`: `PowerShell` (an encoded, wrapped script; failures in their own words, `denied` for an
  administrator's; `json`; `run_elevated` through UAC; `run_admin`: elevated only with LIMINAL_ELEVATE=prompt),
  `is_elevated`, `quote`. `machines/linux.py`: `Shell` (root here through `sudo -n`, or in a WSL distribution
  through `wsl -u root`; targets local, wsl, wsl:<distribution>).
- `machines.CommandError` (`denied`); `MachinePlugin.STEPS` and a `summary` in every status (the WSL base's too).

## 1.19.2 (2026-11-07)

`WslDistribution` is a plugin base, not a contract class: the hooks it gives count as the plugin's own
(`interface()` names them; `ask()` calls them).

## 1.19.1 (2026-11-07)

`machines.wsl.wsl_path` collapses doubled separators.

## 1.19.0 (2026-11-07)

The machine kind of platform plugin, and named Docker instances (the user: "the platform is the interface
for the software/hardware which facilitates the liminal framework"; "the ubuntu plugin needs to be able to
install docker (do everything manually) and allow different docker instances to support the liminal
framework"): `machines.MachinePlugin(PlatformPlugin)` (KIND machine; hooks present, status, setup, run,
instances, scan, settings), found by the registry as `MACHINE`/`MACHINES` and listed by
`registry.machines()`, conforming (`MACHINE_HOOKS`), attached by `attach_registry`, its variables among
the plugins'. `docker.Instance` and `docker.instances()` (this machine's `local`, its contexts
`context:<name>`, a `host`, and what the machine plugins run), `docker.instance(name)`,
`Docker.for_instance`; `Docker(command="wsl -d Ubuntu docker")`, a command with a prefix; `translate`: a
volume's host path as the engine sees it (a Windows path under WSL). A login file's `[server] instance =
name` picks the engine.

## 1.18.2 (2026-11-07)

`docker.wsl()`: on Windows, whether WSL 2 is there (what a local engine runs its Linux VM in); `describe()`
carries it when no engine is installed and no context or host names another machine. INTEGRATION.md says what
containers need: WSL 2 for a local engine on a Windows PC, nothing for a context, native on Linux; every app
runs without containers.

## 1.18.1 (2026-11-07)

The container command is a setting (the user: Rancher): `Docker(command=)` or LIMINAL_DOCKER_COMMAND, `docker`
by default (Docker Desktop, Rancher Desktop's dockerd engine), `nerdctl` for Rancher Desktop's containerd
engine, `podman` likewise; `describe()` names it, and a missing command says what gives it.

## 1.18.0 (2026-11-07)

Docker in the framework (the user: "i want to integrate docker with the liminal framework"; "the container
or email server, would be responsible for services rendered outside the local domain"): `docker.py`, a
driver over the docker command alone, windowless (`Docker(context=, host=)`: this machine's Docker or
another's through a context or a host, LIMINAL_DOCKER_CONTEXT/LIMINAL_DOCKER_HOST; `available`, `version`,
`containers`, `container`, `pull`, `run`, `ensure` (made, started or left running), `start`, `stop`, `remove`,
`logs`, `exec`, `inspect`, `health`, `compose`, `describe`; `Service` as `docker run` would make it; `Container`
as `docker ps` lists it; `DockerError`; a runner stands in for the command in tests). A login's file declares
its mail server container under `[server]` (`Scope.service()`, `Scope.docker()`: image, name, context or
host, hostname (the admin host), ports, volumes (`./x:/y` under the login's data), `env_NAME` with the case
kept, restart, command).

## 1.17.0 (2026-11-06)

A domain's login has an account of its own, and the pieces to check its mail server with it (the user:
"the login-app would need it's own admin account ie. admin@liminal.domain.tld it would need to be valid in
the DNS record ... and the admin account could be used to test the server so that it can send and
receive with the user email and also see if emails can be sent to other servers, without error"):
`Scope.admin` ([login] admin = admin@<a host under the domain>; `admin_address`, `admin_host`; the codes
come from it unless [mail] from says otherwise), `Scope.imap` ([imap]: the admin mailbox; `imap_variables`);
`dns.py` (`addresses`, `mx_records`, `txt_records`, `spf_record`: what the machine's resolver says, now);
`mailbox.py` (`MailboxSettings` from LIMINAL_IMAP_*, a file's [imap] and the secret store; `Mailbox.find`:
whether a message with a subject is in the admin inbox, over IMAP). `mail.mx_records` reads through dns.py.

## 1.16.0 (2026-11-06)

What a login is tied to (the user: "have like a setup.cfg for the login, and then like other web apps
use that cfg file to decide the domain/scope of the login"; "login apps tied to domains (with email
server) or local (file://project/folder)"; "use a url regardless, file if local, domain w/ email server
in mail record (lookup) or specified if none in the domain lookup"): `apps.scope.Scope`, read from
`liminal-login.cfg` (`Scope.find`: LIMINAL_LOGIN_CFG, the workspace, the working folder or one above,
the data folder's login/), whose [login] scope is a URL: `file:///...` a project folder (a local login:
no email, no sign-up; its users in the folder's store/data/login or .liminal/login), `https://domain` the
domain's users (their codes through the domain's own mail record, or the [mail] server named;
`members` domain or any). `MailSettings.from_env(cfg=)` and `Mailer(cfg=)` take the file's [mail]
between the saved variables and the environment; `MailSettings.through_server` (an account at a host, not
direct: what a sign-up needs); `mail.mx_records(domain)` (the mail record alone, [] when none).

## 1.15.0 (2026-11-06)

The app as the mail server of the user's own domain (the user: "it looks like i need a domain/email
server for this to work"): `dkim.py` signs what the mailer sends for the domain (RFC 6376, RSA-SHA256,
relaxed/relaxed; From, To, Subject, Date, Message-ID), given a key (`generate_key`, kept by the login app)
and one DNS record at the domain (`dns_record`: `<selector>._domainkey.<domain> TXT v=DKIM1; k=rsa; p=...`;
`published` reads it back through the machine's resolver); `verify` does what the receiving server does.
`LIMINAL_SMTP_DKIM_KEY` (the private key's file), `LIMINAL_SMTP_DKIM_SELECTOR`, `LIMINAL_SMTP_DKIM_DOMAIN`
(the sender's domain unless said); `MailSettings.signing`, `signing_domain`, `dkim_record`, `describe()['dkim']`;
`Sent.signed`. With it a message from an address at the domain passes DMARC wherever it lands, home
connection or not; a receiver may still want a reverse name for the address.

## 1.14.0 (2026-11-06)

A mail account kept safely, used at once (the user: "is there a way to add something secure to the python
env?"; "so it looks like i need a domain/email server"): `secrets.py` keeps a secret of the user's in
Windows' Credential Manager under `liminal:<VARIABLE>` (`get`, `put`, `remove`; a stand-in backend
elsewhere). `MailSettings.from_env()` reads the process's environment over the user's saved variables and
takes the password from the secret store when it is in neither, and a `Mailer` built without settings reads
them anew each time, so `liminal-login mail setup` counts for a login app already running. TLS to a mail
server on this machine (Proton Bridge at 127.0.0.1) goes without its self-signed certificate verified.

## 1.13.0 (2026-11-06)

Direct delivery, no mail account (the user: "i am pretty sure you can use a terminal to send email if to
the correct port with right protocol"; Proton's exchangers took a message from this machine on port 25):
`LIMINAL_SMTP_HOST=direct` with `LIMINAL_SMTP_FROM` (your address) sends each message straight to the
recipient's own mail exchangers (`mail.exchangers(domain)`: the MX records through the machine's resolver,
by preference, the domain itself when it has none), port 25, STARTTLS when offered (a code never goes in the
clear unless `LIMINAL_SMTP_SECURITY=none`), the next exchanger when one is not reached. The machine calls
itself `LIMINAL_SMTP_HELO`, else its full name, else `liminal.local` (`MailSettings.helo_name`);
`MailSettings.direct`; `describe()` says `direct`; `Mailer(resolve=)` for a test's stand-in.

## 1.12.0 (2026-11-06)

`Mailer.send` returns the mail server's word that it took the message (the user: "i will need a way to
check the server response to see if it received the email and only if it did, does it wait for the
response"): `mail.Sent` (the address, the server, its reply to the message's data with the code, when,
the message id). The envelope goes step by step (MAIL, RCPT, DATA) so a refusal of the sender, the
address or the message is a `MailError` in the server's own words, and the log line carries the reply.
Every message gets a Message-ID (the sender's domain) and a Date.

## 1.11.0 (2026-11-06)

The pairs are named by the variables (the user: "By the variables"): a plugin's key variable
`MASSIVE_API_KEY` is the login app's pair `massive-api-key`, `ALPACA_API_KEY_ID` is `alpaca-api-key-id`
(`apps.pair_name`, `apps.variable_name`, `KeyVar.pair`), so the login app's pairs, the user environment
variables and the Plugins view name the same thing.

- `Login.names()` (the pairs there are, when a realization can list them; `LoginClient` and
  `EnvironmentLogin` do) and `Login.variables(wanted)`: the variables among `wanted` the login furnishes
  from its pairs, nothing asked twice; a login not signed in furnishes none.
- `Settings.load(env, env_file, login=None)` and `load_settings(login=)`: with the app's `Login`, the
  plugins' variables it furnishes win over the `.env` file, the saved variables and the environment
  (the login is the root authorization); without one, as before.
- `apps.attach_registry(app, only=None)`: every plugin the registry loaded attached to `app` with the
  app's login (one system with `only`; a plugin another app holds is left alone), the names attached
  returned.
- `EnvironmentLogin.vector(name)` reads the variable of the pair's name (`massive-api-key` ->
  `MASSIVE_API_KEY`), or the `pairs` mapping given; `names()` lists the pairs of the variables set.

## 1.10.0 (2026-11-06)

The authorization interface and the plugins' IPC surface (the user: "the app plugins need to use the
Abstract Base Class login as the only way to present an interface for IPC, between plugins and login
and the app as far as AUTHORIZATION"; "the plugins use an ABC plugin to communicate IPC between
themselves and the APP for functionality"; "the app itself (either chart or integrator) has plugin ABC
as well"; "the plugin ABC will enumerate attached plugins and their API").

- `apps/authorization.py`: `Login`, the abstract base every plugin and app holds a realization of
  (`user`, `vector`; `key(plugin)`, `account`, `password` by the pairs' names; `has`, `may`, `signed_in`,
  `describe`); `Unauthorized`; `EnvironmentLogin` reading the user environment variables (the keys'
  store until every plugin is attached through an app). `LoginClient` realizes `Login` over HTTP to the
  login app of a namespace (`LoginRefused` and `LoginUnreachable` are `Unauthorized`).
- The plugin contract: `Plugin.HOOKS` by kind (feed, publisher, assistant), `Plugin.login` and `Plugin.app`
  set by `attach(app, login)` (a record too), `interface()` (its name, kind, system, versions and the hooks
  it answers itself with their signatures), `ask(hook, ...)` (a hook by name; across the pipe once the
  plugin is resident), `detach()`.
- `App.login`, `App.attach(plugin)`, `detach`, `plugin`, `plugins()` (the plugins attached and their API),
  `ask(name, hook, ...)`, `interface()` (the app's own surface, the same shape); `GET /api/plugins`,
  `GET /api/interface`. Tests: tests/test_authorization.py.

## 1.9.1 (2026-11-06)

`forward(..., drop_cookies=(prefixes,))`: the browser's cookies that are not the bound app's business stay
with the front (the charts front keeps the login app's session from the integrator). The bound app's
own cookies keep their path unless `cookie_path` says otherwise, so the main page's request carries
the login's session and the front can ask who is signed in.

## 1.9.0 (2026-11-06)

The apps bound together, `apps/binding.py` (the user: "objects that I can bind together, like the login
app and the integrator app ... I can still link to an existing integrator and get its functions tied
into the chart app ... seamlessly like it is local"): `Binding(name, url, module)` (reachable, its tray,
the prefix a super app serves it under), `tray_of(url)`, `start_app(module, port, env)` (the app's
`serve --no-browser --port N --until-quiet`, detached and windowless), `wait_for(port, seconds)`, and
`forward(handler, method, url, path, cookie_path=...)`: a front passes a page's request on to the bound
app and its answer back as it comes (an event stream chunk by chunk), the bound app's cookies with their
path narrowed to the prefix. `App.serve(until_quiet=seconds)` ends the server once no request has come
for that long (`App.touch`, every request). Tests: tests/test_binding.py.

## 1.8.0 (2026-11-06)

Outgoing mail, `mail.py` (the user: "send an email out, to an email server with correct credentials so
that its not blocked, like proton or gmail"; "this operation can be part lib, and part login app"):
`MailSettings.from_env()` reads one SMTP account of the user's from LIMINAL_SMTP_HOST, _PORT (587),
_SECURITY (starttls, ssl, none), _USER, _PASSWORD and _FROM (Gmail with an app password, Proton Business
with an SMTP token, or Proton Bridge on the machine with no login); `Mailer.send(to, subject, text)` sends
through it (`MailError` names what went wrong without the password; the log names the address masked);
`mask(address)`. The reserved names (`sources/keys.APP`) take the SMTP and login variables, so no plugin
claims them. Tests: tests/test_mail.py, on stand-in servers.

## 1.7.0 (2026-11-05)

The apps' frame (the user, 2026-11-04: "define all this stuff in liminal libs ... the library basically
facilitates the interprocess communication, the way the apps can bind to each other, or interoperate,
or seamlessly connect ... As well as the framework for the graphics. The common themes and drawing
methods"; what is particular to one app stays in that app's repo), built for the first app on it,
liminal-login.

- `web.py`, moved here from the charts app's gui/web.py: what every app's server shares (`listening`,
  `send`, `send_json`, `local_only`, `from_this_app`, `cookie`, `profile_cookie`, `static_file(handler,
  rel, dirs)` reading the first of the folders given, `MAX_BODY`, `WRITE_HEADER`).
- `ui/static/`: `icons.js` (moved from the charts app; the `user`, `key`, `eye`, `eyeoff`, `trash` and
  `logout` icons added) and `liminal.css` (the themes' variables, the base controls, the rail, a small
  app's page); `ui.STATIC` is served beside every app's own files.
- `apps/`: `App` (an app's NAME, TITLE, master ICON, PORT and PORT_VAR, its STATIC folder; `tray()`,
  `items()`, `api(handler, method, path, query, body)` for its routes, `page()`, `start()`/`stop()`/
  `serve()` at its port on 127.0.0.1 alone, a taken port replaced by a free one; `GET /api/tray` and
  `GET /api/app` answered by the frame; every write needs the write header and a JSON object), `Refused`,
  `Tray` and `TrayItem` (the master icon first, then the app's view plugins; the dividers between
  bound apps' trays come with the binding), and `LoginClient` (`sign_in`, `sign_out`, `user`, `pairs`,
  `vector`, `put`, `remove`; `key(plugin)`, `account(plugin)`, `password(plugin)` for the pairs named
  `<plugin>-account-api-key` and the like; the session token in `X-Liminal-Session`; `LoginRefused`,
  `LoginUnreachable`; LIMINAL_LOGIN_URL, 8795 by default).
- Tests: tests/test_apps.py.

## 1.6.0 (2026-11-04)

The data specs, plugin API 2.1 (`sources/data.py`; the user, 2026-11-03: "every plugin needs to furnish
the correct mechanisms for assessing data, data integrity, provide a 'spec' for the data, different
source plugins like massive and Tingo can inherit 'stock_symbol_data'. obviously the api for each
source provider is different so the calls are inherent (external calls to source) of the plugin
itself"). A class per kind of data a plugin delivers, three methods each: `spec()` (the fields and
dtypes of a bar or tick row, the resolutions, the sessions and calendar, the adjustments, the symbol
form; a document's parts; the products and the store each goes to), `assess(frame, since, until)`
(what is held and what is missing, as the coverage ledger's spans; completeness against the calendar's
slots; latency; with a plan, freshness's state: what the coverage planner and the integrator's
assessor read) and `integrity(frame)` (the bad-data rules behind one method, `baddata.malformed` and
`baddata.spikes` called, not copied; duplicates, rows outside the sessions, gaps inside them, a
required field missing; `compare` for two feeds' copies of a span, `audit.compare`; `scan` for the
rules that need the store, `baddata.scan_series`). The fetching stays in each plugin's DataSource.

- `TimeSeriesData`, the feeds' bars and ticks: `StockSymbolData` (the user's stock_symbol_data: the
  consolidated tape's hours, split-adjusted prices, TICKER or TICKER.SUFFIX), `IndexData` (regular
  hours, no volume), `FxData` (Sunday 17:00 to Friday 17:00 ET, day bars UTC days), `CryptoSymbolData`
  (around the clock, UTC days, a market per exchange so two copies' volumes are not judged, trades
  without sale conditions) and `FutureData` (CME sessions, settlement dates, no adjustment at a roll);
  `slots` (the bar starts the calendar expects), `rows` and `wire` (a frame in either shape, the feeds'
  or the store's). A feed plugin declares its own where the vendor's data differs
  (`FeedPlugin.data = {"stock": MassiveStockData}`, a subclass of the asset class's) and the contract
  gives the asset class's otherwise (`FeedPlugin.data_for(asset)`), so every plugin conforms unchanged.
- `DocumentData`, the publishers' documents, with the parts `Paragraph`, `Page` and `Statement` and
  `Document` (the original as the stores hold it, with its pages and the statements parsed from it):
  `ReleaseData` (an agency's items, GOV_ITEMS), `HeadlineData` (a vendor's headlines, NEWS) and
  `FilingData` (a filing's pages and statements: the `FILINGS` kind, to be registered in
  storage/documents.KINDS when filings are fetched); a document's completeness is its required
  fields, every page in its run and every statement parsed through; a publisher declares its class
  (`PublisherPlugin.data`) or takes its kind's (`PublisherPlugin.document_data()`: a vendor's
  headlines, every other's releases).
- Storage, in the classes (the user: "mongo is used to store the original source document, while a
  different database is used to evaluate or derive information from the original document"): each
  class's `products` (`Product`: the Store picker's type, the engines, where) name the original (a
  document to MongoDB, or SQLite until it moves; a feed's bars to its file, its closed months to
  DuckDB, its ticks) and what is evaluated or derived from it (parsed statements, the AI evaluations,
  the bars built here, the pruned list), kept apart in SQLite or DuckDB, keyed to the original
  (`keyed_to`) and never written back; `check()` holds a class to it. Nothing moves today.
- The contract: `registry.PLUGIN_API` 2.1; a 2.0 plugin loads unchanged (`api_refusal`); a plugin
  declaring `data` says `api = "2.1"`; `Plugin.api`'s default stays 2.0. The conformance check reads
  the declarations: a feed's `data` maps its asset classes to subclasses of theirs, a publisher's is
  a DocumentData subclass or None, each class a plugin answers with gives its spec and passes its own
  `check()`, a declaration needs 2.1 or later.
- Tests: tests/test_data_specs.py (each class's spec and slots, an assessment with known gaps and
  latency, an integrity report on malformed, duplicate, out-of-session and spiky rows, a document's
  parts and completeness, the contract's defaults and a plugin's own, the conformance rule, a 2.0
  plugin loading under 2.1). The charts app pins the contract's version in two tests of its own
  (tests/test_plugins.py: `PLUGIN_API == "2.0"`, and a plugin for 2.1 expected to be left out): they
  move with the app's pin of the library.

## 1.5.1 (2026-11-04)

`collector.sync` is a plain wrapper of `Collector(...).run(...)` again: the charts app's test reads the
run's first stage (`Collector._before_symbols`) since the app moved to the classes, so the copied
signature and `sync.__wrapped__` go.

## 1.5.0 (2026-11-03)

The library's core classes (Phase 5 of the object-oriented rewrite; the user: the plugins and apps
"follow inheritance/oop paradigm"). The rule: a class owns a run's or a view's state and the
decisions; the hot loops and the pure functions stay functions; every module keeps a function under
each name a caller or a test used, so nothing that imports the library changes (the charts app and
the integrator move to the classes in their own commits); a class calls the module's functions
through the module (a test's stand-in is the one used) and reads the module's constants when a
stage runs, never when it is made.

- The runs (5a). `collector.Collector(source, store, tier, *, now, log, refresh_hours, feeds, audits,
  futures_per_run, proxies)`: a feed's scheduled run, stage by stage (`_before_symbols`, `_plan_run`,
  `_step(item, urgent)`, `_after_symbols`; `run(only, published_only, on_item, directory_allowance) ->
  SyncResult`); `sync(...)` is `Collector(...).run(...)`, its source the class's (inspect.getsource; the
  signature its own). `RunQueue` (the run's rows on the fetch queue; `_Queue` kept); `SYMBOLS_PER_MONTH`
  a mapping that reads the plugins' monthly caps when asked, not when the module loads, so
  `monthly_cap` is lazy. `audit.Auditor(source, store, me, feeds, now, log, rng)` (`run`, `span`,
  `random_span`, `window`; its watch rows read once). `initializer.Initializer(store, feeds,
  futures_feeds, source, now).run(exchanges, by, dry_run)`. Stay functions: sync_bars, _fill, _plan,
  verify_fetched, sync_future, check_listing, daily_first, market_days, refresh_directory,
  fill_directory_icons, scan, history_floor; audit.compare, box, spot, allowance, audit_span.
- The planning (5b). `coverage.Planner(store, feeds, now).plan(me, ticker, asset, timespan, floor,
  listed_from, exchange)`: the audit scores and the standing scheme read once when first needed, a
  ticker's watch rows and a feed's quality the first time they are asked for (`forget(ticker)` reads
  the rows again), the coverage ledger for every plan; the collector makes one planner per symbol
  step, per daily-first sweep and per scan. `sourcing.Scheme.build`, `Scheme.standing` (the cache the
  class's, by store), `Scheme.reports`, `Scheme.offered` (the field `offers` is the offers a scheme
  was built from) and `scheme.text(reports)`; `sourcing.Scans` (`keep`, `last`, `read`, `at`,
  `plans`, `apply`): the providers' capability scans (kv SCAN_KEY) in one place. `derive.Builder(store,
  log)` (`chain`, `symbol`, `run`) and `derive.Lease(store, source, ticker)`, a context manager over
  the build leases; `baddata.Scanner(store, log)` (`symbol`, `repair_from_ticks`, `entries`). Stay
  functions: frontier_ms, subtract, intersect, eras_ahead, has_open_time, latency, rank, same_market;
  derive.aggregate (vectorised), the marks and leases; malformed, spikes, inconsistent, scan_series.
- The settings and the services (5c). `config.Settings.load(env, env_file)` and
  `settings.with_detected(plans)`; `config.UserEnvironment(registry, names)` (`saved`, `save`): the
  user's saved environment variables, the winreg code (a stand-in registry works on any OS).
  `datasets.DatasetFetcher(store, today, session, log)` (`fetch`, `files`, `git`) and `FileQueue`
  (`_FileQueue` kept). `publications.Reader.for_view`, `Reader.view`, `Reader.run_due`,
  `Reader.recheck_now`. `killswitch.KillSwitch(store)` (`killed`, `strike`, `release`, `kills`).
  `runner.Runner(store_factory, settings, log)` (`run`, `plugin`). `live.Recorder.for_settings(settings,
  locks, stop, log)`: the charts app's `make_recorder`. `host.Attachment.to(name, db_path, start, wait,
  log)` and `host.Host.start(name, db_path)` (a host's wait for its first client is `start_wait` now);
  `attach`, `start_host` and `attach_or_start` kept (the integrator imports them by name).
- Stays functional, deliberately: `sessions.py` (the calendar masks), `freshness.expected` and the
  publication rules, `storage/*` (the queries), `stores.py`, `memory.py`, `resources.py`, `proc.py`,
  `ratelimit.py` (classes already), `gov.view`, `gov.parameters`, `gov.upcoming`.
- Tests: tests/test_run_classes.py, tests/test_planning_classes.py, tests/test_settings_classes.py (each
  class's state across calls, the wrappers, a stand-in set on the module used by the class, a constant
  read when the run runs). With another checkout of the library installed editable, the suite needs
  this checkout's `src` first on PYTHONPATH.

## 1.4.2 (2026-11-03)

The recorder's command pattern (`live.RECORDER_COMMAND`: a stray recorder ended by the one holding the
machine lock) reads the new names, `-m liminal_charts live` and `liminal-charts live`, and the old ones
still (a process started before the rename).

## 1.4.1 (2026-11-03)

The class contract's conformance check, `sources/conformance.py` (the user: "evaluate each functional
piece of software or plugin and verify correctness and valid functionality through unit tests created to
address new class scheme"): `problems(plugin)` lists every way a plugin falls short of the contract, read
from the plugin alone (its name, title, contract version, system and kind, keys and variables, hooks,
`with_()`, and what its kind declares: a feed's assets, resolutions, delays and hours; a publisher's feeds
and datasets; an assistant's plans, models, prices, sources and caps); `assert_conforms`,
`assert_module_conforms` and `plugins_of` for the tests: every plugin package's tests/test_contract.py,
and the charts app's test over every plugin found.

## 1.4.0 (2026-11-03)

Renamed `liminal-libs` (the package `liminal_libs`): the naming by system (the user, 2026-11-03: apps are
`liminal-<app>`, the one library `liminal-libs`, plugins `plugin-<app>-<name>`). The charts app is
`liminal-charts` (`liminal_charts`, the command `liminal-charts`; `host.APP_MODULE`), the stock-data
plugins `plugin-integrator-<name>`, the AI plugins `plugin-platform-<name>`; `resources.role_of` reads
the new names and the old (a task registered before). INTEGRATION.md: how the repositories fit
together. Every import of `liminal_lib` becomes `liminal_libs`; nothing else changes.

## 1.3.1 (2026-11-03)

Which plugins a process loads is a selection (`registry.Selection`, LIMINAL_PLUGINS_LOADED; `select`,
`selection`, `plugins_loaded`): every plugin found by default, the ones named (each with its parts: boats
keeps Alpaca, sec keeps Federal), or none at all (the user: "the default case is to load all plugins,
however the integrator can be loaded with select plugins or none"; the integrator's `--plugins`). The
plugins found but not named are left out quietly (`Selection.left_out`, not `errors()`), a name no plugin
answers to is noted (`unknown`), and a process started by this one inherits the selection. LIMINAL_PLUGINS_LOADED
and LIMINAL_INTEGRATOR_NAME (an integrator of its own, liminal-integrator 1.4.0) are the app's variables
(`keys.APP`), no plugin's.

## 1.3.0 (2026-11-03)

The class contract, plugin API 2.0 (the user: "all the plugins under liminal should basically follow
inheritance/oop paradigm"). `sources/plugin.py`: a plugin is an instance of a `FeedPlugin` or
`PublisherPlugin` subclass, what it declares class attributes, what it does methods overriding the
contract's defaults (`build`, `view`, `rate`, `has_keys`, `serves`, `markets`, `carries`,
`plan_resolutions`, `reporter`, `scan`, `settings`; a publisher's `moments`, `calendar`, `read`); the
registry loads an instance, a class (instantiated) or a module's `PLUGIN(S)`, `PUBLISHER(S)`,
`ASSISTANT(S)`. The record form (`Provider`, `Publisher`: the hooks as callback fields) is a subclass of
the same classes (`is_record`), still plugin API 1.x (`RECORD_API` 1.12; `api_refusal(..., record=True)`),
so every plugin loads as before. `Plugin.gives`, `has_scan`, `has_settings`, `settings_of`, `with_`,
`refusal`; `PublisherPlugin.has_moments`, `has_calendar`, `reads_itself` (the reader, the stores and the
views test these instead of the fields). A feed declares its publication delays and market hours
(`FeedPlugin.delays`, `hours`: `freshness.Delays`, `DELAYS.declare` when it loads; the rows of
`PLAN_DELAYS` and `FEED_HOURS` stay until every plugin carries its own). `config.load_settings` builds a
plugin's own settings for every kind (`Settings.plugin` for a publisher too). `sources/archive.py`:
`PublicFeedPlugin` (its source on the contract's public client) and `CryptoVenuePlugin` (a crypto
exchange's plan and caps, `CRYPTO_VENUE_DAYS`). `Scanned`, `Report`, `Limits`, `Capability`,
`minute_window`, `within`, `server_limits`, `server_per_minute` moved to `sources/plugin.py`, still
imported from the registry.

The AI assistant kind, `liminal_libs.assistants` (the user: three AI plugins "that have a vanilla API, are
compliant with the rest of the plugin structure ... but allow interfacing with Claude, Grock and ChatGPT
Codex via API key, an email / account name", "used to evaluate certain standardized arguments from other
plugins or apps", "extensible, and allow for higher order evaluation"). `AssistantPlugin` (`assistants/plugin.py`:
a vendor's plans, models, prices and source pages written in and dated; its keys `<NAME>_API_KEY` and
`<NAME>_ACCOUNT`, its plan variables and caps derived; its settings an `AssistantSettings`); `Assistant`
(`assistants/assistant.py`: `models()`, `evaluate(argument)`, `connect()`, the vendor hooks; `ResponsesAssistant`
for the OpenAI-shaped Responses API; `AssistantClient` on the contract's client, every error scrubbed of the key
and the account); the arguments (`assistants/arguments.py`: `Question`, `Judge`, `ContextItem`, `Answer`, a kind
registry for a plugin's own); `Evaluation` and `Usage` (`assistants/evaluation.py`), kept in the main file's
`evaluations` table (`storage/evaluations.py`); `assistants.evaluate`, `evaluate_all`, `judge`,
`default_assistant` (`LIMINAL_ASSISTANT`); `assistants/context.py` (context items from headlines, assessments,
reports, evaluations); `assistants/verify.py` (the vendor pages read again: a plugin's weekly CI test). The
registry's third kind (`assistants()`, `assistant_menu`, `ASSISTANT(S)` in a module), `config.load_settings` for
it, `sourcing.detected_plans` with its scans. `HttpClient.post` (no transport retry: an answer may have been
billed), a subclass's `_refusal` and `_final`, `limit_prefixes`; `MachineLedger.take_day(n)` and `charge_day`.
Nothing is sent from an offline copy; the caps are per machine (50 requests, 200,000 tokens a day, 1,024
output tokens, the cheapest model), raised on the Plugins view.

## 1.2.4 (2026-11-03)

1.2.3's `same_market` undone: two feeds naming no market for an asset class count as one market again (the
collector's tests run fakes that name none, and a real feed names one for every class it serves); the app's
one-feed-per-span check asks with the asset class the ticker belongs to instead.

## 1.2.3 (2026-11-03)

`coverage.same_market` says no for two feeds neither of which has a market for an asset class (it said yes, two
blanks being equal): the app's one-feed-per-span check counted Bitstamp's and Coinbase's trades of a pair no
longer watched as one market's double download.

## 1.2.2 (2026-11-03)

Found going through the fetcher's page plugin by plugin (the user: "go through the UI and look for discrepancies"):
a feed of daily bars alone (TWSE's, B3's, J-Quants', Alpha Vantage's, Cboe's) no longer lists a trades database it
can never have (`plugin_databases`: the -ticks.db file only where a feed provides 1-second bars or streams trades);
Cboe's VIX futures feed publishes a contract's day with its settlement after the session (`PLAN_DELAYS["cboe-futures"]`,
end of day; `expected` and `assess` take an end-of-day plan's futures like its stocks), where the Plugins view said
"480 min delayed", the free futures plans' rule.

## 1.2.1 (2026-11-02)

A listing outside the US whose source names another exchange keeps its exchange and still takes the record's
identity (listing date, FIGI, name, details): 1.2.0 returned before recording it, so the listing was never dated
and its daily history waited for a date that would not come.

## 1.2.0 (2026-11-02)

Stocks listed outside the US (the user: "update existing plugins, add exchanges where applicable and symbols").
One stored name per listing, `TICKER.SUFFIX` with Reuters-style suffixes of the MIC (`7203.T` Tokyo, `2330.TW`
Taiwan, `PETR4.SA` B3, `600519.SS` Shanghai, `000001.SZ` Shenzhen, `VOD.L` London, ...: `models.VENUES`); `TSE:7203`
and `7203::XTKS` normalise to it (`symbols.stock_spec`); US tickers and pins are as before. Plugin API 1.12:
`Provider.exchanges` names the MICs a feed carries ("US" for every US listing; without it a stock feed carries US
listings alone) and `can_carry` refuses the rest. A listing abroad keeps its exchange's days: every weekday is a
trading day covering the local calendar day (`MarketCalendar.local_day_session`, the seam for exchange_calendars'
holidays later), through `freshness`, `coverage` and the collector (the watch row's `exchange`), so a Tokyo trading
day on a US holiday is asked for; day bars stay stamped at midnight ET of the local date (`derive.aggregate` bins
by the local day, with no regular-session filter). Publication delays by tier name: `twse`, `tpex`, `b3`,
`alphavantage-free`, `jquants-*` (end of day; `jquants-free` twelve weeks late), `twelvedata-free` (UTC day).
`refresh_directory` asks each feed for its own exchanges' listings (stored in the suffix form), `Store.directory()`
spans every source, `Store.watch_exchanges()`, `mic_names` seeded from `VENUES`; the initializer gives a listing to
the feeds carrying it; audits, bad-data scans and the live recorder leave listings abroad alone;
`sessions.world_calendar` moved in from the app's Markets globe.

## 1.1.1 (2026-11-02)

The Resources sampler reads the app's processes under their new names: `python -m liminal_charts ...` and the
console script (`liminal ...`, `liminal.exe` on Windows), the old module name still (`resources.APP_WORDS`).

## 1.1.0 (2026-11-02)

The app is liminal-charts (the user: "lets rename the app to liminal-charts", "not liminal", "refactor"): hosts start as
`python -m liminal_charts host NAME` (`host.APP_MODULE`), messages name the `liminal` command (the app's console
script) instead of `python -m liminal`, and the library's import test refuses the app and the integrator under
their new names. Plugins import the library as `liminal_libs` from their next releases.

## 1.0.1 (2026-11-02)

The workspace (`layout.py`: `home`, `data_dir`, `plugins_dir`): `common/` the library, `app/` the chart app,
`store/` the integrator with the databases in `store/data/` (the default main file), `plugins/` a checkout per
plugin, loaded from there by the registry (`plugin_checkouts`, origin `plugins/<checkout>`; the same plugin
installed as a package besides is not loaded twice).

## 1.0.0 (2026-11-01)

The library, out of the app ([liminal](https://github.com/pcxmac-dev/liminal), feature/collector at d21b4b8):
every module but the app's own, their names kept, as the package `liminal_libs`. The regular session's filter,
masks and close moved in from the chart's bars module (`sessions.py`); the market proxies became a parameter of
`collector.sync`. New: `logs.py`, the fetcher's host name and its clients' side in `host.py`, `stores.history_due`,
`sources.feed_closed`, `proc.hold_until_interrupted`, the fetcher's requests in `storage/requests.py`.
