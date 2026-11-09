# Liminal as a network of nodes, in Rust: the design

Status: **draft for review**. It was first written on 2026-11-09 for Python on a Rust core, then revised the same day
for a full rewrite in Rust. Nothing here is built yet. Decisions 1–8 and 63 are decided, and the decisions the
rewrite retires are marked so. Every other decision in the log (§10) stays open until the user decides it, and the
code follows only decided items.

## 1. What the user asked for

In the user's words, 2026-11-09:

- "the idea is to make sure all modular code uses abstract base classes as interfaces and Inter Process
  Communication to interact between code objects"
- "ALL ABSTRACT BASE CLASSES PROVIDE ALL INTER-PROCESS COMMUNICATION METHODS, AS WELL, AN 'AXON' from which to
  receive requests, ABC form the foundation for internetworking between code objects and API's" — "*not all"
- "basically all code objects, including parts of plugins become internetworked stateful code objects that interact
  in real time"
- "the hillock will be the ABC that interlinks with other nodes, the axon it's input interface will accept
  connections for input, and dendrites, will extend to other nodes and request access to their axons". In the
  decision walk the user then chose biology's direction (decision 4): a node's dendrites take its input, and its
  axon is its output.
- "also, the nodes are structured much like neural networks"
- "the public facing nodes which interact with the user manage input and display, where as the intermediary nodes
  handle logic, and the back side manages OS/API/low level interactions". On how a node knows its side: "for this
  one, the nodes have to find a way to self organize" (decision 5).
- "we are using the existing libraries as the desired output and input and code organization", "the existing UI"
- "it has to look and behave very much the same way, but requires a very much different kind of paradigm in terms
  of coding, it will also require the ability to be interlinked against different compilers' code and libs" — "like
  i will have rust and maybe c++"
- "this is going to be a very extensive rewrite and conceptual design"; "we will have to walk through a lot of the
  decisions you make in order to make sure nothing is skipped over"
- "at each synapse, callbacks or variable functions can be used to filter stimulus our input in order to logically
  order output correctly"
- "can we do this in rust, the base networking, and run python abstractions on top ?"
- "is there a way to have python functions embedded in these nodes" ("pay in mind, they are rust based"), "is there
  a way to use the same types of datatypes/constructs that python uses, in rust ?", and then: "then. lets do a full
  rewrite in rust. All liminal-net stuff will be done in a few days"

Their answers on the rewrite's scope:

| question | answer |
|---|---|
| Python where Rust lacks a library (only `exchange_calendars`) | Rust everywhere: the calendars are ported too, and no Python remains at the end |
| How the rewrite replaces the Python that runs today | Node by node: Rust and Python nodes speak one protocol, each piece is swapped once its Rust version gives the same outputs, and the apps keep running throughout |
| Where the Rust lives | The same repositories: each gets its crate, and its Python leaves as its pieces are replaced |
| The first slice after liminal-net | The platform and its plugins |

The requirements drawn from them:

| | requirement |
|---|---|
| R1 | It looks and behaves the same. Every route and its answer, every command and its output, every file and database, and the UI's HTML, JS and CSS stay as they are (§8). |
| R2 | The organization stays: the same repositories, and each crate's modules keep today's names (`machines/wsl.py` becomes `machines/wsl.rs`). The paradigm is new: nodes that interact only by requests and signals, through their dendrites and axons. |
| R3 | Nothing on the wire or in an interface belongs to one language. Rust is the implementation. C++ can join through a C ABI, and Python through the bridge while it remains. |
| R4 | The network is structured like a neural network, on three sides, which the nodes organize themselves. |
| R5 | Nodes are stateful and real time. Nothing runs unless used (the user's rule of 2026-11-01), and data is secured before a process ends. |
| R6 | Every decision is walked through with the user; nothing is skipped over. |
| R7 | At each synapse, callbacks or variable functions filter the stimulus, so that output comes out in the right logical order. |
| R8 | Rust everywhere. Python appears only in nodes not yet replaced, through liminal-net's bridge, which goes with the last of them. |

## 2. The terms

The direction is biology's (decision 4): a node's **dendrites** take its input, and its **axon** carries its output
to other nodes' dendrites.

| term | meaning |
|---|---|
| **node** | A stateful code object of the network: a plugin, a part of a plugin, an app, a login, a source, an assistant, a service. It has a name among the nodes, and its state lives as long as its process. |
| **Hillock** | The trait every node realizes (`liminal_net::Hillock`). It interlinks the node with others: it integrates what reaches the node's dendrites into the node's state, and fires the node's signals along its axon. |
| **dendrites** | A node's input. They accept synapses from other nodes' axons, admit or refuse them, run each synapse's functions, and take in the requests and signals that arrive. |
| **axon** | A node's output. It reaches other nodes' dendrites and requests access. It carries the node's requests out and their answers back, and fires the node's signals to the nodes linked for them. Through it, a node holds another as that node's own trait, through a client generated from the trait. |
| **synapse** | Where one node's axon meets another node's dendrites: a single connection. Answers travel back across it, as retrograde signals do in biology. (The word is this design's: decision 2.) |
| **stimulus** | Whatever crosses a synapse towards the dendrites: a request or a signal. |
| **synaptic function** | A callback or variable function at a synapse, applied in order to each stimulus crossing it, before the receiving node takes it in. It filters, reshapes, orders, holds back or combines, so that the output comes out in the right logical order (R7). "Variable": it can be replaced while the link is live (§4.8). |
| **request** | A call of one of a node's interface methods. It goes along the caller's axon into the node's dendrites, and is answered back across the same synapse. |
| **signal** | Something a node fires: a status changed, a line printed, a sample taken. It travels along the axon to the dendrites of the nodes linked for it, and their hillocks integrate it. It is never answered. |
| **message** | Data that travels between nodes (a status, a rule, an argument, a report), carried by value. A message is not a node: this is the user's "not all" (decision 3). |
| **side** | Where a node stands: public-facing (the user's input and the display), intermediary (logic) or back side (the OS, the APIs, low-level work). Nodes find their side themselves (decisions 5 and 67). |
| **interface** | What a node offers: its methods, with their arguments' and answers' types, and its signals. Its dendrites serve nothing else. It is described language-neutrally, generated from its Rust trait (§6). |
| **handle** | How a node or a callable is passed in a message: an id the receiver uses to reach it, released explicitly. |
| **scope** | What names a set of nodes' addresses: the reaching app's state (its database, or its folder), through host.py's digest (decisions 14 and 82). Two scopes never share a process. |
| **bridge** | liminal-net's Python module (decision 62): how a Python object takes part as a node while the Python is replaced, piece by piece. |

## 3. How the network works

### 3.1 Like a neural network

- **Links are directed**: an axon reaches a node's dendrites. Two nodes that both start conversations hold a synapse
  each way. The platform's axon reaches a plugin, and the plugin's axon reaches the platform for its login and to
  fire its signals.
- **Requests** go along an axon into a node's dendrites, and are answered back across the same synapse.
- **Signals propagate forward, like activations.** A node fires, and its signal travels along its axon to the
  dendrites of every node linked for it. Each receiving hillock integrates it into its node's state, and may fire in
  turn.
- **Synaptic functions on every link** (R7). Each stimulus crossing a synapse passes the link's functions in order
  before the receiving node takes it in (§4.8). Per link, they filter, reshape and order. Per node, the hillock
  integrates what all its links deliver.
- **Integration at the hillock**, as in a neuron:
  - a burst of the same state signal becomes one, the latest, at most once per interval (decision 20);
  - nothing fires when nothing changed;
  - stream signals (lines, rows, ticks) are delivered every one, in order (decision 43).
- **Three sides.** The user's input enters at the front. Requests travel through the logic to the back side. What
  happens at the back side fires forward through the logic, integrated at each hillock, to the display. Any node may
  still link to any other.
- **The sides organize themselves** (decisions 5 and 67). A node declares no side. The network works it out from
  the node's links and from what the node touches:
  - a node the pages reach is public-facing;
  - a node that reaches the OS, outside hosts or the stores is the back side;
  - the rest is intermediary.

  The network recomputes this as links change, and Connections shows it.

### 3.2 The three sides, with Liminal's nodes

These are the existing classes, in their existing modules. In Rust they keep the same names (R2).

| side | manages | nodes |
|---|---|---|
| public-facing | the user's input and the display | each app's page in the browser, and the HTTP side of its dendrites: the charts front (`liminal_charts.gui.front`) and chart server (`gui.server.ChartApp`), the integrator's page process (`liminal_integrator.service`), the platform (`liminal_platform.app.PlatformApp` routes), the login (`liminal_login.app.LoginApp` routes). The views: the charts' Stock, Analysis, Trading, Watchlist, Preferences; the integrator's Exchanges, Markets, News, Federal, Datasets, Live, Fetcher, Plugins, Resources, Databases; the platform's This machine, each plugin's page (its tables, forms and terminal as the platform draws them), and Connections. The trays |
| intermediary | logic | the apps' logic: `ChartsApp`, `IntegratorApp` and the `Fetcher` with its assessment and standing pass, the `Service`, `PlatformApp`'s nexus (validity, enabling, attaching), `LoginApp`'s users and vault. The library's logic: `collector.Collector`, `coverage.Planner`, `sourcing.Scheme`/`Scans`, `audit.Auditor`, `initializer.Initializer`, `derive.Builder`, `baddata.Scanner`, `runner.Runner`, `publications.Reader`, `killswitch.KillSwitch`. Each plugin's own logic: a feed's plans and declarations, a publisher's feeds and policy, an assistant's plans and models, a machine plugin's hooks (a WSL plugin's installs and steps, a firewall's groups and risk checks, hw-stats' figures, Namecheap's zones). The login's realizations: `EnvironmentLogin`, `LoginClient`, `RecordingLogin` |
| back side | the OS, the APIs, low-level work | the drivers: `machines.windows.PowerShell`, `machines.linux.Shell`, `machines.wsl.Wsl`, `docker.Docker`, `machines.terminal.Terminal`'s PTY, `capture`, `netpath`, `dns`, `ports`. The vendor clients: each feed's `DataSource`, `sources.http.HttpClient`, `assistants.AssistantClient`, Namecheap's API client, the publishers' reads, `wsclient` and `sources.stream`'s live feeds. The stores: `storage.Store` on SQLite, `stores` on DuckDB, `mongo`'s keeper. The machine ledgers (`ratelimit.MachineLedger`). The network's own pipes |

A plugin's parts sit on all three sides. The WSL plugin's tables and terminal are on the front, its installs and
steps in the middle, and `Wsl`, `Shell` and `wsl.exe` at the back. So the parts of plugins become nodes on their own
sides (decision 7).

### 3.3 The processes

```mermaid
flowchart LR
  subgraph front[public-facing]
    page_c[charts page]
    page_i[integrator page]
    page_p[platform page]
    page_l[login page]
  end
  subgraph middle[intermediary]
    charts[charts front :8765]
    integ[integrator page process :8785]
    fetcher[fetcher]
    platform[platform :8775]
    login[login app :8795]
  end
  subgraph back[back side]
    feedrun[feed-NAME runs]
    live[live recorder]
    mongo[MongoDB keeper]
    plug[each platform plugin's own process]:::new
    drivers[PowerShell, Shell, Wsl, Docker, the vendors' APIs, the stores]
  end
  page_c -- HTTP --> charts
  page_i -- HTTP --> integ
  page_p -- HTTP --> platform
  page_l -- HTTP --> login
  charts -- HTTP --> integ
  integ -- axon to dendrites --> fetcher
  fetcher -- axon to dendrites --> feedrun
  charts -- axon to dendrites --> live
  charts -- axon to dendrites --> mongo
  platform -- axon to dendrites --> plug
  plug -- "axon to dendrites: login, app, signals" --> platform
  plug --> drivers
  feedrun --> drivers
  classDef new stroke-dasharray: 4 3
```

Dashed: new. Today the platform's plugins run inside the platform's own process, and host.py's pipes carry pickled
dicts. In the target every process is a Rust executable. Until its piece is ported, it is the Python one, on the
bridge.

### 3.4 The code's layers: Rust everywhere (R8)

```mermaid
flowchart TB
  subgraph rust[Rust: every node]
    APPS["the apps' executables: charts, integrator, platform, login"]
    PLUG["each plugin's executable"]
    LIBS["liminal-libs' crates: core, storage, contract, engine (decision 84)"]
    NET["liminal-net: the Hillock trait, dendrites, axon, synapses, synaptic functions, signals, handles, errors, lifecycle, transport, the protocol"]
  end
  subgraph ways[ways in for other languages]
    BR["the bridge: a Python module (PyO3, abi3), while Python remains"]
    C["liminal_node.h: a C ABI (cbindgen), for C++, later"]
  end
  APPS --> LIBS
  PLUG --> LIBS
  LIBS --> NET
  BR --> NET
  C --> NET
  PYN["a Python node not yet ported"] --> BR
  CN[a C++ node] --> C
```

**One implementation of the network.**
- Rust nodes link liminal-net directly.
- Python nodes, while they remain, go through the bridge; C++ goes through the C ABI.
- No language reimplements the protocol. The exception would be decision 62 choosing a pure-Python speaker for the
  bridge period, and that would be checked against the same test vectors (§5.7).

**What liminal-net holds** (Phase 1):
- the transport: named pipes on Windows and Unix sockets elsewhere, through tokio;
- the handshake (the `hmac` and `sha2` crates);
- the frames and the codec: `serde_json` with its keys kept in order, and later `ciborium`;
- requests and answers matched by id, the handle tables, and the routing of signals to the links made for them;
- the eight built-in synaptic functions;
- the lifecycle: synapses counted, the quiet end, the grace, and a windowless, detached start of a resident node's
  process (CREATE_NO_WINDOW);
- the integration of state signals, coalesced to the latest;
- the `Hillock` trait and the node runtime;
- the interface descriptions, generated from the traits.

**What each repository's crate holds:**
- liminal-libs: the traits that are today's ABCs (§9's table), the records as structs, and the shared parts;
- each app: its executable, whose HTTP side serves today's pages and routes;
- each plugin: its node executable.

**What it takes:**
- The Rust toolchain: installed (decision 63).
- The crates from crates.io, asked once by list before the first build (decision 79).
- The bridge: maturin from PyPI, asked before its build (decision 62).
- liminal-net's repository: local, at `C:\Users\ciara\source\liminal\net`. It goes to GitHub only on the user's yes
  (decision 58).

## 4. The rules

### 4.1 What crosses, and how

| what | how |
|---|---|
| messages: maps, lists, text, numbers, booleans, null | by value, with the wire types of §5.5 |
| typed records: the library's records (`Rule`, `Startup`, `docker.Instance`, `Report`, `Scanned`, `Argument` and its kinds ...) | by value, as `{"$type": "<name>", ...fields}`. Rust reads a struct (serde), and the bridge rebuilds the Python dataclass. |
| nodes, and callables (a `log`) | by handle: `{"$node": id, "traits": [...]}`. The receiver holds a client built from the node's interface description. A handle is answered at its owner's dendrites (decision 44), and released explicitly when done. A synapse closing releases all of its handles. No language's garbage collector is assumed. |
| errors | records: `{"$error": "<kind>", "message": "...", "accept": ..., "denied": ..., "status": ...}`. The kind is named as today's class (`CommandError`, `Refused`, `NotEntitled` ...), so every side agrees. Rust maps it to an error enum that keeps the kind, the words, `accept` and the status. The bridge rebuilds the Python class when it can import it, else a `RemoteError` that keeps the builtin base. The platform's 400/502 mapping and a form's second confirmation depend on that. |

### 4.2 Access

1. **Your key.** The synapse's handshake proves both ends hold the user's key, without sending it (§5.3). The key is
   host.py's own file: `LIMINAL_IPC_DIR`, else `~/.liminal/ipc`, then `key`. Only this user's processes connect.
2. **The node's `admits(peer)`.** The hello names who is reaching (its node name, its kind, its scope, its
   process), and the node's policy admits or refuses: who may connect, and how many. A plugin admits its app's
   namespace; an app admits its plugins. This is the attachment policy the user asked for on 2026-11-03 ("plugins
   can regulate which or how many integrators attach to them").
3. **The login's gating.** What a node may do for the signed-in user stays the `Login` trait's (`may`, the pairs),
   as on 2026-11-06: "the app plugins need to use the Abstract Base Class login as the only way to present an
   interface for IPC, between plugins and login and the app as far as AUTHORIZATION".

Reach: this machine only, a named pipe on Windows and a socket file on Linux, as host.py today. The transport is
pluggable, so reaching other machines would be its own decision later (decision 15).

### 4.3 Lifecycle

- **Nothing runs unless used.** A node's process starts at the first request an axon brings it. A disabled plugin
  never starts one. Neither does a node whose only use is its declarations or pure functions (§4.6).
- A synapse with no request and no link for LIMINAL_QUIET_SECONDS (120 s) closes.
- When a node's dendrites hold no synapse any more, the node is told. A resident node then:
  - waits a short grace (10 s, for a page reload);
  - lets a request in progress finish (a setup step);
  - runs `detach` and `shutdown`, securing its data;
  - and its process exits.

  The user, 2026-11-01: "the plugins should have some sort of resident IPC mechanism that tells them when the
  client process is no longer attached, and then presto, the plugin gracefully shuts down after all data is
  secured".
- A synapse that arrives while the node secures its data waits for that end, then starts the node again. It never
  starts a duplicate beside it (decision 83).
- A request still running when its caller is gone (a setup) finishes. Its lines are kept in the node's own log.
- host.py's values stay for its hosts until they move (§4.10): 60 s idle (LIMINAL_IDLE_SECONDS), a 30 s start wait,
  a 5 s client check and a 5 s hello wait. The network's own values are decision 13's.

### 4.4 Real time

| member | what it does |
|---|---|
| `fire(signal, data)` | sends a signal along the axon, to every node linked for it |
| `link(signal, target)` | asks a node to extend its axon to `target`'s dendrites for that signal |
| `unlink(signal, target)` | the reverse |
| `integrate(signal, data, source)` | what a signal arriving at the dendrites does to the node's state. By default a state signal is kept as the latest, a stream signal is appended, and either is fired on to whoever links for it from this node. |

- A status watch inside a plugin's process runs only while something links for its `status`, every 5 s (decision
  22), and fires on change.
- Background readers fire as they read: hw-stats' samples, Namecheap's reader, the Windows firewall's reads.
- The pages keep their own polling: the existing UI is the reference (decision 21). An app answers them from its
  integrated state, so a poll no longer asks every plugin in turn.

### 4.5 Placement

- Within one process, nodes call each other directly. The synapse delivers without encoding, and the semantics stay
  those of the wire, so messages are treated as immutable. A test mode encodes even in-process, to prove that the
  two behave alike (decision 42).
- Each plugin, with its parts, runs as a resident node in a process of its own: its executable (decision 77). Each
  app's nodes live in the app's process.
- A part shared by several plugins can be a node of its own, in its own process, where sharing pays. One `Wsl` for
  the three WSL plugins would give the single shared `wsl --list --verbose` the helpers asked for.

### 4.6 What stays plain functions, and why

"Where it is not a detriment to performance" (the user, on objects). These are ordinary Rust functions inside a
node, never called across the wire:
- **The hot loops and the table work** (Polars, decision 75): the collector's request loops (`sync_bars`, `_fill`,
  `sync_future` ...), the storage queries, derive's aggregation, the calendars' masks (`sessions`), freshness's
  rules, the bad-data rules.
- **Pure functions of declarations and settings**:
  - the delivery scheme, the planners per symbol;
  - an assistant's validity (`keys_set`, `served`, `free_note`, `plan_state`, `rate_window`);
  - a feed's `carries`, `markets`, `served`, `plan_resolutions`, `request_bars`, `report`.

  They run in the caller's process, from the declarations loaded there (§4.7). Answering them remotely would cost a
  round trip per symbol. It would also mean shipping the settings, every variable and other plugins' keys too, to
  each plugin.
- **A feed's DataSource inside its run** (the bars' hot path). The run already is its own resident process
  (`feed-NAME`).
- **Between apps, HTTP on 127.0.0.1 as today**: page to app, the charts front to the integrator, `LoginClient` to the
  login app. `LoginClient` already realizes the `Login` trait over HTTP: it is the HTTP side of the login's
  dendrites.

### 4.7 Declarations stay where the plugin is found

An app holds each plugin's manifest (decision 77). The manifest carries:
- its name, title, version, icon, steps, keys and options;
- its interface description (§6).

Everything a page shows of a plugin that is not behavior is answered from the manifest. So a disabled plugin's
whole page (its row, its Settings, Connections, the tray) is answered without starting its process.

Behavior is every method of the plugin's trait. It is requested from the plugin's process through a client
generated from the trait, so the caller never knows where the plugin runs. A plugin reaches its app and its login
through its own axon.

### 4.8 Synaptic functions

The user: "at each synapse, callbacks or variable functions can be used to filter stimulus our input in order to
logically order output correctly".

```mermaid
flowchart LR
  A[node A fires or requests] --> X[A's axon]
  X -- "sender's end: declared built-ins" --> S((synapse))
  S -- "receiver's end: any function in B's own code" --> D[B's dendrites]
  D --> H[B's hillock integrates]
  H --> N[B's state]
  N -- fires --> O[along B's axon, through its synapses' functions]
```

**What one function is.** It takes one stimulus and gives back none, one, or several. That covers every case:
- dropping one (none);
- passing it on, or reshaping it (one);
- splitting one, or releasing several held back (several).

A function may keep state (what it holds back, the last value it passed), so each function is a small object of its
own. It is not a node, since it has no dendrites of its own (decision 55).

**What the functions do.** Each row is a built-in function. Every language implements the same vocabulary, so it
works whatever the other side of the link is written in (decision 51):

| function | does | e.g. in Liminal |
|---|---|---|
| `only(where)` | passes a stimulus whose fields match (equal, in, less or more than, present) | only an `error` row of the traffic |
| `pick(fields)` / `rename(map)` | reshapes, keeping some fields or renaming them | a status cut to what the platform's list draws |
| `changed(fields)` | passes only when those fields differ from the last passed | a plugin's `status` only when `valid`, `state` or `summary` changed |
| `throttle(seconds)` | at most one per interval, the latest kept | hw-stats' samples at 2 s while the page shows them, 30 s otherwise |
| `debounce(seconds)` | one after a quiet interval, the latest | a burst of firewall rule changes taken as one |
| `in_order(by)` | restores order by a sequence or a time field, holding early ones back until the gap fills or a limit passes | a setup's lines in the order printed; a request's progress before its end |
| `gate(until)` | holds everything back until a condition is met, then releases it in order | a job's lines held until its `started` arrives |
| `batch(n, seconds)` | gathers up to n, or what came within the interval, into one | traffic rows to Connections every 250 ms |

On requests only two of them apply, so a node's interface stays its contract (decision 53):
- ordering: `in_order`, or one at a time per key, so a `stop` never overtakes its `start`;
- refusal: `only`, as an access policy beside `admits`.

The arguments are never reshaped.

**Where they run** (decision 50):
- **At the receiver's end**, in the receiver's own code: any function. In Rust that is a closure; while Python
  remains, a Python callable through the bridge. This is the default.
- **At the sender's end**, so an unwanted signal is never sent at all: only the built-ins, declared as data in the
  `link` (§5.4).
- A callback of a third node (a handle) is possible, but it costs a round trip per stimulus. It is never used on a
  hot link.

**Variable** (decision 52):
- A live link's functions can be replaced (`tune`, §5.4). This is like a synapse's strength changing: the next
  stimulus already meets the new functions.
- The node that made the link may do it, or the receiving node.
- The change is noted in Connections, in its existing text (the link's hover, the Latest table): no new control.

**Ordering, overall** (decision 54):
- Per synapse, stream signals arrive in the order fired. Each carries a sequence number per source and signal, and
  `in_order` restores the order when concurrency mixes them.
- State signals: the latest wins.
- Across synapses there is no global order, unless a function orders by a field both sides share (a time, a job's
  id). That is how the logical order the user asked for is made explicit, link by link.

### 4.9 Python functions in Rust nodes, while Python remains

- A Rust node holds a Python function only through the bridge, and only while its piece still has Python. R8 removes
  them all in the end.
- The node keeps a reference to the function. It takes Python's lock only for the call, while its own threads keep
  reading, filtering and routing.
- A built-in synaptic function runs in Rust, so a stimulus it drops never wakes Python. A slow Python function is
  queued, and never stalls a synapse.

### 4.10 The old protocol beside the new

- host.py's hosts (`fetcher`, `feed-NAME`, `history`, `live`, `mongo`) keep their pipes
  (`\\.\pipe\liminal-<name>-<digest>`) and their pickled dicts until their pieces are ported (Phase 4).
- The network's pipes have a prefix of their own, `liminal-net-`, so an old client never meets a new node on one
  pipe (decision 82). Both use the same key file.
- Moving a host means restarting the tasks that hold its old clients (LiminalCharts, LiminalIntegrator), with the
  user's yes each time.

## 5. The protocol (language-neutral)

### 5.1 Addresses and the key

- **Addresses:** `\\.\pipe\liminal-net-<name>-<digest>` on Windows, `<ipc_dir>/net-<name>-<digest>.sock` elsewhere.
  `LIMINAL_IPC_DIR` never changes a Windows pipe's name.
- **The digest** is host.py's `_digest`: the first 10 hex characters of the SHA-1 of the scope's path, resolved and
  lower-cased. It matches Python's `resolve()`, which resolves paths that don't exist and gives no `\\?\` prefix.
- **The folder:** `<ipc_dir>` is `LIMINAL_IPC_DIR`, else `~/.liminal/ipc`.
- **The key** is `<ipc_dir>/key`: 64 hex characters, used as they are, and any content of 32 bytes or more is
  accepted. It is created once, with create-new, so two first runs can't end with two keys.
- **Windows pipes** run in byte mode with the framing below. The first instance's guard keeps one node per name, and
  the pipe's access list admits this user only (decision 83).
- **Unix sockets:** a stale socket file is removed when nobody answers on it.

### 5.2 Frames

- A frame is a 4-byte big-endian length, then that many bytes of UTF-8 JSON: one message. It is the same on pipes
  and sockets.
- A frame is at most 16 MB. A larger answer is refused with words (decision 45).
- JSON is the encoding (decision 36): Rust's `serde_json`, C++'s `nlohmann::json` and Python's standard library all
  read it.
- CBOR is the binary encoding for later, if measuring shows the need: Rust's `ciborium`, and `nlohmann::json`, which
  speaks it from the same API.

### 5.3 The handshake

Both ends prove they hold the user's key without sending it (decision 39). The reached node's dendrites speak first.

```mermaid
sequenceDiagram
  participant X as axon (reaching)
  participant D as dendrites (reached)
  D->>X: {"op":"challenge","proto":1,"nonce":n1}
  X->>D: {"op":"proof","mac":HMAC(key,"liminal/1|axon|"+n1),"nonce":n2}
  D->>X: {"op":"proof","mac":HMAC(key,"liminal/1|dendrites|"+n2)}
  X->>D: {"op":"hello","node":"wsl-ubuntu","from":{"name":"platform","kind":"app","scope":"…","pid":1234}}
  D->>X: {"op":"admitted","node":"wsl-ubuntu","pid":5678,"interface":{…}}
  Note over X,D: or {"op":"refused","why":"…"}
```

- HMAC is SHA-256, and each proof's label names the side that proves it.
- The nonces are 32 random bytes, in hex.
- A wrong proof closes the connection, and nothing about the key is said.
- Each handshake runs in its own task, so a slow one never holds up the others (decision 83).

### 5.4 The messages after the hello

| op | from → to | shape | what it does |
|---|---|---|---|
| `request` | axon → dendrites | `{"op":"request","id":7,"node":"wsl-ubuntu","method":"status","args":[],"kwargs":{}}` | calls an interface method; `"handle":12` instead of `"node"` reaches a handle |
| `answer` | dendrites → axon | `{"op":"answer","id":7,"value":…}` | the request's answer |
| `error` | dendrites → axon | `{"op":"error","id":7,"error":{"$error":…}}` | the request failed |
| `fire` | axon → dendrites | `{"op":"fire","signal":"status","from":"wsl-ubuntu","seq":42,"data":…}` | a signal, along the firing node's axon |
| `link` / `unlink` | axon → dendrites | `{"op":"link","signal":"status","to":{"node":"platform","scope":"…"},"functions":[{"fn":"changed","fields":["valid","state","summary"]}]}` | asks the node to extend its axon to `to`'s dendrites for that signal. `functions` are the built-ins run at the sender's end (§4.8) |
| `tune` | axon → dendrites | `{"op":"tune","signal":"status","to":{…},"functions":[{"fn":"throttle","seconds":2}]}` | replaces a live link's sender-end functions |
| `release` | either | `{"op":"release","handles":[12,13]}` | handles no longer held |
| `detach` | axon → dendrites | `{"op":"detach"}` | the axon lets go; the connection closes after |

- Requests from one axon run concurrently at the dendrites, as today's threaded servers do, so answers return
  matched by id, in any order (decision 48).
- A request has no timeout unless its caller gives one, since a setup step can take hours (decision 47).
- A synapse closing fails every request in flight with an error record.

### 5.5 The wire's types

Decisions 70 to 73:
- **Integers and floats are distinct.**
  - An integer is written without a fraction or an exponent, and read as a 64-bit integer.
  - A float always carries a fraction or an exponent (`1.0`), and is read as a 64-bit float.
  - A nanosecond timestamp (about 1.8 × 10^18) needs the integer, since a float holds integers exactly only up to
    2^53.
- **A map's keys keep their order**, as Python's dicts do. In Rust this is `serde_json`'s `preserve_order`.
- **NaN and the infinities are written as null**, as the charts server already does for the page (`gui/server.py:40`).
- **Time** is ISO-8601 text, **bytes** are base64 text, and **a set** crosses as a list. The description's types
  (§6) say which applies.

### 5.6 Versions

- The hello's `proto` is 1. A node refuses a newer major version, with words (decision 46).
- Old host.py clients never reach the network's pipes (§4.10).

### 5.7 Test vectors

They are written with liminal-net 0.1:
- frames;
- the handshake, with a fixed key and fixed nonces;
- one of each op.

The Rust tests check them, and so do the bridge's.

## 6. Interface descriptions (the IDL)

- **The source is each node's Rust trait** (decision 38). A derive writes each trait's description as JSON, and
  `liminal-net describe` writes them all.
- **From the descriptions come:**
  - the Rust clients, generated;
  - the bridge's view for Python;
  - later, a C++ abstract class per trait.

  A trait, an ABC and a pure-virtual class are the same idea.
- **Each method also carries the text the pages show today.** That is Python's signature string, as `/api/plugins`
  and `/api/interface` show it, so the pages stay the same (decision 86).

```json
{"trait": "liminal.MachinePlugin", "base": ["liminal.PlatformPlugin"],
 "methods": {"present": {"args": [], "returns": "bool"},
             "status": {"args": [], "returns": "map"},
             "setup": {"args": [{"name": "log", "type": "node:callable"},
                                {"name": "steps", "type": "list<text>|null", "default": null}],
                       "returns": "list<map>"}},
 "signals": {"status": {"kind": "state", "data": "map"}}}
```

The types (decision 40). The old `number` type is gone, because Rust has to know an integer from a float
(decision 70):

| type | Rust | Python, through the bridge |
|---|---|---|
| `text` | `String` | `str` |
| `int` | `i64` | `int` |
| `float` | `f64` | `float` |
| `bool` | `bool` | `bool` |
| `null` | `None` of an `Option` | `None` |
| `list<…>` | `Vec<…>` | `list`, `tuple` |
| `set<…>` | `IndexSet<…>`, a list on the wire | `set` |
| `map` | `IndexMap<String, Value>`, with its keys in order | `dict` |
| `time` | `chrono::DateTime<Utc>`, ISO-8601 text on the wire | `datetime` |
| `bytes` | `Vec<u8>`, base64 text on the wire | `bytes` |
| `record:<name>` | a struct (serde) | a library dataclass |
| `node:<trait>` | a client, by handle | a proxy, by handle |
| `node:callable` | a callable, by handle | a callable, by handle |

## 7. The paradigm in code (R2)

- A node implements its trait. Its code never reaches into another node's state.
- It requests through its axon. The generated client's methods are named as the other node's interface, so the
  calling code stays readable: `app.machines()`, `login.variables(&[...])`. Underneath, and for other languages, it
  is the explicit form, `request(method, args)`.
- It reacts to signals in `integrate`, and fires its own with `fire`.
- Whether node code is async or plain is decision 60.

```mermaid
classDiagram
  class Hillock {
    <<trait>>
    name()
    interface()
    integrate(signal, data, source)
    admits(peer)
    attach(peer)
    detach()
    shutdown()
  }
  class Node {
    dendrites
    axon
    request(target, method, args)
    fire(signal, data)
    link(signal, target)
  }
  class Plugin { <<trait>> name(); title() }
  class FeedPlugin { <<trait>> build() }
  class PublisherPlugin { <<trait>> policy() }
  class AssistantPlugin { <<trait>> assistant() }
  class MachinePlugin { <<trait>> present() }
  class Firewall { <<trait>> backend() state() list_rules() add_rule() delete_rule() enable() exposing() }
  class Admin { <<trait>> elevated() services() startups() processes() }
  class WslDistribution { <<trait>> distribution(); family() }
  class App { <<trait>> api() }
  class Login { <<trait>> user() vector() }
  class DataSource { <<trait>> bars() … }
  class Assistant { <<trait>> headers() body() parse() }
  Hillock <|-- Plugin
  Plugin <|-- IntegratorPlugin
  Plugin <|-- PlatformPlugin
  IntegratorPlugin <|-- FeedPlugin
  IntegratorPlugin <|-- PublisherPlugin
  PlatformPlugin <|-- AssistantPlugin
  PlatformPlugin <|-- MachinePlugin
  MachinePlugin <|-- Firewall
  MachinePlugin <|-- Admin
  MachinePlugin <|-- WslDistribution
  Hillock <|-- App
  Hillock <|-- Login
  Hillock <|-- DataSource
  Hillock <|-- Assistant
  class Synapse {
    functions
    tune(functions)
  }
  class SynapticFunction {
    <<trait>>
    apply(stimulus) list
  }
  Node o-- Hillock : runs
  Node *-- Dendrites
  Node *-- Axon
  Axon --> Dendrites : a synapse
  Synapse o-- "0..*" SynapticFunction
```

## 8. The inputs and outputs kept (R1)

### 8.1 The listeners

| listener | default port | `Server:` header today (plus ` Python/3.x.y`) |
|---|---|---|
| the charts front (`liminal-charts gui`) | 8765 (`--port`) | `liminal-front` |
| the platform | 8775 (`LIMINAL_PLATFORM_PORT`, `--port`) | `liminal-platform` |
| the integrator's page and data API | 8785 (`LIMINAL_FETCHER_PORT`; 0 is a free port, `none` or `off` no page) | `massive-chart` |
| the login, for charts and for the integrator | 8795 and 8796 (`LIMINAL_LOGIN_PORT`, then its cfg file's `port`) | `liminal-login` |
| MongoDB, when used | 27017 (`LIMINAL_MONGO_PORT`) | — |

Every server binds 127.0.0.1 only. If something already answers on its port, it takes a free port instead.

### 8.2 The frame's rules, kept by every app

- **The server:** HTTP/1.0, one response per connection, a thread per request (`ThreadingHTTPServer`). It accepts
  GET, POST, PUT and DELETE only.
- **Headers on every answer:** `Server`, `Date`, `Content-Type`, `Content-Length`, `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff`. There is no CORS header and no frame header, because the charts sign-in page
  embeds `/login/?embedded=1` in an iframe.
- **The Host check:** `127.0.0.1` or `localhost`, else 403 `forbidden`, static files included.
- **On `/api/`:** `Sec-Fetch-Site` is absent, `same-origin` or `none`, and `Origin` is absent or `http://<Host>`,
  else 403 `forbidden: not from this app's pages`.
- **Writes** carry `X-Liminal-Charts: 1`, else 403 `missing request header`.
- **Request bodies:** a decimal `Content-Length` (else 400), at most 5 MiB (else 413), and a JSON object (else 400).
- **Query strings:** the last value of a key wins, and blank values are dropped (`parse_qs`).
- **Errors:** a refusal answers `{"error": reason}` with its status. Anything else gives 500 `{"error": "<app> could
  not answer; see its log"}`.
- **JSON:** no NaN (`allow_nan=False`).
- **Static files:** `/` serves `index.html`. Other paths are looked up in the app's own folder, then in the
  library's `ui/static`. Text and JavaScript types get `; charset=utf-8`, unknown types are
  `application/octet-stream`, and a missing file is 404 `not found`.

### 8.3 Each app

**The frame's own routes** (every app): `GET /api/tray`, `/api/app`, `/api/plugins`, `/api/interface`,
`/api/traffic?last=N` (N ≤ 400) and `/api/ui`.

**The platform** (`liminal_platform`, Phase 2):
- **Routes:**
  - `GET /api/status`, `GET /api/machines`, `GET /api/instances`;
  - `POST /api/plugins/<name>/settings` `{values, forget}`, `/enabled` `{on}`, `/hidden` `{on}`;
  - `GET /api/machines/<name>`, `GET …/setup`, `GET …/check`, and `GET …/job?since=&wait=`, a long poll held at
    most 5 s;
  - `POST …/job` `{action: install|update}` (202), `POST …/setup` `{steps}` (202), `POST …/ask` `{hook, args}` (a
    refusal: 400 or 502 `{error, words, accept}`), `POST …/enabled` `{on}`, `POST …/run` `{command}`;
  - `POST …/terminal`, `GET …/terminal?since=&wait=` (a long poll), `POST …/terminal/input` `{data}`,
    `POST …/terminal/close`. Each read answers `{text, from, offset, alive, title}`.
- **Answers:**
  - each machine's `{name, title, about, version, status, icon, enabled, valid, why, state, hidden, steps, asks,
    hooks, setup, terminal, settings}`;
  - each assistant's `{name, title, about, version, vendor, icon, model, enabled, valid, why, state, hidden,
    settings}`;
  - the status's `{app, machine, docker, machines, active, disabled, assistants, instances, plugins}`;
  - Connections' `{app, now, since, seq, classes, links, recent, nodes, hidden}`.
- **Commands:** `liminal-platform serve [--port] [--no-browser] [--until-quiet]`, `liminal-platform status`,
  `liminal-platform machine NAME status|setup|run|instances|enable|disable …`.
- **Files:** `LIMINAL_PLATFORM_DIR` (else `<data>\platform\`) holds `plugins.json` (`{disabled, hidden}`, written
  with `indent=1` through a `.part` file) and `logs\platform.log`. Plugin settings go to `HKCU\Environment`.

**The login** (`liminal_login`, Phase 3):
- 16 routes of its own, among them `/api/status`, `/api/signup` and its steps, `/api/sign-in`, `/api/me` and
  `/api/pairs`.
- Its cookie: `liminal_login_<namespace>`, `HttpOnly`, `SameSite=Strict`.
- Its session header: `X-Liminal-Session`.
- Its commands: `serve`, `init`, `server`, `status`, `user`, `mail`.
- Its files: `users.db`, one vault per user, DKIM keys, `liminal-login.cfg`.
- Its vaults stay readable: scrypt (n=2^15, r=8, p=1) and AES-256-GCM, with the same parameters.

**The charts data API**, which is also the integrator's page in fetcher mode (Phase 4):
- 43 GETs, 28 writes, and `/api/stream` (server-sent events: a poll every 0.5 s, `: keep-alive` every 15 s, an end
  after 300 s);
- the front's proxying, and its `/api/trays` and `/api/ui`;
- the profile cookie `mc_profile`;
- the error mapping: 400, 404, 409, 429, 403, 502, 503 and 500;
- 39 subcommands of `liminal-charts`.

**The integrator** (Phase 4): `GET /api/databases` and `/api/databases/detail`, and `liminal-integrator`'s
`fetcher` and `service` commands. The fetcher's old asks (`status`, `pass`, `wake`) and their answers stay on
host.py's pipe until it moves (§4.10).

**The data**, unchanged:
- `liminal.db`;
- `feeds/<feed>.db`, `-ticks.db` and `composite.db`;
- `history/<feed>/<YYYY-MM>.<n>.duckdb`;
- datasets, `gov/gov.db`, and MongoDB's `liminal` database;
- `logs/liminal.log`;
- the lock files (`pid starttime`);
- the `kv` keys shared between processes;
- `~\.liminal\request-windows.db`, and the IPC key.

### 8.4 The goldens, and Python's byte-level details

- The goldens are recorded from today's Python, black-box. A recorder drives each app over HTTP and through its CLI,
  on scratch fixture data, never `store\data`. A Rust piece passes its piece's goldens before it replaces it
  (decision 78).
- My recommendation on what is kept exactly, and what may differ:

  | kept exactly | allowed to differ |
  |---|---|
  | statuses, JSON shapes and key order; `json.dumps`' separators (`", "`, `": "`), `\uXXXX` escapes and float repr; pandas' `to_json` (10 decimals, NaN as null, integer columns with a null read as floats) and `Timestamp.isoformat()` (decision 85); error words; cookie attributes; every file's format | the `Server` header's `Python/3.x` suffix; `Date`; HTTP/1.1 where today's answers are HTTP/1.0; the stdlib's HTML pages for 501 and malformed requests; the `python` fact in `/api/status`; the row estimates in `/api/databases/detail`, which come from Python's seeded `random` unless its generator is reproduced |

## 9. The migration path

| phase | repositories | old form | new form |
|---|---|---|---|
| 0 | liminal-libs | this document, for Python on a Rust core | this document, for Rust everywhere, reviewed |
| 1 | liminal-net 0.1 (new, local) | host.py's pickled dicts | the network in Rust (§3.4), `cargo test`, the test vectors |
| 1b | liminal-net 0.2 | — | the bridge: a Python object as a node |
| 2 | liminal-libs, liminal-platform, the 21 plugins the platform shows | Python, the plugins inside the platform's process | the 42 library modules the platform needs, ported in order; the platform's executable; each plugin's executable, one at a time; the Python plugins on the bridge until each is ported |
| 3 | liminal-login | Python | Rust, its vaults kept readable |
| 4 | liminal-integrator, the charts data API, the storage, the calendars | Python, and host.py's hosts | Rust, the hosts on the network (the restarts on the user's yes) |
| 5 | liminal-charts | Python and pandas | Rust and Polars |
| 6 | the 15 feed plugins | Python | Rust |
| 7 | liminal-net | the bridge | retired |

The traits, each with what it must implement. These are today's ABCs, under the same names:

| trait | module | required |
|---|---|---|
| `Plugin` (→ `IntegratorPlugin`, `PlatformPlugin`) | `sources/plugin` | `name`, `title` |
| `FeedPlugin` | `sources/plugin` | `build` |
| `PublisherPlugin` | `sources/publisher` | `policy` |
| `AssistantPlugin` | `assistants/plugin` | `assistant` |
| `Assistant` | `assistants/assistant` | `headers`, `body`, `parse` |
| `MachinePlugin` | `machines/plugin` | `present` |
| `Firewall` | `machines/firewall` | `backend`, `state`, `list_rules`, `add_rule`, `delete_rule`, `enable`, `exposing` |
| `Admin` | `machines/admin` | `elevated`, `elevation`, `services`, `startups`, `processes`, and the four service and startup actions |
| `WslDistribution` | `machines/wsl` | `distribution`, `family` |
| `App` | `apps/app` | `api` |
| `Login` | `apps/authorization` | `user`, `vector` |
| `DataSource` | `sources/base` | its six |
| `Argument` (a message, not a node) | `assistants/arguments` | `prompt`, `from_dict` |

## 10. The decision log

Every row is **open** until the user decides it, unless it is marked decided or retired.

| # | question | options | recommended, and why | state |
|---|---|---|---|---|
| 1 | The root's name and home | `Hillock`; another name | `Hillock`, the user's word. With Rust everywhere it is liminal-net's node trait, `liminal_net::Hillock` | **decided**: "Hillock in ipc/"; its home moved to liminal-net with the rewrite |
| 2 | The connection's name | "synapse"; "link"; another | "synapse": where an axon meets a node's dendrites | **decided**: "synapse" |
| 3 | The "not all" | messages are data, not nodes; everything a node | messages are data: a status sent by handle would cost a round trip per field read | **decided**: messages are data |
| 4 | The direction | the user's first one (the axon as input); biology's | — | **decided**: biology's. The dendrites are a node's input; the axon is its output, reaching other nodes' dendrites |
| 5 | A node's side | declared on each trait; no declaration | — | **decided**: "the nodes have to find a way to self organize" (how: 67) |
| 6 | The interface bases become nodes | all; some | all: the Plugin family, App, Login, DataSource, Assistant | **decided**: all |
| 7 | The parts become nodes | all, after the platform slice; a few | all, after the slice is proven | **decided**: after the platform slice |
| 8 | The library's other classes | case by case; all | case by case: a stateful object others talk to is a node, and a value or a pure calculation is not | **decided**: case by case |
| 9 | What stays plain functions | §4.6's list; fewer | §4.6's list, for performance | open |
| 10 | Processes for plugins | one each; grouped | one each, its executable, for isolation. A Rust node's memory is measured in Phase 2 (Python's take 30–45 MB) | open |
| 11 | Shared parts as nodes of their own | where sharing pays; never | where sharing pays: one `Wsl` | open |
| 12 | Nodes in one process | direct calls; always through the dendrites | direct: hot loops pay nothing | open |
| 13 | Starting and letting go | at the first request, and after 120 s quiet, with a 10 s grace; host.py's 60 s idle | at the first request, quiet 120 s: nothing runs unless used | open |
| 14 | Address scope | the reaching app's state (its database or folder), through host.py's digest; the user's | the reaching app's state: previews stay apart, and each login serves only its own plugins | open |
| 15 | Reach | this machine only; other machines too | this machine only for now, with the transport pluggable. The user did not answer this one | open |
| 16 | *(replaced by 36: pickle is Python-only, and R3 rules it out)* | | | — |
| 17 | Nodes and callables in messages | by handle, released explicitly; by copy | by handle: a node is live state | open |
| 18 | Default access | a plugin admits its app's namespace, and an app admits its plugins; anyone with the key | as recommended | open |
| 19 | Errors | records whose kind is named as today's class, mapped to an error enum in Rust and rebuilt as classes on the bridge; text only | records: the platform's 400/502 and `accept` depend on the kind | open |
| 20 | Coalescing state signals | 250 ms; another interval | 250 ms | open |
| 21 | Pushing to the pages | keep polling; server-sent events | keep polling: the existing UI is the reference | open |
| 22 | A plugin's status watch | 5 s while linked; other | 5 s while linked, and at once on a background reader's change | open |
| 23 | The abstract members | | becomes the traits' required methods (§9's table) | retired |
| 24 | Records (`Provider`, `Publisher`) with `record_form` | | records are structs | retired |
| 25 | The plugin API's version | 3.0 for Rust plugins, with 2.x still loading through the bridge; 2.2 | 3.0: a plugin is a node now | open |
| 26 | `App.api` abstract | | becomes a trait method | retired |
| 27 | A plugin's process ending | 10 s after its last synapse, a request in progress let finish; at once | 10 s, and let finish | open |
| 28 | A setup outliving the platform | finishes, its lines in the node's log; stopped | finishes: a half-done install is worse | open |
| 29 | host.py rebuilt on the network | | the bridge period (§4.10) | retired |
| 30 | Old dict asks | | stay on host.py's own pipes until each host moves (§4.10) | retired |
| 31 | An in-process fallback | | the bridge period: a piece switches once its goldens pass | retired |
| 32 | Versions: libs 1.41/1.42, platform 0.15, integrator 1.9 | | 81 | retired |
| 33 | The integrator's and charts' first moves | the FetcherService, the plugins' jobs, "Try it"; re-planned with Phase 4 | re-planned when Phase 4 starts | open |
| 34 | Feed runs, scans, extras, recorder | processes as now, nodes in Phase 4; earlier | in Phase 4 | open |
| 35 | Tests | stand-ins only, and a live check on a scratch preview | as listed | open |
| 36 | The wire's encoding | JSON; CBOR; MessagePack; Protocol Buffers; Cap'n Proto | JSON: every language reads it, and it is readable. CBOR later if measured | open |
| 37 | How other languages link in | Rust nodes link liminal-net; C++ through its C ABI; Python through the bridge while it remains | as listed | open |
| 38 | The IDL's source | the Rust traits, the JSON generated from them; a hand-written schema; Protocol Buffers, Cap'n Proto, Thrift | the traits: the Rust is the single source | open |
| 39 | The handshake | our own HMAC-SHA256 challenge, documented; `multiprocessing`'s | our own (§5.3) | open |
| 40 | Types in descriptions | from the Rust types (§6's table); untyped | from the Rust types | open |
| 41 | Python proxies named as the interface | | becomes a Rust client per trait, generated (§7) | retired |
| 42 | In-process delivery | direct, with a test mode that encodes; always encoded | direct, with the test mode | open |
| 43 | Signal kinds | state (coalesced, latest wins) and stream (every item, in order); one kind | both: a status is state, and a setup's lines are a stream | open |
| 44 | Where a handle is answered | at its owner's dendrites (a synapse each way when both sides start conversations); on the same connection both ways | at its owner's dendrites: every link stays directed | open |
| 45 | Frames | 4-byte big-endian length and UTF-8 JSON, at most 16 MB; other | as recommended | open |
| 46 | Protocol versions | `proto` in the hello, a newer major refused with words | as recommended | open |
| 47 | Request timeouts | none unless the caller gives one; a default | none by default: a setup step takes hours | open |
| 48 | Ordering | concurrent per axon, answers matched by id; one at a time | concurrent, as today's threaded servers | open |
| 49 | Synaptic functions | a chain at each synapse, applied in order to every stimulus before the receiving node takes it in; none | a chain at each synapse (R7) | open |
| 50 | Where they run | the receiver's end by default (its own code, any function); the sender's end only as declared built-ins; anywhere | as recommended: a receiver's function never leaves its process, and an unwanted signal need not be sent | open |
| 51 | The built-in vocabulary | `only`, `pick`/`rename`, `changed`, `throttle`, `debounce`, `in_order`, `gate`, `batch`; more | these eight, extended when a case needs one; every language implements the same set | open |
| 52 | Variable functions | replaceable on a live link (`tune`) by its maker or the receiving node, noted in Connections; fixed per link | replaceable: the user's "variable functions" | open |
| 53 | On requests | ordering and refusal only; everything, reshaping included; nothing | ordering and refusal only: the interface stays the contract | open |
| 54 | Order across the network | per synapse (streams in order, state latest-wins), global only through a function ordering by a shared field; a global clock | per synapse, with functions for the rest | open |
| 55 | What a synaptic function is | an object of the synapse's (a `SynapticFunction` trait, not a node); a node of its own | the synapse's own: it has no dendrites of its own to be reached at | open |
| 56 | Showing them | in Connections' existing text (a link's hover, the Latest table); a new control | the existing text: the existing UI is the reference | open |
| 57 | Python on a Rust core | | becomes Rust everywhere (R8) | retired |
| 58 | Where liminal-net lives | its own repository, local at `source\liminal\net`, on GitHub on the user's yes; inside liminal-libs | its own repository: every repository's crates depend on it. Creating the GitHub repository needs the user's yes | open |
| 59 | PyO3 bindings for the Python on top | | the bridge only (62) | retired |
| 60 | Node code | async on tokio; plain functions run on worker threads | plain functions on worker threads, with tokio inside liminal-net: today's code is synchronous, so its ports read the same | open |
| 61 | Python callbacks from Rust | | the bridge only (§4.9) | retired |
| 62 | The bridge | PyO3 bindings of liminal-net (abi3, maturin); a small pure-Python speaker of the protocol | PyO3: one implementation of the network, checked once | open |
| 63 | The toolchain here | rustup's stable MSVC toolchain (the VS 2022 C++ tools give the linker); the GNU toolchain | the MSVC toolchain | **decided**: the user installed it on 2026-11-09 (rustup 1.29.3, `stable-x86_64-pc-windows-msvc`, rustc and cargo 1.99.1, in `~\.cargo\bin`). maturin comes with the bridge (a PyPI download: the user's yes then) |
| 64 | The repositories' CI | every repository builds its crate; wheels only | every repository builds its crate | open |
| 65 | C++ | the crate's C ABI (cbindgen's `liminal_node.h`); a C++ port of the core | the C ABI: still one implementation | open |
| 66 | The order with Rust | | set by the user's scope answers (§1) | retired |
| 67 | How nodes organize their side | from their links and what they touch, recomputed as links change; also announced by the nodes | from links and touches (§3.1): nothing to declare, and Connections shows it | open |
| 68 | How Python processes start | | the bridge period: Python-started processes while Python remains | retired |
| 69 | Python classes on a Rust node: composition | | the bridge only | retired |
| 70 | Integers and floats | `int` (64-bit) and `float` (64-bit) apart; one `number` | apart: nanosecond timestamps need the integer, and the data specs already say `int64` (`sources/data.py:325`) | open |
| 71 | Key order | kept (`serde_json`'s `preserve_order`); sorted | kept: Python keeps insertion order, and the outputs stay as they are | open |
| 72 | NaN and infinity | null; a tagged value | null, as the charts server does for the page (`gui/server.py:40`); the library's `web.py:59` refuses them | open |
| 73 | Time, bytes, sets | ISO-8601 text, base64 text, a list; other | as listed | open |
| 74 | The HTTP side | axum (on hyper); hyper alone; tiny_http | axum: routing reads like today's tables, and every header and check of §8.2 is kept | open |
| 75 | Tables | Polars for the pandas work and ndarray for numpy; DataFusion | Polars and ndarray | open |
| 76 | The calendars' port | from exchange_calendars 4.13.2's rules (Apache-2.0, its notice kept), checked against the Python's sessions for every exchange over decades of dates; by hand from the exchanges' notices | from exchange_calendars' rules, checked | open |
| 77 | How an app finds its Rust plugins | each plugin a node executable of its own, found by a manifest, enabled and disabled as `plugins.json` does; compiled into the app; dynamic libraries | executables with manifests: compiled in would break the separate repositories, and dynamic libraries have no stable Rust ABI and would put plugins back into the app's process | open |
| 78 | The goldens | recorded from today's Python, black-box, on scratch fixtures, and kept in each repository's tests; with §8.4's details kept exactly | as recommended | open |
| 79 | Crates and toolchain | edition 2024 on Rust 1.99 stable, the dependency list approved once; per crate as needed | edition 2024 on stable; the list approved once, before the first build | open |
| 80 | This document's home | liminal-net, as the protocol's specification, once its repository exists; liminal-libs | liminal-net: the specification beside its implementation, and liminal-libs keeps a pointer | open |
| 81 | The new crates' versions | each new crate from 0.1.0, the Python's versions counting on until retired; the crates taking the Python's next major | 0.1.0 for each new crate | open |
| 82 | The network's addresses | a new prefix, `liminal-net-`, with host.py's digest; host.py's names | the new prefix: old pickle clients and new nodes never meet on one pipe | open |
| 83 | host.py's known flaws | fixed; copied | fixed: the handshake holding up the accept thread, stale socket files, a duplicate host starting while one secures its data, a bad pid in the hello, the pipe's default access list, the key's creation race | open |
| 84 | liminal-libs' Rust layout | a workspace of four crates (core, storage, contract, engine), every module keeping its name; one crate | four crates: a platform plugin builds against core and contract only. Today any platform plugin loads pandas just by importing `machines.plugin`, through `sources/__init__` | open |
| 85 | pandas-shaped output | reproduced by hand where the charts and the CLI show it (`to_json` records, `Timestamp.isoformat()`, `to_csv`, `to_string`); Polars' own formats | reproduced: the outputs stay as they are | open |
| 86 | Hook signatures | the descriptions carry today's Python signature text; text generated from the Rust | carried: `/api/plugins` and `/api/interface` show the same | open |
| 87 | Connections' attribution | from the network's links (every synapse, its two ends and its process); an audit-hook equivalent | from the links: the same columns, filled from what the network knows | open |
| 88 | The workspace | from the executable's location, with `LIMINAL_HOME` and `LIMINAL_DB` as today; from the working folder | the executable's location, as `layout.py` uses its own file's | open |
