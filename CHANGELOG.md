# Changelog

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
