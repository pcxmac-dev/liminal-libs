"""What every harness plugin of the platform shares (1.62.0; the user, 2026-11-16: "i also need 3 harness plugins for
the platform :: OpenCode, Aider, and Continue"; "they will be classified as AI plugins"; "all three plugins need to
allow installation and configuration of their respective code").

`Harness` is the base, under AiPlugin (machines/ai.py: the install, its folder, the pairs kept through the login, no
pair of Liminal's in a child), of a coding agent's plugin, drawn under the platform's AI heading among the harnesses
(GROUP "harness"). A subclass says how its tool is started against one model server (`launch`), whether it can use one
(`fits`), what it must say before each start (`open_words`) and what more its Main shows (`main_more`). The base gives
the rest (DECISIONS A.12: "configure against an instance of the inference plugins (asked through the platform, plugin
to plugin); and open the harness in a terminal in a folder the user picks"):

- The model servers it can be started against (`servers`): what each attached plugin that answers `serving` says it
  serves, asked through the platform (`app.ask(name, "serving", [])`), never through a plugin's object and never by
  importing one; a plugin that refuses is left out, its words in the table's note. Kept SERVING_S, asked again at a
  click. Nothing is asked over the network for it: a model server answers `serving` from what it holds.
- Use…: one instance, a model and the tool's own options (OPTIONS, ai.Setting), kept through the login as one pair,
  LIMINAL_AI_<NAME>_USE: {"v": 1, "server", "model", "folder", "options"} (`use_kept`). Nothing is written into the
  tool's own configuration: the plugin's `launch` hands it over at each start.
- Open…: the tool started in a folder the user types (the page has no folder picker; the last one is kept). On Windows
  with a desktop it gets a console window of its own, the one window a plugin opens and only because it is asked for:
  `python -m liminal_libs.console hold -- COMMAND ...`, which keeps the window until its user has read how the tool
  ended; closing it ends the tool. Anywhere else (Linux, a WSL distribution, a platform without a desktop: a boot
  service) no window can be opened, and the answer is the lines to paste into a terminal of the user's
  (children.shown). Command… shows those lines on both, without starting anything. A folder on another system's
  drive is refused (that system's platform opens it), and so is a local instance that is not running or one found
  here that answers nothing (Command… still shows its lines, for later). The lines unset what the launch drops as a
  new terminal has it (on Windows the user's saved variables too), and a launch PowerShell 5.1 would not hand its
  words as they are is refused in words (children.not_passed).
- No pair of Liminal's reaches the tool: every variable an installed plugin declares and every LIMINAL_* name are
  dropped from its environment (AiPlugin.dropping), with what its plugin's launch drops itself (the hosted providers'
  keys). A server's key, kept by its inference plugin as a pair of its own (the `serving` row names its variable,
  never the key), is read through the login only to start a window, and is handed to the tool in its environment
  alone: a launch that would put it on the command line is refused. In the lines to paste it is the placeholder its
  user types (children.PLACEHOLDER); it is in no answer, no log and no line.
- Its Main: the install's facts and forms (AiPlugin's), what it uses ("uses"), the folder it opens in ("opensIn"),
  how it opens ("opens"), the plugin's own tables first (main_more: "Before you use it"), then the Model servers table
  (Server, Instance, Address, State, Models, a Use… button and an Ask… button for each instance), and the forms ai-use,
  ai-open, ai-command and ai-models. A status asks nothing over the network and starts nothing.

The windows it opened are followed while they are open (`running`), so Install and Uninstall wait until they are
closed; nothing ends them when the platform stops: a window is its user's. A window is asked to leave any job object
the platform is held in (a keeper's ends what it holds with itself); where the job lets nothing leave it, the window
is opened in it all the same, and Open… says that it ends with that program.

1.66.0 (the user, 2026-11-18: "top 4 inference engines, top 4 agentic harnesses (open source)", "both linux and
windows compatibility", and an MCP plugin "that mediates MCP connections to resources by local AI agents"):

- A window on Linux too. A window opens where the platform's environment has a display (DISPLAY or WAYLAND_DISPLAY;
  WSLg sets both, and the window then opens on Windows' desktop) and a terminal program of TERMINALS is on its PATH.
  It is found with shutil.which, which looks at files and starts nothing, since a status asks at every draw. Each
  terminal is one whose flag hands the rest of the line over as separate words, so no shell reads the command.
  x-terminal-emulator is used only when its link leads to one of them. The terminal starts in a session of its own,
  and keeps the display's variables whatever its launch drops. Without a display or a terminal (a boot service),
  Open… still answers with the lines to paste.
- Liminal's MCP, for a harness that offers it (MCP_OPTION among its OPTIONS, and MCP_WIRES). It is off unless Use…
  turns it on. Then the MCP plugin is asked through the platform how it is reached (client_offer) and for this
  harness's agent (ensure_client). Each Open… that opens a window asks it for a token for that window alone
  (launch_token), and ends that token once the window is gone (end_launch), at a status or at the platform's stop.
  The token reaches the tool in LIMINAL_MCP_TOKEN alone, a secret of its launch: never on its command line, in a
  file or in the lines to paste. Command… gives none. A plugin's launch asks `mcp_wiring` how to write its MCP part.
- Values a harness would read as more than text are refused (critique 1): a model's id, an option's text and every
  value a plugin writes into its tool's configuration (`clean_value`) hold none of OPENERS (${, $(, {env:, {file:,
  ${{) and do not begin with "!". A plugin adds its tool's own openers (Harness.OPENERS)."""
from __future__ import annotations

import contextvars
import copy
import dataclasses
import json
import os
import posixpath
import re
import subprocess
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from .. import console, instances, mounts
from ..apps import authorization
from . import ai, children, windows
from .ai import Refusal, Setting  # noqa: F401 - Setting: a harness's OPTIONS are ai.Setting (re-exported for plugins)

SERVING_S = 30.0  # what the model servers say they serve is kept this long between two asks of the page
SERVING = "serving"  # the hook a model server answers with what it serves (machines/modelserver.py's)
MODELS_OF = "models_of"  # the hook that asks one of its instances for its models now
NEW_CONSOLE = 0x00000010  # CREATE_NEW_CONSOLE: a harness's window, the one window a plugin opens
BREAKAWAY = 0x01000000  # CREATE_BREAKAWAY_FROM_JOB: out of a job the platform is held in (a keeper's), where it may
HELD_WORDS = ("the platform is held in a job object that lets nothing leave it (a keeper's), so the window ends when "
              "that program ends")
STOPPED = ("stopped", "exited")  # a local instance in one of these states is not running
SILENT = "silent"  # an instance found running here that nothing answers at now (machines/modelserver.py's word)
USE_VERSION = 1  # of the choice kept (LIMINAL_AI_<NAME>_USE)
MODEL_CHARS = 256  # characters of a model's id
FOLDER_CHARS = 1024  # characters of a folder typed
NOTE_CHARS = 300  # characters of one plugin's words in the table's note
MODELS_SHOWN = 4  # model ids named in a row of the Model servers table
WINDOWS_KEPT = 16  # windows followed at most
TOKENS_KEPT = 64  # windows' launch tokens followed at most: past it the oldest is ended at once
# a key this long is looked for inside other text, a shorter one only as a whole word or after a word's "=" (a folder's
# or a file's name may hold a short key's letters by chance, as my-test-app holds "test")
KEY_INSIDE = 16
SERVER = re.compile(r"^([a-z0-9][a-z0-9-]{0,63})/([a-z0-9][a-z0-9-]{0,31})$")  # <plugin>/<instance>
VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")  # a pair's variable, as a `serving` row names a key's
RUN_IT = "Run it in a terminal of yours"
NO_APP = "no model server can be asked: this plugin is not attached to the platform"
NO_SERVER = ("no model server is offered here: an instance of an inference plugin (AI plugins, Inference) is what a "
             "harness is started against")
CHOOSE = "choose a model server first: Use…"
WHERE_WORDS = {"local": "runs here", "found": "found running here", "remote": "on another machine"}
EXAMPLES = {"windows": "C:\\Users\\you\\project", "linux": "/home/you/project"}
OPENS = {True: "in a terminal window of its own, in the folder you give",
         False: "no window from here: Open… shows the command, to run in a terminal of yours"}

# -- a window on Linux (1.66.0) ---------------------------------------------------------------------------------------
DISPLAYS = ("DISPLAY", "WAYLAND_DISPLAY")  # one of them set: the platform has a desktop (WSLg sets both)
# what a window's terminal is given from the platform's environment whatever its launch drops: it opens its window
# with them (the display, the folder that holds the Wayland socket, the session's bus)
DESKTOP_KEEPS = ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
ALTERNATIVE = "x-terminal-emulator"  # Debian's link to the terminal its user chose: used when it leads to one below


@dataclass(frozen=True)
class Terminal:
    """A terminal program a window is opened with on Linux, and how it is told, each flag read from its own manual
    (2026-11-19). `stay`: what keeps the program that is started running as long as its window, so that the window
    is followed (`running`) and its launch token ended once it is gone. `folder`: how it is given the folder, each word
    with {folder} in it (none: it runs the command in the folder it is started in). `run`: the flag after which the
    rest of the line is the command, each word handed over as it is (none: the words after its options are)."""

    name: str
    stay: tuple[str, ...] = ()
    folder: tuple[str, ...] = ()
    run: tuple[str, ...] = ()

    def argv(self, path, folder: str, command: Iterable) -> list[str]:
        """The terminal at `path` started on `command` in `folder`: every word of the command is a word of its own."""
        return [str(path), *self.stay, *(word.format(folder=folder) for word in self.folder), *self.run,
                *(str(word) for word in command)]


TERMINALS = (
    # gnome-terminal(1): "[-- PROGRAM [ARG...]]" (-e splits one string); --wait: "Wait until the terminal's child exits"
    Terminal("gnome-terminal", ("--wait",), ("--working-directory={folder}",), ("--",)),
    # ptyxis(1): "[-- PROGRAM ARGUMENTS]" (-x takes the whole line as one argument); "Single instance mode is implied
    # when running a -- command": the program started holds the window
    Terminal("ptyxis", (), ("-d", "{folder}"), ("--",)),
    # xfce4-terminal: -x "Execute the remainder of the command line inside the terminal" (-e takes one string);
    # --disable-server: "the new window will run in a new process, not trying to open a new window from a running
    # instance"
    Terminal("xfce4-terminal", ("--disable-server",), ("--working-directory={folder}",), ("-x",)),
    # konsole: -e "will catch all following arguments passed to Konsole, and execute it as command"; --separate: "Run
    # the new instance of Konsole in a separate process", so the program started holds the window
    Terminal("konsole", ("--separate",), ("--workdir", "{folder}"), ("-e",)),
    # kitty: "kitty [options] [program-to-run ...]"; one instance for each start unless --single-instance is given
    Terminal("kitty", (), ("--directory", "{folder}")),
    # alacritty(1): -e "Command and args to execute (must be last argument)"
    Terminal("alacritty", (), ("--working-directory", "{folder}"), ("-e",)),
    # foot(1): "All trailing (non-option) arguments are treated as a command, and its arguments"; it serves several
    # windows only with --server
    Terminal("foot", (), ("--working-directory={folder}",)),
    # xterm(1): -e "the program (and its command line arguments) to be run in the xterm window", the last option; the
    # command runs in the folder xterm is started in
    Terminal("xterm", (), (), ("-e",)),
)
BY_NAME = {terminal.name: terminal for terminal in TERMINALS}


def _no_terminal() -> str:
    """Why no window can open where a display is set, in words: no terminal program is installed (the user's Ubuntu
    likely has none)."""
    names = ", ".join(terminal.name for terminal in TERMINALS)
    return (f"no terminal program to open a window with is installed here ({names}): installing one, such as xterm, "
            "is a step for root")


# -- values a harness would read as more than text (1.66.0, critique 1) -----------------------------------------------
# ${NAME} and $(command): Pi resolves ${NAME} in its MCP entries and a shell runs $(...); {env:NAME} and {file:PATH}:
# OpenCode replaces them anywhere in its configuration's text, closed or not; ${{ secrets.X }}: Continue's templating.
# A harness adds its own (Harness.OPENERS).
OPENERS = ("${", "$(", "{env:", "{file:", "${{")
RUNS = "!"  # a value that begins with it is run as a command (Pi's "!command" values)

# -- Liminal's MCP (1.66.0) -------------------------------------------------------------------------------------------
MCP = "mcp"  # the MCP plugin (AI plugins, Protocols), asked through the platform
MCP_VARIABLE = "LIMINAL_MCP_TOKEN"  # the one variable a window's token reaches its tool by
MCP_SLACK_S = 60  # a harness's own MCP timeout is the hold and this much more (a call held for your answer, then run)
HOLD_S = 50  # the hold MCP's page gives a new agent: taken where its offer says none
WIRES = ("stdio", "http")  # how a harness reaches it: the bridge (a program it starts), or the platform's own address
WIRE_WORDS = {"stdio": "the MCP plugin's bridge (stdio)", "http": "the MCP plugin's address on the platform (HTTP)"}
TOKEN = re.compile(r"^[A-Za-z0-9_~+/=.-]{16,512}$")  # a launch token as the MCP plugin mints it (token_urlsafe)
TOKEN_VARIABLE = re.compile(r"^LIMINAL_[A-Z0-9_]{1,100}$")  # Liminal's own: dropped from every other child
MCP_OPTION = Setting(
    "mcp", "Liminal's MCP", "choice", "off",
    choices=(("off", "off", "it reaches no MCP server of Liminal's"),
             ("on", "on", "it reaches Liminal's MCP plugin, which decides what it may list and call")),
    note=("Off unless you turn it on. On: each window it opens gets a token of its own for Liminal's MCP plugin (AI "
          "plugins, Protocols), ended once the window is gone. What it may list and call is granted on that "
          "plugin's page."))
MCP_ASKS = (
    (MCP, "client_offer", "how Liminal's MCP is reached here: its bridge, its address and headers, its revisions and "
                          "its hold"),
    (MCP, "ensure_client", "this harness's agent, made when Use… turns Liminal's MCP on (granted nothing)"),
    (MCP, "launch_token", "a token for one window, at each Open… that opens one"),
    (MCP, "end_launch", "that window's token ended, once the window is gone"),
)
MCP_NOTES = ("With Liminal's MCP on, each window's token is asked of the MCP plugin at the Open… that opens it, and "
             "is handed to the tool in LIMINAL_MCP_TOKEN alone, a secret of its launch: never on its command line, in "
             "a file, in an answer or in the lines to paste (Command… gives none). It is ended once the window is "
             "gone.",)
MCP_LINES = ("Liminal's MCP takes its token from {variable}, which these lines do not set: Show its token once… on "
             "the MCP plugin's page gives one")
# set while a start prepares its launch: whether it opens a window (only then is a token asked), the token asked, and
# whether the plugin's launch asked how Liminal's MCP is reached (`mcp_wiring`)
_PREPARING: contextvars.ContextVar[dict | None] = contextvars.ContextVar("liminal_harness_preparing", default=None)


def _link_target(path) -> str:
    """Where a link leads, read from the file system (a link read, never a process)."""
    return os.path.realpath(path)


def _own_path(path: str | None) -> str | None:
    """Linux's PATH as a terminal program is looked for in it: its folders on another system's drive left out
    (mounts.foreign). WSL puts Windows' own folders there, under /mnt: no Linux terminal is in them, and each look
    crosses to Windows (about 170 ms a status for 38 of them in the user's Ubuntu). None stays None (shutil.which then
    reads this process's own)."""
    if not path:
        return path

    def foreign(folder: str) -> bool:
        try:
            return bool(mounts.foreign(folder))
        except Exception:  # noqa: BLE001 - a folder that cannot say is looked in, as before
            return False

    return ":".join(folder for folder in str(path).split(":") if not folder or not foreign(folder))


def evaluated(value, openers: Iterable[str] = OPENERS) -> str:
    """Why a harness would read `value` as more than text, in words: it holds one of `openers` (closed or not: a
    harness may read from one to the end of the text), or it begins with "!". "" when it would not."""
    text = str(value if value is not None else "")
    for opener in sorted({str(o) for o in openers if str(o)}, key=len, reverse=True):
        if opener in text:
            return f"it holds {opener!r}, which a harness reads as a variable, a file or a command"
    if text.lstrip().startswith(RUNS):
        return f"it begins with {RUNS!r}, which a harness runs as a command"
    return ""


def clean_value(value, what: str, openers: Iterable[str] = OPENERS) -> str:
    """A value written into a harness's configuration, as text, checked: a Refusal in words when a harness would read
    part of it as more than text (`evaluated`)."""
    text = str(value if value is not None else "")
    why = evaluated(text, openers)
    if why:
        raise Refusal(f"{what} cannot be written into a harness's configuration as it is: {why}")
    return text


def _control(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def split_server(server) -> tuple[str, str]:
    """A model server's name, "<plugin>/<instance>" (ollama/default), as its two parts. A Refusal in words for anything
    else."""
    text = str(server if server is not None else "").strip()
    found = SERVER.fullmatch(text)
    if found is None:
        raise Refusal(f"a model server is named <plugin>/<instance> (ollama/default), not {text[:80]!r}")
    return found.group(1), found.group(2)


def clean_model(model, of: str = "its server", openers: Iterable[str] = OPENERS) -> str:
    """A model's id as typed, checked: not empty, MODEL_CHARS at most, on one line, without a double quote (a word that
    holds one is not handed to a program as it is from a line pasted into Windows PowerShell 5.1: children.not_passed;
    a harness puts the id in its command, and the switches after it would be read into it), and holding nothing a
    harness would read as more than text (`evaluated`: a model server's list may name anything). A Refusal in words
    otherwise."""
    text = str(model if model is not None else "").strip()
    if not text:
        raise Refusal(f"choose a model of {of}: its id, as the server lists it")
    if len(text) > MODEL_CHARS or _control(text) or '"' in text:
        raise Refusal(f"a model's id is {MODEL_CHARS} characters at most, without a line break, a control character or "
                      'a double quote (")')
    why = evaluated(text, openers)
    if why:
        raise Refusal(f"a model's id is written into its harness's configuration, and this one cannot be: {why}")
    return text


def server_words(at: Mapping) -> str:
    """A model server in words: "{its plugin's title} / {instance}" (Ollama / default)."""
    title = str(at.get("plugin_title") or at.get("plugin") or "a model server")
    return f"{title} / {at.get('name') or '?'}"


def model_ids(at: Mapping) -> list[str]:
    """The ids of the models a `serving` row lists, as last listed: [] when none were."""
    out = []
    for m in at.get("models") or ():
        said = m.get("id") if isinstance(m, Mapping) else m if isinstance(m, str) else None
        if isinstance(said, str) and said.strip() and said.strip() not in out:
            out.append(said.strip())
    return out


def _stopped(at: Mapping) -> bool:
    """Whether an instance of this machine is not running (stopped, or exited): one on another machine never is."""
    return str(at.get("state") or "") in STOPPED and str(at.get("where") or "local") != "remote"


def _not_running(at: Mapping) -> str:
    """Why Open… cannot start a tool against an instance now, in words ("": it can): a local one that is stopped or
    has exited, or one found running here that nothing answers at now (SILENT: its server has ended since). One on
    another machine is asked by the tool itself."""
    if _stopped(at):
        return f"{server_words(at)} is not running: start it on {at['plugin_title']}'s page first"
    if str(at.get("state") or "") == SILENT and str(at.get("where") or "local") != "remote":
        port = at.get("port")
        on = f" on port {port}" if isinstance(port, int) and not isinstance(port, bool) and port > 0 else ""
        return f"{server_words(at)} answers nothing{on} here: start it first"
    return ""


def _line(e: BaseException, named: bool = False) -> str:
    """A fault in words on one line; `named`: with the name of its kind first, unless it is a refusal (ValueError)."""
    said = " ".join(str(e).split())
    if named and not isinstance(e, ValueError):
        return f"{type(e).__name__}: {said}" if said else type(e).__name__
    return said or type(e).__name__


def _listed(value) -> list:
    return list(value) if isinstance(value, (list, tuple)) else []


def _noted(said: str, notes: Iterable[str]) -> str:
    """Words with what more is to be said of them in brackets, where there is any."""
    more = [str(note) for note in notes if str(note or "").strip()]
    return f"{said} ({'; '.join(more)})" if more else said


def _at(answer: Mapping, row: Mapping) -> dict:
    """An instance as a harness's `launch` is given it: its `serving` row, with its plugin's name ("plugin"), what
    its server is ("native"), its plugin's title ("plugin_title") and its name as a harness keeps it ("server")."""
    plugin = str(answer.get("plugin") or "")
    return {**row, "plugin": plugin, "native": str(answer.get("native") or ""),
            "plugin_title": str(answer.get("title") or plugin), "server": f"{plugin}/{row.get('name')}"}


def _every(served: Iterable[Mapping]) -> dict[str, dict]:
    """Every instance the model servers say they serve, by its name as a harness keeps it (<plugin>/<instance>)."""
    out: dict[str, dict] = {}
    for answer in served:
        for row in answer.get("instances") or ():
            at = _at(answer, row)
            out.setdefault(at["server"], at)
    return out


def _alive(child) -> bool:
    """Whether a window's program still runs (its process not ended): one that cannot say has ended."""
    poll = getattr(child, "poll", None)
    try:
        return callable(poll) and poll() is None
    except Exception:  # noqa: BLE001 - a process that cannot be asked is taken as ended
        return False


@dataclass(frozen=True)
class Use:
    """What a harness is started against: `server`, a model server's instance named "<plugin>/<instance>"; `model`, a
    model's id as that server lists it; `folder`, the last folder it was opened in ("": none yet); `options`, the
    values of the harness's OPTIONS kept, by name (one left out: the tool's own default)."""

    server: str
    model: str
    folder: str = ""
    options: Mapping[str, object] = field(default_factory=dict, hash=False)

    def __post_init__(self):
        object.__setattr__(self, "server", str(self.server if self.server is not None else "").strip())
        object.__setattr__(self, "model", str(self.model if self.model is not None else "").strip())
        object.__setattr__(self, "folder", str(self.folder if self.folder is not None else "").strip())
        object.__setattr__(self, "options", dict(self.options or {}))

    def kept(self) -> dict:
        """As it is kept: {"v": 1, "server", "model", "folder", "options"}."""
        return {"v": USE_VERSION, "server": self.server, "model": self.model, "folder": self.folder,
                "options": dict(self.options)}

    def text(self) -> str:
        """As the pair's text."""
        return json.dumps(self.kept(), ensure_ascii=False)

    @classmethod
    def of(cls, text) -> "Use":
        """The choice kept as `text`; ValueError in words when it is not one (not JSON, another version, a part that
        is not what it should be)."""
        try:
            value = json.loads(text)
        except (TypeError, ValueError):
            raise ValueError("it is not JSON") from None
        if not isinstance(value, dict):
            raise ValueError("it is not a JSON object")
        if value.get("v") != USE_VERSION:
            raise ValueError(f"it is of version {value.get('v')!r}, and this plugin reads version {USE_VERSION}")
        server, model = value.get("server"), value.get("model")
        folder, options = value.get("folder", ""), value.get("options", {})
        if not all(isinstance(x, str) for x in (server, model, folder)) or not isinstance(options, dict):
            raise ValueError("its server, model and folder are texts and its options an object")
        split_server(server)
        clean_model(model)
        if len(folder) > FOLDER_CHARS or _control(folder):
            raise ValueError(f"its folder is {FOLDER_CHARS:,} characters at most, on one line")
        return cls(server, model, folder, options)


@dataclass(frozen=True)
class McpWiring:
    """How one start of a harness reaches Liminal's MCP, as the MCP plugin offers it (`Harness.mcp_wiring`).

    `wire` says which of two ways this start uses. "stdio": `argv` is the bridge's command, a program the tool starts
    and talks MCP to over its standard input and output. "http": `url` is the endpoint on the platform, and `headers`
    go with each request. `token_variable` is the variable the token reaches the tool by (LIMINAL_MCP_TOKEN): its
    configuration names that variable, never the token. `token` is this window's launch token, "" when none was asked
    (Command…, the lines to paste); the base puts it in that variable itself. `hold_s` is how long a call may wait
    for your answer on the MCP plugin's page, and `timeout_s` the tool's own MCP timeout: the hold and a minute more.
    `revisions` are the revisions of the protocol it speaks. The token is in no repr."""

    argv: tuple[str, ...] = ()
    url: str = ""
    headers: Mapping[str, str] = field(default_factory=dict, hash=False)
    token_variable: str = MCP_VARIABLE
    token: str = field(default="", repr=False)
    wire: str = "stdio"
    hold_s: int = HOLD_S
    revisions: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "argv", tuple(str(word) for word in self.argv or ()))
        object.__setattr__(self, "headers", {str(k): str(v) for k, v in dict(self.headers or {}).items()})
        object.__setattr__(self, "revisions", tuple(str(r) for r in self.revisions or ()))

    @property
    def timeout_s(self) -> int:
        """The tool's own MCP timeout, in seconds: a call held for your answer, then run."""
        return int(self.hold_s) + MCP_SLACK_S


def _offer_of(said) -> dict | None:
    """The MCP plugin's client_offer as this module reads it, each part checked. What its plugin says (`offer`):
    "wires", the ways it serves, of WIRES; "bridge", the bridge's command; "endpoint" and "headers", its address on the
    platform and what goes with each request; "revisions". What the protocol base adds: "variable", the token's
    variable (LIMINAL_MCP_TOKEN), and "hold_s". A way it names without what it needs is left out. Kept as {"wires",
    "bridge", "endpoint", "headers", "token_variable", "hold_s", "revisions"}; None when it is not an offer."""
    if not isinstance(said, Mapping):
        return None
    bridge = said.get("bridge")
    if isinstance(bridge, (list, tuple)) and bridge and all(isinstance(w, str) and w and not _control(w)
                                                            for w in bridge):
        bridge = tuple(bridge)
    else:
        bridge = ()
    endpoint = said.get("endpoint")
    endpoint = endpoint.strip() if isinstance(endpoint, str) and not _control(endpoint) else ""
    headers = said.get("headers") or {}
    if not isinstance(headers, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) and k.strip() and not _control(k) and not _control(v)
            for k, v in headers.items()):
        return None
    variable = said.get("variable", MCP_VARIABLE)
    if not isinstance(variable, str) or not TOKEN_VARIABLE.fullmatch(variable):
        return None
    hold = said.get("hold_s")
    hold = hold if isinstance(hold, int) and not isinstance(hold, bool) and 0 < hold <= 3600 else HOLD_S
    revisions = tuple(r for r in _listed(said.get("revisions")) if isinstance(r, str) and r.strip())
    wires = [w for w in _listed(said.get("wires")) if w in WIRES]
    wires = [w for w in dict.fromkeys(wires) if (w == "stdio" and bridge) or (w == "http" and endpoint)]
    return {"wires": tuple(wires), "bridge": bridge, "endpoint": endpoint, "headers": dict(headers),
            "token_variable": variable, "hold_s": hold, "revisions": revisions}


class HarnessRun(ai.Run):
    """A harness's run state: what the model servers said last and when, and the windows it opened."""

    def __init__(self):
        super().__init__()
        self.served: list[dict] | None = None  # the `serving` answers last asked (None: not asked yet)
        self.served_at = 0.0  # when, by the Outside's clock
        self.served_notes: list[str] = []  # the plugins that refused, in their words
        self.windows: list[tuple[object, str]] = []  # (its process, its folder): the windows opened, while open
        # (its process, its launch token): each window opened with a token for Liminal's MCP, followed until it is gone
        # even once WINDOWS_KEPT no longer follows it (a token outlives no window), TOKENS_KEPT at most
        self.tokens: list[tuple[object, str]] = []


class Harness(ai.AiPlugin):
    """A harness's plugin: a coding agent installed, configured against one instance of an inference plugin's, and
    opened in a folder. A subclass sets what every AI plugin sets (name, title, about, order, ICON, apis, LIBS_FLOOR,
    package, installed, install_into, remove_from, runs_here), its OPTIONS, and says `launch`; `fits`, `open_words`
    and `main_more` have the base's answers."""

    GROUP = "harness"
    HOOKS = (*ai.AiPlugin.HOOKS, "use", "open", "command", "ask_models")
    OPTIONS: tuple[Setting, ...] = ()  # the tool's own options, asked under Use… after the server and the model
    RUN_STATE = HarnessRun
    # How the tool reaches Liminal's MCP, in its order of preference: "stdio" (the MCP plugin's bridge) and "http"
    # (its address on the platform). (): not at all. With MCP_OPTION among its OPTIONS, Use… can turn it on; a plugin
    # that wires it adds MCP_ASKS to its ASKS and MCP_NOTES to its INTERNAL_NOTES.
    MCP_WIRES: tuple[str, ...] = ()
    # what its tool reads in a value of its configuration as more than text: the base's, and a plugin's own beside them
    # (OPENERS = (*Harness.OPENERS, "{secret:"))
    OPENERS: tuple[str, ...] = OPENERS
    # What it says of the interface it shares (the contract's words of liminal-libs 1.63.0, read by name by the Internal
    # API tab; nothing reads them before it): its reads beside its bases', what it asks of the other plugins through
    # the platform, and what it keeps through the login (KEEPS, below) and reads there (INTERNAL_NOTES: a server's key)
    READ_HOOKS = ("command", "ask_models")
    ASKS = (("", SERVING, "what each model server serves: its instances, their addresses, states and models"),
            ("", MODELS_OF, "one model server's models, asked now (Ask…)"))
    INTERNAL_NOTES = ("A model server's key is read through its login by the variable that server's `serving` row "
                      "names, only to open a window, and is handed to the tool in its environment alone: never on "
                      "its command line, in an answer, a log or the lines to paste (its placeholder is there).",)

    @property
    def KEEPS(self) -> tuple:  # noqa: N802 - a declared word of the contract, as READ_HOOKS
        """What it keeps through the login beside its keys: the choice Use… keeps (`use_kept`)."""
        return ((self.variable("use"), "what it is started against: the model server, the model, the folder last "
                                       "opened and its options"),)

    # -- what a subclass says -----------------------------------------------------------------------------------------
    def launch(self, folder: str, use: Use, at: dict, key: str = "") -> children.Launch:
        """How the tool is started in `folder` against the instance `at` (its `serving` row with "plugin", "native",
        "plugin_title" and "server"), `use` its choice: the command, the variables it is told by (its configuration
        passed at launch: a switch, a variable, or a file it writes under home/config), the names it drops (the
        hosted providers'), the folder ("": `folder`) and which of its variables are secret. Its telemetry, update
        checks, sharing and hosted providers are switched off, and its shell, edits and fetches asked (A.12). `key`:
        the server's key ("" when it has none), handed over by one of its variables alone, never on the command line
        or in a file; in the lines to paste it is the placeholder its user types. A ValueError (a Refusal) is the
        open's refusal, in its words."""
        raise NotImplementedError(f"{self.title or self.name} says nothing of how it is started")

    def fits(self, at: Mapping) -> str:
        """"" or why this harness cannot use the instance `at`, in words. The base's: it needs an OpenAI-compatible
        address (the row's "openai")."""
        if str(at.get("openai") or "").strip():
            return ""
        return f"{self.title or self.name} needs an OpenAI-compatible address, and {server_words(at)} gives none"

    def open_words(self, use: Use, at: Mapping) -> str:
        """What it must say before each start, appended to Open…'s confirmation (one sentence or more, after a space).
        The base's: nothing."""
        return ""

    def main_more(self) -> dict:
        """What more its Main shows: {"tables", "forms", "actions"}, each a list; its tables are drawn before the Model
        servers table ("Before you use it"). Asked at every draw; it asks nothing over the network and starts
        nothing. The base's: nothing."""
        return {}

    # -- the model servers --------------------------------------------------------------------------------------------
    def servers(self, fresh: bool = False) -> list[dict]:
        """What each attached plugin that answers `serving` says it serves (machines/modelserver.py's shape: {"plugin",
        "title", "native", "instances": [...]}), asked through the platform and kept SERVING_S (`fresh`: asked now).
        A plugin that refuses is left out, its words in the Model servers table's note. No lock is held while another
        plugin is asked, so two plugins asking each other never wait on each other."""
        return self._served(fresh)[0]

    def _served(self, fresh: bool = False) -> tuple[list[dict], list[str]]:
        now = self.out.clock()
        with self._rt.lock:
            kept, at, notes = self._rt.served, self._rt.served_at, list(self._rt.served_notes)
        if not fresh and kept is not None and 0 <= now - at < SERVING_S:
            return copy.deepcopy(kept), notes
        answers, notes = self._ask_servers()  # (no lock held: another plugin is asked through the app)
        with self._rt.lock:
            self._rt.served, self._rt.served_at, self._rt.served_notes = answers, self.out.clock(), notes
        return copy.deepcopy(answers), list(notes)

    def _ask_servers(self) -> tuple[list[dict], list[str]]:
        app = self.app
        if app is None:
            return [], [NO_APP]
        try:
            attached = dict(app.plugins() or {})
        except Exception as e:  # noqa: BLE001 - a platform that cannot say which plugins it holds
            return [], [f"the platform could not list its plugins: {self._refused(e)}"]
        answers, notes = [], []
        for name, face in attached.items():
            hooks = face.get("hooks") if isinstance(face, Mapping) else None
            if name == self.name or not hooks or SERVING not in hooks:
                continue
            try:
                said = app.ask(name, SERVING, [])  # the platform's form: the hook's arguments as one list
            except Exception as e:  # noqa: BLE001 - one that refuses is left out, its words said
                notes.append(f"{name} did not say what it serves: {self._refused(e)}")
                continue
            answer = self._answer_of(name, said)
            if answer is None:
                notes.append(f"{name}'s answer is not what a model server serves: it is left out")
                continue
            answers.append(answer)
        return answers, notes

    @staticmethod
    def _answer_of(name: str, said) -> dict | None:
        """A `serving` answer as kept: its plugin named as the platform holds it, its instances those with a name."""
        if not isinstance(said, Mapping) or not isinstance(said.get("instances"), list):
            return None
        rows = []
        for row in said["instances"]:
            if not isinstance(row, Mapping):
                continue
            try:
                rows.append({**row, "name": instances.clean_name(row.get("name"))})
            except ValueError:
                continue
        return {**said, "plugin": name, "title": str(said.get("title") or name),
                "native": str(said.get("native") or ""), "instances": rows}

    def serving_of(self, server, fresh: bool = False) -> dict | None:
        """The instance `server` ("<plugin>/<instance>") as `launch` is given it, among what the model servers say they
        serve (`servers`); None when none says it now."""
        plugin, instance = split_server(server)
        return _every(self.servers(fresh)).get(f"{plugin}/{instance}")

    def _forget_servers(self) -> None:
        with self._rt.lock:
            self._rt.served, self._rt.served_at = None, 0.0

    def _refused(self, e: BaseException) -> str:
        """Another plugin's refusal or failure in its words (the platform's HookRefused: `words`; its Refused:
        `reason`), on one line, without a secret, NOTE_CHARS at most."""
        words = getattr(e, "words", "") or getattr(e, "reason", "") or ""
        words = " ".join(str(words).split()) or _line(e, named=not isinstance(e, LookupError))
        words = self._scrubbed(words)
        return words if len(words) <= NOTE_CHARS else words[:NOTE_CHARS - 1] + "…"

    # -- the choice kept ----------------------------------------------------------------------------------------------
    def use_kept(self) -> Use | None:
        """What it is started against, as kept through the login (LIMINAL_AI_<NAME>_USE); None when nothing is, or
        what is kept cannot be read (the status says so)."""
        return self._kept()[0]

    def _kept(self) -> tuple[Use | None, str]:
        variable = self.variable("use")
        text = self.pair(variable)
        if not text.strip():
            return None, ""
        try:
            use = Use.of(text)
            clean_model(use.model, openers=self.OPENERS)  # (with its tool's own openers too)
        except ValueError as e:
            return None, f"the choice kept in {variable} could not be read ({e}): Use… keeps a new one"
        good: dict = {}
        for setting in self.OPTIONS:  # its options as this version of the plugin has them, each checked again
            if setting.name in use.options:
                try:
                    value = setting.clean(use.options[setting.name])
                except ValueError:
                    continue
                if value is not None and not (setting.kind == "text" and evaluated(value, self.OPENERS)):
                    good[setting.name] = value
        return (use if good == dict(use.options) else dataclasses.replace(use, options=good)), ""

    def _options_of(self, values) -> dict:
        name = self.title or self.name
        values = list(values)
        if len(values) > len(self.OPTIONS):
            many = len(self.OPTIONS)
            raise Refusal(f"{name} takes {many} option{'' if many == 1 else 's'}, not {len(values)}")
        out: dict = {}
        for setting, value in zip(self.OPTIONS, values):
            kept = setting.clean(value)
            if kept is not None:
                if setting.kind == "text":  # (a text option is written into the tool's configuration)
                    self.clean_value(kept, setting.label)
                out[setting.name] = kept
        return out

    def clean_value(self, value, what: str) -> str:
        """A value this plugin writes into its tool's configuration, as text, checked against its tool's openers
        (OPENERS) and a leading "!": a Refusal in words when the tool would read part of it as more than text. A
        plugin passes every value it writes through it: the model server's address, the folder, a path."""
        return clean_value(value, what, self.OPENERS)

    # -- Liminal's MCP ------------------------------------------------------------------------------------------------
    def _offers_mcp(self) -> bool:
        """Whether this harness offers Liminal's MCP: its OPTIONS hold MCP_OPTION (by its name)."""
        return any(setting.name == MCP_OPTION.name for setting in self.OPTIONS)

    def mcp_on(self, use: Use | None) -> bool:
        """Whether a start against `use` reaches Liminal's MCP: this harness offers it, names how (MCP_WIRES), and
        Use… turned it on."""
        return (use is not None and bool(self.MCP_WIRES) and self._offers_mcp()
                and str(use.options.get(MCP_OPTION.name) or "") == "on")

    def mcp_wiring(self, use: Use | None = None) -> McpWiring | None:
        """How a start against `use` (None: the choice kept) reaches Liminal's MCP, for the plugin's launch to write
        into its tool's configuration; None when it does not (`mcp_on`). The MCP plugin is asked through the platform
        how it is reached (client_offer), and the first of MCP_WIRES it serves is used. Inside an Open… that opens a
        window, a token for that window is asked too (launch_token): the base hands it to the tool in its variable
        alone, and ends it once the window is gone. Anywhere else (Command…, the lines to paste) none is asked. A
        Refusal in words when the MCP plugin does not answer, serves none of MCP_WIRES, or offers a value the tool
        would read as more than text."""
        use = self.use_kept() if use is None else use
        if not self.mcp_on(use):
            return None
        offer = self._mcp_offer()
        wire = self._wire_of(offer)
        box, token = _PREPARING.get(), ""
        if box is not None:
            box["asked"], box["variable"] = True, offer["token_variable"]
            if box["window"]:
                token = box["token"] or self._launch_token()
                box["token"] = token
        stdio = wire == "stdio"
        return McpWiring(argv=offer["bridge"] if stdio else (), url="" if stdio else offer["endpoint"],
                         headers={} if stdio else offer["headers"], token_variable=offer["token_variable"],
                         token=token, wire=wire, hold_s=offer["hold_s"], revisions=offer["revisions"])

    def _mcp_words(self, why: str) -> str:
        name = self.title or self.name
        return (f"Liminal's MCP is on for {name} (Use…), and the MCP plugin {why}. Nothing was started: turn the MCP "
                "plugin on (AI plugins, Protocols), or turn Liminal's MCP off under Use…")

    def _mcp_offer(self) -> dict:
        """The MCP plugin's client_offer, asked through the platform and checked (`_offer_of`), each value the tool is
        given checked against its openers. A Refusal in words when it cannot be had."""
        app = self.app
        if app is None:
            raise Refusal(self._mcp_words("cannot be asked: this plugin is not attached to the platform"))
        try:
            said = self._ask_app(app, MCP, "client_offer", [])
        except Exception as e:  # noqa: BLE001 - its refusal, or its absence, in its words
            raise Refusal(self._mcp_words(f"did not say how it is reached: {self._refused(e)}")) from None
        offer = _offer_of(said)
        if offer is None:
            raise Refusal(self._mcp_words("answered something that is not how it is reached"))
        problem = " ".join(str(said.get("problem") or "").split())  # (the protocol base's words for its own fault)
        if problem and not offer["wires"]:
            raise Refusal(self._mcp_words(f"could not say how it is reached: {self._scrubbed(problem)[:NOTE_CHARS]}"))
        for word in offer["bridge"]:
            self.clean_value(word, "the MCP plugin's bridge")
        self.clean_value(offer["endpoint"], "the MCP plugin's address")
        for header, value in offer["headers"].items():
            self.clean_value(header, "a header the MCP plugin names")
            self.clean_value(value, f"the MCP plugin's header {header}")
        return offer

    def _wire_of(self, offer: Mapping) -> str:
        """The first of MCP_WIRES the offer serves. A Refusal in words when it serves none of them."""
        for wire in self.MCP_WIRES:
            if wire in offer["wires"]:
                return wire
        served = ai._and([WIRE_WORDS[w] for w in offer["wires"]]) or "neither way"
        wanted = ai._and([WIRE_WORDS.get(w, repr(w)) for w in self.MCP_WIRES])
        raise Refusal(self._mcp_words(f"serves {served} here, and {self.title or self.name} reaches it by {wanted} "
                                      "alone"))

    def _launch_token(self) -> str:
        """A token for one window, asked of the MCP plugin through the platform (launch_token: the agent is the asking
        plugin's, as the platform names it). It is kept among this plugin's secrets, so no word of it is said. A
        Refusal in words when none can be had."""
        app = self.app
        if app is None:
            raise Refusal(self._mcp_words("cannot be asked: this plugin is not attached to the platform"))
        try:
            said = self._ask_app(app, MCP, "launch_token", [])
        except Exception as e:  # noqa: BLE001 - its refusal in its words
            raise Refusal(self._mcp_words(f"gave no token for the window: {self._refused(e)}")) from None
        token = said.get("token") if isinstance(said, Mapping) else said
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            raise Refusal(self._mcp_words("gave nothing that can be a token for the window"))
        self._keep_secret(token)
        return token

    def _end_launch(self, token: str) -> None:
        """A window's launch token ended (end_launch), its window gone or never opened: asked through the platform with
        no lock held. A refusal is let be: the MCP plugin ends every launch token at its own stop. The token then
        leaves the secrets this plugin takes out of its words, so that the keys stay among them (SECRETS_KEPT)."""
        app = self.app
        if not token:
            return
        try:
            if app is not None:
                self._ask_app(app, MCP, "end_launch", [token])
        except Exception:  # noqa: BLE001 - one it cannot end now ends with it
            pass
        with self._rt.lock:
            if token in self._rt.secrets:
                self._rt.secrets.remove(token)

    def _mcp_use(self, options: Mapping) -> list[str]:
        """Liminal's MCP as Use… turns it on: the MCP plugin asked how it is reached (client_offer) and for this
        harness's agent (ensure_client, with its title: made once, granted nothing). Its words for the answer; [] when
        it is off or this harness does not offer it. A Refusal in words when it cannot be wired."""
        if str(options.get(MCP_OPTION.name) or "") != "on" or not self._offers_mcp():
            return []
        name = self.title or self.name
        if not self.MCP_WIRES:
            raise Refusal(f"{name} cannot reach Liminal's MCP from here: turn Liminal's MCP off under Use…")
        offer = self._mcp_offer()
        wire = self._wire_of(offer)
        try:
            said = self._ask_app(self.app, MCP, "ensure_client", [name])
        except Exception as e:  # noqa: BLE001 - its refusal in its words
            raise Refusal(self._mcp_words(f"did not make {name}'s agent: {self._refused(e)}")) from None
        words = " ".join(str(said.get("said") or "").split()) if isinstance(said, Mapping) else ""
        return [f"Liminal's MCP: {words}" if words else
                f"Liminal's MCP: {name}'s agent is on the MCP plugin's page, granted nothing until you grant it there",
                f"each window it opens reaches it by {WIRE_WORDS[wire]}, with a token of its own"]

    def _prepared(self, folder: str, use: Use, at: dict, key: str, *, window: bool) -> tuple[children.Launch, str, str]:
        """The plugin's launch as one start needs it (`_launch`), with Liminal's MCP where its choice has it on: in an
        Open… that opens a window (`window`), the token `mcp_wiring` asked for it is handed to the tool in its
        variable alone, a secret of the launch, and is ended at once when the start goes no further. (The launch; its
        token, or ""; the token's variable where the MCP was wired without one: the lines to paste.) ChildError when
        the plugin's launch leaves Liminal's MCP out while it is on."""
        box = {"window": bool(window), "token": "", "asked": False, "variable": MCP_VARIABLE}
        mark = _PREPARING.set(box)
        try:
            made = self._launch(folder, use, at, key)
            if self.mcp_on(use) and not box["asked"]:
                raise children.ChildError(f"{self.title or self.name}'s launch leaves Liminal's MCP out, and it is on "
                                          "for it (Use…): it is not started")
            token, variable = box["token"], box["variable"]
            if token:
                made = self._token_in(made, token, variable)
            elif box["asked"] and made.env.get(variable) == "":
                made = dataclasses.replace(made, env={n: v for n, v in made.env.items() if n != variable})
        except BaseException:
            self._end_launch(box["token"])
            raise
        finally:
            _PREPARING.reset(mark)
        return made, token, (variable if box["asked"] and not token else "")

    def _token_in(self, made: children.Launch, token: str, variable: str) -> children.Launch:
        """A window's launch with its token in `variable` alone, named a secret of it. Refused in words when the
        plugin's launch puts the token anywhere else: a word of its command, its folder, another variable."""
        name = self.title or self.name
        if any(children.carries(word, token, KEY_INSIDE) for word in (*made.argv, made.cwd)):
            raise Refusal(f"{name} would put its token for Liminal's MCP on its command line, where every program here "
                          "can read it: it is not started")
        others = sorted(n for n, v in made.env.items()
                        if n.upper() != variable.upper() and children.carries(v, token, KEY_INSIDE))
        if others:
            raise Refusal(f"{name} would hand its token for Liminal's MCP over in {', '.join(others)}, and only "
                          f"{variable} carries it: it is not started")
        env = {n: v for n, v in made.env.items() if n.upper() != variable.upper()}
        env[variable] = token
        return dataclasses.replace(made, env=env, secret=tuple(dict.fromkeys([*made.secret, variable])))

    # -- the windows it opened ----------------------------------------------------------------------------------------
    def running(self) -> list[str]:
        """The windows it opened that are still open, by their folder ("the window open in C:\\work\\x"): Install and
        Uninstall wait until they are closed (its program's files are in use). The launch token of a window seen gone
        is ended here (end_launch), asked with no lock held: a status asks this at every draw. A window no longer
        followed past WINDOWS_KEPT still has its token ended once it is gone."""
        with self._rt.lock:
            self._rt.windows = [(child, folder) for child, folder in self._rt.windows if _alive(child)]
            shown = [f"the window open in {folder}" for _, folder in self._rt.windows]
            kept, gone = [], []
            for child, token in self._rt.tokens:
                (kept if _alive(child) else gone).append((child, token))
            self._rt.tokens = kept
        for _, token in gone:
            self._end_launch(token)
        return shown

    def app_stopping(self) -> None:
        """The platform stops, or this plugin is turned off: its windows are their user's and stay open; the launch
        tokens of those already gone are ended. It bears a second call."""
        self.running()

    def _desktop(self) -> bool:
        """Whether a window can be opened here. Windows: on a desktop (windows.interactive: not a boot service's).
        Linux: a display is set in the platform's environment and a terminal program is found (`_terminal`)."""
        if self.system != "windows":
            return self._terminal() is not None
        ask = self.out.interactive if self.out.interactive is not None else windows.interactive
        try:
            return bool(ask())
        except Exception:  # noqa: BLE001 - not known: no window
            return False

    def _env(self) -> Mapping[str, str]:
        """The platform's environment, as this plugin reads it (the Outside's, a test's, when it gives one)."""
        return self.out.env if self.out.env is not None else os.environ

    def _display(self) -> bool:
        """Whether the platform's environment names a display a window can open on (Linux: DISPLAY, WAYLAND_DISPLAY;
        a boot service has neither)."""
        env = self._env()
        return any(str(env.get(name) or "").strip() for name in DISPLAYS)

    def _terminal(self) -> tuple[str, Terminal] | None:
        """The terminal program a window is opened with on Linux, and where it is: (its path, its Terminal); None
        without a display, or when none is on the platform's PATH. x-terminal-emulator comes first, when its link
        leads to one of TERMINALS (its user's choice); then TERMINALS in their order. Each is looked for with
        shutil.which (the Outside's `which`), which looks at files and starts nothing: a status asks at every draw.
        It looks in this system's own folders of PATH alone (`_own_path`)."""
        if not self._display():
            return None
        path = _own_path(self._env().get("PATH"))
        if path == "":  # (no folder of this system's own on it: nothing to look in)
            return None

        def found(name: str) -> str:
            try:
                return str(self.out.which(name, path=path) or "")
            except Exception:  # noqa: BLE001 - a look that fails finds nothing
                return ""

        chosen = found(ALTERNATIVE)
        if chosen:
            try:
                real = str(_link_target(chosen) or "")
            except (OSError, ValueError):
                real = ""
            terminal = BY_NAME.get(posixpath.basename(real.replace("\\", "/")))
            if terminal is not None:
                return real, terminal
        for terminal in TERMINALS:
            where = found(terminal.name)
            if where:
                return where, terminal
        return None

    def _window_env(self, launch: children.Launch) -> dict[str, str]:
        """A window's environment: the launch's (children.environment), and on Linux the display's variables of the
        platform's environment (DESKTOP_KEEPS) whatever the launch drops, which its terminal opens the window with.
        The launch's own value of one wins."""
        env = children.environment(launch, base=self.out.env, system=self.system)
        if self.system != "windows":
            base = self._env()
            for name in DESKTOP_KEEPS:
                value = base.get(name)
                if value and name not in launch.env:
                    env[name] = str(value)
        return env

    def _opens(self, desktop: bool, terminal: tuple[str, Terminal] | None) -> str:
        """How it opens, in words: a window, and on Linux which terminal it is and where it shows (under WSLg,
        Windows' desktop), or the lines to paste, and on Linux what a window still needs."""
        if self.system == "windows":
            return OPENS[desktop]
        if terminal is not None:
            where = ", on Windows' desktop (WSLg)" if self.wsl else ""
            return f"in a terminal window of its own ({terminal[1].name}){where}, in the folder you give"
        if self._display():
            return f"{OPENS[False]} ({_no_terminal()})"
        return OPENS[False]

    # -- the hooks ----------------------------------------------------------------------------------------------------
    def refresh(self) -> dict:
        """What is installed looked at again (AiPlugin's), and what the model servers serve asked again at the next
        draw."""
        self._forget_servers()
        return super().refresh()

    def use(self, server, model, *values) -> dict:
        """It is started against `server` ("<plugin>/<instance>") with `model` from now on, with its OPTIONS' `values`
        in their order (one left empty: the tool's own default), kept through the login; nothing is written into the
        tool's own configuration. Refused in words: no server named; one not offered now; one it cannot use
        (`fits`); no model, or one the server does not list; an option's value; more values than it has OPTIONS.
        With Liminal's MCP turned on, the MCP plugin is asked how it is reached and for this harness's agent first;
        nothing is kept when it cannot be wired."""
        self._usable()
        name = self.title or self.name
        if server is None or not str(server).strip():
            raise Refusal("choose a model server: one of the instances the Model servers table lists")
        plugin, instance = split_server(server)
        if self.app is None:
            raise Refusal(NO_APP)
        at = self.serving_of(f"{plugin}/{instance}", fresh=True)
        if at is None:
            raise Refusal(f"{plugin}/{instance} is not offered now: choose one of the instances the Model servers "
                          "table lists (its plugin may be off, or the instance removed)")
        words = server_words(at)
        unfit = self.fits(at)
        if unfit:
            raise Refusal(unfit)
        model = clean_model(model, words, self.OPENERS)
        listed = model_ids(at)
        if listed and model not in listed:
            raise Refusal(f"{words} lists no model {model!r} (it lists {', '.join(listed[:MODELS_SHOWN])}"
                          f"{' …' if len(listed) > MODELS_SHOWN else ''}): Ask… reads its list again")
        options = self._options_of(values)
        mcp = self._mcp_use(options)  # (asked of the MCP plugin before anything is kept)
        before, _ = self._kept()
        chosen = Use(at["server"], model, before.folder if before is not None else "", options)
        where = self.keep_pair(self.variable("use"), chosen.text())
        lasting = self.lasting()
        return self._reply(f"From now on {name} is started against {words} with {model}", True,
                           [f"kept in {where}", *mcp, *([lasting] if lasting else [])])

    def open(self, folder=None) -> dict:
        """It is started in `folder` against what it uses. With a desktop, in a terminal window of its own: on Windows
        a console window (CREATE_NEW_CONSOLE), on Linux a terminal program's (`_terminal`), held by `python -m
        liminal_libs.console hold -- ...`; the server's key read through the login and given in its environment
        alone, and so is the window's token for Liminal's MCP where Use… turned it on. Anywhere else the lines to
        paste into a terminal of yours, the key among them as its placeholder, and no token. The folder is kept for
        the next time. Refused in words: its library too old; not installed; `runs_here`; an install under way;
        nothing chosen; a folder that is not a whole path, not one here, or on another system's drive; its server not
        offered now, one it cannot use, a local one that is not running, or one found here that answers nothing; its
        plugin's own refusal (`launch`), a launch that would put the key or the token on its command line, Liminal's
        MCP on and its plugin not answering, and lines PowerShell would not hand its words as they are."""
        self._usable()
        use, at, path = self._ready(folder, opening=True)
        name, words = self.title or self.name, server_words(at)
        if not self._desktop():
            made, _, variable = self._prepared(path, use, at, children.PLACEHOLDER if self._keyed(at) else "",
                                               window=False)
            lines = self._shown(made)
            notes = [MCP_LINES.format(variable=variable) if variable else "", self._keep_folder(path)]
            return self._lines(_noted(RUN_IT, notes), lines)
        made, token, _ = self._prepared(path, use, at, self._key_of(at), window=True)
        try:
            pid, held = self._window(made, path, token)
        except BaseException:
            self._end_launch(token)  # (nothing opened: its token goes at once)
            raise
        unkept = self._keep_folder(path)
        mcp = "Liminal's MCP: the window has a token of its own, ended once it is gone" if token else ""
        lines = [f"its window's process: {pid}" if pid else "", "closing the window ends it", held, mcp, unkept]
        return self._reply(f"{name} opened in a window of its own in {path}, started against {words} with {use.model}",
                           True, lines)

    def command(self, folder=None) -> dict:
        """The lines that start it in `folder` (None: the folder kept from the last Open…) against what it uses, to
        paste into a terminal of yours (PowerShell's on Windows, sh's on Linux): nothing is started. A key is never
        among them: its placeholder is, for you to type. No token for Liminal's MCP is asked for them: its words say
        where one is given. Refused as Open… is, but for a server that is not running or answers nothing (the lines
        are for later)."""
        self._usable()
        use, at, path = self._ready(folder, opening=False)
        made, _, variable = self._prepared(path, use, at, children.PLACEHOLDER if self._keyed(at) else "",
                                           window=False)
        return self._lines(_noted(RUN_IT, [MCP_LINES.format(variable=variable) if variable else ""]),
                           self._shown(made))

    def ask_models(self, server) -> dict:
        """The models of `server` ("<plugin>/<instance>"), asked of it now through its plugin (`models_of`): its words
        and a line for each model; the Model servers table reads what its plugin serves again at the next draw."""
        self._usable()
        plugin, instance = split_server(server)
        app = self.app
        if app is None:
            raise Refusal(NO_APP)
        try:
            said = app.ask(plugin, MODELS_OF, [instance])  # the platform's form: the arguments as one list
        except Exception as e:  # noqa: BLE001 - another plugin's refusal or failure, in its words
            raise Refusal(f"{plugin}/{instance} could not be asked for its models: {self._refused(e)}") from None
        finally:
            self._forget_servers()
        if not isinstance(said, Mapping):
            raise Refusal(f"{plugin}/{instance}'s answer is not a list of models")
        models = [m for m in _listed(said.get("models")) if isinstance(m, (Mapping, str))]
        ids = model_ids({"models": models})
        many = len(ids)
        words = str(said.get("said") or f"{plugin}/{instance} lists {many} model{'' if many == 1 else 's'}")
        out = self._reply(words, said.get("ok") is not False, [_model_line(m) for m in models])
        out["models"] = ids
        if said.get("asked"):
            out["asked"] = str(said.get("asked"))
        return out

    # -- what a start needs -------------------------------------------------------------------------------------------
    def _ready(self, folder, *, opening: bool) -> tuple[Use, dict, str]:
        """What a start needs, each refusal in words before anything is done: (the choice, its instance, the folder)."""
        name = self.title or self.name
        if self.installed() is None:
            raise Refusal(f"{name} is not installed here: Install… first")
        here = self.runs_here()
        if here:
            raise Refusal(here)
        changing = self.changing_words()  # (Open… was refused so already, by `starting`; Command… is refused here)
        if changing:
            raise Refusal(changing)
        use, trouble = self._kept()
        if use is None:
            raise Refusal(f"{CHOOSE} ({trouble})" if trouble else CHOOSE)
        typed = "" if folder is None else str(folder)  # (a Path as its text)
        path = self._folder(typed if typed.strip() else use.folder)  # left empty: the folder kept
        if self.app is None:
            raise Refusal(NO_APP)
        at = self.serving_of(use.server, fresh=True)
        if at is None:
            raise Refusal(f"{use.server} is not offered now (its plugin is off, or the instance was removed): Use… "
                          "chooses another")
        unfit = self.fits(at)
        if unfit:
            raise Refusal(unfit)
        down = _not_running(at) if opening else ""
        if down:
            raise Refusal(down)
        return use, at, path

    def _folder(self, given) -> str:
        """The folder typed, checked: a whole path, of this system's own disk, a folder here. A Refusal in words."""
        name = self.title or self.name
        example = EXAMPLES["windows" if self.system == "windows" else "linux"]
        text = str(given if given is not None else "").strip()
        if len(text) >= 2 and text[0] == text[-1] == '"':  # pasted with its quotes
            text = text[1:-1].strip()
        if not text:
            raise Refusal(f"give the folder to open {name} in: a whole path, such as {example}")
        if len(text) > FOLDER_CHARS or _control(text):
            raise Refusal(f"a folder is a whole path of {FOLDER_CHARS:,} characters at most, without a line break or a "
                          "control character")
        if not os.path.isabs(text):
            start = "its drive" if self.system == "windows" else "the root"
            raise Refusal(f"{text} is not a whole path: give it from {start}, such as {example}")
        path = os.path.normpath(text)
        try:
            foreign = bool(mounts.foreign(path))
        except Exception:  # noqa: BLE001 - a path that cannot be judged is this system's
            foreign = False
        if foreign:
            raise Refusal(f"{path} is on another system's drive: open it from that system's platform")
        if not os.path.isdir(path):
            raise Refusal(f"there is no folder {path} here")
        return path

    @staticmethod
    def _keyed(at: Mapping) -> bool:
        return bool(str(at.get("key") or "").strip())

    def _key_of(self, at: Mapping) -> str:
        """The server's key, read through the login by the variable its `serving` row names ("": it has none). A
        Refusal in words when it has one and it cannot be read."""
        variable = str(at.get("key") or "").strip()
        if not variable:
            return ""
        words, plugin = server_words(at), at.get("plugin_title") or at.get("plugin")
        if not VARIABLE.fullmatch(variable):
            raise Refusal(f"{words}'s key cannot be read: {variable[:60]!r} is not the name of a pair")
        key = self.pair(variable)
        if not key:
            raise Refusal(f"{words} is asked with a key, and none could be read through your login: sign in, or keep "
                          f"its key again on {plugin}'s page")
        return key

    def _launch(self, folder: str, use: Use, at: dict, key: str) -> children.Launch:
        """The plugin's launch, checked and completed: every pair of Liminal's dropped (`dropping`), the folder its own
        unless it names one, the variables holding the key secret; refused when the key would be on the command
        line. The plugin's refusal passes on in its words, without a secret."""
        name = self.title or self.name
        try:
            made = self.launch(folder, use, dict(at), key)
        except ValueError as e:  # the plugin's refusal (a Refusal among them), in its words
            raise Refusal(self._scrubbed(_line(e)), accept=getattr(e, "accept", None)) from None
        except Exception as e:  # noqa: BLE001 - its words, without a secret
            raise children.ChildError(f"{name} could not be prepared: {self._scrubbed(_line(e, named=True))}") from None
        if not isinstance(made, children.Launch):
            raise children.ChildError(f"{name}'s launch is {type(made).__name__}, not a children.Launch")
        if not made.argv:
            raise children.ChildError(f"{name}'s launch names no program")
        made = self.dropping(made)
        if not made.cwd:
            made = dataclasses.replace(made, cwd=folder)
        if key:  # (the folder its user chose is no part of the command, whatever letters it holds)
            words = (*made.argv, made.cwd) if made.cwd != folder else made.argv
            if any(children.carries(word, key, KEY_INSIDE) for word in words):
                raise Refusal(f"{name} would put {server_words(at)}'s key on its command line, where every program "
                              "here can read it: it is not started (its plugin hands a key over in the environment)")
            same = [variable for variable, value in made.env.items() if value == key]
            made = dataclasses.replace(made, secret=tuple(dict.fromkeys([*made.secret, *same])))
        return made

    def _window(self, launch: children.Launch, folder: str, token: str = "") -> tuple[int | None, str]:
        """The launch started in a window of its own, held open by the console's `hold` until its user has read how it
        ended: (its process's number, "" or what is to be said of it). The window is followed while it is open, with
        its launch token (`token`, ended once it is gone: `running`).

        Windows: a console window. It is asked to leave any job object the platform is held in
        (CREATE_BREAKAWAY_FROM_JOB: a keeper's, keep.py's, ends what it holds with itself), since a window is its
        user's; where that job lets nothing leave it, Windows refuses the start, and the window is started in it all
        the same, which is said. Linux: the terminal program `_terminal` finds, given the command word by word, in a
        session of its own (a window outlives the platform), with nothing of the platform's standard input or
        output."""
        name = self.title or self.name
        env = self._window_env(launch)
        popen = self.out.popen if self.out.popen is not None else subprocess.Popen  # looked up now: a test's stands in
        where, note = launch.cwd or folder, ""
        try:
            if self.system == "windows":
                argv = console.hold_command(launch.argv)
                try:
                    child = popen(argv, env=env, cwd=where, creationflags=NEW_CONSOLE | BREAKAWAY)
                except PermissionError:  # the platform is held in a job that lets nothing leave it
                    child = popen(argv, env=env, cwd=where, creationflags=NEW_CONSOLE)
                    note = HELD_WORDS
            else:
                found = self._terminal()
                if found is None:
                    raise children.ChildError(f"{name}'s window could not be opened: {_no_terminal()}")
                path, terminal = found
                child = popen(terminal.argv(path, where, console.hold_command(launch.argv)), env=env, cwd=where,
                              start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        except (OSError, ValueError, TypeError) as e:
            raise children.ChildError(f"{name}'s window could not be opened: {self._scrubbed(_line(e))}") from None
        with self._rt.lock:
            self._rt.windows = [*self._rt.windows, (child, folder)][-WINDOWS_KEPT:]
            past: list[tuple[object, str]] = []
            if token:
                tokens = [*self._rt.tokens, (child, token)]
                past, self._rt.tokens = tokens[:-TOKENS_KEPT], tokens[-TOKENS_KEPT:]
        for _, old in past:  # (no lock held: asked of the MCP plugin through the platform)
            self._end_launch(old)
        pid = getattr(child, "pid", None)
        return (pid if isinstance(pid, int) and not isinstance(pid, bool) else None), note

    def _keep_folder(self, folder: str) -> str:
        """The folder opened kept for the next time, in the choice as it is kept now: "" when it is (or was already),
        else why not, in words."""
        try:
            now, _ = self._kept()
            if now is None or now.folder == folder:
                return ""
            self.keep_pair(self.variable("use"), dataclasses.replace(now, folder=folder).text())
        except Exception as e:  # noqa: BLE001 - it opened all the same
            return f"the folder is not kept for the next time: {self._scrubbed(_line(e))}"
        return ""

    def _shown(self, launch: children.Launch) -> list[str]:
        """The launch as lines to paste into a terminal of yours (children.shown), unsetting what it drops as that
        terminal has it (`_terminal_env`). A secret this plugin read or kept through its login is its placeholder
        wherever it is a whole value of the launch (a variable's value, a word, all after a word's last "=") or, of
        KEY_INSIDE characters or more, inside one (children.masked); the lines are otherwise left as they are, since
        they are run as they are. A Refusal in words for a launch PowerShell cannot be given as it is
        (children.not_passed)."""
        with self._rt.lock:
            values = sorted(self._rt.secrets, key=len, reverse=True)
        if values:  # (replaced where they are, not named secret: children would then look for them in every word)
            def hidden(text: str) -> str:
                return children.masked(text, values, KEY_INSIDE)
            launch = dataclasses.replace(launch, argv=tuple(map(hidden, launch.argv)), cwd=hidden(launch.cwd),
                                         env={name: hidden(value) for name, value in launch.env.items()})
        try:
            return children.shown(launch, self.system, base=self._terminal_env())
        except ValueError as e:
            raise Refusal(self._scrubbed(_line(e))) from None

    def _terminal_env(self) -> Mapping[str, str]:
        """The environment a terminal of yours starts with, as far as this process can tell: the Outside's when it
        gives one (a test's); else this process's, and on Windows the user's saved variables beside it, since every
        new terminal has a pair another program saved after the platform started (the charts, the integrator, the
        login, tools/set-key.ps1), which this process has not."""
        if self.out.env is not None:
            return self.out.env
        if self.system != "windows":
            return os.environ
        try:
            saved = dict(authorization.saved_variables() or {})
        except Exception:  # noqa: BLE001 - not read: this process's own alone
            saved = {}
        return {**saved, **os.environ}

    def _lines(self, said: str, lines: Iterable[str]) -> dict:
        """An answer of lines to paste: each as it is (none left out, cut or changed: they are run as they are, and
        `_shown` made them without a secret), its words without one."""
        return {"said": self._scrubbed(said), "ok": True, "lines": [str(x) for x in lines]}

    # -- what the page draws ------------------------------------------------------------------------------------------
    def status(self) -> dict:
        """Its Main: AiPlugin's (the install), then what it uses, the folder it opens in, how it opens, its own tables
        (main_more), the Model servers table, and the forms and buttons of Use…, Open…, Command… and Ask…. Nothing is
        asked over the network and nothing is started; what the model servers serve is asked of their plugins
        through the platform (kept SERVING_S). Never raises."""
        out = self.base_status()
        if out.get("applies") is False or not out.get("valid", True):
            return out
        problems = [str(out["problem"])] if out.get("problem") else []
        use, trouble = self._kept()
        if trouble:
            problems.append(trouble)
        served, notes = self._served()
        every = _every(served)
        chosen = every.get(use.server) if use is not None else None
        terminal = self._terminal() if self.system != "windows" else None  # (files looked at: nothing is started)
        desktop = terminal is not None if self.system != "windows" else self._desktop()
        out["uses"] = self._uses(use, chosen)
        if use is not None and use.folder:
            out["opensIn"] = use.folder
        out["opens"] = self._opens(desktop, terminal)
        more = self._more(problems)
        have, here = self.installed(), self.runs_here()
        out["tables"] = [*_listed(out.get("tables")), *_listed(more.get("tables")),
                         self._servers_table(every, notes, use)]
        out["forms"] = [*_listed(out.get("forms")), self._use_form(every, use),
                        self._open_form(use, chosen, desktop, problems, terminal), self._command_form(use),
                        self._models_form(), *_listed(more.get("forms"))]
        out["actions"] = [*_listed(out.get("actions")), *self._buttons(have, here, use, chosen, every),
                          *_listed(more.get("actions"))]
        if problems:
            out["problem"] = "; ".join(problems)
        return out

    @staticmethod
    def _uses(use: Use | None, chosen: Mapping | None) -> str:
        if use is None:
            return "nothing yet"
        if chosen is None:
            return f"{use.server}: {use.model} (not offered now)"
        return f"{server_words(chosen)}: {use.model}"

    def _more(self, problems: list[str]) -> Mapping:
        name = self.title or self.name
        try:
            more = self.main_more() or {}
        except Exception as e:  # noqa: BLE001 - the rest of its page is drawn all the same
            problems.append(f"part of {name}'s page could not be drawn: {self._scrubbed(_line(e, named=True))}")
            return {}
        if not isinstance(more, Mapping):
            problems.append(f"part of {name}'s page could not be drawn: main_more answered {type(more).__name__}")
            return {}
        return more

    def _fit(self, at: Mapping) -> str:
        """`fits` as the page draws it: a fault of the plugin's said in words, never raised."""
        try:
            return str(self.fits(at) or "")
        except Exception as e:  # noqa: BLE001 - the rest of its page is drawn all the same
            return (f"whether {self.title or self.name} can use {server_words(at)} could not be told: "
                    f"{self._scrubbed(_line(e, named=True))}")

    def _blocked(self, have, here: str, use: Use | None, chosen: Mapping | None, opening: bool) -> str:
        """Why Open… (`opening`) or Command… cannot be asked now, in words ("": it can): what their refusals check,
        from what is read already."""
        name = self.title or self.name
        if have is None:
            return f"{name} is not installed here: Install… first"
        if here:
            return here
        if self._rt.changing.locked():
            return "an install or an uninstall is under way"
        if use is None:
            return CHOOSE
        if chosen is None:
            return f"{use.server} is not offered now: Use… chooses another"
        unfit = self._fit(chosen)
        if unfit:
            return unfit
        return _not_running(chosen) if opening else ""

    def _buttons(self, have, here: str, use: Use | None, chosen: Mapping | None, every: Mapping) -> list[dict]:
        values: dict = {}
        if use is not None and use.server in every:
            values = {"server": use.server, "model": use.model}
        elif every:
            first = next(iter(every))
            values = {"server": first, "model": _default_model(every[first], None)}
        pick = {"form": "ai-use", "title": "Use…", "values": values}
        if not every:
            pick.update(disabled=True, note=NO_SERVER)
        out = [pick]
        for form, title, opening in (("ai-open", "Open…", True), ("ai-command", "Command…", False)):
            button = {"form": form, "title": title}
            why = self._blocked(have, here, use, chosen, opening)
            out.append({**button, "disabled": True, "note": why} if why else button)
        return out

    def _servers_table(self, every: Mapping[str, dict], notes: list[str], use: Use | None) -> dict:
        rows = []
        for key, at in every.items():
            words, mine = server_words(at), use is not None and use.server == key
            title, where = str(at.get("title") or ""), WHERE_WORDS.get(str(at.get("where") or ""), "")
            unfit = self._fit(at)
            pick = {"form": "ai-use", "title": "Use…", "label": f"Use {words}",
                    "values": {"server": key, "model": _default_model(at, use if mine else None)}}
            if unfit:
                pick.update(disabled=True, note=unfit)
            asked = str(at.get("asked") or "")
            about = " · ".join(x for x in (title, where, "in use" if mine else "") if x)
            rows.append([
                {"text": at["plugin_title"], "sub": at["plugin"]},
                {"text": str(at.get("name")), "sub": about},
                {"text": str(at.get("base") or at.get("openai") or ""),
                 "sub": "plain http to another machine" if at.get("plain") else ""},
                {"text": str(at.get("state") or "not said"),
                 "sub": f"start it on {at['plugin_title']}'s page" if _stopped(at) else ""},
                {"text": _models_words(at), "sub": f"listed {asked}" if asked else ""},
                pick,
                {"form": "ai-models", "title": "Ask…", "label": f"Ask {words} for its models now",
                 "values": {"server": key}},
            ])
        said = (f"What the inference plugins serve, as each says it, read again every {SERVING_S:g} s while this page "
                "is shown; Ask… asks one server for its models now.")
        return {"title": "Model servers",
                "columns": [{"title": "Server"}, {"title": "Instance"}, {"title": "Address"}, {"title": "State"},
                            {"title": "Models"}, {"title": ""}, {"title": ""}],
                "rows": rows, "note": " ".join([said, *(f"{n}." if not n.endswith(".") else n for n in notes)]),
                "empty": NO_SERVER[0].upper() + NO_SERVER[1:] + "."}

    def _use_form(self, every: Mapping[str, dict], use: Use | None) -> dict:
        name = self.title or self.name
        server: dict = {"name": "server", "label": "Model server", "type": "choice",
                        "choices": [{"value": key, "title": server_words(at), "note": _state_words(at)}
                                    for key, at in every.items()],
                        "note": "an instance an inference plugin holds (AI plugins, Inference)"}
        value = use.server if use is not None and use.server in every else next(iter(every), None)
        if value is not None:
            server["value"] = value
        model: dict = {"name": "model", "label": "Model", "type": "text", "required": True,
                       "placeholder": "its id, as its server lists it",
                       "note": "as its server lists it: the Model servers table's Models column (Ask… lists them now)"}
        if use is not None and use.model:
            model["value"] = use.model
        options = [s.field(use.options.get(s.name) if use is not None else None) for s in self.OPTIONS]
        return {"id": "ai-use", "hook": "use", "title": "Use a model server", "submit": "Review",
                "note": f"What {name} is started against, kept through your login.",
                "fields": [server, model, *options],
                "confirm": {"title": "Use {server} with {model}?",
                            "words": (f"From now on {name} is started against it: kept through your login, given at "
                                      f"each start, nothing written into {name}'s own configuration."),
                            "yes": "Use it"}}

    def _folder_field(self, use: Use | None, required: bool) -> dict:
        example = EXAMPLES["windows" if self.system == "windows" else "linux"]
        out: dict = {"name": "folder", "label": "Folder", "type": "text", "placeholder": f"a whole path: {example}"}
        if use is not None and use.folder:
            out["value"] = use.folder
        if required:
            out.update(required=True, note="a whole path on this system's own disk; the one opened is kept for the "
                                           "next time")
        else:
            out["note"] = "left empty: the folder kept from the last Open…"
        return out

    def _open_form(self, use: Use | None, chosen: Mapping | None, desktop: bool, problems: list[str],
                   terminal: tuple[str, Terminal] | None = None) -> dict:
        name = self.title or self.name
        server = (server_words(chosen) if chosen is not None else use.server if use is not None
                  else "the model server you choose (Use…)")
        if desktop and terminal is not None:  # (Linux)
            words = f"A terminal window ({terminal[1].name}) opens there with {name} started against {server}."
            if self.wsl:
                words += " It opens on Windows' desktop, through WSLg."
            words += " Closing it ends it."
            yes = "Open it"
        elif desktop:
            words = f"A terminal window opens there with {name} started against {server}. Closing it ends it."
            yes = "Open it"
        else:
            words, yes = ("No window can be opened from here: the command is shown, to run in a terminal of yours.",
                          "Show the command")
            if self.system != "windows" and self._display():
                said = _no_terminal()
                words += f" {said[0].upper()}{said[1:]}."
        if use is not None and chosen is not None:
            try:
                more = str(self.open_words(use, chosen) or "")
            except Exception as e:  # noqa: BLE001 - Open… is drawn all the same
                problems.append(f"what {name} says before it starts could not be read: "
                                f"{self._scrubbed(_line(e, named=True))}")
                more = ""
            if more.strip():
                words += more if more[:1].isspace() else " " + more
        return {"id": "ai-open", "hook": "open", "title": f"Open {name}", "submit": "Review",
                "fields": [self._folder_field(use, required=True)],
                "confirm": {"title": f"Open {name} in {{folder}}?", "words": words, "yes": yes}}

    def _command_form(self, use: Use | None) -> dict:
        name = self.title or self.name
        return {"id": "ai-command", "hook": "command", "title": f"The command that starts {name}", "confirm": False,
                "submit": "Show it",
                "note": ("The lines to paste into a terminal of yours: nothing is started. A key is never among them: "
                         "its placeholder is, for you to type."),
                "fields": [self._folder_field(use, required=False)]}

    @staticmethod
    def _models_form() -> dict:
        return {"id": "ai-models", "hook": "ask_models", "title": "Its models, asked now", "confirm": False,
                "fields": [{"name": "server", "label": "Model server", "type": "fixed"}]}


def _default_model(at: Mapping, use: Use | None) -> str:
    """The model a Use… button fills in: the one kept for this server, else the one it is set to serve, else the first
    it lists."""
    if use is not None and use.model:
        return use.model
    said = str(at.get("model") or "").strip()
    if said:
        return said
    ids = model_ids(at)
    return ids[0] if ids else ""


def _models_words(at: Mapping) -> str:
    ids = model_ids(at)
    if not ids:
        return "not listed yet"
    more = len(ids) - MODELS_SHOWN
    return ", ".join(ids[:MODELS_SHOWN]) + (f" and {more} more" if more > 0 else "")


def _state_words(at: Mapping) -> str:
    where = WHERE_WORDS.get(str(at.get("where") or ""), "")
    return " · ".join(x for x in (str(at.get("state") or ""), where, str(at.get("base") or "")) if x)


def _model_line(m) -> str:
    """A model in a line: its id, its context and whether it calls tools, where its server says."""
    if isinstance(m, str):
        return m.strip()
    said = [str(m.get("id") or "?").strip()]
    context = m.get("context")
    if isinstance(context, int) and not isinstance(context, bool) and context > 0:
        said.append(f"context {context:,}")
    tools = m.get("tools")
    if tools is True:
        said.append("calls tools")
    elif tools is False:
        said.append("calls no tools")
    return " · ".join(said)
