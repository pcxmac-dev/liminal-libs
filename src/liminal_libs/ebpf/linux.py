"""The eBPF runtime on a native Linux machine (the design: "LinuxRuntime uses bpftool -j through
machines.linux.Shell, with sudo -n"). It reads the kernel's eBPF state through bpftool and a few /proc and /sys
files, and builds the confirmed, elevated load, attach, detach and unload commands; it never asks for a password.

Native Linux only (the user, 2026-11-08: "the scope of linux administration is only on native linux O/S"): on
Windows or inside WSL it reports `applies` False through `machines.linux.why_not_native`, and every read and change
says why rather than run. Listing and reading objects needs root, which `Shell` takes through `sudo -n`; the tool
versions and the world-readable settings are read without it."""
from __future__ import annotations

import json
import re

from ..machines.linux import Shell, why_not_native
from ..machines.plugin import CommandError
from .runtime import Runtime

WHAT = "The eBPF runtime"
BPF_FS = "/sys/fs/bpf"  # where pins live; a pin outside it is refused
PIN_PREFIX = "liminal_"  # a pin of Liminal's own: /sys/fs/bpf/liminal_<name>
DUMP_LIMIT = 1000  # entries a map dump returns at most
DUMP_BYTES = 8_000_000  # the most of a map dump's output read (bounded RAM): `head -c`, then the entries that fit
NET_KINDS = ("xdp", "xdpgeneric", "xdpdrv", "xdpoffload", "tcx_ingress", "tcx_egress")  # bpftool net attach types
PROG_KINDS = ("sk_msg_verdict", "sk_skb_verdict", "sk_skb_stream_verdict", "sk_skb_stream_parser",
              "flow_dissector")  # bpftool prog attach types
CGROUP_FLAGS = ("multi", "override")
_WORD = re.compile(r"[a-z][a-z0-9_]*")


def _json(text: str):
    """What a `bpftool -j ...` printed, or None when it was not JSON (an error line, nothing)."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _rows(data) -> list[dict]:
    """A bpftool list as rows: a JSON array of objects, or a single object, else nothing."""
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return [data] if isinstance(data, dict) else []


def _array_prefix(text: str, limit: int) -> list:
    """The first `limit` elements of a JSON array that may be cut short (a dump read only so far): each whole
    element in turn, stopping at the cut, the end of the array or the limit."""
    decoder = json.JSONDecoder()
    start = text.find("[")
    if start < 0:
        return []
    i, n, out = start + 1, len(text), []
    while len(out) < limit:
        while i < n and text[i] in " \t\r\n,":
            i += 1
        if i >= n or text[i] == "]":
            break
        try:
            item, i = decoder.raw_decode(text, i)
        except ValueError:
            break  # the element the read cut through
        out.append(item)
    return out


def _bpftool_words(e: CommandError) -> CommandError:
    """bpftool's own words out of a failure: with -j it prints {"error": "..."} rather than a line of text."""
    data = _json(str(e))
    if isinstance(data, dict) and data.get("error"):
        return CommandError(f"bpftool: {data['error']}", denied=e.denied)
    return e


def in_bpf_fs(path) -> bool:
    """Whether `path` is a plain path under the BPF filesystem (/sys/fs/bpf/...), with no `..` in it."""
    text = str(path or "")
    parts = text.split("/")
    return text.startswith(BPF_FS + "/") and ".." not in parts and "" not in parts[4:]


def liminal_pin(path) -> bool:
    """Whether a pin is one of Liminal's own (/sys/fs/bpf/liminal_...): a plugin asks twice before it removes any
    other (the rule: risky changes asked twice)."""
    return in_bpf_fs(path) and str(path)[len(BPF_FS) + 1:].startswith(PIN_PREFIX)


def default_pin(path) -> str:
    """Where a loaded program is pinned unless said: /sys/fs/bpf/liminal_<the file's stem>. bpftool takes no dot in
    a pin's name (bpffs keeps dots for itself), so anything but letters, digits, _ and - becomes _."""
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    stem = re.sub(r"[^A-Za-z0-9_-]", "_", stem).strip("_") or "prog"
    return f"{BPF_FS}/{PIN_PREFIX}{stem}"


class LinuxRuntime(Runtime):
    """The kernel's eBPF, read and driven through bpftool and `Shell`. `shell` stands in for the commands in
    tests; `system`, `release` and `env` stand in for the native-Linux check."""

    system = "linux"

    def __init__(self, shell: Shell | None = None, *, system=None, release=None, env=None):
        self.shell = shell if shell is not None else Shell("local")
        self._why = why_not_native(WHAT, system, release, env)

    def applies(self) -> tuple[bool, str]:
        return (not self._why), self._why

    def _here(self) -> None:
        """Refuse, in words, on a machine this runtime is not for (Windows, WSL): nothing is run there."""
        if self._why:
            raise CommandError(self._why)

    # -- status ----------------------------------------------------------------------------------------------

    def status(self) -> dict:
        """The kernel release (the runtime's version: eBPF is the kernel's), the bpftool and libbpf versions,
        whether unprivileged BPF is disabled, the JIT setting, kernel BTF, the BPF filesystem's mounts and whether
        bpftrace is there. `present` is whether bpftool answered; `why` says what is missing."""
        if self._why:
            return {"present": False, "system": "linux", "applies": False, "version": "", "why": self._why,
                    "summary": "not for this machine"}
        out: dict = {"present": False, "system": "linux", "applies": True, "version": "", "why": "",
                     "kernel": "", "bpftool": "", "libbpf": "", "features": [],
                     "unprivileged_bpf_disabled": None, "bpf_jit_enable": None, "btf": False, "bpffs": [],
                     "bpftrace": "", "bpftrace_present": False}
        out["kernel"] = out["version"] = self._plain("uname", "-r")
        version = self._version()
        if isinstance(version, dict):
            out["present"] = True
            out["bpftool"] = str(version.get("version") or "")
            out["libbpf"] = str(version.get("libbpf_version") or "")
            feats = version.get("features")
            if isinstance(feats, dict):
                out["features"] = sorted(k for k, v in feats.items() if v)
            elif isinstance(feats, list):
                out["features"] = [str(f) for f in feats]
        out["unprivileged_bpf_disabled"] = self._number("/proc/sys/kernel/unprivileged_bpf_disabled")
        out["bpf_jit_enable"] = self._number("/proc/sys/net/core/bpf_jit_enable")
        out["btf"] = bool(self._plain("ls", "/sys/kernel/btf/vmlinux"))
        out["bpffs"] = _bpf_mounts(self._plain("cat", "/proc/mounts"))
        bpftrace = self._plain("bpftrace", "-V")
        out["bpftrace"] = bpftrace
        out["bpftrace_present"] = bool(bpftrace)
        missing = []
        if not out["present"]:
            missing.append("bpftool did not answer: it is not installed here (the distribution's bpftool package)")
        if not out["bpftrace_present"]:
            missing.append("bpftrace is not installed: the watch's scripts are compiled on this machine by "
                           "bpftrace (the distribution's bpftrace package)")
        out["why"] = "; ".join(missing)
        out["summary"] = self._summary(out)
        return out

    def _summary(self, out: dict) -> str:
        parts = [f"kernel {out['kernel']}" if out["kernel"] else "Linux"]
        parts.append(f"bpftool {out['bpftool']}" if out["bpftool"] else "no bpftool")
        parts.append("bpftrace present" if out["bpftrace_present"] else "no bpftrace (the watch needs it)")
        if not out["btf"]:
            parts.append("no kernel BTF")
        return ", ".join(parts)

    def _version(self):
        """`bpftool -j version`, which needs no root: as the platform's user, then through `sudo -n` (bpftool may
        sit on root's path only, /usr/sbin)."""
        for root in (False, True):
            try:
                data = _json(self.shell.run("bpftool", "-j", "version", root=root, timeout=15))
            except CommandError:
                continue
            if isinstance(data, dict):
                return data
        return None

    # -- programs, maps, links -------------------------------------------------------------------------------

    def _bpftool(self, *args: str):
        """`bpftool -j <args>` as root, its JSON; CommandError in bpftool's words (or `Shell`'s, when sudo -n is
        refused: denied, with how to give it the rights)."""
        self._here()
        try:
            return _json(self.shell.run("bpftool", "-j", *args, timeout=30))
        except CommandError as e:
            raise _bpftool_words(e) from None

    def programs(self) -> list[dict]:
        return _rows(self._bpftool("prog", "show"))

    def maps(self) -> list[dict]:
        return _rows(self._bpftool("map", "show"))

    def links(self) -> list[dict]:
        return _rows(self._bpftool("link", "show"))

    def program(self, prog_id) -> dict:
        rows = _rows(self._bpftool("prog", "show", "id", str(int(prog_id))))
        return rows[0] if rows and "error" not in rows[0] else {}

    def dump_map(self, map_id, limit: int = DUMP_LIMIT) -> list[dict]:
        """The map's first `limit` entries. The dump is read through `head -c` so at most DUMP_BYTES come back,
        however large the map, and only the whole entries in that are kept."""
        self._here()
        limit = max(1, int(limit))
        script = f"bpftool -j map dump id {int(map_id)} 2>&1 | head -c {DUMP_BYTES}"
        text = self.shell.sh(script, timeout=60)
        data = _json(text)
        if isinstance(data, dict) and data.get("error"):
            raise CommandError(f"bpftool: {data['error']}")
        if not text.lstrip().startswith("["):
            words = text.strip().splitlines()[-1] if text.strip() else f"map {int(map_id)} could not be read"
            raise CommandError(words)
        return [e for e in _array_prefix(text, limit) if isinstance(e, dict)]

    # -- change (the plugin confirms first; these build and run the commands) --------------------------------

    def load(self, path, *, pin=None, type=None, pinmaps=None) -> str:
        """`bpftool prog load <path> <pin> [type T] [pinmaps DIR]`. The pin defaults to /sys/fs/bpf/liminal_<stem>,
        so the program outlives the loader and is plainly Liminal's."""
        self._here()
        pin = pin or default_pin(path)
        _check_pin(pin)
        command = ["bpftool", "prog", "load", str(path), str(pin)]
        if type:
            command += ["type", _word(type, "a program type")]
        if pinmaps:
            _check_pin(pinmaps, "the maps' pin folder")
            command += ["pinmaps", str(pinmaps)]
        return self._change(command)

    def attach(self, *, kind, target=None, pin=None, prog_id=None, flags=None, map_id=None,
               overwrite=False) -> str:
        """Attach a program. `kind` is a bpftool attach word:
          - xdp, xdpgeneric, xdpdrv, xdpoffload, tcx_ingress, tcx_egress: `bpftool net attach KIND PROG dev TARGET`,
            TARGET a network device (`overwrite` replaces a program already attached there);
          - sk_msg_verdict, sk_skb_verdict, sk_skb_stream_verdict, sk_skb_stream_parser, flow_dissector:
            `bpftool prog attach PROG KIND [id MAP]`, the sk_* kinds needing the sockmap's id (`map_id`);
          - any other is a cgroup attach type (connect4, sendmsg4, recvmsg4, sock_ops, ingress, egress and so on):
            `bpftool cgroup attach TARGET KIND PROG [multi|override]`, TARGET a cgroup v2 folder under /sys/fs/cgroup.
        PROG is `pinned <pin>` or `id <prog_id>`; one of them is needed."""
        self._here()
        kind = _word(kind, "the attach type")
        prog = _prog(pin, prog_id)
        if kind in NET_KINDS:
            command = ["bpftool", "net", "attach", kind, *prog, "dev", _device(target)]
            if overwrite:
                command.append("overwrite")
        elif kind in PROG_KINDS:
            command = ["bpftool", "prog", "attach", *prog, kind]
            if map_id is not None:
                command += ["id", str(int(map_id))]
            elif kind != "flow_dissector":
                raise CommandError(f"a {kind} attach needs the sockmap's id (map_id)")
        else:
            command = ["bpftool", "cgroup", "attach", _cgroup(target), kind, *prog]
            if flags:
                flag = _word(flags, "the cgroup attach flag")
                if flag not in CGROUP_FLAGS:
                    raise CommandError(f"the cgroup attach flag is {' or '.join(CGROUP_FLAGS)}, not {flags!r}")
                command.append(flag)
        return self._change(command)

    def detach(self, *, link_id=None, kind=None, target=None, pin=None, prog_id=None, map_id=None) -> str:
        """Detach an attachment, the way it was made:
          - `link_id`: `bpftool link detach id N`, a link-based attachment (bpftool link show lists them);
          - an XDP or tcx `kind` with its device: `bpftool net detach KIND dev TARGET`;
          - a prog-attach `kind`: `bpftool prog detach PROG KIND [id MAP]`;
          - a cgroup `kind` with its folder: `bpftool cgroup detach TARGET KIND PROG`."""
        self._here()
        if link_id is not None:
            return self._change(["bpftool", "link", "detach", "id", str(int(link_id))])
        if not kind:
            raise CommandError("say what to detach: a link's id, or the attach type with its target")
        kind = _word(kind, "the attach type")
        if kind in NET_KINDS:
            return self._change(["bpftool", "net", "detach", kind, "dev", _device(target)])
        prog = _prog(pin, prog_id)
        if kind in PROG_KINDS:
            command = ["bpftool", "prog", "detach", *prog, kind]
            if map_id is not None:
                command += ["id", str(int(map_id))]
            return self._change(command)
        return self._change(["bpftool", "cgroup", "detach", _cgroup(target), kind, *prog])

    def unload(self, *, pin=None) -> str:
        """Unload a program by removing its pin (`rm -f` as root): once nothing else holds it (a link, an attachment,
        another pin, an open file), the kernel frees it. A pin that is not Liminal's own (`liminal_pin`) is asked
        about twice by the plugin before this runs (the rule: risky changes asked twice)."""
        self._here()
        if not pin:
            raise CommandError("say which pin to remove: a path under /sys/fs/bpf")
        _check_pin(pin)
        return self._change(["rm", "-f", str(pin)])

    def _change(self, command: list[str]) -> str:
        """A change as root through `sudo -n` (never a password): its output, or CommandError in bpftool's words."""
        try:
            return self.shell.run(*command, timeout=60)
        except CommandError as e:
            raise _bpftool_words(e) from None

    # -- reads that need no root -------------------------------------------------------------------------------

    def _plain(self, *command: str) -> str:
        """A command's output as the platform's own user, stripped: "" when it is missing or failed. For the tool
        versions and the world-readable /proc and /sys files, which need no root."""
        try:
            return (self.shell.run(*command, root=False, timeout=15, check=False) or "").strip()
        except CommandError:
            return ""

    def _number(self, path: str):
        """The whole number a /proc or /sys file holds, or None when it cannot be read."""
        text = self._plain("cat", path)
        try:
            return int(text.split()[0])
        except (ValueError, IndexError):
            return None


def _bpf_mounts(text: str) -> list[str]:
    """Where the BPF filesystem is mounted, from /proc/mounts: the lines whose type is bpf (at most 16)."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "bpf" and parts[1] not in out:
            out.append(parts[1])
    return out[:16]


def _check_pin(pin, what: str = "the pin") -> None:
    """Refuse a pin outside the BPF filesystem, or one with `..` in it: commands run as root."""
    if not in_bpf_fs(pin):
        raise CommandError(f"{what} must be a plain path under {BPF_FS}/, with no '..': {pin!r}")


def _word(value, what: str) -> str:
    """A bpftool keyword (an attach type, a flag): lower-case letters, digits and _, nothing else."""
    text = str(value or "").strip().lower()
    if not _WORD.fullmatch(text):
        raise CommandError(f"{what} must be a plain word (letters, digits and _): {value!r}")
    return text


def _prog(pin, prog_id) -> list[str]:
    """How bpftool names the program: `pinned <pin>` or `id <n>`."""
    if pin:
        _check_pin(pin)
        return ["pinned", str(pin)]
    if prog_id is not None:
        return ["id", str(int(prog_id))]
    raise CommandError("say which program: its pin (a path under /sys/fs/bpf) or its id")


_DEVICE = re.compile(r"[A-Za-z0-9_.@-]{1,15}")  # a Linux interface name: at most 15 characters, no slash or space


def _device(target) -> str:
    """A network device's name, checked: an XDP or tcx attach goes on one."""
    text = str(target or "").strip()
    if not _DEVICE.fullmatch(text):
        raise CommandError(f"an XDP or tcx attach needs a network device's name (eth0, wlan0 and the like), not {target!r}")
    return text


def _cgroup(target) -> str:
    """A cgroup v2 folder under /sys/fs/cgroup, checked: a cgroup attach goes on one."""
    text = str(target or "").strip()
    parts = text.split("/")
    if not (text == "/sys/fs/cgroup" or text.startswith("/sys/fs/cgroup/")) or ".." in parts or any(c.isspace() for c in text):
        raise CommandError(f"a cgroup attach needs a cgroup v2 folder under /sys/fs/cgroup, not {target!r}")
    return text.rstrip("/") or "/sys/fs/cgroup"
