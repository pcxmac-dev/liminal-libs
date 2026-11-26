"""What a plugin needs of the machine it runs on, and the judgement of it against this machine's facts (liminal-libs
1.103.0; Monday list item 19, part two, release 1: the needs plan's revision 2 of 2026-11-24, with the user's twenty
answers of 2026-11-25).

The user, 2026-11-18: every plugin has a "needs" requirement (the operating system, the hardware platform, GPUs, the
internet); a plugin whose needs this machine cannot meet is not shown in the left-most list; the Connections view gets a
tab of all of the app's plugins, red for those that could but do not meet current conditions, shaded for those that
never can here.

A plugin says it in NEEDS, a plain tuple of rows on its class, read by name and never called, so it imports nothing:

    class UbuntuPlugin(WslDistribution):
        NEEDS = (*getattr(WslDistribution, "NEEDS", ()),
                 ("architecture", "x86-64|arm64", "required", "the systems Ubuntu's WSL image is built for"),
                 ("disk", ">= 4 GiB", "part", "its install"))

- A row is two to four str: the attribute (ATTRIBUTES; a `windows:` or `linux:` prefix makes it one system's), its
  value, its strength (STRENGTHS, "required" when left out) and its words (at most WORDS_CHARS). `a|b` is any of them.
- `required`, unmet: the plugin is out of the list (the platform's state "unmet"). `part`, unmet: that part is said
  unavailable in its words, and the plugin stays as it is. `preferred`: said, nothing else. A part and a preference say
  which part, or what it gains, in their words. Tools, rights, other plugins, the disk and the desktop are never
  required (PARTS_ONLY: the user's answer 1, a plugin's install, keys and rights are its validity).
- `Plugin` itself has no NEEDS, so a plugin that says nothing ("It has not said what it needs yet") is told apart from
  one that needs nothing (`NEEDS = ()`: "It needs nothing of this machine"). A class adds to its base's only through
  getattr, as above; NEEDS is never a property and never annotated (a record's dataclass would take it for a field).

The judgement (`judge`) is pure and never raises: the rows and the facts in (liminal_libs.facts' shape, read without
sending anything), an answer out, each row met, unmet, unknown or na (not this system's), and each unmet one of the
machine (nothing can change it here: shaded) or of the moment (something can: red), with what was read (`said`) and what
would meet it (`how`). A fact that cannot be read never hides a plugin (the user's answer 10): unknown, and the plugin is
judged by its own status as before. `problems(plugin)` is what a plugin's own test holds its rows to.

Plain: the standard library alone, so the frame, the login and the charts' front may import it.
"""
from __future__ import annotations

import re

VOCABULARY = 1
FIRST = (1, 103, 0)  # the release this module came in: a `library` row at or below it says nothing (M2)
STRENGTHS = ("required", "part", "preferred")
PARTS_ONLY = ("rights", "tool", "plugin", "disk", "desktop")  # never required (decision 1, S11)
PREFIXES = ("windows", "linux")
OFF_FEATURE = "need"  # decision 18 (a): a Windows feature that is off is a need of the moment; "validity": (b)
MAX_ROWS, WORDS_CHARS = 40, 200
INTERNET_APART_S = 15.0  # two readings this far apart before the internet is unmet (decision 2, M9)
NOT_SAID = "It has not said what it needs yet"
NOTHING = "It needs nothing of this machine"
NOT_KNOWN = "not known here"

ARCHITECTURES = ("x86-64", "arm64", "x86", "arm")
CPU_FLAGS = ("avx", "avx2", "avx512f", "sse4.2", "nx")
VIRTUALIZATION = ("extensions", "slat", "firmware", "hypervisor", "kvm")
INITS = ("systemd", "openrc", "sysv", "runit", "s6", "dinit", "busybox", "wsl")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_SIZE = re.compile(r"^\s*(?:>=\s*)?(\d+(?:\.\d+)?)\s*(TiB|GiB|MiB|KiB|TB|GB|MB|KB)\s*$", re.IGNORECASE)
_BUILD = re.compile(r"^\s*>=\s*(\d+)(?:\.(\d+))?\s*(?:\(([^()]*)\))?\s*$")
_VERSION = re.compile(r"^\s*>=\s*(\d+)\.(\d+)\.(\d+)\s*$")
_UNITS = {"kib": 2**10, "mib": 2**20, "gib": 2**30, "tib": 2**40, "kb": 10**3, "mb": 10**6, "gb": 10**9, "tb": 10**12}
_ARCH_WORDS = {"x86-64": "x86-64", "x86_64": "x86-64", "amd64": "x86-64", "x64": "x86-64", "arm64": "arm64",
               "aarch64": "arm64", "arm64e": "arm64", "x86": "x86", "i386": "x86", "i486": "x86", "i586": "x86",
               "i686": "x86", "arm": "arm", "armv7l": "arm", "armv6l": "arm", "armhf": "arm"}


def normal_architecture(word) -> str:
    """A machine's name in the vocabulary's words: AMD64 and x86_64 are x86-64, ARM64 and aarch64 arm64, i386 to i686
    x86, armv7l arm; "" for none of them."""
    return _ARCH_WORDS.get(str(word or "").strip().lower(), "")


def size_of(text) -> int | None:
    """">= 4 GiB", ">=20 GiB", "512 MiB": bytes; None when it is no size."""
    m = _SIZE.match(str(text or ""))
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()]) if m else None


def builds_of(text) -> list[tuple[int, int, str]] | None:
    """Windows builds, each `>= BUILD[.UBR] [(label)]`, alternatives joined by " or ": [(build, ubr, label)], ubr 0
    when none is named; None when it is not that."""
    parts = [p for p in str(text or "").split(" or ")]
    out = []
    for p in parts:
        m = _BUILD.match(p)
        if not m:
            return None
        out.append((int(m.group(1)), int(m.group(2) or 0), (m.group(3) or "").strip()))
    return out or None


def _version(text) -> tuple[int, int, int] | None:
    m = _VERSION.match(str(text or ""))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _choices(text) -> list[str]:
    return [x.strip() for x in str(text or "").split("|")]


def _of(allowed):
    return lambda v: all(x.lower() in allowed for x in _choices(v))


def _names(v) -> bool:
    return all(_NAME.match(x) for x in _choices(v))


def _rights(v) -> bool:
    return all(x.lower() in ("administrator", "root") or (x.lower().startswith("group:") and len(x) > 6)
               for x in _choices(v))


# attribute -> (a test of its value, the values in words)
ATTRIBUTES = {
    "kernel": (_of(("windows", "linux")), "windows, linux"),
    "windows.build": (lambda v: builds_of(v) is not None, ">= BUILD[.UBR], alternatives joined by ' or '"),
    "windows.feature": (_names, "a Windows feature's name, a|b any of them"),
    "architecture": (lambda v: all(normal_architecture(x) for x in _choices(v)), "x86-64, arm64, x86, arm; any of"),
    "cpu": (_of(CPU_FLAGS), "avx, avx2, avx512f, sse4.2, nx; any of"),
    "virtualization": (_of(VIRTUALIZATION), "extensions, slat, firmware, hypervisor, kvm"),
    "memory": (lambda v: size_of(v) is not None, ">= N GiB (or MiB), installed"),
    "wsl": (_of(("none", "1", "2")), "none, 1, 2; any of"),
    "linux.feature": (_of(("netfilter", "ebpf")), "netfilter, ebpf"),
    "init": (_of(INITS), "systemd, openrc (or sysv, runit, s6, dinit, busybox, wsl); any of"),
    "internet": (_of(("yes", "ipv4", "ipv6")), "yes, ipv4, ipv6"),
    "library": (lambda v: _version(v) is not None, ">= X.Y.Z (liminal-libs)"),
    "disk": (lambda v: size_of(v) is not None, ">= N GiB free on the data folder's drive"),
    "desktop": (_of(("yes",)), "yes: a desktop Windows can ask on (UAC, a window)"),
    "tool": (_names, "a program's name (npcap, libpcap known by their files); any of"),
    "plugin": (_names, "another plugin of the same app, active; any of"),
    "rights": (_rights, "administrator, root, group:NAME; any of"),
}
# what a Windows or a Linux alone has: on the other system the row is not this system's (na)
_WINDOWS_ONLY = ("windows.build", "windows.feature")
_LINUX_ONLY = ("linux.feature", "init")


# -- the declaration ---------------------------------------------------------------------------------------------------
def _class(plugin):
    return plugin if isinstance(plugin, type) else type(plugin)


def _name(plugin) -> str:
    try:
        name = getattr(plugin, "name", "")
    except Exception:  # noqa: BLE001 - a name that raises is no name
        name = ""
    return str(name or "") if isinstance(name, str) and name else _class(plugin).__name__


def says(plugin) -> bool:
    """Whether it says what it needs: a class of its line has NEEDS in its own __dict__ (Plugin has none, S9)."""
    try:
        return any("NEEDS" in vars(k) for k in _class(plugin).__mro__)
    except Exception:  # noqa: BLE001
        return False


def rows_of(plugin):
    """Its NEEDS as declared, read by getattr in its own try; None when it says nothing or it cannot be read."""
    if not says(plugin):
        return None
    try:
        return getattr(plugin, "NEEDS", None)
    except Exception:  # noqa: BLE001 - a NEEDS that raises says nothing
        return None


def _split(attribute: str) -> tuple[str, str]:
    """("windows", "architecture") for "windows:architecture"; ("", attribute) with no prefix."""
    head, sep, rest = attribute.partition(":")
    return (head.strip().lower(), rest.strip()) if sep else ("", attribute.strip())


def _row_words(row):
    return isinstance(row, (tuple, list)) and 2 <= len(row) <= 4 and all(isinstance(x, str) and x.strip() for x in row)


def _normal_value(attribute: str, value: str) -> str:
    if attribute == "architecture":
        return "|".join(normal_architecture(x) or x.lower() for x in _choices(value))
    if attribute in ("kernel", "cpu", "virtualization", "wsl", "linux.feature", "init", "internet", "desktop",
                     "rights"):
        return "|".join(x.lower() for x in _choices(value))
    return value.strip()


def declared(plugin) -> list[dict]:
    """Its sound rows, normalized: [{attribute, value, strength, words}]. A row of the wrong shape or strength is left
    out (problems() says it); a `required` tool, right, plugin, disk or desktop is taken as a part."""
    value = rows_of(plugin)
    if not isinstance(value, tuple):
        return []
    out, seen = [], set()
    for row in value[:MAX_ROWS]:
        if not _row_words(row):
            continue
        attribute, val = row[0].strip(), row[1].strip()
        strength = (row[2].strip().lower() if len(row) > 2 else "required")
        words = row[3].strip()[:WORDS_CHARS] if len(row) > 3 else ""
        if strength not in STRENGTHS:
            continue
        prefix, bare = _split(attribute)
        if prefix and prefix not in PREFIXES:
            continue
        bare = bare.lower()
        if strength == "required" and bare in PARTS_ONLY:
            strength = "part"
        attribute = f"{prefix}:{bare}" if prefix else bare
        val = _normal_value(bare, val)
        if (attribute, val) in seen:
            continue
        seen.add((attribute, val))
        out.append({"attribute": attribute, "value": val, "strength": strength, "words": words})
    return out


def attributes(rows) -> set[str]:
    """The facts these rows need read, by their bare attribute names."""
    return {_split(str(r.get("attribute", "")))[1] for r in rows or () if isinstance(r, dict)} - {""}


def unknown(rows) -> list[str]:
    """The attributes of these rows the vocabulary does not know (gpu, libc ...: release 2): judged unknown, said."""
    out = []
    for r in rows or ():
        a = _split(str(r.get("attribute", "")))[1] if isinstance(r, dict) else ""
        if a and a not in ATTRIBUTES and a not in out:
            out.append(a)
    return out


def own_words(plugin) -> str:
    """Its not_for_here(), in its own try: why it is not for this machine in its own words; "" when it has none or it
    raises. By contract it asks nothing."""
    try:
        ask = getattr(plugin, "not_for_here", None)
        words = ask() if callable(ask) else ""
    except Exception:  # noqa: BLE001 - a check that raises says nothing
        return ""
    return str(words or "").strip()[:WORDS_CHARS * 2] if isinstance(words, str) else ""


def _annotated(cls) -> bool:
    for k in cls.__mro__:
        try:
            notes = vars(k).get("__annotations__")
            if notes is None and "__annotate__" in vars(k):
                import inspect

                notes = inspect.get_annotations(k)
        except Exception:  # noqa: BLE001 - annotations that cannot be read are not NEEDS's
            notes = None
        if isinstance(notes, dict) and "NEEDS" in notes:
            return True
    return False


def problems(plugin, *, values: bool = True) -> list[str]:
    """What is wrong with what it says it needs, each naming `plugin 'name'`; [] when it says nothing (unless it has a
    needs() method instead) or says it well. `values` False: the rows' shape alone (conformance), not whether each
    value is one of its attribute's."""
    who = f"plugin {_name(plugin)!r}"
    cls = _class(plugin)
    out: list[str] = []
    if not says(plugin):
        try:
            method = getattr(plugin, "needs", None)
        except Exception:  # noqa: BLE001
            method = None
        if callable(method):
            out.append(f"{who}: its needs() answers GET /api/plugins/{{name}}/needs but is not judged: declare NEEDS")
        return out
    for k in cls.__mro__:
        if "NEEDS" in vars(k) and isinstance(vars(k)["NEEDS"], property):
            out.append(f"{who}: NEEDS must be a plain tuple on its class ({k.__name__} makes it a property)")
            return out
    if _annotated(cls):
        out.append(f"{who}: NEEDS is never annotated (a record's dataclass would take it for a field)")
    try:
        value = getattr(plugin, "NEEDS", None)
    except Exception as e:  # noqa: BLE001
        return [*out, f"{who}: NEEDS could not be read ({type(e).__name__}: {e})"]
    if not isinstance(value, tuple):
        return [*out, f"{who}: NEEDS must be a tuple of rows"]
    if len(value) > MAX_ROWS:
        out.append(f"{who}: {len(value)} rows, more than {MAX_ROWS}")
    seen = set()
    for i, row in enumerate(value, 1):
        if not _row_words(row):
            out.append(f"{who}: row {i}: {row!r:.120} is not two to four words")
            continue
        attribute, val = row[0].strip(), row[1].strip()
        strength = row[2].strip().lower() if len(row) > 2 else "required"
        words = row[3].strip() if len(row) > 3 else ""
        prefix, bare = _split(attribute)
        bare = bare.lower()
        if prefix and prefix not in PREFIXES:
            out.append(f"{who}: row {i}: the prefix {prefix!r} is neither windows: nor linux:")
        if strength not in STRENGTHS:
            out.append(f"{who}: row {i}: strength {strength!r} is none of {', '.join(STRENGTHS)}")
        elif strength != "required" and not words:
            out.append(f"{who}: row {i}: a {strength} need says {'which part' if strength == 'part' else 'what it gains'}"
                       " (its words)")
        if strength == "required" and bare in PARTS_ONLY:
            out.append(f"{who}: row {i}: {bare} is never required (a plugin asks for it at a click, or says how in its "
                       "validity)")
        if len(words) > WORDS_CHARS:
            out.append(f"{who}: row {i}: its words are over {WORDS_CHARS} characters")
        key = (f"{prefix}:{bare}" if prefix else bare, _normal_value(bare, val))
        if key in seen:
            out.append(f"{who}: row {i}: given twice")
        seen.add(key)
        if values and bare in ATTRIBUTES:
            test, said = ATTRIBUTES[bare]
            try:
                ok = bool(test(val))
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                out.append(f"{who}: row {i}: {val!r} is not a value of {bare} ({said})")
            elif bare == "library" and (_version(val) or (0, 0, 0)) <= FIRST:
                out.append(f"{who}: row {i}: a library row at or below {'.'.join(map(str, FIRST))} says nothing: "
                           "the release that judges needs is that one")
    return out


# -- the judgement -----------------------------------------------------------------------------------------------------
def _d(facts, *keys):
    """facts[keys[0]][keys[1]]..., None where any is missing or not a dict."""
    v = facts
    for k in keys:
        if not isinstance(v, dict):
            return None
        v = v.get(k)
    return v


def _why(facts, fact: str) -> str:
    words = _d(facts, "why", fact)
    return f"{NOT_KNOWN}: {words}" if isinstance(words, str) and words else f"{NOT_KNOWN}: not read"


def _gib(n) -> str:
    return f"{n / 2**30:.1f} GiB".replace(".0 GiB", " GiB")


def _in_vm(facts) -> str:
    vm = _d(facts, "virtualization", "vm")
    return vm if isinstance(vm, str) else ""


def _in_wsl(facts) -> str:
    w = facts.get("wsl")
    return w if w in ("1", "2") else ""


def _host_words(facts, what: str) -> str:
    return (f"this virtual machine's host gives it {what}: its settings there can change that"
            f" ({_in_vm(facts)})")


def _kernel(value, facts):
    name = _d(facts, "kernel", "name")
    if name not in ("windows", "linux"):
        return "unknown", "", _why(facts, "kernel"), ""
    if name in _choices(value):
        if name == "linux" and _in_wsl(facts) == "1":
            return "met", "", "WSL 1: Linux programs on Windows' kernel", ""
        return "met", "", f"this is {name.capitalize()}", ""
    return "unmet", "machine", f"this is {name.capitalize()}", ""


def _build(value, facts):
    build, ubr = _d(facts, "windows", "build"), _d(facts, "windows", "ubr")
    if not isinstance(build, int) or build <= 0:
        return "unknown", "", _why(facts, "windows"), ""
    alts = builds_of(value) or []
    said = f"build {build}" + (f".{ubr}" if isinstance(ubr, int) and ubr > 0 else "")
    if build > max(b for b, _r, _l in alts):
        late = any(r for _b, r, _l in alts)
        return "met", "", said + (" (a later Windows carries the update)" if late else ""), ""
    for b, r, _label in alts:
        if not r and build >= b:
            return "met", "", said, ""
        if r and build == b:
            if not isinstance(ubr, int):
                return "unknown", "", f"{said}: its update (UBR) {NOT_KNOWN}", ""
            if ubr >= r:
                return "met", "", said, ""
    return "unmet", "moment", said, "Windows Update brings it"


_FEATURE_HOW = "turn it on in Windows Features (optionalfeatures.exe), as administrator, then restart Windows"


def _feature(value, facts):
    features = _d(facts, "windows", "features")
    if not _d(facts, "windows", "featuresRead") or not isinstance(features, dict):
        return "unknown", "", _why(facts, "features"), ""
    names = _choices(value)
    states = {n: features.get(n, 3) for n in names}
    on = [n for n, s in states.items() if s == 1]
    if on:
        return "met", "", f"{on[0]} is on", ""
    off = [n for n, s in states.items() if s == 2]
    if off:
        said = f"{' and '.join(off)} {'is' if len(off) == 1 else 'are'} off"
        if OFF_FEATURE == "validity":
            return "met", "", said + " (its status says whether it is valid)", ""
        return "unmet", "moment", said, _FEATURE_HOW
    server = _d(facts, "windows", "server")
    product = _d(facts, "windows", "product") or _d(facts, "windows", "edition") or "this Windows"
    if server is not False:
        why = "a Windows Server has it as a role" if server else "whether this is a Windows Server is not known"
        return "unknown", "", f"{NOT_KNOWN}: no {' or '.join(names)} listed, and {why}", ""
    return "unmet", "machine", f"this edition of Windows ({product}) has no {' or '.join(names)}", ""


def _architecture(value, facts):
    arch = normal_architecture(facts.get("architecture"))
    if not arch:
        return "unknown", "", _why(facts, "architecture"), ""
    if arch in _choices(value):
        return "met", "", arch, ""
    return "unmet", "machine", f"this processor is {arch}", ""


def _arm_windows(facts) -> bool:
    return facts.get("system") == "windows" and normal_architecture(facts.get("architecture")) == "arm64"


def _cpu(value, facts):
    flags = facts.get("cpu") if isinstance(facts.get("cpu"), dict) else {}
    seen = []
    for v in _choices(value):
        have = flags.get(v)
        if have is True:
            return "met", "", f"the processor has {v}" + (", on" if v == "nx" else ""), ""
        seen.append((v, have))
    if any(have is None for _v, have in seen):
        return "unknown", "", _why(facts, "cpu"), ""
    if _arm_windows(facts):
        return "unknown", "", f"{NOT_KNOWN}: Windows on Arm reads no for these flags, never seen read right", ""
    names = " or ".join(v for v, _h in seen)
    if _in_vm(facts):
        return "unmet", "moment", f"this virtual processor has no {names}", _host_words(facts, "its processor features")
    if [v for v, _h in seen] == ["nx"]:
        hardware = flags.get("nxHardware")
        if hardware is True:
            return ("unmet", "moment", "the processor has NX, and Data Execution Prevention is off",
                    "bcdedit /set nx OptIn as administrator, then restart Windows")
        if hardware is None and facts.get("system") == "windows":
            return "unknown", "", f"{NOT_KNOWN}: NX is off, and whether the processor has it is not read", ""
    return "unmet", "machine", f"the processor has no {names}", ""


_FIRMWARE_HOW = "switch Intel VT-x or AMD-V on in the firmware's settings (BIOS or UEFI), then start the PC again"


def _virtualization(value, facts):
    v = value
    virt = facts.get("virtualization") if isinstance(facts.get("virtualization"), dict) else {}
    system = facts.get("system")
    vm = _in_vm(facts)
    if v == "kvm":
        if system != "linux":
            return "na", "", "KVM is Linux's", ""
        kvm = virt.get("kvm")
        if kvm is True:
            return "met", "", "/dev/kvm is there", ""
        if kvm is None:
            return "unknown", "", _why(facts, "kvm"), ""
        ext = virt.get("extensions")
        if _in_wsl(facts) == "1":
            how = "wsl --set-version with 2, from Windows: WSL 1 has no Linux kernel"
        elif _in_wsl(facts) == "2" and ext is not True:
            how = "nested virtualization on in .wslconfig (nestedVirtualization=true), then wsl --shutdown"
        elif ext is True:
            how = "load kvm_intel or kvm_amd (modprobe, as root)"
        elif vm:
            how = "nested virtualization on in this virtual machine's host"
        else:
            how = _FIRMWARE_HOW
        return "unmet", "moment", "no /dev/kvm" + ("" if ext is not False else ", and no vmx or svm"), how
    if v == "hypervisor":
        if system != "windows":
            return "na", "", "Windows' hypervisor: not this system's", ""
        h = virt.get("hypervisor")
        if h is True:
            return "met", "", "Windows' hypervisor runs", ""
        if h is None:
            return "unknown", "", _why(facts, "virtualization"), ""
        return ("unmet", "moment", "Windows' hypervisor does not run",
                "turn Hyper-V (or the Virtual Machine Platform) on in Windows Features, then restart Windows")
    have = virt.get(v)
    if system == "windows":
        if virt.get("hypervisor") is True and not vm:
            return "met", "", "Windows' hypervisor runs, which it cannot without it (the processor's flags read no while it runs)", ""
        if have is True:
            return "met", "", f"{v}: yes", ""
        if have is None:
            return "unknown", "", _why(facts, "virtualization"), ""
        if vm:
            return "unknown", "", f"{NOT_KNOWN}: a virtual machine's processor ({vm}) reads no here, its host decides", ""
        if _arm_windows(facts):
            return "unknown", "", f"{NOT_KNOWN}: Windows on Arm reads no here, never seen read right", ""
        if v == "firmware" or virt.get("firmware") is False:
            return "unmet", "moment", f"{v}: no" + (", the firmware's switch reads off" if v != "firmware" else ""), _FIRMWARE_HOW
        return "unmet", "machine", f"the processor has no {'VT-x or AMD-V' if v == 'extensions' else 'SLAT'}", ""
    if system == "linux":
        ext = virt.get("extensions")
        if v == "firmware":
            if ext is True:
                return "met", "", "vmx or svm shown: on in the firmware", ""
            return "unknown", "", f"{NOT_KNOWN}: the firmware's switch is not read on Linux", ""
        if have is True:
            return "met", "", f"{v}: yes", ""
        if have is None:
            return "unknown", "", _why(facts, "cpu"), ""
        if v == "extensions" or vm or _in_wsl(facts):
            how = ("nested virtualization on in .wslconfig, then wsl --shutdown" if _in_wsl(facts) == "2" else
                   "nested virtualization on in this virtual machine's host" if vm else _FIRMWARE_HOW)
            return "unmet", "moment", f"no {'vmx or svm' if v == 'extensions' else 'ept or npt'}", how
        return "unmet", "machine", "the processor has no ept or npt (SLAT)", ""
    return "unknown", "", _why(facts, "virtualization"), ""


def _memory(value, facts):
    need = size_of(value) or 0
    installed, usable = _d(facts, "memory", "installed"), _d(facts, "memory", "usable")
    have = installed if isinstance(installed, int) and installed > 0 else (
        int(usable * 1.05) if isinstance(usable, (int, float)) and usable > 0 else None)
    if have is None:
        return "unknown", "", _why(facts, "memory"), ""
    said = f"{_gib(have)} {'installed' if have == installed else 'usable'}"
    if have >= need:
        return "met", "", said, ""
    if _in_wsl(facts):
        return "unmet", "moment", said + " (WSL's share)", f"memory= in .wslconfig, then wsl --shutdown"
    if _in_vm(facts):
        return "unmet", "moment", said, _host_words(facts, _gib(have))
    return "unmet", "machine", said, ""


def _wsl(value, facts):
    w = facts.get("wsl")
    if w not in ("none", "1", "2"):
        return "unknown", "", _why(facts, "wsl"), ""
    said = "not in WSL" if w == "none" else f"WSL {w}"
    if w in _choices(value):
        return "met", "", said, ""
    how = "wsl --set-version with 2, from Windows" if w == "1" else ""
    return "unmet", "moment", said, how


def _linux_feature(value, facts):
    if _in_wsl(facts) == "1":
        return "unmet", "moment", "WSL 1 has no Linux kernel", "wsl --set-version with 2, from Windows"
    found = _d(facts, "linux")
    found = found if isinstance(found, dict) else {}
    seen = [found.get(v) for v in _choices(value)]
    if True in seen:
        return "met", "", f"{value}: there", ""
    if None in seen:
        return "unknown", "", _why(facts, "linux"), ""
    return "unmet", "machine", f"this kernel has no {value}", ""


def _init(value, facts):
    init = facts.get("init")
    if init not in INITS:
        return "unknown", "", _why(facts, "init"), ""
    if init in _choices(value):
        return "met", "", f"{init} runs", ""
    if _in_wsl(facts):
        return "unmet", "moment", f"{init} runs", "[boot] systemd=true in /etc/wsl.conf, then wsl --shutdown"
    return "unmet", "machine", f"{init} runs", ""


def internet_now(facts) -> tuple[str, str]:
    """The internet as judged from the readings kept (M9): ("yes" | "no" | "unknown", words). A "no" counts once two
    readings at least INTERNET_APART_S apart agree; before that it is judged as the reading before it, and a process's
    first "no" is unknown."""
    net = facts.get("internet") if isinstance(facts.get("internet"), dict) else {}
    state = net.get("state")
    readings = [r for r in (net.get("readings") or ()) if isinstance(r, (list, tuple)) and len(r) == 2]
    if not readings and state in ("yes", "no", "unknown"):
        readings = [(0.0, state)]
    if not readings:
        return "unknown", str(net.get("why") or "not read")
    last = readings[-1][1]
    if last != "no":
        return (last if last in ("yes", "unknown") else "unknown"), str(net.get("why") or "")
    run = [r for r in readings]
    i = len(run) - 1
    while i > 0 and run[i - 1][1] == "no":
        i -= 1
    if len(run) - i >= 2 and float(run[-1][0]) - float(run[i][0]) >= INTERNET_APART_S:
        return "no", str(net.get("why") or "")
    if i > 0:
        before = run[i - 1][1]
        return (before if before in ("yes", "unknown") else "unknown"), "one reading says no: judged as before until a second agrees"
    return "unknown", "the first reading says no: judged once a second agrees"


def _internet(value, facts, rule, offline):
    if offline:
        return "unmet", "moment", f"Liminal is set offline ({offline}): nothing is sent", f"turn {offline} off"
    if rule == "there":
        return "met", "", "taken as there (your switch)", ""
    by = _d(facts, "internet", "by") or ""
    state, why = internet_now(facts)
    if state == "unknown":
        return "unknown", "", f"{NOT_KNOWN}: {why or 'nothing here judges it'}", ""
    if state == "no":
        return "unmet", "moment", f"no internet ({by})" if by else "no internet", "the internet back"
    for v in _choices(value):
        if v == "yes":
            return "met", "", f"there ({by})" if by else "there", ""
        flag = _d(facts, "internet", v)
        if flag is True:
            return "met", "", f"{v.upper().replace('IPV', 'IPv')} there" + (f" ({by})" if by else ""), ""
    flags = [_d(facts, "internet", v) for v in _choices(value)]
    if None in flags:
        return "unknown", "", f"{NOT_KNOWN}: {value} not told apart here", ""
    return "unmet", "moment", f"no {value.replace('ipv', 'IPv')} internet", "the internet back over it"


def _library(value, facts):
    need = _version(value)
    have = tuple(int(x) for x in re.findall(r"\d+", str(facts.get("library") or ""))[:3])
    if len(have) != 3 or need is None:
        return "unknown", "", _why(facts, "library"), ""
    said = "liminal-libs " + ".".join(map(str, have))
    return ("met", "", said, "") if have >= need else ("unmet", "moment", said, "update liminal-libs")


def _disk(value, facts):
    need, free, path = size_of(value) or 0, _d(facts, "disk", "free"), _d(facts, "disk", "path") or "the data folder"
    if not isinstance(free, int) or free < 0:
        return "unknown", "", _why(facts, "disk"), ""
    said = f"{_gib(free)} free on {path}"
    return ("met", "", said, "") if free >= need else ("unmet", "moment", said, f"free space on {path}")


def _desktop(value, facts):
    d = facts.get("desktop")
    if d is True:
        return "met", "", "a desktop to ask on", ""
    if d is None:
        return "unknown", "", _why(facts, "desktop"), ""
    return ("unmet", "moment", "no desktop to ask on (a service's, or a task's run with nobody signed in)",
            "start it from a signed-in desktop")


def _tool(value, facts):
    tools = facts.get("tools") if isinstance(facts.get("tools"), dict) else {}
    seen = [tools.get(v) for v in _choices(value)]
    if True in seen:
        return "met", "", f"{_choices(value)[seen.index(True)]} is there", ""
    if None in seen:
        return "unknown", "", _why(facts, "tools"), ""
    return "unmet", "moment", f"no {value.replace('|', ' or ')} here", f"install {_choices(value)[0]}"


def _plugin(value, plugins):
    if not isinstance(plugins, dict):
        return "unknown", "", f"{NOT_KNOWN}: this app's plugins' states were not handed in", ""
    names = _choices(value)
    states = [plugins.get(n) for n in names]
    if any(s in ("active", "attached") for s in states):
        return "met", "", f"{names[[s in ('active', 'attached') for s in states].index(True)]} is active", ""
    if states and all(s == "cannot" for s in states):
        return "na", "", "none of them is for this machine", ""
    return "unmet", "moment", f"{' or '.join(names)} not active", f"switch {names[0]} on"


def _rights_row(value, facts):
    rights = facts.get("rights") if isinstance(facts.get("rights"), dict) else None
    if rights is None:
        return "unknown", "", _why(facts, "rights"), ""
    for v in _choices(value):
        low = v.lower()
        if low in ("administrator", "root") and rights.get(low) is True:
            return "met", "", f"{low}", ""
        if low.startswith("group:") and v[6:] in (rights.get("groups") or ()):
            return "met", "", f"in {v[6:]}", ""
    return "unmet", "moment", "not " + value.replace("|", " nor "), "the rights its page asks for, then start it again"


def _row(row, facts, plugins, rule, offline):
    prefix, attribute = _split(row["attribute"])
    value = row["value"]
    system = facts.get("system")
    if prefix and system in PREFIXES and prefix != system:
        return "na", "", f"{prefix.capitalize()}'s alone: not this system's", ""
    if attribute not in ATTRIBUTES:
        return "unknown", "", (f"{NOT_KNOWN}: vocabulary {VOCABULARY} has no {attribute!r} "
                               "(release 2 reads GPUs and libc)"), ""
    test = ATTRIBUTES[attribute][0]
    if not test(value):
        return "unknown", "", f"{NOT_KNOWN}: {value!r} is not a value of {attribute} this release reads", ""
    if attribute in _WINDOWS_ONLY and system == "linux":
        return "na", "", "Windows' alone: not this system's", ""
    if attribute in _LINUX_ONLY and system == "windows":
        return "na", "", "Linux's alone: not this system's", ""
    if attribute == "internet":
        return _internet(value, facts, rule, offline)
    if attribute == "plugin":
        return _plugin(value, plugins)
    judge_one = {"kernel": _kernel, "windows.build": _build, "windows.feature": _feature,
                 "architecture": _architecture, "cpu": _cpu, "virtualization": _virtualization, "memory": _memory,
                 "wsl": _wsl, "linux.feature": _linux_feature, "init": _init, "library": _library, "disk": _disk,
                 "desktop": _desktop, "tool": _tool, "rights": _rights_row}[attribute]
    return judge_one(value, facts)


def judge(rows, facts, *, own: str = "", plugins=None, internet: str = "system", offline=None,
          declared: bool = True) -> dict:
    """The rows judged against the facts (liminal_libs.facts' shape): pure, and never raises.

    `own`: the plugin's not_for_here() words, one more required row of the machine (attribute ""); `plugins`: the app's
    states by name (active or attached meet a plugin row; "cannot" is one not for this machine); `internet`: the
    switch's rule, "system" (as this system judges it) or "there" (every internet row met); `offline`: the name of the
    app's setting that makes it send nothing (LIMINAL_OFFLINE, LIMINAL_READONLY), which wins over the switch;
    `declared`: whether the plugin says what it needs (says()).

    The answer: {v, vocabulary, declared, met, sort, why, read, held, rows: [{attribute, value, strength, words, state,
    sort, said, how}]}. `met`: False when a required row is unmet, None when none is and one is unknown (or nothing is
    said), else True. `sort`: "machine" when an unmet required row is of the machine, else "moment", else "".
    """
    try:
        return _judge(rows, facts if isinstance(facts, dict) else {}, own, plugins, internet, offline, declared)
    except Exception as e:  # noqa: BLE001 - a judgement never raises: what it could not judge is unknown
        return {"v": 1, "vocabulary": VOCABULARY, "declared": bool(declared), "met": None, "sort": "",
                "why": f"{NOT_KNOWN}: the needs could not be judged ({type(e).__name__})", "read": "", "held": False,
                "rows": []}


def _judge(rows, facts, own, plugins, internet, offline, declared) -> dict:
    out_rows = []
    own = str(own or "").strip()
    if own:
        out_rows.append({"attribute": "", "value": "", "strength": "required", "words": own, "state": "unmet",
                         "sort": "machine", "said": own, "how": ""})
    for row in rows or ():
        if not isinstance(row, dict):
            continue
        r = {"attribute": str(row.get("attribute", "")), "value": str(row.get("value", "")),
             "strength": str(row.get("strength", "required")), "words": str(row.get("words", ""))}
        try:
            state, sort, said, how = _row(r, facts, plugins, internet, offline)
        except Exception as e:  # noqa: BLE001 - one row that cannot be judged is unknown, the rest are judged
            state, sort, said, how = "unknown", "", f"{NOT_KNOWN}: it could not be judged ({type(e).__name__})", ""
        out_rows.append({**r, "state": state, "sort": sort if state == "unmet" else "", "said": said, "how": how})
    required = [r for r in out_rows if r["strength"] == "required"]
    unmet = [r for r in required if r["state"] == "unmet"]
    if not declared and not own:
        met, why = None, NOT_SAID
    elif unmet:
        met = False
        why = "; ".join(f"{r['said']}" + (f": {r['words']}" if r["words"] and r["words"] != r["said"] else "")
                        for r in unmet)
    elif any(r["state"] == "unknown" for r in required):
        met, why = None, ""
    else:
        met, why = True, "" if out_rows else NOTHING
    sort = ("machine" if any(r["sort"] == "machine" for r in unmet) else "moment") if unmet else ""
    answer = {"v": 1, "vocabulary": VOCABULARY, "declared": bool(declared), "met": met, "sort": sort, "why": why,
              "read": str(facts.get("read") or ""), "held": False, "rows": out_rows}
    answer["held"] = held_for(answer)
    return answer


def held_for(answer) -> bool:
    """Whether every unmet required row is an internet row (decision 19: such a plugin, attached, is held and not let
    go)."""
    rows = [r for r in (answer or {}).get("rows", ()) if isinstance(r, dict)
            and r.get("strength") == "required" and r.get("state") == "unmet"]
    return bool(rows) and all(_split(str(r.get("attribute", "")))[1] == "internet" for r in rows)


def state_of(enabled: bool, answer, valid) -> str:
    """A plugin's state, the one rule the platform calls (and item 30's core later): "disabled" while its switch is off,
    "unmet" while a required need is not met, "invalid" while its own status says it is not valid, else "active"."""
    if not enabled:
        return "disabled"
    if isinstance(answer, dict) and answer.get("met") is False:
        return "unmet"
    if valid is False:
        return "invalid"
    return "active"
