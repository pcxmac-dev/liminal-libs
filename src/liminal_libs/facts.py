"""This machine's facts, read without sending anything, for the judgement of what its plugins need (liminal-libs
1.103.0; Monday list item 19, part two: the needs plan's revision 2, 3.4).

Why the app reads the system itself: the judgement decides which plugins are attached and asked, so it comes before
any plugin can answer. This is the one place the app's object code reads the operating system for it, and it only
reads: no socket, no request, no host named. The internet is the system's own judgement as it stands (Windows' Network
List Manager, NetworkManager's last verdict through nmcli), never asked to probe.

- Windows, in process: sys.getwindowsversion(), the CurrentVersion registry key (winreg), kernel32's IsWow64Process2,
  IsProcessorFeaturePresent, GetPhysicallyInstalledSystemMemory and GlobalMemoryStatusEx, CPython's own `_wmi` for
  Win32_ComputerSystem, Win32_Processor, Win32_OperatingSystem and Win32_OptionalFeature (the features declared, the one
  slow read: begin_features), the Network List Manager's GetConnectivity (one COM call in a thread of its own, joined
  at COM_S), the proxies and the hosts file against NCSI's probe hosts, a desktop to ask on (interactive, copied from
  machines/windows.py and held to it by a test), the data folder's free space and the tools named.
- Linux, WSL included: the files of linuxsys.kernel.FILES handed to linuxsys.kernel.read, which owns the kernel's
  release and machine, WSL and the container (the linuxperm plan's 3.11: one reading for both readers); then needs'
  own files (/proc/cpuinfo, /proc/meminfo, /dev/kvm, the routes, the netfilter and BPF marks, PID 1's name and /run's
  markers); NetworkManager's connectivity through nmcli where /run/NetworkManager is there and never inside WSL
  (decision 4), started through lifecycle.spawn so it is in the process ledger, waited NMCLI_S at most.

Bounds: one reader a process (`reader()`, `use(r)` puts a test's in place); what cannot change while the app runs is
read once and again only when asked fresh, the internet kept INTERNET_S, the disk, the tools and /dev/kvm SLOW_S; one
read in flight for each slow read, a second asked meanwhile given what is kept or unknown; at most MAX_VALUES names
kept; daemon threads only, so a stop never waits on one. A read that fails is unknown, with its words, logged once.

Refused under tests (M25): while PYTEST_CURRENT_TEST is set nothing of the system is read (the registry, `_wmi`,
kernel32, COM, the files, nmcli) unless LIMINAL_REAL_FACTS is "1", so a test that missed its seam reads nothing of this
PC; each such fact is unknown, "not read: a test is running". `sys`, `os.uname` and the environment are read as always.

Plain: the standard library, ctypes, `layout`, `needs` and `linuxsys.kernel` (whose package is plain too, a few
modules loaded with it); `lifecycle` only inside the nmcli reader. `READS` says what is read, how and how long it is
kept, for the Internal and External API cards.
"""
from __future__ import annotations

import ctypes
import logging
import os
import shutil
import sys
import threading
import time

from . import needs
from .linuxsys import kernel

log = logging.getLogger(__name__)

INTERNET_S, SLOW_S = 15.0, 60.0
COM_S, NMCLI_S, FEATURES_WAIT_S = 2.0, 5.0, 2.0
MAX_VALUES = 80
READINGS = 4  # the internet's last readings kept, with their times (M9)
REAL = "LIMINAL_REAL_FACTS"
NOT_READ = "not read: a test is running"
CURRENT_VERSION = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
NCSI = r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
NCSI_HOSTS = ("ActiveWebProbeHost", "ActiveWebProbeHostV6", "ActiveDnsProbeHost", "ActiveDnsProbeHostV6")
PROXY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
PROXY_VARIABLES = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
NLM_CLSID, NLM_IID = "DCB00C01-570F-4A9B-8D69-199FDBA5723B", "DCB00000-570F-4A9B-8D69-199FDBA5723B"
NLM_IPV4_INTERNET, NLM_IPV6_INTERNET = 0x40, 0x400
MACHINES = {0x8664: "x86-64", 0xAA64: "arm64", 0x14C: "x86", 0x1C4: "arm"}
PF = {"nx": 12, "sse4.2": 38, "avx": 39, "avx2": 40, "avx512f": 41}
VM_WORDS = ("virtual machine", "vmware", "virtualbox", "qemu", "kvm", "xen", "parallels", "bochs", "hvm domu")
LINUX_FILES = (*kernel.FILES, "/proc/cpuinfo", "/proc/meminfo", "/sys/module/kvm_intel/parameters/nested",
               "/sys/module/kvm_amd/parameters/nested", "/proc/net/netfilter", "/sys/module/nf_tables",
               "/sys/module/ip_tables", "/proc/sys/kernel/unprivileged_bpf_disabled", "/sys/fs/bpf", "/proc/1/comm",
               "/run/systemd/system", "/run/openrc", "/run/runit", "/run/s6", "/run/dinit", "/run/NetworkManager")
LINUX_KVM = ("/dev/kvm",)
LINUX_ROUTES = ("/proc/net/route", "/proc/net/ipv6_route")
NMCLI = ("nmcli", "-t", "-f", "CONNECTIVITY", "general")  # NetworkManager's last verdict: it starts no check

READS = (
    ("kernel, build, edition", "sys.getwindowsversion(); the registry's CurrentVersion key (winreg)", "once a process"),
    ("architecture", "kernel32 IsWow64Process2's native machine (Windows); os.uname() (Linux)", "once a process"),
    ("processor features", "kernel32 IsProcessorFeaturePresent 12, 38-41 (Windows); /proc/cpuinfo (Linux)",
     "once a process"),
    ("virtualization", "_wmi Win32_ComputerSystem, Win32_Processor (Windows); /proc/cpuinfo, the kvm modules (Linux)",
     "once a process"),
    ("Data Execution Prevention, the product", "_wmi Win32_OperatingSystem", "once a process"),
    ("Windows features", "_wmi Win32_OptionalFeature, the names declared, one query", "once a process"),
    ("memory", "kernel32 GetPhysicallyInstalledSystemMemory, GlobalMemoryStatusEx (Windows); /proc/meminfo (Linux)",
     "once a process"),
    ("the internet", "the Network List Manager's GetConnectivity (COM), the proxies, the hosts file against NCSI's "
     "probe hosts (Windows); nmcli -t -f CONNECTIVITY general, the routes (Linux); never inside WSL",
     f"{INTERNET_S:.0f} s, two readings before a no"),
    ("the kernel, WSL, the container (Linux)", "linuxsys.kernel.read of its files", "once a process"),
    ("Linux features, init", "/proc/net/netfilter, the nf_tables and ip_tables modules, /sys/fs/bpf, /proc/1/comm, "
     "/run's markers", "once a process"),
    ("/dev/kvm", "whether it is there", f"{SLOW_S:.0f} s"),
    ("a desktop to ask on", "user32's window station flags (Windows); DISPLAY, WAYLAND_DISPLAY (Linux)",
     "once a process"),
    ("disk", "shutil.disk_usage of the data folder", f"{SLOW_S:.0f} s"),
    ("tools", "shutil.which; Npcap's wpcap.dll, libpcap's library", f"{SLOW_S:.0f} s"),
    ("rights", "shell32 IsUserAnAdmin (Windows); the effective user and its groups (Linux)", "once a process"),
)
# the facts' groups each attribute needs read, and how long each group is kept (None: until read fresh)
GROUPS = {"kernel": ("os",), "windows.build": ("os",), "windows.feature": ("os", "features"),
          "architecture": ("os",), "cpu": ("os", "cpu"), "virtualization": ("os", "cpu", "virtualization", "kvm"),
          "memory": ("os", "virtualization", "memory"), "wsl": ("os",), "linux.feature": ("os", "linux"),
          "init": ("os", "linux"), "internet": ("os", "internet"), "library": (), "disk": ("disk",),
          "desktop": ("desktop",), "tool": ("tools",), "plugin": (), "rights": ("rights",)}
KEPT = {"internet": INTERNET_S, "disk": SLOW_S, "tools": SLOW_S, "kvm": SLOW_S}


class Refused(Exception):
    """A real read refused while a test runs."""


def refused() -> bool:
    """Whether real reads are refused: a test is running and LIMINAL_REAL_FACTS is not "1" (M25)."""
    return bool(os.environ.get("PYTEST_CURRENT_TEST")) and os.environ.get(REAL) != "1"


def _guard() -> None:
    if refused():
        raise Refused(NOT_READ)


def system() -> str:
    return "windows" if sys.platform == "win32" else "linux" if sys.platform.startswith("linux") else sys.platform


def _library() -> str:
    from . import __version__

    return __version__


_logged: set = set()


def _note(what: str, e: BaseException) -> str:
    words = str(e) if isinstance(e, Refused) else f"{type(e).__name__}: {e}"
    if not isinstance(e, Refused) and what not in _logged:
        _logged.add(what)
        log.info("facts: %s could not be read (%s)", what, words)
    return words


# -- Windows' readers (each in its own function, each its words on a failure) ----------------------------------------
class _ObjectFlags(ctypes.Structure):  # USEROBJECTFLAGS
    _fields_ = [("fInherit", ctypes.c_int), ("fReserved", ctypes.c_int), ("dwFlags", ctypes.c_uint32)]


def interactive() -> bool:
    """Whether this process has a desktop Windows can ask on (its window station visible, WSF_VISIBLE: not a service's,
    nor that of a task run whether or not anyone is signed in); False off Windows; True where it cannot tell."""
    if os.name != "nt":
        return False
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.GetProcessWindowStation.restype = ctypes.c_void_p
        user32.GetUserObjectInformationW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
                                                     ctypes.POINTER(ctypes.c_uint32)]
        user32.GetUserObjectInformationW.restype = ctypes.c_int
        station = user32.GetProcessWindowStation()
        flags, needed = _ObjectFlags(), ctypes.c_uint32()
        if not station or not user32.GetUserObjectInformationW(station, 1, ctypes.byref(flags), ctypes.sizeof(flags),  # UOI_FLAGS
                                                               ctypes.byref(needed)):
            return True
        return bool(flags.dwFlags & 0x0001)  # WSF_VISIBLE
    except (AttributeError, OSError):
        return True


def wmi_rows(query: str) -> list[dict]:
    """A WQL query through CPython's own `_wmi` (root\\cimv2), its answer as rows of {property: text}; a property seen
    again starts the next row."""
    import _wmi  # CPython 3.12 and later on Windows; reached here only

    rows, row = [], {}
    for item in [x for x in _wmi.exec_query(query).split("\0") if x]:
        key, _, value = item.partition("=")
        if key in row:
            rows.append(row)
            row = {}
        row[key] = value
    return [*rows, row] if row else rows


def _flag(text):
    """_wmi's booleans are -1 (TRUE) and 0; True, False, or None when it says neither."""
    t = str(text if text is not None else "").strip().lower()
    return True if t in ("-1", "1", "true") else False if t in ("0", "false") else None


def _registry(root, key: str, names) -> dict:
    import winreg

    out = {}
    with winreg.OpenKey(root, key) as k:
        for name in names:
            try:
                out[name] = winreg.QueryValueEx(k, name)[0]
            except OSError:
                pass
    return out


def win_version() -> dict:
    _guard()
    import winreg

    v = sys.getwindowsversion()
    out = {"build": int(v.build), "productType": int(getattr(v, "product_type", 0) or 0)}
    reg = _registry(winreg.HKEY_LOCAL_MACHINE, CURRENT_VERSION,
                    ("EditionID", "DisplayVersion", "CurrentBuild", "UBR", "InstallationType"))
    out.update({"edition": str(reg.get("EditionID") or ""), "display": str(reg.get("DisplayVersion") or ""),
                "ubr": int(reg["UBR"]) if isinstance(reg.get("UBR"), int) else None,
                "installation": str(reg.get("InstallationType") or "")})
    if str(reg.get("CurrentBuild") or "").isdigit():
        out["build"] = int(reg["CurrentBuild"])
    return out


def win_native() -> int:
    _guard()
    from ctypes import wintypes as w

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.restype = w.HANDLE
    k32.IsWow64Process2.argtypes = [w.HANDLE, ctypes.POINTER(w.USHORT), ctypes.POINTER(w.USHORT)]
    process, native = w.USHORT(), w.USHORT()
    if not k32.IsWow64Process2(k32.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(native)):
        raise OSError(ctypes.get_last_error(), "IsWow64Process2 failed")
    return int(native.value)


def _win_os_group() -> dict:
    """The version, the native machine and Win32_OperatingSystem, each in its own try."""
    out, why = {}, {}
    for key, read in (("version", win_version), ("native", win_native), ("os", win_os)):
        try:
            out[key] = read()
        except Exception as e:  # noqa: BLE001 - each part unknown on its own
            why[key] = _note(f"windows {key}", e)
    if len(why) == 3:
        raise Refused(next(iter(why.values()))) if all(w == NOT_READ for w in why.values()) else OSError(
            "; ".join(why.values()))
    return {**out, "why": why}


def win_pf() -> dict:
    _guard()
    k32 = ctypes.WinDLL("kernel32")
    return {name: bool(k32.IsProcessorFeaturePresent(code)) for name, code in PF.items()}


def win_os() -> dict:
    _guard()
    row = (wmi_rows("SELECT Caption, ProductType, DataExecutionPrevention_Available FROM Win32_OperatingSystem")
           or [{}])[0]
    return {"caption": row.get("Caption", ""), "productType": int(row["ProductType"]) if str(
        row.get("ProductType", "")).isdigit() else None, "dep": _flag(row.get("DataExecutionPrevention_Available"))}


def win_virtualization() -> dict:
    _guard()
    cs = (wmi_rows("SELECT HypervisorPresent, Model, Manufacturer FROM Win32_ComputerSystem") or [{}])[0]
    cpu = (wmi_rows("SELECT VMMonitorModeExtensions, SecondLevelAddressTranslationExtensions, "
                    "VirtualizationFirmwareEnabled FROM Win32_Processor") or [{}])[0]
    return {"hypervisor": _flag(cs.get("HypervisorPresent")), "model": cs.get("Model", ""),
            "manufacturer": cs.get("Manufacturer", ""), "extensions": _flag(cpu.get("VMMonitorModeExtensions")),
            "slat": _flag(cpu.get("SecondLevelAddressTranslationExtensions")),
            "firmware": _flag(cpu.get("VirtualizationFirmwareEnabled"))}


def win_features(names) -> dict:
    """InstallState (1 on, 2 off, 3 absent) of each feature named, one query; a name not answered is absent."""
    _guard()
    names = [n for n in names if needs._NAME.match(n) and "'" not in n][:MAX_VALUES]
    if not names:
        return {}
    where = " OR ".join(f"Name='{n}'" for n in names)
    rows = wmi_rows(f"SELECT Name, InstallState FROM Win32_OptionalFeature WHERE {where}")
    found = {r.get("Name", ""): int(r["InstallState"]) for r in rows if str(r.get("InstallState", "")).isdigit()}
    return {n: found.get(n, 3) for n in names}


class _MemoryStatus(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_uint32), ("dwMemoryLoad", ctypes.c_uint32)] + [(n, ctypes.c_ulonglong) for n in (
        "ullTotalPhys", "ullAvailPhys", "ullTotalPageFile", "ullAvailPageFile", "ullTotalVirtual", "ullAvailVirtual",
        "ullAvailExtendedVirtual")]


def win_memory() -> dict:
    _guard()
    k32 = ctypes.WinDLL("kernel32")
    kb = ctypes.c_ulonglong()
    installed = kb.value * 1024 if k32.GetPhysicallyInstalledSystemMemory(ctypes.byref(kb)) else None
    st = _MemoryStatus()
    st.dwLength = ctypes.sizeof(st)
    usable = int(st.ullTotalPhys) if k32.GlobalMemoryStatusEx(ctypes.byref(st)) else None
    return {"installed": installed, "usable": usable}


def _guid(text: str):
    import uuid

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_ubyte * 8)]

    u, g = uuid.UUID(text), GUID()
    g.Data1, g.Data2, g.Data3 = u.fields[0], u.fields[1], u.fields[2]
    for i, b in enumerate(u.bytes[8:]):
        g.Data4[i] = b
    return g


def _nlm_call() -> int:
    """GetConnectivity's NLM_CONNECTIVITY flags, COM initialized (MTA) and uninitialized in this thread; the layout of
    netlistmgr.h, as the needs plan's probe proved it on this PC."""
    ole32 = ctypes.WinDLL("ole32")
    init = ole32.CoInitializeEx(None, 0) & 0xFFFFFFFF
    try:
        p = ctypes.c_void_p()
        hr = ole32.CoCreateInstance(ctypes.byref(_guid(NLM_CLSID)), None, 0x17, ctypes.byref(_guid(NLM_IID)),
                                    ctypes.byref(p))
        if hr != 0 or not p:
            raise OSError(f"CoCreateInstance of the Network List Manager: 0x{hr & 0xFFFFFFFF:08x}")
        vtbl = ctypes.cast(p, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        try:
            level = ctypes.c_int()
            get = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))(vtbl[13])
            hr = get(p, ctypes.byref(level))
            if hr != 0:
                raise OSError(f"GetConnectivity: 0x{hr & 0xFFFFFFFF:08x}")
            return int(level.value)
        finally:
            ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtbl[2])(p)  # Release
    finally:
        if init in (0, 1):
            ole32.CoUninitialize()


def win_nlm() -> int:
    """_nlm_call in a daemon thread of its own, joined at COM_S."""
    _guard()
    box: dict = {}

    def run():
        try:
            box["level"] = _nlm_call()
        except BaseException as e:  # noqa: BLE001 - said by the caller
            box["error"] = e

    t = threading.Thread(target=run, name="liminal-facts-nlm", daemon=True)
    t.start()
    t.join(COM_S)
    if t.is_alive():
        raise TimeoutError(f"the Network List Manager did not answer in {COM_S:.0f} s")
    if "error" in box:
        raise box["error"]
    return box["level"]


def proxy_words(env=None) -> str:
    """The proxy set in the environment (any case), in words; "" when none."""
    env = os.environ if env is None else env
    for name in PROXY_VARIABLES:
        for key in (name, name.lower()):
            if str(env.get(key) or "").strip():
                return f"{key} is set"
    return ""


def win_internet() -> dict:
    """The raw readings the internet is judged from: NLM's flags, whether NCSI probes, a proxy, a sunk probe host."""
    _guard()
    import winreg

    out = {"nlm": None, "probing": None, "proxy": proxy_words(), "sunk": "", "why": ""}
    try:
        settings = _registry(winreg.HKEY_CURRENT_USER, PROXY_KEY, ("ProxyEnable", "AutoConfigURL"))
        if settings.get("ProxyEnable") == 1:
            out["proxy"] = out["proxy"] or "a proxy is set in Windows' Internet Settings"
        elif str(settings.get("AutoConfigURL") or "").strip():
            out["proxy"] = out["proxy"] or "a proxy script is set in Windows' Internet Settings"
    except OSError:
        pass
    try:
        ncsi = _registry(winreg.HKEY_LOCAL_MACHINE, NCSI, ("EnableActiveProbing", *NCSI_HOSTS))
    except OSError:
        ncsi = {}
    if "EnableActiveProbing" in ncsi:
        out["probing"] = ncsi["EnableActiveProbing"] != 0
    hosts = {str(ncsi[h]).strip().lower() for h in NCSI_HOSTS if str(ncsi.get(h) or "").strip()}
    out["sunk"] = sunk_host(_hosts_text(), hosts) if hosts else ""
    if not hosts:
        out["why"] = "NCSI's probe hosts are not in the registry: the hosts file is not checked"
    out["nlm"] = win_nlm()
    return out


def _hosts_text() -> str:
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(1 << 20)
    except OSError:
        return ""


def sunk_host(text: str, hosts) -> str:
    """The first of `hosts` the hosts file `text` sends nowhere (0.0.0.0, 127.0.0.0/8, ::, ::1), or ""."""
    for line in str(text or "").splitlines():
        words = line.split("#", 1)[0].split()
        if len(words) < 2:
            continue
        address = words[0].lower()
        if address in ("0.0.0.0", "::", "::1") or address.startswith("127."):
            for name in words[1:]:
                if name.lower().rstrip(".") in hosts:
                    return name.lower()
    return ""


# -- the readers both systems have -------------------------------------------------------------------------------------
def disk() -> dict:
    _guard()
    from . import layout

    path = layout.data_dir()
    probe = path
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    return {"free": int(shutil.disk_usage(probe).free), "path": str(probe)}


def tools(names) -> dict:
    _guard()
    out = {}
    for name in list(names)[:MAX_VALUES]:
        if name == "npcap" and os.name == "nt":
            out[name] = os.path.isfile(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap",
                                                    "wpcap.dll"))
        elif name == "libpcap" and os.name != "nt":
            import glob

            out[name] = any(glob.glob(f"{d}/libpcap.so*") for d in ("/usr/lib", "/usr/lib64", "/lib", "/lib64",
                                                                    "/usr/lib/x86_64-linux-gnu",
                                                                    "/usr/lib/aarch64-linux-gnu"))
        else:
            out[name] = shutil.which(name) is not None
    return out


def rights() -> dict:
    _guard()
    if os.name == "nt":
        try:
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            admin = None
        return {"administrator": admin, "root": False, "groups": []}
    import grp

    names = []
    for gid in os.getgroups()[:MAX_VALUES]:
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return {"administrator": False, "root": os.geteuid() == 0, "groups": names}


def desktop() -> bool:
    if os.name == "nt":
        _guard()
        return interactive()
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


# -- Linux's readers ---------------------------------------------------------------------------------------------------
def open_files(paths) -> dict:
    """Each path's text ("" for a folder, a device, or a file there that cannot be read), None where it is not."""
    _guard()
    out = {}
    for path in paths:
        try:
            if os.path.isdir(path) or (os.path.exists(path) and not os.path.isfile(path)):
                out[path] = ""
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                out[path] = f.read(1 << 18)
        except FileNotFoundError:
            out[path] = None
        except OSError:
            out[path] = "" if os.path.exists(path) else None
    return out


def nmcli() -> str | None:
    """NetworkManager's last verdict (full, limited, portal, none, unknown), through lifecycle.spawn, NMCLI_S at most;
    None where it is not there or does not answer. Its row is let go once it has ended (M26)."""
    _guard()
    import subprocess

    from . import lifecycle

    if shutil.which(NMCLI[0]) is None:
        return None
    child = lifecycle.spawn(list(NMCLI), owner="facts", kind="read", stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True)
    late = False
    try:
        out, _ = child.communicate(timeout=NMCLI_S)
    except subprocess.TimeoutExpired:
        late, out = True, None
    finally:
        lifecycle.end_owned("facts", lifecycle.Signal.KILL if late else lifecycle.Signal.TERM,
                            lifecycle.deadline_in(0))
    word = (out or "").strip().splitlines()
    return word[0].strip().lower() if word and not late else None


# -- the parsers (pure: what the readers gathered -> the facts' shape) ------------------------------------------------
def _vm(model: str, manufacturer: str) -> str:
    words = f"{model} {manufacturer}".strip()
    return words if any(w in words.lower() for w in VM_WORDS) else ""


def _internet_windows(raw: dict) -> dict:
    net = raw.get("internet") if isinstance(raw.get("internet"), dict) else None
    by = "Windows' own judgement (NCSI)"
    if net is None:
        return {"state": "unknown", "ipv4": None, "ipv6": None, "by": by, "why": raw.get("why", {}).get("internet")
                or "not read"}
    if net.get("proxy"):
        return {"state": "unknown", "ipv4": None, "ipv6": None, "by": by,
                "why": f"{net['proxy']}: Windows' own judgement cannot be taken for the way out"}
    if net.get("sunk"):
        return {"state": "unknown", "ipv4": None, "ipv6": None, "by": by,
                "why": f"the hosts file sends NCSI's probe host {net['sunk']} nowhere"}
    level = net.get("nlm")
    if not isinstance(level, int):
        return {"state": "unknown", "ipv4": None, "ipv6": None, "by": by, "why": "the Network List Manager did not say"}
    v4, v6 = bool(level & NLM_IPV4_INTERNET), bool(level & NLM_IPV6_INTERNET)
    if not (v4 or v6) and net.get("probing") is False:
        return {"state": "unknown", "ipv4": None, "ipv6": None, "by": by,
                "why": "NCSI's active probing is off: it judges only by what it overhears"}
    return {"state": "yes" if v4 or v6 else "no", "ipv4": v4, "ipv6": v6, "by": by, "why": net.get("why", "")}


def parse_windows(raw: dict) -> dict:
    """What the Windows readers gathered (raw: {version, native, pf, os, virtualization, features, featuresRead,
    memory, internet, desktop, disk, tools, rights, library, why}) in the facts' shape."""
    raw = raw if isinstance(raw, dict) else {}
    why = dict(raw.get("why") or {})
    ver = raw.get("version") if isinstance(raw.get("version"), dict) else {}
    osw = raw.get("os") if isinstance(raw.get("os"), dict) else {}
    virt = raw.get("virtualization") if isinstance(raw.get("virtualization"), dict) else {}
    pf = raw.get("pf") if isinstance(raw.get("pf"), dict) else {}
    product_type = osw.get("productType") or ver.get("productType")
    server = None if not product_type else product_type != 1
    product = str(osw.get("caption") or "").replace("Microsoft ", "", 1).strip()
    build, ubr = ver.get("build"), ver.get("ubr")
    words = " ".join(x for x in (product or "Windows", ver.get("display", ""),
                                 f"build {build}" + (f".{ubr}" if ubr else "") if build else "") if x)
    vm = _vm(str(virt.get("model") or ""), str(virt.get("manufacturer") or ""))
    native = raw.get("native")
    memory = raw.get("memory") if isinstance(raw.get("memory"), dict) else {}
    cpu = {k: pf.get(k) for k in needs.CPU_FLAGS}
    cpu["nxHardware"] = osw.get("dep")
    if not pf:
        why.setdefault("cpu", why.get("pf", "not read"))
    return {
        "system": "windows", "kernel": {"name": "windows", "release": str(build or ""), "words": words},
        "windows": {"build": build, "ubr": ubr, "edition": ver.get("edition", ""), "product": product,
                    "display": ver.get("display", ""), "server": server,
                    "features": dict(raw.get("features") or {}), "featuresRead": bool(raw.get("featuresRead"))},
        "architecture": MACHINES.get(native, "") if isinstance(native, int) else "",
        "cpu": cpu,
        "virtualization": {"extensions": virt.get("extensions"), "slat": virt.get("slat"),
                           "firmware": virt.get("firmware"), "hypervisor": virt.get("hypervisor"),
                           "vm": vm if virt else None, "nested": None, "kvm": None},
        "memory": {"installed": memory.get("installed"), "usable": memory.get("usable"), "share": ""},
        "internet": {**_internet_windows(raw), "readings": list(raw.get("readings") or ())},
        "wsl": "none", "container": "", "linux": {}, "init": "",
        "library": raw.get("library", ""), "desktop": raw.get("desktop"),
        "disk": raw.get("disk") if isinstance(raw.get("disk"), dict) else {"free": None, "path": ""},
        "tools": dict(raw.get("tools") or {}), "rights": raw.get("rights"),
        "read": raw.get("read", ""), "why": why,
    }


def _flags(cpuinfo: str | None) -> tuple[set, set]:
    flags, vmx = set(), set()
    for line in (cpuinfo or "").splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key in ("flags", "features") and not flags:
            flags = set(value.split())
        elif key == "vmx flags" and not vmx:
            vmx = set(value.split())
    return flags, vmx


def _meminfo(text: str | None) -> int | None:
    for line in (text or "").splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024
    return None


def _default_routes(files: dict) -> tuple[bool | None, bool | None]:
    v4 = v6 = None
    route = files.get("/proc/net/route")
    if route is not None:
        v4 = any(len(f) > 2 and f[1] == "00000000" for f in (line.split() for line in route.splitlines()[1:]))
    route6 = files.get("/proc/net/ipv6_route")
    if route6 is not None:
        v6 = any(len(f) > 1 and f[0] == "0" * 32 and f[1] == "00" for f in (line.split() for line in
                                                                           route6.splitlines()))
    return v4, v6


def _init(files: dict, wsl: str) -> str:
    comm = (files.get("/proc/1/comm") or "").strip().lower()
    there = lambda p: files.get(p) is not None  # noqa: E731
    names = {"systemd": "systemd", "openrc-init": "openrc", "runit": "runit", "runsvdir": "runit",
             "s6-svscan": "s6", "dinit": "dinit", "busybox": "busybox"}
    if comm in names:
        return names[comm]
    if there("/run/systemd/system"):
        return "systemd"
    if there("/run/openrc"):
        return "openrc"
    if there("/run/runit"):
        return "runit"
    if there("/run/s6"):
        return "s6"
    if there("/run/dinit"):
        return "dinit"
    if comm == "init" and wsl:
        return "wsl"
    return ""


def parse_linux(files: dict, env: dict, machine: str, *, nmcli: str | None = None, proxies=None) -> dict:
    """A Linux's files' texts (LINUX_FILES, LINUX_KVM, LINUX_ROUTES: None where one is not there) and environment in
    the facts' shape. The kernel, WSL and the container are linuxsys.kernel.read's; `nmcli` is NetworkManager's word
    where it was asked; `proxies` the proxy words, read from `env` when None."""
    files = files if isinstance(files, dict) else {}
    env = env if isinstance(env, dict) else {}
    why: dict = {}
    k = kernel.read(files, env, machine)
    wsl = "none" if not k.wsl else str(k.wsl_generation or 2)
    flags, vmx = _flags(files.get("/proc/cpuinfo"))
    have = files.get("/proc/cpuinfo") is not None
    if not have:
        why["cpu"] = "/proc/cpuinfo could not be read"
    cpu = {f: ((f.replace(".", "_") in flags) if have else None) for f in needs.CPU_FLAGS}
    extensions = (("vmx" in flags) or ("svm" in flags)) if have else None
    slat = (("ept" in vmx) or ("ept" in flags) or ("npt" in flags)) if have else None
    guest = "hypervisor" in flags
    nested_word = (files.get("/sys/module/kvm_intel/parameters/nested") or
                   files.get("/sys/module/kvm_amd/parameters/nested") or "").strip().upper()
    kvm_there = files.get("/dev/kvm") is not None if "/dev/kvm" in files else None
    if kvm_there is None:
        why["kvm"] = "/dev/kvm was not looked at"
    if wsl == "1":
        linux = {"netfilter": False, "ebpf": False}
    else:
        nf = any(files.get(p) is not None for p in ("/proc/net/netfilter", "/sys/module/nf_tables",
                                                    "/sys/module/ip_tables"))
        bpf = any(files.get(p) is not None for p in ("/proc/sys/kernel/unprivileged_bpf_disabled", "/sys/fs/bpf"))
        linux = {"netfilter": True if nf else None, "ebpf": True if bpf else None}
        if not (nf and bpf):
            why["linux"] = "not found, which a module not loaded yet would also give"
    init = _init(files, k.wsl)
    if not init:
        why["init"] = "PID 1's name and /run's markers did not tell"
    memory = _meminfo(files.get("/proc/meminfo"))
    if memory is None:
        why["memory"] = "/proc/meminfo could not be read"
    proxy = proxy_words(env) if proxies is None else (proxies or "")
    v4, v6 = _default_routes(files)
    by = "NetworkManager's own judgement" if nmcli else "the routes"
    if k.wsl:
        internet = {"state": "unknown", "why": "inside WSL nothing here judges the internet: Windows does (decision 4)"}
        by = "nothing inside WSL"
    elif proxy:
        internet = {"state": "unknown", "why": f"{proxy}: the way out is the proxy's"}
    elif nmcli == "full":
        internet = {"state": "yes", "why": ""}
    elif nmcli in ("none", "portal", "limited"):
        internet = {"state": "no", "why": f"NetworkManager says {nmcli}"}
    elif v4 is False and v6 is False:
        internet = {"state": "no", "why": "no default route: there is no way out"}
        by = "the routes"
    elif v4 is None and v6 is None:
        internet = {"state": "unknown", "why": "the routes could not be read"}
    else:
        internet = {"state": "unknown", "why": "a way out, but nothing here judges the internet"}
    full = internet["state"] == "yes"
    internet.update({"ipv4": True if full and v4 else None, "ipv6": True if full and v6 else None, "by": by})
    vm = ("WSL 2's virtual machine" if k.wsl and wsl == "2" else "a virtual machine") if guest else ""
    return {
        "system": "linux",
        "kernel": {"name": "linux", "release": k.release, "words": f"Linux {k.release}".strip()},
        "windows": {},
        "architecture": needs.normal_architecture(k.machine),
        "cpu": cpu,
        "virtualization": {"extensions": extensions, "slat": slat, "firmware": None, "hypervisor": None,
                           "vm": vm, "nested": (nested_word in ("Y", "1")) if nested_word else None,
                           "kvm": kvm_there},
        "memory": {"installed": None, "usable": memory, "share": "WSL's, a .wslconfig setting" if k.wsl else ""},
        "internet": {**internet, "readings": []},
        "wsl": wsl, "wslName": k.wsl, "container": k.container, "linux": linux, "init": init,
        "library": "", "desktop": bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")),
        "disk": {"free": None, "path": ""}, "tools": {}, "rights": None, "read": "",
        "why": {**why, **({"kernel": "; ".join(k.notes)} if k.notes else {})},
    }


# -- the reader --------------------------------------------------------------------------------------------------------
def wanted(rows) -> tuple[set, dict]:
    """The attributes and the names (Windows features, tools) needs' rows want read."""
    attributes, names = set(), {"windows.feature": [], "tool": []}
    for r in rows or ():
        if not isinstance(r, dict):
            continue
        a = needs._split(str(r.get("attribute", "")))[1]
        attributes.add(a)
        if a in names:
            for n in needs._choices(r.get("value", "")):
                if n and n not in names[a]:
                    names[a].append(n)
    return attributes, names


def _iso(at: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at))


def keep_readings(readings: list) -> list:
    """The internet's readings kept, READINGS at most (M9): the last ones, but where the current run of one state
    began before them its first reading (and the one before it) are kept in place of the oldest, so quick reads ("Read
    again") never push a confirmed "no" out of the window: it stays until a reading that is not "no" arrives."""
    if len(readings) <= READINGS:
        return readings
    i = len(readings) - 1
    while i > 0 and readings[i - 1][1] == readings[-1][1]:
        i -= 1
    if i >= len(readings) - READINGS:
        return readings[-READINGS:]
    head = readings[max(i - 1, 0):i + 1]  # the reading before the run, if any, and the run's first
    return [*head, *readings[-(READINGS - len(head)):]]


class Reader:
    """This machine's facts, read when first wanted and kept (the module's words say how long)."""

    def __init__(self, clock=None, wall=None):
        self.clock = clock or time.monotonic
        self.wall = wall or time.time
        self._lock = threading.Lock()
        self._kept: dict = {}  # group -> (at, raw piece)
        self._why: dict = {}
        self._features: dict = {}
        self._features_wanted: list = []
        self._features_thread: threading.Thread | None = None
        self._features_done = threading.Event()
        self._features_done.set()  # nothing in flight
        self._features_tried: set = set()
        self._inflight: set = set()
        self._readings: list = []
        self._tools_wanted: list = []
        self._at = 0.0

    # the seams: one real read each (refused under tests)
    def _read(self, group: str):
        if system() == "windows":
            return {"os": _win_os_group,
                    "cpu": win_pf, "virtualization": win_virtualization, "memory": win_memory,
                    "internet": win_internet, "desktop": desktop, "disk": disk, "rights": rights,
                    "tools": lambda: tools(self._tools_wanted), "kvm": lambda: None,
                    "linux": lambda: None}[group]()
        return {"os": lambda: open_files(LINUX_FILES), "kvm": lambda: open_files(LINUX_KVM),
                "internet": self._linux_internet, "desktop": desktop, "disk": disk, "rights": rights,
                "tools": lambda: tools(self._tools_wanted), "cpu": lambda: None, "virtualization": lambda: None,
                "memory": lambda: None, "linux": lambda: None}[group]()

    def _linux_internet(self) -> dict:
        routes = open_files(LINUX_ROUTES)
        files = self._kept.get("os", (0, {}))[1] or {}
        in_wsl = kernel.read(files, dict(os.environ)).wsl
        word = None
        if not in_wsl and files.get("/run/NetworkManager") is not None:
            word = nmcli()
        return {"routes": routes, "nmcli": word}

    def _features_read(self, names) -> dict:
        return win_features(names)

    def _group(self, group: str, fresh: bool):
        with self._lock:
            kept = self._kept.get(group)
            ttl = KEPT.get(group)
            if kept is not None and not fresh and (ttl is None or self.clock() - kept[0] < ttl):
                return kept[1]
            if group in self._inflight:  # one read in flight: what is kept, or nothing (M7)
                return kept[1] if kept is not None else None
            self._inflight.add(group)
        try:
            piece = self._read(group)
            self._why.pop(group, None)
        except Exception as e:  # noqa: BLE001 - a fact that cannot be read is unknown, in words
            piece = None
            self._why[group] = _note(group, e)
        finally:
            with self._lock:
                self._inflight.discard(group)
        with self._lock:
            self._kept[group] = (self.clock(), piece)
            if group == "internet":
                self._reading(piece)
        return piece

    def _reading(self, piece) -> None:
        raw = {"internet": piece} if system() == "windows" else None
        if raw is not None:
            state = _internet_windows(raw)["state"] if piece is not None else "unknown"
        else:
            files = dict(self._kept.get("os", (0, {}))[1] or {})
            files.update((piece or {}).get("routes") or {})
            state = parse_linux(files, dict(os.environ), os.uname().machine if hasattr(os, "uname") else "",
                                nmcli=(piece or {}).get("nmcli"))["internet"]["state"]
        self._readings = keep_readings([*self._readings, [self.wall(), state]])

    def begin_features(self, names) -> None:
        """Windows' features named, read in a daemon thread (the slow read, about 0.7 s), one read in flight; a name
        asked while one is in flight is read by the next. A name whose read failed is not read again until fresh."""
        with self._lock:
            for n in names or ():
                if isinstance(n, str) and n not in self._features_wanted and len(self._features_wanted) < MAX_VALUES:
                    self._features_wanted.append(n)
            todo = [n for n in self._features_wanted if n not in self._features and n not in self._features_tried]
            if not todo or (self._features_thread is not None and self._features_thread.is_alive()):
                return
            self._features_tried.update(todo)
            self._features_done.clear()

            def run():
                try:
                    found = self._features_read(todo)
                    with self._lock:
                        self._features.update(found)
                        self._why.pop("features", None)
                except Exception as e:  # noqa: BLE001
                    self._why["features"] = _note("features", e)
                finally:
                    self._features_done.set()

            self._features_thread = threading.Thread(target=run, name="liminal-facts-features", daemon=True)
            self._features_thread.start()

    def features_ready(self, timeout: float = FEATURES_WAIT_S) -> bool:
        """Whether no read of the features is in flight, waiting `timeout` at most."""
        return self._features_done.wait(timeout)

    def _features_now(self, names, fresh: bool) -> tuple[dict, bool, str]:
        if fresh:
            with self._lock:
                self._features_tried.difference_update(names)
                for n in names:
                    self._features.pop(n, None)
        if names:
            self.begin_features(names)
        with self._lock:
            got = {n: self._features[n] for n in names if n in self._features}
        ready = bool(names) and len(got) == len(names)
        why = self._why.get("features") or ("" if ready else "the Windows features are being read: asked again shortly")
        return got, ready, why

    def read(self, attributes=None, fresh: bool = False, *, names=None) -> dict:
        """The facts' shape (the needs plan's 2.1, its revision's 3.4), what `attributes` need read (None: all);
        `names`: {"windows.feature": [...], "tool": [...]} the names declared; `fresh`: read again now."""
        names = names or {}
        if names.get("tool"):
            with self._lock:
                self._tools_wanted = list(dict.fromkeys([*self._tools_wanted, *names["tool"]]))[:MAX_VALUES]
        attrs = set(needs.ATTRIBUTES) if attributes is None else set(attributes)
        groups = {g for a in attrs for g in GROUPS.get(a, ())}
        if "tool" in attrs and names.get("tool"):
            fresh_tools = any(n not in ((self._kept.get("tools") or (0, {}))[1] or {}) for n in names["tool"])
        else:
            fresh_tools = False
        order = [g for g in ("os", "kvm", "cpu", "virtualization", "memory", "internet", "desktop", "disk", "tools",
                             "rights", "linux") if g in groups]  # the files first: the internet's reader looks at them
        pieces = {g: self._group(g, fresh or (g == "tools" and fresh_tools)) for g in order}
        self._at = self.wall()
        why = {**self._why}
        if system() == "windows":
            os_piece = pieces.get("os") or {}
            features, ready, fwhy = (self._features_now(names.get("windows.feature") or [], fresh)
                                     if "features" in groups else ({}, False, "not asked"))
            raw = {"version": os_piece.get("version"), "native": os_piece.get("native"), "os": os_piece.get("os"),
                   "pf": pieces.get("cpu"), "virtualization": pieces.get("virtualization"),
                   "memory": pieces.get("memory"), "internet": pieces.get("internet"),
                   "readings": list(self._readings), "features": features, "featuresRead": ready,
                   "desktop": pieces.get("desktop"), "disk": pieces.get("disk"), "tools": pieces.get("tools"),
                   "rights": pieces.get("rights"), "library": _library(), "read": _iso(self._at),
                   "why": {**{f: w for g, w in why.items() if g != "features" for f in _FACTS.get(g, (g,))},
                           **{_FACTS["os"][0] if k == "version" else k: w
                              for k, w in (os_piece.get("why") or {}).items()},
                           **({"features": fwhy} if fwhy else {})}}
            return parse_windows(raw)
        files = dict(pieces.get("os") or {})
        files.update(pieces.get("kvm") or {})
        net = pieces.get("internet") or {}
        files.update(net.get("routes") or {})
        machine = os.uname().machine if hasattr(os, "uname") else ""
        out = parse_linux(files, dict(os.environ), machine, nmcli=net.get("nmcli"))
        if "os" in why:
            out["why"].update({f: why["os"] for f in ("cpu", "linux", "init", "memory", "kernel", "kvm")})
        out["internet"]["readings"] = list(self._readings)
        if "internet" in why:
            out["internet"].update({"state": "unknown", "why": why["internet"]})
        out.update({"library": _library(), "read": _iso(self._at), "desktop": pieces.get("desktop")})
        if pieces.get("disk") is not None:
            out["disk"] = pieces["disk"]
        out["tools"] = pieces.get("tools") or {}
        out["rights"] = pieces.get("rights")
        for g in ("disk", "tools", "rights", "desktop", "kvm"):
            if g in why:
                out["why"][g] = why[g]
        return out

    def internet(self) -> dict:
        """The internet as last read, with its readings: {state, ipv4, ipv6, by, why, readings}."""
        return self.read({"internet"})["internet"]


# the facts a group's failure leaves unknown, by the names needs' words look up (needs._why)
_FACTS = {"os": ("windows", "kernel", "architecture"), "cpu": ("cpu",), "virtualization": ("virtualization",),
          "memory": ("memory",), "internet": ("internet",), "desktop": ("desktop",), "disk": ("disk",),
          "tools": ("tools",), "rights": ("rights",), "kvm": ("kvm",)}


class StandIn(Reader):
    """A recorded machine's facts (liminal_libs.needs_machines), answered as they are; it counts its reads and reads
    nothing of this machine. `readings`, when given, is the internet's readings a test hands in."""

    def __init__(self, facts: dict, clock=None):
        super().__init__(clock=clock)
        import copy

        self.facts = copy.deepcopy(facts)
        self.reads = 0
        self.features_begun: list = []

    def read(self, attributes=None, fresh: bool = False, *, names=None) -> dict:
        import copy

        self.reads += 1
        return copy.deepcopy(self.facts)

    def begin_features(self, names) -> None:
        self.features_begun.extend(names or ())

    def features_ready(self, timeout: float = FEATURES_WAIT_S) -> bool:
        return True


_reader: Reader | None = None
_reader_lock = threading.Lock()


def reader() -> Reader:
    """The one reader of this process."""
    global _reader
    with _reader_lock:
        if _reader is None:
            _reader = Reader()
        return _reader


def use(r: Reader | None) -> Reader | None:
    """Put `r` in place as this process's reader (a test's stand-in; None: a new real one when next asked); returns the
    one it replaced."""
    global _reader
    with _reader_lock:
        before, _reader = _reader, r
        return before
