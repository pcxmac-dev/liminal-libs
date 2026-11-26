"""Recorded machines for the needs judgement's tests: the library's and every plugin package's (liminal-libs 1.103.0;
the needs plan's revision 2, 3.12, S8). Plain data and one function per kind, nothing read of the machine it runs on.

Each machine is named once, with one line saying where it comes from, and its facts are made by facts.py's own
parsers, so a recorded machine and a real one are read the same way:
- WINDOWS: what the Windows readers would have gathered, handed to facts.parse_windows. this-pc is this PC as the needs
  plan's map read it on 2026-11-17 (map-facts 1-10); the others are made from Microsoft's documentation, never read on
  such a machine, and say so.
- LINUX: each of linuxsys's recorded machines by its own name (linuxsys/recorded/<name>: the one set both readers use,
  B4), with needs' own files beside it (what linuxsys never reads: /proc/cpuinfo, /proc/meminfo, /dev/kvm, the routes,
  the netfilter and BPF marks), then a few variants of them, each a linuxsys machine with some of those files
  changed. The kernel, WSL and container facts are linuxsys.kernel.read's of the machine's files, as on a real Linux.

    from liminal_libs import facts, needs_machines
    facts.use(needs_machines.reader("wsl-ubuntu-24.04"))   # a test's machine
    needs.judge(needs.declared(plugin), needs_machines.facts_of("windows-11-home"))

No host name is written here (a test holds that); a proxy and a sunk probe host are said in words.
"""
from __future__ import annotations

import copy

from . import facts

GIB = 2**30
LIBRARY = "1.103.0"
DOC = "made from the documentation (Microsoft Learn, read 2026-11-24), never read on such a machine"
FEATURES_PC = {"Microsoft-Hyper-V": 1, "Microsoft-Hyper-V-All": 1, "Microsoft-Hyper-V-Hypervisor": 1,
               "HypervisorPlatform": 1, "VirtualMachinePlatform": 1, "Microsoft-Windows-Subsystem-Linux": 1,
               "Containers": 2, "Containers-DisposableClientVM": 2}
PF_PC = {"nx": True, "sse4.2": True, "avx": True, "avx2": True, "avx512f": False}


def _windows(**over) -> dict:
    """This PC's readings (map-facts 2-10), with `over`'s parts in place of its own (each part a whole)."""
    raw = {
        "version": {"build": 26300, "ubr": 9974, "edition": "Professional", "display": "26H2",
                    "installation": "Client", "productType": 1},
        "native": 0x8664,
        "os": {"caption": "Microsoft Windows 11 Pro", "productType": 1, "dep": True},
        "pf": dict(PF_PC),
        "virtualization": {"hypervisor": True, "model": "", "manufacturer": "", "extensions": False, "slat": False,
                           "firmware": False},
        "features": dict(FEATURES_PC), "featuresRead": True,
        "memory": {"installed": 64 * GIB, "usable": 68137205760},
        "internet": {"nlm": 0x42, "probing": True, "proxy": "", "sunk": "", "why": ""},
        "readings": [[1763419200.0, "yes"], [1763419230.0, "yes"]],
        "desktop": True, "disk": {"free": 400 * GIB, "path": "C:\\"}, "tools": {},
        "rights": {"administrator": False, "root": False, "groups": []},
        "library": LIBRARY, "read": "2026-11-17T22:40:00Z", "why": {},
    }
    raw.update(copy.deepcopy(over))
    return raw


_NO_HYPERVISOR = {"hypervisor": False, "model": "", "manufacturer": "", "extensions": True, "slat": True,
                  "firmware": True}
WINDOWS: dict[str, tuple[str, dict]] = {
    "this-pc": ("this PC, read 2026-11-17 (the needs plan's map-facts 1-10): Windows 11 Pro 26H2 build 26300.9974, "
                "x86-64, Windows' hypervisor running (the processor's three flags read no), Hyper-V on, Containers and "
                "Windows Sandbox off, 64 GiB, NCSI: IPv4 internet; its free space a stand-in's", _windows()),
    "windows-hyperv-off": (f"Windows 11 Pro with no hypervisor running, Hyper-V off, its flags readable: {DOC}",
                           _windows(virtualization=dict(_NO_HYPERVISOR),
                                    features={**FEATURES_PC, "Microsoft-Hyper-V": 2, "Microsoft-Hyper-V-All": 2})),
    "windows-firmware-off": (f"Windows 11 Pro, virtualization off in the firmware, so no hypervisor: {DOC}",
                             _windows(virtualization={**_NO_HYPERVISOR, "firmware": False},
                                      features={**FEATURES_PC, "Microsoft-Hyper-V": 2})),
    "windows-11-home": (f"Windows 11 Home: Hyper-V and Containers absent from Windows Features: {DOC}",
                        _windows(version={"build": 26200, "ubr": 7000, "edition": "Core", "display": "25H2",
                                          "installation": "Client", "productType": 1},
                                 os={"caption": "Microsoft Windows 11 Home", "productType": 1, "dep": True},
                                 virtualization={**_NO_HYPERVISOR},
                                 features={"VirtualMachinePlatform": 1, "Microsoft-Windows-Subsystem-Linux": 1,
                                           "HypervisorPlatform": 2})),
    "windows-server-hyperv": (f"Windows Server 2025 Datacenter (ProductType 3), its Hyper-V a role, the client "
                              f"feature not listed: {DOC}",
                              _windows(version={"build": 26100, "ubr": 4000, "edition": "ServerDatacenter",
                                                "display": "24H2", "installation": "Server", "productType": 3},
                                       os={"caption": "Microsoft Windows Server 2025 Datacenter", "productType": 3,
                                           "dep": True},
                                       features={}, desktop=True)),
    "windows-vm-no-nesting": (f"Windows 11 Pro in a Hyper-V virtual machine without nested virtualization, 4 GiB: "
                              f"{DOC}",
                              _windows(virtualization={"hypervisor": False, "model": "Virtual Machine",
                                                       "manufacturer": "Microsoft Corporation", "extensions": False,
                                                       "slat": False, "firmware": False},
                                       memory={"installed": 4 * GIB, "usable": 4 * GIB - 2**28},
                                       features={**FEATURES_PC, "Microsoft-Hyper-V": 2})),
    "windows-vm-nested-hyperv-on": (f"Windows 11 Pro in a virtual machine with nested virtualization, Hyper-V on "
                                    f"inside it: {DOC}",
                                    _windows(virtualization={"hypervisor": True, "model": "Virtual Machine",
                                                             "manufacturer": "Microsoft Corporation",
                                                             "extensions": False, "slat": False, "firmware": False},
                                             memory={"installed": 8 * GIB, "usable": 8 * GIB - 2**28})),
    "windows-arm-hyperv-off": (f"Windows 11 Pro on Arm (arm64), no hypervisor, the processor's flags reading no "
                               f"(never seen read right): {DOC}",
                               _windows(native=0xAA64, pf={"nx": True, "sse4.2": False, "avx": False, "avx2": False,
                                                           "avx512f": False},
                                        virtualization={"hypervisor": False, "model": "", "manufacturer": "",
                                                        "extensions": False, "slat": False, "firmware": False},
                                        features={**FEATURES_PC, "Microsoft-Hyper-V": 2, "Microsoft-Hyper-V-All": 2},
                                        memory={"installed": 16 * GIB, "usable": 16 * GIB - 2**29})),
    "windows-proxy": (f"this PC's readings with a proxy set in the environment: {DOC}",
                      _windows(internet={"nlm": 0x42, "probing": True, "proxy": "HTTPS_PROXY is set", "sunk": "",
                                         "why": ""})),
    "windows-ncsi-sunk": (f"this PC's readings with the hosts file sending NCSI's web probe host nowhere: {DOC}",
                          _windows(internet={"nlm": 0x1, "probing": True, "proxy": "",
                                             "sunk": "NCSI's web probe host", "why": ""})),
    "windows-containers-on": (f"this PC's readings with Containers and Windows Sandbox on: {DOC}",
                              _windows(features={**FEATURES_PC, "Containers": 1, "Containers-DisposableClientVM": 1})),
}

# needs' own files of a Linux (what linuxsys never reads)
INTEL_WSL = ("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Core(TM) Ultra 9 275HX\n"
             "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse "
             "sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology tsc_reliable cpuid pni "
             "pclmulqdq vmx ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand "
             "hypervisor lahf_lm abm 3dnowprefetch ssbd ibrs ibpb stibp vpid ept fsgsbase bmi1 avx2 smep bmi2 erms "
             "invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves avx_vnni\n"
             "vmx flags\t: vnmi invvpid ept_x_only ept_ad ept_1gb tsc_offset vtpr ept vpid unrestricted_guest\n")
INTEL_WSL_NO_VMX = INTEL_WSL.replace(" vmx ", " ").replace("vpid ept ", "").split("vmx flags")[0]
AMD_METAL = ("processor\t: 0\nvendor_id\t: AuthenticAMD\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr "
             "pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm "
             "constant_tsc rep_good nopl cpuid pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes "
             "xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch "
             "bmi1 avx2 smep bmi2 npt nrip_save avx512f\n")
VM_GUEST = ("processor\t: 0\nvendor_id\t: AuthenticAMD\nflags\t\t: fpu de pse tsc msr pae mce cx8 apic sep mtrr pge "
            "mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx lm rep_good nopl cpuid pni ssse3 cx16 sse4_1 "
            "sse4_2 popcnt avx avx2 hypervisor\n")
ROUTE = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\nens3\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\n"
ROUTE_WSL = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t01001FAC\t0003\t0\t0\t0\t00000000\n"
ROUTE_NONE = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\nens3\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"


def _meminfo(gib: float) -> str:
    return f"MemTotal:       {int(gib * 1024 * 1024)} kB\nMemFree:        {int(gib * 512 * 1024)} kB\n"


METAL = {"/proc/cpuinfo": AMD_METAL, "/proc/meminfo": _meminfo(30.5), "/dev/kvm": "",
         "/sys/module/kvm_amd/parameters/nested": "1\n", "/proc/net/route": ROUTE, "/proc/net/ipv6_route": "",
         "/sys/module/nf_tables": "", "/sys/fs/bpf": "", "/proc/sys/kernel/unprivileged_bpf_disabled": "2\n"}
WSL2 = {"/proc/cpuinfo": INTEL_WSL, "/proc/meminfo": _meminfo(31.07), "/dev/kvm": "",
        "/sys/module/kvm_intel/parameters/nested": "Y\n", "/proc/net/route": ROUTE_WSL, "/proc/net/ipv6_route": "",
        "/sys/module/nf_tables": "", "/sys/fs/bpf": "", "/proc/sys/kernel/unprivileged_bpf_disabled": "2\n"}
LINUX_DOC = "needs' own files made from the kernel's documentation (proc(5), the kvm modules), never read on it"
PC_UBUNTU = ("needs' own files as this PC's Ubuntu answered them on 2026-11-17 (the needs plan's map-facts 3, 6, 8, 9: "
             "vmx, ept and the hypervisor flag, /dev/kvm with kvm_intel nested=Y, 31.07 GiB, a default route to WSL's "
             "switch, no IPv6 default)")

LINUX: dict[str, tuple[str, str | None, dict, dict, str]] = {
    "alpine-3.24": ("alpine-3.24", None, {**METAL, "/run/openrc": ""}, {}, f"{LINUX_DOC}; OpenRC's /run/openrc"),
    "collision": ("collision", None, dict(METAL), {}, LINUX_DOC),
    "container-bare": ("container-bare", None, {**METAL, "/dev/kvm": None, "/sys/module/kvm_amd/parameters/nested":
                                                None}, {}, f"{LINUX_DOC}; a container is given no /dev/kvm"),
    "debian-13": ("debian-13", None, dict(METAL), {}, LINUX_DOC),
    "debian-13-su": ("debian-13-su", None, dict(METAL), {}, LINUX_DOC),
    "fedora-45": ("fedora-45", None, dict(METAL), {}, LINUX_DOC),
    "liminal-ubuntu": ("liminal-ubuntu", None, dict(WSL2), {}, f"{PC_UBUNTU}: WSL 2's distributions share one VM"),
    "nixos-26.05": ("nixos-26.05", None, dict(METAL), {}, LINUX_DOC),
    "opensuse-tumbleweed": ("opensuse-tumbleweed", None, dict(METAL), {}, LINUX_DOC),
    "service-account": ("service-account", None, dict(METAL), {}, LINUX_DOC),
    "ubuntu-26.04": ("ubuntu-26.04", None, dict(METAL), {}, LINUX_DOC),
    "wsl-ubuntu-24.04": ("wsl-ubuntu-24.04", None, dict(WSL2), {}, PC_UBUNTU),
    # the variants: a linuxsys machine with some of its files changed
    "wsl1": ("wsl-ubuntu-24.04", None,
             {**WSL2, "/proc/sys/kernel/osrelease": "4.4.0-26300-Microsoft\n", "/run/systemd/container": None,
              "/run/systemd/system": None, "/proc/1/comm": "init\n", "/dev/kvm": None,
              "/sys/module/kvm_intel/parameters/nested": None, "/proc/cpuinfo": INTEL_WSL_NO_VMX,
              "/sys/module/nf_tables": None, "/sys/fs/bpf": None, "/proc/sys/kernel/unprivileged_bpf_disabled": None},
             {}, "this PC's Ubuntu as WSL 1 would show it (Windows' kernel, Microsoft's release words, no systemd, no "
                 "/dev/kvm): made from Microsoft's WSL documentation, never read"),
    "wsl2-no-nesting": ("wsl-ubuntu-24.04", None,
                        {**WSL2, "/proc/cpuinfo": INTEL_WSL_NO_VMX, "/dev/kvm": None,
                         "/sys/module/kvm_intel/parameters/nested": None},
                        {}, "this PC's Ubuntu with nestedVirtualization=false in .wslconfig: no vmx, no /dev/kvm "
                            "(made from Microsoft's WSL documentation)"),
    "ubuntu-nm": ("ubuntu-26.04", None, {**METAL, "/run/NetworkManager": ""}, {},
                  f"{LINUX_DOC}; NetworkManager's last verdict full (nmcli -t -f CONNECTIVITY general)"),
    "linux-no-route": ("debian-13", None, {**METAL, "/proc/net/route": ROUTE_NONE}, {},
                       f"{LINUX_DOC}; no default route"),
    "linux-proxy": ("debian-13", None, dict(METAL), {"HTTPS_PROXY": "a stand-in proxy"},
                    f"{LINUX_DOC}; HTTPS_PROXY set"),
    "linux-vm-small": ("fedora-45", None, {**METAL, "/proc/cpuinfo": VM_GUEST, "/proc/meminfo": _meminfo(2),
                                           "/dev/kvm": None, "/sys/module/kvm_amd/parameters/nested": None}, {},
                       f"{LINUX_DOC}; a small virtual machine: the hypervisor flag, no svm, 2 GiB"),
}
NMCLI_SAYS = {"ubuntu-nm": "full"}


def names() -> list[str]:
    return [*WINDOWS, *LINUX]


def source(name: str) -> str:
    """Where the machine's facts come from, in words."""
    if name in WINDOWS:
        return WINDOWS[name][0]
    machine, overlay, _files, _env, words = LINUX[name]
    from .linuxsys import standin

    return f"{standin.Machine(machine, overlay).source}\n{words}"


def linux_files(name: str) -> tuple[dict, dict]:
    """A Linux machine's files as its probe would read them (a folder there is ""), needs' own beside them, and its
    environment."""
    from .linuxsys import standin

    machine, overlay, extra, env, _words = LINUX[name]
    m = standin.Machine(machine, overlay)
    files = {p: t for p, t in m.files.items()}
    for p, f in m.folders.items():
        if f is not None and p not in files:
            files[p] = ""
    for p in m.unread:
        files[p] = ""
    files.update(extra)
    return files, {**m.data.get("env", {}), **env}


def facts_of(name: str) -> dict:
    """The recorded machine's facts, in facts.py's shape, by facts.py's own parsers."""
    if name in WINDOWS:
        return facts.parse_windows(copy.deepcopy(WINDOWS[name][1]))
    if name not in LINUX:
        raise KeyError(f"no recorded machine {name!r}: {', '.join(names())}")
    from .linuxsys import standin

    files, env = linux_files(name)
    out = facts.parse_linux(files, env, "", nmcli=NMCLI_SAYS.get(name))
    m = standin.Machine(LINUX[name][0], LINUX[name][1])
    out.update({"library": LIBRARY, "read": "2026-11-26T00:00:00Z", "tools": {},
                "disk": {"free": 100 * GIB, "path": "/home"},
                "rights": {"administrator": False, "root": m.euid == 0,
                           "groups": str(m.data.get("groupnames", "")).split()}})
    return out


def reader(name: str) -> facts.StandIn:
    """A stand-in reader answering the recorded machine's facts."""
    return facts.StandIn(facts_of(name))
