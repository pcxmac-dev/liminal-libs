"""eBPF for the firewall's Filter tab, for trapdoor, and for the eBPF API plugin (the user, 2026-11-14: "both
windows and linux use ebpf for the filter tab"; "we need an ebpf api plugin, that shows the difference between
windows and linux capabilities as well as basic functionality").

`Runtime` reads and drives the runtime on this machine (`LinuxRuntime` through bpftool, `WindowsRuntime` through
the service and signing reads), and `CAPABILITIES` is the Linux-against-Windows comparison, host-free so the
library stays clear of provider URLs. `Watch` streams events while a tab is being asked and stops itself when it is
not; `make_watch` picks the backend for the machine. The eBPF plugin wires these to its pages and holds the source
links; the library keeps none."""
from __future__ import annotations

from .capabilities import CAPABILITIES, Capability
from .linux import LinuxRuntime
from .runtime import Runtime
from .watch import BpftraceWatch, Event, Watch, make_watch, watch_system
from .windows import WindowsRuntime

__all__ = [
    "CAPABILITIES", "Capability", "Runtime", "LinuxRuntime", "WindowsRuntime",
    "Watch", "Event", "BpftraceWatch", "make_watch", "watch_system",
]
