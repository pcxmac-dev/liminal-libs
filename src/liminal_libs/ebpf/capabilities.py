"""The eBPF capability comparison, Linux against Windows (the user, 2026-11-14: "we need an ebpf api plugin,
that shows the difference between windows and linux capabilities as well as basic functionality"). Rows of
(area, item, linux, windows), read 2026-11-14 from the maintainers' own documentation, headers and release notes:
every row of that research, the comparison first and then the basic functions (area "Basic functions", each
ending with a "Rights:" line for what it needs on each side).

No outside host appears here: the design keeps the library clear of provider hosts, and the charts app's boundary
test scans these files. The source links for every row live in the eBPF plugin (its apis.py), keyed by the row's
(area, item), which are the research's own; `rows(sources)` puts them beside the rows when the plugin gives them.
A cell's lines are separate points, and a line starting "- " is one item of a list.

The short of it: on Linux eBPF is part of the kernel and production-grade; on Windows it is a separate,
pre-release download whose every public build is test-signed (its maintainers have no plans for production-signed
builds), so on a Secure Boot machine it cannot load without test-signing mode. The Linux functions apply only on a
native Linux machine, never WSL (the Liminal rule)."""
from __future__ import annotations

from dataclasses import dataclass

FUNCTIONS_AREA = "Basic functions"  # the rows the plugin's Functions tab shows, with its confirmed forms


@dataclass(frozen=True)
class Capability:
    """One line of the comparison: the `area` it belongs to, the `item` compared, and what each side does."""
    area: str
    item: str
    linux: str
    windows: str

    def as_dict(self) -> dict:
        return {"area": self.area, "item": self.item, "linux": self.linux, "windows": self.windows}


CAPABILITIES: tuple[Capability, ...] = (
    # -- Install and status ----------------------------------------------------------------------------------------
    Capability(
        "Install and status", "Where it comes from",
        "Built into the kernel: bpf() syscall, in-kernel verifier and JIT (CONFIG_BPF_SYSCALL, CONFIG_BPF_JIT). "
        "Nothing to install for the runtime; libbpf and bpftool come from distro packages or source.",
        "Not in-box (no Microsoft statement found that it ships with Windows). The MSI "
        "(ebpf-for-windows.x64|arm64.<ver>.msi) installs into C:\\Program Files\\ebpf-for-windows: eBPFCore.sys "
        "and NetEbpfExt.sys as auto-start kernel services (sc create ... type=kernel start=auto), the eBPFSvc "
        "user-mode service, EbpfApi.dll, bpftool.exe, bpf2c.exe, export_program_info.exe and the netsh helper "
        "ebpfnetsh.dll. JIT is an optional MSI feature. SDK on NuGet (eBPF-for-Windows.x64/ARM64). A Kubernetes "
        "host-process DaemonSet is also documented. XDP and the process/netevent hooks install separately."),
    Capability(
        "Install and status", "Current version",
        "Kernel releases: mainline 7.4-rc2 (2026-11-09), stable 7.3.4 (2026-11-10), longterm 6.18.63, 6.12.117, "
        "6.6.162, 6.1.192, 5.15.225. libbpf v1.8.0 (2026-10-05), bpftool v7.8.1 (2026-10-20).",
        "Release v1.7.0 (2026-10-16). A servicing tag v1.7.1 (2026-11-06, tracing-script fixes) and NuGet 1.7.1 "
        "(2026-11-10), but no release page yet. main is at 1.8.0. History: v1.0.0-rc1 2025-10-23; v1.1.0 "
        "2026-03-25, which its notes call 'the first stable release'; monthly releases 1.2.1 to 1.7.0 since. XDP "
        "for Windows v1.4.0 (2026-07-29, supported to 2028-01-29). ntosebpfext v0.7.0 (2026-05-01, pre-release)."),
    Capability(
        "Install and status", "Production or preview",
        "Production: part of every mainline and longterm kernel.",
        "Preview in practice:\n"
        "- Every public release, including v1.7.0, is flagged Pre-release.\n"
        "- ReleaseProcess.md: 'Pre-release binaries are test signed. Official releases will be production signed "
        "using Microsoft certificates.'\n"
        "- Maintainer on issue #5184 (2026-05-04): 'Currently there are no plans for release production signed "
        "eBPF bits.'\n"
        "- Without test signing, the eBPFCore driver fails to start (System error 577, issue #4418).\n"
        "- The README still calls the project 'a work-in-progress'."),
    Capability(
        "Install and status", "Supported OS and extension model",
        "Any kernel built with BPF (CONFIG_BPF_SYSCALL); all program types live in the kernel itself.",
        "Windows 11 or later and Windows Server 2022 or later, with x64 and ARM64 MSIs. Program types come from "
        "extension drivers over NMR:\n"
        "- NetEbpfExt.sys: sock_addr, sock_ops, bind.\n"
        "- xdp.sys from XDP for Windows: XDP; officially Windows Server 2022/2025 only.\n"
        "- ntosebpfext.sys and neteventebpfext.sys from the ntosebpfext project: process and netevent; build from "
        "source.\n"
        "Since v1.1.0, extensions can also register custom map types."),

    # -- Program types ---------------------------------------------------------------------------------------------
    Capability(
        "Program types", "Count and numbering",
        "32 program types in 7.3 (SOCKET_FILTER to NETFILTER), the same in 6.12 and 6.18.",
        "7 program types:\n"
        "- XDP (1)\n"
        "- BIND (2, deprecated)\n"
        "- CGROUP_SOCK_ADDR (3)\n"
        "- SOCK_OPS (4)\n"
        "- NETEVENT (5)\n"
        "- PROCESS (6)\n"
        "- SAMPLE (999, test only)\n"
        "The names match Linux but the numbers do not: Linux XDP=6, SOCK_OPS=13, CGROUP_SOCK_ADDR=18. Internally "
        "every type is a GUID."),
    Capability(
        "Program types", "XDP",
        "BPF_PROG_TYPE_XDP, sections xdp, xdp.frags, xdp/devmap and xdp/cpumap. Modes: native (xdpdrv), generic "
        "and offload. Actions: XDP_ABORTED 0, DROP 1, PASS 2, TX 3, REDIRECT 4 (to devmap, cpumap or xskmap). "
        "Receive path only. Needs CAP_NET_ADMIN.",
        "Comes from XDP for Windows (xdp.sys), not the core runtime.\n"
        "- eBPF programs are supported from XDP v1.4, per the FAQ.\n"
        "- Receive path only. Context xdp_md_t: data, data_end, data_meta, ingress_ifindex, rx_queue_index.\n"
        "- Actions XDP_PASS 1, DROP 2, TX 3, REDIRECT 4. There is no ABORTED, and the PASS/DROP numbers are "
        "swapped versus Linux.\n"
        "- Redirect goes only to AF_XDP sockets, via XSKMAP and bpf_redirect_map.\n"
        "- Setup: XdpEbpfEnabled=1, xdp-setup.ps1 -Install xdpebpf, and xdpbpfexport.exe. Generic or native mode "
        "is set by XdpEbpfMode.\n"
        "- Only native .sys programs are officially supported.\n"
        "- Official OS support: Windows Server 2022/2025."),
    Capability(
        "Program types", "sched_cls / tc (tcx)",
        "BPF_PROG_TYPE_SCHED_CLS on tcx/ingress and tcx/egress; libbpf deprecates the classic tc, classifier and "
        "action sections. Runs per packet in both directions with skb access.",
        "None. There is no traffic-control or egress packet hook; per-packet processing exists only in XDP on "
        "receive. A FLOW_CLASSIFY program type for TCP stream inspection exists only as a proposal."),
    Capability(
        "Program types", "cgroup_skb",
        "cgroup_skb/ingress and cgroup_skb/egress run on every packet of sockets in a cgroup v2. Helpers include "
        "bpf_skb_cgroup_id, bpf_get_socket_cookie, bpf_get_socket_uid and bpf_sk_storage_get. When unprivileged "
        "BPF is on, an unprivileged user can load one, but attaching checks CAP_NET_ADMIN.",
        "None."),
    Capability(
        "Program types", "cgroup_sock",
        "cgroup/sock_create (also cgroup/sock), cgroup/post_bind4, cgroup/post_bind6 and cgroup/sock_release; run "
        "from the socket system calls.",
        "No such type. Bind and listen are sock_addr attach types, at WFP ALE_RESOURCE_ASSIGNMENT and "
        "ALE_AUTH_LISTEN. The end of a flow arrives as sock_ops CONNECTION_DELETED_CB. The deprecated BIND type "
        "reported BIND, POST_BIND and UNBIND operations."),
    Capability(
        "Program types", "cgroup_sock_addr: connect4/6 (and connect_authorization)",
        "cgroup/connect4 and cgroup/connect6 on a cgroup v2, for TCP connect() and UDP connect(). Can rewrite "
        "user_ip4/6 and user_port; returns 1 to allow, 0 to reject.",
        "BPF_CGROUP_INET4/6_CONNECT:\n"
        "- Runs at WFP ALE_CONNECT_REDIRECT, before route selection, for 'TCP connect() or UDP send to a unique "
        "remote address/port tuple'.\n"
        "- Can redirect; not re-run on WFP reauth.\n"
        "Windows-only BPF_CGROUP_INET4/6_CONNECT_AUTHORIZATION (v1.3.0):\n"
        "- Runs at ALE_AUTH_CONNECT after route selection, and again on reauth.\n"
        "- Reads interface and tunnel data via bpf_sock_addr_get_network_context; cannot redirect.\n"
        "Both:\n"
        "- Verdicts REJECT, PROCEED_SOFT and PROCEED_HARD map to WFP hard block, soft permit and hard permit.\n"
        "- Attach to one network compartment or to all; several programs may attach."),
    Capability(
        "Program types", "cgroup_sock_addr: recv_accept4/6",
        "No such attach type. Inbound TCP: sock_ops PASSIVE_ESTABLISHED_CB, which only notifies, or LSM/fexit on "
        "the accept path. Inbound UDP: cgroup/recvmsg4/6 runs on every recvmsg of an unconnected UDP socket; it "
        "exists to rewrite the source address.",
        "BPF_CGROUP_INET4/6_RECV_ACCEPT at ALE_AUTH_RECV_ACCEPT, for 'TCP accept() or on receiving the first "
        "unicast UDP packet from a unique remote address/port tuple'. Can reject; hard and soft permit since "
        "v1.1.0. Only one program per hook."),
    Capability(
        "Program types", "cgroup_sock_addr: bind4/6 and listen",
        "cgroup/bind4 and cgroup/bind6 can rewrite the address and port; cgroup/post_bind4/6 follow the bind. "
        "There is no listen hook with a verdict; sock_ops TCP_LISTEN_CB only notifies.",
        "BPF_CGROUP_INET4/6_BIND at ALE_RESOURCE_ASSIGNMENT covers explicit and implicit binds. "
        "BPF_CGROUP_INET4/6_LISTEN runs at ALE_AUTH_LISTEN. Both arrived in v1.3.0 to v1.4.0 (June to July 2026) "
        "and allow several programs. They replace BPF_PROG_TYPE_BIND, deprecated in v1.6.0."),
    Capability(
        "Program types", "cgroup_sock_addr: other attach points",
        "cgroup/sendmsg4/6 and recvmsg4/6 (UDP), getpeername4/6, getsockname4/6, and the unix-socket variants: "
        "connect_unix, sendmsg_unix, recvmsg_unix, getpeername_unix, getsockname_unix.",
        "None of these."),
    Capability(
        "Program types", "sock_ops",
        "Section sockops, attached to a cgroup v2. TCP callbacks:\n"
        "- TCP_CONNECT_CB, ACTIVE_ESTABLISHED_CB, PASSIVE_ESTABLISHED_CB\n"
        "- STATE_CB (opt-in flag) and TCP_LISTEN_CB\n"
        "- RTO, RETRANS and RTT\n"
        "- header-option and TX-timestamp callbacks\n"
        "Used to tune TCP (setsockopt, callback flags, header options), not to allow or deny.",
        "Section sockops at WFP ALE_FLOW_ESTABLISHED v4/v6.\n"
        "- Callbacks: ACTIVE_ESTABLISHED_CB (outbound), PASSIVE_ESTABLISHED_CB (inbound), CONNECTION_DELETED_CB.\n"
        "- Covers any IP protocol WFP reports as a flow, not only TCP.\n"
        "- Return 0 permits; nonzero blocks the flow, and the block is final for lower-weight filters.\n"
        "- Context: local and remote IP and port, protocol, compartment_id, interface_luid.\n"
        "- Helpers: bpf_sock_ops_get_flow_id and a PID override.\n"
        "- One program per compartment; a wildcard attach is accepted only when none exists."),
    Capability(
        "Program types", "kprobe / tracepoint / fentry",
        "- KPROBE: kprobe, kretprobe, ksyscall, uprobe, usdt, plus multi and session forms.\n"
        "- TRACEPOINT: tp.\n"
        "- RAW_TRACEPOINT: raw_tp, tp_btf.\n"
        "- TRACING: fentry, fexit, fmod_ret, fsession, iter, with sleepable .s variants.\n"
        "Need CAP_PERFMON plus CAP_BPF. Hooks that rely on BTF need kernel BTF.",
        "None: no kprobe, tracepoint or fentry equivalent, and Windows tracing stays in ETW. The only non-network "
        "hook is the PROCESS type from ntosebpfext."),
    Capability(
        "Program types", "LSM",
        "BPF_PROG_TYPE_LSM with lsm/<hook>, lsm.s/<hook> and lsm_cgroup. Returning -EPERM denies the operation. "
        "Needs CONFIG_BPF_LSM with the bpf LSM active, plus CAP_PERFMON and CAP_BPF.",
        "None. Socket policy goes through WFP ALE via the sock_addr and sock_ops hooks."),
    Capability(
        "Program types", "struct_ops",
        "BPF_PROG_TYPE_STRUCT_OPS (struct_ops, struct_ops.s) together with BPF_MAP_TYPE_STRUCT_OPS: BPF code "
        "implements kernel operation tables. Needs CAP_PERFMON plus CAP_BPF.",
        "None."),
    Capability(
        "Program types", "Windows BIND",
        "No separate type; cgroup/bind4/6 and post_bind4/6 cover it.",
        "BPF_PROG_TYPE_BIND with BPF_ATTACH_TYPE_BIND.\n"
        "- Context bind_md_t: app_id, process_id, socket address, operation (BIND, POST_BIND or UNBIND), "
        "protocol.\n"
        "- Returns BIND_PERMIT_SOFT, BIND_DENY, BIND_REDIRECT or BIND_PERMIT_HARD.\n"
        "- Single attach.\n"
        "Deprecated in v1.6.0 (2026-09-18) in favour of CGROUP_SOCK_ADDR with BPF_CGROUP_INET4/6_BIND."),
    Capability(
        "Program types", "Windows SAMPLE",
        "None.",
        "BPF_PROG_TYPE_SAMPLE (999), BPF_ATTACH_TYPE_SAMPLE and BPF_MAP_TYPE_SAMPLE_HASH_MAP, served by the "
        "sample_ebpf_ext.sys test driver; for testing only. The current header has no XDP_TEST type."),
    Capability(
        "Program types", "Windows NETEVENT",
        "None.",
        "BPF_PROG_TYPE_NETEVENT (5) with BPF_ATTACH_TYPE_NETEVENT (10), from neteventebpfext.sys in the "
        "ntosebpfext project.\n"
        "- Section netevent_monitor; context netevent_event_md_t (data_meta, data, data_end).\n"
        "- Events come from NMR provider modules; today these are pktmon drop (type 100) and flow (type 101) "
        "events.\n"
        "- Attach option: capture all, flow or drop. Helper: bpf_netevent_push_event.\n"
        "- Built from source and run as a demand-start driver; ntosebpfext v0.7.0 is a pre-release."),
    Capability(
        "Program types", "Windows PROCESS",
        "No separate type; process events come from tracepoints, fentry/kprobes or LSM hooks.",
        "BPF_PROG_TYPE_PROCESS (6) with BPF_ATTACH_TYPE_PROCESS (11), from ntosebpfext.sys through "
        "PsSetCreateProcessNotifyRoutineEx.\n"
        "- Create and delete events carry PID, parent PID, creating PID/TID, creation and exit time, exit code, "
        "command line and token SID.\n"
        "- Helpers: bpf_process_get_image_path, bpf_process_get_account_name, bpf_process_get_account_domain."),

    # -- Attach types ----------------------------------------------------------------------------------------------
    Capability(
        "Attach types", "Count and names",
        "62 attach types in 7.3 (58 in 6.18). They cover:\n"
        "- cgroup: inet ingress/egress, sock create/release, sock_addr (inet4/6, udp, unix), sockopt, sysctl, "
        "device\n"
        "- sockets: sk_skb, sk_msg, sk_lookup\n"
        "- networking: XDP with devmap/cpumap, tcx and netkit, flow dissector, netfilter\n"
        "- tracing: fentry/fexit/fmod_ret/fsession and their multi forms, raw tracepoint, iterators, kprobe/uprobe "
        "multi and session, perf_event\n"
        "- LSM MAC and LSM cgroup, struct_ops",
        "17 attach types:\n"
        "- BPF_XDP\n"
        "- BPF_ATTACH_TYPE_BIND (deprecated)\n"
        "- BPF_CGROUP_INET4/6_ CONNECT, RECV_ACCEPT, CONNECT_AUTHORIZATION, BIND and LISTEN\n"
        "- BPF_CGROUP_SOCK_OPS\n"
        "- BPF_ATTACH_TYPE_SAMPLE, _NETEVENT (10) and _PROCESS (11)\n"
        "Windows-only: RECV_ACCEPT, CONNECT_AUTHORIZATION, LISTEN, NETEVENT, PROCESS. Shared names carry other "
        "numbers: Linux CGROUP_INET4_CONNECT=10 and CGROUP_SOCK_OPS=3; Windows 3 and 7."),
    Capability(
        "Attach types", "Targets, links, multi-attach",
        "Targets: a cgroup v2 directory, a netdev ifindex, a netns, a kernel function or hook by BTF id, or a perf "
        "event. BPF links (15 link types in 7.3) can be pinned. cgroup attach flags: multi, override, preorder.",
        "Targets: a network compartment ID for sock_addr and sock_ops (4-byte attach data; empty means all "
        "compartments), or an interface index for XDP (netsh: no index or 0 means all interfaces). 3 link types: "
        "PLAIN, CGROUP, XDP. connect, bind and listen accept several programs; recv_accept and sock_ops accept one "
        "per hook; the legacy BIND hook is single."),

    # -- Map types -------------------------------------------------------------------------------------------------
    Capability(
        "Map types", "Count and numbering",
        "35 map types in 7.3. 6.18 had 33; INSN_ARRAY and RHASH were added since.",
        "16 map types:\n"
        "- HASH 1, ARRAY 2, PROG_ARRAY 3, PERCPU_HASH 4\n"
        "- PERCPU_ARRAY 5, HASH_OF_MAPS 6, ARRAY_OF_MAPS 7, LRU_HASH 8\n"
        "- LPM_TRIE 9, QUEUE 10, LRU_PERCPU_HASH 11, STACK 12\n"
        "- RINGBUF 13, PERF_EVENT_ARRAY 14\n"
        "- SAMPLE_HASH_MAP 15 (test), XSKMAP 16 (from XDP for Windows)\n"
        "Since v1.1.0, extensions can add custom map types. Numbers differ from Linux, where PERF_EVENT_ARRAY=4, "
        "PERCPU_HASH=5, RINGBUF=27."),
    Capability(
        "Map types", "hash",
        "BPF_MAP_TYPE_HASH, with per-CPU and LRU variants.",
        "HASH (1). The Windows-only creation flag BPF_F_NO_MAX_ENTRIES matters here. hash, percpu_hash, "
        "hash_of_maps and lpm_trie now enforce max_entries by default; the flag restores unbounded growth, with "
        "max_entries kept as a bucket-count hint."),
    Capability(
        "Map types", "array",
        "BPF_MAP_TYPE_ARRAY and PERCPU_ARRAY.",
        "ARRAY (2). Since v1.7.0 array-family maps require 4-byte keys, as on Linux. Global-variable sections "
        "become array maps created by the execution context."),
    Capability(
        "Map types", "percpu",
        "PERCPU_HASH, PERCPU_ARRAY and LRU_PERCPU_HASH; PERCPU_CGROUP_STORAGE is deprecated.",
        "PERCPU_HASH (4), PERCPU_ARRAY (5) and LRU_PERCPU_HASH (11). The header's per-CPU macro also counts "
        "PERF_EVENT_ARRAY."),
    Capability(
        "Map types", "lru",
        "LRU_HASH and LRU_PERCPU_HASH.",
        "LRU_HASH (8) and LRU_PERCPU_HASH (11). LRU types reject BPF_F_NO_MAX_ENTRIES. v1.6.0 sped up LRU lookups."),
    Capability(
        "Map types", "lpm_trie",
        "LPM_TRIE (longest-prefix match).",
        "LPM_TRIE (9)."),
    Capability(
        "Map types", "prog_array",
        "PROG_ARRAY with bpf_tail_call; MAX_TAIL_CALL_CNT is 33.",
        "PROG_ARRAY (3) with bpf_tail_call (helper 5); MAX_TAIL_CALL_CNT is 33."),
    Capability(
        "Map types", "array_of_maps / hash_of_maps",
        "ARRAY_OF_MAPS and HASH_OF_MAPS.",
        "HASH_OF_MAPS (6) and ARRAY_OF_MAPS (7). bpf_map_info carries a Windows-only inner_map_id. v1.6.0 fixed "
        "replacing entries in HASH_OF_MAPS."),
    Capability(
        "Map types", "queue / stack",
        "QUEUE and STACK, used with bpf_map_push_elem, pop_elem and peek_elem.",
        "QUEUE (10) and STACK (12), with the push, pop and peek helpers (16 to 18)."),
    Capability(
        "Map types", "ringbuf",
        "RINGBUF (since 5.8): one multi-producer buffer shared by all CPUs that keeps reservation order. Program "
        "side: bpf_ringbuf_reserve, submit and discard, plus bpf_ringbuf_output. USER_RINGBUF carries data from "
        "user space to the kernel.",
        "RINGBUF (13) with bpf_ringbuf_output only. Reserve and submit are 'blocked on verifier support' (PREVAIL "
        "issue #273). No USER_RINGBUF."),
    Capability(
        "Map types", "perf_event_array",
        "PERF_EVENT_ARRAY: per-CPU buffers through the perf subsystem, written with bpf_perf_event_output. The "
        "same subsystem also offers perf counters and hardware events.",
        "PERF_EVENT_ARRAY (14), built on the ring-buffer code.\n"
        "- bpf_perf_event_output writes to the current CPU only.\n"
        "- BPF_F_CTXLEN_MASK copies payload for any program type whose context has a data pointer.\n"
        "- 'Not supported': perf counters, hardware events, attaching programs to perf events, and events sent "
        "from user space."),
    Capability(
        "Map types", "Linux-only map types",
        "STACK_TRACE, CGROUP_ARRAY, DEVMAP and DEVMAP_HASH, CPUMAP, SOCKMAP and SOCKHASH, REUSEPORT_SOCKARRAY, the "
        "SK, INODE, TASK and CGRP storage maps, STRUCT_OPS, BLOOM_FILTER, USER_RINGBUF, ARENA, INSN_ARRAY, RHASH.",
        "None of these; XSKMAP exists only through XDP for Windows. There is no per-socket storage, so per-flow "
        "state goes in a hash keyed by tuple, socket cookie or WFP flow id."),

    # -- Helpers ---------------------------------------------------------------------------------------------------
    Capability(
        "Helpers", "Count",
        "211 helper IDs (1 to 211; the last are cgrp_storage_get and delete). The count is the same in 6.12, 6.18 "
        "and 7.3. New kernel features arrive as kfuncs, which have no stable interface.",
        "35 general helpers (IDs 1 to 35; the last, bpf_redirect_map, arrived in v1.4.0). Program-type helpers use "
        "IDs above 0xFFFF:\n"
        "- sock_addr, 3: get_current_pid_tgid override, set_redirect_context, get_network_context\n"
        "- sock_ops, 1: get_flow_id\n"
        "- process, 3: get_image_path, get_account_name, get_account_domain\n"
        "- netevent, 1: push_event\n"
        "Extensions can also override global helpers."),
    Capability(
        "Helpers", "Notable gaps and Windows-only helpers",
        "Has many helpers Windows lacks, for example:\n"
        "- bpf_get_current_comm, uid_gid, cgroup_id and task\n"
        "- bpf_probe_read_kernel/user, bpf_ringbuf_reserve/submit, bpf_sk_storage_get\n"
        "- bpf_skb_*, bpf_redirect, bpf_xdp_adjust_head/tail\n"
        "- bpf_loop, bpf_for_each_map_elem, bpf_timer_*, bpf_spin_lock\n"
        "- bpf_get_stack, bpf_send_signal, bpf_snprintf\n"
        "Also conntrack kfuncs such as bpf_skb_ct_lookup and bpf_xdp_ct_lookup.",
        "The general set:\n"
        "- map operations: lookup, update, delete, lookup_and_delete, push, pop, peek\n"
        "- tail_call, get_prandom_u32, ktime in ns, ms and boot time, get_smp_processor_id, csum_diff\n"
        "- ringbuf_output, trace_printk2 to 5 (bpf_printk goes to ETW)\n"
        "- get_current_pid_tgid, get_socket_cookie, perf_event_output, redirect_map\n"
        "Windows-only: get_current_logon_id, is_current_admin, memcpy_s, memcmp_s, memset, memmove_s, strncpy_s, "
        "strncat_s, strnlen_s, ktime_get_boot_ms, ktime_get_ms, get_current_process_start_key, "
        "get_current_thread_create_time."),
    Capability(
        "Helpers", "kfuncs / BTF-resolved functions",
        "kfuncs: kernel functions callable from BPF by BTF ID; 'A kfunc will never have any hard stability "
        "guarantees.'",
        "The planned analogue is 'BTF-resolved functions': call_btf by BTF ID, resolved from module GUID and name. "
        "Status is unclear:\n"
        "- v1.5.0 notes say 'Implement BTF-resolved function support'.\n"
        "- The design doc says the interfaces are 'not yet present in current public headers'.\n"
        "- isa-support lists call by BTF ID as unsupported."),

    # -- Verifier --------------------------------------------------------------------------------------------------
    Capability(
        "Verifier", "Where and when it runs",
        "In the kernel (kernel/bpf/verifier.c) on every BPF_PROG_LOAD, inside bpf_check(). It runs a DAG check, "
        "then simulates every path while tracking register and stack state. Privileged programs may reach "
        "1,000,000 instructions (BPF_COMPLEXITY_LIMIT_INSNS); unprivileged ones 4096.",
        "PREVAIL, an abstract-interpretation verifier, runs in user mode:\n"
        "- Native images: offline at build time, inside bpf2c.\n"
        "- JIT: in the eBPFSvc service.\n"
        "The kernel itself does not verify. Proof of Verification (v1.0.0-rc1) ties a native .sys to a passed "
        "verification through a signature and a program-info hash. v1.7.0 pulled in upstream PREVAIL fixes. 'netsh "
        "ebpf show verification' runs it on a file."),
    Capability(
        "Verifier", "Instruction set coverage",
        "The full BPF ISA (standardized as RFC 9669), including atomics and call by BTF ID.",
        "Per isa-support.rst: PREVAIL and bpf2c handle most of the ISA, including 32- and 64-bit atomics. The uBPF "
        "JIT lacks atomics and sign-extending moves. Call by BTF ID is unsupported in all three."),

    # -- Execution -------------------------------------------------------------------------------------------------
    Capability(
        "Execution", "Interpreter / JIT / native",
        "In-kernel JIT, controlled by net.core.bpf_jit_enable (0, 1 or 2) and on by default where the architecture "
        "asks for it (BPF_JIT_DEFAULT_ON). CONFIG_BPF_JIT_ALWAYS_ON removes the interpreter and pins "
        "bpf_jit_enable at 1. bpf_jit_harden adds JIT hardening. There is no ahead-of-time native format.",
        "Three modes:\n"
        "- Native: bpf2c turns verified bytecode into C, built into a kernel driver (.sys). The README calls it "
        "'the preferred way', and it is the only officially supported mode ('JIT execution of BPF object files "
        "(.o) is not officially supported').\n"
        "- JIT: the uBPF JIT inside the user-mode eBPFSvc. An optional MSI feature, 'available on pre-release "
        "versions only'; JIT output is capped at 32 KB.\n"
        "- Interpreter: debug builds only.\n"
        "The NativeOnly build configurations remove both JIT and interpreter."),
    Capability(
        "Execution", "HVCI (memory integrity)",
        "No hypervisor code-integrity rule applies to BPF; the kernel manages its own JIT images.",
        "With HVCI (memory integrity) on, JIT cannot run, because the JIT has no key the hypervisor trusts. "
        "Release builds have no interpreter, so only native signed .sys programs work. The state shows in "
        "Win32_DeviceGuard: SecurityServicesRunning contains 2. Microsoft documents this as an elevated query."),
    Capability(
        "Execution", "Signing and test signing",
        "Not required. Optional program signing since 6.18: a signed BPF_PROG_TYPE_SYSCALL loader (libbpf "
        "gen_loader) carries a PKCS#7 signature. BPF_PROG_LOAD checks it against a keyring and passes the verdict "
        "to LSM hooks. 'An unsigned program loads exactly as before.'",
        "A driver loads only if it is production-signed, a kernel debugger is attached, or test-signing mode is "
        "on. Public eBPF for Windows builds are test-signed, so they need test signing.\n"
        "- Turning it on: 'bcdedit -set TESTSIGNING ON' from an elevated prompt, then reboot.\n"
        "- Windows refuses while Secure Boot protects the setting, so Secure Boot must go off first.\n"
        "- The desktop then shows 'Test Mode' and any certificate can sign drivers (HVCI still requires a "
        "signature).\n"
        "- In test-signing mode, eBPFSvc skips the proof-of-verification check unless an HKLM eBPF Parameters "
        "value opts in.\n"
        "- Otherwise a native .sys must carry Microsoft's 'eBPF Verification' certificate: the code-signing EKU "
        "plus EKU 1.3.6.1.4.1.311.133.1."),

    # -- Loading ---------------------------------------------------------------------------------------------------
    Capability(
        "Loading", "libbpf API compatibility",
        "libbpf (v1.8.0) is the reference loader: bpf_object__open and load, bpf_program__attach_*, links, "
        "skeletons. Other loaders exist, such as ebpf-go.",
        "EbpfApi.dll implements a documented libbpf subset, compiled against the upstream libbpf headers.\n"
        "- Covered: bpf_object__open/load/pin/close, bpf_program__attach/attach_xdp/pin, bpf_map__*, "
        "ring_buffer__*, perf_buffer__*, bpf_prog_load, bpf_map_*_elem and batch calls, *_get_next_id, "
        "*_get_fd_by_id, bpf_obj_get/pin/get_info_by_fd, bpf_link_detach.\n"
        "- Source-compatible only, not ABI-compatible: different enum and bpf_cmd values, BPF_OBJ_NAME_LEN 64 "
        "instead of 16, reordered or missing info fields.\n"
        "- v1.0.0-rc1 and v1.7.0 brought behaviour closer to Linux.\n"
        "- ebpf-go has basic Windows support; unsupported calls return ErrNotSupported."),
    Capability(
        "Loading", "bpftool",
        "bpftool v7.8.1 with prog, map, link, cgroup, net, perf, feature, btf, gen (skeletons), struct_ops and "
        "iter; JSON output with -j.",
        "bpftool.exe, built from a Windows fork of bpftool, reports version 0.1 and supports JSON with -j.\n"
        "- prog: show, pin, load, loadall, run. No dump, attach, detach, tracelog or profile.\n"
        "- map: show, dump, update, lookup, getnext, delete, pin, create, peek, push, pop. No event_pipe or "
        "freeze.\n"
        "- link: show, pin, detach.\n"
        "- net: show, attach, detach (XDP).\n"
        "No feature, btf, gen, cgroup, perf, struct_ops or iter commands, and no bpffs."),
    Capability(
        "Loading", "netsh ebpf",
        "None.",
        "The netsh helper ebpfnetsh.dll, registered by the MSI with 'netsh add helper'. Text tables only. "
        "Commands:\n"
        "- add program: filename, type, pinpath, interface, compartment, pinned (none, first or all), execution "
        "(jit or interpret).\n"
        "- delete program; set program: attached, pinpath, interface.\n"
        "- show programs: type, attached, pinned, level, filename, section, id.\n"
        "- show maps, links, pins, processes, sections, disassembly, verification, hash.\n"
        "- pin and unpin for maps and programs."),
    Capability(
        "Loading", "Pinning",
        "The BPF filesystem, normally at /sys/fs/bpf. A pin is a pseudo-file that holds a reference; rm or unlink "
        "removes it, and pins vanish at reboot. Commands: BPF_OBJ_PIN and BPF_OBJ_GET.",
        "No BPF filesystem: pins live in a kernel namespace. The canonical form is BPF:\\my\\pin\\path; "
        "Linux-style /sys/fs/bpf/... and the older /ebpf/global/... are accepted and canonicalized. List pins with "
        "ebpf_get_next_pinned_object_path or 'netsh ebpf show pins'; remove them with ebpf_object_unpin or 'netsh "
        "ebpf unpin'. LIBBPF_PIN_BY_NAME is supported."),
    Capability(
        "Loading", "BTF and CO-RE",
        "Kernel BTF lives at /sys/kernel/btf/vmlinux. libbpf CO-RE relocations let one binary run across kernel "
        "versions. 'bpftool gen skeleton' generates .skel.h loaders.",
        "No CO-RE: there is no kernel BTF to relocate against, and the Windows bpftool is built without BTF and "
        "skeleton support (BPFTOOL_WITHOUT_SKELETONS). BTF inside the ELF is still used for BTF-style map "
        "definitions and debug information."),
    Capability(
        "Loading", "Program files and registration",
        "An ELF .o built with clang -target bpf loads as is; the kernel knows its own program types.",
        "A native .sys (the official route) or an ELF .o (JIT).\n"
        "- Program types, attach types, section names and helper prototypes must be registered in the eBPF store.\n"
        "- The store is HKLM or HKCU\\Software\\eBPF\\Providers, with ProgramData, SectionData and GlobalHelpers "
        "keys; HKCU is read first.\n"
        "- Registration is done by export_program_info.exe (core), xdpbpfexport.exe (XDP), "
        "ntos_ebpf_ext_export_program_info.exe and netevent_ebpf_ext_export_program_info.exe.\n"
        "- eBPFSvc must be running, because it authorizes each native image's hash before the core lets it attach."),

    # -- Events to user space --------------------------------------------------------------------------------------
    Capability(
        "Events to user space", "Ring buffer consumer",
        "libbpf ring_buffer__new, poll and consume, over mmap plus epoll (ring_buffer__epoll_fd), with self-pacing "
        "notifications.",
        "ring_buffer__new, poll and consume, synchronous like Linux since v1.1.0. Alternatively, map the producer "
        "and consumer pages with ebpf_ring_buffer_map_map_buffer and wait on a HANDLE set with "
        "ebpf_map_set_wait_handle; there is no mmap or epoll. The asynchronous callback mode "
        "(EBPF_RINGBUF_FLAG_AUTO_CALLBACK) is deprecated since v1.5.0."),
    Capability(
        "Events to user space", "Perf buffer consumer",
        "libbpf perf_buffer__new and poll, with one buffer per CPU; 'bpftool map event_pipe' for a quick look.",
        "perf_buffer__new, poll, consume, consume_buffer and buffer_cnt; synchronous and attached to all CPUs. The "
        "bpftool port has no event_pipe."),
    Capability(
        "Events to user space", "Debug output (bpf_printk)",
        "bpf_printk writes to the tracefs trace_pipe; 'bpftool prog tracelog' streams it.",
        "bpf_printk goes to ETW (EbpfForWindowsProvider). Capture with 'wpr -start ebpfforwindows.wprp -filemode', "
        "or with 'tracelog -start NAME -guid ebpf-printk.guid -rt' and 'tracefmt' from the WDK. bpftool has no "
        "tracelog here."),

    # -- Privileges ------------------------------------------------------------------------------------------------
    Capability(
        "Privileges", "Load and attach",
        "CAP_BPF (since 5.8) covers loads.\n"
        "- Network types also need CAP_NET_ADMIN: XDP, sched_cls/act, cgroup sock/sock_addr/sockopt/sysctl/device, "
        "sock_ops, sk_skb/sk_msg, netfilter and others.\n"
        "- Tracing types also need CAP_PERFMON: kprobe, tracepoint, perf_event, raw_tp, tracing, LSM, struct_ops.\n"
        "- unprivileged_bpf_disabled defaults to 2 (BPF_UNPRIV_DEFAULT_OFF=y). Even when unprivileged BPF is on, "
        "only SOCKET_FILTER and CGROUP_SKB load without CAP_BPF.\n"
        "- BPF tokens (6.9+) delegate chosen commands and types to a user namespace via bpffs delegate_* options.",
        "Elevated Administrator or LocalSystem for every operation. The eBPFCore device ACL is "
        "D:P(A;;GA;;;<eBPFSvc service SID>)(A;;GA;;;BA)(A;;GA;;;SY); anyone else gets ERROR_ACCESS_DENIED. There "
        "is no capability split and no delegation. Loading a native program also starts a kernel driver for its "
        ".sys."),
    Capability(
        "Privileges", "List and read",
        "Walking IDs (BPF_*_GET_NEXT_ID) and opening by ID (GET_FD_BY_ID) need CAP_SYS_ADMIN; querying cgroup "
        "attachments needs CAP_NET_ADMIN. A pinned object opens by path within bpffs permissions, since "
        "unprivileged_bpf_disabled blocks only program and map creation. unprivileged_bpf_disabled and "
        "bpf_jit_enable are world-readable (0644); bpf_jit_harden, bpf_jit_kallsyms and bpf_jit_limit are "
        "root-only (0600).",
        "The same device ACL applies: listing programs or reading a map also needs elevated Administrator or "
        "SYSTEM."),

    # -- Process attribution ---------------------------------------------------------------------------------------
    Capability(
        "Process attribution", "In the network hooks",
        "Helper access:\n"
        "- Every program type may call bpf_get_current_pid_tgid and uid_gid; they joined the base helpers in 6.10, "
        "and cgroup programs had them before.\n"
        "- bpf_get_current_cgroup_id needs CAP_BPF; bpf_get_current_comm needs CAP_PERFMON.\n"
        "The values mean something only where the hook runs in the calling task: connect4/6, sendmsg4/6, "
        "recvmsg4/6, bind, sock_create. In softirq paths (XDP, tc, cgroup_skb ingress, passive sock_ops) 'current' "
        "is whatever task was interrupted. Robust attribution keys a flow by socket cookie (bpf_get_socket_cookie) "
        "and sk_storage set at connect or sendmsg, or by cgroup id (bpf_skb_cgroup_id).",
        "WFP ALE metadata carries the originating process, inbound too.\n"
        "- sock_addr overrides bpf_get_current_pid_tgid with the WFP process ID (high 32 bits; current thread in "
        "the low bits).\n"
        "- bpf_get_current_logon_id returns the requesting token's AuthenticationId.\n"
        "- bpf_is_current_admin checks that token and returns -1 when there is none, as for some system binds.\n"
        "- sock_ops captures the PID at establishment and keeps it for the delete callback; "
        "bpf_sock_ops_get_flow_id returns the WFP flow handle.\n"
        "- Network hooks give no image path or command line (issue #4775, still open). Join by PID with the "
        "PROCESS hook (bpf_process_get_image_path) or a user-space lookup, minding PID reuse.\n"
        "- XDP has no process context."),
    Capability(
        "Process attribution", "Two-way and one-off connection tracking (firewall use)",
        "- TCP: sock_ops ACTIVE/PASSIVE_ESTABLISHED and STATE_CB for close (observe only); cgroup/connect4/6 gives "
        "a verdict on outbound connections.\n"
        "- UDP and other one-offs: cgroup/sendmsg4/6 per outgoing datagram (process context), cgroup/recvmsg4/6 "
        "per receive, cgroup_skb ingress/egress per packet (cgroup and cookie).\n"
        "- Kernel conntrack: readable from XDP and tc through the kfuncs bpf_xdp_ct_lookup and bpf_skb_ct_lookup; "
        "BPF_PROG_TYPE_NETFILTER sits on netfilter hooks.\n"
        "- The tcp and udp BPF iterators can snapshot existing sockets.",
        "- sock_ops sees both directions plus deletion for any flow WFP tracks (TCP, UDP and others), carries the "
        "PID and flow id, and can block. The catch: only one program per compartment.\n"
        "- sock_addr connect and recv_accept fire once per new remote tuple (TCP connect/accept, first UDP "
        "send/receive) and can reject.\n"
        "- connect_authorization re-runs on WFP reauth.\n"
        "- No per-packet hook apart from XDP on receive. NETEVENT can surface pktmon flow and drop events.\n"
        "- No iterators, so existing connections must be read from user space."),

    # -- Basic functions -------------------------------------------------------------------------------------------
    Capability(
        "Basic functions", "Runtime status and version",
        "Kernel: 'uname -r'. Tools: 'bpftool -j version' (bpftool and libbpf versions, built-in features). "
        "Settings: read /proc/sys/kernel/unprivileged_bpf_disabled and /proc/sys/net/core/bpf_jit_enable. "
        "Ready-checks:\n"
        "- bpffs mounted ('findmnt -t bpf', normally /sys/fs/bpf)\n"
        "- kernel BTF present (/sys/kernel/btf/vmlinux, needed for CO-RE and fentry/LSM)\n"
        "- bpf in the active LSM list (/sys/kernel/security/lsm), if LSM programs matter\n"
        "Rights: No root: only bpf_jit_harden, bpf_jit_kallsyms and bpf_jit_limit are root-only (0600).",
        "Runtime: 'sc.exe query eBPFCore', 'sc.exe query NetEbpfExt', 'sc.exe query eBPFSvc'. All three must run; "
        "native loads need eBPFSvc. Extensions if present: 'xdp', 'ntosebpfext', 'neteventebpfext'. Version: the "
        "DisplayVersion of the 'eBPF for Windows' MSI entry, or the file version of C:\\Program "
        "Files\\ebpf-for-windows\\EbpfApi.dll. Not 'bpftool version': it prints the port's own 0.1 and its bundled "
        "libbpf. Also show what decides whether anything can load:\n"
        "- test signing on or off ('bcdedit /enum {current}', or the 'Test Mode' watermark)\n"
        "- memory integrity (Win32_DeviceGuard SecurityServicesRunning contains 2)\n"
        "Rights: No administrator for the service state and the version; an administrator for bcdedit and for the "
        "Win32_DeviceGuard query, which Microsoft documents as elevated."),
    Capability(
        "Basic functions", "List programs, maps and links",
        "'bpftool -j prog show', 'bpftool -j map show', 'bpftool -j link show'. Attachments: 'bpftool -j net show' "
        "(XDP, tc, tcx and netkit per device) and 'bpftool -j cgroup tree' (cgroup hooks). Library: "
        "bpf_prog_get_next_id, bpf_map_get_next_id, bpf_link_get_next_id, then *_get_fd_by_id and "
        "bpf_obj_get_info_by_fd.\n"
        "Rights: Root: CAP_SYS_ADMIN to walk ids and open by id; cgroup and net queries need CAP_NET_ADMIN.",
        "Text tables: 'netsh ebpf show programs' (ID, pins, links, mode JIT/INTERPRET/NATIVE, type, name), plus "
        "'show maps', 'show links', 'show pins' and 'show processes'. JSON: 'bpftool -j prog show', 'bpftool -j "
        "map show', 'bpftool -j link show' and 'bpftool -j net show' from the Windows port. Library: the same "
        "bpf_*_get_next_id, *_get_fd_by_id and bpf_obj_get_info_by_fd calls, exported by EbpfApi.dll.\n"
        "Rights: An administrator (elevated Administrator or SYSTEM), because of the eBPFCore device ACL."),
    Capability(
        "Basic functions", "Show a program's info",
        "'bpftool -j prog show id N' gives type, tag, name, load time, uid, map ids, BTF id and translated/JIT "
        "sizes; run counts and times appear once BPF stats are enabled. 'bpftool prog dump xlated id N' and 'dump "
        "jited id N' show the instructions. 'bpftool -j link show' shows where it is attached.\n"
        "Rights: Root, to open by id.",
        "'netsh ebpf show programs id=N level=verbose' or 'bpftool -j prog show id N'. Windows bpf_prog_info holds "
        "id, type, name, map ids, type_uuid, attach_type_uuid, pinned_path_count and link_count. A loaded program "
        "cannot be dumped. For files on disk: 'netsh ebpf show sections FILE', 'show disassembly FILE.o "
        "[SECTION]', 'show verification FILE.o' and 'show hash FILE.sys'.\n"
        "Rights: An administrator for loaded programs; the file-only netsh commands run in user mode and probably "
        "need no elevation (not verified)."),
    Capability(
        "Basic functions", "Dump or read a map",
        "- 'bpftool -j map dump id N', formatted through BTF when the map has it.\n"
        "- 'bpftool -j map lookup id N key hex ...' and 'getnext'; 'peek', 'pop' or 'dequeue' for queues and "
        "stacks.\n"
        "- 'bpftool map event_pipe id N' for a perf event array.\n"
        "- Ring buffers through libbpf ring_buffer__poll.\n"
        "- A pinned map opens by path ('pinned /sys/fs/bpf/NAME').\n"
        "Rights: Root by id (CAP_SYS_ADMIN); a pinned map can be read without root if its bpffs file permissions "
        "allow.",
        "- 'bpftool -j map dump id N' and 'map lookup', 'getnext', 'peek', 'pop'; no event_pipe.\n"
        "- netsh can only list maps.\n"
        "- Ring buffers and perf event arrays through ring_buffer__poll and perf_buffer__poll in EbpfApi.dll, or "
        "the mapped-buffer and wait-handle API.\n"
        "- Pinned maps open by BPF:\\ path with bpf_obj_get.\n"
        "Rights: An administrator, because of the device ACL."),
    Capability(
        "Basic functions", "Load and attach a pre-built program",
        "Load: 'bpftool prog load prog.o /sys/fs/bpf/NAME [type T] [pinmaps DIR] [autoattach]', or 'loadall'. Then "
        "attach:\n"
        "- 'bpftool cgroup attach /sys/fs/cgroup connect4 pinned /sys/fs/bpf/NAME [multi]'\n"
        "- 'bpftool net attach xdp|tcx_ingress|tcx_egress pinned /sys/fs/bpf/NAME dev IF'\n"
        "- 'bpftool prog attach' for sk_msg, sk_skb or flow_dissector\n"
        "In code: libbpf bpf_object__open and load, bpf_program__attach_*, and bpf_link__pin so the attachment "
        "outlives the loader.\n"
        "Rights: Root: CAP_BPF plus CAP_NET_ADMIN (network types) or CAP_PERFMON (tracing types).",
        "On a normal system only a native .sys loads. Conditions:\n"
        "- the .sys is test-signed and test signing is on, or it carries Microsoft's eBPF Verification signature\n"
        "- the program type's extension is running and registered in the eBPF store\n"
        "Two ways to run it:\n"
        "- 'netsh ebpf add program filename=prog.sys [pinpath=P] [interface=IF] [compartment=N] "
        "[pinned=none|first|all]' loads and attaches by section name.\n"
        "- 'bpftool prog load prog.sys PINPATH [pinmaps DIR]', then 'netsh ebpf set program id=N attached=SECTION' "
        "(for XDP: 'bpftool net attach xdp id N dev IF').\n"
        "In code: bpf_object__open('prog.sys'), bpf_object__load, then bpf_program__attach or bpf_xdp_attach. A .o "
        "with execution=jit works only where the pre-release JIT feature is installed and HVCI is off.\n"
        "Rights: An administrator (elevated Administrator or SYSTEM), and the load starts a kernel driver for the "
        ".sys."),
    Capability(
        "Basic functions", "Detach and unload",
        "Detach: 'bpftool link detach id N' for link-based attachments, 'bpftool cgroup detach CGROUP TYPE id N', "
        "'bpftool net detach xdp|tcx_ingress dev IF'. A program unloads when its last reference goes: remove its "
        "pins ('rm /sys/fs/bpf/NAME') and close the loader's file descriptors.\n"
        "Rights: Root, or CAP_SYS_ADMIN and CAP_NET_ADMIN.",
        "Detach: 'netsh ebpf set program id=N attached=\"\"' (an empty string detaches), 'bpftool link detach id "
        "N', 'bpftool net detach xdp dev IF'. Unload: 'netsh ebpf delete program id=N' unpins it and drops netsh's "
        "reference, so it unloads once no other references remain. Unpin with 'netsh ebpf unpin program|map ID "
        "[PATH]'. The native .sys module unloads after its programs detach.\n"
        "Rights: An administrator (elevated Administrator or SYSTEM)."),
    Capability(
        "Basic functions", "Feature probe",
        "- 'bpftool -j feature probe kernel [full]' reports bpf() availability, JIT and hardening state, kernel "
        "config, and the program types, map types and helpers each program type supports.\n"
        "- 'bpftool feature probe dev IF' checks a device for offload.\n"
        "- 'bpftool feature probe unprivileged' gives the non-root view.\n"
        "- 'bpftool feature list_builtins prog_types|map_types|attach_types|link_types|helpers' lists what bpftool "
        "knows without probing.\n"
        "- In code: libbpf_probe_bpf_prog_type, _map_type and _helper.\n"
        "Rights: Root for a full probe; 'unprivileged' and 'list_builtins' need no root.",
        "There is no 'bpftool feature' (it is Linux-only in the port) and no probe calls in the documented libbpf "
        "subset. Equivalent checks:\n"
        "- Read the eBPF store HKLM\\Software\\eBPF\\Providers, and HKCU\\Software\\eBPF\\Providers, which is read "
        "first. ProgramData holds registered program types with their helper prototypes, SectionData maps section "
        "names to program and attach types, and GlobalHelpers lists the global helpers.\n"
        "- Check which extension services run: NetEbpfExt, xdp, ntosebpfext, neteventebpfext.\n"
        "- Report the execution modes actually usable and the signing mode. Native always works; JIT needs the JIT "
        "component, eBPFSvc and HVCI off.\n"
        "- The type numbers themselves are compile-time constants (ebpf_structs.h).\n"
        "- 'netsh ebpf show verification FILE.o' checks one program against the installed program info.\n"
        "Rights: No administrator for reading the store and the service state (HKLM\\Software is normally readable "
        "by users; not checked for this key); an administrator for the signing and HVCI status (bcdedit, "
        "Win32_DeviceGuard)."),
    Capability(
        "Basic functions", "Watch events (ring buffer, perf buffer, printk)",
        "libbpf ring_buffer__new and ring_buffer__poll (mmap and epoll), or perf_buffer__new and "
        "perf_buffer__poll. 'bpftool map event_pipe id N' for perf arrays. 'bpftool prog tracelog' streams "
        "bpf_printk output from trace_pipe.\n"
        "Rights: Root: opening a map by id needs CAP_SYS_ADMIN, and tracefs is root-only by default.",
        "ring_buffer__new with ring_buffer__poll or consume, or perf_buffer__new with perf_buffer__poll or "
        "consume, in EbpfApi.dll; synchronous, like Linux. Alternatively, map the ring with "
        "ebpf_ring_buffer_map_map_buffer and wait on a handle set with ebpf_map_set_wait_handle. bpf_printk lands "
        "in ETW. Capture it with:\n"
        "- 'wpr -start \"%ProgramFiles%\\ebpf-for-windows\\ebpfforwindows.wprp\" -filemode'\n"
        "- or 'tracelog -start NAME -guid ebpf-printk.guid -rt' plus 'tracefmt -rt NAME -displayonly' (WDK tools)\n"
        "Rights: An administrator for maps (device ACL); ETW trace sessions also need Administrator or membership "
        "in Performance Log Users."),
    Capability(
        "Basic functions", "Check a program file before loading",
        "The verifier only runs in the kernel at load time. 'bpftool -d prog load ...' prints the libbpf and "
        "verifier logs, but it does load the program. Offline you can only inspect: 'llvm-objdump -d prog.o', "
        "'bpftool btf dump file prog.o'. PREVAIL also builds on Linux as a user-space check.\n"
        "Rights: Loading needs root; inspecting a file does not.",
        "Offline verification works:\n"
        "- 'netsh ebpf show verification FILE.o [SECTION]' runs PREVAIL in user mode.\n"
        "- 'netsh ebpf show sections FILE' and 'show disassembly FILE.o' inspect the file.\n"
        "- 'show hash FILE.sys' prints the hash embedded in a native image.\n"
        "bpf2c, through Convert-BpfToNative.ps1, builds the .sys.\n"
        "Rights: The file commands run in user mode and probably need no elevation (not verified)."),
)

AREAS: tuple[str, ...] = tuple(dict.fromkeys(c.area for c in CAPABILITIES))


def rows(sources=None) -> list[dict]:
    """Every row as a dict, in order (what Runtime.capabilities() returns). `sources`, the plugin's links keyed by
    (area, item), adds each row's "source" (blank where it names none); without it the rows carry no source."""
    out = [c.as_dict() for c in CAPABILITIES]
    if sources is not None:
        for row in out:
            row["source"] = sources.get((row["area"], row["item"]), "")
    return out


def by_area(sources=None) -> list[dict]:
    """The rows grouped by area, in order: [{"area", "rows": [row]}]."""
    groups: dict[str, list[dict]] = {area: [] for area in AREAS}
    for row in rows(sources):
        groups[row["area"]].append(row)
    return [{"area": area, "rows": group} for area, group in groups.items()]


def functions(sources=None) -> list[dict]:
    """The basic functions only: how each is done on Linux and on Windows, and the rights it needs."""
    return [row for row in rows(sources) if row["area"] == FUNCTIONS_AREA]
