"""A real-time ETW consumer in ctypes (the design, 2026-11-14: "ETW for process, file, registry and net
attribution"; the research of the same day: this PC's account is in Performance Log Users, so a process can
start and consume a real-time session without UAC through the modern system-provider path, not the legacy NT
Kernel Logger). Built on advapi32 and tdh alone (kernel32 and ntdll only to tell whether a session's owner is
alive), no third-party package, to match the firewall plugins' direct-syscall style and to run on this venv's
Python 3.15.

What it does: StartTraceW opens a private real-time session named `Liminal-<tag>-<pid>-<ctime>-<n>` (the owner's
pid and creation time, and a per-process counter) with EVENT_TRACE_REAL_TIME_MODE; EnableTraceEx2 turns on the
Microsoft-Windows-Kernel-Process, -Kernel-File, -Kernel-Network and -Kernel-Registry manifest providers (these may
be enabled in an ordinary real-time session that Performance Log Users may start unelevated, unlike the single
global NT Kernel Logger); OpenTraceW
registers a record callback with PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; ProcessTrace
blocks one daemon thread and delivers records; TdhGetEventInformation and TdhGetProperty decode only the few
properties used (process and parent ids, image and file names, the address, ports and size of a connection, a
registry key). Records land in a bounded queue that drops the oldest and counts the drops. The session is torn
down reliably: ControlTraceW STOP on stop() and in an atexit hook; and a session that a killed process left behind
(no stop, no atexit ran in it) is stopped by `reclaim_stale_sessions()`, which a plugin calls at attach and every
start() runs again.

Nothing here loads a Windows library at import, so the module imports on Linux too (the suite runs there); the
advapi32 and tdh function tables are built lazily on start(), and a test injects stand-ins for both. The real
ctypes structures and the property decode are checked by hand on a scratch platform, as the design says; the
tests drive the callback with synthetic records through the injected tables."""
from __future__ import annotations

import atexit
import collections
import ctypes
import itertools
import os
import re
import socket
import sys
import threading
import time
import weakref
from dataclasses import dataclass, field

# -- what the session asks of Windows -----------------------------------------------------------------------

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_CONTROL_CODE_CAPTURE_STATE = 2  # ask the provider to rundown its current state (event 15 per running process)
EVENT_TRACE_CONTROL_QUERY = 0
EVENT_TRACE_CONTROL_STOP = 1
WNODE_FLAG_TRACED_GUID = 0x00020000
WNODE_CLIENT_CONTEXT_QPC = 1
TRACE_LEVEL_INFORMATION = 4
TRACE_LEVEL_VERBOSE = 5
INVALID_PROCESSTRACE_HANDLE = (1 << 64) - 1
ERROR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_ALREADY_EXISTS = 183
# ERROR_MORE_DATA: from a ControlTraceW STOP, the session is stopped and only its properties did not fit; from
# QueryAllTracesW, more sessions run than there are slots, and the slots given are still filled.
ERROR_MORE_DATA = 234
ERROR_NOACCESS = 998
ERROR_WMI_INSTANCE_NOT_FOUND = 4201
# ProcessTrace's failure statuses by name, for a consumer's words when it ends by itself
STATUS_NAMES = {ERROR_ACCESS_DENIED: "ERROR_ACCESS_DENIED", ERROR_INVALID_HANDLE: "ERROR_INVALID_HANDLE",
                ERROR_INVALID_PARAMETER: "ERROR_INVALID_PARAMETER", ERROR_NOACCESS: "ERROR_NOACCESS"}
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYSTEM_PROCESS_INFORMATION = 5            # NtQuerySystemInformation's class for the system's process list
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004  # the process list did not fit the buffer
PROCESS_LIST_MAX = 64 << 20               # bytes the process list may take at most (bounded RAM; ~1 MB here)

# TDH property in-types we tell apart (the rest decode the same): a string is UTF-16 unless the schema says ANSI.
TDH_INTYPE_UNICODESTRING = 1
TDH_INTYPE_ANSISTRING = 2
PROPERTY_STRUCT = 0x1  # EVENT_PROPERTY_INFO.Flags: a struct member, skipped when reading the schema

PERFORMANCE_LOG_USERS_SID = "S-1-5-32-559"  # the built-in group that may start real-time sessions unelevated

DEFAULT_CAPACITY = 8192  # records kept before the oldest is dropped (bounded RAM)
MAX_STRING = 2048        # a decoded string is truncated here (one record carries up to ~64 KB of strings otherwise)
SCHEMA_CACHE_MAX = 256   # per-(provider, event id, version) property schemas kept, so the decode is read once
MAX_SCHEMA_PROPS = 256   # properties read from one event template at most (bounded work on an odd schema)

# The four kernel providers, each by its well-known GUID (confirmed against the 2026-11-14 research and Microsoft's
# manifests) and a MatchAnyKeyword that keeps the volume to the events the scope needs:
#   process  WINEVENT_KEYWORD_PROCESS 0x10 | WINEVENT_KEYWORD_IMAGE 0x40 (start/stop and image load);
#   file     KERNEL_FILE_KEYWORD_CREATE 0x80 (create/open, not the noisy read/write);
#   network  KERNEL_NETWORK_KEYWORD_IPV4 0x10 | IPV6 0x20 (TCP/UDP with pid, size and addresses);
#   registry 0 (every registry operation at the level; its keywords are per-operation).
PROVIDERS: dict[str, tuple[str, int]] = {
    "process": ("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}", 0x10 | 0x40),
    "file": ("{EDD08927-9CC4-4E65-B970-C2560FB5C289}", 0x80),
    "network": ("{7DD42A49-5329-4832-8DFD-43D979153A88}", 0x10 | 0x20),
    "registry": ("{70EB4F03-C1DE-4F73-A051-33D13D5413BD}", 0x00),
}

# The properties pulled per provider (only these are decoded); names are the manifests' own.
_FIELDS: dict[str, tuple[str, ...]] = {
    "process": ("ProcessID", "ProcessId", "ParentProcessID", "ParentProcessId", "ImageName", "ImageFileName",
                "CommandLine", "ExitCode"),
    "file": ("FileName", "ProcessID", "ProcessId"),
    "network": ("PID", "size", "Size", "daddr", "saddr", "dport", "sport"),
    "registry": ("KeyName", "RelativeName", "ValueName", "ProcessID", "ProcessId", "Status"),
}
_STRINGS = frozenset({"ImageName", "ImageFileName", "FileName", "CommandLine", "KeyName", "RelativeName", "ValueName"})
_ADDRS = frozenset({"daddr", "saddr"})
_PORTS = frozenset({"dport", "sport"})


class EtwError(Exception):
    """An ETW session could not be started, enabled, opened or stopped (Windows' own code or words)."""


@dataclass(frozen=True)
class EtwRecord:
    """One decoded ETW event: when it happened, which provider raised it, its id and opcode, the process it
    belongs to, and the handful of properties decoded (`props`)."""
    at: float
    provider: str  # "process" | "file" | "network" | "registry"
    event_id: int
    opcode: int
    pid: int
    props: dict = field(default_factory=dict)


# -- GUID and time ------------------------------------------------------------------------------------------

class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8)]


def guid_from_string(text: str) -> GUID:
    """A `{8-4-4-4-12}` string as a GUID structure."""
    a, b, c, d, e = text.strip("{}").split("-")
    g = GUID()
    g.Data1, g.Data2, g.Data3 = int(a, 16), int(b, 16), int(c, 16)
    rest = bytes.fromhex(d + e)
    for i in range(8):
        g.Data4[i] = rest[i]
    return g


def guid_to_string(g: GUID) -> str:
    """A GUID structure as a `{8-4-4-4-12}` string, upper-case."""
    return "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" % (
        g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])


_PROVIDER_BY_GUID = {guid.upper(): key for key, (guid, _kw) in PROVIDERS.items()}


def _filetime_epoch(ft: int) -> float:
    """A FILETIME (100 ns ticks since 1601) as seconds since the Unix epoch."""
    return ft / 1e7 - 11644473600.0


def _decode_ansi(raw: bytes) -> str:
    """ANSI (system code page) bytes to text, NUL-terminated. `mbcs` is Windows-only, so fall back to cp1252 and
    latin-1 for the suite's Linux run; ASCII (the common ImageName) decodes the same under any of them."""
    text = bytes(raw).split(b"\x00", 1)[0]
    for codec in ("mbcs", "cp1252", "latin-1"):
        try:
            return text.decode(codec, "replace")
        except LookupError:
            continue
    return text.decode("latin-1", "replace")


def _interpret(name: str, raw: bytes, in_type=None):
    """One property's raw bytes as the value the scope wants. `in_type` is the schema's TDH in-type when known: a
    string field marked win:AnsiString (e.g. ProcessStop's ImageName) is decoded as ANSI, not UTF-16."""
    if name in _STRINGS:
        if in_type == TDH_INTYPE_ANSISTRING:
            text = _decode_ansi(raw)
        else:
            text = bytes(raw).decode("utf-16-le", "replace").split("\x00", 1)[0]
        return text[:MAX_STRING]
    if name in _ADDRS:
        # A 16-byte field is an IPv6 address (always win:Binary length 16 here), a 4-byte field is IPv4. The old
        # "all-zero tail means IPv4" test misread e.g. 2001:db8:: as an IPv4 address.
        if len(raw) >= 16:
            return socket.inet_ntop(socket.AF_INET6, bytes(raw[:16]))
        if len(raw) >= 4:
            return socket.inet_ntop(socket.AF_INET, bytes(raw[:4]))
        return None
    if name in _PORTS:
        return socket.ntohs(int.from_bytes(raw[:2], "little")) if len(raw) >= 2 else None
    return int.from_bytes(raw[:8] if len(raw) >= 8 else raw, "little") if raw else None


# -- the real ctypes structures (checked by hand on a scratch platform) -------------------------------------

class _EventTraceProperties(ctypes.Structure):
    """WNODE_HEADER followed by EVENT_TRACE_PROPERTIES; the session name is written after this structure, at
    LoggerNameOffset."""
    _fields_ = [
        ("BufferSize", ctypes.c_uint32), ("ProviderId", ctypes.c_uint32), ("HistoricalContext", ctypes.c_uint64),
        ("TimeStamp", ctypes.c_int64), ("Guid", GUID), ("ClientContext", ctypes.c_uint32), ("Flags", ctypes.c_uint32),
        ("BufferSizeKB", ctypes.c_uint32), ("MinimumBuffers", ctypes.c_uint32), ("MaximumBuffers", ctypes.c_uint32),
        ("MaximumFileSize", ctypes.c_uint32), ("LogFileMode", ctypes.c_uint32), ("FlushTimer", ctypes.c_uint32),
        ("EnableFlags", ctypes.c_uint32), ("AgeLimit", ctypes.c_int32), ("NumberOfBuffers", ctypes.c_uint32),
        ("FreeBuffers", ctypes.c_uint32), ("EventsLost", ctypes.c_uint32), ("BuffersWritten", ctypes.c_uint32),
        ("LogBuffersLost", ctypes.c_uint32), ("RealTimeBuffersLost", ctypes.c_uint32),
        ("LoggerThreadId", ctypes.c_void_p), ("LogFileNameOffset", ctypes.c_uint32),
        ("LoggerNameOffset", ctypes.c_uint32),
    ]


class _EventDescriptor(ctypes.Structure):
    _fields_ = [("Id", ctypes.c_uint16), ("Version", ctypes.c_ubyte), ("Channel", ctypes.c_ubyte),
                ("Level", ctypes.c_ubyte), ("Opcode", ctypes.c_ubyte), ("Task", ctypes.c_uint16),
                ("Keyword", ctypes.c_uint64)]


class _EventHeader(ctypes.Structure):
    _fields_ = [("Size", ctypes.c_uint16), ("HeaderType", ctypes.c_uint16), ("Flags", ctypes.c_uint16),
                ("EventProperty", ctypes.c_uint16), ("ThreadId", ctypes.c_uint32), ("ProcessId", ctypes.c_uint32),
                ("TimeStamp", ctypes.c_int64), ("ProviderId", GUID), ("EventDescriptor", _EventDescriptor),
                ("ProcessorTime", ctypes.c_uint64), ("ActivityId", GUID)]


class _EtwBufferContext(ctypes.Structure):
    _fields_ = [("ProcessorNumber", ctypes.c_ubyte), ("Alignment", ctypes.c_ubyte), ("LoggerId", ctypes.c_uint16)]


class _EventRecord(ctypes.Structure):
    _fields_ = [("EventHeader", _EventHeader), ("BufferContext", _EtwBufferContext),
                ("ExtendedDataCount", ctypes.c_uint16), ("UserDataLength", ctypes.c_uint16),
                ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p), ("UserContext", ctypes.c_void_p)]


class _EventTrace(ctypes.Structure):
    """EVENT_TRACE: an output field of EVENT_TRACE_LOGFILEW; only its size (88 bytes on x64) matters to us."""
    _fields_ = [("Header", _EventHeader), ("_pad", ctypes.c_ubyte * 8)]


class _TraceLogfileHeader(ctypes.Structure):
    """TRACE_LOGFILE_HEADER: an output field; only its size (280 bytes on x64) matters to us (TimeZone is kept
    opaque)."""
    _fields_ = [
        ("BufferSize", ctypes.c_uint32), ("Version", ctypes.c_uint32), ("ProviderVersion", ctypes.c_uint32),
        ("NumberOfProcessors", ctypes.c_uint32), ("EndTime", ctypes.c_int64), ("TimerResolution", ctypes.c_uint32),
        ("MaximumFileSize", ctypes.c_uint32), ("LogFileMode", ctypes.c_uint32), ("BuffersWritten", ctypes.c_uint32),
        ("LogInstanceGuid", GUID), ("LoggerName", ctypes.c_void_p), ("LogFileName", ctypes.c_void_p),
        ("TimeZone", ctypes.c_byte * 172), ("BootTime", ctypes.c_int64), ("PerfFreq", ctypes.c_int64),
        ("StartTime", ctypes.c_int64), ("ReservedFlags", ctypes.c_uint32), ("BuffersLost", ctypes.c_uint32),
    ]


class _EventTraceLogfile(ctypes.Structure):
    _fields_ = [
        ("LogFileName", ctypes.c_wchar_p), ("LoggerName", ctypes.c_wchar_p), ("CurrentTime", ctypes.c_int64),
        ("BuffersRead", ctypes.c_uint32), ("ProcessTraceMode", ctypes.c_uint32), ("CurrentEvent", _EventTrace),
        ("LogfileHeader", _TraceLogfileHeader), ("BufferCallback", ctypes.c_void_p), ("BufferSize", ctypes.c_uint32),
        ("Filled", ctypes.c_uint32), ("EventsLost", ctypes.c_uint32), ("EventRecordCallback", ctypes.c_void_p),
        ("IsKernelTrace", ctypes.c_uint32), ("Context", ctypes.c_void_p),
    ]


class _PropertyDataDescriptor(ctypes.Structure):
    _fields_ = [("PropertyName", ctypes.c_uint64), ("ArrayIndex", ctypes.c_uint32), ("Reserved", ctypes.c_uint32)]


class _TraceEventInfo(ctypes.Structure):
    """The fixed head of TRACE_EVENT_INFO (x64); the EVENT_PROPERTY_INFO array follows it. Only PropertyCount and
    the array are read, to learn each property's in-type. Measured by hand on a scratch platform."""
    _fields_ = [
        ("ProviderGuid", GUID), ("EventGuid", GUID), ("EventDescriptor", _EventDescriptor),
        ("DecodingSource", ctypes.c_uint32), ("ProviderNameOffset", ctypes.c_uint32),
        ("LevelNameOffset", ctypes.c_uint32), ("ChannelNameOffset", ctypes.c_uint32),
        ("KeywordsNameOffset", ctypes.c_uint32), ("TaskNameOffset", ctypes.c_uint32),
        ("OpcodeNameOffset", ctypes.c_uint32), ("EventMessageOffset", ctypes.c_uint32),
        ("ProviderMessageOffset", ctypes.c_uint32), ("BinaryXMLOffset", ctypes.c_uint32),
        ("BinaryXMLSize", ctypes.c_uint32), ("EventNameOffset", ctypes.c_uint32),
        ("EventAttributesOffset", ctypes.c_uint32), ("PropertyCount", ctypes.c_uint32),
        ("TopLevelPropertyCount", ctypes.c_uint32), ("Flags", ctypes.c_uint32),
    ]


class _EventPropertyInfo(ctypes.Structure):
    """One EVENT_PROPERTY_INFO (x64, 24 bytes): its flags, the offset of its name, and its in/out types. The three
    SDK unions overlay the same bytes, so the non-struct view (InType/OutType/MapNameOffset) is enough here."""
    _fields_ = [("Flags", ctypes.c_uint32), ("NameOffset", ctypes.c_uint32),
                ("InType", ctypes.c_uint16), ("OutType", ctypes.c_uint16), ("MapNameOffset", ctypes.c_uint32),
                ("count", ctypes.c_uint16), ("length", ctypes.c_uint16), ("Tags", ctypes.c_uint32)]


_TRACE_EVENT_INFO_HEAD = ctypes.sizeof(_TraceEventInfo)
_EVENT_PROPERTY_INFO_SIZE = ctypes.sizeof(_EventPropertyInfo)


def _properties_buffer(session: str, mode: int):
    """A zeroed EVENT_TRACE_PROPERTIES buffer with the session name written after it."""
    name = ctypes.create_unicode_buffer(session)
    size = ctypes.sizeof(_EventTraceProperties) + ctypes.sizeof(name)
    buf = (ctypes.c_byte * size)()
    props = ctypes.cast(buf, ctypes.POINTER(_EventTraceProperties))
    p = props.contents
    p.BufferSize = size
    p.Flags = WNODE_FLAG_TRACED_GUID
    p.ClientContext = WNODE_CLIENT_CONTEXT_QPC
    p.LogFileMode = mode
    p.FlushTimer = 1  # flush real-time buffers every second explicitly, so a flow's record is not held back further
    p.LoggerNameOffset = ctypes.sizeof(_EventTraceProperties)
    ctypes.memmove(ctypes.addressof(buf) + ctypes.sizeof(_EventTraceProperties), name, ctypes.sizeof(name))
    return buf, props


# -- advapi32 and tdh, the function tables start() uses (stand-ins injected in tests) ------------------------

class WinAdvapi32:
    """The trace-control calls over advapi32.dll (Windows only)."""

    def __init__(self):
        if sys.platform != "win32":
            raise EtwError("ETW is a Windows facility; it is not available here")
        self._lib = ctypes.WinDLL("advapi32", use_last_error=True)
        self._cb = None  # the live callback, kept from the garbage collector while a trace is open
        self._logfile = None
        self._lib.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_wchar_p,
                                          ctypes.POINTER(_EventTraceProperties)]
        self._lib.StartTraceW.restype = ctypes.c_uint32
        self._lib.EnableTraceEx2.argtypes = [ctypes.c_uint64, ctypes.POINTER(GUID), ctypes.c_uint32, ctypes.c_ubyte,
                                             ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p]
        self._lib.EnableTraceEx2.restype = ctypes.c_uint32
        self._lib.OpenTraceW.argtypes = [ctypes.POINTER(_EventTraceLogfile)]
        self._lib.OpenTraceW.restype = ctypes.c_uint64
        self._lib.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32, ctypes.c_void_p,
                                           ctypes.c_void_p]
        self._lib.ProcessTrace.restype = ctypes.c_uint32
        self._lib.ControlTraceW.argtypes = [ctypes.c_uint64, ctypes.c_wchar_p,
                                            ctypes.POINTER(_EventTraceProperties), ctypes.c_uint32]
        self._lib.ControlTraceW.restype = ctypes.c_uint32
        self._lib.QueryAllTracesW.argtypes = [ctypes.POINTER(ctypes.POINTER(_EventTraceProperties)),
                                              ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        self._lib.QueryAllTracesW.restype = ctypes.c_uint32
        self._lib.CloseTrace.argtypes = [ctypes.c_uint64]
        self._lib.CloseTrace.restype = ctypes.c_uint32

    def start_trace(self, session: str, mode: int) -> int:
        buf, props = _properties_buffer(session, mode)
        handle = ctypes.c_uint64(0)
        status = self._lib.StartTraceW(ctypes.byref(handle), session, props)
        if status == ERROR_ALREADY_EXISTS:  # a stale session of ours: stop it and try once more
            self.control_stop(session)
            buf, props = _properties_buffer(session, mode)
            handle = ctypes.c_uint64(0)
            status = self._lib.StartTraceW(ctypes.byref(handle), session, props)
        if status != ERROR_SUCCESS:
            raise EtwError(f"StartTraceW failed ({status}) for session {session}")
        return handle.value

    def enable_trace(self, control: int, guid: str, level: int, keywords: int) -> int:
        g = guid_from_string(guid)
        status = self._lib.EnableTraceEx2(control, ctypes.byref(g), EVENT_CONTROL_CODE_ENABLE_PROVIDER, level,
                                          keywords, 0, 0, None)
        if status != ERROR_SUCCESS:
            raise EtwError(f"EnableTraceEx2 failed ({status}) for provider {guid}")
        return status

    def capture_state(self, control: int, guid: str) -> int:
        """Ask a provider already enabled on this session to rundown its current state, so a process running before
        the watch started is enumerated (Kernel-Process event 15). Best effort: the caller ignores a failure."""
        g = guid_from_string(guid)
        return self._lib.EnableTraceEx2(control, ctypes.byref(g), EVENT_CONTROL_CODE_CAPTURE_STATE, 0, 0, 0, 0, None)

    def query_all_traces(self) -> list[str]:
        """The names of the real-time sessions running on this machine, so the stale ones of ours can be reclaimed.
        Best effort: [] when the query cannot be made or nothing is running."""
        maximum = 64  # Windows' logger slots
        name_room = 1024  # wide chars reserved after each struct for the logger and log-file names
        unit = ctypes.sizeof(_EventTraceProperties) + 2 * 2 * name_room
        buffers = [(ctypes.c_byte * unit)() for _ in range(maximum)]
        array = (ctypes.POINTER(_EventTraceProperties) * maximum)()
        for i, buf in enumerate(buffers):
            p = ctypes.cast(buf, ctypes.POINTER(_EventTraceProperties))
            p.contents.BufferSize = unit
            p.contents.LoggerNameOffset = ctypes.sizeof(_EventTraceProperties)
            p.contents.LogFileNameOffset = ctypes.sizeof(_EventTraceProperties) + 2 * name_room
            array[i] = p
        count = ctypes.c_uint32(0)
        status = self._lib.QueryAllTracesW(array, maximum, ctypes.byref(count))
        if status not in (ERROR_SUCCESS, ERROR_MORE_DATA):  # MORE_DATA (a raised EtwMaxLoggers): read the slots filled
            return []
        names = []
        for i in range(min(count.value, maximum)):
            offset = array[i].contents.LoggerNameOffset or ctypes.sizeof(_EventTraceProperties)
            name = ctypes.wstring_at(ctypes.addressof(buffers[i]) + offset)
            if name:
                names.append(name)
        return names

    def query_stats(self, session: str) -> dict:
        """ETW's own loss counters for a running session (ControlTraceW QUERY). {} when it cannot be read."""
        _buf, props = _properties_buffer(session, 0)
        if self._lib.ControlTraceW(0, session, props, EVENT_TRACE_CONTROL_QUERY) != ERROR_SUCCESS:
            return {}
        p = props.contents
        return {"events_lost": int(p.EventsLost), "rt_buffers_lost": int(p.RealTimeBuffersLost),
                "buffers_written": int(p.BuffersWritten)}

    def open_trace(self, session: str, callback) -> int:
        proto = ctypes.WINFUNCTYPE(None, ctypes.POINTER(_EventRecord))
        self._cb = proto(lambda record: callback(record))
        logfile = _EventTraceLogfile()
        logfile.LoggerName = session
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.EventRecordCallback = ctypes.cast(self._cb, ctypes.c_void_p)
        self._logfile = logfile
        handle = self._lib.OpenTraceW(ctypes.byref(logfile))
        if handle == INVALID_PROCESSTRACE_HANDLE:
            raise EtwError(f"OpenTraceW failed ({ctypes.get_last_error()}) for session {session}")
        return handle

    def process_trace(self, trace: int) -> int:
        handles = (ctypes.c_uint64 * 1)(trace)
        return self._lib.ProcessTrace(handles, 1, None, None)

    def control_stop(self, session: str) -> int:
        _buf, props = _properties_buffer(session, 0)
        return self._lib.ControlTraceW(0, session, props, EVENT_TRACE_CONTROL_STOP)

    def close_trace(self, trace: int) -> int:
        return self._lib.CloseTrace(trace)


class WinTdh:
    """The property decode over tdh.dll (Windows only): TdhGetEventInformation gives each property's in-type (read
    once per event id/version and cached), then TdhGetPropertySize and TdhGetProperty pull each named property's
    bytes. Knowing the schema lets a string marked win:AnsiString decode as ANSI, and lets a property absent from
    the template be skipped without a TDH call (a busy registry or network record stays cheap)."""

    def __init__(self):
        if sys.platform != "win32":
            raise EtwError("ETW is a Windows facility; it is not available here")
        self._lib = ctypes.WinDLL("tdh", use_last_error=True)
        self._schema: dict = {}  # (provider guid, event id, version) -> {property name: in-type}; {} means unknown
        self._lib.TdhGetEventInformation.argtypes = [ctypes.POINTER(_EventRecord), ctypes.c_uint32, ctypes.c_void_p,
                                                     ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        self._lib.TdhGetEventInformation.restype = ctypes.c_uint32
        self._lib.TdhGetPropertySize.argtypes = [ctypes.POINTER(_EventRecord), ctypes.c_uint32, ctypes.c_void_p,
                                                 ctypes.c_uint32, ctypes.POINTER(_PropertyDataDescriptor),
                                                 ctypes.POINTER(ctypes.c_uint32)]
        self._lib.TdhGetPropertySize.restype = ctypes.c_uint32
        self._lib.TdhGetProperty.argtypes = [ctypes.POINTER(_EventRecord), ctypes.c_uint32, ctypes.c_void_p,
                                             ctypes.c_uint32, ctypes.POINTER(_PropertyDataDescriptor),
                                             ctypes.c_uint32, ctypes.POINTER(ctypes.c_byte)]
        self._lib.TdhGetProperty.restype = ctypes.c_uint32

    def decode(self, record) -> EtwRecord | None:
        try:
            header = record.contents.EventHeader
        except (AttributeError, ValueError):
            return None
        key = _PROVIDER_BY_GUID.get(guid_to_string(header.ProviderId))
        if key is None:
            return None
        schema = self._schema_for(record, header)
        props: dict = {}
        for name in _FIELDS.get(key, ()):
            if schema and name not in schema:  # not a property of this event's template: no TDH call wasted on it
                continue
            raw = self._property(record, name)
            if raw is None:
                continue
            value = _interpret(name, raw, schema.get(name) if schema else None)
            if value is not None:
                props[name] = value
        return EtwRecord(at=_filetime_epoch(header.TimeStamp), provider=key, event_id=header.EventDescriptor.Id,
                         opcode=header.EventDescriptor.Opcode, pid=header.ProcessId, props=props)

    def _schema_for(self, record, header) -> dict:
        """The {property name: in-type} map for this event, cached per (provider, id, version). An empty map means
        the schema could not be read; the caller then probes every listed field as before (never worse)."""
        cache_key = (guid_to_string(header.ProviderId), int(header.EventDescriptor.Id),
                     int(header.EventDescriptor.Version))
        cached = self._schema.get(cache_key)
        if cached is not None:
            return cached
        try:
            schema = self._read_schema(record)
        except Exception:  # noqa: BLE001 - an odd template never breaks a record; fall back to probing all fields
            schema = {}
        if len(self._schema) < SCHEMA_CACHE_MAX:
            self._schema[cache_key] = schema
        return schema

    def _read_schema(self, record) -> dict:
        size = ctypes.c_uint32(0)
        status = self._lib.TdhGetEventInformation(record, 0, None, None, ctypes.byref(size))
        if status not in (ERROR_SUCCESS, ERROR_INSUFFICIENT_BUFFER) or size.value < _TRACE_EVENT_INFO_HEAD:
            return {}
        buf = (ctypes.c_byte * size.value)()
        if self._lib.TdhGetEventInformation(record, 0, None, buf, ctypes.byref(size)) != ERROR_SUCCESS:
            return {}
        info = ctypes.cast(buf, ctypes.POINTER(_TraceEventInfo)).contents
        base = ctypes.addressof(buf)
        out: dict = {}
        offset = _TRACE_EVENT_INFO_HEAD
        for _ in range(min(int(info.PropertyCount), MAX_SCHEMA_PROPS)):
            if offset + _EVENT_PROPERTY_INFO_SIZE > size.value:
                break
            pi = ctypes.cast(base + offset, ctypes.POINTER(_EventPropertyInfo)).contents
            offset += _EVENT_PROPERTY_INFO_SIZE
            if pi.Flags & PROPERTY_STRUCT:  # a struct member has no in-type of its own; skip it
                continue
            name_off = int(pi.NameOffset)
            if 0 < name_off < size.value:
                name = ctypes.wstring_at(base + name_off)
                if name:
                    out[name] = int(pi.InType)
        return out

    def _property(self, record, name: str) -> bytes | None:
        wname = ctypes.c_wchar_p(name)
        desc = _PropertyDataDescriptor()
        desc.PropertyName = ctypes.cast(wname, ctypes.c_void_p).value or 0
        desc.ArrayIndex = 0
        size = ctypes.c_uint32(0)
        if self._lib.TdhGetPropertySize(record, 0, None, 1, ctypes.byref(desc), ctypes.byref(size)) != ERROR_SUCCESS:
            return None
        if size.value == 0:
            return None
        buf = (ctypes.c_byte * size.value)()
        if self._lib.TdhGetProperty(record, 0, None, 1, ctypes.byref(desc), size.value, buf) != ERROR_SUCCESS:
            return None
        return bytes(bytearray(buf))


# -- whether a real-time session can be started here --------------------------------------------------------

def _is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - not known: treat as not elevated
        return False


def _in_performance_log_users() -> bool:
    """Whether this token is an enabled member of the built-in Performance Log Users group (a read-only check)."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertStringSidToSidW.restype = ctypes.c_int
    adv.CheckTokenMembership.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    adv.CheckTokenMembership.restype = ctypes.c_int
    sid = ctypes.c_void_p()
    if not adv.ConvertStringSidToSidW(PERFORMANCE_LOG_USERS_SID, ctypes.byref(sid)):
        return False
    try:
        member = ctypes.c_int(0)
        if not adv.CheckTokenMembership(None, sid, ctypes.byref(member)):
            return False
        return bool(member.value)
    finally:
        ctypes.windll.kernel32.LocalFree(sid)


def _token_probe() -> tuple[bool, bool]:
    """(elevated, in Performance Log Users) read from this process's token."""
    return _is_elevated(), _in_performance_log_users()


def available(probe=None) -> tuple[bool, str]:
    """Whether an ETW real-time session can be started here, and why not. `probe`: a test's stand-in returning
    (elevated, in Performance Log Users)."""
    if probe is None:
        if sys.platform != "win32":
            return False, "ETW is a Windows facility; this is not Windows"
        probe = _token_probe
    try:
        elevated, in_group = probe()
    except Exception as e:  # noqa: BLE001 - the token could not be read
        return False, f"the access token could not be read: {e}"
    if elevated:
        return True, "this process is elevated"
    if in_group:
        return True, "in Performance Log Users: a real-time session can be started unelevated"
    return False, ("not elevated and not in Performance Log Users: a real-time ETW session cannot be started here; "
                   "add this account to Performance Log Users, or run elevated")


# -- the consumer -------------------------------------------------------------------------------------------

def _safe_tag(tag: str) -> str:
    """`tag` reduced to the characters a session name may hold."""
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in str(tag))[:32]
    return safe or "watch"


# A session's name carries the process that owns it, its pid and its creation time (GetProcessTimes' creation
# FILETIME in whole seconds since 1601, FILETIME // 10**7), and a per-process counter:
# `Liminal-<tag>-<pid>-<ctime>-<n>`. So (1) a session left behind by a killed process is told from a live process's
# even after Windows has given the dead owner's pid to another process (that one was created at another time), and
# (2) two consumers in one process never share a name. The older `Liminal-<tag>-<pid>-<n>` still parses (and is
# written only when this process cannot read its own creation time). The numbers are always the last dash groups,
# whatever the tag holds, and the two forms never read as each other: a creation time in seconds has been above 2**32
# since 1737, and a pid is a DWORD, below it.
_SESSION_PREFIX = "Liminal"
_SESSION_SEQ = itertools.count(1)
_SESSION_RE = re.compile(r"^" + re.escape(_SESSION_PREFIX) + r"-.+-(?P<pid>[0-9]+)-(?P<uniq>[0-9]+)$")
_SESSION_CTIME_RE = re.compile(
    r"^" + re.escape(_SESSION_PREFIX) + r"-.+-(?P<pid>[0-9]+)-(?P<ctime>[0-9]+)-(?P<uniq>[0-9]+)$")
_PID_MAX = (1 << 32) - 1  # a Windows pid is a DWORD
_CTIME_MIN = 1 << 32      # the least creation time a name carries: it can never be read back as a pid


def _session_name(tag: str, pid: int, ctime, uniq: int) -> str:
    """`Liminal-<tag>-<pid>-<ctime>-<n>`; the older `Liminal-<tag>-<pid>-<n>` when the creation time is not known (or
    is too small to be one, which would read back as the older form with the wrong pid)."""
    if ctime is not None and int(ctime) >= _CTIME_MIN:
        return f"{_SESSION_PREFIX}-{tag}-{int(pid)}-{int(ctime)}-{int(uniq)}"
    return f"{_SESSION_PREFIX}-{tag}-{int(pid)}-{int(uniq)}"


def _parse_session(name: str):
    """(pid, creation time) from one of our session names, the creation time None for the older form; None when the
    name is not ours."""
    text = name or ""
    match = _SESSION_CTIME_RE.match(text)
    if match:
        pid, ctime = int(match.group("pid")), int(match.group("ctime"))
        if ctime >= _CTIME_MIN and pid <= _PID_MAX:
            return pid, ctime
    match = _SESSION_RE.match(text)
    if match and int(match.group("pid")) <= _PID_MAX:
        return int(match.group("pid")), None
    return None


def _session_pid(name: str):
    """The pid encoded in one of our session names (either form), or None when the name is not ours."""
    parsed = _parse_session(name)
    return parsed[0] if parsed else None


def _process_alive(pid: int) -> bool:
    """Whether `pid` is a live process here (best effort). True off Windows, where reclaim never runs anyway."""
    if sys.platform != "win32":
        return True
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        handle = k32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ctypes.get_last_error() != 87  # ERROR_INVALID_PARAMETER: no such pid -> dead; else assume alive
        try:
            code = ctypes.c_uint32(0)
            k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
            if k32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return code.value == 259  # STILL_ACTIVE
            return True
        finally:
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
            k32.CloseHandle(handle)
    except Exception:  # noqa: BLE001 - the probe could not be made: do not reclaim on a guess
        return True


class _FileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


def _process_ctime(pid: int):
    """When process `pid` was created, in whole seconds since 1601 (GetProcessTimes' creation FILETIME // 10**7): the
    number a session name carries. A process this one may not open (an unelevated process here is refused about half
    of them: every service's) is read from the system's process list instead (`_listed_ctime`). None when it cannot be
    read at all (no such process, not Windows); the caller then does not reclaim on a guess."""
    if sys.platform != "win32":
        return None
    try:
        pid = int(pid)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(_FileTime)] * 4
        k32.GetProcessTimes.restype = ctypes.c_int
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        own = pid == os.getpid()
        handle = k32.GetCurrentProcess() if own else k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None if ctypes.get_last_error() == ERROR_INVALID_PARAMETER else _listed_ctime(pid)
        try:
            times = [_FileTime() for _ in range(4)]  # creation, exit, kernel, user
            if not k32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
                return None
            return ((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime) // 10**7 or None
        finally:
            if not own:
                k32.CloseHandle(handle)
    except Exception:  # noqa: BLE001 - not known
        return None


class _UnicodeString(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_uint16), ("MaximumLength", ctypes.c_uint16), ("Buffer", ctypes.c_void_p)]


class _SystemProcessInformation(ctypes.Structure):
    """The head of one SYSTEM_PROCESS_INFORMATION entry, as far as its process id: the well-known layout (winternl.h
    keeps CreateTime inside its Reserved1), the one Task Manager and psutil read. Only NextEntryOffset, CreateTime and
    UniqueProcessId are read, and `_listed_ctime` checks this process's own entry before it believes another's."""
    _fields_ = [
        ("NextEntryOffset", ctypes.c_uint32), ("NumberOfThreads", ctypes.c_uint32),
        ("WorkingSetPrivateSize", ctypes.c_int64), ("HardFaultCount", ctypes.c_uint32),
        ("NumberOfThreadsHighWatermark", ctypes.c_uint32), ("CycleTime", ctypes.c_uint64),
        ("CreateTime", ctypes.c_int64), ("UserTime", ctypes.c_int64), ("KernelTime", ctypes.c_int64),
        ("ImageName", _UnicodeString), ("BasePriority", ctypes.c_int32), ("UniqueProcessId", ctypes.c_void_p),
    ]


def _listed_ctimes() -> dict:
    """{pid: creation time in whole seconds since 1601} for every process in the system's process list
    (NtQuerySystemInformation, SystemProcessInformation), which needs no handle on any process. Read-only, one
    buffer of about a megabyte, bounded by PROCESS_LIST_MAX. {} when it cannot be read, and off Windows."""
    if sys.platform != "win32":
        return {}
    try:
        query = ctypes.WinDLL("ntdll").NtQuerySystemInformation
        query.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        query.restype = ctypes.c_uint32  # NTSTATUS, compared unsigned
        size = 1 << 20
        while True:
            buf = (ctypes.c_byte * size)()
            needed = ctypes.c_uint32(0)
            status = query(SYSTEM_PROCESS_INFORMATION, buf, size, ctypes.byref(needed))
            if status != STATUS_INFO_LENGTH_MISMATCH:
                break
            size = max(size * 2, int(needed.value) + (1 << 16))  # room for processes started meanwhile
            if size > PROCESS_LIST_MAX:
                return {}
        if status != 0:
            return {}
        filled = min(int(needed.value) or size, size)
        head = ctypes.sizeof(_SystemProcessInformation)
        base = ctypes.addressof(buf)
        out: dict = {}
        offset = 0
        while offset + head <= filled:
            entry = _SystemProcessInformation.from_address(base + offset)
            if entry.CreateTime > 0:
                out[int(entry.UniqueProcessId or 0)] = int(entry.CreateTime) // 10**7
            if not entry.NextEntryOffset:
                break
            offset += int(entry.NextEntryOffset)
        return out
    except Exception:  # noqa: BLE001 - not known
        return {}


def _listed_ctime(pid: int):
    """`pid`'s creation time from the system's process list, believed only when the list gives this process's own
    entry the time GetProcessTimes gives it (so an entry layout this Windows does not use is never read as times).
    None when the pid is not listed or the list is not believed."""
    listed = _listed_ctimes()
    own = _process_ctime(os.getpid())
    if own is None or listed.get(os.getpid()) != own:
        return None
    return listed.get(int(pid))


def _owner_alive(pid: int, ctime, pid_alive, ctime_of) -> bool:
    """Whether a live process has `pid` and, when the name carries one, the creation time `ctime`. A creation time
    that cannot be read is not taken for a different one: such a session is left, not reclaimed on a guess."""
    if not pid_alive(pid):
        return False
    if ctime is None:  # the older name: the pid alone, as before
        return True
    now = ctime_of(pid)
    return now is None or int(now) == int(ctime)


# The consumers of this process that hold a session or are bringing one up: each joins before its StartTraceW and
# leaves once it is stopped (or its start failed). It is the "sessions this process is running now" a reclaim pass
# never touches, and the set the atexit hook stops. One lock guards it, so a pass in another thread reads it whole.
_LIVE: "weakref.WeakSet[EtwConsumer]" = weakref.WeakSet()
_LIVE_LOCK = threading.Lock()


def _live_add(consumer) -> None:
    with _LIVE_LOCK:
        _LIVE.add(consumer)


def _live_discard(consumer) -> None:
    with _LIVE_LOCK:
        _LIVE.discard(consumer)


def _live_consumers() -> list:
    with _LIVE_LOCK:
        return list(_LIVE)


def _live_sessions() -> set:
    """The names of the sessions this process is running now (or bringing up)."""
    return {consumer.session for consumer in _live_consumers()}


def reclaim_stale_sessions(advapi32=None, *, pid_alive=None, ctime_of=None) -> list[str]:
    """Stop every Liminal ETW session on this machine whose owner is gone, and return the names stopped. A plugin
    calls it at attach, so a watch that a killed platform left running is stopped without waiting for a new watch
    to start; every EtwConsumer.start() runs the same pass.

    A name is ours when it parses (`Liminal-<tag>-<pid>-<ctime>-<n>`, or the older `Liminal-<tag>-<pid>-<n>`). One of
    the sessions this process is running now (the module's live set) is never touched. Any other of ours is stopped
    unless a live process has its pid and, in the newer form, its creation time: a pid that Windows has given to
    another process since, this process included, no longer keeps a dead owner's session. The older form keeps the
    pid check alone. A live pid whose creation time cannot be read keeps its session (not reclaimed on a guess).

    `advapi32` (`query_all_traces`, `control_stop`), `pid_alive(pid)` and `ctime_of(pid)` stand in for the real
    calls in tests. A stop that fails is not counted. Best effort: it never raises, and it returns [] off Windows or
    when the sessions cannot be listed."""
    if advapi32 is None:
        if sys.platform != "win32":
            return []
        try:
            advapi32 = WinAdvapi32()
        except Exception:  # noqa: BLE001 - advapi32 could not be loaded: nothing to reclaim with
            return []
    alive = pid_alive or _process_alive
    created = ctime_of or _process_ctime
    try:
        names = list(advapi32.query_all_traces() or ())
    except Exception:  # noqa: BLE001 - the enumeration could not be made: nothing is reclaimed
        return []
    # Read after the listing: a consumer joins the live set before its StartTraceW, so a session listed above is
    # either one this process was already running (and is in the set now) or another process's.
    live = _live_sessions()
    stopped: list[str] = []
    for name in names:
        parsed = _parse_session(name)
        if parsed is None or name in live:
            continue
        pid, ctime = parsed
        try:
            if _owner_alive(pid, ctime, alive, created):
                continue
            status = advapi32.control_stop(name)
        except Exception:  # noqa: BLE001 - one name that cannot be judged or stopped does not block the rest
            continue
        if status is None or status in (ERROR_SUCCESS, ERROR_MORE_DATA):
            stopped.append(name)
    return stopped


def _ended_words(status) -> str:
    """Why ProcessTrace returned by itself while its session was still wanted. ERROR_SUCCESS (or no status, from a
    stand-in) and ERROR_WMI_INSTANCE_NOT_FOUND are the session stopped from outside; any other status is the consumer
    failing, said by its number and, where known, its name."""
    if status is None or status in (ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND):
        return "the session was stopped from outside"
    name = STATUS_NAMES.get(status) if isinstance(status, int) else None
    return f"its consumer failed: ProcessTrace returned {status}" + (f" ({name})" if name else "")


class EtwConsumer:
    """A private real-time ETW session over `providers` (keys of PROVIDERS), consumed on one daemon thread.
    `advapi32` and `tdh` stand in for the function tables in tests; otherwise they are built on start()
    (Windows only). Decoded records wait in a bounded queue that drops the oldest and counts the drops.

    start() and stop() hold one lifecycle lock and run a small state machine ("new" -> "started" -> "stopped",
    or "new" -> "stopped"), so a stop() that lands while start() is bringing the session up always stops it, and
    a start() after stop() is refused. The session name carries this process's pid and creation time and a
    per-process counter, so a session left by a killed process is reclaimed (`reclaim_stale_sessions`, run again by
    every start()) even once Windows has given its pid to another process, and two consumers never share a name.
    `pid_alive(pid)` and `ctime_of(pid)` stand in for the liveness and creation-time reads in tests; `ctime_of` also
    gives this process's own creation time for the name."""

    def __init__(self, tag: str, providers=None, advapi32=None, tdh=None, capacity: int = DEFAULT_CAPACITY,
                 level: int = TRACE_LEVEL_VERBOSE, clock=time.time, *, pid_alive=None, ctime_of=None):
        self.tag = _safe_tag(tag)
        self._pid_alive = pid_alive or _process_alive
        self._ctime_of = ctime_of or _process_ctime
        try:
            own_ctime = self._ctime_of(os.getpid())
        except Exception:  # noqa: BLE001 - not known: the older name, without it
            own_ctime = None
        self.session = _session_name(self.tag, os.getpid(), own_ctime, next(_SESSION_SEQ))
        self.providers = tuple(providers) if providers is not None else tuple(PROVIDERS)
        unknown = [p for p in self.providers if p not in PROVIDERS]
        if unknown:
            raise EtwError(f"no such ETW provider(s): {', '.join(unknown)}")
        self.level = level
        self.capacity = max(1, int(capacity))
        self.clock = clock
        self.events_lost = 0  # ETW's own loss counter at stop, when it can be read (0 otherwise)
        self._advapi32 = advapi32
        self._tdh = tdh
        self._queue: collections.deque = collections.deque()
        self._lock = threading.Lock()          # guards the record queue (the hot callback path)
        self._life_lock = threading.Lock()     # guards start()/stop(): the session is brought up or torn down once
        self.drops = 0
        self.error = ""  # why the consumer ended while the session was still wanted ("" otherwise)
        self._control = None
        self._trace = None
        self._thread: threading.Thread | None = None
        self._state = "new"  # "new" | "started" | "stopped"

    @property
    def _started(self) -> bool:
        return self._state == "started"

    @property
    def _stopped(self) -> bool:
        return self._state == "stopped"

    @property
    def running(self) -> bool:
        """Whether the session is up and its consumer still reading it: False before start() and after stop(), and
        False once ProcessTrace has returned by itself (the session stopped from outside, or the consumer failed:
        `error` then says which), so a caller can tell a quiet machine from a session that is gone."""
        thread = self._thread
        return self._state == "started" and thread is not None and thread.is_alive()

    def start(self) -> None:
        """Start the session, enable each provider, open the trace and consume it on a daemon thread, all under the
        lifecycle lock. If enabling or opening fails after the session was started, it is stopped again at once; a
        stop() that arrives meanwhile waits on the lock and then stops it, so no real-time session is left running
        behind a failure or a race (the design: nothing is left running). The consumer joins the live set before
        StartTraceW, so no reclaim pass (its own, or one in another thread) takes the session for stale, and then
        stops what killed processes left (`reclaim_stale_sessions`)."""
        with self._life_lock:
            if self._state != "new":  # already started, or stopped: a start() after stop() is refused
                return
            adv = self._advapi32 if self._advapi32 is not None else WinAdvapi32()
            tdh = self._tdh if self._tdh is not None else WinTdh()
            self._advapi32, self._tdh = adv, tdh
            _live_add(self)
            reclaim_stale_sessions(adv, pid_alive=self._pid_alive, ctime_of=self._ctime_of)
            try:
                self._control = adv.start_trace(self.session, EVENT_TRACE_REAL_TIME_MODE)
            except Exception:  # nothing was started: out of the live set, and still "new" (a later start may retry)
                _live_discard(self)
                raise
            try:
                for key in self.providers:
                    guid, keywords = PROVIDERS[key]
                    adv.enable_trace(self._control, guid, self.level, keywords)
                if "process" in self.providers:
                    try:  # rundown the running processes, so ones started before the watch are still named
                        adv.capture_state(self._control, PROVIDERS["process"][0])
                    except Exception:  # noqa: BLE001 - best effort; a watch still works without the rundown
                        pass
                self._trace = adv.open_trace(self.session, self._on_record)
            except Exception:  # the session is started but not consumable: stop it rather than leak it
                try:
                    adv.control_stop(self.session)
                except Exception:  # noqa: BLE001 - already gone
                    pass
                self._control = None
                self._state = "stopped"
                _live_discard(self)
                raise
            self._state = "started"
            self._thread = threading.Thread(target=self._run, name=f"etw-{self.tag}", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        """Consume the trace until ProcessTrace returns: at stop(), or by itself when the session ends from outside
        (an administrator's `logman stop`, another program stopping it) or the consumer fails (an exception, or a
        failure status: `_ended_words`). Only the last two are said in `error`: stop() marks the state stopped before
        it stops the session."""
        try:
            status = self._advapi32.process_trace(self._trace)
        except Exception as e:  # noqa: BLE001 - the trace handle went away when the session stopped
            if self._state == "started":
                self.error = f"its consumer failed: {type(e).__name__}: {e}"
        else:
            if self._state == "started":
                self.error = _ended_words(status)
        finally:
            try:
                self._advapi32.close_trace(self._trace)
            except Exception:  # noqa: BLE001
                pass

    def _on_record(self, record) -> None:
        try:
            rec = self._tdh.decode(record)
        except Exception:  # noqa: BLE001 - a record that will not decode is dropped, never fatal
            rec = None
        if rec is None:
            return
        with self._lock:
            if len(self._queue) >= self.capacity:
                self._queue.popleft()
                self.drops += 1
            self._queue.append(rec)

    def drain(self, limit=None) -> list[EtwRecord]:
        """Take the decoded records waiting (the oldest first), up to `limit`."""
        with self._lock:
            if limit is None or limit >= len(self._queue):
                items = list(self._queue)
                self._queue.clear()
            else:
                items = [self._queue.popleft() for _ in range(max(0, int(limit)))]
        return items

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    def stop(self, wait: float = 4.0) -> None:
        """Stop the session (ControlTraceW STOP), which ends ProcessTrace and the thread. Under the lifecycle lock,
        so a stop() racing a start() waits for the session to come up and then stops it; idempotent."""
        with self._life_lock:
            if self._state == "stopped":
                return
            had_session = self._advapi32 is not None and self._control is not None
            self._state = "stopped"
            adv = self._advapi32
            thread = self._thread
            if had_session:
                try:
                    stats = adv.query_stats(self.session)
                    self.events_lost = int(stats.get("events_lost", 0)) if isinstance(stats, dict) else 0
                except Exception:  # noqa: BLE001 - the loss counter is a nicety, never required to stop
                    pass
                try:
                    adv.control_stop(self.session)
                except Exception:  # noqa: BLE001 - already gone
                    pass
        if thread is not None:
            thread.join(wait)
        _live_discard(self)


def _stop_all_at_exit() -> None:
    """Stop every session still open when the interpreter exits (the design: nothing is left running)."""
    for consumer in _live_consumers():
        try:
            consumer.stop(wait=1.0)
        except Exception:  # noqa: BLE001
            pass


atexit.register(_stop_all_at_exit)
