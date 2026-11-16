"""The ETW real-time consumer (liminal_libs.machines.etw): the GUID, time and property decoding; whether a
real-time session can be started here; and the consumer's start/stop ordering, its bounded drop-oldest queue
and its atexit stop. advapi32 and tdh are an injected stand-in function table driven with synthetic records, so
no real ETW session is ever started (the design, 2026-11-14: "Tests never start processes or captures"). The
real ctypes property decode is checked by hand on a scratch platform, as the module says."""
from __future__ import annotations

import ctypes
import os
import socket
import sys
import threading
import time

import pytest

from liminal_libs.machines import etw


# -- the pure decoders (cross-platform: no Windows library) --------------------------------------------------

def test_guid_round_trips_and_maps_back_to_its_provider():
    for key, (guid, _kw) in etw.PROVIDERS.items():
        text = etw.guid_to_string(etw.guid_from_string(guid))
        assert text == guid.upper()
        assert etw._PROVIDER_BY_GUID[text] == key
    # a lower-case guid still round-trips to the upper-case canonical form
    low = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"
    assert etw.guid_to_string(etw.guid_from_string(low)) == low.upper()


def test_the_four_kernel_providers_and_their_keywords():
    assert set(etw.PROVIDERS) == {"process", "file", "network", "registry"}
    assert etw.PROVIDERS["process"] == ("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}", 0x10 | 0x40)
    assert etw.PROVIDERS["file"] == ("{EDD08927-9CC4-4E65-B970-C2560FB5C289}", 0x80)
    assert etw.PROVIDERS["network"] == ("{7DD42A49-5329-4832-8DFD-43D979153A88}", 0x10 | 0x20)
    assert etw.PROVIDERS["registry"] == ("{70EB4F03-C1DE-4F73-A051-33D13D5413BD}", 0x00)
    # only the properties the scope uses are listed to decode
    assert "ImageName" in etw._FIELDS["process"] and "daddr" in etw._FIELDS["network"]
    assert "FileName" in etw._FIELDS["file"] and "KeyName" in etw._FIELDS["registry"]


def test_filetime_to_the_unix_epoch():
    epoch_ticks = 116444736000000000  # 1601-01-01 .. 1970-01-01 in 100 ns ticks
    assert abs(etw._filetime_epoch(epoch_ticks) - 0.0) < 1e-6
    assert abs(etw._filetime_epoch(epoch_ticks + 10_000_000) - 1.0) < 1e-6  # one second on


def test_interpret_decodes_only_the_kinds_the_scope_uses():
    # a wide string, NUL-terminated, is cut at the NUL
    raw = ("C:/Windows/System32/curl.exe\x00trailing").encode("utf-16-le")
    assert etw._interpret("ImageName", raw) == "C:/Windows/System32/curl.exe"
    # an IPv4 address from four bytes, an IPv6 address from sixteen
    assert etw._interpret("daddr", socket.inet_aton("93.184.216.34")) == "93.184.216.34"
    v6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    assert etw._interpret("saddr", v6) == "2001:db8::1"
    # a port is stored network order and comes back host order
    assert etw._interpret("dport", (443).to_bytes(2, "big")) == 443
    # a plain id is a little-endian integer; empty bytes decode to nothing
    assert etw._interpret("ProcessID", (1234).to_bytes(4, "little")) == 1234
    assert etw._interpret("ProcessID", b"") is None


def test_interpret_reads_a_16_byte_address_as_ipv6_even_with_a_zero_tail():
    # regression (F12): a 16-byte win:Binary address is IPv6, including one whose last 12 bytes are zero. The old
    # "any(raw[4:16])" test misread 2001:db8:: and fe80:: as IPv4 (32.1.13.184, 254.128.0.0).
    for text in ("2001:db8::", "fe80::", "::", "2600::"):
        raw = socket.inet_pton(socket.AF_INET6, text)
        assert etw._interpret("daddr", raw) == text
    # a 4-byte field is still IPv4
    assert etw._interpret("saddr", socket.inet_aton("10.0.0.2")) == "10.0.0.2"


def test_interpret_decodes_an_ansi_string_when_the_schema_says_ansi():
    # regression (F12): ProcessStop's ImageName is win:AnsiString on this PC. Decoding its bytes as UTF-16 (the
    # default) yields mojibake; with the schema's ANSI in-type it reads correctly.
    raw = b"curl.exe\x00"
    assert etw._interpret("ImageName", raw, in_type=etw.TDH_INTYPE_ANSISTRING) == "curl.exe"
    assert etw._interpret("ImageName", raw) != "curl.exe"  # UTF-16 by default is still garbage for ANSI bytes
    # a UTF-16 ImageName marked UnicodeString (or left unknown) decodes as before
    wide = "C:/Windows/System32/cmd.exe\x00".encode("utf-16-le")
    assert etw._interpret("ImageName", wide, in_type=etw.TDH_INTYPE_UNICODESTRING) == "C:/Windows/System32/cmd.exe"
    assert etw._interpret("ImageName", wide) == "C:/Windows/System32/cmd.exe"


def test_interpret_truncates_a_runaway_string():
    # a decoded string is capped, so one record cannot carry hundreds of KB into the bounded queue (minor finding)
    huge = ("A" * 50000 + "\x00").encode("utf-16-le")
    assert len(etw._interpret("FileName", huge)) == etw.MAX_STRING


def test_a_synthetic_event_record_header_decodes_to_its_provider_id_opcode_pid_and_time():
    # a real EVENT_RECORD structure (as the callback is handed), filled by hand: the header fields the consumer
    # reads off every record decode to what EtwRecord carries. The property bytes themselves need a live schema,
    # so TdhGetProperty is checked by hand on a scratch platform; this covers the header path portably.
    record = etw._EventRecord()
    record.EventHeader.ProviderId = etw.guid_from_string(etw.PROVIDERS["network"][0])
    record.EventHeader.ProcessId = 4321
    record.EventHeader.TimeStamp = 116444736000000000 + 25_000_000  # 2.5 s past the Unix epoch
    record.EventHeader.EventDescriptor.Id = 12
    record.EventHeader.EventDescriptor.Opcode = 11
    header = record.EventHeader
    assert etw._PROVIDER_BY_GUID[etw.guid_to_string(header.ProviderId)] == "network"
    assert header.ProcessId == 4321 and header.EventDescriptor.Id == 12 and header.EventDescriptor.Opcode == 11
    assert abs(etw._filetime_epoch(header.TimeStamp) - 2.5) < 1e-6


def test_safe_tag_keeps_only_a_session_name_s_characters():
    assert etw._safe_tag("fire wall/plugin") == "fire_wall_plugin"
    assert etw._safe_tag("") == "watch"
    assert len(etw._safe_tag("x" * 100)) == 32


def test_properties_buffer_carries_the_session_name_after_the_struct():
    buf, props = etw._properties_buffer("Liminal-fw-4321", etw.EVENT_TRACE_REAL_TIME_MODE)
    p = props.contents
    assert p.LogFileMode == etw.EVENT_TRACE_REAL_TIME_MODE
    assert p.LoggerNameOffset == ctypes.sizeof(etw._EventTraceProperties)
    assert p.BufferSize == ctypes.sizeof(buf)
    name = ctypes.wstring_at(ctypes.addressof(buf) + p.LoggerNameOffset)
    assert name == "Liminal-fw-4321"


# -- available(): can a real-time session be started here ----------------------------------------------------

def test_available_reads_the_token_without_starting_anything():
    assert etw.available(probe=lambda: (True, False))[0] is True        # elevated
    ok, why = etw.available(probe=lambda: (False, True))                # in Performance Log Users
    assert ok and "Performance Log Users" in why
    ok, why = etw.available(probe=lambda: (False, False))
    assert not ok and "not elevated" in why and "Performance Log Users" in why


def test_available_when_the_token_cannot_be_read():
    def boom():
        raise OSError("no token")
    ok, why = etw.available(probe=boom)
    assert not ok and "could not be read" in why


def test_available_off_windows(monkeypatch):
    monkeypatch.setattr(etw.sys, "platform", "linux")
    ok, why = etw.available()
    assert not ok and "not Windows" in why


# -- a stand-in advapi32 / tdh, driven with synthetic records ------------------------------------------------

class FakeAdvapi32:
    """A stand-in advapi32: it records the calls in order, keeps the callback, and `process_trace` delivers the
    canned records and then blocks (as the real ProcessTrace does) until `control_stop` releases it. No real
    session is started."""

    def __init__(self, records=()):
        self.records = list(records)
        self.calls: list = []
        self._cb = None
        self._go = threading.Event()
        self.delivered = threading.Event()
        self.enabled: list = []

    def start_trace(self, session, mode):
        self.calls.append(("start_trace", session, mode))
        return 0x1111

    def enable_trace(self, control, guid, level, keywords):
        self.calls.append(("enable_trace", guid))
        self.enabled.append(guid)
        return 0

    def capture_state(self, control, guid):
        self.calls.append(("capture_state", guid))
        return 0

    def query_all_traces(self):
        return []

    def query_stats(self, session):
        return {}

    def open_trace(self, session, callback):
        self.calls.append(("open_trace", session))
        self._cb = callback
        return 0x2222

    def process_trace(self, trace):
        self.calls.append(("process_trace", trace))
        for rec in self.records:
            self._cb(rec)
        self.delivered.set()
        self._go.wait(2.0)
        return 0

    def control_stop(self, session):
        self.calls.append(("control_stop", session))
        self._go.set()
        return 0

    def close_trace(self, trace):
        self.calls.append(("close_trace", trace))
        return 0


class FakeTdh:
    """A stand-in tdh whose decode returns the record as handed to the callback (the FakeAdvapi32 delivers
    EtwRecords directly), or runs a given function."""

    def __init__(self, fn=lambda rec: rec):
        self.fn = fn

    def decode(self, record):
        return self.fn(record)


def _rec(pid, provider="process", event_id=1, props=None):
    return etw.EtwRecord(at=1.0, provider=provider, event_id=event_id, opcode=0, pid=pid, props=props or {})


def _names(calls):
    return [c[0] for c in calls]


# -- the consumer --------------------------------------------------------------------------------------------

def test_consumer_starts_enables_every_provider_opens_and_consumes_in_order():
    adv = FakeAdvapi32([_rec(100), _rec(101)])
    tdh = FakeTdh()
    c = etw.EtwConsumer("fw", advapi32=adv, tdh=tdh)  # every provider
    assert c.session.startswith(f"Liminal-fw-{__import__('os').getpid()}-")  # tag, this pid, a per-process counter
    c.start()
    assert adv.delivered.wait(2.0)
    assert _names(adv.calls)[:3] == ["start_trace", "enable_trace", "enable_trace"]
    # every one of the four providers was enabled, by its guid, then the trace opened and processed
    assert adv.enabled == [etw.PROVIDERS[k][0] for k in ("process", "file", "network", "registry")]
    names = _names(adv.calls)
    assert names.index("open_trace") > names.index("enable_trace")  # providers enabled before the trace opened
    assert names.index("process_trace") > names.index("open_trace")  # and consumed after it opened
    seq_records = c.drain()
    assert [r.pid for r in seq_records] == [100, 101]
    c.stop()


def test_consumer_enables_only_the_providers_asked_for():
    adv = FakeAdvapi32()
    c = etw.EtwConsumer("fw", providers=("network", "process"), advapi32=adv, tdh=FakeTdh())
    c.start()
    assert adv.delivered.wait(2.0)
    assert adv.enabled == [etw.PROVIDERS["network"][0], etw.PROVIDERS["process"][0]]
    c.stop()


def test_consumer_rejects_an_unknown_provider():
    with pytest.raises(etw.EtwError):
        etw.EtwConsumer("fw", providers=("process", "disk"))


def test_the_queue_drops_the_oldest_and_counts_the_drops():
    adv = FakeAdvapi32([_rec(i) for i in range(5)])
    c = etw.EtwConsumer("fw", providers=("process",), advapi32=adv, tdh=FakeTdh(), capacity=3)
    c.start()
    assert adv.delivered.wait(2.0)
    assert c.pending == 3 and c.drops == 2  # only the last three kept, two oldest dropped
    kept = c.drain()
    assert [r.pid for r in kept] == [2, 3, 4] and c.pending == 0
    c.stop()


def test_drain_takes_at_most_the_limit_oldest_first():
    adv = FakeAdvapi32([_rec(i) for i in range(4)])
    c = etw.EtwConsumer("fw", providers=("process",), advapi32=adv, tdh=FakeTdh())
    c.start()
    assert adv.delivered.wait(2.0)
    first = c.drain(limit=2)
    assert [r.pid for r in first] == [0, 1] and c.pending == 2
    assert [r.pid for r in c.drain()] == [2, 3]
    c.stop()


def test_a_record_that_will_not_decode_is_dropped_not_fatal():
    def decode(rec):
        if rec.pid == 2:
            raise ValueError("bad record")
        return None if rec.pid == 1 else rec
    adv = FakeAdvapi32([_rec(1), _rec(2), _rec(3)])
    c = etw.EtwConsumer("fw", providers=("process",), advapi32=adv, tdh=FakeTdh(decode))
    c.start()
    assert adv.delivered.wait(2.0)
    assert [r.pid for r in c.drain()] == [3]  # pid 1 decoded to None, pid 2 raised; both skipped
    c.stop()


def test_stop_controls_the_trace_then_the_thread_ends_and_is_idempotent():
    adv = FakeAdvapi32([_rec(1)])
    c = etw.EtwConsumer("fw", providers=("process",), advapi32=adv, tdh=FakeTdh())
    c.start()
    assert adv.delivered.wait(2.0)
    c.stop()
    names = _names(adv.calls)
    assert names.index("control_stop") < names.index("close_trace")  # stopped, then the handle closed
    assert c._stopped and not _thread_alive(f"etw-{c.tag}")
    before = len(adv.calls)
    c.stop()  # idempotent: no more calls
    assert len(adv.calls) == before


def test_start_is_idempotent():
    adv = FakeAdvapi32()
    c = etw.EtwConsumer("fw", providers=("process",), advapi32=adv, tdh=FakeTdh())
    c.start()
    assert adv.delivered.wait(2.0)
    c.start()  # a second start does nothing
    assert _names(adv.calls).count("start_trace") == 1
    c.stop()


def test_a_failed_enable_stops_the_session_rather_than_leaking_it():
    class FailingAdv(FakeAdvapi32):
        def enable_trace(self, control, guid, level, keywords):
            raise etw.EtwError("EnableTraceEx2 failed (5)")
    adv = FailingAdv()
    c = etw.EtwConsumer("fw", providers=("process",), advapi32=adv, tdh=FakeTdh())
    with pytest.raises(etw.EtwError):
        c.start()
    # the session that StartTraceW opened was stopped again, and the consumer is not left live
    assert _names(adv.calls) == ["start_trace", "control_stop"]
    assert c not in list(etw._LIVE) and not c._started


def test_atexit_stops_every_session_still_open():
    adv = FakeAdvapi32()
    c = etw.EtwConsumer("fw", providers=("process",), advapi32=adv, tdh=FakeTdh())
    c.start()
    assert adv.delivered.wait(2.0)
    assert c in list(etw._LIVE)
    etw._stop_all_at_exit()
    assert c._stopped and "control_stop" in _names(adv.calls)
    assert c not in list(etw._LIVE)


# -- F10: two consumers in one process never share a session name --------------------------------------------

def test_two_consumers_with_one_tag_get_distinct_session_names():
    # regression (F10): same tag, same pid, but a per-process counter keeps the names apart, so the second start
    # does not meet the first's name (ERROR_ALREADY_EXISTS) and stop its live session.
    a = etw.EtwConsumer("watch", providers=("process",), advapi32=FakeAdvapi32(), tdh=FakeTdh())
    b = etw.EtwConsumer("watch", providers=("process",), advapi32=FakeAdvapi32(), tdh=FakeTdh())
    assert a.session != b.session
    assert etw._session_pid(a.session) == __import__("os").getpid()
    # each stop() stops its own name only
    a.start(); b.start()
    assert a._advapi32.delivered.wait(2.0) and b._advapi32.delivered.wait(2.0)
    a.stop()
    assert ("control_stop", a.session) in a._advapi32.calls
    assert ("control_stop", a.session) not in b._advapi32.calls  # B's session is untouched
    b.stop()


# -- F1: a session left by a killed process is reclaimed -----------------------------------------------------

def test_start_reclaims_a_stale_session_of_a_dead_pid_but_not_a_live_one():
    # regression (F1): on start, list the running sessions and stop each Liminal-<tag>-<pid>-<n> whose pid is gone.
    # A live process's session, this process's own sessions, and a foreign name are all left alone.
    import os
    dead = 424242
    stale = f"Liminal-watch-{dead}-1"               # left by a crashed watch
    live_other = f"Liminal-watch-777777-1"          # another live Liminal process
    mine = f"Liminal-watch-{os.getpid()}-9"         # the older form with THIS pid: no creation time, the pid check
    foreign = "MyAppSession"                        # not one of ours

    class ReclaimAdv(FakeAdvapi32):
        def query_all_traces(self):
            return [foreign, stale, live_other, mine]

    adv = ReclaimAdv()
    c = etw.EtwConsumer("watch", providers=("process",), advapi32=adv, tdh=FakeTdh(),
                        pid_alive=lambda pid: pid != dead)  # only `dead` is gone
    c.start()
    assert adv.delivered.wait(2.0)
    stopped = [name for kind, *rest in adv.calls if kind == "control_stop" for name in rest]
    assert stale in stopped                         # reclaimed
    assert live_other not in stopped                # a live pid is left running
    assert mine not in stopped                      # this live pid keeps an older-form name (it carries no ctime)
    assert foreign not in stopped                   # not a Liminal name
    c.stop()


def test_session_pid_parses_only_our_names():
    import os
    assert etw._session_pid(f"Liminal-fw-{os.getpid()}-3") == os.getpid()
    assert etw._session_pid("Liminal-plug-in-name-123-4") == 123   # a tag with dashes still parses
    assert etw._session_pid("NotOurs-1-2") is None
    assert etw._session_pid("Liminal-fw-notanumber") is None


# -- F1, the rest: the owner's creation time in the name, this process's own pid, and a pass a plugin can call --------

MINE = 13_439_274_383       # this process's creation time as the tests give it (whole seconds since 1601)
EARLIER = 13_439_000_000    # an earlier process's that had this same pid
LIVE_PID, LIVE_CT = 50_000, 13_400_000_000                  # another live Liminal process, and when it was created
REUSED, REUSED_THEN, REUSED_NOW = 60_000, 13_430_000_000, 13_439_270_000  # a dead platform's pid, given to another


def _ctimes(table):
    """A stand-in for the creation-time read: the table's time for a pid, None (not readable) for any other."""
    return lambda pid: table.get(pid)


class SessionTable:
    """The machine-wide session table as a reclaim pass sees it: `query_all_traces` lists the running names and
    `control_stop` stops one (status 0), or answers the status given for that name (an exception is raised)."""

    def __init__(self, names, status=None):
        self.running = list(names)
        self.status = dict(status or {})
        self.stops: list = []

    def query_all_traces(self):
        return list(self.running)

    def control_stop(self, name):
        self.stops.append(name)
        code = self.status.get(name, 0)
        if isinstance(code, Exception):
            raise code
        if code == 0 and name in self.running:
            self.running.remove(name)
        return code


class ListingAdv(FakeAdvapi32):
    """A FakeAdvapi32 whose machine also runs `names`: a stop of one of them takes it off the list; a stop of
    anything else is the consumer's own session and releases its process_trace, as in FakeAdvapi32."""

    def __init__(self, names, records=()):
        super().__init__(records)
        self.running = list(names)

    def query_all_traces(self):
        return list(self.running)

    def control_stop(self, session):
        if session in self.running:
            self.calls.append(("control_stop", session))
            self.running.remove(session)
            return 0
        return super().control_stop(session)


def test_session_names_carry_the_owner_s_pid_and_creation_time_and_both_forms_parse():
    name = etw._session_name("watch", 1234, MINE, 7)
    assert name == f"Liminal-watch-1234-{MINE}-7"
    assert etw._parse_session(name) == (1234, MINE)
    assert etw._parse_session(f"Liminal-plug-in-7-1234-{MINE}-2") == (1234, MINE)  # a tag with dashes and digits
    # the older form, without a creation time, still parses: its pid alone
    assert etw._parse_session("Liminal-watch-1234-7") == (1234, None)
    assert etw._parse_session("Liminal-a-7-1234-2") == (1234, None)  # a tag that ends in digits is not a ctime
    assert etw._session_pid(name) == 1234 and etw._session_pid("Liminal-watch-1234-7") == 1234
    # an unknown creation time gives the older form, and so does one too small to tell from a pid
    assert etw._session_name("watch", 1234, None, 7) == "Liminal-watch-1234-7"
    assert etw._session_name("watch", 1234, 99, 7) == "Liminal-watch-1234-7"
    for other in ("NotOurs-1-2-3", "Liminal-fw-notanumber", "Liminal-watch-99999999999-1", "", None):
        assert etw._parse_session(other) is None
    # a consumer names its session after this process: its pid and its creation time
    c = etw.EtwConsumer("fw", advapi32=FakeAdvapi32(), tdh=FakeTdh(), ctime_of=_ctimes({os.getpid(): MINE}))
    assert c.session.startswith(f"Liminal-fw-{os.getpid()}-{MINE}-")
    assert etw._parse_session(c.session) == (os.getpid(), MINE)
    # and without a readable creation time, the older form
    old = etw.EtwConsumer("fw", advapi32=FakeAdvapi32(), tdh=FakeTdh(), ctime_of=lambda pid: None)
    assert etw._parse_session(old.session) == (os.getpid(), None)


def test_a_reused_pid_with_a_different_creation_time_is_reclaimed():
    # regression (F1, the skeptic's second finding): liveness was judged by the pid alone, so a killed platform's
    # session lived on once Windows gave its pid to another process. The live process with that pid now was created
    # at another time, so the session is reclaimed, by the pass a plugin calls and by the pass in start().
    stale = f"Liminal-watch-{REUSED}-{REUSED_THEN}-1"
    table = SessionTable([stale])
    assert etw.reclaim_stale_sessions(table, pid_alive=lambda pid: True,
                                      ctime_of=_ctimes({REUSED: REUSED_NOW})) == [stale]
    assert table.running == []

    adv = ListingAdv([stale])
    c = etw.EtwConsumer("watch", providers=("process",), advapi32=adv, tdh=FakeTdh(), pid_alive=lambda pid: True,
                        ctime_of=_ctimes({os.getpid(): MINE, REUSED: REUSED_NOW}))
    c.start()
    assert adv.delivered.wait(2.0)
    assert ("control_stop", stale) in adv.calls and adv.running == []
    names = _names(adv.calls)
    assert names.index("control_stop") < names.index("start_trace")  # reclaimed before the new session started
    c.stop()


def test_this_process_s_own_earlier_pid_session_is_reclaimed_but_never_its_running_ones():
    # regression (F1, the third finding): a session naming this process's pid was always skipped. Now only the
    # sessions this process is running (the module's live set) are skipped: one that an earlier process with this
    # same pid left (another creation time) is reclaimed, in the newer form.
    me = os.getpid()
    ctimes = _ctimes({me: MINE})
    sibling = etw.EtwConsumer("watch", providers=("process",), advapi32=FakeAdvapi32(), tdh=FakeTdh(),
                              ctime_of=ctimes)
    sibling.start()
    assert sibling._advapi32.delivered.wait(2.0)
    earlier = f"Liminal-watch-{me}-{EARLIER}-40"
    table = SessionTable([sibling.session, earlier])
    try:
        assert sibling.session in etw._live_sessions()
        assert etw.reclaim_stale_sessions(table, pid_alive=lambda pid: True, ctime_of=ctimes) == [earlier]
        # the live set, not the liveness, keeps a running session: even "every pid is dead" leaves it alone
        assert etw.reclaim_stale_sessions(table, pid_alive=lambda pid: False, ctime_of=ctimes) == []
        assert table.running == [sibling.session] and table.stops == [earlier]
    finally:
        sibling.stop()
    assert sibling.session not in etw._live_sessions()  # stopped: no longer one this process is running


def test_a_live_owner_s_session_is_kept():
    live = f"Liminal-watch-{LIVE_PID}-{LIVE_CT}-3"        # a live process with its pid and its creation time
    unread = f"Liminal-watch-{LIVE_PID + 4}-{LIVE_CT}-1"  # a live pid whose creation time cannot be read
    old = f"Liminal-watch-{LIVE_PID + 8}-2"               # the older form: its live pid alone keeps it
    table = SessionTable([live, unread, old])
    ctimes = _ctimes({LIVE_PID: LIVE_CT})
    assert etw.reclaim_stale_sessions(table, pid_alive=lambda pid: True, ctime_of=ctimes) == []
    assert table.stops == [] and table.running == [live, unread, old]
    # the same sessions once their owners are gone are reclaimed, the older form too
    assert etw.reclaim_stale_sessions(table, pid_alive=lambda pid: False, ctime_of=ctimes) == [live, unread, old]
    assert table.running == []


def test_reclaim_stale_sessions_is_callable_on_its_own():
    # regression (F1, the first finding): the pass ran only when a later watch started. A plugin calls it at attach,
    # no watch started; it says which sessions it stopped. A stop that fails is not counted, a foreign name is never
    # touched, and a listing that cannot be made reclaims nothing (it never raises).
    dead = f"Liminal-watch-424242-{EARLIER}-1"
    gone = f"Liminal-watch-424246-{EARLIER}-1"  # stopped by someone else meanwhile: ERROR_WMI_INSTANCE_NOT_FOUND
    stuck = "Liminal-watch-424250-1"            # a stop that raises
    more = f"Liminal-watch-424254-{EARLIER}-1"  # ERROR_MORE_DATA: stopped, only its properties did not fit
    table = SessionTable(["NT Kernel Logger", dead, gone, stuck, more],
                         status={gone: 4201, stuck: OSError("denied"), more: etw.ERROR_MORE_DATA})
    assert etw.reclaim_stale_sessions(table, pid_alive=lambda pid: False, ctime_of=lambda pid: None) == [dead, more]
    assert table.stops == [dead, gone, stuck, more] and "NT Kernel Logger" in table.running

    class Unlisted:
        def query_all_traces(self):
            raise OSError("no access")

        def control_stop(self, name):
            raise AssertionError("nothing is stopped when nothing could be listed")

    assert etw.reclaim_stale_sessions(Unlisted(), pid_alive=lambda pid: False) == []

    # a name whose owner cannot be judged is left; the rest are still reclaimed
    other = f"Liminal-watch-424258-{EARLIER}-1"

    def liveness(pid):
        if pid == 424242:
            raise OSError("cannot be judged")
        return False

    table = SessionTable([dead, other])
    assert etw.reclaim_stale_sessions(table, pid_alive=liveness, ctime_of=lambda pid: None) == [other]
    assert table.running == [dead]


def test_reclaim_stale_sessions_off_windows_does_nothing(monkeypatch):
    monkeypatch.setattr(etw.sys, "platform", "linux")
    assert etw.reclaim_stale_sessions() == []  # no advapi32 is loaded; nothing is listed or stopped
    assert etw._process_ctime(os.getpid()) is None and etw._listed_ctimes() == {}


def test_a_session_being_started_is_never_taken_for_stale():
    # a consumer joins the live set before its StartTraceW, so a pass in another thread (a plugin attaching while a
    # watch starts) never stops a session that is coming up, even with a liveness that calls every pid dead.
    entered, proceed = threading.Event(), threading.Event()

    class SlowAdv(FakeAdvapi32):
        def start_trace(self, session, mode):
            self.calls.append(("start_trace", session, mode))
            entered.set()
            proceed.wait(2.0)
            return 0x1111

    adv = SlowAdv()
    c = etw.EtwConsumer("race", providers=("process",), advapi32=adv, tdh=FakeTdh())
    starter = threading.Thread(target=c.start)
    starter.start()
    try:
        assert entered.wait(2.0)
        table = SessionTable([c.session])
        assert etw.reclaim_stale_sessions(table, pid_alive=lambda pid: False) == []
        assert table.stops == []
    finally:
        proceed.set()
        starter.join(2.0)
    assert adv.delivered.wait(2.0)
    c.stop()
    assert c not in etw._live_consumers()


def test_a_failed_start_trace_leaves_nothing_in_the_live_set():
    class NoStart(FakeAdvapi32):
        def start_trace(self, session, mode):
            raise etw.EtwError("StartTraceW failed (5)")

    c = etw.EtwConsumer("fw", providers=("process",), advapi32=NoStart(), tdh=FakeTdh())
    with pytest.raises(etw.EtwError):
        c.start()
    assert c not in etw._live_consumers() and c.session not in etw._live_sessions() and not c._started


@pytest.mark.skipif(sys.platform != "win32", reason="GetProcessTimes and the process list are Windows'")
def test_this_process_s_creation_time_reads_the_same_both_ways():
    # read-only, of this test process alone: GetProcessTimes and the system's process list (the fallback for a
    # process this one may not open) give the same whole seconds since 1601, above 2**32 so a name never reads it as
    # a pid; and the pid of no process gives no time.
    from liminal_libs import proc
    me = os.getpid()
    ctime = etw._process_ctime(me)
    assert ctime is not None and ctime >= 2 ** 32
    assert ctime == proc.started(me) // 10 ** 7
    assert etw._listed_ctimes().get(me) == ctime
    assert etw._listed_ctime(me) == ctime
    assert etw._process_ctime(0) is None


# -- F8: the running processes are rundown so pre-existing ones are named -------------------------------------

def test_start_requests_a_process_rundown():
    # regression (F8): after enabling Kernel-Process, EnableTraceEx2 is called again with the capture-state code,
    # so a process already running when the watch starts is enumerated (event 15) and can be named.
    adv = FakeAdvapi32()
    c = etw.EtwConsumer("fw", providers=("network", "process"), advapi32=adv, tdh=FakeTdh())
    c.start()
    assert adv.delivered.wait(2.0)
    assert ("capture_state", etw.PROVIDERS["process"][0]) in adv.calls
    c.stop()


def test_no_rundown_when_the_process_provider_is_not_enabled():
    adv = FakeAdvapi32()
    c = etw.EtwConsumer("fw", providers=("registry",), advapi32=adv, tdh=FakeTdh())
    c.start()
    assert adv.delivered.wait(2.0)
    assert not any(k == "capture_state" for k, *_ in adv.calls)
    c.stop()


# -- F2: a stop() that lands during start() still stops the session ------------------------------------------

def test_stop_during_start_stops_the_session_and_leaves_no_thread():
    # regression (F2): with no lock the old code let a stop() that arrived while StartTraceW was in flight skip the
    # teardown, leaving the ETW session and thread running with no way to stop them. Now start() and stop() share
    # one lifecycle lock: the stop waits for the session to come up, then stops it.
    entered = threading.Event()
    proceed = threading.Event()

    class RaceAdv(FakeAdvapi32):
        def start_trace(self, session, mode):
            self.calls.append(("start_trace", session, mode))
            entered.set()           # start() holds the lifecycle lock and is inside StartTraceW
            proceed.wait(2.0)       # the test releases us once a stop() is waiting on the lock
            return 0x1111

    adv = RaceAdv([_rec(1)])
    c = etw.EtwConsumer("race", providers=("process",), advapi32=adv, tdh=FakeTdh())
    start_thread = threading.Thread(target=c.start)
    stop_thread = threading.Thread(target=c.stop)
    start_thread.start()
    assert entered.wait(2.0)
    stop_thread.start()             # blocks on the lifecycle lock that start() holds
    time.sleep(0.1)                 # let the stop() reach the lock
    proceed.set()                   # StartTraceW returns; start() finishes and releases the lock; stop() proceeds
    start_thread.join(2.0)
    stop_thread.join(2.0)
    assert c._stopped
    assert ("control_stop", c.session) in adv.calls        # the session was stopped
    assert not _thread_alive(f"etw-{c.tag}")               # and no ETW thread is left running


def test_a_stop_before_start_refuses_the_start():
    # regression (F2): a start() after a stop() opens nothing (the watch was torn down before it ran).
    adv = FakeAdvapi32([_rec(1)])
    c = etw.EtwConsumer("race", providers=("process",), advapi32=adv, tdh=FakeTdh())
    c.stop()
    c.start()
    assert "start_trace" not in _names(adv.calls)
    assert c not in list(etw._LIVE) and not c._started
    assert not _thread_alive(f"etw-{c.tag}")


# -- helpers -------------------------------------------------------------------------------------------------

def _thread_alive(name: str) -> bool:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if not any(t.name == name and t.is_alive() for t in threading.enumerate()):
            return False
        time.sleep(0.01)
    return True
