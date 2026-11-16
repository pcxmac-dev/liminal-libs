"""The Windows watch backend (liminal_libs.ebpf.windows_watch.NpcapEtwWatch): the ETW attribution of a packet
to its process, the record-and-packet to Event mapping, and the watch itself over stand-in capture and ETW. No
Npcap capture and no ETW session are ever started: `capture_factory` and `etw_factory` are injected stand-ins,
fed synthetic packets and records (the design, 2026-11-14: "Stand-in runners, readers and packets are used")."""
from __future__ import annotations

import inspect
import threading
import time

from liminal_libs.capture import Flags, Packet
from liminal_libs.ebpf import windows_watch as ww
from liminal_libs.ebpf.watch import Watch
from liminal_libs.machines.etw import EtwRecord


# -- which providers each kind needs -------------------------------------------------------------------------

def test_providers_for_the_kinds():
    assert ww.NpcapEtwWatch._providers_for({"net"}) == ("network", "process")
    assert ww.NpcapEtwWatch._providers_for({"process"}) == ("process",)
    assert ww.NpcapEtwWatch._providers_for({"file"}) == ("file",)
    assert ww.NpcapEtwWatch._providers_for({"registry"}) == ("registry",)
    assert ww.NpcapEtwWatch._providers_for({"net", "file"}) == ("file", "network", "process")
    assert ww.NpcapEtwWatch._providers_for(set()) == ()


# -- the attribution tables ----------------------------------------------------------------------------------

def _proc(pid, image):
    return EtwRecord(at=1.0, provider="process", event_id=1, opcode=0, pid=pid, props={"ImageName": image})


def _net(pid, saddr, sport, daddr, dport):
    return EtwRecord(at=1.0, provider="network", event_id=12, opcode=0, pid=pid,
                     props={"PID": pid, "saddr": saddr, "sport": sport, "daddr": daddr, "dport": dport})


def test_attribution_names_a_program_for_a_pid():
    a = ww.Attribution()
    a.note_process(_proc(1000, "C:/tools/curl.exe"))
    assert a.program_of(1000) == "curl.exe"
    assert a.program_of(1) == "" and a.program_of(None) == ""


def test_attribution_joins_a_packet_to_its_pid_and_program():
    a = ww.Attribution()
    a.note_process(_proc(1000, "C:/tools/curl.exe"))
    a.note_network(_net(1000, "10.0.0.2", 51000, "93.1.2.3", 443))
    # the full connection, either orientation, resolves to the pid and program
    assert a.for_packet(("10.0.0.2", 51000), ("93.1.2.3", 443)) == (1000, "curl.exe")
    assert a.for_packet(("93.1.2.3", 443), ("10.0.0.2", 51000)) == (1000, "curl.exe")
    # a half-known flow still resolves by one endpoint
    assert a.for_packet(("10.0.0.2", 51000), ("8.8.8.8", 53)) == (1000, "curl.exe")
    # an unseen flow is not attributed
    assert a.for_packet(("10.0.0.9", 1), ("1.1.1.1", 9)) == (None, None)
    # a local-only packet (no remote address) is never attributed
    assert a.for_packet(("10.0.0.2", 51000), (None, None)) == (None, None)


def test_attribution_tables_are_bounded_and_drop_the_least_recently_used():
    a = ww.Attribution(cap=2)
    for pid in (1, 2, 3):
        a.note_process(_proc(pid, f"p{pid}.exe"))
    assert a.program_of(1) == ""          # evicted (cap 2)
    assert a.program_of(2) == "p2.exe" and a.program_of(3) == "p3.exe"
    a.program_of(2)                        # touch 2 so 3 is now the oldest
    a.note_process(_proc(4, "p4.exe"))
    assert a.program_of(3) == "" and a.program_of(2) == "p2.exe" and a.program_of(4) == "p4.exe"


# -- the record / packet to Event mapping --------------------------------------------------------------------

def test_event_fields_from_an_etw_process_record():
    rec = EtwRecord(at=2.0, provider="process", event_id=1, opcode=0, pid=1000,
                    props={"ImageName": "C:/a/b.exe", "ParentProcessID": 4, "CommandLine": "b.exe --go"})
    f = ww.event_fields_from_etw(rec, ww.Attribution())
    assert f["kind"] == "process" and f["action"] == "start" and f["pid"] == 1000 and f["ppid"] == 4
    assert f["program"] == "b.exe" and f["path"] == "C:/a/b.exe" and f["extra"]["command_line"] == "b.exe --go"
    # an unknown opcode falls back to a plain "event-<id>"
    other = EtwRecord(at=2.0, provider="process", event_id=99, opcode=0, pid=1, props={})
    assert ww.event_fields_from_etw(other, ww.Attribution())["action"] == "event-99"


def test_event_fields_from_file_and_registry_records_attribute_the_program():
    a = ww.Attribution()
    a.note_process(_proc(1000, "C:/tools/curl.exe"))
    frec = EtwRecord(at=2.0, provider="file", event_id=12, opcode=0, pid=1000, props={"FileName": "C:/t/x.dat"})
    f = ww.event_fields_from_etw(frec, a)
    assert f["kind"] == "file" and f["action"] == "create" and f["path"] == "C:/t/x.dat" and f["program"] == "curl.exe"
    rrec = EtwRecord(at=2.0, provider="registry", event_id=5, opcode=0, pid=1000,
                     props={"KeyName": "HKLM/Software/X", "ValueName": "Start"})
    r = ww.event_fields_from_etw(rrec, a)
    assert r["kind"] == "registry" and r["action"] == "set" and r["path"] == "HKLM/Software/X"
    assert r["extra"] == {"value": "Start"} and r["program"] == "curl.exe"


def test_a_network_record_is_for_attribution_only_not_an_event():
    rec = _net(1000, "10.0.0.2", 51000, "93.1.2.3", 443)
    assert ww.event_fields_from_etw(rec, ww.Attribution()) is None


def test_event_fields_from_a_packet_carry_direction_and_attribution():
    a = ww.Attribution()
    a.note_process(_proc(1000, "C:/tools/curl.exe"))
    a.note_network(_net(1000, "10.0.0.2", 51000, "93.1.2.3", 443))
    out = Packet(1.0, "10.0.0.2", 51000, "93.1.2.3", 443, Flags("SYN"), 4, "tcp", 74, "out")
    f = ww.event_fields_from_packet(out, a)
    assert f["kind"] == "net" and f["action"] == "out" and f["local"] == "10.0.0.2:51000"
    assert f["remote"] == "93.1.2.3:443" and f["proto"] == "tcp" and f["bytes"] == 74
    assert f["pid"] == 1000 and f["program"] == "curl.exe" and f["extra"]["flags"] == int(Flags("SYN"))
    # an inbound packet: local is the destination (this machine), remote the source
    inbound = Packet(1.0, "8.8.8.8", 53, "10.0.0.2", 55000, Flags(), 4, "udp", 90, "in")
    g = ww.event_fields_from_packet(inbound, ww.Attribution())
    assert g["action"] == "in" and g["local"] == "10.0.0.2:55000" and g["remote"] == "8.8.8.8:53"
    assert g["pid"] is None and g["program"] == "" and g["proto"] == "udp"


# -- stand-in capture and ETW --------------------------------------------------------------------------------

class FakeEtw:
    """A stand-in ETW consumer: `feed` queues records, `drain` returns and clears them. No session is started."""

    def __init__(self, providers):
        self.providers = tuple(providers)
        self._q: list = []
        self._lock = threading.Lock()
        self.started = self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def feed(self, *records):
        with self._lock:
            self._q.extend(records)

    def drain(self, limit=None):
        with self._lock:
            out, self._q = self._q, []
            return out


class FakeCapture:
    """A stand-in capture: the watch sets `on_packet`; `feed` hands a packet to it as a live adapter would. No
    adapter is opened."""

    def __init__(self):
        self.on_packet = None
        self.started = self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def feed(self, packet):
        if self.on_packet is not None:
            self.on_packet(packet)


def _wait(predicate, seconds=3.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def _make(kinds, *, timeout=5.0, ring=2000):
    etw = {"ref": None}
    cap = {"ref": None}

    def etw_factory(providers):
        etw["ref"] = FakeEtw(providers)
        return etw["ref"]

    def capture_factory():
        cap["ref"] = FakeCapture()
        return cap["ref"]

    w = ww.NpcapEtwWatch(kinds, {"poll": 0.01, "tag": "t", "address": "10.0.0.2"},
                         capture_factory=capture_factory, etw_factory=etw_factory, timeout=timeout, ring=ring)
    return w, etw, cap


# -- the watch ------------------------------------------------------------------------------------------------

def test_the_watch_is_a_watch_and_starts_both_sources():
    w, etw, cap = _make({"net", "process"})
    assert isinstance(w, Watch)
    w.start()
    assert _wait(lambda: etw["ref"] is not None and etw["ref"].started)
    assert cap["ref"] is not None and cap["ref"].started
    assert etw["ref"].providers == ("network", "process")
    w.stop()
    assert etw["ref"].stopped and cap["ref"].stopped


def test_the_watch_emits_process_events_and_attributed_net_events():
    w, etw, cap = _make({"net", "process"})
    w.start()
    assert _wait(lambda: etw["ref"] is not None and cap["ref"] is not None)
    etw["ref"].feed(_proc(1000, "C:/tools/curl.exe"),
                    _net(1000, "10.0.0.2", 51000, "93.1.2.3", 443))
    assert _wait(lambda: w.read(0)[0] >= 1)  # the process event lands
    cap["ref"].feed(Packet(1.0, "10.0.0.2", 51000, "93.1.2.3", 443, Flags("SYN"), 4, "tcp", 74, "out"))
    assert _wait(lambda: any(e.kind == "net" for e in w.read(0)[1]))
    seq, events = w.read(0)
    kinds = [e.kind for e in events]
    assert "process" in kinds and "net" in kinds
    net = next(e for e in events if e.kind == "net")
    assert net.pid == 1000 and net.program == "curl.exe" and net.remote == "93.1.2.3:443"
    proc = next(e for e in events if e.kind == "process")
    assert proc.action == "start" and proc.pid == 1000
    w.stop()


def test_a_net_only_watch_uses_process_records_to_attribute_but_does_not_emit_them():
    w, etw, cap = _make({"net"})
    w.start()
    assert _wait(lambda: etw["ref"] is not None and cap["ref"] is not None)
    # the process provider is still enabled, for attribution
    assert etw["ref"].providers == ("network", "process")
    etw["ref"].feed(_proc(1000, "C:/tools/curl.exe"),
                    _net(1000, "10.0.0.2", 51000, "93.1.2.3", 443))
    cap["ref"].feed(Packet(1.0, "10.0.0.2", 51000, "93.1.2.3", 443, Flags("SYN"), 4, "tcp", 74, "out"))
    assert _wait(lambda: w.read(0)[0] >= 1)
    seq, events = w.read(0)
    assert [e.kind for e in events] == ["net"]  # the process record attributed but was not emitted
    assert events[0].program == "curl.exe"
    w.stop()


def test_read_since_a_sequence_returns_only_the_newer_events():
    w, etw, _ = _make({"process"})
    w.start()
    assert _wait(lambda: etw["ref"] is not None)
    etw["ref"].feed(_proc(1, "a.exe"), _proc(2, "b.exe"))
    assert _wait(lambda: w.read(0)[0] == 2)
    seq, events = w.read(0)
    assert seq == 2 and len(events) == 2
    assert [e.pid for e in w.read(1)[1]] == [2]  # only the one after seq 1
    w.stop()


def test_the_ring_is_bounded():
    w, etw, _ = _make({"process"}, ring=3)
    w.start()
    assert _wait(lambda: etw["ref"] is not None)
    etw["ref"].feed(*[_proc(i, f"p{i}.exe") for i in range(5)])
    assert _wait(lambda: w.read(0)[0] == 5)
    seq, events = w.read(0)
    assert seq == 5 and [e.seq for e in events] == [3, 4, 5]  # only the last three kept
    w.stop()


def test_the_watch_stops_itself_after_its_timeout_and_leaves_no_thread():
    w, etw, cap = _make({"net", "process"}, timeout=0.15)
    w.start()
    assert _wait(lambda: etw["ref"] is not None and cap["ref"] is not None)
    etw["ref"].feed(_proc(1, "a.exe"))
    assert _wait(lambda: w.read(0)[0] == 1)
    assert _wait(lambda: w.stopped, seconds=3.0), "self-stopped after the viewing timeout"
    assert etw["ref"].stopped and cap["ref"].stopped
    assert _wait(lambda: not any(t.name in ("npcap-etw-watch", "ebpf-watch") and t.is_alive()
                                 for t in threading.enumerate())), "no watcher thread left behind"


def test_stop_is_idempotent_and_a_read_keeps_it_alive():
    w, etw, cap = _make({"net", "process"}, timeout=0.2)
    w.start()
    assert _wait(lambda: etw["ref"] is not None)
    for _ in range(6):  # read across more than the timeout: it must not self-stop while read
        time.sleep(0.05)
        w.read(0)
        assert not w.stopped
    w.stop()
    assert w.stopped and etw["ref"].stopped
    w.stop()  # idempotent


def test_an_unopenable_source_is_said_and_the_watch_stops_cleanly():
    def bad_etw(providers):
        raise RuntimeError("no ETW session here")
    w = ww.NpcapEtwWatch({"net", "process"}, {"poll": 0.01},
                         capture_factory=lambda: FakeCapture(), etw_factory=bad_etw, timeout=5.0)
    w.start()
    assert _wait(lambda: w.stopped)
    assert "no ETW session" in w.error
    assert _wait(lambda: not any(t.name == "npcap-etw-watch" and t.is_alive() for t in threading.enumerate()))


# -- a source lost after it opened (1.60.0) ------------------------------------------------------------------

class EndingCapture(FakeCapture):
    """A stand-in capture with the real one's `running` and `error`: `end(why)` is its reading ending by itself
    (an adapter removed, a read failing), as the real one's thread does."""

    def __init__(self):
        super().__init__()
        self.running, self.error = False, ""

    def start(self):
        super().start()
        self.running = True

    def end(self, why=""):
        self.error, self.running = why, False

    def stop(self):
        super().stop()
        self.running = False


class EndingEtw(FakeEtw):
    """A stand-in ETW consumer with the real one's `running` and `error`: `end(why)` is the session ending under
    it (stopped from outside, the consumer failing)."""

    def __init__(self, providers):
        super().__init__(providers)
        self.running, self.error = False, ""

    def start(self):
        super().start()
        self.running = True

    def end(self, why=""):
        self.error, self.running = why, False

    def stop(self):
        super().stop()
        self.running = False


def _make_ending(kinds):
    refs: dict = {}
    w = ww.NpcapEtwWatch(kinds, {"poll": 0.01, "tag": "t", "address": "10.0.0.2"},
                         capture_factory=lambda: refs.setdefault("cap", EndingCapture()),
                         etw_factory=lambda p: refs.setdefault("etw", EndingEtw(p)), timeout=5.0)
    return w, refs


def _no_watch_thread():
    return _wait(lambda: not any(t.name == "npcap-etw-watch" and t.is_alive() for t in threading.enumerate()))


def test_a_capture_lost_after_it_opened_is_said_and_the_watch_stops():
    # the reviewers' finding: an adapter gone under a net watch left it live, its reads empty, as a quiet machine
    for why, said in (("the adapter is gone", "the capture stopped: the adapter is gone"),
                      ("", "the capture stopped: its reading of the adapter ended")):
        w, refs = _make_ending({"net", "process"})
        w.start()
        assert _wait(lambda: "cap" in refs and refs["cap"].running and "etw" in refs)
        refs["etw"].feed(_proc(1000, "C:/tools/curl.exe"))
        assert _wait(lambda: w.read(0)[0] == 1)
        refs["cap"].end(why)
        assert _wait(lambda: w.stopped), "the watch stops itself"
        assert _no_watch_thread()  # the pump ends after its own teardown: stop() sets the flag before it closes
        assert w.error == said
        assert refs["etw"].stopped and refs["cap"].stopped  # the other source is closed too
        assert [e.pid for e in w.read(0)[1]] == [1000]  # what came before is still read


def test_an_etw_session_lost_after_it_opened_is_said_and_the_watch_stops():
    for why, said in (("the session was stopped from outside", "the ETW session ended: the session was stopped from "
                                                                "outside"),
                      ("", "the ETW session ended: its consumer stopped reading")):  # a consumer giving no reason
        w, refs = _make_ending({"process", "file"})
        w.start()
        assert _wait(lambda: "etw" in refs and refs["etw"].running)
        refs["etw"].end(why)
        assert _wait(lambda: w.stopped)
        assert _no_watch_thread()  # the pump ends after its own teardown
        assert w.error == said
        assert refs["etw"].stopped and "cap" not in refs  # no capture for a watch without net


def test_a_capture_ending_under_a_watch_without_net_is_not_its_loss():
    # only a net watch reads the capture; the others never open one, and a stand-in left about is not theirs
    w, refs = _make_ending({"process"})
    w.start()
    assert _wait(lambda: "etw" in refs and refs["etw"].running)
    w._capture = EndingCapture()  # a capture the watch does not read (never opened for process alone)
    w._capture.end("not this watch's")
    time.sleep(0.1)
    assert not w.stopped and w.error == ""
    w.stop()


def test_a_watch_stopped_on_purpose_says_no_loss_though_its_sources_then_stop():
    for _ in range(20):  # the pump may be anywhere in its loop when the stop lands: never said as a loss
        w, refs = _make_ending({"net", "process"})
        w.start()
        assert _wait(lambda: "cap" in refs and refs["cap"].running and "etw" in refs)
        w.stop()
        assert w.stopped and w.error == "" and not refs["cap"].running and not refs["etw"].running
    assert _no_watch_thread()


def test_after_a_stop_its_closed_sources_are_no_loss():
    # the guard itself, not left to a race the loop above may never hit: once a stop has begun, the sources it closed
    # are never said as lost
    w, refs = _make_ending({"net", "process"})
    w.start()
    assert _wait(lambda: "cap" in refs and refs["cap"].running and "etw" in refs)
    w.stop()
    assert not refs["cap"].running and not refs["etw"].running
    assert w._source_lost() == "" and w.error == ""
    assert _no_watch_thread()


class StopLandsOnRead(EndingCapture):
    """A source whose `running` is read just as a stop lands: the read sets the watch's stop flag (as stop() does,
    before it closes anything), then answers False, as the source it closes would."""

    def __init__(self, watch):
        super().__init__()
        self.watch = watch

    @property
    def running(self):
        self.watch._stop.set()
        return False

    @running.setter
    def running(self, value):
        pass


def test_a_stop_landing_while_the_sources_are_read_is_no_loss():
    # _source_lost reads the sources first and the stop flag after (the 1.60.0 CHANGELOG's guarantee): a stop that
    # lands between the two is seen, for the capture of a net watch and for the ETW session of any
    for kinds, held in (({"net"}, "_capture"), ({"process"}, "_etw")):
        w, _ = _make_ending(kinds)  # not started: the reads alone are asked
        setattr(w, held, StopLandsOnRead(w))
        assert w._source_lost() == "", kinds
        assert w._stop.is_set()  # the stop did land during the read


def test_a_stand_in_source_without_running_is_taken_as_running():
    w, etw, cap = _make({"net", "process"})  # the plain stand-ins have no `running`
    w.start()
    assert _wait(lambda: etw["ref"] is not None and cap["ref"] is not None)
    time.sleep(0.1)  # several polls
    assert not w.stopped and w.error == "" and w._source_lost() == ""
    w.stop()


# -- available() ---------------------------------------------------------------------------------------------

def test_available_reports_both_sources(monkeypatch):
    monkeypatch.setattr(ww.capturemod, "available", lambda: (True, "Npcap"))
    monkeypatch.setattr(ww.etwmod, "available", lambda: (True, "elevated"))
    assert ww.available() == (True, "Npcap and ETW")
    monkeypatch.setattr(ww.capturemod, "available", lambda: (False, "no Npcap"))
    assert ww.available() == (False, "no Npcap")
    monkeypatch.setattr(ww.capturemod, "available", lambda: (True, "Npcap"))
    monkeypatch.setattr(ww.etwmod, "available", lambda: (False, "not elevated"))
    assert ww.available() == (False, "not elevated")


# -- F4: Kernel-Process records name the right pid -----------------------------------------------------------

def test_a_process_start_names_the_child_not_the_creator():
    # regression (F4): ProcessStart (event 1) is raised in the creator's context, so the EVENT_HEADER pid is the
    # creator and the new process is the ProcessID property. Naming must follow ProcessID.
    a = ww.Attribution()
    start = EtwRecord(1.0, "process", 1, 1, pid=5000,  # header pid 5000 = explorer, the creator
                      props={"ProcessID": 9000, "ParentProcessID": 5000,
                             "ImageName": r"\Device\HarddiskVolume3\Windows\System32\curl.exe"})
    a.note_process(start)
    assert a.program_of(9000) == "curl.exe"   # the child is named
    assert a.program_of(5000) == ""           # the creator is NOT renamed after its child
    f = ww.event_fields_from_etw(start, a)
    assert f["pid"] == 9000 and f["ppid"] == 5000 and f["program"] == "curl.exe"


def test_an_image_load_does_not_rename_the_loading_process():
    # regression (F4): an ImageLoad (event 5) has the DLL as ImageName. It must not rename the process after the
    # DLL; the event belongs to the loading process, with the DLL as its path.
    a = ww.Attribution()
    a.note_process(EtwRecord(1.0, "process", 1, 1, pid=1, props={"ProcessID": 9000, "ImageName": "curl.exe"}))
    img = EtwRecord(1.1, "process", 5, 10, pid=9000,
                    props={"ProcessID": 9000, "ImageName": r"C:/Windows/System32/ws2_32.dll"})
    a.note_process(img)                         # an image record names nobody
    assert a.program_of(9000) == "curl.exe"     # still curl, not ws2_32.dll
    f = ww.event_fields_from_etw(img, a)
    assert f["action"] == "image" and f["program"] == "curl.exe" and f["path"].endswith("ws2_32.dll")


def test_a_rundown_record_names_a_process_that_was_already_running():
    # regression (F8): event 15 (ProcessRundown) carries a pre-existing process in ProcessID; it names that pid.
    a = ww.Attribution()
    a.note_process(EtwRecord(1.0, "process", 15, 0, pid=0,
                             props={"ProcessID": 4000, "ImageName": r"C:/Windows/explorer.exe"}))
    assert a.program_of(4000) == "explorer.exe"


# -- F7: a flow's first packets are not given to the wrong process -------------------------------------------

def test_for_packet_never_attributes_by_the_remote_endpoint():
    # regression (F7): the remote endpoint of a popular server (ip:port) is shared by many flows. A different
    # flow to the same server must not inherit the first flow's process.
    a = ww.Attribution()
    a.note_process(_proc(100, "chrome.exe"))
    a.note_network(_net(100, "10.0.0.2", 50000, "13.107.42.14", 443))
    assert a.for_packet(("10.0.0.2", 50001), ("13.107.42.14", 443)) == (None, None)  # another local port
    assert a.for_packet(("10.0.0.2", 3389), ("13.107.42.14", 443)) == (None, None)   # an inbound to another port
    assert a.for_packet(("10.0.0.2", 50000), ("13.107.42.14", 443)) == (100, "chrome.exe")  # the exact flow still


# -- F5: the default capture gathers what the Filter tab needs -----------------------------------------------

def test_the_default_capture_gathers_udp_payloads_and_every_address_family():
    w = ww.NpcapEtwWatch({"net"}, {"address": "10.0.0.2"})
    c = w._default_capture()  # builds a Capture object; no adapter is opened
    assert c.udp is True and c.payloads is True and c.host is False
    w2 = ww.NpcapEtwWatch({"net"}, {"address": "10.0.0.2", "udp": False, "payloads": False, "host": True})
    c2 = w2._default_capture()
    assert c2.udp is False and c2.payloads is False and c2.host is True  # the spec overrides each


# -- F11: the self-stop timer runs on a monotonic clock ------------------------------------------------------

def test_the_watch_uses_a_monotonic_clock_by_default():
    # regression (F11): the base uses the watch's clock for the idle timer. A wall clock can step back (w32time,
    # a manual change), delaying the self-stop while the ETW session and capture keep running. Default to monotonic.
    default = inspect.signature(ww.NpcapEtwWatch.__init__).parameters["clock"].default
    assert default is time.monotonic


# -- F6: net events are per flow, so a download cannot flood the shared ring ---------------------------------

def test_net_flooding_does_not_evict_the_rare_process_event():
    # regression (F6): the old code emitted one Event per packet into the single shared ring, so a download
    # overwrote the rare process/file/registry events within one tab poll. Now net is aggregated per flow.
    w, etw, cap = _make({"net", "process"}, ring=8)
    w.start()
    assert _wait(lambda: etw["ref"] is not None and cap["ref"] is not None)
    etw["ref"].feed(_proc(1, "svchost.exe"), _net(1, "10.0.0.2", 52000, "203.0.113.9", 443))
    cap["ref"].feed(Packet(1.0, "10.0.0.2", 52000, "203.0.113.9", 443, Flags("SYN"), 4, "tcp", 74, "out"))
    for _ in range(3000):  # ~4.5 MB of a download in one flow
        cap["ref"].feed(Packet(1.0, "203.0.113.9", 443, "10.0.0.2", 52000, Flags("ACK"), 4, "tcp", 1514, "in"))
    assert _wait(lambda: w.read(0)[0] >= 2)
    time.sleep(0.2)
    seq, events = w.read(0)
    kinds = [e.kind for e in events]
    assert "process" in kinds          # the process start survived the download
    assert kinds.count("net") <= 3     # a couple of flow events, not thousands
    net = next(e for e in events if e.kind == "net")
    assert net.pid == 1 and net.program == "svchost.exe"  # the flow is attributed
    assert net.bytes >= 3000 * 1514    # the flow carries the download's bytes, not one packet's
    w.stop()


def test_a_tcp_teardown_closes_the_flow():
    w, etw, cap = _make({"net"})
    w.start()
    assert _wait(lambda: etw["ref"] is not None and cap["ref"] is not None)
    etw["ref"].feed(_proc(1, "curl.exe"), _net(1, "10.0.0.2", 52000, "203.0.113.9", 443))
    cap["ref"].feed(Packet(1.0, "10.0.0.2", 52000, "203.0.113.9", 443, Flags("SYN"), 4, "tcp", 74, "out"))
    cap["ref"].feed(Packet(1.0, "203.0.113.9", 443, "10.0.0.2", 52000, Flags("FIN ACK"), 4, "tcp", 66, "in"))
    assert _wait(lambda: any(e.action == "close" for e in w.read(0)[1]))
    actions = [e.action for e in w.read(0)[1] if e.kind == "net"]
    assert "out" in actions and "close" in actions   # a start then a close
    w.stop()


# -- F3: a teardown racing the source open tears the sources down --------------------------------------------

def test_teardown_during_begin_stops_the_sources_opened_after_it():
    # regression (F3): the old teardown set _torn while _capture was still None, so a stop() that arrived while
    # _begin was opening ETW let _begin go on to open the capture, which was then never stopped. _begin's open and
    # the teardown now share one lock, so whichever runs second stops whatever the first opened.
    entered = threading.Event()
    release = threading.Event()
    refs = {}

    class SlowEtw(FakeEtw):
        def start(self):
            entered.set()
            release.wait(2.0)       # hold _begin inside etw.start(), with _src_lock held
            self.started = True

    def etw_factory(providers):
        refs["etw"] = SlowEtw(providers)
        return refs["etw"]

    def cap_factory():
        refs["cap"] = FakeCapture()
        return refs["cap"]

    w = ww.NpcapEtwWatch({"net", "process"}, {"poll": 0.05, "address": "10.0.0.2"},
                         capture_factory=cap_factory, etw_factory=etw_factory, timeout=30.0)
    begin_thread = threading.Thread(target=w._begin)
    teardown_thread = threading.Thread(target=w._teardown_sources)
    begin_thread.start()
    assert entered.wait(2.0)        # _begin holds _src_lock, inside etw.start()
    teardown_thread.start()         # blocks on _src_lock until _begin finishes opening both sources
    time.sleep(0.1)
    release.set()                   # etw.start() returns; _begin opens the capture, releases; teardown then runs
    begin_thread.join(2.0)
    teardown_thread.join(2.0)
    assert refs["etw"].stopped                          # ETW was stopped
    assert refs["cap"].stopped                          # the capture, opened after the stop, is stopped too
    w._stop.set()                                       # let the pump thread _begin started exit, then reap it
    if w._pump_thread is not None:
        w._pump_thread.join(2.0)
    assert not any(t.name == "npcap-etw-watch" and t.is_alive() for t in threading.enumerate())


def test_begin_opens_nothing_once_a_stop_has_arrived():
    # regression (F3): the other ordering — the teardown runs first, so _begin must open no source at all.
    refs = {}
    w = ww.NpcapEtwWatch({"net", "process"}, {"address": "10.0.0.2"},
                         capture_factory=lambda: refs.setdefault("cap", FakeCapture()),
                         etw_factory=lambda p: refs.setdefault("etw", FakeEtw(p)))
    w._teardown_sources()           # a stop arrived before _begin ran
    w._stop.set()
    w._begin()
    assert refs == {}               # no source was opened
    assert w._etw is None and w._capture is None
    assert w._pump_thread is None


# -- minor findings: clamps and drop counting ----------------------------------------------------------------

def test_spec_queue_and_poll_are_clamped():
    assert ww.NpcapEtwWatch({"net"}, {"queue": 0})._packets.maxlen == 1
    assert ww.NpcapEtwWatch({"net"}, {"queue": -5})._packets.maxlen == 1
    assert ww.NpcapEtwWatch({"net"}, {"queue": 10 ** 8})._packets.maxlen == ww.MAX_PACKET_QUEUE
    assert ww.NpcapEtwWatch({"net"}, {"poll": 0.0001})._poll == ww.MIN_POLL


def test_the_packet_queue_counts_what_it_drops():
    w = ww.NpcapEtwWatch({"net"}, {"queue": 4})
    for i in range(10):
        w._queue_packet(Packet(1.0, "10.0.0.2", 50000 + i, "1.2.3.4", 443, Flags("SYN"), 4, "tcp", 74, "out"))
    assert w._packets_dropped == 6 and len(w._packets) == 4  # first 4 kept, next 6 dropped (oldest)
    assert w.stats()["packets_dropped"] == 6
