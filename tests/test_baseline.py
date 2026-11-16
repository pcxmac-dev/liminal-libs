"""What is usual for this machine (liminal_libs.baseline), over flows made here and a clock the tests move: nothing is
flagged until 30 minutes of watching are learned, and only the time watched counts; then each new peer, port,
program, country and network is flagged once, a short connection with a new peer not seen again in 10 watched
minutes is a one-off, and a port's minute 8 times its usual is a spike, always in the words "unusual for this machine
while Liminal was watching". The seen table is capped (the rows longest unseen pruned first) and kept across closing
and opening, in a file under tmp_path. No capture, no process, no network: the flows are dicts."""
from __future__ import annotations

import re
import sqlite3
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from liminal_libs import baseline
from liminal_libs.baseline import UNUSUAL, Baseline, Flag, group_of, path_for

T0 = 1_800_000_000.0  # 2027-01-15 08:00:00 UTC
KB, MB = 1024, 1024 * 1024


class Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def flow(**given) -> dict:
    """An outgoing HTTPS flow of a browser, to a peer in the US on AS64500, one second long from the given start."""
    f = {"dir": "out", "remote": "203.0.113.5", "remote_port": 443, "proto": "tcp", "local_port": 50123,
         "program": "C:\\Program Files\\Browser\\browser.exe", "country": "US", "asn": 64500, "org": "Example Net",
         "bytes": 1200}
    f.update(given)
    if "start" in f and "end" not in f:
        f["end"] = f["start"] + 1
    return f


def ids(flags) -> list[str]:
    return [f.id for f in flags]


def watch_for(b: Baseline, clock: Clock, seconds: float, every: float = 2.0) -> None:
    """The tab asked every `every` seconds for `seconds`."""
    end = clock.t + seconds
    while clock.t < end:
        clock.t += every
        b.watch()


def learned(path: Path, clock: Clock, flows=(), **options) -> Baseline:
    """A baseline that has watched for its learning (30 minutes), having seen `flows` at the start."""
    b = Baseline(path, clock=clock, **options)
    b.watch()
    for f in flows:
        b.remember(f)
    watch_for(b, clock, b.learn_s)
    assert b.learned
    return b


def seen(path: Path) -> dict[str, tuple]:
    with sqlite3.connect(path) as con:
        rows = {r[0]: r[1:] for r in con.execute("SELECT key, kind, first, last, count FROM seen")}
    con.close()
    return rows


# -- the learning -------------------------------------------------------------------------------------------------

def test_nothing_is_flagged_until_thirty_minutes_of_watching_are_learned_and_learning_says_so(tmp_path):
    clock = Clock()
    with Baseline(tmp_path / "filter.db", clock=clock) as b:
        assert b.learning() == (0.0, None) and not b.learned and b.learn_s == 30 * 60
        assert b.describe()["words"] == ("Learning what is usual for this machine: 0 of 30 minutes watched. Nothing "
                                         "is flagged until then.")
        b.watch()
        assert b.observe(flow(start=T0)) == []
        watch_for(b, clock, 29 * 60)
        assert b.learning() == (29 * 60.0, T0) and not b.learned
        d = b.describe()
        assert d["learned"] is False and d["watched"] == 29 * 60 and d["needed"] == 30 * 60 and d["learned_at"] is None
        assert d["since"] == "2027-01-15T08:00:00+00:00" and "29 of 30 minutes watched" in d["words"]
        assert d["rows"] == 5 and d["cap"] == 50_000
        early = flow(remote="198.51.100.20", start=clock.t, end=clock.t + 1, program="new.exe", country="DE")
        assert b.observe(early) == [] and b.flags(early) == []  # still learning: nothing flagged

        watch_for(b, clock, 60)
        assert b.learning() == (30 * 60.0, T0) and b.learned
        assert b.flags(early) == []  # a flow that started while learning is never judged
        late = flow(remote="192.0.2.40", start=clock.t, end=clock.t + 1)
        assert ids(b.observe(late)) == ["new-peer"]
        d = b.describe()
        assert d["learned"] is True and d["learned_at"] == datetime.fromtimestamp(T0 + 1800, timezone.utc).isoformat()
        assert d["words"] == (f"Learned from 30 min of watching since 2027-01-15T08:00:00+00:00: a flag says what is "
                              f"{UNUSUAL}.")


def test_only_the_time_liminal_watches_counts(tmp_path):
    clock = Clock()
    with Baseline(tmp_path / "filter.db", clock=clock) as b:
        b.watch()
        watch_for(b, clock, 10)
        clock.t += 3600  # an hour closed: not counted, a new spell of watching
        b.watch()
        watch_for(b, clock, 20)
        assert b.learning() == (30.0, T0)
        b.watch(clock.t + 25)  # a moment given
        assert b.learning()[0] == 55.0
        b.watch(clock.t + 25)  # the same moment again: nothing more
        b.watch(clock.t)  # a moment before the latest: nothing more
        assert b.learning()[0] == 55.0
        b.remember(flow(start=clock.t + 26, end=clock.t + 30))  # a flow seen is watching too
        assert b.learning()[0] == 60.0
        b.watch(T0 + 100)  # a moment given an hour before the latest: nothing more
        assert b.learning()[0] == 60.0
        clock.t = T0 + 100  # the clock went back an hour: watching goes on from there
        b.watch()
        clock.t += 10
        b.watch()
        assert b.learning() == (70.0, T0)
        b.watch(float("nan"))
        assert b.learning()[0] == 70.0


def test_what_was_learned_under_a_clock_running_ahead_holds_once_it_is_set_right(tmp_path):
    clock = Clock(T0 + 86400)  # a day ahead
    path = tmp_path / "filter.db"
    b = learned(path, clock, [flow(start=clock.t)])
    clock.t = T0  # set right
    b.watch()
    assert b.learned and b.learning() == (30 * 60.0, T0)
    assert b.observe(flow(start=clock.t + 2)) == []  # its peer, port, program, country and network are not new
    assert ids(b.observe(flow(remote="198.51.100.20", start=clock.t + 4))) == ["new-peer"]
    assert all(last <= T0 + 5 for _, _, last, _ in seen(path).values())  # nothing seen "tomorrow"
    b.close()


# -- the flags ----------------------------------------------------------------------------------------------------

def test_each_new_thing_is_flagged_and_in_plain_words(tmp_path):
    clock = Clock()
    path = tmp_path / "filter.db"
    b = learned(path, clock, [flow(start=T0), flow(dir="in", local_port=3389, remote_port=51000, start=T0,
                                                   remote="203.0.113.9", program="System")])
    t = clock.t
    told_flows: list[dict] = []

    def told(**given) -> list[Flag]:
        nonlocal t
        t += 1
        told_flows.append(flow(**{"start": t, **given}))
        return b.observe(told_flows[-1])

    assert told() == []  # all of it known
    assert told(remote="203.0.113.77") == []  # the same /24: the same peer
    assert told(local_port=61000) == []  # an outgoing flow's passing port is no port of its own
    assert told(program="c:\\program files\\browser\\BROWSER.EXE", asn="AS64500", country="us") == []
    assert told(dir="in", local_port=3389, remote_port=52000, remote="203.0.113.9", program="System") == []

    new_peer = told(remote="198.51.100.20")
    new_peer_flow = told_flows[-1]
    assert ids(new_peer) == ["new-peer"]
    assert new_peer[0].words == f"First contact with 198.51.100.0/24 (198.51.100.20): {UNUSUAL}."
    new_port = told(remote_port=6667)
    assert ids(new_port) == ["new-port"]
    assert new_port[0].words == f"Traffic out to port 6667/tcp for the first time: {UNUSUAL}."
    served = told(dir="in", local_port=22, remote_port=52001, remote="203.0.113.9", program="System")
    assert ids(served) == ["new-port"]
    assert served[0].words == f"Traffic in on port 22/tcp for the first time: {UNUSUAL}."
    new_program = told(program="C:\\Tools\\odd.exe")
    assert ids(new_program) == ["new-program"]
    assert new_program[0].words == f"C:\\Tools\\odd.exe on the network for the first time: {UNUSUAL}."
    new_country = told(country="DE")
    assert ids(new_country) == ["new-country"]
    assert new_country[0].words == f"First traffic with a peer in DE: {UNUSUAL}."
    new_asn = told(asn=64501, org="Other Net")
    assert ids(new_asn) == ["new-asn"]
    assert new_asn[0].words == f"First traffic with the network AS64501 (Other Net): {UNUSUAL}."
    everything = told(remote="2001:db8:77::5", remote_port=8443, program="C:\\Tools\\new.exe", country="NL", asn=64502)
    assert ids(everything) == ["new-peer", "new-port", "new-program", "new-country", "new-asn"]
    assert everything[0].words == f"First contact with 2001:db8:77::/48 (2001:db8:77::5): {UNUSUAL}."

    assert told(remote="198.51.100.21", remote_port=6667, program="C:\\Tools\\odd.exe", country="DE", asn=64501) == []
    later = told_flows[-1]
    assert told(remote="2001:db8:77:ffff::1") == []  # the same /48
    assert told(remote="::ffff:198.51.100.22") == []  # IPv4 written as IPv6
    assert told(remote="192.0.2.1", remote_group="198.51.100.0/24") == []  # the group given is the peer

    assert b.flags(new_peer_flow) == new_peer  # asked again, later: it says the same
    assert b.flags(later) == []  # and a later flow with those says nothing
    for flag in new_peer + new_port + served + new_program + new_country + new_asn + everything:
        assert UNUSUAL in flag.words and "malicious" not in flag.words.lower()
        assert flag.as_dict() == {"id": flag.id, "words": flag.words} and flag.id in baseline.FLAGS
    b.close()


def test_the_machine_talking_to_itself_is_never_kept(tmp_path):
    clock = Clock()
    with Baseline(tmp_path / "filter.db", clock=clock) as b:
        for f in (flow(dir="local", start=T0), flow(remote="127.0.0.1", start=T0), flow(remote="::1", start=T0),
                  flow(remote="0.0.0.0", start=T0), "not a flow", None):
            b.remember(f)
            assert b.flags(f) == [] and b.observe(f) == []
        assert b.rows == 0 and b.learning() == (0.0, None)


def test_a_short_connection_with_a_new_peer_not_seen_again_in_ten_watched_minutes_is_a_one_off(tmp_path):
    clock = Clock()
    b = learned(tmp_path / "filter.db", clock, [flow(start=T0)])
    t = clock.t
    once = flow(remote="198.51.100.20", start=t, end=t + 2)
    repeated = flow(remote="192.0.2.30", start=t, end=t + 2)
    long = flow(remote="198.18.5.5", start=t - 300, end=t)  # five minutes long: no short connection
    known = flow(start=t, end=t + 2)  # a peer seen before
    assert all("one-off" not in ids(b.observe(f)) for f in (once, repeated, long, known))  # not known yet
    watch_for(b, clock, 5 * 60)
    b.observe(flow(remote="192.0.2.31", start=clock.t))  # repeated's peer again, within its ten minutes
    watch_for(b, clock, 4 * 60)
    assert "one-off" not in ids(b.flags(once))  # nine watched minutes: not yet
    clock.t += 3600  # the watching stopped for an hour: those minutes are not watched
    b.watch()
    watch_for(b, clock, 30)
    assert "one-off" not in ids(b.flags(once))
    watch_for(b, clock, 40)
    flags = b.flags(once)
    assert ids(flags) == ["new-peer", "one-off"]
    assert flags[1].words == (f"One short connection (2.0 s) with 198.51.100.20, a peer not seen before and not again "
                              f"in the 10 min watched after it: {UNUSUAL}.")
    assert "one-off" not in ids(b.flags(repeated)) and "one-off" not in ids(b.flags(long))
    assert b.flags(known) == []
    b.observe(flow(remote="198.51.100.99", start=clock.t))  # its peer comes back after its ten minutes
    assert ids(b.flags(once)) == ["new-peer", "one-off"]  # a one-off it stays
    b.close()


def test_a_one_off_not_asked_about_in_its_ten_minutes_is_still_one_when_its_peer_comes_back_later(tmp_path):
    clock = Clock()
    b = learned(tmp_path / "filter.db", clock, [flow(start=T0)])
    once = flow(remote="198.51.100.20", start=clock.t, end=clock.t + 1)
    soon = flow(remote="192.0.2.20", start=clock.t, end=clock.t + 1)
    b.observe(once)
    b.observe(soon)
    watch_for(b, clock, 60)
    b.observe(flow(remote="192.0.2.21", start=clock.t))  # soon's peer again, a minute after
    watch_for(b, clock, 10 * 60)
    b.observe(flow(remote="198.51.100.21", start=clock.t))  # once's peer again, eleven watched minutes after
    assert ids(b.flags(once)) == ["new-peer", "one-off"]
    assert ids(b.flags(soon)) == ["new-peer"]
    b.close()


def test_a_ports_minute_eight_times_its_usual_is_a_spike(tmp_path):
    clock = Clock()
    b = learned(tmp_path / "filter.db", clock, [flow(start=T0)])
    for _ in range(10):  # ten minutes of what is usual: 100 KB a minute out to port 443
        watch_for(b, clock, 60)
        assert "spike" not in ids(b.observe(flow(start=clock.t - 1, end=clock.t, bytes=100 * KB)))
    watch_for(b, clock, 120)  # two quiet minutes: minutes without traffic say nothing of what is usual
    big = flow(start=clock.t, end=clock.t + 1, bytes=MB)
    flags = b.observe(big)
    assert ids(flags) == ["spike"]
    assert flags[0].words == (f"1.0 MB out to port 443/tcp in the last minute, 10 times its usual 100.0 KB a minute: "
                              f"{UNUSUAL}.")
    watch_for(b, clock, 10)
    assert b.flags(big) == flags  # asked again: the same
    watch_for(b, clock, 120)
    assert "spike" not in ids(b.observe(flow(start=clock.t, bytes=500 * KB)))  # five times: no spike
    watch_for(b, clock, 120)
    second = b.observe(flow(start=clock.t, bytes=300 * KB))  # a flow told again with more bytes: they count once
    assert "spike" not in ids(second)
    assert ids(b.observe(flow(start=clock.t, end=clock.t + 2, bytes=900 * KB))) == ["spike"]

    for _ in range(10):  # another port, 1 KB a minute: 60 KB is 60 times that, but under the floor
        b.observe(flow(remote_port=8443, start=clock.t, bytes=KB))
        watch_for(b, clock, 60)
    watch_for(b, clock, 120)
    assert "spike" not in ids(b.observe(flow(remote_port=8443, start=clock.t, bytes=60 * KB)))
    for _ in range(3):  # a third port: three busy minutes say nothing of what is usual
        b.observe(flow(remote_port=993, start=clock.t, bytes=KB))
        watch_for(b, clock, 60)
    watch_for(b, clock, 120)
    assert "spike" not in ids(b.observe(flow(remote_port=993, start=clock.t, bytes=MB)))
    served = dict(flow(dir="in", local_port=8080, remote_port=50000, remote="203.0.113.9"))
    for _ in range(6):  # a port served here: its own minutes
        b.observe(dict(served, start=clock.t, end=clock.t + 1, bytes=10 * KB))
        watch_for(b, clock, 60)
    watch_for(b, clock, 120)
    spike = b.observe(dict(served, start=clock.t, end=clock.t + 1, bytes=MB))
    assert ids(spike)[-1:] == ["spike"] and spike[-1].words.startswith("1.0 MB in on port 8080/tcp in the last minute")
    b.close()


def test_a_ports_bytes_are_counted_in_their_place_even_when_told_late():
    port = baseline._Port()
    for t, n in ((1000.0, 10), (1010.0, 20), (1005.0, 5), (1012.0, 1), (990.0, 7)):
        port.add(t, n)
    assert [k for k, _ in port.steps] == [198, 200, 201, 202]  # in order, the late ones in their place
    assert port.last_minute(1012.0) == 7 + 10 + 5 + 21 and port.last_minute(1069.0) == 21
    assert port.last_minute(1070.0) == 0 and port.last_minute(2000.0) == 0  # (t - 60, t], in whole steps
    steps = deque([[1, 1], [3, 3]], maxlen=2)
    baseline._bump(steps, 2, 2)  # full: the oldest goes to make room
    assert list(steps) == [[2, 2], [3, 3]]
    baseline._bump(steps, 1, 1)  # older than all those kept, and no room: not counted
    assert list(steps) == [[2, 2], [3, 3]]


# -- the file -----------------------------------------------------------------------------------------------------

def test_the_seen_table_is_capped_the_rows_longest_unseen_pruned_first(tmp_path):
    clock = Clock()
    path = tmp_path / "filter.db"
    with Baseline(path, cap=50, clock=clock) as b:
        for i in range(80):
            clock.t += 1
            b.remember(flow(remote=f"10.{i}.0.1", start=clock.t, end=clock.t, country=None, asn=None))
            assert b.rows <= 50
        rows = seen(path)
    peers = sorted(int(k.split(".")[1]) for k, (kind, *_) in rows.items() if kind == "peer")
    assert peers == list(range(32, 80))  # the 48 peers seen latest
    assert "program:c:\\program files\\browser\\browser.exe" in rows and "port:out tcp/443" in rows  # seen by all
    assert [k for k, (kind, *_) in rows.items() if kind == "watch"] == ["watch:time"]  # never pruned, not counted
    assert len(rows) == 51

    with Baseline(tmp_path / "roomy.db", cap=2000, clock=clock) as roomy:  # a prune goes a hundredth under the cap
        for i in range(1999):
            clock.t += 1
            roomy.remember(flow(remote=f"10.{i // 250}.{i % 250}.1", start=clock.t, country=None, asn=None))
            if i == 1997:
                assert roomy.rows == 2000  # the peers, the program and the port
        assert roomy.rows == 1980


def test_what_is_learned_is_kept_across_closing_and_opening_again(tmp_path):
    clock = Clock()
    path = tmp_path / "filter.db"
    b = learned(path, clock, [flow(start=T0)])
    watched, since, rows = *b.learning(), b.rows
    assert (watched, since, rows) == (30 * 60.0, T0, 5)  # the peer, port, program, country and network
    b.close()
    clock.t += 3600  # closed for an hour
    with Baseline(path, clock=clock) as again:
        assert again.learning() == (watched, since) and again.learned and again.rows == rows
        assert again.describe()["learned_at"] == datetime.fromtimestamp(T0 + 1800, timezone.utc).isoformat()
        again.watch()
        watch_for(again, clock, 60)
        assert again.learning() == (watched + 60, since)  # the hour closed is not counted
        assert again.observe(flow(start=clock.t)) == []  # its peer, port, program, country and network are known
        assert ids(again.observe(flow(remote="198.51.100.20", start=clock.t + 1))) == ["new-peer"]
    assert seen(path)["peer:198.51.100.0/24"][3] == 1
    assert b.learned and b.rows == 6  # the first one opens its file again at its next call
    b.close()


def test_a_flow_told_again_is_counted_once(tmp_path):
    clock = Clock()
    path = tmp_path / "filter.db"
    with Baseline(path, clock=clock) as b:
        first = flow(start=T0, end=T0 + 1, bytes=100)
        b.remember(first)
        b.remember(dict(first, end=T0 + 5, bytes=300))  # the same flow, later, its bytes grown
        row = seen(path)["peer:203.0.113.0/24"]
        assert row == ("peer", T0, T0 + 5, 1)
        assert b._ports["out tcp/443"].last_minute(T0 + 5) == 300
        b.remember(flow(start=T0 + 10))  # another flow with the peer
        assert seen(path)["peer:203.0.113.0/24"] == ("peer", T0, T0 + 11, 2)


def test_times_may_be_numbers_datetimes_or_iso_and_one_ahead_of_the_clock_is_the_clocks(tmp_path):
    clock = Clock()
    path = tmp_path / "filter.db"
    with Baseline(path, clock=clock) as b:
        b.remember(flow(start="2027-01-15T08:00:00Z", end=datetime(2027, 1, 15, 8, 0, 3, tzinfo=timezone.utc)))
        assert seen(path)["peer:203.0.113.0/24"][1:3] == (T0, T0 + 3)
        b.remember(flow(remote="198.51.100.1", start="2027-01-15T08:00:04", end=str(T0 + 6)))  # no zone: UTC
        assert seen(path)["peer:198.51.100.0/24"][1:3] == (T0 + 4, T0 + 6)
        b.remember(flow(remote="192.0.2.1", start=(T0 + 10) * 1000, end=(T0 + 11) * 1000))  # milliseconds by mistake
        assert seen(path)["peer:192.0.2.0/24"][1:3] == (T0, T0)
        assert b.learning() == (3.0, T0 + 3)  # the watching is not thrown into the future
        clock.t += 2
        b.remember(flow(remote="198.18.0.2", start=None, end=None))  # no times: seen now
        b.remember(flow(remote="198.18.1.3", start="not a time", end=T0 - 5))  # an end alone: seen then
        rows = seen(path)
        assert rows["peer:198.18.0.0/24"][1:3] == (T0 + 2, T0 + 2) and rows["peer:198.18.1.0/24"][1:3] == (T0 - 5,) * 2
        assert b.rows == 9 and b.learning() == (3.0, T0 + 3)


def test_threads_may_share_a_baseline(tmp_path):
    clock = Clock()
    with Baseline(tmp_path / "filter.db", clock=clock) as b:
        errors = []

        def work(n: int) -> None:
            try:
                for i in range(50):
                    b.observe(flow(remote=f"10.{n}.{i}.1", start=T0 + i))
                    b.watch(T0 + i)
                    b.learning()
                    b.describe()
            except Exception as e:  # noqa: BLE001 - any error is the test's failure
                errors.append(e)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == [] and b.rows == 4 * 50 + 4  # the peers, and one program, port, country and network


def test_a_file_that_is_no_database_is_set_aside_and_learning_starts_anew(tmp_path):
    path = tmp_path / "filter.db"
    path.write_bytes(b"not a database, " * 200)
    with Baseline(path, clock=Clock()) as b:
        assert b.learning() == (0.0, None) and b.rows == 0
        assert "it was set aside as filter.db.bad, and learning starts anew" in b.describe()["words"]
        b.remember(flow(start=T0))
    assert (tmp_path / "filter.db.bad").read_bytes() == b"not a database, " * 200
    assert "peer:203.0.113.0/24" in seen(path)


def test_a_file_removed_while_closed_starts_the_learning_anew(tmp_path):
    clock = Clock()
    path = tmp_path / "filter.db"
    b = learned(path, clock, [flow(start=T0)])
    b.close()
    path.unlink()
    assert b.learning() == (0.0, None) and not b.learned and b.rows == 0
    b.close()


def test_all_it_keeps_in_memory_is_capped(tmp_path, monkeypatch):
    for name, cap in (("MAX_FLOWS", 5), ("MAX_PORTS", 3), ("MAX_SPANS", 4), ("MAX_KEPT", 2)):
        monkeypatch.setattr(baseline, name, cap)
    clock = Clock()
    with Baseline(tmp_path / "filter.db", clock=clock, learn_s=60) as b:
        for i in range(10):
            clock.t += 100  # a pause each time: a new spell of watching
            b.watch()
            b.remember(flow(remote_port=1000 + i, start=clock.t, end=clock.t + 1, bytes=KB))
        assert len(b._flows) == 5 and len(b._ports) == 3 and len(b._spans) == 4
        assert list(b._ports) == ["out tcp/1007", "out tcp/1008", "out tcp/1009"]  # the ones used latest
        watch_for(b, clock, 60)
        assert b.learned
        shorts = [flow(remote=f"198.51.{100 + i}.1", start=clock.t, end=clock.t + 1) for i in range(4)]
        for short in shorts:
            b.observe(short)
        watch_for(b, clock, 11 * 60)
        assert all("one-off" in ids(b.flags(short)) for short in shorts)  # judged, and kept for the latest two
        assert len(b._kept) == 2 and len(b._spans) <= 4 and len(b._flows) == 5


def test_a_plugins_file_and_a_peers_group(tmp_path, monkeypatch):
    monkeypatch.setenv("LIMINAL_HOME", str(tmp_path))
    assert path_for("firewall-windows") == tmp_path / "store" / "data" / "baseline" / "firewall-windows.db"
    assert path_for("Firewall Linux!").name == "firewall-linux.db" and path_for("..").name == "plugin.db"
    assert group_of("203.0.113.77") == "203.0.113.0/24"
    assert group_of("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert group_of("::ffff:203.0.113.7") == "203.0.113.0/24"
    assert group_of("fe80::1%eth0") == "fe80::/48"
    assert group_of("[2001:db8:1::5]:443") == "2001:db8:1::/48" and group_of("203.0.113.7:443") == "203.0.113.0/24"
    assert group_of("not an address") == "not an address"


def test_the_words_never_judge_intent():
    assert UNUSUAL == "unusual for this machine while Liminal was watching"
    source = Path(baseline.__file__).read_text(encoding="utf-8")
    assert "malicious" not in source.lower() and not re.search(r"\b(?:https?|wss?)://", source)
    assert set(baseline.FLAGS) == {"new-peer", "new-port", "new-program", "new-country", "new-asn", "one-off", "spike"}


# -- a flow source's clock ahead, the second contact, the file left closed, odd flows -------------------------------

def test_flows_stamped_ahead_of_the_clock_within_future_s_are_not_the_clock_going_back(tmp_path):
    # a flow source 45 s ahead of this clock (inside FUTURE_S, past GAP_S): the old baseline took the ask after each
    # such flow for the clock going back, so it never finished learning and let go of the ports' minutes and the
    # one-offs' watched minutes
    clock = Clock()
    with Baseline(tmp_path / "ahead.db", clock=clock) as b:
        for _ in range(915):  # thirty minutes and a half of asks every 2 s, a flow 45 s ahead at each
            clock.t += 2
            b.watch()
            b.remember(flow(start=clock.t + 44, end=clock.t + 45))
        assert b.learned and b.learning()[0] >= b.learn_s  # old: (0.0, ...), never learned

    clock = Clock()
    b = learned(tmp_path / "filter.db", clock, [flow(start=T0)])
    for _ in range(10):  # ten minutes of what is usual: 100 KB a minute out to port 443
        watch_for(b, clock, 60)
        b.observe(flow(start=clock.t - 1, end=clock.t, bytes=100 * KB))
    once = flow(remote="198.51.100.20", start=clock.t, end=clock.t + 2)
    shown = flow(remote="198.51.101.20", start=clock.t, end=clock.t + 2)
    b.observe(once)
    b.observe(shown)
    watch_for(b, clock, 11 * 60)
    assert ids(b.flags(shown)) == ["new-peer", "one-off"]
    b.observe(flow(remote_port=8443, start=clock.t + 44, end=clock.t + 45, bytes=KB))  # one flow 45 s ahead
    clock.t += 2
    b.watch()
    assert ids(b.observe(flow(start=clock.t, end=clock.t + 1, bytes=4 * MB))) == ["spike"]  # old: [], minutes let go
    assert ids(b.flags(shown)) == ["new-peer", "one-off"]  # old: ["new-peer"], its judgment let go
    assert ids(b.flags(once)) == ["new-peer", "one-off"]

    pending = flow(remote="198.51.102.20", start=clock.t, end=clock.t + 2)
    assert ids(b.observe(pending)) == ["new-peer", "spike"]  # in the minute of the 4 MB
    watch_for(b, clock, 9 * 60)
    b.remember(flow(remote_port=993, start=clock.t + 44, end=clock.t + 45))  # 45 s ahead, within its ten minutes
    watch_for(b, clock, 3 * 60)
    assert ids(b.flags(pending)) == ["new-peer", "one-off", "spike"]  # old: no one-off, its watched minutes let go
    clock.t -= 3600  # the clock itself going back is still the clock going back
    b.watch()
    assert b._spans and b._spans[-1] == [clock.t, clock.t] and not b._ports
    b.close()


def test_a_second_contact_makes_no_one_off_however_long_it_lasts(tmp_path):
    # the old one-off was judged against the peer's latest sighting: a second connection a minute after a short one,
    # lasting 15 minutes, made the short one "not again in the 10 min watched after it"
    clock = Clock()
    b = learned(tmp_path / "filter.db", clock, [flow(start=T0)])
    t = clock.t
    short = flow(remote="198.51.100.20", start=t, end=t + 2)
    b.observe(short)
    while clock.t < t + 15 * 60:  # the second, told at each ask as it grows (as a flow still open is)
        clock.t += 2
        b.watch()
        if clock.t >= t + 60:
            b.observe(flow(remote="198.51.100.21", local_port=50999, start=t + 60, end=clock.t, bytes=int(clock.t - t)))
    assert ids(b.flags(short)) == ["new-peer"]  # old: ["new-peer", "one-off"]

    t = clock.t
    short = flow(remote="192.0.2.20", start=t, end=t + 2)
    b.observe(short)
    watch_for(b, clock, 16 * 60)
    b.observe(flow(remote="192.0.2.21", start=t + 62, end=clock.t))  # told once, at its end, 15 minutes long
    assert ids(b.flags(short)) == ["new-peer"]  # old: ["new-peer", "one-off"]
    assert seen(b.path)["peer:192.0.2.0/24"][3:] == (2,) and _again(b.path, "peer:192.0.2.0/24") == t + 62
    b.close()


def _again(path: Path, key: str):
    with sqlite3.connect(path) as con:
        row = con.execute("SELECT again FROM seen WHERE key = ?", (key,)).fetchone()
    con.close()
    return row[0]


def test_a_one_off_stays_one_however_often_its_peer_comes_back_after_its_minutes(tmp_path, monkeypatch):
    # the old one-off was no longer one once its peer came back twice; and what it had judged, once let go of (2,048
    # judgments kept), was judged again so
    monkeypatch.setattr(baseline, "MAX_KEPT", 1)
    for returns in (1, 2, 3):
        clock = Clock()
        b = learned(tmp_path / f"returns{returns}.db", clock, [flow(start=T0)])
        once = flow(remote="198.51.100.20", start=clock.t, end=clock.t + 1)
        b.observe(once)
        watch_for(b, clock, 11 * 60)  # eleven watched minutes, not asked about it
        for r in range(returns):
            b.observe(flow(remote="198.51.100.21", local_port=51000 + r, start=clock.t + r, end=clock.t + r + 1))
        assert ids(b.flags(once)) == ["new-peer", "one-off"], returns  # old: ["new-peer"] from two returns
        other = flow(remote="192.0.2.50", start=clock.t, end=clock.t + 1)
        b.observe(other)
        watch_for(b, clock, 11 * 60)
        assert "one-off" in ids(b.flags(other)) and len(b._kept) == 1  # judged: `once`'s judgment let go
        b.observe(flow(remote="198.51.100.22", start=clock.t, end=clock.t + 1))  # back once more
        assert ids(b.flags(once)) == ["new-peer", "one-off"], returns  # judged again from the file: the same
        b.close()


def test_a_file_from_before_again_was_kept_is_read_and_judges_only_what_it_knows(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as con:  # the seen table as the first baseline wrote it, no `again`
        con.execute("CREATE TABLE seen (key TEXT PRIMARY KEY, kind TEXT NOT NULL, first REAL NOT NULL, "
                    "last REAL NOT NULL, count INTEGER NOT NULL)")
        con.execute("INSERT INTO seen VALUES ('watch:time', 'watch', ?, ?, ?)", (T0, T0 + 1800, 1800.0))
        con.execute("INSERT INTO seen VALUES ('peer:198.51.100.0/24', 'peer', ?, ?, 2)", (T0 + 10, T0 + 900))
    con.close()
    clock = Clock(T0 + 1800)
    with Baseline(path, clock=clock) as b:
        assert b.learned and b.rows == 1
        b.remember(flow(remote="198.51.100.9", start=clock.t, end=clock.t + 1))
        b.remember(flow(remote="192.0.2.9", start=clock.t, end=clock.t + 1))
        b.remember(flow(remote="192.0.2.10", start=clock.t + 5, end=clock.t + 6))
        watch_for(b, clock, 11 * 60)
        f = baseline._read(flow(remote="198.51.100.20", start=T0 + 1802, end=T0 + 1803), clock.t)
        assert b._one_off(f, (T0 + 1802, T0 + 2400, 2, None)) is False  # seen again, when is not known
        assert b._one_off(f, (T0 + 1802, T0 + 2500, 3, T0 + 2420)) is True  # seen again after its ten minutes
        assert b._one_off(f, (T0 + 1802, T0 + 1803, 1, None)) is True  # never seen again
        assert b._one_off(f, (T0 + 1850, T0 + 1860, 1, None)) is False  # its peer's flow 47 s after it
    assert seen(path)["peer:198.51.100.0/24"] == ("peer", T0 + 10, T0 + 1801, 3)  # kept, and seen once more
    assert _again(path, "peer:198.51.100.0/24") is None and _again(path, "peer:192.0.2.0/24") == T0 + 1805


def test_a_read_keeps_no_file_open_and_makes_none(tmp_path):
    clock = Clock()
    path = tmp_path / "baseline" / "filter.db"
    b = Baseline(path, clock=clock)
    assert b.learning() == (0.0, None) and not b.learned and b.rows == 0 and b.describe()["learned"] is False
    assert not path.parent.exists()  # old: the folder and the file made, and the file kept open
    b.watch()
    b.remember(flow(start=T0))
    assert b._conn is not None  # watching keeps it open
    b.close()
    assert b.learning() == (1.0, T0) and b.rows == 5 and b.describe()["rows"] == 5 and not b.learned
    assert b._conn is None  # read, and closed again: old, open until some later close()
    b.watch()  # watching opens it again
    assert b._conn is not None
    b.close()
    path.unlink()
    assert b.describe()["watched"] == 0 and not path.exists()


def test_odd_values_in_a_flow_are_missing_never_an_error_and_its_words_are_capped(tmp_path):
    clock = Clock()
    path = tmp_path / "filter.db"
    with Baseline(path, clock=clock) as b:
        odd = flow(start=10**400, end=float("inf"), local_port=float("inf"), remote_port=10**400, bytes=10**400,
                   asn="AS\u00b2", program="C:\\" + "p" * 100_000, country="X" * 10_000, org="o" * 10_000,
                   proto="t" * 1000, dir="out" + " " * 5000, remote_group="g" * 10_000)
        b.watch()
        b.remember(odd)  # old: OverflowError, ValueError
        assert b.observe(odd) == [] and b.flags(odd) == []
        b.remember(flow(remote="x" * 100_000, start=T0, asn=10**30, country="  de  "))
        rows = seen(path)
    assert max(len(key) for key in rows) <= 1100 and "peer:203.0.113.0/24" in rows and "country:DE" in rows
    assert all(baseline._asn(v) is None for v in ("AS\u00b2", "\u0663", 2**32, "1" * 11, "AS", True))
    assert baseline._asn("as 64500") == 64500 and baseline._port("443") == 443 and baseline._count("1e400") == 0
    assert baseline._time("1" * 5000) is None and baseline._time(10**400) is None and baseline._time("1e3") == 1000.0
