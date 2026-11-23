"""Where an address is (liminal_libs.geo), over a tiny GeoIP file written here in the MaxMind DB format, with records
of DB-IP's Lite City shape (country, city, location), looked up through maxminddb as the real file would be. The
local network's addresses are never looked up, nor when IPv6 carries them; the answers kept are bounded in number and
in size, whatever a file's strings; an install is unpacked beside the old copy (what it reads, unpacks and takes in
time bounded), checked to read as a GeoIP file, put in place in one step, and the older copies removed; two installs
at once leave one file; a GeoIP an install lets go opens the new file; the newest file is found; and the library does
without maxminddb. Nothing is downloaded: the downloads are bytes, files and streams made here."""
from __future__ import annotations

import errno
import gc
import gzip
import http.client
import importlib.util
import io
import ipaddress
import os
import stat
import struct
import sys
import tarfile
import threading
import time
import tracemalloc
from datetime import datetime, timezone

import pytest

from liminal_libs import geo, layout
from liminal_libs.geo import GeoError, GeoIP, Place, install_mmdb

# CI installs maxminddb (the dev extra): there the reader's tests run, and fail rather than skip without it
needs_reader = pytest.mark.skipif(not geo.available()[0] and not os.environ.get("CI"),
                                  reason="maxminddb is not installed here")

OCTOBER = int(datetime(2026, 10, 1, 7, 41, tzinfo=timezone.utc).timestamp())
NOVEMBER = int(datetime(2026, 11, 1, 7, 41, tzinfo=timezone.utc).timestamp())


# -- a MaxMind DB file, written by hand (format 2.0) ------------------------------------------------------------------
def uint(kind: int, n: int) -> tuple:
    """An unsigned integer of one width: the metadata's are typed (uint16: 5, uint32: 6, uint64: 9)."""
    return ("uint", kind, n)


def control(kind: int, size: int) -> bytes:
    """A value's control byte: its type in the top 3 bits (0 for an extended type, whose number - 7 is the next
    byte), its size in the low 5 (29, 30 and 31: the size is in one, two or three more bytes)."""
    first, extended = (kind << 5, b"") if kind <= 7 else (0, bytes([kind - 7]))
    if size < 29:
        return bytes([first | size]) + extended
    if size < 285:
        return bytes([first | 29]) + extended + bytes([size - 29])
    if size < 65821:
        return bytes([first | 30]) + extended + (size - 285).to_bytes(2, "big")
    return bytes([first | 31]) + extended + (size - 65821).to_bytes(3, "big")


def encode(value) -> bytes:
    """One value of the data section: a map, an array, a string, a double, an unsigned integer or a boolean."""
    if isinstance(value, tuple):
        _, kind, n = value
        width = (n.bit_length() + 7) // 8
        return control(kind, width) + n.to_bytes(width, "big")
    if isinstance(value, bool):
        return control(14, int(value))
    if isinstance(value, int):
        return encode(uint(6, value))
    if isinstance(value, float):
        return control(3, 8) + struct.pack(">d", value)
    if isinstance(value, str):
        data = value.encode("utf-8")
        return control(2, len(data)) + data
    if isinstance(value, dict):
        return control(7, len(value)) + b"".join(encode(str(k)) + encode(v) for k, v in value.items())
    if isinstance(value, list):
        return control(11, len(value)) + b"".join(encode(v) for v in value)
    raise TypeError(value)


def mmdb(networks, ip_version: int = 6, built: int = NOVEMBER, kind: str = "DBIP-City-Lite",
         meta: dict | None = None) -> bytes:
    """A MaxMind DB file of `networks` ([(cidr, record)], a broader network before a narrower one inside it): a
    binary tree over the addresses' bits with 24-bit records (IPv4 under ::/96 in an IPv6 tree), 16 zero bytes, the
    records, then the metadata after its marker (`meta` changes it: values of the wrong types, say)."""
    bits = 128 if ip_version == 6 else 32
    data, offsets, root = b"", {}, [None, None]
    for cidr, record in networks:
        net = ipaddress.ip_network(cidr)
        value, length = int(net.network_address), net.prefixlen + (96 if net.version == 4 and ip_version == 6 else 0)
        blob = encode(record)
        if blob not in offsets:
            offsets[blob], data = len(data), data + blob
        node = root
        for i in range(length):
            bit = (value >> (bits - 1 - i)) & 1
            if i == length - 1:
                node[bit] = ("data", offsets[blob])
            else:
                if not isinstance(node[bit], list):
                    node[bit] = [node[bit], node[bit]]  # a broader network's record goes down both sides
                node = node[bit]
    nodes, queue, number = [], [root], {}
    while queue:  # numbered breadth first: the root is node 0
        node = queue.pop(0)
        number[id(node)] = len(nodes)
        nodes.append(node)
        queue += [child for child in node if isinstance(child, list)]
    count = len(nodes)

    def record(child) -> int:  # a node's number; node_count for nothing; past it, 16 + the record's place in the data
        if child is None:
            return count
        return number[id(child)] if isinstance(child, list) else count + 16 + child[1]

    tree = b"".join(record(left).to_bytes(3, "big") + record(right).to_bytes(3, "big") for left, right in nodes)
    metadata = {"binary_format_major_version": uint(5, 2), "binary_format_minor_version": uint(5, 0),
                "build_epoch": uint(9, built), "database_type": kind, "description": {"en": "written by test_geo.py"},
                "ip_version": uint(5, ip_version), "languages": ["en"], "node_count": uint(6, count),
                "record_size": uint(5, 24)}
    metadata.update(meta or {})
    return tree + bytes(16) + data + b"\xab\xcd\xefMaxMind.com" + encode(metadata)


def city(iso: str, country: str, name: str, lat: float, lon: float, **more) -> dict:
    """A record as DB-IP's Lite City holds one."""
    return {"city": {"names": {"en": name}}, "continent": {"code": "EU", "geoname_id": 1, "names": {"en": "a continent"}},
            "country": {"geoname_id": 2, "is_in_european_union": False, "iso_code": iso, "names": {"en": country}},
            "location": {"latitude": lat, "longitude": lon}, "subdivisions": [{"names": {"en": "a province"}}], **more}


def tarball(*members) -> bytes:
    """A tar of (name, bytes) members, as GeoLite2's .tar.gz holds its README, LICENSE and the .mmdb."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


PLACES = [
    ("81.2.0.0/16", {"country": {"iso_code": "GB", "names": {"en": "United Kingdom", "fr": "Royaume-Uni"}}}),
    ("81.2.69.0/24", city("GB", "United Kingdom", "London", 51.5142, -0.0931)),
    ("89.160.20.0/24", city("SE", "Sweden", "Linköping", 58.4167, 15.6167)),
    ("175.16.199.0/24", city("CN", "China", "Changchun", 43.88, 125.3228)),
    ("1.1.1.0/24", city("AU", "Australia", "Sydney", -33.8688, 151.209, autonomous_system_number=13335,
                        autonomous_system_organization="Cloudflare, Inc.")),
    ("2a01:4f8::/32", city("DE", "Germany", "Nuremberg", 49.4478, 11.0683)),
    ("2001:218::/32", {"country": {"iso_code": "jp", "names": {"ja": "日本"}}}),  # no English name, no point
]
# the local network's, as a whole file may hold them: never asked
LOCAL = [(cidr, city("ZZ", "Nowhere", "Here", 0.5, 0.5)) for cidr in
         ("10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
          "224.0.0.0/4", "fc00::/7", "fe80::/10", "ff00::/8")]
LONDON = Place("GB", "United Kingdom", "London", 51.5142, -0.0931)
NUREMBERG = Place("DE", "Germany", "Nuremberg", 49.4478, 11.0683)
MOUNTAIN_VIEW = ("8.8.8.0/24", city("US", "United States", "Mountain View", 37.386, -122.0838))  # November's only


class Trickle:
    """A download as an HTTP response gives it: read to its end in short reads, never seeked."""

    def __init__(self, data: bytes, step: int = 7):
        self.data, self.step, self.at = data, step, 0

    def read(self, size: int = -1) -> bytes:
        size = len(self.data) if size is None or size < 0 else min(size, self.step)
        out = self.data[self.at:self.at + size]
        self.at += len(out)
        return out


class ReadTooFar(BaseException):
    """An install read on where it should have stopped (a BaseException: no handler of the library's takes it)."""


class Endless:
    """A download made as it is read, never whole in memory: `head`, then `piece` over and over for `n` bytes, then
    `tail`. It counts the bytes it gave; a read once more than `trip` are given fails the test."""

    def __init__(self, head: bytes, piece: bytes, n: int, tail: bytes = b"", trip: int | None = None):
        self.head, self.piece, self.left, self.tail, self.trip = head, piece, n, tail, trip
        self.given, self._phase = 0, 0

    def read(self, size: int = -1) -> bytes:
        if self.trip is not None and self.given > self.trip:
            raise ReadTooFar(f"read on past {self.trip:,} bytes")
        size = 1 << 20 if size is None or size < 0 else size
        out = b""
        if self.head:
            out, self.head = self.head[:size], self.head[size:]
        if len(out) < size and self.left > 0:
            k = min(size - len(out), self.left)
            reps = -(-(k + self._phase) // len(self.piece))
            out += (self.piece * reps)[self._phase:self._phase + k]  # the pattern goes on where the last read left it
            self._phase = (self._phase + k) % len(self.piece)
            self.left -= k
        if len(out) < size and self.left <= 0 and self.tail:
            k = size - len(out)
            out, self.tail = out + self.tail[:k], self.tail[k:]
        self.given += len(out)
        return out


@pytest.fixture
def city_file(tmp_path):
    path = tmp_path / "dbip-city-lite-2026-11.mmdb"
    path.write_bytes(mmdb(PLACES + LOCAL))
    return path


# -- lookups --------------------------------------------------------------------------------------------------------
@needs_reader
def test_an_address_is_placed_as_the_file_says(city_file):
    with GeoIP(city_file) as g:
        assert g.lookup("81.2.69.142") == LONDON
        assert g.lookup(" 81.2.69.142 ") == LONDON and g.lookup(ipaddress.ip_address("81.2.69.142")) == LONDON
        assert g.lookup("::ffff:81.2.69.142") == LONDON  # IPv4 carried in IPv6: mapped
        assert g.lookup("64:ff9b::5102:458e") == LONDON  # and NAT64's
        assert g.lookup("::ffff:0:81.2.69.142") == LONDON  # translated (RFC 2765)
        assert g.lookup("::81.2.69.142") == LONDON  # and the old IPv4-compatible form
        assert g.lookup("81.2.1.1") == Place("GB", "United Kingdom", None, None, None)  # the /16 around it: a country
        assert g.lookup("89.160.20.112").city == "Linköping"
        sydney = g.lookup("1.1.1.1")
        assert (sydney.asn, sydney.org, sydney.label) == (13335, "Cloudflare, Inc.", "Sydney, Australia")
        assert g.lookup("2a01:4f8:c17:1::5") == NUREMBERG
        assert g.lookup("2a01:4f8:c17:1::5%eth0") == NUREMBERG  # a zone says which link, not where
        assert g.lookup("2001:218::5") == Place("JP", "日本", None, None, None)  # no English name: another language's
        assert g.lookup("8.8.8.8") is None and g.lookup("2600::1") is None  # not in the file


@needs_reader
def test_the_local_networks_addresses_are_never_looked_up(city_file):
    import maxminddb

    with maxminddb.open_database(str(city_file), maxminddb.MODE_MMAP) as reader:  # the file does hold them
        assert reader.get("192.168.1.20")["city"]["names"]["en"] == "Here"
        assert reader.get("224.0.0.251")["city"]["names"]["en"] == "Here"
        assert reader.get("::192.168.1.20")["city"]["names"]["en"] == "Here"  # IPv4's under ::/96 in an IPv6 tree
    with GeoIP(city_file) as g:
        for address in ("10.1.2.3", "172.16.5.4", "192.168.1.20", "100.64.1.1", "127.0.0.1", "169.254.1.1",
                        "224.0.0.251", "239.255.255.250", "0.0.0.0", "255.255.255.255", "::1", "::", "fe80::1",
                        "fe80::1%3", "fc00::1", "ff02::1", "::ffff:192.168.1.1", "64:ff9b::c0a8:114",
                        # the old IPv4-compatible form and the translated one carry the local network's too
                        "::192.168.1.20", "::10.0.0.1", "::127.0.0.1", "::100.64.1.1", "::169.254.1.1",
                        "::224.0.0.251", "::ffff:0:192.168.1.20", "::ffff:0:10.1.2.3",
                        "nonsense", "", None, 42, "81.2.69.142%eth0"):  # IPv4 has no zone: no address
            assert g.lookup(address) is None, address
        assert g.describe()["cache"]["misses"] == 0  # the file was never asked


@needs_reader
def test_an_ipv4_file_has_no_place_for_ipv6(tmp_path):
    path = tmp_path / "v4.mmdb"
    path.write_bytes(mmdb([n for n in PLACES if ":" not in n[0]], ip_version=4))
    with GeoIP(path) as g:
        assert g.lookup("81.2.69.142") == LONDON and g.lookup("2a01:4f8::1") is None
        assert g.lookup("::ffff:81.2.69.142") == LONDON and g.lookup("::81.2.69.142") == LONDON  # carried IPv4: IPv4


@needs_reader
def test_the_answers_kept_are_bounded_and_the_least_recent_goes_first(city_file):
    with GeoIP(city_file, cache=3) as g:
        for address in ("81.2.69.142", "89.160.20.112", "8.8.8.8"):  # looked up in the file (8.8.8.8: no place)
            g.lookup(address)
        assert g.lookup("81.2.69.142") == LONDON  # kept: now the most recent
        g.lookup("175.16.199.1")  # a fourth: 89.160.20.112, the least recent, goes
        assert g.describe()["cache"] == {"entries": 3, "max": 3, "hits": 1, "misses": 4}
        g.lookup("81.2.69.142")
        g.lookup("89.160.20.112")  # looked up again
        assert g.describe()["cache"] == {"entries": 3, "max": 3, "hits": 2, "misses": 5}
    with GeoIP(city_file) as g:
        assert g.describe()["cache"]["max"] == geo.CACHE == 4096
        for n in range(5000):
            g.lookup(ipaddress.IPv4Address("81.2.0.0") + n)
        assert g.describe()["cache"]["entries"] == 4096
        assert g.lookup("81.2.0.7") == Place("GB", "United Kingdom", None, None, None)  # gone from the cache, read again


@needs_reader
def test_a_hostile_files_strings_are_cut_before_they_are_kept(tmp_path):
    """maxminddb decodes a record's strings afresh at each lookup, each up to its 2 MiB: an answer keeps only their
    first TEXT characters (CODE of the country's code), never the record, so 4096 answers stay small whatever the
    file holds. Before, 16 peers of one hostile record kept about 43 MB."""
    wide = "\U0001F600" + "A" * 200_000  # one 4-byte character: Python keeps every character in 4 bytes
    record = {"city": {"names": {"en": wide}}, "location": {"latitude": 1.0, "longitude": 2.0},
              "country": {"iso_code": "ΐ" * 50_000, "names": {"fr": wide}},  # 'ΐ' upper-cases to 3 characters
              "autonomous_system_number": 64500, "autonomous_system_organization": wide}
    path = tmp_path / "hostile.mmdb"
    path.write_bytes(mmdb([("0.0.0.0/1", record), ("128.0.0.0/1", record)], kind="K" * 100_000))  # all of IPv4
    with GeoIP(path) as g:
        gc.collect()
        tracemalloc.start()
        try:
            before = tracemalloc.get_traced_memory()[0]
            places = [g.lookup(ipaddress.IPv4Address("81.0.0.1") + n * 65536) for n in range(16)]  # 16 peers
            gc.collect()
            kept = tracemalloc.get_traced_memory()[0] - before
        finally:
            tracemalloc.stop()
        assert g.describe()["cache"]["entries"] == 16 and g.describe()["cache"]["misses"] == 16
        assert kept < 16 * 8192, f"{kept:,} bytes kept"  # a few KB an answer at most: 4096 of them some MB
        for p in places:
            assert (len(p.city), len(p.country_name), len(p.org), p.asn) == (geo.TEXT, geo.TEXT, geo.TEXT, 64500)
            assert 0 < len(p.country) <= geo.CODE and len(p.label) <= 2 * geo.TEXT + 2
        assert all(isinstance(place, Place) for place in g._cache.values())  # the answers, never the records
        assert g.describe()["type"] == "K" * geo.TEXT  # the file's kind, cut the same way


@needs_reader
def test_an_ipv6_zone_is_no_part_of_the_address_kept(city_file):
    with GeoIP(city_file) as g:
        for n in range(8):  # one address, eight zones as long as a tool's text may make them
            assert g.lookup(f"2a01:4f8::1%{n}" + "z" * 10_000) == NUREMBERG
        assert g.lookup(ipaddress.IPv6Address("2a01:4f8::1%eth0")) == NUREMBERG
        assert g.describe()["cache"] == {"entries": 1, "max": geo.CACHE, "hits": 8, "misses": 1}
        assert [str(address) for address in g._cache] == ["2a01:4f8::1"]


@needs_reader
def test_a_file_is_described_by_its_metadata(city_file):
    g = GeoIP(city_file)
    described = g.describe()
    assert {k: described[k] for k in ("file", "date", "built", "size", "type", "open")} == {
        "file": "dbip-city-lite-2026-11.mmdb", "date": "2026-11-01", "built": "2026-11-01T07:41:00+00:00",
        "size": city_file.stat().st_size, "type": "DBIP-City-Lite", "open": True}
    assert described["path"] == str(city_file) and described["mode"] in ("mmap-ext", "mmap")
    g.close()
    assert g.lookup("81.2.69.142") is None and g.describe()["open"] is False  # a closed GeoIP answers nothing
    g.close()  # twice is fine


@needs_reader
def test_the_file_is_mapped_never_read_into_memory(city_file, monkeypatch):
    import maxminddb

    modes, real = [], maxminddb.open_database
    monkeypatch.setattr(maxminddb, "open_database",
                        lambda path, mode=maxminddb.MODE_AUTO: modes.append(mode) or real(path, mode))
    if geo._extension():
        with GeoIP(city_file) as g:
            assert g.mode == "mmap-ext" and g.lookup("81.2.69.142") == LONDON
        assert "C extension" in geo.available()[1]
    monkeypatch.setitem(sys.modules, "maxminddb.extension", None)  # no C extension: the pure-Python reader maps it
    with GeoIP(city_file) as g:
        assert g.mode == "mmap" and g.lookup("81.2.69.142") == LONDON
    assert "pure Python" in geo.available()[1]
    assert maxminddb.MODE_MMAP in modes and set(modes) <= {maxminddb.MODE_MMAP_EXT, maxminddb.MODE_MMAP}


@needs_reader
def test_a_file_that_does_not_open_says_so(tmp_path):
    for name, blob in (("empty.mmdb", b""), ("text.mmdb", b"not a GeoIP file\n" * 50), ("cut.mmdb", mmdb(PLACES)[:-40])):
        (tmp_path / name).write_bytes(blob)
        with pytest.raises(GeoError, match="does not open"):
            GeoIP(tmp_path / name)
    with pytest.raises(GeoError, match="does not open"):
        GeoIP(tmp_path / "missing.mmdb")
    (tmp_path / "behind.mmdb").write_bytes(b"P" * 4096 + mmdb(PLACES))  # maxminddb opens it, by its metadata at the end
    with pytest.raises(GeoError, match="search tree does not end where its metadata says"):
        GeoIP(tmp_path / "behind.mmdb")
    (tmp_path / "nothing.mmdb").write_bytes(mmdb([]))  # a tree with no record in it
    with pytest.raises(GeoError, match="places no address"):
        GeoIP(tmp_path / "nothing.mmdb")


# -- finding the newest ---------------------------------------------------------------------------------------------
@needs_reader
def test_the_newest_file_that_opens_is_found(tmp_path):
    folder = tmp_path / "geoip"
    assert GeoIP.find(folder) is None  # no folder yet
    folder.mkdir()
    assert GeoIP.find(folder) is None  # nothing in it
    now = time.time()
    for name, built, age in (("dbip-city-lite-2026-10.mmdb", OCTOBER, 2000), ("dbip-city-lite-2026-11.mmdb", NOVEMBER, 1000)):
        (folder / name).write_bytes(mmdb(PLACES, built=built))
        os.utime(folder / name, (now - age, now - age))
    (folder / "broken.mmdb").write_bytes(bytes(64))  # the last written, and it does not open: passed over
    (folder / "tarred.mmdb").write_bytes(tarball(("README.txt", b"readme\n" * 60), ("a.mmdb", mmdb(PLACES))))  # nor this
    (folder / ".dbip-city-lite-2026-12.x1y2.part").write_bytes(mmdb(PLACES))  # an install not finished
    (folder / "a-folder.mmdb").mkdir()
    with GeoIP.find(folder) as g:
        assert (g.describe()["file"], g.describe()["date"]) == ("dbip-city-lite-2026-11.mmdb", "2026-11-01")
    os.utime(folder / "dbip-city-lite-2026-10.mmdb", (now, now))  # the newest by when it was written, not by name
    with GeoIP.find(folder, cache=8) as g:
        assert g.describe()["file"] == "dbip-city-lite-2026-10.mmdb" and g.describe()["cache"]["max"] == 8


# -- installs -------------------------------------------------------------------------------------------------------
@needs_reader
def test_an_install_is_unpacked_beside_the_old_copy_and_put_in_place(tmp_path):
    folder = tmp_path / "data" / "geoip"  # made by the install
    october = install_mmdb(gzip.compress(mmdb(PLACES, built=OCTOBER)), folder, "dbip-city-lite-2026-10")  # bytes
    assert october == folder / "dbip-city-lite-2026-10.mmdb"
    reading = GeoIP(october)
    assert reading.lookup("81.2.69.142") == LONDON
    download = tmp_path / "dbip-city-lite-2026-11.mmdb.gz"
    download.write_bytes(gzip.compress(mmdb(PLACES, built=NOVEMBER)))
    november = install_mmdb(download, folder, "dbip-city-lite-2026-11.mmdb")  # a path; the .mmdb is not doubled
    assert november == folder / "dbip-city-lite-2026-11.mmdb"
    assert reading.describe()["open"] is False  # let go for the rename: Windows keeps a mapped file in place
    assert [p.name for p in folder.iterdir()] == [november.name]  # the older copy went; no temporary file is left
    assert reading.lookup("89.160.20.112").city == "Linköping"  # and then it reads the new file
    assert (reading.describe()["file"], reading.describe()["open"]) == (november.name, True)
    with GeoIP.find(folder) as g:
        assert g.describe()["date"] == "2026-11-01"
    later = gzip.compress(mmdb(PLACES, built=NOVEMBER + 86400))
    assert install_mmdb(Trickle(later), folder, "dbip-city-lite-2026-11") == november  # a stream, over the same name
    with GeoIP.find(folder) as g:
        assert g.describe()["date"] == "2026-11-02" and g.lookup("2a01:4f8::1").city == "Nuremberg"
    assert [p.name for p in folder.iterdir()] == [november.name]
    assert reading.lookup("1.1.1.1").city == "Sydney" and reading.describe()["date"] == "2026-11-02"
    reading.close()


@needs_reader
def test_a_broken_download_leaves_the_current_file_as_it_was(tmp_path, monkeypatch):
    folder = tmp_path / "geoip"
    current = install_mmdb(gzip.compress(mmdb(PLACES)), folder, "dbip-city-lite-2026-11")
    before = current.read_bytes()
    good = gzip.compress(mmdb(PLACES, built=NOVEMBER + 86400))
    flipped = bytearray(good)
    flipped[-8] ^= 1  # the trailer's CRC-32
    with GeoIP(current) as reading:
        for source, words in ((good[:len(good) // 2], "cut short"),
                              (bytes(flipped), "was not installed: .*incorrect data check"),
                              (good + b"and then some", "goes on after its gzip data"),
                              (gzip.compress(b"not a GeoIP file\n" * 100), "does not open"),
                              (b"not a GeoIP file, not gzipped either", "does not open"),
                              (gzip.compress(bytes(4096)), "does not open"),
                              (b"", "empty")):
            with pytest.raises(GeoError, match=words):
                install_mmdb(source, folder, "dbip-city-lite-2026-12")
        with pytest.raises(GeoError, match="more than 1,000 bytes"):
            install_mmdb(good, folder, "dbip-city-lite-2026-12", limit=1000)
        assert reading.lookup("81.2.69.142") == LONDON  # a broken download disturbs no reader
        assert [p.name for p in folder.iterdir()] == [current.name] and current.read_bytes() == before

        def refused(src, dst):
            raise PermissionError(13, "in use", str(dst))

        monkeypatch.setattr(os, "replace", refused)
        with pytest.raises(GeoError, match="was not installed: .*in use"):
            install_mmdb(good, folder, "dbip-city-lite-2026-11")
        monkeypatch.undo()
        assert reading.describe()["open"] is False  # the readers were let go for the rename
        assert reading.lookup("89.160.20.112").city == "Linköping"  # and open the file again: it is as it was
        assert reading.describe()["file"] == current.name
    assert [p.name for p in folder.iterdir()] == [current.name] and current.read_bytes() == before
    with GeoIP.find(folder) as g:  # and found again
        assert g.lookup("81.2.69.142") == LONDON


@needs_reader
def test_a_download_that_opens_yet_does_not_read_is_refused(tmp_path):
    """maxminddb opens a file by its metadata, at its end: a GeoIP file inside a tar, or behind other bytes, opens
    and places nothing, and the good copy went for it. An install checks that the search tree ends where the
    metadata says and leads to a record that decodes."""
    folder = tmp_path / "geoip"
    current = install_mmdb(gzip.compress(mmdb(PLACES, built=OCTOBER)), folder, "dbip-city-lite-2026-10")
    good = mmdb(PLACES, built=NOVEMBER)
    tarred = tarball(("GeoLite2-City_20261110/README.txt", b"readme\n" * 60),
                     ("GeoLite2-City_20261110/LICENSE.txt", b"licence\n" * 300),
                     ("GeoLite2-City_20261110/GeoLite2-City.mmdb", good))
    for download, words in ((gzip.compress(tarred), "its search tree does not"),  # GeoLite2's .tar.gz
                            (b"P" * 4096 + good, "does not end where its metadata says"),  # bytes in front
                            (gzip.compress(bytes(1536) + good), "search tree does not read"),  # zeros in front
                            (bytes(6) + good[6:], "search tree does not read"),  # its root leads back to itself
                            (mmdb([]), "places no address"),  # a tree with nothing in it
                            (mmdb([("81.2.0.0/16", "a string")]), "no maps")):  # records of no GeoIP file
        with pytest.raises(GeoError, match=f"was not installed: .*{words}"):
            install_mmdb(download, folder, "dbip-city-lite-2026-11")
        assert [p.name for p in folder.iterdir()] == [current.name]  # the good copy stays, and nothing else
    with GeoIP.find(folder) as g:
        assert g.describe()["file"] == current.name and g.lookup("81.2.69.142") == LONDON


@needs_reader
def test_metadata_of_the_wrong_types_is_refused_by_either_reader(tmp_path, monkeypatch):
    """libmaxminddb checks the metadata's types when it opens a file; maxminddb's pure-Python reader checks none.
    Either way an install refuses such a file with a GeoError (not a ValueError), and the current copy stays."""
    folder = tmp_path / "geoip"
    current = install_mmdb(gzip.compress(mmdb(PLACES, built=OCTOBER)), folder, "dbip-city-lite-2026-10")
    wrong = ({"build_epoch": "x"}, {"ip_version": "x"}, {"binary_format_major_version": "two"},
             {"binary_format_major_version": {"a": "b"}}, {"ip_version": uint(5, 5)}, {"record_size": uint(5, 20)})
    for pure in (False, True):
        if pure:
            monkeypatch.setitem(sys.modules, "maxminddb.extension", None)  # as where maxminddb has no C extension
        for meta in wrong:
            with pytest.raises(GeoError, match="was not installed"):
                install_mmdb(gzip.compress(mmdb(PLACES, meta=meta)), folder, "dbip-city-lite-2026-11")
            assert [p.name for p in folder.iterdir()] == [current.name], meta
        with GeoIP.find(folder) as g:
            assert g.mode == ("mmap" if pure or not geo._extension() else "mmap-ext")
            assert g.lookup("81.2.69.142") == LONDON


@needs_reader
def test_the_bytes_read_are_bounded_not_only_the_bytes_unpacked(tmp_path):
    """gzip can read on and on and unpack nothing: a header whose name never ends, empty members, empty blocks,
    zeros after the end. An install stops after BARREN such bytes in a row, after MEMBERS members, and after about
    `limit` bytes read in all; zlib reads a header in C, never a byte at a time."""
    folder = tmp_path / "geoip"
    far = 4 << 20  # more than any of these may read: BARREN, and a read more
    header = b"\x1f\x8b\x08\x00\0\0\0\0\0\xff"  # a gzip member's header, nothing flagged
    for stream, words in ((Endless(b"\x1f\x8b\x08\x08\0\0\0\0\0\xff", b"A", 1 << 30, trip=far), "unpack to nothing"),
                          (Endless(b"\x1f\x8b\x08\x10\0\0\0\0\0\xff", b"A", 1 << 30, trip=far), "unpack to nothing"),
                          (Endless(b"", gzip.compress(b"", mtime=0), 20 << 30, trip=far), "more than 16,384 gzip"),
                          (Endless(header, b"\0\0\0\xff\xff", 5 << 30, trip=far), "unpack to nothing"),
                          (Endless(gzip.compress(b"x", mtime=0), b"\0", 1 << 30, trip=far), "unpack to nothing")):
        with pytest.raises(GeoError, match=words):
            install_mmdb(stream, folder, "dbip-city-lite-2026-11")
        assert stream.given <= far
    # a byte unpacked now and then keeps BARREN from tripping: then the bytes read in all stop it
    drip = Endless(header, b"\0\0\0\xff\xff" * 100_000 + b"\0\x01\0\xfe\xffx", 1 << 30, trip=far)
    with pytest.raises(GeoError, match="runs past 1,049,579 bytes"):
        install_mmdb(drip, folder, "dbip-city-lite-2026-11", limit=1000)
    assert drip.given <= 1000 + 1000 // 256 + geo.CHUNK + geo.FEED
    assert [p.name for p in folder.iterdir()] == []  # nothing is left of any
    assert geo.BARREN + geo.FEED <= far and geo.MEMBERS * len(gzip.compress(b"", mtime=0)) <= far


@needs_reader
def test_an_install_stops_at_its_deadline(tmp_path, monkeypatch):
    """A download that trickles in is stopped at the install's deadline (looked at before each read: a read that
    hangs is the stream's own timeout's), and nothing is left of it."""
    now = [1000.0]
    monkeypatch.setattr(geo, "_clock", lambda: now[0], raising=False)

    class Slow(Trickle):
        def read(self, size: int = -1) -> bytes:
            now[0] += 7.0  # each read takes 7 s
            return super().read(size)

    folder = tmp_path / "geoip"
    data = gzip.compress(mmdb(PLACES))
    with pytest.raises(GeoError, match="took more than 60 s"):
        install_mmdb(Slow(data), folder, "dbip-city-lite-2026-11", timeout=60)
    assert [p.name for p in folder.iterdir()] == []
    assert install_mmdb(Slow(data, step=1 << 20), folder, "dbip-city-lite-2026-11", timeout=60).exists()  # in time
    assert install_mmdb(Slow(data), folder, "dbip-city-lite-2026-11", timeout=None).exists()  # no deadline
    assert geo.INSTALL_S == 1800.0  # half an hour unless the plugin says otherwise


@needs_reader
def test_a_streams_own_errors_come_as_geoerror(tmp_path):
    """Whatever goes wrong with the stream, the install says so with a GeoError, and the current file stays."""
    folder = tmp_path / "geoip"
    current = install_mmdb(gzip.compress(mmdb(PLACES)), folder, "dbip-city-lite-2026-11")
    data = gzip.compress(mmdb(PLACES, built=NOVEMBER + 86400))

    class CutOff(Trickle):  # an HTTP response cut short in a chunk
        def read(self, size: int = -1) -> bytes:
            if self.at > 100:
                raise http.client.IncompleteRead(b"partial", 1000)
            return super().read(size)

    class Text(Trickle):  # a stream opened in text mode
        def read(self, size: int = -1) -> str:
            return super().read(size).decode("latin-1")

    class Waiting(Trickle):  # a non-blocking stream with nothing yet
        def read(self, size: int = -1):
            return None

    for stream, words in ((CutOff(data), "IncompleteRead"), (Text(data), "gave str, not bytes"),
                          (Waiting(data), "gave NoneType")):
        with pytest.raises(GeoError, match=f"was not installed: .*{words}"):
            install_mmdb(stream, folder, "dbip-city-lite-2026-12")
        assert [p.name for p in folder.iterdir()] == [current.name]


@needs_reader
def test_two_installs_at_once_leave_one_file(tmp_path, monkeypatch):
    """The platform asks hooks on threads of their own: two installs into one folder at once each put their file in
    place and remove the others, one at a time, so the later one stays (before, each removed the other's)."""
    folder = tmp_path / "geoip"
    real, both = geo._prune, threading.Barrier(2, timeout=0.5)

    def prune(at, keep):  # waits for the other install to have put its file in place too, if it can get there
        try:
            both.wait()
        except threading.BrokenBarrierError:
            pass  # it cannot: the installs take turns
        return real(at, keep)

    monkeypatch.setattr(geo, "_prune", prune)
    data, failed = gzip.compress(mmdb(PLACES)), []

    def install(name: str) -> None:
        try:
            install_mmdb(data, folder, name)
        except Exception as e:  # noqa: BLE001 - the test says which
            failed.append(e)

    threads = [threading.Thread(target=install, args=(name,)) for name in ("dbip-city-lite-2026-11", "dbip-city-lite-2026-12")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert not failed and not any(t.is_alive() for t in threads)
    assert len(list(folder.glob("*.mmdb"))) == 1
    found = GeoIP.find(folder)
    assert found is not None and found.lookup("81.2.69.142") == LONDON
    found.close()


@needs_reader
def test_a_geoip_an_install_let_go_opens_the_newest_file(tmp_path, monkeypatch):
    """A plugin holds its GeoIP: after an install it reads the new file (or the old one again when the rename failed)
    rather than answering None from then on. A GeoIP closed by close() stays closed."""
    now = [5000.0]
    monkeypatch.setattr(geo, "_clock", lambda: now[0], raising=False)
    folder = tmp_path / "geoip"
    october = install_mmdb(gzip.compress(mmdb(PLACES, built=OCTOBER)), folder, "dbip-city-lite-2026-10")
    held, closed = GeoIP(october), GeoIP(october)
    closed.close()
    assert held.lookup("8.8.8.8") is None  # October has no place for it
    november = install_mmdb(gzip.compress(mmdb(PLACES + [MOUNTAIN_VIEW], built=NOVEMBER)), folder,
                            "dbip-city-lite-2026-11")
    assert held.describe()["open"] is False  # let go for the rename
    assert held.lookup("8.8.4.4") is None and held.lookup("8.8.8.8").city == "Mountain View"  # November's answers
    assert (held.describe()["file"], held.describe()["date"], held.describe()["open"]) == (november.name, "2026-11-01", True)
    assert closed.lookup("8.8.8.8") is None and closed.describe()["open"] is False  # closed for good
    install_mmdb(gzip.compress(mmdb(PLACES, built=NOVEMBER)), folder, "dbip-city-lite-2026-12")  # let go again
    for path in folder.iterdir():
        path.unlink()  # and then no file is left to open
    assert held.lookup("1.1.1.1") is None  # tried: none opens
    (folder / "dbip-city-lite-2026-12.mmdb").write_bytes(mmdb(PLACES))
    assert held.lookup("1.1.1.2") is None  # not tried again so soon
    now[0] += geo.REOPEN_S + 1
    assert held.lookup("1.1.1.3").city == "Sydney" and held.describe()["file"] == "dbip-city-lite-2026-12.mmdb"
    held.close()


@needs_reader
def test_a_plain_file_installs_too_and_names_stay_in_their_folder(tmp_path):
    folder = tmp_path / "geoip"
    path = install_mmdb(io.BytesIO(mmdb(PLACES)), folder, "plain")  # not gzipped: copied as it is
    with GeoIP(path) as g:
        assert g.lookup("89.160.20.112").city == "Linköping"
    for name in ("../outside", "a/b", "a\\b", "", ".hidden", "x" * 101):
        with pytest.raises(ValueError):
            install_mmdb(mmdb(PLACES), folder, name)
    with pytest.raises(TypeError):
        install_mmdb(12345, folder, "number")
    assert [p.name for p in folder.iterdir()] == ["plain.mmdb"] and not (tmp_path / "outside.mmdb").exists()


@needs_reader
def test_older_copies_and_the_leftovers_of_dead_installs_go(tmp_path):
    folder = tmp_path / "geoip"
    folder.mkdir()
    (folder / "dbip-city-lite-2026-09.mmdb").write_bytes(mmdb(PLACES, built=OCTOBER))
    (folder / "copied-by-hand.mmdb").write_bytes(b"whatever")  # another .mmdb: the folder holds one GeoIP file
    (folder / "README.txt").write_text("kept")  # no GeoIP file: kept
    dead, live = folder / ".dbip-city-lite-2026-10.ab12.part", folder / ".dbip-city-lite-2026-11.cd34.part"
    dead.write_bytes(b"half")
    live.write_bytes(b"being written")
    old = time.time() - 2 * geo.STALE_PART_S
    os.utime(dead, (old, old))
    install_mmdb(gzip.compress(mmdb(PLACES)), folder, "dbip-city-lite-2026-11")
    assert sorted(p.name for p in folder.iterdir()) == sorted([live.name, "README.txt", "dbip-city-lite-2026-11.mmdb"])


@needs_reader
def test_a_failed_install_still_sweeps_the_leftovers_of_dead_ones(tmp_path):
    folder = tmp_path / "geoip"
    folder.mkdir()
    dead, live = folder / ".dbip-city-lite-2026-10.ab12.part", folder / ".dbip-city-lite-2026-11.cd34.part"
    dead.write_bytes(b"half")
    live.write_bytes(b"being written")
    old = time.time() - 2 * geo.STALE_PART_S
    os.utime(dead, (old, old))
    with pytest.raises(GeoError, match="does not open"):
        install_mmdb(b"not a GeoIP file", folder, "dbip-city-lite-2026-12")
    assert [p.name for p in folder.iterdir()] == [live.name]


def _account(uid: int) -> str:
    """An account's name as the words give it (POSIX)."""
    import pwd

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid {uid}"


@needs_reader
@pytest.mark.skipif(os.name != "posix", reason="file modes and owners are POSIX's")
def test_an_installed_file_is_read_by_whichever_account_runs_the_platform_later(tmp_path, monkeypatch):
    """(fw-linux review, minor) An install unpacked into tempfile.mkstemp's file, 0600, and the rename kept that mode: a
    file installed while the platform ran as root (the data folder is the checkout's) could not be read when it later
    ran as its user. Now it has the mode every file this process makes has, 0644 less the umask; and an install refused
    for want of the right says whose the folder is, when it is another account's."""
    folder = tmp_path / "geoip"
    umask = os.umask(0o027)
    try:
        target = install_mmdb(gzip.compress(mmdb(PLACES)), folder, "dbip-city-lite-2026-11")
    finally:
        os.umask(umask)
    assert stat.S_IMODE(target.stat().st_mode) == 0o640  # 0644 less the umask, not 0600

    def refused(at, stem):  # the folder another account's: no file may be made in it
        raise PermissionError(errno.EACCES, "Permission denied", str(at / f".{stem}.x.part"))
    monkeypatch.setattr(geo, "_temporary", refused)
    me = os.geteuid()
    monkeypatch.setattr(geo.os, "geteuid", lambda: me + 1)  # the platform runs as another account than the folder's
    with pytest.raises(GeoError) as other:
        install_mmdb(gzip.compress(mmdb(PLACES)), folder, "dbip-city-lite-2026-12")
    assert f"Permission denied: '{folder}" in str(other.value)
    assert str(other.value).endswith(f" ({folder} is {_account(me)}'s, and the platform runs as {_account(me + 1)})")
    monkeypatch.setattr(geo.os, "geteuid", lambda: me)  # its own folder: its mode refused it, not whose it is
    with pytest.raises(GeoError) as own:
        install_mmdb(gzip.compress(mmdb(PLACES)), folder, "dbip-city-lite-2026-12")
    assert "and the platform runs as" not in str(own.value)
    assert [p.name for p in folder.iterdir()] == [target.name]  # nothing else written


# -- without maxminddb, and the places themselves ---------------------------------------------------------------------
def test_without_maxminddb_nothing_is_read_or_written(tmp_path, monkeypatch):
    folder = tmp_path / "geoip"
    folder.mkdir()
    (folder / "dbip-city-lite-2026-11.mmdb").write_bytes(mmdb(PLACES))
    monkeypatch.setitem(sys.modules, "maxminddb", None)  # as if it were not installed
    assert geo.available() == (False, "maxminddb is not installed in this Python")
    assert GeoIP.find(folder) is None
    with pytest.raises(GeoError, match="not installed"):
        GeoIP(folder / "dbip-city-lite-2026-11.mmdb")
    with pytest.raises(GeoError, match="not installed"):
        install_mmdb(gzip.compress(mmdb(PLACES)), folder, "dbip-city-lite-2026-12")
    assert [p.name for p in folder.iterdir()] == ["dbip-city-lite-2026-11.mmdb"]  # nothing written
    # the library imports without it: a fresh copy of the module, loaded while maxminddb is missing
    spec = importlib.util.spec_from_file_location("liminal_libs._geo_without_maxminddb", geo.__file__)
    copy = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, copy)
    spec.loader.exec_module(copy)
    assert copy.available()[0] is False and copy.Place("GB", "United Kingdom", None, None, None).label == "United Kingdom"


@needs_reader
def test_maxminddb_says_how_it_reads():
    ok, why = geo.available()
    assert ok and why.startswith("maxminddb ") and why.endswith("the file memory-mapped")


def test_a_place_in_words_and_as_the_page_takes_it():
    assert LONDON.label == "London, United Kingdom" and Place("JP", None, None, None, None).label == "JP"
    assert Place(None, None, None, None, None).label == ""
    assert LONDON.as_dict() == {"country": "GB", "country_name": "United Kingdom", "city": "London", "lat": 51.5142,
                                "lon": -0.0931, "asn": None, "org": None, "label": "London, United Kingdom"}
    assert geo.data_folder() == layout.data_dir() / "geoip"


def test_records_of_other_shapes():
    assert geo._place({"autonomous_system_number": 13335, "autonomous_system_organization": "Cloudflare, Inc."}) == \
        Place(None, None, None, None, None, 13335, "Cloudflare, Inc.")  # an ASN file's record
    assert geo._place({"country": {"iso_code": "GB"}, "location": {"latitude": 91.0, "longitude": 0.0}}) == \
        Place("GB", None, None, None, None)  # a point off the globe is no point
    assert geo._place({"location": {"latitude": 10, "longitude": -20}}) == Place(None, None, None, 10.0, -20.0)
    assert geo._place({"location": {"latitude": True, "longitude": 1}}) is None
    assert geo._place({"location": {"latitude": float("nan"), "longitude": 1.0}}) is None
    assert geo._place({"city": {"names": "London"}, "country": "GB", "autonomous_system_number": True}) is None
    assert geo._place(None) is None and geo._place([1, 2]) is None and geo._place({}) is None
    assert geo._place({"autonomous_system_number": 1 << 32}) is None  # AS numbers have 32 bits
    assert geo._place({"autonomous_system_number": (1 << 32) - 1}).asn == (1 << 32) - 1


def test_a_records_strings_are_cut_to_fixed_lengths():
    long = geo._place({"city": {"names": {"en": "  " + "x" * 1000}}, "country": {"iso_code": "gb" * 100},
                       "autonomous_system_organization": "o" * 1000})
    assert len(long.city) < 1000 and len(long.country) < 200 and len(long.org) < 1000
    assert (long.city, long.country, long.org) == ("x" * (geo.TEXT - 2), "GB" * (geo.CODE // 2), "o" * geo.TEXT)
    assert geo._place({"country": {"iso_code": "ß"}}).country == "SS"  # upper-cased, then cut again
    many = {f"l{n}": "" for n in range(geo.LANGUAGES)}
    assert geo._place({"country": {"names": {**many, "zz": "Far"}}}) is None  # past the languages looked through
    assert geo._place({"country": {"names": {"de": "Deutschland"}}}).country_name == "Deutschland"


@needs_reader
def test_a_folder_on_another_systems_drive_is_that_systems(tmp_path, monkeypatch):
    """1.58.0, for the suite run a second time inside WSL: each system's platform keeps its own state, its GeoIP files
    among them. A folder on another system's drive (mounts.foreign: WSL's /mnt/c, a share, a network drive) holds that
    system's files. None is read from here (mapped, it would keep that system's own update from replacing it), nor
    installed there, the folder not even made; the words are mounts.owner_only's. This machine's own folders are read
    and installed as ever, and with a library from before mounts (1.56.0) every folder is this machine's, as before."""
    from liminal_libs import mounts

    theirs, mine = tmp_path / "theirs", tmp_path / "mine"
    theirs.mkdir()
    (theirs / "dbip-city-lite-2026-11.mmdb").write_bytes(mmdb(PLACES))
    asked: list[str] = []

    def stand_in(path, table=None):  # mounts.foreign as a mount table would answer: theirs is the other system's
        asked.append(str(path))
        return str(path).startswith(str(theirs))
    monkeypatch.setattr(mounts, "foreign", stand_in)
    assert GeoIP.find(theirs) is None and asked == [str(theirs)]  # the folder judged, never listed
    with pytest.raises(GeoError, match=r"^Reading a GeoIP file: .*dbip-city-lite-2026-11\.mmdb is on another system's "
                                       r"drive, and that is done from that system, not from here$"):
        GeoIP(theirs / "dbip-city-lite-2026-11.mmdb")
    with pytest.raises(GeoError, match=r"^Installing a GeoIP file: .*new is on another system's drive"):
        install_mmdb(gzip.compress(mmdb(PLACES)), theirs / "new", "dbip-city-lite-2026-12")
    assert not (theirs / "new").exists() and [p.name for p in theirs.iterdir()] == ["dbip-city-lite-2026-11.mmdb"]
    assert geo.foreign(theirs, "Reading").startswith("Reading: ") and geo.foreign(mine, "Reading") == ""
    installed = install_mmdb(gzip.compress(mmdb(PLACES)), mine, "dbip-city-lite-2026-12")  # this machine's own
    with GeoIP.find(mine) as g:
        assert g.path == installed and g.lookup("81.2.69.142") == LONDON
    monkeypatch.setattr(mounts, "foreign", lambda path, table=None: 1 / 0)
    assert geo.foreign(theirs, "Reading") == ""  # a check that cannot say: as before
    monkeypatch.setattr(mounts, "foreign", stand_in)
    monkeypatch.setitem(sys.modules, "liminal_libs.mounts", None)  # a library from before mounts
    assert geo._mounts() is None and geo.foreign(theirs, "Reading") == ""
    with GeoIP.find(theirs) as g:
        assert g.lookup("81.2.69.142") == LONDON


def _link(target, link) -> bool:
    """A link from `link` to the folder `target`: a symbolic one, or on Windows a junction (which needs no right)."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if sys.platform == "win32":
        import _winapi

        try:
            _winapi.CreateJunction(str(target), str(link))
            return True
        except OSError:
            return False
    return False


@needs_reader
def test_a_reader_let_go_by_an_install_never_reopens_another_systems_file(tmp_path, monkeypatch):
    """(1.58.0's review) The reopening of a reader an install let go (GeoIP._reopen) mapped the folder's newest copy
    unjudged: a newer file there that was another system's (a link into its drive) was read once an install into the
    folder failed to rename. Each copy is judged now, as GeoIP() judges one, and the reader stays on this machine's."""
    from liminal_libs import mounts

    mine = tmp_path / "mine"
    mine.mkdir()
    own, other = mine / "a.mmdb", mine / "b.mmdb"
    own.write_bytes(mmdb(PLACES, built=OCTOBER))
    other.write_bytes(mmdb(PLACES + [MOUNTAIN_VIEW], built=NOVEMBER))  # only the other system's places 8.8.8.8
    past = time.time() - 100
    os.utime(own, (past, past))  # the other system's is the newest
    judged: list[str] = []

    def stand_in(path, table=None):  # b.mmdb: another system's file, a link to its drive
        judged.append(os.path.basename(str(path)))
        return os.path.basename(str(path)) == "b.mmdb"
    monkeypatch.setattr(mounts, "foreign", stand_in)
    held = GeoIP.find(mine)
    assert held.path == own and held.lookup("8.8.8.8") is None  # passed over
    replace = os.replace

    def held_open(src, dst):  # the rename refused, as a target another program holds is on Windows
        raise PermissionError(13, "the target is held open by another program", str(dst))
    monkeypatch.setattr(os, "replace", held_open)
    with pytest.raises(GeoError, match="a.mmdb was not installed"):
        install_mmdb(gzip.compress(mmdb(PLACES, built=NOVEMBER)), mine, "a")
    monkeypatch.setattr(os, "replace", replace)
    assert held.describe()["open"] is False  # let go for the rename
    judged.clear()
    assert held.lookup("8.8.8.8") is None and held.path == own  # reopened this machine's file, never the other one
    assert judged[:1] == ["b.mmdb"] and held.describe()["open"] is True
    held.close()


def test_a_link_into_another_systems_drive_is_judged_where_it_leads(tmp_path, monkeypatch):
    """(1.58.0's review) On Windows mounts judges a path by its spelling: a link from this machine's disk into a share,
    or into WSL's disk, passed for this machine's own. The guard asks of the path as it really is, its links followed."""
    from liminal_libs import mounts

    theirs, mine = tmp_path / "theirs", tmp_path / "mine"
    theirs.mkdir()
    mine.mkdir()
    there = os.path.realpath(theirs)
    monkeypatch.setattr(mounts, "foreign", lambda path, table=None: str(path).startswith(there))
    link = mine / "geoip"
    if not _link(theirs, link):
        pytest.skip("no link can be made here")
    assert geo.foreign(link, "Reading the GeoIP files").startswith("Reading the GeoIP files: ")
    assert geo.foreign(link / "dbip-city-lite-2026-11.mmdb", "Reading").startswith("Reading: ")
    assert geo.foreign(mine, "Reading") == "" and GeoIP.find(link) is None


def test_an_extended_length_spelling_is_judged_as_its_plain_one():
    """(1.58.0's review) mounts takes any path that starts with \\\\ for a share's, so a local folder spelled
    \\\\?\\C:\\... was taken for another system's: its GeoIP files would stop opening and installs be refused. On
    Windows the spelling is made plain before it is judged; elsewhere, and for any other spelling, it stays as it is."""
    plain = lambda path: geo._plain(path, windows=True)  # noqa: E731
    assert plain("\\\\?\\C:\\Liminal\\store\\data\\geoip") == "C:\\Liminal\\store\\data\\geoip"
    assert plain("\\\\.\\D:\\geoip") == "D:\\geoip"
    assert plain("\\\\?\\UNC\\server\\share\\geoip") == "\\\\server\\share\\geoip"  # a share stays a share
    assert plain("\\\\?\\unc\\server\\share") == "\\\\server\\share"
    for same in ("\\\\server\\share\\geoip", "C:\\geoip", "\\\\?\\Volume{0a1b2c}\\geoip", "\\\\?\\", ""):
        assert plain(same) == same
    assert geo._plain("\\\\?\\C:\\geoip", windows=False) == "\\\\?\\C:\\geoip"  # off Windows: as it is


# 1.75.0: an ASN file's records, as DB-IP's IP to ASN Lite holds them (MaxMind's GeoLite2-ASN names), one under traits
ASNS = [("1.1.1.0/24", {"autonomous_system_number": 9999, "autonomous_system_organization": "not this one"}),
        ("81.2.69.0/24", {"autonomous_system_number": 20712, "autonomous_system_organization": "Andrews & Arnold Ltd"}),
        ("175.16.199.0/24", {"traits": {"autonomous_system_number": "AS4837",
                                        "autonomous_system_organization": "China Unicom"}})]


@needs_reader
def test_an_asn_file_beside_the_geoip_file_gives_each_place_its_network(tmp_path):
    """1.75.0: GeoIP.find opens the ASN file in geoip/asn/ beside the GeoIP file; a place with no network of its own
    gets the ASN file's, one with its own keeps it, and the ASN file places nothing by itself."""
    from liminal_libs import geo
    folder = tmp_path / "geoip"
    folder.mkdir()
    (folder / "dbip-city-lite-2026-11.mmdb").write_bytes(mmdb(PLACES))
    with GeoIP.find(folder) as alone:
        assert alone.asn is None and alone.lookup("81.2.69.142").asn is None and alone.describe()["asn"] is None
    geo.asn_folder(folder).mkdir()
    (geo.asn_folder(folder) / "dbip-asn-lite-2026-11.mmdb").write_bytes(mmdb(ASNS, kind="DBIP-ASN-Lite"))
    g = GeoIP.find(folder)
    try:
        london = g.lookup("81.2.69.142")
        assert (london.city, london.asn, london.org) == ("London", 20712, "Andrews & Arnold Ltd")
        assert g.lookup("1.1.1.1").asn == 13335  # the GeoIP file's own network kept
        changchun = g.lookup("175.16.199.5")
        assert (changchun.asn, changchun.org) == (4837, "China Unicom")  # under traits, as "AS4837"
        assert g.lookup("89.160.20.112").city == "Linköping" and g.lookup("89.160.20.112").asn is None  # none there
        assert g.lookup("10.0.0.1") is None  # the local network: never looked up in either
        d = g.describe()
        assert d["asn"]["file"] == "dbip-asn-lite-2026-11.mmdb" and d["asn"]["type"] == "DBIP-ASN-Lite"
        assert [p.name for p in folder.iterdir() if p.is_file()] == ["dbip-city-lite-2026-11.mmdb"]
    finally:
        g.close()
    assert g.asn.lookup("81.2.69.142") is None  # closed for good with the GeoIP file


def test_a_records_network_is_read_under_the_names_files_use():
    """1.75.0: GeoLite2-ASN's names at the top, GeoIP2's under traits, the shorter ones; a number only a whole one
    of 32 bits."""
    from liminal_libs import geo
    assert geo._network({"autonomous_system_number": 13335, "autonomous_system_organization": "Cloudflare, Inc."}) == (
        13335, "Cloudflare, Inc.")
    assert geo._network({"traits": {"autonomous_system_number": 64500, "isp": "An ISP"}}) == (64500, "An ISP")
    assert geo._network({"asn": "AS4837", "as_org": "China Unicom"}) == (4837, "China Unicom")
    for bad in (True, 0, -5, 1 << 32, "ASX", "12.5", "AS²", "٣", None, [1], {"n": 1}):
        assert geo._network({"autonomous_system_number": bad}) == (None, None)
