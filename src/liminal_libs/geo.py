"""Where an address is on the globe, from a GeoIP file on this machine: for the firewalls' World Wide Web view (the
user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web view' that shows the globe and the
routes incoming all traffic"). The file is DB-IP's Lite City database, the user's choice the same day (mmdb, CC BY
4.0). Wherever places are drawn, the plugin puts "IP Geolocation by DB-IP" with DB-IP's link beside them. The plugin
also holds the download and its address: no outside host is named in the library.

A GeoIP file is read by the maxminddb package. It is imported when first used, so the library imports without it
(`available` says why it cannot read). The file is memory-mapped: by maxminddb's C extension (MODE_MMAP_EXT), else
in pure Python (MODE_MMAP), and never read into memory (MODE_MEMORY would hold all of City Lite's ~121 MB). It
stays on disk and in the system's file cache, and a GeoIP keeps its last 4096 answers. An answer keeps only the
first TEXT characters of each name the file gives (CODE of a country's code), never the record itself: a file's
strings can each run to maxminddb's 2 MiB a lookup, yet an answer stays within about 2 KB, and 4096 of them within
about 8 MB, whatever the file holds.

Nothing leaves the machine: a peer is looked up in the file here, never asked of a service. The local network's
addresses are never looked up (netpath.kind: private, loopback, link-local and a carrier's shared addresses; and
multicast), nor are they when IPv6 carries them in its last 32 bits (`CARRIERS`). They answer None, and the page
counts them as "local network".

The files are kept in the data folder's geoip/ (`data_folder`), one current copy. `install_mmdb` unpacks a download
there beside the old one (the bytes it reads, the bytes it unpacks and the time it takes all bounded), checks that it
reads as a GeoIP file, puts it in place in one step and removes the older copies. `GeoIP.find` opens the newest.

1.75.0: an ASN file (DB-IP's IP to ASN Lite, the same licence) may sit in geoip/asn/ (`asn_folder`), installed and
pruned there apart from the GeoIP file. `GeoIP.find` opens it too (`find_asn`), beside the GeoIP file it opens, and
each place the GeoIP file gives with no network of its own gets the ASN file's: its AS number and organisation.

A folder on another system's drive (`foreign`: WSL's /mnt/c, a share, a network drive) holds that system's files: each
system's platform installs its own, so none there is read or installed from here.

1.101.0 (Monday list item 20, more GeoIP sources): each source's files in a folder of its own (machines/geosources.py),
so an install prunes its own folder alone; a file and its notes (<stem>.json, what its maker said at install) go
together. An install may insist on a packing (plain or gzipped), name the file from its own build time (`name_of`), and
compare the bytes as downloaded with the SHA-256 its maker gave before anything is put in place. `GeoIP.find` takes the
networks file to read beside (its own folder's by default, another's, or none) and a `usable` test that passes over a
file too old to be read (`find_asn`, `newest` and a let-go GeoIP's reopening take it too); `remove` closes, for good,
every GeoIP of this process reading a file, then removes it and its notes."""
from __future__ import annotations

import hashlib
import importlib
import io
import ipaddress
import math
import os
import re
import secrets
import sys
import threading
import time
import weakref
import zlib
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

from . import layout
from .netpath import kind

FOLDER = "geoip"  # the GeoIP files' folder, in the data folder (layout.data_dir())
ASN_FOLDER = "asn"  # 1.75.0: the ASN file's folder, inside FOLDER (its own: an install keeps one file a folder)
# 1.75.0: where a record says its network: MaxMind's GeoLite2-ASN names at its top level (as DB-IP's IP to ASN Lite
# is read), else under traits (GeoIP2's ISP and Enterprise files), else the shorter names some files use
ASN_KEYS = ("autonomous_system_number", "asn", "as_number")
ORG_KEYS = ("autonomous_system_organization", "as_org", "as_name", "organization", "isp")
CACHE = 4096  # answers a GeoIP keeps; the least recently asked goes first
TEXT = 128  # characters an answer keeps of a name, an organisation or a file's kind (none is longer in a real file)
CODE = 8  # characters an answer keeps of a country's code (ISO 3166's have two)
LANGUAGES = 16  # a name's languages looked through when the file has no English one
MAX_UNPACKED = 1 << 30  # bytes an install may unpack to: City Lite is about 121 MB, so a bigger file is no GeoIP file
CHUNK = 1 << 20  # bytes read, unpacked and written at a time
FEED = 1 << 16  # bytes of a gzip download read and handed to zlib at a time (what follows a member's end is copied)
MEMBERS = 1 << 14  # gzip members a download may hold: gzip writes one; bgzip's 64 KiB blocks of 1 GiB are 16,384
BARREN = 2 * CHUNK  # bytes of a download read with nothing unpacked from them: past this it is no GeoIP file
INSTALL_S = 1800.0  # seconds an install may take, its download included (City Lite's ~60 MB at 270 kbit/s)
WALK = 256  # networks a file is stepped through for its first record when opened (a real file's comes in a few)
REOPEN_S = 5.0  # how often a GeoIP an install let go tries the folder's newest file again while none opens
STALE_PART_S = 3600.0  # an install's temporary file not written to for an hour is a leftover: that install died
FILE_MODE = 0o644  # an installed file's mode, less this process's umask: every account that runs the platform reads it
TEMP_TRIES = 100  # names an install tries for its temporary file before it says none is free
GZIP = b"\x1f\x8b"  # a gzip file's first two bytes
SEPARATOR = bytes(16)  # what ends a MaxMind DB file's search tree, before its data
NAME_FORM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")  # an installed file's name, before .mmdb
NAT64 = ipaddress.ip_network("64:ff9b::/96")  # the well-known NAT64 prefix (RFC 6052): an IPv4 address in its last 32 bits
CARRIERS = (ipaddress.ip_network("::ffff:0:0/96"), ipaddress.ip_network("::ffff:0:0:0/96"), NAT64,
            ipaddress.ip_network("::/96"))
# IPv6 carrying an IPv4 address in its last 32 bits, looked up (or not, when local) as that address: IPv4-mapped,
# IPv4-translated (RFC 2765), NAT64's, and the old IPv4-compatible form (RFC 4291; :: and ::1 are IPv6's own)

_OPEN: weakref.WeakSet = weakref.WeakSet()  # this process's GeoIPs with a file mapped (install_mmdb lets them go)
_OPEN_LOCK = threading.Lock()
_PLACING = threading.RLock()  # held while an install puts its file in place, and while a file is opened beside it
_clock = time.monotonic  # an install's deadline and a let-go GeoIP's retries (the tests' stand-in clock)
NOTES = ".json"  # 1.101.0: a file's notes beside it (<stem>.json), pruned and removed with it
PACKINGS = ("auto", "mmdb", "mmdb.gz")  # 1.101.0: what an install takes: either, plain only, gzipped only
BESIDE = object()  # 1.101.0: GeoIP.find's default networks file: the one in the folder's own asn/ (find_asn)


class GeoError(Exception):
    """A GeoIP file cannot be read or installed here: no maxminddb, a file that does not open, a broken download."""


@dataclass(frozen=True, slots=True)
class Place:
    """Where a GeoIP file puts an address: the country (its ISO code and English name), the city, and the point
    (latitude and longitude in degrees; both None when the file knows the country but not the point). The network's
    AS number and organisation are there when the file holds them: an ASN file does, DB-IP's Lite City does not."""
    country: str | None
    country_name: str | None
    city: str | None
    lat: float | None
    lon: float | None
    asn: int | None = None
    org: str | None = None

    @property
    def label(self) -> str:
        """The place in words: "City, Country" as far as either is known; "" when neither is."""
        return ", ".join(p for p in (self.city, self.country_name or self.country) if p)

    def as_dict(self) -> dict:
        return {"country": self.country, "country_name": self.country_name, "city": self.city, "lat": self.lat,
                "lon": self.lon, "asn": self.asn, "org": self.org, "label": self.label}


def data_folder() -> Path:
    """The GeoIP files' folder: geoip/ in the data folder (layout.data_dir())."""
    return layout.data_dir() / FOLDER


def _mounts():
    """liminal_libs.mounts (1.56.0: whose files a path's are), or None with a library from before it."""
    try:
        return importlib.import_module(f"{__package__}.mounts")
    except ImportError:
        return None


_EXTENDED = ("\\\\?\\", "\\\\.\\")  # Windows' extended-length and device spellings of a path: \\?\C:\..., \\.\C:\...


def _plain(path: str, windows: bool | None = None) -> str:
    r"""A Windows path's extended-length or device spelling as its plain one, judged as itself: \\?\C:\x as C:\x, and
    \\?\UNC\server\share as \\server\share (mounts takes any path that starts \\ for a share's, a local folder so spelled
    too). Any other path, and any path off Windows, as it is. Nothing is read: the spelling alone. `windows`: whether
    this is Windows (this machine's word when not given)."""
    if not (sys.platform == "win32" if windows is None else windows):
        return path
    for prefix in _EXTENDED:
        if path[:len(prefix)] == prefix:
            rest = path[len(prefix):]
            if rest[:4].upper() == "UNC\\":
                return "\\\\" + rest[4:]
            if len(rest) >= 2 and rest[1] == ":" and rest[0].isalpha():
                return rest
    return path


def _judged(path) -> str:
    """`path` as mounts.foreign is asked it: links followed (on Windows mounts judges a path by its spelling alone, so a
    link from this machine's disk into a share would pass for this machine's own; on Linux it follows them itself), and
    on Windows in its plain spelling (_plain)."""
    text = _plain(str(path))
    try:
        text = os.path.realpath(text)
    except (OSError, ValueError):
        pass
    return _plain(text)


def foreign(path, what: str) -> str:
    """Why `what` is not done from here with the GeoIP files at `path` (a file, or their folder), in words; "" when it
    is. A path on another system's drive seen through a mount (WSL's /mnt/c, a share, a network drive: mounts.foreign,
    asked of the path as it really is, its links followed: _judged) holds that system's files. Each system's platform
    installs its own (1.58.0, for the suite run a second time inside WSL: its platform keeps its state, its GeoIP files
    among them, on Ubuntu's own disk), and a file mapped from here would keep that system's own update from replacing
    it, so its files are neither read nor installed from here: they count as none installed. "" on a library without
    mounts, and when the check cannot say (as before)."""
    m = _mounts()
    if m is None:
        return ""
    try:
        m.owner_only(_judged(path), what)
    except m.NotHere as e:
        return str(e)
    except Exception:  # noqa: BLE001 - a check that cannot say: the path taken as this system's own, as before
        return ""
    return ""


def available() -> tuple[bool, str]:
    """Whether GeoIP files can be read here (the maxminddb package), and why not."""
    try:
        maxminddb = _maxminddb()
    except GeoError as e:
        return False, str(e)
    version = getattr(maxminddb, "__version__", "")
    reader = f"maxminddb {version}" if version else "maxminddb"
    how = "through its C extension" if _extension() else "in pure Python (no C extension)"
    return True, f"{reader} {how}, the file memory-mapped"


def _maxminddb():
    """The maxminddb module, imported when first used; GeoError saying why when it cannot be."""
    try:
        import maxminddb
    except ImportError as e:
        if e.name == "maxminddb":
            raise GeoError("maxminddb is not installed in this Python") from e
        raise GeoError(f"maxminddb does not import: {e}") from e
    except Exception as e:  # a broken install
        raise GeoError(f"maxminddb does not import: {e}") from e
    if not all(hasattr(maxminddb, name) for name in ("open_database", "MODE_MMAP_EXT", "MODE_MMAP")):
        raise GeoError("this maxminddb cannot map a file (3.2.0 can)")
    return maxminddb


def _extension() -> bool:
    """Whether maxminddb's C extension is here (MODE_MMAP_EXT). Without it the pure-Python reader maps the file."""
    try:
        return hasattr(importlib.import_module("maxminddb.extension"), "Reader")
    except Exception:
        return False


def _open(path: Path):
    """maxminddb's reader over the file, memory-mapped: (the reader, "mmap-ext" or "mmap"). The C extension is used
    when it is here, else the pure-Python reader; never MODE_MEMORY or MODE_FD, which read the whole file into
    memory."""
    maxminddb = _maxminddb()
    if _extension():
        try:
            return maxminddb.open_database(str(path), maxminddb.MODE_MMAP_EXT), "mmap-ext"
        except ValueError:  # the extension is there, yet maxminddb would not use it
            pass
    return maxminddb.open_database(str(path), maxminddb.MODE_MMAP), "mmap"


def _opened(path: Path, called: str | None = None) -> tuple:
    """maxminddb's reader over a GeoIP file, checked as GeoIP, GeoIP.find and an install all rely on: (the reader,
    its mode, the build time, the kind of database, the IP version). maxminddb opens a file by its metadata alone, at
    its end, so a file inside an archive or behind other bytes opens and places nothing. Here the file opens as a
    MaxMind DB file of format 2; its metadata gives a build time, an IP version (4 or 6), a record size (24, 28 or 32
    bits) and a node at least, of those types whichever reader reads it (the pure-Python one checks none); its
    search tree ends where the metadata says, at the 16 zero bytes before the data; and the tree leads to a record
    that decodes, a map as GeoIP2's are. GeoError saying why not, the reader closed again; `called` names the file in
    it (its own name otherwise)."""
    called = called or path.name
    try:
        reader, mode = _open(path)
    except GeoError:
        raise
    except Exception as e:  # missing, empty, not a MaxMind DB file, cut short
        raise GeoError(f"{called} does not open as a GeoIP file: {e}") from e
    try:
        meta = reader.metadata()
        try:
            built, version = int(meta.build_epoch), int(meta.ip_version)
            major, nodes, record = int(meta.binary_format_major_version), int(meta.node_count), int(meta.record_size)
        except (AttributeError, TypeError, ValueError, OverflowError) as e:
            raise GeoError(f"{called} has no usable metadata: {e}") from e
        if major != 2 or version not in (4, 6) or record not in (24, 28, 32) or nodes < 1:
            raise GeoError(f"{called} is no MaxMind DB file of format 2 (format {major}, IPv{version}, {record}-bit "
                           f"records, {nodes:,} nodes)")
        _tree_ends(path, nodes * record // 4, called)  # a node is two records
        _leads_to_a_record(reader, version, called)
        return reader, mode, built, _text(meta.database_type), version
    except BaseException as e:
        reader.close()
        if isinstance(e, GeoError) or not isinstance(e, Exception):
            raise
        raise GeoError(f"{called} has no usable metadata: {e}") from e


def _tree_ends(path: Path, at: int, called: str) -> None:
    """GeoError unless the 16 zero bytes that end a MaxMind DB file's search tree are at `at`, where its metadata
    says the tree ends: the file starts where its tree does."""
    try:
        with open(path, "rb") as f:
            f.seek(at)
            found = f.read(len(SEPARATOR))
    except OSError as e:
        raise GeoError(f"{called} cannot be read: {e}") from e
    if found != SEPARATOR:
        raise GeoError(f"{called} is no GeoIP file as it stands: its search tree does not end where its metadata says "
                       "(a file inside an archive, or with bytes in front of it)")


def _leads_to_a_record(reader, version: int, called: str) -> None:
    """GeoError unless the file's search tree leads to a record that decodes: its networks stepped through from its
    first address, one lookup each, at most WALK of them. A real file's first record comes within a few (each network
    before it is a whole empty branch); a tree that is no tree raises in maxminddb, and one that holds nothing places
    no address."""
    bits = 32 if version == 4 else 128
    address = ipaddress.IPv4Address if bits == 32 else ipaddress.IPv6Address
    at = 0
    for _ in range(WALK):
        try:
            record, prefix = reader.get_with_prefix_len(address(at))
        except Exception as e:  # maxminddb.InvalidDatabaseError: a node or a record past where they can be
            raise GeoError(f"{called} is no GeoIP file as it stands: its search tree does not read: {e}") from e
        if record is not None:
            if isinstance(record, dict):
                return
            raise GeoError(f"{called} is no GeoIP file: its records are no maps, as GeoIP2's are, but "
                           f"{type(record).__name__}")
        if not isinstance(prefix, int) or not 0 <= prefix <= bits:
            raise GeoError(f"{called} is no GeoIP file as it stands: its search tree gives a network of {prefix!r} bits")
        at += 1 << (bits - prefix)
        if at >> bits:
            raise GeoError(f"{called} places no address: its search tree holds no record")
    raise GeoError(f"{called} is no GeoIP file: its first {WALK:,} networks hold no record")


class GeoIP:
    """A GeoIP file open for lookups, memory-mapped: MaxMind DB format, DB-IP's Lite City or any file of
    GeoIP2-City's shape. GeoError when it cannot be opened, and for a file on another system's drive (`foreign`: that
    system's, never mapped from here). close() lets the file go; a GeoIP is a context manager too. An install into its
    folder lets it go as well, and then it opens the folder's newest file at its next lookup."""

    def __init__(self, path, cache: int = CACHE, asn: GeoIP | None = None, usable=None):
        self.path = Path(path)
        self.asn = asn  # 1.75.0: the ASN file's GeoIP (find_asn), whose networks fill in each place's
        self.usable = usable  # 1.101.0: usable(path, built) False for a file not to be read (too old): passed over
        self._max = max(1, int(cache))
        elsewhere = foreign(self.path, "Reading a GeoIP file")
        if elsewhere:
            raise GeoError(elsewhere)
        with _PLACING:  # never while an install puts its file in place: it lets go only the GeoIPs it knows
            self._reader, self.mode, self.built, self.type, self.ip_version = _opened(self.path)
            self._cache: OrderedDict = OrderedDict()  # the answers kept, by address (without an IPv6 zone)
            self._lock = threading.Lock()  # the answers kept, and the reader while it is asked, closed or opened
            self.hits = self.misses = 0  # answers given from the ones kept / looked up in the file
            self._moved = False  # let go by an install, not closed: the next lookup opens the folder's newest file
            self._retry = 0.0  # when that may next be tried (_clock), after a try found none that opens
            with _OPEN_LOCK:
                _OPEN.add(self)

    def lookup(self, ip) -> Place | None:
        """Where `ip` is (a string or an ipaddress address): its Place. None when the file has no place for it, when
        it is no address, and when it is the local network's (private, loopback, link-local, shared or multicast:
        never looked up). An IPv4 address carried in IPv6 (::ffff:a.b.c.d, ::ffff:0:a.b.c.d, NAT64's
        64:ff9b::a.b.c.d, the old ::a.b.c.d) is looked up as the IPv4 address; an IPv6 zone (%eth0) is no part of an
        address. The last `cache` answers are kept, missing places too. A closed GeoIP answers None; one an install
        let go opens the folder's newest file first (every REOPEN_S while none opens)."""
        address = _public(ip)
        if address is None:
            return None
        with self._lock:
            if address in self._cache:
                self._cache.move_to_end(address)
                self.hits += 1
                return self._cache[address]
            if self._reader is None and not self._reopen():
                return None
            self.misses += 1
            place = self._with_network(self._read(address), address)
            self._cache[address] = place
            if len(self._cache) > self._max:
                self._cache.popitem(last=False)
            return place

    def _read(self, address) -> Place | None:
        if address.version == 6 and self.ip_version == 4:
            return None  # an IPv4-only file
        try:
            record = self._reader.get(address)
        except Exception:  # a broken record (maxminddb.InvalidDatabaseError) is no place
            return None
        return _place(record)

    def _with_network(self, place: Place | None, address) -> Place | None:
        """1.75.0: a place with no network of its own given the ASN file's (its AS number and organisation), where
        one is open beside this file and has the address; the place as it was otherwise (and None stays None: the
        ASN file places nothing)."""
        asn = self.asn
        if asn is None or place is None or place.asn is not None:
            return place
        try:
            found = asn.lookup(address)
        except Exception:  # noqa: BLE001 - an ASN file that cannot answer: the place without its network
            return place
        if found is None or (found.asn is None and not found.org):
            return place
        return replace(place, asn=found.asn, org=found.org or place.org)

    def _reopen(self) -> bool:
        """With the lock held, for a GeoIP an install let go: the folder's newest file that opens, opened in its
        place (the same file when the install's rename failed). A copy on another system's drive (`foreign`: a link
        there from this folder) is passed over, as GeoIP() refuses it. Not while an install puts its file in place,
        and tried again every REOPEN_S while none opens. False when it stays closed; a GeoIP closed by close() always
        does."""
        if not self._moved or _clock() < self._retry:
            return False
        if not _PLACING.acquire(blocking=False):  # an install is putting its file in place: the next lookup tries
            return False
        try:
            for path in _copies(self.path.parent):
                if foreign(path, "Reading a GeoIP file"):
                    continue
                try:
                    opened = _opened(path)
                except GeoError:
                    continue
                if not _usable(self.usable, path, opened[2]):  # 1.101.0: a file too old to be read is passed over
                    opened[0].close()
                    continue
                self._reader, self.mode, self.built, self.type, self.ip_version = opened
                self.path, self._moved = path, False
                with _OPEN_LOCK:
                    _OPEN.add(self)
                return True
            self._retry = _clock() + REOPEN_S
            return False
        finally:
            _PLACING.release()

    def usable_now(self) -> bool:
        """1.101.0: whether its file may still be read (its `usable` test, asked now with the open file's build time
        alone: no file is read). One closed for good says False."""
        with self._lock:
            path, built, gone = self.path, self.built, self._reader is None and not self._moved
        return not gone and _usable(self.usable, path, built)

    def describe(self) -> dict:
        """The file: its name and path, its date and build time (from its metadata, UTC), its size in bytes, the
        kind of database, and how it is read ("mmap-ext": maxminddb's C extension; "mmap": pure Python). Also
        whether it is still open, and the answers kept."""
        with self._lock:
            path, built, kinds, mode, asn = self.path, self.built, self.type, self.mode, self.asn
            cache = {"entries": len(self._cache), "max": self._max, "hits": self.hits, "misses": self.misses}
            is_open = self._reader is not None
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        built = _utc(built)
        return {"file": path.name, "path": str(path), "date": built[:10] if built else None,
                "built": built, "size": size, "type": kinds, "mode": mode, "open": is_open, "cache": cache,
                "asn": asn.describe() if asn is not None else None}  # 1.75.0: the ASN file beside it

    def close(self) -> None:
        """The file let go, its map closed (Windows can then replace or delete it), and the answers dropped. For
        good: a closed GeoIP answers None, an install or not."""
        self._shut(moved=False)

    def _shut(self, moved: bool) -> None:
        """The file let go and the answers dropped; `moved`: by an install, so the next lookup opens the newest."""
        with self._lock:
            reader, self._reader = self._reader, None
            self._cache.clear()
            self._moved, self._retry = moved, 0.0
            if reader is not None:
                reader.close()
        with _OPEN_LOCK:
            _OPEN.discard(self)
        if not moved and self.asn is not None:  # 1.75.0: closed for good, the ASN file beside it too
            self.asn.close()

    def __enter__(self) -> GeoIP:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def find(cls, folder=None, cache: int = CACHE, asn=BESIDE, usable=None) -> GeoIP | None:
        """The newest GeoIP file in `folder`, open: the last written *.mmdb there that opens (a broken one is passed
        over). The data folder's geoip/ when no folder is given. None when there is none, when maxminddb is not here,
        and when the folder is on another system's drive (`foreign`: its files are that system's, not even listed).
        1.101.0: `asn` is the networks file read beside it: BESIDE, the folder's own asn/ one (find_asn, as before);
        None, none; a GeoIP, that one. `usable(path, built)`: a file it says False of is passed over (too old)."""
        folder = Path(folder) if folder is not None else data_folder()
        found = newest(folder, cache, usable, cls=cls, what="Reading the GeoIP files")
        if found is not None:
            found.asn = find_asn(folder, cache, usable) if asn is BESIDE else asn  # 1.75.0: the ASN file beside it
        return found


def asn_folder(folder=None) -> Path:
    """1.75.0: the ASN file's folder: ASN_FOLDER inside the GeoIP files' folder (`folder`, else the data folder's)."""
    return (Path(folder) if folder is not None else data_folder()) / ASN_FOLDER


def find_asn(folder=None, cache: int = CACHE, usable=None) -> GeoIP | None:
    """1.75.0: the newest ASN file beside the GeoIP files in `folder` (its asn_folder), open; None when there is
    none, none opens, maxminddb is not here, or the folder is on another system's drive. 1.101.0: `usable` as
    GeoIP.find's."""
    return newest(asn_folder(folder), cache, usable, what="Reading the ASN file")


def newest(folder, cache: int = CACHE, usable=None, *, cls=None, what: str = "Reading the GeoIP files") -> GeoIP | None:
    """1.101.0: the newest file in `folder` itself that opens and `usable(path, built)` does not refuse, open, with
    nothing beside it (a networks file in a folder of its own); None as find_asn says."""
    cls = cls or GeoIP
    folder = Path(folder)
    if not available()[0] or foreign(folder, what):
        return None
    with _PLACING:  # the copies as they are between installs, never halfway through one
        for path in _copies(folder):
            try:
                found = cls(path, cache, usable=usable)
            except GeoError:
                continue
            if _usable(usable, path, found.built):
                return found
            found.close()
    return None


def _usable(usable, path: Path, built) -> bool:
    """1.101.0: whether `usable` lets a file built at `built` be read (none given: every file; one that fails: not)."""
    if usable is None:
        return True
    try:
        return bool(usable(path, built))
    except Exception:  # noqa: BLE001 - a test that cannot say: not read
        return False


def remove(path) -> bool:
    """1.101.0: a GeoIP file removed, its notes (<stem>.json) with it, after every GeoIP of this process reading it is
    closed for good (Windows cannot delete a mapped file). False when the file is still there (another program holds
    it, or the system refused): the caller says so, and it is not read from here meanwhile."""
    path = Path(path)
    elsewhere = foreign(path.parent, "Removing a GeoIP file")
    if elsewhere:
        raise GeoError(elsewhere)
    with _PLACING:
        with _OPEN_LOCK:
            open_now = list(_OPEN)
        for geo in open_now:
            if _same_file(geo.path, path):
                geo._shut(moved=False)
        gone = _remove(path) or not path.exists()
        if gone:
            _remove(path.with_suffix(NOTES))
    return gone


def _same_file(a: Path, b: Path) -> bool:
    return _same_folder(a.parent, b.parent) and os.path.normcase(a.name) == os.path.normcase(b.name)


def _public(ip) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address to look up, or None: no address, or the local network's. An IPv6 zone is dropped (it says which
    link, not where), and an IPv4 address carried in IPv6 is judged and looked up as itself."""
    if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        address = ip
    else:
        text = str(ip).strip()
        if ":" in text:  # IPv6: its zone, of any length, is left out before it is parsed
            text = text.partition("%")[0].strip()
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return None
    if address.version == 6:
        if address.scope_id is not None:
            address = ipaddress.IPv6Address(int(address))
        if int(address) > 1 and any(address in carrier for carrier in CARRIERS):
            address = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    if address.is_multicast or kind(str(address)) != "public":  # netpath.kind counts multicast as public
        return None
    return address


def _place(record) -> Place | None:
    """A Place from a record of GeoIP2-City's shape, as DB-IP's Lite City holds them: country.iso_code,
    country.names.en, city.names.en, location.latitude and .longitude. An ASN file's autonomous_system_number and
    _organization are read too when a record has them. Each string is cut to its first TEXT characters (CODE for the
    code) before it is kept. None when the record says nothing of any of these."""
    if not isinstance(record, dict):
        return None
    country, location = _part(record, "country"), _part(record, "location")
    iso = _text(country.get("iso_code"), CODE)
    lat, lon = _degrees(location.get("latitude"), 90), _degrees(location.get("longitude"), 180)
    if lat is None or lon is None:
        lat = lon = None
    asn, org = _network(record)  # 1.75.0: under the names an ASN file may use
    place = Place(iso.upper()[:CODE] if iso else None, _name(country), _name(_part(record, "city")), lat, lon, asn,
                  org)
    known = place.country or place.country_name or place.city or place.lat is not None or place.asn
    return place if known else None


def _network(record: dict) -> tuple[int | None, str | None]:
    """1.75.0: a record's network, (its AS number, its organisation), each None where it says none: at the record's
    top level, else under its traits (ASN_KEYS, ORG_KEYS)."""
    for part in (record, _part(record, "traits")):
        asn = next((n for n in (_as_number(part.get(k)) for k in ASN_KEYS) if n is not None), None)
        org = next((t for t in (_text(part.get(k)) for k in ORG_KEYS) if t), None)
        if asn is not None or org:
            return asn, org
    return None, None


def _as_number(value) -> int | None:
    """An AS number from a record: a whole number, or a string of one ("AS20115", "20115"); None for anything else,
    and outside 32 bits."""
    if isinstance(value, str):
        digits = value.strip()[:16].upper().removeprefix("AS")
        value = int(digits) if digits.isascii() and digits.isdigit() else None  # "²" is a digit int() refuses
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 < value < 1 << 32 else None


def _part(record: dict, key: str) -> dict:
    part = record.get(key)
    return part if isinstance(part, dict) else {}


def _text(value, most: int = TEXT) -> str | None:
    """A string from the file: its first `most` characters, stripped, so an answer never holds more of the file's
    string than that; None when it is no string, or empty."""
    return (value[:most].strip() or None) if isinstance(value, str) else None


def _name(part: dict) -> str | None:
    """A part's English name (names.en), else its name in the first other language the file gives (of the first
    LANGUAGES)."""
    names = part.get("names")
    if not isinstance(names, dict):
        return None
    return _text(names.get("en")) or next((t for t in map(_text, islice(names.values(), LANGUAGES)) if t), None)


def _degrees(value, limit: float) -> float | None:
    """A latitude (limit 90) or a longitude (180) in degrees; None when it is no number or out of range."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        value = float(value)
    except OverflowError:
        return None
    return value if -limit <= value <= limit else None  # NaN is neither


def _utc(epoch: int) -> str | None:
    """The metadata's build time (seconds since 1970) as an ISO time in UTC; None when it has none."""
    if not epoch or epoch < 0:
        return None
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def _copies(folder: Path) -> list[Path]:
    """The .mmdb files in `folder`, the last written first."""
    def written(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0
    try:
        found = [p for p in folder.glob("*.mmdb") if p.is_file()]
    except OSError:
        return []
    return sorted(found, key=lambda p: (written(p), p.name), reverse=True)


def install_mmdb(source, folder, name: str, limit: int = MAX_UNPACKED, timeout: float | None = INSTALL_S, *,
                 packing: str = "auto", name_of=None, sha256: str | None = None) -> Path:
    """A downloaded GeoIP file put in `folder` as <name>.mmdb; its path.

    `source` is the download's bytes, a binary stream or a path to the file, gzipped (DB-IP's .mmdb.gz) or not. A
    stream is read to its end and left open, so an HTTP response streams straight through. The download itself,
    with its address, is the plugin's, and so is the stream's own timeout on each read.

    The file is unpacked to a temporary file in the same folder and checked: it opens as a GeoIP opens files, its
    search tree ends where its metadata says, and the tree leads to a record that decodes. Its mode is every file's
    of this process (FILE_MODE less the umask, not mkstemp's 0600: _temporary), so whichever account runs the platform
    later reads it; an install refused for want of the right says whose the folder is when it is another account's.
    What an install takes is bounded: at most `limit` bytes unpacked (1 GiB), about as many read, no more than BARREN
    read with nothing unpacked from them, MEMBERS gzip members, and `timeout` seconds in all (half an hour; None: only
    the stream's own timeouts). Then the file is renamed over <name>.mmdb in one step: a reader never sees half a
    file. A broken download leaves the current file as it was: GeoError says why (the stream's own errors too), and
    the temporary file is removed.

    Then the older copies go: every other .mmdb in `folder` (it holds one GeoIP file). A copy another program still
    has open stays for the next install. This process's installs put their files in place one at a time, so two at
    once leave the later one. The temporary files of installs that died (not written to for an hour) go first.

    Just before the rename, every GeoIP of this process reading a file in `folder` is let go: on Windows the
    pure-Python reader's mapped file cannot be replaced or deleted. Each opens the folder's newest file at its next
    lookup (the old one again when the rename failed), and GeoIP.find opens it too.

    A folder on another system's drive (`foreign`) is that system's: GeoError before anything is read or written there,
    the folder not even made.

    1.101.0: `packing` is "auto" (plain or gzipped, as before), "mmdb" (plain only) or "mmdb.gz" (gzipped only): any
    other is refused before anything is read. `name_of(built)`, given the checked file's build time (seconds since
    1970), names it, never before the check. `sha256` (hex): the bytes as downloaded are hashed as they come, and one
    that does not match installs nothing, the current copy kept. Each file's notes (<stem>.json) are pruned with it."""
    if packing not in PACKINGS:
        raise ValueError(f"a GeoIP file's packing is {', '.join(PACKINGS)}, not {packing!r}")
    want = str(sha256 or "").strip().lower()
    if sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", want):
        raise ValueError("a GeoIP file's SHA-256 is 64 hex digits")
    folder = Path(folder)
    elsewhere = foreign(folder, "Installing a GeoIP file")
    if elsewhere:
        raise GeoError(elsewhere)
    _maxminddb()  # nothing is written without the reader that checks it
    stem = _stem(name)
    _readable(source)
    target = folder / f"{stem}.mmdb"
    deadline = math.inf if timeout is None else _clock() + float(timeout)
    temp: Path | None = None
    placed = False
    try:
        folder.mkdir(parents=True, exist_ok=True)
        _sweep(folder)
        handle, temp = _temporary(folder, stem)
        digest = hashlib.sha256() if want else None
        with os.fdopen(handle, "wb") as out:
            _unpack(source, out, limit, deadline, timeout, packing=packing, digest=digest)
            out.flush()
            os.fsync(out.fileno())
        if digest is not None and digest.hexdigest() != want:
            raise GeoError("its bytes are not the ones its maker's SHA-256 names (the download was changed or cut)")
        built = _check(temp)
        if name_of is not None:
            target = folder / f"{_stem(name_of(built))}.mmdb"
        with _PLACING:
            _release(folder)
            os.replace(temp, target)
            placed = True
            _sync(folder)
            _prune(folder, target)
    except Exception as e:  # GeoError; OSError (gzip's and zlib's too, the disk's); the stream's own, an HTTP library's
        if placed:
            raise
        raise GeoError(f"{target.name} was not installed: {e}{_whose(e)}") from e
    finally:
        if temp is not None and not placed:
            _remove(temp)
    return target


def _temporary(folder: Path, stem: str) -> tuple[int, Path]:
    """A new temporary file in `folder` for an install, open for writing, and its path: made as tempfile.mkstemp makes
    one (a name of its own, made only where none is, no link followed), yet with the mode every file this process makes
    has, FILE_MODE less its umask, rather than mkstemp's 0600. The data folder is the checkout's, whichever account runs
    the platform: a file installed while it ran as root stays readable when it runs as its user."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    for _ in range(TEMP_TRIES):
        path = folder / f".{stem}.{secrets.token_hex(6)}.part"
        try:
            return os.open(path, flags, FILE_MODE), path
        except FileExistsError:
            continue
    raise FileExistsError(f"no free name for a temporary file in {folder}")


def _whose(e: BaseException) -> str:
    """For an install refused for want of the right (EACCES, EPERM): whose the file or the folder refused is, when it
    is another account's, in words ("" otherwise, and where this machine cannot say: Windows). The data folder is the
    checkout's, so a folder made while the platform ran as root refuses it when it runs as its user."""
    if not isinstance(e, PermissionError) or not e.filename:
        return ""
    try:
        import pwd
    except ImportError:  # not POSIX
        return ""
    path = Path(os.fsdecode(e.filename))
    for at in (path, path.parent):
        try:
            owner = at.stat().st_uid
        except OSError:
            continue
        me = os.geteuid()
        if owner == me:  # this account's own: its mode refused it, not whose it is
            return ""

        def name(uid: int) -> str:
            try:
                return pwd.getpwuid(uid).pw_name
            except (KeyError, OverflowError):
                return f"uid {uid}"
        return f" ({at} is {name(owner)}'s, and the platform runs as {name(me)})"
    return ""


def _stem(name: str) -> str:
    """The installed file's name before .mmdb: letters, digits, dots, dashes and underscores, and no folder."""
    stem = str(name).strip()
    if stem.lower().endswith(".mmdb"):
        stem = stem[:-len(".mmdb")]
    if not NAME_FORM.fullmatch(stem):
        raise ValueError(f"a GeoIP file's name is letters, digits, dots, dashes and underscores, not {name!r}")
    return stem


def _readable(source) -> None:
    """TypeError unless `source` is a download: its bytes, a path to it, or a stream."""
    if isinstance(source, (bytes, bytearray, memoryview, str, os.PathLike)) or callable(getattr(source, "read", None)):
        return
    raise TypeError(f"a GeoIP download is its bytes, a binary stream or a path, not {type(source).__name__}")


@contextmanager
def _reading(source):
    """A binary stream over the download: its bytes, a path to it, or a stream (the caller's: not closed here)."""
    _readable(source)
    if isinstance(source, (bytes, bytearray, memoryview)):
        yield io.BytesIO(source)
    elif isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as f:
            yield f
    else:
        yield source


class _Download:
    """The download, read through: GeoError once more than `most` bytes have come, once more than BARREN have come
    with nothing unpacked from them (`idle`, which the unpacking sets back to 0), once a read gives something other
    than bytes or more than were asked for, and once the deadline has passed (looked at before each read; a read
    that hangs is the stream's own timeout's)."""

    def __init__(self, raw, most: int, deadline: float = math.inf, timeout: float | None = None, digest=None):
        self._raw, self._most, self._deadline, self._timeout = raw, most, deadline, timeout
        self._digest = digest  # 1.101.0: a hash of the bytes as they come, before anything is unpacked
        self.taken = self.idle = 0  # bytes read in all / since the last byte unpacked

    def read(self, size: int) -> bytes:
        if _clock() > self._deadline:
            took = f"more than {self._timeout:,.0f} s" if self._timeout is not None else "past its deadline"
            raise GeoError(f"the download took {took}")
        got = self._raw.read(size)
        if not isinstance(got, (bytes, bytearray, memoryview)):
            raise GeoError(f"the download's stream gave {type(got).__name__}, not bytes")
        got = bytes(got)
        if len(got) > size:
            raise GeoError(f"the download's stream gave {len(got):,} bytes when asked for {size:,}")
        if self._digest is not None:
            self._digest.update(got)
        self.taken += len(got)
        self.idle += len(got)
        if self.taken > self._most:
            raise GeoError(f"the download runs past {self._most:,} bytes, more than a GeoIP file's")
        if self.idle > BARREN:
            raise GeoError(f"{self.idle:,} bytes of it in a row unpack to nothing: it is no GeoIP file")
        return got


def _read_up_to(stream, n: int) -> bytes:
    """The stream's first `n` bytes (fewer at its end), however few each read gives."""
    out = b""
    while len(out) < n:
        got = stream.read(n - len(out))
        if not got:
            break
        out += got
    return out


def _unpack(source, out, limit: int, deadline: float = math.inf, timeout: float | None = None, *,
            packing: str = "auto", digest=None) -> int:
    """The download's bytes written to `out`, gunzipped when they are gzip; the bytes written. GeoError past `limit`
    bytes written, or when there are none; past MEMBERS gzip members (`_gunzip`); and as `_Download` says, past about
    as many bytes read as `limit` (a gzip stream is never much bigger than what it unpacks to), BARREN read in a row
    with nothing unpacked, or the deadline."""
    with _reading(source) as raw:
        down = _Download(raw, limit + limit // 256 + CHUNK, deadline, timeout, digest)
        head = _read_up_to(down, len(GZIP))
        if packing == "mmdb" and head == GZIP:  # 1.101.0: a source that gives a plain file, and this is gzipped
            raise GeoError("a plain MaxMind DB file was to come, and this one is gzipped")
        if packing == "mmdb.gz" and head != GZIP:
            raise GeoError("a gzipped MaxMind DB file was to come, and this one is not gzipped")
        total = _gunzip(head, down, out, limit) if head == GZIP else _copy(head, down, out, limit)
    if not total:
        raise GeoError("the download is empty")
    return total


def _written(total: int, limit: int) -> None:
    if total > limit:
        raise GeoError(f"it unpacks to more than {limit:,} bytes, more than a GeoIP file holds")


def _copy(data: bytes, down: _Download, out, limit: int) -> int:
    """A download that is no gzip, copied as it is; the bytes written."""
    total = 0
    while data:
        total += len(data)
        _written(total, limit)
        out.write(data)
        down.idle = 0
        data = down.read(CHUNK)
    return total


def _gunzip(data: bytes, down: _Download, out, limit: int) -> int:
    """A gzip download unpacked: its members one after another (zeros may pad its end), each read by zlib itself,
    its header, CRC-32 and length checked there (in C: a header that never ends costs no byte-by-byte reads), FEED
    bytes handed over and at most CHUNK unpacked at a time; the bytes written. GeoError when it is cut short, ends in
    bytes that are no gzip member, or holds more than MEMBERS members."""
    total, members, unzip = 0, 0, None
    while True:
        if unzip is None:  # a member starts here, or the download ends
            data = data.lstrip(b"\0")
            if len(data) < len(GZIP):
                more = down.read(FEED)
                if more:
                    data += more
                    continue
                if data:
                    raise GeoError("it ends in a byte that is no gzip data")
                return total
            if not data.startswith(GZIP):
                raise GeoError("it goes on after its gzip data with bytes that are none")
            members += 1
            if members > MEMBERS:
                raise GeoError(f"it holds more than {MEMBERS:,} gzip members: no GeoIP file is packed so")
            unzip = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)  # one gzip member, header and trailer included
        if not data:
            data = down.read(FEED)
            if not data:
                raise GeoError("it is cut short: its gzip data does not end")
        piece = unzip.decompress(data, CHUNK)
        if piece:
            total += len(piece)
            _written(total, limit)
            out.write(piece)
            down.idle = 0
        if unzip.eof:
            data, unzip = unzip.unused_data, None
        else:
            data = unzip.unconsumed_tail


def _check(path: Path) -> int:
    """The unpacked file reads as a GeoIP file, checked as GeoIP.find checks the files it opens (`_opened`: its
    metadata, where its search tree ends, a record it leads to); GeoError saying why not. It is closed again before
    it is renamed. Its build time (1.101.0: what a source's file is named from)."""
    opened = _opened(path, "it")
    opened[0].close()
    return opened[2]


def _release(folder: Path) -> None:
    """Every GeoIP of this process reading a file in `folder` let go, for the rename and the removals; each opens
    the folder's newest file at its next lookup."""
    with _OPEN_LOCK:
        open_now = list(_OPEN)
    for geo in open_now:
        if _same_folder(geo.path.parent, folder):
            geo._shut(moved=True)


def _same_folder(a: Path, b: Path) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _sync(folder: Path) -> None:
    """The rename written to disk: on Linux the folder's entry is synced too (Windows has no fsync for a folder)."""
    if os.name == "nt":
        return
    try:
        handle = os.open(folder, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


def _prune(folder: Path, keep: Path) -> None:
    """The older copies removed: every other .mmdb in `folder`, and the temporary files of installs that died. A file
    another program still has open stays."""
    for path in _copies(folder):
        if os.path.normcase(path.name) != os.path.normcase(keep.name):
            if _remove(path):
                _remove(path.with_suffix(NOTES))  # 1.101.0: its notes with it
    _sweep(folder)


def _sweep(folder: Path) -> None:
    """The temporary files of installs that died removed: those not written to for STALE_PART_S (an hour)."""
    now = time.time()
    try:
        parts = [p for p in folder.glob(".*.part") if p.is_file()]
    except OSError:
        return
    for path in parts:
        try:
            stale = now - path.stat().st_mtime > STALE_PART_S
        except OSError:
            continue
        if stale:
            _remove(path)


def _remove(path: Path) -> bool:
    try:
        path.unlink()
    except OSError:
        return False
    return True
