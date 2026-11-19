"""Internet infrastructure on the firewalls' globe: the data sets a firewall plugin names, their download on the user's
word, the files they are kept in and the layers the globe draws from them (the user, 2026-11-16: "the firewall app
should also have a globe that can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the
time they are connected to *this *computer"; "the globe-firewall should allow filtering, so i can view apps connected
to hosts all across the globe, or ports talking to all hosts. The globe should have the same kind of geography
associated with the exchanges globe, but the firewall globe should instead of exchanges, have all the backbones,ibones,
major internet infrastructure, (as many as possible) datacenter locations.").

- A data set is a plugin's. Its address, its query, its licence and its credit are plain data in the plugin (DataSet.of
  reads the dict), so no outside host is named in the library. Four formats are read: an Overpass answer
  (OpenStreetMap's features by their tags), a SPARQL answer (Wikidata's items by their kind), a GeoJSON
  FeatureCollection of lines (a WFS's cable routes, asked for longitude first) and maps of networks in GML, gzipped
  and archived together or not (the Internet Topology Zoo's: each network's newest map, its points of presence and the
  links between them, unpacked in memory alone and bounded). Only free-licensed data: its licence's words are shown
  whole first and accepted in so many words, and its credit is drawn whole wherever its features are.
- A download happens only inside install(), on the user's word, as a job: one https GET (world.fetch_url: https on
  every hop, from the same host only) whose User-Agent is the plugin's name and version and nothing of the user's or
  the machine's. It runs on a thread of its own under one deadline, INSTALL_S, while the caller waits, looking at the
  time and at the job's cancel every world.POLL_S and shutting the download's sockets (world.run_download, as the GeoIP
  file's install does). A busy server (HTTP 429, 502, 503 or 504) is asked once more RETRY_S later, inside the same
  deadline. What is read and kept is bounded: MAX_ANSWER bytes of an answer, and as many unpacked (MAX_UNPACKED);
  MAX_MAPS files an archive, MAX_MAP bytes and GML_ITEMS nodes and edges a map; MAX_POINTS points and MAX_VERTICES
  vertices a layer; a line's vertices no nearer than STEP. A download that fails leaves the older file as it was.
- The file is <folder>/<id>.json in the data folder's infrastructure/, each system's own (a folder on another system's
  drive is that system's: geo.foreign), written whole beside itself and put in place in one step. The download itself
  is not kept. Coordinates are packed (base64 of little-endian int32 pairs, longitude and latitude in 1e-5 degrees), so
  a full layer is a few megabytes.
- Index says what is installed (the data sets, the layers they feed, the table the page draws) and reads no geometry
  to look: a file is read again only when its size or its time changed, and only its counts, its credit and its date
  are kept. layer() reads a layer's geometry when the globe asks for it, and keeps none.
- Nothing runs when unused: no thread, no timer, no file left open."""
from __future__ import annotations

import base64
import hashlib
import html
import io
import json
import os
import posixpath
import re
import secrets
import sys
import tarfile
import threading
import time
import zlib
from array import array
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

from .. import geo, layout
from . import world
from .world import LicenceRefused, size_words

FOLDER = "infrastructure"  # the layers' folder, in the data folder (layout.data_dir())
VERSION = 1  # a kept file's "v"
INSTALL_S = 600.0  # seconds a download may take in all: both tries and the wait between them
READ_S = 60.0  # a data set's `wait` when it names none: each socket operation of its download waits this long at most
RETRY_S = 60.0  # a busy server is asked once more after this long
INDEX_S = 10.0  # the folder is looked at again this long after the last look, at the soonest
CHUNK = 1 << 20  # bytes of an answer read at a time, at most
MAX_ANSWER = 32 << 20  # bytes of an answer, and of a kept file: twice the largest data set's estimate (15 MB)
MAX_UNPACKED = 32 << 20  # bytes a gzipped answer unpacks to, and an archive's maps read as, at most (the Topology Zoo's
# 0.35 MB: a few MB)
FEED, FEED_MOST = 256, 64 << 10  # bytes of a gzip member handed to zlib at a time: its first piece, twice as many each
# time after, and the most (what follows its end in that piece is copied: _unpacked)
MAX_MAPS = 2000  # files an archive of maps holds, at most (the Topology Zoo's: 261 maps)
MAX_MAP = 4 << 20  # bytes of one map, at most (the Topology Zoo's largest, of some 750 points: a few hundred kB)
MAX_POINTS = 20_000  # points a layer holds
MAX_VERTICES = 400_000  # vertices a layer's lines hold
NAME = 80  # characters kept of a name
STEP = 0.02  # degrees between a line's kept vertices
OLDEST = 2000  # a network whose newest map is from a year before this is history, not a backbone: left out
LICENCE_FIRST = "A data set is downloaded only once you accept its licence."
LAYERS = (  # id, title, kind, mark, the themes' series slot, on at first, names from this zoom
    ("exchanges", "Exchange points", "points", "diamond", 5, True, 3.0),
    ("datacentres", "Data centres", "points", "square", 4, True, 5.0),
    ("landings", "Cable landing stations", "points", "circle", 6, True, 4.0),
    ("stations", "Ground stations and teleports", "points", "circle", 7, False, 4.0),
    # a backbone's points of presence and its links, as maps of networks give them (the Topology Zoo's, of about 2010
    # and 2011: logical links between cities, not routes of fibre): the data centres' colour, the land lines' colour
    ("pops", "Backbones' points of presence, about 2010-2011", "points", "circle", 4, False, 6.0),
    ("cables", "Submarine cables", "lines", "line", 6, True, 3.0),
    ("backbones", "Backbones, about 2010-2011", "lines", "line", 7, True, 4.0),
    ("lines", "Telecom lines on land (partial)", "lines", "dash", 7, False, 6.0))

FORMATS = ("overpass", "sparql", "geojson", "gml")  # what an answer is read as
AS_WRITTEN = ("geojson", "gml")  # the formats whose query, where they have one, is sent as it is written
SCALE = 100_000  # a coordinate is kept in 1e-5 degrees, about a metre
BUSY = (429, 502, 503, 504)  # HTTP codes of a server too busy to answer now: asked once more
MAX_QUERY = 4000  # characters of a data set's query: it travels in the address
TEXT = 2000  # characters of a licence's words at most: shown whole and accepted, never cut
CREDIT = 2 * NAME  # characters of a credit's text at most: drawn whole wherever its features are
REMARK = 300  # characters said back of a server's remark
STALE_S = 3600.0  # an install's temporary file not written to for this long is a leftover: that install died
TITLE = "Internet infrastructure"  # the table's
LAYER_HOOK, GET_HOOK, REMOVE_HOOK = "world_layer", "world_layer_get", "world_layer_remove"  # the Firewall base's hooks
FORM, REMOVE_FORM = "world-layer-", "world-layer-remove-"  # a data set's forms' ids, its own id after them
ACCEPT = world.ACCEPT_LICENCE  # the argument that, exactly true, makes the download (the page's second confirmation)
USER_AGENT = "liminal-libs (infrastructure data sets)"  # a download's, when its caller names none
ALREADY = "a data set is being downloaded already: wait for it to finish"
CANCELLED = "cancelled: nothing was installed"
ID_FORM = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")  # a data set's id: its file's name and its forms' ids
# a User-Agent: a product's name and its version (and a word or two in brackets), words one space apart; AGENT at most
AGENT_FORM, AGENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/()+-]*(?: [A-Za-z0-9._/()+-]+)*"), 100
# how a WFS is asked for its coordinates longitude first (its srsName): GeoServer reads EPSG:4326 so ("longitude/
# latitude assumption"), and CRS84 is so by definition; urn:ogc:def:crs:EPSG::4326, WFS 2.0's default, is latitude first
LONGITUDE_FIRST = ("epsg:4326", "crs:84", "urn:ogc:def:crs:ogc:1.3:crs84", "urn:ogc:def:crs:ogc::crs84")
# why a feature of an answer is left out, as the words count them ("2 repeated, 1 off the globe")
REPEATED, OFF, SHORT, OVER, OTHER = ("repeated", "off the globe", "under two points", "over the most a layer keeps",
                                     "of no kind asked for")
# and of a map of a network: a point with no place given, one of another network's, a link to a point not drawn
UNPLACED, OUTSIDE, ENDS = "with no place", "outside its network", "between points not drawn"
SITES = (  # an OpenStreetMap site's layer by its tags: the first that fits
    ("exchanges", (("telecom", "internet_exchange"),)),
    ("landings", (("telecom", "cable_landing_station"),)),
    ("datacentres", (("telecom", "data_center"), ("building", "data_center"))))
UNDERWATER = (("location", "underwater"), ("submarine", "yes"), ("seamark:type", "cable_submarine"))  # a cable's tags
# a Wikidata item's layer by its kind: an exchange point, a data centre, a ground station, a teleport
KINDS = {"Q1433061": "exchanges", "Q671224": "datacentres", "Q1349167": "stations", "Q10379228": "stations"}
POINT = re.compile(r"\s*POINT\s*\(\s*(\S+)\s+(\S+)\s*\)\s*", re.IGNORECASE)  # WKT, the longitude first; a place on
# another globe (the Moon's) has that globe's address before it, and is none of the Earth's
ENTITY = re.compile(r"Q\d+")  # an item's own id, where it has no label in the language asked for
NAMES = ("name", "name_", "pipe_name", "cable_name")  # a GeoJSON feature's name: the first of these that has words
OPERATORS = ("operator", "owner")  # else its operator's
DEGREES = ("4326", "crs84")  # how a GeoJSON answer's `crs` ends when its coordinates are longitude and latitude
ASKED = {"overpass": "the tags asked for", "sparql": "the kinds of place asked for", "geojson": "the layers asked for",
         "gml": "the file asked for"}
GZIP, TAR = b"\x1f\x8b", b"ustar"  # a gzip stream's first two bytes; a POSIX tar's magic, at its 257th byte
# a map's file name as the Topology Zoo names a network's maps over the years: its name, its map's year and month
# (Geant2012, Arpanet19706, Garr199901); a name without a year (PionierL3) is a network of its own
SNAPSHOT = re.compile(r"(.+?)((?:19|20)\d\d)(\d{1,2})?")
# GML's tokens (Himsolt's GML, as NetworkX writes it): a comment, a list's start and end, a string, a number (INF and
# NAN among them), a key
GML_TOKEN = re.compile(r'\s*(?:(#[^\n]*)|(\[)|(\])|"([^"]*)"|([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?'
                       r'|[+-]?(?:INF|NAN)(?![A-Za-z0-9_]))|([A-Za-z_][A-Za-z0-9_]*))')
GML_DEPTH = 16  # lists in lists a map may hold
GML_KEYS = 64  # values kept of a graph, a node or an edge (the first of each key)
GML_ITEMS = 100_000  # nodes a map may hold, and as many edges (the Topology Zoo's largest: some 750 and 900)
_I32 = next((c for c in "il" if array(c).itemsize == 4), "i")  # this machine's 4-byte integers, signed and not
_U32 = next((c for c in "IL" if array(c).itemsize == 4), "I")

_INSTALLING = threading.Lock()  # one download at a time in this process, whichever data set
_FILES = threading.Lock()  # held while a kept file is read and while one is put in place or removed
_STATE = threading.Lock()  # guards _NOW
_NOW = {"id": "", "changes": 0}  # the data set being downloaded; how often a file was put in place or removed here


class InfrastructureError(Exception):
    """A data set could not be downloaded, read or kept: nothing was installed, and what was installed before stays."""


# -- a plugin's data set ----------------------------------------------------------------------------------------------
def _text(value) -> str:
    """A plugin's words as they are kept: a string, its whitespace made single spaces; "" for anything else."""
    return " ".join(value.split()) if isinstance(value, str) else ""


def _name(value) -> str:
    """A name as it is kept and drawn: a string's first NAME characters, what cannot be printed made a space; "" for
    anything else."""
    if not isinstance(value, str):
        return ""
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())[:NAME].strip()


def _https(url: str) -> bool:
    """Whether `url` is an https address with a host and nothing of anyone's in it (no user, no password)."""
    try:
        parts = urlsplit(url)
        host, _ = parts.hostname, parts.port  # a port that is none: ValueError
    except ValueError:
        return False
    return bool(parts.scheme.lower() == "https" and host and parts.username is None and parts.password is None)


def _wfs_axes(ident: str, query: str) -> None:
    """ValueError unless a query that asks a WFS (service=WFS, its names in any case) asks for its coordinates longitude
    first (LONGITUDE_FIRST): a WFS answers in the axis order its srsName names, and a GeoJSON answer names its CRS alike
    whichever order it is in, so the order is fixed by what is asked. A query that asks no WFS is let be (a GeoJSON
    file, or an OGC API's features: longitude first unless asked otherwise). The values are read as the WFS reads them,
    their %XX escapes undone."""
    pairs = [(k.strip().lower(), v) for k, v in parse_qsl(query, keep_blank_values=True)]
    if not any(k == "service" and v.strip().lower() == "wfs" for k, v in pairs):
        return
    named = [v for k, v in pairs if k == "srsname"]
    wrong = next((v for v in named if v.strip().lower() not in LONGITUDE_FIRST), None)
    if named and wrong is None:
        return
    raise ValueError(f"the data set {ident} asks a WFS, which answers in the axis order its srsName names: its query "
                     "says srsName=EPSG:4326 (or CRS84), longitude first, not "
                     f"{'none' if wrong is None else world._shown(wrong)}")


@dataclass(frozen=True)
class DataSet:
    """One data set a plugin names: what is asked (`url` and `query`, read as `format`), how large its answer is (`size`
    in bytes, an estimate where its maker gives none), whose it is (`source`), under which licence (`licence_name`, and
    `licence`: its words, shown and accepted before the download) and how it is credited (`credit`: {text, url}, drawn
    wherever its features are). `wait`: seconds each socket operation of its download waits at most (the query's own
    time limit and a margin: a server may be silent for as long as a query runs). `about`: what it holds, in a few
    words. Frozen, and hashed by all but its credit (a dict, compared all the same)."""

    id: str
    title: str
    format: str
    url: str
    query: str
    size: int
    licence: str
    licence_name: str
    credit: Mapping = field(hash=False)
    source: str
    about: str = ""
    wait: float = READ_S

    @classmethod
    def of(cls, said) -> "DataSet":
        """A plugin's plain dict as a data set (a DataSet as it is); ValueError, saying what is missing or wrong: an
        address that is no https one, no licence or one longer than TEXT, no credit or one longer than CREDIT (neither
        is ever cut), no size, a format that is none of FORMATS, a WFS not asked for its coordinates longitude
        first."""
        if isinstance(said, cls):
            return said
        if not isinstance(said, Mapping):
            raise ValueError("a data set is a plugin's dict (id, title, format, url, query, size, licence, "
                             f"licence_name, credit, source), not {type(said).__name__}")
        ident = said.get("id")
        if not isinstance(ident, str) or not ID_FORM.fullmatch(ident) or ident.startswith("remove"):
            raise ValueError("a data set's id is lowercase letters, digits and dashes (40 at most, not beginning with "
                             f"remove), not {world._shown(ident)}")

        def named(key: str, what: str, most: int = NAME) -> str:
            text = _text(said.get(key))
            if not text:
                raise ValueError(f"the data set {ident} names no {what}")
            return text[:most]
        title = named("title", "title")
        form = _text(said.get("format")).lower()
        if form not in FORMATS:
            raise ValueError(f"the data set {ident}'s format is {', '.join(FORMATS[:-1])} or {FORMATS[-1]}, not "
                             f"{world._shown(said.get('format'))}")
        url = named("url", "address", MAX_QUERY)
        if not _https(url):
            raise ValueError(f"the data set {ident} is downloaded over https only, not from {world._where(url)}")
        if any(c in url for c in "?# "):
            raise ValueError(f"the data set {ident}'s address holds no space and no query of its own: what is asked is "
                             "its query")
        query = said.get("query", "")
        if not isinstance(query, str) or len(query) > MAX_QUERY:
            raise ValueError(f"the data set {ident}'s query is text, {MAX_QUERY:,} characters at most")
        query = query.strip()
        if form not in AS_WRITTEN and not query:
            raise ValueError(f"the data set {ident} names no query")
        if form in AS_WRITTEN and re.search(r"[\s#]", query):
            raise ValueError(f"the data set {ident}'s query is sent as it is written (name=value&name=value): it holds "
                             "no space and no #")
        if form == "geojson":
            _wfs_axes(ident, query)
        size = said.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ValueError(f"the data set {ident} says no size: its bytes are said before it is downloaded (an "
                             "estimate where its maker gives none)")
        licence = named("licence", "licence: its words are shown and accepted before the download", sys.maxsize)
        if len(licence) > TEXT:
            raise ValueError(f"the data set {ident}'s licence is {TEXT:,} characters at most: the words the user "
                             "accepts are shown whole")
        licence_name = named("licence_name", "short name for its licence (licence_name: ODbL 1.0, CC0)")
        credit = said.get("credit")
        text = _text(credit.get("text")) if isinstance(credit, Mapping) else ""
        if not text:
            raise ValueError(f"the data set {ident} names no credit: its text is drawn wherever its features are")
        if len(text) > CREDIT:
            raise ValueError(f"the data set {ident}'s credit is {CREDIT} characters at most: it is drawn whole "
                             "wherever its features are")
        link = _text(credit.get("url"))
        if link and not _https(link):
            raise ValueError(f"the data set {ident}'s credit links an https address, not {world._where(link)}")
        source = named("source", "source (whose data it is, in words)")
        wait = said.get("wait", READ_S)
        if isinstance(wait, bool) or not isinstance(wait, (int, float)) or not 1 <= wait <= INSTALL_S:
            raise ValueError(f"the data set {ident}'s wait is a number of seconds from 1 to {INSTALL_S:g} (its query's "
                             f"own time limit and a margin), not {world._shown(wait)}")
        return cls(id=ident, title=title, format=form, url=url, query=query, size=size, licence=licence,
                   licence_name=licence_name, credit={"text": text, "url": link}, source=source,
                   about=_text(said.get("about"))[:2 * NAME], wait=float(wait))

    @property
    def host(self) -> str:
        """The host it is asked of."""
        return world._host(self.url).lower()

    def address(self) -> str:
        """The one address asked: an Overpass server's with the query as its `data`, a SPARQL service's with the query
        and the JSON format, a GeoJSON source's or a file of maps' with its query as it is written (or alone, a
        file's)."""
        if self.format == "overpass":
            return f"{self.url}?data={quote(self.query, safe='')}"
        if self.format == "sparql":
            return f"{self.url}?format=json&query={quote(self.query, safe='')}"
        return f"{self.url}?{self.query}" if self.query else self.url


def folder() -> Path:
    """The layers' folder: infrastructure/ in the data folder (layout.data_dir()), on each system's own disk."""
    return layout.data_dir() / FOLDER


def foreign(p=None) -> str:
    """Why the infrastructure layers are not kept at `p` (their folder when not given) from here, in words; "" when
    they are. A folder on another system's drive seen through a mount (geo.foreign: WSL's /mnt/c, a share, a network
    drive) holds that system's files: each system's platform downloads its own, so nothing there is read, written or
    removed from here."""
    return geo.foreign(folder() if p is None else p, "Keeping the infrastructure layers")


def _resolved(given) -> Path:
    """The folder a call works in: the one given, else the data folder's (folder(), as it is now)."""
    return folder() if given is None else Path(given)


# -- an answer's features ---------------------------------------------------------------------------------------------
def _pairs(items: list):
    """json's object_pairs_hook for an Overpass answer: a {lat, lon} object (a way's vertex, a centre) as the tuple
    (lon, lat), every other object as a dict. The vertices then take a third of the memory (measured for the land
    lines' 263,625: tens of megabytes for a moment, not hundreds)."""
    if len(items) == 2:
        (a, x), (b, y) = items
        if a == "lat" and b == "lon":
            return (y, x)
        if a == "lon" and b == "lat":
            return (x, y)
    return dict(items)


def _begins(raw) -> str:
    """How an answer that is no JSON begins, in words: its first 60 characters, for the refusal."""
    head = raw[:60] if isinstance(raw, str) else bytes(raw[:60]).decode("utf-8", "replace")
    head = " ".join("".join(c if c.isprintable() else " " for c in head).split())
    return f"it begins {head!r}" if head else "it is empty"


def _decoded(dataset: DataSet, data):
    """A data set's answer decoded: its bytes (or its text) as JSON; one decoded already as it is. A file of maps
    (gml) is read as its bytes: its text as UTF-8. InfrastructureError when it is no JSON."""
    if dataset.format == "gml":
        return data.encode("utf-8") if isinstance(data, str) else bytes(data) if isinstance(data, memoryview) else data
    if not isinstance(data, (bytes, bytearray, memoryview, str)):
        return data
    raw = bytes(data) if isinstance(data, memoryview) else data
    try:
        return json.loads(raw, object_pairs_hook=_pairs) if dataset.format == "overpass" else json.loads(raw)
    except (ValueError, RecursionError):
        raise InfrastructureError(f"{dataset.host}'s answer is not the data asked for (it is no JSON: "
                                  f"{_begins(raw)})") from None


def _spot(lon, lat) -> tuple[int, int] | None:
    """A place in 1e-5 degrees, (longitude, latitude); None for what is no point of the globe."""
    for v in (lon, lat):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return None
    if not (-180 <= lon <= 180 and -90 <= lat <= 90):  # NaN and the infinities are neither
        return None
    return round(lon * SCALE), round(lat * SCALE)


def _lonlat(v) -> tuple:
    """A vertex or a centre as (longitude, latitude): the tuple _pairs made, a GeoJSON position [lon, lat, ...] or a
    {lat, lon} object; (None, None) for anything else."""
    if isinstance(v, (tuple, list)):
        return (v[0], v[1]) if len(v) >= 2 else (None, None)
    if isinstance(v, Mapping):
        return v.get("lon"), v.get("lat")
    return None, None


def _thinned(vertices) -> list[tuple[int, int]] | None:
    """A line's vertices as they are kept, each in 1e-5 degrees: one nearer than STEP to the last kept is left out, its
    first and its last always kept (a cable ends where it lands). None when one of them is no point of the globe: the
    line is not to be trusted."""
    step = round(STEP * SCALE)
    out: list[tuple[int, int]] = []
    last = None
    for v in vertices:
        last = _spot(*_lonlat(v))
        if last is None:
            return None
        if not out or abs(last[0] - out[-1][0]) >= step or abs(last[1] - out[-1][1]) >= step:
            out.append(last)
    if last is not None and last != out[-1]:
        out.append(last)
    return out


class _Kept:
    """What a parse keeps, by layer, within its bounds: MAX_POINTS points and MAX_VERTICES vertices a layer, nothing
    twice, nothing off the globe, no line under two points. What is left out is counted by why (`dropped`)."""

    def __init__(self):
        self.layers: dict[str, dict] = {}
        self.dropped: dict[str, int] = {}
        self.remarks: list[str] = []  # what the server remarked that is no error, said on
        self._seen: dict[str, set] = {}
        self._vertices: dict[str, int] = {}

    def drop(self, why: str) -> None:
        self.dropped[why] = self.dropped.get(why, 0) + 1

    def point(self, layer: str, lon, lat, name="", sub="") -> None:
        spot = _spot(lon, lat)
        if spot is None:
            return self.drop(OFF)
        name, sub = _name(name), _name(sub)
        seen = self._seen.setdefault(layer, set())
        if (spot, name.casefold()) in seen:
            return self.drop(REPEATED)
        points = self.layers.setdefault(layer, {"points": [], "lines": []})["points"]
        if len(points) >= MAX_POINTS:
            return self.drop(OVER)
        seen.add((spot, name.casefold()))
        points.append((spot[0] / SCALE, spot[1] / SCALE, name, "" if sub == name else sub))

    def line(self, layer: str, vertices, name="") -> None:
        spots = _thinned(vertices)
        if spots is None:
            return self.drop(OFF)
        if len(spots) < 2:
            return self.drop(SHORT)
        mark = hash(tuple(spots))
        seen = self._seen.setdefault(layer, set())
        if mark in seen:
            return self.drop(REPEATED)
        used = self._vertices.get(layer, 0)
        if used + len(spots) > MAX_VERTICES:
            return self.drop(OVER)
        seen.add(mark)
        self._vertices[layer] = used + len(spots)
        self.layers.setdefault(layer, {"points": [], "lines": []})["lines"].append(
            ([(x / SCALE, y / SCALE) for x, y in spots], _name(name)))

    def features(self) -> dict:
        layers = {layer: self.layers[layer] for layer, *_ in LAYERS
                  if layer in self.layers and (self.layers[layer]["points"] or self.layers[layer]["lines"])}
        return {"layers": layers, "features": sum(len(e["points"]) + len(e["lines"]) for e in layers.values()),
                "dropped": dict(self.dropped), "remarks": list(self.remarks)}


def _place(e: Mapping) -> tuple:
    """Where an OpenStreetMap element is, as one point (longitude, latitude): a node's own place, a way's or a
    relation's centre (out center), else the middle of its bounds (out geom, out bb); (None, None) without any."""
    if "lat" in e and "lon" in e:
        return e.get("lon"), e.get("lat")
    if e.get("center") is not None:
        return _lonlat(e["center"])
    b = e.get("bounds")
    if isinstance(b, Mapping):
        try:
            return (b["minlon"] + b["maxlon"]) / 2, (b["minlat"] + b["maxlat"]) / 2
        except (KeyError, TypeError):
            pass
    return None, None


def _overpass(doc, kept: _Kept, host: str, free: bool) -> None:
    """An Overpass answer's elements by their tags: a site (a data centre, an exchange point, a landing station) a
    point; a way printed with its geometry a line, a cable's when its tags say it lies under water. A remark that is an
    error means the query did not finish: what came is not all there is, and nothing of it is kept."""
    elements = doc.get("elements") if isinstance(doc, Mapping) else None
    if not isinstance(elements, list):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it holds no list of elements)")
    remark = _text(doc.get("remark"))[:REMARK]
    if remark:
        if "error" in remark.lower():  # "runtime error: Query timed out ..."
            raise InfrastructureError(f"{host} could not finish the query: {remark}")
        kept.remarks.append(f"{host} remarked: {remark}")
    for i, e in enumerate(elements):
        if free:
            elements[i] = None  # let go as it is read: the answer is not held whole beside what is kept of it
        tags = e.get("tags") if isinstance(e, Mapping) else None
        if not isinstance(tags, Mapping):
            kept.drop(OTHER)
            continue
        layer = next((layer for layer, pairs in SITES if any(tags.get(k) == v for k, v in pairs)), "")
        operator, owner = _name(tags.get("operator")), _name(tags.get("owner"))
        name = _name(tags.get("name")) or operator
        if layer:  # its sub: who runs it, else whose it is (the owner's where the operator's name is its name)
            kept.point(layer, *_place(e), name, operator if operator and operator != name else owner)
        elif isinstance(e.get("geometry"), list):
            under = any(tags.get(k) == v for k, v in UNDERWATER)
            kept.line("cables" if under else "lines", e["geometry"], name)
        else:
            kept.drop(OTHER)


def _value(row: Mapping, key: str) -> str:
    cell = row.get(key)
    value = cell.get("value") if isinstance(cell, Mapping) else None
    return value if isinstance(value, str) else ""


def _label(row: Mapping, key: str) -> str:
    """A label as a name: none where the service gave the item's own id for want of one."""
    text = _name(_value(row, key))
    return "" if ENTITY.fullmatch(text) else text


def _sparql(doc, kept: _Kept, host: str, free: bool) -> None:
    """A SPARQL answer's bindings: `kind` says the layer (KINDS), `coord` the place ("Point(lon lat)"), `itemLabel`
    the name and `operatorLabel` who runs it."""
    results = doc.get("results") if isinstance(doc, Mapping) else None
    rows = results.get("bindings") if isinstance(results, Mapping) else None
    if not isinstance(rows, list):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it holds no results.bindings)")
    for i, row in enumerate(rows):
        if free:
            rows[i] = None
        layer = KINDS.get(_value(row, "kind").rstrip("/").rsplit("/", 1)[-1]) if isinstance(row, Mapping) else None
        if layer is None:
            kept.drop(OTHER)
            continue
        found = POINT.fullmatch(_value(row, "coord"))
        try:
            lon, lat = (float(found.group(1)), float(found.group(2))) if found else (None, None)
        except ValueError:
            lon = lat = None
        kept.point(layer, lon, lat, _label(row, "itemLabel"), _label(row, "operatorLabel"))


def _property(properties, keys) -> str:
    """The first of a GeoJSON feature's properties `keys` (in any case) that holds words; "" when none does."""
    if not isinstance(properties, Mapping):
        return ""
    low = {str(k).lower(): v for k, v in properties.items()}
    return next((text for text in (_name(low.get(k)) for k in keys) if text), "")


def _geojson(doc, kept: _Kept, host: str, free: bool) -> None:
    """A GeoJSON FeatureCollection's lines (LineString, and each part of a MultiLineString) as cables, named by their
    properties (NAMES, else OPERATORS). Positions are [longitude, latitude] in degrees: an answer that says its
    coordinates are another system's is refused."""
    features = doc.get("features") if isinstance(doc, Mapping) and doc.get("type") == "FeatureCollection" else None
    if not isinstance(features, list):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it is no GeoJSON FeatureCollection)")
    crs = doc.get("crs")
    crs = crs.get("properties") if isinstance(crs, Mapping) else None
    system = _text(crs.get("name")) if isinstance(crs, Mapping) else ""
    if system and not system.lower().endswith(DEGREES):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (its coordinates are in {system[:60]}, "
                                  "not in degrees of longitude and latitude)")
    for i, feature in enumerate(features):
        if free:
            features[i] = None
        geometry = feature.get("geometry") if isinstance(feature, Mapping) else None
        kind = geometry.get("type") if isinstance(geometry, Mapping) else None
        parts = geometry.get("coordinates") if kind in ("LineString", "MultiLineString") else None
        if not isinstance(parts, list):
            kept.drop(OTHER)
            continue
        name = _property(feature.get("properties"), NAMES) or _property(feature.get("properties"), OPERATORS)
        for part in ([parts] if kind == "LineString" else parts or [()]):
            kept.line("cables", part if isinstance(part, list) else (), name)


# -- maps of networks in GML (the Topology Zoo's) ---------------------------------------------------------------------
class _Unread(ValueError):
    """A map that does not read as GML, and why."""


def _unpacked(data, host: str):
    """A gml answer unpacked: a gzipped one, each of its gzip members in turn as gzip reads them, MAX_UNPACKED bytes at
    most; one that is not gzipped as it is. A member is handed to zlib a piece at a time, FEED bytes first and twice as
    many each time after, FEED_MOST at most: what follows the member's end in its last piece is copied (zlib's
    unused_data), so the work grows with the answer however many members it holds (handed the whole rest of the
    answer, 320,000 empty members took 306 s). InfrastructureError for one that does not unpack, is cut short or would
    unpack to more."""
    if bytes(data[:2]) != GZIP:
        return data
    view, out, at = memoryview(data), bytearray(), 0
    while len(view) - at >= 2 and bytes(view[at:at + 2]) == GZIP:
        unzip, feed = zlib.decompressobj(16 + zlib.MAX_WBITS), FEED
        while not unzip.eof:
            given = view[at:at + feed]
            if not given:
                raise InfrastructureError(f"{host}'s answer is not the data asked for (it is cut short)")
            try:
                piece = unzip.decompress(given, MAX_UNPACKED + 1 - len(out))  # a byte more than may be: too much
            except zlib.error as e:
                raise InfrastructureError(f"{host}'s answer is not the data asked for (it does not unpack: "
                                          f"{_text(str(e))[:REMARK]})") from None
            out += piece
            if len(out) > MAX_UNPACKED:
                raise InfrastructureError(f"{host}'s answer unpacks to more than {size_words(MAX_UNPACKED)}, the most "
                                          "a data set may be")
            at += len(given) - len(unzip.unconsumed_tail) - len(unzip.unused_data)  # what of the piece zlib read
            feed = min(2 * feed, FEED_MOST)
    return bytes(out)


def _maps(raw, host: str) -> list[tuple[str, object]]:
    """The maps an unpacked gml answer holds, read in memory and never written out: (its file's name without .gml, its
    bytes, or None for one over MAX_MAP bytes) for each regular file of a tar archive whose name ends .gml (macOS's ._
    copies of their metadata left out); a map alone, no archive, as ("", its bytes). The maps read are MAX_UNPACKED
    bytes at most in all, counted by the sizes their members say, before each is read. A GNU sparse file stores
    nothing and reads as the size it says, in zeros: 64 of them in 514 bytes once read as 268 MB. InfrastructureError
    for an archive that does not read whole, holds more than MAX_MAPS files or more than MAX_UNPACKED bytes of maps.
    tarfile reads a long name or an extended header, then the header after it, by recursion: a chain of them too deep
    is an archive that does not read."""
    if bytes(raw[257:262]) != TAR:
        return [("", raw)]
    maps: list[tuple[str, object]] = []
    held = 0  # the bytes the maps read so far say they are
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            for count, member in enumerate(tar, 1):
                if count > MAX_MAPS:
                    raise InfrastructureError(f"{host}'s answer is not the data asked for (its archive holds more than "
                                              f"{MAX_MAPS:,} files)")
                base = posixpath.basename(member.name)
                if not member.isfile() or not base.lower().endswith(".gml") or base.startswith("._"):
                    continue
                if member.size > MAX_MAP:
                    maps.append((base[:-4], None))
                    continue
                held += max(0, member.size)
                if held > MAX_UNPACKED:
                    raise InfrastructureError(f"{host}'s answer unpacks to more than {size_words(MAX_UNPACKED)}, the "
                                              "most a data set may be")
                maps.append((base[:-4], tar.extractfile(member).read(MAX_MAP + 1)))
    except (tarfile.TarError, EOFError, OSError, ValueError) as e:
        raise InfrastructureError(f"{host}'s answer is not the data asked for (its archive does not read: "
                                  f"{_text(str(e))[:REMARK]})") from None
    except RecursionError:  # a long name or an extended header is read, then the header after it, by recursion
        raise InfrastructureError(f"{host}'s answer is not the data asked for (its archive does not read: its headers "
                                  "are chained deeper than can be read)") from None
    return maps


def _gml_text(raw) -> str:
    """A map's text: UTF-8 (a byte-order mark let go), else Latin-1, GML's own character set as older tools wrote it."""
    try:
        return bytes(raw).decode("utf-8-sig")
    except UnicodeDecodeError:
        return bytes(raw).decode("latin-1")


def _number(token: str):
    """A GML number: an integer, else a real (INF and NAN among them). _Unread for an integer of more digits than
    Python reads one (sys.get_int_max_str_digits(), 4,300 by default), which no map holds: int()'s ValueError is no
    _Unread, and once failed the whole answer for one such map."""
    if not re.fullmatch(r"[+-]?\d+", token):
        return float(token)
    try:
        return int(token)
    except ValueError:
        raise _Unread(f"it holds a number of {len(token.lstrip('+-')):,} digits, more than can be read") from None


def _graph(text: str) -> tuple[dict, list[dict], list[dict]]:
    """A GML map's graph: its own values, its nodes' and its edges' (of each the first value of each key, GML_KEYS at
    most), what is outside the graph and the lists inside a node or an edge (its graphics) read past. _Unread when it
    is no GML: a token that is none, a bracket that closes nothing or is never closed, a key with no value or a value
    with no key, lists nested deeper than GML_DEPTH, no graph; and for a map of more than GML_ITEMS nodes or edges."""
    graph: dict | None = None
    nodes: list[dict] = []
    edges: list[dict] = []
    stack: list = []  # the lists open: each the dict its values go to, or None for one read past
    key, at = None, 0
    while True:
        found = GML_TOKEN.match(text, at)
        if found is None:
            rest = text[at:].lstrip()
            if rest:
                raise _Unread(f"it holds no GML at character {len(text) - len(rest):,}")
            break
        at = found.end()
        comment, opened, closed, string, number, word = found.groups()
        if comment is not None:
            continue
        if key is None:  # a key goes here, or the end of a list
            if word is not None:
                key = word
            elif closed is not None and stack:
                stack.pop()
            else:
                raise _Unread(("a bracket that closes nothing" if closed is not None else "a value with no key")
                              + f" at character {found.start(found.lastindex):,}")
            continue
        if opened is not None:
            if len(stack) >= GML_DEPTH:
                raise _Unread(f"its lists are nested more than {GML_DEPTH} deep")
            into = None
            if not stack and key == "graph" and graph is None:
                into = graph = {}
            elif len(stack) == 1 and stack[0] is graph and graph is not None and key in ("node", "edge"):
                items = nodes if key == "node" else edges
                if len(items) >= GML_ITEMS:
                    raise _Unread(f"it holds more than {GML_ITEMS:,} {key}s")
                into = {}
                items.append(into)
            stack.append(into)
        elif string is not None or number is not None:
            holder = stack[-1] if stack else None
            if holder is not None and key not in holder and len(holder) < GML_KEYS:
                holder[key] = string if string is not None else _number(number)
        else:
            raise _Unread(f"its key {key[:40]!r} has no value")
        key = None
    if stack:
        raise _Unread("a list in it is never closed")
    if key is not None:
        raise _Unread(f"its key {key[:40]!r} has no value")
    if graph is None:
        raise _Unread("it holds no graph")
    return graph, nodes, edges


def _words_of(value) -> str:
    """A map's name or label as words: its text, its &-escapes undone; an integer's digits; "" for anything else."""
    if isinstance(value, str):
        return _name(html.unescape(value))
    return str(value) if isinstance(value, int) and not isinstance(value, bool) else ""


def _year(graph: Mapping) -> int:
    """A map's year as its own values say it (DateYear, else NetworkDate's first four digits); 0 where they do not."""
    for key in ("DateYear", "NetworkDate"):
        found = re.match(r"\s*((?:19|20)\d\d)", str(graph.get(key, "")))
        if found:
            return int(found.group(1))
    return 0


def _network(kept: _Kept, graph: Mapping, nodes: list, edges: list, year: int, called: str) -> None:
    """One network's map into the layers: each of its own points of presence (Internal not 0; a hyperedge is none) that
    has a place (Longitude, Latitude) a point of "pops", named by its label and its network, its network and year its
    sub; each link between two of them a line of "backbones", from the end further west to the other (the globe draws
    the great circle between them), named by its network, its year and its ends."""
    network = _words_of(graph.get("Network")) or _words_of(graph.get("label")) or _name(called) or "a network"
    sub = f"{network}, {year}" if year else network
    placed: dict = {}  # a point's id -> (longitude, latitude, label), for its links
    for node in nodes:
        if node.get("hyperedge") not in (None, 0, "0"):
            kept.drop(OTHER)
            continue
        if node.get("Internal") in (0, "0"):
            kept.drop(OUTSIDE)
            continue
        lon, lat = node.get("Longitude"), node.get("Latitude")
        if lon is None or lat is None:
            kept.drop(UNPLACED)
            continue
        label = _words_of(node.get("label"))
        kept.point("pops", lon, lat, f"{label} ({network})" if label else network, sub)
        if _spot(lon, lat) is not None and node.get("id") is not None:
            placed[node["id"]] = (lon, lat, label)
    for edge in edges:
        ends = (placed.get(edge.get("source")), placed.get(edge.get("target")))
        if None in ends:
            kept.drop(ENDS)
            continue
        a, b = sorted(ends)
        kept.line("backbones", [(a[0], a[1]), (b[0], b[1])], f"{sub}: {a[2] or 'a point'} to {b[2] or 'a point'}")


def _gml(doc, kept: _Kept, host: str, free: bool) -> None:
    """A gml answer's networks: maps in GML, in a tar archive (gzipped or not) or one alone, as the Internet Topology
    Zoo gives them. Of each network its newest map, its file's name saying its network and its map's year (SNAPSHOT:
    Geant2009, Geant2012), unless that is from a year before OLDEST; drawn by _network. The answer is read as its bytes
    (`free` has nothing to let go). What was read is said as a remark: how many maps, how many networks drawn, how
    many maps left out and why. InfrastructureError when it is not the data asked for: it does not unpack, its archive
    does not read, or it holds no map that reads."""
    if not isinstance(doc, (bytes, bytearray)):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it is no file of maps)")
    maps = _maps(_unpacked(doc, host), host)
    newest: dict[str, tuple] = {}  # a network (its family of maps) -> (its map's year and month, its name, its bytes)
    for name, raw in maps:
        found = SNAPSHOT.fullmatch(name)
        family = found.group(1) if found else name
        when = (int(found.group(2)), int(found.group(3) or 0)) if found else (0, 0)
        mine = newest.get(family.casefold())
        if mine is None or (when, name) > mine[:2]:
            newest[family.casefold()] = (when, name, raw, family)
    drawn = old = 0
    unread: list[str] = []  # why each map that does not read does not, its name first
    for family in sorted(newest):
        (year, _), name, raw, called = newest[family]
        try:
            if raw is None or len(raw) > MAX_MAP:
                raise _Unread(f"it is larger than {size_words(MAX_MAP)}")
            graph, nodes, edges = _graph(_gml_text(raw))
        except _Unread as e:  # said with its file's name, as a name is kept (printable, NAME characters at most)
            unread.append(f"{_name(name)}: {e}" if name else str(e))
            continue
        year = year or _year(graph)
        if year and year < OLDEST:
            old += 1
            continue
        drawn += 1
        _network(kept, graph, nodes, edges, year, called)
    if not drawn and not old:
        if not maps:
            why = "its archive holds no GML map"
        elif maps[0][0]:
            why = f"no map of it reads: {unread[0]}"
        else:  # no archive, and its one file no map
            why = f"it is no GML map, nor an archive of them: {unread[0]}; {_begins(maps[0][1] or b'')}"
        raise InfrastructureError(f"{host}'s answer is not the data asked for ({why})")
    said = [f"{world._plural(len(maps), 'map')} in the answer: {world._plural(drawn, 'network')} drawn, each from its "
            "newest map"]
    if len(maps) > len(newest):
        said.append(f"{world._plural(len(maps) - len(newest), 'older map')} of the same networks left out")
    if old:
        said.append(f"{world._plural(old, 'network')} whose newest map is from before {OLDEST} left out")
    if unread:
        said.append(f"{world._plural(len(unread), 'map')} that did not read left out ({unread[0]})")
    kept.remarks.append("; ".join(said))


_READERS = {"overpass": _overpass, "sparql": _sparql, "geojson": _geojson, "gml": _gml}


def _features(dataset: DataSet, doc, free: bool) -> dict:
    kept = _Kept()
    _READERS[dataset.format](doc, kept, dataset.host, free)
    return kept.features()


def parse(dataset, data) -> dict:
    """The features of a data set's answer, by layer: {"layers": {layer: {"points": [(lon, lat, name, sub)], "lines":
    [(vertices, name)]}}, "features": how many, "dropped": {why: how many}, "remarks": [what the server remarked]}.
    `data` is the answer's bytes or text, or the answer decoded already. Degrees are kept to 1e-5; a line's `vertices`
    are (lon, lat) pairs.

    - An Overpass answer's `elements`, by their tags: telecom=internet_exchange an exchange point,
      telecom=cable_landing_station a landing station, telecom=data_center or building=data_center a data centre, each
      a point (a node's own place, a way's or a relation's centre); a way with its geometry a line: a cable where
      location=underwater, submarine=yes or seamark:type=cable_submarine, else a line on land. Name: `name`, else the
      operator's; sub: `operator`, else `owner`.
    - A SPARQL answer's `results.bindings`: `kind` ending Q1433061 an exchange point, Q671224 a data centre, Q1349167
      or Q10379228 a ground station or a teleport, at `coord` ("Point(lon lat)").
    - A GeoJSON FeatureCollection's LineString and MultiLineString features, as cables.
    - Maps of networks in GML (gml: a tar archive of them, gzipped or not, or one alone): of each network its newest
      map, from OLDEST on; its own points of presence with a place as points of pops, each link between two of them a
      line of backbones (_gml). What was read and left out of the maps is said as a remark.

    Left out, and counted by why: a place off the globe, a line under two points (or with a vertex off the globe), a
    repeat, a vertex nearer than STEP to the last kept (not counted: the line stays), what is over MAX_POINTS or
    MAX_VERTICES a layer, what is of no kind asked for; of a map, a point with no place, one outside its network and a
    link to a point not drawn. InfrastructureError, in words, for an answer that is not the data asked for, and for
    one whose remark says the query did not finish."""
    dataset = DataSet.of(dataset)
    doc = _decoded(dataset, data)
    return _features(dataset, doc, free=doc is not data)


def _packed(values: array) -> str:
    """An array's bytes, little-endian, as base64 text."""
    if sys.byteorder == "big":
        values = array(values.typecode, values)
        values.byteswap()
    return base64.b64encode(values.tobytes()).decode("ascii")


def _when(fetched) -> str:
    """When a download was made, as the file says it: seconds since 1970 as an ISO time in UTC; words as they are."""
    return fetched if isinstance(fetched, str) else world._iso(float(fetched))


def pack(dataset, features, fetched) -> dict:
    """The file's JSON for a data set's features (parse's), `fetched` being when they were downloaded (seconds since
    1970): {"v": 1, "set", "title", "source", "licence_name", "credit": {"text", "url"}, "fetched": ISO, "features",
    "dropped", "layers": {layer: {"points": {"n", "xy", "names", "subs"}, "lines": {"n", "offsets", "xy", "names"}}}}.
    `xy` is base64 of little-endian int32 pairs, longitude and latitude in 1e-5 degrees; `offsets` is base64 of n + 1
    little-endian uint32: where each line's vertices begin in its layer's `xy`, and where the last one's end."""
    dataset = DataSet.of(dataset)
    said = features.get("layers") if isinstance(features, Mapping) else None
    said = said if isinstance(said, Mapping) else {}
    layers, count = {}, 0
    for layer, *_ in LAYERS:
        got = said.get(layer)
        if not isinstance(got, Mapping):
            continue
        entry = {}
        points = list(got.get("points") or ())
        if points:
            xy = array(_I32)
            for point in points:
                xy.extend((round(point[0] * SCALE), round(point[1] * SCALE)))
            entry["points"] = {"n": len(points), "xy": _packed(xy),
                               "names": [_name(p[2]) if len(p) > 2 else "" for p in points],
                               "subs": [_name(p[3]) if len(p) > 3 else "" for p in points]}
        lines = list(got.get("lines") or ())
        if lines:
            xy, offsets = array(_I32), array(_U32, [0])
            for vertices, _ in lines:
                for lon, lat in vertices:
                    xy.extend((round(lon * SCALE), round(lat * SCALE)))
                offsets.append(len(xy) // 2)
            entry["lines"] = {"n": len(lines), "offsets": _packed(offsets), "xy": _packed(xy),
                              "names": [_name(name) for _, name in lines]}
        if entry:
            layers[layer] = entry
            count += len(points) + len(lines)
    dropped = features.get("dropped") if isinstance(features, Mapping) else 0
    total = sum(int(n) for n in dropped.values()) if isinstance(dropped, Mapping) else int(dropped or 0)
    return {"v": VERSION, "set": dataset.id, "title": dataset.title, "source": dataset.source,
            "licence_name": dataset.licence_name, "credit": dict(dataset.credit), "fetched": _when(fetched),
            "features": count, "dropped": total, "layers": layers}


# -- the download -----------------------------------------------------------------------------------------------------
def installing() -> bool:
    """Whether a data set is being downloaded now, in this process."""
    return _INSTALLING.locked()


def _under_way() -> str:
    with _STATE:
        return _NOW["id"]


def _changes() -> int:
    with _STATE:
        return _NOW["changes"]


def _changed() -> None:
    """A file was put in place or removed here: every Index looks again at its next ask."""
    with _STATE:
        _NOW["changes"] += 1


def _asked(cancel) -> bool:
    """Whether the job was cancelled, as its `cancel` says now; False without one, and for one that cannot say."""
    if not callable(cancel):
        return False
    try:
        return bool(cancel())
    except Exception:  # noqa: BLE001 - a cancel that fails stops nothing
        return False


def _agent(agent) -> str:
    """The download's User-Agent: the caller's (a plugin's name and version), else the library's own (none given: None
    or ""). ValueError for one that is more than a product's name and its version, checked as it is given and never
    mended (a newline, a tab, two spaces or a space at either end is a caller's mistake, said): no address, no contact,
    nothing of the user's."""
    if agent is None or agent == "":
        return USER_AGENT
    if not isinstance(agent, str) or len(agent) > AGENT or not AGENT_FORM.fullmatch(agent):
        raise ValueError("a download's User-Agent is a product's name and its version (firewall-linux/0.9.0): letters, "
                         f"digits and ./_()+-, words one space apart, {AGENT} characters at most, not "
                         f"{world._shown(agent)}")
    return agent


def _apart() -> str:
    return "a minute" if RETRY_S == 60 else f"{world._seconds(RETRY_S)} s"


def _refusal(dataset: DataSet, e: BaseException, wait: float) -> str:
    """Why a fetch or a read failed, in words. `wait`: what its socket was given to wait, the data set's own or, nearer
    the deadline, what was left of the install's time."""
    host, code = dataset.host, getattr(e, "code", None)
    if code in BUSY:
        return (f"{host} is busy (HTTP {code}): it was asked twice, {_apart()} apart. Nothing was installed, and what "
                "was installed before stays. Try again later.")
    if code == 403 and dataset.format == "sparql":  # the query service's rule for automated clients
        return (f"{host} refused the request (HTTP 403): it asks automated clients to name a contact, and none is sent "
                "from here.")
    if isinstance(e, TimeoutError) or isinstance(getattr(e, "reason", None), TimeoutError):
        if wait < dataset.wait:
            return (f"{host} did not answer within {world._seconds(wait)} s, what was left of the "
                    f"{world._seconds(INSTALL_S / 60)} minutes an install may take")
        return f"{host} did not answer within {world._seconds(wait)} s, the longest this data set waits for it"
    return f"{dataset.title} could not be downloaded from {host}: {world._words(e)}"


def _lingers(dataset: DataSet) -> str:
    """The words for a download whose thread still ran once it was stopped and given its grace: on Windows a read
    waiting on a shut socket ends only within its own timeout (the data set's wait at most)."""
    return (f"its connection to {dataset.host} is shut, and the read waiting on it ends by itself within "
            f"{world._seconds(dataset.wait)} s at most: nothing it brings is kept")


def _pause(until: float, deadline: float, clock, cutoff, halt: threading.Event) -> None:
    """The wait before a busy server is asked once more, on the download's thread: until `until` on the install's
    clock and no longer than its deadline, ended at once when the install is stopped (`halt`: cancelled, or its time
    up)."""
    end = min(until, deadline)
    while not cutoff.why:
        left = end - clock()
        if left <= 0 or halt.wait(min(world.POLL_S, left)):
            return


def _read(stream, dataset: DataSet, cutoff, deadline: float, took: str, clock, say, wait: float) -> bytearray:
    """The answer's bytes, read on the download's thread a piece at a time (one of the stream's own reads at most:
    read1, so a server sending a byte now and then holds no read for longer than its socket's timeout, `wait`), the
    stop and the deadline looked at between the pieces, MAX_ANSWER bytes at most; its end noted on the cut-off (what
    is left is this machine's own)."""
    host = dataset.host
    large = f"the answer is larger than {size_words(MAX_ANSWER)}, the most a data set may be"
    size = world._length(stream)
    if size is not None and size > MAX_ANSWER:
        raise InfrastructureError(large)
    say(f"downloading from {host}" + (f": {size_words(size)}" if size else ""))
    one = getattr(stream, "read1", None)
    read = one if callable(one) else stream.read
    data, said = bytearray(), clock()
    while True:
        if cutoff.why:
            raise InfrastructureError(cutoff.why)
        now = clock()
        if now >= deadline:
            cutoff.stop(took)
            raise InfrastructureError(took)
        try:
            got = read(CHUNK)
        except Exception as e:  # noqa: BLE001 - the connection's own: reset, timed out, cut short
            if cutoff.why:
                raise InfrastructureError(cutoff.why) from None
            raise InfrastructureError(_refusal(dataset, e, wait)) from None
        with cutoff.lock:
            if cutoff.why:  # stopped while it read: what came is not kept
                raise InfrastructureError(cutoff.why)
            if not got:
                cutoff.ended = True
        if not got:
            return data
        if not isinstance(got, (bytes, bytearray, memoryview)):
            raise InfrastructureError(f"{host}'s answer is not the data asked for (its stream gave "
                                      f"{type(got).__name__}, not bytes)")
        data += got
        if len(data) > MAX_ANSWER:
            raise InfrastructureError(large)
        if now - said >= world.PROGRESS_S:
            said = now
            say(f"{size_words(len(data))} of {size_words(size)} ({min(100, len(data) * 100 // size)}%)" if size
                else f"{size_words(len(data))} so far")


def _download(dataset: DataSet, fetch, agent: str, cutoff, halt: threading.Event, deadline: float, took: str, clock,
              say) -> bytearray:
    """On the download's thread: the answer's bytes. One GET of the data set's address, each socket operation waiting
    its `wait` at most (less once less is left of the install's time); a busy server is asked once more RETRY_S later,
    that wait and the second try inside the same deadline."""
    host, address = dataset.host, dataset.address()
    for again in (False, True):
        left = deadline - clock()
        if cutoff.why or halt.is_set() or left <= 0:  # stopped (while it waited to ask again), or out of time
            raise InfrastructureError(cutoff.why or took)
        say(f"asking {host} again" if again else f"asking {host} for {dataset.title}")
        wait = min(dataset.wait, left)
        try:
            stream = fetch(address, wait, agent=agent, what="a data set")
        except Exception as e:  # noqa: BLE001 - urllib's HTTPError and URLError, a refused redirect, a stand-in's own
            world._close(e)  # an HTTP error carries its answer: let go unread
            if cutoff.why:
                raise InfrastructureError(cutoff.why) from None
            code = getattr(e, "code", None)
            if code in BUSY and not again:
                until = clock() + RETRY_S
                say(f"{host} is busy (HTTP {code}): it is asked once more in {world._seconds(RETRY_S)} s")
                _pause(until, deadline, clock, cutoff, halt)
                continue
            raise InfrastructureError(_refusal(dataset, e, wait)) from None
        try:
            if cutoff.why:  # it came after the stop: let go unread
                raise InfrastructureError(cutoff.why)
            return _read(stream, dataset, cutoff, deadline, took, clock, say, wait)
        finally:
            world._close(stream)
    raise InfrastructureError(cutoff.why or took)  # not reached: the second try answers or raises


def _unlink(path: Path) -> bool:
    try:
        path.unlink()
    except OSError:
        return False
    return True


def _sweep(target: Path, ident: str) -> None:
    """The temporary files of this data set's installs that died removed: those not written to for STALE_S."""
    now = time.time()
    try:
        parts = [p for p in target.glob(f".{ident}.*.part") if p.is_file()]
    except OSError:
        return
    for path in parts:
        try:
            stale = now - path.stat().st_mtime > STALE_S
        except OSError:
            continue
        if stale:
            _unlink(path)


def _put(target: Path, dataset: DataSet, packed: dict) -> Path:
    """The file written whole beside itself and put in place in one step (a reader never sees half a file); its path.
    InfrastructureError when it cannot be kept: the older file stays, the temporary one is removed. That is so for a
    file larger than MAX_ANSWER, the most Index reads (_kept): a file is ASCII, a name outside it written as a \\u
    escape of six bytes where the answer's UTF-8 took three, and a MultiLineString's name is kept for each part, so a
    file can be larger than the answer it was made from."""
    path = target / f"{dataset.id}.json"
    temp = target / f".{dataset.id}.{secrets.token_hex(6)}.part"
    placed = False
    try:
        text = json.dumps(packed, separators=(",", ":"), allow_nan=False)
        if len(text) > MAX_ANSWER:  # ASCII: its characters are its bytes
            raise InfrastructureError(
                f"{dataset.title} was not kept: its file would be {size_words(len(text))}, larger than "
                f"{size_words(MAX_ANSWER)}, more than a data set's file holds. Nothing was installed, and what was "
                "installed before stays.")
        target.mkdir(parents=True, exist_ok=True)
        _sweep(target, dataset.id)
        with open(temp, "w", encoding="ascii", newline="\n") as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        with _FILES:
            os.replace(temp, path)
        placed = True
    except (OSError, ValueError) as e:
        raise InfrastructureError(f"{dataset.title} could not be kept in {target}: {e}") from None
    finally:
        if not placed:
            _unlink(temp)
    return path


def _whys(dropped: Mapping) -> str:
    """Why a parse left features out, in words: "2 repeated, 1 off the globe"; "" when it left none out."""
    return ", ".join(f"{n:,} {why}" for why, n in dropped.items() if n)


def _left_out(dropped: Mapping) -> str:
    """What a parse left out, in words: "3 features left out: 2 repeated, 1 off the globe"; "" when nothing was."""
    total = sum(dropped.values())
    if not total:
        return ""
    return f"{world._plural(total, 'feature')} left out: {_whys(dropped)}"


def install(dataset, folder=None, *, accept_licence=False, fetch=None, log=None, cancel=None, agent="",
            clock=time.monotonic, wall=time.time) -> dict:
    """A data set downloaded and put in place, on the user's word (the plugin's world_layer_get, run as a job): what
    was installed, in words, for the page.

    Refused first, in words, before anything is asked of anyone or said to `log`: a folder on another system's drive
    (ValueError: foreign); the licence not accepted (world.LicenceRefused naming accept_licence, which the page asks as
    a second, explicit confirmation: `accept_licence` must be exactly True); a download under way (ValueError).

    Then one GET of dataset.address() through `fetch` (world.fetch_url: https on every hop, from the same host only),
    with `agent` as its User-Agent (the plugin's name and version; nothing of the user's or the machine's). It runs on a
    thread of its own while this one waits, under one deadline for all of it (INSTALL_S on `clock`): every
    world.POLL_S the time and `cancel()` (the job's: Callable[[], bool]) are looked at, and the download's sockets
    are shut when either says so. A cancel answers {"said": "cancelled: nothing was installed", "ok": False}, with a
    line saying when the connection ends where its read outlived the shut (on Windows, within its timeout). HTTP 429,
    502, 503 or 504 is asked once more RETRY_S later, that wait ended at once by a cancel and counted inside the
    deadline. The answer is read in pieces, MAX_ANSWER bytes at most, then read here (parse), packed (pack) and put in
    place in one step; `wall` says when (seconds since 1970).

    InfrastructureError, in words, when nothing was installed: the older file stays as it was. `log`: each step said to
    it (the platform's job panel)."""
    dataset = DataSet.of(dataset)
    target = _resolved(folder)
    elsewhere = foreign(target)
    if elsewhere:
        raise ValueError(elsewhere)
    if accept_licence is not True:
        raise LicenceRefused(LICENCE_FIRST)
    agent = _agent(agent)
    if not _INSTALLING.acquire(blocking=False):
        raise ValueError(ALREADY)
    try:
        with _STATE:
            _NOW["id"] = dataset.id
        return _install(dataset, target, fetch or world.fetch_url, world._sayer(log), cancel, agent, clock, wall)
    finally:
        with _STATE:
            _NOW["id"] = ""
        _INSTALLING.release()


def _install(dataset: DataSet, target: Path, fetch, say, cancel, agent: str, clock, wall) -> dict:
    host = dataset.host
    budget = float(INSTALL_S)
    deadline = clock() + budget
    took = (f"the download took more than {world._seconds(budget)} s, the most an install may take, so it was stopped: "
            "nothing was installed")
    cutoff, halt = world._Cutoff(), threading.Event()
    if _asked(cancel):  # cancelled before anything was asked of anyone
        return {"said": CANCELLED, "ok": False}

    def stopping() -> str:
        if not _asked(cancel):
            return ""
        halt.set()  # a wait before a second try ends now
        return CANCELLED
    try:
        data = world.run_download(
            lambda: _download(dataset, fetch, agent, cutoff, halt, deadline, took, clock, say), cutoff, deadline, took,
            name=f"{dataset.id}-layer-download", stopping=stopping, clock=clock, what=dataset.title,
            error=InfrastructureError,
            late=f"{dataset.title} was downloaded, and its thread did not end in time: nothing was installed")
    except InfrastructureError:
        lingers = _lingers(dataset) if cutoff.left else ""  # (on Windows) its read ends only within its timeout
        if lingers:
            say(lingers)
        if cutoff.why == CANCELLED:
            return {"said": CANCELLED, "ok": False, **({"lines": [lingers]} if lingers else {})}
        raise
    finally:
        halt.set()
    size = len(data)
    say(f"{size_words(size)} downloaded: reading it")
    doc = _decoded(dataset, data)
    del data  # the answer's bytes are not held beside what is read of them
    features = _features(dataset, doc, free=True)
    del doc
    for remark in features["remarks"]:
        say(remark)
    if not features["features"]:
        whys = _whys(features["dropped"])
        raise InfrastructureError(f"{host} answered, but every feature was left out: {whys}" if whys
                                  else f"{host} answered with no features")
    packed = pack(dataset, features, wall())
    left = _left_out(features["dropped"])
    del features
    if _asked(cancel):
        return {"said": CANCELLED, "ok": False}
    path = _put(target, dataset, packed)
    _changed()
    try:
        kept = path.stat().st_size
    except OSError:
        kept = 0
    lines = [f"asked of {host}", f"kept in {target}, in place of any older copy",
             f"credited on the globe as {dataset.credit['text']}"]
    if left:
        lines.append(left)
    counts = {layer: sum(part["n"] for part in entry.values()) for layer, entry in packed["layers"].items()}
    return {"said": f"installed {dataset.title}: {world._plural(packed['features'], 'feature')} ({size_words(kept)})",
            "ok": True, "lines": lines,
            "file": {"set": dataset.id, "path": str(path), "bytes": kept, "downloaded": size,
                     "features": packed["features"], "dropped": packed["dropped"], "fetched": packed["fetched"],
                     "layers": counts}}


def remove(dataset, folder=None) -> dict:
    """A data set's file removed (the plugin's world_layer_remove, confirmed on the page): the globe no longer draws
    it, and it can be downloaded again. ValueError for a folder on another system's drive, and while that data set is
    being downloaded; InfrastructureError when the file cannot be removed."""
    dataset = DataSet.of(dataset)
    target = _resolved(folder)
    elsewhere = foreign(target)
    if elsewhere:
        raise ValueError(elsewhere)
    if _under_way() == dataset.id:
        raise ValueError(f"{dataset.title} is being downloaded: wait for it to finish, or cancel it")
    try:
        with _FILES:
            (target / f"{dataset.id}.json").unlink()
    except FileNotFoundError:
        return {"said": f"{dataset.title} is not installed here", "ok": True,
                "lines": [f"nothing of it is kept in {target}"]}
    except OSError as e:
        raise InfrastructureError(f"{dataset.title} could not be removed from {target}: {e}") from None
    _changed()
    return {"said": f"removed {dataset.title}", "ok": True,
            "lines": [f"its file is removed from {target}: the globe no longer draws it", "it can be downloaded again"]}


# -- the forms --------------------------------------------------------------------------------------------------------
def form(dataset, folder, update: bool = False) -> dict:
    """A data set's download form as the page draws it (liminal-platform's forms shape), asked as a job (its progress
    followed in the plugin's panel). Nothing to fill in: its first confirmation says what is asked, of whom, how large
    it is and where it is kept, and shows the licence; the hook then refuses until the licence is accepted
    (LicenceRefused, before the job's first line), and the page asks that as a second confirmation."""
    dataset = DataSet.of(dataset)
    verb = "Update" if update else "Download"
    return {
        "id": FORM + dataset.id, "hook": GET_HOOK, "title": f"{verb} {dataset.title}", "job": True,
        "note": ("Drawn on the globe from a file on this machine: once it is downloaded, the globe asks nothing of "
                 "anyone."),
        "fields": [{"name": "dataset", "type": "fixed", "value": dataset.id},
                   {"name": ACCEPT, "type": "accept", "title": f"Accept its licence ({dataset.licence_name})?",
                    "words": dataset.licence, "yes": "Accept it and download"}],
        "confirm": {"title": f"{verb} {dataset.title}?", "yes": "Go on",
                    "words": (f"{dataset.title} is asked of {dataset.host} in one request, made now on your word (once "
                              f"more {_apart()} later if the server is busy), and kept in {_resolved(folder)} in place "
                              f"of any older copy: {size_words(dataset.size)} (an estimate where its maker gives "
                              "none). Its progress shows in the panel below; it stops by itself after "
                              f"{world._seconds(INSTALL_S / 60)} minutes. The request holds only "
                              f"{ASKED[dataset.format]}: nothing about this machine or its traffic. Its licence, "
                              f"first: {dataset.licence} You are asked to accept it next.")}}


def remove_form(dataset, folder) -> dict:
    """A data set's removal form: one confirmation, saying what is removed and from where."""
    dataset = DataSet.of(dataset)
    return {"id": REMOVE_FORM + dataset.id, "hook": REMOVE_HOOK, "title": f"Remove {dataset.title}",
            "fields": [{"name": "dataset", "type": "fixed", "value": dataset.id}],
            "confirm": {"title": f"Remove {dataset.title}?", "yes": "Remove it",
                        "words": (f"Its file is removed from {_resolved(folder)} and the globe no longer draws it. It "
                                  "can be downloaded again.")}}


# -- what is installed ------------------------------------------------------------------------------------------------
def _kept(path: Path, ident: str) -> dict:
    """A kept file read whole and checked, as pack made it: its JSON. ValueError saying why it is none of this data
    set's files; OSError when it cannot be read."""
    with _FILES:
        if path.stat().st_size > MAX_ANSWER:
            raise ValueError(f"it is larger than {size_words(MAX_ANSWER)}, more than a data set's file holds")
        raw = path.read_bytes()
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError):
        raise ValueError("it is no JSON") from None
    del raw
    if not isinstance(doc, Mapping) or doc.get("v") != VERSION or doc.get("set") != ident:
        raise ValueError(f"it is no file of this data set's (version {VERSION})")
    layers = doc.get("layers")
    if not isinstance(layers, Mapping):
        raise ValueError("it holds no layers")
    known = {layer for layer, *_ in LAYERS}
    for layer, entry in layers.items():
        if layer not in known or not isinstance(entry, Mapping):
            raise ValueError(f"it holds a layer that is none ({str(layer)[:40]!r})")
        for part, lists in (("points", ("names", "subs")), ("lines", ("names",))):
            got = entry.get(part)
            if got is None:
                continue
            n = got.get("n") if isinstance(got, Mapping) else None
            if (isinstance(n, bool) or not isinstance(n, int) or n < 0 or not isinstance(got.get("xy"), str)
                    or any(not isinstance(got.get(k), list) or len(got[k]) != n for k in lists)
                    or (part == "lines" and not isinstance(got.get("offsets"), str))):
                raise ValueError(f"its {layer} {part} do not read")
    return doc


def _facts(path: Path, ident: str) -> dict:
    """A kept file's few facts, its geometry let go again: its title, source, licence and credit, when it was fetched,
    its features and how many were left out, and each layer's counts (points, lines, the lines' vertices)."""
    doc = _kept(path, ident)
    counts = {}
    for layer, entry in doc["layers"].items():
        points, lines = entry.get("points") or {}, entry.get("lines") or {}
        counts[layer] = {"points": points.get("n", 0), "lines": lines.get("n", 0),
                         "vertices": len(lines.get("xy", "")) * 3 // 4 // 8}
    credit = doc.get("credit") if isinstance(doc.get("credit"), Mapping) else {}

    def number(key: str) -> int:
        value = doc.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0
    return {"title": _text(doc.get("title")), "source": _text(doc.get("source")),
            "licence_name": _text(doc.get("licence_name")),
            "credit": {"text": _text(credit.get("text")), "url": _text(credit.get("url"))},
            "fetched": _text(doc.get("fetched")), "features": number("features"), "dropped": number("dropped"),
            "counts": counts, "problem": ""}


def _version(drawn: list) -> str:
    """A layer's version: 12 hex digits of the names, sizes and times of the files that feed it."""
    said = "|".join(f"{fact['file']}:{fact['stamp'][0]}:{fact['stamp'][1]}" for _, fact, _ in drawn)
    return hashlib.sha1(said.encode("utf-8", "replace")).hexdigest()[:12]


class Index:
    """What is installed of a plugin's data sets, in `folder` (the data folder's infrastructure/ when not given): the
    files <id>.json of `datasets` (DataSets, or the plugin's dicts) and no other. The folder is looked at again INDEX_S
    after the last look at the soonest (`clock`: monotonic, a test's own), and at once after an install or a removal in
    this process. A look is one stat a data set: a file is read (whole, once) only when its size or its time changed,
    and only its counts, its credit and its date are kept. A folder on another system's drive is never read: nothing
    counts as installed there. Thread-safe: the platform asks from a thread per request."""

    def __init__(self, folder=None, datasets=(), clock=time.monotonic):
        self._given = None if folder is None else Path(folder)
        self.datasets = tuple(DataSet.of(d) for d in datasets)
        ids = [d.id for d in self.datasets]
        twice = sorted({i for i in ids if ids.count(i) > 1})
        if twice:
            raise ValueError(f"two data sets share the id {twice[0]}: each has its own")
        self.clock = clock
        self._lock = threading.Lock()
        self._looked: float | None = None  # when the folder was last looked at (clock)
        self._seen = -1  # the installs and removals of this process at that look
        self._files: dict[str, dict] = {}  # each installed data set's facts, by its id

    @property
    def folder(self) -> Path:
        """Where the files are: the folder given, else the data folder's infrastructure/."""
        return _resolved(self._given)

    def elsewhere(self) -> str:
        """Why this folder's files are another system's, in words ("" when they are this one's): foreign()."""
        return foreign(self.folder)

    def dataset(self, dataset_id) -> DataSet:
        """The plugin's data set of that id; ValueError naming the ones there are."""
        found = next((d for d in self.datasets if d.id == dataset_id), None)
        if found is None:
            raise ValueError(f"{world._shown(dataset_id)} is not one of this plugin's data sets: "
                             f"{', '.join(d.id for d in self.datasets) or 'it names none'}")
        return found

    def _look(self) -> dict[str, dict]:
        with self._lock:
            now, seen = self.clock(), _changes()
            if self._looked is not None and seen == self._seen and 0 <= now - self._looked < INDEX_S:
                return self._files
            self._looked, self._seen = now, seen
            files: dict[str, dict] = {}
            base = self.folder
            for dataset in self.datasets if not foreign(base) else ():
                path = base / f"{dataset.id}.json"
                try:
                    found = path.stat()
                except OSError:
                    continue
                stamp = (found.st_size, found.st_mtime_ns)
                old = self._files.get(dataset.id)
                if old is not None and old["stamp"] == stamp:
                    files[dataset.id] = old
                    continue
                try:
                    fact = _facts(path, dataset.id)
                except (OSError, ValueError) as e:
                    fact = {"title": dataset.title, "source": dataset.source, "licence_name": dataset.licence_name,
                            "credit": dict(dataset.credit), "fetched": "", "features": 0, "dropped": 0, "counts": {},
                            "problem": f"its file does not read ({e}): download it again"}
                fact.update(stamp=stamp, file=path.name, bytes=found.st_size)
                files[dataset.id] = fact
            self._files = files
            return files

    def _feeding(self, layer: str, files: dict) -> tuple[list, list]:
        """The data sets whose files feed a layer, in the plugin's order, as (the data set, its facts, its counts in
        that layer): those drawn, within what a layer holds in all (MAX_POINTS points, MAX_VERTICES vertices), and those
        left out because the layer is full."""
        drawn, left, points, vertices = [], [], 0, 0
        for dataset in self.datasets:
            fact = files.get(dataset.id)
            count = fact["counts"].get(layer) if fact is not None and not fact["problem"] else None
            if not count or not (count["points"] or count["lines"]):
                continue
            if points + count["points"] > MAX_POINTS or vertices + count["vertices"] > MAX_VERTICES:
                left.append((dataset, fact, count))
                continue
            points, vertices = points + count["points"], vertices + count["vertices"]
            drawn.append((dataset, fact, count))
        return drawn, left

    def sets(self) -> list[dict]:
        """Each data set of the plugin, in its order, installed or not: {"id", "title", "about", "source",
        "licence_name", "format", "host", "size" (its download's, an estimate), "installed", "fetched", "features",
        "dropped", "bytes" (its file's), "layers" (the ones it feeds), "credit", "problem" (a file that does not read),
        "downloading"}."""
        files, now = self._look(), _under_way()
        out = []
        for d in self.datasets:
            fact = files.get(d.id)
            ok = fact is not None and not fact["problem"]
            out.append({"id": d.id, "title": d.title, "about": d.about, "source": d.source,
                        "licence_name": d.licence_name, "format": d.format, "host": d.host, "size": d.size,
                        "installed": ok, "fetched": fact["fetched"] if ok else None,
                        "features": fact["features"] if ok else 0, "dropped": fact["dropped"] if ok else 0,
                        "bytes": fact["bytes"] if fact is not None else 0,
                        "layers": [layer for layer, *_ in LAYERS if ok and layer in fact["counts"]],
                        "credit": dict(d.credit), "problem": fact["problem"] if fact is not None else "",
                        "downloading": now == d.id})
        return out

    def layers(self) -> list[dict]:
        """The layers the globe may draw, in LAYERS' order: each one with features installed, as {"id", "title",
        "kind", "mark", "slot", "on", "names_from", "count", "version", "credits": [{"text", "url"}], "note"}. Small
        enough to travel with every answer of the tab: the geometry is asked for by layer, once a version (layer())."""
        files = self._look()
        out = []
        for layer, title, kind, mark, slot, on, names_from in LAYERS:
            drawn, left = self._feeding(layer, files)
            if not drawn:
                continue
            credits: list[dict] = []
            for _, fact, _ in drawn:
                if fact["credit"]["text"] and fact["credit"] not in credits:
                    credits.append(dict(fact["credit"]))
            note = "; ".join(f"from {fact['source']}, fetched {fact['fetched'][:10]}" for _, fact, _ in drawn)
            if left:
                note += "; left out, the layer being full: " + ", ".join(d.title for d, _, _ in left)
            out.append({"id": layer, "title": title, "kind": kind, "mark": mark, "slot": slot, "on": on,
                        "names_from": names_from, "count": sum(c["points"] + c["lines"] for _, _, c in drawn),
                        "version": _version(drawn), "credits": credits, "note": note})
        return out

    def layer(self, layer_id) -> dict:
        """One layer's geometry as the files hold it, read now and not kept: {"id", "version", "parts": [{"set",
        "credit", "points"?: {"n", "xy", "names", "subs"}, "lines"?: {"n", "offsets", "xy", "names"}}]}, a part a data
        set (pack says what `xy` and `offsets` are). LookupError when no such layer is installed here."""
        drawn = self._feeding(layer_id, self._look())[0] if isinstance(layer_id, str) else []
        parts = []
        for dataset, fact, _ in drawn:
            try:
                entry = _kept(self.folder / fact["file"], dataset.id)["layers"].get(layer_id)
            except (OSError, ValueError):
                continue  # gone or changed since the look: the next look says so
            if entry:
                parts.append({"set": dataset.id, "credit": dict(fact["credit"]),
                              **{part: entry[part] for part in ("points", "lines") if part in entry}})
        if not parts:
            raise LookupError(f"no layer {world._shown(layer_id)} is installed here")
        return {"id": layer_id, "version": _version(drawn), "parts": parts}

    def forms(self, can: bool = True) -> list[dict]:
        """The forms the table's buttons open: each data set's download (an update once it is installed) and, once
        installed, its removal. None when the page may not ask them (`can`), for a folder on another system's drive,
        and while a download is under way."""
        if not can or installing() or self.elsewhere():
            return []
        base, out = self.folder, []
        for s in self.sets():
            dataset = self.dataset(s["id"])
            out.append(form(dataset, base, update=s["installed"]))
            if s["installed"] or s["problem"]:
                out.append(remove_form(dataset, base))
        return out

    def table(self, can: bool = True) -> dict:
        """The page's table of the data sets, "Internet infrastructure": Data set | From | Licence | Here, and two
        columns of buttons: Download… (Update… once installed) and Remove…, each opening its form (forms()). `can`:
        whether the page may ask them; without it, on another system's drive and while a download is under way, no
        button is drawn."""
        elsewhere = self.elsewhere()
        offer = bool(can) and not elsewhere and not installing()
        rows = []
        for s in self.sets():
            if s["downloading"]:
                here = "being downloaded"
            elif elsewhere:
                here = "not from here"
            elif s["problem"]:
                here = {"text": "not read", "sub": s["problem"]}
            elif s["installed"]:
                sub = size_words(s["bytes"]) + (f"; {s['dropped']:,} left out" if s["dropped"] else "")
                here = {"text": f"{world._plural(s['features'], 'feature')}, fetched {s['fetched'][:10]}", "sub": sub}
            else:
                here = "not downloaded"
            there = s["installed"] or bool(s["problem"])
            get = {"form": FORM + s["id"], "title": "Update…" if s["installed"] else "Download…"}
            rows.append([{"text": s["title"], "sub": s["about"]} if s["about"] else s["title"], s["source"],
                         s["licence_name"], here, get if offer else "",
                         {"form": REMOVE_FORM + s["id"], "title": "Remove…"} if offer and there else ""])
        note = ("What the globe draws where the exchanges globe draws exchanges: exchange points, data centres, cable "
                "landing stations, ground stations, submarine cables, backbones and their points of presence, and "
                "telecom lines on land, as far as free-licensed data gives them. A data set is downloaded only on your "
                f"word, its size and its licence said first, and kept in {self.folder}: the globe is then drawn from "
                "that file, and asks nothing of anyone.")
        if elsewhere:
            note += f" {elsewhere}. Each system's platform downloads its own."
        elif installing():
            note += " A data set is being downloaded: its progress shows in the panel."
        return {"title": TITLE, "note": note,
                "columns": [{"title": "Data set"}, {"title": "From"}, {"title": "Licence"}, {"title": "Here"},
                            {"title": ""}, {"title": ""}],
                "rows": rows, "empty": "This plugin names no data set to download."}
