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
- 1.104.0 (Monday list item 27; the user, 2026-11-23: "Kept here, from my downloads"): what is downloaded is kept in
  the plugin's own database, infrastructure.db in the data folder's infrastructure/ (machines/infrastore.py), each
  system's own (a folder on another system's drive is that system's: geo.foreign), each data set written in one
  transaction. The download itself is not kept. Coordinates are packed as before (base64 of little-endian int32 pairs,
  longitude and latitude in 1e-5 degrees) when a layer is read. An older <id>.json of a download made before is read
  into the database once, at the first look, and then left where it is and no longer read.
- Index says what is installed (the data sets, the layers they feed, the table the page draws) and reads no geometry
  to look: the database's sets and counts, read again only when it changed. layer() reads a layer's geometry when the
  globe asks for it, whole or by area, and keeps none.
- Nothing runs when unused: no thread, no timer, no file left open.
- 1.108.0 (Monday list item 25, street maps on the globe; the user, 2026-11-26: "From 64x" and "Your area only"):
  the world's countries and states named from the start and the states' boundaries drawn (Natural Earth, public
  domain: a shapefile's records read alone for the names at the label points they hold, `label`), its counties named
  from 16x and its cities and towns from 32x (GeoNames' cities500 and its second-order divisions, two files of one data
  set, `also`: a county named at the middle of its towns), and the major roads and buildings from 64x, of a region
  round the home place alone and of each region added on the page (OpenStreetMap through the Overpass API, `region`:
  the region's box asked a piece at a time, each piece's XML read as it streams in and let go). Each feature keeps the
  zoom it is drawn from (its name's rank, its town's people, its road's class, its building's size): a layer of them
  (RANKED) is read by area and zoom alone, BY_AREA ones are never capped in all (only what one read answers is), and
  their lines are kept packed (Packed) while a download is read."""
from __future__ import annotations

import base64
import csv
import hashlib
import html
import io
import json
import math
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
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

from .. import jsonread
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
# 1.104.0 (the user, 2026-11-26): a data set may raise its own limit (its `most`: RIPE Atlas's traceroutes of every
# probe, some 50 MB; Natural Earth's North America roads, 45.6 MB), every other set keeping MAX_ANSWER; this at most.
# What it unpacks to and the records it holds may then grow as much, in proportion (_scale)
MOST_LARGEST = 128 << 20
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
COARSE_ZOOM = 6.0  # 1.104.0: the globe's zoom from which a layer is read by area, at every vertex; below it, coarse
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
    ("lines", "Telecom lines on land (partial)", "lines", "dash", 7, False, 6.0),
    # 1.73.0: what routers' names are read with (machines/names.py), drawn too: the airports by their codes, the
    # cities of the world by their names (the most people first, MAX_POINTS of them)
    ("airports", "Airports, by their codes", "points", "diamond", 5, False, 7.0),
    ("cities", "Cities", "points", "circle", 4, False, 4.0),
    # 1.104.0 (Monday list item 24): fibre on land as its operators' maps give it (AfTerFibre's Africa), and where none
    # is mapped the roads and railways long-haul fibre most often runs beside, drawn dashed as the stand-ins they are
    ("fibre", "Fibre on land", "lines", "line", 7, True, 4.0),
    ("roads", "Major roads (a stand-in for fibre)", "lines", "dash", 5, False, 7.0),
    ("railways", "Railways (a stand-in for fibre)", "lines", "dash", 4, False, 7.0),
    # 1.104.0 (items 28 and 29): TopoHub's model of the world's backbones and its cities, a layer of their own (the
    # user, 2026-11-26: not the points of presence of about 2010-2011; its data states no licence, as its title says),
    # and the places RIPE Atlas measures from
    ("models", "Backbone model (TopoHub)", "lines", "line", 6, False, 5.0),
    ("modelcities", "Backbone model's cities (TopoHub; no licence stated for its data)", "points", "circle", 6, False,
     5.0),
    ("probes", "RIPE Atlas probes and anchors", "points", "circle", 5, False, 6.0),
    # 1.108.0 (Monday list item 25: the user, 2026-11-26, "From 64x"): the map's names and boundaries, drawn from the
    # zoom LAYER_FROM says, each name from its own (RANKED): a "label" is a name alone, no mark under it
    ("countrynames", "Countries' names", "points", "label", 4, True, 1.0),
    ("states", "States' and provinces' boundaries", "lines", "dash", 5, True, 0.0),
    ("statenames", "States' and provinces' names", "points", "label", 5, True, 1.0),
    ("counties", "Counties' names", "points", "label", 6, True, 16.0),
    ("countylines", "Counties' boundaries (your regions)", "lines", "dash", 6, True, 0.0),
    ("towns", "Cities and towns", "points", "circle", 4, True, 32.0),
    ("streets", "Major roads (your regions)", "lines", "line", 5, True, 128.0),
    ("buildings", "Buildings (your regions)", "lines", "line", 7, True, 0.0))
LINE_LAYERS = tuple(layer for layer, _, kind, *_ in LAYERS if kind == "lines")
# 1.108.0: the zoom a layer is drawn from (none said: from the start), the layers whose features each say the zoom
# they are drawn from, and those never read whole nor capped in all (what one read answers is: MAX_POINTS points and
# MAX_VERTICES vertices), a download of one keeping MAX_AREA_POINTS points and MAX_AREA_VERTICES vertices at most
LAYER_FROM = {"counties": 16.0, "countylines": 16.0, "towns": 32.0, "streets": 64.0, "buildings": 64.0}
RANKED = ("countrynames", "statenames", "counties", "countylines", "towns", "streets", "buildings")
BY_AREA = ("states", "counties", "countylines", "towns", "streets", "buildings")
MAX_AREA_POINTS = 400_000  # GeoNames' cities500: some 185,000 places
MAX_AREA_VERTICES = 8_000_000  # 64 MB packed: a region's buildings, the states' boundaries
# the globe's 1x as a web map's zoom (a globe 520 px high), and how many of a web map's zooms before its maker says a
# name of a rank is placed (none is ever drawn over another): a name of rank r is placed from 2^(r - both)
WEB_ZOOM, LABEL_EARLY = 2.67, 1.0
# a town's zoom by its people (the most first: GeoNames' population), a road's by its class (OpenStreetMap's highway,
# its _link the same), a building's from where it spans BUILDING_PX pixels (a 24 m pixel at 1024x), never before 64x
TOWN_ZOOMS = ((100_000, 32.0), (10_000, 64.0), (1_000, 128.0), (0, 256.0))
ROAD_ZOOMS = {"motorway": 64.0, "trunk": 64.0, "primary": 64.0, "secondary": 64.0, "tertiary": 128.0}
BUILDING_PX, PIXEL_M = 1.5, 24.0 * 1024
COUNTY_ZOOM = 16.0
# OpenStreetMap's admin_level of a county (the United States' counties, Germany's Kreise, France's départements)
COUNTY_LEVEL = "6"
REGION_KM = (2.0, 100.0)  # a region's width, from and to (the user's choice: one round home, others added)
REGION_PIECE = (0.01, 0.25)  # degrees: a region's box is asked in pieces of this side at most
REGION_PIECES = 100  # pieces a region is asked in, at most
REGION_ID = re.compile(r"(.+)-([ns])(\d{4,5})([ew])(\d{5})")  # a region's id: its template's, then its place
XML_FEED = 64 << 10  # bytes of an XML answer handed to its parser at a time
# the points read of one way (OpenStreetMap's own API refuses a way of more than 2,000 nodes) and of one piece of a
# region in all (the review of 1.108.0: a piece's points are what it holds while it is read)
WAY_POINTS, PIECE_POINTS = 2_000, 2_000_000
POINT_LAYERS = tuple(layer for layer, _, kind, *_ in LAYERS if kind == "points")

FORMATS = ("overpass", "sparql", "geojson", "gml", "ourairports", "geonames", "shapefile", "mvt", "topohub",
           "atlas-probes", "atlas-latest", "omm-csv",
           "geonames-places", "osm-xml")  # what an answer is read as (1.108.0: the last two)
AS_WRITTEN = ("geojson", "gml", "ourairports", "geonames", "shapefile", "mvt", "topohub", "atlas-probes",
              "atlas-latest", "omm-csv", "geonames-places")  # whose query, where they have one, is sent as written
AS_BYTES = ("gml", "ourairports", "geonames", "shapefile", "atlas-probes", "omm-csv", "geonames-places",
            "osm-xml")  # read from the answer's bytes,
# not as JSON
QUERIES = 8  # queries an omm-csv set may ask, one request each (HughesNet's three satellites by their numbers)
EVERY_MOST = 7 * 86400.0  # the longest a data set may ask its Update to wait
# 1.104.0 (the user, 2026-11-26, CelesTrak's "Refresh by itself"): a set whose `refresh` is true is downloaded again by
# itself once its `every` has passed, asked by the World Wide Web tab's page while it is open (refresh_due), never
# less than REFRESH_LEAST apart; `pause`: the seconds nothing is asked of its host after it answered 500 or 503
REFRESH_LEAST = 3600.0
PAUSE_MOST = 86400.0
PAUSE_CODES = (500, 503)
MANY = ("mvt", "atlas-latest", "geonames-places", "osm-xml")  # the formats asked in several requests, one after
# another, on the one click
ATLAS_BATCH = 300  # probes' ids asked in one request of RIPE Atlas's latest results
ATLAS_RESULTS = 20_000  # results read of its answers, at most (1.104.0: every connected probe's, some 12,000)
ATLAS_ASKS = ("anchors", "probes")  # whose results an atlas-latest set asks: the connected anchors', or every
# connected probe's, anchors among them (the user, 2026-11-26: "ALL probes, not only connected anchors")
ATLAS_FAMILIES = (4, 6)  # its measurement's IP version: a probe asked has a network of that version (5151, 6152)
ATLAS_HOPS = 64  # hops read of a result, at most
NEAR_MS = 1.0  # a router this near a probe (its least RTT) is claimed at the probe's place
KM_PER_MS = 100.0  # how far light goes in fibre in a millisecond, there and back halved below
STEPS = (0.00001, 1.0)  # the degrees a data set's `step` may be, from and to (1.104.0; 1.108.0: a metre, buildings)
HOST_FORM = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
CHOICES = 32  # fields a data set's keep or drop names, and values a field, at most
TILES_MOST = 128  # map tiles a data set of them asks for, at most, one after another (AfTerFibre's Africa, zoom 5: 56)
TILE_MOST = 2 << 20  # bytes of one tile, at most
TILE_ZOOMS = (0, 14)  # the zooms a data set's tiles may be asked at
# a tile's fields kept (AfTerFibre's): who runs the fibre, whose it is, whether it is lit, its country. Its
# contributors' names and addresses (contributor, contrib_email) are people's: never decoded, never kept
TILE_FIELDS = ("operator_name", "operator", "owner_name", "owner", "live", "country")
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
LONG = "over the points a way may have"  # 1.108.0: a way of more than WAY_POINTS
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
         "gml": "the file asked for", "ourairports": "the airports' file", "geonames": "the cities' file",
         "shapefile": "the file asked for", "mvt": "the map tiles asked for", "topohub": "the file asked for",
         "atlas-probes": "the file asked for",
         "atlas-latest": "the measurement's newest results for the probes' ids (nothing about this machine)",
         "omm-csv": "the satellites' group or numbers asked for",
         "geonames-places": "the cities' file and the divisions' names",
         "osm-xml": "the region's box and the kinds of way asked for (its place, never this machine's address)"}
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


def _region_pieces(km: float, side: float, lat: float, lon: float) -> list[tuple[float, float, float, float]]:
    """1.108.0: the pieces a region `km` across round (lat, lon) is asked in, (south, west, north, east) each in
    degrees, `side` degrees at most, south to north and west to east; its box stops short of the poles and of the
    antimeridian (a region there is cut at it)."""
    half_lat = km / 2 / 110.574
    half_lon = km / 2 / (111.320 * max(0.05, math.cos(math.radians(lat))))
    s, n = max(-89.9, lat - half_lat), min(89.9, lat + half_lat)
    w, e = max(-179.99, lon - half_lon), min(179.99, lon + half_lon)
    rows, cols = max(1, math.ceil((n - s) / side - 1e-9)), max(1, math.ceil((e - w) / side - 1e-9))
    dy, dx = (n - s) / rows, (e - w) / cols
    return [(round(s + i * dy, 5), round(w + j * dx, 5), round(s + (i + 1) * dy, 5), round(w + (j + 1) * dx, 5))
            for i in range(rows) for j in range(cols)]


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
    # 1.104.0 (Monday list item 24), each optional, so the older sets read as before: the layer a format's lines or
    # points go to; the shapefile's stem in its zip; the records kept and left out; whether its lines stand in for
    # fibre where none is mapped; the degrees between a line's kept vertices; the hosts a redirect may go to
    layer: str = ""
    member: str = ""
    keep: tuple = ()  # ((field, (value, ...)), ...): a record is kept only when each field named holds one of them
    drop: tuple = ()  # likewise: a record is left out when a field named holds one of its values
    stand_in: bool = False
    step: float = STEP
    hosts: tuple = ()
    tiles: tuple = ()  # an mvt set's tiles, (z, x, y) each, asked one after another
    needs: str = ""  # another data set this one is read with, downloaded first (atlas-latest: the probes)
    # item 32's: a busy or failing server asked once more or not (CelesTrak asks that it is not); the seconds its
    # Update waits since the last download; whether the answer is asked gzipped; the satellites' constellation; the
    # queries asked one after another (each its own request)
    retry: bool = True
    every: float = 0.0
    gzip: bool = False
    constellation: str = ""
    queries: tuple = ()
    beams: tuple = ()  # ((a geostationary satellite's number, (the ids of the countries its beams reach, ...)), ...)
    ask: str = "anchors"  # an atlas-latest set's: whose results it asks (ATLAS_ASKS)
    family: int = 4  # ... and its measurement's IP version (ATLAS_FAMILIES)
    most: int = 0  # the bytes its answers may be in all, where it raises its own limit (0: MAX_ANSWER, as every set's)
    refresh: bool = False  # downloaded again by itself every `every` while the tab is open, after the user's first yes
    pause: float = 0.0  # seconds nothing is asked of its host after a 500 or a 503 (CelesTrak's 15 minutes)
    # 1.108.0 (Monday list item 25): a shapefile's names at its records' label points ((lon field, lat field, rank
    # field), its shapes never read); the files asked after its own, beside it on its host (GeoNames' admin2Codes.txt);
    # a set asked round a place, (its width in km, its pieces' side in degrees), and that place (lat, lon, label)
    label: tuple = ()
    also: tuple = ()
    region: tuple = ()
    place: tuple = ()

    @property
    def limit(self) -> int:
        """The bytes its answer may be (all its answers together, where it is asked in several requests): its own
        `most` where it names one, else MAX_ANSWER."""
        return self.most or MAX_ANSWER

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
                   about=_text(said.get("about"))[:2 * NAME], wait=float(wait), **_more(ident, form, said))

    @property
    def host(self) -> str:
        """The host it is asked of."""
        return world._host(self.url).lower()

    def addresses(self, ids=()) -> list[str]:
        """Every address asked, in order: the one address(), or (1.104.0) each of a set of map tiles', or of RIPE
        Atlas's latest results one batch of ATLAS_BATCH anchors' `ids` a request; (1.108.0) its own and then each of
        `also` beside it, or a region's pieces round its place (none before it has one)."""
        if self.region:
            return [f"{self.url}?data={quote(self.query.replace('{bbox}', box), safe='')}" for box in self.boxes()]
        if self.also:
            folder = self.url.rsplit("/", 1)[0]
            return [self.address(), *(f"{folder}/{name}" for name in self.also)]
        if self.format == "atlas-latest":
            ids = sorted({int(i) for i in ids})
            return [f"{self.url}?{self.query + '&' if self.query else ''}probe_ids="
                    f"{','.join(str(i) for i in ids[at:at + ATLAS_BATCH])}" for at in range(0, len(ids), ATLAS_BATCH)]
        if self.queries:
            return [f"{self.url}?{q}" for q in self.queries]
        if self.format != "mvt":
            return [self.address()]
        return [self._tile(z, x, y) for z, x, y in self.tiles]

    def pieces(self) -> list[tuple[float, float, float, float]]:
        """1.108.0: a region's box round its place as the pieces it is asked in, (south, west, north, east) each in
        degrees, south to north and west to east; none before it has a place."""
        if not self.region or not self.place:
            return []
        return _region_pieces(*self.region, float(self.place[0]), float(self.place[1]))

    def boxes(self) -> list[str]:
        """A region's pieces as Overpass's bbox ("south,west,north,east")."""
        return [",".join(f"{v:g}" for v in box) for box in self.pieces()]

    def box(self) -> tuple[float, float, float, float] | None:
        """A region's whole box (south, west, north, east), None without a place."""
        found = self.pieces()
        if not found:
            return None
        return (min(b[0] for b in found), min(b[1] for b in found), max(b[2] for b in found),
                max(b[3] for b in found))

    def placed(self, lat: float, lon: float, label: str = "") -> "DataSet":
        """1.108.0: a region's data set round a place (lat, lon in degrees, its place kept to 0.01 degree, some 1 km):
        its id its template's and the place's (osm-streets-n4071w07401), its title naming the place. ValueError for a
        set that is no region's, and for a place that is none."""
        if not self.region:
            raise ValueError(f"the data set {self.id} is asked of no region")
        for v in (lat, lon):
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v:
                raise ValueError("a region's place is its latitude and longitude, in degrees")
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise ValueError("a region's place is on the globe: latitude -90 to 90, longitude -180 to 180")
        la, lo = round(lat * 100), round(lon * 100)
        code = f"{'n' if la >= 0 else 's'}{abs(la):04d}{'e' if lo >= 0 else 'w'}{abs(lo):05d}"
        name = _name(label) or f"{la / 100:.2f}, {lo / 100:.2f}"
        # the review of 1.108.0: a degree of longitude narrows toward the poles, so a region there takes more pieces
        # (20 km in pieces of 0.05 degrees: 16 at the equator, 84 at 80 degrees, 168 at 85): counted where it is
        many = len(_region_pieces(*self.region, la / 100, lo / 100))
        if many > REGION_PIECES:
            raise ValueError(f"a region {self.region[0]:g} km across round {name} is asked in {many} pieces, more than "
                             f"the {REGION_PIECES} a region may be: a place this near a pole is too wide in longitude")
        return replace(self, id=f"{self.id}-{code}", title=f"{self.title} round {name}"[:2 * NAME],
                       place=(la / 100, lo / 100, name))

    def _tile(self, z: int, x: int, y: int) -> str:
        url = self.url.replace("{z}", str(z)).replace("{x}", str(x)).replace("{y}", str(y))
        return f"{url}?{self.query}" if self.query else url

    def address(self) -> str:
        """The one address asked: an Overpass server's with the query as its `data`, a SPARQL service's with the query
        and the JSON format, a GeoJSON source's or a file of maps' with its query as it is written (or alone, a
        file's); a set of map tiles' first tile."""
        if self.format == "mvt":
            return self._tile(*self.tiles[0])
        if self.region:  # 1.108.0: its first piece, or its address alone before it has a place
            found = self.addresses()
            return found[0] if found else self.url
        if self.queries:
            return f"{self.url}?{self.queries[0]}"
        if self.format == "overpass":
            return f"{self.url}?data={quote(self.query, safe='')}"
        if self.format == "sparql":
            return f"{self.url}?format=json&query={quote(self.query, safe='')}"
        return f"{self.url}?{self.query}" if self.query else self.url


def _choices(ident: str, key: str, value) -> tuple:
    """A data set's keep or drop: {field: [values]} as ((field, (value, ...)), ...); ValueError for anything else."""
    if value is None:
        return ()
    if (not isinstance(value, Mapping) or len(value) > CHOICES
            or any(not isinstance(k, str) or not k or not isinstance(v, (list, tuple)) or not v or len(v) > CHOICES
                   or any(isinstance(x, bool) or not isinstance(x, (str, int, float)) for x in v)
                   for k, v in value.items())):
        raise ValueError(f"the data set {ident}'s {key} is {{field: [values]}}, {CHOICES} of each at most")
    return tuple((k, tuple(v)) for k, v in value.items())


def _more(ident: str, form: str, said: Mapping) -> dict:
    """1.104.0: a data set's optional keys (layer, member, keep, drop, stand_in, step, hosts), checked; ValueError,
    in words, for one that is wrong."""
    out: dict = {}
    layer = said.get("layer", "")
    if layer != "":
        if layer not in {name for name, *_ in LAYERS}:
            names = ", ".join(n for n, *_ in LAYERS)
            raise ValueError(f"the data set {ident}'s layer is one of the globe's ({names}), not {world._shown(layer)}")
        out["layer"] = layer
    if form == "shapefile" and not out.get("layer"):
        raise ValueError(f"the data set {ident} is a shapefile and names no layer its shapes go to")
    member = said.get("member", "")
    if not isinstance(member, str) or (member and not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", member)):
        raise ValueError(f"the data set {ident}'s member is a shapefile's stem (letters, digits and ._-), not "
                         f"{world._shown(member)}")
    if member:
        out["member"] = member
    for key in ("keep", "drop"):
        found = _choices(ident, key, said.get(key))
        if found:
            out[key] = found
    stand_in = said.get("stand_in", False)
    if not isinstance(stand_in, bool):
        raise ValueError(f"the data set {ident}'s stand_in is true or false, not {world._shown(stand_in)}")
    out["stand_in"] = stand_in
    step = said.get("step", STEP)
    if isinstance(step, bool) or not isinstance(step, (int, float)) or not STEPS[0] <= step <= STEPS[1]:
        raise ValueError(f"the data set {ident}'s step is a number of degrees from {STEPS[0]:g} to {STEPS[1]:g}, not "
                         f"{world._shown(step)}")
    out["step"] = float(step)
    hosts = said.get("hosts", ())
    if (not isinstance(hosts, (list, tuple)) or len(hosts) > 4
            or any(not isinstance(h, str) or not HOST_FORM.fullmatch(h.lower()) for h in hosts)):
        raise ValueError(f"the data set {ident}'s hosts are the names a redirect may go to (4 at most), not "
                         f"{world._shown(hosts)}")
    out["hosts"] = tuple(h.lower() for h in hosts)
    needs = said.get("needs", "")
    if not isinstance(needs, str) or (needs and (not ID_FORM.fullmatch(needs) or needs == ident)):
        raise ValueError(f"the data set {ident}'s needs is another data set's id, not {world._shown(needs)}")
    if form == "atlas-latest" and not needs:
        raise ValueError(f"the data set {ident} is read with RIPE Atlas's probes: it names the data set it needs")
    if needs:
        out["needs"] = needs
    ask, family = said.get("ask", "anchors"), said.get("family", 4)
    if ask not in ATLAS_ASKS:
        raise ValueError(f"the data set {ident}'s ask is {' or '.join(ATLAS_ASKS)}, not {world._shown(ask)}")
    if isinstance(family, bool) or family not in ATLAS_FAMILIES:
        raise ValueError(f"the data set {ident}'s family is 4 or 6 (its measurement's IP version), not "
                         f"{world._shown(family)}")
    out["ask"], out["family"] = ask, family
    for key in ("retry", "gzip"):
        value = said.get(key, key == "retry")
        if not isinstance(value, bool):
            raise ValueError(f"the data set {ident}'s {key} is true or false, not {world._shown(value)}")
        out[key] = value
    every = said.get("every", 0)
    if isinstance(every, bool) or not isinstance(every, (int, float)) or not 0 <= every <= EVERY_MOST:
        raise ValueError(f"the data set {ident}'s every is the seconds its Update waits, 0 to {EVERY_MOST:g}, not "
                         f"{world._shown(every)}")
    out["every"] = float(every)
    refresh, pause = said.get("refresh", False), said.get("pause", 0)
    if not isinstance(refresh, bool):
        raise ValueError(f"the data set {ident}'s refresh is true or false, not {world._shown(refresh)}")
    if refresh and every < REFRESH_LEAST:
        raise ValueError(f"the data set {ident} is refreshed by itself only with an every of {REFRESH_LEAST:g} s or "
                         "more: the seconds its maker asks between downloads")
    if isinstance(pause, bool) or not isinstance(pause, (int, float)) or not 0 <= pause <= PAUSE_MOST:
        raise ValueError(f"the data set {ident}'s pause is the seconds nothing is asked after a 500 or a 503, 0 to "
                         f"{PAUSE_MOST:g}, not {world._shown(pause)}")
    out["refresh"], out["pause"] = refresh, float(pause)
    constellation = said.get("constellation", "")
    if not isinstance(constellation, str) or (constellation and not ID_FORM.fullmatch(constellation)):
        raise ValueError(f"the data set {ident}'s constellation is a short id (starlink), not "
                         f"{world._shown(constellation)}")
    if form == "omm-csv" and not constellation:
        raise ValueError(f"the data set {ident} is a file of orbits and names no constellation")
    if constellation:
        out["constellation"] = constellation
    queries = said.get("queries", ())
    if (not isinstance(queries, (list, tuple)) or len(queries) > QUERIES
            or any(not isinstance(q, str) or not q or re.search(r"[\s#?]", q) or len(q) > MAX_QUERY for q in queries)):
        raise ValueError(f"the data set {ident}'s queries are {QUERIES} at most, each sent as it is written")
    if queries:
        out["queries"] = tuple(queries)
    beams = said.get("beams")
    if beams is not None:
        if (not isinstance(beams, Mapping) or len(beams) > 16
                or any(not str(k).isdigit() or not isinstance(v, (list, tuple)) or len(v) > 64
                       or any(not isinstance(x, str) or not x.isalnum() or len(x) > 8 for x in v)
                       for k, v in beams.items())):
            raise ValueError(f"the data set {ident}'s beams are {{a satellite's number: [the countries' ids]}}")
        out["beams"] = tuple((int(k), tuple(v)) for k, v in beams.items())
    most = said.get("most", 0)
    if most:  # the user, 2026-11-26: this set's own limit, said in its confirmation; every other set keeps MAX_ANSWER
        size = said.get("size")
        if (isinstance(most, bool) or not isinstance(most, int) or not MAX_ANSWER < most <= MOST_LARGEST
                or (isinstance(size, int) and most < size)):
            raise ValueError(f"the data set {ident}'s most is the bytes its answers may be, more than "
                             f"{size_words(MAX_ANSWER)} (every set's) and {size_words(MOST_LARGEST)} at most, and no "
                             f"less than its size: not {world._shown(most)}")
        out["most"] = most
    if form == "mvt":
        out["tiles"] = _tiles(ident, said)
        if not out.get("layer"):
            raise ValueError(f"the data set {ident} is a set of map tiles and names no layer its lines go to")
    out.update(_area_keys(ident, form, said, out))
    return out


def _area_keys(ident: str, form: str, said: Mapping, out: Mapping) -> dict:
    """1.108.0 (Monday list item 25): a data set's label, also and region, checked; ValueError, in words, for one that
    is wrong."""
    found: dict = {}
    label = said.get("label")
    if label is not None:
        fields = [label.get(k) for k in ("lon", "lat", "rank")] if isinstance(label, Mapping) else None
        if (form != "shapefile" or out.get("layer") not in POINT_LAYERS or fields is None
                or any(not isinstance(f, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,11}", f) for f in fields[:2])
                or (fields[2] is not None and (not isinstance(fields[2], str)
                                               or not re.fullmatch(r"[A-Za-z0-9_]{1,11}", fields[2])))):
            raise ValueError(f"the data set {ident}'s label is a shapefile's {{lon, lat, rank}}: its records' fields "
                             "(rank optional) of a layer of points")
        found["label"] = tuple(fields[:2]) + ((fields[2],) if fields[2] else ())
    also = said.get("also", ())
    if (not isinstance(also, (list, tuple)) or len(also) > 4
            or any(not isinstance(a, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", a) for a in also)):
        raise ValueError(f"the data set {ident}'s also are the files beside its own on its host (4 at most, a name "
                         "each), not " + world._shown(also))
    if form == "geonames-places" and len(also) != 1:
        raise ValueError(f"the data set {ident} is GeoNames' places and names its divisions' file (also: one name)")
    if also:
        found["also"] = tuple(also)
    region = said.get("region")
    if form == "osm-xml" and region is None:
        raise ValueError(f"the data set {ident} is asked round a place and says no region (its km and its piece)")
    if region is not None:
        km = region.get("km") if isinstance(region, Mapping) else None
        side = region.get("piece") if isinstance(region, Mapping) else None
        if (form != "osm-xml" or any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in (km, side))
                or not REGION_KM[0] <= km <= REGION_KM[1] or not REGION_PIECE[0] <= side <= REGION_PIECE[1]):
            raise ValueError(f"the data set {ident}'s region is {{km: {REGION_KM[0]:g} to {REGION_KM[1]:g}, piece: "
                             f"{REGION_PIECE[0]:g} to {REGION_PIECE[1]:g} degrees}} of an osm-xml set")
        query = said.get("query", "")
        if "{bbox}" not in query:
            raise ValueError(f"the data set {ident} is asked round a place: its query holds {{bbox}}, where each "
                             "piece's box goes")
        found["region"] = (float(km), float(side))
        many = len(_pieces_at_equator(found["region"]))  # the fewest it is ever asked in (placed() counts each)
        if many > REGION_PIECES:
            raise ValueError(f"the data set {ident}'s region is asked in {many} pieces, more than {REGION_PIECES}")
    return found


def _pieces_at_equator(region: tuple) -> list:
    """The pieces a region of that width and piece is asked in at the equator, where they are the most."""
    return _region_pieces(*region, 0.0, 0.0)


def _tiles(ident: str, said: Mapping) -> tuple:
    """An mvt set's tiles: its `tiles` {"zoom", "bounds": [west, south, east, north]} as the (z, x, y) that cover the
    box, TILES_MOST at most; its address a template holding {z}, {x} and {y}. ValueError, in words, for anything
    else."""
    from .. import mvt
    url = said.get("url") if isinstance(said.get("url"), str) else ""
    if not all(k in url for k in ("{z}", "{x}", "{y}")):
        raise ValueError(f"the data set {ident} is a set of map tiles: its address holds {{z}}, {{x}} and {{y}}")
    tiles = said.get("tiles")
    zoom = tiles.get("zoom") if isinstance(tiles, Mapping) else None
    box = tiles.get("bounds") if isinstance(tiles, Mapping) else None
    if (isinstance(zoom, bool) or not isinstance(zoom, int) or not TILE_ZOOMS[0] <= zoom <= TILE_ZOOMS[1]
            or not isinstance(box, (list, tuple)) or len(box) != 4
            or any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in box)
            or not (-180 <= box[0] < box[2] <= 180 and -90 <= box[1] < box[3] <= 90)):
        raise ValueError(f"the data set {ident}'s tiles are {{zoom: {TILE_ZOOMS[0]} to {TILE_ZOOMS[1]}, bounds: [west, "
                         "south, east, north]}")
    found = tuple(mvt.covering(zoom, box))
    if len(found) > TILES_MOST:
        raise ValueError(f"the data set {ident}'s tiles are {len(found):,}, more than the {TILES_MOST} a data set may "
                         "ask for")
    return found


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
    if dataset.format in AS_BYTES:
        return data.encode("utf-8") if isinstance(data, str) else bytes(data) if isinstance(data, memoryview) else data
    if not isinstance(data, (bytes, bytearray, memoryview, str)):
        return data
    raw = bytes(data) if isinstance(data, memoryview) else data
    try:
        if jsonread.too_deep(raw):  # 1.75.2: alike on every Python (3.15 on Linux reads far deeper)
            raise ValueError("nested too deeply")
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


def _thinned(vertices, step_deg: float = STEP) -> list[tuple[int, int]] | None:
    """A line's vertices as they are kept, each in 1e-5 degrees: one nearer than `step_deg` (STEP unless its data set
    says) to the last kept is left out, its first and its last always kept (a cable ends where it lands). None when one
    of them is no point of the globe: the line is not to be trusted."""
    step = round(step_deg * SCALE)
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


class Packed:
    """1.108.0: a line's vertices as a download of a BY_AREA layer keeps them: `ints`, longitude and latitude in 1e-5
    degrees one after the other (8 bytes a vertex, where a pair of floats in a tuple takes some 100), read as (lon, lat)
    pairs in degrees."""
    __slots__ = ("ints",)

    def __init__(self, spots):
        self.ints = array(_I32, (v for spot in spots for v in spot))

    def __len__(self) -> int:
        return len(self.ints) // 2

    def __iter__(self):
        ints = self.ints
        for i in range(0, len(ints) - 1, 2):
            yield ints[i] / SCALE, ints[i + 1] / SCALE


class _Kept:
    """What a parse keeps, by layer, within its bounds: MAX_POINTS points and MAX_VERTICES vertices a layer, nothing
    twice, nothing off the globe, no line under two points. What is left out is counted by why (`dropped`). 1.108.0: a
    BY_AREA layer MAX_AREA_POINTS and MAX_AREA_VERTICES, its lines packed (Packed) and not looked at for repeats (a
    region's way is kept once by its reader); each feature's zoom kept where one is given."""

    def __init__(self, dataset: "DataSet | None" = None):
        self.dataset = dataset  # 1.104.0: whose answer it is (its layer, its records kept, its step)
        self.step = dataset.step if dataset is not None else STEP
        self.layers: dict[str, dict] = {}
        self.dropped: dict[str, int] = {}
        self.remarks: list[str] = []  # what the server remarked that is no error, said on
        self.extra: dict = {}  # 1.104.0: what a reader gives beside the layers (the composite's rows, the probes)
        self.counted: int | None = None  # and how many it read, where that is not its features (atlas-latest)
        self.bytes = 0  # 1.108.0: what a region's pieces came to, read as they came
        self.probes: dict = {}  # the probes an atlas-latest answer is read with, by id
        self._seen: dict[str, set] = {}
        self._vertices: dict[str, int] = {}

    def drop(self, why: str) -> None:
        self.dropped[why] = self.dropped.get(why, 0) + 1

    def point(self, layer: str, lon, lat, name="", sub="", zoom=0) -> None:
        spot = _spot(lon, lat)
        if spot is None:
            return self.drop(OFF)
        name, sub = _name(name), _name(sub)
        seen = self._seen.setdefault(layer, set())
        if (spot, name.casefold()) in seen:
            return self.drop(REPEATED)
        points = self.layers.setdefault(layer, {"points": [], "lines": []})["points"]
        if len(points) >= (MAX_AREA_POINTS if layer in BY_AREA else MAX_POINTS):
            return self.drop(OVER)
        seen.add((spot, name.casefold()))
        kept = (spot[0] / SCALE, spot[1] / SCALE, name, "" if sub == name else sub)
        points.append(kept + (float(zoom),) if zoom else kept)

    def line(self, layer: str, vertices, name="", zoom=0) -> None:
        spots = _thinned(vertices, self.step)
        if spots is None:
            return self.drop(OFF)
        if len(spots) < 2:
            return self.drop(SHORT)
        area = layer in BY_AREA
        seen = self._seen.setdefault(layer, set())
        mark = None if area else hash(tuple(spots))
        if mark is not None and mark in seen:
            return self.drop(REPEATED)
        used = self._vertices.get(layer, 0)
        if used + len(spots) > (MAX_AREA_VERTICES if area else MAX_VERTICES):
            return self.drop(OVER)
        if mark is not None:
            seen.add(mark)
        self._vertices[layer] = used + len(spots)
        kept = (Packed(spots) if area else [(x / SCALE, y / SCALE) for x, y in spots], _name(name))
        self.layers.setdefault(layer, {"points": [], "lines": []})["lines"].append(
            kept + (float(zoom),) if zoom else kept)

    def features(self) -> dict:
        layers = {layer: self.layers[layer] for layer, *_ in LAYERS
                  if layer in self.layers and (self.layers[layer]["points"] or self.layers[layer]["lines"])}
        count = sum(len(e["points"]) + len(e["lines"]) for e in layers.values())
        return {**self.extra, "layers": layers, "features": count if self.counted is None else self.counted,
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


def _unpacked(data, host: str, most: int | None = None):
    """A gml answer unpacked: a gzipped one, each of its gzip members in turn as gzip reads them, MAX_UNPACKED bytes at
    most; one that is not gzipped as it is. A member is handed to zlib a piece at a time, FEED bytes first and twice as
    many each time after, FEED_MOST at most: what follows the member's end in its last piece is copied (zlib's
    unused_data), so the work grows with the answer however many members it holds (handed the whole rest of the
    answer, 320,000 empty members took 306 s). InfrastructureError for one that does not unpack, is cut short or would
    unpack to more."""
    if bytes(data[:2]) != GZIP:
        return data
    most = MAX_UNPACKED if most is None else most  # 1.104.0: a set's own limit's, in proportion (_scale)
    view, out, at = memoryview(data), bytearray(), 0
    while len(view) - at >= 2 and bytes(view[at:at + 2]) == GZIP:
        unzip, feed = zlib.decompressobj(16 + zlib.MAX_WBITS), FEED
        while not unzip.eof:
            given = view[at:at + feed]
            if not given:
                raise InfrastructureError(f"{host}'s answer is not the data asked for (it is cut short)")
            try:
                piece = unzip.decompress(given, most + 1 - len(out))  # a byte more than may be: too much
            except zlib.error as e:
                raise InfrastructureError(f"{host}'s answer is not the data asked for (it does not unpack: "
                                          f"{_text(str(e))[:REMARK]})") from None
            out += piece
            if len(out) > most:
                raise InfrastructureError(f"{host}'s answer unpacks to more than {size_words(most)}, the most "
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


AIRPORT_KINDS = ("large_airport", "medium_airport")  # OurAirports' kinds kept: the ones routers are named after


def _ourairports(doc, kept: _Kept, host: str, free: bool) -> None:
    """OurAirports' airports.csv (1.73.0): each large or medium airport with a three-letter IATA code a point of
    "airports", named by its code, its name, its town and its country its sub."""
    import csv
    text = doc.decode("utf-8-sig", "replace") if isinstance(doc, (bytes, bytearray)) else str(doc)
    rows = csv.DictReader(io.StringIO(text))
    if not rows.fieldnames or not {"type", "iata_code", "latitude_deg", "longitude_deg"} <= set(rows.fieldnames):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (no airports' columns: {_begins(text)})")
    for row in rows:
        code = (row.get("iata_code") or "").strip().upper()
        if row.get("type") not in AIRPORT_KINDS or not re.fullmatch(r"[A-Z]{3}", code):
            kept.drop(OTHER)
            continue
        try:
            lat, lon = float(row["latitude_deg"]), float(row["longitude_deg"])
        except (TypeError, ValueError):
            kept.drop(OFF)
            continue
        where = ", ".join(x for x in ((row.get("name") or "").strip(), (row.get("municipality") or "").strip(),
                                      (row.get("iso_country") or "").strip()) if x)
        kept.point("airports", lon, lat, code, where)


def _geonames(doc, kept: _Kept, host: str, free: bool) -> None:
    """GeoNames' cities (1.73.0: cities15000.zip, the one text file in it, tab-separated): each a point of "cities",
    the most people first (MAX_POINTS of them), named by its name in ASCII, its sub "CC-A1 · people" (its country's
    code, its first-order division's code, as routers' names abbreviate them, and how many live there)."""
    import zipfile
    raw = bytes(doc)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = [i for i in z.infolist() if i.filename.endswith(".txt") and not i.is_dir()]
            if len(names) != 1 or names[0].file_size > MAX_UNPACKED:
                raise InfrastructureError(f"{host}'s answer is not the data asked for (one text file in a zip, "
                                          f"{size_words(MAX_UNPACKED)} at most)")
            text = z.read(names[0]).decode("utf-8", "replace")
    except zipfile.BadZipFile:
        raise InfrastructureError(f"{host}'s answer is not the data asked for (no zip: {_begins(raw)})") from None
    found = []
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) < 15:
            kept.drop(OTHER)
            continue
        try:
            found.append((int(f[14] or 0), float(f[5]), float(f[4]), f[2] or f[1], f[8], f[10]))
        except ValueError:
            kept.drop(OFF)
    found.sort(key=lambda c: -c[0])
    for people, lon, lat, name, country, division in found:
        where = f"{country}-{division}" if division else country
        kept.point("cities", lon, lat, name, f"{where} · {people:,}")


def _chosen(dataset: DataSet, record: Mapping) -> bool:
    """Whether a record is kept by its data set's keep and drop (1.104.0): each field keep names holds one of its
    values, and no field drop names holds one of its; values compared as text, in any case."""
    low = {str(k).lower(): v for k, v in record.items()}

    def holds(name: str, values: tuple) -> bool:
        have = low.get(name.lower())
        return have is not None and str(have).strip().casefold() in {str(v).strip().casefold() for v in values}
    return all(holds(k, v) for k, v in dataset.keep) and not any(holds(k, v) for k, v in dataset.drop)


SHAPE_NAMES = ("name", "label", "name_en")  # a shape's name: the first of its record's fields that holds words


def _shapefile(doc, kept: _Kept, host: str, free: bool) -> None:
    """A zipped ESRI shapefile (1.104.0: Natural Earth's roads and railways): its lines (each part of a polyline, and
    of a polygon its rings) into its data set's layer, its points into it alike when that layer is one of points,
    named by their record (SHAPE_NAMES, else its `type`), its keep and drop applied. Its coordinates must be WGS 84's
    longitude and latitude (liminal_libs.shapefile refuses any other)."""
    from .. import shapefile
    dataset = kept.dataset
    if not isinstance(doc, (bytes, bytearray)):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it is no zipped shapefile)")
    if dataset.label:
        return _labels(doc, kept, host)
    try:
        shapes = shapefile.read(doc, dataset.member or None, most_bytes=shapefile.SHP_MOST * _scale(dataset),
                                most_records=shapefile.RECORDS_MOST * _scale(dataset))
    except shapefile.ShapefileError as e:
        raise InfrastructureError(f"{host}'s answer is not the data asked for ({e})") from None
    points = dataset.layer in POINT_LAYERS
    for shape in shapes:
        if not _chosen(dataset, shape.record):
            kept.drop(OTHER)
            continue
        low = {str(k).lower(): v for k, v in shape.record.items()}
        name = next((t for t in (_name(low.get(k)) for k in SHAPE_NAMES) if t), "") or _name(low.get("type"))
        if shape.kind in ("point", "multipoint"):
            if not points:
                kept.drop(OTHER)
                continue
            for part in shape.parts:
                for lon, lat in part:
                    kept.point(dataset.layer, lon, lat, name)
        elif points:
            kept.drop(OTHER)
        else:
            for part in shape.parts:
                kept.line(dataset.layer, part, name)


def _rank_zoom(rank) -> float:
    """1.108.0: the globe's zoom a name of a web map's rank (Natural Earth's MIN_LABEL: the web map's zoom it is placed
    from) is placed from, 1 (the start) at the least: 2^(rank - WEB_ZOOM - LABEL_EARLY)."""
    if isinstance(rank, bool) or not isinstance(rank, (int, float)) or rank != rank:
        return 1.0
    return float(min(1024.0, max(1.0, round(2 ** (rank - WEB_ZOOM - LABEL_EARLY), 2))))


def _labels(doc, kept: _Kept, host: str) -> None:
    """1.108.0 (Monday list item 25): a shapefile's names at the label points its records hold (Natural Earth's
    countries' LABEL_X and LABEL_Y, its states' longitude and latitude), each from the zoom its rank says (_rank_zoom):
    its .dbf alone is read (shapefile.records), never its shapes; its keep and drop applied, a record without a place
    on the globe or a name left out."""
    from .. import shapefile
    dataset = kept.dataset
    lon_field, lat_field, *rank = dataset.label
    try:
        rows = shapefile.records(doc, dataset.member or None, most_bytes=shapefile.SHP_MOST * _scale(dataset),
                                 most_records=shapefile.RECORDS_MOST * _scale(dataset))
    except shapefile.ShapefileError as e:
        raise InfrastructureError(f"{host}'s answer is not the data asked for ({e})") from None
    if rows and not {lon_field.lower(), lat_field.lower()} <= {str(k).lower() for k in rows[0]}:
        raise InfrastructureError(f"{host}'s answer is not the data asked for (its records hold no {lon_field} and "
                                  f"{lat_field}, the label points its data set reads)")
    for record in rows:
        if not _chosen(dataset, record):
            kept.drop(OTHER)
            continue
        low = {str(k).lower(): v for k, v in record.items()}
        name = next((t for t in (_name(low.get(k)) for k in SHAPE_NAMES) if t), "")
        if not name:
            kept.drop(OTHER)
            continue
        zoom = _rank_zoom(low.get(rank[0].lower())) if rank else 1.0
        kept.point(dataset.layer, low.get(lon_field.lower()), low.get(lat_field.lower()), name, "", zoom=zoom)


def _town_zoom(people: int) -> float:
    return next(z for least, z in TOWN_ZOOMS if people >= least)


def _geonames_places(doc, kept: _Kept, host: str, free: bool) -> None:
    """1.108.0 (Monday list item 25): GeoNames' cities500.zip and admin2Codes.txt, asked one after the other: each town
    a point of "towns" from the zoom its people say (TOWN_ZOOMS), its sub "CC-A1 · people"; each second-order division
    (a county) with a town named at the middle of its towns, a point of "counties" from COUNTY_ZOOM, its sub its
    country's and first division's codes. The cities' text is read a line at a time from the zip, never whole; a
    division with no town of the file is not placed (counted)."""
    import zipfile
    if not isinstance(doc, list) or len(doc) != 2:
        raise InfrastructureError(f"{host}'s answer is not the data asked for (the cities' zip, the divisions' file)")
    raw, codes = bytes(doc[0][1]), bytes(doc[1][1])
    if free:
        doc[:] = []
    names: dict[str, str] = {}
    for line in codes.decode("utf-8", "replace").splitlines():
        f = line.split("\t")
        if len(f) >= 3 and f[0].count(".") == 2:
            names[f[0]] = f[1] or f[2]
    del codes
    middles: dict[str, list] = {}  # a division's code -> [x, y, z, towns]: the sum of its towns' unit vectors
    found = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            texts = [i for i in z.infolist() if i.filename.endswith(".txt") and not i.is_dir()]
            most = MAX_UNPACKED * _scale(kept.dataset)
            if len(texts) != 1 or texts[0].file_size > most:
                raise InfrastructureError(f"{host}'s answer is not the data asked for (one text file in a zip, "
                                          f"{size_words(most)} at most)")
            with z.open(texts[0]) as stream:
                for line in io.TextIOWrapper(stream, encoding="utf-8", errors="replace", newline="\n"):
                    f = line.rstrip("\n").split("\t")
                    if len(f) < 15:
                        kept.drop(OTHER)
                        continue
                    try:
                        lat, lon, people = float(f[4]), float(f[5]), int(f[14] or 0)
                    except ValueError:
                        kept.drop(OFF)
                        continue
                    found.append((people, lon, lat, f[1] or f[2], f[8], f[10]))
                    if f[11] and _spot(lon, lat) is not None:
                        key = f"{f[8]}.{f[10]}.{f[11]}"
                        a, b = math.radians(lat), math.radians(lon)
                        m = middles.setdefault(key, [0.0, 0.0, 0.0, 0])
                        m[0] += math.cos(a) * math.cos(b)
                        m[1] += math.cos(a) * math.sin(b)
                        m[2] += math.sin(a)
                        m[3] += 1
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError) as e:
        raise InfrastructureError(f"{host}'s answer is not the data asked for (no zip that reads: "
                                  f"{' '.join(str(e).split())[:80]})") from None
    del raw
    found.sort(key=lambda c: -c[0])
    for people, lon, lat, name, country, division in found:
        where = f"{country}-{division}" if division else country
        kept.point("towns", lon, lat, name, f"{where} · {people:,}", zoom=_town_zoom(people))
    del found
    for key, name in names.items():
        m = middles.get(key)
        if not m:
            kept.drop(UNPLACED)
            continue
        x, y, zz = m[0] / m[3], m[1] / m[3], m[2] / m[3]
        lat, lon = math.degrees(math.atan2(zz, math.hypot(x, y))), math.degrees(math.atan2(y, x))
        country, first, _ = key.split(".")
        kept.point("counties", round(lon, 5), round(lat, 5), name, f"{country}-{first}", zoom=COUNTY_ZOOM)


def _way_zoom(tags: Mapping, box: tuple[float, float, float, float]) -> tuple[str, float]:
    """1.108.0: an OpenStreetMap way's layer and the zoom it is drawn from, by its tags; ("", 0) for one of no kind
    kept. A road by its class (ROAD_ZOOMS); a building from where it spans BUILDING_PX pixels, 64x at the soonest; a
    county's boundary (admin_level COUNTY_LEVEL) from COUNTY_ZOOM."""
    road = str(tags.get("highway") or "")
    road = road[:-5] if road.endswith("_link") else road
    if road in ROAD_ZOOMS:
        return "streets", ROAD_ZOOMS[road]
    if tags.get("building") not in (None, "", "no"):
        w, s, e, n = box
        span = max((e - w) * 111_320 * math.cos(math.radians((s + n) / 2)), (n - s) * 110_574, 1.0)
        return "buildings", float(min(1024.0, max(LAYER_FROM["buildings"], round(BUILDING_PX * PIXEL_M / span, 2))))
    if tags.get("boundary") == "administrative" and str(tags.get("admin_level") or "") == COUNTY_LEVEL:
        return "countylines", COUNTY_ZOOM
    return "", 0.0


def _osm_piece(raw, kept: _Kept, host: str, piece=None, region=None, outside: set | None = None) -> int:
    """1.108.0 (Monday list item 25): one piece of a region's Overpass answer in XML (out tags geom: each way's tags and
    its points' places, no node's id), read as it streams through expat XML_FEED bytes at a time by its own handlers,
    no tree built: of a way only its tags (GML_KEYS at most) and its points (WAY_POINTS; a longer way is left out) are
    held until it ends, PIECE_POINTS in the piece at most (more refuses the answer), nothing of any other element. Its
    roads, buildings and counties' boundaries kept (_way_zoom), named by their name (else their ref). A way crossing
    several pieces is kept once, segment by segment (1.109.0, _osm_way): each by the piece its first point is in
    (`piece`, south, west, north, east: half-open, its north and east edges the next piece's unless they are the
    region's), or, coming in from outside the region (`region`), by the one its second point is in; an nd without
    coordinates (a point outside the piece, as Overpass crops `out geom`) breaks the way there, nothing dropped of the
    rest (`outside` is no longer needed). The answer is read as UTF-8 whatever it declares
    (Overpass writes nothing else); a document type or an entity declared refuses it in the parser itself, as does a
    remark that is an error (the query did not finish). The ways read, kept or not."""
    from xml.parsers import expat

    data = memoryview(raw)
    parser = expat.ParserCreate(encoding="UTF-8")  # the answer's own declaration overruled: UTF-8 or nothing
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    state = {"root": None, "depth": 0, "way": None, "tags": {}, "points": [], "long": False, "ways": 0, "read": 0,
             "remark": None}

    def refuse(*_args):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it declares a document type or an "
                                  "entity)")

    def start(tag, attrs):
        state["depth"] += 1
        if state["root"] is None:
            state["root"] = tag
            if tag != "osm":
                raise InfrastructureError(f"{host}'s answer is not the data asked for (its root is {_name(tag)[:20]}, "
                                          "not osm)")
        elif tag == "way":
            state.update(way=attrs.get("id"), tags={}, points=[], long=False)
        elif tag == "nd" and state["way"] is not None:
            points = state["points"]
            if len(points) >= WAY_POINTS:
                state["long"] = True
                return
            state["read"] += 1
            if state["read"] > PIECE_POINTS:
                raise InfrastructureError(f"{host}'s answer holds more than {PIECE_POINTS:,} points in one piece: "
                                          "nothing was kept")
            try:
                points.append((float(attrs.get("lon")), float(attrs.get("lat"))))
            except (TypeError, ValueError):
                points.append((None, None))
        elif tag == "tag" and state["way"] is not None and len(state["tags"]) < GML_KEYS:
            state["tags"].setdefault(str(attrs.get("k")), str(attrs.get("v") or ""))
        elif tag == "remark" and state["depth"] == 2:
            state["remark"] = []

    def text(chunk):
        words = state["remark"]
        if words is not None and sum(map(len, words)) < REMARK * 2:
            words.append(chunk)

    def end(tag):
        state["depth"] -= 1
        if tag == "remark" and state["remark"] is not None:
            words = _text("".join(state["remark"]))[:REMARK]
            state["remark"] = None
            if "error" in words.lower():
                raise InfrastructureError(f"{host} could not finish the query: {words}")
            if words:
                kept.remarks.append(f"{host} remarked: {words}")
        elif tag == "way" and state["way"] is not None:
            state["ways"] += 1
            if state["long"]:
                kept.drop(LONG)
            else:
                _osm_way(kept, state["way"], state["tags"], state["points"], piece, region, outside, inside)
            state.update(way=None, tags={}, points=[], long=False)

    def inside(box, lon, lat) -> bool:  # the region's box, closed
        return box is not None and box[0] <= lat <= box[2] and box[1] <= lon <= box[3]

    def ours(lon, lat) -> bool:  # the piece's, half-open: its north and east edges the next piece's
        s_, w_, n_, e_ = piece
        north = lat < n_ or (lat == n_ and (region is None or n_ >= region[2]))
        east = lon < e_ or (lon == e_ and (region is None or e_ >= region[3]))
        return s_ <= lat and w_ <= lon and north and east

    inside.ours = ours
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    try:
        for at in range(0, max(1, len(data)), XML_FEED):
            parser.Parse(bytes(data[at:at + XML_FEED]), at + XML_FEED >= len(data))
    except expat.ExpatError as e:
        raise InfrastructureError(f"{host}'s answer is not the data asked for (its XML does not read: "
                                  f"{' '.join(str(e).split())[:80]})") from None
    if state["root"] is None:
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it is empty)")
    return state["ways"]


def _osm_way(kept: _Kept, ident, tags, points, piece, region, outside, inside) -> None:
    """1.109.0 (item 14): a way kept segment by segment. Overpass' global bbox crops `out geom` to the piece asked: a
    point outside it comes as an nd with no coordinates (but for the first one past each end of a stretch inside), so
    a way crossing a piece's edge has gaps, and the piece its first point is in may not hold the rest of it. Each
    segment between two points with coordinates is kept by one piece, whichever way Overpass answers: the one its
    first point is in (`inside.ours`, half-open), or, for a segment coming in from outside the region (`region`), the
    one its second point is in; the segments a piece keeps that follow one another are one line. Without a piece
    (one answer, no region) every stretch of two points or more is kept. (`ident` and `outside` are no longer
    needed: 1.108.0 kept a way whole by the piece its first point was in.)"""
    if len(points) < 2:
        return kept.drop(OFF if points else SHORT)
    runs, run = [], []
    for a, b in zip(points, points[1:]):
        if a[0] is None or b[0] is None:
            ours = False
        elif piece is None:
            ours = True
        else:
            ours = inside.ours(*a) or (not inside(region, *a) and inside.ours(*b))
        if ours:
            run = run or [a]
            run.append(b)
        elif run:
            runs.append(run)
            run = []
    if run:
        runs.append(run)
    if not runs:  # no segment with both its ends placed, or every one another piece's
        return kept.drop(OFF) if piece is None or all(p[0] is None for p in points) else None
    placed = [p for p in points if p[0] is not None]  # its zoom by all of it this piece was given
    xs, ys = [p[0] for p in placed], [p[1] for p in placed]
    layer, zoom = _way_zoom(tags, (min(xs), min(ys), max(xs), max(ys)))
    if not layer:
        return kept.drop(OTHER)
    name = _name(tags.get("name")) or _name(tags.get("ref"))
    for run in runs:
        kept.line(layer, run, name, zoom=zoom)


def _osm_xml(doc, kept: _Kept, host: str, free: bool) -> None:
    """1.108.0: a region's answers, piece by piece ([(the piece's number, its bytes)], or one answer's bytes): each read
    by _osm_piece as the install does, the region's pieces telling which way each piece keeps."""
    dataset = kept.dataset
    answers = doc if isinstance(doc, list) else [(0, doc)]
    pieces = dataset.pieces() if dataset is not None else []
    box = dataset.box() if dataset is not None else None
    outside: set = set()
    for i, (number, raw) in enumerate(answers):
        if free:
            answers[i] = (number, b"")
        piece = pieces[number] if 0 <= number < len(pieces) else None
        _osm_piece(raw, kept, host, piece, box if piece is not None else None, outside)


def _mvt(doc, kept: _Kept, host: str, free: bool) -> None:
    """A set of map tiles (1.104.0: AfTerFibre's fibre): each tile's layer its data set's member names (all when it
    names none), its lines into the data set's layer in longitude and latitude, named by who runs them (TILE_FIELDS),
    "planned" said of one not yet lit. A line cut at a tile's edge is two lines meeting there (the network joins them).
    Only TILE_FIELDS are decoded: a contributor's name or address is never read into anything."""
    from .. import mvt
    dataset = kept.dataset
    if not isinstance(doc, list):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it is no set of map tiles)")
    layers = (dataset.member,) if dataset.member else None
    read = 0
    for i, (z, x, y, raw) in enumerate(doc):
        if free:
            doc[i] = (z, x, y, b"")
        if not raw:
            continue  # a tile with nothing in it (404): the sea, a desert
        try:
            # the review: tiles kept gzipped (tippecanoe's, on S3 and CloudFront) come so whatever is asked, and
            # urllib unpacks nothing; a tile that is not gzipped is read as it is
            found = mvt.decode(bytes(_unpacked(raw, host)), keys=TILE_FIELDS, layers=layers)
        except mvt.MvtError as e:
            raise InfrastructureError(f"{host}'s tile {z}/{x}/{y} is not the data asked for ({e})") from None
        read += 1
        for layer in found:
            for feature in layer.features:
                if feature.type not in (mvt.LINE, mvt.POLYGON):
                    kept.drop(OTHER)
                    continue
                tags = feature.tags
                name = next((t for t in (_name(tags.get(k)) for k in TILE_FIELDS[:4]) if t), "")
                if tags.get("live") in (False, 0, "false", "no", "planned"):
                    name = f"{name} (planned)" if name else "planned"
                for part in feature.parts:
                    kept.line(dataset.layer, [mvt.lonlat(z, x, y, layer.extent, gx, gy) for gx, gy in part], name)
    kept.remarks.append(f"{world._plural(len(doc), 'tile')} asked: {world._plural(read, 'tile')} with features")


def _place_key(name: str, lat: float, lon: float) -> str:
    """A place's key in the composite database: its name and where it is, to two decimals."""
    return f"{name}|{lat:.2f},{lon:.2f}"


def _topohub(doc, kept: _Kept, host: str, free: bool) -> None:
    """TopoHub's model of the backbones (1.104.0, item 28: networkx node-link JSON, each node's `pos` [longitude,
    latitude]): each City a point of modelcities, each edge a line of models from the end further west (its seacable
    edges too: a model's links are no cable routes), and for the composite database each city a place and each edge a
    link ({"a", "b", "km", "type", "source": "topohub"}). A node without a place is left out, and its edges with it."""
    nodes = doc.get("nodes") if isinstance(doc, Mapping) else None
    edges = (doc.get("links") if isinstance(doc.get("links"), list) else doc.get("edges")) \
        if isinstance(doc, Mapping) else None
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it is no graph of nodes and links)")
    placed, places, links = {}, [], []
    for node in nodes:
        pos = node.get("pos") if isinstance(node, Mapping) else None
        if not isinstance(pos, list) or len(pos) < 2 or _spot(pos[0], pos[1]) is None:
            kept.drop(UNPLACED)
            continue
        lon, lat, name = float(pos[0]), float(pos[1]), _name(node.get("name")) or _name(str(node.get("id", "")))
        kind = _name(node.get("type"))
        placed[node.get("id")] = (lon, lat, name)
        if kind.lower() == "city":
            kept.point("modelcities", lon, lat, name, "TopoHub's model")
            places.append((_place_key(name, lat, lon), {"lat": round(lat, 4), "lon": round(lon, 4), "label": name,
                                                        "type": kind}))
    for edge in edges:
        ends = (placed.get(edge.get("source")), placed.get(edge.get("target"))) if isinstance(edge, Mapping) else ()
        if len(ends) != 2 or None in ends:
            kept.drop(ENDS)
            continue
        a, b = sorted(ends)
        kind = _name(edge.get("type"))
        kept.line("models", [(a[0], a[1]), (b[0], b[1])], f"{a[2] or 'a point'} to {b[2] or 'a point'}")
        km = edge.get("dist")
        links.append((f"topohub:{_place_key(a[2], a[1], a[0])}>{_place_key(b[2], b[1], b[0])}",
                      {"a": _place_key(a[2], a[1], a[0]), "b": _place_key(b[2], b[1], b[0]), "type": kind,
                       "km": round(float(km), 1) if isinstance(km, (int, float)) and not isinstance(km, bool) else None,
                       "source": "topohub"}))
    kept.extra["composite"] = {"places": places, "links": links}


def _bunzipped(data, host: str, most: int | None = None) -> bytes:
    """A bzip2 answer unpacked, MAX_UNPACKED bytes at most; one that is not bzip2 as it is."""
    import bz2
    most = MAX_UNPACKED if most is None else most  # 1.104.0: a set's own limit's, in proportion (_scale)
    if bytes(data[:3]) != b"BZh":
        return bytes(data)
    out, view = bytearray(), memoryview(data)
    unzip = bz2.BZ2Decompressor()
    try:
        out += unzip.decompress(view, most + 1)
        while not unzip.eof and unzip.needs_input is False and len(out) <= most:
            out += unzip.decompress(b"", most + 1 - len(out))
    except (OSError, EOFError, ValueError) as e:
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it does not unpack: "
                                  f"{_text(str(e))[:REMARK]})") from None
    if len(out) > most:
        raise InfrastructureError(f"{host}'s answer unpacks to more than {size_words(most)}, the most a data "
                                  "set may be")
    return bytes(out)


def _atlas_probes(doc, kept: _Kept, host: str, free: bool) -> None:
    """RIPE Atlas's probes file (1.104.0, item 29: bzip2 JSON, its `objects`): each probe and anchor with a place a
    point of probes (its id, its country and networks its sub), and a row of the database's probes table: id, place,
    country, IPv4 and IPv6 networks, whether an anchor and whether connected. Its description and tags (its owner's own
    words) are never kept."""
    raw = _bunzipped(doc, host, MAX_UNPACKED * _scale(kept.dataset))
    try:
        if jsonread.too_deep(raw):
            raise ValueError("nested too deeply")
        found = json.loads(raw)
    except (ValueError, RecursionError):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it is no JSON: "
                                  f"{_begins(raw)})") from None
    objects = found.get("objects") if isinstance(found, Mapping) else found
    if not isinstance(objects, list):
        raise InfrastructureError(f"{host}'s answer is not the data asked for (it holds no list of probes)")
    rows = []
    for p in objects:
        if not isinstance(p, Mapping) or isinstance(p.get("id"), bool) or not isinstance(p.get("id"), int):
            kept.drop(OTHER)
            continue
        geometry = p.get("geometry")
        where = geometry.get("coordinates") if isinstance(geometry, Mapping) else None
        lon, lat = (where[0], where[1]) if isinstance(where, list) and len(where) >= 2 else (p.get("longitude"),
                                                                                              p.get("latitude"))
        if _spot(lon, lat) is None:
            kept.drop(UNPLACED)
            continue
        status = p.get("status")
        status = status.get("name") if isinstance(status, Mapping) else p.get("status_name", status)
        connected = status in (1, "1", "Connected")
        anchor = p.get("is_anchor") is True
        country = _name(p.get("country_code"))[:2].upper()
        asn4, asn6 = (v if isinstance(v, int) and not isinstance(v, bool) else None
                      for v in (p.get("asn_v4"), p.get("asn_v6")))
        nets = ", ".join(f"AS{n}" for n in dict.fromkeys(v for v in (asn4, asn6) if v))
        kept.point("probes", lon, lat, f"{'Anchor' if anchor else 'Probe'} {p['id']}",
                   " · ".join(x for x in (country, nets, "" if connected else "not connected") if x))
        rows.append((p["id"], float(lat), float(lon), country, asn4, asn6, int(anchor), int(connected)))
    kept.extra["probes"] = rows


def _global(address) -> str:
    """An address as it is kept: a global one's text; "" for a private, a shared or a local one (never kept)."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        return ""
    return str(ip) if ip.is_global else ""


def _atlas_latest(doc, kept: _Kept, host: str, free: bool) -> None:
    """RIPE Atlas's newest traceroutes of its probes (1.104.0, item 29), its answers one a batch of ids: of each
    result its probe (its place from the probes table, `kept.probes`), each hop's addresses and RTTs. Into the
    composite database: a router whose least RTT from its probe is NEAR_MS or under claimed at the probe's place,
    within RTT x KM_PER_MS / 2 km (source atlas); every two answering hops one after the other a link. Private and
    shared addresses are never kept, nor the probe's own."""
    probes = kept.probes
    claims, links, read = {}, {}, 0
    for _, raw in doc:
        try:
            if jsonread.too_deep(raw):
                raise ValueError("nested too deeply")
            results = json.loads(raw)
        except (ValueError, RecursionError):
            raise InfrastructureError(f"{host}'s answer is not the data asked for (it is no JSON: "
                                      f"{_begins(raw)})") from None
        if not isinstance(results, list):
            raise InfrastructureError(f"{host}'s answer is not the data asked for (it holds no list of results)")
        for r in results:
            if read >= ATLAS_RESULTS:
                kept.drop(OVER)
                continue
            probe = probes.get(r.get("prb_id")) if isinstance(r, Mapping) else None
            hops = r.get("result") if isinstance(r, Mapping) else None
            if probe is None or not isinstance(hops, list):
                kept.drop(OTHER)
                continue
            read += 1
            before = ""
            for hop in hops[:ATLAS_HOPS]:
                answers = hop.get("result") if isinstance(hop, Mapping) else None
                seen: dict[str, float] = {}
                for a in answers if isinstance(answers, list) else ():
                    address = _global(a.get("from")) if isinstance(a, Mapping) else ""
                    rtt = a.get("rtt") if isinstance(a, Mapping) else None
                    if address and isinstance(rtt, (int, float)) and not isinstance(rtt, bool) and rtt >= 0:
                        seen[address] = min(rtt, seen.get(address, rtt))
                    elif address:
                        seen.setdefault(address, float("inf"))
                if not seen:
                    before = ""
                    continue
                first = next(iter(seen))
                for address, rtt in seen.items():
                    if rtt <= NEAR_MS and (address not in claims or rtt < claims[address]["ms"]):
                        claims[address] = {"lat": probe["lat"], "lon": probe["lon"], "ms": round(rtt, 3),
                                           "within_km": round(rtt * KM_PER_MS / 2, 1),
                                           "label": f"near RIPE Atlas {'anchor' if probe.get('anchor') else 'probe'} "
                                                    f"{probe['id']}"}
                if before and before != first:
                    links[f"{before}>{first}"] = {"a": before, "b": first, "source": "atlas"}
                before = first
    kept.extra["composite"] = {"claims": list(claims.items()), "links": list(links.items())}
    kept.counted = read


def _omm_csv(doc, kept: _Kept, host: str, free: bool) -> None:
    """Satellites' orbits as CelesTrak publishes them (1.104.0, item 32: its GP data as CSV, OMM's fields), one answer
    or one a query, gzipped or not: each satellite a row of the database's orbits table, under its data set's
    constellation. What does not read is counted; an answer that is no CSV of orbits is refused."""
    from . import satellites
    parts = doc if isinstance(doc, list) else [(0, doc)]
    rows: dict[int, tuple] = {}
    for _, raw in parts:
        try:
            found, left = satellites.omm_rows(_unpacked(raw, host))
        except (ValueError, csv.Error) as e:  # 1.109.0: a line past csv's field limit is a refusal too
            raise InfrastructureError(f"{host}'s answer is not the data asked for ({e})") from None
        for _ in range(left):
            kept.drop(OTHER)
        for row in found:
            norad = int(row["NORAD_CAT_ID"])
            if norad in rows:
                kept.drop(REPEATED)
                continue
            rows[norad] = (norad, kept.dataset.constellation, _name(row["OBJECT_NAME"]),
                           satellites.epoch_of(row["EPOCH"]), row)
    kept.extra["orbits"] = list(rows.values())
    kept.counted = len(rows)


_READERS = {"overpass": _overpass, "sparql": _sparql, "geojson": _geojson, "gml": _gml, "ourairports": _ourairports,
            "geonames": _geonames, "shapefile": _shapefile, "mvt": _mvt, "topohub": _topohub,
            "atlas-probes": _atlas_probes, "atlas-latest": _atlas_latest, "omm-csv": _omm_csv,
            "geonames-places": _geonames_places, "osm-xml": _osm_xml}


def _features(dataset: DataSet, doc, free: bool, probes=None) -> dict:
    kept = _Kept(dataset)
    kept.probes = probes or {}
    _READERS[dataset.format](doc, kept, dataset.host, free)
    return kept.features()


def parse(dataset, data, probes=None) -> dict:
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
    return _features(dataset, doc, free=doc is not data, probes=probes)


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
            for vertices, *_ in lines:  # the review of 1.108.0: a line may carry its zoom, third
                for lon, lat in vertices:
                    xy.extend((round(lon * SCALE), round(lat * SCALE)))
                offsets.append(len(xy) // 2)
            entry["lines"] = {"n": len(lines), "offsets": _packed(offsets), "xy": _packed(xy),
                              "names": [_name(line[1]) for line in lines]}
        if entry:
            layers[layer] = entry
            count += len(points) + len(lines)
    dropped = features.get("dropped") if isinstance(features, Mapping) else 0
    total = sum(int(n) for n in dropped.values()) if isinstance(dropped, Mapping) else int(dropped or 0)
    return {"v": VERSION, "set": dataset.id, "title": dataset.title, "source": dataset.source,
            "licence_name": dataset.licence_name, "credit": dict(dataset.credit), "fetched": _when(fetched),
            "features": count, "dropped": total, "layers": layers, **({"stand_in": True} if dataset.stand_in else {})}


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
    if code is not None and not dataset.retry:  # 1.104.0: a source that asks not to be asked again at once
        later = " Its maker asks that nothing is asked of it for 15 minutes after this." if code in (500, 503) else ""
        return (f"{host} answered HTTP {code}, so the download stopped there and is not tried again by itself: "
                f"nothing was installed, and what was installed before stays.{later}")
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


def _too_large(dataset: DataSet, several: bool = False) -> str:
    """The words for an answer (or, `several`, the answers of a set asked in several requests) larger than its data
    set's limit: MAX_ANSWER, or its own `most`."""
    what = "its answers are larger than" if several else "the answer is larger than"
    whose = "the most this data set may be" if dataset.most else "the most a data set may be"
    return f"{what} {size_words(dataset.limit)}{' in all' if several else ''}, {whose}"


def _scale(dataset: "DataSet | None") -> int:
    """How many times every set's bounds of what an answer unpacks to and of the records it holds a data set's own
    limit allows: 1 for every set but one that raises it (its `most` over MAX_ANSWER, rounded up)."""
    if dataset is None or not dataset.most:
        return 1
    return max(1, -(-dataset.most // MAX_ANSWER))


def _read(stream, dataset: DataSet, cutoff, deadline: float, took: str, clock, say, wait: float, final: bool = True,
          most: int | None = None, large: str = "") -> bytearray:
    """The answer's bytes, read on the download's thread a piece at a time (one of the stream's own reads at most:
    read1, so a server sending a byte now and then holds no read for longer than its socket's timeout, `wait`), the
    stop and the deadline looked at between the pieces, MAX_ANSWER bytes at most; its end noted on the cut-off (what
    is left is this machine's own). 1.104.0: `final` false for a tile with more to come (its end is not the
    download's), `most` the bytes it may be (MAX_ANSWER, as it is now, when not given); 1.108.0: `large` the words
    when it is more (a piece of a region's, or a batch's: what is left of the set's limit in all)."""
    host = dataset.host
    large = large or (_too_large(dataset) if most is None
                      else f"a tile is larger than {size_words(most)}, the most one may be")
    most = dataset.limit if most is None else most
    size = world._length(stream)
    if size is not None and size > most:
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
            if not got and final:
                cutoff.ended = True
        if not got:
            return data
        if not isinstance(got, (bytes, bytearray, memoryview)):
            raise InfrastructureError(f"{host}'s answer is not the data asked for (its stream gave "
                                      f"{type(got).__name__}, not bytes)")
        data += got
        if len(data) > most:
            raise InfrastructureError(large)
        if now - said >= world.PROGRESS_S:
            said = now
            say(f"{size_words(len(data))} of {size_words(size)} ({min(100, len(data) * 100 // size)}%)" if size
                else f"{size_words(len(data))} so far")


def _download(dataset: DataSet, fetch, agent: str, cutoff, halt: threading.Event, deadline: float, took: str, clock,
              say):
    """On the download's thread: the answer's bytes (_one), or (1.104.0) for a set of map tiles each tile's in turn,
    [(z, x, y, bytes)], a tile not there (HTTP 404) as no bytes, any other failure the whole install's."""
    if dataset.region:  # 1.108.0: a region's pieces, each read as it comes and let go
        return _region(dataset, fetch, agent, cutoff, halt, deadline, took, clock, say)
    if dataset.format == "atlas-latest" or len(dataset.queries) > 1 or dataset.also:
        return _batches(dataset, fetch, agent, cutoff, halt, deadline, took, clock, say)
    if dataset.format != "mvt":
        return _one(dataset, dataset.address(), fetch, agent, cutoff, halt, deadline, took, clock, say)
    out, last, total = [], len(dataset.tiles) - 1, 0
    for i, (z, x, y) in enumerate(dataset.tiles):
        if i:
            say(f"tile {i + 1} of {len(dataset.tiles)}")
        try:
            raw = _one(dataset, dataset._tile(z, x, y), fetch, agent, cutoff, halt, deadline, took, clock,
                       say if not i else (lambda _line: None), final=i == last, most=TILE_MOST, missing_ok=True)
        except _Missing:
            raw = bytearray()
        total += len(raw)
        if total > dataset.limit:  # 1.104.0: its answers in all, as one answer's
            raise InfrastructureError(_too_large(dataset, several=True))
        out.append((z, x, y, bytes(raw)))
    with cutoff.lock:
        if not cutoff.why:
            cutoff.ended = True
    return out


def _batches(dataset: DataSet, fetch, agent: str, cutoff, halt, deadline: float, took: str, clock, say) -> list:
    """The answers of a data set asked in several requests, one after another: RIPE Atlas's latest results, a batch
    of probes' ids a request (dataset.asked, set by the install from the probes it needs), or an omm-csv set's queries
    (HughesNet's satellites by their numbers): [(the request's number, its bytes)]. A refusal of RIPE Atlas that asks
    for credentials stops it with nothing kept: no key is ever asked for or sent."""
    asked = list(dataset.addresses() if dataset.queries or dataset.also else getattr(dataset, "asked", ()) or ())
    out, total = [], 0
    for i, address in enumerate(asked):
        if i:
            say(f"request {i + 1} of {len(asked)}")
        try:
            raw = _one(dataset, address, fetch, agent, cutoff, halt, deadline, took, clock,
                       say if not i else (lambda _line: None), final=i == len(asked) - 1,
                       most=dataset.limit - total, large=_too_large(dataset, several=True))
        except InfrastructureError as e:
            if dataset.format == "atlas-latest" and getattr(e, "code", None) in (401, 403):
                raise InfrastructureError(f"{dataset.host} refused the request: it asks for credentials, and none "
                                          "is ever sent from here. Nothing was installed.") from None
            raise
        total += len(raw)
        if total > dataset.limit:  # 1.104.0: its answers in all, as one answer's
            raise InfrastructureError(_too_large(dataset, several=True))
        out.append((i, bytes(raw)))
    with cutoff.lock:
        if not cutoff.why:
            cutoff.ended = True
    return out


def _region(dataset: DataSet, fetch, agent: str, cutoff, halt, deadline: float, took: str, clock, say) -> "_Kept":
    """1.108.0 (Monday list item 25): a region's pieces asked one after another on the download's thread, each one's
    answer read (_osm_piece) as soon as it is in and let go before the next is asked: only one piece's bytes are held,
    and what is kept of them (_Kept, its lines packed). Its answers in all are its limit at most, as one answer's."""
    kept, pieces, box, outside = _Kept(dataset), dataset.pieces(), dataset.box(), set()
    addresses, total, ways = dataset.addresses(), 0, 0
    if len(addresses) > REGION_PIECES:  # the review of 1.108.0: placed() refuses it; looked at again before asking
        raise InfrastructureError(f"its region is asked in {len(addresses)} pieces, more than {REGION_PIECES}: "
                                  "nothing was asked")
    for i, (address, piece) in enumerate(zip(addresses, pieces)):
        if i:
            say(f"piece {i + 1} of {len(addresses)}: {world._plural(ways, 'way')} read so far")
        # the review of 1.108.0: asked with what is left of its limit, so a piece is cut off as it passes it, never
        # read whole first
        raw = _one(dataset, address, fetch, agent, cutoff, halt, deadline, took, clock,
                   say if not i else (lambda _line: None), final=i == len(addresses) - 1,
                   most=dataset.limit - total, large=_too_large(dataset, several=True))
        total += len(raw)
        if total > dataset.limit:
            raise InfrastructureError(_too_large(dataset, several=True))
        ways += _osm_piece(raw, kept, dataset.host, piece, box, outside)
        del raw
    with cutoff.lock:
        if not cutoff.why:
            cutoff.ended = True
    kept.bytes = total
    kept.remarks.append(f"{world._plural(len(addresses), 'piece')} of the region asked: "
                        f"{world._plural(ways, 'way')} read")
    return kept


class _Missing(Exception):
    """A tile that is not there (HTTP 404): none of its data set's features are in it."""


def _one(dataset: DataSet, address: str, fetch, agent: str, cutoff, halt: threading.Event, deadline: float, took: str,
         clock, say, final: bool = True, most: int | None = None, missing_ok: bool = False,
         large: str = "") -> bytearray:
    """On the download's thread: one answer's bytes. One GET of `address`, each socket operation waiting its `wait`
    at most (less once less is left of the install's time); a busy server is asked once more RETRY_S later, that wait
    and the second try inside the same deadline. `most` and `large` as _read's."""
    host = dataset.host
    for again in (False, True):
        left = deadline - clock()
        if cutoff.why or halt.is_set() or left <= 0:  # stopped (while it waited to ask again), or out of time
            raise InfrastructureError(cutoff.why or took)
        say(f"asking {host} again" if again else f"asking {host} for {dataset.title}")
        wait = min(dataset.wait, left)
        try:
            stream = fetch(address, wait, agent=agent, what="a data set",
                           **({"hosts": dataset.hosts} if dataset.hosts else {}),
                           **({"encodings": ("gzip",)} if dataset.gzip else {}))
        except Exception as e:  # noqa: BLE001 - urllib's HTTPError and URLError, a refused redirect, a stand-in's own
            world._close(e)  # an HTTP error carries its answer: let go unread
            if cutoff.why:
                raise InfrastructureError(cutoff.why) from None
            code = getattr(e, "code", None)
            if code == 404 and missing_ok:
                raise _Missing() from None
            if code in BUSY and not again and dataset.retry:
                until = clock() + RETRY_S
                say(f"{host} is busy (HTTP {code}): it is asked once more in {world._seconds(RETRY_S)} s")
                _pause(until, deadline, clock, cutoff, halt)
                continue
            refused = InfrastructureError(_refusal(dataset, e, wait))
            refused.code = code  # 1.104.0: what the server answered, for a caller that tells refusals apart
            raise refused from None
        try:
            if cutoff.why:  # it came after the stop: let go unread
                raise InfrastructureError(cutoff.why)
            return _read(stream, dataset, cutoff, deadline, took, clock, say, wait, final, most, large)
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
            clock=time.monotonic, wall=time.time, accepted=None) -> dict:
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
    it (the platform's job panel). `accepted` (1.101.0): asked with nothing, once the refusals passed and the download
    is this one's, before anything is fetched or said (the plugin keeps the licence's acceptance there): what it raises
    ends the install, nothing fetched."""
    dataset = DataSet.of(dataset)
    target = _resolved(folder)
    elsewhere = foreign(target)
    if elsewhere:
        raise ValueError(elsewhere)
    if accept_licence is not True:
        raise LicenceRefused(LICENCE_FIRST)
    agent = _agent(agent)
    if dataset.region and not dataset.place:  # 1.108.0: a region's template is asked round no place
        raise ValueError(f"{dataset.title} is asked round a place: its region names none yet (set your home place, or "
                         "add a region)")
    dataset = _with_needs(dataset, target)
    held = held_back(dataset, target, wall())
    if held:
        raise ValueError(held)
    if not _INSTALLING.acquire(blocking=False):
        raise ValueError(ALREADY)
    try:
        if accepted is not None:
            accepted()
        with _STATE:
            _NOW["id"] = dataset.id
        try:
            return _install(dataset, target, fetch or world.fetch_url, world._sayer(log), cancel, agent, clock, wall,
                            float(wall()))
        except Exception as e:  # 1.109.0: every failure kept, not only a refusal (item 14: a csv.Error was not)
            if dataset.refresh or dataset.pause:  # 1.104.0: kept, so it is not refreshed by itself, and paused
                _answered(dataset, target, e, float(wall()))
            raise
    finally:
        with _STATE:
            _NOW["id"] = ""
        _INSTALLING.release()


def _answered(dataset: DataSet, target: Path, e: Exception, now: float) -> None:
    """A refused or failed download of a set refreshed by itself or paused after a 500 or 503, kept in the database
    (its HTTP code, 0 when no answer came or it failed here; 1.109.0: any failure, so a reader's own error cannot
    have it downloaded again at every look): a database that cannot keep it changes nothing of the refusal said."""
    from .infrastore import Store
    said = str(e) if isinstance(e, InfrastructureError) else f"the download failed here ({type(e).__name__}: {e})"
    try:
        Store(target).answered(dataset.id, getattr(e, "code", None) or 0, now, said)
    except Exception:  # noqa: BLE001 - the refusal is said all the same
        return
    _changed()  # every Index looks again: the table says it at once


def _answer_of(dataset: DataSet, target) -> dict | None:
    from .infrastore import Store
    try:
        return Store(target).answers().get(dataset.id)
    except Exception:  # noqa: BLE001 - a database that cannot say: none kept
        return None


def paused(dataset: DataSet, answer: Mapping | None, now: float) -> str:
    """Why nothing is asked of a data set's host now (1.104.0: CelesTrak asks for nothing for 15 minutes after a 500 or
    a 503), in words; "" when it may be asked. `answer`: its last answer that was not OK (infrastore.answers)."""
    if not dataset.pause or not answer or answer.get("code") not in PAUSE_CODES:
        return ""
    until = float(answer["at"]) + dataset.pause
    if now >= until:
        return ""
    return (f"{dataset.host} answered HTTP {answer['code']} at {world._iso(float(answer['at']))[11:16]} UTC, and its "
            f"maker asks that nothing is asked of it for {world._seconds(dataset.pause / 60)} minutes after that: it "
            f"can be asked again from {world._iso(until)[11:16]} UTC")


def held_back(dataset: DataSet, target, now: float, fetched: float | None = None, answer=False) -> str:
    """Why a data set's Update waits (1.104.0: CelesTrak's orbits, no more often than every 2 hours; nothing for its
    `pause` after a 500 or 503), in words; "" when it does not. `fetched`: when it was last downloaded, and `answer`
    its last answer that was not OK (each read from the database when not given)."""
    if dataset.pause:
        why = paused(dataset, _answer_of(dataset, target) if answer is False else answer, now)
        if why:
            return why
    if not dataset.every:
        return ""
    if fetched is None:
        from .infrastore import Store
        try:
            row = Store(target).sets().get(dataset.id)
        except Exception:  # noqa: BLE001 - a database that cannot say: not held back
            row = None
        fetched = row["fetched"] if row else None
    if fetched is None or now - fetched >= dataset.every:
        return ""
    return (f"{dataset.title} was downloaded at {world._iso(fetched)[11:16]} UTC, and its maker asks for it no more "
            f"often than every {world._seconds(dataset.every / 3600)} hours: it can be updated from "
            f"{world._iso(fetched + dataset.every)[11:16]} UTC")


def _with_needs(dataset: DataSet, target: Path) -> DataSet:
    """A data set that is read with another (its `needs`): ValueError, in words, before anything is asked, while that
    one is not installed here; an atlas-latest set given its probes' ids (`asked`: _atlas_ids) and the probes by id."""
    if not dataset.needs:
        return dataset
    from .infrastore import Store
    store = Store(target)
    if dataset.needs not in store.sets():
        raise ValueError(f"{dataset.title} is read with the data set {dataset.needs}: download that first")
    if dataset.format != "atlas-latest":
        return dataset
    probes = store.probes()
    ids = _atlas_ids(dataset, probes)
    if not ids:
        raise ValueError(f"{dataset.title} asks for {_atlas_whose(dataset)}' results, and the data set "
                         f"{dataset.needs} holds none")
    dataset = replace(dataset)  # 1.110.0: a copy for this install alone, never the Index's own (it held every probe)
    object.__setattr__(dataset, "asked", tuple(dataset.addresses(ids)))
    object.__setattr__(dataset, "probes_by_id", {p["id"]: p for p in probes})
    return dataset


def _atlas_ids(dataset: DataSet, probes) -> list[int]:
    """The probes an atlas-latest set asks the results of (1.104.0): the connected ones of the probes table, anchors
    alone or (its `ask`, "probes") every one, each with a network of its measurement's IP version (its `family`)."""
    net = "asn6" if dataset.family == 6 else "asn4"
    return sorted(p["id"] for p in probes
                  if p["connected"] and (p["anchor"] or dataset.ask == "probes") and p.get(net))


def _atlas_whose(dataset: DataSet) -> str:
    """Whose results an atlas-latest set asks, in words: "the connected anchors with IPv4"."""
    return f"the connected {'probes' if dataset.ask == 'probes' else 'anchors'} with IPv{dataset.family}"


def _composite(dataset: DataSet, target: Path, rows: Mapping) -> str:
    """What a data set gives the composite database (TopoHub's places and links, RIPE Atlas's claims and links),
    written beside the layers; the words of a line for the job, "" when nothing was given."""
    from . import composite
    places, claims, links = rows.get("places") or [], rows.get("claims") or [], rows.get("links") or []
    if not (places or claims or links):
        return ""
    c = composite.Composite(target / composite.FILE)
    try:
        source = "topohub" if dataset.format == "topohub" else "atlas"
        ok = c.record(claims=[(a, source, dataset.licence_name, said) for a, said in claims],
                      links=[(k, said, source, dataset.licence_name) for k, said in links],
                      places=[(k, source, dataset.licence_name, said) for k, said in places])
    finally:
        c.close()
    parts = [world._plural(len(x), w) for x, w in ((places, "place"), (claims, "router placed"), (links, "link")) if x]
    return (f"given to the composite database: {', '.join(parts)}" if ok
            else f"not given to the composite database: {c.problem or 'it could not be written'}")


def _install(dataset: DataSet, target: Path, fetch, say, cancel, agent: str, clock, wall, agreed: float) -> dict:
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
    if isinstance(data, _Kept):  # 1.108.0: a region's, read as its pieces came
        size = data.bytes
        say(f"{size_words(size)} downloaded and read")
        features = data.features()
        del data
    else:
        size = sum(len(t[-1]) for t in data) if isinstance(data, list) else len(data)
        say(f"{size_words(size)} downloaded: reading it")
        doc = _decoded(dataset, data)
        del data  # the answer's bytes are not held beside what is read of them
        features = _features(dataset, doc, free=True, probes=getattr(dataset, "probes_by_id", None))
        del doc
    for remark in features["remarks"]:
        say(remark)
    if not features["features"]:
        whys = _whys(features["dropped"])
        raise InfrastructureError(f"{host} answered, but every feature was left out: {whys}" if whys
                                  else f"{host} answered with no features")
    left, dropped = _left_out(features["dropped"]), sum(features["dropped"].values())
    if _asked(cancel):
        return {"said": CANCELLED, "ok": False}
    from .infrastore import Store, StoreError
    store, fetched = Store(target), float(wall())
    try:
        put = store.put(dataset, features, fetched, accepted=agreed, size=size, orbits=features.get("orbits") or (),
                        probes=features.get("probes") or ())
        composite_rows = features.get("composite") or {}
    except StoreError as e:
        raise InfrastructureError(f"{dataset.title} could not be kept: {e}. Nothing was installed, and what was "
                                  "installed before stays.") from None
    del features
    _changed()
    lines = [f"asked of {host}", f"kept in {store.path}, in place of any older copy",
             f"credited on the globe as {dataset.credit['text']}"]
    if left:
        lines.append(left)
    given = _composite(dataset, target, composite_rows)
    if given:
        lines.append(given)
    counts = {layer: c["points"] + c["lines"] for layer, c in put["counts"].items()}
    return {"said": f"installed {dataset.title}: {world._plural(put['features'], 'feature')} ({size_words(size)})",
            "ok": True, "lines": lines,
            "file": {"set": dataset.id, "path": str(store.path), "bytes": size, "downloaded": size,
                     "features": put["features"], "dropped": dropped, "fetched": _when(fetched), "layers": counts}}


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
    from .infrastore import Store, StoreError
    store = Store(target)
    try:
        there = store.remove(dataset.id)
    except StoreError as e:
        raise InfrastructureError(f"{dataset.title} could not be removed from {store.path}: {e}") from None
    older = target / f"{dataset.id}.json"  # a download made before 1.104.0, read in already: removed with it
    try:
        with _FILES:
            older.unlink()
        there = True
    except FileNotFoundError:
        pass
    except OSError as e:
        raise InfrastructureError(f"{dataset.title} could not be removed from {target}: {e}") from None
    if not there:
        return {"said": f"{dataset.title} is not installed here", "ok": True,
                "lines": [f"nothing of it is kept in {target}"]}
    _changed()
    return {"said": f"removed {dataset.title}", "ok": True,
            "lines": [f"it is removed from {store.path}: the globe no longer draws it", "it can be downloaded again"]}


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
                 "anyone." + (" Only this data set is downloaded again by itself, while this tab is open."
                              if dataset.refresh else "")),
        "fields": [{"name": "dataset", "type": "fixed", "value": dataset.id},
                   {"name": ACCEPT, "type": "accept", "title": f"Accept its licence ({dataset.licence_name})?",
                    "words": dataset.licence, "yes": "Accept it and download"}],
        "confirm": {"title": f"{verb} {dataset.title}?", "yes": "Go on",
                    "words": (f"{dataset.title} is asked of {_host_words(dataset)} in {_requests(dataset, folder)}, "
                              f"made now on your word ({_again_words(dataset)}), and kept in "
                              f"{_resolved(folder)} in place of any older copy: {size_words(dataset.size)} (an "
                              f"estimate where its maker gives none).{_limit_words(dataset)} Its progress shows in the "
                              "panel below; it "
                              f"stops by itself after {world._seconds(INSTALL_S / 60)} minutes. The request holds only "
                              f"{ASKED[dataset.format]}: nothing about this machine or its traffic. Its licence, "
                              f"first: {dataset.licence} You are asked to accept it next."
                              f"{_refresh_words(dataset)}")}}


REGION_FORM, REGION_HOOK = "world-region-", "world_region"  # 1.108.0: a region's form's id (its template's id after)
REGION_NO_PLACE = ("its region is round your home place: set LIMINAL_HOME_PLACE in this plugin's settings or install a "
                   "GeoIP file, or add a region")
REGIONS_MOST = 8  # regions added on the page, at most


def region_form(dataset) -> dict:
    """1.108.0 (the user, 2026-11-26: "Your area only", other regions added from the page): the form adding a region of
    a template, by its place (latitude, longitude and a name), asked of the plugin's world_region. Nothing is
    downloaded: the region is a row of the table, its download its own click, its size and licence said then."""
    dataset = DataSet.of(dataset)
    km = dataset.region[0] if dataset.region else 0
    return {"id": REGION_FORM + dataset.id, "hook": REGION_HOOK, "title": f"Add a region: {dataset.title}",
            "fields": [{"name": "dataset", "type": "fixed", "value": dataset.id},
                       {"name": "lat", "label": "Latitude (degrees, north +)", "type": "number", "min": -90,
                        "max": 90},
                       {"name": "lon", "label": "Longitude (degrees, east +)", "type": "number", "min": -180,
                        "max": 180},
                       {"name": "label", "label": "Its name (optional)", "type": "text", "value": ""}],
            "confirm": {"title": "Add this region?", "yes": "Add it", "words": (
                f"A region {km:g} km across round {{lat}}, {{lon}} is added to the Internet infrastructure table, its "
                f"place kept to 0.01 degree through your login ({REGIONS_MOST} regions at most). Nothing is downloaded "
                f"now: its Download… then says what is asked of {dataset.host}, how large it is and its licence "
                f"({dataset.licence_name}), and asks it only on your click.")}}


def _host_words(dataset: DataSet) -> str:
    """The host a data set is asked of, in words, and (1.104.0) the hosts its answer may be sent on to: Natural Earth's
    published link, sent on once to naciscdn.org."""
    if not dataset.hosts:
        return dataset.host
    return (f"{dataset.host} (whose link sends it on to {' or '.join(dataset.hosts)}, the only "
            f"host{'s' if len(dataset.hosts) > 1 else ''} it may go to)")


def _again_words(dataset: DataSet) -> str:
    """Whether a refused request is asked again, in words: once more a while later for a busy server, or (1.104.0:
    CelesTrak, `retry` false) never, as its maker asks."""
    if dataset.retry:
        return f"once more {_apart()} later if the server is busy"
    later = (f"; after a 500 or 503 nothing is asked of it for {world._seconds(dataset.pause / 60)} minutes"
             if dataset.pause else "")
    return f"not asked again if it refuses: its maker asks so{later}"


def _refresh_words(dataset: DataSet) -> str:
    """For a data set refreshed by itself (1.104.0), with a space before, what follows its first download; "" for any
    other."""
    if not dataset.refresh:
        return ""
    return (f" Once you accept it and it is downloaded, it is downloaded again by itself every "
            f"{world._seconds(dataset.every / 3600)} hours at the soonest, and only while the World Wide Web tab is "
            "open (never while it is closed); an answer that is not OK stops that until you update it yourself.")


def _limit_words(dataset: DataSet) -> str:
    """A data set's own limit in words for its confirmation (1.104.0), with a space before; "" for one that keeps every
    set's (MAX_ANSWER)."""
    if not dataset.most:
        return ""
    dense = (f" A dense city may be larger: past {size_words(dataset.limit)} it is refused, nothing kept."
             if dataset.region else "")  # the review of 1.108.0
    return (f" It may be up to {size_words(dataset.limit)} in all, a limit raised for this data set alone (every other "
            f"set may be {size_words(MAX_ANSWER)} at most).{dense}")


def _requests(dataset: DataSet, folder=None) -> str:
    """How many requests a download makes, in words: one, or a set of map tiles' one after another; (1.104.0) an
    atlas-latest set's one for each ATLAS_BATCH probes it asks, counted from the probes kept in `folder`."""
    if dataset.format == "atlas-latest":
        from .infrastore import Store
        try:
            probes = Store(_resolved(folder)).probes()
        except Exception:  # noqa: BLE001 - a database that cannot say: counted as none
            probes = []
        ids = _atlas_ids(dataset, probes)
        n = -(-len(ids) // ATLAS_BATCH)
        return (f"{world._plural(n, 'request')}, one after another (one for each {ATLAS_BATCH} of "
                f"{_atlas_whose(dataset)}: {len(ids):,} in the probes kept here)")
    n = len(dataset.addresses())
    return "one request" if n == 1 else f"{n} requests, one after another"


def remove_form(dataset, folder) -> dict:
    """A data set's removal form: one confirmation, saying what is removed and from where."""
    dataset = DataSet.of(dataset)
    return {"id": REMOVE_FORM + dataset.id, "hook": REMOVE_HOOK, "title": f"Remove {dataset.title}",
            "fields": [{"name": "dataset", "type": "fixed", "value": dataset.id}],
            "confirm": {"title": f"Remove {dataset.title}?", "yes": "Remove it",
                        "words": (f"It is removed from {_resolved(folder)} and the globe no longer draws it. It "
                                  "can be downloaded again." + _older_words(dataset, folder))}}


def _older_words(dataset: DataSet, folder) -> str:
    """1.104.0: where a download made before 1.104.0 left its <id>.json (read into the database once and kept), that
    it is deleted with the removal, with a space before; "" where there is none."""
    older = _resolved(folder) / f"{dataset.id}.json"
    try:
        there = older.is_file()
    except OSError:
        there = False
    return f" Its older file from before, {older.name}, kept until now, is deleted with it." if there else ""


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
            "counts": counts, "problem": "", "stand_in": doc.get("stand_in") is True}


def _version(drawn: list) -> str:
    """A layer's version: 12 hex digits of the versions of the data sets that feed it (each install's own)."""
    said = "|".join(f"{d.id}:{fact['version']}" for d, fact, _ in drawn)
    return hashlib.sha1(said.encode("utf-8", "replace")).hexdigest()[:12]


def _unpack(doc: Mapping) -> dict:
    """An older file's layers (pack's) as parse's features, to be read into the database."""
    def ints(text: str, code: str) -> array:
        values = array(code)
        values.frombytes(base64.b64decode(text))
        if sys.byteorder == "big":
            values.byteswap()
        return values
    layers: dict = {}
    for layer, entry in doc["layers"].items():
        got = {"points": [], "lines": []}
        points = entry.get("points")
        if points:
            xy = ints(points["xy"], _I32)
            if len(xy) != 2 * points["n"]:
                raise ValueError(f"its {layer} points do not read")
            got["points"] = [(xy[2 * i] / SCALE, xy[2 * i + 1] / SCALE, points["names"][i], points["subs"][i])
                             for i in range(points["n"])]
        lines = entry.get("lines")
        if lines:
            xy, offsets = ints(lines["xy"], _I32), ints(lines["offsets"], _U32)
            if len(offsets) != lines["n"] + 1 or offsets[-1] * 2 != len(xy):
                raise ValueError(f"its {layer} lines do not read")
            for i in range(lines["n"]):
                a, b = offsets[i], offsets[i + 1]
                got["lines"].append(([(xy[2 * j] / SCALE, xy[2 * j + 1] / SCALE) for j in range(a, b)],
                                     lines["names"][i]))
        layers[layer] = got
    return {"layers": layers, "features": int(doc.get("features") or 0), "dropped": int(doc.get("dropped") or 0)}


def _seconds_of(fetched: str) -> float:
    """An older file's `fetched` (ISO, UTC) as seconds since 1970; 0 when it does not read."""
    from datetime import datetime
    try:
        return datetime.fromisoformat(fetched).timestamp()
    except (TypeError, ValueError):
        return 0.0


class Index:
    """What is installed of a plugin's data sets, in `folder` (the data folder's infrastructure/ when not given): those
    of `datasets` (DataSets, or the plugin's dicts) its database holds (1.104.0: infrastore.Store), and no other. The
    folder is looked at again INDEX_S after the last look at the soonest (`clock`: monotonic, a test's own), and at once
    after an install or a removal in this process. A look reads the database's sets and counts only when its files
    changed, and no geometry. An older <id>.json of one of them (a download made before 1.104.0) is read into the
    database once, at the first look that finds it. A folder on another system's drive is never read: nothing counts
    as installed there. Thread-safe: the platform asks from a thread per request."""

    def __init__(self, folder=None, datasets=(), clock=time.monotonic, wall=time.time):
        self._given = None if folder is None else Path(folder)
        self.wall = wall  # 1.104.0: the wall clock an Update held back (a data set's `every`) is measured on
        self._base = tuple(DataSet.of(d) for d in datasets)
        ids = [d.id for d in self._base]
        twice = sorted({i for i in ids if ids.count(i) > 1})
        if twice:
            raise ValueError(f"two data sets share the id {twice[0]}: each has its own")
        # 1.108.0 (Monday list item 25): a region's template is listed as its regions (home's, those added, those
        # kept in the database), each a data set of its own (DataSet.placed)
        self._home: tuple | None = None
        self._added: tuple = ()
        self._kept_ids: frozenset = frozenset()
        self._sets = self._base
        self.clock = clock
        self._lock = threading.Lock()
        self._looked: float | None = None  # when the folder was last looked at (clock)
        self._seen = -1  # the installs and removals of this process at that look
        self._files: dict[str, dict] = {}  # each installed data set's facts, by its id
        self._answers: dict[str, dict] = {}  # 1.104.0: each set's last answer that was not OK (infrastore.answers)

    @property
    def folder(self) -> Path:
        """Where the files are: the folder given, else the data folder's infrastructure/."""
        return _resolved(self._given)

    @property
    def datasets(self) -> tuple:
        """The data sets in the table's order: the plugin's, each region's template given as its regions (1.108.0)."""
        return self._sets

    def templates(self) -> list[DataSet]:
        """1.108.0: the plugin's data sets asked round a place (their `region`)."""
        return [d for d in self._base if d.region]

    def place_regions(self, home=None, added=()) -> None:
        """1.108.0 (the user, 2026-11-26: "Your area only"): the regions each template is asked round, home's first
        (`home`: {lat, lon, label} as the globe draws it, None for none), then those added on the page (`added`:
        (lat, lon, label) each), then any other kept in the database; the folder looked at again when they changed.
        Nothing is downloaded: each is a row of the table, downloaded on its own click."""
        place = None
        if isinstance(home, Mapping):
            try:
                place = (float(home["lat"]), float(home["lon"]), _name(home.get("label")) or "home")
            except (KeyError, TypeError, ValueError):
                place = None
        given = tuple(tuple(a)[:3] for a in added or () if isinstance(a, (list, tuple)) and len(a) >= 2)
        with self._lock:
            if place == self._home and given == self._added:
                return
            self._home, self._added = place, given
            self._rebuild()
            self._looked = None

    def _rebuild(self) -> None:
        """The data sets made again from the plugin's and the regions (under the lock)."""
        out = []
        for d in self._base:
            if not d.region:
                out.append(d)
                continue
            made: dict[str, DataSet] = {}
            places = ([(self._home, "home")] if self._home else []) + [(a, "added") for a in self._added]
            for (lat, lon, *label), why in places:
                try:
                    one = d.placed(lat, lon, label[0] if label else "")
                except ValueError:
                    continue
                if one.id not in made:
                    object.__setattr__(one, "why", why)
                    made[one.id] = one
            for ident in sorted(self._kept_ids):
                found = REGION_ID.fullmatch(ident)
                if found and found.group(1) == d.id and ident not in made:
                    lat = int(found.group(3)) / 100 * (1 if found.group(2) == "n" else -1)
                    lon = int(found.group(5)) / 100 * (1 if found.group(4) == "e" else -1)
                    try:
                        one = d.placed(lat, lon, "")
                    except ValueError:
                        continue
                    object.__setattr__(one, "why", "kept")
                    made[one.id] = one
            out.extend(made.values() or [d])
        self._sets = tuple(out)

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

    def store(self):
        """The database it reads (infrastore.Store)."""
        from .infrastore import Store
        return Store(self.folder)

    def _import(self, store, kept: dict) -> dict[str, dict]:
        """Each older <id>.json of these data sets not read in yet, read into the database once (its fetched date
        kept, accepted when its file was last written), then left where it is; the problems of those that do not
        read, by their data set's id."""
        problems: dict[str, dict] = {}
        base, done = self.folder, None
        for dataset in self.datasets:
            path = base / f"{dataset.id}.json"
            try:
                found = path.stat()
            except OSError:
                continue
            stamp = f"{found.st_size}:{found.st_mtime_ns}"
            if done is None:
                done = store.imported() if store.exists() else {}
            if done.get(path.name) == stamp:
                continue
            if dataset.id in kept:  # downloaded again since: the database's copy is newer
                continue
            try:
                doc = _kept(path, dataset.id)
                features = _unpack(doc)
                store.put(dataset, features, _seconds_of(doc.get("fetched")), accepted=found.st_mtime_ns / 1e9,
                          size=0, imported=(path.name, stamp))
            except (OSError, ValueError, KeyError, TypeError, IndexError) as e:
                problems[dataset.id] = {
                    "title": dataset.title, "source": dataset.source, "licence_name": dataset.licence_name,
                    "credit": dict(dataset.credit), "fetched": "", "features": 0, "dropped": 0, "counts": {},
                    "problem": f"its file does not read ({e}): download it again", "bytes": found.st_size,
                    "version": "", "stand_in": False}
            except Exception as e:  # noqa: BLE001 - the database's own (StoreError): said, the file left as it is
                problems[dataset.id] = {
                    "title": dataset.title, "source": dataset.source, "licence_name": dataset.licence_name,
                    "credit": dict(dataset.credit), "fetched": "", "features": 0, "dropped": 0, "counts": {},
                    "problem": f"its older file could not be read in ({e})", "bytes": found.st_size, "version": "",
                    "stand_in": False}
        return problems

    def _look(self) -> dict[str, dict]:
        with self._lock:
            now, seen = self.clock(), _changes()
            if self._looked is not None and seen == self._seen and 0 <= now - self._looked < INDEX_S:
                return self._files
            self._looked, self._seen = now, seen
            if foreign(self.folder):
                self._files = {}
                return self._files
            store = self.store()
            try:
                kept = store.sets()
                ids = frozenset(i for i in kept if REGION_ID.fullmatch(i))
                if ids != self._kept_ids and self.templates():  # 1.108.0: a region kept is listed, to draw or remove
                    self._kept_ids = ids
                    self._rebuild()
                self._answers = store.answers() if any(d.refresh or d.pause for d in self.datasets) else {}
                problems = self._import(store, kept)
                if not problems and self._files and store.stamp() == getattr(self, "_stamp", None):
                    return self._files
                kept = store.sets()
                counts = store.counts() if kept else {}
            except Exception as e:  # noqa: BLE001 - a database that cannot be read: nothing installed, said
                self._files = {d.id: {"title": d.title, "source": d.source, "licence_name": d.licence_name,
                                      "credit": dict(d.credit), "fetched": "", "features": 0, "dropped": 0,
                                      "counts": {}, "problem": f"its database does not read ({e})", "bytes": 0,
                                      "version": "", "stand_in": False} for d in self.datasets}
                return self._files
            files: dict[str, dict] = {}
            for dataset in self.datasets:
                row = kept.get(dataset.id)
                if row is None:
                    if dataset.id in problems:
                        files[dataset.id] = problems[dataset.id]
                    continue
                files[dataset.id] = {
                    "title": row["title"], "source": row["source"], "licence_name": row["licence_name"],
                    "credit": {"text": row["credit_text"], "url": row["credit_url"]},
                    "fetched": world._iso(row["fetched"]), "features": row["features"], "dropped": row["dropped"],
                    "counts": counts.get(dataset.id, {}), "problem": "", "bytes": row["bytes"],
                    "version": row["version"], "stand_in": bool(row["stand_in"]),
                    "accepted": row["licence"] == dataset.licence}  # 1.104.0: the words accepted are its words now
            self._stamp = store.stamp()
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
            if layer in BY_AREA:  # 1.108.0: never read whole, so never full: each read answers so much at most
                drawn.append((dataset, fact, count))
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
        "kind", "mark", "slot", "on", "names_from", "count", "version", "credits": [{"text", "url"}], "note"}, and
        "stand_in": true for a layer fed by stand-ins for fibre alone (1.104.0: the roads, the railways). Small
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
            entry = {"id": layer, "title": title, "kind": kind, "mark": mark, "slot": slot, "on": on,
                     "names_from": names_from, "count": sum(c["points"] + c["lines"] for _, _, c in drawn),
                     "version": _version(drawn), "credits": credits, "note": note}
            if all(fact.get("stand_in") or d.stand_in for d, fact, _ in drawn):
                entry["stand_in"] = True
            if layer in LAYER_FROM:  # 1.108.0: drawn only from this zoom
                entry["from"] = LAYER_FROM[layer]
            if layer in RANKED:  # ... and each of its features from its own, asked by area and zoom
                entry["ranked"] = True
            out.append(entry)
        return out

    def layer(self, layer_id, area=None, zoom=None) -> dict:
        """One layer's geometry as the database holds it, read now and not kept: {"id", "version", "parts": [{"set",
        "credit", "points"?: {"n", "xy", "names", "subs"}, "lines"?: {"n", "offsets", "xy", "names"}}]}, a part a data
        set (pack says what `xy` and `offsets` are). LookupError when no such layer is installed here.

        1.104.0: `area` (west, south, east, north in degrees; west greater than east across the antimeridian): only
        the features crossing it; `zoom` (the globe's): below COARSE_ZOOM the lines' coarse copies, whole. Neither
        given: the whole layer, every vertex (the network's graph is made of it). "cut": true where more was there
        than an answer holds. 1.108.0: with a `zoom`, only the features drawn from twice that zoom or nearer out (each
        feature's zoom: RANKED layers'), the nearest out first; a ranked layer with none of them answers no parts."""
        from .infrastore import area_of
        box = area_of(area)
        if zoom is not None and (isinstance(zoom, bool) or not isinstance(zoom, (int, float)) or not zoom > 0):
            raise ValueError("a zoom is a number above 0")
        drawn = self._feeding(layer_id, self._look())[0] if isinstance(layer_id, str) else []
        coarse = zoom is not None and zoom < COARSE_ZOOM
        try:
            found = self.store().layer(layer_id, [d.id for d, _, _ in drawn], area=None if coarse else box,
                                       coarse=coarse, upto=None if zoom is None else 2 * float(zoom)) if drawn else {}
        except Exception:  # noqa: BLE001 - gone or changed since the look: the next look says so
            found = {}
        parts, cut = [], False
        for dataset, fact, _ in drawn:
            entry = found.get(dataset.id)
            if entry:
                cut = cut or entry.get("cut", False)
                parts.append({"set": dataset.id, "credit": dict(fact["credit"]),
                              **{part: entry[part] for part in ("points", "lines") if part in entry}})
        if not parts and (box is None or coarse) and not (drawn and zoom is not None and layer_id in RANKED):
            raise LookupError(f"no layer {world._shown(layer_id)} is installed here")
        out = {"id": layer_id, "version": _version(drawn), "parts": parts}
        if box is not None and not coarse:
            out["area"] = list(box)
        if cut:
            out["cut"] = True
        return out

    def points(self, layers, cells,
               most: int = MAX_POINTS) -> tuple[list[tuple[str, float, float, str, str]], int | None] | None:
        """The points of `layers` (their ids) in `cells` (1-degree cells, infrastore.cell_of), from the data sets
        drawn in each (as layer() draws them): ([(layer, lon, lat, name, sub)], `most` at most; the first cell not
        read whole where the read was cut, else None: Store.points) (1.106.0, Monday list item 27: the hubs a route
        passes). Read now by the cells alone and not kept; none for a layer not installed or a folder on another
        system's drive. None where the database did not read (the review of 1.106.0: a failure is not "no points",
        which a caller may keep)."""
        files = self._look()
        feeding = {layer: [d.id for d, _, _ in self._feeding(layer, files)[0]]
                   for layer in layers if isinstance(layer, str)}
        feeding = {layer: ids for layer, ids in feeding.items() if ids}
        if not feeding:
            return [], None
        try:
            return self.store().points(feeding, cells, most)
        except Exception:  # noqa: BLE001 - gone, changed or locked since the look: not read, said so
            return None

    def _held(self, dataset: DataSet) -> str:
        """Why its download or its Update waits (held_back), "" when it does not, from the look's facts."""
        fact = self._look().get(dataset.id)
        why = paused(dataset, self._answers.get(dataset.id), self.wall())  # a first download too (1.104.0)
        if why or not dataset.every or not fact or fact.get("problem"):
            return why
        return held_back(dataset, self.folder, self.wall(), _seconds_of(fact.get("fetched")), answer=None)

    def refresh_due(self) -> list[DataSet]:
        """The data sets to download again by themselves now (1.104.0, the user's "Refresh by itself"): each whose
        `refresh` is true, downloaded here before on the user's word (its licence's words the ones accepted then),
        its `every` passed since, no answer but OK since its last download (any other stops it until a download the
        user asks succeeds), nothing held back (held_back), and no download under way. Asked by the World Wide Web
        tab's page while it is open, and by nothing else: nothing is refreshed while nobody looks."""
        if installing() or self.elsewhere():
            return []
        files, now, out = self._look(), self.wall(), []
        for d in self.datasets:
            fact = files.get(d.id)
            if (not d.refresh or not fact or fact.get("problem") or not fact.get("accepted")
                    or d.id in self._answers or self._held(d)):
                continue
            out.append(d)
        return out

    def _refresh_words(self, dataset: DataSet, fact: Mapping) -> str:
        """What the table says of a set refreshed by itself: when its next refresh is due, or why it is not."""
        answer = self._answers.get(dataset.id)
        if answer:
            return (f"not refreshed by itself since {world._iso(float(answer['at']))[11:16]} UTC: "
                    f"{_text(answer['said'])[:REMARK]} Update… to try again")
        if not fact.get("accepted"):
            return "not refreshed by itself: its licence's words changed since you accepted them; Update… to read them"
        due = _seconds_of(fact.get("fetched")) + dataset.every
        return (f"refreshed by itself every {world._seconds(dataset.every / 3600)} hours while this tab is open: next "
                f"due at {world._iso(max(due, self.wall()))[11:16]} UTC")

    def region_forms(self, can: bool = True) -> list[dict]:
        """1.108.0: each region template's form adding a region (region_form); none where the page may not ask."""
        if not can or self.elsewhere():
            return []
        return [region_form(d) for d in self.templates()]

    def forms(self, can: bool = True) -> list[dict]:
        """The forms the table's buttons open: each data set's download (an update once it is installed) and, once
        installed, its removal. None when the page may not ask them (`can`), for a folder on another system's drive,
        and while a download is under way."""
        if not can or installing() or self.elsewhere():
            return []
        base, out = self.folder, []
        installed = {s["id"] for s in self.sets() if s["installed"]}
        for s in self.sets():
            dataset = self.dataset(s["id"])
            if dataset.needs and dataset.needs not in installed:
                continue  # 1.104.0: offered once the data set it is read with is here
            if dataset.region and not dataset.place:
                continue  # 1.108.0: a region's template, round no place yet: nothing to download
            if getattr(dataset, "why", "") == "added" and not (s["installed"] or s["problem"]):
                out.append(remove_form(dataset, base))  # 1.108.0: a region added, not downloaded: forgotten on Remove
            if self._held(dataset):
                if s["installed"] or s["problem"]:
                    out.append(remove_form(dataset, base))
                continue  # 1.104.0: its download or its Update waits as its maker asks
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
                if self.dataset(s["id"]).refresh:  # 1.104.0: when it is refreshed next, or why not
                    sub += "; " + self._refresh_words(self.dataset(s["id"]), self._look().get(s["id"]) or {})
                here = {"text": f"{world._plural(s['features'], 'feature')}, fetched {s['fetched'][:10]}", "sub": sub}
            else:
                here = "not downloaded"
            there = s["installed"] or bool(s["problem"])
            get = {"form": FORM + s["id"], "title": "Update…" if s["installed"] else "Download…"}
            needs = self.dataset(s["id"]).needs
            held = self._held(self.dataset(s["id"]))
            if held:
                get = {"text": "Update later" if s["installed"] else "Download later", "sub": held}
            if needs and not next((x["installed"] for x in self.sets() if x["id"] == needs), False):
                get = {"text": "needs " + next((x["title"] for x in self.sets() if x["id"] == needs), needs)}
            dataset = self.dataset(s["id"])
            if dataset.region and not dataset.place:  # 1.108.0: a template round no place yet
                get = {"text": "needs a place", "sub": REGION_NO_PLACE}
            forget = getattr(dataset, "why", "") == "added"  # a region added: removed, or forgotten, on Remove…
            rows.append([{"text": s["title"], "sub": s["about"]} if s["about"] else s["title"], s["source"],
                         s["licence_name"], here, get if offer else "",
                         {"form": REMOVE_FORM + s["id"], "title": "Remove…"} if offer and (there or forget) else ""])
        for template in self.templates():  # 1.108.0: another region, added on its own click (nothing downloaded)
            rows.append([{"text": f"Another region: {template.title}", "sub": "added to this table, then downloaded "
                          "on its own Download…"}, template.source, template.licence_name, "",
                         {"form": REGION_FORM + template.id, "title": "Add a region…"} if offer else "", ""])
        note = ("What the globe draws where the exchanges globe draws exchanges: exchange points, data centres, cable "
                "landing stations, ground stations, submarine cables, backbones and their points of presence, and "
                "telecom lines on land, as far as free-licensed data gives them. A data set is downloaded only on your "
                f"word, its size and its licence said first, and kept in {self.folder}: the globe is then drawn from "
                "that file, and asks nothing of anyone.")
        if any(d.refresh for d in self.datasets):  # 1.104.0
            note += (" Those whose Here says so are downloaded again by themselves, as their makers allow, while this "
                     "tab is open and never while it is closed.")
        older = [] if elsewhere else [f"{d.id}.json" for d in self.datasets
                                      if (self.folder / f"{d.id}.json").is_file()]
        if older:  # 1.104.0: a download made before, read into the database once
            note += (f" Downloads made before this database were read into it once, and their files are kept where "
                     f"they are ({', '.join(older)}); Remove… deletes a data set's with it.")
        if elsewhere:
            note += f" {elsewhere}. Each system's platform downloads its own."
        elif installing():
            note += " A data set is being downloaded: its progress shows in the panel."
        return {"title": TITLE, "note": note,
                "columns": [{"title": "Data set"}, {"title": "From"}, {"title": "Licence"}, {"title": "Here"},
                            {"title": ""}, {"title": ""}],
                "rows": rows, "empty": "This plugin names no data set to download."}
