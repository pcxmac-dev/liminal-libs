"""Internet infrastructure on the firewalls' globe (liminal_libs.machines.infrastructure; the user, 2026-11-16: "The
globe should have the same kind of geography associated with the exchanges globe, but the firewall globe should instead
of exchanges, have all the backbones,ibones, major internet infrastructure, (as many as possible) datacenter
locations."; 2026-11-19: "major network 'bones' need to be displayed on the map"). A plugin's dict made a data set, and
what is wrong with one said in words; small recorded Overpass, SPARQL and GeoJSON answers, and maps of networks in GML
archived as the Topology Zoo's (made here, in memory), read into layers and packed, the arrays read back; what is no
file of maps, or more than may be unpacked, refused in words; the download, on the user's word alone: its
licence first, one request over https from the data set's own host, the limit, one deadline on a stand-in clock, a
cancel that ends a wait at once, a busy server asked once more a minute later, the older file kept whenever it fails;
the Index, which reads no geometry to look; the forms' words. And the two edits of machines/world.py made for it: what
fetch_url is told (its User-Agent, what is downloaded) and WorldView.rest().

Nothing is downloaded and no process is started: the fetch is a stand-in (the real fetch_url runs over stand-in
protocols only), the folders are the test's own, and the real ones fail the test if reached."""
from __future__ import annotations

import base64
import email.message
import gzip
import http.client
import inspect
import io
import json
import math
import os
import re
import socket
import struct
import subprocess
import tarfile
import threading
import time
import urllib.error
import urllib.request
import urllib.response
import zlib
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import pytest

from liminal_libs import capture, dns, geo, layout, mounts, netpath
from liminal_libs.machines import infrastore, infrastructure, world
from liminal_libs.machines.infrastructure import (INDEX_S, INSTALL_S, LAYERS, RETRY_S, DataSet, Index,
                                                  InfrastructureError, form, install, pack, parse, remove, remove_form)
from liminal_libs.machines.world import LicenceRefused, RedirectRefused, WorldView

from test_geo import NOVEMBER, city, mmdb, needs_reader

pytestmark = pytest.mark.usefixtures("no_outside")  # the library's shared guard (tests/conftest.py), as well as ours
FETCH_URL = world.fetch_url  # the real one, run over stand-in protocols only (each test's fixture refuses it otherwise)
FOLDER_OF = infrastructure.folder  # the real one, for its own test: each test's fixture moves the layers' folder
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc).timestamp()

# -- the data sets, as a plugin names them (the plan's section 4, at stand-in hosts) -----------------------------------
OSM_CREDIT = {"text": "© OpenStreetMap contributors", "url": "https://www.openstreetmap.example/copyright"}
ODBL = ("OpenStreetMap's data is free under the Open Database License 1.0: it may be copied, used and adapted as long "
        "as OpenStreetMap and its contributors are credited, and a changed copy passed on to others stays under the "
        "same licence.")
OSM = {"format": "overpass", "url": "https://overpass.example/api/interpreter", "licence_name": "ODbL 1.0",
       "source": "OpenStreetMap, through the Overpass API", "licence": ODBL, "credit": OSM_CREDIT}
CENTRES = {**OSM, "id": "osm-datacentres", "title": "Data centres", "size": 2_000_000, "wait": 190,
           "about": "about 5,000 sites, and its few exchange points",
           "query": '[out:json][timeout:180];(nwr["telecom"="data_center"];nwr["building"="data_center"];'
                    'nwr["telecom"="internet_exchange"];);out tags center qt;'}
CABLES = {**OSM, "id": "osm-cables", "title": "Submarine cables and landing stations", "size": 3_000_000, "wait": 190,
          "about": "about 1,100 cable ways, 60 stations",
          "query": '[out:json][timeout:180];(way["seamark:type"="cable_submarine"]'
                   '["seamark:cable_submarine:category"~"^(fibre_optic|telephone)$"];'
                   'way["communication"="line"]["location"="underwater"];'
                   'way["communication"="line"]["submarine"="yes"];);'
                   'out tags geom qt;nwr["telecom"="cable_landing_station"];out tags center qt;'}
LAND = {**OSM, "id": "osm-lines", "title": "Telecom lines on land (partial)", "size": 20_000_000, "wait": 310,
        "about": "about 19,000 ways; no country is complete",
        "query": '[out:json][timeout:300];(way["communication"="line"]["location"!="underwater"]["submarine"!="yes"];'
                 'way["telecom"="line"];way["telecom"="cable"];);out tags geom qt;'}
WIKIDATA = {"id": "wikidata", "title": "Exchange points, ground stations and teleports", "format": "sparql",
            "url": "https://query.wikidata.example/sparql", "source": "Wikidata", "licence_name": "CC0",
            "licence": "Wikidata's structured data is in the public domain (Creative Commons Zero).",
            "credit": {"text": "Wikidata", "url": "https://www.wikidata.example/wiki/Wikidata:Licensing"},
            "size": 200_000, "about": "about 300 places, some data centres among them",
            "query": 'SELECT ?item ?itemLabel ?kind ?coord ?operatorLabel WHERE { VALUES ?kind { wd:Q1433061 '
                     'wd:Q671224 wd:Q1349167 wd:Q10379228 } ?item wdt:P31 ?kind . ?item wdt:P625 ?coord . OPTIONAL { '
                     '?item wdt:P137 ?operator } SERVICE wikibase:label { bd:serviceParam wikibase:language "en" } }'}
# the request the plugins are given for EMODnet's six telecom cable layers (progress/fw-infrastructure.md), at a
# stand-in host: one GetFeature of WFS 1.1.0, GeoJSON, longitude first (srsName=EPSG:4326)
CABLE_TYPES = ("emodnet:bshcontiscables,emodnet:cicacables,emodnet:shomcables,emodnet:sigcables,emodnet:maltacables,"
               "emodnet:ukfibrecables")
ROUTES = {"id": "emodnet-cables", "title": "Telecom cable routes in European waters", "format": "geojson",
          "url": "https://ows.emodnet.example/geoserver/emodnet/wfs", "source": "EMODnet Human Activities",
          "query": f"service=WFS&version=1.1.0&request=GetFeature&typeName={CABLE_TYPES}&outputFormat=application/json"
                   "&srsName=EPSG:4326",
          "licence_name": "CC BY 4.0", "licence": "EMODnet's data is free under Creative Commons Attribution 4.0.",
          "credit": {"text": "EMODnet Human Activities; data originator Cogea Srl",
                     "url": "https://emodnet.example/en/"},
          "size": 3_000_000, "wait": 120, "about": "the actual routes, from six national sources"}
# a file of maps of networks in GML, as the plugins are given the Internet Topology Zoo's gml.tar.gz (progress/
# globe-datasets.md), at a stand-in host: the file alone is asked, no query
ZOO = {"id": "topology-zoo", "title": "Backbone networks, about 2010-2011", "format": "gml",
       "url": "https://raw.zoo.example/InternetTopologyZoo/main/gml.tar.gz",
       "source": "the Internet Topology Zoo, through its repository", "licence_name": "CC BY 4.0",
       "licence": "The Internet Topology Zoo's maps are free under Creative Commons Attribution 4.0.",
       "credit": {"text": "Internet Topology Zoo, CC BY 4.0", "url": "https://zoo.example/InternetTopologyZoo"},
       "size": 348_613, "about": "each network's newest map: its points of presence and links"}
EVERY = (CENTRES, CABLES, LAND, WIKIDATA, ROUTES, ZOO)
AT = {d["id"]: DataSet.of(d).address() for d in EVERY}  # the one address each is asked at
# the formats as a refusal says them (1.104.0: overpass, sparql, geojson, gml, ourairports, geonames, then the globe's)
FORMAT_WORDS = f"{', '.join(infrastructure.FORMATS[:-1])} or {infrastructure.FORMATS[-1]}"

# -- small recorded answers, in their makers' shapes -------------------------------------------------------------------
OSM3S = {"timestamp_osm_base": "2026-11-16T21:58:00Z",
         "copyright": "The data included in this document is from www.openstreetmap.org. The data is made available "
                      "under ODbL."}


def overpass(*elements, **more) -> bytes:
    """An Overpass answer as its server writes one: {lat, lon} objects, lat first."""
    return json.dumps({"version": 0.6, "generator": "Overpass API 0.7.62.5 1bd436f1", "osm3s": OSM3S,
                       "elements": list(elements), **more}, indent=1).encode()


def way(ident: int, vertices, tags: dict) -> dict:
    """A way printed with `out tags geom`: its bounds and its geometry, each vertex {lat, lon}."""
    lons, lats = [lon for lon, _ in vertices], [lat for _, lat in vertices]
    return {"type": "way", "id": ident,
            "bounds": {"minlat": min(lats), "minlon": min(lons), "maxlat": max(lats), "maxlon": max(lons)},
            "geometry": [{"lat": lat, "lon": lon} for lon, lat in vertices], "tags": tags}


AMS = {"type": "node", "id": 2716818205, "lat": 52.3033, "lon": 4.9394,
       "tags": {"telecom": "data_center", "name": "AMS1", "operator": "Example Colocation BV"}}
CENTRES_ANSWER = overpass(
    AMS,
    {"type": "way", "id": 28431521, "center": {"lat": 50.1196, "lon": 8.7354},  # no name: its operator's stands for it
     "tags": {"building": "data_center", "operator": "Example Rechenzentrum GmbH", "owner": "Example Holding"}},
    {"type": "relation", "id": 1234567, "center": {"lat": 39.0169, "lon": -77.4589},
     "tags": {"telecom": "data_center", "type": "multipolygon", "name": "IAD Campus"}},
    {"type": "node", "id": 3001, "lat": 50.1109, "lon": 8.6821,
     "tags": {"telecom": "internet_exchange", "name": "Example-IX Frankfurt",
              "operator": "Example-IX Management GmbH"}},
    {**AMS, "id": 3002},  # mapped twice: a repeat
    {"type": "node", "id": 3003, "lat": 91.5, "lon": 4.9, "tags": {"telecom": "data_center", "name": "nowhere"}},
    {"type": "way", "id": 3004, "tags": {"building": "data_center"}},  # no place at all
    {"type": "node", "id": 3005, "lat": 48.0, "lon": 2.0, "tags": {"telecom": "exchange"}},  # a telephone exchange
    {"type": "way", "id": 3006, "bounds": {"minlat": 48.0, "minlon": 2.0, "maxlat": 48.2, "maxlon": 2.4},
     "tags": {"telecom": "data_center", "name": "Bounds DC"}})  # no centre printed: the middle of its bounds
CHANNEL = [(1.3356, 51.1279), (1.45, 51.1), (1.6, 51.05), (1.8528, 50.9694)]
CABLES_ANSWER = overpass(
    way(500, CHANNEL, {"seamark:type": "cable_submarine", "seamark:cable_submarine:category": "fibre_optic",
                       "name": "Channel Example 1"}),
    way(501, [(-5.0, 50.0), (-5.001, 50.001), (-5.01, 50.005), (-5.03, 50.0), (-5.031, 50.0005), (-5.0315, 50.001)],
        {"communication": "line", "location": "underwater", "operator": "Example Telecom"}),  # vertices metres apart
    way(502, [(10.0, 54.5), (10.5, 54.6)], {"communication": "line", "submarine": "yes"}),
    way(503, CHANNEL, {"seamark:type": "cable_submarine", "name": "the same cable, mapped twice"}),
    way(504, [(2.0, 51.0)], {"communication": "line", "location": "underwater"}),  # one vertex: no line
    way(505, [(2.0, 51.0), (2.5, 123.0)], {"communication": "line", "location": "underwater"}),  # off the globe
    way(506, [(3.0, 3.0), (3.001, 3.001)], {"communication": "line", "submarine": "yes", "name": "a short one"}),
    {"type": "node", "id": 600, "lat": 50.83, "lon": -4.55,
     "tags": {"telecom": "cable_landing_station", "name": "Bude"}},
    {"type": "way", "id": 601, "center": {"lat": 43.3, "lon": 5.37},
     "tags": {"telecom": "cable_landing_station", "building": "yes", "operator": "Example Carrier"}},
    way(507, [(8.0, 47.0), (8.1, 47.1)], {"telecom": "line", "name": "a line on land"}))
ENTITY = "http://www.wikidata.example/entity/"


def binding(item: str, label: str, kind: str, coord: str | None, operator: str | None = None) -> dict:
    """One row of a SPARQL answer, as the query service writes it."""
    row = {"item": {"type": "uri", "value": ENTITY + item}, "kind": {"type": "uri", "value": ENTITY + kind},
           "itemLabel": {"xml:lang": "en", "type": "literal", "value": label}}
    if coord is not None:
        row["coord"] = {"datatype": "http://www.opengis.example/ont/geosparql#wktLiteral", "type": "literal",
                        "value": coord}
    if operator is not None:
        row["operatorLabel"] = {"xml:lang": "en", "type": "literal", "value": operator}
    return row


IX = binding("Q100", "Example-IX Frankfurt", "Q1433061", "Point(8.6821 50.1109)", "Example-IX Management GmbH")
SPARQL_ANSWER = json.dumps({"head": {"vars": ["item", "itemLabel", "kind", "coord", "operatorLabel"]},
                            "results": {"bindings": [
    IX,
    binding("Q101", "Example Data Center", "Q671224", "Point(-121.1838 45.5946)"),
    binding("Q102", "Goonhilly Satellite Earth Station", "Q1349167", "Point(-5.1819 50.0481)",
            "Goonhilly Earth Station Ltd"),
    binding("Q103", "Fucino Space Centre", "Q10379228", "Point(13.6019 41.9783)"),
    binding("Q104", "Q104", "Q1349167", "Point(30.5 -20.25)", "Q555"),  # no label in English: its id stands in
    {**IX, "operatorLabel": {"type": "literal", "value": "another operator of the same exchange"}},  # a repeat
    binding("Q105", "A landing point", "Q5015682", "Point(1.0 2.0)"),  # a kind not asked for
    binding("Q106", "A dish on the Moon", "Q1349167", f"<{ENTITY}Q405> Point(23.47 0.67)"),  # another globe's
    binding("Q107", "Past the edge", "Q671224", "Point(200.0 10.0)"),
    binding("Q108", "No place", "Q671224", None)]}}).encode()
GEOJSON_ANSWER = json.dumps({"type": "FeatureCollection", "features": [
    {"type": "Feature", "id": "bshcontiscables.1", "geometry_name": "the_geom",
     "geometry": {"type": "MultiLineString",
                  "coordinates": [[[7.9, 54.3], [8.1, 54.35], [8.4, 54.4]], [[8.5, 54.5], [8.9, 54.6]]]},
     "properties": {"featureid": 1, "status": "in use", "name_": "Example Atlantic 1", "shape_leng": 1.2}},
    {"type": "Feature", "id": "ukfibrecables.7", "geometry_name": "the_geom",
     "geometry": {"type": "LineString", "coordinates": [[-3.2, 53.4, 0.0], [-3.6, 53.6, 0.0]]},
     "properties": {"PIPE_NAME": "Example Irish Sea link", "operator": "Example Operator plc"}},
    {"type": "Feature", "id": "shomcables.3",
     "geometry": {"type": "LineString", "coordinates": [[-1.6, 49.7], [-1.9, 49.9]]},
     "properties": {"catcbl": 1, "operator": "Example Operator plc"}},  # no name: its operator's
    {"type": "Feature", "id": "maltacables.1",
     "geometry": {"type": "LineString", "coordinates": [[14.5, 35.9], [15.0, 36.2]]}, "properties": {}},
    {"type": "Feature", "id": "x.1", "geometry": {"type": "Point", "coordinates": [1.0, 2.0]},
     "properties": {"name": "a point"}},
    {"type": "Feature", "id": "x.2", "geometry": None, "properties": {}},
    {"type": "Feature", "id": "x.3", "geometry": {"type": "MultiLineString", "coordinates": []}, "properties": {}}],
    "totalFeatures": 7, "numberMatched": 7, "numberReturned": 7, "timeStamp": "2026-11-17T06:40:00.000Z",
    "crs": {"type": "name", "properties": {"name": "urn:ogc:def:crs:EPSG::4326"}}}).encode()
# a network's map as the Topology Zoo's toolset wrote them through NetworkX (Himsolt's GML: key value, lists in
# brackets): its own values, then its nodes (each with its place where one was found, Internal 0 for another network's,
# hyperedge for a shared medium) and its edges; a comment and a node's graphics, which a reader reads past
AARNET = """# a map of a network
graph [
  DateObtained "22/10/10"
  GeoLocation "Australia"
  Network "AARNet"
  Type "REN"
  Backbone 1
  label "Aarnet"
  NetworkDate "2010_08"
  DateYear "2010"
  node [
    id 0
    label "Sydney1"
    Country "Australia"
    Longitude 151.20732
    Internal 1
    Latitude -33.86785
  ]
  node [
    id 1
    label "Sydney2"
    Longitude 151.20732
    Internal 1
    Latitude -33.86785
    graphics [ x 1.0 y 2.0 Label "a drawing's own" ]
  ]
  node [
    id 2
    label "Perth"
    Longitude 115.86048
    Internal 1
    Latitude -31.95224
  ]
  node [
    id 3
    label "Canberra &#38; ACT"
    Longitude 149.12807
    Internal 1
    Latitude -35.28346
  ]
  node [
    id 4
    label "Telstra"
    Internal 0
    Longitude 151.2
    Latitude -33.9
  ]
  node [
    id 5
    label "Somewhere"
    Internal 1
  ]
  node [
    id 6
    label "Nowhere"
    Longitude NAN
    Latitude -12.0
  ]
  node [
    id 7
    label "Ring"
    hyperedge 1
    Longitude 151.2
    Latitude -33.9
  ]
  node [
    label "Darwin"
    Longitude 130.84185
    Latitude -12.46113
  ]
  edge [
    source 0
    target 1
  ]
  edge [
    source 0
    target 2
    LinkLabel "10 Gbps"
  ]
  edge [
    source 2
    target 0
  ]
  edge [
    source 3
    target 0
  ]
  edge [
    source 2
    target 4
  ]
  edge [
    source 2
    target 999
  ]
  edge [
    source 7
    target 0
  ]
  edge [
    target 2
  ]
]
"""


def gml(network: str | None, nodes=(), edges=(), **values) -> str:
    """A network's map in GML, as the Topology Zoo's are written: its own values, then each node and each edge."""
    def value(v) -> str:
        return f'"{v}"' if isinstance(v, str) else str(v)
    lines = ["graph ["] + ([f'  Network "{network}"'] if network is not None else [])
    lines += [f"  {k} {value(v)}" for k, v in values.items()]
    for node in nodes:
        lines += ["  node ["] + [f"    {k} {value(v)}" for k, v in node.items()] + ["  ]"]
    for a, b in edges:
        lines += ["  edge [", f"    source {a}", f"    target {b}", "  ]"]
    return "\n".join(lines + ["]", ""])


def pop(ident: int, label: str, lon: float, lat: float, **more) -> dict:
    return {"id": ident, "label": label, "Longitude": lon, "Latitude": lat, "Internal": 1, **more}


# a network's maps over the years, named by their year (the newest drawn); one whose name has no year (a network of its
# own), written in Latin-1 as older tools wrote GML; history; one that does not read
GEANT_2009 = gml("GEANT", [pop(0, "London", -0.12574, 51.50853), pop(1, "Paris", 2.3488, 48.85341)], [(0, 1)])
GEANT_2012 = gml("G&#201;ANT", [pop(0, "London", -0.12574, 51.50853), pop(1, "Amsterdam", 4.88969, 52.37403),
                                pop(2, "Zürich", 8.55, 47.36667)], [(1, 0), (0, 2)], DateYear="2012")
PIONIER = gml("Pionier", [pop(0, "Warszawa", 21.01178, 52.22977), pop(1, "Kraków", 19.93658, 50.06143)], [(0, 1)],
              Layer="IP")
ARPANET = gml("ARPANET", [pop(0, "UCLA", -118.44, 34.07), pop(1, "SRI", -122.18, 37.46)], [(0, 1)])
NSFNET = gml("NSFNET T1", [pop(0, "Ithaca", -76.5, 42.44), pop(1, "Boulder", -105.27, 40.01)], [(0, 1)],
             DateYear="1991")
MAPS = {"gml/Aarnet.gml": AARNET, "gml/Geant2009.gml": GEANT_2009, "gml/Geant2012.gml": GEANT_2012,
        "gml/Pionierl3.gml": PIONIER, "gml/Arpanet19706.gml": ARPANET, "gml/Arpanet19728.gml": ARPANET,
        "gml/Nsfnet.gml": NSFNET, "gml/Broken.gml": 'graph [ Network "Broken" node [ id 0 ',
        "gml/._Aarnet.gml": b"\x00\x05\x16\x07\x00\x02\x00\x00Mac OS X        ",  # macOS's copy of its metadata
        "README.md": "The Internet Topology Zoo"}


def archive(files: dict, gzipped: bool = True) -> bytes:
    """Maps in a tar archive as the Topology Zoo's gml.tar.gz holds them (a folder, then its files: bytes, or text
    written in Latin-1), gzipped."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        folder = tarfile.TarInfo("gml")
        folder.type, folder.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(folder)
        for name, body in files.items():
            data = body if isinstance(body, bytes) else body.encode("latin-1")
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 1_316_000_000
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(out.getvalue(), mtime=0) if gzipped else out.getvalue()


ZOO_ANSWER = archive(MAPS)
TOOK = "the download took more than 600 s, the most an install may take, so it was stopped: nothing was installed"


# -- stand-ins ---------------------------------------------------------------------------------------------------------
class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class Downloads:
    """The downloads as a stand-in: each address asked for with what it was told (the socket's timeout; the User-Agent
    and what is downloaded), and what it gives: bytes, or an error raised; a list gives its next each time it is
    asked."""

    def __init__(self, answers):
        self.answers, self.asked = dict(answers), []

    def __call__(self, url, timeout, **said):
        self.asked.append((url, timeout, said))
        got = self.answers.get(url, urllib.error.HTTPError(url, 404, "Not Found", {}, None))
        if isinstance(got, list):
            got = got.pop(0)
        if isinstance(got, BaseException):
            raise got
        return io.BytesIO(got) if isinstance(got, bytes) else got


def busy(url: str, code: int = 504) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, http.client.responses[code], {}, None)


class Held:
    """A download's connection socket as a stand-in, its server silent: what reads on it is held until the socket is
    shut (shutdown(), as an install shuts its download's sockets)."""

    def __init__(self):
        self.shut, self.entered = threading.Event(), threading.Event()
        self.how: list[int] = []

    def shutdown(self, how):
        self.how.append(how)
        self.shut.set()

    def fetch(self, url, timeout, **said):
        """A fetch that hands this socket to the install it runs for, as the real https connection does, and is held."""
        world._handed(self)
        self.entered.set()
        self.shut.wait(10)
        raise urllib.error.URLError(ConnectionAbortedError("the connection's socket was shut"))


class Body(io.BytesIO):
    """An answer's body as http.client gives it: once closed, a read gives nothing; the reads while open counted."""

    def __init__(self, data=b""):
        super().__init__(data)
        self.reads = 0

    def read(self, n=-1):
        if self.closed:
            return b""
        self.reads += 1
        return super().read(n)

    def read1(self, n=-1):
        if self.closed:
            return b""
        self.reads += 1
        return super().read1(n)


class Web(urllib.request.HTTPSHandler):
    """https as a stand-in: each address asked answered from `pages` ({url: (code, headers, body)}, a list giving its
    next each time), else 404; the User-Agent each request carried kept. Nothing is connected."""

    def __init__(self, pages, came_from=None):
        super().__init__()
        self.pages, self.asked, self.agents, self.bodies, self.came_from = dict(pages), [], [], [], came_from

    def https_open(self, req):
        self.asked.append(req.full_url)
        self.agents.append(req.get_header("User-agent"))
        page = self.pages.get(req.full_url, (404, {}, b""))
        code, headers, data = page.pop(0) if isinstance(page, list) else page
        said = email.message.Message()
        for k, v in headers.items():
            said[k] = v
        self.bodies.append(Body(data))
        answer = urllib.response.addinfourl(self.bodies[-1], said, self.came_from or req.full_url, code)
        answer.msg = http.client.responses.get(code, "")
        return answer


class Plain(urllib.request.HTTPHandler):
    """http as a stand-in that fails the test when a download reaches it."""

    def http_open(self, req):
        raise AssertionError(f"a download went to {req.full_url}")


def over(web):
    """The real fetch_url over stand-in protocols, as install calls its fetch."""
    return lambda url, timeout, **said: FETCH_URL(url, timeout, handlers=(web, Plain()), **said)


class Feed:
    """A capture as a stand-in, pulled as a Watcher pulls one: opened, nothing yet, closed."""

    def __init__(self):
        self.packets, self.address = deque(), "192.168.1.20"

    def open(self):
        pass

    def next(self):
        return None

    def close(self):
        pass


def wait_for(condition, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


def downloading() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.endswith("-layer-download")]


def background(call, *args, **kwargs) -> tuple[threading.Thread, dict]:
    """`call` on a thread of its own: (the thread, where its answer or its error goes)."""
    out: dict = {}

    def run() -> None:
        try:
            out["answer"] = call(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001 - the test looks at it
            out["error"] = e
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, out


def ints(text: str, code: str = "i") -> list[int]:
    """A packed array read back: base64 of little-endian 4-byte integers (i: signed, I: not)."""
    raw = base64.b64decode(text)
    return list(struct.unpack(f"<{len(raw) // 4}{code}", raw))


def places(part: dict) -> list[tuple[float, float]]:
    """A part's `xy` read back as (longitude, latitude) in degrees."""
    xy = ints(part["xy"])
    return [(xy[i] / 100_000, xy[i + 1] / 100_000) for i in range(0, len(xy), 2)]


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch, tmp_path):
    """Nothing real is reached: no process started, nothing fetched, no socket connected, no capture, no name server,
    not this machine's data folder (each reach is noted, so one inside a thread is seen too). No download's thread is
    left after a test, and none is under way."""
    reached: list[str] = []

    def refusing(name):
        def refuse(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"a test reached the real {name}")
        return refuse
    for module, name in ((subprocess, "Popen"), (urllib.request, "urlopen"), (world, "fetch_url"),
                         (socket, "create_connection"), (capture, "load_pcap"), (netpath, "lan_address"),
                         (world, "route_address"), (dns, "query")):
        monkeypatch.setattr(module, name, refusing(name))
    monkeypatch.setattr(layout, "data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(infrastructure, "folder", lambda: tmp_path / "data" / "infrastructure")
    yield
    assert wait_for(lambda: downloading() == []), "a download's thread was left"
    assert wait_for(lambda: not [t for t in threading.enumerate() if t.name == "traffic-watcher"])
    assert not infrastructure.installing() and reached == []


def got(dataset, folder, answer: bytes, **more) -> dict:
    """A data set installed from a recorded answer, its licence accepted."""
    more.setdefault("wall", Clock(NOW))
    return install(dataset, folder, accept_licence=True, fetch=Downloads({AT[dataset["id"]]: answer}), clock=Clock(),
                   **more)


def refused(dataset, folder, answer, **more) -> str:
    """Why an install over a stand-in fetch installed nothing, in its own words."""
    more.setdefault("clock", Clock())
    with pytest.raises(InfrastructureError) as said:
        install(dataset, folder, accept_licence=True, fetch=Downloads({AT[dataset["id"]]: answer}), **more)
    return str(said.value)


# -- a plugin's dict as a data set -------------------------------------------------------------------------------------
def test_a_plugins_dict_is_a_data_set_and_each_format_has_its_one_address():
    centres = DataSet.of(CENTRES)
    assert (centres.id, centres.title, centres.format, centres.host) == ("osm-datacentres", "Data centres", "overpass",
                                                                         "overpass.example")
    assert (centres.size, centres.wait, centres.licence_name, centres.source) == (
        2_000_000, 190.0, "ODbL 1.0", "OpenStreetMap, through the Overpass API")
    assert centres.credit == OSM_CREDIT and centres.licence == ODBL and centres.about.startswith("about 5,000 sites")
    assert DataSet.of(centres) is centres  # a data set as it is
    # (review, low) frozen, so it hashes: a key, a set's member; its credit still compares
    assert hash(DataSet.of(dict(CENTRES))) == hash(centres) and {centres, DataSet.of(CENTRES)} == {centres}
    assert DataSet.of({**CENTRES, "credit": {"text": "OSM"}}) != centres
    assert DataSet.of(WIKIDATA).wait == 60.0 == infrastructure.READ_S  # a data set that names no wait
    # the query travels in the address, every character of it escaped: one GET, and nothing else is sent
    assert AT["osm-datacentres"] == (
        "https://overpass.example/api/interpreter?data=%5Bout%3Ajson%5D%5Btimeout%3A180%5D"
        "%3B%28nwr%5B%22telecom%22%3D%22data_center%22%5D%3Bnwr%5B%22building%22%3D%22data_"
        "center%22%5D%3Bnwr%5B%22telecom%22%3D%22internet_exchange%22%5D%3B%29%3Bout%20tags"
        "%20center%20qt%3B")
    assert AT["wikidata"].startswith("https://query.wikidata.example/sparql?format=json&query=SELECT%20%3Fitem%20")
    assert " " not in AT["wikidata"] and "{" not in AT["wikidata"]
    # a GeoJSON source's query is sent as it is written (a WFS's own names and values); without one, the address alone
    assert AT["emodnet-cables"] == (
        "https://ows.emodnet.example/geoserver/emodnet/wfs?service=WFS&version=1.1.0&request=GetFeature&typeName="
        "emodnet:bshcontiscables,emodnet:cicacables,emodnet:shomcables,emodnet:sigcables,emodnet:maltacables,"
        "emodnet:ukfibrecables&outputFormat=application/json&srsName=EPSG:4326")
    assert DataSet.of({**ROUTES, "query": ""}).address() == "https://ows.emodnet.example/geoserver/emodnet/wfs"
    # a file of maps is asked at its address alone, needing no query (one given is sent as it is written)
    zoo = DataSet.of(ZOO)
    assert (zoo.format, zoo.query, zoo.host, zoo.wait) == ("gml", "", "raw.zoo.example", infrastructure.READ_S)
    assert AT["topology-zoo"] == "https://raw.zoo.example/InternetTopologyZoo/main/gml.tar.gz" == ZOO["url"]
    assert DataSet.of({**ZOO, "query": "raw=true"}).address() == ZOO["url"] + "?raw=true"
    for said in EVERY:  # each of the plan's shapes is one
        assert DataSet.of(said).id == said["id"]


def test_what_is_wrong_with_a_plugins_data_set_is_said_in_words():
    for change, words in (
            ({"url": "http://overpass.example/api/interpreter"},
             "the data set osm-datacentres is downloaded over https only, not from http://overpass.example"),
            ({"url": "ftp://overpass.example/x"}, "over https only, not from ftp://overpass.example"),
            ({"url": "https://me:secret@overpass.example/x"}, "over https only"),  # nothing of anyone's in an address
            ({"url": "https://overpass.example/api?x=1"}, "holds no space and no query of its own"),
            ({"url": ""}, "the data set osm-datacentres names no address"),
            ({"licence": "  "}, "names no licence: its words are shown and accepted before the download"),
            # (review, low) words the user accepts, and the credit the licence asks for, are never cut short
            ({"licence": "x" * 2001}, "the data set osm-datacentres's licence is 2,000 characters at most: the words "
                                      "the user accepts are shown whole"),
            ({"credit": {"text": "x" * 161}}, "the data set osm-datacentres's credit is 160 characters at most: it is "
                                              "drawn whole wherever its features are"),
            ({"licence_name": None}, "names no short name for its licence"),
            ({"credit": {}}, "names no credit: its text is drawn wherever its features are"),
            ({"credit": "© OpenStreetMap contributors"}, "names no credit"),
            ({"credit": {"text": "OSM", "url": "http://www.openstreetmap.example/copyright"}},
             "credit links an https address, not http://www.openstreetmap.example"),
            ({"format": "kml"}, f"format is {FORMAT_WORDS}, not 'kml'"),
            ({"format": None}, f"format is {FORMAT_WORDS}, not None"),
            ({"size": 0}, "says no size: its bytes are said before it is downloaded"),
            ({"size": "2 MB"}, "says no size"), ({"size": True}, "says no size"),
            ({"query": ""}, "the data set osm-datacentres names no query"),
            ({"query": "x" * 4001}, "query is text, 4,000 characters at most"),
            ({"title": ""}, "names no title"), ({"source": ""}, "names no source"),
            ({"wait": 0}, "wait is a number of seconds from 1 to 600"), ({"wait": 601}, "from 1 to 600"),
            ({"wait": "190"}, "not '190'"), ({"wait": float("nan")}, "from 1 to 600"),
            ({"id": "OSM Datacentres"}, "a data set's id is lowercase letters, digits and dashes"),
            ({"id": "remove-me"}, "not beginning with remove"), ({"id": None}, "not None")):
        with pytest.raises(ValueError, match=re.escape(words)):
            DataSet.of({**CENTRES, **change})
    for wrong in ({**ROUTES, "query": "service=WFS&typeName=a b"}, {**ZOO, "query": "raw=1#top"}):
        with pytest.raises(ValueError, match="it holds no space and no #"):
            DataSet.of(wrong)
    with pytest.raises(ValueError, match="a data set is a plugin's dict .*, not str"):
        DataSet.of("osm-datacentres")
    with pytest.raises(ValueError, match="two data sets share the id osm-datacentres"):
        Index(datasets=[CENTRES, {**CABLES, "id": "osm-datacentres"}])


def test_the_layers_are_kept_in_the_data_folder_each_systems_own(tmp_path, monkeypatch):
    assert FOLDER_OF() == tmp_path / "data" / "infrastructure" and infrastructure.FOLDER == "infrastructure"
    assert infrastructure.foreign() == "" and infrastructure.foreign(tmp_path / "anywhere") == ""
    theirs = tmp_path / "theirs"
    monkeypatch.setattr(mounts, "foreign", lambda path, table=None: str(path).startswith(os.path.realpath(theirs)))
    words = infrastructure.foreign(theirs / "infrastructure")
    assert words.startswith("Keeping the infrastructure layers: ") and words.endswith(
        "is on another system's drive, and that is done from that system, not from here")


# -- an answer's features ----------------------------------------------------------------------------------------------
def test_an_overpass_answer_is_read_by_its_tags_into_points_and_lines():
    centres = parse(CENTRES, CENTRES_ANSWER)
    assert list(centres["layers"]) == ["exchanges", "datacentres"]  # in the layers' own order
    assert centres["layers"]["datacentres"] == {"lines": [], "points": [
        (4.9394, 52.3033, "AMS1", "Example Colocation BV"),  # a node: its own place
        # a way: its centre; no name: its operator's
        (8.7354, 50.1196, "Example Rechenzentrum GmbH", "Example Holding"),
        (-77.4589, 39.0169, "IAD Campus", ""),  # a relation: its centre
        (2.2, 48.1, "Bounds DC", "")]}  # no centre printed: the middle of its bounds
    assert centres["layers"]["exchanges"]["points"] == [(8.6821, 50.1109, "Example-IX Frankfurt",
                                                         "Example-IX Management GmbH")]
    assert centres["features"] == 5 and centres["remarks"] == []
    assert centres["dropped"] == {"repeated": 1, "off the globe": 2, "of no kind asked for": 1}
    cables = parse(CABLES, CABLES_ANSWER)
    assert list(cables["layers"]) == ["landings", "cables", "lines"]
    assert cables["layers"]["cables"]["lines"] == [
        (CHANNEL, "Channel Example 1"),  # seamark:type=cable_submarine: every vertex kept, each 0.02 degrees on or more
        # location=underwater: named by its operator; a vertex nearer than 0.02 degrees to the last kept is left out,
        # its end kept where it is
        ([(-5.0, 50.0), (-5.03, 50.0), (-5.0315, 50.001)], "Example Telecom"),
        ([(10.0, 54.5), (10.5, 54.6)], ""),  # submarine=yes
        ([(3.0, 3.0), (3.001, 3.001)], "a short one")]  # two vertices a hundred metres apart are still a line
    assert cables["layers"]["lines"]["lines"] == [([(8.0, 47.0), (8.1, 47.1)], "a line on land")]  # not under water
    assert cables["layers"]["landings"]["points"] == [(-4.55, 50.83, "Bude", ""), (5.37, 43.3, "Example Carrier", "")]
    assert cables["dropped"] == {"repeated": 1, "under two points": 1, "off the globe": 1} and cables["features"] == 7
    # the answer decoded already (its {lat, lon} objects as they are) reads alike, and is left as it was
    decoded = json.loads(CABLES_ANSWER)
    before = json.dumps(decoded)
    assert parse(CABLES, decoded) == cables and json.dumps(decoded) == before
    assert parse(CABLES, CABLES_ANSWER.decode()) == cables  # and so does its text


def test_an_overpass_answer_whose_query_did_not_finish_is_refused_whole():
    late = overpass(AMS, remark='runtime error: Query timed out in "query" at line 1 after 181 seconds.')
    with pytest.raises(InfrastructureError) as said:
        parse(CENTRES, late)
    assert str(said.value) == ('overpass.example could not finish the query: runtime error: Query timed out in "query" '
                               'at line 1 after 181 seconds.')
    note = parse(CENTRES, overpass(AMS, remark="the server is  in maintenance\ntomorrow"))  # a remark that is no error
    assert note["features"] == 1
    assert note["remarks"] == ["overpass.example remarked: the server is in maintenance tomorrow"]
    for wrong, why in ((b"<?xml version=\"1.0\"?><html>\n<body>rate_limited</body></html>",
                        "it is no JSON: it begins '<?xml version=\"1.0\"?><html> <body>rate_limited</body></html>'"),
                       (b"", "it is no JSON: it is empty"), (b'{"version": 0.6}', "it holds no list of elements"),
                       (b"[1, 2]", "it holds no list of elements"), (b"[" * 100_000, "it is no JSON: it begins '[[[[")):
        words = f"overpass.example's answer is not the data asked for ({why}"
        with pytest.raises(InfrastructureError, match=re.escape(words)):
            parse(CENTRES, wrong)


def test_a_sparql_answer_is_read_by_its_kind():
    found = parse(WIKIDATA, SPARQL_ANSWER)
    assert found["layers"] == {
        "exchanges": {"lines": [], "points": [(8.6821, 50.1109, "Example-IX Frankfurt", "Example-IX Management GmbH")]},
        "datacentres": {"lines": [], "points": [(-121.1838, 45.5946, "Example Data Center", "")]},
        "stations": {"lines": [], "points": [  # ground stations and teleports alike
            (-5.1819, 50.0481, "Goonhilly Satellite Earth Station", "Goonhilly Earth Station Ltd"),
            (13.6019, 41.9783, "Fucino Space Centre", ""),
            (30.5, -20.25, "", "")]}}  # an id standing in for a label is no name
    # the same exchange under a second operator; a kind not asked for; a place on the Moon, one past the edge, none
    assert found["dropped"] == {"repeated": 1, "of no kind asked for": 1, "off the globe": 3} and found["features"] == 5
    for wrong in (b'{"head": {}}', b'{"results": {"bindings": {}}}', b'"a string"'):
        with pytest.raises(InfrastructureError, match=r"query\.wikidata\.example's answer is not the data asked for "
                                                      r"\(it holds no results\.bindings\)"):
            parse(WIKIDATA, wrong)


def test_a_geojson_answer_gives_its_lines_as_cables():
    found = parse(ROUTES, GEOJSON_ANSWER)
    assert found["layers"] == {"cables": {"points": [], "lines": [
        ([(7.9, 54.3), (8.1, 54.35), (8.4, 54.4)], "Example Atlantic 1"),  # a MultiLineString: each part a line
        ([(8.5, 54.5), (8.9, 54.6)], "Example Atlantic 1"),
        ([(-3.2, 53.4), (-3.6, 53.6)], "Example Irish Sea link"),  # a LineString; its name's property in any case
        ([(-1.6, 49.7), (-1.9, 49.9)], "Example Operator plc"),  # no name: its operator's
        ([(14.5, 35.9), (15.0, 36.2)], "")]}}
    assert found["dropped"] == {"of no kind asked for": 2, "under two points": 1}  # a point, no geometry; no part
    metres = json.loads(GEOJSON_ANSWER)
    metres["crs"]["properties"]["name"] = "urn:ogc:def:crs:EPSG::3857"
    with pytest.raises(InfrastructureError, match=r"its coordinates are in urn:ogc:def:crs:EPSG::3857, not in degrees"):
        parse(ROUTES, metres)
    for name in ("EPSG:4326", "urn:ogc:def:crs:OGC:1.3:CRS84"):
        metres["crs"]["properties"]["name"] = name
        assert parse(ROUTES, metres)["features"] == 5
    for wrong in (b'{"type": "Feature"}', b'{"type": "FeatureCollection"}', b"[]"):
        with pytest.raises(InfrastructureError,
                           match=r"is not the data asked for \(it is no GeoJSON FeatureCollection\)"):
            parse(ROUTES, wrong)


def test_a_wfs_is_asked_for_its_coordinates_longitude_first():
    """(Review S11) A WFS answers in the axis order its srsName names: GeoServer reads EPSG:4326 as longitude first,
    and urn:ogc:def:crs:EPSG::4326 (WFS 2.0's default, and WFS 1.1's for GML) as latitude first, while its GeoJSON
    names the same CRS either way. So a data set that asks a WFS says srsName=EPSG:4326 or CRS84, or every route would
    be drawn with its longitude and latitude swapped, and nothing would say so."""
    plain = ROUTES["query"].replace("&srsName=EPSG:4326", "")
    for srs in ("EPSG:4326", "epsg:4326", "EPSG%3A4326", "CRS:84", "urn:ogc:def:crs:OGC:1.3:CRS84",
                "urn:ogc:def:crs:OGC::CRS84"):
        assert DataSet.of({**ROUTES, "query": f"{plain}&srsName={srs}"}).address().endswith(f"&srsName={srs}")
    assert DataSet.of({**ROUTES, "query": f"SRSNAME=EPSG:4326&{plain}"}).format == "geojson"  # a WFS's names: any case
    for query, said in ((f"{plain}&srsName=urn:ogc:def:crs:EPSG::4326", "'urn:ogc:def:crs:EPSG::4326'"),
                        (f"{plain}&srsName=EPSG:3857", "'EPSG:3857'"), (plain, "none"),
                        (f"{plain}&srsName=", "''"), (f"{plain}&srsName=EPSG:4326&srsName=EPSG:3857", "'EPSG:3857'"),
                        ("SERVICE=wfs&request=GetFeature&typeNames=emodnet:sigcables&outputFormat=json", "none")):
        with pytest.raises(ValueError) as wrong:
            DataSet.of({**ROUTES, "query": query})
        assert str(wrong.value) == (
            "the data set emodnet-cables asks a WFS, which answers in the axis order its srsName names: its query says "
            f"srsName=EPSG:4326 (or CRS84), longitude first, not {said}")
    # a GeoJSON file, or a service that is no WFS (OGC API Features: CRS84 unless asked otherwise), as it is
    assert DataSet.of({**ROUTES, "query": ""}).query == ""
    assert DataSet.of({**ROUTES, "query": "f=json"}).query == "f=json"


def test_maps_of_networks_are_read_into_backbones_and_their_points_of_presence():
    """The user, 2026-11-19: "major network 'bones' need to be displayed on the map". Of each network its newest map
    (its file's name says its year: Geant2009, Geant2012), unless that is history (before 2000: ARPANET's, NSFNET's);
    of the map its own points of presence with a place, and the links between them, each drawn once, from its end
    further west. Another network's point, a shared medium (a hyperedge), a point with no place and the links to them
    are left out and counted; what was read and left out of the maps is said as a remark."""
    found = parse(ZOO, ZOO_ANSWER)
    assert list(found["layers"]) == ["pops", "backbones"]  # in the layers' own order
    assert found["layers"]["pops"] == {"lines": [], "points": [
        (151.20732, -33.86785, "Sydney1 (AARNet)", "AARNet, 2010"),  # its network's year, from its own DateYear
        (151.20732, -33.86785, "Sydney2 (AARNet)", "AARNet, 2010"),  # in the same city: a point of its own
        (115.86048, -31.95224, "Perth (AARNet)", "AARNet, 2010"),
        (149.12807, -35.28346, "Canberra & ACT (AARNet)", "AARNet, 2010"),  # its &-escape undone
        (130.84185, -12.46113, "Darwin (AARNet)", "AARNet, 2010"),  # no id: a point, and no link reaches it
        (-0.12574, 51.50853, "London (GÉANT)", "GÉANT, 2012"),  # its newest map's, the year its file's name says
        (4.88969, 52.37403, "Amsterdam (GÉANT)", "GÉANT, 2012"),
        (8.55, 47.36667, "Zürich (GÉANT)", "GÉANT, 2012"),  # written in Latin-1
        (21.01178, 52.22977, "Warszawa (Pionier)", "Pionier"),  # no year said: none written
        (19.93658, 50.06143, "Kraków (Pionier)", "Pionier")]}
    assert found["layers"]["backbones"] == {"points": [], "lines": [
        ([(115.86048, -31.95224), (151.20732, -33.86785)], "AARNet, 2010: Perth to Sydney1"),  # west to east
        ([(149.12807, -35.28346), (151.20732, -33.86785)], "AARNet, 2010: Canberra & ACT to Sydney1"),
        ([(-0.12574, 51.50853), (4.88969, 52.37403)], "GÉANT, 2012: London to Amsterdam"),
        ([(-0.12574, 51.50853), (8.55, 47.36667)], "GÉANT, 2012: London to Zürich"),
        ([(19.93658, 50.06143), (21.01178, 52.22977)], "Pionier: Kraków to Warszawa")]}
    assert found["features"] == 15 and found["dropped"] == {
        "outside its network": 1, "with no place": 1, "off the globe": 1,  # Telstra's; Somewhere; NAN
        "of no kind asked for": 1,  # the ring, a hyperedge
        "under two points": 1, "repeated": 1,  # Sydney1 to Sydney2, in one city; Perth to Sydney1 again
        "between points not drawn": 4}  # to Telstra's, to a node there is none of, to the ring, from no node at all
    assert found["remarks"] == [
        "8 maps in the answer: 3 networks drawn, each from its newest map; 2 older maps of the same networks left out; "
        "2 networks whose newest map is from before 2000 left out; 1 map that did not read left out (Broken: a list in "
        "it is never closed)"]
    assert infrastructure.OLDEST == 2000
    # a map alone, gzipped or not, or an archive not gzipped, or one gzipped in two members, reads alike
    alone = gml("Abilene", [pop(0, "Seattle", -122.33, 47.61), pop(1, "Denver", -104.98, 39.74)], [(1, 0)],
                DateYear=2011)
    tar = archive({"Abilene.gml": alone}, gzipped=False)
    assert tar.index(b"graph [") < 1100 < tar.index(b"Denver")  # (the second member holds the map's end)
    for answer in (alone.encode(), gzip.compress(alone.encode()), tar, archive({"Abilene.gml": alone}),
                   gzip.compress(tar[:1100]) + gzip.compress(tar[1100:]), alone):
        abilene = parse(ZOO, answer)
        assert abilene["layers"] == {
            "pops": {"lines": [], "points": [(-122.33, 47.61, "Seattle (Abilene)", "Abilene, 2011"),
                                             (-104.98, 39.74, "Denver (Abilene)", "Abilene, 2011")]},
            "backbones": {"points": [], "lines": [([(-122.33, 47.61), (-104.98, 39.74)],
                                                   "Abilene, 2011: Seattle to Denver")]}}
        assert abilene["remarks"] == ["1 map in the answer: 1 network drawn, each from its newest map"]
    # a map that names no network: its file's, else none
    assert parse(ZOO, archive({"Kdl.gml": gml(None, [pop(0, "Chicago", -87.65, 41.85)])}))["layers"]["pops"][
        "points"] == [(-87.65, 41.85, "Chicago (Kdl)", "Kdl")]
    assert parse(ZOO, gml(None, [pop(0, "", -87.65, 41.85)]))["layers"]["pops"]["points"] == [
        (-87.65, 41.85, "a network", "")]  # its sub, the same as its name, is not said twice
    # history alone: nothing drawn, and said (an install says so: every feature left out, or none)
    old = parse(ZOO, archive({"Arpanet19728.gml": ARPANET}))
    assert old["features"] == 0 and old["remarks"] == [
        "1 map in the answer: 0 networks drawn, each from its newest map; 1 network whose newest map is from before "
        "2000 left out"]


def test_a_map_in_gml_is_read_as_its_graph_and_what_is_no_gml_is_said(monkeypatch):
    assert (infrastructure.GML_ITEMS, infrastructure.GML_DEPTH, infrastructure.GML_KEYS) == (100_000, 16, 64)
    graph, nodes, edges = infrastructure._graph(
        'Creator "a tool" Version 1 graph [ label "first" label "second" directed 0\n'
        '  node [ id 1 Longitude -INF Latitude +INF Elevation NAN Weight 1.5E+01 graphics [ a [ b 1 ] ] ] # a comment\n'
        '  edge [ source 1 target 2 ] list [ node [ id 9 ] ] ]')
    assert graph == {"label": "first", "directed": 0}  # the first of each key; what is outside the graph read past
    [node] = nodes  # a node inside another list is none of the graph's
    assert node["id"] == 1 and node["Longitude"] == -math.inf and node["Latitude"] == math.inf
    assert math.isnan(node["Elevation"]) and node["Weight"] == 15.0 and "graphics" not in node and "b" not in node
    assert edges == [{"source": 1, "target": 2}]
    assert infrastructure._graph("graph [ node [ " + " ".join(f"k{i} {i}" for i in range(70)) + " ] ]")[1][0] == {
        f"k{i}": i for i in range(infrastructure.GML_KEYS)}  # GML_KEYS values an item at most
    deep = "graph [ " + "a [ " * 16 + "]" * 16 + " ]"
    for text, why in (('graph [ node [ id 1 ] ] ]', "a bracket that closes nothing at character 24"),
                      ('graph [ node [ id ] ]', "its key 'id' has no value"),
                      ('graph [ 7 ]', "a value with no key at character 8"),
                      ('graph [ label "x"', "a list in it is never closed"),
                      ('graph [ ] label', "its key 'label' has no value"),
                      ('graph [ label @ ]', "it holds no GML at character 14"),
                      ('label "a map of nothing"', "it holds no graph"), ("", "it holds no graph"),
                      (deep, "its lists are nested more than 16 deep")):
        with pytest.raises(ValueError) as wrong:
            infrastructure._graph(text)
        assert str(wrong.value) == why, text
    monkeypatch.setattr(infrastructure, "GML_ITEMS", 2)  # nodes a map holds, and edges: no more are read
    with pytest.raises(ValueError, match=r"^it holds more than 2 nodes$"):
        infrastructure._graph("graph [ node [ id 1 ] node [ id 2 ] node [ id 3 ] ]")
    with pytest.raises(ValueError, match=r"^it holds more than 2 edges$"):
        infrastructure._graph("graph [ edge [ ] edge [ ] edge [ ] ]")
    assert len(infrastructure._graph("graph [ node [ id 1 ] node [ id 2 ] edge [ ] edge [ ] ]")[2]) == 2


def test_an_answer_that_is_no_file_of_maps_or_unpacks_to_more_than_may_be_is_refused_in_words(monkeypatch):
    """A file of maps is unpacked in memory alone, never written out, and bounded: MAX_UNPACKED bytes unpacked,
    MAX_MAPS files an archive, MAX_MAP bytes a map. What is not the data asked for is said, and nothing of it kept."""
    assert (infrastructure.MAX_UNPACKED, infrastructure.MAX_MAPS, infrastructure.MAX_MAP) == (32 << 20, 2000, 4 << 20)
    broken = bytearray(archive(MAPS, gzipped=False))
    broken[148:156] = b"0000000\x00"  # its first header's checksum
    for answer, why in (
            (b"<!DOCTYPE html><html><body>Not Found</body></html>",
             "it is no GML map, nor an archive of them: it holds no GML at character 0; it begins '<!DOCTYPE html>"
             "<html><body>Not Found</body></html>'"),
            (ZOO_ANSWER[:-10], "it is cut short"),
            (b"\x1f\x8b\x08\x00" + bytes(6) + b"\xff" * 64, "it does not unpack: "),
            (bytes(broken), "its archive does not read: "),
            (archive({"README.md": "The Internet Topology Zoo"}), "its archive holds no GML map"),
            (archive({"gml/Broken.gml": 'graph [ Network "Broken" ', "gml/Empty.gml": ""}),
             "no map of it reads: Broken: a list in it is never closed"),
            (archive({"gml/Bro\x07ken\nmap.gml": "graph ["}),  # a file's name said as a name is kept: printable
             "no map of it reads: Bro ken map: a list in it is never closed"),
            ({"type": "FeatureCollection"}, "it is no file of maps")):
        with pytest.raises(InfrastructureError) as said:
            parse(ZOO, answer)
        assert str(said.value).startswith(f"raw.zoo.example's answer is not the data asked for ({why}"), said.value
    monkeypatch.setattr(infrastructure, "MAX_UNPACKED", 20_000)  # a bomb: small, and unpacking to far more
    for bomb in (gzip.compress(bytes(10_000_000)), archive({"Big.gml": "graph [ ]" + " " * 30_000})):
        with pytest.raises(InfrastructureError) as said:
            parse(ZOO, bomb)
        assert str(said.value) == (f"raw.zoo.example's answer unpacks to more than {world.size_words(20_000)}, the "
                                   "most a data set may be")
    monkeypatch.setattr(infrastructure, "MAX_UNPACKED", 32 << 20)
    monkeypatch.setattr(infrastructure, "MAX_MAPS", 3)  # the folder and three files: one file too many
    with pytest.raises(InfrastructureError, match=r"\(its archive holds more than 3 files\)$"):
        parse(ZOO, archive({"A.gml": alone_map(), "B.gml": alone_map(), "C.gml": alone_map()}))
    assert parse(ZOO, archive({"A.gml": alone_map(), "B.gml": alone_map()}))["features"] == 3
    monkeypatch.setattr(infrastructure, "MAX_MAPS", 2000)
    monkeypatch.setattr(infrastructure, "MAX_MAP", 1000)  # a map larger than a map may be: not read, and said
    found = parse(ZOO, ZOO_ANSWER)
    assert "Sydney1 (AARNet)" not in [p[2] for p in found["layers"]["pops"]["points"]]
    assert found["remarks"][0].endswith("2 maps that did not read left out (Aarnet: it is larger than "
                                        f"{world.size_words(1000)})")
    with pytest.raises(InfrastructureError, match=r"\(it is no GML map, nor an archive of them: it is larger than "):
        parse(ZOO, AARNET)  # a map alone: the answer itself


def alone_map() -> str:
    """One network's map: two points and the link between them."""
    return gml("Abilene", [pop(0, "Seattle", -122.33, 47.61), pop(1, "Denver", -104.98, 39.74)], [(0, 1)])


ABILENE = ([(-122.33, 47.61), (-104.98, 39.74)], "Abilene: Seattle to Denver")  # alone_map()'s link, as it is drawn


def gnu_header(name: str, kind: bytes, size: int, real: int = 0) -> bytes:
    """One header block of a GNU tar archive, made by hand (tarfile writes neither of these kinds): b"L", a long name
    for the member after it, its `size` bytes following; b"S", a sparse file that stores nothing and reads as `real`
    bytes of zeros. Then the checksum: the block's bytes summed with that field as spaces."""
    block = bytearray(512)
    block[:len(name)] = name.encode("ascii")
    for at, value in ((100, "0000644"), (108, "0000000"), (116, "0000000"), (124, f"{size:011o}"),
                      (136, "00000000000")):
        block[at:at + len(value) + 1] = value.encode("ascii") + b"\x00"
    block[156:157] = kind
    block[257:265] = b"ustar  \x00"  # GNU's magic
    if kind == b"S":  # its one piece of data holds no bytes (from 386), none more follow (482), its size (483)
        block[483:495] = f"{real:011o}\x00".encode("ascii")
    block[148:156] = b" " * 8
    block[148:156] = f"{sum(block):06o}\x00 ".encode("ascii")
    return bytes(block)


def gnu_file(name: str, data: bytes) -> bytes:
    """A file's header and its data, padded to the archive's blocks."""
    return gnu_header(name, b"0", len(data)) + data + bytes(-len(data) % 512)


def test_a_map_holding_a_number_too_long_to_read_is_left_out_and_said():
    """A GML integer of more digits than Python reads one (sys.get_int_max_str_digits(), 4,300 by default) is no
    map's: that map does not read and is said, and the others are drawn. int()'s ValueError, no _Unread, once left
    the reader whole: one such map failed the whole data set, in Python's words."""
    huge = 'graph [ Network "Huge" node [ id ' + "7" * 5000 + ' Longitude 1.0 Latitude 2.0 Internal 1 ] ]'
    found = parse(ZOO, archive({"gml/Abilene.gml": alone_map(), "gml/Huge.gml": huge}))
    assert found["layers"]["backbones"]["lines"] == [ABILENE]
    assert found["remarks"] == [
        "2 maps in the answer: 1 network drawn, each from its newest map; 1 map that did not read left out (Huge: it "
        "holds a number of 5,000 digits, more than can be read)"]
    assert infrastructure._number("-" + "1" * 4000) == -int("1" * 4000)  # a long one that int() reads, as it is
    assert infrastructure._number("7" * 5000 + ".5") == math.inf  # a real of any length: as float() reads it


def test_an_answer_of_many_gzip_members_is_unpacked_in_step_with_its_size(monkeypatch):
    """A gzip member is handed to zlib a piece at a time, FEED bytes first, twice as many each time after, FEED_MOST
    at most: what zlib copies past a member's end (its unused_data) is no more than that piece, so the work grows with
    the answer however many members it holds. Handed the whole rest of the answer at each member, 320,000 empty members
    (6.4 MB) took 306 s here, and a 32 MB answer of them would have taken hours, after the download's deadline and with
    no cancel looked at. Counted here as the bytes handed to zlib."""
    class Counting:  # zlib as the reader uses it, counting the bytes handed to its decompressors
        MAX_WBITS, error, handed = zlib.MAX_WBITS, zlib.error, 0

        def decompressobj(self, wbits):
            real, outer = zlib.decompressobj(wbits), self

            class Unzip:
                eof = property(lambda self: real.eof)
                unused_data = property(lambda self: real.unused_data)
                unconsumed_tail = property(lambda self: real.unconsumed_tail)

                def decompress(self, data, max_length=0):
                    outer.handed += len(data)
                    return real.decompress(data, max_length)
            return Unzip()
    counting = Counting()
    monkeypatch.setattr(infrastructure, "zlib", counting)
    members = 2000
    answer = gzip.compress(b"", mtime=0) * members + archive({"gml/Abilene.gml": alone_map()})
    assert parse(ZOO, answer)["layers"]["backbones"]["lines"] == [ABILENE]  # the map after them, read whole
    assert counting.handed <= 256 * members + 2 * len(answer)  # some 0.6 MB, where it was 40 MB
    assert (infrastructure.FEED, infrastructure.FEED_MOST) == (256, 1 << 16)
    counting.handed = 0
    big = gzip.compress(bytes(3 << 20), mtime=0)  # one member of 3 MB unpacked: read whole through its pieces
    assert infrastructure._unpacked(big, "raw.zoo.example") == bytes(3 << 20)
    assert counting.handed <= 2 * len(big) + 256


def test_an_archive_is_read_to_no_more_than_max_unpacked_whatever_its_members_say(monkeypatch):
    """What an archive's maps read as is held to MAX_UNPACKED in all, as what a gzipped answer unpacks to. A GNU sparse
    file stores nothing and reads as the size it says (tarfile fills it with zeros): 64 of them in an answer of 514
    bytes once read as 268 MB, and 2,000 of them, each the 4 MB a map may be, would have read as 8 GB. Such an answer
    is refused in words before its maps are read; one within it is read, its sparse files maps that do not read."""
    monkeypatch.setattr(infrastructure, "MAX_UNPACKED", 1 << 20)  # 1 MB in all; a map 4 MB at most, as ever
    good = gnu_file("gml/Abilene.gml", alone_map().encode())
    sparse = [gnu_header(f"gml/Net{i}.gml", b"S", 0, 300_000) for i in range(4)]
    over = good + b"".join(sparse) + bytes(1024)  # 1.2 MB of zeros said
    assert len(over) == 4096 and tarfile.open(fileobj=io.BytesIO(over)).getmember("gml/Net0.gml").issparse()
    with pytest.raises(InfrastructureError) as said:
        parse(ZOO, gzip.compress(over, mtime=0))
    assert str(said.value) == (f"raw.zoo.example's answer unpacks to more than {world.size_words(1 << 20)}, the most "
                               "a data set may be")
    within = parse(ZOO, gzip.compress(good + b"".join(sparse[:3]) + bytes(1024), mtime=0))  # 0.9 MB said
    assert within["layers"]["backbones"]["lines"] == [ABILENE]
    assert within["remarks"][0].endswith("3 maps that did not read left out (Net0: it holds no GML at character 0)")


def test_an_archive_whose_headers_chain_deeper_than_can_be_read_is_refused_in_words():
    """tarfile reads a GNU long name (or an extended header), then by recursion the header after it: some 500 chained
    raised RecursionError, which once left the reader in Python's words. Such an archive does not read, and is said."""
    name = b"gml/Abilene.gml\x00"
    link = gnu_header("././@LongLink", b"L", len(name)) + name + bytes(512 - len(name))
    tail = gnu_file("gml/Abilene.gml", alone_map().encode()) + bytes(1024)
    assert parse(ZOO, gzip.compress(link + tail, mtime=0))["layers"]["backbones"]["lines"] == [ABILENE]
    with pytest.raises(InfrastructureError) as said:
        parse(ZOO, gzip.compress(link * 2000 + tail, mtime=0))
    assert str(said.value) == ("raw.zoo.example's answer is not the data asked for (its archive does not read: its "
                               "headers are chained deeper than can be read)")


def test_a_layer_keeps_no_more_than_its_caps_and_says_what_it_left_out(monkeypatch):
    assert (infrastructure.MAX_POINTS, infrastructure.MAX_VERTICES, infrastructure.STEP, infrastructure.NAME) == (
        20_000, 400_000, 0.02, 80)
    monkeypatch.setattr(infrastructure, "MAX_POINTS", 2)
    monkeypatch.setattr(infrastructure, "MAX_VERTICES", 5)
    centres = parse(CENTRES, CENTRES_ANSWER)
    assert [p[2] for p in centres["layers"]["datacentres"]["points"]] == ["AMS1", "Example Rechenzentrum GmbH"]
    assert len(centres["layers"]["exchanges"]["points"]) == 1  # each layer has its own count
    assert centres["dropped"]["over the most a layer keeps"] == 2 and centres["features"] == 3
    cables = parse(CABLES, CABLES_ANSWER)
    # its 4 vertices; no more fit
    assert [name for _, name in cables["layers"]["cables"]["lines"]] == ["Channel Example 1"]
    assert cables["dropped"] == {"over the most a layer keeps": 3, "repeated": 1, "under two points": 1,
                                 "off the globe": 1}
    assert len(cables["layers"]["lines"]["lines"]) == 1
    long = overpass({"type": "node", "id": 1, "lat": 1.0, "lon": 2.0,  # a name is cut, and what cannot be printed goes
                     "tags": {"telecom": "data_center", "name": "A\tvery\x00 long name " + "x" * 200,
                              "operator": "é" * 90}})
    [(_, _, name, sub)] = parse(CENTRES, long)["layers"]["datacentres"]["points"]
    assert name == ("A very long name " + "x" * 200)[:80] and sub == "é" * 80


def test_the_file_packs_each_layers_coordinates_and_they_read_back():
    packed = pack(CABLES, parse(CABLES, CABLES_ANSWER), NOW)
    assert json.loads(json.dumps(packed, allow_nan=False)) == packed  # plain data
    assert {k: v for k, v in packed.items() if k != "layers"} == {
        "v": 1, "set": "osm-cables", "title": "Submarine cables and landing stations", "licence_name": "ODbL 1.0",
        "source": "OpenStreetMap, through the Overpass API", "credit": OSM_CREDIT,
        "fetched": "2026-11-16T12:00:00+00:00", "features": 7, "dropped": 3}
    assert list(packed["layers"]) == ["landings", "cables", "lines"]
    cables = packed["layers"]["cables"]["lines"]
    assert set(packed["layers"]["cables"]) == {"lines"} and cables["n"] == 4
    assert cables["names"] == ["Channel Example 1", "Example Telecom", "", "a short one"]
    # where each line's vertices begin, and where the last one's end: n + 1 little-endian uint32
    assert ints(cables["offsets"], "I") == [0, 4, 7, 9, 11]
    # longitude and latitude in 1e-5 degrees, little-endian int32 pairs
    assert ints(cables["xy"])[:8] == [133560, 5112790, 145000, 5110000, 160000, 5105000, 185280, 5096940]
    assert places(cables)[4:7] == [(-5.0, 50.0), (-5.03, 50.0), (-5.0315, 50.001)] and len(places(cables)) == 11
    landings = packed["layers"]["landings"]["points"]
    assert landings["n"] == 2 and places(landings) == [(-4.55, 50.83), (5.37, 43.3)]
    assert (landings["names"], landings["subs"]) == (["Bude", "Example Carrier"], ["", ""])
    assert "float" not in {type(v).__name__ for part in packed["layers"].values() for v in part.values()}
    empty = pack(CABLES, {"layers": {}, "dropped": {}}, "2026-11-16T12:00:00+00:00")
    assert (empty["layers"], empty["features"], empty["dropped"], empty["fetched"]) == (
        {}, 0, 0, "2026-11-16T12:00:00+00:00")


# -- the download: on the user's word, its licence accepted ------------------------------------------------------------
def test_a_data_set_is_downloaded_only_once_its_licence_is_accepted(tmp_path):
    folder, lines = tmp_path / "layers", []
    fetch = Downloads({AT["osm-datacentres"]: CENTRES_ANSWER})
    with pytest.raises(LicenceRefused) as no:
        install(CENTRES, folder, fetch=fetch, log=lines.append)
    # the argument the second confirmation fills in
    assert no.value.accept == "accept_licence" == form(CENTRES, folder)["fields"][1]["name"]
    assert str(no.value) == "A data set is downloaded only once you accept its licence."
    assert isinstance(no.value, ValueError)
    for almost in (None, 1, "true", "yes", [True], {"accept": True}):
        with pytest.raises(LicenceRefused):
            install(CENTRES, folder, accept_licence=almost, fetch=fetch, log=lines.append)
    assert fetch.asked == [] and lines == [] and not folder.exists()  # nothing asked, nothing said, nothing written
    out = install(CENTRES, folder, accept_licence=True, fetch=fetch, log=lines.append, agent="walled-firewall/1.2.3",
                  clock=Clock(), wall=Clock(NOW))
    # one request: the data set's address, its own wait as each socket operation's, the plugin's name and version
    assert fetch.asked == [(AT["osm-datacentres"], 190.0, {"agent": "walled-firewall/1.2.3", "what": "a data set"})]
    size = len(CENTRES_ANSWER)  # 1.104.0: the download's bytes, kept in the database
    db = folder / infrastore.FILE
    assert out["ok"] is True and out["said"] == f"installed Data centres: 5 features ({world.size_words(size)})"
    assert out["lines"] == ["asked of overpass.example", f"kept in {db}, in place of any older copy",
                            "credited on the globe as © OpenStreetMap contributors",
                            "4 features left out: 1 repeated, 2 off the globe, 1 of no kind asked for"]
    assert out["file"] == {"set": "osm-datacentres", "path": str(db), "bytes": size,
                           "downloaded": len(CENTRES_ANSWER), "features": 5, "dropped": 4,
                           "fetched": "2026-11-16T12:00:00+00:00", "layers": {"exchanges": 1, "datacentres": 4}}
    assert lines == ["asking overpass.example for Data centres", "downloading from overpass.example",
                     f"{world.size_words(len(CENTRES_ANSWER))} downloaded: reading it"]
    assert [p.name for p in folder.iterdir()] == [infrastore.FILE]  # the download itself is not kept
    packed = pack(CENTRES, parse(CENTRES, CENTRES_ANSWER), NOW)  # read back as the file of 1.103.0 held it
    parts = {layer: Index(folder, [CENTRES]).layer(layer)["parts"][0] for layer in packed["layers"]}
    assert {layer: {k: v for k, v in part.items() if k in ("points", "lines")} for layer, part in parts.items()} == \
        packed["layers"]
    assert json.loads(json.dumps(out, allow_nan=False)) == out
    # no agent given: the library's own, which names nothing of anyone's either
    fetch = Downloads({AT["wikidata"]: SPARQL_ANSWER})
    install(WIKIDATA, folder, accept_licence=True, fetch=fetch, clock=Clock())
    assert fetch.asked[0][1:] == (60.0, {"agent": "liminal-libs (infrastructure data sets)", "what": "a data set"})
    # (review M7) checked as it is given: what is more than a name and a version is refused, never mended
    for contact in ("someone@example.org", "walled\nfirewall", "walled-firewall/1.2.3\n", " walled-firewall/1.2.3",
                    "a\tb", "walled  firewall/1.2.3", "x" * 200, "walled-firewall/1.2.3; +https://example.org", 7):
        with pytest.raises(ValueError, match="a download's User-Agent is a product's name and its version"):
            install(CENTRES, folder, accept_licence=True, fetch=fetch, agent=contact)
    assert len(fetch.asked) == 1
    assert [infrastructure._agent(a) for a in ("firewall-linux/0.9.0", "a-plugin/0.7.0 (liminal)", None, "")] == [
        "firewall-linux/0.9.0", "a-plugin/0.7.0 (liminal)", infrastructure.USER_AGENT, infrastructure.USER_AGENT]


def test_one_download_at_a_time_and_the_table_says_it_is_under_way(tmp_path):
    gate, entered = threading.Event(), threading.Event()

    def slow(url, timeout, **said):
        entered.set()
        gate.wait(5)
        return io.BytesIO(CENTRES_ANSWER)
    folder = tmp_path / "layers"
    index = Index(folder, [CENTRES, WIKIDATA])
    job, out = background(install, CENTRES, folder, accept_licence=True, fetch=slow)
    assert entered.wait(3) and infrastructure.installing() and [t.name for t in downloading()] == [
        "osm-datacentres-layer-download"]
    with pytest.raises(ValueError, match="^a data set is being downloaded already: wait for it to finish$"):
        install(WIKIDATA, folder, accept_licence=True, fetch=slow)
    with pytest.raises(ValueError, match="^Data centres is being downloaded: wait for it to finish, or cancel it$"):
        remove(CENTRES, folder)
    table = index.table()
    assert [row[3] for row in table["rows"]] == ["being downloaded", "not downloaded"]
    assert all(row[4] == row[5] == "" for row in table["rows"]) and index.forms() == []  # nothing offered meanwhile
    assert table["note"].endswith("A data set is being downloaded: its progress shows in the panel.")
    assert [s["downloading"] for s in index.sets()] == [True, False]
    gate.set()
    job.join(5)
    assert out["answer"]["ok"] is True and not infrastructure.installing()
    assert [row[4]["title"] for row in index.table()["rows"]] == ["Update…", "Download…"]  # offered again, at once


def test_a_busy_server_is_asked_once_more_a_minute_later_inside_the_same_deadline(tmp_path):
    """(Review S6) Two tries of a query that may run five minutes, and the minute between them, are all counted inside
    the install's ten minutes: the second try's socket waits no longer than what is left."""
    folder, clock, lines = tmp_path / "layers", Clock(), []

    def log(line):
        lines.append(line)
        if "asked once more" in line:
            clock.t += RETRY_S  # the minute passes

    long = {**CENTRES, "wait": 600}
    fetch = Downloads({AT["osm-datacentres"]: [busy(AT["osm-datacentres"]), CENTRES_ANSWER]})
    out = install(long, folder, accept_licence=True, fetch=fetch, log=log, clock=clock, wall=Clock(NOW))
    assert out["ok"] is True and [(url, wait) for url, wait, _ in fetch.asked] == [
        (AT["osm-datacentres"], 600.0), (AT["osm-datacentres"], 540.0)]
    assert lines[:4] == ["asking overpass.example for Data centres",
                         "overpass.example is busy (HTTP 504): it is asked once more in 60 s",
                         "asking overpass.example again", "downloading from overpass.example"]
    before = infrastore.Store(folder).sets()
    for code in infrastructure.BUSY:  # still busy the second time: said, and the older copy stays
        assert code in (429, 502, 503, 504)
        at = AT["osm-datacentres"]
        fetch = Downloads({at: [busy(at, code), busy(at, code)]})
        with pytest.raises(InfrastructureError) as said:
            install(CENTRES, folder, accept_licence=True, fetch=fetch, log=log, clock=clock)
        assert str(said.value) == (f"overpass.example is busy (HTTP {code}): it was asked twice, a minute apart. "
                                   "Nothing was installed, and what was installed before stays. Try again later.")
        assert len(fetch.asked) == 2
    assert infrastore.Store(folder).sets() == before and RETRY_S == 60.0


def test_the_wait_before_the_second_try_ends_at_once_on_a_cancel_and_at_the_deadline(tmp_path):
    """(Review S6) The minute before a busy server is asked again is waited on the install's clock: a cancel ends it at
    once (nothing more is asked), and so does the install's deadline."""
    folder, clock, waiting, cancelled = tmp_path / "layers", Clock(), threading.Event(), threading.Event()
    fetch = Downloads({AT["osm-datacentres"]: [busy(AT["osm-datacentres"], 503), CENTRES_ANSWER]})
    began = time.monotonic()
    job, out = background(install, CENTRES, folder, accept_licence=True, fetch=fetch, cancel=cancelled.is_set,
                          clock=clock, log=lambda line: "asked once more" in line and waiting.set())
    assert waiting.wait(3)
    time.sleep(2 * world.POLL_S)
    assert job.is_alive() and len(fetch.asked) == 1  # its minute is not over: the clock stands still
    cancelled.set()
    job.join(3)
    assert not job.is_alive() and out == {"answer": {"said": "cancelled: nothing was installed", "ok": False}}
    assert len(fetch.asked) == 1 and not folder.exists() and time.monotonic() - began < 3
    clock, waiting = Clock(), threading.Event()
    fetch = Downloads({AT["osm-datacentres"]: [busy(AT["osm-datacentres"], 503), CENTRES_ANSWER]})
    job, out = background(install, CENTRES, folder, accept_licence=True, fetch=fetch, clock=clock,
                          log=lambda line: "asked once more" in line and waiting.set())
    assert waiting.wait(3)
    clock.t += INSTALL_S  # the ten minutes are up while it waits
    job.join(3)
    assert not job.is_alive() and isinstance(out["error"], InfrastructureError) and str(out["error"]) == TOOK
    assert len(fetch.asked) == 1 and not folder.exists()
    # cancelled before anything was asked: nothing is
    fetch = Downloads({AT["osm-datacentres"]: CENTRES_ANSWER})
    assert install(CENTRES, folder, accept_licence=True, fetch=fetch, cancel=lambda: True) == {
        "said": "cancelled: nothing was installed", "ok": False} and fetch.asked == []
    # a cancel that cannot say stops nothing
    assert install(CENTRES, folder, accept_licence=True, fetch=fetch, cancel=lambda: 1 / 0, clock=Clock())["ok"] is True


def test_one_deadline_bounds_the_whole_download_and_a_cancel_ends_a_wait_on_the_socket(tmp_path):
    """(Review S6) An Overpass server is silent for as long as a query runs, so a download spends its time waiting on
    its socket: neither the deadline nor a cancel looked at between pieces would end that. The fetch runs on a thread of
    its own, as the GeoIP file's does (world.run_download): the waiting side looks at both every POLL_S and shuts the
    download's sockets."""
    folder, clock, lines = tmp_path / "layers", Clock(), []
    sock = Held()
    job, out = background(install, CENTRES, folder, accept_licence=True, fetch=sock.fetch, log=lines.append,
                          clock=clock)
    assert sock.entered.wait(3) and infrastructure.installing()
    clock.t += INSTALL_S - 1
    time.sleep(3 * world.POLL_S)
    assert job.is_alive() and not sock.shut.is_set()  # a second before the time is up: it goes on
    clock.t += 1  # ten minutes on the install's clock, the server still silent
    job.join(3)
    assert not job.is_alive() and sock.how == [socket.SHUT_RDWR]  # its socket shut: its thread ends as well
    assert isinstance(out["error"], InfrastructureError) and str(out["error"]) == TOOK
    assert wait_for(lambda: downloading() == []) and not folder.exists() and not infrastructure.installing()
    assert lines == ["asking overpass.example for Data centres"]
    # a cancel, while the read waits
    sock, cancelled, began = Held(), threading.Event(), time.monotonic()
    job, out = background(install, CENTRES, folder, accept_licence=True, fetch=sock.fetch, cancel=cancelled.is_set,
                          clock=Clock())
    assert sock.entered.wait(3)
    time.sleep(2 * world.POLL_S)
    assert job.is_alive() and not sock.shut.is_set()
    cancelled.set()
    job.join(3)
    assert not job.is_alive() and sock.how == [socket.SHUT_RDWR] and time.monotonic() - began < 3
    assert out == {"answer": {"said": "cancelled: nothing was installed", "ok": False}} and not folder.exists()
    assert INSTALL_S == 600.0 and world.POLL_S <= 0.25


def test_a_body_that_dribbles_and_an_answer_that_comes_late_install_nothing(tmp_path):
    folder, clock, streams = tmp_path / "layers", Clock(), []

    class Answer(io.BytesIO):
        given = 0

        def read1(self, n=-1):
            clock.t += 50.0  # each read takes this long on the install's clock
            piece = super().read1(min(n, 1))
            self.given += len(piece)
            return piece

    def dribbling(url, timeout, **said):
        streams.append(Answer(CENTRES_ANSWER))
        return streams[-1]
    with pytest.raises(InfrastructureError) as said:
        install(CENTRES, folder, accept_licence=True, fetch=dribbling, clock=clock)
    assert str(said.value) == TOOK and streams[0].closed and streams[0].given == 12  # a byte every 50 s: 12 in 600 s

    def late(url, timeout, **said):
        clock.t += 7200.0  # its status line and headers came over two hours, each read within its timeout
        streams.append(Answer(CENTRES_ANSWER))
        return streams[-1]
    with pytest.raises(InfrastructureError) as said:
        install(CENTRES, folder, accept_licence=True, fetch=late, clock=clock)
    assert str(said.value) == TOOK and streams[1].closed and streams[1].given == 0 and not folder.exists()


def test_an_answer_is_read_up_to_its_limit_and_no_further(tmp_path, monkeypatch):
    """(Review M7) 32 MB, half again the largest data set's estimate: decoding holds about three bytes a byte of it."""
    assert infrastructure.MAX_ANSWER == 32 << 20 and infrastructure.CHUNK == 1 << 20
    folder = tmp_path / "layers"
    monkeypatch.setattr(infrastructure, "MAX_ANSWER", 1000)
    monkeypatch.setattr(infrastructure, "CHUNK", 100)
    assert len(CENTRES_ANSWER) > 1000
    plain = Body(CENTRES_ANSWER)  # (review) an answer that says no size: read in pieces, and refused while it is read
    assert refused(CENTRES, folder, plain) == "the answer is larger than 1000 B, the most a data set may be"
    assert plain.reads == 11 and plain.closed  # ten pieces fill the limit, the eleventh passes it: no further

    class Sized(Body):
        """An answer that says its size first."""
        headers = {"Content-Length": str(len(CENTRES_ANSWER))}
    stream = Sized(CENTRES_ANSWER)
    assert refused(CENTRES, folder, stream) == "the answer is larger than 1000 B, the most a data set may be"
    assert stream.reads == 0 and stream.closed and not folder.exists()  # refused by its size: nothing read of it
    monkeypatch.setattr(infrastructure, "CHUNK", 1 << 20)
    monkeypatch.setattr(infrastructure, "MAX_ANSWER", 32 << 20)
    stream, lines = Sized(CENTRES_ANSWER), []
    assert got(CENTRES, folder, stream, log=lines.append)["ok"] is True and stream.closed
    assert lines[1] == f"downloading from overpass.example: {world.size_words(len(CENTRES_ANSWER))}"


def test_a_read_that_times_out_says_how_long_it_waited(tmp_path):
    """(Review, low) A second try's socket waits what is left of the install's time, less than the data set's own wait:
    a read that times out says the wait it was given."""
    folder, clock = tmp_path / "layers", Clock()

    class Silent(io.BytesIO):
        def read1(self, n=-1):
            raise TimeoutError("timed out")

    def log(line):
        if "asked once more" in line:
            clock.t += RETRY_S
    long, at = {**CENTRES, "wait": 600}, AT["osm-datacentres"]
    fetch = Downloads({at: [busy(at), Silent(CENTRES_ANSWER)]})
    with pytest.raises(InfrastructureError) as said:
        install(long, folder, accept_licence=True, fetch=fetch, log=log, clock=clock)
    assert str(said.value) == ("overpass.example did not answer within 540 s, what was left of the 10 minutes an "
                               "install may take")
    assert [wait for _, wait, _ in fetch.asked] == [600.0, 540.0]
    assert refused(CENTRES, folder, Silent(CENTRES_ANSWER)) == (  # its own wait: said so
        "overpass.example did not answer within 190 s, the longest this data set waits for it")
    assert not folder.exists()


def test_a_read_that_outlives_its_shut_socket_is_said_and_keeps_nothing(tmp_path, monkeypatch):
    """(Review, low) On Windows a read waiting on a shut socket ends only within its own timeout: the install answers
    all the same once the thread was given its grace, and says that the connection ends by itself within the data
    set's wait, with nothing it brings kept."""
    monkeypatch.setattr(world, "GRACE_S", 0.05)
    folder, release, cancelled, lines = tmp_path / "layers", threading.Event(), threading.Event(), []
    sock = Held()

    def stubborn(url, timeout, **said):
        """A connection whose read the shut does not end (as on Windows, until its own timeout)."""
        world._handed(sock)
        sock.entered.set()
        release.wait(10)
        return io.BytesIO(CENTRES_ANSWER)  # it came after the stop: never read, never kept
    job, out = background(install, CENTRES, folder, accept_licence=True, fetch=stubborn, cancel=cancelled.is_set,
                          log=lines.append, clock=Clock())
    assert sock.entered.wait(3)
    cancelled.set()
    job.join(3)
    words = ("its connection to overpass.example is shut, and the read waiting on it ends by itself within 190 s at "
             "most: nothing it brings is kept")
    assert not job.is_alive() and sock.how == [socket.SHUT_RDWR]
    assert out == {"answer": {"said": "cancelled: nothing was installed", "ok": False, "lines": [words]}}
    assert lines[-1] == words and [t.name for t in downloading()] == ["osm-datacentres-layer-download"]
    release.set()
    assert wait_for(lambda: downloading() == []) and not folder.exists() and not infrastructure.installing()
    # its time up while such a read waits: said the same way, the time's words the error's
    sock, release, lines, clock = Held(), threading.Event(), [], Clock()
    job, out = background(install, CENTRES, folder, accept_licence=True, fetch=stubborn, log=lines.append, clock=clock)
    assert sock.entered.wait(3)
    clock.t += INSTALL_S
    job.join(3)
    assert not job.is_alive() and str(out["error"]) == TOOK and lines[-1] == words
    release.set()
    assert wait_for(lambda: downloading() == []) and not folder.exists()
    # a read the shut ends (as on Linux), within its grace: nothing more is said
    monkeypatch.setattr(world, "GRACE_S", 5.0)
    sock, cancelled, lines = Held(), threading.Event(), []
    job, out = background(install, CENTRES, folder, accept_licence=True, fetch=sock.fetch, cancel=cancelled.is_set,
                          log=lines.append, clock=Clock())
    assert sock.entered.wait(3)
    cancelled.set()
    job.join(3)
    assert out == {"answer": {"said": "cancelled: nothing was installed", "ok": False}}
    assert lines == ["asking overpass.example for Data centres"] and sock.how == [socket.SHUT_RDWR]


def test_with_no_fetch_given_a_download_goes_through_fetch_url(tmp_path, monkeypatch):
    """(Review, low) Every other test hands install a fetch: without one it is world.fetch_url's, https on every hop and
    from the data set's own host (that path's own test: test_a_download_is_https_on_every_hop_...)."""
    asked = []

    def recorded(url, timeout, **said):
        asked.append((url, timeout, said))
        return io.BytesIO(CENTRES_ANSWER)
    monkeypatch.setattr(world, "fetch_url", recorded)
    out = install(CENTRES, tmp_path / "layers", accept_licence=True, agent="walled-firewall/1.2.3", clock=Clock())
    assert out["ok"] is True and asked == [
        (AT["osm-datacentres"], 190.0, {"agent": "walled-firewall/1.2.3", "what": "a data set"})]


def test_a_download_that_fails_says_why_and_leaves_the_older_file(tmp_path):
    folder = tmp_path / "layers"
    assert got(CENTRES, folder, CENTRES_ANSWER)["ok"] and got(WIKIDATA, folder, SPARQL_ANSWER)["ok"]
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    at = AT["osm-datacentres"]
    late = overpass(AMS, remark='runtime error: Query run out of memory in "query" at line 1 using about 541 MB of '
                                'RAM.')

    class Cut(io.BytesIO):
        def read1(self, n=-1):
            raise ConnectionResetError("the connection was reset")
    cut = Cut(CENTRES_ANSWER)
    for answer, words in (
            (overpass(), "overpass.example answered with no features"),
            (overpass({"type": "node", "id": 9, "lat": 1.0, "lon": 1.0, "tags": {"amenity": "cafe"}},
                      {"type": "node", "id": 10, "lat": 91.0, "lon": 1.0, "tags": {"telecom": "data_center"}}),
             "overpass.example answered, but every feature was left out: 1 of no kind asked for, 1 off the globe"),
            (late, 'overpass.example could not finish the query: runtime error: Query run out of memory in "query" at '
                   "line 1 using about 541 MB of RAM."),
            (b"<html>busy</html>", "overpass.example's answer is not the data asked for (it is no JSON: it begins "
                                   "'<html>busy</html>')"),
            (urllib.error.HTTPError(at, 500, "Internal Server Error", {}, None),
             "Data centres could not be downloaded from overpass.example: HTTP 500 Internal Server Error"),
            (urllib.error.HTTPError(at, 403, "Forbidden", {}, None),  # no rule of this host's is known: its own words
             "Data centres could not be downloaded from overpass.example: HTTP 403 Forbidden"),
            (urllib.error.URLError("no route to the host"),
             "Data centres could not be downloaded from overpass.example: no route to the host"),
            (TimeoutError("timed out"),
             "overpass.example did not answer within 190 s, the longest this data set waits for it"),
            (urllib.error.URLError(TimeoutError("timed out")),
             "overpass.example did not answer within 190 s, the longest this data set waits for it"),
            (cut, "Data centres could not be downloaded from overpass.example: ConnectionResetError: the connection "
                  "was reset")):
        assert refused(CENTRES, folder, answer) == words
    assert cut.closed
    # (review M7) the query service asks automated clients for a contact, and none is sent: its refusal in words
    forbidden = urllib.error.HTTPError(AT["wikidata"], 403, "Forbidden", {}, None)
    assert refused(WIKIDATA, folder, forbidden) == (
        "query.wikidata.example refused the request (HTTP 403): it asks automated clients to name a contact, and none "
        "is sent from here.")
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before  # nothing changed, no part file left
    remark, lines = overpass(AMS, remark="it is  Tuesday"), []
    assert got(CENTRES, folder, remark, log=lines.append)["said"].startswith("installed Data centres: 1 feature (")
    assert lines[-1] == "overpass.example remarked: it is Tuesday"  # a remark that is no error is said on


def test_a_download_is_https_on_every_hop_from_the_data_sets_own_host(tmp_path):
    """The real fetch_url over stand-in protocols: the request carries the plugin's name and version as its User-Agent
    and nothing else of anyone's; a redirect elsewhere is refused before anything is asked of it, in a data set's words;
    a busy answer is urllib's own error, and asked once more."""
    folder, clock, lines = tmp_path / "layers", Clock(), []
    at = AT["osm-datacentres"]
    web = Web({at: (200, {"Content-Length": str(len(CENTRES_ANSWER))}, CENTRES_ANSWER)})
    out = install(CENTRES, folder, accept_licence=True, fetch=over(web), agent="walled-firewall/1.2.3", clock=clock)
    assert out["ok"] is True and web.asked == [at] and web.agents == ["walled-firewall/1.2.3"]
    for n, where in enumerate(("http://mirror.example/x", "https://cdn.other.example/x",
                               "https://overpass.example.evil.example/x")):
        web = Web({at: (302, {"Location": where}, b"the redirect's own body"), where: (200, {}, CENTRES_ANSWER)})
        with pytest.raises(InfrastructureError) as said:
            install(CENTRES, tmp_path / f"refused-{n}", accept_licence=True, fetch=over(web), clock=clock)
        scheme, host = where.split("://")[0], where.split("/")[2]
        assert str(said.value) == ("Data centres could not be downloaded from overpass.example: it was sent on to "
                                   f"{scheme}://{host}, and a data set comes over https from overpass.example alone")
        assert web.asked == [at] and web.bodies[0].reads == 0 and not (tmp_path / f"refused-{n}").exists()
    # it says where it came from
    elsewhere = Web({at: (200, {}, CENTRES_ANSWER)}, came_from="https://cdn.other.example/x")
    with pytest.raises(InfrastructureError, match="it was sent on to https://cdn.other.example, and a data set comes"):
        install(CENTRES, tmp_path / "elsewhere", accept_licence=True, fetch=over(elsewhere), clock=clock)
    assert elsewhere.bodies[0].reads == 0

    def log(line):
        lines.append(line)
        if "asked once more" in line:
            clock.t += RETRY_S
    web = Web({at: [(504, {}, b"<html>Gateway Timeout: the server is at capacity</html>"), (200, {}, CENTRES_ANSWER)]})
    assert install(CENTRES, folder, accept_licence=True, fetch=over(web), log=log, clock=clock)["ok"] is True
    assert web.asked == [at, at] and web.bodies[0].reads == 0  # the busy answer's body is never read
    assert "overpass.example is busy (HTTP 504): it is asked once more in 60 s" in lines


# -- machines/world.py's two edits (review M9: their tests live here) --------------------------------------------------
def test_fetch_url_carries_the_callers_agent_and_says_what_is_downloaded():
    at = AT["osm-datacentres"]
    web = Web({at: (200, {}, b"{}")})
    FETCH_URL(at, 5, handlers=(web,)).close()
    FETCH_URL(at, 5, handlers=(web,), agent="walled-firewall/1.2.3", what="a data set").close()
    FETCH_URL(at, 5, handlers=(web,), agent="").close()
    assert web.agents == ["liminal-libs (GeoIP download)", "walled-firewall/1.2.3", "liminal-libs (GeoIP download)"]
    assert world.USER_AGENT == "liminal-libs (GeoIP download)"  # the GeoIP download's own, as before
    with pytest.raises(ValueError, match="^a data set is downloaded over https only$"):
        FETCH_URL("http://overpass.example/api/interpreter", 5, handlers=(web,), what="a data set")
    with pytest.raises(ValueError, match="^a GeoIP file is downloaded over https only$"):
        FETCH_URL("http://overpass.example/api/interpreter", 5, handlers=(web,))
    moved = {at: (302, {"Location": "http://mirror.example/x"}, b"")}
    with pytest.raises(RedirectRefused, match="it was sent on to http://mirror.example, and a data set comes over "
                                              "https from overpass.example alone"):
        FETCH_URL(at, 5, handlers=(Web(moved),), what="a data set")
    with pytest.raises(RedirectRefused, match="and a GeoIP file comes over https from overpass.example alone"):
        FETCH_URL(at, 5, handlers=(Web(moved),))
    elsewhere = Web({at: (200, {}, b"{}")}, came_from="https://cdn.other.example/x")
    with pytest.raises(RedirectRefused, match="sent on to https://cdn.other.example, and a data set comes over https"):
        FETCH_URL(at, 5, handlers=(elsewhere,), what="a data set")
    assert elsewhere.bodies[0].closed


def test_a_download_runs_on_a_thread_of_its_own_and_what_it_raised_is_raised_by_its_install(monkeypatch):
    """world.run_download, the waiting loop lifted out of the GeoIP file's install for a data set's too (review S6)."""
    names = []
    assert world.run_download(lambda: names.append(threading.current_thread().name) or 7, world._Cutoff(),
                              geo._clock() + 5, "its time is up", name="a-layer-download") == 7
    assert names == ["a-layer-download"]
    with pytest.raises(KeyError):  # its own error, when nothing stopped it
        world.run_download(lambda: {}["x"], world._Cutoff(), geo._clock() + 5, "its time is up",
                           name="a-layer-download")
    # stopped: the cut-off's words, as the error told (each work held until the waiting side has stopped it: work
    # that ends before the first look was stopped by nothing, and what it raised is raised, as above)
    stopped = world._Cutoff()
    with pytest.raises(geo.GeoError, match="^the plugin was detached$"):
        world.run_download(lambda: wait_for(lambda: stopped.why) and 1 / 0, stopped, geo._clock() + 5,
                           "its time is up", name="a-layer-download", stopping=lambda: "the plugin was detached")
    assert stopped.left is False  # its thread ended within its grace
    past = world._Cutoff()
    with pytest.raises(InfrastructureError, match="^its time is up$"):
        world.run_download(lambda: wait_for(lambda: past.why) and 1 / 0, past, 10.0, "its time is up",
                           name="a-layer-download", clock=lambda: 11.0, error=InfrastructureError)
    # a thread still running once its grace is over: the cut-off says so (`left`), for the install's words
    monkeypatch.setattr(world, "GRACE_S", 0.05)
    held, release = world._Cutoff(), threading.Event()
    with pytest.raises(InfrastructureError, match="^cancelled$"):
        world.run_download(lambda: release.wait(10), held, geo._clock() + 5, "its time is up",
                           name="a-layer-download", stopping=lambda: "cancelled", error=InfrastructureError)
    assert held.left is True and held.why == "cancelled"
    release.set()
    assert wait_for(lambda: downloading() == [])

    def no_thread(self):
        raise RuntimeError("can't start new thread")
    monkeypatch.setattr(threading.Thread, "start", no_thread)
    with pytest.raises(InfrastructureError, match="^Data centres could not be downloaded: can't start new thread$"):
        world.run_download(lambda: 7, world._Cutoff(), 10.0, "its time is up", name="a-layer-download",
                           what="Data centres", error=InfrastructureError)
    with pytest.raises(geo.GeoError, match="^the GeoIP file could not be downloaded: can't start new thread$"):
        world.run_download(lambda: 7, world._Cutoff(), 10.0, "its time is up", name="a-layer-download")


@needs_reader
def test_the_geoip_file_asked_for_outside_the_page_is_let_go_again_unless_the_view_watches(tmp_path):
    """WorldView.rest(): the Netstat tab and the hosts database ask geoip() outside page(), which lets the file go
    itself; rest() is theirs. Nothing stays mapped while nobody watches; while the capture runs it stays, as ever."""
    folder = tmp_path / "geoip"
    folder.mkdir()
    (folder / "dbip-city-lite-2026-11.mmdb").write_bytes(
        mmdb([("81.2.69.0/24", city("GB", "United Kingdom", "London", 51.5142, -0.0931))], built=NOVEMBER))
    view = WorldView("walled-firewall", capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW))
    first = view.geoip()
    assert first is not None and first.describe()["open"] and first.lookup("81.2.69.142").city == "London"
    view.rest()  # nobody watches: let go, and still said for the plugin's card
    assert view._geoip is None and first.describe()["open"] is False and view.describe()["geoip"]["open"] is False
    view.rest()  # nothing open: nothing to do
    assert view.touch() is True and view.running
    again = view.geoip()
    view.rest()  # it watches: the file stays mapped, as page() leaves it
    assert view._geoip is again and again is not first and again.describe()["open"]
    view.stop()
    assert again.describe()["open"] is False
    view.rest()


# -- what is installed -------------------------------------------------------------------------------------------------
def test_the_index_says_what_is_installed_and_reads_no_geometry_to_look(tmp_path, monkeypatch):
    """(Review M8) The layers travel with every answer of the tab, asked every two seconds: the database's counts are
    read again only when it changed (1.104.0: its files' sizes and times), only its counts, its credits and its dates
    are kept, and layer() reads the geometry when the globe asks for it and keeps none."""
    folder, clock, read = tmp_path / "layers", Clock(), []
    counts = infrastore.Store.counts
    monkeypatch.setattr(infrastore.Store, "counts",
                        lambda self, set_id=None: (read.append("look") if set_id is None else None) or
                        counts(self, set_id))
    index = Index(folder, [CENTRES, CABLES, WIKIDATA], clock=clock)
    assert index.folder == folder and index.layers() == [] and read == []  # nothing installed: nothing read
    assert [(s["id"], s["installed"], s["features"], s["bytes"]) for s in index.sets()] == [
        ("osm-datacentres", False, 0, 0), ("osm-cables", False, 0, 0), ("wikidata", False, 0, 0)]
    with pytest.raises(LookupError, match="^no layer 'cables' is installed here$"):
        index.layer("cables")
    got(CENTRES, folder, CENTRES_ANSWER)
    got(CABLES, folder, CABLES_ANSWER)
    layers = index.layers()  # looked at again at once after an install here, the ten seconds over or not
    assert read == ["look"]
    assert [(x["id"], x["count"]) for x in layers] == [("exchanges", 1), ("datacentres", 4), ("landings", 2),
                                                        ("cables", 4), ("lines", 1)]
    by = {x["id"]: x for x in layers}
    assert by["cables"] == {"id": "cables", "title": "Submarine cables", "kind": "lines", "mark": "line", "slot": 6,
                            "on": True, "names_from": 3.0, "count": 4, "version": by["cables"]["version"],
                            "credits": [OSM_CREDIT],
                            "note": "from OpenStreetMap, through the Overpass API, fetched 2026-11-16"}
    assert re.fullmatch(r"[0-9a-f]{12}", by["cables"]["version"])
    assert by["cables"]["version"] == by["landings"]["version"]
    assert by["cables"]["version"] != by["datacentres"]["version"]  # another data set's
    assert (by["lines"]["on"], by["lines"]["mark"], by["datacentres"]["mark"], by["exchanges"]["mark"]) == (
        False, "dash", "square", "diamond")
    assert [x[0] for x in LAYERS] == ["exchanges", "datacentres", "landings", "stations", "pops", "cables",
                                      "backbones", "lines", "airports", "cities", "fibre", "roads", "railways",
                                      "models", "modelcities", "probes",
                                      # 1.107.0 (Monday list item 25): the map's names, boundaries, towns and streets
                                      "countrynames", "states", "statenames", "counties", "countylines", "towns",
                                      "streets", "buildings"]
    # every layer the library has is one the shared globe lists (its MAX_LAYERS), each on a slot it draws (4 to 7)
    script = Path(infrastructure.__file__).parents[1] / "ui" / "static" / "liminal-globe.js"
    # 1.73.0: ten, the airports and the cities with them; 1.104.0: sixteen, the fibre, the roads and the railways too
    most = int(re.search(r"const MAX_LAYERS = (\d+);", script.read_text(encoding="utf-8")).group(1))
    # 1.107.0: twenty-four, the map's names, boundaries, towns, streets and buildings too, a name alone a "label"
    assert len(LAYERS) <= most == 24
    assert {x[4] for x in LAYERS} <= {4, 5, 6, 7} and all(x[3] in ("circle", "square", "diamond", "line", "dash",
                                                                   "label")
                                                          for x in LAYERS)
    assert json.loads(json.dumps(layers, allow_nan=False)) == layers and len(json.dumps(layers)) < 2000  # small
    sets = index.sets()
    size = len(CABLES_ANSWER)  # 1.104.0: the download's
    assert sets[1] == {"id": "osm-cables", "title": "Submarine cables and landing stations", "format": "overpass",
                       "about": "about 1,100 cable ways, 60 stations",
                       "source": "OpenStreetMap, through the Overpass API",
                       "licence_name": "ODbL 1.0", "host": "overpass.example", "size": 3_000_000, "installed": True,
                       "fetched": "2026-11-16T12:00:00+00:00", "features": 7, "dropped": 3, "bytes": size,
                       "layers": ["landings", "cables", "lines"], "credit": OSM_CREDIT, "problem": "",
                       "downloading": False}
    assert (sets[2]["installed"], sets[2]["fetched"], sets[2]["layers"]) == (False, None, [])
    index.table(), index.forms()
    assert len(read) == 1  # asked again and again within the ten seconds: nothing read
    clock.t += INDEX_S
    assert index.layers() == layers and len(read) == 1  # looked at again: the database as it was, nothing read
    infrastore.Store(folder).put(CABLES, parse(CABLES, CABLES_ANSWER), NOW)  # another process's update
    assert index.layers() == layers and len(read) == 1  # not looked at so soon
    clock.t += INDEX_S
    changed = {x["id"]: x for x in index.layers()}
    assert read[1:] == ["look"]  # read again, once
    assert changed["cables"]["version"] != by["cables"]["version"]  # so the globe asks for its geometry anew
    assert changed["datacentres"]["version"] == by["datacentres"]["version"]
    assert "xy" not in json.dumps(index._files) and "names" not in json.dumps(index._files)  # no geometry is kept
    # the geometry, when the globe asks for it: as the file holds it
    cables = index.layer("cables")
    assert (cables["id"], cables["version"]) == ("cables", changed["cables"]["version"])
    [part] = cables["parts"]
    assert set(part) == {"set", "credit", "lines"} and (part["set"], part["credit"]) == ("osm-cables", OSM_CREDIT)
    assert part["lines"]["n"] == 4 and ints(part["lines"]["offsets"], "I") == [0, 4, 7, 9, 11]
    assert places(part["lines"])[:4] == CHANNEL and part["lines"]["names"][0] == "Channel Example 1"
    [points] = index.layer("landings")["parts"]
    assert set(points) == {"set", "credit", "points"} and places(points["points"]) == [(-4.55, 50.83), (5.37, 43.3)]
    assert json.loads(json.dumps(cables, allow_nan=False)) == cables
    assert "xy" not in json.dumps(index._files) and len(read) == 2  # read for the asker, and let go again
    for missing in ("stations", "nothing", "", None, 7, "x" * 500):  # no file feeds it; no such layer
        with pytest.raises(LookupError, match="^no layer .{1,60} is installed here$"):
            index.layer(missing)
    # the data folder's when none is given
    assert Index(datasets=[CENTRES]).folder == tmp_path / "data" / "infrastructure"


def test_two_data_sets_feed_one_layer_within_what_a_layer_holds(tmp_path, monkeypatch):
    folder, clock = tmp_path / "layers", Clock()
    index = Index(folder, [CENTRES, WIKIDATA], clock=clock)
    got(CENTRES, folder, CENTRES_ANSWER)
    got(WIKIDATA, folder, SPARQL_ANSWER, wall=Clock(NOW + 86400))
    by = {x["id"]: x for x in index.layers()}
    assert list(by) == ["exchanges", "datacentres", "stations"]
    assert (by["datacentres"]["count"], by["exchanges"]["count"], by["stations"]["count"]) == (5, 2, 3)
    # each maker credited where its features are
    assert by["datacentres"]["credits"] == [OSM_CREDIT, WIKIDATA["credit"]]
    assert by["stations"]["credits"] == [WIKIDATA["credit"]]
    assert by["datacentres"]["note"] == ("from OpenStreetMap, through the Overpass API, fetched 2026-11-16; from "
                                         "Wikidata, fetched 2026-11-17")
    parts = index.layer("datacentres")["parts"]
    assert [(p["set"], p["points"]["n"], p["credit"]["text"]) for p in parts] == [
        ("osm-datacentres", 4, "© OpenStreetMap contributors"), ("wikidata", 1, "Wikidata")]  # in the plugin's order
    assert places(parts[1]["points"]) == [(-121.1838, 45.5946)]
    assert parts[1]["points"]["names"] == ["Example Data Center"]
    # a layer holds 20,000 points and 400,000 vertices in all: a data set that would pass that is left out whole, and
    # said
    monkeypatch.setattr(infrastructure, "MAX_POINTS", 4)
    full = {x["id"]: x for x in index.layers()}
    assert full["datacentres"]["count"] == 4 and full["datacentres"]["credits"] == [OSM_CREDIT]
    assert full["datacentres"]["note"] == ("from OpenStreetMap, through the Overpass API, fetched 2026-11-16; left "
                                           "out, the layer being full: Exchange points, ground stations and teleports")
    assert [p["set"] for p in index.layer("datacentres")["parts"]] == ["osm-datacentres"]
    assert full["datacentres"]["version"] != by["datacentres"]["version"]  # what feeds it changed
    assert full["stations"] == by["stations"]


def test_a_file_of_maps_is_downloaded_at_its_address_alone_and_drawn_as_backbones(tmp_path):
    """One GET of the file's own address, waited for as the data set says; what was read of its maps said to the job's
    log; the two layers it feeds as LAYERS says them (the backbones on at first, their points of presence not, both
    named "about 2010-2011"), credited to the file's makers."""
    folder, lines = tmp_path / "layers", []
    fetch = Downloads({ZOO["url"]: ZOO_ANSWER})
    out = install(ZOO, folder, accept_licence=True, fetch=fetch, log=lines.append, agent="firewall-linux/0.9.0",
                  clock=Clock(), wall=Clock(NOW))
    assert fetch.asked == [(ZOO["url"], 60.0, {"agent": "firewall-linux/0.9.0", "what": "a data set"})]
    size = len(ZOO_ANSWER)
    assert out["said"] == f"installed Backbone networks, about 2010-2011: 15 features ({world.size_words(size)})"
    assert out["lines"] == ["asked of raw.zoo.example",
                            f"kept in {folder / infrastore.FILE}, in place of any older copy",
                            "credited on the globe as Internet Topology Zoo, CC BY 4.0",
                            "10 features left out: 1 outside its network, 1 with no place, 1 off the globe, 1 of no "
                            "kind asked for, 1 under two points, 1 repeated, 4 between points not drawn"]
    assert out["file"]["layers"] == {"pops": 10, "backbones": 5} and out["file"]["downloaded"] == len(ZOO_ANSWER)
    assert lines == ["asking raw.zoo.example for Backbone networks, about 2010-2011",
                     "downloading from raw.zoo.example", f"{world.size_words(len(ZOO_ANSWER))} downloaded: reading it",
                     parse(ZOO, ZOO_ANSWER)["remarks"][0]]  # what was read of the maps, said to the job's log
    assert [p.name for p in folder.iterdir()] == [infrastore.FILE]  # the archive itself is not kept, nor unpacked
    index = Index(folder, [ZOO], clock=Clock())
    by = {x["id"]: x for x in index.layers()}
    assert list(by) == ["pops", "backbones"]
    assert by["backbones"] == {"id": "backbones", "title": "Backbones, about 2010-2011", "kind": "lines",
                               "mark": "line", "slot": 7, "on": True, "names_from": 4.0, "count": 5,
                               "version": by["backbones"]["version"], "credits": [ZOO["credit"]],
                               "note": "from the Internet Topology Zoo, through its repository, fetched 2026-11-16"}
    assert {k: by["pops"][k] for k in ("title", "kind", "mark", "slot", "on", "names_from", "count")} == {
        "title": "Backbones' points of presence, about 2010-2011", "kind": "points", "mark": "circle", "slot": 4,
        "on": False, "names_from": 6.0, "count": 10}
    [part] = index.layer("backbones")["parts"]
    assert part["set"] == "topology-zoo" and part["lines"]["n"] == 5
    assert ints(part["lines"]["offsets"], "I") == [0, 2, 4, 6, 8, 10]  # two ends a link: the globe draws the arc
    assert part["lines"]["names"][0] == "AARNet, 2010: Perth to Sydney1"
    assert places(part["lines"])[:2] == [(115.86048, -31.95224), (151.20732, -33.86785)]
    [points] = index.layer("pops")["parts"]
    assert (points["points"]["names"][5], points["points"]["subs"][5]) == ("London (GÉANT)", "GÉANT, 2012")
    words = form(ZOO, folder)["confirm"]["words"]  # its form: the file alone is asked
    assert "Backbone networks, about 2010-2011 is asked of raw.zoo.example in one request" in words
    assert "The request holds only the file asked for: nothing about this machine or its traffic." in words


def test_the_table_offers_each_data_set_and_a_file_that_does_not_read_is_said(tmp_path):
    folder = tmp_path / "layers"
    index = Index(folder, [CENTRES, WIKIDATA], clock=Clock())
    table = index.table()
    assert table["title"] == "Internet infrastructure"
    assert table["empty"] == "This plugin names no data set to download."
    assert [c["title"] for c in table["columns"]] == ["Data set", "From", "Licence", "Here", "", ""]
    assert table["rows"] == [
        [{"text": "Data centres", "sub": "about 5,000 sites, and its few exchange points"},
         "OpenStreetMap, through the Overpass API", "ODbL 1.0", "not downloaded",
         {"form": "world-layer-osm-datacentres", "title": "Download…"}, ""],
        [{"text": "Exchange points, ground stations and teleports",
          "sub": "about 300 places, some data centres among them"},
         "Wikidata", "CC0", "not downloaded", {"form": "world-layer-wikidata", "title": "Download…"}, ""]]
    assert table["note"].startswith("What the globe draws where the exchanges globe draws exchanges: ")
    assert f"kept in {folder}: the globe is then drawn from that file, and asks nothing of anyone." in table["note"]
    assert [f["id"] for f in index.forms()] == ["world-layer-osm-datacentres", "world-layer-wikidata"]
    assert index.forms()[0] == form(CENTRES, folder) and json.loads(json.dumps(table, allow_nan=False)) == table
    got(CENTRES, folder, CENTRES_ANSWER)
    size = world.size_words(len(CENTRES_ANSWER))
    row = index.table()["rows"][0]
    assert row[3:] == [{"text": "5 features, fetched 2026-11-16", "sub": f"{size}; 4 left out"},
                       {"form": "world-layer-osm-datacentres", "title": "Update…"},
                       {"form": "world-layer-remove-osm-datacentres", "title": "Remove…"}]
    assert [f["id"] for f in index.forms()] == ["world-layer-osm-datacentres", "world-layer-remove-osm-datacentres",
                                                 "world-layer-wikidata"]
    assert index.forms()[0] == form(CENTRES, folder, update=True) and index.forms()[1] == remove_form(CENTRES, folder)
    bare = index.table(can=False)  # the page may not ask: nothing is offered
    assert all(r[4] == r[5] == "" for r in bare["rows"]) and index.forms(can=False) == []
    assert Index(folder).table()["rows"] == [] and Index(folder).forms() == [] and Index(folder).layers() == []
    # an older file (1.103.0's) that does not read: said, never drawn, and offered again (or removed)
    for wrong, why in ((b"no JSON at all", "it is no JSON"),
                       (json.dumps(pack(CENTRES, parse(CENTRES, CENTRES_ANSWER), NOW)).encode(),
                        "it is no file of this data set's (version 1)"),
                       (b'{"v": 1, "set": "wikidata"}', "it holds no layers"),
                       (b'{"v": 1, "set": "wikidata", "layers": {"motorways": {}}}',
                        "it holds a layer that is none ('motorways')"),
                       (b'{"v": 1, "set": "wikidata", "layers": {"stations": {"points": {"n": 2, "xy": "", '
                        b'"names": [], "subs": []}}}}', "its stations points do not read")):
        (folder / "wikidata.json").write_bytes(wrong)
        infrastructure._changed()  # (a file changed under a running index is seen at its next look)
        problem = f"its file does not read ({why}): download it again"
        assert index.sets()[1]["problem"] == problem and index.sets()[1]["installed"] is False
        assert index.table()["rows"][1][3:] == [{"text": "not read", "sub": problem},
                                                {"form": "world-layer-wikidata", "title": "Download…"},
                                                {"form": "world-layer-remove-wikidata", "title": "Remove…"}]
        assert [x["id"] for x in index.layers()] == ["exchanges", "datacentres"]  # the file that reads, alone
    assert index.dataset("wikidata") == DataSet.of(WIKIDATA)
    for unknown in ("osm-cables", "", None, 7):
        with pytest.raises(ValueError, match="is not one of this plugin's data sets: osm-datacentres, wikidata$"):
            index.dataset(unknown)
    with pytest.raises(ValueError, match="^'x' is not one of this plugin's data sets: it names none$"):
        Index(folder).dataset("x")


def test_a_data_set_is_removed_on_the_users_word_and_can_be_downloaded_again(tmp_path):
    folder = tmp_path / "layers"
    index = Index(folder, [CENTRES], clock=Clock())
    got(CENTRES, folder, CENTRES_ANSWER)
    assert [x["id"] for x in index.layers()] == ["exchanges", "datacentres"]
    assert remove(CENTRES, folder) == {"said": "removed Data centres", "ok": True, "lines": [
        f"it is removed from {folder / infrastore.FILE}: the globe no longer draws it", "it can be downloaded again"]}
    assert index.layers() == [] and infrastore.Store(folder).sets() == {}  # seen at once, the ten seconds over or not
    assert remove(CENTRES, folder) == {"said": "Data centres is not installed here", "ok": True,
                                       "lines": [f"nothing of it is kept in {folder}"]}
    assert got(CENTRES, folder, CENTRES_ANSWER)["ok"] is True and len(index.layers()) == 2
    # with no folder given: the data folder's own
    assert got(CENTRES, None, CENTRES_ANSWER)["file"]["path"] == str(tmp_path / "data" / "infrastructure" /
                                                                    infrastore.FILE)
    assert remove(CENTRES)["said"] == "removed Data centres"


def test_layers_on_another_systems_drive_are_that_systems(tmp_path, monkeypatch):
    """Each system's platform keeps its own layers on its own disk: a folder on another system's drive (mounts.foreign)
    is never read, written or removed from here, and the page says why."""
    theirs = tmp_path / "theirs"
    got(CENTRES, theirs, CENTRES_ANSWER)  # (as that system left it)
    before = (theirs / infrastore.FILE).read_bytes()
    monkeypatch.setattr(mounts, "foreign", lambda path, table=None: str(path).startswith(os.path.realpath(theirs)))
    read = []
    monkeypatch.setattr(infrastore.Store, "sets", lambda self: read.append("sets") or {})
    index = Index(theirs, [CENTRES], clock=Clock())
    assert index.elsewhere().startswith("Keeping the infrastructure layers: ")
    assert index.layers() == [] and index.sets()[0]["installed"] is False and index.forms() == [] and read == []
    with pytest.raises(LookupError):
        index.layer("datacentres")
    table = index.table()
    assert table["rows"][0][3:] == ["not from here", "", ""]
    assert "is on another system's drive, and that is done from that system, not from here. Each system's platform " \
           "downloads its own." in table["note"]
    fetch, lines = Downloads({AT["osm-datacentres"]: CENTRES_ANSWER}), []
    for accepted in (True, False):  # refused before its licence is even asked, and before anything is fetched or said
        with pytest.raises(ValueError, match=r"^Keeping the infrastructure layers: .* is on another system's drive"):
            install(CENTRES, theirs, accept_licence=accepted, fetch=fetch, log=lines.append)
    with pytest.raises(ValueError, match=r"^Keeping the infrastructure layers: .* is on another system's drive"):
        remove(CENTRES, theirs)
    assert fetch.asked == [] and lines == [] and read == [] and (theirs / infrastore.FILE).read_bytes() == before


# -- the forms' words --------------------------------------------------------------------------------------------------
def test_the_forms_say_what_is_asked_of_whom_how_large_it_is_and_show_the_licence_first(tmp_path):
    folder = tmp_path / "layers"
    get = form(CENTRES, folder)
    assert get == {
        "id": "world-layer-osm-datacentres", "hook": "world_layer_get", "title": "Download Data centres", "job": True,
        "note": ("Drawn on the globe from a file on this machine: once it is downloaded, the globe asks nothing of "
                 "anyone."),
        "fields": [{"name": "dataset", "type": "fixed", "value": "osm-datacentres"},  # the hook's arguments, in order
                   {"name": "accept_licence", "type": "accept", "title": "Accept its licence (ODbL 1.0)?",
                    "words": ODBL, "yes": "Accept it and download"}],
        "confirm": {"title": "Download Data centres?", "yes": "Go on", "words": (
            "Data centres is asked of overpass.example in one request, made now on your word (once more a minute later "
            f"if the server is busy), and kept in {folder} in place of any older copy: 1.9 MB (an estimate where its "
            "maker gives none). Its progress shows in the panel "
            "below; it stops by itself after 10 minutes. The request holds only the tags asked for: nothing about this "
            f"machine or its traffic. Its licence, first: {ODBL} You are asked to accept it next.")}}
    again = form(CENTRES, folder, update=True)
    assert (again["title"], again["confirm"]["title"], again["id"]) == ("Update Data centres", "Update Data centres?",
                                                                       get["id"])
    assert "holds only the kinds of place asked for: nothing" in form(WIKIDATA, folder)["confirm"]["words"]
    assert "holds only the layers asked for: nothing" in form(ROUTES, folder)["confirm"]["words"]
    assert "asked of ows.emodnet.example in one request" in form(ROUTES, folder)["confirm"]["words"]
    assert remove_form(CENTRES, folder) == {
        "id": "world-layer-remove-osm-datacentres", "hook": "world_layer_remove", "title": "Remove Data centres",
        "fields": [{"name": "dataset", "type": "fixed", "value": "osm-datacentres"}],
        "confirm": {"title": "Remove Data centres?", "yes": "Remove it", "words": (
            f"It is removed from {folder} and the globe no longer draws it. It can be downloaded again.")}}
    assert (infrastructure.LAYER_HOOK, infrastructure.GET_HOOK, infrastructure.REMOVE_HOOK) == (
        "world_layer", "world_layer_get", "world_layer_remove")
    for made in (get, again, remove_form(CENTRES, folder)):  # no {name} the page would fill in from a field
        assert json.loads(json.dumps(made, allow_nan=False)) == made and not re.search(r"\{\w+\}", json.dumps(made))


# -- the library's rules -----------------------------------------------------------------------------------------------
def test_no_outside_host_is_named_in_the_library_and_the_module_imports_on_either_system():
    """The addresses, the queries, the licences and the credits are the plugins': no .py of the library holds a
    scheme://host, docstrings and comments included (the app's boundary test scans for it); nothing of one system alone
    is imported; no line is longer than 120 characters."""
    named = re.compile(r"\b(?:https?|wss?)://([A-Za-z0-9.-]+)")
    source = Path(infrastructure.__file__).read_text(encoding="utf-8")
    assert named.findall(source) == [] and named.findall(Path(world.__file__).read_text(encoding="utf-8")) == []
    assert not re.search(r"\b(WinDLL|winreg|import pwd|subprocess|urlopen|socket\.)", source)
    # (review) characters counted: this module, its tests, and what of world.py was written for it
    written = [source, Path(__file__).read_text(encoding="utf-8")] + [inspect.getsource(part) for part in (
        world.run_download, world._Cutoff, world._over_https, world.WorldView.rest)]
    assert [line for text in written for line in text.splitlines() if len(line) > 120] == []
