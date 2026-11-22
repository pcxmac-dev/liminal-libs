"""Routers' names read for their places (liminal_libs.machines.names, 1.73.0): OurAirports' and GeoNames' files read
into the airports and cities layers, a router's name read with them, bounded by the trace's time and its country, and
the hop placed by it on the page; over stand-in files and lookups (nothing is downloaded, nothing asked)."""
from __future__ import annotations

import io
import zipfile

from liminal_libs import netpath
from liminal_libs.machines import infrastructure, lookups
from liminal_libs.machines.names import Gazetteer, Names
from liminal_libs.machines.routes import Routes

BASE = {"source": "a stand-in", "licence_name": "public domain", "licence": "Free to use.",
        "credit": {"text": "a stand-in", "url": "https://stand-in.example/"}, "size": 1_000_000, "wait": 60}
AIRPORTS = {**BASE, "id": "ourairports", "title": "Airports", "format": "ourairports",
            "url": "https://stand-in.example/airports.csv"}
CITIES = {**BASE, "id": "geonames", "title": "Cities", "format": "geonames",
          "url": "https://stand-in.example/cities15000.zip"}
CSV = ("id,ident,type,name,latitude_deg,longitude_deg,iso_country,municipality,iata_code\n"
       "1,KSEA,large_airport,Seattle-Tacoma International Airport,47.449,-122.309,US,Seattle,SEA\n"
       "2,KPDX,large_airport,Portland International Airport,45.589,-122.597,US,Portland,PDX\n"
       "3,EDDF,large_airport,Frankfurt am Main Airport,50.033,8.570,DE,Frankfurt,FRA\n"
       "4,XX01,heliport,A heliport,10,10,US,Nowhere,HHH\n"
       "5,KLAG,small_airport,No code,10,10,US,Nowhere,\n")
ROWS = [  # geonameid, name, ascii, alternates, lat, lon, class, code, country, cc2, admin1, …, population
    ("5809844", "Seattle", "Seattle", "", "47.60621", "-122.33207", "P", "PPLA2", "US", "", "WA", "", "", "", "737015"),
    ("5814616", "Vancouver", "Vancouver", "", "45.63873", "-122.66149", "P", "PPLA2", "US", "", "WA", "", "", "",
     "190915"),
    ("5746545", "Portland", "Portland", "", "45.52345", "-122.67621", "P", "PPLA2", "US", "", "OR", "", "", "",
     "652503"),
    ("2925533", "Frankfurt am Main", "Frankfurt am Main", "", "50.11552", "8.68417", "P", "PPLA2", "DE", "", "05", "",
     "", "", "763380"),
    ("2925535", "Frankfurt", "Frankfurt", "", "52.3", "14.55", "P", "PPL", "DE", "", "11", "", "", "", "57000"),
]


def zipped(rows) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("cities15000.txt", "\n".join("\t".join(r) for r in rows) + "\n")
    return out.getvalue()


def layer_of(features, layer_id):
    """A layer as Index.layer gives it, from parse()'s features (infrastructure.pack)."""
    packed = infrastructure.pack(AIRPORTS if layer_id == "airports" else CITIES, features, 0)
    return {"id": layer_id, "version": "v1", "parts": [{"set": "t", **packed["layers"][layer_id]}]}


class Index:
    def __init__(self):
        self.airports = layer_of(infrastructure.parse(AIRPORTS, CSV.encode()), "airports")
        self.cities = layer_of(infrastructure.parse(CITIES, zipped(ROWS)), "cities")

    def layers(self):
        return [{"id": "airports", "kind": "points", "version": "v1"},
                {"id": "cities", "kind": "points", "version": "v1"}]

    def layer(self, layer_id):
        return {"airports": self.airports, "cities": self.cities}[layer_id]


def test_the_airports_with_a_code_and_the_cities_most_people_first_are_read_into_their_layers():
    airports = infrastructure.parse(AIRPORTS, CSV.encode())
    assert [p[2] for p in airports["layers"]["airports"]["points"]] == ["SEA", "PDX", "FRA"]
    assert airports["layers"]["airports"]["points"][0][3] == "Seattle-Tacoma International Airport, Seattle, US"
    assert airports["dropped"] == {"of no kind asked for": 2} or sum(airports["dropped"].values()) == 2
    cities = infrastructure.parse(CITIES, zipped(ROWS))
    assert [p[2] for p in cities["layers"]["cities"]["points"]][:2] == ["Frankfurt am Main", "Seattle"]  # the most first
    assert cities["layers"]["cities"]["points"][1][3] == "US-WA · 737,015"


def test_a_routers_name_is_read_for_its_airport_its_city_or_its_city_and_state():
    g = Names().gazetteer(Index())
    assert isinstance(g, Gazetteer)
    sttl = g.place("lag-807-10.bbr01sttlwa.netops.charter.com")
    assert (sttl["label"], sttl["how"], sttl["token"]) == ("Seattle, WA, US", "code and state", "sttlwa")
    assert g.place("ae-1.r20.sea01.example.net")["label"] == "Seattle, US"  # the airport's town
    assert g.place("ae-2.frankfurtammain.example.net")["label"] == "Frankfurt am Main, DE"  # a city's letters
    assert g.place("ae-2.bbr.lag.example.net") is None  # words of routers' parts are no airports
    assert g.place("router.example.net") is None and g.place("example.net") is None


def test_a_place_the_traces_time_does_not_allow_is_left_out_and_the_routers_country_comes_first():
    g = Names().gazetteer(Index())
    home = (45.6, -121.2)  # The Dalles
    assert g.place("ae-1.fra.example.net", home=home, ms=10.0) is None  # Frankfurt is 8,000 km away: 10 ms allow 1,300
    assert g.place("ae-1.fra.example.net", home=home, ms=150.0)["label"] == "Frankfurt, DE"
    # two readings, Portland's airport and Seattle's code and state: the router's country first, then the surest way
    assert g.place("ae-1.pdx.sttlwa.example.net", country="US")["how"] == "code and state"


def test_a_hop_is_placed_by_its_name_where_that_is_surer_than_the_geoip_file(monkeypatch):
    target = "81.2.69.142"

    def tracer(address):
        return netpath.Trace(address, (netpath.Hop(1, "62.0.0.1", 4.0), netpath.Hop(2, target, 9.0)), True, "stand-in")

    class Place:
        def __init__(self, lat, lon, label, country):
            self.lat, self.lon, self.label, self.country = lat, lon, label, country

    class Geo:
        def lookup(self, address):
            return {"62.0.0.1": Place(34.85, -82.39, "Greenville, United States", "US"),
                    target: Place(47.6, -122.3, "Seattle, United States", "US")}.get(address)
    monkeypatch.setattr(lookups, "_ptr", lambda address: "lag-807-10.bbr01sttlwa.netops.charter.com")
    r = Routes(tracer=tracer, start=lambda work: None)
    r.want([target])
    while r.step():
        pass
    page = {"globe": {"home": {"lat": 45.6, "lon": -121.2}, "origins": [{"id": "s", "lat": 47.6, "lon": -122.3}]}}
    index = Index()
    r.onto(page, Geo(), [target], index=index)
    (hop,) = page["globe"]["origins"][0]["via"]
    assert hop["label"] == "Greenville, United States" and "placed_by" not in hop  # the GeoIP file's, so far
    while r.lookups.step():
        pass
    page = {"globe": {"home": {"lat": 45.6, "lon": -121.2}, "origins": [{"id": "s", "lat": 47.6, "lon": -122.3}]}}
    r.onto(page, Geo(), [target], index=index)
    (hop,) = page["globe"]["origins"][0]["via"]
    assert hop["label"] == "Seattle, WA, US" and hop["placed_by"] == "its name (sttlwa)"  # no more Greenville
    best = r.composite.best("62.0.0.1")
    assert best["label"] == "Seattle, WA, US" and best["by"] == "its name (sttlwa)" and best["confidence"] == 0.6
    r.close()
