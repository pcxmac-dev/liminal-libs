"""Routers' names read for their places (1.73.0; the user, 2026-11-22: "it will take a lot of looking over and using
reverse lookups, and whois to figure out as much info as possible on the nodes"). A router's name often says where it
is: an airport's code (fra, sea), a city's name (frankfurt), or a city and its state as the telephone companies'
codes write them (sttlwa: Seattle, Washington). They are read with two of the installed layers, "airports" (OurAirports'
airports with a code) and "cities" (GeoNames' cities), each the user's download: nothing is asked of anyone here.

- The name's own labels are read, its domain left out (its last two labels; three under a country's second level,
  co.uk). Each label is cut at what is no letter; of the pieces: one of three letters that is an airport's code (none
  of STOP: words routers' names use for their parts) gives that airport's town; one of six whose last two letters are
  a US state's code and whose first four are letters of a city of that state, in order, its first the city's own,
  gives that city (the most people first); one of four letters or more that is a city's name gives that city.
- A place is kept only where the trace's time to the router allows it: no further from home than light in fibre goes
  in half that time (FIBRE_KM_PER_MS a millisecond of the time there and back, and SLACK_KM for the rest of the way and
  home's own place); of those left, one in the router's country first (its network's or the GeoIP file's, where known),
  then the surest way of reading (WAYS), then the most people.
- The lists are read from the layers' files when a page asks and their versions changed (Names.gazetteer), held until
  they change again; none installed: no name is read."""
from __future__ import annotations

import base64
import math
import re
import threading
from collections.abc import Mapping

import numpy as np

FIBRE_KM_PER_MS = 100.0  # light in fibre: about 200 km a millisecond one way, so 100 km a millisecond there and back
SLACK_KM = 300.0  # and the rest: the way not straight, the routers' own time, home's place itself
WAYS = {"code and state": 3, "city": 2, "airport": 1}  # how sure a way of reading is, the surest highest
STOP = frozenset((  # three letters routers' names use for their parts, not for their places
    "bbr agg lag net pos ixp gin cpe dsl srv bar car per rtr cor acc dis int ext gig ten eth ipv tbr bdr brd cus dcn"
    " mgt lan wan isp res biz dyn ptr rev pop dcs edg asr mxr crs gsr mlx cat jun cis ibr ebr ccr csr pea peb tor sw"
    " vlan bun ae xe ge te hu et be ar pr er cs fw gw lo xl ten hun gig fab spn").split())
US_STATES = frozenset((
    "AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA"
    " RI SC SD TN TX UT VT VA WA WV WI WY DC").split())
SECOND_LEVEL = frozenset(("co", "com", "net", "org", "ac", "or", "ne", "gov", "edu"))  # co.uk, com.au, ne.jp …
EARTH_KM = 6371.0088


def _km(a, b) -> float:
    p1, p2 = math.radians(a[0]), math.radians(b[0])
    h = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(b[1] - a[1]) / 2) ** 2
    return 2 * EARTH_KM * math.asin(min(1.0, math.sqrt(h)))


def _letters(word: str) -> str:
    return re.sub(r"[^a-z]", "", word.lower())


def _in_order(short: str, long: str) -> bool:
    """Whether `short`'s letters are all in `long`, in their order, both beginning alike."""
    if not short or not long or short[0] != long[0]:
        return False
    at = 0
    for c in long:
        if at < len(short) and c == short[at]:
            at += 1
    return at == len(short)


def _points(layer: Mapping) -> list[tuple[float, float, str, str]]:
    """A layer's points as the files keep them: [(lat, lon, name, sub)]."""
    out = []
    for part in layer.get("parts") or ():
        points = part.get("points") if isinstance(part, Mapping) else None
        if not isinstance(points, Mapping):
            continue
        try:
            xy = np.frombuffer(base64.b64decode(points.get("xy") or ""), dtype="<i4").reshape(-1, 2)
        except (TypeError, ValueError):
            continue
        names, subs = points.get("names") or [], points.get("subs") or []
        for i, (lon, lat) in enumerate(xy.tolist()):
            out.append((lat / 100_000, lon / 100_000, str(names[i]) if i < len(names) else "",
                        str(subs[i]) if i < len(subs) else ""))
    return out


class Gazetteer:
    """The airports' codes and the cities, as routers' names are read with them (the module's docstring)."""

    def __init__(self, airports, cities):
        self.airports: dict[str, tuple] = {}  # code -> (lat, lon, its town, its country)
        for lat, lon, code, sub in airports:
            parts = [x.strip() for x in sub.split(",")]
            town = parts[-2] if len(parts) >= 3 else (parts[0] if parts else code)
            self.airports.setdefault(code.lower(), (lat, lon, town or code, parts[-1] if parts else ""))
        self.by_name: dict[str, tuple] = {}  # a city's letters -> (people, lat, lon, name, country), the most people
        self.by_state: dict[str, list] = {}  # a US state -> [(people, lat, lon, name, letters)], the most people first
        for lat, lon, name, sub in cities:
            where, _, people = sub.partition(" · ")
            country, _, division = where.partition("-")
            try:
                many = int(people.replace(",", "") or 0)
            except ValueError:
                many = 0
            letters = _letters(name)
            if len(letters) >= 4 and many > self.by_name.get(letters, (-1,))[0]:
                self.by_name[letters] = (many, lat, lon, name, country)
            if country == "US" and division in US_STATES:
                self.by_state.setdefault(division, []).append((many, lat, lon, name, letters))
        for cities_of in self.by_state.values():
            cities_of.sort(key=lambda c: -c[0])

    def place(self, host: str, *, home=None, ms=None, country: str = "") -> dict | None:
        """Where a router's name says it is: {"lat", "lon", "label", "how", "token"}, or None (the module's
        docstring). `home` (lat, lon) and `ms` (the trace's time to it) bound it; `country` (two letters) comes first."""
        labels = [x for x in str(host or "").lower().strip(".").split(".") if x]
        if len(labels) < 3:
            return None
        own = labels[:-3] if len(labels) >= 4 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL else labels[:-2]
        found = []
        for label in own:
            for token in (t for t in re.split(r"[^a-z]+", label) if t):
                if len(token) == 3 and token not in STOP and token in self.airports:
                    lat, lon, town, cc = self.airports[token]
                    found.append(("airport", 0, lat, lon, f"{town}, {cc}" if cc else town, cc, token))
                if len(token) == 6 and token[4:].upper() in US_STATES:
                    for many, lat, lon, name, letters in self.by_state.get(token[4:].upper(), ()):
                        if _in_order(token[:4], letters):
                            found.append(("code and state", many, lat, lon, f"{name}, {token[4:].upper()}, US", "US",
                                          token))
                            break
                if len(token) >= 4 and token in self.by_name:
                    many, lat, lon, name, cc = self.by_name[token]
                    found.append(("city", many, lat, lon, f"{name}, {cc}" if cc else name, cc, token))
        if home is not None and ms is not None and ms >= 0:
            reach = FIBRE_KM_PER_MS * float(ms) + SLACK_KM
            found = [f for f in found if _km(home, (f[2], f[3])) <= reach]
        if not found:
            return None
        want = (country or "").upper()
        how, _, lat, lon, label, _, token = max(found, key=lambda f: (bool(want) and f[5] == want, WAYS[f[0]], f[1]))
        return {"lat": round(lat, 4), "lon": round(lon, 4), "label": label, "how": how, "token": token}


class Names:
    """The gazetteer of a plugin's installed airports and cities, made again when their versions change."""

    def __init__(self):
        self._lock = threading.Lock()
        self._key: tuple | None = None
        self._gazetteer: Gazetteer | None = None

    def gazetteer(self, index) -> Gazetteer | None:
        try:
            listed = index.layers() if index is not None else []
        except Exception:  # noqa: BLE001 - a folder that cannot be read: no lists
            listed = []
        layers = {x.get("id"): x for x in listed if isinstance(x, Mapping) and x.get("id") in ("airports", "cities")}
        key = tuple(sorted((k, str(v.get("version") or "")) for k, v in layers.items()))
        with self._lock:
            if key == self._key:
                return self._gazetteer
            read = {}
            for layer_id in layers:
                try:
                    read[layer_id] = _points(index.layer(layer_id))
                except (LookupError, OSError, ValueError):
                    read[layer_id] = []
            self._gazetteer = Gazetteer(read.get("airports", []), read.get("cities", [])) if read else None
            self._key = key
            return self._gazetteer

    def clear(self) -> None:
        with self._lock:
            self._key, self._gazetteer = None, None
