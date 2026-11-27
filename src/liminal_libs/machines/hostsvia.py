"""Another plugin's hosts database and places, as the code that reads them locally asks them (1.105.0, Monday list item
33). The World Wide Web tab left the firewalls for plugin-platform-worldwideweb; the hosts are still recorded by a
firewall, and the places are looked up by the World Wide Web plugin's GeoIP files. Each side asks the other through the
platform (a plugin never imports another), and these two classes stand where the local objects stood, so the code
paths of the globe and of the Netstat tab run unchanged:

- `HostsVia` is the HostBook face that NetstatView's globe paths call (the hosts view's places, programs, ports and
  hosts; their sums; the database's facts; the routes kept; the places to look up and kept), each method one ask of
  the serving firewall's services (Firewall.hosts_found, hosts_routes, hosts_keep_route, hosts_keep_places,
  hosts_clear_places). Feeding, writing, forgetting are the firewall's: here they do nothing or refuse. With no firewall
  serving, every read answers nothing, and the facts say why.
- `PlacesVia` is the WorldView face that NetstatView.page and its placing use (geoip, stamp, rest, closed), from one
  ask of the World Wide Web plugin's `places` for the addresses a page needs.

Nothing here holds a lock while it asks."""
from __future__ import annotations

import time
from collections.abc import Mapping

from .. import geo, hostbook

FACTS_S = 2.0  # the firewall's facts (its mode, where its file is, its changes) asked again after this long at most


class HostsVia:
    """The serving firewall's hosts database. `ask(hook, *args)` asks that firewall (LookupError, in words, when none
    serves); `owner_of()` names it ("" for none). `clock` is monotonic (a test's own)."""

    path = None  # not a file of this plugin's

    def __init__(self, ask, owner_of=None, *, clock=time.monotonic):
        self._ask, self._owner_of, self.clock = ask, owner_of, clock
        self._facts: tuple[float, dict] | None = None
        self.problem = ""  # why the last ask failed, until one works again

    @property
    def owner(self) -> str:
        try:
            return str(self._owner_of() or "") if callable(self._owner_of) else ""
        except Exception:  # noqa: BLE001 - who cannot be said: no one
            return ""

    def _found(self, what: str, default, **query):
        try:
            got = self._ask("hosts_found", what, query)
        except Exception as e:  # noqa: BLE001 - a firewall that refuses or none serving: nothing, and why
            self.problem = str(e)
            return default
        self.problem = ""
        return got

    # -- the facts ---------------------------------------------------------------------------------------------------
    def describe(self) -> dict:
        """The firewall's facts of its hosts database (rows, since, problem, mode, elsewhere, changes); with none
        serving, no rows and why."""
        got = self._found("describe", None)
        if not isinstance(got, Mapping):
            return {"rows": 0, "problem": self.problem or "no firewall serves the World Wide Web tab"}
        facts = dict(got)
        self._facts = (self.clock(), facts)
        return dict(facts)

    def _fact(self, key: str, default):
        kept = self._facts
        if kept is None or not 0 <= self.clock() - kept[0] < FACTS_S:
            self.describe()
            kept = self._facts
        return (kept[1] if kept else {}).get(key, default)

    @property
    def changes(self) -> int:
        """The firewall's count of writes that changed the hosts' rows (HostBook.changes), asked each time: -1 when
        no firewall says."""
        got = self._found("changes", None)
        return got if isinstance(got, int) and not isinstance(got, bool) else -1

    def mode(self) -> str:
        return str(self._fact("mode", "shown") or "shown")

    def elsewhere(self) -> str:
        return str(self._fact("elsewhere", "") or "")

    # -- the hosts view's queries --------------------------------------------------------------------------------------
    def places(self, *, most: int = 300, **filters):
        got = self._found("places", None, most=most, **_plain(filters))
        if isinstance(got, (list, tuple)) and len(got) == 2 and isinstance(got[1], Mapping):
            return [dict(p) for p in got[0] or () if isinstance(p, Mapping)], dict(got[1])
        return [], {}

    def programs(self, limit: int = 100, **filters) -> list[dict]:
        return _rows(self._found("programs", [], limit=limit, **_plain(filters)))

    def ports(self, limit: int = 100, **filters) -> list[dict]:
        return _rows(self._found("ports", [], limit=limit, **_plain(filters)))

    def hosts(self, *, limit: int = hostbook.QUERY_ROWS, **filters) -> list[dict]:
        return _rows(self._found("hosts", [], limit=limit, **_plain(filters)))

    def sums(self, **filters) -> dict:
        got = self._found("sums", None, **_plain(filters))
        return dict(got) if isinstance(got, Mapping) else {"hosts": 0, "connections": 0, "seconds": 0.0}

    # -- placing: the hosts the firewall has no place for, placed from this plugin's files -----------------------------
    def unplaced(self, stamp) -> int:
        got = self._found("unplaced", 0, stamp=str(stamp or ""))
        return got if isinstance(got, int) and not isinstance(got, bool) else 0

    def in_use(self, stamp) -> None:
        """1.110.0 (item 14): nothing asked. The firewall's book takes the stamp from the places it is handed
        (hosts_keep_places), never from a read; with every row placed as of `stamp`, its rows of a host agree."""
        return None

    def place(self, lookup, stamp, most: int = hostbook.PLACE_ROWS, only=None) -> int:
        """The hosts the firewall names for `stamp` looked up with `lookup` here, and handed to it to keep."""
        hosts = self._found("unplaced_hosts", [], stamp=str(stamp or ""), most=most)
        hosts = [h for h in hosts or () if isinstance(h, str) and (only is None or h in only)]
        if not hosts:
            return 0
        places = {}
        for host in hosts:
            try:
                places[host] = _mapping(lookup(host))
            except Exception:  # noqa: BLE001 - a lookup that fails places nothing
                places[host] = None
        try:
            said = self._ask("hosts_keep_places", str(stamp or ""), places)
        except Exception as e:  # noqa: BLE001 - kept at a later ask
            self.problem = str(e)
            return 0
        return int((said or {}).get("placed") or 0) if isinstance(said, Mapping) else 0

    def clear_places(self, role: str, pattern: str, *, bare: bool = False) -> int:
        try:
            said = self._ask("hosts_clear_places", role, pattern, bool(bare))
        except Exception as e:  # noqa: BLE001 - placed again by the firewall's own next ask
            self.problem = str(e)
            return 0
        return int((said or {}).get("cleared") or 0) if isinstance(said, Mapping) else 0

    # -- the routes ----------------------------------------------------------------------------------------------------
    def routed(self) -> set[str]:
        try:
            got = self._ask("hosts_routes")
        except Exception as e:  # noqa: BLE001 - none known: traced again, and kept if a firewall serves by then
            self.problem = str(e)
            return set()
        return {h for h in got or () if isinstance(h, str)}

    def routes_of(self, remotes) -> dict:
        wanted = [str(r) for r in remotes or () if r]
        if not wanted:
            return {}
        try:
            got = self._ask("hosts_routes", wanted)
        except Exception as e:  # noqa: BLE001 - none read back
            self.problem = str(e)
            return {}
        return {str(k): list(v) for k, v in (got or {}).items() if isinstance(v, list)} if isinstance(got, Mapping) else {}

    def keep_route(self, remote, traced, reached, how, hops, way) -> None:
        try:
            self._ask("hosts_keep_route", remote, traced, bool(reached), str(how or ""),
                      [dict(h) for h in hops or () if isinstance(h, Mapping)], str(way or ""))
        except Exception as e:  # noqa: BLE001 - not kept: traced again at a later ask
            self.problem = str(e)

    # -- what only the firewall does -----------------------------------------------------------------------------------
    def feed(self, *args, **kwargs) -> dict:
        return {"new": 0, "ended": 0, "open": 0}

    def flush(self, keep_open: bool = False) -> None:
        return None

    def close(self) -> None:
        return None

    def connections(self, limit: int = 0) -> list[dict]:
        return []

    def forget(self) -> int:
        raise ValueError(f"the hosts are recorded by {self.owner or 'the firewall'}: forget them on its page")


class GeoVia:
    """A GeoIP file's face (lookup, describe) over the places one `places` ask answered; `known` the addresses it was
    asked, so only those are placed (HostBook.place's `only`)."""

    def __init__(self, places: Mapping, stamp: str):
        self._places = {str(k): v for k, v in places.items()}
        self.known = frozenset(self._places)
        self.stamp = str(stamp or "")

    def lookup(self, address) -> geo.Place | None:
        said = self._places.get(str(address))
        if not isinstance(said, Mapping):
            return None
        try:
            return geo.Place(said.get("country"), said.get("country_name"), said.get("city"), said.get("lat"),
                             said.get("lon"), said.get("asn"), said.get("org"))
        except TypeError:
            return None

    def describe(self) -> dict:
        return {"date": self.stamp}


class PlacesVia:
    """The World Wide Web plugin's places, as NetstatView.page and its placing use a WorldView: `geoip()` asks `places`
    once (`ask(addresses)`: the answer, or an error), for `addresses()` (the reading's internet hosts and the hosts the
    database has no place for). None when no plugin answers or it has no GeoIP file (`why` says which)."""

    closed = False

    def __init__(self, ask, addresses):
        self._ask, self._addresses = ask, addresses
        self._geoip: GeoVia | None = None
        self.why = ""

    def geoip(self) -> GeoVia | None:
        if self._geoip is not None:
            return self._geoip
        try:
            wanted = list(self._addresses() if callable(self._addresses) else self._addresses or ())
            got = self._ask(wanted)
        except Exception as e:  # noqa: BLE001 - no place column, and why
            self.why = str(e)
            return None
        if not isinstance(got, Mapping) or not isinstance(got.get("places"), Mapping) or not got.get("stamp"):
            self.why = str((got or {}).get("why") or "no GeoIP file") if isinstance(got, Mapping) else "no answer"
            return None
        self._geoip = GeoVia(got["places"], got["stamp"])
        return self._geoip

    def stamp(self, geoip=None) -> str:
        found = geoip if geoip is not None else self._geoip
        return str(getattr(found, "stamp", "") or "")

    def rest(self) -> None:
        return None


def _plain(filters: Mapping) -> dict:
    """The filters a query passes, None left out (the firewall takes its defaults)."""
    return {k: v for k, v in filters.items() if v is not None}


def _rows(got) -> list[dict]:
    return [dict(r) for r in got or () if isinstance(r, Mapping)] if isinstance(got, (list, tuple)) else []


def _mapping(place) -> dict | None:
    if place is None:
        return None
    if isinstance(place, Mapping):
        return {k: place.get(k) for k in ("country", "country_name", "city", "lat", "lon", "asn", "org")}
    return {k: getattr(place, k, None) for k in ("country", "country_name", "city", "lat", "lon", "asn", "org")}
