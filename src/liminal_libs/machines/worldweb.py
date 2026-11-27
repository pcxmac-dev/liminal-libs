"""The World Wide Web tab as a plugin's base of its own (1.105.0, Monday list item 33; the user, 2026-11-23: "the
World Wide Web tab as a plugin of its own"): plugin-platform-worldwideweb is built on it. Until 1.105.0 the tab was the
Firewall base's (1.55.0); its code moved here method by method, its words kept: the traffic watched at this machine's
adapter (machines/world.py: a WorldView), its GeoIP sources, files and installs (1.101.0), the switch of the watching
(1.74.0), the globe's home, the globe's choices and the internet infrastructure's layers and data sets (1.65.0), the
routes traced (1.67.0), and (1.104.0, moved here with the tab) the satellites in the sky: the sgp4 package's download
and removal, the places of the satellites, CelesTrak's orbits refreshed by themselves while the tab is open, and the
layers read by the view's area past 6x. The settings are the system's and keep their names: LIMINAL_HOME_PLACE,
LIMINAL_TRAFFIC_WATCHING, the GeoIP sources chosen and each licence accepted, read through the same login; and so are
the files: the GeoIP files in the data folder, the infrastructure's folder and composite.db.

What only a firewall knows, it asks through the platform and never imports (plugins never import each other): the
socket table's reading (netstat_seen), the hosts recorded for the globe's hosts view (hosts_found), the routes kept and
a route traced kept (hosts_routes, hosts_keep_route), the places it looked up kept and cleared (hosts_keep_places,
hosts_clear_places), the rules covering a port of this machine's busiest (rules_covering, told in its pick), and on
Linux what an XDP program drops before the capture sees it (capture_unseen). The firewall
serving it is the one LIMINAL_WWW_FIREWALL names, else the first attached that answers netstat_seen, chosen again after
a refusal. With none, the tab draws the traffic it captures alone and says why. It offers one service back, `places`:
the GeoIP places of addresses, which a firewall's Netstat tab asks for its place column.

No lock of this plugin is held while it asks another plugin, and no service hook of either asks back, so the two
cannot wait on each other."""
from __future__ import annotations

import ipaddress
import json
import math
import sys
import threading
import time
from collections.abc import Mapping
from datetime import datetime, timezone

from .. import sockets
from ..apps import asking
from ..apps.authorization import (PREFERENCE, Unauthorized, accept_licence as keep_licence, asking_login, keep, keeps,
                                   licence_pair, recall)
from ..apps.tabs import Tab
from ..sources.keys import KeyVar
from . import asks, geosources, netstat, routes as routes_module, world as world_module
from .firewall import WATCH_FORM, WATCH_HOOK, WATCH_KEY, WATCH_READ_S, WATCH_VAR, WATCH_WORDS, geosources_pair
from .hostsvia import HostsVia
from .infrastructure import DataSet, Index
from .netstat import NetstatView
from .plugin import MachinePlugin
from .world import (ASN_HOOK, GEOIP_GET_HOOK, GEOIP_HOOK, GEOIP_REMOVE_HOOK, GEOIP_USE_HOOK, HOME_KEY, HOME_PLACE_VAR,
                    HOOK as WORLD_HOOK, LICENCE_FIRST, SETTING_S, TAB as WORLD_TAB, TIMEOUT_S, TITLE as WORLD_TITLE,
                    LicenceRefused, WorldView, not_here_page)

SERVES = "netstat_seen"  # the hook that tells a firewall that can serve the tab
UNSEEN_HOOK = "capture_unseen"  # a Linux firewall's: what an XDP program drops before the capture sees it
RULES_HOOK = "rules_covering"  # a firewall's rules covering a port, told in the port's pick
RULES_PORTS = 10  # the busiest ports here whose rules are asked, at most
RULES_S = 30.0  # a port's rules asked again after this long (a refusal too)
RULES_SHOWN = 8  # rules told in a port's pick, at most (the count says how many cover it)
PLACES_HOOK = "places"  # what it offers back
PLACES_MOST = 2000  # addresses placed in one ask, at most
FIREWALL_VAR = "LIMINAL_WWW_FIREWALL"
FIREWALL_KEY = KeyVar(FIREWALL_VAR, label="The firewall serving the World Wide Web tab", secret=False,
                      hint="optional: the name of the firewall plugin whose socket table and hosts database the tab "
                           "shows (firewall-windows, firewall-linux); nothing set, the first attached that answers")
NO_FIREWALL = ("No firewall plugin answers here, so no connection is read, no host recorded is shown and no route is "
               "kept: the globe shows the traffic captured at this machine's adapter alone.")
_WORLD_LOCK = threading.Lock()  # a plugin's WorldView made once, however many asks come at once
_NETSTAT_LOCK = threading.Lock()  # ... and its NetstatView in the globe's mode
# 1.104.0: the sgp4 package's licence accepted at the page, kept in the person's own store (the user's 13a), one pair
# a version (the user, 2026-11-26: asked again per version): licence-sgp4-2.27
SKY_LICENCE = "sgp4-{version}"


def sky_licence(version) -> str:
    """The name the sgp4 package's licence acceptance is kept under for that version (its pair: licence-<this>)."""
    return SKY_LICENCE.format(version=str(version))


class WorldWideWeb(MachinePlugin):
    """The base of the World Wide Web plugin: the tab (its hook `world`, a read asked every two seconds while it is
    shown), the GeoIP sources' and files' hooks, the watching's switch, the globe's choices and layers and the data
    sets' downloads, each as the Firewall base had them until 1.105.0. A subclass names its GeoIP sources
    (GEOIP_SOURCES), its data sets (INFRASTRUCTURE), its RDAP bootstrap files, its attribution and its name servers
    (PUBLIC_DNS), as the firewalls' apis.py named them, and makes a capture of its own in make_world_view when it needs
    one. What only a firewall knows it asks of the firewall serving it (`firewall`)."""

    HOOKS = (*MachinePlugin.HOOKS,
             WORLD_HOOK, GEOIP_HOOK, WATCH_HOOK, ASN_HOOK, GEOIP_GET_HOOK, GEOIP_USE_HOOK, GEOIP_REMOVE_HOOK,
             *netstat.GLOBE_HOOKS, PLACES_HOOK)
    # its reads: a layer's geometry, the satellites' places (1.104.0: world_sky) and the places it offers
    READ_HOOKS = (netstat.LAYER_HOOK, netstat.SKY_HOOK, PLACES_HOOK)
    SERVICE_HOOKS = (PLACES_HOOK,)  # a firewall's Netstat tab asks it for its place column
    # what it asks of a firewall, through the platform: "" for whichever offers it (internal.py's words)
    ASKS = (("", SERVES, "the socket table's reading now: the open connections the tab watches and traces"),
            ("", "hosts_found", "the hosts recorded, for the globe's hosts view"),
            ("", "hosts_routes", "the routes traced before, read back"),
            ("", "hosts_keep_route", "a route traced, kept in the hosts database"),
            ("", "hosts_keep_places", "the places its GeoIP files gave the hosts recorded, kept with them"),
            ("", "hosts_clear_places", "the places of a GeoIP file removed, cleared from the hosts recorded"),
            ("", RULES_HOOK, "the rules covering a port of this machine's busiest, told in the port's pick"),
            ("", UNSEEN_HOOK, "what the firewall drops before the capture sees it"))
    ICON = "globe"
    SECTION = "os"
    TABS = (Tab(WORLD_TAB, WORLD_TITLE, WORLD_HOOK, 2.0),)
    JOB_HOOKS = (GEOIP_HOOK, netstat.GET_HOOK, ASN_HOOK, GEOIP_GET_HOOK,
                 netstat.SKY_GET_HOOK)  # 1.104.0: the sgp4 package's download
    CANCEL_HOOKS = (netstat.GET_HOOK, GEOIP_GET_HOOK)
    # what only a person at the platform's page may ask (each refuses any other ask itself too: geosources.NotAsked):
    # the GeoIP sources' download, use and removal, the older installs, a data set's download (the user's 11b), and
    # (1.104.0) the sgp4 package's download and removal, code the plugin imports
    PAGE_ONLY_HOOKS = (GEOIP_GET_HOOK, GEOIP_USE_HOOK, GEOIP_REMOVE_HOOK, GEOIP_HOOK, ASN_HOOK, netstat.GET_HOOK,
                       netstat.SKY_GET_HOOK, netstat.SKY_REMOVE_HOOK)
    GEOIP_SOURCES: tuple = ()
    INFRASTRUCTURE: tuple = ()
    # 1.104.0 (Monday list item 32): the sgp4 package the satellites are placed with, as the plugin pins it ({version,
    # url, name, size, sha256, hosts, licence}): offered on the World Wide Web tab beside the data sets; None: none
    SKY_PACKAGE = None
    GEOIP_URL = ""
    RDAP_BOOTSTRAP: tuple = ()
    GEOIP_LICENCE = ""
    GEOIP_ASN_URL = ""
    GEOIP_ASN_LICENCE = ""
    ATTRIBUTION: dict = {}
    PUBLIC_DNS: tuple = ()
    WORLD_TIMEOUT = TIMEOUT_S
    keys = (HOME_KEY, WATCH_KEY, FIREWALL_KEY)

    # -- the firewall serving it (asked through the platform, never imported) ----------------------------------------
    def firewall(self) -> str:
        """The name of the firewall serving the tab now: the one chosen at the last ask that answered, else "" until
        one answers (`_seen` chooses)."""
        return str(self.__dict__.get("_firewall") or "")

    def _named(self) -> str:
        """LIMINAL_WWW_FIREWALL as the login says it ("" when unset or unreadable), read at most every SETTING_S."""
        kept = self.__dict__.get("_firewall_named")
        if kept is not None and time.monotonic() - kept[0] < SETTING_S:
            return kept[1]
        login = getattr(self, "login", None)
        try:
            raw = (login.variables([FIREWALL_VAR]) or {}).get(FIREWALL_VAR) if login is not None else None
        except Exception:  # noqa: BLE001 - a login that cannot say: none named
            raw = None
        name = str(raw or "").strip()
        self.__dict__["_firewall_named"] = (time.monotonic(), name)
        return name

    def firewalls(self) -> list[str]:
        """The attached plugins whose hooks list SERVES, the one named by LIMINAL_WWW_FIREWALL first, then in the
        platform's order. Asks only the app's list: no plugin is asked anything."""
        app = getattr(self, "app", None)
        try:
            faces = dict(app.plugins() or {}) if app is not None else {}
        except Exception:  # noqa: BLE001 - an app that cannot list its plugins: none
            faces = {}
        found = [n for n, f in faces.items()
                 if n != self.name and isinstance(f, Mapping) and SERVES in (f.get("hooks") or ())]
        named = self._named()
        return [named, *(n for n in found if n != named)] if named in found else found

    def _ask(self, hook: str, *args):
        """`hook` of the firewall serving the tab, asked through the platform (LookupError when none serves it)."""
        name = self.firewall()
        if not name:
            raise LookupError(NO_FIREWALL)
        return asks.ask(self, name, hook, *args)

    def _seen(self) -> dict:
        """The socket table's reading, the serving firewall's (netstat_seen): the one chosen before while it answers,
        else each in `firewalls`' order until one does, which serves from then on. LookupError, in words, when none
        answers. Asked with no lock of this plugin held."""
        kept = self.firewall()
        order = self.firewalls()
        tried = [kept] if kept in order else []
        tried += [n for n in order if n != kept]
        if kept and kept not in order:
            self.__dict__["_firewall"] = ""
        why = []
        for name in tried:
            try:
                seen = asks.ask(self, name, SERVES)
            except Exception as e:  # noqa: BLE001 - one that refuses: the next is asked, and its words kept
                why.append(f"{name}: {e}")
                continue
            if name != kept:
                self.__dict__["_firewall"] = name
                net = self.netstat_view(make=False)
                if net is not None:
                    net.replaced()
            return seen if isinstance(seen, Mapping) else {}
        self.__dict__["_firewall"] = ""
        raise LookupError(" ".join([NO_FIREWALL, *(f"({w})" for w in why)]))

    def _unseen(self, view) -> str:
        """What the serving firewall says it drops before the capture sees it at the adapter watched ("" for none, or
        when it offers no such word)."""
        name = self.firewall()
        address = str(getattr(view, "address", "") or "")
        if not name or not address:
            return ""
        try:
            face = dict(self.app.plugins() or {}).get(name) or {}
            if UNSEEN_HOOK not in (face.get("hooks") or ()):
                return ""
            said = asks.ask(self, name, UNSEEN_HOOK, address)
        except Exception:  # noqa: BLE001 - a word not had never costs the tab its page
            return ""
        return str(said or "")

    def _rules(self, port: int, proto: str) -> list | None:
        """The serving firewall's rules covering port/proto (rules_covering), kept RULES_S seconds per firewall and
        port; None when it does not offer them or refused (kept as long, so a refusal is not asked again every two
        seconds). Asked with no lock of this plugin held."""
        name = self.firewall()
        if not name:
            return None
        kept = self.__dict__.setdefault("_rules_kept", {})
        at = kept.get((name, port, proto))
        now = time.monotonic()
        if at is not None and now - at[0] < RULES_S:
            return at[1]
        try:
            face = dict(self.app.plugins() or {}).get(name) or {}
            said = asks.ask(self, name, RULES_HOOK, port, proto) if RULES_HOOK in (face.get("hooks") or ()) else None
            got = [r for r in said if isinstance(r, Mapping)] if isinstance(said, list) else None
        except Exception:  # noqa: BLE001 - rules not had never cost the tab its page
            got = None
        if len(kept) > 4 * RULES_PORTS:  # the ports change: the oldest let go
            for k in sorted(kept, key=lambda k: kept[k][0])[:len(kept) - 2 * RULES_PORTS]:
                kept.pop(k, None)
        kept[(name, port, proto)] = (now, got)
        return got

    def _rules_onto(self, page) -> None:
        """Into the pick of each of the RULES_PORTS busiest ports here (Busiest ports here's details, keyed
        here:<port>/<proto>): a section of the serving firewall's rules covering it, the ones naming it first, as the
        firewall gives them (rules_covering). Nothing with no firewall serving or none offering them."""
        for table in (page or {}).get("tables") or ():
            if not isinstance(table, dict) or table.get("title") != "Busiest ports here":
                continue
            asked = 0
            for d in table.get("details") or ():
                key = str(d.get("key") or "") if isinstance(d, dict) else ""
                if not key.startswith("here:") or asked >= RULES_PORTS:
                    continue
                number, _, proto = key[5:].partition("/")
                if not number.isdigit() or proto not in ("tcp", "udp"):
                    continue
                asked += 1
                rules = self._rules(int(number), proto)
                if rules is None:
                    continue
                facts = [[str(r.get("label") or r.get("name") or "a rule")[:120],
                          " · ".join(x for x in (str(r.get("direction") or ""), str(r.get("action") or ""),
                                                 "on" if r.get("enabled", True) else "off",
                                                 "Liminal's" if r.get("owned") else "", str(r.get("why") or ""),
                                                 str(r.get("program") or "")) if x)[:400]]
                         for r in rules[:RULES_SHOWN]]
                title = f"Firewall rules covering it ({len(rules):,}, {self.firewall()})"
                if facts:
                    d.setdefault("sections", []).append({"title": title, "facts": facts})
                else:
                    d["note"] = " ".join(x for x in (str(d.get("note") or ""), f"No rule of {self.firewall()} covers it.") if x)

    # -- what it offers back -----------------------------------------------------------------------------------------
    def places(self, addresses) -> dict:
        """The GeoIP places of addresses, for a firewall's Netstat tab (a read other plugins ask).

        {"places": {address: {country, country_name, city, lat, lon, asn, org} or None}, "stamp": the files' stamp,
        "why": why none is placed, or ""}. At most PLACES_MOST addresses are taken; a private, local or unreadable one
        gets no place. The GeoIP files on this machine are opened for the ask and let go after it unless the capture
        runs. Asks nobody."""
        self._only_here()
        if not isinstance(addresses, (list, tuple)):
            raise ValueError("places are asked of a list of addresses")
        wanted = list(dict.fromkeys(str(a) for a in addresses[:PLACES_MOST] if isinstance(a, str) and a))
        view = self.world_view()
        geoip = None
        try:
            geoip = view.geoip()
            if geoip is None:
                return {"places": {}, "stamp": "", "why": "no GeoIP file is installed: the World Wide Web tab offers one"}
            stamped = getattr(view, "stamp", None)
            try:
                stamp = str(stamped(geoip) if callable(stamped) else (geoip.describe() or {}).get("date") or "")
            except Exception:  # noqa: BLE001 - a file that cannot say its date: placed as of none
                stamp = ""
            out: dict[str, dict | None] = {}
            for address in wanted:
                out[address] = _place_of(geoip, address)
            return {"places": out, "stamp": stamp, "why": ""}
        finally:
            view.rest()

    # -- the World Wide Web tab (1.55.0; machines/world.py), moved from the Firewall base -----------------------------
    def world_view(self, make: bool = True) -> WorldView | None:
        """This plugin's World Wide Web tab: made when first asked (make_world_view), kept until the plugin is detached.
        `make=False`: the view there is, or None, never making one (for what asks nothing: the plugin's API card's facts,
        before the tab was first asked since the plugin was attached)."""
        view = self.__dict__.get("_world")
        if view is None and make:
            with _WORLD_LOCK:
                view = self.__dict__.get("_world")
                if view is None:
                    view = self.__dict__["_world"] = self.make_world_view()
        return view

    def make_world_view(self) -> WorldView:
        """The WorldView the tab watches with: every packet at the adapter of this machine's way out (world.default_capture),
        the GeoIP files in the data folder, WORLD_TIMEOUT seconds of watching after the last ask. A subclass with a capture
        of its own (another adapter, a stand-in in its tests) makes it here."""
        return WorldView(self.name, timeout=self.WORLD_TIMEOUT, sources=self.world_sources())

    def world_sources(self):
        """What a WorldView is given of the GeoIP sources (its `sources`): (those that read, what was wrong with the
        others, the choice's reader); None when the plugin names none."""
        if not self.GEOIP_SOURCES:
            return None
        read, refused = geosources.read(self.GEOIP_SOURCES, self._declared_keys())
        return read, refused, self.geoip_choice

    def geoip_choice(self, fresh: bool = False) -> dict:
        """The GeoIP sources chosen, {"places": id, "networks": id} ({} for the default's), kept per machine through
        the plugin's login (geosources.SETTING where it keeps settings, else its own LIMINAL_GEOIP_SOURCES), read at
        most every world.SETTING_S."""
        kept = self.__dict__.get("_geoip_choice")
        if not fresh and kept is not None and time.monotonic() - kept[0] < SETTING_S:
            return dict(kept[1])
        login = getattr(self, "login", None)

        def from_variable():
            try:
                raw = (login.variables([geosources.VAR]) or {}).get(geosources.VAR) if login is not None else None
                return json.loads(raw) if raw else None
            except Exception:  # noqa: BLE001 - nothing kept, or nothing that reads: the default's
                return None
        try:
            value = recall(login, geosources.SETTING, from_variable) if login is not None else None
        except Exception:  # noqa: BLE001 - a login that cannot say: the default's
            value = None
        choice = {r: str(value[r]) for r in geosources.ROLES if isinstance(value, dict) and isinstance(value.get(r), str)}
        self.__dict__["_geoip_choice"] = (time.monotonic(), choice)
        return dict(choice)

    @staticmethod
    def _at_the_page() -> bool:
        """Whether this ask is a person's, signed in at the platform's page: the page asks it (asking.PAGE), and the
        asking login keeps settings (a person's own store, not the platform's EnvironmentLogin)."""
        return asking.asker() == asking.PAGE and keeps(asking_login())

    def _geoip_gate(self, source, role, *, offered: bool = True):
        """The checks every GeoIP sources hook makes first, each local and in words: not for this machine; no sources,
        or a source or role the plugin does not name (or, with `offered`, does not offer); not a person signed in at
        the platform's page (geosources.NotAsked). (the view, the source, its file)"""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")
        if not self.GEOIP_SOURCES:
            raise ValueError(f"{self.title or self.name} names no GeoIP sources")
        view = self.world_view()
        named, file = view.source(source), view.file_of(source, role)
        if file is None:
            raise ValueError(f"{self.title or self.name} names no {world_module._shown(role)} file of a GeoIP source "
                             f"{world_module._shown(source)}")
        if offered and not named.offered:
            raise ValueError(f"{named.title} is not offered: waiting for your word")
        if not self._at_the_page():
            raise geosources.NotAsked()
        return view, named, file

    def _geoip_replaced(self, view) -> None:
        view.replaced()
        net = self.netstat_view(make=False)
        if net is not None:
            net.replaced()

    def world_geoip_get(self, source, role, accept_licence=False, log=None) -> dict:
        """A GeoIP source's file downloaded, on the word of a person signed in at the platform's page: run as a job
        (`log` its panel; Cancel stops it). Refused first, each in words and before anything is read or asked of
        anyone: not for this machine; a source or role not named or not offered; not a person at the page; a key not
        set in their login store (by name, no value read); the licence not accepted (world.LicenceRefused, naming
        accept_licence: the page asks it as a second confirmation with the licence's words); another download under
        way. Then, in the job: the keys read through the asking person's login and checked, the acceptance kept in
        their own login store (a store that refuses ends it, nothing fetched), and the download (WorldView.get)."""
        view, named, file = self._geoip_gate(source, role)
        login = asking_login()
        if named.keys:
            try:
                have = login.names()
            except Exception:  # noqa: BLE001 - a store that cannot list: the job reads them and says
                have = None
            missing = [n for n in named.keys if have is not None and geosources_pair(n) not in have]
            if missing:
                raise ValueError(f"{', '.join(missing)} is not set in your login store: add it "
                                 f"{geosources.WHERE_KEYS}")
        if accept_licence is not True:
            raise LicenceRefused(f"{file.title} is downloaded only once you accept its licence.")
        if view._installing.locked():
            raise ValueError("a GeoIP file is being downloaded already: wait for it to finish")
        return self._geoip_download(view, named, file, login, log)

    def _geoip_download(self, view, named, file, login, log) -> dict:
        secrets = geosources.credentials(named, login)
        now = datetime.fromtimestamp(view.wall(), timezone.utc)
        built = now.strftime("%Y-%m") if file.monthly else now.strftime("%Y-%m-%d")
        said = geosources.licence_of(file, built)
        try:
            keep_licence(login, said.pop("name"), **said, file=False)
        except Unauthorized as e:
            raise ValueError(f"your acceptance of {file.title}'s licence could not be kept in your login store "
                             f"({e.reason}): nothing was downloaded") from None
        out = view.get(named.id, file.role, secrets, log=log,
                       cancel=lambda: bool(getattr(log, "cancelled", False)))
        self._geoip_replaced(view)
        out.setdefault("lines", []).append("your acceptance of its licence is kept in your own login store")
        return out

    def world_geoip_use(self, source, role) -> dict:
        """A GeoIP source's file, installed already, used for its role from now on, on this machine (the choice kept
        through the plugin's login, as the traffic's watching is): asked by a person signed in at the platform's page.
        The hosts are placed again from it at the next ask."""
        view, named, file = self._geoip_gate(source, role)
        if view.installed(named.id, role) is None:
            raise ValueError(f"{file.title} is not installed: download it first")
        login = getattr(self, "login", None)
        if login is None:
            raise ValueError("no login to keep the choice through: sign in first")
        if named.id != view.default and not keeps(login) and sys.platform != "win32":
            raise ValueError("the choice cannot be kept here: the platform's login on this system keeps a setting only "
                             "until the platform stops, so the default source stays in use")
        choice = {**self.geoip_choice(fresh=True), role: named.id}

        def to_variable(value) -> None:
            login.save(geosources.VAR, json.dumps(value, sort_keys=True))
        try:
            where = keep(login, geosources.SETTING, choice, to_variable, PREFERENCE, "the GeoIP sources chosen")
        except Exception as e:  # noqa: BLE001 - a login that keeps nothing: its own words
            raise ValueError(f"the choice could not be kept: {e}") from None
        self.__dict__.pop("_geoip_choice", None)
        self._geoip_replaced(view)
        return {"said": f"{file.title} is used for {role}", "ok": True,
                "lines": [f"kept in {where}", "the hosts are placed again from it at the next ask"]}

    def world_geoip_remove(self, source, role, accept_removal=False) -> dict:
        """A GeoIP source's file removed, with its notes, on the word of a person signed in at the platform's page,
        asked twice (geosources.RemovalRefused, naming accept_removal, until the second). A source no longer offered
        may still be removed. The places it gave are cleared from the hosts database where no file in use gives
        them, and placed again at the next ask."""
        view, named, file = self._geoip_gate(source, role, offered=False)
        if accept_removal is not True:
            raise geosources.RemovalRefused(f"{file.title} is removed only once you confirm it a second time.")
        out = view.remove(named.id, role)
        if out.get("ok") and view.chosen()[role]["source"] != named.id:
            net = self.netstat_view(make=False)
            if net is not None and not net.elsewhere():
                # the default's own rows carry the bare date, as before 1.101.0 (geosources.stamp)
                net.book.clear_places(role, geosources.cleared(role, named.id), bare=named.id == view.default)
        self._geoip_replaced(view)
        return out

    def world_home(self, view: WorldView | None = None):
        """The place the user set for this machine on the globe (LIMINAL_HOME_PLACE, "lat,lon[,label]"), read through this
        plugin's login, the one way to a setting, at most every world.SETTING_S; None when none is set, nobody is signed in
        or the login cannot say."""
        login = getattr(self, "login", None)
        if login is None:
            return None

        def read():
            try:
                return (login.variables([HOME_PLACE_VAR]) or {}).get(HOME_PLACE_VAR) or None
            except Exception:  # noqa: BLE001 - a login that cannot say: no place set
                return None
        return (view or self.world_view()).setting(read)

    def _geoip_keys(self, view) -> set | None:
        """1.101.0: the keys the offered sources need that the asking person's login store holds, by name alone (never
        a value); None when none is asked of anyone or the store cannot list."""
        wanted = [n for s in getattr(view, "sources", None) or () if s.offered for n in s.keys]
        if not wanted:
            return None
        login = asking_login()
        if not keeps(login):
            return set()
        try:
            have = login.names()
        except Exception:  # noqa: BLE001 - a store that cannot list: not known
            return None
        return None if have is None else {n for n in wanted if geosources_pair(n) in have}

    def world_watch_mode(self, fresh: bool = False) -> str:
        """When the traffic is watched, as the login says (WATCH_VAR, read every WATCH_READ_S at most): "shown" (also
        with no login or nothing set) or "always"."""
        kept = self.__dict__.get("_watch")
        if not fresh and kept is not None and time.monotonic() - kept[0] < WATCH_READ_S:
            return kept[1]
        login = getattr(self, "login", None)
        try:
            raw = (login.variables([WATCH_VAR]) or {}).get(WATCH_VAR) if login is not None else None
        except Exception:  # noqa: BLE001 - a login that cannot say: shown
            raw = None
        mode = "always" if str(raw or "").strip().lower() == "always" else "shown"
        self.__dict__["_watch"] = (time.monotonic(), mode)
        return mode

    def world_watch_follow(self) -> None:
        """The watching follows its setting: always, started now and never stopped for want of an ask (only by the
        plugin's detach or the platform's stop); shown, stopped WORLD_TIMEOUT after the tab's last ask, as before.
        Only the capture: the routes are still traced only while the tab is shown. Nothing on a machine the plugin is
        not for."""
        if self.not_for_here():
            return
        try:
            if self.world_watch_mode(fresh=True) == "always":
                view = self.world_view()
                view.watcher.timeout = math.inf
                view.touch()
            else:
                view = self.world_view(make=False)
                if view is not None:
                    view.watcher.timeout = view.timeout
        except Exception:  # noqa: BLE001 - a capture that cannot start: its tab says why when it is asked
            pass

    def world_watching(self, mode) -> dict:
        """The traffic watched "shown" (only while the World Wide Web tab is shown) or "always" (all the time the
        platform runs, with no page open), kept through the plugin's login (WATCH_VAR); the watching follows at
        once. ValueError, in words: neither word, no login, a login that keeps nothing, a machine not for it."""
        self._only_here()
        word = str(mode or "").strip().lower()
        if word not in WATCH_WORDS:
            raise ValueError(f"the traffic is watched shown or always, not {world_module._shown(mode)}")
        login = getattr(self, "login", None)
        if login is None:
            raise ValueError("no login to keep the setting through: sign in first")
        try:
            where = login.save(WATCH_VAR, word)
        except Exception as e:  # noqa: BLE001 - a login that keeps nothing: its own words
            raise ValueError(f"the setting could not be kept: {e}") from None
        self.world_watch_follow()
        return {"said": f"the traffic watched {WATCH_WORDS[word]}", "ok": True, "lines": [f"kept in {where}"]}

    def _watch_table(self) -> tuple[dict, dict]:
        """The World Wide Web tab's table of the switch, and its form."""
        mode = self.world_watch_mode()
        form = {"id": WATCH_FORM, "hook": WATCH_HOOK, "title": "Watching the traffic",
                "fields": [{"name": "mode", "label": "Watch the traffic", "type": "choice", "value": mode,
                            "choices": [{"value": "shown", "title": "Only while this tab is shown"},
                                        {"value": "always", "title": "All the time the platform runs",
                                         "note": "the capture keeps running with no page open"}]}],
                "confirm": {"title": "Change when the traffic is watched?", "yes": "Change it", "words": (
                    "Watching is set to {mode}. Always keeps the capture at this machine's adapter running for as long "
                    "as the platform runs, with no page open too, counting the packets, the ports and the places as "
                    "this tab does; nothing is sent anywhere. The routes are still traced only while this tab is "
                    "shown. The choice is kept through your login.")}}
        table = {"title": "Watching the traffic", "note": "Whether the capture keeps running while this tab is not "
                 "shown (the switch is kept through your login).", "columns": [{"title": "Watched"}, {"title": ""}],
                 "rows": [[WATCH_WORDS[mode], {"form": WATCH_FORM, "title": "Change…"}]]}
        return table, form

    def world_geoip(self, accept_licence=False, log=None) -> dict:
        """The GeoIP file installed for the World Wide Web tab, on the user's word: a change, asked only from the tab's
        install form, never by the page on its own, and run by the platform as a job (JOB_HOOKS: `log` is its panel,
        given each step and the bytes downloaded with their percent, at most every two seconds). Refused before anything
        is said or done (world.LicenceRefused, naming accept_licence, which the platform's page asks as a second, explicit
        confirmation with the licence's words) unless `accept_licence` is exactly True. Then this month's file at
        GEOIP_URL is downloaded (last month's when this month's is not out yet) and put in place (WorldView.install: one
        deadline for all of it, https on every hop from the plugin's own host); what was installed, in words."""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")
        if self.GEOIP_SOURCES:  # 1.101.0: the default source's places file
            return self._default_install("places", accept_licence, log, LICENCE_FIRST)
        if not self.GEOIP_URL:
            raise ValueError(f"{self.title or self.name} offers no GeoIP file to download")
        if accept_licence is not True:
            raise LicenceRefused(LICENCE_FIRST)
        return self.world_view().install(self.GEOIP_URL, log=log)

    def world_asn(self, accept_licence=False, log=None) -> dict:
        """1.75.0: the ASN file installed beside the GeoIP file, on the user's word, as world_geoip installs that:
        asked only from its form, run as a job, refused (world.LicenceRefused) unless `accept_licence` is exactly
        True; then this month's file at GEOIP_ASN_URL (last month's while this month's is not out) put in the GeoIP
        folder's asn/, and each place's network read from it from then on."""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")
        if self.GEOIP_SOURCES:  # 1.101.0: the default source's networks file
            return self._default_install("networks", accept_licence, log,
                                         "The ASN file is downloaded only once you accept its licence.")
        if not self.GEOIP_ASN_URL:
            raise ValueError(f"{self.title or self.name} offers no ASN file to download")
        if accept_licence is not True:
            raise LicenceRefused("The ASN file is downloaded only once you accept its licence.")
        return self.world_view().install(self.GEOIP_ASN_URL, log=log, kind="asn")

    def _default_install(self, role: str, accept_licence, log, first: str) -> dict:
        """1.101.0: world_geoip and world_asn with GEOIP_SOURCES: the default source's file of `role`. Its acceptance is
        kept only for a person signed in at the platform's page (in their own login store, or nothing is downloaded);
        any other ask downloads as before 1.101.0 and records nothing."""
        view = self.world_view()
        named, file = view.source(view.default), view.file_of(view.default, role)
        if file is None:
            raise ValueError(f"{self.title or self.name} offers no {role} file to download")
        if named.keys:
            raise ValueError(f"{file.title} needs a key: ask it from the GeoIP sources table")
        if accept_licence is not True:
            raise LicenceRefused(first)
        if self._at_the_page():
            return self._geoip_download(view, named, file, asking_login(), log)
        out = view.get(named.id, role, log=log, cancel=lambda: bool(getattr(log, "cancelled", False)))
        self._geoip_replaced(view)
        return out

    def world_show(self, what) -> dict:
        """What the globe shows: "traffic" (watched now, the default) or "hosts" (recorded in the hosts database).

        A choice of its page, kept in this plugin until it is detached; its answer says the filter in words. ValueError
        on a machine the plugin is not for, as for every choice of the globe."""
        self._only_here()
        return self.netstat_view().show(what)

    def world_direction(self, direction) -> dict:
        """The hosts recorded of one direction on the globe: "out", "in", or "" for both (the globe shows the hosts)."""
        self._only_here()
        return self.netstat_view().direction(direction)

    def world_within(self, within) -> dict:
        """The hosts last seen within "hour", "day", "week" or "month", or "" for any time, on the globe.

        The globe shows the hosts recorded."""
        self._only_here()
        return self.netstat_view().within(within)

    def world_pick(self, choice) -> dict:
        """A program's hosts on the globe (program=<name>), every host on a port (port=<tcp|udp>/<number>), or clear.

        program= and port= alone pick every program, every port; clear takes every filter back. The globe shows the
        hosts recorded."""
        self._only_here()
        return self.netstat_view().pick(choice)

    def world_layer(self, layer, area=None, zoom=None) -> dict:
        """One infrastructure layer's geometry for the globe, read from this machine's database (a read).

        The page asks it once a layer's version, with the layer's id (Index.layer); 1.104.0: and, past the globe's
        AREA_ZOOM, with the view's `area` ([west, south, east, north] in degrees) and its `zoom`, so the globe asks
        for what it shows. LookupError when none is installed, ValueError for an area or a zoom that is none and on a
        machine the plugin is not for."""
        self._only_here()
        return self.netstat_view().layer(layer, area=area, zoom=zoom)

    def world_layer_get(self, dataset, accept_licence=False, log=None) -> dict:
        """A data set of INFRASTRUCTURE downloaded on the user's word, run by the platform as a job (Cancel stops it).

        Refused (world.LicenceRefused, naming accept_licence, asked by the page as a second confirmation with the
        licence's words) until its licence is accepted; then one https request to the data set's own host, read under
        one deadline and kept on this machine's disk in place of any older copy (infrastructure.install). ValueError for
        a data set this plugin does not name, and on a machine it is not for.

        1.101.0 (the user's 13a): asked by a person signed in at the platform's page, the acceptance is kept in their
        own login store as licence-<the data set's id>, as DB-IP's are, once the download's own refusals passed and
        before anything is fetched (a store that refuses ends it, nothing fetched); any other ask downloads as before
        and records nothing."""
        self._only_here()
        view = self.netstat_view()
        if accept_licence is not True or not self._at_the_page():
            return view.get(dataset, accept_licence, log)
        found, login = view.index.dataset(dataset), asking_login()

        def accepted() -> None:
            try:
                keep_licence(login, found.id, title=found.title, version=found.licence_name,
                             url=str(dict(found.credit).get("url") or ""), words=found.licence, file=False)
            except Unauthorized as e:
                raise ValueError(f"your acceptance of {found.title}'s licence could not be kept in your login store "
                                 f"({e.reason}): nothing was downloaded") from None
        out = view.get(dataset, accept_licence, log, accepted=accepted)
        if out.get("ok"):
            out.setdefault("lines", []).append("your acceptance of its licence is kept in your own login store")
        return out

    def world_layer_remove(self, dataset) -> dict:
        """A data set's file removed from this machine, confirmed on the page: the globe no longer draws its layers.

        ValueError on a machine the plugin is not for: the layers' folder is this system's, and its own plugin's
        files are left as they are."""
        self._only_here()
        return self.netstat_view().drop(dataset)

    # -- the satellites (1.104.0, moved here from the Firewall base with the tab) --------------------------------------
    def _sky(self):
        self._only_here()
        sky = getattr(self.netstat_view(), "sky", None)
        if sky is None:
            raise ValueError("this plugin names no satellites")
        return sky

    def world_sky(self, t=None) -> dict:
        """The satellites' places for the globe at `t` (seconds since 1970; now when not given) and a minute later,
        worked out with the sgp4 package downloaded for it (a read): {"needs": why} without it. The page asks it while
        the tab is shown, once a minute at most."""
        return self._sky().read(t)

    def world_sky_get(self, accept_licence=False, log=None) -> dict:
        """The sgp4 package downloaded on the user's word (a job): its size and sha256 checked, each file against its
        RECORD, unpacked into the data folder's packages/ and imported from there alone (satellites.install_package).
        world.LicenceRefused until its licence is accepted. Only a person signed in at the platform's page may ask it
        (PAGE_ONLY_HOOKS, and geosources.NotAsked here to any other ask): it is code this plugin then imports."""
        from . import satellites
        sky = self._sky()
        if sky.package is None:
            raise ValueError("this plugin pins no sgp4 package")
        if not self._at_the_page():
            raise geosources.NotAsked()
        package = sky.package
        if accept_licence is True:  # the user's 13a: the acceptance kept in their own login store, as a data set's
            try:
                keep_licence(asking_login(), sky_licence(package.version), title=f"The sgp4 package {package.version}",
                             version=package.licence_name, url=package.source.url, words=package.licence, file=False)
            except Unauthorized as e:
                raise ValueError(f"your acceptance of the sgp4 package's licence could not be kept in your login "
                                 f"store ({e.reason}): nothing was downloaded") from None
        out = satellites.install_package(package, sky.data_dir, accept_licence=accept_licence, log=log,
                                         cancel=lambda: bool(getattr(log, "cancelled", False)))
        if out.get("ok"):
            out.setdefault("lines", []).append("your acceptance of its licence is kept in your own login store")
        return out

    def world_sky_remove(self) -> dict:
        """The sgp4 package's folder removed, confirmed on the page: the satellites are no longer placed. The page's
        alone, as its download is."""
        from . import satellites
        sky = self._sky()
        if sky.package is None:
            raise ValueError("this plugin pins no sgp4 package")
        if not self._at_the_page():
            raise geosources.NotAsked()
        try:
            return satellites.remove_package(sky.package, sky.data_dir)
        finally:  # placed with it no more: a folder marked removed is not loaded again (satellites.load_package)
            sky.sky._package = None

    # -- the routes (1.67.0), kept in the serving firewall's hosts database ------------------------------------------
    def world_routes(self) -> routes_module.Routes:
        """The routes of this plugin's World Wide Web tab (1.67.0, machines/routes.py): made when first asked, closed
        when the plugin is detached or the platform stops."""
        routes = self.__dict__.get("_routes")
        if routes is None:
            with _WORLD_LOCK:
                routes = self.__dict__.get("_routes")
                if routes is None:
                    routes = self.__dict__["_routes"] = self.make_world_routes()
        return routes

    def make_world_routes(self) -> routes_module.Routes:
        """The Routes the tab traces with: the system's own (netpath.trace), each route kept in the serving firewall's
        hosts database (hosts_keep_route). A subclass's tests hand a stand-in."""
        return routes_module.Routes(keep=self._keep_route, bootstrap=self.RDAP_BOOTSTRAP, known=self._routed,
                                    stored=self._stored_routes)

    def _routed(self) -> set[str]:
        """The hosts the serving firewall's hosts database has a route to: each is not traced again."""
        return set() if self.not_for_here() else self.netstat_view().book.routed()

    def _stored_routes(self, addresses) -> dict:
        """The routes the serving firewall's hosts database keeps of these hosts, read back for the tab."""
        return {} if self.not_for_here() else self.netstat_view().book.routes_of(addresses)

    def _keep_route(self, *route) -> None:
        """A traced route into the serving firewall's hosts database; nothing on a machine the plugin is not for, or
        with no firewall serving."""
        if not self.not_for_here():
            self.netstat_view().book.keep_route(*route)

    # -- the tab's page ------------------------------------------------------------------------------------------------
    def world(self) -> dict:
        """The World Wide Web tab's page (apps/tabs.py), asked every two seconds while the tab is shown.

        Each ask reads the socket table through the serving firewall (netstat_seen: recorded there while a tab is shown,
        unless always) and, while the globe shows the traffic, keeps the watching going: a capture at this machine's
        adapter, which stops by itself WORLD_TIMEOUT seconds after the last ask, and on detach. The page is what has
        been counted: the globe with the places traffic came from and went to (placed by the GeoIP file on this
        machine) and their routes to home, the busiest ports' charts, the ports and the places tabled, and the GeoIP
        file's install form while none is installed; or, while it shows the hosts recorded, each program's remote hosts
        by place, as the firewall's hosts database recorded them. With no firewall serving, the traffic captured alone,
        and why. Always what the globe shows and the internet infrastructure's layers and data sets (NetstatView.onto).
        1.104.0: asked by a person signed in at the page, the data sets refreshed by themselves that are due
        (CelesTrak's orbits, every 2 hours at most) are downloaded again (NetstatView.refresh): only while the tab is
        open. Not for this machine (not_for_here): a page saying so, and nothing started."""
        here = self.not_for_here()
        if here:
            return not_here_page(here)
        view = self.world_view()
        net = self.netstat_view()
        if self._at_the_page():  # 1.104.0: what is refreshed by itself (CelesTrak's orbits), while a person looks
            try:
                net.refresh()
            except Exception:  # noqa: BLE001 - a refresh never costs the tab its page
                pass
        seen = net.touch()  # the firewall asked here, with no lock of this plugin held
        alone = self.firewall() == ""
        remotes = [r.get("remote") for r in seen.get("rows") or ()
                   if isinstance(r, Mapping) and r.get("remote") and r.get("where") == sockets.WHERE[2]]
        routes = self.world_routes()
        try:
            if not alone and not getattr(view, "closed", False):  # routes are kept by a firewall: none, none traced
                routes.want(remotes)
        except Exception:  # noqa: BLE001 - the routes never cost the tab its page
            pass
        attribution = dict(self.ATTRIBUTION) if isinstance(self.ATTRIBUTION, dict) and self.ATTRIBUTION else None
        if getattr(view, "sources", None):  # 1.101.0: the places file's in use
            attribution = (view.credits() or {}).get("places") or attribution
        frame = {"home": self.world_home(view), "public": self.PUBLIC_DNS, "attribution": attribution,
                 "can_install": bool(self.GEOIP_URL), "licence": self.GEOIP_LICENCE, "source": self.GEOIP_URL,
                 "asn_source": self.GEOIP_ASN_URL, "asn_licence": self.GEOIP_ASN_LICENCE,
                 "keys": self._geoip_keys(view)}
        if alone and net.shows() == "hosts":  # no hosts recorded to show: the traffic, and the note says why
            net.show("traffic")
        page = None
        if net.shows() == "traffic":
            view.touch()
            page = view.page(**frame)
        page = net.onto(page, view, **frame)
        try:
            routes.onto(page, view.geoip(), remotes, index=net.index, licence=frame["licence"])
        except Exception:  # noqa: BLE001 - the routes never cost the tab its page
            pass
        finally:
            view.rest()
        globe = page.get("globe") if isinstance(page, dict) else None
        if isinstance(globe, dict):  # 1.106.0 (item 27): a heat always, an empty one where the routes failed, so the
            # globe draws no route then, never the straight lines it draws a page without one
            globe.setdefault("heat", [])
            globe.setdefault("heat_by", "connections")
        try:  # 1.74.0: the switch of the traffic's watching, its table and its form (kept through a login: with one)
            if getattr(self, "login", None) is not None:
                table, form = self._watch_table()
                page.setdefault("tables", []).append(table)
                page.setdefault("forms", []).append(form)
        except Exception:  # noqa: BLE001 - the switch never costs the tab its page
            pass
        if not alone:  # Monday list item 31: a port picked is told the rules that cover it
            try:
                self._rules_onto(page)
            except Exception:  # noqa: BLE001 - the rules never cost the tab its page
                pass
        words = [NO_FIREWALL] if alone else []
        unseen = "" if alone else self._unseen(view)
        if unseen:
            words.append(unseen)
        if words:
            page["note"] = " ".join(x for x in (str(page.get("note") or ""), *words) if x)
        under = world_module.under_wsl()  # inside a WSL distribution: what WSL changes for the tab
        if under is not None and isinstance(page.get("tables"), list):
            page["tables"].append(under)
        return page

    # -- its globe's view of the hosts: a NetstatView in the globe's mode ---------------------------------------------
    def netstat_view(self, make: bool = True) -> NetstatView | None:
        """The globe's choices, layers and hosts view (machines/netstat.py in the globe's mode, records=False): made
        when first asked (make_netstat_view), kept until the plugin is detached. `make=False`: the view there is, or
        None."""
        view = self.__dict__.get("_netstat")
        if view is None and make:
            with _NETSTAT_LOCK:
                view = self.__dict__.get("_netstat")
                if view is None:
                    view = self.__dict__["_netstat"] = self.make_netstat_view()
        return view

    def make_netstat_view(self) -> NetstatView:
        """The NetstatView the globe asks, recording nothing: its reading the serving firewall's (`_seen`), its hosts
        database that firewall's (hostsvia.HostsVia), the data sets of INFRASTRUCTURE as the Firewall base read them,
        and (1.104.0) the sky where those name satellites (sky_onto). A subclass's tests make it here with stand-ins."""
        sets, refused, ids = [], [], set()
        for said in self.INFRASTRUCTURE or ():
            try:
                found = DataSet.of(said)
            except ValueError as e:
                refused.append(str(e))
                continue
            if found.id in ids:
                refused.append(f"the data set {found.id} is named twice: its first is kept")
                continue
            ids.add(found.id)
            sets.append(found)
        view = NetstatView(self.name, reader=self._seen, book=HostsVia(self._ask, self.firewall),
                           login_of=lambda: getattr(self, "login", None), index=Index(datasets=sets), refused=refused,
                           agent=netstat.agent_of(self.name, self.version), records=False)
        return self.sky_onto(view)

    def sky_onto(self, view: NetstatView) -> NetstatView:
        """1.104.0 (moved here with the tab): the sky set up on the globe's view (view.sky, a satellites.SkyView) where
        its data sets name satellites (an omm-csv set) and none is set yet, with the plugin's SKY_PACKAGE; a pin that
        does not read sets none. The view, for make_netstat_view to hand back."""
        if getattr(view, "sky", None) is None and any(
                d.format == "omm-csv" for d in getattr(getattr(view, "index", None), "datasets", ())):
            from . import satellites
            try:
                view.sky = satellites.SkyView(view.index, self.SKY_PACKAGE)
            except ValueError:  # a pin that does not read: no sky
                view.sky = None
        return view

    def _only_here(self) -> None:
        """A ValueError in words on a machine this plugin is not for (not_for_here), asked first by every hook of the
        globe's choices and layers and of the places: there none of them makes a view, keeps a setting or removes a
        data set."""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")

    def _declared_keys(self) -> list[str]:
        return [str(getattr(k, "name", k)) for k in (getattr(self, "keys", None) or ())]

    @property
    def KEEPS(self) -> tuple:
        """What it keeps through its login beside its keys (Plugin.KEEPS, for its Internal API tab): the GeoIP sources
        chosen, and each offered file's licence acceptance (in the asking person's own store), and each data set's of
        INFRASTRUCTURE (licence-<its id>, the same), and (1.104.0) the sgp4 package's, one pair a version
        (licence-sgp4-<version>). Said by name: no login is asked."""
        kept = []
        if self.GEOIP_SOURCES:
            kept.append((geosources.VAR, "the GeoIP sources chosen for places and for networks"))
            read, _ = geosources.read(self.GEOIP_SOURCES, self._declared_keys())
            for source in read:
                if source.offered:
                    kept += [(f"licence-{f.licence.pair}", f"your acceptance of {f.title}'s licence, in your own "
                              "login store") for f in source.files]
        for said in self.INFRASTRUCTURE or ():
            try:
                found = DataSet.of(said)
            except (TypeError, ValueError):
                continue
            pair = licence_pair(found.id)
            if pair not in dict(kept):
                kept.append((pair, f"your acceptance of {found.title}'s licence, in your own login store"))
        version = self.SKY_PACKAGE.get("version") if isinstance(self.SKY_PACKAGE, dict) else getattr(
            self.SKY_PACKAGE, "version", None)
        if version:  # 1.104.0: the sgp4 package's, the same, one a version
            kept.append((licence_pair(sky_licence(version)), f"your acceptance of the sgp4 package {version}'s "
                                                              "licence, in your own login store"))
        return tuple(kept)

    # -- attached, told, detached --------------------------------------------------------------------------------------
    def attach(self, app, login=None) -> dict:
        """Attached by its app as every plugin is; then, on a machine it is for, the traffic's watching follows its
        setting (never in a one-shot app). Nothing is asked of a firewall until the tab is."""
        out = super().attach(app, login)
        if not self.not_for_here() and not getattr(app, "once", False):
            self.world_watch_follow()
        return out

    def app_stopping(self) -> None:
        """The platform stops: the routes let go (a platform stopped may start again in this process). It bears a
        second call."""
        with _WORLD_LOCK:
            routes = self.__dict__.pop("_routes", None)
        if routes is not None:
            routes.close()

    def settings_changed(self) -> None:
        """The platform kept one of this plugin's settings: the home, the GeoIP sources chosen and the firewall named
        are read anew at the tab's next ask, and the traffic's watching follows its setting at once."""
        view = self.world_view(make=False)
        if view is not None:
            view.forget_setting()
        self.__dict__.pop("_geoip_choice", None)
        self.__dict__.pop("_firewall_named", None)
        if not self.not_for_here():
            self.world_watch_follow()

    def detach(self) -> None:
        """Detached by its app: the globe's view closed, then the watching (WorldView.close: its capture closed, its
        thread gone, its GeoIP file let go, an ask still under way starting nothing) and the routes, all forgotten; then
        the plugin detached as every plugin is."""
        with _NETSTAT_LOCK:
            net = self.__dict__.pop("_netstat", None)
        if net is not None:
            net.close()
        with _WORLD_LOCK:
            view = self.__dict__.pop("_world", None)
            routes = self.__dict__.pop("_routes", None)
        self.__dict__["_firewall"] = ""
        if view is not None:
            view.close()
        if routes is not None:
            routes.close()
        super().detach()


def _place_of(geoip, address: str) -> dict | None:
    """One address's place as a plain mapping, or None: a private, local or unreadable address, or one the file has no
    point for."""
    try:
        if not ipaddress.ip_address(address).is_global:
            return None
        found = geoip.lookup(address)
    except Exception:  # noqa: BLE001 - an address that does not read, or a lookup that fails, places nothing
        return None
    if found is None:
        return None
    get = found.get if isinstance(found, Mapping) else (lambda name: getattr(found, name, None))
    if isinstance(found, Mapping):
        return {k: found.get(k) for k in ("country", "country_name", "city", "lat", "lon", "asn", "org")}
    return {"country": get("country"), "country_name": get("country_name"), "city": get("city"), "lat": get("lat"),
            "lon": get("lon"), "asn": get("asn"), "org": get("org")}
