"""The firewalls' World Wide Web tab (the user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web
view' that shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats"). A WorldView
watches this machine's traffic while the tab is looked at, and answers the tab's page (apps/tabs.py): the globe, with each
place traffic came from or went to and its route to this machine; the busiest ports' bytes in and out over the last ten
minutes; and tables of the busiest ports and places.

- Watching runs only while the user looks (the user's decision, 2026-11-14). touch() starts a traffic.Watcher around a
  capture, or keeps it going. It stops by itself `timeout` seconds after the last touch, on stop(), and for good on
  close() (the plugin's detach: an ask still under way then starts nothing). The capture is the capture module's pull
  source for every packet at the adapter of this machine's way out:
  TCP and UDP, IPv4 and IPv6, the headers alone (default_capture). When it cannot run (no Npcap or libpcap, no right to
  capture, Npcap installed for administrators only), the page says why and how to put it right, and it is tried again
  RETRY_S later at the soonest. Nothing here asks for a password or for an administrator.
- Counters, never packets. The TrafficBook keeps its own caps. The charts keep their samples for the last WINDOW_S
  (MAX_SAMPLES at most), and the globe draws MAX_DRAWN places at most, the rest summed as "more".
- Data stays on this machine. Places come from the GeoIP file in the data folder (geo.GeoIP), mapped only while the tab
  is watched or asked: once watching stops, the file is let go, and opened again at the next ask. No peer's address is
  sent anywhere, and none is looked up by name. A data folder on another system's drive (WSL's /mnt/c, a share:
  geo.foreign) holds that system's files: none is read or installed from here, and the page says so.
- Home is the place the user set (LIMINAL_HOME_PLACE, "lat,lon[,label]", read through the plugin's login). Else it is
  where the GeoIP file puts this network's public address, asked once of the name servers the plugin names
  (dns.public_address: they are asked for the name that answers with the asker's own address, nothing about any peer).
  Else there is none, and the globe draws the places without their routes.
- The GeoIP file is downloaded only on the user's word (install): this month's file at the plugin's address, or last
  month's when this month's is not out yet, streamed into geo.install_mmdb with its bounds, under one deadline for all
  of it (geo.INSTALL_S), over https on every hop and from the plugin's own host alone. The address is the plugin's: no
  outside host is named in the library.
- 1.102.0 (Monday list item 20): a plugin may name GeoIP sources (machines/geosources.py), for places and for networks
  apart, the first the default (today's files and folders). The view then opens the chosen files (`choose`, kept by the
  plugin), checks at every ask that neither is too old to be read, and answers the "GeoIP sources" table, whose
  Download… (`get`), Use… and Remove… (`remove`) take the place of the two install buttons. A source's key is read only
  in its download's job, sent only to its own host in the first address, and never said: its words go through
  geosources.redact, and a keyed download's failures are said in fixed words."""
from __future__ import annotations

import functools
import inspect
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import threading
import time
import urllib.error
from collections import Counter, deque
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .. import capture, dns, geo, netpath, traffic
from ..sources.keys import KeyVar
from . import geosources

TITLE = "World Wide Web"
TAB = "world"  # the tab's id: its charts' keys begin with it
HOOK = "world"  # the tab's read hook, asked with no arguments
GEOIP_HOOK = "world_geoip"  # the change the install form asks, as a job (its progress followed on the page)
FORM = "world-geoip"  # the install form's id
# 1.75.0 (the user, 2026-11-22: "Yes, do it", asked whether to fill the hop table's empty ASN and Operator columns
# from DB-IP's free ASN file): the ASN file's install, as a job, and its form
ASN_HOOK = "world_asn"
ASN_FORM = "world-asn"
ACCEPT_LICENCE = "accept_licence"  # its one argument: true only through the page's second confirmation
HOME_PLACE_VAR = "LIMINAL_HOME_PLACE"  # "lat,lon[,label]": where this machine is drawn, when the user says
HOME_KEY = KeyVar(HOME_PLACE_VAR, label="Home on the globe", secret=False,
                  hint="optional: lat,lon[,label] in degrees, south and west below 0 (48.86,2.35,Paris); without it, "
                       "the GeoIP file places this network's public address")
TIMEOUT_S = 20.0  # watching stops this long after the tab was last asked
RETRY_S = 15.0  # a capture that could not start is tried again after this long at the soonest
SETTING_S = 30.0  # the home the user set is read again through the login after this long
GEO_LOOK_S = 10.0  # while no GeoIP file is open, the folder is looked at again after this long
HOME_RETRY_S = 900.0  # a public address the name servers did not give is asked for again after this long
WINDOW_S = 600.0  # the charts' ten minutes
MAX_SAMPLES = 400  # samples kept for the charts (one an ask: the tab is asked every few seconds)
SAMPLE_PORTS = 16  # ports kept in one sample, the busiest
MIN_SAMPLE_S = 0.5  # two asks closer than this make one sample
GAP_S = 5.0  # an ask later than the timeout and this: watching paused in between, and the charts' lines break there
CHART_PORTS = 4  # the busiest ports here charted
MAX_DRAWN = 300  # places drawn on the globe: the most connections first, the rest summed as "more"
ORIGIN_ROWS = 50  # places in the places' table
PORT_ROWS = 25  # ports in the busiest ports' table
REMOTE_ROWS = 15  # ports in the ports elsewhere's table
# each socket operation of the GeoIP download waits this long at most (less once less is left): the whole install, its
# fetches with their connections, TLS, headers and redirects included, keeps one deadline, geo.INSTALL_S
READ_S = 60.0
MAX_REDIRECTS = 3  # redirects a download follows, each to its own host over https
POLL_S = 0.25  # how often an install looks at its deadline, and for a detach, while its download runs
GRACE_S = 5.0  # once its time is up, the download's thread is waited for this long (its sockets shut) before it is said
LOCAL_S = 120.0  # a download read to its end is waited for this long more: checked and put in place on this machine
PROGRESS_S = 2.0  # the bytes downloaded so far are said at most this often
PROBE6 = "2001:db8::1"  # IPv6's documentation prefix: a UDP socket "connected" to it shows this machine's way out
KIND_WORDS = {"allowed": "allowed in", "unanswered": "unanswered in", "outbound": "out"}  # as the globe's legend says them
UNITS = ("B", "KB", "MB", "GB", "TB", "PB")
USER_AGENT = "liminal-libs (GeoIP download)"
LICENCE_FIRST = "The GeoIP file is downloaded only once you accept its licence."
DETACHED = "the plugin was detached, so the download was stopped: nothing was installed"
CANCELLED = "the download was cancelled: nothing was installed"
# 1.102.0: the GeoIP sources' hooks (each asked from its form alone, by a person signed in at the page) and forms
GEOIP_GET_HOOK = "world_geoip_get"  # a source's file downloaded, as a job (Cancel stops it)
GEOIP_USE_HOOK = "world_geoip_use"  # a source's file used for its role
GEOIP_REMOVE_HOOK = "world_geoip_remove"  # a source's file removed, asked twice
GET_FORM, USE_FORM, REMOVE_FORM = "world-geoip-get-", "world-geoip-use-", "world-geoip-remove-"  # + <source>-<role>
ACCEPT_REMOVAL = "accept_removal"
SOURCES_TITLE = "GeoIP sources"
CHECKSUM_MOST = 4096  # bytes of a maker's checksum answer read at most
SHOWN = 40  # characters of a setting that is no place shown back in the words
# what capture.py adds to the words of every libpcap open that failed off Windows, whatever the cause: never taken for
# libpcap's own word that the right to capture is missing
LIBRARY_HINT = " (packets are watched as root, or with CAP_NET_RAW)"
NSLOOKUP_PACKAGES = "dnsutils on Debian and Ubuntu, bind-utils on Fedora, bind-tools on Arch and Alpine"
NUMBERS = re.compile(r"[+-]?\d+(?:[.,]\d+)*(?:\s*,\s*[+-]?\d+(?:[.,]\d+)*)*")  # a label that is numbers: decimal commas
_WORLD_DOWNLOADS = threading.local()  # the install a download's thread runs for (its _Cutoff): its sockets go there


class LicenceRefused(ValueError):
    """The GeoIP file not downloaded until the user accepts its licence: `accept` names the argument that, exactly true,
    makes the download; the platform's page asks it as a second, explicit confirmation, the licence's words in it."""

    accept = ACCEPT_LICENCE


class RedirectRefused(urllib.error.URLError):
    """A GeoIP download sent on (an HTTP redirect) to an address that is no https one on the plugin's own host (http,
    ftp, another host), or an answer that came from one: never followed, nothing read of it."""


# -- what the tab watches --------------------------------------------------------------------------------------------------
def route_address() -> str | None:
    """The address this machine goes out from: the IPv4 default route's (netpath.lan_address), else the IPv6 one's. A UDP
    socket "connected" to a documentation address shows it, and nothing is sent. None without a network."""
    address = netpath.lan_address()
    if address:
        return address
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect((PROBE6, 9))
            found = str(s.getsockname()[0]).split("%")[0]
    except OSError:
        return None
    return None if found in ("", "::") else found


def default_capture() -> capture.Capture:
    """The capture the tab watches by default, not started: every packet the adapter of this machine's way out sees
    (route_address), TCP and UDP, IPv4 and IPv6, to and from any of its addresses, the headers alone. A traffic.Watcher
    opens it, pulls it on its one thread and closes it. CaptureError when there is no network to watch."""
    address = route_address()
    if address is None:
        raise capture.CaptureError("this machine has no network to watch: no default route")
    return capture.Capture(address, udp=True, payloads=False, host=False)


def _root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    try:
        return bool(callable(geteuid) and geteuid() == 0)
    except OSError:
        return False


def _inside(path: str, folder: str) -> bool:
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # different drives, or one relative
        return False


def _python(executable: str | None = None, prefix: str | None = None, base_prefix: str | None = None) -> tuple[str, bool]:
    """This Python as the platform runs it: (its file, the links followed; whether it is the platform's own copy, a file
    of a venv's own made with --copies, rather than the system's interpreter, which a venv links to and every program
    and every user runs). A hard link to the system's interpreter is that very file under another name: never its own
    (a file with more than one name). `executable`, `prefix` and `base_prefix` stand in for sys's in tests."""
    exe = os.path.abspath(executable or sys.executable or "python3")
    real = os.path.realpath(exe)
    prefix = sys.prefix if prefix is None else prefix
    base = getattr(sys, "base_prefix", sys.prefix) if base_prefix is None else base_prefix
    try:
        alone = os.stat(real).st_nlink == 1
    except OSError:
        alone = False
    return real, bool(prefix != base and alone and not os.path.islink(exe) and _inside(real, os.path.realpath(prefix)))


def _init() -> str:
    """The init the platform's boot service is made under, on Linux (the admin plugins' boot services, machines/admin.py):
    "systemd" (a system unit; sd_booted's own test), "openrc" (an init script), "other" (none is made); "" off Linux,
    where nothing says (a test's: both ways are told)."""
    if not sys.platform.startswith("linux"):
        return ""
    if os.path.isdir("/run/systemd/system"):
        return "systemd"
    return "openrc" if os.path.isdir("/run/openrc") else "other"


def _permission(e: str) -> bool:
    """Whether libpcap's own words (lowercased, the library's hint taken out) say the right to capture is missing."""
    return "permission" in e or "not permitted" in e or "cap_net_raw may be required" in e


def _capability_help(python: tuple[str, bool] | None = None, init: str | None = None) -> str:
    """The right to capture, for a platform on Linux that runs without it: CAP_NET_RAW alone (a capture that is not
    promiscuous needs no more; never CAP_NET_ADMIN, which rewrites the firewall), and for the platform alone: in its
    system unit (under systemd), or on a copy of Python that is its own. Never on the system's Python, which every
    program and every user runs (a venv's python links to it). `init`: _init()'s word (under OpenRC, or another init, no
    system unit starts the platform, so only its own copy of Python is told)."""
    path, own = _python() if python is None else python
    init = _init() if init is None else init
    unit = ("in the system unit that starts the platform (the Linux administration plugin's boot service, "
            "liminal-platform-boot.service), AmbientCapabilities=CAP_NET_RAW under [Service]; or" if init in ("systemd", "")
            else "")
    head = "Packets are watched with CAP_NET_RAW, which the platform runs without. Give that one right to the platform alone: "
    if own:
        return (head + (f"{unit}, since" if unit else "as") + f" this Python ({path}) is the platform's own copy, an "
                f"administrator can give it that right (setcap cap_net_raw=ep {path}), keeping the copy the platform's "
                "user's alone (chmod 0750, its group the platform's): whoever can run it gets the right. Then restart the "
                "platform.")
    return (head + (f"{unit} " if unit else "") + "run the platform from a copy of Python that is its own (python3 -m venv "
            "--copies), kept the platform's user's alone (chmod 0750) and given that right (setcap cap_net_raw=ep on that "
            f"copy's python). Never give it to the system's Python ({path}): every program and every user that runs it "
            "would have it. Then restart the platform.")


def capture_help(error: str, windows: bool | None = None, root: bool | None = None) -> str:
    """How to make watching possible, in words, for what stopped it (`error`: the capture's own words). Never by typing a
    password here: what needs an administrator is said, for the user to do. `windows`: whether this is Windows, and
    `root`: whether the platform runs as root (this machine's own word for either when not given).

    On Linux the right to capture is advised only when libpcap's own words say it is missing (not the library's hint
    after every failure: LIBRARY_HINT), and only to a platform that is not root: CAP_NET_RAW alone, for the platform
    alone (_capability_help). On Windows, Npcap installed for administrators only is never opened from here (opening it
    would ask for an administrator: capture.ADMIN_ONLY): its installer's option, or the platform run as an
    administrator."""
    windows = sys.platform == "win32" if windows is None else windows
    e = (error or "").lower().replace(LIBRARY_HINT.lower(), "")
    if "no network" in e or "no default route" in e:
        return "Connect this machine to a network, then show this tab again."
    held = re.search(r"no adapter holds (\S+)", error or "", re.IGNORECASE)
    if held:
        address = held.group(1).strip(".,;:()")
        if windows:
            return (f"Npcap lists no adapter holding this machine's address ({address}): it may not be bound to that "
                    "adapter (a VPN's, or one added after Npcap was installed). Install Npcap again to bind it to every "
                    "adapter, then show this tab again.")
        return (f"libpcap lists no adapter holding this machine's address ({address}): the adapter may have gone (a VPN "
                "reconnecting, another Wi-Fi network) or be in another network namespace. Show this tab again once it is "
                "back.")
    if "npcap was installed for administrators only" in e:  # capture.ADMIN_ONLY: not opened, nothing asked of anyone
        return ("Npcap was installed for administrators only, and opening it would ask for an administrator, so it is not "
                "opened. Install Npcap again with \"Restrict Npcap driver's access to Administrators only\" unticked "
                "(Wireshark's installer includes it), or run the platform as an administrator; then show this tab again.")
    if windows:
        if "npcap is not installed" in e or "wpcap.dll" in e:
            return ("Install Npcap (Wireshark's installer includes it), leaving \"Restrict Npcap driver's access to "
                    "Administrators only\" unticked, then show this tab again.")
        if "could not be opened" in e or "denied" in e or "administrator" in e:
            return ("Npcap may be installed for administrators only: install it again with \"Restrict Npcap driver's access "
                    "to Administrators only\" unticked, then show this tab again.")
    else:
        if "libpcap is not installed" in e or "libpcap could not be loaded" in e:
            return ("Install libpcap (libpcap0.8 on Debian and Ubuntu; libpcap on Fedora, Arch and Alpine), then show this "
                    "tab again.")
        if _permission(e):
            if _root() if root is None else root:
                return ("The platform runs as root, and still the adapter could not be opened: a container, or a security "
                        "module (AppArmor, SELinux), may forbid packet sockets here. Show this tab again once that is put "
                        "right.")
            return _capability_help()
    return "Show this tab again once that is put right."


def _shown_error(error: str) -> str:
    """The capture's words as the page says them: the library's hint after a libpcap open that failed (root, or
    CAP_NET_RAW) kept only where libpcap itself says the right is missing."""
    if LIBRARY_HINT in (error or "") and not _permission((error or "").lower().replace(LIBRARY_HINT.lower(), "")):
        return error.replace(LIBRARY_HINT, "")
    return error


# -- the home the user sets ---------------------------------------------------------------------------------------------
def _shown(value) -> str:
    """A setting that is no place, as the words show it back: its first SHOWN characters."""
    text = value if isinstance(value, str) else repr(value)
    cut = text if len(text) <= SHOWN else text[:SHOWN] + "…"
    return repr(cut) if isinstance(value, str) else cut


def _degrees(value, limit: float, what: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"the {what} is a number of degrees, not {_shown(value)}")
    try:
        out = float(str(value).strip()) if isinstance(value, str) else float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"the {what} is a number of degrees, not {_shown(value)}") from None
    if not -limit <= out <= limit:  # NaN is neither
        raise ValueError(f"the {what} is from -{limit:g} to {limit:g} degrees, not {_shown(value)}")
    return out


def home_place(value) -> dict | None:
    """A home as the globe draws it, {lat, lon, label}, from what the user set: LIMINAL_HOME_PLACE's "lat,lon[,label]"
    (degrees north and east, south and west below 0, decimals after a point; the label may hold commas, but is no number),
    a dict with lat and lon (and a label), or (lat, lon[, label]). None when nothing is set; ValueError, saying why, for
    what is no place (the value shown back in SHOWN characters at most)."""
    if value is None:
        return None
    if isinstance(value, Mapping):
        lat, lon, label = value.get("lat"), value.get("lon"), value.get("label")
    elif isinstance(value, (tuple, list)):
        if len(value) not in (2, 3):
            raise ValueError("a place is a latitude and a longitude, and a label if you like")
        lat, lon, label = value[0], value[1], value[2] if len(value) == 3 else ""
    else:
        text = str(value).strip()
        if not text:
            return None
        parts = [p.strip() for p in text.split(",", 2)]
        if len(parts) < 2:
            raise ValueError(f"a place is lat,lon[,label], not {_shown(text)}")
        lat, lon, label = parts[0], parts[1], parts[2] if len(parts) == 3 else ""
        if label and NUMBERS.fullmatch(label):  # 48,86,2,35: decimal commas, read as 48, 86 and a label of 2,35
            raise ValueError(f"degrees take a decimal point, not a comma (48.86,2.35,Paris): {_shown(text)} holds more "
                             "numbers than a latitude and a longitude")
    return {"lat": _degrees(lat, 90.0, "latitude"), "lon": _degrees(lon, 180.0, "longitude"),
            "label": str(label or "").strip()[:80] or "the place you set"}


def _absolute(name) -> str:
    """A DNS name made absolute (a trailing dot), so nslookup appends none of this machine's search suffixes to it
    (Windows' would, sending them to the server asked before the name itself)."""
    text = str(name or "").strip()
    return text if not text or text.endswith(".") else text + "."


def _entry(entry) -> tuple | None:
    """A name server to ask, in dns.public_address's shape (the name, made absolute; its type; the server; whose); None
    for anything else."""
    if isinstance(entry, (str, bytes)):  # no server: four letters would unpack as one
        return None
    try:
        name, rtype, server, whose = entry
    except (TypeError, ValueError):
        return None
    return _absolute(name), rtype, server, whose


def servers_of(public, version: int) -> tuple:
    """The name servers to ask for this network's public address of `version` (4 or 6), from what the plugin names
    (`public`): each in dns.public_address's shape, (the name, its type, the server, whose), the name made absolute (a
    trailing dot: no search suffix of this machine's goes with it). A dict {4: ..., 6: ...} gives them by version; a list
    is split by the server's address (one named, not numbered, is asked for either)."""
    if not public:
        return ()
    if isinstance(public, Mapping):
        return tuple(e for e in map(_entry, public.get(version) or public.get(str(version)) or ()) if e)
    out = []
    for entry in map(_entry, public):
        if entry is None:
            continue
        try:
            asked = ipaddress.ip_address(str(entry[2]).strip().strip("[]")).version
        except ValueError:
            asked = None
        if asked in (None, version):
            out.append(entry)
    return tuple(out)


def nslookup_path() -> str | None:
    """Where nslookup is (what dns.public_address runs to ask the name servers), None when this machine has none."""
    return shutil.which("nslookup")


def nslookup_missing(windows: bool | None = None) -> str:
    windows = sys.platform == "win32" if windows is None else windows
    where = ("it comes with Windows, in System32, which this process's PATH does not reach" if windows
             else NSLOOKUP_PACKAGES)
    return f"nslookup is not installed here ({where}), so this network's public address cannot be asked for"


# -- the GeoIP download --------------------------------------------------------------------------------------------------
def _where(url: str) -> str:
    """An address in words: its scheme and host (its path is no one's business here)."""
    try:
        parts = urlsplit(str(url or ""))
        host = parts.hostname or ""
    except ValueError:
        return "an address that is none"
    return f"{parts.scheme.lower()}://{host}" if parts.scheme and host else (str(url or "")[:80] or "nowhere")


def _over_https(url: str, host: str, what: str = "a GeoIP file", hosts=()) -> None:
    """RedirectRefused unless `url` is https on `host`, or (1.102.0) on one of `hosts`, those its plugin names for the
    download to be sent on to (a maker's storage). `what`: what is downloaded, for the words (a GeoIP file; a data set
    of machines/infrastructure.py). The words name a host alone, never an address's path or query."""
    try:
        parts = urlsplit(str(url or ""))
        there = (parts.hostname or "").lower()
    except ValueError:
        parts, there = None, ""
    allowed = {host, *(str(h).lower() for h in hosts or ())}
    if parts is None or parts.scheme.lower() != "https" or there not in allowed:
        alone = f"{host} alone" if len(allowed) == 1 else f"{host} and the hosts its plugin names for it alone"
        raise RedirectRefused(f"it was sent on to {_site(url)}, and {what} comes over https from {alone}")


def _site(url: str) -> str:
    """1.102.0: an address in words as _where says it, its scheme and host, yet never any of the address itself when
    no host parses (a keyed address's query may hold a key)."""
    try:
        parts = urlsplit(str(url or ""))
        host = parts.hostname or ""
    except ValueError:
        return "an address that is none"
    return f"{parts.scheme.lower()}://{host}" if parts.scheme and host else "an address that is none"


def _shut(sock) -> None:
    """A socket shut both ways (a read waiting on it then ends: at once on Linux; on Windows within its own timeout at
    most); one closed already is let be."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except (OSError, ValueError, AttributeError):
        pass


class _Cutoff:
    """One install's stop. The sockets its download's connections opened are handed to it (_handed), and shut when it is
    stopped: its deadline passed, or the plugin detached. Every read of the download is refused from then on (`why` says
    why). Once its stream was read to its end (`ended`) it is not stopped any more: what is left, checking the file and
    putting it in place, is this machine's own. Bounded: a socket or two a connection, MAX_REDIRECTS + 1 connections a
    month's file, two months."""

    def __init__(self):
        self.lock = threading.Lock()
        self.sockets: list = []
        self.why = ""  # why it was stopped; "" while it goes on
        self.ended = False  # the stream read to its end
        # its download's thread still ran when the install stopped waiting for it (run_download): a read waiting on a
        # shut socket ends at once on Linux, and on Windows only within its own timeout
        self.left = False

    def hand(self, sock) -> None:
        with self.lock:
            if not self.why:
                self.sockets.append(sock)
                return
        _shut(sock)  # opened after the stop: shut at once

    def stop(self, why: str) -> bool:
        """Stopped now (the first words why are kept), its sockets shut: True; False when its stream was read to its end
        already (nothing is stopped then)."""
        with self.lock:
            if self.ended:
                return False
            self.why = self.why or why
            sockets, self.sockets = self.sockets, []
        for s in sockets:
            _shut(s)
        return True


def _handed(sock) -> None:
    """A socket a download's connection opened, handed to the install the thread runs for, if any (_Cutoff.hand)."""
    cutoff = getattr(_WORLD_DOWNLOADS, "cutoff", None)
    if cutoff is not None:
        cutoff.hand(sock)


def run_download(work, cutoff: _Cutoff, deadline: float, took: str, *, name: str, stopping=None, clock=None,
                 late: str = "", what: str = "the GeoIP file", error=None):
    """A download run on a thread of its own while the caller waits for it, under one deadline: what `work()` gives. The
    GeoIP file's install waits so, and a data set's (machines/infrastructure.py): a read waiting on a socket ends
    neither for a deadline nor for a cancel by itself, so the waiting side ends it.

    The thread is named `name`, and the sockets its connections open are handed to `cutoff` (_handed). Every POLL_S the
    caller looks at the time (`clock`, the GeoIP install's when not given, against `deadline`: `took` says it has
    passed) and at `stopping()` (the words why the download must end now, "" to go on: the plugin detached, the user
    cancelled). Then the sockets are shut (cutoff.stop: a read waiting on one ends), the thread is waited for GRACE_S,
    and `error` (geo.GeoError when not given) is raised with those words, unless the work was done meanwhile; a thread
    still running then is noted on the cut-off (`left`: its read ends within its socket's timeout at most). A stream
    read to its end (cutoff.ended) is not stopped: what is left is this machine's own, waited for LOCAL_S more, then
    `error` with `late`. What `work` raised is raised here, as `error` with the cut-off's words when it was stopped.
    `what`: what is downloaded, for the words when no thread could be started."""
    error = geo.GeoError if error is None else error
    clock = clock or (lambda: geo._clock())  # geo's as it is now: a test's stand-in clock too
    result: dict = {}
    done = threading.Event()

    def download() -> None:
        _WORLD_DOWNLOADS.cutoff = cutoff
        try:
            result["out"] = work()
        except BaseException as e:  # noqa: BLE001 - said by the install waiting for it
            result["error"] = e
        finally:
            _WORLD_DOWNLOADS.cutoff = None
            done.set()

    worker = threading.Thread(target=download, name=name, daemon=True)
    try:
        worker.start()
    except RuntimeError as e:  # no thread to download on: nothing done
        raise error(f"{what} could not be downloaded: {e}") from None
    while not done.is_set():
        left = deadline - clock()
        stop = took if left <= 0 else (cutoff.why or (stopping() if stopping is not None else ""))
        if stop:
            if cutoff.stop(stop):
                done.wait(GRACE_S)  # its sockets shut: its thread ends soon, and puts nothing in place
                if "out" in result:  # done before it needed to read (this month's file there already)
                    break
                cutoff.left = not done.is_set()
                raise error(cutoff.why or stop)
            if not done.wait(LOCAL_S):  # read to its end: what is left is this machine's own, not stopped
                raise error(late or f"{what} was downloaded, and what was left to do here took more than "
                            f"{_seconds(LOCAL_S)} s")
            break
        done.wait(min(POLL_S, left))
    if "error" in result:
        if cutoff.why:
            raise error(cutoff.why) from None
        raise result["error"]
    return result["out"]


@functools.lru_cache(maxsize=None)
def _transport() -> tuple[type, type, type]:
    """The https connection, urllib's https handler and its redirect handler for a GeoIP download, made once (ssl is
    imported then): (Connection, Https, SameHost)."""
    import http.client
    import urllib.request

    class Connection(http.client.HTTPSConnection):
        """An https connection whose sockets reach the install its thread runs for (_handed): the plain one as it is
        connected (a proxy's tunnel is read on it), then the TLS one (the answer and the body are read on it), so they
        are shut when the install's time is up."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            create = self._create_connection

            def created(*a, **k):
                sock = create(*a, **k)
                _handed(sock)
                return sock
            self._create_connection = created

        def connect(self):
            super().connect()
            _handed(self.sock)

    class Https(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(Connection, req, context=self._context)

    class SameHost(urllib.request.HTTPRedirectHandler):
        """Redirects followed only to `host`, over https, MAX_REDIRECTS at most, and the body of each never read (urllib
        reads it whole, without a bound); any other is refused before anything is asked of it (RedirectRefused)."""

        max_redirections = MAX_REDIRECTS

        def __init__(self, host: str, what: str = "a GeoIP file", hosts=()):
            self.host, self.what = host, what  # `what` is downloaded: for a refusal's words
            self.hosts = tuple(hosts or ())  # 1.102.0: the other hosts its plugin names for it to be sent on to

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            try:
                _over_https(newurl, self.host, self.what, self.hosts)
                new = super().redirect_request(req, fp, code, msg, headers, newurl)
            except BaseException:
                _close(fp)  # refused: its connection let go now, nothing read of it
                raise
            if new is not None:
                _close(fp)
            return new

    return Connection, Https, SameHost


def fetch_url(url: str, timeout: float = READ_S, *, handlers=(), agent: str = USER_AGENT, what: str = "a GeoIP file",
              hosts=()):
    """The download's stream: an HTTP GET of `url`, https on every hop: a redirect is followed only to the same host over
    https (MAX_REDIRECTS at most, its body never read), and one anywhere else (http, ftp, another host) is refused before
    anything is asked of it (RedirectRefused); the address the answer came from is checked again. Each socket operation
    waits `timeout` seconds at most, and the sockets it opens reach the install its thread runs for, which shuts them
    when its time is up. urllib's HTTPError (its code 404 when the file is not there) or URLError when it cannot be had;
    ValueError for an address that is no https one. `handlers`: a test's stand-ins for the protocols (no socket).

    `agent`: the request's User-Agent, a product's name and its version and nothing of the user's or the machine's: the
    library's own for a GeoIP file, a plugin's name and version for a data set it downloads
    (machines/infrastructure.py). `what`: what is downloaded, for the words of a refusal (a GeoIP file; a data set).
    `hosts` (1.102.0): the other hosts a redirect may go to, and the answer come from (a GeoIP source's storage, as its
    plugin names them); none: the same host alone, as before."""
    import urllib.request

    try:
        parts = urlsplit(str(url or ""))
        host = (parts.hostname or "").lower()
    except ValueError:
        parts, host = None, ""
    if parts is None or parts.scheme.lower() != "https" or not host:
        raise ValueError(f"{what} is downloaded over https only")
    _, https, same_host = _transport()
    opener = urllib.request.build_opener(same_host(host, what, hosts), *(handlers or (https(),)))
    request = urllib.request.Request(url, headers={"User-Agent": str(agent or USER_AGENT)})
    response = opener.open(request, timeout=timeout)  # noqa: S310 - the plugin's own https address, on the user's word
    try:
        _over_https(_answered_from(response, url), host, what, hosts)
    except RedirectRefused:
        _close(response)
        raise
    return response


def _answered_from(stream, url: str) -> str:
    """The address an answer says it came from (http.client's `url`, else urllib's older geturl()); `url` when it says
    none."""
    where = getattr(stream, "url", None)
    if not isinstance(where, str) or not where:
        geturl = getattr(stream, "geturl", None)
        try:
            where = geturl() if callable(geturl) else None
        except Exception:  # noqa: BLE001 - a stream that cannot say: the address asked
            where = None
    return str(where) if where else url


def months(now: float) -> list[tuple[int, int]]:
    """This month and the one before it (UTC), as (year, month): the files a download tries, in order."""
    d = datetime.fromtimestamp(now, timezone.utc)
    return [(d.year, d.month), (d.year, d.month - 1) if d.month > 1 else (d.year - 1, 12)]


def month_url(template: str, year: int, month: int) -> str:
    """The plugin's address for one month's file: {year} and {month} filled in (2026, 11)."""
    return str(template).replace("{year}", f"{year:04d}").replace("{month}", f"{month:02d}")


def file_stem(url: str, year: int, month: int) -> str:
    """The name the file is installed under: the download's own (dbip-city-lite-2026-11 of dbip-city-lite-2026-11.mmdb.gz),
    else geoip-<year>-<month>."""
    stem = urlsplit(url).path.rsplit("/", 1)[-1]
    for end in (".gz", ".mmdb"):
        if stem.lower().endswith(end):
            stem = stem[:-len(end)]
    return stem if geo.NAME_FORM.fullmatch(stem) else f"geoip-{year:04d}-{month:02d}"


def _host(url: str) -> str:
    try:
        return urlsplit(str(url or "")).hostname or ""
    except ValueError:
        return ""


def _missing(e: BaseException) -> bool:
    """Whether a fetch's failure says the file is not there (HTTP 404)."""
    return getattr(e, "code", None) == 404 or getattr(e, "status", None) == 404 or isinstance(e, FileNotFoundError)


def _words(e: BaseException) -> str:
    code = getattr(e, "code", None)
    if isinstance(code, int) and not isinstance(code, bool):
        return f"HTTP {code} {getattr(e, 'reason', '') or ''}".strip()
    reason = getattr(e, "reason", None)
    return str(reason) if reason else f"{type(e).__name__}: {e}"


def _close(stream) -> None:
    close = getattr(stream, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001 - read to its end already
            pass


def _opens(path: Path) -> bool:
    """Whether `path` is a GeoIP file that opens (it is closed again)."""
    if not path.is_file():
        return False
    try:
        geo.GeoIP(path).close()
    except geo.GeoError:
        return False
    return True


def _length(stream) -> int | None:
    """The download's size in bytes as its answer says it (Content-Length), None when it says none."""
    value = None
    headers = getattr(stream, "headers", None)
    try:
        value = headers.get("Content-Length") if headers is not None else None
    except Exception:  # noqa: BLE001 - headers of another shape: no size
        value = None
    try:
        n = int(str(value).strip()) if value is not None else None
    except ValueError:
        n = None
    return n if n is not None and n > 0 else None


def _came_from(stream, url: str, hosts=()) -> str:
    """The address the download's answer came from (its own, after any redirect: https on the plugin's host, or one of
    `hosts` (1.102.0), or GeoError); `url` when the stream does not say."""
    where = _answered_from(stream, url)
    host = _host(url).lower()
    try:
        _over_https(where, host, hosts=hosts)
    except RedirectRefused:
        raise geo.GeoError(f"the GeoIP file came from {_site(where)}, not over https from {host}"
                           f"{' or the hosts its plugin names' if hosts else ''}: nothing was installed") from None
    return where


def _fixed(e: BaseException, url: str, own=()) -> str:
    """1.102.0: a keyed download's failure in fixed words: what failed, the HTTP status and the host alone, never the
    exception's own words (they may print the address, its query and the key in it) nor the address. `own`: the maker's
    own hosts, whose 401 or 403 is the key's; any other host's is its storage's, refusing a signed address."""
    code = getattr(e, "code", None)
    code = code if isinstance(code, int) and not isinstance(code, bool) else None
    where = getattr(e, "url", None) or getattr(e, "filename", None)
    host = (_host(where) if isinstance(where, str) and where else "") or _host(url) or "its host"
    mine = host.lower() in {str(h).lower() for h in own or ()}
    if code in (401, 403):
        return (f"HTTP {code} from {host}: the key was refused (set it again on the login's page): nothing was "
                "installed" if mine else f"HTTP {code} from {host}: the storage host refused the signed address it was "
                "sent on to (it may have expired): nothing was installed")
    if code == 429:
        return f"HTTP 429 from {host}: the maker's limit was reached; try again later: nothing was installed"
    if code is not None:
        return f"HTTP {code} from {host}: nothing was installed"
    if isinstance(e, RedirectRefused):
        return f"{getattr(e, 'reason', '') or 'it was sent on elsewhere'}: nothing was installed"  # a host alone
    if isinstance(e, geo.GeoError):
        return f"the file from {host} did not install: {type(e).__name__}"
    return f"the download from {host} failed ({type(e).__name__}): nothing was installed"


def _sayer(log):
    """Each step said to `log` (the platform's job panel): nothing when there is none; a log that fails is let be."""
    if not callable(log):
        return lambda line: None

    def say(line: str) -> None:
        try:
            log(line)
        except Exception:  # noqa: BLE001 - the install goes on without its panel
            pass
    return say


def _seconds(n: float) -> str:
    return f"{n:,.0f}" if n >= 10 else f"{n:g}"


class _Body:
    """The download's stream as geo.install_mmdb reads it, under the install's one deadline: a read refused once its time
    is up or the install was stopped (_Cutoff: its sockets shut meanwhile, so a read waiting on one ends); each read
    one of the stream's own at most (read1: a server sending a byte a minute holds no read for longer than its socket's
    timeout, and the deadline is looked at between them); the bytes come so far said at most every PROGRESS_S (`say`,
    and `told` for the tab's note), with their percent when the answer gave its size; its end noted on the cutoff."""

    def __init__(self, raw, cutoff: _Cutoff, deadline: float, took: str, say, told=None):
        self._raw, self._cutoff, self._deadline, self._took = raw, cutoff, deadline, took
        self._say, self._told = say, told or (lambda words: None)
        self.size = _length(raw)
        self.taken = 0
        self._said: float | None = None  # when the bytes were last said (geo's clock, the install's)
        self._ended = False
        one = getattr(raw, "read1", None)
        self._read = one if callable(one) else raw.read

    def read(self, size: int = -1) -> bytes:
        cutoff = self._cutoff
        if cutoff.why:
            raise geo.GeoError(cutoff.why)
        if geo._clock() >= self._deadline:
            cutoff.stop(self._took)
            raise geo.GeoError(self._took)
        got = self._read(size if isinstance(size, int) and size > 0 else geo.CHUNK)
        with cutoff.lock:
            if cutoff.why:  # stopped while it read: what came is not kept
                raise geo.GeoError(cutoff.why)
            if not got:
                cutoff.ended = True
        if got:
            self.taken += len(got)
        self._tell(not got)
        return got

    def words(self) -> str:
        if self.size:
            return f"{size_words(self.taken)} of {size_words(self.size)} ({min(100, self.taken * 100 // self.size)}%)"
        return f"{size_words(self.taken)} so far"

    def _tell(self, ended: bool) -> None:
        if ended:
            if not self._ended:
                self._ended = True
                self._told(f"{size_words(self.taken)} downloaded")
                self._say(f"{size_words(self.taken)} downloaded: unpacking and checking it")
            return
        now = geo._clock()
        if self._said is not None and now - self._said < PROGRESS_S:
            return
        self._said = now
        words = self.words()
        self._told(words)
        self._say(words)


def geoip_form(licence: str = "", source: str = "", folder=None, update: bool = False) -> dict:
    """The install form the page draws (liminal-platform's status.forms shape), asked as a job (its progress followed in
    the plugin's panel). Nothing to fill in: its first confirmation says what is downloaded, from where and to where, and
    shows the licence; the hook then refuses until the licence is accepted (LicenceRefused, before the job's first line),
    and the page asks that as a second confirmation with the licence's words."""
    words = (licence or "").strip() or "the licence its maker publishes with it."
    verb = "Update" if update else "Install"
    host = _host(source)
    whence = f" from {host}" if host else ""
    where = f" into {folder}" if folder else " into the data folder"
    return {
        "id": FORM, "hook": GEOIP_HOOK, "title": f"{verb} the GeoIP file", "job": True,
        "note": "Places on the globe are looked up in this file, on this machine: no address is sent anywhere.",
        "fields": [{"name": ACCEPT_LICENCE, "type": "accept", "title": "Accept the GeoIP file's licence?", "words": words,
                    "yes": "Accept it and download"}],
        "confirm": {"title": f"{verb} the GeoIP file?", "yes": "Go on",
                    "words": (f"This month's GeoIP file is downloaded{whence} (DB-IP's Lite City is about 60 MB) and "
                              f"unpacked{where}, in place of any older copy; its progress shows in the panel below, and "
                              f"it stops by itself after {_seconds(geo.INSTALL_S / 60)} minutes. Nothing about your "
                              f"traffic is sent: places are then looked up on this machine. Its licence, first: {words} "
                              "You are asked to accept it next.")}}


def asn_form(licence: str = "", source: str = "", folder=None, update: bool = False) -> dict:
    """1.75.0: the ASN file's install form, as geoip_form's: asked as a job, its licence shown in the first
    confirmation and accepted in the second (LicenceRefused until it is)."""
    words = (licence or "").strip() or "the licence its maker publishes with it."
    verb = "Update" if update else "Install"
    host = _host(source)
    whence = f" from {host}" if host else ""
    where = f" into {folder}" if folder else " into the data folder"
    return {
        "id": ASN_FORM, "hook": ASN_HOOK, "title": f"{verb} the ASN file", "job": True,
        "note": ("Each address's network, its AS number and operator, is looked up in this file, on this machine: "
                 "no address is sent anywhere."),
        "fields": [{"name": ACCEPT_LICENCE, "type": "accept", "title": "Accept the ASN file's licence?", "words": words,
                    "yes": "Accept it and download"}],
        "confirm": {"title": f"{verb} the ASN file?", "yes": "Go on",
                    "words": (f"This month's ASN file is downloaded{whence} and unpacked{where}, beside the GeoIP "
                              f"file and in place of any older ASN file; its progress shows in the panel below, and it "
                              f"stops by itself after {_seconds(geo.INSTALL_S / 60)} minutes. Nothing about your traffic "
                              "is sent: each address's network is then looked up on this machine. Its licence, first: "
                              f"{words} You are asked to accept it next.")}}


# -- 1.102.0: the GeoIP sources' forms and helpers ---------------------------------------------------------------------
def _fixed_fields(source, file) -> list:
    return [{"name": "source", "type": "fixed", "value": source.id}, {"name": "role", "type": "fixed", "value": file.role}]


def get_form(source, file, folder, update: bool = False) -> dict:
    """A source's file's download form (a job): its first confirmation says what is downloaded, from which host and
    which it is sent on to, its size, where it is kept, how a key travels and to whom, and the licence's words; the hook
    refuses until the licence is accepted (LicenceRefused), and the page asks that as a second confirmation."""
    verb = "Update" if update else "Download"
    sent = f", which sends it on from {' or '.join(file.sent_on)}" if file.sent_on else ""
    key = ""
    if source.keys:
        names = " and ".join(source.keys)
        key = (f" Your {names} goes to {file.host} alone, in the first address, read from your login store for this "
               "download; it is never shown, logged or kept anywhere else.")
    check = (f" Its checksum is asked of {file.host} first, which counts against no limit: when the newest is "
             "installed already, nothing is downloaded." if file.checksum != "none" else "")
    return {
        "id": GET_FORM + file.key, "hook": GEOIP_GET_HOOK, "title": f"{verb} {file.title}", "job": True,
        "note": f"Its {file.role} are looked up in this file, on this machine: no address is sent anywhere.",
        "fields": [*_fixed_fields(source, file),
                   {"name": ACCEPT_LICENCE, "type": "accept", "title": f"Accept its licence ({file.licence.name})?",
                    "words": file.licence.words, "yes": "Accept it and download"}],
        "confirm": {"title": f"{verb} {file.title}?", "yes": "Go on",
                    "words": (f"{file.title} is downloaded from {file.host}{sent}, and kept in {folder}, in place of "
                              f"any older copy: {file.size}.{key}{check} Its progress shows in the panel below; it "
                              f"stops by itself after {_seconds(geo.INSTALL_S / 60)} minutes. Nothing about your "
                              f"traffic is sent. Its licence, first: {file.licence.words} You are asked to accept it "
                              "next.")}}


def use_form(source, file) -> dict:
    """A source's file used for its role: one confirmation."""
    return {"id": USE_FORM + file.key, "hook": GEOIP_USE_HOOK, "title": f"Use {file.title}",
            "fields": _fixed_fields(source, file),
            "confirm": {"title": f"Use {file.title} for {file.role}?", "yes": "Use it",
                        "words": (f"{file.title} is used for {file.role} from now on, on this machine, for everyone "
                                  "who opens this tab: the hosts are placed again from it at the next ask. Its credit "
                                  f"is shown wherever its {file.role} are: {file.credit.get('text', '')}.")}}


def remove_form(source, file, folder) -> dict:
    """A source's file removed: asked twice (its hook refuses, naming accept_removal, until the second)."""
    words = (f"{file.title} is removed from {folder}, with its notes, and is no longer read; the {file.role} it gave "
             "are placed again from the files in use, or cleared. It can be downloaded again.")
    return {"id": REMOVE_FORM + file.key, "hook": GEOIP_REMOVE_HOOK, "title": f"Remove {file.title}",
            "fields": [*_fixed_fields(source, file),
                       {"name": ACCEPT_REMOVAL, "type": "accept", "title": f"Remove {file.title} for good?",
                        "words": words, "yes": "Remove it"}],
            "confirm": {"title": f"Remove {file.title}?", "yes": "Go on", "words": words}}


def _checksum(stream) -> str:
    """A maker's checksum answer ({"checksums": {"sha256": ...}}), read bounded (CHECKSUM_MOST) as strict JSON: its
    SHA-256, 64 hex digits. GeoError in fixed words otherwise."""
    raw = b""
    while len(raw) <= CHECKSUM_MOST:
        got = stream.read(CHECKSUM_MOST + 1 - len(raw))
        if not got:
            break
        raw += bytes(got)
    if len(raw) > CHECKSUM_MOST:
        raise geo.GeoError(f"the checksum's answer runs past {CHECKSUM_MOST:,} bytes: nothing was downloaded")

    def strict(value):
        raise ValueError("not strict JSON")
    try:
        doc = json.loads(raw.decode("utf-8"), parse_constant=strict)
    except (ValueError, UnicodeDecodeError, RecursionError):
        doc = None
    sha = doc.get("checksums", {}).get("sha256") if isinstance(doc, dict) and isinstance(doc.get("checksums"),
                                                                                           dict) else None
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        raise geo.GeoError("the checksum's answer is not the maker's: no SHA-256 in it, so nothing was downloaded")
    return sha.lower()


def _notes(path: Path) -> dict:
    """A file's notes (<stem>.json beside it), {} when there are none or they do not read."""
    try:
        doc = json.loads(Path(path).with_suffix(geo.NOTES).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _write_notes(path: Path, notes: dict) -> None:
    """A file's notes written beside it: what its maker said at install (the SHA-256 checked, when): never a key, a
    token or an address."""
    part = Path(path).with_suffix(geo.NOTES + ".part")
    try:
        part.write_text(json.dumps(notes, sort_keys=True), encoding="utf-8")
        os.replace(part, Path(path).with_suffix(geo.NOTES))
    except OSError:
        try:
            part.unlink()
        except OSError:
            pass


def _day(built) -> str:
    try:
        return datetime.fromtimestamp(int(built), timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OverflowError, OSError):
        return "undated"


def _geo_words(e: BaseException) -> str:
    """An install's refusal, its reason alone (what geo said after "was not installed: "), for a keyed download."""
    text = str(e)
    return text.split("was not installed: ", 1)[-1] if "was not installed: " in text else type(e).__name__


# -- the page's words and numbers ------------------------------------------------------------------------------------------
def size_words(n) -> str:
    """Bytes in words, as the page's charts say them (1024 to a KB): 512 B, 1.2 MB, 135 GB."""
    v, i = abs(float(n or 0)), 0
    while v >= 1024 and i < len(UNITS) - 1:
        v /= 1024
        i += 1
    return f"{v:.0f} {UNITS[i]}" if i == 0 or v >= 100 else f"{v:.1f} {UNITS[i]}"


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def _local_peer(group: dict) -> bool:
    """Whether a remote group is the local network's, never placed: private, loopback, link-local, a carrier's shared
    addresses (netpath.kind), and multicast, broadcast or unspecified ones."""
    if group.get("network") != "public":
        return True
    try:
        ip = ipaddress.ip_address(str(group.get("address", "")).split("%")[0])
    except ValueError:
        return True
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_multicast or ip.is_unspecified or ip.is_reserved or str(ip) == "255.255.255.255"


def _starts(group: dict) -> dict[str, int]:
    """A remote group's flow starts by the globe's kinds: allowed in, unanswered in (TCP and UDP), out."""
    return {"allowed": int(group.get("new_in", 0)),
            "unanswered": int(group.get("unanswered", 0)) + int(group.get("unanswered_udp", 0)),
            "outbound": int(group.get("new_out", 0))}


def _kind(starts: dict[str, int], group: dict, here: set, there: set) -> str:
    """The kind a place is drawn as: the one most of its connections started as (allowed first, then unanswered, on a
    tie). With no start seen, nothing that went back to that network: unanswered, for what came from it was attempts
    not answered yet (younger than traffic.ANSWER_S) or never judged (watching paused before an answer could come, or
    crowded out); never allowed in. Something went back (a connection open before watching began): allowed when its
    ports are this machine's services alone, else out."""
    best = max(traffic.KINDS, key=lambda k: starts[k])
    if starts[best]:
        return best
    group = group if isinstance(group, Mapping) else {}
    if not int(group.get("out_packets", 0) or 0):
        came = int(group.get("in_packets", 0) or 0) or int(group.get("unjudged", 0) or 0)
        return "unanswered" if came else "outbound"
    used = set(group.get("ports") or ())
    return "allowed" if used & here and not used & there else "outbound"


def not_here_page(why: str) -> dict:
    """The tab's page on a machine the plugin is not for (its not_for_here): saying so, nothing started."""
    return {"title": TITLE, "note": f"Not for this machine: {why}. Nothing is watched here."}


def under_wsl(release: str | None = None, env=None) -> dict | None:
    """What running inside a WSL distribution changes for the World Wide Web tab, as a table for its page (the user,
    2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some capability this
    should reflect in the plugin"). None on a machine of its own, off Linux, and with a library from before the Linux
    plugins worked inside WSL (machines.linux.wsl names the distribution the platform runs in; until then a WSL kernel
    was refused before the tab was drawn). `release` and `env` stand in for the kernel's release and the environment in
    tests. Read only: nothing is run."""
    from . import linux

    name_of, generation_of = getattr(linux, "wsl", None), getattr(linux, "wsl_generation", None)
    if not callable(name_of) or not callable(generation_of):
        return None
    try:
        name = name_of(release, env)
        generation = generation_of(release) if name else 0
    except Exception:  # noqa: BLE001 - a check that cannot say: nothing said
        return None
    if not name:
        return None
    named = name if name != "WSL" else "<its name>"
    if generation == 1:
        rows = [["This Linux", f"WSL 1: {name}", "a WSL distribution on Windows, with no Linux kernel and no network adapter "
                 "of its own"],
                ["Watched", "nothing", "WSL 1 gives libpcap no adapter to open, so no packet can be watched here; WSL 2 can "
                 f"(wsl --set-version {named} 2, from Windows)"],
                ["This PC's traffic", "the Windows firewall's", "what goes in and out of this PC is the Windows firewall "
                 "plugin's World Wide Web tab's to draw"]]
    else:
        rows = [["This Linux", f"WSL 2: {name}", "a WSL distribution on Windows: the adapter watched is this distribution's "
                 "own, behind Windows"],
                ["Watched", "this distribution's traffic", "what Windows' own programs send and receive is not this "
                 "distribution's: the Windows firewall plugin's World Wide Web tab draws it"],
                ["From the internet", "through Windows only", "under WSL's NAT networking (its default) nothing from outside "
                 "the PC reaches this distribution unless Windows forwards a port to it (netsh interface portproxy); under "
                 "mirrored networking (networkingMode=mirrored in .wslconfig) it can, where Windows' firewall and WSL's "
                 "Hyper-V firewall let it in"],
                ["Home", "this PC's", "the name servers see this PC's way out, so the public address placed (when no home "
                 "is set) is the one Windows has too"]]
    return {"title": "Under WSL", "note": "What running inside a WSL distribution changes for this tab.",
            "columns": [{"title": "What"}, {"title": "Here"}, {"title": "What it means"}], "rows": rows}


class _Watched:
    """The capture a WorldView's Watcher pulls, as its factory made it: open(), next() and close() handed on, and what
    else is asked of it (its broadcast addresses, its address). Once it was open, its close (watching ended: the viewing
    timeout, stop(), the adapter gone) lets the view's GeoIP file go too (`ended`): nothing stays mapped while nobody
    looks, and the next ask opens it again."""

    def __init__(self, source, ended):
        self._source, self._ended, self._opened = source, ended, False

    def open(self):
        self._source.open()
        self._opened = True

    def next(self):
        return self._source.next()

    def close(self):
        try:
            self._source.close()
        finally:
            if self._opened:
                self._opened = False
                self._ended()

    def __getattr__(self, name):
        if name.startswith("__") or name in ("_source", "_ended", "_opened"):
            raise AttributeError(name)
        return getattr(self._source, name)


class WorldView:
    """A plugin's World Wide Web tab: its watching and the page it answers.

    `name` is the plugin's. `capture_factory` makes the capture a traffic.Watcher pulls (default_capture when not given;
    a test's stand-in: anything with open(), next() and close()). `geo_folder` holds the GeoIP files (geo.data_folder()
    when not given). `timeout` is the viewing timeout in seconds of `clock` (monotonic: a test's own), which also times
    the charts' samples. `resolve` asks for this network's public address (dns.public_address, through nslookup), `fetch`
    downloads (fetch_url), `wall` gives the time of day (the charts' times, the months), and `book` is the
    traffic.TrafficBook counted into: each a test's stand-in when given.

    touch() keeps the watching going (the tab's every ask), stop() ends it, page() answers the tab's page and install()
    downloads the GeoIP file on the user's word. Thread-safe: the platform asks from a thread per request."""

    def __init__(self, name: str, *, capture_factory=None, geo_folder=None, timeout: float = TIMEOUT_S,
                 clock=time.monotonic, resolve=None, fetch=None, wall=time.time, book: traffic.TrafficBook | None = None,
                 sources=None):
        self.name = str(name or "")
        # 1.102.0: (the GeoIP sources read, what was wrong with the others, the choice's reader: {role: source id})
        named, refused, choice_of = sources if sources is not None else ((), (), None)
        self.sources: list = list(named or ())
        self.refused: list[str] = [str(r) for r in refused or ()]
        self._choice_of = choice_of if callable(choice_of) else (lambda: {})
        self._facts: dict = {}  # a folder's newest file, as it was described: {folder: ((path, mtime), facts)}
        self._held: set[str] = set()  # files a removal could not take (Windows held them): never read from here
        self._open_ids: dict[str, str | None] = {"places": None, "networks": None}  # the sources of the files open
        self._said_choice: dict = {}  # why a role falls back, in words, as chosen() last said it
        self.capture_factory = capture_factory or default_capture
        self._folder = Path(geo_folder) if geo_folder is not None else None
        self.timeout = float(timeout)
        self.clock, self.wall = clock, wall
        self._resolve = resolve or dns.public_address
        self._nslookup = resolve is None  # dns.public_address runs nslookup: missing, it is said so
        self._fetch = fetch or fetch_url
        self.watcher = traffic.Watcher(self._source, self.timeout, book=book, clock=clock)
        self.address = ""  # the address whose adapter is watched, once a capture was made
        self.error = ""  # why watching could not start, the last time it was tried
        self._failed: float | None = None  # when that was (clock)
        self.closed = False  # close(): stopped for good, the plugin detached
        self._lock = threading.RLock()
        self._halt = threading.Event()  # stop(): a public address being asked for is not kept
        self._installing = threading.Lock()
        self._cutoff: _Cutoff | None = None  # the install under way's, stopped by close()
        self._progress = ""  # how far it is, in words (the tab's note)
        self._what = ""  # 1.75.0: the file being downloaded ("GeoIP file" or "ASN file")
        self._geoip: geo.GeoIP | None = None
        self._geo_said: dict | None = None  # the GeoIP file as last open (describe), once it was let go
        self._geo_looked: float | None = None
        self._public = {"address": None, "why": "", "at": None, "running": False}
        self._setting: tuple[float, object] | None = None
        self._samples: deque = deque(maxlen=MAX_SAMPLES)  # (clock, seconds, {(proto, port): (in, out)} | None for a gap)
        self._base: tuple[float, dict] | None = None  # (clock, {(proto, port): (in bytes, out bytes)}) at the last sample

    @property
    def book(self) -> traffic.TrafficBook:
        return self.watcher.book

    @property
    def folder(self) -> Path:
        """Where the GeoIP files are: the folder given, else the data folder's geoip/."""
        return self._folder if self._folder is not None else geo.data_folder()

    def _source(self):
        source = self.capture_factory()
        self.address = str(getattr(source, "address", "") or "")
        return _Watched(source, self._let_go)

    # -- watching ---------------------------------------------------------------------------------------------------
    def touch(self) -> bool:
        """The tab asked for: watching kept going, or started (its capture made and opened here). True while it watches;
        False when it cannot (`error` says why, and it is tried again RETRY_S later at the soonest, however often it is
        asked)."""
        with self._lock:
            if self.closed:  # an ask still under way as the plugin was detached starts nothing
                return False
            self._halt.clear()
            now = self.clock()
            if not self.watcher.running and self._failed is not None and now - self._failed < RETRY_S:
                return False
            try:
                self.watcher.touch()
            except Exception as e:  # noqa: BLE001 - no Npcap or libpcap, no right to capture, no network: said on the page
                self.error = self.watcher.error or str(e) or type(e).__name__
                self._failed = now
                return False
            self.error, self._failed = "", None
            return True

    @property
    def running(self) -> bool:
        return self.watcher.running

    def stop(self) -> None:
        """Watching ended now (the plugin's detach): the capture closed and its thread gone, the GeoIP file let go, a
        public address still being asked for not kept. What was counted stays; a touch starts it again."""
        self._halt.set()
        self.watcher.stop()
        self._let_go()

    def close(self) -> None:
        """Stopped for good (the plugin's detach, which then forgets it): stop(), an install under way stopped (its
        sockets shut, nothing installed), and no ask still under way starts the watching again or opens the GeoIP file."""
        with self._lock:
            self.closed = True
            cutoff = self._cutoff
        if cutoff is not None:
            cutoff.stop(DETACHED)
        self.stop()

    # -- the GeoIP file -------------------------------------------------------------------------------------------------
    def elsewhere(self) -> str:
        """Why this view's GeoIP files are another system's, in words ("" when they are this one's): the folder is on
        another system's drive seen through a mount (geo.foreign: WSL's /mnt/c, a share, a network drive). They count as
        none installed: never read from here, and no install offered or made."""
        return geo.foreign(self.folder, "Reading the GeoIP files")

    def geoip(self) -> geo.GeoIP | None:
        """The GeoIP file open for lookups: the folder's newest (looked for again every GEO_LOOK_S while none opens);
        None without one, or without maxminddb, once closed, and for a folder on another system's drive (elsewhere)."""
        if self.elsewhere():
            return None
        with self._lock:
            if self.sources and self._geoip is not None and not self._still_usable(self._geoip):
                self._let_go_now()  # 1.102.0: a file too old to be read let go at once, at whichever ask finds it
            if self._geoip is not None or self.closed:
                return self._geoip
            now = self.clock()
            if self._geo_looked is not None and now - self._geo_looked < GEO_LOOK_S:
                return None
            self._geo_looked = now
            self._geoip = self._open_chosen() if self.sources else geo.GeoIP.find(self.folder)
            return self._geoip

    # -- 1.102.0: the GeoIP sources ---------------------------------------------------------------------------------
    @property
    def default(self) -> str:
        """The default source's id: the plugin's first ("" when it names none)."""
        return self.sources[0].id if self.sources else ""

    def source(self, ident) -> geosources.GeoSource | None:
        return next((s for s in self.sources if s.id == ident), None)

    def file_of(self, ident, role) -> geosources.GeoFile | None:
        source = self.source(ident)
        return source.file(role) if source is not None and role in geosources.ROLES else None

    def file_folder(self, ident: str, role: str) -> Path:
        return geosources.folder(self.folder, ident, role, self.default)

    def _now(self) -> float:
        return self.wall()

    def _usable(self, file: geosources.GeoFile):
        """A file's usable test: not one a removal could not take, and not past its max_age_days (asked now)."""
        age = geosources.usable(file, self._now)

        def test(path, built) -> bool:
            return str(path) not in self._held and age(path, built)
        return test

    def _still_usable(self, geoip) -> bool:
        asn = getattr(geoip, "asn", None)
        return geoip.usable_now() and (asn is None or asn.usable_now())

    def _let_go_now(self) -> None:
        """With the lock held: the file open let go (it is opened anew, by the choice, at the next ask)."""
        geoip, self._geoip, self._geo_looked = self._geoip, None, None
        if geoip is not None:
            geoip.close()
            self._geo_said = geoip.describe()
        self._open_ids = {"places": None, "networks": None}

    def replaced(self) -> None:
        """The files in use changed (a use, an install, a removal): the one open let go, the folders looked at anew."""
        with self._lock:
            self._facts.clear()
            self._let_go_now()

    def installed(self, ident: str, role: str) -> dict | None:
        """A source's file of `role` installed here, as it was described when last opened (its file, path, date and
        built, and `epoch`), cached by its name and time; None when there is none (or none that opens)."""
        folder = self.file_folder(ident, role)
        if geo.foreign(folder, "Reading the GeoIP files"):
            return None
        for path in geo._copies(folder):
            if str(path) in self._held:
                continue
            try:
                key = (str(path), path.stat().st_mtime)
            except OSError:
                continue
            kept = self._facts.get(str(folder))
            if kept is not None and kept[0] == key:
                return kept[1]
            try:
                with geo.GeoIP(path) as opened:
                    facts = {**opened.describe(), "epoch": opened.built}
            except geo.GeoError:
                continue
            facts.pop("asn", None)
            self._facts[str(folder)] = (key, facts)
            return facts
        return None

    def chosen(self) -> dict:
        """The files used for each role: {role: {"source", "file", "facts", "words"}}: the source chosen (the plugin's
        choice_of), else the default's; a choice whose file is missing, too old, of a source not named or not offered
        falls back to the default source's file where it is installed, else to none, and `words` says why."""
        try:
            wanted = dict(self._choice_of() or {})
        except Exception:  # noqa: BLE001 - a choice that cannot be read: the default's
            wanted = {}
        out = {}
        for role in geosources.ROLES:
            want = str(wanted.get(role) or self.default)
            pick, why = None, ""
            for ident in dict.fromkeys((want, self.default)):
                source, file = self.source(ident), self.file_of(ident, role)
                if file is None or not source.offered:
                    if ident == want and ident != self.default:
                        why = f"{ident} gives no {role} file here (not named, or not offered)"
                    continue
                facts = self.installed(ident, role)
                if facts is None:
                    if ident == want and ident != self.default:
                        why = f"{file.title} is not installed"
                    continue
                if geosources.due(file, facts.get("epoch"), self._now()) == "expired":
                    why = f"{file.title} is too old to be read (its licence's {file.max_age_days} days)"
                    continue
                pick = {"source": ident, "file": file, "facts": facts}
                break
            if pick is None:
                pick = {"source": None, "file": None, "facts": None}
            if why and pick["source"] is not None:
                why += f", so {pick['file'].title} is used for {role}"
            elif why:
                why += f", and no other {role} file is installed"
            out[role] = {**pick, "words": why}
        self._said_choice = {r: c["words"] for r, c in out.items()}
        return out

    def _open_chosen(self) -> geo.GeoIP | None:
        """With the lock held: the chosen places file opened, the chosen networks file read beside it."""
        chosen = self.chosen()
        places, networks = chosen["places"], chosen["networks"]
        if places["file"] is None:
            return None
        beside = None
        if networks["file"] is not None:
            beside = geo.newest(self.file_folder(networks["source"], "networks"), usable=self._usable(networks["file"]),
                                what="Reading the ASN file")
        found = geo.GeoIP.find(self.file_folder(places["source"], "places"), asn=beside,
                               usable=self._usable(places["file"]))
        if found is None:
            if beside is not None:
                beside.close()
            return None
        self._open_ids = {"places": places["source"], "networks": networks["source"] if beside is not None else None}
        return found

    def stamp(self, geoip=None) -> str:
        """What a host placed from the files open is stamped with (geosources.stamp): the places file's date alone with
        the default source's files, as before 1.102.0."""
        geoip = geoip if geoip is not None else self._geoip
        if geoip is None:
            return ""
        try:
            d = geoip.describe() or {}
        except Exception:  # noqa: BLE001 - a file that cannot say: placed as of none
            return ""
        date = str(d.get("date") or "")
        if not self.sources:
            return date
        ids = dict(self._open_ids)
        places = (ids["places"] or self.default, date)
        asn = d.get("asn") or {}
        networks = (ids["networks"] or self.default, str(asn.get("date") or "")) if asn else None
        return geosources.stamp(places, networks, self.default)

    def credits(self) -> dict:
        """The credits of the files in use, by role ({text, url}), for the globe and the tables: the files open, else
        the ones chosen (before the first ask opens them)."""
        with self._lock:
            ids = dict(self._open_ids)
        if not any(ids.values()):
            ids = {role: c["source"] for role, c in self.chosen().items()}
        out = {}
        for role in geosources.ROLES:
            file = self.file_of(ids.get(role), role) if ids.get(role) else None
            out[role] = dict(file.credit) if file is not None else None
        return out

    def _fetch_to(self, url: str, timeout: float, hosts=()):
        """The view's fetch, given the hosts a download may be sent on to when it takes them (fetch_url does)."""
        try:
            params = inspect.signature(self._fetch).parameters
            takes = "hosts" in params or any(p.kind is p.VAR_KEYWORD for p in params.values())
        except (TypeError, ValueError):
            takes = False
        return self._fetch(url, timeout, hosts=tuple(hosts)) if takes else self._fetch(url, timeout)

    def get(self, ident: str, role: str, secrets=None, log=None, cancel=None) -> dict:
        """A source's file of `role` downloaded on the user's word (the plugin's world_geoip_get, its licence accepted
        and its keys read in the job): a month's file as install() fetches DB-IP's, into the source's own folder; a
        fixed address's (IPinfo Lite) with its checksum first (the newest installed already: nothing downloaded), then
        the file, its SHA-256 compared before it is put in place, named from its build date, its notes beside it (the
        SHA-256 and when: never a key, a token or an address). One download at a time; `cancel()` stops it. Every word
        it says goes through geosources.redact; a keyed download's failure is said in fixed words (status and host)."""
        source, file = self.source(ident), self.file_of(ident, role)
        if file is None:
            raise ValueError(f"the plugin names no {role} file of a source {ident}")
        secrets = dict(secrets or {})
        folder = self.file_folder(ident, role)
        if file.monthly:
            out = self.install(file.url, log=log, kind="asn" if role == "networks" else "city", folder=folder,
                               packing=file.packing, cancel=cancel)
        else:
            out = self._get_fixed(source, file, folder, secrets, log, cancel)
        self.replaced()
        return out

    def _get_fixed(self, source, file, folder: Path, secrets: dict, log, cancel) -> dict:
        say = _sayer(log)

        def said(line: str) -> None:
            say(geosources.redact(line, secrets))
        elsewhere = geo.foreign(folder, f"Installing {file.title}")
        if elsewhere:
            raise ValueError(elsewhere)
        if not self._installing.acquire(blocking=False):
            raise ValueError(f"{'an' if (self._what or 'a').startswith('ASN') else 'a'} {self._what or 'GeoIP file'} "
                             "is being downloaded already: wait for it to finish")
        failure = ""
        try:
            ok, why = geo.available()
            if not ok:
                raise ValueError(f"places cannot be read here, so nothing is downloaded: {why}")
            cutoff = _Cutoff()
            with self._lock:
                if self.closed:
                    raise ValueError("the plugin was detached: nothing is downloaded")
                self._cutoff, self._progress, self._what = cutoff, "", file.title
            budget = float(geo.INSTALL_S)
            deadline = geo._clock() + budget
            took = (f"the download took more than {_seconds(budget)} s, the most an install may take, so it was "
                    "stopped: nothing was installed")
            try:
                out = run_download(lambda: self._fixed_download(source, file, folder, secrets, cutoff, deadline, took,
                                                                said), cutoff, deadline, took,
                                   name=f"{self.name or 'world'}-{file.key}-download",
                                   stopping=lambda: self._stopping(cancel), what=file.title)
            except geo.GeoError as e:
                failure = geosources.redact(str(e), secrets)
            finally:
                with self._lock:
                    self._cutoff, self._progress, self._what = None, "", ""
        finally:
            self._installing.release()
        if failure:
            raise geo.GeoError(failure)  # outside every except block: no cause, no context
        return out

    def _fixed_download(self, source, file, folder: Path, secrets: dict, cutoff: _Cutoff, deadline: float, took: str,
                        said) -> dict:
        """On the download's thread: the checksum, then the file. Every failure in fixed words (_fixed), raised after
        the except block, so neither its cause nor its context holds what an exception printed."""
        failure, asked = "", file.url
        try:
            current = self.installed(source.id, file.role)
            want = None
            if file.checksum == "ipinfo-checksums":
                asked = geosources.address(file, source, secrets, checksum=True)
                said(f"asking {file.host} for the newest file's checksum (it counts against no limit)")
                stream = self._fetch_to(asked, min(READ_S, max(1.0, deadline - geo._clock())))
                try:
                    want = _checksum(stream)
                finally:
                    _close(stream)
                if current is not None and _notes(Path(current["path"])).get("sha256") == want:
                    return {"said": f"{current['file']} is installed already: it is the newest, by its checksum",
                            "ok": True, "lines": [f"kept in {folder}, the only copy", "nothing was downloaded"],
                            "file": current}
            if cutoff.why:
                raise geo.GeoError(cutoff.why)
            asked = geosources.address(file, source, secrets)
            said(f"asking {file.host} for {file.title}")
            stream = self._fetch_to(asked, min(READ_S, max(1.0, deadline - geo._clock())), file.sent_on)
            try:
                came = _came_from(stream, asked, file.sent_on)
                body = _Body(stream, cutoff, deadline, took, said, self._told)
                said(f"downloading {file.title} from {_host(came)}" + (f": {size_words(body.size)}" if body.size else ""))
                path = geo.install_mmdb(body, folder, file.stem, timeout=None, packing=file.packing,
                                        name_of=lambda built: f"{file.stem}-{_day(built)}", sha256=want)
            finally:
                _close(stream)
            _write_notes(path, {"source": source.id, "role": file.role, "sha256": want or "",
                                "installed": _iso(self.wall())})
        except Exception as e:  # noqa: BLE001 - every failure said in fixed words below
            if cutoff.why:
                failure = cutoff.why
            elif isinstance(e, geo.GeoError):  # the library's own words (an install's, the checksum's, the answer's host)
                failure = f"{file.title} was not installed: {_geo_words(e)}"
            else:
                failure = _fixed(e, asked, source.hosts)
        if failure:
            raise geo.GeoError(geosources.redact(failure, secrets))
        self._facts.pop(str(folder), None)
        return {"said": f"installed {path.name}", "ok": True, "file": {"file": path.name, "path": str(path)},
                "lines": [f"downloaded from {_host(came)}", f"kept in {folder}, in place of any older copy",
                          f"its {file.role} are looked up in it on this machine: no address is sent anywhere"]}

    def remove(self, ident: str, role: str) -> dict:
        """A source's file of `role` removed, with its notes, every reader of it closed first. One Windows still holds
        is said so, left unread from here, and tried again at the next ask."""
        file = self.file_of(ident, role)
        if file is None:
            raise ValueError(f"the plugin names no {role} file of a source {ident}")
        folder = self.file_folder(ident, role)
        elsewhere = geo.foreign(folder, f"Removing {file.title}")
        if elsewhere:
            raise ValueError(elsewhere)
        if self._installing.locked():
            raise ValueError("a GeoIP file is being downloaded: wait for it to finish")
        with self._lock:
            self._let_go_now()
        copies = geo._copies(folder)
        left = []
        for path in copies:
            if geo.remove(path):
                self._held.discard(str(path))
            else:
                self._held.add(str(path))
                left.append(path.name)
        self.replaced()
        if not copies:
            return {"said": f"{file.title} is not installed here", "ok": True, "lines": []}
        if left:
            return {"said": f"{', '.join(left)} could not be removed: another program still holds it", "ok": False,
                    "lines": ["it is not read from here meanwhile", "Remove… tries again"]}
        return {"said": f"removed {file.title}", "ok": True, "lines": [f"from {folder}, with its notes"]}

    def sources_table(self, keys=None, can: bool = True) -> tuple[dict, list]:
        """The "GeoIP sources" table and its forms: a row a source's file (Source | Gives | Licence | Key | Here) and
        three columns of buttons, Use…, Download… (Update… once one is due) and Remove…. `keys`: the key names set in
        the asking person's login store (names only), None when not known. A source not offered says so, with no
        button and no form; Download… shows only while its keys are set."""
        chosen = self.chosen()
        elsewhere = self.elsewhere()
        offer = bool(can) and not elsewhere and not self._installing.locked() and geo.available()[0]
        rows, forms = [], []
        for source in self.sources:
            for file in source.files:
                facts = self.installed(source.id, file.role)
                state = geosources.due(file, facts.get("epoch"), self._now()) if facts else ""
                used = chosen[file.role]["source"] == source.id
                if not source.offered:
                    key, here = "not asked", "not offered: waiting for your word"
                else:
                    missing = [n for n in source.keys if keys is None or n not in keys]
                    key = ("none needed" if not source.keys else "set in your login store" if not missing else
                           {"text": "not set in your login store", "sub": f"add it {geosources.WHERE_KEYS}"})
                    if self._what == file.title:
                        here = "being downloaded"
                    elif elsewhere:
                        here = "not from here"
                    elif facts:
                        sub = ("too old to be read: Update… or Remove…" if state == "expired" else
                               "an update is out" if state == "update" else "")
                        here = {"text": f"built {facts.get('date') or 'on an unknown day'}"
                                        + (f"; used for {file.role}" if used else ""), "sub": sub}
                    else:
                        here = "not downloaded"
                buttons = ["", "", ""]
                if offer and source.offered:
                    if facts and not used and state != "expired":
                        buttons[0] = {"form": USE_FORM + file.key, "title": "Use…"}
                        forms.append(use_form(source, file))
                    if not missing and (not facts or state in ("update", "expired")):
                        buttons[1] = {"form": GET_FORM + file.key, "title": "Update…" if facts else "Download…"}
                        forms.append(get_form(source, file, self.file_folder(source.id, file.role),
                                              update=bool(facts)))
                if offer and facts:
                    buttons[2] = {"form": REMOVE_FORM + file.key, "title": "Remove…"}
                    forms.append(remove_form(source, file, self.file_folder(source.id, file.role)))
                rows.append([{"text": file.title, "sub": source.maker}, file.role, file.licence.name, key, here,
                             *buttons])
        note = ("Where places and networks come from: each file is downloaded only on your word, its size, hosts and "
                "licence said first, and read on this machine alone. Places and networks are chosen apart.")
        said = [w for w in self._said_choice.values() if w]
        if said:
            note += " " + "; ".join(said) + "."
        if self.refused:
            note += " Not read from the plugin: " + "; ".join(self.refused) + "."
        if elsewhere:
            note += f" {elsewhere}. Each system's platform downloads its own."
        table = {"title": SOURCES_TITLE, "note": note,
                 "columns": [{"title": "Source"}, {"title": "Gives"}, {"title": "Licence"}, {"title": "Key"},
                             {"title": "Here"}, {"title": ""}, {"title": ""}, {"title": ""}],
                 "rows": rows, "empty": "This plugin names no GeoIP source."}
        return table, forms

    def _let_go(self) -> None:
        """The GeoIP file let go, its map closed (nobody watches): opened again at the next ask that needs it. What it
        was is kept for describe(), in the same hold as the file is let go (a map's close and a stat: on this machine,
        and quick), so describe() never finds neither the file nor what it was."""
        with self._lock:
            geoip, self._geoip = self._geoip, None
            if geoip is None:
                return
            self._geo_looked = None
            geoip.close()
            self._geo_said = geoip.describe()

    def rest(self) -> None:
        """The GeoIP file let go again unless this view watches: for a geoip() asked outside page() (the Netstat tab's
        places and the hosts database's: machines/netstat.py), which lets it go itself. While the capture runs the file
        stays mapped, as page() leaves it; once nobody watches nothing stays mapped, and the next ask opens it again."""
        if not self.watcher.running:
            self._let_go()

    def install(self, template: str, log=None, kind: str = "city", *, folder=None, packing: str = "auto",
                cancel=None) -> dict:
        """The GeoIP file downloaded and put in place, on the user's word (the plugin's world_geoip, its licence accepted).
        `template` is the plugin's https address with {year} and {month} in it: this month's file, else last month's when
        this month's is not out yet (a 404). A month's file installed already is not downloaded again.

        One deadline for all of it, geo.INSTALL_S on the install's clock (geo's): both months' fetches (each connection,
        its TLS, its headers and its redirects) and the body, streamed through geo.install_mmdb with its bounds on the
        bytes. The download runs on a thread of its own while this one waits what is left of the time. When the time is
        up, or the view is closed (the plugin's detach), its sockets are shut, its reads refused, its file not put in
        place, and the install says so at once. Its thread ends once its socket does; a connection still being made (its
        name looked up, its TLS agreed) has no socket to shut yet, and ends at its own timeout, READ_S at most, putting
        nothing in place. A file read to its end is checked and put in place on this machine, waited for LOCAL_S more;
        past that the install says so, and the file is still put in place if it passes. https on every hop, from the
        plugin's own host alone (fetch_url; the address the answer came from checked again), and nothing else is sent.

        `log`: each step said to it, and the bytes so far with their percent, at most every PROGRESS_S (the platform's job
        panel). What was installed, in words, for the page. ValueError for an address that is no https one, maxminddb
        missing, a download under way, a view closed, or a folder on another system's drive (geo.foreign: that system's
        platform installs its own; nothing is fetched); geo.GeoError when nothing was installed (the current file stays as
        it was).

        1.75.0: `kind` "asn" installs the ASN file instead, into the GeoIP folder's asn/ (geo.asn_folder), its own
        folder, so neither install removes the other's file; the GeoIP file is then opened again with it.

        1.102.0: `folder` puts it in a source's own folder (geosources.folder), `packing` insists on how it comes, and
        `cancel()` true stops it as a detach does (the platform's Cancel)."""
        say = _sayer(log)
        template = str(template or "").strip()
        what = "ASN file" if kind == "asn" else "GeoIP file"
        if not template:
            raise ValueError(f"there is no {what} to download: the plugin names none")
        wanted = months(self.wall())
        if any(urlsplit(month_url(template, y, m)).scheme.lower() != "https" or not _host(month_url(template, y, m))
               for y, m in wanted):
            raise ValueError(f"a {what} is downloaded over https only")
        elsewhere = geo.foreign(Path(folder) if folder is not None else self.folder, f"Installing a {what}")
        if elsewhere:
            raise ValueError(elsewhere)
        if not self._installing.acquire(blocking=False):
            running = self._what or what  # 1.75.0: the GeoIP file or the ASN file, one download at a time
            raise ValueError(f"{'an' if running.startswith('ASN') else 'a'} {running} is being downloaded already: "
                             "wait for it to finish")
        try:
            ok, why = geo.available()
            if not ok:
                raise ValueError(f"places cannot be read here, so nothing is downloaded: {why}")
            cutoff = _Cutoff()
            with self._lock:
                if self.closed:
                    raise ValueError("the plugin was detached: nothing is downloaded")
                self._cutoff, self._progress, self._what = cutoff, "", what
            try:
                return self._install(template, wanted, cutoff, say, kind, folder=folder, packing=packing,
                                     cancel=cancel)
            finally:
                with self._lock:
                    self._cutoff, self._progress, self._what = None, "", ""
        finally:
            self._installing.release()

    def _install(self, template: str, wanted: list, cutoff: _Cutoff, say, kind: str = "city", *, folder=None,
                 packing: str = "auto", cancel=None) -> dict:
        budget = float(geo.INSTALL_S)
        deadline = geo._clock() + budget
        took = (f"the download took more than {_seconds(budget)} s, the most an install may take, so it was stopped: "
                "nothing was installed")
        late = (f"the GeoIP file was downloaded, and checking it here took more than {_seconds(LOCAL_S)} s: it is "
                "still put in place if it passes, and the tab then shows its places")
        # the download on a thread of its own, this one waiting what is left of the time (run_download: its sockets shut
        # once the time is up or the plugin was detached)
        if folder is None:
            folder = geo.asn_folder(self.folder) if kind == "asn" else self.folder  # 1.75.0: the ASN file's own
        path, url, fell_back, again = run_download(
            lambda: self._download(template, wanted, cutoff, deadline, took, say, folder, packing), cutoff, deadline,
            took, name=f"{self.name or 'world'}-{'asn' if kind == 'asn' else 'geoip'}-download",
            stopping=lambda: self._stopping(cancel), late=late)
        if kind == "asn":
            return self._installed_asn(path, url, fell_back, again)
        return self._installed(path, url, fell_back, again)

    def _download(self, template: str, wanted: list, cutoff: _Cutoff, deadline: float, took: str, say,
                  folder=None, packing: str = "auto") -> tuple:
        """On the download's thread: this month's file, else last month's, fetched and installed into `folder` (the
        GeoIP folder, or 1.75.0's asn/ in it); (its path, the address it came from, whether it was last month's,
        whether it was there already)."""
        folder, tried = (folder if folder is not None else self.folder), []
        for year, month in wanted:
            url = month_url(template, year, month)
            stem = file_stem(url, year, month)
            name = urlsplit(url).path.rsplit("/", 1)[-1] or stem
            if _opens(folder / f"{stem}.mmdb"):
                return folder / f"{stem}.mmdb", url, bool(tried), True
            left = deadline - geo._clock()
            if cutoff.why or left <= 0:
                raise geo.GeoError(cutoff.why or took)
            say(f"asking {_host(url)} for {name}")
            try:
                stream = self._fetch(url, min(READ_S, left))
            except Exception as e:  # noqa: BLE001 - urllib's HTTPError and URLError, a refused redirect, a stand-in's own
                if cutoff.why:
                    raise geo.GeoError(cutoff.why) from None
                if _missing(e):
                    tried.append(url)
                    say(f"{name} is not out yet")
                    continue
                raise geo.GeoError(f"the GeoIP file could not be downloaded from {_host(url) or url}: {_words(e)}") from None
            try:
                if cutoff.why:  # it came after the time was up: let go unread
                    raise geo.GeoError(cutoff.why)
                came = _came_from(stream, url)
                body = _Body(stream, cutoff, deadline, took, say, self._told)
                say(f"downloading {name} from {_host(came)}" + (f": {size_words(body.size)}" if body.size else ""))
                path = geo.install_mmdb(body, folder, stem, timeout=None, packing=packing)  # the one deadline
            finally:
                _close(stream)
            return path, came, bool(tried), False
        raise geo.GeoError("no GeoIP file is out yet, neither this month's nor last month's: " + ", ".join(tried))

    def _told(self, words: str) -> None:
        with self._lock:
            self._progress = words

    def _stopping(self, cancel=None) -> str:
        """Why a download under way must end now, in words ("" to go on): the plugin detached, or the user cancelled."""
        if self.closed:
            return DETACHED
        try:
            return CANCELLED if cancel is not None and cancel() else ""
        except Exception:  # noqa: BLE001 - a cancel that cannot say: not cancelled
            return ""

    def _installed(self, path: Path, url: str, fell_back: bool, again: bool = False) -> dict:
        """The file just put in place opened for lookups (the one open before let go), and what it is, in words."""
        with self._lock:
            old, self._geoip, self._geo_looked = self._geoip, None, None
            if old is not None:
                old.close()
            try:
                geoip = geo.GeoIP(path)
                geoip.asn = geo.find_asn(path.parent)  # 1.75.0: the ASN file beside it, as find() opens it
            except geo.GeoError:
                geoip = geo.GeoIP.find(path.parent)
            if not self.closed:
                self._geoip = geoip
        d = geoip.describe() if geoip is not None else {"file": path.name, "date": None, "size": None}
        if geoip is not None and self.closed:  # detached meanwhile: nothing kept open
            geoip.close()
        facts = ", ".join(x for x in ((f"built {d['date']}" if d.get("date") else ""),
                                       (size_words(d["size"]) if d.get("size") else "")) if x)
        said = (f"{d.get('file') or path.name} is installed already" if again else f"installed {d.get('file') or path.name}")
        whence = f"downloaded from {_host(url) or url}" + (": this month's file is not out yet, so last month's"
                                                             if fell_back else "")
        lines = [f"kept in {path.parent}, the only copy" if again else whence,
                 "places on the globe are looked up in it on this machine: no address is sent anywhere"]
        if not again:
            lines.insert(1, f"kept in {path.parent}, in place of any older copy")
        return {"said": said + (f" ({facts})" if facts else ""), "ok": True, "lines": lines, "file": d}

    def _installed_asn(self, path: Path, url: str, fell_back: bool, again: bool = False) -> dict:
        """1.75.0: the ASN file just put in place, and what it is, in words. The GeoIP file open now is let go, so the
        next ask opens it again with the ASN file beside it (geo.GeoIP.find)."""
        with self._lock:
            old, self._geoip, self._geo_looked = self._geoip, None, None
            if old is not None:
                old.close()
        try:
            with geo.GeoIP(path) as opened:
                d = opened.describe()
        except geo.GeoError:
            d = {"file": path.name, "date": None, "size": None}
        facts = ", ".join(x for x in ((f"built {d['date']}" if d.get("date") else ""),
                                       (size_words(d["size"]) if d.get("size") else "")) if x)
        said = (f"{d.get('file') or path.name} is installed already" if again else f"installed {d.get('file') or path.name}")
        whence = f"downloaded from {_host(url) or url}" + (": this month's file is not out yet, so last month's"
                                                             if fell_back else "")
        lines = [f"kept in {path.parent}, the only copy" if again else whence,
                 "each address's network is looked up in it on this machine: no address is sent anywhere"]
        if not again:
            lines.insert(1, f"kept in {path.parent}, beside the GeoIP file, in place of any older ASN file")
        return {"said": said + (f" ({facts})" if facts else ""), "ok": True, "lines": lines, "file": d}

    # -- home ---------------------------------------------------------------------------------------------------------------
    def setting(self, read, every: float = SETTING_S):
        """What `read` gives (the home the user set, read through the plugin's login), kept for `every` seconds: the tab
        is asked every few seconds, its login not as often. forget_setting() has it read anew at the next ask."""
        now = self.clock()
        with self._lock:
            if self._setting is not None and now - self._setting[0] < every:
                return self._setting[1]
        value = read()
        with self._lock:
            self._setting = (now, value)
        return value

    def forget_setting(self) -> None:
        with self._lock:
            self._setting = None

    def public_address(self, public) -> tuple[str | None, str]:
        """This network's public address as the name servers the plugin names (`public`: servers_of) give it, asked once on
        a thread of its own (a lookup waits on the network) and kept for this view's life; asked again HOME_RETRY_S after
        none was given. (the address, or None meanwhile or when there is none; the words why there is none)."""
        with self._lock:
            found = self._public
            if found["address"]:
                return found["address"], ""
            if found["running"]:
                return None, "this network's public address is being asked for"
            if not (servers_of(public, 4) or servers_of(public, 6)):
                return None, "no name server is named to ask for this network's public address"
            if found["at"] is not None and self.clock() - found["at"] < HOME_RETRY_S:
                return None, found["why"] or "no public address was given"
            found["running"] = True
        thread = threading.Thread(target=self._ask_public, args=(public,), name=f"{self.name or 'world'}-public-address",
                                  daemon=True)
        try:
            thread.start()
        except RuntimeError as e:  # no thread to ask on: said, and asked again later
            with self._lock:
                self._public.update(running=False, at=self.clock(), why=f"it could not be asked for: {e}")
        return None, "this network's public address is being asked for"

    def _ask_public(self, public) -> None:
        address, why = None, ""
        try:
            if self._nslookup and nslookup_path() is None:  # no lookup could run: said so, not "the servers did not answer"
                why = nslookup_missing()
            else:
                for version in (4, 6):
                    servers = servers_of(public, version)
                    if not servers or self._halt.is_set():
                        continue
                    try:
                        address, why = self._resolve(version, servers)
                    except Exception as e:  # noqa: BLE001 - a lookup failing says why; asked again later
                        address, why = None, f"the lookup failed ({type(e).__name__})"
                    if address:
                        break
        finally:
            with self._lock:
                if self._halt.is_set():  # stopped meanwhile: nothing kept, asked again once watched again
                    self._public.update(running=False)
                else:
                    self._public.update(address=address or None, why="" if address else (why or "no public address was given"),
                                        at=self.clock(), running=False)

    def _home(self, home, public, geoip) -> tuple[dict | None, str]:
        """(the globe's home, the words saying where it came from or why there is none). This network's public address is
        asked for only once a GeoIP file can place it."""
        said = ""
        if home is not None:
            try:
                place = home_place(home)
            except ValueError as e:
                said = f"{HOME_PLACE_VAR} is not a place ({e}), so it is passed over. "
            else:
                if place is not None:
                    return place, "Home is the place you set."
        yours = f"Set {HOME_PLACE_VAR} (lat,lon[,label]) in this plugin's settings to draw the routes to a place of your own."
        if geoip is None:
            return None, said + f"This machine is placed once a GeoIP file is installed; until then no route is drawn. {yours}"
        if not (servers_of(public, 4) or servers_of(public, 6)):
            return None, said + f"This machine is not placed, so no route is drawn. {yours}"
        address, why = self.public_address(public)
        if address is None:
            return None, said + f"This machine is not placed yet ({why}), so no route is drawn. {yours}"
        place = geoip.lookup(address)
        if place is None or place.lat is None or place.lon is None:
            return None, said + f"The GeoIP file has no point for this network's public address, so no route is drawn. {yours}"
        return ({"lat": place.lat, "lon": place.lon, "label": place.label or "this network"},
                said + "Home is where the GeoIP file puts this network's public address.")

    # -- the charts' samples ---------------------------------------------------------------------------------------------
    def _sample(self, snap: dict, now: float) -> None:
        """The bytes each port here moved since the last ask, kept as one sample (the busiest SAMPLE_PORTS of them), timed
        by the view's own clock (monotonic: a wall clock set back stops nothing). An ask after a pause (watching stopped
        in between) closes the last stretch at the timeout and breaks the lines."""
        ports = {(r["proto"], r["port"]): (int(r["in_bytes"]), int(r["out_bytes"])) for r in snap.get("ports", ())}
        base = self._base
        if base is not None and now - base[0] < MIN_SAMPLE_S:
            return
        self._base = (now, ports)
        if base is None:
            return
        then, before = base
        span = now - then
        paused = span > self.timeout + GAP_S
        if paused:
            span = self.timeout
        moved = {}
        for key, (i, o) in ports.items():
            pi, po = before.get(key, (0, 0))
            di, do = (i - pi if i >= pi else i), (o - po if o >= po else o)  # counted again from 0 once folded away
            if di or do:
                moved[key] = (di, do)
        if len(moved) > SAMPLE_PORTS:
            moved = dict(sorted(moved.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:SAMPLE_PORTS])
        self._samples.append((then + span, span, moved))
        if paused:
            self._samples.append(((then + span + now) / 2, 0.0, None))
        while self._samples and (self._samples[0][0] < now - WINDOW_S or self._samples[0][2] is None):
            self._samples.popleft()  # older than the window, or a break with nothing before it

    def _charts(self, wall: float, now: float) -> dict | None:
        """The busiest ports here charted: bytes a second in and out, each sample's, over the last ten minutes (a
        LiminalCharts spec; its charts' keys begin with the tab's id), each sample at its time of day as the wall clock
        says it now (`wall`, at the view's clock's `now`). None before the second sample."""
        samples = list(self._samples)
        if sum(1 for s in samples if s[2] is not None) < 2:
            return None
        moved = Counter()
        for _, _, ports in samples:
            for key, (i, o) in (ports or {}).items():
                moved[key] += i + o
        busiest = sorted((k for k in moved if moved[k]), key=lambda k: (-moved[k], k[1], k[0]))[:CHART_PORTS]
        if not busiest:
            return None
        charts = []
        for proto, port in busiest:
            ins, outs = [], []
            for _, span, ports in samples:
                if ports is None or span <= 0:
                    ins.append(None)
                    outs.append(None)
                    continue
                i, o = ports.get((proto, port), (0, 0))
                ins.append(round(i / span, 1))
                outs.append(round(o / span, 1))
            charts.append({"key": f"{TAB}-{proto}-{port}", "title": f"Port {port}/{proto} here", "unit": "bytes/s",
                           "lines": [{"key": "in", "name": "in", "values": ins}, {"key": "out", "name": "out", "values": outs}]})
        return {"span": "recent", "t": [round(wall - (now - s[0]), 3) for s in samples], "charts": charts}

    # -- the page -------------------------------------------------------------------------------------------------------
    def page(self, *, home=None, public=None, attribution=None, can_install: bool = True, licence: str = "",
             source: str = "", asn_source: str = "", asn_licence: str = "", keys=None) -> dict:
        """The tab's page (apps/tabs.py's shape): its title and note; the globe (home, each place with its kind, count,
        bytes and ports, the local network's peers summed apart, the attribution of the places, when it was counted); the
        busiest ports here charted; the busiest ports here and elsewhere and the places, tabled; and the GeoIP file's
        install form when none is installed (`can_install`: the plugin names a download; `licence`: its words, shown
        first; `source`: its address, for the host it comes from).

        `home`: the place the user set (home_place's shapes), which wins; else this network's public address placed by the
        GeoIP file, asked of the name servers `public` names (servers_of), else none. `attribution`: {text, url}, drawn
        wherever places are (DB-IP's "IP Geolocation by DB-IP"). While nothing watches (its capture cannot run), the GeoIP
        file is let go again once the page is made."""
        if self.closed:  # an ask still under way as the plugin was detached: nothing opened, nothing asked
            return {"title": TITLE, "note": "Nothing is watched now: the plugin was detached."}
        status = self.watcher.status()
        snap = self.book.snapshot()
        now, tick = self.wall(), self.clock()
        with self._lock:
            self._sample(snap, tick)
            charts = self._charts(now, tick)
        readable, unreadable = geo.available()
        geoip = self.geoip() if readable else None
        try:
            return self._page(status, snap, now, charts, readable, unreadable, geoip, home, public, attribution,
                              can_install, licence, source, asn_source=asn_source, asn_licence=asn_licence, keys=keys)
        finally:
            if not self.watcher.running:  # nobody watches: nothing stays mapped until the next ask
                self._let_go()

    def _page(self, status, snap, now, charts, readable, unreadable, geoip, home, public, attribution, can_install,
              licence, source, asn_source: str = "", asn_licence: str = "", keys=None) -> dict:
        home_spec, home_note = self._home(home, public, geoip)
        here_ports = {r["port"] for r in snap["ports"]}
        there_ports = {r["port"] for r in snap["remote_ports"]}

        local = {"count": 0, "bytes": int(snap["totals"].get("local_bytes", 0)), "places": 0,
                 "packets": int(snap["totals"].get("local_packets", 0))}
        public_groups = []
        for g in snap["groups"]:
            starts = _starts(g)
            if _local_peer(g):
                local["count"] += sum(starts.values()) or 1
                local["bytes"] += int(g["bytes"])
                local["places"] += 1
                continue
            kind = _kind(starts, g, here_ports, there_ports)
            count = starts[kind] or (int(g.get("unjudged", 0) or 0) if kind == "unanswered" else 0) or 1
            public_groups.append((g, kind, count, starts))
        public_groups.sort(key=lambda x: (-x[2], -x[0]["bytes"], x[0]["group"]))
        drawn, rest = public_groups[:MAX_DRAWN], public_groups[MAX_DRAWN:]
        origins = [self._origin(g, kind, count, starts, geoip) for g, kind, count, starts in drawn]
        folded = snap["other"]["groups"]
        more = {"places": len(rest) + int(snap["evicted"]["groups"]),
                "count": sum(c for _, _, c, _ in rest) + sum(_starts(folded).values()),
                "bytes": sum(int(g["bytes"]) for g, _, _, _ in rest) + int(folded.get("bytes", 0))}

        mark = None
        if geoip is not None and isinstance(attribution, Mapping) and (attribution.get("text") or attribution.get("url")):
            mark = {"text": str(attribution.get("text") or ""), "url": str(attribution.get("url") or "")}
        globe_notes = [home_note] if home_note else []
        elsewhere = self.elsewhere()
        if not readable:
            globe_notes.append(f"Places cannot be read here: {unreadable}. Install maxminddb in the platform's Python "
                               f"({os.path.realpath(sys.executable)} -m pip install maxminddb).")
        elif elsewhere:
            globe_notes.append(f"No place is known here. {elsewhere}. Each system's platform installs a GeoIP file of its "
                               "own" + (": with this platform's data folder on this machine's own disk, the tab offers its "
                                        "install." if can_install else ". This plugin offers no GeoIP file to download."))
        elif geoip is None:
            globe_notes.append("No GeoIP file is installed, so no place is known and the globe draws none yet."
                               + (" Download… in the GeoIP sources table downloads one once you accept its licence."
                                  if self.sources else
                                  " Install the GeoIP file… downloads one once you accept its licence." if can_install
                                  else " This plugin offers no GeoIP file to download."))
        if more["places"]:
            globe_notes.append(f"{_plural(more['places'], 'more place')} not drawn ({_plural(more['count'], 'connection')}, "
                               f"{size_words(more['bytes'])}): the {MAX_DRAWN} with the most connections are.")
        globe = {"home": home_spec, "origins": origins, "local": local, "attribution": mark, "updated": _iso(now),
                 "note": " ".join(globe_notes), "more": more}

        out = {"title": TITLE, "note": self._note(status, snap), "globe": globe,
               "tables": [self._ports_table(snap), self._origins_table(origins, local, more, mark),
                          self._remote_table(snap)],
               "watching": {"running": bool(status["running"]), "address": self.address, "timeout": self.timeout,
                            "packets": int(status["packets"]), "error": self.error or status["error"],
                            "since": _iso(snap["since"]) if snap.get("since") else None}}
        if charts is not None:
            out["charts"] = [charts]
        if self.sources:  # 1.102.0: the sources' table and its forms, in place of the two install buttons
            table, forms = self.sources_table(keys)
            out["tables"].append(table)
            if forms:
                out["forms"] = forms
            return out
        offer = self._offer(geoip, readable, can_install, now)
        if offer is not None:
            out["forms"] = [geoip_form(licence, source, self.folder, update=offer == "update")]
            verb = "Update" if offer == "update" else "Install"
            out["actions"] = [{"form": FORM, "title": f"{verb} the GeoIP file…", "note": "Downloads it once you accept its licence"}]
        asn_offer = self._asn_offer(geoip, readable, asn_source, now)  # 1.75.0: the ASN file, once the GeoIP file is in
        if asn_offer is not None:
            out.setdefault("forms", []).append(asn_form(asn_licence, asn_source, geo.asn_folder(self.folder),
                                                     update=asn_offer == "update"))
            verb = "Update" if asn_offer == "update" else "Install"
            out.setdefault("actions", []).append({"form": ASN_FORM, "title": f"{verb} the ASN file…",
                                                  "note": "Each network's number and operator, once you accept its licence"})
        return out

    def _asn_offer(self, geoip, readable: bool, asn_source: str, now: float) -> str | None:
        """1.75.0: whether the page offers the ASN file's download: "install" when the GeoIP file is open with no ASN
        file beside it, "update" when the ASN file was built before this month; None when the plugin names none, the
        GeoIP file is not in yet (it comes first), a download is under way, or the folder is another system's."""
        if not asn_source or not readable or geoip is None or self._installing.locked() or self.elsewhere():
            return None
        asn = getattr(geoip, "asn", None)
        if asn is None:
            return "install"
        built = (asn.describe().get("date") or "")[:7]
        this = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m")
        return "update" if built and built < this else None

    def _offer(self, geoip, readable: bool, can_install: bool, now: float) -> str | None:
        """Whether the page offers the GeoIP file's download: "install" when none is open, "update" when the one open was
        built before this month; None when the plugin names no download, the file cannot be read here anyway, or the
        folder is on another system's drive (elsewhere: that system's platform installs its own)."""
        if not can_install or not readable or self._installing.locked() or self.elsewhere():
            return None
        if geoip is None:
            return "install"
        built = (geoip.describe().get("date") or "")[:7]
        this = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m")
        return "update" if built and built < this else None

    def _note(self, status: dict, snap: dict) -> str:
        counted = int(snap["totals"].get("packets", 0)) + int(snap["totals"].get("local_packets", 0))
        error = self.error or status.get("error") or ""  # it could not start; or its capture failed while it read
        if status["running"]:
            where = f" ({self.address})" if self.address else ""
            head = (f"Watching every packet at this machine's network adapter{where} while this tab is shown, and for "
                    f"{self.timeout:g} s after: {_plural(int(status['packets']), 'packet')} read so far.")
        elif error:
            head = (f"Traffic cannot be watched here: {_shown_error(error)}. {capture_help(error)} It is tried again while "
                    "this tab is shown." + (" What is shown was counted before." if counted else ""))
        else:
            head = "Watching starts while this tab is shown."
        if self._installing.locked():
            with self._lock:
                progress, what = self._progress, self._what or "GeoIP file"  # 1.75.0: or the ASN file
            head += f" {'An' if what.startswith('ASN') else 'A'} {what} is being downloaded." + (
                f" So far: {progress}." if progress else "")
        return head + (" Only counts are kept, in memory. Places come from the GeoIP file on this machine, and no address "
                       "is sent anywhere.")

    def _origin(self, g: dict, kind: str, count: int, starts: dict, geoip) -> dict:
        place = geoip.lookup(g["address"]) if geoip is not None else None
        return {"id": g["group"], "lat": place.lat if place else None, "lon": place.lon if place else None,
                "label": place.label if place else "", "country": (place.country_name or place.country or "") if place else "",
                "code": (place.country or "") if place else "", "city": (place.city or "") if place else "",
                "asn": place.asn if place else None, "org": (place.org or "") if place else "",
                "count": int(count), "bytes": int(g["bytes"]), "kind": kind, "ports": list(g.get("ports") or ()),
                "starts": dict(starts), "unjudged": int(g.get("unjudged", 0) or 0), "family": g.get("family")}

    @staticmethod
    def _ports_table(snap: dict) -> dict:
        rows = [[f"{r['port']}/{r['proto']}", size_words(r["in_bytes"]), size_words(r["out_bytes"]), f"{r['packets']:,}",
                 f"{r['new_in']:,}", f"{r['unanswered'] + r['unanswered_udp']:,}"] for r in snap["ports"][:PORT_ROWS]]
        left = snap["ports"][PORT_ROWS:]
        others = [snap["other"]["ports"]] if snap["evicted"]["ports"] else []
        folded = int(snap["evicted"]["ports"]) + len(left)
        if folded:
            tally = left + others
            rows.append([f"{_plural(folded, 'more port')}", size_words(sum(t["in_bytes"] for t in tally)),
                         size_words(sum(t["out_bytes"] for t in tally)), f"{sum(t['packets'] for t in tally):,}",
                         f"{sum(t['new_in'] for t in tally):,}",
                         f"{sum(t['unanswered'] + t['unanswered_udp'] for t in tally):,}"])
        return {"title": "Busiest ports here",
                "note": ("This machine's ports that others reached, the most bytes first. A connection this machine started "
                         "is counted at the far end's port, under Ports elsewhere. An attempt is unanswered when nothing "
                         "came back within 3 s."),
                "columns": [{"title": "Port"}, {"title": "In", "num": True}, {"title": "Out", "num": True},
                            {"title": "Packets", "num": True}, {"title": "New connections", "num": True},
                            {"title": "Unanswered", "num": True}],
                "rows": rows, "empty": "No port here has been reached while this tab was shown."}

    @staticmethod
    def _remote_table(snap: dict) -> dict:
        rows = [[f"{r['port']}/{r['proto']}", size_words(r["in_bytes"]), size_words(r["out_bytes"]), f"{r['packets']:,}",
                 f"{r['new_out']:,}"] for r in snap["remote_ports"][:REMOTE_ROWS]]
        return {"title": "Ports elsewhere",
                "note": "The far end's port of the connections this machine started (443 for the web), the most bytes first.",
                "columns": [{"title": "Port"}, {"title": "In", "num": True}, {"title": "Out", "num": True},
                            {"title": "Packets", "num": True}, {"title": "New connections", "num": True}],
                "rows": rows, "empty": "This machine has reached no port elsewhere while this tab was shown."}

    @staticmethod
    def _origins_table(origins: list, local: dict, more: dict, mark: dict | None) -> dict:
        def network(o: dict) -> dict:
            said = " · ".join(x for x in ((f"AS{o['asn']}" if o["asn"] else ""), o["org"]) if x)
            others = ", ".join(f"{n:,} {KIND_WORDS[k]}" for k, n in o["starts"].items() if n and k != o["kind"])
            unjudged = f"{o.get('unjudged', 0):,} not judged" if o.get("unjudged") else ""
            sub = "; ".join(x for x in (said, f"also {others}" if others else "", unjudged) if x)
            return {"text": o["id"], "sub": sub} if sub else {"text": o["id"]}

        rows = [[o["country"] or "–", o["city"] or "–", network(o), f"{o['count']:,}", size_words(o["bytes"]),
                 KIND_WORDS[o["kind"]]] for o in origins[:ORIGIN_ROWS]]
        if len(origins) > ORIGIN_ROWS:
            left = origins[ORIGIN_ROWS:]
            rows.append(["–", "–", {"text": _plural(len(left), "more place"), "sub": "drawn on the globe"},
                         f"{sum(o['count'] for o in left):,}", size_words(sum(o['bytes'] for o in left)), "–"])
        if more["places"]:
            rows.append(["–", "–", {"text": _plural(more["places"], "more place"), "sub": "not drawn"}, f"{more['count']:,}",
                         size_words(more["bytes"]), "–"])
        if local["places"] or local["packets"]:
            rows.append(["–", "–", {"text": "the local network", "sub": "never placed"}, f"{local['count']:,}",
                         size_words(local["bytes"]), "local"])
        whose = ""
        if mark:
            whose = " Places: " + ", ".join(x for x in (mark.get("text"), mark.get("url")) if x) + "."
        return {"title": "Places",
                "note": ("Where traffic came from and went to, by network (an IPv4 /24, an IPv6 /48), the most connections "
                         "first: the count is the connections started while this tab was shown (the attempts, when "
                         "unanswered; one not judged when watching paused before its answer could come)." + whose),
                "columns": [{"title": "Country"}, {"title": "City"}, {"title": "Network"}, {"title": "Count", "num": True},
                            {"title": "Bytes", "num": True}, {"title": "Kind"}],
                "rows": rows, "empty": "No traffic has been counted while this tab was shown."}

    def describe(self) -> dict:
        """The watching and the GeoIP file as they are now, asking nothing (for the plugin's API card): the Watcher's
        status, the address watched, why it cannot start, and the GeoIP file: the one open (its "open" true), else the
        one last open, let go while nobody watches ("open" false); None before one was open."""
        with self._lock:
            geoip, said = self._geoip, self._geo_said
        return {"watching": self.watcher.status(), "address": self.address, "error": self.error,
                "geoip": geoip.describe() if geoip is not None else (dict(said) if said else None)}
