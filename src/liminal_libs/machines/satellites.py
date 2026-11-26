"""The satellites on the firewalls' globe (1.104.0, Monday list item 32): Starlink, OneWeb and HughesNet placed from
CelesTrak's published orbits (the user chose CelesTrak and the sgp4 package), each one's footprint the ground that sees
it at ELEVATION degrees or more.

- The pure parts need no package: a footprint's radius (footprint_deg: on a spherical Earth of EARTH_KM, a satellite
  at height h seen at elevation e serves the ground within the central angle arccos(R cos e / (R + h)) - e: Starlink
  at 550 km 8.46 degrees, OneWeb at 1,200 km 15.30, a geostationary one 57.12); the Greenwich mean sidereal time (gmst,
  IAU 1982, as Vallado gives it); a TEME position turned into latitude, longitude and height (teme_to_latlon, WGS 84);
  CelesTrak's CSV read into its OMM rows (omm_rows).
- The orbit math is the sgp4 package's (Sky), imported only from the folder its download was unpacked to
  (the data folder's packages/sgp4-<version>/), never from anywhere else: until the user downloads it (offered on the
  World Wide Web tab, its size, its sum and its licence said first: package_form), Sky.positions raises SkyUnavailable
  and the layer says it needs the package and draws nothing. The wheel is unpacked by install_package: every file's
  sha256 checked against the wheel's own RECORD before the folder is used.
- Nothing runs when unused: the positions are worked out when the page asks for them, and kept for nothing."""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import math
import os
import shutil
import sys
import threading
import time
import zipfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

EARTH_KM = 6371.0088  # the mean radius
WGS84_A, WGS84_F = 6378.137, 1 / 298.257223563
ELEVATION = 25.0  # degrees above the horizon a terminal sees its satellite at, at the least
GEO_KM = 35_786.0  # a geostationary orbit's height
GEO_BAND_KM = 500.0  # a satellite this near that height, and nearly circular, is a geostationary one
STEP_S = 60.0  # the page is given each place now and STEP_S later, to move it between
STALE_D = 14.0  # an orbit older than this many days is left out (its place is no longer to be trusted)
MAX_ROWS = 20_000  # rows read of CelesTrak's CSV (Starlink's some 9,000 in 2026)
PACKAGES = "packages"  # the data folder's folder the packages downloaded for the globe are unpacked into
OMM_FIELDS = ("OBJECT_NAME", "OBJECT_ID", "EPOCH", "MEAN_MOTION", "ECCENTRICITY", "INCLINATION", "RA_OF_ASC_NODE",
              "ARG_OF_PERICENTER", "MEAN_ANOMALY", "EPHEMERIS_TYPE", "CLASSIFICATION_TYPE", "NORAD_CAT_ID",
              "ELEMENT_SET_NO", "REV_AT_EPOCH", "BSTAR", "MEAN_MOTION_DOT", "MEAN_MOTION_DDOT")
NEEDED = ("OBJECT_NAME", "EPOCH", "MEAN_MOTION", "ECCENTRICITY", "INCLINATION", "RA_OF_ASC_NODE", "ARG_OF_PERICENTER",
          "MEAN_ANOMALY", "NORAD_CAT_ID", "BSTAR")
NEEDS_PACKAGE = "Needs the sgp4 package: Download it on this tab"


class SkyUnavailable(RuntimeError):
    """The orbit math cannot be done here: the sgp4 package is not downloaded (or does not import from its folder)."""


# -- the pure parts ---------------------------------------------------------------------------------------------------
def footprint_deg(height_km: float, elevation_deg: float = ELEVATION) -> float:
    """The central angle, in degrees, of the ground that sees a satellite at `height_km` at `elevation_deg` or more."""
    e = math.radians(elevation_deg)
    return math.degrees(math.acos(EARTH_KM * math.cos(e) / (EARTH_KM + height_km)) - e)


def gmst(jd_ut1: float) -> float:
    """The Greenwich mean sidereal time at a Julian date (UT1), in radians from 0 to 2 pi (IAU 1982, Vallado's
    gstime)."""
    t = (jd_ut1 - 2451545.0) / 36525.0
    seconds = -6.2e-6 * t ** 3 + 0.093104 * t ** 2 + (876600.0 * 3600 + 8640184.812866) * t + 67310.54841
    return math.radians(seconds / 240.0) % (2 * math.pi)


def julian(when: float) -> float:
    """A moment (seconds since 1970, UTC) as a Julian date."""
    return when / 86400.0 + 2440587.5


def teme_to_latlon(r_km, jd: float) -> tuple[float, float, float]:
    """A TEME position (x, y, z in km) at Julian date `jd` as (latitude, longitude, height in km) over WGS 84: turned
    by the sidereal time (polar motion left out: metres), the latitude found by Bowring's iteration."""
    x, y, z = (float(v) for v in r_km)
    g = gmst(jd)
    xe, ye = math.cos(g) * x + math.sin(g) * y, -math.sin(g) * x + math.cos(g) * y
    lon = math.degrees(math.atan2(ye, xe))
    p = math.hypot(xe, ye)
    e2 = WGS84_F * (2 - WGS84_F)
    lat = math.atan2(z, p * (1 - e2))
    for _ in range(6):
        n = WGS84_A / math.sqrt(1 - e2 * math.sin(lat) ** 2)
        lat = math.atan2(z + e2 * n * math.sin(lat), p)
    n = WGS84_A / math.sqrt(1 - e2 * math.sin(lat) ** 2)
    height = p / math.cos(lat) - n if abs(math.cos(lat)) > 1e-9 else abs(z) - n * (1 - e2)
    return math.degrees(lat), (lon + 540.0) % 360.0 - 180.0, height


def epoch_of(text: str) -> float | None:
    """An OMM EPOCH ("2026-11-26T03:11:15.123456") as seconds since 1970, UTC; None when it does not read."""
    try:
        when = datetime.fromisoformat(str(text).strip().rstrip("Z"))
    except ValueError:
        return None
    return (when if when.tzinfo else when.replace(tzinfo=timezone.utc)).timestamp()


def omm_rows(data, most: int = MAX_ROWS) -> tuple[list[dict], int]:
    """CelesTrak's CSV (its GP data as OMM fields) as its rows, the OMM_FIELDS kept of each, and how many were left
    out: a row without the NEEDED fields, or whose numbers or epoch do not read; past `most` rows. ValueError for a
    file that is no such CSV."""
    text = data.decode("utf-8-sig", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not set(NEEDED) <= {f.strip() for f in reader.fieldnames}:
        raise ValueError("it is no CSV of orbits (CelesTrak's GP data as OMM fields)")
    rows, left = [], 0
    for row in reader:
        if len(rows) >= most:
            left += 1
            continue
        kept = {k: (row.get(k) or "").strip() for k in OMM_FIELDS if row.get(k) is not None}
        try:
            for k in ("MEAN_MOTION", "ECCENTRICITY", "INCLINATION", "RA_OF_ASC_NODE", "ARG_OF_PERICENTER",
                      "MEAN_ANOMALY", "BSTAR"):
                float(kept[k])
            norad = int(kept["NORAD_CAT_ID"])
        except (KeyError, ValueError):
            left += 1
            continue
        if not kept.get("OBJECT_NAME") or epoch_of(kept.get("EPOCH", "")) is None or norad <= 0:
            left += 1
            continue
        rows.append(kept)
    return rows, left


def height_of(row: Mapping) -> float:
    """A satellite's mean height over the Earth from its mean motion (revolutions a day), in km."""
    mu = 398600.4418
    n = float(row["MEAN_MOTION"]) * 2 * math.pi / 86400.0
    return (mu / n ** 2) ** (1 / 3) - EARTH_KM


def geostationary(row: Mapping) -> bool:
    """Whether an orbit is geostationary: near GEO_KM, nearly circular, nearly equatorial."""
    try:
        return (abs(height_of(row) - GEO_KM) < GEO_BAND_KM and float(row["ECCENTRICITY"]) < 0.01
                and float(row["INCLINATION"]) < 5.0)
    except (KeyError, ValueError, ZeroDivisionError):
        return False


# -- the orbit math, the sgp4 package's -------------------------------------------------------------------------------
def package_folder(version: str, data_dir=None) -> Path:
    """Where a version of the sgp4 package is unpacked: the data folder's packages/sgp4-<version>/."""
    from .. import layout
    return Path(data_dir if data_dir is not None else layout.data_dir()) / PACKAGES / f"sgp4-{version}"


_LOCK = threading.Lock()


def load_package(folder) -> object:
    """The sgp4 package imported from `folder` (its unpacked wheel) and nowhere else: its `api` and `omm` modules.
    SkyUnavailable when it is not there, does not import, or an sgp4 from elsewhere is loaded in this process."""
    folder = Path(folder)
    init = folder / "sgp4" / "__init__.py"
    if not init.is_file():
        raise SkyUnavailable(NEEDS_PACKAGE)
    with _LOCK:
        have = sys.modules.get("sgp4")
        if have is not None:
            where = os.path.realpath(getattr(have, "__file__", "") or "")
            if not where.startswith(os.path.realpath(folder) + os.sep):
                raise SkyUnavailable("an sgp4 package from elsewhere is loaded in this process: only the one "
                                     f"downloaded for the globe is used ({folder})")
        else:
            spec = importlib.util.spec_from_file_location("sgp4", init,
                                                          submodule_search_locations=[str(folder / "sgp4")])
            if spec is None or spec.loader is None:
                raise SkyUnavailable(NEEDS_PACKAGE)
            module = importlib.util.module_from_spec(spec)
            sys.modules["sgp4"] = module
            try:
                spec.loader.exec_module(module)
            except Exception as e:  # noqa: BLE001 - a folder that does not import: said, and let go
                sys.modules.pop("sgp4", None)
                raise SkyUnavailable(f"the sgp4 package in {folder} does not import: {e}") from None
        try:
            import sgp4.api as api  # noqa: PLC0415 - from the folder just loaded
            import sgp4.omm as omm  # noqa: PLC0415
        except Exception as e:  # noqa: BLE001
            raise SkyUnavailable(f"the sgp4 package in {folder} does not import: {e}") from None
    return type("Package", (), {"api": api, "omm": omm, "folder": folder})


class Sky:
    """The satellites' places from their kept orbits (infrastore's orbits table), worked out with the sgp4 package
    loaded from `folder` (load_package), or with `package` (a test's stand-in of its calls)."""

    def __init__(self, folder=None, package=None, clock=time.time):
        self.folder, self._package, self.clock = folder, package, clock

    def package(self):
        if self._package is None:
            if self.folder is None:
                raise SkyUnavailable(NEEDS_PACKAGE)
            self._package = load_package(self.folder)
        return self._package

    def available(self) -> tuple[bool, str]:
        try:
            self.package()
        except SkyUnavailable as e:
            return False, str(e)
        return True, ""

    def positions(self, rows, when: float | None = None, elevation: float = ELEVATION) -> dict:
        """Each satellite's place at `when` (the clock's now) and STEP_S later: {"at", "satellites": [{"norad",
        "name", "lat", "lon", "lat2", "lon2", "height", "footprint", "geo"}], "left": {why: how many}}. `rows`: the
        orbits table's ({"norad", "name", "epoch", "omm"}). SkyUnavailable without the package."""
        pkg = self.package()
        when = self.clock() if when is None else float(when)
        left: dict[str, int] = {}
        sats, kept = [], []
        for row in rows:
            if when - float(row["epoch"]) > STALE_D * 86400:
                left["older than 14 days"] = left.get("older than 14 days", 0) + 1
                continue
            sat = pkg.api.Satrec()
            try:
                pkg.omm.initialize(sat, dict(row["omm"]))
            except Exception:  # noqa: BLE001 - an orbit its math does not take: counted
                left["not read by the orbit math"] = left.get("not read by the orbit math", 0) + 1
                continue
            sats.append(sat)
            kept.append(row)
        out = {"at": when, "satellites": [], "left": left}
        if not sats:
            return out
        import numpy as np  # noqa: PLC0415 - the package's arrays
        jd, fr = [], []
        for t in (when, when + STEP_S):
            j = julian(t)
            jd.append(math.floor(j - 0.5) + 0.5)
            fr.append(j - jd[-1])
        errors, r, _ = pkg.api.SatrecArray(sats).sgp4(np.array(jd), np.array(fr))
        for i, row in enumerate(kept):
            if errors[i][0] or errors[i][1]:
                left["its propagation failed"] = left.get("its propagation failed", 0) + 1
                continue
            lat, lon, height = teme_to_latlon(r[i][0], jd[0] + fr[0])
            lat2, lon2, _ = teme_to_latlon(r[i][1], jd[1] + fr[1])
            if not height > 100:
                left["below 100 km"] = left.get("below 100 km", 0) + 1
                continue
            out["satellites"].append({"norad": row["norad"], "name": row["name"], "lat": lat, "lon": lon,
                                      "lat2": lat2, "lon2": lon2, "height": height,
                                      "footprint": footprint_deg(height, elevation),
                                      "geo": geostationary(row["omm"])})
        return out


# -- the package's download -------------------------------------------------------------------------------------------
class PackageError(Exception):
    """The package's wheel did not unpack or does not match its RECORD: nothing was put in place."""


def _record_sum(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def unpack_wheel(wheel, into, *, most: int = 16 << 20) -> Path:
    """A wheel's files unpacked into `into` (made new beside itself and put in place in one step), each file's sha256
    checked against the wheel's RECORD first: a file the RECORD does not name, one whose sum or size differs, a name
    that leads out of the folder, or more than `most` bytes in all is refused (PackageError), nothing put in place."""
    into = Path(into)
    try:
        z = zipfile.ZipFile(wheel)
    except (zipfile.BadZipFile, OSError) as e:
        raise PackageError(f"the wheel does not read: {e}") from None
    with z:
        records = [n for n in z.namelist() if n.endswith(".dist-info/RECORD") and n.count("/") == 1]
        if len(records) != 1:
            raise PackageError("the wheel holds no RECORD of its files")
        record = {}
        for line in csv.reader(io.StringIO(z.read(records[0]).decode("utf-8"))):
            if line and line[0]:
                record[line[0]] = (line[1] if len(line) > 1 else "", line[2] if len(line) > 2 else "")
        total, files = 0, []
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename
            parts = name.split("/")
            if name.startswith("/") or "\\" in name or ".." in parts or ":" in name:
                raise PackageError(f"the wheel's {name[:80]!r} leads out of its folder")
            total += info.file_size
            if total > most:
                raise PackageError(f"the wheel unpacks to more than {most:,} bytes")
            data = z.read(info)
            want, size = record.get(name, (None, ""))
            if want is None:
                raise PackageError(f"the wheel's {name[:80]!r} is not in its RECORD")
            if name != records[0] and (want != _record_sum(data) or (size and int(size) != len(data))):
                raise PackageError(f"the wheel's {name[:80]!r} is not as its RECORD says")
            files.append((parts, data))
    temp = into.with_name(into.name + ".part")
    shutil.rmtree(temp, ignore_errors=True)
    try:
        for parts, data in files:
            target = temp.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        shutil.rmtree(into, ignore_errors=True)
        os.replace(temp, into)
    except OSError as e:
        shutil.rmtree(temp, ignore_errors=True)
        raise PackageError(f"the package could not be put in {into}: {e}") from None
    return into


# -- the package's offer, and the tab's sky ---------------------------------------------------------------------------
SKY_HOOK, SKY_GET_HOOK, SKY_REMOVE_HOOK = "world_sky", "world_sky_get", "world_sky_remove"
PACKAGE_FORM, PACKAGE_REMOVE_FORM = "world-sky-package", "world-sky-package-remove"
SKY_ASK_S = 60.0  # the page asks the satellites' places again this often at most
SLOTS = (1, 2, 3)  # the constellations' colours: the theme's --sky-1 to --sky-3


class Package:
    """The sgp4 package as a plugin pins it: its version, its wheel (download.Source: address, name, size, sha256,
    hosts) and its licence's words (MIT). Plain data in the plugin: the library names no host."""

    def __init__(self, version: str, source, licence: str, licence_name: str = "MIT"):
        self.version, self.source, self.licence, self.licence_name = version, source, licence, licence_name

    @classmethod
    def of(cls, said):
        from . import download
        if said is None or isinstance(said, cls):
            return said
        if not isinstance(said, Mapping):
            raise ValueError("the sgp4 package's pin is a dict (version, url, name, size, sha256, licence)")
        version = str(said.get("version") or "")
        if not version or not all(c.isalnum() or c == "." for c in version):
            raise ValueError("the sgp4 package's pin names its version (2.27)")
        size, digest = said.get("size"), str(said.get("sha256") or "")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0 or len(digest) != 64:
            raise ValueError("the sgp4 package's pin says its size and its sha256: both are checked")
        name = str(said.get("name") or "")
        if not name.endswith(".whl") or "/" in name or "\\" in name:
            raise ValueError("the sgp4 package's pin names its wheel (a .whl)")
        licence = " ".join(str(said.get("licence") or "").split())
        if not licence:
            raise ValueError("the sgp4 package's pin holds its licence's words, shown before it is downloaded")
        source = download.Source(str(said.get("url") or ""), name, size, digest, tuple(said.get("hosts") or ()))
        return cls(version, source, licence, str(said.get("licence_name") or "MIT"))


def package_form(package: Package, data_dir=None) -> dict:
    """The package's download form, as a data set's (infrastructure.form): its first confirmation the file, the host,
    the size, the sha256 and where it is unpacked, its licence's words shown and accepted next."""
    from .world import size_words, _host
    where = package_folder(package.version, data_dir)
    return {
        "id": PACKAGE_FORM, "hook": SKY_GET_HOOK, "title": f"Download the sgp4 package {package.version}", "job": True,
        "note": "The orbit math the satellites are placed with, kept on this machine.",
        "fields": [{"name": "accept_licence", "type": "accept", "title": f"Accept its licence ({package.licence_name})?",
                    "words": package.licence, "yes": "Accept it and download"}],
        "confirm": {"title": f"Download the sgp4 package {package.version}?", "yes": "Go on",
                    "words": (f"{package.source.name} is asked of {_host(package.source.url).lower()} in one request, "
                              f"made now on your word: {size_words(package.source.size)}, its sha256 "
                              f"{package.source.sha256} checked, and every file of it checked against its own "
                              f"RECORD before it is unpacked into {where}. Nothing is installed into Python itself: "
                              "only the globe imports it, from that folder. Its licence, first: "
                              f"{package.licence} You are asked to accept it next.")}}


def package_remove_form(package: Package, data_dir=None) -> dict:
    where = package_folder(package.version, data_dir)
    return {"id": PACKAGE_REMOVE_FORM, "hook": SKY_REMOVE_HOOK, "title": "Remove the sgp4 package",
            "fields": [], "confirm": {"title": "Remove the sgp4 package?", "yes": "Remove it",
                                      "words": f"{where} is removed: the satellites are no longer placed until it is "
                                               "downloaded again."}}


def install_package(package: Package, data_dir=None, *, accept_licence=False, log=None, cancel=None,
                    opener=None) -> dict:
    """The package downloaded (download.fetch: its size and sha256 checked), its wheel unpacked into its folder
    (unpack_wheel: every file against its RECORD), the wheel itself removed. world.LicenceRefused until the licence
    is accepted (exactly True); DownloadError or PackageError, in words, when nothing was put in place."""
    from . import download
    from .world import LicenceRefused
    if accept_licence is not True:
        raise LicenceRefused("The sgp4 package is downloaded only once you accept its licence.")
    into = package_folder(package.version, data_dir)
    downloads = into.parent / ".downloads"
    say = log if callable(log) else (lambda _line: None)
    wheel = download.fetch(package.source, downloads, log=log, cancel=cancel, resume=True, limit=16 << 20,
                           timeout=600.0, opener=opener)
    try:
        say(f"unpacking {package.source.name}, each file checked against its RECORD")
        unpack_wheel(wheel, into)
    finally:
        try:
            wheel.unlink()
        except OSError:
            pass
    return {"said": f"installed the sgp4 package {package.version}", "ok": True,
            "lines": [f"unpacked into {into}", "the satellites are placed with it from now on"]}


def remove_package(package: Package, data_dir=None) -> dict:
    into = package_folder(package.version, data_dir)
    if not into.exists():
        return {"said": "the sgp4 package is not installed here", "ok": True}
    shutil.rmtree(into)
    return {"said": "removed the sgp4 package", "ok": True, "lines": [f"{into} is removed"]}


def _packed(values, code: str) -> str:
    from array import array
    a = array(code, values)
    if sys.byteorder == "big":
        a.byteswap()
    return base64.b64encode(a.tobytes()).decode("ascii")


class SkyView:
    """The World Wide Web tab's sky: the constellations of the plugin's omm-csv data sets, their orbits kept in its
    database (`index`: infrastructure.Index), placed with the package (`package`: a Package, the plugin's pin) loaded
    from its folder. Nothing is worked out until the page asks (read)."""

    def __init__(self, index, package=None, data_dir=None, sky: Sky | None = None, clock=time.time):
        self.index, self.package, self.data_dir, self.clock = index, Package.of(package), data_dir, clock
        folder = package_folder(self.package.version, data_dir) if self.package else None
        self.sky = sky if sky is not None else Sky(folder, clock=clock)

    def sets(self) -> list:
        return [d for d in self.index.datasets if d.format == "omm-csv"]

    def installed(self) -> bool:
        return bool(self.package) and package_folder(self.package.version, self.data_dir).is_dir()

    def spec(self) -> dict | None:
        """What the globe is told of the sky: {"hook", "every", "needs", "constellations": [{"id", "title", "slot",
        "count", "epoch"}]}; None when the plugin names no constellation."""
        sets = self.sets()
        if not sets:
            return None
        ok, why = self.sky.available() if self.package or self.sky._package else (False, NEEDS_PACKAGE)
        try:
            kept = self.index.store().orbits()
        except Exception:  # noqa: BLE001 - a database that cannot be read: nothing kept
            kept = []
        out = []
        for i, d in enumerate(sets):
            mine = [o for o in kept if o["constellation"] == d.constellation]
            out.append({"id": d.constellation, "title": d.title, "slot": SLOTS[i % len(SLOTS)], "count": len(mine),
                        "epoch": world_iso(max((o["epoch"] for o in mine), default=0)) if mine else "",
                        "beams": {str(norad): list(ids) for norad, ids in d.beams},
                        "credit": dict(d.credit)})  # the review: drawn on the globe while its footprints are
        return {"hook": SKY_HOOK, "every": SKY_ASK_S, "needs": "" if ok else why, "constellations": out}

    def read(self, t=None, elevation: float = ELEVATION) -> dict:
        """Each constellation's satellites at `t` (seconds since 1970; now when not given) and a minute later, packed:
        {"at", "elevation", "constellations": [{"id", "n", "now": base64 int32 lat, lon pairs in 1e-4 degrees, "next"
        likewise, "radius": base64 int16 footprints in 1e-2 degrees, "geo": [their indexes], "left"}]}; or {"needs":
        why} without the package. ValueError for a moment that is no number."""
        if t is not None and (isinstance(t, bool) or not isinstance(t, (int, float)) or t != t):
            raise ValueError("the moment shown is a number of seconds since 1970")
        if not self.sets():
            return {"constellations": []}
        try:
            self.sky.package()
        except SkyUnavailable as e:
            return {"needs": str(e), "constellations": []}
        when = self.clock() if t is None else float(t)
        kept = self.index.store().orbits()
        out = []
        for d in self.sets():
            rows = [o for o in kept if o["constellation"] == d.constellation]
            got = self.sky.positions(rows, when, elevation)
            sats = got["satellites"]
            out.append({"id": d.constellation, "n": len(sats),
                        "now": _packed([round(v * 1e4) for s in sats for v in (s["lat"], s["lon"])], "i"),
                        "next": _packed([round(v * 1e4) for s in sats for v in (s["lat2"], s["lon2"])], "i"),
                        "radius": _packed([min(32767, round(s["footprint"] * 100)) for s in sats], "h"),
                        "geo": [i for i, s in enumerate(sats) if s["geo"]],
                        "geo_norad": [s["norad"] for s in sats if s["geo"]], "left": got["left"]})
        return {"at": when, "elevation": elevation, "constellations": out}

    def forms(self) -> list[dict]:
        if not self.package:
            return []
        return [package_remove_form(self.package, self.data_dir) if self.installed()
                else package_form(self.package, self.data_dir)]

    def row(self) -> list | None:
        """The package's row in the data sets' table, as theirs are: what it is, from, licence, here, the buttons."""
        if not self.package or not self.sets():
            return None
        from .world import size_words
        here = self.installed()
        return [{"text": f"The sgp4 package {self.package.version}", "sub": "the orbit math the satellites are placed "
                 f"with ({size_words(self.package.source.size)})"}, "PyPI (Brandon Rhodes)", self.package.licence_name,
                "installed" if here else "not downloaded",
                "" if here else {"form": PACKAGE_FORM, "title": "Download…"},
                {"form": PACKAGE_REMOVE_FORM, "title": "Remove…"} if here else ""]


def world_iso(seconds: float) -> str:
    from .world import _iso
    return _iso(float(seconds))
