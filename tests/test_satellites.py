"""The satellites on the globe (1.104.0, Monday list item 32: machines/satellites.py): the footprints' radii, the
sidereal time, a TEME place turned into latitude and longitude, CelesTrak's CSV read; the orbit math through a
stand-in of the sgp4 package's calls, and nothing without it; the wheel unpacked only as its RECORD says, and the
package imported from its own folder alone. Nothing is downloaded and no real package is needed."""
from __future__ import annotations

import base64
import hashlib
import io
import math
import sys
import zipfile

import numpy as np
import pytest

from liminal_libs.machines import satellites as S
from liminal_libs.machines.satellites import PackageError, Sky, SkyUnavailable

CSV = ("OBJECT_NAME,OBJECT_ID,EPOCH,MEAN_MOTION,ECCENTRICITY,INCLINATION,RA_OF_ASC_NODE,ARG_OF_PERICENTER,"
       "MEAN_ANOMALY,EPHEMERIS_TYPE,CLASSIFICATION_TYPE,NORAD_CAT_ID,ELEMENT_SET_NO,REV_AT_EPOCH,BSTAR,"
       "MEAN_MOTION_DOT,MEAN_MOTION_DDOT\n"
       "STARLINK-1007,2019-074A,2026-11-25T12:00:00.000000,15.06,0.0001,53.05,100.1,90.2,270.3,0,U,44713,999,"
       "38000,0.0001,0.00001,0\n"
       "ECHOSTAR 17,2012-035A,2026-11-25T00:00:00.000000,1.0027,0.0002,0.03,80.0,10.0,200.0,0,U,38551,999,5000,"
       "0,0,0\n"
       "SHORT,2020-001A,2026-11-25T00:00:00\n"
       "BROKEN,2020-002A,not a date,15.0,0.0,53,0,0,0,0,U,45000,999,1,0,0,0\n")


def test_a_footprint_is_the_ground_that_sees_its_satellite_at_25_degrees():
    assert S.footprint_deg(550) == pytest.approx(8.46, abs=0.01)
    assert S.footprint_deg(1200) == pytest.approx(15.30, abs=0.01)
    assert S.footprint_deg(S.GEO_KM) == pytest.approx(57.12, abs=0.01)
    assert S.footprint_deg(550, 0) > S.footprint_deg(550, 25) > S.footprint_deg(550, 40)


def test_the_sidereal_time_and_a_teme_place_on_the_globe():
    assert math.degrees(S.gmst(2451545.0)) == pytest.approx(280.46061837, abs=1e-6)
    jd = 2461000.25
    g = S.gmst(jd)
    r = S.WGS84_A + 550
    lat, lon, height = S.teme_to_latlon((r * math.cos(g + math.radians(30)), r * math.sin(g + math.radians(30)), 0), jd)
    assert (lat, lon, height) == pytest.approx((0.0, 30.0, 550.0), abs=1e-6)
    b = S.WGS84_A * (1 - S.WGS84_F)
    lat, _, height = S.teme_to_latlon((0.0, 0.0, b + 1000), jd)
    assert lat == pytest.approx(90.0) and height == pytest.approx(1000.0, abs=1e-3)
    assert S.julian(0) == 2440587.5


def test_celestraks_csv_is_read_into_its_rows_and_what_does_not_read_counted():
    rows, left = S.omm_rows(CSV.encode())
    assert [r["OBJECT_NAME"] for r in rows] == ["STARLINK-1007", "ECHOSTAR 17"] and left == 2
    assert rows[0]["NORAD_CAT_ID"] == "44713" and set(rows[0]) == set(S.OMM_FIELDS)
    assert S.height_of(rows[0]) == pytest.approx(550, abs=15) and S.geostationary(rows[1]) and not S.geostationary(
        rows[0])
    assert S.omm_rows(CSV, most=1)[1] == 3
    with pytest.raises(ValueError, match="no CSV of orbits"):
        S.omm_rows(b"a,b\n1,2\n")


class StandIn:
    """The sgp4 package's calls as Sky makes them: Satrec, omm.initialize, SatrecArray(...).sgp4(jd, fr)."""

    def __init__(self, places):
        self.places, self.asked = places, []
        stand = self

        class Satrec:
            pass

        class SatrecArray:
            def __init__(self, sats):
                self.sats = sats

            def sgp4(self, jd, fr):
                stand.asked.append((list(jd), list(fr)))
                r = np.array([[stand.places[s.norad](j + f) for j, f in zip(jd, fr)] for s in self.sats])
                errors = np.array([[1 if s.norad == 3 else 0] * len(jd) for s in self.sats])
                return errors, r, np.zeros_like(r)

        def initialize(sat, fields):
            if fields.get("bad"):
                raise ValueError("not an orbit")
            sat.norad = int(fields["NORAD_CAT_ID"])
        self.api = type("api", (), {"Satrec": Satrec, "SatrecArray": SatrecArray})
        self.omm = type("omm", (), {"initialize": staticmethod(initialize)})


def at_longitude(lon, height=550.0):
    def place(jd):
        g, r = S.gmst(jd), S.WGS84_A + height
        return [r * math.cos(g + math.radians(lon)), r * math.sin(g + math.radians(lon)), 0.0]
    return place


def test_the_places_come_from_the_packages_math_and_nothing_without_it():
    with pytest.raises(SkyUnavailable, match="^Needs the sgp4 package: Download it on this tab$"):
        Sky().positions([])
    assert Sky(folder="C:/nowhere").available() == (False, S.NEEDS_PACKAGE)
    now = 1_795_000_000.0
    rows = [{"norad": 1, "name": "ONE", "epoch": now - 86400, "omm": {"NORAD_CAT_ID": "1"}},
            {"norad": 2, "name": "OLD", "epoch": now - 15 * 86400, "omm": {"NORAD_CAT_ID": "2"}},
            {"norad": 3, "name": "FAILS", "epoch": now, "omm": {"NORAD_CAT_ID": "3"}},
            {"norad": 4, "name": "BAD", "epoch": now, "omm": {"NORAD_CAT_ID": "4", "bad": True}}]
    stand = StandIn({1: at_longitude(10.0), 3: at_longitude(0.0)})
    out = Sky(package=stand).positions(rows, now)
    (one,) = out["satellites"]
    assert (one["name"], round(one["lat"], 6), round(one["lon"], 6), round(one["height"], 3)) == ("ONE", 0, 10, 550)
    assert one["footprint"] == pytest.approx(S.footprint_deg(550)) and one["geo"] is False
    assert out["left"] == {"older than 14 days": 1, "not read by the orbit math": 1, "its propagation failed": 1}
    (jd, fr), = stand.asked
    assert jd[0] + fr[0] == pytest.approx(S.julian(now)) and jd[1] + fr[1] == pytest.approx(S.julian(now + 60))


def wheel(files: dict, record_lies: str = "", unlisted: str = "") -> bytes:
    lines = []
    for name, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        lines.append(f"{name},sha256={'x' * 43 if name == record_lies else digest},{len(data)}")
    lines.append("sgp4-2.27.dist-info/RECORD,,")
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
        if unlisted:
            z.writestr(unlisted, b"more")
        z.writestr("sgp4-2.27.dist-info/RECORD", "\n".join(lines))
    return out.getvalue()


PACKAGE = {"sgp4/__init__.py": b"VERSION = 'stand-in'\n",
           "sgp4/api.py": b"class Satrec:\n    pass\n\n\nclass SatrecArray:\n    pass\n",
           "sgp4/omm.py": b"def initialize(sat, fields):\n    sat.fields = fields\n"}


def test_the_wheel_is_unpacked_only_as_its_record_says_and_imported_from_there_alone(tmp_path, monkeypatch):
    for name in [m for m in sys.modules if m == "sgp4" or m.startswith("sgp4.")]:
        monkeypatch.delitem(sys.modules, name)
    into = tmp_path / "packages" / "sgp4-2.27"
    with pytest.raises(PackageError, match="is not as its RECORD says"):
        S.unpack_wheel(io.BytesIO(wheel(PACKAGE, record_lies="sgp4/api.py")), into)
    with pytest.raises(PackageError, match="is not in its RECORD"):
        S.unpack_wheel(io.BytesIO(wheel(PACKAGE, unlisted="sgp4/extra.py")), into)
    with pytest.raises(PackageError, match="leads out of its folder"):
        S.unpack_wheel(io.BytesIO(wheel({**PACKAGE, "../evil.py": b"x"})), into)
    assert not into.exists() and not (tmp_path / "packages" / "sgp4-2.27.part").exists()
    S.unpack_wheel(io.BytesIO(wheel(PACKAGE)), into)
    assert (into / "sgp4" / "api.py").is_file()
    monkeypatch.setitem(sys.modules, "sgp4", type(sys)("sgp4"))  # an sgp4 from elsewhere: refused
    with pytest.raises(SkyUnavailable, match="from elsewhere is loaded"):
        S.load_package(into)
    monkeypatch.delitem(sys.modules, "sgp4")
    pkg = S.load_package(into)
    assert sys.modules["sgp4"].VERSION == "stand-in" and pkg.api.__file__.startswith(str(into))
    assert S.package_folder("2.27", tmp_path) == into
    for name in [m for m in sys.modules if m == "sgp4" or m.startswith("sgp4.")]:
        monkeypatch.delitem(sys.modules, name)


# -- the tab's sky, and the package's offer (pieces 4 and 5) -----------------------------------------------------------
ORBITS = {"format": "omm-csv", "url": "https://celestrak.example/NORAD/elements/gp.php", "source": "CelesTrak",
          "licence_name": "none stated", "licence": "CelesTrak states no licence for its orbits.",
          "credit": {"text": "CelesTrak", "url": ""}, "size": 1000, "retry": False}
SETS = ({**ORBITS, "id": "celestrak-starlink", "title": "Starlink's orbits", "constellation": "starlink",
         "query": "GROUP=starlink&FORMAT=csv"},
        {**ORBITS, "id": "celestrak-hughesnet", "title": "HughesNet's satellites", "constellation": "hughesnet",
         "query": "CATNR=38551&FORMAT=csv"})


def pin(data: bytes) -> dict:
    return {"version": "2.27", "url": "https://files.pypi.example/sgp4-2.27-py3-none-any.whl",
            "name": "sgp4-2.27-py3-none-any.whl", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "licence": "MIT License: permission is granted, free of charge, to deal in the software."}


def sky_of(tmp_path, package=None, data=b"x"):
    from liminal_libs.machines.infrastore import Store
    from liminal_libs.machines.infrastructure import Index, DataSet
    folder = tmp_path / "layers"
    now = 1_795_000_000.0
    Store(folder).put(DataSet.of(SETS[0]), {"layers": {}, "features": 2}, now,
                      orbits=[(1, "starlink", "STARLINK-1", now - 3600, {"NORAD_CAT_ID": "1"}),
                              (2, "starlink", "STARLINK-2", now - 3600, {"NORAD_CAT_ID": "2"})])
    Store(folder).put(DataSet.of(SETS[1]), {"layers": {}, "features": 1}, now,
                      orbits=[(38551, "hughesnet", "ECHOSTAR 17", now - 3600, {"NORAD_CAT_ID": "38551"})])
    index = Index(folder, SETS)
    sky = None if package is None else Sky(package=package, clock=lambda: now)
    return S.SkyView(index, pin(data), data_dir=tmp_path / "data", sky=sky, clock=lambda: now), now


def test_the_sky_says_its_constellations_and_needs_the_package_until_it_is_here(tmp_path):
    view, _ = sky_of(tmp_path)
    spec = view.spec()
    assert spec["hook"] == "world_sky" and spec["every"] == 60.0 and spec["needs"] == S.NEEDS_PACKAGE
    assert [(c["id"], c["slot"], c["count"]) for c in spec["constellations"]] == [("starlink", 1, 2), ("hughesnet", 2, 1)]
    # the review: each constellation carries its orbits' credit, drawn on the globe while its footprints are
    assert [c["credit"] for c in spec["constellations"]] == [{"text": "CelesTrak", "url": ""}] * 2
    assert view.read() == {"needs": S.NEEDS_PACKAGE, "constellations": []}
    assert view.row()[3:] == ["not downloaded", {"form": "world-sky-package", "title": "Download…"}, ""]
    (form,) = view.forms()
    words = form["confirm"]["words"]
    assert form["hook"] == "world_sky_get" and form["job"] is True and form["fields"][0]["name"] == "accept_licence"
    assert "sgp4-2.27-py3-none-any.whl is asked of files.pypi.example in one request" in words
    assert "its sha256 " + hashlib.sha256(b"x").hexdigest() + " checked" in words and "MIT License" in words
    with pytest.raises(ValueError, match="a number of seconds"):
        view.read("now")


def test_the_places_are_packed_for_the_page(tmp_path):
    import struct
    stand = StandIn({1: at_longitude(10.0), 2: at_longitude(-20.0), 38551: at_longitude(-101.0, S.GEO_KM)})
    view, now = sky_of(tmp_path, package=stand)
    assert view.spec()["needs"] == ""
    out = view.read(now)
    star, hughes = out["constellations"]
    assert (star["id"], star["n"], hughes["n"]) == ("starlink", 2, 1)
    now_xy = struct.unpack("<4i", base64.b64decode(star["now"]))
    assert [round(v / 1e4) for v in now_xy] == [0, 10, 0, -20]
    radius = struct.unpack("<2h", base64.b64decode(star["radius"]))
    assert [r / 100 for r in radius] == [pytest.approx(S.footprint_deg(550), abs=0.01)] * 2
    assert struct.unpack("<1h", base64.b64decode(hughes["radius"]))[0] / 100 == pytest.approx(57.12, abs=0.02)
    assert star["geo"] == [] and hughes["geo"] == [] and out["at"] == now  # its stand-in orbit: no OMM to call GEO


def test_the_package_is_downloaded_checked_and_unpacked_on_the_users_word(tmp_path, monkeypatch):
    from liminal_libs.machines.endpoint import Reply
    from liminal_libs.machines.world import LicenceRefused
    data = wheel(PACKAGE)
    view, _ = sky_of(tmp_path, data=data)
    asked = []

    def opener(url, headers, timeout):
        asked.append(url)
        return Reply(200, {"Content-Length": str(len(data))}, [data], lambda: None)
    with pytest.raises(LicenceRefused):
        S.install_package(view.package, view.data_dir, opener=opener)
    assert asked == []
    out = S.install_package(view.package, view.data_dir, accept_licence=True, opener=opener)
    into = S.package_folder("2.27", view.data_dir)
    assert out["ok"] is True and (into / "sgp4" / "omm.py").is_file() and asked == [view.package.source.url]
    assert list((into.parent / ".downloads").iterdir()) == []  # the wheel itself is not kept
    assert view.installed() and view.row()[3:] == ["installed", "", {"form": "world-sky-package-remove",
                                                                      "title": "Remove…"}]
    assert S.remove_package(view.package, view.data_dir)["said"] == "removed the sgp4 package" and not into.exists()
    bad, _ = sky_of(tmp_path / "bad", data=b"another file")
    from liminal_libs.machines.download import ChecksumError
    with pytest.raises(ChecksumError):
        S.install_package(bad.package, bad.data_dir, accept_licence=True, opener=opener)
    assert not S.package_folder("2.27", bad.data_dir).exists()


# -- the review: a removal on Windows, where a loaded .pyd is locked --------------------------------------------------
def test_a_removal_that_cannot_delete_every_file_is_marked_and_finished_at_the_next_start(tmp_path, monkeypatch):
    view, _ = sky_of(tmp_path)
    into = S.package_folder("2.27", view.data_dir)
    S.unpack_wheel(io.BytesIO(wheel(PACKAGE)), into)
    real = S.shutil.rmtree
    locked = {"on": True}

    def rmtree(path, ignore_errors=False, **more):  # the .py files go, the locked one stays: as Windows does
        for f in sorted(S.Path(path).rglob("*.py")):
            if f.name != "api.py" or not locked["on"]:
                f.unlink()
        if locked["on"]:
            if ignore_errors:
                return None
            raise PermissionError(13, "Access is denied", str(path / "sgp4" / "api.py"))
        return real(path, ignore_errors=ignore_errors, **more)
    monkeypatch.setattr(S.shutil, "rmtree", rmtree)
    out = S.remove_package(view.package, view.data_dir)
    assert out["ok"] and "is deleted when the platform next starts" in out["lines"][-1] and "Access is denied" in \
        out["lines"][-1]
    assert (into / S.REMOVED).is_file() and not view.installed()
    assert view.row()[3:] == ["not downloaded", {"form": "world-sky-package", "title": "Download…"}, ""]
    with pytest.raises(SkyUnavailable, match="Needs the sgp4 package"):
        S.load_package(into)
    locked["on"] = False  # the next start: nothing holds it
    S.SkyView(view.index, view.package, data_dir=view.data_dir)
    assert not into.exists()


def test_a_package_loaded_by_this_process_is_marked_removed_and_never_loaded_again(tmp_path, monkeypatch):
    for name in [m for m in sys.modules if m == "sgp4" or m.startswith("sgp4.")]:
        monkeypatch.delitem(sys.modules, name)
    view, _ = sky_of(tmp_path)
    into = S.package_folder("2.27", view.data_dir)
    S.unpack_wheel(io.BytesIO(wheel(PACKAGE)), into)
    S.load_package(into)
    assert S.loaded_from(into)
    out = S.remove_package(view.package, view.data_dir)
    assert out["ok"] and "it is loaded by this process" in out["lines"][-1]
    assert (into / "sgp4" / "api.py").is_file() and (into / S.REMOVED).is_file() and not view.installed()
    with pytest.raises(SkyUnavailable, match="Needs the sgp4 package"):
        S.load_package(into)
    with pytest.raises(PackageError, match="still in use by this process"):
        S.install_package(view.package, view.data_dir, accept_licence=True, opener=lambda *a: None)
    S.SkyView(view.index, view.package, data_dir=view.data_dir)  # still loaded: left for the next start
    assert into.exists()
    for name in [m for m in sys.modules if m == "sgp4" or m.startswith("sgp4.")]:
        sys.modules.pop(name)  # the stand-in loaded here, gone for good (the start's own sgp4, if any, comes back)
    S.SkyView(view.index, view.package, data_dir=view.data_dir)  # the next start: swept
    assert not into.exists()
