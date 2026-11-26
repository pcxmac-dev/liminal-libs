"""liminal_libs.mvt (1.104.0): Mapbox Vector Tiles read with the standard library, on tiles encoded here
(tests/tiles.py)."""
from __future__ import annotations

import pytest

from liminal_libs import mvt
from liminal_libs.mvt import LINE, POINT, POLYGON, MvtError

import tiles as T


def test_a_tiles_line_polygon_and_point_are_read_with_their_tags():
    data = T.tile(T.layer("fiber", [(LINE, [[(0, 0), (100, 50), (200, 50)]], {"operator": "Liquid", "live": True,
                                                                              "fibre_cores": 48, "length": 1.5}),
                                    (POLYGON, [[(10, 10), (20, 10), (20, 20)]], {"operator": "x"}),
                                    (POINT, [[(5, 6)], [(7, 8)]], {})]),
                  T.layer("other", [(POINT, [[(1, 1)]], {"a": "b"})]))
    fibre, other = mvt.decode(data)
    assert (fibre.name, fibre.extent, other.name) == ("fiber", 4096, "other")
    line, ring, point = fibre.features
    assert line.type == LINE and line.parts == [[(0, 0), (100, 50), (200, 50)]]
    assert line.tags == {"operator": "Liquid", "live": True, "fibre_cores": 48, "length": 1.5}
    assert ring.parts == [[(10, 10), (20, 10), (20, 20), (10, 10)]]  # closed again at its first point
    assert point.parts == [[(5, 6)], [(7, 8)]]


def test_only_the_keys_and_layers_asked_for_are_decoded():
    data = T.tile(T.layer("fiber", [(LINE, [[(0, 0), (1, 1)]], {"operator": "Liquid", "contributor": "A Person",
                                                                "contrib_email": "a@person.example"})]),
                  T.layer("other", [(POINT, [[(1, 1)]], {})]))
    (only,) = mvt.decode(data, keys=("operator",), layers=("fiber",))
    assert only.features[0].tags == {"operator": "Liquid"}


def test_what_does_not_read_is_refused_in_words():
    with pytest.raises(MvtError, match="longer than ten bytes"):
        mvt.decode(b"\x1a" + b"\xff" * 11)
    with pytest.raises(MvtError, match="past its message's end"):
        mvt.decode(T.field(3, 2, b"abc")[:-1])
    with pytest.raises(MvtError, match="wire type is 3"):
        mvt.decode(T.field(3, 2, b"\x0b"))
    past = T.layer("fiber", [(LINE, [], {}, [(1 << 3) | 1, 2])])  # a MoveTo of one point, one number given
    with pytest.raises(MvtError, match="runs past its geometry"):
        mvt.decode(T.tile(past))
    with pytest.raises(MvtError, match="command is 4"):
        mvt.decode(T.tile(T.layer("fiber", [(LINE, [], {}, [(1 << 3) | 4])])))


def test_tile_units_are_longitude_and_latitude_and_a_box_is_covered():
    assert mvt.lonlat(0, 0, 0, 4096, 2048, 2048) == pytest.approx((0.0, 0.0), abs=1e-9)
    lon, lat = mvt.lonlat(1, 0, 0, 4096, 0, 0)
    assert lon == -180 and lat == pytest.approx(85.0511287798)
    assert mvt.lonlat(5, 17, 15, 4096, 0, 4096) == pytest.approx((11.25, 0.0), abs=1e-9)
    tiles = mvt.covering(5, (-17.42, -34.50, 55.74, 36.87))  # AfTerFibre's bounds, as its TileJSON says them
    assert len(tiles) == 56 and tiles[0] == (5, 14, 12) and tiles[-1] == (5, 20, 19)
