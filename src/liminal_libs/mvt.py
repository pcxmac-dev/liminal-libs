"""Mapbox Vector Tiles read with the standard library alone (1.104.0, Monday list item 24: AfTerFibre's fibre, which its
map now serves only as tiles). A tile is a protocol buffer (the Mapbox Vector Tile specification 2.1): its layers, each
with its features, their tags (keys and values in the layer's tables) and their geometry (MoveTo, LineTo and ClosePath
commands over zigzag-coded steps, in the layer's own grid of `extent` units a side).

decode() reads a tile's layers, the tags asked for alone (`keys`: what is not asked for is never decoded into a value,
so a field of people's, a contributor's name or address, is not kept even for a moment), each feature's parts in tile
units; lonlat() turns tile units into longitude and latitude (Web Mercator's inverse); covering() names the tiles of a
zoom that cover a box. Bounded and refused in words (MvtError), never mended: a varint longer than ten bytes, a field
past its message's end, a wire type that is none, a command past the geometry, more than MAX_FEATURES features or
MAX_POINTS points a tile."""
from __future__ import annotations

import math
import struct
from typing import NamedTuple

MAX_FEATURES = 50_000  # features a tile may hold
MAX_POINTS = 500_000  # points a tile's geometries may hold in all
EXTENT = 4096  # a layer's grid when it says none (the specification's default)
POINT, LINE, POLYGON = 1, 2, 3  # a feature's geometry types
MOVE, DRAW, CLOSE = 1, 2, 7  # the geometry's commands: MoveTo, LineTo, ClosePath
MERCATOR_LAT = 85.0511287798  # the latitude Web Mercator's square ends at


class MvtError(ValueError):
    """A tile that does not read, and why."""


class Feature(NamedTuple):
    id: int
    type: int  # POINT, LINE or POLYGON (0: unknown)
    tags: dict  # the keys asked for, by name
    parts: list  # each part a list of (x, y) in tile units: a point's, a line's, a ring's


class Layer(NamedTuple):
    name: str
    extent: int
    features: list


def _varint(data: bytes, at: int, end: int) -> tuple[int, int]:
    value, shift = 0, 0
    for i in range(10):
        if at >= end:
            raise MvtError("a number runs past its message's end")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at
        shift += 7
    raise MvtError("a number is longer than ten bytes")


def _fields(data: bytes, at: int, end: int):
    """Each field of a message between at and end: (its number, its wire type, its value: a number, or (start, stop)
    of its bytes for a length-delimited one)."""
    while at < end:
        key, at = _varint(data, at, end)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, at = _varint(data, at, end)
        elif wire == 1:
            if at + 8 > end:
                raise MvtError("a field runs past its message's end")
            value, at = struct.unpack_from("<Q", data, at)[0], at + 8
        elif wire == 2:
            size, at = _varint(data, at, end)
            if at + size > end:
                raise MvtError("a field runs past its message's end")
            value, at = (at, at + size), at + size
        elif wire == 5:
            if at + 4 > end:
                raise MvtError("a field runs past its message's end")
            value, at = struct.unpack_from("<I", data, at)[0], at + 4
        else:
            raise MvtError(f"a field's wire type is {wire}, which is none")
        yield number, wire, value


def _packed(data: bytes, span: tuple[int, int]) -> list[int]:
    out, at, end = [], span[0], span[1]
    while at < end:
        v, at = _varint(data, at, end)
        out.append(v)
    return out


def _zigzag(n: int) -> int:
    return (n >> 1) ^ -(n & 1)


def _value(data: bytes, span: tuple[int, int]):
    """A Value message: its string, number or truth."""
    for number, wire, v in _fields(data, *span):
        if number == 1 and wire == 2:
            return data[v[0]:v[1]].decode("utf-8", "replace")
        if number == 2 and wire == 5:
            return struct.unpack("<f", struct.pack("<I", v))[0]
        if number == 3 and wire == 1:
            return struct.unpack("<d", struct.pack("<Q", v))[0]
        if number in (4, 5) and wire == 0:
            return v - (1 << 64) if number == 4 and v >= 1 << 63 else v
        if number == 6 and wire == 0:
            return _zigzag(v)
        if number == 7 and wire == 0:
            return bool(v)
    return None


def geometry(commands: list[int], kind: int) -> list[list[tuple[int, int]]]:
    """A feature's parts in tile units from its commands: a point's each MoveTo, a line's each run from a MoveTo, a
    ring's closed again at its first point. MvtError for a command past the geometry or one that is none."""
    parts: list[list[tuple[int, int]]] = []
    x = y = 0
    at, n = 0, len(commands)
    while at < n:
        command, count = commands[at] & 7, commands[at] >> 3
        at += 1
        if command in (MOVE, DRAW):
            if at + 2 * count > n:
                raise MvtError("a command runs past its geometry")
            for i in range(count):
                x += _zigzag(commands[at])
                y += _zigzag(commands[at + 1])
                at += 2
                if command == MOVE and (kind == POINT or i == 0):
                    parts.append([(x, y)])
                elif not parts:
                    raise MvtError("a LineTo comes before any MoveTo")
                else:
                    parts[-1].append((x, y))
        elif command == CLOSE:
            if parts and parts[-1]:
                parts[-1].append(parts[-1][0])
        else:
            raise MvtError(f"a geometry's command is {command}, which is none")
    return parts


def decode(tile: bytes, keys=None, layers=None) -> list[Layer]:
    """A tile's layers (those named in `layers`, all when None), each feature with the tags `keys` names (all when
    None) and its parts in tile units. MvtError, in words, for a tile that does not read or holds more than may be."""
    data = bytes(tile)
    wanted = None if keys is None else set(keys)
    out: list[Layer] = []
    features_seen = points_seen = 0
    for number, wire, span in _fields(data, 0, len(data)):
        if number != 3 or wire != 2:
            continue
        name, extent, names, values, raw = "", EXTENT, [], [], []
        for n, w, v in _fields(data, *span):
            if n == 1 and w == 2:
                name = data[v[0]:v[1]].decode("utf-8", "replace")
            elif n == 5 and w == 0:
                extent = v
            elif n == 3 and w == 2:
                names.append(data[v[0]:v[1]].decode("utf-8", "replace"))
            elif n == 4 and w == 2:
                values.append(v)  # read only when a tag asked for points at it
            elif n == 2 and w == 2:
                raw.append(v)
        if layers is not None and name not in layers:
            continue
        if not 1 <= extent <= 1 << 20:
            raise MvtError(f"its layer {name[:40]!r} has an extent of {extent}")
        features = []
        for span_f in raw:
            features_seen += 1
            if features_seen > MAX_FEATURES:
                raise MvtError(f"it holds more than {MAX_FEATURES:,} features")
            ident, kind, tags, commands = 0, 0, [], []
            for n, w, v in _fields(data, *span_f):
                if n == 1 and w == 0:
                    ident = v
                elif n == 2 and w == 2:
                    tags = _packed(data, v)
                elif n == 3 and w == 0:
                    kind = v
                elif n == 4 and w == 2:
                    commands = _packed(data, v)
            if len(tags) % 2:
                raise MvtError("a feature's tags are not in pairs")
            said = {}
            for k, v in zip(tags[0::2], tags[1::2]):
                if k >= len(names) or v >= len(values):
                    raise MvtError("a feature's tag points past its layer's tables")
                if wanted is None or names[k] in wanted:
                    said[names[k]] = _value(data, values[v])
            parts = geometry(commands, kind)
            points_seen += sum(len(p) for p in parts)
            if points_seen > MAX_POINTS:
                raise MvtError(f"its geometries hold more than {MAX_POINTS:,} points")
            features.append(Feature(ident, kind, said, parts))
        out.append(Layer(name, extent, features))
    return out


def lonlat(z: int, x: int, y: int, extent: int, gx: float, gy: float) -> tuple[float, float]:
    """A point of tile z/x/y, in its layer's units, as (longitude, latitude) in degrees: Web Mercator's inverse."""
    side = 1 << z
    px, py = (x + gx / extent) / side, (y + gy / extent) / side
    lon = px * 360.0 - 180.0
    lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * py))))
    return lon, lat


def tile_of(z: int, lon: float, lat: float) -> tuple[int, int]:
    """The tile of zoom z a place is in."""
    side = 1 << z
    lat = max(-MERCATOR_LAT, min(MERCATOR_LAT, lat))
    x = int((lon + 180.0) / 360.0 * side)
    r = math.radians(lat)
    y = int((1 - math.log(math.tan(r) + 1 / math.cos(r)) / math.pi) / 2 * side)
    return min(max(x, 0), side - 1), min(max(y, 0), side - 1)


def covering(z: int, bounds) -> list[tuple[int, int, int]]:
    """The tiles (z, x, y) of zoom z that cover a box (west, south, east, north), west to east, north to south."""
    w, s, e, n = bounds
    x0, y0 = tile_of(z, w, n)
    x1, y1 = tile_of(z, e, s)
    return [(z, x, y) for y in range(y0, y1 + 1) for x in range(x0, x1 + 1)]
