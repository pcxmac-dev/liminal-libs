"""A small Mapbox Vector Tile writer for the tests (1.104.0): tiles encoded by hand, as AfTerFibre's map serves them."""
from __future__ import annotations

import struct


def varint(n: int) -> bytes:
    out = bytearray()
    n &= (1 << 64) - 1
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field(number: int, wire: int, payload) -> bytes:
    key = varint((number << 3) | wire)
    if wire == 0:
        return key + varint(payload)
    if wire == 2:
        return key + varint(len(payload)) + payload
    if wire == 5:
        return key + struct.pack("<I", payload)
    if wire == 1:
        return key + struct.pack("<Q", payload)
    raise ValueError(wire)


def zz(n: int) -> int:
    return (n << 1) ^ (n >> 31)


def commands(parts, close=False) -> list[int]:
    """Geometry commands for parts of absolute tile points: a MoveTo, then a LineTo of the rest (and a ClosePath)."""
    out, x, y = [], 0, 0
    for part in parts:
        (px, py), rest = part[0], part[1:]
        out += [(1 << 3) | 1, zz(px - x), zz(py - y)]
        x, y = px, py
        if rest:
            out.append((len(rest) << 3) | 2)
            for px, py in rest:
                out += [zz(px - x), zz(py - y)]
                x, y = px, py
        if close:
            out.append((1 << 3) | 7)
    return out


def packed(values) -> bytes:
    return b"".join(varint(v) for v in values)


def value(v) -> bytes:
    if isinstance(v, bool):
        return field(7, 0, int(v))
    if isinstance(v, int):
        return field(4, 0, v)
    if isinstance(v, float):
        return field(3, 1, struct.unpack("<Q", struct.pack("<d", v))[0])
    return field(1, 2, str(v).encode("utf-8"))


def layer(name: str, features, extent: int = 4096) -> bytes:
    """A layer of features, each (type, parts, tags dict), its keys' and values' tables made."""
    keys, values, body = [], [], b""
    for i, (kind, parts, tags, *raw) in enumerate(features, 1):
        tag_ids = []
        for k, v in tags.items():
            if k not in keys:
                keys.append(k)
            enc = value(v)
            if enc not in values:
                values.append(enc)
            tag_ids += [keys.index(k), values.index(enc)]
        geo = raw[0] if raw else commands(parts, close=kind == 3)
        feature = (field(1, 0, i) + field(2, 2, packed(tag_ids)) + field(3, 0, kind) + field(4, 2, packed(geo)))
        body += field(2, 2, feature)
    out = field(15, 0, 2) + field(1, 2, name.encode("utf-8")) + body
    out += b"".join(field(3, 2, k.encode("utf-8")) for k in keys)
    out += b"".join(field(4, 2, v) for v in values)
    return out + field(5, 0, extent)


def tile(*layers: bytes) -> bytes:
    return b"".join(field(3, 2, one) for one in layers)
