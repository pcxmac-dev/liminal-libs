"""A small shapefile writer for the tests (1.104.0): zips of a .shp, .shx-less, a .dbf, a .prj and a .cpg packed in
memory, as Natural Earth's are laid out, so the reader and the data sets are tried on hand-made files alone."""
from __future__ import annotations

import io
import struct
import zipfile

WGS84_PRJ = ('GEOGCS["GCS_WGS_1984",DATUM["D_WGS_1984",SPHEROID["WGS_1984",6378137.0,298.257223563]],'
             'PRIMEM["Greenwich",0.0],UNIT["Degree",0.0174532925199433]]')
MERCATOR_PRJ = ('PROJCS["WGS_1984_Web_Mercator",GEOGCS["GCS_WGS_1984",DATUM["D_WGS_1984",'
                'SPHEROID["WGS_1984",6378137.0,298.257223563]]],PROJECTION["Mercator"]]')


def content(kind: int, parts) -> bytes:
    """A record's content: `kind` the shape type, `parts` a list of lists of (x, y) (a point: [[(x, y)]])."""
    if kind == 0:
        return struct.pack("<i", 0)
    base = kind % 10
    if base == 1:
        x, y = parts[0][0]
        out = struct.pack("<i2d", kind, x, y)
        return out + (struct.pack("<d", 0.0) if kind == 21 else struct.pack("<2d", 0.0, 0.0) if kind == 11 else b"")
    points = [p for part in parts for p in part]
    xs, ys = [p[0] for p in points] or [0], [p[1] for p in points] or [0]
    out = struct.pack("<i4d", kind, min(xs), min(ys), max(xs), max(ys))
    if base == 8:
        out += struct.pack("<i", len(points))
    else:
        offsets, at = [], 0
        for part in parts:
            offsets.append(at)
            at += len(part)
        out += struct.pack("<ii", len(parts), len(points)) + struct.pack(f"<{len(parts)}i", *offsets)
    out += b"".join(struct.pack("<2d", x, y) for x, y in points)
    if kind > 20 or kind > 10:  # Z: a range and a value a point; M likewise
        extra = struct.pack("<2d", 0, 0) + b"".join(struct.pack("<d", 0) for _ in points)
        out += extra * (2 if 10 < kind < 20 else 1)
    return out


def shp(records, kind: int = 3) -> bytes:
    """A .shp of `records` (each its type and its parts, or its content's bytes as they are)."""
    body = b""
    for i, rec in enumerate(records, 1):
        raw = rec if isinstance(rec, bytes) else content(*rec)
        body += struct.pack(">ii", i, len(raw) // 2) + raw
    head = struct.pack(">i", 9994) + b"\x00" * 20 + struct.pack(">i", (100 + len(body)) // 2)
    head += struct.pack("<ii", 1000, kind) + struct.pack("<8d", *([0.0] * 8))
    return head + body


def dbf(fields, rows, encoding: str = "utf-8", deleted=()) -> bytes:
    """A dBase III table: `fields` (name, type, length), `rows` their values; the rows of `deleted` marked deleted."""
    head = 32 + 32 * len(fields) + 1
    size = 1 + sum(length for _, _, length in fields)
    out = struct.pack("<B3BIHH", 3, 126, 11, 26, len(rows), head, size) + b"\x00" * 20
    for name, kind, length in fields:
        out += name.encode("ascii").ljust(11, b"\x00") + kind.encode("ascii") + b"\x00" * 4
        out += bytes([length, 0]) + b"\x00" * 14
    out += b"\x0d"
    for i, row in enumerate(rows):
        out += b"*" if i in deleted else b" "
        for (_, kind, length), value in zip(fields, row):
            text = "" if value is None else str(value)
            raw = text.encode(encoding)
            out += (raw.rjust(length) if kind in "NF" else raw.ljust(length))[:length]
    return out + b"\x1a"


def zipped(stem: str = "ne_10m_roads", *, shp_bytes: bytes, dbf_bytes: bytes, prj: str | None = WGS84_PRJ,
           cpg: str | None = "UTF-8", folder: str = "", more: dict | None = None) -> bytes:
    """A zip of one shapefile's members, `folder` the folder they are in."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{folder}{stem}.shp", shp_bytes)
        z.writestr(f"{folder}{stem}.dbf", dbf_bytes)
        if prj is not None:
            z.writestr(f"{folder}{stem}.prj", prj)
        if cpg is not None:
            z.writestr(f"{folder}{stem}.cpg", cpg)
        for name, data in (more or {}).items():
            z.writestr(name, data)
    return out.getvalue()
