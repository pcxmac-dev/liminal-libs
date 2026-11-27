"""ESRI shapefiles read from a zip in memory (1.104.0, Monday list item 24: Natural Earth's roads and railways), with
the standard library alone: no package is installed for it, and nothing is unpacked to disk.

A shapefile is a few files of one stem: <stem>.shp holds the shapes, <stem>.dbf their records (dBase III), <stem>.prj
the coordinate system and <stem>.cpg the records' code page. read() yields each shape in the file's order as a Shape:
its kind ("point", "line", "polygon", "multipoint"), its parts (lists of (longitude, latitude) pairs) and its record
(the .dbf's row, the fields asked for alone). A Z or M shape is read as its plain one, its heights and measures read
past; a null shape is left out, and so is one whose .dbf row is marked deleted. 1.108.0 (Monday list item 25): every
record is checked first and the shapes are then read one at a time as they are asked for, so a file of millions of
points is never held as Python's pairs at once; records() reads the .dbf's rows alone, its .shp never read.

What is read is bounded, and what does not fit is refused in words (ShapefileError), never mended: a coordinate system
that is not WGS 84's longitude and latitude (anything projected among them), a member larger than SHP_MOST bytes, more
than RECORDS_MOST records, a record whose length or whose parts' offsets do not fit its points, a .dbf whose rows are
not as many as the .shp's shapes."""
from __future__ import annotations

import codecs
import io
import posixpath
import re
import struct
import zipfile
import zlib
from collections.abc import Iterator
from typing import NamedTuple

SHP_MOST = 64 << 20  # bytes of a member read at most (Natural Earth's railways: some 40 MB unpacked)
RECORDS_MOST = 200_000  # records a shapefile may hold (Natural Earth's roads: 56,601)
FILE_CODE, FILE_VERSION = 9994, 1000  # a .shp's first word and its version, as ESRI's white paper of 1998 gives them
HEADER = 100  # bytes of a .shp's header
KINDS = {1: "point", 3: "line", 5: "polygon", 8: "multipoint"}  # the plain shape types; Z is 10 more, M 20 more
NULL = 0
WGS84 = re.compile(r"WGS[ _]?(?:19)?84", re.IGNORECASE)  # GEOGCS["GCS_WGS_1984",DATUM["D_WGS_1984",...]]


class ShapefileError(ValueError):
    """A shapefile that is not one, or not one this reader keeps: why, in words."""


class Shape(NamedTuple):
    kind: str  # "point", "line", "polygon" or "multipoint"
    parts: list  # each part a list of (longitude, latitude) pairs; a point's one part of one pair
    record: dict  # its .dbf row: the fields asked for, by name


def _members(z: zipfile.ZipFile, stem: str | None) -> dict[str, zipfile.ZipInfo]:
    """The shapefile's members by their extension (".shp", ".dbf", ".prj", ".cpg"): of the stem asked for, else of the
    zip's one .shp, in whichever folder of the zip, in any case."""
    files = [i for i in z.infolist() if not i.is_dir()]
    shps = [i for i in files if i.filename.lower().endswith(".shp")]
    if stem is None:
        if len(shps) != 1:
            raise ShapefileError(f"the zip holds {len(shps)} shapefiles, and which one to read is not said")
        stem = posixpath.basename(shps[0].filename)[:-4]
    found: dict[str, zipfile.ZipInfo] = {}
    for info in files:
        base = posixpath.basename(info.filename)
        head, dot, ext = base.rpartition(".")
        if dot and head.lower() == stem.lower() and f".{ext.lower()}" in (".shp", ".dbf", ".prj", ".cpg"):
            found.setdefault(f".{ext.lower()}", info)
    for need in (".shp", ".dbf", ".prj"):
        if need not in found:
            raise ShapefileError(f"the zip holds no {stem}{need}")
    return found


def _read(z: zipfile.ZipFile, info: zipfile.ZipInfo, most: int) -> bytes:
    if info.file_size > most:
        raise ShapefileError(f"{posixpath.basename(info.filename)} is {info.file_size:,} bytes, more than the "
                             f"{most:,} a shapefile's member may be")
    with z.open(info) as stream:
        data = stream.read(most + 1)  # a byte more than may be: what the zip's directory understated
    if len(data) > most:
        raise ShapefileError(f"{posixpath.basename(info.filename)} unpacks to more than {most:,} bytes")
    return data


def _geographic(prj: str) -> None:
    """ShapefileError unless the .prj names WGS 84's longitude and latitude (a GEOGCS, never a PROJCS)."""
    text = prj.strip()
    if not text.upper().startswith("GEOGCS") or not WGS84.search(text):
        raise ShapefileError("its coordinates are not WGS 84's longitude and latitude (its .prj says "
                             f"{' '.join(text.split())[:60]!r}): only those are read")


def _encoding(cpg: bytes | None) -> str:
    """The records' code page as the .cpg names it ("UTF-8", "1252", "ISO-8859-1"); UTF-8 when none is named, or one
    Python does not know."""
    name = (cpg or b"").decode("ascii", "replace").strip()
    if name.isdigit():
        name = f"cp{name}"
    try:
        return codecs.lookup(name).name if name else "utf-8"
    except LookupError:
        return "utf-8"


def _value(kind: str, raw: bytes, encoding: str):
    text = raw.decode(encoding, "replace").strip(" \x00")
    if kind == "C":
        return text
    if kind in ("N", "F"):
        if not text or set(text) <= {"*", "?"}:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
        return int(number) if kind == "N" and re.fullmatch(r"[+-]?\d+", text) else number
    if kind == "L":
        return True if text[:1] in "YyTt" and text else False if text[:1] in "NnFf" and text else None
    if kind == "D":
        return f"{text[:4]}-{text[4:6]}-{text[6:8]}" if re.fullmatch(r"\d{8}", text) else ""
    return text


def _records(dbf: bytes, encoding: str, fields, most_records: int | None = None) -> tuple[int, list]:
    """The .dbf's count and its rows: each a dict of the fields asked for (all when `fields` is None), or None for a
    row marked deleted. 1.108.0 (the review): more than `most_records` refused from its header, no row made."""
    if len(dbf) < 32:
        raise ShapefileError("its .dbf is cut short")
    count, head, size = struct.unpack_from("<IHH", dbf, 4)
    if most_records is not None and count > most_records:
        raise ShapefileError(f"it holds more than {most_records:,} records, the most a shapefile may")
    if head < 33 or size < 1 or head > len(dbf):
        raise ShapefileError("its .dbf's header does not read")
    columns, at, width = [], 32, 1
    while at + 32 <= head and dbf[at] != 0x0D:
        name = dbf[at:at + 11].split(b"\x00", 1)[0].decode("ascii", "replace").strip()
        kind, length = chr(dbf[at + 11]), dbf[at + 16]
        columns.append((name, kind, width, length))
        width += length
        at += 32
    if width > size:
        raise ShapefileError("its .dbf's fields are wider than its rows")
    if head + count * size > len(dbf):
        raise ShapefileError(f"its .dbf says {count:,} rows and holds fewer")
    wanted = None if fields is None else {f.lower() for f in fields}
    keep = [c for c in columns if wanted is None or c[0].lower() in wanted]
    rows = []
    for i in range(count):
        row = dbf[head + i * size:head + (i + 1) * size]
        if row[:1] == b"*":
            rows.append(None)
            continue
        rows.append({name: _value(kind, row[start:start + length], encoding) for name, kind, start, length in keep})
    return count, rows


def _shapes(shp: bytes, most_records: int) -> Iterator[tuple[int, str, list] | None]:
    """The .shp's shapes in order: (its number, its kind, its parts), None for a null shape."""
    for number, base, start, stop in _index(shp, most_records):
        yield _decoded(shp, number, base, start, stop)


def _decoded(shp: bytes, number: int, base: int, start: int, stop: int) -> tuple[int, str, list] | None:
    """One record of the .shp, checked already (_index), as (its number, its kind, its parts); None for a null one."""
    if base == NULL:
        return None
    if base == 1:
        x, y = struct.unpack_from("<2d", shp, start + 4)
        return number, KINDS[1], [[(x, y)]]
    return number, KINDS[base], _parts(shp, start, stop, number, multi=base == 8)


def _index(shp: bytes, most_records: int) -> list[tuple[int, int, int, int]]:
    """1.108.0 (Monday list item 25: the states' boundaries, some millions of points): every record of the .shp found
    and checked, its parts' counts and offsets among them, without its points read: (its number, its plain type, where
    its content begins and ends) each, so the shapes are read one at a time after (read() yields them as they are
    read, never all of them held at once)."""
    if len(shp) < HEADER:
        raise ShapefileError("its .shp is cut short")
    code, = struct.unpack_from(">i", shp, 0)
    words, = struct.unpack_from(">i", shp, 24)
    version, _ = struct.unpack_from("<ii", shp, 28)
    if code != FILE_CODE or version != FILE_VERSION:
        raise ShapefileError("its .shp is no shapefile (its file code or version is not ESRI's)")
    end = min(len(shp), words * 2)
    at, count, found = HEADER, 0, []
    while at + 8 <= end:
        number, length = struct.unpack_from(">ii", shp, at)
        start, stop = at + 8, at + 8 + length * 2
        if length < 2 or stop > end:
            raise ShapefileError(f"its record {number:,} does not fit the file")
        count += 1
        if count > most_records:
            raise ShapefileError(f"it holds more than {most_records:,} records, the most a shapefile may")
        kind_code, = struct.unpack_from("<i", shp, start)
        base = kind_code % 10 if kind_code else NULL
        if kind_code not in (NULL, 1, 3, 5, 8, 11, 13, 15, 18, 21, 23, 25, 28):
            raise ShapefileError(f"its record {number:,} is a shape of type {kind_code}, which is none read here")
        if base == 1 and start + 20 > stop:
            raise ShapefileError(f"its record {number:,} is cut short")
        if base not in (NULL, 1):
            _parts(shp, start, stop, number, multi=base == 8, read=False)
        found.append((number, base, start, stop))
        at = stop
    if at != end:
        raise ShapefileError("its .shp ends inside a record")
    return found


def _parts(shp: bytes, start: int, stop: int, number: int, multi: bool, read: bool = True) -> list:
    """A polyline's, a polygon's or a multipoint's parts, each its (x, y) pairs: their counts and offsets checked
    (`read` false: checked alone, no coordinate unpacked; the review of 1.108.0: it was overwritten by the count)."""
    at = start + 4 + 32  # the type, then the box
    if multi:
        if at + 4 > stop:
            raise ShapefileError(f"its record {number:,} is cut short")
        points, = struct.unpack_from("<i", shp, at)
        offsets, at = [0], at + 4
        parts = 1
    else:
        if at + 8 > stop:
            raise ShapefileError(f"its record {number:,} is cut short")
        parts, points = struct.unpack_from("<ii", shp, at)
        at += 8
        if parts < 1 or points < 0 or at + 4 * parts > stop:
            raise ShapefileError(f"its record {number:,}'s parts do not fit it")
        offsets = list(struct.unpack_from(f"<{parts}i", shp, at))
        at += 4 * parts
    if points < 0 or at + 16 * points > stop:
        raise ShapefileError(f"its record {number:,} says more points than it holds")
    if offsets[0] != 0 or any(b < a for a, b in zip(offsets, offsets[1:])) or offsets[-1] > points:
        raise ShapefileError(f"its record {number:,}'s parts begin past its points")
    if not points or not read:
        return []
    xy = struct.unpack_from(f"<{2 * points}d", shp, at)
    pairs = list(zip(xy[0::2], xy[1::2]))
    bounds = offsets + [points]
    return [pairs[bounds[i]:bounds[i + 1]] for i in range(parts)]


def read(zip_bytes, stem: str | None = None, *, fields=None, most_bytes: int = SHP_MOST,
         most_records: int = RECORDS_MOST) -> Iterator[Shape]:
    """Each shape of the zip's shapefile (`stem` the one named, else the zip's one .shp) as a Shape, in the file's
    order: its null shapes and those whose .dbf row is deleted left out. `fields`: the .dbf's columns kept (by name, in
    any case); all when None. ShapefileError, in words, for a zip that is none, a shapefile not in WGS 84's longitude
    and latitude, and for anything that does not fit (see the module's words). Everything is checked before the first
    shape is yielded."""
    try:
        z = zipfile.ZipFile(io.BytesIO(bytes(zip_bytes)))
    except zipfile.BadZipFile:
        raise ShapefileError("it is no zip") from None
    with z:
        members = _members(z, stem)
        try:
            prj = _read(z, members[".prj"], 64 << 10).decode("latin-1")
            _geographic(prj)
            encoding = _encoding(_read(z, members[".cpg"], 256) if ".cpg" in members else None)
            shp = _read(z, members[".shp"], most_bytes)
            dbf = _read(z, members[".dbf"], most_bytes)
        except (zipfile.BadZipFile, zlib.error, EOFError, OSError) as e:
            raise ShapefileError(f"its zip does not read: {' '.join(str(e).split())[:120]}") from None
    count, rows = _records(dbf, encoding, fields, most_records)
    del dbf
    found = _index(shp, most_records)  # 1.108.0: every record checked, none of its points read yet
    if len(found) != count:
        raise ShapefileError(f"its .shp holds {len(found):,} shapes and its .dbf {count:,} rows: they do not match")
    return _yield(shp, found, rows)


def _yield(shp: bytes, found: list, rows: list) -> Iterator[Shape]:
    """Each shape read as it is asked for (1.108.0): only the .shp's bytes are held, never every shape's points."""
    for at, row in zip(found, rows):
        if row is None:
            continue
        shape = _decoded(shp, *at)
        if shape is None:
            continue
        _, kind, parts = shape
        yield Shape(kind, parts, row)


def records(zip_bytes, stem: str | None = None, *, fields=None, most_bytes: int = SHP_MOST,
            most_records: int = RECORDS_MOST) -> list[dict]:
    """1.108.0 (Monday list item 25: the countries' and the states' names, at the label points their records hold):
    the .dbf's rows alone, in the file's order, those marked deleted left out, `fields` as read() keeps them. Its .shp
    is not read at all (Natural Earth's states and provinces: some 60 MB of polygons not needed for their names), but
    its .prj is: ShapefileError, in words, for what read() refuses of the zip, its coordinate system and its .dbf, and
    for more than `most_records` rows."""
    try:
        z = zipfile.ZipFile(io.BytesIO(bytes(zip_bytes)))
    except zipfile.BadZipFile:
        raise ShapefileError("it is no zip") from None
    with z:
        members = _members(z, stem)
        try:
            _geographic(_read(z, members[".prj"], 64 << 10).decode("latin-1"))
            encoding = _encoding(_read(z, members[".cpg"], 256) if ".cpg" in members else None)
            dbf = _read(z, members[".dbf"], most_bytes)
        except (zipfile.BadZipFile, zlib.error, EOFError, OSError) as e:
            raise ShapefileError(f"its zip does not read: {' '.join(str(e).split())[:120]}") from None
    _, rows = _records(dbf, encoding, fields, most_records)
    return [row for row in rows if row is not None]
