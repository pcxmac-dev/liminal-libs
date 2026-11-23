"""JSON read with a bound on its nesting (1.75.2). Python's own reader recursed once a level and raised RecursionError,
which is no ValueError, a thousand or so levels down: the library's readers of what comes from outside (an app's request
bodies, the classification lists and their manifest, the infrastructure's downloads) caught it as a bad file. From
Python 3.15 on Linux, whose guard measures the C stack itself, the same reader goes on 100,000 levels deep (CI,
2026-11-23: two tests failed on ubuntu-latest 3.15 alone), and what it read was handed on to code that recurses over it.
So the depth is bounded here, alike on every Python and every system: MAX_DEPTH levels of arrays and objects, counted
outside strings with the bytes' own methods before anything is parsed (a text with fewer openings than the bound is not
counted at all)."""
from __future__ import annotations

import json
import re
from array import array
from itertools import accumulate

MAX_DEPTH = 512  # levels of arrays and objects a JSON text may nest; past this it is refused as no JSON
STRING = re.compile(rb'"[^"\\]*(?:\\.[^"\\]*)*"')  # a JSON string, its escapes in it: a bracket in it is text
_MARKS = bytes.maketrans(b"[{]}", b"\x01\x01\xff\xff")  # an opening one 1, a closing one -1 (read as signed bytes)
_OTHERS = bytes(c for c in range(256) if c not in b"[{]}")


def _raw(data) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    return str(data).encode("utf-8", "surrogatepass")


def depth(data) -> int:
    """How deep `data`'s arrays and objects nest (a str, bytes, bytearray or memoryview; a bracket inside a string is
    passed over): 0 for none."""
    raw = _raw(data)
    if b"[" not in raw and b"{" not in raw:
        return 0
    if b'"' in raw:
        raw = STRING.sub(b'""', raw)
    return max(accumulate(array("b", raw.translate(_MARKS, _OTHERS))), default=0)


def too_deep(data, most: int = MAX_DEPTH) -> bool:
    """Whether `data` nests past `most` levels: never counted when it holds no more openings than that."""
    raw = _raw(data)
    if raw.count(b"[") + raw.count(b"{") <= most:
        return False
    return depth(raw) > most


def loads(data, *, most: int = MAX_DEPTH, **kwargs):
    """json.loads, refusing as no JSON (ValueError, as JSONDecodeError is) a text nested past `most` levels, and one the
    parser's own stack cannot read (its RecursionError): a reader that takes ValueError for a bad file takes these as
    one, on every Python."""
    if too_deep(data, most):
        raise ValueError(f"JSON nested too deeply to be read (over {most} levels)")
    try:
        return json.loads(data, **kwargs)
    except RecursionError:
        raise ValueError("JSON nested too deeply to be read") from None
