"""JSON's nesting bounded by the library itself (liminal_libs.jsonread, 1.75.2), alike on every Python: CI on
ubuntu-latest 3.15 read 100,000 levels where the others raised RecursionError."""
from __future__ import annotations

import pytest

from liminal_libs import jsonread
from liminal_libs.jsonread import MAX_DEPTH


def test_the_depth_is_counted_outside_strings_on_every_kind_of_text():
    assert jsonread.depth('{"a": [1, {"b": "[[[[{{{{"}]}') == 3
    assert jsonread.depth('["a\\"[[[", ["b"]]') == 2  # an escaped quote does not end the string
    assert jsonread.depth(b"[]") == 1 and jsonread.depth("") == 0 and jsonread.depth("17") == 0
    assert jsonread.depth(memoryview(b"[[]]")) == 2 and jsonread.depth(bytearray(b"{}")) == 1


def test_json_past_the_bound_is_refused_as_no_json_and_within_it_read():
    ok = "[" * MAX_DEPTH + "]" * MAX_DEPTH
    assert not jsonread.too_deep(ok) and jsonread.loads(ok) is not None
    for deep in ("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1), '{"a":' * 600 + "1" + "}" * 600,
                 b"[" * 100_000 + b"]" * 100_000):
        assert jsonread.too_deep(deep)
        with pytest.raises(ValueError, match="nested too deeply"):
            jsonread.loads(deep)
    many = "[" + ",".join(["[1]"] * 10_000) + "]"  # many brackets, none deep
    assert not jsonread.too_deep(many) and len(jsonread.loads(many)) == 10_000
    quoted = '"' + "[" * 100_000 + '"'  # brackets in a string are text
    assert not jsonread.too_deep(quoted) and jsonread.loads(quoted) == "[" * 100_000
    assert jsonread.loads(b'{"a": 1}', object_pairs_hook=list) == [("a", 1)]  # json.loads' own arguments pass
    with pytest.raises(ValueError):
        jsonread.loads("{not json")
