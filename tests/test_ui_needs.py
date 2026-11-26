"""The needs' drawing, held by its text (ui/static/needs.js, liminal-libs 1.103.0): one script draws what a plugin needs
of this machine on every app's page, the shading only for what cannot be met here and red, said in words, for what is
not met now (the needs plan's revision 2, 3.6, S10). It draws what it is given and asks nothing of any server."""
from __future__ import annotations

import re

import pytest

from liminal_libs import needs
from liminal_libs.ui import STATIC

pytestmark = pytest.mark.usefixtures("no_outside")
JS = STATIC / "needs.js"


def read() -> str:
    return JS.read_text(encoding="utf-8")


def test_the_object_and_its_four_functions():
    js = read()
    assert "window.LiminalNeeds = api" in js
    assert re.search(r"Object\.freeze\(\{ table, line, row, style,", js)
    for name in ("table", "line", "row", "style"):
        assert f"  function {name}(" in js


def test_the_classes_shading_only_for_what_cannot_be_met_s10():
    js = read()
    assert ".nd-cannot{opacity:.45}" in js
    assert ".nd-now{border-left:3px solid var(--down)}" in js and "opacity" not in js.split(".nd-now{")[1].split("}")[0]
    assert ".nd-met" in js and ".nd-unknown" in js
    assert "answer.sort === 'machine' ? 'nd-cannot' : 'nd-now'" in js


def test_the_words_are_the_librarys():
    js = read()
    assert f"const NOT_SAID = '{needs.NOT_SAID}'" in js and f"const NOTHING = '{needs.NOTHING}'" in js
    assert f"const UNKNOWN = '{needs.NOT_KNOWN}'" in js
    assert "'Not for this machine'" in js and "'Not met now'" in js


def test_every_word_is_escaped():
    js = read()
    for hole in re.findall(r"\$\{([^{}]*)\}", js):
        assert hole.startswith("esc(") or hole in ("cls", "rowClass(r)", "how", "line(answer)") or "esc(" in hole \
            or hole.startswith("list.map(row)"), hole


def test_its_hover_only_under_hover_and_it_asks_nothing():
    js = read()
    for rule in re.findall(r"[^\n]*:hover[^\n]*", js):
        assert rule.startswith("@media (hover:hover)"), rule
    assert "fetch(" not in js and "XMLHttpRequest" not in js and "var(--" in js
