"""The regions the globe's street maps are asked round (1.107.0, Monday list item 25; the user, 2026-11-26: "Your area
only"): the World Wide Web plugin lists a region round the globe's home and round each region added on the page
(world_region, kept through its login as LIMINAL_WWW_REGIONS), each a row of the Internet infrastructure table with its
own Download…, and forgets one added on its Remove…. Nothing is downloaded: the page is asked, a region added and
removed; the stand-in firewall and the test's own folder as test_worldweb's."""
from __future__ import annotations

import pytest

from liminal_libs.machines import worldweb
from liminal_libs.machines.infrastructure import REGION_HOOK, REGIONS_MOST
from liminal_libs.machines.world import HOME_PLACE_VAR

from test_infrastructure_maps import STREETS
from test_worldweb import Frame, Web, Wall, page_ask
from test_world import _nothing_real  # noqa: F401 - the guard

pytestmark = pytest.mark.usefixtures("no_outside")


class Kept:
    """A login that keeps what it is given, in memory alone."""

    def __init__(self, pairs):
        self.pairs = dict(pairs)

    def variables(self, names):
        return {n: self.pairs.get(n) for n in names}

    def save(self, name, value):
        self.pairs[name] = value
        return "the test's login"


class Streets(Web):
    INFRASTRUCTURE = (STREETS,)


def framed(pairs):
    app = Frame(log=lambda m: None, login=Kept(pairs))
    app.attach(Wall())
    web = Streets()
    app.attach(web)
    web.login = app.login if getattr(web, "login", None) is None else web.login
    return app, web


def rows_of(page):
    table = next(t for t in page["tables"] if t.get("title") == "Internet infrastructure")
    return [r[0] if isinstance(r[0], str) else r[0]["text"] for r in table["rows"]]


def test_a_region_round_home_and_each_added_are_rows_downloaded_on_their_own_click():
    app, web = framed({HOME_PLACE_VAR: "-33.87,151.21,Sydney"})
    assert REGION_HOOK in web.HOOKS and REGION_HOOK in web.PAGE_ONLY_HOOKS
    assert worldweb.REGIONS_VAR in [k.name for k in web.keys]
    page = page_ask(app, "www", "world")
    assert rows_of(page) == ["Major roads and buildings round Sydney", "Another region: Major roads and buildings"]
    forms = {f["id"]: f for f in page["forms"]}
    assert "world-layer-osm-streets-s3387e15121" in forms and "world-region-osm-streets" in forms
    add = forms["world-region-osm-streets"]
    assert add["hook"] == REGION_HOOK and [f["name"] for f in add["fields"]] == ["dataset", "lat", "lon", "label"]
    assert "Nothing is downloaded" in add["confirm"]["words"]
    said = page_ask(app, "www", REGION_HOOK, "osm-streets", 51.5072, -0.1276, "London; the City")
    assert said["ok"] is True and "nothing was downloaded" in said["lines"][1]
    assert app.login.pairs[worldweb.REGIONS_VAR] == "51.51,-0.13,London the City"
    page = page_ask(app, "www", "world")
    assert rows_of(page)[:2] == ["Major roads and buildings round Sydney",
                                 "Major roads and buildings round London the City"]
    assert "world-layer-remove-osm-streets-n5151w00013" in {f["id"] for f in page["forms"]}
    with pytest.raises(ValueError, match="added already"):
        page_ask(app, "www", REGION_HOOK, "osm-streets", 51.51, -0.13, "")
    with pytest.raises(ValueError, match="no data set asked round a region"):
        page_ask(app, "www", REGION_HOOK, "osm-datacentres", 1, 2, "")
    with pytest.raises(ValueError, match="on the globe"):
        page_ask(app, "www", REGION_HOOK, "osm-streets", 91, 2, "")
    out = page_ask(app, "www", "world_layer_remove", "osm-streets-n5151w00013")
    assert out["ok"] is True and "the region is forgotten" in out["lines"][-1]
    assert app.login.pairs[worldweb.REGIONS_VAR] == ""
    assert rows_of(page_ask(app, "www", "world"))[:1] == ["Major roads and buildings round Sydney"]
    web.detach()


def test_no_more_than_the_most_regions_are_added_and_a_region_is_asked_only_by_the_page():
    many = ";".join(f"{i}.0,{i}.0,r{i}" for i in range(REGIONS_MOST))
    app, web = framed({worldweb.REGIONS_VAR: many + ";not,a,place"})
    assert len(web.world_regions(fresh=True)) == REGIONS_MOST  # one that does not read passed over
    with pytest.raises(ValueError, match=f"{REGIONS_MOST} regions are added already"):
        page_ask(app, "www", REGION_HOOK, "osm-streets", 50, 50, "")
    with pytest.raises(Exception):  # not at the page: refused, nothing kept
        app.ask("www", REGION_HOOK, "osm-streets", 60, 60, "")
    assert app.login.pairs[worldweb.REGIONS_VAR].startswith("0.0,0.0,r0;")
    page = page_ask(app, "www", "world")  # no home here: the table says the template needs a place
    assert rows_of(page)[0] == "Major roads and buildings round r0"
    web.detach()
