"""What a plugin attaches to (plugin API 2.2), said on its page in every app.

The user, 2026-11-11: "each plugin should reflect the the API its attached to, and present links that provide
documentation, the plugin interface should more or less contain what it already has, BUT, it should also expose more of
what the API is about"; then "please revisit all plugins and the two new ones, and ensure this is true".

A plugin declares `apis` (Plugin.apis): an `Api` for each thing it talks to, whatever its form: a vendor's REST API, an
XML one, a command line (wsl.exe, kubectl, virsh), PowerShell's cmdlets, an SDK, the operating system's or the kernel's
interfaces, a local socket, a file. Each says

  - what it is about (`about`), whose it is (`maker`), its form (`kind`, API_KINDS), where it is reached (`base`: an
    address, a command, a path), the version the plugin was written for (`version`), how a caller proves who it is
    (`auth`), its limits (`limits`) and what of it costs money (`costs`);
  - the maker's pages (`links`: Link(title, url, kind), a documentation or reference page among them): its reference,
    guides, limits, pricing, status page, changes, specification, console, its tool;
  - its parts (`areas`: Area(name, about, docs, covered)), every part the API has, each said covered by the plugin
    (what the plugin does with it) or not: how much more of the API there is than the plugin uses;
  - its calls (`calls`: Call(name, about, area, used, docs, writes, costs)): the ones the plugin makes, each with what it
    makes it for, and others worth knowing that it does not make;
  - the day these facts were read from the maker's own pages (`verified`, an ISO date).

Every address is an https one of the maker's (or the project's) own pages, read when the plugin was written: never a
guess. What the plugin learned of an API while it ran (the server's version, the requests left of a limit, the last
answer and when) it says with Plugin.api_facts(): {api name: {label: words}}, asking nothing to answer it. Every app's
page draws both, the declarations and the facts, with the library's ui/static/apis.js.

`problems(apis)` says what is wrong with the declarations (conformance's rule: a plugin written for plugin API 2.2
declares at least one Api, each with a documentation link; offline, nothing sent). `dead_links(apis)` asks each address
once (the plugins' page check, LIMINAL_VENDOR_PAGES=1): the only part of this module that sends anything.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import date, timedelta

LINK_KINDS = {  # a link's kind -> its words on the page (the page shows them in this order)
    "docs": "Documentation",
    "reference": "Reference",
    "guide": "Guide",
    "auth": "Authentication",
    "limits": "Limits",
    "pricing": "Pricing",
    "status": "Status",
    "changelog": "Changes",
    "spec": "Specification",
    "console": "Console",
    "tool": "Tool",
    "sdk": "SDK",
    "source": "Source",
    "terms": "Terms",
}
DOCS_KINDS = ("docs", "reference", "guide")  # the kinds that count as the API's documentation
API_KINDS = {  # an API's form -> its words on the page
    "rest": "REST API over HTTPS",
    "xml": "XML API over HTTPS",
    "query": "query API over HTTPS",
    "feed": "files and feeds over HTTPS",
    "stream": "WebSocket stream",
    "dns": "DNS",
    "command": "command line",
    "powershell": "PowerShell",
    "sdk": "SDK",
    "socket": "local socket",
    "system": "the operating system's interface",
    "kernel": "the kernel's interface",
    "file": "a local file",
}
HTTPS = re.compile(r"^https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?(?:[/?#][^\s]*)?$")  # an https address with a host
ALIVE = frozenset({401, 403, 405, 429})  # a page that answered but refuses automated readers: there, not dead
CHECK_AGENT = "Mozilla/5.0 (compatible; Liminal plugin page check)"


@dataclass(frozen=True)
class Link:
    """One of the maker's pages about the API: its title on the page, its https address, its kind (LINK_KINDS)."""

    title: str
    url: str
    kind: str = "docs"

    def as_dict(self) -> dict:
        return {"title": self.title, "url": self.url, "kind": self.kind, "kindWords": LINK_KINDS.get(self.kind, self.kind)}


@dataclass(frozen=True)
class Area:
    """A part of the API (a cloud's Droplets, Domains, Firewalls; a command's distributions, its networking): what it is,
    its page, and what the plugin does with it ("" when it does nothing with it: the rest of the API, shown as such)."""

    name: str
    about: str = ""
    docs: str = ""
    covered: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "about": self.about, "docs": self.docs, "covered": self.covered}


@dataclass(frozen=True)
class Call:
    """One thing the API offers: an endpoint ("GET /v2/droplets"), a command ("wsl --list --verbose"), a cmdlet
    ("Get-NetFirewallRule"), a method of an SDK. `used` says what the plugin makes it for ("" when it does not make it);
    `writes` that it changes something, `costs` that it starts or raises a charge."""

    name: str
    about: str = ""
    area: str = ""
    used: str = ""
    docs: str = ""
    writes: bool = False
    costs: bool = False

    def as_dict(self) -> dict:
        return {"name": self.name, "about": self.about, "area": self.area, "used": self.used, "docs": self.docs,
                "writes": self.writes, "costs": self.costs}


@dataclass(frozen=True)
class Api:
    """An API a plugin attaches to, as the maker's pages describe it (the module's docstring says each part)."""

    name: str
    maker: str
    about: str
    kind: str = "rest"
    base: str = ""
    version: str = ""
    auth: str = ""
    limits: str = ""
    costs: str = ""
    links: tuple[Link, ...] = ()
    areas: tuple[Area, ...] = ()
    calls: tuple[Call, ...] = ()
    verified: str = ""

    @property
    def docs(self) -> str:
        """The address of its documentation (the first documentation, reference or guide link)."""
        for kind in DOCS_KINDS:
            for link in self.links:
                if link.kind == kind:
                    return link.url
        return ""

    @property
    def used(self) -> tuple[Call, ...]:
        return tuple(c for c in self.calls if c.used)

    @property
    def covered(self) -> tuple[Area, ...]:
        return tuple(a for a in self.areas if a.covered)

    def link(self, kind: str) -> str:
        """The address of its first link of `kind` ("" when it has none)."""
        return next((x.url for x in self.links if x.kind == kind), "")

    def as_dict(self) -> dict:
        return {"name": self.name, "maker": self.maker, "about": self.about, "kind": self.kind,
                "kindWords": API_KINDS.get(self.kind, self.kind), "base": self.base, "version": self.version,
                "auth": self.auth, "limits": self.limits, "costs": self.costs, "verified": self.verified,
                "docs": self.docs, "links": [x.as_dict() for x in self.links], "areas": [a.as_dict() for a in self.areas],
                "calls": [c.as_dict() for c in self.calls],
                "counts": {"areas": len(self.areas), "covered": len(self.covered), "calls": len(self.calls),
                           "used": len(self.used)}}


def as_dicts(apis: Iterable[Api]) -> list[dict]:
    """The declarations as the pages read them (JSON)."""
    return [a.as_dict() for a in apis or ()]


def facts_of(plugin) -> dict[str, dict[str, str]]:
    """A plugin's api_facts() as the pages read them: {api name: {label: words}}, words as text; {} when it says none
    or its answer is not one (a page never fails on it)."""
    try:
        got = plugin.api_facts()
    except Exception:  # noqa: BLE001 - what a plugin learned is extra: its page is drawn without it
        return {}
    if not isinstance(got, Mapping):
        return {}
    out: dict[str, dict[str, str]] = {}
    for name, facts in got.items():
        if isinstance(facts, Mapping):
            out[str(name)] = {str(k): "" if v is None else str(v) for k, v in facts.items()}
    return out


def is_https(url) -> bool:
    return isinstance(url, str) and bool(HTTPS.match(url.strip())) and url == url.strip()


def problems(apis, today: date | None = None) -> list[str]:
    """Every way the declarations fall short, in words (empty when they are sound): a tuple of Api, each named once,
    with its maker, what it is about, its form, a documentation link, https addresses only, its parts and calls named
    once each, and the day it was verified (an ISO date, not after today)."""
    if not isinstance(apis, tuple):
        return [f"apis must be a tuple of sources.apis.Api, not {type(apis).__name__}"]
    out: list[str] = []
    seen: set[str] = set()
    today = today or date.today()
    for api in apis:
        if not isinstance(api, Api):
            out.append(f"apis: {api!r} is not a sources.apis.Api")
            continue
        tag = f"api {api.name!r}"
        if not isinstance(api.name, str) or not api.name.strip():
            out.append("an api without a name")
        elif api.name in seen:
            out.append(f"{tag}: declared twice")
        seen.add(api.name)
        for attr in ("maker", "about", "kind"):
            value = getattr(api, attr)
            if not isinstance(value, str) or not value.strip():
                out.append(f"{tag}: no {attr}")
        for attr in ("base", "version", "auth", "limits", "costs"):
            if not isinstance(getattr(api, attr), str):
                out.append(f"{tag}: {attr} is not a str")
        out += _links(tag, api.links)
        out += _named(tag, "areas", api.areas, Area)
        out += _named(tag, "calls", api.calls, Call)
        if isinstance(api.calls, tuple):
            for c in api.calls:
                if isinstance(c, Call) and not all(isinstance(getattr(c, f), bool) for f in ("writes", "costs")):
                    out.append(f"{tag}: call {c.name!r}: writes and costs are bools")
        out += _verified(tag, api.verified, today)
    return out


def _links(tag: str, links) -> list[str]:
    if not isinstance(links, tuple):
        return [f"{tag}: links must be a tuple of Link"]
    out: list[str] = []
    urls: set[str] = set()
    for x in links:
        if not isinstance(x, Link):
            out.append(f"{tag}: link {x!r} is not a sources.apis.Link")
            continue
        if not isinstance(x.title, str) or not x.title.strip():
            out.append(f"{tag}: a link without a title ({x.url!r})")
        if not is_https(x.url):
            out.append(f"{tag}: link {x.title!r}: {x.url!r} is not an https address")
        elif x.url in urls:
            out.append(f"{tag}: link {x.url!r} given twice")
        urls.add(x.url)
        if x.kind not in LINK_KINDS:
            out.append(f"{tag}: link {x.title!r}: kind {x.kind!r} is none of {sorted(LINK_KINDS)}")
    if not any(isinstance(x, Link) and x.kind in DOCS_KINDS for x in links):
        out.append(f"{tag}: no documentation link (a Link of kind {' | '.join(DOCS_KINDS)})")
    return out


def _named(tag: str, what: str, items, cls) -> list[str]:
    if not isinstance(items, tuple):
        return [f"{tag}: {what} must be a tuple of {cls.__name__}"]
    out: list[str] = []
    names: set[str] = set()
    for item in items:
        if not isinstance(item, cls):
            out.append(f"{tag}: {what}: {item!r} is not a sources.apis.{cls.__name__}")
            continue
        if not isinstance(item.name, str) or not item.name.strip():
            out.append(f"{tag}: one of its {what} has no name")
        elif item.name in names:
            out.append(f"{tag}: {what}: {item.name!r} given twice")
        names.add(item.name)
        if item.docs and not is_https(item.docs):
            out.append(f"{tag}: {what}: {item.name!r}: {item.docs!r} is not an https address")
        for attr in ("about", "covered" if cls is Area else "used"):
            if not isinstance(getattr(item, attr), str):
                out.append(f"{tag}: {what}: {item.name!r}: {attr} is not a str")
    return out


def _verified(tag: str, verified, today: date) -> list[str]:
    try:
        day = date.fromisoformat(verified)
    except (TypeError, ValueError):
        return [f"{tag}: verified {verified!r} is not an ISO date (the day its facts were read from the maker's pages)"]
    if day > today + timedelta(days=1):
        return [f"{tag}: verified {verified} is after today"]
    return []


def urls(apis: Iterable[Api]) -> list[str]:
    """Every address the declarations hold, each once, in order: the links, then the parts' and the calls' pages."""
    found: dict[str, None] = {}
    for api in apis or ():
        for x in api.links:
            found.setdefault(x.url, None)
        for item in (*api.areas, *api.calls):
            if item.docs:
                found.setdefault(item.docs, None)
    return list(found)


def dead_links(apis: Iterable[Api], get: Callable | None = None, timeout: float = 20.0) -> list[tuple[str, str]]:
    """The addresses that do not answer as a page (each asked once: a GET, its redirects followed): (address, why). A
    page that answers but refuses automated readers (ALIVE: 401, 403, 405, 429) is there. `get(url, timeout)` -> status
    (a test's); else requests, its body never read."""
    if get is None:
        import requests

        def get(url: str, timeout: float) -> int:
            with requests.get(url, timeout=timeout, stream=True, allow_redirects=True,
                              headers={"User-Agent": CHECK_AGENT, "Accept": "text/html,*/*"}) as resp:
                return resp.status_code

    out: list[tuple[str, str]] = []
    for url in urls(apis):
        try:
            status = int(get(url, timeout))
        except Exception as e:  # noqa: BLE001 - why it could not be read is the finding
            out.append((url, f"{type(e).__name__}: {e}"[:200]))
            continue
        if status >= 400 and status not in ALIVE:
            out.append((url, f"HTTP {status}"))
    return out
