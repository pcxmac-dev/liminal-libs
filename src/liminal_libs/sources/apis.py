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

Since 1.63.0 all of it is liminal_libs/apis.py's, which needs the standard library alone: importing this module runs
sources/__init__.py, and with it the registry, pandas and numpy, which an app that holds no plugin must not pay to say
what it attaches to. Every name is imported back here, the same objects, so no plugin changes an import.
"""
from __future__ import annotations

from ..apis import (  # noqa: F401 - the same objects, importable from here as before 1.63.0
    ALIVE, API_KINDS, CHECK_AGENT, DOCS_KINDS, ERROR_PAGE, HTTPS, LINK_KINDS, Api, Area, Call, Link, _links, _named,
    _verified, as_dicts, dead_links, facts_of, is_https, problems, urls)
