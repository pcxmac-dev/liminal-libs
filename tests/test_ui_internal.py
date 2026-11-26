"""The Internal API tab's drawing, held by its text (ui/static/internal.js, liminal-libs 1.63.0): one script draws a
plugin's Internal API, and an app's own, on every app's page. The user, 2026-11-16: "for all apps, and all plugins,
there should be an external api tab, and an internal api tab"; 2026-11-17: "all plugins are middleware", "even for
other plugins", "and then the app object code". So a plugin's tab leads with what kind of middleware it is and how it
is called, then the standard interface its base gives it, layer by layer, then its own hooks, each hook saying what
it does and who uses it (C-critique B1, S2, S3, M7). It asks nothing of any server, and given nothing it says so."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from liminal_libs.ui import STATIC

pytestmark = pytest.mark.usefixtures("no_outside")

JS = STATIC / "internal.js"


def read() -> str:
    return JS.read_text(encoding="utf-8")


def code_of(js: str) -> str:
    """The script without its comments: a line that is one, and one after code (two spaces, then //)."""
    out = []
    for line in js.splitlines():
        if line.lstrip().startswith("//"):
            continue
        cut = line.find("  // ")
        if cut >= 0 and all(line[:cut].count(q) % 2 == 0 for q in ("'", '"', "`")):
            line = line[:cut]
        out.append(line)
    return "\n".join(out)


def body_of(js: str, name: str) -> str:
    """A function's text, from `function name(` to the next line that starts another at its depth."""
    start = js.index(f"  function {name}(")
    rest = js[start + 2:]
    end = re.search(r"\n  (?:function |const |let |// )", rest)
    return rest[: end.start()] if end else rest


def interpolations(code: str) -> list[str]:
    """Every ${...} of the script's templates, as written (an inner one is listed too)."""
    found, at = [], 0
    while (at := code.find("${", at)) >= 0:
        depth, i, quote = 1, at + 2, ""
        while depth:
            ch = code[i]
            if quote:
                if ch == "\\":
                    i += 1
                elif ch == quote:
                    quote = ""
            elif ch in "'\"`":
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        found.append(code[at + 2: i - 1].strip())
        at += 2
    return found


def closes_at_end(expr: str, opened: int) -> bool:
    """Whether the bracket opened at `opened` closes at the expression's last character."""
    depth, quote = 0, ""
    for i in range(opened, len(expr)):
        ch = expr[i]
        if quote:
            if ch == quote and expr[i - 1] != "\\":
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i == len(expr) - 1
    return False


def drawn_safely(expr: str) -> bool:
    """A value drawn into the page is one call of esc, or HTML this script built (a name ending in Html, or a call
    of such a function), and nothing beside it."""
    if expr.startswith("esc("):
        return closes_at_end(expr, 3)
    m = re.match(r"[A-Za-z_$][\w$]*Html", expr)
    if not m:
        return False
    if m.end() == len(expr):
        return True
    return expr[m.end()] == "(" and closes_at_end(expr, m.end())


def test_one_drawing_for_every_page_shipped_with_the_library():
    js = read()
    assert JS.parent == STATIC  # ui/static/* is packaged whole (pyproject.toml's package-data)
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert '"ui/static/*"' in pyproject
    code = code_of(js).strip()
    assert code.startswith("(function () {\n  'use strict';")
    assert code.endswith("  window.LiminalInternal = { html, tabs, style, KINDS };\n})();")
    assert re.findall(r"window\.(\w+)\s*=", code) == ["LiminalInternal"]  # nothing else of its own on the page
    assert "const KINDS = Object.freeze(['read', 'tab', 'change', 'job', 'service', 'own']);" in code


def test_it_asks_nothing_of_any_server_and_writes_nothing_into_the_page():
    code = code_of(read())
    for word in ("fetch(", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "import(", "navigator.",
                 "location", "window.open", "new Image", "innerHTML", "outerHTML", "insertAdjacentHTML",
                 "document.write", "eval(", "Function("):
        assert word not in code, word  # it hands back HTML; the page puts it where it wants


def test_every_value_drawn_goes_through_esc():
    js = read()
    assert "const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' };" in js
    assert "const esc = (s) => String(s ?? '').replace(/[&<>\"']/g, (c) => ESCAPES[c]);" in js
    found = interpolations(code_of(js))
    assert len(found) > 80  # the scan sees the templates
    loose = [expr for expr in found if not drawn_safely(expr)]
    assert loose == [], f"drawn without esc: {loose}"
    # a page's own attributes on a plugin's button only when they are data-*, aria-* or title, each quoted
    assert "return SAFE_ATTRS.test(out) ? out.trim() : '';" in js
    safe = re.compile(js.split("const SAFE_ATTRS = /", 1)[1].split("/;\n", 1)[0])
    assert safe.match('data-select="ebpf"') and safe.match(' data-select="a" aria-label="b" ')
    for bad in ('onclick="x"', 'data-a="x" onmouseover="y"', 'data-a="x"><img src=x>', "data-a='x'", 'href="#x"'):
        assert not safe.match(bad), bad
    # Connections is linked only by an address within the page
    assert "const addressOf = (v) => (typeof v === 'string' && /^#[\\w\\-./:]*$/.test(v) ? v : '');" in js


def test_its_look_is_its_own_on_the_themes_variables():
    js = read()
    assert "const STYLE_ID = 'liminal-internal-style';" in js
    assert "if (!document.getElementById(STYLE_ID)) {" in js  # added once, whoever asks
    css = js.split("const STYLE = `", 1)[1].split("`;", 1)[0]
    for m in re.finditer(r"([^{}]+)\{", css):
        head = m.group(1).strip()
        if head.startswith("@media"):
            continue
        for selector in head.split(","):
            assert ".in-" in selector, selector  # its own classes: no rule of it reaches another part of the page
    for var in ("--text", "--muted", "--border", "--accent", "--hover", "--up", "--down", "--panel"):
        assert f"var({var})" in css, var
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", css)  # no colour of its own: every theme draws it
    # the (+) and the (−), round, the open one in the accent: as the firewall's groups and the API cards have them
    for part in (".in-pm::before{content:'+'}", ".in-fold[open]>summary>.in-pm::before{content:'−'}",
                 ".in-fold[open]>summary>.in-pm{border-color:var(--accent);color:var(--accent)}",
                 ".in-fold>summary::-webkit-details-marker{display:none}"):
        assert part in css, part
    assert "@media (max-width:480px){.in-facts{grid-template-columns:minmax(0,1fr)" in css  # a phone: one column
    assert "@media (any-pointer:coarse){.in-fold>summary,.in-tab{min-height:40px" in css  # a finger's targets


def test_a_hover_highlight_is_a_mouses_alone():
    css = read().split("const STYLE = `", 1)[1].split("`;", 1)[0]
    blocks = re.findall(r"@media \(hover:hover\)\{[^{}]*\{[^{}]*\}\}", css)
    assert len(blocks) >= 3
    rest = css
    for block in blocks:
        rest = rest.replace(block, "")
    assert ":hover" not in rest


def test_a_plugins_tab_leads_with_what_kind_of_middleware_it_is():
    """B1: what it is, how it is called, the standard interface of its base layer by layer (the nearest open), its
    own hooks; then what else the app's code takes from it, what it asks of others, its settings, its steps."""
    js = read()
    assert ("const PLUGIN_PARTS = [whatHtml, needsHtml, howHtml, standardHtml, ownHtml, alsoHtml, asksHtml, "
            "settingsHtml,\n    stepsHtml, notesHtml, seenHtml];") in js
    heads = {"whatHtml": "titleHtml('What it is')", "howHtml": "titleHtml('How it is called')",
             "standardHtml": "esc('The standard interface of ' + whose)", "ownHtml": "titleHtml('Its own hooks')",
             "alsoHtml": "titleHtml('What else ' + c.app + \"'s code takes from it\")",
             "asksHtml": "titleHtml('What it asks of other plugins')",
             "settingsHtml": "titleHtml('Settings through the login')", "stepsHtml": "titleHtml('Set up in steps')",
             "seenHtml": "esc('What it says and to whom, as it happens: ')"}
    for name, head in heads.items():
        assert head in body_of(js, name), name
    # open at first: what it is, how it is called, the nearest layer and its own hooks; the rest closed
    assert "bodyHtml, true);" in body_of(js, "whatHtml") and "bodyHtml, true);" in body_of(js, "howHtml")
    assert "i === 0, 'in-layer');" in body_of(js, "standardHtml")
    assert "bodyHtml, true);" in body_of(js, "ownHtml")
    for name in ("alsoHtml", "asksHtml", "settingsHtml", "stepsHtml"):
        assert body_of(js, name).rstrip().endswith(", false);\n  }"), name
    what = body_of(js, "whatHtml")
    for words in ("'Built on'", "'Above it'", "'Contract'", "'Hooks'", "\"'s code and its other plugins reach \"",
                  "'It sits on ' + and(sits) + ': its External API tab.'",
                  "'It declares no outside API or SDK of its own.'"):
        assert words in what, words
    # what it sits on is reached through it by Liminal's rule (addendum 14), said as the rule, not as what each app
    # does: the platform asks Docker's and WSL's command lines itself for its status, as its own External API says
    assert "pHtml(\"Liminal's rule: \" + c.app + \"'s code and its other plugins reach \"" in what
    assert "+ ' through ' + c.title + ', never around it.')" in what and "only through" not in code_of(what)
    # the six kinds are not heads: their counts, as internal.py counts them (its `counts`), are one line of facts
    counts = body_of(js, "countsWords")
    assert "const n = isObj(d.counts) ? d.counts : {}, kinds = isObj(n.kinds) ? n.kinds : {};" in counts
    assert "count(n.answered || 0, 'hook answered', 'hooks answered')" in counts
    assert "' left to the contract'" in counts and "c.rows" not in counts  # drawn as said, not counted again
    # the layers are the base's: the library class that names each hook (its row's `layer`), in the order internal.py
    # sends the rows (the nearest first: tests/test_internal.py holds it); the rest are its own
    assert "rows.filter((h) => str(h.layer)).forEach((h) => {" in body_of(js, "layersOf")
    assert "c.layers = layersOf(c.rows);" in body_of(js, "contextOf")
    assert "c.own = c.rows.filter((h) => !str(h.layer));" in body_of(js, "contextOf")
    words = ("'None of its own: it answers the standard interface alone.'",
             "\"It answers no hook of its own: the contract's defaults answer for it.\"")
    assert all(w in body_of(js, "ownHtml") for w in words)


def test_each_hook_says_what_it_does_and_who_uses_it():
    js = read()
    tags = body_of(js, "tagsHtml")
    for line in ("if (h.reads === true) tags.push(['a read', 'in-read']);",
                 "else if (h.reads === false) tags.push(['a change', '']);", "if (h.job) tags.push(['a job', '']);",
                 "if (h.cancels) tags.push(['can be cancelled', '']);",
                 "if (twice.length) tags.push(['asked twice: ' + twice.join(', '), 'in-twice']);",
                 "if (c.pageAsks.has(h.name)) tags.push(['its page asks it', '']);",
                 "if (h.property) tags.push(['a property', '']);"):
        assert line in tags, line
    assert "return 'tab ' + (text(t && t.title) || text(h.tab)) + (every ? ', every ' + every + ' s' : '');" in js
    who = body_of(js, "whoHtml")
    for line in ("const app = 'used by ' + c.app + \"'s code\" + (how ? ': ' + how : '');",
                 "const plugins = 'for other plugins: ' + (by.length ? and(by) : 'none known here');",
                 "case 'both': lines = [app, plugins]; break;", "case 'plugins': lines = [plugins]; break;",
                 "case 'app': lines = [app]; break;", "case 'named': lines = [named]; break;",
                 "default: lines = ['not used here'];",
                 "lines.push('asked by other plugins here: ' + and(by));"):
        assert line in who, line
    # asked by name: by its page and a client only where the app has a route for it (its words' `clients`: the
    # platform's POST /api/machines/{name}/ask); on the frame's apps, by another plugin through the app's ask alone
    assert ("const named = c.clients ? 'asked by name: its page, a client or another plugin'\n"
            "      : 'asked by name: another plugin, through ' + c.app + \"'s ask\";") in who
    assert "clients: isObj(d.calls) && str(d.calls.clients) };" in body_of(js, "contextOf")
    answered = body_of(js, "answeredWords")
    for line in ("if (h.answered === 'itself') return 'answered by its own code';",
                 "if (h.answered === '') return \"left to the contract's default\";",
                 "return str(h.answered) ? 'answered by ' + h.answered + \"'s code\" : '';"):
        assert line in answered, line
    hook = body_of(js, "hookHtml")
    assert "const answered = standard || isLeft(h) ? answeredWords(h) : '';" in hook  # a standard row, or one left
    assert "'<p class=\"in-line in-muted\">It says nothing of itself.</p>'" in hook
    doc = body_of(js, "docHtml")  # S2: the whole docstring, folded under its line, closed
    assert "if (!doc || squash(doc) === squash(h.line)) return '';" in doc
    assert "'<span class=\"in-doc-head\">The whole docstring</span>'" in doc and "false, 'in-doc');" in doc


def test_an_apps_tab_says_what_its_code_calls_then_what_it_offers():
    js = read()
    assert "return d.of === 'app' ? appHtml(d, o) : pluginHtml(d, o);" in js
    assert ("const APP_PARTS = [appFactsHtml, appCallsHtml, appOffersHtml, appRoutesHtml, appIncludesHtml, "
            "appLinksHtml,\n    appPluginsHtml, notesHtml, seenHtml];") in js
    calls = body_of(js, "appCallsHtml")
    for words in ("titleHtml('What ' + c.title + ' calls on its plugins')", "esc('It reads of it by name: ')",
                  "pHtml('And any other hook by name:')", "subHtml('On ' + kindWords(k, '')"):
        assert words in calls, words
    offers = body_of(js, "appOffersHtml")
    for words in ("titleHtml('What it offers them')",
                  "esc('Attached, a plugin is given the app as ') + codeHtml('self.app')",
                  "': one that notes, in Connections, each pair it reads or keeps.'",
                  "subHtml('What a plugin or another app may call on it', callsListHtml(d.methods))",
                  "const lent = 'The login it lends its plugins' + (str(lends.kind) ? ': ' + lends.kind : '');",
                  "subHtml(lent, callsListHtml(lends.interface))",
                  "subHtml('For code in its process', callsListHtml(d.offers))"):
        assert words in offers, words
    assert "tableHtml(['Method', 'Path', 'What', 'Class', 'For'], cells)" in body_of(js, "appRoutesHtml")
    assert "titleHtml('What it includes')" in body_of(js, "appIncludesHtml")
    assert "titleHtml('The apps it links')" in body_of(js, "appLinksHtml")
    assert "subHtml('Asked as reads, with no line in its log'" in calls  # its READ_HOOKS
    plugins = body_of(js, "appPluginsHtml")  # those it knows, attached or not, each with the class it is built on
    assert "titleHtml('Its plugins')" in plugins and "const attrsHtml = pickAttrs(c.pick, p.name);" in plugins
    assert "'built on ' + built" in plugins
    assert "p.attached === false ? '<span class=\"in-tag\">not attached</span>'" in plugins


def test_what_others_find_here_comes_with_the_data():
    """S3: what a plugin's asks find here is internal.py's `here`; the page computes nothing of other plugins."""
    js = read()
    assert "others" not in code_of(js)
    asks = body_of(js, "asksHtml")
    assert "tableHtml(['Plugin', 'Hook', 'Why', 'Here'], cells)" in asks
    assert "esc(text(a.here) || '–')" in asks  # "" when the app said nothing of its plugins (known=None)
    assert "'<span class=\"in-muted\">whichever answers it</span>'" in asks
    assert "pHtml('It asks nothing of other plugins.', 'in-muted')" in asks


def test_given_nothing_it_says_so_and_a_part_that_cannot_be_drawn_is_said():
    js = read()
    assert "const noneHtml = (o) => `<div class=\"in-none\">${esc(text(o.older) || 'Nothing to show.')}</div>`;" in js
    assert "if (Array.isArray(d)) return d.some(isObj) ? manyHtml(d, o) : noneHtml(o);" in js
    assert "if (!isObj(d) || blank(d)) return noneHtml(o);" in js
    assert "esc('The Internal API could not be drawn: ' + errorWords(e))" in js
    assert ("try { return part(d, c); } catch (e) { return pHtml('A part could not be drawn: ' + errorWords(e), "
            "'in-none'); }") in js


def test_what_was_opened_is_kept_in_this_browser():
    js = read()
    assert "const FOLDS_KEY = 'liminal:internal:folds';" in js  # its own key: apis.js keeps liminal:apis:folds
    assert "const MOST = 600;" in js
    assert "const last = Object.fromEntries([...folds].slice(-MOST));" in js
    assert "while (folds.size > MOST) folds.delete(folds.keys().next().value);" in js
    storage = [line for line in code_of(js).splitlines() if "localStorage" in line]
    assert len(storage) == 2 and all("try {" in line for line in storage)  # a page without storage draws all the same
    assert "const isOpen = (key, first) => (folds.has(key) ? folds.get(key) === true : !!first);" in js
    # a part drawn as it was (open at first, say) is not kept: only what the user opened or closed
    assert "if ((folds.has(key) ? folds.get(key) : el.dataset.inFirst === '1') === el.open) return;" in js
    assert "document.addEventListener('toggle', toggled, true);" in js


def test_a_page_without_tabs_of_its_own_gets_a_row_of_them():
    js = read()
    tabs = body_of(js, "tabs")
    assert "`<nav class=\"in-tabs\" role=\"tablist\" aria-label=\"${esc(text(label) || 'Its pages')}\">" in tabs
    assert "`<button type=\"button\" role=\"tab\" class=\"in-tab\" data-api-tab=\"${esc(t.id)}\"`" in tabs
    assert "` aria-selected=\"${esc(t.id === on)}\" tabindex=\"${esc(t.id === on ? 0 : -1)}\">`" in tabs
    assert "const on = all.some((t) => t.id === shown) ? shown : all[0].id;" in tabs
    keys = body_of(js, "keyed")  # the arrow keys, Home and End move along the row, each tab taken as it is reached
    assert "const to = { ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: all.length - 1 }[e.key];" in keys
    assert "next.focus();" in keys and "next.click();" in keys


def test_no_line_is_longer_than_120_and_no_release_number_is_in_its_words():
    for path in (JS, Path(__file__)):
        long = [n for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1) if len(line) > 120]
        assert long == [], f"{path.name}: lines over 120 characters: {long}"
    assert not re.search(r"\b\d+\.\d+\.\d+\b", code_of(read()))  # its comments may name a release; its words not
