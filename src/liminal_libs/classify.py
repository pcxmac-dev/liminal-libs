"""What a name this machine talks to is known for, read from free lists kept on this machine, for the firewalls'
Filter tab (the user, 2026-11-14: "classifying traffic as potential advert/monitoring sites that track users, etc").
Only lists with no non-commercial clause (the user's decision, the same day):

- EasyList: adverts;
- EasyPrivacy: tracking, and from the markers of its sections cryptomining, email trackers and trackers behind a
  site's own name (a CNAME);
- AdGuard companiesdb: the company a domain belongs to, and what its tracker does (telemetry, analytics, a CDN,
  hosting ...);
- hagezi's native-tracker lists: each vendor's telemetry.

The plugin downloads them, on the user's ask, into `lists_dir()` (layout.data_dir()/lists) with a manifest,
lists.json, saying what each file is: [{file, format, kind, source}] (`install_list` keeps both, one copy of each
file). Here they are only read: nothing is fetched and no outside host is named. Of an adblock (ABP) list only the
rules for a whole domain are taken, ||domain^ with options that keep it about the domain: exceptions (@@), cosmetic
rules (##), regular expressions and rules for a path say nothing about who is reached.

A name is looked up by its labels, its own and its parents' (www.ads.example.com: itself, ads.example.com,
example.com): a list's rule for a domain covers the names under it, and nothing is guessed beyond what is listed
(example.co.uk is matched by a rule for co.uk only when a list has that rule; a rule for a whole top-level domain is
never taken). The rules are one dict, capped (MAX_RULES), so a lookup is a handful of dict reads, and a name is
looked up in the form DNS carries it (an internationalised name in its xn-- form). A label says what a list says of
a name, never what the traffic is.

A list is downloaded, so it is read as untrusted text: line by line with string operations (no regular expression
that can backtrack), a line longer than MAX_LINE skipped, a token measured before it is encoded (a name in Unicode
label by label, as the codec's nameprep maps it), at most MAX_IDN names in Unicode encoded per list, and a file no
bigger than MAX_FILE (MAX_JSON for companiesdb's): the time a list costs its reader grows with its length alone (its
names in Unicode add under a second), and its RAM is its text and the names it gives (MAX_RULES at the most;
companiesdb's JSON once parsed, some 8 times its size)."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import reprlib
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from unicodedata import ucd_3_2_0

from . import layout
from .dns import valid_name

LISTS = "lists"  # the lists' folder, in layout.data_dir()
MANIFEST = "lists.json"  # what each file there is: [{file, format, kind, source}]
KINDS = {  # a label's kind, and what it means in plain words
    "ads": "serves adverts",
    "tracking": "follows people across sites and apps",
    "analytics": "measures how sites and apps are used",
    "telemetry": "reports how a program or a device is used",
    "cryptomining": "mines cryptocurrency on its visitors' machines",
    "email": "tracks when an email is opened",
    "cname-tracker": "tracks from behind a site's own name (a CNAME)",
    "social": "carries a social network's buttons, widgets or tracking",
    "cdn": "delivers content for many sites (a CDN)",
    "hosting": "hosts the servers of many owners",
}
FORMATS = ("abp", "hosts", "domains", "adguard_companies")  # a manifest entry's format, one per parser
_FORMAT_NAMES = {"adblock": "abp", "adblockplus": "abp", "host": "hosts", "domain": "domains", "wildcard": "domains",
                 "adguard": "adguard_companies", "companiesdb": "adguard_companies", "companies": "adguard_companies"}
# An ABP list's sections, by the file a marker names
# ("! *** easylist:easyprivacy/easyprivacy_trackingservers_mining.txt ***"), the first part found in its name deciding:
# the mining servers are tracking servers too, so they come first. Any other section is the list's own kind.
SECTIONS = (("_mining", "cryptomining"), ("emailtrackers", "email"), ("specific_cname", "cname-tracker"),
            ("trackingservers", "tracking"), ("adservers", "ads"))
# Options that make a rule about something other than reaching the domain: a page's headers or parameters rewritten, a
# redirect, a rule turned off (badfilter), a cosmetic switch, a DNS answer rewritten, or a rule for an app, a site key
# or some clients alone.
SKIP_OPTIONS = frozenset({
    "badfilter", "csp", "redirect", "redirect-rule", "rewrite", "removeparam", "queryprune", "removeheader", "header",
    "permissions", "replace", "cookie", "stealth", "urltransform", "uritransform", "hls", "jsonprune", "xmlprune",
    "referrerpolicy", "generichide", "ghide", "genericblock", "elemhide", "ehide", "specifichide", "shide", "content",
    "jsinject", "urlblock", "extension", "sitekey", "app", "empty", "mp4", "inline-script", "inline-font",
    "dnsrewrite", "client", "ctag"})
# AdGuard companiesdb's categories (dist/trackers.json, 2026-11-13), the ones a label is made of mapped to its kinds
# (comment widgets are a social kind); the others (a video player, customer chat, essential, consent, misc, unknown,
# extensions) give no label.
ADGUARD_CATEGORIES = {0: "audio_video_player", 1: "comments", 2: "customer_interaction", 3: "pornvertising",
                      4: "advertising", 5: "essential", 6: "site_analytics", 7: "social_media", 8: "misc", 9: "cdn",
                      10: "hosting", 11: "unknown", 12: "extensions", 13: "email", 14: "consent", 15: "telemetry",
                      101: "mobile_analytics"}
ADGUARD_KINDS = {"advertising": "ads", "pornvertising": "ads", "site_analytics": "analytics",
                 "mobile_analytics": "analytics", "telemetry": "telemetry", "social_media": "social",
                 "comments": "social", "email": "email", "cdn": "cdn", "hosting": "hosting"}
NOT_HOSTS = frozenset({"localhost.localdomain", "local", "localhost", "broadcasthost", "ip6-localhost",
                       "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
                       "ip6-allhosts"})  # a hosts file's own names, never a list's
# Names kept from all the lists together. EasyList and EasyPrivacy hold some 60k names of whole domains, companiesdb
# some 10k, hagezi's native-tracker lists a few thousand. MAX_RULES names cost some 25 MB at the lists' usual length
# (24 characters), and about 80 MB at the most, every name as long as a DNS name can be (253 characters; measured).
MAX_RULES = 250_000
# A text list read at most (EasyList is about 2 MB; MAX_RULES names fill some 8 MB in any format): while it is read,
# its text (up to 4 bytes a character) and the names taken from it are what it costs.
MAX_FILE = 8 * 2**20
MAX_JSON = 4 * 2**20  # companiesdb's files read at most (trackers.json is about 0.6 MB): parsed, some 8 times that
MAX_LINE = 64 * 1024  # a list's line longer than this is no rule of a list (skipped, never copied)
MAX_NAME = 253  # a DNS name's length at the most, in the form DNS carries it
MAX_LABEL = 63  # a DNS label's
# Names in Unicode encoded from one list at most (the lists hold a few hundred). The idna codec is pure Python: the
# costliest name a list can still hand it, four labels it takes and then one it refuses only once its punycode is done,
# takes some 1.5 ms here (measured on 2026-11-15), so a list's names in Unicode cost under a second.
MAX_IDN = 512
MAX_BADFILTERS = 10_000  # rules a list turns off, kept at most while it is read
MAX_NAMES = 16  # names of one peer looked up at most (classify_names: a CNAME chain, the names an address had)
COMPANIES = ".companies.json"  # companiesdb's company names kept beside its trackers file: <its stem>.companies.json
_RULE = re.compile(r"\|\|([^\s/^$*|#]+)\^\|?(?:\$(.*))?")  # every part bounded by the next: linear
_BADFILTER_WORD = re.compile("badfilter", re.I)
_LINE = re.compile(r"[^\r\n]+")
_FIELD = re.compile(r"\S+")
_DOTS = re.compile("[.\u3002\uff0e\uff61]")  # the dots between labels, as the idna codec splits a name
# IDNA 2003 (Python's codec) maps these (ß to ss, ς to σ, the zero-width joiners to nothing) where IDNA 2008 and the
# browsers keep them: a name holding one is not put in a form DNS might not carry
_DEVIATIONS = frozenset("\u00df\u03c2\u200c\u200d")
# What nameprep maps to nothing (stringprep's table B.1: the soft hyphen, the joiners, the variation selectors ...):
# left out of a label's measure, as the codec leaves it out
_NOTHING = dict.fromkeys((0x00AD, 0x034F, 0x1806, 0x180B, 0x180C, 0x180D, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,
                          *range(0xFE00, 0xFE10)))
_MAX_TOKEN = 4 * MAX_NAME  # a token longer than this is no name, blanks and trailing dots and all (never lowercased)
_FILE_NAME = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?")  # a list's file: a plain name, the same in any case
_DEVICES = frozenset({"con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)),
                      *(f"lpt{i}" for i in range(10))})  # names Windows keeps for its devices, whatever follows a dot
_install_lock = threading.Lock()


@dataclass(frozen=True)
class Label:
    """What a list says of a name: its kind (one of KINDS), the list that says it (`source`), and whose domain it is
    when the list knows (`company`)."""
    kind: str
    source: str
    company: str | None = None

    @property
    def words(self) -> str:
        """The kind in plain words ("serves adverts"), for the page's chips."""
        return KINDS.get(self.kind, self.kind)

    def as_dict(self) -> dict:
        """The page's label: {kind, source, company}, and its words."""
        return {"kind": self.kind, "source": self.source, "company": self.company, "words": self.words}


def lists_dir() -> Path:
    """Where the lists are kept: layout.data_dir()/lists."""
    return layout.data_dir() / LISTS


# -- names --------------------------------------------------------------------------------------------------------

def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    s = text.strip().strip("[]")
    if len(s) > 64 or (":" not in s and not s.replace(".", "").isdigit()):  # no address is longer, zone and all
        return None
    try:
        ip = ipaddress.ip_address(s.split("%", 1)[0])
    except ValueError:
        return None
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip


def _mapped(label: str) -> str:
    """A label as the idna codec's nameprep maps it before its punycode, at C speed: what it maps to nothing left out
    (_NOTHING), case folded, NFKC of Unicode 3.2 (U+FDFA becomes 18 characters, ᾳ two once case folded). Character
    by character it equals what the codec makes of a label; a few rare pairs of a letter and a combining mark (U+1C82
    with U+0308, the mathematical capital I letters with U+0307 and the like, 15 found) compose here and not in the
    codec, so such a label can reach the codec up to twice as long as measured. They add no distinct characters, and
    the codec's work grows with length times distinct characters, so they stay cheap (some 0.3 ms a name)."""
    return ucd_3_2_0.normalize("NFKC", label.translate(_NOTHING).casefold())


def _ascii(name: str) -> str:
    """A name in the form DNS carries it: an internationalised one in its xn-- form ("" when it has none). It is
    measured before it is encoded, each label as nameprep maps it (`_mapped`), so the codec (pure Python, whose work
    grows with a label's length times its distinct characters) is handed only what a DNS name can be once mapped,
    save the rare composing pairs `_mapped` names, which stay cheap. A name longer than a DNS name (before it is
    mapped or after), a label longer than a DNS label once mapped, and a name holding a character IDNA 2003 maps
    otherwise than browsers do (_DEVIATIONS) have none."""
    if name.isascii():
        return name
    if len(name) > MAX_NAME or not _DEVIATIONS.isdisjoint(name):
        return ""
    labels = [_mapped(label) for label in _DOTS.split(name)]  # split as the codec splits it, then mapped
    if any(len(label) > MAX_LABEL for label in labels) or sum(map(len, labels)) + len(labels) - 1 > MAX_NAME:
        return ""
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


class _Names:
    """One list's names read in turn: each as `_name` keeps it, the ones in Unicode (whose encoding is the costly
    part) at most MAX_IDN of them, the others then skipped. So a list made of long or many names in Unicode costs
    its reader under a second more than a list of plain names does."""
    __slots__ = ("idn",)

    def __init__(self):
        self.idn = 0

    def __call__(self, text, addresses: bool = True) -> str:
        return _name(text, addresses, self)[0]


def _name(text, addresses: bool = True, names: _Names | None = None) -> tuple[str, bool]:
    """A name as the rules and the lookups keep it (lowercased, no trailing dot, in its xn-- form; an address in its
    short form) and whether it is an address; ("", False) when it is neither a name of two labels or more nor an
    address. A token longer than a name can be is refused before anything is made of it; one in Unicode counts
    against `names`' MAX_IDN when it is read from a list."""
    s = str(text or "")
    if len(s) > _MAX_TOKEN:
        return "", False
    s = s.strip().lower().rstrip(".")
    if not s or len(s) > MAX_NAME:  # measured before it is encoded (no list's name is shorter once encoded)
        return "", False
    if not s.isascii():
        if names is not None:
            if names.idn >= MAX_IDN:
                return "", False
            names.idn += 1
        s = _ascii(s)
        if not s or len(s) > MAX_NAME:
            return "", False
    if ":" in s or s.strip("[]").replace(".", "").isdigit():  # an address, or nothing (1.2.3 is no name)
        ip = _address(s)
        return (ip.compressed, True) if ip is not None and addresses else ("", False)
    return valid_name(s), False


def _rule_name(text, addresses: bool = True) -> str:
    return _name(text, addresses)[0]


def _kind(kind) -> str:
    if not isinstance(kind, str) or kind not in KINDS:
        raise ValueError(f"{reprlib.repr(kind)} is no kind of label ({', '.join(KINDS)})")
    return kind


def _text(text) -> str:
    """A list's text: bytes read as UTF-8 (a byte that is not is replaced), a leading byte-order mark dropped."""
    if isinstance(text, (bytes, bytearray, memoryview)):
        return bytes(text).decode("utf-8-sig", errors="replace")
    return str(text or "").lstrip("\ufeff")


def _lines(text: str):
    """A list's lines, stripped, the empty ones and the ones longer than MAX_LINE left out (measured before they are
    copied): one pass over the text."""
    for m in _LINE.finditer(text):
        if m.end() - m.start() <= MAX_LINE:
            line = m.group().strip()
            if line:
                yield line


# -- the parsers --------------------------------------------------------------------------------------------------

def section_kind(marker: str, default_kind: str) -> str:
    """The kind of the rules after an ABP list's section marker (the file it names: easyprivacy_trackingservers.txt
    is tracking), `default_kind` for a section SECTIONS does not name."""
    name = re.split(r"[/:\\]", marker.strip().lower())[-1]
    return next((kind for part, kind in SECTIONS if part in name), default_kind)


def _marker(line: str) -> str | None:
    """What an ABP comment line's section marker names ("! *** easylist:easyprivacy/easyprivacy_general.txt ***"
    gives "easylist:easyprivacy/easyprivacy_general.txt"), None when the line is no marker. String operations only,
    so a line costs its length, whatever it holds."""
    s = line[1:].strip()
    if len(s) < 7 or not s.startswith("***") or not s.endswith("***"):
        return None
    return s[3:-3].strip()


def _whole_domain(options: str) -> bool:
    """Whether a rule's options keep it about reaching its domain: none of SKIP_OPTIONS, and no domain= naming the
    sites it alone holds on (a rule for some sites only says nothing of the domain itself; ~site, the sites it does not
    hold on, is fine)."""
    for option in options.split(","):
        name, _, value = option.strip().partition("=")
        name = (name.split(None, 1) or [""])[0].lstrip("~")  # an option's name is one word ("badfilter x" is badfilter)
        if name in SKIP_OPTIONS:
            return False
        if name in ("domain", "from") and any(d.strip() and not d.strip().startswith("~") for d in value.split("|")):
            return False
    return True


def _badfilters(text: str) -> set[str]:
    """The rules a list turns off (`||x^$third-party,badfilter` turns off `||x^$third-party`), lowercased: the
    rules for a domain with badfilter among their options, at most MAX_BADFILTERS of them. Read over the lines
    parse_abp reads, with string operations: one pass more, and only when the list says "badfilter" at all."""
    if not _BADFILTER_WORD.search(text):
        return set()
    out: set[str] = set()
    for line in _lines(text):
        if not line.startswith("||") or not _BADFILTER_WORD.search(line):
            continue
        base, dollar, options = line.lower().partition("$")
        options = [o.strip() for o in options.split(",")] if dollar else []
        if "badfilter" not in options:
            continue
        kept = [o for o in options if o and o != "badfilter"]
        out.add(base + ("$" + ",".join(kept) if kept else ""))
        if len(out) >= MAX_BADFILTERS:
            break
    return out


def parse_abp(text, default_kind: str, source: str = "adblock list", limit: int = MAX_RULES) -> dict[str, Label]:
    """The names an adblock (ABP) list's network rules for a whole domain give, each with its label: ||domain^ and
    ||domain^$options. The kind is the section's (SECTIONS, from the "! *** easylist:...file.txt ***" markers),
    `default_kind` before the first marker and in sections SECTIONS does not name; a name met in two sections keeps a
    section's own kind over the default. Skipped: comments, exceptions (@@), cosmetic rules (##, #@#, #?#, #$#),
    regular expressions, rules for a path or with a wildcard, rules for some sites only (domain=) or that only rewrite
    (SKIP_OPTIONS), rules a badfilter turns off, and rules for a whole top-level domain. At most `limit` names."""
    text = _text(text)
    default = _kind(default_kind)
    labels: dict[str, Label] = {}
    cancelled = _badfilters(text)
    out: dict[str, Label] = {}
    kind = default
    read = _Names()
    for line in _lines(text):
        if line[0] == "!":
            marker = _marker(line)
            if marker is not None:
                kind = section_kind(marker, default)
            continue
        if not line.startswith("||") or "#" in line:
            continue
        low = line.lower()
        if cancelled and low in cancelled:
            continue
        rule = _RULE.fullmatch(low)
        if rule is None or (rule.group(2) is not None and not _whole_domain(rule.group(2))):
            continue
        name = read(rule.group(1))
        if not name:
            continue
        had = out.get(name)
        if (had is None and len(out) < limit) or (had is not None and had.kind == default and kind != default):
            label = labels.get(kind)
            if label is None:
                label = labels[kind] = Label(kind, source)
            out[name] = label
    return out


def parse_hosts(text, kind: str, source: str = "hosts list", limit: int = MAX_RULES) -> dict[str, Label]:
    """The names a hosts-file list gives ("0.0.0.0 tracker.example", aliases after it, "# comments"), each labelled
    `kind`. A hosts file's own names (localhost, broadcasthost ...) and addresses are skipped; a line holding a name
    alone is read as that name. At most `limit` names (the reading stops there)."""
    text = _text(text)
    label = Label(_kind(kind), source)
    out: dict[str, Label] = {}
    read = _Names()
    for line in _lines(text):
        fields = _FIELD.finditer(line.partition("#")[0])  # one field at a time, never all of a line's at once
        first = next(fields, None)
        if first is None:
            continue
        names = (m.group() for m in fields) if _address(first.group()) is not None else (first.group(),)
        for field in names:
            if len(out) >= limit:
                return out
            name = read(field, addresses=False)
            if name and name not in NOT_HOSTS and name not in out:
                out[name] = label
    return out


def parse_domains(text, kind: str, source: str = "domain list", limit: int = MAX_RULES) -> dict[str, Label]:
    """The names a list of domains gives, one a line, each labelled `kind`: a plain name (hagezi's "onlydomains", where
    a name covers the names under it), a wildcard (*.example.com and .example.com: example.com and the names under
    it), an address. Comments ("#", "!" and ";" lines, and "# ..." after a name) and lines that are no name are
    skipped; a hosts line ("0.0.0.0 name") is read as its name. At most `limit` names (the reading stops there)."""
    text = _text(text)
    label = Label(_kind(kind), source)
    out: dict[str, Label] = {}
    read = _Names()
    for line in _lines(text):
        if len(out) >= limit:
            break
        if line[0] in "#!;[":
            continue
        fields = line.partition("#")[0].split(None, 2)  # the two fields a line's name can be in, and the rest
        if not fields:
            continue
        if len(fields) > 1 and _address(fields[0]) is not None:
            fields = fields[1:]
        token = fields[0]
        if token.startswith("||") and token.endswith("^"):
            token = token[2:-1]
        elif token.startswith("*."):
            token = token[2:]
        elif token.startswith("."):
            token = token[1:]
        name = read(token)
        if name and name not in out:
            out[name] = label
    return out


def _json(value):
    """JSON read: ValueError when it is none, and when it is nested too deeply to be read (the parser's
    RecursionError, which is no ValueError)."""
    if value is None or isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(_text(value))
    except RecursionError:
        raise ValueError("JSON nested too deeply to be read") from None


def _scalar(value) -> str | None:
    """A JSON id (a string or a whole number) as a string, None for anything else (a list or a map is no id, and is
    never made a string: a deep one would cost its depth)."""
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _company_names(value) -> dict[str, str]:
    """Company ids to names, from companiesdb's companies.json ({"companies": {id: {"name"}}}) or a map like it; {}
    when it holds none (or is no JSON)."""
    try:
        value = _json(value)
    except ValueError:
        return {}
    if isinstance(value, dict) and isinstance(value.get("companies"), dict):
        value = value["companies"]
    out = {}
    if isinstance(value, dict):
        for cid, company in value.items():
            name = company.get("name") if isinstance(company, dict) else company
            if isinstance(name, str) and name.strip():
                out[str(cid)] = name.strip()
    return out


def parse_adguard_companies(json_text, companies=None, source: str = "AdGuard companiesdb",
                            limit: int = MAX_RULES) -> dict[str, Label]:
    """The names AdGuard companiesdb's trackers.json gives ({categories, trackers, trackerDomains}): each domain to its
    tracker, the tracker to its category and its company. The label's kind is the category's (ADGUARD_KINDS; a
    category with no kind gives no label), its company the company's name when the file (a "companies" key) or
    `companies` (companies.json, its text or its dict) names it, else the tracker's name. At most `limit` names."""
    data = _json(json_text)
    if not isinstance(data, dict) or not isinstance(data.get("trackerDomains"), dict):
        raise ValueError("not AdGuard companiesdb's trackers.json: no trackerDomains")
    categories: dict[str, str] = {}
    given = data.get("categories")
    for key, value in (given.items() if isinstance(given, dict) else ()):
        if isinstance(value, str):
            categories[str(key)] = value
        elif isinstance(value, int) and not isinstance(value, bool):  # name -> id
            categories[str(value)] = str(key)
    if not categories:
        categories = {str(k): v for k, v in ADGUARD_CATEGORIES.items()}
    names = {**_company_names(data.get("companies")), **_company_names(companies)}
    trackers = data.get("trackers") if isinstance(data.get("trackers"), dict) else {}
    made: dict[str, Label | None] = {}
    shared: dict[Label, Label] = {}

    def label_of(tracker_id: str) -> Label | None:
        if tracker_id in made:
            return made[tracker_id]
        tracker = trackers.get(tracker_id)
        label = None
        if isinstance(tracker, dict):
            category = _scalar(tracker.get("categoryId", tracker.get("category")))
            category = categories.get(category, category) if category is not None else ""
            kind = ADGUARD_KINDS.get(category)
            if kind:
                company_id = _scalar(tracker.get("companyId"))
                company = (names.get(company_id) if company_id is not None else None) or tracker.get("name") or None
                label = Label(kind, source, company.strip() if isinstance(company, str) and company.strip() else None)
                label = shared.setdefault(label, label)
        made[tracker_id] = label
        return label

    out: dict[str, Label] = {}
    read = _Names()
    for domain, tracker_id in data["trackerDomains"].items():
        if len(out) >= limit:
            break
        if isinstance(tracker_id, dict):
            tracker_id = tracker_id.get("tracker") or tracker_id.get("trackerId")
        if not isinstance(tracker_id, str):
            continue
        name = read(domain)
        label = label_of(tracker_id) if name else None
        if label is not None and name not in out:
            out[name] = label
    return out


# -- the manifest and the classifier -------------------------------------------------------------------------------

def _word(value) -> str:
    """A manifest's value as words: a string, a number or a path as written, stripped; anything else (a list, a map:
    never made a string, a deep one would cost its depth) as nothing."""
    if isinstance(value, (str, int, float, os.PathLike)) and not isinstance(value, bool):
        return str(value).strip()
    return ""


def _format(value) -> str:
    fmt = _word(value).lower().replace("-", "_")
    fmt = _FORMAT_NAMES.get(fmt, fmt)
    if fmt not in FORMATS:
        raise ValueError(f"{reprlib.repr(value)} is no list format ({', '.join(FORMATS)})")
    return fmt


def _entry(entry) -> tuple[str, str, str | None, str]:
    """A manifest entry's file, format, kind (None for companiesdb's, whose kinds are its categories') and source,
    checked: ValueError, in plain words, when one is wrong (what the manifest held shown in short)."""
    if not isinstance(entry, dict):
        raise ValueError(f"{MANIFEST}: an entry that is no object: {reprlib.repr(entry)}")
    file = _word(entry.get("file"))
    if not file:
        raise ValueError(f"{MANIFEST}: an entry with no file")
    fmt = _format(entry.get("format"))
    kind = None if fmt == "adguard_companies" else _kind(entry.get("kind"))
    source = _word(entry.get("source")) or Path(file).stem
    return file, fmt, kind, source


def _inside(folder: Path, file: str) -> Path:
    path = (folder / file).resolve()
    if path == folder.resolve() or folder.resolve() not in path.parents:
        raise ValueError(f"{file}: not in the lists' folder")
    return path


def _cap(fmt: str) -> int:
    """The bytes a file of `fmt` is read to at most: MAX_FILE, and MAX_JSON for companiesdb's JSON (which costs
    some 8 times its size once parsed)."""
    return min(MAX_FILE, MAX_JSON) if fmt == "adguard_companies" else MAX_FILE


def _read_bytes(path: Path, cap: int) -> bytes:
    """A file's bytes, `cap` of them at most: ValueError when it is longer, even when it grew after it was measured."""
    size = path.stat().st_size
    if size > cap:
        raise ValueError(f"{path.name}: {size} bytes, more than a list is read ({cap})")
    with open(path, "rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"{path.name}: more than {cap} bytes, more than a list is read ({cap})")
    return data


def _read_text(path: Path, cap: int | None = None) -> str:
    """A list file's text, read to `cap` bytes at most (MAX_FILE when None)."""
    return _read_bytes(path, MAX_FILE if cap is None else cap).decode("utf-8-sig", errors="replace")


def _parse(fmt: str, text, kind: str | None, source: str, limit: int, companies=None) -> dict[str, Label]:
    if fmt == "abp":
        return parse_abp(text, kind, source, limit)
    if fmt == "hosts":
        return parse_hosts(text, kind, source, limit)
    if fmt == "domains":
        return parse_domains(text, kind, source, limit)
    return parse_adguard_companies(text, companies, source, limit)


def read_manifest(folder) -> list[dict]:
    """The manifest's entries as written ([] when there is none yet); ValueError when it is no list (or more than a
    manifest is, MAX_JSON, or nested too deeply to be read)."""
    path = Path(folder) / MANIFEST
    try:
        text = _read_bytes(path, MAX_JSON).decode("utf-8-sig")
    except FileNotFoundError:
        return []
    try:
        data = json.loads(text) if text.strip() else []
    except RecursionError:
        raise ValueError(f"{MANIFEST}: nested too deeply to be read") from None
    if isinstance(data, dict):
        data = data.get("lists", [])
    if not isinstance(data, list):
        raise ValueError(f"{MANIFEST}: not a list of the lists")
    return data


def _write(path: Path, data: bytes) -> None:
    """`data` in `path` at once: a reader sees the old file or the new one, never a part."""
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".part", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        for attempt in range(20):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:  # Windows: a reader has it open for a moment
                if attempt == 19:
                    raise
                time.sleep(0.05)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _bytes(data, file: str, cap: int | None = None) -> bytes:
    """A list's bytes as given (text as UTF-8), `cap` of them at most (MAX_FILE when None)."""
    cap = MAX_FILE if cap is None else cap
    if isinstance(data, (bytes, bytearray, memoryview)):
        if (data.nbytes if isinstance(data, memoryview) else len(data)) > cap:  # measured before it is copied
            raise ValueError(f"{file}: more than {cap} bytes, more than a list is read ({cap})")
        raw = bytes(data)
    else:
        text = str(data)
        if len(text) > cap:  # each character a byte at least: too long before it is encoded
            raise ValueError(f"{file}: more than {cap} bytes, more than a list is read ({cap})")
        raw = text.encode("utf-8")
    if len(raw) > cap:
        raise ValueError(f"{file}: {len(raw)} bytes, more than a list is read ({cap})")
    return raw


def _plain(file: str) -> str:
    """A list's file name as it is kept: a plain name, lowercased (so two names never fold onto one file, as Windows
    folds them): letters, digits, '.', '_' and '-', a letter or a digit at each end (Windows drops a trailing dot or
    blank), at most 128 characters, and none of the names Windows keeps for its devices, the manifest's or a part's
    being written. ValueError otherwise."""
    name = file.lower()
    if (not _FILE_NAME.fullmatch(name) or name == MANIFEST or name.endswith(".part")
            or name.split(".", 1)[0] in _DEVICES):
        raise ValueError(f"{file!r}: a list is kept as a plain file name in the lists' folder (letters, digits, '.', "
                         f"'_' and '-', a letter or a digit at each end)")
    return name


def install_list(data, folder, file: str, format: str, kind: str | None = None, source: str | None = None, *,
                 companies=None, **more) -> Path:
    """A downloaded list (its bytes) kept in `folder` as `file`, one copy (the old one replaced), and named in the
    manifest with its format, kind and source (and `more`, kept in its entry as given), in the place it had there or
    last. `file` is a plain name, kept lowercased (`_plain`), and neither another list's nor another list's company
    names'. For companiesdb's trackers.json, `companies` is its companies.json (bytes or text), kept beside it as
    <stem>.companies.json and named in the entry ("companies"); without it, a companion already kept stays. Each is
    read first: a file that gives no names (or company names) is refused, ValueError, and nothing changes."""
    folder = Path(folder)
    entry = {"file": file, "format": format, "kind": kind, "source": source, **more}
    file, fmt, kind, source = _entry(entry)
    file = _plain(file)
    raw = _bytes(data, file, _cap(fmt))
    companion = names = None
    if companies is not None:
        if fmt != "adguard_companies":
            raise ValueError(f"{file}: company names go with companiesdb's trackers.json only")
        companion = Path(file).stem + COMPANIES
        names = _bytes(companies, companion, _cap(fmt))
        if not _company_names(names):
            raise ValueError(f"{companion}: no company names read from it: not kept")
    if not _parse(fmt, raw, kind, source, MAX_RULES, names):
        raise ValueError(f"{file}: no names read from it as {fmt}: not kept")
    entry.update(file=file, format=fmt, kind=kind, source=source,
                 installed=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    with _install_lock:
        try:
            entries = read_manifest(folder)
        except ValueError:  # a manifest that cannot be read names nothing that can be read: it starts again
            entries = []
        at = next((i for i, e in enumerate(entries) if isinstance(e, dict) and _word(e.get("file")).lower() == file),
                  None)
        if companion is None and fmt == "adguard_companies" and at is not None:
            kept = entries[at].get("companies")
            if isinstance(kept, str) and kept == Path(kept).name and (folder / kept).is_file():
                companion = kept
        others = [e for i, e in enumerate(entries) if i != at and isinstance(e, dict)]
        files = {_word(e.get("file")).lower() for e in others}
        companions = {_word(e.get("companies")).lower() for e in others}
        if file in companions:  # checked before anything is written: refused, nothing changes
            raise ValueError(f"{file}: another list's company names are kept in it")
        if companion is not None and companion.lower() in files | companions:
            raise ValueError(f"{companion}: another list is kept in it")
        folder.mkdir(parents=True, exist_ok=True)
        if names is not None:
            _write(folder / companion, names)
        _write(folder / file, raw)
        if companion is not None:
            entry["companies"] = companion
        if at is None:
            entries.append(entry)
        else:
            entries[at] = entry
        _write(folder / MANIFEST, json.dumps(entries, indent=1, ensure_ascii=False).encode("utf-8"))
    return folder / file


class Classifier:
    """The lists' names in one dict, each to its labels (one of each kind, the first list's), at most `max_rules`
    names: the ones past it are not loaded and `describe` says how many. Labels and their tuples are kept once each,
    so a name costs its own string and a dict slot."""

    def __init__(self, max_rules: int = MAX_RULES):
        self.max_rules = max(0, int(max_rules))
        self.folder: Path | None = None
        self.lists: list[dict] = []  # each list read: file, format, kind, source, names, size, modified, error
        self.capped = 0  # names not loaded, past max_rules
        self.error: str | None = None  # the manifest could not be read
        self._rules: dict[str, tuple[Label, ...]] = {}
        self._shared: dict = {}

    def __len__(self) -> int:
        return len(self._rules)

    def add(self, rules: dict[str, Label]) -> int:
        """A parsed list's names added (a name keeps its first label of each kind): how many names it labelled."""
        rules_here, shared, added = self._rules, self._shared, 0
        for name, label in rules.items():
            label = shared.setdefault(label, label)
            had = rules_here.get(name)
            if had is None:
                if len(rules_here) >= self.max_rules:
                    self.capped += 1
                    continue
                labels = (label,)
            elif any(h.kind == label.kind for h in had):
                continue
            else:
                labels = had + (label,)
            rules_here[name] = shared.setdefault(labels, labels)
            added += 1
        return added

    @classmethod
    def from_folder(cls, folder=None, max_rules: int = MAX_RULES) -> Classifier:
        """The lists the manifest (lists.json) in `folder` (lists_dir() when None) names, in its order (the first
        list's label wins for its kind). A list that cannot be read is skipped and says why in `lists` ("error"); no
        manifest is no lists. Without its company names, companiesdb's labels name its trackers ("note")."""
        c = cls(max_rules)
        c.folder = Path(folder) if folder is not None else lists_dir()
        try:
            entries = read_manifest(c.folder)
        except (OSError, ValueError) as e:
            c.error = f"{MANIFEST} could not be read: {e}"
            return c
        for entry in entries:
            given = entry if isinstance(entry, dict) else {}
            info = {key: given.get(key) if isinstance(given.get(key), str) else None  # as the manifest says, in words
                    for key in ("file", "format", "kind", "source")}
            info.update(names=0, size=None, modified=None, error=None, note=None)
            try:
                file, fmt, kind, source = _entry(entry)
                info.update(file=file, format=fmt, kind=kind, source=source)
                path = _inside(c.folder, file)
                stat = path.stat()
                info.update(size=stat.st_size,
                            modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds"))
                companies = None
                if fmt == "adguard_companies" and given.get("companies"):
                    try:
                        companies = _company_names(_read_text(_inside(c.folder, _word(given["companies"])), _cap(fmt)))
                    except (OSError, ValueError, RecursionError) as e:
                        info["note"] = f"company names not read ({e}): its labels name the trackers"
                    else:
                        if not companies:
                            info["note"] = "no company names in its companion file: its labels name the trackers"
                rules = _parse(fmt, _read_text(path, _cap(fmt)), kind, source, max(1, c.max_rules), companies)
                info["names"] = len(rules)
                c.add(rules)
            except FileNotFoundError as e:
                info["error"] = f"not downloaded yet ({Path(e.filename or info['file'] or '').name})"
            except (OSError, ValueError, TypeError, RecursionError) as e:  # this list's, never the others'
                info["error"] = str(e)
            c.lists.append(info)
        return c

    def classify(self, name) -> list[Label]:
        """What the lists say of `name`: its labels, one of each kind, the most particular name's first (a rule for
        ads.example.com before one for example.com), then the lists' order. An address is matched as itself only."""
        name, is_address = _name(name)
        if not name:
            return []
        rules = self._rules
        if is_address:
            return list(rules.get(name, ()))
        out: list[Label] = []
        kinds: set[str] = set()
        at = 0
        while True:
            for label in rules.get(name[at:], ()):
                if label.kind not in kinds:
                    kinds.add(label.kind)
                    out.append(label)
            dot = name.find(".", at)
            if dot < 0:
                return out
            at = dot + 1

    def classify_names(self, names) -> list[Label]:
        """What the lists say of a peer known by several names (a CNAME chain, the names an address had, the most
        recent first): each name's labels, one of each kind, the earlier names' first; at most MAX_NAMES names."""
        out: list[Label] = []
        kinds: set[str] = set()
        for name in list(names or ())[:MAX_NAMES]:
            for label in self.classify(name):
                if label.kind not in kinds:
                    kinds.add(label.kind)
                    out.append(label)
        return out

    def describe(self) -> dict:
        """What is loaded, for the plugin's page: the folder, the names, how many the cap left out, each list."""
        return {"folder": str(self.folder) if self.folder is not None else None, "names": len(self._rules),
                "capped": self.capped, "error": self.error, "lists": [dict(i) for i in self.lists]}
