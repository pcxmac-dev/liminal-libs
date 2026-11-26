"""The GeoIP sources a firewall plugin names for its World Wide Web tab (Monday list item 20; the user, 2026-11-19: "add
a way to download different GEOIP sources"). A source is a maker (DB-IP, IPinfo ...) and the files it gives, each for
one role: `places` (where an address is: a city and a point) or `networks` (its AS number and operator). Places and
networks are chosen apart, and the default source for both is the plugin's first (DB-IP's, today's files and folders).

- Every host, address, licence and credit is the plugin's own (its GEOIP_SOURCES, plain dicts): no outside host is
  named here. `of` reads one dict as `infrastructure.DataSet.of` reads a data set, and refuses in words what it cannot
  be: an address that is no https one or holds a user name, a host that is no plain name, an unknown role, packing,
  shape, checksum or way of sending a key, licence words longer than WORDS or without the pointer to the full licence.
- A source may be named and not offered (`offered` false): it is drawn as "not offered: waiting for your word", with
  no button, no key asked and nothing downloaded (the user, 2026-11-25: each source offered only after their yes).
- Keys are read only in a download's job, through the login given (the asking person's), checked before use
  (`checked`: keys.clean, then the maker's form), and never said: every word a download says goes through `redact`,
  which takes out each value in the forms an error may print it (as typed, percent-encoded both ways, repr-escaped,
  and in base64 beside another).
- Files are kept apart by source: the default source's in the GeoIP folder and its asn/ folder, as before; any other
  in <folder>/<id> and <folder>/<id>/asn (`folder`), so an install prunes its own source's older copies alone.
- Nothing runs by itself: whether a file is due is worked out from its build date when the tab is drawn (`due`).
- The places a host was given carry the stamp of the files in use (`stamp`): the default pair's is the places file's
  date, as before, so the rows placed already are not placed again; any other pair's begins with # (`cleared` names
  a role's rows of one source)."""
from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit

from ..sources import keys as keys_module

ROLES = ("places", "networks")
ROLE_WORDS = {"places": "places", "networks": "networks"}
PACKINGS = ("mmdb", "mmdb.gz")  # how a file comes: a plain MaxMind DB file, or gzipped (phases 2 and 3 add tar and zip)
SHAPES = ("geoip2", "ipinfo-lite")  # how its records read: GeoIP2's maps (DB-IP's, MaxMind's), or IPinfo Lite's flat ones
CHECKSUMS = ("none", "ipinfo-checksums")  # how a newer file is told before it is downloaded
KEY_WAYS = ("none", "query")  # how a source's key travels: none needed, or in the first address's query alone
FORMS = ("digits", "token")  # a key's form: an account's number, or a key or token of letters, digits, _ and -
WORDS = 1500  # characters of a licence's words at most (apps.WORDS_KEPT: the record keeps them whole)
CREDIT = 160  # characters of a credit's text at most: drawn whole wherever its data is
TITLE = 80  # characters of a title or a maker's name at most
SIZE_WORDS = 160  # characters of a file's size in words at most
SENT_ON = 3  # hosts a file's download may be sent on to, beside its own (MAX_REDIRECTS hops at most)
MAX_DAYS = 366  # an update's rhythm and a file's age, in days, at most
VAR = "LIMINAL_GEOIP_SOURCES"  # the choice kept per machine, through the platform's login, while it keeps no settings
SETTING = "geoip-sources"  # ... and as the signed-in user's preference where the login keeps them
ID = re.compile(r"[a-z][a-z0-9-]{0,31}")
STEM = re.compile(r"[a-z][a-z0-9-]{0,47}")
QUERY = re.compile(r"[a-z][a-z0-9_]{0,31}")
HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
TOKEN = re.compile(r"[A-Za-z0-9_-]{8,128}")
DIGITS = re.compile(r"[0-9]{1,12}")
NOT_ASKED = "sign in on the platform's page, then ask again"
WHERE_KEYS = "on the login's page, under the pairs the platform's plugins ask for"


class NotAsked(ValueError):
    """A GeoIP source's download, use or removal asked by anyone but a person signed in at the platform's page."""

    def __init__(self, words: str = ""):
        super().__init__(words or f"Only you can ask this, from the platform's page: {NOT_ASKED}.")


class RemovalRefused(ValueError):
    """A GeoIP file's removal asked without its second confirmation: the page asks it, naming `accept_removal`."""

    accept = "accept_removal"


def pointer(url: str) -> str:
    """The sentence a licence's words end with: they are a summary, and the licence itself applies."""
    return f"This is a summary; the full licence at {url} applies."


@dataclass(frozen=True)
class Licence:
    words: str  # what the user reads and accepts, a summary ending with pointer(url)
    name: str  # its short name, for the table: CC BY 4.0
    pair: str  # its record's pair, without licence-: dbip-lite
    version: str  # the licence's own version: CC BY 4.0
    url: str  # the licence's own page, never a download address


@dataclass(frozen=True)
class GeoFile:
    """One file a source gives, for one role. `url`: a month's address ({year} and {month} filled in) or one fixed
    address; `stem`: what a fixed address's file is named, before its build date (ipinfo-lite-2026-11-24); `sent_on`:
    the hosts its download may be sent on to; `every_days`: an update is offered this many days after its build (0:
    once it is from an earlier month); `max_age_days`: from this day on it is not read (0: never too old)."""

    source: str
    role: str
    title: str
    url: str
    packing: str
    shape: str
    size: str
    licence: Licence
    credit: Mapping = field(hash=False, compare=False)
    stem: str = ""
    sent_on: tuple[str, ...] = ()
    checksum: str = "none"
    checksum_url: str = ""
    every_days: int = 0
    max_age_days: int = 0
    places_home: bool = True
    keep_places: bool = True

    @property
    def monthly(self) -> bool:
        return "{year}" in self.url or "{month}" in self.url

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").lower()

    @property
    def key(self) -> str:
        """Its form's and its row's name: <source>-<role>."""
        return f"{self.source}-{self.role}"


@dataclass(frozen=True)
class GeoSource:
    """A maker and the files it gives. `hosts`: the maker's own (a 401 or 403 from one of them is the key's; from any
    other, a storage host's); `keys`: the key names it needs, each with its form (FORMS); `sends`: how they travel
    (KEY_WAYS), `query` the address's parameter; `offered`: whether the tab offers it (false: named, drawn as waiting
    for the user's word, nothing asked)."""

    id: str
    title: str
    maker: str
    hosts: tuple[str, ...]
    files: tuple[GeoFile, ...]
    keys: Mapping = field(hash=False, compare=False, default_factory=dict)
    sends: str = "none"
    query: str = ""
    offered: bool = True

    def file(self, role: str) -> GeoFile | None:
        return next((f for f in self.files if f.role == role), None)

    @property
    def roles(self) -> tuple[str, ...]:
        return tuple(f.role for f in self.files)


def _shown(value) -> str:
    text = value if isinstance(value, str) else repr(value)
    return repr(text[:40] + "…" if len(text) > 40 else text) if isinstance(value, str) else text[:40]


def _text(value) -> str:
    return " ".join(value.split()) if isinstance(value, str) else ""


def _https(url: str, what: str) -> str:
    """`url` when it is an https address on a plain host with nothing of anyone's in it; ValueError naming `what`."""
    try:
        parts = urlsplit(url)
        host, _ = parts.hostname, parts.port
    except (TypeError, ValueError):
        raise ValueError(f"{what} is no address") from None
    if parts.scheme.lower() != "https" or not host:
        raise ValueError(f"{what} is downloaded over https only")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError(f"{what} holds no user name or password: a key travels as its source says, never in a name")
    if not HOST.fullmatch(host) or parts.port is not None:
        raise ValueError(f"{what}'s host is a plain name ({_shown(host)} is not)")
    if any(c in url for c in " \t\r\n#"):
        raise ValueError(f"{what} holds no space and no #")
    return url


def _host(value, what: str) -> str:
    host = value.strip().lower() if isinstance(value, str) else ""
    if not HOST.fullmatch(host):
        raise ValueError(f"{what} is a plain host name, not {_shown(value)}")
    return host


def _days(value, what: str, least: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not least <= value <= MAX_DAYS:
        raise ValueError(f"{what} is a whole number of days from {least} to {MAX_DAYS}, not {_shown(value)}")
    return value


def _one_of(value, known: tuple, what: str) -> str:
    out = value.strip().lower() if isinstance(value, str) else value
    if out not in known:
        raise ValueError(f"{what} is {', '.join(known[:-1])} or {known[-1]}, not {_shown(value)}")
    return out


def _licence(said, ident: str) -> Licence:
    if not isinstance(said, Mapping):
        raise ValueError(f"{ident} names no licence: its words are shown and accepted before the download")
    url = _https(_text(said.get("url")), f"{ident}'s licence page")
    words = said.get("words")
    words = words.strip() if isinstance(words, str) else ""
    if not words:
        raise ValueError(f"{ident}'s licence has no words: they are shown and accepted before the download")
    if len(words) > WORDS:
        raise ValueError(f"{ident}'s licence words are {WORDS:,} characters at most (a summary, kept whole in the "
                         "record of its acceptance)")
    if not words.endswith(pointer(url)):
        raise ValueError(f"{ident}'s licence words end with {pointer(url)!r}: they are a summary")
    name = _text(said.get("name"))[:TITLE]
    version = _text(said.get("version"))[:TITLE]
    pair = _text(said.get("pair")).lower()
    if not name or not version:
        raise ValueError(f"{ident}'s licence names its short name and its version (CC BY 4.0)")
    if not STEM.fullmatch(pair) or pair.startswith("licence"):
        raise ValueError(f"{ident}'s licence pair is lowercase letters, digits and dashes (dbip-lite), not "
                         f"{_shown(said.get('pair'))}")
    return Licence(words=words, name=name, pair=pair, version=version, url=url)


def _credit(said, ident: str) -> dict:
    text = _text(said.get("text")) if isinstance(said, Mapping) else ""
    if not text:
        raise ValueError(f"{ident} names no credit: its text is drawn wherever its data is")
    if len(text) > CREDIT:
        raise ValueError(f"{ident}'s credit is {CREDIT} characters at most: it is drawn whole")
    link = _text(said.get("url"))
    return {"text": text, "url": _https(link, f"{ident}'s credit link") if link else ""}


def _file(said, source: str, hosts: tuple[str, ...]) -> GeoFile:
    if not isinstance(said, Mapping):
        raise ValueError(f"the source {source}'s file is a dict, not {type(said).__name__}")
    role = _one_of(said.get("role"), ROLES, f"the source {source}'s file's role")
    ident = f"the source {source}'s {role} file"
    title = _text(said.get("title"))[:TITLE]
    if not title:
        raise ValueError(f"{ident} has no title")
    url = _https(_text(said.get("url")), ident)
    if "?" in url:
        raise ValueError(f"{ident}'s address holds no query of its own: a key travels as its source says")
    host = (urlsplit(url).hostname or "").lower()
    if host not in hosts:
        raise ValueError(f"{ident} is asked of one of the source's own hosts ({', '.join(hosts)}), not {host}")
    packing = _one_of(said.get("packing"), PACKINGS, f"{ident}'s packing")
    shape = _one_of(said.get("shape", "geoip2"), SHAPES, f"{ident}'s shape")
    monthly = "{year}" in url or "{month}" in url
    stem = _text(said.get("stem")).lower()
    if not monthly and not STEM.fullmatch(stem):
        raise ValueError(f"{ident} comes from one fixed address, so it names its stem (lowercase letters, digits and "
                         "dashes: ipinfo-lite), which its build date follows")
    if monthly and ("{year}" not in url or "{month}" not in url):
        raise ValueError(f"{ident}'s month address names both {{year}} and {{month}}")
    size = _text(said.get("size"))[:SIZE_WORDS]
    if not size:
        raise ValueError(f"{ident} says no size: its bytes are said before it is downloaded")
    sent = said.get("sent_on", ())
    if isinstance(sent, str) or not isinstance(sent, (list, tuple)) or len(sent) > SENT_ON:
        raise ValueError(f"{ident}'s sent_on is a list of {SENT_ON} hosts at most")
    sent_on = tuple(dict.fromkeys(_host(h, f"{ident}'s sent_on host") for h in sent))
    checksum = _one_of(said.get("checksum", "none"), CHECKSUMS, f"{ident}'s checksum")
    checksum_url = _text(said.get("checksum_url"))
    if checksum != "none":
        checksum_url = _https(checksum_url, f"{ident}'s checksum address")
        if (urlsplit(checksum_url).hostname or "").lower() not in hosts or "?" in checksum_url:
            raise ValueError(f"{ident}'s checksum address is on the source's own hosts, with no query of its own")
    elif checksum_url:
        raise ValueError(f"{ident} names a checksum address but no checksum")
    if shape == "ipinfo-lite" and role != "networks":
        raise ValueError(f"{ident}: IPinfo Lite's records hold no points, so it gives networks alone")
    return GeoFile(source=source, role=role, title=title, url=url, packing=packing, shape=shape, size=size,
                   licence=_licence(said.get("licence"), ident), credit=_credit(said.get("credit"), ident), stem=stem,
                   sent_on=sent_on, checksum=checksum, checksum_url=checksum_url,
                   every_days=_days(said.get("every_days", 0), f"{ident}'s every_days"),
                   max_age_days=_days(said.get("max_age_days", 0), f"{ident}'s max_age_days"),
                   places_home=said.get("places_home", True) is True, keep_places=said.get("keep_places", True) is True)


def of(said, declared=()) -> GeoSource:
    """A plugin's plain dict as a GeoIP source (a GeoSource as it is); ValueError, in words, for what it cannot be.
    `declared`: the key names the plugin declares (its keys' names); an offered source's keys are among them."""
    if isinstance(said, GeoSource):
        return said
    if not isinstance(said, Mapping):
        raise ValueError(f"a GeoIP source is a plugin's dict (id, title, maker, hosts, files), not "
                         f"{type(said).__name__}")
    ident = said.get("id")
    if not isinstance(ident, str) or not ID.fullmatch(ident) or ident == "asn":
        raise ValueError("a GeoIP source's id is lowercase letters, digits and dashes (32 at most, a letter first, never "
                         f"asn: that is the networks' folder), not {_shown(ident)}")
    title, maker = _text(said.get("title"))[:TITLE], _text(said.get("maker"))[:TITLE]
    if not title or not maker:
        raise ValueError(f"the source {ident} names its title and its maker")
    hosts = said.get("hosts")
    if isinstance(hosts, str) or not isinstance(hosts, (list, tuple)) or not hosts or len(hosts) > SENT_ON:
        raise ValueError(f"the source {ident} names its maker's own hosts, {SENT_ON} at most")
    hosts = tuple(dict.fromkeys(_host(h, f"the source {ident}'s host") for h in hosts))
    offered = said.get("offered", True) is True
    sends = _one_of(said.get("sends", "none"), KEY_WAYS, f"the source {ident}'s way of sending its key")
    wanted = said.get("keys") or {}
    if not isinstance(wanted, Mapping):
        raise ValueError(f"the source {ident}'s keys are its key names, each with its form ({', '.join(FORMS)})")
    if sends == "none" and wanted:
        raise ValueError(f"the source {ident} sends no key, so it names none")
    forms: dict[str, str] = {}
    declared = {str(getattr(k, "name", k)) for k in declared}
    for name, form in wanted.items():
        why = keys_module.refusal(name) if isinstance(name, str) else f"{_shown(name)} is not a variable name"
        if why:
            raise ValueError(f"the source {ident}: {why}")
        forms[name] = _one_of(form, FORMS, f"the source {ident}'s key {name}'s form")
        if offered and name not in declared:
            raise ValueError(f"the source {ident} needs {name}, which the plugin does not declare")
    query = _text(said.get("query")).lower()
    if sends == "none" and (forms or query):
        raise ValueError(f"the source {ident} sends no key, so it names none")
    if sends == "query" and (len(forms) != 1 or not QUERY.fullmatch(query)):
        raise ValueError(f"the source {ident} sends its one key in the address: it names that key and the query's "
                         "parameter (lowercase letters, digits and _)")
    files = said.get("files")
    if isinstance(files, (str, Mapping)) or not isinstance(files, (list, tuple)) or not files:
        raise ValueError(f"the source {ident} gives no file")
    read = tuple(_file(f, ident, hosts) for f in files)
    roles = [f.role for f in read]
    if len(set(roles)) != len(roles):
        raise ValueError(f"the source {ident} gives one file a role")
    return GeoSource(id=ident, title=title, maker=maker, hosts=hosts, files=read, keys=forms, sends=sends,
                     query=query, offered=offered)


def read(sources, declared=()) -> tuple[list[GeoSource], list[str]]:
    """A plugin's GEOIP_SOURCES read: those that read (`of`), and what was wrong with each that did not, in words (one
    named twice is the first)."""
    out: list[GeoSource] = []
    refused: list[str] = []
    for said in sources or ():
        try:
            source = of(said, declared)
        except ValueError as e:
            refused.append(str(e))
            continue
        if any(s.id == source.id for s in out):
            refused.append(f"the source {source.id} is named twice: the first is used")
            continue
        out.append(source)
    return out, refused


def folder(base: Path, source: str, role: str, default: str) -> Path:
    """Where a source's file of `role` is kept: the default source's in `base` (places) and base/asn (networks), as
    before 1.101.0; any other's in base/<id> and base/<id>/asn, so no source's install prunes another's file."""
    base = Path(base)
    own = base if source == default else base / source
    return own / "asn" if role == "networks" else own


def _utc(when) -> datetime | None:
    if when is None or isinstance(when, bool):
        return None
    if isinstance(when, (int, float)):
        return datetime.fromtimestamp(when, timezone.utc)
    if isinstance(when, datetime):
        return when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    return None


def age_days(built, now) -> float | None:
    built, now = _utc(built), _utc(now)
    return None if built is None or now is None else (now - built).total_seconds() / 86400.0


def due(file: GeoFile, built, now) -> str:
    """Whether a file built at `built` (epoch seconds or a datetime) is `fresh`, due an `update` (offered, never done by
    itself), or `expired` (not read from its max_age_days on), at `now`."""
    age = age_days(built, now)
    if age is None:
        return "update"
    if file.max_age_days and age >= file.max_age_days:
        return "expired"
    if file.every_days:
        return "update" if age >= file.every_days else "fresh"
    b, n = _utc(built), _utc(now)
    return "update" if (b.year, b.month) < (n.year, n.month) else "fresh"


def usable(file: GeoFile, now):
    """A test of a file's build time for geo's `usable`: False from its max_age_days on (`now()` asked at each test)."""
    def test(path, built) -> bool:
        return not file.max_age_days or due(file, built, now()) != "expired"
    return test


def stamp(places, networks, default: str) -> str:
    """What a host placed from these files is stamped with. `places` and `networks`: (source id, the file's date) or
    None for none. The default source's places, with its networks or none: the places file's date, as before 1.101.0
    (so its rows are not placed again); any other pair: #<id>:<date>+<id>:<date>, `none` for a role with no file."""
    def one(f) -> str:
        return f"{f[0]}:{f[1]}" if f else "none"
    if places and places[0] == default and (not networks or networks[0] == default):
        return str(places[1] or "")
    if not places and not networks:
        return ""
    return f"#{one(places)}+{one(networks)}"


def cleared(role: str, source: str) -> str:
    """The LIKE pattern of the rows a source placed in `role`: #<id>:% (places), %+<id>:% (networks). The default
    source's rows stamped with a bare date are not met by it: HostBook.clear_places(bare=True) takes those too."""
    return f"#{source}:%" if role == "places" else f"%+{source}:%"


def checked(name: str, value, form: str) -> str:
    """A key's value as it is sent: keys.clean, then its maker's form (digits: 1 to 12 of them; token: letters, digits,
    _ and -, 8 to 128). ValueError in words that never hold the value, naming where to set it again."""
    try:
        out = keys_module.clean(value)
    except ValueError as e:
        raise ValueError(f"{name} cannot be sent: {e}; set it again {WHERE_KEYS}") from None
    if form == "digits" and not DIGITS.fullmatch(out):
        raise ValueError(f"{name} is a number of 1 to 12 digits, and what is kept is not; set it again {WHERE_KEYS}")
    if form != "digits" and not TOKEN.fullmatch(out):
        raise ValueError(f"{name} is 8 to 128 letters, digits, _ and - (no space, no other sign), and what is kept is "
                         f"not; set it again {WHERE_KEYS}")
    return out


def credentials(source: GeoSource, login) -> dict[str, str]:
    """The source's keys, read once through `login` (the asking person's, in the download's job alone) and checked.
    ValueError in words naming the key and where to set it, never its value; {} for a source that needs none."""
    if not source.keys:
        return {}
    if login is None:
        raise NotAsked()
    try:
        found = login.variables(list(source.keys))
    except Exception:  # noqa: BLE001 - a store that cannot be read: said, nothing sent
        found = None
    if not isinstance(found, Mapping):
        raise ValueError(f"your login store could not be read for {', '.join(source.keys)}: sign in again, then ask "
                         "again")
    out: dict[str, str] = {}
    for name, form in source.keys.items():
        value = found.get(name)
        if not value:
            raise ValueError(f"{name} is not set in your login store: add it {WHERE_KEYS}")
        out[name] = checked(name, value, form)
    return out


def _forms(value: str) -> set[str]:
    forms = {value, quote(value, safe=""), quote(value), quote_plus(value), repr(value)[1:-1],
             value.encode("unicode_escape").decode("ascii", "replace"), repr(value.encode("utf-8"))[2:-1],
             base64.b64encode(value.encode("utf-8")).decode("ascii")}
    return {f for f in forms if len(f) >= 4}


def redact(text, secrets) -> str:
    """`text` with every form of each secret taken out (as typed, percent-encoded with quote and quote_plus,
    repr-escaped, its base64, and the base64 of id:key for two of them), longest first."""
    values = [str(v) for v in (secrets.values() if isinstance(secrets, Mapping) else secrets or ()) if v]
    if not values:
        return str(text)
    forms: set[str] = set()
    for v in values:
        forms |= _forms(v)
        for w in values:
            if w != v:
                forms.add(base64.b64encode(f"{v}:{w}".encode("utf-8")).decode("ascii"))
    out = str(text)
    for f in sorted(forms, key=len, reverse=True):
        out = out.replace(f, "[hidden]")
    return out


def licence_of(file: GeoFile, built: str) -> dict:
    """What a file's acceptance is recorded with (apps.accept_licence's name and keywords): its pair, the file and its
    date as the title, the licence's own version and page, its words."""
    title = f"{file.title}, {built}" if built else file.title
    return {"name": file.licence.pair, "title": title, "version": file.licence.version, "url": file.licence.url,
            "words": file.licence.words}


def address(file: GeoFile, source: GeoSource, secrets: Mapping | None = None, *, checksum: bool = False) -> str:
    """The first address of a fixed-address file's download (or of its checksum), the source's key in its query when
    the source sends it so. Never said: the words name its host alone."""
    url = file.checksum_url if checksum else file.url
    if source.sends != "query":
        return url
    value = next(iter((secrets or {}).values()), "")
    return f"{url}?{source.query}={quote(value, safe='')}" if value else url
