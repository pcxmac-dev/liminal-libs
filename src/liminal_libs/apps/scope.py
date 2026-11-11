"""What a login is tied to, and what every app reads to know which login it binds to (the user,
2026-11-06: "have like a setup.cfg for the login, and then like other web apps use that cfg file to decide
the domain/scope of the login"; "lets have login apps tied to domains (with email server) or local
(file://project/folder)"; "use a url regardless, file if local, domain w/ email server in mail record
(lookup) or specified if none in the domain lookup"): `liminal-login.cfg`, an INI file whose [login] scope
is a URL. `file:///...` is a project folder: a local login, no email and no sign-up (the first user is made on
the page or at the command line, the next by a signed-in user). `https://<domain>` is the domain's users:
their codes go through the domain's own mail server, the one its mail record (MX) names, unless the [mail]
section names a server to send through. `Scope.find` reads the file every app looks for the same way:
LIMINAL_LOGIN_CFG, else `liminal-login.cfg` in the workspace, in the working folder or one above it, else in
the data folder's login/."""
from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urlsplit
from urllib.request import url2pathname

from .. import layout

FILE_NAME = "liminal-login.cfg"
CFG_VAR = "LIMINAL_LOGIN_CFG"
MAIL_KEYS = ("host", "port", "security", "user", "from", "helo", "dkim_key", "dkim_selector", "dkim_domain")
IMAP_KEYS = ("host", "port", "security", "user")  # the admin mailbox, read for the checks
SERVER_KEYS = ("image", "name", "instance", "context", "host", "hostname", "ports", "volumes", "restart", "command")  # the mail server container
MEMBERS = ("domain", "any")
_DOMAIN = r"[a-z0-9-]+(\.[a-z0-9-]+)+"
REMOTES_VAR = "LIMINAL_LOGIN_REMOTES"  # `host=url;host=url`: where remote logins answer, over the file's [remotes] (1.45.0)
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def remote_url(value) -> str:
    """The address of a remote login app (1.45.0; the user, 2026-11-10: "make sure every login instance has a database,
    it's location can be remote"; "so domain should be local or some domain remote.tld"; "login apps can connect to
    remote login apps"; "and shift context to the remote execution"; "remote users are like email format
    user@remote.domain.tld"): a domain alone is its https address; a URL is kept as given, over https (http only to
    this machine, for a test). ValueError for anything else."""
    raw = str(value or "").strip()
    url = raw if "://" in raw else f"https://{raw}"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"a remote login is a domain (remote.tld) or its address, not {raw!r}")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK:
        raise ValueError(f"a remote login is reached over https (http only to this machine): {raw!r}")
    return f"{parts.scheme}://{parts.netloc}{parts.path}".rstrip("/")


def remotes_from(text) -> dict[str, str]:
    """`host=url;host=url` (REMOTES_VAR) as a map, each address checked (remote_url)."""
    out: dict[str, str] = {}
    for part in str(text or "").replace(",", ";").split(";"):
        host, sep, url = part.partition("=")
        if sep and host.strip():
            out[host.strip().lower().strip(".")] = remote_url(url)
    return out


@dataclass(frozen=True)
class Scope:
    url: str
    title: str = ""
    # no `serves` (1.43.0): a login names no app it serves; the app that inherits one says so when it starts it
    # (apps.login.inherited_by). A file's old `serves = ...` line is read past.
    port: int | None = None
    members: str = "domain"  # a domain's login: "domain" (addresses at the domain only) or "any"
    data: Path | None = None  # where the users' folders live; None: by the kind (data_dir)
    mail: dict = field(default_factory=dict)  # the [mail] section: host, port, security, user, from, helo, dkim_*
    imap: dict = field(default_factory=dict)  # the [imap] section: the admin mailbox (host, port, security, user)
    server: dict = field(default_factory=dict)  # the [server] section: the mail server container (docker.py), env_* its environment
    admin: str = ""  # a domain's login's own account, admin@<a host under the domain> (the user, 2026-11-06)
    path: Path | None = None  # the file read, when one was
    remotes: dict = field(default_factory=dict)  # [remotes]: a domain -> where its login app answers (1.45.0)

    def remote_url(self, host: str) -> str:
        """Where the login app of `host` answers, for its users (name@host): the file's [remotes] says so (assigned
        here), else the domain's own address, https://<the domain> (assigned there)."""
        host = str(host or "").strip().lower().strip(".")
        return remote_url(self.remotes.get(host) or host)

    @property
    def kind(self) -> str:
        return "local" if self.url.lower().startswith("file:") else "domain"

    @property
    def root(self) -> Path | None:
        """A local login's project folder (the file URL as a path)."""
        if self.kind != "local":
            return None
        parts = urlparse(self.url)
        raw = parts.path if not parts.netloc or parts.netloc == "localhost" else f"//{parts.netloc}{parts.path}"
        return Path(url2pathname(raw))

    @property
    def domain(self) -> str:
        if self.kind != "domain":
            return ""
        return (urlparse(self.url).hostname or "").lower().strip(".")

    @property
    def admin_address(self) -> str:
        """The login's own account: `admin`, else admin@<domain> for a domain's login, "" for a local one."""
        if self.kind != "domain":
            return ""
        return self.admin.strip().lower() or f"admin@{self.domain}"

    @property
    def admin_host(self) -> str:
        """The host of the admin address (liminal.domain.tld, say): what must be valid in DNS."""
        return self.admin_address.rpartition("@")[2]

    @property
    def name(self) -> str:
        """The scope's short name: the domain, or the project folder's name."""
        if self.kind == "domain":
            return self.domain
        return self.root.name if self.root is not None and self.root.name else "local"

    @property
    def label(self) -> str:
        """For a page: `@hypokrites.me`, or `local to C:\\...\\liminal`."""
        return f"@{self.domain}" if self.kind == "domain" else f"local to {self.root}"

    def data_dir(self, default: Path | None = None) -> Path:
        """Where the users' folders live: `data` when set; a local login's project folder (its
        store/data/login when it has a store/data, else .liminal/login inside it); a domain's `default` (the
        data folder's login/), where the app keeps a folder per domain."""
        if self.data is not None:
            return self.data
        if self.kind == "local" and self.root is not None:
            store = self.root / "store" / "data"
            return store / "login" if store.is_dir() else self.root / ".liminal" / "login"
        return default if default is not None else layout.data_dir() / "login"

    def mail_variables(self) -> dict[str, str]:
        """The [mail] section as the mailer's variables (LIMINAL_SMTP_*). A domain's login with no server
        named sends straight to each address's own mail server (direct), from login@<domain>."""
        out = {f"LIMINAL_SMTP_{k.upper()}": str(v).strip() for k, v in self.mail.items() if k in MAIL_KEYS and str(v).strip()}
        if self.kind == "domain":
            out.setdefault("LIMINAL_SMTP_HOST", "direct")
            out.setdefault("LIMINAL_SMTP_FROM", f"Liminal <{self.admin_address}>")
        return out

    def service(self, data: Path | None = None):
        """The mail server container the file declares ([server] image = ...; docker.Service), or None: its
        name `liminal-mail-<domain>` unless said, its hostname the admin host, `./x:/y` volumes under the
        login's data folder, `env_NAME = value` keys its environment."""
        from ..docker import Service

        sec = self.server
        image = (sec.get("image") or "").strip()
        if not image:
            return None
        base = Path(data) if data is not None else self.data_dir()
        volumes = []
        for v in (sec.get("volumes") or "").replace(";", ",").split(","):
            v = v.strip()
            if not v:
                continue
            if v.startswith("./"):  # under the login's data folder
                host_path, _, inside = v[2:].partition(":")
                v = f"{(base / host_path).as_posix()}:{inside}" if inside else (base / host_path).as_posix()
            volumes.append(v)
        import shlex

        return Service(name=(sec.get("name") or f"liminal-mail-{self.name.replace('.', '-')}").strip(), image=image,
                       ports=tuple(p.strip() for p in (sec.get("ports") or "").replace(";", ",").split(",") if p.strip()),
                       env={k[4:]: v for k, v in sec.items() if k.startswith("env_") and k[4:]},
                       volumes=tuple(volumes), hostname=(sec.get("hostname") or self.admin_host).strip(),
                       restart=(sec.get("restart") or "unless-stopped").strip(), command=tuple(shlex.split(sec.get("command") or "")),
                       labels={"liminal.login": self.name})

    def docker(self, **kw):
        """The Docker the server container runs on: the [server] instance by name (docker.instance: local, a
        context, a host, a machine plugin's such as wsl-ubuntu), else the [server] context or host, else the
        environment's (LIMINAL_DOCKER_CONTEXT, LIMINAL_DOCKER_HOST), else this machine."""
        from ..docker import Docker, instance

        named = (self.server.get("instance") or "").strip()
        if named:
            return instance(named, **kw)
        return Docker(context=self.server.get("context"), host=self.server.get("host"), **kw)

    def imap_variables(self) -> dict[str, str]:
        """The [imap] section as the mailbox reader's variables (LIMINAL_IMAP_*); the user is the admin
        address unless said."""
        out = {f"LIMINAL_IMAP_{k.upper()}": str(v).strip() for k, v in self.imap.items() if k in IMAP_KEYS and str(v).strip()}
        if out.get("LIMINAL_IMAP_HOST") and self.kind == "domain":
            out.setdefault("LIMINAL_IMAP_USER", self.admin_address)
        return out

    def describe(self) -> dict:
        return {"url": self.url, "kind": self.kind, "name": self.name, "label": self.label, "title": self.title or self.name,
                "members": self.members if self.kind == "domain" else "local",
                "root": str(self.root) if self.root is not None else None, "domain": self.domain,
                "mailServer": (self.mail.get("host") or "the domain's own mail record") if self.kind == "domain" else "",
                "admin": self.admin_address, "adminHost": self.admin_host, "mailbox": self.imap.get("host", ""),
                "server": self.server.get("image", ""),
                "remotes": dict(self.remotes),
                "path": str(self.path) if self.path is not None else None}

    @classmethod
    def local(cls, root: Path, **kw) -> "Scope":
        return cls(Path(root).resolve().as_uri(), **kw)

    @classmethod
    def for_domain(cls, domain: str, **kw) -> "Scope":
        return cls(f"https://{domain.strip().lower().strip('.')}", **kw)

    @classmethod
    def parse(cls, text: str, path: Path | None = None) -> "Scope":
        cfg = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";", "#"))
        cfg.optionxform = str  # the case of a key kept: a container's env_NAME
        cfg.read_string(text)
        where = path or FILE_NAME
        login = {k.strip().lower(): v for k, v in cfg["login"].items()} if "login" in cfg else {}
        if not login.get("scope", "").strip():
            raise ValueError(f"{where}: a [login] section with `scope = file:///... or https://<domain>` is needed")
        url = login["scope"].strip()
        if "://" not in url and not url.lower().startswith("file:"):
            url = f"https://{url}"
        if not url.lower().startswith("file:"):  # a domain: its name alone, lowercased
            url = f"https://{(urlparse(url).hostname or '').lower().strip('.')}"
        port = login.get("port", "").strip()
        data = login.get("data", "").strip()
        try:
            remotes = {k.strip().lower().strip("."): remote_url(v) for k, v in cfg["remotes"].items()} if "remotes" in cfg else {}
        except ValueError as e:
            raise ValueError(f"{where}: [remotes]: {e}") from None
        members = (login.get("members", "domain").strip().lower()) or "domain"
        if members not in MEMBERS:
            raise ValueError(f"{where}: members is domain or any, not {members!r}")
        mail = {k.strip().lower(): v.strip() for k, v in cfg["mail"].items()} if "mail" in cfg else {}
        imap = {k.strip().lower(): v.strip() for k, v in cfg["imap"].items()} if "imap" in cfg else {}
        server = {(k.strip() if k.strip().startswith("env_") else k.strip().lower()): v.strip() for k, v in cfg["server"].items()} if "server" in cfg else {}
        scope = cls(url, title=login.get("title", "").strip(), port=int(port) if port.isdecimal() else None,
                    members=members, data=Path(data).expanduser() if data else None, mail=mail, imap=imap, server=server,
                    admin=login.get("admin", "").strip().lower(), path=Path(path) if path else None, remotes=remotes)
        if scope.kind == "domain" and not scope.domain:
            raise ValueError(f"{where}: the scope names no domain: {url}")
        if scope.kind == "domain":
            host = scope.admin_host
            if "@" not in scope.admin_address or not (host == scope.domain or host.endswith("." + scope.domain)):
                raise ValueError(f"{where}: admin is an address at the domain or a host under it (admin@liminal.{scope.domain}), not {scope.admin!r}")
        return scope

    @classmethod
    def read(cls, path: Path) -> "Scope":
        path = Path(path)
        return cls.parse(path.read_text(encoding="utf-8"), path)

    @classmethod
    def find(cls, start: Path | None = None, env=None) -> "Scope | None":
        """The file every app reads: LIMINAL_LOGIN_CFG, else liminal-login.cfg in the workspace, in `start`
        (the working folder) or one above it, else in the data folder's login/; None when there is none."""
        env = os.environ if env is None else env
        named = (env.get(CFG_VAR) or "").strip()
        if named:
            return cls.read(Path(named).expanduser())
        places: list[Path] = []
        home = layout.home()
        if home is not None:
            places.append(home / FILE_NAME)
        here = Path(start) if start is not None else Path.cwd()
        places.extend(p / FILE_NAME for p in (here, *here.parents))
        places.append(layout.data_dir() / "login" / FILE_NAME)
        for p in places:
            if p.is_file():
                return cls.read(p)
        return None

    def text(self) -> str:
        """The file's text."""
        lines = ["[login]", f"; what this login is tied to: file:///a/project/folder (local: no email, no sign-up) or https://<your-domain>",
                 f"scope = {self.url}"]
        if self.title:
            lines.append(f"title = {self.title}")
        if self.port:
            lines.append(f"port = {self.port}")
        if self.kind == "domain":
            lines.append("; members: domain (addresses at the domain only) or any (everyone)")
            lines.append(f"members = {self.members}")
            lines.append("; the login's own account, at the domain or a host under it that is valid in DNS; the codes come from it")
            lines.append(f"admin = {self.admin_address}")
        if self.data is not None:
            lines.append(f"data = {self.data}")
        lines += ["", "[mail]"]
        if self.kind == "domain":
            lines.append("; the email server the codes go through; nothing here: the domain's own mail record (MX) is looked up")
        else:
            lines.append("; a local login sends no email")
        for k in MAIL_KEYS:
            v = self.mail.get(k, "")
            lines.append(f"{k} = {v}" if v else f"; {k} =")
        lines.append("; the password: `liminal-login mail setup` keeps it in Windows Credential Manager, never here")
        if self.kind == "domain":
            lines += ["", "[imap]", "; the admin mailbox, read by `liminal-login mail check` to see its own test message arrive"]
            for k in IMAP_KEYS:
                v = self.imap.get(k, "")
                lines.append(f"{k} = {v}" if v else f"; {k} =")
            lines.append("; its password: `liminal-login mail setup` keeps it in Windows Credential Manager too")
            lines += ["", "[server]", "; the mail server as a container (liminal_libs.docker; `liminal-login server up`): the image, on this",
                      "; machine's Docker or a context's (a VPS: `docker context create vps --docker host=ssh://user@vps`);",
                      "; it carries everything beyond the local domain; env_NAME = value sets its environment"]
            for k in SERVER_KEYS:
                v = self.server.get(k, "")
                lines.append(f"{k} = {v}" if v else f"; {k} =")
            for k, v in self.server.items():
                if k.startswith("env_"):
                    lines.append(f"{k} = {v}")
        lines += ["", "[remotes]", "; the users of other logins sign in here as name@their.domain: their login app does the work, over",
                  "; https. Each answers at https://<their domain> unless named here: <their domain> = https://<their login's address>"]
        lines += [f"{k} = {v}" for k, v in self.remotes.items()]
        return "\n".join(lines) + "\n"

    def write(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.text(), encoding="utf-8")
        return path
