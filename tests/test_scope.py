"""What a login is tied to (liminal_libs.apps.scope): the file, a local folder or a domain as a URL, where
the users live, the mail settings it gives, and how every app finds the same file."""
from __future__ import annotations

from pathlib import Path

import pytest

from liminal_libs import layout
from liminal_libs.apps import Scope
from liminal_libs.apps import scope as scope_mod


def test_a_local_login_is_a_project_folder_as_a_file_url(tmp_path):
    s = Scope.local(tmp_path / "project", title="My project", port=8801)
    assert s.kind == "local" and s.url.startswith("file:///") and s.root == (tmp_path / "project").resolve() and s.domain == ""
    assert s.name == "project" and s.label == f"local to {s.root}" and s.describe()["members"] == "local" and s.describe()["mailServer"] == ""
    assert s.mail_variables() == {}  # a local login sends no email
    # the users live inside the folder: its store/data/login when it has a store/data, else .liminal/login
    assert s.data_dir() == s.root / ".liminal" / "login"
    (tmp_path / "project" / "store" / "data").mkdir(parents=True)
    assert s.data_dir() == s.root / "store" / "data" / "login"
    assert Scope(s.url, data=tmp_path / "elsewhere").data_dir() == tmp_path / "elsewhere"
    # the file round trip keeps it all
    back = Scope.parse(s.text(), tmp_path / "liminal-login.cfg")
    assert (back.url, back.title, back.port, back.kind, back.path) == (s.url, "My project", 8801, "local", tmp_path / "liminal-login.cfg")
    assert Scope.read(s.write(tmp_path / "liminal-login.cfg")).root == s.root
    # a login names no app it serves (1.43.0: the app that inherits one says so): the file says none, an old file's
    # `serves` line is read past
    assert "serves" not in s.text() and "serves" not in s.describe()
    old = Scope.parse(f"[login]\nscope = {s.url}\nserves = charts, integrator\n")
    assert old.url == s.url and not hasattr(old, "serves")


def test_the_users_of_another_login_are_reached_at_its_domain_over_https(tmp_path):
    """1.45.0 (the user, 2026-11-10: "make sure every login instance has a database, it's location can be remote"; "login
    apps can connect to remote login apps"; "remote users are like email format user@remote.domain.tld"; "IPC turns in
    to encrypted internet comms"): every login keeps its own users; one of another login signs in as name@their.domain,
    whose login app answers at https://their.domain unless the file's [remotes] names it (assigned here); over https,
    http only to this machine (a test)."""
    from liminal_libs.apps import remote_url, remotes_from

    assert remote_url("remote.tld") == "https://remote.tld" and remote_url("https://Remote.tld:8443/login/") == "https://Remote.tld:8443/login"
    assert remote_url("http://127.0.0.1:8799") == "http://127.0.0.1:8799" and remote_url("http://localhost:8799/") == "http://localhost:8799"
    for bad in ("http://remote.tld", "ftp://remote.tld", "https://", ""):
        with pytest.raises(ValueError):
            remote_url(bad)
    assert remotes_from("Remote.test=http://127.0.0.1:8799; other.tld = https://login.other.tld") == {
        "remote.test": "http://127.0.0.1:8799", "other.tld": "https://login.other.tld"}
    local = Scope.local(tmp_path)
    assert local.remotes == {} and local.remote_url("Remote.TLD.") == "https://remote.tld" and "[remotes]" in local.text()
    named = Scope.parse(f"[login]\nscope = {local.url}\n\n[remotes]\nremote.tld = https://login.remote.tld:8443\n")
    assert named.remote_url("remote.tld") == "https://login.remote.tld:8443" and named.remote_url("other.tld") == "https://other.tld"
    assert named.describe()["remotes"] == {"remote.tld": "https://login.remote.tld:8443"}
    assert Scope.parse(named.text()).remotes == named.remotes
    with pytest.raises(ValueError, match="https"):
        Scope.parse(f"[login]\nscope = {local.url}\n\n[remotes]\nremote.tld = http://remote.tld\n")


def test_a_domain_login_is_the_domains_users_with_its_own_mail_record_unless_a_server_is_named(tmp_path):
    s = Scope.for_domain("Hypokrites.me.")
    assert s.kind == "domain" and s.url == "https://hypokrites.me" and s.domain == "hypokrites.me" and s.name == "hypokrites.me" and s.label == "@hypokrites.me"
    assert s.members == "domain" and s.root is None and s.data_dir(tmp_path) == tmp_path  # the app adds the domain's folder
    assert s.mail_variables() == {"LIMINAL_SMTP_HOST": "direct", "LIMINAL_SMTP_FROM": "Liminal <admin@hypokrites.me>"}
    assert s.admin_address == "admin@hypokrites.me" and s.admin_host == "hypokrites.me" and s.imap_variables() == {}
    assert s.describe()["mailServer"] == "the domain's own mail record"
    named = Scope.parse("[login]\nscope = hypokrites.me\nmembers = any\n\n[mail]\nhost = 127.0.0.1\nport = 1025\nuser = me@hypokrites.me\nfrom = Liminal <login@hypokrites.me>\n")
    assert named.url == "https://hypokrites.me" and named.members == "any" and named.describe()["mailServer"] == "127.0.0.1"
    assert named.mail_variables() == {"LIMINAL_SMTP_HOST": "127.0.0.1", "LIMINAL_SMTP_PORT": "1025", "LIMINAL_SMTP_USER": "me@hypokrites.me",
                                      "LIMINAL_SMTP_FROM": "Liminal <login@hypokrites.me>"}
    assert "members = any" in named.text() and "host = 127.0.0.1" in named.text() and "password" in named.text()
    # the login's own account: admin@ a host under the domain, valid in DNS; the admin mailbox for the checks
    own = Scope.parse("[login]\nscope = https://hypokrites.me\nadmin = Admin@liminal.hypokrites.me\n\n[imap]\nhost = mail.liminal.hypokrites.me\nport = 993\n")
    assert own.admin_address == "admin@liminal.hypokrites.me" and own.admin_host == "liminal.hypokrites.me"
    assert own.mail_variables()["LIMINAL_SMTP_FROM"] == "Liminal <admin@liminal.hypokrites.me>"
    assert own.imap_variables() == {"LIMINAL_IMAP_HOST": "mail.liminal.hypokrites.me", "LIMINAL_IMAP_PORT": "993", "LIMINAL_IMAP_USER": "admin@liminal.hypokrites.me"}
    assert own.describe()["admin"] == "admin@liminal.hypokrites.me" and own.describe()["mailbox"] == "mail.liminal.hypokrites.me"
    back = Scope.parse(own.text())
    assert back.admin == "admin@liminal.hypokrites.me" and back.imap["host"] == "mail.liminal.hypokrites.me" and "[imap]" in own.text()
    with pytest.raises(ValueError):
        Scope.parse("[login]\nscope = https://hypokrites.me\nadmin = admin@elsewhere.test\n")
    # the mail server as a container the file declares: the image, its environment with the case kept
    boxed = Scope.parse("[login]\nScope = https://hypokrites.me\nadmin = admin@liminal.hypokrites.me\n\n[server]\nimage = foxcpp/maddy:0.8\n"
                        "ports = 25:25, 587:587; 993:993\nvolumes = ./mail:/data, certs:/certs\nenv_MADDY_DOMAIN = hypokrites.me\ncontext = vps\n")
    svc = boxed.service(tmp_path)
    assert svc.name == "liminal-mail-hypokrites-me" and svc.image == "foxcpp/maddy:0.8" and svc.hostname == "liminal.hypokrites.me"
    assert svc.ports == ("25:25", "587:587", "993:993") and svc.env == {"MADDY_DOMAIN": "hypokrites.me"} and svc.labels == {"liminal.login": "hypokrites.me"}
    assert svc.volumes == (f"{(tmp_path / 'mail').as_posix()}:/data", "certs:/certs")
    assert boxed.docker(env={}).where == "context vps" and boxed.describe()["server"] == "foxcpp/maddy:0.8"
    # an instance by name: a machine plugin's engine (wsl-ubuntu, say), asked of the registry
    from liminal_libs import docker as docker_mod

    named = Scope.parse("[login]\nscope = https://hypokrites.me\n\n[server]\nimage = foxcpp/maddy:0.8\ninstance = wsl-ubuntu\n")
    seen = []
    monkeypatch_instance = lambda name, **kw: seen.append(name) or docker_mod.Docker(command="wsl -d Ubuntu docker", env={}, **kw)  # noqa: E731
    import unittest.mock as mock

    with mock.patch.object(docker_mod, "instance", monkeypatch_instance):
        assert named.docker().argv == ["wsl", "-d", "Ubuntu", "docker"] and seen == ["wsl-ubuntu"]
    again = Scope.parse(boxed.text())
    assert again.server["image"] == "foxcpp/maddy:0.8" and again.server["env_MADDY_DOMAIN"] == "hypokrites.me" and "[server]" in boxed.text()
    assert s.service() is None and Scope.local(tmp_path).service() is None
    assert Scope.local(tmp_path).admin_address == "" and Scope.local(tmp_path).admin_host == ""
    with pytest.raises(ValueError):
        Scope.parse("[login]\nscope = https://hypokrites.me\nmembers = some\n")
    with pytest.raises(ValueError):
        Scope.parse("[other]\nx = 1\n")
    with pytest.raises(ValueError):
        Scope.parse("[login]\nscope = https:///\n")


def test_every_app_finds_the_same_file(tmp_path, monkeypatch):
    monkeypatch.setattr(layout, "home", lambda: None)
    monkeypatch.setattr(layout, "data_dir", lambda: tmp_path / "data")
    monkeypatch.delenv(scope_mod.CFG_VAR, raising=False)
    assert Scope.find(tmp_path / "deep" / "er") is None
    project = tmp_path / "project"
    (project / "sub" / "dir").mkdir(parents=True)
    Scope.local(project, title="P").write(project / "liminal-login.cfg")
    found = Scope.find(project / "sub" / "dir")  # from a folder inside the project: its file
    assert found is not None and found.title == "P" and found.path == project / "liminal-login.cfg"
    (tmp_path / "data" / "login").mkdir(parents=True)
    Scope.for_domain("example.test").write(tmp_path / "data" / "login" / "liminal-login.cfg")
    assert Scope.find(tmp_path / "deep").domain == "example.test"  # else the data folder's
    monkeypatch.setenv(scope_mod.CFG_VAR, str(project / "liminal-login.cfg"))
    assert Scope.find(tmp_path / "deep").title == "P"  # LIMINAL_LOGIN_CFG names it outright
    monkeypatch.setattr(layout, "home", lambda: project)
    monkeypatch.setenv(scope_mod.CFG_VAR, "")
    assert Scope.find(tmp_path / "deep").title == "P"  # the workspace's
