"""What the resolver says (liminal_libs.dns), parsed from nslookup's two shapes (Windows, Linux)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from liminal_libs import dns

WINDOWS_A = ("Server:  UnKnown\nAddress:  192.168.1.1\n\nNon-authoritative answer:\nName:    liminal.hypokrites.me\n"
             "Addresses:  2606:2800:21f:cb07:6820:80da:af6b:8b2c\n          93.184.216.34\n")
LINUX_A = ("Server:\t\t127.0.0.53\nAddress:\t127.0.0.53#53\n\nNon-authoritative answer:\nName:\tliminal.hypokrites.me\n"
           "Address: 93.184.216.34\nName:\tliminal.hypokrites.me\nAddress: 2606:2800:21f:cb07:6820:80da:af6b:8b2c\n")
NONE = "Server:  UnKnown\nAddress:  192.168.1.1\n\n*** UnKnown can't find nowhere.hypokrites.me: Non-existent domain\n"
TXT = ("Server:  UnKnown\nAddress:  192.168.1.1\n\nNon-authoritative answer:\nhypokrites.me\ttext =\n\n\t\"v=spf1 include:_spf.protonmail.ch\" \" mx ~all\"\n"
       "hypokrites.me\ttext =\n\n\t\"some-verification=abc\"\n")


def test_addresses_mail_record_and_text_records_are_read_from_either_shape(monkeypatch):
    asked: list = []

    def run(args, **kw):
        asked.append(args)
        rtype, name = args[1].split("=", 1)[1], args[2]
        if "nowhere" in name:
            return SimpleNamespace(stdout=NONE)
        if rtype == "a":
            return SimpleNamespace(stdout=WINDOWS_A if len(asked) % 2 else LINUX_A)
        if rtype == "aaaa":
            return SimpleNamespace(stdout=NONE)
        if rtype == "txt":
            return SimpleNamespace(stdout=TXT)
        return SimpleNamespace(stdout="hypokrites.me\tMX preference = 10, mail exchanger = mail.protonmail.ch\n")
    monkeypatch.setattr(dns.subprocess, "run", run)
    assert dns.addresses("Liminal.Hypokrites.me.") == ["2606:2800:21f:cb07:6820:80da:af6b:8b2c", "93.184.216.34"]
    assert sorted(dns.addresses("liminal.hypokrites.me")) == ["2606:2800:21f:cb07:6820:80da:af6b:8b2c", "93.184.216.34"]  # the other shape
    assert dns.addresses("nowhere.hypokrites.me") == [] and dns.addresses("not a name") is None
    assert dns.mx_records("hypokrites.me") == ["mail.protonmail.ch"] and dns.mx_records("nowhere.hypokrites.me") == []
    assert dns.txt_records("hypokrites.me") == ["v=spf1 include:_spf.protonmail.ch mx ~all", "some-verification=abc"]
    assert dns.spf_record("hypokrites.me") == "v=spf1 include:_spf.protonmail.ch mx ~all" and dns.spf_record("nowhere.hypokrites.me") == ""
    assert dns.valid_name("A.B.") == "a.b" and dns.valid_name("no") == ""
    monkeypatch.setattr(dns.subprocess, "run", lambda args, **kw: (_ for _ in ()).throw(OSError("no nslookup")))
    assert dns.addresses("a.b") is None and dns.mx_records("a.b") is None and dns.txt_records("a.b") is None and dns.spf_record("a.b") is None


OPENDNS = "Server:  dns.opendns.com\nAddress:  208.67.222.222\n\nName:    myip.opendns.com\nAddress:  93.184.216.34\n\n"
OPENDNS6 = ("Server:  dns.opendns.com\nAddress:  2620:119:35::35\n\nName:    myip.opendns.com\n"
            "Address:  2606:2800:21f:cb07:6820:80da:af6b:8b2c\n\n")
GOOGLE = 'Server:  UnKnown\nAddress:  216.239.32.10\n\no-o.myaddr.l.google.com\ttext =\n\n\t"93.184.216.35"\n'
TIMED_OUT = "DNS request timed out.\n    timeout was 3 seconds.\nServer:  UnKnown\nAddress:  2620:119:35::35\n\nDNS request timed out.\n"


SERVERS = {4: (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"), ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google")),
           6: (("myip.opendns.com", "aaaa", "2620:119:35::35", "OpenDNS"), ("o-o.myaddr.l.google.com", "txt", "2001:4860:4802:32::a", "Google"))}


def test_this_networks_public_address_is_asked_of_the_servers_named_a_public_one_only(monkeypatch):
    asked, answers = [], {}

    def run(args, **kw):
        asked.append(args)
        assert kw.get("stdin") is not None and kw.get("timeout") == 15  # never waiting on a console, never for ever
        return SimpleNamespace(stdout=answers.get((args[-2], args[-1]), TIMED_OUT))
    monkeypatch.setattr(dns.subprocess, "run", run)
    answers[("myip.opendns.com", "208.67.222.222")] = OPENDNS
    assert dns.public_address(4, SERVERS[4]) == ("93.184.216.34", "OpenDNS")
    assert asked == [["nslookup", "-type=a", "-timeout=3", "-retry=1", "myip.opendns.com", "208.67.222.222"]]  # asked directly
    answers[("myip.opendns.com", "208.67.222.222")] = OPENDNS.replace("93.184.216.34", "10.0.0.5")  # a private address: not it
    answers[("o-o.myaddr.l.google.com", "216.239.32.10")] = GOOGLE
    assert dns.public_address(4, SERVERS[4]) == ("93.184.216.35", "Google") and asked[-1][1] == "-type=txt"
    answers[("myip.opendns.com", "2620:119:35::35")] = OPENDNS6
    assert dns.public_address(6, SERVERS[6]) == ("2606:2800:21f:cb07:6820:80da:af6b:8b2c", "OpenDNS")
    answers.clear()  # no IPv6 route: every server timed out
    assert dns.public_address(6, SERVERS[6]) == (None, "neither OpenDNS nor Google answered with a public IPv6 address")
    answers[("myip.opendns.com", "208.67.222.222")] = OPENDNS
    assert dns.public_address(6, SERVERS[4])[0] is None  # an IPv4 answer is no IPv6 address
    assert dns.public_address(4, SERVERS[4][:1]) == ("93.184.216.34", "OpenDNS") and dns.public_address(4, ()) == (None, "no server to ask")
    with pytest.raises(ValueError, match="4 or 6"):
        dns.public_address(5, SERVERS[4])
    monkeypatch.setattr(dns.subprocess, "run", lambda args, **kw: (_ for _ in ()).throw(OSError("no nslookup")))
    assert dns.public_address(4, SERVERS[4][1:]) == (None, "Google did not answer with a public IPv4 address")
