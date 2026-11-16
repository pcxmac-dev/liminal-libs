"""Names for the addresses this machine talks to (liminal_libs.names), for the firewalls' Filter tab (the user,
2026-11-14: "classifying traffic as potential advert/monitoring sites that track users, etc"): DNS answers read with
their compression pointers, each address named with the name asked for and every CNAME on the way (a tracker behind a
first party's name still seen) and nothing off that way, lengths never trusted, loops and forward pointers refused,
what is no bytes never taken for a size; the server_name of a real ClientHello (made by this machine's own TLS library,
in memory), of Chromium-shaped ones in any extension order, and of malformed ones; a NameBook believing only answers
to this machine's own questions and ClientHellos it sent, keeping the latest names, capped, the most recent first.
Nothing is looked up and no socket is opened."""
from __future__ import annotations

import random
import socket
import ssl
import struct
import time

import pytest

from liminal_libs import capture, names
from liminal_libs.capture import Packet
from liminal_libs.names import NameBook, parse_dns, parse_sni

A, CNAME, AAAA, TXT = 1, 5, 28, 16
LAN, ROUTER = "192.168.1.20", "192.168.1.1"
EDGE, EDGE2, EDGE6 = "81.2.69.160", "81.2.69.161", "2a02:1810:4d0a::10"


# -- DNS messages written by hand ------------------------------------------------------------------------------------
def labels(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode("latin-1") for p in name.split(".") if p) + b"\x00"


def pointer(offset: int) -> bytes:
    return struct.pack("!H", 0xC000 | offset)


class Message:
    """A DNS message written by hand: where each part lands is known, for compression pointers to it."""

    def __init__(self, flags: int = 0x8180, ident: int = 0x1234):
        self.flags, self.ident, self.body, self.questions, self.answers = flags, ident, bytearray(), 0, 0

    @property
    def at(self) -> int:
        return 12 + len(self.body)

    def question(self, name: bytes, qtype: int = A) -> int:
        where = self.at
        self.body += name + struct.pack("!HH", qtype, 1)
        self.questions += 1
        return where

    def answer(self, owner: bytes, rtype: int, rdata: bytes, ttl: int = 300, rclass: int = 1, size=None) -> int:
        """The record added; where its data begins."""
        self.body += owner + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata) if size is None else size)
        where = self.at
        self.body += rdata
        self.answers += 1
        return where

    def raw(self, data: bytes) -> int:
        where = self.at
        self.body += data
        return where

    def bytes(self, questions=None, answers=None) -> bytes:
        return struct.pack("!HHHHHH", self.ident, self.flags, self.questions if questions is None else questions,
                           self.answers if answers is None else answers, 0, 0) + bytes(self.body)


def chain() -> bytes:
    """www.shop.example, a first party's name, behind which a tracker's edge answers: two CNAMEs, then two A records
    and an AAAA, every name after the question compressed."""
    m = Message()
    q = m.question(labels("WWW.Shop.Example"))
    first = m.answer(pointer(q), CNAME, labels("shop.tracker.example"), ttl=300)
    second = m.answer(pointer(first), CNAME, b"\x04edge" + pointer(first + 5), ttl=60)  # edge + "tracker.example"
    m.answer(pointer(second), A, socket.inet_aton(EDGE), ttl=120)
    m.answer(pointer(second), A, socket.inet_aton(EDGE2), ttl=120)
    m.answer(pointer(second), AAAA, socket.inet_pton(socket.AF_INET6, EDGE6), ttl=30)
    return m.bytes()


def test_an_answer_names_each_address_with_the_name_asked_for_and_every_cname_on_the_way():
    found = parse_dns(chain())
    assert found == [("www.shop.example", EDGE, 60), ("shop.tracker.example", EDGE, 60), ("edge.tracker.example", EDGE, 120),
                     ("www.shop.example", EDGE2, 60), ("shop.tracker.example", EDGE2, 60), ("edge.tracker.example", EDGE2, 120),
                     ("www.shop.example", EDGE6, 30), ("shop.tracker.example", EDGE6, 30), ("edge.tracker.example", EDGE6, 30)]
    framed = struct.pack("!H", len(chain())) + chain()
    assert parse_dns(framed, tcp=True) == found  # over TCP: its two length bytes first
    assert parse_dns(framed + b"\x00" * 9, tcp=True) == found  # what follows the message is not read
    assert parse_dns(b"\x01", tcp=True) == [] and parse_dns(framed[:40], tcp=True) == []

    m = Message()
    q = m.question(labels("cdn.example"))
    m.answer(pointer(q), A, socket.inet_aton(EDGE), ttl=0x80000001)  # a TTL with its top bit set counts as 0
    m.answer(labels("other.example"), A, socket.inet_aton(EDGE2), ttl=5)  # on no question's way: not taken
    m.answer(pointer(q), A, b"\x01\x02\x03", ttl=5)  # an A record of three bytes: no address
    m.answer(pointer(q), AAAA, b"\x00" * 4, ttl=5)
    m.answer(pointer(q), TXT, b"\x05hello", ttl=5)  # a kind of record no address is in
    m.answer(pointer(q), A, socket.inet_aton("81.2.69.162"), ttl=5, rclass=0x8001)  # mDNS's cache-flush bit: still IN
    m.answer(pointer(q), A, socket.inet_aton("81.2.69.163"), ttl=5, rclass=3)  # CHAOS: not the internet's
    assert parse_dns(m.bytes()) == [("cdn.example", EDGE, 0), ("cdn.example", "81.2.69.162", 5)]


def test_only_what_is_on_the_questions_way_is_taken():
    """(Review F4) A resolver answers with the name asked for and the CNAMEs from it; a record owned by any other
    name is not believed (an answer could otherwise name any address after anything)."""
    m = Message()
    q = m.question(labels("shop.example"))
    m.answer(labels("windowsupdate.microsoft.com"), A, socket.inet_aton("203.0.113.66"))  # someone else's name
    m.answer(pointer(q), CNAME, labels("edge.example"), ttl=40)
    m.answer(labels("edge.example"), A, socket.inet_aton(EDGE), ttl=30)
    m.answer(labels("aside.example"), CNAME, labels("edge.example"))  # leads to the address, but not from the question
    assert parse_dns(m.bytes()) == [("shop.example", EDGE, 30), ("edge.example", EDGE, 30)]
    lone = Message()  # no question at all: nothing is on its way
    lone.answer(labels("shop.example"), A, socket.inet_aton(EDGE))
    assert parse_dns(lone.bytes()) == []
    two = Message()  # two questions: each one's way
    a, b = two.question(labels("a.example")), two.question(labels("b.example"), AAAA)
    two.answer(pointer(a), A, socket.inet_aton(EDGE))
    two.answer(pointer(b), AAAA, socket.inet_pton(socket.AF_INET6, EDGE6))
    assert parse_dns(two.bytes()) == [("a.example", EDGE, 300), ("b.example", EDGE6, 300)]


def test_cnames_that_loop_or_branch_still_end():
    m = Message()
    q = m.question(labels("a.example"))
    m.answer(pointer(q), CNAME, labels("b.example"), ttl=50)
    m.answer(labels("b.example"), CNAME, labels("a.example"), ttl=40)  # back to the first: a loop
    m.answer(labels("c.example"), CNAME, labels("b.example"), ttl=30)  # another name leading the same way: not asked
    m.answer(labels("b.example"), A, socket.inet_aton(EDGE), ttl=20)
    assert parse_dns(m.bytes()) == [("a.example", EDGE, 20), ("b.example", EDGE, 20)]  # the address's own name last
    long = Message()  # a chain longer than MAX_CHAIN: the names past it are not followed
    q = long.question(labels("n0.example"))
    for i in range(names.MAX_CHAIN + 3):
        long.answer(labels(f"n{i}.example"), CNAME, labels(f"n{i + 1}.example"))
    long.answer(labels(f"n{names.MAX_CHAIN + 3}.example"), A, socket.inet_aton(EDGE))
    long.answer(labels(f"n{names.MAX_CHAIN - 1}.example"), A, socket.inet_aton(EDGE2))
    assert [n for n, _, _ in parse_dns(long.bytes())] == [f"n{i}.example" for i in range(names.MAX_CHAIN)]


def test_a_question_or_an_odd_message_names_nothing():
    q = Message(flags=0x0100)  # a question (recursion desired), with an answer section filled in all the same
    at = q.question(labels("shop.example"))
    q.answer(pointer(at), A, socket.inet_aton(EDGE))
    assert parse_dns(q.bytes()) == []
    status = Message(flags=0x8180 | 0x1000)  # opcode 2: not a standard query's answer
    status.answer(labels("shop.example"), A, socket.inet_aton(EDGE))
    assert parse_dns(status.bytes()) == []
    many = Message()
    for i in range(5):
        many.question(labels(f"q{i}.example"))
    assert parse_dns(many.bytes()) == []  # more questions than any resolver asks
    assert parse_dns(chain()[:11]) == [] and parse_dns(b"") == [] and parse_dns(None) == []
    assert parse_dns("not bytes") == [] and parse_dns(12) == []
    assert parse_dns(bytearray(chain())) == parse_dns(memoryview(chain())) == parse_dns(chain()) != []
    nx = Message(flags=0x8183)  # NXDOMAIN: no answer
    nx.question(labels("nowhere.example"))
    assert parse_dns(nx.bytes()) == []


def test_what_is_no_bytes_is_never_taken_for_a_size():
    """(Review, minor) An int given where bytes belong names nothing at once: no bytes are made of it."""
    started = time.monotonic()
    assert parse_dns(10 ** 12) == [] and parse_dns(10 ** 12, tcp=True) == [] and parse_sni(10 ** 12) is None
    assert parse_dns(-1) == [] and parse_sni(2 ** 40) is None and parse_sni([0x16, 3, 1]) is None
    assert time.monotonic() - started < 1.0
    assert parse_sni(bytearray(GOOD)) == parse_sni(memoryview(GOOD)) == "shop.example"
    huge = chain() + b"\x00" * (names.MAX_INPUT * 2)  # more than any message: only MAX_INPUT bytes are read
    assert parse_dns(huge) == parse_dns(chain())


def test_compression_pointers_go_only_backwards_and_a_few_at_most():
    def with_owner(owner: bytes, before: bytes = b"") -> bytes:
        m = Message()
        q = m.question(labels("shop.example"))
        if before:
            m.answer(b"\x00", TXT, before)  # bytes for pointers to land on, in a record of no interest
        m.answer(owner(m) if callable(owner) else owner, A, socket.inet_aton(EDGE))
        return m.bytes()

    assert parse_dns(with_owner(pointer(12))) == [("shop.example", EDGE, 300)]
    assert parse_dns(with_owner(lambda m: pointer(m.at))) == []  # to itself
    assert parse_dns(with_owner(lambda m: pointer(m.at + 4))) == []  # forward
    assert parse_dns(with_owner(pointer(4000))) == []  # past the end
    cut = Message()
    cut.question(labels("shop.example"))
    cut.raw(b"\x03www\xc0")
    assert parse_dns(cut.bytes(answers=1)) == []  # a pointer cut short, at the very end

    # a pointer landing on a pointer that leads forward again: A -> B -> A
    m = Message()
    m.question(labels("shop.example"))
    first = m.at
    m.answer(b"\x00", TXT, b"\x00\x00")  # rdata at first+11: two bytes, filled below
    target = first + 11
    m.answer(pointer(target), A, socket.inet_aton(EDGE))
    data = bytearray(m.bytes())
    data[target:target + 2] = pointer(target + 2)  # the pointer there leads forward, past the place it was reached from
    assert parse_dns(bytes(data)) == []

    def ladder(steps: int) -> bytes:
        """A name reached through `steps` pointers, each landing on the one before it (the name asked for)."""
        m = Message()
        m.question(labels("deep.example"))
        start = m.at + 11  # where the TXT record's data begins
        pool = labels("deep.example")
        for i in range(steps - 1):
            pool += pointer(start if i == 0 else start + len(labels("deep.example")) + 2 * (i - 1))
        m.answer(b"\x00", TXT, pool)
        last = start if steps == 1 else start + len(labels("deep.example")) + 2 * (steps - 2)
        m.answer(pointer(last), A, socket.inet_aton(EDGE))
        return m.bytes()
    assert parse_dns(ladder(names.MAX_JUMPS)) == [("deep.example", EDGE, 300)]
    assert parse_dns(ladder(names.MAX_JUMPS + 1)) == []


def test_labels_and_lengths_are_checked_against_the_bytes_there_are():
    def one(owner: bytes, rtype=A, rdata=None, size=None) -> list:
        m = Message()
        q = m.question(labels("shop.example"))
        m.answer(owner, rtype, socket.inet_aton(EDGE) if rdata is None else rdata, size=size)
        m.answer(pointer(q), A, socket.inet_aton(EDGE2))  # after it: read when the one before could be stepped over
        return parse_dns(m.bytes())

    assert one(b"\x40" + b"x" * 64 + b"\x00") == []  # 0x40: a kind of label no answer uses
    assert one(b"\x80\x00") == []
    long_name = b"".join(b"\x3f" + b"a" * 63 for _ in range(4)) + b"\x00"  # 257 bytes: over 255
    assert one(long_name) == []
    assert one(b"\x05sh.op\x07example\x00") == [("shop.example", EDGE2, 300)]  # a dot inside a label: no host name
    assert one(b"\x06sh\xc3\xb6p!\x07example\x00") == [("shop.example", EDGE2, 300)]  # odd characters: the same
    assert one(b"\x00") == [("shop.example", EDGE2, 300)]  # the root has no address of interest
    assert one(b"\x09localhost\x00") == [("shop.example", EDGE2, 300)]  # one label: no host name here
    # a CNAME whose name runs past its record's data: the CNAME passed over, the records after it read
    assert one(pointer(12), CNAME, labels("edge.example"), size=4) == []  # its length cuts the next record's start
    m = Message()
    q = m.question(labels("shop.example"))
    m.answer(pointer(q), CNAME, b"\x04edge\x07example", ttl=5)  # no end in its own data
    m.answer(labels("edge.example"), A, socket.inet_aton(EDGE))  # where it seemed to lead: on no question's way now
    m.answer(pointer(q), A, socket.inet_aton(EDGE2))
    assert parse_dns(m.bytes()) == [("shop.example", EDGE2, 300)]
    # a record running past the end: the answers before it stand
    cut = Message()
    q = cut.question(labels("shop.example"))
    cut.answer(pointer(q), A, socket.inet_aton(EDGE))
    cut.answer(pointer(q), A, socket.inet_aton(EDGE2), size=400)
    assert parse_dns(cut.bytes()) == [("shop.example", EDGE, 300)]
    assert parse_dns(cut.bytes(answers=9)) == [("shop.example", EDGE, 300)]  # more answers said than there are
    many = Message()
    q = many.question(labels("shop.example"))
    for i in range(100):
        many.answer(pointer(q), A, socket.inet_aton(f"81.2.70.{i}"))
    assert len(parse_dns(many.bytes())) == names.MAX_RECORDS  # the first ones, capped


def test_reading_dns_never_faults_on_bytes_cut_or_changed():
    message = chain()
    for cut in range(len(message)):
        got = parse_dns(message[:cut])
        assert isinstance(got, list)
    rng = random.Random(20261114)
    for _ in range(5000):
        data = bytearray(message)
        for _ in range(rng.randrange(1, 10)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        for name, address, ttl in parse_dns(bytes(data)) + parse_dns(bytes(data), tcp=True):
            assert name and address and 0 <= ttl < 2 ** 31 and len(name) <= 253
    for _ in range(500):
        parse_dns(bytes(rng.randrange(256) for _ in range(rng.randrange(600))))


# -- ClientHellos --------------------------------------------------------------------------------------------------------
# Recorded on 2026-11-15 from this machine's own TLS library (Python 3.15's ssl, OpenSSL 3.5.9), in memory, no socket:
# a ClientHello for www.example.com, cut as the capture keeps it, at 512 bytes (the whole record is 1522: its key
# shares X25519MLKEM768 and X25519).
RECORDED = bytes.fromhex(
    "16030105ed010005e9030335b0e55343c989fd86b71035ed4917890578b941d5a42f6dd7fa5d78f497e44620dfcae3b63e9b8822b9e6fe6e"
    "179e94de07b18433a421853a488cbe9ad5d61a910022130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b0067"
    "0100057eff0100010000000014001200000f7777772e6578616d706c652e636f6d000b000403000102000a0012001011ec001d0017001e00"
    "18001901000101002300000016000000170000000d0036003409050906090404030503060308070808081a081b081c0809080a080b080408"
    "050806040105010601030303010302040205020602002b00050403040303002d00020101003304ea04e811ec04c0a813a4e5675b92aa0aa6"
    "f611fee29fd88c55b6a17950811377d37ff14b2b78c14f2cea797ce687fa686301791693b48208a62e0ec9397b7a886ada79cdc28334d50d"
    "815b50e30032c5153b880876f549a2ff192f45c05b05d86d2545c633bc76af0723ab32612d5990fb135d2f40c68ea421d6d706f2219a6232"
    "01a7177031b64197f8a8f864ba360204bdb8865b7635ed964b907b9386c77188738f93b06f656b157dd393c0504ea611adb288c12b862de3"
    "25c793386250f38e21812297010304fa6dd79b82f285bbdca7072fc25381505efb369ecb8c3061d1a798e19eb2ca252a05b845118da42334"
    "9eb81487fb40eed6")


def made_here(name: str) -> bytes:
    """A ClientHello this machine's TLS library writes for `name`: the handshake begun in memory, nothing sent."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_bio(incoming, outgoing, server_hostname=name)
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def server_name(name: bytes, kind: int = 0) -> bytes:
    entry = bytes([kind]) + struct.pack("!H", len(name)) + name
    return struct.pack("!HH", 0, len(entry) + 2) + struct.pack("!H", len(entry)) + entry


def extension(kind: int, data: bytes) -> bytes:
    return struct.pack("!HH", kind, len(data)) + data


def hello(extensions: bytes, *, session=b"\x11" * 32, suites=b"\x13\x01\x13\x02", methods=b"\x00", version=b"\x03\x03",
          kind=1, record=b"\x16\x03\x01") -> bytes:
    body = (version + b"\x22" * 32 + bytes([len(session)]) + session + struct.pack("!H", len(suites)) + suites
            + bytes([len(methods)]) + methods + struct.pack("!H", len(extensions)) + extensions)
    message = bytes([kind]) + len(body).to_bytes(3, "big") + body
    return record + struct.pack("!H", len(message)) + message if record else message


GOOD = hello(extension(0xFF01, b"\x00") + extension(0x000A, b"\x00\x02\x00\x1d") + server_name(b"Shop.Example."))


def test_a_real_client_hello_names_its_server():
    assert parse_sni(RECORDED) == "www.example.com"  # as captured: its first 512 bytes
    whole = made_here("liminal.example")
    assert len(whole) > 200 and parse_sni(whole) == "liminal.example"
    assert parse_sni(whole[:512]) == "liminal.example" and parse_sni(whole[5:]) == "liminal.example"  # QUIC's: no record
    assert parse_sni(made_here("api.shop.example")[:512]) == "api.shop.example"
    assert parse_sni(GOOD) == "shop.example"  # lowered, its last dot dropped


def test_malformed_client_hellos_name_nothing_and_never_fault():
    assert parse_sni(b"\x17" + GOOD[1:]) is None  # application data, not a handshake
    assert parse_sni(GOOD[:1] + b"\x02" + GOOD[2:]) is None  # not TLS 1.x's record
    assert parse_sni(hello(server_name(b"shop.example"), kind=2)) is None  # a ServerHello
    assert parse_sni(hello(server_name(b"shop.example"), version=b"\x02\x00")) is None
    assert parse_sni(hello(server_name(b"shop.example"), session=b"\x00" * 33)) is None  # a session id over 32 bytes
    assert parse_sni(hello(server_name(b"shop.example"), suites=b"\x13\x01\x13")) is None  # an odd suites' length
    assert parse_sni(hello(server_name(b"shop.example"), suites=b"")) is None
    assert parse_sni(hello(server_name(b"shop.example"), methods=b"")) is None  # no compression method at all
    assert parse_sni(hello(server_name(b"shop.example"), record=b"")) == "shop.example"  # the handshake alone reads
    assert parse_sni(hello(extension(0x000A, b"\x00\x02\x00\x1d"))) is None  # no server_name
    assert parse_sni(hello(server_name(b"shop.example", kind=1))) is None  # a name of another kind than host_name
    for bad in (b"81.2.69.142", b"shop_example!.com", b"a" * 64 + b".example", (b"a" * 62 + b".") * 4 + b"example",
                b"localhost", b"", b"sh\xc3\xb6p.example", b".shop.example"):
        assert parse_sni(hello(server_name(bad))) is None, bad
    assert parse_sni(hello(server_name(b"tracker-1.ads_cdn.example"))) == "tracker-1.ads_cdn.example"

    stretched = bytearray(GOOD)  # the server_name extension says more bytes than there are
    at = GOOD.index(server_name(b"Shop.Example."))
    stretched[at + 2:at + 4] = struct.pack("!H", 400)
    assert parse_sni(bytes(stretched)) is None
    late = hello(extension(0x0015, b"\x00" * 600) + server_name(b"late.example"))  # behind 600 bytes of padding
    assert parse_sni(late) == "late.example" and parse_sni(late[:512]) is None  # cut where the capture cuts: not named
    assert parse_sni(None) is None and parse_sni(b"") is None and parse_sni("\x16\x03\x01") is None

    for sample in (GOOD, RECORDED):
        for cut in range(len(sample)):
            assert parse_sni(sample[:cut]) in (None, "shop.example", "www.example.com")
    rng = random.Random(20261114)
    for _ in range(5000):
        data = bytearray(GOOD if rng.random() < 0.5 else RECORDED)
        for _ in range(rng.randrange(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        got = parse_sni(bytes(data))
        assert got is None or (0 < len(got) <= 253 and got == got.lower())


# -- ClientHellos as Chrome and Edge send them ---------------------------------------------------------------------------
def chromium_hello(name: bytes, rng: random.Random, *, order=None, ech: int | None = None) -> bytes:
    """A ClientHello shaped as Chromium's (Chrome, Edge) since its post-quantum key share: a GREASE extension first and
    one last, the sixteen between in an order of their own each time (BoringSSL's permutation), a key share of an
    X25519MLKEM768 key (1,216 bytes) and an X25519 one (1,267 bytes in all), an ECH GREASE extension of 190 to 286
    bytes; `order`: the sixteen's kinds in that order (shuffled when not given)."""
    def grease() -> bytes:
        return bytes([0x0A + 0x10 * rng.randrange(16)]) * 2

    payload = rng.choice((144, 176, 208, 240)) if ech is None else ech
    entry = b"\x00" + struct.pack("!H", len(name)) + name
    shares = (grease() + b"\x00\x01\x00" + b"\x11\xec" + struct.pack("!H", 1216) + rng.randbytes(1216)
              + b"\x00\x1d\x00\x20" + rng.randbytes(32))
    body = {
        0x0000: struct.pack("!H", len(entry)) + entry,  # server_name
        0x0017: b"", 0xFF01: b"\x00",  # extended_master_secret, renegotiation_info
        0x000A: b"\x00\x0a" + grease() + b"\x11\xec\x00\x1d\x00\x17\x00\x18",  # supported_groups
        0x000B: b"\x01\x00", 0x0023: b"",  # ec_point_formats, session_ticket
        0x0010: b"\x00\x0c\x02h2\x08http/1.1",  # ALPN
        0x0005: b"\x01\x00\x00\x00\x00",  # status_request
        0x000D: b"\x00\x10" + bytes.fromhex("04030804040105030805050108060601"),  # signature_algorithms
        0x0012: b"",  # signed_certificate_timestamp
        0x0033: struct.pack("!H", len(shares)) + shares,  # key_share
        0x002D: b"\x01\x01", 0x002B: b"\x06" + grease() + b"\x03\x04\x03\x03",  # psk modes, supported_versions
        0x001B: b"\x02\x00\x02", 0x44CD: b"\x00\x03\x02h2",  # compress_certificate, application_settings
        0xFE0D: (b"\x00\x00\x01\x00\x01" + bytes([rng.randrange(256)]) + b"\x00\x20" + rng.randbytes(32)
                 + struct.pack("!H", payload) + rng.randbytes(payload)),  # encrypted_client_hello (GREASE)
    }
    kinds = list(body) if order is None else list(order)
    if order is None:
        rng.shuffle(kinds)
    extensions = (grease() + b"\x00\x00" + b"".join(extension(k, body[k]) for k in kinds)
                  + grease() + b"\x00\x01\x00")
    suites = grease() + bytes.fromhex("130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035")
    return hello(extensions, session=rng.randbytes(32), suites=suites)


def test_chromiums_client_hellos_fit_what_a_capture_keeps_whatever_their_extensions_order():
    """(Review F5) The first 512 bytes held a Chromium ClientHello's server_name about half the time (its key share
    alone is 1,267 bytes, shuffled before it as often as not); what a capture keeps now holds all of them."""
    rng = random.Random(20261115)
    late = (0x0033, 0xFE0D, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x002D, 0x002B,
            0x001B, 0x44CD, 0x0000)  # the key share and ECH first, the server_name last of all
    longest = b".".join([b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61])  # 253 characters: the longest host name
    worst = chromium_hello(longest, rng, order=late, ech=240)  # its name after every other extension, its ECH longest
    assert len(longest) == 253 and parse_sni(worst) == longest.decode() and parse_sni(worst[:512]) is None
    assert worst.index(longest) + len(longest) <= capture.MAX_HELLO  # the name ends inside what is kept
    assert parse_sni(worst[:capture.MAX_HELLO]) == longest.decode()
    for _ in range(500):
        whole = chromium_hello(b"www.bank.example", rng)
        assert 1700 <= len(whole) <= capture.MAX_HELLO and parse_sni(whole) == "www.bank.example"
        assert parse_sni(whole[:capture.MAX_HELLO]) == "www.bank.example"


# -- a NameBook ------------------------------------------------------------------------------------------------------------
def dns_packet(payload: bytes, proto="udp", at=1.0, src=ROUTER, port=53000, direction="in") -> Packet:
    return Packet(at, src, 53, LAN, port, 0x18 if proto == "tcp" else 0, 4, proto, 60 + len(payload), direction, payload)


def asked(name: str, ident: int = 0x1234, proto: str = "udp", port: int = 53000, at: float = 0.5,
          resolver: str = ROUTER, qtype: int = A, framed: bool = True) -> Packet:
    """A question this machine sends: from its port `port` to `resolver`, port 53."""
    q = Message(flags=0x0100, ident=ident)
    q.question(labels(name), qtype)
    body = q.bytes()
    if proto == "tcp" and framed:
        body = struct.pack("!H", len(body)) + body
    return Packet(at, LAN, port, resolver, 53, 0x18 if proto == "tcp" else 0, 4, proto, 60 + len(body), "out", body)


def test_a_namebook_learns_names_from_dns_answers_and_client_hellos():
    book = NameBook()
    assert book.observe(asked("www.shop.example")) == 0  # a question names nothing: it is remembered
    assert book.observe(dns_packet(chain())) == 9
    assert book.names_of(EDGE) == ["www.shop.example", "shop.tracker.example", "edge.tracker.example"]
    assert book.name_of(EDGE) == "www.shop.example" and book.name_of(EDGE6) == "www.shop.example"  # the name asked for
    m = Message()
    q = m.question(labels("mail.example"))
    m.answer(pointer(q), A, socket.inet_aton(EDGE2))
    framed = struct.pack("!H", len(m.bytes())) + m.bytes()
    book.observe(asked("mail.example", proto="tcp"))
    assert book.observe(dns_packet(framed, "tcp")) == 1  # DNS over TCP
    book.observe(asked("mail.example", proto="tcp", framed=False))  # its length bytes in a segment of their own
    assert book.observe(dns_packet(m.bytes(), "tcp")) == 1
    assert book.names_of(EDGE2)[0] == "mail.example"
    to_web = Packet(2.0, LAN, 52000, EDGE, 443, 0x18, 4, "tcp", 600, "out", RECORDED)
    assert book.observe(to_web) == 1
    assert book.names_of(EDGE) == ["www.example.com", "www.shop.example", "shop.tracker.example", "edge.tracker.example"]
    assert book.read == {"dns": 3, "sni": 1, "unasked": 0} and len(book) == 3

    question = Message(flags=0x0100)
    question.question(labels("shop.example"))
    ask = Packet(3.0, LAN, 53000, ROUTER, 53, 0, 4, "udp", 80, "out", question.bytes())
    assert book.observe(ask) == 0  # a question names nothing
    assert book.observe(Packet(3.0, EDGE, 443, LAN, 52000, 0x18, 4, "tcp", 600, "in", RECORDED)) == 0  # from 443
    assert book.observe(Packet(3.0, LAN, 52000, EDGE, 80, 0x18, 4, "tcp", 600, "out", RECORDED)) == 0  # another port
    assert book.observe(Packet(3.0, LAN, 52000, EDGE, 443, 0x18, 4, "udp", 600, "out", RECORDED)) == 0  # QUIC
    assert book.observe(dns_packet(b"")) == 0 and book.observe(Packet(3.0, ROUTER, 53, LAN, 1)) == 0  # no payload
    assert book.names_of("81.2.69.99") == [] and book.name_of("81.2.69.99") is None and book.names_of("nowhere") == []


def spoofed(name: str = "windowsupdate.microsoft.com", address: str = "203.0.113.66", ident: int = 0x1234,
            records: int = 1) -> bytes:
    """An answer naming `address` (and more, `records` in all) after `name`, as anyone could send one."""
    m = Message(ident=ident)
    q = m.question(labels(name))
    for i in range(records):
        m.answer(pointer(q), A, socket.inet_aton(address) if i == 0 else socket.inet_aton(f"203.0.{i // 250}.{i % 250}"))
    return m.bytes()


def test_a_namebook_believes_an_answer_only_to_a_question_this_machine_asked():
    """(Review F4) One datagram from port 53, from anywhere, used to name any address after anything (a C2 server
    after Microsoft), and a few hundred evicted every real name. Now an answer is believed only when it answers this
    machine's own question: from the resolver asked, to the port asked from, with its id and its name, soon after."""
    book = NameBook()
    unasked = dns_packet(spoofed(), src="198.51.100.7", port=40000)
    assert book.observe(unasked) == 0 and book.name_of("203.0.113.66") is None and book.read["unasked"] == 1
    for _ in range(137):  # the flood that emptied the book
        book.observe(dns_packet(spoofed(records=28), src="198.51.100.7", port=40000))
    assert len(book) == 0

    book.observe(asked("windowsupdate.microsoft.com", port=40000, at=10.0))
    assert book.observe(dns_packet(spoofed(), src="198.51.100.7", port=40000, at=10.1)) == 0  # not the resolver asked
    assert book.observe(dns_packet(spoofed(), port=40001, at=10.1)) == 0  # not the port it was asked from
    assert book.observe(dns_packet(spoofed(ident=0x4321), port=40000, at=10.1)) == 0  # another id
    assert book.observe(dns_packet(spoofed("update.example"), port=40000, at=10.1)) == 0  # another name
    assert book.observe(dns_packet(spoofed(), port=40000, at=10.1, direction="out")) == 0  # one this machine serves
    assert book.name_of("203.0.113.66") is None
    assert book.observe(dns_packet(spoofed(), port=40000, at=10.2)) == 1  # the answer to it
    assert book.name_of("203.0.113.66") == "windowsupdate.microsoft.com"
    assert book.observe(dns_packet(spoofed(address="203.0.113.99"), port=40000, at=10.3)) == 0  # answered once only
    assert book.name_of("203.0.113.99") is None

    late = NameBook(wait=5.0)
    late.observe(asked("shop.example", at=100.0))
    assert late.observe(dns_packet(spoofed("shop.example"), at=105.5)) == 0  # past its wait
    v6 = NameBook()  # over IPv6, and an A and an AAAA question on one port with their own ids
    q4 = asked("shop.example", ident=1, resolver="2001:db8:1::1")
    v6.observe(Packet(1.0, "2001:db8:1::20", 53000, "2001:db8:1::1", 53, 0, 6, "udp", 90, "out", q4.payload))
    q6 = asked("shop.example", ident=2, qtype=AAAA)
    v6.observe(Packet(1.0, "2001:db8:1::20", 53000, "2001:db8:1::1", 53, 0, 6, "udp", 90, "out", q6.payload))
    m = Message(ident=2)
    q = m.question(labels("shop.example"), AAAA)
    m.answer(pointer(q), AAAA, socket.inet_pton(socket.AF_INET6, EDGE6))
    answer = Packet(1.1, "2001:db8:1::1", 53, "2001:db8:1::20", 53000, 0, 6, "udp", 120, "in", m.bytes())
    assert v6.observe(answer) == 1 and v6.name_of(EDGE6) == "shop.example"
    here = NameBook()  # between two of this machine's own addresses, port 53 at both ends: asked, then answered
    q = asked("local.example", port=53)
    assert here.observe(Packet(1.0, LAN, 53, "192.168.1.21", 53, 0, 4, "udp", 80, "local", q.payload)) == 0
    reply = Packet(1.1, "192.168.1.21", 53, LAN, 53, 0, 4, "udp", 80, "local", spoofed("local.example", EDGE2))
    assert here.observe(reply) == 1 and here.name_of(EDGE2) == "local.example"


def test_a_namebook_names_an_address_only_after_a_client_hello_this_machine_sent():
    """(Review F4) An inbound ClientHello (to a server here, or a raw segment sent to its hardware address) named this
    machine's own address, or any address, after whatever it said."""
    book = NameBook()
    inbound = Packet(2.0, "81.2.69.142", 52000, LAN, 443, 0x18, 4, "tcp", 600, "in", RECORDED)
    foreign = Packet(2.0, "81.2.69.142", 52000, "198.51.100.50", 443, 0x18, 4, "tcp", 600, "in", RECORDED)
    unjudged = Packet(2.0, LAN, 52000, EDGE, 443, 0x18, 4, "tcp", 600, "", RECORDED)
    assert book.observe(inbound) == book.observe(foreign) == book.observe(unjudged) == 0
    assert book.name_of(LAN) is None and book.name_of("198.51.100.50") is None and len(book) == 0
    assert book.observe(Packet(2.0, LAN, 52000, EDGE, 443, 0x18, 4, "tcp", 600, "out", RECORDED)) == 1
    assert book.name_of(EDGE) == "www.example.com"


def test_the_questions_awaiting_an_answer_are_capped_and_forgotten_in_time():
    book = NameBook(max_asked=4, wait=5.0)
    for i in range(10):
        book.observe(asked(f"q{i}.example", port=41000 + i, at=1.0 + i / 100))
    assert len(book._asked) == 4  # the latest four
    for i in range(10):
        book.observe(dns_packet(spoofed(f"q{i}.example", address=f"81.2.70.{i}"), port=41000 + i, at=1.5))
    assert [book.name_of(f"81.2.70.{i}") for i in range(10)] == [None] * 6 + [f"q{i}.example" for i in range(6, 10)]
    assert book.read["unasked"] == 6 and len(book._asked) == 0
    book.observe(asked("old.example", port=42000, at=10.0))
    book.observe(asked("new.example", port=42001, at=20.0))  # the old one waited too long: forgotten
    assert list(book._asked) == [("udp", ROUTER, LAN, 42001, 0x1234)]
    many = Message(flags=0x0100)
    for i in range(6):
        many.question(labels(f"m{i}.example"))  # more than any resolver asks: no question
    assert book.observe(Packet(21.0, LAN, 42002, ROUTER, 53, 0, 4, "udp", 200, "out", many.bytes())) == 0
    assert len(book._asked) == 1


def test_a_namebook_keeps_the_most_recent_names_first_and_is_capped():
    book = NameBook(max_ips=3, per_ip=4)
    for i in range(6):
        book.add(f"n{i}.example", EDGE)
    assert book.names_of(EDGE) == ["n5.example", "n4.example", "n3.example", "n2.example"]
    book.add("n3.example", EDGE)  # said again: the most recent once more
    assert book.names_of(EDGE) == ["n3.example", "n5.example", "n4.example", "n2.example"]
    book.add("one.example", "81.2.69.1")
    book.add("two.example", "81.2.69.2")
    book.add("again.example", EDGE)  # EDGE noted again: now the most recent address
    book.add("three.example", "81.2.69.3")  # room made: the address noted longest ago goes
    assert len(book) == 3 and book.names_of("81.2.69.1") == [] and book.name_of("81.2.69.2") == "two.example"
    assert book.name_of(EDGE) == "again.example"

    keys = NameBook()
    keys.add("Shop.Example.", "::ffff:81.2.69.142")  # an IPv4 address written as IPv6 is the IPv4 one
    keys.add("v6.example", "[2A02:1810:4D0A::10]")
    keys.add("link.example", "fe80::1%12")
    assert keys.names_of("81.2.69.142") == ["shop.example"] and keys.name_of(EDGE6) == "v6.example"
    assert keys.name_of("fe80::1") == "link.example"
    for bad_name, ip in (("not a name!", EDGE), ("x" * 300 + ".example", EDGE), ("", EDGE), (None, EDGE),
                         ("localhost", EDGE), ("shop.example", "nowhere"), ("shop.example", None)):
        keys.add(bad_name, ip)
    assert len(keys) == 3 and keys.names_of(EDGE) == []
