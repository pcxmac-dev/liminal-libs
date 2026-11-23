"""A model server asked over http (liminal_libs.machines.endpoint): an address as typed and as built from its parts,
plain http kept to this machine until its user accepts it for another, the key in no error, every answer bounded, a
stream handed on line by line until its end, its deadline or a cancel, the OpenAI-compatible list of models as
llama.cpp, Ollama and vLLM answer it, a chat cut, a download's progress in words, and one deadline for the whole of
a request, kept by its watchdog however slowly its connection, its handshake, its head or its body comes.

Every ask goes to a stand-in transport; the `requests` transport is run over a stand-in adapter, a slow sender over a
stand-in connection under the real stack (http.client, urllib3, requests), and the deadline over stand-in sockets
under the whole of it (urllib3's connections and their TLS wrapping too), each shut both as Windows shuts a socket
and as Linux does, whichever system runs them. No socket is connected and no process started: the shared guard
(conftest.py, `no_outside`) fails a test that does either. No address is written whole here either: each is built
from its parts, as the library's own are."""
from __future__ import annotations

import errno
import http.client
import io
import json
import re
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
import requests
import urllib3
from requests.structures import CaseInsensitiveDict

from liminal_libs.instances import Refusal
from liminal_libs.machines import endpoint
from liminal_libs.machines.endpoint import (ACCEPT_PLAIN, ANSWER_CHARS, CHAT_S, LINE_MOST, LOOK_S, Endpoint,
                                            EndpointError, Progress, Reply, base_url, parse_address)
from liminal_libs.machines.rest import Answer
from liminal_libs.machines.terminal import Cancelled, Output

pytestmark = pytest.mark.usefixtures("no_outside")

KEY = "sk-local-0123456789abcdef"
HERE = base_url("127.0.0.1", 11434)  # an Ollama on this machine
THERE = base_url("gpu-box.example", 8000)  # a vLLM on another machine, over plain http
SAFE = base_url("models.example", 443, tls=True)  # one behind https


def address(scheme: str, rest: str) -> str:
    return f"{scheme}://{rest}"


class Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class Transport:
    """A transport as a stand-in: answers in order, each (status, headers, body) or an error to raise; what was sent
    is kept, the pieces read are counted, and the replies let go. A body: bytes, JSON to dump (handed on a few bytes
    at a time), or a list of pieces handed on as they are (a piece that is an error is raised in its place; one that
    is a function is called for its bytes)."""

    def __init__(self, *answers):
        self.answers, self.sent, self.read, self.closed = list(answers), [], 0, 0

    def __call__(self, method, url, headers, body, timeout, stream):
        self.sent.append({"method": method, "url": url, "headers": dict(headers), "body": body, "timeout": timeout,
                          "stream": stream})
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        status, said, data = answer
        if isinstance(data, dict):
            said = {"Content-Type": "application/json", **said}
            data = json.dumps(data).encode()
        parts = data if isinstance(data, list) else [data[i:i + 7] for i in range(0, len(data), 7)]

        def pieces():
            for piece in parts:
                if isinstance(piece, BaseException):
                    raise piece
                self.read += 1
                yield piece() if callable(piece) else piece

        def close():
            self.closed += 1
        return Reply(status, said, pieces(), close)


# -- the address -------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("typed, parts", [
    ("gpu-box", ("gpu-box", 8000, False, "")),  # a host alone: http, at the maker's port
    ("gpu-box:9931", ("gpu-box", 9931, False, "")),
    ("  GPU-Box.Example:8000/ ", ("gpu-box.example", 8000, False, "")),
    (address("http", "gpu-box"), ("gpu-box", 80, False, "")),  # a scheme and no port: the scheme's own, not the maker's
    (address("https", "gpu-box"), ("gpu-box", 443, True, "")),
    (address("https", "gpu-box:8443/llama/"), ("gpu-box", 8443, True, "/llama")),  # a path is the prefix
    (address("HTTP", "192.168.1.20:11434"), ("192.168.1.20", 11434, False, "")),
    ("gpu-box:8000/proxy/vllm", ("gpu-box", 8000, False, "/proxy/vllm")),
    ("[::1]:9931", ("::1", 9931, False, "")),
    ("::1", ("::1", 8000, False, "")),
    (address("https", "[2001:db8::7]/v"), ("2001:db8::7", 443, True, "/v")),
    ("ollama_server", ("ollama_server", 8000, False, "")),  # a compose service's name
    ("xn--bcher-kva.example", ("xn--bcher-kva.example", 8000, False, "")),  # an international name, as DNS knows it
])
def test_an_address_as_typed(typed, parts):
    assert parse_address(typed, 8000) == parts
    host, port, tls, prefix = parts
    assert parse_address(base_url(host, port, tls, prefix), 1) == parts  # built from its parts, it reads back the same


@pytest.mark.parametrize("typed, words", [
    ("", "no address given"), (None, "no address given"), ("gpu box", "no space and no line break"),
    (address("ftp", "gpu-box"), "over http or https, not over ftp"), (address("ws", "gpu-box:8000"), "not over ws"),
    ("me@gpu-box", "no user name and no password"), (address("https", "me:hunter2hunter2@gpu-box:x"), "no user name"),
    ("gpu-box?x=1", "no query"), ("gpu-box/#top", "no query"),
    ("gpu-box:99999", "its port is a whole number"), ("gpu-box:http", "its port is a whole number"),
    ("gpu-box:0", "from 1 to 65535"), (address("http", ""), "names no host"), (":8000", "names no host"),
    ("-gpu", "no host's name and no address"), ("gpu-box/a/../b", r"no \. and no \.\."),
    ("::1:8000:x", "stands in brackets"), ("fe80::1%eth0", "with a zone"),
    ("bücher.example", r"letters outside ASCII: give it as your DNS knows it, in its ASCII form \(xn--\.\.\.\)"),
    (address("https", "bücher.example:8443"), "letters outside ASCII"),
])
def test_what_is_no_address_is_said_in_words(typed, words):
    with pytest.raises(ValueError, match=words) as said:
        parse_address(typed, 8000)
    assert not isinstance(said.value, Refusal)
    assert "hunter2" not in str(said.value)  # a password typed is not shown back


def test_an_address_is_built_from_its_parts():
    assert base_url("127.0.0.1", 11434) == address("http", "127.0.0.1:11434")
    assert base_url("GPU-Box", 80) == address("http", "gpu-box")  # a scheme's own port is not written
    assert base_url("gpu-box", 443, tls=True, prefix="llama/") == address("https", "gpu-box/llama")
    assert base_url("[::1]", 9931) == address("http", "[::1]:9931") == base_url("::1", "9931")
    for host, port in (("", 80), ("a b", 80), ("gpu-box", 0), ("gpu-box", "x"), ("gpu-box", True),
                       ("gpu-box", 65536), ("bücher", 80)):
        with pytest.raises(ValueError):
            base_url(host, port)


# -- where it may ask --------------------------------------------------------------------------------------------
def test_this_machine_is_asked_over_plain_http():
    t = Transport((200, {"Content-Type": "application/json; charset=utf-8"}, {"version": "0.14.2"}))
    at = Endpoint(HERE, transport=t)
    assert at.seen == {"at": None, "status": 0, "seconds": 0.0, "error": ""}  # making one asks nothing
    assert at.get("/api/version") == {"version": "0.14.2"}
    sent = t.sent[0]
    assert (sent["method"], sent["url"], sent["body"]) == ("GET", HERE + "/api/version", None)
    assert sent["timeout"] == LOOK_S == 3.0 and sent["stream"] is False
    assert sent["headers"] == {"User-Agent": endpoint.AGENT, "Accept-Encoding": "identity",
                               "Accept": "application/json"}
    assert t.closed == 1 and len(t.sent) == 1
    assert at.seen["status"] == 200 and at.seen["error"] == "" and abs(at.seen["at"] - time.time()) < 60
    for local in ("127.0.0.1", "localhost", "::1"):
        assert Endpoint(base_url(local, 9931), transport=Transport()).local
    assert Endpoint(base_url("::1", 9931)).url("/health") == address("http", "[::1]:9931/health")


def test_another_machine_is_not_asked_over_plain_http_until_its_user_accepts_it():
    t = Transport()
    with pytest.raises(Refusal) as refused:
        Endpoint(THERE, key=KEY, transport=t)
    assert refused.value.accept == ACCEPT_PLAIN == "accept_plain"
    assert str(refused.value) == ("gpu-box.example would be asked over plain http: its key and everything sent to it "
                                  "can be read on the way. Give an https address, or accept it for a network you "
                                  "trust.")
    for no_yes in (False, None, 1, "true", "yes"):  # exactly True accepts it, nothing else
        with pytest.raises(Refusal):
            Endpoint(THERE, plain=no_yes, transport=t)
    assert t.sent == []  # refused before anything is asked
    t = Transport((200, {}, {"version": "0.33.0"}))
    at = Endpoint(THERE, plain=True, key=KEY, transport=t)
    assert at.get("/version") == {"version": "0.33.0"} and not at.local
    assert t.sent[0]["url"] == THERE + "/version" and t.sent[0]["headers"]["Authorization"] == f"Bearer {KEY}"
    t = Transport((200, {}, {"object": "list", "data": []}))  # https needs no accepting, wherever it leads
    assert Endpoint(SAFE, transport=t).models() == [] and t.sent[0]["url"] == SAFE + "/v1/models"


def test_what_is_no_http_or_https_address_is_no_endpoint():
    for bad, words in (("gpu-box:8000", "says http or https first"), (address("ftp", "gpu-box"), "not over ftp"),
                       (address("https", "me:pw@gpu-box"), "no user name and no password"),
                       (address("http", "127.0.0.1:11434/?x=1"), "no query"), (address("http", ""), "names no host"),
                       (address("https", "bücher.example"), "letters outside ASCII")):
        with pytest.raises(ValueError, match=words) as said:
            Endpoint(bad)
        assert not isinstance(said.value, Refusal)  # nothing a second confirmation could accept
    with pytest.raises(ValueError, match="above 0"):
        Endpoint(HERE, timeout=0)


# -- the key -----------------------------------------------------------------------------------------------------
def test_the_key_goes_as_a_bearer_and_is_in_no_error():
    echo = {"error": {"message": f"Invalid API key: Bearer {KEY}", "type": "authentication_error", "code": 401}}
    t = Transport((401, {}, echo), ConnectionError(f"reset while sending Authorization: Bearer {KEY}"),
                  (500, {}, f"trace: headers={{'authorization': 'Bearer {KEY}'}}".encode()),
                  (403, {"Content-Type": "application/json"}, [json.dumps({"error": f"no: {KEY}"}).encode()]))
    at = Endpoint(HERE, key=f"  {KEY}\n", transport=t)  # pasted with its line break: sent without it
    with pytest.raises(EndpointError) as refused:
        at.get("/v1/models")
    assert t.sent[0]["headers"]["Authorization"] == f"Bearer {KEY}"
    assert refused.value.status == 401 and refused.value.refused
    assert str(refused.value) == "GET /v1/models: HTTP 401: Invalid API key: Bearer •••" == at.seen["error"]
    with pytest.raises(EndpointError) as broke:
        at.post("/v1/chat/completions", {"model": "m"})
    assert broke.value.status == 0 and not broke.value.refused
    assert str(broke.value).endswith("ConnectionError: reset while sending Authorization: Bearer •••")
    with pytest.raises(EndpointError) as failed:
        at.get(f"/models/{KEY}")  # even a path that held it
    assert str(failed.value) == "GET /models/•••: HTTP 500: trace: headers={'authorization': 'Bearer •••'}"
    with pytest.raises(EndpointError) as denied:
        list(at.lines("POST", "/api/pull", json={"model": "qwen3:8b"}))
    assert denied.value.refused and str(denied.value) == "POST /api/pull: HTTP 403: no: •••"
    for error in (refused, broke, failed, denied):
        assert KEY not in str(error.value)
    assert KEY not in json.dumps(at.seen) and t.closed == 3
    with pytest.raises(ValueError, match="a space or a line break") as spaced:
        Endpoint(HERE, key="two words")
    assert "two words" not in str(spaced.value)
    t = Transport((200, {}, {}))
    Endpoint(HERE, transport=t).get("/x")
    assert "Authorization" not in t.sent[0]["headers"]  # no key, no header


def test_not_a_character_of_the_key_is_left_where_an_answer_says_it_back_oddly():
    detail = [{"loc": ["header", "authorization"], "msg": "x" * 324, "input": f"Bearer {KEY}"}]  # it ends past 400
    t = Transport((200, {"Content-Encoding": KEY}, [b"{}"]),  # a header that says it back
                  (422, {}, {"detail": detail}),  # an error list, cut at 400 characters
                  (500, {}, b" " * 3990 + KEY.encode()),  # a body that holds it across its 4,000th byte
                  ConnectionError("x" * 230 + f" Bearer {KEY}"),  # an error whose words are cut at 300
                  (401, {}, {"error": f"no such key: {KEY.upper()}"}),  # said back in another case
                  (200, {}, [b"one\n", ConnectionResetError("x" * 240 + f" {KEY}")]))
    at = Endpoint(HERE, key=KEY, transport=t)
    said = []
    for ask in (lambda: at.get("/x"), lambda: at.get("/x"), lambda: at.get("/x"), lambda: at.get("/x"),
                lambda: at.get("/x"), lambda: list(at.lines("GET", "/s"))):
        with pytest.raises(EndpointError) as error:
            ask()
        said.append(str(error.value))
        assert KEY[:6] not in said[-1] and KEY.upper()[:6] not in said[-1], said[-1]
        assert KEY[:6] not in at.seen["error"]
    assert said[0] == "GET /x: its answer comes •••-encoded, which was not asked for: not read"
    assert said[1].startswith('GET /x: HTTP 422: [{"loc"') and said[1].endswith('"input": "Bearer •••"}]')
    assert said[2] == "GET /x: HTTP 500: •••"
    assert said[3].startswith("GET /x: no answer from 127.0.0.1:11434: ConnectionError: xxx")
    assert said[3].endswith(" Bearer •••") and said[4] == "GET /x: HTTP 401: no such key: •••"


def test_a_key_that_is_not_plain_ascii_is_refused_in_words():
    for key in ("sk-‘quoted’-0123456789", "sk-café-0123456789", "sk-local-0123456789​"):
        with pytest.raises(ValueError) as refused:
            Endpoint(HERE, key=key)
        assert str(refused.value) == ("the key holds a character that is no plain letter, digit or sign (a curly "
                                      "quote, an accented letter): enter it again as its maker gave it")
        assert not isinstance(refused.value, Refusal) and "0123456789" not in str(refused.value)


# -- bounds ------------------------------------------------------------------------------------------------------
def test_an_answer_is_read_in_pieces_and_refused_past_its_bound():
    t = Transport((200, {"Content-Length": "5000"}, [b"x" * 5000]))  # it says so itself: not a byte of it is read
    at = Endpoint(HERE, most=4096, transport=t)
    with pytest.raises(EndpointError, match="its answer is 4.9 KB, and 4.0 KB is the most read of one: not read") \
            as said:
        at.get("/api/tags")
    assert said.value.status == 200 and t.read == 0 and t.closed == 1
    t = Transport((200, {}, [b"x" * 1000] * 9))  # it does not say: read until the bound, then let go
    at = Endpoint(HERE, most=4096, transport=t)
    with pytest.raises(EndpointError, match="GET /metrics: its answer is longer than 4.0 KB: not read"):
        at.text("/metrics")
    assert t.read == 5 and t.closed == 1
    t = Transport((200, {}, [b"x" * 1000] * 4))  # under it: whole
    assert Endpoint(HERE, most=4096, transport=t).text("/metrics") == "x" * 4000
    assert endpoint.MOST == 4 << 20

    clock = Clock()

    def slow():
        clock.now += 4.0
        return b" "
    t = Transport((200, {}, [slow, slow, slow]))  # a byte now and then: whole within twice its wait, or not at all
    at = Endpoint(HERE, transport=t, clock=clock)
    with pytest.raises(EndpointError, match="GET /x: its answer was not whole after 6 s: not read") as late:
        at.get("/x")
    assert late.value.status == 0 and t.read == 2 and t.closed == 1 and at.seen["seconds"] == 8.0

    t = Transport((200, {"Content-Encoding": "gzip"}, [b"\x1f\x8b\x08"]))  # packed, though none was asked for
    with pytest.raises(EndpointError, match="its answer comes gzip-encoded, which was not asked for: not read"):
        Endpoint(HERE, transport=t).get("/x")
    assert t.read == 0 and t.closed == 1


def test_no_answer_is_said_in_plain_words():
    class Wrapped(Exception):
        """As `requests` wraps the socket's own error: by argument, by cause."""

    try:
        try:
            raise TimeoutError("timed out")
        except TimeoutError as inner:
            raise Wrapped("the read") from inner
    except Wrapped as e:
        late = e
    t = Transport(Wrapped(Wrapped(ConnectionRefusedError(10061, "No connection could be made"))), late,
                  socket.gaierror(11001, "getaddrinfo failed"), OSError("a pipe broke \n  in two"))
    at = Endpoint(HERE, transport=t)
    with pytest.raises(EndpointError) as none:
        at.get("/api/version")
    assert str(none.value) == "GET /api/version: nothing listens at 127.0.0.1:11434" and none.value.status == 0
    with pytest.raises(EndpointError) as slow:
        at.get("/api/version", timeout=7.5)
    assert str(slow.value) == "GET /api/version: no answer from 127.0.0.1:11434 within 7.5 s"
    with pytest.raises(EndpointError, match="127.0.0.1:11434 is no name this machine finds"):
        at.get("/api/version")
    with pytest.raises(EndpointError) as other:
        at.post("/api/generate", {"model": "qwen3:8b"})
    assert str(other.value) == "POST /api/generate: no answer from 127.0.0.1:11434: OSError: a pipe broke in two"
    assert at.seen["status"] == 0 and at.seen["error"] == str(other.value)
    assert [s["timeout"] for s in t.sent] == [LOOK_S, 7.5, LOOK_S, LOOK_S]
    assert len(t.sent) == 4 and t.closed == 0  # each asked once (a write may have been done); nothing to let go


# -- asking ------------------------------------------------------------------------------------------------------
def test_a_write_sends_json_and_params_are_spelled_into_the_address():
    t = Transport((200, {}, {"success": True}), (200, {}, b""), (200, {}, {"data": []}), (204, {}, b""),
                  (200, {}, {}))
    at = Endpoint(HERE, transport=t)
    assert at.post("/models/load", {"model": "ggml-org/gemma-3-4b-it-GGUF:Q4_K_M"}) == {"success": True}
    assert t.sent[0]["body"] == b'{"model":"ggml-org/gemma-3-4b-it-GGUF:Q4_K_M"}'
    assert t.sent[0]["headers"]["Content-Type"] == "application/json"
    assert at.delete("api/delete", {"model": "qwen3:8b"}) is None  # no JSON came back; a path without its slash
    assert (t.sent[1]["method"], t.sent[1]["url"]) == ("DELETE", HERE + "/api/delete")
    assert t.sent[1]["body"] == b'{"model":"qwen3:8b"}'
    assert at.get("/props", params={"model": "a b/c", "autoload": "false", "skip": None}) == {"data": []}
    assert t.sent[2]["url"] == HERE + "/props?model=a+b%2Fc&autoload=false"
    assert t.sent[2]["body"] is None and "Content-Type" not in t.sent[2]["headers"]
    assert at.answer("delete", "/models", params={"model": "x"}).status == 204
    assert (t.sent[3]["method"], t.sent[3]["url"]) == ("DELETE", HERE + "/models?model=x")
    with pytest.raises(ValueError, match="no line break"):
        at.get("/x\r\nHost: elsewhere")
    assert len(t.sent) == 4
    under = Endpoint(base_url("gpu-box.example", 443, tls=True, prefix="/llama/"), transport=t)  # under a proxy's path
    under.get("/v1/models")
    assert t.sent[4]["url"] == address("https", "gpu-box.example/llama/v1/models")


def test_an_error_names_the_path_asked_under_the_addresss_prefix():
    typed = parse_address("127.0.0.1:8000/v1", 8000)  # an address typed with the /v1 its user knows from a client
    t = Transport((404, {"Content-Type": "application/json"}, {"detail": "Not Found"}), (200, {}, {"models": []}),
                  (200, {}, {"choices": []}), (200, {}, b"x"))
    at = Endpoint(base_url(*typed), transport=t)
    with pytest.raises(EndpointError) as missing:
        at.models()
    assert t.sent[0]["url"] == address("http", "127.0.0.1:8000/v1/v1/models")
    assert str(missing.value) == "GET /v1/v1/models: HTTP 404: Not Found"  # what was asked, not what was meant
    with pytest.raises(EndpointError, match="^GET /v1/v1/models: what answered is no list of models"):
        at.models()
    with pytest.raises(EndpointError, match="^POST /v1/v1/chat/completions: its answer holds no choice"):
        at.chat("m", "Say hello.")
    assert at.text("") == "x" and t.sent[3]["url"] == address("http", "127.0.0.1:8000/v1")
    assert at._where("") == "/v1" and Endpoint(HERE)._where("") == "/" and Endpoint(HERE)._where("a?b=1") == "/a"


def test_an_error_is_said_in_the_servers_own_words():
    loading = {"error": {"code": 503, "message": "Loading model", "type": "unavailable_error"}}  # llama.cpp's
    gone = {"object": "error", "message": "The model `x` does not exist.", "type": "NotFoundError", "code": 404}
    t = Transport((503, {"Server": "llama.cpp"}, loading), (503, {"Server": "llama.cpp"}, loading),
                  (404, {}, {"error": "model 'nope' not found"}),  # Ollama's
                  (404, {}, gone),  # vLLM's
                  (422, {}, {"detail": [{"loc": ["body", "model"], "msg": "Field required"}]}),
                  (502, {"Content-Type": "text/html"}, b"<html>\n  <h1>Bad   Gateway</h1>\n</html>"), (500, {}, b""))
    at = Endpoint(HERE, transport=t)
    with pytest.raises(EndpointError) as busy:
        at.get("/health")
    assert str(busy.value) == "GET /health: HTTP 503: Loading model" and busy.value.status == 503
    assert not busy.value.refused and at.seen["status"] == 503
    got = at.answer("GET", "/health", ok=(200, 503))  # a status that is itself the news
    assert isinstance(got, Answer) and got.status == 503 and got.header("server") == "llama.cpp"
    assert got.data == loading and at.seen["error"] == ""
    for method, path, words in (("POST", "/api/show", "HTTP 404: model 'nope' not found"),
                                ("POST", "/v1/chat/completions", "HTTP 404: The model `x` does not exist."),
                                ("POST", "/tokenize",
                                 'HTTP 422: [{"loc": ["body", "model"], "msg": "Field required"}]'),
                                ("GET", "/v1/models", "HTTP 502: <html> <h1>Bad Gateway</h1> </html>"),
                                ("GET", "/version", "HTTP 500: no words came back")):
        with pytest.raises(EndpointError) as said:
            at.answer(method, path, json={} if method == "POST" else None)
        assert str(said.value) == f"{method} {path}: {words}"
    assert t.closed == 7


def test_a_plain_answer_is_read_as_text_and_a_callers_headers_go_with_every_ask():
    t = Transport((200, {"Content-Type": "text/plain; charset=utf-8"}, b"Ollama is running"), (200, {}, b""),
                  (200, {"Content-Type": "text/plain"}, b"not json"))
    at = Endpoint(HERE, transport=t)
    assert at.text("/") == "Ollama is running"
    assert t.sent[0]["url"] == HERE + "/" and t.sent[0]["headers"]["Accept"] == "*/*"
    assert at.text("/health") == "" and at.get("/") is None  # vLLM's health: 200 and nothing; no JSON: None
    manifest = "application/vnd.docker.distribution.manifest.v2+json"
    t = Transport((200, {"Content-Type": manifest}, [b'{"layers": []}']), (200, {}, [b"a\n"]))
    at = Endpoint(SAFE, headers={"accept": manifest, "X-Extra": "1", "accept-encoding": "gzip"},
                  agent="liminal-plugin-ollama/0.1.0", transport=t)
    assert at.get("/v2/library/qwen3/manifests/8b") == {"layers": []}
    assert t.sent[0]["headers"] == {"User-Agent": "liminal-plugin-ollama/0.1.0", "Accept": manifest, "X-Extra": "1",
                                    "Accept-Encoding": "identity"}  # the body is asked for as it is, whatever they say
    assert list(at.lines("GET", "/x")) == ["a"] and t.sent[1]["headers"]["Accept"] == manifest


# -- a stream ----------------------------------------------------------------------------------------------------
PULL = [b'{"status":"pulling manifest"}\n{"status":"pulling 6a0746a1ec1a","digest":"sha256:6a0746a1ec1a",'
        b'"total":4683073184}\r\n',
        b'\n{"status":"pulling 6a0746a1ec1a","digest":"sha256:6a0746a1ec1a","total":4683073184,"comp',
        b'leted":2147483648}\n\n',
        b'{"status":"verifying sha256 digest"}\n{"status":"success"}']  # a pull's lines as they come (research 7)


def test_a_stream_is_handed_on_line_by_line_as_it_comes():
    t = Transport((200, {"Content-Type": "application/x-ndjson"}, PULL))
    at = Endpoint(HERE, timeout=30, transport=t)
    lines, read = [], []
    for line in at.lines("post", "/api/pull", json={"model": "qwen3:8b", "stream": True}):
        lines.append(json.loads(line))
        read.append(t.read)
    assert [x["status"] for x in lines] == ["pulling manifest", "pulling 6a0746a1ec1a", "pulling 6a0746a1ec1a",
                                            "verifying sha256 digest", "success"]
    assert lines[2]["completed"] == 2147483648  # a line that came in two pieces is one line
    assert read == [1, 1, 3, 4, 4]  # each handed on once it is whole, not when the stream ends
    sent = t.sent[0]
    assert (sent["method"], sent["url"], sent["stream"], sent["timeout"]) == ("POST", HERE + "/api/pull", True, 30.0)
    assert sent["body"] == b'{"model":"qwen3:8b","stream":true}' and sent["headers"]["Accept"] == "*/*"
    assert t.closed == 1 and at.seen["status"] == 200 and at.seen["error"] == ""
    events = [b'event: download_progress\ndata: {"x":{"done":1,"total":2}}\n\n',
              b": keep-alive\n\nevent: download_finished\r\ndata: {}\r\n\r\n"]  # a server-sent stream: as it is
    t = Transport((200, {"Content-Type": "text/event-stream"}, events))
    assert list(Endpoint(HERE, transport=t).lines("GET", "/models/sse")) == [
        "event: download_progress", 'data: {"x":{"done":1,"total":2}}', ": keep-alive", "event: download_finished",
        "data: {}"]
    assert t.sent[0]["body"] is None and "Content-Type" not in t.sent[0]["headers"]


def test_a_stream_is_left_at_its_deadline():
    clock = Clock()

    def later(piece: bytes):
        def read():
            clock.now += 20.0
            return piece
        return read
    t = Transport((200, {}, [later(b"one\n"), later(b"two\n"), later(b"three\n"), later(b"never\n")]))
    at = Endpoint(HERE, transport=t, clock=clock)
    assert list(at.lines("GET", "/models/sse", deadline=50)) == ["one", "two", "three"]  # no error: it ends
    assert t.read == 3 and t.closed == 1  # nothing more read of it, and the connection let go
    assert at.seen["status"] == 200 and at.seen["seconds"] == 60.0
    assert at.seen["error"] == "GET /models/sse: its stream was left after 50 s, before its end"


def test_a_stream_ends_with_cancelled_once_its_cancel_says_so():
    stop: list = []
    t = Transport((200, {}, [b"one\ntwo\nthree\n", b"four\n"]))
    at = Endpoint(HERE, transport=t)
    got = []
    with pytest.raises(Cancelled):
        for line in at.lines("POST", "/api/pull", json={}, cancel=lambda: bool(stop)):
            got.append(line)
            if line == "two":
                stop.append(1)
    assert got == ["one", "two"] and t.read == 1 and t.closed == 1  # not one line more, and the connection let go
    assert at.seen["error"] == "POST /api/pull: cancelled"
    log = Output()  # a job's log: its flag is the cancel
    log.cancel()
    t = Transport((200, {}, [b"one\n"]))
    with pytest.raises(Cancelled):
        list(Endpoint(HERE, transport=t).lines("GET", "/models/sse", cancel=lambda: log.cancelled))
    assert t.sent == []  # cancelled before it began: nothing is sent


def test_a_cancel_that_came_while_a_read_waited_ends_the_stream_as_cancelled():
    stop: list = []

    def stalled():  # the user cancels while nothing comes; the read then ends at the socket's own wait
        stop.append(1)
        raise TimeoutError("timed out")
    for cancel, ends in ((lambda: bool(stop), Cancelled), (None, EndpointError)):
        stop.clear()
        t = Transport((200, {}, [b"one\n", stalled]))
        at = Endpoint(HERE, transport=t)
        got = []
        with pytest.raises(ends) as ended:
            for line in at.lines("POST", "/api/pull", json={}, cancel=cancel):
                got.append(line)
        assert got == ["one"] and t.closed == 1
    assert at.seen["error"] == str(ended.value) == ("POST /api/pull: its stream broke off: no answer from "
                                                    "127.0.0.1:11434 within 3 s")


def test_a_stream_that_is_none_is_said():
    t = Transport((200, {}, [b"x" * LINE_MOST, b"y\n"]),  # a line past the bound, come in two pieces
                  (200, {}, [b"x" * LINE_MOST + b"\r\n", b"x" * (LINE_MOST + 1)]),  # one at the bound, one past it
                  (404, {}, {"error": "model 'nope' not found"}),
                  (200, {}, [b"one\n", ConnectionResetError("reset by peer")]),
                  ConnectionRefusedError(111, "Connection refused"),
                  (200, {"Content-Encoding": "gzip"}, [b"\x1f\x8b"]))
    at = Endpoint(HERE, transport=t)
    with pytest.raises(EndpointError, match="GET /a: a line of its stream is longer than 64.0 KB: not read") as long:
        list(at.lines("GET", "/a"))
    assert long.value.status == 200
    got = []
    with pytest.raises(EndpointError, match="longer than 64.0 KB"):
        for line in at.lines("GET", "/a"):
            got.append(line)
    assert got == ["x" * LINE_MOST]
    with pytest.raises(EndpointError) as missing:
        list(at.lines("POST", "/api/pull", json={"model": "nope"}))
    assert str(missing.value) == "POST /api/pull: HTTP 404: model 'nope' not found" and missing.value.status == 404
    got = []
    with pytest.raises(EndpointError) as broke:
        for line in at.lines("GET", "/c"):
            got.append(line)
    assert got == ["one"] and broke.value.status == 0
    assert str(broke.value) == ("GET /c: its stream broke off: no answer from 127.0.0.1:11434: ConnectionResetError: "
                                "reset by peer")
    with pytest.raises(EndpointError, match="GET /d: nothing listens at 127.0.0.1:11434"):
        list(at.lines("GET", "/d"))
    with pytest.raises(EndpointError, match="gzip-encoded, which was not asked for"):
        list(at.lines("GET", "/e"))
    assert t.closed == 5 and at.seen["error"].startswith("GET /e: its answer comes gzip-encoded")


def test_a_stream_left_early_lets_its_connection_go():
    t = Transport((200, {}, [b"one\n", b"two\n", b"three\n"]))
    at = Endpoint(HERE, transport=t)
    stream = at.lines("GET", "/models/sse")
    assert t.sent == []  # nothing is sent until the first line is asked for
    assert next(stream) == "one" and t.closed == 0
    stream.close()
    assert t.closed == 1 and t.read == 1 and at.seen["error"] == ""


# -- the OpenAI-compatible two -----------------------------------------------------------------------------------
# GET /v1/models as each server answers it (research-llama-cpp 7, research-vllm 7; Ollama's as its OpenAI
# compatibility page gives it: research-ollama 7 names the path)
LLAMACPP = {"object": "list", "data": [
    {"id": "ggml-org/gemma-3-4b-it-GGUF:Q4_K_M", "object": "model", "created": 1763300000, "owned_by": "llamacpp",
     "architecture": {"input_modalities": ["text", "image"], "output_modalities": ["text"]},
     "meta": {"vocab_type": 1, "n_vocab": 262208, "n_ctx_train": 131072, "n_embd": 2560, "n_params": 3880263168,
              "size": 2489757856}}]}
OLLAMA = {"object": "list", "data": [
    {"id": "qwen3:8b", "object": "model", "created": 1757401200, "owned_by": "library"},
    {"id": "hf.co/bartowski/Qwen_Qwen3-8B-GGUF:Q4_K_M", "object": "model", "created": 1757404800,
     "owned_by": "bartowski"}]}
VLLM = {"object": "list", "data": [
    {"id": "qwen3-8b", "object": "model", "created": 1763300000, "owned_by": "vllm", "root": "Qwen/Qwen3-8B",
     "parent": None, "max_model_len": 40960,
     "permission": [{"id": "modelperm-1", "object": "model_permission", "allow_sampling": True}]},
    {"id": "my-adapter", "object": "model", "created": 1763300001, "owned_by": "vllm", "root": "/adapters/mine",
     "parent": "qwen3-8b", "max_model_len": None, "permission": []}]}


def test_models_as_the_three_servers_list_them():
    t = Transport((200, {}, LLAMACPP), (200, {}, OLLAMA), (200, {}, VLLM))
    at = Endpoint(HERE, transport=t)
    assert at.models() == [{"id": "ggml-org/gemma-3-4b-it-GGUF:Q4_K_M", "owner": "llamacpp", "context": 131072}]
    assert at.models() == [{"id": "qwen3:8b", "owner": "library", "context": None},  # Ollama's list says no context
                           {"id": "hf.co/bartowski/Qwen_Qwen3-8B-GGUF:Q4_K_M", "owner": "bartowski", "context": None}]
    assert at.models() == [{"id": "qwen3-8b", "owner": "vllm", "context": 40960},
                           {"id": "my-adapter", "owner": "vllm", "context": None}]
    assert {s["url"] for s in t.sent} == {HERE + "/v1/models"} and {s["method"] for s in t.sent} == {"GET"}
    odd = {"object": "list", "data": [{"id": "a", "max_model_len": True, "meta": "x"}, {"object": "model"}, "b",
                                      {"id": ""}, {"id": "c", "owned_by": 7, "meta": {"n_ctx_train": 4096.0}}]}
    t = Transport((200, {}, odd), (200, {}, {"models": []}), (200, {"Content-Type": "text/html"}, b"<html></html>"))
    at = Endpoint(HERE, transport=t)
    assert at.models() == [{"id": "a", "owner": "", "context": None}, {"id": "c", "owner": "", "context": 4096}]
    for _ in range(2):  # Ollama's own /api/tags shape, a web page: no OpenAI-compatible list
        with pytest.raises(EndpointError, match="GET /v1/models: what answered is no list of models") as said:
            at.models()
        assert said.value.status == 200 and at.seen["error"] == str(said.value)


def test_a_chat_is_asked_once_and_its_answer_cut():
    said = "word " * 1000  # 5,000 characters
    whole = {"id": "chatcmpl-1", "object": "chat.completion", "created": 1763300000, "model": "qwen3:8b",
             "choices": [{"index": 0, "message": {"role": "assistant", "content": said}, "finish_reason": "length"}],
             "usage": {"prompt_tokens": 21, "completion_tokens": 512, "total_tokens": 533}}
    clock = Clock()

    def answered():
        clock.now += 1.5
        return json.dumps(whole).encode()
    t = Transport((200, {"Content-Type": "application/json"}, [answered]))
    at = Endpoint(HERE, key=KEY, transport=t, clock=clock)
    out = at.chat("qwen3:8b", "Say hello.", system="Be brief.")
    assert out == {"text": said[:ANSWER_CHARS], "cut": True, "model": "qwen3:8b", "finish": "length",
                   "tokens": {"prompt": 21, "completion": 512}, "seconds": 1.5}
    assert len(out["text"]) == ANSWER_CHARS == 4000
    sent = t.sent[0]
    assert (sent["method"], sent["url"]) == ("POST", HERE + "/v1/chat/completions")
    assert sent["timeout"] == CHAT_S == 120.0 and sent["stream"] is False and len(t.sent) == 1
    assert json.loads(sent["body"]) == {
        "model": "qwen3:8b", "max_tokens": 512, "stream": False,
        "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Say hello."}]}
    short = {"model": "as-it-is-served", "choices": [{"message": {"role": "assistant", "content": "Hello."},
                                                      "finish_reason": "stop"}]}
    parts = {"choices": [{"message": {"content": [{"type": "text", "text": "Hel"}, {"type": "text", "text": "lo."}]}}]}
    t = Transport((200, {}, short), (200, {}, parts), (200, {}, {"choices": []}), (200, {}, b"busy"))
    at = Endpoint(HERE, transport=t)
    out = at.chat("m", "Say hello.", max_tokens=64, timeout=30)
    assert out == {"text": "Hello.", "cut": False, "model": "as-it-is-served", "finish": "stop",
                   "tokens": {"prompt": None, "completion": None}, "seconds": out["seconds"]}
    assert json.loads(t.sent[0]["body"]) == {"model": "m", "max_tokens": 64, "stream": False,
                                             "messages": [{"role": "user", "content": "Say hello."}]}
    assert t.sent[0]["timeout"] == 30.0
    out = at.chat("m", "Say hello.")
    assert (out["text"], out["model"], out["finish"]) == ("Hello.", "m", "")  # what it leaves out is not made up
    for _ in range(2):
        with pytest.raises(EndpointError, match="POST /v1/chat/completions: its answer holds no choice"):
            at.chat("m", "Say hello.")


# -- how far a download is ---------------------------------------------------------------------------------------
def test_progress_is_said_every_two_seconds_at_most():
    clock, lines = Clock(), []
    progress = Progress(lines.append, clock=clock)
    progress.say(0, 63_000_000, "qwen3:8b")  # the first word at once
    progress.say(1_000_000, 63_000_000, "qwen3:8b")  # too soon
    clock.now += 1.9
    progress.say(2_000_000, 63_000_000, "qwen3:8b")  # still too soon
    clock.now += 0.1
    progress.say(12_900_000, 63_000_000, "qwen3:8b")
    progress.say(13_000_000, 63_000_000, "another")  # of something new: at once
    clock.now += 2
    progress.say(5 << 20, None, "another")  # its whole size not known
    clock.now += 2
    progress.say(70_000_000, 63_000_000)  # more than the whole: 100% at most
    progress.end("qwen3:8b is here (60.1 MB)")
    progress.say(1, 2)  # after the last word, the next is said at once
    assert lines == ["qwen3:8b: 0 B of 60.1 MB (0%)", "qwen3:8b: 12.3 MB of 60.1 MB (20%)",
                     "another: 12.4 MB of 60.1 MB (20%)", "another: 5.0 MB so far", "66.8 MB of 60.1 MB (100%)",
                     "qwen3:8b is here (60.1 MB)", "1 B of 2 B (50%)"]

    def gone(line):
        raise RuntimeError("the panel is gone")
    for log in (gone, None, "no function"):  # the work goes on without its panel
        Progress(log).say(1, 2)
        Progress(log).end("done")


# -- the `requests` transport, over a stand-in adapter -----------------------------------------------------------
class Body(io.BytesIO):
    """An answer's body as the connection gives it; its reads counted."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.reads = 0

    def read(self, n=-1):
        self.reads += 1
        return super().read(n)

    def read1(self, n=-1):
        self.reads += 1
        return super().read1(n)


class Adapter(requests.adapters.BaseAdapter):
    """`requests`' way to a host as a stand-in: each request answered in order (status, headers, body), nothing
    connected; what was sent is kept, and how."""

    def __init__(self, *answers):
        super().__init__()
        self.answers, self.sent, self.bodies, self.closed = list(answers), [], [], 0

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        self.sent.append({"method": request.method, "url": request.url, "headers": dict(request.headers),
                          "body": request.body, "stream": stream, "timeout": timeout, "verify": verify, "cert": cert,
                          "proxies": proxies})
        status, headers, data = self.answers.pop(0)
        self.bodies.append(Body(data))
        response = requests.Response()
        response.status_code, response.headers = status, CaseInsensitiveDict(headers)
        response.url, response.request = request.url, request
        response.raw = urllib3.HTTPResponse(body=self.bodies[-1], headers=headers, status=status,
                                            preload_content=False, decode_content=False)
        return response

    def close(self):
        self.closed += 1


class Trickle(io.RawIOBase):
    """A connection as a stand-in under the real stack: the answer's head at once, then its body one byte a receive,
    the clock moved on `step` seconds with each (each within the socket's wait, so no read of it times out)."""

    def __init__(self, head: bytes, body: bytes, clock: Clock, step: float):
        super().__init__()
        self.head, self.body, self.clock, self.step, self.reads = head, body, clock, step, 0

    def readable(self):
        return True

    def readinto(self, b):
        if self.head:
            n = min(len(b), len(self.head))
            b[:n], self.head = self.head[:n], self.head[n:]
            return n
        if self.reads >= len(self.body):
            return 0
        self.clock.now += self.step
        b[:1] = self.body[self.reads:self.reads + 1]
        self.reads += 1
        return 1


class Connection:
    """What http.client reads an answer from (a socket's makefile), over a Trickle."""

    def __init__(self, raw: Trickle):
        self.raw = raw

    def makefile(self, mode):
        return io.BufferedReader(self.raw)


class RealStack(requests.adapters.BaseAdapter):
    """`requests`' way to a host as a stand-in whose answers come through the real stack: http.client's answer over
    a Trickle, in urllib3's, in requests', as a connection would give them; nothing connected."""

    def __init__(self, *connections: Trickle):
        super().__init__()
        self.connections, self.closed = list(connections), 0

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        answer = http.client.HTTPResponse(Connection(self.connections.pop(0)), method=request.method)
        answer.begin()
        headers = dict(answer.getheaders())
        response = requests.Response()
        response.status_code, response.headers = answer.status, CaseInsensitiveDict(headers)
        response.raw = urllib3.HTTPResponse(body=answer, headers=headers, status=answer.status, preload_content=False,
                                            decode_content=False, original_response=answer)
        response.url, response.request = request.url, request
        return response

    def close(self):
        self.closed += 1


def mount(monkeypatch, stand_in: requests.adapters.BaseAdapter) -> None:
    """The real session (what it takes from the environment: nothing), its two ways out replaced by one stand-in."""
    real = endpoint._session

    def session():
        made = real()
        assert made.trust_env is False and dict(made.headers) == {}
        for prefix in list(made.adapters):
            made.mount(prefix, stand_in)
        return made
    monkeypatch.setattr(endpoint, "_session", session)


@pytest.fixture
def adapter(monkeypatch):
    stand_in = Adapter()
    mount(monkeypatch, stand_in)
    return stand_in


def test_the_requests_transport_takes_nothing_from_the_environment(adapter, monkeypatch, tmp_path):
    netrc = tmp_path / "netrc"
    netrc.write_text("machine models.example login me password from-the-netrc-file\n", encoding="utf-8")
    monkeypatch.setenv("NETRC", str(netrc))
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"):
        monkeypatch.setenv(name, address("http", "proxy.example:3128"))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "ca.pem"))
    adapter.answers += [(200, {"Content-Type": "application/json"}, b'{"version":"0.33.0"}'),
                        (200, {}, b'{"status":"success"}\n')]
    at = Endpoint(SAFE)  # no transport given: the `requests` one
    assert at.get("/version") == {"version": "0.33.0"}
    sent = adapter.sent[0]
    assert (sent["method"], sent["url"], sent["body"]) == ("GET", SAFE + "/version", None)
    assert sent["proxies"] == {} and sent["verify"] is True and sent["cert"] is None and sent["timeout"] == LOOK_S
    assert sent["headers"] == {"User-Agent": endpoint.AGENT, "Accept-Encoding": "identity",
                               "Accept": "application/json"}
    assert adapter.bodies[0].closed and adapter.closed > 0  # the answer and the session let go
    lines = list(Endpoint(SAFE, key=KEY).lines("POST", "/api/pull", json={"model": "qwen3:8b"}))
    assert lines == ['{"status":"success"}']
    sent = adapter.sent[1]
    assert sent["body"] == b'{"model":"qwen3:8b"}' and sent["headers"]["Authorization"] == f"Bearer {KEY}"
    assert sent["headers"]["Content-Type"] == "application/json" and sent["headers"]["Content-Length"] == "20"


def test_the_requests_transport_follows_no_redirect_and_reads_none(adapter):
    elsewhere = address("https", "elsewhere.example/v1/models")
    adapter.answers += [(302, {"Location": elsewhere}, b"the redirect's own body"),
                        (302, {"Location": elsewhere}, b"the redirect's own body"),
                        (200, {}, b"x" * 200_000), (200, {}, b"y" * 3000)]
    reply = endpoint.requests_transport("GET", SAFE + "/v1/models", {"User-Agent": "x"}, None, 5.0, False)
    assert reply.status == 302 and reply.headers["Location"] == elsewhere
    assert len(adapter.sent) == 1 and adapter.bodies[0].reads == 0  # asked once; not a byte of its body read
    reply.close()
    assert adapter.bodies[0].closed and adapter.bodies[0].reads == 0
    with pytest.raises(EndpointError) as moved:  # an instance answers at its own address or not at all
        Endpoint(SAFE).models()
    assert moved.value.status == 302 and str(moved.value) == "GET /v1/models: HTTP 302: the redirect's own body"
    assert len(adapter.sent) == 2 and {s["url"] for s in adapter.sent} == {SAFE + "/v1/models"}
    reply = endpoint.requests_transport("GET", SAFE + "/big", {}, None, 5.0, False)  # an answer: in pieces
    assert [len(piece) for piece in reply.chunks] == [65536, 65536, 65536, 3392]
    reply.close()
    reply = endpoint.requests_transport("GET", SAFE + "/stream", {}, None, 5.0, True, 1000)  # a stream: as it comes
    assert b"".join(reply.chunks) == b"y" * 3000
    reply.close()


def test_a_slow_sender_is_looked_at_after_every_byte_through_the_requests_transport(monkeypatch):
    """A server that sends a byte every 2.9 s (each within the 3 s a socket read waits) is not read until 64 KB have
    come: its answer is refused once twice its wait has gone, after the third byte; a stream's cancel and its
    deadline are seen after the byte they came with."""
    clock = Clock()
    head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n"
    slow = Trickle(head, b"x" * 100_000, clock, 2.9)
    stream = b'{"status":"pulling"}\n' * 3  # three lines of 21 bytes
    lines = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: %d\r\n\r\n" % len(stream)
    asked, left = Trickle(lines, stream, clock, 0.5), Trickle(lines, stream, clock, 20.0)
    stack = RealStack(slow, asked, left)
    mount(monkeypatch, stack)
    at = Endpoint(SAFE, clock=clock)
    with pytest.raises(EndpointError) as late:
        at.get("/v1/models")
    assert str(late.value) == "GET /v1/models: its answer was not whole after 6 s: not read"
    assert slow.reads == 3 and slow.closed and stack.closed > 0  # three bytes, not 65,536; all of it let go
    got = []
    with pytest.raises(Cancelled):
        for line in at.lines("POST", "/api/pull", json={"model": "qwen3:8b"}, cancel=lambda: asked.reads >= 22):
            got.append(line)
    assert got == ['{"status":"pulling"}'] and asked.reads == 22  # the byte after the first line, not the rest
    assert list(at.lines("GET", "/api/pull", deadline=60)) == [] and left.reads == 3 and left.closed  # 20 s a byte


def test_without_a_transport_the_requests_one_is_the_way(monkeypatch):
    asked = []

    def transport(method, url, headers, body, timeout, stream):
        asked.append((method, url, timeout, stream))
        return Reply(200, {}, [b"{}"])
    monkeypatch.setattr(endpoint, "requests_transport", transport)
    assert Endpoint(HERE, timeout=1.5).get("/api/version") == {}
    assert asked == [("GET", HERE + "/api/version", 1.5, False)]
    assert Reply(204).headers == {} and list(Reply(204).chunks) == [] and Reply(204).close() is None


# -- one deadline for the whole of a request ---------------------------------------------------------------------
STEP_S = 0.02  # a stand-in socket's next byte comes this long after its last: within any socket's wait
SAFETY_S = 10.0  # what a stand-in waits at most to be shut: a deadline that does not hold fails a test, never hangs it


def watchdogs() -> list:
    """The deadlines' watchdogs alive now (each a thread of its request's own)."""
    return [t for t in threading.enumerate() if t.name == "endpoint-deadline"]


@pytest.fixture(autouse=True)
def no_watchdog_left():
    """Every test of this file, those through the requests transport over stand-in adapters too: no deadline's
    watchdog outlives it."""
    yield
    assert watchdogs() == [], "a deadline's watchdog outlived its request"


@pytest.fixture(params=[True, False], ids=["windows", "linux"])
def closes(request, monkeypatch):
    """A test of the deadline run as each system shuts a socket, whichever system this is: as Windows does, where a
    wait ends only once its socket is closed (the watchdog closes a plain socket as well as shutting it down, and a
    call on it then finds no socket: ENOTSOCK), and as Linux does (shut down alone: a read then gets nothing)."""
    monkeypatch.setattr(endpoint, "_CLOSES", request.param)
    return request.param


class Feed(io.RawIOBase):
    """What http.client reads an answer from (a socket's makefile), over a Wire."""

    def __init__(self, wire: Wire):
        super().__init__()
        self.wire = wire

    def readable(self):
        return True

    def readinto(self, b):
        return self.wire.give(b)

    def close(self):
        if not self.closed:
            self.wire.let_go()
        super().close()


class Wire:
    """A socket as a stand-in under the whole real stack (requests, urllib3's connection, http.client): its answer's
    `fast` bytes come at once, then `drip` again and again, a byte every STEP_S, for as long as it is not shut; `hangs`
    names the step it waits at until it is shut ("connect", its peer silent; or as a TLS socket "handshake", its peer
    still sending within each wait), or is "connected": a connect made just in time, its deadline coming and going as
    it ends. What was sent is kept, and how it ended (`ended`: "shutdown" and "close", as they were asked).

    Shut as the system endpoint._CLOSES names shuts a socket (each test of the deadline runs both, on any system).
    Shut down where that ends a wait (Linux): a connect or a handshake fails, and a read gets nothing. Shut down where
    it ends none (Windows): a wait ends at its peer's next byte, which resets the connection, and every later call
    fails (ESHUTDOWN). Its C socket closed (the watchdog's close, at once whatever files made of it are open, as it
    closes a plain socket on Windows; or its owner's, once no file made of it is open, as socket.close() puts it off):
    a wait ends then, and every call fails as one on a socket that is no more does (ENOTSOCK), each counted in
    `notsock`: on a TLS socket, a call OpenSSL would have made through a freed number, the next socket's made."""

    def __init__(self, fast: bytes = b"", drip: bytes = b"", hangs: str = ""):
        self.fast, self.drip, self.hangs = fast, drip, hangs
        self.woken = threading.Event()  # what waits on it ends: shut down where that ends a wait, or closed
        self.down = self.killed = False  # shut down; its C socket closed by the watchdog
        self.sent, self.given, self.handshakes, self.ended, self.notsock = b"", 0, 0, [], 0
        self.where = self.timeout = None
        self.files, self.closing = 0, False  # the files made of it still open; its owner's close() asked
        self.detached = False  # a TLS socket took its place (ssl detaches the plain one: it closes nothing then)
        self.waited_out = False  # waited SAFETY_S without being shut: what a deadline that holds never lets happen
        self.dripping = 0.0  # when its first slow byte was given

    @property
    def closed(self) -> bool:
        """Closed for good by its owner: close() asked, and every file made of it closed too."""
        return self.closing and self.files == 0

    @property
    def gone(self) -> bool:
        """Its C socket closed: by the watchdog, or by its owner for good."""
        return self.killed or self.closed

    def detach(self) -> int:
        self.detached = True
        return -1

    def let_go(self) -> None:
        self.files -= 1
        if self.closed:
            self.woken.set()

    def _wait(self, sending: bool) -> None:
        """Until it is shut: woken; or, its peer `sending` (a byte within each wait), shut down by the time the next
        byte comes, which ends a wait where a shutdown does not (Windows: the byte resets the connection)."""
        began = time.monotonic()
        while not self.woken.wait(STEP_S) and not (sending and self.down):
            if time.monotonic() - began > SAFETY_S:
                self.waited_out = True
                return

    def _check(self) -> None:
        """A call on it as it is now: OSError once its C socket is closed (ENOTSOCK, counted), and on Windows once it
        is shut down (ESHUTDOWN)."""
        if self.gone:
            self.notsock += 1
            raise OSError(errno.ENOTSOCK, "an operation was attempted on something that is not a socket")
        if self.down and endpoint._CLOSES:
            raise OSError(errno.ESHUTDOWN, "a call on the socket after it was shut down")

    def setsockopt(self, *option):
        pass

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def connect(self, where):
        self.where = where
        if self.hangs == "connected":  # made: its deadline comes, and its watchdog is done, as the connect ends
            for thread in watchdogs():
                thread.join(SAFETY_S)
            return
        if self.hangs == "connect":
            self._wait(sending=False)
        self._check()
        if self.down:
            raise ConnectionResetError(errno.ECONNRESET, "the connection was reset")

    def do_handshake(self):
        self.handshakes += 1
        if self.hangs == "handshake":
            self._wait(sending=True)
        self._check()
        if self.down:
            raise ssl.SSLEOFError(8, "EOF occurred in violation of protocol")

    def sendall(self, data):
        self._check()
        if self.down:
            raise BrokenPipeError(errno.EPIPE, "the connection was shut")
        self.sent += bytes(data)

    def makefile(self, mode="rb", *args, **kwargs):
        self.files += 1
        return io.BufferedReader(Feed(self))

    def give(self, b) -> int:
        self._check()
        if self.down:
            return 0  # (a socket shut down reads nothing)
        if self.given < len(self.fast):
            n = min(len(b), len(self.fast) - self.given)
            b[:n] = self.fast[self.given:self.given + n]
            self.given += n
            return n
        if not self.drip:
            return 0  # the answer's end
        if self.woken.wait(STEP_S) or self.down:  # shut while the next byte was waited for: as a shut socket reads
            self._check()
            return 0
        self.dripping = self.dripping or time.monotonic()
        if time.monotonic() - self.dripping > SAFETY_S:  # never shut: it gives up, and the test says so
            self.waited_out = True
            return 0
        k = (self.given - len(self.fast)) % len(self.drip)
        b[:1] = self.drip[k:k + 1]
        self.given += 1
        return 1

    def shutdown(self, how):
        self.ended.append("shutdown")
        self.down = True
        if not endpoint._CLOSES:  # (on Windows a shutdown ends no wait: the peer's next byte does, or a close)
            self.woken.set()

    def close(self):
        self.ended.append("close")
        if threading.current_thread().name == "endpoint-deadline":  # the watchdog's: the C socket itself, at once
            self.killed = True
        else:  # its owner's: put off while a file made of it is open, as socket.close() puts it off
            self.closing = True
        if self.gone:
            self.woken.set()


class Context:
    """A TLS context as a stand-in, no ssl under it: what urllib3 sets on it and loads into it kept; its wrap_socket
    takes the plain socket's number as ssl does (`taking()`, when given, is called as it is taken), notes whether that
    number was closed under it meanwhile (`freed`: the TLS socket's would then be the next socket's made), and hands
    back `tls`, a Wire of its own (ssl's socket takes the plain one's place, and shutting that one no longer reaches
    it)."""

    def __init__(self, tls: Wire, taking=None):
        self.tls, self.taking = tls, taking
        self.verify_mode, self.check_hostname = ssl.CERT_NONE, True
        self.loaded, self.alpn, self.wrapped, self.freed = [], [], [], []

    def load_verify_locations(self, *args):
        self.loaded.append(args)

    def set_alpn_protocols(self, protocols):
        self.alpn = list(protocols)

    def wrap_socket(self, sock, **kwargs):
        self.wrapped.append((sock, kwargs))
        if self.taking is not None:
            self.taking()
        self.freed.append(sock.gone)
        sock.detach()  # as ssl takes the plain socket's place
        return self.tls


class Wires:
    """What a request's connection reaches, as stand-ins: every name found at `addresses` documentation addresses
    (`found()`, when given, is called before it is: a slow lookup, or one that fails), and each socket made the next
    Wire of `ready` (kept in `made`)."""

    def __init__(self):
        self.ready, self.made, self.looked = [], [], []
        self.addresses, self.found = 1, None

    def getaddrinfo(self, host, port, family=0, kind=0, proto=0, flags=0):
        self.looked.append((host, port))
        if self.found is not None:
            self.found()
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (f"192.0.2.{n + 1}", port))
                for n in range(self.addresses)]

    def socket(self, family, kind, proto):
        self.made.append(self.ready.pop(0))
        return self.made[-1]


@pytest.fixture
def wires(monkeypatch, no_outside):
    """The name looked up and the sockets made, stood in for (after the guard's own stand-ins)."""
    stand_in = Wires()
    monkeypatch.setattr(socket, "getaddrinfo", stand_in.getaddrinfo)
    monkeypatch.setattr(endpoint, "_socket", stand_in.socket)
    return stand_in


def timed(ask) -> tuple[BaseException | None, float]:
    """What `ask()` raised (None: nothing), and the seconds it took."""
    began = time.monotonic()
    try:
        ask()
    except Exception as e:  # noqa: BLE001 - looked at by the test
        return e, time.monotonic() - began
    return None, time.monotonic() - began


def test_a_request_hung_at_its_connection_is_cut_off_at_its_deadline(wires, closes):
    """A connect that outlasts the deadline (an address that answers nothing, the first of two): the watchdog shuts
    the socket it holds from before its connect, and the ask fails at once, as one whose read waited too long, in the
    deadline's own seconds (twice the wait); the second address is never tried, and nothing outlives the ask."""
    wires.addresses = 2
    wires.ready += [Wire(hangs="connect"), Wire(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")]
    at = Endpoint(HERE, timeout=0.1, clock=Clock())  # its own clock stands still: only the watchdog can end the ask
    late, took = timed(lambda: at.get("/api/version"))
    assert isinstance(late, EndpointError) and late.status == 0, late
    assert str(late) == "GET /api/version: no answer from 127.0.0.1:11434 within 0.2 s" == at.seen["error"]
    first = wires.made[0]
    assert 0.15 <= took < 5.0 and not first.waited_out and first.where == ("192.0.2.1", 11434)
    assert len(wires.made) == 1 and wires.looked == [("127.0.0.1", 11434)]  # one address tried
    assert "shutdown" in first.ended and first.closed and watchdogs() == []


def test_a_request_hung_at_its_tls_handshake_is_cut_off_at_its_deadline(wires, monkeypatch, closes):
    """A handshake that never ends: the TLS socket is held from before its handshake (endpoint._Held), so the watchdog's
    shutting reaches it (shutting the plain one under it would not), and the ask fails at its deadline. The watchdog
    only shuts it down, on Windows too (where its peer's next byte then ends the wait), and its owner closes it once
    its handshake has failed: OpenSSL never reads or writes through a number closed under it. urllib3 set on the
    context what it sets on its own (its check, its CA bundle, ALPN), and the context was asked for the address's name
    and for no handshake of its own."""
    plain, tls = Wire(), Wire(hangs="handshake")
    wires.ready.append(plain)
    context = Context(tls)
    monkeypatch.setattr(endpoint, "_context", lambda: context)
    at = Endpoint(SAFE, timeout=0.1, clock=Clock())
    late, took = timed(at.models)
    assert isinstance(late, EndpointError), late
    assert str(late) == "GET /v1/models: no answer from models.example:443 within 0.2 s" == at.seen["error"]
    assert 0.15 <= took < 5.0 and tls.handshakes == 1 and not tls.waited_out
    assert tls.ended == ["shutdown", "close"] and tls.notsock == 0 and tls.closed  # shut down; closed by its owner
    assert plain.detached and context.freed == [False] and watchdogs() == []
    (sock, kwargs), = context.wrapped
    assert sock is plain and kwargs["server_hostname"] == "models.example"
    assert kwargs["do_handshake_on_connect"] is False  # its own, made once the TLS socket was held
    assert context.verify_mode == ssl.CERT_REQUIRED and len(context.loaded) == 1 and context.alpn == ["http/1.1"]


def test_a_plain_socket_is_let_go_before_a_tls_socket_takes_its_number(wires, monkeypatch, closes):
    """ssl copies the plain socket's number for OpenSSL, which reads and writes through it from then on, and detaches
    the plain socket: the watch lets that one go first and holds the TLS one in its place, so that a deadline that
    comes as the number is taken closes nothing under it (on Windows a closed number goes to the next socket made, and
    the TLS socket's reads and writes would go on in that one's connection). A deadline that came before the TLS
    context was asked hands it nothing. Either way the ask is cut off at its deadline, and nothing outlives it."""
    def deadline():  # the deadline comes, and its watchdog is done
        for thread in watchdogs():
            thread.join(SAFETY_S)
    contexts: list = []
    monkeypatch.setattr(endpoint, "_context", lambda: contexts[-1])
    at = Endpoint(SAFE, timeout=0.1, clock=Clock())
    plain, tls = Wire(), Wire()
    wires.ready.append(plain)
    contexts.append(Context(tls, taking=deadline))  # it comes as ssl takes the plain socket's number
    late, took = timed(at.models)
    assert str(late) == "GET /v1/models: no answer from models.example:443 within 0.2 s" == at.seen["error"]
    assert contexts[0].freed == [False] and plain.detached and plain.ended == ["close"]  # by its owner alone
    assert tls.ended == ["shutdown", "close"] and tls.notsock == 0 and tls.closed and 0.15 <= took < 5.0
    early = Wire(hangs="connected")  # its deadline comes as its connect ends: before the TLS context is asked
    wires.ready.append(early)
    contexts.append(Context(Wire()))
    late, took = timed(at.models)
    assert str(late) == "GET /v1/models: no answer from models.example:443 within 0.2 s" == at.seen["error"]
    assert contexts[1].wrapped == [] and early.closed and 0.15 <= took < 5.0 and watchdogs() == []


def test_an_answer_whose_head_comes_a_byte_at_a_time_is_cut_off_at_its_deadline(wires, closes):
    """The status line at once, then a header a byte every STEP_S: no read waits as long as the socket's timeout, and
    before 1.76.0 nothing bounded them all. The watchdog shuts the socket at the deadline: the ask fails then, in the
    deadline's seconds, and what http.client made of the head it had is not taken for an answer."""
    wire = Wire(b"HTTP/1.1 200 OK\r\n", b"X-Slow: 1\r\n")
    wires.ready.append(wire)
    at = Endpoint(HERE, timeout=0.1, clock=Clock())
    late, took = timed(lambda: at.get("/api/tags"))
    assert isinstance(late, EndpointError) and str(late) == "GET /api/tags: no answer from 127.0.0.1:11434 within 0.2 s"
    assert 0.15 <= took < 5.0 and wire.given > len(wire.fast) + 2 and not wire.waited_out  # its bytes kept coming
    assert wire.sent.startswith(b"GET /api/tags HTTP/1.1\r\n") and "shutdown" in wire.ended and wire.closed
    assert watchdogs() == []


def test_an_answer_whose_body_comes_a_byte_at_a_time_is_cut_off_at_its_deadline(wires, closes):
    """The head at once, then the body a byte every STEP_S, no length said (it ends with its connection): the watchdog
    shuts the socket at the deadline, and what the read waiting on it then gets is the deadline's: not the body's end
    where it gets nothing (Linux; the bytes so far would have been a whole answer of no JSON: None), nor a connection
    that broke off where it fails, its socket closed (Windows). Not whole, in its bound's words and the deadline's
    seconds."""
    wire = Wire(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", b"x")
    wires.ready.append(wire)
    at = Endpoint(HERE, timeout=0.1, clock=Clock())
    late, took = timed(lambda: at.get("/api/tags"))
    assert isinstance(late, EndpointError) and late.status == 0, late
    assert str(late) == "GET /api/tags: its answer was not whole after 0.2 s: not read" == at.seen["error"]
    assert 0.15 <= took < 5.0 and wire.given > len(wire.fast) + 2 and not wire.waited_out
    assert "shutdown" in wire.ended and wire.closed and watchdogs() == []  # (its close was asked before: put off)


def test_a_stream_is_left_at_its_deadline_as_a_read_waits_and_its_head_bounded_by_it(wires, closes):
    """A stream's deadline is the whole request's: a read waiting when it comes is ended by the watchdog (it gets
    nothing, or fails as its socket is closed: either is the deadline's), and the stream left there without an error,
    its last line the one that came whole; an answer whose head has not come by then is an EndpointError in the
    deadline's seconds."""
    events = Wire(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\nevent: one\n", b".")
    wires.ready.append(events)
    at = Endpoint(HERE, timeout=0.1, clock=Clock())
    got: list = []
    late, took = timed(lambda: got.extend(at.lines("GET", "/models/sse", deadline=0.3)))
    assert late is None and got == ["event: one"] and 0.25 <= took < 5.0 and not events.waited_out
    assert at.seen["status"] == 200 and at.seen["error"] == ("GET /models/sse: its stream was left after 0.3 s, "
                                                            "before its end")
    assert "shutdown" in events.ended and events.closed and watchdogs() == []
    head = Wire(b"HTTP/1.1 200 OK\r\n", b"X-Slow: 1\r\n")
    wires.ready.append(head)
    late, took = timed(lambda: list(at.lines("POST", "/api/pull", json={"model": "qwen3:8b"}, deadline=0.3)))
    assert isinstance(late, EndpointError) and str(late) == ("POST /api/pull: no answer from 127.0.0.1:11434 within "
                                                             "0.3 s") == at.seen["error"]
    assert 0.25 <= took < 5.0 and b'{"model":"qwen3:8b"}' in head.sent and head.closed and watchdogs() == []


def test_the_requests_transport_is_overdue_as_a_slow_read_is_late(wires, closes):
    """The transport's own deadline: twice its timeout for an answer read whole (Endpoint's bound on one, Jenkins'
    too), or the one given. Overdue is a TimeoutError, and trouble() says it as it says a read that waited past its
    timeout, in the deadline's own seconds; a body cut off is Overdue from its next read on, and the reply's close
    leaves nothing behind."""
    wires.ready += [Wire(b"HTTP/1.1 200 OK\r\n", b"X-Slow: 1\r\n"),
                    Wire(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", b"x")]
    late, took = timed(lambda: endpoint.requests_transport("GET", HERE + "/api/json", {}, None, 0.1, False))
    assert isinstance(late, endpoint.Overdue) and isinstance(late, TimeoutError) and late.seconds == 0.2
    assert str(late) == "no whole answer within 0.2 s: the request was cut off at its deadline" and 0.15 <= took < 5.0
    assert endpoint.trouble(late, "127.0.0.1:11434", 0.1) == "no answer from 127.0.0.1:11434 within 0.2 s"
    slow_read = TimeoutError("timed out")  # what a socket whose wait ran out raises
    assert endpoint.trouble(slow_read, "127.0.0.1:11434", 0.1) == "no answer from 127.0.0.1:11434 within 0.1 s"
    reply = endpoint.requests_transport("GET", HERE + "/file", {}, None, 5.0, True, deadline=0.15)
    pieces = []
    with pytest.raises(endpoint.Overdue) as cut:
        for piece in reply.chunks:
            pieces.append(piece)
    assert cut.value.seconds == 0.15 and pieces and set(b"".join(pieces)) == {ord("x")}
    reply.close()
    assert watchdogs() == [] and all(w.closed and "shutdown" in w.ended for w in wires.made)


def test_a_name_found_after_the_deadline_connects_nothing(wires):
    """A lookup is not cut short (nothing cuts getaddrinfo short): this one ends only once the watchdog has fired and
    is gone, by order, and the request is Overdue then, nothing made or connected."""
    def found():  # the name found only once the deadline has passed: its watchdog waited for to the end
        for thread in watchdogs():
            thread.join(SAFETY_S)
    wires.found = found
    wires.ready.append(Wire(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"))
    at = Endpoint(HERE, timeout=0.1, clock=Clock())
    late, _ = timed(lambda: at.get("/api/version"))
    assert str(late) == "GET /api/version: no answer from 127.0.0.1:11434 within 0.2 s"
    assert wires.looked == [("127.0.0.1", 11434)] and wires.made == [] and watchdogs() == []


def test_a_name_not_found_once_the_deadline_has_passed_is_said_as_one(wires):
    """A name this machine does not find is said as one whenever its lookup fails, at once or once the deadline has
    passed (a DNS server that does not answer: Windows' resolver gives up after some 10 s): the lookup is not cut
    short and no socket was shut, so the failure is the lookup's own, not the deadline's, and it is not said as an
    answer that came too slowly."""
    def unknown():
        raise socket.gaierror(socket.EAI_NONAME, "no such name")

    def unknown_late():  # the name not found only once the deadline has passed: its watchdog waited for to the end
        for thread in watchdogs():
            thread.join(SAFETY_S)
        unknown()
    at = Endpoint(THERE, plain=True, timeout=0.1, clock=Clock())
    for found in (unknown, unknown_late):
        wires.found = found
        late, _ = timed(lambda: at.get("/api/version"))
        assert isinstance(late, EndpointError) and late.status == 0, late
        assert str(late) == "GET /api/version: gpu-box.example:8000 is no name this machine finds" == at.seen["error"]
    assert wires.looked == [("gpu-box.example", 8000)] * 2 and wires.made == [] and watchdogs() == []


def test_an_answer_in_time_through_the_watched_connections_is_whole_and_leaves_nothing(wires, monkeypatch):
    """The same stack answering in time: whole over http, and over https through the TLS socket held before its
    handshake (made once, by endpoint._Held); the watchdog stopped with its request, nothing shut, every socket
    closed."""
    answer = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{"version":"0.14.2"}'
    plain, under, tls = Wire(answer), Wire(), Wire(answer)
    wires.ready += [plain, under]
    context = Context(tls)
    monkeypatch.setattr(endpoint, "_context", lambda: context)
    assert Endpoint(HERE, timeout=5).get("/api/version") == {"version": "0.14.2"}
    assert Endpoint(SAFE, key=KEY, timeout=5).get("/version") == {"version": "0.14.2"}
    assert plain.sent.startswith(b"GET /api/version HTTP/1.1\r\n") and plain.timeout == 5.0
    assert tls.handshakes == 1 and tls.sent.startswith(b"GET /version HTTP/1.1\r\n") and under.sent == b""
    assert f"Authorization: Bearer {KEY}".encode() in tls.sent and context.verify_mode == ssl.CERT_REQUIRED
    assert plain.closed and under.detached and tls.closed and watchdogs() == []
    assert not any("shutdown" in w.ended for w in (plain, under, tls))  # its watchdog stopped before its time


def test_a_watch_shuts_what_it_holds_at_its_deadline_and_ends_with_its_request(closes):
    """A watch stopped first shuts nothing, and its thread is gone once stop() returns; one whose time is up shuts
    what it holds (a plain socket shut down, and closed too where a shutdown ends no wait; a TLS one only shut down,
    on every system) and ends by itself, and shuts at once what it is handed after; a socket let go before its time
    is up is never reached, and one let go after it is Overdue; one longer than any wait can be waits the longest one
    can, until its request ends."""
    early, held, tls, freed, after = Wire(), Wire(), Wire(), Wire(), Wire()
    watch = endpoint._Watch(60)
    assert watch.hold(early) is early and len(watchdogs()) == 1
    watch.stop()
    assert not watch.fired and early.ended == [] and watchdogs() == []
    watch = endpoint._Watch(0.05)
    watch.hold(held)
    watch.hold(freed)
    watch.release(freed)  # (a TLS socket is to take its number)
    assert watch.hold(tls, tls=True) is tls
    watch._thread.join(SAFETY_S)  # it fires by itself, then ends
    assert watch.fired and held.ended == (["shutdown", "close"] if closes else ["shutdown"])
    assert tls.ended == ["shutdown"] and freed.ended == []
    watch.hold(after)
    assert after.ended == held.ended
    with pytest.raises(endpoint.Overdue):
        watch.release(after)
    watch.stop()
    endless = endpoint._Watch(float("inf"))
    endless.stop()
    assert not endless.fired and watchdogs() == []


def test_a_socket_is_shut_through_a_file_made_of_it(closes):
    """Where a wait on a socket ends only once it is closed (Windows), and socket.close() puts that off while a file
    made of it is open (as http.client reads an answer), the watchdog closes a plain socket's C socket itself: a call
    on it then finds no socket. Elsewhere its shutdown ends a wait, and the socket is left for its owner to close. A
    TLS socket is only shut down on every system, its number its own until its owner closes it: OpenSSL reads and
    writes through that number, which a close would free for the next socket made. Sockets made and never connected,
    no handshake: nothing is reached."""
    with socket.socket() as made:
        file = made.makefile("rb")
        endpoint._shut(made)
        assert (made.fileno() == -1) == closes
        file.close()
    assert made.fileno() == -1
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with context.wrap_socket(socket.socket(), server_hostname="models.example", do_handshake_on_connect=False) as tls:
        number = tls.fileno()
        endpoint._shut(tls)
        assert isinstance(tls, ssl.SSLSocket) and tls.fileno() == number != -1
    assert tls.fileno() == -1


def test_the_librarys_own_transport_is_given_each_asks_deadline(monkeypatch):
    """Twice its wait for an answer read whole, a stream's own deadline for a stream; a stand-in transport is asked
    with the six it takes, as every other test here shows."""
    asked = []

    def own(method, url, headers, body, timeout, stream, deadline=None):
        asked.append((method, timeout, stream, deadline))
        return Reply(200, {}, [b"a\n"] if stream else [b"{}"])
    monkeypatch.setattr(endpoint, "_OWN", own)
    at = Endpoint(HERE, timeout=1.5, transport=own)
    assert at.get("/x") == {} and at.post("/y", {}, timeout=20) == {}
    assert list(at.lines("GET", "/s", deadline=90)) == ["a"]
    assert list(at.lines("GET", "/s", deadline=-5)) == []  # a deadline past already: left at once, given none below 0
    assert asked == [("GET", 1.5, False, 3.0), ("POST", 20.0, False, 40.0), ("GET", 1.5, True, 90.0),
                     ("GET", 1.5, True, 0.0)]


def test_a_stream_given_no_deadline_has_no_watchdog(adapter):
    """A download's stream (it looks at its own deadline after every receive) is given none: no watchdog, and its
    connections urllib3's own, as before 1.76.0. An answer read whole has one while it is asked, gone once its reply
    is let go."""
    seen = []
    send = adapter.send

    def watched(request, **kwargs):
        seen.append((endpoint._WATCH.get() is not None, len(watchdogs())))
        return send(request, **kwargs)
    adapter.send = watched
    adapter.answers += [(200, {}, b"abc"), (200, {}, b"{}")]
    reply = endpoint.requests_transport("GET", SAFE + "/file", {}, None, 60.0, True, 1 << 20)
    assert b"".join(reply.chunks) == b"abc"
    reply.close()
    reply = endpoint.requests_transport("GET", SAFE + "/x", {}, None, 5.0, False)
    assert b"".join(reply.chunks) == b"{}" and len(watchdogs()) == 1
    reply.close()
    assert seen == [(False, 0), (True, 1)] and watchdogs() == []


# -- the rule ----------------------------------------------------------------------------------------------------
def test_no_address_is_written_out_in_the_module_or_in_these_tests():
    """No .py of the library holds a scheme and a host written out, docstrings included: an address is built from
    its parts, or is its plugin's."""
    written = re.compile(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]")
    for path in (Path(endpoint.__file__), Path(__file__)):
        found = [line for line in path.read_text(encoding="utf-8").splitlines() if written.search(line)]
        assert found == [], path.name
