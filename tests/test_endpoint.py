"""A model server asked over http (liminal_libs.machines.endpoint): an address as typed and as built from its parts,
plain http kept to this machine until its user accepts it for another, the key in no error, every answer bounded, a
stream handed on line by line until its end, its deadline or a cancel, the OpenAI-compatible list of models as
llama.cpp, Ollama and vLLM answer it, a chat cut, and a download's progress in words.

Every ask goes to a stand-in transport; the `requests` transport is run over a stand-in adapter, and a slow sender
over a stand-in connection under the real stack (http.client, urllib3, requests). No socket is opened and no process
started: the shared guard (conftest.py, `no_outside`) fails a test that does either. No address is written whole
here either: each is built from its parts, as the library's own are."""
from __future__ import annotations

import http.client
import io
import json
import re
import socket
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


# -- the rule ----------------------------------------------------------------------------------------------------
def test_no_address_is_written_out_in_the_module_or_in_these_tests():
    """No .py of the library holds a scheme and a host written out, docstrings included: an address is built from
    its parts, or is its plugin's."""
    written = re.compile(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]")
    for path in (Path(endpoint.__file__), Path(__file__)):
        found = [line for line in path.read_text(encoding="utf-8").splitlines() if written.search(line)]
        assert found == [], path.name
