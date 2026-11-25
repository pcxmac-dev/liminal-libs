"""A file fetched as a job (liminal_libs.machines.download): https on every hop and a redirect only to a host the pin
lists, a part gone on from or started again, a wrong size and a wrong sum refused with the part removed, a cancel that
keeps it, a download bounded in bytes and in time, a folder on another system's drive refused; an archive unpacked
with nothing written outside its folder and no link left leading out of it; and a folder removed only inside the
plugin's own, following no link.

Every download goes to a stand-in opener, or to the `requests` transport over a stand-in connection under the real
stack (test_endpoint's RealStack), and the system's zstd is a stand-in process: no socket is opened and no process
started (the shared guard, conftest.py's `no_outside`, fails a test that does either). No address is written whole
here: each is built from its parts, as the library's own are."""
from __future__ import annotations

import gzip
import hashlib
import io
import os
import re
import stat
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from liminal_libs import mounts
from liminal_libs.machines import download
from liminal_libs.machines.download import (ChecksumError, DownloadError, Source, fetch, member_steps, remove_tree,
                                            sha256, size_of, unpack)
from liminal_libs.machines.endpoint import Reply
from liminal_libs.machines.terminal import Cancelled
from test_endpoint import RealStack, Trickle, mount

pytestmark = pytest.mark.usefixtures("no_outside")

HOST = "releases.example"  # the pin's own host
STORE = "objects.releases.example"  # where its files are stored: one of the pin's hosts
NAME = "tool-linux-amd64.tar.gz"
DATA = bytes(range(256)) * 39 + bytes(16)  # 10,000 bytes: ten of the stand-in's reads
FILES = {"bin/tool": b"#!/bin/sh\necho tool\n", "lib/libtool.so.1.2.3": b"\x7fELF" + bytes(2000),
         "README.md": b"# tool\n"}  # 2,031 bytes in three files


def address(scheme: str, rest: str) -> str:
    return f"{scheme}://{rest}"


URL = address("https", f"{HOST}/tool/v1.2.3/{NAME}")
PART = NAME + ".part"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source(data: bytes = DATA, **other) -> Source:
    """The pin of `data` at URL: its size, its sha256, and where its files are stored."""
    return replace(Source(URL, NAME, len(data), digest(data), (STORE,)), **other)


class Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class Web:
    """https as a stand-in opener: each address asked is answered from `pages` ({address: (status, headers, body), or
    a function of the request's headers giving one, or an error to raise}), else 404. What was asked is kept
    (address, headers, timeout), and of each answer how many pieces were read and whether it was let go. A body is
    handed on `piece` bytes at a time, or as the list of pieces it is (an error among them is raised in its place, a
    function called for its bytes)."""

    def __init__(self, pages, piece: int = 1000):
        self.pages, self.piece, self.asked, self.answers = dict(pages), piece, [], []

    def __call__(self, url, headers, timeout):
        self.asked.append((url, dict(headers), timeout))
        page = self.pages.get(url, (404, {}, b""))
        if isinstance(page, BaseException):
            raise page
        status, said, data = page(dict(headers)) if callable(page) else page
        answer = {"url": url, "read": 0, "closed": False}
        self.answers.append(answer)
        parts = data if isinstance(data, list) else [data[i:i + self.piece] for i in range(0, len(data), self.piece)]

        def pieces():
            for part in parts:
                if isinstance(part, BaseException):
                    raise part
                answer["read"] += 1
                yield part() if callable(part) else part

        def close():
            answer["closed"] = True
        return Reply(status, said, pieces(), close)


def ranged(data: bytes):
    """A file as a server that gives a range of it gives it."""
    def page(headers):
        asked = headers.get("Range")
        if not asked:
            return 200, {"Content-Length": str(len(data))}, data
        start = int(asked.removeprefix("bytes=").rstrip("-"))
        if start >= len(data):
            return 416, {"Content-Range": f"bytes */{len(data)}"}, b""
        return 206, {"Content-Range": f"bytes {start}-{len(data) - 1}/{len(data)}",
                     "Content-Length": str(len(data) - start)}, data[start:]
    return page


def after(web: Web, reads: int):
    """A cancel that says so once the stand-in's last answer was read `reads` pieces of."""
    return lambda: bool(web.answers) and web.answers[-1]["read"] >= reads


def names(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir())


def tree(folder: Path) -> dict[str, bytes]:
    """Every file under a folder, by its path from there."""
    return {p.relative_to(folder).as_posix(): p.read_bytes() for p in sorted(folder.rglob("*")) if p.is_file()}


# -- fetched, checked, named -------------------------------------------------------------------------------------
def test_a_file_is_fetched_checked_and_given_its_name(tmp_path):
    web, log = Web({URL: ranged(DATA)}), []
    path = fetch(source(), tmp_path / "ai" / "downloads", log=log.append, opener=web, clock=Clock())
    assert path == tmp_path / "ai" / "downloads" / NAME and path.read_bytes() == DATA
    assert names(path.parent) == [NAME]  # no part is left
    url, headers, timeout = web.asked[0]
    assert url == URL and timeout == download.READ_S == 60.0 and len(web.asked) == 1
    assert headers == {"User-Agent": download.USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity"}
    assert web.answers[0] == {"url": URL, "read": 10, "closed": True}
    assert log == [f"downloading {NAME} from {HOST} (9.8 KB)", f"{NAME}: 1000 B of 9.8 KB (10%)",
                   f"{NAME}: 9.8 KB downloaded", f"{NAME}: 9.8 KB here, checked against the sha256 pinned for it",
                   f"{NAME} is the file pinned: its sha256 is {digest(DATA)}"]
    for pin, last in ((source(sha256=""), f"{NAME} is 10,000 bytes, as pinned; no sha256 is pinned for it"),
                      (Source(URL, NAME), f"{NAME}: 9.8 KB, not checked against a pinned sum: none is pinned for it"),
                      (source(size=0, sha256=digest(DATA).upper()), f"{NAME} is the file pinned: its sha256 is "
                                                                    f"{digest(DATA)}")):
        log.clear()
        assert fetch(pin, tmp_path / "other", log=log.append, opener=web, resume=False).read_bytes() == DATA
        assert log[-1] == last
    web = Web({URL: (200, {}, DATA)})  # a server that does not say its size
    log.clear()
    assert fetch(Source(URL, NAME), tmp_path / "unsaid", log=log.append, opener=web).read_bytes() == DATA
    assert log[0] == f"downloading {NAME} from {HOST}: its size is not known until it is downloaded"


def test_a_redirect_is_followed_to_a_listed_host_and_to_no_other(tmp_path):
    stored = address("https", f"{STORE}/blobs/abc?sig=1")
    web = Web({URL: (302, {"Location": stored}, [AssertionError("a redirect's body was read")]), stored: ranged(DATA)})
    log = []
    assert fetch(source(), tmp_path / "a", opener=web, log=log.append).read_bytes() == DATA
    assert [asked[0] for asked in web.asked] == [URL, stored]
    assert web.answers[0] == {"url": URL, "read": 0, "closed": True}  # its body never read, its connection let go
    assert log[0] == f"downloading {NAME} from {STORE} (9.8 KB)"  # where it came from
    moved = address("https", f"{HOST}/mirror/{NAME}")  # a relative one, on the address's own host
    web = Web({URL: (301, {"location": f"/mirror/{NAME}"}, b"moved"), moved: ranged(DATA)})
    assert fetch(source(), tmp_path / "b", opener=web).read_bytes() == DATA and web.asked[1][0] == moved
    for n, where in enumerate((address("https", "elsewhere.example/x"), address("http", f"{STORE}/x"),
                               address("ftp", f"{HOST}/x"), address("https", f"{HOST}.elsewhere.example/x"),
                               address("https", f"me@{STORE}/x"))):
        web = Web({URL: (302, {"Location": where}, b"the redirect's own body"), where: ranged(DATA)})
        folder = tmp_path / f"refused-{n}"
        with pytest.raises(DownloadError, match=f"{NAME} was sent on to .*: nothing was asked of it") as refused:
            fetch(source(), folder, opener=web)
        assert not isinstance(refused.value, ChecksumError)
        assert [asked[0] for asked in web.asked] == [URL] and web.answers[0]["read"] == 0  # never followed
        assert names(folder) == []  # nothing written
    assert str(refused.value) == f"{NAME} was sent on to an address with a user name in it: nothing was asked of it"
    web = Web({URL: (302, {"Location": address("https", "elsewhere.example/x")}, b"")})
    with pytest.raises(DownloadError) as refused:
        fetch(source(), tmp_path / "c", opener=web)
    assert str(refused.value) == (f"{NAME} was sent on to {address('https', 'elsewhere.example')}, and it comes over "
                                  f"https from {HOST} or {STORE} alone: nothing was asked of it")
    hops = {address("https", f"{HOST}/{i}"): (302, {"Location": f"/{i + 1}"}, b"") for i in range(9)}
    hops[URL] = (302, {"Location": "/0"}, b"")
    web = Web(hops)  # and no more than five of them
    with pytest.raises(DownloadError, match=f"{NAME} was sent on more than 5 times: not followed further"):
        fetch(source(), tmp_path / "d", opener=web)
    assert len(web.asked) == 1 + download.MAX_REDIRECTS == 6
    with pytest.raises(DownloadError, match=rf"{HOST} sent it on \(HTTP 307\) without saying where"):
        fetch(source(), tmp_path / "e", opener=Web({URL: (307, {}, b"")}))


def test_what_goes_wrong_after_a_redirect_is_said_of_the_host_that_answered_and_of_the_wait_it_had(tmp_path):
    stored = address("https", f"{STORE}/blobs/abc")
    whole, kept = {"Content-Length": str(len(DATA))}, "what came is kept, and the next download goes on from there"
    for page, words in (((200, whole, [DATA[:1000], ConnectionResetError("reset by peer")]),
                         f"the download of {NAME} broke off at 1000 B of 9.8 KB (no answer from {STORE}: "
                         f"ConnectionResetError: reset by peer); {kept}"),
                        ((200, whole, [DATA[:1000], TimeoutError("timed out")]),
                         f"the download of {NAME} broke off at 1000 B of 9.8 KB (no answer from {STORE} within 60 s); "
                         f"{kept}"),
                        ((503, {}, b"busy"), f"{NAME} could not be downloaded from {STORE}: HTTP 503"),
                        ((200, {"Content-Encoding": "br"}, DATA),
                         f"{NAME} comes br-encoded from {STORE}, which was not asked for: not downloaded"),
                        ((200, {"Content-Length": "0"}, b""), f"nothing came of {NAME} from {STORE}")):
        web = Web({URL: (302, {"Location": stored}, b""), stored: page})
        with pytest.raises(DownloadError) as failed:
            fetch(source(size=0), tmp_path / "a", opener=web)
        assert str(failed.value) == words
    with pytest.raises(DownloadError, match=f"{NAME}'s size could not be asked of {STORE}: HTTP 404"):
        size_of(source(), opener=Web({URL: (302, {"Location": stored}, b"")}))
    web = Web({URL: TimeoutError("timed out")})  # less time left than a read's own wait: the wait it had is said
    with pytest.raises(DownloadError, match=f"{NAME} could not be downloaded: no answer from {HOST} within 12.5 s$"):
        fetch(source(), tmp_path / "b", opener=web, clock=Clock(), timeout=12.5)
    assert web.asked[0][2] == 12.5


def test_only_https_is_downloaded_from_and_only_a_pin_that_is_one(tmp_path):
    web, folder = Web({}), tmp_path / "downloads"
    for bad in (address("http", f"{HOST}/{NAME}"), address("ftp", f"{HOST}/{NAME}"), f"{HOST}/{NAME}", "",
                address("https", f"me:pw@{HOST}/{NAME}"), address("https", f"/{NAME}")):
        with pytest.raises(DownloadError, match=f"{NAME} is downloaded over https only"):
            fetch(Source(bad, NAME), folder, opener=web)
        with pytest.raises(DownloadError, match=f"{NAME} is downloaded over https only"):
            size_of(Source(bad, NAME), opener=web)
    for name in ("", ".", "..", "a/b.zip", "..\\b.zip", "C:b.zip", " b.zip", "b\n.zip"):
        with pytest.raises(DownloadError, match="is no plain file name"):
            fetch(Source(URL, name), folder, opener=web)
    with pytest.raises(DownloadError, match=f"{NAME}'s pinned sha256 is none"):
        fetch(Source(URL, NAME, 0, "abc123"), folder, opener=web)
    for size in (-1, 1.5, "10000", True):
        with pytest.raises(DownloadError, match=f"{NAME}'s pinned size is no number of bytes"):
            fetch(Source(URL, NAME, size), folder, opener=web)
    for wait in (0, -1, float("nan"), "soon"):
        with pytest.raises(ValueError):
            fetch(source(), folder, opener=web, timeout=wait)
    assert web.asked == [] and not folder.exists()  # nothing asked, nothing made
    assert source(hosts=STORE) != source() and fetch(source(hosts=STORE), folder, opener=Web({URL: ranged(DATA)}))


# -- gone on from, or started again ------------------------------------------------------------------------------
def test_a_part_is_gone_on_from(tmp_path):
    (tmp_path / PART).write_bytes(DATA[:4000])
    web, log = Web({URL: ranged(DATA)}), []
    path = fetch(source(), tmp_path, log=log.append, opener=web, clock=Clock())
    assert path.read_bytes() == DATA and names(tmp_path) == [NAME]
    assert web.asked[0][1]["Range"] == "bytes=4000-" and len(web.asked) == 1
    assert web.answers[0]["read"] == 6  # the 6,000 bytes that were missing, not the whole again
    assert log[:2] == [f"going on with {NAME} from 3.9 KB of 9.8 KB", f"{NAME}: 4.9 KB of 9.8 KB (50%)"]


def test_a_part_starts_again_when_the_server_gives_no_range_of_the_same_whole(tmp_path):
    (tmp_path / PART).write_bytes(DATA[:4000])
    web = Web({URL: (200, {"Content-Length": str(len(DATA))}, DATA)})  # it gives no range: all of it, from the start
    assert fetch(source(), tmp_path, opener=web).read_bytes() == DATA
    assert web.asked[0][1]["Range"] == "bytes=4000-" and len(web.asked) == 1 and web.answers[0]["read"] == 10

    def another(first: int, whole: int):
        def page(headers):
            if "Range" in headers:
                return 206, {"Content-Range": f"bytes {first}-{whole - 1}/{whole}"}, b"y" * (whole - first)
            return 200, {"Content-Length": str(len(DATA))}, DATA
        return page
    for first, whole in ((4000, 11000), (0, 10000), (5000, 10000)):  # of another whole; not from where it was asked
        (tmp_path / NAME).unlink()
        (tmp_path / PART).write_bytes(DATA[:4000])
        web = Web({URL: another(first, whole)})
        assert fetch(source(), tmp_path, opener=web).read_bytes() == DATA
        assert ["Range" in asked[1] for asked in web.asked] == [True, False]
        assert web.answers[0] == {"url": URL, "read": 0, "closed": True}  # not a byte of the wrong range taken


def test_a_part_that_is_all_there_is_only_checked(tmp_path):
    (tmp_path / PART).write_bytes(DATA)  # it all came; the try ended before its check
    web = Web({})
    assert fetch(source(), tmp_path, opener=web).read_bytes() == DATA and web.asked == []  # its size is pinned
    (tmp_path / NAME).unlink()
    (tmp_path / PART).write_bytes(DATA)
    web = Web({URL: ranged(DATA)})  # its size is not pinned: the server says there is no more of it
    assert fetch(source(size=0), tmp_path, opener=web).read_bytes() == DATA
    assert web.asked[0][1]["Range"] == "bytes=10000-" and len(web.asked) == 1 and web.answers[0]["read"] == 0
    (tmp_path / NAME).unlink()
    (tmp_path / PART).write_bytes(DATA + b"and more")  # longer than the pin: no part of this file
    web = Web({URL: ranged(DATA)})
    assert fetch(source(), tmp_path, opener=web).read_bytes() == DATA and "Range" not in web.asked[0][1]


def test_a_part_that_was_not_this_files_is_downloaded_again_once(tmp_path):
    (tmp_path / PART).write_bytes(bytes(4000))  # an older pin's part, left under the same name
    web, log = Web({URL: ranged(DATA)}), []
    assert fetch(source(), tmp_path, log=log.append, opener=web).read_bytes() == DATA
    assert [asked[1].get("Range") for asked in web.asked] == ["bytes=4000-", None]
    assert f"what was here of {NAME} was not this file's: it is downloaded again from the start" in log
    (tmp_path / NAME).unlink()
    (tmp_path / PART).write_bytes(bytes(4000))
    web = Web({URL: ranged(bytes(reversed(DATA)))})  # and the whole is not the pinned file either: once, not for ever
    with pytest.raises(ChecksumError):
        fetch(source(), tmp_path, opener=web)
    assert len(web.asked) == 2 and names(tmp_path) == []


def test_a_part_the_server_did_not_go_on_from_is_not_downloaded_a_second_time(tmp_path):
    (tmp_path / PART).write_bytes(DATA[:3000])  # left by a try that broke off
    web = Web({URL: (200, {"Content-Length": str(len(DATA))}, DATA)})  # no ranges given: all of it came at once
    with pytest.raises(ChecksumError, match=f"{NAME} is not the file pinned"):
        fetch(source(sha256=digest(b"the file as it was when it was pinned")), tmp_path, opener=web)
    assert len(web.asked) == 1 and "Range" in web.asked[0][1] and names(tmp_path) == []  # one whole download, not two


def test_without_a_pinned_sum_no_part_is_gone_on_from_and_none_is_kept(tmp_path):
    (tmp_path / PART).write_bytes(b"y" * 4000)  # a part of another file of the same size: its size would not tell
    web, log = Web({URL: ranged(DATA)}), []
    assert fetch(source(sha256=""), tmp_path, opener=web, log=log.append).read_bytes() == DATA
    assert "Range" not in web.asked[0][1] and len(web.asked) == 1
    assert log[0] == f"downloading {NAME} from {HOST} (9.8 KB)"  # from the start
    (tmp_path / NAME).unlink()
    web = Web({URL: (200, {"Content-Length": str(len(DATA))}, DATA[:5000])})
    with pytest.raises(DownloadError, match=f"broke off at 4.9 KB of 9.8 KB; what came of it was removed$"):
        fetch(source(sha256=""), tmp_path, opener=web)
    assert names(tmp_path) == []
    web = Web({URL: ranged(DATA)})
    with pytest.raises(Cancelled, match="what came of it was removed$"):
        fetch(source(sha256=""), tmp_path, opener=web, cancel=after(web, 3))
    assert names(tmp_path) == []
    assert fetch(source(sha256=""), tmp_path, opener=Web({URL: ranged(DATA)})).read_bytes() == DATA
    web = Web({})  # a whole file there of the pinned size is still used as it is: it came whole, and was checked
    assert fetch(source(sha256=""), tmp_path, opener=web).read_bytes() == DATA and web.asked == []


def test_a_whole_file_already_here_is_used_as_it_is(tmp_path):
    (tmp_path / NAME).write_bytes(DATA)
    (tmp_path / PART).write_bytes(DATA[:10])
    web, log = Web({}), []
    assert fetch(source(), tmp_path, log=log.append, opener=web) == tmp_path / NAME and web.asked == []
    assert log == [f"{NAME} is here already (9.8 KB) and is the file pinned: not downloaded again"]
    assert names(tmp_path) == [NAME]
    (tmp_path / NAME).write_bytes(bytes(reversed(DATA)))  # one that is not the pinned file: downloaded again
    web = Web({URL: ranged(DATA)})
    assert fetch(source(), tmp_path, log=log.append, opener=web).read_bytes() == DATA and len(web.asked) == 1
    assert f"the {NAME} here is not the file pinned: it is downloaded again" in log
    for pin, how in ((Source(URL, NAME), {}), (source(), {"resume": False})):  # nothing pinned says it is; no resume
        web = Web({URL: ranged(DATA)})
        assert fetch(pin, tmp_path, opener=web, **how).read_bytes() == DATA and len(web.asked) == 1


# -- checked -----------------------------------------------------------------------------------------------------
def test_a_wrong_size_is_refused(tmp_path):
    web = Web({URL: ranged(DATA + b"more")})  # the server says another size: not a byte of it is taken
    with pytest.raises(ChecksumError) as wrong:
        fetch(source(), tmp_path, opener=web)
    assert str(wrong.value) == f"{NAME} is 10,004 bytes at its maker's, not the 10,000 pinned for it: not downloaded"
    assert web.answers[0] == {"url": URL, "read": 0, "closed": True} and names(tmp_path) == []
    web = Web({URL: (200, {}, DATA + b"more")})  # it says none and sends more: stopped there, the part removed
    with pytest.raises(ChecksumError, match=f"more came of {NAME} than the 10,000 bytes pinned for it: removed"):
        fetch(source(), tmp_path, opener=web)
    assert web.answers[0]["read"] == 11 and names(tmp_path) == []
    web = Web({URL: (200, {}, DATA[:9000])})  # it says none and sends less: broken off, as far as anyone can tell
    with pytest.raises(DownloadError, match=f"the download of {NAME} broke off at 8.8 KB of 9.8 KB") as short:
        fetch(source(), tmp_path, opener=web)
    assert not isinstance(short.value, ChecksumError) and names(tmp_path) == [PART]


def test_a_wrong_sum_removes_the_part(tmp_path):
    other = bytes(reversed(DATA))  # the same size, another file
    web = Web({URL: ranged(other)})
    with pytest.raises(ChecksumError) as wrong:
        fetch(source(), tmp_path, opener=web)
    assert str(wrong.value) == (f"{NAME} is not the file pinned: its sha256 is {digest(other)}, not {digest(DATA)}: "
                                "removed, nothing was installed")
    assert isinstance(wrong.value, DownloadError)
    assert names(tmp_path) == [] and len(web.asked) == 1  # no part, no file; and it is not tried again by itself


def test_a_files_sha256(tmp_path):
    (tmp_path / "f").write_bytes(DATA)
    (tmp_path / "empty").write_bytes(b"")
    assert sha256(tmp_path / "f") == digest(DATA) == sha256(str(tmp_path / "f"), cancel=lambda: False)
    assert sha256(tmp_path / "empty") == digest(b"")
    with pytest.raises(Cancelled):
        sha256(tmp_path / "f", cancel=lambda: True)


# -- cancelled, broken off, bounded ------------------------------------------------------------------------------
def test_cancel_keeps_the_part_for_the_next_try(tmp_path):
    web = Web({URL: ranged(DATA)})
    with pytest.raises(Cancelled) as stopped:
        fetch(source(), tmp_path, opener=web, cancel=after(web, 3))
    assert str(stopped.value) == (f"cancelled at 2.9 KB of 9.8 KB of {NAME}: what came is kept, and the next download "
                                  "goes on from there")
    assert names(tmp_path) == [PART] and (tmp_path / PART).read_bytes() == DATA[:3000]
    assert web.answers[0] == {"url": URL, "read": 3, "closed": True}  # no read after the cancel, the connection let go
    web = Web({URL: ranged(DATA)})
    assert fetch(source(), tmp_path, opener=web).read_bytes() == DATA  # the next try goes on from it
    assert web.asked[0][1]["Range"] == "bytes=3000-" and web.answers[0]["read"] == 7
    web = Web({URL: ranged(DATA)})  # where no part is kept, none is left
    with pytest.raises(Cancelled, match="what came of it was removed"):
        fetch(source(), tmp_path / "fresh", opener=web, cancel=after(web, 3), resume=False)
    assert names(tmp_path / "fresh") == []
    (tmp_path / "whole").mkdir()
    (tmp_path / "whole" / PART).write_bytes(DATA)  # cancelled while it is checked: the part stays, all of it
    with pytest.raises(Cancelled):
        fetch(source(), tmp_path / "whole", opener=Web({}), cancel=lambda: True)
    assert (tmp_path / "whole" / PART).read_bytes() == DATA
    stop: list = []

    def stalled():  # the user cancels while nothing comes; the read then ends at the socket's own wait
        stop.append(1)
        raise TimeoutError("timed out")
    web = Web({URL: (200, {"Content-Length": str(len(DATA))}, [DATA[:1000], stalled])})
    with pytest.raises(Cancelled, match=f"cancelled at 1000 B of 9.8 KB of {NAME}: what came is kept"):
        fetch(source(), tmp_path / "stalled", opener=web, cancel=lambda: bool(stop))  # cancelled, not "broke off"


def test_a_download_that_breaks_off_keeps_its_part(tmp_path):
    cut = [DATA[:1000], DATA[1000:2000], ConnectionResetError("reset by peer")]
    web = Web({URL: (200, {"Content-Length": str(len(DATA))}, cut)})
    with pytest.raises(DownloadError) as broke:
        fetch(source(), tmp_path, opener=web)
    assert not isinstance(broke.value, ChecksumError)
    assert str(broke.value) == (f"the download of {NAME} broke off at 2.0 KB of 9.8 KB (no answer from {HOST}: "
                                "ConnectionResetError: reset by peer); what came is kept, and the next download goes "
                                "on from there")
    assert (tmp_path / PART).read_bytes() == DATA[:2000] and web.answers[0]["closed"]
    web = Web({URL: (200, {"Content-Length": str(len(DATA))}, DATA[:5000])})  # one that just ends early
    with pytest.raises(DownloadError, match=f"the download of {NAME} broke off at 4.9 KB of 9.8 KB; what came is "
                                            "kept"):
        fetch(source(), tmp_path, opener=web)
    assert (tmp_path / PART).read_bytes() == DATA[:5000]
    with pytest.raises(DownloadError, match="what came of it was removed"):
        fetch(source(), tmp_path, opener=Web({URL: (200, {"Content-Length": "10000"}, DATA[:5000])}), resume=False)
    assert names(tmp_path) == []
    for page, words in ((ConnectionRefusedError(111, "Connection refused"),
                         f"{NAME} could not be downloaded: nothing listens at {HOST}"),
                        (TimeoutError("timed out"),
                         f"{NAME} could not be downloaded: no answer from {HOST} within 60 s"),
                        ((404, {}, b""), f"{NAME} could not be downloaded from {HOST}: HTTP 404 \\(it is not there\\)"),
                        ((503, {}, b"busy"), f"{NAME} could not be downloaded from {HOST}: HTTP 503$"),
                        ((200, {"Content-Encoding": "gzip"}, DATA), f"{NAME} comes gzip-encoded from {HOST}"),
                        ((200, {"Content-Length": "0"}, b""), f"nothing came of {NAME} from {HOST}")):
        with pytest.raises(DownloadError, match=words):
            fetch(source(size=0), tmp_path, opener=Web({URL: page}))
        assert names(tmp_path) in ([], [PART])


def test_a_download_stops_past_its_limit_and_past_its_time(tmp_path):
    web = Web({URL: ranged(DATA)})
    with pytest.raises(DownloadError, match=f"{NAME} is pinned at 9.8 KB, more than the 4.0 KB a download may be"):
        fetch(source(), tmp_path, opener=web, limit=4096)
    assert web.asked == []
    with pytest.raises(DownloadError, match=f"{NAME} is 9.8 KB, more than the 4.0 KB a download may be: not "
                                            "downloaded"):
        fetch(Source(URL, NAME), tmp_path, opener=web, limit=4096)  # nothing pinned: by what the server says
    assert web.answers[0]["read"] == 0
    web = Web({URL: (200, {}, DATA)})  # nor does the server say: stopped at the limit, what came removed
    with pytest.raises(DownloadError, match=f"{NAME} is more than the 4.0 KB a download may be: stopped"):
        fetch(Source(URL, NAME), tmp_path, opener=web, limit=4096)
    assert web.answers[0]["read"] == 5 and names(tmp_path) == []
    clock = Clock()

    def slow(piece: bytes):
        def read():
            clock.now += 3000.0
            return piece
        return read
    pieces = [slow(DATA[i:i + 1000]) for i in range(0, len(DATA), 1000)]
    web = Web({URL: (200, {"Content-Length": str(len(DATA))}, pieces)})
    with pytest.raises(DownloadError) as late:
        fetch(source(), tmp_path, opener=web, clock=clock, timeout=7200)
    assert str(late.value) == (f"{NAME} was not whole after 120 minutes: stopped at 2.9 KB of 9.8 KB; what came is "
                               "kept, and the next download goes on from there")
    assert (tmp_path / PART).read_bytes() == DATA[:3000] and web.answers[0] == {"url": URL, "read": 3, "closed": True}

    def jumps() -> float:  # the time is up before anything is asked
        clock.now += 8000.0
        return clock.now
    with pytest.raises(DownloadError, match=f"{NAME} was not whole after 120 minutes: stopped$"):
        fetch(source(), tmp_path, opener=web, clock=jumps, timeout=7200)  # no time left: nothing is asked
    assert len(web.asked) == 1 and (tmp_path / PART).read_bytes() == DATA[:3000]


def test_a_slow_download_sees_its_cancel_and_its_deadline_after_every_receive(tmp_path, monkeypatch):
    """Through the `requests` transport, over a stand-in connection that sends a byte at a time: a cancel and the
    deadline are seen after the byte they came with, never only once a whole CHUNK (1 MiB) has come."""
    clock, size = Clock(), 2 << 20
    data = bytes(size)
    pin = Source(URL, NAME, size, digest(data))
    head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % size
    first, later = Trickle(head, data, clock, 1.0), Trickle(head, data, clock, 1000.0)
    mount(monkeypatch, RealStack(first, later))
    with pytest.raises(Cancelled) as stopped:
        fetch(pin, tmp_path, cancel=lambda: first.reads >= 1, clock=clock)
    assert str(stopped.value).startswith(f"cancelled at 1 B of 2.0 MB of {NAME}: what came is kept")
    assert first.reads == 1 and first.closed and (tmp_path / PART).read_bytes() == b"\x00"
    with pytest.raises(DownloadError) as late:
        fetch(pin, tmp_path, clock=clock, timeout=7200)  # 1,000 s a byte: the eighth crosses the deadline
    assert str(late.value) == (f"{NAME} was not whole after 120 minutes: stopped at 8 B of 2.0 MB; what came is "
                               "kept, and the next download goes on from there")
    assert later.reads == 8 and later.closed


def test_the_size_is_asked_without_the_body(tmp_path):
    stored = address("https", f"{STORE}/blobs/abc")
    web = Web({URL: (302, {"Location": stored}, b""),
               stored: (200, {"Content-Length": "1618244995"}, [AssertionError("the body was read")])})
    assert size_of(source(), opener=web) == 1_618_244_995
    assert [asked[0] for asked in web.asked] == [URL, stored]
    assert web.answers[1] == {"url": stored, "read": 0, "closed": True}
    assert all(0 < asked[2] <= 20.0 for asked in web.asked) and web.asked[0][1]["Accept-Encoding"] == "identity"
    assert size_of(source(), opener=Web({URL: (200, {}, b"")})) == 0  # it does not say
    with pytest.raises(DownloadError, match=f"{NAME}'s size could not be asked of {HOST}: HTTP 404"):
        size_of(source(), opener=Web({}))
    with pytest.raises(DownloadError, match="was sent on to"):
        size_of(source(), opener=Web({URL: (302, {"Location": address("https", "elsewhere.example/x")}, b"")}))


def test_without_an_opener_the_requests_transport_is_the_way(tmp_path, monkeypatch):
    asked = []

    def transport(method, url, headers, body, timeout, stream, piece):
        asked.append((method, url, body, stream, piece))
        return Reply(200, {"Content-Length": str(len(DATA))}, [DATA])
    monkeypatch.setattr(download, "requests_transport", transport)
    assert fetch(source(), tmp_path).read_bytes() == DATA
    assert size_of(source()) == len(DATA)
    assert asked == [("GET", URL, None, True, download.CHUNK)] * 2 and download.CHUNK == 1 << 20  # as it comes


def test_a_folder_on_another_systems_drive_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(mounts, "foreign", lambda path, table=None: True)  # as WSL sees a folder of Windows' drive
    web, folder = Web({URL: ranged(DATA)}), tmp_path / "there"
    with pytest.raises(mounts.NotHere, match=f"Downloading {NAME}: .* is on another system's drive"):
        fetch(source(), folder, opener=web)
    with pytest.raises(mounts.NotHere, match="Unpacking tool.zip"):
        unpack(tmp_path / "tool.zip", folder)
    with pytest.raises(mounts.NotHere, match="Removing app"):
        remove_tree(folder / "app", folder)
    assert web.asked == [] and not folder.exists()  # nothing asked, nothing made


# -- unpacked ----------------------------------------------------------------------------------------------------
def entry(name: str, data: bytes | None = b"", *, kind: bytes = tarfile.REGTYPE, link: str = "", mode: int = 0o644):
    """A tar member and its bytes."""
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.mode = kind, link, mode
    info.size = len(data) if kind == tarfile.REGTYPE and data is not None else 0
    return info, (data if kind == tarfile.REGTYPE else None)


def tarred(path: Path, members, mode: str = "w:gz", **how) -> Path:
    with tarfile.open(path, mode, **how) as packed:
        for info, data in members:
            packed.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def zipped(path: Path, members) -> Path:
    """A .zip of (name, bytes) and (name, bytes, mode as Unix keeps it) members."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as packed:
        for name, data, *mode in members:
            info = zipfile.ZipInfo(name)
            if mode:
                info.create_system, info.external_attr = 3, mode[0] << 16
            packed.writestr(info, data)
    return path


def linked(target: Path, link: Path) -> bool:
    """A link to a folder made: a symbolic one, else (Windows, where few accounts may make one) a junction."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    try:
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
        return True
    except (ImportError, AttributeError, OSError):
        return False


@pytest.fixture
def links(tmp_path) -> bool:
    """Whether this account may make a symbolic link here (on Windows, mostly not)."""
    try:
        os.symlink("nowhere", tmp_path / "probe")
    except (OSError, NotImplementedError):
        return False
    os.unlink(tmp_path / "probe")
    return True


@pytest.mark.parametrize("name, mode", [("tool.zip", ""), ("tool.tar.gz", "w:gz"), ("Tool.TGZ", "w:gz"),
                                        ("tool.tar.xz", "w:xz")])
def test_an_archive_is_unpacked_into_its_folder(tmp_path, name, mode):
    archive = tmp_path / name
    if mode:
        tarred(archive, [entry("tool-1.2.3/", None, kind=tarfile.DIRTYPE, mode=0o755), entry("./tool-1.2.3/top", b""),
                         *(entry(f"tool-1.2.3/{n}", d, mode=0o755 if n.startswith("bin/") else 0o644)
                           for n, d in FILES.items())], mode)
    else:
        zipped(archive, [("tool-1.2.3/", b""), ("tool-1.2.3/top", b""),
                         *((f"tool-1.2.3/{n}", d, stat.S_IFREG | (0o755 if n.startswith("bin/") else 0o644))
                           for n, d in FILES.items())])
    into, log = tmp_path / "ai" / "app" / "1.2.3", []
    assert unpack(archive, into, log=log.append) == 4
    assert tree(into) == {"tool-1.2.3/top": b"", **{f"tool-1.2.3/{n}": d for n, d in FILES.items()}}
    assert log[0] == f"unpacking {name} into {into}" and log[-1] == f"4 files unpacked into {into} (2.0 KB)"
    if os.name != "nt":
        modes = [stat.S_IMODE((into / "tool-1.2.3" / n).stat().st_mode) for n in ("bin/tool", "README.md")]
        assert modes == [0o755, 0o644]
    flat = tmp_path / "flat"  # the archive's one top folder left out
    assert unpack(archive, flat, strip=1) == 4 and tree(flat) == {"top": b"", **FILES}
    assert unpack(archive, flat, strip=2) == 2  # top and README.md name nothing then: skipped; the rest written over
    assert tree(flat) == {"top": b"", **FILES, "tool": FILES["bin/tool"],
                          "libtool.so.1.2.3": FILES["lib/libtool.so.1.2.3"]}


@pytest.mark.skipif(os.name == "nt", reason="a file's mode is POSIX's")
def test_a_members_mode_is_kept_without_what_lets_others_write_it(tmp_path):
    archive = tarred(tmp_path / "t.tar.gz", [entry("tool", b"x", mode=0o4777), entry("data", b"y", mode=0o640),
                                             entry("locked", b"z", mode=0o400)])
    unpack(archive, tmp_path / "app")
    modes = [stat.S_IMODE((tmp_path / "app" / n).stat().st_mode) for n in ("tool", "data", "locked")]
    assert modes == [0o755, 0o640, 0o600]  # not run as its owner, not written by others; its owner's to remove


def test_a_members_name_as_its_steps():
    assert member_steps("./tool-1.2.3//bin/tool") == ["tool-1.2.3", "bin", "tool"]
    assert member_steps("a\\b/c") == ["a", "b", "c"] and member_steps("tool-1.2.3/") == ["tool-1.2.3"]
    for name in ("", "/whole", "\\whole", "a/../b", "..", "a/b\x00c", "a/b\nc"):
        with pytest.raises(DownloadError, match="x.zip holds"):
            member_steps(name, "x.zip")
    for name in ("C:evil", "c:/evil", "a/b:stream", "NUL", "a/con.txt", "a./b", "a /b", "a/b.",
                 # a device by any of the names Windows keeps for one: CONIN$, CONOUT$, COM and LPT 0 to 9 and with a
                 # superscript 1, 2 or 3 (Windows reads it as that digit), the part before the first dot without the
                 # spaces at its end; or a character none of its names holds
                 "CONIN$", "a/conout$.txt", "COM\u00b9", "lpt\u00b2.log", "LPT\u00b3", "COM0", "NUL .txt",
                 "aux  .tar.gz", 'a"b', "a*b", "a<b", "a>b", "a?b", "a|b"):
        with pytest.raises(DownloadError, match="a name Windows does not keep as it is"):
            member_steps(name, "x.zip", windows=True)
        assert member_steps(name, "x.zip", windows=False)  # another system keeps them as they are
    for name in ("console.txt", "nul-device", "com10", "lpt", "auxiliary", "conin", "a$b"):  # no device's name
        assert member_steps(name, "x.zip", windows=True) == [name]
    # a name longer than any path the system keeps is said before it is split (a step a folder to make)
    long = "d/" * (download.NAME_MOST // 2) + "f"
    with pytest.raises(DownloadError, match=r"^x.tar.gz holds a name of 4,097 characters \('d/d/.*'\.\.\.\), longer "
                                            r"than any path this system keeps \(4,096\): not unpacked further$"):
        member_steps(long, "x.tar.gz", windows=False)
    assert len(member_steps(long, "x.tar.gz", windows=True)) == 2049  # Windows keeps longer paths ...
    with pytest.raises(DownloadError, match=r"a name of 32,768 characters .* \(32,767\)"):
        member_steps("d/" * 16_384, "x.zip", windows=True)  # ... and none longer than these


def test_unpacking_writes_nothing_outside_its_folder(tmp_path):
    box, packed, outside = tmp_path / "box", tmp_path / "packed", tmp_path / "box" / "outside"
    packed.mkdir()
    outside.mkdir(parents=True)
    into = box / "ai" / "app"
    sym, hard = tarfile.SYMTYPE, tarfile.LNKTYPE
    cases = [
        (zipped(packed / "up.zip", [("ok.txt", b"1"), ("../evil.txt", b"x")]), "leads out of the folder"),
        (zipped(packed / "whole.zip", [("/etc/evil", b"x")]), "holds a whole path"),
        (zipped(packed / "back.zip", [("a/../../evil", b"x")]), "leads out of the folder"),
        (zipped(packed / "slash.zip", [("..\\evil.txt", b"x")]), "leads out of the folder"),
        (zipped(packed / "link.zip", [("lib", b"../../outside", stat.S_IFLNK | 0o777)]), "which leads out of"),
        (zipped(packed / "pipe.zip", [("pipe", b"", stat.S_IFIFO | 0o644)]), "neither a file, a folder nor a link"),
        (tarred(packed / "up.tar.gz", [entry("../evil", b"x")]), "leads out of the folder"),
        (tarred(packed / "deep.tgz", [entry("a/b/../../../evil", b"x")]), "leads out of the folder"),
        (tarred(packed / "link.tar.xz", [entry("lib", None, kind=sym, link="../../outside")], "w:xz"),
         "which leads out of"),
        (tarred(packed / "whole.tar.gz", [entry("passwd", None, kind=sym, link="/etc/passwd")]),
         "holds a link .* to a whole path"),
        (tarred(packed / "hard.tar.gz", [entry("f", None, kind=hard, link="../outside/kept")]),
         "leads out of the folder"),
        (tarred(packed / "none.tar.gz", [entry("f", None, kind=hard, link="not/there")]), "is no file it unpacked"),
        (tarred(packed / "dev.tar.gz", [entry("dev/null", None, kind=tarfile.CHRTYPE)]), "a device or a pipe"),
        (tarred(packed / "fifo.tar.gz", [entry("pipe", None, kind=tarfile.FIFOTYPE)]), "a device or a pipe"),
    ]
    (outside / "kept").write_bytes(b"its own")
    for archive, words in cases:
        with pytest.raises(DownloadError, match=words) as refused:
            unpack(archive, into)
        assert str(refused.value).startswith(f"{archive.name} holds") and "not unpacked further" in str(refused.value)
        assert tree(box) in ({"outside/kept": b"its own"}, {"outside/kept": b"its own", "ai/app/ok.txt": b"1"})
        assert names(tmp_path) == ["box", "packed"] and names(box) == ["ai", "outside"]
    assert (into / "ok.txt").read_bytes() == b"1"  # what was unpacked before a refusal is left, the caller's to remove
    if linked(outside, into / "via"):  # a link that was there already and leads out is not written through
        with pytest.raises(DownloadError, match="via.zip holds 'via/evil.txt', which leads out of"):
            unpack(zipped(packed / "via.zip", [("via/evil.txt", b"x")]), into)
        assert names(outside) == ["kept"]


def test_a_link_a_later_member_turns_outward_is_removed_and_the_archive_refused(tmp_path, links):
    """A link that stayed inside when it was made can lead out once later members are there: a link it goes through
    pointed elsewhere, or one made where there was nothing. Every link made is looked at again at the end, however
    the unpacking ends: one that leads out is removed, and the archive refused. That is Linux's way of following a
    link, step by step; Windows folds a link's `..` against the link's own folder before it reads any link (and
    ntpath.realpath with it), so there each such link is judged by what it says alone, when it is made."""
    into, folder, sym = tmp_path / "a" / "b" / "into", tarfile.DIRTYPE, tarfile.SYMTYPE
    start = [entry("x/y/z/", None, kind=folder), entry("q/", None, kind=folder),
             entry("hop", None, kind=sym, link="x/y/z"),  # inside
             entry("way", None, kind=sym, link="hop/../../..")]  # through hop: x/y/z/../../.., the folder itself
    repointed = tarred(tmp_path / "repoint.tar.gz", [*start, entry("hop", None, kind=sym, link="q")])  # hop elsewhere
    made_later = tarred(tmp_path / "later.tar.gz", [entry("way", None, kind=sym, link="a/b/../.."),  # a is not there
                                                    entry("a", None, kind=sym, link=".")])  # a made: way now leads out
    refused_too = tarred(tmp_path / "then.tar.gz", [*start, entry("hop", None, kind=sym, link="q"),
                                                    entry("../evil", b"x")])  # and then refused for another reason
    fine = tarred(tmp_path / "fine.tar.gz", start)
    if not links:  # (this account may make none: said, not skipped over)
        for archive in (repointed, made_later, refused_too):
            with pytest.raises(DownloadError, match="holds a link .*this system did not let it be made"):
                unpack(archive, tmp_path / archive.name.split(".")[0])
        return
    if os.name == "nt":  # `hop/../../..` is the folder's grandparent as Windows reads it: refused at its making
        for archive, where in ((repointed, into), (refused_too, tmp_path / "then"), (fine, tmp_path / "fine")):
            with pytest.raises(DownloadError, match=f"^{re.escape(archive.name)} holds 'way -> hop/../../..', which "
                                                    "leads out of .*: not unpacked further$"):
                unpack(archive, where)
            assert not os.path.lexists(where / "way") and (where / "hop").is_dir()  # hop made, and read through
        assert sorted(os.listdir(tmp_path / "a")) == ["b"]  # nothing written outside
        assert unpack(made_later, tmp_path / "later") == 2  # `a/b/../..` is the folder itself, whatever `a` is
        assert os.path.realpath(tmp_path / "later" / "way") == os.path.realpath(tmp_path / "later")
        return
    with pytest.raises(DownloadError) as refused:
        unpack(repointed, into)
    assert str(refused.value) == (f"repoint.tar.gz holds a link ('way -> hop/../../..') that leads out of {into} once "
                                  "the members after it were unpacked: removed, and the archive refused")
    assert not os.path.lexists(into / "way") and os.readlink(into / "hop") == "q"  # nothing left leading out
    assert sorted(os.listdir(tmp_path / "a")) == ["b"]  # nothing written outside
    with pytest.raises(DownloadError, match=r"later.tar.gz holds a link \('way -> a/b/../..'\) that leads out of"):
        unpack(made_later, tmp_path / "later")
    assert not os.path.lexists(tmp_path / "later" / "way") and os.readlink(tmp_path / "later" / "a") == "."
    with pytest.raises(DownloadError, match=r"then.tar.gz holds '../evil', which leads out of the folder"):
        unpack(refused_too, tmp_path / "then")  # the refusal said is the member's own ...
    assert not os.path.lexists(tmp_path / "then" / "way")  # ... and the link that leads out is gone all the same
    assert unpack(fine, tmp_path / "fine") == 2  # two links that stay inside
    assert os.path.realpath(tmp_path / "fine" / "way") == os.path.realpath(tmp_path / "fine")


def test_a_link_that_stays_inside_is_made(tmp_path, links):
    archive = tarred(tmp_path / "tool.tar.gz", [
        entry("lib/libtool.so.1.2.3", b"\x7fELF"), entry("lib/libtool.so.1", None, kind=tarfile.SYMTYPE,
                                                         link="libtool.so.1.2.3"),
        entry("bin/tool", b"#!/bin/sh\n", mode=0o755), entry("bin/lib", None, kind=tarfile.SYMTYPE, link="../lib"),
        entry("bin/tool-too", None, kind=tarfile.LNKTYPE, link="bin/tool")])
    into = tmp_path / "app"
    if not links:  # (this account may make none: said, not skipped over)
        with pytest.raises(DownloadError, match="holds a link .*libtool.so.1.*this system did not let it be made"):
            unpack(archive, into)
        return
    assert unpack(archive, into) == 5
    assert os.readlink(into / "lib" / "libtool.so.1") == "libtool.so.1.2.3"
    assert (into / "lib" / "libtool.so.1").read_bytes() == b"\x7fELF"
    # written with this system's separator (..\lib on Windows, which follows no other), and read through
    assert os.readlink(into / "bin" / "lib") == os.path.join("..", "lib")
    assert (into / "bin" / "lib" / "libtool.so.1.2.3").read_bytes() == b"\x7fELF"
    again = into / "bin" / "tool-too"  # a hard link's file is a copy, not a second name
    assert again.read_bytes() == b"#!/bin/sh\n" and not again.is_symlink()
    assert again.stat().st_ino != (into / "bin" / "tool").stat().st_ino
    assert unpack(archive, into) == 5  # over what is there: a link is replaced, never written through


def test_links_are_made_as_the_archive_names_them(tmp_path, monkeypatch):
    into, made = tmp_path / "app", []

    def symlink(aim, dest, target_is_directory=False):
        made.append((aim, Path(dest).relative_to(os.path.realpath(into)).as_posix(), target_is_directory))
    monkeypatch.setattr(os, "symlink", symlink)
    archive = zipped(tmp_path / "tool.zip", [("lib/", b""), ("lib/libtool.so.1.2.3", b"\x7fELF"),
                                             ("lib/libtool.so.1", b"libtool.so.1.2.3", stat.S_IFLNK | 0o777),
                                             ("bin/lib", b"../lib", stat.S_IFLNK | 0o777)])
    assert unpack(archive, into) == 3
    assert made == [("libtool.so.1.2.3", "lib/libtool.so.1", False), (os.path.join("..", "lib"), "bin/lib", True)]


def test_a_links_target_is_written_with_this_systems_separator():
    """Windows follows a link's target by its own separator alone: a link an archive names with `/` is written with
    `\\` there, and as it is named elsewhere."""
    assert download.link_target("../lib/libtool.so", windows=True) == "..\\lib\\libtool.so"
    assert download.link_target("../lib/libtool.so", windows=False) == "../lib/libtool.so"
    assert download.link_target("libtool.so.1.2.3") == "libtool.so.1.2.3"
    assert download.link_target("a/b") == ("a\\b" if os.name == "nt" else "a/b")


def test_a_links_target_longer_than_any_path_is_refused(tmp_path):
    far = "d/" * (download.LINK_MOST // 2) + "f"  # 4,097 characters: followed step by step, a long time
    for archive in (tarred(tmp_path / "far.tar.gz", [entry("lib", None, kind=tarfile.SYMTYPE, link=far)]),
                    zipped(tmp_path / "far.zip", [("lib", far.encode(), stat.S_IFLNK | 0o777)])):
        with pytest.raises(DownloadError) as refused:
            unpack(archive, tmp_path / archive.name.replace(".", "-"))
        assert str(refused.value) == (f"{archive.name} holds a link ('lib') to a target of more than 4,096 "
                                      "characters: not unpacked further")
        assert tree(tmp_path / archive.name.replace(".", "-")) == {}


def test_an_archive_unpacks_to_its_limit_at_most(tmp_path, monkeypatch):
    big = zipped(tmp_path / "big.zip", [("a", b"x" * 3000), ("b", b"y" * 3000)])
    with pytest.raises(DownloadError, match="big.zip unpacks to 5.9 KB, more than 4.0 KB: not unpacked"):
        unpack(big, tmp_path / "z", limit=4096)
    assert tree(tmp_path / "z") == {}  # as it says itself, before anything is written
    big = tarred(tmp_path / "big.tar.gz", [entry("a", b"x" * 3000), entry("b", b"y" * 3000)])
    with pytest.raises(DownloadError, match="big.tar.gz unpacks to more than 4.0 KB: stopped, not unpacked whole"):
        unpack(big, tmp_path / "t", limit=4096)
    assert tree(tmp_path / "t") == {"a": b"x" * 3000}  # the member that crossed it was not written
    monkeypatch.setattr(download, "MOST_FILES", 2)
    many = [(f"f{i}", b"") for i in range(3)]
    with pytest.raises(DownloadError, match="many.zip holds more than 2 entries"):
        unpack(zipped(tmp_path / "many.zip", many), tmp_path / "m")
    with pytest.raises(DownloadError, match="many.tgz holds more than 2 entries"):
        unpack(tarred(tmp_path / "many.tgz", [entry(n, d) for n, d in many]), tmp_path / "n")


def plain_tar(members, **how) -> bytes:
    """A .tar's bytes, as zstd would hand them on (or as gzip packs them)."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", **how) as packed:
        for info, data in members:
            packed.addfile(info, io.BytesIO(data) if data is not None else None)
    return out.getvalue()


def test_a_tar_members_long_header_is_refused_before_it_is_read(tmp_path):
    """tarfile reads a member's extended header (PAX records, a GNU long name) whole into memory, and the limit
    counts members' bytes: a header past HEADER_MOST bytes is refused before it is read."""
    assert download.HEADER_MOST == 1 << 20
    pax, _ = entry("small.txt", b"hello")
    pax.pax_headers = {"comment": "x" * (2 << 20)}  # 2 MB of header, a few KB packed
    archive = tmp_path / "pax.tar.gz"
    archive.write_bytes(gzip.compress(plain_tar([(pax, b"hello")], format=tarfile.PAX_FORMAT)))
    assert archive.stat().st_size < 20_000
    with pytest.raises(DownloadError) as refused:
        unpack(archive, tmp_path / "app", limit=1 << 20)
    assert str(refused.value) == ("pax.tar.gz holds an extended header of 2.0 MB, more than the 1.0 MB read of one: "
                                  "not unpacked further")
    named, _ = entry("d/" * (600 << 10) + "f", b"x")  # a GNU long name of 1.2 MB
    archive = tmp_path / "gnu.tgz"
    archive.write_bytes(gzip.compress(plain_tar([(named, b"x")], format=tarfile.GNU_FORMAT)))
    with pytest.raises(DownloadError, match="gnu.tgz holds an extended header of 1.2 MB"):
        unpack(archive, tmp_path / "gnu")
    small, _ = entry("tool-1.2.3/" + "long-name/" * 10 + "f", b"x")  # a long name of its own (PAX): as it is
    small.pax_headers = {"comment": "built by its maker"}
    archive = tmp_path / "fine.tar.gz"
    archive.write_bytes(gzip.compress(plain_tar([(small, b"x")], format=tarfile.PAX_FORMAT)))
    assert unpack(archive, tmp_path / "fine", strip=1) == 1 and tree(tmp_path / "fine") == {small.name[11:]: b"x"}


def raw(name: str, size: int, kind: bytes) -> bytes:
    """One tar header written by hand, for what tarfile writes none of: a global header before each member, a chain
    of long names, an old sparse file."""
    info = tarfile.TarInfo(name)
    info.size, info.type = size, kind
    return info.tobuf(format=tarfile.USTAR_FORMAT)


def block(data: bytes) -> bytes:
    """Bytes as a tar keeps them: to the end of their last block of 512."""
    return data + bytes(-len(data) % tarfile.BLOCKSIZE)


def record(key: str, value: str) -> bytes:
    """One PAX record, its length (which counts its own digits) first."""
    body = f" {key}={value}\n"
    n = len(body) + 1
    while len(str(n)) + len(body) != n:
        n = len(str(n)) + len(body)
    return f"{n}{body}".encode()


def summed(head: bytearray) -> bytes:
    """A header changed by hand, its checksum made again."""
    head[148:156] = b" " * 8
    head[148:156] = b"%06o\x00 " % sum(head)
    return bytes(head)


def test_an_archives_headers_together_and_its_sparse_files_are_refused_before_they_are_read(tmp_path, monkeypatch):
    """One extended header under its bound, yet many: tarfile keeps what each says (a global header for the rest of
    the archive, a chain of long names all at once, each member's name with it), so all of an archive's headers
    together have a bound too (HEADERS_MOST); a sparse file's map, which tarfile reads whole before it hands the
    member on, is never read (a review made 300 MB of global headers, 200 MB of chained names and 196 MB of a sparse
    map from archives of a few hundred KB); and a name longer than any path is said before it is split."""
    # a name of more steps than any path holds: said before a folder of it is made, on either system
    named, _ = entry("d/" * 16_384 + "f", b"x")  # 32,769 characters, a GNU long name of 32 KB
    (tmp_path / "deep.tgz").write_bytes(gzip.compress(plain_tar([(named, b"x")], format=tarfile.GNU_FORMAT)))
    with pytest.raises(DownloadError, match=r"^deep.tgz holds a name of 32,769 characters .*, longer than any path "
                                            r"this system keeps \((4,096|32,767)\): not unpacked further$"):
        unpack(tmp_path / "deep.tgz", tmp_path / "deep")
    assert list((tmp_path / "deep").iterdir()) == []
    assert download.HEADERS_MOST == 16 << 20
    monkeypatch.setattr(download, "HEADERS_MOST", 8 << 10)  # 8 KB here, to be quick
    piles = b""
    for i in range(2):  # a global header of 6 KB before each member, each with a keyword of its own
        said = record(f"LIMINAL.test.k{i}", "x" * 6000)
        piles += raw("././@PaxHeader", len(said), tarfile.XGLTYPE) + block(said) + raw(f"f{i}", 1, tarfile.REGTYPE)
        piles += block(b"%d" % i)
    (tmp_path / "globals.tar.gz").write_bytes(gzip.compress(piles + bytes(1024)))
    with pytest.raises(DownloadError) as refused:
        unpack(tmp_path / "globals.tar.gz", tmp_path / "globals")
    assert str(refused.value) == ("globals.tar.gz holds more than 8.0 KB of extended headers (PAX records, long names) "
                                  "in all: not unpacked further")
    assert tree(tmp_path / "globals") == {"f0": b"0"}  # what came before it was unpacked, the caller's to remove
    chain = b"".join(raw("././@LongLink", 6000, tarfile.GNUTYPE_LONGNAME) + block(b"n%d-" % i + b"a" * 5996 + b"\x00")
                     for i in range(2))  # two long names one after the other, no member between
    chain += raw("f", 1, tarfile.REGTYPE) + block(b"x") + bytes(1024)
    (tmp_path / "chain.tgz").write_bytes(gzip.compress(chain))
    with pytest.raises(DownloadError, match=r"^chain.tgz holds more than 8.0 KB of extended headers"):
        unpack(tmp_path / "chain.tgz", tmp_path / "chain")
    assert tree(tmp_path / "chain") == {}
    # an old GNU sparse file ('S'), its map going on in extension blocks
    head = bytearray(raw("big", 0, tarfile.GNUTYPE_SPARSE))
    head[482], head[483:495] = 1, b"%011o\x00" % (1 << 20)  # its map goes on; 1 MB, once unpacked
    ext = bytearray(tarfile.BLOCKSIZE)
    for i in range(21):
        ext[i * 24:i * 24 + 24] = b"%011o\x00%011o\x00" % (i + 1, 1)
    ext[504] = 1
    blocks = bytes(ext) * 3 + bytes(tarfile.BLOCKSIZE)
    (tmp_path / "sparse.tar.gz").write_bytes(gzip.compress(summed(head) + blocks + bytes(1024)))
    with pytest.raises(DownloadError) as refused:
        unpack(tmp_path / "sparse.tar.gz", tmp_path / "sparse")
    assert str(refused.value) == ("sparse.tar.gz holds a sparse file (GNU tar's), which no install here unpacks: not "
                                  "unpacked further")
    # ... and one as PAX records say it (GNU's 1.0: its map in the member's own bytes)
    info = tarfile.TarInfo("GNUSparseFile.0/f")
    data = block(b"1\n0\n5\n") + b"hello"
    info.size, info.pax_headers = len(data), {"GNU.sparse.major": "1", "GNU.sparse.minor": "0",
                                              "GNU.sparse.name": "f", "GNU.sparse.realsize": "5"}
    (tmp_path / "pax-sparse.tar.gz").write_bytes(gzip.compress(plain_tar([(info, data)], format=tarfile.PAX_FORMAT)))
    with pytest.raises(DownloadError, match=r"^pax-sparse.tar.gz holds a sparse file \(GNU tar's\)"):
        unpack(tmp_path / "pax-sparse.tar.gz", tmp_path / "pax-sparse")
    assert tree(tmp_path / "sparse") == {} and tree(tmp_path / "pax-sparse") == {}


def test_an_unpacking_is_cancelled_between_its_members(tmp_path):
    archive = tarred(tmp_path / "t.tar.gz", [entry("a", b"1"), entry("b", b"2"), entry("c", b"3")])
    into = tmp_path / "app"
    with pytest.raises(Cancelled, match="t.tar.gz was not unpacked whole, and what was unpacked is left in"):
        unpack(archive, into, cancel=lambda: (into / "a").is_file() and (into / "a").stat().st_size == 1)
    assert tree(into) == {"a": b"1"}
    with pytest.raises(Cancelled):
        unpack(zipped(tmp_path / "z.zip", [("a", b"1")]), tmp_path / "none", cancel=lambda: True)
    assert tree(tmp_path / "none") == {}


def test_what_is_no_archive_is_said(tmp_path):
    with pytest.raises(DownloadError, match="tool.rar is no archive unpacked here: a .zip, .tar.gz, .tgz, .tar.xz or "):
        unpack(tmp_path / "tool.rar", tmp_path / "x")
    assert not (tmp_path / "x").exists()
    broken = tmp_path / "broken.zip"
    broken.write_bytes(b"no archive at all")
    with pytest.raises(DownloadError, match="broken.zip could not be unpacked into"):
        unpack(broken, tmp_path / "x")
    whole = tarred(tmp_path / "whole.tar.gz", [entry("a", os.urandom(50_000))]).read_bytes()
    (tmp_path / "cut.tar.gz").write_bytes(whole[:len(whole) // 2])
    with pytest.raises(DownloadError, match="cut.tar.gz could not be unpacked into"):
        unpack(tmp_path / "cut.tar.gz", tmp_path / "x")
    with pytest.raises(DownloadError, match="missing.tar.xz could not be unpacked into"):
        unpack(tmp_path / "missing.tar.xz", tmp_path / "x")
    for strip in (-1, True, "1"):
        with pytest.raises(ValueError, match="strip is a number of leading folders"):
            unpack(broken, tmp_path / "x", strip=strip)


# -- a .tar.zst --------------------------------------------------------------------------------------------------
@pytest.mark.skipif(sys.version_info < (3, 14), reason="a Python before 3.14 writes and reads no .tar.zst")
def test_a_tar_zst_is_read_by_this_python_where_it_can(tmp_path):
    archive = tarred(tmp_path / "ollama-linux-amd64.tar.zst", [entry(n, d) for n, d in FILES.items()], "w:zst")

    def never(*args, **kwargs):
        raise AssertionError("zstd was looked for, though this Python reads it")
    assert unpack(archive, tmp_path / "app", which=never, popen=never) == 3 and tree(tmp_path / "app") == FILES
    pax, _ = entry("small.txt", b"hello")
    pax.pax_headers = {"comment": "x" * (2 << 20)}
    archive = tarred(tmp_path / "pax.tar.zst", [(pax, b"hello")], "w:zst", format=tarfile.PAX_FORMAT)
    with pytest.raises(DownloadError, match="pax.tar.zst holds an extended header of 2.0 MB"):
        unpack(archive, tmp_path / "pax", which=never, popen=never)


class Zstd:
    """The system's zstd as a stand-in process: what it would write (the archive, unpacked) is `out`; nothing is
    started. How it was started, waited for and ended is kept."""

    def __init__(self, out: bytes, code: int = 0):
        self.stdout, self.code, self.started, self.waited, self.killed = io.BytesIO(out), code, [], 0, 0

    def __call__(self, argv, **how):
        self.started.append((list(argv), how))
        return self

    def poll(self):
        return self.code if self.waited or self.killed else None

    def wait(self, timeout=None):
        self.waited += 1
        return self.code

    def kill(self):
        self.killed += 1


def test_a_tar_zst_goes_through_the_systems_zstd_where_this_python_reads_none(tmp_path, monkeypatch):
    monkeypatch.setattr(download, "_reads_zst", lambda: False)  # as a Python before 3.14
    monkeypatch.setattr(download, "_os_release", lambda: {"ID": "ubuntu", "ID_LIKE": "debian"})  # not this one's
    monkeypatch.setenv("LIMINAL_AI_OLLAMA_DEFAULT_KEY", "sk-not-for-a-child")  # a pair, as the Login keeps it
    monkeypatch.setenv("LIMINAL_PLATFORM_DIR", str(tmp_path))
    monkeypatch.setenv("SOMETHING_OF_THE_USERS", "kept")
    plain = plain_tar([entry(n, d) for n, d in FILES.items()])
    archive = tmp_path / "ollama-linux-amd64.tar.zst"
    archive.write_bytes(b"\x28\xb5\x2f\xfd what zstd would read")

    def which(name):
        return "/usr/bin/zstd" if name == "zstd" else None
    zstd = Zstd(plain)
    assert unpack(archive, tmp_path / "app", which=which, popen=zstd) == 3 and tree(tmp_path / "app") == FILES
    argv, how = zstd.started[0]
    assert argv == ["/usr/bin/zstd", "-d", "-c", "-q", "--", str(archive)]
    env = how.pop("env")
    assert how == {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL,
                   **({"creationflags": 0x08000000} if os.name == "nt" else {})}  # no window opens for it on Windows
    assert [name for name in env if name.upper().startswith("LIMINAL_")] == []  # no pair of Liminal's reaches it
    assert "sk-not-for-a-child" not in env.values() and env.get("PATH") == os.environ.get("PATH")
    assert env["SOMETHING_OF_THE_USERS"] == "kept"  # a net only, as its words say: the AI base hands its own (below)
    assert (zstd.waited, zstd.killed, zstd.stdout.closed) == (1, 0, True)
    given = Zstd(plain)  # the AI base's own environment, every pair taken out: handed on as it is
    unpack(archive, tmp_path / "given", which=which, popen=given, env={"PATH": "/usr/bin", "LANG": "C.UTF-8"})
    assert given.started[0][1]["env"] == {"PATH": "/usr/bin", "LANG": "C.UTF-8"}
    failed = Zstd(plain, code=1)  # it ended badly: the file was not whole
    with pytest.raises(DownloadError, match=r"zstd could not unpack ollama-linux-amd64.tar.zst \(it ended with 1\)"):
        unpack(archive, tmp_path / "failed", which=which, popen=failed)
    way_out = Zstd(plain_tar([entry("ok", b"1"), entry("../evil", b"x")]))
    with pytest.raises(DownloadError, match="leads out of the folder"):
        unpack(archive, tmp_path / "refused", which=which, popen=way_out)
    # ended with the unpacking, however that ends: asked and its pipe closed, never killed (1.88.4)
    assert (way_out.killed, way_out.stdout.closed) == (0, True)
    pax, _ = entry("small.txt", b"hello")
    pax.pax_headers = {"comment": "x" * (2 << 20)}
    long = Zstd(plain_tar([(pax, b"hello")], format=tarfile.PAX_FORMAT))  # a header past its bound, here too
    with pytest.raises(DownloadError, match="ollama-linux-amd64.tar.zst holds an extended header of 2.0 MB"):
        unpack(archive, tmp_path / "long", which=which, popen=long)
    assert (long.killed, long.stdout.closed) == (0, True)  # asked, never killed (1.88.4)
    endless = Zstd(plain + bytes(download.TRAIL_MOST + download.CHUNK))
    with pytest.raises(DownloadError, match="goes on after its last entry"):
        unpack(archive, tmp_path / "endless", which=which, popen=endless)
    with pytest.raises(DownloadError) as none:  # neither: said, with the command that puts it right
        unpack(archive, tmp_path / "none", which=lambda name: None, popen=zstd)
    assert str(none.value) == download._no_zstd(archive.name) and len(zstd.started) == 1
    assert download._no_zstd("a.tar.zst", linux=False).endswith("and no zstd program is on this system's PATH")


@pytest.mark.parametrize("release, how", [
    ({"ID": "ubuntu", "ID_LIKE": "debian"}, "`sudo apt install zstd`, yours to run"),
    ({"ID": "debian"}, "`sudo apt install zstd`, yours to run"),
    ({"ID": "fedora"}, "`sudo dnf install zstd`, yours to run"),
    ({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, "`sudo dnf install zstd`, yours to run"),
    ({"ID": "gentoo"}, "`sudo emerge app-arch/zstd`, yours to run"),
    ({"ID": "alpine"}, "`sudo apk add zstd`, yours to run"),
    ({"ID": "manjaro", "ID_LIKE": "arch"}, "`sudo pacman -S zstd`, yours to run"),
    ({"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse"}, "`sudo zypper install zstd`, yours to run"),
    ({"ID": "nixos"}, "your distribution's package manager installs it, yours to run"),
    ({}, "your distribution's package manager installs it, yours to run"),
])
def test_zstds_words_name_this_distributions_own_command(release, how):
    version = f"{sys.version_info[0]}.{sys.version_info[1]}"
    assert download._no_zstd("a.tar.zst", linux=True, release=release) == (
        f"a.tar.zst is a .tar.zst, which this Python ({version}) does not read by itself, and zstd is not installed "
        f"here: {how}")


# -- removed -----------------------------------------------------------------------------------------------------
def test_only_a_folder_inside_the_plugins_own_is_removed(tmp_path):
    home, models = tmp_path / "ai" / "ollama", tmp_path / "ai" / "models"
    app = home / "app" / "0.40.16"
    (app / "lib").mkdir(parents=True)
    models.mkdir()
    (app / "ollama").write_bytes(b"x" * 1000)
    (app / "lib" / "libggml.so").write_bytes(b"y" * 500)
    (home / "app" / "CURRENT").write_bytes(b"0.40.16\n")
    (models / "blob").write_bytes(b"z" * 10)
    for other in (home, tmp_path, models, home / ".." / "models", home / "app" / ".." / "..", tmp_path / "ai" / "oll"):
        with pytest.raises(ValueError, match="does not lie inside .*: only a folder of the plugin's own is removed"):
            remove_tree(other, home)
    assert remove_tree(home / "nothing-there", home) == 0
    assert remove_tree(home / "app" / "CURRENT", home) == 8  # a file there goes the same way
    assert remove_tree(home / "app", home) == 1500  # the bytes its files held
    assert names(home) == [] and (models / "blob").read_bytes() == b"z" * 10


def test_removing_follows_no_link(tmp_path):
    home, models, elsewhere = tmp_path / "ai" / "ollama", tmp_path / "models", tmp_path / "elsewhere"
    app = home / "app"
    app.mkdir(parents=True)
    models.mkdir()
    (elsewhere / "x").mkdir(parents=True)
    (models / "blob").write_bytes(b"z" * 1000)
    (elsewhere / "x" / "kept").write_bytes(b"k")
    (app / "f").write_bytes(b"x" * 7)
    if not linked(models, app / "models"):
        pytest.skip("no link can be made here")
    assert remove_tree(app, home) == 7  # a link is removed as the link it is: what it shows is not counted, and stays
    assert names(home) == [] and (models / "blob").read_bytes() == b"z" * 1000
    assert linked(models, home / "cache")  # a folder that is itself a link: the link goes, not what it shows
    assert remove_tree(home / "cache", home) == 0
    assert names(home) == [] and (models / "blob").read_bytes() == b"z" * 1000
    assert linked(elsewhere, home / "via")  # one reached through a link out of the plugin's own: not removed
    with pytest.raises(ValueError, match="is reached through a link that leads out of"):
        remove_tree(home / "via" / "x", home)
    assert (elsewhere / "x" / "kept").read_bytes() == b"k"


def test_what_is_marked_read_only_is_removed_and_what_is_held_is_left_and_said(tmp_path, monkeypatch):
    home = tmp_path / "ai" / "llamacpp"
    app = home / "app"
    for name in ("bin", "lib", "other"):
        (app / name).mkdir(parents=True)
        (app / name / "f").write_bytes(b"x" * 100)
    os.chmod(app / "lib" / "f", stat.S_IREAD)
    if os.name != "nt":
        os.chmod(app / "other", 0o500)  # a folder that lets nothing be removed from it
    assert remove_tree(app / "lib", home) == 100 and remove_tree(app / "other", home) == 100
    (app / "bin" / "held.exe").write_bytes(b"y" * 50)
    real = os.unlink

    def unlink(path, *args, **kwargs):
        if str(path).endswith("held.exe"):  # as Windows refuses a program that still runs
            raise PermissionError(13, "The process cannot access the file because it is being used", str(path))
        return real(path, *args, **kwargs)
    monkeypatch.setattr(os, "unlink", unlink)
    with pytest.raises(OSError) as left:
        remove_tree(app, home)
    assert "held.exe could not be removed: " in str(left.value) and "nor" not in str(left.value)
    assert str(left.value).endswith(f"; 100 B of {app} was removed")
    assert tree(app) == {"bin/held.exe": b"y" * 50}  # the rest still removed
    monkeypatch.setattr(os, "unlink", real)
    assert remove_tree(app, home) == 50 and names(home) == []


# -- the rule ----------------------------------------------------------------------------------------------------
def test_no_address_is_written_out_in_the_module_or_in_these_tests():
    """No .py of the library holds a scheme and a host written out, docstrings included: an address is built from
    its parts, or is its plugin's."""
    written = re.compile(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]")
    for path in (Path(download.__file__), Path(__file__)):
        found = [line for line in path.read_text(encoding="utf-8").splitlines() if written.search(line)]
        assert found == [], path.name
