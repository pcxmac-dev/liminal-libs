"""No file this release adds to the library writes out an address (A-revisions M12; DECISIONS: "Outside addresses live
in the plugins (`apis.py` or a constants module), never in liminal-libs' .py files"): a scheme and a host written whole,
docstrings and comments included, are in none of them. An address is built from its parts (endpoint.base_url), or it
is its plugin's. Each file is named: one that is not there fails its own test, so the list cannot go stale by a file
moving away or not being written yet."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import liminal_libs

pytestmark = pytest.mark.usefixtures("no_outside")

ROOT = Path(liminal_libs.__file__).resolve().parent
WRITTEN = re.compile(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9\[]")  # a scheme, then a host (or an address in brackets)
ADDED = ("instances.py", "console.py", "machines/children.py", "machines/endpoint.py", "machines/download.py",
         "machines/gpu.py", "machines/autostart.py", "machines/uv.py", "machines/ai.py", "machines/modelserver.py",
         "machines/harness.py", "machines/launch.py")


@pytest.mark.parametrize("name", ADDED)
def test_no_file_of_this_release_writes_out_an_address(name):
    path = ROOT / name
    assert path.is_file(), f"{name} is not in the library: this release adds it"
    found = [f"{n}: {line.strip()}" for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
             if WRITTEN.search(line)]
    assert found == [], f"{name} writes out an address: {found}"


def test_the_pattern_finds_what_it_is_for():
    """The pattern itself: it finds an address written whole and leaves what only looks like one."""
    https, http = "https:" + "//", "http:" + "//"
    for text in (f"{https}example.test", f"{http}127.0.0.1:11434", f"{http}[::1]:8000", f"git+ssh:{'//'}host"):
        assert WRITTEN.search(text), text
    for text in ("a scheme:// alone", "C:\\Users", "//host", "http or https", "127.0.0.1:11434", f"{https}"):
        assert not WRITTEN.search(text), text
