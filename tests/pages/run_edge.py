"""Runs a check page of this folder (side-check.html: side.js on stand-ins, and its twin of ui.standard on
tests/data/ui_standard_cases.json) in headless Edge, by hand: `python tests/pages/run_edge.py tests/pages/side-check.html`.
Never run by pytest (the library's tests start no process). A throwaway profile of its own in the system's temporary
folder, no background networking, no component updates, file access for the page's own files; it prints what the page
wrote into #out and exits 1 unless it says ALL PASSED. Edge ends when the page is dumped; the profile is taken away
after."""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


def main(page: str, budget: str = "20000") -> int:
    profile = Path(tempfile.mkdtemp(prefix="liminal-page-check-"))
    flags = ["--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
             "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps",
             "--mute-audio", f"--user-data-dir={profile}", "--allow-file-access-from-files"]
    try:
        got = subprocess.run([EDGE, *flags, f"--virtual-time-budget={budget}", "--dump-dom", Path(page).resolve().as_uri()],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    m = re.search(r'id="out">(.*?)</pre>', got.stdout, re.S)
    out = m.group(1) if m else f"no #out (exit {got.returncode})"
    print(out)
    return 0 if out.startswith("ALL PASSED") else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
