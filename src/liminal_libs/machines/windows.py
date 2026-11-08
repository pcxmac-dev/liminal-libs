"""Windows for the machine plugins (the firewall and admin plugins of the platform): Windows PowerShell run
windowless, its script given as -EncodedCommand (UTF-16 base64: no quoting to go wrong), wrapped so a failure
comes back as one line of its own words, objects back as JSON; whether this process is elevated; a script run
elevated, through Windows' own prompt (UAC), when the user says so (LIMINAL_ELEVATE=prompt). A runner stands
in for powershell.exe in tests."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from .plugin import CommandError

TIMEOUT_S = 120.0
ELEVATE_VAR = "LIMINAL_ELEVATE"  # prompt: a step needing an administrator asks through UAC; else it fails saying so
ERROR_MARK = "LIMINAL-ERROR: "
PRELUDE = ("$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; "
           "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n")
DENIED = ("access is denied", "access denied", "0x80070005", "requires elevation", "run as administrator",
          "administrator privileges", "permission denied", "not have permission")


def quote(text) -> str:
    """`text` as a PowerShell single-quoted string."""
    return "'" + str(text).replace("'", "''") + "'"


def is_elevated() -> bool:
    """Whether this process runs with an administrator's rights (Windows only; False elsewhere)."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - not known: not elevated
        return False


def wrapped(script: str) -> str:
    """The script with the prelude and a catch that prints one ERROR_MARK line and exits 1."""
    return PRELUDE + "try {\n" + script + "\n} catch { [Console]::Out.WriteLine('" + ERROR_MARK + "' + $_.Exception.Message); exit 1 }"


def encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def decoded(value: str) -> str:
    """An -EncodedCommand's script (for tests and logs)."""
    return base64.b64decode(value).decode("utf-16-le")


class PowerShell:
    """powershell.exe, windowless. `runner(args, timeout) -> (code, stdout text, stderr text)` stands in for it."""

    def __init__(self, runner=None, env=None):
        self._runner = runner
        self._env = env

    @property
    def here(self) -> bool:
        return self._runner is not None or (os.name == "nt" and shutil.which("powershell") is not None)

    def args(self, script: str) -> list[str]:
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded(wrapped(script))]

    def run(self, script: str, timeout: float = TIMEOUT_S) -> str:
        """The script's output; CommandError with its own words (denied when it needed an administrator)."""
        args = self.args(script)
        if self._runner is not None:
            code, out, err = self._runner(args, timeout)
        else:
            if not self.here:
                raise CommandError("Windows PowerShell is not here (this is not Windows)")
            try:
                done = subprocess.run(args, capture_output=True, timeout=timeout, **_no_window())
            except subprocess.TimeoutExpired:
                raise CommandError(f"PowerShell took more than {timeout:g} s") from None
            except OSError as e:
                raise CommandError(f"PowerShell could not run: {e}") from None
            code, out, err = done.returncode, done.stdout.decode("utf-8", "replace"), done.stderr.decode("utf-8", "replace")
        if code != 0:
            words = next((line[len(ERROR_MARK):].strip() for line in out.splitlines() if line.startswith(ERROR_MARK)), "")
            words = words or _clean(err) or out.strip() or f"PowerShell failed ({code})"
            raise CommandError(words, denied=any(d in words.lower() for d in DENIED))
        return out

    def json(self, script: str, timeout: float = TIMEOUT_S) -> list[dict]:
        """The objects a script emits, as dicts (none: [])."""
        out = self.run("@(" + script + ") | ConvertTo-Json -Compress -Depth 5", timeout).strip()
        if not out:
            return []
        data = json.loads(out)
        return data if isinstance(data, list) else [data]

    def run_elevated(self, script: str, timeout: float = 600.0) -> str:
        """The script run with an administrator's rights: Windows asks the user once (UAC); its output comes
        back through a file in the temporary folder. CommandError when the user declines or the script fails."""
        out_file = Path(tempfile.gettempdir()) / f"liminal-elevated-{uuid.uuid4().hex}.txt"
        inner = (PRELUDE + "try {\n& {\n" + script + "\n} *>&1 | Out-File -FilePath " + quote(out_file) + " -Encoding utf8\n"
                 "} catch { ('" + ERROR_MARK + "' + $_.Exception.Message) | Out-File -FilePath " + quote(out_file) + " -Encoding utf8; exit 1 }")
        outer = ("$p = Start-Process -FilePath powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList "
                 "'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','" + encoded(inner) + "'; "
                 "[Console]::Out.WriteLine('exit ' + $p.ExitCode)")
        try:
            status = self.run(outer, timeout)
            text = out_file.read_text(encoding="utf-8-sig") if out_file.exists() else ""
        finally:
            try:
                out_file.unlink()
            except OSError:
                pass
        failed = next((line[len(ERROR_MARK):].strip() for line in text.splitlines() if line.startswith(ERROR_MARK)), "")
        if failed or "exit 0" not in status:
            raise CommandError(failed or f"the elevated script ended with {status.strip() or 'no answer'}")
        return text

    def run_admin(self, script: str, timeout: float = TIMEOUT_S) -> str:
        """A script that needs an administrator: run as it is; when denied, run elevated if the user said so
        (LIMINAL_ELEVATE=prompt), else CommandError saying how to give it the rights."""
        try:
            return self.run(script, timeout)
        except CommandError as e:
            if not e.denied:
                raise
            env = os.environ if self._env is None else self._env
            if (env.get(ELEVATE_VAR) or "").strip().lower() == "prompt":
                return self.run_elevated(script, max(timeout, 600.0))
            raise CommandError(f"this needs an administrator: run the platform as administrator, or set {ELEVATE_VAR}=prompt "
                               f"to be asked (UAC) when a step needs it ({e})", denied=True) from None


def _clean(err: str) -> str:
    """stderr without PowerShell's CLIXML wrapping: its first readable line."""
    for line in (err or "").splitlines():
        line = line.strip()
        if line and not line.startswith(("#< CLIXML", "<Objs", "<S ", "</Objs")):
            return line
    return ""


def _no_window() -> dict:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}  # CREATE_NO_WINDOW
