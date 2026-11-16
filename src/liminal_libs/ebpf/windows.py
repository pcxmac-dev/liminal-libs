"""The eBPF runtime on Windows (the design: "WindowsRuntime checks sc query eBPFCore/NetEbpfExt/eBPFSvc and
netsh ebpf show programs when installed; why_not_here() reads Secure Boot, HVCI and test signing"). Every read here
is read-only and asks for no rights it does not need: the three service states and the installed version, then the
program listing when the runtime is installed, and the Secure Boot, memory-integrity and test-signing facts that
decide whether anything can load.

The plain fact, which `why_not_here` always says: every public eBPF for Windows build is test-signed pre-release,
so on a machine with Secure Boot on it needs test-signing mode (Secure Boot off, a Test Mode desktop) before the
core driver will start. This PC runs Secure Boot and memory integrity, so the test-signed runtime cannot load; the
Windows capture backend uses Npcap and ETW instead (the user's decision, 2026-11-14), behind the same interface an
eBPF backend would fill once signed builds exist."""
from __future__ import annotations

from ..machines.plugin import CommandError
from ..machines.windows import PowerShell
from .runtime import Runtime

SERVICES = ("eBPFCore", "NetEbpfExt", "eBPFSvc")
# Where test signing was read, as FACTS_READ names it, and how the words say it.
SIGNING_SOURCES = {"boot options": "this boot's start options", "bcdedit": "bcdedit's entry for this Windows"}
TEST_SIGNED = ("every eBPF for Windows build is test-signed pre-release, so it needs test-signing mode "
               "(Secure Boot off, a Test Mode desktop) before the core driver will start")

# Read the three service states and the installed version. Each lookup is guarded, so a missing service or folder
# leaves a blank rather than failing the read.
SERVICES_READ = r"""
$names = '""" + "','".join(SERVICES) + r"""'
$svc = foreach ($n in $names) {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    [pscustomobject]@{ Name = $n; Present = [bool]$s
        Status = if ($s) { $s.Status.ToString() } else { '' }
        StartType = if ($s) { $s.StartType.ToString() } else { '' } }
}
$ver = ''
try {
    $dll = Join-Path $env:ProgramFiles 'ebpf-for-windows\EbpfApi.dll'
    if (Test-Path $dll) { $ver = [string](Get-Item $dll -ErrorAction Stop).VersionInfo.ProductVersion }
} catch { }
[pscustomobject]@{ Services = $svc; Version = $ver }
"""

# This boot's start options: where Windows keeps them (any user may read the value), the option test-signing mode adds
# to them (as a whole word, matched as PowerShell's -match does, ignoring case: never NOTESTSIGNING), and bcdedit's
# line for the setting in its {current} entry.
BOOT_OPTIONS_KEY = r"HKLM:\SYSTEM\CurrentControlSet\Control"
BOOT_OPTIONS_VALUE = "SystemStartOptions"
TESTSIGNING_OPTION = r"(^|\s)TESTSIGNING(\s|$)"
BCD_TESTSIGNING = r"(?m)^\s*testsigning\s+Yes\b"

# Secure Boot, memory integrity (HVCI) and test signing, each read on its own so one failing does not lose the rest.
# Test signing is read first from this boot's own start options (the registry's SystemStartOptions, which carries
# TESTSIGNING while Windows runs in test-signing mode): what is in effect now, which is what decides whether a
# test-signed driver loads. bcdedit's {current} entry only where that value cannot be read, and only when bcdedit
# answered: without an administrator it prints an error where the entry would be (its words differ from one build to
# another) and exits 1, so only its exit code and the entry are trusted (1.60.0: its error was read as the entry,
# and test signing was said off unread). The names and patterns above are put in where @KEY@, @VALUE@, @OPTION@ and
# @BCD@ stand.
FACTS_READ = (r"""
$out = [ordered]@{ SecureBoot = $null; SecureBootSource = 'unknown'; Hvci = $null
    TestSigning = $null; TestSigningReadable = $false; TestSigningSource = 'unknown' }
try { $out.SecureBoot = [bool](Confirm-SecureBootUEFI); $out.SecureBootSource = 'firmware' }
catch {
    try {
        $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction Stop
        $out.SecureBoot = [bool]$v.UEFISecureBootEnabled; $out.SecureBootSource = 'registry'
    } catch { $out.SecureBootSource = 'unknown' }
}
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $out.Hvci = [bool](@([int[]]$dg.SecurityServicesRunning) -contains 2)
} catch { $out.Hvci = $null }
try {
    $control = Get-ItemProperty -Path '@KEY@' -Name @VALUE@ -ErrorAction Stop
    $opts = $control.@VALUE@
    if ($null -ne $opts) {
        $out.TestSigning = [bool]([string]$opts -match '@OPTION@')
        $out.TestSigningReadable = $true; $out.TestSigningSource = 'boot options'
    }
} catch { }
if (-not $out.TestSigningReadable) {
    try {
        $bcd = cmd /c 'bcdedit /enum {current} 2>nul' | Out-String
        if ($LASTEXITCODE -eq 0 -and $bcd -match '\{current\}') {
            $out.TestSigning = [bool]($bcd -match '@BCD@')
            $out.TestSigningReadable = $true; $out.TestSigningSource = 'bcdedit'
        }
    } catch { }
}
[pscustomobject]$out
""".replace("@KEY@", BOOT_OPTIONS_KEY).replace("@VALUE@", BOOT_OPTIONS_VALUE)
              .replace("@OPTION@", TESTSIGNING_OPTION).replace("@BCD@", BCD_TESTSIGNING))


class WindowsRuntime(Runtime):
    """The eBPF for Windows runtime, read through the library's windowless PowerShell. `powershell` stands in for
    it in tests; `env` is passed through to a default PowerShell."""

    system = "windows"

    def __init__(self, powershell: PowerShell | None = None, env=None):
        self.ps = powershell if powershell is not None else PowerShell(env=env)

    # -- status ----------------------------------------------------------------------------------------------

    def status(self) -> dict:
        """The three services and the installed version; when the core service is there, the program listing too
        (netsh ebpf show programs). `present` is whether any of the three services exist; `why` carries the
        test-signed caveat, which holds whatever this machine's state."""
        out: dict = {"present": False, "system": "windows", "applies": True, "installed": False,
                     "version": "", "services": [], "programs": [], "programs_note": "", "why": TEST_SIGNED}
        try:
            read = self.ps.json(SERVICES_READ)
        except CommandError as e:
            out["why"] = f"the eBPF services could not be read: {e}"
            out["summary"] = "eBPF state could not be read"
            return out
        data = read[0] if read else {}
        services = data.get("Services") if isinstance(data, dict) else None
        rows = services if isinstance(services, list) else [services] if isinstance(services, dict) else []
        out["services"] = [{"name": r.get("Name", ""), "present": bool(r.get("Present")),
                            "status": r.get("Status", ""), "start": r.get("StartType", "")}
                           for r in rows if isinstance(r, dict)]
        out["version"] = str((data.get("Version") if isinstance(data, dict) else "") or "")
        out["present"] = any(s["present"] for s in out["services"])
        out["installed"] = out["present"]
        core = next((s for s in out["services"] if s["name"] == "eBPFCore"), None)
        if core and core["present"]:
            out["programs"], out["programs_note"] = self._programs_or_note()
        out["summary"] = self._summary(out)
        return out

    def _summary(self, out: dict) -> str:
        if not out["present"]:
            return "eBPF for Windows is not installed (a pre-release, test-signed download)"
        running = [s["name"] for s in out["services"] if s["status"] == "Running"]
        core = "core running" if "eBPFCore" in running else "core not running"
        version = f" v{out['version']}" if out["version"] else ""
        return f"eBPF for Windows installed{version}, {core}; {TEST_SIGNED}"

    def _programs_or_note(self) -> tuple[list[dict], str]:
        """`netsh ebpf show programs` parsed to rows; a note instead when it cannot be read (it needs an
        administrator, by the core device's access control)."""
        try:
            text = self.ps.run("netsh ebpf show programs")
        except CommandError as e:
            return [], f"the program listing needs an administrator: {e}"
        return _table(text), ""

    # -- why it may not run here -----------------------------------------------------------------------------

    def why_not_here(self) -> dict:
        """Secure Boot, memory integrity and test signing on this machine, and the words for the page. Read-only:
        Confirm-SecureBootUEFI when it answers unelevated, else the registry; memory integrity from the device
        guard information; test signing from this boot's start options (`test_signing_source` "boot options"),
        else from bcdedit when it answered ("bcdedit"), else not read ("unknown", `test_signing_readable` False).
        The test-signed caveat is always said."""
        facts: dict = {"secure_boot": None, "secure_boot_source": "unknown", "hvci": None,
                       "test_signing": None, "test_signing_readable": False, "test_signing_source": "unknown",
                       "blocked": None, "words": ""}
        try:
            read = self.ps.json(FACTS_READ)
        except CommandError as e:
            facts["words"] = f"this machine's Secure Boot and memory-integrity state could not be read ({e}); {TEST_SIGNED}"
            return facts
        data = read[0] if read else {}
        if isinstance(data, dict):
            facts["secure_boot"] = _bool(data.get("SecureBoot"))
            facts["secure_boot_source"] = str(data.get("SecureBootSource") or "unknown")
            facts["hvci"] = _bool(data.get("Hvci"))
            readable = bool(data.get("TestSigningReadable"))
            source = str(data.get("TestSigningSource") or "unknown")
            value = _bool(data.get("TestSigning"))
            if readable and source in SIGNING_SOURCES and value is not None:  # a read gives a source and a value
                facts["test_signing"] = value
                facts["test_signing_readable"], facts["test_signing_source"] = True, source
        facts["blocked"], facts["words"] = self._verdict(facts)
        return facts

    def _verdict(self, facts: dict) -> tuple[bool | None, str]:
        parts: list[str] = []
        sb, hvci, ts = facts["secure_boot"], facts["hvci"], facts["test_signing"]
        if sb is True:
            parts.append("Secure Boot is on")
        elif sb is False:
            parts.append("Secure Boot is off")
        if hvci is True:
            parts.append("memory integrity is on, so the JIT cannot run and only signed native drivers load")
        elif hvci is False:
            parts.append("memory integrity is off")
        if facts["test_signing_readable"]:
            where = SIGNING_SOURCES[facts["test_signing_source"]]
            parts.append(f"test signing is {'on' if ts else 'off'}, read from {where}")
        else:
            parts.append("test signing could not be read here (neither this boot's start options nor bcdedit answered)")
        blocked: bool | None
        if sb is True and ts is not True:
            blocked = True
            head = ("the test-signed runtime cannot load here: Secure Boot is on and test signing is off" if ts is False
                    else "the test-signed runtime cannot load here: Secure Boot is on, which keeps test-signing mode "
                    "off")
        elif ts is True and hvci is not True:
            blocked = False
            head = "a test-signed native driver could load (test signing is on)"
        else:
            blocked = None if sb is None else (sb is True)
            head = "whether the test-signed runtime can load depends on the state below"
        detail = "; ".join(parts)
        return blocked, f"{head} ({detail}). {TEST_SIGNED}."

    # -- programs, maps, links (netsh text tables; empty when it cannot be read) -----------------------------

    def programs(self) -> list[dict]:
        return self._netsh("programs")

    def maps(self) -> list[dict]:
        return self._netsh("maps")

    def links(self) -> list[dict]:
        return self._netsh("links")

    def program(self, prog_id) -> dict:
        try:
            text = self.ps.run(f"netsh ebpf show programs id={int(prog_id)} level=verbose")
        except CommandError:
            return {}
        rows = _table(text)
        return rows[0] if rows else {"detail": text.strip()}

    def dump_map(self, map_id, limit: int = 1000) -> list[dict]:
        # netsh only lists maps; reading a map's contents is the bpftool port's or the API's job, not available here.
        return []

    def _netsh(self, what: str) -> list[dict]:
        try:
            return _table(self.ps.run(f"netsh ebpf show {what}"))
        except CommandError:
            return []


def _table(text: str) -> list[dict]:
    """A netsh-style aligned table as rows: the first non-empty line is the header, a rule line of dashes is
    skipped, and each row is split on runs of two or more spaces into the header's columns."""
    lines = [ln.rstrip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return []
    header = [h.strip().lower() for h in _split(lines[0])]
    rows = []
    for line in lines[1:]:
        if set(line.strip()) <= {"-", "=", " "}:
            continue
        cells = _split(line)
        if len(cells) == 1 and len(header) > 1:  # a wrapped or note line, not a row
            continue
        rows.append({header[i] if i < len(header) else f"col{i}": cells[i].strip() for i in range(len(cells))})
    return rows


def _split(line: str) -> list[str]:
    import re

    return [c for c in re.split(r"\s{2,}", line.strip()) if c != ""]


def _bool(value):
    """A tri-state from PowerShell's JSON: True, False, or None when it was null (could not be read)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("true", "1", "yes", "on"):
        return True
    if text in ("false", "0", "no", "off"):
        return False
    return None
