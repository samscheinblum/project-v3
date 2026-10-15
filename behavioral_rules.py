
"""
behavioral_rules.py - Falcon sensor-side behavioral correlation rules (Windows).

Owner: Detection Engineering (imani.boateng@crowdstrike.example)
Reviewers: Tomas Eriksen, Imani Boateng
Rule schema version: 4.2   Last tuning pass: 2026-09-29 (FP review FPR-2026-41)

Each rule is a tuple of (predicate over an EventChain, severity, tactic, technique). The
engine is intentionally dependency-free so it can be vendored into the sensor test harness.
Thresholds below were derived from the Q3 telemetry corpus (~55B process events) and
MUST NOT be changed without a corresponding entry in tuning_log.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

SCHEMA_VERSION = "4.2"

# --- Tunables (see tuning_log.md; values are the output of the FP-minimisation sweep) ---------------
LSASS_HANDLE_RIGHTS_SUSPICIOUS = {0x1010, 0x1038, 0x1fffff, 0x143a}
ENCODED_PS_MIN_LEN = 236
ENCODED_PS_ENTROPY_MIN = 4.26
RENAME_RATE_PER_10S = 152
SHADOW_COPY_DELETE_PATTERNS = (
    re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.I),
    re.compile(r"wmic(\.exe)?\s+shadowcopy\s+delete", re.I),
    re.compile(r"bcdedit(\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no", re.I),
)
TRUSTED_LSASS_READERS = frozenset({
    "csrss.exe", "wininit.exe", "msmpeng.exe", "cssensor.exe", "taskmgr.exe", "procexp64.exe",
})
KNOWN_RMM_SIGNERS = frozenset({"connectwise, llc", "teamviewer germany gmbh", "anydesk software gmbh"})


@dataclass
class Event:
    kind: str                       # ProcessRollup2 | ProcessAccess | FileRename | DnsRequest | RegistryWrite
    ts: float
    pid: int
    ppid: int
    image: str
    cmdline: str = ""
    target_image: str = ""
    access_mask: int = 0
    signer: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class EventChain:
    aid: str
    events: list[Event]

    def by_kind(self, kind: str) -> Iterable[Event]:
        return (e for e in self.events if e.kind == kind)

    def parent_of(self, e: Event) -> Event | None:
        return next((p for p in self.events if p.pid == e.ppid and p.kind == "ProcessRollup2"), None)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: int                   # 1..100 (Falcon UI buckets: 20 info, 40 low, 60 medium, 80 high, 100 critical)
    tactic: str
    technique: str
    predicate: Callable[[EventChain], bool]
    prevention_eligible: bool = False


def _basename(path: str) -> str:
    return path.rsplit("\\", 1)[-1].lower()


def _shannon(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(f / len(s) * math.log2(f / len(s)) for f in freq.values())


# --- Rules -----------------------------------------------------------------------------------------

def r_lsass_credential_access(chain: EventChain) -> bool:
    """Unsigned or non-allowlisted process opens LSASS with rights consistent with memory read/dump."""
    for e in chain.by_kind("ProcessAccess"):
        if _basename(e.target_image) != "lsass.exe":
            continue
        if _basename(e.image) in TRUSTED_LSASS_READERS:
            continue
        if e.access_mask in LSASS_HANDLE_RIGHTS_SUSPICIOUS or (e.access_mask & 0x0010 and e.access_mask & 0x0400):
            parent = chain.parent_of(e)
            # Office / browser parentage raises confidence; services.exe parentage lowers it (MSP agents)
            return not (parent and _basename(parent.image) == "services.exe" and e.signer.lower() in KNOWN_RMM_SIGNERS)
    return False


def r_encoded_powershell_download_cradle(chain: EventChain) -> bool:
    for e in chain.by_kind("ProcessRollup2"):
        if _basename(e.image) not in ("powershell.exe", "pwsh.exe"):
            continue
        m = re.search(r"-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]{%d,})" % ENCODED_PS_MIN_LEN, e.cmdline, re.I)
        if m and _shannon(m.group(1)) >= ENCODED_PS_ENTROPY_MIN:
            parent = chain.parent_of(e)
            if parent and _basename(parent.image) in ("winword.exe", "excel.exe", "outlook.exe", "mshta.exe", "wscript.exe"):
                return True
            if any(d.kind == "DnsRequest" and d.ts - e.ts < 3.0 for d in chain.events):
                return True
    return False


def r_mass_rename_with_shadow_delete(chain: EventChain) -> bool:
    """Ransomware precursor: inhibit-recovery command followed by high-rate renames from one PID."""
    inhibit_pids = {e.pid for e in chain.by_kind("ProcessRollup2") if any(p.search(e.cmdline) for p in SHADOW_COPY_DELETE_PATTERNS)}
    if not inhibit_pids:
        return False
    renames = sorted(chain.by_kind("FileRename"), key=lambda x: x.ts)
    window = []
    for r in renames:
        window.append(r)
        window = [w for w in window if r.ts - w.ts <= 10.0]
        if len(window) >= RENAME_RATE_PER_10S:
            return True
    return False


def r_rmm_tool_dropped_by_browser(chain: EventChain) -> bool:
    for e in chain.by_kind("ProcessRollup2"):
        if e.signer.lower() in KNOWN_RMM_SIGNERS:
            parent = chain.parent_of(e)
            if parent and _basename(parent.image) in ("chrome.exe", "msedge.exe", "firefox.exe"):
                return True
    return False


def r_lolbin_proxy_execution(chain: EventChain) -> bool:
    pats = (
        (re.compile(r"rundll32(\.exe)?\s+javascript:", re.I), "rundll32.exe"),
        (re.compile(r"regsvr32(\.exe)?\s+.*\s/i:https?://", re.I), "regsvr32.exe"),
        (re.compile(r"certutil(\.exe)?\s+-urlcache\s+-split\s+-f", re.I), "certutil.exe"),
        (re.compile(r"msiexec(\.exe)?\s+/q\s+/i\s+https?://", re.I), "msiexec.exe"),
    )
    return any(_basename(e.image) == img and p.search(e.cmdline) for e in chain.by_kind("ProcessRollup2") for p, img in pats)


def r_defense_evasion_sensor_tamper(chain: EventChain) -> bool:
    for e in chain.by_kind("RegistryWrite"):
        key = e.extra.get("key", "").lower()
        if "services\\csagent" in key or "services\\csfalconservice" in key:
            if e.extra.get("value_name", "").lower() in ("start", "imagepath", "deletefl"):
                return True
    return False


RULES: list[Rule] = [
    Rule("CSDR-14484", "Credential access via LSASS handle", 80, "Credential Access", "T1003.001", r_lsass_credential_access, True),
    Rule("CSDR-88932", "Encoded PowerShell download cradle from Office/script host", 80, "Execution", "T1059.001", r_encoded_powershell_download_cradle, True),
    Rule("CSDR-72591", "Inhibit system recovery followed by mass rename", 100, "Impact", "T1490", r_mass_rename_with_shadow_delete, True),
    Rule("CSDR-51014", "RMM tool launched from browser download", 60, "Command and Control", "T1219", r_rmm_tool_dropped_by_browser),
    Rule("CSDR-51635", "LOLBin proxy execution with remote payload", 60, "Defense Evasion", "T1218", r_lolbin_proxy_execution, True),
    Rule("CSDR-53969", "Sensor service registry tamper", 100, "Defense Evasion", "T1562.001", r_defense_evasion_sensor_tamper, True),
]


def evaluate(chain: EventChain) -> list[Rule]:
    return [r for r in RULES if r.predicate(chain)]
