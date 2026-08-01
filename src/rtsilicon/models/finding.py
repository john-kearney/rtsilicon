"""rtsilicon — finding lifecycle models.

The Finding is the central object, exactly as in redthread. A scanner hit is a
CANDIDATE (signal < 50). It only becomes a published Finding after passing the
gates: deduped -> reproducible -> fix_ready -> shipped. The gates are
VERIFICATION, not presence checks.

The taxonomy field binds every finding to a class in VULN-TAXONOMY.md. This is
what lets us build the labeled dataset that becomes the moat.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStage(StrEnum):
    """Mirrors redthread's gated lifecycle. A finding only advances by passing
    a verification gate, never by assertion."""

    CANDIDATE = "candidate"      # scanner hint, unverified
    DEDUPED = "deduped"          # checked against known CVEs/advisories/PRs
    REPRODUCIBLE = "reproducible"  # PoC exists: simulation transcript / proof sketch
    FIX_READY = "fix_ready"      # remediation drafted, lint-clean
    SHIPPED = "shipped"          # advisory sent / PR opened (auth-gated regardless)
    ABANDONED = "abandoned"      # refuted or out of scope


class TaxonomyClass(StrEnum):
    """Each class maps to a MITRE CWE (CWE-1194 Hardware Design view).
    The internal name is for code; the CWE ID is the authoritative
    vocabulary emitted in attestations and reports."""

    # Group A — PUF / TRNG
    PUF_CRP_EXFIL = "A1-PUF-CRP-EXFIL"
    TRNG_STARTUP_BYPASS = "A2-TRNG-STARTUP-TEST-BYPASS"
    TRNG_ENTROPY_INJECTION = "A3-TRNG-ENTROPY-INJECTION"
    # Group B — reset / CDC / FSM
    LOGIC_RESET_RACE = "B1-LOGIC-RESET-RACE"
    FSM_NO_ESCALATION = "B2-FSM-NO-ESCALATION"
    CDC_METASTABILITY = "B3-CDC-METASTABILITY"
    GLITCH_SENSITIVE_COUNTER = "B4-GLITCH-SENSITIVE-COUNTER"
    # Group C — crypto
    UNMASKED_CRYPTO = "C1-UNMASKED-CRYPTO"
    KEY_DATA_DEPENDENT_CONTROL = "C2-KEY-DATA-DEPENDENT-CONTROL"
    CONSTANT_LOADING_LEAK = "C3-CONSTANT-LOADING-LEAK"
    # Group D — privilege
    UNDOCUMENTED_TEST_MODE = "D1-UNDOCUMENTED-TEST-MODE"
    DMA_NO_IOMMU = "D2-DMA-NO-IOMMU"
    MMIO_NO_BOUND = "D3-MMIO-WRITE-NO-BOUND"
    # Group E — trojan
    DORMANT_TRIGGER = "E1-DORMANT-TRIGGER"
    LEAKAGE_TRIGGER = "E2-LEAKAGE-TRIGGER"
    # Group F — provenance
    UNATTRIBUTED_IP = "F1-UNATTRIBUTED-IP"
    BITSTREAM_UNENCRYPTED = "F2-BITSTREAM-UNENCRYPTED"


# Mapping from our internal class names to MITRE CWE IDs.
# This is the authoritative vocabulary — attestations emit CWE IDs.
# See https://cwe.mitre.org/data/definitions/1194.html
#
# Audit 2026-07-25: corrected three mapping errors found by verifying
# against MITRE definitions:
#   - REMOVED CWE-1261 from GLITCH_SENSITIVE_COUNTER: CWE-1261 is about
#     cosmic radiation (SEUs), NOT attacker glitch attacks. Category error.
#     CWE-1247 (missing glitch protection) is the correct primary, even
#     though it's device-level rather than RTL-level — no perfect CWE
#     exists for "unhardened security counter at RTL."
#   - REMOVED CWE-1240 from PUF_CRP_EXFIL and UNMASKED_CRYPTO where it
#     was wrong: CWE-1240 is "choosing a non-standard primitive," not
#     "implementing a standard primitive badly." PUF CRP exfil is closer
#     to CWE-203 (observable discrepancy); unmasked crypto is CWE-1300.
#   - CWE-325 (missing crypto step) is the correct primary for the AES-GCM
#     length-block finding, NOT CWE-1240.
TAXONOMY_TO_CWE: dict[TaxonomyClass, list[str]] = {
    # Group A — PUF / TRNG (CWE-1205 Security Primitives)
    TaxonomyClass.PUF_CRP_EXFIL: ["CWE-203"],  # observable discrepancy / info exposure
    TaxonomyClass.TRNG_STARTUP_BYPASS: ["CWE-1241", "CWE-325"],
    TaxonomyClass.TRNG_ENTROPY_INJECTION: ["CWE-1240", "CWE-1189"],
    # Group B — reset / CDC / FSM (CWE-1199 General Circuit + CWE-1206 Power/Reset)
    TaxonomyClass.LOGIC_RESET_RACE: ["CWE-1271", "CWE-1245", "CWE-362"],
    TaxonomyClass.FSM_NO_ESCALATION: ["CWE-1245"],
    TaxonomyClass.CDC_METASTABILITY: ["CWE-1245", "CWE-1261"],
    TaxonomyClass.GLITCH_SENSITIVE_COUNTER: ["CWE-1247", "CWE-369", "CWE-1285"],
    # Group C — crypto (CWE-1205 Security Primitives)
    TaxonomyClass.UNMASKED_CRYPTO: ["CWE-1300", "CWE-835"],
    TaxonomyClass.KEY_DATA_DEPENDENT_CONTROL: ["CWE-1300", "CWE-1254"],
    TaxonomyClass.CONSTANT_LOADING_LEAK: ["CWE-1300", "CWE-1431"],
    # Group D — privilege (CWE-1198 Privilege Separation + CWE-1203 Peripherals)
    TaxonomyClass.UNDOCUMENTED_TEST_MODE: ["CWE-1191", "CWE-1234", "CWE-1244"],
    TaxonomyClass.DMA_NO_IOMMU: ["CWE-1190", "CWE-1189", "CWE-1318"],
    TaxonomyClass.MMIO_NO_BOUND: ["CWE-1262", "CWE-1220"],
    # Group E — trojan (CWE-1242 Chicken Bits + CWE-1199 Logic)
    TaxonomyClass.DORMANT_TRIGGER: ["CWE-1242"],
    TaxonomyClass.LEAKAGE_TRIGGER: ["CWE-1242", "CWE-1431"],
    # Group F — provenance (CWE-1195 Manufacturing/Lifecycle)
    TaxonomyClass.UNATTRIBUTED_IP: ["CWE-1059", "CWE-1297"],
    TaxonomyClass.BITSTREAM_UNENCRYPTED: ["CWE-1243"],
}


class Finding(BaseModel):
    """The unit of work. Scanner candidates become Findings only through gates."""

    id: str
    target: str = Field(description="repo path or org/design identifier")
    title: str
    severity: Severity
    taxonomy_class: TaxonomyClass
    cwe_ids: list[str] = Field(default_factory=list, description="MITRE CWE IDs (authoritative vocabulary)")
    stage: FindingStage = FindingStage.CANDIDATE

    # Location — file + line range, plus optional module/hierarchy path.
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    module_path: str | None = Field(default=None, description="e.g. top.foo.bar")

    # The reasoning. This is what makes it a real finding and not a grep hit.
    summary: str
    impact: str
    recommendation: str

    # Evidence trail.
    code_snippet: str | None = None
    poc: str | None = Field(default=None, description="testbench, proof sketch, or sim transcript")
    dedup_evidence: str | None = None
    lint_evidence: str | None = None

    # Signal score 0-100. <50 = do not ship. Mirrors redthread.
    signal: int = Field(default=0, ge=0, le=100)
    signal_notes: list[str] = Field(default_factory=list)

    # Provenance.
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def add_signal_note(self, delta: int, note: str) -> None:
        """Every gate mutates signal with a recorded reason. Auditable."""
        self.signal = max(0, min(100, self.signal + delta))
        self.signal_notes.append(f"{'+' if delta >= 0 else ''}{delta}: {note}")
        self.updated_at = datetime.now(UTC)


class AuditRecord(BaseModel):
    """One line per stage transition. Appended to .rtsilicon/audit.jsonl.
    Same discipline as redthread: every promotion is logged."""

    finding_id: str
    from_stage: FindingStage
    to_stage: FindingStage
    signal_after: int
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    operator: str = "agent"


def finding_dir(root: Path) -> Path:
    d = root / ".rtsilicon" / "findings"
    d.mkdir(parents=True, exist_ok=True)
    return d


def persist(finding: Finding, root: Path) -> Path:
    """Write the finding JSON. Idempotent on id."""
    p = finding_dir(root) / f"{finding.id}.json"
    p.write_text(finding.model_dump_json(indent=2))
    return p


def load(finding_id: str, root: Path) -> Finding | None:
    p = finding_dir(root) / f"{finding_id}.json"
    if not p.exists():
        return None
    return Finding.model_validate_json(p.read_text())


def list_all(root: Path) -> list[Finding]:
    return [
        Finding.model_validate_json(p.read_text())
        for p in sorted(finding_dir(root).glob("*.json"))
    ]


def audit_log(root: Path) -> Path:
    p = root / ".rtsilicon" / "audit.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def append_audit(rec: AuditRecord, root: Path) -> None:
    with audit_log(root).open("a") as f:
        f.write(rec.model_dump_json() + "\n")


def gate_transition(
    finding: Finding,
    to_stage: FindingStage,
    signal_delta: int,
    reason: str,
    root: Path,
    operator: str = "agent",
) -> Finding:
    """The ONLY way a finding changes stage. Logs the transition."""
    from_stage = finding.stage
    if to_stage.value not in [s.value for s in FindingStage]:
        raise ValueError(f"unknown stage {to_stage}")
    finding.stage = to_stage
    finding.add_signal_note(signal_delta, reason)
    persist(finding, root)
    append_audit(
        AuditRecord(
            finding_id=finding.id,
            from_stage=from_stage,
            to_stage=to_stage,
            signal_after=finding.signal,
            reason=reason,
            operator=operator,
        ),
        root,
    )
    return finding


# Convenience for scanners that want a free-form props bag.
FindingBag = dict[str, Any]
