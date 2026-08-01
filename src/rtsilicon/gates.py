"""rtsilicon gates — verification, not presence checks.

Mirrors redthread v0.3 gate semantics:
- reproducible — a PoC (sim transcript / proof sketch) must exist and pass
- deduped — checked against known advisories / CVEs / open PRs
- fix_ready — remediation drafted, lint-clean (or --force-poc with penalty)
- shipped — auth-boundary-gated regardless (see permissions.py)

Each gate either promotes the finding (signal up) or refuses (signal down)
with a recorded reason. Nothing advances by assertion.
"""

from __future__ import annotations

from pathlib import Path

from .models import Finding, FindingStage, gate_transition


def gate_dedup(
    finding: Finding,
    *,
    dedup_evidence_file: Path | None,
    checked_clean: bool,
    root: Path,
) -> Finding:
    """Promote candidate -> deduped.

    checked_clean=True means the agent searched CVE databases, the target's
    issues/PRs, and public advisories and found no duplicate. A machine-
    verifiable evidence file keeps signal at 100; otherwise -20 (honor system).
    """
    if finding.stage != FindingStage.CANDIDATE:
        raise ValueError(f"dedup gate expects CANDIDATE, got {finding.stage}")

    if not checked_clean:
        return gate_transition(
            finding,
            FindingStage.CANDIDATE,
            -10,
            "dedup refused: agent did not confirm clean",
            root,
        )

    if dedup_evidence_file and dedup_evidence_file.exists():
        finding.dedup_evidence = str(dedup_evidence_file)
        return gate_transition(
            finding, FindingStage.DEDUPED, +20, "dedup: machine-verified evidence", root
        )

    return gate_transition(
        finding, FindingStage.DEDUPED, +10, "dedup: agent-confirmed clean (no evidence file)", root
    )


def gate_reproducible(
    finding: Finding,
    *,
    poc: str,
    poc_passes: bool,
    root: Path,
    force_poc: bool = False,
) -> Finding:
    """Promote deduped -> reproducible.

    poc_passes=True means the PoC exits clean (sim transcript shows the buggy
    behaviour, or the proof sketch is valid). force_poc=True allows a non-
    passing PoC through but costs signal — use sparingly.
    """
    if finding.stage != FindingStage.DEDUPED:
        raise ValueError(f"repro gate expects DEDUPED, got {finding.stage}")

    finding.poc = poc

    if poc_passes:
        return gate_transition(
            finding, FindingStage.REPRODUCIBLE, +20, "repro: PoC passes", root
        )

    if force_poc:
        return gate_transition(
            finding,
            FindingStage.REPRODUCIBLE,
            -15,
            "repro: PoC forced (non-passing), signal penalised",
            root,
        )

    return gate_transition(
        finding,
        FindingStage.DEDUPED,
        -15,
        "repro refused: PoC does not pass and --force-poc not set",
        root,
    )


def gate_fix_ready(
    finding: Finding,
    *,
    recommendation: str,
    lint_evidence_file: Path | None,
    root: Path,
) -> Finding:
    """Promote reproducible -> fix_ready.

    Requires the remediation text AND (preferably) machine-verified lint-clean
    evidence. Without the evidence file, signal is reduced.
    """
    if finding.stage != FindingStage.REPRODUCIBLE:
        raise ValueError(f"fix gate expects REPRODUCIBLE, got {finding.stage}")

    finding.recommendation = recommendation

    if lint_evidence_file and lint_evidence_file.exists():
        finding.lint_evidence = str(lint_evidence_file)
        return gate_transition(
            finding, FindingStage.FIX_READY, +15, "fix: lint evidence provided", root
        )

    return gate_transition(
        finding,
        FindingStage.FIX_READY,
        +5,
        "fix: recommendation drafted, no lint evidence (signal reduced)",
        root,
    )


def gate_shipped(finding: Finding, *, root: Path) -> Finding:
    """Promote fix_ready -> shipped. The actual push/advisory-send is
    auth-boundary-gated in permissions.py regardless of this gate."""
    if finding.stage != FindingStage.FIX_READY:
        raise ValueError(f"ship gate expects FIX_READY, got {finding.stage}")
    return gate_transition(finding, FindingStage.SHIPPED, +10, "shipped", root)


def abandon(finding: Finding, *, reason: str, root: Path) -> Finding:
    """Mark a finding abandoned (refuted, out of scope, or duplicate found).
    Signal drops; the finding stays on disk for the audit trail."""
    return gate_transition(
        finding, FindingStage.ABANDONED, -30, f"abandoned: {reason}", root
    )
