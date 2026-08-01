"""rt-si attest — the `make secure` layer.

Runs the scanner against an RTL target, collects findings, and emits a
CWE-anchored attestation: a signed (integrity-hashed) JSON record stating
"this design was scanned by rtsilicon vX on date Y; here are the CWE
classes with candidates." Plus a README-embeddable badge.

This is the contribution-pipeline integration (Gap 2). Designed to run:
  - Locally: `rt-si attest --target ./my_design`
  - In CI: `rt-si attest --target . --ci --exit-on-high`
  - As a GitHub Action: via the action.yml wrapper

The attestation is content-hashed (SHA-256 over the canonical JSON) for
integrity. A future version will use Sigstore for cryptographic signing.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import __version__
from .scanners import scan
from .scanners.patterns import hit_to_candidate


@dataclass
class Attestation:
    """The security attestation record for a design."""

    design_name: str
    scanned_at: str  # ISO-8601 UTC
    scanner_version: str
    target_path: str
    total_candidates: int
    cwe_summary: dict[str, int]  # CWE-ID -> count of candidates
    severity_summary: dict[str, int]  # severity -> count
    rtl_files_scanned: int
    notes: list[str] = field(default_factory=list)

    def integrity_hash(self) -> str:
        """SHA-256 over the canonical JSON. Binds the record to its content."""
        blob = json.dumps(asdict(self), sort_keys=True).encode()
        return hashlib.sha256(blob).hexdigest()

    def to_badge_markdown(self) -> str:
        """README-embeddable badge."""
        if self.total_candidates == 0:
            color = "brightgreen"
            label = "0 findings"
        else:
            high_count = (
                self.severity_summary.get("HIGH", 0)
                + self.severity_summary.get("CRITICAL", 0)
            )
            if high_count > 0:
                color = "red"
                label = f"{high_count} high"
            else:
                color = "yellow"
                label = f"{self.total_candidates} candidates"
        h = self.integrity_hash()[:12]
        # URL-encode the label for shields.io (spaces -> %20)
        import urllib.parse
        label_encoded = urllib.parse.quote(label)
        return (
            f"![rtsilicon](https://img.shields.io/badge/rtsilicon-{label_encoded}-{color})\n"
            f"<sub>scanned {self.scanned_at[:10]} · rtsilicon v{self.scanner_version} · "
            f"integrity `{h}`</sub>"
        )


def attest_target(
    target: Path,
    *,
    design_name: str | None = None,
) -> Attestation:
    """Scan a target and produce an attestation."""
    from collections import Counter

    if design_name is None:
        design_name = target.name

    # Count RTL files we'll scan
    from .scanners.patterns import iter_target_files
    rtl_files = list(iter_target_files(target))

    # Run the scanner
    hits = scan(target)

    # Materialize candidates to get CWE IDs
    candidates = [hit_to_candidate(h, str(target), i) for i, h in enumerate(hits)]

    # Aggregate by CWE
    cwe_counts: Counter = Counter()
    severity_counts: Counter = Counter()
    for c in candidates:
        for cwe in c.cwe_ids:
            cwe_counts[cwe] += 1
        # All candidates are INFO severity from the scanner; the agent
        # would triage to real severities. For the attestation, we report
        # what the scanner found.
        severity_counts["CANDIDATE"] += 1

    att = Attestation(
        design_name=design_name,
        scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        scanner_version=__version__,
        target_path=str(target),
        total_candidates=len(candidates),
        cwe_summary=dict(cwe_counts.most_common()),
        severity_summary=dict(severity_counts),
        rtl_files_scanned=len(rtl_files),
        notes=[
            "Scanner candidates are HINTS, not confirmed vulnerabilities. "
            "Each requires human review before acting.",
            "A clean attestation (0 candidates) means no pattern hits at "
            "this scanner version's sensitivity — not a guarantee of security.",
        ],
    )
    return att


def write_attestation(att: Attestation, out_path: Path) -> Path:
    """Write the attestation as JSON (with integrity hash) to out_path."""
    payload = asdict(att)
    payload["integrity_hash"] = att.integrity_hash()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    return out_path
