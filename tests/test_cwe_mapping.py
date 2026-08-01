"""Tests for the CWE mapping — ensures findings emit MITRE's authoritative
vocabulary, not reinvented class names. Regression-proof: if someone adds
a new TaxonomyClass without a CWE mapping, this catches it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rtsilicon.models import TAXONOMY_TO_CWE, TaxonomyClass
from rtsilicon.scanners import ScanHit, hit_to_candidate


def test_every_taxonomy_class_has_cwe_mapping():
    """Every TaxonomyClass must map to at least one CWE ID. If you add a
    new class, add it to TAXONOMY_TO_CWE or this fails."""
    unmapped = [tc for tc in TaxonomyClass if tc not in TAXONOMY_TO_CWE]
    assert not unmapped, f"TaxonomyClasses without CWE mapping: {unmapped}"


def test_cwe_ids_are_well_formed():
    """CWE IDs must match the CWE-NNNN format."""
    import re
    pat = re.compile(r"^CWE-\d+$")
    for tc, cwes in TAXONOMY_TO_CWE.items():
        for cwe in cwes:
            assert pat.match(cwe), f"{tc}: malformed CWE ID {cwe!r}"


def test_findings_carry_cwe_ids():
    """A Finding materialized from a ScanHit must have cwe_ids populated
    from the taxonomy mapping."""
    hit = ScanHit(
        file=Path("/tmp/x.v"),
        line=1,
        snippet="reg [15:0] round_ctr;",
        rule_id="B4-plain-counter",
        taxonomy_class=TaxonomyClass.GLITCH_SENSITIVE_COUNTER,
        initial_signal=15,
        note="test",
    )
    finding = hit_to_candidate(hit, "test", 0)
    assert finding.cwe_ids, "Finding has no CWE IDs"
    assert "CWE-1247" in finding.cwe_ids
    # CWE-1261 was REMOVED in the audit — it's about cosmic radiation (SEUs),
    # not attacker glitch attacks. Assert it's NOT there.
    assert "CWE-1261" not in finding.cwe_ids


def test_dma_finding_maps_to_cwe_1190():
    """The D2-DMA class must map to CWE-1190 (DMA Enabled Too Early) —
    this is the canonical CWE for the FastVDMA/dma_axi finding."""
    cwes = TAXONOMY_TO_CWE[TaxonomyClass.DMA_NO_IOMMU]
    assert "CWE-1190" in cwes
    assert "CWE-1189" in cwes  # improper isolation of shared resources


def test_debug_finding_maps_to_cwe_1191():
    """The D1 debug class must map to CWE-1191 (On-Chip Debug Improper
    Access Control) — the canonical CWE for the VexRiscv godmode finding."""
    cwes = TAXONOMY_TO_CWE[TaxonomyClass.UNDOCUMENTED_TEST_MODE]
    assert "CWE-1191" in cwes
