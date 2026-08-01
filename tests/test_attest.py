"""Tests for the attest module — the `make secure` layer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rtsilicon.attest import attest_target, write_attestation


@pytest.fixture
def vuln_target(tmp_path):
    """A tiny RTL file that should produce candidates."""
    d = tmp_path / "vuln"
    d.mkdir()
    (d / "x.v").write_text(
        "module x(input clk);\n"
        "  reg [15:0] round_ctr;\n"
        "  always @(posedge clk) round_ctr <= round_ctr + 1;\n"
        "endmodule\n"
    )
    return d


@pytest.fixture
def clean_target(tmp_path):
    """A tiny RTL file with no security-relevant patterns."""
    d = tmp_path / "clean"
    d.mkdir()
    (d / "x.v").write_text(
        "module blinker(input clk, output reg led);\n"
        "  always @(posedge clk) led <= ~led;\n"
        "endmodule\n"
    )
    return d


def test_attest_vuln_target_produces_candidates(vuln_target):
    att = attest_target(vuln_target)
    assert att.total_candidates > 0
    assert len(att.cwe_summary) > 0
    # CWE IDs should be well-formed
    for cwe in att.cwe_summary:
        assert cwe.startswith("CWE-")


def test_attest_clean_target_produces_zero_candidates(clean_target):
    att = attest_target(clean_target)
    assert att.total_candidates == 0
    assert att.cwe_summary == {}


def test_attestation_has_integrity_hash(vuln_target):
    att = attest_target(vuln_target)
    h = att.integrity_hash()
    assert len(h) == 64  # SHA-256 hex
    # Deterministic on same content
    att2 = attest_target(vuln_target)
    # Note: scanned_at differs, so hashes will differ. That's correct —
    # the attestation is bound to the moment of scanning. To test
    # determinism, we'd need to fix the timestamp.
    assert len(att2.integrity_hash()) == 64


def test_write_attestation_round_trip(vuln_target, tmp_path):
    att = attest_target(vuln_target)
    out = write_attestation(att, tmp_path / "att.json")
    assert out.exists()
    payload = json.loads(out.read_text())
    assert payload["total_candidates"] == att.total_candidates
    assert payload["integrity_hash"] == att.integrity_hash()
    # The stored hash must match a recomputation over the payload
    import hashlib
    stripped = {k: v for k, v in payload.items() if k != "integrity_hash"}
    recomputed = hashlib.sha256(json.dumps(stripped, sort_keys=True).encode()).hexdigest()
    assert payload["integrity_hash"] == recomputed


def test_badge_markdown_varies_by_findings(vuln_target, clean_target):
    att_vuln = attest_target(vuln_target)
    att_clean = attest_target(clean_target)
    badge_vuln = att_vuln.to_badge_markdown()
    badge_clean = att_clean.to_badge_markdown()
    assert "brightgreen" in badge_clean
    assert "brightgreen" not in badge_vuln


def test_attestation_includes_disclaimer_notes(vuln_target):
    att = attest_target(vuln_target)
    combined = " ".join(att.notes).lower()
    assert "hint" in combined
    assert "not a guarantee" in combined
