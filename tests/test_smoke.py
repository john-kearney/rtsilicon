"""Smoke test: scanner must reproduce the TT07 RO-PUF findings.

This is the proof that the scanner works. If we can't reproduce F1-F5 (the
findings I made by hand on the same target), the tool is vapor.

These tests need the local audit targets, which only exist on the
machine the dataset was built on. They skip everywhere else (fresh
clones, other machines) instead of failing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the package importable without install.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rtsilicon.scanners import scan  # noqa: E402

# TT07 RO-PUF target — cloned earlier in the session.
TARGET = Path("/Users/johnkearney/ZCodeProject/silicon-audit/targets/tt07-RO-based-PUF")

# Antmicro FastVDMA — paying-customer demo target for the D-group rules.
FASTVDMA = Path("/Users/johnkearney/ZCodeProject/silicon-audit/targets/fastvdma")

pytestmark = pytest.mark.skipif(
    not TARGET.exists(), reason=f"local audit target not present: {TARGET}"
)


def test_scanner_fires_on_target():
    """Scanner must produce at least some hits on the TT07 design."""
    hits = scan(TARGET)
    assert len(hits) > 0, "scanner produced zero hits — broken"


def test_scanner_finds_reset_x_predicate():
    """F2 (CRITICAL): arbiter.v has `if (marked_1 == 'x ...)`.

    The exact bug. The B1 rule must fire.
    """
    hits = scan(TARGET)
    reset_hits = [h for h in hits if h.rule_id == "B1-reset-x-predicate"]
    assert reset_hits, "B1 rule did not fire on arbiter.v — F2 missed"
    # Must point at the arbiter file.
    assert any("arbiter" in str(h.file).lower() for h in reset_hits)


def test_scanner_finds_crp_exfil():
    """F1 (CRITICAL): README crowdsources CRPs, 8-bit challenge.

    The A1 rule must fire on the README.
    """
    hits = scan(TARGET)
    crp_hits = [h for h in hits if h.rule_id == "A1-puf-crp-exfil"]
    assert crp_hits, "A1 rule did not fire — F1 missed"


def test_scanner_finds_glitch_counter():
    """F3 (HIGH): counter.v has a plain reg[15:0] threshold counter.

    The B4 rule should fire.
    """
    hits = scan(TARGET)
    counter_hits = [
        h for h in hits if h.rule_id == "B4-plain-counter" and "counter" in str(h.file).lower()
    ]
    assert counter_hits, "B4 rule did not fire on counter.v — F3 missed"


def test_all_hits_are_candidates_not_findings():
    """Discipline check: every scanner hit must convert to a low-signal
    CANDIDATE finding, never a promoted finding."""
    from rtsilicon.scanners import hit_to_candidate

    hits = scan(TARGET)
    for i, h in enumerate(hits):
        cand = hit_to_candidate(h, target_id="test", counter=i)
        assert cand.signal < 60, f"candidate signal too high: {cand.signal}"


# ---------------------------------------------------------------------------
# D-group tests — FastVDMA paying-customer demo
# ---------------------------------------------------------------------------


def test_scanner_finds_dma_addr_from_csr():
    """D2 (HIGH): FastVDMA sinks an unchecked CSR-derived address onto the AXI bus.

    The canonical paying-customer finding. The taint chain is:
      io.ctl.startAddress  (AddressGenerator.scala:62)
        -> address_i -> io.xfer.address  (AddressGenerator.scala:45)
        -> araddr      (AXI4Reader.scala:52, araddr sourced from io.xfer.address)
    The security-relevant sink is the AXI frontend (araddr/awaddr). The D2
    rule correctly fires there. Asserting on the reader/writer files, not
    the AddressGenerator source.
    """
    hits = scan(FASTVDMA)
    d2_addr = [h for h in hits if h.rule_id == "D2-dma-addr-from-csr"]
    assert d2_addr, "D2-dma-addr-from-csr did not fire on FastVDMA — paying demo missed"
    frontend = [
        h for h in d2_addr
        if any(name in str(h.file).lower() for name in ("axi4reader", "axi4writer", "axi4litewriter"))
    ]
    assert frontend, (
        f"D2 fired but not on an AXI frontend (reader/writer); got files: "
        f"{[str(h.file) for h in d2_addr]}"
    )


def test_scanner_flags_no_range_guard_in_dma_file():
    """D2 corroboration: any file driving araddr/awaddr with no range-guard
    token in the file gets the corroborating hit."""
    hits = scan(FASTVDMA)
    d2_norange = [h for h in hits if h.rule_id == "D2-dma-no-range-check"]
    assert d2_norange, "D2-dma-no-range-check corroborating rule did not fire"


def test_d_group_rules_do_not_crash_on_crypto_targets():
    """Regression: the new D-group regexes must not break scanning of the
    crypto cores (which have no DMA)."""
    aes = Path("/Users/johnkearney/ZCodeProject/silicon-audit/targets/aes")
    if not aes.exists():
        return  # skip if aes wasn't cloned
    hits = scan(aes)
    # We don't assert what crypto hits we get — only that it doesn't crash.
    assert isinstance(hits, list)


def test_scanner_does_not_fire_on_documentation():
    """Regression: the scanner must NOT pattern-match code rules on
    documentation files. Field guides contain EXAMPLE vulnerable code for
    teaching — firing on those is a false positive. Found by audit
    2026-07-25: B1/B4/D2 rules were matching code blocks in .md files."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        # A markdown file with example vulnerable Verilog in a code block
        (d / "tutorial.md").write_text(
            "# Tutorial\n\nHere is bad code:\n```verilog\n"
            "reg [15:0] round_ctr;\nalways @(posedge clk) round_ctr <= round_ctr + 1;\n"
            "if (state == 'x) ...\n```\n"
        )
        hits = scan(d)
        # Should be 0 — documentation is not scanned by code rules
        code_rule_hits = [h for h in hits if h.rule_id != "A1-puf-crp-exfil"]
        assert len(code_rule_hits) == 0, (
            f"scanner fired {len(code_rule_hits)} code-rule hits on a .md file: "
            f"{[h.rule_id for h in code_rule_hits]}"
        )

