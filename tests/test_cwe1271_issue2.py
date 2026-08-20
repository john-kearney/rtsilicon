"""Regression tests for issue #2 (secworks/aes false positives).

Two bugs in CWE-1271 were reported by a real user running the tool on
their own AES core:

1. Substring name matching: 'block' matched 'lock', so every *_block
   variable in an AES core was flagged as a security register.
2. No declaration-context check: 'reg' declared inside always @* is a
   combinational local (a wire), not a flip-flop, and must never be
   flagged as needing a reset.

The reproducer below is the exact code from the issue.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rtsilicon.scanners.patterns import _scan_sec_reg_no_reset


def _write(content: str, name: str = "dut.v") -> tuple[Path, Path]:
    d = Path(tempfile.mkdtemp())
    f = d / name
    f.write_text(content)
    return d, f


# The exact code from issue #2 (aes_encipher_block.v round_logic).
# None of these variables may be flagged.
ISSUE2_REPRO = """\
module aes_encipher_block(input clk, input rst_n);

  always @*
    begin : round_logic
      reg [127 : 0] old_block, shiftrows_block, mixcolumns_block;
      reg [127 : 0] addkey_init_block, addkey_main_block, addkey_final_block;

      block_new   = 128'h0;
      muxed_sboxw = 32'h0;

      old_block          = {block_w0_reg, block_w1_reg, block_w2_reg, block_w3_reg};
      shiftrows_block    = old_block;
      mixcolumns_block   = shiftrows_block;
      addkey_init_block  = old_block;
      addkey_main_block  = mixcolumns_block;
      addkey_final_block = shiftrows_block;
    end

endmodule
"""


def test_issue2_repro_no_hits():
    """The exact code from the issue must produce ZERO hits."""
    _d, f = _write(ISSUE2_REPRO)
    hits = _scan_sec_reg_no_reset(f, f.read_text())
    assert hits == [], f"issue #2 regression: {[(h.snippet, h.line) for h in hits]}"


def test_block_names_do_not_match_lock():
    """Module-level *_block declarations must not be flagged (substring bug)."""
    _d, f = _write("""\
module m(input clk);
  reg [127:0] data_block;
  reg [127:0] block_reg;
  reg [31:0] clock_divider;
endmodule
""")
    hits = _scan_sec_reg_no_reset(f, f.read_text())
    names = [h.snippet for h in hits]
    assert hits == [], f"*_block / clock_* matched as lock: {names}"


def test_always_at_star_locals_not_flagged():
    """A security-named reg inside always @* is combinational, not a FF."""
    _d, f = _write("""\
module m(input clk, input [31:0] a);
  reg [31:0] lock_state;  // module-level, would normally flag
  always @*
    begin : comb
      reg [31:0] enable_tmp;  // combinational local, must NOT flag
      enable_tmp = a + 1;
      lock_state = enable_tmp;
    end
endmodule
""")
    hits = _scan_sec_reg_no_reset(f, f.read_text())
    # lock_state is driven combinationally here with no reset path; the rule
    # may flag the module-level one, but the local enable_tmp must never hit.
    for h in hits:
        assert "enable_tmp" not in h.snippet, "combinational local flagged"


def test_always_comb_locals_not_flagged():
    """SystemVerilog always_comb locals are combinational too."""
    _d, f = _write("""\
module m(input logic [31:0] a);
  always_comb begin
    reg [31:0] secure_scratch;  // local, not a FF
    secure_scratch = a ^ 32'hFF;
  end
endmodule
""")
    hits = _scan_sec_reg_no_reset(f, f.read_text())
    assert hits == [], f"always_comb local flagged: {[h.snippet for h in hits]}"


def test_true_positive_lock_reg_still_flagged():
    """The fix must not kill the true positive: module-level lock_reg
    with no reset assignment anywhere must still be flagged."""
    _d, f = _write("""\
module m(input clk, input d);
  reg lock_enable;
  always @(posedge clk)
    lock_enable <= d;
endmodule
""")
    hits = _scan_sec_reg_no_reset(f, f.read_text())
    assert any("lock_enable" in h.snippet for h in hits), "true positive lost"


def test_reset_lock_reg_not_flagged():
    """Module-level lock_reg WITH a reset assignment must not be flagged."""
    _d, f = _write("""\
module m(input clk, input rst_n, input d);
  reg lock_enable;
  always @(posedge clk)
    if (!rst_n) lock_enable <= 1'b0;
    else lock_enable <= d;
endmodule
""")
    hits = _scan_sec_reg_no_reset(f, f.read_text())
    assert hits == [], f"reset register still flagged: {[h.snippet for h in hits]}"


def test_security_names_still_recognized():
    """Token-based matching must still catch the real security names."""
    from rtsilicon.scanners.patterns import _is_security_name
    must_match = ["lock_reg", "lock_enable", "jtag_lock", "secure_en",
                  "debug_en", "scan_mode", "priv_level", "auth_ok"]
    must_not = ["old_block", "addkey_final_block", "clock_div", "block_reg",
                "shiftrows_block", "data_bus", "counter"]
    for n in must_match:
        assert _is_security_name(n), f"'{n}' should match"
    for n in must_not:
        assert not _is_security_name(n), f"'{n}' should NOT match"
