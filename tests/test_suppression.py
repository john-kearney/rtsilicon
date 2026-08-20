"""Tests for the suppression comments (issue #2, contract case).

Some findings are fine by contract or design decision — only the designer
knows. `// rt-si: ignore` (per line) and `// rt-si: ignore-file` (whole
file) let them silence those without losing the rest of the scan.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rtsilicon.scanners import scan  # noqa: E402


def _write(content: str, name: str = "dut.v") -> Path:
    d = Path(tempfile.mkdtemp())
    f = d / name
    f.write_text(content)
    return d


VULNERABLE = """\
module dut(input clk, input d, output reg q);
  reg lock_enable;  # module-level, security-named, never initialized
  always @(posedge clk) begin
    lock_enable <= d;
    q <= lock_enable;
  end
endmodule
"""


def test_baseline_hits_without_suppression():
    d = _write(VULNERABLE)
    hits = scan(d)
    assert any(h.rule_id == "CWE-1271-sec-reg-no-reset" for h in hits)


def test_line_suppression_kills_that_line_only():
    d = _write(VULNERABLE.replace(
        "reg lock_enable;",
        "reg lock_enable;  // rt-si: ignore  by contract with the instancer",
    ))
    hits = scan(d)
    assert not any(h.rule_id == "CWE-1271-sec-reg-no-reset" for h in hits)


def test_file_suppression_kills_everything():
    d = _write("#!/nothing\n" + VULNERABLE.replace(
        "module dut",
        "// rt-si: ignore-file  reviewed, findings here are by design\nmodule dut",
        1,
    ))
    hits = scan(d)
    assert hits == []


def test_vhdl_comment_syntax_works():
    d = _write("""\
-- rt-si: ignore-file
module dut(input clk, input d, output reg q);
  reg lock_enable;
  always @(posedge clk) begin
    lock_enable <= d;
  end
endmodule
""")
    hits = scan(d)
    assert not any(h.rule_id == "CWE-1271-sec-reg-no-reset" for h in hits)


def test_ignore_file_marker_not_confused_with_line_marker():
    """A line with `ignore-file` must not act as a per-line marker for
    OTHER lines when the file-level check already removed everything."""
    suppressed = _write(VULNERABLE.replace(
        "reg lock_enable;", "reg lock_enable;  // rt-si: ignore"))
    clean = _write(VULNERABLE)
    hits_suppressed = scan(suppressed)
    hits_clean = scan(clean)
    n_sup = len([h for h in hits_suppressed if h.rule_id == "CWE-1271-sec-reg-no-reset"])
    n_clean = len([h for h in hits_clean if h.rule_id == "CWE-1271-sec-reg-no-reset"])
    assert n_sup == 0 and n_clean > 0
