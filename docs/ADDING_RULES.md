# Adding a detection rule to rtsilicon

A rule is a Python function that takes `(file: Path, text: str)` and
returns a list of `ScanHit` objects. This guide shows how to add one in
under 30 minutes.

## The 5-minute version

```python
# 1. Write your regex
import re
MY_RULE_RE = re.compile(r"pattern_to_match", re.IGNORECASE)

# 2. Write the function
def _scan_my_rule(file: Path, text: str) -> list[ScanHit]:
    hits: list[ScanHit] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if MY_RULE_RE.search(line):
            hits.append(ScanHit(
                file=file,
                line=i,
                snippet=line.strip(),
                rule_id="MY-RULE-name",           # short ID
                taxonomy_class=TaxonomyClass.SOME_CLASS,  # from models
                initial_signal=20,                 # 0-100, <50 = low confidence
                note="What this means + which CWE.",
            ))
    return hits

# 3. Register it
# Add _scan_my_rule to the RULES tuple at the bottom of patterns.py
```

## The ScanHit dataclass

```python
@dataclass
class ScanHit:
    file: Path           # the file being scanned
    line: int            # 1-based line number
    snippet: str         # the matched line (stripped)
    rule_id: str         # short identifier (e.g., "B4-plain-counter")
    taxonomy_class: TaxonomyClass  # maps to CWE IDs via TAXONOMY_TO_CWE
    initial_signal: int  # 0-100, how confident the rule is
    note: str            # human-readable explanation for the triage agent
```

## Available TaxonomyClass values (and their CWE mappings)

| TaxonomyClass | CWE IDs |
|---|---|
| PUF_CRP_EXFIL | CWE-203 |
| TRNG_STARTUP_BYPASS | CWE-1241, CWE-325 |
| LOGIC_RESET_RACE | CWE-1271, CWE-1245 |
| FSM_NO_ESCALATION | CWE-1245 |
| GLITCH_SENSITIVE_COUNTER | CWE-1247 |
| UNMASKED_CRYPTO | CWE-1300 |
| KEY_DATA_DEPENDENT_CONTROL | CWE-1300, CWE-1254 |
| UNDOCUMENTED_TEST_MODE | CWE-1191, CWE-1234, CWE-1244 |
| DMA_NO_IOMMU | CWE-1190, CWE-1189, CWE-1318 |
| DORMANT_TRIGGER | CWE-1242 |

If your rule maps to a CWE not listed here, add it to `TAXONOMY_TO_CWE`
in `models/finding.py`.

## Signal scoring guide

| Signal | Meaning | When to use |
|--------|---------|-------------|
| 10-15 | Very low confidence — high false-positive rate | Magic constants, loose patterns |
| 20-30 | Low-medium — needs human confirmation | Counters, crypto references |
| 35-50 | Medium — likely a real pattern but needs context | DMA address from CSR |
| 50+ | High — very likely real (rare for regex rules) | Double-gated auth bypass |

Most regex rules should start at 15-30. The scanner is a HINT, not a
finding — the triage layer (human or LLM) raises the signal after review.

## File-type handling

Rules are called for every file that passes `iter_target_files`. If your
rule only applies to specific file types, check the extension:

```python
def _scan_my_rule(file: Path, text: str) -> list[ScanHit]:
    # Only scan Verilog files
    if file.suffix.lower() not in (".v", ".sv"):
        return []
    # ...
```

**Important:** documentation files (.md, .yaml) are only scanned by
doc-signal rules. If your rule matches code patterns, it will NOT fire
on documentation (the `_DOC_SAFE_RULES` set controls this). This
prevents false positives on field-guide examples.

## Excluding testbenches and generated files

```python
def _scan_my_rule(file: Path, text: str) -> list[ScanHit]:
    name = file.name.lower()
    if name.startswith("tb_") or name.endswith("_tb.v"):
        return []
    # Skip HLS-generated code
    if "sva_1" in text[:1000].lower():
        return []
    # ...
```

## Testing your rule

Add a positive and negative sample to `tests/test_precision_benchmark.py`:

```python
POSITIVES["my_rule_positive"] = """
    module vulnerable(input clk);
        // RTL that SHOULD trigger your rule
    endmodule
"""

NEGATIVES["my_rule_negative"] = """
    module safe(input clk);
        // RTL that looks similar but SHOULD NOT trigger
    endmodule
"""
```

Run: `pytest tests/test_precision_benchmark.py -v -s`

Your rule should catch the positive and miss the negative. If it fires
on the negative, tighten the regex or add an exclusion.

## Example: a complete rule for CWE-1284 (length-field underflow)

This is the bug class found across multiple OSS Ethernet and SoC designs.

```python
# Regex: length_field - constant without bounds check
_LENGTH_UNDERFLOW_RE = re.compile(
    r"(length|num|count|total_length)\w*\s*[-]\s*(\d+|h[0-9a-fA-F]+|header\w*\.length)",
    re.IGNORECASE,
)

def _scan_length_underflow(file: Path, text: str) -> list[ScanHit]:
    if file.suffix.lower() not in (".v", ".sv", ".vhd", ".vhdl", ".py"):
        return []
    hits: list[ScanHit] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if _LENGTH_UNDERFLOW_RE.search(line):
            hits.append(ScanHit(
                file=file, line=i, snippet=line.strip(),
                rule_id="CWE1284-length-underflow",
                taxonomy_class=TaxonomyClass.MMIO_NO_BOUND,  # closest class
                initial_signal=35,
                note="Unsigned subtraction of a constant from a length/count "
                     "field. If the field can be < the constant, this underflows. "
                     "Check: is the field validated before this subtraction? "
                     "(CWE-125 / CWE-1284).",
            ))
    return hits
```

**Note:** this rule is NOT yet in the scanner because it has a high
false-positive rate on legitimate arithmetic. It's included here as a
template for a more sophisticated rule (e.g., one that checks whether
the length field comes from a packet header or external input).

## What makes a good rule

1. **Specific enough to avoid noise:** the pattern should match the
   vulnerability, not just any similar syntax. Test against negatives.
2. **Anchored to a CWE:** every rule maps to a real MITRE CWE. If you
   can't map it, it's not a hardware security weakness.
3. **Low initial signal:** the scanner is a hint. Let the triage layer
   (human or LLM) decide if it's real. Start at 15-30.
4. **Documented:** the `note` field should tell the triage agent what
   to check and why it matters. "Counter declared as plain reg" is
   unhelpful. "Counter gating a security decision — a glitch on the MSB
   can bypass the threshold (CWE-1247)" is helpful.
5. **Tested:** add positive AND negative samples to the precision
   benchmark. If you can't think of a negative, your rule is too broad.
