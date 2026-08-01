"""Plain-English output for rt-si findings.

Translates CWE-anchored scanner hits into human-readable descriptions:
- What's wrong (in plain English)
- Where it is (file:line)
- Why it matters (the security impact)
- How to fix it (concrete suggestion)

This is the accessibility layer that makes rt-si usable by people
who don't know what CWE-1190 is.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PlainFinding:
    """A finding described in plain English."""
    severity_icon: str        # 🔴 / 🟡 / 🔵
    severity_label: str       # HIGH / MEDIUM / LOW
    title: str                # one-line plain-English title
    location: str             # file:line
    why: str                  # why it matters (plain English)
    fix: str                  # how to fix it (plain English)
    cwe: str                  # the CWE ID (for reference, not primary)


# The translation table: rule_id → plain English
# This is what makes the tool accessible. Every scanner rule has an entry.
PLAIN_ENGLISH: dict[str, PlainFinding] = {
    "B4-plain-counter": PlainFinding(
        severity_icon="🟡", severity_label="MEDIUM",
        title="Counter vulnerable to glitching",
        location="", why="", fix="", cwe="CWE-1247",
    ),
    "B1-reset-x-predicate": PlainFinding(
        severity_icon="🔴", severity_label="HIGH",
        title="Reset logic compares against 'x' — won't work in real silicon",
        location="", why="", fix="", cwe="CWE-1271",
    ),
    "B2-fsm-not-sparse": PlainFinding(
        severity_icon="🟡", severity_label="MEDIUM",
        title="State machine has no Error state for fault protection",
        location="", why="", fix="", cwe="CWE-1245",
    ),
    "D1-undocumented-test-mode": PlainFinding(
        severity_icon="🔴", severity_label="HIGH",
        title="Debug/test interface accessible without authentication",
        location="", why="", fix="", cwe="CWE-1191",
    ),
    "D2-dma-addr-from-csr": PlainFinding(
        severity_icon="🔴", severity_label="HIGH",
        title="DMA can access any memory address",
        location="", why="", fix="", cwe="CWE-1190",
    ),
    "D2-dma-no-range-check": PlainFinding(
        severity_icon="🔴", severity_label="HIGH",
        title="DMA has no address-range enforcement",
        location="", why="", fix="", cwe="CWE-1190",
    ),
    "C1-unmasked-crypto": PlainFinding(
        severity_icon="🟡", severity_label="MEDIUM",
        title="Crypto core has no side-channel masking",
        location="", why="", fix="", cwe="CWE-1300",
    ),
    "CWE1284-length-underflow": PlainFinding(
        severity_icon="🔴", severity_label="HIGH",
        title="Length/count subtraction can underflow to a huge value",
        location="", why="", fix="", cwe="CWE-125",
    ),
    "CWE362-nba-race": PlainFinding(
        severity_icon="🟡", severity_label="MEDIUM",
        title="Signal assigned twice in same clock cycle — last one wins silently",
        location="", why="", fix="", cwe="CWE-362",
    ),
    "CWE1233-key-midop": PlainFinding(
        severity_icon="🟡", severity_label="MEDIUM",
        title="Key register writable while operation is in progress",
        location="", why="", fix="", cwe="CWE-1233",
    ),
    "CWE835-index-dup": PlainFinding(
        severity_icon="🔴", severity_label="HIGH",
        title="Duplicate array index — likely copy-paste error producing wrong output",
        location="", why="", fix="", cwe="CWE-835",
    ),
    "CWE369-div-by-zero": PlainFinding(
        severity_icon="🟡", severity_label="MEDIUM",
        title="Division without checking for zero divisor",
        location="", why="", fix="", cwe="CWE-369",
    ),
    "CWE-1271-sec-reg-no-reset": PlainFinding(
        severity_icon="🟡", severity_label="MEDIUM",
        title="Security register has no explicit reset value",
        location="", why="", fix="", cwe="CWE-1271",
    ),
    "CWE-1239-secret-no-zeroize": PlainFinding(
        severity_icon="🟡", severity_label="MEDIUM",
        title="Secret data not cleared after use",
        location="", why="", fix="", cwe="CWE-1239",
    ),
    "CWE-1255-comparison-early-exit": PlainFinding(
        severity_icon="🟡", severity_label="MEDIUM",
        title="Secret comparison exits early — leaks matched count",
        location="", why="", fix="", cwe="CWE-1255",
    ),
    "E1-magic-constant": PlainFinding(
        severity_icon="🔵", severity_label="LOW",
        title="Undocumented magic constant in control flow",
        location="", why="", fix="", cwe="CWE-1242",
    ),
    # VHDL rules
    "B4-vhdl-plain-counter": None,  # reuse B4-plain-counter text
    "B1-vhdl-reset-x": None,
    "D1-vhdl-debug-enable": None,
    "D2-vhdl-dma-addr": None,
    "C1-vhdl-unmasked-crypto": None,
    "E1-vhdl-magic-constant": None,
}

# Fill in why/fix text for each
_WHY_FIX = {
    "CWE-1247": (
        "A voltage spike (glitch attack) can flip a bit in this counter, "
        "resetting it. If the counter gates a security check (login limit, "
        "round count, timeout), the attacker bypasses it.",
        "Replace the plain counter with a redundant encoding: store the "
        "value AND its bitwise complement. Check they agree every cycle. "
        "Any mismatch = immediate error."
    ),
    "CWE-1271": (
        "In real silicon, flip-flops power up to an undefined value. If "
        "'undefined' means 'protection disabled,' the chip boots insecure "
        "until firmware enables protection — creating an attack window.",
        "Add an explicit reset value: if (!rst_n) register <= 0; (or 1, "
        "whichever is the SECURE default for this register)."
    ),
    "CWE-1191": (
        "A debug or test interface (JTAG, scan chain, debug bus) is "
        "accessible without authentication. Anyone with physical (or bus) "
        "access can read internal state, inject instructions, or escalate "
        "privilege.",
        "Gate the debug interface with a lifecycle controller or "
        "authentication signal. In production state, all debug access "
        "should be blocked."
    ),
    "CWE-1190": (
        "The DMA controller's address comes from a software-writable "
        "register with no address-range check. Any software that can write "
        "the register can read/write ANY address in the system, including "
        "keys, boot code, and security configuration.",
        "Add an address-range check: define allowed base and limit "
        "addresses. Reject (and alert on) any DMA transaction outside "
        "the allowed range."
    ),
    "CWE-1300": (
        "This crypto core has no masking against power/EM side-channel "
        "attacks. The power consumption during encryption depends on the "
        "key, allowing an attacker with physical access to recover the key "
        "by measuring power draw.",
        "If the threat model includes physical access, use a masked "
        "implementation. If not, document this as a known limitation."
    ),
    "CWE-125": (
        "When the length/count field is smaller than the header constant "
        "(e.g., length=0), the unsigned subtraction wraps around to a "
        "huge value (~65535). The module then processes far more data "
        "than intended, passing attacker-controlled data past security "
        "boundaries.",
        "Add a bounds check before the subtraction: "
        "if (length >= HEADER_SIZE) word_count = length - HEADER_SIZE; "
        "else discard the frame."
    ),
    "CWE-362": (
        "The same signal is assigned twice via non-blocking assignment "
        "(<=) in the same clock cycle. Verilog's rule is 'last assignment "
        "wins' — the second assignment silently overrides the first. This "
        "can cause data corruption or counter drift.",
        "Combine the assignments into a single if/else chain, or compute "
        "the next value combinationally before assigning."
    ),
    "CWE-1233": (
        "Security-critical registers (key, password, configuration) can "
        "be overwritten at any time — even while an operation is in "
        "progress. Overwriting mid-operation produces corrupted output "
        "silently.",
        "Add a ready/busy guard: only accept register writes when the "
        "core is idle. Reject writes during active operation."
    ),
    "CWE-835": (
        "An array index appears twice in a concatenation, likely due to "
        "a copy-paste error. This means one element is duplicated and "
        "another is skipped, producing wrong output (e.g., wrong hash).",
        "Check the indices in the concatenation against the spec. Fix "
        "the duplicated index to reference the correct element."
    ),
    "CWE-369": (
        "Division is performed without checking for a zero divisor. "
        "Division by zero produces undefined or incorrect results.",
        "Add a guard: if (divisor != 0) result = dividend / divisor; "
        "else handle the zero case per spec."
    ),
    "CWE-1245": (
        "The state machine doesn't use sparse encoding or a default→Error "
        "path. A single-bit fault in the state register can land in a "
        "defined-but-wrong state, bypassing security checks.",
        "Add a default→Error branch to every case statement. Consider "
        "using one-hot or gray-code state encoding for critical FSMs."
    ),
    "CWE-1239": (
        "Secret data (keys, passwords, RNG state) is stored in registers "
        "that are never cleared. After use, the data persists and can be "
        "read by the next user or via debug access.",
        "Clear secret registers after use: on session end, ownership "
        "change, or reset. Assign zero to the register."
    ),
    "CWE-1255": (
        "The comparison exits early when a mismatch is found. The timing "
        "difference between 'matched N bytes' and 'matched N+1 bytes' is "
        "measurable through power analysis, leaking the secret one byte "
        "at a time.",
        "Use a constant-time comparison: XOR all bytes and accumulate "
        "mismatches. Never exit early."
    ),
    "CWE-1242": (
        "An undocumented constant value in a control-flow predicate. "
        "Usually legitimate (opcode, protocol value), but occasionally a "
        "dormant trigger for a hardware trojan.",
        "Document the constant. If it's not in the spec, investigate why "
        "it's there."
    ),
}


def get_plain_finding(rule_id: str, cwe_id: str, file: str, line: int) -> PlainFinding:
    """Get a PlainFinding for a scanner hit, with location filled in."""

    # Check VHDL aliases
    vhdl_alias = {
        "B4-vhdl-plain-counter": "B4-plain-counter",
        "B1-vhdl-reset-x": "B1-reset-x-predicate",
        "D1-vhdl-debug-enable": "D1-undocumented-test-mode",
        "D2-vhdl-dma-addr": "D2-dma-addr-from-csr",
        "C1-vhdl-unmasked-crypto": "C1-unmasked-crypto",
        "E1-vhdl-magic-constant": "E1-magic-constant",
    }
    effective_rule = vhdl_alias.get(rule_id, rule_id)

    template = PLAIN_ENGLISH.get(effective_rule)
    if template is None:
        # Unknown rule — generic fallback
        return PlainFinding(
            severity_icon="🔵", severity_label="INFO",
            title=f"Scanner flagged: {rule_id}",
            location=f"{file}:{line}",
            why="The scanner detected a pattern that may be security-relevant. "
                "Review the code at the indicated location.",
            fix="See the rtsilicon field guide for guidance on this CWE class.",
            cwe=cwe_id,
        )

    # Fill in why/fix from the CWE lookup
    why, fix = _WHY_FIX.get(cwe_id, ("Review the field guide entry for this CWE.", ""))

    return PlainFinding(
        severity_icon=template.severity_icon,
        severity_label=template.severity_label,
        title=template.title,
        location=f"{file}:{line}",
        why=why,
        fix=fix,
        cwe=cwe_id,
    )


def format_plain_report(findings: list[PlainFinding], target_name: str = "") -> str:
    """Format a list of plain findings as a human-readable report."""
    if not findings:
        return f"✅ All clear. 0 issues found in {target_name or 'design'}.\n"

    high = sum(1 for f in findings if f.severity_label == "HIGH")
    medium = sum(1 for f in findings if f.severity_label == "MEDIUM")
    low = sum(1 for f in findings if f.severity_label in ("LOW", "INFO"))

    lines = [
        f"🔍 Scanned {target_name or 'design'} ...",
        "",
        f"Found {len(findings)} issue{'s' if len(findings) != 1 else ''}:",
        "",
    ]

    for f in findings:
        lines.append(f"{f.severity_icon} {f.severity_label}: {f.title}")
        lines.append(f"   📍 {f.location}")
        if f.why:
            lines.append(f"   💡 {f.why}")
        if f.fix:
            # Wrap fix text at ~70 chars
            words = f.fix.split()
            fix_line = "   🔧 "
            for word in words:
                if len(fix_line) + len(word) > 75:
                    lines.append(fix_line)
                    fix_line = "      " + word
                else:
                    fix_line += word + " "
            lines.append(fix_line.rstrip())
        lines.append("")

    lines.append(f"📊 Summary: {high} high, {medium} medium, {low} low")

    if high == 0 and medium == 0:
        lines.append("✅ No critical issues. Your design looks clean.")
    elif high > 0:
        lines.append(f"⚠️  {high} high-severity issue(s) should be fixed before tapeout.")

    return "\n".join(lines)
