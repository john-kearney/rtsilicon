"""rtsilicon scanners.

DISCIPLINE (carried over from redthread): THE SCANNER IS A HINT, NOT A FINDING.
Every function here returns CANDIDATE findings with low default signal. The
agent must read the code, form a creative hypothesis, build a PoC, and verify
before promoting through the gates.

Why this matters here specifically: hardware bugs that matter are semantic
(reset races, CRP exposure, FSM escalation) not syntactic. A pattern match on
`== 'x` is useless without the reasoning that says "this is a reset predicate
that won't fire in silicon." The scanner surfaces the line; the agent proves
the bug.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, FindingStage, Severity, TaxonomyClass

# File types we consider RTL/RTL-adjacent for scanning.
RTL_GLOBS = ("*.v", "*.sv", "*.vhd", "*.vhdl", "*.chisel", "*.scala")


@dataclass
class ScanHit:
    """A raw pattern hit. Not yet a Finding — the agent triages these."""

    file: Path
    line: int
    snippet: str
    rule_id: str
    taxonomy_class: TaxonomyClass
    initial_signal: int
    note: str


# ---------------------------------------------------------------------------
# Rule implementations. Each rule is a function over file lines.
# ---------------------------------------------------------------------------

_RESET_X_RE = re.compile(r"==\s*('x|1'bx|'X)\b")
_RESET_Z_RE = re.compile(r"==\s*('z|1'bz|'Z)\b")
# "if (... rst ...)" in close proximity to a security-looking signal is a
# B1 hint; we keep it loose and let the agent decide.
_RESET_PREDICATE_RE = re.compile(r"if\s*\([^)]*\brst\b[^)]*\)")


def _scan_reset_x_predicate(file: Path, text: str) -> list[ScanHit]:
    """B1-LOGIC-RESET-RACE: reset predicate compares against 'x'/'z'.

    This is the exact TT07 RO-PUF arbiter bug: a reset term that only fires
    in simulation because FFs power up to 'x' there but to a real 0/1 in
    silicon. Almost always indicates a broken reset mental model.

    Exclude simulation/formal checker files: 'x'/'z' checks are CORRECT in
    assertion checkers, protocol checkers, and formal properties — they're
    only wrong when they appear in synthesised RTL reset paths.
    """
    name = file.name.lower()
    in_sim_path = any(
        part in {"sim", "formal", "tb", "dv", "verif"}
        or "checker" in part
        for part in file.parts
    )
    if (
        "checker" in name
        or "assertion" in name
        or "_asserts" in name
        or name.endswith("_assert.sv")
        or in_sim_path
    ):
        return []
    hits: list[ScanHit] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if _RESET_X_RE.search(line) or _RESET_Z_RE.search(line):
            hits.append(
                ScanHit(
                    file=file,
                    line=i,
                    snippet=line.strip(),
                    rule_id="B1-reset-x-predicate",
                    taxonomy_class=TaxonomyClass.LOGIC_RESET_RACE,
                    initial_signal=35,
                    note=(
                        "Reset/control predicate compares against 'x' or 'z'. "
                        "In silicon this never evaluates true — likely dead reset "
                        "logic or a broken FSM mental model. Read the surrounding "
                        "always-block before promoting."
                    ),
                )
            )
    return hits


# Detection of "no sparse FSM" is structural: a state enum that is NOT wrapped
# in PRIM_FLOP_SPARSE_FSM (lowRISC's hardened register) and is used in a
# state_q/state_d pattern. Also matches VHDL state types.
_STATE_ENUM_RE = re.compile(r"\b(enum|typedef\s+enum|type\s+\w+\s+is\b.*\(.*\))", re.IGNORECASE)
_SPARSE_FSM_RE = re.compile(r"PRIM_FLOP_SPARSE_FSM|prim_flop_sparse_fsm", re.IGNORECASE)
_STATE_REG_RE = re.compile(r"state_[qd]\b|state_r\b|\.state\b", re.IGNORECASE)


def _scan_fsm_no_escalation(file: Path, text: str) -> list[ScanHit]:
    """B2-FSM-NO-ESCALATION: FSM declared without sparse-state encoding.

    Single-bit faults on the state register land in undefined behaviour
    instead of a terminal Error state. OpenTitan uses PRIM_FLOP_SPARSE_FSM
    everywhere; absence elsewhere is the signal.
    """
    hits: list[ScanHit] = []
    has_enum = bool(_STATE_ENUM_RE.search(text))
    has_state_reg = bool(_STATE_REG_RE.search(text))
    has_sparse = bool(_SPARSE_FSM_RE.search(text))
    if has_enum and has_state_reg and not has_sparse:
        # Find a representative line — the enum declaration.
        for i, line in enumerate(text.splitlines(), start=1):
            if _STATE_ENUM_RE.search(line):
                hits.append(
                    ScanHit(
                        file=file,
                        line=i,
                        snippet=line.strip(),
                        rule_id="B2-fsm-not-sparse",
                        taxonomy_class=TaxonomyClass.FSM_NO_ESCALATION,
                        initial_signal=25,
                        note=(
                            "FSM declared with a plain enum and state_q/state_d "
                            "registers, no PRIM_FLOP_SPARSE_FSM. Glitching the state "
                            "register is likely to land in defined-but-wrong states. "
                            "Verify the case has a default -> Error and that there is "
                            "a local_escalate override."
                        ),
                    )
                )
                break
    return hits


# A plain reg[N] counter that guards a security decision.
# Token-based, not substring (found on the secworks sweep): 'ctrl' must not
# match 'ctr'. An identifier counts as a counter only if one of its
# underscore-separated tokens is exactly one of these keywords.
_COUNTER_TOKENS = {"ctr", "counter", "count", "cnt", "attempt", "tries"}

_PLAIN_COUNTER_DECL_RE = re.compile(
    r"\breg\b\s*\[[^\]]+\]\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)",
    re.IGNORECASE,
)


def _is_counter_name(identifier: str) -> bool:
    tokens = re.split(r"_+", identifier.lower())
    return any(t in _COUNTER_TOKENS for t in tokens)


def _scan_glitch_counter(file: Path, text: str) -> list[ScanHit]:
    """B4-GLITCH-SENSITIVE-COUNTER: security-relevant counter is a plain reg.

    A single-bit flip on the MSB can bypass a threshold. OpenTitan uses
    prim_count; absence is the signal. Very noisy rule — high false positive
    rate, agent must confirm the counter actually gates something.

    We exclude testbenches (tb_*, _tb.sv, /test/, /dv/) since counters there
    are coverage bookkeeping, not security state.
    """
    # Skip testbench files outright.
    name = file.name.lower()
    in_test_path = any(part in {"test", "tests", "tb", "dv", "sim"} for part in file.parts)
    if name.startswith("tb_") or name.endswith("_tb.v") or name.endswith("_tb.sv") or in_test_path:
        return []
    # Skip simulation/monitor/driver artefacts that look like RTL but aren't
    # security-relevant (bus protocol monitors, test drivers, coverage).
    if any(x in name for x in ("testdriver", "tlmonitor", "_monitor", "coverage", "driver", "bfm_")):
        return []
    hits: list[ScanHit] = []
    for i, line in enumerate(text.splitlines(), start=1):
        code = line.split("//", 1)[0]
        m = _PLAIN_COUNTER_DECL_RE.search(code)
        if not m:
            continue
        names = [n.strip() for n in m.group(1).split(",") if n.strip()]
        if not any(_is_counter_name(n) for n in names):
            continue
        hits.append(
            ScanHit(
                file=file,
                line=i,
                snippet=line.strip(),
                rule_id="B4-plain-counter",
                taxonomy_class=TaxonomyClass.GLITCH_SENSITIVE_COUNTER,
                initial_signal=15,
                note=(
                    "Counter declared as plain reg. If it gates a security "
                    "decision (lifecycle, attempt-limit, threshold), a single-bit "
                    "glitch can bypass it. Confirm the counter's downstream effect "
                    "before promoting."
                ),
            )
        )
    return hits


# Document/README signals for PUF/TRNG CRP exposure.
# We scan README/yaml/doc files too — Finding 1 in TT07-RO-PUF came from the
# README's crowdsourcing campaign, not the RTL.
_PUF_CRP_RE = re.compile(r"challenge[- ]response|CRP|physically unclonable", re.IGNORECASE)
_COLLECT_RE = re.compile(r"collect|submit|crowdsource|public.*data|help needed", re.IGNORECASE)
_SMALL_CHALLENGE_RE = re.compile(r"(8|16|32)[- ]bit.*(challenge|CRP)", re.IGNORECASE)


def _scan_puf_crp_exfil(file: Path, text: str) -> list[ScanHit]:
    """A1-PUF-CRP-EXFIL: small-CRP PUF with a public collection campaign.

    The canonical TT07 case. A weak PUF (small challenge space) whose CRPs are
    being crowdsourced has no security property left. README/docs are in scope.
    """
    hits: list[ScanHit] = []
    if not _PUF_CRP_RE.search(text):
        return hits
    # Strong signal if there's both a small challenge and a collection ask.
    if _COLLECT_RE.search(text) or _SMALL_CHALLENGE_RE.search(text):
        # Find a representative line.
        for i, line in enumerate(text.splitlines(), start=1):
            if _PUF_CRP_RE.search(line):
                hits.append(
                    ScanHit(
                        file=file,
                        line=i,
                        snippet=line.strip(),
                        rule_id="A1-puf-crp-exfil",
                        taxonomy_class=TaxonomyClass.PUF_CRP_EXFIL,
                        initial_signal=55,
                        note=(
                            "PUF design with documentation soliciting CRP collection "
                            "and/or a small challenge space. Read the README campaign "
                            "and confirm the CRP count vs the security claim before "
                            "promoting."
                        ),
                    )
                )
                break
    return hits


# Undocumented magic constants — dormant-trigger trojan surface (E1).
# A bare 32-bit hex constant with no nearby comment in a comparator is the
# canonical trigger signature. We require the constant to drive CONTROL FLOW
# (be inside an if/case/when predicate), not just appear in any equality —
# CRC polynomial checks like `crc == 16'h800D` are legitimate and must not
# fire the rule.
_MAGIC_CONST_RE = re.compile(
    r"==\s*(32'h[0-9a-fA-F]{8}|16'h[0-9a-fA-F]{4}|0x[0-9a-fA-F]{4,})"
)
_CONTROL_FLOW_RE = re.compile(r"\b(if|case|casex|casez|when|switch|is)\b")


# ---------------------------------------------------------------------------
# VHDL-specific patterns (parallel to the Verilog rules above)
# ---------------------------------------------------------------------------

# VHDL plain counter: `signal ... ctr : unsigned(...)`
_VHDL_COUNTER_RE = re.compile(
    r"\bsignal\s+\w*(ctr|counter|count|attempt|tries|num)"
    r"\w*\s*:\s*(unsigned|std_ulogic_vector|std_logic_vector)\s*\(",
    re.IGNORECASE,
)

# VHDL reset race: comparison against 'X'/'U'/'Z'
_VHDL_RESET_X_RE = re.compile(r"=\s*'(X|U|Z|W|-)'", re.IGNORECASE)

# VHDL debug enable
_VHDL_DEBUG_RE = re.compile(
    r"\b(debug_?en|dmactive|scan_?en|test_?en|manuf_?en)\b\s*[:<>=]",
    re.IGNORECASE,
)

# VHDL DMA address from register: addr <= src_addr or addr <= engine.src_addr
_VHDL_DMA_ADDR_RE = re.compile(
    r"\b(addr|src_addr|dst_addr|araddr|awaddr)\s*<=\s*\w+(\.\w+)?\s*;",
    re.IGNORECASE,
)

# VHDL unmasked crypto (S-box array/type)
_VHDL_CRYPTO_RE = re.compile(
    r"\b(type\s+\w*(sbox|s_box)\w*\s+is\s+array|"
    r"constant\s+\w*(sbox|s_box)\w*\s*:)",
    re.IGNORECASE,
)

# VHDL magic constant in comparison
_VHDL_MAGIC_RE = re.compile(
    r"=\s*(x\"[0-9a-fA-F]{4,8}\"|16#[0-9a-fA-F]{4,8}#)",
    re.IGNORECASE,
)
_VHDL_CONTROL_RE = re.compile(r"\b(if\s|when\s|case\s)", re.IGNORECASE)


def _scan_dormant_trigger(file: Path, text: str) -> list[ScanHit]:
    """E1-DORMANT-TRIGGER: comparator against an undocumented magic constant
    that drives control flow.

    Classic hardware trojan trigger: `if (state == 32'hDEADBEEF)`. Requiring
    control-flow context filters out the dominant false-positive class
    (CRC polynomials, opcodes in data-path equalities).
    """
    hits: list[ScanHit] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        if not _MAGIC_CONST_RE.search(line):
            continue
        # Require control-flow context: this line or the line above has an
        # if/case/when/switch keyword. (Verilog multi-line if conditions
        # span lines, so look back one.)
        ctx = line + ((" " + lines[i - 2]) if i >= 2 else "")
        if not _CONTROL_FLOW_RE.search(ctx):
            continue
        has_comment = "//" in line or "--" in line or (i >= 2 and "//" in lines[i - 2])
        if has_comment:
            continue
        hits.append(
            ScanHit(
                file=file,
                line=i,
                snippet=line.strip(),
                rule_id="E1-magic-constant",
                taxonomy_class=TaxonomyClass.DORMANT_TRIGGER,
                initial_signal=15,
                note=(
                    "Control-flow predicate against an undocumented magic constant. "
                    "Usually legitimate (opcode/protocol); occasionally a dormant "
                    "trigger. Cross-check against docs and confirm the constant is "
                    "reachable from a primary input."
                ),
            )
        )
    return hits


# Unmasked AES / plain sbox / schoolbook multiply — C1.
_SBOX_LOOKUP_RE = re.compile(r"\bs[_]?box\b", re.IGNORECASE)
_PLAIN_MUL_RE = re.compile(r"\b(schoolbook|plaintext_key|key_schedule)\b", re.IGNORECASE)
_MASKED_RE = re.compile(r"\b(mask|masked|DOM|HODL|isw)\b", re.IGNORECASE)


def _scan_unmasked_crypto(file: Path, text: str) -> list[ScanHit]:
    """C1-UNMASKED-CRYPTO: crypto core without masking."""
    hits: list[ScanHit] = []
    if not (_SBOX_LOOKUP_RE.search(text) or _PLAIN_MUL_RE.search(text)):
        return hits
    if _MASKED_RE.search(text):
        return hits
    for i, line in enumerate(text.splitlines(), start=1):
        if _SBOX_LOOKUP_RE.search(line) or _PLAIN_MUL_RE.search(line):
            hits.append(
                ScanHit(
                    file=file,
                    line=i,
                    snippet=line.strip(),
                    rule_id="C1-unmasked-crypto",
                    taxonomy_class=TaxonomyClass.UNMASKED_CRYPTO,
                    initial_signal=30,
                    note=(
                        "Crypto core with S-box / key-schedule references and no "
                        "masking signal. Confirm by reading the S-box implementation "
                        "(plain LUT = leaky) before promoting."
                    ),
                )
            )
            break
    return hits


# ---------------------------------------------------------------------------
# Group D — privilege / access-control (DMA, debug, MMIO)
# ---------------------------------------------------------------------------

# D2: DMA master drives the bus address directly from a CSR/descriptor value,
# with no address-range / permission check. This is the canonical "DMA without
# an IOMMU" finding — confirmed real on Antmicro FastVDMA.
#
# Pattern A (Verilog): assignment of an AXI AR/AW address from a register
# whose name suggests it came from software (xfer/desc/csr/ctl/startAddress).
_DMA_ADDR_FROM_CSR_V_RE = re.compile(
    r"\b(araddr|awaddr|axaddr|m_axi_(ar|aw)addr)\b\s*(:=|<=|=)\s*"
    r"([a-zA-Z_]\w*\.)?(xfer|desc|csr|ctl|config|start_?addr|src_?addr|dst_?addr)\b",
    re.IGNORECASE,
)
# Pattern B (Chisel): the same idea — io.xfer.address or io.ctl.startAddress
# flowing into a bus address. We key on the source-side name.
_DMA_ADDR_FROM_CSR_S_RE = re.compile(
    r"\b(araddr|awaddr|address_o|address)\b\s*:=\s*"
    r"(io\.)?(xfer|ctl|csr|desc)\.?(address|startAddress|src|dst)",
    re.IGNORECASE,
)


def _scan_dma_addr_from_csr(file: Path, text: str) -> list[ScanHit]:
    """D2-DMA-NO-IOMMU: DMA address sourced from CSR without range check."""
    hits: list[ScanHit] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if _DMA_ADDR_FROM_CSR_V_RE.search(line) or _DMA_ADDR_FROM_CSR_S_RE.search(line):
            hits.append(
                ScanHit(
                    file=file,
                    line=i,
                    snippet=line.strip(),
                    rule_id="D2-dma-addr-from-csr",
                    taxonomy_class=TaxonomyClass.DMA_NO_IOMMU,
                    initial_signal=40,
                    note=(
                        "DMA/bus master address is sourced directly from a CSR/descriptor "
                        "value (xfer/ctl/desc.address) with no visible range or permission "
                        "check on this line. If no IOMMU guards this DMA, firmware can "
                        "read/write arbitrary physical memory. Confirm the address path has "
                        "no comparator before promoting."
                    ),
                )
            )
    return hits


# D2 corroboration: an explicit address-range check near a DMA address would
# DISCONFIRM the finding. We don't fire a hit for this; we use it in the
# agent's reasoning. But we DO flag its ABSENCE in DMA-heavy files via a
# weaker secondary signal: a file that mentions araddr/awaddr but never
# mentions any of {range, bound, limit, iommu, smmu, allowed, region}.
_DMA_ADDR_RE = re.compile(r"\b(araddr|awaddr|m_axi_araddr|m_axi_awaddr)\b", re.IGNORECASE)
_RANGE_GUARD_RE = re.compile(
    r"\b(addr_?(range|bound|limit|check)|iommu|smmu|allowed_?region|in_?range|base_?limit)\b",
    re.IGNORECASE,
)


def _scan_dma_no_range_check(file: Path, text: str) -> list[ScanHit]:
    """D2-DMA-NO-IOMMU (weaker, file-level): DMA address present, no range guard
    anywhere in the file. Lower signal — corroborates D2-dma-addr-from-csr."""
    hits: list[ScanHit] = []
    if not _DMA_ADDR_RE.search(text):
        return hits
    if _RANGE_GUARD_RE.search(text):
        return hits
    # Find the first araddr/awaddr line to anchor the hit.
    for i, line in enumerate(text.splitlines(), start=1):
        if _DMA_ADDR_RE.search(line):
            hits.append(
                ScanHit(
                    file=file,
                    line=i,
                    snippet=line.strip(),
                    rule_id="D2-dma-no-range-check",
                    taxonomy_class=TaxonomyClass.DMA_NO_IOMMU,
                    initial_signal=20,
                    note=(
                        "File drives a bus address (araddr/awaddr) but contains no "
                        "address-range / IOMMU guard pattern anywhere. Likely no DMA "
                        "isolation. Read the whole address path before promoting; this "
                        "is corroborating evidence, not a standalone finding."
                    ),
                )
            )
            break
    return hits


# D1: debug / test / JTAG / scan logic reachable in PROD without lifecycle
# gating. Signal: presence of a debug/JTAG/scan enable that is a plain reg
# (not LC-mubi-gated).
_DEBUG_ENABLE_RE = re.compile(
    r"\b(debug_?en|jtag_?en|scan_?en|test_?en|bist_?en|manuf_?en|dm_?active|dmactive)\b\s*"
    r"(:=|<=|=|;|,)",  # also match port declarations (input debug_en; / debug_en,)
    re.IGNORECASE,
)
_LC_MUBI_RE = re.compile(r"\b(lc_?ctrl|mubi|lc_?enable|lifecycle)\b", re.IGNORECASE)


def _scan_undocumented_test_mode(file: Path, text: str) -> list[ScanHit]:
    """D1-UNDOCUMENTED-TEST-MODE: debug/test enable not lifecycle-gated."""
    hits: list[ScanHit] = []
    has_lc = bool(_LC_MUBI_RE.search(text))
    for i, line in enumerate(text.splitlines(), start=1):
        if _DEBUG_ENABLE_RE.search(line):
            note = (
                "Debug/test/JTAG/scan enable signal present. "
                "If this file (or its enclosing SoC) does not gate it with a "
                "lifecycle controller (lc_ctrl/mubi), it may be reachable in PROD."
            )
            signal = 25 if has_lc else 35
            if has_lc:
                note += " NOTE: an lc/mubi token appears elsewhere in this file — check whether it actually gates this enable."
            hits.append(
                ScanHit(
                    file=file,
                    line=i,
                    snippet=line.strip(),
                    rule_id="D1-undocumented-test-mode",
                    taxonomy_class=TaxonomyClass.UNDOCUMENTED_TEST_MODE,
                    initial_signal=signal,
                    note=note,
                )
            )
    return hits


# D3: MMIO register written without checking the write-enable (.qe) strobe,
# or a W1C field consumed directly. Common privilege/TOCTOU surface.
_MMIO_NO_QE_RE = re.compile(
    r"\breg2hw\.[a-zA-Z_]\w*\.[a-zA-Z_]\w*\.q\b(?!e)",  # .q not followed by 'e' (i.e. not .qe)
    re.IGNORECASE,
)


def _scan_mmio_write_no_qe(file: Path, text: str) -> list[ScanHit]:
    """D3-MMIO-WRITE-NO-BOUND: register consumed via .q without .qe strobe."""
    hits: list[ScanHit] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if _MMIO_NO_QE_RE.search(line):
            hits.append(
                ScanHit(
                    file=file,
                    line=i,
                    snippet=line.strip(),
                    rule_id="D3-mmio-no-qe",
                    taxonomy_class=TaxonomyClass.MMIO_NO_BOUND,
                    initial_signal=15,
                    note=(
                        "Register field consumed via .q without a .qe (write-enable) "
                        "strobe check. May permit unintended writes or TOCTOU. Verify "
                        "against the register spec before promoting."
                    ),
                )
            )
    return hits


# ---------------------------------------------------------------------------
# CWE-1239: Improper Zeroization — secret registers without clear-to-zero
# ---------------------------------------------------------------------------
# Detects registers holding secret data (key, password, nonce, IV, salt)
# that are loaded but never assigned a zero value, indicating missing
# zeroization on session end / reset / ownership change.

_SECRET_REG_RE = re.compile(
    r"\breg\s*\[[^\]]+\]\s*\w*(key|password|nonce|iv_|salt|secret|token|hmac)"
    r"\w*\s*[;,=]",
    re.IGNORECASE,
)
_ZEROIZE_RE = re.compile(
    r"\b\w*(key|password|nonce|iv_|salt|secret|token)\w*\s*<=\s*"
    r"(0\b|0'h0|0x0|\{.*\{.*1'b0.*\}\})",
    re.IGNORECASE,
)


def _scan_secret_no_zeroize(file: Path, text: str) -> list[ScanHit]:
    """CWE-1239: secret-holding register with no clear-to-zero path."""
    hits: list[ScanHit] = []
    # Find all secret register declarations.
    # Skip next-state (_new) and write-enable (_we) helpers: they are
    # recomputed every cycle, not persistent state, so zeroize
    # requirements do not apply to them.
    _TRANSIENT_SUFFIXES = ("_new", "_we", "_vld", "_next")
    secret_regs = []
    for i, line in enumerate(text.splitlines(), start=1):
        if _SECRET_REG_RE.search(line):
            # Extract the register name
            m = re.search(r"reg\s*\[[^\]]+\]\s*(\w+)", line)
            if m and not m.group(1).endswith(_TRANSIENT_SUFFIXES):
                secret_regs.append((m.group(1), i))
    # For each secret register, check if it's ever zeroized
    for reg_name, decl_line in secret_regs:
        # Look for any assignment of this register to zero
        zeroize_pattern = re.compile(
            rf"\b{re.escape(reg_name)}\b\s*<=\s*(0\b|0'h0|{{.*'b0}})",
            re.IGNORECASE,
        )
        if not zeroize_pattern.search(text):
            hits.append(
                ScanHit(
                    file=file,
                    line=decl_line,
                    snippet=text.splitlines()[decl_line - 1].strip(),
                    rule_id="CWE-1239-secret-no-zeroize",
                    taxonomy_class=TaxonomyClass.TRNG_ENTROPY_INJECTION,  # closest class
                    initial_signal=30,
                    note=(
                        f"Register '{reg_name}' holds secret data (key/password/"
                        "nonce) but is never explicitly zeroized. Confirm whether "
                        "it should be cleared on reset/session-end/ownership-change "
                        "(CWE-1239)."
                    ),
                )
            )
    return hits


# ---------------------------------------------------------------------------
# CWE-1255: Comparison vulnerable to power SCA — early-exit on secret
# ---------------------------------------------------------------------------
# Detects comparison loops or if-chains on secret data that exit early,
# leaking how many elements matched through timing/power.

_SECRET_CMP_NAMES = re.compile(
    r"\b(pin|password|key|token|secret|hmac|otp|auth_data)\b", re.IGNORECASE
)


def _scan_comparison_early_exit(file: Path, text: str) -> list[ScanHit]:
    """CWE-1255: early-exit comparison on secret data."""
    hits: list[ScanHit] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        # Pattern: if (secret[i] != reference) begin ... break/disable/return
        # or: if (secret != ref) match = 0; (inside a loop)
        if (
            _SECRET_CMP_NAMES.search(line)
            and ("!=" in line or "==" in line)
            and ("for" in lines[i - 2].lower() if i >= 2 else False
                 or "while" in lines[i - 2].lower() if i >= 2 else False
                 or "disable" in line.lower()
                 or "break" in line.lower())
        ):
            hits.append(
                ScanHit(
                    file=file,
                    line=i,
                    snippet=line.strip(),
                    rule_id="CWE-1255-comparison-early-exit",
                    taxonomy_class=TaxonomyClass.KEY_DATA_DEPENDENT_CONTROL,
                    initial_signal=25,
                    note=(
                        "Comparison on secret data with possible early exit inside "
                        "a loop. Timing/power leaks which element mismatched. Use "
                        "XOR-accumulate (constant-time) instead (CWE-1255)."
                    ),
                )
            )
    return hits


# ---------------------------------------------------------------------------
# CWE-1271: Security-critical register without explicit reset value
# ---------------------------------------------------------------------------
# Detects registers with security-relevant names that lack a reset
# assignment (no `if (!rst_n) reg <= ...` or `reg = ...` in reset block).

_SEC_NAME_KEYWORDS = {
    "lock", "locked", "lockdown", "unlock", "enable", "priv", "secure",
    "protect", "protected", "protection", "auth", "debug", "scan",
    "manuf", "bist",
}

_SEC_REG_DECL_RE = re.compile(
    r"\breg\b\s*(?:\[[^\]]*\]\s*)?([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)",
    re.IGNORECASE,
)

_BEGIN_WORD_RE = re.compile(r"\bbegin\b")
_END_WORD_RE = re.compile(r"\bend\b")


def _is_security_name(identifier: str) -> bool:
    tokens = re.split(r"_+", identifier.lower())
    return any(t in _SEC_NAME_KEYWORDS for t in tokens)


def _scan_sec_reg_no_reset(file: Path, text: str) -> list[ScanHit]:
    """CWE-1271: security register without explicit reset to safe value.

    Two precision guards (issue #2, false positives on secworks/aes):
    1. Name matching is token-based, not substring. A 'reg' named
       '*_block' or 'clock_*' is not a lock.
    2. Only module-level declarations are considered. A 'reg' declared
       inside a begin/end block is a procedural local (a combinational
       variable in always @*, a named-block temp), not a flip-flop.
       Module-level declarations never appear inside begin/end, so
       tracking begin/end depth is sufficient context.
    """
    hits: list[ScanHit] = []
    lines = text.splitlines()
    begin_depth = 0

    for i, line in enumerate(lines, start=1):
        # Strip line comments so 'begin' in a comment can not skew depth.
        code = line.split("//", 1)[0]
        stripped = code.strip()

        if begin_depth == 0:
            m = _SEC_REG_DECL_RE.search(stripped)
            if m:
                names = [n.strip() for n in m.group(1).split(",") if n.strip()]
                for reg_name in names:
                    if not _is_security_name(reg_name):
                        continue
                    # Skip write-enable strobes and next-state helpers:
                    # one-cycle transients, not flip-flop state, so
                    # "no reset" does not apply to them.
                    if reg_name.endswith(("_we", "_new", "_vld", "_next")):
                        continue
                    # A declaration initializer (`reg enable = 1'b0;`)
                    # defines the power-up value on FPGA targets, so the
                    # "powers up undefined" concern does not apply.
                    if re.search(rf"\b{re.escape(reg_name)}\s*=", stripped):
                        continue
                    # Check if this register appears in any reset block
                    # (look for reg_name <= in proximity to rst/rst_n).
                    # Array indexing allowed between name and <=, so
                    # `block_reg[i] <= 32'h0` counts as a reset.
                    reset_pattern = re.compile(
                        rf"(!?rst_?n?|reset_?n?)\b[^;]{{0,200}}\b{re.escape(reg_name)}"
                        rf"(?:\s*\[[^\]]*\])?\s*<=",
                        re.IGNORECASE | re.DOTALL,
                    )
                    if not reset_pattern.search(text):
                        hits.append(
                            ScanHit(
                                file=file,
                                line=i,
                                snippet=stripped[:70],
                                rule_id="CWE-1271-sec-reg-no-reset",
                                taxonomy_class=TaxonomyClass.LOGIC_RESET_RACE,
                                initial_signal=25,
                                note=(
                                    f"Security-relevant register '{reg_name}' has no explicit "
                                    "reset assignment. It powers up undefined — if 'undefined' "
                                    "means 'protection disabled', the chip boots insecure. "
                                    "Reset to the most restrictive value (CWE-1271)."
                                ),
                            )
                        )

        # Update begin/end depth after processing the line.
        begin_depth += len(_BEGIN_WORD_RE.findall(code))
        begin_depth -= len(_END_WORD_RE.findall(code))
        if begin_depth < 0:
            begin_depth = 0

    return hits


def _scan_vhdl_patterns(file: Path, text: str) -> list[ScanHit]:
    """VHDL-specific detection rules. Parallel to the Verilog rules but
    matching VHDL syntax (signal declarations, <= assignments, 'X' literals).
    Only runs on .vhd/.vhdl files."""
    if file.suffix.lower() not in (".vhd", ".vhdl"):
        return []
    # Skip testbench files
    name = file.name.lower()
    if any(x in name for x in ("tb_", "_tb", "testbench", "sim_", "bench")):
        return []

    hits: list[ScanHit] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        # B4: plain counter (VHDL signal)
        if _VHDL_COUNTER_RE.search(line):
            hits.append(ScanHit(
                file=file, line=i, snippet=line.strip(),
                rule_id="B4-vhdl-plain-counter",
                taxonomy_class=TaxonomyClass.GLITCH_SENSITIVE_COUNTER,
                initial_signal=15,
                note="VHDL: security-relevant counter as plain signal. If it gates a "
                     "security decision, a glitch can bypass it (CWE-1247).",
            ))
        # B1: reset race (comparison against 'X'/'U'/'Z')
        if _VHDL_RESET_X_RE.search(line):
            hits.append(ScanHit(
                file=file, line=i, snippet=line.strip(),
                rule_id="B1-vhdl-reset-x",
                taxonomy_class=TaxonomyClass.LOGIC_RESET_RACE,
                initial_signal=30,
                note="VHDL: comparison against 'X'/'U'/'Z' in synthesised logic. "
                     "These never evaluate true in silicon (CWE-1271/CWE-1245).",
            ))
        # D1: debug enable
        if _VHDL_DEBUG_RE.search(line):
            hits.append(ScanHit(
                file=file, line=i, snippet=line.strip(),
                rule_id="D1-vhdl-debug-enable",
                taxonomy_class=TaxonomyClass.UNDOCUMENTED_TEST_MODE,
                initial_signal=30,
                note="VHDL: debug/test enable signal. Check if gated by lifecycle/auth "
                     "(CWE-1191).",
            ))
        # D2: DMA address from register
        if _VHDL_DMA_ADDR_RE.search(line):
            hits.append(ScanHit(
                file=file, line=i, snippet=line.strip(),
                rule_id="D2-vhdl-dma-addr",
                taxonomy_class=TaxonomyClass.DMA_NO_IOMMU,
                initial_signal=35,
                note="VHDL: DMA/bus address sourced from register. Check for address-"
                     "range enforcement (CWE-1190/CWE-1189).",
            ))
        # C1: unmasked crypto
        if _VHDL_CRYPTO_RE.search(line):
            hits.append(ScanHit(
                file=file, line=i, snippet=line.strip(),
                rule_id="C1-vhdl-unmasked-crypto",
                taxonomy_class=TaxonomyClass.UNMASKED_CRYPTO,
                initial_signal=30,
                note="VHDL: crypto S-box array/type. Check for masking (CWE-1300).",
            ))
        # E1: magic constant in control flow
        if _VHDL_MAGIC_RE.search(line):
            ctx = line + ((" " + lines[i - 2]) if i >= 2 else "")
            if _VHDL_CONTROL_RE.search(ctx):
                has_comment = "--" in line or (i >= 2 and "--" in lines[i - 2])
                if not has_comment:
                    hits.append(ScanHit(
                        file=file, line=i, snippet=line.strip(),
                        rule_id="E1-vhdl-magic-constant",
                        taxonomy_class=TaxonomyClass.DORMANT_TRIGGER,
                        initial_signal=15,
                        note="VHDL: control-flow predicate against undocumented magic "
                             "constant. Cross-check against docs (CWE-1242).",
                    ))
    return hits


# ---------------------------------------------------------------------------
# CWE-125/CWE-1284: unsigned length/count underflow (the systemic pattern)
# ---------------------------------------------------------------------------
# Found in verilog-ethernet (6 instances), liteeth (3), neorv32 (1).
# Pattern: subtraction of a constant from a length/count field that could
# be attacker-controlled, without a bounds check. Cross-HDL.

# Verilog: ASSIGNMENT context only — `word_count = length - 8` or `<= length - const`
_V_UNDERFLOW_V_RE = re.compile(
    r"(word_count\w*|num\w*|payload_len\w*|data_len\w*)\s*"
    r"(<=|=)\s*(\w*length\w*|m_udp_length\w*|m_ip_length\w*|total_length\w*)\s*-\s*"
    r"(16'h[0-9a-fA-F]+|8'h[0-9a-fA-F]+|\d+|\w*header\w*\.length)",
    re.IGNORECASE,
)
# VHDL: ASSIGNMENT context — `engine.num <= ...unsigned(engine.num) - 1`
_V_UNDERFLOW_VHDL_RE = re.compile(
    r"(num|count|length)\w*\s*<=\s*.*unsigned\(\w+\.(num|count|length)\w*\)\s*-\s*\d+",
    re.IGNORECASE,
)
# Migen/Python: `.length.eq(X.length - Y.length)` — the .eq( wraps the expression
_V_UNDERFLOW_PY_RE = re.compile(
    r"\.(length|total_length)\w*\.eq\([^)]*length\w*\s*-\s*\w*\.?length",
    re.IGNORECASE,
)


def _scan_length_underflow(file: Path, text: str) -> list[ScanHit]:
    """CWE-125/CWE-1284: unsigned subtraction of a constant from a
    length/count field in an ASSIGNMENT context. Only matches runtime
    computations, not declarations. Found systemic across verilog-ethernet
    (6), liteeth (3), neorv32 (1)."""
    suffix = file.suffix.lower()
    if suffix in DOC_SUFFIXES:
        return []
    name = file.name.lower()
    if any(x in name for x in ("tb_", "_tb", "testbench", "sim_")):
        return []

    hits: list[ScanHit] = []
    for i, line in enumerate(text.splitlines(), start=1):
        matched = False
        if suffix in (".v", ".sv") and _V_UNDERFLOW_V_RE.search(line):
            matched = True
        elif suffix in (".vhd", ".vhdl") and _V_UNDERFLOW_VHDL_RE.search(line):
            matched = True
        elif suffix in (".py", ".scala") and _V_UNDERFLOW_PY_RE.search(line):
            matched = True
        if matched:
            hits.append(ScanHit(
                file=file, line=i, snippet=line.strip(),
                rule_id="CWE1284-length-underflow",
                taxonomy_class=TaxonomyClass.MMIO_NO_BOUND,
                initial_signal=40,
                note="Unsigned subtraction in an assignment: a length/count field "
                     "minus a constant. If the field < the constant (from packet "
                     "header, descriptor, or register), this underflows. Check: is "
                     "there a bounds check BEFORE this subtraction? (CWE-125/CWE-1284). "
                     "This is the systemic pattern found in verilog-ethernet, "
                     "liteeth, and neorv32.",
            ))
    return hits


# ---------------------------------------------------------------------------
# CWE-362: NBA race condition — same signal assigned twice in same always block
# ---------------------------------------------------------------------------
# Found in UET-RV SPI FIFO. 4273 candidates across the dataset.
# Pattern: signal <= expr1; ... signal <= expr2; in the same clocked block
# WITHOUT an if/else/case branch between them. The LAST NBA wins.

_NBA_SIGNAL_RE = re.compile(r"^\s*(\w+)\s*<=\s*")


def _scan_nba_race(file: Path, text: str) -> list[ScanHit]:
    """CWE-362: non-blocking assignment race — same signal assigned twice
    without a branch separator. The last assignment silently overrides.

    Precision note (audit 2026-08-07): the original rule produced ~445 hits
    on verilog-ethernet, ~95% false positive. The dominant FP class was a
    plain `if (...)` block between two NBAs — the two assignments are in
    different branch contexts but the rule only recognized `else`/`endcase`
    as separators. Fix: treat a new `if` statement at the same depth as a
    context reset, since assignments before vs after an if-block are in
    different execution paths.
    """
    suffix = file.suffix.lower()
    if suffix in DOC_SUFFIXES:
        return []
    name = file.name.lower()
    if any(x in name for x in ("tb_", "_tb", "testbench", "sim_")):
        return []

    hits: list[ScanHit] = []
    lines = text.splitlines()
    in_always = False
    always_depth = 0
    last_nba = {}  # signal -> (line, code)

    # Track the nesting depth at which each NBA was recorded, so a new
    # top-level `if` correctly invalidates prior NBAs at the same depth.
    NBA_SEP_RE = re.compile(
        r"\b(else|elsif|endcase|end\s*case|when\s+others)\b",
        re.IGNORECASE,
    )
    # A standalone `if` that OPENS a new block at the same level is a
    # context boundary for assignments above it.
    IF_OPEN_RE = re.compile(r"^\s*if\s*\(", re.IGNORECASE)

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        if re.match(r"always\s*[@(]|always_ff", stripped):
            in_always = True
            always_depth = stripped.count("{") - stripped.count("}")
            always_depth += stripped.count("begin") - stripped.count("end")
            last_nba = {}
            if "begin" not in stripped and "{" not in stripped:
                in_always = False
            continue

        if in_always:
            always_depth += stripped.count("begin") - stripped.count("end")
            always_depth += stripped.count("{") - stripped.count("}")

            # If this line opens a new top-level conditional, any NBA from
            # a prior if/else arm is no longer in the same context.
            if IF_OPEN_RE.match(stripped) and "else" not in stripped.lower():
                last_nba = {}

            m = _NBA_SIGNAL_RE.match(stripped)
            if m:
                sig = m.group(1).split("[")[0]
                if sig in last_nba:
                    prev_line, prev_code = last_nba[sig]
                    between = "\n".join(lines[prev_line:i - 1])
                    if not NBA_SEP_RE.search(between) and (i - prev_line) < 15:
                        hits.append(ScanHit(
                            file=file, line=i, snippet=stripped[:70],
                            rule_id="CWE362-nba-race",
                            taxonomy_class=TaxonomyClass.LOGIC_RESET_RACE,
                            cwe_ids=["CWE-362"],
                            initial_signal=20,
                            note=f"Signal '{sig}' assigned via <= twice in same "
                            "always block without branch separator. The last "
                            "assignment silently overrides the first. Verify both "
                            "paths are mutually exclusive (CWE-362).",
                        ))
                last_nba[sig] = (i, stripped[:70])

            if always_depth <= 0:
                in_always = False
                last_nba = {}
    return hits


# ---------------------------------------------------------------------------
# CWE-1233: Security-critical register writable mid-operation
# ---------------------------------------------------------------------------
# Found in secworks AES and HMAC. Key registers accept writes without
# checking ready/busy status.

_KEY_WE_RE = re.compile(
    r"(key_we|key_wr|config_we)\s*[:=]\s*1'b1\s*;",
    re.IGNORECASE,
)
_READY_CHECK_RE = re.compile(r"ready|busy|idle|done", re.IGNORECASE)


def _scan_key_writable_midop(file: Path, text: str) -> list[ScanHit]:
    """CWE-1233: key registers writable without checking ready/busy."""
    suffix = file.suffix.lower()
    if suffix in DOC_SUFFIXES or suffix in (".py", ".scala"):
        return []
    name = file.name.lower()
    if any(x in name for x in ("tb_", "_tb", "testbench")):
        return []

    hits: list[ScanHit] = []
    # Only flag if the file mentions both key_we AND has no ready check nearby
    if not _KEY_WE_RE.search(text):
        return hits
    for i, line in enumerate(text.splitlines(), 1):
        if _KEY_WE_RE.search(line):
            # Check surrounding 10 lines for a ready/busy guard
            context = text[max(0, (i - 1) * 80 - 400):(i - 1) * 80 + 400]
            if not _READY_CHECK_RE.search(context):
                hits.append(ScanHit(
                    file=file, line=i, snippet=line.strip()[:70],
                    rule_id="CWE1233-key-midop",
                    taxonomy_class=TaxonomyClass.UNDOCUMENTED_TEST_MODE,
                    initial_signal=25,
                    note="Key/control register write-enable asserted without "
                    "visible ready/busy guard. If the core is mid-operation, "
                    "overwriting the key corrupts the result silently "
                    "(CWE-1233).",
                ))
    return hits


# ---------------------------------------------------------------------------
# CWE-835: Duplicate array index in concatenation (the secworks SHA-3 bug)
# ---------------------------------------------------------------------------
# Found in secworks/sha3. block_reg[04] duplicated, block_reg[06] skipped.

def _scan_index_dup_in_concat(file: Path, text: str) -> list[ScanHit]:
    """CWE-835: duplicate array index in concatenation → wrong data."""
    suffix = file.suffix.lower()
    if suffix in DOC_SUFFIXES or suffix in (".py", ".scala"):
        return []
    name = file.name.lower()
    if any(x in name for x in ("tb_", "_tb", "testbench")):
        return []

    hits: list[ScanHit] = []
    # Find concatenation blocks with array references
    for m in re.finditer(r"\{([^}]{50,})\}", text, re.DOTALL):
        block = m.group(1)
        refs = re.findall(r"(\w+)\[(\d{2})\]", block)
        if len(refs) >= 8:
            seen = {}
            for n, (arr, idx) in enumerate(refs):
                key = (arr, int(idx))
                if key in seen:
                    line_num = text[:m.start()].count("\n") + 1
                    hits.append(ScanHit(
                        file=file, line=line_num,
                        snippet=f"{arr}[{idx}] duplicated at positions "
                                f"{seen[key]} and {n}",
                        rule_id="CWE835-index-dup",
                        taxonomy_class=TaxonomyClass.UNMASKED_CRYPTO,
                        initial_signal=40,
                        note=f"Array index {arr}[{idx}] appears twice in a "
                        "concatenation block. This is likely a copy-paste error "
                        "that corrupts the data — verify against the spec "
                        "(CWE-835).",
                    ))
                seen[key] = n
    return hits


# ---------------------------------------------------------------------------
# CWE-369: Division without checking for zero divisor
# ---------------------------------------------------------------------------
# Found in NEORV32. No guard before iterative division.

_DIV_OP_RE = re.compile(
    r"(div|rem|divide|division)\w*",
    re.IGNORECASE,
)
_DIV_BY_ZERO_GUARD_RE = re.compile(
    r"(divisor|rs2|denominator)\s*(==|!=|/=|<)\s*0\b",
    re.IGNORECASE,
)


def _scan_div_by_zero(file: Path, text: str) -> list[ScanHit]:
    """CWE-369: division operation without zero-divisor check."""
    suffix = file.suffix.lower()
    if suffix in DOC_SUFFIXES or suffix in (".py", ".scala"):
        return []
    name = file.name.lower()
    if any(x in name for x in ("tb_", "_tb", "testbench")):
        return []

    # Only flag files that have division logic
    if not _DIV_OP_RE.search(text):
        return []
    # And don't flag if there IS a zero check
    if _DIV_BY_ZERO_GUARD_RE.search(text):
        return []

    hits: list[ScanHit] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _DIV_OP_RE.search(line) and any(
            kw in line.lower() for kw in ("start", "begin", "state", "div_divi", "divisor")
        ):
            hits.append(ScanHit(
                file=file, line=i, snippet=line.strip()[:70],
                rule_id="CWE369-div-by-zero",
                taxonomy_class=TaxonomyClass.GLITCH_SENSITIVE_COUNTER,
                initial_signal=30,
                note="Division operation found but no zero-divisor check in "
                "this file. RISC-V spec requires DIV x/0 = -1, REM x/0 = x. "
                "Verify the core handles div-by-zero correctly (CWE-369).",
            ))
            break  # one hit per file is enough
    return hits


RULES = (
    _scan_reset_x_predicate,
    _scan_fsm_no_escalation,
    _scan_glitch_counter,
    _scan_puf_crp_exfil,
    _scan_dormant_trigger,
    _scan_unmasked_crypto,
    _scan_dma_addr_from_csr,
    _scan_dma_no_range_check,
    _scan_undocumented_test_mode,
    _scan_mmio_write_no_qe,
    _scan_secret_no_zeroize,
    _scan_comparison_early_exit,
    _scan_sec_reg_no_reset,
    _scan_vhdl_patterns,
    _scan_length_underflow,
    _scan_nba_race,
    _scan_key_writable_midop,
    _scan_index_dup_in_concat,
    _scan_div_by_zero,
)

# Files scanners are allowed to look at.
# RTL source files — these are what the pattern rules scan.
RTL_SUFFIXES = {".v", ".sv", ".vhd", ".vhdl", ".svh", ".chisel"}
# Chisel/Scala source — treated as RTL-equivalent (generates Verilog).
CHISEL_SUFFIXES = {".scala"}
# Documentation files — ONLY scanned by the doc-signal rules (A1 PUF CRP
# exfil looks at READMEs). Pattern rules (B1/B2/B4/C1/D1/D2/E1) should
# NOT fire on documentation, because docs contain example vulnerable code
# for teaching purposes — firing on those is a false positive.
DOC_SUFFIXES = {".md", ".yaml", ".yml"}
# All suffixes the scanner considers (for iter_target_files).
RTL_DOC_SUFFIXES = RTL_SUFFIXES | CHISEL_SUFFIXES | DOC_SUFFIXES | {".vhd", ".vhdl", ".py"}

# Signatures that mark a file as NOT human-readable RTL — these are post-
# synthesis netlists, vendor IP, or generated files where pattern scanning is
# meaningless (no `always` blocks, just `wire _0001_ = ...` chains).
_NETLIST_SIG_RE = re.compile(r"^\s*wire\s+_[0-9a-f]+_\s*=", re.MULTILINE)
# Paths that indicate vendor IP / generated artefacts — skip entirely.
_VENDOR_PATH_PARTS = {
    "ipstatic", "ip_user_files", ".gen", "blk_mem_gen", "Simulation",
    "simulation", "testbench", "vendor", "third_party", "_old",
}


def _looks_like_rtl(file: Path, text: str) -> bool:
    """Filter out post-synthesis netlists and vendor IP. Scanning those wastes
    time and produces nonsense hits. Returns True if the file is plausibly
    human-authored RTL."""
    name = file.name.lower()
    if name.startswith("tb_") or name.endswith("_tb.v") or name.endswith("_tb.sv"):
        return False
    if any(part in _VENDOR_PATH_PARTS for part in file.parts):
        return False
    # Gate-level netlist signature: lots of `wire _0042_ =` assignments and
    # no behavioural constructs.
    if _NETLIST_SIG_RE.search(text) and "always" not in text and "always_ff" not in text:
        return False
    return True


def iter_target_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part.startswith(".") and part not in (".",) for part in p.relative_to(root).parts[:-1]):
            continue  # skip hidden dirs (.git, .rtsilicon, ...)
        if p.suffix.lower() not in RTL_DOC_SUFFIXES:
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        if _looks_like_rtl(p, text):
            yield p


def _is_doc_file(file: Path) -> bool:
    """True if this is a documentation file, not RTL source."""
    return file.suffix.lower() in DOC_SUFFIXES


# Rules that are allowed to scan documentation files (they look for
# README/doc signals, not code patterns). All other rules skip docs
# because documentation contains EXAMPLE vulnerable code for teaching.
_DOC_SAFE_RULES = {"_scan_puf_crp_exfil"}


def scan_file(file: Path) -> list[ScanHit]:
    try:
        text = file.read_text(errors="ignore")
    except OSError:
        return []
    is_doc = _is_doc_file(file)
    hits: list[ScanHit] = []
    for rule in RULES:
        if is_doc and rule.__name__ not in _DOC_SAFE_RULES:
            continue  # don't pattern-match code rules on documentation
        try:
            hits.extend(rule(file, text))
        except Exception:  # noqa: BLE001 — scanner must never crash the run
            continue
    return _filter_suppressed(text, hits)


# ---------------------------------------------------------------------------
# Suppression comments (issue #2, the contract/design-decision case).
# Some findings are fine by contract between the core and its instance, or
# by design decision only the designer can judge. These are suppressible:
#   // rt-si: ignore        — suppress findings on this line (Verilog)
#   -- rt-si: ignore        — same, VHDL comment syntax
#   // rt-si: ignore-file   — suppress all findings in this file
# ---------------------------------------------------------------------------

_SUPPRESS_FILE_RE = re.compile(r"(?://|--)\s*rt-si:\s*ignore-file\b")
_SUPPRESS_LINE_RE = re.compile(r"(?://|--)\s*rt-si:\s*ignore(?![\w-])")


def _filter_suppressed(text: str, hits: list[ScanHit]) -> list[ScanHit]:
    """Drop hits the author has explicitly suppressed with a comment."""
    lines = text.splitlines()
    if any(_SUPPRESS_FILE_RE.search(line) for line in lines):
        return []
    suppressed = {
        i for i, line in enumerate(lines, start=1)
        if _SUPPRESS_LINE_RE.search(line)
    }
    if not suppressed:
        return hits
    return [h for h in hits if h.line not in suppressed]


def scan(root: Path) -> list[ScanHit]:
    """Run all rules across the target tree. Returns candidates, NOT findings."""
    hits: list[ScanHit] = []
    for file in iter_target_files(root):
        hits.extend(scan_file(file))
    return hits


# ---------------------------------------------------------------------------
# Candidate -> Finding conversion. The agent does the real work after this.
# ---------------------------------------------------------------------------


def hit_to_candidate(hit: ScanHit, target_id: str, counter: int) -> Finding:
    """Materialise a scanner hit as a CANDIDATE finding. Signal is low by
    design; only gate promotion raises it. Populates CWE IDs from the
    taxonomy mapping so attestations use MITRE's authoritative vocabulary."""
    from ..models import TAXONOMY_TO_CWE
    return Finding(
        id=f"CAND-{counter:04d}",
        target=target_id,
        title=f"{hit.rule_id} @ {hit.file.name}:{hit.line}",
        severity=Severity.INFO,  # candidates start at INFO; agent sets real severity
        taxonomy_class=hit.taxonomy_class,
        cwe_ids=TAXONOMY_TO_CWE.get(hit.taxonomy_class, []),
        stage=FindingStage.CANDIDATE,
        file=str(hit.file),
        line_start=hit.line,
        line_end=hit.line,
        summary=hit.note,
        impact="(unverified — candidate from scanner)",
        recommendation="(unverified — agent must analyse)",
        code_snippet=hit.snippet,
        signal=hit.initial_signal,
        signal_notes=[f"init: scanner rule {hit.rule_id}"],
    )
