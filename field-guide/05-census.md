# The OSS silicon security census

**What we did:** scanned 491 standalone open-source hardware IP blocks +
596 Tiny Tapeout projects (TT04–TT08) for the CWE-1194 pattern classes
covered in this field guide. This document reports what we found —
honestly, without inflating candidates into confirmed vulnerabilities.

**Why it matters:** this is the first broad survey of security defect
candidates across the OSS silicon ecosystem. It shows that the patterns
described in the field guide are not theoretical — they're present, at
scale, in the designs people are writing today.

---

## Headline numbers

| Metric | Value |
|--------|-------:|
| Standalone IP targets scanned | 491 |
| Tiny Tapeout projects attested | 596 |
| Total candidates (standalone) | 2,459 |
| Distinct CWE classes hit | 8 |
| Targets with ≥1 candidate | 56.8% |
| Full scan runtime | 71 seconds |

## CWE class prevalence (standalone targets)

These are the pattern-match counts from the scanner. **Each is a
candidate, not a confirmed vulnerability.** The scanner is a hint; human
review confirms or refutes. The high B4/CWE-1247 count reflects the
noisiness of the "plain counter" rule; the rare classes (D1, A1) are
higher-signal.

| CWE | Internal class | Candidates | Targets | % of targets |
|-----|---------------|--------:|--------:|---:|
| CWE-1247/1261 | B4 Glitch-sensitive counter | 1,835 | 234 | 47.7% |
| CWE-1300/1240 | C1 Unmasked crypto | 172 | 44 | 9.0% |
| CWE-1190/1189/1318 | D2 DMA without IOMMU | 161 | 26 | 5.3% |
| CWE-1271/1245 | B1 Logic reset race | 146 | 19 | 3.9% |
| CWE-1242 | E1 Dormant trigger (magic constant) | 57 | 16 | 3.3% |
| CWE-1191/1234/1244 | D1 Undocumented test mode | 60 | 5 | 1.0% |
| CWE-1241/1240 | A1 PUF CRP exfiltration | 6 | 4 | 0.8% |
| CWE-1245 | B2 FSM without escalation | 22 | 3 | 0.6% |

## What the numbers actually say

### Nearly half of OSS-silicon designs have unglitch-hardened counters (CWE-1247)

47.7% of targets have at least one security-relevant counter declared as
a plain `reg`. Sampled and confirmed at scale: AES round counters, RSA
modular-multiplication counters, TRNG entropy-mixer counters, RISC-V
cycle counters. The OSS ecosystem does not, in general, use hardened
counter primitives (like OpenTitan's `prim_count`). This is the
whitepaper headline.

### One in eleven has an unmasked crypto core (CWE-1300)

9% of targets have a crypto core with no masking signal. Sampled:
secworks/aes, SpinalHDL VexRiscv AesPlugin, multiple PRESENT/Simon/
ChaCha20 implementations. Almost no OSS crypto core ships with masking.
The structural SCA precondition is endemic.

### DMA without isolation is systemic (CWE-1190/1189)

Two unrelated OSS DMA controllers (Antmicro FastVDMA + OpenCores
dma_axi) both have no address-range enforcement — confirmed by full
taint-chain analysis in both. The CSR-programmed and descriptor-in-
memory variants are both present. This is the strongest "systemic
pattern" finding: the class is structurally identical across unrelated
designs.

## What the numbers do NOT support

- **"X% of OSS silicon is vulnerable."** Candidates are hints, not
  confirmed vulnerabilities. Many CWE-1247 hits are counters that gate
  nothing security-relevant. The prevalence of candidates is high; the
  prevalence of exploitable defects is lower and unmeasured.
- **Specific exploit chains.** Only 3 targets have deep-dive-confirmed
  findings (VexRiscv, MIT-LL CEP, AES-256-GCM), and even those are
  honestly graded as teaching examples, not disclosure-grade vulns.
- **Side-channel exploitability.** CWE-1300 hits are confirmed at the
  RTL level (unmasked S-boxes) but one attempted gate-level
  verification (RC5) refuted the bulk-power leak. SCA exploitability
  requires per-target lab work, which is out of scope for this census.

## Honest limitations of the census

1. **The scanner is pattern-based.** It catches syntactic signals
   (`reg [N] round_ctr`, `araddr := io.xfer.address`, `=='x'` in reset
   predicates). It misses semantic defects that require understanding
   the design's intent. The 3 deep-dive diamonds were found by reading
   RTL, not by the scanner.
2. **HLS-generated RTL is a blind spot.** ~10% of TT targets are
   HLS compiler output (CATAPULT) — structurally un-auditable without
   the original C/C++ source. The census skips these.
3. **Tiny Tapeout projects commit post-synthesis netlists, not source.**
   Of 819 TT projects, only 596 had recoverable source. 213 were dropped
   for missing provenance. The TT coverage is 73%, not 100%.
4. **The classifier for "security claim" had bugs.** Original version
   matched 'sha' in 'shadow', 'rsa' in 'universal', 'key' in 'keypad'.
   Fixed with word-boundary regex + 21 regression tests, but the lesson
   stands: substring matching produces plausible-looking but wrong
   classifications. Only the test suite caught it.

## Methodology

- **Scanner:** rtsilicon v0.2, 10 pattern rules covering 8 CWE classes.
- **Filters:** post-synthesis netlists (`wire _0042_ =` signature),
  vendor IP paths, simulation checkers, and testbenches excluded.
- **Targets:** 491 standalone GitHub repos (crypto cores, TRNGs, RISC-V
  SoCs, DMAs, peripherals) + 596 source-recovered TT projects.
- **Runtime:** 71 seconds for the full 491-target standalone scan.
- **Reproducibility:** `python scripts/build_dataset.py` regenerates
  the dataset; `python scripts/recover_tt_all.py` + `python scripts/
  tt_attest_sweep.py` regenerates the TT registry.

## The deeper point

The census proves that the CWE classes in the field guide are not
hypothetical — they're present in real OSS hardware, at scale, today.
As adoption of OSS silicon grows (and every signal says it is —
OpenTitan in Chromebooks, RISC-V in everything, SiFive+DARPA), these
latent defects will ship in real systems. The field guide + the
scanner exist to catch them before that happens.
