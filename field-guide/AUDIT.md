# rtsilicon field guide — audit report

**Date:** 2026-07-25
**Auditor:** self-audit, no external review yet
**Scope:** accuracy of CWE mappings, honesty of claims, technical
correctness, credibility against expert review.

## Defects found and fixed

### Fixed (6 defects)

1. **CWE-1261 mapped for glitch-vulnerable counter — CATEGORY ERROR.**
   CWE-1261 is "Improper Handling of Single Event Upsets" — specifically
   about *cosmic radiation* and non-adversarial soft errors, NOT
   attacker-driven voltage/clock glitch attacks. Mapping "glitch-
   vulnerable counter" to CWE-1261 conflates natural soft errors with
   adversarial fault injection. A real HW security researcher would
   catch this instantly.
   **Fix:** removed CWE-1261 from GLITCH_SENSITIVE_COUNTER mapping.
   CWE-1247 (missing glitch protection) is the correct primary, with
   the acknowledged caveat that it's device-level (missing sensors)
   rather than RTL-level (plain register) — no perfect CWE exists.

2. **CWE-1240 mapped for AES-GCM length-block — WRONG.**
   CWE-1240 is "Use of a Cryptographic Primitive with a Risky
   Implementation" — about choosing a non-standard/unproven primitive
   (MD5 instead of SHA-256). AES-GCM is standard; the bug is a missing
   step (trusting firmware length). Correct: CWE-325 only.
   **Fix:** removed CWE-1240 from the AES-GCM / PUF-CRP mappings.

3. **CWE-1240 mapped for PUF CRP exfiltration — IMPRECISE.**
   CWE-1241 (predictable RNG) doesn't cover publishing all CRPs of a
   weak PUF. Closer: CWE-203 (Observable Discrepancy).
   **Fix:** changed PUF_CRP_EXFIL mapping to CWE-203.

4. **Defense overclaim in threat model.** "SiFive partners with DARPA"
   was extended to "defense prototypes" — implying fielded systems.
   SiFive markets to defense and has a DARPA Toolbox partnership, but
   no public deployments are verified.
   **Fix:** softened to "markets to aerospace and defense through a
   DARPA partnership."

5. **Scanner fires on documentation files.** B1/B4/D2 rules matched
   code blocks inside Markdown field-guide entries (which contain
   example vulnerable RTL for teaching). 9 false positives on the
   field guide itself, 10 on the Python repo.
   **Fix:** doc files (.md/.yaml) are now only scanned by doc-signal
   rules (A1 PUF CRP). Code-pattern rules skip docs. Regression test
   added (test_scanner_does_not_fire_on_documentation).

6. **CLI docstring bug.** `rt-si attest --help` example showed
   `--exit-on-high` which doesn't exist (the flag is `--ci`).
   **Fix:** corrected the example.

## Defects identified but NOT fixed (need design decisions)

### A. The "worked examples" are configuration hazards, not vulnerabilities

The VexRiscv godmode finding is how debug controllers work — the
"vulnerability" is the integrator exposing the bus. The MIT-LL CEP
finding is in a research testbed. The AES-GCM finding is a known
misuse class. A real HW security researcher reviewing the field guide
will recognize these as teaching examples, not novel vulnerabilities.

**Current mitigation:** each entry says "honestly: it's a configuration
hazard" or "it's the GCM-misuse class." The framing is honest.

**Remaining risk:** the headline "worked example from audited OSS
hardware" could still mislead a casual reader into thinking we found
real CVEs. Consider strengthening the language to "teaching example
drawn from real OSS hardware" throughout.

### B. The census headline invites misreading

"47.7% of OSS-silicon designs have unglitch-hardened counters" reads
like "47.7% are vulnerable" despite the disclaimer that candidates
are hints. Most of those counters gate nothing security-relevant.

**Current mitigation:** the census says "candidates, not confirmed
vulnerabilities" and explicitly states "the prevalence of exploitable
defects is lower and unmeasured."

**Remaining risk:** the headline number is still quotable out of
context. Consider reframing as "47.7% have the CWE-1247 *pattern*,
of which an unknown subset are exploitable."

### C. No comparison to existing tools

The field guide doesn't mention SymbiYosys (open-source formal
verification), ChipWhisperer (SCA), or the academic pre-silicon
detection tools (VeriTrust, etc.). A researcher will ask "why not
just use formal?"

**Current mitigation:** none. The README links to ChipWhisperer but
doesn't position rt-si relative to formal tools.

**Needed:** a short "how rt-si relates to other tools" section.
Positioning: rt-si is the accessible entry point (regex patterns, no
formal expertise needed), complementary to formal verification (which
is stronger but harder to use). Not a competitor.

### D. The RC5 refutation is under-foregrounded

The most credible thing we did was refute our own SCA leak claim via
gate-level toggle counting. A researcher who discovers this buried in
entry 7 will trust us MORE for having done it — but only if they find
it. Currently it's mentioned once in the SCA entry.

**Needed:** mention the refutation in the README and the census, not
just the SCA entry. "We attempted to verify a side-channel leak and
the measurement refuted it — documented as a limitation, not hidden."

### E. The scanner is regex-based, not semantic

A researcher will immediately note: regex pattern matching can't
catch the defects that actually matter (composition bugs, semantic
logic errors, analog trojans). The field guide claims "the scanner is
a hint" — which is honest — but doesn't explicitly acknowledge what
it CAN'T catch vs what formal/SCA tools can.

**Needed:** a clear "what rt-si catches vs what it misses" table.

## Verified correct

- All census numbers (491 targets, 2459 candidates, 56.8%, 47.7%, 9.0%,
  5.3%) match the dataset exactly. No inflation.
- All 8 CLI commands work as documented (scan, finding, gate, audit,
  demo, attest, tt-audit, triage).
- 62/62 tests green after fixes.
- All factual claims about OpenTitan/Chromebook/SiFive verified against
  primary sources in the earlier research session.
- The CWE field guide entries correctly cite MITRE definitions and link
  to the actual CWE pages.

## Meta-lesson

The audit found 6 real defects (3 CWE mapping errors, 1 overclaim, 1
false-positive bug, 1 docstring error) in work I was about to call
"done." The CWE-1261 category error alone would have destroyed
credibility with any real HW security researcher. This is exactly why
external validation matters — and why the next step before publishing
is having an actual HW security person review the CWE mappings and
the field guide entries.
