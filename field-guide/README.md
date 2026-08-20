# Hardware security field guide for open-source contributors

**You write RTL. You want to ship a chip. You don't want to read 98 NIST
failure scenarios. This guide is for you.**

Hardware security is a mature field with excellent foundational
literature — but it's written for security professionals at chip vendors
and government labs, not for the OSS HW contributor. This guide
translates the authoritative sources into something you can read in an
hour and act on immediately.

## What this is

A plain-language field guide to the MITRE CWE hardware weakness classes
(CWE-1194) that matter most for open-source hardware. Each entry:

- Explains the weakness in language a Verilog/Chisel writer understands
- Shows what the pattern looks like in real RTL (bad and hardened)
- Gives a worked example from audited OSS hardware
- Tells you how to check for it (manual review + `rt-si` if supported)
- Tells you how to fix it
- Links to the MITRE CWE entry for the authoritative definition

## What this isn't

- **Not a new taxonomy.** MITRE's CWE-1194 is the vocabulary. We use it.
- **Not a guarantee.** The scanner is a hint; the field guide is a
  starting point. Real security requires human review.
- **Not comprehensive.** We cover ~16 of CWE-1194's ~110 classes — the
  ones most relevant to OSS HW. The full list is at
  [cwe.mitre.org/data/definitions/1194.html](https://cwe.mitre.org/data/definitions/1194.html).

## How to use it

1. **Read [the threat model](01-threat-model.md)** (15 min). Understand
   who might attack your design and why.
2. **Run `make secure`** on your design. See which CWE classes have
   candidates.
3. **Read the field-guide entries** for the CWEs it flagged. Understand
   what the pattern is and how to fix it.
4. **Fix, re-scan, repeat.**
5. **Ship with the badge** — the attestation proves the design was
   scanned.

## Table of contents

### Part 1: Threat model
- [01 — Hardware security for people who just want to ship a chip](01-threat-model.md)

### Part 2: CWE field guide entries

| CWE | Class | Worked example |
|-----|-------|----------------|
| [CWE-1191](02-cwe-field-guide-entries.md#) | Debug interface access control | VexRiscv DebugPlugin "godmode" |
| [CWE-1262](02-cwe-field-guide-entries.md#) | Register interface access control | MIT-LL CEP SROT key-RAM TOCTOU |
| [CWE-325](02-cwe-field-guide-entries.md#) | Missing cryptographic step | AES-256-GCM GHASH length-block |
| [CWE-1190](02-cwe-field-guide-entries.md#) | DMA enabled too early / uncontrolled | FastVDMA + dma_axi |
| [CWE-1245](03-cwe-field-guide-entries.md#) | Improper FSMs | TT07 RO-PUF arbiter reset race |
| [CWE-1300](03-cwe-field-guide-entries.md#) | Physical side-channel (unmasked crypto) | secworks/aes, VexRiscv AesPlugin |
| [CWE-1247](03-cwe-field-guide-entries.md#) | Glitch-vulnerable counters | AES round counters (population) |
| [CWE-1271](03-cwe-field-guide-entries.md#) | Uninitialized security registers on reset | MIT-LL CEP SROT mode bits |
| [CWE-1242](03-cwe-field-guide-entries.md#) | Undocumented features / chicken bits | E1 dormant-trigger class |
| [CWE-1189](04-cwe-field-guide-entries.md#) | Improper isolation of shared resources | FastVDMA (shared memory) |
| [CWE-1326](04-cwe-field-guide-entries.md#) | Missing immutable root of trust | The OSS HW RoT gap |
| [CWE-1239](04-cwe-field-guide-entries.md#) | Improper zeroization of secret registers | 2025 CWE MIHW #1 |
| [CWE-1255](04-cwe-field-guide-entries.md#) | Power-vulnerable comparison logic | Universal class |
| [CWE-1243](04-cwe-field-guide-entries.md#) | NV secrets not protected during debug | OpenTitan (how to do it right) |
| [CWE-1318](04-cwe-field-guide-entries.md#) | Missing security in on-chip fabric | AXI-Lite AxPROT |
| [CWE-1280](04-cwe-field-guide-entries.md#) | Access check after asset accessed | FastVDMA 4KBarrier confusion |
| [CWE-362](03-cwe-field-guide-entries.md#) | NBA race — silent assignment override | verilog-ethernet population |
| [CWE-369](03-cwe-field-guide-entries.md#) | Divide by zero (RISC-V spec result) | neorv32 iterative divider |
| [CWE-835](03-cwe-field-guide-entries.md#) | Duplicate index in concatenation | secworks/sha3 wrong hashes |

## Authoritative sources (for when you want depth)

| Source | What it is | URL |
|--------|-----------|-----|
| MITRE CWE-1194 | Hardware Design weakness view (~110 classes) | [cwe.mitre.org/1194](https://cwe.mitre.org/data/definitions/1194.html) |
| 2025 CWE MIHW | Most Important Hardware Weaknesses (prioritized) | [cwe.mitre.org/topHW](https://cwe.mitre.org/topHW/index.html) |
| NIST IR 8517 | 98 hardware security failure scenarios (Nov 2024) | [csrc.nist.gov/ir/8517](https://csrc.nist.gov/pubs/ir/8517/final) |
| Wen et al. 2025 | Unified taxonomy mapping fragmented standards | [mdpi.com/2624-800X/5/4/86](https://www.mdpi.com/2624-800X/5/4/86) |
| Dong et al. 2020 | Hardware trojan survey (trigger/payload/detection) | [pmc.ncbi.nlm.nih.gov/PMC7570641](https://pmc.ncbi.nlm.nih.gov/articles/PMC7570641/) |
| ChipWhisperer | Open-source SCA hardware + tutorials | [chipwhisperer.readthedocs.io](https://chipwhisperer.readthedocs.io/) |

## Contributing

This field guide is open source. If you find a CWE class that should be
covered, or a worked example that would help the community, open a PR.
The entries follow a fixed template (see any existing entry); new
entries should match it.
