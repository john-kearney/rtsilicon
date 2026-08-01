# Hardware security for people who just want to ship a chip

You're writing RTL. You want to tape out a chip, or you're pulling an
open-source core into your design. You do not want to read 98 NIST
failure scenarios or 600 pages of hardware-trojan survey. This document
is for you.

It tells you: **who might attack your design, how, what it costs them,
and what you can do about it in under an hour.** No theory. No taxonomy
lessons. The threats, in plain language, with the fix.

---

## Why this matters (90 seconds)

Open-source silicon is where open-source software was around 1998.
TinyTapeout is the equivalent of a 1990s Linux install-fest. OpenTitan —
the open-source root-of-trust chip — shipped in commercial Chromebooks in
2025, the first time OSS silicon reached consumer production. RISC-V, the
open processor architecture, is now in everything from microcontrollers to
AI accelerators, and SiFive (a major RISC-V vendor) markets to aerospace
and defense through a DARPA partnership.

We've seen this movie. Open source software started as a hobbyist
community, scaled into everything, and then a single vulnerable logging
library (log4j) being included in everything caused a global incident in
2021. Nobody had audited it because it was "just" open source.

Open-source hardware is on the same curve, ~20 years behind. The designs
being written today by hobbyists and researchers will be pulled into
commercial and critical systems in the next 5–10 years. **The difference
between software and hardware: you can't patch hardware.** A defect that
ships in silicon is there forever — the next tapeout is 12–18 months and
millions of dollars away.

The time to catch defects is now, at the RTL stage, before they propagate.

---

## The three attackers (and what they want)

### Attacker 1: The malicious contributor

**Who:** someone who submits a pull request to an open-source IP project
(rocket-chip, OpenTitan, a SpinalHDL core, a TinyTapeout submission).
**What they want:** to insert a backdoor into the IP that ships
everywhere it gets integrated.
**How:** adds a small, hard-to-trigger circuit (a "hardware trojan") that
does something malicious only under a rare condition — a specific counter
value, a particular input sequence, an analog condition like temperature.
99.99% of the time it's invisible. When the trigger fires, it leaks a
key, bypasses authentication, or bricks the chip.
**Real-world precedent:** this isn't hypothetical. Academic researchers
have demonstrated trojans in published IP that survived expert review
(see the "HT gray area" literature). The USB firmware attacks (BadUSB)
showed how a small malicious change in a peripheral's logic compromises
the host.
**Your exposure if you're a contributor:** someone could trojan YOUR
project via a PR if you're not reviewing contributions for security. If
you're an integrator pulling OSS IP, you're trusting every contributor to
every upstream.
**What it costs the attacker:** low. A GitHub account and a cleverly
hidden ~50 lines of RTL.

### Attacker 2: The naive integrator (this might be you)

**Who:** an engineer who pulls an open-source IP block into their SoC and
ships it without checking the security implications of the integration.
**What they want:** to ship a working product fast.
**How they hurt themselves:** by making reasonable-looking integration
choices that turn out to be catastrophic. Examples we've actually seen in
OSS IP:
- Wiring a DMA controller's address input directly to a software-
  controllable register, with no address-range check, so any code can
  read/write any physical memory. (This is the FastVDMA and OpenCores
  dma_axi pattern — both widely-used OSS DMA controllers have it.)
- Exposing a debug interface on a memory-mapped bus where user-mode code
  or a DMA peripheral can reach it, giving anyone debug privilege over
  the CPU. (The VexRiscv DebugPlugin does this if you follow the
  Linux.scala integration example without adding protection.)
- Trusting a crypto core's length inputs from software without verifying
  they match the actual data, producing valid-looking but wrong
  authentication tags. (An AES-GCM accelerator we audited.)
**This is the log4j pattern in hardware.** The IP itself is fine in
isolation. The integration is the vulnerability. And nobody documents
the integration requirements because there's no shared language for it.
**Your exposure:** if you integrate ANY open-source IP — a DMA, a debug
module, a crypto core — without checking whether it assumes protection
that your SoC doesn't provide, you may be shipping a hole.
**What it costs:** zero. It's an accident, not an attack.

### Attacker 3: The physical adversary

**Who:** someone with their hands on a device containing your chip — a
stolen laptop, a captured sensor, a purchased consumer device.
**What they want:** extract secrets (keys, firmware), bypass secure boot,
clone the device.
**How:** voltage glitching (spiking or dropping power to flip a bit in a
security-critical register), clock glitching, EM probing to read key
material from power consumption, laser fault injection through the
package.
**Real-world precedent:** this is how every game-console and
smartcard-hacking scene works. ChipWhisperer (open-source hardware, ~$50)
makes power-analysis attacks accessible to hobbyists. The Xbox 360 and PS3
were broken this way.
**Your exposure:** if your chip handles secrets (keys, boot
measurements, authentication tokens) and an attacker can physically
access a deployed device, you are on this threat model whether you chose
to be or not.
**What it costs the attacker:** $50 (ChipWhisperer) to $5000 (professional
glitcher + EM probe). A weekend to months, depending on the target.

---

## What you should actually do (the 60-minute checklist)

You don't need to become a security researcher. You need to run this
checklist before you tape out or integrate. Each item maps to a
well-documented class of hardware weakness (cited from MITRE's CWE-1194
hardware weakness list) so you can read more if you want.

### Before taping out your own design:

- [ ] **Do you have any debug or test interfaces (JTAG, scan chain)?**
      If yes: are they disabled or authenticated in the production
      configuration? (CWE-1191, CWE-1244) If you ship with debug open,
      anyone with physical access owns the chip.
- [ ] **Do you have security-relevant counters (round counters, attempt
      limits, watchdogs)?** If yes: are they hardened against single-bit
      glitching (using techniques like redundant counters), or are they
      plain `reg [N:0]`? (CWE-1245, CWE-1261) A glitch on one bit can
      bypass them.
- [ ] **Do you handle secrets (keys, RNG state)?** If yes: are they
      cleared on reset and on ownership change? (CWE-226, CWE-1239) Are
      your RNG health tests actually running before the first key use?
      (CWE-1241)
- [ ] **Do you use crypto?** If yes: is it masked against side-channel,
      or is it a plain textbook implementation? (CWE-1300) Plain AES
      S-boxes leak the key through power consumption. This is not
      theoretical — it's how smartcards were broken in the 1990s.
- [ ] **Does your design reset security-critical registers to a safe
      value?** (CWE-1271) A register that powers up undefined can leave
      a protection disabled.

### Before integrating open-source IP:

- [ ] **DMA controllers:** does the DMA enforce address ranges, or does
      it trust software-provided addresses? (CWE-1190, CWE-1189) If the
      latter, YOU must provide an IOMMU or address firewall, or any
      bus master can read/write all of memory.
- [ ] **Debug modules:** is the debug bus reachable from anything other
      than physical JTAG? (CWE-1191) If it's memory-mapped and not
      gated by lifecycle or authentication, it's a privilege-escalation
      path.
- [ ] **Crypto cores:** do they trust software for parameters like
      data length, IV, nonce? (CWE-325, CWE-1240) If yes, a buggy or
      malicious driver can produce forged ciphertexts that pass
      authentication.
- [ ] **Peripheral controllers (USB, network, SPI slaves):** do they
      validate the addresses they're told to DMA to/from? (CWE-1189)
      Peripherals are a classic privilege-escalation vector — see
      every DMA attack ever.
- [ ] **Third-party IP provenance:** do you know where every IP block
      came from and that it's been reviewed? (CWE-1242) Undocumented
      features and "chicken bits" are entry points.

---

## How rtsilicon helps (and where it doesn't)

`rt-si` is a free scanner that checks OSS-silicon RTL for the patterns
above. It's a **hint, not a guarantee** — it flags candidates that match
known-bad patterns; a human reviews and decides. It catches the
"integrate without checking" class (Attacker 2) well. It does NOT catch:

- Sophisticated hardware trojans hidden in analog behavior or
  dopant-level modifications. (That needs post-silicon side-channel
  analysis — a lab, not a scanner.)
- Composition vulnerabilities that only emerge when specific IP blocks
  are combined in specific ways. (That needs system-level review.)
- Anything in IP you don't have RTL for (closed-source third-party IP).

For those, you need a human reviewer who knows hardware security — which
is exactly the gap this field guide and the surrounding tooling are
trying to close by training more people.

---

## Where to read more (when you want depth)

The field is well-documented for security professionals; the gap is
material written for *you* (the hardware designer). These are the
authoritative sources if you want to go deeper:

- **MITRE CWE-1194 (Hardware Design view)** — the full list of ~110
  hardware weakness classes, organized by where in the chip.
  https://cwe.mitre.org/data/definitions/1194.html
- **2025 CWE Most Important Hardware Weaknesses** — the prioritized
  subset. https://cwe.mitre.org/topHW/index.html
- **NIST IR 8517 (Nov 2024)** — 98 concrete hardware failure scenarios.
  https://csrc.nist.gov/pubs/ir/8517/final
- **Dong et al. 2020** — comprehensive survey of hardware trojans:
  triggers, payloads, detection. https://pmc.ncbi.nlm.nih.gov/articles/PMC7570641/
- **Wen et al. 2025** — unified taxonomy mapping the fragmented standards.
  https://www.mdpi.com/2624-800X/5/4/86
- **ChipWhisperer** — open-source side-channel analysis hardware + tutorials.
  https://chipwhisperer.readthedocs.io/

The rest of this field guide takes the most OSS-HW-relevant subset of
CWE-1194 and translates each weakness into: what it looks like in your
RTL, how to check for it, a worked example from a real OSS design, and
how to fix it.
