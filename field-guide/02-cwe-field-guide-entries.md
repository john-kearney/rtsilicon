# CWE field guide for OSS hardware — worked examples

Each entry takes one MITRE CWE (from CWE-1194, the Hardware Design view)
and translates it into: what it looks like in real RTL, how to check for
it, a worked example from audited OSS hardware, and the fix. These are
the capstone examples — the rest of the field guide (the remaining ~15
most-OSS-HW-relevant CWEs) follows the same template.

Every example here is from a real audit of real OSS hardware. The code
patterns are faithful to what shipped. The CWE IDs are MITRE's, not ours.

---

## CWE-1191: On-Chip Debug and Test Interface With Improper Access Control

**Plain language:** Your chip has a debug or test interface (JTAG, scan
chain, a debug bus) that lets someone inspect or modify internal state.
If that interface isn't gated — by authentication, by a lifecycle
controller that disables it in production, or by physical access
controls — then anyone who can reach it owns the chip.

**What it looks like in RTL:** a debug or test module whose enable/
access signals come straight from a register or bus without a privilege
or lifecycle check.

### Worked example: VexRiscv DebugPlugin "godmode"

**Target:** SpinalHDL/VexRiscv — one of the most-deployed OSS RISC-V
soft cores, used in FPGA SoCs.

**The pattern:** VexRiscv's DebugPlugin exposes a debug bus
(`DebugExtensionBus`) that, when driven with a single write, halts the
CPU and triggers a privilege escalation to machine mode:

```
// DebugPlugin.scala:285 — write to bus addr 0x00, data[17]=1 sets haltIt
// DebugPlugin.scala:238 — godmode auto-sets when (haltIt && !isPipBusy)
// DebugPlugin.scala:355 — when(godmode) { forceMachine() }
// CsrPlugin.scala:700 — when(forceMachineWire) privilege := 3 (machine mode)
```

The DebugExtensionBus has **no authentication field.** No `auth_valid`,
no lifecycle gate, no key check. It can be exposed as APB3, Avalon, or
BMB — any of which an integrator can map onto the system bus.

**The integration hazard:** VexRiscv's own `Linux.scala:366` exposes
the debug bus as a top-level Avalon slave port (`debugBusAvalon`). If an
integrator maps that onto the system bus without adding protection, any
bus master (DMA, user-mode code, another core) can write to it, halt the
CPU, and escalate to machine privilege. We verified this end-to-end in a
full Verilator simulation: one unauthenticated bus write flipped the CPU
from User mode to Machine mode (privilege 0 → 3) in ~12 cycles.

**Is this a "vulnerability"?** Honestly: it's a configuration hazard.
Debug controllers *have to* escalate privilege when halted — that's how
debugging works. The defect is that it's trivially easy to expose the
bus insecurely, with no warning in the code or docs. The integrator is
the victim of their own reasonable-looking choice.

**The fix:**
1. **If you integrate VexRiscv:** do NOT map `debugBusAvalon` onto any
   bus reachable by software or DMA. Use JTAG-only (the Briey/Murax
   pattern). If you must expose it for remote debug, gate it behind an
   authentication mechanism or a lifecycle signal that's only asserted
   in development.
2. **If you're writing a debug controller:** add a one-bit `debug_auth`
   input that must be asserted for writes to take effect. Document
   prominently that the bus grants machine-mode privilege.

**How to check:** `rt-si` flags debug-enable signals (`debug_en`,
`scan_en`, `dm_active`) that aren't gated by a lifecycle controller
(`lc_ctrl`, `mubi`). Manual review: trace the debug bus's fan-in and
confirm it's either JTAG-only or auth-gated.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1191.html

---

## CWE-1262: Improper Access Control for Register Interface

**Plain language:** Memory-mapped registers that hold security-critical
state (keys, lock bits, configuration) don't check who's reading or
writing them. Any bus master that can address the register can read
secrets or flip protection bits.

**What it looks like in RTL:** a register file holding security state
where reads and writes are gated only by address decode, not by privilege
level or a lock mechanism.

### Worked example: MIT-LL CEP SROT key-RAM TOCTOU

**Target:** MIT Lincoln Laboratory Common Evaluation Platform (CEP) — a
defense-research SoC with a Surrogate Root of Trust (SROT) and a key-
delivery mechanism.

**The pattern:** the SROT protects its Key RAM with two "mode bits" in
the `srot_ctrlstatus_register`. When either bit is set, host reads of
Key RAM are silently ignored. The lock semantics:

```
// srot_wrapper.sv:501 — rst clears the mode bits (UNLOCKED)
// srot_wrapper.sv:569-570 — mode bits are SET-ONLY via host write
// (no clear path exists except reset)
// srot_wrapper.sv:637-640 — host read of Key RAM returns keyram_rdata_o
//                            if mode bits clear, stale data if set
```

**The defect:** there is a window between reset (mode bits clear) and
firmware setting the lock, during which the host can read any key in Key
RAM directly. There is no hardware enforcement that the lock is engaged
before key readout becomes possible. The key-delivery state machine
(`MESSAGE_CHECK`) doesn't check the lock either — it'll deliver keys to
accelerators regardless.

**Is this a vulnerability?** It's a structural defect in a root-of-trust
component. A RoT's key protection should be a hardware invariant, not a
software convention. "Trust the firmware to lock before reading" is the
wrong shape. That said: CEP is explicitly a research testbed, and the
intended boot path may always lock first. Exploitability depends on
whether attacker-controlled code can run in the window.

**The fix:**
1. Auto-lock on first key write — the first host write to Key RAM should
   set a mode bit automatically. Closes the window at the hardware level.
2. Check the lock in the key-delivery state machine — refuse to deliver
   keys if not locked.
3. Or: make Key RAM write-only (returns zeros on read) until locked.

**How to check:** `rt-si` flags register files holding security state
whose access isn't gated by a lock or privilege signal. Manual review:
trace the lock mechanism's set/clear paths and confirm it can't be
bypassed.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1262.html

---

## CWE-325: Missing Cryptographic Step

**Plain language:** a cryptographic algorithm is implemented without one
of the steps that makes it secure. The cipher "works" (produces output)
but the output doesn't have the security property it should.

**What it looks like in RTL:** a crypto core that takes a parameter
(length, IV, nonce) from software on trust, without cross-checking it
against the actual data processed.

### Worked example: AES-256-GCM GHASH length-block trust

**Target:** `dzemildzigal/aes-256-systemverilog` — an AES-256-GCM
hardware accelerator on Zynq-7020, DMA-fed.

**The pattern:** GHashEngine computes the GHASH length block — the final
block encoding `len(AAD)_bits || len(CT)_bits` per NIST SP 800-38D —
from firmware-provided session-config registers, not from counting the
actual blocks that passed through the FIFO:

```
// GHashEngine.sv:175-176 — aad_len_bits_reg <= aad_len_bits_i (from firmware)
// GHashEngine.sv:223 — enq_data = {aad_len_bits_reg, ct_len_bits_reg}
// (the length block uses firmware-provided values, not measured counts)
```

**The defect:** the FIFO processes whatever blocks actually arrive, but
the length block at the end uses the *claimed* length. A mismatch
produces a tag that's "valid" for the claimed length but not for the
actual data. An attacker who controls the length register (via DMA to
the session-config CSR) while streaming a different number of blocks can
produce tag-valid ciphertext whose decrypted content doesn't match what
the verifier expects. We confirmed numerically that claimed vs actual
length produces different GHASH results.

**Is this a vulnerability?** It's the GCM-misuse class — known, studied.
The specific instance is real (the RTL does trust firmware for length).
Exploitability depends on whether the host can desync claimed vs actual
lengths (driver bug, DMA attacker, fault injection).

**The fix:**
1. Count actual AAD/CT blocks in the FIFO. Assert the count matches the
   claimed length before emitting the tag. Abort on mismatch.
2. Or: derive the length block from the actual count, ignoring firmware.

**How to check:** `rt-si` flags crypto cores that take length/IV/nonce
parameters from registers without a cross-check. Manual review: trace
where the length block comes from and confirm it's measured, not trusted.

**MITRE reference:** https://cwe.mitre.org/data/definitions/325.html

---

## CWE-1190: DMA Device Enabled Too Early in Boot Phase

**Plain language:** a DMA controller is active before the system's memory
protection is configured, so it can read/write anything.

**What it looks like in RTL:** a DMA master whose address comes from a
CSR with no range check or IOMMU enforcement.

### Worked example: FastVDMA and OpenCores dma_axi

**Target:** Antmicro FastVDMA (Chisel) and OpenCores dma_axi (Verilog) —
two widely-used OSS DMA controllers.

**The pattern (FastVDMA):** the DMA address comes from
`io.ctl.startAddress` (a CSR) and flows to the AXI bus with no check:

```
// AddressGenerator.scala:62 — address_i := io.ctl.startAddress
// AddressGenerator.scala:45 — io.xfer.address := address_o
// AXI4Reader.scala:65 — araddr := io.xfer.address
// (no comparator, no IOMMU, no range check anywhere)
```

**The pattern (dma_axi, strictly worse):** the DMA fetches *descriptors*
from memory over AXI. Descriptor fields become DMA addresses:

```
// dma_axi32_core0_axim_rdata.v:123 — assign load_wdata = RDATA;
// dma_axi32_core0_ch_reg.v:354 — rd_start_addr <= load_wdata[31:0];
// (descriptor-in-memory: attacker controls addresses via crafted descriptors)
```

**The defect:** neither DMA enforces address ranges. Any code with CSR
access (FastVDMA) or any code that can place a descriptor in fetched
memory (dma_axi) gets arbitrary read/write over system memory. The
`4KBarrier` config in FastVDMA is an AXI-protocol splitter, not a
security boundary.

**Is this a vulnerability?** Likely "by design" — isolation is the
integrator's job. But it's not documented prominently, and the
`4KBarrier` name misleads. The defect is the absent documentation +
the misleading config name. Two unrelated OSS DMAs have the same
pattern — evidence the class is endemic to OSS DMA IP.

**The fix:**
1. Add an optional address-range guard IP between the DMA and the AXI
   frontends, configurable with an allowed-region base/limit.
2. Document prominently: "FastVDMA provides no isolation. You MUST place
   it behind an IOMMU/SMMU or a privilege-gated interconnect."
3. Rename/annotate `4KBarrier` to make clear it's a protocol feature.

**How to check:** `rt-si` flags DMA address assignments sourced from
CSRs or descriptors without a range check. Manual review: trace the
address path from CSR/descriptor to AXI AR/AW channel and confirm
there's a comparator.

**MITRE references:** https://cwe.mitre.org/data/definitions/1190.html
(closely related: CWE-1189 Improper Isolation of Shared Resources on SoC)

---

## How these map to the scanner

`rt-si` detects the RTL patterns above. Each rule is being re-anchored
to emit the CWE ID rather than a reinvented class name. The attestation
output becomes: "no findings of CWE-1191, CWE-1262, CWE-325, CWE-1190,
CWE-1189 at severity HIGH or above." That uses MITRE's authoritative
vocabulary, so a reviewer who knows CWE understands the result without
learning our terminology.

The scanner is a **hint, not a finding.** Every confirmed defect above
came from a human reading the surrounding RTL and forming a hypothesis,
not from a regex match. The scanner surfaces the line; the reasoning
proves the bug.
