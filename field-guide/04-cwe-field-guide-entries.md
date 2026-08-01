# CWE field guide for OSS hardware — entries 10–16

Continues from `03-cwe-field-guide-entries.md`. These entries cover the
remaining high-priority CWE classes for OSS HW contributors: resource
isolation, root-of-trust, secret zeroization, comparison side-channels,
debug-data leakage, fabric security, and TOCTOU on access checks.

---

## CWE-1189: Improper Isolation of Shared Resources on System-on-a-Chip (SoC)

**Plain language:** multiple components on your chip share a resource
(memory, bus, register block) and the sharing isn't enforced. A
lower-privilege component can read or modify what a higher-privilege
component is using.

**Why it matters:** this is the hardware equivalent of not isolating
process memory. If a USB peripheral and the secure boot ROM share a bus
without a firewall between them, the peripheral can read the boot keys.
Every "peripheral DMA attacks the host" exploit in history is this class.

**What it looks like in RTL:** a shared memory or bus accessed by multiple
masters with no access-control firewall between them.

### The pattern (vulnerable)

```verilog
// Multiple masters share one memory with no firewall
// master_cpu, master_dma, master_usb all drive the same ddr_if
// Any master can read/write any address — no enforcement.
assign mem_we = cpu_we | dma_we | usb_we;
assign mem_addr = cpu_valid ? cpu_addr :
                  dma_valid ? dma_addr : usb_addr;
assign mem_wdata = cpu_valid ? cpu_wdata :
                   dma_valid ? dma_wdata : usb_wdata;
// No check that dma_addr or usb_addr is within the peripheral's region.
```

### The pattern (hardened)

```verilog
// Each master goes through a firewall that checks its address range.
// OpenTitan uses tlul_socket_1n / tlul_socket_mfn interconnects with
// per-port address range enforcement.

// Simplified firewall:
assign dma_allowed = (dma_addr >= DMA_BASE) && (dma_addr < DMA_LIMIT);
assign usb_allowed = (usb_addr >= USB_BASE) && (usb_addr < USB_LIMIT);

assign mem_we   = (cpu_we) | (dma_we   && dma_allowed) | (usb_we   && usb_allowed);
assign mem_addr = cpu_valid ? cpu_addr :
                  (dma_valid && dma_allowed) ? dma_addr :
                  (usb_valid && usb_allowed) ? usb_addr : 32'h0;
// Mismatch -> error interrupt + block the transaction
```

### Worked example: FastVDMA (see entry 4, CWE-1190)

The FastVDMA finding (entry 4) is CWE-1189 + CWE-1190 in combination:
the DMA is a shared resource whose address path has no isolation. Any
bus master that can write the DMA's CSR gets arbitrary memory access.
**The DMA is the un-isolated shared resource; the system memory it
reads/writes is the asset being compromised.**

In the broader population, this pattern recurs wherever an OSS peripheral
controller (USB, SPI slave, network MAC) can issue bus transactions
without an address firewall.

**The fix:**
1. Every DMA-capable master must pass through an address firewall with
   per-master allowed regions.
2. If using a NoC/fabric: configure the fabric's built-in security
   (OpenTitan's TileLink, ARM TrustZone-aware AXI, RISC-V PMP for
   CPU-initiated access).
3. **Document the isolation requirement** — this is where OSS IP fails
   most often. The IP doesn't enforce isolation; the integrator must.
   Say so explicitly.

**How to check:** `rt-si` flags DMA address paths sourced from CSR
without range checks (CWE-1190/1189 combined). Manual review: trace
every bus master and confirm it passes through a firewall or IOMMU.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1189.html

---

## CWE-1326: Missing Immutable Root of Trust in Hardware

**Plain language:** your chip has no unchangeable, hardware-enforced
anchor of trust for boot verification. The first code that runs isn't
verified against anything immutable, so an attacker who can replace it
(or the verification key) controls the whole system.

**Why it matters:** secure boot only works if the root verification key
is in immutable storage (ROM, OTP fuse, eFuse). If the key is in writable
flash, or if the boot ROM can be patched to skip verification, the entire
trust chain is hollow. Every "secure boot bypass" is ultimately this
class: the root isn't really a root.

**What it looks like in RTL:**
- A boot verification key stored in mutable memory (SRAM, flash) rather
  than OTP/ROM
- A boot ROM that can be overridden or patched by software
- No hardware enforcement that the boot ROM runs first (another core or
  DMA can modify boot code before verification)

### The pattern (vulnerable)

```verilog
// Boot verification key in mutable flash
assign verify_key = flash_read(BOOT_KEY_ADDR);
// An attacker who can write flash (via DMA, JTAG, or a flash exploit)
// replaces the key with their own and signs their boot image.
// The verification "passes" — but it's checking against the attacker's key.

// Or: boot ROM is patchable
always @(posedge clk) begin
    if (rom_patch_enable)  // software-controllable!
        boot_instr <= rom_patch_data;
end
```

### The pattern (hardened)

```verilog
// Boot key in one-time-programmable (immutable) fuse
assign verify_key = otp_read(BOOT_KEY_FUSE_ADDR);
// OTP is physically write-once; once blown, the key can't be changed.
// This is the hardware root of trust.

// Boot ROM in mask ROM (physically immutable)
// No patch mechanism. If a patch is needed, it's signed and verified
// against the ROM key before loading.
```

### Worked example: the absence is the finding

In our OSS HW scan, we didn't find a specific design with a broken RoT —
we found that **most OSS HW designs have no RoT at all.** A Tiny Tapeout
chip or a hobbyist FPGA SoC has no secure boot, no immutable key, no
measurement chain. That's fine for a blinky LED; it's catastrophic if
that design gets pulled into a product that needs secure boot.

The finding is the gap between "what OSS HW ships with" and "what a
security-relevant integration needs." If you're integrating OSS IP into
a product that needs secure boot, **you must add the RoT** — the OSS IP
doesn't have one.

**The fix:**
1. If your product needs secure boot: add an immutable RoT (OTP fuse for
   the key, mask ROM or signed-flash for the boot code). OpenTitan is the
   OSS reference for how to do this.
2. Never store the boot verification key in writable memory.
3. Never make the boot ROM patchable without signed verification.

**How to check:** manual review. Does the design have a boot path? If so,
where's the verification key stored? Is it immutable? `rt-si` doesn't
detect this (requires understanding the boot architecture, not just code).

**MITRE reference:** https://cwe.mitre.org/data/definitions/1326.html

---

## CWE-1239: Improper Zeroization of Hardware Register

**Plain language:** your chip stores a secret (key, password hash, RNG
state) in a register, then doesn't clear it when it should — when the
owner changes, on reset, or before reuse. The next user (or attacker)
reads the previous user's secret.

**Why it matters:** this is the hardware equivalent of not clearing
memory before freeing it. In a multi-tenant device (multiple users, or
firmware reload), uncleared secrets from one context leak to the next.

**What it looks like in RTL:** a register holding secret data with no
clear path on context switch, ownership change, or reset.

### The pattern (vulnerable)

```verilog
reg [255:0] aes_key;

always @(posedge clk) begin
    if (key_load)
        aes_key <= key_input;
    // ... encryption happens ...
    if (encryption_done)
        done <= 1;
    // NO clearing of aes_key when done, or when a new session starts.
    // The key persists in the register, readable by whoever accesses it next.
end
```

### The pattern (hardened)

```verilog
reg [255:0] aes_key;

always @(posedge clk) begin
    if (key_load)
        aes_key <= key_input;
    if (encryption_done || session_end || !rst_n) begin
        // Zeroize on completion, session end, AND reset
        aes_key <= 256'h0;
        done <= 1;
    end
end

// OpenTitan additionally uses prim_sec_anchor_buf to prevent the key
// register from being optimized away or probed by synthesis tools.
```

### Worked example: the 2025 CWE MIHW #1 entry

**CWE-226 (Sensitive Information in Resource Not Cleared Before Reuse)**
is the #1 entry on the 2025 CWE Most Important Hardware Weaknesses list —
MITRE's data-driven ranking. CWE-1239 is the hardware-register-specific
child of CWE-226. The field considers this the single highest-priority
hardware weakness.

In OSS HW, uncleared key registers are endemic. Most OSS AES cores load a
key into a register and never clear it. On a multi-session device or after
a reset, the previous key is recoverable.

**The fix:**
1. Every register that holds secret data (keys, passwords, RNG state,
   intermediate crypto values) must have an explicit zeroization path.
2. Zeroize on: reset, session end, ownership change, and before reuse.
3. Use OpenTitan's `prim_sec_anchor_buf` to prevent synthesis from
   optimizing away the zeroization.

**How to check:** manual review of every register in the secret-data path.
Confirm each has a clear-to-zero path that's actually reachable. This is
a strong candidate for a future `rt-si` rule (flag registers with
key/password/secret names that lack a `<= 0` assignment).

**MITRE reference:** https://cwe.mitre.org/data/definitions/1239.html

---

## CWE-1255: Comparison Logic is Vulnerable to Power Side-Channel Attacks

**Plain language:** your design compares a secret value against a
reference (a PIN, a key, a token) in a way that leaks information through
power consumption. By measuring power during the comparison, an attacker
recovers the secret bit-by-bit.

**Why it matters:** this is how hardware security tokens and smartcards
were broken in the 1990s and 2000s. A comparison that exits early (on the
first mismatch) takes different amounts of time for different inputs, and
the timing is observable through power. Even a constant-time comparison
can leak if the comparison logic's power consumption depends on the data
being compared.

**What it looks like in RTL:** a comparison that short-circuits, or whose
intermediate operations have data-dependent power.

### The pattern (vulnerable)

```verilog
// Early-exit comparison — leaks how many bytes matched
integer i;
always @(posedge clk) begin
    match <= 1;
    for (i = 0; i < 8; i = i + 1) begin
        if (input_pin[i] != stored_pin[i]) begin
            match <= 0;
            // Early exit — power trace reveals which byte mismatched.
            // An attacker flips input bytes one at a time and watches
            // when the power trace changes length.
        end
    end
end
```

### The pattern (hardened)

```verilog
// Constant-time comparison: XOR all bytes, accumulate mismatches.
// Power is independent of WHICH bytes matched — only of the total
// (which the attacker already knows: they know if they matched).
reg mismatch;
always @(posedge clk) begin
    mismatch <= 1'b0;
    for (i = 0; i < 8; i = i + 1) begin
        mismatch <= mismatch | (input_pin[i] ^ stored_pin[i]);
        // No early exit. Every byte is compared regardless.
    end
    match <= ~mismatch;
end
```

### Worked example: no specific OSS instance, but the class is universal

We didn't find a specific comparison-SCA instance in the diamonds. But
the class is universal: any OSS design that compares a secret (PIN, key,
token) against a reference using a loop or early-exit is vulnerable.
TRNG health-check comparators, PUF authentication, and boot-ROM
measurement comparison are all candidates.

**The fix:**
1. Never use early-exit comparisons on secret data.
2. Use XOR-and-accumulate (constant-time) comparisons.
3. If the comparison gates something critical (authentication, unlock),
   add randomization or rate-limiting to make power attacks harder.

**How to check:** manual review of every comparison involving secret data.
Look for `for`/`while` loops with early exits, or `if`-chained
comparisons. A future `rt-si` rule could flag comparison loops on
secret-named signals.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1255.html

---

## CWE-1243: Sensitive Non-Volatile Information Not Protected During Debug

**Plain language:** your chip stores secrets in non-volatile memory (OTP
fuses, flash) and the debug interface can read them. An attacker with
debug access extracts all the fuses, including keys and configuration.

**Why it matters:** OTP fuses hold the most sensitive data on the chip —
boot keys, device IDs, calibration data, security configuration. If debug
access can read them, physical access = total key extraction.

**What it looks like in RTL:** a debug path that can access OTP/eFuse read
data without restriction.

### The pattern (vulnerable)

```verilog
// Debug can read any fuse
always @(posedge clk) begin
    if (debug_read_req)
        debug_read_data <= otp_fuses[debug_read_addr];
        // No check whether this fuse is sensitive or whether debug
        // access is authorized for this fuse.
end
```

### The pattern (hardened)

```verilog
// OpenTitan's OTP controller partitions fuses into "creator," "owner,"
// and "isolated" partitions. Debug access to each is gated by lifecycle
// state (TEST, DEV, PROD). In PROD, all key partitions are inaccessible
// via debug regardless of authentication.

always @(posedge clk) begin
    if (debug_read_req) begin
        if (lc_state == PROD && fuse_is_sensitive[debug_read_addr])
            debug_read_data <= 32'h0;  // blocked in PROD
            // Or: trigger an alert / escalation
        else if (lc_state == DEV || lc_state == TEST)
            debug_read_data <= otp_fuses[debug_read_addr];
    end
end
```

### Worked example: the OpenTitan reference (how to do it right)

OpenTitan is the reference here — not because it has the bug, but because
it's the rare OSS design that gets this right. Its lifecycle controller
(`lc_ctrl`) partitions fuse access by lifecycle state (TEST → DEV → PROD
→ RMA) and each partition has distinct access rules. In PROD, all key
partitions are inaccessible. This is the pattern to copy.

Most OSS HW has no lifecycle controller at all. A Tiny Tapeout chip has
no OTP, no fuses, no lifecycle — which is fine for toys but means the
design has no model for protecting NV secrets when it's pulled into a
real product.

**The fix:**
1. If your design uses OTP/eFuse for secrets: add a lifecycle controller
   that gates debug access to sensitive partitions.
2. In PROD state: block all debug reads of key/secret fuses.
3. Allow RMA (return-merchant-authorization) state for legitimate
   post-deployment debug, but require authenticated entry.

**How to check:** manual review. Does the design have OTP? Does the debug
path reach it? Is access gated by lifecycle? A future `rt-si` rule could
flag OTP read paths reachable from debug without a lifecycle gate.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1243.html

---

## CWE-1318: Missing Support for Security Features in On-chip Fabrics or Buses

**Plain language:** the bus that connects components on your chip doesn't
carry security information. When a CPU, a DMA, and a peripheral talk to
memory over the same bus, the bus doesn't know who's who — so it can't
enforce access control.

**Why it matters:** if the bus doesn't carry privilege level, security
identifier, or transaction attributes, no firewall can enforce policy.
The bus is the backbone; if the backbone has no security, the attached
components can't help.

**What it looks like in RTL:** a bus fabric (crossbar, NoC, shared bus)
with no security-ID signal on transactions.

### The pattern (vulnerable)

```verilog
// Simple shared bus: address, data, valid/ready. No privilege,
// no master ID, no security attributes.
typedef struct {
    logic [31:0] addr;
    logic [31:0] wdata;
    logic        we;
    logic        valid;
    logic        ready;
} bus_txn_t;
// The memory controller can't tell if a request is from the CPU
// (trusted) or from USB (untrusted). It must allow or deny all.
```

### The pattern (hardened)

```verilog
// Security-aware bus: carries privilege + master ID + transaction type
typedef struct {
    logic [31:0] addr;
    logic [31:0] wdata;
    logic        we;
    logic        valid;
    logic        ready;
    logic [3:0]  master_id;    // who initiated this
    logic [1:0]  priv_level;   // M/S/U
    logic        secure_txn;    // secure vs non-secure (TrustZone-style)
} bus_txn_t;
// The firewall can now check: is master_id=USB accessing a secure region?
// Is priv_level=U trying to write a machine-mode register?
```

### Worked example: AXI-Lite without AxPROT

Many OSS SoCs use AXI-Lite for simplicity. AXI-Lite's `AxPROT` signal
(which carries privilege + secure/non-secure info) is **frequently left
unconnected** in OSS designs — it's optional in the protocol, and
simplification often drops it. Without `AxPROT`, the interconnect has no
way to enforce TrustZone-style isolation or privilege separation.

This is a composition-level defect: each IP is fine in isolation (it
doesn't need AxPROT to function), but the integrated system can't enforce
access control because the backbone doesn't carry the signal.

**The fix:**
1. If using AXI: wire `AxPROT` on every interconnect. Configure firewalls
   to check it.
2. If using TileLink (RISC-V): use the `TL_A` channel's privilege signals.
3. If using a custom bus: include a master-ID and privilege-level on every
   transaction from day one. Adding it later means re-working every IP.
4. Document the bus's security model so integrators know what the fabric
   does and doesn't enforce.

**How to check:** manual review of the bus fabric. Does it carry privilege
or security-ID signals? Are they wired through every IP port? A future
`rt-si` rule could flag AXI-Lite instances with unconnected `AxPROT`.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1318.html

---

## CWE-1280: Access Control Check Implemented After Asset is Accessed

**Plain language:** the security check happens too late — the data has
already been read or written before the check runs. It's like checking
ID after letting someone into the vault.

**Why it matters:** in hardware, pipelining makes this subtle. A bus
transaction might fetch data from memory on cycle N, and the access-
control check completes on cycle N+1. If the data was already sent on
cycle N, the check is advisory, not enforcing.

**What it looks like in RTL:** a data path that's faster than the security
check path, so the data reaches the output before the check gates it.

### The pattern (vulnerable)

```verilog
// Memory read returns data combinationally; check completes next cycle
assign mem_rdata = memory[mem_addr];  // data available immediately
always @(posedge clk) begin
    access_ok <= check_permission(mem_addr, requester_id);
    // By the time access_ok is known, mem_rdata has already been driven
    // and potentially latched by the requester.
end
```

### The pattern (hardened)

```verilog
// Check BEFORE the read. Data only returns if the check passes.
reg access_ok_r;
always @(posedge clk) begin
    access_ok_r <= check_permission(mem_addr, requester_id);
end
// Data gated by the registered check result
assign mem_rdata = access_ok_r ? memory[mem_addr] : 32'h0;
// Mismatch (access denied) triggers an alert
```

### Worked example: the FastVDMA "4K barrier" confusion

The FastVDMA finding (entry 4) has a TOCTOU flavor: the `4KBarrier` in
TransferSplitter looks like a boundary check (security), but it's actually
an AXI-protocol compliance splitter that operates after the address is
already accepted. An integrator who reads "4KBarrier" and assumes it's
enforcing access control before the transfer is mistaken — the transfer
is already in flight.

More broadly, this class appears in any design where the security check
and the data path are in different pipeline stages without explicit
ordering enforcement.

**The fix:**
1. Security checks must complete BEFORE the asset is accessed. Register
   the check result and gate the data path with it.
2. Never make access control "advisory" (log but allow). Either block or
   don't — half-measures get bypassed.
3. Document the check-vs-data timing explicitly so integrators know the
   check is enforcing, not just monitoring.

**How to check:** manual review. Trace the security check and the data
path. Which completes first? If data reaches the output before the check
gates it, it's CWE-1280.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1280.html
