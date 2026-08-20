# CWE field guide for OSS hardware — entries 5–9

Continues from `02-cwe-field-guide-entries.md`. Same template: plain-
language definition → RTL pattern → worked example → fix → detection.

---

## CWE-1245: Improper Finite State Machines (FSMs) in Hardware Logic

**Plain language:** your design has a state machine that can be pushed
into an undefined or wrong state by a fault (a voltage spike, a cosmic
ray, a deliberate glitch). When that happens, the state machine might
skip a security check, bypass a lock, or enter a privileged state it
shouldn't.

**Why it matters:** in software, an unexpected state causes a crash
(usually recoverable). In hardware, an FSM that lands in the wrong state
silently continues executing — often with security properties violated.
This is one of the most common fault-injection attack vectors: glitch
the state register, skip the "check PIN" state, land in "authenticated."

**What it looks like in RTL:** a state machine declared as a plain enum
with `case`/`switch`, no terminal Error state, no sparse encoding, and
no default branch that forces a safe state.

### The pattern (bad)

```verilog
typedef enum logic [2:0] {
    IDLE, CHECK_PIN, AUTHENTICATED, LOCKED
} state_t;

always @(posedge clk) begin
    case (state)
        IDLE:        state <= CHECK_PIN;
        CHECK_PIN:   state <= pin_valid ? AUTHENTICATED : LOCKED;
        AUTHENTICATED: state <= IDLE;  // done
        LOCKED:      state <= IDLE;    // reset
        // NO default — undefined states are unreachable... in simulation
    endcase
end
```

A 3-bit register has 8 possible values but only 4 are defined. A glitch
that flips one bit lands in states 4–7, which have no case branch — the
FSM stays there forever, or worse, the synthesis tool picks an arbitrary
behavior for the undefined states.

### The pattern (hardened — OpenTitan style)

```verilog
typedef enum logic [2:0] {
    IDLE, CHECK_PIN, AUTHENTICATED, LOCKED, ERROR
} state_t;

always @(posedge clk) begin
    case (state)
        IDLE:          state <= CHECK_PIN;
        CHECK_PIN:     state <= pin_valid ? AUTHENTICATED : LOCKED;
        AUTHENTICATED: state <= IDLE;
        LOCKED:        state <= IDLE;
        default:       state <= ERROR;  // ANY undefined state -> ERROR
    endcase
end

// OpenTitan goes further: uses PRIM_FLOP_SPARSE_FSM which encodes
// states with maximum Hamming distance and auto-detects single-bit
// faults, forcing ERROR immediately.
```

### Worked example: TT07 RO-PUF arbiter reset race

**Target:** `litneet64/tt07-RO-based-PUF` — a Tiny Tapeout ring-
oscillator PUF.

The arbiter module's reset predicate compared against Verilog's `'x`
(unknown) value:

```verilog
// arbiter.v:13-17
if ((marked_1 == 'x && marked_2 == 'x) || rst) begin
    marked_1 <= 0; marked_2 <= 0;
end
```

In simulation, registers initialize to `'x`, so this fires on cycle 1.
In real silicon, flip-flops power up to a physical 0 or 1 — the `=='x'`
check **never evaluates true in hardware.** The reset logic is dead.
Combined with the fact that the arbiter can be re-armed by pulsing
`rst` at a chosen time (a single-bit glitch), an attacker can re-run
the race under controlled timing and forge any PUF response bit.

This is CWE-1245 (improper FSM) + CWE-1271 (uninitialized reset) in
combination — the FSM's reset behavior doesn't match the author's
mental model, and the undefined power-up state is exploitable.

**Is this a vulnerability?** The design makes no security claim (it's
an educational PUF characterisation project). But the *pattern* —
relying on `'x` for reset logic — is a real defect class that appears
in production RTL. It's a teaching example of how simulation-only
assumptions break in silicon.

**The fix:**
1. Never compare against `'x`/`'z` in synthesised logic. Rely on
   explicit `rst` and document that FFs power up undefined.
2. Use sparse FSM encoding (e.g., OpenTitan's `PRIM_FLOP_SPARSE_FSM`).
3. Always include a `default → ERROR` branch.
4. Add a fault-detection canary if the FSM gates something critical.

**How to check:** `rt-si` flags `=='x'`/`=='z'` comparisons in reset
predicates (the B1 rule). Manual review: confirm every FSM has a
default branch and that reset doesn't depend on simulation-only state.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1245.html

---

## CWE-1300: Improper Protection of Physical Side Channels

**Plain language:** your chip leaks secret information through physical
signals — power consumption, electromagnetic emission, timing — that an
attacker can measure from outside the chip. The crypto is mathematically
correct, but the *implementation* betrays the key.

**Why it matters:** this is how smartcards, game consoles, and hardware
wallets have been broken for 30 years. A plain (unmasked) AES
implementation leaks the key through power consumption after ~1,000
measurements. The attack is cheap (ChipWhisperer ~$50) and well-
documented. Every OSS crypto core that ships without masking is
vulnerable to anyone with physical access.

**What it looks like in RTL:** a crypto core using plain lookup tables
for S-boxes, storing round keys in plain registers, with control flow
that branches on secret data.

### The pattern (vulnerable)

```verilog
// Plain AES S-box — power consumption depends on the key
wire [7:0] sbox_out = sbox[plaintext_byte ^ round_key_byte];

// The index (plaintext ^ key) determines which of 256 mux paths
// activates, producing a distinct power signature per key byte.
// An attacker measures power across many encryptions and recovers
// the key via Correlation Power Analysis (CPA).
```

### The pattern (hardened — masked)

```verilog
// Masked AES S-box (e.g., DOM-deep, Canright right-sided)
// The key byte is split into shares: key = k0 XOR k1
// The S-box computation operates on masked intermediates such that
// no single wire carries a value correlated with the key.
// Power consumption is independent of the key (first-order secure).
```

Masking is complex and most OSS implementations don't do it. OpenTitan's
AES is the rare exception that ships with masking options.

### Worked example: secworks/aes, SpinalHDL AesPlugin, and the OSS crypto census

We scanned 491 OSS-silicon targets. **9% of them have an unmasked crypto
core** (CWE-1300 candidates). Sampled hits at scale:
- `secworks/aes` — plain S-box LUT
- SpinalHDL VexRiscv `AesPlugin` — T-table AES in the CPU pipeline
- Multiple PRESENT, Simon/Speck, ChaCha20 implementations — all unmasked

This is endemic. Almost no OSS crypto core ships with masking. The few
that attempt it (OpenTitan, some research projects) are the exception.

**Important nuance — we tried to verify a leak and couldn't (honest
negative):** we synthesized an RC5 rotation unit (secret-dependent
rotation amount, classic C2 leak) and ran gate-level toggle counting
across multiple seeds. The across-rotation coefficient of variation
was 2.2% — below real-silicon measurement noise. The structural
precondition exists (distinct mux branches), but bulk-power toggle
counting did not confirm an exploitable leak. Targeted-EM or layout-
aware analysis would be needed. **This is documented as a limitation,
not hidden.** The field guide claims "unmasked crypto has a structural
SCA precondition" (true, well-established) not "every unmasked core
is exploitable from bulk power" (unproven by us).

**The fix:**
1. If the threat model includes physical access: use a masked
   implementation (DOM, ISW, HODL). OpenTitan's is a reference.
2. If the threat model is network-only (no physical access): unmasked
   may be acceptable, but document it as a known limitation.
3. Never branch on secret data in timing-critical paths (CWE-1254).

**How to check:** `rt-si` flags crypto cores with S-box references and
no masking signal (the C1 rule). Confirmation requires gate-level
toggle counting (Yosys + Verilator) or real measurement (ChipWhisperer)
— the scanner is a hint, not proof.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1300.html

---

## CWE-1247: Improper Protection Against Voltage and Clock Glitches

**Plain language:** an attacker can spike or drop the power supply, or
mess with the clock, to flip a specific bit in a security-critical
register. The most common target: a counter that gates a security
decision (login attempts, crypto rounds, watchdog timeout). Glitch the
counter's MSB and it wraps past the threshold.

**Why it matters:** glitch attacks are cheap (a $10 FPGA and a resistor
on the power line) and well-documented. They bypass software-only
defenses entirely because they operate on the physical registers.

**What it looks like in RTL:** a security-relevant counter declared as
a plain `reg [N:0]` instead of a hardened (redundant, glitch-aware)
counter.

### The pattern (vulnerable)

```verilog
reg [15:0] login_attempts;  // plain counter — glitch the MSB, wrap to 0

always @(posedge clk) begin
    if (login_valid && !login_correct)
        login_attempts <= login_attempts + 1;
    if (login_attempts >= 16'd5)
        lock_out <= 1;  // never reached if attacker glitches past 5
end
```

### The pattern (hardened — OpenTitan style)

```verilog
// OpenTitan uses prim_count: a redundant counter that stores the value
// in two complement representations and checks they agree every cycle.
// A single-bit glitch produces a mismatch -> ERROR, not a bypass.

prim_count #(
    .Width(16),
    .CntSrc("Increment")  // or " decrement", with parity
) u_login_attempts (
    .clk_i, .rst_ni,
    .clr_i(1'b0),
    .set_i(login_valid && !login_correct),
    .set_cnt_i(login_attempts + 1),
    .cnt_o(login_attempts),
    .err_o(counter_error)  // any bit-flip -> error
);
```

### Worked example: AES round counters across OSS cores

In our 491-target scan, **47.7% of designs have at least one security-
relevant counter declared as a plain `reg`** (B4/CWE-1247 candidates).
These include:
- AES round counters (`round_ctr_reg`) — glitch to skip the final round,
  producing ciphertext that's distinguishable from correct AES
- RSA modular-multiplication counters — glitch to shorten the operation
- TRNG entropy-mixer word counters (`word_ctr_reg`) — glitch to corrupt
  the mixed output
- picorv32 cycle counters — glitchable core state

Not every plain counter gates a security decision. But the prevalence of
unglitch-hardened security-adjacent counters is the whitepaper headline:
the OSS ecosystem does not, in general, use hardened counters.

**The fix:**
1. For counters that gate security decisions: use a redundant encoding
   (`prim_count` or equivalent). The cost is ~2x the registers; the
   benefit is single-bit-fault detection.
2. Add a glitch detector / canary FF if the design handles secrets.
3. At minimum: document which counters are security-relevant so a
   reviewer knows where to look.

**How to check:** `rt-si` flags plain `reg[N]` counters with security-
relevant names (`round`, `attempt`, `key`, `ctr`, `counter` on modules
with security context). Testbench files are excluded. The rule has a
high false-positive rate — confirm the counter actually gates something
before acting.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1247.html

---

## CWE-1271: Uninitialized Value on Reset for Registers Holding Security Settings

**Plain language:** when your chip powers on (or after a reset), the
registers that control security settings (lock bits, privilege levels,
protection enables) come up in an undefined state. If "undefined" happens
to mean "protection disabled," the chip boots with security off — and if
an attacker can act before firmware enables protection, they win.

**Why it matters:** this is the root of many boot-time vulnerabilities.
The window between power-on and firmware-configuration is when the chip
is most exposed. A register that powers up to "debug enabled" or "memory
unprotected" is an open door.

**What it looks like in RTL:** security-critical registers without an
explicit reset value, or with a reset value that leaves protection
disabled.

### The pattern (vulnerable)

```verilog
reg debug_enable;         // no reset value — powers up undefined
reg [1:0] privilege_level; // no reset value — could be anything

// In real silicon, these power up to 0 or 1 depending on the FF
// architecture and process variation. You don't control it.
// If debug_enable powers up as 1, debug is open until firmware clears it.
```

### The pattern (safe)

```verilog
reg debug_enable = 1'b0;              // explicitly reset to DISABLED
reg [1:0] privilege_level = 2'b00;    // explicitly reset to lowest privilege

// Or in an always block:
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        debug_enable <= 1'b0;          // fail-safe: disabled on reset
        privilege_level <= 2'b00;      // fail-safe: lowest privilege
    end else ...
end
```

### Worked example: MIT-LL CEP SROT mode bits (combined with CWE-1262)

The MIT-LL CEP SROT (covered in entry 2 under CWE-1262) has a combined
CWE-1262 + CWE-1271 defect: the mode bits that lock Key RAM **reset to
0 (unlocked)**, not to 1 (locked). This means on every reset, the key
protection is off until firmware explicitly engages it. The fail-safe
design would reset to locked and require firmware to explicitly unlock
(with authentication). The actual design resets to unlocked and trusts
firmware to lock.

**The principle:** security-critical registers should reset to their
MOST restrictive value, not their least. "Fail-safe" means the default
state is secure, and the insecure state requires explicit action.

**The fix:**
1. Audit every security-critical register's reset value. Confirm it
   resets to the most restrictive state (debug disabled, privilege
   lowest, protection enabled, keys cleared).
2. If a register must reset to a permissive state (e.g., for bring-up),
   document it prominently and add a timeout or watchdog that forces
   the secure state.
3. Use OpenTitan's pattern: lifecycle controller asserts a global
   `lc_escalate` that forces all security signals to their safe state
   regardless of register values.

**How to check:** manual review of every register in the security path.
`rt-si` doesn't currently detect this (it requires understanding the
intended security state, not just the code). This is a candidate for
a future rule that flags registers with security-relevant names that
lack explicit reset values.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1271.html

---

## CWE-1242: Inclusion of Undocumented Features or Chicken Bits

**Plain language:** the design contains hidden features, test modes, or
"chicken bits" (configuration bits left over from development) that
create entry points an attacker can use. These aren't bugs — they're
intentional features that were never documented or removed before
production.

**Why it matters:** chicken bits are how many real-world exploits work.
The Intel ME, the AMD PSP, various baseband debug modes — all are
"features" that became attack surfaces. In OSS HW, anyone can see them
in the RTL, which makes them both easier to find and easier to exploit.

**What it looks like in RTL:** a register bit or mode that activates
behavior not described in the spec, or a test/debug path that's reachable
in production configuration.

### The pattern

```verilog
// Hidden test mode left in production RTL
reg [31:0] magic_value;
always @(posedge clk) begin
    if (magic_value == 32'hDEADBEEF) begin
        // Bypass all security checks — this is the "test mode"
        // the team used during bring-up and forgot to remove
        bypass_security <= 1;
    end
end
```

### Worked example: the E1 dormant-trigger class in OSS HW

In our 491-target scan, the E1 rule (which flags control-flow predicates
against undocumented magic constants) fired on 16 targets. Most were
legitimate (opcodes, protocol constants, CRC polynomials — the rule
requires control-flow context and no nearby comment). But the class is
real: a magic-constant trigger is the canonical hardware-trojan
signature.

The academic trojan literature (Dong et al. 2020, Chakraborty et al.)
classifies these as "combinational trigger" trojans — activated when
internal signals reach a specific value. The trigger is rare enough
that functional testing never exercises it, but an attacker who knows
the value can fire it at will.

**The OSS HW supply-chain angle:** in a commercial chip, chicken bits
are inserted by the vendor's own engineers. In OSS HW, **anyone can
insert one via a pull request.** A malicious contributor adds a
plausible-looking "performance optimization" or "debug helper" that
contains a dormant trigger. It merges because reviewers check
functionality, not security. This is the OSS HW equivalent of a
malicious npm package — except you can't uninstall it after tapeout.

**The fix:**
1. Document every configuration bit, test mode, and magic constant in
   the design. If it's not documented, it's a finding.
2. For OSS projects: require security review of any PR that adds
   conditional logic based on specific constant values.
3. Remove chicken bits before tapeout. Run a "dead code elimination"
   pass that flags unreachable or undocumented logic.
4. Use OpenTitan's pattern: all debug/test logic is gated by a
   lifecycle controller that's physically disabled in production
   (via OTP fuse).

**How to check:** `rt-si` flags control-flow predicates against
undocumented magic constants (the E1 rule). Manual review: for every
magic constant in the design, confirm it's documented and reachable
only via intended inputs. For OSS projects: review PRs that add
conditional logic.

**MITRE reference:** https://cwe.mitre.org/data/definitions/1242.html

---

## CWE-362: Race Condition (non-blocking assignment override)

**Plain language:** the same signal is assigned twice in the same clock
cycle without the assignments being in mutually exclusive branches. The
last assignment silently wins, and the first one is dead code. If the
two assignments encode different intents (reset vs. data, two different
conditions), one of them never happens.

**Why it matters:** in simulation you may see the correct value (the
last assignment is what settles), so tests pass. But the dead
assignment masks a real intent bug: usually one condition was supposed
to take priority, and the priority is inverted or one path is
unreachable. In security logic this shows up as a reset or lock that
appears to be implemented but never fires.

**What it looks like in RTL:** two non-blocking assignments to the same
signal inside one always block, with only plain `if` blocks between
them (no `else` making the paths exclusive).

### The pattern (vulnerable)

```verilog
always @(posedge clk) begin
    if (lock_request)
        lock_reg <= 1'b1;      // intent: set the lock
    if (clear_all)
        lock_reg <= 1'b0;      // intent: clear — silently overrides above
endmodule
```

When both `lock_request` and `clear_all` are high, `lock_reg` gets 0.
If the design intent was "lock wins," the code is wrong and no test
caught it — both assignments "ran."

### The pattern (correct — explicit priority)

```verilog
always @(posedge clk) begin
    if (clear_all)
        lock_reg <= 1'b0;      // clear has priority
    else if (lock_request)
        lock_reg <= 1'b1;      // lock only when not clearing
end
```

**How to check:** `rt-si` flags signals assigned twice in one always
block without a branch separator between the assignments (the CWE362
rule). Manual review: for each hit, confirm the two assignment paths
are genuinely mutually exclusive and the winning order matches intent.

**MITRE reference:** https://cwe.mitre.org/data/definitions/362.html

---

## CWE-369: Divide By Zero

**Plain language:** the design performs a division or modulo where the
divisor can be zero. In hardware the result is undefined (each
synthesis tool picks its own behavior), and in a CPU core it usually
means a hang or a wrong result where the ISA defines an exact answer.

**Why it matters:** on RISC-V cores the architecture specifies exact
results for divide-by-zero (`DIV x/0 = -1`, `REM x/0 = x`). A divider
that instead hangs the pipeline or returns garbage breaks software that
relies on the spec — and an attacker who can drive a zero divisor has
a denial-of-service primitive against the core.

**What it looks like in RTL:** an iterative divider whose control FSM
has no guard on the divisor before starting the shift-subtract loop.

### The pattern (vulnerable)

```verilog
// iterative restoring divider, no zero check
if (div_start) begin
    state <= DIVIDE;      // enters 32-cycle loop regardless of divisor
    quotient <= (others => '0');
end
```

If `divisor == 0`, the subtraction loop never converges to a sensible
quotient — or worse, the FSM stalls waiting for a borrow that behaves
unexpectedly.

### The pattern (correct)

```verilog
if (div_start) begin
    if (divisor = ZERO) begin
        quotient  <= signed ? NEG_ONE : UNSIGNED_MAX;  -- x/0 per spec
        remainder <= dividend;                          -- x MOD 0 = x
        state     <= DONE;
    end else
        state <= DIVIDE;
end
```

**How to check:** `rt-si` flags division logic with no zero-divisor
comparison anywhere in the file (the CWE369 rule). Manual review:
trace the divisor input through the FSM and confirm the spec-defined
result is produced.

**MITRE reference:** https://cwe.mitre.org/data/definitions/369.html

---

## CWE-835: Loop with Unreachable Exit Condition (infinite loop)

**Plain language:** in RTL terms, the class we flag is the copy-paste
index error: a concatenation or assignment list that uses the same
array index twice and skips another. The "loop" (your enumeration of
elements) has a wrong exit state — one element never gets read, and
another gets read twice.

**Why it matters:** this is a silent data-corruption bug that produces
wrong results with no error signal. The canonical case: secworks/sha3
assembled its Keccak state with `block_reg[04]` twice and `block_reg[06]`
never — the core computed wrong hashes, and because SHA-3 output looks
random either way, only a known-answer test catches it.

**What it looks like in RTL:** a hand-written concatenation or case
enumeration where indices are copy-pasted.

### The pattern (vulnerable)

```verilog
// Keccak state assembly — [04] duplicated, [06] missing
assign state_in = {block_reg[03], block_reg[04], block_reg[04],
                   block_reg[05], block_reg[07], ...};
// Every hash this core produces is wrong. Simulation "works" (no X's),
// the design synthesizes, and only a NIST test vector catches it.
```

### The pattern (correct)

```verilog
assign state_in = {block_reg[03], block_reg[04], block_reg[05],
                   block_reg[06], block_reg[07], ...};
// Sequential indices — generate the list or test against the spec.
```

**How to check:** `rt-si` flags duplicate array indices inside
concatenations (the CWE835 rule — this exact check found the sha3
bug). Manual review: for any hand-enumerated list, verify against the
spec's element ordering, and always run known-answer test vectors
before trusting a crypto core.

**MITRE reference:** https://cwe.mitre.org/data/definitions/835.html
