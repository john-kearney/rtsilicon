# Plain-Verilog fixes (no OpenTitan primitives)

The hardened examples in entries 02-04 show OpenTitan's `prim_count` and
`PRIM_FLOP_SPARSE_FSM`. Most OSS HW contributors don't have OpenTitan's
primitive library. This appendix provides **plain-Verilog equivalents**
that work with any synthesis tool, plus VHDL versions where relevant.

The OpenTitan versions are still listed as the "gold standard" reference.

---

## CWE-1245 (FSM): plain-Verilog sparse encoding

Instead of `PRIM_FLOP_SPARSE_FSM`, use a one-hot or gray-code encoding
with a `default → ERROR` branch:

```verilog
// BAD: sequential encoding, undefined states reachable
typedef enum logic [2:0] {IDLE=0, CHECK=1, AUTH=2, LOCKED=3} state_t;

// GOOD (plain Verilog): one-hot encoding + default → ERROR
typedef enum logic [4:0] {
    IDLE    = 5'b00001,
    CHECK   = 5'b00010,
    AUTH    = 5'b00100,
    LOCKED  = 5'b01000,
    ERROR   = 5'b10000
} state_t;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) state <= IDLE;
    else begin
        case (state)
            IDLE:    state <= CHECK;
            CHECK:   state <= pin_valid ? AUTH : LOCKED;
            AUTH:    state <= IDLE;
            LOCKED:   state <= IDLE;
            default: state <= ERROR;  // ANY undefined → ERROR
        endcase
    end
end

// Optional: error detection (any multi-bit assertion = fault)
wire fault_detected = ^(state);  // XOR-reduction: 0 if >1 bit set
```

**VHDL equivalent:**
```vhdl
-- One-hot state type
type state_t is (IDLE, CHECK, AUTH, LOCKED, ERROR);
-- Synthesis attribute for one-hot encoding:
attribute enum_encoding : string;
attribute enum_encoding of state_t : type is
    "00001 00010 00100 01000 10000";

process(clk)
begin
    if rising_edge(clk) then
        if rst_n = '0' then
            state <= IDLE;
        else
            case state is
                when IDLE   => state <= CHECK;
                when CHECK  => state <= AUTH when pin_valid else LOCKED;
                when AUTH   => state <= IDLE;
                when LOCKED => state <= IDLE;
                when others => state <= ERROR;  -- catch-all
            end case;
        end if;
    end if;
end process;
```

---

## CWE-1247 (glitch-vulnerable counter): plain-Verilog redundant counter

Instead of `prim_count`, use a redundant counter that stores the value
and its complement:

```verilog
// BAD: plain counter
reg [15:0] login_attempts;
always @(posedge clk) login_attempts <= login_attempts + 1;

// GOOD (plain Verilog): redundant counter with mismatch detection
reg [15:0] attempts_val;
reg [15:0] attempts_inv;  // bitwise complement
wire counter_error = (attempts_val != ~attempts_inv);

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        attempts_val <= 16'h0000;
        attempts_inv <= 16'hFFFF;
    end else if (increment) begin
        attempts_val <= attempts_val + 1;
        attempts_inv <= attempts_inv - 1;  // complement tracks
    end
end
// If a glitch flips one but not the other: counter_error = 1
```

**VHDL equivalent:**
```vhdl
signal attempts_val : unsigned(15 downto 0);
signal attempts_inv : unsigned(15 downto 0);
signal counter_error : std_ulogic;

counter_error <= '1' when attempts_val /= not attempts_inv else '0';

process(clk)
begin
    if rising_edge(clk) then
        if rst_n = '0' then
            attempts_val <= (others => '0');
            attempts_inv <= (others => '1');
        elsif increment = '1' then
            attempts_val <= attempts_val + 1;
            attempts_inv <= attempts_inv - 1;
        end if;
    end if;
end process;
```

---

## CWE-1191 (debug access control): plain-Verilog auth gate

Instead of OpenTitan's lifecycle controller, use a simple fuse/auth
register:

```verilog
// GOOD (plain Verilog): debug auth gate
reg debug_locked;  // set by fuse or OTP at boot
reg [31:0] debug_key;
reg [31:0] debug_key_input;
wire debug_auth_valid = (debug_key_input == debug_key) && !debug_locked;

// Gate all debug writes on auth
always @(posedge clk) begin
    if (debug_auth_valid && debug_write_req) begin
        // debug access allowed
    end
    // If !debug_auth_valid: silently ignore all debug writes
end
```

---

## CWE-1190 (DMA without range check): plain-Verilog address firewall

Instead of OpenTitan's TileLink socket, use a simple comparator:

```verilog
// GOOD (plain Verilog): DMA address firewall
parameter [31:0] DMA_ALLOWED_BASE  = 32'h1000_0000;
parameter [31:0] DMA_ALLOWED_LIMIT = 32'h1FFF_FFFF;
reg addr_in_range;

always @(*) begin
    addr_in_range = (dma_addr >= DMA_ALLOWED_BASE) &&
                    (dma_addr <= DMA_ALLOWED_LIMIT);
end

// Gate the DMA request on the firewall
assign dma_axi_arvalid  = dma_req_valid && addr_in_range;
assign dma_axi_araddr   = dma_addr;
assign dma_error        = dma_req_valid && !addr_in_range;  // alert

// If out of range: block the request + raise an error interrupt
```

---

## CWE-1239 (zeroization): plain-Verilog secret clear

```verilog
// GOOD (plain Verilog): explicit zeroization on reset + session end
reg [255:0] aes_key;
reg session_active;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        aes_key <= 256'h0;  // zeroize on reset
    end else if (!session_active) begin
        aes_key <= 256'h0;  // zeroize when session ends
    end else if (key_load) begin
        aes_key <= key_input;
    end
end

// Prevent synthesis from optimizing away the zeroization:
// synthesis translate_off
// Prevent optimization of aes_key clear
// synthesis translate_on
```

---

## Why OpenTitan is still the reference

The plain-Verilog fixes above are **adequate for hobbyist and low-stakes
designs.** OpenTitan's primitives (`prim_count`, `PRIM_FLOP_SPARSE_FSM`,
`sec_anchor_buf`) provide stronger guarantees:

- `prim_count` uses a more complex redundant encoding with parity,
  catching multi-bit faults, not just single-bit
- `PRIM_FLOP_SPARSE_FSM` uses maximal Hamming distance between states
- `sec_anchor_buf` prevents synthesis from optimizing away security
  signals during area/timing optimization

For designs that need formal security certification (Common Criteria,
FIPS 140-3): use OpenTitan's primitives. For designs that need "better
than nothing" protection against the CWEs in this field guide: the plain
versions above are a significant improvement over no protection.
