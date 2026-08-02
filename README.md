# rtsilicon

Check your hardware design for security issues. Plain English. No PhD required.

```bash
pip install rtsilicon
cd my_design
rt-si check
```

## What it does

Scans your Verilog, SystemVerilog, VHDL, and Chisel/Migen source for 25 MITRE CWE classes of hardware security defects. Tells you what's wrong, why it matters, and how to fix it — in plain English.

```
$ rt-si check --target ./my_design

🔍 Scanned my_design ...

🔴 HIGH: DMA can access any memory address
   📍 dma.v:42
   💡 The DMA controller's address comes from a software-writable
      register with no address-range check...
   🔧 Add an address-range check: define allowed base and limit.

🟡 MEDIUM: Counter vulnerable to glitching
   📍 aes_core.v:23
   💡 A voltage spike can flip a bit in this counter...
   🔧 Replace the plain counter with a redundant encoding.

📊 Summary: 1 high, 1 medium
```

## Commands

| Command | What it does |
|---------|-------------|
| `rt-si check` | Plain-English security check (the main command) |
| `rt-si research` | Detailed analysis with CWE IDs and field guide links |
| `rt-si scan` | Raw scanner output (JSON-able, for scripting) |
| `rt-si attest` | Generate a security attestation + badge for CI |

## What it detects

25 MITRE CWE classes including:

- **CWE-125**: Unsigned length/count underflow (the most common class in OSS HW)
- **CWE-1190**: DMA without address-range enforcement
- **CWE-1191**: Debug interface accessible without authentication
- **CWE-1247**: Glitch-vulnerable plain counters on security paths
- **CWE-1233**: Security registers writable mid-operation
- **CWE-1300**: Unmasked crypto (side-channel vulnerable)
- **CWE-1335**: FSM states without escape conditions (DoS)
- **CWE-362**: NBA race conditions (signal assigned twice, last wins)

Full list: run `rt-si research` or read the [field guide](field-guide/).

## Supported HDLs

- ✅ Verilog (`.v`)
- ✅ SystemVerilog (`.sv`)
- ✅ VHDL (`.vhd`, `.vhdl`)
- ✅ Chisel/Migen (`.scala`, `.py`)

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/rt-si check --target .
```

## CI integration

### GitHub Actions
Add to `.github/workflows/security.yml`:
```yaml
uses: john-kearney/rtsilicon@v1
with:
  target: ./src
```

### pre-commit hook
Add to your `.pre-commit-config.yaml`:
```yaml
- repo: https://github.com/john-kearney/rtsilicon
  rev: v0.3
  hooks:
    - id: rt-si-check
      args: ["--target", "src"]
```

Runs on every commit. Catches security issues before they ship.

## Field guide

The [field guide](field-guide/) explains each CWE class in plain language:
- What the vulnerability looks like in RTL
- How to check for it (manual review + scanner)
- How to fix it (plain Verilog/VHDL, no OpenTitan primitives needed)

## Precision

Measured against a labeled benchmark: **precision 92.3%, recall 100%**.

## Contributing

Found a bug? Want to add a detection rule? See the [field guide](field-guide/README.md) for the rule format and the CWE mapping. PRs welcome.

## License

MIT
