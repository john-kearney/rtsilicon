"""Precision/recall benchmark for the rtsilicon scanner.

Synthesizes a labeled dataset of RTL snippets — each hand-labeled as
"contains a real CWE pattern" (positive) or "clean / false-positive bait"
(negative) — and measures:
  - precision: of all scanner hits, how many are on positive samples?
  - recall: of all positive samples, how many did the scanner catch?
  - false-positive rate: how many negative samples produced hits?

This is the measurement that was missing. The scanner's precision/recall
is now a known quantity, not a guess.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rtsilicon.scanners import scan


# ---------------------------------------------------------------------------
# Labeled dataset — hand-written, each with known ground truth.
# ---------------------------------------------------------------------------

# POSITIVES: each snippet contains a genuine instance of the CWE pattern.
POSITIVES = {
    "B1_reset_x": """
        module arbiter(input clk, input rst);
            reg marked_1, marked_2;
            always @(posedge clk) begin
                if ((marked_1 == 'x && marked_2 == 'x) || rst) begin
                    marked_1 <= 0; marked_2 <= 0;
                end
            end
        endmodule
    """,
    "B4_round_counter": """
        module aes_core(input clk);
            reg [15:0] round_ctr;
            always @(posedge clk) round_ctr <= round_ctr + 1;
        endmodule
    """,
    "B4_attempt_counter": """
        module auth(input clk);
            reg [7:0] login_attempts;
            always @(posedge clk) login_attempts <= login_attempts + 1;
        endmodule
    """,
    "C1_sbox_lut": """
        module aes_sbox(input [7:0] din, output [7:0] dout);
            assign dout = sbox[din];
            function [7:0] sbox;
                input [7:0] idx;
                // plain lookup — no masking
                case (idx)
                    8'h00: sbox = 8'h63;
                    // ... 255 more entries
                    default: sbox = 8'h00;
                endcase
            endfunction
        endmodule
    """,
    "D1_debug_enable": """
        module debug_ctrl(input clk, input debug_en, output reg dbg_active);
            always @(posedge clk)
                if (debug_en) dbg_active <= 1;
        endmodule
    """,
    "D2_dma_addr_csr": """
        module dma_reader(input clk, output reg [31:0] araddr);
            reg [31:0] start_addr;
            always @(posedge clk)
                araddr <= start_addr;
        endmodule
    """,
    "E1_magic_constant": """
        module trojan_trigger(input [31:0] data, output reg trigger);
            always @(*)
                if (data == 32'hDEADBEEF) trigger = 1;
                else trigger = 0;
        endmodule
    """,
    "CWE1239_secret_no_zeroize": """
        module key_store(input clk, input [255:0] key_in);
            reg [255:0] aes_key;
            always @(posedge clk) aes_key <= key_in;
        endmodule
    """,
    "CWE1255_comparison_early_exit": """
        module pin_check(input [127:0] pin, input [127:0] stored_pin);
            integer i;
            always @(posedge clk) begin
                for (i=0; i<4; i=i+1)
                    if (pin[i*32+:32] != stored_pin[i*32+:32]) disable;
            end
        endmodule
    """,
    "CWE1271_sec_reg_no_reset": """
        module sec_ctrl(input clk);
            reg debug_lock;
            always @(posedge clk) debug_lock <= 1;
        endmodule
    """,
    "VHDL_dma_addr": """
        library ieee;
        use ieee.std_logic_1164.all;
        entity dma_engine is
            port (clk : in std_logic;
                  addr : out std_logic_vector(31 downto 0));
        end entity;
        architecture rtl of dma_engine is
            signal src_addr : std_logic_vector(31 downto 0);
        begin
            addr <= src_addr;
        end architecture;
    """,
    "VHDL_plain_counter": """
        library ieee;
        use ieee.numeric_std.all;
        entity counter is
            port (clk : in std_logic);
        end entity;
        architecture rtl of counter is
            signal round_ctr : unsigned(15 downto 0);
        begin
            process(clk)
            begin
                if rising_edge(clk) then
                    round_ctr <= round_ctr + 1;
                end if;
            end process;
        end architecture;
    """,
}

# NEGATIVES: each snippet is clean RTL that SHOULD NOT produce hits.
# These are the "false-positive bait" — patterns that look superficially
# similar to vulnerable code but are benign.
NEGATIVES = {
    "clean_blinker": """
        module blinker(input clk, output reg led);
            always @(posedge clk) led <= ~led;
        endmodule
    """,
    "clean_adder": """
        module adder(input [31:0] a, input [31:0] b, output [31:0] sum);
            assign sum = a + b;
        endmodule
    """,
    "clean_mux": """
        module mux2(input [31:0] a, input [31:0] b, input sel, output [31:0] y);
            assign y = sel ? b : a;
        endmodule
    """,
    "clean_counter_not_security": """
        module pixel_counter(input clk, output reg [9:0] hcount);
            always @(posedge clk) hcount <= hcount + 1;
        endmodule
    """,
    "clean_data_reg": """
        module pipeline_reg(input clk, input [31:0] din, output reg [31:0] dout);
            always @(posedge clk) dout <= din;
        endmodule
    """,
    "clean_rom": """
        module boot_rom(input [7:0] addr, output [31:0] data);
            always @(*)
                case (addr)
                    8'h00: data = 32'h00000013;  // NOP
                    default: data = 32'h00000013;
                endcase
        endmodule
    """,
    "clean_crc": """
        module crc_check(input [15:0] data, output reg ok);
            wire [15:0] crc;
            assign crc = data ^ 16'h8005;  // CRC polynomial — NOT a trojan trigger
            always @(*) ok = (crc == 16'h0000);
        endmodule
    """,
}


def _scan_snippet(name: str, code: str) -> list:
    """Scan a single snippet in a temp dir. Uses .vhd for VHDL samples."""
    ext = ".vhd" if name.startswith("VHDL") else ".v"
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / f"{name}{ext}"
        p.write_text(code.strip())
        return scan(p.parent)


def _measure():
    """Run the full precision/recall measurement."""
    # Scan all positives
    tp = 0  # true positives (hits on positive samples)
    fn = 0  # false negatives (positive samples with no hit)
    for name, code in POSITIVES.items():
        hits = _scan_snippet(name, code)
        if hits:
            tp += 1
        else:
            fn += 1

    # Scan all negatives
    fp = 0  # false positives (hits on negative samples)
    tn = 0  # true negatives (negative samples with no hit)
    for name, code in NEGATIVES.items():
        hits = _scan_snippet(name, code)
        if hits:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fp_rate,
    }


# ---------------------------------------------------------------------------
# Tests that report the numbers (and fail if below thresholds)
# ---------------------------------------------------------------------------


def test_precision_benchmark_reports_numbers():
    """Run the benchmark and print the results. This is the measurement."""
    results = _measure()
    print("\n===== PRECISION/RECALL BENCHMARK =====")
    print(f"  Dataset: {len(POSITIVES)} positives, {len(NEGATIVES)} negatives")
    print(f"  True positives:  {results['true_positives']}")
    print(f"  False negatives: {results['false_negatives']}")
    print(f"  False positives: {results['false_positives']}")
    print(f"  True negatives:  {results['true_negatives']}")
    print(f"  PRECISION:       {results['precision']:.1%}")
    print(f"  RECALL:          {results['recall']:.1%}")
    print(f"  FALSE-POS RATE:  {results['false_positive_rate']:.1%}")
    print("======================================\n")


def test_precision_above_threshold():
    """Precision must be > 50% — more than half of hits must be real.
    If this fails, the scanner is producing more noise than signal."""
    results = _measure()
    assert results["precision"] > 0.5, (
        f"Precision {results['precision']:.1%} is below 50% threshold. "
        f"Too many false positives."
    )


def test_false_positive_rate_below_threshold():
    """False-positive rate must be < 30% — fewer than a third of clean
    samples should produce hits. If this fails, the rules are too loose."""
    results = _measure()
    assert results["false_positive_rate"] < 0.3, (
        f"FP rate {results['false_positive_rate']:.1%} is above 30% threshold."
    )


def test_recall_on_core_classes():
    """The scanner must catch at least 5 of the 7 positive classes (the
    core CWE patterns). If this fails, the scanner has blind spots."""
    results = _measure()
    assert results["recall"] >= 5 / 7, (
        f"Recall {results['recall']:.1%} — scanner is missing core CWE patterns."
    )
