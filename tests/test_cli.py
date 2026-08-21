"""End-to-end CLI tests — invoke rt-si as a subprocess."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
import shutil
_rt_si = shutil.which("rt-si") or str(REPO / ".venv" / "bin" / "rt-si")
RT_SI = [_rt_si]


def run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    return subprocess.run(
        RT_SI + args, capture_output=True, text=True, cwd=cwd, env=env, timeout=30
    )


def test_help_exits_zero():
    r = run(["--help"])
    assert r.returncode == 0
    assert "hardware" in r.stdout.lower()


def test_version_flag():
    r = run(["--version"])
    assert r.returncode == 0
    assert "rtsilicon" in r.stdout


def test_no_args_shows_help():
    r = run([])
    assert r.returncode != 0


def test_scan_runs_without_recursion(tmp_path):
    (tmp_path / "x.v").write_text(
        "module x(input clk);\n  reg [15:0] ctr;\n"
        "  always @(posedge clk) ctr <= ctr + 1;\nendmodule\n"
    )
    r = run(["scan", "--target", str(tmp_path), "--no-persist"])
    assert r.returncode == 0
    assert "recursion" not in (r.stdout + r.stderr).lower()


def test_scan_persists_candidates(tmp_path):
    (tmp_path / "x.v").write_text(
        "module x(input clk);\n  reg [15:0] round_ctr;\n"
        "  always @(posedge clk) round_ctr <= round_ctr + 1;\nendmodule\n"
    )
    r = run(["scan", "--target", str(tmp_path)])
    assert r.returncode == 0
    jsons = list((tmp_path / ".rtsilicon" / "findings").glob("*.json"))
    assert len(jsons) >= 1


def test_check_runs(tmp_path):
    (tmp_path / "x.v").write_text(
        "module x(input clk);\n  reg [15:0] round_ctr;\n"
        "  always @(posedge clk) round_ctr <= round_ctr + 1;\nendmodule\n"
    )
    r = run(["check", "--target", str(tmp_path)])
    assert "traceback" not in (r.stdout + r.stderr).lower()
    assert "Counter" in r.stdout or "counter" in r.stdout.lower()


def test_research_runs(tmp_path):
    (tmp_path / "x.v").write_text(
        "module x(input clk);\n  reg [15:0] round_ctr;\n"
        "  always @(posedge clk) round_ctr <= round_ctr + 1;\nendmodule\n"
    )
    r = run(["research", "--target", str(tmp_path)])
    assert "CWE" in r.stdout or "no security candidates" in r.stdout.lower()


def test_check_clean_design(tmp_path):
    (tmp_path / "x.v").write_text(
        "module blinker(input clk, output reg led);\n"
        "  always @(posedge clk) led <= ~led;\nendmodule\n"
    )
    r = run(["check", "--target", str(tmp_path)])
    assert "0 issues" in r.stdout or "All clear" in r.stdout
