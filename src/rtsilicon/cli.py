"""rtsilicon CLI — the user interface.

Four commands:
  rt-si check     — plain-English security check (the main command)
  rt-si research  — CWE-anchored detailed analysis
  rt-si scan      — raw scanner output (for scripting)
  rt-si attest    — security attestation + badge for CI
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .scanners import scan as run_scan
from .scanners.patterns import hit_to_candidate
from .models import Finding, FindingStage, Severity, list_all, load, persist
from .models import TAXONOMY_TO_CWE

app = typer.Typer(
    no_args_is_help=True,
    help="rt-si — check your hardware design for security issues.",
    rich_markup_mode="rich",
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        from . import __version__
        console.print(f"rtsilicon {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None, "--version", "-V", help="Show version and exit.",
        callback=_version_callback, is_eager=True,
    ),
) -> None:
    """rt-si — check your hardware design for security issues."""


console = Console()


def _resolve_root(target: str) -> Path:
    return Path(target).resolve()


# ---------------------------------------------------------------------------
# check — plain-English security check (the main command)
# ---------------------------------------------------------------------------


@app.command()
def check(
    target: str = typer.Option(".", "--target", "-t", help="RTL target directory"),
) -> None:
    """Check your hardware design for security issues.

    Plain English output. No CWE jargon. Tells you what's wrong,
    why it matters, and how to fix it.

    \b
    Examples:
      rt-si check
      rt-si check --target ./my_rtl
    """
    from .plain_english import get_plain_finding, format_plain_report

    root = _resolve_root(target)
    if not root.exists():
        console.print(f"[red]target not found:[/red] {root}")
        raise typer.Exit(1)

    hits = run_scan(root)

    plain_findings = []
    for hit in hits:
        cwe_ids = TAXONOMY_TO_CWE.get(hit.taxonomy_class, [])
        primary_cwe = cwe_ids[0] if cwe_ids else "CWE-unknown"
        fname = hit.file.name if hasattr(hit.file, "name") else str(hit.file).split("/")[-1]
        plain = get_plain_finding(hit.rule_id, primary_cwe, fname, hit.line)
        plain_findings.append(plain)

    report = format_plain_report(plain_findings, root.name)
    console.print(report)

    if plain_findings:
        console.print(
            f"\n[dim]Want more detail? Run:[/dim] "
            f"[cyan]rt-si research --target {target}[/cyan] "
            f"[dim]for CWE IDs and field guide links.[/dim]"
        )


# ---------------------------------------------------------------------------
# research — detailed analysis with CWE IDs
# ---------------------------------------------------------------------------


@app.command()
def research(
    target: str = typer.Option(".", "--target", "-t", help="RTL target directory"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="show full notes"),
) -> None:
    """Detailed security analysis with CWE IDs, rule IDs, and field guide links.

    The companion to `rt-si check`. Where `check` shows plain English,
    `research` shows the full picture for security researchers.

    \b
    Examples:
      rt-si research --target ./my_rtl
      rt-si research -t . --verbose
    """
    from .plain_english import get_plain_finding

    root = _resolve_root(target)
    if not root.exists():
        console.print(f"[red]target not found:[/red] {root}")
        raise typer.Exit(1)

    hits = run_scan(root)

    if not hits:
        console.print(f"[green]No security candidates detected in {root.name}.[/green]")
        return

    console.print(f"[bold]rt-si research[/bold] — detailed analysis of {root.name}")
    console.print(
        f"[dim]{len(hits)} candidates across "
        f"{len(set(h.taxonomy_class.value for h in hits))} CWE classes[/dim]\n"
    )

    from collections import defaultdict

    by_cwe: dict[str, list] = defaultdict(list)
    for hit in hits:
        cwe_ids = TAXONOMY_TO_CWE.get(hit.taxonomy_class, [])
        primary_cwe = cwe_ids[0] if cwe_ids else "CWE-unknown"
        by_cwe[primary_cwe].append(hit)

    table = Table(title=f"Security Analysis — {root.name}")
    table.add_column("CWE", style="blue", no_wrap=True)
    table.add_column("Severity", style="yellow")
    table.add_column("Rule", style="cyan")
    table.add_column("Location", style="green")
    table.add_column("Description", overflow="fold")

    for cwe_id, cwe_hits in sorted(by_cwe.items()):
        for hit in cwe_hits[:3]:
            plain = get_plain_finding(
                hit.rule_id,
                cwe_id,
                hit.file.name if hasattr(hit.file, "name") else str(hit.file).split("/")[-1],
                hit.line,
            )
            fname = (
                hit.file.name
                if hasattr(hit.file, "name")
                else str(hit.file).split("/")[-1]
            )
            table.add_row(
                cwe_id,
                f"{plain.severity_icon} {plain.severity_label}",
                hit.rule_id,
                f"{fname}:{hit.line}",
                plain.title,
            )
        if len(cwe_hits) > 3:
            table.add_row("", "", "", "", f"... +{len(cwe_hits) - 3} more")

    console.print(table)

    console.print(f"\n[bold]CWE Summary:[/bold]")
    for cwe_id, cwe_hits in sorted(by_cwe.items()):
        console.print(f"  [blue]{cwe_id}[/blue]: {len(cwe_hits)} candidate(s)")

    if verbose:
        console.print(f"\n[bold]Detailed Notes:[/bold]")
        for hit in hits[:20]:
            fname = (
                hit.file.name
                if hasattr(hit.file, "name")
                else str(hit.file).split("/")[-1]
            )
            console.print(
                f"\n  [cyan]{hit.rule_id}[/cyan] at {fname}:{hit.line}"
            )
            console.print(f"  [dim]Code:[/dim] {hit.snippet}")
            console.print(f"  [dim]Note:[/dim] {hit.note}")

    console.print(
        f"\n[dim]For plain-English output: rt-si check --target {target}[/dim]"
    )
    console.print(
        f"[dim]Field guide: see field-guide/ directory or "
        f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html[/dim]"
    )


# ---------------------------------------------------------------------------
# scan — raw scanner output
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: str = typer.Option(".", "--target", "-t", help="RTL target directory"),
    persist_candidates: bool = typer.Option(
        True, "--persist/--no-persist", help="write candidates to .rtsilicon/findings/"
    ),
) -> None:
    """Raw scanner output. Produces CANDIDATES — hints, not findings."""
    root = _resolve_root(target)
    hits = run_scan(root)

    if not hits:
        console.print("[dim]no scanner hits[/dim]")
        return

    table = Table(title=f"Scanner candidates — {len(hits)} hits (HINTS, not findings)")
    table.add_column("rule", style="cyan")
    table.add_column("CWE", style="blue")
    table.add_column("loc", style="green")
    table.add_column("snippet", overflow="fold")

    for h in hits:
        cwe_ids = TAXONOMY_TO_CWE.get(h.taxonomy_class, [])
        cwe_str = cwe_ids[0] if cwe_ids else "?"
        table.add_row(h.rule_id, cwe_str, f"{h.file.name}:{h.line}", h.snippet[:70])

    console.print(table)

    if persist_candidates:
        existing = {f.id for f in list_all(root)}
        counter = len(existing)
        written = 0
        for h in hits:
            counter += 1
            cand = hit_to_candidate(h, target_id=str(root), counter=counter)
            if cand.id in existing:
                continue
            persist(cand, root)
            written += 1
        console.print(f"[dim]wrote {written} candidates to .rtsilicon/findings/[/dim]")


# ---------------------------------------------------------------------------
# attest — security attestation + badge
# ---------------------------------------------------------------------------


@app.command()
def attest(
    target: str = typer.Option(".", "--target", "-t", help="RTL target directory"),
    name: str = typer.Option("", "--name", "-n", help="design name"),
    output: str = typer.Option("", "--output", "-o", help="output JSON path"),
    badge: bool = typer.Option(True, "--badge/--no-badge", help="print README badge"),
    ci: bool = typer.Option(False, "--ci", help="CI mode: exit 1 if candidates found"),
) -> None:
    """Generate a CWE-anchored security attestation + badge for CI."""
    from . import attest as attest_mod

    root = _resolve_root(target)
    if not root.exists():
        console.print(f"[red]target not found:[/red] {root}")
        raise typer.Exit(1)

    att = attest_mod.attest_target(root, design_name=name or None)

    payload = json.dumps(
        {**att.__dict__, "integrity_hash": att.integrity_hash()},
        indent=2,
    )

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload)
        console.print(f"[green]wrote[/green] {out_path}")
    else:
        console.print_json(payload)

    console.print(f"\n[bold]integrity hash:[/bold] {att.integrity_hash()}")

    if badge:
        console.print("\n[bold]README badge:[/bold]")
        console.print(att.to_badge_markdown())

    if att.cwe_summary:
        table = Table(title=f"CWE summary — {att.total_candidates} candidates")
        table.add_column("CWE", style="magenta")
        table.add_column("count", justify="right")
        for cwe, count in att.cwe_summary.items():
            table.add_row(cwe, str(count))
        console.print(table)

    if ci and att.total_candidates > 0:
        console.print(
            f"\n[yellow]CI mode:[/yellow] {att.total_candidates} candidates found. Exiting 1."
        )
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# demo — quick showcase
# ---------------------------------------------------------------------------


@app.command()
def demo(
    target: str = typer.Option("", "--target", "-t", help="target repo (auto-picks)"),
) -> None:
    """Run rt-si on a target and show headline results."""
    console.print("[bold cyan]rt-si demo[/bold cyan] — open-source silicon security scan")
    console.print("[dim]THE SCANNER IS A HINT, NOT A FINDING.[/dim]\n")

    home = "/Users/johnkearney"
    candidates = [
        Path(home + "/ZCodeProject/silicon-audit/targets/tt07-RO-based-PUF"),
        Path.cwd(),
    ]
    root = Path(target) if target else next((c for c in candidates if c.exists()), Path.cwd())
    console.print(f"[dim]target:[/dim] {str(root)}\n")

    hits = run_scan(root)
    if not hits:
        console.print("[yellow]no candidates[/yellow] — try a target with crypto/DMA/RTL")
        return

    by_class: dict[str, list] = {}
    for h in hits:
        by_class.setdefault(h.taxonomy_class.value, []).append(h)

    table = Table(title=f"Found {len(hits)} candidates across {len(by_class)} classes")
    table.add_column("class", style="magenta")
    table.add_column("hits", justify="right")
    table.add_column("top location", style="green")
    for cls, hs in sorted(by_class.items(), key=lambda x: -len(x[1])):
        top = hs[0]
        fname = top.file.name if hasattr(top.file, "name") else str(top.file).split("/")[-1]
        table.add_row(cls, str(len(hs)), f"{fname}:{top.line}")
    console.print(table)


if __name__ == "__main__":
    app()
