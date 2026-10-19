"""Human-readable terminal output using rich."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from apkguard.baseline import UNCHANGED
from apkguard.model import Severity
from apkguard.scanner import ScanResult

STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_table(
    result: ScanResult,
    console: Console,
    *,
    show_suppressed: bool = False,
    min_severity: Severity = Severity.INFO,
) -> None:
    header = Text.assemble(
        ("APKGuard ", "bold"),
        (result.tool_version, "dim"),
        "  ",
        (result.package or "?", "bold cyan"),
        f"  {result.version_name or ''}  minSdk={result.min_sdk} targetSdk={result.target_sdk}",
    )
    console.print(header)

    shown = [
        f
        for f in result.findings
        if f.severity >= min_severity
        and (show_suppressed or not f.suppressed)
        and not result.is_separated(f)
        and f.baseline_state != UNCHANGED
    ]
    if shown:
        table = Table(show_lines=False, header_style="bold", expand=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Title")
        table.add_column("Location", overflow="fold")
        table.add_column("Details", overflow="fold")
        for f in shown:
            sev = Text(f.severity.label.upper(), style=STYLES[f.severity])
            if f.suppressed:
                sev.append(" (suppressed)", style="dim")
            if f.library:
                sev.append(f" [{f.library}]", style="dim")
            table.add_row(sev, f.rule_id, f.title, str(f.location), f.message)
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")

    counts = result.counts()
    parts = [
        f"[{STYLES[Severity.parse(label)]}]{label}: {n}[/]" for label, n in counts.items() if n
    ]
    suppressed = len(result.findings) - len(result.active_findings)
    summary = ", ".join(parts) if parts else "0 findings"
    if suppressed:
        summary += f" [dim](+{suppressed} suppressed)[/dim]"
    console.print(f"Summary: {summary}  [dim]({result.duration_s:.2f}s)[/dim]")
    _print_library_note(result, console)
    _print_baseline_note(result, console)
    for err in result.errors:
        console.print(f"[red]Rule {err.rule_id} failed:[/red] {err.error}")


def _print_library_note(result: ScanResult, console: Console) -> None:
    by_library = result.library_counts()
    if not by_library:
        return
    top = ", ".join(f"{lib} {n}" for lib, n in list(by_library.items())[:5])
    console.print(
        f"[dim]Not shown: {sum(by_library.values())} finding(s) in third-party libraries "
        f"({top}). They do not affect the exit code; use --library-findings include to "
        "list them.[/dim]"
    )


def _print_baseline_note(result: ScanResult, console: Console) -> None:
    comparison = result.baseline
    if comparison is None:
        return
    console.print(
        f"Baseline: [bold]{comparison.new} new[/bold], {comparison.unchanged} unchanged "
        f"(not shown, do not affect the exit code), {comparison.absent} no longer present."
    )
