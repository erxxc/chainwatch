"""
chainwatch.output
~~~~~~~~~~~~~~~~~

Renders ``RiskReport`` objects to either:

  - A colour-coded Rich terminal table (human mode, default)
  - Machine-readable newline-delimited JSON / ndjson (``--json`` flag)

Design notes:
- This module has no knowledge of how a report was produced — it only knows
  how to render one.  The CLI passes the RiskReport in; the renderer puts it out.
- Severity colours match the design system used in the sprint plan UI so the
  terminal output is visually consistent with any future web frontend.
- Rich Console is created here as a module-level singleton so tests can capture
  it by replacing ``_console``.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from chainwatch.models import FeedResult, FeedStatus, RiskDimension, RiskReport, Severity

# Module-level console — replace in tests to capture output
_console = Console(stderr=False)

# ── Severity colour map ───────────────────────────────────────────────────────

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.LOW:      "bold green",
    Severity.MEDIUM:   "bold yellow",
    Severity.HIGH:     "bold red",
    Severity.CRITICAL: "bold white on red",
}

_FEED_STATUS_STYLE: dict[FeedStatus, str] = {
    FeedStatus.clean:      "green",
    FeedStatus.suspicious: "yellow",
    FeedStatus.malicious:  "bold red",
    FeedStatus.no_data:    "dim",
}

_FEED_STATUS_ICON: dict[FeedStatus, str] = {
    FeedStatus.clean:      "✓",
    FeedStatus.suspicious: "⚠",
    FeedStatus.malicious:  "✗",
    FeedStatus.no_data:    "–",
}


# ── Public API ────────────────────────────────────────────────────────────────


def emit_report(
    report: RiskReport,
    *,
    json_mode: bool = False,
    output_file: Path | None = None,
) -> None:
    """
    Render a RiskReport to stdout (or ``output_file`` if provided).

    Args:
        report:      The completed risk report.
        json_mode:   If True, emit compact ndjson instead of Rich terminal output.
        output_file: If provided, write to this path instead of stdout.
    """
    if json_mode:
        _emit_json(report, output_file=output_file)
    else:
        _emit_rich(report, output_file=output_file)


def emit_error(message: str, *, json_mode: bool = False) -> None:
    """Render a top-level error (feed failure, API error, etc.)."""
    if json_mode:
        payload = {"error": message, "timestamp": datetime.utcnow().isoformat() + "Z"}
        _write_text(json.dumps(payload) + "\n", output_file=None)
    else:
        _console.print(f"[bold red]ERROR[/bold red] {message}", file=sys.stderr)


# ── JSON emitter ──────────────────────────────────────────────────────────────


def _emit_json(report: RiskReport, *, output_file: Path | None) -> None:
    """
    Emit the report as a single JSON line (ndjson-compatible).

    ``model_dump_json`` uses pydantic's serialiser which handles datetime,
    Enum, and SecretStr correctly without a custom encoder.
    """
    line = report.model_dump_json(indent=None) + "\n"
    _write_text(line, output_file=output_file)


# ── Rich terminal renderer ────────────────────────────────────────────────────


def _emit_rich(report: RiskReport, *, output_file: Path | None) -> None:
    """
    Render a full-colour terminal report.

    Layout:
      1. Header panel  — package identity + composite score + severity
      2. Dimensions table — per-dimension LLM scores and reasoning
      3. Feed results table — OSV / Rekor / Scorecard status
      4. Summary block — LLM free-text explanation
      5. Provenance footnote — model, timestamp, SHA256s
    """
    console = _get_console(output_file)

    sev_style = _SEVERITY_STYLE[report.severity]

    # ── 1. Header ─────────────────────────────────────────────────────────────
    score_bar = _score_bar(report.risk_score)
    header_text = Text()
    header_text.append(f"{report.ecosystem.value}  ", style="dim")
    header_text.append(report.package, style="bold white")
    header_text.append(f"  {report.from_version}", style="dim")
    header_text.append("  →  ", style="dim")
    header_text.append(report.to_version, style="bold cyan")
    header_text.append(f"\n\n{score_bar}\n")
    header_text.append(f"Risk Score  ", style="dim")
    header_text.append(f"{report.risk_score:.1f} / 100", style="bold white")
    header_text.append(f"    Severity  ", style="dim")
    header_text.append(report.severity.value, style=sev_style)

    if report.confirmed_malicious_by_feed():
        header_text.append("\n\n⚠  CONFIRMED MALICIOUS BY THREAT FEED", style="bold red")
    if report.has_mal_advisory():
        header_text.append("\n   OSV MAL-* advisory present", style="red")

    console.print(
        Panel(
            header_text,
            title="[bold]chainwatch[/bold] · diff analysis",
            border_style=sev_style,
            padding=(1, 2),
        )
    )
    console.print()

    # ── 2. Risk Dimensions ────────────────────────────────────────────────────
    dim_table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        pad_edge=False,
    )
    dim_table.add_column("Dimension", style="white", min_width=20)
    dim_table.add_column("Score", justify="center", min_width=7)
    dim_table.add_column("Weight", justify="center", min_width=7)
    dim_table.add_column("Contribution", justify="center", min_width=12)
    dim_table.add_column("Reasoning", style="dim", min_width=40, max_width=60)

    for dim in report.dimensions:
        score_style = _dim_score_style(dim.score)
        dim_table.add_row(
            dim.label,
            Text(f"{dim.score:.1f}", style=score_style),
            f"{dim.weight * 100:.0f}%",
            f"{dim.weighted_contribution:.1f}",
            dim.reasoning,
        )

    console.print("[bold dim]RISK DIMENSIONS[/bold dim]")
    console.print(dim_table)
    console.print()

    # ── 3. Feed Results ───────────────────────────────────────────────────────
    feed_table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        pad_edge=False,
    )
    feed_table.add_column("Feed", min_width=12)
    feed_table.add_column("Status", justify="center", min_width=12)
    feed_table.add_column("Details", style="dim", min_width=40)
    feed_table.add_column("URL", style="dim cyan", min_width=20)

    for feed in report.feed_results:
        status_style = _FEED_STATUS_STYLE[feed.status]
        icon = _FEED_STATUS_ICON[feed.status]
        feed_table.add_row(
            feed.source.upper(),
            Text(f"{icon}  {feed.status.value}", style=status_style),
            feed.details,
            feed.url or "—",
        )

    console.print("[bold dim]THREAT FEED RESULTS[/bold dim]")
    console.print(feed_table)
    console.print()

    # ── 4. LLM Summary ───────────────────────────────────────────────────────
    console.print("[bold dim]LLM ASSESSMENT[/bold dim]")
    console.print(
        Panel(
            report.llm_summary,
            border_style="dim",
            padding=(0, 1),
        )
    )
    console.print()

    # ── 5. Diff Summary ───────────────────────────────────────────────────────
    ds = report.diff_summary
    diff_parts = []
    if ds.files_added:
        diff_parts.append(f"[green]+{len(ds.files_added)} added[/green]")
    if ds.files_removed:
        diff_parts.append(f"[red]-{len(ds.files_removed)} removed[/red]")
    if ds.files_modified:
        diff_parts.append(f"[yellow]~{len(ds.files_modified)} modified[/yellow]")
    if ds.new_dependencies:
        diff_parts.append(f"[cyan]+{len(ds.new_dependencies)} new deps[/cyan]")
    if ds.new_install_hooks:
        diff_parts.append(f"[red]install hooks: {', '.join(ds.new_install_hooks)}[/red]")
    if ds.diff_truncated:
        diff_parts.append("[dim](diff truncated — token budget)[/dim]")

    console.print("[bold dim]DIFF SUMMARY[/bold dim]  " + "  ·  ".join(diff_parts))
    console.print()

    # ── 6. Provenance ─────────────────────────────────────────────────────────
    ts = report.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    prov = (
        f"[dim]model: {report.llm_model}  ·  "
        f"schema: v{report.schema_version}  ·  "
        f"generated: {ts}[/dim]"
    )
    if report.to_version_sha256:
        prov += f"\n[dim]to_version sha256: {report.to_version_sha256}[/dim]"
    console.print(prov)
    console.print()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _score_bar(score: float, width: int = 40) -> str:
    """ASCII progress bar representing the 0-100 risk score."""
    filled = int(round(score / 100 * width))
    bar = "█" * filled + "░" * (width - filled)
    # Colour the bar according to severity thresholds
    if score >= 80:
        style_open, style_close = "[bold red]", "[/bold red]"
    elif score >= 55:
        style_open, style_close = "[red]", "[/red]"
    elif score >= 30:
        style_open, style_close = "[yellow]", "[/yellow]"
    else:
        style_open, style_close = "[green]", "[/green]"
    return f"{style_open}{bar}{style_close}"


def _dim_score_style(score: float) -> str:
    if score >= 8:
        return "bold red"
    if score >= 5:
        return "yellow"
    if score >= 3:
        return "dim yellow"
    return "green"


def _get_console(output_file: Path | None) -> Console:
    """Return the module console, or a file-writing console if output_file is set."""
    if output_file is None:
        return _console
    # Rich can write to a file — force no colour codes in file output
    fh: TextIO = open(output_file, "w", encoding="utf-8")  # noqa: SIM115
    return Console(file=fh, highlight=False, markup=True)


def _write_text(text: str, *, output_file: Path | None) -> None:
    if output_file is None:
        sys.stdout.write(text)
    else:
        output_file.write_text(text, encoding="utf-8")
