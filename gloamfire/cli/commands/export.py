# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""gloamfire export — export telemetry artefacts."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Export telemetry and MITRE ATT&CK mappings.", no_args_is_help=True)
console = Console()
err = Console(stderr=True)


@app.command("timeline")
def export_timeline(
    telemetry: Path = typer.Option(
        Path("gloamfire_telemetry.jsonl"),
        "--telemetry", "-t",
        help="Source JSONL telemetry file",
    ),
    output: Path = typer.Option(
        Path("timeline.json"),
        "--output", "-o",
        help="Output timeline JSON file",
    ),
) -> None:
    """Export a chronological event timeline from recorded telemetry."""
    from gloamfire.telemetry.collector import TelemetryCollector
    from gloamfire.telemetry.exporter import ResultExporter

    results = TelemetryCollector.load_from_jsonl(telemetry)
    if not results:
        err.print(f"[bold red]No telemetry found in[/bold red] {telemetry}")
        raise typer.Exit(1)

    all_events: list[dict] = []
    for r in results:
        all_events.extend(ResultExporter(r).to_timeline())

    all_events.sort(key=lambda e: e["timestamp"])
    output.write_text(json.dumps(all_events, indent=2))
    console.print(f"[green][+][/green] Timeline written to [bold]{output}[/bold] ({len(all_events)} events)")


@app.command("mitre")
def export_mitre(
    telemetry: Path = typer.Option(
        Path("gloamfire_telemetry.jsonl"),
        "--telemetry", "-t",
    ),
    output: Path = typer.Option(
        Path("mitre_map.json"),
        "--output", "-o",
    ),
) -> None:
    """Export a MITRE ATT&CK technique map from recorded telemetry."""
    from gloamfire.telemetry.collector import TelemetryCollector
    from gloamfire.telemetry.exporter import ResultExporter

    results = TelemetryCollector.load_from_jsonl(telemetry)
    if not results:
        err.print(f"[bold red]No telemetry found in[/bold red] {telemetry}")
        raise typer.Exit(1)

    all_techniques: list[dict] = []
    seen: set[str] = set()
    for r in results:
        for t in ResultExporter(r).to_mitre_map():
            if t["technique_id"] not in seen:
                seen.add(t["technique_id"])
                all_techniques.append(t)

    output.write_text(json.dumps(all_techniques, indent=2))

    table = Table(title="MITRE ATT&CK Coverage", show_header=True, header_style="bold cyan")
    table.add_column("Technique ID", style="yellow", no_wrap=True)
    table.add_column("Name")
    table.add_column("Tactic")

    for t in all_techniques:
        table.add_row(t["technique_id"], t["technique_name"], t["tactic"])

    console.print(table)
    console.print(f"\n[green][+][/green] Map written to [bold]{output}[/bold]")
