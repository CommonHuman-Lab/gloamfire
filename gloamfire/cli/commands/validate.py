# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""gloamfire validate — validate detection backends and stored telemetry."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Validate detections and backend connectivity.", no_args_is_help=True)
console = Console()
err = Console(stderr=True)


@app.command("backends")
def validate_backends() -> None:
    """Check connectivity to Wazuh and Suricata detection backends."""
    from gloamfire.detections.suricata import SuricataCollector
    from gloamfire.detections.wazuh import WazuhCollector

    table = Table(title="Detection Backends", show_header=True, header_style="bold cyan")
    table.add_column("Backend", style="bold")
    table.add_column("Status")
    table.add_column("Detail", style="dim")

    suricata = SuricataCollector()
    backends = [
        ("Wazuh", WazuhCollector(), "https://localhost:55000"),
        ("Suricata", suricata, str(suricata._eve)),
    ]

    for name, collector, endpoint in backends:
        ok = collector.is_available()
        status = "[green]AVAILABLE[/green]" if ok else "[red]UNAVAILABLE[/red]"
        table.add_row(name, status, endpoint)

    console.print(table)
    console.print(
        "\n[dim]Start the monitor stack with: [bold]gloamfire lab up monitor[/bold][/dim]"
    )


@app.command("telemetry")
def validate_telemetry(
    path: Path = typer.Argument(
        Path("gloamfire_telemetry.jsonl"),
        help="Path to JSONL telemetry file",
    ),
) -> None:
    """Parse and summarise a recorded telemetry file."""
    from gloamfire.telemetry.collector import TelemetryCollector

    results = TelemetryCollector.load_from_jsonl(path)
    if not results:
        err.print(f"[bold red]No results found in[/bold red] {path}")
        raise typer.Exit(1)

    table = Table(title=f"Telemetry: {path}", show_header=True, header_style="bold cyan")
    table.add_column("Scenario", style="bold")
    table.add_column("Events", justify="right")
    table.add_column("Pass", style="green", justify="right")
    table.add_column("Fail", style="red", justify="right")
    table.add_column("Duration", justify="right")
    table.add_column("Overall")

    for r in results:
        overall = "[green]PASS[/green]" if r.overall_pass else "[red]FAIL[/red]"
        table.add_row(
            r.scenario,
            str(len(r.events)),
            str(r.passed),
            str(r.failed),
            f"{r.duration_s:.1f}s",
            overall,
        )
    console.print(table)
