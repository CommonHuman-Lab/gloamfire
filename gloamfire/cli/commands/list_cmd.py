# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""gloamfire list — show available scenarios and attack plugins."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="List available scenarios and attack plugins.", no_args_is_help=True)
console = Console()


@app.command("scenarios")
def list_scenarios(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show MITRE mappings"),
) -> None:
    """List all available attack scenarios."""
    from gloamfire.core.executor import ScenarioExecutor

    executor = ScenarioExecutor.__new__(ScenarioExecutor)
    from gloamfire.core.executor import _BUILTIN_SCENARIOS

    executor._scenarios_dir = _BUILTIN_SCENARIOS

    paths = executor.list_scenarios()
    if not paths:
        console.print("[dim]No scenarios found.[/dim]")
        return

    table = Table(
        title="Available Scenarios",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("Name", style="bold green", no_wrap=True)
    table.add_column("Description")
    table.add_column("Tags", style="dim")
    if verbose:
        table.add_column("MITRE", style="yellow")

    for path in paths:
        try:
            import yaml

            raw = yaml.safe_load(path.read_text())
            from gloamfire.core.models import Scenario

            s = Scenario.model_validate(raw)
            row = [
                s.name,
                s.description,
                ", ".join(s.tags) or "—",
            ]
            if verbose:
                row.append(", ".join(s.mitre))
            table.add_row(*row)
        except Exception:
            table.add_row(path.stem, "[red]Failed to load[/red]", "")

    console.print(table)
    console.print(
        f"\nRun a scenario: [bold green]gloamfire simulate run <name>[/bold green]"
    )


@app.command("attacks")
def list_attacks() -> None:
    """List all registered attack plugins."""
    from gloamfire.core.registry import all_attacks, load_builtin_attacks

    load_builtin_attacks()
    plugins = all_attacks()

    table = Table(
        title="Attack Plugins",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Plugin Key", style="bold green", no_wrap=True)
    table.add_column("Description")
    table.add_column("MITRE", style="yellow")

    for name, cls in sorted(plugins.items()):
        table.add_row(
            name,
            cls.description,
            ", ".join(cls.mitre) or "—",
        )
    console.print(table)
