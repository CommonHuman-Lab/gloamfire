# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Gloamfire CLI — entry point and top-level command group."""

from __future__ import annotations

import logging

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from gloamfire import __version__

app = typer.Typer(
    name="gloamfire",
    help="Purple-team attack replay and detection validation platform.",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Sub-command groups
# ---------------------------------------------------------------------------


def _register_commands() -> None:
    from gloamfire.cli.commands.dashboard import app as dashboard_app
    from gloamfire.cli.commands.export import app as export_app
    from gloamfire.cli.commands.labs import app as labs_app
    from gloamfire.cli.commands.list_cmd import app as list_app
    from gloamfire.cli.commands.simulate import app as simulate_app
    from gloamfire.cli.commands.validate import app as validate_app

    app.add_typer(simulate_app, name="simulate")
    app.add_typer(labs_app, name="lab")
    app.add_typer(list_app, name="list")
    app.add_typer(export_app, name="export")
    app.add_typer(validate_app, name="validate")
    app.add_typer(dashboard_app, name="dashboard")


_register_commands()


# ---------------------------------------------------------------------------
# Global options callback
# ---------------------------------------------------------------------------


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    version: bool = typer.Option(False, "--version", help="Show version and exit"),
) -> None:
    if version:
        console.print(f"Gloamfire [bold green]v{__version__}[/bold green]")
        raise typer.Exit()

    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(name)s: %(message)s")


# ---------------------------------------------------------------------------
# Convenience top-level commands
# ---------------------------------------------------------------------------


@app.command("up")
def up_cmd(
    stack: str = typer.Option(
        "all", "--stack", "-s", help="Which stack to start: victims | monitor | all"
    ),
) -> None:
    """Start Docker stacks (default: all)."""
    from gloamfire.cli.commands.labs import start_stack

    start_stack(stack)


@app.command("down")
def down_cmd(
    stack: str = typer.Option(
        "all", "--stack", "-s", help="Which stack to stop: victims | monitor | all"
    ),
) -> None:
    """Stop running Gloamfire containers (default: all)."""
    from gloamfire.cli.commands.labs import stop_stack

    stop_stack(stack)


@app.command("status")
def status_cmd() -> None:
    """Show running Gloamfire containers."""
    from gloamfire.cli.commands.labs import show_status

    show_status()


# ---------------------------------------------------------------------------
# Banner (printed by labs commands, not by default — keeps CLI clean)
# ---------------------------------------------------------------------------


def print_banner() -> None:
    banner = Text()
    banner.append("  ____       __        ____  _\n", style="bold green")
    banner.append(" / __ \\___  / /___    / __ \\(_)__ _\n", style="bold green")
    banner.append("/ /_/ / __// __/ _ \\  / /_/ / / __ `/\n", style="bold green")
    banner.append("\\____/\\___/\\__/\\___/ /_____/_/\\__, /\n", style="bold green")
    banner.append("                             /____/\n", style="bold green")
    console.print(
        Panel(
            banner,
            subtitle=f"[dim]v{__version__} · Purple-team attack replay platform[/dim]",
            border_style="green",
            padding=(0, 2),
        )
    )
