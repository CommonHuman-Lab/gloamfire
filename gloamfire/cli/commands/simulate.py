# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""gloamfire simulate — run attack scenarios against victim containers."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from gloamfire.core.exceptions import (
    AttackNotFoundError,
    ContainerNotFoundError,
    DockerUnavailableError,
    ExecutionError,
    ScenarioNotFoundError,
    ScenarioValidationError,
)
from gloamfire.core.models import DetectionResult

app = typer.Typer(help="Execute attack simulation scenarios.", no_args_is_help=True)
console = Console()
err = Console(stderr=True)


def _status_icon(status: str) -> Text:
    icons = {
        "pass": Text("[PASS]", style="bold green"),
        "fail": Text("[FAIL]", style="bold red"),
        "skip": Text("[SKIP]", style="bold yellow"),
        "error": Text("[ERR] ", style="bold magenta"),
    }
    return icons.get(status, Text(f"[{status}]"))


def _print_detection_results(results: list[DetectionResult]) -> None:
    if not results:
        console.print("[dim]No detection expectations configured for this scenario.[/dim]")
        return

    table = Table(title="Detection Results", show_header=True, header_style="bold cyan")
    table.add_column("Status", width=8)
    table.add_column("Source", width=10)
    table.add_column("Rule", width=14)
    table.add_column("Description")
    table.add_column("Detail", style="dim")

    for r in results:
        table.add_row(
            _status_icon(r.status),
            r.expectation.source,
            r.expectation.rule_id or "—",
            r.expectation.description,
            r.detail,
        )
    console.print(table)


@app.command(name="run")
def run_scenario(
    scenario: str = typer.Argument(help="Scenario name or path to .yaml file"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Preview without executing"),
    scenarios_dir: Path = typer.Option(
        None, "--scenarios-dir", "-d", help="Custom scenarios directory"
    ),
    no_validate: bool = typer.Option(
        False, "--no-validate", help="Skip detection validation"
    ),
    export: Path = typer.Option(None, "--export", "-e", help="Export artefacts to directory"),
) -> None:
    """
    Execute a named scenario against victim containers.

    Examples:

        gloamfire simulate run suspicious-curl
        gloamfire simulate run reverse-shell --dry-run
        gloamfire simulate run fake-ransomware --export ./output
    """
    from gloamfire.core.docker_client import DockerClient
    from gloamfire.core.executor import ScenarioExecutor
    from gloamfire.detections.validator import DetectionValidator
    from gloamfire.telemetry.exporter import ResultExporter

    try:
        docker_client = DockerClient()
    except DockerUnavailableError as exc:
        err.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1)

    validator = DetectionValidator() if not no_validate else None
    executor = ScenarioExecutor(
        docker_client=docker_client,
        scenarios_dir=scenarios_dir,
        detection_validator=validator,
        dry_run=dry_run,
    )

    scenario_name = scenario.replace("-", "_")

    console.print()
    if dry_run:
        console.print(
            Panel(
                f"[bold yellow]DRY RUN[/bold yellow] — scenario: [bold]{scenario_name}[/bold]",
                border_style="yellow",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold green]Running[/bold green] scenario: [bold]{scenario_name}[/bold]",
                border_style="green",
            )
        )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Executing [bold]{scenario_name}[/bold]…", total=None)

        try:
            result = executor.run(scenario_name)
        except ScenarioNotFoundError as exc:
            err.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)
        except ScenarioValidationError as exc:
            err.print(f"[bold red]Invalid scenario:[/bold red] {exc}")
            raise typer.Exit(1)
        except ContainerNotFoundError as exc:
            err.print(f"[bold red]Container missing:[/bold red] {exc}")
            err.print("[dim]Run [bold]gloamfire up[/bold] first.[/dim]")
            raise typer.Exit(1)
        except AttackNotFoundError as exc:
            err.print(f"[bold red]Plugin error:[/bold red] {exc}")
            raise typer.Exit(1)
        except ExecutionError as exc:
            err.print(f"[bold red]Execution failed:[/bold red] {exc}")
            raise typer.Exit(1)

        progress.update(task, description="Done")

    # Summary
    console.print()
    console.print(
        f"Completed [bold]{result.scenario}[/bold] in "
        f"[cyan]{result.duration_s:.1f}s[/cyan] — "
        f"[green]{len(result.events)} events[/green]"
    )

    if result.detections:
        console.print()
        _print_detection_results(result.detections)
        console.print()
        if result.overall_pass:
            console.print("[bold green]Overall: PASS[/bold green]")
        else:
            console.print("[bold red]Overall: FAIL[/bold red]")

    if export:
        exporter = ResultExporter(result)
        paths = exporter.write_report(export)
        console.print()
        console.print("[bold]Exported artefacts:[/bold]")
        for label, path in paths.items():
            console.print(f"  [cyan]{label:<10}[/cyan] {path}")

    if not result.overall_pass and result.detections:
        raise typer.Exit(2)


# Allow `gloamfire simulate <name>` as shorthand for `gloamfire simulate run <name>`
@app.command(name="reverse-shell")
def _sim_reverse_shell(
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
) -> None:
    """Shorthand: simulate reverse-shell scenario."""
    _invoke_run("reverse_shell", dry_run)


@app.command(name="suspicious-curl")
def _sim_suspicious_curl(
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
) -> None:
    """Shorthand: simulate suspicious-curl scenario."""
    _invoke_run("suspicious_curl", dry_run)


@app.command(name="fake-ransomware")
def _sim_fake_ransomware(
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
) -> None:
    """Shorthand: simulate fake-ransomware scenario."""
    _invoke_run("fake_ransomware", dry_run)


@app.command(name="encoded-command")
def _sim_encoded_command(
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
) -> None:
    """Shorthand: simulate encoded-command scenario."""
    _invoke_run("encoded_command", dry_run)


@app.command(name="persistence")
def _sim_persistence(
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
) -> None:
    """Shorthand: simulate persistence scenario."""
    _invoke_run("persistence", dry_run)


@app.command(name="suspicious-dns")
def _sim_suspicious_dns(
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
) -> None:
    """Shorthand: simulate suspicious-dns scenario."""
    _invoke_run("suspicious_dns", dry_run)


@app.command(name="credential-dump")
def _sim_credential_dump(
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
) -> None:
    """Shorthand: simulate credential-dump scenario."""
    _invoke_run("credential_dump", dry_run)


@app.command(name="log-tampering")
def _sim_log_tampering(
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
) -> None:
    """Shorthand: simulate log-tampering scenario."""
    _invoke_run("log_tampering", dry_run)


@app.command(name="privilege-escalation")
def _sim_privilege_escalation(
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
) -> None:
    """Shorthand: simulate privilege-escalation scenario."""
    _invoke_run("privilege_escalation", dry_run)


_ALL_SCENARIOS = [
    "suspicious_curl",
    "reverse_shell",
    "fake_ransomware",
    "encoded_command",
    "persistence",
    "suspicious_dns",
    "credential_dump",
    "log_tampering",
    "privilege_escalation",
]


@app.command(name="all")
def run_all(
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Preview without executing"),
) -> None:
    """Run all built-in scenarios in sequence and print a combined summary."""
    from gloamfire.core.docker_client import DockerClient
    from gloamfire.core.executor import ScenarioExecutor
    from gloamfire.detections.validator import DetectionValidator

    try:
        docker_client = DockerClient()
    except DockerUnavailableError as exc:
        err.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1)

    validator = DetectionValidator() if not dry_run else None
    executor = ScenarioExecutor(
        docker_client=docker_client,
        scenarios_dir=None,
        detection_validator=validator,
        dry_run=dry_run,
    )

    summary_rows: list[tuple[str, str, str]] = []  # (scenario, status, duration)
    any_fail = False

    for name in _ALL_SCENARIOS:
        console.print()
        console.print(
            Panel(
                f"[bold green]Running[/bold green] scenario: [bold]{name}[/bold]",
                border_style="green",
            )
        )
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(f"Executing [bold]{name}[/bold]…", total=None)
            try:
                result = executor.run(name)
            except (
                ScenarioNotFoundError,
                ScenarioValidationError,
                ContainerNotFoundError,
                AttackNotFoundError,
                ExecutionError,
            ) as exc:
                err.print(f"[bold red]Error:[/bold red] {exc}")
                summary_rows.append((name, "error", "—"))
                any_fail = True
                continue

        console.print(
            f"Completed [bold]{result.scenario}[/bold] in "
            f"[cyan]{result.duration_s:.1f}s[/cyan]"
        )
        if result.detections:
            _print_detection_results(result.detections)

        status = "pass" if result.overall_pass else "fail"
        if not result.overall_pass:
            any_fail = True
        summary_rows.append((name, status, f"{result.duration_s:.1f}s"))

    # Combined summary
    console.print()
    console.rule("[bold]Summary[/bold]")
    summary = Table(show_header=True, header_style="bold cyan")
    summary.add_column("Scenario", style="bold")
    summary.add_column("Result", width=8)
    summary.add_column("Duration", style="dim", width=10)
    for scenario_name, status, duration in summary_rows:
        summary.add_row(scenario_name, _status_icon(status), duration)
    console.print(summary)
    console.print()
    if any_fail:
        console.print("[bold red]Overall: FAIL[/bold red]")
        raise typer.Exit(2)
    console.print("[bold green]Overall: PASS[/bold green]")


_BUILTIN_CHAINS = Path(__file__).parent.parent.parent.parent / "scenarios" / "chains"


@app.command(name="chain")
def run_chain(
    chain: str = typer.Argument(help="Chain name or path to .yaml file"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Preview without executing"),
    export: Path = typer.Option(None, "--export", "-e", help="Export artefacts to directory"),
) -> None:
    """
    Run an ordered sequence of scenarios defined in a chain YAML file.

    Examples:

        gloamfire simulate chain kill-chain
        gloamfire simulate chain kill-chain --dry-run
        gloamfire simulate chain ./my_chain.yaml --export ./output
    """
    import yaml
    from pydantic import ValidationError

    from gloamfire.core.docker_client import DockerClient
    from gloamfire.core.executor import ScenarioExecutor
    from gloamfire.core.models import Chain
    from gloamfire.detections.validator import DetectionValidator
    from gloamfire.telemetry.exporter import ResultExporter

    chain_name = chain.replace("-", "_")
    candidate = _BUILTIN_CHAINS / f"{chain_name}.yaml"
    direct = Path(chain)
    if candidate.exists():
        chain_path = candidate
    elif direct.exists() and direct.suffix == ".yaml":
        chain_path = direct
    else:
        err.print(f"[bold red]Chain not found:[/bold red] {chain!r}")
        raise typer.Exit(1)

    try:
        chain_obj = Chain.model_validate(yaml.safe_load(chain_path.read_text()))
    except (ValidationError, Exception) as exc:
        err.print(f"[bold red]Invalid chain file:[/bold red] {exc}")
        raise typer.Exit(1)

    try:
        docker_client = DockerClient()
    except DockerUnavailableError as exc:
        err.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1)

    validator = DetectionValidator() if not dry_run else None
    executor = ScenarioExecutor(
        docker_client=docker_client,
        scenarios_dir=None,
        detection_validator=validator,
        dry_run=dry_run,
    )

    console.print()
    console.print(
        Panel(
            f"[bold cyan]Chain:[/bold cyan] [bold]{chain_obj.name}[/bold]\n"
            f"[dim]{chain_obj.description}[/dim]\n"
            f"[dim]{len(chain_obj.scenarios)} scenarios  ·  on_fail: {chain_obj.on_fail}[/dim]",
            border_style="cyan",
        )
    )

    summary_rows: list[tuple[str, str, str]] = []
    any_fail = False
    all_results = []

    for scenario_name in chain_obj.scenarios:
        name = scenario_name.replace("-", "_")
        console.print()
        console.print(
            Panel(
                f"[bold green]Running[/bold green] scenario: [bold]{name}[/bold]",
                border_style="green",
            )
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(f"Executing [bold]{name}[/bold]…", total=None)
            try:
                result = executor.run(name)
            except (
                ScenarioNotFoundError,
                ScenarioValidationError,
                ContainerNotFoundError,
                AttackNotFoundError,
                ExecutionError,
            ) as exc:
                err.print(f"[bold red]Error:[/bold red] {exc}")
                summary_rows.append((name, "error", "—"))
                any_fail = True
                if chain_obj.on_fail == "stop":
                    console.print("[yellow]on_fail: stop — aborting chain[/yellow]")
                    break
                continue

        console.print(
            f"Completed [bold]{result.scenario}[/bold] in "
            f"[cyan]{result.duration_s:.1f}s[/cyan]"
        )
        if result.detections:
            _print_detection_results(result.detections)

        all_results.append(result)
        status = "pass" if result.overall_pass else "fail"
        if not result.overall_pass:
            any_fail = True
            if chain_obj.on_fail == "stop":
                summary_rows.append((name, status, f"{result.duration_s:.1f}s"))
                console.print("[yellow]on_fail: stop — aborting chain[/yellow]")
                break
        summary_rows.append((name, status, f"{result.duration_s:.1f}s"))

    if export and all_results:
        for result in all_results:
            ResultExporter(result).write_report(export)
        console.print(f"\n[green][+][/green] Artefacts exported to [bold]{export}[/bold]")

    console.print()
    console.rule(f"[bold]Chain: {chain_obj.name}[/bold]")
    summary = Table(show_header=True, header_style="bold cyan")
    summary.add_column("Scenario", style="bold")
    summary.add_column("Result", width=8)
    summary.add_column("Duration", style="dim", width=10)
    for scenario_name, status, duration in summary_rows:
        summary.add_row(scenario_name, _status_icon(status), duration)
    console.print(summary)
    console.print()
    if any_fail:
        console.print("[bold red]Chain: FAIL[/bold red]")
        raise typer.Exit(2)
    console.print("[bold green]Chain: PASS[/bold green]")


def _invoke_run(name: str, dry_run: bool) -> None:
    run_scenario(
        scenario=name,
        dry_run=dry_run,
        scenarios_dir=None,
        no_validate=False,
        export=None,
    )
