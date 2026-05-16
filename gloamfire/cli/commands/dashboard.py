# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Gloamfire dashboard command — starts the web UI."""

from __future__ import annotations

import typer
from rich.console import Console

app = typer.Typer(help="Web dashboard for scenario management and results.")
console = Console()


@app.callback(invoke_without_command=True)
def dashboard(
    port: int = typer.Option(7100, "--port", "-p", help="Port to bind the API server"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind"),
    no_open: bool = typer.Option(False, "--no-open", help="Don't open browser automatically"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev mode)"),
) -> None:
    """Start the Gloamfire web dashboard."""
    import subprocess
    import sys
    import webbrowser
    import threading

    url = f"http://{host}:{port}"
    console.print(f"[bold green]Gloamfire Dashboard[/bold green]  →  [cyan]{url}[/cyan]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")

    if not no_open:
        def _open() -> None:
            import time
            time.sleep(1.2)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    try:
        import uvicorn
        uvicorn.run(
            "gloamfire.api.server:app",
            host=host,
            port=port,
            reload=reload,
            log_level="warning",
        )
    except ImportError:
        console.print("[red]uvicorn not installed — run: pip install gloamfire[/red]")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard stopped.[/dim]")
        raise typer.Exit(0)
