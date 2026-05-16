# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""gloamfire lab — manage victim and monitor stacks."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage Gloamfire Docker stacks.", no_args_is_help=True)
console = Console()
err = Console(stderr=True)

_REPO_ROOT = Path(__file__).parent.parent.parent.parent
_VICTIMS_COMPOSE = _REPO_ROOT / "docker" / "victims" / "docker-compose.yml"
_MONITOR_COMPOSE = _REPO_ROOT / "docker" / "monitor" / "docker-compose.yml"
_MONITOR_DIR = _REPO_ROOT / "docker" / "monitor"

_STACKS = {
    "victims": _VICTIMS_COMPOSE,
    "monitor": _MONITOR_COMPOSE,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
    return subprocess.run(  # type: ignore[call-overload]
        cmd, capture_output=True, text=True, check=False, **kwargs
    )


def _detect_bridge_iface() -> str:
    """Return the Linux bridge name for gloamfire-attack-net (e.g. br-a1b2c3d4e5f6)."""
    try:
        r = _run(
            ["docker", "network", "inspect", "gloamfire-attack-net", "--format", "{{.Id}}"],
            timeout=5,
        )
        if r.returncode == 0:
            net_id = r.stdout.strip()
            if net_id:
                return f"br-{net_id[:12]}"
    except (subprocess.SubprocessError, OSError, ValueError):
        pass
    return "any"


def _write_monitor_env(iface: str) -> None:
    """Write .env for the monitor compose so Suricata picks up the right interface."""
    env_file = _MONITOR_DIR / ".env"
    env_file.write_text(f"SURICATA_IFACE={iface}\n")


_SECURITYADMIN = (
    "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"
)
_SECURITYADMIN_CONF = "/usr/share/wazuh-indexer/opensearch-security/"
_INDEXER_CERTS = "/usr/share/wazuh-indexer/certs"
_JAVA_HOME = "/usr/share/wazuh-indexer/jdk"


def _run_securityadmin() -> None:
    """Initialize the OpenSearch security index."""
    console.print("[dim]Waiting for Wazuh indexer (port 9200)…[/dim]")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        r = _run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                  "https://localhost:9200/_cluster/health"], timeout=5)
        code = r.stdout.strip()
        if code and code != "000":
            break
        time.sleep(5)
    else:
        console.print("[yellow]  Indexer not ready — skipping securityadmin[/yellow]")
        return

    console.print("[dim]Initializing OpenSearch security index (securityadmin)…[/dim]")
    r = subprocess.run(
        ["docker", "exec", "--user", "root", "wazuh.indexer", "bash", "-c",
         f"export JAVA_HOME={_JAVA_HOME} && export PATH=$JAVA_HOME/bin:$PATH && "
         f"chmod +x {_SECURITYADMIN} && "
         f"bash {_SECURITYADMIN} "
         f"-cd {_SECURITYADMIN_CONF} -nhnv "
         f"-cacert {_INDEXER_CERTS}/root-ca.pem "
         f"-cert {_INDEXER_CERTS}/admin.pem "
         f"-key {_INDEXER_CERTS}/admin-key.pem "
         f"-p 9200 -icl"],
        capture_output=True, text=True, check=False, timeout=120,
    )
    if r.returncode == 0:
        console.print("[green]  OpenSearch security initialized[/green]")
    else:
        console.print("[yellow]  securityadmin non-zero — dashboard may not be ready[/yellow]")
        if r.stderr.strip():
            console.print(f"[dim]{r.stderr.strip()[:400]}[/dim]")


def _wait_for_suricata(timeout_s: int = 60) -> bool:
    """Poll until Suricata's unix control socket is accepting connections."""
    console.print("[dim]Waiting for Suricata to start…[/dim]")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        r = _run(
            ["docker", "exec", "gloamfire-suricata", "suricatasc", "-c", "uptime"],
            timeout=5,
        )
        if r.returncode == 0:
            return True
        time.sleep(3)
    return False


def _suricata_update_and_reload() -> None:
    """Download ET Open rules inside the running Suricata container."""
    if not _wait_for_suricata():
        console.print("[yellow]  Suricata not ready — skipping rule update[/yellow]")
        return
    console.print("[dim]Downloading ET Open rules via suricata-update…[/dim]")
    r = subprocess.run(
        ["docker", "exec", "gloamfire-suricata", "suricata-update", "--no-test"],
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if r.returncode != 0:
        console.print("[yellow]  suricata-update exited non-zero — rules may be stale[/yellow]")
        console.print(f"[dim]{r.stderr.strip()}[/dim]")
        return

    time.sleep(5)
    console.print("[green]  Suricata rules reloaded[/green]")


def _wait_for_wazuh_agent(timeout_s: int = 120) -> None:
    """Poll until the Gloamfire Wazuh agent is active in the manager."""
    console.print("[dim]Waiting for gloamfire-wazuh-agent to enrol…[/dim]")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        r = _run(
            ["docker", "exec", "wazuh.manager",
             "/var/ossec/bin/agent_control", "-l"],
        )
        if "gloamfire-attack-host" in r.stdout and "Active" in r.stdout:
            console.print("[green]  Wazuh agent enrolled and active[/green]")
            _fix_alerts_permissions()
            return
        time.sleep(5)
    console.print(
        "[yellow]  Wazuh agent not active within timeout — detections may skip[/yellow]"
    )


def _fix_alerts_permissions() -> None:
    """Make the Wazuh alerts log world-readable so the host Python process can read it."""
    subprocess.run(
        ["docker", "exec", "wazuh.manager",
         "chmod", "-R", "o+r", "/var/ossec/logs/alerts"],
        capture_output=True,
        check=False,
    )


def _try_chmod(path: Path, mode: int) -> None:
    """chmod best-effort — skips silently if the path is root-owned via Docker."""
    try:
        path.chmod(mode)
    except PermissionError:
        pass


def _ensure_log_files() -> None:
    """Create bind-mount target log files and directories if they don't exist yet."""
    logs_dir = _MONITOR_DIR / "logs"
    attack_log = logs_dir / "gloamfire-attacks.log"
    attack_log.parent.mkdir(parents=True, exist_ok=True)
    if not attack_log.exists():
        attack_log.touch()
    wazuh_log = logs_dir / "wazuh"
    for subdir in ("alerts", "archives", "firewall", "cluster", "api", "wazuh"):
        d = wazuh_log / subdir
        d.mkdir(parents=True, exist_ok=True)
        _try_chmod(d, 0o777)
    alerts_json = wazuh_log / "alerts" / "alerts.json"
    if not alerts_json.exists():
        alerts_json.touch()
        _try_chmod(alerts_json, 0o666)
    _try_chmod(wazuh_log, 0o777)
    suricata_rules = logs_dir / "suricata-rules"
    suricata_rules.mkdir(parents=True, exist_ok=True)
    _try_chmod(suricata_rules, 0o777)


def _compose(compose_file: Path, action: str, project: str) -> bool:
    """Run `docker compose <action>` and return True on success."""
    if not compose_file.exists():
        err.print(f"[bold red]Compose file not found:[/bold red] {compose_file}")
        return False
    cmd = ["docker", "compose", "-f", str(compose_file), "-p", project, action]
    if action == "up":
        cmd.append("-d")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        err.print(result.stderr)
    return result.returncode == 0


def start_stack(stack: str) -> None:
    """Start one or both Docker stacks, running post-up setup for the monitor."""
    stacks = _resolve_stacks(stack)
    for name, path in stacks.items():
        console.print(f"[green][+][/green] Starting [bold]{name}[/bold] stack…")
        if name == "monitor":
            _ensure_log_files()
            iface = _detect_bridge_iface()
            _write_monitor_env(iface)
            subprocess.run(
                ["docker", "compose", "-f", str(path), "-p", "gloamfire-monitor",
                 "down", "--volumes"],
                capture_output=True,
                check=False,
            )
        ok = _compose(path, "up", f"gloamfire-{name}")
        if ok:
            console.print(f"[green][+][/green] {name} started")
            if name == "monitor":
                _run_securityadmin()
                _suricata_update_and_reload()
                _wait_for_wazuh_agent()
                console.print(
                    "[dim]  Wazuh dashboard  → [/dim]"
                    "[bold cyan]https://localhost:5601[/bold cyan]"
                    "[dim]  (admin / admin)[/dim]"
                )
                console.print(
                    "[dim]  Suricata alerts  → [/dim]"
                    "[bold]docker/monitor/logs/suricata/eve.json[/bold]"
                    "[dim]  (bind-mounted, readable on host)[/dim]"
                )
        else:
            err.print(f"[bold red][-][/bold red] Failed to start {name}")


def stop_stack(stack: str) -> None:
    """Stop one or both Docker stacks."""
    stacks = _resolve_stacks(stack)
    for name, path in stacks.items():
        console.print(f"[yellow][*][/yellow] Stopping [bold]{name}[/bold] stack…")
        _compose(path, "down", f"gloamfire-{name}")
        console.print(f"[yellow][*][/yellow] {name} stopped")


def show_status() -> None:
    """Print a table of all running Gloamfire containers."""
    result = subprocess.run(
        ["docker", "ps",
         "--filter", "name=gloamfire-",
         "--filter", "name=wazuh",
         "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [line for line in result.stdout.strip().splitlines() if line.strip()]
    if not lines:
        console.print("[dim]No Gloamfire containers are running.[/dim]")
        return

    table = Table(title="Gloamfire Containers", show_header=True, header_style="bold cyan")
    table.add_column("Container", style="bold")
    table.add_column("Status")
    table.add_column("Ports", style="dim")

    for line in lines:
        parts = line.split("\t")
        name = parts[0] if len(parts) > 0 else "?"
        status = parts[1] if len(parts) > 1 else "?"
        ports = parts[2] if len(parts) > 2 else ""
        color = "green" if "Up" in status else "red"
        table.add_row(name, f"[{color}]{status}[/{color}]", ports)

    console.print(table)


def _resolve_stacks(stack: str) -> dict[str, Path]:
    if stack == "all":
        return _STACKS
    if stack not in _STACKS:
        err.print(
            f"[bold red]Unknown stack:[/bold red] {stack!r} "
            f"— choose from: {', '.join(_STACKS)}, all"
        )
        raise typer.Exit(1)
    return {stack: _STACKS[stack]}


# ---------------------------------------------------------------------------
# Typer commands
# ---------------------------------------------------------------------------


@app.command("up")
def lab_up(
    stack: str = typer.Argument(
        "all", help="Stack to start: victims | monitor | all"
    ),
) -> None:
    """Start a Docker stack (default: all)."""
    start_stack(stack)


@app.command("down")
def lab_down(
    stack: str = typer.Argument(
        "all", help="Stack to stop: victims | monitor | all"
    ),
) -> None:
    """Stop a Docker stack (default: all)."""
    stop_stack(stack)


@app.command("status")
def lab_status() -> None:
    """Show running Gloamfire containers."""
    show_status()
