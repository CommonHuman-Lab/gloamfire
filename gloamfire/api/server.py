# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Gloamfire Dashboard API — FastAPI application."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

_REPO_ROOT = Path(__file__).parent.parent.parent
_SCENARIOS_DIR = _REPO_ROOT / "scenarios"
_CHAINS_DIR = _SCENARIOS_DIR / "chains"
_TELEMETRY = _REPO_ROOT / "gloamfire_telemetry.jsonl"
_STATIC_DIR = Path(__file__).parent / "static"

_CRITICAL_SCENARIOS = {"credential_dump", "log_tampering", "privilege_escalation"}

app = FastAPI(title="Gloamfire Dashboard API", version="0.1.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _docker_ps() -> list[dict[str, Any]]:
    r = subprocess.run(
        ["docker", "ps", "-a",
         "--filter", "name=gloamfire-",
         "--filter", "name=wazuh",
         "--format", "{{.Names}}\t{{.Status}}"],
        capture_output=True, text=True, check=False,
    )
    containers = []
    for line in r.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        name = parts[0]
        status = parts[1] if len(parts) > 1 else ""
        containers.append({"name": name, "status": status, "running": status.startswith("Up")})
    return containers


def _load_scenarios() -> list[dict[str, Any]]:
    scenarios = []
    for path in sorted(_SCENARIOS_DIR.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text())
            name = raw.get("name", path.stem)
            scenarios.append({
                "name": name,
                "description": str(raw.get("description", "")).strip(),
                "severity": "Critical" if name in _CRITICAL_SCENARIOS else "High",
                "mitre": raw.get("mitre", []),
                "tags": raw.get("tags", []),
            })
        except Exception:
            continue
    return scenarios


def _load_results(limit: int = 50) -> list[dict[str, Any]]:
    if not _TELEMETRY.exists():
        return []
    results = []
    try:
        lines = _TELEMETRY.read_text().strip().splitlines()
        for line in reversed(lines[-limit * 10:]):
            if not line.strip():
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        results = results[:limit]
    except OSError:
        pass
    return results


def _run_simulation_sync(scenario_name: str) -> dict[str, Any]:
    from gloamfire.core.docker_client import DockerClient
    from gloamfire.core.executor import ScenarioExecutor
    from gloamfire.core.exceptions import DockerUnavailableError
    from gloamfire.detections.validator import DetectionValidator
    from gloamfire.telemetry.exporter import ResultExporter

    try:
        docker_client = DockerClient()
    except DockerUnavailableError as exc:
        return {"error": str(exc)}

    executor = ScenarioExecutor(
        docker_client=docker_client,
        detection_validator=DetectionValidator(),
    )
    result = executor.run(scenario_name)
    exporter = ResultExporter(result)
    exporter.to_jsonl(_TELEMETRY)

    detections = [
        {
            "source": d.expectation.source,
            "status": d.status,
            "description": d.expectation.description,
            "rule_id": d.expectation.rule_id,
        }
        for d in result.detections
    ]
    return {
        "scenario": result.scenario,
        "started_at": result.started_at.isoformat(),
        "duration_s": round(result.duration_s, 2),
        "passed": result.passed,
        "failed": result.failed,
        "overall_pass": result.overall_pass,
        "detections": detections,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    containers = await asyncio.to_thread(_docker_ps)
    running = [c for c in containers if c["running"]]
    return {
        "containers": containers,
        "lab_ready": len(running) > 0,
        "containers_running": len(running),
        "containers_total": len(containers),
    }


@app.get("/api/scenarios")
async def get_scenarios() -> list[dict[str, Any]]:
    return await asyncio.to_thread(_load_scenarios)


@app.get("/api/results")
async def get_results() -> dict[str, Any]:
    raw = await asyncio.to_thread(_load_results, 20)

    results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for event in raw:
        sid = f"{event.get('scenario')}_{event.get('timestamp', '')[:19]}"
        if sid in seen_ids:
            continue
        seen_ids.add(sid)
        results.append({
            "scenario": event.get("scenario", ""),
            "timestamp": event.get("timestamp", ""),
            "step_id": event.get("step_id", ""),
            "exit_code": event.get("exit_code", 0),
            "mitre": event.get("mitre", []),
            "duration_ms": event.get("duration_ms", 0),
        })

    techniques: set[str] = set()
    for r in results:
        techniques.update(r.get("mitre", []))

    return {
        "events": results,
        "total_events": len(results),
        "techniques_covered": sorted(techniques),
    }


@app.post("/api/simulate/{name}")
async def run_simulation(name: str) -> StreamingResponse:
    scenario_name = name.replace("-", "_")

    async def event_stream():
        yield f"data: {json.dumps({'type': 'start', 'scenario': scenario_name})}\n\n"
        try:
            result = await asyncio.to_thread(_run_simulation_sync, scenario_name)
            if "error" in result:
                yield f"data: {json.dumps({'type': 'error', 'message': result['error']})}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'done', **result})}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/lab/up")
async def lab_up(stack: str = "all") -> dict[str, str]:
    from gloamfire.cli.commands.labs import start_stack
    await asyncio.to_thread(start_stack, stack)
    return {"status": "started", "stack": stack}


@app.post("/api/lab/down")
async def lab_down(stack: str = "all") -> dict[str, str]:
    from gloamfire.cli.commands.labs import stop_stack
    await asyncio.to_thread(stop_stack, stack)
    return {"status": "stopped", "stack": stack}


@app.get("/api/chains")
async def get_chains() -> list[dict[str, Any]]:
    chains = []
    for path in sorted(_CHAINS_DIR.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text())
            chains.append({
                "name": raw.get("name", path.stem),
                "description": str(raw.get("description", "")).strip(),
                "on_fail": raw.get("on_fail", "continue"),
                "scenarios": raw.get("scenarios", []),
            })
        except Exception:
            continue
    return chains


# ---------------------------------------------------------------------------
# Static file serving (production — built UI)
# ---------------------------------------------------------------------------

if _STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str) -> FileResponse:
        return FileResponse(str(_STATIC_DIR / "index.html"))
