# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""FastAPI route tests — subprocess and telemetry file I/O mocked."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from gloamfire.api.server import app
from gloamfire.core.models import ExecutionEvent, SimulationResult
from gloamfire.telemetry.collector import TelemetryCollector

client = TestClient(app, raise_server_exceptions=True)


def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _event() -> ExecutionEvent:
    return ExecutionEvent(
        timestamp=_ts(),
        scenario="test_scenario",
        step_id="s1",
        attack="curl_wget",
        target="gloamfire-ubuntu",
        command="curl http://example.com",
        exit_code=0,
        stdout="",
        stderr="",
        mitre=["T1105"],
        duration_ms=100,
    )


def _sim_result(scenario: str = "test_scenario") -> SimulationResult:
    return SimulationResult(
        scenario=scenario,
        started_at=_ts(),
        finished_at=_ts(),
        events=[_event()],
    )


def _docker_ps_output(*containers: dict) -> MagicMock:
    """Build a mock subprocess result for docker ps."""
    lines = []
    for c in containers:
        lines.append(
            f"{c['name']}\t{c['status']}\t{c.get('image', 'img')}\t{c.get('ports', '')}\t{c.get('id', 'abc')}"
        )
    m = MagicMock()
    m.stdout = "\n".join(lines)
    m.returncode = 0
    return m


# ---------------------------------------------------------------------------
# GET /api/status
# ---------------------------------------------------------------------------


class TestGetStatus:
    def test_returns_200(self):
        with patch("gloamfire.api.server.subprocess.run", return_value=_docker_ps_output()):
            resp = client.get("/api/status")
        assert resp.status_code == 200

    def test_response_shape(self):
        with patch("gloamfire.api.server.subprocess.run", return_value=_docker_ps_output()):
            data = client.get("/api/status").json()
        for key in ("containers", "lab_ready", "containers_running", "containers_total"):
            assert key in data

    def test_no_containers_lab_not_ready(self):
        with patch("gloamfire.api.server.subprocess.run", return_value=_docker_ps_output()):
            data = client.get("/api/status").json()
        assert data["lab_ready"] is False
        assert data["containers_running"] == 0

    def test_running_container_detected(self):
        ps = _docker_ps_output({"name": "gloamfire-ubuntu", "status": "Up 5 minutes"})
        with patch("gloamfire.api.server.subprocess.run", return_value=ps):
            data = client.get("/api/status").json()
        assert data["lab_ready"] is True
        assert data["containers_running"] == 1

    def test_container_list_populated(self):
        ps = _docker_ps_output(
            {"name": "gloamfire-ubuntu", "status": "Up 2 minutes"},
            {"name": "wazuh.manager", "status": "Exited (0) 1 minute ago"},
        )
        with patch("gloamfire.api.server.subprocess.run", return_value=ps):
            data = client.get("/api/status").json()
        assert data["containers_total"] == 2


# ---------------------------------------------------------------------------
# GET /api/scenarios
# ---------------------------------------------------------------------------


class TestGetScenarios:
    def test_returns_200(self):
        resp = client.get("/api/scenarios")
        assert resp.status_code == 200

    def test_returns_list(self):
        data = client.get("/api/scenarios").json()
        assert isinstance(data, list)

    def test_scenario_has_required_fields(self):
        data = client.get("/api/scenarios").json()
        if data:  # skip if no yaml files found (bare test env)
            entry = data[0]
            for key in ("name", "description", "severity", "mitre"):
                assert key in entry

    def test_critical_scenarios_have_critical_severity(self):
        data = client.get("/api/scenarios").json()
        critical = {s["name"] for s in data if s["severity"] == "Critical"}
        # credential_dump, log_tampering, privilege_escalation should be Critical
        if any(s["name"] in ("credential_dump", "log_tampering") for s in data):
            assert len(critical) > 0


# ---------------------------------------------------------------------------
# GET /api/results
# ---------------------------------------------------------------------------


class TestGetResults:
    def test_returns_200(self, tmp_path):
        with patch("gloamfire.api.server._TELEMETRY", tmp_path / "missing.jsonl"):
            resp = client.get("/api/results")
        assert resp.status_code == 200

    def test_no_telemetry_returns_empty(self, tmp_path):
        with patch("gloamfire.api.server._TELEMETRY", tmp_path / "missing.jsonl"):
            data = client.get("/api/results").json()
        assert data["total_events"] == 0
        assert data["events"] == []
        assert data["techniques_covered"] == []

    def test_with_telemetry_returns_events(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        col = TelemetryCollector(tel)
        col.record(_sim_result())
        with patch("gloamfire.api.server._TELEMETRY", tel):
            data = client.get("/api/results").json()
        assert data["total_events"] >= 1

    def test_techniques_covered_populated(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        col = TelemetryCollector(tel)
        col.record(_sim_result())
        with patch("gloamfire.api.server._TELEMETRY", tel):
            data = client.get("/api/results").json()
        assert "T1105" in data["techniques_covered"]

    def test_response_shape(self, tmp_path):
        with patch("gloamfire.api.server._TELEMETRY", tmp_path / "x.jsonl"):
            data = client.get("/api/results").json()
        for key in ("events", "total_events", "techniques_covered"):
            assert key in data


# ---------------------------------------------------------------------------
# GET /api/mitre
# ---------------------------------------------------------------------------


class TestGetMitre:
    def test_returns_200(self):
        assert client.get("/api/mitre").status_code == 200

    def test_returns_list(self):
        assert isinstance(client.get("/api/mitre").json(), list)

    def test_entries_have_required_fields(self):
        data = client.get("/api/mitre").json()
        assert len(data) > 0
        entry = data[0]
        for key in ("id", "name", "tactic", "url"):
            assert key in entry

    def test_known_technique_present(self):
        data = client.get("/api/mitre").json()
        ids = {t["id"] for t in data}
        assert "T1105" in ids


# ---------------------------------------------------------------------------
# GET /api/chains
# ---------------------------------------------------------------------------


class TestGetChains:
    def test_returns_200(self):
        assert client.get("/api/chains").status_code == 200

    def test_returns_list(self):
        assert isinstance(client.get("/api/chains").json(), list)

    def test_kill_chain_present(self):
        data = client.get("/api/chains").json()
        names = [c["name"] for c in data]
        # kill_chain.yaml should always exist
        assert any("kill" in n.lower() for n in names)

    def test_chain_has_required_fields(self):
        data = client.get("/api/chains").json()
        if data:
            entry = data[0]
            for key in ("name", "description", "on_fail", "scenarios"):
                assert key in entry


# ---------------------------------------------------------------------------
# POST /api/lab/reset
# ---------------------------------------------------------------------------


class TestLabReset:
    def test_returns_200(self, tmp_path):
        with patch("gloamfire.api.server._TELEMETRY", tmp_path / "tel.jsonl"):
            resp = client.post("/api/lab/reset")
        assert resp.status_code == 200

    def test_response_has_status_reset(self, tmp_path):
        with patch("gloamfire.api.server._TELEMETRY", tmp_path / "tel.jsonl"):
            data = client.post("/api/lab/reset").json()
        assert data["status"] == "reset"

    def test_telemetry_file_deleted(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        tel.write_text("some data\n")
        with patch("gloamfire.api.server._TELEMETRY", tel):
            data = client.post("/api/lab/reset").json()
        assert not tel.exists()
        assert "tel.jsonl" in data["wiped"]

    def test_no_telemetry_wiped_is_empty(self, tmp_path):
        with patch("gloamfire.api.server._TELEMETRY", tmp_path / "missing.jsonl"):
            data = client.post("/api/lab/reset").json()
        assert data["wiped"] == []
