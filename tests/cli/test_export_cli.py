# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""CLI tests for `gloamfire export` — file I/O only, no Docker."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gloamfire.cli.commands.export import app
from gloamfire.core.models import ExecutionEvent, SimulationResult
from gloamfire.telemetry.collector import TelemetryCollector

runner = CliRunner()


def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _event(mitre: list[str] | None = None) -> ExecutionEvent:
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
        mitre=mitre or ["T1105", "T1059.004"],
        duration_ms=100,
    )


def _write_telemetry(path: Path, scenarios: list[str] | None = None) -> None:
    col = TelemetryCollector(path)
    for name in (scenarios or ["test_scenario"]):
        col.record(SimulationResult(
            scenario=name,
            started_at=_ts(),
            finished_at=_ts(),
            events=[_event()],
        ))


# ---------------------------------------------------------------------------
# gloamfire export navigator
# ---------------------------------------------------------------------------


class TestExportNavigator:
    def test_no_telemetry_exits_one(self, tmp_path):
        result = runner.invoke(app, [
            "navigator",
            "--telemetry", str(tmp_path / "missing.jsonl"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert result.exit_code == 1

    def test_writes_navigator_json(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "navigator_layer.json"
        _write_telemetry(tel)
        result = runner.invoke(app, [
            "navigator",
            "--telemetry", str(tel),
            "--output", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()

    def test_output_is_valid_navigator_layer(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "layer.json"
        _write_telemetry(tel)
        runner.invoke(app, ["navigator", "--telemetry", str(tel), "--output", str(out)])
        layer = json.loads(out.read_text())
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert isinstance(layer["techniques"], list)

    def test_techniques_include_simulated_ids(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "layer.json"
        _write_telemetry(tel)
        runner.invoke(app, ["navigator", "--telemetry", str(tel), "--output", str(out)])
        layer = json.loads(out.read_text())
        ids = [t["techniqueID"] for t in layer["techniques"]]
        assert "T1105" in ids

    def test_deduplicates_techniques_across_results(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "layer.json"
        _write_telemetry(tel, scenarios=["s1", "s1", "s2"])
        runner.invoke(app, ["navigator", "--telemetry", str(tel), "--output", str(out)])
        layer = json.loads(out.read_text())
        ids = [t["techniqueID"] for t in layer["techniques"]]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# gloamfire export timeline
# ---------------------------------------------------------------------------


class TestExportTimeline:
    def test_no_telemetry_exits_one(self, tmp_path):
        result = runner.invoke(app, [
            "timeline",
            "--telemetry", str(tmp_path / "missing.jsonl"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert result.exit_code == 1

    def test_writes_timeline_json(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "timeline.json"
        _write_telemetry(tel)
        result = runner.invoke(app, [
            "timeline",
            "--telemetry", str(tel),
            "--output", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()

    def test_timeline_is_list_of_events(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "timeline.json"
        _write_telemetry(tel, scenarios=["s1", "s2"])
        runner.invoke(app, ["timeline", "--telemetry", str(tel), "--output", str(out)])
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert len(data) == 2  # one event per scenario

    def test_timeline_sorted_by_timestamp(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "timeline.json"
        _write_telemetry(tel, scenarios=["s1", "s2"])
        runner.invoke(app, ["timeline", "--telemetry", str(tel), "--output", str(out)])
        data = json.loads(out.read_text())
        timestamps = [e["timestamp"] for e in data]
        assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# gloamfire export mitre
# ---------------------------------------------------------------------------


class TestExportMitre:
    def test_no_telemetry_exits_one(self, tmp_path):
        result = runner.invoke(app, [
            "mitre",
            "--telemetry", str(tmp_path / "missing.jsonl"),
            "--output", str(tmp_path / "out.json"),
        ])
        assert result.exit_code == 1

    def test_writes_mitre_json(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "mitre_map.json"
        _write_telemetry(tel)
        result = runner.invoke(app, [
            "mitre",
            "--telemetry", str(tel),
            "--output", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()

    def test_mitre_json_has_technique_ids(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "mitre.json"
        _write_telemetry(tel)
        runner.invoke(app, ["mitre", "--telemetry", str(tel), "--output", str(out)])
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        ids = [t["technique_id"] for t in data]
        assert "T1105" in ids

    def test_deduplicates_techniques(self, tmp_path):
        tel = tmp_path / "tel.jsonl"
        out = tmp_path / "mitre.json"
        _write_telemetry(tel, scenarios=["s1", "s2"])
        runner.invoke(app, ["mitre", "--telemetry", str(tel), "--output", str(out)])
        data = json.loads(out.read_text())
        ids = [t["technique_id"] for t in data]
        assert len(ids) == len(set(ids))
