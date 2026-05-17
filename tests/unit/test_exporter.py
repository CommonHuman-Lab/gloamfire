# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for ResultExporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from gloamfire.core.models import (
    DetectionExpectation,
    DetectionResult,
    ExecutionEvent,
    SimulationResult,
)
from gloamfire.telemetry.exporter import ResultExporter


def _ts(offset_s: int = 0) -> datetime:
    return datetime(2026, 1, 1, 12, 0, offset_s, tzinfo=UTC)


def _event(step_id: str = "s1", mitre: list[str] | None = None, offset_s: int = 0) -> ExecutionEvent:
    return ExecutionEvent(
        timestamp=_ts(offset_s),
        scenario="test_scenario",
        step_id=step_id,
        attack="curl_wget",
        target="gloamfire-ubuntu",
        command="curl http://example.com",
        exit_code=0,
        stdout="ok",
        stderr="",
        mitre=mitre or ["T1105"],
        duration_ms=100,
    )


def _result(events: list[ExecutionEvent] | None = None) -> SimulationResult:
    return SimulationResult(
        scenario="test_scenario",
        started_at=_ts(0),
        finished_at=_ts(5),
        events=events or [_event()],
    )


class TestToJsonl:
    def test_appends_one_line_per_event(self, tmp_path):
        r = _result([_event("s1"), _event("s2")])
        path = tmp_path / "events.jsonl"
        ResultExporter(r).to_jsonl(path)
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        assert len(lines) == 2

    def test_each_line_is_valid_json(self, tmp_path):
        r = _result([_event("s1")])
        path = tmp_path / "events.jsonl"
        ResultExporter(r).to_jsonl(path)
        data = json.loads(path.read_text().strip())
        assert data["step_id"] == "s1"

    def test_appends_on_successive_calls(self, tmp_path):
        path = tmp_path / "events.jsonl"
        ResultExporter(_result([_event("s1")])).to_jsonl(path)
        ResultExporter(_result([_event("s2")])).to_jsonl(path)
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        assert len(lines) == 2


class TestToTimeline:
    def test_sorted_by_timestamp(self):
        events = [_event("s2", offset_s=5), _event("s1", offset_s=1)]
        timeline = ResultExporter(_result(events)).to_timeline()
        timestamps = [e["timestamp"] for e in timeline]
        assert timestamps == sorted(timestamps)

    def test_contains_required_keys(self):
        timeline = ResultExporter(_result()).to_timeline()
        entry = timeline[0]
        for key in ("timestamp", "scenario", "step", "attack", "target", "exit_code", "mitre", "success"):
            assert key in entry

    def test_success_field_reflects_exit_code(self):
        e = _event()
        e.exit_code = 1
        timeline = ResultExporter(_result([e])).to_timeline()
        assert timeline[0]["success"] is False


class TestToMitreMap:
    def test_deduplicates_techniques(self):
        events = [_event("s1", ["T1105"]), _event("s2", ["T1105", "T1059.004"])]
        mitre_map = ResultExporter(_result(events)).to_mitre_map()
        ids = [t["technique_id"] for t in mitre_map]
        assert len(ids) == len(set(ids))

    def test_known_technique_has_name(self):
        mitre_map = ResultExporter(_result([_event(mitre=["T1105"])])).to_mitre_map()
        t = next(t for t in mitre_map if t["technique_id"] == "T1105")
        assert t["technique_name"] != "Unknown Technique"

    def test_unknown_technique_gracefully_handled(self):
        mitre_map = ResultExporter(_result([_event(mitre=["T9999"])])).to_mitre_map()
        assert mitre_map[0]["technique_id"] == "T9999"
        assert mitre_map[0]["technique_name"] == "Unknown Technique"

    def test_preserves_insertion_order(self):
        events = [_event("s1", ["T1059.004"]), _event("s2", ["T1105"])]
        ids = [t["technique_id"] for t in ResultExporter(_result(events)).to_mitre_map()]
        assert ids[0] == "T1059.004"
        assert ids[1] == "T1105"


class TestToNavigatorLayer:
    def test_required_top_level_keys(self):
        layer = ResultExporter(_result()).to_navigator_layer()
        for key in ("name", "versions", "domain", "techniques", "gradient"):
            assert key in layer

    def test_domain_is_enterprise(self):
        layer = ResultExporter(_result()).to_navigator_layer()
        assert layer["domain"] == "enterprise-attack"

    def test_techniques_list_populated(self):
        layer = ResultExporter(_result([_event(mitre=["T1105", "T1059.004"])])).to_navigator_layer()
        ids = [t["techniqueID"] for t in layer["techniques"]]
        assert "T1105" in ids
        assert "T1059.004" in ids

    def test_technique_entry_structure(self):
        layer = ResultExporter(_result()).to_navigator_layer()
        t = layer["techniques"][0]
        for key in ("techniqueID", "tactic", "score", "color", "enabled"):
            assert key in t

    def test_scenario_name_in_layer_name(self):
        layer = ResultExporter(_result()).to_navigator_layer()
        assert "test_scenario" in layer["name"]


class TestToSummary:
    def test_summary_keys(self):
        summary = ResultExporter(_result()).to_summary()
        for key in ("scenario", "started_at", "duration_s", "events", "detections", "overall_pass", "dry_run"):
            assert key in summary

    def test_event_count(self):
        summary = ResultExporter(_result([_event("s1"), _event("s2")])).to_summary()
        assert summary["events"] == 2

    def test_detection_counts(self):
        exp = DetectionExpectation(source="wazuh", description="d")
        r = _result()
        r.detections = [
            DetectionResult(expectation=exp, status="pass"),
            DetectionResult(expectation=exp, status="fail"),
            DetectionResult(expectation=exp, status="skip"),
        ]
        summary = ResultExporter(r).to_summary()
        assert summary["detections"]["passed"] == 1
        assert summary["detections"]["failed"] == 1

    def test_duration_rounded(self):
        summary = ResultExporter(_result()).to_summary()
        assert summary["duration_s"] == 5.0


class TestWriteReport:
    def test_writes_all_four_files(self, tmp_path):
        paths = ResultExporter(_result()).write_report(tmp_path)
        assert set(paths.keys()) == {"events", "timeline", "mitre", "summary"}
        for p in paths.values():
            assert p.exists()

    def test_timeline_is_valid_json(self, tmp_path):
        paths = ResultExporter(_result()).write_report(tmp_path)
        data = json.loads(paths["timeline"].read_text())
        assert isinstance(data, list)

    def test_summary_is_valid_json(self, tmp_path):
        paths = ResultExporter(_result()).write_report(tmp_path)
        data = json.loads(paths["summary"].read_text())
        assert data["scenario"] == "test_scenario"

    def test_creates_output_dir_if_missing(self, tmp_path):
        out = tmp_path / "new_dir"
        ResultExporter(_result()).write_report(out)
        assert out.is_dir()
