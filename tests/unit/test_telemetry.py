# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for TelemetryCollector and MITRE lookup helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gloamfire.core.models import ExecutionEvent, SimulationResult
from gloamfire.telemetry.collector import TelemetryCollector
from gloamfire.telemetry.mitre import TechniqueInfo, format_mitre_table, lookup, lookup_many


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _event() -> ExecutionEvent:
    return ExecutionEvent(
        timestamp=_ts(),
        scenario="s",
        step_id="s1",
        attack="curl_wget",
        target="gloamfire-ubuntu",
        command="curl http://example.com",
        exit_code=0,
        stdout="",
        stderr="",
        mitre=["T1105"],
        duration_ms=50,
    )


def _result(scenario: str = "test") -> SimulationResult:
    return SimulationResult(
        scenario=scenario,
        started_at=_ts(),
        finished_at=_ts(),
        events=[_event()],
    )


# ---------------------------------------------------------------------------
# TelemetryCollector
# ---------------------------------------------------------------------------


class TestTelemetryCollector:
    def test_record_adds_to_list(self, tmp_path):
        col = TelemetryCollector(tmp_path / "tel.jsonl")
        col.record(_result())
        assert len(col.all_results()) == 1

    def test_record_writes_jsonl_file(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        col = TelemetryCollector(path)
        col.record(_result())
        assert path.exists()
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        assert len(lines) == 1

    def test_multiple_records_multiple_lines(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        col = TelemetryCollector(path)
        col.record(_result("a"))
        col.record(_result("b"))
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        assert len(lines) == 2

    def test_clear_empties_in_memory_list(self, tmp_path):
        col = TelemetryCollector(tmp_path / "tel.jsonl")
        col.record(_result())
        col.clear()
        assert col.all_results() == []

    def test_clear_does_not_delete_file(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        col = TelemetryCollector(path)
        col.record(_result())
        col.clear()
        assert path.exists()

    def test_all_results_returns_copy(self, tmp_path):
        col = TelemetryCollector(tmp_path / "tel.jsonl")
        col.record(_result())
        results = col.all_results()
        results.clear()
        assert len(col.all_results()) == 1


class TestLoadFromJsonl:
    def test_loads_written_results(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        col = TelemetryCollector(path)
        col.record(_result("s1"))
        col.record(_result("s2"))

        loaded = TelemetryCollector.load_from_jsonl(path)
        assert len(loaded) == 2
        assert {r.scenario for r in loaded} == {"s1", "s2"}

    def test_missing_file_returns_empty(self, tmp_path):
        results = TelemetryCollector.load_from_jsonl(tmp_path / "missing.jsonl")
        assert results == []

    def test_malformed_line_skipped(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        col = TelemetryCollector(path)
        col.record(_result("good"))
        with path.open("a") as fh:
            fh.write("this is not json\n")
        loaded = TelemetryCollector.load_from_jsonl(path)
        assert len(loaded) == 1
        assert loaded[0].scenario == "good"

    def test_empty_lines_skipped(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        col = TelemetryCollector(path)
        col.record(_result())
        with path.open("a") as fh:
            fh.write("\n\n")
        assert len(TelemetryCollector.load_from_jsonl(path)) == 1

    def test_roundtrip_preserves_events(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        col = TelemetryCollector(path)
        col.record(_result())
        loaded = TelemetryCollector.load_from_jsonl(path)
        assert loaded[0].events[0].step_id == "s1"


# ---------------------------------------------------------------------------
# MITRE lookup
# ---------------------------------------------------------------------------


class TestMitreLookup:
    def test_known_technique_returns_info(self):
        info = lookup("T1105")
        assert isinstance(info, TechniqueInfo)
        assert info.technique_id == "T1105"
        assert info.technique_name != "Unknown Technique"
        assert info.tactic != "Unknown Tactic"

    def test_case_normalised_to_upper(self):
        info = lookup("t1105")
        assert info.technique_id == "T1105"

    def test_unknown_technique_returns_placeholder(self):
        info = lookup("T9999")
        assert info.technique_id == "T9999"
        assert info.technique_name == "Unknown Technique"
        assert info.tactic == "Unknown Tactic"

    def test_subtechnique_resolved(self):
        info = lookup("T1059.004")
        assert "Unix Shell" in info.technique_name

    def test_url_property(self):
        info = lookup("T1059.004")
        assert "attack.mitre.org" in info.url
        assert "T1059" in info.url
        assert ".004" not in info.url  # URL uses base ID only

    def test_lookup_many_returns_list(self):
        results = lookup_many(["T1105", "T1059.004"])
        assert len(results) == 2
        assert all(isinstance(r, TechniqueInfo) for r in results)

    def test_format_mitre_table_keys(self):
        table = format_mitre_table(["T1105"])
        assert len(table) == 1
        entry = table[0]
        for key in ("technique_id", "technique_name", "tactic", "url"):
            assert key in entry

    def test_format_mitre_table_empty_input(self):
        assert format_mitre_table([]) == []
