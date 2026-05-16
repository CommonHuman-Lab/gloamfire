# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for Pydantic domain models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gloamfire.core.models import (
    DetectionExpectation,
    ExecutionEvent,
    Scenario,
    ScenarioStep,
    SimulationResult,
)
from datetime import UTC, datetime


class TestMitreNormalisation:
    def test_technique_ids_uppercased(self):
        s = Scenario(
            name="x",
            description="d",
            mitre=["t1105", "t1059.004"],
            steps=[ScenarioStep(id="s1", attack="curl_wget", target="ubuntu")],
        )
        assert s.mitre == ["T1105", "T1059.004"]


class TestScenario:
    def test_minimal_valid_scenario(self, minimal_scenario):
        assert minimal_scenario.name == "test_scenario"
        assert len(minimal_scenario.steps) == 1

    def test_missing_name_raises(self):
        with pytest.raises(ValidationError):
            Scenario(description="d", mitre=["T1105"], steps=[])  # type: ignore

    def test_default_author(self):
        s = Scenario(
            name="x",
            description="d",
            mitre=["T1105"],
            steps=[ScenarioStep(id="s", attack="a", target="t")],
        )
        assert s.author == "Gloamfire"

    def test_cleanup_defaults_empty(self, minimal_scenario):
        assert minimal_scenario.cleanup == []

    def test_tags_default_empty(self, minimal_scenario):
        assert minimal_scenario.tags == []


class TestDetectionExpectation:
    def test_wazuh_source(self):
        e = DetectionExpectation(source="wazuh", description="test")
        assert e.source == "wazuh"
        assert e.required is True

    def test_invalid_source(self):
        with pytest.raises(ValidationError):
            DetectionExpectation(source="invalid_source", description="test")


class TestSimulationResult:
    def test_passed_count(self, sample_result):
        from gloamfire.core.models import DetectionResult

        exp = DetectionExpectation(source="wazuh", description="test")
        sample_result.detections = [
            DetectionResult(expectation=exp, status="pass"),
            DetectionResult(expectation=exp, status="fail"),
            DetectionResult(expectation=exp, status="skip"),
        ]
        assert sample_result.passed == 1
        assert sample_result.failed == 1
        assert sample_result.skipped == 1

    def test_overall_pass_no_required_fails(self, sample_result):
        from gloamfire.core.models import DetectionResult

        req = DetectionExpectation(source="wazuh", description="req", required=True)
        opt = DetectionExpectation(source="suricata", description="opt", required=False)
        sample_result.detections = [
            DetectionResult(expectation=req, status="pass"),
            DetectionResult(expectation=opt, status="fail"),
        ]
        assert sample_result.overall_pass is True

    def test_overall_fail_required_fails(self, sample_result):
        from gloamfire.core.models import DetectionResult

        req = DetectionExpectation(source="wazuh", description="req", required=True)
        sample_result.detections = [
            DetectionResult(expectation=req, status="fail"),
        ]
        assert sample_result.overall_pass is False

    def test_duration_property(self):
        t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        t1 = datetime(2026, 1, 1, 12, 0, 5, tzinfo=UTC)
        r = SimulationResult(
            scenario="x",
            started_at=t0,
            finished_at=t1,
        )
        assert r.duration_s == 5.0


class TestExecutionEvent:
    def test_success_property(self, sample_event):
        assert sample_event.success is True

    def test_failure_exit_code(self, sample_event):
        sample_event.exit_code = 1
        assert sample_event.success is False
