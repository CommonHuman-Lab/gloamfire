# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for DetectionValidator and BaseDetectionCollector."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from gloamfire.core.models import DetectionExpectation, ExecutionEvent
from gloamfire.detections.base import BaseDetectionCollector
from gloamfire.detections.validator import DetectionValidator


def _event() -> ExecutionEvent:
    return ExecutionEvent(
        timestamp=datetime.now(UTC),
        scenario="test",
        step_id="s1",
        attack="curl_wget",
        target="gloamfire-ubuntu",
        command="curl http://example.com",
        exit_code=0,
        stdout="",
        stderr="",
        mitre=["T1105"],
        duration_ms=10,
    )


class _Stub(BaseDetectionCollector):
    source = "wazuh"

    def __init__(self, available: bool = True, alerts: list[dict[str, Any]] | None = None) -> None:
        self._available = available
        self._alerts = alerts if alerts is not None else []

    def is_available(self) -> bool:
        return self._available

    def fetch_alerts(self, since_event: ExecutionEvent, window_s: int = 30) -> list[dict[str, Any]]:
        return self._alerts


class _SuricataStub(_Stub):
    source = "suricata"


class TestValidatorRouting:
    def test_no_collector_for_source_skips(self):
        # Only wazuh registered; suricata expectation → no collector found → skip
        v = DetectionValidator(collectors=[_Stub(available=True)])
        exp = DetectionExpectation(source="suricata", description="d")
        results = v.validate([exp], [_event()])
        assert results[0].status == "skip"
        assert "No collector" in results[0].detail

    def test_empty_expectations_returns_empty(self):
        v = DetectionValidator(collectors=[_Stub()])
        assert v.validate([], []) == []

    def test_routes_to_correct_collector(self):
        w = _Stub(available=True, alerts=[{"rule": {"id": "1"}}])
        s = _SuricataStub(available=False)
        v = DetectionValidator(collectors=[w, s])
        exps = [
            DetectionExpectation(source="wazuh", description="w"),
            DetectionExpectation(source="suricata", description="s"),
        ]
        results = v.validate(exps, [_event()])
        assert results[0].status == "pass"
        assert results[1].status == "skip"

    def test_register_replaces_existing(self):
        v = DetectionValidator(collectors=[_Stub(available=False)])
        v.register(_Stub(available=True, alerts=[{"rule": {"id": "1"}}]))
        exp = DetectionExpectation(source="wazuh", description="d")
        assert v.validate([exp], [_event()])[0].status == "pass"


class TestBaseCollectorEvaluate:
    def test_not_available_skips(self):
        c = _Stub(available=False)
        exp = DetectionExpectation(source="wazuh", description="d")
        result = c.evaluate(exp, [_event()])
        assert result.status == "skip"
        assert "not available" in result.detail

    def test_no_events_skips(self):
        c = _Stub(available=True, alerts=[{"rule": {"id": "1"}}])
        exp = DetectionExpectation(source="wazuh", description="d")
        result = c.evaluate(exp, [])
        assert result.status == "skip"
        assert "No execution events" in result.detail

    def test_no_alerts_fails(self):
        c = _Stub(available=True, alerts=[])
        exp = DetectionExpectation(source="wazuh", description="d")
        result = c.evaluate(exp, [_event()])
        assert result.status == "fail"

    def test_any_alert_without_rule_id_passes(self):
        alert = {"rule": {"id": "555"}, "data": "hit"}
        c = _Stub(available=True, alerts=[alert])
        exp = DetectionExpectation(source="wazuh", description="d")
        result = c.evaluate(exp, [_event()])
        assert result.status == "pass"
        assert result.raw_alert == alert

    def test_matching_rule_id_passes(self):
        alert = {"rule": {"id": "9001"}}
        c = _Stub(available=True, alerts=[alert])
        exp = DetectionExpectation(source="wazuh", description="d", rule_id="9001")
        assert c.evaluate(exp, [_event()]).status == "pass"

    def test_wrong_rule_id_fails(self):
        alert = {"rule": {"id": "1234"}}
        c = _Stub(available=True, alerts=[alert])
        exp = DetectionExpectation(source="wazuh", description="d", rule_id="9999")
        assert c.evaluate(exp, [_event()]).status == "fail"

    def test_window_passed_to_fetch(self):
        c = _Stub(available=True, alerts=[])
        exp = DetectionExpectation(source="wazuh", description="d")
        c.evaluate(exp, [_event()], window_s=60)
        # fetch_alerts is called — we can verify via a subclass that records it
        calls: list[int] = []

        class _Recording(_Stub):
            def fetch_alerts(self, since_event, window_s=30):
                calls.append(window_s)
                return []

        _Recording(available=True).evaluate(exp, [_event()], window_s=45)
        assert calls == [45]
