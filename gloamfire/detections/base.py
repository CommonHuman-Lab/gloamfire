# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Abstract base for detection backend collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from gloamfire.core.models import DetectionExpectation, DetectionResult, ExecutionEvent


class BaseDetectionCollector(ABC):
    """
    A detection collector queries a backend (Wazuh, Suricata, …) for alerts
    generated during a simulation window and evaluates them against expectations.
    """

    source: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the backend is reachable."""
        ...

    @abstractmethod
    def fetch_alerts(
        self,
        since_event: ExecutionEvent,
        window_s: int = 30,
    ) -> list[dict[str, Any]]:
        """Fetch raw alerts from the backend in the post-execution window."""
        ...

    def evaluate(
        self,
        expectation: DetectionExpectation,
        events: list[ExecutionEvent],
        window_s: int = 30,
    ) -> DetectionResult:
        """Default evaluation: fetch alerts and match rule_id / description."""
        if not self.is_available():
            return DetectionResult(
                expectation=expectation,
                status="skip",
                detail=f"{self.source} backend not available",
            )

        if not events:
            return DetectionResult(
                expectation=expectation,
                status="skip",
                detail="No execution events to correlate against",
            )

        alerts = self.fetch_alerts(events[0], window_s)
        matched = self._match(expectation, alerts)

        if matched:
            return DetectionResult(
                expectation=expectation,
                status="pass",
                detail=f"Matched alert in {self.source}",
                raw_alert=matched,
            )
        return DetectionResult(
            expectation=expectation,
            status="fail",
            detail=f"No matching alert found in {self.source} within {window_s}s window",
        )

    def _match(
        self,
        expectation: DetectionExpectation,
        alerts: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        for alert in alerts:
            if expectation.rule_id and self._alert_rule_id(alert) == expectation.rule_id:
                return alert
            if not expectation.rule_id and alerts:
                return alerts[0]
        return None

    def _alert_rule_id(self, alert: dict[str, Any]) -> str:
        return str(alert.get("rule", {}).get("id", ""))
