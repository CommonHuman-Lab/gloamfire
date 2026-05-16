# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Detection validator — routes DetectionExpectations to the correct collector
and aggregates pass/fail results.
"""

from __future__ import annotations

import logging

from gloamfire.core.models import DetectionExpectation, DetectionResult, ExecutionEvent
from gloamfire.detections.base import BaseDetectionCollector
from gloamfire.detections.suricata import SuricataCollector
from gloamfire.detections.wazuh import WazuhCollector

log = logging.getLogger(__name__)


class DetectionValidator:
    """
    Orchestrates detection validation across multiple backends.
    """

    def __init__(
        self,
        collectors: list[BaseDetectionCollector] | None = None,
        window_s: int = 30,
    ) -> None:
        self._window = window_s
        self._collectors: dict[str, BaseDetectionCollector] = {}

        defaults = collectors or [WazuhCollector(), SuricataCollector()]
        for c in defaults:
            self.register(c)

    def register(self, collector: BaseDetectionCollector) -> None:
        self._collectors[collector.source] = collector

    def validate(
        self,
        expectations: list[DetectionExpectation],
        events: list[ExecutionEvent],
    ) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for exp in expectations:
            collector = self._collectors.get(exp.source)
            if collector is None:
                results.append(
                    DetectionResult(
                        expectation=exp,
                        status="skip",
                        detail=f"No collector registered for source '{exp.source}'",
                    )
                )
                continue
            result = collector.evaluate(exp, events, self._window)
            results.append(result)
            log.info(
                "[%s] %s — %s",
                result.status.upper(),
                exp.description,
                result.detail,
            )
        return results
