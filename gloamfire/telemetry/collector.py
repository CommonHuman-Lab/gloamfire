# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""In-memory telemetry collector — accumulates SimulationResults for export."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from gloamfire.core.models import SimulationResult

log = logging.getLogger(__name__)

_DEFAULT_OUTPUT = Path("gloamfire_telemetry.jsonl")


class TelemetryCollector:
    """
    Records simulation results and persists them as JSONL.
    """

    def __init__(self, output: Path = _DEFAULT_OUTPUT) -> None:
        self._output = output
        self._results: list[SimulationResult] = []

    def record(self, result: SimulationResult) -> None:
        self._results.append(result)
        self._append_jsonl(result)

    def all_results(self) -> list[SimulationResult]:
        return list(self._results)

    def clear(self) -> None:
        self._results.clear()

    def _append_jsonl(self, result: SimulationResult) -> None:
        try:
            line = result.model_dump_json()
            with self._output.open("a") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            log.warning("Failed to write telemetry to %s: %s", self._output, exc)

    @classmethod
    def load_from_jsonl(cls, path: Path) -> list[SimulationResult]:
        results: list[SimulationResult] = []
        if not path.exists():
            return results
        with path.open() as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(SimulationResult.model_validate_json(line))
                except Exception as exc:
                    log.warning("Skipping malformed telemetry line %d: %s", lineno, exc)
        return results
