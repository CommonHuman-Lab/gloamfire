# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Scenario executor — orchestrates step execution, telemetry collection,
and detection validation for a given Scenario.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from gloamfire.core.docker_client import DockerClient
from gloamfire.core.exceptions import (
    ExecutionError,
    ScenarioNotFoundError,
    ScenarioValidationError,
)
from gloamfire.core.models import (
    DetectionResult,
    ExecutionEvent,
    Scenario,
    SimulationResult,
)
from gloamfire.core.registry import get as get_attack
from gloamfire.core.registry import load_builtin_attacks
from gloamfire.detections.validator import DetectionValidator
from gloamfire.telemetry.collector import TelemetryCollector

log = logging.getLogger(__name__)

_BUILTIN_SCENARIOS = Path(__file__).parent.parent.parent / "scenarios"


class ScenarioExecutor:
    """Loads, validates, and executes attack scenarios."""

    def __init__(
        self,
        docker_client: DockerClient | None = None,
        scenarios_dir: Path | None = None,
        detection_validator: DetectionValidator | None = None,
        dry_run: bool = False,
    ) -> None:
        self._docker = docker_client or DockerClient()
        self._scenarios_dir = scenarios_dir or _BUILTIN_SCENARIOS
        self._validator = detection_validator or DetectionValidator()
        self._dry_run = dry_run
        self._collector = TelemetryCollector()
        load_builtin_attacks()

    # ------------------------------------------------------------------
    # Scenario loading
    # ------------------------------------------------------------------

    def load_scenario(self, name: str) -> Scenario:
        path = self._resolve_path(name)
        raw = yaml.safe_load(path.read_text())
        try:
            return Scenario.model_validate(raw)
        except ValidationError as exc:
            raise ScenarioValidationError(str(path), str(exc)) from exc

    def list_scenarios(self) -> list[Path]:
        if not self._scenarios_dir.exists():
            return []
        return sorted(self._scenarios_dir.glob("*.yaml"))

    def _resolve_path(self, name: str) -> Path:
        candidate = self._scenarios_dir / f"{name}.yaml"
        if candidate.exists():
            return candidate
        direct = Path(name)
        if direct.exists() and direct.suffix == ".yaml":
            return direct
        raise ScenarioNotFoundError(name)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self, name: str) -> SimulationResult:
        scenario = self.load_scenario(name)
        started = datetime.now(UTC)
        events: list[ExecutionEvent] = []

        log.info("Starting scenario %s (dry_run=%s)", scenario.name, self._dry_run)

        try:
            events.extend(self._run_steps(scenario, scenario.steps))
        except ExecutionError:
            raise
        finally:
            if scenario.cleanup and not self._dry_run:
                try:
                    self._run_steps(scenario, scenario.cleanup)
                except Exception as exc:
                    log.warning("Cleanup failed for %s: %s", scenario.name, exc)

        detections = self._validate_detections(scenario, events)
        finished = datetime.now(UTC)

        result = SimulationResult(
            scenario=scenario.name,
            started_at=started,
            finished_at=finished,
            events=events,
            detections=detections,
            dry_run=self._dry_run,
        )
        self._collector.record(result)
        return result

    def _run_steps(self, scenario: Scenario, steps: list) -> list[ExecutionEvent]:
        events: list[ExecutionEvent] = []
        for step in steps:
            attack_cls = get_attack(step.attack)
            attack = attack_cls(self._docker)

            if self._dry_run:
                log.info("[DRY-RUN] Would execute %s on %s", step.attack, step.target)
                events.append(
                    ExecutionEvent(
                        timestamp=datetime.now(UTC),
                        scenario=scenario.name,
                        step_id=step.id,
                        attack=step.attack,
                        target=step.target,
                        command="[dry-run]",
                        exit_code=0,
                        stdout="",
                        stderr="",
                        mitre=scenario.mitre,
                        duration_ms=0,
                        metadata={"dry_run": True},
                    )
                )
                continue

            start_ts = datetime.now(UTC)
            try:
                result = attack.execute(step.target, step.params)
            except Exception as exc:
                raise ExecutionError(step.id, str(exc)) from exc

            events.append(
                ExecutionEvent(
                    timestamp=start_ts,
                    scenario=scenario.name,
                    step_id=step.id,
                    attack=step.attack,
                    target=step.target,
                    command=result.command,
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    mitre=scenario.mitre,
                    duration_ms=result.duration_ms,
                    metadata=result.metadata,
                )
            )
        return events

    def _validate_detections(
        self, scenario: Scenario, events: list[ExecutionEvent]
    ) -> list[DetectionResult]:
        if self._dry_run or not scenario.expect:
            return []
        return self._validator.validate(scenario.expect, events)
