# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Typed domain models for scenarios, execution events, and detection results."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------


class MitreMapping(BaseModel):
    """A single MITRE ATT&CK technique reference."""

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    tactic: str

    @field_validator("technique_id")
    @classmethod
    def normalise_id(cls, v: str) -> str:
        return v.upper()


# ---------------------------------------------------------------------------
# Scenario definition (loaded from YAML)
# ---------------------------------------------------------------------------


class Chain(BaseModel):
    """An ordered sequence of scenarios that execute as a unit."""

    name: str
    description: str = ""
    on_fail: Literal["stop", "continue"] = "continue"
    scenarios: list[str]


class ScenarioStep(BaseModel):
    """A single executable step within a scenario."""

    id: str
    attack: str
    target: str = "gloamfire-ubuntu"
    params: dict[str, Any] = Field(default_factory=dict)


class DetectionExpectation(BaseModel):
    """What the operator expects to be detected after execution."""

    source: Literal["wazuh", "suricata", "sigma", "log"]
    rule_id: str | None = None
    description: str
    required: bool = True


class Scenario(BaseModel):
    """A complete, replayable attack scenario loaded from a YAML file."""

    name: str
    description: str
    author: str = "Gloamfire"
    version: str = "1.0"
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(description="MITRE ATT&CK technique IDs, e.g. ['T1105']")
    steps: list[ScenarioStep]
    expect: list[DetectionExpectation] = Field(default_factory=list)
    cleanup: list[ScenarioStep] = Field(default_factory=list)

    @field_validator("mitre", mode="before")
    @classmethod
    def normalise_mitre(cls, v: list[str]) -> list[str]:
        return [t.upper() for t in v]


# ---------------------------------------------------------------------------
# Execution telemetry
# ---------------------------------------------------------------------------


class ExecutionEvent(BaseModel):
    """A single telemetry event captured during scenario execution."""

    timestamp: datetime
    scenario: str
    step_id: str
    attack: str
    target: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    mitre: list[str]
    duration_ms: int
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.exit_code == 0


# ---------------------------------------------------------------------------
# Detection validation
# ---------------------------------------------------------------------------


class DetectionResult(BaseModel):
    """Pass/fail result for a single detection expectation."""

    expectation: DetectionExpectation
    status: Literal["pass", "fail", "skip", "error"]
    detail: str = ""
    raw_alert: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Aggregate simulation result
# ---------------------------------------------------------------------------


class SimulationResult(BaseModel):
    """Complete result of running a scenario end-to-end."""

    scenario: str
    started_at: datetime
    finished_at: datetime
    events: list[ExecutionEvent] = Field(default_factory=list)
    detections: list[DetectionResult] = Field(default_factory=list)
    dry_run: bool = False

    @property
    def duration_s(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def passed(self) -> int:
        return sum(1 for d in self.detections if d.status == "pass")

    @property
    def failed(self) -> int:
        return sum(1 for d in self.detections if d.status == "fail")

    @property
    def skipped(self) -> int:
        return sum(1 for d in self.detections if d.status == "skip")

    @property
    def overall_pass(self) -> bool:
        required = [d for d in self.detections if d.expectation.required]
        return all(d.status == "pass" for d in required)
