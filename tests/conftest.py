# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Shared pytest fixtures for Gloamfire test suite."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from gloamfire.core.docker_client import DockerClient, ExecResult
from gloamfire.core.models import (
    DetectionExpectation,
    ExecutionEvent,
    Scenario,
    ScenarioStep,
    SimulationResult,
)


# ---------------------------------------------------------------------------
# Scenario fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_scenario() -> Scenario:
    return Scenario(
        name="test_scenario",
        description="Minimal scenario for testing",
        mitre=["T1105"],
        steps=[
            ScenarioStep(id="step1", attack="curl_wget", target="gloamfire-ubuntu")
        ],
    )


@pytest.fixture
def scenario_with_expectations() -> Scenario:
    return Scenario(
        name="test_with_detections",
        description="Scenario with detection expectations",
        mitre=["T1059.004"],
        steps=[
            ScenarioStep(id="step1", attack="reverse_shell", target="gloamfire-ubuntu")
        ],
        expect=[
            DetectionExpectation(
                source="wazuh",
                description="Wazuh detects reverse shell",
                required=True,
            ),
            DetectionExpectation(
                source="suricata",
                description="Suricata alert",
                required=False,
            ),
        ],
    )


@pytest.fixture
def scenarios_dir(tmp_path: Path) -> Path:
    """A temp directory pre-populated with the built-in scenario files."""
    import shutil

    builtin = Path(__file__).parent.parent / "scenarios"
    dest = tmp_path / "scenarios"
    if builtin.exists():
        shutil.copytree(builtin, dest)
    else:
        dest.mkdir()
    return dest


# ---------------------------------------------------------------------------
# Execution event fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_event() -> ExecutionEvent:
    return ExecutionEvent(
        timestamp=datetime.now(UTC),
        scenario="test_scenario",
        step_id="step1",
        attack="curl_wget",
        target="gloamfire-ubuntu",
        command="curl -sSL -o /tmp/test http://testmynids.org/uid/index.html",
        exit_code=0,
        stdout="",
        stderr="",
        mitre=["T1105"],
        duration_ms=150,
    )


@pytest.fixture
def sample_result(sample_event: ExecutionEvent) -> SimulationResult:
    now = datetime.now(UTC)
    return SimulationResult(
        scenario="test_scenario",
        started_at=now,
        finished_at=now,
        events=[sample_event],
        detections=[],
    )


# ---------------------------------------------------------------------------
# Docker mock fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_exec_result() -> ExecResult:
    return ExecResult(
        exit_code=0,
        stdout="simulation output",
        stderr="",
        duration_ms=42,
    )


@pytest.fixture
def mock_docker(mock_exec_result: ExecResult) -> MagicMock:
    """A DockerClient mock that returns successful exec results."""
    client = MagicMock(spec=DockerClient)
    client.exec_in_container.return_value = mock_exec_result
    client.container_running.return_value = True
    return client


@pytest.fixture
def patched_docker(mock_docker: MagicMock):
    """Patch DockerClient() construction to return the mock."""
    with patch("gloamfire.core.docker_client.DockerClient", return_value=mock_docker):
        yield mock_docker
