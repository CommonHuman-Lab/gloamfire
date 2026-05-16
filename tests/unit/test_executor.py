# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for the ScenarioExecutor."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from gloamfire.core.exceptions import (
    AttackNotFoundError,
    ScenarioNotFoundError,
    ScenarioValidationError,
)
from gloamfire.core.executor import ScenarioExecutor
from gloamfire.core.models import Scenario, ScenarioStep
from gloamfire.core.docker_client import ExecResult


def _make_executor(tmp_path: Path, mock_docker: MagicMock) -> ScenarioExecutor:
    from gloamfire.detections.validator import DetectionValidator

    validator = MagicMock(spec=DetectionValidator)
    validator.validate.return_value = []

    return ScenarioExecutor(
        docker_client=mock_docker,
        scenarios_dir=tmp_path,
        detection_validator=validator,
        dry_run=False,
    )


def _write_scenario(tmp_path: Path, data: dict) -> None:
    name = data["name"]
    (tmp_path / f"{name}.yaml").write_text(yaml.dump(data))


class TestScenarioLoading:
    def test_load_valid_scenario(self, tmp_path, mock_docker):
        _write_scenario(tmp_path, {
            "name": "test_load",
            "description": "desc",
            "mitre": ["T1105"],
            "steps": [{"id": "s1", "attack": "curl_wget", "target": "t"}],
        })
        executor = _make_executor(tmp_path, mock_docker)
        scenario = executor.load_scenario("test_load")
        assert scenario.name == "test_load"

    def test_load_missing_raises(self, tmp_path, mock_docker):
        executor = _make_executor(tmp_path, mock_docker)
        with pytest.raises(ScenarioNotFoundError):
            executor.load_scenario("does_not_exist")

    def test_load_invalid_yaml_raises(self, tmp_path, mock_docker):
        (tmp_path / "bad.yaml").write_text("name: bad\n# missing required fields")
        executor = _make_executor(tmp_path, mock_docker)
        with pytest.raises(ScenarioValidationError):
            executor.load_scenario("bad")

    def test_list_scenarios(self, tmp_path, mock_docker):
        for name in ("alpha", "beta", "gamma"):
            _write_scenario(tmp_path, {
                "name": name,
                "description": "d",
                "mitre": ["T1105"],
                "steps": [{"id": "s", "attack": "curl_wget", "target": "t"}],
            })
        executor = _make_executor(tmp_path, mock_docker)
        paths = executor.list_scenarios()
        assert len(paths) == 3


class TestDryRun:
    def test_dry_run_no_docker_calls(self, tmp_path, mock_docker):
        _write_scenario(tmp_path, {
            "name": "dry_test",
            "description": "d",
            "mitre": ["T1105"],
            "steps": [{"id": "s1", "attack": "curl_wget", "target": "gloamfire-ubuntu"}],
        })
        from gloamfire.detections.validator import DetectionValidator

        executor = ScenarioExecutor(
            docker_client=mock_docker,
            scenarios_dir=tmp_path,
            detection_validator=MagicMock(spec=DetectionValidator),
            dry_run=True,
        )
        result = executor.run("dry_test")
        mock_docker.exec_in_container.assert_not_called()
        assert result.dry_run is True
        assert len(result.events) == 1
        assert result.events[0].metadata["dry_run"] is True


class TestExecution:
    def test_successful_run_creates_events(self, tmp_path, mock_docker):
        _write_scenario(tmp_path, {
            "name": "exec_test",
            "description": "d",
            "mitre": ["T1105"],
            "steps": [
                {"id": "s1", "attack": "curl_wget", "target": "gloamfire-ubuntu"},
                {"id": "s2", "attack": "dns_suspicious", "target": "gloamfire-ubuntu"},
            ],
        })
        executor = _make_executor(tmp_path, mock_docker)
        result = executor.run("exec_test")
        assert len(result.events) == 2
        assert result.events[0].step_id == "s1"
        assert result.events[1].step_id == "s2"

    def test_unknown_attack_raises(self, tmp_path, mock_docker):
        _write_scenario(tmp_path, {
            "name": "bad_attack",
            "description": "d",
            "mitre": ["T1105"],
            "steps": [{"id": "s1", "attack": "nonexistent_attack_xyz", "target": "t"}],
        })
        executor = _make_executor(tmp_path, mock_docker)
        with pytest.raises(AttackNotFoundError):
            executor.run("bad_attack")
