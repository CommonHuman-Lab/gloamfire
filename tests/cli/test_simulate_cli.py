# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""CLI tests for `gloamfire simulate` — DockerClient and executor fully mocked."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from gloamfire.cli.commands.simulate import app
from gloamfire.core.exceptions import (
    ContainerNotFoundError,
    DockerUnavailableError,
    ScenarioNotFoundError,
)
from gloamfire.core.models import ExecutionEvent, SimulationResult

runner = CliRunner()


def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _event() -> ExecutionEvent:
    return ExecutionEvent(
        timestamp=_ts(),
        scenario="test_scenario",
        step_id="s1",
        attack="curl_wget",
        target="gloamfire-ubuntu",
        command="curl http://example.com",
        exit_code=0,
        stdout="",
        stderr="",
        mitre=["T1105"],
        duration_ms=100,
    )


def _sim_result(scenario: str = "test_scenario") -> SimulationResult:
    return SimulationResult(
        scenario=scenario,
        started_at=_ts(),
        finished_at=_ts(),
        events=[_event()],
    )


def _mock_executor(result: SimulationResult | None = None) -> MagicMock:
    m = MagicMock()
    m.return_value.run.return_value = result or _sim_result()
    return m


def _mock_docker() -> MagicMock:
    return MagicMock()


# ---------------------------------------------------------------------------
# gloamfire simulate run
# ---------------------------------------------------------------------------


class TestSimulateRun:
    def _invoke(self, args: list[str], executor_result=None, docker_raises=None):
        mock_exec = _mock_executor(executor_result)
        mock_docker_cls = MagicMock(
            side_effect=docker_raises if docker_raises else None,
            return_value=_mock_docker(),
        )
        with patch("gloamfire.core.docker_client.DockerClient", mock_docker_cls), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"):
            return runner.invoke(app, ["run"] + args)

    def test_happy_path_exits_zero(self):
        result = self._invoke(["test-scenario"])
        assert result.exit_code == 0

    def test_output_contains_scenario_name(self):
        result = self._invoke(["test-scenario"])
        assert "test_scenario" in result.output

    def test_dry_run_flag_exits_zero(self):
        result = self._invoke(["test-scenario", "--dry-run"])
        assert result.exit_code == 0

    def test_docker_unavailable_exits_one(self):
        result = self._invoke(
            ["test-scenario"],
            docker_raises=DockerUnavailableError(),
        )
        assert result.exit_code == 1

    def test_scenario_not_found_exits_one(self):
        mock_exec = MagicMock()
        mock_exec.return_value.run.side_effect = ScenarioNotFoundError("no such scenario")
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"):
            result = runner.invoke(app, ["run", "nonexistent"])
        assert result.exit_code == 1

    def test_container_not_found_exits_one(self):
        mock_exec = MagicMock()
        mock_exec.return_value.run.side_effect = ContainerNotFoundError("container missing")
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"):
            result = runner.invoke(app, ["run", "some-scenario"])
        assert result.exit_code == 1

    def test_export_flag_writes_artefacts(self, tmp_path):
        mock_exec = _mock_executor()
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"), \
             patch("gloamfire.telemetry.exporter.ResultExporter") as mock_exporter:
            mock_exporter.return_value.write_report.return_value = {}
            result = runner.invoke(app, ["run", "test-scenario", "--export", str(tmp_path)])
        assert result.exit_code == 0
        mock_exporter.return_value.write_report.assert_called_once()

    def test_no_validate_skips_detection_validator(self):
        mock_exec = _mock_executor()
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator") as mock_val:
            runner.invoke(app, ["run", "test-scenario", "--no-validate"])
        mock_val.assert_not_called()

    def test_pcap_flag_starts_capture(self):
        mock_exec = _mock_executor()
        mock_capture = MagicMock()
        mock_capture.start.return_value = True
        mock_capture.stop.return_value = False  # no file written
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"), \
             patch("gloamfire.core.pcap.PcapCapture", return_value=mock_capture):
            runner.invoke(app, ["run", "test-scenario", "--pcap"])
        mock_capture.start.assert_called_once()
        mock_capture.stop.assert_called_once()


# ---------------------------------------------------------------------------
# gloamfire simulate all
# ---------------------------------------------------------------------------


class TestSimulateAll:
    def _invoke(self, args: list[str] | None = None):
        mock_exec = _mock_executor()
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"):
            return runner.invoke(app, ["all"] + (args or []))

    def test_exits_zero_on_all_pass(self):
        result = self._invoke()
        assert result.exit_code == 0

    def test_docker_unavailable_exits_one(self):
        with patch("gloamfire.core.docker_client.DockerClient",
                   side_effect=DockerUnavailableError()):
            result = runner.invoke(app, ["all"])
        assert result.exit_code == 1

    def test_summary_printed(self):
        result = self._invoke()
        assert "Summary" in result.output

    def test_dry_run_flag_accepted(self):
        result = self._invoke(["--dry-run"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# gloamfire simulate chain
# ---------------------------------------------------------------------------


class TestSimulateChain:
    def _make_chain_file(self, tmp_path: Path, scenarios: list[str], on_fail: str = "continue") -> Path:
        chain = {
            "name": "test_chain",
            "description": "Test chain",
            "on_fail": on_fail,
            "scenarios": scenarios,
        }
        path = tmp_path / "test_chain.yaml"
        path.write_text(yaml.dump(chain))
        return path

    def test_chain_not_found_exits_one(self):
        result = runner.invoke(app, ["chain", "nonexistent_chain_xyz"])
        assert result.exit_code == 1

    def test_valid_chain_exits_zero(self, tmp_path):
        chain_path = self._make_chain_file(tmp_path, ["suspicious_curl"])
        mock_exec = _mock_executor()
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"):
            result = runner.invoke(app, ["chain", str(chain_path)])
        assert result.exit_code == 0

    def test_chain_name_in_output(self, tmp_path):
        chain_path = self._make_chain_file(tmp_path, ["suspicious_curl"])
        mock_exec = _mock_executor()
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"):
            result = runner.invoke(app, ["chain", str(chain_path)])
        assert "test_chain" in result.output

    def test_on_fail_stop_aborts_after_error(self, tmp_path):
        chain_path = self._make_chain_file(
            tmp_path, ["scenario_a", "scenario_b"], on_fail="stop"
        )
        mock_exec = MagicMock()
        mock_exec.return_value.run.side_effect = ScenarioNotFoundError("not found")
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"):
            result = runner.invoke(app, ["chain", str(chain_path)])
        # only one run attempt (stopped after first failure)
        assert mock_exec.return_value.run.call_count == 1

    def test_on_fail_continue_runs_all_scenarios(self, tmp_path):
        chain_path = self._make_chain_file(
            tmp_path, ["scenario_a", "scenario_b"], on_fail="continue"
        )
        mock_exec = MagicMock()
        mock_exec.return_value.run.side_effect = ScenarioNotFoundError("not found")
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"):
            runner.invoke(app, ["chain", str(chain_path)])
        assert mock_exec.return_value.run.call_count == 2

    def test_dry_run_flag(self, tmp_path):
        chain_path = self._make_chain_file(tmp_path, ["suspicious_curl"])
        mock_exec = _mock_executor()
        with patch("gloamfire.core.docker_client.DockerClient"), \
             patch("gloamfire.core.executor.ScenarioExecutor", mock_exec), \
             patch("gloamfire.detections.validator.DetectionValidator"):
            result = runner.invoke(app, ["chain", str(chain_path), "--dry-run"])
        assert result.exit_code == 0

    def test_invalid_yaml_exits_one(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("name: bad\n# missing required 'scenarios' field")
        result = runner.invoke(app, ["chain", str(path)])
        assert result.exit_code == 1
