# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Scenario schema validation tests.

Every YAML file in scenarios/ must load cleanly as a valid Scenario.
This acts as a regression guard against schema drift.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from gloamfire.core.models import Scenario

_SCENARIOS_DIR = Path(__file__).parent.parent.parent / "scenarios"
_SCENARIO_FILES = sorted(_SCENARIOS_DIR.glob("*.yaml")) if _SCENARIOS_DIR.exists() else []


@pytest.mark.parametrize("path", _SCENARIO_FILES, ids=[p.stem for p in _SCENARIO_FILES])
def test_scenario_is_valid(path: Path) -> None:
    raw = yaml.safe_load(path.read_text())
    scenario = Scenario.model_validate(raw)

    assert scenario.name, f"{path.name}: name must not be empty"
    assert scenario.description, f"{path.name}: description must not be empty"
    assert len(scenario.mitre) > 0, f"{path.name}: must have at least one MITRE ID"
    assert len(scenario.steps) > 0, f"{path.name}: must have at least one step"

    for step in scenario.steps:
        assert step.id, f"{path.name}: step missing id"
        assert step.attack, f"{path.name}: step {step.id!r} missing attack"
        assert step.target, f"{path.name}: step {step.id!r} missing target"

    for exp in scenario.expect:
        assert exp.source in ("wazuh", "suricata", "sigma", "log"), \
            f"{path.name}: invalid source {exp.source!r}"
        assert exp.description, f"{path.name}: expectation missing description"


def test_all_builtin_scenarios_exist() -> None:
    """Verify the six expected builtin scenarios are present."""
    expected = {
        "suspicious_curl",
        "reverse_shell",
        "fake_ransomware",
        "encoded_command",
        "persistence",
        "suspicious_dns",
    }
    found = {p.stem for p in _SCENARIO_FILES}
    missing = expected - found
    assert not missing, f"Missing built-in scenarios: {missing}"
