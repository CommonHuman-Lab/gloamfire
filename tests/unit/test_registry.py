# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for the attack plugin registry."""

from __future__ import annotations

import pytest

from gloamfire.core import registry
from gloamfire.core.exceptions import AttackNotFoundError
from gloamfire.core.registry import all_attacks, get, load_builtin_attacks, register
from gloamfire.attacks.base import BaseAttack, AttackResult
from gloamfire.core.docker_client import DockerClient
from typing import Any


class TestRegister:
    def test_register_and_retrieve(self):
        class _TestAttack(BaseAttack):
            name = "_unit_test_attack"
            description = "test"
            mitre = ["T1105"]

            def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
                return self._exec(target, "echo test")

        register(_TestAttack)
        assert get("_unit_test_attack") is _TestAttack
        # Cleanup
        registry._REGISTRY.pop("_unit_test_attack", None)

    def test_missing_name_raises(self):
        class _NoName(BaseAttack):
            name = ""
            description = "x"
            mitre = []

            def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
                return self._exec(target, "echo")

        with pytest.raises(ValueError, match="name"):
            register(_NoName)

    def test_get_missing_raises(self):
        with pytest.raises(AttackNotFoundError):
            get("does_not_exist_ever")


class TestLoadBuiltins:
    def test_all_builtin_attacks_registered(self):
        load_builtin_attacks()
        plugins = all_attacks()
        expected = {
            "curl_wget",
            "reverse_shell",
            "fake_ransomware",
            "fake_ransomware_cleanup",
            "encoded_command",
            "persistence",
            "dns_suspicious",
        }
        assert expected.issubset(set(plugins.keys()))

    def test_all_have_mitre_or_empty(self):
        load_builtin_attacks()
        for name, cls in all_attacks().items():
            assert isinstance(cls.mitre, list), f"{name}.mitre must be a list"
