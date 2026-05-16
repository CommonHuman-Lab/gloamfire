# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for attack plugins (Docker calls mocked)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from gloamfire.attacks.curl_wget import CurlWgetAttack
from gloamfire.attacks.dns_suspicious import SuspiciousDNSAttack
from gloamfire.attacks.encoded_command import EncodedCommandAttack
from gloamfire.attacks.fake_ransomware import FakeRansomwareAttack, FakeRansomwareCleanup
from gloamfire.attacks.persistence import PersistenceCronAttack
from gloamfire.attacks.reverse_shell import ReverseShellAttack
from gloamfire.core.docker_client import ExecResult


def _make_docker(stdout: str = "ok", exit_code: int = 0) -> MagicMock:
    m = MagicMock()
    m.exec_in_container.return_value = ExecResult(
        exit_code=exit_code, stdout=stdout, stderr="", duration_ms=10
    )
    return m


class TestCurlWget:
    def test_default_uses_curl(self):
        docker = _make_docker()
        attack = CurlWgetAttack(docker)
        result = attack.execute("gloamfire-ubuntu", {})
        assert "curl" in result.command
        assert result.metadata["method"] == "curl"

    def test_wget_method(self):
        docker = _make_docker()
        attack = CurlWgetAttack(docker)
        result = attack.execute("gloamfire-ubuntu", {"method": "wget"})
        assert "wget" in result.command
        assert result.metadata["method"] == "wget"

    def test_custom_url(self):
        docker = _make_docker()
        attack = CurlWgetAttack(docker)
        result = attack.execute("gloamfire-ubuntu", {"url": "http://example.com"})
        assert result.metadata["url"] == "http://example.com"

    def test_success_property(self):
        docker = _make_docker(exit_code=0)
        attack = CurlWgetAttack(docker)
        assert attack.execute("t", {}).success is True

    def test_fail_on_nonzero_exit(self):
        docker = _make_docker(exit_code=1)
        attack = CurlWgetAttack(docker)
        assert attack.execute("t", {}).success is False


class TestReverseShell:
    def test_default_params(self):
        docker = _make_docker()
        attack = ReverseShellAttack(docker)
        result = attack.execute("gloamfire-ubuntu", {})
        assert "192.0.2.1" in result.command
        assert "4444" in result.command
        assert result.metadata["lhost"] == "192.0.2.1"

    def test_custom_lhost_lport(self):
        docker = _make_docker()
        attack = ReverseShellAttack(docker)
        result = attack.execute("t", {"lhost": "10.0.0.1", "lport": 9999})
        assert result.metadata["lhost"] == "10.0.0.1"
        assert result.metadata["lport"] == 9999


class TestFakeRansomware:
    def test_script_contains_rename(self):
        docker = _make_docker()
        attack = FakeRansomwareAttack(docker)
        result = attack.execute("gloamfire-ubuntu", {})
        _, kwargs = docker.exec_in_container.call_args
        # The command passed should be the full script
        assert result.metadata["sim_dir"] == FakeRansomwareAttack._SIM_DIR

    def test_custom_file_count(self):
        docker = _make_docker()
        attack = FakeRansomwareAttack(docker)
        result = attack.execute("t", {"file_count": 5})
        assert result.metadata["file_count"] == 5

    def test_cleanup_attack(self):
        docker = _make_docker()
        cleanup = FakeRansomwareCleanup(docker)
        result = cleanup.execute("t", {})
        assert "rm -rf" in result.command


class TestEncodedCommand:
    def test_encodes_payload(self):
        import base64

        docker = _make_docker()
        attack = EncodedCommandAttack(docker)
        payload = "echo hello"
        result = attack.execute("t", {"payload": payload})
        expected_b64 = base64.b64encode(payload.encode()).decode()
        assert result.metadata["encoded_payload"] == expected_b64
        assert result.metadata["decoded_payload"] == payload
        assert "base64 -d | bash" in result.command

    def test_default_payload_harmless(self):
        docker = _make_docker()
        attack = EncodedCommandAttack(docker)
        result = attack.execute("t", {})
        assert "echo" in result.metadata["decoded_payload"]


class TestPersistence:
    def test_generates_cron_script(self):
        docker = _make_docker()
        attack = PersistenceCronAttack(docker)
        result = attack.execute("t", {})
        assert result.metadata["cron_file"] == PersistenceCronAttack._CRON_FILE

    def test_custom_cron_file(self):
        docker = _make_docker()
        attack = PersistenceCronAttack(docker)
        result = attack.execute("t", {"cron_file": "/etc/cron.d/custom"})
        assert result.metadata["cron_file"] == "/etc/cron.d/custom"


class TestSuspiciousDNS:
    def test_default_domains(self):
        docker = _make_docker()
        attack = SuspiciousDNSAttack(docker)
        result = attack.execute("t", {})
        assert isinstance(result.metadata["domains"], list)
        assert len(result.metadata["domains"]) > 0

    def test_custom_domains(self):
        docker = _make_docker()
        attack = SuspiciousDNSAttack(docker)
        result = attack.execute("t", {"domains": ["evil.example.com"]})
        assert result.metadata["domains"] == ["evil.example.com"]
