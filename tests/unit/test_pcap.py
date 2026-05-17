# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for PcapCapture — Docker calls and subprocess mocked."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from gloamfire.core.docker_client import ExecResult
from gloamfire.core.pcap import PcapCapture, _PCAP_TMP, _PID_TMP


def _docker(raise_on_exec: Exception | None = None) -> MagicMock:
    m = MagicMock()
    if raise_on_exec:
        m.exec_in_container.side_effect = raise_on_exec
    else:
        m.exec_in_container.return_value = ExecResult(
            exit_code=0, stdout="", stderr="", duration_ms=5
        )
    return m


def _cp_result(rc: int = 0) -> MagicMock:
    r = MagicMock()
    r.returncode = rc
    r.stderr = b""
    return r


class TestStart:
    def test_success_returns_true_and_sets_active(self):
        docker = _docker()
        with patch("gloamfire.core.pcap.time.sleep"):
            cap = PcapCapture(docker, container="gloamfire-ubuntu", iface="eth0")
            assert cap.start() is True
        assert cap._active is True

    def test_tcpdump_command_in_exec(self):
        docker = _docker()
        with patch("gloamfire.core.pcap.time.sleep"):
            PcapCapture(docker).start()
        cmd = docker.exec_in_container.call_args[0][1]
        assert "tcpdump" in cmd
        assert _PCAP_TMP in cmd

    def test_custom_iface_used(self):
        docker = _docker()
        with patch("gloamfire.core.pcap.time.sleep"):
            PcapCapture(docker, iface="eth1").start()
        cmd = docker.exec_in_container.call_args[0][1]
        assert "eth1" in cmd

    def test_docker_exception_returns_false(self):
        docker = _docker(raise_on_exec=RuntimeError("boom"))
        with patch("gloamfire.core.pcap.time.sleep"):
            cap = PcapCapture(docker)
            assert cap.start() is False
        assert cap._active is False

    def test_sleep_called_after_exec(self):
        docker = _docker()
        with patch("gloamfire.core.pcap.time.sleep") as mock_sleep:
            PcapCapture(docker).start()
        mock_sleep.assert_called_once_with(0.5)


class TestStop:
    def test_inactive_returns_false_immediately(self):
        docker = _docker()
        cap = PcapCapture(docker)
        assert cap._active is False
        assert cap.stop(Path("/tmp/out.pcap")) is False
        docker.exec_in_container.assert_not_called()

    def test_success_path(self, tmp_path):
        docker = _docker()
        dest = tmp_path / "capture.pcap"
        dest.write_bytes(b"dummy")  # simulate docker cp writing the file

        with patch("gloamfire.core.pcap.time.sleep"), \
             patch("gloamfire.core.pcap.subprocess.run", return_value=_cp_result(0)):
            cap = PcapCapture(docker)
            cap._active = True
            result = cap.stop(dest)

        assert result is True
        assert cap._active is False

    def test_docker_cp_failure_returns_false(self, tmp_path):
        docker = _docker()
        dest = tmp_path / "capture.pcap"

        with patch("gloamfire.core.pcap.time.sleep"), \
             patch("gloamfire.core.pcap.subprocess.run", return_value=_cp_result(1)):
            cap = PcapCapture(docker)
            cap._active = True
            result = cap.stop(dest)

        assert result is False

    def test_file_missing_after_cp_returns_false(self, tmp_path):
        docker = _docker()
        dest = tmp_path / "missing.pcap"  # never created

        with patch("gloamfire.core.pcap.time.sleep"), \
             patch("gloamfire.core.pcap.subprocess.run", return_value=_cp_result(0)):
            cap = PcapCapture(docker)
            cap._active = True
            result = cap.stop(dest)

        assert result is False

    def test_kill_command_sent_before_cp(self, tmp_path):
        docker = _docker()
        dest = tmp_path / "out.pcap"
        dest.write_bytes(b"x")

        with patch("gloamfire.core.pcap.time.sleep"), \
             patch("gloamfire.core.pcap.subprocess.run", return_value=_cp_result(0)):
            cap = PcapCapture(docker)
            cap._active = True
            cap.stop(dest)

        kill_cmd = docker.exec_in_container.call_args_list[0][0][1]
        assert "kill" in kill_cmd or "pkill" in kill_cmd

    def test_cleanup_exec_called(self, tmp_path):
        docker = _docker()
        dest = tmp_path / "out.pcap"
        dest.write_bytes(b"x")

        with patch("gloamfire.core.pcap.time.sleep"), \
             patch("gloamfire.core.pcap.subprocess.run", return_value=_cp_result(0)):
            cap = PcapCapture(docker)
            cap._active = True
            cap.stop(dest)

        assert docker.exec_in_container.call_count == 2
        cleanup_cmd = docker.exec_in_container.call_args_list[1][0][1]
        assert "rm -f" in cleanup_cmd

    def test_exception_during_stop_returns_false(self, tmp_path):
        docker = _docker(raise_on_exec=RuntimeError("exec failed"))
        dest = tmp_path / "out.pcap"

        with patch("gloamfire.core.pcap.time.sleep"):
            cap = PcapCapture(docker)
            cap._active = True
            result = cap.stop(dest)

        assert result is False

    def test_parent_dir_created_if_missing(self, tmp_path):
        docker = _docker()
        dest = tmp_path / "sub" / "dir" / "out.pcap"
        # don't pre-create parent — stop() should mkdir

        with patch("gloamfire.core.pcap.time.sleep"), \
             patch("gloamfire.core.pcap.subprocess.run", return_value=_cp_result(1)):
            cap = PcapCapture(docker)
            cap._active = True
            cap.stop(dest)

        assert dest.parent.exists()
