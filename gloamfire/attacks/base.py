# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Abstract base class for all Gloamfire attack simulation plugins."""

from __future__ import annotations

import datetime
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gloamfire.core.docker_client import DockerClient

log = logging.getLogger(__name__)

_ATTACK_LOG = (
    Path(__file__).parent.parent.parent / "docker" / "monitor" / "logs" / "gloamfire-attacks.log"
)


@dataclass
class AttackResult:
    """Structured output from a single attack execution."""

    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.exit_code == 0


class BaseAttack(ABC):
    """
    All attack simulation plugins inherit from this class.

    Subclasses MUST set class attributes:
        name    — matches the `attack:` key in scenario YAML
        mitre   — list of MITRE ATT&CK technique IDs
        description — human-readable summary

    They MUST implement:
        execute(target, params) -> AttackResult
    """

    name: str = ""
    description: str = ""
    mitre: list[str] = []

    def __init__(self, docker_client: DockerClient) -> None:
        self._docker = docker_client

    @abstractmethod
    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        """Execute the simulation inside `target` container and return telemetry."""
        ...

    def _write_attack_log(self, target: str, attack_name: str) -> None:
        """Append a syslog-format entry to the host attack log (Wazuh picks it up)."""
        ts = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        line = f"{ts} {target} Gloamfire: {attack_name} executed\n"
        try:
            _ATTACK_LOG.parent.mkdir(parents=True, exist_ok=True)
            with _ATTACK_LOG.open("a") as fh:
                fh.write(line)
        except OSError as exc:
            log.debug("Could not write attack log: %s", exc)

    def _c2_beacon(self, target: str) -> None:
        """Simulate C2 check-in via HTTP — generates Suricata GPL ATTACK_RESPONSE alert."""
        try:
            self._exec(
                target,
                "curl -s --max-time 10 http://testmynids.org/uid/index.html > /dev/null 2>&1 || true",
            )
        except Exception:
            pass

    def _exec(
        self,
        target: str,
        cmd: str,
        user: str = "root",
        workdir: str = "/tmp",
        env: dict[str, str] | None = None,
    ) -> AttackResult:
        """Convenience wrapper around DockerClient.exec_in_container."""
        result = self._docker.exec_in_container(
            container_name=target,
            cmd=cmd,
            user=user,
            workdir=workdir,
            environment=env or {},
        )
        return AttackResult(
            command=cmd,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
        )
