# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Docker API abstraction — all container interactions go through this module."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import docker
import docker.errors
from docker.models.containers import Container

from gloamfire.core.exceptions import ContainerNotFoundError, DockerUnavailableError


@dataclass
class ExecResult:
    """Result of a `docker exec` call."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.exit_code == 0


class DockerClient:
    """Thin, testable wrapper around the Docker SDK."""

    def __init__(self, base_url: str = "unix:///var/run/docker.sock") -> None:
        try:
            self._client = docker.DockerClient(base_url=base_url, timeout=10)
            self._client.ping()
        except Exception as exc:
            raise DockerUnavailableError() from exc

    # ------------------------------------------------------------------
    # Container queries
    # ------------------------------------------------------------------

    def container_running(self, name: str) -> bool:
        try:
            c = self._client.containers.get(name)
            return c.status == "running"  # type: ignore[no-any-return]
        except docker.errors.NotFound:
            return False

    def get_container(self, name: str) -> Container:
        try:
            c = self._client.containers.get(name)
            if c.status != "running":
                raise ContainerNotFoundError(name)
            return c  # type: ignore[return-value]
        except docker.errors.NotFound:
            raise ContainerNotFoundError(name)

    def list_gloamfire_containers(self) -> list[dict[str, str]]:
        containers = self._client.containers.list(
            filters={"name": "gloamfire-"}
        )
        return [
            {
                "name": c.name,
                "status": c.status,
                "image": c.image.tags[0] if c.image.tags else "unknown",
            }
            for c in containers
        ]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def exec_in_container(
        self,
        container_name: str,
        cmd: str | list[str],
        user: str = "root",
        workdir: str = "/tmp",
        environment: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> ExecResult:
        container = self.get_container(container_name)

        shell_cmd: list[str]
        if isinstance(cmd, str):
            shell_cmd = ["/bin/bash", "-c", cmd]
        else:
            shell_cmd = cmd

        started = time.monotonic()
        result = container.exec_run(
            cmd=shell_cmd,
            user=user,
            workdir=workdir,
            environment=environment or {},
            demux=True,
            tty=False,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)

        stdout_bytes, stderr_bytes = result.output or (b"", b"")
        return ExecResult(
            exit_code=result.exit_code or 0,
            stdout=(stdout_bytes or b"").decode("utf-8", errors="replace").strip(),
            stderr=(stderr_bytes or b"").decode("utf-8", errors="replace").strip(),
            duration_ms=elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Compose helpers (delegates to subprocess to reuse existing compose files)
    # ------------------------------------------------------------------

    def compose_up(self, compose_file: str, project_name: str = "gloamfire") -> None:
        import subprocess

        subprocess.run(
            ["docker", "compose", "-f", compose_file, "-p", project_name, "up", "-d"],
            check=True,
        )

    def compose_down(self, compose_file: str, project_name: str = "gloamfire") -> None:
        import subprocess

        subprocess.run(
            ["docker", "compose", "-f", compose_file, "-p", project_name, "down"],
            check=True,
        )

    def raw(self) -> docker.DockerClient:
        """Expose the underlying SDK client for advanced use."""
        return self._client
