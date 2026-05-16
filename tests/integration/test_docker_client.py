# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Integration tests for DockerClient.

These tests require a live Docker daemon. They are skipped automatically
when Docker is unavailable (CI without Docker, unit-only runs, etc.).
"""

from __future__ import annotations

import pytest

from gloamfire.core.docker_client import DockerClient
from gloamfire.core.exceptions import ContainerNotFoundError, DockerUnavailableError


def _docker_available() -> bool:
    try:
        DockerClient()
        return True
    except DockerUnavailableError:
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker daemon not available",
)


@requires_docker
class TestDockerClientLive:
    def test_client_connects(self):
        client = DockerClient()
        assert client is not None

    def test_list_gloamfire_containers(self):
        client = DockerClient()
        containers = client.list_gloamfire_containers()
        assert isinstance(containers, list)

    def test_container_not_found_raises(self):
        client = DockerClient()
        with pytest.raises(ContainerNotFoundError):
            client.get_container("gloamfire-nonexistent-xyz-abc")

    def test_container_running_returns_bool(self):
        client = DockerClient()
        result = client.container_running("gloamfire-nonexistent-xyz-abc")
        assert result is False
