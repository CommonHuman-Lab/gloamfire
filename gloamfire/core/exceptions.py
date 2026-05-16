# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Gloamfire custom exception hierarchy."""


class GloamfireError(Exception):
    """Base exception for all Gloamfire errors."""


class ScenarioNotFoundError(GloamfireError):
    """Raised when a named scenario cannot be located."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Scenario not found: {name!r}")
        self.name = name


class ScenarioValidationError(GloamfireError):
    """Raised when a scenario YAML fails schema validation."""

    def __init__(self, path: str, detail: str) -> None:
        super().__init__(f"Invalid scenario {path!r}: {detail}")
        self.path = path
        self.detail = detail


class AttackNotFoundError(GloamfireError):
    """Raised when a scenario references an unregistered attack plugin."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Attack plugin not found: {name!r}")
        self.name = name


class ContainerNotFoundError(GloamfireError):
    """Raised when the target container is not running."""

    def __init__(self, name: str) -> None:
        super().__init__(
            f"Container {name!r} is not running. "
            f"Start victim containers with: gloamfire up"
        )
        self.name = name


class DockerUnavailableError(GloamfireError):
    """Raised when the Docker daemon cannot be reached."""

    def __init__(self) -> None:
        super().__init__(
            "Docker daemon is not available. "
            "Ensure Docker is running: sudo systemctl start docker"
        )


class ExecutionError(GloamfireError):
    """Raised when an attack step fails unexpectedly during execution."""

    def __init__(self, step_id: str, detail: str) -> None:
        super().__init__(f"Step {step_id!r} failed: {detail}")
        self.step_id = step_id
        self.detail = detail


class DetectionBackendError(GloamfireError):
    """Raised when a detection backend (Wazuh, Suricata) cannot be reached."""

    def __init__(self, backend: str, detail: str) -> None:
        super().__init__(f"Detection backend {backend!r} unavailable: {detail}")
        self.backend = backend
        self.detail = detail
