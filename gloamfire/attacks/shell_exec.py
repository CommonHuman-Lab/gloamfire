# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Attack: shell_exec — run an arbitrary shell command inside a target container."""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register


@register
class ShellExecAttack(BaseAttack):
    name = "shell_exec"
    description = "Execute an arbitrary shell command in the target container (setup/cleanup)"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        cmd = params.get("cmd", "true")
        return self._exec(target, cmd)
