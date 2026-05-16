# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: reverse_shell — T1059.004 Unix Shell

SAFE simulation of reverse shell behaviour.
Spawns a background nc process that immediately times out on a dead port,
producing the characteristic process tree / network telemetry without
establishing any real connection or executing malicious code.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register


@register
class ReverseShellAttack(BaseAttack):
    name = "reverse_shell"
    description = "Simulate reverse shell attempt (safe — dead-port timeout)"
    mitre = ["T1059.004", "T1071.001"]

    _DEFAULT_HOST = "192.0.2.1"  # RFC 5737 TEST-NET-1, not routable
    _DEFAULT_PORT = 4444

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        lhost = params.get("lhost", self._DEFAULT_HOST)
        lport = params.get("lport", self._DEFAULT_PORT)
        timeout = params.get("timeout", 3)

        # The shell invocation pattern is what IDS signatures look for.
        # nc will fail immediately on the non-routable address — that's
        # intentional. The command string itself is the artefact.
        cmd = (
            f"bash -c 'nc -w {timeout} {lhost} {lport} </dev/null >/dev/null 2>&1 || true'"
        )

        result = self._exec(target, cmd)
        result.metadata.update({"lhost": lhost, "lport": lport, "timeout": timeout})
        self._write_attack_log(target, self.name)
        return result
