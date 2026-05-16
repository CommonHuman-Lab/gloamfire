# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: encoded_command — T1027 Obfuscated Files or Information

Simulates PowerShell-style base64-encoded command execution on Linux.
The payload decodes to a harmless echo statement — the encoded form is what
triggers IDS/EDR signatures for obfuscated execution patterns.
"""

from __future__ import annotations

import base64
from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DEFAULT_PAYLOAD = 'echo "[Gloamfire] Encoded command simulation — $(hostname) $(date)"'


@register
class EncodedCommandAttack(BaseAttack):
    name = "encoded_command"
    description = "Simulate base64-obfuscated command execution (Linux powershell pattern)"
    mitre = ["T1027", "T1059.004"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        payload = params.get("payload", _DEFAULT_PAYLOAD)
        encoded = base64.b64encode(payload.encode()).decode()

        # This pattern (pipe base64 -d | bash) is a well-known IDS trigger.
        cmd = f"echo '{encoded}' | base64 -d | bash"

        result = self._exec(target, cmd)
        result.metadata.update({
            "encoded_payload": encoded,
            "decoded_payload": payload,
        })
        # C2 beacon: simulates post-execution check-in → Suricata GPL alert fires.
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result
