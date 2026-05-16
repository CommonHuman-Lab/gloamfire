# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: python_exec — Execution / Defense Evasion
T1059.006  Command and Scripting Interpreter: Python
T1140      Deobfuscate/Decode Files or Information
T1027.002  Obfuscated Files or Information: Software Packing

SAFE simulation: executes a base64-encoded Python one-liner that decodes itself
at runtime (common real-world staging technique). No destructive payload.
"""

from __future__ import annotations

import base64
from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "pyexec-sim.gloamfire.invalid"

# Payload that looks like obfuscated C2 staging but is completely harmless
_SAFE_PAYLOAD = (
    "import os,socket\n"
    "print('[Gloamfire] Python exec simulation')\n"
    "print('hostname:', socket.gethostname())\n"
    "print('uid:', os.getuid())\n"
    "print('NOTE: SIMULATION ONLY — no real payload')\n"
)


@register
class PythonExecAttack(BaseAttack):
    name = "python_exec"
    description = (
        "Simulate Python-based payload execution with base64 decode-and-run staging "
        "(T1059.006, T1140, T1027.002)"
    )
    mitre = ["T1059.006", "T1140", "T1027.002"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        payload = params.get("payload", _SAFE_PAYLOAD)
        resolver = params.get("resolver", "8.8.8.8")
        drop_file = "/tmp/gloamfire_pyexec_staged.b64"

        encoded = base64.b64encode(payload.encode()).decode()

        script = f"""
echo "[Gloamfire] Python exec simulation starting"

# T1027.002 / T1140 — write encoded payload, decode and execute at runtime
echo '{encoded}' > {drop_file}
echo "[Gloamfire] Encoded payload staged at {drop_file}"

# T1059.006 — Python execution: decode and run inline
python3 -c "import base64; exec(base64.b64decode(open('{drop_file}').read()).decode())"

# Also demonstrate direct Python one-liner pattern (T1059.006)
python3 -c "import subprocess; r = subprocess.run(['id'], capture_output=True, text=True); print(r.stdout.strip())"

echo "[Gloamfire] Python exec simulation complete"
"""
        result = self._exec(target, script)
        result.metadata["drop_file"] = drop_file
        result.metadata["encoded_len"] = len(encoded)

        self._exec(target, f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class PythonExecCleanup(BaseAttack):
    name = "python_exec_cleanup"
    description = "Remove python exec staged payload"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        return self._exec(target, "rm -f /tmp/gloamfire_pyexec_staged.b64")
