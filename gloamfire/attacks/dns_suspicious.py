# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: dns_suspicious — T1071.004 Application Layer Protocol: DNS

Simulates suspicious DNS activity including high-entropy subdomain lookups
(C2 DGA pattern) and lookups to known IDS test domains. Uses nslookup/dig
to generate realistic DNS telemetry visible to Suricata and Wazuh.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_IDS_TEST_DOMAIN = "testmynids.org"
_DGA_DOMAINS = [
    "a1b2c3d4e5f6.evil-c2-sim.example.com",
    "xk9mzp2qrvn8.dga-beacon-sim.example.com",
    "beacon.gloamfire-dns-sim.invalid",
]


@register
class SuspiciousDNSAttack(BaseAttack):
    name = "dns_suspicious"
    description = "Simulate suspicious DNS lookups (DGA pattern + IDS test domains)"
    mitre = ["T1071.004", "T1568.002"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        domains = params.get("domains", _DGA_DOMAINS + [_IDS_TEST_DOMAIN])
        resolver = params.get("resolver", "8.8.8.8")

        # Build a script that performs all lookups — partial failures are fine
        lookup_cmds = "\n".join(
            f"nslookup {d} {resolver} 2>/dev/null || dig +short {d} @{resolver} 2>/dev/null || true"
            for d in domains
        )
        script = f"""
echo "[Gloamfire] Starting suspicious DNS simulation"
{lookup_cmds}
echo "[Gloamfire] DNS simulation complete"
"""
        result = self._exec(target, script)
        result.metadata.update({"domains": domains, "resolver": resolver})
        self._write_attack_log(target, self.name)
        return result
