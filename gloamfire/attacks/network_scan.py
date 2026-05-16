# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: network_scan — Discovery (TA0007)
T1046  Network Service Discovery
T1018  Remote System Discovery
T1033  System Owner/User Discovery

SAFE simulation: nmap discovers all hosts on gloamfire-attack-net (172.30.0.0/24),
identifies open ports on each victim, and enumerates running users/owners.
All commands are standard Linux tools; results written to /tmp only.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "netscan-sim.gloamfire.invalid"
_SCAN_OUTPUT = "/tmp/gloamfire_netscan.txt"


@register
class NetworkScanAttack(BaseAttack):
    name = "network_scan"
    description = "Simulate network and host discovery across the lab subnet (T1046, T1018, T1033)"
    mitre = ["T1046", "T1018", "T1033"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        subnet = params.get("subnet", "172.30.0.0/24")
        resolver = params.get("resolver", "8.8.8.8")
        out = params.get("output_file", _SCAN_OUTPUT)

        script = f"""
echo "[Gloamfire] Network scan simulation starting"

# T1018 — discover live hosts on the subnet
echo "=== Remote System Discovery (T1018) ===" > {out}
nmap -sn {subnet} 2>/dev/null >> {out} || \
  for h in 172.30.0.1 172.30.0.2 172.30.0.3 172.30.0.4; do
    ping -c1 -W1 $h 2>/dev/null && echo "Host up: $h" >> {out} || true
  done

# T1046 — discover open services on discovered hosts
echo "" >> {out}
echo "=== Network Service Discovery (T1046) ===" >> {out}
nmap -T4 -p 22,80,443,8080,8443,3306,5432,6379,27017 \
  --open {subnet} 2>/dev/null >> {out}

# T1033 — identify owner/user of running processes on this host
echo "" >> {out}
echo "=== System Owner/User Discovery (T1033) ===" >> {out}
who >> {out} 2>/dev/null || true
w >> {out} 2>/dev/null || true
last 2>/dev/null | head -10 >> {out} || true

echo "[Gloamfire] Network scan simulation complete"
echo "Results: $(wc -l < {out}) lines written to {out}"
"""
        result = self._exec(target, script)
        result.metadata["output_file"] = out
        result.metadata["subnet"] = subnet

        self._exec(target, f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class NetworkScanCleanup(BaseAttack):
    name = "network_scan_cleanup"
    description = "Remove network scan output"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        out = params.get("output_file", _SCAN_OUTPUT)
        return self._exec(target, f"rm -f {out}")
