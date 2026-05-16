# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: recon — Discovery (TA0007)
T1082 System Information Discovery
T1083 File and Directory Discovery
T1087 Account Discovery
T1016 System Network Configuration Discovery
T1057 Process Discovery
T1069 Permission Groups Discovery
T1049 System Network Connections Established

SAFE simulation: runs standard discovery commands available on any Linux host.
All output is written to /tmp. No data leaves the container.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "recon-sim.gloamfire.invalid"


@register
class ReconAttack(BaseAttack):
    name = "recon"
    description = "Simulate adversary host/network/account discovery (T1082, T1083, T1087, T1016, T1057, T1069, T1049)"
    mitre = ["T1082", "T1083", "T1087", "T1016", "T1057", "T1069", "T1049"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        out = params.get("output_file", "/tmp/gloamfire_recon.txt")
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] Recon simulation starting"
OUT={out}
echo "=== System Information (T1082) ===" > $OUT
uname -a >> $OUT
cat /etc/os-release >> $OUT 2>/dev/null || true
hostname >> $OUT

echo "=== File & Directory Discovery (T1083) ===" >> $OUT
find /tmp /var /etc -maxdepth 2 -name "*.conf" -o -name "*.log" 2>/dev/null | head -20 >> $OUT

echo "=== Account Discovery (T1087) ===" >> $OUT
cat /etc/passwd >> $OUT
id >> $OUT
who 2>/dev/null >> $OUT || true

echo "=== Network Configuration (T1016) ===" >> $OUT
ip addr 2>/dev/null >> $OUT || ifconfig 2>/dev/null >> $OUT || true
ip route 2>/dev/null >> $OUT || true
cat /etc/resolv.conf >> $OUT 2>/dev/null || true

echo "=== Process Discovery (T1057) ===" >> $OUT
ps aux >> $OUT 2>/dev/null || ps -ef >> $OUT 2>/dev/null || true

echo "=== Permission Groups Discovery (T1069) ===" >> $OUT
cat /etc/group >> $OUT
groups 2>/dev/null >> $OUT || true

echo "=== Network Connections (T1049) ===" >> $OUT
ss -tuln 2>/dev/null >> $OUT || netstat -tuln 2>/dev/null >> $OUT || true

echo "[Gloamfire] Recon simulation complete — $(wc -l < $OUT) lines collected"
"""
        result = self._exec(target, script)
        result.metadata["output_file"] = out

        self._exec(target, f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class ReconCleanup(BaseAttack):
    name = "recon_cleanup"
    description = "Remove recon simulation output file"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        out = params.get("output_file", "/tmp/gloamfire_recon.txt")
        return self._exec(target, f"rm -f {out}")
