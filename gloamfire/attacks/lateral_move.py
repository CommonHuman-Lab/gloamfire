# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: lateral_move — Lateral Movement (TA0008)
T1021     Remote Services
T1021.004 Remote Services: SSH
T1570     Lateral Tool Transfer

Two-phase simulation across the isolated gloamfire-attack-net bridge network:

Phase 1 (lateral_move_probe) — runs on gloamfire-ubuntu:
  - Scans workstation with nmap to discover open ports (T1046/T1021)
  - Attempts SSH connection to gloamfire-workstation (fails gracefully — no sshd
    installed on workstation, but the TCP SYN to port 22 hits Suricata)
  - Encodes a fake payload and "transfers" it via netcat to simulate T1570

Phase 2 (lateral_move_pivot) — runs on gloamfire-workstation:
  - Simulates the attacker's post-pivot foothold: runs discovery commands
    and writes decoy files as if already on the second host
  - Fires its own DNS beacon so Suricata sees traffic originating from
    a different container (distinct lateral movement indicator)

SAFE: all traffic stays inside gloamfire-attack-net. No real credentials.
No real SSH session is established.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_PROBE = "lateral-sim.gloamfire.invalid"
_DNS_BEACON_PIVOT = "pivot-sim.gloamfire.invalid"
_PAYLOAD_FILE = "/tmp/gloamfire_lateral_payload.b64"
_PIVOT_MARKER = "/tmp/gloamfire_pivot_marker.txt"

# Workstation sits on the same 172.30.0.0/24 bridge; use hostname — Docker DNS resolves it.
_PIVOT_TARGET = "gloamfire-workstation"


@register
class LateralMoveProbeAttack(BaseAttack):
    name = "lateral_move_probe"
    description = "Phase 1: probe workstation via SSH/nmap and simulate tool transfer (T1021.004, T1570)"
    mitre = ["T1021", "T1021.004", "T1570"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        pivot_host = params.get("pivot_host", _PIVOT_TARGET)
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] Lateral movement probe starting from $(hostname)"

# T1021 — discover services on pivot target
echo "=== Port scan of {pivot_host} (T1021) ==="
nmap -T4 -p 22,80,443,8080 --open {pivot_host} 2>/dev/null || \
  nc -zv -w2 {pivot_host} 22 2>&1 || true

# T1021.004 — SSH lateral movement attempt (generates port-22 traffic Suricata sees)
echo "=== SSH probe to {pivot_host}:22 (T1021.004) ==="
ssh -o ConnectTimeout=3 \
    -o StrictHostKeyChecking=no \
    -o BatchMode=yes \
    root@{pivot_host} "id" 2>&1 || true

# T1570 — lateral tool transfer: encode a fake implant, transfer via netcat
echo "=== Lateral tool transfer to {pivot_host} (T1570) ==="
echo "GLOAMFIRE_SIMULATION=true; echo pivoted > /tmp/implant_sim.sh" | \
  base64 > {_PAYLOAD_FILE}
# Attempt netcat transfer (listener not running — connection refused is expected)
nc -w2 {pivot_host} 9999 < {_PAYLOAD_FILE} 2>/dev/null || true

echo "[Gloamfire] Lateral movement probe complete"
"""
        result = self._exec(target, script)
        result.metadata["pivot_target"] = pivot_host

        self._exec(target, f"nslookup {_DNS_BEACON_PROBE} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, "lateral_move")
        return result


@register
class LateralMovePivotAttack(BaseAttack):
    name = "lateral_move_pivot"
    description = "Phase 2: simulate attacker foothold on the pivot host (T1021.004)"
    mitre = ["T1021.004"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] Pivot simulation running on $(hostname)"

# Simulate post-pivot attacker activity on the second host
echo "=== Running as pivoted attacker on $(hostname) ==="
id
hostname
ip addr 2>/dev/null | grep inet | head -4 || true
ps aux 2>/dev/null | head -10 || true

# Drop a marker file simulating an implant written post-pivot
echo "GLOAMFIRE_SIMULATION=true" > {_PIVOT_MARKER}
echo "PIVOT_FROM=gloamfire-ubuntu" >> {_PIVOT_MARKER}
echo "PIVOT_TO=$(hostname)" >> {_PIVOT_MARKER}
echo "NOTE=Safe simulation — not real persistence" >> {_PIVOT_MARKER}

echo "[Gloamfire] Pivot simulation complete on $(hostname)"
"""
        result = self._exec(target, script)

        # DNS beacon from the pivot host — Suricata sees it as originating from workstation
        self._exec(target, f"nslookup {_DNS_BEACON_PIVOT} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        return result


@register
class LateralMoveCleanup(BaseAttack):
    name = "lateral_move_cleanup"
    description = "Remove lateral movement simulation artefacts from both hosts"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        return self._exec(target, f"rm -f {_PAYLOAD_FILE} {_PIVOT_MARKER} /tmp/implant_sim.sh")
