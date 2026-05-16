# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: log_tampering — T1070.002 Clear Linux or Mac System Logs / T1070 Indicator Removal

SAFE simulation: creates a fake auth log in /tmp, then clears it, clears bash history.
Does NOT touch real system log files (/var/log/auth.log, /var/log/syslog).
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "log-clear-sim.gloamfire.invalid"


@register
class LogTamperingAttack(BaseAttack):
    name = "log_tampering"
    description = "Simulate log file clearing and bash history wiping (T1070.002)"
    mitre = ["T1070", "T1070.002"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        fake_log = params.get("fake_log", "/tmp/gloamfire_fake_auth.log")
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] Log tampering simulation starting"
# Create a fake auth log with realistic content
cat > {fake_log} << 'EOF'
May 16 12:00:01 victim sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2
May 16 12:00:03 victim sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2
May 16 12:01:00 victim sudo[5678]: pam_unix(sudo:auth): authentication failure
May 16 12:01:45 victim su[9999]: FAILED su for root by www-data
EOF
echo "Fake log created: $(wc -l < {fake_log}) lines"
# Simulate clearing the log
echo "" > {fake_log}
echo "Log cleared: $(wc -c < {fake_log}) bytes remaining"
# Simulate bash history wipe
echo "" > /tmp/gloamfire_fake_history
echo "[Gloamfire] Log tampering simulation complete"
"""
        result = self._exec(target, script)
        result.metadata["fake_log"] = fake_log

        # Unique DNS beacon → Suricata rule 9000021
        self._exec(
            target,
            f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true",
        )
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class LogTamperingCleanup(BaseAttack):
    name = "log_tampering_cleanup"
    description = "Remove log tampering simulation artefacts"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        fake_log = params.get("fake_log", "/tmp/gloamfire_fake_auth.log")
        return self._exec(target, f"rm -f {fake_log} /tmp/gloamfire_fake_history")
