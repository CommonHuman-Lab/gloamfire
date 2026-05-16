# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: persistence — T1053.005 Scheduled Task/Job: Cron

Simulates cron-based persistence: installs a cron entry that would execute
a backdoor script, then immediately removes it. The install event is the
artefact that detection rules key on.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register


@register
class PersistenceCronAttack(BaseAttack):
    name = "persistence"
    description = "Simulate cron-based persistence installation and removal"
    mitre = ["T1053.005"]

    _CRON_FILE = "/etc/cron.d/gloamfire_sim_persistence"
    _BACKDOOR = "/tmp/gloamfire_backdoor.sh"

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        cron_file = params.get("cron_file", self._CRON_FILE)
        backdoor = params.get("backdoor_path", self._BACKDOOR)
        cron_user = params.get("cron_user", "root")

        script = f"""
set -e
# Stage a fake backdoor script
echo '#!/bin/bash\necho "[Gloamfire sim] persistence beacon"' > {backdoor}
chmod +x {backdoor}

# Install cron persistence entry
echo "# Gloamfire persistence simulation" > {cron_file}
echo "* * * * * {cron_user} {backdoor} > /dev/null 2>&1" >> {cron_file}
echo "Persistence installed: {cron_file}"
cat {cron_file}

# Immediately remove — this is a simulation, not actual persistence
sleep 1
rm -f {cron_file} {backdoor}
echo "Persistence cleaned up"
"""
        result = self._exec(target, script)
        result.metadata.update({
            "cron_file": cron_file,
            "backdoor_path": backdoor,
        })
        # C2 beacon: simulates persistence beacon check-in → Suricata GPL alert fires.
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result
