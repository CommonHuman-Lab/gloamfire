# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: data_collection — Collection (TA0009)
T1005 Data from Local System
T1074 Data Staged
T1560 Archive Collected Data
T1560.001 Archive via Utility

SAFE simulation: searches for config/log files, creates a fake-sensitive staging
directory in /tmp, archives it with tar. No real data leaves the container.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "collection-sim.gloamfire.invalid"
_STAGE_DIR = "/tmp/gloamfire_stage"
_ARCHIVE = "/tmp/gloamfire_collected.tar.gz"


@register
class DataCollectionAttack(BaseAttack):
    name = "data_collection"
    description = "Simulate data collection — local file search, staging, and archiving (T1005, T1074, T1560)"
    mitre = ["T1005", "T1074", "T1560", "T1560.001"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        stage = params.get("stage_dir", _STAGE_DIR)
        archive = params.get("archive", _ARCHIVE)
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] Data collection simulation starting"

# T1005 — collect data from local system (config files, env vars)
mkdir -p {stage}
find /etc -maxdepth 1 -name "*.conf" 2>/dev/null | head -5 | xargs -I{{}} cp {{}} {stage}/ 2>/dev/null || true
env > {stage}/env_dump.txt 2>/dev/null || true
echo "SIMULATION_ONLY=true" > {stage}/credentials_sim.txt
echo "DB_PASS=FAKE_NOT_REAL" >> {stage}/credentials_sim.txt

# T1074 — stage collected files
echo "[Gloamfire] Files staged: $(ls {stage} | wc -l)"

# T1560 — archive staged data
tar czf {archive} -C /tmp gloamfire_stage 2>/dev/null
echo "[Gloamfire] Archive created: $(du -sh {archive} | cut -f1)"
echo "[Gloamfire] Data collection simulation complete"
"""
        result = self._exec(target, script)
        result.metadata["stage_dir"] = stage
        result.metadata["archive"] = archive

        self._exec(target, f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class DataCollectionCleanup(BaseAttack):
    name = "data_collection_cleanup"
    description = "Remove data collection staging directory and archive"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        stage = params.get("stage_dir", _STAGE_DIR)
        archive = params.get("archive", _ARCHIVE)
        return self._exec(target, f"rm -rf {stage} {archive}")
