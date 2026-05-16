# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: fake_ransomware — T1486 Data Encrypted for Impact

SAFE simulation: creates dummy "document" files in /tmp, renames them with
an .gloamfire_enc extension to mimic mass encryption, drops a ransom note,
then (in the cleanup step) removes everything. No real encryption occurs.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register


@register
class FakeRansomwareAttack(BaseAttack):
    name = "fake_ransomware"
    description = "Simulate ransomware file-rename activity (no real encryption)"
    mitre = ["T1486"]

    _SIM_DIR = "/tmp/gloamfire_ransomware_sim"
    _FILE_COUNT = 20

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        sim_dir = params.get("sim_dir", self._SIM_DIR)
        file_count = int(params.get("file_count", self._FILE_COUNT))
        ext = params.get("extension", ".gloamfire_enc")

        script = f"""
set -e
mkdir -p {sim_dir}
# Create dummy documents
for i in $(seq 1 {file_count}); do
    echo "Confidential document $i — Gloamfire Simulation" > {sim_dir}/document_$i.txt
done
# Simulate "encryption" by mass rename
for f in {sim_dir}/*.txt; do
    mv "$f" "$f{ext}"
done
# Drop ransom note
cat > {sim_dir}/README_RESTORE.txt << 'RANSOM'
YOUR FILES HAVE BEEN ENCRYPTED.
[Gloamfire Simulation — No real encryption occurred]
RANSOM
echo "Renamed $(ls {sim_dir}/*.txt* | wc -l) files in {sim_dir}"
"""
        result = self._exec(target, script)
        result.metadata.update({
            "sim_dir": sim_dir,
            "file_count": file_count,
            "extension": ext,
        })
        # C2 beacon: simulates ransom note exfil attempt → Suricata GPL alert fires.
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class FakeRansomwareCleanup(BaseAttack):
    name = "fake_ransomware_cleanup"
    description = "Remove ransomware simulation artefacts"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        sim_dir = params.get("sim_dir", FakeRansomwareAttack._SIM_DIR)
        cmd = f"rm -rf {sim_dir}"
        return self._exec(target, cmd)
