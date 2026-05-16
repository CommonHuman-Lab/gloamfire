# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""MITRE ATT&CK technique metadata — offline lookup table for MVP."""

from __future__ import annotations

from dataclasses import dataclass

# Offline subset of ATT&CK Enterprise — extend as needed.
_TECHNIQUE_DB: dict[str, dict[str, str]] = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task/Job: Cron", "tactic": "Persistence"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1568": {"name": "Dynamic Resolution", "tactic": "Command and Control"},
    "T1568.002": {"name": "Domain Generation Algorithms", "tactic": "Command and Control"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
}


@dataclass
class TechniqueInfo:
    technique_id: str
    technique_name: str
    tactic: str

    @property
    def url(self) -> str:
        base_id = self.technique_id.split(".")[0]
        return f"https://attack.mitre.org/techniques/{base_id}/"


def lookup(technique_id: str) -> TechniqueInfo:
    tid = technique_id.upper()
    data = _TECHNIQUE_DB.get(tid, {})
    return TechniqueInfo(
        technique_id=tid,
        technique_name=data.get("name", "Unknown Technique"),
        tactic=data.get("tactic", "Unknown Tactic"),
    )


def lookup_many(technique_ids: list[str]) -> list[TechniqueInfo]:
    return [lookup(t) for t in technique_ids]


def format_mitre_table(technique_ids: list[str]) -> list[dict[str, str]]:
    """Return a list of dicts suitable for Rich Table or JSON export."""
    return [
        {
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactic": t.tactic,
            "url": t.url,
        }
        for t in lookup_many(technique_ids)
    ]
