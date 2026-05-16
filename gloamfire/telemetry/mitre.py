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
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "Credential Access"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1070.002": {"name": "Clear Linux or Mac System Logs", "tactic": "Defense Evasion"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1548.001": {"name": "Setuid and Setgid", "tactic": "Privilege Escalation"},
    # Discovery (TA0007)
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1087.001": {"name": "Account Discovery: Local Account", "tactic": "Discovery"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "Discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1069": {"name": "Permission Groups Discovery", "tactic": "Discovery"},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "Discovery"},
    # Collection (TA0009)
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1074": {"name": "Data Staged", "tactic": "Collection"},
    "T1074.001": {"name": "Data Staged: Local Data Staging", "tactic": "Collection"},
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection"},
    "T1560.001": {"name": "Archive via Utility", "tactic": "Collection"},
    # Exfiltration (TA0010)
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1048.003": {
        "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
        "tactic": "Exfiltration",
    },
    # Persistence (TA0003) additions
    "T1136": {"name": "Create Account", "tactic": "Persistence"},
    "T1136.001": {"name": "Create Account: Local Account", "tactic": "Persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    # Defense Evasion (TA0005) additions
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1036.005": {
        "name": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
    },
    "T1070.003": {"name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion"},
    "T1222": {"name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion"},
    # Lateral Movement (TA0008)
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.004": {"name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    # Discovery (TA0007) additions
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T1033": {"name": "System Owner/User Discovery", "tactic": "Discovery"},
    # Execution (TA0002) additions
    "T1059.006": {"name": "Command and Scripting Interpreter: Python", "tactic": "Execution"},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion"},
    "T1027.002": {"name": "Obfuscated Files or Information: Software Packing", "tactic": "Defense Evasion"},
    # C2 (TA0011) additions
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "T1132": {"name": "Data Encoding", "tactic": "Command and Control"},
    "T1132.001": {"name": "Data Encoding: Standard Encoding", "tactic": "Command and Control"},
    # Persistence (TA0003) additions
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence"},
    "T1543.002": {"name": "Create or Modify System Process: Systemd Service", "tactic": "Persistence"},
    # Privilege Escalation / Defense Evasion additions
    "T1574": {"name": "Hijack Execution Flow", "tactic": "Defense Evasion"},
    "T1574.006": {"name": "Hijack Execution Flow: LD_PRELOAD", "tactic": "Defense Evasion"},
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
