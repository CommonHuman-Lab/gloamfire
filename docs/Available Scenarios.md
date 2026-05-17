# Available Scenarios

20 scenarios covering **~55 MITRE ATT&CK techniques across 11 of 14 tactics**.

Run them individually

```bash
# Example 
gloamfire simulate suspicious-curl
```

## Execution

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `suspicious_curl` | High | T1105 | GPL ATTACK_RESPONSE (testmynids.org HTTP) |
| `reverse_shell` | High | T1059.004, T1071.001 | Outbound TCP SYN to port 4444 |
| `encoded_command` | High | T1027, T1059.004 | C2 beacon HTTP after base64 exec |
| `python_exec` | High | T1059.006, T1140, T1027.002 | Python decode-and-run + DNS beacon |

## Persistence

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `persistence` | High | T1053.005 | C2 beacon HTTP after cron install |
| `account_backdoor` | High | T1136, T1136.001, T1098 | Backdoor account DNS beacon + fake sudoers |
| `service_persistence` | High | T1543, T1543.002 | Systemd service unit DNS beacon |

## Privilege Escalation

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `privilege_escalation` | **Critical** | T1548, T1548.001 | SUID enum + privesc DNS beacon |
| `env_hijack` | High | T1574, T1574.006 | LD_PRELOAD inject + PATH hijack DNS beacon |

## Defense Evasion

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `defense_evasion` | High | T1070.003, T1036, T1036.005, T1222, T1562.001 | History clear + masquerade binary + chmod |
| `log_tampering` | **Critical** | T1070, T1070.002 | Log clear DNS beacon + C2 HTTP |

## Credential Access

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `credential_dump` | **Critical** | T1003, T1552.001 | /etc/shadow access + exfil DNS beacon |

## Discovery

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `recon` | High | T1082, T1083, T1087, T1016, T1057, T1069, T1049 | Recon DNS beacon after host/network discovery |
| `network_scan` | High | T1046, T1018, T1033 | nmap subnet scan + DNS beacon |
| `suspicious_dns` | High | T1071.004, T1568.002 | DGA-style DNS queries |

## Lateral Movement

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `lateral_move` | High | T1021, T1021.004, T1570 | SSH probe to port 22 + pivot DNS beacon |

## Collection & Exfiltration

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `data_collection` | High | T1005, T1074, T1560, T1560.001 | Collection DNS beacon after file staging + tar |
| `exfil_http` | High | T1041, T1048, T1048.003 | HTTP POST + DNS exfil to non-routable C2 |

## Command & Control

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `c2_icmp` | High | T1095, T1132, T1132.001 | ICMP size-encoded beacon + DNS beacon |

## Impact

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `fake_ransomware` | High | T1486 | C2 beacon HTTP after mass file rename |

All scenarios pass both **Wazuh** (custom rules 100002–100021, levels 10–15) and **Suricata** (ET Open + custom rules 9000001–9000037) out of the box.