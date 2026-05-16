# Gloamfire

<p align="center"><em>Purple-team attack replay and detection validation platform</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-blue.svg" />
  <img src="https://img.shields.io/badge/Runtime-Docker-blue.svg" />
  <img src="https://img.shields.io/badge/License-AGPL--3.0-green.svg" />
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-orange.svg" />
</p>

---

Gloamfire is a **local-first, Docker-native adversary simulation and detection validation framework** for SOC teams, purple teams, homelabs, and detection engineers.

It safely simulates attack techniques inside isolated Docker containers, validates that your detections fire, and maps everything to MITRE ATT&CK — fully offline with no cloud dependencies.

> **This is NOT malware.** All simulations are safe, sandboxed, and deterministic.

---

## Quick Start

**Prerequisites:** Python 3.12+, Docker Engine with Compose plugin, 4 GB RAM free.

```bash
# Kali / Debian / Ubuntu — venv required on externally-managed Python
python3 -m venv .venv && source .venv/bin/activate
pip install gloamfire
```

Or from source:

```bash
git clone https://github.com/CommonHuman-Lab/gloamfire.git
cd gloamfire
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

### Boot the full lab (victims + Wazuh SIEM + Suricata IDS)

```bash
gloamfire up
```

This single command:

- Starts three victim containers on an isolated network
- Builds and starts the Wazuh 4.8 manager, indexer, and dashboard
- Downloads 50,000+ Emerging Threats rules into Suricata
- Waits for the Wazuh agent to enrol — then you're ready

### Run all six simulations

```bash
gloamfire simulate all
```

Or run them individually:

```bash
gloamfire simulate suspicious-curl
gloamfire simulate reverse-shell
gloamfire simulate fake-ransomware
gloamfire simulate encoded-command
gloamfire simulate persistence
gloamfire simulate suspicious-dns
```

Each prints a result table showing `[PASS]` or `[FAIL]` for every detection backend. `simulate all` adds a combined summary at the end.

### Run a scenario chain

```bash
gloamfire simulate chain kill-chain
```

Runs an ordered sequence of scenarios defined in a YAML file. The built-in `kill_chain` covers all six simulations in a realistic attack sequence. Write your own:

```yaml
# scenarios/chains/my_chain.yaml
name: my_chain
description: Custom attack sequence
on_fail: stop   # stop | continue (default: continue)
scenarios:
  - suspicious_curl
  - reverse_shell
  - fake_ransomware
```

Then run it:

```bash
gloamfire simulate chain my_chain
gloamfire simulate chain ./scenarios/chains/my_chain.yaml --export ./output
```

### Export an ATT&CK Navigator heatmap

```bash
gloamfire export navigator
```

Reads accumulated telemetry from `gloamfire_telemetry.jsonl` and writes `navigator_layer.json`. Upload it at [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/) → Open Existing Layer → Upload from local.

### Tear down

```bash
gloamfire down
```

---

## Available Scenarios

| Name | Severity | MITRE Techniques | Detection trigger |
| ---- | -------- | ---------------- | ----------------- |
| `suspicious_curl` | High | T1105 | GPL ATTACK_RESPONSE (testmynids.org HTTP) |
| `reverse_shell` | High | T1059.004, T1071.001 | Outbound TCP SYN to port 4444 |
| `fake_ransomware` | High | T1486 | C2 beacon HTTP after mass file rename |
| `encoded_command` | High | T1027, T1059.004 | C2 beacon HTTP after base64 exec |
| `persistence` | High | T1053.005 | C2 beacon HTTP after cron install |
| `suspicious_dns` | High | T1071.004, T1568.002 | DGA-style DNS queries |
| `credential_dump` | **Critical** | T1003, T1552.001 | /etc/shadow access + exfil DNS beacon |
| `log_tampering` | **Critical** | T1070, T1070.002 | Log clear DNS beacon + C2 HTTP |
| `privilege_escalation` | **Critical** | T1548, T1548.001 | SUID enum + privesc DNS beacon |

All nine pass both **Wazuh** (custom rules 100002–100010, levels 10–15) and **Suricata** (ET Open + custom rules 9000001–9000022) out of the box.

---

## Architecture

```text
gloamfire up
  ├─ victims stack   ──  gloamfire-ubuntu, gloamfire-workstation, gloamfire-vuln-web
  └─ monitor stack   ──  wazuh.manager, wazuh.indexer, wazuh.dashboard
       ├─ gloamfire-wazuh-agent  (reads attacks.log, forwards events to manager)
       └─ gloamfire-suricata     (AF_PACKET on Docker bridge, ET Open + custom rules)

gloamfire simulate <name>
  ├─ runs attack plugin inside victim container
  ├─ writes to attacks.log  →  Wazuh alert  →  WazuhCollector reads alerts.json
  └─ generates network traffic  →  Suricata alert  →  SuricataCollector reads eve.json
```

- **Plugin registry** — Attack modules self-register at import time; adding a simulation is one Python file.
- **YAML-driven scenarios** — Scenarios are data, not code.
- **File-based collection** — No API or OpenSearch connection needed; collectors read bind-mounted log files directly.
- **Isolated network** — Victim containers run on `gloamfire-attack-net` (172.30.0.0/24).

---

## Monitor Stack

The monitor stack (Wazuh + Suricata) is included in `gloamfire up`. You can also manage stacks independently:

```bash
gloamfire lab up victims
gloamfire lab up monitor
gloamfire lab status
```

**Wazuh dashboard** — `https://localhost:5601` (admin / admin)

---

## Writing a Custom Scenario

Create `scenarios/my_scenario.yaml`:

```yaml
name: my_scenario
description: My custom attack simulation
mitre:
  - T1059.004

steps:
  - id: step_one
    attack: encoded_command
    target: gloamfire-ubuntu
    params:
      payload: 'id && whoami'

expect:
  - source: wazuh
    rule_id: "100005"
    description: "Wazuh detects encoded command"
    required: true
  - source: suricata
    description: "Suricata detects C2 beacon"
    required: true

cleanup:
  - id: cleanup
    attack: shell_exec
    target: gloamfire-ubuntu
    params:
      cmd: "rm -f /tmp/my_artefact"
```

Run it:

```bash
gloamfire simulate run my_scenario
```

---

## Writing a Custom Attack Plugin

Create `gloamfire/attacks/my_attack.py`:

```python
from typing import Any
from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

@register
class MyAttack(BaseAttack):
    name = "my_attack"          # matches `attack:` key in scenario YAML
    description = "My simulation"
    mitre = ["T1059"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        result = self._exec(target, "echo hello from Gloamfire")
        self._c2_beacon(target)                    # generates a Suricata HTTP alert
        self._write_attack_log(target, self.name)  # generates a Wazuh alert
        return result
```

The plugin is available immediately — no registration step required.

---

## Development

```bash
pip install -e ".[dev]"

pytest tests/unit/ tests/scenarios/   # no Docker required
pytest                                 # full suite (requires Docker)

ruff check gloamfire/ tests/
ruff format gloamfire/ tests/
mypy gloamfire/
```

---

## Requirements

- Python 3.12+
- Docker Engine with Compose plugin (daemon running)
- 2 GB RAM for the victim stack only
- 4 GB RAM for the full lab (victims + monitor)

---

## Roadmap

- [ ] Sigma rule validation backend
- [ ] Windows AD victim container
- [ ] PCAP capture from simulations
- [ ] Web UI for scenario management

---

## Related

[OctoRig](https://github.com/CommonHuman-Lab/OctoRig) — Docker-based vulnerable lab launcher (Juice Shop, DVWA, Metasploitable, and more).

---

## License

AGPL-3.0-or-later © 2026 CommonHuman-Lab
