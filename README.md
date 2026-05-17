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
- Builds and starts the Wazuh manager, indexer, and dashboard
- Downloads 50,000+ Emerging Threats rules into Suricata

### Tear down

```bash
gloamfire down
```

### Web Dashboard

```bash
gloamfire dashboard
```

Opens a browser to `http://127.0.0.1:7100` with a live dashboard

Use `--port` to change the default port, `--no-open` to skip auto-launching the browser.

### Run all simulations

```bash
gloamfire simulate all
```

[All available scenarios](https://github.com/CommonHuman-Lab/gloamfire/wiki/Available_Scenarios)

### Run a scenario chain

```bash
gloamfire simulate chain kill-chain
```

Runs an ordered sequence of scenarios defined in a YAML file. The built-in `kill_chain` covers all simulations in a realistic attack sequence. 

[Custom Chain](https://github.com/CommonHuman-Lab/gloamfire/wiki/Custom_Chain)

### Capture network traffic (PCAP)

```bash
gloamfire simulate run suspicious-curl --pcap
gloamfire simulate run credential-dump --pcap --pcap-out ./captures/cred.pcap
gloamfire simulate all --pcap --pcap-dir ./captures/
```

Runs `tcpdump` inside the victim container for the duration of the simulation and copies the `.pcap` file to the host. Open the result in Wireshark to inspect the exact packets each attack generates.

### Export an ATT&CK Navigator heatmap

```bash
gloamfire export navigator
```

Reads accumulated telemetry and writes `navigator_layer.json`. Upload it at [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/) → Open Existing Layer → Upload from local.

---

## Available Scenarios

20 scenarios covering **~55 MITRE ATT&CK techniques across 11 of 14 tactics**.

[All available scenarios](https://github.com/CommonHuman-Lab/gloamfire/wiki/Available_Scenarios)
[Custom Scenario](https://github.com/CommonHuman-Lab/gloamfire/wiki/Custom_Scenario)

---

## Architecture

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

## Development

```bash
pip install -e ".[dev]"

pytest tests/unit/ tests/scenarios/   # no Docker required
pytest                                 # full suite (requires Docker)

ruff check gloamfire/ tests/
ruff format gloamfire/ tests/
mypy gloamfire/

#UI
cd ui
npm install
npm run dev       # dev server at :5173, proxies /api to :7100
npm run build     # outputs to gloamfire/api/static/ (served by FastAPI)
```

---

## Related

[OctoRig](https://github.com/CommonHuman-Lab/OctoRig) — Docker-based vulnerable lab launcher (Juice Shop, DVWA, Metasploitable, and more).

---

## License

AGPL-3.0-or-later © 2026 CommonHuman-Lab
