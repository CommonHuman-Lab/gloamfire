# CLI Commands

## gloamfire up

Boot the full lab (victims + Wazuh SIEM + Suricata IDS).

```bash
gloamfire up
```

- Starts three victim containers on an isolated network
- Builds and starts the Wazuh manager, indexer, and dashboard
- Downloads 50,000+ Emerging Threats rules into Suricata

## gloamfire down

Tear down all running containers.

```bash
gloamfire down
```

## gloamfire dashboard

```bash
gloamfire dashboard
```

Opens a browser to `http://127.0.0.1:7100`. Use `--port` to change the default port, `--no-open` to skip auto-launching the browser.

## gloamfire simulate

### Run all simulations

```bash
gloamfire simulate all
```

### Run a single scenario

```bash
gloamfire simulate run <scenario-name>
```

[All available scenarios](https://github.com/CommonHuman-Lab/gloamfire/wiki/Available_Scenarios)

[Custom Scenario](https://github.com/CommonHuman-Lab/gloamfire/wiki/Custom_Scenario)

### Run a scenario chain

```bash
gloamfire simulate chain kill-chain
```

Runs an ordered sequence of scenarios defined in a YAML file. The built-in `kill_chain` covers all simulations in a realistic attack sequence.

[Custom Chain](https://github.com/CommonHuman-Lab/gloamfire/wiki/Custom_Chain)

### Capture network traffic (PCAP)

Append `--pcap` to any `simulate` command to run `tcpdump` inside the victim container for the duration of the simulation and copy the `.pcap` to the host.

```bash
gloamfire simulate run suspicious-curl --pcap
gloamfire simulate run credential-dump --pcap --pcap-out ./captures/cred.pcap
gloamfire simulate all --pcap --pcap-dir ./captures/
```

Open the result in Wireshark to inspect the exact packets each attack generates.

## gloamfire export

### ATT&CK Navigator heatmap

```bash
gloamfire export navigator
```

Reads accumulated telemetry and writes `navigator_layer.json`. Upload it at [attack-navigator](https://mitre-attack.github.io/attack-navigator/) → Open Existing Layer → Upload from local.

## gloamfire lab

Manage victim and monitor stacks independently.

```bash
gloamfire lab up victims
gloamfire lab up monitor
gloamfire lab status
```

**Wazuh dashboard** — `https://localhost:5601` (admin / admin)
