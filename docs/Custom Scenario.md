# Custom Scenario

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
