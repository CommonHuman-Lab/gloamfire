# Custom Attack Plugin

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