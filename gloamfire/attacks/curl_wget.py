# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Attack: suspicious_curl — T1105 Ingress Tool Transfer

Simulates an attacker downloading a remote payload via curl or wget.
Uses testmynids.org, a legitimate IDS-testing endpoint designed for exactly
this purpose. The file is written to /tmp and removed in cleanup.
"""

from __future__ import annotations

from typing import Any

from gloamfire.attacks.base import AttackResult, BaseAttack
from gloamfire.core.registry import register


@register
class CurlWgetAttack(BaseAttack):
    name = "curl_wget"
    description = "Simulate suspicious remote file download via curl or wget"
    mitre = ["T1105"]

    _TEST_URL = "http://testmynids.org/uid/index.html"
    _OUTPUT_PATH = "/tmp/gloamfire_sim_download"

    def execute(self, target: str, params: dict[str, Any]) -> AttackResult:
        url = params.get("url", self._TEST_URL)
        method = params.get("method", "curl").lower()
        output = params.get("output", self._OUTPUT_PATH)

        if method == "wget":
            cmd = f"wget -q -O {output} {url}"
        else:
            cmd = f"curl -sSL -o {output} --max-time 10 {url}"

        result = self._exec(target, cmd)
        result.metadata["url"] = url
        result.metadata["method"] = method
        result.metadata["output_path"] = output
        self._write_attack_log(target, self.name)
        return result
