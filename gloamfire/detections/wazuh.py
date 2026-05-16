# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Wazuh detection collector.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from gloamfire.core.models import ExecutionEvent
from gloamfire.detections.base import BaseDetectionCollector

log = logging.getLogger(__name__)

_BIND_MOUNT_ALERTS = (
    Path(__file__).parent.parent.parent
    / "docker" / "monitor" / "logs" / "wazuh" / "alerts" / "alerts.json"
)
_DEFAULT_ALERTS = Path(os.environ.get("WAZUH_ALERTS_LOG", str(_BIND_MOUNT_ALERTS)))


class WazuhCollector(BaseDetectionCollector):
    source = "wazuh"

    def __init__(
        self,
        alerts_path: Path = _DEFAULT_ALERTS,
        poll_interval_s: float = 2.0,
    ) -> None:
        self._alerts = alerts_path
        self._poll_interval = poll_interval_s

    def is_available(self) -> bool:
        return self._alerts.exists() and self._alerts.is_file()

    def fetch_alerts(
        self,
        since_event: ExecutionEvent,
        window_s: int = 30,
    ) -> list[dict[str, Any]]:
        if not self.is_available():
            return []

        deadline = time.monotonic() + window_s
        since_ts = since_event.timestamp

        while time.monotonic() < deadline:
            alerts = self._read_alerts_since(since_ts)
            if alerts:
                return alerts
            time.sleep(self._poll_interval)

        return []

    def _read_alerts_since(self, since: datetime) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        try:
            with self._alerts.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ts_str = record.get("timestamp", "")
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts >= since:
                            alerts.append(record)
                    except ValueError:
                        continue
        except OSError as exc:
            log.warning("Cannot read Wazuh alerts log: %s", exc)
        return alerts

    def _alert_rule_id(self, alert: dict[str, Any]) -> str:
        return str(alert.get("rule", {}).get("id", ""))
