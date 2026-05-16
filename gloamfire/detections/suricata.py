# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Suricata detection collector.
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

_BIND_MOUNT_EVE = (
    Path(__file__).parent.parent.parent / "docker" / "monitor" / "logs" / "suricata" / "eve.json"
)
_DEFAULT_EVE = Path(os.environ.get("SURICATA_EVE_LOG", str(_BIND_MOUNT_EVE)))


class SuricataCollector(BaseDetectionCollector):
    source = "suricata"

    def __init__(
        self,
        eve_path: Path = _DEFAULT_EVE,
        poll_interval_s: float = 2.0,
    ) -> None:
        self._eve = eve_path
        self._poll_interval = poll_interval_s

    def is_available(self) -> bool:
        return self._eve.exists() and self._eve.is_file()

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
            with self._eve.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("event_type") != "alert":
                        continue
                    ts_str = record.get("timestamp", "")
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts >= since:
                            alerts.append(record)
                    except ValueError:
                        continue
        except OSError as exc:
            log.warning("Cannot read Suricata EVE log: %s", exc)
        return alerts

    def _alert_rule_id(self, alert: dict[str, Any]) -> str:
        return str(alert.get("alert", {}).get("signature_id", ""))
