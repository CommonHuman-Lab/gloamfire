# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Export simulation results to various formats: JSONL, timeline, MITRE map."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gloamfire.core.models import SimulationResult
from gloamfire.telemetry.mitre import format_mitre_table


class ResultExporter:
    """Transforms SimulationResult objects into exportable artefacts."""

    def __init__(self, result: SimulationResult) -> None:
        self._r = result

    # ------------------------------------------------------------------
    # Formats
    # ------------------------------------------------------------------

    def to_jsonl(self, path: Path) -> None:
        """Append structured event log to a JSONL file."""
        with path.open("a") as fh:
            for event in self._r.events:
                fh.write(event.model_dump_json() + "\n")

    def to_timeline(self) -> list[dict[str, Any]]:
        """Return a chronological event timeline suitable for display/export."""
        return [
            {
                "timestamp": event.timestamp.isoformat(),
                "scenario": event.scenario,
                "step": event.step_id,
                "attack": event.attack,
                "target": event.target,
                "exit_code": event.exit_code,
                "duration_ms": event.duration_ms,
                "mitre": event.mitre,
                "success": event.success,
            }
            for event in sorted(self._r.events, key=lambda e: e.timestamp)
        ]

    def to_mitre_map(self) -> list[dict[str, str]]:
        """Return MITRE ATT&CK technique metadata for all techniques in this result."""
        all_ids: list[str] = []
        for event in self._r.events:
            all_ids.extend(event.mitre)
        unique_ids = list(dict.fromkeys(all_ids))
        return format_mitre_table(unique_ids)

    def to_summary(self) -> dict[str, Any]:
        """Return a compact result summary for display."""
        return {
            "scenario": self._r.scenario,
            "started_at": self._r.started_at.isoformat(),
            "duration_s": round(self._r.duration_s, 2),
            "events": len(self._r.events),
            "detections": {
                "passed": self._r.passed,
                "failed": self._r.failed,
                "skipped": self._r.skipped,
            },
            "overall_pass": self._r.overall_pass,
            "dry_run": self._r.dry_run,
        }

    def write_report(self, output_dir: Path) -> dict[str, Path]:
        """Write all artefacts to output_dir and return their paths."""
        output_dir.mkdir(parents=True, exist_ok=True)
        base = output_dir / self._r.scenario

        events_path = base.with_suffix(".events.jsonl")
        timeline_path = base.with_suffix(".timeline.json")
        mitre_path = base.with_suffix(".mitre.json")
        summary_path = base.with_suffix(".summary.json")

        self.to_jsonl(events_path)
        timeline_path.write_text(json.dumps(self.to_timeline(), indent=2))
        mitre_path.write_text(json.dumps(self.to_mitre_map(), indent=2))
        summary_path.write_text(json.dumps(self.to_summary(), indent=2))

        return {
            "events": events_path,
            "timeline": timeline_path,
            "mitre": mitre_path,
            "summary": summary_path,
        }
