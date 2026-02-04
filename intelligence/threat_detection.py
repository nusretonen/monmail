from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Iterable

import yaml

from intelligence.scoring import score_detection


def load_rules(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return data.get("rules", [])


def evaluate_event(event: dict, rules: Iterable[dict]) -> list[dict]:
    detections = []
    raw = event.get("raw", "")
    metadata = json.loads(event.get("metadata", "{}"))
    for rule in rules:
        pattern = rule.get("pattern")
        field = rule.get("field", "raw")
        target = raw if field == "raw" else metadata.get(field, "")
        if pattern and re.search(pattern, str(target), re.IGNORECASE):
            confidence, severity = score_detection(rule)
            detections.append(
                {
                    "event_id": event["id"],
                    "detection_type": rule.get("type", "unknown"),
                    "severity": severity,
                    "confidence": confidence,
                    "rule": rule.get("name", "rule"),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )
    return detections
