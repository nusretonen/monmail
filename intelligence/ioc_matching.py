from __future__ import annotations

from datetime import datetime, timezone


SEVERITY_SCORES = {
    "low": 10,
    "medium": 30,
    "high": 60,
    "critical": 90,
}


def score_sighting(confidence: int, severity: str) -> int:
    base = SEVERITY_SCORES.get(severity.lower(), 20)
    confidence_factor = max(0, min(confidence, 100)) / 100
    return int(base * confidence_factor)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
