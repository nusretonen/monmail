from __future__ import annotations

from datetime import datetime, timezone


def decide_action(severity: str) -> dict:
    if severity in {"critical", "high"}:
        return {
            "action": "log_and_alert",
            "reason": "Severity threshold reached",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    return {
        "action": "log_only",
        "reason": "Below automation threshold",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
