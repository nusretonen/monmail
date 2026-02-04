from __future__ import annotations

from datetime import datetime, timedelta, timezone


def build_incident_key(event: dict) -> str:
    source = event.get("source", "unknown")
    source_ip = event.get("source_ip", "unknown")
    destination = event.get("destination", "unknown")
    return f"{source}:{source_ip}:{destination}"


def within_window(timestamp: str, window_minutes: int = 60) -> bool:
    now = datetime.now(timezone.utc)
    event_time = datetime.fromisoformat(timestamp)
    return now - event_time <= timedelta(minutes=window_minutes)
