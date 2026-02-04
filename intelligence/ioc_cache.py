from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


class HotIndicatorCache:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self._store: dict[tuple[str, str], tuple[datetime, list[dict[str, Any]]]] = {}

    def get(self, indicator_type: str, value: str) -> list[dict[str, Any]] | None:
        key = (indicator_type, value)
        entry = self._store.get(key)
        if not entry:
            return None
        expires_at, data = entry
        if datetime.now(timezone.utc) >= expires_at:
            self._store.pop(key, None)
            return None
        return data

    def set(self, indicator_type: str, value: str, data: list[dict[str, Any]]) -> None:
        expires_at = datetime.now(timezone.utc) + self.ttl
        self._store[(indicator_type, value)] = (expires_at, data)
