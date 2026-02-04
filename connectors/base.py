from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass
class ConnectorConfig:
    endpoint: str
    token: str | None = None
    proxy: str | None = None
    tls_verify: bool = True
    tenant_id: str | None = None


class ConnectorBase:
    name: str = "base"

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config

    def pull(self, since: str | None = None) -> Iterable[dict]:
        raise NotImplementedError

    def push_sightings(self, sightings: Iterable[dict]) -> None:
        raise NotImplementedError

    def healthcheck(self) -> dict[str, Any]:
        return {"status": "unknown", "connector": self.name}

    def rate_limit_state(self) -> dict[str, Any]:
        return {"remaining": None, "reset_at": None}
