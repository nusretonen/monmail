from __future__ import annotations

import json
from datetime import datetime, timezone


def emit_event(source: str, raw: str, source_ip: str | None, destination: str | None, metadata: dict) -> None:
    event = {
        "source": source,
        "event_time": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "destination": destination,
        "metadata": json.dumps(metadata),
        "raw": raw.strip(),
    }
    print(json.dumps(event))
