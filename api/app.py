from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from intelligence.correlation import build_incident_key
from intelligence.enrichment import enrich_event
from intelligence.ioc_cache import HotIndicatorCache
from intelligence.ioc_matching import now_iso, score_sighting
from intelligence.ioc_normalization import (
    extract_event_indicators,
    normalize_event_fields,
    normalize_indicator_value,
    serialize_indicators,
)
from intelligence.threat_detection import evaluate_event, load_rules
from response.alert_manager import build_alert, send_email_alert
from storage.database import (
    fetch_alerts,
    fetch_dashboard_stats,
    fetch_indicator_matches,
    fetch_sightings,
    get_connection,
    init_db,
    insert_sighting,
    insert_alert,
    insert_detection,
    insert_event,
    upsert_indicator,
    update_event_metadata,
    update_incident,
)

app = FastAPI(title="Monmail Threat Intel")

DB_PATH = os.getenv("MONMAIL_DB_PATH", "./data/monmail.db")
RULES_PATH = os.getenv("MONMAIL_RULES_PATH", "./config/detection_rules.yaml")
DATA_DIR = os.getenv("MONMAIL_DATA_DIR", "./data")
HOT_INDICATOR_CACHE = HotIndicatorCache()


class EventIn(BaseModel):
    source: str
    event_time: str | None = None
    source_ip: str | None = None
    destination: str | None = None
    metadata: dict = Field(default_factory=dict)
    raw: str


class IndicatorIn(BaseModel):
    indicator_type: str
    value: str
    confidence: int = 50
    severity: str = "medium"
    source: str = "feed"
    first_seen: str | None = None
    last_seen: str | None = None
    expires_at: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw_payload: dict | None = None


@app.on_event("startup")
def startup() -> None:
    conn = get_connection(DB_PATH)
    init_db(conn)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/alerts")
def list_alerts(limit: int = 50) -> list[dict]:
    conn = get_connection(DB_PATH)
    rows = fetch_alerts(conn, limit=limit)
    return [dict(row) for row in rows]


@app.get("/sightings")
def list_sightings(limit: int = 50) -> list[dict]:
    conn = get_connection(DB_PATH)
    rows = fetch_sightings(conn, limit=limit)
    return [dict(row) for row in rows]


@app.get("/dashboard")
def dashboard() -> dict:
    conn = get_connection(DB_PATH)
    return fetch_dashboard_stats(conn)


@app.get("/", response_class=HTMLResponse)
def dashboard_ui() -> str:
    stats = fetch_dashboard_stats(get_connection(DB_PATH))
    return f"""
    <html>
      <head>
        <title>Monmail Dashboard</title>
        <style>
          body {{ font-family: Arial, sans-serif; margin: 2rem; background: #0f172a; color: #e2e8f0; }}
          .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }}
          .card {{ background: #1e293b; padding: 1rem; border-radius: 0.5rem; }}
          h1 {{ margin-bottom: 1rem; }}
        </style>
      </head>
      <body>
        <h1>Monmail Threat Intel</h1>
        <div class="cards">
          <div class="card">Alerts<br/><strong>{stats['alert_count']}</strong></div>
          <div class="card">Detections<br/><strong>{stats['detection_count']}</strong></div>
          <div class="card">Events<br/><strong>{stats['event_count']}</strong></div>
          <div class="card">Incidents<br/><strong>{stats['incident_count']}</strong></div>
        </div>
      </body>
    </html>
    """


@app.post("/ingest")
@app.post("/ingest/{source}")
def ingest_event(event: EventIn, source: str | None = None) -> dict:
    conn = get_connection(DB_PATH)
    init_db(conn)
    rules = load_rules(RULES_PATH)

    event_payload = event.model_dump()
    event_payload["source"] = source or event.source
    event_payload["event_time"] = event_payload["event_time"] or datetime.now(timezone.utc).isoformat()
    metadata = event_payload.get("metadata", {})
    normalized_fields = normalize_event_fields(event_payload, metadata)
    indicators = extract_event_indicators(event_payload, metadata)
    metadata["normalized"] = normalized_fields
    metadata["extracted_iocs"] = serialize_indicators(indicators)
    event_payload["metadata"] = json.dumps(metadata)

    event_id = insert_event(conn, event_payload)
    event_payload["id"] = event_id

    enrichment = enrich_event(event_payload, DATA_DIR)
    if enrichment:
        metadata = json.loads(event_payload["metadata"])
        metadata["enrichment"] = enrichment
        event_payload["metadata"] = json.dumps(metadata)
        update_event_metadata(conn, event_id, event_payload["metadata"])

    detections = evaluate_event(event_payload, rules)
    now = now_iso()
    for indicator in indicators:
        cached = HOT_INDICATOR_CACHE.get(indicator["indicator_type"], indicator["value"])
        if cached is None:
            rows = fetch_indicator_matches(
                conn,
                indicator["indicator_type"],
                indicator["value"],
                now,
            )
            cached = [dict(row) for row in rows]
            HOT_INDICATOR_CACHE.set(indicator["indicator_type"], indicator["value"], cached)
        matches = cached
        for match in matches:
            score_delta = score_sighting(match["confidence"], match["severity"])
            sighting_id = insert_sighting(
                conn,
                {
                    "indicator_id": match["id"],
                    "event_id": event_id,
                    "matched_field": indicator["matched_field"],
                    "matched_value": indicator["matched_value"],
                    "timestamp": now,
                    "context": json.dumps(
                        {
                            "source": event_payload["source"],
                            "normalized": normalized_fields,
                        }
                    ),
                    "score_delta": score_delta,
                },
            )
            if sighting_id:
                detections.append(
                    {
                        "event_id": event_id,
                        "detection_type": "cti_match",
                        "severity": match["severity"],
                        "confidence": match["confidence"],
                        "rule": f"{match['source']}:{match['indicator_type']}",
                        "created_at": now,
                    }
                )
    if not detections:
        return {"status": "stored", "event_id": event_id}

    alerts = []
    for detection in detections:
        detection_id = insert_detection(conn, detection)
        detection["id"] = detection_id
        alert = build_alert(detection, event_payload)
        alert_id = insert_alert(conn, alert)
        alert["id"] = alert_id
        alerts.append(alert)

        incident_key = build_incident_key(event_payload)
        update_incident(conn, incident_key, detection["severity"], detection["created_at"])

        if detection["severity"] in {"critical", "high"}:
            send_email_alert(alert["title"], alert["details"])

    return {"status": "alerted", "alerts": alerts}


@app.post("/indicators/ingest")
def ingest_indicator(indicator: IndicatorIn) -> dict:
    conn = get_connection(DB_PATH)
    init_db(conn)
    payload = indicator.model_dump()
    timestamp = now_iso()
    payload["indicator_type"] = payload["indicator_type"].lower()
    payload["value"] = normalize_indicator_value(payload["indicator_type"], payload["value"])
    payload["first_seen"] = payload["first_seen"] or timestamp
    payload["last_seen"] = payload["last_seen"] or timestamp
    payload["raw_payload"] = json.dumps(payload["raw_payload"]) if payload.get("raw_payload") else None
    payload["tags"] = json.dumps(payload["tags"]) if payload.get("tags") else None
    indicator_id = upsert_indicator(conn, payload)
    return {"status": "stored", "indicator_id": indicator_id}


@app.post("/ingest/raw")
def ingest_raw(payload: dict) -> dict:
    if "raw" not in payload:
        raise HTTPException(status_code=400, detail="Missing raw field")
    event = EventIn(**payload)
    return ingest_event(event)
