from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from intelligence.correlation import build_incident_key
from intelligence.enrichment import enrich_event
from intelligence.threat_detection import evaluate_event, load_rules
from response.alert_manager import build_alert, send_email_alert
from storage.database import (
    fetch_alerts,
    fetch_dashboard_stats,
    get_connection,
    init_db,
    insert_alert,
    insert_detection,
    insert_event,
    update_incident,
)

app = FastAPI(title="Monmail Threat Intel")

DB_PATH = os.getenv("MONMAIL_DB_PATH", "./data/monmail.db")
RULES_PATH = os.getenv("MONMAIL_RULES_PATH", "./config/detection_rules.yaml")
DATA_DIR = os.getenv("MONMAIL_DATA_DIR", "./data")


class EventIn(BaseModel):
    source: str
    event_time: str | None = None
    source_ip: str | None = None
    destination: str | None = None
    metadata: dict = {}
    raw: str


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
    event_payload["metadata"] = json.dumps(event_payload.get("metadata", {}))

    event_id = insert_event(conn, event_payload)
    event_payload["id"] = event_id

    enrichment = enrich_event(event_payload, DATA_DIR)
    if enrichment:
        metadata = json.loads(event_payload["metadata"])
        metadata["enrichment"] = enrichment
        event_payload["metadata"] = json.dumps(metadata)

    detections = evaluate_event(event_payload, rules)
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


@app.post("/ingest/raw")
def ingest_raw(payload: dict) -> dict:
    if "raw" not in payload:
        raise HTTPException(status_code=400, detail="Missing raw field")
    event = EventIn(**payload)
    return ingest_event(event)
