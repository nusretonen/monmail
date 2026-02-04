from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

EVENTS_INGESTED = Counter(
    "monmail_events_ingested_total",
    "Total number of ingested events",
    ["source"],
)
SIGHTINGS_CREATED = Counter(
    "monmail_sightings_total",
    "Total number of IOC sightings created",
    ["indicator_type", "source"],
)
ALERTS_CREATED = Counter(
    "monmail_alerts_total",
    "Total number of alerts created",
    ["severity"],
)
DETECTIONS_CREATED = Counter(
    "monmail_detections_total",
    "Total number of detections created",
    ["detection_type", "severity"],
)
INGEST_DURATION = Histogram(
    "monmail_ingest_duration_seconds",
    "Time spent ingesting events",
    ["source"],
)


def render_metrics() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
