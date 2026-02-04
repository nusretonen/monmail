from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        event_time TEXT NOT NULL,
        source_ip TEXT,
        destination TEXT,
        smtp_mail_from TEXT,
        smtp_rcpt_to TEXT,
        smtp_helo TEXT,
        smtp_status TEXT,
        email_subject TEXT,
        email_message_id TEXT,
        email_client_ip TEXT,
        attachment_hash TEXT,
        url TEXT,
        dns_query TEXT,
        dns_qtype TEXT,
        dns_rcode TEXT,
        dns_server TEXT,
        client_ip TEXT,
        resolved_ip TEXT,
        host_name TEXT,
        sensor_id TEXT,
        tenant_id TEXT,
        asset_id TEXT,
        asset_criticality TEXT,
        user_name TEXT,
        metadata TEXT,
        raw TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        detection_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        rule TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(event_id) REFERENCES events(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detection_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        details TEXT NOT NULL,
        FOREIGN KEY(detection_id) REFERENCES detections(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_key TEXT NOT NULL,
        title TEXT NOT NULL,
        status TEXT NOT NULL,
        owner TEXT,
        severity TEXT NOT NULL,
        sla_due_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        summary TEXT,
        tags TEXT,
        UNIQUE(incident_key)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        severity TEXT NOT NULL,
        count INTEGER NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        case_id INTEGER,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_type TEXT NOT NULL,
        value TEXT NOT NULL,
        source TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        severity TEXT NOT NULL,
        tlp TEXT,
        kill_chain_phase TEXT,
        revoked INTEGER NOT NULL DEFAULT 0,
        false_positive INTEGER NOT NULL DEFAULT 0,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        expires_at TEXT,
        tags TEXT,
        relationships TEXT,
        raw_payload TEXT,
        UNIQUE(indicator_type, value, source)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS sightings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_id INTEGER NOT NULL,
        event_id INTEGER NOT NULL,
        matched_field TEXT NOT NULL,
        matched_value TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        context TEXT,
        score_delta INTEGER NOT NULL,
        UNIQUE(indicator_id, event_id, matched_field, matched_value),
        FOREIGN KEY(indicator_id) REFERENCES indicators(id),
        FOREIGN KEY(event_id) REFERENCES events(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS enrichment_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        expires_at TEXT
    );
    """,
]

EVENT_COLUMNS: dict[str, str] = {
    "smtp_mail_from": "TEXT",
    "smtp_rcpt_to": "TEXT",
    "smtp_helo": "TEXT",
    "smtp_status": "TEXT",
    "email_subject": "TEXT",
    "email_message_id": "TEXT",
    "email_client_ip": "TEXT",
    "attachment_hash": "TEXT",
    "url": "TEXT",
    "dns_query": "TEXT",
    "dns_qtype": "TEXT",
    "dns_rcode": "TEXT",
    "dns_server": "TEXT",
    "client_ip": "TEXT",
    "resolved_ip": "TEXT",
    "host_name": "TEXT",
    "sensor_id": "TEXT",
    "tenant_id": "TEXT",
    "asset_id": "TEXT",
    "asset_criticality": "TEXT",
    "user_name": "TEXT",
}

INDICATOR_COLUMNS: dict[str, str] = {
    "tlp": "TEXT",
    "kill_chain_phase": "TEXT",
    "revoked": "INTEGER NOT NULL DEFAULT 0",
    "false_positive": "INTEGER NOT NULL DEFAULT 0",
    "relationships": "TEXT",
}

INCIDENT_COLUMNS: dict[str, str] = {"case_id": "INTEGER"}


def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, column_type in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {column_type}")


def _ensure_indexes(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_destination ON events(destination)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_dns_query ON events(dns_query)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_url ON events(url)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type_value ON indicators(indicator_type, value)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sightings_indicator ON sightings(indicator_id)")


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    for statement in SCHEMA:
        conn.execute(statement)
    _ensure_columns(conn, "events", EVENT_COLUMNS)
    _ensure_columns(conn, "indicators", INDICATOR_COLUMNS)
    _ensure_columns(conn, "incidents", INCIDENT_COLUMNS)
    _ensure_indexes(conn)
    conn.commit()


def insert_event(conn: sqlite3.Connection, event: dict) -> int:
    cursor = conn.execute(
        """
        INSERT INTO events (
            source, event_time, source_ip, destination,
            smtp_mail_from, smtp_rcpt_to, smtp_helo, smtp_status,
            email_subject, email_message_id, email_client_ip,
            attachment_hash, url,
            dns_query, dns_qtype, dns_rcode, dns_server,
            client_ip, resolved_ip,
            host_name, sensor_id, tenant_id, asset_id, asset_criticality, user_name,
            metadata, raw
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["source"],
            event["event_time"],
            event.get("source_ip"),
            event.get("destination"),
            event.get("smtp_mail_from"),
            event.get("smtp_rcpt_to"),
            event.get("smtp_helo"),
            event.get("smtp_status"),
            event.get("email_subject"),
            event.get("email_message_id"),
            event.get("email_client_ip"),
            event.get("attachment_hash"),
            event.get("url"),
            event.get("dns_query"),
            event.get("dns_qtype"),
            event.get("dns_rcode"),
            event.get("dns_server"),
            event.get("client_ip"),
            event.get("resolved_ip"),
            event.get("host_name"),
            event.get("sensor_id"),
            event.get("tenant_id"),
            event.get("asset_id"),
            event.get("asset_criticality"),
            event.get("user_name"),
            event.get("metadata", "{}"),
            event["raw"],
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)


def update_event_metadata(conn: sqlite3.Connection, event_id: int, metadata: str) -> None:
    conn.execute(
        """
        UPDATE events
        SET metadata = ?
        WHERE id = ?
        """,
        (metadata, event_id),
    )
    conn.commit()


def insert_detection(conn: sqlite3.Connection, detection: dict) -> int:
    cursor = conn.execute(
        """
        INSERT INTO detections (event_id, detection_type, severity, confidence, rule, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            detection["event_id"],
            detection["detection_type"],
            detection["severity"],
            detection["confidence"],
            detection["rule"],
            detection["created_at"],
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)


def insert_alert(conn: sqlite3.Connection, alert: dict) -> int:
    cursor = conn.execute(
        """
        INSERT INTO alerts (detection_id, title, severity, status, created_at, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            alert["detection_id"],
            alert["title"],
            alert["severity"],
            alert["status"],
            alert["created_at"],
            alert["details"],
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)


def update_incident(conn: sqlite3.Connection, key: str, severity: str, timestamp: str) -> None:
    existing = conn.execute("SELECT * FROM incidents WHERE key = ?", (key,)).fetchone()
    case_id = _ensure_case_for_incident(conn, key, severity, timestamp)
    if existing:
        conn.execute(
            """
            UPDATE incidents
            SET count = count + 1, last_seen = ?, severity = ?, case_id = ?
            WHERE key = ?
            """,
            (timestamp, severity, case_id, key),
        )
    else:
        conn.execute(
            """
            INSERT INTO incidents (key, severity, count, first_seen, last_seen, case_id)
            VALUES (?, ?, 1, ?, ?, ?)
            """,
            (key, severity, timestamp, timestamp, case_id),
        )
    conn.commit()


def _ensure_case_for_incident(
    conn: sqlite3.Connection, incident_key: str, severity: str, timestamp: str
) -> int | None:
    if severity.lower() not in {"high", "critical"}:
        return None
    existing = conn.execute("SELECT * FROM cases WHERE incident_key = ?", (incident_key,)).fetchone()
    if existing:
        conn.execute(
            """
            UPDATE cases
            SET updated_at = ?, severity = ?
            WHERE incident_key = ?
            """,
            (timestamp, severity, incident_key),
        )
        return int(existing["id"])
    cursor = conn.execute(
        """
        INSERT INTO cases (incident_key, title, status, owner, severity, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_key,
            f"Incident {incident_key}",
            "open",
            None,
            severity,
            timestamp,
            timestamp,
        ),
    )
    return int(cursor.lastrowid)


def upsert_indicator(conn: sqlite3.Connection, indicator: dict) -> int:
    cursor = conn.execute(
        """
        INSERT INTO indicators (
            indicator_type, value, source, confidence, severity,
            tlp, kill_chain_phase, revoked, false_positive,
            first_seen, last_seen, expires_at, tags, relationships, raw_payload
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(indicator_type, value, source)
        DO UPDATE SET
            confidence = excluded.confidence,
            severity = excluded.severity,
            tlp = excluded.tlp,
            kill_chain_phase = excluded.kill_chain_phase,
            revoked = excluded.revoked,
            false_positive = excluded.false_positive,
            last_seen = excluded.last_seen,
            expires_at = excluded.expires_at,
            tags = excluded.tags,
            relationships = excluded.relationships,
            raw_payload = excluded.raw_payload
        """,
        (
            indicator["indicator_type"],
            indicator["value"],
            indicator["source"],
            indicator["confidence"],
            indicator["severity"],
            indicator.get("tlp"),
            indicator.get("kill_chain_phase"),
            indicator.get("revoked", 0),
            indicator.get("false_positive", 0),
            indicator["first_seen"],
            indicator["last_seen"],
            indicator.get("expires_at"),
            indicator.get("tags"),
            indicator.get("relationships"),
            indicator.get("raw_payload"),
        ),
    )
    conn.commit()
    if cursor.lastrowid:
        return int(cursor.lastrowid)
    row = conn.execute(
        """
        SELECT id FROM indicators
        WHERE indicator_type = ? AND value = ? AND source = ?
        """,
        (indicator["indicator_type"], indicator["value"], indicator["source"]),
    ).fetchone()
    return int(row["id"]) if row else 0


def fetch_indicator_matches(
    conn: sqlite3.Connection,
    indicator_type: str,
    value: str,
    now: str,
) -> Iterable[sqlite3.Row]:
    return conn.execute(
        """
        SELECT *
        FROM indicators
        WHERE indicator_type = ?
          AND value = ?
          AND revoked = 0
          AND false_positive = 0
          AND (expires_at IS NULL OR expires_at > ?)
        """,
        (indicator_type, value, now),
    ).fetchall()


def insert_sighting(conn: sqlite3.Connection, sighting: dict) -> int | None:
    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO sightings (
            indicator_id, event_id, matched_field, matched_value, timestamp, context, score_delta
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sighting["indicator_id"],
            sighting["event_id"],
            sighting["matched_field"],
            sighting["matched_value"],
            sighting["timestamp"],
            sighting.get("context"),
            sighting["score_delta"],
        ),
    )
    conn.commit()
    if cursor.rowcount == 0:
        return None
    return int(cursor.lastrowid)


def fetch_sightings(conn: sqlite3.Connection, limit: int = 50) -> Iterable[sqlite3.Row]:
    return conn.execute(
        """
        SELECT sightings.*, indicators.indicator_type, indicators.value, indicators.source
        FROM sightings
        JOIN indicators ON sightings.indicator_id = indicators.id
        ORDER BY sightings.timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def fetch_enrichment_cache(
    conn: sqlite3.Connection, indicator: str, indicator_type: str, now: str
) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT * FROM enrichment_cache
        WHERE indicator = ? AND indicator_type = ?
          AND (expires_at IS NULL OR expires_at > ?)
        """,
        (indicator, indicator_type, now),
    ).fetchone()


def upsert_enrichment_cache(conn: sqlite3.Connection, entry: dict) -> int:
    cursor = conn.execute(
        """
        INSERT INTO enrichment_cache (indicator, indicator_type, value, updated_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            entry["indicator"],
            entry["indicator_type"],
            entry["value"],
            entry["updated_at"],
            entry.get("expires_at"),
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)


def fetch_alerts(conn: sqlite3.Connection, limit: int = 50) -> Iterable[sqlite3.Row]:
    return conn.execute(
        """
        SELECT alerts.*, detections.detection_type, events.source_ip, events.destination
        FROM alerts
        JOIN detections ON alerts.detection_id = detections.id
        JOIN events ON detections.event_id = events.id
        ORDER BY alerts.created_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def fetch_dashboard_stats(conn: sqlite3.Connection) -> dict:
    counts = conn.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM alerts) AS alert_count,
            (SELECT COUNT(*) FROM detections) AS detection_count,
            (SELECT COUNT(*) FROM events) AS event_count,
            (SELECT COUNT(*) FROM incidents) AS incident_count,
            (SELECT COUNT(*) FROM cases) AS case_count
        """
    ).fetchone()
    return dict(counts)
