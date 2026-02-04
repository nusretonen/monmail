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
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        severity TEXT NOT NULL,
        count INTEGER NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS enrichment_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
]


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    for statement in SCHEMA:
        conn.execute(statement)
    conn.commit()


def insert_event(conn: sqlite3.Connection, event: dict) -> int:
    cursor = conn.execute(
        """
        INSERT INTO events (source, event_time, source_ip, destination, metadata, raw)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event["source"],
            event["event_time"],
            event.get("source_ip"),
            event.get("destination"),
            event.get("metadata", "{}"),
            event["raw"],
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)


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
    if existing:
        conn.execute(
            """
            UPDATE incidents
            SET count = count + 1, last_seen = ?, severity = ?
            WHERE key = ?
            """,
            (timestamp, severity, key),
        )
    else:
        conn.execute(
            """
            INSERT INTO incidents (key, severity, count, first_seen, last_seen)
            VALUES (?, ?, 1, ?, ?)
            """,
            (key, severity, timestamp, timestamp),
        )
    conn.commit()


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
            (SELECT COUNT(*) FROM incidents) AS incident_count
        """
    ).fetchone()
    return dict(counts)
