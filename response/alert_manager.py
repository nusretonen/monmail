from __future__ import annotations

import json
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage


def build_alert(detection: dict, event: dict) -> dict:
    title = f"{detection['detection_type']} detected"
    return {
        "detection_id": detection["id"],
        "title": title,
        "severity": detection["severity"],
        "status": "open",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "details": json.dumps({"event": event, "detection": detection}),
    }


def send_email_alert(subject: str, body: str) -> None:
    if os.getenv("ALERT_EMAIL_ENABLED", "true").lower() != "true":
        return
    smtp_host = os.getenv("SMTP_HOST", "localhost")
    smtp_port = int(os.getenv("SMTP_PORT", "25"))
    from_addr = os.getenv("ALERT_EMAIL_FROM", "alerts@example.com")
    to_addr = os.getenv("ALERT_EMAIL_TO", "security@example.com")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_addr
    message["To"] = to_addr
    message.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.send_message(message)
