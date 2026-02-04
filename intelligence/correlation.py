from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse


def _email_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.split("@", 1)[1].lower()


def _url_domain(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else None


def build_incident_key(event: dict, normalized_fields: dict | None = None) -> str:
    normalized_fields = normalized_fields or {}
    source = event.get("source", "unknown")
    tenant_id = event.get("tenant_id") or "tenant-unknown"
    asset_id = event.get("asset_id") or "asset-unknown"
    source_ip = event.get("source_ip") or normalized_fields.get("src_ip") or "ip-unknown"
    destination = event.get("destination") or "dest-unknown"

    if source == "mail":
        sender_domain = _email_domain(event.get("smtp_mail_from")) or _email_domain(
            normalized_fields.get("mail_from")
        )
        rcpt_domain = _email_domain(event.get("smtp_rcpt_to")) or _email_domain(
            normalized_fields.get("rcpt_to")
        )
        return f"mail:{tenant_id}:{asset_id}:{sender_domain or 'sender-unknown'}:{rcpt_domain or 'rcpt-unknown'}:{source_ip}"

    if source == "dns":
        query = event.get("dns_query") or normalized_fields.get("domain") or destination
        client_ip = event.get("client_ip") or normalized_fields.get("src_ip") or source_ip
        return f"dns:{tenant_id}:{asset_id}:{query}:{client_ip}"

    url_domain = _url_domain(event.get("url")) or normalized_fields.get("domain")
    primary = url_domain or normalized_fields.get("url") or destination
    return f"{source}:{tenant_id}:{asset_id}:{primary}:{source_ip}"


def within_window(timestamp: str, window_minutes: int = 60) -> bool:
    now = datetime.now(timezone.utc)
    event_time = datetime.fromisoformat(timestamp)
    return now - event_time <= timedelta(minutes=window_minutes)
