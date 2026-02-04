from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse

IPV4_RE = re.compile(r"\b(?:(?:\d{1,3}\.){3}\d{1,3})\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>()]+\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
DOMAIN_RE = re.compile(r"\b(?!https?://)([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b")


def normalize_indicator_value(indicator_type: str, value: str) -> str:
    cleaned = value.strip()
    if indicator_type in {"domain", "email"}:
        return cleaned.lower()
    if indicator_type == "hash":
        return cleaned.lower()
    if indicator_type == "url":
        return cleaned.strip()
    if indicator_type == "ip":
        return cleaned
    return cleaned


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def guess_indicator_type(value: str) -> str | None:
    if _valid_ip(value):
        return "ip"
    if EMAIL_RE.fullmatch(value):
        return "email"
    if URL_RE.fullmatch(value):
        return "url"
    if HASH_RE.fullmatch(value):
        return "hash"
    if DOMAIN_RE.fullmatch(value):
        return "domain"
    return None


def normalize_event_fields(event: dict, metadata: dict) -> dict:
    source = event.get("source")
    destination = event.get("destination")
    fields = {
        "src_ip": event.get("source_ip") or metadata.get("client_ip"),
        "dst_ip": metadata.get("destination_ip") or metadata.get("dst_ip"),
        "domain": metadata.get("domain") if source == "dns" else None,
        "helo": metadata.get("helo"),
        "mail_from": metadata.get("sender") or metadata.get("mail_from"),
        "rcpt_to": metadata.get("recipient") or metadata.get("rcpt_to"),
        "url": metadata.get("url"),
        "attachment_hash": metadata.get("attachment_hash"),
    }

    if source == "dns" and not fields["domain"]:
        fields["domain"] = destination

    if source == "mail" and destination and not fields["rcpt_to"]:
        fields["rcpt_to"] = destination

    return {key: value for key, value in fields.items() if value}


def _extract_from_text(text: str) -> list[dict]:
    indicators: list[dict] = []
    for match in IPV4_RE.findall(text):
        if _valid_ip(match):
            indicators.append({"indicator_type": "ip", "value": normalize_indicator_value("ip", match)})
    for match in IPV6_RE.findall(text):
        if _valid_ip(match):
            indicators.append({"indicator_type": "ip", "value": normalize_indicator_value("ip", match)})
    for match in EMAIL_RE.findall(text):
        indicators.append({"indicator_type": "email", "value": normalize_indicator_value("email", match)})
    for match in URL_RE.findall(text):
        indicators.append({"indicator_type": "url", "value": normalize_indicator_value("url", match)})
        parsed = urlparse(match)
        if parsed.hostname:
            indicators.append({"indicator_type": "domain", "value": normalize_indicator_value("domain", parsed.hostname)})
    for match in HASH_RE.findall(text):
        indicators.append({"indicator_type": "hash", "value": normalize_indicator_value("hash", match)})
    for match in DOMAIN_RE.findall(text):
        indicators.append({"indicator_type": "domain", "value": normalize_indicator_value("domain", match)})
    return indicators


def extract_event_indicators(event: dict, metadata: dict) -> list[dict]:
    indicators: list[dict] = []
    normalized_fields = normalize_event_fields(event, metadata)

    for field, value in normalized_fields.items():
        if not value:
            continue
        indicator_type = guess_indicator_type(str(value))
        if indicator_type:
            indicators.append(
                {
                    "indicator_type": indicator_type,
                    "value": normalize_indicator_value(indicator_type, str(value)),
                    "matched_field": field,
                    "matched_value": str(value),
                }
            )

    raw_text = event.get("raw", "")
    for indicator in _extract_from_text(raw_text):
        indicator["matched_field"] = "raw"
        indicator["matched_value"] = indicator["value"]
        indicators.append(indicator)

    unique: dict[tuple[str, str, str], dict] = {}
    for indicator in indicators:
        key = (
            indicator["indicator_type"],
            indicator["value"],
            indicator["matched_field"],
        )
        unique[key] = indicator

    return list(unique.values())


def serialize_indicators(indicators: list[dict]) -> list[dict]:
    return json.loads(json.dumps(indicators))
