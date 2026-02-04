from __future__ import annotations

import csv
from pathlib import Path


def load_csv(path: str) -> list[dict]:
    if not Path(path).exists():
        return []
    with open(path, "r", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def enrich_event(event: dict, data_dir: str) -> dict:
    enrichment = {}
    domain_blacklist = load_csv(str(Path(data_dir) / "domain_blacklist.csv"))
    ip_reputation = load_csv(str(Path(data_dir) / "ip_reputation.csv"))
    domain = event.get("destination")
    source_ip = event.get("source_ip")
    if domain:
        matches = [row for row in domain_blacklist if row.get("domain") == domain]
        if matches:
            enrichment["domain_reputation"] = matches[0].get("reason", "blacklisted")
    if source_ip:
        matches = [row for row in ip_reputation if row.get("ip") == source_ip]
        if matches:
            enrichment["ip_reputation"] = matches[0].get("reason", "suspicious")
    return enrichment
