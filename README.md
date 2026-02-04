# Monmail - Local Mail & DNS Threat Intelligence

Monmail is a fully local threat intelligence system for mail servers and DNS servers. It collects logs, enriches events, detects threats, correlates incidents, and exposes a dashboard API without relying on external platforms.

## Features

- Mail, DNS, Syslog, and optional network log collectors
- SQLite storage with alert and incident tracking
- Detection engine (regex + heuristics)
- Local enrichment (GeoIP placeholder, IP reputation, domain blacklist)
- IOC normalization, indicator ingestion, and sightings
- Correlation and alerting
- FastAPI backend + dashboard UI

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start API
uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` for the dashboard.

## Collector Usage

```bash
python collectors/mail_collector.py --path /var/log/mail.log
python collectors/dns_collector.py --path /var/log/named/query.log
python collectors/syslog_collector.py --path /var/log/syslog
```

Each collector prints parsed events as JSON; you can pipe them into the API:

```bash
python collectors/dns_collector.py --path /var/log/named/query.log | \
  python api/ingest_cli.py --endpoint http://localhost:8000/ingest/dns
```

## Indicator Ingestion

Send IOC data to the API for CTI matching:

```bash
curl -X POST http://localhost:8000/indicators/ingest \
  -H "Content-Type: application/json" \
  -d '{"indicator_type":"ip","value":"203.0.113.10","source":"misp","confidence":80,"severity":"high"}'
```

## Configuration

- `config/database.yaml`: database path and retention
- `config/detection_rules.yaml`: regex rules and scoring
- `config/alert_rules.yaml`: alert thresholds and channels
- `config/sources.yaml`: log sources

## Docker Compose

```bash
docker compose up --build
```

This starts the API service on port 8000 with a local SQLite database stored under `./data/monmail.db`.

## Project Structure

```
collectors/   Log collectors for mail, dns, syslog
storage/      SQLite storage and schema
intelligence/ Detection, enrichment, correlation
response/     Alerting and response actions
api/          FastAPI app and routes
config/       Local configuration files
data/         Local threat intel data
```

## Security Note

The system is designed to run in air-gapped/edge environments. External lookups are disabled by default.
