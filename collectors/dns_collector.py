from __future__ import annotations

import argparse
import re

from collectors.base import emit_event

DNS_PATTERN = re.compile(r"client (?P<ip>[\d\.]+)#\d+: query: (?P<domain>[^ ]+) IN (?P<qtype>\w+)")


def parse_line(line: str) -> dict:
    match = DNS_PATTERN.search(line)
    if not match:
        return {}
    return {
        "client_ip": match.group("ip"),
        "domain": match.group("domain"),
        "query_type": match.group("qtype"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    args = parser.parse_args()
    with open(args.path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            parsed = parse_line(line)
            if parsed:
                emit_event(
                    source="dns",
                    raw=line,
                    source_ip=parsed["client_ip"],
                    destination=parsed["domain"],
                    metadata=parsed,
                )


if __name__ == "__main__":
    main()
