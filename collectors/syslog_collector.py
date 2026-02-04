from __future__ import annotations

import argparse
import re

from collectors.base import emit_event

AUTH_PATTERN = re.compile(r"Failed password for (?P<user>\w+) from (?P<ip>[\d\.]+)")


def parse_line(line: str) -> dict:
    match = AUTH_PATTERN.search(line)
    if not match:
        return {}
    return {
        "user": match.group("user"),
        "source_ip": match.group("ip"),
        "event": "failed_login",
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
                    source="syslog",
                    raw=line,
                    source_ip=parsed["source_ip"],
                    destination=None,
                    metadata=parsed,
                )


if __name__ == "__main__":
    main()
