from __future__ import annotations

import argparse
import re

from collectors.base import emit_event

MAIL_PATTERN = re.compile(r"from=<(?P<from>[^>]+)>.*to=<(?P<to>[^>]+)>.*client=(?P<ip>[\d\.]+)")


def parse_line(line: str) -> dict:
    match = MAIL_PATTERN.search(line)
    if not match:
        return {}
    return {
        "sender": match.group("from"),
        "recipient": match.group("to"),
        "source_ip": match.group("ip"),
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
                    source="mail",
                    raw=line,
                    source_ip=parsed["source_ip"],
                    destination=parsed["recipient"],
                    metadata=parsed,
                )


if __name__ == "__main__":
    main()
