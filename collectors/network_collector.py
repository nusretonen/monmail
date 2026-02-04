from __future__ import annotations

import argparse

from collectors.base import emit_event


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--protocol", default="tcp")
    args = parser.parse_args()
    emit_event(
        source="network",
        raw=f"{args.source_ip} -> {args.destination} ({args.protocol})",
        source_ip=args.source_ip,
        destination=args.destination,
        metadata={"protocol": args.protocol},
    )


if __name__ == "__main__":
    main()
