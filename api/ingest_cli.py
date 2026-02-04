from __future__ import annotations

import argparse
import json
import sys

import requests


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    args = parser.parse_args()

    for line in sys.stdin:
        if not line.strip():
            continue
        payload = json.loads(line)
        response = requests.post(args.endpoint, json=payload, timeout=10)
        response.raise_for_status()
        print(response.json())


if __name__ == "__main__":
    main()
