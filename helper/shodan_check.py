#!/usr/bin/env python3
"""shodan_check — Optional Shodan API enrichment for netascan.

Communicates via newline-delimited JSON over stdin/stdout.

Request format:
    {"method": "shodan_lookup", "args": {"ip": "..."}}

Response format:
    {"status": "ok", "data": {...}}
    {"status": "error", "message": "..."}
"""

import json
import sys


def shodan_lookup(ip: str, api_key: str = "") -> dict:
    """Look up an IP address on Shodan.

    Args:
        ip: IP address to look up.
        api_key: Shodan API key.

    Returns:
        Dictionary with Shodan host data.
    """
    # TODO: Implement Shodan API call.
    return {"ip": ip, "ports": [], "vulns": []}


def handle_request(request: dict) -> dict:
    """Process a single JSON request and return a response."""
    method = request.get("method")
    args = request.get("args", {})

    if method == "shodan_lookup":
        result = shodan_lookup(
            ip=args.get("ip", ""),
            api_key=args.get("api_key", ""),
        )
        return {"status": "ok", "data": result}

    return {"status": "error", "message": f"Unknown method: {method}"}


def main() -> None:
    """Read JSON requests from stdin and write responses to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = handle_request(request)
        except json.JSONDecodeError as e:
            response = {"status": "error", "message": str(e)}
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
