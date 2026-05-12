#!/usr/bin/env python3
"""nmap_bridge — Bridge between netascan (Rust) and nmap.

Communicates via newline-delimited JSON over stdin/stdout.

Request format:
    {"method": "nmap_scan", "args": {"target": "...", "ports": "..."}}

Response format:
    {"status": "ok", "data": {...}}
    {"status": "error", "message": "..."}
"""

import json
import sys


def nmap_scan(target: str, ports: str = "") -> dict:
    """Run nmap scan and return parsed results.

    Args:
        target: IP or CIDR range to scan.
        ports: Port specification (e.g. "top-1000", "1-65535", "80,443").

    Returns:
        Dictionary with scan results.
    """
    # TODO: Implement nmap subprocess invocation and XML parsing.
    return {"hosts": [], "scan_info": {"target": target, "ports": ports}}


def handle_request(request: dict) -> dict:
    """Process a single JSON request and return a response."""
    method = request.get("method")
    args = request.get("args", {})

    if method == "nmap_scan":
        result = nmap_scan(
            target=args.get("target", ""),
            ports=args.get("ports", ""),
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
