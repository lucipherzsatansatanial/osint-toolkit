#!/usr/bin/env python3
"""Send log files to the SOC dashboard ingest API (stdlib only).

Examples
  SOC_API_KEY=... python3 tools/ship_logs.py defender_export.json --format defender --url https://soc.example.com
  SOC_API_KEY=... python3 tools/ship_logs.py winlogbeat.ndjson --format ecs
  SOC_API_KEY=... python3 tools/ship_logs.py /var/log/nginx/access.log --format access_log --host SRV-WEB-01
  SOC_API_KEY=... python3 tools/ship_logs.py agent_audit.ndjson            # native AI-agent audit records

JSON arrays, {"records": [...]} and NDJSON are accepted; access logs are sent as text lines.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def batches(path: str, fmt: str, size: int):
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    if fmt == "access_log":
        lines = [ln for ln in text.splitlines() if ln.strip()]
        for i in range(0, len(lines), size):
            yield "\n".join(lines[i:i + size]).encode(), "text/plain"
        return
    try:
        doc = json.loads(text)
        items = doc.get("records", [doc]) if isinstance(doc, dict) else doc
    except json.JSONDecodeError:
        items = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    for i in range(0, len(items), size):
        yield json.dumps(items[i:i + size]).encode(), "application/json"


def post(url: str, body: bytes, ctype: str, key: str, retries: int = 4) -> dict:
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": ctype, "X-API-Key": key})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:  # rate limited: back off
                time.sleep(2 ** attempt * 2)
                continue
            raise SystemExit(f"HTTP {e.code}: {e.read().decode(errors='replace')[:500]}")
        except urllib.error.URLError as e:
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise SystemExit(f"connection failed: {e.reason}")
    raise SystemExit("gave up after retries")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--url", default=os.getenv("SOC_URL", "http://localhost:8000"))
    ap.add_argument("--format", default="auto", choices=["auto", "native", "ecs", "defender", "access_log"])
    ap.add_argument("--host", help="web server name for access_log lines")
    ap.add_argument("--batch", type=int, default=1000)
    a = ap.parse_args()
    key = os.getenv("SOC_API_KEY", "")
    q = {"format": a.format, **({"host": a.host} if a.host else {})}
    endpoint = a.url.rstrip("/") + "/api/soc/ingest?" + urllib.parse.urlencode(q)
    total = {"accepted": 0, "rejected": 0, "alerts": 0}
    for body, ctype in batches(a.file, a.format, max(1, min(a.batch, 5000))):
        r = post(endpoint, body, ctype, key)
        for k in total:
            total[k] += r.get(k, 0)
        print(f"batch: accepted={r['accepted']} rejected={r['rejected']} alerts={r['alerts']} {r.get('alerts_by_rule', {})}")
    print(f"done: {total}")
    sys.exit(0)


if __name__ == "__main__":
    main()
