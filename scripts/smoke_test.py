#!/usr/bin/env python3
"""
End-to-end check against a running deployment (local or hosted):

    python scripts/smoke_test.py https://your-host.example [--user admin --password ...]

Fails (exit 1) unless the stack is genuinely healthy: ML worker up, all three
TRAINED models loaded (not rule-based fallback), and a real job completes.
"""
import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request


def call(base, path, headers, body=None):
    req = urllib.request.Request(base + path, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method="POST" if body is not None else "GET")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--target", default="https://example.com")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="")
    a = ap.parse_args()
    base = a.base.rstrip("/")
    h = {}
    if a.password:
        h["Authorization"] = "Basic " + base64.b64encode(f"{a.user}:{a.password}".encode()).decode()

    health = call(base, "/health", h)
    print("health:", json.dumps(health))
    ok = health.get("ml_worker") == "up"
    models = health.get("models") or {}
    for name in ("url_nlp", "behavior", "vision"):
        loaded = models.get(name)
        print(f"  {name:9} trained model loaded: {loaded}")
        ok = ok and bool(loaded)

    job = call(base, "/analyze", h, {"target": a.target, "target_type": "url"})
    print("submitted:", job["job_id"])
    for _ in range(60):
        time.sleep(2)
        res = call(base, f"/jobs/{job['job_id']}", h)
        if res.get("status") in ("done", "error"):
            break
    print("status:", res.get("status"), "| verdict:", res.get("threat_level"), "| score:", res.get("aggregate_score"))
    if res.get("status") != "done":
        print("error:", res.get("error"))
        sys.exit(1)
    for name in ("url_nlp", "behavior", "vision"):
        src = (res.get(name) or {}).get("model_source")
        print(f"  {name:9} scored by: {src}")
    print("  sandbox mode:", (res.get("sandbox") or {}).get("sandbox_mode"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as exc:
        print("could not reach the deployment:", exc)
        sys.exit(1)
