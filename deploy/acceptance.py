#!/usr/bin/env python3
"""
Live acceptance test for ECDAT's exposure controls.

Unit tests prove the policy functions work; this proves the policy holds
against a running, reachable service - which is the only version of the claim
that matters for a public demo.
"""
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8095"
KEY = open("/tmp/key").read().strip()
OPTS = '{"run_benchmarks":false,"iterations":5}'


def post(target, key=KEY, timeout=600):
    """Returns (status_code, body)."""
    body = json.dumps({"target": target, "run_benchmarks": False, "iterations": 5}).encode()
    req = urllib.request.Request(f"{BASE}/api/scan", data=body, method="POST")
    req.add_header("content-type", "application/json")
    if key is not None:
        req.add_header("X-ECDAT-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def status_of(scan_id, key=KEY, tries=200):
    """Polls to completion. Returns (state, error)."""
    for _ in range(tries):
        req = urllib.request.Request(f"{BASE}/api/scan/{scan_id}/status")
        if key is not None:
            req.add_header("X-ECDAT-Key", key)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.loads(r.read())
        except urllib.error.HTTPError as e:
            return f"http{e.code}", ""
        if d["state"] in ("done", "failed", "cancelled"):
            return d["state"], d.get("error") or ""
        time.sleep(2)
    return "timeout", ""


def drain(timeout=600):
    """
    Wait until nothing is running.

    Necessary because this instance runs with ECDAT_MAX_CONCURRENT_SCANS=1, so
    an unfinished scan from a previous section turns every later assertion into
    a 429. Without this, "429" reads as a pass and proves nothing.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        req = urllib.request.Request(f"{BASE}/api/scan")
        req.add_header("X-ECDAT-Key", KEY)
        with urllib.request.urlopen(req, timeout=30) as r:
            scans = json.loads(r.read() or b"[]")
        if not any(s["state"] in ("running", "queued") for s in scans):
            return True
        time.sleep(3)
    return False


def post_retry(target, key=KEY, tries=40):
    """POST, retrying through the concurrency cap rather than reporting it."""
    for _ in range(tries):
        code, body = post(target, key=key)
        if code != 429:
            return code, body
        drain()
    return 429, {}


results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if detail:
        print(f"        {detail}")


print("=== D. file disclosure: targets OUTSIDE ECDAT_SCAN_ROOT (/app/demo) ===")
drain()
for target in ("/app", "/etc", "/app/scanner/src", "/app/demo/../scanner"):
    code, body = post_retry(target)
    if code != 202:
        check(f"scan {target}", False, f"POST -> {code}: {str(body)[:100]}")
        continue
    state, err = status_of(body["scan_id"])
    refused = state == "failed" and ("outside ECDAT_SCAN_ROOT" in err or "TargetNotAllowed" in err)
    check(f"scan {target}", refused, f"{state}: {err[:120]}")

print()
print("=== E. allowed target still works (no over-blocking) ===")
drain()
code, body = post_retry("/app/demo/sample")
if code == 202:
    state, err = status_of(body["scan_id"])
    n = 0
    if state == "done":
        req = urllib.request.Request(f"{BASE}/api/risk/{body['scan_id']}")
        req.add_header("X-ECDAT-Key", KEY)
        with urllib.request.urlopen(req, timeout=60) as r:
            n = len(json.loads(r.read())["ranked"])
    check("scan inside ECDAT_SCAN_ROOT completes", state == "done" and n > 0,
          f"{state}, {n} findings")
else:
    check("scan inside ECDAT_SCAN_ROOT completes", False, f"POST -> {code}")

print()
print("=== F. SSRF: git targets that resolve to non-public addresses ===")
drain()
for target in ("http://localhost/repo.git", "http://127.0.0.1/repo.git",
               "http://169.254.169.254/latest/", "http://10.0.0.1/x.git",
               "http://[::1]/x.git"):
    code, body = post_retry(target)
    if code != 202:
        check(f"clone {target}", False, f"POST -> {code}: {str(body)[:100]}")
        continue
    state, err = status_of(body["scan_id"])
    refused = state == "failed" and ("not a public address" in err or "TargetNotAllowed" in err)
    check(f"clone {target}", refused, f"{state}: {err[:110]}")

print()
print("=== G. concurrency cap (max=1) ===")
drain()
codes = [post("https://github.com/torvalds/linux")[0] for _ in range(4)]
check("4 rapid scans -> only 1 admitted", codes.count(202) == 1 and codes.count(429) == 3,
      f"statuses: {codes}")
drain()

print()
print("=== H. results endpoints are gated too ===")
listing = urllib.request.Request(f"{BASE}/api/scan")
listing.add_header("X-ECDAT-Key", KEY)
with urllib.request.urlopen(listing, timeout=30) as r:
    scans = json.loads(r.read() or b"[]")

if not scans:
    check("results endpoints gated", False, "no scans to inspect")
else:
    sid = scans[0]["scan_id"]
    for ep in ("cbom", "risk", "benchmark", "recommendations"):
        req = urllib.request.Request(f"{BASE}/api/{ep}/{sid}")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                code_nokey = r.status
        except urllib.error.HTTPError as e:
            code_nokey = e.code
        check(f"/api/{ep} without key -> 401", code_nokey == 401, f"got {code_nokey}")

        req2 = urllib.request.Request(f"{BASE}/api/{ep}/{sid}")
        req2.add_header("X-ECDAT-Key", KEY)
        try:
            with urllib.request.urlopen(req2, timeout=30) as r:
                code_key = r.status
        except urllib.error.HTTPError as e:
            code_key = e.code
        check(f"/api/{ep} with key -> 200", code_key == 200, f"got {code_key}")

print()
failed = [n for n, ok, _ in results if not ok]
print(f"{len(results) - len(failed)}/{len(results)} checks passed")
if failed:
    print("FAILED: " + ", ".join(failed))
sys.exit(1 if failed else 0)
