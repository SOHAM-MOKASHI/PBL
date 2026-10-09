"""
test_csoc.py — Full backend test suite for CSOC
Tests: REST endpoints, pipeline liveness, novelty_engine, WebSocket feedback
"""
import asyncio
import json
import sys
import time
import urllib.request
import urllib.error
import websockets

BASE = "http://localhost:8000"
WS_ALERTS = "ws://localhost:8000/ws/alerts"
WS_FEEDBACK = "ws://localhost:8000/ws/feedback"

PASS = "[PASS]"
FAIL = "[FAIL]"
WARN = "[WARN]"

results = []

# ── Helpers ────────────────────────────────────────────────────────────────

def http_get(path, timeout=5):
    url = f"{BASE}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read())

def check(name, passed, detail=""):
    mark = PASS if passed else FAIL
    results.append(passed)
    print(f"  {mark}  {name}")
    if detail:
        print(f"           {detail}")

def section(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


# ── 1. REST Endpoints ──────────────────────────────────────────────────────
section("REST API Endpoints")

try:
    status, body = http_get("/health")
    check("GET /health returns 200", status == 200)
    check("GET /health has 'status' key", "status" in body, f"status={body.get('status')}")
    check("GET /health has 'ts' timestamp", "ts" in body, f"ts={body.get('ts')}")
except Exception as e:
    check("GET /health", False, str(e))

try:
    status, body = http_get("/api/metrics")
    check("GET /api/metrics returns 200", status == 200)
    for k in ["total_ingested", "total_dropped", "total_scored", "total_alerts", "active_threats"]:
        check(f"  metrics has '{k}'", k in body, f"{k}={body.get(k)}")
except Exception as e:
    check("GET /api/metrics", False, str(e))

try:
    status, body = http_get("/api/logs/recent?limit=10")
    check("GET /api/logs/recent returns 200", status == 200)
    check("GET /api/logs/recent returns a list", isinstance(body, list), f"len={len(body)}")
    if body:
        log = body[0]
        for k in ["src_ip", "dst_ip", "threat_score", "severity", "stage"]:
            check(f"  log entry has '{k}'", k in log, f"{k}={log.get(k)}")
except Exception as e:
    check("GET /api/logs/recent", False, str(e))

try:
    status, body = http_get("/api/alerts?limit=10")
    check("GET /api/alerts returns 200", status == 200)
    check("GET /api/alerts returns a list", isinstance(body, list), f"len={len(body)}")
    if body:
        alert = body[0]
        check("  alert has 'alert_id'", "alert_id" in alert, alert.get("alert_id"))
        check("  alert has 'threat_score'", "threat_score" in alert)
        check("  alert has 'severity'", alert.get("severity") in ("CRITICAL","HIGH","MEDIUM","LOW"))
except Exception as e:
    check("GET /api/alerts", False, str(e))

try:
    status, body = http_get("/api/timeline")
    check("GET /api/timeline returns 200", status == 200)
    check("GET /api/timeline returns a list", isinstance(body, list))
    if body:
        bucket = body[-1]
        for k in ["ts", "time", "avg_score", "max_score", "count"]:
            check(f"  timeline bucket has '{k}'", k in bucket)
except Exception as e:
    check("GET /api/timeline", False, str(e))

try:
    status, body = http_get("/api/telemetry")
    check("GET /api/telemetry returns 200", status == 200)
    check("  has 'blind_spot_index'", "blind_spot_index" in body, f"{body.get('blind_spot_index')}")
    check("  has 'sources' list", isinstance(body.get("sources"), list), f"len={len(body.get('sources',[]))}")
    check("  has 'active_sources'", "active_sources" in body, f"{body.get('active_sources')}/{body.get('total_sources')}")
    check("  blind_spot_index in [0,1]", 0 <= body.get("blind_spot_index", -1) <= 1)
    check("  risk_note present", bool(body.get("risk_note")))
except Exception as e:
    check("GET /api/telemetry", False, str(e))

try:
    status, body = http_get("/api/threshold")
    check("GET /api/threshold returns 200", status == 200)
    check("  has 'threshold'", "threshold" in body, f"threshold={body.get('threshold')}")
    check("  threshold in [50,99]", 50 <= body.get("threshold", 0) <= 99)
    check("  has 'whitelist' list", isinstance(body.get("whitelist"), list))
except Exception as e:
    check("GET /api/threshold", False, str(e))


# ── 2. Pipeline Liveness ───────────────────────────────────────────────────
section("Pipeline Liveness (4-Stage)")

try:
    _, m1 = http_get("/api/metrics")
    time.sleep(4)
    _, m2 = http_get("/api/metrics")
    check("Stage 1 (Ingest): counter incrementing",
          m2["total_ingested"] > m1["total_ingested"],
          f"{m1['total_ingested']} -> {m2['total_ingested']}")
    check("Stage 2 (Heuristic Drop): drops happening",
          m2["total_dropped"] >= m1["total_dropped"],
          f"dropped={m2['total_dropped']}")
    check("Stage 3 (ML Score): scored counter growing",
          m2["total_scored"] > m1["total_scored"],
          f"{m1['total_scored']} -> {m2['total_scored']}")
    check("Stage 4 (Alert Gen): alerts tracked",
          isinstance(m2["total_alerts"], int),
          f"total_alerts={m2['total_alerts']}")
    drop_rate = round(m2["total_dropped"] / max(m2["total_ingested"], 1) * 100, 1)
    check(f"Heuristic drop rate reasonable (>5%)", drop_rate > 5, f"drop_rate={drop_rate}%")
except Exception as e:
    check("Pipeline liveness", False, str(e))


# ── 3. XAI Enrichment ─────────────────────────────────────────────────────
section("XAI Alert Enrichment (novelty_engine)")

try:
    _, alerts = http_get("/api/alerts?limit=30")
    xai_alerts = [a for a in alerts if "xai" in a]
    check("XAI-enriched alerts exist in queue", len(xai_alerts) > 0,
          f"{len(xai_alerts)}/{len(alerts)} alerts have XAI data")
    if xai_alerts:
        xai = xai_alerts[0]["xai"]
        for k in ["narrative", "mitre_technique_id", "mitre_technique_name", "mitre_tactic", "playbook", "confidence"]:
            check(f"  xai has '{k}'", k in xai, str(xai.get(k, ""))[:60])
        check("  confidence in [0,1]", 0 <= xai.get("confidence", -1) <= 1)
        check("  mitre_technique_id starts with 'T'", str(xai.get("mitre_technique_id","")).startswith("T"))
        check("  narrative non-empty", len(xai.get("narrative","")) > 20)
        check("  playbook non-empty", len(xai.get("playbook","")) > 10)
except Exception as e:
    check("XAI enrichment", False, str(e))


# ── 4. Dynamic Threshold ──────────────────────────────────────────────────
section("Dynamic Threshold Logic")

async def test_feedback():
    try:
        async with websockets.connect(WS_FEEDBACK, ping_timeout=5) as ws:
            # Get initial threshold
            init_msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            check("WS /ws/feedback connects and sends init", init_msg.get("type") == "threshold_update",
                  f"threshold={init_msg.get('threshold_value')}")
            init_threshold = init_msg["threshold_value"]

            # Test: confirm_threat → threshold -1
            await ws.send(json.dumps({"type": "confirm_threat", "ip": "1.2.3.4"}))
            resp1 = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            new_t = resp1.get("threshold_value", init_threshold)
            check("confirm_threat decreases threshold by 1",
                  abs(new_t - (init_threshold - 1.0)) < 0.01,
                  f"{init_threshold} -> {new_t} (expected {init_threshold - 1.0})")

            # Test: false_positive → threshold +2
            before = new_t
            await ws.send(json.dumps({"type": "false_positive", "ip": "5.6.7.8"}))
            resp2 = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            after = resp2.get("threshold_value", before)
            check("false_positive raises threshold by 2",
                  abs(after - (before + 2.0)) < 0.01,
                  f"{before} -> {after} (expected {before + 2.0})")

            # Test: whitelist size incremented
            ws_size = resp2.get("whitelist_size", 0)
            check("false_positive adds IP to whitelist", ws_size >= 1, f"whitelist_size={ws_size}")

            # Verify via REST
            _, thr = http_get("/api/threshold")
            check("REST /api/threshold reflects WS changes",
                  abs(thr["threshold"] - after) < 0.01,
                  f"REST threshold={thr['threshold']}")
            check("REST /api/threshold whitelist contains IP",
                  "5.6.7.8" in thr["whitelist"],
                  f"whitelist={thr['whitelist'][:3]}")

    except Exception as e:
        check("WS /ws/feedback", False, str(e))

asyncio.run(test_feedback())


# ── 5. WebSocket /ws/alerts ────────────────────────────────────────────────
section("WebSocket /ws/alerts Stream")

async def test_ws_alerts():
    try:
        async with websockets.connect(WS_ALERTS, ping_timeout=5) as ws:
            # Should receive init frame first
            init_raw = await asyncio.wait_for(ws.recv(), timeout=8)
            init = json.loads(init_raw)
            check("WS /ws/alerts init frame received", init.get("type") == "init",
                  f"type={init.get('type')}")
            check("  init has 'metrics'", "metrics" in init)
            check("  init has 'recent_logs' list", isinstance(init.get("recent_logs"), list))
            check("  init has 'timeline' list", isinstance(init.get("timeline"), list))

            # Collect a few live log messages
            live_msgs = []
            deadline = time.time() + 6
            while time.time() < deadline and len(live_msgs) < 5:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=3)
                    msg = json.loads(raw)
                    if msg.get("type") == "log":
                        live_msgs.append(msg)
                except asyncio.TimeoutError:
                    break

            check("Live log frames received over WS", len(live_msgs) >= 1,
                  f"received {len(live_msgs)} frames")
            if live_msgs:
                msg = live_msgs[0]
                check("  log frame has 'data'", "data" in msg)
                check("  log frame has 'metrics'", "metrics" in msg)
                check("  log frame has 'threshold'", "threshold" in msg,
                      f"threshold={msg.get('threshold')}")
                data = msg.get("data", {})
                check("  data has threat_score", "threat_score" in data,
                      f"score={data.get('threat_score')}")
                check("  data has severity", data.get("severity") in ("CRITICAL","HIGH","MEDIUM","LOW"))
                check("  data has src_ip", bool(data.get("src_ip")))

    except Exception as e:
        check("WS /ws/alerts", False, str(e))

asyncio.run(test_ws_alerts())


# ── 6. novelty_engine unit tests ──────────────────────────────────────────
section("novelty_engine Unit Tests (direct import)")

sys.path.insert(0, ".")
try:
    from novelty_engine import generate_xai_narrative, get_telemetry_coverage

    # generate_xai_narrative
    for attack in ["DDoS", "Port Scan", "Data Exfiltration", "Brute Force", None]:
        mock_packet = {
            "src_ip": "203.0.113.42",
            "dst_ip": "10.0.1.100",
            "dst_port": 22 if attack == "Brute Force" else 80,
            "protocol": "SSH" if attack == "Brute Force" else "TCP",
            "packet_count": 500,
            "bytes_sent": 2_000_000 if attack == "Data Exfiltration" else 1024,
            "bytes_recv": 200,
            "duration_ms": 3000,
            "ttl": 10,
            "threat_score": 92.0,
            "attack_label": attack,
        }
        xai = generate_xai_narrative(mock_packet)
        label = attack or "DEFAULT"
        check(f"  generate_xai_narrative({label}) returns dict", isinstance(xai, dict))
        check(f"    -> has narrative", len(xai.get("narrative","")) > 10)
        check(f"    -> has mitre_technique_id", xai.get("mitre_technique_id","").startswith("T"))
        check(f"    -> confidence in [0,1]", 0 <= xai.get("confidence",-1) <= 1)

    # get_telemetry_coverage
    cov = get_telemetry_coverage()
    check("get_telemetry_coverage() returns dict", isinstance(cov, dict))
    check("  blind_spot_index in [0,1]", 0 <= cov.get("blind_spot_index",-1) <= 1)
    check("  sources is a list", isinstance(cov.get("sources"), list))
    check("  active_sources + missing_sources == total_sources",
          cov.get("active_sources",0) + cov.get("missing_sources",0) == cov.get("total_sources",0))
    for src in cov["sources"]:
        check(f"  source '{src['name'][:30]}' has coverage_pct",
              0 <= src.get("coverage_pct",-1) <= 100)

except Exception as e:
    check("novelty_engine import/tests", False, str(e))


# ── Summary ────────────────────────────────────────────────────────────────
section("TEST SUMMARY")
passed = sum(1 for r in results if r)
total = len(results)
bar = "=" * 60
print(f"\n{bar}")
pct = round(passed / total * 100, 1) if total else 0
print(f"  {passed}/{total} tests passed ({pct}%)")
if passed == total:
    print("  All systems operational.")
else:
    failed = [i+1 for i,r in enumerate(results) if not r]
    print(f"  Failed test indices: {failed}")
print(f"{bar}\n")
