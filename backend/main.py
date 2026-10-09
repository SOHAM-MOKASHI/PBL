"""
main.py — CSOC FastAPI Backend
4-Stage AI Log Filtering Pipeline + WebSocket broadcaster
"""

import asyncio
import json
import math
import random
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from traffic_gen import run_traffic_generator, log_queue, NetworkLog, TrafficType
from novelty_engine import generate_xai_narrative, get_telemetry_coverage

# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------
app = FastAPI(title="CSOC Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------
class AppState:
    total_ingested: int = 0
    total_dropped_stage2: int = 0
    total_scored: int = 0
    total_alerts: int = 0
    active_threats: int = 0
    recent_logs: deque = deque(maxlen=200)        # raw terminal feed
    alert_logs: deque = deque(maxlen=100)          # high-priority alerts
    threat_timeline: deque = deque(maxlen=120)     # time-series for chart
    ip_frequency: dict = defaultdict(int)          # for frequency scoring
    ip_first_seen: dict = {}
    connected_clients: list = []                   # WebSocket clients

state = AppState()

# ---------------------------------------------------------------------------
# Dynamic threshold & RLHF whitelist  (additive)
# ---------------------------------------------------------------------------
CURRENT_ALERT_THRESHOLD: float = 85.0   # adjusted at runtime via /ws/feedback
BENIGN_WHITELIST: set = set()            # IPs confirmed benign by analyst
feedback_manager_ref = None              # filled after ConnectionManager init

# ---------------------------------------------------------------------------
# Trusted subnet set (stage 2 heuristic)
# ---------------------------------------------------------------------------
TRUSTED_PREFIXES = ("10.0.", "192.168.1.", "172.16.")
NORMAL_PORTS = {80, 443}

# ---------------------------------------------------------------------------
# ── STAGE PIPELINE ──────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def stage1_ingest(log: NetworkLog) -> dict:
    """Stage 1: Deserialize / enrich with ingestion metadata."""
    state.total_ingested += 1
    raw = log.to_dict()
    raw["ingested_at"] = time.time()
    raw["stage"] = 1
    return raw


def stage2_heuristic_drop(raw: dict) -> dict | None:
    """
    Stage 2: Drop benign traffic.
    Rule: src AND dst are both trusted AND dst_port is 80/443 → DROP.
    """
    src: str = raw["src_ip"]
    dst: str = raw["dst_ip"]
    dst_port: int = raw["dst_port"]

    src_trusted = any(src.startswith(p) for p in TRUSTED_PREFIXES)
    dst_trusted = any(dst.startswith(p) for p in TRUSTED_PREFIXES)
    is_normal_port = dst_port in NORMAL_PORTS

    if src_trusted and dst_trusted and is_normal_port and raw["traffic_type"] == TrafficType.NORMAL:
        state.total_dropped_stage2 += 1
        return None   # DROP

    raw["stage"] = 2
    return raw


def stage3_ml_anomaly_score(raw: dict) -> dict:
    """
    Stage 3: Simulated ML Anomaly Scoring (0-100).
    Combines: payload size, packet frequency, port risk, traffic type label.
    """
    score = 0.0

    # --- Payload size factor (large outbound = suspicious) ---
    bytes_out = raw.get("bytes_sent", 0)
    if bytes_out > 1_000_000:
        score += 40
    elif bytes_out > 100_000:
        score += 25
    elif bytes_out > 10_000:
        score += 10

    # --- Port risk factor ---
    risky_ports = {22, 23, 21, 3389, 4444, 6666, 1433, 3306}
    if raw["dst_port"] in risky_ports:
        score += 15

    # --- Protocol risk ---
    risky_protocols = {"SSH", "FTP", "SMTP", "RDP"}
    if raw.get("protocol") in risky_protocols:
        score += 10

    # --- Frequency factor (same src IP hitting us often) ---
    src_ip = raw["src_ip"]
    state.ip_frequency[src_ip] += 1
    freq = state.ip_frequency[src_ip]
    if freq > 200:
        score += 30
    elif freq > 100:
        score += 20
    elif freq > 50:
        score += 10

    # --- TTL anomaly (very low TTL = spoofing indicator) ---
    ttl = raw.get("ttl", 64)
    if ttl < 20:
        score += 15
    elif ttl < 48:
        score += 5

    # --- Packet count spike ---
    pkts = raw.get("packet_count", 1)
    if pkts > 2000:
        score += 20
    elif pkts > 500:
        score += 10

    # --- Label override for simulated attacks ---
    traffic_type = raw.get("traffic_type", "")
    if traffic_type == TrafficType.ATTACK:
        score = max(score, 70 + random.uniform(0, 25))   # always high

    # --- Add slight noise ---
    score += random.uniform(-3, 5)
    score = max(0.0, min(100.0, score))

    raw["threat_score"] = round(score, 1)
    raw["stage"] = 3
    state.total_scored += 1
    return raw


def stage4_alert_generation(raw: dict) -> dict:
    """
    Stage 4: Decide alert severity using dynamic threshold, update counters.
    """
    score = raw["threat_score"]
    src_ip = raw.get("src_ip", "")

    # Whitelisted IPs are always LOW regardless of score
    if src_ip in BENIGN_WHITELIST:
        raw["severity"] = "LOW"
        raw["alert_id"] = f"ALT-{int(time.time() * 1000) % 1_000_000:06d}"
        raw["stage"] = 4
        raw["whitelisted"] = True
        return raw

    if score >= CURRENT_ALERT_THRESHOLD:
        severity = "CRITICAL"
        state.total_alerts += 1
        state.active_threats = min(state.active_threats + 1, 50)
    elif score >= 60:
        severity = "HIGH"
    elif score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"
        if state.active_threats > 0 and random.random() < 0.05:
            state.active_threats -= 1

    raw["severity"] = severity
    raw["alert_id"] = f"ALT-{int(time.time() * 1000) % 1_000_000:06d}"
    raw["stage"] = 4
    raw["current_threshold"] = CURRENT_ALERT_THRESHOLD

    # Enrich CRITICAL and HIGH alerts with XAI narrative
    if severity in ("CRITICAL", "HIGH"):
        raw["xai"] = generate_xai_narrative(raw)

    return raw


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

async def process_pipeline():
    """Continuously drains log_queue through the 4-stage pipeline."""
    while True:
        try:
            log: NetworkLog = await asyncio.wait_for(log_queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            await asyncio.sleep(0.05)
            continue

        # Run stages
        raw = stage1_ingest(log)
        raw = stage2_heuristic_drop(raw)
        if raw is None:
            log_queue.task_done()
            continue

        raw = stage3_ml_anomaly_score(raw)
        raw = stage4_alert_generation(raw)

        # Store in recent_logs (all non-dropped)
        state.recent_logs.appendleft(raw)

        # Update threat timeline (1-second buckets)
        ts_bucket = int(raw["timestamp"])
        if state.threat_timeline and state.threat_timeline[-1]["ts"] == ts_bucket:
            prev = state.threat_timeline[-1]
            prev["avg_score"] = round((prev["avg_score"] * prev["count"] + raw["threat_score"]) / (prev["count"] + 1), 1)
            prev["count"] += 1
            prev["max_score"] = max(prev["max_score"], raw["threat_score"])
        else:
            state.threat_timeline.append({
                "ts": ts_bucket,
                "time": time.strftime("%H:%M:%S", time.localtime(ts_bucket)),
                "avg_score": raw["threat_score"],
                "max_score": raw["threat_score"],
                "count": 1,
            })

        # High priority → alerts queue + broadcast
        if raw["severity"] in ("CRITICAL", "HIGH"):
            state.alert_logs.appendleft(raw)

        # Broadcast to all WS clients
        await broadcast(raw)

        log_queue.task_done()


# ---------------------------------------------------------------------------
# WebSocket hub
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def send(self, ws: WebSocket, data: str):
        try:
            await ws.send_text(data)
        except Exception:
            self.disconnect(ws)

    async def broadcast(self, data: str):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()

async def broadcast(raw: dict):
    if not manager.active:
        return
    payload = json.dumps({
        "type": "log",
        "data": raw,
        "metrics": {
            "total_ingested": state.total_ingested,
            "total_dropped": state.total_dropped_stage2,
            "total_scored": state.total_scored,
            "total_alerts": state.total_alerts,
            "active_threats": state.active_threats,
        },
        "threshold": CURRENT_ALERT_THRESHOLD,
    })
    await manager.broadcast(payload)


# ---------------------------------------------------------------------------
# Feedback WebSocket manager (separate from alerts manager)
# ---------------------------------------------------------------------------
class FeedbackManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast_threshold(self):
        msg = json.dumps({
            "type": "threshold_update",
            "threshold_value": CURRENT_ALERT_THRESHOLD,
            "whitelist_size": len(BENIGN_WHITELIST),
        })
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

feedback_manager = FeedbackManager()


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/api/metrics")
async def get_metrics():
    return {
        "total_ingested": state.total_ingested,
        "total_dropped": state.total_dropped_stage2,
        "total_scored": state.total_scored,
        "total_alerts": state.total_alerts,
        "active_threats": state.active_threats,
    }


@app.get("/api/logs/recent")
async def get_recent_logs(limit: int = 50):
    return list(state.recent_logs)[:limit]


@app.get("/api/alerts")
async def get_alerts(limit: int = 30):
    return list(state.alert_logs)[:limit]


@app.get("/api/timeline")
async def get_timeline():
    return list(state.threat_timeline)


@app.get("/health")
async def health():
    return {"status": "ok", "ts": time.time()}


@app.get("/api/telemetry")
async def get_telemetry():
    """Returns telemetry coverage and blind-spot analysis."""
    return get_telemetry_coverage()


@app.get("/api/threshold")
async def get_threshold():
    return {"threshold": CURRENT_ALERT_THRESHOLD, "whitelist": list(BENIGN_WHITELIST)}


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/alerts")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    # Send current state on connect
    init_payload = json.dumps({
        "type": "init",
        "recent_logs": list(state.recent_logs)[:50],
        "alerts": list(state.alert_logs)[:20],
        "timeline": list(state.threat_timeline),
        "metrics": {
            "total_ingested": state.total_ingested,
            "total_dropped": state.total_dropped_stage2,
            "total_scored": state.total_scored,
            "total_alerts": state.total_alerts,
            "active_threats": state.active_threats,
        },
    })
    await ws.send_text(init_payload)

    try:
        while True:
            # Keep alive ping every 25s
            await asyncio.sleep(25)
            await ws.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        manager.disconnect(ws)


# ---------------------------------------------------------------------------
# RLHF Feedback WebSocket endpoint  (additive)
# ---------------------------------------------------------------------------

@app.websocket("/ws/feedback")
async def feedback_endpoint(ws: WebSocket):
    """
    Receives analyst RLHF feedback to tune the dynamic alert threshold.
    Supported messages:
      {"type": "false_positive", "ip": "x.x.x.x"}  -> threshold +2, IP whitelisted
      {"type": "confirm_threat",  "ip": "x.x.x.x"}  -> threshold -1, IP removed from whitelist
      {"type": "ping"}                               -> noop keepalive
    Broadcasts updated threshold_value to all feedback subscribers.
    """
    global CURRENT_ALERT_THRESHOLD
    await feedback_manager.connect(ws)
    # Send current state immediately on connect
    await ws.send_text(json.dumps({
        "type": "threshold_update",
        "threshold_value": CURRENT_ALERT_THRESHOLD,
        "whitelist_size": len(BENIGN_WHITELIST),
    }))
    try:
        while True:
            raw_msg = await ws.receive_text()
            try:
                msg = json.loads(raw_msg)
            except Exception:
                continue

            msg_type = msg.get("type", "")
            ip = msg.get("ip", "")

            if msg_type == "false_positive":
                CURRENT_ALERT_THRESHOLD = min(CURRENT_ALERT_THRESHOLD + 2.0, 99.0)
                if ip:
                    BENIGN_WHITELIST.add(ip)
                await feedback_manager.broadcast_threshold()

            elif msg_type == "confirm_threat":
                CURRENT_ALERT_THRESHOLD = max(CURRENT_ALERT_THRESHOLD - 1.0, 50.0)
                BENIGN_WHITELIST.discard(ip)
                await feedback_manager.broadcast_threshold()

    except WebSocketDisconnect:
        feedback_manager.disconnect(ws)
    except Exception:
        feedback_manager.disconnect(ws)


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(run_traffic_generator())
    asyncio.create_task(process_pipeline())
    print("[OK] CSOC Backend started -- traffic generator & pipeline running.")


@app.on_event("shutdown")
async def shutdown_event():
    print("[STOP] CSOC Backend shutting down.")
