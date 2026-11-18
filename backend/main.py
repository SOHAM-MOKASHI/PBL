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
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from traffic_gen import run_traffic_generator, log_queue, NetworkLog, TrafficType
from novelty_engine import generate_xai_narrative, get_telemetry_coverage
from database import init_db, load_config, save_alert, save_config

# ---------------------------------------------------------------------------
# App lifespan context manager (modern FastAPI standard, replaces on_event)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global CURRENT_ALERT_THRESHOLD, BENIGN_WHITELIST
    # Initialize DB (creates sqlite schema if not present)
    init_db()

    # Load persistent configurations if they exist
    t, w = load_config()
    CURRENT_ALERT_THRESHOLD = t
    BENIGN_WHITELIST = w

    traffic_task = asyncio.create_task(run_traffic_generator())
    pipeline_task = asyncio.create_task(process_pipeline())
    print("[OK] CSOC Backend started -- traffic generator, DB & pipeline running.")

    try:
        yield
    finally:
        traffic_task.cancel()
        pipeline_task.cancel()
        print("[STOP] CSOC Backend shutting down.")


# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------
app = FastAPI(title="CSOC Backend", version="1.0.0", lifespan=lifespan)

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
        state.total_alerts += 1
        state.active_threats = min(state.active_threats + 1, 50)
    elif score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"
        if state.active_threats > 0 and random.random() < 0.05:
            state.active_threats -= 1

    raw["severity"] = severity
    import uuid
    raw["alert_id"] = f"ALT-{int(time.time() * 1000) % 1_000_000:06d}-{uuid.uuid4().hex[:4]}"
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

        # Add all processed logs to the alerts queue to show a mix of severities
        state.alert_logs.appendleft(raw)

        # Persist all processed alerts to DB
        asyncio.create_task(asyncio.to_thread(save_alert, raw))

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
                asyncio.create_task(asyncio.to_thread(save_config, CURRENT_ALERT_THRESHOLD, BENIGN_WHITELIST))

            elif msg_type == "confirm_threat":
                CURRENT_ALERT_THRESHOLD = max(CURRENT_ALERT_THRESHOLD - 1.0, 50.0)
                BENIGN_WHITELIST.discard(ip)
                await feedback_manager.broadcast_threshold()
                asyncio.create_task(asyncio.to_thread(save_config, CURRENT_ALERT_THRESHOLD, BENIGN_WHITELIST))

    except WebSocketDisconnect:
        feedback_manager.disconnect(ws)
    except Exception:
        feedback_manager.disconnect(ws)




# ---------------------------------------------------------------------------
# ── VULNERABLE LOGIN TARGET & INGESTION ────────────────────────────────────
# ---------------------------------------------------------------------------
# Target authentication portal for real-time cyberattack demonstration
DEMO_USERNAME = "admin"
DEMO_PASSWORD = "admin123"

# Track failed attempts per IP for brute-force frequency scoring
_login_attempts: dict[str, list[float]] = defaultdict(list)


def _detect_attack_type(username: str, password: str) -> str:
    """Heuristic to classify the type of attack based on incoming payload."""
    sql_patterns = ["'", '"', "OR ", "UNION", "SELECT", "DROP", "--", ";", "1=1", "' OR", "/*", "*/"]
    xss_patterns = ["<script", "javascript:", "onerror", "onload", "alert(", "<img", "<svg", "eval("]

    combined = (username + " " + password).upper()
    if any(p.upper() in combined for p in sql_patterns):
        return "SQL Injection"
    if any(p.upper() in combined for p in xss_patterns):
        return "XSS Attack"
    return "Login Brute Force"


async def _handle_login_attempt(request: Request, username: str = "", password: str = ""):
    """
    Central login handler that captures real-time attack traffic from any tool
    (Hydra, Burp Suite, curl, python scripts, or browser forms),
    generates a standard network log, and passes it into the CSOC AI pipeline.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()

    attack_type = _detect_attack_type(username, password)
    is_success = (username == DEMO_USERNAME and password == DEMO_PASSWORD)

    # Track frequency for brute force scoring
    _login_attempts[client_ip].append(now)
    _login_attempts[client_ip] = [t for t in _login_attempts[client_ip] if now - t < 60]
    recent_count = len(_login_attempts[client_ip])

    # Build NetworkLog for CSOC pipeline
    log = NetworkLog(
        timestamp=now,
        src_ip=client_ip,
        dst_ip="10.0.1.50",         # Target application server
        src_port=request.client.port if request.client else random.randint(40000, 65535),
        dst_port=8000,
        protocol="HTTP",
        bytes_sent=len(username) + len(password) + 200,
        bytes_recv=512 if is_success else 256,
        duration_ms=round(random.uniform(5.0, 100.0), 2),
        traffic_type=TrafficType.NORMAL if is_success else TrafficType.ATTACK,
        attack_label="DEFAULT" if is_success else attack_type,
        packet_count=recent_count,
        ttl=64,
        flags="ACK" if is_success else "SYN",
    )

    # Feed into the same 4-stage pipeline queue used by traffic_gen & dataset
    try:
        log_queue.put_nowait(log)
    except asyncio.QueueFull:
        pass

    if is_success:
        return {"status": "success", "message": "Authentication successful", "user": username}
    else:
        return {
            "status": "failed",
            "message": "Invalid credentials",
            "attempts_last_60s": recent_count,
        }


import urllib.parse

@app.post("/api/login")
async def login_api(request: Request):
    """
    Universal login API endpoint.
    Accepts attacks from automated tools (Burp, Hydra, curl, custom scripts).
    Handles JSON, URL-encoded form data, and raw text bodies.
    """
    username = ""
    password = ""
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="ignore")

    # 1. Try parsing JSON
    try:
        data = json.loads(body_str)
        if isinstance(data, dict):
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))
    except Exception:
        pass

    # 2. Try parsing URL-encoded form data (e.g. username=admin&password=xyz)
    if not username and not password and body_str:
        try:
            parsed = urllib.parse.parse_qs(body_str)
            if "username" in parsed:
                username = parsed["username"][0]
            if "password" in parsed:
                password = parsed["password"][0]
        except Exception:
            pass

    # 3. Fallback: check query params (?username=admin&password=xyz)
    if not username and not password:
        username = request.query_params.get("username", "")
        password = request.query_params.get("password", "")

    # 4. If still empty but raw body exists, treat raw body as payload
    if not username and body_str:
        username = body_str[:100]
        password = "raw"

    result = await _handle_login_attempt(request, username, password)
    return result


# ---------------------------------------------------------------------------
# Standalone vulnerable login portal (served at /vulnerable-login)
# ---------------------------------------------------------------------------
CAMPUS_PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Campus Portal - Sign In</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f8fafc; min-height: 100vh; display: flex; flex-direction: column;
         justify-content: center; align-items: center; color: #1e293b; padding: 1rem; }
  .card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px;
          padding: 2.25rem 2rem; width: 100%; max-width: 400px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
  .logo { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.5rem; }
  .logo-icon { width: 36px; height: 36px; border-radius: 8px; background: #2563eb; color: #fff;
               display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 1.1rem; }
  .logo-text h1 { font-size: 1rem; font-weight: 700; color: #0f172a; line-height: 1.2; }
  .logo-text p { font-size: 0.75rem; color: #64748b; }
  label { display: block; font-size: 0.75rem; font-weight: 600; color: #475569; margin-bottom: 0.35rem; }
  input { width: 100%; padding: 0.55rem 0.75rem; border: 1px solid #cbd5e1; border-radius: 6px;
          font-size: 0.875rem; margin-bottom: 1rem; outline: none; transition: border-color 0.15s; }
  input:focus { border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }
  button { width: 100%; padding: 0.65rem; background: #2563eb; color: #ffffff; border: none;
           border-radius: 6px; font-size: 0.875rem; font-weight: 600; cursor: pointer; transition: background 0.15s; }
  button:hover { background: #1d4ed8; }
  .msg { font-size: 0.8rem; padding: 0.6rem 0.75rem; border-radius: 6px; margin-top: 1rem; display: none; }
  .msg.ok { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; display: block; }
  .msg.err { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; display: block; }
  .footer { margin-top: 1.5rem; text-align: center; font-size: 0.7rem; color: #94a3b8; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">U</div>
    <div class="logo-text">
      <h1>University Portal</h1>
      <p>Student & Staff Authentication Gateway</p>
    </div>
  </div>
  <form id="loginForm" method="POST" action="/vulnerable-login">
    <label for="username">Username / ID</label>
    <input type="text" id="username" name="username" placeholder="e.g. admin" required autocomplete="off">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" placeholder="••••••••" required>
    <button type="submit" id="submitBtn">Sign In</button>
  </form>
  <div id="result" class="msg"></div>
  <div class="footer">
    Authorized Access Only • Activity Logged & Monitored
  </div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const u = document.getElementById('username').value;
  const p = document.getElementById('password').value;
  const btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.textContent = 'Verifying...';
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: u, password: p})
    });
    const data = await res.json();
    const el = document.getElementById('result');
    if (data.status === 'success') {
      el.className = 'msg ok';
      el.textContent = 'Login successful. Welcome, ' + data.user;
    } else {
      el.className = 'msg err';
      el.textContent = 'Access Denied: Invalid credentials (' + data.attempts_last_60s + ' attempt(s) recorded)';
    }
  } catch (err) {
    const el = document.getElementById('result');
    el.className = 'msg err';
    el.textContent = 'Gateway error connecting to authentication server.';
  }
  btn.disabled = false;
  btn.textContent = 'Sign In';
});
</script>
</body>
</html>"""


@app.get("/vulnerable-login", response_class=HTMLResponse)
async def vulnerable_login_page():
    """Serves the standalone authentication portal."""
    return CAMPUS_PORTAL_HTML


@app.post("/vulnerable-login")
async def vulnerable_login_post(request: Request):
    """
    Direct POST target for form-based attack tools (e.g. Hydra, Burp, curl).
    Passes directly into the CSOC AI pipeline.
    """
    return await login_api(request)

