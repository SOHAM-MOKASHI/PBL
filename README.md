# 🛡️ CSOC — Cognitive Security Operations Center
### AI-Driven Real-Time Threat Detection Dashboard | Hackathon Demo

---

## ✨ Overview

A fully in-memory, zero-external-dependency **Cybersecurity Operations Center** dashboard featuring:

- 🔴 **Real-time AI threat detection** via a 4-stage pipeline (Ingest → Heuristic Drop → ML Scoring → Alert Generation)  
- ⚡ **Live attack simulations** — DDoS bursts, Port Scans, Data Exfiltration & Brute Force every 15–22 seconds  
- 📡 **WebSocket streaming** from FastAPI → React  
- 📊 **Live Recharts time-series** with animated threat score curves  
- 🖥️ **Dark cyberpunk terminal UI** with scanline effects, glow animations, and critical red flashes  

---

## 🗂️ Project Structure

```
PBL2/
├── backend/
│   ├── main.py           # FastAPI server — 4-stage pipeline + WebSocket hub
│   ├── traffic_gen.py    # Simulated network traffic + attack injections
│   └── requirements.txt  # Python dependencies
└── frontend/
    ├── src/
    │   ├── App.jsx                    # Main layout & orchestration
    │   ├── components/
    │   │   ├── MetricCards.jsx        # KPI cards (Component 4)
    │   │   ├── ThreatChart.jsx        # Live Recharts time-series (Component 2)
    │   │   ├── TerminalFeed.jsx       # Scrolling log terminal (Component 1)
    │   │   ├── AlertPanel.jsx         # High-priority alerts (Component 3)
    │   │   └── PipelineView.jsx       # 4-stage pipeline visualization
    │   └── hooks/
    │       └── useWebSocket.js        # Auto-reconnecting WebSocket hook
    ├── tailwind.config.js
    ├── vite.config.js
    └── package.json
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Python | ≥ 3.11 |
| Node.js | ≥ 18 |
| npm | ≥ 9 |

---

### Step 1 — Install Python dependencies

```bash
cd backend
pip install -r requirements.txt
```

### Step 2 — Install Node dependencies (first time only)

```bash
cd ../frontend
npm install
```

---

### Step 3 — Launch Backend (Terminal 1)

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

You should see:
```
✅ CSOC Backend started — traffic generator & pipeline running.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

### Step 4 — Launch Frontend (Terminal 2)

```bash
cd frontend
npm run dev
```

Open: **http://localhost:5173**

---

### ⚡ One-liner (PowerShell, run from `PBL2/`)

```powershell
# Terminal 1
cd backend; uvicorn main:app --port 8000 --reload

# Terminal 2 (separate window)
cd frontend; npm run dev
```

---

## 🎯 Dashboard Components

| Component | Description |
|-----------|-------------|
| **Metric Cards** | Total Packets Analyzed, Active Threats, Total Alerts, Logs Scored |
| **AI Pipeline** | Visual 4-stage flow with live event counts per stage |
| **Threat Chart** | Real-time area chart — Avg Score + Peak Score curves with CRITICAL/HIGH lines |
| **Terminal Feed** | Raw log stream with color-coded severity, IP chips, byte sizes |
| **Alert Panel** | HIGH/CRITICAL alerts with red flash, attack labels, and pipeline stage badges |

---

## ⚔️ Attack Simulation Schedule

Attack bursts inject every **15–22 seconds** randomly cycling through:

| Attack | Events/Burst | Indicators |
|--------|-------------|------------|
| **DDoS** | 30–60 packets | Many IPs → 1 target, SYN flood, low TTL |
| **Port Scan** | 50–100 probes | Sequential ports, 60-byte SYN packets |
| **Data Exfiltration** | 10–25 flows | Massive outbound (500KB–5MB), odd ports |
| **Brute Force** | 30–50 attempts | Same IP → SSH/RDP, rapid retries |

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/metrics` | Current pipeline metrics |
| `GET` | `/api/logs/recent` | Last 50 processed logs |
| `GET` | `/api/alerts` | Last 30 HIGH/CRITICAL alerts |
| `GET` | `/api/timeline` | Threat score time-series buckets |
| `WS`  | `/ws/alerts` | Live WebSocket stream |
| `GET` | `/health` | Health check |

---

## 🧠 AI Pipeline Stages

```
[RAW LOGS] → S1: INGEST → S2: HEURISTIC DROP → S3: ML SCORE → S4: ALERT GEN → [WS BROADCAST]
```

| Stage | Logic |
|-------|-------|
| **S1 Ingest** | Deserialize log, add metadata |
| **S2 Heuristic Drop** | Drop trusted-subnet port-80/443 traffic (~40% noise reduction) |
| **S3 ML Score** | Weighted scoring: payload size + port risk + IP frequency + TTL + protocol + label |
| **S4 Alert Gen** | Classify: `CRITICAL ≥85`, `HIGH ≥60`, `MEDIUM ≥35`, `LOW <35` |

---

> Built for hackathon demo purposes. All data is synthetically generated in-memory — no external APIs, databases, or credentials required.
