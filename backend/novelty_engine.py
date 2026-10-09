"""
novelty_engine.py — XAI narrative, MITRE mapping, and telemetry coverage helpers.
This module is purely additive — imported by main.py for alert enrichment.
"""

import random
import time
from typing import Optional


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique catalogue (subset relevant to our simulated attacks)
# ---------------------------------------------------------------------------
_MITRE_MAP = {
    "DDoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "playbook": (
            "1. Rate-limit inbound SYN packets at perimeter firewall (>500 pps per src). "
            "2. Enable BGP Blackhole routing for top-offending /24 subnets. "
            "3. Activate upstream scrubbing centre if traffic exceeds 10 Gbps. "
            "4. Notify ISP abuse desk with pcap evidence."
        ),
    },
    "Port Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "playbook": (
            "1. Block offending src IP at edge router with 24 h ACL. "
            "2. Review exposed service inventory — close unnecessary ports. "
            "3. Enable IDS signature for Nmap/Masscan fingerprints. "
            "4. Correlate against threat-intel feeds for known scanner IPs."
        ),
    },
    "Data Exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "playbook": (
            "1. Immediately isolate src host from network (quarantine VLAN). "
            "2. Capture full PCAP of dst IP connection for forensics. "
            "3. Block dst IP at proxy & firewall egress. "
            "4. Initiate IR playbook PR-04 (Data Breach). "
            "5. Notify DPO if PII may be involved."
        ),
    },
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "playbook": (
            "1. Lock affected accounts after 5 failed attempts (already auto-triggered). "
            "2. Enforce MFA on SSH/RDP immediately. "
            "3. Rotate credentials for any accounts with recent successful logins from src IP. "
            "4. Add src IP to deny-list; geo-block origin country if warranted."
        ),
    },
    "SUSPICIOUS": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol Abuse",
        "tactic": "Command and Control",
        "playbook": (
            "1. Flag src IP for enhanced monitoring (48 h watchlist). "
            "2. Inspect TLS SNI/JA3 fingerprints for covert channel indicators. "
            "3. Cross-reference against OSINT threat feeds. "
            "4. Escalate to Tier-2 analyst if repeated within 10 minutes."
        ),
    },
    "DEFAULT": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "playbook": (
            "1. Log and retain for 30 days. "
            "2. No immediate action required unless score rises above threshold."
        ),
    },
}

# ---------------------------------------------------------------------------
# Narrative templates per attack type
# ---------------------------------------------------------------------------
_NARRATIVES = {
    "DDoS": [
        "A volumetric flood of {pkt} UDP packets was detected originating from {n_src} distinct "
        "external IP addresses targeting {dst}:{port}. The sustained packet rate is consistent with "
        "a botnet-amplified Distributed Denial of Service campaign. Avg TTL of {ttl} suggests "
        "spoofed source addresses. Immediate upstream mitigation is advised.",

        "High-volume SYN flood detected: {pkt} packets from {src} → {dst}:{port}. "
        "The attack pattern matches known DDoS-for-hire tooling. TTL={ttl} indicates possible "
        "IP spoofing. Traffic is already degrading availability — escalate to NOC.",
    ],
    "Port Scan": [
        "Sequential TCP SYN probes across {port_count} ports were observed from {src} targeting {dst}. "
        "The sweep pattern is consistent with automated reconnaissance tools (Nmap/Masscan). "
        "No successful connections established yet, but attacker has mapped open ports.",

        "Stealthy port scan from {src}: {pkt} probes over {dur}ms covering common service ports. "
        "This is likely pre-attack reconnaissance. The source IP has not been seen before, "
        "indicating a fresh or rotated threat actor infrastructure.",
    ],
    "Data Exfiltration": [
        "Critical: {mb} MB of data transferred from internal host {src} to external endpoint "
        "{dst}:{port} over {proto}. Outbound-to-inbound ratio of {ratio}:1 far exceeds baseline. "
        "This pattern is strongly indicative of automated data staging and exfiltration.",

        "Anomalous large outbound transfer detected: {src} → {dst}. {mb} MB sent in {dur}ms via "
        "{proto}. Destination IP has no prior legitimate business relationship. Possible data "
        "theft or ransomware exfiltration phase in progress.",
    ],
    "Brute Force": [
        "{src} has made {pkt} failed authentication attempts against {dst}:{port} ({proto}) "
        "within a short window. Credential stuffing or dictionary attack in progress. "
        "The target service has not yet locked out the account — immediate action required.",

        "Rapid-fire login attempts from {src} to {proto} service on {dst}:{port}. "
        "Request frequency of {pkt} attempts per minute exceeds human capability, "
        "confirming automated brute-force tooling. Rotate credentials immediately.",
    ],
    "DEFAULT": [
        "Anomalous traffic detected from {src} to {dst}:{port} via {proto}. "
        "Threat score of {score} triggered by unusual payload size ({mb} MB) and "
        "elevated packet frequency ({pkt} packets). Pattern does not match known baselines.",
    ],
}


def generate_xai_narrative(packet_data: dict) -> dict:
    """
    Returns a structured XAI enrichment payload for a given processed log dict.
    Includes: plain-English narrative, MITRE technique, tactic, and response playbook.
    """
    label = packet_data.get("attack_label") or (
        "SUSPICIOUS" if packet_data.get("traffic_type") == "SUSPICIOUS" else "DEFAULT"
    )
    mitre = _MITRE_MAP.get(label, _MITRE_MAP["DEFAULT"])
    templates = _NARRATIVES.get(label, _NARRATIVES["DEFAULT"])

    src = packet_data.get("src_ip", "?.?.?.?")
    dst = packet_data.get("dst_ip", "?.?.?.?")
    port = packet_data.get("dst_port", 0)
    proto = packet_data.get("protocol", "TCP")
    pkt = packet_data.get("packet_count", 1)
    ttl = packet_data.get("ttl", 64)
    dur = round(packet_data.get("duration_ms", 0), 1)
    score = packet_data.get("threat_score", 0)
    bytes_sent = packet_data.get("bytes_sent", 0)
    bytes_recv = packet_data.get("bytes_recv", 1)
    mb = round(bytes_sent / 1_000_000, 2)
    ratio = round(bytes_sent / max(bytes_recv, 1), 1)
    n_src = random.randint(12, 300)      # simulated distinct sources for DDoS
    port_count = random.randint(50, 900) # simulated ports scanned

    tmpl = random.choice(templates)
    narrative = tmpl.format(
        src=src, dst=dst, port=port, proto=proto, pkt=pkt, ttl=ttl,
        dur=dur, score=score, mb=mb, ratio=ratio, n_src=n_src, port_count=port_count,
    )

    return {
        "narrative": narrative,
        "mitre_technique_id": mitre["technique_id"],
        "mitre_technique_name": mitre["technique_name"],
        "mitre_tactic": mitre["tactic"],
        "playbook": mitre["playbook"],
        "confidence": round(min(score / 100.0, 0.99), 2),
        "generated_at": time.time(),
    }


# ---------------------------------------------------------------------------
# Telemetry coverage & blind-spot analysis
# ---------------------------------------------------------------------------
_TELEMETRY_SOURCES = {
    "Network Flows (NetFlow/IPFIX)": {"coverage": 100, "active": True},
    "DNS Query Logs":                {"coverage": 100, "active": True},
    "HTTP/TLS Proxy Logs":           {"coverage": 85,  "active": True},
    "Endpoint Process Execution":    {"coverage": 0,   "active": False},
    "Windows Event Logs (SIEM)":     {"coverage": 0,   "active": False},
    "Cloud Trail / API Logs":        {"coverage": 0,   "active": False},
    "Email Gateway Logs":            {"coverage": 0,   "active": False},
    "Identity Provider (IdP) Logs":  {"coverage": 0,   "active": False},
}


def get_telemetry_coverage() -> dict:
    """
    Returns structured telemetry coverage data including a Blind Spot Index.
    Blind Spot Index = fraction of sources with 0% coverage (0=perfect, 1=blind).
    """
    sources = []
    total = len(_TELEMETRY_SOURCES)
    missing = 0

    for name, meta in _TELEMETRY_SOURCES.items():
        sources.append({
            "name": name,
            "coverage_pct": meta["coverage"],
            "active": meta["active"],
        })
        if not meta["active"]:
            missing += 1

    blind_spot_index = round(missing / total, 2)
    active_count = total - missing

    return {
        "sources": sources,
        "blind_spot_index": blind_spot_index,
        "blind_spot_pct": round(blind_spot_index * 100, 1),
        "active_sources": active_count,
        "total_sources": total,
        "missing_sources": missing,
        "risk_note": (
            "HOST/PROCESS TELEMETRY ABSENT — lateral movement and fileless attacks "
            "cannot be detected. Recommend deploying EDR agents immediately."
            if blind_spot_index > 0.5
            else "Telemetry coverage acceptable."
        ),
    }
