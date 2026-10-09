"""
traffic_gen.py — Simulated Network Traffic Generator
Generates realistic baseline logs and periodically injects attack patterns.
"""

import asyncio
import random
import time
import json
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

# ---------------------------------------------------------------------------
# IP / Port pools
# ---------------------------------------------------------------------------
TRUSTED_SUBNETS = ["10.0.0.", "192.168.1.", "172.16.0."]
EXTERNAL_IPS = [
    f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
    for _ in range(200)
]
INTERNAL_IPS = [f"10.0.{random.randint(0,5)}.{random.randint(2,254)}" for _ in range(50)]

COMMON_PORTS = [80, 443, 22, 3306, 5432, 8080, 8443, 53, 25, 110, 993]
SENSITIVE_PORTS = [22, 3306, 5432, 8080, 23, 21, 3389, 1433]
SCAN_PORTS = list(range(1, 1025))

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "FTP", "SMTP"]

ATTACK_TYPES = ["DDoS", "Port Scan", "Data Exfiltration", "Brute Force", "SQL Injection"]

# ---------------------------------------------------------------------------
# Log event dataclass
# ---------------------------------------------------------------------------
class TrafficType(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"

@dataclass
class NetworkLog:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int
    bytes_recv: int
    duration_ms: float
    traffic_type: str
    attack_label: Optional[str] = None
    packet_count: int = 1
    ttl: int = 64
    flags: str = "ACK"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp
        return d


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def _random_trusted_ip() -> str:
    subnet = random.choice(TRUSTED_SUBNETS)
    return f"{subnet}{random.randint(2, 254)}"

def _random_external_ip() -> str:
    return random.choice(EXTERNAL_IPS)

def _random_internal_ip() -> str:
    return random.choice(INTERNAL_IPS)


def gen_normal_log() -> NetworkLog:
    """Generates a benign traffic log (HTTP/HTTPS on trusted subnets)."""
    src = _random_trusted_ip()
    dst = _random_trusted_ip()
    port = random.choice([80, 443, 8080, 53])
    proto = "HTTPS" if port == 443 else "HTTP"
    return NetworkLog(
        timestamp=time.time(),
        src_ip=src,
        dst_ip=dst,
        src_port=random.randint(1024, 65535),
        dst_port=port,
        protocol=proto,
        bytes_sent=random.randint(200, 4096),
        bytes_recv=random.randint(500, 16384),
        duration_ms=round(random.uniform(5.0, 120.0), 2),
        traffic_type=TrafficType.NORMAL,
        packet_count=random.randint(1, 20),
        ttl=random.choice([64, 128]),
        flags="ACK",
    )


def gen_suspicious_log() -> NetworkLog:
    """Generates a borderline suspicious log (external IP, non-standard port)."""
    src = _random_external_ip()
    dst = _random_internal_ip()
    port = random.choice(SENSITIVE_PORTS)
    return NetworkLog(
        timestamp=time.time(),
        src_ip=src,
        dst_ip=dst,
        src_port=random.randint(1024, 65535),
        dst_port=port,
        protocol=random.choice(["TCP", "UDP", "SSH"]),
        bytes_sent=random.randint(4096, 65536),
        bytes_recv=random.randint(100, 512),
        duration_ms=round(random.uniform(200.0, 2000.0), 2),
        traffic_type=TrafficType.SUSPICIOUS,
        packet_count=random.randint(20, 200),
        ttl=random.choice([32, 48, 60]),
        flags=random.choice(["SYN", "SYN-ACK", "RST"]),
    )


def gen_ddos_burst(count: int = 50) -> list[NetworkLog]:
    """Simulates a DDoS burst from many external IPs to one target."""
    target = _random_internal_ip()
    target_port = random.choice([80, 443, 8080])
    logs = []
    for _ in range(count):
        src = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
        logs.append(NetworkLog(
            timestamp=time.time(),
            src_ip=src,
            dst_ip=target,
            src_port=random.randint(1024, 65535),
            dst_port=target_port,
            protocol="UDP",
            bytes_sent=random.randint(512, 65535),
            bytes_recv=0,
            duration_ms=round(random.uniform(0.1, 5.0), 2),
            traffic_type=TrafficType.ATTACK,
            attack_label="DDoS",
            packet_count=random.randint(500, 5000),
            ttl=random.choice([1, 5, 10, 32]),
            flags="SYN",
        ))
    return logs


def gen_port_scan(count: int = 80) -> list[NetworkLog]:
    """Simulates a sequential port scan from a single attacker IP."""
    src = _random_external_ip()
    dst = _random_internal_ip()
    ports = random.sample(SCAN_PORTS, min(count, len(SCAN_PORTS)))
    logs = []
    for port in ports:
        logs.append(NetworkLog(
            timestamp=time.time(),
            src_ip=src,
            dst_ip=dst,
            src_port=random.randint(40000, 65535),
            dst_port=port,
            protocol="TCP",
            bytes_sent=60,
            bytes_recv=random.choice([0, 40]),
            duration_ms=round(random.uniform(0.1, 2.0), 2),
            traffic_type=TrafficType.ATTACK,
            attack_label="Port Scan",
            packet_count=1,
            ttl=64,
            flags="SYN",
        ))
    return logs


def gen_data_exfil(count: int = 20) -> list[NetworkLog]:
    """Simulates data exfiltration: large outbound payloads to external IP."""
    src = _random_internal_ip()
    dst = _random_external_ip()
    logs = []
    for _ in range(count):
        logs.append(NetworkLog(
            timestamp=time.time(),
            src_ip=src,
            dst_ip=dst,
            src_port=random.randint(40000, 65535),
            dst_port=random.choice([443, 8443, 4444, 6666]),
            protocol="TCP",
            bytes_sent=random.randint(500_000, 5_000_000),
            bytes_recv=random.randint(100, 500),
            duration_ms=round(random.uniform(1000.0, 8000.0), 2),
            traffic_type=TrafficType.ATTACK,
            attack_label="Data Exfiltration",
            packet_count=random.randint(1000, 10000),
            ttl=random.choice([48, 64]),
            flags="ACK",
        ))
    return logs


def gen_brute_force(count: int = 40) -> list[NetworkLog]:
    """Simulates SSH/RDP brute-force logins."""
    src = _random_external_ip()
    dst = _random_internal_ip()
    port = random.choice([22, 3389])
    proto = "SSH" if port == 22 else "RDP"
    logs = []
    for _ in range(count):
        logs.append(NetworkLog(
            timestamp=time.time(),
            src_ip=src,
            dst_ip=dst,
            src_port=random.randint(40000, 65535),
            dst_port=port,
            protocol=proto,
            bytes_sent=random.randint(200, 1024),
            bytes_recv=random.randint(100, 512),
            duration_ms=round(random.uniform(50.0, 500.0), 2),
            traffic_type=TrafficType.ATTACK,
            attack_label="Brute Force",
            packet_count=random.randint(5, 50),
            ttl=64,
            flags=random.choice(["SYN", "ACK", "RST"]),
        ))
    return logs


# ---------------------------------------------------------------------------
# Async queue — shared with main.py
# ---------------------------------------------------------------------------
log_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)


async def run_traffic_generator():
    """
    Main coroutine: emits ~10 baseline logs/s, injects attack bursts every 15-20s.
    """
    loop_count = 0
    next_attack_at = time.time() + random.uniform(10, 15)

    while True:
        now = time.time()

        # --- Baseline traffic (5-10 normal + 0-2 suspicious per iteration) ---
        batch: list[NetworkLog] = []
        for _ in range(random.randint(5, 10)):
            batch.append(gen_normal_log())
        for _ in range(random.randint(0, 2)):
            batch.append(gen_suspicious_log())

        # --- Inject attack burst on schedule ---
        if now >= next_attack_at:
            attack = random.choice(["ddos", "scan", "exfil", "brute"])
            if attack == "ddos":
                batch.extend(gen_ddos_burst(random.randint(30, 60)))
            elif attack == "scan":
                batch.extend(gen_port_scan(random.randint(50, 100)))
            elif attack == "exfil":
                batch.extend(gen_data_exfil(random.randint(10, 25)))
            else:
                batch.extend(gen_brute_force(random.randint(30, 50)))
            next_attack_at = now + random.uniform(15, 22)

        random.shuffle(batch)
        for log in batch:
            try:
                log_queue.put_nowait(log)
            except asyncio.QueueFull:
                pass  # drop if consumer is slow

        loop_count += 1
        await asyncio.sleep(1.0)
