import sqlite3
import json
import os

db_path = os.path.join(os.path.dirname(__file__), 'soc_prototype.db')
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

print("=" * 60)
print("  DATABASE: soc_prototype.db (SQLite)")
print("=" * 60)

# 1. Tables and Row Counts
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [t[0] for t in cursor.fetchall() if t[0] != 'sqlite_sequence']

for table in tables:
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    count = cursor.fetchone()[0]
    cursor.execute(f"PRAGMA table_info({table})")
    cols = [f"{col[1]} ({col[2]})" for col in cursor.fetchall()]
    print(f"\n[TABLE] {table} -> {count:,} total records")
    print(f"  Schema: {', '.join(cols)}")

# 2. Sample from alerts
print("\n" + "=" * 60)
print("  SAMPLE RECORDS: alerts (Latest 3 Elevated Incidents)")
print("=" * 60)
cursor.execute("""
    SELECT id, alert_id, src_ip, dst_ip, dst_port, protocol, threat_score, severity, attack_label
    FROM alerts
    WHERE severity IN ('CRITICAL', 'HIGH')
    ORDER BY id DESC LIMIT 3;
""")
rows = cursor.fetchall()
for r in rows:
    print(f"  ID: {r[0]} | Alert ID: {r[1]} | Severity: {r[7]} | Score: {r[6]} pts")
    print(f"    Attack: {r[8]} | Flow: {r[2]} -> {r[3]}:{r[4]} [{r[5]}]")

# 3. Sample from xai_narratives
print("\n" + "=" * 60)
print("  SAMPLE RECORDS: xai_narratives (Latest 2 Records)")
print("=" * 60)
cursor.execute("""
    SELECT id, alert_id, mitre_technique_id, mitre_technique_name, mitre_tactic, confidence, narrative, playbook
    FROM xai_narratives
    ORDER BY id DESC LIMIT 2;
""")
xai_rows = cursor.fetchall()
for x in xai_rows:
    print(f"  Alert ID: {x[1]}")
    print(f"    MITRE: {x[2]} ({x[3]}) - Tactic: {x[4]} | Confidence: {x[5]}")
    print(f"    Narrative: {x[6][:110]}...")
    print(f"    Playbook: {x[7][:95]}...")
    print()

# 4. Config Table
print("=" * 60)
print("  RUNTIME CONFIGURATION (configs table)")
print("=" * 60)
cursor.execute("SELECT key, value FROM configs;")
configs = cursor.fetchall()
for k, v in configs:
    print(f"  Key: {k} -> Value: {v}")

conn.close()
