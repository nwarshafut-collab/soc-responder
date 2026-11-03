"""Generates a SYNTHETIC attack scenario log file (no real data)."""
import csv, random
from datetime import datetime, timedelta
random.seed(7)
t0 = datetime(2026, 11, 3, 9, 0, 0)
rows = []
def add(minutes, ip, host, ev, details):
    rows.append(((t0 + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S"), ip, host, ev, details))

# Normal background noise
users = ["sara", "omar", "lina", "khaled"]
for i in range(25):
    add(i*3 + random.randint(0, 2), f"10.0.0.{random.randint(20, 40)}", "web-server-01",
        "login_success", f"user={random.choice(users)}")
for ip in ["10.0.0.21", "10.0.0.33"]:          # normal typo, not an attack
    for k in range(2):
        add(30 + k, ip, "web-server-01", "failed_login", "user=omar")

# FALSE POSITIVE: trusted internal vulnerability scanner
for p in range(20):
    add(10 + p*0.1, "10.0.0.5", "web-server-01", "port_probe", f"port={20+p}")

# REAL ATTACK from 203.0.113.45 (documentation IP range - fake)
atk = "203.0.113.45"
for p in [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]:
    add(40 + p/2000, atk, "web-server-01", "port_probe", f"port={p}")
for k in range(14):
    add(44 + k*0.2, atk, "web-server-01", "failed_login", "user=admin")
add(48, atk, "web-server-01", "login_success", "user=admin")
add(52, atk, "web-server-01", "privilege_escalation", "sudo su executed by admin")
add(58, atk, "web-server-01", "large_outbound_transfer", "850MB to 198.51.100.99")

# A second, weaker suspicious source (only brute force)
atk2 = "192.0.2.77"
for k in range(8):
    add(70 + k*0.3, atk2, "db-server-01", "failed_login", "user=root")

rows.sort()
with open("sample_logs/attack_scenario.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "source_ip", "dest_host", "event_type", "details"])
    w.writerows(rows)
print(len(rows), "events written")
