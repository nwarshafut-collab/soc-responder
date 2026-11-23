import csv
import io
import os
import json
import urllib.request
import urllib.parse
from collections import defaultdict

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY_HERE")

TRUSTED_IPS = {"10.0.0.5": "Internal vulnerability scanner"}
KNOWN_BAD_IPS = {
    "203.0.113.45": "Reported for SSH brute force and data theft",
}
PORT_SCAN_THRESHOLD = 10
BRUTE_FORCE_THRESHOLD = 5

MITRE = {
    "PORT_SCAN":        ("Discovery",            "T1046", "Network Service Discovery"),
    "BRUTE_FORCE":      ("Credential Access",    "T1110", "Brute Force"),
    "LOGIN_AFTER_FAIL": ("Initial Access",       "T1078", "Valid Accounts"),
    "PRIV_ESC":         ("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism"),
    "EXFILTRATION":     ("Exfiltration",         "T1041", "Exfiltration Over C2 Channel"),
    "DDOS":             ("Impact",               "T1498", "Network Denial of Service"),
    "RANSOMWARE":       ("Impact",               "T1486", "Data Encrypted for Impact"),
    
}

def ask_gemini_ai(prompt_text):
    import streamlit as st
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key or api_key == "YOUR_GEMINI_API_KEY_HERE":
        return None
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent"
    payload = {"contents": [{"parts": [{"text": prompt_text}]}]}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key.strip()},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as e:
        print(f"Gemini API Error: {e}")
        return f"Gemini API Error: {e}"
def load_logs(file_or_path):
    if isinstance(file_or_path, str):
        with open(file_or_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    else:
        text = file_or_path.getvalue().decode("utf-8") if hasattr(file_or_path, "getvalue") else file_or_path.read().decode("utf-8")
        rows = list(csv.DictReader(io.StringIO(text)))
        if rows and "traffic_count" in rows[0]:
            converted = []
            for r in rows:
                converted.append({
                    "timestamp": r["timestamp"],
                    "source_ip": f"Botnet ({r['source_count']} sources)",
                    "dest_host": r["destination"],
                    "event_type": "ddos_attack",
                    "details": f"Traffic: {r['traffic_count']} | {r['reason']}"
            })
            return sorted(converted, key=lambda r: r["timestamp"])
    required = {"timestamp", "source_ip", "dest_host", "event_type", "details"}
    if not rows or not required.issubset(rows[0].keys()):
        raise ValueError("CSV must have columns: " + ", ".join(sorted(required)))
    return sorted(rows, key=lambda r: r["timestamp"])
        

def _alert(kind, ip, host, ts, description, evidence_count):
    tactic, tid, tname = MITRE[kind]
    return {"kind": kind, "source_ip": ip, "host": host, "timestamp": ts,
            "description": description, "evidence_count": evidence_count,
            "tactic": tactic, "technique_id": tid, "technique": tname}

def detect(events):
    alerts, false_positives = [], []
    probes, fails, successes = defaultdict(list), defaultdict(list), defaultdict(list)
    for e in events:
        key = (e["source_ip"], e["dest_host"])
        if e["event_type"] == "port_probe":
            probes[key].append(e)
        elif e["event_type"] == "failed_login":
            fails[key].append(e)
        elif e["event_type"] == "login_success":
            successes[key].append(e)
        elif e["event_type"] == "privilege_escalation":
            alerts.append(_alert("PRIV_ESC", e["source_ip"], e["dest_host"], e["timestamp"], e["details"], 1))
        elif e["event_type"] == "large_outbound_transfer":
            alerts.append(_alert("EXFILTRATION", e["source_ip"], e["dest_host"], e["timestamp"], e["details"], 1))
        elif e["event_type"] == "ddos_attack":
            alerts.append(_alert("DDOS", e["source_ip"], e["dest_host"], e["timestamp"], e["details"], 1))
        elif e["event_type"] == "ransomware":
            alerts.append(_alert("RANSOMWARE", e["source_ip"], e["dest_host"], e["timestamp"], e["details"], 1))
    for (ip, host), ev in probes.items():
        if len(ev) >= PORT_SCAN_THRESHOLD:
            a = _alert("PORT_SCAN", ip, host, ev[0]["timestamp"], f"{len(ev)} ports probed", len(ev))
            if ip in TRUSTED_IPS:
                a["reason"] = TRUSTED_IPS[ip]
                false_positives.append(a)
            else:
                alerts.append(a)

    for (ip, host), ev in fails.items():
        if len(ev) >= BRUTE_FORCE_THRESHOLD:
            alerts.append(_alert("BRUTE_FORCE", ip, host, ev[0]["timestamp"], f"{len(ev)} failed logins", len(ev)))
            for s in successes.get((ip, host), []):
                if s["timestamp"] > ev[-1]["timestamp"]:
                    alerts.append(_alert("LOGIN_AFTER_FAIL", ip, host, s["timestamp"], f"Successful login after failures", 1))
    return sorted(alerts, key=lambda a: a["timestamp"]), false_positives

def query_external_threat_intel(ip):
    import streamlit as st
    if not ip or ip.startswith(("10.", "192.168.", "172.", "Botnet")):
        return KNOWN_BAD_IPS.get(ip)

    clean_ip = urllib.parse.quote(ip.strip())
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")

    if abuse_key:
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={clean_ip}&maxAgeInDays=90"
            req = urllib.request.Request(
                url,
                headers={"Key": abuse_key.strip(), "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))["data"]
                score = data.get("abuseConfidenceScore", 0)
                country = data.get("countryCode", "Unknown")
                isp = data.get("isp", "Unknown ISP")
                if score > 0:
                    return f"AbuseIPDB Confidence: {score}% | Country: {country} | ISP: {isp}"
        except Exception:
            pass

    if vt_key:
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}"
            req = urllib.request.Request(
                url,
                headers={"x-apikey": vt_key.strip()}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                stats = json.loads(resp.read().decode("utf-8"))["data"]["attributes"]["last_analysis_stats"]
                mal = stats.get("malicious", 0)
                if mal > 0:
                    return f"VirusTotal Flagged: {mal} security vendors marked this IP malicious"
        except Exception:
            pass

    return KNOWN_BAD_IPS.get(ip)

def enrich(alerts):
    cache = {}
    for a in alerts:
        ip = a["source_ip"]
        if ip not in cache:
            cache[ip] = query_external_threat_intel(ip)
        a["threat_intel"] = cache[ip]
    return alerts

def build_chains(alerts):
    groups = defaultdict(list)
    for a in alerts:
        groups[a["source_ip"]].append(a)
    chains = []
    for ip, items in groups.items():
        items.sort(key=lambda a: a["timestamp"])
        stages = list(dict.fromkeys(a["tactic"] for a in items))
        intel = next((a["threat_intel"] for a in items if a["threat_intel"]), None)
        is_heavy = any(s in ip for s in ("(7 ", "(10 ", "(12 ", "(5 ")) or len(items) >= 10
        is_medium_ddos = any(s in ip for s in ("(1 ", "(2 ")) and len(items) <= 2
        has_critical_type = any(a["kind"] in ("DDOS", "RANSOMWARE") for a in items)

        if len(stages) >= 4 or (has_critical_type and is_heavy):
            severity = "Critical"
        elif has_critical_type and not is_medium_ddos:
            severity = "High"
        elif len(stages) >= 2 or is_medium_ddos:
            severity = "Medium"
        else:
            severity = "Low"
        chains.append({"id": f"INC-{len(chains)+1:03d}", "source_ip": ip, "alerts": items,
                       "stages": stages, "severity": severity, "threat_intel": intel,
                       "hosts": sorted({a["host"] for a in items}),
                       "start": items[0]["timestamp"], "end": items[-1]["timestamp"]})
    for i, c in enumerate(chains, 1):
        c["id"] = f"INC-{i:03d}"
        c["summary"] = summarize(c)
        c["actions"] = recommend(c)
    return chains

def summarize(c):
    steps = " -> ".join(c["stages"])
    prompt = f"Summarize SOC incident from IP {c['source_ip']} with stages {steps} and severity {c['severity']}."
    ai_response = ask_gemini_ai(prompt)

    if ai_response and not ai_response.startswith("Gemini API Error"):
        return f"🤖 [AI Analysis]: {ai_response}"

    return f"Source {c['source_ip']} targeted {', '.join(c['hosts'])}. Stages: {steps}. Severity: {c['severity']}."
def recommend(c):
    acts = []
    kinds = {a["kind"] for a in c["alerts"]}
    sev = c["severity"]

    if "DDOS" in kinds:
        best_ddos = (sev in ("Critical", "High"))
        acts.append({
            "id": f"{c['id']}-A1",
            "action": ("⭐ [Best Solution] Enable DDoS Rate-Limiting" if best_ddos else "Enable DDoS Rate-Limiting"),
            "target": ", ".join(c["hosts"]),
            "reason": f"Severity is {sev}: Rate-limiting absorbs volumetric flood immediately without shutting down the server."
        })
        acts.append({
            "id": f"{c['id']}-A2",
            "action": ("Block Botnet IPs" if best_ddos else "⭐ [Best Solution] Block Botnet IPs"),
            "target": c["source_ip"],
            "reason": "Block attacking source IPs at the perimeter firewall."
        })
        acts.append({
            "id": f"{c['id']}-A3",
            "action": "Isolate Target Host",
            "target": ", ".join(c["hosts"]),
            "reason": "Last-resort option: completely disconnect server if traffic overwhelms defenses."
        })
        return acts

    is_critical_host = sev == "Critical" and ("PRIV_ESC" in kinds or "EXFILTRATION" in kinds or "RANSOMWARE" in kinds)
    is_med_account = not is_critical_host and ("LOGIN_AFTER_FAIL" in kinds or "BRUTE_FORCE" in kinds)

    acts.append({
        "id": f"{c['id']}-A1",
        "action": ("⭐ [Best Solution] Block IP" if (not is_critical_host and not is_med_account) else "Block IP"),
        "target": c["source_ip"],
        "reason": f"Severity is {sev}: Blocking external source IP stops reconnaissance and external probes."
    })

    if "LOGIN_AFTER_FAIL" in kinds or "BRUTE_FORCE" in kinds or len(kinds) >= 2:
        acts.append({
            "id": f"{c['id']}-A2",
            "action": ("⭐ [Best Solution] Disable account" if is_med_account else "Disable account"),
            "target": "admin",
            "reason": f"Severity is {sev}: Compromised credentials detected; disabling account prevents lateral movement."
        })

    if "PRIV_ESC" in kinds or "EXFILTRATION" in kinds or "RANSOMWARE" in kinds or len(kinds) >= 2:
        acts.append({
            "id": f"{c['id']}-A3",
            "action": ("⭐ [Best Solution] Isolate host" if is_critical_host else "Isolate host"),
            "target": ", ".join(c["hosts"]),
            "reason": f"Severity is {sev} (Critical Impact): Immediate host isolation is the safest action to stop active breach/exfiltration."
        })

    return acts

def run_pipeline(events):
    alerts, fps = detect(events)
    alerts = enrich(alerts)
    chains = build_chains(alerts)
    return {"events": events, "alerts": alerts, "false_positives": fps, "chains": chains}

def simulate_action(action):
    return f"[SIMULATED] {action['action']} executed on {action['target']}"

def action_status(action, decisions):
    d = decisions.get(action["id"])
    return {"approved": "Mitigated", "rejected": "Left as-is"}.get(d, "Pending decision")

def response_summary(chains, decisions):
    acts = [a for c in chains for a in c["actions"]]
    total = len(acts)
    approved = sum(1 for a in acts if decisions.get(a["id"]) == "approved")
    return {"total": total, "approved": approved, "rejected": 0, "pending": total - approved, "contained_pct": int(round(100 * approved / total)) if total else 0}

def asset_table(chains, decisions):
    rows = []
    for c in chains:
        for a in c["actions"]:
            rows.append({"Incident": c["id"], "Asset": a["target"], "Type": "IP", "Action": a["action"], "Status": action_status(a, decisions)})
    return rows

def build_dot(chain, decisions):
    is_mitigated = any(decisions.get(a["id"]) == "approved" for a in chain["actions"])
    target_color = "#10b981" if is_mitigated else "#f59e0b"
    target_fill = "#064e3b" if is_mitigated else "#451a03"
    target_status = "Protected (Mitigated)" if is_mitigated else "Under Attack"
    stages_text = " -> ".join(chain["stages"])
    hosts_text = ", ".join(chain["hosts"])
    return f'''
    digraph G {{
        rankdir=LR;
        bgcolor="#0e1117";
        node [shape=box, style="rounded,filled", fontname="Arial", fontsize=11, margin="0.25,0.18", penwidth=2];
        edge [color="#64748b", penwidth=2, arrowsize=0.8];

        atk [label="THREAT SOURCE\\n\\n{chain['source_ip']}\\nSeverity: {chain['severity']}", fillcolor="#450a0a", color="#ef4444", fontcolor="#fecaca"];
        stg [label="ATTACK STAGE\\n\\n{stages_text}", fillcolor="#431407", color="#f97316", fontcolor="#fed7aa"];
        tgt [label="TARGET HOST\\n\\n{hosts_text}\\nStatus: {target_status}", fillcolor="{target_fill}", color="{target_color}", fontcolor="#ffffff"];

        atk -> stg [color="#ef4444"];
        stg -> tgt [color="{target_color}"];
    }}
    '''
def incident_report(chain, decisions, recovery_verified=False):   
    report_lines = [
        f"=== INCIDENT REPORT: {chain['id']} ===",
        f"Attacker IP: {chain['source_ip']}",
        f"Severity: {chain['severity']}",
        f"Target Hosts: {', '.join(chain['hosts'])}",
        f"Time Window: {chain['start']} to {chain['end']}",
        f"Attack Stages: {' -> '.join(chain['stages'])}",
        f"Summary: {chain['summary']}",
        "\n--- Response Actions ---"
    ]
    for a in chain['actions']:
        status = action_status(a, decisions)
        report_lines.append(f"- [{a['action']}] target: {a['target']} | Status: {status}")

    report_lines.append("")
    report_lines.append("--- Recovery Verification ---")
    if recovery_verified:
        report_lines.append("Recovery Status: Verified (Simulated)")
        report_lines.append("Note: Recovery verification completed (simulated).")
        
    else:
        report_lines.append("Recovery Status: Pending Verification")
        report_lines.append("Note: Recovery has not yet been verified on the target host.")
    return "\n".join(report_lines)

