"""
Core logic of the SOC Triage & Response system (v3: Gemini AI Integrated).
Pipeline: parse logs -> detect alerts -> enrich (threat intel) -> build attack chains
          -> AI reasoning & severity -> recommend response actions
"""
import csv
import io
import os
import json
import urllib.request
from collections import defaultdict

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY_HERE")

TRUSTED_IPS = {"10.0.0.5": "Internal vulnerability scanner"}
KNOWN_BAD_IPS = {
    "203.0.113.45": "Reported for SSH brute force and data theft (demo feed)",
}
PORT_SCAN_THRESHOLD = 10
BRUTE_FORCE_THRESHOLD = 5

MITRE = {
    "PORT_SCAN":        ("Discovery",            "T1046", "Network Service Discovery"),
    "BRUTE_FORCE":      ("Credential Access",    "T1110", "Brute Force"),
    "LOGIN_AFTER_FAIL": ("Initial Access",       "T1078", "Valid Accounts"),
    "PRIV_ESC":         ("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism"),
    "EXFILTRATION":     ("Exfiltration",         "T1041", "Exfiltration Over C2 Channel"),
}


def ask_gemini_ai(prompt_text):
    """Connects directly to Google Gemini API."""
    if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
        return None
    url = "https://googleapis.com"
    payload = {"contents": [{"parts": [{"text": prompt_text}]}]}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": GEMINI_API_KEY.strip()
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as e:
        return f"(AI API Status: {str(e)})"


def load_logs(file_or_path):
    """Read a CSV (path or uploaded file) -> list of dict events."""
    if isinstance(file_or_path, str):
        with open(file_or_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    else:
        text = file_or_path.getvalue().decode("utf-8") if hasattr(file_or_path, "getvalue") else file_or_path.read().decode("utf-8")
        rows = list(csv.DictReader(io.StringIO(text)))
    required = {"timestamp", "source_ip", "dest_host", "event_type", "details"}
    first_row = next(iter(rows), {})
    if not rows or not required.issubset(first_row.keys()):
        raise ValueError("CSV must have columns: " + ", ".join(sorted(required)))
    return sorted(rows, key=lambda r: r["timestamp"])


def _alert(kind, ip, host, ts, description, evidence_count):
    tactic, tid, tname = MITRE[kind]
    return {"kind": kind, "source_ip": ip, "host": host, "timestamp": ts,
            "description": description, "evidence_count": evidence_count,
            "tactic": tactic, "technique_id": tid, "technique": tname}


def detect(events):
    """Apply detection rules. Returns (alerts, filtered_false_positives)."""
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

    for (ip, host), ev in probes.items():
        if len(ev) >= PORT_SCAN_THRESHOLD:
            first_ev = next(iter(ev))
            a = _alert("PORT_SCAN", ip, host, first_ev["timestamp"], f"{len(ev)} ports probed", len(ev))
            (false_positives if ip in TRUSTED_IPS else alerts).append(a)
    for (ip, host), ev in fails.items():
        if len(ev) >= BRUTE_FORCE_THRESHOLD:
            first_ev = next(iter(ev))
            alerts.append(_alert("BRUTE_FORCE", ip, host, first_ev["timestamp"], f"{len(ev)} failed logins", len(ev)))
            for s in successes.get((ip, host), []):
                if s["timestamp"] > ev[-1]["timestamp"]:
                    alerts.append(_alert("LOGIN_AFTER_FAIL", ip, host, s["timestamp"],
                                         f"Successful login after {len(ev)} failures ({s['details']})", 1))
    for a in false_positives:
        a["reason"] = TRUSTED_IPS.get(a["source_ip"], "Trusted source")
    return sorted(alerts, key=lambda a: a["timestamp"]), false_positives


def enrich(alerts):
    """Threat-intelligence enrichment."""
    for a in alerts:
        a["threat_intel"] = KNOWN_BAD_IPS.get(a["source_ip"])
    return alerts


def build_chains(alerts):
    """Group alerts by attacker IP into one incident = one attack story."""
    groups = defaultdict(list)
    for a in alerts:
        groups[a["source_ip"]].append(a)
    chains = []
    for ip, items in groups.items():
        items.sort(key=lambda a: a["timestamp"])
        stages = list(dict.fromkeys(a["tactic"] for a in items))
        intel = next((a["threat_intel"] for a in items if a["threat_intel"]), None)
        score = len(stages) + (1 if intel else 0)
        severity = "Critical" if score >= 5 else "High" if score >= 3 else "Medium" if score >= 2 else "Low"
        first_item = next(iter(items))
        chains.append({"id": f"INC-{len(chains)+1:03d}", "source_ip": ip, "alerts": items,
                       "stages": stages, "severity": severity, "threat_intel": intel,
                       "hosts": sorted({a["host"] for a in items}),
                       "start": first_item["timestamp"], "end": items[-1]["timestamp"]})
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    chains.sort(key=lambda c: order[c["severity"]])
    for i, c in enumerate(chains, 1):
        c["id"] = f"INC-{i:03d}"
        c["summary"] = summarize(c)
        c["actions"] = recommend(c)
    return chains


def summarize(c):
    """Uses Gemini AI to generate an intelligent SOC incident analysis, with rule-based fallback."""
    steps = " -> ".join(c["stages"])
    prompt = (
        f"You are an expert SOC AI Analyst. Write a concise 2-sentence security investigation summary "
        f"for an incident from attacker IP {c['source_ip']} targeting {', '.join(c['hosts'])}. "
        f"Observed MITRE attack stages: {steps}. Severity level: {c['severity']}. "
        f"Threat intelligence context: {c['threat_intel'] or 'None'}. Explain the risk clearly."
    )
    ai_response = ask_gemini_ai(prompt)
    if ai_response:
        return f"🤖 [AI Analysis]: {ai_response}"
    return (f"Source {c['source_ip']} targeted {', '.join(c['hosts'])} between {c['start']} and {c['end']}. "
            f"Attack stages observed: {steps}. Severity: {c['severity']}.")


def recommend(c):
    """Recommended response actions, each with a reason. Executed only after analyst approval."""
    kinds = {a["kind"] for a in c["alerts"]}
    acts = [{"id": f"{c['id']}-A1", "action": "Block IP", "target": c["source_ip"],
             "reason": f"Source performed {len(c['alerts'])} malicious actions across {len(c['stages'])} attack stage(s)."}]
    if "LOGIN_AFTER_FAIL" in kinds:
        acts.append({"id": f"{c['id']}-A2", "action": "Disable account", "target": "admin",
                     "reason": "Account was accessed after a brute-force attack and is likely compromised."})
    if kinds & {"PRIV_ESC", "EXFILTRATION"}:
        host = next(iter(c["hosts"]))
        acts.append({"id": f"{c['id']}-A3", "action": "Isolate host", "target": host,
                     "reason": "Privilege escalation and/or data exfiltration detected on this host."})
    return acts


def run_pipeline(events):
    alerts, fps = detect(events)
    alerts = enrich(alerts)
    chains = build_chains(alerts)
    return {"events": events, "alerts": alerts, "false_positives": fps, "chains": chains}


def simulate_action(action):
    """SIMULATED execution (nothing real is touched)."""
    return f"[SIMULATED] {action['action']} executed on {action['target']}"


# ---------------- After-Detection helpers ----------------
def action_status(action, decisions):
    d = decisions.get(action["id"])
    return {"approved": "Mitigated", "rejected": "Left as-is (rejected)"}.get(d, "Pending analyst decision")


def response_summary(chains, decisions):
    acts = [a for c in chains for a in c["actions"]]
    total = len(acts)
    approved = sum(1 for a in acts if decisions.get(a["id"]) == "approved")
    rejected = sum(1 for a in acts if decisions.get(a["id"]) == "rejected")
    return {"total": total, "approved": approved, "rejected": rejected,
            "pending": total - approved - rejected,
            "contained_pct": int(round(100 * approved / total)) if total else 0}


def asset_table(chains, decisions):
    """What the response does to each asset (IP / account / host)."""
    kind = {"Block IP": "Attacker IP", "Disable account": "User account", "Isolate host": "Server"}
    rows = []
    for c in chains:
        for a in c["actions"]:
            rows.append({"Incident": c["id"], "Asset": a["target"], "Type": kind.get(a["action"], "Asset"),
                         "Action": a["action"], "Status": action_status(a, decisions)})
    return rows


def build_dot(chain, decisions):
    """Graphviz DOT text of the attack path + the recommended responses."""
    L = ["digraph G {", "rankdir=LR;", 'bgcolor="transparent";',
         'node [shape=box, style="rounded,filled", fontname="Arial", fontcolor="white"];',
