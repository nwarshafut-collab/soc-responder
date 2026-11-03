from engine import load_logs, run_pipeline
r = run_pipeline(load_logs("sample_logs/attack_scenario.csv"))
print("events", len(r["events"]), "| alerts", len(r["alerts"]), "| false positives", len(r["false_positives"]), "| incidents", len(r["chains"]))
for c in r["chains"]:
    print(c["id"], c["source_ip"], c["severity"], c["stages"])
    print("  ", c["summary"])
    for a in c["actions"]: print("   ->", a["action"], a["target"])
assert len(r["false_positives"]) == 1 and r["chains"][0]["severity"] == "Critical"
print("OK")
