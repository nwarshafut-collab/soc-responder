"""
SmartAlert AI - Security Detection Rules
Version: 1.0 (educational prototype)

Purpose:
- Assess possible DDoS indicators in network-flow records.
- Assess possible ransomware indicators in endpoint/file/process logs.
- Return evidence, risk level, and recommended next steps.

IMPORTANT:
These are configurable heuristic rules, not proof of an attack.
Thresholds must be calibrated against the organization's normal traffic.
Ransomware detection requires endpoint/file/process telemetry; a network-flow
CSV alone generally cannot confirm file encryption.
"""

from typing import Any, Dict, List, Optional


def _number(record: Dict[str, Any], *names: str) -> Optional[float]:
    """Return the first usable numeric value from a record, ignoring missing values."""
    for name in names:
        value = record.get(name)
        if value is None or value == "":
            continue
        try:
            number = float(value)
            if number == number:  # exclude NaN
                return number
        except (TypeError, ValueError):
            continue
    return None


def _truthy(record: Dict[str, Any], *names: str) -> bool:
    """Read a boolean-like field from a record."""
    for name in names:
        value = record.get(name)
        if value is None:
            continue
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {
                "1", "true", "yes", "y", "detected", "suspicious"
            }
    return False


def _result(attack_type: str, score: int, evidence: List[str],
            limitations: List[str], recommendations: List[str]) -> Dict[str, Any]:
    score = max(0, min(100, int(score)))
    if score >= 70:
        level = "HIGH"
        status = "POTENTIAL_ATTACK"
    elif score >= 40:
        level = "MEDIUM"
        status = "SUSPICIOUS"
    else:
        level = "LOW"
        status = "NO_STRONG_INDICATORS"
    return {
        "attack_type": attack_type,
        "status": status,
        "risk_level": level,
        "risk_score": score,
        "evidence": evidence,
        "limitations": limitations,
        "recommendations": recommendations,
        "requires_human_review": True,
    }


def assess_ddos(
    record: Dict[str, Any],
    baseline: Optional[Dict[str, float]] = None,
    thresholds: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Assess a single network-flow summary or time-window record.

    Supported common aliases include CICIDS-style fields such as:
    Flow Packets/s, Flow Bytes/s, SYN Flag Count, Flow Duration,
    Total Fwd Packets, Total Backward Packets.

    Recommended input is an aggregate over a defined time window, with baseline
    values calculated from known-normal traffic for the same service/time period.
    """
    baseline = baseline or {}
    thresholds = thresholds or {}

    # Defaults are starting points for a prototype only. Tune to local baseline.
    packets_rate_ratio = thresholds.get("packets_rate_ratio", 3.0)
    bytes_rate_ratio = thresholds.get("bytes_rate_ratio", 3.0)
    syn_count_min = thresholds.get("syn_flag_count_min", 1000.0)
    failed_rate_min = thresholds.get("failed_connection_rate_min", 0.5)
    high_cpu_percent = thresholds.get("high_cpu_percent", 90.0)

    score = 0
    evidence: List[str] = []
    limitations: List[str] = []
    recommendations: List[str] = []

    packets_rate = _number(record, "packets_per_second", "Flow Packets/s", "flow_packets_per_s")
    bytes_rate = _number(record, "bytes_per_second", "Flow Bytes/s", "flow_bytes_per_s")
    syn_count = _number(record, "syn_flag_count", "SYN Flag Count", "syn_count")
    failed_rate = _number(record, "failed_connection_rate", "connection_failure_rate")
    cpu = _number(record, "cpu_percent", "CPU Usage", "cpu_usage_percent")
    service_degraded = _truthy(record, "service_degraded", "service_unavailable", "high_latency")
    provider_alert = _truthy(record, "ddos_provider_alert", "provider_ddos_alert")

    normal_packets = baseline.get("packets_per_second")
    normal_bytes = baseline.get("bytes_per_second")

    if packets_rate is not None and normal_packets and normal_packets > 0:
        ratio = packets_rate / normal_packets
        if ratio >= packets_rate_ratio:
            score += 25
            evidence.append(
                f"Packet rate is {ratio:.1f}x the supplied normal baseline "
                f"(threshold: {packets_rate_ratio:.1f}x)."
            )
    elif packets_rate is not None:
        limitations.append(
            "No valid normal packet-rate baseline supplied; packet volume alone is not conclusive."
        )

    if bytes_rate is not None and normal_bytes and normal_bytes > 0:
        ratio = bytes_rate / normal_bytes
        if ratio >= bytes_rate_ratio:
            score += 20
            evidence.append(
                f"Byte rate is {ratio:.1f}x the supplied normal baseline "
                f"(threshold: {bytes_rate_ratio:.1f}x)."
            )
    elif bytes_rate is not None:
        limitations.append(
            "No valid normal bandwidth baseline supplied; byte rate alone is not conclusive."
        )

    if syn_count is not None and syn_count >= syn_count_min:
        score += 20
        evidence.append(
            f"SYN flag count ({syn_count:g}) meets/exceeds the configured review threshold "
            f"({syn_count_min:g}). This is an indicator, not proof of SYN flooding."
        )

    if failed_rate is not None and failed_rate >= failed_rate_min:
        score += 15
        evidence.append(
            f"Connection failure rate ({failed_rate:.2f}) is at/above the configured threshold "
            f"({failed_rate_min:.2f})."
        )

    if cpu is not None and cpu >= high_cpu_percent:
        score += 10
        evidence.append(
            f"CPU utilization is high ({cpu:.1f}%, threshold {high_cpu_percent:.1f}%)."
        )

    if service_degraded:
        score += 20
        evidence.append("Service degradation, high latency, or unavailability was reported.")

    if provider_alert:
        score += 25
        evidence.append("A DDoS alert from a protection/provider service was supplied.")

    if not evidence:
        evidence.append("No configured DDoS indicator crossed its threshold in the supplied record.")

    limitations.append(
        "Confirm whether a release, marketing event, load test, service fault, or provider outage "
        "explains the traffic spike before classifying it as an attack."
    )
    recommendations.extend([
        "Correlate network-flow data with firewall, load balancer, application, and server logs.",
        "Compare against a baseline for the same service and time period.",
        "If service availability is affected, alert the security/network team and follow the incident plan.",
    ])

    return _result("DDoS", score, evidence, limitations, recommendations)


def assess_ransomware(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Assess one endpoint/security event or an aggregated event summary.

    Suggested input fields:
      mass_file_modifications, suspicious_process, ransom_note_detected,
      backup_tampering, security_tool_alert, unusual_extension_changes,
      file_modification_count, file_modifications_per_minute, known_malicious_hash

    These fields must come from trusted endpoint/file/process monitoring.
    """
    score = 0
    evidence: List[str] = []
    limitations: List[str] = []
    recommendations: List[str] = []

    mass_modifications = _truthy(event, "mass_file_modifications")
    suspicious_process = _truthy(event, "suspicious_process")
    ransom_note = _truthy(event, "ransom_note_detected")
    backup_tampering = _truthy(event, "backup_tampering")
    security_alert = _truthy(event, "security_tool_alert")
    extension_changes = _truthy(event, "unusual_extension_changes")
    malicious_hash = _truthy(event, "known_malicious_hash")
    file_count = _number(event, "file_modification_count")
    mods_per_min = _number(event, "file_modifications_per_minute")

    if mass_modifications:
        score += 25
        evidence.append("Endpoint telemetry reports mass file modifications.")
    if file_count is not None and file_count >= 100:
        score += 15
        evidence.append(f"{file_count:g} file modifications were reported; verify the normal workload.")
    if mods_per_min is not None and mods_per_min >= 30:
        score += 15
        evidence.append(
            f"File modification rate is {mods_per_min:g} per minute; the threshold is a configurable heuristic."
        )
    if suspicious_process:
        score += 20
        evidence.append("A process was flagged as suspicious by the supplied telemetry.")
    if extension_changes:
        score += 15
        evidence.append("Unusual file-extension changes were observed.")
    if ransom_note:
        score += 30
        evidence.append("A ransom note or ransom instruction was detected.")
    if backup_tampering:
        score += 20
        evidence.append("Possible backup deletion or tampering was reported.")
    if security_alert:
        score += 25
        evidence.append("An endpoint security tool reported a malware-related alert.")
    if malicious_hash:
        score += 30
        evidence.append("A file hash matched a known-malicious indicator in the supplied threat intelligence.")

    if not evidence:
        evidence.append("No configured ransomware indicator was present in the supplied event.")

    limitations.append(
        "A high file-change rate can be caused by backups, software updates, synchronization, or bulk editing. "
        "Correlate multiple independent indicators and verify the process/user context."
    )
    limitations.append(
        "A network-flow CSV alone cannot establish that files were encrypted; endpoint, file, and process logs are needed."
    )
    recommendations.extend([
        "Preserve relevant logs and file/process metadata for investigation.",
        "Escalate high-risk cases to the security analyst immediately.",
        "Use the organization's approved incident-response plan; do not automatically delete files or isolate systems "
        "unless an authorized response workflow explicitly permits it.",
    ])

    return _result("Ransomware", score, evidence, limitations, recommendations)


def assess_security_event(event: Dict[str, Any],
                          baseline: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """
    Entry point for the application.
    Supply event['event_type'] as 'ddos' or 'ransomware'.
    """
    event_type = str(event.get("event_type", "")).strip().lower()

    if event_type in {"ddos", "dos", "network_flood"}:
        return assess_ddos(event, baseline=baseline)

    if event_type in {"ransomware", "file_encryption", "endpoint_malware"}:
        return assess_ransomware(event)

    return {
        "attack_type": "UNKNOWN",
        "status": "NEEDS_TRIAGE",
        "risk_level": "UNDETERMINED",
        "risk_score": 0,
        "evidence": [],
        "limitations": [
            "The event_type is not recognized. Choose ddos or ransomware, or add a reviewed rule set."
        ],
        "recommendations": [
            "Have Gemini select an approved analysis path, then call the corresponding assessment function."
        ],
        "requires_human_review": True,
    }


if __name__ == "__main__":
    # Example 1: DDoS assessment using sample values only.
    sample_ddos = {
        "event_type": "ddos",
        "packets_per_second": 9000,
        "bytes_per_second": 8000000,
        "syn_flag_count": 1500,
        "failed_connection_rate": 0.7,
        "cpu_percent": 94,
        "service_degraded": True,
    }
    sample_baseline = {
        "packets_per_second": 1000,
        "bytes_per_second": 1000000,
    }
    print("DDoS example:")
    print(assess_security_event(sample_ddos, baseline=sample_baseline))

    # Example 2: Ransomware assessment using sample endpoint telemetry.
    sample_ransomware = {
        "event_type": "ransomware",
        "mass_file_modifications": True,
        "file_modification_count": 350,
        "file_modifications_per_minute": 120,
        "suspicious_process": True,
        "unusual_extension_changes": True,
        "ransom_note_detected": False,
        "backup_tampering": True,
    }
    print("\\nRansomware example:")
    print(assess_security_event(sample_ransomware))
