"""
Automated Threat Containment
Objective: c.ii — Automated threat containment and quarantine
Extended: patient-safety-aware branch for IoMT/medical devices
"""

import json
import datetime
import subprocess
import os
import sys
from device_safety_utils import infer_device_type, PATIENT_SAFETY_DEVICES

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))
from metrics import log_stage

LOG_FILE = "/tmp/containment_log.json"

# Devices jahan blind network isolation khud ek patient-safety risk hai —
# in devices ke liye kabhi bhi auto-isolate nahi karna, sirf escalate karna hai.


def contain_threat(alert):
    severity   = alert.get("rule", {}).get("level", 0)
    agent_ip   = alert.get("agent", {}).get("ip", "unknown")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    rule_desc  = alert.get("rule", {}).get("description", "")

    data        = alert.get("data", {})
    device_id   = data.get("device_id", "")
    device_type = infer_device_type(data.get("device_id", ""), data.get("device_type", ""))

    log = {
        "timestamp": datetime.datetime.now().isoformat(),
        "agent": agent_name,
        "agent_ip": agent_ip,
        "alert": rule_desc,
        "severity": severity,
        "device_id": device_id or None,
        "device_type": device_type or None,
        "actions_taken": []
    }

    wazuh_id = str(alert.get("id", "")) or f"{device_id or agent_name}-{log['timestamp']}"

    # ── IoMT branch — patient-safety devices NEVER auto-isolated ───────────
    if device_type and device_type in PATIENT_SAFETY_DEVICES:
        log["actions_taken"].append("ESCALATE: clinical/biomedical engineering notified")
        log["actions_taken"].append("MONITOR: read-only monitoring continues (NOT isolated)")
        log["actions_taken"].append("HOLD: human sign-off required before any network action")
        log["threat_level"] = "PATIENT_SAFETY_ESCALATION"
        log["auto_isolated"] = False

        print(f"[PATIENT-SAFETY] {device_id} ({device_type}) — ESCALATION ONLY, no isolation")
        print(f"  Reason: auto-isolating this device type risks disrupting patient care")
        print(f"  Action: on-call biomedical engineer + SOC notified")
        print(f"  Action: monitoring continues, device stays on network")

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log) + "\n")
        try:
            log_stage(case_id=wazuh_id, stage="containment_action", device_id=device_id or None)
        except Exception as e:
            print(f"[Metrics] {e}")
        return log

    # ── IoMT branch — non-critical device, full isolation allowed ──────────
    if device_type:
        log["actions_taken"].append(f"ISOLATE: network block for device {device_id} ({device_type})")
        log["actions_taken"].append("EVIDENCE: connection log snapshot requested")
        log["threat_level"] = "IOMT_DEVICE_CONTAINED"
        log["auto_isolated"] = True

        print(f"[IoMT] Containing {device_id} ({device_type})")
        print(f"  Action: Network isolation triggered (non-critical device)")

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log) + "\n")
        try:
            log_stage(case_id=wazuh_id, stage="containment_action", device_id=device_id or None)
        except Exception as e:
            print(f"[Metrics] {e}")
        return log

    # ── Original endpoint (Windows/Linux) severity-based logic ─────────────
    if severity >= 12:  # CRITICAL
        log["actions_taken"].append("ISOLATE: network block triggered")
        log["actions_taken"].append("ALERT: SOC notified")
        log["actions_taken"].append("EVIDENCE: memory snapshot requested")
        log["threat_level"] = "CRITICAL"
        print(f"[CRITICAL] Containing {agent_name} ({agent_ip})")
        print(f"  Action: Network isolation triggered")
        print(f"  Action: SOC alert sent")

    elif severity >= 8:  # HIGH
        log["actions_taken"].append("MONITOR: enhanced logging enabled")
        log["actions_taken"].append("TICKET: TheHive case created")
        log["threat_level"] = "HIGH"
        print(f"[HIGH] Alert from {agent_name} ({agent_ip})")
        print(f"  Action: Enhanced monitoring enabled")
        print(f"  Action: TheHive case created")

    elif severity >= 5:  # MEDIUM
        log["actions_taken"].append("LOG: alert recorded")
        log["threat_level"] = "MEDIUM"
        print(f"[MEDIUM] Alert from {agent_name} — logged")

    else:
        log["actions_taken"].append("LOG: low severity recorded")
        log["threat_level"] = "LOW"

    # Save to log
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log) + "\n")

    try:
        log_stage(case_id=wazuh_id, stage="containment_action", device_id=device_id or None)
    except Exception as e:
        print(f"[Metrics] {e}")

    return log


def demo_containment():
    """Demo — different severity alerts test karo, endpoint aur IoMT dono"""
    print("=" * 55)
    print("AUTO CONTAINMENT DEMO (Endpoint + IoMT)")
    print("=" * 55)

    test_alerts = [
        {
            "rule": {"level": 12, "description": "Ransomware behavior detected"},
            "agent": {"ip": "192.168.1.22", "name": "ubuntu-endpoint"}
        },
        {
            "rule": {"level": 10, "description": "Privilege escalation attempt"},
            "agent": {"ip": "192.168.1.22", "name": "ubuntu-endpoint"}
        },
        {
            "rule": {"level": 6, "description": "Suspicious file created"},
            "agent": {"ip": "192.168.1.22", "name": "ubuntu-endpoint"}
        },
        {
            "rule": {"level": 14, "description": "Ventilator anomalous activity, life-support risk"},
            "agent": {"ip": "172.31.27.110", "name": "ip-172-31-27-110"},
            "data": {"device_id": "ventilator-02", "device_type": "ventilator"}
        },
        {
            "rule": {"level": 10, "description": "Device connected to unknown destination IP"},
            "agent": {"ip": "172.31.27.110", "name": "ip-172-31-27-110"},
            "data": {"device_id": "dental-xray-01", "device_type": "imaging"}
        },
    ]

    results = []
    for alert in test_alerts:
        result = contain_threat(alert)
        results.append(result)
        print()

    print("=" * 55)
    print(f"Processed {len(results)} alerts")
    print(f"Log saved: {LOG_FILE}")
    print("=" * 55)

    return results


if __name__ == "__main__":
    demo_containment()
