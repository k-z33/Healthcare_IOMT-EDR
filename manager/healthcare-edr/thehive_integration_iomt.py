#!/usr/bin/env python3
import os
import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from device_safety_utils import infer_device_type, PATIENT_SAFETY_DEVICES

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))
from metrics import log_stage

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://32.195.86.7:9000").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
THEHIVE_TLP = int(os.getenv("THEHIVE_TLP", "2"))
THEHIVE_PAP = int(os.getenv("THEHIVE_PAP", "2"))
REQUEST_TIMEOUT = int(os.getenv("THEHIVE_TIMEOUT", "10"))

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

CORTEX_ID = os.getenv("CORTEX_ID", "cortex0")
ANALYZER_MAP = {
    "hash": os.getenv("ANALYZER_HASH_ID", "bfcfa3d11138d1bcae90eb85ef59e5a3"),  # CIRCLHashlookup
    "file": os.getenv("ANALYZER_FILE_ID", "b3e8383ff7be48ed26deefb984267279"),  # FileInfo
    "ip": os.getenv("ANALYZER_IP_ID", "d532088b2a390bee5c68a19eaa12ae17"),     # DShield_lookup
}

SEVERITY_MAP = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}



def safe_get(d: Dict[str, Any], *path, default=None):
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def normalize_severity(ml_result: Dict[str, Any], wazuh_alert: Dict[str, Any]) -> str:
    sev = ml_result.get("severity")
    if isinstance(sev, str) and sev.upper() in SEVERITY_MAP:
        return sev.upper()
    rule_level = int(safe_get(wazuh_alert, "rule", "level", default=0) or 0)
    if rule_level >= 14:
        return "CRITICAL"
    if rule_level >= 10:
        return "HIGH"
    if rule_level >= 6:
        return "MEDIUM"
    return "LOW"


def extract_mitre(wazuh_alert: Dict[str, Any]) -> Dict[str, Any]:
    rule = wazuh_alert.get("rule", {})
    mitre = rule.get("mitre", {}) if isinstance(rule, dict) else {}
    mid = mitre.get("id")
    if isinstance(mid, list) and mid:
        mid = mid[0]
    elif isinstance(mid, str):
        mid = mid
    else:
        mid = "T1059"
    tactic = mitre.get("tactic", "Unknown")
    technique = mitre.get("technique", "Unclassified")
    return {"id": mid, "tactic": tactic, "technique": technique}


def extract_healthcare_context(wazuh_alert: Dict[str, Any], ml_result: Dict[str, Any]) -> Dict[str, Any]:
    rule = wazuh_alert.get("rule", {})
    agent = wazuh_alert.get("agent", {})
    data = wazuh_alert.get("data", {}) if isinstance(wazuh_alert.get("data", {}), dict) else {}

    device_id_temp = data.get("device_id") or ml_result.get("device_id") or ""
    device_type = data.get("device_type") or ml_result.get("device_type") or infer_device_type(device_id_temp, "")
    device_id = data.get("device_id") or ml_result.get("device_id") or agent.get("name", "unknown")
    patient_safety = bool(device_type in PATIENT_SAFETY_DEVICES)

    return {
        "device_id": device_id,
        "device_type": device_type,
        "agent_name": agent.get("name", "Unknown"),
        "agent_ip": agent.get("ip", "Unknown"),
        "rule_id": rule.get("id", "unknown"),
        "rule_level": rule.get("level", 0),
        "rule_description": rule.get("description", "Alert"),
        "patient_safety": patient_safety,
        "containment_status": ml_result.get("containment_status", "unknown"),
        "verdict": ml_result.get("verdict", "AUTOMATED_ANALYSIS"),
    }


def build_description(wazuh_alert: Dict[str, Any], ml_result: Dict[str, Any]) -> str:
    rule = wazuh_alert.get("rule", {})
    agent = wazuh_alert.get("agent", {})
    data = wazuh_alert.get("data", {}) if isinstance(wazuh_alert.get("data", {}), dict) else {}
    mitre = extract_mitre(wazuh_alert)
    severity = normalize_severity(ml_result, wazuh_alert)
    context = extract_healthcare_context(wazuh_alert, ml_result)

    lines = [
        "## Healthcare EDR Automated Alert",
        f"**Timestamp**: {datetime.now(timezone.utc).isoformat()}",
        f"**Severity**: {severity}",
        f"**Verdict**: {context['verdict']}",
        f"**Agent**: {agent.get('name', 'Unknown')} ({agent.get('ip', 'Unknown')})",
        f"**Device ID**: {context['device_id']}",
        f"**Device Type**: {context['device_type']}",
        f"**Rule**: {rule.get('description', 'Alert')}",
        f"**Rule ID**: {context['rule_id']}",
        f"**MITRE**: {mitre['id']} | {mitre['tactic']} | {mitre['technique']}",
        f"**Patient Safety Device**: {str(context['patient_safety'])}",
        f"**Containment Status**: {context['containment_status']}",
    ]

    if data:
        lines.append(f"**Raw Data**: {json.dumps(data, ensure_ascii=False)}")

    return "\n".join(lines)


def build_alert_payload(wazuh_alert: Dict[str, Any], ml_result: Dict[str, Any]) -> Dict[str, Any]:
    rule = wazuh_alert.get("rule", {})
    agent = wazuh_alert.get("agent", {})
    mitre = extract_mitre(wazuh_alert)
    severity_label = normalize_severity(ml_result, wazuh_alert)
    severity = SEVERITY_MAP.get(severity_label, 2)
    context = extract_healthcare_context(wazuh_alert, ml_result)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")

    title = f"[Healthcare EDR] {context['device_type']} | {rule.get('description', 'Unknown Threat')}"
    source_ref = f"wazuh-{context['rule_id']}-{context['device_id']}-{timestamp}"

    tags = [
        "EDR",
        "Healthcare",
        "Wazuh",
        f"device_type:{context['device_type']}",
        f"device_id:{context['device_id']}",
        f"mitre:{mitre['id']}",
        f"severity:{severity_label}",
        f"verdict:{context['verdict']}",
    ]
    if context["patient_safety"]:
        tags.append("patient_safety")
    if context.get("containment_status"):
        tags.append(f"containment:{context['containment_status']}")

    custom_fields = {
        "string": {
            "device_id": {"value": context["device_id"]},
            "device_type": {"value": context["device_type"]},
            "agent_name": {"value": context["agent_name"]},
            "agent_ip": {"value": context["agent_ip"]},
            "rule_id": {"value": str(context["rule_id"])},
            "mitre_id": {"value": mitre["id"]},
            "mitre_tactic": {"value": mitre["tactic"]},
            "mitre_technique": {"value": mitre["technique"]},
            "verdict": {"value": context["verdict"]},
            "containment_status": {"value": context.get("containment_status", "unknown")},
        },
        "boolean": {
            "patient_safety_device": {"value": context["patient_safety"]},
        },
        "number": {
            "wazuh_severity_level": {"value": int(context.get("rule_level", 0) or 0)},
            "thehive_severity": {"value": severity},
        },
    }

    return {
        "title": title,
        "description": build_description(wazuh_alert, ml_result),
        "type": "Healthcare-EDR",
        "source": "Wazuh-AI-Healthcare-EDR-v1",
        "sourceRef": source_ref,
        "severity": severity,
        "tlp": THEHIVE_TLP,
        "pap": THEHIVE_PAP,
        "tags": tags,
        "customFields": custom_fields,
        "observables": [
            {
                "dataType": "ip",
                "data": context["agent_ip"],
                "message": "Observed agent IP",
                "tags": ["agent_ip"],
            }
        ],
    }


def ensure_config() -> None:
    if not THEHIVE_URL:
        raise RuntimeError("THEHIVE_URL is not configured")
    if not THEHIVE_API_KEY:
        raise RuntimeError("THEHIVE_API_KEY is not configured (set the THEHIVE_API_KEY env var)")


def create_alert(wazuh_alert: Dict[str, Any], ml_result: Dict[str, Any]) -> Optional[str]:
    ensure_config()
    payload = build_alert_payload(wazuh_alert, ml_result)
    response = requests.post(
        f"{THEHIVE_URL}/api/v1/alert",
        headers=HEADERS,
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code in (200, 201):
        body = response.json()
        alert_id = body.get("_id") or body.get("id")
        print(f"✅ TheHive alert created: {alert_id}")

        context = extract_healthcare_context(wazuh_alert, ml_result)
        wazuh_id = str(wazuh_alert.get("id", "")) or alert_id
        try:
            log_stage(case_id=wazuh_id, stage="case_created", device_id=context.get("device_id"))
        except Exception as e:
            print(f"⚠️ Metrics logging failed: {e}")

        observables = get_alert_observables(alert_id)
        run_analyzers_on_observables(observables)
        return alert_id

    print(f"❌ TheHive alert creation failed: {response.status_code} {response.text}")
    return None


def load_wazuh_alert_from_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        raise ValueError("Alert file is empty")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        lines = [line for line in raw.splitlines() if line.strip()]
        if not lines:
            raise
        return json.loads(lines[-1])


def default_ml_result(wazuh_alert: Dict[str, Any]) -> Dict[str, Any]:
    rule = wazuh_alert.get("rule", {})
    level = int(rule.get("level", 0) or 0)
    if level >= 14:
        severity = "CRITICAL"
    elif level >= 10:
        severity = "HIGH"
    elif level >= 6:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    return {
        "severity": severity,
        "verdict": "AUTOMATED_ANALYSIS",
        "containment_status": "unknown",
    }


def get_alert_observables(alert_id: str):
    query = {"query": [{"_name": "getAlert", "idOrName": alert_id}, {"_name": "observables"}]}
    try:
        resp = requests.post(f"{THEHIVE_URL}/api/v1/query", headers=HEADERS, json=query, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        print(f"⚠️ Could not fetch observables: {e}")
        return []
    if resp.status_code != 200:
        print(f"⚠️ Could not fetch observables: {resp.status_code} {resp.text}")
        return []
    return resp.json()


def run_analyzers_on_observables(observables):
    for obs in observables:
        data_type = obs.get("dataType")
        obs_id = obs.get("_id") or obs.get("id")
        analyzer_id = ANALYZER_MAP.get(data_type)
        if not analyzer_id or not obs_id:
            print(f"⏭️  Skipping {data_type}:{obs.get('data')} (no matching analyzer enabled)")
            continue
        artifact_id = str(obs_id)
        if not artifact_id.startswith("~"):
            artifact_id = f"~{artifact_id}"
        payload = {"analyzerId": analyzer_id, "cortexId": CORTEX_ID, "artifactId": artifact_id}
        try:
            resp = requests.post(f"{THEHIVE_URL}/api/connector/cortex/job", headers=HEADERS, json=payload, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            print(f"⚠️ Analyzer trigger failed for {data_type}:{obs.get('data')}: {e}")
            continue
        if resp.status_code in (200, 201):
            print(f"🔎 Analyzer triggered for {data_type}:{obs.get('data')} -> job {resp.json().get('id')}")
        else:
            print(f"⚠️ Analyzer trigger failed for {data_type}:{obs.get('data')}: {resp.status_code} {resp.text}")


def main() -> int:
    if len(sys.argv) > 1:
        alert_file_path = sys.argv[1]
        try:
            wazuh_alert = load_wazuh_alert_from_file(alert_file_path)
            ml_result = default_ml_result(wazuh_alert)
            create_alert(wazuh_alert, ml_result)
            return 0
        except Exception as e:
            print(f"❌ Error reading alert file: {e}")
            return 1

    print("Running in test mode...")
    fake_wazuh_alert = {
        "rule": {
            "id": "100216",
            "level": 14,
            "description": "CRITICAL: Ventilator anomalous activity, life-support risk",
            "mitre": {"id": ["T0836"], "tactic": "Impact", "technique": "Device compromise"},
        },
        "agent": {"name": "ventilator-node-01", "ip": "172.31.27.110"},
        "data": {"device_id": "ventilator-02", "device_type": "ventilator"},
    }
    fake_ml = {
        "severity": "CRITICAL",
        "verdict": "AUTOMATED_ANALYSIS",
        "containment_status": "ESCALATE_ONLY",
        "device_type": "ventilator",
        "device_id": "ventilator-02",
    }
    print(json.dumps(build_alert_payload(fake_wazuh_alert, fake_ml), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def create_case(wazuh_alert, ml_result, thehive_alert_id=None):
    """
    Creates a TheHive Case (not just an Alert) for CRITICAL/HIGH severity events.
    Called only when severity warrants a full investigation workflow —
    LOW/MEDIUM stay as Alert-only.
    """
    data = wazuh_alert.get("data", {})
    device_id = data.get("device_id", "")
    device_type = data.get("device_type", "")
    rule_desc = wazuh_alert.get("rule", {}).get("description", "")
    rule_level = wazuh_alert.get("rule", {}).get("level", 0)
    wazuh_id = wazuh_alert.get("id", "")
    mitre = wazuh_alert.get("rule", {}).get("mitre", {})
    mitre_id = ", ".join(mitre.get("id", [])) or "Unclassified"
    mitre_tactic = ", ".join(mitre.get("tactic", [])) or "Unknown"

    severity_num = 4 if rule_level >= 15 else 3  # 4=CRITICAL, 3=HIGH in TheHive scale

    payload = {
        "title": f"[INVESTIGATION] {device_type or 'unknown'} | {rule_desc[:100]}",
        "description": (
            f"## Auto-Generated Investigation Case\n"
            f"**Wazuh Alert ID**: {wazuh_id}\n"
            f"**Device**: {device_id} ({device_type})\n"
            f"**Rule**: {rule_desc}\n"
            f"**Severity Level**: {rule_level}\n"
            f"**MITRE**: {mitre_id} | {mitre_tactic}\n"
            f"**Trigger**: Automated escalation — severity >= HIGH (level {rule_level})\n"
            f"**Linked Alert**: {thehive_alert_id or 'N/A'}\n"
        ),
        "severity": severity_num,
        "tlp": THEHIVE_TLP,
        "pap": THEHIVE_PAP,
        "tags": [
            "auto-case", f"device_id:{device_id}", f"device_type:{device_type}",
            f"mitre:{mitre_id}", "Healthcare", "IoMT-EDR"
        ],
        "status": "InProgress",
    }

    try:
        resp = requests.post(f"{THEHIVE_URL}/api/v1/case", headers=HEADERS, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        case_data = resp.json()
        case_id = case_data.get("_id")
        print(f"[THEHIVE] Case created: {case_id} for device={device_id}")

        # Attach the wazuh alert id as an observable on the case for traceability
        try:
            obs_payload = {
                "dataType": "other",
                "data": wazuh_id,
                "message": "Source Wazuh alert ID",
                "tags": ["wazuh_alert_id"],
            }
            requests.post(f"{THEHIVE_URL}/api/v1/case/{case_id}/observable",
                          headers=HEADERS, json=obs_payload, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            print(f"[THEHIVE] Warning: could not attach observable: {e}")

        return case_id
    except Exception as e:
        print(f"[THEHIVE] ERROR creating case: {e}")
        return None

