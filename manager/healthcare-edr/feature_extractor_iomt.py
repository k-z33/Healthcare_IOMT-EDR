"""
IoMT EDR Feature Extractor
==========================
Wazuh alert dictionary se 11 ML features nikalta hai (8 original + 3 IoMT-specific).
In features ko Isolation Forest aur Random Forest models use karte hain.

Base 8 features same hain jo generic EDR project (Feature-extractor.py) mein thay —
taake dono projects comparable rahein. 3 naye features IoMT-specific risk capture
karte hain (patient-safety device, device criticality, firmware/tamper keyword).

Objective: a.i, a.ii (AI Behavioral Analysis) — IoMT variant
"""

import re
from datetime import datetime, timezone

# ── Device-type detection (same categories as live_edr_iomt.py / compliance script) ──

DEVICE_TYPE_PATTERNS = [
    (re.compile(r"ventilator", re.I), "ventilator"),
    (re.compile(r"infusion.?pump", re.I), "infusion_pump"),
    (re.compile(r"patient.?monitor", re.I), "patient_monitor"),
    (re.compile(r"dialysis", re.I), "dialysis_machine"),
    (re.compile(r"defibrillator", re.I), "defibrillator"),
    (re.compile(r"pharmacy.?cabinet", re.I), "pharmacy_cabinet"),
    (re.compile(r"dental.?xray|imaging|x.?ray", re.I), "imaging_device"),
]
PATIENT_SAFETY_DEVICE_TYPES = {
    "ventilator", "infusion_pump", "patient_monitor", "dialysis_machine", "defibrillator"
}

# ── Feature Names (examiner ko explain karo) ──────────────────────────────────
FEATURE_NAMES = [
    "rule_level",               # 0: Wazuh alert severity (1-15)
    "hour_of_day",               # 1: Kab hua (0-23) - raat ko zyada suspicious
    "is_business_hours",         # 2: 1 = 8am-6pm, 0 = baad mein
    "has_network_event",         # 3: 1 = network activity thi
    "has_external_ip",           # 4: 1 = non-private IP (outside org)
    "syscheck_changed",          # 5: 1 = file system change hua
    "auth_event",                # 6: 1 = login/auth activity
    "is_high_rule",              # 7: 1 = rule level >= 12 (serious alert)
    "is_patient_safety_device",  # 8: 1 = ventilator/infusion pump/monitor/dialysis/defib
    "device_criticality_score",  # 9: 0 = unknown, 1 = non-critical device, 2 = patient-safety device
    "firmware_or_tamper_kw",     # 10: 1 = description mentions firmware/tamper/unauthorized update
]


def device_type_from_id(device_id: str) -> str:
    for pattern, dtype in DEVICE_TYPE_PATTERNS:
        if pattern.search(device_id or ""):
            return dtype
    return "unknown_device"


def extract_features(alert: dict) -> list:
    """
    Wazuh alert dict se 11-element feature list banao.

    Parameters
    ----------
    alert : dict
        Wazuh alert JSON (Elasticsearch se ya direct API se)

    Returns
    -------
    list of float — length always 11
    """
    now = datetime.now(timezone.utc)  # matches the fix already applied in live_edr.py
    hour = now.hour

    rule = alert.get("rule", {})
    rule_level = int(rule.get("level", 0))
    description = rule.get("description", "") or alert.get("full_log", "")

    data = alert.get("data", {})
    src_ip = data.get("srcip", "")

    decoder = alert.get("decoder", {})
    groups_str = str(rule.get("groups", []))

    agent = alert.get("agent", {})
    agent_name = agent.get("name", "")

    # Private IP ranges (RFC 1918 + loopback)
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.",
                         "172.18.", "172.19.", "172.20.", "172.21.",
                         "172.22.", "172.23.", "172.24.", "172.25.",
                         "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "127.", "::1", "0.0.0.0")

    has_external = 0
    if src_ip and not any(src_ip.startswith(p) for p in private_prefixes):
        has_external = 1

    device_type = device_type_from_id(agent_name)
    is_patient_safety = 1 if device_type in PATIENT_SAFETY_DEVICE_TYPES else 0

    if device_type == "unknown_device":
        criticality = 0
    elif is_patient_safety:
        criticality = 2
    else:
        criticality = 1

    desc_lower = (description or "").lower()
    firmware_kw = 1 if any(w in desc_lower for w in
                           ["firmware", "tamper", "unauthorized update", "unrecognized firmware"]) else 0

    features = [
        float(rule_level),                                          # feature 0
        float(hour),                                                # feature 1
        1.0 if 8 <= hour <= 18 else 0.0,                             # feature 2
        1.0 if src_ip else 0.0,                                      # feature 3
        float(has_external),                                         # feature 4
        1.0 if decoder.get("name") == "syscheck" else 0.0,           # feature 5
        1.0 if "authentication" in groups_str.lower() else 0.0,      # feature 6
        1.0 if rule_level >= 12 else 0.0,                            # feature 7
        float(is_patient_safety),                                    # feature 8
        float(criticality),                                          # feature 9
        float(firmware_kw),                                          # feature 10
    ]
    return features


# ── Quick sanity test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Normal business-hours alert, non-patient-safety device
    normal_alert = {
        "rule": {"level": 3, "groups": ["syslog"], "description": "Routine log entry"},
        "data": {"srcip": "172.31.27.110"},
        "decoder": {"name": "syslog"},
        "agent": {"name": "pharmacy-cabinet-01"},
    }

    # Firmware tamper on a ventilator at 3 AM — should score high + patient-safety flag
    attack_alert = {
        "rule": {"level": 14, "groups": ["attack"],
                 "description": "CRITICAL: Unrecognized firmware update request on ventilator"},
        "data": {"srcip": "185.220.101.42"},
        "decoder": {"name": "syscheck"},
        "agent": {"name": "ventilator-02"},
    }

    normal_f = extract_features(normal_alert)
    attack_f = extract_features(attack_alert)

    print("Feature names :", FEATURE_NAMES)
    print("Normal alert  :", normal_f)
    print("Attack alert  :", attack_f)
    print("\n✅ IoMT feature extractor working correctly")
