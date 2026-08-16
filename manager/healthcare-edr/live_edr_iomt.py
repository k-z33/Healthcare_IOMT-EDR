#!/usr/bin/env python3
"""
EDR Live Monitor  (Extended — Endpoint ML + IoMT Healthcare Layer + Suricata)
====================================================================
Wazuh se live alerts uthata hai. Teen parallel paths hain:
  1. Endpoint alerts (Windows/Linux LoTL)     -> Isolation Forest + Random Forest ML
  2. IoMT/medical-device alerts (device_id)   -> rule-level severity + MITRE + HIPAA
                                                   + patient-safety-aware containment
  3. Suricata/network-IDS alerts (groups has 'suricata') -> dedicated clean display,
                                                   NOT pushed through endpoint ML
                                                   (ML features are Windows-endpoint
                                                   specific, semantically wrong for
                                                   network-layer IDS signatures)

Koi Wazuh config change nahi — sirf Docker alerts.json read karta hai.

Chalao:  python3 live_edr_iomt.py
Container: healthcare-edr-wazuh.manager-1  (AWS setup)
"""
from auto_contain import contain_threat
from device_safety_utils import infer_device_type, PATIENT_SAFETY_DEVICES
import json
import time
import subprocess
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))
from metrics import log_stage

try:
    from thehive_integration_iomt import create_alert as thehive_create
    THEHIVE_AVAILABLE = True
except ImportError:
    THEHIVE_AVAILABLE = False

try:
    from file_reputation import check_file_reputation
    FILE_REP_AVAILABLE = True
except ImportError:
    FILE_REP_AVAILABLE = False

# ── FIX: correct module name, no space (was: "hippa_ mitre_map" — SyntaxError) ─
try:
    from mitre_mapper import map_mitre as mitre_lookup
    MITRE_MAPPER_AVAILABLE = True
except ImportError:
    MITRE_MAPPER_AVAILABLE = False

try:
    from ml_enrichment_iomt import enrich_with_ml
    ML_ENRICHMENT_AVAILABLE = True
except ImportError:
    ML_ENRICHMENT_AVAILABLE = False

try:
    import numpy as np
    import joblib
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False

CONTAINER = "healthcare-edr-wazuh.manager-1"


# ── Terminal Colors ─────────────────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    ORANGE = '\033[93m'
    YELLOW = '\033[33m'
    GREEN  = '\033[92m'
    CYAN   = '\033[96m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    WHITE  = '\033[97m'
    GREY   = '\033[90m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'


# ── Load ML Models (endpoint alerts only — NOT trained on IoMT data) ───────
iso_model = None
rf_model = None
if MODELS_AVAILABLE:
    for model_dir in ['models', './models', os.path.dirname(__file__) + '/models']:
        iso_path = os.path.join(model_dir, 'isolation_forest.pkl')
        rf_path = os.path.join(model_dir, 'random_forest.pkl')
        if os.path.exists(iso_path) and os.path.exists(rf_path):
            try:
                iso_model = joblib.load(iso_path)
                rf_model = joblib.load(rf_path)
                print(f"{C.GREEN}✅ ML models loaded from: {model_dir}{C.RESET}")
                break
            except Exception as e:
                print(f"{C.YELLOW}⚠ Model load error: {e}{C.RESET}")

if iso_model is None:
    print(f"{C.YELLOW}⚠ ML models not found — running in RULE-BASED mode{C.RESET}\n")

mitre_status = f"{C.GREEN}LOADED{C.RESET}" if MITRE_MAPPER_AVAILABLE else f"{C.RED}FAILED TO LOAD (check mitre_mapper.py exists){C.RESET}"
print(f"{C.CYAN}ℹ MITRE mapper: {mitre_status}{C.RESET}")
print(f"{C.CYAN}ℹ IoMT alerts use rule-level severity + MITRE + HIPAA{C.RESET}\n")

THREAT_LABELS = {
    0: 'BENIGN', 1: 'RANSOMWARE', 2: 'TROJAN',
    3: 'SPYWARE', 4: 'ROOTKIT', 5: 'APT', 6: 'CRYPTOMINER',
}

MITRE_MAP = {
    'RANSOMWARE': 'T1486', 'APT': 'T1071',
    'ROOTKIT': 'T1055', 'TROJAN': 'T1204',
    'SPYWARE': 'T1056', 'CRYPTOMINER': 'T1496',
}

SEVERITY_COLOR = {
    'CRITICAL': C.RED, 'HIGH': C.ORANGE, 'MEDIUM': C.YELLOW,
    'LOW': C.GREEN, 'INFO': C.GREY,
}


# ── HIPAA Security Rule map — same keyword pattern as live_compliance.py ────
HIPAA_MAP = {
    "unknown destination ip":  ("§164.312(e)(1)", "Transmission Security"),
    "unexpected port":         ("§164.312(e)(1)", "Transmission Security"),
    "data volume spike":       ("§164.308(a)(6)", "Security Incident Procedures"),
    "outside normal operating hours": ("§164.312(b)", "Audit Controls"),
    "flooding":                ("§164.308(a)(7)", "Contingency Plan"),
    "firmware":                ("§164.312(c)(1)", "Integrity"),
    "legacy protocol":         ("§164.312(e)(1)", "Transmission Security"),
    "default or weak credentials": ("§164.308(a)(5)(ii)(D)", "Password Management"),
    "authentication failed":   ("§164.312(d)", "Person/Entity Authentication"),
    "brute force":             ("§164.312(d)", "Person/Entity Authentication"),
    "impersonation":           ("§164.312(e)(1)", "Transmission Security"),
    "replay attack":           ("§164.312(e)(2)(i)", "Integrity Controls"),
    "unencrypted":             ("§164.312(e)(1)", "Transmission Security"),
    "clock or time-sync":      ("§164.312(b)", "Audit Controls"),
    "admin or billing network": ("§164.312(a)(1)", "Access Control"),
    "patient dosing risk":     ("§164.308(a)(6)", "Security Incident Procedures — Patient Safety"),
    "life-support risk":       ("§164.308(a)(6)", "Security Incident Procedures — Patient Safety"),
    "vitals data integrity":   ("§164.308(a)(6)", "Security Incident Procedures — Patient Safety"),
    "dicom":                   ("§164.404", "Breach Notification Rule"),
    "hl7 message tampering":   ("§164.312(c)(1)", "Integrity"),
    "rebooted without authorization": ("§164.308(a)(6)", "Security Incident Procedures"),
    "configuration change":    ("§164.312(a)(1)", "Access Control"),
    "reconnaissance":          ("§164.312(b)", "Audit Controls"),
    "diversion":               ("§164.308(a)(3)", "Workforce Security"),
    "arp spoofing":            ("§164.312(e)(1)", "Transmission Security"),
    "port scan":               ("§164.312(b)", "Audit Controls"),
    "rogue":                   ("§164.312(d)", "Person/Entity Authentication"),
    "segmentation violation":  ("§164.312(a)(1)", "Access Control"),
    "tls":                     ("§164.312(e)(1)", "Transmission Security"),
    "firewall":                ("§164.312(b)", "Audit Controls"),
}


def map_hipaa(description: str):
    d = description.lower()
    for kw, (cite, safeguard) in HIPAA_MAP.items():
        if kw in d:
            return cite, safeguard
    return None, None


def titlecase_event(raw: str) -> str:
    """snake_case ya raw event string ko Title Case mein badlo, display ke liye"""
    if not raw:
        return "Unknown Event"
    return raw.replace('_', ' ').replace('-', ' ').strip().title()


# ── Feature Extractor (endpoint ML) ────────────────────────────────────────
def extract_features(alert: dict) -> list:
    hour = datetime.now(timezone.utc).hour
    rule = alert.get('rule', {})
    rule_level = int(rule.get('level', 0))
    data = alert.get('data', {})
    src_ip = data.get('srcip', '')
    decoder = alert.get('decoder', {})
    groups_str = str(rule.get('groups', []))

    private = ('10.', '192.168.', '172.', '127.', '::1', '0.0.0.0')
    has_ext = 0 if (not src_ip or any(src_ip.startswith(p) for p in private)) else 1

    return [
        float(rule_level), float(hour),
        1.0 if 8 <= hour <= 18 else 0.0,
        1.0 if src_ip else 0.0,
        float(has_ext),
        1.0 if decoder.get('name') == 'syscheck' else 0.0,
        1.0 if 'authentication' in groups_str.lower() else 0.0,
        1.0 if rule_level >= 12 else 0.0,
    ]


# ── Alert Category Helpers ──────────────────────────────────────────────────
def is_iomt_alert(alert: dict) -> bool:
    return bool(alert.get('data', {}).get('device_id'))


def is_suricata_alert(alert: dict) -> bool:
    groups = alert.get('rule', {}).get('groups', [])
    return 'suricata' in groups or 'ids' in groups


def analyze_iomt(alert: dict) -> dict:
    rule = alert.get('rule', {})
    rule_level = int(rule.get('level', 0))
    desc = rule.get('description', '')
    data = alert.get('data', {})
    device_type = infer_device_type(data.get('device_id', ''), data.get('device_type', ''))
    event_raw = data.get('event', '')

    if rule_level >= 14:
        severity, action = 'CRITICAL', 'AUTO_CONTAIN'
    elif rule_level >= 11:
        severity, action = 'HIGH', 'ALERT_ANALYST'
    elif rule_level >= 7:
        severity, action = 'MEDIUM', 'LOG_REVIEW'
    else:
        severity, action = 'LOW', 'LOG_ONLY'

    # Numeric severity score — normalized rule_level out of max level (15)
    score = round(min(rule_level / 15.0, 1.0), 3)

    if MITRE_MAPPER_AVAILABLE:
        mitre_id, tactic, technique = mitre_lookup(desc)
    else:
        mitre_id, tactic, technique = 'T0000', 'Unknown', 'Unclassified'

    hipaa_cite, hipaa_safeguard = map_hipaa(desc)

    is_patient_safety = device_type in PATIENT_SAFETY_DEVICES
    if is_patient_safety and action == 'AUTO_CONTAIN':
        action = 'ESCALATE_CLINICAL_ENGINEERING'

    result = {
        'mode': 'IOMT_RULE',
        'severity': severity,
        'action': action,
        'score': score,
        'threat_type': device_type.upper() if device_type else 'UNKNOWN_DEVICE',
        'event_display': titlecase_event(event_raw),
        'confidence': 1.0,
        'mitre': mitre_id,
        'mitre_tactic': tactic,
        'hipaa_citation': hipaa_cite,
        'hipaa_safeguard': hipaa_safeguard,
        'is_anomaly': rule_level >= 10,
        'is_patient_safety': is_patient_safety,
        'device_id': data.get('device_id', ''),
        'device_type': device_type,
    }

    if ML_ENRICHMENT_AVAILABLE:
        result = enrich_with_ml(alert, result)

    return result


def analyze_suricata(alert: dict) -> dict:
    """Suricata/network-IDS alert — clean dedicated path, endpoint ML se bypass"""
    rule = alert.get('rule', {})
    rule_level = int(rule.get('level', 0))
    data = alert.get('data', {})
    sig_alert = data.get('alert', {})
    signature = sig_alert.get('signature', 'Unknown Signature')
    category = sig_alert.get('category', 'Uncategorized')
    src_ip = data.get('src_ip', '')
    src_port = data.get('src_port', '')
    dest_ip = data.get('dest_ip', '')
    dest_port = data.get('dest_port', '')

    if rule_level >= 12:
        severity, action = 'HIGH', 'ALERT_ANALYST'
    elif rule_level >= 7:
        severity, action = 'MEDIUM', 'LOG_REVIEW'
    else:
        severity, action = 'LOW', 'LOG_ONLY'

    return {
        'mode': 'SURICATA',
        'severity': severity,
        'action': action,
        'score': round(min(rule_level / 15.0, 1.0), 3),
        'signature': signature,
        'category': titlecase_event(category.replace(' ', '_')),
        'src': f"{src_ip}:{src_port}" if src_ip else 'N/A',
        'dest': f"{dest_ip}:{dest_port}" if dest_ip else 'N/A',
    }


def analyze(alert: dict) -> dict:
    """Endpoint ML analysis — sirf non-IoMT, non-Suricata alerts ke liye"""
    rule_level = int(alert.get('rule', {}).get('level', 0))
    features = extract_features(alert)

    if iso_model is not None and rf_model is not None:
        try:
            f = np.array(features, dtype=float).reshape(1, -1)
            f_scaled = iso_model.named_steps['scaler'].transform(f)
            score = float(iso_model.named_steps['model'].decision_function(f_scaled)[0])
            is_anom = iso_model.predict(f_scaled)[0] == -1

            rf_class = int(rf_model.predict(f)[0])
            rf_proba = rf_model.predict_proba(f)[0]
            threat_type = THREAT_LABELS.get(rf_class, 'UNKNOWN')
            confidence = float(max(rf_proba))

            if score < -0.30 or rule_level >= 15:
                severity, action = 'CRITICAL', 'AUTO_CONTAIN'
            elif score < -0.10 or rule_level >= 12:
                severity, action = 'HIGH', 'ALERT_ANALYST'
            elif score < 0.0 or rule_level >= 7:
                severity, action = 'MEDIUM', 'LOG_REVIEW'
            else:
                severity, action = 'LOW', 'LOG_ONLY'

            return {
                'mode': 'ML', 'severity': severity, 'action': action,
                'score': round(score, 4), 'threat_type': threat_type,
                'confidence': round(confidence, 3),
                'mitre': MITRE_MAP.get(threat_type, 'T1059'), 'is_anomaly': is_anom,
            }
        except Exception:
            pass

    if rule_level >= 15:
        severity, action = 'CRITICAL', 'AUTO_CONTAIN'
    elif rule_level >= 12:
        severity, action = 'HIGH', 'ALERT_ANALYST'
    elif rule_level >= 7:
        severity, action = 'MEDIUM', 'LOG_REVIEW'
    else:
        severity, action = 'LOW', 'LOG_ONLY'

    return {
        'mode': 'RULE', 'severity': severity, 'action': action,
        'score': 0.0, 'threat_type': 'UNKNOWN', 'confidence': 0.0,
        'mitre': 'T1059', 'is_anomaly': rule_level >= 10,
    }


# ── Print Alert ───────────────────────────────────────────────────────────────
alert_count = {'total': 0, 'critical': 0, 'high': 0, 'iomt': 0, 'iomt_escalated': 0, 'suricata': 0}
processed_alert_ids = set()


def print_alert(alert: dict, result: dict):
    alert_count['total'] += 1

    wazuh_id = str(alert.get("id", ""))
    if wazuh_id:
        try:
            log_stage(case_id=wazuh_id, stage="alert_generated", device_id=alert.get('data', {}).get('device_id'))
        except Exception as e:
            print(f"  {C.GREY}[Metrics] {e}{C.RESET}")
    if result['severity'] == 'CRITICAL':
        alert_count['critical'] += 1
    elif result['severity'] == 'HIGH':
        alert_count['high'] += 1

    mode = result.get('mode')
    is_iomt = mode == 'IOMT_RULE'
    is_suricata = mode == 'SURICATA'
    if is_iomt:
        alert_count['iomt'] += 1
    if is_suricata:
        alert_count['suricata'] += 1

    alert_level = int(alert.get('rule', {}).get('level', 0))
    sev_col = SEVERITY_COLOR.get(result['severity'], C.WHITE)

    rule = alert.get('rule', {})
    agent = alert.get('agent', {})
    ts = alert.get('timestamp', datetime.now(timezone.utc).isoformat())[:19]

    print(f"\n{sev_col}{'━'*68}{C.RESET}")

    tag = f"{C.BLUE}[IOMT]{C.RESET} " if is_iomt else f"{C.PURPLE}[SURICATA]{C.RESET} " if is_suricata else f"{C.GREY}[ENDPOINT]{C.RESET} "
    print(f"{tag}{C.BOLD}{sev_col}[{result['severity']}]{C.RESET} "
          f"{C.WHITE}{ts}{C.RESET} "
          f"{C.GREY}Alert #{alert_count['total']}{C.RESET}")

    # Severity score — always shown now, all three modes
    print(f"  {C.CYAN}Severity Score:{C.RESET} {C.YELLOW}{result['score']:.3f}{C.RESET} "
          f"{C.GREY}(0.0=benign, 1.0=maximum){C.RESET}")

    if is_iomt and result.get('is_patient_safety'):
        print(f"  {C.BOLD}{C.RED}⚠  PATIENT SAFETY DEVICE — direct clinical risk{C.RESET}")

    print(f"  {C.CYAN}Rule     :{C.RESET} "
          f"{C.WHITE}{rule.get('id','?')} (Level {rule.get('level','?')}){C.RESET} "
          f"{C.GREY}{rule.get('description','')[:55]}{C.RESET}")

    print(f"  {C.CYAN}Agent    :{C.RESET} "
          f"{C.WHITE}{agent.get('name','?')}{C.RESET} "
          f"{C.GREY}({agent.get('ip','?')}){C.RESET}")

    if is_iomt:
        device_type_display = f"  [{result.get('device_type','?')}]" if result.get('device_type') else ""
        print(f"  {C.CYAN}Device   :{C.RESET} "
              f"{C.WHITE}{result.get('device_id','?')}{C.RESET}{device_type_display}")
        print(f"  {C.CYAN}Attack   :{C.RESET} {C.WHITE}{result.get('event_display', 'Unknown')}{C.RESET}")
        print(f"  {C.CYAN}MITRE    :{C.RESET} {C.WHITE}{result['mitre']}{C.RESET} "
              f"{C.GREY}({result.get('mitre_tactic','')}){C.RESET}")
        if result.get('hipaa_citation'):
            print(f"  {C.CYAN}HIPAA    :{C.RESET} {C.YELLOW}{result['hipaa_citation']}{C.RESET} "
                  f"{C.GREY}{result['hipaa_safeguard']}{C.RESET}")
        else:
            print(f"  {C.CYAN}HIPAA    :{C.RESET} {C.GREY}not applicable to this event{C.RESET}")

        if result.get("ml_available"):
            print(f"  {C.PURPLE}ML Overlay:{C.RESET} score={result['ml_score']:+.3f} "
                  f"anomaly={result['ml_is_anomaly']} "
                  f"predicted={result['ml_threat_type']} "
                  f"conf={result['ml_confidence']:.0%}")

    elif is_suricata:
        print(f"  {C.CYAN}Signature:{C.RESET} {C.WHITE}{result['signature']}{C.RESET}")
        print(f"  {C.CYAN}Category :{C.RESET} {C.PURPLE}{result['category']}{C.RESET}")
        print(f"  {C.CYAN}Flow     :{C.RESET} {C.WHITE}{result['src']}{C.RESET} "
              f"{C.GREY}→{C.RESET} {C.WHITE}{result['dest']}{C.RESET}")

    else:
        src_ip = alert.get('data', {}).get('srcip', '')
        if src_ip:
            print(f"  {C.CYAN}Source IP:{C.RESET} {C.WHITE}{src_ip}{C.RESET}")
        mode_tag = f"{C.BLUE}[ML]{C.RESET}" if result['mode'] == 'ML' else f"{C.GREY}[RULE]{C.RESET}"
        print(f"  {C.CYAN}Detection:{C.RESET} {mode_tag} "
              f"threat={C.PURPLE}{result['threat_type']}{C.RESET} "
              f"conf={C.WHITE}{result['confidence']:.0%}{C.RESET}")
        print(f"  {C.CYAN}MITRE    :{C.RESET} {C.WHITE}{result['mitre']}{C.RESET}")

    action_col = C.RED if result['action'] in ('AUTO_CONTAIN', 'ESCALATE_CLINICAL_ENGINEERING') else \
                 C.ORANGE if result['action'] == 'ALERT_ANALYST' else C.GREY
    print(f"  {C.CYAN}Action   :{C.RESET} {action_col}{C.BOLD}{result['action']}{C.RESET}")

    if result['severity'] == 'CRITICAL' and mode == 'ML':
        print(f"\n  {C.RED}{C.BOLD}🚨 CRITICAL: AUTO-CONTAINMENT TRIGGERED{C.RESET}")
        print(f"  {C.RED}   → Endpoint would be quarantined via Wazuh active-response{C.RESET}")
    elif is_iomt and result.get('is_patient_safety') and result['severity'] in ('CRITICAL', 'HIGH'):
        alert_count['iomt_escalated'] += 1
        print(f"\n  {C.RED}{C.BOLD}⚠  PATIENT-SAFETY ESCALATION — NO AUTO-ISOLATION{C.RESET}")
        print(f"  {C.RED}   → On-call biomedical engineer notified{C.RESET}")
    elif is_iomt and result['severity'] in ('CRITICAL', 'HIGH'):
        print(f"\n  {C.ORANGE}{C.BOLD}🔒 DEVICE ISOLATION TRIGGERED{C.RESET}")

    print(f"{sev_col}{'━'*68}{C.RESET}")

    if THEHIVE_AVAILABLE and result['severity'] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        try:
            alert_id = thehive_create(alert, result)

            # Auto-case creation: only CRITICAL/HIGH get promoted to a full
            # investigation Case (LOW/MEDIUM stay Alert-only in TheHive).
            if result['severity'] in ('CRITICAL', 'HIGH'):
                try:
                    from thehive_integration_iomt import create_case
                    case_id = create_case(alert, result, thehive_alert_id=alert_id)
                    if case_id:
                        print(f"  {C.RED}[TheHive] Case created: {case_id}{C.RESET}")
                        # Auto-generate investigation report
                        try:
                            from investigate_case_report import generate_report
                            device_id_for_report = alert.get("data", {}).get("device_id") or alert.get("agent", {}).get("id", "unknown")
                            generate_report(
                                case_id=case_id,
                                device_id=device_id_for_report,
                                device_type=alert.get("data", {}).get("device_type", "IoMT Device"),
                                rule_description=alert.get("rule", {}).get("description", "Security event")[:120],
                                severity=result.get("severity", "HIGH"),
                                wazuh_alert_id=alert.get("id"),
                                flow_id=None,  # will be filled by velociraptor if available
                                extra_notes="Automatically generated when TheHive case was created."
                            )
                        except Exception as rep_err:
                            print(f"  [REPORT] Warning: could not generate report — {rep_err}")
                            try:
                                with open("logs/edr_events.jsonl", "a") as _ef:
                                    _ef.write(json.dumps({
                                        "event": "report_generation_failed",
                                        "case_id": case_id,
                                        "error": str(rep_err),
                                        "timestamp": datetime.now(timezone.utc).isoformat()
                                    }) + "\n")
                            except Exception:
                                pass
                        device_id_for_forensics = alert.get('data', {}).get('device_id')
                        try:
                            from velociraptor_collect import trigger_collection
                            flow_id, vr_status = trigger_collection(
                                case_id=case_id, device_id=device_id_for_forensics
                            )
                            if vr_status == "submitted":
                                print(f"  {C.CYAN}[Velociraptor] Forensic collection triggered: {flow_id}{C.RESET}")
                            else:
                                print(f"  {C.GREY}[Velociraptor] Collection not triggered ({vr_status}){C.RESET}")
                        except Exception as ve:
                            print(f"  {C.GREY}[Velociraptor] {ve}{C.RESET}")
                except Exception as ce:
                    print(f"  {C.GREY}[TheHive Case] {ce}{C.RESET}")
        except Exception as e:
            print(f"  {C.GREY}[TheHive] {e}{C.RESET}")

    if result.get('action') in ('AUTO_CONTAIN', 'ALERT_ANALYST', 'ESCALATE_CLINICAL_ENGINEERING') and not is_suricata:
        try:
            contain_result = contain_threat(alert)
            print(f"  {C.CYAN}Containment: {contain_result['threat_level']}{C.RESET}")
        except Exception as e:
            print(f"  {C.GREY}[Contain] {e}{C.RESET}")

    if FILE_REP_AVAILABLE and mode == 'ML':
        file_path = alert.get('data', {}).get('path', '')
        if file_path and result['severity'] in ('HIGH', 'CRITICAL'):
            try:
                rep = check_file_reputation(file_path)
                print(f"  {C.CYAN}File Rep : {C.RESET}"
                      f"{C.RED if rep.get('verdict')=='MALICIOUS' else C.GREEN}"
                      f"{rep.get('verdict','N/A')}{C.RESET}")
            except Exception:
                pass

    print(f"  {C.GREY}Stats: total={alert_count['total']} "
          f"critical={C.RED}{alert_count['critical']}{C.GREY} "
          f"high={C.ORANGE}{alert_count['high']}{C.GREY} "
          f"iomt={C.BLUE}{alert_count['iomt']}{C.GREY} "
          f"iomt_escalated={C.RED}{alert_count['iomt_escalated']}{C.GREY} "
          f"suricata={C.PURPLE}{alert_count['suricata']}{C.GREY}{C.RESET}")


# ── Docker Log Reader ─────────────────────────────────────────────────────────
def read_wazuh_docker_alerts():
    container = CONTAINER
    alerts_file = '/var/ossec/logs/alerts/alerts.json'

    print(f"{C.CYAN}[*] Connecting to Docker container: {container}{C.RESET}")
    print(f"{C.CYAN}[*] Reading: {alerts_file}{C.RESET}\n")

    cmd = ['docker', 'exec', container, 'tail', '-f', '-n', '0', alerts_file]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    except FileNotFoundError:
        print(f"{C.RED}❌ docker command not found{C.RESET}")
        return

    buffer = ''
    for raw_line in iter(proc.stdout.readline, ''):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        buffer += raw_line
        try:
            alert = json.loads(buffer)
            alert_id = str(alert.get("id", ""))
            if alert_id and alert_id in processed_alert_ids:
                continue
            if alert_id:
                processed_alert_ids.add(alert_id)
            buffer = ''
            rule_level = int(alert.get('rule', {}).get('level', 0))
            if rule_level >= 3:
                if is_suricata_alert(alert):
                    result = analyze_suricata(alert)
                elif is_iomt_alert(alert):
                    result = analyze_iomt(alert)
                else:
                    result = analyze(alert)
                print_alert(alert, result)
        except json.JSONDecodeError:
            if len(buffer) > 5000:
                buffer = ''
            continue

    stderr_output = proc.stderr.read()
    if stderr_output:
        print(f"\n{C.RED}Docker error: {stderr_output[:200]}{C.RESET}")


def print_banner():
    ml_status = f"{C.GREEN}ACTIVE{C.RESET}" if iso_model else f"{C.YELLOW}RULE-BASED FALLBACK{C.RESET}"

    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║   EDR LIVE MONITOR — Endpoint ML + IoMT + Suricata                ║
║   EduQual Level 6  |  Kinat Zahra Khalil                          ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}

  {C.CYAN}ML Engine (endpoint):{C.RESET} {ml_status}
  {C.CYAN}IoMT Engine         :{C.RESET} {C.GREEN}RULE-BASED (device-type-aware) + MITRE + HIPAA{C.RESET}
  {C.CYAN}Suricata Engine     :{C.RESET} {C.GREEN}DEDICATED (network-IDS signatures){C.RESET}
  {C.CYAN}Container           :{C.RESET} {C.WHITE}{CONTAINER}{C.RESET}
  {C.CYAN}Patient-safety devices:{C.RESET} {C.WHITE}ventilator, infusion_pump, patient_monitor{C.RESET}

{C.GREY}  Waiting for Wazuh alerts...{C.RESET}
{C.GREY}  ─────────────────────────────────────────────────────────────────{C.RESET}
""")


if __name__ == '__main__':
    print_banner()
    try:
        read_wazuh_docker_alerts()
    except KeyboardInterrupt:
        print(f"\n\n{C.CYAN}[*] Monitor stopped.{C.RESET}")
        print(f"    Total alerts processed : {alert_count['total']}")
        print(f"    Critical               : {C.RED}{alert_count['critical']}{C.RESET}")
        print(f"    High                   : {C.ORANGE}{alert_count['high']}{C.RESET}")
        print(f"    IoMT alerts            : {C.BLUE}{alert_count['iomt']}{C.RESET}")
        print(f"    IoMT patient-safety     : {C.RED}{alert_count['iomt_escalated']}{C.RESET}")
        print(f"    Suricata alerts         : {C.PURPLE}{alert_count['suricata']}{C.RESET}\n")
